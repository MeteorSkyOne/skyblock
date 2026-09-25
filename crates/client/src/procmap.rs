//! Which process owns a local port (SPEC §6.2), from WinDivert socket
//! events and, on a miss, the system TCP/UDP tables (IPv4 and IPv6, since
//! games often use dual-stack sockets for IPv4 traffic).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use skyblock_proto::ip::{PROTO_TCP, PROTO_UDP};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, INVALID_HANDLE_VALUE, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

/// How long a cached PID → "is a game" answer is used on the fast path. PIDs
/// get reused, so the authoritative path (`resolve`) never relies on it.
const PID_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Tunnel,
    Bypass,
}

#[derive(Default)]
struct State {
    ports: HashMap<(u8, u16), u32>,
    pids: HashMap<u32, (bool, Instant)>,
}

pub struct ProcMap {
    /// Lower-cased executable file names.
    targets: Vec<String>,
    state: Mutex<State>,
}

impl ProcMap {
    pub fn new(targets: &[String]) -> Self {
        Self {
            targets: targets.iter().map(|t| t.to_lowercase()).collect(),
            state: Mutex::new(State::default()),
        }
    }

    /// Decision from the socket-event cache (may be stale after port reuse).
    pub fn lookup(&self, proto: u8, port: u16) -> Option<Decision> {
        let mut st = self.state.lock().expect("procmap lock");
        let pid = *st.ports.get(&(proto, port))?;
        Some(self.decide(&mut st, pid))
    }

    /// Decision from the system table for `proto`: authoritative for sockets
    /// that exist now. Returns `None` if no socket owns `port`.
    pub fn resolve(&self, proto: u8, port: u16) -> Option<Decision> {
        let rows = match proto {
            PROTO_TCP => tcp_table(),
            PROTO_UDP => udp_table(),
            _ => return None,
        };
        let (_, pid) = rows.into_iter().find(|&(p, _)| p == port)?;
        // Look the name up afresh: PIDs are reused quickly, so a cached
        // answer may describe a process that has since exited.
        let is_target = self.is_target(pid);
        let mut st = self.state.lock().expect("procmap lock");
        st.ports.insert((proto, port), pid);
        st.pids.insert(pid, (is_target, Instant::now()));
        Some(Self::decision(is_target))
    }

    pub fn learn(&self, proto: u8, port: u16, pid: u32) {
        self.state
            .lock()
            .expect("procmap lock")
            .ports
            .insert((proto, port), pid);
    }

    pub fn forget(&self, proto: u8, port: u16) {
        self.state
            .lock()
            .expect("procmap lock")
            .ports
            .remove(&(proto, port));
    }

    /// Cached decision for `pid` (the fast path only trusts `Tunnel`).
    fn decide(&self, st: &mut State, pid: u32) -> Decision {
        let now = Instant::now();
        let is_target = match st.pids.get(&pid) {
            Some(&(t, at)) if now.duration_since(at) < PID_TTL => t,
            _ => {
                let t = self.is_target(pid);
                st.pids.insert(pid, (t, now));
                t
            }
        };
        Self::decision(is_target)
    }

    fn is_target(&self, pid: u32) -> bool {
        exe_name(pid).is_some_and(|n| self.targets.contains(&n))
    }

    fn decision(is_target: bool) -> Decision {
        if is_target {
            Decision::Tunnel
        } else {
            Decision::Bypass
        }
    }
}

/// Lower-cased file name of `pid`'s executable. Falls back to a process
/// snapshot, which needs no handle: kernel anti-cheats often deny opening
/// the game process even for limited queries.
fn exe_name(pid: u32) -> Option<String> {
    if pid == 0 || pid == 4 {
        return None;
    }
    exe_name_by_handle(pid).or_else(|| exe_name_by_snapshot(pid))
}

fn exe_name_by_handle(pid: u32) -> Option<String> {
    // SAFETY: plain Win32 calls with owned buffers; the handle is closed.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        if ok == 0 {
            return None;
        }
        let path = String::from_utf16_lossy(&buf[..len as usize]);
        path.rsplit(['\\', '/']).next().map(str::to_lowercase)
    }
}

fn exe_name_by_snapshot(pid: u32) -> Option<String> {
    // SAFETY: the snapshot handle is closed; the entry's dwSize is set as
    // the API requires.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = None;
        let mut ok = Process32FirstW(snap, &mut entry);
        while ok != 0 {
            if entry.th32ProcessID == pid {
                let name = &entry.szExeFile;
                let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
                found = Some(String::from_utf16_lossy(&name[..len]).to_lowercase());
                break;
            }
            ok = Process32NextW(snap, &mut entry);
        }
        CloseHandle(snap);
        found
    }
}

/// Calls a `GetExtended*Table` function with a growing buffer.
fn fetch(call: impl Fn(*mut core::ffi::c_void, *mut u32) -> u32) -> Option<Vec<u32>> {
    let mut size = 0u32;
    let mut buf: Vec<u32> = Vec::new();
    for _ in 0..4 {
        let r = call(buf.as_mut_ptr().cast(), &mut size);
        if r == NO_ERROR {
            return Some(buf);
        }
        if r != ERROR_INSUFFICIENT_BUFFER {
            return None;
        }
        buf = vec![0u32; (size as usize).div_ceil(4) + 64];
        size = (buf.len() * 4) as u32;
    }
    None
}

/// Rows of a `MIB_*TABLE_OWNER_PID` buffer: a u32 count, then the rows.
fn rows<R: Copy>(buf: &[u32]) -> Vec<R> {
    let Some(&n) = buf.first() else {
        return Vec::new();
    };
    let bytes = buf.len() * 4;
    let first = std::mem::size_of::<u32>().max(std::mem::align_of::<R>());
    let n = (n as usize).min((bytes.saturating_sub(first)) / std::mem::size_of::<R>());
    // SAFETY: the OS wrote `n` rows of `R` after the count, and we bounded
    // `n` by the buffer size; the u32 buffer is sufficiently aligned.
    unsafe {
        let p = buf.as_ptr().cast::<u8>().add(first).cast::<R>();
        std::slice::from_raw_parts(p, n).to_vec()
    }
}

/// Converts a port stored in network order in the low 16 bits.
fn port(dw: u32) -> u16 {
    u16::from_be(dw as u16)
}

fn udp_table() -> Vec<(u16, u32)> {
    let mut out = Vec::new();
    // SAFETY: `fetch` passes a buffer of the size it reports.
    let v4 = fetch(|p, s| unsafe {
        GetExtendedUdpTable(p, s, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0)
    });
    if let Some(buf) = v4 {
        out.extend(
            rows::<MIB_UDPROW_OWNER_PID>(&buf)
                .iter()
                .map(|r| (port(r.dwLocalPort), r.dwOwningPid)),
        );
    }
    // SAFETY: as above.
    let v6 = fetch(|p, s| unsafe {
        GetExtendedUdpTable(p, s, 0, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0)
    });
    if let Some(buf) = v6 {
        out.extend(
            rows::<MIB_UDP6ROW_OWNER_PID>(&buf)
                .iter()
                .map(|r| (port(r.dwLocalPort), r.dwOwningPid)),
        );
    }
    out
}

fn tcp_table() -> Vec<(u16, u32)> {
    let mut out = Vec::new();
    // SAFETY: `fetch` passes a buffer of the size it reports.
    let v4 = fetch(|p, s| unsafe {
        GetExtendedTcpTable(p, s, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0)
    });
    if let Some(buf) = v4 {
        out.extend(
            rows::<MIB_TCPROW_OWNER_PID>(&buf)
                .iter()
                .map(|r| (port(r.dwLocalPort), r.dwOwningPid)),
        );
    }
    // SAFETY: as above.
    let v6 = fetch(|p, s| unsafe {
        GetExtendedTcpTable(p, s, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0)
    });
    if let Some(buf) = v6 {
        out.extend(
            rows::<MIB_TCP6ROW_OWNER_PID>(&buf)
                .iter()
                .map(|r| (port(r.dwLocalPort), r.dwOwningPid)),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, UdpSocket};

    #[test]
    fn finds_our_own_sockets() {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tcp = TcpListener::bind("[::]:0").unwrap();
        let me = std::env::current_exe().unwrap();
        let name = me.file_name().unwrap().to_string_lossy().to_string();

        let map = ProcMap::new(&[name]);
        let uport = udp.local_addr().unwrap().port();
        let tport = tcp.local_addr().unwrap().port();
        assert_eq!(map.lookup(PROTO_UDP, uport), None);
        assert_eq!(map.resolve(PROTO_UDP, uport), Some(Decision::Tunnel));
        assert_eq!(
            map.resolve(PROTO_TCP, tport),
            Some(Decision::Tunnel),
            "IPv6 table"
        );

        let other = ProcMap::new(&["game.exe".to_owned()]);
        assert_eq!(other.resolve(PROTO_UDP, uport), Some(Decision::Bypass));
    }

    #[test]
    fn both_name_lookups_agree() {
        let me = std::env::current_exe().unwrap();
        let expected = me.file_name().unwrap().to_string_lossy().to_lowercase();
        let pid = std::process::id();
        assert_eq!(exe_name_by_handle(pid).as_deref(), Some(expected.as_str()));
        assert_eq!(
            exe_name_by_snapshot(pid).as_deref(),
            Some(expected.as_str())
        );
        assert_eq!(exe_name(0), None);
    }

    #[test]
    fn learn_and_forget() {
        let map = ProcMap::new(&[]);
        map.learn(PROTO_UDP, 5000, std::process::id());
        assert_eq!(map.lookup(PROTO_UDP, 5000), Some(Decision::Bypass));
        map.forget(PROTO_UDP, 5000);
        assert_eq!(map.lookup(PROTO_UDP, 5000), None);
    }
}

#[cfg(test)]
mod bench {
    use super::*;

    /// `cargo test -p skyblock --release table_query_cost -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn table_query_cost() {
        for (name, f) in [
            ("udp", udp_table as fn() -> Vec<(u16, u32)>),
            ("tcp", tcp_table),
        ] {
            let n = f().len();
            let t = Instant::now();
            for _ in 0..200 {
                std::hint::black_box(f());
            }
            println!("{name}: {n} rows, {:?} per query", t.elapsed() / 200);
        }
    }
}
