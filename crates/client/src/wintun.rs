//! Wintun FFI, loaded at run time from `wintun.dll` next to
//! skyblock.exe, and the IP Helper calls that give the adapter its
//! address, MTU and routes.

use std::ffi::{CString, c_void};
use std::io;
use std::net::Ipv4Addr;
use std::os::windows::ffi::OsStrExt;
use std::sync::OnceLock;

use ipnet::Ipv4Net;
use windows_sys::Win32::Foundation::{
    ERROR_NO_MORE_ITEMS, ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, GetLastError, HANDLE,
    NO_ERROR, WIN32_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2, GetBestRoute2,
    GetIpInterfaceEntry, InitializeIpForwardEntry, InitializeIpInterfaceEntry,
    InitializeUnicastIpAddressEntry, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW,
    MIB_UNICASTIPADDRESS_ROW, SetIpInterfaceEntry,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, IN_ADDR, IN_ADDR_0, IpDadStatePreferred, MIB_IPPROTO_NETMGMT, SOCKADDR_IN,
    SOCKADDR_INET,
};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::core::GUID;

type CreateAdapterFn =
    unsafe extern "system" fn(*const u16, *const u16, *const GUID) -> *mut c_void;
type CloseAdapterFn = unsafe extern "system" fn(*mut c_void);
type GetLuidFn = unsafe extern "system" fn(*mut c_void, *mut NET_LUID_LH);
type StartSessionFn = unsafe extern "system" fn(*mut c_void, u32) -> *mut c_void;
type EndSessionFn = unsafe extern "system" fn(*mut c_void);
type ReadEventFn = unsafe extern "system" fn(*mut c_void) -> HANDLE;
type ReceiveFn = unsafe extern "system" fn(*mut c_void, *mut u32) -> *mut u8;
type ReleaseFn = unsafe extern "system" fn(*mut c_void, *const u8);
type AllocSendFn = unsafe extern "system" fn(*mut c_void, u32) -> *mut u8;
type SendFn = unsafe extern "system" fn(*mut c_void, *const u8);
type FarProc = unsafe extern "system" fn() -> isize;

/// Ring size per direction (Wintun allows 128KiB–64MiB).
const RING_CAPACITY: u32 = 4 << 20;

struct Api {
    create: CreateAdapterFn,
    close: CloseAdapterFn,
    luid: GetLuidFn,
    start: StartSessionFn,
    end: EndSessionFn,
    read_event: ReadEventFn,
    receive: ReceiveFn,
    release: ReleaseFn,
    alloc_send: AllocSendFn,
    send: SendFn,
}

static API: OnceLock<Result<Api, String>> = OnceLock::new();

fn api() -> io::Result<&'static Api> {
    API.get_or_init(load)
        .as_ref()
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.clone()))
}

fn load() -> Result<Api, String> {
    let dll = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("wintun.dll")))
        .ok_or("cannot locate the executable directory")?;
    let wide: Vec<u16> = dll.as_os_str().encode_wide().chain([0]).collect();
    // SAFETY: NUL-terminated wide path.
    let lib = unsafe { LoadLibraryW(wide.as_ptr()) };
    if lib.is_null() {
        return Err(format!(
            "cannot load {}: download Wintun 0.14 (https://www.wintun.net) and put \
             bin/amd64/wintun.dll next to skyblock.exe",
            dll.display()
        ));
    }
    let sym = |name: &str| {
        let c = CString::new(name).expect("no NUL");
        // SAFETY: `lib` is a loaded module and `c` is NUL-terminated.
        unsafe { GetProcAddress(lib, c.as_ptr().cast()) }
            .ok_or_else(|| format!("wintun.dll lacks {name}"))
    };
    // SAFETY: the symbols have these signatures in Wintun 0.14 (wintun.h).
    unsafe {
        Ok(Api {
            create: std::mem::transmute::<FarProc, CreateAdapterFn>(sym("WintunCreateAdapter")?),
            close: std::mem::transmute::<FarProc, CloseAdapterFn>(sym("WintunCloseAdapter")?),
            luid: std::mem::transmute::<FarProc, GetLuidFn>(sym("WintunGetAdapterLUID")?),
            start: std::mem::transmute::<FarProc, StartSessionFn>(sym("WintunStartSession")?),
            end: std::mem::transmute::<FarProc, EndSessionFn>(sym("WintunEndSession")?),
            read_event: std::mem::transmute::<FarProc, ReadEventFn>(sym("WintunGetReadWaitEvent")?),
            receive: std::mem::transmute::<FarProc, ReceiveFn>(sym("WintunReceivePacket")?),
            release: std::mem::transmute::<FarProc, ReleaseFn>(sym("WintunReleaseReceivePacket")?),
            alloc_send: std::mem::transmute::<FarProc, AllocSendFn>(sym(
                "WintunAllocateSendPacket",
            )?),
            send: std::mem::transmute::<FarProc, SendFn>(sym("WintunSendPacket")?),
        })
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

/// A Wintun adapter created by this process; Wintun removes it when the
/// handle is closed or the process exits.
struct Adapter {
    h: *mut c_void,
    api: &'static Api,
}

impl Drop for Adapter {
    fn drop(&mut self) {
        // SAFETY: `h` came from WintunCreateAdapter and is closed once.
        unsafe { (self.api.close)(self.h) }
    }
}

/// An adapter with a running session: the packet rings to and from the
/// system.
pub struct Session {
    h: *mut c_void,
    adapter: Adapter,
    luid: NET_LUID_LH,
}

// SAFETY: Wintun's receive, release, allocate and send functions are
// thread-safe (wintun README); the handles stay valid until drop.
unsafe impl Send for Session {}
unsafe impl Sync for Session {}

impl Session {
    /// Creates adapter `name` with a fixed GUID (so Windows keeps one
    /// network profile for it across runs) and starts its session.
    pub fn open(name: &str, guid: &GUID) -> io::Result<Session> {
        let api = api()?;
        let (n, t) = (wide(name), wide("skyblock"));
        // SAFETY: NUL-terminated strings and a valid GUID.
        let h = unsafe { (api.create)(n.as_ptr(), t.as_ptr(), guid) };
        if h.is_null() {
            return Err(io::Error::last_os_error());
        }
        let adapter = Adapter { h, api };
        let mut luid = NET_LUID_LH { Value: 0 };
        // SAFETY: valid adapter handle and output pointer.
        unsafe { (api.luid)(h, &mut luid) };
        // SAFETY: valid adapter handle; capacity within Wintun's limits.
        let s = unsafe { (api.start)(h, RING_CAPACITY) };
        if s.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Session {
            h: s,
            adapter,
            luid,
        })
    }

    pub fn luid(&self) -> NET_LUID_LH {
        self.luid
    }

    /// Signalled when packets are waiting to be received.
    pub fn read_event(&self) -> HANDLE {
        // SAFETY: valid session handle.
        unsafe { (self.adapter.api.read_event)(self.h) }
    }

    /// Copies the next packet from the system into `buf`; `Ok(None)` when
    /// there is none right now. Longer packets are cut to `buf`.
    pub fn receive(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        let api = self.adapter.api;
        let mut size = 0u32;
        // SAFETY: valid session handle and output pointer.
        let p = unsafe { (api.receive)(self.h, &mut size) };
        if p.is_null() {
            // SAFETY: plain FFI call.
            let e = unsafe { GetLastError() };
            return if e == ERROR_NO_MORE_ITEMS {
                Ok(None)
            } else {
                Err(io::Error::from_raw_os_error(e as i32))
            };
        }
        let n = (size as usize).min(buf.len());
        // SAFETY: Wintun hands out `size` readable bytes at `p` until the
        // packet is released.
        unsafe {
            buf[..n].copy_from_slice(std::slice::from_raw_parts(p, n));
            (api.release)(self.h, p);
        }
        Ok(Some(n))
    }

    /// Hands a packet to the system as if it arrived on the adapter.
    pub fn send(&self, pkt: &[u8]) -> io::Result<()> {
        let api = self.adapter.api;
        // SAFETY: valid session handle.
        let p = unsafe { (api.alloc_send)(self.h, pkt.len() as u32) };
        if p.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: Wintun allocated `pkt.len()` writable bytes at `p`.
        unsafe {
            std::ptr::copy_nonoverlapping(pkt.as_ptr(), p, pkt.len());
            (api.send)(self.h, p);
        }
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: valid session handle, ended once; the adapter closes after.
        unsafe { (self.adapter.api.end)(self.h) }
    }
}

fn check(e: WIN32_ERROR, what: &str) -> io::Result<()> {
    if e == NO_ERROR {
        Ok(())
    } else {
        let os = io::Error::from_raw_os_error(e as i32);
        Err(io::Error::new(os.kind(), format!("{what}: {os}")))
    }
}

fn sockaddr(ip: Ipv4Addr) -> SOCKADDR_INET {
    SOCKADDR_INET {
        Ipv4: SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(ip.octets()),
                },
            },
            sin_zero: [0; 8],
        },
    }
}

fn ipv4_of(a: &SOCKADDR_INET) -> Ipv4Addr {
    // SAFETY: only IPv4 addresses are stored or asked for here.
    Ipv4Addr::from(unsafe { a.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes())
}

/// Gives the adapter its address.
pub fn set_address(luid: NET_LUID_LH, ip: Ipv4Addr, prefix_len: u8) -> io::Result<()> {
    // SAFETY: an all-zero row is valid input to the initializer.
    let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
    // SAFETY: valid row pointer.
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid = luid;
    row.Address = sockaddr(ip);
    row.OnLinkPrefixLength = prefix_len;
    row.DadState = IpDadStatePreferred;
    // SAFETY: fully initialized row.
    check(
        unsafe { CreateUnicastIpAddressEntry(&row) },
        "adding the adapter address",
    )
}

/// Sets the adapter's IPv4 MTU and a fixed interface metric (low: its
/// routes and DNS server win over the physical adapter's).
pub fn set_mtu_and_metric(luid: NET_LUID_LH, mtu: u16, metric: u32) -> io::Result<()> {
    // SAFETY: an all-zero row is valid input to the initializer.
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    // SAFETY: valid row pointer.
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = AF_INET;
    row.InterfaceLuid = luid;
    // SAFETY: row identifies the interface by family and LUID.
    check(
        unsafe { GetIpInterfaceEntry(&mut row) },
        "reading the adapter",
    )?;
    row.NlMtu = u32::from(mtu);
    row.UseAutomaticMetric = false;
    row.Metric = metric;
    // Must be 0 for IPv4 when setting (SetIpInterfaceEntry docs).
    row.SitePrefixLength = 0;
    // SAFETY: row read back from the system with our changes.
    check(
        unsafe { SetIpInterfaceEntry(&mut row) },
        "setting the adapter MTU",
    )
}

/// A route this program added: enough to delete it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub prefix: Ipv4Net,
    pub luid: u64,
    pub next_hop: Ipv4Addr,
}

fn route_row(r: &Route) -> MIB_IPFORWARD_ROW2 {
    // SAFETY: an all-zero row is valid input to the initializer.
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    // SAFETY: valid row pointer.
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = NET_LUID_LH { Value: r.luid };
    row.DestinationPrefix.Prefix = sockaddr(r.prefix.network());
    row.DestinationPrefix.PrefixLength = r.prefix.prefix_len();
    row.NextHop = sockaddr(r.next_hop);
    row.Metric = 0;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row
}

/// Adds a route; `Ok(false)` when an identical one already exists (then it
/// is not ours to delete).
pub fn add_route(r: &Route) -> io::Result<bool> {
    let row = route_row(r);
    // SAFETY: fully initialized row.
    match unsafe { CreateIpForwardEntry2(&row) } {
        NO_ERROR => Ok(true),
        ERROR_OBJECT_ALREADY_EXISTS => Ok(false),
        e => check(e, &format!("adding route {}", r.prefix)).map(|_| false),
    }
}

/// Deletes a route; one that is already gone is fine.
pub fn delete_route(r: &Route) -> io::Result<()> {
    let row = route_row(r);
    // SAFETY: row identifies the route by interface, prefix and next hop.
    match unsafe { DeleteIpForwardEntry2(&row) } {
        NO_ERROR | ERROR_NOT_FOUND => Ok(()),
        e => check(e, &format!("deleting route {}", r.prefix)),
    }
}

/// The interface and next hop the system uses for `dest` right now.
pub fn best_route(dest: Ipv4Addr) -> io::Result<(u64, Ipv4Addr)> {
    let d = sockaddr(dest);
    // SAFETY: all-zero output structures are fine to overwrite.
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    let mut src: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    // SAFETY: null LUID and source mean "any"; valid output pointers.
    let e = unsafe {
        GetBestRoute2(
            std::ptr::null(),
            0,
            std::ptr::null(),
            &d,
            0,
            &mut row,
            &mut src,
        )
    };
    check(e, &format!("looking up the route to {dest}"))?;
    // SAFETY: the union holds the LUID's 64-bit value.
    Ok((unsafe { row.InterfaceLuid.Value }, ipv4_of(&row.NextHop)))
}
