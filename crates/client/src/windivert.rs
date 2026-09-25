//! Minimal WinDivert 2.2 bindings. `WinDivert.dll` is loaded at runtime
//! from the executable's directory, so the client builds without it and
//! only needs it (plus `WinDivert64.sys`) in WinDivert mode.

use std::ffi::{CString, c_char, c_void};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

pub const LAYER_NETWORK: u32 = 0;
pub const LAYER_SOCKET: u32 = 3;

pub const FLAG_SNIFF: u64 = 0x0001;
pub const FLAG_RECV_ONLY: u64 = 0x0004;

pub const EVENT_SOCKET_BIND: u8 = 3;
pub const EVENT_SOCKET_CONNECT: u8 = 4;
pub const EVENT_SOCKET_ACCEPT: u8 = 6;
pub const EVENT_SOCKET_CLOSE: u8 = 7;

const PARAM_QUEUE_LENGTH: u32 = 0;
const PARAM_QUEUE_TIME: u32 = 1;

const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INVALID_IMAGE_HASH: u32 = 577;
const ERROR_DRIVER_BLOCKED: u32 = 1275;

/// `WINDIVERT_ADDRESS` (80 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Address {
    pub timestamp: i64,
    /// Layer:8, Event:8, Sniffed, Outbound, Loopback, Impostor, IPv6,
    /// IPChecksum, TCPChecksum, UDPChecksum, Reserved1:8.
    bits: u32,
    reserved2: u32,
    data: [u8; 64],
}

const _: () = assert!(std::mem::size_of::<Address>() == 80);

const BIT_IP_CHECKSUM: u32 = 1 << 21;
const BIT_TCP_CHECKSUM: u32 = 1 << 22;
const BIT_UDP_CHECKSUM: u32 = 1 << 23;

impl Default for Address {
    fn default() -> Self {
        Self {
            timestamp: 0,
            bits: 0,
            reserved2: 0,
            data: [0; 64],
        }
    }
}

/// Fields of `WINDIVERT_DATA_SOCKET` / `WINDIVERT_DATA_FLOW` we use.
#[derive(Debug, Clone, Copy)]
pub struct SocketInfo {
    pub process_id: u32,
    pub local_port: u16,
    pub protocol: u8,
}

impl Address {
    /// An inbound network-layer address on the given interface, with all
    /// checksums marked valid.
    pub fn inbound(if_idx: u32, sub_if_idx: u32) -> Self {
        let mut a = Self {
            bits: LAYER_NETWORK | BIT_IP_CHECKSUM | BIT_TCP_CHECKSUM | BIT_UDP_CHECKSUM,
            ..Self::default()
        };
        a.data[0..4].copy_from_slice(&if_idx.to_ne_bytes());
        a.data[4..8].copy_from_slice(&sub_if_idx.to_ne_bytes());
        a
    }

    pub fn event(&self) -> u8 {
        (self.bits >> 8) as u8
    }

    /// `(IfIdx, SubIfIdx)` of a network-layer packet.
    pub fn interface(&self) -> (u32, u32) {
        (
            u32::from_ne_bytes(self.data[0..4].try_into().expect("4 bytes")),
            u32::from_ne_bytes(self.data[4..8].try_into().expect("4 bytes")),
        )
    }

    pub fn socket(&self) -> SocketInfo {
        SocketInfo {
            process_id: u32::from_ne_bytes(self.data[16..20].try_into().expect("4 bytes")),
            local_port: u16::from_ne_bytes([self.data[52], self.data[53]]),
            protocol: self.data[56],
        }
    }
}

type OpenFn = unsafe extern "C" fn(*const c_char, u32, i16, u64) -> HANDLE;
type RecvFn = unsafe extern "C" fn(HANDLE, *mut c_void, u32, *mut u32, *mut Address) -> i32;
type SendFn = unsafe extern "C" fn(HANDLE, *const c_void, u32, *mut u32, *const Address) -> i32;
type CloseFn = unsafe extern "C" fn(HANDLE) -> i32;
type SetParamFn = unsafe extern "C" fn(HANDLE, u32, u64) -> i32;
type CompileFilterFn =
    unsafe extern "C" fn(*const c_char, u32, *mut c_char, u32, *mut *const c_char, *mut u32) -> i32;
type FarProc = unsafe extern "system" fn() -> isize;

struct Api {
    open: OpenFn,
    recv: RecvFn,
    send: SendFn,
    close: CloseFn,
    set_param: SetParamFn,
    compile_filter: CompileFilterFn,
}

static API: OnceLock<Result<Api, String>> = OnceLock::new();

fn api() -> io::Result<&'static Api> {
    API.get_or_init(load)
        .as_ref()
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.clone()))
}

fn load() -> Result<Api, String> {
    let dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .ok_or("cannot locate the executable directory")?;
    load_from(&dir)
}

fn load_from(dir: &std::path::Path) -> Result<Api, String> {
    let dll = dir.join("WinDivert.dll");
    let wide: Vec<u16> = dll.as_os_str().encode_wide().chain([0]).collect();
    // SAFETY: NUL-terminated wide path.
    let lib = unsafe { LoadLibraryW(wide.as_ptr()) };
    if lib.is_null() {
        return Err(format!(
            "cannot load {}: download WinDivert 2.2.2 (https://reqrypt.org/windivert.html) \
             and put WinDivert.dll and WinDivert64.sys next to skyblock.exe",
            dll.display()
        ));
    }
    let sym = |name: &str| {
        let c = CString::new(name).expect("no NUL");
        // SAFETY: `lib` is a loaded module and `c` is NUL-terminated.
        unsafe { GetProcAddress(lib, c.as_ptr().cast()) }
            .ok_or_else(|| format!("WinDivert.dll lacks {name}"))
    };
    // SAFETY: the symbols have these signatures in WinDivert 2.2.
    unsafe {
        Ok(Api {
            open: std::mem::transmute::<FarProc, OpenFn>(sym("WinDivertOpen")?),
            recv: std::mem::transmute::<FarProc, RecvFn>(sym("WinDivertRecv")?),
            send: std::mem::transmute::<FarProc, SendFn>(sym("WinDivertSend")?),
            close: std::mem::transmute::<FarProc, CloseFn>(sym("WinDivertClose")?),
            set_param: std::mem::transmute::<FarProc, SetParamFn>(sym("WinDivertSetParam")?),
            compile_filter: std::mem::transmute::<FarProc, CompileFilterFn>(sym(
                "WinDivertHelperCompileFilter",
            )?),
        })
    }
}

/// An open WinDivert handle. Handles are safe to use from several threads.
pub struct Handle {
    h: HANDLE,
    api: &'static Api,
}

// SAFETY: WinDivert handles may be used concurrently from multiple threads.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

impl Handle {
    pub fn open(filter: &str, layer: u32, priority: i16, flags: u64) -> io::Result<Handle> {
        let api = api()?;
        let f = CString::new(filter).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: valid NUL-terminated filter string.
        let h = unsafe { (api.open)(f.as_ptr(), layer, priority, flags) };
        if h == INVALID_HANDLE_VALUE {
            // SAFETY: trivially safe.
            let code = unsafe { GetLastError() };
            return Err(open_error(code, api, filter, layer));
        }
        Ok(Handle { h, api })
    }

    /// Raises the queue limits so a burst never stalls the game.
    pub fn tune_queue(&self) {
        // SAFETY: valid handle; parameters within documented ranges.
        unsafe {
            (self.api.set_param)(self.h, PARAM_QUEUE_LENGTH, 8192);
            (self.api.set_param)(self.h, PARAM_QUEUE_TIME, 2000);
        }
    }

    /// Receives one packet (or, on sniff-only event layers, one event with
    /// an empty `buf`).
    pub fn recv(&self, buf: &mut [u8], addr: &mut Address) -> io::Result<usize> {
        let mut len = 0u32;
        let ptr = if buf.is_empty() {
            std::ptr::null_mut()
        } else {
            buf.as_mut_ptr().cast()
        };
        // SAFETY: `ptr`/`buf.len()` describe writable memory; `addr` is a
        // valid WINDIVERT_ADDRESS.
        let ok = unsafe { (self.api.recv)(self.h, ptr, buf.len() as u32, &mut len, addr) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(len as usize)
    }

    pub fn send(&self, pkt: &[u8], addr: &Address) -> io::Result<()> {
        let mut sent = 0u32;
        // SAFETY: `pkt` is readable for its length; `addr` is valid.
        let ok = unsafe {
            (self.api.send)(
                self.h,
                pkt.as_ptr().cast(),
                pkt.len() as u32,
                &mut sent,
                addr,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle is open and closed exactly once.
        unsafe { (self.api.close)(self.h) };
    }
}

/// Checks `filter` with WinDivert's own compiler, reporting where it fails.
fn compile(api: &Api, filter: &str, layer: u32) -> Result<(), String> {
    let f = CString::new(filter).map_err(|_| "filter contains NUL".to_owned())?;
    let mut err: *const c_char = std::ptr::null();
    let mut pos = 0u32;
    // SAFETY: a NULL object buffer asks only for validation; `err` receives
    // a pointer to a static string owned by the DLL.
    let ok = unsafe {
        (api.compile_filter)(
            f.as_ptr(),
            layer,
            std::ptr::null_mut(),
            0,
            &mut err,
            &mut pos,
        )
    };
    if ok != 0 {
        return Ok(());
    }
    let reason = if err.is_null() {
        "unknown error".into()
    } else {
        // SAFETY: WinDivert returns a NUL-terminated static string.
        unsafe { std::ffi::CStr::from_ptr(err) }
            .to_string_lossy()
            .into_owned()
    };
    let at = filter.get(pos as usize..).unwrap_or("");
    Err(format!(
        "{reason} at position {pos}: `{}`",
        at.chars().take(40).collect::<String>()
    ))
}

fn open_error(code: u32, api: &Api, filter: &str, layer: u32) -> io::Error {
    let msg = match code {
        ERROR_ACCESS_DENIED => "WinDivertOpen: access denied; run skyblock as administrator".into(),
        ERROR_FILE_NOT_FOUND => {
            "WinDivertOpen: WinDivert64.sys not found next to skyblock.exe".into()
        }
        ERROR_INVALID_IMAGE_HASH | ERROR_DRIVER_BLOCKED => {
            "WinDivertOpen: the WinDivert driver was blocked (signature, Secure Boot policy \
             or anti-cheat); try `mode = \"tun\"` once Wintun mode lands"
                .into()
        }
        ERROR_INVALID_PARAMETER => match compile(api, filter, layer) {
            Err(e) => format!("WinDivertOpen: invalid filter ({e})"),
            Ok(()) => format!("WinDivertOpen: invalid parameter (layer {layer})"),
        },
        _ => format!("WinDivertOpen failed with error {code}"),
    };
    io::Error::other(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compiles the filters we use with the real DLL, when it has been
    /// unpacked into `target/windivert` (otherwise there is nothing to test
    /// against).
    #[test]
    fn our_filters_compile() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/windivert/WinDivert-2.2.2-A/x64");
        if !dir.join("WinDivert.dll").exists() {
            eprintln!("skipping: {} has no WinDivert.dll", dir.display());
            return;
        }
        let api = load_from(&dir).expect("load WinDivert.dll");
        let nodes = [std::net::Ipv4Addr::new(203, 0, 113, 1)];
        compile(
            &api,
            &crate::capture::windivert::filter(&nodes),
            LAYER_NETWORK,
        )
        .unwrap();
        compile(&api, crate::capture::windivert::SOCKET_FILTER, LAYER_SOCKET).unwrap();
        let bad = compile(&api, "outbound and !(tcp and udp)", LAYER_NETWORK).unwrap_err();
        assert!(bad.contains("position"), "{bad}");
    }
}
