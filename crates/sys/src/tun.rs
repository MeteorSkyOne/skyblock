//! Linux TUN devices (`IFF_TUN | IFF_NO_PI`: reads and writes are bare IP
//! packets). The device is non-persistent and disappears when closed.

use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;

use crate::cmd;

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

/// `struct ifreq` with the `ifr_flags` member of the union.
#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

pub struct Tun {
    file: File,
    name: String,
}

impl Tun {
    pub fn open(name: &str, nonblocking: bool) -> io::Result<Tun> {
        if name.is_empty() || name.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("bad interface name {name:?}"),
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(if nonblocking { libc::O_NONBLOCK } else { 0 })
            .open("/dev/net/tun")
            .map_err(|e| io::Error::new(e.kind(), format!("/dev/net/tun: {e}")))?;
        let mut req = IfReq {
            name: [0; libc::IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };
        for (d, s) in req.name.iter_mut().zip(name.bytes()) {
            *d = s as libc::c_char;
        }
        // SAFETY: `req` is a correctly laid out ifreq that outlives the call.
        if unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF as _, &mut req) } < 0 {
            let e = io::Error::last_os_error();
            return Err(io::Error::new(e.kind(), format!("TUNSETIFF {name}: {e}")));
        }
        // SAFETY: the kernel returns a NUL-terminated name within the array.
        let actual = unsafe { CStr::from_ptr(req.name.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        Ok(Tun { file, name: actual })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Assigns `addr/prefix`, sets the MTU and brings the link up.
    pub fn configure(&self, addr: Ipv4Addr, prefix: u8, mtu: u16) -> io::Result<()> {
        let cidr = format!("{addr}/{prefix}");
        let mtu = mtu.to_string();
        cmd::run("ip", &["addr", "replace", &cidr, "dev", &self.name])?;
        cmd::run("ip", &["link", "set", "dev", &self.name, "mtu", &mtu, "up"])
    }

    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.file).read(buf)
    }

    pub fn send(&self, pkt: &[u8]) -> io::Result<usize> {
        (&self.file).write(pkt)
    }
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}
