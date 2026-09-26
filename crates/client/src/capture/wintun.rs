//! Wintun backend (SPEC §6.3): a virtual adapter whose address is the VIP.
//! Rules mode routes the games' `ip_ranges` (and `[tun] routes`) to it,
//! global mode routes everything (`0.0.0.0/1` + `128.0.0.0/1`) and points
//! the adapter's DNS at the node's resolver. Every node address keeps a
//! `/32` route through the original gateway, added before the tunnel
//! routes so it is looked up while the physical path is still the best.
//!
//! Wintun removes the adapter (and the routes on it) when the process
//! exits, even after a crash. The node routes live on the physical
//! adapter, so they are listed in a state file before they are added and
//! removed on exit, or on the next start after a crash.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use tracing::{debug, error, info, warn};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{
    CreateEventW, INFINITE, SetEvent, WaitForMultipleObjects,
};
use windows_sys::core::GUID;

use super::{Capture, Sink};
use crate::wintun::{self, Route, Session};

/// Fixed so that Windows keeps one network profile for the adapter.
const ADAPTER_GUID: GUID = GUID::from_u128(0x5b0c1d6e_8a3f_4e27_9c41_2f6d7a8b9c10);
/// Interface metric: below physical adapters (which get 25 and up).
const METRIC: u32 = 5;

pub struct WintunCapture {
    session: Session,
    /// Wakes the receive thread to exit.
    quit: HANDLE,
    /// Node routes on the physical adapter, deleted on stop.
    node_routes: Mutex<Vec<Route>>,
}

// SAFETY: the event handle is only signalled and waited on.
unsafe impl Send for WintunCapture {}
unsafe impl Sync for WintunCapture {}

/// What goes into the tunnel.
pub enum Routing<'a> {
    Rules(&'a [Ipv4Net]),
    Global,
}

impl WintunCapture {
    pub fn open(
        name: &str,
        vip: Ipv4Addr,
        mtu: u16,
        routing: Routing<'_>,
        nodes: &[Ipv4Addr],
        resolver: Ipv4Addr,
    ) -> Result<Self> {
        remove_stale_routes();
        let node_routes = add_node_routes(nodes)?;
        let session = match Session::open(name, &ADAPTER_GUID) {
            Ok(s) => s,
            Err(e) => {
                remove_routes(&node_routes);
                return Err(e).context("creating the Wintun adapter (run as administrator)");
            }
        };
        let cap = Self {
            session,
            quit: new_event()?,
            node_routes: Mutex::new(node_routes),
        };
        // From here on, `stop` (or process exit) undoes everything.
        let luid = cap.session.luid();
        wintun::set_address(luid, vip, 32)?;
        wintun::set_mtu_and_metric(luid, mtu, METRIC)?;
        let global = [
            "0.0.0.0/1".parse().expect("valid"),
            "128.0.0.0/1".parse().expect("valid"),
        ];
        let routes = match routing {
            Routing::Rules(r) => r,
            Routing::Global => &global[..],
        };
        let luid = unsafe { luid.Value };
        for prefix in routes.iter().copied().chain([Ipv4Net::from(resolver)]) {
            wintun::add_route(&Route {
                prefix,
                luid,
                next_hop: Ipv4Addr::UNSPECIFIED,
            })?;
        }
        if matches!(routing, Routing::Global) {
            set_dns(name, resolver)?;
        }
        info!(
            adapter = name,
            %vip,
            mtu,
            routes = ?routes,
            global = matches!(routing, Routing::Global),
            "Wintun capture ready"
        );
        Ok(cap)
    }
}

impl Capture for WintunCapture {
    fn start(self: Arc<Self>, sink: Sink) -> Result<()> {
        std::thread::Builder::new()
            .name("wintun-rx".into())
            .spawn(move || {
                let _boost = skyblock_sys::prio::boost_current_thread();
                let wait = [self.session.read_event(), self.quit];
                let mut buf = vec![0u8; 65536];
                loop {
                    match self.session.receive(&mut buf) {
                        Ok(Some(n)) => {
                            if wanted(&buf[..n]) {
                                sink(&mut buf[..n]);
                            }
                        }
                        Ok(None) => {
                            // SAFETY: two valid event handles.
                            let r =
                                unsafe { WaitForMultipleObjects(2, wait.as_ptr(), 0, INFINITE) };
                            if r != WAIT_OBJECT_0 {
                                return;
                            }
                        }
                        Err(e) => {
                            error!("wintun read: {e}");
                            return;
                        }
                    }
                }
            })?;
        Ok(())
    }

    fn inject(&self, pkt: &mut [u8]) {
        if let Err(e) = self.session.send(pkt) {
            debug!("wintun write: {e}");
        }
    }

    fn stop(&self) {
        // SAFETY: valid event handle.
        unsafe { SetEvent(self.quit) };
        let routes = std::mem::take(&mut *self.node_routes.lock().expect("not poisoned"));
        remove_routes(&routes);
        let _ = std::fs::remove_file(state_file());
    }
}

impl Drop for WintunCapture {
    fn drop(&mut self) {
        self.stop();
        // SAFETY: created in `open`, closed once.
        unsafe { CloseHandle(self.quit) };
    }
}

/// IPv4 unicast only: the adapter also sees the system's own multicast
/// and broadcast chatter, which has no business in the tunnel.
fn wanted(pkt: &[u8]) -> bool {
    pkt.len() >= 20 && pkt[0] >> 4 == 4 && pkt[16] < 224 && pkt[16..20] != [255; 4]
}

fn new_event() -> Result<HANDLE> {
    // SAFETY: default security, manual reset, not signalled, unnamed.
    let h = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
    anyhow::ensure!(
        !h.is_null(),
        "CreateEventW: {}",
        std::io::Error::last_os_error()
    );
    Ok(h)
}

fn state_file() -> PathBuf {
    let base = std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into());
    PathBuf::from(base)
        .join("skyblock")
        .join("wintun-routes.txt")
}

fn save_state(routes: &[Route]) -> Result<()> {
    let path = state_file();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let text: String = routes
        .iter()
        .map(|r| format!("{} {} {}\n", r.prefix, r.luid, r.next_hop))
        .collect();
    std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))
}

fn parse_state(text: &str) -> Vec<Route> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            Some(Route {
                prefix: f.next()?.parse().ok()?,
                luid: f.next()?.parse().ok()?,
                next_hop: f.next()?.parse().ok()?,
            })
        })
        .collect()
}

/// Node routes left behind by a run that did not exit cleanly.
fn remove_stale_routes() {
    let path = state_file();
    let Ok(text) = std::fs::read_to_string(&path) else {
        return;
    };
    let routes = parse_state(&text);
    if !routes.is_empty() {
        warn!(
            count = routes.len(),
            "removing node routes left by an earlier run"
        );
    }
    remove_routes(&routes);
    let _ = std::fs::remove_file(&path);
}

fn remove_routes(routes: &[Route]) {
    for r in routes {
        if let Err(e) = wintun::delete_route(r) {
            warn!("{e}");
        }
    }
}

/// `/32` routes to the nodes through whatever path reaches them now.
fn add_node_routes(nodes: &[Ipv4Addr]) -> Result<Vec<Route>> {
    let mut added = Vec::new();
    for &n in nodes {
        if n.is_loopback() || n.is_unspecified() {
            continue;
        }
        let (luid, next_hop) = wintun::best_route(n)?;
        let r = Route {
            prefix: Ipv4Net::from(n),
            luid,
            next_hop,
        };
        // Listed before it exists: a crash in between leaves at worst a
        // harmless delete of a missing route.
        let mut listed = added.clone();
        listed.push(r);
        save_state(&listed)?;
        if wintun::add_route(&r)? {
            added.push(r);
        }
    }
    if added.is_empty() {
        let _ = std::fs::remove_file(state_file());
    } else {
        save_state(&added)?;
    }
    Ok(added)
}

/// Global mode: the adapter's DNS server is the node's resolver. (The
/// adapter disappears on exit, and its settings with it.)
fn set_dns(name: &str, resolver: Ipv4Addr) -> Result<()> {
    skyblock_sys::cmd::run(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            &format!("name={name}"),
            "source=static",
            &format!("address={resolver}"),
            "register=none",
            "validate=no",
        ],
    )
    .context("setting the adapter's DNS server")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trip() {
        let r = vec![
            Route {
                prefix: "1.2.3.4/32".parse().unwrap(),
                luid: 1234567890123,
                next_hop: Ipv4Addr::new(192, 168, 5, 1),
            },
            Route {
                prefix: "5.6.7.8/32".parse().unwrap(),
                luid: 42,
                next_hop: Ipv4Addr::UNSPECIFIED,
            },
        ];
        let text: String = r
            .iter()
            .map(|r| format!("{} {} {}\n", r.prefix, r.luid, r.next_hop))
            .collect();
        assert_eq!(parse_state(&text), r);
        assert!(parse_state("garbage\n1.2.3.4/32 x 1.1.1.1\n").is_empty());
    }

    #[test]
    fn only_ipv4_unicast_goes_in() {
        let mut p = [0u8; 20];
        p[0] = 0x45;
        p[16..20].copy_from_slice(&[198, 19, 0, 3]);
        assert!(wanted(&p));
        p[16..20].copy_from_slice(&[224, 0, 0, 251]);
        assert!(!wanted(&p));
        p[16..20].copy_from_slice(&[255, 255, 255, 255]);
        assert!(!wanted(&p));
        p[0] = 0x60;
        assert!(!wanted(&p));
        assert!(!wanted(&p[..10]));
    }
}
