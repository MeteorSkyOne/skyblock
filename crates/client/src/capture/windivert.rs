//! WinDivert per-process capture (SPEC §6.2).
//!
//! Every outbound TCP/UDP packet to a public address passes through user
//! space. Each flow (5-tuple) is decided once, on its first packet, and keeps
//! that decision for its lifetime: moving a live flow between the tunnel and
//! the direct path would change its source address and break it.
//!
//! - A local port the socket-event cache attributes to a game is trusted at
//!   once, on the capture thread, so game packets never wait.
//! - Anything else (unknown, or cached as non-game, which can be stale when a
//!   game socket reuses a port) is verified against the system tables on a
//!   helper thread. A game's first packet therefore never leaves directly,
//!   and table lookups (0.2-0.4ms) never block the capture thread.
//! - Packets whose owner never appears in the tables (connections made by
//!   other drivers, e.g. other accelerators) go out directly after
//!   `HOLD_MAX`.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use skyblock_proto::ip::Ipv4Packet;
use tracing::{debug, info, trace, warn};

use super::{Capture, Sink};
use crate::flows::FlowTable;
use crate::procmap::{Decision, ProcMap};
use crate::windivert::{
    Address, EVENT_SOCKET_ACCEPT, EVENT_SOCKET_BIND, EVENT_SOCKET_CLOSE, EVENT_SOCKET_CONNECT,
    FLAG_RECV_ONLY, FLAG_SNIFF, Handle, LAYER_NETWORK, LAYER_SOCKET,
};

/// A socket is in the system tables before its first packet is sent, so
/// this only bounds the wait for flows that never show up there.
const HOLD_MAX: Duration = Duration::from_millis(15);
const HOLD_RETRY: Duration = Duration::from_millis(5);
/// Flow decisions unused for this long are forgotten.
const FLOW_IDLE: Duration = Duration::from_secs(120);
const REPORT_EVERY: Duration = Duration::from_secs(10);

/// Destinations never tunneled: private, loopback, link-local, CGNAT,
/// multicast and reserved ranges.
const EXCLUDED: [(Ipv4Addr, Ipv4Addr); 9] = [
    (Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 255, 255, 255)),
    (Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 255, 255, 255)),
    (
        Ipv4Addr::new(100, 64, 0, 0),
        Ipv4Addr::new(100, 127, 255, 255),
    ),
    (
        Ipv4Addr::new(127, 0, 0, 0),
        Ipv4Addr::new(127, 255, 255, 255),
    ),
    (
        Ipv4Addr::new(169, 254, 0, 0),
        Ipv4Addr::new(169, 254, 255, 255),
    ),
    (
        Ipv4Addr::new(172, 16, 0, 0),
        Ipv4Addr::new(172, 31, 255, 255),
    ),
    (
        Ipv4Addr::new(192, 168, 0, 0),
        Ipv4Addr::new(192, 168, 255, 255),
    ),
    (
        Ipv4Addr::new(224, 0, 0, 0),
        Ipv4Addr::new(239, 255, 255, 255),
    ),
    (
        Ipv4Addr::new(240, 0, 0, 0),
        Ipv4Addr::new(255, 255, 255, 255),
    ),
];

/// Socket events worth learning port owners from.
pub const SOCKET_FILTER: &str = "!loopback and (tcp or udp)";

/// The capture filter: outbound IPv4 TCP/UDP to public addresses other
/// than the nodes themselves.
pub fn filter(nodes: &[Ipv4Addr]) -> String {
    let mut f = String::from("outbound and !loopback and !impostor and ip and (tcp or udp)");
    // WinDivert's `not` only applies to a single test, so "outside the
    // range" is spelled out rather than negating a parenthesized group.
    for (lo, hi) in EXCLUDED {
        if lo == Ipv4Addr::UNSPECIFIED {
            f += &format!(" and ip.DstAddr > {hi}");
        } else if hi == Ipv4Addr::BROADCAST {
            f += &format!(" and ip.DstAddr < {lo}");
        } else {
            f += &format!(" and (ip.DstAddr < {lo} or ip.DstAddr > {hi})");
        }
    }
    for n in nodes {
        f += &format!(" and ip.DstAddr != {n}");
    }
    f
}

/// `(protocol, local port, remote address, remote port)`.
type FlowKey = (u8, u16, Ipv4Addr, u16);

fn flow_key(pkt: &[u8]) -> Option<FlowKey> {
    let p = Ipv4Packet::parse(pkt).ok()?;
    // Non-first fragments carry no ports (handled in M3).
    let (sport, dport) = p.ports()?;
    Some((p.protocol(), sport, p.dst(), dport))
}

struct Held {
    pkt: Vec<u8>,
    addr: Address,
    key: FlowKey,
    since: Instant,
}

/// How captured packets were decided.
#[derive(Default)]
struct Counters {
    /// On the capture thread: known flow, or a port cached as a game's.
    fast: AtomicU64,
    /// On the helper thread, from the system tables.
    verified: AtomicU64,
    /// Owner never found; sent directly.
    timed_out: AtomicU64,
    /// Sent into the tunnel.
    tunneled: AtomicU64,
}

impl Counters {
    fn bump(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> [u64; 4] {
        [&self.fast, &self.verified, &self.timed_out, &self.tunneled]
            .map(|c| c.load(Ordering::Relaxed))
    }
}

type Decisions = HashMap<FlowKey, (Decision, Instant)>;

pub struct WinDivertCapture {
    net: Handle,
    procmap: ProcMap,
    flows: FlowTable<(u32, u32)>,
    decided: Mutex<Decisions>,
    counters: Counters,
}

impl WinDivertCapture {
    pub fn open(processes: &[String], nodes: &[Ipv4Addr], vip: Ipv4Addr, mtu: u16) -> Result<Self> {
        let f = filter(nodes);
        let net = Handle::open(&f, LAYER_NETWORK, 0, 0).context("opening WinDivert")?;
        net.tune_queue();
        info!(processes = ?processes, "WinDivert capture ready");
        Ok(Self {
            net,
            procmap: ProcMap::new(processes),
            flows: FlowTable::new(vip, mtu),
            decided: Mutex::new(HashMap::new()),
            counters: Counters::default(),
        })
    }

    fn decided(&self) -> MutexGuard<'_, Decisions> {
        self.decided.lock().expect("decisions lock")
    }

    /// Capture-thread decision: no system calls.
    fn fast_path(&self, key: FlowKey) -> Option<Decision> {
        let now = Instant::now();
        if let Some(e) = self.decided().get_mut(&key) {
            e.1 = now;
            return Some(e.0);
        }
        if self.procmap.lookup(key.0, key.1) == Some(Decision::Tunnel) {
            self.decided().insert(key, (Decision::Tunnel, now));
            return Some(Decision::Tunnel);
        }
        None
    }

    /// Helper-thread decision from the system tables.
    fn verify(&self, key: FlowKey) -> Option<Decision> {
        // An earlier held packet of the same flow may have settled it.
        if let Some(e) = self.decided().get(&key) {
            return Some(e.0);
        }
        let d = self.procmap.resolve(key.0, key.1)?;
        self.decided().insert(key, (d, Instant::now()));
        Some(d)
    }

    fn act(&self, decision: Decision, pkt: &mut [u8], addr: &Address, sink: &Sink) {
        match decision {
            Decision::Tunnel if self.flows.outbound(pkt, addr.interface()) => {
                Counters::bump(&self.counters.tunneled);
                sink(pkt)
            }
            _ => self.reinject(pkt, addr),
        }
    }

    fn reinject(&self, pkt: &[u8], addr: &Address) {
        if let Err(e) = self.net.send(pkt, addr) {
            debug!("reinject: {e}");
        }
    }

    fn capture_loop(&self, sink: Sink, hold: Sender<Held>) {
        let mut buf = vec![0u8; 65536];
        let mut addr = Address::default();
        loop {
            let n = match self.net.recv(&mut buf, &mut addr) {
                Ok(n) => n,
                Err(e) => {
                    warn!("WinDivert recv: {e}");
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
            };
            let pkt = &mut buf[..n];
            let Some(key) = flow_key(pkt) else {
                self.reinject(pkt, &addr);
                continue;
            };
            match self.fast_path(key) {
                Some(d) => {
                    Counters::bump(&self.counters.fast);
                    self.act(d, pkt, &addr, &sink);
                }
                None => {
                    let held = Held {
                        pkt: pkt.to_vec(),
                        addr,
                        key,
                        since: Instant::now(),
                    };
                    if hold.send(held).is_err() {
                        return;
                    }
                }
            }
        }
    }

    /// Verifies held packets' owners; gives up after `HOLD_MAX` and sends
    /// them directly, as the least-bad option.
    fn hold_loop(&self, sink: Sink, rx: Receiver<Held>) {
        let mut held: Vec<Held> = Vec::new();
        let mut last_report = (Instant::now(), self.counters.snapshot());
        loop {
            let wait = if held.is_empty() {
                Duration::from_secs(1)
            } else {
                HOLD_RETRY
            };
            match rx.recv_timeout(wait) {
                Ok(h) => held.push(h),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            held.extend(rx.try_iter());
            held.retain_mut(|h| {
                let (proto, sport, dst, dport) = h.key;
                match self.verify(h.key) {
                    Some(d) => {
                        Counters::bump(&self.counters.verified);
                        let waited_us = h.since.elapsed().as_micros() as u64;
                        trace!(proto, sport, %dst, dport, ?d, waited_us, "flow verified");
                        self.act(d, &mut h.pkt, &h.addr, &sink);
                        false
                    }
                    None if h.since.elapsed() >= HOLD_MAX => {
                        Counters::bump(&self.counters.timed_out);
                        debug!(proto, sport, %dst, dport, "owner not found; sending directly");
                        self.decided()
                            .insert(h.key, (Decision::Bypass, Instant::now()));
                        self.reinject(&h.pkt, &h.addr);
                        false
                    }
                    None => true,
                }
            });
            if last_report.0.elapsed() >= REPORT_EVERY {
                self.decided()
                    .retain(|_, (_, last)| last.elapsed() < FLOW_IDLE);
                let snap = self.counters.snapshot();
                if snap != last_report.1 {
                    let [fast, verified, timed_out, tunneled] = snap;
                    debug!(fast, verified, timed_out, tunneled, "capture counters");
                }
                last_report = (Instant::now(), snap);
            }
        }
    }

    /// Learns port owners from socket events, ahead of their first packet.
    fn socket_loop(&self, events: Handle) {
        let mut addr = Address::default();
        loop {
            if let Err(e) = events.recv(&mut [], &mut addr) {
                warn!("WinDivert socket events: {e}");
                return;
            }
            let s = addr.socket();
            match addr.event() {
                EVENT_SOCKET_BIND | EVENT_SOCKET_CONNECT | EVENT_SOCKET_ACCEPT => {
                    self.procmap.learn(s.protocol, s.local_port, s.process_id)
                }
                EVENT_SOCKET_CLOSE => self.procmap.forget(s.protocol, s.local_port),
                _ => {}
            }
        }
    }
}

impl Capture for WinDivertCapture {
    fn start(self: Arc<Self>, sink: Sink) -> Result<()> {
        let events = Handle::open(SOCKET_FILTER, LAYER_SOCKET, 0, FLAG_SNIFF | FLAG_RECV_ONLY)
            .context("opening WinDivert socket layer")?;
        let (tx, rx) = mpsc::channel();

        let me = Arc::clone(&self);
        std::thread::Builder::new()
            .name("wd-sockets".into())
            .spawn(move || me.socket_loop(events))?;
        let (me, s) = (Arc::clone(&self), Arc::clone(&sink));
        std::thread::Builder::new()
            .name("wd-hold".into())
            .spawn(move || me.hold_loop(s, rx))?;
        std::thread::Builder::new()
            .name("wd-capture".into())
            .spawn(move || self.capture_loop(sink, tx))?;
        Ok(())
    }

    fn inject(&self, pkt: &mut [u8]) {
        let Some((if_idx, sub_if_idx)) = self.flows.inbound(pkt) else {
            debug!("inbound packet for an unknown flow");
            return;
        };
        if let Err(e) = self.net.send(pkt, &Address::inbound(if_idx, sub_if_idx)) {
            debug!("inject: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_text() {
        let f = filter(&[Ipv4Addr::new(203, 0, 113, 1)]);
        assert!(f.starts_with("outbound and !loopback and !impostor and ip and (tcp or udp)"));
        assert!(f.contains(" and ip.DstAddr > 0.255.255.255 "));
        assert!(f.contains(" and (ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255) "));
        assert!(f.contains(" and ip.DstAddr < 240.0.0.0 "));
        assert!(f.ends_with("and ip.DstAddr != 203.0.113.1"));
        assert!(!f.contains("!("), "WinDivert cannot negate a group");
    }

    #[test]
    fn flow_keys() {
        let mut b = vec![0u8; 64];
        let n = skyblock_proto::ip::build_udp(
            &mut b,
            std::net::SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 2), 5000),
            std::net::SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 27015),
            1,
            b"x",
        )
        .unwrap();
        assert_eq!(
            flow_key(&b[..n]),
            Some((17, 5000, Ipv4Addr::new(203, 0, 113, 9), 27015))
        );
        assert_eq!(flow_key(&[0u8; 10]), None);
    }
}
