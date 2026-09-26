//! Latency probes the node runs on a client's behalf (SPEC §7.6): ICMP
//! echo over a raw socket, or TCP connects, where both a SYN-ACK and a RST
//! count as a reply. Each probe sends `count` pings `interval` apart and
//! reports once every ping was answered or timed out.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use mio::net::TcpStream;
use mio::unix::SourceFd;
use mio::{Interest, Registry, Token};
use skyblock_proto::Micros;
use skyblock_proto::frame::{ProbeKind, ProbeReq, ProbeResp};
use skyblock_proto::ip::{Ipv4Packet, PROTO_ICMP, checksum};
use skyblock_proto::timing::{MS, SECOND};
use tracing::{debug, warn};

/// Tokens of TCP probe sockets start here.
pub const TCP_TOKEN_BASE: usize = 1 << 30;
/// A ping unanswered for this long is lost.
const ATTEMPT_TIMEOUT: Micros = 2 * SECOND;
const MAX_PER_USER: usize = 4;
const MAX_TOTAL: usize = 32;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;

/// A finished probe.
pub struct Finished {
    pub user: usize,
    pub resp: ProbeResp,
}

struct Attempt {
    seq: u16,
    sent_at: Micros,
    /// Slot of the TCP socket, for TCP probes.
    tcp: Option<usize>,
}

struct Probe {
    user: usize,
    req: ProbeReq,
    interval: Micros,
    ident: u16,
    sent: u8,
    next_at: Micros,
    outstanding: Vec<Attempt>,
    rtts: Vec<Micros>,
}

impl Probe {
    fn done(&self) -> bool {
        self.sent >= self.req.count && self.outstanding.is_empty()
    }

    fn record(&mut self, seq: u16, now: Micros) -> Option<Attempt> {
        let i = self.outstanding.iter().position(|a| a.seq == seq)?;
        let a = self.outstanding.swap_remove(i);
        self.rtts.push(now.saturating_sub(a.sent_at));
        Some(a)
    }
}

pub struct Prober {
    probes: Vec<Probe>,
    icmp: Option<OwnedFd>,
    /// TCP sockets of outstanding attempts: `(probe ident, seq, stream)`.
    tcp: Vec<Option<(u16, u16, TcpStream)>>,
    next_ident: u16,
}

impl Prober {
    /// Opens the raw ICMP socket (needs root or CAP_NET_RAW; without it,
    /// ICMP probes report nothing sent) and registers it under `token`.
    pub fn new(registry: &Registry, token: Token) -> Self {
        let icmp = match open_icmp() {
            Ok(fd) => {
                if let Err(e) =
                    registry.register(&mut SourceFd(&fd.as_raw_fd()), token, Interest::READABLE)
                {
                    warn!("registering ICMP probe socket: {e}");
                }
                Some(fd)
            }
            Err(e) => {
                warn!("no raw ICMP socket ({e}); ICMP probes disabled");
                None
            }
        };
        Self {
            probes: Vec::new(),
            icmp,
            tcp: Vec::new(),
            next_ident: rand::random(),
        }
    }

    pub fn active(&self) -> usize {
        self.probes.len()
    }

    /// Queues a probe. Returns a result right away if it cannot run.
    pub fn start(&mut self, now: Micros, user: usize, req: ProbeReq) -> Option<Finished> {
        let busy = self.probes.iter().filter(|p| p.user == user).count() >= MAX_PER_USER
            || self.probes.len() >= MAX_TOTAL;
        let unsupported = req.kind == ProbeKind::Icmp && self.icmp.is_none();
        if busy || unsupported {
            return Some(Finished {
                user,
                resp: summarize(req.id, 0, &[]),
            });
        }
        self.next_ident = self.next_ident.wrapping_add(1);
        self.probes.push(Probe {
            user,
            req,
            interval: Micros::from(req.interval_ms) * MS,
            ident: self.next_ident,
            sent: 0,
            next_at: now,
            outstanding: Vec::new(),
            rtts: Vec::new(),
        });
        None
    }

    /// Sends pings that are due, times out old ones and returns the
    /// probes that finished.
    pub fn poll(&mut self, now: Micros, registry: &Registry) -> Vec<Finished> {
        for i in 0..self.probes.len() {
            while self.probes[i].sent < self.probes[i].req.count && self.probes[i].next_at <= now {
                self.send(i, now, registry);
            }
            let p = &mut self.probes[i];
            let (keep, expired): (Vec<Attempt>, Vec<Attempt>) = std::mem::take(&mut p.outstanding)
                .into_iter()
                .partition(|a| now < a.sent_at + ATTEMPT_TIMEOUT);
            p.outstanding = keep;
            for a in expired {
                self.close_tcp(a.tcp, registry);
            }
        }
        let mut finished = Vec::new();
        self.probes.retain(|p| {
            if p.done() {
                finished.push(Finished {
                    user: p.user,
                    resp: summarize(p.req.id, p.sent, &p.rtts),
                });
                false
            } else {
                true
            }
        });
        finished
    }

    /// When `poll` next has something to do.
    pub fn next_due(&self) -> Option<Micros> {
        self.probes
            .iter()
            .flat_map(|p| {
                let send = (p.sent < p.req.count).then_some(p.next_at);
                let timeout = p
                    .outstanding
                    .iter()
                    .map(|a| a.sent_at + ATTEMPT_TIMEOUT)
                    .min();
                send.into_iter().chain(timeout)
            })
            .min()
    }

    /// Reads echo replies from the raw socket.
    pub fn on_icmp(&mut self, now: Micros) {
        let Some(fd) = &self.icmp else { return };
        let mut buf = [0u8; 1500];
        loop {
            // SAFETY: reading into a local buffer from our own socket.
            let n = unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::WouldBlock {
                    debug!("icmp recv: {e}");
                }
                return;
            }
            let Some((from, ident, seq)) = parse_echo_reply(&buf[..n as usize]) else {
                continue;
            };
            if let Some(p) = self
                .probes
                .iter_mut()
                .find(|p| p.ident == ident && p.req.ip == from && p.req.kind == ProbeKind::Icmp)
            {
                p.record(seq, now);
            }
        }
    }

    /// Handles readiness of a TCP probe socket.
    pub fn on_tcp(&mut self, now: Micros, token: Token, registry: &Registry) {
        let slot = token.0 - TCP_TOKEN_BASE;
        let Some(Some((ident, seq, stream))) = self.tcp.get(slot) else {
            return;
        };
        // A RST means the target answered, just not with an open port.
        let answered = match stream.take_error() {
            Ok(Some(e)) | Err(e) => e.kind() == io::ErrorKind::ConnectionRefused,
            Ok(None) => match stream.peer_addr() {
                Ok(_) => true,
                Err(e) if e.kind() == io::ErrorKind::NotConnected => return,
                Err(_) => false,
            },
        };
        let (ident, seq) = (*ident, *seq);
        if let Some(p) = self.probes.iter_mut().find(|p| p.ident == ident) {
            if answered {
                p.record(seq, now);
            } else if let Some(i) = p.outstanding.iter().position(|a| a.seq == seq) {
                p.outstanding.swap_remove(i);
            }
        }
        self.close_tcp(Some(slot), registry);
    }

    fn send(&mut self, i: usize, now: Micros, registry: &Registry) {
        let p = &mut self.probes[i];
        let seq = u16::from(p.sent);
        p.sent += 1;
        p.next_at = now + p.interval;
        let (ident, req) = (p.ident, p.req);
        let tcp = match req.kind {
            ProbeKind::Icmp => {
                let fd = self.icmp.as_ref().expect("checked in start");
                if let Err(e) = send_echo(fd, req.ip, ident, seq) {
                    debug!(target = %req.ip, "icmp send: {e}");
                    return;
                }
                None
            }
            ProbeKind::Tcp => {
                let addr = SocketAddr::V4(SocketAddrV4::new(req.ip, req.port));
                match self.connect(addr, ident, seq, registry) {
                    Ok(slot) => Some(slot),
                    Err(e) => {
                        debug!(%addr, "tcp probe: {e}");
                        return;
                    }
                }
            }
        };
        self.probes[i].outstanding.push(Attempt {
            seq,
            sent_at: now,
            tcp,
        });
    }

    fn connect(
        &mut self,
        addr: SocketAddr,
        ident: u16,
        seq: u16,
        registry: &Registry,
    ) -> io::Result<usize> {
        let mut stream = TcpStream::connect(addr)?;
        let slot = self
            .tcp
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                self.tcp.push(None);
                self.tcp.len() - 1
            });
        registry.register(
            &mut stream,
            Token(TCP_TOKEN_BASE + slot),
            Interest::WRITABLE,
        )?;
        self.tcp[slot] = Some((ident, seq, stream));
        Ok(slot)
    }

    fn close_tcp(&mut self, slot: Option<usize>, registry: &Registry) {
        if let Some((_, _, mut s)) = slot.and_then(|i| self.tcp.get_mut(i)?.take()) {
            let _ = registry.deregister(&mut s);
        }
    }
}

/// PROBE_RESP from the round-trip times of the pings that were answered.
pub fn summarize(id: u32, sent: u8, rtts: &[Micros]) -> ProbeResp {
    let us = |v: Micros| v.min(Micros::from(u32::MAX)) as u32;
    let n = rtts.len() as Micros;
    ProbeResp {
        id,
        sent,
        recv: rtts.len().min(usize::from(u8::MAX)) as u8,
        min_us: us(rtts.iter().copied().min().unwrap_or(0)),
        avg_us: us(rtts.iter().sum::<Micros>().checked_div(n).unwrap_or(0)),
        max_us: us(rtts.iter().copied().max().unwrap_or(0)),
    }
}

/// ICMP echo request with identifier `ident` and sequence `seq`.
pub fn echo_request(ident: u16, seq: u16) -> [u8; 16] {
    let mut m = [0u8; 16];
    m[0] = ICMP_ECHO_REQUEST;
    m[4..6].copy_from_slice(&ident.to_be_bytes());
    m[6..8].copy_from_slice(&seq.to_be_bytes());
    m[8..].copy_from_slice(b"skyblock");
    let c = checksum(&m);
    m[2..4].copy_from_slice(&c.to_be_bytes());
    m
}

/// `(source, identifier, sequence)` of an echo reply as read from a raw
/// socket (IPv4 header included).
pub fn parse_echo_reply(pkt: &[u8]) -> Option<(Ipv4Addr, u16, u16)> {
    let ip = Ipv4Packet::parse(pkt).ok()?;
    if ip.protocol() != PROTO_ICMP || ip.is_fragment() {
        return None;
    }
    let m = ip.payload();
    if m.len() < 8 || m[0] != ICMP_ECHO_REPLY || m[1] != 0 {
        return None;
    }
    Some((
        ip.src(),
        u16::from_be_bytes([m[4], m[5]]),
        u16::from_be_bytes([m[6], m[7]]),
    ))
}

fn open_icmp() -> io::Result<OwnedFd> {
    // SAFETY: plain syscall; the fd is owned below.
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::IPPROTO_ICMP,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor nobody else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn send_echo(fd: &OwnedFd, dst: Ipv4Addr, ident: u16, seq: u16) -> io::Result<()> {
    let msg = echo_request(ident, seq);
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(dst).to_be(),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: valid buffer and sockaddr_in for the duration of the call.
    let n = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            msg.as_ptr().cast(),
            msg.len(),
            0,
            (&addr as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mio::{Events, Poll};
    use skyblock_proto::ip::checksum_valid;
    use std::time::{Duration, Instant};

    #[test]
    fn echo_messages() {
        let m = echo_request(0x1234, 7);
        assert!(checksum_valid(&m));
        // As a reply would come back: IPv4 header + type 0.
        let mut pkt = vec![
            0x45, 0, 0, 36, 0, 0, 0, 0, 64, 1, 0, 0, 203, 0, 113, 9, 10, 0, 0, 1,
        ];
        let mut reply = m;
        reply[0] = ICMP_ECHO_REPLY;
        pkt.extend_from_slice(&reply);
        assert_eq!(
            parse_echo_reply(&pkt),
            Some((Ipv4Addr::new(203, 0, 113, 9), 0x1234, 7))
        );
        pkt[20] = ICMP_ECHO_REQUEST;
        assert_eq!(parse_echo_reply(&pkt), None);
    }

    #[test]
    fn summary() {
        let r = summarize(3, 5, &[10, 30, 20]);
        assert_eq!((r.id, r.sent, r.recv), (3, 5, 3));
        assert_eq!((r.min_us, r.avg_us, r.max_us), (10, 20, 30));
        let r = summarize(4, 5, &[]);
        assert_eq!((r.recv, r.min_us, r.avg_us, r.max_us), (0, 0, 0, 0));
    }

    /// Runs one probe to completion against the local stack.
    fn run(req: ProbeReq) -> ProbeResp {
        let mut poll = Poll::new().unwrap();
        let mut prober = Prober::new(poll.registry(), Token(1));
        let start = Instant::now();
        let now = || start.elapsed().as_micros() as Micros;
        if let Some(f) = prober.start(now(), 0, req) {
            return f.resp;
        }
        let mut events = Events::with_capacity(16);
        loop {
            if let Some(f) = prober.poll(now(), poll.registry()).pop() {
                return f.resp;
            }
            let wait = prober
                .next_due()
                .map_or(10 * MS, |d| d.saturating_sub(now()).max(100));
            poll.poll(&mut events, Some(Duration::from_micros(wait)))
                .unwrap();
            for e in events.iter() {
                if e.token() == Token(1) {
                    prober.on_icmp(now());
                } else {
                    prober.on_tcp(now(), e.token(), poll.registry());
                }
            }
        }
    }

    fn tcp_req(port: u16, count: u8) -> ProbeReq {
        ProbeReq {
            id: 1,
            kind: ProbeKind::Tcp,
            ip: Ipv4Addr::LOCALHOST,
            port,
            count,
            interval_ms: 10,
        }
    }

    #[test]
    fn tcp_probe_counts_accepts_and_resets() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open = listener.local_addr().unwrap().port();
        let r = run(tcp_req(open, 3));
        assert_eq!((r.sent, r.recv), (3, 3));
        assert!(r.min_us <= r.avg_us && r.avg_us <= r.max_us);

        // A closed port answers with RST: still a reply.
        drop(listener);
        let r = run(tcp_req(open, 2));
        assert_eq!((r.sent, r.recv), (2, 2));
    }

    #[test]
    fn icmp_probe_to_localhost_when_permitted() {
        let r = run(ProbeReq {
            id: 2,
            kind: ProbeKind::Icmp,
            ip: Ipv4Addr::LOCALHOST,
            port: 0,
            count: 3,
            interval_ms: 10,
        });
        // Without CAP_NET_RAW nothing is sent.
        assert!(r.sent == 0 || r.recv == 3, "{r:?}");
    }
}
