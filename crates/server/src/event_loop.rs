//! Linux event loop (SPEC §7.1): one mio thread multiplexing the tunnel
//! sockets, the TUN device, the NAT sockets, the DNS upstream socket, the
//! probe sockets and the control socket for `status`.

use std::fmt::Write as _;
use std::io::{self, Write as _};
use std::net::SocketAddr;
use std::ops::Range;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use mio::net::UdpSocket;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Registry, Token};
use skyblock_proto::Micros;
use skyblock_proto::frame::{Frame, ProbeReq};
use skyblock_proto::ip::{Ipv4Packet, PROTO_UDP};
use skyblock_proto::ipfrag::Ipv4Reassembler;
use skyblock_proto::packet::DATA_PAD_MAX;
use skyblock_proto::timing::{MS, SECOND};
use skyblock_sys::tun::Tun;
use tracing::{debug, info, warn};

use crate::config::{Config, parse_resolv_conf};
use crate::core::{Core, CoreParams, ServerIo, User, duration};
use crate::dns::DnsForwarder;
use crate::filter::InnerFilter;
use crate::nat::{Nat, Outbound};
use crate::probe::{self, Prober};
use crate::setup;

const TUN_TOKEN: Token = Token(1 << 15);
const TIMER_TOKEN: Token = Token((1 << 15) + 1);
const DNS_TOKEN: Token = Token((1 << 15) + 2);
const ICMP_TOKEN: Token = Token((1 << 15) + 3);
const CONTROL_TOKEN: Token = Token((1 << 15) + 4);
const TICK: Micros = 100 * MS;
const STATS_EVERY: Micros = 60 * SECOND;
const BUF_LEN: usize = 65536;
/// Concurrent reassemblies of inner IPv4 fragments.
const REASSEMBLY_SLOTS: usize = 64;

/// Inner packets and probe requests handed over by the core, processed
/// once it returns.
#[derive(Default)]
struct Deliveries {
    data: Vec<u8>,
    items: Vec<(usize, Range<usize>)>,
    probes: Vec<(usize, ProbeReq)>,
}

/// I/O for datagrams from clients: sends immediately, queues the rest.
struct LoopIo<'a> {
    socks: &'a [UdpSocket],
    out: &'a mut Deliveries,
}

impl ServerIo for LoopIo<'_> {
    fn send(&mut self, sock: usize, to: SocketAddr, pkt: &[u8]) {
        send(self.socks, sock, to, pkt);
    }

    fn deliver(&mut self, user: usize, ip: &[u8]) {
        let start = self.out.data.len();
        self.out.data.extend_from_slice(ip);
        self.out.items.push((user, start..self.out.data.len()));
    }

    fn probe(&mut self, user: usize, req: ProbeReq) {
        self.out.probes.push((user, req));
    }
}

/// I/O for traffic towards clients, which never delivers.
struct SendOnly<'a>(&'a [UdpSocket]);

impl ServerIo for SendOnly<'_> {
    fn send(&mut self, sock: usize, to: SocketAddr, pkt: &[u8]) {
        send(self.0, sock, to, pkt);
    }

    fn deliver(&mut self, _user: usize, _ip: &[u8]) {
        debug_assert!(false, "send path never delivers");
    }
}

fn send(socks: &[UdpSocket], sock: usize, to: SocketAddr, pkt: &[u8]) {
    if let Err(e) = socks[sock].send_to(pkt, to) {
        if e.kind() != io::ErrorKind::WouldBlock {
            debug!(%to, "tunnel send: {e}");
        }
    }
}

/// Everything the loop owns besides the poller.
struct Node {
    core: Core,
    nat: Nat,
    dns: DnsForwarder,
    dns_sock: Option<UdpSocket>,
    reasm: Ipv4Reassembler,
    prober: Prober,
    tun: Tun,
    socks: Vec<UdpSocket>,
    ports: Vec<u16>,
    control: Option<UnixListener>,
    about: String,
    started: Instant,
    buf: Vec<u8>,
    scratch: Vec<u8>,
    out: Vec<u8>,
    deliveries: Deliveries,
    /// Poll with a zero timeout (`busy_poll`).
    busy_poll: bool,
}

pub fn run(cfg: Config) -> Result<()> {
    let (egress, egress_ip) = setup::egress(&cfg)?;
    let tun = Tun::open(&cfg.tun, true).context("creating TUN device (are you root?)")?;
    tun.configure(cfg.gateway(), cfg.subnet.prefix_len(), cfg.mtu)?;
    setup::prepare_system(&cfg, &egress)?;

    let mut poll = Poll::new()?;
    let mut socks = Vec::with_capacity(cfg.ports.len());
    for (i, &port) in cfg.ports.iter().enumerate() {
        let addr = SocketAddr::new(cfg.listen_ip, port);
        let mut s = UdpSocket::bind(addr).with_context(|| format!("binding {addr}"))?;
        poll.registry()
            .register(&mut s, Token(i), Interest::READABLE)?;
        socks.push(s);
    }
    poll.registry().register(
        &mut SourceFd(&tun.as_raw_fd()),
        TUN_TOKEN,
        Interest::READABLE,
    )?;

    let users = cfg
        .users
        .iter()
        .map(|u| User::new(u.name.clone(), u.public_key, u.psk, u.vip))
        .collect();
    let params = CoreParams {
        mtu: cfg.mtu,
        resolver: cfg.gateway(),
        pad_max: DATA_PAD_MAX,
    };
    let filter = InnerFilter::new(cfg.subnet, cfg.allow_destinations.clone(), Some(egress_ip))
        .with_resolver(cfg.gateway());
    let core = Core::new(cfg.private_key.clone(), users, params, filter);
    let nat = Nat::new(
        egress_ip,
        Some(egress_ip),
        cfg.nat_port_range.clone(),
        cfg.udp_nat_timeout,
    );

    let upstreams = if cfg.dns_upstream.is_empty() {
        std::fs::read_to_string("/etc/resolv.conf")
            .map(|t| parse_resolv_conf(&t))
            .unwrap_or_default()
    } else {
        cfg.dns_upstream.clone()
    };
    if upstreams.is_empty() {
        warn!(
            "no DNS upstream (dns_upstream is empty and /etc/resolv.conf has no IPv4 nameserver); DNS queries to {} are dropped",
            cfg.gateway()
        );
    }
    let dns_sock = match UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))) {
        Ok(mut s) => {
            poll.registry()
                .register(&mut s, DNS_TOKEN, Interest::READABLE)?;
            Some(s)
        }
        Err(e) => {
            warn!("DNS upstream socket: {e}");
            None
        }
    };
    let dns = DnsForwarder::new(upstreams, cfg.gateway());
    let prober = Prober::new(poll.registry(), ICMP_TOKEN);
    let control = match open_control(&cfg.control_socket, poll.registry()) {
        Ok(l) => Some(l),
        Err(e) => {
            warn!(path = %cfg.control_socket.display(), "control socket: {e:#}; `status` unavailable");
            None
        }
    };
    let about = format!(
        "node key {}\nports {:?}, egress {egress} {egress_ip}, VIP subnet {}, resolver {}\n",
        cfg.private_key.public_key(),
        cfg.ports,
        cfg.subnet,
        cfg.gateway()
    );
    if let Some(cpu) = cfg.cpu {
        pin_to_cpu(cpu).with_context(|| format!("pinning to CPU {cpu}"))?;
    }
    info!(
        public_key = %cfg.private_key.public_key(),
        ports = ?cfg.ports,
        %egress,
        %egress_ip,
        users = cfg.users.len(),
        dns_upstream = ?dns.upstreams(),
        cpu = ?cfg.cpu,
        busy_poll = cfg.busy_poll,
        "skyblock-server running"
    );

    let mut node = Node {
        core,
        nat,
        dns,
        dns_sock,
        reasm: Ipv4Reassembler::new(REASSEMBLY_SLOTS),
        prober,
        tun,
        socks,
        ports: cfg.ports.clone(),
        control,
        about,
        started: Instant::now(),
        buf: vec![0u8; BUF_LEN],
        scratch: vec![0u8; BUF_LEN],
        out: vec![0u8; BUF_LEN],
        deliveries: Deliveries::default(),
        busy_poll: cfg.busy_poll,
    };
    node.run(&mut poll)
}

/// Keeps this (single-threaded) process on one CPU.
fn pin_to_cpu(cpu: usize) -> io::Result<()> {
    // SAFETY: a zeroed cpu_set_t is an empty set; CPU_SET stays within it
    // for cpu < CPU_SETSIZE, which sched_setaffinity checks against the
    // machine anyway.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        if cpu >= libc::CPU_SETSIZE as usize {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        libc::CPU_SET(cpu, &mut set);
        if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

impl Node {
    fn clock(&self) -> Micros {
        self.started.elapsed().as_micros() as Micros
    }

    fn run(&mut self, poll: &mut Poll) -> Result<()> {
        let timer = TimerFd::new().context("creating timerfd")?;
        poll.registry().register(
            &mut SourceFd(&timer.as_raw_fd()),
            TIMER_TOKEN,
            Interest::READABLE,
        )?;
        let mut events = Events::with_capacity(256);
        let (mut next_tick, mut next_stats) = (TICK, STATS_EVERY);
        let mut armed: Option<Micros> = None;

        loop {
            // One timer for housekeeping, delayed copies and probes; epoll
            // timeouts only have millisecond resolution.
            let deadline = [self.core.next_due(), self.prober.next_due()]
                .into_iter()
                .flatten()
                .fold(next_tick, Micros::min);
            if armed != Some(deadline) {
                timer.arm(deadline.saturating_sub(self.clock()));
                armed = Some(deadline);
            }
            // Busy polling: never sleep in the kernel (the timerfd still
            // shows up as an event on the next round).
            let timeout = self.busy_poll.then_some(std::time::Duration::ZERO);
            if let Err(e) = poll.poll(&mut events, timeout) {
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e.into());
            }
            let now = self.clock();
            let registry = poll.registry();
            for event in events.iter() {
                match event.token() {
                    TIMER_TOKEN => {
                        timer.clear();
                        armed = None;
                    }
                    TUN_TOKEN => self.on_tun(now),
                    DNS_TOKEN => self.on_dns_answer(now),
                    ICMP_TOKEN => self.prober.on_icmp(now),
                    CONTROL_TOKEN => self.on_control(now),
                    Token(i) if i < self.socks.len() => self.on_tunnel(now, i, registry),
                    Token(t) if t >= probe::TCP_TOKEN_BASE => {
                        self.prober.on_tcp(now, Token(t), registry)
                    }
                    token => {
                        if let Some(slot) = Nat::slot_for(token) {
                            let Node {
                                nat,
                                core,
                                socks,
                                scratch,
                                out,
                                ..
                            } = self;
                            nat.drain(slot, scratch, out, |user, ip| {
                                core.send_ip(now, user, ip, &mut SendOnly(socks));
                            });
                        }
                    }
                }
            }
            for f in self.prober.poll(now, registry) {
                self.core.send_control(
                    f.user,
                    &Frame::ProbeResp(f.resp),
                    &mut SendOnly(&self.socks),
                );
            }
            self.core.poll(now, &mut SendOnly(&self.socks));
            if now >= next_tick {
                self.core.tick(now, &mut SendOnly(&self.socks));
                self.nat.expire(now, registry);
                self.dns.expire(now);
                self.reasm.expire(now);
                next_tick = now + TICK;
            }
            if now >= next_stats {
                info!(
                    sessions = self.core.session_count(),
                    nat_mappings = self.nat.len(),
                    stats = ?self.core.stats,
                    sched = ?self.core.sched_stats(),
                    dns = ?self.dns.stats,
                    "stats"
                );
                next_stats = now + STATS_EVERY;
            }
        }
    }

    fn on_tun(&mut self, now: Micros) {
        loop {
            let n = match self.tun.recv(&mut self.buf) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    warn!("tun read: {e}");
                    break;
                }
            };
            let Ok(p) = Ipv4Packet::parse(&self.buf[..n]) else {
                continue;
            };
            if let Some(u) = self.core.user_by_vip(p.dst()) {
                self.core
                    .send_ip(now, u, &self.buf[..n], &mut SendOnly(&self.socks));
            }
        }
    }

    fn on_tunnel(&mut self, now: Micros, i: usize, registry: &Registry) {
        loop {
            let (n, from) = match self.socks[i].recv_from(&mut self.buf) {
                Ok(r) => r,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    debug!("tunnel recv: {e}");
                    break;
                }
            };
            let mut io = LoopIo {
                socks: &self.socks,
                out: &mut self.deliveries,
            };
            self.core
                .handle_datagram(now, i, from, &mut self.buf[..n], &mut io);
        }
        self.flush(now, registry);
    }

    /// Routes inner packets from clients: UDP to the resolver or the NAT
    /// (reassembled first if fragmented), the rest to TUN. Starts probes.
    fn flush(&mut self, now: Micros, registry: &Registry) {
        let mut d = std::mem::take(&mut self.deliveries);
        for (user, range) in d.items.drain(..) {
            let pkt = &d.data[range];
            let Ok(p) = Ipv4Packet::parse(pkt) else {
                continue;
            };
            if p.protocol() != PROTO_UDP {
                if let Err(e) = self.tun.send(pkt) {
                    if e.kind() != io::ErrorKind::WouldBlock {
                        debug!("tun write: {e}");
                    }
                }
                continue;
            }
            if !p.is_fragment() {
                self.route_udp(now, registry, user, pkt);
                continue;
            }
            match self.reasm.push(now, pkt) {
                Ok(Some(whole)) => {
                    let whole = whole.to_vec();
                    self.route_udp(now, registry, user, &whole);
                }
                Ok(None) => {}
                Err(e) => debug!(user, "inner fragment dropped: {e}"),
            }
        }
        for (user, req) in d.probes.drain(..) {
            if let Some(f) = self.prober.start(now, user, req) {
                self.core.send_control(
                    f.user,
                    &Frame::ProbeResp(f.resp),
                    &mut SendOnly(&self.socks),
                );
            }
        }
        d.data.clear();
        self.deliveries = d;
    }

    fn route_udp(&mut self, now: Micros, registry: &Registry, user: usize, pkt: &[u8]) {
        let Ok(p) = Ipv4Packet::parse(pkt) else {
            return;
        };
        if self.core.filter().is_dns_query(&p) {
            let Some(sock) = &self.dns_sock else { return };
            if let Some((to, n)) = self.dns.query(now, user, &p, &mut self.scratch) {
                if let Err(e) = sock.send_to(&self.scratch[..n], to) {
                    debug!(%to, "dns forward: {e}");
                }
            }
            return;
        }
        match self.nat.outbound(now, registry, user, &p) {
            Outbound::Sent => {}
            Outbound::Hairpin { user, packet } => {
                self.core
                    .send_ip(now, user, &packet, &mut SendOnly(&self.socks));
            }
            Outbound::Dropped(reason) => debug!(user, reason, "nat drop"),
        }
    }

    fn on_dns_answer(&mut self, now: Micros) {
        let Some(sock) = &self.dns_sock else { return };
        loop {
            let (n, from) = match sock.recv_from(&mut self.scratch) {
                Ok(r) => r,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(e) => {
                    debug!("dns recv: {e}");
                    return;
                }
            };
            if let Some((user, len)) = self.dns.answer(from, &self.scratch[..n], &mut self.out) {
                self.core
                    .send_ip(now, user, &self.out[..len], &mut SendOnly(&self.socks));
            }
        }
    }

    /// Answers `skyblock-server status`: each connection gets the report.
    fn on_control(&mut self, now: Micros) {
        let Some(listener) = &self.control else {
            return;
        };
        loop {
            let mut stream = match listener.accept() {
                Ok((s, _)) => s,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(e) => {
                    debug!("control accept: {e}");
                    return;
                }
            };
            let report = self.report(now);
            let _ = stream.set_nonblocking(false);
            let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
            if let Err(e) = stream.write_all(report.as_bytes()) {
                debug!("control write: {e}");
            }
        }
    }

    fn report(&self, now: Micros) -> String {
        let mut r = format!(
            "skyblock-server {} up {}\n{}",
            env!("CARGO_PKG_VERSION"),
            duration(now),
            self.about
        );
        let s = &self.core.stats;
        let sched = self.core.sched_stats();
        let d = &self.dns.stats;
        let _ = writeln!(
            r,
            "sessions {}/{} users, NAT mappings {}, probes running {}, reassemblies {}",
            self.core.session_count(),
            self.core.user_count(),
            self.nat.len(),
            self.prober.active(),
            self.reasm.pending(),
        );
        let _ = writeln!(
            r,
            "handshakes {} (rejected {}, rate-limited {}), rekeys {}, roamed {}, unauthenticated {}",
            s.handshakes,
            s.rejected_handshakes,
            s.rate_limited,
            s.rekeys,
            s.roamed,
            s.unauthenticated
        );
        let _ = writeln!(
            r,
            "inner packets: delivered {}, filtered {}, sent {} (bulk {}), extra copies {} (dropped {})",
            s.delivered, s.filtered, s.sent, s.sent_bulk, sched.copies_sent, sched.copies_dropped
        );
        let _ = writeln!(
            r,
            "dns via {:?}: queries {}, retries {}, answers {}, timeouts {}, dropped {}, pending {}; probes {}",
            self.dns.upstreams(),
            d.queries,
            d.retries,
            d.answers,
            d.timeouts,
            d.dropped,
            self.dns.pending(),
            s.probes
        );
        let nat = &self.nat;
        self.core.report(
            now,
            &self.ports,
            |u| format!(", NAT mappings {}", nat.user_mappings(u)),
            &mut r,
        );
        r
    }
}

/// Binds the control socket (replacing a stale one), owner-only.
fn open_control(path: &Path, registry: &Registry) -> Result<UnixListener> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        anyhow::ensure!(
            meta.file_type().is_socket(),
            "{} exists and is not a socket",
            path.display()
        );
        std::fs::remove_file(path)?;
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    registry.register(
        &mut SourceFd(&listener.as_raw_fd()),
        CONTROL_TOKEN,
        Interest::READABLE,
    )?;
    Ok(listener)
}

/// A non-blocking one-shot `timerfd` on `CLOCK_MONOTONIC`.
struct TimerFd(OwnedFd);

impl TimerFd {
    fn new() -> io::Result<Self> {
        // SAFETY: plain syscall; the returned fd is owned below.
        let fd = unsafe {
            libc::timerfd_create(
                libc::CLOCK_MONOTONIC,
                libc::TFD_NONBLOCK | libc::TFD_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh descriptor nobody else owns.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    /// Fires once, `after` microseconds from now (at least 1µs: zero
    /// would disarm it).
    fn arm(&self, after: Micros) {
        let after = after.max(1);
        let spec = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: (after / SECOND) as _,
                tv_nsec: ((after % SECOND) * 1000) as _,
            },
        };
        // SAFETY: valid timerfd and itimerspec.
        let r =
            unsafe { libc::timerfd_settime(self.0.as_raw_fd(), 0, &spec, std::ptr::null_mut()) };
        if r != 0 {
            warn!("timerfd_settime: {}", io::Error::last_os_error());
        }
    }

    /// Consumes the expiration count so the fd stops being readable.
    fn clear(&self) {
        let mut n = [0u8; 8];
        // SAFETY: reading 8 bytes into a local buffer.
        unsafe {
            libc::read(self.0.as_raw_fd(), n.as_mut_ptr().cast(), n.len());
        }
    }
}

impl AsRawFd for TimerFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
