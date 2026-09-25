//! Linux event loop (SPEC §7.1): one mio thread multiplexing the tunnel
//! sockets, the TUN device and the NAT sockets.

use std::io;
use std::net::SocketAddr;
use std::ops::Range;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use mio::net::UdpSocket;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Registry, Token};
use skyblock_proto::Micros;
use skyblock_proto::ip::{Ipv4Packet, PROTO_UDP};
use skyblock_proto::packet::DATA_PAD_MAX;
use skyblock_proto::timing::{MS, SECOND};
use skyblock_sys::tun::Tun;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::core::{Core, CoreParams, ServerIo, User};
use crate::filter::InnerFilter;
use crate::nat::{Nat, Outbound};
use crate::setup;

const TUN_TOKEN: Token = Token(1 << 15);
const TICK: Micros = 100 * MS;
const STATS_EVERY: Micros = 60 * SECOND;
const BUF_LEN: usize = 65536;

/// Inner packets handed over by the core, processed once it returns.
#[derive(Default)]
struct Deliveries {
    data: Vec<u8>,
    items: Vec<(usize, Range<usize>)>,
}

/// I/O for datagrams from clients: sends immediately, queues deliveries.
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
    let filter = InnerFilter::new(cfg.subnet, cfg.allow_destinations.clone(), Some(egress_ip));
    let mut core = Core::new(cfg.private_key.clone(), users, params, filter);
    let mut nat = Nat::new(
        egress_ip,
        Some(egress_ip),
        cfg.nat_port_range.clone(),
        cfg.udp_nat_timeout,
    );
    info!(
        public_key = %cfg.private_key.public_key(),
        ports = ?cfg.ports,
        %egress,
        %egress_ip,
        users = cfg.users.len(),
        "skyblock-server running"
    );

    let start = Instant::now();
    let clock = || start.elapsed().as_micros() as Micros;
    let mut events = Events::with_capacity(256);
    let mut buf = vec![0u8; BUF_LEN];
    let mut scratch = vec![0u8; BUF_LEN];
    let mut out = vec![0u8; BUF_LEN];
    let mut deliveries = Deliveries::default();
    let (mut next_tick, mut next_stats) = (TICK, STATS_EVERY);

    loop {
        let timeout = Duration::from_micros(next_tick.saturating_sub(clock()));
        if let Err(e) = poll.poll(&mut events, Some(timeout)) {
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e.into());
        }
        let now = clock();
        for event in events.iter() {
            match event.token() {
                TUN_TOKEN => loop {
                    let n = match tun.recv(&mut buf) {
                        Ok(n) => n,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            warn!("tun read: {e}");
                            break;
                        }
                    };
                    let Ok(p) = Ipv4Packet::parse(&buf[..n]) else {
                        continue;
                    };
                    if let Some(u) = core.user_by_vip(p.dst()) {
                        core.send_ip(now, u, &buf[..n], &mut SendOnly(&socks));
                    }
                },
                Token(i) if i < socks.len() => {
                    loop {
                        let (n, from) = match socks[i].recv_from(&mut buf) {
                            Ok(r) => r,
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(e) => {
                                debug!("tunnel recv: {e}");
                                break;
                            }
                        };
                        let mut io = LoopIo {
                            socks: &socks,
                            out: &mut deliveries,
                        };
                        core.handle_datagram(now, i, from, &mut buf[..n], &mut io);
                    }
                    flush(
                        now,
                        &mut deliveries,
                        &mut core,
                        &mut nat,
                        &tun,
                        poll.registry(),
                        &socks,
                    );
                }
                token => {
                    if let Some(slot) = Nat::slot_for(token) {
                        nat.drain(slot, &mut scratch, &mut out, |user, ip| {
                            core.send_ip(now, user, ip, &mut SendOnly(&socks));
                        });
                    }
                }
            }
        }
        if now >= next_tick {
            core.tick(now);
            nat.expire(now, poll.registry());
            next_tick = now + TICK;
        }
        if now >= next_stats {
            info!(
                sessions = core.session_count(),
                nat_mappings = nat.len(),
                stats = ?core.stats,
                "stats"
            );
            next_stats = now + STATS_EVERY;
        }
    }
}

/// Routes inner packets from clients: UDP to the NAT, the rest to TUN.
fn flush(
    now: Micros,
    d: &mut Deliveries,
    core: &mut Core,
    nat: &mut Nat,
    tun: &Tun,
    registry: &Registry,
    socks: &[UdpSocket],
) {
    for (user, range) in d.items.drain(..) {
        let pkt = &d.data[range];
        let Ok(p) = Ipv4Packet::parse(pkt) else {
            continue;
        };
        if p.protocol() == PROTO_UDP {
            if p.is_fragment() {
                debug!(user, "fragmented UDP not supported yet");
                continue;
            }
            match nat.outbound(now, registry, user, &p) {
                Outbound::Sent => {}
                Outbound::Hairpin { user, packet } => {
                    core.send_ip(now, user, &packet, &mut SendOnly(socks));
                }
                Outbound::Dropped(reason) => debug!(user, reason, "nat drop"),
            }
        } else if let Err(e) = tun.send(pkt) {
            if e.kind() != io::ErrorKind::WouldBlock {
                debug!("tun write: {e}");
            }
        }
    }
    d.data.clear();
}
