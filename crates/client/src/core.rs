//! Transport-independent client logic (SPEC §3.6, §3.8, §4): handshake with
//! retries, per-path keepalive PINGs and RTT, redundant sending with delayed
//! copies, flow classification, the STATS exchange and dead-session
//! detection. The tunnel threads feed it datagrams and perform the I/O it
//! requests.

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use skyblock_proto::Micros;
use skyblock_proto::flow::{Class, FlowClassifier, FlowKey};
use skyblock_proto::frame::{Frame, FrameReader, MAX_PATHS, PathStats, Ping, Pong, Stats};
use skyblock_proto::handshake::{ClientHello, Initiator, MAX_MSG_LEN, ServerHello, next_timestamp};
use skyblock_proto::ip::Ipv4Packet;
use skyblock_proto::keys::{PrivateKey, Psk, PublicKey, SessionKeys};
use skyblock_proto::packet::PacketBuf;
use skyblock_proto::path::{PathMetrics, Ranking, Rtt, down_after};
use skyblock_proto::sched::{Plan, Policy, Scheduler};
use skyblock_proto::session::{Data, RxState, RxStats, TxState, open_handshake, seal_handshake};
use skyblock_proto::timing::{
    ACTIVE_WINDOW, CLIENT_SESSION_DEAD, HANDSHAKE_GIVE_UP, HANDSHAKE_RETRY, HANDSHAKE_RETRY_MAX,
    MS, PING_ACTIVE, PING_IDLE, PING_JITTER_PCT, SECOND, STATS_ACTIVE, STATS_IDLE,
};
use tracing::{info, warn};

/// Delayed copies due within this much are sent now: the timer thread may
/// wake up slightly early.
const COPY_SLACK: Micros = 300;
/// Longest the core asks to sleep, so path states and ranking stay fresh.
const MAX_POLL: Micros = 100 * MS;

pub trait ClientIo {
    /// Sends a tunnel packet on path `path`.
    fn send(&mut self, path: usize, pkt: &[u8]);
    /// Hands over an inner packet received from the node.
    fn deliver(&mut self, ip: &[u8]);
    /// An echo response arrived (`bench`): its id and send timestamp.
    fn echo(&mut self, _now: Micros, _id: u32, _ts: u64) {}
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ClientStats {
    pub handshakes: u64,
    pub pings: u64,
    pub pongs: u64,
    /// Inner packets sent / delivered, and their bytes.
    pub tx_ip: u64,
    pub tx_bytes: u64,
    pub rx_ip: u64,
    pub rx_bytes: u64,
    /// Inner packets sent as part of a bulk flow (single copy).
    pub tx_bulk: u64,
}

/// A `STATS` frame from the node, with our own counters as they were when
/// it arrived; two of these give exact loss figures over an interval.
#[derive(Debug, Clone, Copy)]
pub struct Exchange {
    pub at: Micros,
    pub peer: Stats,
    pub tx_unique: u64,
    pub rx: RxStats,
    /// Our (tx_pkts, rx_pkts) per path.
    pub paths: [(u64, u64); MAX_PATHS],
}

impl Exchange {
    /// The node's (tx_pkts, rx_pkts) on `path`, if it reported it.
    pub fn peer_path(&self, path: usize) -> Option<(u64, u64)> {
        self.peer
            .paths()
            .iter()
            .find(|p| usize::from(p.path) == path)
            .map(|p| (p.tx_pkts, p.rx_pkts))
    }
}

#[derive(Debug, Clone)]
pub struct PathView {
    pub up: bool,
    pub rtt: Rtt,
    pub loss_out: f32,
    pub loss_in: f32,
}

/// What the status line and `bench` report.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub connected: bool,
    pub stats: ClientStats,
    pub paths: Vec<PathView>,
    pub best: Option<usize>,
    pub flows: usize,
    pub bulk_flows: usize,
    pub exchange: Option<Exchange>,
}

struct Handshake {
    /// `None` after a response failed to verify; retried at `next_retry`.
    init: Option<Initiator>,
    first_sent: Micros,
    next_retry: Micros,
    backoff: Micros,
    warned: bool,
}

struct Session {
    tx: TxState,
    rx: RxState,
    sched: Scheduler,
    hello: ServerHello,
    paths: Vec<PathMetrics>,
    next_ping: Vec<Micros>,
    ranking: Ranking,
    flows: FlowClassifier,
    last_rx: Micros,
    /// Last inner data either way; 0 = never.
    last_active: Micros,
    next_stats: Micros,
    next_expire: Micros,
    exchange: Option<Exchange>,
}

impl Session {
    fn active(&self, now: Micros) -> bool {
        self.last_active != 0 && now.saturating_sub(self.last_active) < ACTIVE_WINDOW
    }

    /// Notes data; after an idle spell, PINGs and STATS go out right away
    /// so path state is fresh while traffic flows.
    fn touch(&mut self, now: Micros) {
        if !self.active(now) {
            self.next_ping.iter_mut().for_each(|t| *t = now);
            self.next_stats = now;
        }
        self.last_active = now;
    }
}

pub struct ClientCore {
    local: PrivateKey,
    node: PublicKey,
    psk: Psk,
    obfs: SessionKeys,
    pad_max: usize,
    n_paths: usize,
    policy: Policy,
    handshake: Option<Handshake>,
    session: Option<Session>,
    last_ts: u64,
    ping_id: u32,
    rng: StdRng,
    hs_buf: PacketBuf,
    pub stats: ClientStats,
}

impl ClientCore {
    pub fn new(
        local: PrivateKey,
        node: PublicKey,
        psk: Psk,
        pad_max: usize,
        n_paths: usize,
        policy: Policy,
    ) -> Self {
        Self {
            obfs: SessionKeys::obfuscation(&node),
            local,
            node,
            psk,
            pad_max,
            n_paths: n_paths.clamp(1, MAX_PATHS),
            policy,
            handshake: None,
            session: None,
            last_ts: 0,
            ping_id: 0,
            rng: StdRng::from_rng(&mut rand::rng()),
            hs_buf: PacketBuf::new(),
            stats: ClientStats::default(),
        }
    }

    pub fn hello(&self) -> Option<ServerHello> {
        self.session.as_ref().map(|s| s.hello)
    }

    /// Changes the redundancy policy for both directions; the node learns
    /// it from the `TUNE` sent with a PING on every path.
    pub fn set_policy(&mut self, now: Micros, policy: Policy, io: &mut impl ClientIo) {
        self.policy = policy;
        if let Some(s) = &mut self.session {
            s.flows
                .set_thresholds(policy.bulk_enter_kbps, policy.bulk_exit_kbps);
        }
        for p in 0..self.n_paths {
            self.send_ping(now, p, io);
        }
    }

    /// Drives timers and delayed copies; returns the time by which it wants
    /// to be polled again.
    pub fn poll(&mut self, now: Micros, io: &mut impl ClientIo) -> Micros {
        if self
            .session
            .as_ref()
            .is_some_and(|s| now.saturating_sub(s.last_rx) > CLIENT_SESSION_DEAD)
        {
            warn!(
                "nothing from the node for {}s; reconnecting",
                CLIENT_SESSION_DEAD / SECOND
            );
            self.session = None;
        }
        if self.session.is_none() {
            return self.poll_handshake(now, io);
        }

        {
            let s = self.session.as_mut().expect("session present");
            s.ranking
                .update(now, down_after(s.active(now)), s.paths.iter());
            let Session {
                tx,
                sched,
                paths,
                ranking,
                ..
            } = s;
            sched.poll(tx, now + COPY_SLACK, ranking, |path, pkt| {
                paths[path].tx_pkts += 1;
                io.send(path, pkt);
            });
        }
        for p in 0..self.n_paths {
            let due = self.session.as_ref().is_some_and(|s| now >= s.next_ping[p]);
            if due {
                self.send_ping(now, p, io);
            }
        }
        let dead_at = {
            let s = self.session.as_mut().expect("session present");
            if now >= s.next_stats {
                send_stats(s, now, io);
            }
            if now >= s.next_expire {
                s.rx.expire(now);
                s.flows.expire(now);
                s.next_expire = now + SECOND;
            }
            s.last_rx + CLIENT_SESSION_DEAD
        };
        self.next_due()
            .unwrap_or(Micros::MAX)
            .min(dead_at)
            .min(now + MAX_POLL)
    }

    /// The earliest scheduled PING, STATS or delayed copy. The tunnel checks
    /// this after sending, to wake its timer thread early if needed.
    pub fn next_due(&self) -> Option<Micros> {
        let s = self.session.as_ref()?;
        let ping = s.next_ping.iter().copied().min().unwrap_or(Micros::MAX);
        let t = ping.min(s.next_stats);
        Some(s.sched.next_due().map_or(t, |d| d.min(t)))
    }

    /// Processes one datagram that arrived on `path`; `pkt` is decrypted
    /// in place.
    pub fn handle_datagram(
        &mut self,
        now: Micros,
        path: usize,
        pkt: &mut [u8],
        io: &mut impl ClientIo,
    ) {
        let ClientCore { session, stats, .. } = self;
        if let Some(s) = session {
            if let Ok(body) = s.rx.open(pkt) {
                s.last_rx = now;
                if let Some(m) = s.paths.get_mut(path) {
                    m.on_rx(now);
                }
                let mut close = false;
                for frame in FrameReader::new(body) {
                    let Ok(frame) = frame else { break };
                    match frame {
                        Frame::Pong(p) => {
                            stats.pongs += 1;
                            if let Some(m) = s.paths.get_mut(usize::from(p.path)) {
                                let rtt = now
                                    .saturating_sub(p.ts)
                                    .saturating_sub(u64::from(p.hold_us));
                                m.rtt.update(rtt);
                            }
                        }
                        Frame::Ping(p) => {
                            let pong = Frame::Pong(Pong {
                                path: p.path,
                                id: p.id,
                                ts: p.ts,
                                hold_us: 0,
                            });
                            if let (Ok(out), Some(m)) =
                                (s.tx.control(|w| w.write(&pong)), s.paths.get_mut(path))
                            {
                                io.send(path, out);
                                m.tx_pkts += 1;
                            }
                        }
                        Frame::Stats(st) => on_node_stats(s, now, st),
                        Frame::Close(_) => close = true,
                        _ => match s.rx.accept(now, &frame) {
                            Some(Data::Ip(ip)) => {
                                stats.rx_ip += 1;
                                stats.rx_bytes += ip.len() as u64;
                                io.deliver(ip);
                                s.touch(now);
                            }
                            Some(Data::EchoResp(e)) => {
                                io.echo(now, e.id, e.ts);
                                s.touch(now);
                            }
                            _ => {}
                        },
                    }
                }
                if close {
                    warn!("node closed the session; reconnecting");
                    *session = None;
                }
                return;
            }
        }
        self.on_handshake_response(now, pkt, io);
    }

    /// Sends an inner packet with the redundancy its flow gets; returns
    /// `false` when there is no session.
    pub fn send_ip(&mut self, now: Micros, ip: &[u8], io: &mut impl ClientIo) -> bool {
        let Some(s) = &mut self.session else {
            return false;
        };
        let Ok(p) = Ipv4Packet::parse(ip) else {
            return false;
        };
        s.touch(now);
        let flow = s.flows.classify(now, FlowKey::of(&p), ip.len());
        self.stats.tx_ip += 1;
        self.stats.tx_bytes += ip.len() as u64;
        if flow.class == Class::Bulk {
            self.stats.tx_bulk += 1;
        }
        let plan = Plan::for_flow(&self.policy, flow);
        let Session {
            tx,
            sched,
            paths,
            ranking,
            ..
        } = s;
        sched
            .send_ip(tx, now, ip, plan, ranking, |path, pkt| {
                paths[path].tx_pkts += 1;
                io.send(path, pkt);
            })
            .is_ok()
    }

    /// Sends an echo request stamped with `now`, with game-flow redundancy
    /// (`bench`).
    pub fn send_echo(
        &mut self,
        now: Micros,
        id: u32,
        payload: &[u8],
        io: &mut impl ClientIo,
    ) -> bool {
        let Some(s) = &mut self.session else {
            return false;
        };
        s.touch(now);
        let plan = Plan::redundant(&self.policy);
        let Session {
            tx,
            sched,
            paths,
            ranking,
            ..
        } = s;
        sched
            .send_echo(
                tx,
                now,
                true,
                id,
                now,
                payload,
                plan,
                ranking,
                |path, pkt| {
                    paths[path].tx_pkts += 1;
                    io.send(path, pkt);
                },
            )
            .is_ok()
    }

    /// Tells the node we are leaving.
    pub fn close(&mut self, io: &mut impl ClientIo) {
        if let Some(s) = &mut self.session {
            for p in 0..s.paths.len() {
                if let Ok(out) = s.tx.control(|w| w.write(&Frame::Close(0))) {
                    io.send(p, out);
                }
            }
        }
        self.session = None;
    }

    pub fn snapshot(&self, now: Micros) -> Snapshot {
        let Some(s) = &self.session else {
            return Snapshot {
                connected: false,
                stats: self.stats,
                paths: vec![],
                best: None,
                flows: 0,
                bulk_flows: 0,
                exchange: None,
            };
        };
        Snapshot {
            connected: true,
            stats: self.stats,
            paths: s
                .paths
                .iter()
                .map(|m| PathView {
                    up: m.is_up(now, down_after(s.active(now))),
                    rtt: m.rtt,
                    loss_out: m.loss_out(),
                    loss_in: m.loss_in(),
                })
                .collect(),
            best: s.ranking.best(),
            flows: s.flows.len(),
            bulk_flows: s.flows.bulk_count(),
            exchange: s.exchange,
        }
    }

    fn poll_handshake(&mut self, now: Micros, io: &mut impl ClientIo) -> Micros {
        match &self.handshake {
            None => self.send_hs_init(now, now, HANDSHAKE_RETRY, io),
            Some(h) if now >= h.next_retry => {
                let (first, warned) = (h.first_sent, h.warned);
                let backoff = (h.backoff * 2).min(HANDSHAKE_RETRY_MAX);
                let give_up = now.saturating_sub(first) > HANDSHAKE_GIVE_UP;
                if give_up && !warned {
                    warn!(
                        "no handshake response for 30s; check the node address, keys and firewall"
                    );
                }
                self.send_hs_init(now, first, backoff, io);
                if let Some(h) = &mut self.handshake {
                    h.warned = warned || give_up;
                }
            }
            Some(_) => {}
        }
        self.handshake
            .as_ref()
            .map_or(now + HANDSHAKE_RETRY, |h| h.next_retry)
    }

    fn on_handshake_response(&mut self, now: Micros, pkt: &mut [u8], io: &mut impl ClientIo) {
        let Some(h) = &mut self.handshake else { return };
        let Ok(body) = open_handshake(&self.obfs.s2c, pkt) else {
            return;
        };
        let Some(Ok(Frame::HsResp(msg))) = FrameReader::new(body).next() else {
            return;
        };
        let Some(init) = h.init.take() else { return };
        match init.finish(msg) {
            Ok((hello, keys)) => {
                self.handshake = None;
                self.session = Some(Session {
                    tx: TxState::new(keys.c2s, self.pad_max),
                    rx: RxState::new(keys.s2c),
                    sched: Scheduler::new(),
                    hello,
                    paths: vec![PathMetrics::new(now); self.n_paths],
                    next_ping: vec![now; self.n_paths],
                    ranking: Ranking::default(),
                    flows: FlowClassifier::new(
                        self.policy.bulk_enter_kbps,
                        self.policy.bulk_exit_kbps,
                    ),
                    last_rx: now,
                    last_active: 0,
                    next_stats: now + STATS_IDLE,
                    next_expire: now + SECOND,
                    exchange: None,
                });
                if let Some(s) = &mut self.session {
                    s.ranking.update(now, down_after(false), s.paths.iter());
                }
                self.stats.handshakes += 1;
                info!(vip = %hello.vip, mtu = hello.mtu, paths = self.n_paths, "connected");
                // The first packets under the new keys confirm the session
                // and register every path with the node.
                for p in 0..self.n_paths {
                    self.send_ping(now, p, io);
                }
            }
            Err(e) => {
                warn!("handshake response rejected ({e}); wrong node key or psk?");
            }
        }
    }

    fn send_hs_init(
        &mut self,
        now: Micros,
        first_sent: Micros,
        backoff: Micros,
        io: &mut impl ClientIo,
    ) {
        self.last_ts = next_timestamp(self.last_ts);
        let hello = ClientHello {
            timestamp: self.last_ts,
            n_paths: self.n_paths as u8,
            flags: 0,
        };
        let mut m1 = [0u8; MAX_MSG_LEN];
        let init = match Initiator::start(&self.local, &self.node, &self.psk, &hello, &mut m1) {
            Ok((init, n)) => {
                if let Ok(pkt) = seal_handshake(
                    &self.obfs.c2s,
                    &Frame::HsInit(&m1[..n]),
                    &mut self.rng,
                    &mut self.hs_buf,
                ) {
                    io.send(0, pkt);
                }
                Some(init)
            }
            Err(e) => {
                warn!("cannot start handshake: {e}");
                None
            }
        };
        self.handshake = Some(Handshake {
            init,
            first_sent,
            next_retry: now + backoff,
            backoff,
            warned: false,
        });
    }

    /// PINGs `path`, with the current `TUNE` alongside so the node always
    /// has our policy.
    fn send_ping(&mut self, now: Micros, path: usize, io: &mut impl ClientIo) {
        let Some(s) = &mut self.session else { return };
        self.ping_id = self.ping_id.wrapping_add(1);
        let ping = Frame::Ping(Ping {
            path: path as u8,
            id: self.ping_id,
            ts: now,
        });
        let tune = Frame::Tune(self.policy.to_tune());
        if let Ok(out) = s.tx.control(|w| {
            w.write(&ping)?;
            w.write(&tune)
        }) {
            io.send(path, out);
            s.paths[path].tx_pkts += 1;
            self.stats.pings += 1;
        }
        let base = if s.active(now) {
            PING_ACTIVE
        } else {
            PING_IDLE
        };
        let jitter = base * PING_JITTER_PCT / 100;
        s.next_ping[path] = now + self.rng.random_range(base - jitter..=base + jitter);
    }
}

fn send_stats(s: &mut Session, now: Micros, io: &mut impl ClientIo) {
    let mut st = Stats::new(
        s.tx.items_sent(),
        s.rx.stats.unique,
        s.rx.stats.dup,
        s.rx.stats.rescued,
    );
    for (i, m) in s.paths.iter().enumerate() {
        st.push_path(PathStats {
            path: i as u8,
            tx_pkts: m.tx_pkts,
            rx_pkts: m.rx_pkts,
            srtt_us: clamp_u32(m.rtt.srtt),
            rttvar_us: clamp_u32(m.rtt.rttvar),
        });
    }
    let path = s.ranking.best().unwrap_or(0);
    if let Ok(out) = s.tx.control(|w| w.write(&Frame::Stats(st))) {
        io.send(path, out);
        s.paths[path].tx_pkts += 1;
    }
    s.next_stats = now
        + if s.active(now) {
            STATS_ACTIVE
        } else {
            STATS_IDLE
        };
}

/// Microseconds for a `STATS` field (0 while unmeasured).
fn clamp_u32(us: Micros) -> u32 {
    us.min(Micros::from(u32::MAX)) as u32
}

fn on_node_stats(s: &mut Session, now: Micros, st: Stats) {
    for p in st.paths() {
        if let Some(m) = s.paths.get_mut(usize::from(p.path)) {
            m.on_peer_stats(p.tx_pkts, p.rx_pkts);
        }
    }
    let mut paths = [(0, 0); MAX_PATHS];
    for (slot, m) in paths.iter_mut().zip(&s.paths) {
        *slot = (m.tx_pkts, m.rx_pkts);
    }
    s.exchange = Some(Exchange {
        at: now,
        peer: st,
        tx_unique: s.tx.items_sent(),
        rx: s.rx.stats,
        paths,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use skyblock_proto::frame::Echo;
    use skyblock_proto::handshake::PendingResponse;
    use skyblock_proto::ip::build_udp;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[derive(Default)]
    struct Io {
        sent: Vec<(usize, Vec<u8>)>,
        delivered: Vec<Vec<u8>>,
        echoes: Vec<(u32, u64)>,
    }

    impl ClientIo for Io {
        fn send(&mut self, path: usize, pkt: &[u8]) {
            self.sent.push((path, pkt.to_vec()));
        }
        fn deliver(&mut self, ip: &[u8]) {
            self.delivered.push(ip.to_vec());
        }
        fn echo(&mut self, _now: Micros, id: u32, ts: u64) {
            self.echoes.push((id, ts));
        }
    }

    /// A minimal node: answers handshakes and holds the session keys.
    struct Node {
        key: PrivateKey,
        obfs: SessionKeys,
        tx: Option<TxState>,
        rx: Option<RxState>,
    }

    impl Node {
        fn new() -> Self {
            let key = PrivateKey::generate();
            Self {
                obfs: SessionKeys::obfuscation(&key.public_key()),
                key,
                tx: None,
                rx: None,
            }
        }

        fn answer(&mut self, pkt: &[u8], psk: &Psk) -> Vec<u8> {
            let mut p = pkt.to_vec();
            let body = open_handshake(&self.obfs.c2s, &mut p).unwrap();
            let Some(Ok(Frame::HsInit(msg))) = FrameReader::new(body).next() else {
                panic!("not HS_INIT")
            };
            let pending = PendingResponse::read(&self.key, msg).unwrap();
            let hello = ServerHello {
                vip: Ipv4Addr::new(10, 77, 0, 2),
                resolver: Ipv4Addr::new(10, 77, 0, 1),
                mtu: 1400,
                flags: 0,
            };
            let mut m2 = [0u8; MAX_MSG_LEN];
            let (n, keys) = pending.accept(psk, &hello, &mut m2).unwrap();
            self.tx = Some(TxState::new(keys.s2c, 0));
            self.rx = Some(RxState::new(keys.c2s));
            let mut buf = PacketBuf::new();
            seal_handshake(
                &self.obfs.s2c,
                &Frame::HsResp(&m2[..n]),
                &mut rand::rng(),
                &mut buf,
            )
            .unwrap()
            .to_vec()
        }

        fn frames(&mut self, pkt: &[u8]) -> Vec<String> {
            let mut p = pkt.to_vec();
            let body = self.rx.as_mut().unwrap().open(&mut p).unwrap();
            FrameReader::new(body)
                .map(|f| format!("{:?}", f.unwrap()))
                .collect()
        }

        fn control(&mut self, f: &Frame<'_>) -> Vec<u8> {
            self.tx
                .as_mut()
                .unwrap()
                .control(|w| w.write(f))
                .unwrap()
                .to_vec()
        }
    }

    fn connect(core: &mut ClientCore, node: &mut Node, io: &mut Io) {
        core.poll(0, io);
        let (path, init) = io.sent.pop().expect("HS_INIT sent");
        assert_eq!(path, 0);
        let mut resp = node.answer(&init, &Psk::ZERO);
        core.handle_datagram(1000, 0, &mut resp, io);
    }

    fn setup_with(n_paths: usize, policy: Policy) -> (ClientCore, Node, Io) {
        let node = Node::new();
        let core = ClientCore::new(
            PrivateKey::generate(),
            node.key.public_key(),
            Psk::ZERO,
            0,
            n_paths,
            policy,
        );
        (core, node, Io::default())
    }

    fn setup() -> (ClientCore, Node, Io) {
        setup_with(1, Policy::SINGLE)
    }

    fn udp(sport: u16, len: usize) -> Vec<u8> {
        let mut b = vec![0u8; 64 + len];
        let n = build_udp(
            &mut b,
            SocketAddrV4::new(Ipv4Addr::new(10, 77, 0, 2), sport),
            SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 27015),
            1,
            &vec![7; len],
        )
        .unwrap();
        b.truncate(n);
        b
    }

    fn game(copies: u8, delay: Micros) -> Policy {
        Policy {
            copies,
            copy_delay: delay,
            ..Policy::SINGLE
        }
    }

    #[test]
    fn connects_and_pings_every_path_with_tune() {
        let (mut core, mut node, mut io) = setup_with(3, game(2, 2 * MS));
        connect(&mut core, &mut node, &mut io);
        assert_eq!(core.stats.handshakes, 1);
        assert_eq!(core.hello().unwrap().vip, Ipv4Addr::new(10, 77, 0, 2));
        let paths: Vec<_> = io.sent.iter().map(|s| s.0).collect();
        assert_eq!(paths, vec![0, 1, 2]);
        for (_, pkt) in io.sent.clone() {
            let f = node.frames(&pkt);
            assert!(f[0].starts_with("Ping"), "{f:?}");
            assert!(f[1].contains("copies: 2"), "{f:?}");
        }
    }

    #[test]
    fn handshake_retries_with_backoff() {
        let (mut core, _node, mut io) = setup();
        let mut t = 0;
        let mut sends = vec![];
        for _ in 0..6 {
            let next = core.poll(t, &mut io);
            sends.push((t, io.sent.len()));
            t = next;
        }
        assert_eq!(io.sent.len(), 6);
        // Deadlines: 0, +1s, +2s, +4s, +8s, +8s.
        let times: Vec<_> = sends.iter().map(|s| s.0 / SECOND).collect();
        assert_eq!(times, vec![0, 1, 3, 7, 15, 23]);
        // Each attempt is a fresh handshake packet.
        assert_ne!(io.sent[0], io.sent[1]);
    }

    #[test]
    fn stale_response_to_an_earlier_attempt_is_ignored() {
        let (mut core, mut node, mut io) = setup();
        core.poll(0, &mut io);
        let (_, first) = io.sent.pop().unwrap();
        core.poll(HANDSHAKE_RETRY, &mut io);
        let mut resp = node.answer(&first, &Psk::ZERO);
        core.handle_datagram(HANDSHAKE_RETRY + 1, 0, &mut resp, &mut io);
        assert!(core.hello().is_none());
    }

    #[test]
    fn psk_mismatch_does_not_connect() {
        let (mut core, mut node, mut io) = setup();
        core.poll(0, &mut io);
        let (_, init) = io.sent.pop().unwrap();
        let mut resp = node.answer(&init, &Psk::generate());
        core.handle_datagram(1, 0, &mut resp, &mut io);
        assert!(core.hello().is_none());
        // It retries on schedule rather than immediately.
        core.poll(2, &mut io);
        assert!(io.sent.is_empty());
        core.poll(HANDSHAKE_RETRY, &mut io);
        assert_eq!(io.sent.len(), 1);
    }

    #[test]
    fn data_both_ways_and_pong_rtt() {
        let (mut core, mut node, mut io) = setup();
        connect(&mut core, &mut node, &mut io);
        io.sent.clear();

        assert!(core.send_ip(2000, &udp(5000, 20), &mut io));
        let (_, up) = io.sent.pop().unwrap();
        assert!(node.frames(&up)[0].starts_with("Ip"));

        let mut down = vec![];
        node.tx
            .as_mut()
            .unwrap()
            .send_ip(&udp(5000, 20), |p| down.push(p.to_vec()))
            .unwrap();
        core.handle_datagram(3000, 0, &mut down[0], &mut io);
        assert_eq!(io.delivered, vec![udp(5000, 20)]);

        let mut pong = node.control(&Frame::Pong(Pong {
            path: 0,
            id: 1,
            ts: 1000,
            hold_us: 100,
        }));
        core.handle_datagram(43_000, 0, &mut pong, &mut io);
        assert_eq!(core.snapshot(43_000).paths[0].rtt.last, 41_900);
    }

    #[test]
    fn game_packets_are_sent_on_two_paths() {
        let (mut core, mut node, mut io) = setup_with(2, game(2, 0));
        connect(&mut core, &mut node, &mut io);
        io.sent.clear();
        core.send_ip(2000, &udp(5000, 100), &mut io);
        let paths: Vec<_> = io.sent.iter().map(|s| s.0).collect();
        assert_eq!(paths, vec![0, 1]);
        assert_ne!(io.sent[0].1, io.sent[1].1, "each copy is its own packet");
        assert!(node.frames(&io.sent[1].1)[0].contains("copy: 1"));
    }

    /// Drains sent packets; returns the paths of those carrying IP data.
    fn data_paths(node: &mut Node, io: &mut Io) -> Vec<usize> {
        io.sent
            .drain(..)
            .filter(|(_, p)| node.frames(p)[0].starts_with("Ip"))
            .map(|(path, _)| path)
            .collect()
    }

    #[test]
    fn delayed_copy_goes_out_when_polled() {
        let (mut core, mut node, mut io) = setup_with(2, game(2, 2 * MS));
        connect(&mut core, &mut node, &mut io);
        io.sent.clear();
        core.send_ip(2000, &udp(5000, 100), &mut io);
        assert_eq!(data_paths(&mut node, &mut io), vec![0]);
        let sched_due = core.session.as_ref().unwrap().sched.next_due();
        assert_eq!(sched_due, Some(4000));
        core.poll(4000 - COPY_SLACK - 1, &mut io);
        assert!(data_paths(&mut node, &mut io).is_empty());
        core.poll(4000 - COPY_SLACK, &mut io);
        assert_eq!(data_paths(&mut node, &mut io), vec![1]);
    }

    #[test]
    fn bulk_flow_gets_one_copy() {
        let (mut core, mut node, mut io) = setup_with(2, game(2, 0));
        connect(&mut core, &mut node, &mut io);
        io.sent.clear();
        // ~10 Mbit/s for 1.2 s on one flow.
        let pkt = udp(6000, 1200);
        let mut t = 2000;
        for _ in 0..1200 {
            core.send_ip(t, &pkt, &mut io);
            t += MS;
        }
        let before = io.sent.len();
        core.send_ip(t, &pkt, &mut io);
        assert_eq!(io.sent.len(), before + 1);
        assert!(core.stats.tx_bulk > 0);
        // A game flow alongside still gets two copies.
        core.send_ip(t, &udp(5000, 100), &mut io);
        assert_eq!(io.sent.len(), before + 3);
        assert_eq!(core.snapshot(t).bulk_flows, 1);
    }

    #[test]
    fn stats_exchange_and_echo() {
        let (mut core, mut node, mut io) = setup_with(2, game(1, 0));
        connect(&mut core, &mut node, &mut io);
        io.sent.clear();

        assert!(core.send_echo(5000, 9, b"abc", &mut io));
        let (_, req) = io.sent.pop().unwrap();
        let f = node.frames(&req);
        assert!(f[0].starts_with("EchoReq"), "{f:?}");

        let mut resp = vec![];
        node.tx
            .as_mut()
            .unwrap()
            .send_echo(
                false,
                Echo {
                    seq: 0,
                    copy: 0,
                    id: 9,
                    ts: 5000,
                    payload: b"abc",
                },
                |p| resp = p.to_vec(),
            )
            .unwrap();
        core.handle_datagram(9000, 1, &mut resp, &mut io);
        assert_eq!(io.echoes, vec![(9, 5000)]);

        let mut st = Stats::new(1, 1, 0, 0);
        st.push_path(PathStats {
            path: 1,
            tx_pkts: 2,
            rx_pkts: 3,
            srtt_us: 0,
            rttvar_us: 0,
        });
        let mut pkt = node.control(&Frame::Stats(st));
        core.handle_datagram(9500, 1, &mut pkt, &mut io);
        let ex = core.snapshot(9500).exchange.expect("exchange recorded");
        assert_eq!(ex.at, 9500);
        assert_eq!(ex.tx_unique, 1);
        assert_eq!(ex.rx.unique, 1);
        assert_eq!(ex.peer_path(1), Some((2, 3)));
        assert_eq!(ex.paths[1].1, 2, "two packets received on path 1");
    }

    #[test]
    fn stats_go_out_periodically_with_path_counters() {
        let (mut core, mut node, mut io) = setup_with(2, Policy::SINGLE);
        connect(&mut core, &mut node, &mut io);
        core.send_ip(2000, &udp(5000, 10), &mut io);
        io.sent.clear();
        core.poll(2000, &mut io);
        let stats: Vec<_> = io
            .sent
            .iter()
            .map(|(_, p)| node.frames(p))
            .filter(|f| f[0].starts_with("Stats"))
            .collect();
        assert_eq!(stats.len(), 1, "active: STATS right away");
        assert!(stats[0][0].contains("tx_unique: 1"), "{:?}", stats[0]);
    }

    #[test]
    fn dead_session_triggers_reconnect() {
        let (mut core, mut node, mut io) = setup();
        connect(&mut core, &mut node, &mut io);
        io.sent.clear();
        core.poll(1000 + CLIENT_SESSION_DEAD + 1, &mut io);
        assert!(core.hello().is_none());
        assert_eq!(io.sent.len(), 1, "a new HS_INIT goes out");
        assert!(!core.send_ip(0, &udp(5000, 10), &mut io));
    }

    #[test]
    fn ping_schedule_depends_on_activity() {
        let (mut core, mut node, mut io) = setup();
        connect(&mut core, &mut node, &mut io);
        let idle_next = core.poll(2000, &mut io);
        assert!(idle_next <= 2000 + MAX_POLL);
        let s = core.session.as_ref().unwrap();
        let ping = s.next_ping[0];
        assert!((1000 + PING_IDLE * 8 / 10..=1000 + PING_IDLE * 12 / 10 + 1).contains(&ping));

        // Data after idling brings the next PING forward to now.
        let t = 3 * SECOND;
        core.send_ip(t, &udp(5000, 10), &mut io);
        assert_eq!(core.next_due(), Some(t));
        io.sent.clear();
        core.poll(t, &mut io);
        assert!(!io.sent.is_empty());
        let s = core.session.as_ref().unwrap();
        assert!(s.next_ping[0] <= t + PING_ACTIVE * 12 / 10);
    }
}
