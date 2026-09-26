//! Transport-independent client logic (SPEC §3.6–3.9, §4): handshake with
//! retries, per-path keepalive PINGs and RTT, moving silent paths to new
//! sockets, in-channel rekeys, redundant sending with delayed copies, flow
//! classification, the STATS exchange and dead-session detection. The
//! tunnel threads feed it datagrams and perform the I/O it requests.

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use skyblock_proto::Micros;
use skyblock_proto::flow::{Class, FlowClassifier, FlowKey};
use skyblock_proto::frame::{
    Frame, FrameReader, MAX_PATHS, PathStats, Ping, Pong, ProbeReq, ProbeResp, Stats,
};
use skyblock_proto::handshake::{ClientHello, Initiator, MAX_MSG_LEN, ServerHello, next_timestamp};
use skyblock_proto::ip::Ipv4Packet;
use skyblock_proto::keys::{PrivateKey, Psk, PublicKey, SessionKeys};
use skyblock_proto::packet::PacketBuf;
use skyblock_proto::path::{PathMetrics, Ranking, Rtt, down_after};
use skyblock_proto::sched::{Plan, Policy, Scheduler};
use skyblock_proto::session::{
    Data, KeyPhase, RxState, RxStats, TxState, open_handshake, seal_handshake,
};
use skyblock_proto::timing::{
    ACTIVE_WINDOW, CLIENT_RESUME, CLIENT_SESSION_DEAD, CLIENT_SESSION_DEAD_IDLE, HANDSHAKE_GIVE_UP,
    HANDSHAKE_RETRY, HANDSHAKE_RETRY_MAX, MS, PATH_REBIND, PING_ACTIVE, PING_IDLE, PING_JITTER_PCT,
    REKEY_INTERVAL, REKEY_RETRY, SECOND, STATS_ACTIVE, STATS_IDLE,
};
use tracing::{debug, info, warn};

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
    /// A PONG arrived for `path`, `rtt` after its PING (`ping`).
    fn pong(&mut self, _path: usize, _rtt: Micros) {}
    /// A PROBE_RESP arrived (`ping --target`).
    fn probe(&mut self, _resp: ProbeResp) {}
    /// Moves `path` to a new socket, hence a new local port and NAT
    /// mapping. Packets sent after this call use the new socket.
    fn rebind(&mut self, _path: usize) {}
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
    /// In-channel rekeys completed.
    pub rekeys: u64,
    /// Path sockets replaced (silent paths, dead sessions, handshake
    /// retries).
    pub rebinds: u64,
    /// Handshakes started beside a session that went silent while data
    /// flowed (the node may have restarted).
    pub resumes: u64,
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
    /// Attempts so far; attempt `n` goes out on path `n % paths`.
    attempt: usize,
    /// For a handshake beside a silent session: that session's `last_rx`
    /// when it began. Once the session hears from the node again it is not
    /// retried, but a late `HS_RESP` still completes it (the node dropped
    /// the old session when it accepted `HS_INIT`).
    beside: Option<Micros>,
}

/// A REKEY_INIT waiting for its REKEY_RESP.
struct Rekey {
    init: Initiator,
    sent: Micros,
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
    /// When data last started flowing after an idle spell: only silence
    /// since then counts towards `CLIENT_RESUME` (while idle, PINGs are
    /// 10s apart and `last_rx` is naturally old).
    active_since: Micros,
    next_stats: Micros,
    next_expire: Micros,
    exchange: Option<Exchange>,
    /// When each path's socket was last replaced (or the session began).
    rebound: Vec<Micros>,
    rekey: Option<Rekey>,
    next_rekey: Micros,
}

impl Session {
    fn active(&self, now: Micros) -> bool {
        self.last_active != 0 && now.saturating_sub(self.last_active) < ACTIVE_WINDOW
    }

    /// Silence after which the session counts as dead.
    fn dead_after(&self, now: Micros) -> Micros {
        if self.active(now) {
            CLIENT_SESSION_DEAD
        } else {
            CLIENT_SESSION_DEAD_IDLE
        }
    }

    /// Notes data; after an idle spell, PINGs and STATS go out right away
    /// so path state is fresh while traffic flows.
    fn touch(&mut self, now: Micros) {
        if !self.active(now) {
            self.next_ping.iter_mut().for_each(|t| *t = now);
            self.next_stats = now;
            self.active_since = now;
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
    rekey_interval: Option<Micros>,
    handshake: Option<Handshake>,
    /// Set by [`close`](Self::close): no more handshakes.
    closed: bool,
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
            rekey_interval: Some(REKEY_INTERVAL),
            handshake: None,
            closed: false,
            session: None,
            last_ts: 0,
            ping_id: 0,
            rng: StdRng::from_rng(&mut rand::rng()),
            hs_buf: PacketBuf::new(),
            stats: ClientStats::default(),
        }
    }

    /// How often to rekey in the channel (`None`: never).
    pub fn with_rekey_interval(mut self, interval: Option<Micros>) -> Self {
        self.rekey_interval = interval;
        self
    }

    pub fn hello(&self) -> Option<ServerHello> {
        self.session.as_ref().map(|s| s.hello)
    }

    /// PINGs every path now (`ping` takes RTT samples this way).
    pub fn ping_all(&mut self, now: Micros, io: &mut impl ClientIo) {
        for p in 0..self.n_paths {
            self.send_ping(now, p, io);
        }
    }

    /// The tunnel replaced `path`'s socket on its own (sending failed):
    /// PING through the new one so the node learns its address.
    pub fn path_rebound(&mut self, now: Micros, path: usize, io: &mut impl ClientIo) {
        self.stats.rebinds += 1;
        if let Some(s) = &mut self.session {
            if let Some(t) = s.rebound.get_mut(path) {
                *t = now;
                self.send_ping(now, path, io);
            }
        }
    }

    /// Asks the node to probe a target; returns `false` without a session.
    pub fn send_probe(&mut self, req: ProbeReq, io: &mut impl ClientIo) -> bool {
        let Some(s) = &mut self.session else {
            return false;
        };
        let path = s.ranking.best().unwrap_or(0);
        match s.tx.control(|w| w.write(&Frame::ProbeReq(req))) {
            Ok(out) => {
                io.send(path, out);
                s.paths[path].tx_pkts += 1;
                true
            }
            Err(_) => false,
        }
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
        if self.closed {
            return now + MAX_POLL;
        }
        let dead = self.session.as_ref().and_then(|s| {
            let limit = s.dead_after(now);
            (now.saturating_sub(s.last_rx) > limit).then_some(limit)
        });
        if let Some(limit) = dead {
            warn!(
                "nothing from the node for {}s; reconnecting",
                limit / SECOND
            );
            self.session = None;
            // Probably a network change: start over on fresh sockets.
            for p in 0..self.n_paths {
                io.rebind(p);
            }
            self.stats.rebinds += self.n_paths as u64;
        }
        if self.session.is_none() {
            return self.poll_handshake(now, io);
        }
        let resume_at = self.poll_resume(now, io);
        self.rebind_silent_paths(now, io);
        self.poll_rekey(now, io);

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
            s.last_rx + s.dead_after(now)
        };
        self.next_due()
            .unwrap_or(Micros::MAX)
            .min(dead_at)
            .min(resume_at)
            .min(now + MAX_POLL)
    }

    /// While data flows and nothing has come from the node for
    /// `CLIENT_RESUME`, handshakes again beside the session: a restarted
    /// node has forgotten it and stays silent, and waiting for
    /// `CLIENT_SESSION_DEAD` would cut the game off for 15s. The session
    /// carries on until `HS_RESP` replaces it. Returns when to look again.
    fn poll_resume(&mut self, now: Micros, io: &mut impl ClientIo) -> Micros {
        let Some(s) = &self.session else {
            return Micros::MAX;
        };
        if !s.active(now) {
            return Micros::MAX;
        }
        let last_rx = s.last_rx;
        let at = last_rx.max(s.active_since) + CLIENT_RESUME;
        if now < at {
            return at;
        }
        match &self.handshake {
            Some(h) if h.beside == Some(last_rx) => {
                if now >= h.next_retry {
                    let (first, attempt) = (h.first_sent, h.attempt + 1);
                    let backoff = (h.backoff * 2).min(HANDSHAKE_RETRY_MAX);
                    self.send_hs_init(now, first, backoff, attempt, io);
                }
            }
            _ => {
                info!(
                    "nothing from the node for {}s; handshaking again beside the session",
                    CLIENT_RESUME / SECOND
                );
                self.stats.resumes += 1;
                self.send_hs_init(now, now, HANDSHAKE_RETRY, 0, io);
            }
        }
        let h = self.handshake.as_mut().expect("handshake started");
        h.beside = Some(last_rx);
        h.next_retry
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
        let ClientCore {
            session,
            stats,
            rekey_interval,
            ..
        } = self;
        if let Some(s) = session {
            if let Ok((body, phase)) = s.rx.open(now, pkt) {
                if phase == KeyPhase::Next {
                    debug!("node switched to the new keys");
                }
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
                                io.pong(usize::from(p.path), rtt);
                            }
                        }
                        Frame::RekeyResp(msg) => {
                            let Some(r) = s.rekey.take() else { continue };
                            match r.init.finish(msg) {
                                Ok((_, keys)) => {
                                    // Send under the new keys from now on; the
                                    // node follows once it sees them.
                                    s.tx.rekey(keys.c2s);
                                    s.rx.set_next(keys.s2c);
                                    stats.rekeys += 1;
                                    s.next_rekey = now + rekey_interval.unwrap_or(Micros::MAX / 2);
                                    debug!("rekeyed");
                                }
                                Err(e) => {
                                    debug!("REKEY_RESP rejected ({e}); retrying");
                                    s.next_rekey = now + REKEY_RETRY;
                                }
                            }
                        }
                        Frame::ProbeResp(r) => io.probe(r),
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

    /// Tells the node we are leaving; the core stays idle afterwards.
    pub fn close(&mut self, io: &mut impl ClientIo) {
        if let Some(s) = &mut self.session {
            for p in 0..s.paths.len() {
                if let Ok(out) = s.tx.control(|w| w.write(&Frame::Close(0))) {
                    io.send(p, out);
                }
            }
        }
        self.session = None;
        self.handshake = None;
        self.closed = true;
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
            None => self.send_hs_init(now, now, HANDSHAKE_RETRY, 0, io),
            Some(h) if now >= h.next_retry => {
                let (first, warned, attempt) = (h.first_sent, h.warned, h.attempt + 1);
                let backoff = (h.backoff * 2).min(HANDSHAKE_RETRY_MAX);
                let give_up = now.saturating_sub(first) > HANDSHAKE_GIVE_UP;
                if give_up && !warned {
                    warn!(
                        "no handshake response for 30s; check the node address, keys and firewall"
                    );
                }
                self.send_hs_init(now, first, backoff, attempt, io);
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
                let replaced = self.session.is_some();
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
                    active_since: now,
                    next_stats: now + STATS_IDLE,
                    next_expire: now + SECOND,
                    exchange: None,
                    rebound: vec![now; self.n_paths],
                    rekey: None,
                    next_rekey: self
                        .rekey_interval
                        .map_or(Micros::MAX, |i| now.saturating_add(i)),
                });
                if let Some(s) = &mut self.session {
                    s.ranking.update(now, down_after(false), s.paths.iter());
                }
                self.stats.handshakes += 1;
                info!(vip = %hello.vip, mtu = hello.mtu, paths = self.n_paths, replaced, "connected");
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

    /// Sends HS_INIT attempt `attempt`. Attempts rotate over the paths (a
    /// node port may be blocked), and from the second round on each one
    /// uses a fresh socket (the old one may be bound to a stale address).
    fn send_hs_init(
        &mut self,
        now: Micros,
        first_sent: Micros,
        backoff: Micros,
        attempt: usize,
        io: &mut impl ClientIo,
    ) {
        let path = attempt % self.n_paths;
        if attempt >= self.n_paths {
            io.rebind(path);
            self.stats.rebinds += 1;
            if let Some(t) = self.session.as_mut().and_then(|s| s.rebound.get_mut(path)) {
                *t = now;
            }
        }
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
                    io.send(path, pkt);
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
            attempt,
            beside: None,
        });
    }

    /// Moves paths that stayed silent for `PATH_REBIND` past being marked
    /// down to new sockets and PINGs them: a new local port gets a new NAT
    /// mapping (and 5-tuple), and the node follows by trial decryption.
    fn rebind_silent_paths(&mut self, now: Micros, io: &mut impl ClientIo) {
        let Some(s) = &mut self.session else { return };
        let limit = down_after(s.active(now)) + PATH_REBIND;
        let mut stale = [false; MAX_PATHS];
        for (p, flag) in stale.iter_mut().enumerate().take(self.n_paths) {
            let silent = now.saturating_sub(s.paths[p].last_rx);
            if silent > limit && now.saturating_sub(s.rebound[p]) >= PATH_REBIND {
                s.rebound[p] = now;
                *flag = true;
                info!(
                    path = p,
                    silent_s = silent / SECOND,
                    "path silent; moving it to a new socket"
                );
            }
        }
        for p in (0..self.n_paths).filter(|&p| stale[p]) {
            io.rebind(p);
            self.stats.rebinds += 1;
            self.send_ping(now, p, io);
        }
    }

    /// Starts an in-channel rekey when due, or repeats one that got no
    /// answer (SPEC §3.9).
    fn poll_rekey(&mut self, now: Micros, io: &mut impl ClientIo) {
        let Some(s) = &mut self.session else { return };
        let due = match &s.rekey {
            None => now >= s.next_rekey,
            Some(r) => now >= r.sent + REKEY_RETRY,
        };
        if !due {
            return;
        }
        self.last_ts = next_timestamp(self.last_ts);
        let hello = ClientHello {
            timestamp: self.last_ts,
            n_paths: self.n_paths as u8,
            flags: 0,
        };
        let mut m1 = [0u8; MAX_MSG_LEN];
        match Initiator::start(&self.local, &self.node, &self.psk, &hello, &mut m1) {
            Ok((init, n)) => {
                let path = s.ranking.best().unwrap_or(0);
                if let Ok(out) = s.tx.control(|w| w.write(&Frame::RekeyInit(&m1[..n]))) {
                    io.send(path, out);
                    s.paths[path].tx_pkts += 1;
                }
                s.rekey = Some(Rekey { init, sent: now });
            }
            Err(e) => {
                warn!("cannot start rekey: {e}");
                s.next_rekey = now + REKEY_RETRY;
            }
        }
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
    use skyblock_proto::timing::PATH_DOWN as PATH_DOWN_ACTIVE;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[derive(Default)]
    struct Io {
        sent: Vec<(usize, Vec<u8>)>,
        delivered: Vec<Vec<u8>>,
        echoes: Vec<(u32, u64)>,
        pongs: Vec<(usize, Micros)>,
        probes: Vec<ProbeResp>,
        /// `(path, number of packets sent before the rebind)`.
        rebinds: Vec<(usize, usize)>,
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
        fn pong(&mut self, path: usize, rtt: Micros) {
            self.pongs.push((path, rtt));
        }
        fn probe(&mut self, resp: ProbeResp) {
            self.probes.push(resp);
        }
        fn rebind(&mut self, path: usize) {
            self.rebinds.push((path, self.sent.len()));
        }
    }

    /// A minimal node: answers handshakes and holds the session keys.
    struct Node {
        key: PrivateKey,
        obfs: SessionKeys,
        tx: Option<TxState>,
        rx: Option<RxState>,
        next_tx: Option<skyblock_proto::keys::Keyset>,
    }

    impl Node {
        fn new() -> Self {
            let key = PrivateKey::generate();
            Self {
                obfs: SessionKeys::obfuscation(&key.public_key()),
                key,
                tx: None,
                rx: None,
                next_tx: None,
            }
        }

        /// Answers a REKEY_INIT as the node does: REKEY_RESP under the
        /// current keys, new keys staged.
        fn answer_rekey(&mut self, pkt: &[u8]) -> Vec<u8> {
            let mut p = pkt.to_vec();
            let (body, _) = self.rx.as_mut().unwrap().open(0, &mut p).unwrap();
            let Some(Ok(Frame::RekeyInit(msg))) = FrameReader::new(body).next() else {
                panic!("not REKEY_INIT")
            };
            let pending = PendingResponse::read(&self.key, msg).unwrap();
            let hello = ServerHello {
                vip: Ipv4Addr::new(10, 77, 0, 2),
                resolver: Ipv4Addr::new(10, 77, 0, 1),
                mtu: 1400,
                flags: 0,
            };
            let mut m2 = [0u8; MAX_MSG_LEN];
            let (n, keys) = pending.accept(&Psk::ZERO, &hello, &mut m2).unwrap();
            self.rx.as_mut().unwrap().set_next(keys.c2s);
            self.next_tx = Some(keys.s2c);
            self.control(&Frame::RekeyResp(&m2[..n]))
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

        fn is_handshake(&self, pkt: &[u8]) -> bool {
            open_handshake(&self.obfs.c2s, &mut pkt.to_vec()).is_ok()
        }

        fn frames(&mut self, pkt: &[u8]) -> Vec<String> {
            let mut p = pkt.to_vec();
            let (body, phase) = self.rx.as_mut().unwrap().open(0, &mut p).unwrap();
            if phase == KeyPhase::Next {
                let k = self.next_tx.take().unwrap();
                self.tx.as_mut().unwrap().rekey(k);
            }
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
        // Idle: one lost PONG (PINGs 10s apart) is not the end.
        core.poll(1000 + CLIENT_SESSION_DEAD + 1, &mut io);
        assert!(core.hello().is_some());
        io.sent.clear();
        core.poll(1000 + CLIENT_SESSION_DEAD_IDLE + 1, &mut io);
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

    #[test]
    fn rekey_in_the_channel() {
        let (core, mut node, mut io) = setup();
        let mut core = core.with_rekey_interval(Some(5 * SECOND));
        connect(&mut core, &mut node, &mut io);
        // Connected at t = 1000µs.
        let t = 5 * SECOND + 1000;
        io.sent.clear();
        core.poll(t - 1, &mut io);
        assert!(io.sent.is_empty(), "rekey too early");
        core.poll(t, &mut io);
        assert!(!io.sent.is_empty(), "rekey not started");
        let (_, init) = io.sent.pop().unwrap();
        let mut resp = node.answer_rekey(&init);
        // Before the answer, data still goes under the old keys.
        core.send_ip(t + 1, &udp(5000, 10), &mut io);
        let (_, old) = io.sent.pop().unwrap();
        core.handle_datagram(t + 2, 0, &mut resp, &mut io);
        assert_eq!(core.stats.rekeys, 1);

        core.send_ip(t + 3, &udp(5000, 10), &mut io);
        let (_, new) = io.sent.pop().unwrap();
        let mut p = new.clone();
        let (_, phase) = node.rx.as_mut().unwrap().open(0, &mut p).unwrap();
        assert_eq!(phase, KeyPhase::Next, "client switched to the new keys");
        let mut p = old.clone();
        assert!(
            node.rx.as_mut().unwrap().open(1, &mut p).is_ok(),
            "old keys still accepted"
        );

        // The node switches once it saw the new keys; the client accepts both.
        let k = node.next_tx.take().unwrap();
        node.tx.as_mut().unwrap().rekey(k);
        let mut pong = node.control(&Frame::Pong(Pong {
            path: 0,
            id: 1,
            ts: 0,
            hold_us: 0,
        }));
        let before = core.stats.pongs;
        core.handle_datagram(t + 4, 0, &mut pong, &mut io);
        assert_eq!(core.stats.pongs, before + 1);

        // The next rekey is a full interval after the last one finished
        // (the node keeps answering PINGs meanwhile).
        let mut pong = node.control(&Frame::Pong(Pong {
            path: 0,
            id: 2,
            ts: 0,
            hold_us: 0,
        }));
        core.handle_datagram(t + 4 * SECOND, 0, &mut pong, &mut io);
        io.sent.clear();
        core.poll(t + 5 * SECOND, &mut io);
        assert!(
            io.sent
                .iter()
                .all(|(_, p)| !node.frames(p)[0].starts_with("RekeyInit"))
        );
        io.sent.clear();
        core.poll(t + 5 * SECOND + 2, &mut io);
        assert!(
            io.sent
                .iter()
                .any(|(_, p)| node.frames(p)[0].starts_with("RekeyInit"))
        );
    }

    #[test]
    fn unanswered_rekey_is_retried() {
        let (core, mut node, mut io) = setup();
        let mut core = core.with_rekey_interval(Some(5 * SECOND));
        connect(&mut core, &mut node, &mut io);
        let rekeys = |io: &mut Io, node: &mut Node| {
            io.sent
                .drain(..)
                .filter(|(_, p)| node.frames(p)[0].starts_with("RekeyInit"))
                .count()
        };
        let t = 5 * SECOND + 1000;
        io.sent.clear();
        core.poll(t, &mut io);
        assert_eq!(rekeys(&mut io, &mut node), 1);
        core.poll(t + REKEY_RETRY - 1, &mut io);
        assert_eq!(rekeys(&mut io, &mut node), 0);
        core.poll(t + REKEY_RETRY, &mut io);
        assert_eq!(rekeys(&mut io, &mut node), 1, "a fresh REKEY_INIT");
    }

    #[test]
    fn silent_path_moves_to_a_new_socket() {
        let (mut core, mut node, mut io) = setup_with(2, Policy::SINGLE);
        connect(&mut core, &mut node, &mut io);
        // Traffic keeps the session active; only path 1 hears back.
        let mut t = 1000;
        while t < 30 * SECOND {
            core.send_ip(t, &udp(5000, 10), &mut io);
            let mut pong = node.control(&Frame::Pong(Pong {
                path: 1,
                id: 0,
                ts: t,
                hold_us: 0,
            }));
            core.handle_datagram(t, 1, &mut pong, &mut io);
            core.poll(t, &mut io);
            t += 500 * MS;
            if !io.rebinds.is_empty() {
                break;
            }
        }
        let silent_for = t - 500 * MS - 1000;
        assert!(
            silent_for > PATH_DOWN_ACTIVE + PATH_REBIND,
            "rebound after {silent_for}us"
        );
        assert!(silent_for <= PATH_DOWN_ACTIVE + PATH_REBIND + 500 * MS);
        let (path, at) = io.rebinds[0];
        assert_eq!(path, 0);
        assert_eq!(io.rebinds.len(), 1, "path 1 is fine");
        // A PING re-registers the path right after the rebind.
        assert!(
            io.sent[at..]
                .iter()
                .any(|(p, pkt)| *p == 0 && node.frames(pkt)[0].starts_with("Ping"))
        );
        assert_eq!(core.stats.rebinds, 1);

        // Not again until PATH_REBIND has passed.
        io.rebinds.clear();
        core.poll(t + PATH_REBIND - MS, &mut io);
        assert!(io.rebinds.is_empty());
    }

    #[test]
    fn dead_session_rebinds_every_path_and_handshakes_rotate() {
        let (mut core, mut node, mut io) = setup_with(2, Policy::SINGLE);
        connect(&mut core, &mut node, &mut io);
        io.sent.clear();
        let dead = 1000 + CLIENT_SESSION_DEAD_IDLE + 1;
        core.poll(dead, &mut io);
        assert_eq!(io.rebinds, vec![(0, 0), (1, 0)]);
        assert_eq!(io.sent.len(), 1);
        assert_eq!(io.sent[0].0, 0, "first attempt on path 0");
        // Retries go round the paths; from the second round on, each on a
        // fresh socket.
        io.rebinds.clear();
        let mut t = dead;
        let mut paths = vec![];
        for _ in 0..3 {
            t = core.poll(t, &mut io).max(t);
            t = core.poll(t, &mut io).max(t);
        }
        for (p, _) in &io.sent {
            paths.push(*p);
        }
        assert_eq!(&paths[..4], &[0, 1, 0, 1]);
        assert_eq!(io.rebinds.first().map(|r| r.0), Some(0));
        assert_eq!(io.rebinds[0].1, 2, "rebound right before the third attempt");
    }

    fn hs_inits(node: &Node, io: &Io) -> Vec<(usize, Vec<u8>)> {
        io.sent
            .iter()
            .filter(|(_, p)| node.is_handshake(p))
            .cloned()
            .collect()
    }

    #[test]
    fn silent_node_gets_a_handshake_beside_the_session() {
        // The node restarted: it forgot the session and ignores its packets
        // while the game keeps sending.
        let (mut core, mut node, mut io) = setup_with(2, Policy::SINGLE);
        connect(&mut core, &mut node, &mut io);
        let mut t = 1000;
        while t < 1000 + CLIENT_RESUME {
            core.send_ip(t, &udp(5000, 10), &mut io);
            core.poll(t, &mut io);
            t += 100 * MS;
        }
        assert!(hs_inits(&node, &io).is_empty());
        core.send_ip(t, &udp(5000, 10), &mut io);
        assert!(core.poll(t, &mut io) <= t + HANDSHAKE_RETRY);
        assert_eq!(core.stats.resumes, 1);
        assert_eq!(hs_inits(&node, &io).len(), 1);
        assert!(core.hello().is_some(), "the session carries on meanwhile");

        // Retried on the next path while the node stays silent.
        io.sent.clear();
        core.poll(t + HANDSHAKE_RETRY / 2, &mut io);
        assert!(hs_inits(&node, &io).is_empty());
        t += HANDSHAKE_RETRY;
        core.send_ip(t, &udp(5000, 10), &mut io);
        core.poll(t, &mut io);
        let inits = hs_inits(&node, &io);
        assert_eq!(inits.len(), 1);
        assert_eq!(inits[0].0, 1);
        assert_eq!(core.stats.resumes, 1, "a retry, not a new start");

        // The node answers: the new session replaces the old one.
        let mut resp = node.answer(&inits[0].1, &Psk::ZERO);
        core.handle_datagram(t + 160 * MS, 1, &mut resp, &mut io);
        assert_eq!(core.stats.handshakes, 2);
        io.sent.clear();
        assert!(core.send_ip(t + 200 * MS, &udp(5000, 10), &mut io));
        let f = node.frames(&io.sent.last().unwrap().1);
        assert!(f.iter().any(|f| f.starts_with("Ip")), "{f:?}");
    }

    #[test]
    fn idle_session_waits_for_the_dead_limit() {
        let (mut core, mut node, mut io) = setup();
        connect(&mut core, &mut node, &mut io);
        io.sent.clear();
        let t = 1000 + CLIENT_RESUME + SECOND;
        let next = core.poll(t, &mut io);
        assert!(next > t, "idle: no deadline in the past ({next} <= {t})");
        assert!(hs_inits(&node, &io).is_empty());
        assert!(core.hello().is_some());
    }

    #[test]
    fn data_after_an_idle_spell_does_not_count_the_idle_silence() {
        // Idle for 12s (PINGs 10s apart): `last_rx` is old when the game
        // starts, but the node has had no chance to answer yet.
        let (mut core, mut node, mut io) = setup();
        connect(&mut core, &mut node, &mut io);
        let t = 1000 + 12 * SECOND;
        core.send_ip(t, &udp(5000, 10), &mut io);
        core.poll(t, &mut io);
        assert!(hs_inits(&node, &io).is_empty());
        assert_eq!(core.stats.resumes, 0);
        // Still silent 3s into the traffic: now it is suspicious.
        let t = t + CLIENT_RESUME;
        core.send_ip(t, &udp(5000, 10), &mut io);
        core.poll(t, &mut io);
        assert_eq!(core.stats.resumes, 1);
    }

    #[test]
    fn recovered_session_stops_retrying_but_takes_a_late_answer() {
        let (mut core, mut node, mut io) = setup();
        connect(&mut core, &mut node, &mut io);
        // Sent by the node before it got HS_INIT, arriving afterwards.
        let mut late = node.control(&Frame::Pong(Pong {
            path: 0,
            id: 0,
            ts: 0,
            hold_us: 0,
        }));
        core.send_ip(1000, &udp(5000, 10), &mut io);
        let t = 1000 + CLIENT_RESUME + 1;
        core.send_ip(t, &udp(5000, 10), &mut io);
        core.poll(t, &mut io);
        let inits = hs_inits(&node, &io);
        assert_eq!(inits.len(), 1);

        core.handle_datagram(t + 100 * MS, 0, &mut late, &mut io);
        io.sent.clear();
        core.send_ip(t + 2 * SECOND, &udp(5000, 10), &mut io);
        core.poll(t + 2 * SECOND, &mut io);
        assert!(hs_inits(&node, &io).is_empty(), "no retry once heard from");

        // The node did accept HS_INIT (and dropped the old session): its
        // answer still switches the client over.
        let mut resp = node.answer(&inits[0].1, &Psk::ZERO);
        core.handle_datagram(t + 2 * SECOND, 0, &mut resp, &mut io);
        assert_eq!(core.stats.handshakes, 2);
        io.sent.clear();
        assert!(core.send_ip(t + 3 * SECOND, &udp(5000, 10), &mut io));
        assert!(!node.frames(&io.sent.last().unwrap().1).is_empty());
    }

    #[test]
    fn closed_core_stays_closed() {
        let (mut core, mut node, mut io) = setup_with(2, Policy::SINGLE);
        connect(&mut core, &mut node, &mut io);
        io.sent.clear();
        core.close(&mut io);
        assert_eq!(io.sent.len(), 2, "CLOSE on every path");
        io.sent.clear();
        core.poll(SECOND, &mut io);
        core.poll(60 * SECOND, &mut io);
        assert!(io.sent.is_empty(), "no new handshake");
    }

    #[test]
    fn pong_and_probe_results_are_reported() {
        let (mut core, mut node, mut io) = setup_with(2, Policy::SINGLE);
        connect(&mut core, &mut node, &mut io);
        io.sent.clear();
        core.ping_all(5000, &mut io);
        assert_eq!(io.sent.iter().map(|s| s.0).collect::<Vec<_>>(), vec![0, 1]);
        let mut pong = node.control(&Frame::Pong(Pong {
            path: 1,
            id: 1,
            ts: 5000,
            hold_us: 0,
        }));
        core.handle_datagram(9000, 1, &mut pong, &mut io);
        assert_eq!(io.pongs, vec![(1, 4000)]);

        let req = ProbeReq {
            id: 3,
            kind: skyblock_proto::frame::ProbeKind::Tcp,
            ip: Ipv4Addr::new(203, 0, 113, 9),
            port: 443,
            count: 5,
            interval_ms: 100,
        };
        io.sent.clear();
        assert!(core.send_probe(req, &mut io));
        assert!(node.frames(&io.sent[0].1)[0].starts_with("ProbeReq"));
        let resp = ProbeResp {
            id: 3,
            sent: 5,
            recv: 5,
            min_us: 10,
            avg_us: 11,
            max_us: 12,
        };
        let mut pkt = node.control(&Frame::ProbeResp(resp));
        core.handle_datagram(9500, 0, &mut pkt, &mut io);
        assert_eq!(io.probes, vec![resp]);
    }
}
