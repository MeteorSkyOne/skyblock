//! Transport-independent server logic (SPEC §3.6–3.9, §4, §7.2): handshakes,
//! in-channel rekeys, sessions, paths, redundant sending and frame
//! handling. The event loop feeds datagrams in and performs the I/O
//! requested through [`ServerIo`].

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::{Ipv4Addr, SocketAddr};

use rand::SeedableRng;
use rand::rngs::StdRng;
use skyblock_proto::Micros;
use skyblock_proto::flow::{Class, Flow, FlowClassifier, FlowKey};
use skyblock_proto::frame::{
    Frame, FrameReader, NackRange, PathStats, Pong, ProbeReq, ProbeResp, Stats,
};
use skyblock_proto::handshake::{MAX_MSG_LEN, PendingResponse, ServerHello};
use skyblock_proto::ip::Ipv4Packet;
use skyblock_proto::keys::{Keyset, PrivateKey, Psk, PublicKey, SessionKeys};
use skyblock_proto::nack;
use skyblock_proto::packet::{MIN_LEN, PacketBuf};
use skyblock_proto::path::{PathMetrics, Ranking, down_after};
use skyblock_proto::sched::{Plan, Policy, SchedStats, Scheduler};
use skyblock_proto::session::{Data, KeyPhase, RxState, TxState, open_handshake, seal_handshake};
use skyblock_proto::timing::{
    ACTIVE_WINDOW, PATH_FORGET, SECOND, SERVER_SESSION_EXPIRE, STATS_ACTIVE, STATS_IDLE,
};
use tracing::{debug, info};

use crate::filter::InnerFilter;
use crate::limit::RateLimiter;
use crate::shape::Shaper;

/// A session whose client never proved key possession is dropped sooner.
const UNCONFIRMED_EXPIRE: Micros = 30 * SECOND;

/// Most pings one PROBE_REQ may ask for.
pub const MAX_PROBE_COUNT: u8 = 20;

pub trait ServerIo {
    /// Sends a tunnel packet from local socket `sock` to `to`.
    fn send(&mut self, sock: usize, to: SocketAddr, pkt: &[u8]);
    /// Hands over an inner packet from `user` that passed the filter.
    fn deliver(&mut self, user: usize, ip: &[u8]);
    /// Starts a latency probe for `user` (already validated); the result
    /// goes back through [`Core::send_control`].
    fn probe(&mut self, _user: usize, _req: ProbeReq) {}
}

pub struct User {
    pub name: String,
    pub key: PublicKey,
    pub psk: Psk,
    pub vip: Ipv4Addr,
    last_ts: u64,
}

impl User {
    pub fn new(name: String, key: PublicKey, psk: Psk, vip: Ipv4Addr) -> Self {
        Self {
            name,
            key,
            psk,
            vip,
            last_ts: 0,
        }
    }
}

pub struct CoreParams {
    pub mtu: u16,
    pub resolver: Ipv4Addr,
    pub pad_max: usize,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CoreStats {
    pub handshakes: u64,
    pub rejected_handshakes: u64,
    pub rate_limited: u64,
    pub unauthenticated: u64,
    /// Packets from an unknown address matched to a session by trial
    /// decryption (new paths, NAT rebinding).
    pub roamed: u64,
    pub filtered: u64,
    pub delivered: u64,
    /// Inner packets sent to clients, and those sent as bulk (one copy).
    pub sent: u64,
    pub sent_bulk: u64,
    /// In-channel rekeys completed (the client switched to the new keys).
    pub rekeys: u64,
    pub probes: u64,
}

struct Path {
    /// Client-side path id, learned from PING frames.
    id: Option<u8>,
    sock: usize,
    addr: SocketAddr,
    m: PathMetrics,
}

struct Session {
    tx: TxState,
    rx: RxState,
    sched: Scheduler,
    policy: Policy,
    flows: FlowClassifier,
    /// Set once the client sent something under the session keys.
    confirmed: bool,
    paths: Vec<Path>,
    ranking: Ranking,
    last_rx: Micros,
    /// Last inner data either way; 0 = never.
    last_active: Micros,
    next_stats: Micros,
    established: Micros,
    /// Sending keys from an answered REKEY_INIT, used once the client
    /// sends under its new keys.
    next_tx: Option<Keyset>,
    rekeys: u64,
    /// Bulk shaping towards the client (`TUNE` `bulk_rate_kbps`).
    shaper: Option<Shaper>,
    /// NACK frames sent to the client.
    nacks_sent: u64,
}

impl Session {
    fn active(&self, now: Micros) -> bool {
        self.last_active != 0 && now.saturating_sub(self.last_active) < ACTIVE_WINDOW
    }

    fn touch(&mut self, now: Micros) {
        if !self.active(now) {
            self.next_stats = self.next_stats.min(now + STATS_ACTIVE);
        }
        self.last_active = now;
    }

    /// The best path's smoothed RTT as the client reports it (0: none yet).
    fn best_srtt(&self) -> Micros {
        self.ranking
            .best()
            .and_then(|i| self.paths.get(i))
            .map_or(0, |p| p.m.rtt.srtt)
    }

    fn rerank(&mut self, now: Micros) {
        let down = down_after(self.active(now));
        self.ranking
            .update(now, down, self.paths.iter().map(|p| &p.m));
    }
}

pub struct Core {
    local: PrivateKey,
    obfs: SessionKeys,
    params: CoreParams,
    filter: InnerFilter,
    users: Vec<User>,
    by_key: HashMap<PublicKey, usize>,
    by_vip: HashMap<Ipv4Addr, usize>,
    /// Indexed by user: at most one session per user.
    sessions: Vec<Option<Session>>,
    by_addr: HashMap<(usize, SocketAddr), usize>,
    hs_limit: RateLimiter,
    trial_limit: RateLimiter,
    rng: StdRng,
    hs_buf: PacketBuf,
    /// Scratch space for NACK ranges.
    nack_buf: Vec<NackRange>,
    pub stats: CoreStats,
}

impl Core {
    pub fn new(
        local: PrivateKey,
        users: Vec<User>,
        params: CoreParams,
        filter: InnerFilter,
    ) -> Self {
        let obfs = SessionKeys::obfuscation(&local.public_key());
        let by_key = users.iter().enumerate().map(|(i, u)| (u.key, i)).collect();
        let by_vip = users.iter().enumerate().map(|(i, u)| (u.vip, i)).collect();
        let sessions = users.iter().map(|_| None).collect();
        Self {
            local,
            obfs,
            params,
            filter,
            users,
            by_key,
            by_vip,
            sessions,
            by_addr: HashMap::new(),
            hs_limit: RateLimiter::per_ip(5.0, 10.0).with_global(100.0, 100.0),
            trial_limit: RateLimiter::per_ip(20.0, 20.0),
            rng: StdRng::from_rng(&mut rand::rng()),
            hs_buf: PacketBuf::new(),
            nack_buf: Vec::new(),
            stats: CoreStats::default(),
        }
    }

    pub fn user_by_vip(&self, ip: Ipv4Addr) -> Option<usize> {
        self.by_vip.get(&ip).copied()
    }

    pub fn filter(&self) -> &InnerFilter {
        &self.filter
    }

    pub fn user_count(&self) -> usize {
        self.users.len()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.iter().flatten().count()
    }

    /// Redundancy counters summed over the live sessions.
    pub fn sched_stats(&self) -> SchedStats {
        self.sessions
            .iter()
            .flatten()
            .fold(SchedStats::default(), |mut acc, s| {
                acc.copies_sent += s.sched.stats.copies_sent;
                acc.copies_dropped += s.sched.stats.copies_dropped;
                acc
            })
    }

    /// Processes one datagram received on local socket `sock`. `pkt` is
    /// decrypted in place.
    pub fn handle_datagram(
        &mut self,
        now: Micros,
        sock: usize,
        from: SocketAddr,
        pkt: &mut [u8],
        io: &mut impl ServerIo,
    ) {
        if pkt.len() < MIN_LEN {
            self.stats.unauthenticated += 1;
            return;
        }
        let known = self.by_addr.get(&(sock, from)).copied();
        if let Some(u) = known {
            if self.on_session_packet(now, u, sock, from, pkt, io) {
                return;
            }
        }
        if let Ok(body) = open_handshake(&self.obfs.c2s, pkt) {
            self.on_handshake(now, sock, from, body, io);
            return;
        }
        // Unknown address: a client that roamed or opened a new path.
        if self.trial_limit.allow(now, from.ip()) {
            for u in 0..self.sessions.len() {
                if Some(u) != known
                    && self.sessions[u].is_some()
                    && self.on_session_packet(now, u, sock, from, pkt, io)
                {
                    self.stats.roamed += 1;
                    return;
                }
            }
        }
        self.stats.unauthenticated += 1;
    }

    /// Sends an inner packet to `user`'s client with the redundancy its
    /// flow gets. Returns whether it was sent.
    pub fn send_ip(&mut self, now: Micros, user: usize, ip: &[u8], io: &mut impl ServerIo) -> bool {
        let Some(Some(s)) = self.sessions.get_mut(user) else {
            return false;
        };
        if !s.confirmed {
            return false;
        }
        let Ok(p) = Ipv4Packet::parse(ip) else {
            return false;
        };
        s.touch(now);
        let flow = s.flows.classify(now, FlowKey::of(&p), ip.len());
        if flow.class == Class::Bulk
            && let Some(sh) = &mut s.shaper
            && !sh.offer(now, flow.hash, ip)
        {
            // Queued behind the bucket (or dropped: queue full).
            return true;
        }
        let plan = Plan::for_flow(&s.policy, flow);
        let Session {
            tx,
            sched,
            paths,
            ranking,
            ..
        } = s;
        let ok = sched
            .send_ip(tx, now, ip, plan, ranking, |i, pkt| {
                if let Some(p) = paths.get_mut(i) {
                    p.m.tx_pkts += 1;
                    io.send(p.sock, p.addr, pkt);
                }
            })
            .is_ok();
        if ok {
            self.stats.sent += 1;
            if flow.class == Class::Bulk {
                self.stats.sent_bulk += 1;
            }
        }
        ok
    }

    /// Sends delayed copies and shaped bulk packets that are due, and
    /// NACKs for gaps that stayed open.
    pub fn poll(&mut self, now: Micros, io: &mut impl ServerIo) {
        let nacks = &mut self.nack_buf;
        for s in self.sessions.iter_mut().flatten() {
            let Session {
                tx,
                rx,
                sched,
                paths,
                ranking,
                policy,
                shaper,
                nacks_sent,
                ..
            } = s;
            let mut send = |i: usize, pkt: &[u8]| {
                if let Some(p) = paths.get_mut(i) {
                    p.m.tx_pkts += 1;
                    io.send(p.sock, p.addr, pkt);
                }
            };
            if sched.next_due().is_some_and(|d| d <= now) {
                sched.poll(tx, now, ranking, &mut send);
            }
            if let Some(sh) = shaper
                && sh.next_due().is_some_and(|d| d <= now)
            {
                sh.poll(now, |hash, pkt| {
                    let plan = Plan::for_flow(
                        policy,
                        Flow {
                            class: Class::Bulk,
                            hash,
                        },
                    );
                    let _ = sched.send_ip(tx, now, pkt, plan, ranking, &mut send);
                });
            }
            if rx.next_nack().is_some_and(|d| d <= now) {
                rx.nacks(now, nacks);
                if !nacks.is_empty()
                    && let Some(best) = ranking.best()
                    && let Ok(out) = tx.control(|w| w.nack(nacks))
                {
                    send(best, out);
                    *nacks_sent += 1;
                }
            }
        }
    }

    /// Sends one control frame (e.g. PROBE_RESP) to `user`'s client on its
    /// best path. Returns whether it was sent.
    pub fn send_control(&mut self, user: usize, frame: &Frame<'_>, io: &mut impl ServerIo) -> bool {
        let Some(Some(s)) = self.sessions.get_mut(user) else {
            return false;
        };
        let Some(i) = s.ranking.best().filter(|_| s.confirmed) else {
            return false;
        };
        let Ok(out) = s.tx.control(|w| w.write(frame)) else {
            return false;
        };
        let p = &mut s.paths[i];
        p.m.tx_pkts += 1;
        io.send(p.sock, p.addr, out);
        true
    }

    /// When the earliest delayed copy, shaped packet or NACK is due.
    pub fn next_due(&self) -> Option<Micros> {
        self.sessions
            .iter()
            .flatten()
            .flat_map(|s| {
                [
                    s.sched.next_due(),
                    s.shaper.as_ref().and_then(Shaper::next_due),
                    s.rx.next_nack(),
                ]
            })
            .flatten()
            .min()
    }

    /// Housekeeping: STATS, path ranking, and expiry of sessions, paths,
    /// flows, reassemblies and rate limiters.
    pub fn tick(&mut self, now: Micros, io: &mut impl ServerIo) {
        for u in 0..self.sessions.len() {
            let Some(s) = &mut self.sessions[u] else {
                continue;
            };
            let idle = now.saturating_sub(s.last_rx);
            if idle > SERVER_SESSION_EXPIRE || (!s.confirmed && idle > UNCONFIRMED_EXPIRE) {
                info!(user = %self.users[u].name, idle_s = idle / SECOND, "session expired");
                self.drop_session(u);
                continue;
            }
            s.rx.expire(now);
            s.flows.expire(now);
            let by_addr = &mut self.by_addr;
            s.paths.retain(|p| {
                let keep = now.saturating_sub(p.m.last_rx) <= PATH_FORGET;
                if !keep {
                    by_addr.remove(&(p.sock, p.addr));
                }
                keep
            });
            s.rerank(now);
            if s.confirmed && now >= s.next_stats {
                send_stats(s, now, io);
            }
        }
        self.hs_limit.cleanup(now);
        self.trial_limit.cleanup(now);
    }

    /// Per-user session state for `skyblock-server status`. `ports[i]` is
    /// the port of local socket `i`; `extra(user)` is appended to the
    /// user's first line (e.g. NAT mapping count).
    pub fn report(
        &self,
        now: Micros,
        ports: &[u16],
        extra: impl Fn(usize) -> String,
        out: &mut String,
    ) {
        let ms = |us: Micros| us as f64 / 1000.0;
        let pct = |v: f32| v * 100.0;
        for (u, user) in self.users.iter().enumerate() {
            let Some(s) = &self.sessions[u] else {
                let _ = writeln!(
                    out,
                    "user {} ({}): no session{}",
                    user.name,
                    user.vip,
                    extra(u)
                );
                continue;
            };
            let up = s.active(now);
            let _ = writeln!(
                out,
                "user {} ({}): session {} {}, last packet {:.1}s ago, {}, copies {} paths {} delay {:.1}ms, rekeys {}, flows {} (bulk {}){}",
                user.name,
                user.vip,
                duration(now.saturating_sub(s.established)),
                if s.confirmed {
                    "confirmed"
                } else {
                    "unconfirmed"
                },
                now.saturating_sub(s.last_rx) as f64 / SECOND as f64,
                if up { "active" } else { "idle" },
                s.policy.copies,
                s.policy.paths,
                ms(s.policy.copy_delay),
                s.rekeys,
                s.flows.len(),
                s.flows.bulk_count(),
                extra(u),
            );
            let down = down_after(up);
            for (i, p) in s.paths.iter().enumerate() {
                let id = p.id.map_or_else(|| "?".to_owned(), |id| id.to_string());
                let port = ports.get(p.sock).copied().unwrap_or(0);
                let rank = s.ranking.order().iter().position(|&r| usize::from(r) == i);
                let _ = writeln!(
                    out,
                    "  path {id:>2}  {} -> :{port}  {}{}  rtt {:.1}ms ±{:.1}  loss out {:.2}% in {:.2}%  tx {} rx {}",
                    p.addr,
                    if p.m.is_up(now, down) { "up  " } else { "down" },
                    if rank == Some(0) { " best" } else { "     " },
                    ms(p.m.rtt.srtt),
                    ms(p.m.rtt.rttvar),
                    pct(p.m.loss_out()),
                    pct(p.m.loss_in()),
                    p.m.tx_pkts,
                    p.m.rx_pkts,
                );
            }
            let r = s.rx.stats;
            let _ = writeln!(
                out,
                "  received {} unique, {} duplicate, {} rescued; sent {} items, {} extra copies",
                r.unique,
                r.dup,
                r.rescued,
                s.tx.items_sent(),
                s.sched.stats.copies_sent,
            );
            if s.policy.nack || s.policy.piggyback > 0 {
                let _ = writeln!(
                    out,
                    "  recovery: nack {}, piggyback {}; received {} retransmitted, {} piggybacked; sent {} NACKs, {} retransmits, {} piggybacked",
                    if s.policy.nack { "on" } else { "off" },
                    s.policy.piggyback,
                    r.retx,
                    r.piggy,
                    s.nacks_sent,
                    s.sched.stats.retransmits,
                    s.sched.stats.piggybacked,
                );
            }
            if let Some(sh) = &s.shaper {
                let st = sh.stats;
                let _ = writeln!(
                    out,
                    "  shaping {}kbps: passed {}, queued {}, dropped {}, backlog {}/{} bytes",
                    sh.rate_kbps(),
                    st.passed,
                    st.queued,
                    st.dropped,
                    sh.queued_bytes(),
                    sh.limit_bytes(),
                );
            }
        }
    }

    fn on_handshake(
        &mut self,
        now: Micros,
        sock: usize,
        from: SocketAddr,
        body: &[u8],
        io: &mut impl ServerIo,
    ) {
        let Some(Ok(Frame::HsInit(msg))) = FrameReader::new(body).next() else {
            self.stats.rejected_handshakes += 1;
            return;
        };
        if !self.hs_limit.allow(now, from.ip()) {
            self.stats.rate_limited += 1;
            return;
        }
        let pending = match PendingResponse::read(&self.local, msg) {
            Ok(p) => p,
            Err(e) => {
                debug!(%from, "handshake rejected: {e}");
                self.stats.rejected_handshakes += 1;
                return;
            }
        };
        let Some(&u) = self.by_key.get(&pending.client) else {
            debug!(%from, client = %pending.client, "handshake from unknown key");
            self.stats.rejected_handshakes += 1;
            return;
        };
        let user = &mut self.users[u];
        if pending.hello.timestamp <= user.last_ts {
            debug!(%from, user = %user.name, "stale or replayed handshake");
            self.stats.rejected_handshakes += 1;
            return;
        }
        user.last_ts = pending.hello.timestamp;
        let n_paths = pending.hello.n_paths;
        let hello = ServerHello {
            vip: user.vip,
            resolver: self.params.resolver,
            mtu: self.params.mtu,
            flags: 0,
        };
        let mut msg2 = [0u8; MAX_MSG_LEN];
        let (n, keys) = match pending.accept(&user.psk, &hello, &mut msg2) {
            Ok(r) => r,
            Err(e) => {
                debug!(%from, "handshake response failed: {e}");
                self.stats.rejected_handshakes += 1;
                return;
            }
        };

        self.drop_session(u);
        let policy = Policy::SINGLE;
        let mut s = Session {
            tx: TxState::new(keys.s2c, self.params.pad_max),
            rx: RxState::new(keys.c2s),
            sched: Scheduler::new(),
            policy,
            flows: FlowClassifier::new(policy.bulk_enter_kbps, policy.bulk_exit_kbps),
            confirmed: false,
            paths: vec![Path {
                id: None,
                sock,
                addr: from,
                m: PathMetrics::new(now),
            }],
            ranking: Ranking::default(),
            last_rx: now,
            last_active: 0,
            next_stats: now + STATS_IDLE,
            established: now,
            next_tx: None,
            rekeys: 0,
            shaper: None,
            nacks_sent: 0,
        };
        s.rerank(now);
        self.sessions[u] = Some(s);
        self.by_addr.insert((sock, from), u);
        if let Ok(pkt) = seal_handshake(
            &self.obfs.s2c,
            &Frame::HsResp(&msg2[..n]),
            &mut self.rng,
            &mut self.hs_buf,
        ) {
            io.send(sock, from, pkt);
        }
        self.stats.handshakes += 1;
        info!(user = %self.users[u].name, %from, paths = n_paths, "session established");
    }

    /// Tries `pkt` against `u`'s session keys; returns whether it was
    /// authentic (and has been processed).
    fn on_session_packet(
        &mut self,
        now: Micros,
        u: usize,
        sock: usize,
        from: SocketAddr,
        pkt: &mut [u8],
        io: &mut impl ServerIo,
    ) -> bool {
        let Core {
            local,
            params,
            sessions,
            by_addr,
            filter,
            users,
            hs_limit,
            stats,
            ..
        } = self;
        let Some(s) = sessions[u].as_mut() else {
            return false;
        };
        let Ok((body, phase)) = s.rx.open(now, pkt) else {
            return false;
        };
        if phase == KeyPhase::Next {
            // The client uses the keys from its last rekey: follow suit.
            if let Some(k) = s.next_tx.take() {
                s.tx.rekey(k);
            }
            s.rekeys += 1;
            stats.rekeys += 1;
            debug!(user = %users[u].name, "rekeyed");
        }
        s.last_rx = now;
        s.confirmed = true;
        let mut path = match s
            .paths
            .iter()
            .position(|p| p.sock == sock && p.addr == from)
        {
            Some(i) => i,
            None => {
                debug!(user = %users[u].name, %from, "new path");
                s.paths.push(Path {
                    id: None,
                    sock,
                    addr: from,
                    m: PathMetrics::new(now),
                });
                by_addr.insert((sock, from), u);
                s.rerank(now);
                s.paths.len() - 1
            }
        };
        s.paths[path].m.on_rx(now);

        let vip = users[u].vip;
        let mut close = false;
        for frame in FrameReader::new(body) {
            let Ok(frame) = frame else { break };
            match frame {
                Frame::Ping(p) => {
                    path = learn_path_id(s, by_addr, path, p.path, now);
                    let pong = Frame::Pong(Pong {
                        path: p.path,
                        id: p.id,
                        ts: p.ts,
                        hold_us: 0,
                    });
                    if let Ok(out) = s.tx.control(|w| w.write(&pong)) {
                        let p = &mut s.paths[path];
                        p.m.tx_pkts += 1;
                        io.send(p.sock, p.addr, out);
                    }
                }
                Frame::Tune(t) => {
                    let policy = Policy::from_tune(&t);
                    if policy != s.policy {
                        debug!(user = %users[u].name, ?policy, "redundancy policy");
                        s.flows
                            .set_thresholds(policy.bulk_enter_kbps, policy.bulk_exit_kbps);
                        s.rx.set_nack_wait(policy.nack.then(|| nack::wait_for(policy.copy_delay)));
                        let rate = policy.bulk_rate_kbps;
                        let same = s
                            .shaper
                            .as_ref()
                            .is_some_and(|sh| sh.rate_kbps() == u64::from(rate));
                        if rate == 0 {
                            s.shaper = None;
                        } else if !same {
                            let mut sh = Shaper::new(now, rate);
                            sh.set_rtt(s.best_srtt());
                            s.shaper = Some(sh);
                        }
                        s.policy = policy;
                    }
                }
                Frame::Nack(n) => {
                    let Session {
                        tx,
                        sched,
                        paths,
                        ranking,
                        ..
                    } = &mut *s;
                    sched.on_nack(tx, now, n.ranges(), ranking, |i, pkt| {
                        if let Some(p) = paths.get_mut(i) {
                            p.m.tx_pkts += 1;
                            io.send(p.sock, p.addr, pkt);
                        }
                    });
                }
                Frame::Stats(st) => {
                    for ps in st.paths() {
                        if let Some(p) = s.paths.iter_mut().find(|p| p.id == Some(ps.path)) {
                            p.m.on_peer_stats(ps.tx_pkts, ps.rx_pkts);
                            if ps.srtt_us > 0 {
                                p.m.rtt
                                    .adopt(Micros::from(ps.srtt_us), Micros::from(ps.rttvar_us));
                            }
                        }
                    }
                    s.rerank(now);
                    let rtt = s.best_srtt();
                    if let Some(sh) = &mut s.shaper {
                        sh.set_rtt(rtt);
                    }
                }
                Frame::RekeyInit(msg) => {
                    if !hs_limit.allow(now, from.ip()) {
                        stats.rate_limited += 1;
                        continue;
                    }
                    let user = &mut users[u];
                    let (msg2, n) = match answer_rekey(local, params, user, s, msg) {
                        Ok(r) => r,
                        Err(e) => {
                            debug!(user = %user.name, "rekey rejected: {e}");
                            stats.rejected_handshakes += 1;
                            continue;
                        }
                    };
                    if let Ok(out) = s.tx.control(|w| w.write(&Frame::RekeyResp(&msg2[..n]))) {
                        let p = &mut s.paths[path];
                        p.m.tx_pkts += 1;
                        io.send(p.sock, p.addr, out);
                    }
                }
                Frame::ProbeReq(req) => {
                    stats.probes += 1;
                    if probe_allowed(filter, &req) {
                        io.probe(u, req);
                    } else {
                        debug!(user = %users[u].name, target = %req.ip, "probe refused");
                        let resp = Frame::ProbeResp(ProbeResp {
                            id: req.id,
                            sent: 0,
                            recv: 0,
                            min_us: 0,
                            avg_us: 0,
                            max_us: 0,
                        });
                        if let Ok(out) = s.tx.control(|w| w.write(&resp)) {
                            let p = &mut s.paths[path];
                            p.m.tx_pkts += 1;
                            io.send(p.sock, p.addr, out);
                        }
                    }
                }
                Frame::Close(_) => close = true,
                _ => match s.rx.accept(now, &frame) {
                    Some(Data::Ip(ip)) => {
                        match Ipv4Packet::parse(ip) {
                            Ok(p) => match filter.check(vip, &p) {
                                Ok(()) => {
                                    stats.delivered += 1;
                                    io.deliver(u, p.as_bytes());
                                }
                                Err(reason) => {
                                    stats.filtered += 1;
                                    debug!(user = %users[u].name, dst = %p.dst(), ?reason, "inner packet filtered");
                                }
                            },
                            Err(_) => stats.filtered += 1,
                        }
                        s.touch(now);
                    }
                    Some(Data::EchoReq(e)) => {
                        let (id, ts) = (e.id, e.ts);
                        let mut payload = [0u8; 1500];
                        let n = e.payload.len().min(payload.len());
                        payload[..n].copy_from_slice(&e.payload[..n]);
                        s.touch(now);
                        let plan = Plan::redundant(&s.policy);
                        let Session {
                            tx,
                            sched,
                            paths,
                            ranking,
                            ..
                        } = s;
                        let _ = sched.send_echo(
                            tx,
                            now,
                            false,
                            id,
                            ts,
                            &payload[..n],
                            plan,
                            ranking,
                            |i, pkt| {
                                if let Some(p) = paths.get_mut(i) {
                                    p.m.tx_pkts += 1;
                                    io.send(p.sock, p.addr, pkt);
                                }
                            },
                        );
                    }
                    _ => {}
                },
            }
        }
        if close {
            info!(user = %self.users[u].name, "session closed by client");
            self.drop_session(u);
        }
        true
    }

    fn drop_session(&mut self, u: usize) {
        if let Some(s) = self.sessions[u].take() {
            for p in s.paths {
                self.by_addr.remove(&(p.sock, p.addr));
            }
        }
    }
}

/// `1h02m`, `3m05s`, `42s`.
pub fn duration(us: Micros) -> String {
    let s = us / SECOND;
    match s {
        0..60 => format!("{s}s"),
        60..3600 => format!("{}m{:02}s", s / 60, s % 60),
        _ => format!("{}h{:02}m", s / 3600, s % 3600 / 60),
    }
}

/// Handles REKEY_INIT (SPEC §3.9): a fresh IKpsk2 message 1 from the same
/// client key. Returns message 2, which the caller sends in REKEY_RESP
/// under the current keys, and stages the new keys: receiving ones as
/// `next`, sending ones until the client uses its new keys.
fn answer_rekey(
    local: &PrivateKey,
    params: &CoreParams,
    user: &mut User,
    s: &mut Session,
    msg: &[u8],
) -> Result<([u8; MAX_MSG_LEN], usize), String> {
    let pending = PendingResponse::read(local, msg).map_err(|e| e.to_string())?;
    if pending.client != user.key {
        return Err("different client key".into());
    }
    if pending.hello.timestamp <= user.last_ts {
        return Err("stale or replayed".into());
    }
    user.last_ts = pending.hello.timestamp;
    let hello = ServerHello {
        vip: user.vip,
        resolver: params.resolver,
        mtu: params.mtu,
        flags: 0,
    };
    let mut msg2 = [0u8; MAX_MSG_LEN];
    let (n, keys) = pending
        .accept(&user.psk, &hello, &mut msg2)
        .map_err(|e| e.to_string())?;
    s.rx.set_next(keys.c2s);
    s.next_tx = Some(keys.s2c);
    Ok((msg2, n))
}

/// Whether a PROBE_REQ may run: a reasonable count and interval, and a
/// target clients could reach anyway.
fn probe_allowed(filter: &InnerFilter, req: &ProbeReq) -> bool {
    (1..=MAX_PROBE_COUNT).contains(&req.count)
        && (10..=1000).contains(&req.interval_ms)
        && filter.destination_allowed(req.ip)
}

/// Records that path slot `idx` is the client's path `id`. If another slot
/// held that id (the client's NAT mapping for it changed), this slot takes
/// over its counters and the old slot is removed. Returns `idx`'s position
/// after the removal.
fn learn_path_id(
    s: &mut Session,
    by_addr: &mut HashMap<(usize, SocketAddr), usize>,
    idx: usize,
    id: u8,
    now: Micros,
) -> usize {
    if s.paths[idx].id == Some(id) {
        return idx;
    }
    s.paths[idx].id = Some(id);
    let Some(old) = s
        .paths
        .iter()
        .enumerate()
        .position(|(i, p)| i != idx && p.id == Some(id))
    else {
        return idx;
    };
    let gone = s.paths.remove(old);
    by_addr.remove(&(gone.sock, gone.addr));
    let idx = if old < idx { idx - 1 } else { idx };
    s.paths[idx].m.absorb(&gone.m);
    debug!(path = id, from = %gone.addr, to = %s.paths[idx].addr, "path moved");
    s.rerank(now);
    idx
}

fn send_stats(s: &mut Session, now: Micros, io: &mut impl ServerIo) {
    let mut st = Stats::new(
        s.tx.items_sent(),
        s.rx.stats.unique,
        s.rx.stats.dup,
        s.rx.stats.rescued,
    );
    for p in &s.paths {
        if let Some(id) = p.id {
            st.push_path(PathStats {
                path: id,
                tx_pkts: p.m.tx_pkts,
                rx_pkts: p.m.rx_pkts,
                srtt_us: 0,
                rttvar_us: 0,
            });
        }
    }
    s.next_stats = now
        + if s.active(now) {
            STATS_ACTIVE
        } else {
            STATS_IDLE
        };
    let Some(i) = s.ranking.best() else { return };
    if let Ok(out) = s.tx.control(|w| w.write(&Frame::Stats(st))) {
        let p = &mut s.paths[i];
        p.m.tx_pkts += 1;
        io.send(p.sock, p.addr, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use skyblock_proto::frame::{Echo, Ping, TUNE_NACK, Tune};
    use skyblock_proto::handshake::{ClientHello, Initiator, next_timestamp};
    use skyblock_proto::ip::build_udp;
    use skyblock_proto::timing::MS;
    use std::net::SocketAddrV4;

    const VIP: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);
    const GAME: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([198, 51, 100, 7], port))
    }

    #[derive(Default)]
    struct Io {
        sent: Vec<(usize, SocketAddr, Vec<u8>)>,
        delivered: Vec<(usize, Vec<u8>)>,
        probes: Vec<(usize, ProbeReq)>,
    }

    impl ServerIo for Io {
        fn send(&mut self, sock: usize, to: SocketAddr, pkt: &[u8]) {
            self.sent.push((sock, to, pkt.to_vec()));
        }
        fn deliver(&mut self, user: usize, ip: &[u8]) {
            self.delivered.push((user, ip.to_vec()));
        }
        fn probe(&mut self, user: usize, req: ProbeReq) {
            self.probes.push((user, req));
        }
    }

    struct Client {
        key: PrivateKey,
        tx: Option<TxState>,
        rx: Option<RxState>,
        last_ts: u64,
    }

    struct Harness {
        core: Core,
        node: PublicKey,
        client: Client,
        io: Io,
    }

    impl Harness {
        fn new() -> Self {
            let node = PrivateKey::generate();
            let ckey = PrivateKey::generate();
            let users = vec![User::new("me".into(), ckey.public_key(), Psk::ZERO, VIP)];
            let params = CoreParams {
                mtu: 1400,
                resolver: Ipv4Addr::new(10, 77, 0, 1),
                pad_max: 48,
            };
            let filter = InnerFilter::new("10.77.0.0/16".parse().unwrap(), vec![], None);
            Self {
                node: node.public_key(),
                core: Core::new(node, users, params, filter),
                client: Client {
                    key: ckey,
                    tx: None,
                    rx: None,
                    last_ts: 0,
                },
                io: Io::default(),
            }
        }

        fn feed(&mut self, now: Micros, from: SocketAddr, pkt: &[u8]) {
            let mut p = pkt.to_vec();
            self.core
                .handle_datagram(now, 0, from, &mut p, &mut self.io);
        }

        /// Builds a HS_INIT packet; returns it and the initiator.
        fn hs_init(&mut self) -> (Vec<u8>, Initiator) {
            let ts = next_timestamp(self.client.last_ts);
            self.client.last_ts = ts;
            let hello = ClientHello {
                timestamp: ts,
                n_paths: 1,
                flags: 0,
            };
            let mut m1 = [0u8; MAX_MSG_LEN];
            let (init, n) =
                Initiator::start(&self.client.key, &self.node, &Psk::ZERO, &hello, &mut m1)
                    .unwrap();
            let obfs = SessionKeys::obfuscation(&self.node);
            let mut buf = PacketBuf::new();
            let pkt = seal_handshake(
                &obfs.c2s,
                &Frame::HsInit(&m1[..n]),
                &mut rand::rng(),
                &mut buf,
            )
            .unwrap()
            .to_vec();
            (pkt, init)
        }

        fn handshake(&mut self, from: SocketAddr) -> ServerHello {
            let (pkt, init) = self.hs_init();
            self.feed(0, from, &pkt);
            let (_, to, mut resp) = self.io.sent.pop().expect("HS_RESP");
            assert_eq!(to, from);
            let obfs = SessionKeys::obfuscation(&self.node);
            let body = open_handshake(&obfs.s2c, &mut resp).unwrap();
            let Some(Ok(Frame::HsResp(msg))) = FrameReader::new(body).next() else {
                panic!("expected HS_RESP")
            };
            let (hello, keys) = init.finish(msg).unwrap();
            self.client.tx = Some(TxState::new(keys.c2s, 48));
            self.client.rx = Some(RxState::new(keys.s2c));
            hello
        }

        fn client_ip(&mut self, ip: &[u8]) -> Vec<u8> {
            let mut out = vec![];
            self.client
                .tx
                .as_mut()
                .unwrap()
                .send_ip(ip, |p| out.push(p.to_vec()))
                .unwrap();
            out.remove(0)
        }

        fn client_control(&mut self, frames: &[Frame<'_>]) -> Vec<u8> {
            self.client
                .tx
                .as_mut()
                .unwrap()
                .control(|w| frames.iter().try_for_each(|f| w.write(f)))
                .unwrap()
                .to_vec()
        }

        fn client_ping(&mut self, path: u8, id: u32) -> Vec<u8> {
            self.client_control(&[Frame::Ping(Ping { path, id, ts: 5 })])
        }

        /// Registers `n` paths from ports 1000, 1001, ... with copies/delay.
        fn connect(&mut self, n: u8, copies: u8, delay_us: u32) {
            self.connect_with(
                n,
                Tune {
                    copies,
                    paths: 0,
                    copy_delay_us: delay_us,
                    bulk_enter_kbps: 2000,
                    bulk_exit_kbps: 1000,
                    flags: 0,
                    piggyback: 0,
                    bulk_rate_kbps: 0,
                },
            );
        }

        /// [`connect`](Self::connect) with a full `TUNE`.
        fn connect_with(&mut self, n: u8, tune: Tune) {
            self.handshake(addr(1000));
            let tune = Frame::Tune(tune);
            for i in 0..n {
                let pkt = self.client_control(&[
                    Frame::Ping(Ping {
                        path: i,
                        id: 1,
                        ts: 5,
                    }),
                    tune,
                ]);
                self.feed(1, addr(1000 + u16::from(i)), &pkt);
            }
            self.io.sent.clear();
        }

        /// Opens a server->client packet and returns its frames' debug text.
        fn client_open(&mut self, pkt: &[u8]) -> Vec<String> {
            let mut p = pkt.to_vec();
            let (body, _) = self.client.rx.as_mut().unwrap().open(0, &mut p).unwrap();
            FrameReader::new(body)
                .map(|f| format!("{:?}", f.unwrap()))
                .collect()
        }
    }

    fn udp(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        udp_sized(src, 9000, dst, 4)
    }

    fn udp_sized(src: Ipv4Addr, sport: u16, dst: Ipv4Addr, len: usize) -> Vec<u8> {
        let mut b = vec![0u8; 64 + len];
        let n = build_udp(
            &mut b,
            SocketAddrV4::new(src, sport),
            SocketAddrV4::new(dst, 5000),
            1,
            &vec![1; len],
        )
        .unwrap();
        b.truncate(n);
        b
    }

    #[test]
    fn handshake_ping_and_data_both_ways() {
        let mut h = Harness::new();
        let hello = h.handshake(addr(1000));
        assert_eq!(hello.vip, VIP);
        assert_eq!(hello.mtu, 1400);
        assert_eq!(h.core.session_count(), 1);

        // Unconfirmed: nothing is sent to the client yet.
        assert!(!h.core.send_ip(0, 0, &udp(GAME, VIP), &mut h.io));

        let ping = h.client_ping(0, 7);
        h.feed(1, addr(1000), &ping);
        let (_, to, pong) = h.io.sent.pop().unwrap();
        assert_eq!(to, addr(1000));
        assert!(h.client_open(&pong)[0].starts_with("Pong"));

        let up = h.client_ip(&udp(VIP, GAME));
        h.feed(2, addr(1000), &up);
        assert_eq!(h.io.delivered, vec![(0, udp(VIP, GAME))]);

        assert!(h.core.send_ip(3, 0, &udp(GAME, VIP), &mut h.io));
        let (_, to, down) = h.io.sent.pop().unwrap();
        assert_eq!(to, addr(1000));
        assert!(h.client_open(&down)[0].starts_with("Ip"));
    }

    #[test]
    fn replayed_data_is_delivered_once() {
        let mut h = Harness::new();
        h.handshake(addr(1000));
        let up = h.client_ip(&udp(VIP, GAME));
        h.feed(1, addr(1000), &up);
        h.feed(2, addr(1000), &up);
        h.feed(3, addr(2000), &up);
        assert_eq!(h.io.delivered.len(), 1);
    }

    #[test]
    fn replayed_handshake_gets_no_response() {
        let mut h = Harness::new();
        let (pkt, _) = h.hs_init();
        h.feed(0, addr(1000), &pkt);
        assert_eq!(h.io.sent.len(), 1);
        h.feed(1, addr(1000), &pkt);
        h.feed(2, addr(3000), &pkt);
        assert_eq!(h.io.sent.len(), 1);
        assert_eq!(h.core.stats.rejected_handshakes, 2);
    }

    #[test]
    fn garbage_gets_no_response() {
        let mut h = Harness::new();
        for len in [0usize, 1, 24, 25, 100, 1400] {
            let junk: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
            h.feed(0, addr(1000), &junk);
        }
        assert!(h.io.sent.is_empty());
        assert_eq!(h.core.session_count(), 0);
    }

    #[test]
    fn unknown_client_key_is_ignored() {
        let mut h = Harness::new();
        h.client.key = PrivateKey::generate();
        let (pkt, _) = h.hs_init();
        h.feed(0, addr(1000), &pkt);
        assert!(h.io.sent.is_empty());
        assert_eq!(h.core.session_count(), 0);
    }

    #[test]
    fn roaming_client_is_followed() {
        let mut h = Harness::new();
        h.handshake(addr(1000));
        let ping = h.client_ping(0, 1);
        h.feed(1, addr(1000), &ping);
        // Client's NAT mapping changes; its PING re-registers path 0.
        let ping = h.client_ping(0, 2);
        h.feed(2, addr(4000), &ping);
        assert_eq!(h.core.stats.roamed, 1);
        let up = h.client_ip(&udp(VIP, GAME));
        h.feed(3, addr(4000), &up);
        assert_eq!(h.io.delivered.len(), 1);
        h.io.sent.clear();
        assert!(h.core.send_ip(4, 0, &udp(GAME, VIP), &mut h.io));
        assert_eq!(h.io.sent.len(), 1);
        assert_eq!(h.io.sent[0].1, addr(4000));
        let s = h.core.sessions[0].as_ref().unwrap();
        assert_eq!(s.paths.len(), 1, "old mapping of path 0 dropped");
        assert!(!h.core.by_addr.contains_key(&(0, addr(1000))));
    }

    #[test]
    fn spoofed_and_private_inner_packets_are_filtered() {
        let mut h = Harness::new();
        h.handshake(addr(1000));
        let spoofed = h.client_ip(&udp(Ipv4Addr::new(10, 77, 0, 3), GAME));
        h.feed(1, addr(1000), &spoofed);
        let metadata = h.client_ip(&udp(VIP, Ipv4Addr::new(169, 254, 169, 254)));
        h.feed(2, addr(1000), &metadata);
        assert!(h.io.delivered.is_empty());
        assert_eq!(h.core.stats.filtered, 2);
    }

    #[test]
    fn handshake_rate_limited_per_source() {
        let mut h = Harness::new();
        for _ in 0..30 {
            let (pkt, _) = h.hs_init();
            h.feed(0, addr(1000), &pkt);
        }
        assert_eq!(h.io.sent.len(), 10);
        assert_eq!(h.core.stats.rate_limited, 20);
    }

    #[test]
    fn new_handshake_replaces_session() {
        let mut h = Harness::new();
        h.handshake(addr(1000));
        let old_tx_pkt = h.client_ip(&udp(VIP, GAME));
        h.handshake(addr(1001));
        assert_eq!(h.core.session_count(), 1);
        // Packets under the old keys are no longer accepted.
        h.feed(1, addr(1000), &old_tx_pkt);
        assert!(h.io.delivered.is_empty());
    }

    #[test]
    fn sessions_expire() {
        let mut h = Harness::new();
        h.handshake(addr(1000));
        h.core.tick(UNCONFIRMED_EXPIRE + 1, &mut h.io);
        assert_eq!(
            h.core.session_count(),
            0,
            "unconfirmed session expires early"
        );

        h.handshake(addr(1000));
        let ping = h.client_ping(0, 1);
        h.feed(0, addr(1000), &ping);
        h.core.tick(UNCONFIRMED_EXPIRE + 1, &mut h.io);
        assert_eq!(h.core.session_count(), 1);
        h.core.tick(SERVER_SESSION_EXPIRE + 1, &mut h.io);
        assert_eq!(h.core.session_count(), 0);
    }

    #[test]
    fn close_frame_drops_session() {
        let mut h = Harness::new();
        h.handshake(addr(1000));
        let close = h.client_control(&[Frame::Close(0)]);
        h.feed(1, addr(1000), &close);
        assert_eq!(h.core.session_count(), 0);
    }

    #[test]
    fn paths_register_and_copies_spread_over_them() {
        let mut h = Harness::new();
        h.connect(2, 2, 0);
        let s = h.core.sessions[0].as_ref().unwrap();
        let ids: Vec<_> = s.paths.iter().map(|p| p.id).collect();
        assert_eq!(ids, vec![Some(0), Some(1)]);

        assert!(h.core.send_ip(2, 0, &udp(GAME, VIP), &mut h.io));
        let to: Vec<_> = h.io.sent.iter().map(|s| s.1).collect();
        assert_eq!(to, vec![addr(1000), addr(1001)]);
        let sent = h.io.sent.clone();
        assert!(h.client_open(&sent[1].2)[0].contains("copy: 1"));
    }

    #[test]
    fn delayed_copies_wait_for_poll() {
        let mut h = Harness::new();
        h.connect(2, 2, 2000);
        assert!(h.core.send_ip(10, 0, &udp(GAME, VIP), &mut h.io));
        assert_eq!(h.io.sent.len(), 1);
        assert_eq!(h.core.next_due(), Some(10 + 2 * MS));
        h.core.poll(10 + 2 * MS - 1, &mut h.io);
        assert_eq!(h.io.sent.len(), 1);
        h.core.poll(10 + 2 * MS, &mut h.io);
        assert_eq!(h.io.sent.len(), 2);
        assert_eq!(h.io.sent[1].1, addr(1001));
        assert_eq!(h.core.next_due(), None);
        assert_eq!(h.core.sched_stats().copies_sent, 1);
    }

    #[test]
    fn bulk_downloads_get_one_copy() {
        let mut h = Harness::new();
        h.connect(2, 2, 0);
        let big = udp_sized(GAME, 443, VIP, 1200);
        let mut t = 10;
        for _ in 0..1200 {
            h.core.send_ip(t, 0, &big, &mut h.io);
            t += MS;
        }
        h.io.sent.clear();
        h.core.send_ip(t, 0, &big, &mut h.io);
        assert_eq!(h.io.sent.len(), 1);
        assert!(h.core.stats.sent_bulk > 0);
        h.core.send_ip(t, 0, &udp(GAME, VIP), &mut h.io);
        assert_eq!(h.io.sent.len(), 3, "game flow still doubled");
    }

    fn tune(copies: u8, flags: u8, bulk_rate_kbps: u32) -> Tune {
        Tune {
            copies,
            paths: 0,
            copy_delay_us: 0,
            bulk_enter_kbps: 2000,
            bulk_exit_kbps: 1000,
            flags,
            piggyback: 0,
            bulk_rate_kbps,
        }
    }

    #[test]
    fn nack_both_ways() {
        let mut h = Harness::new();
        h.connect_with(1, tune(1, TUNE_NACK, 0));
        // Down: game items are kept and resent once for a NACK.
        for t in 0..3 {
            assert!(h.core.send_ip(10 + t, 0, &udp(GAME, VIP), &mut h.io));
        }
        h.io.sent.clear();
        let nack = [NackRange { start: 1, count: 1 }];
        let pkt = h
            .client
            .tx
            .as_mut()
            .unwrap()
            .control(|w| w.nack(&nack))
            .unwrap()
            .to_vec();
        h.feed(20, addr(1000), &pkt);
        let (_, _, resent) = h.io.sent.pop().expect("retransmission");
        let f = h.client_open(&resent);
        assert!(f[0].starts_with("Ip(Ip { seq: 1, copy: 255"), "{f:?}");

        // Up: a gap in the client's items gets a NACK once it is due.
        let a = h.client_ip(&udp(VIP, GAME));
        let _lost = h.client_ip(&udp(VIP, GAME));
        let c = h.client_ip(&udp(VIP, GAME));
        h.feed(100, addr(1000), &a);
        h.feed(101, addr(1000), &c);
        assert_eq!(h.core.next_due(), Some(101 + 5 * MS));
        h.io.sent.clear();
        h.core.poll(101 + 5 * MS - 1, &mut h.io);
        assert!(h.io.sent.is_empty());
        h.core.poll(101 + 5 * MS, &mut h.io);
        let (_, _, pkt) = h.io.sent.pop().expect("NACK");
        assert!(h.client_open(&pkt)[0].starts_with("Nack"));
        assert_eq!(h.core.next_due(), None);
    }

    #[test]
    fn bulk_is_shaped_while_game_packets_pass() {
        let mut h = Harness::new();
        // 8000 kbps = 1 MB/s; the download below offers 2.4 MB/s.
        h.connect_with(1, tune(2, 0, 8000));
        let big = udp_sized(GAME, 443, VIP, 1200);
        let mut t = 10;
        let mut sent_late = 0;
        for i in 0..3000 {
            if i == 2000 {
                h.io.sent.clear();
            }
            h.core.send_ip(t, 0, &big, &mut h.io);
            h.core.poll(t, &mut h.io);
            t += 500;
            if i >= 2000 {
                sent_late = h.io.sent.len();
            }
        }
        // The last 0.5s (well after classification): 1 MB/s of 1256B packets.
        assert!((380..=420).contains(&sent_late), "{sent_late}");
        h.io.sent.clear();
        assert!(h.core.send_ip(t, 0, &udp(GAME, VIP), &mut h.io));
        assert_eq!(h.io.sent.len(), 2, "game packets skip the bulk queue");
        let mut out = String::new();
        h.core.report(t, &[40001], |_| String::new(), &mut out);
        assert!(out.contains("  shaping 8000kbps: passed"), "{out}");
        // Rate 0 turns shaping off.
        let off = h.client_control(&[Frame::Tune(tune(2, 0, 0))]);
        h.feed(t, addr(1000), &off);
        let mut out = String::new();
        h.core.report(t, &[40001], |_| String::new(), &mut out);
        assert!(!out.contains("shaping"));
    }

    #[test]
    fn echo_is_answered_with_copies() {
        let mut h = Harness::new();
        h.connect(2, 2, 0);
        let mut req = vec![];
        h.client
            .tx
            .as_mut()
            .unwrap()
            .send_echo(
                true,
                Echo {
                    seq: 0,
                    copy: 0,
                    id: 3,
                    ts: 99,
                    payload: b"xyz",
                },
                |p| req = p.to_vec(),
            )
            .unwrap();
        h.feed(5, addr(1001), &req);
        assert_eq!(h.io.sent.len(), 2);
        let sent = h.io.sent.clone();
        let f = h.client_open(&sent[0].2);
        assert!(
            f[0].starts_with("EchoResp") && f[0].contains("id: 3"),
            "{f:?}"
        );
    }

    #[test]
    fn stats_report_paths_and_rtt_from_client_ranks_paths() {
        let mut h = Harness::new();
        h.connect(2, 1, 0);
        // The client says path 1 is faster.
        let mut st = Stats::new(0, 0, 0, 0);
        for (path, srtt_us) in [(0u8, 160_000u32), (1, 150_000)] {
            st.push_path(PathStats {
                path,
                tx_pkts: 0,
                rx_pkts: 0,
                srtt_us,
                rttvar_us: 0,
            });
        }
        let pkt = h.client_control(&[Frame::Stats(st)]);
        h.feed(10, addr(1000), &pkt);
        assert!(h.core.send_ip(20, 0, &udp(GAME, VIP), &mut h.io));
        assert_eq!(h.io.sent.last().unwrap().1, addr(1001));

        // Active session: STATS goes out on the next tick.
        h.io.sent.clear();
        h.core.tick(20 + STATS_ACTIVE, &mut h.io);
        let sent = h.io.sent.clone();
        assert_eq!(sent.len(), 1);
        let f = h.client_open(&sent[0].2);
        assert!(
            f[0].starts_with("Stats") && f[0].contains("tx_unique: 1"),
            "{f:?}"
        );
    }

    /// REKEY_INIT carrying a fresh message 1 stamped `ts`, and the
    /// initiator that finishes it with the node's REKEY_RESP.
    fn rekey_init_at(h: &mut Harness, key: &PrivateKey, ts: u64) -> (Vec<u8>, Initiator) {
        let hello = ClientHello {
            timestamp: ts,
            n_paths: 1,
            flags: 0,
        };
        let mut m1 = [0u8; MAX_MSG_LEN];
        let (init, n) = Initiator::start(key, &h.node, &Psk::ZERO, &hello, &mut m1).unwrap();
        let pkt = h.client_control(&[Frame::RekeyInit(&m1[..n])]);
        (pkt, init)
    }

    fn rekey_init(h: &mut Harness) -> (Vec<u8>, Initiator) {
        let ts = next_timestamp(h.client.last_ts);
        h.client.last_ts = ts;
        let key = h.client.key.clone();
        rekey_init_at(h, &key, ts)
    }

    #[test]
    fn in_channel_rekey() {
        let mut h = Harness::new();
        h.connect(1, 1, 0);
        let old_up = h.client_ip(&udp(VIP, GAME));

        let (init_pkt, init) = rekey_init(&mut h);
        h.feed(10, addr(1000), &init_pkt);
        let (_, _, resp) = h.io.sent.pop().expect("REKEY_RESP");
        // Sealed under the old keys.
        let mut p = resp.clone();
        let (body, _) = h.client.rx.as_mut().unwrap().open(0, &mut p).unwrap();
        let Some(Ok(Frame::RekeyResp(msg))) = FrameReader::new(body).next() else {
            panic!("expected REKEY_RESP")
        };
        let (_, keys) = init.finish(msg).unwrap();

        // Until the client uses the new keys, the node keeps sending under
        // the old ones.
        assert!(h.core.send_ip(11, 0, &udp(GAME, VIP), &mut h.io));
        let (_, _, down) = h.io.sent.pop().unwrap();
        assert!(h.client_open(&down)[0].starts_with("Ip"));

        h.client.tx.as_mut().unwrap().rekey(keys.c2s);
        h.client.rx.as_mut().unwrap().set_next(keys.s2c);
        let new_up = h.client_ip(&udp(VIP, GAME));
        h.feed(12, addr(1000), &new_up);
        assert_eq!(h.io.delivered.len(), 1);
        assert_eq!(h.core.stats.rekeys, 1);
        // Now the node sends under the new keys...
        assert!(h.core.send_ip(13, 0, &udp(GAME, VIP), &mut h.io));
        let (_, _, down) = h.io.sent.pop().unwrap();
        let mut p = down.clone();
        let (_, phase) = h.client.rx.as_mut().unwrap().open(13, &mut p).unwrap();
        assert_eq!(phase, KeyPhase::Next);
        // ...and a late packet under the old ones still gets through.
        h.feed(14, addr(1000), &old_up);
        assert_eq!(h.io.delivered.len(), 2);
    }

    #[test]
    fn stale_or_foreign_rekey_is_refused() {
        let mut h = Harness::new();
        h.connect(1, 1, 0);
        let (pkt, _) = rekey_init(&mut h);
        h.feed(10, addr(1000), &pkt);
        assert_eq!(h.io.sent.len(), 1);

        // A message 1 no newer than the last one seen.
        let (key, ts) = (h.client.key.clone(), h.client.last_ts);
        let (stale, _) = rekey_init_at(&mut h, &key, ts);
        h.feed(11, addr(1000), &stale);
        assert_eq!(h.io.sent.len(), 1, "stale timestamp: no answer");

        // Another user's key cannot rekey this session.
        let (foreign, _) = rekey_init_at(&mut h, &PrivateKey::generate(), ts + 1);
        h.feed(12, addr(1000), &foreign);
        assert_eq!(h.io.sent.len(), 1);
        assert_eq!(h.core.stats.rejected_handshakes, 2);
    }

    fn probe_req(ip: Ipv4Addr, count: u8) -> ProbeReq {
        ProbeReq {
            id: 5,
            kind: skyblock_proto::frame::ProbeKind::Icmp,
            ip,
            port: 0,
            count,
            interval_ms: 100,
        }
    }

    #[test]
    fn probes_are_validated_and_answered() {
        let mut h = Harness::new();
        h.connect(1, 1, 0);
        let pkt = h.client_control(&[Frame::ProbeReq(probe_req(GAME, 10))]);
        h.feed(10, addr(1000), &pkt);
        assert_eq!(h.io.probes, vec![(0, probe_req(GAME, 10))]);
        assert!(h.io.sent.is_empty());

        for bad in [
            probe_req(Ipv4Addr::new(169, 254, 169, 254), 10),
            probe_req(GAME, 0),
            probe_req(GAME, MAX_PROBE_COUNT + 1),
        ] {
            let pkt = h.client_control(&[Frame::ProbeReq(bad)]);
            h.feed(11, addr(1000), &pkt);
        }
        assert_eq!(h.io.probes.len(), 1);
        let sent = h.io.sent.clone();
        assert_eq!(sent.len(), 3);
        for (_, _, p) in sent {
            let f = h.client_open(&p);
            assert!(
                f[0].starts_with("ProbeResp") && f[0].contains("sent: 0"),
                "{f:?}"
            );
        }

        h.io.sent.clear();
        let resp = Frame::ProbeResp(ProbeResp {
            id: 5,
            sent: 10,
            recv: 9,
            min_us: 1,
            avg_us: 2,
            max_us: 3,
        });
        assert!(h.core.send_control(0, &resp, &mut h.io));
        let (_, to, p) = h.io.sent.pop().unwrap();
        assert_eq!(to, addr(1000));
        assert!(h.client_open(&p)[0].contains("recv: 9"));
        assert!(!h.core.send_control(1, &resp, &mut h.io), "no such user");
    }

    #[test]
    fn status_report() {
        let mut h = Harness::new();
        h.connect(2, 2, 2000);
        let mut out = String::new();
        h.core
            .report(3 * SECOND, &[40001], |u| format!(", nat {u}"), &mut out);
        assert!(
            out.starts_with("user me (10.77.0.2): session 3s confirmed"),
            "{out}"
        );
        assert!(out.contains("copies 2 paths 0 delay 2.0ms"), "{out}");
        assert!(out.contains(", nat 0"), "{out}");
        assert_eq!(out.matches("  path ").count(), 2, "{out}");
        assert!(out.contains("198.51.100.7:1000 -> :40001"), "{out}");
        assert_eq!(duration(3725 * SECOND), "1h02m");
        assert_eq!(duration(185 * SECOND), "3m05s");
    }
}
