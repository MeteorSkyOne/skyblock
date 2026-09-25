//! Transport-independent server logic (SPEC §3.6–3.9, §7.2): handshakes,
//! sessions, paths and frame handling. The event loop feeds datagrams in
//! and performs the I/O requested through [`ServerIo`].

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

use rand::SeedableRng;
use rand::rngs::StdRng;
use skyblock_proto::Micros;
use skyblock_proto::frame::{Frame, FrameReader, Pong};
use skyblock_proto::handshake::{MAX_MSG_LEN, PendingResponse, ServerHello};
use skyblock_proto::ip::Ipv4Packet;
use skyblock_proto::keys::{PrivateKey, Psk, PublicKey, SessionKeys};
use skyblock_proto::packet::{MIN_LEN, PacketBuf};
use skyblock_proto::session::{Data, RxState, TxState, open_handshake, seal_handshake};
use skyblock_proto::timing::{PATH_FORGET, SECOND, SERVER_SESSION_EXPIRE};
use tracing::{debug, info};

use crate::filter::InnerFilter;
use crate::limit::RateLimiter;

/// A session whose client never proved key possession is dropped sooner.
const UNCONFIRMED_EXPIRE: Micros = 30 * SECOND;

pub trait ServerIo {
    /// Sends a tunnel packet from local socket `sock` to `to`.
    fn send(&mut self, sock: usize, to: SocketAddr, pkt: &[u8]);
    /// Hands over an inner packet from `user` that passed the filter.
    fn deliver(&mut self, user: usize, ip: &[u8]);
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
    pub roamed: u64,
    pub filtered: u64,
    pub delivered: u64,
    pub sent: u64,
}

struct Path {
    /// Client-side path id, learned from PING frames.
    id: Option<u8>,
    sock: usize,
    addr: SocketAddr,
    last_rx: Micros,
}

struct Session {
    tx: TxState,
    rx: RxState,
    /// Set once the client sent something under the session keys.
    confirmed: bool,
    paths: Vec<Path>,
    last_rx: Micros,
}

impl Session {
    fn best_path(&self) -> Option<&Path> {
        self.paths.iter().max_by_key(|p| p.last_rx)
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
            stats: CoreStats::default(),
        }
    }

    pub fn user_by_vip(&self, ip: Ipv4Addr) -> Option<usize> {
        self.by_vip.get(&ip).copied()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.iter().flatten().count()
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
        // Unknown address: maybe a client that roamed or opened a new path.
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

    /// Sends an inner packet to `user`'s client. Returns whether it was sent.
    pub fn send_ip(
        &mut self,
        _now: Micros,
        user: usize,
        ip: &[u8],
        io: &mut impl ServerIo,
    ) -> bool {
        let Some(Some(s)) = self.sessions.get_mut(user) else {
            return false;
        };
        if !s.confirmed {
            return false;
        }
        let Some(p) = s.best_path() else {
            return false;
        };
        let (sock, addr) = (p.sock, p.addr);
        let ok = s.tx.send_ip(ip, |pkt| io.send(sock, addr, pkt)).is_ok();
        if ok {
            self.stats.sent += 1;
        }
        ok
    }

    /// Housekeeping: expires sessions, paths, reassemblies, rate limiters.
    pub fn tick(&mut self, now: Micros) {
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
            let by_addr = &mut self.by_addr;
            s.paths.retain(|p| {
                let keep = now.saturating_sub(p.last_rx) <= PATH_FORGET;
                if !keep {
                    by_addr.remove(&(p.sock, p.addr));
                }
                keep
            });
        }
        self.hs_limit.cleanup(now);
        self.trial_limit.cleanup(now);
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
        self.sessions[u] = Some(Session {
            tx: TxState::new(keys.s2c, self.params.pad_max),
            rx: RxState::new(keys.c2s),
            confirmed: false,
            paths: vec![Path {
                id: None,
                sock,
                addr: from,
                last_rx: now,
            }],
            last_rx: now,
        });
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
        info!(user = %self.users[u].name, %from, "session established");
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
            sessions,
            by_addr,
            filter,
            users,
            stats,
            ..
        } = self;
        let Some(s) = sessions[u].as_mut() else {
            return false;
        };
        let Ok(body) = s.rx.open(pkt) else {
            return false;
        };
        s.last_rx = now;
        s.confirmed = true;
        let path = match s
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
                    last_rx: now,
                });
                by_addr.insert((sock, from), u);
                s.paths.len() - 1
            }
        };
        s.paths[path].last_rx = now;

        let vip = users[u].vip;
        let mut close = false;
        for frame in FrameReader::new(body) {
            let Ok(frame) = frame else { break };
            match frame {
                Frame::Ping(p) => {
                    s.paths[path].id = Some(p.path);
                    let pong = Frame::Pong(Pong {
                        path: p.path,
                        id: p.id,
                        ts: p.ts,
                        hold_us: 0,
                    });
                    if let Ok(out) = s.tx.control(|w| w.write(&pong)) {
                        io.send(sock, from, out);
                    }
                }
                Frame::Close(_) => close = true,
                _ => match s.rx.accept(now, &frame) {
                    Some(Data::Ip(ip)) => match Ipv4Packet::parse(ip) {
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
                    },
                    Some(Data::EchoReq(e)) => {
                        if let Ok(out) = s.tx.send_echo(false, e) {
                            io.send(sock, from, out);
                        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use skyblock_proto::frame::Ping;
    use skyblock_proto::handshake::{ClientHello, Initiator, next_timestamp};
    use skyblock_proto::ip::build_udp;
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
    }

    impl ServerIo for Io {
        fn send(&mut self, sock: usize, to: SocketAddr, pkt: &[u8]) {
            self.sent.push((sock, to, pkt.to_vec()));
        }
        fn deliver(&mut self, user: usize, ip: &[u8]) {
            self.delivered.push((user, ip.to_vec()));
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

        fn client_ping(&mut self, id: u32) -> Vec<u8> {
            self.client
                .tx
                .as_mut()
                .unwrap()
                .control(|w| w.write(&Frame::Ping(Ping { path: 0, id, ts: 5 })))
                .unwrap()
                .to_vec()
        }

        /// Opens a server->client packet and returns its frames' debug text.
        fn client_open(&mut self, pkt: &[u8]) -> Vec<String> {
            let mut p = pkt.to_vec();
            let body = self.client.rx.as_mut().unwrap().open(&mut p).unwrap();
            FrameReader::new(body)
                .map(|f| format!("{:?}", f.unwrap()))
                .collect()
        }
    }

    fn udp(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut b = vec![0u8; 128];
        let n = build_udp(
            &mut b,
            SocketAddrV4::new(src, 5000),
            SocketAddrV4::new(dst, 9000),
            1,
            b"game",
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

        let ping = h.client_ping(7);
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
        let ping = h.client_ping(1);
        h.feed(1, addr(1000), &ping);
        // Client's NAT mapping changes.
        let up = h.client_ip(&udp(VIP, GAME));
        h.feed(2, addr(4000), &up);
        assert_eq!(h.io.delivered.len(), 1);
        assert_eq!(h.core.stats.roamed, 1);
        h.io.sent.clear();
        assert!(h.core.send_ip(3, 0, &udp(GAME, VIP), &mut h.io));
        assert_eq!(h.io.sent[0].1, addr(4000));
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
        h.core.tick(UNCONFIRMED_EXPIRE + 1);
        assert_eq!(
            h.core.session_count(),
            0,
            "unconfirmed session expires early"
        );

        h.handshake(addr(1000));
        let ping = h.client_ping(1);
        h.feed(0, addr(1000), &ping);
        h.core.tick(UNCONFIRMED_EXPIRE + 1);
        assert_eq!(h.core.session_count(), 1);
        h.core.tick(SERVER_SESSION_EXPIRE + 1);
        assert_eq!(h.core.session_count(), 0);
    }

    #[test]
    fn close_frame_drops_session() {
        let mut h = Harness::new();
        h.handshake(addr(1000));
        let close = h
            .client
            .tx
            .as_mut()
            .unwrap()
            .control(|w| w.write(&Frame::Close(0)))
            .unwrap()
            .to_vec();
        h.feed(1, addr(1000), &close);
        assert_eq!(h.core.session_count(), 0);
    }
}
