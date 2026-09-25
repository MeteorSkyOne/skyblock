//! Transport-independent client logic (SPEC §3.6, §3.8): handshake with
//! retries, keepalive PINGs, RTT tracking and dead-session detection. The
//! tunnel threads feed it datagrams and perform the I/O it requests.

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use skyblock_proto::Micros;
use skyblock_proto::frame::{Frame, FrameReader, Ping, Pong};
use skyblock_proto::handshake::{ClientHello, Initiator, MAX_MSG_LEN, ServerHello, next_timestamp};
use skyblock_proto::keys::{PrivateKey, Psk, PublicKey, SessionKeys};
use skyblock_proto::packet::PacketBuf;
use skyblock_proto::session::{Data, RxState, TxState, open_handshake, seal_handshake};
use skyblock_proto::timing::{
    ACTIVE_WINDOW, CLIENT_SESSION_DEAD, HANDSHAKE_GIVE_UP, HANDSHAKE_RETRY, HANDSHAKE_RETRY_MAX,
    PING_ACTIVE, PING_IDLE, PING_JITTER_PCT,
};
use tracing::{info, warn};

pub trait ClientIo {
    fn send(&mut self, pkt: &[u8]);
    /// Hands over an inner packet received from the node.
    fn deliver(&mut self, ip: &[u8]);
}

/// Smoothed RTT (RFC 6298 style), in microseconds.
#[derive(Debug, Default, Clone, Copy)]
pub struct Rtt {
    pub srtt: Micros,
    pub rttvar: Micros,
    pub last: Micros,
    pub min: Micros,
    pub samples: u64,
}

impl Rtt {
    fn update(&mut self, r: Micros) {
        if self.samples == 0 {
            self.srtt = r;
            self.rttvar = r / 2;
            self.min = r;
        } else {
            self.rttvar = (3 * self.rttvar + self.srtt.abs_diff(r)) / 4;
            self.srtt = (7 * self.srtt + r) / 8;
            self.min = self.min.min(r);
        }
        self.last = r;
        self.samples += 1;
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ClientStats {
    pub handshakes: u64,
    pub pings: u64,
    pub pongs: u64,
    pub tx_data: u64,
    pub rx_data: u64,
    pub rtt: Rtt,
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
    hello: ServerHello,
    last_rx: Micros,
    last_data: Micros,
    next_ping: Micros,
}

pub struct ClientCore {
    local: PrivateKey,
    node: PublicKey,
    psk: Psk,
    obfs: SessionKeys,
    pad_max: usize,
    handshake: Option<Handshake>,
    session: Option<Session>,
    last_ts: u64,
    ping_id: u32,
    rng: StdRng,
    hs_buf: PacketBuf,
    pub stats: ClientStats,
}

impl ClientCore {
    pub fn new(local: PrivateKey, node: PublicKey, psk: Psk, pad_max: usize) -> Self {
        Self {
            obfs: SessionKeys::obfuscation(&node),
            local,
            node,
            psk,
            pad_max,
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

    /// Drives timers; returns the time by which it wants to be polled again.
    pub fn poll(&mut self, now: Micros, io: &mut impl ClientIo) -> Micros {
        if self
            .session
            .as_ref()
            .is_some_and(|s| now.saturating_sub(s.last_rx) > CLIENT_SESSION_DEAD)
        {
            warn!(
                "nothing from the node for {}s; reconnecting",
                CLIENT_SESSION_DEAD / 1_000_000
            );
            self.session = None;
        }
        if self.session.is_none() {
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
            return self
                .handshake
                .as_ref()
                .map_or(now + HANDSHAKE_RETRY, |h| h.next_retry);
        }

        let due = self.session.as_ref().is_some_and(|s| now >= s.next_ping);
        if due {
            self.send_ping(now, io);
        }
        let s = self.session.as_ref().expect("session present");
        s.next_ping.min(s.last_rx + CLIENT_SESSION_DEAD)
    }

    /// Processes one datagram from the node; `pkt` is decrypted in place.
    pub fn handle_datagram(&mut self, now: Micros, pkt: &mut [u8], io: &mut impl ClientIo) {
        if let Some(s) = &mut self.session {
            if let Ok(body) = s.rx.open(pkt) {
                s.last_rx = now;
                let mut close = false;
                for frame in FrameReader::new(body) {
                    let Ok(frame) = frame else { break };
                    match frame {
                        Frame::Pong(p) => {
                            self.stats.pongs += 1;
                            let rtt = now
                                .saturating_sub(p.ts)
                                .saturating_sub(u64::from(p.hold_us));
                            self.stats.rtt.update(rtt);
                        }
                        Frame::Ping(p) => {
                            let pong = Frame::Pong(Pong {
                                path: p.path,
                                id: p.id,
                                ts: p.ts,
                                hold_us: 0,
                            });
                            if let Ok(out) = s.tx.control(|w| w.write(&pong)) {
                                io.send(out);
                            }
                        }
                        Frame::Close(_) => close = true,
                        _ => {
                            if let Some(Data::Ip(ip)) = s.rx.accept(now, &frame) {
                                self.stats.rx_data += 1;
                                io.deliver(ip);
                            }
                        }
                    }
                }
                if close {
                    warn!("node closed the session; reconnecting");
                    self.session = None;
                }
                return;
            }
        }
        self.on_handshake_response(now, pkt, io);
    }

    /// Sends an inner packet; returns `false` when there is no session.
    pub fn send_ip(&mut self, now: Micros, ip: &[u8], io: &mut impl ClientIo) -> bool {
        let Some(s) = &mut self.session else {
            return false;
        };
        s.last_data = now;
        let ok = s.tx.send_ip(ip, |p| io.send(p)).is_ok();
        if ok {
            self.stats.tx_data += 1;
        }
        ok
    }

    /// Tells the node we are leaving.
    pub fn close(&mut self, io: &mut impl ClientIo) {
        if let Some(s) = &mut self.session {
            if let Ok(out) = s.tx.control(|w| w.write(&Frame::Close(0))) {
                io.send(out);
            }
        }
        self.session = None;
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
                    hello,
                    last_rx: now,
                    last_data: 0,
                    next_ping: now,
                });
                self.stats.handshakes += 1;
                info!(vip = %hello.vip, mtu = hello.mtu, "connected");
                // The first packet under the new keys confirms the session.
                self.send_ping(now, io);
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
            n_paths: 1,
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
                    io.send(pkt);
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

    fn send_ping(&mut self, now: Micros, io: &mut impl ClientIo) {
        let Some(s) = &mut self.session else { return };
        self.ping_id = self.ping_id.wrapping_add(1);
        let ping = Frame::Ping(Ping {
            path: 0,
            id: self.ping_id,
            ts: now,
        });
        if let Ok(out) = s.tx.control(|w| w.write(&ping)) {
            io.send(out);
            self.stats.pings += 1;
        }
        let active = s.last_data != 0 && now.saturating_sub(s.last_data) < ACTIVE_WINDOW;
        let base = if active { PING_ACTIVE } else { PING_IDLE };
        let jitter = base * PING_JITTER_PCT / 100;
        s.next_ping = now + self.rng.random_range(base - jitter..=base + jitter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use skyblock_proto::handshake::PendingResponse;
    use skyblock_proto::ip::build_udp;
    use skyblock_proto::timing::SECOND;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[derive(Default)]
    struct Io {
        sent: Vec<Vec<u8>>,
        delivered: Vec<Vec<u8>>,
    }

    impl ClientIo for Io {
        fn send(&mut self, pkt: &[u8]) {
            self.sent.push(pkt.to_vec());
        }
        fn deliver(&mut self, ip: &[u8]) {
            self.delivered.push(ip.to_vec());
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
    }

    fn connect(core: &mut ClientCore, node: &mut Node, io: &mut Io) {
        core.poll(0, io);
        let init = io.sent.pop().expect("HS_INIT sent");
        let mut resp = node.answer(&init, &Psk::ZERO);
        core.handle_datagram(1000, &mut resp, io);
    }

    fn setup() -> (ClientCore, Node, Io) {
        let node = Node::new();
        let core = ClientCore::new(PrivateKey::generate(), node.key.public_key(), Psk::ZERO, 0);
        (core, node, Io::default())
    }

    fn udp() -> Vec<u8> {
        let mut b = vec![0u8; 64];
        let n = build_udp(
            &mut b,
            SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 27015),
            SocketAddrV4::new(Ipv4Addr::new(10, 77, 0, 2), 5000),
            1,
            b"state",
        )
        .unwrap();
        b.truncate(n);
        b
    }

    #[test]
    fn connects_and_pings_immediately() {
        let (mut core, mut node, mut io) = setup();
        connect(&mut core, &mut node, &mut io);
        assert_eq!(core.stats.handshakes, 1);
        assert_eq!(core.hello().unwrap().vip, Ipv4Addr::new(10, 77, 0, 2));
        let ping = io.sent.pop().expect("confirming PING");
        assert!(node.frames(&ping)[0].starts_with("Ping"));
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
        let first = io.sent.pop().unwrap();
        core.poll(HANDSHAKE_RETRY, &mut io);
        let mut resp = node.answer(&first, &Psk::ZERO);
        core.handle_datagram(HANDSHAKE_RETRY + 1, &mut resp, &mut io);
        assert!(core.hello().is_none());
    }

    #[test]
    fn psk_mismatch_does_not_connect() {
        let (mut core, mut node, mut io) = setup();
        core.poll(0, &mut io);
        let init = io.sent.pop().unwrap();
        let mut resp = node.answer(&init, &Psk::generate());
        core.handle_datagram(1, &mut resp, &mut io);
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

        assert!(core.send_ip(2000, &udp(), &mut io));
        let up = io.sent.pop().unwrap();
        assert!(node.frames(&up)[0].starts_with("Ip"));

        let mut down = vec![];
        node.tx
            .as_mut()
            .unwrap()
            .send_ip(&udp(), |p| down.push(p.to_vec()))
            .unwrap();
        core.handle_datagram(3000, &mut down[0], &mut io);
        assert_eq!(io.delivered, vec![udp()]);

        let mut pong = node
            .tx
            .as_mut()
            .unwrap()
            .control(|w| {
                w.write(&Frame::Pong(Pong {
                    path: 0,
                    id: 1,
                    ts: 1000,
                    hold_us: 100,
                }))
            })
            .unwrap()
            .to_vec();
        core.handle_datagram(43_000, &mut pong, &mut io);
        assert_eq!(core.stats.rtt.last, 41_900);
    }

    #[test]
    fn dead_session_triggers_reconnect() {
        let (mut core, mut node, mut io) = setup();
        connect(&mut core, &mut node, &mut io);
        io.sent.clear();
        core.poll(1000 + CLIENT_SESSION_DEAD + 1, &mut io);
        assert!(core.hello().is_none());
        assert_eq!(io.sent.len(), 1, "a new HS_INIT goes out");
        assert!(!core.send_ip(0, &udp(), &mut io));
    }

    #[test]
    fn ping_schedule_depends_on_activity() {
        let (mut core, mut node, mut io) = setup();
        connect(&mut core, &mut node, &mut io);
        let idle_next = core.poll(2000, &mut io);
        assert!((1000 + PING_IDLE * 8 / 10..=1000 + PING_IDLE * 12 / 10 + 1).contains(&idle_next));

        let t = idle_next;
        core.send_ip(t - 1, &udp(), &mut io);
        core.poll(t, &mut io);
        let active_next = core.poll(t + 1, &mut io);
        assert!(active_next <= t + PING_ACTIVE * 12 / 10);
    }
}
