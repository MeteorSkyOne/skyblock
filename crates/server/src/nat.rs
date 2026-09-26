//! User-space full-cone UDP NAT (SPEC §7.4). Each `(user, inner source
//! port)` gets its own public UDP socket; anything arriving on that socket,
//! from any address, is forwarded back to the user (endpoint-independent
//! mapping and filtering).

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::ops::RangeInclusive;

use mio::net::UdpSocket;
use mio::{Interest, Registry, Token};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use skyblock_proto::Micros;
use skyblock_proto::ip::{Ipv4Packet, build_udp};
use tracing::{debug, warn};

/// Tokens at or above this value belong to NAT sockets.
pub const TOKEN_BASE: usize = 1 << 16;
const MAX_PER_USER: usize = 1024;
const BIND_ATTEMPTS: usize = 16;

pub enum Outbound {
    Sent,
    /// Destined to another mapping on this node: deliver `packet` to `user`.
    Hairpin {
        user: usize,
        packet: Vec<u8>,
    },
    Dropped(&'static str),
}

struct Mapping {
    user: usize,
    vip: Ipv4Addr,
    sport: u16,
    port: u16,
    sock: UdpSocket,
    last_out: Micros,
}

pub struct Nat {
    slots: Vec<Option<Mapping>>,
    free: Vec<usize>,
    by_key: HashMap<(usize, u16), usize>,
    by_port: HashMap<u16, usize>,
    per_user: HashMap<usize, usize>,
    bind_ip: Ipv4Addr,
    public_ip: Option<Ipv4Addr>,
    range: RangeInclusive<u16>,
    timeout: Micros,
    ident: u16,
    rng: StdRng,
}

impl Nat {
    /// `bind_ip` is the address mapping sockets bind to; `public_ip` is the
    /// address clients see, used to detect hairpin traffic.
    pub fn new(
        bind_ip: Ipv4Addr,
        public_ip: Option<Ipv4Addr>,
        range: RangeInclusive<u16>,
        timeout: Micros,
    ) -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
            by_key: HashMap::new(),
            by_port: HashMap::new(),
            per_user: HashMap::new(),
            bind_ip,
            public_ip,
            range,
            timeout,
            ident: 0,
            rng: StdRng::from_rng(&mut rand::rng()),
        }
    }

    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    /// Mappings owned by `user`.
    pub fn user_mappings(&self, user: usize) -> usize {
        self.per_user.get(&user).copied().unwrap_or(0)
    }

    /// Maps a token back to a slot, if it is one of ours.
    pub fn slot_for(token: Token) -> Option<usize> {
        token.0.checked_sub(TOKEN_BASE)
    }

    /// Sends an inner UDP datagram from `user` out through its mapping.
    pub fn outbound<B: AsRef<[u8]>>(
        &mut self,
        now: Micros,
        registry: &Registry,
        user: usize,
        pkt: &Ipv4Packet<B>,
    ) -> Outbound {
        let (Some(payload), Some((sport, dport))) = (pkt.udp_payload(), pkt.ports()) else {
            return Outbound::Dropped("not a whole UDP datagram");
        };
        let slot = match self.mapping(now, registry, user, pkt.src(), sport) {
            Ok(s) => s,
            Err(reason) => return Outbound::Dropped(reason),
        };
        let dst = pkt.dst();
        let m = self.slots[slot].as_mut().expect("live slot");
        m.last_out = now;
        let from_port = m.port;

        if Some(dst) == self.public_ip {
            let Some(target) = self
                .by_port
                .get(&dport)
                .and_then(|&s| self.slots[s].as_ref())
            else {
                return Outbound::Dropped("hairpin to unmapped port");
            };
            let mut packet = vec![0u8; payload.len() + 28];
            let src = SocketAddrV4::new(dst, from_port);
            let to = SocketAddrV4::new(target.vip, target.sport);
            self.ident = self.ident.wrapping_add(1);
            return match build_udp(&mut packet, src, to, self.ident, payload) {
                Ok(n) => {
                    packet.truncate(n);
                    Outbound::Hairpin {
                        user: target.user,
                        packet,
                    }
                }
                Err(_) => Outbound::Dropped("hairpin build failed"),
            };
        }

        match m.sock.send_to(payload, SocketAddr::from((dst, dport))) {
            Ok(_) => Outbound::Sent,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Outbound::Dropped("socket full"),
            Err(e) => {
                debug!(%dst, "nat send failed: {e}");
                Outbound::Dropped("send failed")
            }
        }
    }

    /// Drains datagrams that arrived on a mapping socket, handing each to
    /// `f` as an IPv4/UDP packet addressed to the user's VIP. `scratch`
    /// receives payloads and `out` holds the built packet; both should be
    /// 64 KiB to fit any datagram.
    pub fn drain(
        &mut self,
        slot: usize,
        scratch: &mut [u8],
        out: &mut [u8],
        mut f: impl FnMut(usize, &[u8]),
    ) {
        let Some(Some(m)) = self.slots.get(slot) else {
            return;
        };
        let mut errors = 0;
        loop {
            let (n, from) = match m.sock.recv_from(scratch) {
                Ok(r) => r,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(e) => {
                    // ICMP errors surface here on some platforms; keep
                    // draining, but never spin on a persistent error.
                    debug!(port = m.port, "nat recv: {e}");
                    errors += 1;
                    if errors > 16 {
                        return;
                    }
                    continue;
                }
            };
            let SocketAddr::V4(from) = from else { continue };
            self.ident = self.ident.wrapping_add(1);
            let to = SocketAddrV4::new(m.vip, m.sport);
            if let Ok(len) = build_udp(out, from, to, self.ident, &scratch[..n]) {
                f(m.user, &out[..len]);
            }
        }
    }

    /// Closes mappings idle (no outbound traffic) past the timeout.
    pub fn expire(&mut self, now: Micros, registry: &Registry) {
        for slot in 0..self.slots.len() {
            let expired = self.slots[slot]
                .as_ref()
                .is_some_and(|m| now.saturating_sub(m.last_out) > self.timeout);
            if expired {
                self.remove(slot, registry);
            }
        }
    }

    fn mapping(
        &mut self,
        now: Micros,
        registry: &Registry,
        user: usize,
        vip: Ipv4Addr,
        sport: u16,
    ) -> Result<usize, &'static str> {
        if let Some(&slot) = self.by_key.get(&(user, sport)) {
            return Ok(slot);
        }
        if self.per_user.get(&user).copied().unwrap_or(0) >= MAX_PER_USER {
            return Err("too many mappings");
        }
        let (mut sock, port) = self.bind(sport).ok_or("no free port")?;
        let slot = self.free.pop().unwrap_or_else(|| {
            self.slots.push(None);
            self.slots.len() - 1
        });
        if let Err(e) = registry.register(&mut sock, Token(TOKEN_BASE + slot), Interest::READABLE) {
            warn!("nat register: {e}");
            self.free.push(slot);
            return Err("register failed");
        }
        self.slots[slot] = Some(Mapping {
            user,
            vip,
            sport,
            port,
            sock,
            last_out: now,
        });
        self.by_key.insert((user, sport), slot);
        self.by_port.insert(port, slot);
        *self.per_user.entry(user).or_default() += 1;
        debug!(user, sport, port, "nat mapping created");
        Ok(slot)
    }

    /// Binds a socket, preferring the client's own source port so that
    /// peers see the same port number (helps some NAT-type checks).
    fn bind(&mut self, preferred: u16) -> Option<(UdpSocket, u16)> {
        let mut candidates = Vec::with_capacity(BIND_ATTEMPTS + 1);
        if self.range.contains(&preferred) {
            candidates.push(preferred);
        }
        for _ in 0..BIND_ATTEMPTS {
            candidates.push(self.rng.random_range(self.range.clone()));
        }
        candidates.into_iter().find_map(|port| {
            if self.by_port.contains_key(&port) {
                return None;
            }
            let sock = UdpSocket::bind(SocketAddr::from((self.bind_ip, port))).ok()?;
            Some((sock, port))
        })
    }

    #[cfg(test)]
    fn port_of(&self, user: usize, sport: u16) -> Option<u16> {
        let slot = *self.by_key.get(&(user, sport))?;
        self.slots[slot].as_ref().map(|m| m.port)
    }

    fn remove(&mut self, slot: usize, registry: &Registry) {
        if let Some(mut m) = self.slots[slot].take() {
            let _ = registry.deregister(&mut m.sock);
            self.by_key.remove(&(m.user, m.sport));
            self.by_port.remove(&m.port);
            if let Some(n) = self.per_user.get_mut(&m.user) {
                *n -= 1;
            }
            self.free.push(slot);
            debug!(user = m.user, port = m.port, "nat mapping removed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mio::{Events, Poll};
    use std::time::Duration;

    const VIP: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);
    const LO: Ipv4Addr = Ipv4Addr::LOCALHOST;

    fn inner(src_port: u16, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 1500];
        let n = build_udp(&mut b, SocketAddrV4::new(VIP, src_port), dst, 1, payload).unwrap();
        b.truncate(n);
        b
    }

    fn wait_readable(poll: &mut Poll) -> Vec<Token> {
        let mut events = Events::with_capacity(16);
        poll.poll(&mut events, Some(Duration::from_secs(2)))
            .unwrap();
        events.iter().map(|e| e.token()).collect()
    }

    /// A port that was free a moment ago.
    fn free_port() -> u16 {
        std::net::UdpSocket::bind((LO, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn full_cone_roundtrip_and_third_party() {
        let mut poll = Poll::new().unwrap();
        let mut nat = Nat::new(
            LO,
            Some(Ipv4Addr::new(192, 0, 2, 1)),
            1024..=65535,
            1_000_000,
        );

        let game = std::net::UdpSocket::bind((LO, 0)).unwrap();
        let game_addr = match game.local_addr().unwrap() {
            SocketAddr::V4(a) => a,
            _ => unreachable!(),
        };
        let sport = free_port();
        let pkt = inner(sport, game_addr, b"hello");
        let p = Ipv4Packet::parse(&pkt[..]).unwrap();
        assert!(matches!(
            nat.outbound(0, poll.registry(), 0, &p),
            Outbound::Sent
        ));
        assert_eq!(nat.len(), 1);

        let mut buf = [0u8; 64];
        let (n, mapped) = game.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(Some(mapped.port()), nat.port_of(0, sport));
        assert_eq!(mapped.port(), sport, "source port preserved");

        // A third party that never talked to the mapping can reach it.
        let stranger = std::net::UdpSocket::bind((LO, 0)).unwrap();
        stranger.send_to(b"p2p", mapped).unwrap();
        let tokens = wait_readable(&mut poll);
        let slot = Nat::slot_for(tokens[0]).unwrap();
        let mut got = vec![];
        let (mut scratch, mut out) = ([0u8; 2048], [0u8; 2048]);
        nat.drain(slot, &mut scratch, &mut out, |user, ip| {
            got.push((user, ip.to_vec()))
        });
        assert_eq!(got.len(), 1);
        let ip = Ipv4Packet::parse(&got[0].1[..]).unwrap();
        assert_eq!(ip.dst(), VIP);
        assert_eq!(ip.ports().unwrap().1, sport);
        assert_eq!(ip.src(), LO);
        assert_eq!(ip.udp_payload(), Some(&b"p2p"[..]));
    }

    #[test]
    fn same_source_port_reuses_mapping_and_expiry_frees_it() {
        let poll = Poll::new().unwrap();
        let mut nat = Nat::new(LO, None, 1024..=65535, 1_000);
        let dst = SocketAddrV4::new(LO, 9);
        let sport = free_port();
        for _ in 0..3 {
            let pkt = inner(sport, dst, b"x");
            nat.outbound(0, poll.registry(), 0, &Ipv4Packet::parse(&pkt[..]).unwrap());
        }
        assert_eq!(nat.len(), 1);
        nat.expire(500, poll.registry());
        assert_eq!(nat.len(), 1);
        nat.expire(2_000, poll.registry());
        assert_eq!(nat.len(), 0);
    }

    #[test]
    fn hairpin_between_users() {
        let poll = Poll::new().unwrap();
        let public = Ipv4Addr::new(192, 0, 2, 1);
        let other_vip = Ipv4Addr::new(10, 77, 0, 3);
        let mut nat = Nat::new(LO, Some(public), 1024..=65535, 1_000_000);
        // User 1 gets a mapping.
        let (sport1, sport0) = (free_port(), free_port());
        let mut pkt1 = vec![0u8; 100];
        let n = build_udp(
            &mut pkt1,
            SocketAddrV4::new(other_vip, sport1),
            SocketAddrV4::new(LO, 9),
            1,
            b"a",
        )
        .unwrap();
        pkt1.truncate(n);
        nat.outbound(
            0,
            poll.registry(),
            1,
            &Ipv4Packet::parse(&pkt1[..]).unwrap(),
        );
        let port1 = nat.port_of(1, sport1).unwrap();

        // User 0 sends to the node's public address at that port.
        let pkt0 = inner(sport0, SocketAddrV4::new(public, port1), b"hi");
        match nat.outbound(
            0,
            poll.registry(),
            0,
            &Ipv4Packet::parse(&pkt0[..]).unwrap(),
        ) {
            Outbound::Hairpin { user, packet } => {
                assert_eq!(user, 1);
                let ip = Ipv4Packet::parse(&packet[..]).unwrap();
                assert_eq!(ip.src(), public);
                assert_eq!(ip.dst(), other_vip);
                assert_eq!(ip.ports(), Some((nat.port_of(0, sport0).unwrap(), sport1)));
                assert_eq!(ip.udp_payload(), Some(&b"hi"[..]));
            }
            _ => panic!("expected hairpin"),
        }
    }
}
