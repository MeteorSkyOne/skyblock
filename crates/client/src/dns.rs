//! Sending DNS queries through the node (SPEC §6.5). Windows resolves
//! names in the DNS Client service rather than in the game, so queries are
//! picked by name: in `rules` mode those for the games' domains, in `all`
//! mode every one.
//!
//! A picked IPv4 query is readdressed to the node's resolver VIP, and its
//! answer gets the address of the server the host asked back, or the host
//! would ignore it. Windows prefers an IPv6 DNS server when the network
//! offers one, so IPv6 queries are handled too: the query is re-sent as
//! IPv4 UDP from the VIP, and the answer is rebuilt as the IPv6 packet the
//! host expects. The tunnel itself stays IPv4-only.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use skyblock_proto::dns;
use skyblock_proto::ip::{Ipv4Packet, PROTO_UDP, build_udp, fold, ones_sum};

use crate::config::DnsMode;

/// Answers later than this are no longer matched to their query.
const ANSWER_WINDOW: Duration = Duration::from_secs(10);
/// Pending queries kept before old ones are swept.
const SWEEP_AT: usize = 256;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;

/// Whether `pkt` is a whole UDP datagram to port 53, over IPv4 or IPv6
/// (without extension headers).
pub fn is_query(pkt: &[u8]) -> bool {
    match pkt.first().map(|b| b >> 4) {
        Some(4) => Ipv4Packet::parse(pkt).is_ok_and(|p| {
            p.protocol() == PROTO_UDP
                && !p.is_fragment()
                && p.ports().is_some_and(|(_, d)| d == dns::PORT)
        }),
        Some(6) => Udp6::parse(pkt).is_some_and(|u| u.dport == dns::PORT),
        _ => false,
    }
}

/// What to do with a captured query.
pub enum Outbound {
    /// Not for the node: send it on unchanged.
    Direct,
    /// An IPv4 query, readdressed in place; still needs the VIP as source.
    Redirected,
    /// An IPv6 query: tunnel this IPv4 packet in its place.
    Relayed(Vec<u8>),
}

/// What to do with a packet coming back from the tunnel.
pub enum Answer<I> {
    /// Not an answer to a query sent through the node.
    NotOurs,
    /// An IPv4 answer, its source restored in place.
    Restored,
    /// An answer to an IPv6 query: inject this packet on `iface` instead.
    V6 { packet: Vec<u8>, iface: I },
}

#[derive(Clone, Copy)]
enum Origin<I> {
    V4 {
        server: Ipv4Addr,
    },
    V6 {
        client: Ipv6Addr,
        server: Ipv6Addr,
        iface: I,
    },
}

/// `(local port, transaction ID)` → who the host asked, and when.
type Pending<I> = HashMap<(u16, u16), (Origin<I>, Instant)>;

pub struct DnsRedirect<I> {
    all: bool,
    domains: Vec<String>,
    resolver: Ipv4Addr,
    vip: Ipv4Addr,
    pending: Mutex<Pending<I>>,
}

impl<I: Copy> DnsRedirect<I> {
    /// `None` when nothing would be redirected (`off`, or `rules` without
    /// any domain), so DNS need not be captured at all.
    pub fn new(
        mode: DnsMode,
        domains: &[String],
        resolver: Ipv4Addr,
        vip: Ipv4Addr,
    ) -> Option<Self> {
        let domains: Vec<String> = domains
            .iter()
            .filter_map(|d| dns::normalize_domain(d))
            .collect();
        let all = match mode {
            DnsMode::Off => return None,
            DnsMode::Rules if domains.is_empty() => return None,
            DnsMode::Rules => false,
            DnsMode::All => true,
        };
        Some(Self {
            all,
            domains,
            resolver,
            vip,
            pending: Mutex::new(HashMap::new()),
        })
    }

    /// Whether the query `msg` goes through the node.
    pub fn wants(&self, msg: &[u8]) -> bool {
        if self.all {
            return dns::id(msg).is_some() && !dns::is_response(msg);
        }
        dns::query_name(msg).is_some_and(|n| self.domains.iter().any(|d| n.in_domain(d)))
    }

    /// Decides a captured query (see [`is_query`]); `iface` is where it
    /// was captured, for injecting an IPv6 answer.
    pub fn outbound(&self, pkt: &mut [u8], iface: I) -> Outbound {
        if pkt.first().map(|b| b >> 4) == Some(6) {
            return self.outbound_v6(pkt, iface);
        }
        let Ok(mut p) = Ipv4Packet::parse(pkt) else {
            return Outbound::Direct;
        };
        let (Some(msg), Some((sport, _))) = (p.udp_payload(), p.ports()) else {
            return Outbound::Direct;
        };
        if !self.wants(msg) {
            return Outbound::Direct;
        }
        let id = dns::id(msg).expect("wanted queries have a header");
        self.remember(sport, id, Origin::V4 { server: p.dst() });
        p.set_dst(self.resolver);
        Outbound::Redirected
    }

    fn outbound_v6(&self, pkt: &[u8], iface: I) -> Outbound {
        let Some(u) = Udp6::parse(pkt) else {
            return Outbound::Direct;
        };
        if !self.wants(u.payload) {
            return Outbound::Direct;
        }
        let id = dns::id(u.payload).expect("wanted queries have a header");
        let mut v4 = vec![0u8; u.payload.len() + 28];
        let Ok(n) = build_udp(
            &mut v4,
            SocketAddrV4::new(self.vip, u.sport),
            SocketAddrV4::new(self.resolver, dns::PORT),
            id,
            u.payload,
        ) else {
            return Outbound::Direct;
        };
        v4.truncate(n);
        self.remember(
            u.sport,
            id,
            Origin::V6 {
                client: u.src,
                server: u.dst,
                iface,
            },
        );
        Outbound::Relayed(v4)
    }

    /// Checks whether `pkt` answers a query sent through the node and, if
    /// so, makes it look like the answer from the server the host asked.
    pub fn inbound(&self, pkt: &mut [u8]) -> Answer<I> {
        let Ok(mut p) = Ipv4Packet::parse(pkt) else {
            return Answer::NotOurs;
        };
        if p.src() != self.resolver {
            return Answer::NotOurs;
        }
        let (Some(msg), Some((sport, dport))) = (p.udp_payload(), p.ports()) else {
            return Answer::NotOurs;
        };
        let Some(id) = dns::id(msg).filter(|_| sport == dns::PORT) else {
            return Answer::NotOurs;
        };
        let origin = match self.pending.lock().expect("dns lock").get(&(dport, id)) {
            Some(&(o, at)) if at.elapsed() < ANSWER_WINDOW => o,
            _ => return Answer::NotOurs,
        };
        match origin {
            Origin::V4 { server } => {
                p.set_src(server);
                Answer::Restored
            }
            Origin::V6 {
                client,
                server,
                iface,
            } => Answer::V6 {
                packet: build_udp6(server, dns::PORT, client, dport, msg),
                iface,
            },
        }
    }

    fn remember(&self, port: u16, id: u16, origin: Origin<I>) {
        let mut pending = self.pending.lock().expect("dns lock");
        if pending.len() >= SWEEP_AT {
            pending.retain(|_, (_, at)| at.elapsed() < ANSWER_WINDOW);
        }
        pending.insert((port, id), (origin, Instant::now()));
    }
}

/// A UDP datagram in an IPv6 packet without extension headers.
struct Udp6<'a> {
    src: Ipv6Addr,
    dst: Ipv6Addr,
    sport: u16,
    dport: u16,
    payload: &'a [u8],
}

impl<'a> Udp6<'a> {
    fn parse(pkt: &'a [u8]) -> Option<Self> {
        if pkt.len() < IPV6_HEADER_LEN + UDP_HEADER_LEN || pkt[0] >> 4 != 6 || pkt[6] != PROTO_UDP {
            return None;
        }
        let end = IPV6_HEADER_LEN + usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
        let udp = pkt.get(IPV6_HEADER_LEN..end)?;
        let len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
        if len < UDP_HEADER_LEN || len > udp.len() {
            return None;
        }
        let addr = |off: usize| -> Ipv6Addr {
            let b: [u8; 16] = pkt[off..off + 16].try_into().expect("16 bytes");
            Ipv6Addr::from(b)
        };
        Some(Self {
            src: addr(8),
            dst: addr(24),
            sport: u16::from_be_bytes([udp[0], udp[1]]),
            dport: u16::from_be_bytes([udp[2], udp[3]]),
            payload: &udp[UDP_HEADER_LEN..len],
        })
    }
}

/// An IPv6/UDP packet with a valid checksum.
fn build_udp6(src: Ipv6Addr, sport: u16, dst: Ipv6Addr, dport: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = UDP_HEADER_LEN + payload.len();
    let mut p = Vec::with_capacity(IPV6_HEADER_LEN + udp_len);
    p.extend_from_slice(&[0x60, 0, 0, 0]);
    p.extend_from_slice(&(udp_len as u16).to_be_bytes());
    p.extend_from_slice(&[PROTO_UDP, 64]);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(&sport.to_be_bytes());
    p.extend_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(&(udp_len as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    let mut sum = ones_sum(0, &src.octets());
    sum = ones_sum(sum, &dst.octets());
    sum += udp_len as u64 + u64::from(PROTO_UDP);
    let mut c = !fold(ones_sum(sum, &p[IPV6_HEADER_LEN..]));
    if c == 0 {
        c = 0xffff;
    }
    p[IPV6_HEADER_LEN + 6..IPV6_HEADER_LEN + 8].copy_from_slice(&c.to_be_bytes());
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use skyblock_proto::ip::{checksum_valid, transport_checksum_valid};

    const LAN: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 23);
    const ROUTER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
    const RESOLVER: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 1);
    const VIP: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);

    fn query(id: u16, name: &str) -> Vec<u8> {
        let mut m = vec![0u8; 12];
        m[..2].copy_from_slice(&id.to_be_bytes());
        m[5] = 1;
        for l in name.split('.') {
            m.push(l.len() as u8);
            m.extend_from_slice(l.as_bytes());
        }
        m.extend_from_slice(&[0, 0, 1, 0, 1]);
        m
    }

    fn udp(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 512];
        let n = build_udp(&mut b, src, dst, 1, payload).unwrap();
        b.truncate(n);
        b
    }

    fn valid(p: &[u8]) -> bool {
        let pkt = Ipv4Packet::parse(p).unwrap();
        checksum_valid(&p[..20])
            && transport_checksum_valid(pkt.src(), pkt.dst(), pkt.protocol(), pkt.payload())
    }

    fn rules() -> DnsRedirect<u32> {
        DnsRedirect::new(DnsMode::Rules, &["RiotGames.com.".into()], RESOLVER, VIP).unwrap()
    }

    #[test]
    fn modes() {
        assert!(DnsRedirect::<u32>::new(DnsMode::Off, &["a.com".into()], RESOLVER, VIP).is_none());
        assert!(DnsRedirect::<u32>::new(DnsMode::Rules, &[], RESOLVER, VIP).is_none());
        let all = DnsRedirect::<u32>::new(DnsMode::All, &[], RESOLVER, VIP).unwrap();
        assert!(all.wants(&query(1, "baidu.com")));
        let r = rules();
        assert!(r.wants(&query(1, "auth.riotgames.com")));
        assert!(r.wants(&query(1, "riotgames.com")));
        assert!(!r.wants(&query(1, "baidu.com")));
        assert!(!r.wants(&[0u8; 5]));
    }

    #[test]
    fn query_and_answer_are_readdressed() {
        let r = rules();
        let host = SocketAddrV4::new(LAN, 61000);
        let mut q = udp(
            host,
            SocketAddrV4::new(ROUTER, 53),
            &query(0x4242, "a.riotgames.com"),
        );
        assert!(is_query(&q));
        assert!(matches!(r.outbound(&mut q, 1), Outbound::Redirected));
        let p = Ipv4Packet::parse(&q[..]).unwrap();
        assert_eq!(p.dst(), RESOLVER);
        assert!(valid(&q));

        let mut other = udp(host, SocketAddrV4::new(ROUTER, 53), &query(1, "qq.com"));
        let before = other.clone();
        assert!(matches!(r.outbound(&mut other, 1), Outbound::Direct));
        assert_eq!(other, before, "untouched");

        let mut answer = query(0x4242, "a.riotgames.com");
        answer[2] |= 0x80;
        let mut a = udp(SocketAddrV4::new(RESOLVER, 53), host, &answer);
        assert!(matches!(r.inbound(&mut a), Answer::Restored));
        let p = Ipv4Packet::parse(&a[..]).unwrap();
        assert_eq!(p.src(), ROUTER);
        assert!(valid(&a));

        // Unknown transaction or not from the resolver: left alone.
        answer[1] ^= 1;
        let mut stray = udp(SocketAddrV4::new(RESOLVER, 53), host, &answer);
        assert!(matches!(r.inbound(&mut stray), Answer::NotOurs));
        let mut direct = udp(SocketAddrV4::new(ROUTER, 53), host, &answer);
        assert!(matches!(r.inbound(&mut direct), Answer::NotOurs));
    }

    const HOST6: Ipv6Addr = Ipv6Addr::new(0xfd12, 0x3456, 0x789a, 5, 0, 0, 0, 0x239);
    const ROUTER6: Ipv6Addr = Ipv6Addr::new(0xfd12, 0x3456, 0x789a, 5, 0, 0, 0, 0x100);

    fn udp6_valid(p: &[u8]) -> bool {
        let u = Udp6::parse(p).unwrap();
        let mut sum = ones_sum(0, &u.src.octets());
        sum = ones_sum(sum, &u.dst.octets());
        let seg = &p[IPV6_HEADER_LEN..];
        sum += seg.len() as u64 + u64::from(PROTO_UDP);
        fold(ones_sum(sum, seg)) == 0xffff
    }

    #[test]
    fn ipv6_queries_are_relayed_over_ipv4() {
        let r = rules();
        let q = query(0x7777, "lol.riotgames.com");
        let mut pkt = build_udp6(HOST6, 55000, ROUTER6, 53, &q);
        assert!(udp6_valid(&pkt));
        assert!(is_query(&pkt));
        let Outbound::Relayed(v4) = r.outbound(&mut pkt, 9) else {
            panic!("not relayed")
        };
        let p = Ipv4Packet::parse(&v4[..]).unwrap();
        assert_eq!((p.src(), p.dst()), (VIP, RESOLVER));
        assert_eq!(p.ports(), Some((55000, 53)));
        assert_eq!(p.udp_payload(), Some(&q[..]));
        assert!(valid(&v4));

        // The node's answer, addressed to VIP:55000, becomes an IPv6 packet
        // from the router to the host.
        let mut ans = q.clone();
        ans[2] |= 0x80;
        let mut a = udp(
            SocketAddrV4::new(RESOLVER, 53),
            SocketAddrV4::new(VIP, 55000),
            &ans,
        );
        let Answer::V6 { packet, iface } = r.inbound(&mut a) else {
            panic!("not rebuilt")
        };
        assert_eq!(iface, 9);
        let u = Udp6::parse(&packet).unwrap();
        assert_eq!(
            (u.src, u.dst, u.sport, u.dport),
            (ROUTER6, HOST6, 53, 55000)
        );
        assert_eq!(u.payload, &ans[..]);
        assert!(udp6_valid(&packet));

        let mut other = build_udp6(HOST6, 55001, ROUTER6, 53, &query(1, "qq.com"));
        assert!(matches!(r.outbound(&mut other, 9), Outbound::Direct));
    }

    #[test]
    fn ipv6_parsing_is_strict() {
        let good = build_udp6(HOST6, 1, ROUTER6, 53, &query(1, "a.com"));
        let mut ext = good.clone();
        ext[6] = 0; // hop-by-hop options header
        assert!(!is_query(&ext));
        assert!(
            !is_query(&good[..good.len() - 1]),
            "payload length past the end"
        );
        let to_5353 = build_udp6(HOST6, 1, ROUTER6, 5353, b"x");
        assert!(!is_query(&to_5353));
        assert!(!is_query(&[]));
    }

    #[test]
    fn only_whole_udp_to_port_53_is_a_query() {
        let host = SocketAddrV4::new(LAN, 61000);
        let q = udp(host, SocketAddrV4::new(ROUTER, 53), &query(1, "a.com"));
        let mut tcp = q.clone();
        tcp[9] = 6;
        assert!(!is_query(&tcp));
        let mut frag = q.clone();
        frag[6] = 0x20;
        assert!(!is_query(&frag));
        assert!(!is_query(&udp(host, SocketAddrV4::new(ROUTER, 5353), b"x")));
    }
}
