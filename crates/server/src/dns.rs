//! DNS forwarding for the resolver VIP (SPEC §7.5). A client's query to
//! `resolver:53` leaves the node from one upstream socket under a fresh
//! transaction ID; the answer gets the client's ID back and returns as a
//! UDP packet from `resolver:53`. No caching. This module does no I/O.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use skyblock_proto::Micros;
use skyblock_proto::dns;
use skyblock_proto::ip::{Ipv4Packet, build_udp};
use skyblock_proto::timing::DNS_TIMEOUT;

const MAX_PENDING: usize = 4096;
const MAX_PENDING_PER_USER: usize = 256;

#[derive(Debug, Default, Clone, Copy)]
pub struct DnsStats {
    pub queries: u64,
    /// Queries repeated by the client while still pending; they go to the
    /// next upstream.
    pub retries: u64,
    pub answers: u64,
    pub timeouts: u64,
    /// Queries refused (no upstream, too many pending, malformed).
    pub dropped: u64,
}

struct Query {
    user: usize,
    client: SocketAddrV4,
    id: u16,
    upstream: usize,
    deadline: Micros,
}

pub struct DnsForwarder {
    upstreams: Vec<SocketAddr>,
    resolver: Ipv4Addr,
    /// By the ID used towards the upstreams.
    pending: HashMap<u16, Query>,
    /// `(user, client port, client ID)` → upstream ID, to spot retries.
    by_client: HashMap<(usize, u16, u16), u16>,
    per_user: HashMap<usize, usize>,
    ident: u16,
    rng: StdRng,
    pub stats: DnsStats,
}

impl DnsForwarder {
    pub fn new(upstreams: Vec<SocketAddr>, resolver: Ipv4Addr) -> Self {
        Self {
            upstreams,
            resolver,
            pending: HashMap::new(),
            by_client: HashMap::new(),
            per_user: HashMap::new(),
            ident: 0,
            rng: StdRng::from_rng(&mut rand::rng()),
            stats: DnsStats::default(),
        }
    }

    pub fn upstreams(&self) -> &[SocketAddr] {
        &self.upstreams
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Takes a query `user` sent to the resolver. Writes the message to
    /// forward into `out` and returns where to send it and its length.
    pub fn query<B: AsRef<[u8]>>(
        &mut self,
        now: Micros,
        user: usize,
        pkt: &Ipv4Packet<B>,
        out: &mut [u8],
    ) -> Option<(SocketAddr, usize)> {
        let (Some(msg), Some((sport, _))) = (pkt.udp_payload(), pkt.ports()) else {
            self.stats.dropped += 1;
            return None;
        };
        let Some(client_id) = dns::id(msg).filter(|_| !dns::is_response(msg)) else {
            self.stats.dropped += 1;
            return None;
        };
        if self.upstreams.is_empty() || msg.len() > out.len() {
            self.stats.dropped += 1;
            return None;
        }
        let key = (user, sport, client_id);
        let id = match self.by_client.get(&key) {
            Some(&id) => {
                // The client's resolver retried: try the next upstream.
                let q = self.pending.get_mut(&id).expect("indexed query");
                q.upstream = (q.upstream + 1) % self.upstreams.len();
                q.deadline = now + DNS_TIMEOUT;
                self.stats.retries += 1;
                id
            }
            None => {
                let n = self.per_user.get(&user).copied().unwrap_or(0);
                if self.pending.len() >= MAX_PENDING || n >= MAX_PENDING_PER_USER {
                    self.stats.dropped += 1;
                    return None;
                }
                let id = self.free_id()?;
                self.pending.insert(
                    id,
                    Query {
                        user,
                        client: SocketAddrV4::new(pkt.src(), sport),
                        id: client_id,
                        upstream: 0,
                        deadline: now + DNS_TIMEOUT,
                    },
                );
                self.by_client.insert(key, id);
                *self.per_user.entry(user).or_default() += 1;
                id
            }
        };
        self.stats.queries += 1;
        out[..msg.len()].copy_from_slice(msg);
        dns::set_id(&mut out[..msg.len()], id);
        let upstream = self.upstreams[self.pending[&id].upstream];
        Some((upstream, msg.len()))
    }

    /// Takes a datagram that arrived from `from` on the upstream socket.
    /// For an answer to a pending query, writes the IPv4/UDP packet for
    /// the client into `out` and returns the user and its length.
    pub fn answer(
        &mut self,
        from: SocketAddr,
        msg: &[u8],
        out: &mut [u8],
    ) -> Option<(usize, usize)> {
        if !self.upstreams.contains(&from) || !dns::is_response(msg) {
            return None;
        }
        let q = self.remove(dns::id(msg)?)?;
        let mut reply = msg.to_vec();
        dns::set_id(&mut reply, q.id);
        self.ident = self.ident.wrapping_add(1);
        let src = SocketAddrV4::new(self.resolver, dns::PORT);
        let n = build_udp(out, src, q.client, self.ident, &reply).ok()?;
        self.stats.answers += 1;
        Some((q.user, n))
    }

    /// Forgets queries that got no answer in time.
    pub fn expire(&mut self, now: Micros) {
        let stale: Vec<u16> = self
            .pending
            .iter()
            .filter(|(_, q)| q.deadline <= now)
            .map(|(&id, _)| id)
            .collect();
        for id in stale {
            self.remove(id);
            self.stats.timeouts += 1;
        }
    }

    fn remove(&mut self, id: u16) -> Option<Query> {
        let q = self.pending.remove(&id)?;
        self.by_client.remove(&(q.user, q.client.port(), q.id));
        if let Some(n) = self.per_user.get_mut(&q.user) {
            *n -= 1;
        }
        Some(q)
    }

    /// A random ID not in use, so answers cannot be matched by guessing.
    fn free_id(&mut self) -> Option<u16> {
        (0..64)
            .map(|_| self.rng.random::<u16>())
            .find(|id| !self.pending.contains_key(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VIP: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);
    const RESOLVER: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 1);

    fn upstreams() -> Vec<SocketAddr> {
        vec![
            SocketAddr::from(([192, 0, 2, 53], 53)),
            SocketAddr::from(([198, 51, 100, 53], 53)),
        ]
    }

    fn query_msg(id: u16) -> Vec<u8> {
        let mut m = vec![0u8; 12];
        m[..2].copy_from_slice(&id.to_be_bytes());
        m[5] = 1;
        m.extend_from_slice(&[3, b'a', b'b', b'c', 0, 0, 1, 0, 1]);
        m
    }

    fn query_pkt(sport: u16, id: u16) -> Vec<u8> {
        let mut b = vec![0u8; 128];
        let n = build_udp(
            &mut b,
            SocketAddrV4::new(VIP, sport),
            SocketAddrV4::new(RESOLVER, 53),
            1,
            &query_msg(id),
        )
        .unwrap();
        b.truncate(n);
        b
    }

    fn ask(
        f: &mut DnsForwarder,
        now: Micros,
        user: usize,
        sport: u16,
        id: u16,
    ) -> Option<(SocketAddr, Vec<u8>)> {
        let pkt = query_pkt(sport, id);
        let mut out = [0u8; 512];
        let (to, n) = f.query(now, user, &Ipv4Packet::parse(&pkt[..]).unwrap(), &mut out)?;
        Some((to, out[..n].to_vec()))
    }

    fn respond(msg: &[u8]) -> Vec<u8> {
        let mut r = msg.to_vec();
        r[2] |= 0x80;
        r
    }

    #[test]
    fn forwards_and_restores_the_id() {
        let mut f = DnsForwarder::new(upstreams(), RESOLVER);
        let (to, fwd) = ask(&mut f, 0, 3, 5353, 0xbeef).unwrap();
        assert_eq!(to, upstreams()[0]);
        assert_eq!(fwd[2..], query_msg(0xbeef)[2..]);
        assert_eq!(f.pending(), 1);

        let mut out = [0u8; 512];
        let (user, n) = f.answer(to, &respond(&fwd), &mut out).unwrap();
        assert_eq!(user, 3);
        let ip = Ipv4Packet::parse(&out[..n]).unwrap();
        assert_eq!((ip.src(), ip.dst()), (RESOLVER, VIP));
        assert_eq!(ip.ports(), Some((53, 5353)));
        let msg = ip.udp_payload().unwrap();
        assert_eq!(dns::id(msg), Some(0xbeef));
        assert_eq!(f.pending(), 0);
        assert!(
            f.answer(to, &respond(&fwd), &mut out).is_none(),
            "answered once"
        );
    }

    #[test]
    fn rejects_strangers_and_non_answers() {
        let mut f = DnsForwarder::new(upstreams(), RESOLVER);
        let (to, fwd) = ask(&mut f, 0, 0, 1000, 1).unwrap();
        let mut out = [0u8; 512];
        let stranger = SocketAddr::from(([203, 0, 113, 1], 53));
        assert!(f.answer(stranger, &respond(&fwd), &mut out).is_none());
        assert!(f.answer(to, &fwd, &mut out).is_none(), "QR not set");
        assert!(f.answer(to, &[0u8; 5], &mut out).is_none());
        assert_eq!(f.pending(), 1);
    }

    #[test]
    fn retries_rotate_upstreams_and_share_the_id() {
        let mut f = DnsForwarder::new(upstreams(), RESOLVER);
        let (a, fa) = ask(&mut f, 0, 0, 1000, 9).unwrap();
        let (b, fb) = ask(&mut f, 1000, 0, 1000, 9).unwrap();
        assert_ne!(a, b);
        assert_eq!(fa, fb);
        assert_eq!(f.pending(), 1);
        assert_eq!(f.stats.retries, 1);
        // An answer from either upstream completes it.
        let mut out = [0u8; 512];
        assert!(f.answer(a, &respond(&fa), &mut out).is_some());
    }

    #[test]
    fn distinct_clients_get_distinct_ids() {
        let mut f = DnsForwarder::new(upstreams(), RESOLVER);
        let (_, x) = ask(&mut f, 0, 0, 1000, 7).unwrap();
        let (_, y) = ask(&mut f, 0, 1, 1000, 7).unwrap();
        assert_ne!(dns::id(&x), dns::id(&y));
        assert_eq!(f.pending(), 2);
    }

    #[test]
    fn timeouts_and_limits() {
        let mut f = DnsForwarder::new(upstreams(), RESOLVER);
        ask(&mut f, 0, 0, 1000, 1).unwrap();
        f.expire(DNS_TIMEOUT - 1);
        assert_eq!(f.pending(), 1);
        f.expire(DNS_TIMEOUT);
        assert_eq!((f.pending(), f.stats.timeouts), (0, 1));

        for i in 0..MAX_PENDING_PER_USER as u16 {
            assert!(ask(&mut f, 0, 0, 2000, i).is_some());
        }
        assert!(ask(&mut f, 0, 0, 2000, 60000).is_none(), "per-user cap");
        assert!(
            ask(&mut f, 0, 1, 2000, 60000).is_some(),
            "other users unaffected"
        );

        let mut none = DnsForwarder::new(vec![], RESOLVER);
        assert!(ask(&mut none, 0, 0, 1000, 1).is_none());
    }
}
