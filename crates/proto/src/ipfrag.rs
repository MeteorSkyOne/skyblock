//! Reassembly of IPv4 fragments (RFC 791 §3.2). The node's user-space UDP
//! NAT needs whole datagrams, so inner UDP that a game fragmented itself is
//! put back together first (SPEC §7.4). Overlapping fragments drop the
//! whole datagram, as they only come from broken or hostile senders.

use std::net::Ipv4Addr;

use crate::ip::{Ipv4Packet, checksum};
use crate::timing::SECOND;
use crate::{Error, Micros};

pub const TIMEOUT: Micros = SECOND;
/// Largest IPv4 datagram.
const MAX_DATAGRAM: usize = u16::MAX as usize;
/// Fragments per datagram; more is treated as an attack.
const MAX_PIECES: usize = 64;

/// `(src, dst, protocol, identification)`.
type Key = (Ipv4Addr, Ipv4Addr, u8, u16);

struct Group {
    key: Key,
    deadline: Micros,
    /// Header of the first fragment, once it arrived.
    header: Vec<u8>,
    data: Vec<u8>,
    /// Payload byte ranges received, `[start, end)`.
    pieces: Vec<(usize, usize)>,
    /// Payload length, once the last fragment arrived.
    total: Option<usize>,
}

impl Group {
    fn received(&self) -> usize {
        self.pieces.iter().map(|(s, e)| e - s).sum()
    }
}

/// In-progress reassemblies, at most `capacity`; when full, the one
/// closest to its deadline is dropped.
pub struct Ipv4Reassembler {
    groups: Vec<Group>,
    capacity: usize,
    timeout: Micros,
    out: Vec<u8>,
}

impl Ipv4Reassembler {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0);
        Self {
            groups: Vec::new(),
            capacity,
            timeout: TIMEOUT,
            out: Vec::new(),
        }
    }

    /// Adds a fragment (`frag` must be one: MF set or a non-zero offset);
    /// returns the whole datagram, unfragmented, once all parts are in.
    pub fn push(&mut self, now: Micros, frag: &[u8]) -> Result<Option<&[u8]>, Error> {
        let p = Ipv4Packet::parse(frag)?;
        if !p.is_fragment() {
            return Err(Error::MalformedFragment);
        }
        let payload = p.payload();
        let start = usize::from(p.frag_offset()) * 8;
        let end = start + payload.len();
        let more = p.more_fragments();
        if (more && payload.len() % 8 != 0) || payload.is_empty() {
            return Err(Error::MalformedFragment);
        }
        if p.header_len() + end > MAX_DATAGRAM {
            return Err(Error::MalformedFragment);
        }
        let key = (p.src(), p.dst(), p.protocol(), p.ident());
        let i = self.find_or_claim(now, key);

        let g = &mut self.groups[i];
        if g.pieces.contains(&(start, end)) {
            return Ok(None);
        }
        let overlaps = g.pieces.iter().any(|&(s, e)| start < e && s < end);
        let bad_end = match (more, g.total) {
            (false, Some(t)) => t != end,
            (false, None) => g.pieces.iter().any(|&(_, e)| e > end),
            (true, Some(t)) => end > t,
            (true, None) => false,
        };
        if overlaps || bad_end || g.pieces.len() == MAX_PIECES {
            self.groups.swap_remove(i);
            return Err(Error::MalformedFragment);
        }
        if !more {
            g.total = Some(end);
        }
        if start == 0 {
            g.header.clear();
            g.header.extend_from_slice(&frag[..p.header_len()]);
        }
        if g.data.len() < end {
            g.data.resize(end, 0);
        }
        g.data[start..end].copy_from_slice(payload);
        g.pieces.push((start, end));

        let complete = matches!(g.total, Some(t) if g.received() == t) && !g.header.is_empty();
        if !complete {
            return Ok(None);
        }
        let g = self.groups.swap_remove(i);
        let total = g.total.expect("complete group has a length");
        let hl = g.header.len();
        self.out.clear();
        self.out.extend_from_slice(&g.header);
        self.out.extend_from_slice(&g.data[..total]);
        let h = &mut self.out[..hl];
        h[2..4].copy_from_slice(&((hl + total) as u16).to_be_bytes());
        // Keep DF, clear MF and the offset.
        h[6] &= 0x40;
        h[7] = 0;
        h[10..12].fill(0);
        let c = checksum(h);
        h[10..12].copy_from_slice(&c.to_be_bytes());
        Ok(Some(&self.out))
    }

    /// Drops reassemblies past their deadline.
    pub fn expire(&mut self, now: Micros) {
        self.groups.retain(|g| g.deadline > now);
    }

    pub fn pending(&self) -> usize {
        self.groups.len()
    }

    fn find_or_claim(&mut self, now: Micros, key: Key) -> usize {
        if let Some(i) = self
            .groups
            .iter()
            .position(|g| g.key == key && g.deadline > now)
        {
            return i;
        }
        self.groups.retain(|g| g.deadline > now && g.key != key);
        if self.groups.len() >= self.capacity {
            let (oldest, _) = self
                .groups
                .iter()
                .enumerate()
                .min_by_key(|(_, g)| g.deadline)
                .expect("capacity > 0");
            self.groups.swap_remove(oldest);
        }
        self.groups.push(Group {
            key,
            deadline: now + self.timeout,
            header: Vec::new(),
            data: Vec::new(),
            pieces: Vec::new(),
            total: None,
        });
        self.groups.len() - 1
    }
}

/// Splits an IPv4 packet into fragments whose total length is at most
/// `mtu` (the inverse of [`Ipv4Reassembler`]; used by tests and tools).
pub fn fragment(packet: &[u8], mtu: usize) -> Result<Vec<Vec<u8>>, Error> {
    let p = Ipv4Packet::parse(packet)?;
    let hl = p.header_len();
    let chunk = mtu.saturating_sub(hl) / 8 * 8;
    if chunk == 0 || p.is_fragment() {
        return Err(Error::MalformedFragment);
    }
    let payload = p.payload();
    let mut out = Vec::new();
    for (i, part) in payload.chunks(chunk).enumerate() {
        let mut f = Vec::with_capacity(hl + part.len());
        f.extend_from_slice(&packet[..hl]);
        f.extend_from_slice(part);
        let off = (i * chunk / 8) as u16;
        let more = (i + 1) * chunk < payload.len();
        f[2..4].copy_from_slice(&((hl + part.len()) as u16).to_be_bytes());
        let flags = (u16::from(packet[6] & 0x40) << 8) | if more { 0x2000 } else { 0 };
        f[6..8].copy_from_slice(&(flags | off).to_be_bytes());
        f[10..12].fill(0);
        let c = checksum(&f[..hl]);
        f[10..12].copy_from_slice(&c.to_be_bytes());
        out.push(f);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip::{build_udp, checksum_valid, transport_checksum_valid};
    use std::net::SocketAddrV4;

    fn datagram(len: usize, ident: u16) -> Vec<u8> {
        let payload: Vec<u8> = (0..len).map(|i| (i * 13 + 5) as u8).collect();
        let mut b = vec![0u8; len + 28];
        let n = build_udp(
            &mut b,
            SocketAddrV4::new(Ipv4Addr::new(10, 77, 0, 2), 5000),
            SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 27015),
            ident,
            &payload,
        )
        .unwrap();
        b.truncate(n);
        b
    }

    fn valid(p: &[u8]) -> bool {
        let pkt = Ipv4Packet::parse(p).unwrap();
        !pkt.is_fragment()
            && checksum_valid(&p[..pkt.header_len()])
            && transport_checksum_valid(pkt.src(), pkt.dst(), pkt.protocol(), pkt.payload())
    }

    #[test]
    fn fragments_roundtrip_in_any_order() {
        let d = datagram(3000, 7);
        let frags = fragment(&d, 1400).unwrap();
        assert_eq!(frags.len(), 3);
        for order in [[0, 1, 2], [2, 1, 0], [1, 2, 0], [2, 0, 1]] {
            let mut r = Ipv4Reassembler::new(4);
            let mut got = None;
            for (n, &i) in order.iter().enumerate() {
                let out = r.push(0, &frags[i]).unwrap().map(<[u8]>::to_vec);
                if n < 2 {
                    assert!(out.is_none());
                } else {
                    got = out;
                }
            }
            let got = got.unwrap();
            assert_eq!(got, d, "order {order:?}");
            assert!(valid(&got));
            assert_eq!(r.pending(), 0);
        }
    }

    #[test]
    fn interleaved_datagrams_and_duplicates() {
        let (a, b) = (datagram(2000, 1), datagram(2500, 2));
        let (fa, fb) = (fragment(&a, 1000).unwrap(), fragment(&b, 1000).unwrap());
        let mut r = Ipv4Reassembler::new(4);
        assert!(r.push(0, &fa[0]).unwrap().is_none());
        assert!(r.push(0, &fb[1]).unwrap().is_none());
        assert!(r.push(0, &fa[0]).unwrap().is_none(), "duplicate ignored");
        assert!(r.push(0, &fa[1]).unwrap().is_none());
        assert_eq!(r.push(0, &fa[2]).unwrap().unwrap(), &a[..]);
        assert!(r.push(0, &fb[0]).unwrap().is_none());
        assert_eq!(r.push(0, &fb[2]).unwrap().unwrap(), &b[..]);
    }

    #[test]
    fn overlap_drops_the_datagram() {
        let d = datagram(2000, 3);
        let frags = fragment(&d, 1000).unwrap();
        let mut r = Ipv4Reassembler::new(2);
        r.push(0, &frags[0]).unwrap();
        // Same offset, different length: overlaps the first fragment.
        let mut evil = frags[0].clone();
        evil.truncate(evil.len() - 8);
        let len = evil.len() as u16;
        evil[2..4].copy_from_slice(&len.to_be_bytes());
        assert!(r.push(0, &evil).is_err());
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn inconsistent_lengths_are_rejected() {
        let d = datagram(2000, 4);
        let frags = fragment(&d, 1000).unwrap();
        let mut r = Ipv4Reassembler::new(2);
        r.push(0, &frags[2]).unwrap();
        // A "last" fragment ending earlier than the known end.
        let mut short_last = frags[1].clone();
        short_last[6] &= !0x20;
        assert!(r.push(0, &short_last).is_err());

        // MF fragments must carry a multiple of 8 bytes.
        let mut odd = frags[0].clone();
        odd.pop();
        let len = odd.len() as u16;
        odd[2..4].copy_from_slice(&len.to_be_bytes());
        assert!(Ipv4Reassembler::new(1).push(0, &odd).is_err());
        assert!(
            Ipv4Reassembler::new(1).push(0, &d).is_err(),
            "not a fragment"
        );
    }

    #[test]
    fn timeout_and_eviction() {
        let d = datagram(2000, 5);
        let frags = fragment(&d, 1000).unwrap();
        let mut r = Ipv4Reassembler::new(1);
        r.push(0, &frags[0]).unwrap();
        r.expire(TIMEOUT);
        assert_eq!(r.pending(), 0);
        // Late parts start over and never complete on their own.
        r.push(TIMEOUT, &frags[1]).unwrap();
        r.push(TIMEOUT, &frags[2]).unwrap();
        assert_eq!(r.pending(), 1);

        let other = fragment(&datagram(2000, 6), 1000).unwrap();
        r.push(TIMEOUT, &other[0]).unwrap();
        assert_eq!(r.pending(), 1, "capacity 1: the older group was evicted");
        assert!(r.push(TIMEOUT, &frags[0]).unwrap().is_none());
    }

    #[test]
    fn oversized_is_rejected() {
        let d = datagram(1000, 8);
        let mut f = fragment(&d, 600).unwrap().pop().unwrap();
        // Move the last fragment near the 64 KiB limit.
        f[6..8].copy_from_slice(&(0x1fffu16).to_be_bytes());
        assert!(Ipv4Reassembler::new(1).push(0, &f).is_err());
    }
}
