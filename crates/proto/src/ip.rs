//! Minimal IPv4 / TCP / UDP handling: parsing, address rewrite with
//! incremental checksum update (RFC 1624), MSS clamping and UDP datagram
//! synthesis.

use std::net::{Ipv4Addr, SocketAddrV4};

use crate::Error;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

pub const IPV4_HEADER_LEN: usize = 20;
pub const UDP_HEADER_LEN: usize = 8;
const TCP_HEADER_LEN: usize = 20;

const TCP_FLAG_SYN: u8 = 0x02;
const TCP_OPT_END: u8 = 0;
const TCP_OPT_NOP: u8 = 1;
const TCP_OPT_MSS: u8 = 2;

const DEFAULT_TTL: u8 = 64;

/// A validated view over an IPv4 packet. Bytes past `total_len` are ignored.
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Packet<B> {
    buf: B,
    header_len: usize,
    total_len: usize,
}

impl<B: AsRef<[u8]>> Ipv4Packet<B> {
    pub fn parse(buf: B) -> Result<Self, Error> {
        let b = buf.as_ref();
        if b.len() < IPV4_HEADER_LEN || b[0] >> 4 != 4 {
            return Err(Error::MalformedIp);
        }
        let header_len = usize::from(b[0] & 0x0f) * 4;
        let total_len = usize::from(u16::from_be_bytes([b[2], b[3]]));
        if header_len < IPV4_HEADER_LEN || total_len < header_len || total_len > b.len() {
            return Err(Error::MalformedIp);
        }
        Ok(Self {
            buf,
            header_len,
            total_len,
        })
    }

    pub fn into_inner(self) -> B {
        self.buf
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf.as_ref()[..self.total_len]
    }

    pub fn header_len(&self) -> usize {
        self.header_len
    }

    pub fn total_len(&self) -> usize {
        self.total_len
    }

    pub fn protocol(&self) -> u8 {
        self.buf.as_ref()[9]
    }

    pub fn ident(&self) -> u16 {
        let b = self.buf.as_ref();
        u16::from_be_bytes([b[4], b[5]])
    }

    pub fn src(&self) -> Ipv4Addr {
        self.addr_at(12)
    }

    pub fn dst(&self) -> Ipv4Addr {
        self.addr_at(16)
    }

    /// Fragment offset in 8-byte units.
    pub fn frag_offset(&self) -> u16 {
        let b = self.buf.as_ref();
        u16::from_be_bytes([b[6], b[7]]) & 0x1fff
    }

    pub fn more_fragments(&self) -> bool {
        self.buf.as_ref()[6] & 0x20 != 0
    }

    pub fn is_fragment(&self) -> bool {
        self.more_fragments() || self.frag_offset() != 0
    }

    /// Everything after the IP header (the transport segment, or a slice of it
    /// for fragments).
    pub fn payload(&self) -> &[u8] {
        &self.buf.as_ref()[self.header_len..self.total_len]
    }

    /// `(src_port, dst_port)` for TCP/UDP. `None` for other protocols and for
    /// non-first fragments, which carry no transport header.
    pub fn ports(&self) -> Option<(u16, u16)> {
        let p = self.transport_header(4)?;
        Some((
            u16::from_be_bytes([p[0], p[1]]),
            u16::from_be_bytes([p[2], p[3]]),
        ))
    }

    pub fn tcp_flags(&self) -> Option<u8> {
        if self.protocol() != PROTO_TCP {
            return None;
        }
        self.transport_header(TCP_HEADER_LEN).map(|p| p[13])
    }

    pub fn is_tcp_syn(&self) -> bool {
        self.tcp_flags().is_some_and(|f| f & TCP_FLAG_SYN != 0)
    }

    /// Payload of an unfragmented UDP datagram.
    pub fn udp_payload(&self) -> Option<&[u8]> {
        if self.protocol() != PROTO_UDP || self.is_fragment() {
            return None;
        }
        let p = self.payload();
        if p.len() < UDP_HEADER_LEN {
            return None;
        }
        let udp_len = usize::from(u16::from_be_bytes([p[4], p[5]]));
        if udp_len < UDP_HEADER_LEN || udp_len > p.len() {
            return None;
        }
        Some(&p[UDP_HEADER_LEN..udp_len])
    }

    fn addr_at(&self, off: usize) -> Ipv4Addr {
        let b = self.buf.as_ref();
        Ipv4Addr::new(b[off], b[off + 1], b[off + 2], b[off + 3])
    }

    /// The TCP/UDP header, if this is the first fragment and at least
    /// `min_len` bytes of it are present.
    fn transport_header(&self, min_len: usize) -> Option<&[u8]> {
        match self.protocol() {
            PROTO_TCP | PROTO_UDP if self.frag_offset() == 0 => {
                let p = self.payload();
                (p.len() >= min_len).then_some(p)
            }
            _ => None,
        }
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> Ipv4Packet<B> {
    pub fn set_src(&mut self, addr: Ipv4Addr) {
        self.set_addr(12, addr);
    }

    pub fn set_dst(&mut self, addr: Ipv4Addr) {
        self.set_addr(16, addr);
    }

    /// Lowers the MSS option of a TCP SYN / SYN-ACK to at most `mss`.
    /// Returns whether the packet was modified.
    pub fn clamp_mss(&mut self, mss: u16) -> bool {
        if !self.is_tcp_syn() {
            return false;
        }
        let hl = self.header_len;
        let seg = &mut self.buf.as_mut()[hl..self.total_len];
        let data_off = usize::from(seg[12] >> 4) * 4;
        if data_off < TCP_HEADER_LEN || data_off > seg.len() {
            return false;
        }
        let mut i = TCP_HEADER_LEN;
        while i < data_off {
            match seg[i] {
                TCP_OPT_END => break,
                TCP_OPT_NOP => i += 1,
                kind => {
                    let Some(&len) = seg.get(i + 1) else { break };
                    let len = usize::from(len);
                    if len < 2 || i + len > data_off {
                        break;
                    }
                    if kind == TCP_OPT_MSS && len == 4 {
                        let cur = u16::from_be_bytes([seg[i + 2], seg[i + 3]]);
                        if cur <= mss {
                            return false;
                        }
                        seg[i + 2..i + 4].copy_from_slice(&mss.to_be_bytes());
                        adjust_field16(&mut seg[16..18], cur, mss);
                        return true;
                    }
                    i += len;
                }
            }
        }
        false
    }

    fn set_addr(&mut self, off: usize, addr: Ipv4Addr) {
        let (hl, proto, first_frag) = (self.header_len, self.protocol(), self.frag_offset() == 0);
        let b = self.buf.as_mut();
        let old = u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]);
        let new = u32::from(addr);
        if old == new {
            return;
        }
        b[off..off + 4].copy_from_slice(&new.to_be_bytes());
        adjust_field32(&mut b[10..12], old, new);

        // The TCP/UDP checksum covers a pseudo-header containing both
        // addresses; only the first fragment carries it.
        if !first_frag {
            return;
        }
        let seg = &mut b[hl..self.total_len];
        match proto {
            PROTO_TCP if seg.len() >= TCP_HEADER_LEN => adjust_field32(&mut seg[16..18], old, new),
            PROTO_UDP if seg.len() >= UDP_HEADER_LEN => {
                let cur = u16::from_be_bytes([seg[6], seg[7]]);
                // A zero UDP checksum means "not computed" and must stay zero.
                if cur != 0 {
                    let mut c = adjust32(cur, old, new);
                    if c == 0 {
                        c = 0xffff;
                    }
                    seg[6..8].copy_from_slice(&c.to_be_bytes());
                }
            }
            _ => {}
        }
    }
}

/// Writes an IPv4/UDP datagram into `out` and returns its length.
pub fn build_udp(
    out: &mut [u8],
    src: SocketAddrV4,
    dst: SocketAddrV4,
    ident: u16,
    payload: &[u8],
) -> Result<usize, Error> {
    let udp_len = UDP_HEADER_LEN + payload.len();
    let total = IPV4_HEADER_LEN + udp_len;
    if total > usize::from(u16::MAX) || out.len() < total {
        return Err(Error::BufferTooSmall);
    }
    let (hdr, rest) = out[..total].split_at_mut(IPV4_HEADER_LEN);
    hdr[0] = 0x45;
    hdr[1] = 0;
    hdr[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    hdr[4..6].copy_from_slice(&ident.to_be_bytes());
    hdr[6..8].fill(0);
    hdr[8] = DEFAULT_TTL;
    hdr[9] = PROTO_UDP;
    hdr[10..12].fill(0);
    hdr[12..16].copy_from_slice(&src.ip().octets());
    hdr[16..20].copy_from_slice(&dst.ip().octets());
    let c = checksum(hdr);
    hdr[10..12].copy_from_slice(&c.to_be_bytes());

    rest[0..2].copy_from_slice(&src.port().to_be_bytes());
    rest[2..4].copy_from_slice(&dst.port().to_be_bytes());
    rest[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    rest[6..8].fill(0);
    rest[UDP_HEADER_LEN..].copy_from_slice(payload);
    let mut c = transport_checksum(*src.ip(), *dst.ip(), PROTO_UDP, rest);
    if c == 0 {
        c = 0xffff;
    }
    rest[6..8].copy_from_slice(&c.to_be_bytes());
    Ok(total)
}

/// One's-complement sum of `data` as big-endian 16-bit words, added to `sum`.
pub fn ones_sum(mut sum: u64, data: &[u8]) -> u64 {
    let mut words = data.chunks_exact(2);
    for w in &mut words {
        sum += u64::from(u16::from_be_bytes([w[0], w[1]]));
    }
    if let [last] = words.remainder() {
        sum += u64::from(*last) << 8;
    }
    sum
}

pub fn fold(mut sum: u64) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// Internet checksum of `data` (checksum field must be zeroed).
pub fn checksum(data: &[u8]) -> u16 {
    !fold(ones_sum(0, data))
}

/// Whether `data`, including its checksum field, sums to all ones.
pub fn checksum_valid(data: &[u8]) -> bool {
    fold(ones_sum(0, data)) == 0xffff
}

/// TCP/UDP checksum over the IPv4 pseudo-header and `segment` (whose
/// checksum field must be zeroed).
pub fn transport_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, segment: &[u8]) -> u16 {
    let mut sum = ones_sum(0, &src.octets());
    sum = ones_sum(sum, &dst.octets());
    sum += u64::from(proto) + segment.len() as u64;
    !fold(ones_sum(sum, segment))
}

/// Whether a TCP/UDP segment's checksum is valid for the given addresses.
pub fn transport_checksum_valid(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, segment: &[u8]) -> bool {
    let mut sum = ones_sum(0, &src.octets());
    sum = ones_sum(sum, &dst.octets());
    sum += u64::from(proto) + segment.len() as u64;
    fold(ones_sum(sum, segment)) == 0xffff
}

/// RFC 1624 eqn. 3: `HC' = ~(~HC + ~m + m')`.
fn adjust16(csum: u16, old: u16, new: u16) -> u16 {
    !fold(u64::from(!csum) + u64::from(!old) + u64::from(new))
}

fn adjust32(csum: u16, old: u32, new: u32) -> u16 {
    let c = adjust16(csum, (old >> 16) as u16, (new >> 16) as u16);
    adjust16(c, old as u16, new as u16)
}

fn adjust_field16(field: &mut [u8], old: u16, new: u16) {
    let c = adjust16(u16::from_be_bytes([field[0], field[1]]), old, new);
    field.copy_from_slice(&c.to_be_bytes());
}

fn adjust_field32(field: &mut [u8], old: u32, new: u32) {
    let c = adjust32(u16::from_be_bytes([field[0], field[1]]), old, new);
    field.copy_from_slice(&c.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAN: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 23);
    const VIP: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);
    const REMOTE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);

    fn tcp_syn(src: Ipv4Addr, dst: Ipv4Addr, mss: u16) -> Vec<u8> {
        // 20B IP + 20B TCP + 12B options (MSS, NOP, NOP, SACK-perm, NOP, WS)
        let opts: [u8; 12] = [2, 4, (mss >> 8) as u8, mss as u8, 1, 1, 4, 2, 1, 3, 3, 8];
        let seg_len = TCP_HEADER_LEN + opts.len();
        let total = IPV4_HEADER_LEN + seg_len;
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        p[6] = 0x40; // DF
        p[8] = 128;
        p[9] = PROTO_TCP;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        let c = checksum(&p[..20]);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        let seg = &mut p[20..];
        seg[0..2].copy_from_slice(&50000u16.to_be_bytes());
        seg[2..4].copy_from_slice(&443u16.to_be_bytes());
        seg[4..8].copy_from_slice(&0xdeadbeefu32.to_be_bytes());
        seg[12] = ((seg_len / 4) as u8) << 4;
        seg[13] = TCP_FLAG_SYN;
        seg[14..16].copy_from_slice(&64240u16.to_be_bytes());
        seg[20..].copy_from_slice(&opts);
        let c = transport_checksum(src, dst, PROTO_TCP, seg);
        seg[16..18].copy_from_slice(&c.to_be_bytes());
        p
    }

    fn udp(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; 1500];
        let n = build_udp(
            &mut out,
            SocketAddrV4::new(src, 40000),
            SocketAddrV4::new(dst, 27015),
            7,
            payload,
        )
        .unwrap();
        out.truncate(n);
        out
    }

    fn assert_valid(p: &[u8]) {
        let pkt = Ipv4Packet::parse(p).unwrap();
        assert!(checksum_valid(&p[..pkt.header_len()]), "ip header checksum");
        if pkt.frag_offset() == 0 {
            assert!(
                transport_checksum_valid(pkt.src(), pkt.dst(), pkt.protocol(), pkt.payload()),
                "transport checksum"
            );
        }
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(Ipv4Packet::parse(&[0u8; 10][..]).is_err());
        assert!(Ipv4Packet::parse(&[0x60u8; 40][..]).is_err());
        let mut p = udp(LAN, REMOTE, b"hi");
        p[0] = 0x44; // IHL < 5
        assert!(Ipv4Packet::parse(&p[..]).is_err());
        let mut p = udp(LAN, REMOTE, b"hi");
        p[3] = 0xff; // total length beyond buffer
        assert!(Ipv4Packet::parse(&p[..]).is_err());
    }

    #[test]
    fn parse_fields() {
        let p = udp(LAN, REMOTE, b"hello");
        let pkt = Ipv4Packet::parse(&p[..]).unwrap();
        assert_eq!(pkt.src(), LAN);
        assert_eq!(pkt.dst(), REMOTE);
        assert_eq!(pkt.protocol(), PROTO_UDP);
        assert_eq!(pkt.ports(), Some((40000, 27015)));
        assert_eq!(pkt.udp_payload(), Some(&b"hello"[..]));
        assert!(!pkt.is_fragment());
        assert_valid(&p);
    }

    #[test]
    fn trailing_bytes_ignored() {
        let mut p = udp(LAN, REMOTE, b"x");
        let len = p.len();
        p.extend_from_slice(&[0xaa; 16]);
        let pkt = Ipv4Packet::parse(&p[..]).unwrap();
        assert_eq!(pkt.as_bytes().len(), len);
    }

    #[test]
    fn rewrite_udp_addresses() {
        for payload in [&b""[..], b"a", b"odd-length payload", &[0xff; 999]] {
            let mut p = udp(LAN, REMOTE, payload);
            let mut pkt = Ipv4Packet::parse(&mut p[..]).unwrap();
            pkt.set_src(VIP);
            assert_eq!(pkt.src(), VIP);
            assert_valid(&p);
            let mut pkt = Ipv4Packet::parse(&mut p[..]).unwrap();
            pkt.set_dst(Ipv4Addr::new(255, 255, 255, 255));
            pkt.set_src(LAN);
            assert_valid(&p);
        }
    }

    #[test]
    fn rewrite_udp_zero_checksum_stays_zero() {
        let mut p = udp(LAN, REMOTE, b"payload");
        p[26..28].fill(0);
        Ipv4Packet::parse(&mut p[..]).unwrap().set_src(VIP);
        assert_eq!(&p[26..28], &[0, 0]);
        assert!(checksum_valid(&p[..20]));
    }

    #[test]
    fn rewrite_tcp_addresses() {
        let mut p = tcp_syn(LAN, REMOTE, 1460);
        assert_valid(&p);
        let mut pkt = Ipv4Packet::parse(&mut p[..]).unwrap();
        pkt.set_src(VIP);
        pkt.set_dst(Ipv4Addr::new(1, 1, 1, 1));
        assert_valid(&p);
    }

    #[test]
    fn rewrite_matches_full_recompute() {
        let mut p = tcp_syn(LAN, REMOTE, 1460);
        Ipv4Packet::parse(&mut p[..]).unwrap().set_src(VIP);
        let expected = tcp_syn(VIP, REMOTE, 1460);
        assert_eq!(p, expected);
    }

    #[test]
    fn non_first_fragment_keeps_transport_bytes() {
        let mut p = udp(LAN, REMOTE, &[7; 64]);
        p[6..8].copy_from_slice(&100u16.to_be_bytes()); // offset 800 bytes
        let c = {
            p[10..12].fill(0);
            checksum(&p[..20])
        };
        p[10..12].copy_from_slice(&c.to_be_bytes());
        let before = p[20..].to_vec();
        let mut pkt = Ipv4Packet::parse(&mut p[..]).unwrap();
        assert!(pkt.is_fragment());
        assert_eq!(pkt.ports(), None);
        pkt.set_src(VIP);
        assert_eq!(&p[20..], &before[..]);
        assert!(checksum_valid(&p[..20]));
    }

    #[test]
    fn clamp_mss_lowers_only() {
        let mut p = tcp_syn(LAN, REMOTE, 1460);
        assert!(Ipv4Packet::parse(&mut p[..]).unwrap().clamp_mss(1360));
        assert_eq!(p, tcp_syn(LAN, REMOTE, 1360));
        assert_valid(&p);

        let mut p = tcp_syn(LAN, REMOTE, 1200);
        assert!(!Ipv4Packet::parse(&mut p[..]).unwrap().clamp_mss(1360));
        assert_eq!(p, tcp_syn(LAN, REMOTE, 1200));
    }

    #[test]
    fn clamp_mss_ignores_non_syn_and_udp() {
        let mut p = tcp_syn(LAN, REMOTE, 1460);
        p[33] = 0x10; // ACK only
        assert!(!Ipv4Packet::parse(&mut p[..]).unwrap().clamp_mss(1000));
        let mut p = udp(LAN, REMOTE, &[2, 4, 5, 180]);
        assert!(!Ipv4Packet::parse(&mut p[..]).unwrap().clamp_mss(1000));
    }

    #[test]
    fn clamp_mss_survives_malformed_options() {
        let mut p = tcp_syn(LAN, REMOTE, 1460);
        p[40] = 9; // unknown kind
        p[41] = 0; // zero length would loop forever if not guarded
        assert!(!Ipv4Packet::parse(&mut p[..]).unwrap().clamp_mss(1000));
        let mut p = tcp_syn(LAN, REMOTE, 1460);
        p[41] = 200; // length past the header
        assert!(!Ipv4Packet::parse(&mut p[..]).unwrap().clamp_mss(1000));
    }

    #[test]
    fn incremental_matches_full_on_many_values() {
        // Exercise the carry paths of RFC 1624 across many address pairs.
        let mut x: u32 = 0x1234_5678;
        for _ in 0..2000 {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let a = Ipv4Addr::from(x);
            let b = Ipv4Addr::from(x.rotate_left(13) ^ 0xffff_0000);
            let mut p = udp(a, REMOTE, &x.to_be_bytes());
            Ipv4Packet::parse(&mut p[..]).unwrap().set_src(b);
            assert_valid(&p);
        }
    }
}
