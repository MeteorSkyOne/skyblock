//! Packet layout constants, padding policy and a stack buffer helper
//! (SPEC §3.3, §5).

use rand::{Rng, RngExt};

use crate::Error;
use crate::frame::FrameWriter;
use crate::keys::Keyset;

pub const PN_LEN: usize = 8;
pub const TAG_LEN: usize = 16;
pub const OVERHEAD: usize = PN_LEN + TAG_LEN;
/// Shortest valid packet: overhead plus a one-byte body.
pub const MIN_LEN: usize = OVERHEAD + 1;
/// Largest UDP payload sent: PPPoE MTU 1492 − IPv4 20 − UDP 8.
pub const MAX_LEN: usize = 1464;
/// Largest body (frames + padding) per packet.
pub const MAX_BODY: usize = MAX_LEN - OVERHEAD;

/// Default padding ceiling for data packets.
pub const DATA_PAD_MAX: usize = 48;
/// Padding ceiling for control-only packets.
pub const CONTROL_PAD_MAX: usize = 96;
/// Handshake packets are padded to a uniformly random total length in
/// this range.
pub const HANDSHAKE_LEN_MIN: usize = 180;
pub const HANDSHAKE_LEN_MAX: usize = 400;

/// Uniform padding in `[0, max]`, limited to the room left in the body.
pub fn random_padding<R: Rng + ?Sized>(rng: &mut R, body_len: usize, max: usize) -> usize {
    let room = MAX_BODY.saturating_sub(body_len);
    rng.random_range(0..=max.min(room))
}

/// Padding that brings a body of `body_len` to `target` bytes (none if it
/// is already longer), limited to the room left.
pub fn padding_towards(body_len: usize, target: usize) -> usize {
    target
        .saturating_sub(body_len)
        .min(MAX_BODY.saturating_sub(body_len))
}

/// Padding that brings a handshake packet to a random total length in
/// `[HANDSHAKE_LEN_MIN, HANDSHAKE_LEN_MAX]`.
pub fn handshake_padding<R: Rng + ?Sized>(rng: &mut R, body_len: usize) -> usize {
    let target = rng.random_range(HANDSHAKE_LEN_MIN..=HANDSHAKE_LEN_MAX);
    target
        .saturating_sub(body_len + OVERHEAD)
        .min(MAX_BODY.saturating_sub(body_len))
}

/// A full-size packet buffer. Write frames through [`writer`](Self::writer),
/// then [`seal`](Self::seal) with the resulting body length.
pub struct PacketBuf {
    buf: [u8; MAX_LEN],
}

impl Default for PacketBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketBuf {
    pub fn new() -> Self {
        Self { buf: [0; MAX_LEN] }
    }

    pub fn writer(&mut self) -> FrameWriter<'_> {
        FrameWriter::new(&mut self.buf[PN_LEN..MAX_LEN - TAG_LEN])
    }

    pub fn seal(&mut self, keys: &Keyset, pn: u64, body_len: usize) -> Result<&[u8], Error> {
        let n = keys.seal(pn, &mut self.buf, body_len)?;
        Ok(&self.buf[..n])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{Frame, FrameReader, Ip, Ping};
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn build_and_open() {
        let keys = Keyset::from_secret(&[9; 32]);
        let mut rng = StdRng::seed_from_u64(1);
        let mut pb = PacketBuf::new();
        let mut w = pb.writer();
        w.write(&Frame::Ip(Ip {
            seq: 3,
            copy: 0,
            packet: &[0x45; 100],
        }))
        .unwrap();
        w.write(&Frame::Ping(Ping {
            path: 1,
            id: 2,
            ts: 3,
        }))
        .unwrap();
        let pad = random_padding(&mut rng, w.len(), DATA_PAD_MAX);
        w.pad(pad).unwrap();
        let body_len = w.len();
        let mut pkt = pb.seal(&keys, 42, body_len).unwrap().to_vec();
        assert_eq!(pkt.len(), body_len + OVERHEAD);

        let (pn, body) = keys.open(&mut pkt).unwrap();
        assert_eq!(pn, 42);
        let frames: Vec<_> = FrameReader::new(body).collect::<Result<_, _>>().unwrap();
        assert_eq!(frames.len(), 2);
    }

    #[test]
    fn padding_bounds() {
        let mut rng = StdRng::seed_from_u64(2);
        for _ in 0..1000 {
            assert!(random_padding(&mut rng, 100, DATA_PAD_MAX) <= DATA_PAD_MAX);
            assert!(random_padding(&mut rng, MAX_BODY - 5, DATA_PAD_MAX) <= 5);
            assert_eq!(random_padding(&mut rng, MAX_BODY, DATA_PAD_MAX), 0);
            let body = 111;
            let total = body + handshake_padding(&mut rng, body) + OVERHEAD;
            assert!((HANDSHAKE_LEN_MIN..=HANDSHAKE_LEN_MAX).contains(&total));
        }
    }

    #[test]
    fn full_body_fits() {
        let keys = Keyset::from_secret(&[1; 32]);
        let mut pb = PacketBuf::new();
        let mut w = pb.writer();
        assert_eq!(w.remaining(), MAX_BODY);
        w.pad(MAX_BODY).unwrap();
        assert_eq!(pb.seal(&keys, 0, MAX_BODY).unwrap().len(), MAX_LEN);
    }
}
