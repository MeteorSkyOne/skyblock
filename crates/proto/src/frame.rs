//! Frame codec (SPEC §3.7). A packet body is a sequence of frames followed
//! by optional padding; a `PADDING` type byte ends the frame list.

use std::net::Ipv4Addr;

use crate::Error;

pub mod ty {
    pub const PADDING: u8 = 0x00;
    pub const IP: u8 = 0x01;
    pub const IP_FRAG: u8 = 0x02;
    pub const ECHO_REQ: u8 = 0x03;
    pub const ECHO_RESP: u8 = 0x04;
    pub const PING: u8 = 0x10;
    pub const PONG: u8 = 0x11;
    pub const STATS: u8 = 0x12;
    pub const NACK: u8 = 0x13;
    pub const PROBE_REQ: u8 = 0x14;
    pub const PROBE_RESP: u8 = 0x15;
    pub const REKEY_INIT: u8 = 0x16;
    pub const REKEY_RESP: u8 = 0x17;
    pub const CLOSE: u8 = 0x18;
    pub const HS_INIT: u8 = 0x20;
    pub const HS_RESP: u8 = 0x21;
}

/// Bytes an `IP` frame adds in front of the IP packet.
pub const IP_OVERHEAD: usize = 1 + 4 + 1 + 2;
/// Bytes an `IP_FRAG` frame adds in front of the fragment data.
pub const IP_FRAG_OVERHEAD: usize = 1 + 4 + 1 + 1 + 1 + 2;
/// Most path counters a `STATS` frame can carry.
pub const MAX_PATHS: usize = 8;

const ECHO_OVERHEAD: usize = 1 + 4 + 1 + 4 + 8 + 2;
const NACK_RANGE_LEN: usize = 4 + 2;
const PATH_RX_LEN: usize = 1 + 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ip<'a> {
    pub seq: u32,
    pub copy: u8,
    pub packet: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpFrag<'a> {
    pub seq: u32,
    pub copy: u8,
    pub idx: u8,
    pub cnt: u8,
    pub data: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Echo<'a> {
    pub seq: u32,
    pub copy: u8,
    pub id: u32,
    pub ts: u64,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ping {
    pub path: u8,
    pub id: u32,
    pub ts: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pong {
    pub path: u8,
    pub id: u32,
    pub ts: u64,
    pub hold_us: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PathRx {
    pub path: u8,
    pub rx_pkts: u64,
}

/// Cumulative receive counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    pub rx_unique: u64,
    pub rx_dup: u64,
    pub rx_rescued: u64,
    n_paths: u8,
    paths: [PathRx; MAX_PATHS],
}

impl Stats {
    pub fn new(rx_unique: u64, rx_dup: u64, rx_rescued: u64) -> Self {
        Self {
            rx_unique,
            rx_dup,
            rx_rescued,
            ..Self::default()
        }
    }

    /// Adds a per-path counter; returns `false` once `MAX_PATHS` is reached.
    pub fn push_path(&mut self, path: PathRx) -> bool {
        let n = usize::from(self.n_paths);
        if n == MAX_PATHS {
            return false;
        }
        self.paths[n] = path;
        self.n_paths += 1;
        true
    }

    pub fn paths(&self) -> &[PathRx] {
        &self.paths[..usize::from(self.n_paths)]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NackRange {
    pub start: u32,
    pub count: u16,
}

/// Encoded NACK ranges, borrowed from a received packet or a writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nack<'a> {
    raw: &'a [u8],
}

impl<'a> Nack<'a> {
    pub fn len(&self) -> usize {
        self.raw.len() / NACK_RANGE_LEN
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    pub fn ranges(&self) -> impl Iterator<Item = NackRange> + 'a {
        self.raw.chunks_exact(NACK_RANGE_LEN).map(|c| NackRange {
            start: u32::from_be_bytes([c[0], c[1], c[2], c[3]]),
            count: u16::from_be_bytes([c[4], c[5]]),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProbeKind {
    Icmp = 1,
    Tcp = 2,
}

impl TryFrom<u8> for ProbeKind {
    type Error = Error;

    fn try_from(v: u8) -> Result<Self, Error> {
        match v {
            1 => Ok(Self::Icmp),
            2 => Ok(Self::Tcp),
            _ => Err(Error::MalformedFrame),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeReq {
    pub id: u32,
    pub kind: ProbeKind,
    pub ip: Ipv4Addr,
    pub port: u16,
    pub count: u8,
    pub interval_ms: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeResp {
    pub id: u32,
    pub sent: u8,
    pub recv: u8,
    pub min_us: u32,
    pub avg_us: u32,
    pub max_us: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    Ip(Ip<'a>),
    IpFrag(IpFrag<'a>),
    EchoReq(Echo<'a>),
    EchoResp(Echo<'a>),
    Ping(Ping),
    Pong(Pong),
    Stats(Stats),
    Nack(Nack<'a>),
    ProbeReq(ProbeReq),
    ProbeResp(ProbeResp),
    RekeyInit(&'a [u8]),
    RekeyResp(&'a [u8]),
    Close(u8),
    HsInit(&'a [u8]),
    HsResp(&'a [u8]),
}

impl Frame<'_> {
    /// Data frames carry a sequence number and take part in dedup and
    /// redundancy; everything else is control.
    pub fn seq(&self) -> Option<u32> {
        match self {
            Frame::Ip(f) => Some(f.seq),
            Frame::IpFrag(f) => Some(f.seq),
            Frame::EchoReq(f) | Frame::EchoResp(f) => Some(f.seq),
            _ => None,
        }
    }

    pub fn encoded_len(&self) -> usize {
        match self {
            Frame::Ip(f) => IP_OVERHEAD + f.packet.len(),
            Frame::IpFrag(f) => IP_FRAG_OVERHEAD + f.data.len(),
            Frame::EchoReq(f) | Frame::EchoResp(f) => ECHO_OVERHEAD + f.payload.len(),
            Frame::Ping(_) => 1 + 1 + 4 + 8,
            Frame::Pong(_) => 1 + 1 + 4 + 8 + 4,
            Frame::Stats(s) => 1 + 8 * 3 + 1 + s.paths().len() * PATH_RX_LEN,
            Frame::Nack(n) => 1 + 1 + n.raw.len(),
            Frame::ProbeReq(_) => 1 + 4 + 1 + 4 + 2 + 1 + 2,
            Frame::ProbeResp(_) => 1 + 4 + 1 + 1 + 4 + 4 + 4,
            Frame::RekeyInit(m) | Frame::RekeyResp(m) | Frame::HsInit(m) | Frame::HsResp(m) => {
                1 + 2 + m.len()
            }
            Frame::Close(_) => 1 + 1,
        }
    }
}

/// Appends frames to a packet body.
pub struct FrameWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> FrameWriter<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn len(&self) -> usize {
        self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn write(&mut self, frame: &Frame<'_>) -> Result<(), Error> {
        let len = frame.encoded_len();
        if len > self.remaining() {
            return Err(Error::BufferTooSmall);
        }
        let mut w = Put {
            buf: &mut self.buf[self.pos..self.pos + len],
            pos: 0,
        };
        match frame {
            Frame::Ip(f) => {
                w.u8(ty::IP).u32(f.seq).u8(f.copy);
                w.blob16(f.packet)?;
            }
            Frame::IpFrag(f) => {
                w.u8(ty::IP_FRAG).u32(f.seq).u8(f.copy).u8(f.idx).u8(f.cnt);
                w.blob16(f.data)?;
            }
            Frame::EchoReq(f) | Frame::EchoResp(f) => {
                let t = if matches!(frame, Frame::EchoReq(_)) {
                    ty::ECHO_REQ
                } else {
                    ty::ECHO_RESP
                };
                w.u8(t).u32(f.seq).u8(f.copy).u32(f.id).u64(f.ts);
                w.blob16(f.payload)?;
            }
            Frame::Ping(p) => {
                w.u8(ty::PING).u8(p.path).u32(p.id).u64(p.ts);
            }
            Frame::Pong(p) => {
                w.u8(ty::PONG).u8(p.path).u32(p.id).u64(p.ts).u32(p.hold_us);
            }
            Frame::Stats(s) => {
                w.u8(ty::STATS)
                    .u64(s.rx_unique)
                    .u64(s.rx_dup)
                    .u64(s.rx_rescued)
                    .u8(s.n_paths);
                for p in s.paths() {
                    w.u8(p.path).u64(p.rx_pkts);
                }
            }
            Frame::Nack(n) => {
                let count = u8::try_from(n.len()).map_err(|_| Error::MalformedFrame)?;
                w.u8(ty::NACK).u8(count).bytes(n.raw);
            }
            Frame::ProbeReq(p) => {
                w.u8(ty::PROBE_REQ)
                    .u32(p.id)
                    .u8(p.kind as u8)
                    .bytes(&p.ip.octets())
                    .u16(p.port)
                    .u8(p.count)
                    .u16(p.interval_ms);
            }
            Frame::ProbeResp(p) => {
                w.u8(ty::PROBE_RESP)
                    .u32(p.id)
                    .u8(p.sent)
                    .u8(p.recv)
                    .u32(p.min_us)
                    .u32(p.avg_us)
                    .u32(p.max_us);
            }
            Frame::RekeyInit(m) => {
                w.u8(ty::REKEY_INIT);
                w.blob16(m)?;
            }
            Frame::RekeyResp(m) => {
                w.u8(ty::REKEY_RESP);
                w.blob16(m)?;
            }
            Frame::Close(reason) => {
                w.u8(ty::CLOSE).u8(*reason);
            }
            Frame::HsInit(m) => {
                w.u8(ty::HS_INIT);
                w.blob16(m)?;
            }
            Frame::HsResp(m) => {
                w.u8(ty::HS_RESP);
                w.blob16(m)?;
            }
        }
        debug_assert_eq!(w.pos, len);
        self.pos += len;
        Ok(())
    }

    /// Writes a NACK frame from explicit ranges (at most 255).
    pub fn nack(&mut self, ranges: &[NackRange]) -> Result<(), Error> {
        let count = u8::try_from(ranges.len()).map_err(|_| Error::MalformedFrame)?;
        let len = 1 + 1 + ranges.len() * NACK_RANGE_LEN;
        if len > self.remaining() {
            return Err(Error::BufferTooSmall);
        }
        let mut w = Put {
            buf: &mut self.buf[self.pos..self.pos + len],
            pos: 0,
        };
        w.u8(ty::NACK).u8(count);
        for r in ranges {
            w.u32(r.start).u16(r.count);
        }
        self.pos += len;
        Ok(())
    }

    /// Appends `n` bytes of padding. Must be the last thing written.
    pub fn pad(&mut self, n: usize) -> Result<(), Error> {
        if n > self.remaining() {
            return Err(Error::BufferTooSmall);
        }
        // PADDING is 0x00, so zero bytes form a valid padding run.
        self.buf[self.pos..self.pos + n].fill(0);
        self.pos += n;
        Ok(())
    }
}

/// Iterates over the frames of a decrypted packet body. Stops at padding or
/// at the end of the body; after yielding an error it yields nothing more.
pub struct FrameReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> FrameReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn next_frame(&mut self) -> Result<Option<Frame<'a>>, Error> {
        let mut r = Get {
            buf: self.buf,
            pos: self.pos,
        };
        let t = match r.buf.get(r.pos) {
            None | Some(&ty::PADDING) => return Ok(None),
            Some(&t) => t,
        };
        r.pos += 1;
        let frame = match t {
            ty::IP => Frame::Ip(Ip {
                seq: r.u32()?,
                copy: r.u8()?,
                packet: r.blob16()?,
            }),
            ty::IP_FRAG => {
                let f = IpFrag {
                    seq: r.u32()?,
                    copy: r.u8()?,
                    idx: r.u8()?,
                    cnt: r.u8()?,
                    data: r.blob16()?,
                };
                if f.idx >= f.cnt {
                    return Err(Error::MalformedFrame);
                }
                Frame::IpFrag(f)
            }
            ty::ECHO_REQ | ty::ECHO_RESP => {
                let e = Echo {
                    seq: r.u32()?,
                    copy: r.u8()?,
                    id: r.u32()?,
                    ts: r.u64()?,
                    payload: r.blob16()?,
                };
                if t == ty::ECHO_REQ {
                    Frame::EchoReq(e)
                } else {
                    Frame::EchoResp(e)
                }
            }
            ty::PING => Frame::Ping(Ping {
                path: r.u8()?,
                id: r.u32()?,
                ts: r.u64()?,
            }),
            ty::PONG => Frame::Pong(Pong {
                path: r.u8()?,
                id: r.u32()?,
                ts: r.u64()?,
                hold_us: r.u32()?,
            }),
            ty::STATS => {
                let mut s = Stats::new(r.u64()?, r.u64()?, r.u64()?);
                let n = r.u8()?;
                if usize::from(n) > MAX_PATHS {
                    return Err(Error::MalformedFrame);
                }
                for _ in 0..n {
                    s.push_path(PathRx {
                        path: r.u8()?,
                        rx_pkts: r.u64()?,
                    });
                }
                Frame::Stats(s)
            }
            ty::NACK => {
                let n = usize::from(r.u8()?);
                Frame::Nack(Nack {
                    raw: r.bytes(n * NACK_RANGE_LEN)?,
                })
            }
            ty::PROBE_REQ => Frame::ProbeReq(ProbeReq {
                id: r.u32()?,
                kind: ProbeKind::try_from(r.u8()?)?,
                ip: {
                    let b = r.bytes(4)?;
                    Ipv4Addr::new(b[0], b[1], b[2], b[3])
                },
                port: r.u16()?,
                count: r.u8()?,
                interval_ms: r.u16()?,
            }),
            ty::PROBE_RESP => Frame::ProbeResp(ProbeResp {
                id: r.u32()?,
                sent: r.u8()?,
                recv: r.u8()?,
                min_us: r.u32()?,
                avg_us: r.u32()?,
                max_us: r.u32()?,
            }),
            ty::REKEY_INIT => Frame::RekeyInit(r.blob16()?),
            ty::REKEY_RESP => Frame::RekeyResp(r.blob16()?),
            ty::CLOSE => Frame::Close(r.u8()?),
            ty::HS_INIT => Frame::HsInit(r.blob16()?),
            ty::HS_RESP => Frame::HsResp(r.blob16()?),
            other => return Err(Error::UnknownFrame(other)),
        };
        self.pos = r.pos;
        Ok(Some(frame))
    }
}

impl<'a> Iterator for FrameReader<'a> {
    type Item = Result<Frame<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_frame() {
            Ok(f) => f.map(Ok),
            Err(e) => {
                self.pos = self.buf.len();
                Some(Err(e))
            }
        }
    }
}

/// Big-endian writer over a slice already checked to be large enough.
struct Put<'b> {
    buf: &'b mut [u8],
    pos: usize,
}

impl Put<'_> {
    fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.buf[self.pos..self.pos + b.len()].copy_from_slice(b);
        self.pos += b.len();
        self
    }

    fn u8(&mut self, v: u8) -> &mut Self {
        self.bytes(&[v])
    }

    fn u16(&mut self, v: u16) -> &mut Self {
        self.bytes(&v.to_be_bytes())
    }

    fn u32(&mut self, v: u32) -> &mut Self {
        self.bytes(&v.to_be_bytes())
    }

    fn u64(&mut self, v: u64) -> &mut Self {
        self.bytes(&v.to_be_bytes())
    }

    /// `len u16 | bytes`.
    fn blob16(&mut self, b: &[u8]) -> Result<&mut Self, Error> {
        let len = u16::try_from(b.len()).map_err(|_| Error::BufferTooSmall)?;
        Ok(self.u16(len).bytes(b))
    }
}

/// Big-endian reader that fails on truncation.
struct Get<'b> {
    buf: &'b [u8],
    pos: usize,
}

impl<'b> Get<'b> {
    fn bytes(&mut self, n: usize) -> Result<&'b [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::MalformedFrame)?;
        let b = self.buf.get(self.pos..end).ok_or(Error::MalformedFrame)?;
        self.pos = end;
        Ok(b)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        Ok(self.bytes(N)?.try_into().expect("length checked"))
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        self.array().map(u16::from_be_bytes)
    }

    fn u32(&mut self) -> Result<u32, Error> {
        self.array().map(u32::from_be_bytes)
    }

    fn u64(&mut self) -> Result<u64, Error> {
        self.array().map(u64::from_be_bytes)
    }

    fn blob16(&mut self) -> Result<&'b [u8], Error> {
        let n = usize::from(self.u16()?);
        self.bytes(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples() -> Vec<Frame<'static>> {
        let mut stats = Stats::new(1_000_000, 42, 7);
        stats.push_path(PathRx {
            path: 0,
            rx_pkts: 500_000,
        });
        stats.push_path(PathRx {
            path: 1,
            rx_pkts: u64::MAX,
        });
        vec![
            Frame::Ip(Ip {
                seq: 1,
                copy: 0,
                packet: &[0x45; 60],
            }),
            Frame::Ip(Ip {
                seq: u32::MAX,
                copy: 3,
                packet: &[],
            }),
            Frame::IpFrag(IpFrag {
                seq: 9,
                copy: 1,
                idx: 1,
                cnt: 2,
                data: &[1, 2, 3],
            }),
            Frame::EchoReq(Echo {
                seq: 5,
                copy: 0,
                id: 77,
                ts: 123_456_789,
                payload: &[9; 200],
            }),
            Frame::EchoResp(Echo {
                seq: 6,
                copy: 1,
                id: 77,
                ts: 123_456_789,
                payload: b"",
            }),
            Frame::Ping(Ping {
                path: 2,
                id: 0xdead_beef,
                ts: u64::MAX,
            }),
            Frame::Pong(Pong {
                path: 2,
                id: 1,
                ts: 2,
                hold_us: 3,
            }),
            Frame::Stats(stats),
            Frame::Stats(Stats::default()),
            Frame::ProbeReq(ProbeReq {
                id: 3,
                kind: ProbeKind::Tcp,
                ip: Ipv4Addr::new(203, 0, 113, 5),
                port: 443,
                count: 10,
                interval_ms: 200,
            }),
            Frame::ProbeResp(ProbeResp {
                id: 3,
                sent: 10,
                recv: 9,
                min_us: 1,
                avg_us: 2,
                max_us: 3,
            }),
            Frame::RekeyInit(&[7; 108]),
            Frame::RekeyResp(&[8; 61]),
            Frame::Close(4),
            Frame::HsInit(&[1; 108]),
            Frame::HsResp(&[2; 61]),
        ]
    }

    #[test]
    fn roundtrip_each_frame() {
        for f in samples() {
            let mut buf = [0u8; 512];
            let mut w = FrameWriter::new(&mut buf);
            w.write(&f).unwrap();
            let n = w.len();
            assert_eq!(n, f.encoded_len(), "{f:?}");
            let got: Vec<_> = FrameReader::new(&buf[..n])
                .collect::<Result<_, _>>()
                .unwrap();
            assert_eq!(got, vec![f]);
        }
    }

    #[test]
    fn roundtrip_sequence_with_padding() {
        let frames = samples();
        let mut buf = [0u8; 4096];
        let mut w = FrameWriter::new(&mut buf);
        for f in &frames {
            w.write(f).unwrap();
        }
        w.pad(37).unwrap();
        let n = w.len();
        let got: Vec<_> = FrameReader::new(&buf[..n])
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(got, frames);
    }

    #[test]
    fn nack_roundtrip() {
        let ranges = [
            NackRange {
                start: 10,
                count: 1,
            },
            NackRange {
                start: u32::MAX,
                count: 500,
            },
        ];
        let mut buf = [0u8; 64];
        let mut w = FrameWriter::new(&mut buf);
        w.nack(&ranges).unwrap();
        let n = w.len();
        let mut it = FrameReader::new(&buf[..n]);
        let Some(Ok(Frame::Nack(nack))) = it.next() else {
            panic!()
        };
        assert_eq!(nack.ranges().collect::<Vec<_>>(), ranges);
        assert!(it.next().is_none());

        // A decoded NACK re-encodes to the same bytes.
        let mut buf2 = [0u8; 64];
        let mut w2 = FrameWriter::new(&mut buf2);
        w2.write(&Frame::Nack(nack)).unwrap();
        let n2 = w2.len();
        assert_eq!(&buf2[..n2], &buf[..n]);
    }

    #[test]
    fn empty_and_padding_only_bodies() {
        assert!(FrameReader::new(&[]).next().is_none());
        assert!(FrameReader::new(&[0; 50]).next().is_none());
    }

    #[test]
    fn writer_rejects_overflow() {
        let mut buf = [0u8; 10];
        let mut w = FrameWriter::new(&mut buf);
        assert!(matches!(
            w.write(&Frame::Ip(Ip {
                seq: 0,
                copy: 0,
                packet: &[0; 3]
            })),
            Err(Error::BufferTooSmall)
        ));
        assert_eq!(w.len(), 0);
        w.write(&Frame::Ip(Ip {
            seq: 0,
            copy: 0,
            packet: &[0; 2],
        }))
        .unwrap();
        assert!(w.pad(1).is_err());
    }

    #[test]
    fn every_truncation_is_an_error() {
        for f in samples() {
            let mut buf = [0u8; 512];
            let mut w = FrameWriter::new(&mut buf);
            w.write(&f).unwrap();
            let n = w.len();
            for cut in 1..n {
                let r: Result<Vec<_>, _> = FrameReader::new(&buf[..cut]).collect();
                assert!(r.is_err(), "{f:?} cut at {cut}");
            }
        }
    }

    #[test]
    fn unknown_type_and_bad_fields() {
        let mut it = FrameReader::new(&[0x7f, 1, 2]);
        assert!(matches!(it.next(), Some(Err(Error::UnknownFrame(0x7f)))));
        assert!(it.next().is_none());

        // idx >= cnt
        let bad_frag = [ty::IP_FRAG, 0, 0, 0, 1, 0, 2, 2, 0, 0];
        assert!(FrameReader::new(&bad_frag).next().unwrap().is_err());

        // too many STATS paths
        let mut bad_stats = vec![ty::STATS];
        bad_stats.extend_from_slice(&[0; 24]);
        bad_stats.push(MAX_PATHS as u8 + 1);
        bad_stats.extend_from_slice(&[0; 9 * (MAX_PATHS + 1)]);
        assert!(FrameReader::new(&bad_stats).next().unwrap().is_err());

        // unknown probe kind
        let bad_probe = [ty::PROBE_REQ, 0, 0, 0, 1, 9, 1, 2, 3, 4, 0, 80, 1, 0, 10];
        assert!(FrameReader::new(&bad_probe).next().unwrap().is_err());
    }

    #[test]
    fn frames_after_error_are_not_yielded() {
        let mut buf = [0u8; 64];
        let mut w = FrameWriter::new(&mut buf);
        w.write(&Frame::Close(1)).unwrap();
        let n = w.len();
        buf[n] = 0x7e;
        let items: Vec<_> = FrameReader::new(&buf[..n + 1]).collect();
        assert_eq!(items.len(), 2);
        assert!(items[0].is_ok());
        assert!(items[1].is_err());
    }
}
