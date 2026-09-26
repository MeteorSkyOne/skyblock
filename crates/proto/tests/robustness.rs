//! Cheap stand-in for the fuzz targets (see `fuzz/`), run by `cargo test`
//! on every platform: random and mutated inputs through every parser a
//! peer or a client can reach. Nothing may panic.

use std::net::{Ipv4Addr, SocketAddrV4};

use skyblock_proto::dns;
use skyblock_proto::frame::{
    Frame, FrameReader, FrameWriter, Ip, IpFrag, Ping, ProbeKind, ProbeReq, Stats,
};
use skyblock_proto::handshake::PendingResponse;
use skyblock_proto::ip::{Ipv4Packet, build_udp};
use skyblock_proto::ipfrag::{Ipv4Reassembler, fragment};
use skyblock_proto::keys::{Keyset, PrivateKey};
use skyblock_proto::packet::{MAX_LEN, PN_LEN};
use skyblock_proto::session::RxState;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }

    /// Up to `max - 1` random bytes.
    fn some_bytes(&mut self, max: usize) -> Vec<u8> {
        let n = self.below(max);
        self.bytes(n)
    }

    /// Flips, overwrites, truncates or extends `v` a little.
    fn mutate(&mut self, v: &mut Vec<u8>) {
        for _ in 0..1 + self.below(4) {
            match self.below(4) {
                0 if !v.is_empty() => {
                    let i = self.below(v.len());
                    v[i] ^= 1 << self.below(8);
                }
                1 if !v.is_empty() => {
                    let i = self.below(v.len());
                    v[i] = self.next() as u8;
                }
                2 => v.truncate(self.below(v.len() + 1)),
                _ => {
                    let extra = self.some_bytes(8);
                    v.extend_from_slice(&extra);
                }
            }
        }
    }
}

fn frames_seed() -> Vec<u8> {
    let mut buf = vec![0u8; 1024];
    let mut w = FrameWriter::new(&mut buf);
    for f in [
        Frame::Ip(Ip {
            seq: 7,
            copy: 1,
            packet: &[0x45; 40],
        }),
        Frame::IpFrag(IpFrag {
            seq: 9,
            copy: 0,
            idx: 1,
            cnt: 3,
            data: &[1; 30],
        }),
        Frame::Ping(Ping {
            path: 1,
            id: 2,
            ts: 3,
        }),
        Frame::Stats(Stats::new(1, 2, 3, 4)),
        Frame::ProbeReq(ProbeReq {
            id: 1,
            kind: ProbeKind::Tcp,
            ip: Ipv4Addr::new(203, 0, 113, 9),
            port: 443,
            count: 3,
            interval_ms: 100,
        }),
        Frame::RekeyInit(&[5; 108]),
    ] {
        w.write(&f).unwrap();
    }
    let n = w.len();
    buf.truncate(n);
    buf
}

fn udp_seed(len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len + 28];
    let n = build_udp(
        &mut b,
        SocketAddrV4::new(Ipv4Addr::new(10, 77, 0, 2), 5353),
        SocketAddrV4::new(Ipv4Addr::new(10, 77, 0, 1), 53),
        9,
        &{
            let mut q = vec![0u8; 12];
            q[5] = 1;
            q.extend_from_slice(&[
                4, b'g', b'a', b'm', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
            ]);
            q.resize(len, 0);
            q
        },
    )
    .unwrap();
    b.truncate(n);
    b
}

#[test]
fn frame_parsing_survives_garbage() {
    let mut rng = Rng(0x5eed_0001);
    let seed = frames_seed();
    for i in 0..5_000 {
        let mut v = if i % 2 == 0 {
            seed.clone()
        } else {
            rng.some_bytes(300)
        };
        rng.mutate(&mut v);
        for f in FrameReader::new(&v).map_while(Result::ok) {
            // Whatever parses must encode again.
            let mut out = vec![0u8; f.encoded_len()];
            FrameWriter::new(&mut out).write(&f).unwrap();
        }
    }
}

#[test]
fn receive_path_survives_authentic_garbage() {
    let mut rng = Rng(0x5eed_0002);
    let keys = Keyset::from_secret(&[1; 32]);
    let mut rx = RxState::new(Keyset::from_secret(&[1; 32]));
    let seed = frames_seed();
    for pn in 0..3_000u64 {
        let mut body = seed.clone();
        rng.mutate(&mut body);
        body.truncate(1400);
        if body.is_empty() {
            body.push(0);
        }
        let mut buf = [0u8; MAX_LEN];
        buf[PN_LEN..PN_LEN + body.len()].copy_from_slice(&body);
        let n = keys.seal(pn, &mut buf, body.len()).unwrap();
        let mut forged = buf[..n].to_vec();
        rng.mutate(&mut forged);
        let _ = rx.open(pn, &mut forged);
        let Ok((plain, _)) = rx.open(pn, &mut buf[..n]) else {
            continue;
        };
        let frames: Vec<_> = FrameReader::new(plain).map_while(Result::ok).collect();
        for f in &frames {
            let _ = rx.accept(pn, f);
        }
    }
}

#[test]
fn handshake_reader_survives_garbage() {
    let mut rng = Rng(0x5eed_0003);
    let node = PrivateKey::from_bytes([3; 32]);
    for _ in 0..500 {
        let msg = rng.some_bytes(200);
        assert!(PendingResponse::read(&node, &msg).is_err());
    }
}

#[test]
fn inner_packets_survive_garbage() {
    let mut rng = Rng(0x5eed_0004);
    let mut reasm = Ipv4Reassembler::new(4);
    let big = udp_seed(3000);
    let frags = fragment(&big, 700).unwrap();
    for i in 0..5_000u64 {
        let mut p = match i % 3 {
            0 => udp_seed(40),
            1 => frags[rng.below(frags.len())].clone(),
            _ => rng.some_bytes(100),
        };
        rng.mutate(&mut p);
        if let Ok(mut pkt) = Ipv4Packet::parse(&mut p[..]) {
            let _ = (pkt.ports(), pkt.tcp_flags());
            if let Some(msg) = pkt.udp_payload() {
                let _ = dns::query_name(msg);
            }
            pkt.set_src(Ipv4Addr::new(1, 2, 3, 4));
            pkt.clamp_mss(1000);
            pkt.recompute_checksums();
        }
        if let Ok(Some(whole)) = reasm.push(i * 1000, &p) {
            assert!(Ipv4Packet::parse(whole).is_ok_and(|w| !w.is_fragment()));
        }
    }
    // Untouched fragments still reassemble afterwards.
    let mut r = Ipv4Reassembler::new(1);
    let whole = frags
        .iter()
        .find_map(|f| r.push(0, f).unwrap().map(<[u8]>::to_vec))
        .unwrap();
    assert_eq!(whole, big);
}
