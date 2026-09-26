//! Hot-path micro-benchmarks: packet seal/open, header rewrite,
//! dedup and a full encode+seal / open+decode round.

use std::hint::black_box;
use std::net::{Ipv4Addr, SocketAddrV4};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use skyblock_proto::dedup::DedupWindow;
use skyblock_proto::frame::{Frame, FrameReader, Ip};
use skyblock_proto::ip::{Ipv4Packet, build_udp};
use skyblock_proto::keys::Keyset;
use skyblock_proto::packet::{MAX_LEN, PacketBuf};

const SIZES: [usize; 3] = [64, 200, 1400];

fn seal_open(c: &mut Criterion) {
    let keys = Keyset::from_secret(&[7; 32]);
    let mut g = c.benchmark_group("seal");
    for size in SIZES {
        g.throughput(Throughput::Bytes(size as u64));
        let mut buf = [0u8; MAX_LEN];
        let mut pn = 0u64;
        g.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| {
                pn += 1;
                black_box(keys.seal(pn, &mut buf, size).unwrap())
            })
        });
    }
    g.finish();

    let mut g = c.benchmark_group("open");
    for size in SIZES {
        g.throughput(Throughput::Bytes(size as u64));
        let mut sealed = [0u8; MAX_LEN];
        let n = keys.seal(1, &mut sealed, size).unwrap();
        let mut work = [0u8; MAX_LEN];
        g.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                work[..n].copy_from_slice(&sealed[..n]);
                black_box(keys.open(&mut work[..n]).unwrap().0)
            })
        });
    }
    g.finish();

    // Cost of rejecting a packet under the wrong keyset (trial decryption).
    let other = Keyset::from_secret(&[8; 32]);
    let mut sealed = [0u8; MAX_LEN];
    let n = keys.seal(1, &mut sealed, 200).unwrap();
    c.bench_function("open_wrong_key/200", |b| {
        b.iter(|| black_box(other.open(&mut sealed[..n]).is_err()))
    });
}

fn udp_packet(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; 1500];
    let n = build_udp(
        &mut out,
        SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 23), 40000),
        SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 27015),
        1,
        &vec![0xab; len],
    )
    .unwrap();
    out.truncate(n);
    out
}

fn rewrite(c: &mut Criterion) {
    let mut pkt = udp_packet(200);
    let (a, b) = (Ipv4Addr::new(192, 168, 1, 23), Ipv4Addr::new(10, 77, 0, 2));
    let mut flip = false;
    c.bench_function("ip_set_src/udp200", |bch| {
        bch.iter(|| {
            flip = !flip;
            let mut p = Ipv4Packet::parse(&mut pkt[..]).unwrap();
            p.set_src(if flip { a } else { b });
        })
    });
}

fn dedup(c: &mut Criterion) {
    let mut d = DedupWindow::new();
    let mut seq = 0u32;
    c.bench_function("dedup_insert", |b| {
        b.iter(|| {
            seq = seq.wrapping_add(1);
            black_box(d.insert(seq))
        })
    });
}

/// Frame encode + seal on one side, open + decode on the other, as each
/// forwarded game packet will do.
fn pipeline(c: &mut Criterion) {
    let keys = Keyset::from_secret(&[3; 32]);
    let ip = udp_packet(200 - 28);
    let mut pb = PacketBuf::new();
    let mut rx = [0u8; MAX_LEN];
    let mut pn = 0u64;
    c.bench_function("pipeline/game200", |b| {
        b.iter(|| {
            pn += 1;
            let mut w = pb.writer();
            w.write(&Frame::Ip(Ip {
                seq: pn as u32,
                copy: 0,
                packet: &ip,
            }))
            .unwrap();
            let body = w.len();
            let pkt = pb.seal(&keys, pn, body).unwrap();
            let n = pkt.len();
            rx[..n].copy_from_slice(pkt);
            let (_, body) = keys.open(&mut rx[..n]).unwrap();
            let Some(Ok(Frame::Ip(f))) = FrameReader::new(body).next() else {
                unreachable!()
            };
            black_box(f.packet.len())
        })
    });
}

criterion_group!(benches, seal_open, rewrite, dedup, pipeline);
criterion_main!(benches);
