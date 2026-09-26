//! Inner packets from clients: IPv4 parsing and
//! rewriting, IPv4 fragment reassembly and DNS query parsing.
#![no_main]

use std::net::Ipv4Addr;

use libfuzzer_sys::fuzz_target;
use skyblock_proto::dns;
use skyblock_proto::ip::Ipv4Packet;
use skyblock_proto::ipfrag::Ipv4Reassembler;

fuzz_target!(|data: &[u8]| {
    let mut pkt = data.to_vec();
    if let Ok(mut p) = Ipv4Packet::parse(&mut pkt[..]) {
        let _ = (p.ports(), p.tcp_flags(), p.udp_payload(), p.is_fragment());
        p.set_src(Ipv4Addr::new(10, 77, 0, 2));
        p.set_dst(Ipv4Addr::new(10, 77, 0, 1));
        p.clamp_mss(1360);
        p.recompute_checksums();
        if let Some(msg) = p.udp_payload() {
            let _ = (dns::id(msg), dns::is_response(msg), dns::query_name(msg));
        }
    }
    let _ = dns::query_name(data);

    // The input as a run of fragments: `len u16 | packet` chunks.
    let mut r = Ipv4Reassembler::new(4);
    let mut rest = data;
    let mut now = 0;
    while rest.len() >= 2 {
        let len = usize::from(u16::from_be_bytes([rest[0], rest[1]])).min(rest.len() - 2);
        let frag = &rest[2..2 + len];
        rest = &rest[2 + len..];
        if let Ok(Some(whole)) = r.push(now, frag) {
            let p = Ipv4Packet::parse(whole).expect("reassembled packet parses");
            assert!(!p.is_fragment());
        }
        now += 100_000;
        r.expire(now);
    }
});
