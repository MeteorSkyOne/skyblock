//! The receive path: arbitrary datagrams against the
//! session and handshake keysets, and arbitrary *authentic* bodies (sealed
//! here) through frame parsing, dedup and IP_FRAG reassembly.
#![no_main]

use libfuzzer_sys::fuzz_target;
use skyblock_proto::frame::FrameReader;
use skyblock_proto::keys::{Keyset, PrivateKey, SessionKeys};
use skyblock_proto::packet::{MAX_BODY, MAX_LEN, PN_LEN};
use skyblock_proto::session::{RxState, open_handshake};

fuzz_target!(|data: &[u8]| {
    // As a raw datagram from an unknown sender.
    let node = PrivateKey::from_bytes([3; 32]).public_key();
    let obfs = SessionKeys::obfuscation(&node);
    let mut raw = data.to_vec();
    let mut rx = RxState::new(Keyset::from_secret(&[1; 32]));
    rx.set_next(Keyset::from_secret(&[2; 32]));
    assert!(rx.open(0, &mut raw).is_err(), "forged packet opened");
    assert_eq!(raw, data, "failed open modified the packet");
    assert!(open_handshake(&obfs.c2s, &mut raw).is_err());

    // As a sequence of authentic bodies: `len u16 | body` chunks.
    let keys = Keyset::from_secret(&[1; 32]);
    let mut rx = RxState::new(Keyset::from_secret(&[1; 32]));
    let mut rest = data;
    let mut pn = 0u64;
    while rest.len() >= 2 {
        let len = usize::from(u16::from_be_bytes([rest[0], rest[1]])) % (MAX_BODY + 1);
        rest = &rest[2..];
        let len = len.clamp(1, rest.len().max(1));
        let Some(body) = rest.get(..len) else { break };
        rest = &rest[len..];
        let mut buf = [0u8; MAX_LEN];
        buf[PN_LEN..PN_LEN + len].copy_from_slice(body);
        let n = keys.seal(pn, &mut buf, len).unwrap();
        pn += 1 + u64::from(body[0] % 4);
        let Ok((body, _)) = rx.open(pn, &mut buf[..n]) else {
            continue;
        };
        let frames: Vec<_> = FrameReader::new(body).map_while(Result::ok).collect();
        for f in &frames {
            let _ = rx.accept(pn, f);
        }
        rx.expire(pn * 1000);
    }
});
