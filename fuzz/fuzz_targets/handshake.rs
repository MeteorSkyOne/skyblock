//! Noise messages from the wire: the node reading message 1,
//! the client reading message 2. Both must reject garbage without panics.
#![no_main]

use libfuzzer_sys::fuzz_target;
use skyblock_proto::handshake::{ClientHello, Initiator, MAX_MSG_LEN, PendingResponse};
use skyblock_proto::keys::{PrivateKey, Psk};

fuzz_target!(|data: &[u8]| {
    let node = PrivateKey::from_bytes([3; 32]);
    let _ = PendingResponse::read(&node, data);

    let client = PrivateKey::from_bytes([4; 32]);
    let hello = ClientHello {
        timestamp: 1,
        n_paths: 2,
        flags: 0,
    };
    let mut m1 = [0u8; MAX_MSG_LEN];
    let (init, _) =
        Initiator::start(&client, &node.public_key(), &Psk::ZERO, &hello, &mut m1).unwrap();
    let _ = init.finish(data);
});
