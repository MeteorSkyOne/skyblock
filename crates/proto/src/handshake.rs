//! Noise `IKpsk2` session handshake. This module produces and
//! consumes the Noise messages only; callers carry them in `HS_*` /
//! `REKEY_*` frames, sealing handshake packets with
//! [`SessionKeys::obfuscation`].

use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use snow::{Builder, HandshakeState, params::NoiseParams};

use crate::Error;
use crate::keys::{KEY_LEN, PrivateKey, Psk, PublicKey, SessionKeys};

pub const NOISE_PARAMS: &str = "Noise_IKpsk2_25519_AESGCM_SHA256";
pub const PROLOGUE: &[u8] = b"skyblock v1";
pub const VERSION: u8 = 1;
/// Upper bound on handshake message size, used for stack buffers.
pub const MAX_MSG_LEN: usize = 256;

const PSK_LOCATION: u8 = 2;

fn params() -> NoiseParams {
    NOISE_PARAMS.parse().expect("valid noise params")
}

/// Unix time in nanoseconds, bumped past `last` so it strictly increases
/// even if the wall clock steps backwards.
pub fn next_timestamp(last: u64) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    now.max(last.saturating_add(1))
}

/// Payload of message 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientHello {
    /// Unix nanoseconds; must strictly increase per user (replay guard).
    pub timestamp: u64,
    pub n_paths: u8,
    pub flags: u16,
}

impl ClientHello {
    const LEN: usize = 1 + 8 + 1 + 2;

    fn encode(&self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        b[0] = VERSION;
        b[1..9].copy_from_slice(&self.timestamp.to_be_bytes());
        b[9] = self.n_paths;
        b[10..12].copy_from_slice(&self.flags.to_be_bytes());
        b
    }

    fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != Self::LEN {
            return Err(Error::MalformedHello);
        }
        if b[0] != VERSION {
            return Err(Error::Version(b[0]));
        }
        Ok(Self {
            timestamp: u64::from_be_bytes(b[1..9].try_into().expect("length checked")),
            n_paths: b[9],
            flags: u16::from_be_bytes([b[10], b[11]]),
        })
    }
}

/// Payload of message 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerHello {
    pub vip: Ipv4Addr,
    pub resolver: Ipv4Addr,
    pub mtu: u16,
    pub flags: u16,
}

impl ServerHello {
    const LEN: usize = 1 + 4 + 4 + 2 + 2;

    fn encode(&self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        b[0] = VERSION;
        b[1..5].copy_from_slice(&self.vip.octets());
        b[5..9].copy_from_slice(&self.resolver.octets());
        b[9..11].copy_from_slice(&self.mtu.to_be_bytes());
        b[11..13].copy_from_slice(&self.flags.to_be_bytes());
        b
    }

    fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != Self::LEN {
            return Err(Error::MalformedHello);
        }
        if b[0] != VERSION {
            return Err(Error::Version(b[0]));
        }
        Ok(Self {
            vip: Ipv4Addr::new(b[1], b[2], b[3], b[4]),
            resolver: Ipv4Addr::new(b[5], b[6], b[7], b[8]),
            mtu: u16::from_be_bytes([b[9], b[10]]),
            flags: u16::from_be_bytes([b[11], b[12]]),
        })
    }
}

/// Client side of an in-flight handshake.
pub struct Initiator {
    state: HandshakeState,
}

impl Initiator {
    /// Writes message 1 into `out`; returns the initiator and message length.
    pub fn start(
        local: &PrivateKey,
        node: &PublicKey,
        psk: &Psk,
        hello: &ClientHello,
        out: &mut [u8],
    ) -> Result<(Self, usize), Error> {
        let mut state = Builder::new(params())
            .local_private_key(local.as_bytes())?
            .remote_public_key(node.as_bytes())?
            .psk(PSK_LOCATION, psk.as_bytes())?
            .prologue(PROLOGUE)?
            .build_initiator()?;
        let n = state.write_message(&hello.encode(), out)?;
        Ok((Self { state }, n))
    }

    /// Consumes message 2 and derives the session keys.
    pub fn finish(mut self, msg: &[u8]) -> Result<(ServerHello, SessionKeys), Error> {
        let mut payload = [0u8; MAX_MSG_LEN];
        let n = self.state.read_message(msg, &mut payload)?;
        let hello = ServerHello::decode(&payload[..n])?;
        let (c2s, s2c) = self.state.dangerously_get_raw_split();
        Ok((hello, SessionKeys::from_secrets(&c2s, &s2c)))
    }
}

/// Server side: a message 1 that decrypted correctly. The caller looks up
/// `client`, checks `hello.timestamp`, then [`accept`](Self::accept)s.
pub struct PendingResponse {
    state: HandshakeState,
    pub client: PublicKey,
    pub hello: ClientHello,
}

impl PendingResponse {
    pub fn read(local: &PrivateKey, msg: &[u8]) -> Result<Self, Error> {
        let mut state = Builder::new(params())
            .local_private_key(local.as_bytes())?
            .prologue(PROLOGUE)?
            .build_responder()?;
        let mut payload = [0u8; MAX_MSG_LEN];
        let n = state.read_message(msg, &mut payload)?;
        let hello = ClientHello::decode(&payload[..n])?;
        let client: [u8; KEY_LEN] = state
            .get_remote_static()
            .and_then(|k| k.try_into().ok())
            .ok_or(Error::MalformedHello)?;
        Ok(Self {
            state,
            client: PublicKey::from_bytes(client),
            hello,
        })
    }

    /// Writes message 2 into `out`; returns its length and the session keys.
    pub fn accept(
        mut self,
        psk: &Psk,
        hello: &ServerHello,
        out: &mut [u8],
    ) -> Result<(usize, SessionKeys), Error> {
        self.state
            .set_psk(usize::from(PSK_LOCATION), psk.as_bytes())?;
        let n = self.state.write_message(&hello.encode(), out)?;
        let (c2s, s2c) = self.state.dangerously_get_raw_split();
        Ok((n, SessionKeys::from_secrets(&c2s, &s2c)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{MAX_LEN, PN_LEN};

    struct Setup {
        client: PrivateKey,
        node: PrivateKey,
        psk: Psk,
    }

    fn setup() -> Setup {
        Setup {
            client: PrivateKey::generate(),
            node: PrivateKey::generate(),
            psk: Psk::generate(),
        }
    }

    fn client_hello() -> ClientHello {
        ClientHello {
            timestamp: next_timestamp(0),
            n_paths: 2,
            flags: 0,
        }
    }

    fn server_hello() -> ServerHello {
        ServerHello {
            vip: Ipv4Addr::new(10, 77, 0, 2),
            resolver: Ipv4Addr::new(10, 77, 0, 1),
            mtu: 1400,
            flags: 0,
        }
    }

    /// Runs a full handshake; returns (client keys, server keys).
    fn run(
        s: &Setup,
        client_psk: &Psk,
        server_psk: &Psk,
    ) -> Result<(SessionKeys, SessionKeys), Error> {
        let mut m1 = [0u8; MAX_MSG_LEN];
        let (init, n1) = Initiator::start(
            &s.client,
            &s.node.public_key(),
            client_psk,
            &client_hello(),
            &mut m1,
        )?;
        let pending = PendingResponse::read(&s.node, &m1[..n1])?;
        assert_eq!(pending.client, s.client.public_key());
        let mut m2 = [0u8; MAX_MSG_LEN];
        let (n2, server_keys) = pending.accept(server_psk, &server_hello(), &mut m2)?;
        let (hello, client_keys) = init.finish(&m2[..n2])?;
        assert_eq!(hello, server_hello());
        Ok((client_keys, server_keys))
    }

    fn assert_keys_match(client: &SessionKeys, server: &SessionKeys) {
        let mut buf = [0u8; MAX_LEN];
        buf[PN_LEN..PN_LEN + 4].copy_from_slice(b"ping");
        let n = client.c2s.seal(1, &mut buf, 4).unwrap();
        assert_eq!(server.c2s.open(&mut buf[..n]).unwrap().1, b"ping");
        buf[PN_LEN..PN_LEN + 4].copy_from_slice(b"pong");
        let n = server.s2c.seal(1, &mut buf, 4).unwrap();
        assert_eq!(client.s2c.open(&mut buf[..n]).unwrap().1, b"pong");
    }

    #[test]
    fn full_handshake() {
        let s = setup();
        let (c, sv) = run(&s, &s.psk, &s.psk).unwrap();
        assert_keys_match(&c, &sv);
    }

    #[test]
    fn zero_psk_works() {
        let s = setup();
        let (c, sv) = run(&s, &Psk::ZERO, &Psk::ZERO).unwrap();
        assert_keys_match(&c, &sv);
    }

    #[test]
    fn message_sizes() {
        let s = setup();
        let mut m1 = [0u8; MAX_MSG_LEN];
        let (_, n1) = Initiator::start(
            &s.client,
            &s.node.public_key(),
            &s.psk,
            &client_hello(),
            &mut m1,
        )
        .unwrap();
        // e(32) + enc(s)(32+16) + enc(payload)(12+16)
        assert_eq!(n1, 108);
        let pending = PendingResponse::read(&s.node, &m1[..n1]).unwrap();
        let mut m2 = [0u8; MAX_MSG_LEN];
        let (n2, _) = pending.accept(&s.psk, &server_hello(), &mut m2).unwrap();
        // e(32) + enc(payload)(13+16)
        assert_eq!(n2, 61);
    }

    #[test]
    fn psk_mismatch_fails_at_client() {
        let s = setup();
        assert!(run(&s, &s.psk, &Psk::generate()).is_err());
    }

    #[test]
    fn wrong_node_key_fails_at_server() {
        let s = setup();
        let other_node = PrivateKey::generate();
        let mut m1 = [0u8; MAX_MSG_LEN];
        let (_, n1) = Initiator::start(
            &s.client,
            &other_node.public_key(),
            &s.psk,
            &client_hello(),
            &mut m1,
        )
        .unwrap();
        assert!(PendingResponse::read(&s.node, &m1[..n1]).is_err());
    }

    #[test]
    fn tampered_messages_fail() {
        let s = setup();
        let mut m1 = [0u8; MAX_MSG_LEN];
        let (init, n1) = Initiator::start(
            &s.client,
            &s.node.public_key(),
            &s.psk,
            &client_hello(),
            &mut m1,
        )
        .unwrap();
        for i in 0..n1 {
            let mut bad = m1;
            bad[i] ^= 1;
            assert!(
                PendingResponse::read(&s.node, &bad[..n1]).is_err(),
                "m1 byte {i}"
            );
        }
        let pending = PendingResponse::read(&s.node, &m1[..n1]).unwrap();
        let mut m2 = [0u8; MAX_MSG_LEN];
        let (n2, _) = pending.accept(&s.psk, &server_hello(), &mut m2).unwrap();
        m2[n2 - 1] ^= 1;
        assert!(init.finish(&m2[..n2]).is_err());
    }

    #[test]
    fn garbage_is_rejected() {
        let node = PrivateKey::generate();
        for len in [0, 1, 32, 107, 108, 200] {
            assert!(
                PendingResponse::read(&node, &vec![0xa5; len]).is_err(),
                "len {len}"
            );
        }
    }

    #[test]
    fn replayed_message1_decrypts_again() {
        // Noise alone does not stop msg1 replay; the server must reject
        // it by comparing `hello.timestamp` with the last one seen.
        let s = setup();
        let mut m1 = [0u8; MAX_MSG_LEN];
        let (_init, n1) = Initiator::start(
            &s.client,
            &s.node.public_key(),
            &s.psk,
            &client_hello(),
            &mut m1,
        )
        .unwrap();
        let a = PendingResponse::read(&s.node, &m1[..n1]).unwrap();
        let b = PendingResponse::read(&s.node, &m1[..n1]).unwrap();
        assert_eq!(a.hello.timestamp, b.hello.timestamp);
    }

    #[test]
    fn timestamps_increase() {
        let t1 = next_timestamp(0);
        assert!(next_timestamp(t1) > t1);
        assert_eq!(next_timestamp(u64::MAX - 1), u64::MAX);
    }

    #[test]
    fn hello_codecs() {
        let h = client_hello();
        assert_eq!(ClientHello::decode(&h.encode()).unwrap(), h);
        let mut bad = h.encode();
        bad[0] = 9;
        assert!(matches!(ClientHello::decode(&bad), Err(Error::Version(9))));
        assert!(ClientHello::decode(&bad[..5]).is_err());
        let s = server_hello();
        assert_eq!(ServerHello::decode(&s.encode()).unwrap(), s);
    }
}
