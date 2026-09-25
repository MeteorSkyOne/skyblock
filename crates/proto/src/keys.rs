//! Static identity keys and per-direction packet keysets (SPEC §3.2–3.5).
//!
//! Wire format of every packet:
//!
//! ```text
//! | PN (8B, masked) | AES-256-GCM ciphertext | tag (16B) |
//! ```

use std::fmt;
use std::str::FromStr;

use aes::Aes256;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes_gcm::aead::{Nonce, Tag};
use aes_gcm::{AeadInOut, Aes256Gcm};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;

use crate::Error;
use crate::packet::{MIN_LEN, OVERHEAD, PN_LEN, TAG_LEN};

pub const KEY_LEN: usize = 32;
const IV_LEN: usize = 12;
const SAMPLE_LEN: usize = 16;

const OBFS_SALT: &[u8] = b"skyblock obfs v1";

/// X25519 private key.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateKey([u8; KEY_LEN]);

/// X25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; KEY_LEN]);

/// Optional pre-shared key mixed into the handshake; all zeros when unused.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Psk([u8; KEY_LEN]);

impl PrivateKey {
    pub fn generate() -> Self {
        let mut b = [0u8; KEY_LEN];
        rand::rng().fill_bytes(&mut b);
        // Clamp as X25519 does, so the stored form is canonical.
        b[0] &= 248;
        b[31] &= 127;
        b[31] |= 64;
        Self(b)
    }

    pub fn from_bytes(b: [u8; KEY_LEN]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub fn public_key(&self) -> PublicKey {
        let secret = x25519_dalek::StaticSecret::from(self.0);
        PublicKey(x25519_dalek::PublicKey::from(&secret).to_bytes())
    }

    pub fn to_base64(&self) -> String {
        B64.encode(self.0)
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(..)")
    }
}

impl PublicKey {
    pub fn from_bytes(b: [u8; KEY_LEN]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&B64.encode(self.0))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

impl Psk {
    pub const ZERO: Psk = Psk([0; KEY_LEN]);

    pub fn generate() -> Self {
        let mut b = [0u8; KEY_LEN];
        rand::rng().fill_bytes(&mut b);
        Self(b)
    }

    pub fn from_bytes(b: [u8; KEY_LEN]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub fn to_base64(&self) -> String {
        B64.encode(self.0)
    }
}

impl fmt::Debug for Psk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Psk(..)")
    }
}

fn decode_key(s: &str) -> Result<[u8; KEY_LEN], Error> {
    let v = B64.decode(s.trim()).map_err(|_| Error::InvalidKey)?;
    v.try_into().map_err(|_| Error::InvalidKey)
}

impl FromStr for PrivateKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        decode_key(s).map(Self)
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        decode_key(s).map(Self)
    }
}

impl FromStr for Psk {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        decode_key(s).map(Self)
    }
}

/// Keys protecting one direction of traffic.
pub struct Keyset {
    aead: Aes256Gcm,
    iv: [u8; IV_LEN],
    hp: Aes256,
}

impl Keyset {
    /// Derives a keyset from a 32-byte secret used as the HKDF PRK.
    pub fn from_secret(secret: &[u8; KEY_LEN]) -> Self {
        let hk = Hkdf::<Sha256>::from_prk(secret).expect("32-byte PRK");
        let mut key = [0u8; KEY_LEN];
        let mut iv = [0u8; IV_LEN];
        let mut hp = [0u8; KEY_LEN];
        hk.expand(b"sb1 aead", &mut key).expect("valid length");
        hk.expand(b"sb1 iv", &mut iv).expect("valid length");
        hk.expand(b"sb1 hp", &mut hp).expect("valid length");
        Self {
            aead: Aes256Gcm::new_from_slice(&key).expect("32-byte key"),
            iv,
            hp: Aes256::new_from_slice(&hp).expect("32-byte key"),
        }
    }

    /// Encrypts `buf[PN_LEN..PN_LEN + body_len]` in place, appends the tag
    /// and masks the packet number. Returns the packet length.
    pub fn seal(&self, pn: u64, buf: &mut [u8], body_len: usize) -> Result<usize, Error> {
        let len = body_len + OVERHEAD;
        if body_len == 0 || buf.len() < len {
            return Err(Error::BufferTooSmall);
        }
        let pn_bytes = pn.to_be_bytes();
        let (head, rest) = buf[..len].split_at_mut(PN_LEN);
        head.copy_from_slice(&pn_bytes);
        let (body, tag_out) = rest.split_at_mut(body_len);
        let tag = self
            .aead
            .encrypt_inout_detached(&self.nonce(pn), &pn_bytes, body.into())
            .map_err(|_| Error::BufferTooSmall)?;
        tag_out.copy_from_slice(&tag);
        let mask = self.hp_mask(&buf[PN_LEN..PN_LEN + SAMPLE_LEN]);
        for (b, m) in buf[..PN_LEN].iter_mut().zip(mask) {
            *b ^= m;
        }
        Ok(len)
    }

    /// Recovers the packet number without authenticating. Useful for a
    /// replay pre-check before paying for decryption.
    pub fn peek_pn(&self, packet: &[u8]) -> Result<u64, Error> {
        if packet.len() < MIN_LEN {
            return Err(Error::Truncated);
        }
        let mask = self.hp_mask(&packet[PN_LEN..PN_LEN + SAMPLE_LEN]);
        let mut pn = [0u8; PN_LEN];
        for ((o, b), m) in pn.iter_mut().zip(&packet[..PN_LEN]).zip(mask) {
            *o = b ^ m;
        }
        Ok(u64::from_be_bytes(pn))
    }

    /// Authenticates and decrypts `packet` in place, returning the packet
    /// number and plaintext body. On failure `packet` is left unchanged, so
    /// the caller may try another keyset.
    pub fn open<'a>(&self, packet: &'a mut [u8]) -> Result<(u64, &'a [u8]), Error> {
        let pn = self.peek_pn(packet)?;
        let (_, rest) = packet.split_at_mut(PN_LEN);
        let body_len = rest.len() - TAG_LEN;
        let (body, tag) = rest.split_at_mut(body_len);
        let tag: [u8; TAG_LEN] = (&*tag).try_into().expect("tag length");
        // aes-gcm verifies the tag before touching the buffer.
        self.aead
            .decrypt_inout_detached(
                &self.nonce(pn),
                &pn.to_be_bytes(),
                body.into(),
                &Tag::<Aes256Gcm>::from(tag),
            )
            .map_err(|_| Error::Auth)?;
        Ok((pn, body))
    }

    fn nonce(&self, pn: u64) -> Nonce<Aes256Gcm> {
        let mut n = self.iv;
        for (a, b) in n[IV_LEN - 8..].iter_mut().zip(pn.to_be_bytes()) {
            *a ^= b;
        }
        Nonce::<Aes256Gcm>::from(n)
    }

    fn hp_mask(&self, sample: &[u8]) -> [u8; PN_LEN] {
        let sample: [u8; SAMPLE_LEN] = sample.try_into().expect("sample length");
        let mut block = aes::Block::from(sample);
        self.hp.encrypt_block(&mut block);
        block[..PN_LEN].try_into().expect("mask length")
    }
}

/// Keysets for both directions: `c2s` protects client→server traffic.
pub struct SessionKeys {
    pub c2s: Keyset,
    pub s2c: Keyset,
}

impl SessionKeys {
    pub fn from_secrets(c2s: &[u8; KEY_LEN], s2c: &[u8; KEY_LEN]) -> Self {
        Self {
            c2s: Keyset::from_secret(c2s),
            s2c: Keyset::from_secret(s2c),
        }
    }

    /// Keysets that disguise handshake packets for the node owning
    /// `node_public`. They only hide structure; Noise authenticates.
    pub fn obfuscation(node_public: &PublicKey) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(OBFS_SALT), node_public.as_bytes());
        let mut c2s = [0u8; KEY_LEN];
        let mut s2c = [0u8; KEY_LEN];
        hk.expand(b"c2s", &mut c2s).expect("valid length");
        hk.expand(b"s2c", &mut s2c).expect("valid length");
        Self::from_secrets(&c2s, &s2c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::MAX_LEN;

    fn keyset(seed: u8) -> Keyset {
        Keyset::from_secret(&[seed; KEY_LEN])
    }

    fn sealed(k: &Keyset, pn: u64, body: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; MAX_LEN];
        buf[PN_LEN..PN_LEN + body.len()].copy_from_slice(body);
        let n = k.seal(pn, &mut buf, body.len()).unwrap();
        buf.truncate(n);
        buf
    }

    #[test]
    fn seal_open_roundtrip() {
        let k = keyset(1);
        for (pn, len) in [
            (0u64, 1usize),
            (1, 17),
            (u64::MAX, 200),
            (12345, MAX_LEN - OVERHEAD),
        ] {
            let body: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut pkt = sealed(&k, pn, &body);
            assert_eq!(pkt.len(), len + OVERHEAD);
            assert_eq!(k.peek_pn(&pkt).unwrap(), pn);
            let (got_pn, got) = k.open(&mut pkt).unwrap();
            assert_eq!(got_pn, pn);
            assert_eq!(got, &body[..]);
        }
    }

    #[test]
    fn packet_number_is_masked() {
        let k = keyset(2);
        let a = sealed(&k, 0, &[0; 32]);
        let b = sealed(&k, 1, &[0; 32]);
        assert_ne!(&a[..PN_LEN], &0u64.to_be_bytes());
        assert_ne!(&b[..PN_LEN], &1u64.to_be_bytes());
        // Consecutive PNs must not show up as consecutive wire values.
        let wa = u64::from_be_bytes(a[..8].try_into().unwrap());
        let wb = u64::from_be_bytes(b[..8].try_into().unwrap());
        assert_ne!(wa.wrapping_add(1), wb);
    }

    #[test]
    fn any_bit_flip_fails_and_leaves_packet_intact() {
        let k = keyset(3);
        let pkt = sealed(&k, 77, b"hello world, this is a test body");
        for i in 0..pkt.len() {
            for bit in [0x01u8, 0x80] {
                let mut bad = pkt.clone();
                bad[i] ^= bit;
                let before = bad.clone();
                assert!(matches!(k.open(&mut bad), Err(Error::Auth)), "byte {i}");
                assert_eq!(bad, before, "buffer modified on failure");
            }
        }
    }

    #[test]
    fn wrong_keyset_fails_then_right_one_succeeds() {
        let (a, b) = (keyset(4), keyset(5));
        let mut pkt = sealed(&a, 9, b"trial decryption");
        assert!(b.open(&mut pkt).is_err());
        assert_eq!(a.open(&mut pkt).unwrap().1, b"trial decryption");
    }

    #[test]
    fn short_and_empty() {
        let k = keyset(6);
        assert!(matches!(
            k.open(&mut [0u8; MIN_LEN - 1]),
            Err(Error::Truncated)
        ));
        let mut buf = [0u8; 64];
        assert!(k.seal(0, &mut buf, 0).is_err());
        assert!(k.seal(0, &mut buf, 64 - OVERHEAD + 1).is_err());
    }

    #[test]
    fn session_directions_differ() {
        let s = SessionKeys::from_secrets(&[1; 32], &[2; 32]);
        let mut pkt = sealed(&s.c2s, 1, b"x");
        assert!(s.s2c.open(&mut pkt).is_err());
        assert!(s.c2s.open(&mut pkt).is_ok());
    }

    #[test]
    fn obfuscation_keys_are_node_specific() {
        let n1 = PrivateKey::generate().public_key();
        let n2 = PrivateKey::generate().public_key();
        let o1 = SessionKeys::obfuscation(&n1);
        let o1b = SessionKeys::obfuscation(&n1);
        let o2 = SessionKeys::obfuscation(&n2);
        let mut pkt = sealed(&o1.c2s, 5, b"hs");
        assert!(o2.c2s.open(&mut pkt).is_err());
        assert!(o1.s2c.open(&mut pkt).is_err());
        assert!(o1b.c2s.open(&mut pkt).is_ok());
    }

    #[test]
    fn key_encoding() {
        let sk = PrivateKey::generate();
        let pk = sk.public_key();
        assert_eq!(sk.to_base64().parse::<PrivateKey>().unwrap(), sk);
        assert_eq!(pk.to_string().parse::<PublicKey>().unwrap(), pk);
        assert!("AAAA".parse::<PublicKey>().is_err());
        assert!("not base64!".parse::<PublicKey>().is_err());
        assert_eq!(format!("{sk:?}"), "PrivateKey(..)");
        let psk = Psk::generate();
        assert_eq!(psk.to_base64().parse::<Psk>().unwrap(), psk);
    }

    #[test]
    fn public_key_matches_x25519_reference() {
        // RFC 7748 §6.1 test vector (Alice).
        let sk: [u8; 32] = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let pk: [u8; 32] = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        assert_eq!(PrivateKey::from_bytes(sk).public_key().as_bytes(), &pk);
    }

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let v: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        v.try_into().unwrap()
    }
}
