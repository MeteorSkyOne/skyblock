//! Just enough DNS (RFC 1035) to route queries: the transaction ID, the QR
//! flag and the first question's name (SPEC §6.5, §7.5). Nothing here
//! allocates; names are decoded into a stack buffer.

pub const PORT: u16 = 53;
pub const HEADER_LEN: usize = 12;
/// Longest name in dotted form (255 octets on the wire).
pub const MAX_NAME: usize = 253;

const QR: u8 = 0x80;
const MAX_LABEL: usize = 63;

/// The transaction ID.
pub fn id(msg: &[u8]) -> Option<u16> {
    (msg.len() >= HEADER_LEN).then(|| u16::from_be_bytes([msg[0], msg[1]]))
}

/// Overwrites the transaction ID; returns `false` if `msg` has no header.
pub fn set_id(msg: &mut [u8], id: u16) -> bool {
    if msg.len() < HEADER_LEN {
        return false;
    }
    msg[..2].copy_from_slice(&id.to_be_bytes());
    true
}

/// Whether `msg` has a header with the QR (response) bit set.
pub fn is_response(msg: &[u8]) -> bool {
    msg.len() >= HEADER_LEN && msg[2] & QR != 0
}

/// A lower-cased domain name without the trailing dot.
#[derive(Clone)]
pub struct Name {
    buf: [u8; MAX_NAME],
    len: usize,
}

impl Name {
    pub fn as_str(&self) -> &str {
        // Only printable ASCII is ever stored.
        std::str::from_utf8(&self.buf[..self.len]).expect("ascii name")
    }

    /// Whether this name is `domain` or a subdomain of it. `domain` must be
    /// lower-case without leading or trailing dots.
    pub fn in_domain(&self, domain: &str) -> bool {
        let (n, d) = (self.as_str(), domain);
        if d.is_empty() {
            return false;
        }
        n == d
            || (n.len() > d.len() && n.ends_with(d) && n.as_bytes()[n.len() - d.len() - 1] == b'.')
    }
}

impl std::fmt::Debug for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Name({})", self.as_str())
    }
}

/// The name of the first question of a query. `None` for responses, for
/// messages without a question and for names this code does not handle
/// (compression pointers, or bytes other than printable ASCII).
pub fn query_name(msg: &[u8]) -> Option<Name> {
    if msg.len() < HEADER_LEN || is_response(msg) || u16::from_be_bytes([msg[4], msg[5]]) == 0 {
        return None;
    }
    let mut name = Name {
        buf: [0; MAX_NAME],
        len: 0,
    };
    let mut pos = HEADER_LEN;
    loop {
        let len = usize::from(*msg.get(pos)?);
        pos += 1;
        if len == 0 {
            return Some(name);
        }
        // 0xc0 marks a compression pointer, 0x40/0x80 are reserved.
        if len > MAX_LABEL {
            return None;
        }
        let label = msg.get(pos..pos + len)?;
        pos += len;
        let dot = usize::from(name.len > 0);
        if name.len + dot + len > MAX_NAME {
            return None;
        }
        if dot == 1 {
            name.buf[name.len] = b'.';
            name.len += 1;
        }
        for &b in label {
            if !(0x21..=0x7e).contains(&b) || b == b'.' {
                return None;
            }
            name.buf[name.len] = b.to_ascii_lowercase();
            name.len += 1;
        }
    }
}

/// Normalizes a configured domain: lower-case, no surrounding dots or
/// spaces. `None` if nothing is left.
pub fn normalize_domain(d: &str) -> Option<String> {
    let d = d.trim().trim_matches('.').to_ascii_lowercase();
    (!d.is_empty()).then_some(d)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A query for `name` (type A, class IN) with transaction ID `id`.
    pub fn query(id: u16, name: &str) -> Vec<u8> {
        let mut m = vec![0u8; HEADER_LEN];
        m[..2].copy_from_slice(&id.to_be_bytes());
        m[2] = 0x01; // RD
        m[5] = 1; // QDCOUNT
        for label in name.split('.').filter(|l| !l.is_empty()) {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0, 1, 0, 1]);
        m
    }

    #[test]
    fn header_fields() {
        let mut q = query(0x1234, "example.com");
        assert_eq!(id(&q), Some(0x1234));
        assert!(!is_response(&q));
        assert!(set_id(&mut q, 7));
        assert_eq!(id(&q), Some(7));
        q[2] |= QR;
        assert!(is_response(&q));
        assert_eq!(id(&q[..11]), None);
        assert!(!set_id(&mut [0u8; 3], 1));
    }

    #[test]
    fn names() {
        let n = query_name(&query(1, "Game.Riotgames.COM")).unwrap();
        assert_eq!(n.as_str(), "game.riotgames.com");
        assert!(n.in_domain("riotgames.com"));
        assert!(n.in_domain("game.riotgames.com"));
        assert!(!n.in_domain("games.com"), "suffix must start at a label");
        assert!(!n.in_domain("otgames.com"));
        assert!(!n.in_domain("x.game.riotgames.com"));
        assert!(!n.in_domain(""));
        assert_eq!(query_name(&query(1, "")).unwrap().as_str(), "");
    }

    #[test]
    fn rejects_what_it_cannot_route() {
        let mut resp = query(1, "a.com");
        resp[2] |= QR;
        assert!(query_name(&resp).is_none(), "responses");
        let mut none = query(1, "a.com");
        none[5] = 0;
        assert!(query_name(&none).is_none(), "no question");
        let mut ptr = query(1, "a.com");
        ptr[HEADER_LEN] = 0xc0;
        assert!(query_name(&ptr).is_none(), "compression pointer");
        let mut odd = query(1, "a.com");
        odd[HEADER_LEN + 1] = b' ';
        assert!(query_name(&odd).is_none(), "space in label");
        let q = query(1, "abc.com");
        for cut in HEADER_LEN..q.len() - 4 {
            assert!(query_name(&q[..cut]).is_none(), "truncated at {cut}");
        }
        // 5 labels of 63 bytes exceed the 253-byte limit.
        let long = [&"a".repeat(63)[..]; 5].join(".");
        assert!(query_name(&query(1, &long)).is_none());
        let max = [
            &"a".repeat(63)[..],
            &"b".repeat(63),
            &"c".repeat(63),
            &"d".repeat(61),
        ]
        .join(".");
        assert_eq!(
            query_name(&query(1, &max)).unwrap().as_str().len(),
            MAX_NAME
        );
    }

    #[test]
    fn domain_normalization() {
        assert_eq!(
            normalize_domain(" .RiotGames.com. ").as_deref(),
            Some("riotgames.com")
        );
        assert_eq!(normalize_domain(".."), None);
    }
}
