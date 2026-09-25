//! Splitting oversized IP packets into `IP_FRAG` chunks and reassembling
//! them (SPEC §3.11). Fragments of one packet use consecutive sequence
//! numbers, so the group is identified by `seq - idx`.

use crate::{Error, Micros};

/// Fragments per packet; bounded by the width of the received bitmap.
pub const MAX_FRAGS: usize = 64;
pub const REASSEMBLY_TIMEOUT: Micros = 1_000_000;
/// Largest packet we reassemble (the IPv4 maximum).
const MAX_REASSEMBLED: usize = u16::MAX as usize;

/// Splits `packet` into the fewest chunks of at most `max_chunk` bytes, with
/// sizes as even as possible.
pub fn split(packet: &[u8], max_chunk: usize) -> Result<Split<'_>, Error> {
    if packet.is_empty() || max_chunk == 0 {
        return Err(Error::MalformedFragment);
    }
    let cnt = packet.len().div_ceil(max_chunk);
    if cnt > MAX_FRAGS {
        return Err(Error::MalformedFragment);
    }
    Ok(Split {
        packet,
        chunk: packet.len().div_ceil(cnt),
        cnt: cnt as u8,
        idx: 0,
    })
}

/// Iterator over `(idx, cnt, chunk)`.
pub struct Split<'a> {
    packet: &'a [u8],
    chunk: usize,
    cnt: u8,
    idx: u8,
}

impl<'a> Iterator for Split<'a> {
    type Item = (u8, u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx == self.cnt {
            return None;
        }
        let start = usize::from(self.idx) * self.chunk;
        let end = (start + self.chunk).min(self.packet.len());
        let item = (self.idx, self.cnt, &self.packet[start..end]);
        self.idx += 1;
        Some(item)
    }
}

struct Group {
    active: bool,
    first_seq: u32,
    cnt: u8,
    received: u64,
    deadline: Micros,
    data: Vec<u8>,
    /// `(offset into data, len)` per fragment index.
    parts: [(u32, u32); MAX_FRAGS],
}

impl Group {
    fn empty() -> Self {
        Self {
            active: false,
            first_seq: 0,
            cnt: 0,
            received: 0,
            deadline: 0,
            data: Vec::new(),
            parts: [(0, 0); MAX_FRAGS],
        }
    }

    fn start(&mut self, first_seq: u32, cnt: u8, deadline: Micros) {
        self.active = true;
        self.first_seq = first_seq;
        self.cnt = cnt;
        self.received = 0;
        self.deadline = deadline;
        self.data.clear();
    }

    fn live(&self, now: Micros) -> bool {
        self.active && self.deadline > now
    }
}

/// Bounded set of in-progress reassemblies. When full, the group closest to
/// its deadline is evicted.
pub struct Reassembler {
    groups: Vec<Group>,
    out: Vec<u8>,
    timeout: Micros,
}

impl Reassembler {
    pub fn new(capacity: usize) -> Self {
        Self::with_timeout(capacity, REASSEMBLY_TIMEOUT)
    }

    pub fn with_timeout(capacity: usize, timeout: Micros) -> Self {
        assert!(capacity > 0);
        Self {
            groups: (0..capacity).map(|_| Group::empty()).collect(),
            out: Vec::new(),
            timeout,
        }
    }

    /// Adds a fragment; returns the whole packet once all fragments are in.
    pub fn push(
        &mut self,
        now: Micros,
        seq: u32,
        idx: u8,
        cnt: u8,
        data: &[u8],
    ) -> Result<Option<&[u8]>, Error> {
        if cnt == 0 || usize::from(cnt) > MAX_FRAGS || idx >= cnt {
            return Err(Error::MalformedFragment);
        }
        let first = seq.wrapping_sub(u32::from(idx));
        let slot = self.find_or_claim(now, first, cnt);
        let g = &mut self.groups[slot];

        let bit = 1u64 << idx;
        if g.received & bit != 0 {
            return Ok(None);
        }
        if g.data.len() + data.len() > MAX_REASSEMBLED {
            g.active = false;
            return Err(Error::MalformedFragment);
        }
        g.parts[usize::from(idx)] = (g.data.len() as u32, data.len() as u32);
        g.data.extend_from_slice(data);
        g.received |= bit;
        if g.received != full_mask(cnt) {
            return Ok(None);
        }

        self.out.clear();
        for &(off, len) in &g.parts[..usize::from(cnt)] {
            let (off, len) = (off as usize, len as usize);
            self.out.extend_from_slice(&g.data[off..off + len]);
        }
        g.active = false;
        Ok(Some(&self.out))
    }

    /// Drops groups whose deadline has passed.
    pub fn expire(&mut self, now: Micros) {
        for g in &mut self.groups {
            if !g.live(now) {
                g.active = false;
            }
        }
    }

    pub fn pending(&self) -> usize {
        self.groups.iter().filter(|g| g.active).count()
    }

    fn find_or_claim(&mut self, now: Micros, first: u32, cnt: u8) -> usize {
        if let Some(i) = self
            .groups
            .iter()
            .position(|g| g.live(now) && g.first_seq == first && g.cnt == cnt)
        {
            return i;
        }
        let i = self
            .groups
            .iter()
            .position(|g| !g.live(now))
            .unwrap_or_else(|| {
                let (i, _) = self
                    .groups
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, g)| g.deadline)
                    .expect("capacity > 0");
                i
            });
        self.groups[i].start(first, cnt, now + self.timeout);
        i
    }
}

fn full_mask(cnt: u8) -> u64 {
    if usize::from(cnt) == MAX_FRAGS {
        u64::MAX
    } else {
        (1u64 << cnt) - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 + 3) as u8).collect()
    }

    #[test]
    fn split_sizes() {
        let p = packet(1500);
        let chunks: Vec<_> = split(&p, 1432).unwrap().collect();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].2.len(), 750);
        assert_eq!(chunks[1].2.len(), 750);

        for (len, max) in [(10, 4), (9, 4), (5, 2), (1, 1), (100, 100), (65535, 1432)] {
            let p = packet(len);
            let chunks: Vec<_> = split(&p, max).unwrap().collect();
            assert_eq!(chunks.len(), len.div_ceil(max), "{len}/{max}");
            assert!(chunks.iter().all(|c| !c.2.is_empty() && c.2.len() <= max));
            assert!(chunks.iter().all(|c| usize::from(c.1) == chunks.len()));
            let joined: Vec<u8> = chunks.iter().flat_map(|c| c.2.iter().copied()).collect();
            assert_eq!(joined, p);
        }
    }

    #[test]
    fn split_rejects_bad_input() {
        assert!(split(&[], 10).is_err());
        assert!(split(&[1], 0).is_err());
        assert!(split(&packet(65 * 10), 10).is_err());
    }

    #[test]
    fn reassemble_out_of_order() {
        let p = packet(5000);
        let chunks: Vec<_> = split(&p, 1000).unwrap().collect();
        let mut r = Reassembler::new(4);
        let order = [3, 0, 4, 2, 1];
        for (n, &i) in order.iter().enumerate() {
            let (idx, cnt, data) = chunks[i];
            let got = r.push(0, 100 + u32::from(idx), idx, cnt, data).unwrap();
            if n + 1 < order.len() {
                assert!(got.is_none());
            } else {
                assert_eq!(got.unwrap(), &p[..]);
            }
        }
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn duplicate_fragment_ignored() {
        let p = packet(300);
        let chunks: Vec<_> = split(&p, 100).unwrap().collect();
        let mut r = Reassembler::new(2);
        let (idx, cnt, d) = chunks[0];
        assert!(r.push(0, 10, idx, cnt, d).unwrap().is_none());
        assert!(r.push(0, 10, idx, cnt, d).unwrap().is_none());
        let (idx, cnt, d) = chunks[1];
        assert!(r.push(0, 11, idx, cnt, d).unwrap().is_none());
        let (idx, cnt, d) = chunks[2];
        assert_eq!(r.push(0, 12, idx, cnt, d).unwrap().unwrap(), &p[..]);
    }

    #[test]
    fn sequence_wraparound() {
        let p = packet(250);
        let mut r = Reassembler::new(1);
        let mut out = None;
        for (idx, cnt, d) in split(&p, 100).unwrap() {
            let seq = u32::MAX.wrapping_add(u32::from(idx));
            out = r.push(0, seq, idx, cnt, d).unwrap().map(<[u8]>::to_vec);
        }
        assert_eq!(out.unwrap(), p);
    }

    #[test]
    fn timeout_discards_partial() {
        let p = packet(200);
        let chunks: Vec<_> = split(&p, 100).unwrap().collect();
        let mut r = Reassembler::with_timeout(2, 1000);
        r.push(0, 0, 0, 2, chunks[0].2).unwrap();
        assert_eq!(r.pending(), 1);
        r.expire(1000);
        assert_eq!(r.pending(), 0);
        // The late second half starts a new group rather than completing.
        assert!(r.push(1000, 1, 1, 2, chunks[1].2).unwrap().is_none());
    }

    #[test]
    fn eviction_when_full() {
        let mut r = Reassembler::with_timeout(2, 1000);
        r.push(0, 0, 0, 2, &[1]).unwrap();
        r.push(10, 10, 0, 2, &[2]).unwrap();
        // Third group evicts the oldest (first_seq 0); the others survive.
        r.push(20, 20, 0, 2, &[3]).unwrap();
        assert_eq!(r.push(20, 11, 1, 2, &[4]).unwrap().unwrap(), &[2, 4]);
        assert_eq!(r.push(20, 21, 1, 2, &[5]).unwrap().unwrap(), &[3, 5]);
        assert!(r.push(20, 1, 1, 2, &[9]).unwrap().is_none());
    }

    #[test]
    fn rejects_malformed() {
        let mut r = Reassembler::new(1);
        assert!(r.push(0, 0, 2, 2, &[1]).is_err());
        assert!(r.push(0, 0, 0, 0, &[1]).is_err());
        assert!(r.push(0, 0, 0, 65, &[1]).is_err());
    }

    #[test]
    fn max_fragment_count() {
        let p = packet(64 * 3);
        let mut r = Reassembler::new(1);
        let mut out = None;
        for (idx, cnt, d) in split(&p, 3).unwrap() {
            assert_eq!(cnt, 64);
            out = r
                .push(0, u32::from(idx), idx, cnt, d)
                .unwrap()
                .map(<[u8]>::to_vec);
        }
        assert_eq!(out.unwrap(), p);
    }
}
