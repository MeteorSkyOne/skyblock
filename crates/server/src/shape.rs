//! Downlink shaping of bulk flows: a token bucket below the
//! client's bottleneck with a queue in front of it. A download then queues
//! here, where game packets pass it by, instead of in the bottleneck's
//! buffer (the home line), where they would wait behind it.

use std::collections::VecDeque;

use skyblock_proto::Micros;
use skyblock_proto::timing::{MS, SECOND};

/// Bucket depth: this much time at the rate (at least two full packets).
const BURST: Micros = 5 * MS;
/// Queue limit: this much time at the rate, or two round trips if longer;
/// arrivals beyond it are dropped, which is what tells the sender's TCP to
/// slow down. Shorter than about one round trip, TCP backs off below the
/// rate and never fills it again (real line, 160ms RTT: 40 Mbps shaping
/// with a 50ms queue gave 29 Mbps). Game packets skip the queue, so its
/// length costs only the download itself.
const MIN_QUEUE_TIME: Micros = 50 * MS;
const MIN_BURST_BYTES: u64 = 3000;
const MIN_QUEUE_BYTES: usize = 64 * 1024;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ShapeStats {
    pub passed: u64,
    pub queued: u64,
    pub dropped: u64,
}

pub struct Shaper {
    /// Bytes per second.
    rate: u64,
    burst: u64,
    /// Tokens in bytes × `SECOND` (keeps sub-byte refills exact).
    tokens: u64,
    last: Micros,
    /// Queued packets with their flow hash (for the bulk path choice).
    queue: VecDeque<(u64, Vec<u8>)>,
    queued_bytes: usize,
    limit_bytes: usize,
    /// Buffers of sent packets, reused.
    spare: Vec<Vec<u8>>,
    pub stats: ShapeStats,
}

impl Shaper {
    pub fn new(now: Micros, rate_kbps: u32) -> Self {
        let rate = u64::from(rate_kbps.max(1)) * 1000 / 8;
        let burst = (rate * BURST / SECOND).max(MIN_BURST_BYTES);
        Self {
            rate,
            burst,
            tokens: burst * SECOND,
            last: now,
            queue: VecDeque::new(),
            queued_bytes: 0,
            limit_bytes: Self::limit(rate, 0),
            spare: Vec::new(),
            stats: ShapeStats::default(),
        }
    }

    pub fn rate_kbps(&self) -> u64 {
        self.rate * 8 / 1000
    }

    fn limit(rate: u64, rtt: Micros) -> usize {
        ((rate * (2 * rtt).max(MIN_QUEUE_TIME) / SECOND) as usize).max(MIN_QUEUE_BYTES)
    }

    /// Sizes the queue for the session's round-trip time.
    pub fn set_rtt(&mut self, rtt: Micros) {
        self.limit_bytes = Self::limit(self.rate, rtt);
    }

    pub fn limit_bytes(&self) -> usize {
        self.limit_bytes
    }

    fn refill(&mut self, now: Micros) {
        let dt = now.saturating_sub(self.last);
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.burst * SECOND);
    }

    fn take(&mut self, len: usize) -> bool {
        let need = len as u64 * SECOND;
        if self.tokens >= need {
            self.tokens -= need;
            true
        } else {
            false
        }
    }

    /// A bulk packet to send: `true` when it may go now, otherwise it has
    /// been queued (or dropped, queue full).
    pub fn offer(&mut self, now: Micros, hash: u64, pkt: &[u8]) -> bool {
        self.refill(now);
        if self.queue.is_empty() && self.take(pkt.len()) {
            self.stats.passed += 1;
            return true;
        }
        if self.queued_bytes + pkt.len() > self.limit_bytes {
            self.stats.dropped += 1;
            return false;
        }
        let mut buf = self.spare.pop().unwrap_or_default();
        buf.clear();
        buf.extend_from_slice(pkt);
        self.queued_bytes += buf.len();
        self.queue.push_back((hash, buf));
        self.stats.queued += 1;
        false
    }

    /// Hands the queued packets the bucket allows by `now` to `send`.
    pub fn poll(&mut self, now: Micros, mut send: impl FnMut(u64, &[u8])) {
        self.refill(now);
        while let Some(len) = self.queue.front().map(|q| q.1.len()) {
            if !self.take(len) {
                break;
            }
            let (hash, buf) = self.queue.pop_front().expect("front exists");
            self.queued_bytes -= len;
            send(hash, &buf);
            self.stats.passed += 1;
            if self.spare.len() < 64 {
                self.spare.push(buf);
            }
        }
    }

    /// When the head of the queue can go.
    pub fn next_due(&self) -> Option<Micros> {
        let len = self.queue.front()?.1.len() as u64 * SECOND;
        let missing = len.saturating_sub(self.tokens);
        Some(self.last + missing.div_ceil(self.rate))
    }

    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holds_the_rate_over_time() {
        // 8 Mbps = 1 MB/s; offer 1500B packets at 2 MB/s for 1s.
        let mut s = Shaper::new(0, 8000);
        let mut sent = 0usize;
        let pkt = [0u8; 1500];
        let mut t = 0;
        while t < SECOND {
            if s.offer(t, 0, &pkt) {
                sent += pkt.len();
            }
            s.poll(t, |_, p| sent += p.len());
            t += 750;
        }
        // 1 MB plus the initial bucket, within two packets.
        let expected = 1_000_000 + s.burst as usize;
        assert!(
            sent.abs_diff(expected) <= 3000,
            "sent {sent}, expected {expected}"
        );
        assert!(
            s.stats.dropped > 0,
            "the excess did not fit in 50ms of queue"
        );
        assert!(s.queued_bytes() <= s.limit_bytes);
    }

    #[test]
    fn passes_directly_while_under_the_rate() {
        let mut s = Shaper::new(0, 80_000);
        for i in 0..100 {
            assert!(s.offer(i * MS, 0, &[0u8; 1000]), "packet {i}");
        }
        assert_eq!(s.stats.queued, 0);
        assert_eq!(s.next_due(), None);
    }

    #[test]
    fn next_due_is_when_the_head_fits() {
        let mut s = Shaper::new(0, 8000); // 1 byte per µs
        while s.offer(0, 0, &[0u8; 1500]) {}
        let due = s.next_due().unwrap();
        assert!((1..=1500).contains(&due), "{due}");
        let mut out = 0;
        s.poll(due - 1, |_, _| out += 1);
        assert_eq!(out, 0);
        s.poll(due, |_, _| out += 1);
        assert_eq!(out, 1);
    }

    #[test]
    fn queue_grows_with_the_round_trip() {
        let mut s = Shaper::new(0, 40_000); // 5 MB/s
        assert_eq!(s.limit_bytes(), 250_000, "50ms");
        s.set_rtt(160 * MS);
        assert_eq!(s.limit_bytes(), 1_600_000, "two round trips");
        s.set_rtt(10 * MS);
        assert_eq!(s.limit_bytes(), 250_000);
    }

    #[test]
    fn queue_keeps_order() {
        let mut s = Shaper::new(0, 8000);
        while s.offer(0, 9, &[0u8; 1500]) {}
        for i in 1..=3u8 {
            assert!(!s.offer(0, u64::from(i), &[i; 100]));
        }
        let mut got = vec![];
        s.poll(SECOND, |h, p| got.push((h, p[0])));
        assert_eq!(got, vec![(9, 0), (1, 1), (2, 2), (3, 3)]);
    }
}
