//! Data-sequence dedup window (SPEC §3.10). Sequence numbers are 32-bit and
//! wrap; they are unwrapped against the highest one seen and tracked in a
//! [`SlidingWindow`].

use crate::replay::{Seen, SlidingWindow};

// Offset for the first unwrapped value so that sequence numbers slightly
// older than the first one received never underflow.
const BASE: u64 = 1 << 32;

#[derive(Clone, Default)]
pub struct DedupWindow {
    win: SlidingWindow,
}

impl DedupWindow {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check(&self, seq: u32) -> Seen {
        self.win.check(self.unwrap(seq))
    }

    pub fn insert(&mut self, seq: u32) -> Seen {
        let n = self.unwrap(seq);
        self.win.insert(n)
    }

    /// Maps `seq` to the 64-bit value closest to the current top
    /// (RFC 1982 serial-number arithmetic).
    fn unwrap(&self, seq: u32) -> u64 {
        match self.win.top() {
            None => BASE + u64::from(seq),
            Some(top) => {
                let delta = i64::from(seq.wrapping_sub(top as u32) as i32);
                top.wrapping_add_signed(delta)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay::WINDOW;

    #[test]
    fn dedups_across_wraparound() {
        let mut d = DedupWindow::new();
        let start = u32::MAX - 100;
        for i in 0..300u32 {
            let s = start.wrapping_add(i);
            assert_eq!(d.insert(s), Seen::New, "{s}");
        }
        for i in 150..300u32 {
            assert_eq!(d.insert(start.wrapping_add(i)), Seen::Duplicate);
        }
    }

    #[test]
    fn older_than_first_is_accepted_within_window() {
        let mut d = DedupWindow::new();
        assert_eq!(d.insert(0), Seen::New);
        assert_eq!(d.insert(u32::MAX), Seen::New);
        assert_eq!(d.insert(u32::MAX - 10), Seen::New);
        assert_eq!(d.insert(u32::MAX - 10), Seen::Duplicate);
    }

    #[test]
    fn too_old() {
        let mut d = DedupWindow::new();
        d.insert(10_000);
        assert_eq!(d.check(10_000 - WINDOW as u32), Seen::TooOld);
        assert_eq!(d.check(10_000 - WINDOW as u32 + 1), Seen::New);
    }

    #[test]
    fn duplicated_stream_passes_each_seq_once() {
        // Two copies per seq, second copy delayed by a few positions.
        let mut d = DedupWindow::new();
        let mut delivered = 0;
        for s in 0..10_000u32 {
            if d.insert(s) == Seen::New {
                delivered += 1;
            }
            if s >= 3 && d.insert(s - 3) == Seen::New {
                delivered += 1;
            }
        }
        assert_eq!(delivered, 10_000);
    }
}
