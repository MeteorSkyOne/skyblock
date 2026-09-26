//! Sliding bitmap window over a 64-bit counter (RFC 6479 style). Used
//! directly as the packet-number replay window.

/// Counters older than `top - WINDOW` are rejected.
pub const WINDOW: u64 = 4096;

const WORD_BITS: u64 = 64;
// One extra word so the word holding `top` never aliases the oldest one.
const WORDS: usize = (WINDOW / WORD_BITS) as usize + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seen {
    New,
    Duplicate,
    TooOld,
}

#[derive(Clone)]
pub struct SlidingWindow {
    top: Option<u64>,
    bits: [u64; WORDS],
}

pub type ReplayWindow = SlidingWindow;

impl Default for SlidingWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl SlidingWindow {
    pub fn new() -> Self {
        Self {
            top: None,
            bits: [0; WORDS],
        }
    }

    /// Highest counter accepted so far.
    pub fn top(&self) -> Option<u64> {
        self.top
    }

    /// Classifies `n` without recording it. Use before authenticating a
    /// packet, then call [`insert`](Self::insert) once it is authentic.
    pub fn check(&self, n: u64) -> Seen {
        let Some(top) = self.top else {
            return Seen::New;
        };
        if n > top {
            return Seen::New;
        }
        if top - n >= WINDOW {
            return Seen::TooOld;
        }
        let (word, mask) = Self::locate(n);
        if self.bits[word] & mask == 0 {
            Seen::New
        } else {
            Seen::Duplicate
        }
    }

    /// Records `n` if it is new; returns the classification either way.
    pub fn insert(&mut self, n: u64) -> Seen {
        let seen = self.check(n);
        if seen != Seen::New {
            return seen;
        }
        match self.top {
            Some(top) if n <= top => {}
            _ => {
                // Clear the words that slide into the window. On the first
                // insert every word is already zero.
                if let Some(top) = self.top {
                    let (cur, new) = (top / WORD_BITS, n / WORD_BITS);
                    let steps = (new - cur).min(WORDS as u64);
                    for i in 1..=steps {
                        self.bits[((cur + i) % WORDS as u64) as usize] = 0;
                    }
                }
                self.top = Some(n);
            }
        }
        let (word, mask) = Self::locate(n);
        self.bits[word] |= mask;
        Seen::New
    }

    fn locate(n: u64) -> (usize, u64) {
        (
            ((n / WORD_BITS) % WORDS as u64) as usize,
            1 << (n % WORD_BITS),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_insert_is_new() {
        let mut w = SlidingWindow::new();
        assert_eq!(w.check(12345), Seen::New);
        assert_eq!(w.insert(12345), Seen::New);
        assert_eq!(w.insert(12345), Seen::Duplicate);
        assert_eq!(w.top(), Some(12345));
    }

    #[test]
    fn in_order_and_duplicates() {
        let mut w = SlidingWindow::new();
        for n in 0..10_000 {
            assert_eq!(w.insert(n), Seen::New);
            assert_eq!(w.insert(n), Seen::Duplicate);
        }
    }

    #[test]
    fn reorder_within_window() {
        let mut w = SlidingWindow::new();
        assert_eq!(w.insert(5000), Seen::New);
        for n in (5000 - WINDOW + 1..5000).rev() {
            assert_eq!(w.insert(n), Seen::New, "{n}");
        }
        assert_eq!(w.insert(5000 - WINDOW), Seen::TooOld);
        for n in 5000 - WINDOW + 1..=5000 {
            assert_eq!(w.check(n), Seen::Duplicate);
        }
    }

    #[test]
    fn check_does_not_record() {
        let mut w = SlidingWindow::new();
        w.insert(10);
        assert_eq!(w.check(8), Seen::New);
        assert_eq!(w.check(8), Seen::New);
        assert_eq!(w.insert(8), Seen::New);
        assert_eq!(w.check(8), Seen::Duplicate);
    }

    #[test]
    fn large_jump_clears_everything() {
        let mut w = SlidingWindow::new();
        for n in 0..100 {
            w.insert(n);
        }
        w.insert(1_000_000);
        // Old bits must not leak into the words now covering new counters.
        for n in 1_000_000 - WINDOW + 1..1_000_000 {
            assert_eq!(w.check(n), Seen::New, "{n}");
        }
        assert_eq!(w.check(99), Seen::TooOld);
    }

    #[test]
    fn slides_across_word_boundaries() {
        let mut w = SlidingWindow::new();
        // Insert every third counter, then verify exact membership.
        let mut n = 0u64;
        while n < 3 * WINDOW {
            w.insert(n);
            n += 3;
        }
        let top = w.top().unwrap();
        for m in top.saturating_sub(WINDOW - 1)..=top {
            let expected = if m % 3 == 0 {
                Seen::Duplicate
            } else {
                Seen::New
            };
            assert_eq!(w.check(m), expected, "{m}");
        }
    }

    #[test]
    fn matches_reference_model() {
        use std::collections::BTreeSet;
        let mut w = SlidingWindow::new();
        let mut set = BTreeSet::new();
        let mut top: Option<u64> = None;
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut base = 0u64;
        for _ in 0..50_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            // Mostly forward with jitter, occasional big jumps.
            base += x % 4;
            if x % 997 == 0 {
                base += 10_000;
            }
            let n = base.saturating_sub((x >> 20) % 6000);
            let expected = match top {
                Some(t) if n <= t && t - n >= WINDOW => Seen::TooOld,
                _ if set.contains(&n) => Seen::Duplicate,
                _ => Seen::New,
            };
            assert_eq!(w.insert(n), expected, "n={n} top={top:?}");
            if expected == Seen::New {
                set.insert(n);
                top = Some(top.map_or(n, |t| t.max(n)));
            }
        }
    }
}
