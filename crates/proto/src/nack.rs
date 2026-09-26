//! NACK fast retransmission, receiving side (SPEC §4.5): notes the data
//! sequence numbers skipped by each new highest one and, once a gap has
//! stayed open for the wait (copies and cross-path reordering had their
//! chance), reports it for a `NACK`.

use std::collections::VecDeque;

use crate::Micros;
use crate::frame::NackRange;
use crate::timing::MS;

/// Shortest wait before a gap is reported.
pub const MIN_WAIT: Micros = 5 * MS;
/// A jump over more sequence numbers than this is not a loss worth
/// recovering one by one (the sender was idle, or restarted numbering).
pub const MAX_GAP: u32 = 64;
/// Gaps waiting for their deadline, at most.
const CAPACITY: usize = 1024;
/// Ranges per NACK frame, at most.
pub const MAX_RANGES: usize = 32;

/// How long a gap may stay open: `max(2 × copy_delay, MIN_WAIT)`.
pub fn wait_for(copy_delay: Micros) -> Micros {
    (2 * copy_delay).max(MIN_WAIT)
}

#[derive(Debug, Clone, Default)]
pub struct GapTracker {
    highest: Option<u32>,
    /// Missing sequence numbers with the time they are due for a NACK, in
    /// order.
    missing: VecDeque<(u32, Micros)>,
}

impl GapTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// A data frame with `seq` arrived for the first time.
    pub fn on_new(&mut self, now: Micros, seq: u32, wait: Micros) {
        let Some(h) = self.highest else {
            self.highest = Some(seq);
            return;
        };
        let ahead = seq.wrapping_sub(h);
        if ahead == 0 || ahead > u32::MAX / 2 {
            return; // at or behind the highest: fills a gap, or a late copy
        }
        if ahead > 1 && ahead - 1 <= MAX_GAP {
            let due = now + wait;
            for i in 1..ahead {
                if self.missing.len() == CAPACITY {
                    self.missing.pop_front();
                }
                self.missing.push_back((h.wrapping_add(i), due));
            }
        }
        self.highest = Some(seq);
    }

    /// Collects the gaps due by `now` that are still open (`is_missing`),
    /// merged into ranges, at most [`MAX_RANGES`]; the rest wait for the
    /// next call. Each sequence number is reported once.
    pub fn due(&mut self, now: Micros, is_missing: impl Fn(u32) -> bool, out: &mut Vec<NackRange>) {
        out.clear();
        while let Some(&(seq, due)) = self.missing.front() {
            if due > now {
                break;
            }
            if !is_missing(seq) {
                self.missing.pop_front();
                continue;
            }
            let extends = out.last().is_some_and(|r| {
                r.start.wrapping_add(u32::from(r.count)) == seq && r.count < u16::MAX
            });
            if extends {
                out.last_mut().expect("checked").count += 1;
            } else if out.len() == MAX_RANGES {
                break;
            } else {
                out.push(NackRange {
                    start: seq,
                    count: 1,
                });
            }
            self.missing.pop_front();
        }
    }

    /// When the earliest open gap is due.
    pub fn next_due(&self) -> Option<Micros> {
        self.missing.front().map(|m| m.1)
    }

    pub fn pending(&self) -> usize {
        self.missing.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn ranges(v: &[NackRange]) -> Vec<(u32, u16)> {
        v.iter().map(|r| (r.start, r.count)).collect()
    }

    #[test]
    fn wait_is_twice_the_copy_delay_or_the_minimum() {
        assert_eq!(wait_for(0), MIN_WAIT);
        assert_eq!(wait_for(2 * MS), MIN_WAIT);
        assert_eq!(wait_for(4 * MS), 8 * MS);
    }

    #[test]
    fn open_gaps_are_reported_once_after_the_wait() {
        let mut g = GapTracker::new();
        let mut got = HashSet::new();
        for s in [10, 11, 14, 15, 19] {
            g.on_new(0, s, MIN_WAIT);
            got.insert(s);
        }
        assert_eq!(g.pending(), 5, "12, 13 and 16..=18");
        let mut out = vec![];
        g.due(MIN_WAIT - 1, |s| !got.contains(&s), &mut out);
        assert!(out.is_empty());
        // 13 turns up late (reordered or a copy).
        g.on_new(1, 13, MIN_WAIT);
        got.insert(13);
        g.due(MIN_WAIT, |s| !got.contains(&s), &mut out);
        assert_eq!(ranges(&out), vec![(12, 1), (16, 3)]);
        assert_eq!(g.pending(), 0);
        g.due(10 * MIN_WAIT, |s| !got.contains(&s), &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn large_jumps_and_old_numbers_are_ignored() {
        let mut g = GapTracker::new();
        g.on_new(0, 100, MIN_WAIT);
        g.on_new(0, 100 + MAX_GAP + 2, MIN_WAIT);
        assert_eq!(g.pending(), 0);
        g.on_new(0, 50, MIN_WAIT);
        assert_eq!(g.pending(), 0);
        g.on_new(0, 100 + MAX_GAP + 3, MIN_WAIT);
        assert_eq!(g.pending(), 0);
    }

    #[test]
    fn wraps_around() {
        let mut g = GapTracker::new();
        g.on_new(0, u32::MAX - 1, MIN_WAIT);
        g.on_new(0, 1, MIN_WAIT);
        let mut out = vec![];
        g.due(MIN_WAIT, |_| true, &mut out);
        assert_eq!(ranges(&out), vec![(u32::MAX, 2)]);
    }

    #[test]
    fn at_most_max_ranges_per_call() {
        let mut g = GapTracker::new();
        let mut s = 0;
        g.on_new(0, s, MIN_WAIT);
        for _ in 0..MAX_RANGES + 5 {
            s += 2;
            g.on_new(0, s, MIN_WAIT);
        }
        let mut out = vec![];
        g.due(MIN_WAIT, |_| true, &mut out);
        assert_eq!(out.len(), MAX_RANGES);
        g.due(MIN_WAIT, |_| true, &mut out);
        assert_eq!(out.len(), 5);
    }
}
