//! Adaptive copy count (SPEC §4.5): the number of copies for one direction
//! follows that direction's raw packet loss over the last 10s.
//!
//! With independent losses at rate `p`, `k` copies lose an item with
//! probability `p^k`; the count is the smallest in `[floor, ceil]` that
//! brings this under [`TARGET_LOSS`]. More copies take effect at once;
//! fewer only after the lower count has met the target for [`HOLD_DOWN`],
//! so a loss burst does not make the count flap.

use std::collections::VecDeque;

use crate::Micros;
use crate::timing::SECOND;

/// Effective loss the copy count aims for.
pub const TARGET_LOSS: f64 = 1e-4;
/// Raw loss is measured over this window.
pub const WINDOW: Micros = 10 * SECOND;
/// How long a lower count must suffice before it is used.
pub const HOLD_DOWN: Micros = 10 * SECOND;
/// With fewer packets than this in the window the count stays as it is.
pub const MIN_SAMPLE: u64 = 200;

#[derive(Debug, Clone)]
pub struct AdaptiveCopies {
    floor: u8,
    ceil: u8,
    current: u8,
    /// `(when, packets sent, packets lost)` per interval; `lost` may be
    /// negative (packets in flight at one end of an interval).
    samples: VecDeque<(Micros, u64, i64)>,
    /// A lower count the loss allows, and since when (restarts whenever
    /// that count changes).
    lower: Option<(u8, Micros)>,
}

impl AdaptiveCopies {
    /// Starts at `floor`; `ceil == floor` pins the count.
    pub fn new(floor: u8, ceil: u8) -> Self {
        let floor = floor.max(1);
        Self {
            floor,
            ceil: ceil.max(floor),
            current: floor,
            samples: VecDeque::new(),
            lower: None,
        }
    }

    pub fn current(&self) -> u8 {
        self.current
    }

    pub fn ceil(&self) -> u8 {
        self.ceil
    }

    /// Raw loss over the window, if it holds enough packets.
    pub fn loss(&self) -> Option<f64> {
        let sent: u64 = self.samples.iter().map(|s| s.1).sum();
        let lost: i64 = self.samples.iter().map(|s| s.2).sum();
        (sent >= MIN_SAMPLE).then(|| (lost.max(0) as f64 / sent as f64).min(1.0))
    }

    /// Adds one interval's counts and returns the copy count to use.
    pub fn update(&mut self, now: Micros, sent: u64, lost: i64) -> u8 {
        self.samples.push_back((now, sent, lost));
        while self
            .samples
            .front()
            .is_some_and(|s| now.saturating_sub(s.0) > WINDOW)
        {
            self.samples.pop_front();
        }
        let Some(p) = self.loss() else {
            return self.current;
        };
        let want = needed(p, self.floor, self.ceil);
        if want >= self.current {
            self.current = want;
            self.lower = None;
            return self.current;
        }
        match self.lower {
            Some((w, since)) if w == want => {
                if now.saturating_sub(since) >= HOLD_DOWN {
                    self.current = want;
                    self.lower = None;
                }
            }
            _ => self.lower = Some((want, now)),
        }
        self.current
    }
}

/// The smallest count in `[floor, ceil]` with `p^k <= TARGET_LOSS`.
fn needed(p: f64, floor: u8, ceil: u8) -> u8 {
    (floor..=ceil)
        .find(|&k| p.powi(i32::from(k)) <= TARGET_LOSS)
        .unwrap_or(ceil)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feeds one interval per second at `pps` with `loss` for `secs`.
    fn run(a: &mut AdaptiveCopies, t: &mut Micros, secs: u64, pps: u64, loss: f64) -> u8 {
        let mut c = a.current();
        for _ in 0..secs {
            *t += SECOND;
            c = a.update(*t, pps, (pps as f64 * loss).round() as i64);
        }
        c
    }

    #[test]
    fn needed_counts() {
        assert_eq!(needed(0.0, 1, 3), 1);
        assert_eq!(needed(0.0, 2, 3), 2);
        assert_eq!(needed(0.005, 1, 3), 2);
        assert_eq!(needed(0.01, 2, 3), 2);
        assert_eq!(needed(0.03, 2, 3), 3);
        assert_eq!(needed(0.3, 2, 3), 3, "capped");
    }

    #[test]
    fn rises_at_once_and_falls_after_the_hold() {
        let mut a = AdaptiveCopies::new(2, 3);
        let mut t = 0;
        assert_eq!(run(&mut a, &mut t, 10, 250, 0.0), 2);
        // 5% loss: 3 copies as soon as the window shows it.
        assert_eq!(run(&mut a, &mut t, 1, 250, 0.05), 2, "0.5% over the window");
        assert_eq!(run(&mut a, &mut t, 2, 250, 0.05), 3);
        // Clean again: the window forgets the loss after 10s, then the
        // lower count must hold for another 10s.
        run(&mut a, &mut t, 9, 250, 0.0);
        assert_eq!(a.current(), 3);
        assert_eq!(run(&mut a, &mut t, 9, 250, 0.0), 3);
        assert_eq!(run(&mut a, &mut t, 3, 250, 0.0), 2);
    }

    #[test]
    fn a_short_relapse_restarts_the_hold() {
        let mut a = AdaptiveCopies::new(1, 3);
        let mut t = 0;
        run(&mut a, &mut t, 5, 250, 0.05);
        assert_eq!(a.current(), 3);
        run(&mut a, &mut t, 15, 250, 0.0);
        run(&mut a, &mut t, 1, 250, 0.05);
        assert_eq!(run(&mut a, &mut t, 9, 250, 0.0), 3);
    }

    #[test]
    fn too_few_packets_keep_the_count() {
        let mut a = AdaptiveCopies::new(2, 3);
        let mut t = 0;
        assert_eq!(run(&mut a, &mut t, 5, 10, 0.5), 2);
        assert_eq!(a.loss(), None);
    }

    #[test]
    fn negative_samples_offset_positive_ones() {
        let mut a = AdaptiveCopies::new(1, 3);
        a.update(SECOND, 500, -6);
        a.update(2 * SECOND, 500, 6);
        assert_eq!(a.loss(), Some(0.0));
        assert_eq!(a.current(), 1);
    }

    #[test]
    fn pinned_when_floor_equals_ceil() {
        let mut a = AdaptiveCopies::new(2, 2);
        let mut t = 0;
        assert_eq!(run(&mut a, &mut t, 10, 250, 0.2), 2);
    }
}
