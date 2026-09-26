//! Flow classification: each side labels the flows it sends as
//! GAME (redundant copies) or BULK (single copy on a fixed path) by rate.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::Ipv4Addr;

use crate::Micros;
use crate::ip::Ipv4Packet;
use crate::timing::{BULK_EXIT_HOLD, FLOW_IDLE, FLOW_WINDOW};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Game,
    Bulk,
}

/// A flow's 5-tuple; ports are 0 for protocols without them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub proto: u8,
    pub src: Ipv4Addr,
    pub sport: u16,
    pub dst: Ipv4Addr,
    pub dport: u16,
}

impl FlowKey {
    pub fn of<B: AsRef<[u8]>>(p: &Ipv4Packet<B>) -> Self {
        let (sport, dport) = p.ports().unwrap_or((0, 0));
        Self {
            proto: p.protocol(),
            src: p.src(),
            sport,
            dst: p.dst(),
            dport,
        }
    }
}

/// What the classifier says about a packet's flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flow {
    pub class: Class,
    /// Stable per-flow hash, for pinning bulk flows to one path.
    pub hash: u64,
}

struct State {
    class: Class,
    hash: u64,
    window_start: Micros,
    window_bytes: u64,
    /// Start of the current run of slow windows while BULK.
    slow_since: Option<Micros>,
    last_seen: Micros,
}

pub struct FlowClassifier {
    flows: HashMap<FlowKey, State>,
    enter_kbps: u64,
    exit_kbps: u64,
}

impl FlowClassifier {
    pub fn new(enter_kbps: u32, exit_kbps: u32) -> Self {
        Self {
            flows: HashMap::new(),
            enter_kbps: u64::from(enter_kbps),
            exit_kbps: u64::from(exit_kbps),
        }
    }

    pub fn set_thresholds(&mut self, enter_kbps: u32, exit_kbps: u32) {
        self.enter_kbps = u64::from(enter_kbps);
        self.exit_kbps = u64::from(exit_kbps);
    }

    /// Accounts `bytes` to `key`'s flow and returns its class. A flow turns
    /// BULK after a one-second window above the enter rate, and GAME again
    /// after windows below the exit rate spanning `BULK_EXIT_HOLD`.
    pub fn classify(&mut self, now: Micros, key: FlowKey, bytes: usize) -> Flow {
        let f = self.flows.entry(key).or_insert_with(|| {
            let mut h = DefaultHasher::new();
            key.hash(&mut h);
            State {
                class: Class::Game,
                hash: h.finish(),
                window_start: now,
                window_bytes: 0,
                slow_since: None,
                last_seen: now,
            }
        });
        f.last_seen = now;
        let elapsed = now.saturating_sub(f.window_start);
        if elapsed >= FLOW_WINDOW {
            // bits per millisecond == kbit/s
            let kbps = f.window_bytes * 8 * 1000 / elapsed;
            match f.class {
                Class::Game if kbps > self.enter_kbps => {
                    f.class = Class::Bulk;
                    f.slow_since = None;
                }
                Class::Bulk if kbps < self.exit_kbps => {
                    let since = *f.slow_since.get_or_insert(f.window_start);
                    if now - since >= BULK_EXIT_HOLD {
                        f.class = Class::Game;
                        f.slow_since = None;
                    }
                }
                Class::Bulk => f.slow_since = None,
                Class::Game => {}
            }
            f.window_start = now;
            f.window_bytes = 0;
        }
        f.window_bytes += bytes as u64;
        Flow {
            class: f.class,
            hash: f.hash,
        }
    }

    /// Forgets flows idle for `FLOW_IDLE`.
    pub fn expire(&mut self, now: Micros) {
        self.flows
            .retain(|_, f| now.saturating_sub(f.last_seen) < FLOW_IDLE);
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn bulk_count(&self) -> usize {
        self.flows
            .values()
            .filter(|f| f.class == Class::Bulk)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timing::{MS, SECOND};

    fn key(port: u16) -> FlowKey {
        FlowKey {
            proto: 17,
            src: Ipv4Addr::new(10, 77, 0, 2),
            sport: port,
            dst: Ipv4Addr::new(203, 0, 113, 9),
            dport: 27015,
        }
    }

    /// Feeds `kbps` worth of 1000-byte packets for `dur`, starting at `t`.
    fn feed(c: &mut FlowClassifier, k: FlowKey, t: Micros, dur: Micros, kbps: u64) -> Class {
        let pps = (kbps * 1000 / 8 / 1000).max(1);
        let gap = SECOND / pps;
        let mut now = t;
        let mut class = Class::Game;
        while now < t + dur {
            class = c.classify(now, k, 1000).class;
            now += gap;
        }
        class
    }

    #[test]
    fn game_rate_stays_game() {
        let mut c = FlowClassifier::new(2000, 1000);
        // 128 pps x 200 B ~ 200 kbps.
        for i in 0..128 * 10 {
            let f = c.classify(i * SECOND / 128, key(1), 200);
            assert_eq!(f.class, Class::Game);
        }
    }

    #[test]
    fn fast_flow_turns_bulk_after_a_window() {
        let mut c = FlowClassifier::new(2000, 1000);
        assert_eq!(feed(&mut c, key(1), 0, 900 * MS, 8000), Class::Game);
        assert_eq!(feed(&mut c, key(1), 900 * MS, 300 * MS, 8000), Class::Bulk);
        assert_eq!(c.bulk_count(), 1);
    }

    #[test]
    fn bulk_exit_needs_sustained_slow_rate() {
        let mut c = FlowClassifier::new(2000, 1000);
        feed(&mut c, key(1), 0, 2 * SECOND, 8000);
        // Slow for 3 s: still bulk (hysteresis).
        assert_eq!(
            feed(&mut c, key(1), 2 * SECOND, 3 * SECOND, 100),
            Class::Bulk
        );
        // A burst in between restarts the slow run.
        feed(&mut c, key(1), 5 * SECOND, 1100 * MS, 8000);
        assert_eq!(
            feed(&mut c, key(1), 6100 * MS, 4 * SECOND, 100),
            Class::Bulk
        );
        assert_eq!(
            feed(&mut c, key(1), 10100 * MS, 3 * SECOND, 100),
            Class::Game
        );
    }

    #[test]
    fn between_thresholds_keeps_class() {
        let mut c = FlowClassifier::new(2000, 1000);
        assert_eq!(feed(&mut c, key(1), 0, 5 * SECOND, 1500), Class::Game);
        feed(&mut c, key(2), 0, 2 * SECOND, 8000);
        assert_eq!(
            feed(&mut c, key(2), 2 * SECOND, 10 * SECOND, 1500),
            Class::Bulk
        );
    }

    #[test]
    fn idle_bulk_flow_resumes_as_game() {
        let mut c = FlowClassifier::new(2000, 1000);
        feed(&mut c, key(1), 0, 2 * SECOND, 8000);
        let f = c.classify(30 * SECOND, key(1), 100);
        assert_eq!(f.class, Class::Game);
    }

    #[test]
    fn flows_are_separate_and_expire() {
        let mut c = FlowClassifier::new(2000, 1000);
        feed(&mut c, key(1), 0, 2 * SECOND, 8000);
        let g = c.classify(2 * SECOND, key(2), 100);
        assert_eq!(g.class, Class::Game);
        assert_ne!(
            g.hash,
            c.classify(2 * SECOND, key(1), 100).hash,
            "different flows hash differently"
        );
        assert_eq!(c.len(), 2);
        c.expire(2 * SECOND + FLOW_IDLE);
        assert!(c.is_empty());
    }
}
