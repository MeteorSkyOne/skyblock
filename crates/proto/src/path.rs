//! Path quality and ranking (SPEC §3.8, §4.4). Both sides count packets
//! per path and exchange the counters in `STATS`; loss towards the peer
//! follows from the peer's receive count, loss from the peer from its send
//! count. Paths are ranked by `srtt + 2 × rttvar + LOSS_PENALTY × loss`.

use crate::Micros;
use crate::frame::MAX_PATHS;
use crate::timing::{JITTER_WEIGHT, LOSS_PENALTY, PATH_DOWN, PATH_DOWN_IDLE, PATH_HYSTERESIS};

/// How long a path may stay silent before it counts as down: PINGs go out
/// every second while the session is active, every ten while idle.
pub fn down_after(active: bool) -> Micros {
    if active { PATH_DOWN } else { PATH_DOWN_IDLE }
}

/// Fewest packets a loss sample is taken over; smaller deltas accumulate.
const MIN_LOSS_SAMPLE: u64 = 20;
/// Weight of a new loss sample in the moving average.
const LOSS_GAIN: f32 = 0.25;
/// Score of a path without an RTT estimate yet: after every measured one.
const UNKNOWN_SCORE: Micros = 10_000_000;

/// Smoothed RTT (RFC 6298 style), in microseconds.
#[derive(Debug, Default, Clone, Copy)]
pub struct Rtt {
    pub srtt: Micros,
    pub rttvar: Micros,
    pub last: Micros,
    pub min: Micros,
    pub samples: u64,
}

impl Rtt {
    pub fn update(&mut self, r: Micros) {
        if self.samples == 0 {
            // Unlike RFC 6298 (rttvar = r/2, meant for a conservative RTO),
            // start from no variation: rttvar feeds the path score, and a
            // large made-up value would dominate it for the first seconds.
            self.srtt = r;
            self.rttvar = 0;
            self.min = r;
        } else {
            self.rttvar = (3 * self.rttvar + self.srtt.abs_diff(r)) / 4;
            self.srtt = (7 * self.srtt + r) / 8;
            self.min = self.min.min(r);
        }
        self.last = r;
        self.samples += 1;
    }

    /// Adopts an estimate made by the peer (the node learns RTTs from the
    /// client's `STATS`).
    pub fn adopt(&mut self, srtt: Micros, rttvar: Micros) {
        self.srtt = srtt;
        self.rttvar = rttvar;
        self.last = srtt;
        self.min = if self.samples == 0 {
            srtt
        } else {
            self.min.min(srtt)
        };
        self.samples += 1;
    }
}

#[derive(Debug, Clone, Copy)]
struct Baseline {
    tx: u64,
    rx: u64,
    peer_tx: u64,
    peer_rx: u64,
}

/// One side's view of one path.
#[derive(Debug, Default, Clone)]
pub struct PathMetrics {
    pub tx_pkts: u64,
    pub rx_pkts: u64,
    pub last_rx: Micros,
    pub rtt: Rtt,
    /// Moving averages of loss towards / from the peer. Samples are not
    /// clamped: packets in flight at one sample make it read high and the
    /// next one low, and clamping the low reading would bias the average.
    avg_out: f32,
    avg_in: f32,
    base_out: Option<Baseline>,
    base_in: Option<Baseline>,
}

impl PathMetrics {
    pub fn new(now: Micros) -> Self {
        Self {
            last_rx: now,
            ..Self::default()
        }
    }

    pub fn on_rx(&mut self, now: Micros) {
        self.rx_pkts += 1;
        self.last_rx = now;
    }

    /// Whether anything arrived on the path recently enough. How recent
    /// depends on the PING interval: see [`down_after`].
    pub fn is_up(&self, now: Micros, down_after: Micros) -> bool {
        now.saturating_sub(self.last_rx) <= down_after
    }

    /// Smoothed loss rate towards the peer, 0.0..=1.0.
    pub fn loss_out(&self) -> f32 {
        self.avg_out.clamp(0.0, 1.0)
    }

    /// Smoothed loss rate from the peer, 0.0..=1.0.
    pub fn loss_in(&self) -> f32 {
        self.avg_in.clamp(0.0, 1.0)
    }

    /// `srtt + JITTER_WEIGHT × rttvar + LOSS_PENALTY × loss_out`: a path
    /// whose delay swings is worse for games than its average suggests.
    pub fn score(&self) -> Micros {
        if self.rtt.samples == 0 {
            return UNKNOWN_SCORE;
        }
        self.rtt.srtt
            + JITTER_WEIGHT * self.rtt.rttvar
            + (LOSS_PENALTY as f32 * self.loss_out()) as Micros
    }

    /// Folds in the peer's cumulative counters for this path, from a
    /// `STATS` frame that just arrived.
    pub fn on_peer_stats(&mut self, peer_tx: u64, peer_rx: u64) {
        let now = Baseline {
            tx: self.tx_pkts,
            rx: self.rx_pkts,
            peer_tx,
            peer_rx,
        };
        // Towards the peer: what it received of what we sent.
        if let Some(l) = sample(&mut self.base_out, now, |b| (b.tx, b.peer_rx)) {
            self.avg_out += LOSS_GAIN * (l - self.avg_out);
        }
        // From the peer: what we received of what it sent.
        if let Some(l) = sample(&mut self.base_in, now, |b| (b.peer_tx, b.rx)) {
            self.avg_in += LOSS_GAIN * (l - self.avg_in);
        }
    }

    /// Takes over the counters and estimates of `old`, the same path seen
    /// from a previous address (NAT rebinding).
    pub fn absorb(&mut self, old: &PathMetrics) {
        self.tx_pkts += old.tx_pkts;
        self.rx_pkts += old.rx_pkts;
        self.rtt = old.rtt;
        self.avg_out = old.avg_out;
        self.avg_in = old.avg_in;
        self.base_out = old.base_out;
        self.base_in = old.base_in;
    }

    #[cfg(test)]
    fn set_loss_out(&mut self, loss: f32) {
        self.avg_out = loss;
    }
}

/// Loss over the counters since `base`, once enough packets were sent;
/// advances `base` when a sample is taken. Counters that went backwards
/// (the peer reset them) restart the baseline.
fn sample(
    base: &mut Option<Baseline>,
    now: Baseline,
    pick: impl Fn(&Baseline) -> (u64, u64),
) -> Option<f32> {
    let Some(b) = base else {
        *base = Some(now);
        return None;
    };
    let (sent0, got0) = pick(b);
    let (sent1, got1) = pick(&now);
    let (Some(sent), Some(got)) = (sent1.checked_sub(sent0), got1.checked_sub(got0)) else {
        *base = Some(now);
        return None;
    };
    if sent < MIN_LOSS_SAMPLE {
        return None;
    }
    *base = Some(now);
    Some((1.0 - got as f32 / sent as f32).clamp(-1.0, 1.0))
}

/// Paths in sending order: up paths by score, then down ones.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ranking {
    order: [u8; MAX_PATHS],
    n: u8,
    n_up: u8,
    /// Up paths in index order, for pinning bulk flows.
    up: [u8; MAX_PATHS],
}

impl Ranking {
    /// Re-ranks `paths` (index = path slot). The current best path keeps
    /// its place unless another beats it by `PATH_HYSTERESIS`.
    pub fn update<'a>(
        &mut self,
        now: Micros,
        down_after: Micros,
        paths: impl Iterator<Item = &'a PathMetrics>,
    ) {
        let prev_best = (self.n > 0).then(|| self.order[0]);
        let mut items = [(false, 0u64, 0u8); MAX_PATHS];
        let mut n = 0;
        for (i, p) in paths.enumerate().take(MAX_PATHS) {
            items[n] = (!p.is_up(now, down_after), p.score(), i as u8);
            n += 1;
        }
        let items = &mut items[..n];
        items.sort_unstable();
        if let Some(prev) = prev_best {
            if let Some(pos) = items.iter().position(|it| it.2 == prev) {
                let (down, score, _) = items[pos];
                let (best_down, best_score, _) = items[0];
                if pos > 0 && down == best_down && best_score + PATH_HYSTERESIS > score {
                    items[..=pos].rotate_right(1);
                }
            }
        }
        self.n = n as u8;
        self.n_up = items.iter().filter(|it| !it.0).count() as u8;
        for (slot, it) in self.order.iter_mut().zip(items.iter()) {
            *slot = it.2;
        }
        let mut k = 0;
        for i in 0..n as u8 {
            if items.iter().any(|it| it.2 == i && !it.0) {
                self.up[k] = i;
                k += 1;
            }
        }
    }

    pub fn len(&self) -> usize {
        usize::from(self.n)
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    pub fn up_count(&self) -> usize {
        usize::from(self.n_up)
    }

    pub fn best(&self) -> Option<usize> {
        self.pick(0, 0)
    }

    pub fn order(&self) -> &[u8] {
        &self.order[..self.len()]
    }

    /// Path for copy `copy` when spreading over at most `max_paths` of the
    /// best paths (0 = no limit). With every path down, all are used.
    pub fn pick(&self, copy: u8, max_paths: u8) -> Option<usize> {
        let usable = self.usable(max_paths);
        (usable > 0).then(|| usize::from(self.order[usize::from(copy) % usable]))
    }

    /// A fixed path for a flow, chosen by hash among the up paths in index
    /// order, so the choice only changes when a path goes up or down.
    pub fn pick_hashed(&self, hash: u64) -> Option<usize> {
        if self.n_up > 0 {
            let i = (hash % u64::from(self.n_up)) as usize;
            Some(usize::from(self.up[i]))
        } else {
            (self.n > 0).then(|| (hash % u64::from(self.n)) as usize)
        }
    }

    fn usable(&self, max_paths: u8) -> usize {
        let n = if self.n_up > 0 { self.n_up } else { self.n };
        let n = if max_paths > 0 { n.min(max_paths) } else { n };
        usize::from(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timing::{MS, SECOND};

    fn path(srtt: Micros, loss: f32, last_rx: Micros) -> PathMetrics {
        let mut p = PathMetrics::new(last_rx);
        p.rtt.update(srtt);
        p.set_loss_out(loss);
        p
    }

    #[test]
    fn rtt_smoothing() {
        let mut r = Rtt::default();
        r.update(100);
        assert_eq!((r.srtt, r.rttvar, r.min), (100, 0, 100));
        r.update(180);
        assert_eq!(r.srtt, 110);
        assert_eq!(r.min, 100);
        assert_eq!(r.last, 180);
    }

    #[test]
    fn loss_from_counters() {
        let mut p = PathMetrics::new(0);
        p.tx_pkts = 100;
        p.rx_pkts = 50;
        p.on_peer_stats(60, 90); // baseline
        p.tx_pkts = 200;
        p.rx_pkts = 140;
        p.on_peer_stats(160, 180);
        // out: sent 100, peer got 90; in: peer sent 100, we got 90.
        assert!((p.loss_out() - 0.25 * 0.10).abs() < 1e-6);
        assert!((p.loss_in() - 0.25 * 0.10).abs() < 1e-6);
    }

    #[test]
    fn small_samples_accumulate() {
        let mut p = PathMetrics::new(0);
        p.on_peer_stats(0, 0);
        p.tx_pkts = 10;
        p.on_peer_stats(0, 5);
        assert_eq!(p.loss_out(), 0.0, "10 packets is too few");
        p.tx_pkts = 40;
        p.on_peer_stats(0, 40);
        assert_eq!(p.loss_out(), 0.0, "40 sent, 40 received since baseline");
    }

    #[test]
    fn packets_in_flight_do_not_bias_the_average() {
        // No real loss; each STATS catches a varying number of our packets
        // still in flight, so single samples read high or low.
        let mut p = PathMetrics::new(0);
        let mut peer_rx = 0;
        for i in 0..200u64 {
            p.tx_pkts += 1000;
            let in_flight = if i % 2 == 0 { 60 } else { 0 };
            peer_rx = p.tx_pkts - in_flight;
            p.on_peer_stats(0, peer_rx);
        }
        assert_eq!(peer_rx, p.tx_pkts);
        assert!(p.loss_out() < 0.01, "{}", p.loss_out());
    }

    #[test]
    fn counter_reset_restarts_baseline() {
        let mut p = PathMetrics::new(0);
        p.tx_pkts = 1000;
        p.on_peer_stats(0, 1000);
        p.on_peer_stats(0, 3);
        p.tx_pkts = 1100;
        p.on_peer_stats(0, 103);
        assert_eq!(p.loss_out(), 0.0);
    }

    #[test]
    fn ranking_prefers_low_rtt_and_low_loss() {
        let now = SECOND;
        let paths = [
            path(160 * MS, 0.0, now),
            path(158 * MS, 0.0, now),
            path(150 * MS, 0.5, now),
        ];
        let mut r = Ranking::default();
        r.update(now, PATH_DOWN, paths.iter());
        assert_eq!(r.order(), &[1, 0, 2]);
        assert_eq!(r.pick(0, 0), Some(1));
        assert_eq!(r.pick(1, 0), Some(0));
        assert_eq!(r.pick(3, 0), Some(1));
        assert_eq!(r.pick(1, 1), Some(1), "one path: every copy on the best");
        assert_eq!(r.pick(1, 2), Some(0));
    }

    #[test]
    fn down_paths_go_last_unless_all_are_down() {
        let paths = [path(100, 0.0, 0), path(2000, 0.0, 10 * SECOND)];
        let mut r = Ranking::default();
        r.update(10 * SECOND, PATH_DOWN, paths.iter());
        assert_eq!(r.order(), &[1, 0]);
        assert_eq!(r.up_count(), 1);
        assert_eq!(r.pick(1, 0), Some(1), "copies stay on up paths");

        r.update(30 * SECOND, PATH_DOWN, paths.iter());
        assert_eq!(r.up_count(), 0);
        assert_eq!(r.pick(0, 0), Some(0));
        assert_eq!(r.pick(1, 0), Some(1), "all down: use every path");
    }

    #[test]
    fn idle_paths_get_a_whole_ping_interval() {
        let p = path(100, 0.0, 0);
        assert!(!p.is_up(8 * SECOND, down_after(true)));
        assert!(p.is_up(8 * SECOND, down_after(false)));
        assert!(!p.is_up(PATH_DOWN_IDLE + 1, down_after(false)));
    }

    #[test]
    fn jittery_path_ranks_below_a_steady_one() {
        // Same average RTT; path 0 swings by ±15ms.
        let mut paths = [PathMetrics::new(0), PathMetrics::new(0)];
        for i in 0..20 {
            let swing = if i % 2 == 0 { 15 * MS } else { 0 };
            paths[0].rtt.update(30 * MS - 7 * MS + swing);
            paths[1].rtt.update(30 * MS);
        }
        assert!(paths[0].rtt.srtt < paths[1].rtt.srtt + MS);
        let mut r = Ranking::default();
        r.update(0, PATH_DOWN, paths.iter());
        assert_eq!(r.best(), Some(1));
    }

    #[test]
    fn best_path_has_hysteresis() {
        let mut paths = [path(1000, 0.0, 0), path(1100, 0.0, 0)];
        let mut r = Ranking::default();
        r.update(0, PATH_DOWN, paths.iter());
        assert_eq!(r.best(), Some(0));
        paths[1].rtt.srtt = 700; // better, but by less than the margin
        r.update(0, PATH_DOWN, paths.iter());
        assert_eq!(r.best(), Some(0));
        paths[1].rtt.srtt = 400;
        r.update(0, PATH_DOWN, paths.iter());
        assert_eq!(r.best(), Some(1));
    }

    #[test]
    fn unmeasured_paths_rank_after_measured_ones() {
        let paths = [PathMetrics::new(0), path(150 * MS, 0.0, 0)];
        let mut r = Ranking::default();
        r.update(0, PATH_DOWN, paths.iter());
        assert_eq!(r.best(), Some(1));
    }

    #[test]
    fn hashed_pick_is_stable_across_rank_changes() {
        let mut paths = [path(100, 0.0, 0), path(200, 0.0, 0), path(300, 0.0, 0)];
        let mut r = Ranking::default();
        r.update(0, PATH_DOWN, paths.iter());
        let before: Vec<_> = (0..10u64).map(|h| r.pick_hashed(h)).collect();
        paths[2].rtt.srtt = 1;
        paths[0].rtt.srtt = 10_000;
        r.update(0, PATH_DOWN, paths.iter());
        let after: Vec<_> = (0..10u64).map(|h| r.pick_hashed(h)).collect();
        assert_eq!(before, after);
    }
}
