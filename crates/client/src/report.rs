//! Loss arithmetic over two `STATS` exchanges, shared by the
//! `up` status line and `bench`.

use crate::core::Exchange;

/// `1 − got / sent`, or `None` when nothing was sent.
pub fn loss(sent: u64, got: u64) -> Option<f64> {
    (sent > 0).then(|| (1.0 - got as f64 / sent as f64).max(0.0))
}

/// Counters between two exchanges `a` (earlier) and `b`.
pub struct Interval<'a> {
    pub a: &'a Exchange,
    pub b: &'a Exchange,
}

impl Interval<'_> {
    /// Items we sent that the node never received, after redundancy.
    pub fn up_eff(&self) -> Option<f64> {
        loss(
            self.b.tx_unique.saturating_sub(self.a.tx_unique),
            self.b.peer.rx_unique.saturating_sub(self.a.peer.rx_unique),
        )
    }

    pub fn down_eff(&self) -> Option<f64> {
        loss(
            self.b.peer.tx_unique.saturating_sub(self.a.peer.tx_unique),
            self.b.rx.unique.saturating_sub(self.a.rx.unique),
        )
    }

    /// Items the node first received through a copy other than copy 0.
    pub fn up_rescued(&self) -> u64 {
        self.b
            .peer
            .rx_rescued
            .saturating_sub(self.a.peer.rx_rescued)
    }

    pub fn down_rescued(&self) -> u64 {
        self.b.rx.rescued.saturating_sub(self.a.rx.rescued)
    }

    /// Raw packet loss on `path` towards the node.
    pub fn up_raw(&self, path: usize) -> Option<f64> {
        let (_, rx_a) = self.a.peer_path(path)?;
        let (_, rx_b) = self.b.peer_path(path)?;
        loss(
            self.b.paths[path].0.saturating_sub(self.a.paths[path].0),
            rx_b.saturating_sub(rx_a),
        )
    }

    /// Raw packet loss on `path` from the node.
    pub fn down_raw(&self, path: usize) -> Option<f64> {
        let (tx_a, _) = self.a.peer_path(path)?;
        let (tx_b, _) = self.b.peer_path(path)?;
        loss(
            tx_b.saturating_sub(tx_a),
            self.b.paths[path].1.saturating_sub(self.a.paths[path].1),
        )
    }
}

pub fn pct(v: Option<f64>) -> String {
    v.map_or_else(|| "-".to_owned(), |v| format!("{:.2}%", v * 100.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use skyblock_proto::frame::{MAX_PATHS, PathStats, Stats};
    use skyblock_proto::session::RxStats;

    fn ex(tx_unique: u64, rx_unique: u64, peer: Stats, paths: &[(u64, u64)]) -> Exchange {
        let mut p = [(0, 0); MAX_PATHS];
        p[..paths.len()].copy_from_slice(paths);
        Exchange {
            at: 0,
            peer,
            tx_unique,
            rx: RxStats {
                unique: rx_unique,
                ..RxStats::default()
            },
            paths: p,
        }
    }

    fn peer(tx_unique: u64, rx_unique: u64, rescued: u64, path0: (u64, u64)) -> Stats {
        let mut s = Stats::new(tx_unique, rx_unique, 0, rescued);
        s.push_path(PathStats {
            path: 0,
            tx_pkts: path0.0,
            rx_pkts: path0.1,
            srtt_us: 0,
            rttvar_us: 0,
        });
        s
    }

    #[test]
    fn interval_losses() {
        let a = ex(100, 50, peer(60, 90, 1, (200, 300)), &[(400, 500)]);
        let b = ex(
            1100,
            1040,
            peer(1060, 1080, 6, (2200, 2280)),
            &[(2400, 2490)],
        );
        let i = Interval { a: &a, b: &b };
        assert!((i.up_eff().unwrap() - 0.01).abs() < 1e-9); // 1000 sent, 990 got
        assert!((i.down_eff().unwrap() - 0.01).abs() < 1e-9); // 1000 sent, 990 got
        assert_eq!(i.up_rescued(), 5);
        assert!((i.up_raw(0).unwrap() - 0.01).abs() < 1e-9); // 2000 sent, 1980 got
        assert!((i.down_raw(0).unwrap() - 0.005).abs() < 1e-9); // 2000 sent, 1990 got
        assert_eq!(i.up_raw(1), None, "path unknown to the node");
    }
}
