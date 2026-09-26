//! Redundant sending (SPEC §4.2, §4.5). Copy 0 of a data item goes out at
//! once on the best path; copy `c` follows `c × copy_delay` later on the
//! `c`-th path of the ranking. Every copy is a separate packet with its own
//! PN and padding, sealed when it is sent. Recent game items are kept for
//! NACK retransmission and for piggybacking on later game packets.

use std::collections::VecDeque;

use crate::flow::{Class, Flow};
use crate::frame::{Echo, Frame, Ip, NackRange, PIGGY_COPY, RETX_COPY, TUNE_NACK, Tune};
use crate::path::Ranking;
use crate::session::{Pad, TxState};
use crate::timing::MS;
use crate::{Error, Micros};

pub const MAX_COPIES: u8 = 4;
pub const MAX_COPY_DELAY: Micros = 50 * MS;
/// Most recent items a game packet carries along.
pub const MAX_PIGGYBACK: u8 = 8;
/// Largest data item kept for delayed copies; bigger ones get copy 0 only.
const MAX_DELAYED_LEN: usize = 1500;
/// Bound on each per-copy queue; copies beyond it are dropped.
const QUEUE_CAP: usize = 1024;
/// Game items are kept this long for NACK retransmission ...
pub const RETX_HORIZON: Micros = 500 * MS;
/// ... and piggybacked only while this young.
pub const PIGGY_HORIZON: Micros = 50 * MS;
/// Recent game items kept, at most.
const RECENT_CAP: usize = 256;
/// Retransmissions per NACK, at most.
const MAX_RETX_PER_NACK: usize = 64;

/// Redundancy settings for one direction of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub copies: u8,
    /// Spread copies over at most this many of the best paths (0 = all).
    pub paths: u8,
    pub copy_delay: Micros,
    pub bulk_enter_kbps: u32,
    pub bulk_exit_kbps: u32,
    /// NACK fast retransmission (both directions; the receiver asks).
    pub nack: bool,
    /// Recent game items each game packet carries along (0 = off).
    pub piggyback: u8,
    /// Towards the client: shape bulk flows to this rate (0 = off).
    pub bulk_rate_kbps: u32,
}

impl Policy {
    /// What the node uses until the client sends `TUNE`.
    pub const SINGLE: Policy = Policy {
        copies: 1,
        paths: 0,
        copy_delay: 0,
        bulk_enter_kbps: 2000,
        bulk_exit_kbps: 1000,
        nack: false,
        piggyback: 0,
        bulk_rate_kbps: 0,
    };

    /// Clamps values from the wire to sane ranges.
    pub fn from_tune(t: &Tune) -> Self {
        let enter = t.bulk_enter_kbps.max(1);
        Self {
            copies: t.copies.clamp(1, MAX_COPIES),
            paths: t.paths,
            copy_delay: Micros::from(t.copy_delay_us).min(MAX_COPY_DELAY),
            bulk_enter_kbps: enter,
            bulk_exit_kbps: t.bulk_exit_kbps.min(enter),
            nack: t.flags & TUNE_NACK != 0,
            piggyback: t.piggyback.min(MAX_PIGGYBACK),
            bulk_rate_kbps: t.bulk_rate_kbps,
        }
    }

    pub fn to_tune(&self) -> Tune {
        Tune {
            copies: self.copies,
            paths: self.paths,
            copy_delay_us: self.copy_delay as u32,
            bulk_enter_kbps: self.bulk_enter_kbps,
            bulk_exit_kbps: self.bulk_exit_kbps,
            flags: if self.nack { TUNE_NACK } else { 0 },
            piggyback: self.piggyback,
            bulk_rate_kbps: self.bulk_rate_kbps,
        }
    }

    /// Whether game items must be kept after sending.
    fn keeps_recent(&self) -> bool {
        self.nack || self.piggyback > 0
    }
}

/// How to send one data item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    copies: u8,
    delay: Micros,
    max_paths: u8,
    /// Single copy on the path this flow hash maps to, unpadded (bulk
    /// flows).
    pinned: Option<u64>,
    /// Keep the item for NACKs and piggybacking.
    keep: bool,
    piggyback: u8,
}

impl Plan {
    pub fn redundant(p: &Policy) -> Self {
        Self {
            copies: p.copies.clamp(1, MAX_COPIES),
            delay: p.copy_delay,
            max_paths: p.paths,
            pinned: None,
            keep: p.keeps_recent(),
            piggyback: p.piggyback.min(MAX_PIGGYBACK),
        }
    }

    pub fn for_flow(p: &Policy, flow: Flow) -> Self {
        match flow.class {
            Class::Game => Self::redundant(p),
            Class::Bulk => Self {
                copies: 1,
                delay: 0,
                max_paths: 0,
                pinned: Some(flow.hash),
                keep: false,
                piggyback: 0,
            },
        }
    }

    pub fn copies(&self) -> u8 {
        self.copies
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Ip,
    Echo { request: bool, id: u32, ts: u64 },
}

struct Pending {
    due: Micros,
    seq: u32,
    copy: u8,
    max_paths: u8,
    kind: Kind,
    len: u16,
    data: [u8; MAX_DELAYED_LEN],
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SchedStats {
    /// Copies after the first that were sent.
    pub copies_sent: u64,
    /// Copies not sent: queue full or item too large to keep.
    pub copies_dropped: u64,
    /// Items resent for a NACK.
    pub retransmits: u64,
    /// Items carried along in later packets.
    pub piggybacked: u64,
}

/// A game item sent lately.
struct Recent {
    at: Micros,
    seq: u32,
    kind: Kind,
    resent: bool,
    len: u16,
    data: [u8; MAX_DELAYED_LEN],
}

impl Recent {
    fn frame(&self) -> Frame<'_> {
        let data = &self.data[..usize::from(self.len)];
        match self.kind {
            Kind::Ip => Frame::Ip(Ip {
                seq: self.seq,
                copy: PIGGY_COPY,
                packet: data,
            }),
            Kind::Echo { request, id, ts } => {
                let e = Echo {
                    seq: self.seq,
                    copy: PIGGY_COPY,
                    id,
                    ts,
                    payload: data,
                };
                if request {
                    Frame::EchoReq(e)
                } else {
                    Frame::EchoResp(e)
                }
            }
        }
    }
}

/// Sends data items with their redundant copies, holding delayed copies
/// until they are due.
pub struct Scheduler {
    queues: [VecDeque<Pending>; MAX_COPIES as usize - 1],
    /// Game items of the last `RETX_HORIZON`, oldest first.
    recent: VecDeque<Recent>,
    pub stats: SchedStats,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            queues: Default::default(),
            recent: VecDeque::new(),
            stats: SchedStats::default(),
        }
    }

    /// Sends an inner IP packet: copy 0 through `emit(path, packet)` now,
    /// the rest now or later depending on the plan. Without any path the
    /// item is dropped.
    pub fn send_ip(
        &mut self,
        tx: &mut TxState,
        now: Micros,
        ip: &[u8],
        plan: Plan,
        ranking: &Ranking,
        mut emit: impl FnMut(usize, &[u8]),
    ) -> Result<(), Error> {
        let first = match plan.pinned {
            Some(hash) => ranking.pick_hashed(hash),
            None => ranking.pick(0, plan.max_paths),
        };
        let Some(path) = first else { return Ok(()) };
        let pad = if plan.pinned.is_some() {
            Pad::Bulk
        } else {
            Pad::Game
        };
        let mut extra = [Frame::Close(0); MAX_PIGGYBACK as usize];
        let n = self.piggyback(now, plan, &mut extra);
        let seq = tx.send_ip_with(ip, pad, &extra[..n], |pkt| emit(path, pkt))?;
        self.stats.piggybacked += n as u64;
        if plan.keep && TxState::fits_one_frame(ip) {
            self.remember(now, seq, Kind::Ip, ip);
        }
        self.follow_up(tx, now, seq, Kind::Ip, ip, plan, ranking, emit)
    }

    /// Sends an echo frame with the same redundancy as a game packet.
    #[allow(clippy::too_many_arguments)]
    pub fn send_echo(
        &mut self,
        tx: &mut TxState,
        now: Micros,
        request: bool,
        id: u32,
        ts: u64,
        payload: &[u8],
        plan: Plan,
        ranking: &Ranking,
        mut emit: impl FnMut(usize, &[u8]),
    ) -> Result<(), Error> {
        let Some(path) = ranking.pick(0, plan.max_paths) else {
            return Ok(());
        };
        let echo = Echo {
            seq: 0,
            copy: 0,
            id,
            ts,
            payload,
        };
        let mut extra = [Frame::Close(0); MAX_PIGGYBACK as usize];
        let n = self.piggyback(now, plan, &mut extra);
        let seq = tx.send_echo_with(request, echo, &extra[..n], |pkt| emit(path, pkt))?;
        self.stats.piggybacked += n as u64;
        let kind = Kind::Echo { request, id, ts };
        if plan.keep && payload.len() <= MAX_DELAYED_LEN {
            self.remember(now, seq, kind, payload);
        }
        self.follow_up(tx, now, seq, kind, payload, plan, ranking, emit)
    }

    /// Resends the kept items a NACK asks for, once each, on the best
    /// path. Items not kept (bulk, too old, already resent) are skipped.
    /// Returns how many went out.
    pub fn on_nack(
        &mut self,
        tx: &mut TxState,
        now: Micros,
        ranges: impl Iterator<Item = NackRange>,
        ranking: &Ranking,
        mut emit: impl FnMut(usize, &[u8]),
    ) -> usize {
        let Some(path) = ranking.pick(0, 0) else {
            return 0;
        };
        let mut sent = 0;
        'ranges: for r in ranges {
            for i in 0..u32::from(r.count) {
                if sent == MAX_RETX_PER_NACK {
                    break 'ranges;
                }
                let seq = r.start.wrapping_add(i);
                let Some(item) = self.recent.iter_mut().find(|x| x.seq == seq) else {
                    continue;
                };
                if item.resent || now.saturating_sub(item.at) > RETX_HORIZON {
                    continue;
                }
                item.resent = true;
                let data = &item.data[..usize::from(item.len)];
                if send_copy(tx, seq, RETX_COPY, item.kind, data, |pkt| emit(path, pkt)).is_ok() {
                    sent += 1;
                }
            }
        }
        self.stats.retransmits += sent as u64;
        sent
    }

    /// Fills `out` with the newest kept items young enough to piggyback,
    /// newest first; returns how many.
    fn piggyback<'s>(&'s self, now: Micros, plan: Plan, out: &mut [Frame<'s>]) -> usize {
        let mut n = 0;
        for r in self.recent.iter().rev() {
            if n == usize::from(plan.piggyback)
                || n == out.len()
                || now.saturating_sub(r.at) > PIGGY_HORIZON
            {
                break;
            }
            out[n] = r.frame();
            n += 1;
        }
        n
    }

    fn remember(&mut self, now: Micros, seq: u32, kind: Kind, data: &[u8]) {
        while self.recent.len() >= RECENT_CAP
            || self
                .recent
                .front()
                .is_some_and(|r| now.saturating_sub(r.at) > RETX_HORIZON)
        {
            self.recent.pop_front();
        }
        let mut r = Recent {
            at: now,
            seq,
            kind,
            resent: false,
            len: data.len() as u16,
            data: [0; MAX_DELAYED_LEN],
        };
        r.data[..data.len()].copy_from_slice(data);
        self.recent.push_back(r);
    }

    /// Sends the delayed copies that are due, each on the path its copy
    /// number maps to in the current ranking.
    pub fn poll(
        &mut self,
        tx: &mut TxState,
        now: Micros,
        ranking: &Ranking,
        mut emit: impl FnMut(usize, &[u8]),
    ) {
        for q in &mut self.queues {
            while let Some(p) = q.front() {
                if p.due > now {
                    break;
                }
                if let Some(path) = ranking.pick(p.copy, p.max_paths) {
                    let data = &p.data[..usize::from(p.len)];
                    if send_copy(tx, p.seq, p.copy, p.kind, data, |pkt| emit(path, pkt)).is_ok() {
                        self.stats.copies_sent += 1;
                    }
                }
                q.pop_front();
            }
        }
    }

    /// When the earliest delayed copy is due.
    pub fn next_due(&self) -> Option<Micros> {
        self.queues
            .iter()
            .filter_map(|q| q.front().map(|p| p.due))
            .min()
    }

    pub fn pending(&self) -> usize {
        self.queues.iter().map(VecDeque::len).sum()
    }

    #[allow(clippy::too_many_arguments)]
    fn follow_up(
        &mut self,
        tx: &mut TxState,
        now: Micros,
        seq: u32,
        kind: Kind,
        data: &[u8],
        plan: Plan,
        ranking: &Ranking,
        mut emit: impl FnMut(usize, &[u8]),
    ) -> Result<(), Error> {
        for copy in 1..plan.copies {
            if plan.delay == 0 {
                if let Some(path) = ranking.pick(copy, plan.max_paths) {
                    send_copy(tx, seq, copy, kind, data, |pkt| emit(path, pkt))?;
                    self.stats.copies_sent += 1;
                }
                continue;
            }
            let q = &mut self.queues[usize::from(copy) - 1];
            if data.len() > MAX_DELAYED_LEN || q.len() >= QUEUE_CAP {
                self.stats.copies_dropped += 1;
                continue;
            }
            let mut p = Pending {
                due: now + Micros::from(copy) * plan.delay,
                seq,
                copy,
                max_paths: plan.max_paths,
                kind,
                len: data.len() as u16,
                data: [0; MAX_DELAYED_LEN],
            };
            p.data[..data.len()].copy_from_slice(data);
            q.push_back(p);
        }
        Ok(())
    }
}

fn send_copy(
    tx: &mut TxState,
    seq: u32,
    copy: u8,
    kind: Kind,
    data: &[u8],
    mut emit: impl FnMut(&[u8]),
) -> Result<(), Error> {
    match kind {
        Kind::Ip => tx.send_ip_as(seq, copy, data, emit),
        Kind::Echo { request, id, ts } => {
            let echo = Echo {
                seq,
                copy,
                id,
                ts,
                payload: data,
            };
            tx.send_echo_as(request, echo, |pkt| emit(pkt))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{Frame, FrameReader};
    use crate::keys::{Keyset, SessionKeys};
    use crate::path::PathMetrics;
    use crate::session::{Data, RxState};
    use crate::timing::SECOND;

    fn setup(n_paths: usize) -> (TxState, RxState, Ranking) {
        let k = SessionKeys::from_secrets(&[1; 32], &[2; 32]);
        let tx = TxState::new(k.c2s, 48);
        let rx = RxState::new(Keyset::from_secret(&[1; 32]));
        let paths: Vec<_> = (0..n_paths)
            .map(|i| {
                let mut p = PathMetrics::new(SECOND);
                p.rtt.update(100_000 + i as u64 * 1000);
                p
            })
            .collect();
        let mut r = Ranking::default();
        r.update(SECOND, crate::timing::PATH_DOWN, paths.iter());
        (tx, rx, r)
    }

    fn policy(copies: u8, delay: Micros) -> Policy {
        Policy {
            copies,
            copy_delay: delay,
            ..Policy::SINGLE
        }
    }

    /// Opens a packet and returns (seq, copy) of its data frame.
    fn open(rx: &mut RxState, pkt: &[u8]) -> (u32, u8, bool) {
        let mut p = pkt.to_vec();
        let (body, _) = rx.open(0, &mut p).unwrap();
        let f = FrameReader::new(body).next().unwrap().unwrap();
        let (seq, copy) = match f {
            Frame::Ip(i) => (i.seq, i.copy),
            Frame::EchoReq(e) => (e.seq, e.copy),
            other => panic!("unexpected {other:?}"),
        };
        let new = rx.accept(0, &f).is_some();
        (seq, copy, new)
    }

    #[test]
    fn immediate_copies_go_to_successive_paths() {
        let (mut tx, mut rx, r) = setup(2);
        let mut s = Scheduler::new();
        let mut out = vec![];
        s.send_ip(
            &mut tx,
            0,
            &[0x45; 60],
            Plan::redundant(&policy(3, 0)),
            &r,
            |p, pkt| out.push((p, pkt.to_vec())),
        )
        .unwrap();
        let paths: Vec<_> = out.iter().map(|o| o.0).collect();
        assert_eq!(paths, vec![0, 1, 0]);
        let seen: Vec<_> = out.iter().map(|o| open(&mut rx, &o.1)).collect();
        assert_eq!(seen, vec![(0, 0, true), (0, 1, false), (0, 2, false)]);
        assert_eq!(s.stats.copies_sent, 2);
        assert_eq!(tx.items_sent(), 1);
    }

    #[test]
    fn delayed_copies_wait_for_their_time() {
        let (mut tx, mut rx, r) = setup(2);
        let mut s = Scheduler::new();
        let mut out = vec![];
        let plan = Plan::redundant(&policy(3, 2 * MS));
        s.send_ip(&mut tx, 1000, &[0x45; 60], plan, &r, |p, pkt| {
            out.push((p, pkt.to_vec()))
        })
        .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(s.next_due(), Some(1000 + 2 * MS));

        s.poll(&mut tx, 1000 + 2 * MS - 1, &r, |p, pkt| {
            out.push((p, pkt.to_vec()))
        });
        assert_eq!(out.len(), 1);
        s.poll(&mut tx, 1000 + 2 * MS, &r, |p, pkt| {
            out.push((p, pkt.to_vec()))
        });
        assert_eq!(out.len(), 2);
        assert_eq!(out[1].0, 1);
        assert_eq!(s.next_due(), Some(1000 + 4 * MS));
        s.poll(&mut tx, 10 * MS, &r, |p, pkt| out.push((p, pkt.to_vec())));
        assert_eq!(out.len(), 3);
        assert_eq!(s.next_due(), None);

        // The copy arriving first is delivered; the rest are duplicates.
        let seen: Vec<_> = out.iter().rev().map(|o| open(&mut rx, &o.1)).collect();
        assert_eq!(seen, vec![(0, 2, true), (0, 1, false), (0, 0, false)]);
        assert_eq!(rx.stats.rescued, 1);
    }

    #[test]
    fn delayed_copies_of_many_items_keep_order_per_copy() {
        let (mut tx, _rx, r) = setup(2);
        let mut s = Scheduler::new();
        let plan = Plan::redundant(&policy(2, 2 * MS));
        for i in 0..5 {
            s.send_ip(&mut tx, i * 100, &[0x45; 40], plan, &r, |_, _| {})
                .unwrap();
        }
        assert_eq!(s.pending(), 5);
        let mut n = 0;
        s.poll(&mut tx, 2 * MS + 250, &r, |_, _| n += 1);
        assert_eq!(n, 3);
        assert_eq!(s.next_due(), Some(2 * MS + 300));
    }

    #[test]
    fn bulk_flows_get_one_copy_on_a_pinned_path() {
        let (mut tx, _rx, r) = setup(3);
        let mut s = Scheduler::new();
        let flow = Flow {
            class: Class::Bulk,
            hash: 7,
        };
        let plan = Plan::for_flow(&policy(3, 2 * MS), flow);
        let mut paths = vec![];
        for _ in 0..4 {
            s.send_ip(&mut tx, 0, &[0x45; 1000], plan, &r, |p, _| paths.push(p))
                .unwrap();
        }
        assert_eq!(paths, vec![1; 4], "hash 7 % 3 up paths = index 1");
        assert_eq!(s.pending(), 0);
    }

    #[test]
    fn copies_limited_to_best_paths() {
        let (mut tx, _rx, r) = setup(3);
        let mut s = Scheduler::new();
        let p = Policy {
            paths: 1,
            ..policy(2, 0)
        };
        let mut paths = vec![];
        s.send_ip(&mut tx, 0, &[0x45; 40], Plan::redundant(&p), &r, |p, _| {
            paths.push(p)
        })
        .unwrap();
        assert_eq!(paths, vec![0, 0]);
    }

    #[test]
    fn echo_copies_carry_id_and_timestamp() {
        let (mut tx, mut rx, r) = setup(2);
        let mut s = Scheduler::new();
        let mut out = vec![];
        let plan = Plan::redundant(&policy(2, MS));
        s.send_echo(&mut tx, 0, true, 42, 777, b"hello", plan, &r, |_, pkt| {
            out.push(pkt.to_vec())
        })
        .unwrap();
        s.poll(&mut tx, MS, &r, |_, pkt| out.push(pkt.to_vec()));
        assert_eq!(out.len(), 2);
        let mut p = out[1].clone();
        let (body, _) = rx.open(0, &mut p).unwrap();
        let f = FrameReader::new(body).next().unwrap().unwrap();
        let Some(Data::EchoReq(e)) = rx.accept(0, &f) else {
            panic!("expected echo request")
        };
        assert_eq!((e.id, e.ts, e.copy, e.payload), (42, 777, 1, &b"hello"[..]));
    }

    /// All data frames of a packet as (seq, copy), accepting them.
    fn frames(rx: &mut RxState, now: Micros, pkt: &[u8]) -> Vec<(u32, u8, bool)> {
        let mut p = pkt.to_vec();
        let (body, _) = rx.open(now, &mut p).unwrap();
        let fs: Vec<Frame<'_>> = FrameReader::new(body).map(|f| f.unwrap()).collect();
        fs.iter()
            .map(|f| {
                let (seq, copy) = match f {
                    Frame::Ip(i) => (i.seq, i.copy),
                    Frame::EchoReq(e) | Frame::EchoResp(e) => (e.seq, e.copy),
                    other => panic!("unexpected {other:?}"),
                };
                (seq, copy, rx.accept(now, f).is_some())
            })
            .collect()
    }

    #[test]
    fn nacked_game_items_are_resent_once() {
        let (mut tx, mut rx, r) = setup(2);
        let mut s = Scheduler::new();
        let p = Policy {
            nack: true,
            ..policy(1, 0)
        };
        let mut out = vec![];
        for i in 0..5 {
            s.send_ip(
                &mut tx,
                i * MS,
                &[0x45; 40],
                Plan::redundant(&p),
                &r,
                |_, pkt| out.push(pkt.to_vec()),
            )
            .unwrap();
        }
        let ranges = [
            NackRange { start: 1, count: 2 },
            NackRange { start: 9, count: 1 },
        ];
        let mut resent = vec![];
        let n = s.on_nack(&mut tx, 10 * MS, ranges.into_iter(), &r, |path, pkt| {
            resent.push((path, pkt.to_vec()))
        });
        assert_eq!(n, 2, "9 was never sent");
        assert!(resent.iter().all(|(path, _)| *path == 0), "best path");
        let seen: Vec<_> = resent
            .iter()
            .flat_map(|(_, p)| frames(&mut rx, 0, p))
            .collect();
        assert_eq!(seen, vec![(1, RETX_COPY, true), (2, RETX_COPY, true)]);
        assert_eq!(rx.stats.retx, 2);
        // Once only, and not after the horizon.
        assert_eq!(
            s.on_nack(&mut tx, 10 * MS, ranges.into_iter(), &r, |_, _| {}),
            0
        );
        let late = [NackRange { start: 3, count: 1 }];
        assert_eq!(
            s.on_nack(
                &mut tx,
                3 * MS + RETX_HORIZON + 1,
                late.into_iter(),
                &r,
                |_, _| {}
            ),
            0
        );
        assert_eq!(s.stats.retransmits, 2);
    }

    #[test]
    fn bulk_items_are_not_kept() {
        let (mut tx, _rx, r) = setup(2);
        let mut s = Scheduler::new();
        let p = Policy {
            nack: true,
            ..policy(1, 0)
        };
        let bulk = Flow {
            class: Class::Bulk,
            hash: 1,
        };
        s.send_ip(
            &mut tx,
            0,
            &[0x45; 1000],
            Plan::for_flow(&p, bulk),
            &r,
            |_, _| {},
        )
        .unwrap();
        let ranges = [NackRange { start: 0, count: 1 }];
        assert_eq!(s.on_nack(&mut tx, MS, ranges.into_iter(), &r, |_, _| {}), 0);
    }

    #[test]
    fn game_packets_carry_recent_items_along() {
        let (mut tx, mut rx, r) = setup(1);
        let mut s = Scheduler::new();
        let p = Policy {
            piggyback: 2,
            ..policy(1, 0)
        };
        let mut out = vec![];
        for t in [0, 10 * MS, 20 * MS, 30 * MS, 200 * MS] {
            s.send_ip(
                &mut tx,
                t,
                &[0x45; 40],
                Plan::redundant(&p),
                &r,
                |_, pkt| out.push(pkt.to_vec()),
            )
            .unwrap();
        }
        // Packet 1 (seq 1) is lost; the next ones carry it along.
        let got: Vec<_> = [0, 2, 3, 4]
            .iter()
            .map(|&i| frames(&mut rx, 0, &out[i]))
            .collect();
        assert_eq!(got[0], vec![(0, 0, true)]);
        assert_eq!(
            got[1],
            vec![(2, 0, true), (1, PIGGY_COPY, true), (0, PIGGY_COPY, false)]
        );
        assert_eq!(
            got[2],
            vec![(3, 0, true), (2, PIGGY_COPY, false), (1, PIGGY_COPY, false)]
        );
        assert_eq!(got[3], vec![(4, 0, true)], "older than the horizon");
        assert_eq!(rx.stats.piggy, 1);
        assert_eq!(s.stats.piggybacked, 5, "0 + 1 + 2 + 2 + 0");
    }

    #[test]
    fn policy_from_wire_is_clamped() {
        let p = Policy::from_tune(&Tune {
            copies: 9,
            paths: 0,
            copy_delay_us: u32::MAX,
            bulk_enter_kbps: 100,
            bulk_exit_kbps: 500,
            flags: 0xFF,
            piggyback: 200,
            bulk_rate_kbps: 50_000,
        });
        assert_eq!(p.copies, MAX_COPIES);
        assert_eq!(p.copy_delay, MAX_COPY_DELAY);
        assert_eq!(p.bulk_exit_kbps, 100);
        assert!(p.nack);
        assert_eq!(p.piggyback, MAX_PIGGYBACK);
        assert_eq!(p.bulk_rate_kbps, 50_000);
        assert_eq!(Policy::from_tune(&p.to_tune()), p);
    }
}
