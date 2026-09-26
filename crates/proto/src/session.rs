//! Per-direction session state shared by client and server: sealing data
//! and control packets on the way out, authentication, replay protection,
//! dedup and reassembly on the way in.

use rand::rngs::StdRng;
use rand::{Rng, RngExt, SeedableRng};

use crate::dedup::DedupWindow;
use crate::frag::{self, Reassembler};
use crate::frame::{
    Echo, Frame, FrameWriter, IP_FRAG_OVERHEAD, IP_OVERHEAD, Ip, IpFrag, NackRange, PIGGY_COPY,
    RETX_COPY,
};
use crate::keys::Keyset;
use crate::nack::GapTracker;
use crate::packet::{
    CONTROL_PAD_MAX, MAX_BODY, PN_LEN, PacketBuf, TAG_LEN, handshake_padding, padding_towards,
    random_padding,
};
use crate::replay::{ReplayWindow, Seen};
use crate::timing::KEY_RETAIN;
use crate::{Error, Micros};

/// Concurrent reassemblies kept per session.
const REASSEMBLY_SLOTS: usize = 16;
/// Recent game packet lengths that control packets imitate.
const LEN_SAMPLES: usize = 16;
/// Control packets land within this many bytes of the length they imitate.
const CONTROL_LEN_JITTER: usize = 16;

/// How a data packet is padded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pad {
    /// `[0, pad_max]`, and the length is remembered for control packets
    /// to imitate (game items).
    Game,
    /// None: bulk packets are near full size, padding only costs.
    Bulk,
}

enum Fill {
    Data(Pad),
    Control,
}

/// Sending half: packet numbers, data sequence numbers, padding.
pub struct TxState {
    keys: Keyset,
    pn: u64,
    seq: u32,
    /// Sequence numbers allocated so far (the `tx_unique` of `STATS`).
    items: u64,
    pad_max: usize,
    rng: StdRng,
    buf: PacketBuf,
    /// Body lengths of recent game packets (ring).
    lens: [u16; LEN_SAMPLES],
    n_lens: usize,
}

impl TxState {
    pub fn new(keys: Keyset, pad_max: usize) -> Self {
        Self {
            keys,
            pn: 0,
            seq: 0,
            items: 0,
            pad_max,
            rng: StdRng::from_rng(&mut rand::rng()),
            buf: PacketBuf::new(),
            lens: [0; LEN_SAMPLES],
            n_lens: 0,
        }
    }

    /// Data items sent, counting each fragment.
    pub fn items_sent(&self) -> u64 {
        self.items
    }

    /// Switches to a new keyset (in-channel rekey). Packet
    /// numbers restart at 0; data sequence numbers carry on.
    pub fn rekey(&mut self, keys: Keyset) {
        self.keys = keys;
        self.pn = 0;
    }

    fn alloc_seq(&mut self, n: u32) -> u32 {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(n);
        self.items += u64::from(n);
        seq
    }

    /// Seals one packet of control frames written by `f`.
    pub fn control(
        &mut self,
        f: impl FnOnce(&mut FrameWriter<'_>) -> Result<(), Error>,
    ) -> Result<&[u8], Error> {
        self.seal(Fill::Control, f)
    }

    /// Whether `ip` fits in one data frame (otherwise it goes as IP_FRAG).
    pub fn fits_one_frame(ip: &[u8]) -> bool {
        ip.len() + IP_OVERHEAD <= MAX_BODY
    }

    /// Sends `ip` as a new game data item: assigns sequence numbers,
    /// fragments if needed and calls `emit` with each sealed packet.
    /// Returns the first sequence number so that redundant copies can
    /// reuse it.
    pub fn send_ip(&mut self, ip: &[u8], emit: impl FnMut(&[u8])) -> Result<u32, Error> {
        self.send_ip_with(ip, Pad::Game, &[], emit)
    }

    /// [`send_ip`](Self::send_ip) with a padding mode and, when `ip` fits
    /// one frame, other data frames carried along in the same packet as
    /// far as they fit (piggybacking).
    pub fn send_ip_with(
        &mut self,
        ip: &[u8],
        pad: Pad,
        extra: &[Frame<'_>],
        mut emit: impl FnMut(&[u8]),
    ) -> Result<u32, Error> {
        if Self::fits_one_frame(ip) {
            let seq = self.alloc_seq(1);
            let frame = Frame::Ip(Ip {
                seq,
                copy: 0,
                packet: ip,
            });
            emit(self.seal(Fill::Data(pad), |w| write_bundle(w, &frame, extra))?);
            return Ok(seq);
        }
        let n = ip.len().div_ceil(MAX_BODY - IP_FRAG_OVERHEAD) as u32;
        let seq = self.alloc_seq(n);
        self.send_frags(seq, 0, ip, pad, emit)?;
        Ok(seq)
    }

    /// Sends copy `copy` of a game data item whose sequence numbers start
    /// at `seq`.
    pub fn send_ip_as(
        &mut self,
        seq: u32,
        copy: u8,
        ip: &[u8],
        emit: impl FnMut(&[u8]),
    ) -> Result<(), Error> {
        self.send_frags(seq, copy, ip, Pad::Game, emit)
    }

    fn send_frags(
        &mut self,
        seq: u32,
        copy: u8,
        ip: &[u8],
        pad: Pad,
        mut emit: impl FnMut(&[u8]),
    ) -> Result<(), Error> {
        if Self::fits_one_frame(ip) {
            let frame = Frame::Ip(Ip {
                seq,
                copy,
                packet: ip,
            });
            emit(self.seal(Fill::Data(pad), |w| w.write(&frame))?);
            return Ok(());
        }
        for (idx, cnt, data) in frag::split(ip, MAX_BODY - IP_FRAG_OVERHEAD)? {
            let frame = Frame::IpFrag(IpFrag {
                seq: seq.wrapping_add(u32::from(idx)),
                copy,
                idx,
                cnt,
                data,
            });
            emit(self.seal(Fill::Data(pad), |w| w.write(&frame))?);
        }
        Ok(())
    }

    /// Sends copy 0 of an echo frame (used by `bench`) under a new sequence
    /// number, which it returns; `echo.seq` and `echo.copy` are ignored.
    pub fn send_echo(
        &mut self,
        request: bool,
        echo: Echo<'_>,
        emit: impl FnOnce(&[u8]),
    ) -> Result<u32, Error> {
        self.send_echo_with(request, echo, &[], emit)
    }

    /// [`send_echo`](Self::send_echo) with other data frames carried along.
    pub fn send_echo_with(
        &mut self,
        request: bool,
        echo: Echo<'_>,
        extra: &[Frame<'_>],
        emit: impl FnOnce(&[u8]),
    ) -> Result<u32, Error> {
        let seq = self.alloc_seq(1);
        let echo = Echo {
            seq,
            copy: 0,
            ..echo
        };
        let frame = if request {
            Frame::EchoReq(echo)
        } else {
            Frame::EchoResp(echo)
        };
        emit(self.seal(Fill::Data(Pad::Game), |w| write_bundle(w, &frame, extra))?);
        Ok(seq)
    }

    /// Sends an echo frame with the sequence number and copy it carries.
    pub fn send_echo_as(
        &mut self,
        request: bool,
        echo: Echo<'_>,
        emit: impl FnOnce(&[u8]),
    ) -> Result<(), Error> {
        let frame = if request {
            Frame::EchoReq(echo)
        } else {
            Frame::EchoResp(echo)
        };
        emit(self.seal(Fill::Data(Pad::Game), |w| w.write(&frame))?);
        Ok(())
    }

    fn seal(
        &mut self,
        fill: Fill,
        f: impl FnOnce(&mut FrameWriter<'_>) -> Result<(), Error>,
    ) -> Result<&[u8], Error> {
        let mut w = self.buf.writer();
        f(&mut w)?;
        let body = w.len();
        let pad = match fill {
            Fill::Data(Pad::Game) => random_padding(&mut self.rng, body, self.pad_max),
            Fill::Data(Pad::Bulk) => 0,
            // Control packets take the length of a recent game packet, so
            // that keepalives do not form a length cluster of their own.
            Fill::Control if self.n_lens > 0 => {
                let pick = self.lens[self.rng.random_range(0..self.n_lens.min(LEN_SAMPLES))];
                let jitter = self.rng.random_range(0..=2 * CONTROL_LEN_JITTER);
                let target = (usize::from(pick) + jitter).saturating_sub(CONTROL_LEN_JITTER);
                padding_towards(body, target)
            }
            Fill::Control => random_padding(&mut self.rng, body, CONTROL_PAD_MAX),
        };
        w.pad(pad)?;
        let len = w.len();
        if matches!(fill, Fill::Data(Pad::Game)) {
            self.lens[self.n_lens % LEN_SAMPLES] = len as u16;
            self.n_lens += 1;
        }
        let pn = self.pn;
        self.pn += 1;
        self.buf.seal(&self.keys, pn, len)
    }
}

/// `first`, then as many of `extra` as fit, in order.
fn write_bundle(
    w: &mut FrameWriter<'_>,
    first: &Frame<'_>,
    extra: &[Frame<'_>],
) -> Result<(), Error> {
    w.write(first)?;
    for f in extra {
        if f.encoded_len() > w.remaining() {
            break;
        }
        w.write(f)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RxStats {
    /// Authentic, non-replayed packets.
    pub packets: u64,
    /// Data frames delivered for the first time.
    pub unique: u64,
    /// Data frames dropped as duplicates (including too-old ones).
    pub dup: u64,
    /// Unique data frames whose first arrival was a copy other than 0 ...
    pub rescued: u64,
    /// ... of which NACK retransmissions, and piggybacked items.
    pub retx: u64,
    pub piggy: u64,
}

/// Payload of a data frame accepted for the first time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Data<'a> {
    Ip(&'a [u8]),
    EchoReq(Echo<'a>),
    EchoResp(Echo<'a>),
}

/// Which receive keyset opened a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPhase {
    Current,
    /// The keyset installed by a rekey; it has just become current.
    Next,
    /// The keyset replaced by the last rekey, still accepted for a while.
    Previous,
}

/// A receive keyset with its own packet-number replay window (packet
/// numbers restart with every keyset).
struct RxKeys {
    keys: Keyset,
    replay: ReplayWindow,
}

impl RxKeys {
    fn new(keys: Keyset) -> Self {
        Self {
            keys,
            replay: ReplayWindow::new(),
        }
    }

    /// Decrypts `pkt` in place if it is authentic under this keyset and
    /// not a replay; the body is then `pkt[PN_LEN..len - TAG_LEN]`. On
    /// failure `pkt` is unchanged.
    fn open(&mut self, pkt: &mut [u8]) -> Result<(), Error> {
        let pn = self.keys.peek_pn(pkt)?;
        if self.replay.check(pn) != Seen::New {
            return Err(Error::Replay);
        }
        let (pn, _) = self.keys.open(pkt)?;
        self.replay.insert(pn);
        Ok(())
    }
}

/// Receiving half: authentication, replay windows, dedup, reassembly.
/// Around a rekey it holds up to three keysets: the current
/// one, the peer's next one (which becomes current with the first packet
/// sealed under it) and the previous one, kept for late packets until
/// `KEY_RETAIN` after the switch.
pub struct RxState {
    cur: RxKeys,
    next: Option<RxKeys>,
    prev: Option<(RxKeys, Micros)>,
    dedup: DedupWindow,
    reasm: Reassembler,
    gaps: GapTracker,
    /// How long a gap in the data sequence may stay open before it is
    /// NACKed (`None`: no NACKs).
    nack_wait: Option<Micros>,
    pub stats: RxStats,
}

impl RxState {
    pub fn new(keys: Keyset) -> Self {
        Self {
            cur: RxKeys::new(keys),
            next: None,
            prev: None,
            dedup: DedupWindow::new(),
            reasm: Reassembler::new(REASSEMBLY_SLOTS),
            gaps: GapTracker::new(),
            nack_wait: None,
            stats: RxStats::default(),
        }
    }

    /// Turns NACKs on (with the wait for gaps) or off.
    pub fn set_nack_wait(&mut self, wait: Option<Micros>) {
        if wait.is_none() {
            self.gaps = GapTracker::new();
        }
        self.nack_wait = wait;
    }

    /// Gaps due for a NACK by `now`, into `out`.
    pub fn nacks(&mut self, now: Micros, out: &mut Vec<NackRange>) {
        let dedup = &self.dedup;
        self.gaps.due(now, |s| dedup.check(s) == Seen::New, out);
    }

    /// When the next gap is due for a NACK.
    pub fn next_nack(&self) -> Option<Micros> {
        self.nack_wait.and(self.gaps.next_due())
    }

    /// Installs the keyset the peer is about to switch to, replacing any
    /// earlier one that never got used.
    pub fn set_next(&mut self, keys: Keyset) {
        self.next = Some(RxKeys::new(keys));
    }

    /// Opens `pkt` under the current, next or previous keyset, rejecting
    /// replays. The first packet under the next keyset makes it current.
    /// On failure `pkt` is left unchanged and the error is the current
    /// keyset's.
    pub fn open<'a>(
        &mut self,
        now: Micros,
        pkt: &'a mut [u8],
    ) -> Result<(&'a [u8], KeyPhase), Error> {
        let phase = match self.cur.open(pkt) {
            Ok(()) => KeyPhase::Current,
            Err(e) => {
                if self.next.as_mut().is_some_and(|k| k.open(pkt).is_ok()) {
                    let next = self.next.take().expect("next keyset present");
                    let old = std::mem::replace(&mut self.cur, next);
                    self.prev = Some((old, now + KEY_RETAIN));
                    KeyPhase::Next
                } else if self
                    .prev
                    .as_mut()
                    .is_some_and(|(k, until)| now < *until && k.open(pkt).is_ok())
                {
                    KeyPhase::Previous
                } else {
                    return Err(e);
                }
            }
        };
        self.stats.packets += 1;
        let end = pkt.len() - TAG_LEN;
        Ok((&pkt[PN_LEN..end], phase))
    }

    /// Runs a data frame through dedup and reassembly. Returns the payload
    /// the first time a data item is complete; `None` for duplicates,
    /// incomplete fragments and control frames.
    pub fn accept<'s, 'p: 's>(&'s mut self, now: Micros, frame: &Frame<'p>) -> Option<Data<'s>> {
        match *frame {
            Frame::Ip(f) => self
                .first_time(now, f.seq, f.copy)
                .then_some(Data::Ip(f.packet)),
            Frame::IpFrag(f) => {
                if !self.first_time(now, f.seq, f.copy) {
                    return None;
                }
                self.reasm
                    .push(now, f.seq, f.idx, f.cnt, f.data)
                    .ok()
                    .flatten()
                    .map(Data::Ip)
            }
            Frame::EchoReq(e) => self
                .first_time(now, e.seq, e.copy)
                .then_some(Data::EchoReq(e)),
            Frame::EchoResp(e) => self
                .first_time(now, e.seq, e.copy)
                .then_some(Data::EchoResp(e)),
            _ => None,
        }
    }

    /// Drops stale partial reassemblies and a retired keyset past its time.
    pub fn expire(&mut self, now: Micros) {
        self.reasm.expire(now);
        if self.prev.as_ref().is_some_and(|(_, until)| now >= *until) {
            self.prev = None;
        }
    }

    fn first_time(&mut self, now: Micros, seq: u32, copy: u8) -> bool {
        if self.dedup.insert(seq) == Seen::New {
            self.stats.unique += 1;
            match copy {
                0 => {}
                RETX_COPY => {
                    self.stats.rescued += 1;
                    self.stats.retx += 1;
                }
                PIGGY_COPY => {
                    self.stats.rescued += 1;
                    self.stats.piggy += 1;
                }
                _ => self.stats.rescued += 1,
            }
            if let Some(wait) = self.nack_wait {
                self.gaps.on_new(now, seq, wait);
            }
            true
        } else {
            self.stats.dup += 1;
            false
        }
    }
}

/// Seals a handshake frame under an obfuscation keyset, with a random
/// packet number and handshake padding.
pub fn seal_handshake<'b, R: Rng + ?Sized>(
    keys: &Keyset,
    frame: &Frame<'_>,
    rng: &mut R,
    buf: &'b mut PacketBuf,
) -> Result<&'b [u8], Error> {
    let mut w = buf.writer();
    w.write(frame)?;
    let pad = handshake_padding(rng, w.len());
    w.pad(pad)?;
    let len = w.len();
    let pn = rng.next_u64();
    buf.seal(keys, pn, len)
}

/// Opens a handshake packet. There is no replay window here: Noise plus the
/// hello timestamp handle replays.
pub fn open_handshake<'a>(keys: &Keyset, pkt: &'a mut [u8]) -> Result<&'a [u8], Error> {
    keys.open(pkt).map(|(_, body)| body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{FrameReader, Ping};
    use crate::keys::SessionKeys;
    use crate::packet::{HANDSHAKE_LEN_MAX, HANDSHAKE_LEN_MIN};

    fn pair() -> (TxState, RxState) {
        let k = SessionKeys::from_secrets(&[1; 32], &[2; 32]);
        (
            TxState::new(k.c2s, 48),
            RxState::new(Keyset::from_secret(&[1; 32])),
        )
    }

    fn deliver(rx: &mut RxState, pkt: &[u8]) -> Vec<Vec<u8>> {
        let mut p = pkt.to_vec();
        let Ok((body, _)) = rx.open(0, &mut p) else {
            return vec![];
        };
        let frames: Vec<Frame<'_>> = FrameReader::new(body).collect::<Result<_, _>>().unwrap();
        let mut out = vec![];
        for f in &frames {
            if let Some(Data::Ip(ip)) = rx.accept(0, f) {
                out.push(ip.to_vec());
            }
        }
        out
    }

    #[test]
    fn bulk_packets_are_not_padded_and_control_packets_imitate_game_ones() {
        let (mut tx, _) = pair();
        let bulk_len = |tx: &mut TxState| {
            let mut n = 0;
            tx.send_ip_with(&[0x45; 1000], Pad::Bulk, &[], |p| n = p.len())
                .unwrap();
            n
        };
        let base = 1000 + IP_OVERHEAD + crate::packet::OVERHEAD;
        for _ in 0..20 {
            assert_eq!(bulk_len(&mut tx), base);
        }
        // Before any game packet: control packets are padded [0, 96].
        let ping = Frame::Ping(Ping {
            path: 0,
            id: 1,
            ts: 2,
        });
        let short = ping.encoded_len() + crate::packet::OVERHEAD;
        for _ in 0..50 {
            let n = tx.control(|w| w.write(&ping)).unwrap().len();
            assert!((short..=short + CONTROL_PAD_MAX).contains(&n), "{n}");
        }
        // After 300B game packets, they land near those lengths.
        let mut game = vec![];
        for _ in 0..LEN_SAMPLES {
            tx.send_ip(&[0x45; 300], |p| game.push(p.len())).unwrap();
        }
        let (lo, hi) = (game.iter().min().unwrap(), game.iter().max().unwrap());
        for _ in 0..200 {
            let n = tx.control(|w| w.write(&ping)).unwrap().len();
            assert!(
                (lo - CONTROL_LEN_JITTER..=hi + CONTROL_LEN_JITTER).contains(&n),
                "{n} outside {lo}..={hi} ± {CONTROL_LEN_JITTER}"
            );
        }
    }

    #[test]
    fn gaps_are_nacked_once_they_are_due() {
        let (mut tx, mut rx) = pair();
        rx.set_nack_wait(Some(5_000));
        let mut pkts = vec![];
        for _ in 0..6 {
            tx.send_ip(&[0x45; 40], |p| pkts.push(p.to_vec())).unwrap();
        }
        let accept = |rx: &mut RxState, now: Micros, pkt: &[u8]| {
            let mut p = pkt.to_vec();
            let (body, _) = rx.open(now, &mut p).unwrap();
            let f = FrameReader::new(body).next().unwrap().unwrap();
            rx.accept(now, &f).is_some()
        };
        for i in [0, 3, 5] {
            assert!(accept(&mut rx, 0, &pkts[i]));
        }
        assert_eq!(rx.next_nack(), Some(5_000));
        let mut out = vec![];
        rx.nacks(4_999, &mut out);
        assert!(out.is_empty());
        // 4 arrives late, as a copy would.
        assert!(accept(&mut rx, 1_000, &pkts[4]));
        rx.nacks(5_000, &mut out);
        let got: Vec<_> = out.iter().map(|r| (r.start, r.count)).collect();
        assert_eq!(got, vec![(1, 2)]);
        assert_eq!(rx.next_nack(), None);

        rx.set_nack_wait(None);
        accept(&mut rx, 6_000, &pkts[2]);
        assert_eq!(rx.next_nack(), None, "off: no tracking");
    }

    #[test]
    fn data_roundtrip_and_dedup() {
        let (mut tx, mut rx) = pair();
        let ip = vec![0x45; 300];
        let mut sent = vec![];
        let seq = tx.send_ip(&ip, |p| sent.push(p.to_vec())).unwrap();
        // A redundant copy of the same item under a fresh PN.
        tx.send_ip_as(seq, 1, &ip, |p| sent.push(p.to_vec()))
            .unwrap();
        assert_eq!(sent.len(), 2);
        assert_ne!(sent[0], sent[1]);

        assert_eq!(deliver(&mut rx, &sent[0]), vec![ip.clone()]);
        assert!(deliver(&mut rx, &sent[1]).is_empty());
        assert_eq!(rx.stats.unique, 1);
        assert_eq!(rx.stats.dup, 1);
        assert_eq!(rx.stats.rescued, 0);
    }

    #[test]
    fn rescued_when_copy_arrives_first() {
        let (mut tx, mut rx) = pair();
        let mut sent = vec![];
        let seq = tx.send_ip(&[0x45; 50], |p| sent.push(p.to_vec())).unwrap();
        tx.send_ip_as(seq, 1, &[0x45; 50], |p| sent.push(p.to_vec()))
            .unwrap();
        assert_eq!(deliver(&mut rx, &sent[1]).len(), 1);
        assert_eq!(rx.stats.rescued, 1);
    }

    #[test]
    fn replayed_packet_is_rejected() {
        let (mut tx, mut rx) = pair();
        let mut sent = vec![];
        tx.send_ip(&[0x45; 50], |p| sent.push(p.to_vec())).unwrap();
        assert_eq!(deliver(&mut rx, &sent[0]).len(), 1);
        let mut again = sent[0].clone();
        assert!(matches!(rx.open(0, &mut again), Err(Error::Replay)));
        assert_eq!(again, sent[0], "rejected packet must be untouched");
    }

    #[test]
    fn oversized_packet_is_fragmented_and_reassembled() {
        let (mut tx, mut rx) = pair();
        let ip: Vec<u8> = (0..3000).map(|i| i as u8).collect();
        let mut sent = vec![];
        let seq = tx.send_ip(&ip, |p| sent.push(p.to_vec())).unwrap();
        assert_eq!(sent.len(), 3);
        // Next item continues after the fragments' sequence numbers.
        let next = tx.send_ip(&[1], |_| {}).unwrap();
        assert_eq!(next, seq + 3);

        let mut got = vec![];
        for p in sent.iter().rev() {
            got.extend(deliver(&mut rx, p));
        }
        assert_eq!(got, vec![ip]);
    }

    #[test]
    fn control_packets_open() {
        let (mut tx, mut rx) = pair();
        let pkt = tx
            .control(|w| {
                w.write(&Frame::Ping(Ping {
                    path: 0,
                    id: 1,
                    ts: 2,
                }))
            })
            .unwrap()
            .to_vec();
        let mut p = pkt.clone();
        let (body, _) = rx.open(0, &mut p).unwrap();
        let f = FrameReader::new(body).next().unwrap().unwrap();
        assert_eq!(
            f,
            Frame::Ping(Ping {
                path: 0,
                id: 1,
                ts: 2
            })
        );
        assert!(rx.accept(0, &f).is_none());
    }

    #[test]
    fn handshake_packets() {
        let obfs = SessionKeys::from_secrets(&[5; 32], &[6; 32]);
        let mut rng = rand::rng();
        let mut buf = PacketBuf::new();
        for _ in 0..200 {
            let pkt = seal_handshake(&obfs.c2s, &Frame::HsInit(&[7; 108]), &mut rng, &mut buf)
                .unwrap()
                .to_vec();
            assert!((HANDSHAKE_LEN_MIN..=HANDSHAKE_LEN_MAX).contains(&pkt.len()));
            let mut p = pkt.clone();
            let body = open_handshake(&obfs.c2s, &mut p).unwrap();
            assert_eq!(
                FrameReader::new(body).next().unwrap().unwrap(),
                Frame::HsInit(&[7; 108])
            );
        }
    }

    fn sealed_ip(tx: &mut TxState, len: usize) -> Vec<u8> {
        let mut out = vec![];
        tx.send_ip(&vec![0x45; len], |p| out = p.to_vec()).unwrap();
        out
    }

    fn phase(rx: &mut RxState, now: Micros, pkt: &[u8]) -> Result<KeyPhase, Error> {
        let mut p = pkt.to_vec();
        rx.open(now, &mut p).map(|(_, phase)| phase)
    }

    #[test]
    fn rekey_switches_on_first_packet_and_keeps_old_keys_for_a_while() {
        let (mut tx, mut rx) = pair();
        let old = sealed_ip(&mut tx, 40);
        let old_late = sealed_ip(&mut tx, 40);

        rx.set_next(Keyset::from_secret(&[9; 32]));
        // The old keyset is still current until the peer uses the new one.
        assert!(matches!(phase(&mut rx, 10, &old), Ok(KeyPhase::Current)));

        tx.rekey(Keyset::from_secret(&[9; 32]));
        let new0 = sealed_ip(&mut tx, 40);
        let new1 = sealed_ip(&mut tx, 40);
        assert!(matches!(phase(&mut rx, 20, &new1), Ok(KeyPhase::Next)));
        // Packet numbers restarted: new0 has PN 0, below new1, still new.
        assert!(matches!(phase(&mut rx, 21, &new0), Ok(KeyPhase::Current)));
        assert!(matches!(phase(&mut rx, 22, &new0), Err(Error::Replay)));

        // A late packet under the old keys opens until KEY_RETAIN passes.
        assert!(matches!(
            phase(&mut rx, 30, &old_late),
            Ok(KeyPhase::Previous)
        ));
        assert!(
            phase(&mut rx, 31, &old_late).is_err(),
            "replay under old keys"
        );
        let old_later = {
            let mut t = TxState::new(Keyset::from_secret(&[1; 32]), 0);
            t.pn = 100;
            sealed_ip(&mut t, 40)
        };
        rx.expire(20 + KEY_RETAIN);
        assert!(phase(&mut rx, 20 + KEY_RETAIN, &old_later).is_err());
        assert_eq!(rx.stats.packets, 4);
    }

    #[test]
    fn rekey_keeps_dedup_across_keysets() {
        // A copy sealed under the old keys and one under the new keys carry
        // the same sequence number: only one is delivered.
        let (mut tx, mut rx) = pair();
        let ip = vec![0x45; 60];
        let mut first = vec![];
        let seq = tx.send_ip(&ip, |p| first = p.to_vec()).unwrap();
        rx.set_next(Keyset::from_secret(&[3; 32]));
        tx.rekey(Keyset::from_secret(&[3; 32]));
        let mut copy = vec![];
        tx.send_ip_as(seq, 1, &ip, |p| copy = p.to_vec()).unwrap();
        assert_eq!(deliver(&mut rx, &copy), vec![ip.clone()]);
        assert!(deliver(&mut rx, &first).is_empty());
        assert_eq!(rx.stats.dup, 1);
    }
}
