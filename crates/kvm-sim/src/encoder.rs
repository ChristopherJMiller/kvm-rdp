//! The ES3's one shared encoder (§6.5, `census.md`): every viewer gets the
//! same frames; a new FLV connection forces an IDR into every open stream
//! and restarts the GOP; with no HDMI signal it sends its NO SIGNAL card
//! (every frame an IDR, same SPS).
use crate::source::{Frame, Source, nal_type};
use crate::state::Shared;
use crate::{Fault, Pacing, Profile, ResizeSignal};
use bytes::Bytes;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::MissedTickBehavior;

/// Frames a viewer may fall behind before kvm-sim drops frames for it.
const VIEWER_QUEUE: usize = 512;

/// A frame as every viewer receives it: the source frame's NALs filtered by
/// the profile, and the encoder's running sequence number.
#[derive(Debug)]
pub(crate) struct OutFrame {
    pub seq: u64,
    pub source_index: usize,
    pub idr: bool,
    pub nals: Vec<Bytes>,
}

#[derive(Debug, Clone)]
pub(crate) enum Item {
    Frame(Arc<OutFrame>),
    Params {
        sps: Bytes,
        pps: Bytes,
        signal: ResizeSignal,
    },
    Fault(Fault),
}

pub(crate) struct Subscription {
    pub rx: mpsc::Receiver<Item>,
    pub sps: Bytes,
    pub pps: Bytes,
    /// Resolves once `broadcast` evicts this viewer (a full queue on a
    /// `Fault`/`Params` item). Fix round 1 (I1): dropping the paired
    /// `oneshot::Sender` in `Encoder::viewers` signals this even while the
    /// viewer's writer is stuck in an in-flight write the client isn't
    /// draining, so `flv::serve` can abort that write instead of waiting
    /// for the client to resume and drain the whole backlog first.
    pub evicted: oneshot::Receiver<()>,
}

enum Cmd {
    Subscribe(oneshot::Sender<Subscription>),
    /// Tests: answered once every earlier command is done.
    #[cfg(test)]
    Sync(oneshot::Sender<()>),
    Advance(u32),
    Signal(bool),
    Switch(Source, ResizeSignal),
    Inject(Fault),
}

#[derive(Clone)]
pub(crate) struct EncoderHandle {
    tx: mpsc::UnboundedSender<Cmd>,
}

impl EncoderHandle {
    pub(crate) async fn subscribe(&self) -> Option<Subscription> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(Cmd::Subscribe(tx)).ok()?;
        rx.await.ok()
    }
    #[cfg(test)]
    async fn sync(&self) {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(Cmd::Sync(tx));
        let _ = rx.await;
    }
    pub(crate) fn advance(&self, frames: u32) {
        let _ = self.tx.send(Cmd::Advance(frames));
    }
    pub(crate) fn signal(&self, present: bool) {
        let _ = self.tx.send(Cmd::Signal(present));
    }
    pub(crate) fn switch(&self, source: Source, signal: ResizeSignal) {
        let _ = self.tx.send(Cmd::Switch(source, signal));
    }
    pub(crate) fn inject(&self, fault: Fault) {
        let _ = self.tx.send(Cmd::Inject(fault));
    }
}

struct Encoder {
    source: Source,
    profile: Profile,
    shared: Arc<Shared>,
    pos: usize,
    seq: u64,
    force_idr: bool,
    signal: bool,
    no_signal_k: usize,
    /// The source index of the most recently emitted IDR, so a forced or
    /// NO SIGNAL IDR never repeats it back to back (`avoid_idr_repeat`).
    last_idr_source: Option<usize>,
    gop_cache: Vec<Arc<OutFrame>>,
    /// Each viewer's item queue, paired with a oneshot whose drop (on
    /// eviction, in `broadcast`'s `retain`) is `Subscription::evicted`'s
    /// signal (fix round 1, I1).
    viewers: Vec<(mpsc::Sender<Item>, oneshot::Sender<()>)>,
}

impl Encoder {
    fn subscribe(&mut self) -> Subscription {
        let (tx, rx) = mpsc::channel(VIEWER_QUEUE);
        let (evict_tx, evicted) = oneshot::channel();
        if self.profile.idr_on_new_connection {
            self.force_idr = true;
        }
        if self.profile.burst_on_connect {
            for f in &self.gop_cache {
                let _ = tx.try_send(Item::Frame(f.clone()));
            }
        }
        self.viewers.push((tx, evict_tx));
        Subscription {
            rx,
            sps: self.source.sps.clone(),
            pps: self.source.pps.clone(),
            evicted,
        }
    }

    fn filter(&self, f: &Frame) -> Vec<Bytes> {
        f.nals
            .iter()
            .filter(|n| match nal_type(n) {
                1 | 5 => true,
                9 => self.profile.aud,
                7 | 8 => self.profile.inband_params,
                6 => self.profile.sei,
                _ => false,
            })
            .cloned()
            .collect()
    }

    /// If `idx` (a GOP start) would repeat the most recently emitted IDR
    /// and the source has more than one GOP, use the next one instead:
    /// two consecutive IDR access units must not share `idr_pic_id`
    /// (H.264 §7.4.3), and repeating a GOP start means repeating its
    /// encoded IDU byte for byte. A single-GOP source
    /// (`gop_starts.len() == 1`) has no other IDR to show and keeps
    /// repeating — a documented limit, not fixed here.
    fn avoid_idr_repeat(&self, idx: usize) -> usize {
        if self.source.gop_starts.len() > 1 && Some(idx) == self.last_idr_source {
            self.source.next_gop_start(idx)
        } else {
            idx
        }
    }

    fn tick(&mut self) {
        let frames_len = self.source.frames.len().max(1);
        let index = if self.signal {
            let at_idr = self.source.frames.get(self.pos).is_some_and(|f| f.idr);
            if self.force_idr {
                if !at_idr {
                    self.pos = self.source.next_gop_start(self.pos);
                }
                self.pos = self.avoid_idr_repeat(self.pos);
            }
            self.force_idr = false;
            let i = self.pos;
            self.pos = (self.pos + 1) % frames_len;
            i
        } else {
            let starts = &self.source.gop_starts;
            let candidate = starts
                .get(self.no_signal_k % starts.len().max(1))
                .copied()
                .unwrap_or(0);
            self.no_signal_k += 1;
            self.avoid_idr_repeat(candidate)
        };
        let Some(frame) = self.source.frames.get(index) else {
            return;
        };
        let out = Arc::new(OutFrame {
            seq: self.seq,
            source_index: frame.index,
            idr: frame.idr,
            nals: self.filter(frame),
        });
        self.seq += 1;
        if out.idr {
            self.gop_cache.clear();
            self.last_idr_source = Some(out.source_index);
        }
        self.gop_cache.push(out.clone());
        self.broadcast(&Item::Frame(out));
    }

    /// Queue `item` for every viewer. A viewer whose 512-slot queue is
    /// full loses only a `Frame` — a merely slow viewer skips a frame, as
    /// a real server would. A full queue on a `Fault` or `Params` instead
    /// disconnects that viewer (I1): a stalled connection that misses a
    /// close or a new sequence header must not silently keep streaming
    /// under stale parameters once it resumes, so kvm-sim ends its stream
    /// the way a real server drops a client it can no longer keep up with.
    /// `retain` dropping the tuple also drops its `oneshot::Sender`, which
    /// is `Subscription::evicted`'s signal — even while the viewer's
    /// writer is stuck in an in-flight write the client isn't draining
    /// (fix round 1, I1).
    fn broadcast(&mut self, item: &Item) {
        let shared = &self.shared;
        self.viewers
            .retain(|(tx, _)| match tx.try_send(item.clone()) {
                Ok(()) => true,
                Err(mpsc::error::TrySendError::Full(_)) => match item {
                    Item::Frame(_) => {
                        shared.frame_dropped();
                        true
                    }
                    Item::Fault(_) | Item::Params { .. } => false,
                },
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            });
    }

    fn handle(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Subscribe(reply) => {
                let sub = self.subscribe();
                let _ = reply.send(sub);
            }
            #[cfg(test)]
            Cmd::Sync(done) => {
                let _ = done.send(());
            }
            Cmd::Advance(n) => (0..n).for_each(|_| self.tick()),
            Cmd::Signal(present) => {
                // Signal coming back is a new input: the encoder restarts at an IDR.
                if present && !self.signal {
                    self.force_idr = true;
                }
                self.signal = present;
            }
            Cmd::Switch(source, signal) => {
                self.source = source;
                self.pos = 0;
                self.force_idr = false;
                self.gop_cache.clear();
                let item = Item::Params {
                    sps: self.source.sps.clone(),
                    pps: self.source.pps.clone(),
                    signal,
                };
                self.broadcast(&item);
            }
            Cmd::Inject(fault) => self.broadcast(&Item::Fault(fault)),
        }
    }
}

pub(crate) fn spawn(
    source: Source,
    profile: Profile,
    pacing: Pacing,
    shared: Arc<Shared>,
) -> (EncoderHandle, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut enc = Encoder {
        source,
        profile,
        shared,
        pos: 0,
        seq: 0,
        force_idr: false,
        signal: true,
        no_signal_k: 0,
        last_idr_source: None,
        gop_cache: Vec::new(),
        viewers: Vec::new(),
    };
    let task = tokio::spawn(async move {
        let mut ticker = match pacing {
            Pacing::RealTime => {
                let period = Duration::from_secs(1) / profile.fps.max(1);
                let mut t = tokio::time::interval(period);
                t.set_missed_tick_behavior(MissedTickBehavior::Skip);
                Some(t)
            }
            Pacing::Manual => None,
        };
        loop {
            tokio::select! {
                cmd = rx.recv() => match cmd {
                    Some(c) => enc.handle(c),
                    None => break,
                },
                () = async {
                    match ticker.as_mut() {
                        Some(t) => { t.tick().await; }
                        None => std::future::pending::<()>().await,
                    }
                } => enc.tick(),
            }
        }
    });
    (EncoderHandle { tx }, task)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::Source;

    fn es3() -> (EncoderHandle, Arc<Shared>) {
        let shared = Arc::new(Shared::default());
        let src = Source::fixture("360p30_es3like_poc0.h264").unwrap();
        let (enc, _task) = spawn(src, Profile::es3(), Pacing::Manual, shared.clone());
        (enc, shared)
    }

    /// Everything queued for a viewer right now: `(seq, idr, NAL types)`.
    async fn drain(enc: &EncoderHandle, sub: &mut Subscription) -> Vec<(u64, bool, Vec<u8>)> {
        enc.sync().await;
        let mut out = Vec::new();
        while let Ok(item) = sub.rx.try_recv() {
            if let Item::Frame(f) = item {
                out.push((f.seq, f.idr, f.nals.iter().map(|n| n[0] & 0x1F).collect()));
            }
        }
        out
    }

    /// Drain `rx` until it closes, asserting every item until then is a
    /// `Frame`. Bounded by a 5 s timeout (fix round 2) so a regression that
    /// leaves a stalled viewer connected fails the test quickly instead of
    /// hanging it.
    async fn drain_to_close(rx: &mut mpsc::Receiver<Item>) -> usize {
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut frames = 0;
            while let Some(item) = rx.recv().await {
                assert!(matches!(item, Item::Frame(_)));
                frames += 1;
            }
            frames
        })
        .await
        .expect("viewer was not disconnected within 5s")
    }

    #[tokio::test]
    async fn a_new_viewer_forces_an_idr_into_every_open_stream() {
        let (enc, _) = es3();
        let mut a = enc.subscribe().await.unwrap();
        enc.advance(10);
        let first = drain(&enc, &mut a).await;
        assert_eq!(first.len(), 10);
        assert!(first[0].1 && first[1..].iter().all(|f| !f.1));
        let mut b = enc.subscribe().await.unwrap();
        enc.advance(2);
        let (a2, b2) = (drain(&enc, &mut a).await, drain(&enc, &mut b).await);
        assert_eq!(a2, b2, "one encoder: both viewers get the same frames");
        assert_eq!((a2[0].0, a2[0].1, a2[1].1), (10, true, false));
        // The forced IDR restarts the GOP: the next IDR is 60 frames later
        // (seq 70), not on the old cadence (seq 60).
        enc.advance(60);
        let rest = drain(&enc, &mut a).await;
        let idrs: Vec<u64> = first
            .iter()
            .chain(&a2)
            .chain(&rest)
            .filter(|f| f.1)
            .map(|f| f.0)
            .collect();
        assert_eq!(idrs, [0, 10, 70]);
    }

    #[tokio::test]
    async fn the_gop_is_the_source_gop_and_es3_frames_carry_only_slices() {
        let (enc, _) = es3();
        let mut a = enc.subscribe().await.unwrap();
        enc.advance(121);
        let f = drain(&enc, &mut a).await;
        let idrs: Vec<u64> = f.iter().filter(|f| f.1).map(|f| f.0).collect();
        assert_eq!(idrs, [0, 60, 120]);
        assert!(f.iter().all(|f| f.2 == [if f.1 { 5 } else { 1 }]));
    }

    #[tokio::test]
    async fn no_signal_is_all_intra_and_the_signal_returns_on_an_idr() {
        let (enc, _) = es3();
        let mut a = enc.subscribe().await.unwrap();
        enc.advance(5);
        enc.signal(false);
        enc.advance(4);
        enc.signal(true);
        enc.advance(2);
        let idr: Vec<bool> = drain(&enc, &mut a).await.iter().map(|f| f.1).collect();
        assert_eq!(
            idr,
            [
                true, false, false, false, false, true, true, true, true, true, false
            ]
        );
    }

    #[tokio::test]
    async fn a_gop_caching_profile_replays_the_gop_so_far_to_a_new_viewer() {
        let shared = Arc::new(Shared::default());
        let src = Source::fixture("360p30_es3like_poc0.h264").unwrap();
        let profile = Profile {
            burst_on_connect: true,
            idr_on_new_connection: false,
            ..Profile::es3()
        };
        let (enc, _task) = spawn(src, profile, Pacing::Manual, shared);
        let _a = enc.subscribe().await.unwrap();
        enc.advance(7);
        let mut b = enc.subscribe().await.unwrap();
        let replay = drain(&enc, &mut b).await;
        assert_eq!(
            replay.iter().map(|f| f.0).collect::<Vec<_>>(),
            (0..7).collect::<Vec<_>>()
        );
        assert!(replay[0].1);
    }

    #[tokio::test]
    async fn a_full_viewer_queue_drops_only_that_viewers_frames() {
        let (enc, shared) = es3();
        let mut a = enc.subscribe().await.unwrap();
        let mut b = enc.subscribe().await.unwrap();
        enc.advance(512);
        assert_eq!(drain(&enc, &mut a).await.len(), 512);
        enc.advance(100); // b never drained: its queue is full
        assert_eq!(drain(&enc, &mut a).await.len(), 100);
        assert_eq!(shared.stats().frames_dropped, 100);
        assert_eq!(drain(&enc, &mut b).await.len(), 512);
    }

    #[tokio::test]
    async fn faults_and_source_switches_reach_every_viewer_in_order() {
        let (enc, _) = es3();
        let mut a = enc.subscribe().await.unwrap();
        enc.advance(1);
        enc.inject(Fault::Close);
        let other = Source::fixture("480p30_main_full.h264").unwrap();
        let sps = other.sps.clone();
        enc.switch(other, ResizeSignal::SequenceHeader);
        enc.advance(1);
        enc.sync().await;
        let kinds: Vec<String> = std::iter::from_fn(|| a.rx.try_recv().ok())
            .map(|i| match i {
                Item::Frame(f) => format!("frame {} idr {}", f.seq, f.idr),
                Item::Fault(f) => format!("{f:?}"),
                Item::Params { sps: s, signal, .. } => format!("params {} {signal:?}", s == sps),
            })
            .collect();
        assert_eq!(
            kinds,
            [
                "frame 0 idr true",
                "Close",
                "params true SequenceHeader",
                "frame 1 idr true"
            ]
        );
    }

    /// I1 fix round 1: a full queue must disconnect on a control item, not
    /// silently drop it and count it as a dropped frame.
    #[tokio::test]
    async fn a_full_viewer_is_disconnected_by_a_fault_instead_of_losing_it() {
        let (enc, shared) = es3();
        let mut a = enc.subscribe().await.unwrap();
        let mut b = enc.subscribe().await.unwrap();
        enc.advance(512);
        // a drains normally; b never does, so its queue is now full.
        assert_eq!(drain(&enc, &mut a).await.len(), 512);
        enc.inject(Fault::Close);
        enc.sync().await;
        // a, not full, gets the fault like any other item.
        assert!(matches!(a.rx.try_recv(), Ok(Item::Fault(Fault::Close))));
        // b, full, is dropped instead of losing the fault: its 512 queued
        // frames still drain, then its stream ends (`recv` returns `None`),
        // and the fault it never saw is not counted as a dropped frame.
        let frames = drain_to_close(&mut b.rx).await;
        assert_eq!(frames, 512);
        assert_eq!(shared.stats().frames_dropped, 0);
        // Other viewers are unaffected: a is still subscribed and working.
        enc.advance(1);
        assert_eq!(drain(&enc, &mut a).await.len(), 1);
    }

    /// I1 fix round 1: the same disconnect-not-drop rule for a `Params`
    /// item (a source switch), not just a `Fault`.
    #[tokio::test]
    async fn a_full_viewer_is_disconnected_by_a_source_switch_instead_of_losing_it() {
        let (enc, shared) = es3();
        let mut a = enc.subscribe().await.unwrap();
        let mut b = enc.subscribe().await.unwrap();
        enc.advance(512);
        assert_eq!(drain(&enc, &mut a).await.len(), 512);
        let other = Source::fixture("480p30_main_full.h264").unwrap();
        enc.switch(other, ResizeSignal::SequenceHeader);
        enc.sync().await;
        assert!(matches!(a.rx.try_recv(), Ok(Item::Params { .. })));
        let frames = drain_to_close(&mut b.rx).await;
        assert_eq!(frames, 512);
        assert_eq!(shared.stats().frames_dropped, 0);
    }

    /// m1 fix round 1: H.264 §7.4.3 forbids two consecutive IDR access
    /// units with the same `idr_pic_id`; kvm-sim reuses the source frame's
    /// own `idr_pic_id`, so two consecutive IDRs must come from different
    /// source frames. The NO SIGNAL → return transition is where the old
    /// code repeated one (census: the alternating card is fine on its own,
    /// but a forced-return IDR could land back on the GOP start the NO
    /// SIGNAL card had just shown).
    #[tokio::test]
    async fn consecutive_idrs_never_repeat_the_same_source_frame() {
        let (enc, _) = es3();
        let mut a = enc.subscribe().await.unwrap();
        enc.advance(5);
        enc.signal(false);
        enc.advance(4);
        enc.signal(true);
        enc.advance(2);
        enc.sync().await;
        let mut idr_sources = Vec::new();
        while let Ok(item) = a.rx.try_recv() {
            if let Item::Frame(f) = item
                && f.idr
            {
                idr_sources.push(f.source_index);
            }
        }
        assert!(
            idr_sources.windows(2).all(|w| w[0] != w[1]),
            "two consecutive IDRs reused the same source frame (same idr_pic_id): {idr_sources:?}"
        );
    }
}
