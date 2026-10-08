//! §7.3's queue: the input handler pushes full-state reports stamped with
//! the current release epoch; a motion-only report replaces a motion-only
//! tail; a full queue is cleared and resynced to the final state;
//! release-all bumps the epoch, clears the queue and raises a flag the
//! writer services before anything else (§7.4). O(1) per push.
use crate::metrics::Metrics;
use kvm_proto::hid::HidFrame;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use tokio::sync::Notify;

const KBD_ZERO: HidFrame = HidFrame::Keyboard {
    modifiers: 0,
    keys: [0; 5],
};

/// What triggered a release-all (§7.4); the `release_all{trigger}` label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseTrigger {
    SessionStart,
    SessionEnd,
    Closing,
    Watchdog,
    Shutdown,
    WebsocketReconnect,
    Suppression,
}

impl ReleaseTrigger {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ReleaseTrigger::SessionStart => "session_start",
            ReleaseTrigger::SessionEnd => "session_end",
            ReleaseTrigger::Closing => "closing",
            ReleaseTrigger::Watchdog => "watchdog",
            ReleaseTrigger::Shutdown => "shutdown",
            ReleaseTrigger::WebsocketReconnect => "websocket_reconnect",
            ReleaseTrigger::Suppression => "suppression",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    pub epoch: u64,
    pub frame: HidFrame,
    /// Only the pointer moved (no button or key change): coalescable.
    pub motion_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Push {
    Queued,
    Coalesced,
    /// The queue was full: cleared, and the final state goes out next.
    Resync,
}

pub struct HidQueue {
    cap: usize,
    items: VecDeque<Report>,
    resync: bool,
    /// A resync's frames, waiting to be popped.
    out: VecDeque<HidFrame>,
    latest_kbd: Option<HidFrame>,
    latest_mouse: Option<HidFrame>,
}

impl HidQueue {
    #[must_use]
    pub fn new(cap: usize) -> HidQueue {
        HidQueue {
            cap: cap.max(1),
            items: VecDeque::with_capacity(cap.clamp(1, 4096)),
            resync: false,
            out: VecDeque::with_capacity(2),
            latest_kbd: None,
            latest_mouse: None,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty() && self.out.is_empty()
    }

    pub fn push(&mut self, r: Report) -> Push {
        match r.frame {
            HidFrame::Keyboard { .. } => self.latest_kbd = Some(r.frame),
            HidFrame::AbsMouse { .. } => self.latest_mouse = Some(r.frame),
            HidFrame::SetMode { .. } | HidFrame::Wheel { .. } => {}
        }
        if r.motion_only
            && let Some(tail) = self.items.back_mut()
            && tail.motion_only
            && tail.epoch == r.epoch
        {
            *tail = r;
            return Push::Coalesced;
        }
        if self.items.len() >= self.cap {
            self.items.clear();
            self.resync = true;
            return Push::Resync;
        }
        self.items.push_back(r);
        Push::Queued
    }

    /// The next frame to write at `epoch`; reports of older epochs are
    /// dropped and counted in `discarded`.
    pub fn pop(&mut self, epoch: u64, discarded: &mut u64) -> Option<HidFrame> {
        if let Some(f) = self.out.pop_front() {
            return Some(f);
        }
        while let Some(r) = self.items.pop_front() {
            if r.epoch < epoch {
                *discarded = discarded.saturating_add(1);
                continue;
            }
            return Some(r.frame);
        }
        if self.resync {
            self.resync = false;
            self.out.extend(self.latest_kbd);
            self.out.extend(self.latest_mouse);
            return self.out.pop_front();
        }
        None
    }

    /// Release-all: nothing queued survives; the remembered state becomes
    /// "nothing pressed" at the same position.
    pub fn release(&mut self) {
        self.clear();
        if self.latest_kbd.is_some() {
            self.latest_kbd = Some(KBD_ZERO);
        }
        if let Some(HidFrame::AbsMouse { x, y, .. }) = self.latest_mouse {
            self.latest_mouse = Some(HidFrame::AbsMouse { buttons: 0, x, y });
        }
    }

    pub fn clear(&mut self) {
        self.items.clear();
        self.out.clear();
        self.resync = false;
    }
}

pub struct HidControl {
    epoch: AtomicU64,
    release_pending: AtomicBool,
    notify: Notify,
    queue: Mutex<HidQueue>,
    last_pos: Mutex<Option<(u16, u16)>>,
    pub(crate) metrics: Arc<Metrics>,
}

impl HidControl {
    #[must_use]
    pub fn new(capacity: usize, metrics: Arc<Metrics>) -> HidControl {
        HidControl {
            epoch: AtomicU64::new(0),
            release_pending: AtomicBool::new(false),
            notify: Notify::new(),
            queue: Mutex::new(HidQueue::new(capacity)),
            last_pos: Mutex::new(None),
            metrics,
        }
    }

    fn q(&self) -> MutexGuard<'_, HidQueue> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// Queue one full-state report at the current epoch (never blocks).
    pub fn push(&self, frame: HidFrame, motion_only: bool) -> Push {
        let r = {
            // The epoch is read under the queue lock, which `release_all`
            // also bumps it under: a report can never be stamped before a
            // release and land after it, where it would overwrite the
            // queue's zeroed latest state and come back in a resync.
            let mut q = self.q();
            let epoch = self.epoch();
            q.push(Report {
                epoch,
                frame,
                motion_only,
            })
        };
        match r {
            Push::Coalesced => self.metrics.hid_reports_coalesced.inc(),
            Push::Resync => self.metrics.hid_resyncs.inc(),
            Push::Queued => {}
        }
        self.notify.notify_one();
        r
    }

    /// §7.3/§7.4: bump the epoch, drop everything queued, and have the
    /// writer send the zero reports before anything else.
    pub fn release_all(&self, trigger: ReleaseTrigger) {
        {
            let mut q = self.q();
            self.epoch.fetch_add(1, Ordering::SeqCst);
            self.metrics
                .hid_epoch_discards
                .add(u64::try_from(q.len()).unwrap_or(u64::MAX));
            q.release();
        }
        self.release_pending.store(true, Ordering::SeqCst);
        self.metrics.release_all.inc(trigger.label());
        self.notify.notify_one();
    }

    pub fn take_release(&self) -> bool {
        self.release_pending.swap(false, Ordering::SeqCst)
    }

    pub fn next_frame(&self) -> Option<HidFrame> {
        let mut discarded = 0;
        let f = self.q().pop(self.epoch(), &mut discarded);
        if discarded > 0 {
            self.metrics.hid_epoch_discards.add(discarded);
        }
        f
    }

    /// Reports made while the websocket was down are discarded (§7.3).
    pub fn discard_queued(&self) {
        self.q().clear();
    }

    /// Resolves after a push or release (a permit is kept if none waits).
    pub async fn wait(&self) {
        self.notify.notified().await;
    }

    #[must_use]
    pub fn last_position(&self) -> Option<(u16, u16)> {
        *self.last_pos.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The writer wrote `frame`.
    pub fn note_sent(&self, frame: &HidFrame) {
        if let HidFrame::AbsMouse { x, y, .. } = *frame {
            *self.last_pos.lock().unwrap_or_else(PoisonError::into_inner) = Some((x, y));
        }
        self.metrics.hid_reports_sent.inc();
    }

    /// §7.4: an all-zero keyboard report and a zero-button pointer report at
    /// the last position sent — none if no position was ever sent.
    #[must_use]
    pub fn release_frames(&self) -> Vec<HidFrame> {
        let mut v = vec![KBD_ZERO];
        if let Some((x, y)) = self.last_position() {
            v.push(HidFrame::AbsMouse { buttons: 0, x, y });
        }
        v
    }

    /// §3.3: absolute mode, then the release frames.
    #[must_use]
    pub fn session_start_frames(&self) -> Vec<HidFrame> {
        let mut v = vec![HidFrame::SetMode { hid_type: 0 }];
        v.extend(self.release_frames());
        v
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]
    use super::*;
    use std::time::Duration;

    fn ctl(cap: usize) -> HidControl {
        HidControl::new(cap, Arc::new(Metrics::default()))
    }
    fn kbd(k: u8) -> HidFrame {
        HidFrame::Keyboard {
            modifiers: 0,
            keys: [k, 0, 0, 0, 0],
        }
    }
    fn mouse(buttons: u8, x: u16, y: u16) -> HidFrame {
        HidFrame::AbsMouse { buttons, x, y }
    }
    fn drain(c: &HidControl) -> Vec<HidFrame> {
        std::iter::from_fn(|| c.next_frame()).collect()
    }

    #[test]
    fn reports_come_out_in_order_and_only_motion_coalesces() {
        let c = ctl(16);
        c.push(kbd(4), false);
        c.push(mouse(0, 10, 10), true);
        assert_eq!(c.push(mouse(0, 20, 20), true), Push::Coalesced);
        c.push(kbd(5), false);
        c.push(mouse(1, 20, 20), false);
        c.push(mouse(1, 30, 30), true);
        assert_eq!(
            drain(&c),
            [
                kbd(4),
                mouse(0, 20, 20),
                kbd(5),
                mouse(1, 20, 20),
                mouse(1, 30, 30)
            ]
        );
        assert_eq!(c.metrics.hid_reports_coalesced.get(), 1);
    }

    /// §7.3: release-all bumps the epoch; nothing queued before it is sent
    /// after it.
    #[test]
    fn a_release_discards_every_older_report() {
        let c = ctl(16);
        c.push(kbd(4), false);
        c.push(kbd(5), false);
        c.release_all(ReleaseTrigger::Closing);
        c.push(kbd(6), false);
        assert!(c.take_release());
        assert!(!c.take_release());
        assert_eq!(drain(&c), [kbd(6)]);
        assert_eq!(c.metrics.hid_epoch_discards.get(), 2);
        assert_eq!(c.metrics.release_all.get("closing"), 1);
    }

    /// The race §7.3 names: a report stamped before a release, queued after
    /// it, is still discarded.
    #[test]
    fn a_report_stamped_before_a_release_is_never_popped_after_it() {
        let mut q = HidQueue::new(8);
        q.push(Report {
            epoch: 0,
            frame: kbd(4),
            motion_only: false,
        });
        let mut discarded = 0;
        assert_eq!(q.pop(1, &mut discarded), None);
        assert_eq!(discarded, 1);
    }

    /// §7.3: a full queue is cleared and resynced to the final state.
    #[test]
    fn a_full_queue_resyncs_to_the_final_state() {
        let c = ctl(4);
        for k in 1..=4 {
            assert_eq!(c.push(kbd(k), false), Push::Queued);
        }
        assert_eq!(c.push(kbd(5), false), Push::Resync);
        c.push(mouse(2, 7, 7), false);
        let out = drain(&c);
        assert_eq!(out, [mouse(2, 7, 7), kbd(5), mouse(2, 7, 7)]);
        assert_eq!(c.metrics.hid_resyncs.get(), 1);
    }

    #[test]
    fn a_release_clears_a_pending_resync() {
        let c = ctl(2);
        c.push(kbd(1), false);
        c.push(kbd(2), false);
        c.push(kbd(3), false);
        c.release_all(ReleaseTrigger::Suppression);
        assert!(c.take_release());
        assert_eq!(drain(&c), []);
    }

    /// §3.3/§7.4: zero reports at the last position sent — none before any
    /// position, never a made-up (0, 0).
    #[test]
    fn release_frames_use_the_last_position_sent() {
        let c = ctl(4);
        let zero = HidFrame::Keyboard {
            modifiers: 0,
            keys: [0; 5],
        };
        assert_eq!(c.release_frames(), [zero]);
        assert_eq!(
            c.session_start_frames(),
            [HidFrame::SetMode { hid_type: 0 }, zero]
        );
        c.note_sent(&mouse(1, 300, 400));
        c.note_sent(&kbd(4));
        assert_eq!(c.last_position(), Some((300, 400)));
        assert_eq!(c.release_frames(), [zero, mouse(0, 300, 400)]);
        assert_eq!(
            c.session_start_frames(),
            [HidFrame::SetMode { hid_type: 0 }, zero, mouse(0, 300, 400)]
        );
        assert_eq!(c.metrics.hid_reports_sent.get(), 2);
    }

    #[tokio::test]
    async fn a_push_wakes_the_writer_even_before_it_waits() {
        let c = Arc::new(ctl(4));
        c.push(kbd(4), false);
        tokio::time::timeout(Duration::from_secs(1), c.wait())
            .await
            .unwrap();
        let c2 = c.clone();
        let waiter = tokio::spawn(async move { c2.wait().await });
        tokio::task::yield_now().await;
        c.release_all(ReleaseTrigger::SessionEnd);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
    }
}
