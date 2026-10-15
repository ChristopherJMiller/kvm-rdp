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
    /// The client's `Synchronize` (§7.4), raised by the input core.
    Synchronize,
    /// `key_repeat_timeout` (§7.4), raised by the input core's timer.
    KeyRepeat,
    /// `modifier_idle_timeout` (§7.4), raised by the input core's timer.
    ModifierIdle,
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
            ReleaseTrigger::Synchronize => "synchronize",
            ReleaseTrigger::KeyRepeat => "key_repeat",
            ReleaseTrigger::ModifierIdle => "modifier_idle",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Report {
    pub epoch: u64,
    pub frame: HidFrame,
    /// Only the pointer moved (no button or key change): coalescable.
    pub motion_only: bool,
}

/// §4.5 (PD5 ruling): a queued report is a keystroke; `Debug` shows its
/// epoch and motion flag, and the frame only as `HidFrame`'s redacted kind.
impl std::fmt::Debug for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Report")
            .field("epoch", &self.epoch)
            .field("frame", &self.frame)
            .field("motion_only", &self.motion_only)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Push {
    Queued,
    Coalesced,
    /// The queue was full: cleared, and the final state goes out next.
    Resync,
    /// Stamped before a release that has since happened: dropped whole —
    /// neither queued nor kept as resync state (§7.3; PC7 fix round 1, I1).
    Discarded,
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
        self.push_at(self.epoch(), frame, motion_only)
    }

    /// Queue a report stamped with the epoch its state was built at, taken
    /// before the queue lock. If a release has moved the epoch since — it won
    /// the lock first — the report is dropped whole: not queued, and not
    /// written into the resync state the release just zeroed, so a
    /// pre-release key can neither go out after the zero reports nor come
    /// back in a later resync (§7.3; §7.4 "never a down-up-down glitch";
    /// PC7 fix round 1, I1).
    pub(crate) fn push_at(&self, stamp: u64, frame: HidFrame, motion_only: bool) -> Push {
        let r = {
            let mut q = self.q();
            if self.epoch() == stamp {
                q.push(Report {
                    epoch: stamp,
                    frame,
                    motion_only,
                })
            } else {
                Push::Discarded
            }
        };
        match r {
            Push::Coalesced => self.metrics.hid_reports_coalesced.inc(),
            Push::Resync => self.metrics.hid_resyncs.inc(),
            Push::Discarded => {
                // Nothing new to write: no wake-up.
                self.metrics.hid_epoch_discards.inc();
                return r;
            }
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
            // Under the lock (PC7 m2): `next_frame` sees the flag and the
            // cleared queue together.
            self.release_pending.store(true, Ordering::SeqCst);
        }
        self.metrics.release_all.inc(trigger.label());
        self.notify.notify_one();
    }

    pub fn take_release(&self) -> bool {
        self.release_pending.swap(false, Ordering::SeqCst)
    }

    /// The next report to write — `None` while a release is pending, so the
    /// zero reports always go first (§7.3 "services it before anything
    /// else"; PC7 m2).
    pub fn next_frame(&self) -> Option<HidFrame> {
        let mut discarded = 0;
        let f = {
            let mut q = self.q();
            if self.release_pending.load(Ordering::SeqCst) {
                return None;
            }
            q.pop(self.epoch(), &mut discarded)
        };
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

    /// PD5 ruling (§4.5): a queued report is a keystroke; its `Debug`
    /// keeps the epoch and the motion flag, and redacts the frame.
    #[test]
    fn a_reports_debug_never_prints_its_frame() {
        let r = |frame| Report {
            epoch: 3,
            frame,
            motion_only: false,
        };
        let a = r(HidFrame::Keyboard {
            modifiers: 0xA7,
            keys: [0x1E, 0x2C, 0x3B, 0x5D, 0x6F],
        });
        let b = r(kbd(0));
        crate::testkit::assert_debug_redacted(&a, &b, &[0xA7, 0x1E, 0x2C, 0x3B, 0x5D, 0x6F]);
        assert!(format!("{a:?}").contains("epoch: 3"), "{a:?}");
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

    /// §10.4: the input core's three triggers (Task 2.2) widen the
    /// `release_all{trigger}` family, each under its own label.
    #[test]
    fn the_input_cores_triggers_are_counted_under_their_labels() {
        let c = ctl(4);
        for (t, label) in [
            (ReleaseTrigger::Synchronize, "synchronize"),
            (ReleaseTrigger::KeyRepeat, "key_repeat"),
            (ReleaseTrigger::ModifierIdle, "modifier_idle"),
        ] {
            assert_eq!(t.label(), label);
            let before = c.epoch();
            c.release_all(t);
            assert_eq!(c.epoch(), before + 1);
            assert_eq!(c.metrics.release_all.get(label), 1);
        }
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

    /// PC7 I1, §7.3/§7.4: a report stamped before a release that lands after
    /// it — the input handler built it, then lost the race for the queue
    /// lock to `release_all` — is dropped whole: never sent after the zero
    /// reports, and never kept as the state a later resync replays.
    #[test]
    fn a_report_stamped_before_a_release_and_pushed_after_it_is_dropped_whole() {
        let c = ctl(2);
        c.push(kbd(9), false); // a key held before the release
        let stamp = c.epoch();
        c.release_all(ReleaseTrigger::Closing);
        let pushed = c.push_at(stamp, kbd(4), false);
        assert!(c.take_release());
        assert_eq!(
            drain(&c),
            [],
            "a pre-release report went out after the zeros"
        );
        // Overflow the queue: the resync replays the zeroed keyboard state.
        for i in 1..=3 {
            c.push(mouse(0, i, i), false);
        }
        assert_eq!(
            drain(&c),
            [KBD_ZERO, mouse(0, 3, 3)],
            "the resync re-pressed a key"
        );
        assert_eq!(pushed, Push::Discarded);
        // `kbd(9)` cleared by the release, `kbd(4)` dropped at the push.
        assert_eq!(c.metrics.hid_epoch_discards.get(), 2);
    }

    /// PC7 I2: a release zeroes the keyboard half of the resync state — a
    /// later overflow never re-presses a key held before the release.
    #[test]
    fn a_resync_after_a_release_replays_no_key_held_before_it() {
        let c = ctl(2);
        c.push(kbd(4), false);
        c.release_all(ReleaseTrigger::Closing);
        assert!(c.take_release());
        for i in 1..=3 {
            c.push(mouse(0, i, i), false);
        }
        assert_eq!(drain(&c), [KBD_ZERO, mouse(0, 3, 3)]);
    }

    /// PC7 I2: a release zeroes the pointer's buttons in the resync state —
    /// a later overflow never re-presses a button held before the release.
    #[test]
    fn a_resync_after_a_release_replays_no_button_held_before_it() {
        let c = ctl(2);
        c.push(mouse(1, 9, 9), false);
        c.release_all(ReleaseTrigger::Closing);
        assert!(c.take_release());
        for k in 1..=3 {
            c.push(kbd(k), false);
        }
        assert_eq!(drain(&c), [kbd(3), mouse(0, 9, 9)]);
    }

    /// PC7 m2, §7.3 ("services it before anything else"): a release raised
    /// after the writer last looked for one still goes out before a report
    /// pushed after it — no frame is handed out while a release is pending.
    #[test]
    fn no_frame_is_handed_out_while_a_release_is_pending() {
        let c = ctl(8);
        assert!(!c.take_release()); // the writer looked: nothing pending
        c.release_all(ReleaseTrigger::Closing);
        c.push(kbd(2), false); // fresh input after the release
        assert_eq!(c.next_frame(), None, "a report went out before the zeros");
        assert!(c.take_release());
        assert_eq!(c.next_frame(), Some(kbd(2)));
    }
}
