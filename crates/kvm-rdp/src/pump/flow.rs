//! §6.6's flow control, sans-IO: the unacked set mirroring IronRDP's
//! tracker, grace frames, the soft / backlog / standing-delay /
//! back-pressure gates, the stall timer (frozen in Paused and
//! WaitReactivation, disabled while suspended) and the suspended-backlog
//! bound. Arithmetic saturates.
use crate::pump::types::FlowConfig;
use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

/// `queue_depth` meaning "acknowledgements suspended" (MS-RDPEGFX 2.2.2.13).
pub const SUSPEND: u32 = 0xFFFF_FFFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    Open,
    Soft,
    Backlog,
    StandingDelay,
    Backpressure,
}

impl Gate {
    #[must_use]
    pub fn is_open(self) -> bool {
        self == Gate::Open
    }

    /// The `frames_dropped{reason}` label (§10.4).
    #[must_use]
    pub fn drop_reason(self) -> &'static str {
        match self {
            Gate::Open => "none",
            Gate::Soft => "soft_gate",
            Gate::Backlog => "backlog_gate",
            Gate::StandingDelay => "standing_delay",
            Gate::Backpressure => "backpressure",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Sent {
    at: Instant,
    burst: bool,
    grace: bool,
}

#[derive(Debug, Default)]
struct Stall {
    armed: bool,
    elapsed: Duration,
    since: Option<Instant>,
    frozen: bool,
}

impl Stall {
    fn arm(&mut self, now: Instant) {
        if !self.armed {
            self.armed = true;
            self.elapsed = Duration::ZERO;
            self.since = (!self.frozen).then_some(now);
        }
    }
    fn disarm(&mut self) {
        self.armed = false;
        self.elapsed = Duration::ZERO;
        self.since = None;
    }
    fn set_frozen(&mut self, now: Instant, frozen: bool) {
        if frozen == self.frozen {
            return;
        }
        self.frozen = frozen;
        if frozen {
            if let Some(s) = self.since.take() {
                self.elapsed = self
                    .elapsed
                    .saturating_add(now.saturating_duration_since(s));
            }
        } else if self.armed {
            self.since = Some(now);
        }
    }
    fn running(&self, now: Instant) -> Duration {
        self.elapsed.saturating_add(
            self.since
                .map_or(Duration::ZERO, |s| now.saturating_duration_since(s)),
        )
    }
}

/// The auto-detect RTT samples of one generation (§6.6 standing delay).
#[derive(Debug, Default)]
struct Rtt {
    /// The handle's value at the generation's first sample (it is per
    /// server, so it may be the previous connection's).
    reference: Option<u32>,
    active: bool,
    last: Option<u32>,
    unchanged: u32,
    samples: VecDeque<u32>,
    baseline: Option<u32>,
}

impl Rtt {
    /// One read of the handle; true when it is a live sample (in the window).
    /// This is the one place DC6's reference rule lives: the shell feeds
    /// every read, and a generation's first is only the reference.
    fn sample(&mut self, v: u32) -> bool {
        if self.reference.is_none() {
            self.reference = Some(v);
            self.last = Some(v);
            return false;
        }
        if Some(v) == self.last {
            self.unchanged = self.unchanged.saturating_add(1);
        } else {
            self.unchanged = 0;
        }
        self.last = Some(v);
        if v == u32::MAX {
            return false;
        }
        if !self.active && Some(v) != self.reference {
            self.active = true;
        }
        if !self.active {
            return false;
        }
        if self.samples.len() >= 8 {
            self.samples.pop_front();
        }
        self.samples.push_back(v);
        self.baseline = Some(self.baseline.map_or(v, |b| b.min(v)));
        true
    }

    fn standing_ms(&self) -> Option<u32> {
        if !self.active || self.unchanged >= 8 || self.last == Some(u32::MAX) {
            return None;
        }
        // A fixed stack buffer instead of a per-call `Vec`: `samples` never
        // holds more than 8 (the push/pop in `sample` enforces it).
        let mut buf = [0u32; 8];
        let mut len = 0usize;
        for (slot, v) in buf.iter_mut().zip(self.samples.iter()) {
            *slot = *v;
            len = len.saturating_add(1);
        }
        let (filled, _) = buf.split_at_mut(len);
        filled.sort_unstable();
        let median = *filled.get(len / 2)?;
        Some(median.saturating_sub(self.baseline?))
    }
}

pub struct Flow {
    cfg: FlowConfig,
    unacked: BTreeMap<u32, Sent>,
    grace_next_idr: bool,
    /// A suspend ack was seen; the next ordinary ack clears the set first.
    resume_pending: bool,
    handed: u64,
    written: u64,
    rtt: Rtt,
    stall: Stall,
    backlog_since: Option<Instant>,
}

impl Flow {
    #[must_use]
    pub fn new(cfg: FlowConfig) -> Flow {
        Flow {
            cfg,
            unacked: BTreeMap::new(),
            grace_next_idr: true,
            resume_pending: false,
            handed: 0,
            written: 0,
            rtt: Rtt::default(),
            stall: Stall::default(),
            backlog_since: None,
        }
    }

    /// Setup cleared IronRDP's tracker (§6.6); the next IDR is a grace
    /// frame. The stall timer survives.
    pub fn on_setup(&mut self) {
        self.unacked.clear();
        self.grace_next_idr = true;
    }

    pub fn on_flv_opened(&mut self) {
        self.grace_next_idr = true;
    }

    /// Whether this frame is the grace IDR (consumed by the first IDR).
    pub fn take_grace(&mut self, idr: bool) -> bool {
        if idr && self.grace_next_idr {
            self.grace_next_idr = false;
            true
        } else {
            false
        }
    }

    pub fn add_handed(&mut self, weight: u64) {
        self.handed = self.handed.saturating_add(weight);
    }

    pub fn set_written(&mut self, written: u64) {
        self.written = written;
    }

    #[must_use]
    pub fn backlog(&self) -> u64 {
        self.handed.saturating_sub(self.written)
    }

    /// A frame IronRDP accepted (`Some(frame_id)`); nothing is recorded while
    /// acks are suspended.
    pub fn record(
        &mut self,
        frame_id: u32,
        now: Instant,
        burst: bool,
        grace: bool,
        suspended: bool,
    ) {
        if !suspended {
            self.unacked.insert(
                frame_id,
                Sent {
                    at: now,
                    burst,
                    grace,
                },
            );
        }
    }

    pub fn on_ack(&mut self, frame_id: u32, queue_depth: u32) {
        self.stall.disarm();
        if queue_depth == SUSPEND {
            self.unacked.clear();
            self.resume_pending = true;
            return;
        }
        if self.resume_pending {
            self.unacked.clear();
            self.resume_pending = false;
        }
        self.unacked.remove(&frame_id);
    }

    /// The gates before an AU (`burst` exempts it from the soft gate) or on
    /// a tick; a closure arms the stall timer unless acks are suspended.
    pub fn gates(
        &mut self,
        now: Instant,
        burst: bool,
        suspended: bool,
        backpressure: bool,
    ) -> Gate {
        let g = self.check(now, burst, suspended, backpressure);
        if suspended {
            self.stall.disarm();
        } else if g != Gate::Open {
            self.stall.arm(now);
        }
        g
    }

    fn check(&self, now: Instant, burst: bool, suspended: bool, backpressure: bool) -> Gate {
        if !suspended
            && !burst
            && self
                .oldest_gated(now)
                .is_some_and(|at| now.saturating_duration_since(at) >= self.cfg.soft_gate)
        {
            return Gate::Soft;
        }
        if self.backlog() >= self.cfg.backlog_limit {
            return Gate::Backlog;
        }
        if self
            .rtt
            .standing_ms()
            .is_some_and(|ms| Duration::from_millis(u64::from(ms)) >= self.cfg.standing_delay_limit)
        {
            return Gate::StandingDelay;
        }
        if !suspended && backpressure {
            return Gate::Backpressure;
        }
        Gate::Open
    }

    /// The oldest unacked frame that is neither burst nor in its grace.
    fn oldest_gated(&self, now: Instant) -> Option<Instant> {
        self.unacked
            .values()
            .filter(|s| {
                !(s.burst
                    || (s.grace && now.saturating_duration_since(s.at) < self.cfg.first_ack_grace))
            })
            .map(|s| s.at)
            .min()
    }

    pub fn set_frozen(&mut self, now: Instant, frozen: bool) {
        self.stall.set_frozen(now, frozen);
    }

    #[must_use]
    pub fn stall_expired(&self, now: Instant, suspended: bool) -> bool {
        !suspended && self.stall.armed && self.stall.running(now) >= self.cfg.stall_timeout
    }

    pub fn suspended_backlog_expired(&mut self, now: Instant, suspended: bool) -> bool {
        if suspended && self.backlog() >= self.cfg.backlog_limit {
            let since = *self.backlog_since.get_or_insert(now);
            now.saturating_duration_since(since) >= self.cfg.stall_timeout
        } else {
            self.backlog_since = None;
            false
        }
    }

    /// True when `v` was taken as a live sample (not the reference, not
    /// `u32::MAX`, not before the handle first moved).
    pub fn rtt_sample(&mut self, v: u32) -> bool {
        self.rtt.sample(v)
    }

    #[must_use]
    pub fn standing_delay_ms(&self) -> Option<u32> {
        self.rtt.standing_ms()
    }

    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.unacked.len()
    }

    /// When an unacked frame was handed to IronRDP (the §10.4 ack RTT).
    #[must_use]
    pub fn sent_at(&self, frame_id: u32) -> Option<Instant> {
        self.unacked.get(&frame_id).map(|s| s.at)
    }

    #[must_use]
    pub fn oldest_age(&self, now: Instant) -> Duration {
        self.unacked
            .values()
            .map(|s| now.saturating_duration_since(s.at))
            .max()
            .unwrap_or(Duration::ZERO)
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

    fn cfg() -> FlowConfig {
        FlowConfig {
            soft_gate: Duration::from_millis(500),
            backlog_limit: 4 << 20,
            standing_delay_limit: Duration::from_millis(500),
            first_ack_grace: Duration::from_millis(1600),
            stall_timeout: Duration::from_secs(10),
        }
    }

    struct Clock(Instant);
    impl Clock {
        fn at(&self, ms: u64) -> Instant {
            self.0 + Duration::from_millis(ms)
        }
    }

    /// §6.6 grace: a first ack slower than `soft_gate` but within
    /// `first_ack_grace` does not close the soft gate.
    #[test]
    fn a_grace_frame_tolerates_a_slow_first_ack() {
        let c = Clock(Instant::now());
        let mut f = Flow::new(cfg());
        f.on_setup();
        let grace = f.take_grace(true);
        assert!(grace && !f.take_grace(true), "one grace IDR per Setup");
        f.record(0, c.at(0), false, grace, false);
        assert_eq!(f.gates(c.at(1000), false, false, false), Gate::Open);
        assert_eq!(f.gates(c.at(1700), false, false, false), Gate::Soft);
        f.on_ack(0, 0);
        assert_eq!(f.gates(c.at(1700), false, false, false), Gate::Open);
    }

    /// §6.6 grace: only an IDR consumes the flag (never a P-frame, M8), and
    /// an FLV open re-arms it the same as a Setup (M9).
    #[test]
    fn grace_applies_only_to_an_idr_and_an_flv_open_rearms_it() {
        let mut f = Flow::new(cfg());
        f.on_setup();
        assert!(!f.take_grace(false), "a P-frame is never grace");
        assert!(f.take_grace(true));
        f.on_flv_opened();
        assert!(f.take_grace(true), "an FLV open re-arms grace");
    }

    /// §6.6: the soft gate is the age of the oldest unacked frame, so a
    /// 5 fps → 60 fps transition never closes it.
    #[test]
    fn the_soft_gate_is_time_based_so_fps_changes_do_not_close_it() {
        let c = Clock(Instant::now());
        let mut f = Flow::new(cfg());
        let mut id = 0u32;
        let mut t = 0u64;
        // (frame period, ack delay): 5 fps idle, then 60 fps motion — at 60
        // fps two frames are in flight where at 5 fps there was one.
        let mut pending: VecDeque<(u32, u64)> = VecDeque::new();
        let mut most = 0;
        for (period, ack_after) in [(200u64, 100u64), (16, 30)] {
            for _ in 0..60 {
                while let Some(&(pid, due)) = pending.front() {
                    if due > t {
                        break;
                    }
                    f.on_ack(pid, 0);
                    pending.pop_front();
                }
                assert_eq!(f.gates(c.at(t), false, false, false), Gate::Open, "t={t}");
                f.record(id, c.at(t), false, false, false);
                pending.push_back((id, t + ack_after));
                most = most.max(f.in_flight());
                id += 1;
                t += period;
            }
        }
        assert!(most >= 2, "the 60 fps phase had more in flight: {most}");
    }

    /// §6.5/§6.6: burst frames are exempt; live frames after a burst are
    /// gated on the oldest non-burst, non-grace frame.
    #[test]
    fn burst_frames_are_exempt_and_live_frames_gate_on_the_oldest_non_burst() {
        let c = Clock(Instant::now());
        let mut f = Flow::new(cfg());
        for id in 0..10 {
            f.record(id, c.at(0), true, false, false);
        }
        assert_eq!(f.gates(c.at(900), true, false, false), Gate::Open);
        assert_eq!(
            f.gates(c.at(900), false, false, false),
            Gate::Open,
            "only burst frames are old"
        );
        f.record(10, c.at(900), false, false, false);
        assert_eq!(f.gates(c.at(1300), false, false, false), Gate::Open);
        assert_eq!(f.gates(c.at(1450), false, false, false), Gate::Soft);
        assert_eq!(
            f.gates(c.at(1450), true, false, false),
            Gate::Open,
            "a burst AU skips the soft gate"
        );
        assert_eq!(
            f.gates(c.at(1450), true, false, true),
            Gate::Backpressure,
            "but not the hard cap"
        );
    }

    /// §6.6 stall: arms at the first closure, survives a Setup, is frozen in
    /// Paused/WaitReactivation, fires at `stall_timeout`; any ack disarms.
    #[test]
    fn the_stall_arms_survives_setup_freezes_and_fires() {
        let c = Clock(Instant::now());
        let mut f = Flow::new(cfg());
        f.record(0, c.at(0), false, false, false);
        assert_eq!(f.gates(c.at(600), false, false, false), Gate::Soft);
        f.on_setup();
        f.set_frozen(c.at(2_000), true);
        assert!(!f.stall_expired(c.at(20_000), false), "frozen");
        f.set_frozen(c.at(20_000), false);
        assert!(!f.stall_expired(c.at(28_000), false));
        assert!(f.stall_expired(c.at(28_700), false), "1.4 s + 8.7 s ≥ 10 s");
        assert!(
            !f.stall_expired(c.at(28_700), true),
            "disabled while suspended"
        );
        f.on_ack(99, 0);
        assert!(!f.stall_expired(c.at(40_000), false), "any ack disarms");
    }

    /// §6.6 stall: an open gate never arms the timer (M2), and a second
    /// closure while already armed does not restart the clock (M1).
    #[test]
    fn the_stall_arms_only_once_at_the_first_closure() {
        let c = Clock(Instant::now());
        let mut f = Flow::new(cfg());
        assert_eq!(f.gates(c.at(0), false, false, false), Gate::Open);
        assert!(
            !f.stall_expired(c.at(20_000), false),
            "an open gate never arms"
        );

        let mut f = Flow::new(cfg());
        f.record(0, c.at(0), false, false, false);
        assert_eq!(f.gates(c.at(600), false, false, false), Gate::Soft);
        assert_eq!(f.gates(c.at(5_000), false, false, false), Gate::Soft);
        assert!(
            f.stall_expired(c.at(10_600), false),
            "armed at 600, not re-armed at 5 000"
        );
    }

    /// §6.6: the soft gate is bypassed while acks are suspended, even for a
    /// frame recorded before suspension began (M11).
    #[test]
    fn the_soft_gate_is_bypassed_while_suspended() {
        let c = Clock(Instant::now());
        let mut f = Flow::new(cfg());
        f.record(0, c.at(0), false, false, false);
        assert_eq!(f.gates(c.at(1_000), false, true, false), Gate::Open);
    }

    /// §6.6 suspension: nothing is recorded, the soft gate and back-pressure
    /// are bypassed; the first non-suspend ack clears the set first.
    #[test]
    fn suspended_acks_record_nothing_and_a_resume_clears_the_set() {
        let c = Clock(Instant::now());
        let mut f = Flow::new(cfg());
        f.record(0, c.at(0), false, false, false);
        f.record(1, c.at(0), false, false, false);
        f.on_ack(0, SUSPEND);
        assert_eq!(f.in_flight(), 0);
        f.record(2, c.at(10), false, false, true);
        assert_eq!(f.in_flight(), 0, "nothing recorded while suspended");
        assert_eq!(f.gates(c.at(5_000), false, true, true), Gate::Open);
        f.record(3, c.at(5_000), false, false, false);
        f.on_ack(2, 0);
        assert_eq!(
            f.in_flight(),
            0,
            "the resume ack cleared the set before removing its own id"
        );
        assert_eq!(f.gates(c.at(5_100), false, false, false), Gate::Open);
    }

    /// §6.6: while suspended, backlog held ≥ the limit for `stall_timeout`
    /// is a stall; a dip resets it.
    #[test]
    fn suspended_backlog_held_for_the_stall_timeout_is_a_stall() {
        let c = Clock(Instant::now());
        let mut f = Flow::new(cfg());
        f.add_handed(5 << 20);
        assert!(!f.suspended_backlog_expired(c.at(0), true));
        f.set_written(2 << 20);
        assert!(
            !f.suspended_backlog_expired(c.at(5_000), true),
            "dipped below the limit"
        );
        f.set_written(0);
        assert!(!f.suspended_backlog_expired(c.at(6_000), true));
        assert!(
            !f.suspended_backlog_expired(c.at(12_000), true),
            "the dip restarted the clock at 6 s"
        );
        assert!(f.suspended_backlog_expired(c.at(16_000), true));
        assert!(
            !f.suspended_backlog_expired(c.at(16_000), false),
            "only while suspended"
        );
    }

    /// §6.6 backlog gate with the per-generation counter; acks for unknown
    /// ids are ignored and nothing underflows.
    #[test]
    fn the_backlog_gate_follows_the_counter_and_nothing_underflows() {
        let c = Clock(Instant::now());
        let mut f = Flow::new(cfg());
        f.add_handed(5 << 20);
        assert_eq!(f.gates(c.at(0), false, false, false), Gate::Backlog);
        f.set_written(2 << 20);
        assert_eq!(f.gates(c.at(0), false, false, false), Gate::Open);
        f.set_written(9 << 20);
        assert_eq!(f.backlog(), 0);
        // An unknown id does not corrupt the set (M10); a stale repeat of an
        // already-removed id is a no-op, not a second removal.
        f.record(0, c.at(0), false, false, false);
        f.record(1, c.at(0), false, false, false);
        assert_eq!(f.in_flight(), 2);
        f.on_ack(77, 0);
        assert_eq!(f.in_flight(), 2, "an unknown id is ignored");
        f.on_ack(1, 0);
        assert_eq!(f.in_flight(), 1);
        f.on_ack(1, 0);
        assert_eq!(f.in_flight(), 1, "a stale repeat is ignored");
        f.on_ack(0, 0);
        assert_eq!(f.in_flight(), 0);
    }

    /// §6.6 standing delay: inactive before this generation's first sample,
    /// median − baseline against the limit, and a stale handle (unchanged
    /// for 8 probes, or `u32::MAX`) is no signal.
    #[test]
    fn standing_delay_needs_a_live_signal() {
        let c = Clock(Instant::now());
        let mut f = Flow::new(cfg());
        f.rtt_sample(900); // the previous connection's last value: a reference only
        assert_eq!(f.standing_delay_ms(), None);
        for v in [10, 12, 11] {
            f.rtt_sample(v);
        }
        assert_eq!(f.standing_delay_ms(), Some(1));
        for v in [600, 700, 650, 620, 640] {
            f.rtt_sample(v);
        }
        assert_eq!(f.gates(c.at(0), false, false, false), Gate::StandingDelay);
        for _ in 0..8 {
            f.rtt_sample(640);
        }
        assert_eq!(f.standing_delay_ms(), None, "unchanged for 8 probes");
        assert_eq!(f.gates(c.at(0), false, false, false), Gate::Open);
        f.rtt_sample(u32::MAX);
        assert_eq!(f.standing_delay_ms(), None);
    }

    /// §6.6 standing delay, pinned precisely: a repeated reference still has
    /// not moved (M7); the window is exactly the last 8 live samples, so an
    /// older one is evicted (M5); the baseline is the minimum since this
    /// generation began, not just of the current window (M6); and
    /// "unchanged" means consecutive repeats, not a lifetime count (M23).
    #[test]
    fn standing_delay_tracks_a_sliding_median_against_a_lifetime_baseline() {
        let mut f = Flow::new(cfg());
        assert!(!f.rtt_sample(10), "reference");
        assert!(!f.rtt_sample(10), "the reference repeated has not moved");
        assert_eq!(f.standing_delay_ms(), None);
        assert!(f.rtt_sample(5));
        for v in 600..608 {
            assert!(f.rtt_sample(v));
        }
        assert_eq!(
            f.standing_delay_ms(),
            Some(604 - 5),
            "median of the last 8 (600..=607, the 5 evicted) minus the min since start"
        );
        f.rtt_sample(607); // one repeat
        f.rtt_sample(610); // moves again
        for _ in 0..7 {
            f.rtt_sample(610);
        }
        assert!(
            f.standing_delay_ms().is_some(),
            "8 repeats across the test in all, but never 8 consecutive"
        );
    }
}
