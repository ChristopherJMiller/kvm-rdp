use core::time::Duration;
use std::collections::VecDeque;
use std::time::Instant;

/// How far back, in receive time, the burst baseline looks (§6.2, rev 6.2).
pub const BURST_WINDOW: Duration = Duration::from_secs(1);

/// Bound on the baseline window: a hostile source cannot grow it.
const MAX_SAMPLES: usize = 256;

/// Marks access units that arrive faster than real time — a GOP-caching
/// source replaying on connect (§6.2). An AU is a burst when its delivery
/// delay (receive time − FLV timestamp) is more than `threshold` below the
/// median delay of the AUs received in the last `BURST_WINDOW` on this FLV
/// connection (rev 6.2, DC1). A replay is marked; a late first tag, a past
/// replay or one late tag mid-stream is outvoted by the on-time AUs around
/// it and marks nothing after it. State is per FLV connection; `reset`
/// starts afresh. The caller (`video::VideoAdmission::coded`) calls `mark`
/// for coded tags only.
pub struct BurstMarker {
    /// Receive-time origin of this connection (its first marked tag).
    epoch: Option<Instant>,
    /// `(receive ms since epoch, delay ms)` in arrival order: at most
    /// `MAX_SAMPLES`, none older than `BURST_WINDOW`.
    window: VecDeque<(i64, i64)>,
    /// Scratch for the median, reused so `mark` does not allocate.
    sorted: Vec<i64>,
    threshold: Duration,
}

impl BurstMarker {
    pub fn new(threshold: Duration) -> Self {
        Self {
            epoch: None,
            window: VecDeque::with_capacity(MAX_SAMPLES),
            sorted: Vec::with_capacity(MAX_SAMPLES),
            threshold,
        }
    }

    pub fn reset(&mut self) {
        self.epoch = None;
        self.window.clear();
    }

    /// Record a tag's FLV timestamp (ms) and receive time; returns whether
    /// it is a burst. The first call after construction or `reset` is never
    /// a burst.
    pub fn mark(&mut self, flv_ts_ms: u32, now: Instant) -> bool {
        let epoch = *self.epoch.get_or_insert(now);
        let recv =
            i64::try_from(now.saturating_duration_since(epoch).as_millis()).unwrap_or(i64::MAX);
        let delay = recv.saturating_sub(i64::from(flv_ts_ms));
        let window = i64::try_from(BURST_WINDOW.as_millis()).unwrap_or(i64::MAX);
        while let Some(&(at, _)) = self.window.front() {
            if recv.saturating_sub(at) > window {
                self.window.pop_front();
            } else {
                break;
            }
        }
        self.sorted.clear();
        self.sorted.extend(self.window.iter().map(|&(_, d)| d));
        self.sorted.sort_unstable();
        let threshold = i64::try_from(self.threshold.as_millis()).unwrap_or(i64::MAX);
        let mid = self.sorted.len() >> 1;
        let burst = self
            .sorted
            .get(mid)
            .is_some_and(|&median| delay < median.saturating_sub(threshold));
        if self.window.len() >= MAX_SAMPLES {
            self.window.pop_front();
        }
        self.window.push_back((recv, delay));
        burst
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::as_conversions
    )]
    use super::*;
    use core::time::Duration;
    use std::time::Instant;

    #[test]
    fn first_is_never_burst_then_detects_replay() {
        let t0 = Instant::now();
        let mut m = BurstMarker::new(Duration::from_millis(100));
        assert!(!m.mark(1000, t0)); // baseline
        assert!(m.mark(1500, t0 + Duration::from_millis(300))); // 200 ms ahead > 100 ms
        assert!(!m.mark(1200, t0 + Duration::from_millis(300))); // behind real time
    }

    #[test]
    fn reset_rebaselines_on_new_connection() {
        let t0 = Instant::now();
        let mut m = BurstMarker::new(Duration::from_millis(100));
        assert!(!m.mark(1000, t0));
        m.reset();
        assert!(!m.mark(9999, t0 + Duration::from_millis(50))); // new baseline, not a burst
    }

    /// I3 (Plan B final review): a GOP-caching replay is marked, and the
    /// live frames that follow stop being marked within `BURST_WINDOW` —
    /// the old baseline, fixed at the first coded tag, marked 300 of 300.
    #[test]
    fn a_replay_is_marked_and_live_frames_after_it_stop_within_the_window() {
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let mut m = BurstMarker::new(Duration::from_millis(100));
        // 60 frames (2 s of timestamps) replayed in 60 ms of receive time …
        let replayed = (0..60u32)
            .filter(|&i| m.mark(i * 33, at(u64::from(i))))
            .count();
        assert_eq!(
            replayed, 54,
            "frames 6..=59 run > 100 ms below the median delay before them"
        );
        // … then live at the real cadence, 1920 ms ahead of the first tag.
        let mut marked = Vec::new();
        for j in 60..360u32 {
            let recv = u64::from(j) * 33 - 1920;
            if m.mark(j * 33, at(recv)) {
                marked.push(recv);
            }
        }
        assert!(marked.len() <= 31, "{} live frames marked", marked.len());
        assert!(
            marked.iter().all(|&r| r <= 1100),
            "a live frame was marked after the window: {marked:?}"
        );
    }

    /// I3's second scenario: a real-time source whose first coded tag is
    /// read 150 ms late (the bridge busy at connect) — every later AU was
    /// marked; now none is.
    #[test]
    fn a_late_first_tag_marks_nothing_after_it() {
        let t0 = Instant::now();
        let mut m = BurstMarker::new(Duration::from_millis(100));
        let mut marked = Vec::new();
        for i in 0..300u32 {
            let recv = u64::from(i * 33).max(150);
            if m.mark(i * 33, t0 + Duration::from_millis(recv)) {
                marked.push(recv);
            }
        }
        assert!(
            marked.is_empty(),
            "{} frames marked, the first {:?}",
            marked.len(),
            marked.first()
        );
    }

    /// The census's worst https inter-tag gap (136 ms, `census.md` Leg A):
    /// frame 100 read 103 ms late with 101..=103 in the same read, then on
    /// time. A baseline at the window's *largest* delay would mark the next
    /// second of on-time AUs (about 30); the median marks none.
    #[test]
    fn one_late_tag_mid_stream_marks_nothing_after_it() {
        let t0 = Instant::now();
        let mut m = BurstMarker::new(Duration::from_millis(100));
        let mut marked = Vec::new();
        for i in 0..300u32 {
            let recv = if (100..=103).contains(&i) {
                100 * 33 + 103
            } else {
                u64::from(i * 33)
            };
            if m.mark(i * 33, t0 + Duration::from_millis(recv)) {
                marked.push(i);
            }
        }
        assert!(
            marked.is_empty(),
            "{} frames marked, the first {:?}",
            marked.len(),
            marked.first()
        );
    }

    /// A hostile stream (every tag at one instant) cannot grow the window.
    /// P11 (preflight, Minor): 2 000 iterations, not 100 000 — the 256 cap
    /// is reached after 256 calls regardless, and this keeps the test fast
    /// at opt-level 0.
    #[test]
    fn the_baseline_window_is_bounded_under_a_hostile_stream() {
        let t0 = Instant::now();
        let mut m = BurstMarker::new(Duration::from_millis(100));
        for i in 0..2_000u32 {
            let _ = m.mark(i, t0);
        }
        assert!(m.window.len() <= 256, "{}", m.window.len());
    }
}
