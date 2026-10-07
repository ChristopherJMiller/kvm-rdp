use core::time::Duration;
use std::time::Instant;

/// Marks access units that arrive faster than real time — a GOP-caching
/// source replaying on connect (§6.2). State is per FLV connection; `reset`
/// re-baselines from the next connection's first call to `mark` — the
/// caller (`video::VideoAdmission::coded`) calls `mark` only for coded
/// tags, so in practice that is the connection's first *coded* tag, not any
/// sequence header ahead of it (D11; fix round 1, P10/m5).
pub struct BurstMarker {
    baseline: Option<(u32, Instant)>,
    threshold: Duration,
}

impl BurstMarker {
    pub fn new(threshold: Duration) -> Self {
        Self {
            baseline: None,
            threshold,
        }
    }

    pub fn reset(&mut self) {
        self.baseline = None;
    }

    /// Record a tag's FLV timestamp (ms) and receive time; returns whether
    /// it is a burst. The first call after construction or `reset` sets the
    /// baseline and is never a burst (D11: the caller drives this from the
    /// connection's first *coded* tag, not its sequence header).
    pub fn mark(&mut self, flv_ts_ms: u32, now: Instant) -> bool {
        match self.baseline {
            None => {
                self.baseline = Some((flv_ts_ms, now));
                false
            }
            Some((ts0, recv0)) => {
                let flv_elapsed = u128::from(flv_ts_ms.saturating_sub(ts0));
                let recv_elapsed = now.saturating_duration_since(recv0).as_millis();
                let bound = recv_elapsed.saturating_add(self.threshold.as_millis());
                flv_elapsed > bound
            }
        }
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
}
