//! §6.9 framing-violation accounting: a violation is transient (FLV
//! reconnect) unless it is the third within 60 s, which is fatal
//! `stream_corrupt`. Sans-IO: the caller passes `now`.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use core::time::Duration;
use std::collections::VecDeque;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationVerdict {
    /// Reconnect the FLV.
    Transient,
    /// Disconnect with `stream_corrupt`.
    Fatal,
}

/// Sliding-window counter of framing violations.
#[derive(Debug, Clone)]
pub struct ViolationWindow {
    threshold: usize,
    window: Duration,
    recent: VecDeque<Instant>,
}

impl ViolationWindow {
    /// `threshold` violations within `window` are fatal (`threshold` ≥ 1).
    #[must_use]
    pub fn new(threshold: usize, window: Duration) -> Self {
        let threshold = threshold.max(1);
        ViolationWindow {
            threshold,
            window,
            // `record` never holds more than `threshold` entries (the
            // cap-pop below), but `threshold` is caller-supplied
            // configuration, not hostile stream input; `with_capacity`
            // with an absurd value (e.g. `usize::MAX`) panics with
            // "capacity overflow" (fix round 1, m2), so cap the eager
            // allocation instead of trusting the argument.
            recent: VecDeque::with_capacity(threshold.min(8)),
        }
    }

    /// §6.9's rule: three within 60 s.
    #[must_use]
    pub fn stream_corrupt() -> Self {
        Self::new(3, Duration::from_secs(60))
    }

    /// Record one violation at `now`.
    pub fn record(&mut self, now: Instant) -> ViolationVerdict {
        while let Some(&oldest) = self.recent.front() {
            if now.saturating_duration_since(oldest) >= self.window {
                self.recent.pop_front();
            } else {
                break;
            }
        }
        if self.recent.len() >= self.threshold {
            self.recent.pop_front();
        }
        self.recent.push_back(now);
        if self.recent.len() >= self.threshold {
            ViolationVerdict::Fatal
        } else {
            ViolationVerdict::Transient
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects)]
    use super::*;

    #[test]
    fn the_third_violation_within_sixty_seconds_is_fatal() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let mut w = ViolationWindow::stream_corrupt();
        assert_eq!(w.record(t0), ViolationVerdict::Transient);
        assert_eq!(w.record(t0 + s(30)), ViolationVerdict::Transient);
        assert_eq!(w.record(t0 + s(59)), ViolationVerdict::Fatal);
    }

    #[test]
    fn violations_older_than_the_window_drop_out() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let mut w = ViolationWindow::stream_corrupt();
        w.record(t0);
        w.record(t0 + s(30));
        // The first is 60 s old by now: only two remain in the window.
        assert_eq!(w.record(t0 + s(60)), ViolationVerdict::Transient);
        assert_eq!(w.record(t0 + s(61)), ViolationVerdict::Fatal);
    }

    /// `new` is a `pub` constructor a caller can misconfigure; it must not
    /// panic however large `threshold` is (fix round 1, m2).
    #[test]
    fn a_huge_threshold_does_not_panic_on_construction() {
        let mut w = ViolationWindow::new(usize::MAX, Duration::from_secs(60));
        assert_eq!(w.record(Instant::now()), ViolationVerdict::Transient);
    }

    /// Storage never grows past `threshold`, however many violations land
    /// inside the window (fix round 1, m3).
    #[test]
    fn storage_never_exceeds_the_threshold() {
        let t0 = Instant::now();
        let mut w = ViolationWindow::stream_corrupt();
        for i in 0..10u64 {
            w.record(t0 + Duration::from_millis(i));
        }
        assert_eq!(w.recent.len(), 3);
    }
}
