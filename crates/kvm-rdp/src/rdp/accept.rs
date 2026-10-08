//! `security.accept_rate` (§5.1, §9.1): at most `rate` admitted TCP accepts
//! per sliding `window`, across all peers. Only admissions are counted
//! (DC15), so the memory is `rate` instants and a refused flood cannot
//! extend its own lockout.
use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub struct AcceptRate {
    rate: usize,
    window: Duration,
    admitted: VecDeque<Instant>,
}

impl AcceptRate {
    #[must_use]
    pub fn new(rate: u32, window: Duration) -> AcceptRate {
        AcceptRate {
            rate: usize::try_from(rate).unwrap_or(usize::MAX),
            window,
            admitted: VecDeque::new(),
        }
    }

    pub fn admit(&mut self, now: Instant) -> bool {
        while let Some(&t) = self.admitted.front() {
            if now.saturating_duration_since(t) < self.window {
                break;
            }
            self.admitted.pop_front();
        }
        if self.admitted.len() >= self.rate {
            return false;
        }
        self.admitted.push_back(now);
        true
    }

    #[cfg(test)]
    fn held(&self) -> usize {
        self.admitted.len()
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

    fn s(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn admits_the_rate_per_sliding_window() {
        let t0 = Instant::now();
        let mut r = AcceptRate::new(3, s(60));
        assert!(r.admit(t0) && r.admit(t0 + s(1)) && r.admit(t0 + s(2)));
        assert!(!r.admit(t0 + s(3)));
        assert!(!r.admit(t0 + s(59)));
        assert!(
            r.admit(t0 + s(60)),
            "the first admission has left the window"
        );
        assert!(!r.admit(t0 + s(60)));
    }

    /// DC15: refusals are not counted, so a refused flood cannot extend its
    /// own lockout past the window.
    #[test]
    fn a_refused_flood_does_not_extend_the_lockout() {
        let t0 = Instant::now();
        let mut r = AcceptRate::new(1, s(10));
        assert!(r.admit(t0));
        for i in 1..1000u64 {
            assert!(!r.admit(t0 + Duration::from_millis(i)));
        }
        assert!(r.admit(t0 + s(10)));
    }

    #[test]
    fn memory_is_bounded_by_the_rate() {
        let t0 = Instant::now();
        let mut r = AcceptRate::new(5, s(60));
        for i in 0..10_000u64 {
            r.admit(t0 + Duration::from_millis(i));
        }
        assert_eq!(r.held(), 5);
    }
}
