//! `security.accept_rate` (§5.1, §9.1): at most `rate` admitted TCP accepts
//! per sliding `window`, across all peers. Only admissions are counted
//! (DC15), so the memory is `rate` instants and a refused flood cannot
//! extend its own lockout. Refusals are also tallied for the log, which
//! reports them at most once per `REFUSAL_LOG_INTERVAL` (m8): a TCP flood
//! must not become a log flood, and `kvm_rdp_accept_refused` already
//! counts every one.
use std::collections::VecDeque;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// At most one refusal log line per interval.
pub const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(10);

pub struct AcceptRate {
    rate: usize,
    window: Duration,
    admitted: VecDeque<Instant>,
    /// Refusals since the last report line.
    unreported: u64,
    last_report: Option<Instant>,
}

impl AcceptRate {
    #[must_use]
    pub fn new(rate: u32, window: Duration) -> AcceptRate {
        AcceptRate {
            rate: usize::try_from(rate).unwrap_or(usize::MAX),
            window,
            admitted: VecDeque::new(),
            unreported: 0,
            last_report: None,
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
            self.unreported = self.unreported.saturating_add(1);
            return false;
        }
        self.admitted.push_back(now);
        true
    }

    /// After a refusal: `Some(n)` when a log line is due — the first
    /// refusal, then at most one per `REFUSAL_LOG_INTERVAL` — with `n` the
    /// refusals since the previous line, this one included.
    pub fn refusal_report(&mut self, now: Instant) -> Option<u64> {
        if self.unreported == 0
            || self
                .last_report
                .is_some_and(|t| now.saturating_duration_since(t) < REFUSAL_LOG_INTERVAL)
        {
            return None;
        }
        self.last_report = Some(now);
        Some(std::mem::take(&mut self.unreported))
    }

    #[cfg(test)]
    fn held(&self) -> usize {
        self.admitted.len()
    }
}

/// How long an admitted connection counts as handshaking without being
/// reported finished (DC21, PC15 review m4). IronRDP reports nothing for a
/// Preempt candidate that fails NLA or is dropped at the handoff, and does
/// not bound a fresh connection's TLS and CredSSP, so a silent peer must not
/// hold a renewal off for ever. A real one is done well inside this: its
/// candidate negotiation is bounded at 10 s, the handoff and eviction graces
/// at 0.75 s each, and the winner's finalize at 30 s.
pub const HANDSHAKE_GRACE: Duration = Duration::from_secs(45);
/// At most this many handshakes are tracked (the accept rate bounds them
/// far lower; this bounds the memory whatever it is set to).
pub const MAX_HANDSHAKES: usize = 1024;

/// Connections between `on_accept` and their session's start (or their end
/// before one): DC21's "a client is connected" counts these as well as a
/// live generation. Each is an anonymous admission time; a finish retires
/// the oldest (the conservative choice: the younger ones expire later).
/// The lock is held only to push, pop or prune — never across an await,
/// never while calling IronRDP.
pub struct Handshakes {
    grace: Duration,
    admitted: Mutex<VecDeque<Instant>>,
}

impl Handshakes {
    #[must_use]
    pub fn new(grace: Duration) -> Handshakes {
        Handshakes {
            grace,
            admitted: Mutex::new(VecDeque::new()),
        }
    }

    /// How long an unfinished handshake counts, and the longest handshakes
    /// alone may hold a pending renewal off (m4).
    #[must_use]
    pub fn grace(&self) -> Duration {
        self.grace
    }

    /// `on_accept` admitted a connection at `now`.
    pub fn admit(&self, now: Instant) {
        let mut q = self.admitted.lock().unwrap_or_else(PoisonError::into_inner);
        if q.len() >= MAX_HANDSHAKES {
            q.pop_front();
        }
        q.push_back(now);
    }

    /// One handshake ended: its session began, or it went before one did.
    pub fn finish(&self) {
        self.admitted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front();
    }

    /// Admitted connections still handshaking at `now`.
    #[must_use]
    pub fn in_flight(&self, now: Instant) -> usize {
        let mut q = self.admitted.lock().unwrap_or_else(PoisonError::into_inner);
        while q
            .front()
            .is_some_and(|&t| now.saturating_duration_since(t) > self.grace)
        {
            q.pop_front();
        }
        q.len()
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

    /// m8: a refused flood is reported as one line now, then at most one
    /// line per `REFUSAL_LOG_INTERVAL`, each carrying the refusals since the
    /// line before it.
    #[test]
    fn refusals_are_reported_once_per_interval_with_their_count() {
        let t0 = Instant::now();
        let mut r = AcceptRate::new(1, s(60));
        assert!(r.admit(t0));
        assert_eq!(r.refusal_report(t0), None, "nothing refused yet");
        let mut lines = Vec::new();
        for i in 1..=25_000u64 {
            let now = t0 + Duration::from_millis(i);
            assert!(!r.admit(now));
            if let Some(n) = r.refusal_report(now) {
                lines.push((i, n));
            }
        }
        assert_eq!(lines, [(1, 1), (10_001, 10_000), (20_001, 10_000)]);
        assert_eq!(REFUSAL_LOG_INTERVAL, s(10));
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

    /// DC21 (PC15 review m4): a connection counts as handshaking from its
    /// admission until it finishes; one never reported finished (a failed
    /// Preempt candidate, a silent TCP peer) stops counting after the grace.
    #[test]
    fn handshakes_count_until_they_finish_or_the_grace_runs_out() {
        let t0 = Instant::now();
        let h = Handshakes::new(s(45));
        assert_eq!(h.in_flight(t0), 0);
        h.admit(t0);
        h.admit(t0 + s(1));
        assert_eq!(h.in_flight(t0 + s(2)), 2);
        h.finish();
        assert_eq!(h.in_flight(t0 + s(2)), 1);
        assert_eq!(
            h.in_flight(t0 + s(45)),
            1,
            "the younger one counts until its own grace"
        );
        assert_eq!(h.in_flight(t0 + s(47)), 0, "never finished: expired");
        h.finish();
        h.finish();
        assert_eq!(h.in_flight(t0 + s(47)), 0, "finishing nothing is a no-op");
        h.admit(t0 + s(50));
        assert_eq!(h.in_flight(t0 + s(50)), 1, "no finish was banked");
    }

    /// The tracker's memory is capped whatever the admissions do.
    #[test]
    fn the_handshake_tracker_is_bounded() {
        let t0 = Instant::now();
        let h = Handshakes::new(s(45));
        for _ in 0..(MAX_HANDSHAKES * 3) {
            h.admit(t0);
        }
        assert_eq!(h.in_flight(t0), MAX_HANDSHAKES);
        assert_eq!(HANDSHAKE_GRACE, s(45));
    }
}
