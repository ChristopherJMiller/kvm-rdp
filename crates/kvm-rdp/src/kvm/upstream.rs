//! The KVM side's sans-IO cores (§4.3): reconnect backoff with jitter, the
//! auth rule (re-login once, §6.9) and the upstream deadline. Callers pass
//! `now`; nothing here sleeps or reads a clock except `Jitter::from_clock`.
use crate::config::BackoffConfig;
use std::time::{Duration, Instant};

/// splitmix64: enough randomness to keep reconnects from synchronising.
pub struct Jitter(u64);

impl Jitter {
    #[must_use]
    pub fn new(seed: u64) -> Jitter {
        Jitter(seed)
    }
    #[must_use]
    pub fn from_clock() -> Jitter {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        Jitter(u64::from(nanos) ^ u64::from(std::process::id()).rotate_left(32))
    }
    /// The next draw (not `next`: clippy's `should_implement_trait`).
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// `kvm.backoff` (§4.4): one per connection kind; the caller resets it once
/// the connection proves healthy.
pub struct Backoff {
    cfg: BackoffConfig,
    attempt: u32,
    rng: Jitter,
}

impl Backoff {
    #[must_use]
    pub fn new(cfg: BackoffConfig, rng: Jitter) -> Backoff {
        Backoff {
            cfg,
            attempt: 0,
            rng,
        }
    }

    pub fn next_delay(&mut self) -> Duration {
        let base = (0..self.attempt).fold(self.cfg.initial, |d, _| {
            d.saturating_mul(self.cfg.factor).min(self.cfg.max)
        });
        let base = base.min(self.cfg.max);
        self.attempt = self.attempt.saturating_add(1).min(64);
        let base_us = u64::try_from(base.as_micros()).unwrap_or(u64::MAX);
        let span = base_us.saturating_mul(u64::from(self.cfg.jitter_percent)) / 100;
        if span == 0 {
            return base;
        }
        let offset = self.rng.next_u64() % span.saturating_mul(2).saturating_add(1);
        Duration::from_micros(base_us.saturating_sub(span).saturating_add(offset))
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStep {
    /// Log in again (once).
    Relogin,
    /// A newer token exists or a re-login is in flight: retry with it.
    Wait,
    /// `kvm_auth_failed`.
    Fatal,
}

/// §6.9 auth: an auth failure re-logs in once; a second consecutive failure
/// with no successful re-login in between is fatal. Tokens are numbered so
/// a refusal of an already-replaced token (the websocket and the FLV both
/// hitting a global logout) counts once.
#[derive(Debug, Default)]
pub struct AuthGate {
    consecutive: u8,
    seq: u64,
    pending: bool,
}

impl AuthGate {
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn login_ok(&mut self) {
        self.consecutive = 0;
        self.seq = self.seq.saturating_add(1);
        self.pending = false;
    }

    pub fn login_rejected(&mut self) -> AuthStep {
        self.pending = true;
        self.bump()
    }

    /// A request made with token `seq` was refused (401/403/`result: 403`).
    pub fn refused(&mut self, seq: u64) -> AuthStep {
        if seq < self.seq || self.pending {
            return AuthStep::Wait;
        }
        self.pending = true;
        self.bump()
    }

    fn bump(&mut self) -> AuthStep {
        self.consecutive = self.consecutive.saturating_add(1);
        if self.consecutive >= 2 {
            AuthStep::Fatal
        } else {
            AuthStep::Relogin
        }
    }
}

/// §6.9 deadline: no successful login within `limit` of Start, or no FLV
/// tag within `limit` of the first open or of losing the FLV.
#[derive(Debug)]
pub struct Deadline {
    limit: Duration,
    login_by: Option<Instant>,
    tag_by: Option<Instant>,
}

impl Deadline {
    #[must_use]
    pub fn new(limit: Duration) -> Deadline {
        Deadline {
            limit,
            login_by: None,
            tag_by: None,
        }
    }
    pub fn started(&mut self, now: Instant) {
        self.login_by = Some(now + self.limit);
    }
    pub fn logged_in(&mut self) {
        self.login_by = None;
    }
    pub fn flv_wanted(&mut self, now: Instant) {
        self.tag_by.get_or_insert(now + self.limit);
    }
    pub fn tag(&mut self) {
        self.tag_by = None;
    }
    pub fn flv_lost(&mut self, now: Instant) {
        self.tag_by.get_or_insert(now + self.limit);
    }
    #[must_use]
    pub fn expired(&self, now: Instant) -> bool {
        self.login_by.is_some_and(|t| now >= t) || self.tag_by.is_some_and(|t| now >= t)
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

    fn cfg(jitter: u32) -> BackoffConfig {
        BackoffConfig {
            initial: Duration::from_millis(250),
            factor: 2,
            max: Duration::from_secs(8),
            jitter_percent: jitter,
        }
    }

    /// §4.4: 250 ms ×2 → 8 s.
    #[test]
    fn backoff_doubles_to_its_cap_and_resets() {
        let mut b = Backoff::new(cfg(0), Jitter::new(1));
        let got: Vec<u64> = (0..8)
            .map(|_| u64::try_from(b.next_delay().as_millis()).unwrap())
            .collect();
        assert_eq!(got, [250, 500, 1000, 2000, 4000, 8000, 8000, 8000]);
        b.reset();
        assert_eq!(b.next_delay(), Duration::from_millis(250));
    }

    /// ±20 %: every draw in [0.8, 1.2] × the base, and they differ.
    #[test]
    fn backoff_jitter_stays_inside_twenty_percent() {
        let mut seen = std::collections::BTreeSet::new();
        for seed in 0..200 {
            let mut b = Backoff::new(cfg(20), Jitter::new(seed));
            let d = b.next_delay().as_micros();
            assert!((200_000..=300_000).contains(&d), "{d}");
            seen.insert(d);
        }
        assert!(seen.len() > 50, "jitter is not spreading: {}", seen.len());
    }

    /// §6.9: re-login once; a second consecutive failure with no successful
    /// re-login in between is fatal; a success resets the count.
    #[test]
    fn the_auth_gate_allows_one_relogin_per_failure_run() {
        let mut g = AuthGate::default();
        assert_eq!(
            g.login_rejected(),
            AuthStep::Relogin,
            "the first login rejected: retry once"
        );
        assert_eq!(
            g.login_rejected(),
            AuthStep::Fatal,
            "rejected twice running"
        );

        let mut g = AuthGate::default();
        g.login_ok();
        let s1 = g.seq();
        assert_eq!(g.refused(s1), AuthStep::Relogin, "token expiry");
        assert_eq!(
            g.refused(s1),
            AuthStep::Wait,
            "the websocket refused with the same stale token"
        );
        g.login_ok();
        assert_eq!(
            g.refused(s1),
            AuthStep::Wait,
            "an older token's refusal after the re-login"
        );
        assert_eq!(
            g.refused(g.seq()),
            AuthStep::Relogin,
            "expiry again, after a successful re-login"
        );
        assert_eq!(
            g.login_rejected(),
            AuthStep::Fatal,
            "then the re-login is rejected"
        );
    }

    /// §6.9 deadline: login within the limit of Start; a tag within the
    /// limit of the first open, or of losing the FLV.
    #[test]
    fn the_deadline_covers_login_and_tags() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let mut d = Deadline::new(Duration::from_secs(20));
        d.started(t0);
        assert!(!d.expired(at(19)) && d.expired(at(20)));
        d.logged_in();
        assert!(!d.expired(at(100)));
        d.flv_wanted(at(100));
        assert!(d.expired(at(120)));
        d.tag();
        assert!(!d.expired(at(500)));
        d.flv_lost(at(500));
        d.flv_lost(at(510));
        assert!(
            d.expired(at(520)),
            "losing it again does not extend the deadline"
        );
        d.tag();
        assert!(!d.expired(at(600)));
    }
}
