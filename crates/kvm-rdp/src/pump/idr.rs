//! §6.5's IDR acquisition, sans-IO. A Setup cause requests an IDR (except
//! the first Setup, whose `OpenFlv` serves); a flow cause starts idr-wait
//! accounting and requests once the gates were open for `idr_wait_max`;
//! an FLV open never requests. Two clocks rate-limit requests; one inside
//! its clock's window is deferred to the window's end and cancelled if an
//! IDR arrives, an FLV opens, or the pump leaves NeedIdr first. Under
//! `side`, a request that brings no IDR within `idr_side_timeout` falls
//! back to a `ReconnectFlv` on the same clock.
use crate::config::IdrPolicy;
use crate::pump::types::IdrConfig;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdrAction {
    RequestIdr,
    ReconnectFlv,
    /// A `side` request's fallback (`ReconnectFlv` + a metric).
    FallbackReconnect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Clock {
    Setup,
    Flow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Primary,
    Fallback,
}

pub struct IdrCore {
    cfg: IdrConfig,
    /// When the last request went out or the last FLV opened: both clocks.
    last_issue: Option<Instant>,
    deferred: Option<(Instant, Clock, Kind)>,
    waiting: bool,
    wait_accum: Duration,
    wait_open_since: Option<Instant>,
    /// An outstanding `side` request: when, and on which clock.
    fallback: Option<(Instant, Clock)>,
}

impl IdrCore {
    #[must_use]
    pub fn new(cfg: IdrConfig) -> IdrCore {
        IdrCore {
            cfg,
            last_issue: None,
            deferred: None,
            waiting: false,
            wait_accum: Duration::ZERO,
            wait_open_since: None,
            fallback: None,
        }
    }

    /// A Setup (re-advertise, resize, leaving Paused). The caller does not
    /// call this for a connection's first Setup.
    pub fn setup_cause(&mut self, now: Instant) -> Option<IdrAction> {
        self.request(now, Clock::Setup, Kind::Primary)
    }

    /// A gate closed, an IDR was dropped, `send_avc420_frame` refused, an
    /// AU was dropped on a full channel, a burst was truncated, or
    /// `SpsChanged{other}`.
    pub fn flow_cause(&mut self, _now: Instant) {
        if self.cfg.policy != IdrPolicy::Wait && !self.waiting {
            self.waiting = true;
            self.wait_accum = Duration::ZERO;
            self.wait_open_since = None;
        }
    }

    /// Idr-wait accounting: the gates' state now.
    pub fn observe_gates(&mut self, now: Instant, open: bool) -> Option<IdrAction> {
        if !self.waiting {
            return None;
        }
        match (open, self.wait_open_since) {
            (true, None) => self.wait_open_since = Some(now),
            (false, Some(s)) => {
                self.wait_accum = self
                    .wait_accum
                    .saturating_add(now.saturating_duration_since(s));
                self.wait_open_since = None;
            }
            _ => {}
        }
        let total = self.wait_accum.saturating_add(
            self.wait_open_since
                .map_or(Duration::ZERO, |s| now.saturating_duration_since(s)),
        );
        if total >= self.cfg.wait_max {
            self.waiting = false;
            return self.request(now, Clock::Flow, Kind::Primary);
        }
        None
    }

    /// Any FLV open (first, transient, commanded): clears an outstanding
    /// request, resets idr-wait and restarts both clocks; never requests.
    /// True when a deferred request was cancelled (P26: counted).
    pub fn flv_opened(&mut self, now: Instant) -> bool {
        let cancelled = self.deferred.take().is_some();
        self.fallback = None;
        self.reset_wait();
        self.last_issue = Some(now);
        cancelled
    }

    /// The pump left NeedIdr (an IDR went out, or Paused, WaitReactivation,
    /// Closing). True when a deferred request was cancelled.
    pub fn resolve(&mut self) -> bool {
        self.fallback = None;
        self.reset_wait();
        self.deferred.take().is_some()
    }

    pub fn tick(&mut self, now: Instant) -> Option<IdrAction> {
        if let Some((at, clock, kind)) = self.deferred
            && now >= at
        {
            self.deferred = None;
            return self.issue(now, clock, kind);
        }
        if let Some((at, clock)) = self.fallback
            && now >= at + self.cfg.side_timeout
        {
            self.fallback = None;
            return self.request(now, clock, Kind::Fallback);
        }
        None
    }

    fn interval(&self, clock: Clock) -> Duration {
        match clock {
            Clock::Setup => self.cfg.interval_setup,
            Clock::Flow => self.cfg.interval_flow,
        }
    }

    fn request(&mut self, now: Instant, clock: Clock, kind: Kind) -> Option<IdrAction> {
        if self.cfg.policy == IdrPolicy::Wait {
            return None;
        }
        if let Some(t) = self.last_issue {
            let end = t + self.interval(clock);
            if now < end {
                if self.deferred.is_none_or(|(at, _, _)| at > end) {
                    self.deferred = Some((end, clock, kind));
                }
                return None;
            }
        }
        self.issue(now, clock, kind)
    }

    fn issue(&mut self, now: Instant, clock: Clock, kind: Kind) -> Option<IdrAction> {
        self.last_issue = Some(now);
        self.deferred = None;
        self.reset_wait();
        match (self.cfg.policy, kind) {
            (IdrPolicy::Wait, _) => None,
            (IdrPolicy::Side, Kind::Primary) => {
                self.fallback = Some((now, clock));
                Some(IdrAction::RequestIdr)
            }
            (IdrPolicy::Reconnect, Kind::Primary) => {
                self.fallback = None;
                Some(IdrAction::ReconnectFlv)
            }
            (_, Kind::Fallback) => {
                self.fallback = None;
                Some(IdrAction::FallbackReconnect)
            }
        }
    }

    fn reset_wait(&mut self) {
        self.waiting = false;
        self.wait_accum = Duration::ZERO;
        self.wait_open_since = None;
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
    use crate::config::IdrPolicy;

    fn core(policy: IdrPolicy) -> (IdrCore, impl Fn(u64) -> Instant) {
        let t0 = Instant::now();
        let cfg = IdrConfig {
            policy,
            side_timeout: Duration::from_secs(1),
            wait_max: Duration::from_secs(3),
            interval_setup: Duration::from_secs(1),
            interval_flow: Duration::from_secs(10),
        };
        (IdrCore::new(cfg), move |ms| t0 + Duration::from_millis(ms))
    }

    /// Ticks every 10 ms over (from, to], collecting actions.
    fn ticks(
        c: &mut IdrCore,
        at: &impl Fn(u64) -> Instant,
        from: u64,
        to: u64,
    ) -> Vec<(u64, IdrAction)> {
        (from / 10 + 1..=to / 10)
            .filter_map(|i| c.tick(at(i * 10)).map(|a| (i * 10, a)))
            .collect()
    }

    /// §11.2: two Setup causes 300 ms apart → exactly two `RequestIdr`, the
    /// second deferred to the window's end.
    #[test]
    fn two_setup_causes_300ms_apart_are_two_requests_the_second_deferred() {
        let (mut c, at) = core(IdrPolicy::Side);
        assert_eq!(c.setup_cause(at(0)), Some(IdrAction::RequestIdr));
        assert_eq!(c.setup_cause(at(300)), None);
        let got = ticks(&mut c, &at, 300, 1500);
        assert_eq!(got, [(1000, IdrAction::RequestIdr)]);
    }

    /// §11.2: a deferred request whose NeedIdr is resolved by an IDR inside
    /// the window is cancelled, and nothing more is requested.
    #[test]
    fn a_deferred_request_resolved_by_an_idr_is_cancelled() {
        let (mut c, at) = core(IdrPolicy::Side);
        c.setup_cause(at(0));
        c.setup_cause(at(300));
        assert!(c.resolve(), "the deferred request is cancelled");
        assert_eq!(ticks(&mut c, &at, 300, 5000), []);
    }

    /// §11.2: no IDR within `idr_side_timeout` of a `RequestIdr` → exactly one
    /// `ReconnectFlv`, at the window's end.
    #[test]
    fn no_idr_within_the_side_timeout_falls_back_to_one_reconnect() {
        let (mut c, at) = core(IdrPolicy::Side);
        assert_eq!(c.setup_cause(at(0)), Some(IdrAction::RequestIdr));
        assert_eq!(
            ticks(&mut c, &at, 0, 5000),
            [(1000, IdrAction::FallbackReconnect)]
        );
    }

    /// §6.5: a flow cause starts idr-wait accounting; the request comes only
    /// once the gates were open for a cumulative `idr_wait_max` — flapping
    /// does not reset it — on the flow clock.
    #[test]
    fn a_flow_cause_requests_after_cumulative_open_gate_time() {
        let (mut c, at) = core(IdrPolicy::Side);
        c.flow_cause(at(0));
        assert_eq!(c.observe_gates(at(0), true), None);
        assert_eq!(c.observe_gates(at(2000), false), None, "2 s open");
        assert_eq!(
            c.observe_gates(at(5000), true),
            None,
            "closed time does not count"
        );
        assert_eq!(c.observe_gates(at(5900), true), None);
        assert_eq!(
            c.observe_gates(at(6000), true),
            Some(IdrAction::RequestIdr),
            "2 s + 1 s"
        );
    }

    /// §6.5: any FLV open clears a pending request, cancels a deferred one
    /// (and says so, P26), resets idr-wait and restarts both clocks; it never
    /// requests.
    #[test]
    fn an_flv_open_clears_everything_and_restarts_the_clocks() {
        let (mut c, at) = core(IdrPolicy::Side);
        c.setup_cause(at(0));
        c.setup_cause(at(300));
        c.flow_cause(at(300));
        c.observe_gates(at(300), true);
        assert!(c.flv_opened(at(400)), "the deferred request is cancelled");
        assert_eq!(
            ticks(&mut c, &at, 400, 3000),
            [],
            "no deferred, no fallback, no idr-wait request"
        );
        assert_eq!(
            c.setup_cause(at(1200)),
            None,
            "the setup clock restarted at 400"
        );
        assert_eq!(
            ticks(&mut c, &at, 1200, 1500),
            [(1400, IdrAction::RequestIdr)]
        );
        assert!(
            !c.flv_opened(at(1500)),
            "nothing deferred: nothing cancelled"
        );
    }

    #[test]
    fn reconnect_policy_reconnects_and_has_no_fallback() {
        let (mut c, at) = core(IdrPolicy::Reconnect);
        assert_eq!(c.setup_cause(at(0)), Some(IdrAction::ReconnectFlv));
        assert_eq!(ticks(&mut c, &at, 0, 5000), []);
    }

    #[test]
    fn wait_policy_never_requests() {
        let (mut c, at) = core(IdrPolicy::Wait);
        assert_eq!(c.setup_cause(at(0)), None);
        c.flow_cause(at(0));
        assert_eq!(c.observe_gates(at(0), true), None);
        assert_eq!(c.observe_gates(at(60_000), true), None);
        assert_eq!(ticks(&mut c, &at, 0, 5000), []);
    }

    /// A flow-clock request's fallback waits for the flow window (10 s).
    #[test]
    fn a_flow_requests_fallback_lands_at_the_flow_windows_end() {
        let (mut c, at) = core(IdrPolicy::Side);
        c.flow_cause(at(0));
        c.observe_gates(at(0), true);
        assert_eq!(c.observe_gates(at(3000), true), Some(IdrAction::RequestIdr));
        assert_eq!(
            ticks(&mut c, &at, 3000, 14_000),
            [(13_000, IdrAction::FallbackReconnect)]
        );
    }

    /// §6.5 rate limit, no storm: a Setup cause every 10 ms for 5 s (a
    /// client re-advertising in a loop) is one request per
    /// `interval_setup`, never more than one action at an instant, and
    /// leaves nothing queued behind it but the last request's one fallback.
    #[test]
    fn a_flood_of_setup_causes_is_one_request_per_window() {
        let (mut c, at) = core(IdrPolicy::Side);
        let mut got = Vec::new();
        for t in (0..=5000).step_by(10) {
            got.extend(c.setup_cause(at(t)).map(|a| (t, a)));
            got.extend(c.tick(at(t)).map(|a| (t, a)));
        }
        got.extend(ticks(&mut c, &at, 5000, 10_000));
        let mut want: Vec<_> = (0..=5).map(|s| (s * 1000, IdrAction::RequestIdr)).collect();
        want.push((6000, IdrAction::FallbackReconnect));
        assert_eq!(got, want);
    }

    /// §6.5 rate limit, no storm: flow causes on every 10 ms sample with the
    /// gates open for 30 s are one request per `interval_flow` — the first
    /// after `idr_wait_max`, its fallback deferred to the flow window's end,
    /// and the next request a full window after that.
    #[test]
    fn a_flood_of_flow_causes_is_one_request_per_flow_window() {
        let (mut c, at) = core(IdrPolicy::Side);
        let mut got = Vec::new();
        for t in (0..=30_000).step_by(10) {
            c.flow_cause(at(t));
            got.extend(c.observe_gates(at(t), true).map(|a| (t, a)));
            got.extend(c.tick(at(t)).map(|a| (t, a)));
        }
        assert_eq!(
            got,
            [
                (3000, IdrAction::RequestIdr),
                (13_000, IdrAction::FallbackReconnect),
                (23_000, IdrAction::RequestIdr)
            ]
        );
    }
}
