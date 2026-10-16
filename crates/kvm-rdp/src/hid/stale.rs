//! Plan E Task 1.5 (spec §7.4 rev 6.3, Plan D final review m3): a stalled
//! RDP runtime must not leave a key held. The input core, its driver and
//! both §7.4 timers run on the RDP thread (§4.3); stalled, nothing steps
//! them, and only `/livez`'s restart would heal it. This task runs on the
//! KVM runtime, which the stall does not reach: once the RDP heartbeat is
//! older than `RDP_STALE_RELEASE` while the queue's newest state holds a
//! key or a button, it calls release-all — once per stale episode.
use crate::admin::Health;
use crate::hid::{HidControl, ReleaseTrigger};
use std::sync::Arc;
use std::time::Duration;

/// How old the RDP heartbeat may be before held input is released: three
/// heartbeat periods (DE16, controller ruling 11; §12 said "about 1 s"), so
/// a single late beat never reads as a stall.
pub const RDP_STALE_RELEASE: Duration = Duration::from_secs(3);
/// The heartbeat's longest period, §4.5's cap (bridge.rs's clamp; idle CPU
/// rests on it: PC15 m2's ~21 wakeups per 10 s).
pub const HEARTBEAT_MAX: Duration = Duration::from_secs(1);
/// How often the watch reads the heartbeat's age once it is past the bound
/// (before that it sleeps until the bound: `next_check`).
pub const WATCH_EVERY: Duration = Duration::from_millis(100);
/// How far past the bound the watch first looks: a millisecond, tokio's
/// timer resolution, so the age it reads then is over the bound.
const PAST_THE_BOUND: Duration = Duration::from_millis(1);

const _: () = assert!(RDP_STALE_RELEASE.as_millis() >= 3 * HEARTBEAT_MAX.as_millis());

/// How long the watch sleeps after reading `age`: until the heartbeat could
/// first be over the bound — `RDP_STALE_RELEASE` past its last beat, plus
/// `PAST_THE_BOUND` — and every `WATCH_EVERY` while it is. A fresh beat
/// meanwhile only moves the next look on, so on a healthy bridge the watch
/// wakes once every two or three heartbeats: never a fixed 100 ms poll,
/// which would cost the idle KVM runtime ~100 wakeups per 10 s on top of
/// PC15 m2's ~21.
#[must_use]
pub fn next_check(age: Duration) -> Duration {
    match RDP_STALE_RELEASE.checked_sub(age) {
        Some(left) => left.saturating_add(PAST_THE_BOUND),
        None => WATCH_EVERY,
    }
}

/// The decision, apart from the clock and the queue: release once per
/// stale episode, re-armed when the heartbeat is fresh again.
#[derive(Debug, Default)]
pub struct StaleWatch {
    fired: bool,
}

impl StaleWatch {
    /// Whether to release now, given the heartbeat's `age`; `held` (the
    /// queue's newest state holds something) is read only when stale.
    pub fn step(&mut self, age: Duration, held: impl FnOnce() -> bool) -> bool {
        if age <= RDP_STALE_RELEASE {
            self.fired = false;
            return false;
        }
        if self.fired || !held() {
            return false;
        }
        self.fired = true;
        true
    }
}

/// The watch, an essential KVM-runtime task (bridge.rs): the heartbeat's
/// age and, when stale, whether input is held — read again `next_check`
/// later. Never returns.
pub async fn run(health: Arc<Health>, hid: Arc<HidControl>) {
    let mut watch = StaleWatch::default();
    loop {
        let age = health.rdp_age();
        if watch.step(age, || hid.newest_holds()) {
            tracing::warn!("the RDP runtime stopped with input held: released all");
            hid.release_all(ReleaseTrigger::RdpStale);
        }
        tokio::time::sleep(next_check(age)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// m3: a stale episode releases once, and only while something is
    /// held; a fresh heartbeat re-arms it. The bound itself is not stale.
    #[test]
    fn a_stale_episode_releases_once_and_only_while_held() {
        let mut w = StaleWatch::default();
        let fresh = Duration::from_millis(300);
        let stale = RDP_STALE_RELEASE + Duration::from_millis(1);
        assert!(!w.step(fresh, || true), "fresh: never");
        assert!(!w.step(RDP_STALE_RELEASE, || true), "at the bound: not yet");
        assert!(
            !w.step(stale, || false),
            "stale, nothing held: nothing to release"
        );
        assert!(w.step(stale, || true), "stale and held: release");
        assert!(!w.step(stale * 3, || true), "once per episode");
        assert!(!w.step(fresh, || true), "fresh again: re-armed");
        assert!(w.step(stale, || true), "the next episode releases again");
    }

    /// `held` is read only once the heartbeat is stale: the watch takes no
    /// queue lock every 100 ms on a healthy bridge.
    #[test]
    fn held_is_read_only_when_stale() {
        let mut w = StaleWatch::default();
        let mut reads = 0;
        let _ = w.step(Duration::from_millis(10), || {
            reads += 1;
            true
        });
        assert_eq!(reads, 0);
    }

    /// DE16 (controller ruling 11): the bound is three heartbeats at
    /// §4.5's 1 s cap, so one late beat never reads as a stall.
    #[test]
    fn the_bound_is_three_heartbeats() {
        assert_eq!(RDP_STALE_RELEASE, Duration::from_secs(3));
        assert_eq!(HEARTBEAT_MAX, Duration::from_secs(1));
        assert!(RDP_STALE_RELEASE >= HEARTBEAT_MAX * 3);
        assert!(WATCH_EVERY < RDP_STALE_RELEASE / 5);
    }

    /// DE16, by its behaviour and in literal milliseconds (not the
    /// constant, so a lowered bound fails here): a beat one or two periods
    /// late, or exactly 3 s old, releases nothing; one past 3 s does.
    #[test]
    fn a_late_beat_never_releases_and_one_past_3_s_does() {
        for late in [1_000u64, 2_000, 2_999, 3_000] {
            let mut w = StaleWatch::default();
            assert!(!w.step(Duration::from_millis(late), || true), "{late} ms");
        }
        let mut w = StaleWatch::default();
        assert!(w.step(Duration::from_millis(3_001), || true));
    }

    /// The schedule: from any age up to the bound the watch looks again
    /// just past it — never later than a watch period past it, never at it
    /// — and once past it, every `WATCH_EVERY`.
    #[test]
    fn the_watch_looks_again_just_past_the_bound() {
        for ms in [0u64, 1, 250, 999, 1_000, 2_000, 2_999, 3_000] {
            let age = Duration::from_millis(ms);
            let at = age + next_check(age);
            assert!(
                at > RDP_STALE_RELEASE && at <= RDP_STALE_RELEASE + WATCH_EVERY,
                "{ms} ms: next look at {at:?}"
            );
        }
        for ms in [3_001u64, 3_100, 60_000] {
            assert_eq!(
                next_check(Duration::from_millis(ms)),
                WATCH_EVERY,
                "{ms} ms"
            );
        }
    }

    /// PC15 m2's idle budget: with the heartbeat beating every second, the
    /// watch wakes at most once per two beats over a minute — a fixed
    /// 100 ms poll would wake 600 times — and never releases.
    #[test]
    fn a_healthy_heartbeat_wakes_the_watch_at_most_every_two_beats() {
        let mut w = StaleWatch::default();
        let (mut now, mut wakes) = (Duration::ZERO, 0u32);
        while now < Duration::from_secs(60) {
            // The last beat: the last whole second.
            let age = now - Duration::from_secs(now.as_secs());
            assert!(!w.step(age, || true), "a release at {now:?}");
            wakes += 1;
            now += next_check(age);
        }
        assert!(wakes <= 30, "{wakes} wakeups in 60 s");
    }
}
