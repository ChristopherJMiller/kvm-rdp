//! Plan E Task 1.5 (spec §7.4 rev 6.3, Plan D final review m3): a stalled
//! RDP runtime must not leave a key held. The input core, its driver and
//! both §7.4 timers run on the RDP thread (§4.3); stalled, nothing steps
//! them, and only `/livez`'s restart would heal it. This task runs on the
//! KVM runtime, which the stall does not reach: once the RDP heartbeat is
//! older than `RDP_STALE_RELEASE` while input is held (`held`: what was
//! written, or the queue's newest state, holds a key or a button), it
//! calls release-all — once per stale episode.
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

/// What the watch reads as held input: what was written holds a key or a
/// button, or the queue's newest state does (`HidControl::input_held`).
/// The newest state alone misses one case (PE4 review I1): a typing push
/// that resyncs the queue zeroes it (`push_typing_at`) while the KVM still
/// holds the Typist's last press written, until the abort's release-all
/// µs later — a stall that begins there would keep that key held.
pub fn held(hid: &HidControl) -> bool {
    hid.input_held()
}

/// The watch's release, then its line — in that order (PE4 review m1):
/// stdout is a synchronous writer, and a line stuck on a blocked pipe must
/// not hold the release back.
fn release(hid: &HidControl) {
    hid.release_all(ReleaseTrigger::RdpStale);
    tracing::warn!("the RDP runtime stopped with input held: released all");
}

/// The watch, an essential KVM-runtime task (bridge.rs): the heartbeat's
/// age and, when stale, whether input is held — read again `next_check`
/// later. Never returns.
pub async fn run(health: Arc<Health>, hid: Arc<HidControl>) {
    let mut watch = StaleWatch::default();
    loop {
        let age = health.rdp_age();
        if watch.step(age, || held(&hid)) {
            release(&hid);
        }
        tokio::time::sleep(next_check(age)).await;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use crate::hid::Push;
    use crate::metrics::Metrics;
    use kvm_proto::hid::HidFrame;

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

    const KBD_ZERO: HidFrame = HidFrame::Keyboard {
        modifiers: 0,
        keys: [0; 5],
    };

    fn press(usage: u8) -> HidFrame {
        HidFrame::Keyboard {
            modifiers: 0,
            keys: [usage, 0, 0, 0, 0],
        }
    }

    fn holds_a_key(f: Option<HidFrame>) -> bool {
        matches!(f, Some(HidFrame::Keyboard { modifiers, keys }) if modifiers != 0 || keys != [0; 5])
    }

    /// PE4 review I1: the m4 window. A typing push that resyncs the queue
    /// zeroes its newest state (`push_typing_at`, PE4 D2) while the KVM
    /// still holds the Typist's last press written, and no release is
    /// pending until the abort's release-all, µs later on the RDP thread.
    /// Only what was written says the KVM holds a key: a stall that begins
    /// there must still be released, so the watch reads held input as
    /// written or newest (`HidControl::input_held`), not the newest alone.
    #[test]
    fn the_watch_sees_the_press_the_kvm_holds_inside_a_typing_resync() {
        // `input.queue`'s least (TYPIST_ROOM + 1).
        let hid = HidControl::new(9, Arc::new(Metrics::default()));
        let e = hid.epoch();
        assert_eq!(hid.push_typing_at(e, press(0x04), false), Push::Queued);
        let written = hid.next_frame().unwrap();
        hid.note_sent(&written); // the writer wrote 'a' down
        let mut pushes = [KBD_ZERO, press(0x05)].into_iter().cycle();
        while hid.push_typing_at(e, pushes.next().unwrap(), false) != Push::Resync {}
        assert!(
            !hid.newest_holds() && hid.next_frame().is_none() && !hid.take_release(),
            "precondition: the window — newest state zeroed, nothing to write, no release"
        );
        let stale = RDP_STALE_RELEASE + Duration::from_millis(1);
        assert!(
            StaleWatch::default().step(stale, || held(&hid)),
            "a stall in the window would keep 'a' held on the KVM"
        );
    }

    /// PE4 review I1, its stress case S1: the window under a real writer
    /// thread. The writer pops or takes the release and records what it
    /// wrote under one lock — a write and its `note_sent`, the KVM's state.
    /// The "RDP thread" types press, release and a wheel notch through
    /// `push_typing_at` into the least queue (9), and at each typing resync,
    /// before the abort's release-all, holding that lock (so no frame is in
    /// flight), asks the watch whether input is held whenever the KVM holds
    /// a key. It must always say so.
    #[test]
    fn under_a_writer_thread_the_watch_never_misses_a_press_the_kvm_holds() {
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicBool, Ordering};
        let hid = Arc::new(HidControl::new(9, Arc::new(Metrics::default())));
        let kvm = Arc::new(Mutex::new(None::<HidFrame>));
        let done = Arc::new(AtomicBool::new(false));
        let writer = {
            let (hid, kvm, done) = (hid.clone(), kvm.clone(), done.clone());
            std::thread::spawn(move || {
                while !done.load(Ordering::SeqCst) {
                    let mut k = kvm.lock().unwrap();
                    let frames = if hid.take_release() {
                        hid.release_frames()
                    } else {
                        hid.next_frame().into_iter().collect()
                    };
                    for f in frames {
                        hid.note_sent(&f);
                        if matches!(f, HidFrame::Keyboard { .. }) {
                            *k = Some(f);
                        }
                    }
                }
            })
        };
        let stale = RDP_STALE_RELEASE + Duration::from_millis(1);
        let wheel = HidFrame::Wheel {
            buttons: 0,
            wheel: kvm_proto::hid::Wheel::Down,
        };
        let typed = [press(0x04), KBD_ZERO, wheel, press(0x05), KBD_ZERO, wheel];
        let (mut resyncs, mut kvm_held, mut missed) = (0u64, 0u64, 0u64);
        let t0 = std::time::Instant::now();
        while t0.elapsed() < Duration::from_millis(400) {
            let e = hid.epoch();
            for f in typed {
                if hid.push_typing_at(e, f, false) != Push::Resync {
                    continue;
                }
                resyncs += 1;
                {
                    let k = kvm.lock().unwrap();
                    if holds_a_key(*k) {
                        kvm_held += 1;
                        if !StaleWatch::default().step(stale, || held(&hid)) {
                            missed += 1;
                        }
                    }
                }
                hid.release_all(ReleaseTrigger::PasteResync);
                break;
            }
        }
        done.store(true, Ordering::SeqCst);
        writer.join().unwrap();
        eprintln!("I1: {kvm_held} of {resyncs} typing resyncs found the KVM holding a key");
        assert!(
            kvm_held > 100,
            "{kvm_held} of {resyncs} typing resyncs found the KVM holding a key"
        );
        assert_eq!(
            missed, 0,
            "the watch missed the KVM's press in {missed} of {kvm_held} typing resyncs"
        );
    }

    /// A log writer that blocks every write until it is opened: a stdout
    /// pipe nobody reads.
    #[derive(Clone)]
    struct Blocked(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);

    impl std::io::Write for Blocked {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let (open, cv) = &*self.0;
            let mut o = open.lock().unwrap();
            while !*o {
                o = cv.wait(o).unwrap();
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Blocked {
        type Writer = Blocked;
        fn make_writer(&'a self) -> Blocked {
            self.clone()
        }
    }

    /// PE4 review m1: the watch's release lands while its WARN line is
    /// stuck on a blocked writer — the release comes first.
    #[test]
    fn the_release_lands_before_the_line_is_written() {
        let hid = Arc::new(HidControl::new(9, Arc::new(Metrics::default())));
        let _ = hid.push(press(0x04), false);
        let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let logging = {
            let (hid, writer) = (hid.clone(), Blocked(gate.clone()));
            std::thread::spawn(move || {
                let sub = tracing_subscriber::fmt().with_writer(writer).finish();
                tracing::subscriber::with_default(sub, || release(&hid));
            })
        };
        let t0 = std::time::Instant::now();
        let mut landed = false;
        while !landed && t0.elapsed() < Duration::from_secs(5) {
            landed = hid.metrics.release_all.get("rdp_stale") == 1;
            std::thread::sleep(Duration::from_millis(5));
        }
        let (open, cv) = &*gate;
        *open.lock().unwrap() = true;
        cv.notify_all();
        logging.join().unwrap();
        assert!(landed, "the release waited for the blocked log line");
        assert!(!hid.newest_holds());
    }
}
