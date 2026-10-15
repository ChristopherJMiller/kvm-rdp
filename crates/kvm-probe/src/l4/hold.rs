//! DC18: what the Mac sees when the control websocket dies with a key held
//! (→ §9.3). Hold a key, kill the websocket one of three ways, and wait
//! with nothing released; the caller snapshots the page then, and again
//! after the releases (`hid_hold`, Task 1.6 step 8).
//!
//! The one key ever held is `HOLD_USAGE` ('1', no modifier — never Esc,
//! Alt/Option or Cmd, PD3 R-I1), for at most `MAX_HELD` before the release
//! starts, and every run ends released: `hid_hold` runs inside a section
//! that releases after any end and again `SECOND_RELEASE_AFTER` later —
//! always, since its body leaves '1' last on a dead websocket (PD4 I2).
use super::hid::{self, End, HidWs, Interrupts, Releaser, Relogin, Second};
use crate::kvm::KvmError;
use crate::request::KvmTarget;
use kvm_proto::hid::HidFrame;
use std::time::Duration;

/// '1': it auto-repeats on macOS (a rising `repeat` on the page) and has
/// no press-and-hold accent menu.
pub const HOLD_USAGE: u8 = 0x1E;

/// The longest `hold_then_kill` waits with the key held on the dead
/// websocket (`--observe-ms`; Task 1.6 uses 1.5 s).
pub const MAX_OBSERVE: Duration = Duration::from_secs(10);

/// PD4 m1: the longest '1' is ever held before the release starts, every
/// step bounded: the drain (`hid::DRAIN_WINDOW`), the end
/// (`hid::END_WINDOW`), the observe (`MAX_OBSERVE`) and the `_held`
/// snapshot (`hid::SHOT_WINDOW`) — 24 s.
pub const MAX_HELD: Duration = MAX_OBSERVE
    .saturating_add(hid::DRAIN_WINDOW)
    .saturating_add(hid::END_WINDOW)
    .saturating_add(hid::SHOT_WINDOW);

/// `hid_hold`'s snapshot suffixes, in order: `<NAME>_held` while nothing
/// has released the key, `<NAME>_released` after both releases.
pub const SHOTS: [&str; 2] = ["_held", "_released"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldReport {
    pub end: End,
}

fn check_observe(observe: Duration) -> Result<(), KvmError> {
    if observe > MAX_OBSERVE {
        return Err(KvmError::Io(format!(
            "hid-hold holds a key for at most {MAX_OBSERVE:?}; got {observe:?}"
        )));
    }
    Ok(())
}

/// Open the HID websocket, press `usage` (hold it), wait until the press
/// is acknowledged — in the KVM's own kernel, so ending the websocket
/// cannot purge it (PD4 I1) — end the websocket by `end`, then wait
/// `observe` with the key never released. Every caller wraps this in a
/// releasing section (`hid_hold` does). Any `usage` but `HOLD_USAGE`, or
/// an `observe` past `MAX_OBSERVE`, is refused before anything connects.
/// A press that never drains is reset away (it is not in the KVM's
/// kernel, so purging it is the safe end) and is an error that says KEY
/// MAY BE HELD: it may still be in flight, and the run measures nothing.
pub async fn hold_then_kill(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    usage: u8,
    end: End,
    observe: Duration,
) -> Result<HoldReport, KvmError> {
    if usage != HOLD_USAGE {
        return Err(KvmError::Io(format!(
            "hid-hold holds only {HOLD_USAGE:#04x} ('1'), never {usage:#04x}"
        )));
    }
    check_observe(observe)?;
    let mut w = HidWs::open(t, pin, token, Duration::from_secs(10)).await?;
    w.send(HidFrame::Keyboard {
        modifiers: 0,
        keys: [usage, 0, 0, 0, 0],
    })
    .await?;
    if let Err(why) = w.drain(hid::DRAIN_WINDOW).await {
        w.end(End::Reset).await;
        return Err(KvmError::Io(format!(
            "the held press never drained ({why}), so the run measures nothing: KEY MAY BE HELD on the Mac — run `kvm-probe hid-release` and check `held -`"
        )));
    }
    w.end(end).await;
    tokio::time::sleep(observe).await;
    Ok(HoldReport { end })
}

/// `hid_hold`'s settings.
pub struct HoldPlan<'a> {
    /// How the held websocket ends.
    pub end: End,
    /// How long '1' stays held on the dead websocket before `_held` (at
    /// most `MAX_OBSERVE`).
    pub observe: Duration,
    /// Each snapshot's bound: `hid::SHOT_WINDOW` (tests shorten it).
    pub shot_window: Duration,
    /// A fresh login for a release refused for its token (PD3 m7, PD4 m5).
    pub relogin: Option<Relogin<'a>>,
}

impl<'a> HoldPlan<'a> {
    /// `hid::SHOT_WINDOW`, no fresh login.
    #[must_use]
    pub fn new(end: End, observe: Duration) -> HoldPlan<'a> {
        HoldPlan {
            end,
            observe,
            shot_window: hid::SHOT_WINDOW,
            relogin: None,
        }
    }
}

/// `hid-hold` (Task 1.6 step 8). In one section: `hold_then_kill` with
/// `HOLD_USAGE`, then `shot(SHOTS[0], token)` while '1' is still held on
/// the dead websocket. The section releases twice on every path where it
/// ran, `SECOND_RELEASE_AFTER` apart (PD4 I2: the body leaves '1' last on
/// a dead websocket, whose backlog may be read late), and is KEY MAY BE
/// HELD if the KVM confirmed neither release (PD3 R-m1). A release refused
/// for its token logs in again once with `plan.relogin` (PD4 m5). Then
/// `shot(SHOTS[1], token)` — with a fresh token if one was needed — after
/// every section that ran, a failed one included, since it is how `held -`
/// is checked, unless an interrupt asks to stop (D34). Each snapshot is
/// bounded by `plan.shot_window` (PD4 m1); `shot` is main's snapshot
/// (`<NAME><suffix>` into captures/, or nothing without `--snapshot`).
pub async fn hid_hold(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    plan: &HoldPlan<'_>,
    irq: &mut Interrupts,
    mut shot: impl AsyncFnMut(&str, &str) -> Result<(), KvmError>,
) -> Result<HoldReport, KvmError> {
    check_observe(plan.observe)?;
    let [held, released] = SHOTS;
    let mut r = Releaser::new(token, plan.relogin.as_ref(), hid::RELEASE_WINDOW);
    let out = hid::guarded_with(t, pin, &mut r, None, irq, Second::Always, async {
        let report = hold_then_kill(t, pin, token, HOLD_USAGE, plan.end, plan.observe).await?;
        hid::bounded_shot(plan.shot_window, shot(held, token)).await?;
        Ok(report)
    })
    .await;
    let after = match irq.check() {
        Ok(()) => hid::bounded_shot(plan.shot_window, shot(released, &r.token)).await,
        Err(e) => Err(e),
    };
    let report = out?;
    after?;
    irq.check()?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// '1' is the US layout's unshifted `1`: the held report carries no
    /// modifier, and is neither Esc nor a modifier's own usage.
    #[test]
    fn the_held_key_is_an_unshifted_one() {
        let s = kvm_proto::keymap::us_stroke('1');
        assert_eq!(
            s,
            Some(kvm_proto::keymap::Stroke {
                usage: HOLD_USAGE,
                shift: false
            })
        );
        assert_ne!(HOLD_USAGE, kvm_proto::keymap::USAGE_ESC);
        assert!(!(0xE0..=0xE7).contains(&HOLD_USAGE));
    }
}
