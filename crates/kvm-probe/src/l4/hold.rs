//! DC18: what the Mac sees when the control websocket dies with a key held
//! (→ §9.3). Hold a key, kill the websocket one of three ways, and wait
//! with nothing released; the caller snapshots the page then, and again
//! after `guarded`'s release (`hid_hold`, Task 1.6 step 8).
//!
//! The one key ever held is `HOLD_USAGE` ('1', no modifier — never Esc,
//! Alt/Option or Cmd, PD3 R-I1), for at most `MAX_OBSERVE`, and every run
//! ends released: `hid_hold` runs inside `hid::guarded`, which releases
//! after any end and again `SECOND_RELEASE_AFTER` later after a failure.
use super::hid::{self, End, HidWs, Interrupts};
use crate::kvm::KvmError;
use crate::request::KvmTarget;
use kvm_proto::hid::HidFrame;
use std::time::Duration;

/// '1': it auto-repeats on macOS (a rising `repeat` on the page) and has
/// no press-and-hold accent menu.
pub const HOLD_USAGE: u8 = 0x1E;

/// The longest `hold_then_kill` waits with the key held on the dead
/// websocket (`--observe-ms`; Task 1.6 uses 1.5 s): a key is never held
/// without bound.
pub const MAX_OBSERVE: Duration = Duration::from_secs(10);

/// `hid_hold`'s snapshot suffixes, in order: `<NAME>_held` while nothing
/// has released the key, `<NAME>_released` after the release.
pub const SHOTS: [&str; 2] = ["_held", "_released"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldReport {
    pub end: End,
}

/// Open the HID websocket, press `usage` (hold it), end the websocket by
/// `end`, then wait `observe` with the key never released. Every caller
/// wraps this in `hid::guarded` (`hid_hold` does), so the release always
/// runs. Any `usage` but `HOLD_USAGE`, or an `observe` past `MAX_OBSERVE`,
/// is refused before anything connects.
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
    if observe > MAX_OBSERVE {
        return Err(KvmError::Io(format!(
            "hid-hold holds a key for at most {MAX_OBSERVE:?}; got {observe:?}"
        )));
    }
    let mut w = HidWs::open(t, pin, token, Duration::from_secs(10)).await?;
    w.send(HidFrame::Keyboard {
        modifiers: 0,
        keys: [usage, 0, 0, 0, 0],
    })
    .await?;
    w.end(end).await;
    tokio::time::sleep(observe).await;
    Ok(HoldReport { end })
}

/// `hid-hold` (Task 1.6 step 8): inside `hid::guarded`, `hold_then_kill`
/// with `HOLD_USAGE` and then `shot(SHOTS[0])` while the key is still held
/// on the dead websocket; after the release, `shot(SHOTS[1])`. `shot` is
/// the snapshot (main: `<NAME><suffix>` into captures/, or nothing without
/// `--snapshot`); a failed one ends the section and the release still
/// runs. An interrupt during the release ends the run before the second
/// snapshot (D34).
pub async fn hid_hold(
    t: &KvmTarget,
    pin: Option<&str>,
    token: &str,
    end: End,
    observe: Duration,
    irq: &mut Interrupts,
    mut shot: impl AsyncFnMut(&str) -> Result<(), KvmError>,
) -> Result<HoldReport, KvmError> {
    let [held, released] = SHOTS;
    let r = hid::guarded(t, pin, token, None, irq, async {
        let r = hold_then_kill(t, pin, token, HOLD_USAGE, end, observe).await?;
        shot(held).await?;
        Ok(r)
    })
    .await?;
    irq.check()?;
    shot(released).await?;
    irq.check()?;
    Ok(r)
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
