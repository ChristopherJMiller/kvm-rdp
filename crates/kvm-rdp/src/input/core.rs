//! The input state machine (§7), sans-IO: `step(now, ctx, event)` appends
//! `Out`s, `next_deadline` says when a timer next needs a `Tick`. The
//! release epoch is the release channel: a step whose `ctx.epoch` moved
//! since the last one releases first (every held key and button becomes
//! released-by-bridge), and every report it then builds carries `ctx.epoch`
//! as its stamp, so the shell's `push_at(stamp, …)` drops it if a release
//! raced it (design decision 6; §7.3, §7.4). The two timers and
//! `Synchronize` are the triggers the core raises itself; the shell's own
//! triggers (session start/end, suppression, reconnect, Closing, shutdown)
//! reach the core only as a bumped epoch.
//!
//! The timers fire only on a `Tick`, and a release the core raises is the
//! last out of its step: no report is ever built after it in the same step,
//! where it would carry the pre-release stamp and be dropped by `push_at`.
//! An event that arrives after a deadline but before the driver's `Tick`
//! therefore counts as activity, as if it had come just before; a shell
//! that steps a `Tick` first when `next_deadline() <= now` gets the
//! deadline exactly (the release, then the event at the new epoch).
//!
//! Every type here that holds input (`Event`, `Out`, `InputCore`) has a
//! redacted `Debug` (PD5 ruling, §4.5): kinds, counts and flags only.
use crate::hid::ReleaseTrigger;
use crate::input::keys::{KeyReport, Keyboard};
use crate::input::pointer::{Button, Pointer};
use crate::msg::Gen;
use kvm_proto::hid::HidFrame;
use kvm_proto::keymap::{modifier_bit, us_stroke, usage_for_scancode};
use std::time::{Duration, Instant};

/// What the shell knows at one step (no input state: a derived `Debug` is
/// safe).
#[derive(Debug, Clone)]
pub struct Ctx {
    pub now: Instant,
    pub epoch: u64,
    pub generation: Gen,
    pub surface: (u16, u16),
    pub mac_remap: bool,
    pub key_repeat_timeout: Duration,
    pub modifier_idle_timeout: Duration,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Event {
    KeyPressed {
        code: u8,
        extended: bool,
    },
    KeyReleased {
        code: u8,
        extended: bool,
    },
    UnicodePressed(u16),
    UnicodeReleased(u16),
    Synchronize {
        caps_lock: bool,
    },
    MouseMove {
        x: u16,
        y: u16,
    },
    /// A button event at the client's (x, y): IronRDP's carries the click
    /// position (D8d).
    MouseButton {
        button: Button,
        pressed: bool,
        x: u16,
        y: u16,
    },
    Wheel {
        units: i16,
    },
    Tick,
}

#[derive(Clone, PartialEq, Eq)]
pub enum Out {
    Push {
        frame: HidFrame,
        motion_only: bool,
        stamp: u64,
    },
    Release(ReleaseTrigger),
    /// One dropped input, counted as `input_events_ignored` (DD7, DD9).
    Ignored,
}

/// §4.5 (PD5 ruling): an event is a keystroke, a typed unit or the
/// pointer's state — `Debug` names its kind only (never a code, a unit,
/// Caps Lock, a position, a button or a wheel turn).
impl std::fmt::Debug for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Event::KeyPressed { .. } => "KeyPressed",
            Event::KeyReleased { .. } => "KeyReleased",
            Event::UnicodePressed(_) => "UnicodePressed",
            Event::UnicodeReleased(_) => "UnicodeReleased",
            Event::Synchronize { .. } => "Synchronize",
            Event::MouseMove { .. } => "MouseMove",
            Event::MouseButton { .. } => "MouseButton",
            Event::Wheel { .. } => "Wheel",
            Event::Tick => "Tick",
        };
        f.debug_struct("Event")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

/// §4.5 (PD5 ruling): a report shows only `HidFrame`'s redacted kind, with
/// its flag and stamp; a release shows its trigger.
impl std::fmt::Debug for Out {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Out::Push {
                frame,
                motion_only,
                stamp,
            } => f
                .debug_struct("Push")
                .field("frame", frame)
                .field("motion_only", motion_only)
                .field("stamp", stamp)
                .finish(),
            Out::Release(t) => f.debug_tuple("Release").field(&t.label()).finish(),
            Out::Ignored => f.write_str("Ignored"),
        }
    }
}

pub struct InputCore {
    keys: Keyboard,
    pointer: Pointer,
    generation: Gen,
    seen_epoch: u64,
    /// When a held non-modifier key last saw a `Pressed` (a new press or a
    /// repeat of a key held after it, D8e): the key-repeat timer's base.
    last_key_activity: Option<Instant>,
    /// When the keyboard last saw any event, if a modifier is held: the
    /// modifier-idle timer's base.
    last_kbd_event: Option<Instant>,
    /// The armed deadlines, recomputed by `arm` at the end of each step, so
    /// `next_deadline` needs no `Ctx`.
    key_repeat_at: Option<Instant>,
    modifier_idle_at: Option<Instant>,
}

/// §4.5 (PD5 ruling): the keyboard's and pointer's redacted `Debug`s, the
/// generation and epoch, and whether each timer is armed — never a key,
/// a position or a keystroke's time.
impl std::fmt::Debug for InputCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InputCore")
            .field("keys", &self.keys)
            .field("pointer", &self.pointer)
            .field("generation", &self.generation)
            .field("seen_epoch", &self.seen_epoch)
            .field("key_repeat_armed", &self.key_repeat_at.is_some())
            .field("modifier_idle_armed", &self.modifier_idle_at.is_some())
            .finish()
    }
}

/// `base + timeout`; on an (impossible: timeouts are bounded to an hour)
/// overflow, `base` — the timer fires at once, the safe side (§7.4).
fn deadline(base: Instant, timeout: Duration) -> Instant {
    base.checked_add(timeout).unwrap_or(base)
}

impl InputCore {
    #[must_use]
    pub fn new() -> InputCore {
        InputCore {
            keys: Keyboard::default(),
            pointer: Pointer::default(),
            generation: 0,
            seen_epoch: 0,
            last_key_activity: None,
            last_kbd_event: None,
            key_repeat_at: None,
            modifier_idle_at: None,
        }
    }

    #[must_use]
    pub fn generation(&self) -> Gen {
        self.generation
    }

    /// A new session: reset everything (its keys are released by the
    /// shell's own trigger). The release epoch it has seen is kept — it is
    /// `HidControl`'s, not the session's.
    pub fn on_generation(&mut self, g: Gen) {
        self.keys = Keyboard::default();
        self.pointer = Pointer::default();
        self.generation = g;
        self.last_key_activity = None;
        self.last_kbd_event = None;
        self.key_repeat_at = None;
        self.modifier_idle_at = None;
    }

    #[must_use]
    pub fn caps_lock_on(&self) -> bool {
        self.keys.caps_lock_on()
    }

    /// The sooner of the two armed timer deadlines.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        [self.key_repeat_at, self.modifier_idle_at]
            .into_iter()
            .flatten()
            .min()
    }

    /// The two timer deadlines from the state: each is armed only while
    /// something it watches is held (§7.4).
    fn deadlines(&self, ctx: &Ctx) -> (Option<Instant>, Option<Instant>) {
        let key_repeat = (self.keys.held_nonmodifier_usages() > 0)
            .then_some(self.last_key_activity)
            .flatten()
            .map(|t| deadline(t, ctx.key_repeat_timeout));
        let modifier_idle = (self.keys.held_modifier_bits() != 0)
            .then_some(self.last_kbd_event)
            .flatten()
            .map(|t| deadline(t, ctx.modifier_idle_timeout));
        (key_repeat, modifier_idle)
    }

    fn arm(&mut self, ctx: &Ctx) {
        // A key is never held with no timer to release it (§7.4): every
        // path that holds a key or a modifier sets its base, and this keeps
        // that true by construction.
        if self.keys.held_nonmodifier_usages() > 0 {
            self.last_key_activity.get_or_insert(ctx.now);
        }
        if self.keys.held_modifier_bits() != 0 {
            self.last_kbd_event.get_or_insert(ctx.now);
        }
        (self.key_repeat_at, self.modifier_idle_at) = self.deadlines(ctx);
    }

    pub fn step(&mut self, ctx: &Ctx, event: Event, out: &mut Vec<Out>) {
        self.pointer.set_surface(ctx.surface.0, ctx.surface.1);
        self.keys.set_mac_remap(ctx.mac_remap); // D8a: applied at report time
        // The release channel: a moved epoch releases before the event.
        if ctx.epoch != self.seen_epoch {
            self.seen_epoch = ctx.epoch;
            let frame = self.release_marked(out);
            out.push(Out::Push {
                frame,
                motion_only: false,
                stamp: ctx.epoch,
            });
        }
        self.handle(ctx, event, out);
        self.arm(ctx);
    }

    /// §7.4's release of the core's own state: keys and modifiers (D3a) and
    /// buttons (D3b) become released-by-bridge; both timers disarm. Every
    /// release path — the epoch step, `Synchronize`, both timers — comes
    /// through here.
    fn release_state(&mut self) -> KeyReport {
        let r = self.keys.release_all();
        self.pointer.release_all();
        self.last_key_activity = None;
        self.last_kbd_event = None;
        r
    }

    /// A release that keeps its marks (the epoch step and both timers): a
    /// held key `MAX_RBB` had no room for is one dropped input (DD9).
    fn release_marked(&mut self, out: &mut Vec<Out>) -> HidFrame {
        let r = self.release_state();
        if r.dropped {
            out.push(Out::Ignored);
        }
        r.frame
    }

    fn push_key(ctx: &Ctx, r: KeyReport, out: &mut Vec<Out>) {
        if r.dropped {
            out.push(Out::Ignored); // DD7, DD9
        } else if !r.ignored {
            out.push(Out::Push {
                frame: r.frame,
                motion_only: false,
                stamp: ctx.epoch,
            });
        }
    }

    /// D8e: a `Pressed` resets the key-repeat timer only when its usage is
    /// a non-modifier that is held after it (a new press or a repeat).
    fn note_key_activity(&mut self, ctx: &Ctx, usage: Option<u8>) {
        if usage.is_some_and(|u| modifier_bit(u).is_none() && self.keys.is_down(u)) {
            self.last_key_activity = Some(ctx.now);
        }
    }

    fn handle(&mut self, ctx: &Ctx, event: Event, out: &mut Vec<Out>) {
        match event {
            Event::KeyPressed { code, extended } => {
                self.last_kbd_event = Some(ctx.now);
                match self.keys.press(code, extended) {
                    // An unmapped scancode: one dropped input (DD7, D8f),
                    // counted here, on its press, once.
                    None => out.push(Out::Ignored),
                    Some(r) => {
                        self.note_key_activity(ctx, usage_for_scancode(code, extended));
                        Self::push_key(ctx, r, out);
                    }
                }
            }
            Event::KeyReleased { code, extended } => {
                self.last_kbd_event = Some(ctx.now);
                // An unmapped key's release is not counted again: its press
                // was (PD5 carry).
                if let Some(r) = self.keys.release(code, extended) {
                    Self::push_key(ctx, r, out);
                }
            }
            Event::UnicodePressed(u) => {
                self.last_kbd_event = Some(ctx.now);
                let r = self.keys.unicode_press(u);
                let usage = char::from_u32(u32::from(u))
                    .and_then(us_stroke)
                    .map(|s| s.usage);
                self.note_key_activity(ctx, usage);
                if let Some(r) = r {
                    Self::push_key(ctx, r, out);
                }
            }
            Event::UnicodeReleased(u) => {
                self.last_kbd_event = Some(ctx.now);
                if let Some(r) = self.keys.unicode_release(u) {
                    Self::push_key(ctx, r, out);
                }
            }
            Event::Synchronize { caps_lock } => {
                // §7.4, then m6 (PD5 review): MS-RDPBCGR's Synchronize
                // "resets the server key state to all keys up" and is
                // followed by key-downs for whatever the client still holds,
                // so after releasing all the core forgets every mark — keys,
                // modifiers and buttons. A stale mark (a Released lost
                // after an earlier release) would otherwise swallow the next
                // fresh press: Cmd+C reaching the Mac as a typed 'c'. The
                // marks are forgotten at once, so one `MAX_RBB` had no room
                // for drops nothing.
                let _ = self.release_state();
                self.keys.forget_released_by_bridge();
                self.pointer.forget_released_by_bridge();
                self.keys.set_caps_lock(caps_lock);
                out.push(Out::Release(ReleaseTrigger::Synchronize));
            }
            Event::MouseMove { x, y } => {
                let r = self.pointer.moved(x, y);
                out.push(Out::Push {
                    frame: r.frame,
                    motion_only: true,
                    stamp: ctx.epoch,
                });
            }
            Event::MouseButton {
                button,
                pressed,
                x,
                y,
            } => {
                // `None`: a press of a released-by-bridge button (D3b).
                if let Some(r) = self.pointer.button(button, pressed, x, y) {
                    out.push(Out::Push {
                        frame: r.frame,
                        motion_only: false,
                        stamp: ctx.epoch,
                    });
                }
            }
            Event::Wheel { units } => {
                for frame in self.pointer.wheel(units) {
                    out.push(Out::Push {
                        frame,
                        motion_only: false,
                        stamp: ctx.epoch,
                    });
                }
            }
            Event::Tick => self.timers(ctx, out),
        }
    }

    /// §7.4's two timers, from the state as it is now (an epoch release at
    /// the top of this step has already disarmed both). One release covers
    /// everything, so at most one fires; the key-repeat timer first. The
    /// release is the last out of the step.
    fn timers(&mut self, ctx: &Ctx, out: &mut Vec<Out>) {
        let (key_repeat, modifier_idle) = self.deadlines(ctx);
        let trigger = if key_repeat.is_some_and(|at| ctx.now >= at) {
            ReleaseTrigger::KeyRepeat
        } else if modifier_idle.is_some_and(|at| ctx.now >= at) {
            ReleaseTrigger::ModifierIdle
        } else {
            return;
        };
        let _ = self.release_marked(out);
        out.push(Out::Release(trigger));
    }
}

impl Default for InputCore {
    fn default() -> InputCore {
        InputCore::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::*;
    use crate::hid::HidControl;
    use crate::metrics::Metrics;
    use kvm_proto::hid::HidFrame;
    use kvm_proto::keymap::{modifier_bit, us_stroke, usage_for_scancode};
    use std::sync::Arc;

    fn kbd(modifiers: u8, k: u8) -> HidFrame {
        HidFrame::Keyboard {
            modifiers,
            keys: [k, 0, 0, 0, 0],
        }
    }

    struct Rig {
        core: InputCore,
        now: Instant,
        epoch: u64,
    }

    impl Rig {
        fn new() -> Rig {
            Rig {
                core: InputCore::new(),
                now: Instant::now(),
                epoch: 0,
            }
        }
        fn ctx(&self) -> Ctx {
            Ctx {
                now: self.now,
                epoch: self.epoch,
                generation: 1,
                surface: (1920, 1080),
                mac_remap: false,
                key_repeat_timeout: Duration::from_secs(10),
                modifier_idle_timeout: Duration::from_secs(30),
            }
        }
        /// Step and return the outs; a `Release` out bumps the rig's epoch,
        /// as the shell's `HidControl::release_all` would.
        fn step(&mut self, e: Event) -> Vec<Out> {
            let mut out = Vec::new();
            self.core.step(&self.ctx(), e, &mut out);
            if out.iter().any(|o| matches!(o, Out::Release(_))) {
                self.epoch += 1;
            }
            out
        }
        fn advance(&mut self, d: Duration) {
            self.now += d;
        }
        /// The core holds no key, modifier or button.
        fn holds_nothing(&self) -> bool {
            self.core.keys.held_modifier_bits() == 0
                && self.core.keys.held_nonmodifier_usages() == 0
                && self.core.pointer.held_buttons() == 0
        }
    }

    fn pushes(out: &[Out]) -> Vec<(HidFrame, u64)> {
        out.iter()
            .filter_map(|o| match o {
                Out::Push { frame, stamp, .. } => Some((*frame, *stamp)),
                _ => None,
            })
            .collect()
    }

    fn releases(out: &[Out]) -> Vec<ReleaseTrigger> {
        out.iter()
            .filter_map(|o| match o {
                Out::Release(t) => Some(*t),
                _ => None,
            })
            .collect()
    }

    /// A frame's bytes, for failure messages: `HidFrame`'s `Debug` is
    /// redacted (PD5 ruling), so a test that needs the detail prints these.
    fn bytes(f: HidFrame) -> String {
        format!("{:02x?}", f.to_vec())
    }

    /// An event in full, for failure messages (`Event`'s `Debug` is
    /// redacted).
    fn describe(e: Event) -> String {
        match e {
            Event::KeyPressed { code, extended } => {
                format!("KeyPressed({code:#04x}, ext={extended})")
            }
            Event::KeyReleased { code, extended } => {
                format!("KeyReleased({code:#04x}, ext={extended})")
            }
            Event::UnicodePressed(u) => format!("UnicodePressed({u:#06x})"),
            Event::UnicodeReleased(u) => format!("UnicodeReleased({u:#06x})"),
            Event::Synchronize { caps_lock } => format!("Synchronize(caps={caps_lock})"),
            Event::MouseMove { x, y } => format!("MouseMove({x}, {y})"),
            Event::MouseButton {
                button,
                pressed,
                x,
                y,
            } => format!("MouseButton({button:?}, pressed={pressed}, {x}, {y})"),
            Event::Wheel { units } => format!("Wheel({units})"),
            Event::Tick => "Tick".to_owned(),
        }
    }

    fn show(out: &[Out]) -> String {
        out.iter()
            .map(|o| match o {
                Out::Push {
                    frame,
                    motion_only,
                    stamp,
                } => format!("Push({} motion={motion_only} @{stamp})", bytes(*frame)),
                Out::Release(t) => format!("Release({})", t.label()),
                Out::Ignored => "Ignored".to_owned(),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    #[test]
    fn a_press_and_release_push_full_state_at_the_current_epoch() {
        let mut r = Rig::new();
        assert_eq!(
            pushes(&r.step(Event::KeyPressed {
                code: 0x1E,
                extended: false
            })),
            [(kbd(0, 0x04), 0)]
        );
        assert_eq!(
            pushes(&r.step(Event::KeyReleased {
                code: 0x1E,
                extended: false
            })),
            [(kbd(0, 0), 0)]
        );
        // An unmapped scancode is dropped and counted (D8f), never pushed.
        assert_eq!(
            r.step(Event::KeyPressed {
                code: 0x54,
                extended: false
            }),
            [Out::Ignored]
        );
    }

    /// Design decision 6: a bumped epoch (a release the shell did) releases
    /// before the event, and reports carry the new stamp.
    #[test]
    fn a_bumped_epoch_releases_held_keys_before_the_next_event() {
        let mut r = Rig::new();
        r.step(Event::KeyPressed {
            code: 0x1E,
            extended: false,
        }); // 'a' down
        r.epoch = 5; // the shell released all (websocket reconnect, say)
        // The next event first sees the release: 'a' is now released-by-
        // bridge, so its repeat is ignored, and everything is stamped 5.
        let out = r.step(Event::KeyPressed {
            code: 0x1E,
            extended: false,
        });
        assert!(
            pushes(&out).iter().all(|(_, stamp)| *stamp == 5),
            "{}",
            show(&out)
        );
        assert!(
            !out.iter().any(|o| matches!(
                o,
                Out::Push {
                    frame: HidFrame::Keyboard {
                        keys: [0x04, ..],
                        ..
                    },
                    ..
                }
            )),
            "{}",
            show(&out)
        );
        // Its client Released clears the released-by-bridge mark.
        r.step(Event::KeyReleased {
            code: 0x1E,
            extended: false,
        });
        assert_eq!(
            pushes(&r.step(Event::KeyPressed {
                code: 0x1E,
                extended: false
            })),
            [(kbd(0, 0x04), 5)]
        );
    }

    /// §7.4 (D3a): a modifier held at a release is released by the bridge
    /// too — the client's typematic repeats of a held Ctrl or Cmd never
    /// re-press it (the down-up-down glitch §7.4 forbids).
    #[test]
    fn a_held_modifier_is_not_repressed_by_repeats_after_a_release() {
        let mut r = Rig::new();
        r.step(Event::KeyPressed {
            code: 0x1D,
            extended: false,
        }); // LCtrl
        r.epoch = 5;
        for _ in 0..3 {
            let out = r.step(Event::KeyPressed {
                code: 0x1D,
                extended: false,
            });
            assert!(
                !pushes(&out).iter().any(
                    |(f, _)| matches!(f, HidFrame::Keyboard { modifiers, .. } if *modifiers != 0)
                ),
                "{}",
                show(&out)
            );
        }
        let mut out = r.step(Event::KeyReleased {
            code: 0x1D,
            extended: false,
        });
        out.extend(r.step(Event::KeyPressed {
            code: 0x1D,
            extended: false,
        }));
        assert_eq!(pushes(&out), [(kbd(0x01, 0), 5)]);
    }

    /// §7.4 (D3b): a reconnect never re-presses a button — the next move
    /// after a release carries no button, and a press before the client's
    /// release changes nothing.
    #[test]
    fn a_held_button_is_released_by_bridge() {
        let mut r = Rig::new();
        r.step(Event::MouseMove { x: 10, y: 10 });
        r.step(Event::MouseButton {
            button: Button::Left,
            pressed: true,
            x: 10,
            y: 10,
        });
        r.epoch = 1;
        let out = r.step(Event::MouseMove { x: 20, y: 20 });
        let moves: Vec<HidFrame> = pushes(&out)
            .into_iter()
            .map(|(f, _)| f)
            .filter(|f| matches!(f, HidFrame::AbsMouse { .. }))
            .collect();
        assert!(
            matches!(moves.as_slice(), [HidFrame::AbsMouse { buttons: 0, .. }]),
            "{}",
            show(&out)
        );
        assert!(
            pushes(&r.step(Event::MouseButton {
                button: Button::Left,
                pressed: true,
                x: 20,
                y: 20
            }))
            .is_empty()
        );
    }

    /// §7.4: Synchronize releases all and records Caps Lock.
    #[test]
    fn synchronize_releases_all_and_tracks_caps_lock() {
        let mut r = Rig::new();
        r.step(Event::KeyPressed {
            code: 0x1E,
            extended: false,
        });
        let out = r.step(Event::Synchronize { caps_lock: true });
        assert!(
            out.iter()
                .any(|o| matches!(o, Out::Release(ReleaseTrigger::Synchronize)))
        );
        assert!(r.core.caps_lock_on());
    }

    /// §7.4: non-modifier keys held and no Pressed repeat of any of them for
    /// key_repeat_timeout → release; a repeat before then resets it; mouse
    /// never resets it.
    #[test]
    fn the_key_repeat_timer_releases_after_silence() {
        let mut r = Rig::new();
        r.step(Event::KeyPressed {
            code: 0x1E,
            extended: false,
        });
        assert_eq!(
            r.core.next_deadline(),
            Some(r.now + Duration::from_secs(10))
        );
        r.advance(Duration::from_secs(9));
        r.step(Event::MouseMove { x: 10, y: 10 }); // does not reset (§7.4)
        assert_eq!(
            r.core.next_deadline(),
            Some(r.now - Duration::from_secs(9) + Duration::from_secs(10))
        );
        r.advance(Duration::from_secs(2)); // 11 s since the press
        let out = r.step(Event::Tick);
        assert!(
            out.iter()
                .any(|o| matches!(o, Out::Release(ReleaseTrigger::KeyRepeat))),
            "{}",
            show(&out)
        );
        assert_eq!(r.core.next_deadline(), None);
    }

    #[test]
    fn a_repeat_of_the_held_key_resets_the_key_repeat_timer() {
        let mut r = Rig::new();
        r.step(Event::KeyPressed {
            code: 0x1E,
            extended: false,
        });
        r.advance(Duration::from_secs(9));
        r.step(Event::KeyPressed {
            code: 0x1E,
            extended: false,
        }); // a repeat
        r.advance(Duration::from_secs(9)); // 9 s since the repeat
        assert!(
            !r.step(Event::Tick)
                .iter()
                .any(|o| matches!(o, Out::Release(_)))
        );
    }

    /// §7.4 (D8e): only a `Pressed` repeat of a held non-modifier key
    /// resets the key-repeat timer — Windows' typematic Shift does not, so a
    /// stuck letter is released while Shift repeats.
    #[test]
    fn a_modifier_repeat_does_not_reset_the_key_repeat_timer() {
        let mut r = Rig::new();
        let t0 = r.now;
        r.step(Event::KeyPressed {
            code: 0x1E,
            extended: false,
        }); // a
        r.step(Event::KeyPressed {
            code: 0x2A,
            extended: false,
        }); // LShift
        let mut released_at = None;
        for _ in 0..10 {
            r.advance(Duration::from_secs(2));
            let mut out = r.step(Event::KeyPressed {
                code: 0x2A,
                extended: false,
            });
            out.extend(r.step(Event::Tick));
            if released_at.is_none()
                && out
                    .iter()
                    .any(|o| matches!(o, Out::Release(ReleaseTrigger::KeyRepeat)))
            {
                released_at = Some(r.now - t0);
            }
        }
        assert_eq!(released_at, Some(Duration::from_secs(10)));
    }

    /// §7.4: two keys held, repeats of only the second → no release (the
    /// §11 case).
    #[test]
    fn two_keys_held_with_repeats_of_the_second_only_never_release() {
        let mut r = Rig::new();
        r.step(Event::KeyPressed {
            code: 0x1E,
            extended: false,
        }); // a
        r.step(Event::KeyPressed {
            code: 0x30,
            extended: false,
        }); // b
        for _ in 0..30 {
            r.advance(Duration::from_secs(9));
            r.step(Event::KeyPressed {
                code: 0x30,
                extended: false,
            }); // repeat b
            assert!(
                !r.step(Event::Tick)
                    .iter()
                    .any(|o| matches!(o, Out::Release(_)))
            );
        }
    }

    /// §7.4: modifiers held and no keyboard event of any kind for
    /// modifier_idle_timeout → release; a mouse event never resets it.
    #[test]
    fn the_modifier_idle_timer_releases_a_stuck_modifier() {
        let mut r = Rig::new();
        r.step(Event::KeyPressed {
            code: 0x1D,
            extended: false,
        }); // LCtrl down
        assert_eq!(
            r.core.next_deadline(),
            Some(r.now + Duration::from_secs(30))
        );
        r.advance(Duration::from_secs(29));
        r.step(Event::MouseMove { x: 1, y: 1 });
        r.advance(Duration::from_secs(2));
        let out = r.step(Event::Tick);
        assert!(
            out.iter()
                .any(|o| matches!(o, Out::Release(ReleaseTrigger::ModifierIdle))),
            "{}",
            show(&out)
        );
    }

    /// Review Focus 3: a flood still releases on the key-repeat timeout.
    #[test]
    fn a_flood_still_releases_on_the_key_repeat_timeout() {
        let mut r = Rig::new();
        for code in 0x02..=0x40u8 {
            r.step(Event::KeyPressed {
                code,
                extended: false,
            });
        }
        r.advance(Duration::from_secs(11));
        assert!(
            r.step(Event::Tick)
                .iter()
                .any(|o| matches!(o, Out::Release(ReleaseTrigger::KeyRepeat)))
        );
    }

    #[test]
    fn a_new_generation_resets_the_state_and_the_timers() {
        let mut r = Rig::new();
        r.step(Event::KeyPressed {
            code: 0x1E,
            extended: false,
        });
        r.core.on_generation(2);
        assert_eq!(r.core.next_deadline(), None);
        assert_eq!(r.core.generation(), 2);
    }

    /// A Tick with nothing armed and no state change pushes nothing.
    #[test]
    fn an_idle_tick_does_nothing() {
        let mut r = Rig::new();
        assert!(r.step(Event::Tick).is_empty());
    }

    // ---- Beyond the plan's listing: the PD5 carries and every trigger's
    // mechanics, pinned one by one (each killed a mutant; see the report).

    /// m6 (PD5 review; MS-RDPBCGR 2.2.8.1.1.3.1.1.5: a Synchronize "resets
    /// the server key state to all keys up" and is followed by key-downs for
    /// whatever is still held): Synchronize releases all and then forgets
    /// every released-by-bridge mark — keys, modifiers and buttons. A Cmd
    /// whose client Released was lost after an earlier release must not
    /// swallow the next fresh Cmd: Cmd+C reaches the Mac as Cmd+C, never as
    /// a typed 'c'.
    #[test]
    fn synchronize_forgets_every_released_by_bridge_mark() {
        let mut r = Rig::new();
        let left = |pressed| Event::MouseButton {
            button: Button::Left,
            pressed,
            x: 10,
            y: 10,
        };
        r.step(Event::KeyPressed {
            code: 0x5B,
            extended: true,
        }); // LGUI (Cmd)
        r.step(Event::KeyPressed {
            code: 0x1E,
            extended: false,
        }); // 'a'
        r.step(left(true));
        // The earlier release: the key-repeat timer, everything marked.
        r.advance(Duration::from_secs(10));
        assert_eq!(releases(&r.step(Event::Tick)), [ReleaseTrigger::KeyRepeat]);
        // Their client Released are lost (focus left the client). The marks
        // hold: a fresh Cmd is swallowed, so C would go out bare, 'a' and
        // the click are swallowed.
        let mut out = r.step(Event::KeyPressed {
            code: 0x5B,
            extended: true,
        });
        out.extend(r.step(Event::KeyPressed {
            code: 0x2E,
            extended: false,
        }));
        assert_eq!(
            pushes(&out).last().map(|p| p.0),
            Some(kbd(0, 0x06)),
            "precondition: {}",
            show(&out)
        );
        r.step(Event::KeyReleased {
            code: 0x2E,
            extended: false,
        });
        assert!(
            !pushes(&r.step(Event::KeyPressed {
                code: 0x1E,
                extended: false
            }))
            .iter()
            .any(|(f, _)| *f != kbd(0, 0))
        );
        assert!(pushes(&r.step(left(true))).is_empty());
        // The client regains focus and resyncs.
        let out = r.step(Event::Synchronize { caps_lock: false });
        assert_eq!(out, [Out::Release(ReleaseTrigger::Synchronize)]);
        assert!(r.holds_nothing());
        let e = r.epoch;
        // A fresh Cmd+C goes out with the modifier; 'a' and the click too.
        assert_eq!(
            pushes(&r.step(Event::KeyPressed {
                code: 0x5B,
                extended: true
            })),
            [(kbd(0, 0), e), (kbd(0x08, 0), e)]
        );
        assert_eq!(
            pushes(&r.step(Event::KeyPressed {
                code: 0x2E,
                extended: false
            })),
            [(kbd(0x08, 0x06), e)],
            "Cmd+C"
        );
        assert_eq!(
            pushes(&r.step(Event::KeyPressed {
                code: 0x1E,
                extended: false
            })),
            [(
                HidFrame::Keyboard {
                    modifiers: 0x08,
                    keys: [0x06, 0x04, 0, 0, 0]
                },
                e
            )]
        );
        assert_eq!(
            pushes(&r.step(left(true))),
            [(
                HidFrame::AbsMouse {
                    buttons: 0x01,
                    x: 170,
                    y: 303
                },
                e
            )]
        );
    }

    /// m6, MS-RDPBCGR's other half: what the client still holds AT the
    /// Synchronize it re-sends as key-downs after it, and those are fresh
    /// presses — the release does not mark them. Cmd held while the window
    /// regains focus, then C: Cmd+C.
    #[test]
    fn keys_held_across_a_synchronize_are_pressed_again_by_their_key_downs() {
        let mut r = Rig::new();
        r.step(Event::KeyPressed {
            code: 0x5B,
            extended: true,
        }); // LGUI
        r.step(Event::KeyPressed {
            code: 0x1E,
            extended: false,
        }); // 'a'
        r.step(Event::MouseButton {
            button: Button::Right,
            pressed: true,
            x: 10,
            y: 10,
        });
        assert_eq!(
            r.step(Event::Synchronize { caps_lock: false }),
            [Out::Release(ReleaseTrigger::Synchronize)]
        );
        assert!(r.holds_nothing());
        for usage in [0xE3, 0x04] {
            assert!(!r.core.keys.is_released_by_bridge(usage), "{usage:#x}");
        }
        assert!(!r.core.pointer.is_released_by_bridge(Button::Right));
        let e = r.epoch;
        let mut out = r.step(Event::KeyPressed {
            code: 0x5B,
            extended: true,
        });
        out.extend(r.step(Event::KeyPressed {
            code: 0x1E,
            extended: false,
        }));
        out.extend(r.step(Event::MouseButton {
            button: Button::Right,
            pressed: true,
            x: 10,
            y: 10,
        }));
        out.extend(r.step(Event::KeyPressed {
            code: 0x2E,
            extended: false,
        }));
        assert_eq!(
            pushes(&out),
            [
                (kbd(0, 0), e),
                (kbd(0x08, 0), e),
                (kbd(0x08, 0x04), e),
                (
                    HidFrame::AbsMouse {
                        buttons: 0x02,
                        x: 170,
                        y: 303
                    },
                    e
                ),
                (
                    HidFrame::Keyboard {
                        modifiers: 0x08,
                        keys: [0x04, 0x06, 0, 0, 0]
                    },
                    e
                ),
            ],
            "{}",
            show(&out)
        );
    }

    /// m6's other half: the timers and the shell's releases KEEP the marks
    /// (§7.4) — only a Synchronize forgets them.
    #[test]
    fn only_synchronize_forgets_the_marks() {
        for how in ["key_repeat", "modifier_idle", "epoch"] {
            let mut r = Rig::new();
            r.step(Event::KeyPressed {
                code: 0x5B,
                extended: true,
            });
            match how {
                "key_repeat" => {
                    r.step(Event::KeyPressed {
                        code: 0x1E,
                        extended: false,
                    });
                    r.advance(Duration::from_secs(10));
                    r.step(Event::Tick);
                }
                "modifier_idle" => {
                    r.advance(Duration::from_secs(30));
                    r.step(Event::Tick);
                }
                _ => {
                    r.epoch = 9;
                    r.step(Event::Tick);
                }
            }
            assert!(r.holds_nothing(), "{how}");
            let out = r.step(Event::KeyPressed {
                code: 0x5B,
                extended: true,
            });
            assert!(
                pushes(&out).iter().all(|(f, _)| *f == kbd(0, 0)),
                "{how}: a stale mark was forgotten: {}",
                show(&out)
            );
        }
    }

    /// DD7 (D8f), PD5 carry: an unmapped scancode — base or extended (E0 5E,
    /// Power, is never sent) — is one dropped input, counted on its press
    /// only; its release is not counted again. Likewise an untypeable or a
    /// surrogate Unicode unit, and a press past the 16 tracked keys.
    #[test]
    fn a_dropped_key_counts_once() {
        let mut r = Rig::new();
        for (code, extended) in [(0x54, false), (0x5E, true)] {
            assert_eq!(usage_for_scancode(code, extended), None);
            assert_eq!(r.step(Event::KeyPressed { code, extended }), [Out::Ignored]);
            let out = r.step(Event::KeyReleased { code, extended });
            assert!(out.is_empty(), "{code:#x}'s release: {}", show(&out));
        }
        for unit in [0x00E9u16, 0xD800] {
            assert_eq!(r.step(Event::UnicodePressed(unit)), [Out::Ignored]);
            let out = r.step(Event::UnicodeReleased(unit));
            assert!(out.is_empty(), "{unit:#x}'s release: {}", show(&out));
        }
        let letters: Vec<u8> = (0x10..=0x19).chain(0x1E..=0x23).collect();
        assert_eq!(letters.len(), 16);
        for code in letters {
            assert_eq!(
                pushes(&r.step(Event::KeyPressed {
                    code,
                    extended: false
                }))
                .len(),
                1
            );
        }
        let out = r.step(Event::KeyPressed {
            code: 0x2C,
            extended: false,
        }); // z, the 17th
        assert_eq!(out, [Out::Ignored]);
        let out = r.step(Event::KeyReleased {
            code: 0x2C,
            extended: false,
        });
        assert!(out.is_empty(), "{}", show(&out));
    }

    /// Both timers fire at their deadline, and not a nanosecond before.
    #[test]
    fn both_timers_fire_at_their_deadline_and_not_before() {
        let cases = [
            (0x1E, Duration::from_secs(10), ReleaseTrigger::KeyRepeat), // 'a'
            (0x1D, Duration::from_secs(30), ReleaseTrigger::ModifierIdle), // LCtrl
        ];
        for (code, timeout, trigger) in cases {
            let mut r = Rig::new();
            let t0 = r.now;
            r.step(Event::KeyPressed {
                code,
                extended: false,
            });
            assert_eq!(r.core.next_deadline(), Some(t0 + timeout));
            r.now = t0 + timeout - Duration::from_nanos(1);
            let out = r.step(Event::Tick);
            assert!(out.is_empty(), "{}", show(&out));
            r.now = t0 + timeout;
            let out = r.step(Event::Tick);
            assert_eq!(out, [Out::Release(trigger)]);
            assert!(r.holds_nothing());
            assert_eq!(r.core.next_deadline(), None);
            // The release went out once; the next step sees its own epoch
            // move and fires nothing more.
            r.advance(Duration::from_secs(60));
            assert_eq!(releases(&r.step(Event::Tick)), []);
        }
    }

    /// §7.4: "no keyboard event of any kind" — a held modifier's own
    /// typematic repeat, another modifier, a stray release, an unmapped key
    /// or an untypeable unit all keep it alive; only keyboard silence (the
    /// mouse never counts) releases it.
    #[test]
    fn any_keyboard_event_resets_the_modifier_idle_timer() {
        let events = [
            Event::KeyPressed {
                code: 0x1D,
                extended: false,
            }, // LCtrl's own repeat
            Event::KeyPressed {
                code: 0x2A,
                extended: false,
            }, // LShift
            Event::KeyReleased {
                code: 0x1E,
                extended: false,
            }, // a stray release of 'a'
            Event::KeyPressed {
                code: 0x54,
                extended: false,
            }, // unmapped
            Event::UnicodePressed(0x00E9),
            Event::UnicodeReleased(u16::from(b'x')),
        ];
        for (i, e) in events.into_iter().enumerate() {
            let mut r = Rig::new();
            r.step(Event::KeyPressed {
                code: 0x1D,
                extended: false,
            });
            r.advance(Duration::from_secs(20));
            r.step(e);
            let te = r.now;
            assert_eq!(
                r.core.next_deadline(),
                Some(te + Duration::from_secs(30)),
                "event {i}"
            );
            r.step(Event::MouseButton {
                button: Button::Right,
                pressed: true,
                x: 1,
                y: 1,
            });
            r.step(Event::Wheel { units: 120 });
            r.advance(Duration::from_secs(29));
            r.step(Event::MouseMove { x: 5, y: 5 });
            assert_eq!(releases(&r.step(Event::Tick)), [], "event {i}");
            r.advance(Duration::from_secs(1));
            assert_eq!(
                releases(&r.step(Event::Tick)),
                [ReleaseTrigger::ModifierIdle],
                "event {i}"
            );
            assert!(r.holds_nothing(), "event {i}");
        }
    }

    /// D8e for Unicode keys (Windows App's Unicode mode): a held Unicode
    /// key's repeat resets the key-repeat timer as a scancode's does, and a
    /// Unicode key — with its Shift — held alone is released by it.
    #[test]
    fn a_held_unicode_key_follows_the_key_repeat_timer() {
        let mut r = Rig::new();
        let t0 = r.now;
        assert_eq!(
            pushes(&r.step(Event::UnicodePressed(u16::from(b'A')))),
            [(kbd(0x02, 0x04), 0)]
        );
        r.advance(Duration::from_secs(9));
        r.step(Event::UnicodePressed(u16::from(b'A'))); // its repeat
        assert_eq!(r.core.next_deadline(), Some(t0 + Duration::from_secs(19)));
        r.advance(Duration::from_secs(9));
        assert_eq!(releases(&r.step(Event::Tick)), []);
        r.advance(Duration::from_secs(1));
        assert_eq!(releases(&r.step(Event::Tick)), [ReleaseTrigger::KeyRepeat]);
        assert!(r.holds_nothing());
        // Its repeat after the release is ignored (released by the bridge).
        let out = r.step(Event::UnicodePressed(u16::from(b'A')));
        assert!(
            pushes(&out).iter().all(|(f, _)| *f == kbd(0, 0)),
            "{}",
            show(&out)
        );
    }

    /// Design decision 6: a release the shell did (a moved epoch) releases
    /// everything and disarms both timers — an overdue timer then fires
    /// nothing more; the only out is the zero report at the new epoch.
    #[test]
    fn a_moved_epoch_disarms_both_timers() {
        let mut r = Rig::new();
        r.step(Event::KeyPressed {
            code: 0x1E,
            extended: false,
        });
        r.step(Event::KeyPressed {
            code: 0x1D,
            extended: false,
        });
        r.step(Event::MouseButton {
            button: Button::Middle,
            pressed: true,
            x: 3,
            y: 3,
        });
        r.advance(Duration::from_secs(31)); // both overdue
        r.epoch = 3;
        let out = r.step(Event::Tick);
        assert_eq!(
            out,
            [Out::Push {
                frame: kbd(0, 0),
                motion_only: false,
                stamp: 3
            }]
        );
        assert!(r.holds_nothing());
        assert_eq!(r.core.next_deadline(), None);
    }

    /// The shell's contract (Task 4.1): a Tick at a passed deadline, stepped
    /// before the next event, releases first; that event's report is built
    /// after the release, at the epoch the release made, so it goes out.
    #[test]
    fn a_tick_before_a_late_event_releases_first_and_the_event_goes_out() {
        let mut r = Rig::new();
        r.step(Event::KeyPressed {
            code: 0x1E,
            extended: false,
        });
        r.advance(Duration::from_secs(12));
        assert_eq!(
            r.step(Event::Tick),
            [Out::Release(ReleaseTrigger::KeyRepeat)]
        );
        let out = r.step(Event::KeyPressed {
            code: 0x30,
            extended: false,
        });
        assert_eq!(pushes(&out), [(kbd(0, 0), 1), (kbd(0, 0x05), 1)]);
    }

    /// A new session (`on_generation`) starts with nothing held and no marks
    /// — the old session's keys are not owed — and keeps the epoch it has
    /// seen: no release is read into it.
    #[test]
    fn a_new_generation_starts_clean_at_the_same_epoch() {
        let mut r = Rig::new();
        r.step(Event::KeyPressed {
            code: 0x1D,
            extended: false,
        });
        let middle = |pressed| Event::MouseButton {
            button: Button::Middle,
            pressed,
            x: 10,
            y: 10,
        };
        r.step(middle(true));
        r.epoch = 4;
        r.step(Event::Tick); // LCtrl and Middle marked
        r.step(Event::KeyPressed {
            code: 0x1E,
            extended: false,
        });
        r.step(Event::MouseButton {
            button: Button::Left,
            pressed: true,
            x: 10,
            y: 10,
        });
        assert_eq!(r.core.pointer.held_buttons(), 0x01);
        r.core.on_generation(7);
        assert!(r.holds_nothing());
        assert_eq!(r.core.next_deadline(), None);
        assert_eq!(
            pushes(&r.step(Event::KeyPressed {
                code: 0x1D,
                extended: false
            })),
            [(kbd(0x01, 0), 4)]
        );
        // The pointer starts clean too: no button held, none owed.
        assert_eq!(
            pushes(&r.step(middle(true))),
            [(
                HidFrame::AbsMouse {
                    buttons: 0x04,
                    x: 170,
                    y: 303
                },
                4
            )]
        );
    }

    /// DD9: a release whose held keys `MAX_RBB` has no room to mark still
    /// releases everything and still goes out; the key it could not mark is
    /// one dropped input — from the epoch step and from a timer alike.
    #[test]
    fn a_release_with_no_room_for_a_mark_still_releases_and_counts_it() {
        let mods: [(u8, bool); 8] = [
            (0x1D, false),
            (0x2A, false),
            (0x38, false),
            (0x5B, true),
            (0x1D, true),
            (0x36, false),
            (0x38, true),
            (0x5C, true),
        ];
        let letters: Vec<u8> = (0x10..=0x19).chain(0x1E..=0x23).collect(); // 16
        let others: Vec<u8> = (0x02..=0x0B).chain(0x3B..=0x40).collect(); // 1-0, F1-F6
        assert_eq!((letters.len(), others.len()), (16, 16));
        for by_timer in [false, true] {
            let mut r = Rig::new();
            for (code, extended) in mods {
                r.step(Event::KeyPressed { code, extended });
            }
            for code in &letters {
                r.step(Event::KeyPressed {
                    code: *code,
                    extended: false,
                });
            }
            r.epoch = 1; // 24 marks: room for 8 more
            r.step(Event::Tick);
            // Their Released are lost; 16 fresh keys are held.
            for code in &others {
                r.step(Event::KeyPressed {
                    code: *code,
                    extended: false,
                });
            }
            assert_eq!(r.core.keys.held_nonmodifier_usages(), 16);
            let out = if by_timer {
                r.advance(Duration::from_secs(10));
                r.step(Event::Tick)
            } else {
                r.epoch = 2;
                r.step(Event::Tick)
            };
            let want = if by_timer {
                vec![Out::Ignored, Out::Release(ReleaseTrigger::KeyRepeat)]
            } else {
                vec![
                    Out::Ignored,
                    Out::Push {
                        frame: kbd(0, 0),
                        motion_only: false,
                        stamp: 2,
                    },
                ]
            };
            assert_eq!(out, want, "by_timer={by_timer}: {}", show(&out));
            assert!(r.holds_nothing());
        }
    }

    /// The core takes the surface (§7.2) and the Mac remap (DD3) from each
    /// step's `Ctx`; only a move is motion-only (§7.3: coalescable).
    #[test]
    fn the_surface_and_the_remap_come_from_the_ctx() {
        let mut core = InputCore::new();
        let mut ctx = Ctx {
            now: Instant::now(),
            epoch: 0,
            generation: 1,
            surface: (1280, 720),
            mac_remap: true,
            key_repeat_timeout: Duration::from_secs(10),
            modifier_idle_timeout: Duration::from_secs(30),
        };
        let mut step = |ctx: &Ctx, e| {
            let mut out = Vec::new();
            core.step(ctx, e, &mut out);
            out
        };
        let push = |frame, motion_only| Out::Push {
            frame,
            motion_only,
            stamp: 0,
        };
        let abs = |buttons, x, y| HidFrame::AbsMouse { buttons, x, y };
        assert_eq!(
            step(&ctx, Event::MouseMove { x: 1279, y: 719 }),
            [push(abs(0, 32_767, 32_767), true)]
        );
        assert_eq!(
            step(
                &ctx,
                Event::MouseButton {
                    button: Button::Right,
                    pressed: true,
                    x: 0,
                    y: 0
                }
            ),
            [push(abs(0x02, 0, 0), false)]
        );
        assert_eq!(
            step(&ctx, Event::Wheel { units: 120 }),
            [push(
                HidFrame::Wheel {
                    buttons: 0x02,
                    wheel: kvm_proto::hid::Wheel::Up
                },
                false
            )]
        );
        step(
            &ctx,
            Event::KeyPressed {
                code: 0x1D,
                extended: false,
            },
        );
        assert_eq!(
            step(
                &ctx,
                Event::KeyPressed {
                    code: 0x2E,
                    extended: false
                }
            ),
            [push(kbd(0x08, 0x06), false)],
            "Ctrl+C → Cmd+C with the remap on"
        );
        ctx.mac_remap = false;
        ctx.surface = (1920, 1080);
        assert_eq!(
            step(
                &ctx,
                Event::KeyReleased {
                    code: 0x2E,
                    extended: false
                }
            ),
            [push(kbd(0x01, 0), false)]
        );
        assert_eq!(
            step(
                &ctx,
                Event::KeyPressed {
                    code: 0x2F,
                    extended: false
                }
            ),
            [push(kbd(0x01, 0x19), false)],
            "Ctrl+V stays with the remap off"
        );
        let (x, y) = (
            kvm_proto::hid::scale_abs(1279, 1920),
            kvm_proto::hid::scale_abs(719, 1080),
        );
        assert!(x < 32_767 && y < 32_767);
        assert_eq!(
            step(&ctx, Event::MouseMove { x: 1279, y: 719 }),
            [push(abs(0x02, x, y), true)]
        );
    }

    /// PD5 ruling (§4.5): the core's state, its events and its outs print
    /// kinds, counts and flags only — never a key, a modifier, a unit, a
    /// position, a button or a wheel turn.
    #[test]
    fn debug_never_prints_a_key_or_a_position() {
        let mut a = Rig::new();
        let mut b = Rig::new();
        let ea = [
            Event::KeyPressed {
                code: 0x5C,
                extended: true,
            },
            Event::KeyPressed {
                code: 0x2C,
                extended: false,
            },
            Event::MouseButton {
                button: Button::Middle,
                pressed: true,
                x: 1234,
                y: 567,
            },
        ];
        let eb = [
            Event::KeyPressed {
                code: 0x1D,
                extended: false,
            },
            Event::KeyPressed {
                code: 0x10,
                extended: false,
            },
            Event::MouseButton {
                button: Button::Left,
                pressed: true,
                x: 89,
                y: 1011,
            },
        ];
        let mut oa = Vec::new();
        let mut ob = Vec::new();
        for (x, y) in ea.into_iter().zip(eb) {
            crate::testkit::assert_debug_redacted(
                &x,
                &y,
                &[0x5C, 0x2C, 0x1D, 0x10, 1234, 567, 89, 1011],
            );
            oa.extend(a.step(x));
            ob.extend(b.step(y));
        }
        let values = [
            0x80, 0x1D, 0x01, 0x10, 0x14, 0x5C, 0x2C, 0x04, 1234, 567, 89, 1011,
        ];
        crate::testkit::assert_debug_redacted(&oa, &ob, &values);
        crate::testkit::assert_debug_redacted(&a.core, &b.core, &values);
        for (x, y) in [
            (Event::UnicodePressed(0x2603), Event::UnicodePressed(0x41)),
            (Event::UnicodeReleased(0x2603), Event::UnicodeReleased(0x41)),
            (
                Event::Synchronize { caps_lock: true },
                Event::Synchronize { caps_lock: false },
            ),
            (
                Event::MouseMove { x: 1234, y: 567 },
                Event::MouseMove { x: 89, y: 1011 },
            ),
            (Event::Wheel { units: 1234 }, Event::Wheel { units: -567 }),
        ] {
            crate::testkit::assert_debug_redacted(&x, &y, &[0x2603, 0x41, 1234, 567, 89, 1011]);
        }
        let s = format!("{:?}", a.core);
        assert!(
            s.contains("keys_down: 1") && s.contains("buttons_down: 1"),
            "{s}"
        );
    }

    // ---- The property: no event or time sequence ends with a key held.

    /// xorshift64*: a fixed, seedable sequence for the property test.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
        }

        fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
            xs[self.below(xs.len())]
        }
    }

    const BUTTONS: [(Button, u8); 3] = [
        (Button::Left, 0x01),
        (Button::Right, 0x02),
        (Button::Middle, 0x04),
    ];

    fn button_bit(b: Button) -> u8 {
        BUTTONS.iter().find(|(x, _)| *x == b).unwrap().1
    }

    fn unit_usage(unit: u16) -> Option<u8> {
        char::from_u32(u32::from(unit))
            .and_then(us_stroke)
            .map(|s| s.usage)
    }

    /// What the writer wrote (§3.3: every frame is full state).
    #[derive(Default)]
    struct Device {
        kbd: Option<HidFrame>,
        buttons: u8,
    }

    impl Device {
        fn apply(&mut self, f: HidFrame) {
            match f {
                HidFrame::Keyboard { .. } => self.kbd = Some(f),
                HidFrame::AbsMouse { buttons, .. } | HidFrame::Wheel { buttons, .. } => {
                    self.buttons = buttons;
                }
                HidFrame::SetMode { .. } => {}
            }
        }

        fn holds_a_key(&self) -> bool {
            self.kbd.is_some_and(|f| f != kbd(0, 0))
        }
    }

    /// The writer's loop (hid/writer.rs): a pending release's zero reports
    /// first, then the queue.
    fn drain(hid: &HidControl, dev: &mut Device) {
        loop {
            if hid.take_release() {
                for f in hid.release_frames() {
                    dev.apply(f);
                    hid.note_sent(&f);
                }
                continue;
            }
            let Some(f) = hid.next_frame() else {
                break;
            };
            dev.apply(f);
            hid.note_sent(&f);
        }
    }

    /// The shell (Task 4.1's `carry_out`): every report through `push_at`
    /// with its stamp, every release through `HidControl::release_all`.
    fn carry(hid: &HidControl, outs: &[Out]) {
        for o in outs {
            match *o {
                Out::Push {
                    frame,
                    motion_only,
                    stamp,
                } => {
                    let _ = hid.push_at(stamp, frame, motion_only);
                }
                Out::Release(t) => hid.release_all(t),
                Out::Ignored => {}
            }
        }
    }

    /// What the core holds: non-modifier usages, modifier usages
    /// (0xE0..=0xE7), the button mask.
    fn held(core: &InputCore) -> (Vec<u8>, u8) {
        let mods = core.keys.held_modifier_bits();
        let usages = (0..=255u8)
            .filter(|u| core.keys.is_down(*u) || modifier_bit(*u).is_some_and(|b| mods & b != 0))
            .collect();
        (usages, core.pointer.held_buttons())
    }

    /// The property (§7.4, "a key must never end held"), over random
    /// sequences of keyboard, Unicode, mouse and Synchronize events, Ticks,
    /// time jumps (to a deadline, a nanosecond short of one, or past both
    /// timeouts), the shell's own releases (a moved epoch, a new session),
    /// lost client releases, remap and surface changes, and a stalled
    /// writer whose queue overflows — carried out through the real
    /// `HidControl` and drained as the writer does:
    /// - every report carries its step's epoch, and a release is always the
    ///   last out of its step;
    /// - a release fires exactly when its oracle says (Synchronize on a
    ///   Synchronize; at a Tick, the key-repeat timer when a held non-
    ///   modifier saw no accepted press for its timeout, else the modifier-
    ///   idle timer when a held modifier saw no keyboard event for its own),
    ///   and `next_deadline` is exactly the sooner armed deadline;
    /// - after any trigger or timer expiry nothing is held, in the core or
    ///   on the device; a moved epoch's step starts with the zero report;
    /// - whatever was held at a release stays up until the client's own
    ///   Released (or a Synchronize, m6);
    /// - whenever the core holds a key or modifier a deadline is armed, and
    ///   the device never holds what the core does not;
    /// - at the end the client goes silent: one Tick at the deadline leaves
    ///   no key held, and once the client lets go the device holds nothing.
    #[test]
    fn no_event_or_time_sequence_leaves_a_key_held() {
        let codes: [(u8, bool); 18] = [
            (0x1E, false), // a
            (0x2E, false), // c
            (0x2F, false), // v
            (0x30, false), // b
            (0x10, false), // q
            (0x02, false), // 1
            (0x1D, false), // LCtrl
            (0x1D, true),  // RCtrl
            (0x2A, false), // LShift
            (0x36, false), // RShift
            (0x38, false), // LAlt
            (0x38, true),  // RAlt
            (0x5B, true),  // LGUI
            (0x5C, true),  // RGUI
            (0x3A, false), // Caps Lock
            (0x1C, false), // Return
            (0x4D, true),  // Right
            (0x54, false), // unmapped
        ];
        let units: Vec<u16> = "AaCc1!".encode_utf16().chain([0xD800, 0x00E9]).collect();
        let coords = [0u16, 10, 960, 1919, 5000, u16::MAX];
        let spans = [(1920u16, 1080u16), (1280, 720), (1, 1), (0, 0)];
        let advances = [0u64, 1, 200, 900, 2_000, 9_000, 11_000, 31_000];
        let timeouts = [
            (Duration::from_secs(10), Duration::from_secs(30)),
            (Duration::from_secs(1), Duration::from_millis(500)),
            (Duration::from_secs(1), Duration::from_secs(3)),
            (Duration::from_secs(10), Duration::from_secs(3)),
        ];
        let shell_triggers = [
            ReleaseTrigger::SessionStart,
            ReleaseTrigger::WebsocketReconnect,
            ReleaseTrigger::Suppression,
            ReleaseTrigger::Closing,
        ];
        let mut fired = [0usize; 3]; // synchronize, key_repeat, modifier_idle
        for seed in 1..=64u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let (krt, mit) = timeouts[usize::try_from(seed).unwrap() % timeouts.len()];
            let hid = HidControl::new(rng.pick(&[4usize, 64]), Arc::new(Metrics::default()));
            let mut dev = Device::default();
            let mut core = InputCore::new();
            core.on_generation(1);
            let mut now = Instant::now();
            let mut seen = hid.epoch();
            let mut generation = 1;
            let (mut remap, mut surface) = (false, (1920, 1080));
            let mut stalled = false;
            // The client's side: what it has sent a Pressed for and not a
            // Released (a lost release stays here, never sent).
            let mut sent_codes: Vec<(u8, bool)> = Vec::new();
            let mut sent_units: Vec<u16> = Vec::new();
            let mut sent_buttons: Vec<Button> = Vec::new();
            // The oracle: the timers' bases (D8e; "any keyboard event"), and
            // what was held at a marking release and is still owed its
            // client Released (§7.4).
            let mut key_activity: Option<Instant> = None;
            let mut kbd_event: Option<Instant> = None;
            let mut owed: Vec<u8> = Vec::new();
            let mut owed_buttons = 0u8;
            let mk =
                |now: Instant, epoch: u64, generation: Gen, remap: bool, surface: (u16, u16)| Ctx {
                    now,
                    epoch,
                    generation,
                    surface,
                    mac_remap: remap,
                    key_repeat_timeout: krt,
                    modifier_idle_timeout: mit,
                };
            for i in 0..2_000 {
                let event = match rng.below(26) {
                    0..=4 => {
                        let c = if !sent_codes.is_empty() && rng.below(2) == 0 {
                            rng.pick(&sent_codes) // a typematic repeat
                        } else {
                            rng.pick(&codes)
                        };
                        if !sent_codes.contains(&c) {
                            sent_codes.push(c);
                        }
                        Event::KeyPressed {
                            code: c.0,
                            extended: c.1,
                        }
                    }
                    5..=7 => {
                        let c = if !sent_codes.is_empty() && rng.below(4) != 0 {
                            rng.pick(&sent_codes)
                        } else {
                            rng.pick(&codes) // a stray release
                        };
                        sent_codes.retain(|d| *d != c);
                        Event::KeyReleased {
                            code: c.0,
                            extended: c.1,
                        }
                    }
                    8 => {
                        let u = rng.pick(&units);
                        if !sent_units.contains(&u) {
                            sent_units.push(u);
                        }
                        Event::UnicodePressed(u)
                    }
                    9 => {
                        let u = if !sent_units.is_empty() && rng.below(4) != 0 {
                            rng.pick(&sent_units)
                        } else {
                            rng.pick(&units)
                        };
                        sent_units.retain(|d| *d != u);
                        Event::UnicodeReleased(u)
                    }
                    10 => Event::MouseMove {
                        x: rng.pick(&coords),
                        y: rng.pick(&coords),
                    },
                    11 | 12 => {
                        let pressed = rng.below(2) == 0;
                        let b = if !pressed && !sent_buttons.is_empty() && rng.below(4) != 0 {
                            rng.pick(&sent_buttons)
                        } else {
                            rng.pick(&BUTTONS).0
                        };
                        sent_buttons.retain(|d| *d != b);
                        if pressed {
                            sent_buttons.push(b);
                        }
                        Event::MouseButton {
                            button: b,
                            pressed,
                            x: rng.pick(&coords),
                            y: rng.pick(&coords),
                        }
                    }
                    13 => Event::Wheel {
                        units: rng.pick(&[-240i16, -120, -60, 60, 120, 360]),
                    },
                    14 => Event::Synchronize {
                        caps_lock: rng.below(2) == 0,
                    },
                    15 | 16 => Event::Tick,
                    17 | 18 => {
                        now += Duration::from_millis(rng.pick(&advances));
                        continue;
                    }
                    19 => {
                        // To a deadline, or a nanosecond short of it.
                        if let Some(at) = core.next_deadline() {
                            let at = if rng.below(2) == 0 {
                                at
                            } else {
                                at - Duration::from_nanos(1)
                            };
                            now = now.max(at);
                        }
                        Event::Tick
                    }
                    20 => {
                        // The shell's own release (§7.4's other triggers).
                        hid.release_all(rng.pick(&shell_triggers));
                        drain(&hid, &mut dev);
                        assert!(
                            !dev.holds_a_key() && dev.buttons == 0,
                            "seed {seed} step {i}: the shell's release left the device holding"
                        );
                        if rng.below(4) == 0 {
                            generation += 1;
                            core.on_generation(generation);
                            assert_eq!(held(&core), (Vec::new(), 0), "seed {seed} step {i}");
                            assert_eq!(core.next_deadline(), None, "seed {seed} step {i}");
                            owed.clear();
                            owed_buttons = 0;
                            key_activity = None;
                            kbd_event = None;
                        }
                        continue;
                    }
                    21 => {
                        // A lost client release (focus left the client): the
                        // key stays held at the bridge, with no more events.
                        if !sent_codes.is_empty() {
                            let c = rng.pick(&sent_codes);
                            sent_codes.retain(|d| *d != c);
                        }
                        continue;
                    }
                    22 => {
                        remap = rng.below(2) == 0;
                        surface = rng.pick(&spans);
                        continue;
                    }
                    23 => {
                        stalled = !stalled && rng.below(2) == 0;
                        continue;
                    }
                    _ => {
                        now += Duration::from_millis(rng.pick(&advances));
                        Event::Tick
                    }
                };
                let epoch = hid.epoch();
                let moved = epoch != seen;
                seen = epoch;
                let before = held(&core);
                let (held_nonmod, held_mod) = if moved {
                    (false, false)
                } else {
                    (
                        core.keys.held_nonmodifier_usages() > 0,
                        core.keys.held_modifier_bits() != 0,
                    )
                };
                let mut outs = Vec::new();
                core.step(
                    &mk(now, epoch, generation, remap, surface),
                    event,
                    &mut outs,
                );
                let at = format!("seed {seed} step {i} {}: {}", describe(event), show(&outs));
                // Every report carries its step's epoch; a release is the
                // last out of its step.
                for o in &outs {
                    if let Out::Push { stamp, .. } = o {
                        assert_eq!(*stamp, epoch, "{at}");
                    }
                }
                let rel = releases(&outs);
                assert!(rel.len() <= 1, "{at}");
                if !rel.is_empty() {
                    assert!(matches!(outs.last(), Some(Out::Release(_))), "{at}");
                }
                // A moved epoch: everything held then is released and
                // marked, and the step starts with the zero report.
                if moved {
                    assert_eq!(
                        outs.first(),
                        Some(&Out::Push {
                            frame: kbd(0, 0),
                            motion_only: false,
                            stamp: epoch
                        }),
                        "{at}"
                    );
                    for u in &before.0 {
                        if !owed.contains(u) {
                            owed.push(*u);
                        }
                    }
                    owed_buttons |= before.1;
                    key_activity = None;
                    kbd_event = None;
                }
                // The oracle for the core's own triggers.
                let want = match event {
                    Event::Synchronize { .. } => Some(ReleaseTrigger::Synchronize),
                    Event::Tick if held_nonmod && key_activity.is_some_and(|t| now >= t + krt) => {
                        Some(ReleaseTrigger::KeyRepeat)
                    }
                    Event::Tick if held_mod && kbd_event.is_some_and(|t| now >= t + mit) => {
                        Some(ReleaseTrigger::ModifierIdle)
                    }
                    _ => None,
                };
                assert_eq!(rel.first().copied(), want, "{at}");
                match want {
                    Some(ReleaseTrigger::Synchronize) => {
                        fired[0] += 1;
                        owed.clear(); // m6: the client has resynced
                        owed_buttons = 0;
                    }
                    Some(t) => {
                        fired[if t == ReleaseTrigger::KeyRepeat { 1 } else { 2 }] += 1;
                        for u in &before.0 {
                            if !owed.contains(u) {
                                owed.push(*u);
                            }
                        }
                        owed_buttons |= before.1;
                    }
                    None => {}
                }
                if want.is_some() {
                    key_activity = None;
                    kbd_event = None;
                    assert!(
                        held(&core) == (Vec::new(), 0),
                        "{at}: a trigger left something held"
                    );
                    assert_eq!(core.next_deadline(), None, "{at}");
                }
                // The event's own effects on the oracle.
                match event {
                    Event::KeyPressed { code, extended } => {
                        kbd_event = Some(now);
                        if let Some(u) = usage_for_scancode(code, extended)
                            && modifier_bit(u).is_none()
                            && core.keys.is_down(u)
                        {
                            key_activity = Some(now);
                        }
                    }
                    Event::UnicodePressed(unit) => {
                        kbd_event = Some(now);
                        if let Some(u) = unit_usage(unit)
                            && core.keys.is_down(u)
                        {
                            key_activity = Some(now);
                        }
                    }
                    Event::KeyReleased { code, extended } => {
                        kbd_event = Some(now);
                        if let Some(u) = usage_for_scancode(code, extended) {
                            owed.retain(|o| *o != u);
                        }
                    }
                    Event::UnicodeReleased(unit) => {
                        kbd_event = Some(now);
                        if let Some(u) = unit_usage(unit) {
                            owed.retain(|o| *o != u);
                        }
                    }
                    Event::MouseButton {
                        button,
                        pressed: false,
                        ..
                    } => owed_buttons &= !button_bit(button),
                    _ => {}
                }
                // Whatever was held at a release stays up until its own
                // Released (§7.4); with 18 codes the marks never overflow.
                for u in &owed {
                    assert!(
                        core.keys.is_released_by_bridge(*u),
                        "{at}: {u:#x} lost its mark"
                    );
                    let up = match modifier_bit(*u) {
                        Some(bit) => core.keys.held_modifier_bits() & bit == 0,
                        None => !core.keys.is_down(*u),
                    };
                    assert!(up, "{at}: {u:#x} re-pressed before its release");
                }
                assert_eq!(
                    core.pointer.held_buttons() & owed_buttons,
                    0,
                    "{at}: a button re-pressed before its release"
                );
                // ...and the marks are exactly what is owed: nothing else
                // is swallowed (m6: a Synchronize leaves no mark, so the
                // key-downs the client re-sends after it are presses).
                for u in 0..=255u8 {
                    assert_eq!(
                        core.keys.is_released_by_bridge(u),
                        owed.contains(&u),
                        "{at}: {u:#x}'s mark"
                    );
                }
                for (b, bit) in BUTTONS {
                    assert_eq!(
                        core.pointer.is_released_by_bridge(b),
                        owed_buttons & bit != 0,
                        "{at}: {b:?}'s mark"
                    );
                }
                // A held key or modifier always has its timer armed, at
                // exactly the sooner deadline.
                let kr = (core.keys.held_nonmodifier_usages() > 0)
                    .then(|| key_activity.expect("a held key with no key-repeat base") + krt);
                let mi = (core.keys.held_modifier_bits() != 0)
                    .then(|| kbd_event.expect("a held modifier with no idle base") + mit);
                assert_eq!(
                    core.next_deadline(),
                    [kr, mi].into_iter().flatten().min(),
                    "{at}"
                );
                carry(&hid, &outs);
                if !stalled || want.is_some() {
                    drain(&hid, &mut dev);
                    if want.is_some() {
                        assert!(
                            !dev.holds_a_key() && dev.buttons == 0,
                            "{at}: the device holds after a trigger"
                        );
                    }
                    // The device never holds what the core does not.
                    if let Some(HidFrame::Keyboard { modifiers, keys }) = dev.kbd {
                        for k in keys.iter().filter(|k| **k != 0) {
                            assert!(core.keys.is_down(*k), "{at}: device holds {k:#x}");
                        }
                        if modifiers != 0 {
                            assert!(
                                core.keys.held_modifier_bits() != 0
                                    || core.keys.held_nonmodifier_usages() > 0,
                                "{at}: device holds modifiers {modifiers:#x}"
                            );
                        }
                    }
                    assert_eq!(
                        dev.buttons & !core.pointer.held_buttons(),
                        0,
                        "{at}: device holds a button"
                    );
                }
            }
            // The client goes silent: one Tick at the deadline releases
            // every key (each release is of everything).
            drain(&hid, &mut dev);
            let epoch = hid.epoch();
            if let Some(at) = core.next_deadline() {
                now = now.max(at);
                let mut outs = Vec::new();
                core.step(
                    &mk(now, epoch, generation, remap, surface),
                    Event::Tick,
                    &mut outs,
                );
                assert!(
                    epoch != seen || !releases(&outs).is_empty(),
                    "seed {seed}: the deadline Tick released nothing: {}",
                    show(&outs)
                );
                seen = epoch;
                carry(&hid, &outs);
                drain(&hid, &mut dev);
            }
            assert_eq!(core.next_deadline(), None, "seed {seed}");
            assert_eq!(
                held(&core).0,
                Vec::<u8>::new(),
                "seed {seed}: a key was left held"
            );
            assert!(
                !dev.holds_a_key(),
                "seed {seed}: the device was left holding a key"
            );
            // The client lets go of its buttons: nothing is held anywhere.
            for b in sent_buttons {
                let mut outs = Vec::new();
                let epoch = hid.epoch();
                let e = Event::MouseButton {
                    button: b,
                    pressed: false,
                    x: 1,
                    y: 1,
                };
                core.step(&mk(now, epoch, generation, remap, surface), e, &mut outs);
                carry(&hid, &outs);
            }
            drain(&hid, &mut dev);
            assert_eq!(held(&core), (Vec::new(), 0), "seed {seed}");
            assert!(
                !dev.holds_a_key() && dev.buttons == 0,
                "seed {seed}: the device holds"
            );
        }
        // Every trigger the oracle knows fired, many times over.
        assert!(fired.iter().all(|n| *n > 500), "{fired:?}");
    }
}
