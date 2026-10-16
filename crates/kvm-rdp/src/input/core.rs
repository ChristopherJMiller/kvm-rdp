//! The input state machine (§7, §8), sans-IO: `step(now, ctx, event)`
//! appends `Out`s, `next_deadline` says when a timer or the paste next
//! needs a `Tick`. The release epoch is the release channel: a step whose
//! `ctx.epoch` moved since the last one releases first (every held key and
//! button becomes released-by-bridge, a paste ends), and every report it
//! then builds carries `ctx.epoch` as its stamp, so the shell's
//! `push_at(stamp, …)` drops it if a release raced it (design decision 6;
//! §7.3, §7.4). The two timers and `Synchronize` are the triggers the core
//! raises itself; the shell's own triggers (session start/end, suppression,
//! reconnect, Closing, shutdown) reach the core only as a bumped epoch.
//!
//! The timers fire only on a `Tick`, and a release the core raises is the
//! last out of its step: no report is ever built after it in the same step,
//! where it would carry the pre-release stamp and be dropped by `push_at`.
//! An event that arrives after a deadline but before the driver's `Tick`
//! therefore counts as activity, as if it had come just before; a shell
//! that steps a `Tick` first when `next_deadline() <= now` gets the
//! deadline exactly (the release, then the event at the new epoch).
//!
//! Paste (§8, design decision 7) is `input::paste`'s state, stepped here:
//! the chord (raw scancode, raw held bits, before any remap) starts it;
//! Pending waits, bounded by `paste.modifier_wait`, for the clipboard text
//! and for every modifier to release; Typing types through the Typist at
//! `paste.pace`, never more reports per step than `ctx.queue_room`, and
//! never more than `TYPIST_ROOM` whatever the shell says (DD6; PD9 carry 5).
//! Every key the paste swallows is released by the bridge (D3c).
//!
//! Clipboard answers are accounted per generation (PD9 carry 3): CLIPRDR
//! answers data requests in order and IronRDP forwards every answer, asked
//! or not, so the core counts the requests it has made and not seen
//! answered, and an answer — text, a failure, the fatal oversize, or one
//! the backend dropped in flight — belongs to the oldest of them. Only the
//! Pending paste whose own request that is takes it; any other is
//! discarded and counted (`late`, or `unasked` with none outstanding), so a
//! paste never types the answer to an earlier one that timed out.
//!
//! A request whose answer never comes would otherwise shift every later
//! answer onto the request before it, for the rest of the session (PD9
//! review I2): a client that never answers, or one whose answer IronRDP
//! parses as a file list (the backend forwards that as an answer with no
//! text). So each request keeps its instant, and one `request_retire` old
//! (`max(60 s, 2 × paste.modifier_wait)`: never a waiting paste's own) is
//! retired, counted `unanswered`, when the next paste starts or the next
//! answer comes — no timer of its own. Two residuals remain, accepted (PD9
//! re-review; see `retire`): a never-answering client's drift heals only
//! after a `request_retire` pause in paste attempts, and an answer later
//! than that can be typed by a newer paste.
//!
//! Every type here that holds input (`Event`, `Out`, `InputCore`) has a
//! redacted `Debug` (PD5 ruling, §4.5): kinds, counts and flags only —
//! pasted text included (PD7 rule).
use crate::hid::ReleaseTrigger;
use crate::input::keys::{KeyReport, Keyboard};
use crate::input::paste::{PasteOutcome, PasteRefusal, ROOM_POLL, State, TYPIST_ROOM};
use crate::input::pointer::{Button, Pointer};
use crate::msg::Gen;
use kvm_proto::hid::HidFrame;
use kvm_proto::keymap::{Chord, USAGE_ESC, modifier_bit, unicode_key_stroke, usage_for_scancode};
use kvm_proto::paste::{PastePolicy, Prepared, RELEASE, Typist, decode_utf16le, prepare};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// What the shell knows at one step (no input state: a derived `Debug` is
/// safe — the chord and the paste settings are config).
#[derive(Debug, Clone)]
pub struct Ctx {
    pub now: Instant,
    pub epoch: u64,
    pub generation: Gen,
    pub surface: (u16, u16),
    pub mac_remap: bool,
    pub key_repeat_timeout: Duration,
    pub modifier_idle_timeout: Duration,
    /// `paste.chord` (§8, DD11).
    pub chord: Chord,
    /// `paste.pace`: the least time between two Typist reports (DD6).
    pub pace: Duration,
    /// `paste.modifier_wait`: how long a pending paste waits for its text
    /// and for the modifiers to release (DD4).
    pub modifier_wait: Duration,
    /// `paste.multiline = "refuse"`.
    pub multiline_refuse: bool,
    /// `paste.max_chars`.
    pub max_chars: usize,
    /// The HID queue's free room, `TYPIST_ROOM - queued` (DD6, D2b): the most Typist
    /// reports one step may push.
    pub queue_room: usize,
}

#[derive(Clone, PartialEq, Eq)]
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
    /// A button released with no position (a relative release, PD9 review
    /// I4): released where the pointer is, if held.
    ButtonUp {
        button: Button,
    },
    Wheel {
        units: i16,
    },
    /// The reassembled `CF_UNICODETEXT` bytes of a clipboard response.
    ClipboardText(Vec<u8>),
    /// A clipboard response failed (CB_RESPONSE_FAIL, the client's or
    /// IronRDP's own): one answer, with no text.
    ClipboardFailed,
    /// A clipboard response over `paste.max_bytes`: one answer, and the
    /// session's end (§8; the shell steps it before the close).
    ClipboardOversize,
    /// This many answers came while another was in flight to the shell and
    /// were dropped by the backend (PD8 review m2): answers with no text.
    ClipboardLost(u32),
    /// A format list said Unicode text is (or is not) on the clipboard: the
    /// core's only availability signal (D9c).
    ClipboardAvailable(bool),
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
    /// Ask the client for its `CF_UNICODETEXT` (a paste is pending).
    RequestClipboard,
    /// A paste outcome, for the shell to count (§8).
    Paste(PasteOutcome),
    /// A clipboard answer no paste took (PD9 carry 3): `"late"` (an earlier
    /// request's, after its paste ended) or `"unasked"`; never typed. Or a
    /// request retired with no answer, `"unanswered"` (I2).
    ClipboardDiscarded(&'static str),
}

/// §4.5 (PD5 ruling; PD7: pasted text is as sensitive as a password): an
/// event is a keystroke, a typed unit, the pointer's state or clipboard
/// text — `Debug` names its kind only (never a code, a unit, Caps Lock, a
/// position, a button, a wheel turn, a byte of text or its availability).
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
            Event::ButtonUp { .. } => "ButtonUp",
            Event::Wheel { .. } => "Wheel",
            Event::ClipboardText(_) => "ClipboardText",
            Event::ClipboardFailed => "ClipboardFailed",
            Event::ClipboardOversize => "ClipboardOversize",
            Event::ClipboardLost(_) => "ClipboardLost",
            Event::ClipboardAvailable(_) => "ClipboardAvailable",
            Event::Tick => "Tick",
        };
        f.debug_struct("Event")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

/// §4.5 (PD5 ruling): a report shows only `HidFrame`'s redacted kind, with
/// its flag and stamp; a release shows its trigger; a paste outcome its
/// label and counts (never text).
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
            Out::RequestClipboard => f.write_str("RequestClipboard"),
            Out::Paste(p) => f.debug_tuple("Paste").field(p).finish(),
            Out::ClipboardDiscarded(why) => f.debug_tuple("ClipboardDiscarded").field(why).finish(),
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
    /// The paste's state (§8).
    paste: State,
    /// The last format list offered Unicode text (D9c).
    clipboard_text: bool,
    /// When each clipboard request made this generation and not answered
    /// went out, oldest first (PD9 carry 3a; I2): at most `MAX_REQUESTS`,
    /// each retired once `request_retire` old. A request that strays into
    /// another connection dies with this one: `on_generation` clears it.
    requests: VecDeque<Instant>,
}

/// Whose a clipboard answer is (PD9 carry 3a).
enum Whose {
    /// The Pending paste's own: its request was the oldest unanswered.
    Paste,
    /// An earlier request's, whose paste has ended (or is not this one).
    Late,
    /// No request is outstanding.
    Unasked,
}

/// At most this many clipboard requests are outstanding (IronRDP's own cap
/// on unanswered ones, ironrdp-cliprdr's 64): a paste past it is refused
/// (`Refused(Backlog)`) and asks nothing (PD9 review I2, re-review m-R2).
pub const MAX_REQUESTS: usize = 64;

/// The least age at which an unanswered clipboard request is retired.
pub const REQUEST_RETIRE_MIN: Duration = Duration::from_secs(60);

/// When a clipboard request no answer has come for is retired (PD9 review
/// I2): `max(60 s, 2 × paste.modifier_wait)` — never while the paste that
/// made it still waits.
#[must_use]
pub fn request_retire(modifier_wait: Duration) -> Duration {
    REQUEST_RETIRE_MIN.max(modifier_wait.saturating_mul(2))
}

/// §4.5 (PD5 ruling): the keyboard's, pointer's and paste's redacted
/// `Debug`s, the generation and epoch, and whether each timer is armed —
/// never a key, a position, a keystroke's time or pasted text.
impl std::fmt::Debug for InputCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InputCore")
            .field("keys", &self.keys)
            .field("pointer", &self.pointer)
            .field("generation", &self.generation)
            .field("seen_epoch", &self.seen_epoch)
            .field("key_repeat_armed", &self.key_repeat_at.is_some())
            .field("modifier_idle_armed", &self.modifier_idle_at.is_some())
            .field("paste", &self.paste)
            .field("clipboard_text", &self.clipboard_text)
            .field("requests", &self.requests.len())
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
            paste: State::Idle,
            clipboard_text: false,
            requests: VecDeque::new(),
        }
    }

    #[must_use]
    pub fn generation(&self) -> Gen {
        self.generation
    }

    /// The release epoch of the core's last step: every report it has
    /// built since carries it (design decision 6).
    #[must_use]
    pub fn seen_epoch(&self) -> u64 {
        self.seen_epoch
    }

    /// Whether something the core sent may still be down on the KVM: a
    /// key, a modifier, a button, or a typing paste's press. (A Pending
    /// paste sent nothing of its own.)
    #[must_use]
    pub fn holds_input(&self) -> bool {
        self.keys.held_modifier_bits() != 0
            || self.keys.held_nonmodifier_usages() > 0
            || self.pointer.held_buttons() != 0
            || matches!(self.paste, State::Typing { .. })
    }

    /// A new session: reset everything, the paste, the clipboard's
    /// availability (D9c) and its outstanding requests included. The
    /// release epoch it has seen is kept — it is `HidControl`'s, not the
    /// session's.
    ///
    /// Nothing is released here: the caller must make sure the KVM holds
    /// nothing the core forgets — the handler's `SessionStart`/`SessionEnd`
    /// release comes with every generation change, and `rdp::input` adds
    /// one should it ever not have (PD6 m3). An active paste's end is
    /// returned for the shell to count (PD9 carry 2): `Aborted("session")`.
    #[must_use]
    pub fn on_generation(&mut self, g: Gen) -> Option<PasteOutcome> {
        let ended = self
            .paste
            .is_active()
            .then_some(PasteOutcome::Aborted("session"));
        self.keys = Keyboard::default();
        self.pointer = Pointer::default();
        self.generation = g;
        self.last_key_activity = None;
        self.last_kbd_event = None;
        self.key_repeat_at = None;
        self.modifier_idle_at = None;
        self.paste = State::Idle;
        self.clipboard_text = false;
        self.requests.clear();
        ended
    }

    #[must_use]
    pub fn caps_lock_on(&self) -> bool {
        self.keys.caps_lock_on()
    }

    /// The soonest of the two armed timer deadlines and the paste's.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        [
            self.key_repeat_at,
            self.modifier_idle_at,
            self.paste.deadline(),
        ]
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
        // The release channel: a moved epoch releases before the event. Its
        // zero report goes out whatever the event — a clipboard word or a
        // Tick too: one extra KVM write per release, harmless (PD6 m6; PD9
        // review m4; L2 goldens expect it).
        if ctx.epoch != self.seen_epoch {
            self.seen_epoch = ctx.epoch;
            let frame = self.release_marked(out);
            out.push(Out::Push {
                frame,
                motion_only: false,
                stamp: ctx.epoch,
            });
        }
        if let Some(event) = self.paste_filter(ctx, event, out) {
            self.handle(ctx, event, out);
        }
        self.paste_step(ctx, out);
        self.arm(ctx);
    }

    /// §7.4's release of the core's own state: keys and modifiers (D3a) and
    /// buttons (D3b) become released-by-bridge; both timers disarm; an
    /// active paste ends (§8, D3c). Every release path — the epoch step,
    /// `Synchronize`, both timers — comes through here. The aborted paste
    /// pushes nothing of its own: the release's zero (the epoch step's
    /// report, or the shell's `release_all` for the core's own triggers)
    /// clears whatever the Typist left on the KVM, and a report pushed here
    /// would only be a second zero — or, ahead of a core trigger, one
    /// `push_at` drops.
    fn release_state(&mut self, out: &mut Vec<Out>) -> KeyReport {
        if self.paste.is_active() {
            self.paste = State::Idle;
            out.push(Out::Paste(PasteOutcome::Aborted("release")));
        }
        let r = self.keys.release_all();
        self.pointer.release_all();
        self.last_key_activity = None;
        self.last_kbd_event = None;
        r
    }

    /// A release that keeps its marks (the epoch step and both timers): a
    /// held key `MAX_RBB` had no room for is one dropped input (DD9).
    fn release_marked(&mut self, out: &mut Vec<Out>) -> HidFrame {
        let r = self.release_state(out);
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
                self.note_key_activity(ctx, unit_usage(u));
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
                // for drops nothing. A paste ends (§8, D3c).
                let _ = self.release_state(out);
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
            // I4: `None`: it was not held (its mark, if any, is cleared).
            Event::ButtonUp { button } => {
                if let Some(r) = self.pointer.button_up(button) {
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
            Event::ClipboardAvailable(text) => self.clipboard_text = text,
            Event::ClipboardText(bytes) => match self.answer(ctx, out) {
                Whose::Paste => self.clipboard_text_arrived(ctx, &bytes, out),
                other => Self::discard(&other, out),
            },
            // PD8 review (b): the paste that asked ends at once, not after
            // `paste.modifier_wait`.
            Event::ClipboardFailed => match self.answer(ctx, out) {
                Whose::Paste => {
                    self.end_paste(ctx, PasteOutcome::Aborted("clipboard_failed"), out);
                }
                other => Self::discard(&other, out),
            },
            // The session is ending (the pump's close follows); the paste
            // that asked is counted as refused for it. Nothing else to do.
            Event::ClipboardOversize => {
                if let Whose::Paste = self.answer(ctx, out) {
                    self.end_paste(ctx, PasteOutcome::Refused(PasteRefusal::Oversize), out);
                }
            }
            // The shell counted these (`in_flight`); they still answer
            // requests, oldest first. Bounded by the requests outstanding.
            Event::ClipboardLost(n) => {
                for _ in 0..n {
                    match self.answer(ctx, out) {
                        Whose::Paste => {
                            self.end_paste(ctx, PasteOutcome::Aborted("clipboard_lost"), out);
                        }
                        Whose::Late => {}
                        Whose::Unasked => break,
                    }
                }
            }
            Event::Tick => self.timers(ctx, out),
        }
    }

    /// One clipboard answer, in the order the client sends them: it is the
    /// oldest outstanding request's (PD9 carry 3a). The Pending paste takes
    /// it only if that request is its own (`ahead` is 0) and no text has
    /// come — an answer to an earlier paste that timed out or was aborted
    /// never reaches the next. Requests `request_retire` old are retired
    /// first (I2).
    fn answer(&mut self, ctx: &Ctx, out: &mut Vec<Out>) -> Whose {
        self.retire(ctx, out);
        if self.requests.pop_front().is_none() {
            return Whose::Unasked;
        }
        match &mut self.paste {
            State::Pending {
                ahead, text: None, ..
            } => match ahead.checked_sub(1) {
                None => Whose::Paste,
                Some(a) => {
                    *ahead = a;
                    Whose::Late
                }
            },
            _ => Whose::Late,
        }
    }

    /// I2: retire every request `request_retire` old, counted `unanswered`.
    /// One ahead of the Pending paste's own leaves one fewer to wait for.
    /// The paste's own is that old only once the paste is past its own wait
    /// (at most half that age) with no step since to end it: this step's
    /// `paste_step` ends it (`modifier_wait`), and no answer can reach it —
    /// none is outstanding after its own.
    ///
    /// Two residuals, accepted (PD9 re-review m-R1; rev 6.3):
    /// - Retirement goes by age, so with a client that leaves a request
    ///   unanswered, a paste made before that request is `request_retire`
    ///   old takes the phantom's slot with its own prompt answer (discarded,
    ///   `late`), and its own request becomes the phantom, with a fresh age:
    ///   retrying within 60 s moves the drift forward, and only a
    ///   `request_retire` pause in paste attempts heals it. Ending the chain
    ///   would mean letting a paste take an answer while an older request
    ///   may still be answered — what carry 3a forbids
    ///   (`a_late_answer_is_never_typed_by_the_next_paste`).
    /// - An answer more than `request_retire` late, once its request is
    ///   retired, pairs with a newer one and can be typed. CLIPRDR's format
    ///   data responses carry no request id to tell them apart, and with
    ///   delayed rendering a merely slow answer carries the clipboard as of
    ///   answering; stale content needs a transport stall over 60 s. While
    ///   video flows to the client, that stall closes the EGFX gates and
    ///   `video.stall_timeout` (10 s) ends it as `client_stalled` first; not
    ///   while the client has suppressed its display (`Paused`) or is
    ///   reactivating, when the stall timer is frozen, nor while it suspends
    ///   acks, when the timer is off (PD11b review I3; spec §8).
    fn retire(&mut self, ctx: &Ctx, out: &mut Vec<Out>) {
        let after = request_retire(ctx.modifier_wait);
        while let Some(at) = self.requests.front().copied() {
            if ctx.now < deadline(at, after) {
                break;
            }
            let _ = self.requests.pop_front();
            out.push(Out::ClipboardDiscarded("unanswered"));
            if let State::Pending {
                ahead, text: None, ..
            } = &mut self.paste
            {
                *ahead = ahead.saturating_sub(1);
            }
        }
    }

    /// PD9 carry 3 (a, c): an answer no paste takes is discarded and
    /// counted, never kept for a later paste.
    fn discard(whose: &Whose, out: &mut Vec<Out>) {
        out.push(Out::ClipboardDiscarded(match whose {
            Whose::Unasked => "unasked",
            Whose::Paste | Whose::Late => "late",
        }));
    }

    /// §7.4's two timers, from the state as it is now (an epoch release at
    /// the top of this step has already disarmed both). One release covers
    /// everything, so at most one fires; the key-repeat timer first. The
    /// release is the last out of the step (it ends any paste, so the
    /// paste's step after it pushes nothing).
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

    // ---- Paste (§8).

    /// §8's input rules around a paste: DD4's while Pending, §8's "while
    /// typing" list while Typing. `None`: the event was swallowed.
    fn paste_filter(&mut self, ctx: &Ctx, event: Event, out: &mut Vec<Out>) -> Option<Event> {
        let active = self.paste.is_active();
        let typing = matches!(self.paste, State::Typing { .. });
        match event {
            // The chord starts a paste; a second one meanwhile is swallowed.
            Event::KeyPressed { code, extended } if self.is_chord(ctx, code, extended) => {
                self.last_kbd_event = Some(ctx.now);
                self.swallow_press(usage_for_scancode(code, extended), out);
                if !active {
                    self.start_paste(ctx, out);
                }
                None
            }
            // A fresh Esc aborts, Pending or Typing, and is itself
            // swallowed. A repeat of an Esc held since before the chord is a
            // repeat (it falls through and changes nothing): swallowing it
            // would mark a key that is still down. A Unicode ESC (U+001B)
            // is the same key (rev 6.3, PD11b I5; PD7 m5).
            Event::KeyPressed { code, extended }
                if active
                    && usage_for_scancode(code, extended) == Some(USAGE_ESC)
                    && self.is_fresh_press(USAGE_ESC) =>
            {
                self.last_kbd_event = Some(ctx.now);
                self.swallow_press(Some(USAGE_ESC), out);
                self.end_paste(ctx, PasteOutcome::Aborted("esc"), out);
                None
            }
            Event::UnicodePressed(unit)
                if active
                    && unit_usage(unit) == Some(USAGE_ESC)
                    && self.is_fresh_press(USAGE_ESC) =>
            {
                self.last_kbd_event = Some(ctx.now);
                self.swallow_press(Some(USAGE_ESC), out);
                self.end_paste(ctx, PasteOutcome::Aborted("esc"), out);
                None
            }
            // Typing: every client press is swallowed and released by the
            // bridge; a release updates the state (all-zero since typing
            // began) and sends nothing (§8, D3c). An unmapped or untypeable
            // key is counted on its press, once (the PD5 carry).
            Event::KeyPressed { code, extended } if typing => {
                self.last_kbd_event = Some(ctx.now);
                self.swallow_press(usage_for_scancode(code, extended), out);
                None
            }
            Event::UnicodePressed(unit) if typing => {
                self.last_kbd_event = Some(ctx.now);
                self.swallow_press(unit_usage(unit), out);
                None
            }
            Event::KeyReleased { code, extended } if typing => {
                self.last_kbd_event = Some(ctx.now);
                let _ = self.keys.release(code, extended);
                None
            }
            Event::UnicodeReleased(unit) if typing => {
                self.last_kbd_event = Some(ctx.now);
                let _ = self.keys.unicode_release(unit);
                None
            }
            // Pending: a fresh non-modifier press cancels and goes through
            // (DD4). Modifier presses, repeats and releases fall through to
            // `handle` as ever, so the KVM's state follows the client's —
            // the chord's modifiers reached the KVM, so their releases must
            // (controller ruling 8).
            Event::KeyPressed { code, extended }
                if active && self.is_fresh(usage_for_scancode(code, extended)) =>
            {
                self.end_paste(ctx, PasteOutcome::Aborted("key"), out);
                Some(event)
            }
            Event::UnicodePressed(unit) if active && self.is_fresh(unit_usage(unit)) => {
                self.end_paste(ctx, PasteOutcome::Aborted("key"), out);
                Some(event)
            }
            Event::MouseButton { .. } | Event::ButtonUp { .. } if active => {
                self.end_paste(ctx, PasteOutcome::Aborted("mouse"), out);
                Some(event) // the click itself goes through
            }
            other => Some(other),
        }
    }

    /// The chord: matched on the raw scancode and the raw held bits (§8),
    /// and only on a fresh press of its key — never on a repeat of a key the
    /// bridge released (a swallowed V), nor of one the client holds (a V
    /// pressed, and sent, before the modifiers).
    fn is_chord(&self, ctx: &Ctx, code: u8, extended: bool) -> bool {
        usage_for_scancode(code, extended).is_some_and(|u| self.is_fresh_press(u))
            && ctx
                .chord
                .matches(code, extended, self.keys.held_modifier_bits())
    }

    /// A press that is not a typematic repeat: its key is neither held nor
    /// released by the bridge. Only such a press is swallowed while
    /// Pending, so a usage is never both down and marked.
    fn is_fresh_press(&self, usage: u8) -> bool {
        !self.keys.is_down(usage) && !self.keys.is_released_by_bridge(usage)
    }

    /// A new press of a non-modifier key: not a modifier, not a repeat of a
    /// held key, not a released-by-bridge key's repeat.
    fn is_fresh(&self, usage: Option<u8>) -> bool {
        usage.is_some_and(|u| modifier_bit(u).is_none() && self.is_fresh_press(u))
    }

    /// A swallowed press is released by the bridge (D3c): its repeats after
    /// the paste are not fresh presses. Unmapped or unremembered: counted.
    fn swallow_press(&mut self, usage: Option<u8>, out: &mut Vec<Out>) {
        if !usage.is_some_and(|u| self.keys.mark_released_by_bridge(u)) {
            out.push(Out::Ignored);
        }
    }

    fn start_paste(&mut self, ctx: &Ctx, out: &mut Vec<Out>) {
        let refusal = if !self.clipboard_text {
            Some(PasteRefusal::NoText)
        } else if self.keys.caps_lock_on() {
            Some(PasteRefusal::CapsLock)
        } else {
            None
        };
        if let Some(why) = refusal {
            out.push(Out::Paste(PasteOutcome::Refused(why)));
            return;
        }
        // Its answer comes after those of the requests still unanswered,
        // less any retired now (I2). With `MAX_REQUESTS` of them, the paste
        // is refused here and sends nothing (m-R2): IronRDP would fail the
        // request itself, and that failure would be taken for the oldest
        // request's answer.
        self.retire(ctx, out);
        if self.requests.len() >= MAX_REQUESTS {
            out.push(Out::Paste(PasteOutcome::Refused(PasteRefusal::Backlog)));
            return;
        }
        self.paste = State::Pending {
            deadline: deadline(ctx.now, ctx.modifier_wait),
            ahead: u32::try_from(self.requests.len()).unwrap_or(u32::MAX),
            text: None,
            skipped: 0,
        };
        self.requests.push_back(ctx.now);
        out.push(Out::Paste(PasteOutcome::Started));
        out.push(Out::RequestClipboard);
    }

    /// DD4: only a paste that is Pending and has no text yet takes a
    /// response — `answer` has made sure this one is its own (PD9 carry
    /// 3a); any other response types nothing. Each ill-formed unit is
    /// one U+FFFD that `prepare` skips and counts, so `prepare`'s count is
    /// the whole skip count (adding `decode_utf16le`'s would count each
    /// twice).
    fn clipboard_text_arrived(&mut self, ctx: &Ctx, bytes: &[u8], out: &mut Vec<Out>) {
        if !matches!(self.paste, State::Pending { text: None, .. }) {
            return;
        }
        let (decoded, _ill_formed) = decode_utf16le(bytes);
        let policy = PastePolicy {
            multiline_refuse: ctx.multiline_refuse,
            max_chars: ctx.max_chars,
        };
        match prepare(&decoded, &policy) {
            (Prepared::RefusedMultiline, _) => {
                self.end_paste(ctx, PasteOutcome::Refused(PasteRefusal::Multiline), out);
            }
            (Prepared::Text(chars), s) => {
                if let State::Pending { text, skipped, .. } = &mut self.paste {
                    *text = Some(chars);
                    *skipped = s.skipped;
                }
            }
        }
    }

    /// End an active paste with `outcome`. If it was typing, the Typist may
    /// have left a press on the KVM: an all-zero report follows, stamped
    /// with the step's epoch (the core's keyboard state is all-zero while
    /// typing, so the two agree; §8: "abort and completion both end with an
    /// all-zero keyboard report"). A Pending paste sent nothing of its own:
    /// the KVM already holds exactly the core's state.
    fn end_paste(&mut self, ctx: &Ctx, outcome: PasteOutcome, out: &mut Vec<Out>) {
        let was_typing = matches!(self.paste, State::Typing { .. });
        self.paste = State::Idle;
        out.push(Out::Paste(outcome));
        if was_typing {
            out.push(Out::Push {
                frame: RELEASE,
                motion_only: false,
                stamp: ctx.epoch,
            });
        }
    }

    /// Every step's tail: Pending's deadline and its move to Typing, then
    /// Typing's paced, room-bounded reports (DD6, D2b). The room is
    /// clamped to `TYPIST_ROOM` whatever the shell reports (PD9 carry 5).
    fn paste_step(&mut self, ctx: &Ctx, out: &mut Vec<Out>) {
        let room = ctx.queue_room.min(TYPIST_ROOM);
        self.paste = match std::mem::replace(&mut self.paste, State::Idle) {
            State::Pending {
                text: Some(chars),
                skipped,
                ..
            } if self.keys.held_modifier_bits() == 0 => {
                // From here the Typist is the only keyboard source: what the
                // client still holds is released by the bridge (D3c). Its
                // zero goes out now, not with the Typist's first report:
                // the Typist may push nothing (an empty text, or no room),
                // and a key the core no longer holds — whose client Released
                // will send nothing — must never stay held on the KVM
                // (§7.4). A release is never withheld for room; it takes one
                // unit of it when there is some.
                let held = self.keys.held_nonmodifier_usages() > 0;
                let r = self.keys.release_all();
                if r.dropped {
                    out.push(Out::Ignored);
                }
                self.last_key_activity = None;
                let mut room = room;
                if held {
                    out.push(Out::Push {
                        frame: r.frame,
                        motion_only: false,
                        stamp: ctx.epoch,
                    });
                    room = room.saturating_sub(1);
                }
                Self::type_some(ctx, room, Typist::new(&chars), 0, skipped, ctx.now, out)
            }
            State::Pending { deadline, .. } if ctx.now >= deadline => {
                out.push(Out::Paste(PasteOutcome::Aborted("modifier_wait")));
                State::Idle
            }
            State::Typing {
                typist,
                typed,
                skipped,
                next_report_at,
            } => Self::type_some(ctx, room, typist, typed, skipped, next_report_at, out),
            other => other,
        };
    }

    /// At most `room` (the queue's, `ctx.queue_room`, less what this step
    /// already pushed) reports, each only when its time has come; after
    /// each, the next is `pace` from now (no catch-up burst). With no room,
    /// look again `ROOM_POLL` from now.
    fn type_some(
        ctx: &Ctx,
        mut room: usize,
        mut typist: Typist,
        mut typed: usize,
        skipped: usize,
        mut next_report_at: Instant,
        out: &mut Vec<Out>,
    ) -> State {
        if room == 0 {
            next_report_at = next_report_at.max(deadline(ctx.now, ROOM_POLL));
        }
        while room > 0 && ctx.now >= next_report_at {
            let Some(frame) = typist.next() else {
                break;
            };
            if frame != RELEASE {
                typed = typed.saturating_add(1);
            }
            out.push(Out::Push {
                frame,
                motion_only: false,
                stamp: ctx.epoch,
            });
            room = room.saturating_sub(1);
            next_report_at = deadline(ctx.now, ctx.pace);
        }
        if typist.is_done() {
            out.push(Out::Paste(PasteOutcome::Done { typed, skipped }));
            return State::Idle;
        }
        State::Typing {
            typist,
            typed,
            skipped,
            next_report_at,
        }
    }
}

/// A Unicode unit's live-keystroke usage (`unicode_key_stroke`: the US
/// layout, and CR, BS and ESC as Return, Backspace and Esc — rev 6.3);
/// `None`: untypeable or a surrogate.
fn unit_usage(unit: u16) -> Option<u8> {
    char::from_u32(u32::from(unit))
        .and_then(unicode_key_stroke)
        .map(|s| s.usage)
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
    use crate::input::paste::{PasteOutcome, PasteRefusal};
    use crate::metrics::Metrics;
    use kvm_proto::hid::HidFrame;
    use kvm_proto::keymap::{
        Chord, MOD_LSHIFT, modifier_bit, unicode_key_stroke, usage_for_scancode,
    };
    use std::sync::Arc;

    /// The default chord, `ctrl+option+shift+v`.
    fn chord() -> Chord {
        Chord::parse("ctrl+option+shift+v").unwrap()
    }

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
        /// The HID queue's free room the ctx reports (DD6).
        room: usize,
    }

    impl Rig {
        /// A clean core that has seen a format list offering text (D9c).
        fn new() -> Rig {
            let mut r = Rig {
                core: InputCore::new(),
                now: Instant::now(),
                epoch: 0,
                room: 1,
            };
            r.step(Event::ClipboardAvailable(true));
            r
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
                chord: chord(),
                pace: Duration::ZERO,
                modifier_wait: Duration::from_secs(5),
                multiline_refuse: false,
                max_chars: 4096,
                queue_room: self.room,
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
    fn describe(e: &Event) -> String {
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
            Event::ButtonUp { button } => format!("ButtonUp({button:?})"),
            Event::Wheel { units } => format!("Wheel({units})"),
            Event::ClipboardText(b) => format!("ClipboardText({:02x?})", b),
            Event::ClipboardFailed => "ClipboardFailed".to_owned(),
            Event::ClipboardOversize => "ClipboardOversize".to_owned(),
            Event::ClipboardLost(n) => format!("ClipboardLost({n})"),
            Event::ClipboardAvailable(a) => format!("ClipboardAvailable({a})"),
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
                Out::RequestClipboard => "RequestClipboard".to_owned(),
                Out::Paste(p) => format!("Paste({p:?})"),
                Out::ClipboardDiscarded(why) => format!("ClipboardDiscarded({why})"),
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
        assert_eq!(r.core.on_generation(2), None, "no paste to end");
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
        assert_eq!(r.core.on_generation(7), None);
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
            chord: chord(),
            pace: Duration::ZERO,
            modifier_wait: Duration::from_secs(5),
            multiline_refuse: false,
            max_chars: 4096,
            queue_room: 8,
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

    // ---- Paste (§8, Task 3.2).

    fn chord_event() -> Event {
        // The chord is ctrl+option+shift+v; press V (0x2F) with them held.
        Event::KeyPressed {
            code: 0x2F,
            extended: false,
        }
    }

    fn hold_chord(r: &mut Rig) {
        for code in [0x1D, 0x38, 0x2A] {
            // LCtrl, LAlt, LShift
            r.step(Event::KeyPressed {
                code,
                extended: false,
            });
        }
    }

    fn outcomes(out: &[Out]) -> Vec<&PasteOutcome> {
        out.iter()
            .filter_map(|o| if let Out::Paste(p) = o { Some(p) } else { None })
            .collect()
    }

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// The chord, its release, and `text` arriving: typing has begun. The
    /// outs of the step the text arrived in.
    fn start_paste(r: &mut Rig, text: &str) -> Vec<Out> {
        hold_chord(r);
        r.step(chord_event());
        for code in [0x2F, 0x1D, 0x38, 0x2A] {
            r.step(Event::KeyReleased {
                code,
                extended: false,
            });
        }
        r.step(Event::ClipboardText(utf16le(text)))
    }

    /// Ticks until the paste ends; its outcome.
    fn finish(r: &mut Rig) -> PasteOutcome {
        for _ in 0..64 {
            r.advance(Duration::from_millis(1));
            let o = r.step(Event::Tick);
            if let Some(p) = outcomes(&o).first() {
                return (*p).clone();
            }
        }
        panic!("the paste never ended");
    }

    /// A keyboard push whose first slot holds `usage`.
    fn pushes_usage(out: &[Out], usage: u8) -> bool {
        pushes(out)
            .iter()
            .any(|(f, _)| matches!(f, HidFrame::Keyboard { keys, .. } if keys[0] == usage))
    }

    /// §8: the chord (matched before any remap) with text available starts
    /// a paste and requests the clipboard; the chord's key never reaches
    /// the KVM.
    #[test]
    fn the_chord_starts_a_paste_and_swallows_its_key() {
        let mut r = Rig::new();
        hold_chord(&mut r);
        let before = r.now;
        let out = r.step(chord_event());
        assert!(matches!(outcomes(&out).as_slice(), [PasteOutcome::Started]));
        assert!(out.iter().any(|o| matches!(o, Out::RequestClipboard)));
        // No keyboard push carries V's usage (0x19).
        assert!(!pushes_usage(&out, 0x19), "{}", show(&out));
        assert_eq!(
            r.core.next_deadline(),
            Some(before + Duration::from_secs(5))
        );
    }

    #[test]
    fn a_chord_with_no_text_is_swallowed_and_refused() {
        let mut r = Rig::new();
        r.step(Event::ClipboardAvailable(false));
        hold_chord(&mut r);
        let out = r.step(chord_event());
        assert!(matches!(
            outcomes(&out).as_slice(),
            [PasteOutcome::Refused(PasteRefusal::NoText)]
        ));
        assert!(!out.iter().any(|o| matches!(o, Out::RequestClipboard)));
        assert!(!pushes_usage(&out, 0x19), "{}", show(&out));
        // V's typematic repeat is not a second chord.
        assert!(outcomes(&r.step(chord_event())).is_empty());
    }

    /// §8: once the modifiers release and the text arrives, the Typist
    /// types it; a client key mid-typing never reaches the KVM (D2b).
    #[test]
    fn a_paste_types_the_text_once_modifiers_release() {
        let mut r = Rig::new();
        let out = start_paste(&mut r, "Hi");
        let typed: Vec<HidFrame> = pushes(&out).into_iter().map(|(f, _)| f).collect();
        assert_eq!(
            typed,
            [kbd(MOD_LSHIFT, 0x0B)],
            "'H' — one report: the rig's queue room is 1"
        );
        assert!(!pushes_usage(
            &r.step(Event::KeyPressed {
                code: 0x10,
                extended: false
            }),
            0x14
        ));
        assert_eq!(
            finish(&mut r),
            PasteOutcome::Done {
                typed: 2,
                skipped: 0
            }
        );
    }

    /// DD6 (D2b): a step pushes at most `queue_room` Typist reports; with
    /// no room it pushes none and looks again ROOM_POLL later (no spin).
    #[test]
    fn the_typist_never_pushes_more_than_the_queue_room() {
        let mut r = Rig::new();
        assert!(pushes(&start_paste(&mut r, "abcd")).len() <= 1);
        for _ in 0..3 {
            r.advance(Duration::from_millis(1));
            assert!(pushes(&r.step(Event::Tick)).len() <= 1);
        }
        let mut r = Rig::new();
        r.room = 0;
        assert!(pushes(&start_paste(&mut r, "abcd")).is_empty());
        // PD7 review m2: the look again is 2 ms off — never now, which
        // would spin the driver while the queue stays full.
        assert_eq!(crate::input::paste::ROOM_POLL, Duration::from_millis(2));
        assert_eq!(
            r.core.next_deadline(),
            Some(r.now + Duration::from_millis(2))
        );
        r.advance(Duration::from_millis(1));
        assert!(r.step(Event::Tick).is_empty(), "no room: nothing, no spin");
        assert_eq!(
            r.core.next_deadline(),
            Some(r.now + Duration::from_millis(2))
        );
        r.room = 3;
        r.advance(crate::input::paste::ROOM_POLL);
        assert_eq!(pushes(&r.step(Event::Tick)).len(), 3);
    }

    #[test]
    fn caps_lock_refuses_the_paste() {
        let mut r = Rig::new();
        r.step(Event::Synchronize { caps_lock: true });
        hold_chord(&mut r);
        let out = r.step(chord_event());
        assert!(matches!(
            outcomes(&out).as_slice(),
            [PasteOutcome::Refused(PasteRefusal::CapsLock)]
        ));
    }

    /// DD5 (D8c): a Caps Lock press after a Synchronize is tracked.
    #[test]
    fn a_caps_lock_press_after_a_synchronize_is_tracked() {
        let mut r = Rig::new();
        r.step(Event::Synchronize { caps_lock: false });
        r.step(Event::KeyPressed {
            code: 0x3A,
            extended: false,
        });
        r.step(Event::KeyReleased {
            code: 0x3A,
            extended: false,
        });
        hold_chord(&mut r);
        let out = r.step(chord_event());
        assert!(matches!(
            outcomes(&out).as_slice(),
            [PasteOutcome::Refused(PasteRefusal::CapsLock)]
        ));
    }

    /// Rev 6.3 (PD11b I5; PD7 m5): a fresh Unicode Esc (U+001B) aborts a
    /// paste exactly as a scancode Esc does — Pending or Typing, swallowed
    /// and released by the bridge, so its repeats after the paste push
    /// nothing until its release. A repeat of a Unicode Esc held since
    /// before the chord is a repeat and aborts nothing. Outside a paste it
    /// types Esc.
    #[test]
    fn a_unicode_esc_aborts_a_paste_like_a_scancode_esc() {
        const ESC: u16 = 0x001B;
        // Outside a paste: Esc goes out, and its release.
        let mut r = Rig::new();
        assert_eq!(
            pushes(&r.step(Event::UnicodePressed(ESC))),
            [(kbd(0, 0x29), 0)]
        );
        assert_eq!(
            pushes(&r.step(Event::UnicodeReleased(ESC))),
            [(kbd(0, 0), 0)]
        );
        // Pending: aborted, swallowed — nothing pushed.
        hold_chord(&mut r);
        assert!(matches!(
            outcomes(&r.step(chord_event())).as_slice(),
            [PasteOutcome::Started]
        ));
        let out = r.step(Event::UnicodePressed(ESC));
        assert!(
            matches!(outcomes(&out).as_slice(), [PasteOutcome::Aborted("esc")]),
            "{}",
            show(&out)
        );
        assert!(pushes(&out).is_empty(), "swallowed: {}", show(&out));
        assert!(r.core.keys.is_released_by_bridge(0x29));
        assert!(pushes(&r.step(Event::UnicodePressed(ESC))).is_empty());
        assert!(pushes(&r.step(Event::UnicodeReleased(ESC))).is_empty());
        assert!(!r.core.paste.is_active());
        // Typing: aborted, swallowed, and the all-zero report goes out.
        let mut r = Rig::new();
        start_paste(&mut r, "abc");
        let out = r.step(Event::UnicodePressed(ESC));
        assert!(
            matches!(outcomes(&out).as_slice(), [PasteOutcome::Aborted("esc")]),
            "{}",
            show(&out)
        );
        assert_eq!(pushes(&out), [(kbd(0, 0), 0)], "{}", show(&out));
        assert!(pushes(&r.step(Event::UnicodePressed(ESC))).is_empty());
        assert!(pushes(&r.step(Event::UnicodeReleased(ESC))).is_empty());
        assert_eq!(
            pushes(&r.step(Event::UnicodePressed(ESC))),
            [(kbd(0, 0x29), 0)]
        );
        // Held since before the chord: its repeat aborts nothing; once it
        // is released, a fresh press does.
        let mut r = Rig::new();
        assert_eq!(
            pushes(&r.step(Event::UnicodePressed(ESC))),
            [(kbd(0, 0x29), 0)]
        );
        hold_chord(&mut r);
        assert!(matches!(
            outcomes(&r.step(chord_event())).as_slice(),
            [PasteOutcome::Started]
        ));
        let out = r.step(Event::UnicodePressed(ESC)); // its repeat
        assert!(out.is_empty(), "{}", show(&out));
        assert!(r.core.paste.is_active());
        assert_eq!(
            pushes(&r.step(Event::UnicodeReleased(ESC))),
            [(kbd(0x07, 0), 0)]
        );
        let out = r.step(Event::UnicodePressed(ESC));
        assert!(
            matches!(outcomes(&out).as_slice(), [PasteOutcome::Aborted("esc")]),
            "{}",
            show(&out)
        );
        assert!(pushes(&out).is_empty(), "swallowed: {}", show(&out));
        // With every released-by-bridge mark taken (DD9), the swallowed Esc
        // cannot be marked: it is counted, and still never reaches the KVM.
        let mut r = Rig::new();
        let keys: Vec<u8> = (0x02..=0x0D)
            .chain(0x10..=0x1B)
            .chain(0x1E..=0x25)
            .collect();
        assert_eq!(keys.len(), 32);
        for batch in keys.chunks(16) {
            for &code in batch {
                r.step(Event::KeyPressed {
                    code,
                    extended: false,
                });
            }
            r.epoch += 1; // a release-all: the held keys become marks
            r.step(Event::Tick);
        }
        hold_chord(&mut r);
        assert!(matches!(
            outcomes(&r.step(chord_event())).as_slice(),
            [PasteOutcome::Started]
        ));
        let out = r.step(Event::UnicodePressed(ESC));
        assert!(
            matches!(outcomes(&out).as_slice(), [PasteOutcome::Aborted("esc")]),
            "{}",
            show(&out)
        );
        assert!(out.contains(&Out::Ignored), "{}", show(&out));
        assert!(pushes(&out).is_empty(), "swallowed: {}", show(&out));
    }

    /// Rev 6.3 (PD11b I5): a Unicode Return (U+000D) is a held non-modifier
    /// key like a scancode one — its repeats push nothing new but keep the
    /// key-repeat timer from firing; with none for `key_repeat_timeout` it
    /// is released and stays released by the bridge until its release.
    /// And while a paste is Pending, a fresh one cancels it and goes through
    /// (DD4).
    #[test]
    fn a_held_unicode_return_repeats_and_cancels_a_pending_paste() {
        const CR: u16 = 0x000D;
        let mut r = Rig::new();
        assert_eq!(
            pushes(&r.step(Event::UnicodePressed(CR))),
            [(kbd(0, 0x28), 0)]
        );
        for _ in 0..30 {
            r.advance(Duration::from_secs(1));
            let out = r.step(Event::UnicodePressed(CR)); // its repeat
            assert!(out.is_empty(), "{}", show(&out));
            let out = r.step(Event::Tick);
            assert!(releases(&out).is_empty(), "{}", show(&out));
        }
        assert!(r.core.keys.is_down(0x28), "30 s of repeats: still held");
        r.advance(Duration::from_secs(10));
        assert_eq!(releases(&r.step(Event::Tick)), [ReleaseTrigger::KeyRepeat]);
        let out = r.step(Event::UnicodePressed(CR));
        assert!(!pushes_usage(&out, 0x28), "re-pressed: {}", show(&out));
        assert!(!pushes_usage(&r.step(Event::UnicodeReleased(CR)), 0x28));
        assert_eq!(
            pushes(&r.step(Event::UnicodePressed(CR))),
            [(kbd(0, 0x28), 1)]
        );
        r.step(Event::UnicodeReleased(CR));
        // Pending: a fresh Unicode Return cancels the paste and goes through.
        hold_chord(&mut r);
        assert!(matches!(
            outcomes(&r.step(chord_event())).as_slice(),
            [PasteOutcome::Started]
        ));
        let out = r.step(Event::UnicodePressed(CR));
        assert!(
            matches!(outcomes(&out).as_slice(), [PasteOutcome::Aborted("key")]),
            "{}",
            show(&out)
        );
        assert_eq!(pushes(&out), [(kbd(0x07, 0x28), 1)], "{}", show(&out));
    }

    /// Rev 6.3 (PD11b I5): the live Unicode mapping is not paste's (§8). A
    /// pasted BS or ESC is skipped and counted, never typed; a pasted CR is
    /// still a line break, typed as one Return.
    #[test]
    fn paste_never_types_backspace_or_esc() {
        let mut r = Rig::new();
        let mut frames: Vec<HidFrame> = pushes(&start_paste(&mut r, "a\u{8}b\rc\u{1B}d"))
            .into_iter()
            .map(|(f, _)| f)
            .collect();
        let mut done = None;
        for _ in 0..64 {
            r.advance(Duration::from_millis(1));
            let out = r.step(Event::Tick);
            frames.extend(pushes(&out).into_iter().map(|(f, _)| f));
            if let Some(p) = outcomes(&out).first() {
                done = Some((*p).clone());
                break;
            }
        }
        assert_eq!(
            done,
            Some(PasteOutcome::Done {
                typed: 5,
                skipped: 2
            })
        );
        let presses: Vec<u8> = frames
            .iter()
            .filter_map(|f| match f {
                HidFrame::Keyboard { keys, .. } if keys[0] != 0 => Some(keys[0]),
                _ => None,
            })
            .collect();
        assert_eq!(presses, [0x04, 0x05, 0x28, 0x06, 0x07]);
    }

    /// Review Focus 1 / §8: Esc aborts (and is swallowed), an all-zero
    /// report clears the Typist's press, and Esc's repeats stay silent
    /// until its Released.
    #[test]
    fn esc_aborts_and_the_typists_keys_do_not_leak() {
        let mut r = Rig::new();
        start_paste(&mut r, "abc");
        let out = r.step(Event::KeyPressed {
            code: 0x01,
            extended: false,
        }); // Esc
        assert!(matches!(
            outcomes(&out).as_slice(),
            [PasteOutcome::Aborted("esc")]
        ));
        assert_eq!(pushes(&out), [(kbd(0, 0), 0)]);
        assert!(
            pushes(&r.step(Event::KeyPressed {
                code: 0x01,
                extended: false
            }))
            .is_empty()
        );
        assert!(
            pushes(&r.step(Event::KeyReleased {
                code: 0x01,
                extended: false
            }))
            .is_empty()
        );
        assert_eq!(
            pushes(&r.step(Event::KeyPressed {
                code: 0x01,
                extended: false
            })),
            [(kbd(0, 0x29), 0)]
        );
    }

    /// D3c: a key pressed mid-typing is released by the bridge — after the
    /// paste, its repeats push nothing until its Released.
    #[test]
    fn a_key_swallowed_during_a_paste_stays_released_after_it() {
        let mut r = Rig::new();
        start_paste(&mut r, "ab");
        r.step(Event::KeyPressed {
            code: 0x10,
            extended: false,
        }); // q, mid-typing
        assert!(matches!(finish(&mut r), PasteOutcome::Done { .. }));
        assert!(
            pushes(&r.step(Event::KeyPressed {
                code: 0x10,
                extended: false
            }))
            .is_empty()
        );
        assert!(
            pushes(&r.step(Event::KeyReleased {
                code: 0x10,
                extended: false
            }))
            .is_empty()
        );
        assert_eq!(
            pushes(&r.step(Event::KeyPressed {
                code: 0x10,
                extended: false
            })),
            [(kbd(0, 0x14), 0)]
        );
    }

    /// §8 (D3c): a §7.4 trigger aborts typing — a bumped epoch and a
    /// Synchronize each end it, with an all-zero report at the epoch.
    #[test]
    fn a_bumped_epoch_or_synchronize_aborts_typing() {
        let mut r = Rig::new();
        start_paste(&mut r, "abc");
        r.epoch = 7;
        let out = r.step(Event::MouseMove { x: 1, y: 1 });
        assert!(
            matches!(
                outcomes(&out).as_slice(),
                [PasteOutcome::Aborted("release")]
            ),
            "{}",
            show(&out)
        );
        assert!(pushes(&out).contains(&(kbd(0, 0), 7)));
        r.advance(Duration::from_millis(1));
        assert!(
            pushes(&r.step(Event::Tick)).is_empty(),
            "nothing more is typed"
        );
        let mut r = Rig::new();
        start_paste(&mut r, "abc");
        let out = r.step(Event::Synchronize { caps_lock: false });
        assert!(
            matches!(
                outcomes(&out).as_slice(),
                [PasteOutcome::Aborted("release")]
            ),
            "{}",
            show(&out)
        );
        assert!(
            out.iter()
                .any(|o| matches!(o, Out::Release(ReleaseTrigger::Synchronize)))
        );
    }

    /// Review Focus 5 / DD4: a paste pending past modifier_wait with no
    /// response ends; a late or unasked response then types nothing.
    #[test]
    fn a_late_or_unasked_clipboard_response_types_nothing() {
        let mut r = Rig::new();
        hold_chord(&mut r);
        r.step(chord_event());
        r.advance(Duration::from_secs(6)); // past modifier_wait (5 s)
        let out = r.step(Event::Tick);
        assert!(matches!(
            outcomes(&out).as_slice(),
            [PasteOutcome::Aborted("modifier_wait")]
        ));
        assert!(pushes(&r.step(Event::ClipboardText(utf16le("x")))).is_empty());
    }

    /// DD4: while pending, a fresh non-modifier press cancels the paste and
    /// goes through (with the modifiers the KVM already holds); a second
    /// chord meanwhile is swallowed.
    #[test]
    fn a_fresh_key_while_pending_cancels_and_goes_through() {
        let mut r = Rig::new();
        hold_chord(&mut r);
        r.step(chord_event());
        let out = r.step(Event::KeyPressed {
            code: 0x2D,
            extended: false,
        }); // x
        assert!(matches!(
            outcomes(&out).as_slice(),
            [PasteOutcome::Aborted("key")]
        ));
        assert_eq!(pushes(&out), [(kbd(0x07, 0x1B), 0)]);
        let mut r = Rig::new();
        hold_chord(&mut r);
        r.step(chord_event());
        r.step(Event::KeyReleased {
            code: 0x2F,
            extended: false,
        });
        let out = r.step(chord_event());
        assert!(
            outcomes(&out).is_empty() && pushes(&out).is_empty(),
            "{}",
            show(&out)
        );
    }

    #[test]
    fn a_mouse_button_aborts_a_paste() {
        let mut r = Rig::new();
        hold_chord(&mut r);
        r.step(chord_event());
        let out = r.step(Event::MouseButton {
            button: Button::Left,
            pressed: true,
            x: 0,
            y: 0,
        });
        assert!(matches!(
            outcomes(&out).as_slice(),
            [PasteOutcome::Aborted("mouse")]
        ));
    }

    // ---- Beyond the plan's listing: ruling 8, the bounds, and every
    // outcome through a real `HidControl`.

    /// PD7 review I1 (§8's wait, §11.1's "does not happen before"): a
    /// pending paste waits the whole `paste.modifier_wait` — a Tick a
    /// nanosecond short of its deadline leaves it Pending with no outcome,
    /// and the Tick at the deadline ends it — whether or not its text has
    /// come (here the modifiers are still held).
    #[test]
    fn modifier_wait_ends_a_pending_paste_at_its_deadline_and_not_before() {
        for with_text in [false, true] {
            let mut r = Rig::new();
            hold_chord(&mut r);
            let t0 = r.now;
            r.step(chord_event());
            if with_text {
                r.step(Event::ClipboardText(utf16le("ab")));
            }
            let at = t0 + Duration::from_secs(5);
            assert_eq!(r.core.paste.deadline(), Some(at), "with_text={with_text}");
            r.now = at - Duration::from_nanos(1);
            let out = r.step(Event::Tick);
            assert!(
                outcomes(&out).is_empty(),
                "with_text={with_text}: {}",
                show(&out)
            );
            assert!(
                matches!(r.core.paste, State::Pending { .. }),
                "with_text={with_text}"
            );
            r.now = at;
            let out = r.step(Event::Tick);
            assert!(
                matches!(
                    outcomes(&out).as_slice(),
                    [PasteOutcome::Aborted("modifier_wait")]
                ),
                "with_text={with_text}: {}",
                show(&out)
            );
            assert!(!r.core.paste.is_active(), "with_text={with_text}");
        }
    }

    /// PD7 review I2 (DD4 in Windows App's Unicode mode, Review Focus 2): a
    /// fresh Unicode press while Pending cancels the paste and goes through
    /// — 'x' is usage 0x1B, with the modifiers the KVM already holds — and
    /// the repeat of a unit held since before the chord does nothing.
    #[test]
    fn a_fresh_unicode_press_while_pending_cancels_and_goes_through() {
        let x = u16::from(b'x');
        let mut r = Rig::new();
        hold_chord(&mut r);
        r.step(chord_event());
        let out = r.step(Event::UnicodePressed(x));
        assert!(
            matches!(outcomes(&out).as_slice(), [PasteOutcome::Aborted("key")]),
            "{}",
            show(&out)
        );
        assert_eq!(pushes(&out), [(kbd(0x07, 0x1B), 0)], "{}", show(&out));
        assert!(!r.core.paste.is_active());
        // A unit held (and sent) before the chord: its repeat is a repeat.
        let mut r = Rig::new();
        assert_eq!(
            pushes(&r.step(Event::UnicodePressed(x))),
            [(kbd(0, 0x1B), 0)]
        );
        hold_chord(&mut r);
        assert!(matches!(
            outcomes(&r.step(chord_event())).as_slice(),
            [PasteOutcome::Started]
        ));
        let out = r.step(Event::UnicodePressed(x));
        assert!(
            outcomes(&out).is_empty() && pushes(&out).is_empty(),
            "{}",
            show(&out)
        );
        assert!(r.core.paste.is_active());
    }

    /// Controller ruling 8 (1): while Pending, releases still go out — the
    /// chord's modifier presses reached the KVM, so their releases must,
    /// or a paste that ends untyped leaves Ctrl+Option+Shift held. A
    /// modifier's own repeat changes nothing, and typing waits until every
    /// modifier is up (§8).
    #[test]
    fn releases_while_pending_go_out_and_typing_waits_for_every_modifier() {
        let mut r = Rig::new();
        hold_chord(&mut r);
        r.step(chord_event());
        assert!(
            pushes(&r.step(Event::KeyPressed {
                code: 0x2A,
                extended: false
            }))
            .is_empty(),
            "LShift's repeat"
        );
        assert!(
            pushes(&r.step(Event::ClipboardText(utf16le("ab")))).is_empty(),
            "three modifiers still held"
        );
        assert_eq!(
            pushes(&r.step(Event::KeyReleased {
                code: 0x2A,
                extended: false
            })),
            [(kbd(0x05, 0), 0)]
        );
        assert_eq!(
            pushes(&r.step(Event::KeyReleased {
                code: 0x38,
                extended: false
            })),
            [(kbd(0x01, 0), 0)]
        );
        // The last modifier up: its release goes out, then the Typist.
        assert_eq!(
            pushes(&r.step(Event::KeyReleased {
                code: 0x1D,
                extended: false
            })),
            [(kbd(0, 0), 0), (kbd(0, 0x04), 0)]
        );
        assert_eq!(
            finish(&mut r),
            PasteOutcome::Done {
                typed: 2,
                skipped: 0
            }
        );
    }

    /// Only a fresh press of the chord's key starts a paste: a repeat of a V
    /// held (and sent) before the modifiers is a repeat, not a chord, and
    /// a repeat of a swallowed V is not a second one.
    #[test]
    fn a_repeat_of_a_held_v_is_not_a_chord() {
        let mut r = Rig::new();
        assert_eq!(pushes(&r.step(chord_event())), [(kbd(0, 0x19), 0)]); // V alone
        hold_chord(&mut r);
        let out = r.step(chord_event()); // V's repeat, the modifiers held
        assert!(outcomes(&out).is_empty(), "{}", show(&out));
        assert!(pushes(&out).is_empty(), "a repeat changes nothing");
        assert!(!r.core.keys.is_released_by_bridge(0x19));
        assert!(r.core.keys.is_down(0x19));
    }

    /// Found by the property test: only a fresh Esc aborts. The repeat of
    /// an Esc held (and sent) since before the chord is a repeat — the paste
    /// stays pending and Esc is never both held and marked; its release and
    /// a fresh press then abort as ever.
    #[test]
    fn a_repeat_of_a_held_esc_does_not_abort() {
        let mut r = Rig::new();
        let esc = |pressed| {
            if pressed {
                Event::KeyPressed {
                    code: 0x01,
                    extended: false,
                }
            } else {
                Event::KeyReleased {
                    code: 0x01,
                    extended: false,
                }
            }
        };
        assert_eq!(pushes(&r.step(esc(true))), [(kbd(0, 0x29), 0)]);
        hold_chord(&mut r);
        assert!(matches!(
            outcomes(&r.step(chord_event())).as_slice(),
            [PasteOutcome::Started]
        ));
        let out = r.step(esc(true)); // Esc's repeat
        assert!(out.is_empty(), "{}", show(&out));
        assert!(r.core.paste.is_active());
        assert!(r.core.keys.is_down(0x29) && !r.core.keys.is_released_by_bridge(0x29));
        assert_eq!(pushes(&r.step(esc(false))), [(kbd(0x07, 0), 0)]);
        let out = r.step(esc(true));
        assert!(matches!(
            outcomes(&out).as_slice(),
            [PasteOutcome::Aborted("esc")]
        ));
        assert!(pushes(&out).is_empty(), "swallowed: {}", show(&out));
    }

    /// §8 (D3c): every press while typing — scancode, Unicode, a modifier, a
    /// second chord — is swallowed and released by the bridge; an unmapped
    /// key or an untypeable unit is one dropped input, counted on its press
    /// only (the PD5 carry), and its release sends nothing.
    #[test]
    fn every_press_while_typing_is_swallowed_and_counted_once() {
        let mut r = Rig::new();
        start_paste(&mut r, "abcdef");
        r.room = 0; // nothing of the Typist's in the way
        let presses = [
            Event::KeyPressed {
                code: 0x1D,
                extended: false,
            }, // LCtrl
            Event::KeyPressed {
                code: 0x10,
                extended: false,
            }, // q
            Event::UnicodePressed(u16::from(b'Z')),
            chord_event(),
        ];
        for e in presses {
            let d = describe(&e);
            let out = r.step(e);
            assert!(out.is_empty(), "{d}: {}", show(&out));
        }
        for u in [0xE0, 0x14, 0x1D, 0x19] {
            assert!(r.core.keys.is_released_by_bridge(u), "{u:#x}");
        }
        assert!(r.holds_nothing());
        assert_eq!(
            r.step(Event::KeyPressed {
                code: 0x54,
                extended: false
            }),
            [Out::Ignored]
        );
        assert_eq!(r.step(Event::UnicodePressed(0xE9)), [Out::Ignored]);
        for e in [
            Event::KeyReleased {
                code: 0x54,
                extended: false,
            },
            Event::UnicodeReleased(0xE9),
            Event::KeyReleased {
                code: 0x10,
                extended: false,
            },
            Event::KeyReleased {
                code: 0x1D,
                extended: false,
            },
        ] {
            let d = describe(&e);
            let out = r.step(e);
            assert!(out.is_empty(), "{d}: {}", show(&out));
        }
        // The swallowed releases updated the state: q and LCtrl are fresh.
        assert!(!r.core.keys.is_released_by_bridge(0x14));
        assert!(!r.core.keys.is_released_by_bridge(0xE0));
    }

    /// DD9 meets D3c: once the 32 released-by-bridge marks are full, a key
    /// the paste swallows cannot be remembered — it is one dropped input,
    /// and it still never reaches the KVM: a press while typing, Esc, and
    /// the chord's own V (killed mutants Q1, Q9: the mark alone had been
    /// keeping a passed-through V or Esc out of the reports).
    #[test]
    fn a_swallowed_key_never_reaches_the_kvm_even_with_no_mark_left() {
        let in_frame = |out: &[Out], usage: u8| {
            pushes(out)
                .iter()
                .any(|(f, _)| matches!(f, HidFrame::Keyboard { keys, .. } if keys.contains(&usage)))
        };
        let mut r = Rig::new();
        start_paste(&mut r, &"acdefghijk".repeat(4)); // no b, no v
        // 32 presses mid-typing, all swallowed: every mark is taken.
        let codes: Vec<u8> = (0x02..=0x0B)
            .chain(0x10..=0x19)
            .chain(0x1E..=0x26)
            .chain([0x2C, 0x2D, 0x2E])
            .collect();
        assert_eq!(codes.len(), 32);
        for code in &codes {
            let out = r.step(Event::KeyPressed {
                code: *code,
                extended: false,
            });
            assert!(!out.contains(&Out::Ignored), "{code:#x}: {}", show(&out));
        }
        assert!(codes.iter().all(|c| {
            let u = usage_for_scancode(*c, false).unwrap();
            r.core.keys.is_released_by_bridge(u)
        }));
        // A 33rd: no room for its mark — counted, and not sent.
        let out = r.step(Event::KeyPressed {
            code: 0x30,
            extended: false,
        }); // b
        assert!(out.contains(&Out::Ignored), "{}", show(&out));
        assert!(
            !r.core.keys.is_down(0x05) && !in_frame(&out, 0x05),
            "{}",
            show(&out)
        );
        // Esc: counted, aborts, and only the all-zero report goes out.
        let out = r.step(Event::KeyPressed {
            code: 0x01,
            extended: false,
        });
        assert!(out.contains(&Out::Ignored), "{}", show(&out));
        assert!(matches!(
            outcomes(&out).as_slice(),
            [PasteOutcome::Aborted("esc")]
        ));
        assert_eq!(pushes(&out), [(kbd(0, 0), 0)], "{}", show(&out));
        // The chord's V: counted, starts a paste, and never goes out.
        hold_chord(&mut r);
        let out = r.step(chord_event());
        assert!(out.contains(&Out::Ignored), "{}", show(&out));
        assert!(matches!(outcomes(&out).as_slice(), [PasteOutcome::Started]));
        assert!(!in_frame(&out, 0x19), "{}", show(&out));
        assert!(!r.core.keys.is_down(0x19));
    }

    /// D3c: a key the client holds when typing begins is released by the
    /// bridge, and its zero goes out at once (it takes the step's one unit
    /// of room) — the Typist's reports never carry it, and after the paste
    /// its repeats stay silent until its Released.
    #[test]
    fn a_key_held_when_typing_begins_is_released_by_the_bridge() {
        let mut r = Rig::new();
        r.step(Event::KeyPressed {
            code: 0x1E,
            extended: false,
        }); // 'a' held throughout
        let out = start_paste(&mut r, "x");
        assert_eq!(pushes(&out), [(kbd(0, 0), 0)], "{}", show(&out));
        assert!(r.core.keys.is_released_by_bridge(0x04));
        assert_eq!(
            finish(&mut r),
            PasteOutcome::Done {
                typed: 1,
                skipped: 0
            }
        );
        let a = Event::KeyPressed {
            code: 0x1E,
            extended: false,
        };
        assert!(pushes(&r.step(a.clone())).is_empty(), "a's repeat");
        r.step(Event::KeyReleased {
            code: 0x1E,
            extended: false,
        });
        assert_eq!(pushes(&r.step(a)), [(kbd(0, 0x04), 0)]);
    }

    /// Found by the property test (§7.4): when typing begins with a key
    /// held and the Typist pushes nothing — an empty text, or a full queue
    /// — the release's zero still goes out. Otherwise the KVM keeps a key
    /// the core has marked released, and the client's own Released then
    /// sends nothing: a stuck key.
    #[test]
    fn typing_begins_by_zeroing_what_the_client_held_even_with_nothing_to_type() {
        for (text, room) in [("", 1), ("\r\n", 1), ("é", 1), ("x", 0), ("", 0)] {
            let mut r = Rig::new();
            r.room = room;
            r.step(Event::KeyPressed {
                code: 0x01,
                extended: false,
            }); // Esc held (and sent) since before the chord
            let out = start_paste(&mut r, text);
            assert_eq!(
                pushes(&out).first(),
                Some(&(kbd(0, 0), 0)),
                "{text:?} room {room}: {}",
                show(&out)
            );
            assert!(r.core.keys.is_released_by_bridge(0x29));
            if r.core.paste.is_active() {
                r.room = 1;
                finish(&mut r);
            }
            assert!(!r.core.paste.is_active(), "{text:?}");
            // Esc's client Released sends nothing — the KVM has it up.
            assert!(
                pushes(&r.step(Event::KeyReleased {
                    code: 0x01,
                    extended: false
                }))
                .is_empty()
            );
        }
        // Nothing held: no extra report.
        let mut r = Rig::new();
        let out = start_paste(&mut r, "");
        assert!(pushes(&out).is_empty(), "{}", show(&out));
        assert!(matches!(
            outcomes(&out).as_slice(),
            [PasteOutcome::Done {
                typed: 0,
                skipped: 0
            }]
        ));
    }

    /// DD6: with a pace, one report per `pace` and no catch-up burst after
    /// a late step; the paste's next report is the core's deadline.
    #[test]
    fn the_typist_keeps_its_pace_without_a_catch_up_burst() {
        let mut r = Rig::new();
        r.room = 8;
        let pace = Duration::from_millis(15);
        let mut ctx = r.ctx();
        ctx.pace = pace;
        let step = |r: &mut Rig, ctx: &mut Ctx, e: Event| {
            ctx.now = r.now;
            ctx.epoch = r.epoch;
            let mut out = Vec::new();
            r.core.step(ctx, e, &mut out);
            out
        };
        hold_chord(&mut r);
        r.step(chord_event());
        for code in [0x2F, 0x1D, 0x38, 0x2A] {
            r.step(Event::KeyReleased {
                code,
                extended: false,
            });
        }
        let out = step(&mut r, &mut ctx, Event::ClipboardText(utf16le("abc")));
        assert_eq!(pushes(&out), [(kbd(0, 0x04), 0)]);
        assert_eq!(r.core.next_deadline(), Some(r.now + pace));
        r.advance(pace - Duration::from_nanos(1));
        assert!(pushes(&step(&mut r, &mut ctx, Event::Tick)).is_empty());
        r.advance(Duration::from_nanos(1));
        assert_eq!(
            pushes(&step(&mut r, &mut ctx, Event::Tick)),
            [(kbd(0, 0), 0)]
        );
        r.advance(Duration::from_secs(1)); // a late step
        assert_eq!(
            pushes(&step(&mut r, &mut ctx, Event::Tick)),
            [(kbd(0, 0x05), 0)],
            "one report, not a burst"
        );
        assert_eq!(r.core.next_deadline(), Some(r.now + pace));
    }

    /// DD4: only a pending paste with no text yet takes a response — a
    /// second response types nothing more, and one before any chord
    /// types nothing.
    #[test]
    fn only_the_first_response_to_a_pending_paste_is_typed() {
        let mut r = Rig::new();
        // PD9 carry 3 (c): discarded and counted, nothing else.
        assert_eq!(
            r.step(Event::ClipboardText(utf16le("unasked"))),
            [Out::ClipboardDiscarded("unasked")]
        );
        hold_chord(&mut r);
        r.step(chord_event());
        r.step(Event::ClipboardText(utf16le("ab")));
        assert_eq!(
            r.step(Event::ClipboardText(utf16le("WXYZ"))),
            [Out::ClipboardDiscarded("unasked")]
        );
        for code in [0x2F, 0x1D, 0x38, 0x2A] {
            r.step(Event::KeyReleased {
                code,
                extended: false,
            });
        }
        assert_eq!(
            finish(&mut r),
            PasteOutcome::Done {
                typed: 2,
                skipped: 0
            }
        );
    }

    /// §8's limits through the core: multiline = refuse refuses an inner
    /// break (ending the pending paste), max_chars caps what is typed, and
    /// skipped characters plus ill-formed units are counted (D4: the
    /// terminator ends the text, so nothing after it is typed or counted).
    #[test]
    fn the_section_8_limits_apply_in_the_core() {
        let mut r = Rig::new();
        hold_chord(&mut r);
        r.step(chord_event());
        let mut ctx = r.ctx();
        ctx.multiline_refuse = true;
        let mut out = Vec::new();
        r.core
            .step(&ctx, Event::ClipboardText(utf16le("a\nb")), &mut out);
        assert!(
            matches!(
                outcomes(&out).as_slice(),
                [PasteOutcome::Refused(PasteRefusal::Multiline)]
            ),
            "{}",
            show(&out)
        );
        assert!(pushes(&out).is_empty());
        assert_eq!(r.core.paste.deadline(), None);
        // max_chars, skips and the terminator.
        let mut r = Rig::new();
        r.room = 8;
        hold_chord(&mut r);
        r.step(chord_event());
        for code in [0x2F, 0x1D, 0x38, 0x2A] {
            r.step(Event::KeyReleased {
                code,
                extended: false,
            });
        }
        let mut ctx = r.ctx();
        ctx.max_chars = 2;
        // 'é' (skipped), a lone D800 (one U+FFFD, skipped once), "abc\n"
        // (c is past the cap of 2), the terminator, then 'z' (not text).
        let bytes = vec![
            0xE9, 0, 0x00, 0xD8, b'a', 0, b'b', 0, b'c', 0, b'\n', 0, 0, 0, b'z', 0,
        ];
        let mut out = Vec::new();
        r.core.step(&ctx, Event::ClipboardText(bytes), &mut out);
        assert_eq!(
            outcomes(&out),
            [&PasteOutcome::Done {
                typed: 2,
                skipped: 2
            }],
            "{}",
            show(&out)
        );
        assert!(
            !pushes_usage(&out, 0x06),
            "c is past max_chars: {}",
            show(&out)
        );
        // D4 through the core: a copied line as every client sends it —
        // NUL-terminated — types the line and never a trailing Return.
        let mut r = Rig::new();
        r.room = 8;
        let mut bytes = utf16le("ls\r\n");
        bytes.extend_from_slice(&[0, 0]);
        hold_chord(&mut r);
        r.step(chord_event());
        for code in [0x2F, 0x1D, 0x38, 0x2A] {
            r.step(Event::KeyReleased {
                code,
                extended: false,
            });
        }
        let out = r.step(Event::ClipboardText(bytes));
        assert_eq!(
            outcomes(&out),
            [&PasteOutcome::Done {
                typed: 2,
                skipped: 0
            }],
            "{}",
            show(&out)
        );
        assert!(
            !pushes_usage(&out, 0x28),
            "a Return was typed: {}",
            show(&out)
        );
        // PD7 review m1 through the core: the same line with one odd byte
        // appended and no terminator (a hostile client) types the line, and
        // never a Return; the odd byte is the one skip.
        let mut r = Rig::new();
        r.room = 8;
        let mut bytes = utf16le("ls\r\n");
        bytes.push(0x41);
        hold_chord(&mut r);
        r.step(chord_event());
        for code in [0x2F, 0x1D, 0x38, 0x2A] {
            r.step(Event::KeyReleased {
                code,
                extended: false,
            });
        }
        let out = r.step(Event::ClipboardText(bytes));
        assert_eq!(
            outcomes(&out),
            [&PasteOutcome::Done {
                typed: 2,
                skipped: 1
            }],
            "{}",
            show(&out)
        );
        assert!(
            !pushes_usage(&out, 0x28),
            "a Return was typed: {}",
            show(&out)
        );
    }

    /// D9c: a new session forgets the paste and the clipboard's
    /// availability — a chord before the new session's format list is
    /// refused for no text.
    #[test]
    fn a_new_generation_ends_the_paste_and_forgets_the_clipboard() {
        let mut r = Rig::new();
        start_paste(&mut r, "abc");
        assert_eq!(
            r.core.on_generation(2),
            Some(PasteOutcome::Aborted("session"))
        );
        assert_eq!(r.core.next_deadline(), None);
        r.advance(Duration::from_millis(5));
        assert!(r.step(Event::Tick).is_empty(), "nothing more is typed");
        hold_chord(&mut r);
        assert!(matches!(
            outcomes(&r.step(chord_event())).as_slice(),
            [PasteOutcome::Refused(PasteRefusal::NoText)]
        ));
    }

    /// §4.5, §9.2 (PD7 rule: pasted text is as sensitive as a password):
    /// a clipboard event, the paste state and its outs print kinds and
    /// counts only — never a byte of the text or a typed usage.
    #[test]
    fn debug_never_prints_the_pasted_text() {
        let values = [0x5A, 0x71, 0x7E, 0x1D, 0x14, 0x35, 0x41, 0x42, 0x43, 0x04];
        crate::testkit::assert_debug_redacted(
            &Event::ClipboardText(utf16le("Zq~")),
            &Event::ClipboardText(utf16le("ABC")),
            &values,
        );
        let mut a = Rig::new();
        let mut b = Rig::new();
        let oa = start_paste(&mut a, "Zq~");
        let ob = start_paste(&mut b, "abc");
        crate::testkit::assert_debug_redacted(&oa, &ob, &values);
        crate::testkit::assert_debug_redacted(&a.core, &b.core, &values);
        crate::testkit::assert_debug_redacted(&a.core.paste, &b.core.paste, &values);
        let s = format!("{:?}", a.core);
        assert!(s.contains("Typing"), "{s}");
        let (fa, fb) = (finish(&mut a), finish(&mut b));
        assert_eq!(format!("{fa:?}"), format!("{fb:?}"));
        // Pending with its text arrived (the modifiers still held).
        let mut a = Rig::new();
        let mut b = Rig::new();
        for (r, text) in [(&mut a, "Zq~"), (&mut b, "abc")] {
            hold_chord(r);
            r.step(chord_event());
            r.step(Event::ClipboardText(utf16le(text)));
        }
        let s = format!("{:?}", a.core.paste);
        assert!(s.contains("Pending") && s.contains("Some(3)"), "{s}");
        crate::testkit::assert_debug_redacted(&a.core, &b.core, &values);
        crate::testkit::assert_debug_redacted(&a.core.paste, &b.core.paste, &values);
    }

    /// A core wired to a real `HidControl` and the writer's loop (the
    /// shell's carry, Task 4.1), to see what the device ends up holding.
    struct Wired {
        core: InputCore,
        hid: HidControl,
        dev: Device,
        now: Instant,
        pace: Duration,
        modifier_wait: Duration,
        multiline_refuse: bool,
        /// Every outcome so far.
        outcomes: Vec<PasteOutcome>,
    }

    impl Wired {
        fn new() -> Wired {
            let mut w = Wired {
                core: InputCore::new(),
                hid: HidControl::new(64, Arc::new(Metrics::default())),
                dev: Device::default(),
                now: Instant::now(),
                pace: Duration::from_millis(15),
                modifier_wait: Duration::from_secs(5),
                multiline_refuse: false,
                outcomes: Vec::new(),
            };
            let _ = w.core.on_generation(1);
            w.step(Event::ClipboardAvailable(true));
            w
        }

        fn step(&mut self, e: Event) -> Vec<Out> {
            let ctx = Ctx {
                now: self.now,
                epoch: self.hid.epoch(),
                generation: 1,
                surface: (1920, 1080),
                mac_remap: false,
                key_repeat_timeout: Duration::from_secs(10),
                modifier_idle_timeout: Duration::from_secs(30),
                chord: chord(),
                pace: self.pace,
                modifier_wait: self.modifier_wait,
                multiline_refuse: self.multiline_refuse,
                max_chars: 4096,
                queue_room: 8,
            };
            let mut out = Vec::new();
            self.core.step(&ctx, e, &mut out);
            carry(&self.hid, &out);
            drain(&self.hid, &mut self.dev);
            self.outcomes.extend(outcomes(&out).into_iter().cloned());
            out
        }

        fn key(&mut self, code: u8, pressed: bool) {
            let extended = false;
            self.step(if pressed {
                Event::KeyPressed { code, extended }
            } else {
                Event::KeyReleased { code, extended }
            });
        }

        /// The chord pressed and V released: a paste is pending.
        fn chord(&mut self) {
            for code in [0x1D, 0x38, 0x2A, 0x2F] {
                self.key(code, true);
            }
            self.key(0x2F, false);
        }

        /// The chord, every modifier up, then `text`: typing.
        fn typing(&mut self, text: &str) {
            self.chord();
            for code in [0x1D, 0x38, 0x2A] {
                self.key(code, false);
            }
            self.step(Event::ClipboardText(utf16le(text)));
            assert!(
                matches!(self.core.paste, crate::input::paste::State::Typing { .. }),
                "precondition: typing"
            );
        }

        /// The device holds no key the core does not (§7.4).
        fn device_follows_the_core(&self, what: &str) {
            if let Some(HidFrame::Keyboard { modifiers, keys }) = self.dev.kbd {
                for k in keys.iter().filter(|k| **k != 0) {
                    assert!(self.core.keys.is_down(*k), "{what}: device holds {k:#x}");
                }
                assert_eq!(
                    modifiers,
                    self.core.keys.held_modifier_bits(),
                    "{what}: the device's modifiers"
                );
            }
        }

        /// The client lets go of `keys` and every button, and goes silent:
        /// a Tick at each deadline until none is armed. Then nothing is
        /// held anywhere.
        fn settle(&mut self, keys: &[u8], what: &str) {
            for code in keys {
                self.key(*code, false);
            }
            for button in [Button::Left, Button::Right, Button::Middle] {
                self.step(Event::MouseButton {
                    button,
                    pressed: false,
                    x: 1,
                    y: 1,
                });
            }
            for _ in 0..10_000 {
                let Some(at) = self.core.next_deadline() else {
                    break;
                };
                self.now = self.now.max(at);
                self.step(Event::Tick);
            }
            assert_eq!(self.core.next_deadline(), None, "{what}");
            assert!(!self.core.paste.is_active(), "{what}");
            assert_eq!(held(&self.core), (Vec::new(), 0), "{what}");
            assert!(
                !self.dev.holds_a_key() && self.dev.buttons == 0,
                "{what}: the device holds"
            );
        }
    }

    /// §8 / §7.4: EVERY paste outcome leaves nothing held — not the
    /// Typist's last key, not the chord's own modifiers (their releases
    /// went out while Pending, ruling 8), not a key swallowed meanwhile.
    /// Each outcome is driven through a real `HidControl`; at the outcome
    /// the device holds no key the core does not, and once the client lets
    /// go, nothing is held anywhere.
    #[test]
    fn every_paste_outcome_leaves_nothing_held() {
        type Drive = fn(&mut Wired) -> Vec<u8>;
        let cases: [(&str, PasteOutcome, Drive); 15] = [
            (
                "no text",
                PasteOutcome::Refused(PasteRefusal::NoText),
                |w| {
                    w.step(Event::ClipboardAvailable(false));
                    w.chord();
                    vec![0x1D, 0x38, 0x2A]
                },
            ),
            (
                "caps lock",
                PasteOutcome::Refused(PasteRefusal::CapsLock),
                |w| {
                    w.step(Event::Synchronize { caps_lock: true });
                    w.chord();
                    vec![0x1D, 0x38, 0x2A]
                },
            ),
            (
                "multiline",
                PasteOutcome::Refused(PasteRefusal::Multiline),
                |w| {
                    w.multiline_refuse = true;
                    w.chord();
                    w.step(Event::ClipboardText(utf16le("a\nb")));
                    vec![0x1D, 0x38, 0x2A]
                },
            ),
            ("esc pending", PasteOutcome::Aborted("esc"), |w| {
                w.chord();
                w.key(0x01, true);
                vec![0x1D, 0x38, 0x2A, 0x01]
            }),
            ("esc typing", PasteOutcome::Aborted("esc"), |w| {
                w.typing("abcdef");
                w.key(0x10, true); // q, swallowed
                w.key(0x01, true);
                vec![0x10, 0x01]
            }),
            ("key pending", PasteOutcome::Aborted("key"), |w| {
                w.chord();
                w.key(0x2D, true);
                vec![0x1D, 0x38, 0x2A, 0x2D]
            }),
            ("mouse pending", PasteOutcome::Aborted("mouse"), |w| {
                w.chord();
                w.step(Event::MouseButton {
                    button: Button::Left,
                    pressed: true,
                    x: 5,
                    y: 5,
                });
                vec![0x1D, 0x38, 0x2A]
            }),
            ("mouse typing", PasteOutcome::Aborted("mouse"), |w| {
                w.typing("abcdef");
                w.step(Event::MouseButton {
                    button: Button::Right,
                    pressed: true,
                    x: 5,
                    y: 5,
                });
                vec![]
            }),
            ("epoch typing", PasteOutcome::Aborted("release"), |w| {
                w.typing("abcdef");
                w.hid.release_all(ReleaseTrigger::WebsocketReconnect);
                drain(&w.hid, &mut w.dev);
                w.step(Event::Tick);
                vec![]
            }),
            ("epoch pending", PasteOutcome::Aborted("release"), |w| {
                w.chord();
                w.hid.release_all(ReleaseTrigger::Suppression);
                drain(&w.hid, &mut w.dev);
                w.step(Event::MouseMove { x: 3, y: 3 });
                vec![0x1D, 0x38, 0x2A]
            }),
            (
                "synchronize typing",
                PasteOutcome::Aborted("release"),
                |w| {
                    w.typing("abcdef");
                    w.step(Event::Synchronize { caps_lock: false });
                    vec![]
                },
            ),
            (
                "synchronize pending",
                PasteOutcome::Aborted("release"),
                |w| {
                    w.chord();
                    w.step(Event::Synchronize { caps_lock: false });
                    vec![0x1D, 0x38, 0x2A]
                },
            ),
            ("timer pending", PasteOutcome::Aborted("release"), |w| {
                w.modifier_wait = Duration::from_secs(60);
                w.chord();
                w.now += Duration::from_secs(30); // modifier_idle_timeout
                w.step(Event::Tick);
                vec![0x1D, 0x38, 0x2A]
            }),
            (
                "modifier wait",
                PasteOutcome::Aborted("modifier_wait"),
                |w| {
                    w.chord();
                    w.now += Duration::from_secs(5);
                    w.step(Event::Tick);
                    vec![0x1D, 0x38, 0x2A]
                },
            ),
            (
                "done",
                PasteOutcome::Done {
                    typed: 6,
                    skipped: 0,
                },
                |w| {
                    w.key(0x1E, true); // 'a', held through the paste
                    w.typing("abcdef");
                    w.key(0x10, true); // q, swallowed
                    for _ in 0..64 {
                        w.now += w.pace;
                        w.step(Event::Tick);
                    }
                    vec![0x1E, 0x10]
                },
            ),
        ];
        for (what, want, drive) in cases {
            let mut w = Wired::new();
            let held = drive(&mut w);
            let ends: Vec<_> = w
                .outcomes
                .iter()
                .filter(|o| !matches!(o, PasteOutcome::Started))
                .collect();
            assert_eq!(ends, [&want], "{what}");
            assert!(!w.core.paste.is_active(), "{what}");
            w.device_follows_the_core(what);
            w.settle(&held, what);
        }
    }

    // ---- The PD9 carries: clipboard answers, the session boundary, room.

    fn discards(out: &[Out]) -> Vec<&'static str> {
        out.iter()
            .filter_map(|o| match o {
                Out::ClipboardDiscarded(why) => Some(*why),
                _ => None,
            })
            .collect()
    }

    /// The chord's keys up; the outs of their steps.
    fn release_chord(r: &mut Rig) -> Vec<Out> {
        let mut out = Vec::new();
        for code in [0x2F, 0x1D, 0x38, 0x2A] {
            out.extend(r.step(Event::KeyReleased {
                code,
                extended: false,
            }));
        }
        out
    }

    /// A paste that waits out `modifier_wait` unanswered.
    fn time_out_a_paste(r: &mut Rig) {
        hold_chord(r);
        assert!(matches!(
            outcomes(&r.step(chord_event())).as_slice(),
            [PasteOutcome::Started]
        ));
        r.advance(Duration::from_secs(5));
        assert!(matches!(
            outcomes(&r.step(Event::Tick)).as_slice(),
            [PasteOutcome::Aborted("modifier_wait")]
        ));
        let _ = release_chord(r);
    }

    /// PD9 carry 3 (a): CLIPRDR answers in order, so an answer belongs to
    /// the oldest request still unanswered. A paste's request queued behind
    /// a timed-out paste's: the first answer is the old one's — discarded
    /// and counted `late`, never typed — and the second is the paste's.
    #[test]
    fn an_answer_is_the_pastes_only_if_it_asked_for_it() {
        let mut r = Rig::new();
        time_out_a_paste(&mut r);
        hold_chord(&mut r);
        r.step(chord_event());
        let out = r.step(Event::ClipboardText(utf16le("old")));
        assert_eq!(discards(&out), ["late"]);
        assert!(pushes(&out).is_empty());
        let out = r.step(Event::ClipboardText(utf16le("ok")));
        assert!(discards(&out).is_empty(), "{}", show(&out));
        let mut out = release_chord(&mut r); // typing begins
        let mut typed = Vec::new();
        for _ in 0..8 {
            r.advance(Duration::from_millis(1));
            out.extend(r.step(Event::Tick));
        }
        for (f, _) in pushes(&out) {
            if let HidFrame::Keyboard { keys, .. } = f
                && keys[0] != 0
            {
                typed.push(keys[0]);
            }
        }
        assert!(
            r.core.paste.deadline().is_none(),
            "the paste did not end: {}",
            show(&out)
        );
        // 'o' 'k', and nothing of "old" (whose 'l' and 'd' would show).
        assert_eq!(typed, [0x12, 0x0E], "{}", show(&out));
        // Nothing is outstanding now: a further answer is unasked.
        assert_eq!(
            discards(&r.step(Event::ClipboardText(utf16le("x")))),
            ["unasked"]
        );
    }

    /// PD9 carry 3 (b): a failed answer to the waiting paste ends it at
    /// once (`clipboard_failed`), long before `modifier_wait`; a failure
    /// no paste is waiting on is discarded — `late` while a request is
    /// outstanding, `unasked` when none is.
    #[test]
    fn a_failed_answer_ends_the_paste_that_asked() {
        let mut r = Rig::new();
        hold_chord(&mut r);
        r.step(chord_event());
        let out = r.step(Event::ClipboardFailed);
        assert!(matches!(
            outcomes(&out).as_slice(),
            [PasteOutcome::Aborted("clipboard_failed")]
        ));
        assert!(pushes(&out).is_empty(), "a Pending paste pushed nothing");
        assert_eq!(r.core.paste.deadline(), None);
        assert_eq!(discards(&r.step(Event::ClipboardFailed)), ["unasked"]);
        let _ = release_chord(&mut r);
        time_out_a_paste(&mut r);
        assert_eq!(discards(&r.step(Event::ClipboardFailed)), ["late"]);
        assert!(r.holds_nothing());
    }

    /// PD9 carry 3 (c): an answer nobody asked for is discarded and
    /// counted, and kept for nothing: the next paste waits for its own.
    #[test]
    fn an_unasked_answer_is_counted_and_not_kept() {
        let mut r = Rig::new();
        assert_eq!(
            discards(&r.step(Event::ClipboardText(utf16le("zz")))),
            ["unasked"]
        );
        hold_chord(&mut r);
        r.step(chord_event());
        let mut out = release_chord(&mut r);
        r.advance(Duration::from_millis(10));
        out.extend(r.step(Event::Tick));
        assert!(
            !out.iter().any(|o| matches!(o, Out::Push { frame, .. }
                if matches!(frame, HidFrame::Keyboard { keys, .. } if keys[0] != 0))),
            "the unasked text was typed: {}",
            show(&out)
        );
        assert!(matches!(r.core.paste, State::Pending { text: None, .. }));
    }

    /// PD9 carry 3 (m2): answers the backend dropped while one was in
    /// flight are answers too — the paste one of them answered ends at
    /// once (`clipboard_lost`), and the count stays true for the next. The
    /// core counts no discard for them (the shell counts `in_flight`); past
    /// the outstanding requests they change nothing.
    #[test]
    fn answers_lost_in_flight_are_answers() {
        let mut r = Rig::new();
        time_out_a_paste(&mut r);
        hold_chord(&mut r);
        r.step(chord_event());
        let out = r.step(Event::ClipboardLost(1));
        assert!(discards(&out).is_empty());
        assert!(outcomes(&out).is_empty(), "the old paste's answer");
        let out = r.step(Event::ClipboardLost(u32::MAX));
        assert!(matches!(
            outcomes(&out).as_slice(),
            [PasteOutcome::Aborted("clipboard_lost")]
        ));
        assert!(discards(&out).is_empty());
        let _ = release_chord(&mut r);
        hold_chord(&mut r);
        r.step(chord_event());
        r.step(Event::ClipboardText(utf16le("k")));
        let _ = release_chord(&mut r);
        assert_eq!(
            finish(&mut r),
            PasteOutcome::Done {
                typed: 1,
                skipped: 0
            }
        );
    }

    /// The fatal oversize answer (§8; the shell steps it before the close)
    /// ends the paste that asked as `Refused(Oversize)`.
    #[test]
    fn an_oversize_answer_ends_the_paste_as_oversize() {
        let mut r = Rig::new();
        hold_chord(&mut r);
        r.step(chord_event());
        let out = r.step(Event::ClipboardOversize);
        assert!(matches!(
            outcomes(&out).as_slice(),
            [PasteOutcome::Refused(PasteRefusal::Oversize)]
        ));
        assert!(discards(&r.step(Event::ClipboardOversize)).is_empty());
        assert_eq!(r.core.paste.deadline(), None);
    }

    /// PD9 carry 2 (PD7): a new generation reports the paste it ends (the
    /// shell counts it), Pending or Typing, and forgets the requests the
    /// old one had outstanding — their answers die with its connection, so
    /// the new session's first answer is its first paste's.
    #[test]
    fn a_new_generation_reports_the_paste_it_ends_and_forgets_the_requests() {
        let mut r = Rig::new();
        assert_eq!(r.core.on_generation(2), None, "no paste, no outcome");
        r.step(Event::ClipboardAvailable(true));
        time_out_a_paste(&mut r);
        hold_chord(&mut r);
        r.step(chord_event());
        assert_eq!(
            r.core.on_generation(3),
            Some(PasteOutcome::Aborted("session"))
        );
        r.step(Event::ClipboardAvailable(true));
        hold_chord(&mut r);
        r.step(chord_event());
        let out = r.step(Event::ClipboardText(utf16le("k")));
        assert!(discards(&out).is_empty(), "{}", show(&out));
        let _ = release_chord(&mut r);
        assert_eq!(
            finish(&mut r),
            PasteOutcome::Done {
                typed: 1,
                skipped: 0
            }
        );
        // Typing, too.
        start_paste(&mut r, "abcdefghij");
        assert!(matches!(r.core.paste, State::Typing { .. }));
        assert!(r.core.holds_input(), "a typing paste may hold a press");
        assert_eq!(
            r.core.on_generation(4),
            Some(PasteOutcome::Aborted("session"))
        );
        assert!(!r.core.holds_input());
    }

    /// `holds_input`: what the core sent may still be down on the KVM — a
    /// key, a modifier, a button, a typing paste's press — and nothing
    /// else; `seen_epoch` is the epoch of its last step.
    #[test]
    fn holds_input_is_exactly_what_may_be_down() {
        let mut r = Rig::new();
        assert!(!r.core.holds_input());
        for (down, up) in [
            (
                Event::KeyPressed {
                    code: 0x1E,
                    extended: false,
                },
                Event::KeyReleased {
                    code: 0x1E,
                    extended: false,
                },
            ),
            (
                Event::KeyPressed {
                    code: 0x1D,
                    extended: false,
                },
                Event::KeyReleased {
                    code: 0x1D,
                    extended: false,
                },
            ),
            (
                Event::MouseButton {
                    button: Button::Middle,
                    pressed: true,
                    x: 1,
                    y: 1,
                },
                Event::MouseButton {
                    button: Button::Middle,
                    pressed: false,
                    x: 1,
                    y: 1,
                },
            ),
        ] {
            r.step(down);
            assert!(r.core.holds_input());
            r.step(up);
            assert!(!r.core.holds_input());
        }
        hold_chord(&mut r);
        r.step(chord_event());
        let _ = release_chord(&mut r);
        assert!(!r.core.holds_input(), "a Pending paste sent nothing");
        r.epoch = 9;
        r.step(Event::Tick);
        assert_eq!(r.core.seen_epoch(), 9);
    }

    /// PD9 carry 5 (PD7 m3): the Typist takes at most eight reports per
    /// step (DD6) whatever room the shell reports — a shell bug, or a
    /// larger `8 - queued`, never lets typing outrun the queue.
    #[test]
    fn typing_takes_at_most_eight_reports_a_step() {
        let mut r = Rig::new();
        r.room = 1000;
        let out = start_paste(&mut r, "abcdefghijklmnopqrstuvwxyz");
        assert_eq!(pushes(&out).len(), TYPIST_ROOM, "{}", show(&out));
        r.advance(Duration::from_millis(1));
        assert_eq!(pushes(&r.step(Event::Tick)).len(), TYPIST_ROOM);
    }

    // ---- PD9 fix round 1, I2: requests the client never answers.

    /// A paste through to its outcome: the chord, the answer `text`, the
    /// chord's keys up, Ticks to the end. Its outcome and every discard.
    fn paste_with(r: &mut Rig, text: &str) -> (PasteOutcome, Vec<&'static str>) {
        let mut out = Vec::new();
        hold_chord(r);
        out.extend(r.step(chord_event()));
        out.extend(r.step(Event::ClipboardText(utf16le(text))));
        out.extend(release_chord(r));
        for _ in 0..64 {
            if outcomes(&out)
                .iter()
                .any(|p| !matches!(p, PasteOutcome::Started))
            {
                break;
            }
            r.advance(Duration::from_millis(1));
            out.extend(r.step(Event::Tick));
        }
        let end = outcomes(&out)
            .into_iter()
            .find(|p| !matches!(p, PasteOutcome::Started))
            .cloned()
            .expect("the paste never ended");
        (end, discards(&out))
    }

    /// I2 (a), the review's X1: a client that never answers one request
    /// does not break paste for the session. The request is retired once it
    /// is `request_retire` old (counted `unanswered`), and every later paste
    /// takes its own answer — before, all five were discarded as `late`.
    #[test]
    fn a_request_never_answered_is_retired() {
        let mut r = Rig::new();
        assert_eq!(
            request_retire(Duration::from_secs(5)),
            Duration::from_secs(60)
        );
        time_out_a_paste(&mut r); // its request is never answered
        for n in 0..5 {
            r.advance(Duration::from_secs(600));
            let (end, discarded) = paste_with(&mut r, "ok");
            assert_eq!(
                end,
                PasteOutcome::Done {
                    typed: 2,
                    skipped: 0
                },
                "paste {n}"
            );
            let want: &[&str] = if n == 0 { &["unanswered"] } else { &[] };
            assert_eq!(discarded, want, "paste {n}");
        }
    }

    /// I2: a request younger than `request_retire` is still outstanding —
    /// its late answer, at half that age, is discarded and never typed;
    /// the next answer is the waiting paste's.
    #[test]
    fn a_late_answer_before_retirement_is_still_discarded() {
        let mut r = Rig::new();
        time_out_a_paste(&mut r);
        r.advance(request_retire(Duration::from_secs(5)) / 2);
        hold_chord(&mut r);
        r.step(chord_event());
        assert_eq!(
            discards(&r.step(Event::ClipboardText(utf16le("old")))),
            ["late"]
        );
        r.step(Event::ClipboardText(utf16le("k")));
        let _ = release_chord(&mut r);
        assert_eq!(
            finish(&mut r),
            PasteOutcome::Done {
                typed: 1,
                skipped: 0
            }
        );
    }

    /// I2: `request_retire` is `max(60 s, 2 × modifier_wait)`, so a Pending
    /// paste's own request is never retired while it waits; were the first
    /// step after its wait to come later still, the paste ends
    /// `modifier_wait` (it is past it) and the answer that step brings is
    /// discarded — never typed.
    #[test]
    fn a_pastes_own_request_is_never_retired_while_it_waits() {
        assert_eq!(
            request_retire(Duration::from_secs(100)),
            Duration::from_secs(200)
        );
        let mut r = Rig::new();
        hold_chord(&mut r);
        r.step(chord_event());
        r.advance(Duration::from_secs(61)); // no step meanwhile
        let out = r.step(Event::ClipboardText(utf16le("late")));
        assert!(matches!(
            outcomes(&out).as_slice(),
            [PasteOutcome::Aborted("modifier_wait")]
        ));
        assert_eq!(discards(&out), ["unanswered", "unasked"]);
        assert!(!pushes_usage(&out, 0x0F), "{}", show(&out));
    }

    /// I2: a request retired while a paste waits behind it moves that
    /// paste up — the paste's own answer, coming after the retirement, is
    /// its (not taken for the retired one's and discarded).
    #[test]
    fn a_request_retired_while_a_paste_waits_behind_it() {
        let mut r = Rig::new();
        time_out_a_paste(&mut r); // its request went out at t0; now t0 + 5 s
        r.advance(Duration::from_secs(53)); // that request is 58 s old
        hold_chord(&mut r);
        r.step(chord_event()); // one request ahead of this one's
        r.advance(Duration::from_secs(3)); // 61 s old; this paste waited 3 s of 5
        let out = r.step(Event::ClipboardText(utf16le("k")));
        assert_eq!(discards(&out), ["unanswered"], "{}", show(&out));
        let _ = release_chord(&mut r);
        assert_eq!(
            finish(&mut r),
            PasteOutcome::Done {
                typed: 1,
                skipped: 0
            }
        );
    }

    /// I2, m-R2 (PD9 re-review): at most `MAX_REQUESTS` (64, IronRDP's own
    /// cap) are outstanding. A paste past it is refused locally (`backlog`)
    /// and sends no request — IronRDP would fail a 65th itself, and the
    /// core would take that failure for its oldest request's answer. Once
    /// the oldest are retired, pastes ask again.
    #[test]
    fn a_paste_past_the_outstanding_requests_cap_is_refused_locally() {
        let mut r = Rig::new();
        let (mut discarded, mut refused, mut requests) = (Vec::new(), 0, 0);
        for _ in 0..70 {
            hold_chord(&mut r);
            let out = r.step(chord_event());
            discarded.extend(discards(&out));
            refused += outcomes(&out)
                .iter()
                .filter(|p| matches!(p, PasteOutcome::Refused(PasteRefusal::Backlog)))
                .count();
            requests += out
                .iter()
                .filter(|o| matches!(o, Out::RequestClipboard))
                .count();
            // Esc ends it at once: 70 pastes well inside `request_retire`.
            r.step(Event::KeyPressed {
                code: 0x01,
                extended: false,
            });
            r.step(Event::KeyReleased {
                code: 0x01,
                extended: false,
            });
            let _ = release_chord(&mut r);
            r.advance(Duration::from_millis(1));
        }
        assert_eq!(r.core.requests.len(), MAX_REQUESTS);
        assert_eq!((requests, refused), (MAX_REQUESTS, 6));
        assert!(discarded.is_empty(), "{discarded:?}");
        // Past `request_retire` the 64 retire, and a paste asks again.
        r.advance(Duration::from_secs(60));
        hold_chord(&mut r);
        let out = r.step(chord_event());
        assert_eq!(discards(&out), ["unanswered"; MAX_REQUESTS]);
        assert!(matches!(outcomes(&out).as_slice(), [PasteOutcome::Started]));
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
            .and_then(unicode_key_stroke)
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
            match o {
                Out::Push {
                    frame,
                    motion_only,
                    stamp,
                } => {
                    let _ = hid.push_at(*stamp, *frame, *motion_only);
                }
                Out::Release(t) => hid.release_all(*t),
                Out::Ignored
                | Out::RequestClipboard
                | Out::Paste(_)
                | Out::ClipboardDiscarded(_) => {}
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

    /// The paste's phase, for the property's oracle.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Phase {
        Idle,
        Pending,
        Typing,
    }

    fn phase(core: &InputCore) -> Phase {
        match core.paste {
            State::Idle => Phase::Idle,
            State::Pending { .. } => Phase::Pending,
            State::Typing { .. } => Phase::Typing,
        }
    }

    /// Every outcome's label, for the coverage count (`session` is
    /// `on_generation`'s).
    const OUTCOMES: [&str; 15] = [
        "started",
        "no_text",
        "caps_lock",
        "multiline",
        "done",
        "esc",
        "key",
        "mouse",
        "release",
        "modifier_wait",
        "clipboard_failed",
        "clipboard_lost",
        "oversize",
        "session",
        "backlog",
    ];

    fn label(p: &PasteOutcome) -> &'static str {
        match p {
            PasteOutcome::Started => "started",
            PasteOutcome::Refused(PasteRefusal::NoText) => "no_text",
            PasteOutcome::Refused(PasteRefusal::CapsLock) => "caps_lock",
            PasteOutcome::Refused(PasteRefusal::Multiline) => "multiline",
            PasteOutcome::Refused(PasteRefusal::Oversize) => "oversize",
            PasteOutcome::Refused(PasteRefusal::Backlog) => "backlog",
            PasteOutcome::Done { .. } => "done",
            PasteOutcome::Aborted(why) => why,
        }
    }

    /// The oracle's paste bookkeeping: a `Started` is open until exactly
    /// one end (`Done`, an `Aborted`, `Refused(Multiline | Oversize)`); a
    /// refusal at the chord (`NoText`, `CapsLock`) opens nothing; `Started`
    /// is followed at once by `RequestClipboard`.
    struct PasteOracle {
        open: bool,
        /// The pending paste's deadline: its chord plus `modifier_wait`.
        pending_deadline: Option<Instant>,
        /// The seed's `paste.max_chars`: no paste types more.
        max_chars: usize,
        fired: [usize; 15],
    }

    impl PasteOracle {
        fn see(&mut self, outs: &[Out], now: Instant, modifier_wait: Duration, at: &str) {
            for (i, o) in outs.iter().enumerate() {
                let Out::Paste(p) = o else { continue };
                let l = label(p);
                let n = OUTCOMES.iter().position(|x| *x == l);
                assert!(n.is_some(), "{at}: {l} from the core");
                self.fired[n.unwrap()] += 1;
                if let PasteOutcome::Done { typed, .. } = p {
                    assert!(*typed <= self.max_chars, "{at}: past max_chars");
                }
                match p {
                    PasteOutcome::Started => {
                        assert!(!self.open, "{at}: a second Started");
                        assert_eq!(outs.get(i + 1), Some(&Out::RequestClipboard), "{at}");
                        self.open = true;
                        self.pending_deadline = Some(now + modifier_wait);
                    }
                    PasteOutcome::Refused(
                        PasteRefusal::NoText | PasteRefusal::CapsLock | PasteRefusal::Backlog,
                    ) => {
                        assert!(!self.open, "{at}: a chord refused while a paste is open");
                    }
                    _ => {
                        assert!(self.open, "{at}: {l} ends no paste");
                        self.open = false;
                        self.pending_deadline = None;
                    }
                }
            }
            assert_eq!(
                outs.iter()
                    .filter(|o| matches!(o, Out::RequestClipboard))
                    .count(),
                outs.iter()
                    .filter(|o| matches!(o, Out::Paste(PasteOutcome::Started)))
                    .count(),
                "{at}: a request without a Started"
            );
        }
    }

    /// The property (§7.4 "a key must never end held", and §8), over random
    /// sequences of keyboard, Unicode, mouse and Synchronize events, Ticks,
    /// time jumps (to a deadline, a nanosecond short of one, or past both
    /// timeouts), the shell's own releases (a moved epoch, a new session),
    /// lost client releases, remap and surface changes, a stalled writer
    /// whose queue overflows — and pastes: chords (sought on purpose), Esc,
    /// clipboard responses asked and unasked (single-line, multiline,
    /// untypeable, long, NUL-terminated with junk after), availability
    /// changes, at a pace of 0, 1 or 15 ms, a 300 ms or 5 s modifier wait,
    /// multiline refused or not, and a 5-character cap — carried out
    /// through the real `HidControl` and drained as the writer does, with
    /// the HID queue's room as the shell computes it:
    /// - every report carries its step's epoch, and a release is always the
    ///   last out of its step;
    /// - a release fires exactly when its oracle says (Synchronize on a
    ///   Synchronize; at a Tick, the key-repeat timer when a held non-
    ///   modifier saw no accepted press for its timeout, else the modifier-
    ///   idle timer when a held modifier saw no keyboard event for its own),
    ///   and `next_deadline` is exactly the soonest of the armed deadlines
    ///   and the paste's (Pending: its chord plus `modifier_wait`);
    /// - after any trigger or timer expiry nothing is held, in the core or
    ///   on the device, and no paste is active; a moved epoch's step pushes
    ///   the zero report first;
    /// - whatever was held at a release, and every key a paste swallowed or
    ///   released when typing began, stays up until the client's own
    ///   Released (or a Synchronize, m6) — and the marks are exactly these;
    /// - paste outcomes are well-sequenced (one end per Started, a request
    ///   with each Started) and match the core's phase;
    /// - a typing step pushes at most the queue's room (DD6), and with no
    ///   room looks again no sooner than ROOM_POLL;
    /// - whenever the core holds a key or modifier a deadline is armed, and
    ///   the device never holds what the core does not — while typing, only
    ///   the Typist's one key (with at most Shift) or keys already marked;
    /// - at the end the client goes silent: Ticks at each deadline end any
    ///   paste and leave no key held, and once the client lets go the
    ///   device holds nothing.
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
        const ESC: (u8, bool) = (0x01, false);
        let chord_mods: [[(u8, bool); 2]; 3] = [
            [(0x1D, false), (0x1D, true)],  // Ctrl
            [(0x38, false), (0x38, true)],  // Alt / Option
            [(0x2A, false), (0x36, false)], // Shift
        ];
        let units: Vec<u16> = "AaCc1!".encode_utf16().chain([0xD800, 0x00E9]).collect();
        let texts = [
            "",
            "x",
            "Hi there\r\n",
            "a\nb",
            "é€z",
            "abcdefghijklmnopqrstuvwxyz0123456789",
            "\t \r\n\r\n",
            "ls -la",
        ];
        let coords = [0u16, 10, 960, 1919, 5000, u16::MAX];
        let spans = [(1920u16, 1080u16), (1280, 720), (1, 1), (0, 0)];
        let advances = [0u64, 1, 200, 900, 2_000, 9_000, 11_000, 31_000];
        let timeouts = [
            (Duration::from_secs(10), Duration::from_secs(30)),
            (Duration::from_secs(1), Duration::from_millis(500)),
            (Duration::from_secs(1), Duration::from_secs(3)),
            (Duration::from_secs(10), Duration::from_secs(3)),
        ];
        let paces = [
            Duration::ZERO,
            Duration::from_millis(1),
            Duration::from_millis(15),
        ];
        let waits = [Duration::from_millis(300), Duration::from_secs(5)];
        let shell_triggers = [
            ReleaseTrigger::SessionStart,
            ReleaseTrigger::WebsocketReconnect,
            ReleaseTrigger::Suppression,
            ReleaseTrigger::Closing,
        ];
        let mut fired = [0usize; 3]; // synchronize, key_repeat, modifier_idle
        let mut paste = PasteOracle {
            open: false,
            pending_deadline: None,
            max_chars: 4096,
            fired: [0; 15],
        };
        let (mut typing_steps, mut roomless_steps) = (0usize, 0usize);
        // 96 seeds: every outcome fires 20 times over with a margin (PD9 fix
        // round 1 added the relative release, which moved the stream).
        for seed in 1..=96u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let s = usize::try_from(seed).unwrap();
            let (krt, mit) = timeouts[s % timeouts.len()];
            let pace = paces[s % paces.len()];
            let modifier_wait = waits[(s / 3) % waits.len()];
            let multiline_refuse = (s / 2) % 2 == 0;
            let max_chars = if s % 5 == 0 { 5 } else { 4096 };
            let hid = HidControl::new(rng.pick(&[4usize, 64]), Arc::new(Metrics::default()));
            let mut dev = Device::default();
            let mut core = InputCore::new();
            let _ = core.on_generation(1);
            let mut now = Instant::now();
            let mut seen = hid.epoch();
            let mut generation = 1;
            let (mut remap, mut surface) = (false, (1920, 1080));
            let mut stalled = false;
            // What sits in the HID queue since the writer last drained it:
            // the shell's room is 8 less that (DD6).
            let mut queued = 0usize;
            paste.open = false;
            paste.pending_deadline = None;
            paste.max_chars = max_chars;
            // The client's side: what it has sent a Pressed for and not a
            // Released (a lost release stays here, never sent).
            let mut sent_codes: Vec<(u8, bool)> = Vec::new();
            let mut sent_units: Vec<u16> = Vec::new();
            let mut sent_buttons: Vec<Button> = Vec::new();
            // The oracle: the timers' bases (D8e; "any keyboard event"), and
            // what was held at a marking release, or swallowed by a paste,
            // and is still owed its client Released (§7.4, D3c).
            let mut key_activity: Option<Instant> = None;
            let mut kbd_event: Option<Instant> = None;
            let mut owed: Vec<u8> = Vec::new();
            let mut owed_buttons = 0u8;
            let mk = |now: Instant,
                      epoch: u64,
                      generation: Gen,
                      remap: bool,
                      surface: (u16, u16),
                      queue_room: usize| Ctx {
                now,
                epoch,
                generation,
                surface,
                mac_remap: remap,
                key_repeat_timeout: krt,
                modifier_idle_timeout: mit,
                chord: chord(),
                pace,
                modifier_wait,
                multiline_refuse,
                max_chars,
                queue_room,
            };
            let press = |sent_codes: &mut Vec<(u8, bool)>, c: (u8, bool)| {
                if !sent_codes.contains(&c) {
                    sent_codes.push(c);
                }
                Event::KeyPressed {
                    code: c.0,
                    extended: c.1,
                }
            };
            let release = |sent_codes: &mut Vec<(u8, bool)>, c: (u8, bool)| {
                sent_codes.retain(|d| *d != c);
                Event::KeyReleased {
                    code: c.0,
                    extended: c.1,
                }
            };
            let clipboard = |rng: &mut Rng| {
                let mut b = utf16le(rng.pick(&texts));
                if rng.below(4) != 0 {
                    b.extend_from_slice(&[0, 0]); // CF_UNICODETEXT's terminator
                    if rng.below(2) == 0 {
                        b.extend_from_slice(&utf16le("\r\njunk")); // not text
                    }
                }
                Event::ClipboardText(b)
            };
            // Any answer (PD9 carry 3): mostly text; now and then a failure,
            // the fatal oversize, or answers lost in flight.
            let answer = |rng: &mut Rng| match rng.below(16) {
                0 => Event::ClipboardFailed,
                1 => Event::ClipboardOversize,
                2 => Event::ClipboardLost(rng.pick(&[1u32, 2, 1_000])),
                _ => clipboard(rng),
            };
            for i in 0..2_000 {
                // Pastes are driven on more often than not once one is
                // pending or typing, and sought now and then when idle;
                // otherwise any event.
                let branch = match phase(&core) {
                    Phase::Pending if rng.below(4) != 0 => 31,
                    Phase::Typing if rng.below(8) != 0 => 31,
                    Phase::Idle if rng.below(6) == 0 => 26,
                    _ => rng.below(34),
                };
                let event = match branch {
                    0..=4 => {
                        let c = if !sent_codes.is_empty() && rng.below(2) == 0 {
                            rng.pick(&sent_codes) // a typematic repeat
                        } else {
                            rng.pick(&codes)
                        };
                        press(&mut sent_codes, c)
                    }
                    5..=7 => {
                        let c = if !sent_codes.is_empty() && rng.below(4) != 0 {
                            rng.pick(&sent_codes)
                        } else {
                            rng.pick(&codes) // a stray release
                        };
                        release(&mut sent_codes, c)
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
                        // I4: now and then a release with no position (relative).
                        if !pressed && rng.below(4) == 0 {
                            Event::ButtonUp { button: b }
                        } else {
                            Event::MouseButton {
                                button: b,
                                pressed,
                                x: rng.pick(&coords),
                                y: rng.pick(&coords),
                            }
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
                        queued = 0;
                        drain(&hid, &mut dev);
                        assert!(
                            !dev.holds_a_key() && dev.buttons == 0,
                            "seed {seed} step {i}: the shell's release left the device holding"
                        );
                        // A new session, more often while a paste is open (its
                        // `session` outcome, PD9 carry 2).
                        if rng.below(if paste.open { 2 } else { 4 }) == 0 {
                            generation += 1;
                            // PD9 carry 2: the paste it ends is reported.
                            let ended = core.on_generation(generation);
                            assert_eq!(ended.is_some(), paste.open, "seed {seed} step {i}");
                            if let Some(p) = ended {
                                assert_eq!(p, PasteOutcome::Aborted("session"));
                                paste.fired[13] += 1;
                            }
                            assert_eq!(held(&core), (Vec::new(), 0), "seed {seed} step {i}");
                            assert_eq!(core.next_deadline(), None, "seed {seed} step {i}");
                            assert_eq!(phase(&core), Phase::Idle, "seed {seed} step {i}");
                            owed.clear();
                            owed_buttons = 0;
                            key_activity = None;
                            kbd_event = None;
                            paste.open = false;
                            paste.pending_deadline = None;
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
                    26 | 27 => {
                        // Seek the chord: drop a GUI, press a missing chord
                        // modifier (either side), then V.
                        let bits = core.keys.held_modifier_bits();
                        let classes = kvm_proto::keymap::modifier_classes(bits);
                        let missing = (0..3).find(|n| classes & [0x01, 0x04, 0x02][*n] == 0);
                        if classes & 0x08 != 0 {
                            let c = if bits & 0x08 != 0 {
                                (0x5B, true)
                            } else {
                                (0x5C, true)
                            };
                            release(&mut sent_codes, c)
                        } else if let Some(n) = missing {
                            let c = rng.pick(&chord_mods[n]);
                            press(&mut sent_codes, c)
                        } else {
                            press(&mut sent_codes, (0x2F, false))
                        }
                    }
                    28 => answer(&mut rng),
                    29 => Event::ClipboardAvailable(rng.below(4) != 0),
                    30 => {
                        if sent_codes.contains(&ESC) && rng.below(2) == 0 {
                            release(&mut sent_codes, ESC)
                        } else {
                            press(&mut sent_codes, ESC)
                        }
                    }
                    31 | 32 => {
                        // Drive a paste on: its response, or the chord's
                        // modifiers up, or the Typist's next pace.
                        match phase(&core) {
                            Phase::Pending
                                if matches!(core.paste, State::Pending { text: None, .. })
                                    && rng.below(4) != 0 =>
                            {
                                answer(&mut rng)
                            }
                            Phase::Pending => {
                                let held_mod = sent_codes.iter().copied().find(|c| {
                                    *c == (0x2F, false)
                                        || chord_mods.iter().flatten().any(|m| m == c)
                                });
                                match held_mod {
                                    Some(c) => release(&mut sent_codes, c),
                                    None => Event::Tick,
                                }
                            }
                            _ => {
                                now += pace.max(Duration::from_millis(1));
                                Event::Tick
                            }
                        }
                    }
                    33 => {
                        now += Duration::from_millis(rng.pick(&[0u64, 1, 2, 15]));
                        Event::Tick
                    }
                    _ => {
                        now += Duration::from_millis(rng.pick(&advances));
                        Event::Tick
                    }
                };
                let epoch = hid.epoch();
                let moved = epoch != seen;
                seen = epoch;
                let room = 8usize.saturating_sub(queued);
                let before = held(&core);
                let (held_nonmod, held_mod) = if moved {
                    (false, false)
                } else {
                    (
                        core.keys.held_nonmodifier_usages() > 0,
                        core.keys.held_modifier_bits() != 0,
                    )
                };
                // The paste filter's view: a moved epoch releases first (the
                // paste ends, the held keys are marked) — then the event.
                let pre_phase = if moved { Phase::Idle } else { phase(&core) };
                let is_rbb =
                    |u: u8| core.keys.is_released_by_bridge(u) || (moved && before.0.contains(&u));
                let is_down = |u: u8| !moved && core.keys.is_down(u);
                let mods = if moved {
                    0
                } else {
                    core.keys.held_modifier_bits()
                };
                // D3c: the press a paste swallows (and marks), if any.
                let swallowed: Option<Option<u8>> = match event {
                    Event::KeyPressed { code, extended } => {
                        let u = usage_for_scancode(code, extended);
                        let chord_hit = u.is_some_and(|u| !is_rbb(u) && !is_down(u))
                            && chord().matches(code, extended, mods);
                        let esc_hit = pre_phase != Phase::Idle
                            && u == Some(0x29)
                            && !is_rbb(0x29)
                            && !is_down(0x29);
                        (chord_hit || esc_hit || pre_phase == Phase::Typing).then_some(u)
                    }
                    Event::UnicodePressed(unit) if pre_phase == Phase::Typing => {
                        Some(unit_usage(unit))
                    }
                    _ => None,
                };
                let released = match event {
                    Event::KeyReleased { code, extended } => usage_for_scancode(code, extended),
                    Event::UnicodeReleased(unit) => unit_usage(unit),
                    _ => None,
                };
                let mut outs = Vec::new();
                core.step(
                    &mk(now, epoch, generation, remap, surface, room),
                    event.clone(),
                    &mut outs,
                );
                let at = format!("seed {seed} step {i} {}: {}", describe(&event), show(&outs));
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
                // marked, and the step's first report is the zero report.
                if moved {
                    assert_eq!(pushes(&outs).first(), Some(&(kbd(0, 0), epoch)), "{at}");
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
                    assert_eq!(phase(&core), Phase::Idle, "{at}: a trigger left a paste");
                }
                // The paste: outcomes well-sequenced and matching the phase.
                let pending_deadline = paste.pending_deadline;
                paste.see(&outs, now, modifier_wait, &at);
                let post_phase = phase(&core);
                assert_eq!(paste.open, post_phase != Phase::Idle, "{at}");
                // PD7 review I1: modifier_wait ends a paste at its deadline,
                // never before, and no paste is still Pending at or past it.
                if outs
                    .iter()
                    .any(|o| matches!(o, Out::Paste(PasteOutcome::Aborted("modifier_wait"))))
                {
                    assert!(
                        pending_deadline.is_some_and(|d| now >= d),
                        "{at}: modifier_wait fired early"
                    );
                }
                if post_phase == Phase::Pending {
                    assert!(
                        paste.pending_deadline.is_some_and(|d| now < d),
                        "{at}: still pending past modifier_wait"
                    );
                }
                // D3c: a swallowed press is marked; typing's start marks
                // what the client still holds (never a modifier: typing
                // waits for every one to be up).
                if let Some(Some(u)) = swallowed
                    && !owed.contains(&u)
                {
                    owed.push(u);
                }
                let done = outs
                    .iter()
                    .any(|o| matches!(o, Out::Paste(PasteOutcome::Done { .. })));
                let began = pre_phase == Phase::Pending && (post_phase == Phase::Typing || done);
                if began {
                    for u in before.0.iter().filter(|u| modifier_bit(**u).is_none()) {
                        if Some(*u) != released && !owed.contains(u) {
                            owed.push(*u);
                        }
                    }
                    assert_eq!(core.keys.held_modifier_bits(), 0, "{at}");
                }
                // DD6: a typing step pushes at most the room; an abort's
                // only keyboard report is the all-zero one.
                let kb: Vec<HidFrame> = pushes(&outs)
                    .into_iter()
                    .map(|(f, _)| f)
                    .filter(|f| matches!(f, HidFrame::Keyboard { .. }))
                    .collect();
                if !moved && pre_phase == Phase::Typing {
                    typing_steps += 1;
                    let aborted = outs
                        .iter()
                        .any(|o| matches!(o, Out::Paste(PasteOutcome::Aborted("esc" | "mouse"))));
                    if aborted {
                        assert_eq!(kb, [kbd(0, 0)], "{at}");
                    } else {
                        assert!(kb.len() <= room, "{at}: room {room}");
                    }
                }
                if began {
                    // The event's own report, then the zero for what the client
                    // held (it goes out even with no room) and the Typist's.
                    assert!(kb.len() <= room.max(1) + 1, "{at}: room {room}");
                }
                if post_phase == Phase::Typing {
                    let d = core.paste.deadline().unwrap();
                    assert!(d >= now, "{at}: a typing deadline in the past");
                    if room == 0 {
                        roomless_steps += 1;
                        assert!(d >= now + crate::input::paste::ROOM_POLL, "{at}: a spin");
                        assert!(d > now, "{at}: a spin (ROOM_POLL is 0)");
                    }
                }
                if post_phase == Phase::Pending {
                    assert_eq!(core.paste.deadline(), paste.pending_deadline, "{at}");
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
                    }
                    | Event::ButtonUp { button } => owed_buttons &= !button_bit(button),
                    _ => {}
                }
                // Whatever was held at a release or swallowed stays up until
                // its own Released (§7.4); with 19 codes the marks never
                // overflow.
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
                // A held key or modifier always has its timer armed; the
                // core's deadline is exactly the soonest armed one.
                let kr = (core.keys.held_nonmodifier_usages() > 0)
                    .then(|| key_activity.expect("a held key with no key-repeat base") + krt);
                let mi = (core.keys.held_modifier_bits() != 0)
                    .then(|| kbd_event.expect("a held modifier with no idle base") + mit);
                assert_eq!(
                    core.next_deadline(),
                    [kr, mi, core.paste.deadline()].into_iter().flatten().min(),
                    "{at}"
                );
                carry(&hid, &outs);
                queued += outs
                    .iter()
                    .filter(|o| matches!(o, Out::Push { .. }))
                    .count();
                if !rel.is_empty() {
                    queued = 0; // a release clears the queue
                }
                if !stalled || want.is_some() {
                    drain(&hid, &mut dev);
                    queued = 0;
                    if want.is_some() {
                        assert!(
                            !dev.holds_a_key() && dev.buttons == 0,
                            "{at}: the device holds after a trigger"
                        );
                    }
                    // The device never holds what the core does not; while
                    // typing, only the Typist's press — one key in the first
                    // slot, with at most Shift — or its all-zero release
                    // (what the client held went to zero as typing began).
                    if let Some(HidFrame::Keyboard { modifiers, keys }) = dev.kbd {
                        let held_keys: Vec<u8> = keys.iter().copied().filter(|k| *k != 0).collect();
                        if post_phase == Phase::Typing {
                            let typist = keys[1..] == [0; 4]
                                && (modifiers == 0 || (modifiers == MOD_LSHIFT && keys[0] != 0));
                            assert!(typist, "{at}: device holds {:02x?} while typing", keys);
                        } else {
                            for k in &held_keys {
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
                    }
                    assert_eq!(
                        dev.buttons & !core.pointer.held_buttons(),
                        0,
                        "{at}: device holds a button"
                    );
                }
            }
            // The client goes silent: Ticks at each deadline end any paste
            // and release every key (each release is of everything).
            drain(&hid, &mut dev);
            for k in 0..20_000 {
                let Some(at) = core.next_deadline() else {
                    break;
                };
                now = now.max(at);
                let epoch = hid.epoch();
                let mut outs = Vec::new();
                core.step(
                    &mk(now, epoch, generation, remap, surface, 8),
                    Event::Tick,
                    &mut outs,
                );
                seen = epoch;
                let at = format!("seed {seed} silent tick {k}: {}", show(&outs));
                paste.see(&outs, now, modifier_wait, &at);
                carry(&hid, &outs);
                drain(&hid, &mut dev);
            }
            let _ = seen;
            assert_eq!(core.next_deadline(), None, "seed {seed}");
            assert_eq!(
                phase(&core),
                Phase::Idle,
                "seed {seed}: a paste never ended"
            );
            assert!(!paste.open, "seed {seed}");
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
                core.step(&mk(now, epoch, generation, remap, surface, 8), e, &mut outs);
                carry(&hid, &outs);
            }
            drain(&hid, &mut dev);
            assert_eq!(held(&core), (Vec::new(), 0), "seed {seed}");
            assert!(
                !dev.holds_a_key() && dev.buttons == 0,
                "seed {seed}: the device holds"
            );
        }
        // Every trigger the oracle knows fired, many times over; every
        // paste outcome the core can give, too, and typing met a full queue.
        assert!(fired.iter().all(|n| *n > 500), "{fired:?}");
        eprintln!(
            "paste outcomes {:?}, typing steps {typing_steps}, roomless {roomless_steps}",
            OUTCOMES.iter().zip(paste.fired).collect::<Vec<_>>()
        );
        // All but `backlog`, which needs 64 unanswered pastes inside 60 s.
        assert!(
            paste.fired[..14].iter().all(|n| *n >= 20),
            "{:?}",
            paste.fired
        );
        assert!(
            typing_steps > 1_000 && roomless_steps > 20,
            "{typing_steps} {roomless_steps}"
        );
    }
}
