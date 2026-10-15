//! The input path (§7, §8), wired: `InputShared` holds the sans-IO
//! `InputCore` under a mutex beside `HidControl`, the display, the server's
//! event sender and the config; `InputHandler` is IronRDP's callback, and
//! `run_driver` ticks the core at its next deadline. Every step reads the
//! release epoch into its `Ctx` and pushes with `push_at`, so a report
//! built before a release never lands after its zeros (§7.3; design
//! decision 6). The mutex is never held across an await (§4.3), and
//! nothing is called into IronRDP under it: a `ServerEvent` is a channel
//! send.
//!
//! A feed holds the core lock from its first step to the last of its
//! outputs carried out (PD9 fix round 1, I1): two feeds — from the handler,
//! the driver, the pump shell, or any other thread — never interleave their
//! reports, so a Typist press built by one step never lands after another
//! step's abort zero. Every lock taken under it is a leaf (the HID queue,
//! the display, the metrics). And the handler takes input only on the RDP
//! thread (`bind_rdp_thread`): IronRDP's ainput DVC calls it from
//! `spawn_blocking`, one task per PDU in no order — a Devolutions extension
//! Windows App does not use — and those calls are dropped and counted
//! (`input_events_ignored`, as DD7 drops relative motion).
//!
//! The core follows the live generation (`Generations`), whatever word the
//! pump shell last passed on: the handler moves it — and releases all —
//! inside `on_connection_info`/`on_disconnected`, on this thread, before
//! any input of the new session can be fed. So a `SessionStop` the shell
//! reads after the next session's keys began (Preempt) never resets them.
//! With no session live, input is counted and dropped.
//!
//! Nothing here logs input (§4.5, §9.2): no key, frame, position or byte
//! of clipboard text; paste activity is metrics, and the one log line (a
//! chord with no text offered, §8) names no content.
use crate::config::{Config, Multiline};
use crate::hid::{HidControl, ReleaseTrigger};
use crate::input::core::{Ctx, Event, InputCore, Out};
use crate::input::paste::{PasteOutcome, PasteRefusal, TYPIST_ROOM};
use crate::input::pointer::Button;
use crate::metrics::Metrics;
use crate::msg::{Gen, Generations};
use crate::rdp::clipboard::ServerEvents;
use crate::rdp::display::DisplayShared;
use ironrdp_cliprdr::backend::ClipboardMessage;
use ironrdp_cliprdr::pdu::ClipboardFormatId;
use ironrdp_pdu::input::fast_path::SynchronizeFlags;
use ironrdp_server::{KeyboardEvent, MouseButton, MouseEvent, RdpServerInputHandler, ServerEvent};
use kvm_proto::keymap::Chord;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread::ThreadId;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

/// The `input.*`/`paste.*` the core reads, resolved from `Config` once.
#[derive(Debug, Clone)]
pub struct InputRuntimeConfig {
    pub mac_remap: bool,
    pub key_repeat_timeout: Duration,
    pub modifier_idle_timeout: Duration,
    pub chord: Chord,
    pub pace: Duration,
    pub modifier_wait: Duration,
    pub multiline_refuse: bool,
    pub max_chars: usize,
}

impl InputRuntimeConfig {
    #[must_use]
    pub fn from_config(c: &Config) -> InputRuntimeConfig {
        InputRuntimeConfig {
            mac_remap: c.input.mac_remap,
            key_repeat_timeout: c.input.key_repeat_timeout,
            modifier_idle_timeout: c.input.modifier_idle_timeout,
            chord: c.paste.chord,
            pace: c.paste.pace,
            modifier_wait: c.paste.modifier_wait,
            multiline_refuse: matches!(c.paste.multiline, Multiline::Refuse),
            max_chars: c.paste.max_chars,
        }
    }
}

pub struct InputDeps {
    pub hid: Arc<HidControl>,
    pub display: Arc<DisplayShared>,
    /// IronRDP's `ServerEvent` sender, once `RdpServer::new` has handed it
    /// to `ClipFactory::set_sender` (D9a): the bridge's one cell, shared
    /// with the clipboard factory (PD9 carry 4).
    pub events: ServerEvents,
    pub gens: Arc<Generations>,
    pub metrics: Arc<Metrics>,
    pub cfg: InputRuntimeConfig,
}

/// The input path's clock: tokio's, so the core and the driver's sleeps
/// read one clock (a paused one in tests); outside tests it is
/// `Instant::now()`.
fn clock() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// The input core and what its `Out`s need. The handler, the driver and the
/// pump shell all feed it on the RDP `LocalSet`; whatever thread a feed
/// runs on, it steps and carries out its `Out`s under the core lock, so two
/// feeds never interleave them (D27; PD9 fix round 1, I1).
pub struct InputShared {
    core: Mutex<InputCore>,
    hid: Arc<HidControl>,
    display: Arc<DisplayShared>,
    events: ServerEvents,
    gens: Arc<Generations>,
    metrics: Arc<Metrics>,
    cfg: InputRuntimeConfig,
    /// The driver's next wake, in nanoseconds past `base` (at least 1), or
    /// 0 for "nothing armed"; `wake` tells the driver it changed.
    deadline: AtomicU64,
    base: Instant,
    wake: Notify,
    /// The RDP thread, the only one the handler takes input on (I1).
    rdp_thread: OnceLock<ThreadId>,
}

impl InputShared {
    #[must_use]
    pub fn new(d: InputDeps) -> InputShared {
        InputShared {
            core: Mutex::new(InputCore::new()),
            hid: d.hid,
            display: d.display,
            events: d.events,
            gens: d.gens,
            metrics: d.metrics,
            cfg: d.cfg,
            deadline: AtomicU64::new(0),
            base: clock(),
            wake: Notify::new(),
            rdp_thread: OnceLock::new(),
        }
    }

    /// Record the calling thread as the RDP thread, whose handler calls are
    /// the only ones taken (the first call wins; `bridge::rdp_main` makes
    /// it before the server runs). Unbound, the handler takes nothing.
    pub fn bind_rdp_thread(&self) {
        let _ = self.rdp_thread.set(std::thread::current().id());
    }

    fn on_rdp_thread(&self) -> bool {
        self.rdp_thread.get() == Some(&std::thread::current().id())
    }

    fn lock(&self) -> MutexGuard<'_, InputCore> {
        self.core.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn ctx(&self, now: Instant, generation: Gen) -> Ctx {
        let surface = self
            .display
            .surface()
            .unwrap_or_else(|| self.display.size());
        Ctx {
            now,
            epoch: self.hid.epoch(),
            generation,
            surface,
            mac_remap: self.cfg.mac_remap,
            key_repeat_timeout: self.cfg.key_repeat_timeout,
            modifier_idle_timeout: self.cfg.modifier_idle_timeout,
            chord: self.cfg.chord,
            pace: self.cfg.pace,
            modifier_wait: self.cfg.modifier_wait,
            multiline_refuse: self.cfg.multiline_refuse,
            max_chars: self.cfg.max_chars,
            // DD6 (D2b): how many more reports the HID queue takes before
            // the Typist could overflow it (the core clamps to it too).
            queue_room: TYPIST_ROOM.saturating_sub(self.hid.queued()),
        }
    }

    /// Bring the core to the live generation. `on_generation` drops the
    /// core's state with no release of its own (PD6 m3): the handler's
    /// `SessionStart`/`SessionEnd` release comes with every generation
    /// change, so the epoch has moved since the core's last step and the
    /// KVM was zeroed after anything it built. Should it ever not have,
    /// the KVM may still hold what the core is about to forget — release
    /// it here (PD9 carry 2). An ended paste is counted (PD7 carry).
    fn follow(&self, core: &mut InputCore, outs: &mut Vec<Out>) -> Gen {
        let live = self.gens.current().unwrap_or(0);
        if core.generation() != live {
            if core.holds_input() && core.seen_epoch() == self.hid.epoch() {
                outs.push(Out::Release(if live == 0 {
                    ReleaseTrigger::SessionEnd
                } else {
                    ReleaseTrigger::SessionStart
                }));
            }
            if let Some(ended) = core.on_generation(live) {
                outs.push(Out::Paste(ended));
            }
        }
        live
    }

    /// Bring the core to the live generation and carry out what that took
    /// — before any event's `Ctx` reads the epoch, so a release `follow`
    /// raised is behind every report the event builds (as carry 1's Tick
    /// is). Under the caller's core lock. The live generation.
    fn sync_generation(&self, core: &mut InputCore) -> Gen {
        let mut outs = Vec::new();
        let generation = self.follow(core, &mut outs);
        self.carry_out(generation, outs);
        generation
    }

    /// One core step at the live generation, its `Out`s carried out, all
    /// under the caller's core lock (I1). With no session, input is
    /// dropped (and counted).
    fn step(&self, core: &mut InputCore, now: Instant, event: Event) {
        let generation = self.sync_generation(core);
        let mut outs = Vec::new();
        if generation == 0 {
            if is_client_input(&event) {
                outs.push(Out::Ignored);
            }
        } else {
            core.step(&self.ctx(now, generation), event, &mut outs);
        }
        self.carry_out(generation, outs);
    }

    /// Step the core with `event`, carry out its `Out`s, and re-arm the
    /// driver — one hold of the core lock (I1).
    ///
    /// PD9 carry 1 (PD6 m2): the timers fire only on a `Tick`, and the
    /// driver shares this thread, so an event can come after a deadline
    /// the driver has not ticked yet. That Tick is stepped first and its
    /// `Out`s carried out — a release moves the epoch — and the event is
    /// stepped after, with the epoch read again. Stepped under one epoch
    /// read, the event's report would carry the pre-release stamp: dropped
    /// by `push_at`, its key then marked released-by-bridge.
    fn feed(&self, event: Event) {
        let now = clock();
        let mut core = self.lock();
        let due = core.next_deadline().is_some_and(|at| at <= now);
        if due && !matches!(event, Event::Tick) {
            self.step(&mut core, now, Event::Tick);
        }
        self.step(&mut core, now, event);
        self.rearm(&core);
    }

    fn carry_out(&self, generation: Gen, outs: Vec<Out>) {
        for out in outs {
            match out {
                Out::Push {
                    frame,
                    motion_only,
                    stamp,
                } => {
                    let _ = self.hid.push_at(stamp, frame, motion_only);
                }
                Out::Release(trigger) => self.hid.release_all(trigger),
                Out::Ignored => self.metrics.input_events_ignored.inc(), // DD7, DD9 (D8f)
                Out::RequestClipboard => self.request_clipboard(generation),
                Out::Paste(outcome) => self.count_paste(&outcome),
                Out::ClipboardDiscarded(why) => self.metrics.clipboard_discarded.inc(why),
            }
        }
    }

    /// §8 step 3: ask the client for its CF_UNICODETEXT — a `ServerEvent`,
    /// so only for the current generation (§4.3). The sender is read at
    /// send time: it exists once `RdpServer::new` has run, before any
    /// connection (D9a).
    fn request_clipboard(&self, generation: Gen) {
        if !self.gens.is_current(generation) {
            return;
        }
        if let Some(tx) = self.events.get() {
            let _ = tx.send(ServerEvent::Clipboard(ClipboardMessage::SendInitiatePaste(
                ClipboardFormatId::CF_UNICODETEXT,
            )));
        }
    }

    fn count_paste(&self, outcome: &PasteOutcome) {
        let label = match outcome {
            PasteOutcome::Started => "started",
            PasteOutcome::Done { typed: _, skipped } => {
                self.metrics
                    .paste_skipped_chars
                    .add(u64::try_from(*skipped).unwrap_or(u64::MAX));
                "done"
            }
            PasteOutcome::Refused(PasteRefusal::NoText) => {
                // §8: swallowed *and logged* (D20). Never any content.
                tracing::info!("paste chord with no text on the clipboard");
                "no_text"
            }
            PasteOutcome::Refused(PasteRefusal::CapsLock) => "caps_lock",
            PasteOutcome::Refused(PasteRefusal::Multiline) => "multiline",
            PasteOutcome::Refused(PasteRefusal::Oversize) => "oversize",
            PasteOutcome::Aborted(_) => "aborted",
        };
        self.metrics.paste_events.inc(label);
    }

    /// Publish the core's next deadline to the driver, and wake it if it
    /// changed. A deadline at or before `base` (none is: each follows an
    /// event after it) reads as 1 ns past it — at once, never "unarmed".
    fn rearm(&self, core: &InputCore) {
        let v = core.next_deadline().map_or(0, |at| {
            u64::try_from(at.saturating_duration_since(self.base).as_nanos())
                .unwrap_or(u64::MAX)
                .max(1)
        });
        if self.deadline.swap(v, Ordering::SeqCst) != v {
            self.wake.notify_one();
        }
    }

    /// The pump shell's word that a session began (`g`) or ended (`0`).
    /// The core follows the live generation, not this word (module doc):
    /// a stale word changes nothing.
    pub fn set_generation(&self, g: Gen) {
        let _ = g;
        let mut core = self.lock();
        let _ = self.sync_generation(&mut core);
        self.rearm(&core);
    }

    pub fn keyboard(&self, e: KeyboardEvent) {
        self.feed(to_key_event(e));
    }

    pub fn mouse(&self, e: MouseEvent) {
        match to_mouse_event(e) {
            Some(ev) => self.feed(ev),
            None => self.metrics.input_events_ignored.inc(),
        }
    }

    pub fn clipboard_available(&self, text: bool) {
        self.feed(Event::ClipboardAvailable(text));
    }

    pub fn clipboard_text(&self, bytes: Vec<u8>) {
        self.feed(Event::ClipboardText(bytes));
    }

    /// A failed answer (CB_RESPONSE_FAIL): the paste it answers ends at once
    /// (PD8 review (b)).
    pub fn clipboard_failed(&self) {
        self.feed(Event::ClipboardFailed);
    }

    /// The answer over `paste.max_bytes` the shell is ending the session
    /// for (§8): the paste it answers is counted `oversize`.
    pub fn clipboard_oversize(&self) {
        self.feed(Event::ClipboardOversize);
    }

    /// `n` answers the backend dropped while another was in flight (PD8
    /// review m2): counted, and answers to the requests all the same.
    pub fn clipboard_lost(&self, n: u32) {
        if n == 0 {
            return;
        }
        self.metrics
            .clipboard_discarded
            .add("in_flight", u64::from(n));
        self.feed(Event::ClipboardLost(n));
    }

    /// Tick the core when a timer, the pending paste's wait or the Typist's
    /// pace is due. Lives on the RDP `LocalSet`; it only locks, steps and
    /// sends — never blocks. A `notify_one` that comes while it is not
    /// waiting is kept as a permit, so no re-arm is missed.
    pub async fn run_driver(self: Arc<Self>) {
        loop {
            let d = self.deadline.load(Ordering::SeqCst);
            if d == 0 {
                self.wake.notified().await;
                continue;
            }
            let at = self.base + Duration::from_nanos(d);
            tokio::select! {
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(at)) => {
                    self.feed(Event::Tick);
                }
                () = self.wake.notified() => {}
            }
        }
    }
}

/// An event the client sent (not a clipboard word or a tick): counted as
/// ignored when no session is live to take it.
fn is_client_input(e: &Event) -> bool {
    matches!(
        e,
        Event::KeyPressed { .. }
            | Event::KeyReleased { .. }
            | Event::UnicodePressed(_)
            | Event::UnicodeReleased(_)
            | Event::Synchronize { .. }
            | Event::MouseMove { .. }
            | Event::MouseButton { .. }
            | Event::ButtonUp { .. }
            | Event::Wheel { .. }
    )
}

fn to_key_event(e: KeyboardEvent) -> Event {
    match e {
        KeyboardEvent::Pressed { code, extended } => Event::KeyPressed { code, extended },
        KeyboardEvent::Released { code, extended } => Event::KeyReleased { code, extended },
        KeyboardEvent::UnicodePressed(u) => Event::UnicodePressed(u),
        KeyboardEvent::UnicodeReleased(u) => Event::UnicodeReleased(u),
        KeyboardEvent::Synchronize(flags) => Event::Synchronize {
            caps_lock: flags.contains(SynchronizeFlags::CAPS_LOCK),
        },
    }
}

fn to_mouse_event(e: MouseEvent) -> Option<Event> {
    match e {
        MouseEvent::Move { x, y } => Some(Event::MouseMove { x, y }),
        // The click's own position rides on the button event (D8d): a
        // click with no prior move goes where it was made, never (0, 0).
        MouseEvent::Button {
            x,
            y,
            button,
            pressed,
        } => button_for(button).map(|b| Event::MouseButton {
            button: b,
            pressed,
            x,
            y,
        }),
        MouseEvent::VerticalScroll { value } => Some(Event::Wheel { units: value }),
        // PD9 review I4 (controller ruling 3): a release is honoured from
        // any event — a relative one releases where the pointer is.
        MouseEvent::ButtonRel {
            button,
            pressed: false,
            ..
        } => button_for(button).map(|b| Event::ButtonUp { button: b }),
        // DD7: relative motion and presses, horizontal and ainput scroll
        // are dropped and counted by the caller.
        _ => None,
    }
}

fn button_for(b: MouseButton) -> Option<Button> {
    match b {
        MouseButton::Left => Some(Button::Left),
        MouseButton::Right => Some(Button::Right),
        MouseButton::Middle => Some(Button::Middle),
        _ => None, // X1, X2 and any later button (DD7); `MouseButton` is #[non_exhaustive]
    }
}

/// IronRDP's input handler: it only feeds `InputShared` (never blocks the
/// RDP runtime, §4.3), and only on the RDP thread — a call from any other
/// (IronRDP's ainput DVC runs it in `spawn_blocking`, I1) is dropped and
/// counted.
pub struct InputHandler {
    shared: Arc<InputShared>,
}

impl InputHandler {
    #[must_use]
    pub fn new(shared: Arc<InputShared>) -> InputHandler {
        InputHandler { shared }
    }

    fn admitted(&self) -> bool {
        let on = self.shared.on_rdp_thread();
        if !on {
            self.shared.metrics.input_events_ignored.inc();
        }
        on
    }
}

impl RdpServerInputHandler for InputHandler {
    fn keyboard(&mut self, event: KeyboardEvent) {
        if self.admitted() {
            self.shared.keyboard(event);
        }
    }
    fn mouse(&mut self, event: MouseEvent) {
        if self.admitted() {
            self.shared.mouse(event);
        }
    }
}

#[cfg(test)]
impl InputRuntimeConfig {
    pub fn test() -> Self {
        Self {
            mac_remap: false,
            key_repeat_timeout: Duration::from_secs(10),
            modifier_idle_timeout: Duration::from_secs(30),
            chord: Chord::parse("ctrl+option+shift+v").unwrap_or(Chord {
                classes: 0x07,
                code: 0x2F,
            }),
            pace: Duration::ZERO,
            modifier_wait: Duration::from_secs(5),
            multiline_refuse: false,
            max_chars: 4096,
        }
    }
}

#[cfg(test)]
impl InputShared {
    pub(crate) fn hid_for_test(&self) -> &HidControl {
        &self.hid
    }

    pub(crate) fn metrics_for_test(&self) -> &Metrics {
        &self.metrics
    }

    /// The `ServerEvent` cell this shell sends its clipboard requests on.
    pub(crate) fn events_for_test(&self) -> &ServerEvents {
        &self.events
    }

    /// The thread `bind_rdp_thread` recorded.
    pub(crate) fn rdp_thread_for_test(&self) -> Option<ThreadId> {
        self.rdp_thread.get().copied()
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
    use crate::hid::ReleaseTrigger;
    use crate::msg::{Generations, KvmCommand, RdpInput};
    use crate::rdp::accept::{AcceptRate, HANDSHAKE_GRACE, Handshakes};
    use crate::rdp::clipboard::{ClipSlot, ServerEvents};
    use crate::rdp::gfx::GfxSlot;
    use crate::rdp::handler::Lifecycle;
    use ironrdp_server::ConnectionHandler as _;
    use kvm_proto::hid::HidFrame;
    use std::sync::atomic::AtomicBool;
    use tokio::sync::mpsc;
    use tokio::task::LocalSet;

    fn shared() -> Arc<InputShared> {
        let metrics = Arc::new(Metrics::default());
        let hid = Arc::new(HidControl::new(256, metrics.clone()));
        let gens = Arc::new(Generations::default());
        gens.begin();
        let display = DisplayShared::new((1920, 1080));
        Arc::new(InputShared::new(InputDeps {
            hid,
            display,
            events: ServerEvents::default(),
            gens: gens.clone(),
            metrics,
            cfg: InputRuntimeConfig::test(),
        }))
    }
    fn drain(h: &HidControl) -> Vec<HidFrame> {
        std::iter::from_fn(|| h.next_frame()).collect()
    }

    /// A scancode press and release reach the HID queue as §3.3 frames,
    /// stamped at the live epoch; every event counts, none is "ignored".
    #[tokio::test(flavor = "current_thread")]
    async fn a_keypress_reaches_the_hid_queue() {
        let s = shared();
        s.set_generation(1);
        s.keyboard(KeyboardEvent::Pressed {
            code: 0x1E,
            extended: false,
        });
        s.mouse(MouseEvent::Move { x: 960, y: 540 });
        s.keyboard(KeyboardEvent::Released {
            code: 0x1E,
            extended: false,
        });
        let got = drain(s.hid_for_test());
        assert_eq!(
            got[0],
            HidFrame::Keyboard {
                modifiers: 0,
                keys: [0x04, 0, 0, 0, 0]
            }
        );
        // 960·32767/1919 and 540·32767/1079 (§7.2, D2a).
        assert!(got.iter().any(|f| matches!(
            f,
            HidFrame::AbsMouse {
                x: 16_392,
                y: 16_398,
                ..
            }
        )));
        assert_eq!(
            got.last(),
            Some(&HidFrame::Keyboard {
                modifiers: 0,
                keys: [0; 5]
            })
        );
        assert_eq!(s.metrics_for_test().input_events_ignored.get(), 0);
    }

    /// DD7: a relative or horizontal-scroll event is dropped and counted.
    #[tokio::test(flavor = "current_thread")]
    async fn unmapped_mouse_events_are_counted_not_mapped() {
        let s = shared();
        s.set_generation(1);
        s.mouse(MouseEvent::RelMove { x: 3, y: 4 });
        s.mouse(MouseEvent::HorizontalScroll { value: 120 });
        assert_eq!(s.metrics_for_test().input_events_ignored.get(), 2);
        assert!(drain(s.hid_for_test()).is_empty());
    }

    /// DD7 (D8f): an unmapped scancode is dropped by the core and counted
    /// by the shell.
    #[tokio::test(flavor = "current_thread")]
    async fn an_unmapped_scancode_is_counted() {
        let s = shared();
        s.set_generation(1);
        s.keyboard(KeyboardEvent::Pressed {
            code: 0x54,
            extended: false,
        });
        assert_eq!(s.metrics_for_test().input_events_ignored.get(), 1);
        assert!(drain(s.hid_for_test()).is_empty());
    }

    /// D8d: a click goes where it was made, with no prior move.
    #[tokio::test(flavor = "current_thread")]
    async fn a_click_carries_its_own_position() {
        let s = shared();
        s.set_generation(1);
        s.mouse(MouseEvent::Button {
            x: 960,
            y: 540,
            button: MouseButton::Left,
            pressed: true,
        });
        assert_eq!(
            drain(s.hid_for_test()),
            [HidFrame::AbsMouse {
                buttons: 1,
                x: 16_392,
                y: 16_398
            }]
        );
    }

    /// A new generation resets the core, and a release the shell did (an
    /// epoch bump) still lands: a held key does not survive into the new
    /// session.
    #[tokio::test(flavor = "current_thread")]
    async fn a_release_all_from_the_shell_clears_held_state() {
        let s = shared();
        s.set_generation(1);
        s.keyboard(KeyboardEvent::Pressed {
            code: 0x1E,
            extended: false,
        });
        s.hid_for_test()
            .release_all(ReleaseTrigger::WebsocketReconnect);
        let _ = drain(s.hid_for_test());
        // The held 'a' is now released-by-bridge: its repeat is swallowed.
        s.keyboard(KeyboardEvent::Pressed {
            code: 0x1E,
            extended: false,
        });
        assert!(
            drain(s.hid_for_test())
                .iter()
                .all(|f| !matches!(f, HidFrame::Keyboard { keys, .. } if keys[0] == 0x04))
        );
    }

    /// Paste metrics: a chord with text available counts `started`.
    #[tokio::test(flavor = "current_thread")]
    async fn a_paste_counts_its_outcome() {
        let s = shared();
        s.set_generation(1);
        s.clipboard_available(true);
        for code in [0x1D, 0x38, 0x2A, 0x2F] {
            s.keyboard(KeyboardEvent::Pressed {
                code,
                extended: false,
            });
        }
        assert_eq!(s.metrics_for_test().paste_events.get("started"), 1);
    }

    // ---- The PD9 carries.

    struct Rig {
        s: Arc<InputShared>,
        hid: Arc<HidControl>,
        gens: Arc<Generations>,
        metrics: Arc<Metrics>,
        /// What the shell sent IronRDP (the `ServerEvents` cell's sender).
        server: mpsc::UnboundedReceiver<ServerEvent>,
        /// The KVM's keyboard and buttons, as the writer leaves them.
        kbd: Option<HidFrame>,
        buttons: u8,
    }

    fn rig() -> Rig {
        rig_with_queue(256)
    }

    /// `input.queue = n`.
    fn rig_with_queue(n: usize) -> Rig {
        let metrics = Arc::new(Metrics::default());
        let hid = Arc::new(HidControl::new(n, metrics.clone()));
        let gens = Arc::new(Generations::default());
        let events = ServerEvents::default();
        let (tx, server) = mpsc::unbounded_channel();
        events.set(tx).unwrap();
        let s = Arc::new(InputShared::new(InputDeps {
            hid: hid.clone(),
            display: DisplayShared::new((1920, 1080)),
            events,
            gens: gens.clone(),
            metrics: metrics.clone(),
            cfg: InputRuntimeConfig::test(),
        }));
        s.bind_rdp_thread(); // the test thread plays the RDP thread
        Rig {
            s,
            hid,
            gens,
            metrics,
            server,
            kbd: None,
            buttons: 0,
        }
    }

    const fn kbd(modifiers: u8, k: u8) -> HidFrame {
        HidFrame::Keyboard {
            modifiers,
            keys: [k, 0, 0, 0, 0],
        }
    }

    const KBD_ZERO: HidFrame = kbd(0, 0);

    /// The chord's keys: Ctrl, Alt (Option), Shift, then V.
    const CHORD: [u8; 4] = [0x1D, 0x38, 0x2A, 0x2F];

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    impl Rig {
        /// `on_connection_info`'s pair (handler.rs): a generation begins,
        /// then the release; then the shell's `SessionStart` word.
        fn start(&self) -> Gen {
            let g = self.gens.begin();
            self.hid.release_all(ReleaseTrigger::SessionStart);
            self.s.set_generation(g);
            g
        }
        /// `on_disconnected`'s pair: the generation ends, then the release.
        fn end(&self) {
            self.gens.end();
            self.hid.release_all(ReleaseTrigger::SessionEnd);
        }
        fn press(&self, code: u8) {
            self.s.keyboard(KeyboardEvent::Pressed {
                code,
                extended: false,
            });
        }
        fn release(&self, code: u8) {
            self.s.keyboard(KeyboardEvent::Released {
                code,
                extended: false,
            });
        }
        fn chord(&self) {
            for c in CHORD {
                self.press(c);
            }
        }
        fn unchord(&self) {
            for c in CHORD.iter().rev() {
                self.release(*c);
            }
        }
        /// What the writer would write now, in its order (a pending release
        /// first, then the queue), applied to the KVM's state; the frames.
        fn write(&mut self) -> Vec<HidFrame> {
            let mut out = Vec::new();
            loop {
                if self.hid.take_release() {
                    out.extend(self.hid.release_frames());
                } else if let Some(f) = self.hid.next_frame() {
                    out.push(f);
                } else {
                    break;
                }
            }
            for f in &out {
                self.hid.note_sent(f);
                match *f {
                    HidFrame::Keyboard { .. } => self.kbd = Some(*f),
                    HidFrame::AbsMouse { buttons, .. } | HidFrame::Wheel { buttons, .. } => {
                        self.buttons = buttons;
                    }
                    HidFrame::SetMode { .. } => {}
                }
            }
            out
        }
        fn holds_nothing(&mut self) -> bool {
            let _ = self.write();
            self.kbd.is_none_or(|k| k == KBD_ZERO) && self.buttons == 0
        }
        /// Tick until the paste ends (pace 0: the queue's room paces it,
        /// and a step that found none looks again `ROOM_POLL` later),
        /// draining the queue as the writer would; the usages typed. Real
        /// time, or the paused clock auto-advancing.
        async fn type_out(&mut self) -> Vec<u8> {
            let ended = |m: &Metrics| m.paste_events.get("done") + m.paste_events.get("aborted");
            let before = ended(&self.metrics);
            let mut typed = Vec::new();
            for _ in 0..64 {
                for f in self.write() {
                    if let HidFrame::Keyboard { keys, .. } = f
                        && keys[0] != 0
                    {
                        typed.push(keys[0]);
                    }
                }
                if ended(&self.metrics) > before {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(3)).await;
                self.s.feed(Event::Tick);
            }
            typed
        }
        fn requests(&mut self) -> usize {
            let mut n = 0;
            while let Ok(e) = self.server.try_recv() {
                assert!(
                    matches!(
                        e,
                        ServerEvent::Clipboard(ClipboardMessage::SendInitiatePaste(f))
                            if f == ClipboardFormatId::CF_UNICODETEXT
                    ),
                    "the input shell sent something other than a paste request"
                );
                n += 1;
            }
            n
        }
    }

    /// PD9 carry 1 (PD6 m2): an event that arrives after a deadline the
    /// driver has not ticked yet steps that Tick first, carries out its
    /// release (the epoch moves), and only then steps the event, at the new
    /// epoch. The timer fires on time, and the fresh press lands: stepped
    /// with the Tick under one epoch read it would carry the pre-release
    /// stamp, `push_at` would drop it, and the next step would mark the key
    /// released-by-bridge.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_late_event_steps_the_due_tick_first() {
        let mut r = rig();
        r.start();
        r.press(0x1E); // 'a' held, then nothing: key_repeat_timeout is 10 s
        let _ = r.write(); // an empty queue: any discard below is push_at's
        tokio::time::advance(Duration::from_secs(10)).await;
        r.press(0x30); // 'b', after the deadline, before any driver Tick
        assert_eq!(
            r.metrics.release_all.get("key_repeat"),
            1,
            "the due timer did not fire before the event"
        );
        assert_eq!(
            r.metrics.hid_epoch_discards.get(),
            0,
            "the press was stamped before the release"
        );
        let _ = r.write();
        assert_eq!(r.kbd, Some(kbd(0, 0x05)), "'b' alone is down");
        // 'b' is a key the client holds, not one the bridge released.
        r.release(0x30);
        assert!(r.holds_nothing());
        r.press(0x30);
        let _ = r.write();
        assert_eq!(r.kbd, Some(kbd(0, 0x05)));
    }

    /// The driver ticks the core at its next deadline with no event to
    /// bring it — and not before (§7.4's timers are the driver's).
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn the_driver_fires_a_timer_at_its_deadline() {
        LocalSet::new()
            .run_until(async {
                let mut r = rig();
                r.start();
                tokio::task::spawn_local(r.s.clone().run_driver());
                r.press(0x1E);
                tokio::time::sleep(Duration::from_millis(9_990)).await;
                assert_eq!(r.metrics.release_all.get("key_repeat"), 0, "early");
                tokio::time::sleep(Duration::from_millis(20)).await;
                assert_eq!(r.metrics.release_all.get("key_repeat"), 1);
                assert!(r.holds_nothing());
                // Re-armed by a later press, after the driver slept on
                // nothing armed.
                r.release(0x1E);
                tokio::time::sleep(Duration::from_secs(60)).await;
                r.press(0x30);
                tokio::time::sleep(Duration::from_millis(10_010)).await;
                assert_eq!(r.metrics.release_all.get("key_repeat"), 2);
                assert!(r.holds_nothing());
            })
            .await;
    }

    /// The driver types a paste at pace 0 as the writer drains the queue
    /// (DD6: never more than the queue's room), and the paste completes.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn the_driver_types_a_paste_as_the_queue_drains() {
        LocalSet::new()
            .run_until(async {
                // The least queue config allows (carry 5): typing never
                // overflows it.
                let mut r = rig_with_queue(TYPIST_ROOM + 1);
                r.start();
                tokio::task::spawn_local(r.s.clone().run_driver());
                r.s.clipboard_available(true);
                r.chord();
                assert_eq!(r.requests(), 1);
                r.s.clipboard_text(utf16("hello world"));
                r.unchord();
                let mut typed = Vec::new();
                for _ in 0..200 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    assert!(r.hid.queued() <= TYPIST_ROOM + 1, "past DD6's budget");
                    for f in r.write() {
                        if let HidFrame::Keyboard { keys, .. } = f
                            && keys[0] != 0
                        {
                            typed.push(keys[0]);
                        }
                    }
                    if r.metrics.paste_events.get("done") == 1 {
                        break;
                    }
                }
                assert_eq!(r.metrics.paste_events.get("done"), 1);
                assert_eq!(
                    typed,
                    [
                        0x0B, 0x08, 0x0F, 0x0F, 0x12, 0x2C, 0x1A, 0x12, 0x15, 0x0F, 0x07
                    ]
                );
                assert_eq!(
                    r.metrics.hid_resyncs.get(),
                    0,
                    "typing overflowed the queue"
                );
                assert!(r.holds_nothing());
            })
            .await;
    }

    /// PD9 carry 2 (PD7): a session change ends an active paste, and its
    /// outcome is counted (`aborted`), not dropped.
    #[tokio::test(flavor = "current_thread")]
    async fn a_session_ending_mid_paste_counts_it() {
        let r = rig();
        r.start();
        r.s.clipboard_available(true);
        r.chord();
        assert_eq!(r.metrics.paste_events.get("started"), 1);
        r.end();
        r.s.set_generation(0); // the shell's SessionStop
        assert_eq!(r.metrics.paste_events.get("aborted"), 1);
        assert_eq!(r.metrics.paste_events.total(), 2);
        // Typing, too.
        r.start();
        r.s.clipboard_available(true);
        r.chord();
        r.s.clipboard_text(utf16("abcdefghijklmnopqrstuvwxyz"));
        r.unchord();
        assert!(
            r.metrics.paste_events.get("done") == 0,
            "typed it all at once"
        );
        let g = r.gens.begin(); // Preempt: the winner's on_connection_info
        r.hid.release_all(ReleaseTrigger::SessionStart);
        r.s.set_generation(g);
        assert_eq!(r.metrics.paste_events.get("aborted"), 2);
    }

    /// PD9 carry 2 (PD6 m3): `on_generation` drops the core's state with
    /// no release of its own. The handler's release always comes with a
    /// generation change — here the real `Lifecycle::on_disconnected` —
    /// so the KVM holds nothing after it, and the shell adds no second
    /// release.
    #[tokio::test(flavor = "current_thread")]
    async fn the_handlers_release_comes_with_a_generation_change() {
        let mut r = rig();
        let (to_pump, mut pump) = mpsc::unbounded_channel();
        let (to_kvm, _kvm) = mpsc::unbounded_channel::<KvmCommand>();
        let mut lifecycle = Lifecycle {
            gens: r.gens.clone(),
            accepting: Arc::new(AtomicBool::new(true)),
            rate: AcceptRate::new(30, Duration::from_secs(60)),
            gfx: GfxSlot::default(),
            clip: ClipSlot::default(),
            hid: r.hid.clone(),
            metrics: r.metrics.clone(),
            to_pump,
            to_kvm,
            handshakes: Arc::new(Handshakes::new(HANDSHAKE_GRACE)),
        };
        let g = r.start();
        r.press(0x1D); // Ctrl
        r.press(0x2E); // C
        r.s.mouse(MouseEvent::Button {
            x: 5,
            y: 5,
            button: MouseButton::Left,
            pressed: true,
        });
        let _ = r.write();
        assert_eq!(r.kbd, Some(kbd(0x01, 0x06)));
        let _ = lifecycle.on_disconnected("127.0.0.2:5".parse().unwrap(), Duration::ZERO, None);
        assert!(matches!(
            pump.try_recv(),
            Ok(RdpInput::SessionStop { generation }) if generation == g
        ));
        // The handler released before the shell heard of it.
        assert_eq!(r.metrics.release_all.get("session_end"), 1);
        r.s.set_generation(0);
        assert_eq!(
            r.metrics.release_all.total(),
            2,
            "start, end: no second release"
        );
        assert!(r.holds_nothing());
        // The next session starts clean: a press is a press.
        r.start();
        r.press(0x2E);
        let _ = r.write();
        assert_eq!(r.kbd, Some(kbd(0, 0x06)));
    }

    /// PD9 carry 2 (PD6 m3), enforced: a generation change that came with
    /// no release (none does today) still leaves the KVM holding nothing —
    /// the shell releases what the core is about to forget.
    #[tokio::test(flavor = "current_thread")]
    async fn a_generation_change_without_a_release_still_releases() {
        let mut r = rig();
        r.start();
        r.press(0x1E);
        r.s.mouse(MouseEvent::Button {
            x: 5,
            y: 5,
            button: MouseButton::Right,
            pressed: true,
        });
        r.gens.end(); // and no release
        r.s.set_generation(0);
        assert_eq!(r.metrics.release_all.get("session_end"), 1);
        assert!(r.holds_nothing());
        let g = r.gens.begin(); // and no release
        r.s.set_generation(g);
        r.press(0x1E);
        r.gens.begin(); // a newer one, with 'a' held: no release either
        r.press(0x30); // the core follows it at once
        assert_eq!(r.metrics.release_all.get("session_start"), 2);
        let _ = r.write();
        assert_eq!(r.kbd, Some(kbd(0, 0x05)), "'a' was released");
    }

    /// The core follows the live generation, not the shell's word: a
    /// `SessionStop` the shell reads after the next session's input began
    /// (Preempt: the winner's keys come straight from IronRDP) must not
    /// reset the new session's keys — 'b' would be forgotten while down on
    /// the KVM, and its release would send nothing.
    #[tokio::test(flavor = "current_thread")]
    async fn a_stale_session_word_never_resets_a_newer_session() {
        let mut r = rig();
        r.start();
        r.press(0x1E);
        r.end();
        let g2 = r.gens.begin();
        r.hid.release_all(ReleaseTrigger::SessionStart);
        r.press(0x30); // the winner's 'b'
        r.s.set_generation(0); // the loser's SessionStop, read late
        r.s.set_generation(1); // even a stale start
        r.s.set_generation(g2);
        let _ = r.write();
        assert_eq!(r.kbd, Some(kbd(0, 0x05)));
        r.release(0x30);
        assert!(r.holds_nothing(), "'b' was forgotten while down");
    }

    /// PD9 carry 3 (a): an answer is the paste's only if that paste asked
    /// for it. A paste that timed out leaves its request outstanding; its
    /// late answer, coming after the next paste asked, is discarded and
    /// counted — never typed by the next paste — and the next answer is
    /// the next paste's.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_late_answer_is_never_typed_by_the_next_paste() {
        let mut r = rig();
        r.start();
        r.s.clipboard_available(true);
        r.chord();
        tokio::time::advance(Duration::from_secs(5)).await; // modifier_wait
        r.unchord(); // the due Tick first: the paste ends unanswered
        assert_eq!(r.metrics.paste_events.get("aborted"), 1);
        r.chord();
        assert_eq!(r.requests(), 2);
        r.s.clipboard_text(utf16("old"));
        assert_eq!(r.metrics.clipboard_discarded.get("late"), 1);
        r.s.clipboard_text(utf16("ok"));
        r.unchord();
        assert_eq!(r.type_out().await, [0x12, 0x0E]);
        assert_eq!(r.metrics.paste_events.get("done"), 1);
        assert!(r.holds_nothing());
        // A new generation starts its count afresh: its first answer is its
        // first paste's (gen 1's outstanding requests died with it).
        r.chord();
        r.end();
        r.start();
        r.s.clipboard_available(true);
        r.unchord();
        r.chord();
        r.s.clipboard_text(utf16("k"));
        r.unchord();
        assert_eq!(r.type_out().await, [0x0E]);
        assert_eq!(r.metrics.clipboard_discarded.get("late"), 1);
    }

    /// PD9 carry 3 (b): a failed answer (`ClipboardFailed`) ends the paste
    /// that asked at once, not after `modifier_wait`; a failure nobody is
    /// waiting for is discarded.
    #[tokio::test(flavor = "current_thread")]
    async fn a_failed_answer_ends_the_waiting_paste_at_once() {
        let mut r = rig();
        r.start();
        r.s.clipboard_available(true);
        r.chord();
        r.s.clipboard_failed();
        assert_eq!(r.metrics.paste_events.get("aborted"), 1);
        r.s.clipboard_text(utf16("x"));
        r.s.clipboard_failed();
        assert_eq!(r.metrics.clipboard_discarded.get("unasked"), 2);
        r.unchord();
        assert!(r.holds_nothing());
    }

    /// PD9 carry 3 (c): an answer nobody asked for is discarded and
    /// counted; it is not kept for the next paste.
    #[tokio::test(flavor = "current_thread")]
    async fn an_unasked_answer_is_discarded_and_counted() {
        let mut r = rig();
        r.start();
        r.s.clipboard_available(true);
        r.s.clipboard_text(utf16("zz"));
        assert_eq!(r.metrics.clipboard_discarded.get("unasked"), 1);
        r.chord();
        r.unchord();
        r.s.feed(Event::Tick);
        assert!(r.type_out().await.is_empty(), "the unasked text was kept");
        r.s.clipboard_text(utf16("hi"));
        assert_eq!(r.type_out().await, [0x0B, 0x0C]);
    }

    /// PD9 carry 3 (m2), the shell's half: answers the backend dropped
    /// while one was in flight are counted (`in_flight`) and still count
    /// as answers — the paste one of them answered ends at once, and the
    /// next paste's answer is its own.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn answers_lost_in_flight_are_counted_as_answers() {
        let mut r = rig();
        r.start();
        r.s.clipboard_available(true);
        r.chord();
        tokio::time::advance(Duration::from_secs(5)).await;
        r.unchord(); // paste 1 ends unanswered
        r.chord(); // paste 2 asks
        // Paste 1's answer arrives, and paste 2's is dropped behind it.
        r.s.clipboard_text(utf16("old"));
        r.s.clipboard_lost(1);
        assert_eq!(r.metrics.clipboard_discarded.get("late"), 1);
        assert_eq!(r.metrics.clipboard_discarded.get("in_flight"), 1);
        assert_eq!(r.metrics.paste_events.get("aborted"), 2);
        r.unchord();
        r.chord();
        r.s.clipboard_lost(0);
        r.s.clipboard_text(utf16("k"));
        r.unchord();
        assert_eq!(r.type_out().await, [0x0E]);
    }

    /// A clipboard request goes to IronRDP once per paste, and only for the
    /// current generation (§4.3).
    #[tokio::test(flavor = "current_thread")]
    async fn a_paste_request_goes_out_for_the_current_generation_only() {
        let mut r = rig();
        r.start();
        r.s.clipboard_available(true);
        r.chord();
        assert_eq!(r.requests(), 1);
        r.release(0x2F);
        r.press(0x2F); // a second chord meanwhile: swallowed, no request
        assert_eq!(r.requests(), 0);
        r.unchord();
        r.end();
        r.chord(); // no session: nothing is stepped or sent
        assert_eq!(r.requests(), 0);
        assert_eq!(r.metrics.paste_events.get("started"), 1);
    }

    /// The oversize answer the shell steps as a fatal (§8) ends the paste
    /// that asked for it as `oversize`.
    #[tokio::test(flavor = "current_thread")]
    async fn an_oversize_answer_ends_the_paste_as_oversize() {
        let r = rig();
        r.start();
        r.s.clipboard_available(true);
        r.chord();
        r.s.clipboard_oversize();
        assert_eq!(r.metrics.paste_events.get("oversize"), 1);
        assert_eq!(r.metrics.paste_events.total(), 2);
    }

    /// PD9 carry 6 (§4.5, §9.2): nothing the input path does logs a
    /// keystroke, a frame or pasted text — at TRACE, the only line is the
    /// no-text paste's, which names no content.
    #[test]
    fn the_input_path_logs_no_input() {
        #[derive(Clone, Default)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Buf::default();
        let writer = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish();
        let canary = "SNTLpaste7qZq";
        // A current-thread runtime runs on this thread: the subscriber,
        // this thread's default, sees all of it.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        tracing::subscriber::with_default(subscriber, || {
            rt.block_on(async {
                let mut r = rig();
                r.start();
                r.chord(); // no text offered yet: the one log line
                r.unchord();
                r.s.clipboard_available(true);
                r.chord();
                r.s.clipboard_text(utf16(canary));
                r.unchord();
                let _ = r.type_out().await;
                r.s.clipboard_text(utf16(canary));
                for code in [0x1E, 0x30, 0x2E, 0x54] {
                    r.press(code);
                    r.release(code);
                }
                r.s.mouse(MouseEvent::Move { x: 777, y: 333 });
                r.s.keyboard(KeyboardEvent::UnicodePressed(0x51));
                r.s.keyboard(KeyboardEvent::UnicodeReleased(0x51));
            })
        });
        let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1, "{text}");
        assert!(lines[0].contains("paste chord with no text"), "{text}");
        // The canary as its UTF-16 bytes, decimal and hex, as a `?bytes`
        // field would show them.
        let (dec, hex) = (
            format!("{:?}", &utf16(canary)[..8]),
            format!("{:02x?}", &utf16(canary)[..8]),
        );
        let bytes = [dec.trim_matches(['[', ']']), hex.trim_matches(['[', ']'])];
        for needle in [canary, "Keyboard", "AbsMouse", "777", "333", "0x1e", "0x04"]
            .into_iter()
            .chain(bytes)
        {
            assert!(!text.contains(needle), "{needle} in {text}");
        }
    }

    // ---- PD9 fix round 1.

    /// I1(b), the review's X3 stress: two threads feed at once — the
    /// driver ticking a 2 080-character paste at pace 0, and a click from
    /// another thread that aborts it — while a writer thread drains the
    /// queue in order. A step's outputs are carried out under the core
    /// lock, so a Typist press one step built never lands after another
    /// step's abort zero: in 2 000 runs, none ends with a key down (before
    /// the fix, 100–106 did, with no timer armed to release it).
    #[test]
    fn feeds_from_two_threads_never_leave_a_key_down() {
        use std::sync::atomic::{AtomicBool, Ordering};
        const RUNS: usize = 2_000;
        let text = utf16(&"abcdefghijklmnopqrstuvwxyz".repeat(80));
        let mut held = 0usize;
        for run in 0..RUNS {
            let r = rig();
            r.start();
            r.s.clipboard_available(true);
            r.chord();
            r.s.clipboard_text(text.clone());
            r.unchord(); // typing begins
            let stop = Arc::new(AtomicBool::new(false));
            let ended = Arc::new(AtomicBool::new(false));
            let writer = {
                let (hid, stop) = (r.hid.clone(), stop.clone());
                std::thread::spawn(move || {
                    let mut kbd = None;
                    loop {
                        let f = if hid.take_release() {
                            hid.release_frames()
                        } else if let Some(f) = hid.next_frame() {
                            vec![f]
                        } else if stop.load(Ordering::SeqCst) {
                            break;
                        } else {
                            std::thread::yield_now();
                            continue;
                        };
                        for f in f {
                            hid.note_sent(&f);
                            if matches!(f, HidFrame::Keyboard { .. }) {
                                kbd = Some(f);
                            }
                        }
                    }
                    kbd
                })
            };
            let driver = {
                let (s, ended) = (r.s.clone(), ended.clone());
                std::thread::spawn(move || {
                    while !ended.load(Ordering::SeqCst) {
                        s.feed(Event::Tick);
                    }
                })
            };
            let sent = 2 + u64::try_from(run % 40).unwrap();
            let t0 = std::time::Instant::now();
            while r.metrics.hid_reports_sent.get() < sent && t0.elapsed() < Duration::from_secs(5) {
                std::thread::yield_now();
            }
            r.s.mouse(MouseEvent::Button {
                x: 5,
                y: 5,
                button: MouseButton::Left,
                pressed: true,
            });
            r.s.mouse(MouseEvent::Button {
                x: 5,
                y: 5,
                button: MouseButton::Left,
                pressed: false,
            });
            let ended_paste =
                || r.metrics.paste_events.get("aborted") + r.metrics.paste_events.get("done") > 0;
            while !ended_paste() && t0.elapsed() < Duration::from_secs(10) {
                std::thread::yield_now();
            }
            assert!(ended_paste(), "run {run}: the paste never ended");
            ended.store(true, Ordering::SeqCst);
            driver.join().unwrap();
            stop.store(true, Ordering::SeqCst);
            let kbd = writer.join().unwrap();
            if kbd.is_some_and(|k| k != KBD_ZERO) {
                held += 1;
            }
        }
        assert_eq!(held, 0, "{held} of {RUNS} runs ended with a key down");
    }

    /// I1(a): IronRDP's ainput DVC calls the handler from `spawn_blocking`,
    /// off the RDP thread, one task per PDU in no order. Such a call is
    /// dropped and counted (`input_events_ignored`), and pushes nothing; on
    /// the RDP thread the handler works as ever.
    #[tokio::test(flavor = "current_thread")]
    async fn handler_calls_off_the_rdp_thread_are_dropped() {
        let mut r = rig();
        r.start();
        let mut off = InputHandler::new(r.s.clone());
        std::thread::spawn(move || {
            off.mouse(MouseEvent::Button {
                x: 5,
                y: 5,
                button: MouseButton::Left,
                pressed: true,
            });
            off.keyboard(KeyboardEvent::Pressed {
                code: 0x1E,
                extended: false,
            });
        })
        .join()
        .unwrap();
        assert_eq!(r.metrics.input_events_ignored.get(), 2);
        // Only the session start's release went out: no click, no key.
        assert_eq!(r.write(), [KBD_ZERO], "an off-thread call pushed");
        let mut on = InputHandler::new(r.s.clone());
        on.keyboard(KeyboardEvent::Pressed {
            code: 0x1E,
            extended: false,
        });
        assert_eq!(r.write().last(), Some(&kbd(0, 0x04)));
        assert_eq!(r.metrics.input_events_ignored.get(), 2);
    }

    /// I2 (a), the review's X1 through the shell: one request is never
    /// answered; five pastes ten minutes apart, each answered at once, all
    /// type (before, all five were discarded as `late`). The stale request
    /// is retired once, counted `unanswered`.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_request_never_answered_does_not_break_later_pastes() {
        let mut r = rig();
        r.start();
        r.s.clipboard_available(true);
        r.chord();
        tokio::time::advance(Duration::from_secs(5)).await;
        r.unchord(); // paste 1 ends unanswered; its answer never comes
        for n in 0..5 {
            tokio::time::advance(Duration::from_secs(600)).await;
            r.chord();
            r.s.clipboard_text(utf16("ok"));
            r.unchord();
            assert_eq!(r.type_out().await, [0x12, 0x0E], "paste {n}");
        }
        assert_eq!(r.metrics.paste_events.get("done"), 5);
        assert_eq!(r.metrics.clipboard_discarded.get("unanswered"), 1);
        assert_eq!(r.metrics.clipboard_discarded.get("late"), 0);
    }

    fn rel(button: MouseButton, pressed: bool) -> MouseEvent {
        MouseEvent::ButtonRel {
            x: 3,
            y: -4,
            button,
            pressed,
        }
    }

    /// I4 (controller ruling 3): a button pressed with an absolute event
    /// and released with a relative one ends released on the KVM — at the
    /// pointer's place, the relative delta ignored (DD7) — and the release
    /// is not counted as dropped.
    #[tokio::test(flavor = "current_thread")]
    async fn a_relative_release_ends_an_absolute_press() {
        let mut r = rig();
        r.start();
        r.s.mouse(MouseEvent::Button {
            x: 960,
            y: 540,
            button: MouseButton::Left,
            pressed: true,
        });
        let _ = r.write();
        assert_eq!(r.buttons, 1);
        r.s.mouse(rel(MouseButton::Left, false));
        assert_eq!(
            r.write(),
            [HidFrame::AbsMouse {
                buttons: 0,
                x: 16_392,
                y: 16_398
            }]
        );
        assert_eq!(r.metrics.input_events_ignored.get(), 0);
    }

    /// I4: a relative press (and relative motion) stays dropped and counted
    /// (DD7): it pushes nothing; a relative release with nothing held
    /// pushes nothing either.
    #[tokio::test(flavor = "current_thread")]
    async fn a_relative_press_is_dropped() {
        let mut r = rig();
        r.start();
        let _ = r.write();
        r.s.mouse(rel(MouseButton::Left, true));
        r.s.mouse(MouseEvent::RelMove { x: 5, y: 5 });
        assert_eq!(r.metrics.input_events_ignored.get(), 2);
        r.s.mouse(rel(MouseButton::Right, false));
        // No pointer frame (the one zero keyboard report is the session
        // start's epoch step, m4).
        assert_eq!(r.write(), [KBD_ZERO]);
        assert_eq!(r.buttons, 0);
        assert_eq!(r.metrics.input_events_ignored.get(), 2);
    }

    /// I4: a relative release of a button the bridge released clears its
    /// mark, so the next absolute press goes through.
    #[tokio::test(flavor = "current_thread")]
    async fn a_relative_release_clears_a_released_by_bridge_mark() {
        let mut r = rig();
        r.start();
        let down = MouseEvent::Button {
            x: 10,
            y: 10,
            button: MouseButton::Middle,
            pressed: true,
        };
        r.s.mouse(down);
        r.hid.release_all(ReleaseTrigger::Suppression);
        r.s.mouse(MouseEvent::Button {
            x: 10,
            y: 10,
            button: MouseButton::Middle,
            pressed: true,
        }); // a repeat of a released button: nothing
        let _ = r.write();
        assert_eq!(r.buttons, 0);
        r.s.mouse(rel(MouseButton::Middle, false));
        r.s.mouse(MouseEvent::Button {
            x: 10,
            y: 10,
            button: MouseButton::Middle,
            pressed: true,
        });
        let _ = r.write();
        assert_eq!(r.buttons, 0x04, "the fresh press was swallowed");
    }
}
