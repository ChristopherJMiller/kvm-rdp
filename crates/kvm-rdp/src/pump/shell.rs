//! The pump's async shell (§4.3). It owns no timing rule: it feeds the core
//! — RDP-side inputs first, then the 50 ms tick, then this generation's KVM
//! events (`biased`, in that order), sampling the suppression flag and the
//! write counter before each tick and each AU (DC6) — one GFX lock per step,
//! and carries out the commands. Every `ServerEvent`, `Disconnect`
//! included, is sent only for the current generation.
//!
//! DC4's order is decided here. `on_connection_info` pushes `SessionStart`
//! and sends `KvmCommand::Start` on this thread, so both are queued before
//! the shell next runs; a KVM event for the new generation can be queued
//! by then too, and the `biased` select steps the session's start before
//! it.
//!
//! The tick goes ahead of the KVM stream (I1). The KVM is the hostile side,
//! and a stream that never empties must not stop the disconnect watchdog,
//! the stall and IDR timers, the RTT probes or the suppression debounce —
//! all tick-driven. A tick is ready at most once per `TICK`
//! (`MissedTickBehavior::Delay`), so it cannot starve KVM events in turn.
//! It stays behind the RDP side, so a tick never steps an ended
//! generation's link ahead of its queued `SessionStop`.
//!
//! Nothing here holds a lock across an await, and the GFX lock is held only
//! inside `step` — IronRDP's GFX callbacks, which run under it, only push.
use crate::hid::HidControl;
use crate::metrics::Metrics;
use crate::msg::{Cause, Gen, Generations, KvmCommand, KvmEvent, RdpInput};
use crate::pump::core::Pump;
use crate::pump::types::{Command, DvcBatch, Input, PumpConfig};
use crate::rdp::clipboard::fatal_input;
use crate::rdp::display::DisplayShared;
use crate::rdp::gfx::closed_channel_input;
use crate::rdp::input::InputShared;
use ironrdp_dvc::encode_dvc_messages;
use ironrdp_egfx::server::GraphicsPipelineServer;
use ironrdp_server::{ConnectionAbortHandle, EgfxServerMessage, GfxServerHandle, ServerEvent};
use ironrdp_svc::ChannelFlags;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

/// How often the shell samples and ticks the core (DC6).
pub const TICK: Duration = Duration::from_millis(50);
/// §5.2's disconnect watchdog, inside the 5 s exit (DC13).
pub const SHUTDOWN_WATCHDOG: Duration = Duration::from_secs(2);
/// The `Stall` test hook never blocks longer than this.
#[cfg(feature = "test-hooks")]
const MAX_STALL: Duration = Duration::from_secs(30);
/// A held resize re-reads IronRDP's write counter this long after it was
/// held, then twice as long each time, up to `RESIZE_POLL_MAX` (PC17 I4,
/// n1): a client that stopped reading holds the resize for the session's
/// life, and nothing ends a session in WaitReactivation (§6.4).
const RESIZE_POLL: Duration = Duration::from_millis(5);
const RESIZE_POLL_MAX: Duration = Duration::from_millis(250);

pub struct ShellDeps {
    pub cfg: PumpConfig,
    pub metrics: Arc<Metrics>,
    pub gens: Arc<Generations>,
    pub hid: Arc<HidControl>,
    pub display: Arc<DisplayShared>,
    /// The server's event channel (`RdpServer::event_sender`).
    pub events: mpsc::UnboundedSender<ServerEvent>,
    /// `RdpServer`'s display-suppressed flag (§6.6).
    pub suppressed: Arc<AtomicBool>,
    /// `RdpServer`'s auto-detect RTT handle (ms; `u32::MAX` = none).
    pub rtt: Arc<AtomicU32>,
    pub to_kvm: mpsc::UnboundedSender<KvmCommand>,
    /// The input shell (§7, §8): told of each session's start and end, and
    /// fed this session's clipboard words.
    pub input: Arc<InputShared>,
}

/// The live session: what `SessionStart` brought.
struct Link {
    generation: Gen,
    slot: u64,
    gfx: GfxServerHandle,
    counter: Arc<AtomicU64>,
    abort: ConnectionAbortHandle,
    /// This connection's CLIPRDR backend: only its words are this
    /// session's (design decision 8).
    clip_slot: Option<u64>,
    caps: Vec<String>,
    /// The client closed its EGFX channel mid-session (the `no_avc420`
    /// close is then not about its capability sets).
    egfx_closed: bool,
    /// The weight of every EGFX batch sent on this link: once `counter`
    /// reaches it, IronRDP has written them all (PC17 I4).
    sent: u64,
    /// A `DisplayResize` waiting for the EGFX sent before it to be written.
    held_resize: Option<(u16, u16)>,
}

pub struct PumpShell {
    d: ShellDeps,
    pump: Pump,
    link: Option<Link>,
    waiters: Vec<oneshot::Sender<()>>,
    shutting_down: bool,
    /// `SHUTDOWN_WATCHDOG`; scaled down only by tests.
    shutdown_watchdog: Duration,
    /// `TICK`; slowed down only by tests.
    tick_every: Duration,
    /// The held resize's next re-read, backing off (PC17 n1).
    resize_poll: Duration,
    /// The run loop's turns, counted only by tests.
    #[cfg(test)]
    turns: Option<Arc<AtomicU64>>,
}

fn lock(gfx: &GfxServerHandle) -> MutexGuard<'_, GraphicsPipelineServer> {
    gfx.lock().unwrap_or_else(PoisonError::into_inner)
}

impl PumpShell {
    #[must_use]
    pub fn new(deps: ShellDeps) -> PumpShell {
        let pump = Pump::new(deps.cfg.clone(), deps.metrics.clone());
        PumpShell::with_pump(deps, pump)
    }

    #[must_use]
    pub fn with_pump(deps: ShellDeps, pump: Pump) -> PumpShell {
        PumpShell {
            d: deps,
            pump,
            link: None,
            waiters: Vec::new(),
            shutting_down: false,
            shutdown_watchdog: SHUTDOWN_WATCHDOG,
            tick_every: TICK,
            resize_poll: RESIZE_POLL,
            #[cfg(test)]
            turns: None,
        }
    }

    /// A scaled shutdown watchdog, so a test need not wait 2 s.
    #[cfg(test)]
    fn with_shutdown_watchdog(mut self, watchdog: Duration) -> PumpShell {
        self.shutdown_watchdog = watchdog;
        self
    }

    /// A slower tick, so a test can place a burst between two ticks.
    #[cfg(test)]
    fn with_tick(mut self, every: Duration) -> PumpShell {
        self.tick_every = every;
        self
    }

    /// Counts the run loop's turns (one per input, tick or KVM event), so a
    /// test can see an idle shell sleep.
    #[cfg(test)]
    fn with_turns(mut self, turns: Arc<AtomicU64>) -> PumpShell {
        self.turns = Some(turns);
        self
    }

    /// Runs until `rdp` closes. A due tick is taken within one step of its
    /// deadline whatever the KVM stream does; only a backlog of RDP-side
    /// inputs (IronRDP's, on this same thread) goes ahead of it. Inside an
    /// arm the only await is a burst chunk's `yield_now`.
    pub async fn run(
        mut self,
        mut rdp: mpsc::UnboundedReceiver<RdpInput>,
        mut kvm: mpsc::Receiver<KvmEvent>,
    ) {
        let mut tick = tokio::time::interval(self.tick_every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut kvm_open = true;
        loop {
            let had_link = self.link.is_some();
            tokio::select! {
                // RDP, then the tick, then KVM. DC4: a session's start (and
                // an ended one's stop) is stepped before any tick or KVM
                // event queued alongside it. I1: a due tick goes ahead of
                // the KVM stream, which may never empty.
                biased;
                input = rdp.recv() => match input {
                    Some(i) => self.rdp_input(i).await,
                    None => return,
                },
                // PC15 review m2: only while a session lives, so an idle
                // bridge sleeps. Without a link the tick did nothing (the
                // core is Idle), and every timer that ends a close — the
                // disconnect watchdog, §5.2's — runs while its session's
                // link is still here: it goes only with `SessionStop`.
                _ = tick.tick(), if self.link.is_some() => self.tick().await,
                ev = kvm.recv(), if kvm_open => match ev {
                    Some(e) => self.kvm_event(e).await,
                    None => kvm_open = false,
                },
                // PC17 I4: IronRDP's write counter moves without waking this
                // loop; re-read it while a resize is held.
                () = tokio::time::sleep(self.resize_poll), if self.resize_held() => {
                    self.resize_poll = self.resize_poll.saturating_mul(2).min(RESIZE_POLL_MAX);
                }
            }
            // Whatever woke the loop, a held resize goes once IronRDP has
            // written the EGFX sent before it.
            self.release_resize();
            if !had_link && self.link.is_some() {
                // A session began: the next tick is a full period away, not
                // the one overdue since the shell went to sleep.
                tick.reset();
            }
            #[cfg(test)]
            if let Some(t) = &self.turns {
                t.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    /// Step `inputs` in order under one GFX lock hold (§4.3).
    fn step(&mut self, inputs: impl IntoIterator<Item = Input>) -> Vec<Command> {
        let Some(gfx) = self.link.as_ref().map(|l| l.gfx.clone()) else {
            return Vec::new();
        };
        let now = Instant::now();
        let mut g = lock(&gfx);
        let mut out = Vec::new();
        for i in inputs {
            out.extend(self.pump.step(&mut g, now, i));
        }
        out
    }

    fn link_for(&mut self, slot: u64) -> Option<&mut Link> {
        self.link.as_mut().filter(|l| l.slot == slot)
    }

    /// The link whose CLIPRDR backend is `slot`: another connection's
    /// clipboard (a Preempt candidate's, an evicted session's) is never
    /// this session's.
    fn link_for_clip(&self, slot: u64) -> Option<&Link> {
        self.link.as_ref().filter(|l| l.clip_slot == Some(slot))
    }

    /// A clipboard word from `slot` is this session's to act on: the link's
    /// own backend, and its generation still current — the gate `Fatal`
    /// has (§4.3, D17). Another slot's, or an ended session's, is dropped
    /// (its place on the channel freed with it, PD8 review m2).
    fn clip_is_current(&self, slot: u64) -> bool {
        self.link_for_clip(slot)
            .is_some_and(|l| self.d.gens.is_current(l.generation))
    }

    /// The link's generation has ended: `on_disconnected` ran, and its
    /// `SessionStop` is queued behind the input being read.
    fn link_ended(&self) -> bool {
        self.link
            .as_ref()
            .is_some_and(|l| !self.d.gens.is_current(l.generation))
    }

    async fn rdp_input(&mut self, input: RdpInput) {
        match input {
            RdpInput::SessionStart {
                generation,
                slot,
                gfx,
                counter,
                abort,
                clip_slot,
            } => {
                if let Some(old) = self.link.as_ref().map(|l| l.generation) {
                    // `on_disconnected` always comes first; never let two
                    // sessions share a pump.
                    let cmds = self.step([Input::SessionStop { generation: old }]);
                    self.exec(cmds).await;
                    self.end_link();
                    self.d.input.set_generation(0);
                }
                // The input core follows the live generation itself; this
                // is the shell's word that one began (D27).
                self.d.input.set_generation(generation);
                self.link = Some(Link {
                    generation,
                    slot,
                    gfx,
                    counter,
                    abort,
                    clip_slot,
                    caps: Vec::new(),
                    egfx_closed: false,
                    sent: 0,
                    held_resize: None,
                });
                let mut inputs = vec![Input::SessionStart {
                    generation,
                    size: self.d.display.size(),
                }];
                if self.shutting_down {
                    inputs.push(Input::Shutdown {
                        watchdog: self.shutdown_watchdog,
                    });
                }
                let cmds = self.step(inputs);
                self.exec(cmds).await;
            }
            RdpInput::SessionStop { generation } => {
                if self
                    .link
                    .as_ref()
                    .is_some_and(|l| l.generation == generation)
                {
                    let cmds = self.step([Input::SessionStop { generation }]);
                    self.exec(cmds).await;
                    self.end_link();
                    // The core resets (D27); the KVM's release was the
                    // handler's `SessionEnd`.
                    self.d.input.set_generation(0);
                }
            }
            RdpInput::CapsAdvertised { slot, sets } => {
                if let Some(l) = self.link_for(slot) {
                    l.caps = sets;
                }
            }
            RdpInput::OnReady { slot, version } => {
                // PC17: IronRDP can run a re-advertise's `on_ready`, then the
                // teardown's `on_close` and `on_disconnected`, before the
                // shell reads any of them. The Setup this would run meets
                // the closed channel, which IronRDP refuses (m7), and would
                // count a `no_avc420` disconnect for a session the client
                // ended. An ended generation runs no Setup.
                if self.link_for(slot).is_none() || self.link_ended() {
                    return;
                }
                self.d
                    .metrics
                    .egfx_capability_version
                    .set(i64::from(version));
                let cmds = self.on_ready();
                self.exec(cmds).await;
            }
            RdpInput::FrameAck {
                slot,
                frame_id,
                queue_depth,
            } => {
                if self.link_for(slot).is_none() {
                    return;
                }
                self.d.metrics.frames_acked.inc();
                let cmds = self.step([Input::FrameAck {
                    frame_id,
                    queue_depth,
                }]);
                self.exec(cmds).await;
            }
            RdpInput::GfxClosed { slot } => {
                let Some(generation) = self.link_for(slot).map(|l| l.generation) else {
                    return;
                };
                // IronRDP runs `on_close` at every connection's teardown,
                // just before `on_disconnected` (PC13): by the time a
                // teardown's close is read here its generation has ended.
                // Only a close while the generation is still current — a
                // client's DVC Close mid-session — is a cause. The filter
                // is load-bearing: without it every plain disconnect
                // counts as `no_avc420`. One window is accepted (PC13
                // review m1): a session that ends during a
                // Deactivation-Reactivation while a Preempt candidate is
                // negotiating reaches `on_disconnected` up to 750 ms
                // (`CANDIDATE_HANDOFF_GRACE`) after its close, and is
                // closed here as `no_avc420` first — one miscount and a log
                // line; the stale `Disconnect` and abort reach nothing.
                if let Some(input) = closed_channel_input(&self.d.gens, generation) {
                    if let Some(l) = self.link.as_mut() {
                        l.egfx_closed = true;
                    }
                    let cmds = self.step([input]);
                    self.exec(cmds).await;
                }
            }
            RdpInput::Fatal { slot, cause } => {
                // Only this session's clipboard ends it (§4.3): another
                // slot is a stale or rival connection's, and an ended
                // generation's client has gone already — stepping it would
                // count a disconnect that never happens (D17).
                let Some(generation) = self.link_for_clip(slot).map(|l| l.generation) else {
                    return;
                };
                if let Some(input) = fatal_input(&self.d.gens, generation, cause) {
                    // The oversize answer ends the paste that asked for it
                    // as `oversize`, before the close releases all (§8).
                    if cause == Cause::ClipboardOversize {
                        self.d.input.clipboard_oversize();
                    }
                    let cmds = self.step([input]);
                    self.exec(cmds).await;
                }
            }
            // This session's clipboard words reach the input core under
            // `Fatal`'s gate; any other is dropped, freeing its place.
            RdpInput::ClipboardAvailable { slot, offer } => {
                if self.clip_is_current(slot) {
                    self.d.input.clipboard_available(offer.text());
                }
            }
            RdpInput::ClipboardText {
                slot,
                bytes,
                answer,
            } => {
                if self.clip_is_current(slot) {
                    let lost = answer.lost();
                    drop(answer); // its place is free before the core runs
                    self.d.input.clipboard_text(bytes);
                    self.d.input.clipboard_lost(lost);
                }
            }
            RdpInput::ClipboardFailed { slot, answer } => {
                if self.clip_is_current(slot) {
                    let lost = answer.lost();
                    drop(answer);
                    self.d.input.clipboard_failed();
                    self.d.input.clipboard_lost(lost);
                }
            }
            RdpInput::Updates => {
                // PC17: the reactivation's Setup, same window as `OnReady`.
                if self.link_ended() {
                    return;
                }
                let cmds = self.step([Input::ReactivationComplete]);
                self.exec(cmds).await;
            }
            RdpInput::Shutdown { done } => {
                self.shutting_down = true;
                if self.link.is_none() {
                    let _ = done.send(());
                    return;
                }
                self.waiters.push(done);
                // Always passed through, Closing included: the core then
                // shortens a running close's watchdog to this one (m6), so
                // a long `disconnect_watchdog` cannot hold §5.2's 5 s exit.
                let cmds = self.step([Input::Shutdown {
                    watchdog: self.shutdown_watchdog,
                }]);
                self.exec(cmds).await;
            }
            // Test hook (L2 `/livez`): block this runtime's thread.
            #[cfg(feature = "test-hooks")]
            RdpInput::Stall(d) => std::thread::sleep(d.min(MAX_STALL)),
            // Test hook: a bug in the shell (unit tests; `[test] panic_after`).
            #[cfg(any(test, feature = "test-hooks"))]
            #[allow(clippy::panic)]
            RdpInput::InjectedPanic => panic!("injected: the pump shell panics"),
        }
    }

    /// `on_ready`: what IronRDP negotiated, read under the same lock hold.
    fn on_ready(&mut self) -> Vec<Command> {
        let Some(gfx) = self.link.as_ref().map(|l| l.gfx.clone()) else {
            return Vec::new();
        };
        let mut g = lock(&gfx);
        let avc420 = g.supports_avc420();
        self.pump
            .step(&mut g, Instant::now(), Input::OnReady { avc420 })
    }

    async fn kvm_event(&mut self, ev: KvmEvent) {
        let generation = ev.generation();
        let ours = self
            .link
            .as_ref()
            .is_some_and(|l| l.generation == generation)
            && self.d.gens.is_current(generation);
        if !ours {
            return; // another generation's word (§4.3)
        }
        // Fixed-size steps: the per-AU path allocates no input list (m1).
        let cmds = match ev {
            KvmEvent::FlvOpened { origin, .. } => self.step([Input::FlvOpened { origin }]),
            KvmEvent::SpsChanged { class, params, .. } => {
                self.step([Input::SpsChanged { class, params }])
            }
            KvmEvent::Au { au, .. } => {
                let [suppress, backlog] = self.samples();
                self.step([suppress, backlog, Input::Au(au)])
            }
            KvmEvent::UpstreamFatal { cause, .. } => self.step([Input::UpstreamFatal(cause)]),
        };
        self.exec(cmds).await;
    }

    /// DC6: the suppression flag and this generation's write counter.
    fn samples(&self) -> [Input; 2] {
        let written = self
            .link
            .as_ref()
            .map_or(0, |l| l.counter.load(Ordering::Relaxed));
        [
            Input::Suppress(self.d.suppressed.load(Ordering::Relaxed)),
            Input::Backlog { written },
        ]
    }

    async fn tick(&mut self) {
        if self.link.is_none() {
            return;
        }
        let [suppress, backlog] = self.samples();
        let cmds = self.step([suppress, backlog, Input::Tick]);
        self.exec(cmds).await;
    }

    fn end_link(&mut self) {
        self.link = None;
        let m = &self.d.metrics;
        m.egfx_in_flight.set(0);
        m.egfx_backlog_bytes.set(0);
        m.egfx_ack_suspended.set(0);
        m.egfx_oldest_unacked_ms.set(0);
        m.standing_delay_ms.set(-1);
        for w in self.waiters.drain(..) {
            let _ = w.send(());
        }
    }

    async fn exec(&mut self, cmds: Vec<Command>) {
        let mut queue: VecDeque<Command> = cmds.into();
        while let Some(c) = queue.pop_front() {
            let Some(generation) = self.link.as_ref().map(|l| l.generation) else {
                return;
            };
            let current = self.d.gens.is_current(generation);
            tracing::trace!(generation, kind = c.kind(), current, "pump command");
            match c {
                Command::SendDvc(b) => {
                    if current {
                        self.send_dvc(b).await;
                    }
                }
                // m5: the shared state — the display's size (the next
                // connection's), mouse scaling's surface, the HID release —
                // belongs to the current session only, like every send. A
                // link whose generation has ended (`on_disconnected` ran,
                // its `SessionStop` not yet stepped) already released all
                // (SessionEnd). The watchdog's release is always current:
                // it fires only while `on_disconnected` has not come.
                // Since PC17 an ended link runs no Setup (`OnReady` and
                // `Updates` are skipped, `link_ended`), so the display and
                // surface gates are a second line, unreachable from those
                // inputs; the release gate still serves `Shutdown`.
                Command::DisplayResize { width, height } => {
                    if current {
                        self.d.display.set_size((width, height));
                        // PC17 I4: IronRDP writes EGFX and display updates
                        // from two futures it runs concurrently, so the
                        // DeactivateAll could overtake EGFX sent before it
                        // (a first Setup's slate). Held until written.
                        if let Some(l) = self.link.as_mut() {
                            l.held_resize = Some((width, height));
                        }
                        self.resize_poll = RESIZE_POLL;
                        self.release_resize();
                    }
                }
                Command::SurfaceSize { width, height } => {
                    if current {
                        self.d.display.set_surface((width, height));
                    }
                }
                Command::ReleaseAll(trigger) => {
                    if current {
                        self.d.hid.release_all(trigger);
                    }
                }
                Command::OpenFlv => {
                    let _ = self.d.to_kvm.send(KvmCommand::OpenFlv { generation });
                }
                Command::RequestIdr => {
                    let _ = self.d.to_kvm.send(KvmCommand::RequestIdr { generation });
                }
                Command::ReconnectFlv => {
                    let _ = self.d.to_kvm.send(KvmCommand::ReconnectFlv { generation });
                }
                // DC11 (P34): pump-internal. The core counts
                // `idr_cancelled` when it cancels a deferred request (on
                // leaving NeedIdr and, per P26, on an FLV open); the
                // command exists for L1's assertions. Never count it here.
                Command::CancelIdrRequest => {}
                Command::ProbeRtt => {
                    if current {
                        queue.extend(self.probe_rtt());
                    }
                }
                Command::Disconnect(cause) => {
                    if current {
                        self.disconnect(cause);
                    }
                }
                Command::Abort => {
                    // Whatever the generation's state: a stale `Stop` after
                    // a newer `Start` is the KVM actor's to ignore.
                    let _ = self.d.to_kvm.send(KvmCommand::Stop {
                        generation,
                        done: None,
                    });
                    if let Some(l) = self.link.as_ref() {
                        l.abort.abort();
                    }
                    tracing::warn!(
                        generation,
                        "disconnect watchdog fired: aborting the connection"
                    );
                }
            }
        }
    }

    fn resize_held(&self) -> bool {
        self.link.as_ref().is_some_and(|l| l.held_resize.is_some())
    }

    /// The held resize, once the counter shows every EGFX batch sent before
    /// it written (IronRDP adds a batch's weight after its `write_all`). One
    /// held for an ended generation is dropped.
    fn release_resize(&mut self) {
        let Some(l) = self.link.as_mut() else {
            return;
        };
        let Some((width, height)) = l.held_resize else {
            return;
        };
        if self.d.gens.is_current(l.generation) && l.counter.load(Ordering::Relaxed) < l.sent {
            return;
        }
        l.held_resize = None;
        if self.d.gens.is_current(l.generation) && !self.d.display.resize(width, height) {
            tracing::warn!(width, height, "no display stream for a resize");
        }
    }

    async fn send_dvc(&mut self, b: DvcBatch) {
        let Some(counter) = self.link.as_ref().map(|l| l.counter.clone()) else {
            return;
        };
        let DvcBatch {
            channel_id,
            messages,
            weight,
            received,
            yield_after,
            ..
        } = b;
        match encode_dvc_messages(channel_id, messages, ChannelFlags::SHOW_PROTOCOL) {
            Ok(svc) => {
                let msg = EgfxServerMessage::send_messages(svc).with_write_counter(counter, weight);
                if self.d.events.send(ServerEvent::Egfx(msg)).is_err() {
                    tracing::debug!("the server's event channel is closed");
                }
            }
            Err(e) => {
                // Keep the backlog honest: this batch will never be written.
                counter.fetch_add(weight, Ordering::Relaxed);
                tracing::warn!(error = %e, "EGFX batch encoding failed");
            }
        }
        // Either way `weight` reaches the counter: written, or never to be.
        if let Some(l) = self.link.as_mut() {
            l.sent = l.sent.saturating_add(weight);
        }
        if let Some(t) = received {
            self.d.metrics.enqueue_latency.observe(t.elapsed());
        }
        if yield_after {
            // A burst chunk: let input interleave (§6.5).
            tokio::task::yield_now().await;
        }
    }

    /// DC6: read the previous probe's answer, probe again, feed every read.
    /// The reference rule (a generation's first sample is only a reference:
    /// the handle outlives connections) lives in the core's `Rtt`, once —
    /// applying it here as well would make the first *live* answer the
    /// core's reference and keep it out of the baseline.
    fn probe_rtt(&mut self) -> Vec<Command> {
        let v = self.d.rtt.load(Ordering::Relaxed);
        let _ = self.d.events.send(ServerEvent::AutoDetectRttRequest);
        self.step([Input::Rtt(v)])
    }

    fn disconnect(&mut self, cause: Cause) {
        if cause == Cause::NoAvc420 {
            match self.link.as_ref() {
                Some(l) if l.egfx_closed => {
                    tracing::warn!("the client closed its EGFX channel mid-session");
                }
                l => {
                    let caps = l.map(|l| l.caps.clone()).unwrap_or_default();
                    tracing::warn!(?caps, "the client offered no AVC420 capability set (§6.7)");
                }
            }
        }
        tracing::info!(cause = cause.label(), "disconnecting the client");
        // What `ErrorInfoDisconnectHandle::disconnect` sends.
        let _ = self
            .d
            .events
            .send(ServerEvent::Disconnect(cause.error_info()));
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
    use crate::msg::FlvOrigin;
    use crate::pump::rig::{self, CHAN, ES3, Null, P480};
    use crate::rdp::accept::AcceptRate;
    use crate::rdp::clipboard::{Answer, ClipFactory, ClipSlot, Offer, ServerEvents};
    use crate::rdp::gfx::{GfxFactory, GfxSlot};
    use crate::rdp::handler::Lifecycle;
    use crate::rdp::input::{InputDeps, InputRuntimeConfig};
    use ironrdp_cliprdr::backend::CliprdrBackendFactory as _;
    use ironrdp_cliprdr::pdu::{ClipboardFormat, ClipboardFormatId, FormatDataResponse};
    use ironrdp_core::encode_vec;
    use ironrdp_server::KeyboardEvent;
    // `start` and `process` are `DvcProcessor` methods on the GFX server,
    // and `SvcProcessor` methods on IronRDP's DVC server.
    use ironrdp_dvc::DrdynvcServer;
    use ironrdp_dvc::DvcProcessor as _;
    use ironrdp_dvc::pdu::{
        CapabilitiesResponsePdu, CapsVersion, ClosePdu, CreateResponsePdu, CreationStatus, DataPdu,
        DrdynvcClientPdu, DrdynvcDataPdu,
    };
    use ironrdp_egfx::pdu::{CapabilitiesAdvertisePdu, FrameAcknowledgePdu, GfxPdu, QueueDepth};
    use ironrdp_pdu::gcc::KeyboardType;
    use ironrdp_pdu::rdp::server_error_info::{ErrorInfo, ProtocolIndependentCode as P};
    use ironrdp_server::{
        ConnectionHandler as _, ConnectionInfo, DisplayUpdate, GfxDvcBridge, GfxServerFactory as _,
        RdpServerDisplay as _,
    };
    use ironrdp_svc::SvcProcessor as _;
    use kvm_proto::video::ParamClass;
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use tokio::task::LocalSet;

    /// Wait (bounded) for a condition the shell task makes true.
    async fn until(what: &str, f: impl Fn() -> bool) {
        let waited = tokio::time::timeout(Duration::from_secs(2), async {
            while !f() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(waited.is_ok(), "timed out waiting for {what}");
    }

    /// The next item on one of the shell's outbound channels (bounded).
    async fn recv<M>(rx: &mut mpsc::UnboundedReceiver<M>) -> M {
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out waiting for the shell")
            .expect("the shell's channel closed")
    }

    /// The FLV's first tag, its parameter sets, then one IDR.
    async fn first_idr(kvm: &mpsc::Sender<KvmEvent>, generation: Gen) {
        kvm.send(KvmEvent::FlvOpened {
            generation,
            origin: FlvOrigin::First,
        })
        .await
        .unwrap();
        let Input::SpsChanged { class, params } = rig::sps(ParamClass::Initial, ES3) else {
            unreachable!()
        };
        kvm.send(KvmEvent::SpsChanged {
            generation,
            class,
            params,
        })
        .await
        .unwrap();
        let Input::Au(au) = rig::au(true, false) else {
            unreachable!()
        };
        kvm.send(KvmEvent::Au { generation, au }).await.unwrap();
    }

    fn info() -> ConnectionInfo {
        ConnectionInfo::new(0x409, KeyboardType::IBM_ENHANCED, String::new())
    }

    fn peer() -> SocketAddr {
        "127.0.0.2:50000".parse().unwrap()
    }

    struct T {
        rdp: mpsc::UnboundedSender<RdpInput>,
        kvm: mpsc::Sender<KvmEvent>,
        events: mpsc::UnboundedReceiver<ServerEvent>,
        cmds: mpsc::UnboundedReceiver<KvmCommand>,
        gfx: GfxServerHandle,
        gens: Arc<Generations>,
        metrics: Arc<Metrics>,
        suppressed: Arc<AtomicBool>,
        rtt: Arc<AtomicU32>,
        counter: Arc<AtomicU64>,
        display: Arc<DisplayShared>,
        /// The input shell the shell feeds.
        input: Arc<InputShared>,
    }

    /// The shell on the current `LocalSet` over a 640×360 display (the ES3
    /// fixture's size: no resize), no slate, RTT probes off unless `set`
    /// turns them on, and a GFX server the test plays the client for.
    fn shell(set: impl FnOnce(&mut PumpConfig)) -> T {
        spawn(set, |s| s)
    }

    /// `shell`, with its test seams (shutdown watchdog, tick) set by `seams`.
    fn spawn(set: impl FnOnce(&mut PumpConfig), seams: impl FnOnce(PumpShell) -> PumpShell) -> T {
        let mut cfg = rig::cfg();
        cfg.rtt_probe_interval = Duration::from_secs(3600);
        set(&mut cfg);
        let metrics = Arc::new(Metrics::default());
        let (rdp, rdp_rx) = mpsc::unbounded_channel();
        let (kvm, kvm_rx) = mpsc::channel(68);
        let (etx, events) = mpsc::unbounded_channel();
        let (ktx, cmds) = mpsc::unbounded_channel();
        let gens = Arc::new(Generations::default());
        let suppressed = Arc::new(AtomicBool::new(false));
        let rtt = Arc::new(AtomicU32::new(u32::MAX));
        let display = DisplayShared::new((640, 360));
        let hid = Arc::new(HidControl::new(16, metrics.clone()));
        let input = Arc::new(InputShared::new(InputDeps {
            hid: hid.clone(),
            display: display.clone(),
            events: ServerEvents::default(),
            gens: gens.clone(),
            metrics: metrics.clone(),
            cfg: InputRuntimeConfig::test(),
        }));
        let deps = ShellDeps {
            cfg: cfg.clone(),
            metrics: metrics.clone(),
            gens: gens.clone(),
            hid,
            display: display.clone(),
            events: etx,
            suppressed: suppressed.clone(),
            rtt: rtt.clone(),
            to_kvm: ktx,
            input: input.clone(),
        };
        let pump = Pump::with_slate(cfg, metrics.clone(), None);
        let shell = PumpShell::with_pump(deps, pump);
        // DC13 and DC6: every shell closes at shutdown with the 2 s
        // watchdog and ticks every 50 ms; only these seams change that.
        assert_eq!(shell.shutdown_watchdog, SHUTDOWN_WATCHDOG);
        assert_eq!(shell.tick_every, TICK);
        tokio::task::spawn_local(seams(shell).run(rdp_rx, kvm_rx));
        let gfx: GfxServerHandle =
            Arc::new(Mutex::new(GraphicsPipelineServer::new(Box::new(Null))));
        gfx.lock().unwrap().start(CHAN).unwrap();
        let counter = Arc::new(AtomicU64::new(0));
        T {
            rdp,
            kvm,
            events,
            cmds,
            gfx,
            gens,
            metrics,
            suppressed,
            rtt,
            counter,
            display,
            input,
        }
    }

    impl T {
        fn session_start(&self) -> Gen {
            let generation = self.gens.begin();
            let abort = info().abort_handle();
            self.rdp
                .send(RdpInput::SessionStart {
                    generation,
                    slot: 1,
                    gfx: self.gfx.clone(),
                    counter: self.counter.clone(),
                    abort,
                    clip_slot: Some(1),
                })
                .unwrap();
            generation
        }

        /// The client advertises the census pair; IronRDP's `on_ready`.
        fn ready(&self) {
            let adv = encode_vec(&GfxPdu::CapabilitiesAdvertise(CapabilitiesAdvertisePdu(
                rig::census_caps(),
            )))
            .unwrap();
            self.gfx.lock().unwrap().process(CHAN, &adv).unwrap();
            self.rdp
                .send(RdpInput::OnReady {
                    slot: 1,
                    version: 0x8_0105,
                })
                .unwrap();
        }

        fn start(&self) -> Gen {
            let generation = self.session_start();
            self.ready();
            generation
        }

        async fn event(&mut self) -> ServerEvent {
            recv(&mut self.events).await
        }

        async fn quiet(&mut self, d: Duration) -> bool {
            tokio::time::timeout(d, self.events.recv()).await.is_err()
        }

        async fn cmd(&mut self) -> KvmCommand {
            recv(&mut self.cmds).await
        }

        async fn first_idr(&self, generation: Gen) {
            first_idr(&self.kvm, generation).await;
        }

        /// `first_idr` and then `burst` burst AUs, queued without an await,
        /// so that a shell not yet polled finds them all at once.
        fn queue_first_idr_and_burst(&self, generation: Gen, burst: usize) {
            let send = |ev| self.kvm.try_send(ev).unwrap();
            send(KvmEvent::FlvOpened {
                generation,
                origin: FlvOrigin::First,
            });
            let Input::SpsChanged { class, params } = rig::sps(ParamClass::Initial, ES3) else {
                unreachable!()
            };
            send(KvmEvent::SpsChanged {
                generation,
                class,
                params,
            });
            for idr in std::iter::once(true).chain(std::iter::repeat_n(false, burst)) {
                let Input::Au(au) = rig::au(idr, !idr) else {
                    unreachable!()
                };
                send(KvmEvent::Au { generation, au });
            }
        }

        /// The client acknowledges `frame_id`: IronRDP first, then the
        /// callback's push (as `GfxCallbacks::on_frame_ack` would).
        fn ack(&self, frame_id: u32) {
            let pdu = encode_vec(&GfxPdu::FrameAcknowledge(FrameAcknowledgePdu {
                queue_depth: QueueDepth::Unavailable,
                frame_id,
                total_frames_decoded: 1,
            }))
            .unwrap();
            self.gfx.lock().unwrap().process(CHAN, &pdu).unwrap();
            self.rdp
                .send(RdpInput::FrameAck {
                    slot: 1,
                    frame_id,
                    queue_depth: 0,
                })
                .unwrap();
        }
    }

    fn egfx(ev: &ServerEvent) -> Option<(&Arc<AtomicU64>, u64)> {
        match ev {
            ServerEvent::Egfx(EgfxServerMessage::SendMessages {
                write_progress: Some((c, w)),
                ..
            }) => Some((c, *w)),
            _ => None,
        }
    }

    /// A KVM side that never lets the stream empty, as a fast KVM actor's
    /// `try_send` of every AU does: another thread offers AUs for
    /// `generation` until dropped (bounded: 10 s, or the shell gone).
    struct Flood {
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Flood {
        fn start(kvm: &mpsc::Sender<KvmEvent>, generation: Gen) -> Flood {
            let (tx, stop) = (kvm.clone(), Arc::new(AtomicBool::new(false)));
            let halt = stop.clone();
            let Input::Au(au) = rig::au(false, false) else {
                unreachable!()
            };
            let thread = std::thread::spawn(move || {
                let t0 = Instant::now();
                while !halt.load(Ordering::Relaxed) && t0.elapsed() < Duration::from_secs(10) {
                    let ev = KvmEvent::Au {
                        generation,
                        au: au.clone(),
                    };
                    match tx.try_send(ev) {
                        Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                        Err(mpsc::error::TrySendError::Closed(_)) => break,
                    }
                }
            });
            Flood {
                stop,
                thread: Some(thread),
            }
        }
    }

    impl Drop for Flood {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    /// I1: a KVM stream that never empties (the hostile side, §3.2) cannot
    /// hold off the ticks: the disconnect watchdog of a Closing session
    /// still fires on time, within 5× and not before 0.5×, while AUs keep
    /// arriving.
    #[tokio::test(flavor = "current_thread")]
    async fn a_kvm_flood_cannot_hold_off_the_disconnect_watchdog() {
        LocalSet::new()
            .run_until(async {
                let wd = Duration::from_millis(300);
                let mut t = shell(|c| c.disconnect_watchdog = wd);
                let generation = t.start();
                t.event().await; // the Setup
                assert!(matches!(t.cmd().await, KvmCommand::OpenFlv { .. }));
                let t0 = Instant::now();
                t.kvm
                    .send(KvmEvent::UpstreamFatal {
                        generation,
                        cause: Cause::StreamCorrupt,
                    })
                    .await
                    .unwrap();
                assert!(matches!(t.event().await, ServerEvent::Disconnect(_)));
                let flood = Flood::start(&t.kvm, generation);
                let stop = tokio::time::timeout(wd * 5, t.cmds.recv()).await;
                let took = t0.elapsed();
                drop(flood);
                let stop = stop
                    .expect("the KVM flood held the disconnect watchdog off")
                    .unwrap();
                assert!(
                    matches!(stop, KvmCommand::Stop { generation: g, done: None } if g == generation),
                    "{stop:?}"
                );
                assert!(took >= wd / 2, "{took:?}");
                assert!(t.metrics.frames_dropped.get("closing") > 0, "no flood");
            })
            .await;
    }

    /// I1: under the same flood a Live session keeps its RTT probes — and
    /// with them every other tick-driven timer (stall, IDR, debounce): at
    /// least one per 5× the probe interval.
    #[tokio::test(flavor = "current_thread")]
    async fn rtt_probes_keep_flowing_under_a_kvm_flood() {
        LocalSet::new()
            .run_until(async {
                let interval = Duration::from_millis(100);
                let mut t = shell(|c| c.rtt_probe_interval = interval);
                let generation = t.start();
                t.event().await; // the Setup
                t.first_idr(generation).await;
                until("the first IDR", || t.metrics.frames_sent.get() == 1).await;
                let flood = Flood::start(&t.kvm, generation);
                let window = interval * 10;
                let t0 = Instant::now();
                let mut probes = 0;
                while let Ok(Some(ev)) =
                    tokio::time::timeout(window.saturating_sub(t0.elapsed()), t.events.recv()).await
                {
                    probes += usize::from(matches!(ev, ServerEvent::AutoDetectRttRequest));
                }
                drop(flood);
                assert!(
                    probes >= 2,
                    "{probes} RTT probes in {window:?} under a KVM flood"
                );
            })
            .await;
    }

    /// The bridge's wiring around the shell, as Task 5.4 assembles it:
    /// `Lifecycle` and the GFX and clipboard factories' callbacks push into
    /// the shell's RDP-side channel and send to the same KVM-command
    /// channel the shell does. The shell is spawned but not yet polled
    /// when this returns.
    struct W {
        h: Lifecycle,
        factory: GfxFactory,
        /// The clipboard factory, `paste.max_bytes` = `CLIP_MAX`.
        clips: ClipFactory,
        rdp: mpsc::UnboundedSender<RdpInput>,
        kvm: mpsc::Sender<KvmEvent>,
        events: mpsc::UnboundedReceiver<ServerEvent>,
        cmds: mpsc::UnboundedReceiver<KvmCommand>,
        metrics: Arc<Metrics>,
        /// The input shell the shell feeds (`paste.modifier_wait` = `WIRED_WAIT`).
        input: Arc<InputShared>,
    }

    fn wired() -> W {
        let mut cfg = rig::cfg();
        cfg.rtt_probe_interval = Duration::from_secs(3600);
        let metrics = Arc::new(Metrics::default());
        let gens = Arc::new(Generations::default());
        let hid = Arc::new(HidControl::new(16, metrics.clone()));
        let (rdp, rdp_rx) = mpsc::unbounded_channel();
        let (kvm, kvm_rx) = mpsc::channel(68);
        let (etx, events) = mpsc::unbounded_channel();
        let (ktx, cmds) = mpsc::unbounded_channel();
        let latest = GfxSlot::default();
        let factory = GfxFactory::new(latest.clone(), rdp.clone(), cfg.hard_cap, metrics.clone());
        let clip = ClipSlot::default();
        let clips = ClipFactory::new(
            Arc::new(AtomicU64::new(0)),
            clip.clone(),
            rdp.clone(),
            CLIP_MAX,
            ServerEvents::default(),
        );
        let h = Lifecycle {
            gens: gens.clone(),
            accepting: Arc::new(AtomicBool::new(true)),
            rate: AcceptRate::new(30, Duration::from_secs(60)),
            gfx: latest,
            clip,
            hid: hid.clone(),
            metrics: metrics.clone(),
            to_pump: rdp.clone(),
            to_kvm: ktx.clone(),
            handshakes: Arc::new(crate::rdp::accept::Handshakes::new(
                crate::rdp::accept::HANDSHAKE_GRACE,
            )),
        };
        let display = DisplayShared::new((640, 360));
        let input = Arc::new(InputShared::new(InputDeps {
            hid: hid.clone(),
            display: display.clone(),
            events: ServerEvents::default(),
            gens: gens.clone(),
            metrics: metrics.clone(),
            cfg: InputRuntimeConfig {
                modifier_wait: WIRED_WAIT,
                ..InputRuntimeConfig::test()
            },
        }));
        let deps = ShellDeps {
            cfg: cfg.clone(),
            metrics: metrics.clone(),
            gens,
            hid,
            display,
            events: etx,
            suppressed: Arc::new(AtomicBool::new(false)),
            rtt: Arc::new(AtomicU32::new(u32::MAX)),
            to_kvm: ktx,
            input: input.clone(),
        };
        let pump = Pump::with_slate(cfg, metrics.clone(), None);
        tokio::task::spawn_local(PumpShell::with_pump(deps, pump).run(rdp_rx, kvm_rx));
        W {
            h,
            factory,
            clips,
            rdp,
            kvm,
            events,
            cmds,
            metrics,
            input,
        }
    }

    /// The wired rig's `paste.modifier_wait`: a paste times out in real time.
    const WIRED_WAIT: Duration = Duration::from_millis(100);

    /// The wired rig's `paste.max_bytes`.
    const CLIP_MAX: usize = 16;

    /// The client's end of one connection's EGFX channel, through IronRDP's
    /// own DVC server hosting the factory's bridge as `RdpServer` hosts it.
    /// Dropping it is IronRDP's teardown of the connection's channels
    /// (`DynamicChannel::drop` runs `on_close` for an open channel);
    /// `close()` is a client's mid-session DVC Close PDU.
    struct Egfx {
        dvc: DrdynvcServer,
        id: u32,
    }

    impl Egfx {
        /// IronRDP builds the connection's handle before auth
        /// (`attach_channels`).
        fn build(factory: &GfxFactory) -> Egfx {
            let (bridge, _) = factory.build_server_with_handle().unwrap();
            let dvc = DrdynvcServer::new().with_dynamic_channel(bridge);
            let id = dvc.get_channel_id_by_type::<GfxDvcBridge>().unwrap();
            Egfx { dvc, id }
        }

        fn client(&mut self, pdu: DrdynvcClientPdu) {
            self.dvc.process(&encode_vec(&pdu).unwrap()).unwrap();
        }

        /// After activation: the DVC capabilities, the channel's Create
        /// Response, then the census capability pair — IronRDP's
        /// `on_ready`.
        fn open(&mut self) {
            self.dvc.start().unwrap();
            self.client(DrdynvcClientPdu::Capabilities(
                CapabilitiesResponsePdu::new(CapsVersion::V2),
            ));
            self.client(DrdynvcClientPdu::Create(CreateResponsePdu::new(
                self.id,
                CreationStatus::OK,
            )));
            self.advertise();
        }

        /// The census capability pair on the open channel: IronRDP's
        /// `on_ready` (again, for a re-advertise).
        fn advertise(&mut self) {
            let adv = encode_vec(&GfxPdu::CapabilitiesAdvertise(CapabilitiesAdvertisePdu(
                rig::census_caps(),
            )))
            .unwrap();
            self.client(DrdynvcClientPdu::Data(DrdynvcDataPdu::Data(DataPdu::new(
                self.id, adv,
            ))));
        }

        fn close(&mut self) {
            self.client(DrdynvcClientPdu::Close(ClosePdu::new(self.id)));
        }
    }

    impl W {
        /// One connection in IronRDP's order — its handle built, NLA's
        /// `on_connection_info`, its channels opened — to Live: the Setup,
        /// the first Setup's `OpenFlv`, and the FLV's first IDR on the wire.
        async fn live(&mut self) -> (Egfx, Gen) {
            let mut chan = Egfx::build(&self.factory);
            self.h.on_connection_info(&info());
            chan.open();
            assert!(egfx(&recv(&mut self.events).await).is_some(), "the Setup");
            let KvmCommand::Start { generation } = recv(&mut self.cmds).await else {
                panic!("no Start")
            };
            assert!(matches!(
                recv(&mut self.cmds).await,
                KvmCommand::OpenFlv { generation: g } if g == generation
            ));
            first_idr(&self.kvm, generation).await;
            assert!(egfx(&recv(&mut self.events).await).is_some(), "the IDR");
            assert_eq!(self.metrics.frames_sent.get(), 1);
            (chan, generation)
        }

        /// IronRDP's teardown of a connection: its channels are dropped —
        /// `on_close` — then `on_disconnected` runs, with no await between
        /// (`RdpServer::run`, server.rs:2985 → 2988).
        fn teardown(&mut self, chan: Egfx) {
            drop(chan);
            self.h.on_disconnected(peer(), Duration::from_secs(1), None);
        }

        /// Every RDP-side input sent so far has been stepped and no session
        /// is left: only then is a `Shutdown` answered at once.
        async fn settled(&self) {
            let (done, rx) = oneshot::channel();
            self.rdp.send(RdpInput::Shutdown { done }).unwrap();
            tokio::time::timeout(Duration::from_secs(2), rx)
                .await
                .expect("a session outlived its connection's teardown")
                .unwrap();
        }
    }

    /// DC4, §5.2: Task 5.3's constants.
    #[test]
    fn the_tick_and_the_shutdown_watchdog_are_the_specs() {
        assert_eq!(TICK, Duration::from_millis(50));
        assert_eq!(SHUTDOWN_WATCHDOG, Duration::from_secs(2));
    }

    /// §4.3, §4.2 patch 2: Setup and frames leave only as
    /// `ServerEvent::Egfx`, each carrying this generation's write counter
    /// and its weight; the first Setup opens the FLV for this generation.
    #[tokio::test(flavor = "current_thread")]
    async fn a_session_reaches_the_wire_through_server_events_with_its_counter() {
        LocalSet::new()
            .run_until(async {
                let mut t = shell(|_| {});
                let generation = t.start();
                let setup = t.event().await;
                let (c, w) = egfx(&setup).expect("the Setup batch");
                assert!(Arc::ptr_eq(c, &t.counter) && w > 0);
                assert!(
                    matches!(t.cmd().await, KvmCommand::OpenFlv { generation: g } if g == generation)
                );
                t.first_idr(generation).await;
                assert!(egfx(&t.event().await).is_some());
                assert_eq!(t.metrics.frames_sent.get(), 1);
                assert_eq!(t.metrics.egfx_capability_version.get(), 0x8_0105);
            })
            .await;
    }

    /// DC4: only the current generation's KVM events reach the core.
    #[tokio::test(flavor = "current_thread")]
    async fn another_generations_kvm_events_are_dropped() {
        LocalSet::new()
            .run_until(async {
                let mut t = shell(|_| {});
                let generation = t.start();
                t.event().await;
                t.first_idr(generation + 100).await;
                assert!(t.quiet(Duration::from_millis(300)).await);
                assert_eq!(t.metrics.frames_sent.get(), 0);
                t.first_idr(generation).await;
                assert!(egfx(&t.event().await).is_some());
            })
            .await;
    }

    /// §4.3: once `on_disconnected` has ended the generation, nothing more
    /// reaches IronRDP for it — even before `SessionStop` is processed.
    #[tokio::test(flavor = "current_thread")]
    async fn nothing_is_sent_for_an_ended_generation() {
        LocalSet::new()
            .run_until(async {
                let mut t = shell(|_| {});
                let generation = t.session_start();
                t.gens.end();
                t.ready();
                assert!(
                    t.quiet(Duration::from_millis(300)).await,
                    "a Setup went out for an ended generation"
                );
                t.rdp.send(RdpInput::SessionStop { generation }).unwrap();
            })
            .await;
    }

    /// §4.3 (I2): no `ServerEvent` — an RTT probe, a `Disconnect` — goes
    /// out for a generation `on_disconnected` has ended, though its
    /// `SessionStop` is not yet stepped: the server's event channel would
    /// carry it to whichever connection IronRDP serves next.
    #[tokio::test(flavor = "current_thread")]
    async fn no_rtt_probe_or_disconnect_for_an_ended_generation() {
        LocalSet::new()
            .run_until(async {
                let mut t = shell(|c| c.rtt_probe_interval = Duration::from_millis(50));
                let generation = t.start();
                t.event().await; // the Setup
                t.first_idr(generation).await;
                t.event().await; // the IDR
                t.gens.end(); // on_disconnected ran; its SessionStop not yet stepped
                assert!(
                    t.quiet(Duration::from_millis(300)).await,
                    "an RTT probe went out for an ended generation"
                );
                let (done, _rx) = oneshot::channel();
                t.rdp.send(RdpInput::Shutdown { done }).unwrap();
                assert!(
                    t.quiet(Duration::from_millis(300)).await,
                    "a Disconnect went out for an ended generation"
                );
                t.rdp.send(RdpInput::SessionStop { generation }).unwrap();
            })
            .await;
    }

    /// m5: like the gated sends, the shared state belongs to the current
    /// session only. A generation `on_disconnected` has ended (its
    /// `SessionStop` not yet stepped) already released all (SessionEnd); its
    /// late Setup, resize and close must not size the display for the next
    /// connection, set mouse scaling's surface, or release the HID again.
    /// (Since PC17 its late `on_ready` runs no Setup at all; the gated
    /// display and surface writes stay as a second line.)
    #[tokio::test(flavor = "current_thread")]
    async fn an_ended_generation_leaves_the_display_and_the_hid_alone() {
        LocalSet::new()
            .run_until(async {
                let mut t = shell(|_| {});
                let generation = t.session_start();
                // A 480p SPS before negotiation: the Setup will resize.
                let Input::SpsChanged { class, params } = rig::sps(ParamClass::Initial, P480)
                else {
                    unreachable!()
                };
                let size = (params.summary.width, params.summary.height);
                assert_ne!(size, (640, 360));
                t.kvm
                    .send(KvmEvent::SpsChanged {
                        generation,
                        class,
                        params,
                    })
                    .await
                    .unwrap();
                until("the SPS to be stepped", || {
                    t.kvm.capacity() == t.kvm.max_capacity()
                })
                .await;
                t.gens.end(); // on_disconnected ran; its SessionStop not yet stepped
                t.ready(); // its late on_ready (a Setup and a 480p resize before PC17)
                let (done, rx) = oneshot::channel();
                t.rdp.send(RdpInput::Shutdown { done }).unwrap(); // ReleaseAll(closing)
                t.rdp.send(RdpInput::SessionStop { generation }).unwrap();
                tokio::time::timeout(Duration::from_secs(1), rx)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    t.display.size(),
                    (640, 360),
                    "an ended session sized the display"
                );
                assert_eq!(
                    t.display.surface(),
                    None,
                    "an ended session set the surface"
                );
                assert_eq!(
                    t.metrics.release_all.get("closing"),
                    0,
                    "an ended session released again"
                );
                assert!(
                    t.events.try_recv().is_err(),
                    "a ServerEvent for an ended session"
                );
            })
            .await;
    }

    /// DC6, §4.2 patch 2 (I3): the shell feeds IronRDP's write counter to
    /// the core, so written bytes leave the backlog. Without it the backlog
    /// only grows, and the backlog gate shuts for good once `backlog_limit`
    /// bytes have been handed over.
    #[tokio::test(flavor = "current_thread")]
    async fn the_write_counter_drains_the_backlog() {
        LocalSet::new()
            .run_until(async {
                let mut t = shell(|_| {});
                let generation = t.start();
                let w1 = egfx(&t.event().await).unwrap().1;
                t.first_idr(generation).await;
                let w2 = egfx(&t.event().await).unwrap().1;
                let handed = i64::try_from(w1 + w2).unwrap();
                until("the backlog gauge", || {
                    t.metrics.egfx_backlog_bytes.get() == handed
                })
                .await;
                t.counter.fetch_add(w1 + w2, Ordering::SeqCst); // IronRDP wrote both
                until("the written bytes to leave the backlog", || {
                    t.metrics.egfx_backlog_bytes.get() == 0
                })
                .await;
            })
            .await;
    }

    /// §6.9: a fatal cause → release (closing), then `Disconnect` with the
    /// cause's ErrorInfo.
    #[tokio::test(flavor = "current_thread")]
    async fn an_upstream_fatal_disconnects_with_its_errorinfo() {
        LocalSet::new()
            .run_until(async {
                let mut t = shell(|_| {});
                let generation = t.start();
                t.event().await;
                t.kvm
                    .send(KvmEvent::UpstreamFatal {
                        generation,
                        cause: Cause::KvmAuthFailed,
                    })
                    .await
                    .unwrap();
                match t.event().await {
                    ServerEvent::Disconnect(ErrorInfo::ProtocolIndependentCode(
                        P::ServerInsufficientPrivileges,
                    )) => {}
                    other => panic!("{other:?}"),
                }
                assert_eq!(t.metrics.release_all.get("closing"), 1);
                assert_eq!(t.metrics.disconnects.get("kvm_auth_failed"), 1);
            })
            .await;
    }

    /// §6.9: `on_disconnected` never comes → release (watchdog), `Stop` to
    /// the KVM side, abort; within 5× the scaled watchdog, not before 0.5×.
    #[tokio::test(flavor = "current_thread")]
    async fn the_disconnect_watchdog_releases_and_stops_the_kvm_side() {
        LocalSet::new()
            .run_until(async {
                let wd = Duration::from_millis(300);
                let mut t = shell(|c| c.disconnect_watchdog = wd);
                let generation = t.start();
                t.event().await;
                assert!(matches!(t.cmd().await, KvmCommand::OpenFlv { .. }));
                let t0 = Instant::now();
                t.kvm
                    .send(KvmEvent::UpstreamFatal {
                        generation,
                        cause: Cause::StreamCorrupt,
                    })
                    .await
                    .unwrap();
                assert!(matches!(t.event().await, ServerEvent::Disconnect(_)));
                assert!(matches!(
                    t.cmd().await,
                    KvmCommand::Stop { generation: g, done: None } if g == generation
                ));
                let took = t0.elapsed();
                assert!(took >= wd / 2 && took <= wd * 5, "{took:?}");
                assert_eq!(t.metrics.release_all.get("watchdog"), 1);
            })
            .await;
    }

    /// §5.2: shutdown disconnects with `shutdown` (0x1) and is answered only
    /// once the session stopped; with no session, at once.
    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_is_answered_when_the_session_stops() {
        LocalSet::new()
            .run_until(async {
                let mut t = shell(|_| {});
                let generation = t.start();
                t.event().await;
                let (done, mut rx) = oneshot::channel();
                t.rdp.send(RdpInput::Shutdown { done }).unwrap();
                let ev = t.event().await;
                assert!(
                    matches!(
                        ev,
                        ServerEvent::Disconnect(ErrorInfo::ProtocolIndependentCode(
                            P::RpcInitiatedDisconnect
                        ))
                    ),
                    "{ev:?}"
                );
                assert!(
                    rx.try_recv().is_err(),
                    "answered before the session stopped"
                );
                t.gens.end();
                t.rdp.send(RdpInput::SessionStop { generation }).unwrap();
                tokio::time::timeout(Duration::from_secs(1), &mut rx)
                    .await
                    .unwrap()
                    .unwrap();
                let (done, rx) = oneshot::channel();
                t.rdp.send(RdpInput::Shutdown { done }).unwrap();
                tokio::time::timeout(Duration::from_secs(1), rx)
                    .await
                    .unwrap()
                    .unwrap();
            })
            .await;
    }

    /// §5.2, DC13: a session whose `on_connection_info` read `accepting`
    /// just before shutdown began reaches the shell after the `Shutdown`;
    /// it is closed at once with `shutdown` (0x1), before any negotiation.
    #[tokio::test(flavor = "current_thread")]
    async fn a_session_starting_after_shutdown_began_is_closed_at_once() {
        LocalSet::new()
            .run_until(async {
                let mut t = shell(|_| {});
                let (done, rx) = oneshot::channel();
                t.rdp.send(RdpInput::Shutdown { done }).unwrap();
                tokio::time::timeout(Duration::from_secs(1), rx)
                    .await
                    .unwrap()
                    .unwrap();
                t.session_start();
                let ev = t.event().await;
                assert!(
                    matches!(
                        ev,
                        ServerEvent::Disconnect(ErrorInfo::ProtocolIndependentCode(
                            P::RpcInitiatedDisconnect
                        ))
                    ),
                    "{ev:?}"
                );
                assert_eq!(t.metrics.disconnects.get("shutdown"), 1);
            })
            .await;
    }

    /// m6 through the shell (PC14 carry 4): a `Shutdown` while an earlier
    /// close is running passes the shutdown's watchdog to the core, which
    /// shortens the running one to it — so a long `disconnect_watchdog`
    /// cannot hold §5.2's 5 s exit. The close keeps its cause and its one
    /// `Disconnect`. (Scaled: 300 ms here, `SHUTDOWN_WATCHDOG` in
    /// production; the close's own watchdog is 30 s.)
    #[tokio::test(flavor = "current_thread")]
    async fn a_shutdown_during_a_close_shortens_its_watchdog() {
        LocalSet::new()
            .run_until(async {
                let wd = Duration::from_millis(300);
                let mut t = spawn(
                    |c| c.disconnect_watchdog = Duration::from_secs(30),
                    |s| s.with_shutdown_watchdog(wd),
                );
                let generation = t.start();
                t.event().await;
                assert!(matches!(t.cmd().await, KvmCommand::OpenFlv { .. }));
                t.kvm
                    .send(KvmEvent::UpstreamFatal {
                        generation,
                        cause: Cause::StreamCorrupt,
                    })
                    .await
                    .unwrap();
                assert!(matches!(t.event().await, ServerEvent::Disconnect(_)));
                let t0 = Instant::now();
                let (done, mut rx) = oneshot::channel();
                t.rdp.send(RdpInput::Shutdown { done }).unwrap();
                let stop = tokio::time::timeout(wd * 5, t.cmds.recv())
                    .await
                    .expect("the shutdown did not shorten the running close's watchdog")
                    .unwrap();
                assert!(
                    matches!(stop, KvmCommand::Stop { generation: g, done: None } if g == generation),
                    "{stop:?}"
                );
                let took = t0.elapsed();
                assert!(took >= wd / 2, "{took:?}");
                assert_eq!(t.metrics.release_all.get("watchdog"), 1);
                assert_eq!(t.metrics.disconnects.total(), 1, "one close, one cause");
                assert_eq!(t.metrics.disconnects.get("stream_corrupt"), 1);
                assert!(t.quiet(Duration::from_millis(100)).await, "a second Disconnect");
                assert!(rx.try_recv().is_err(), "answered before the session stopped");
            })
            .await;
    }

    /// DC6: the tick samples IronRDP's suppression flag into the core: held
    /// past the debounce after a KVM frame → ReleaseAll(suppression).
    #[tokio::test(flavor = "current_thread")]
    async fn the_tick_samples_suppression() {
        LocalSet::new()
            .run_until(async {
                let hold = Duration::from_millis(200);
                let mut t = shell(|c| c.suppress_debounce = hold);
                let generation = t.start();
                t.event().await;
                t.first_idr(generation).await;
                t.event().await;
                let t0 = Instant::now();
                t.suppressed.store(true, Ordering::SeqCst);
                while t.metrics.release_all.get("suppression") == 0 {
                    assert!(t0.elapsed() < hold * 5, "no release within 5× the debounce");
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                assert!(t0.elapsed() >= hold / 2, "{:?}", t0.elapsed());
            })
            .await;
    }

    /// DC6 through shell and core together: each probe reads the handle
    /// first (the previous probe's answer); the core keeps a generation's
    /// first read as its reference only. A stale 900 left by the last
    /// connection, then answers of 2 ms, give a 2 ms baseline, and a
    /// standing queue around 700 ms closes the gate (§6.6). (With the rule
    /// applied in the shell too, 2 became the reference, ~700 the baseline,
    /// and the gate never closed.)
    #[tokio::test(flavor = "current_thread")]
    async fn a_stale_handle_then_live_answers_close_the_standing_delay_gate() {
        LocalSet::new()
            .run_until(async {
                let mut t = shell(|c| c.rtt_probe_interval = Duration::from_millis(100));
                t.rtt.store(900, Ordering::SeqCst); // the last connection's answer
                let generation = t.start();
                t.first_idr(generation).await;
                until("the first IDR", || t.metrics.frames_sent.get() == 1).await;
                t.ack(0); // keep the soft gate out of the way
                let mut first = true;
                for v in [2, 2, 2, 690, 700, 710, 720, 705, 695, 715] {
                    while !matches!(t.event().await, ServerEvent::AutoDetectRttRequest) {}
                    if first {
                        assert_eq!(
                            t.metrics.autodetect_rtt_ms.get(),
                            0,
                            "the stale read was used as a sample"
                        );
                        first = false;
                    }
                    t.rtt.store(v, Ordering::SeqCst); // the next probe reads it
                }
                while !matches!(t.event().await, ServerEvent::AutoDetectRttRequest) {}
                let sd = t.metrics.standing_delay_ms.get();
                assert!(
                    sd >= 500,
                    "baseline 2 ms, median ~705 ms: standing delay {sd}"
                );
                let Input::Au(au) = rig::au(true, false) else {
                    unreachable!()
                };
                t.kvm.send(KvmEvent::Au { generation, au }).await.unwrap();
                until("a standing-delay drop", || {
                    t.metrics.frames_dropped.get("standing_delay") > 0
                })
                .await;
            })
            .await;
    }

    /// §6.5 through the shell: burst AUs leave in chunks of `burst_chunk`
    /// (8), one `ServerEvent` each. The shell steps `Suppress` and `Backlog`
    /// before every AU (DC6); those samples must not split a chunk.
    ///
    /// A tick does flush a partial chunk (the last 4 leave at one), and
    /// since I1 a due tick goes ahead of queued AUs; so the burst is queued
    /// before the shell first runs — it runs right after its first,
    /// immediate tick — and the tick is slowed to 250 ms, leaving no tick
    /// inside the burst.
    #[tokio::test(flavor = "current_thread")]
    async fn burst_aus_leave_in_chunks_of_burst_chunk() {
        LocalSet::new()
            .run_until(async {
                let tick = Duration::from_millis(250);
                let mut t = spawn(|_| {}, |s| s.with_tick(tick));
                let generation = t.start();
                t.queue_first_idr_and_burst(generation, 20);
                assert!(egfx(&t.event().await).is_some(), "the Setup");
                assert!(egfx(&t.event().await).is_some(), "the IDR");
                let mut events = 0;
                while !t.quiet(tick * 2).await {
                    events += 1;
                }
                assert_eq!(
                    events,
                    20_usize.div_ceil(8),
                    "8 + 8 + the last 4 at the next tick"
                );
                assert_eq!(t.metrics.frames_sent.get(), 21);
            })
            .await;
    }

    /// §6.5 (m3): after each burst chunk the shell yields, so the RDP
    /// thread's other work — IronRDP writing the chunk, reading client
    /// input — runs before the next chunk is stepped. The test body is that
    /// other work here: it sees chunk k when exactly 1 + 8k frames have been
    /// sent. (Without the yield the whole burst is stepped first: 21.)
    #[tokio::test(flavor = "current_thread")]
    async fn the_shell_yields_between_burst_chunks() {
        LocalSet::new()
            .run_until(async {
                let tick = Duration::from_millis(250);
                let mut t = spawn(|_| {}, |s| s.with_tick(tick));
                let generation = t.start();
                t.queue_first_idr_and_burst(generation, 20);
                let mut seen = Vec::new();
                for _ in 0..4 {
                    // The Setup, the IDR, then the first two chunks.
                    assert!(egfx(&t.event().await).is_some());
                    seen.push(t.metrics.frames_sent.get());
                }
                assert_eq!(
                    &seen[2..],
                    [9, 17],
                    "frames sent as each chunk left: {seen:?}"
                );
            })
            .await;
    }

    /// DC6 (m2): the shell samples the write counter before each AU, not
    /// only at ticks. With a 1-byte `backlog_limit` the Setup's bytes shut
    /// the backlog gate until their write is fed in; IronRDP writes them,
    /// and the IDR that follows must see it — with the tick slowed to an
    /// hour, nothing else can feed it.
    #[tokio::test(flavor = "current_thread")]
    async fn the_write_counter_is_sampled_before_each_au() {
        LocalSet::new()
            .run_until(async {
                let mut t = spawn(
                    |c| c.flow.backlog_limit = 1,
                    |s| s.with_tick(Duration::from_secs(3600)),
                );
                let generation = t.start();
                let setup = egfx(&t.event().await).expect("the Setup").1;
                t.counter.fetch_add(setup, Ordering::SeqCst); // IronRDP wrote it
                t.first_idr(generation).await;
                let idr = tokio::time::timeout(Duration::from_secs(2), t.events.recv())
                    .await
                    .expect("the IDR was gated on a backlog already written")
                    .unwrap();
                assert!(egfx(&idr).is_some(), "{idr:?}");
                assert_eq!(t.metrics.frames_dropped.get("backlog_gate"), 0);
            })
            .await;
    }

    /// This thread's CPU time (Linux: `/proc/thread-self/schedstat`, its
    /// first field is nanoseconds on CPU); `None` on a kernel built without
    /// schedstat.
    #[cfg(target_os = "linux")]
    fn thread_cpu() -> Option<Duration> {
        let stat = std::fs::read_to_string("/proc/thread-self/schedstat").ok()?;
        let ns = stat.split_whitespace().next()?.parse().ok()?;
        Some(Duration::from_nanos(ns))
    }

    /// m4: once the KVM stream closes (the KVM actor ends at
    /// `KvmCommand::Shutdown`), the shell stops polling it: the RDP thread
    /// does not spin on the closed stream, and the ticks still run — here
    /// a suppression release lands. (Unguarded, the closed stream is ready
    /// on every poll; since I1 the tick still goes first, so the cost is the
    /// spin, measured as this thread's CPU time.)
    ///
    /// Parked #7 (PC14 n2): the release is waited for, bounded, rather than
    /// assumed after a fixed sleep a slow tick can outlast; the spin is then
    /// measured over a fixed window. Without schedstat there is nothing to
    /// measure, so the test skips rather than panics.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn a_closed_kvm_stream_is_not_polled_again() {
        if thread_cpu().is_none() {
            eprintln!("skipped: no /proc/thread-self/schedstat to measure CPU time with");
            return;
        }
        LocalSet::new()
            .run_until(async {
                let mut t = shell(|c| c.suppress_debounce = Duration::from_millis(100));
                let generation = t.start();
                t.event().await; // the Setup
                t.first_idr(generation).await;
                t.event().await; // a KVM frame went out: suppression counts (§6.6)
                t.kvm = mpsc::channel(1).0; // its only sender gone: the stream closes
                t.suppressed.store(true, Ordering::SeqCst);
                let released = tokio::time::timeout(Duration::from_secs(5), async {
                    while t.metrics.release_all.get("suppression") == 0 {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await;
                assert!(released.is_ok(), "no tick ran once the KVM stream closed");
                let (Some(cpu0), wall0) = (thread_cpu(), Instant::now()) else {
                    return;
                };
                tokio::time::sleep(Duration::from_millis(300)).await;
                let (Some(cpu1), wall) = (thread_cpu(), wall0.elapsed()) else {
                    return;
                };
                let cpu = cpu1.saturating_sub(cpu0);
                assert_eq!(t.metrics.release_all.get("suppression"), 1);
                assert!(
                    cpu < wall / 3,
                    "the RDP thread spun on the closed KVM stream: {cpu:?} of CPU in {wall:?}"
                );
            })
            .await;
    }

    /// A callback from another connection's GFX handle (a Preempt
    /// candidate's slot) is dropped: no Setup, no ack accounting, and its
    /// channel closing is not this session's cause.
    #[tokio::test(flavor = "current_thread")]
    async fn a_stale_slots_callbacks_are_dropped() {
        LocalSet::new()
            .run_until(async {
                let mut t = shell(|_| {});
                t.session_start();
                let adv = encode_vec(&GfxPdu::CapabilitiesAdvertise(CapabilitiesAdvertisePdu(
                    rig::census_caps(),
                )))
                .unwrap();
                t.gfx.lock().unwrap().process(CHAN, &adv).unwrap();
                t.rdp
                    .send(RdpInput::OnReady {
                        slot: 2,
                        version: 0x8_0105,
                    })
                    .unwrap();
                t.rdp
                    .send(RdpInput::FrameAck {
                        slot: 2,
                        frame_id: 0,
                        queue_depth: 0,
                    })
                    .unwrap();
                t.rdp.send(RdpInput::GfxClosed { slot: 2 }).unwrap();
                assert!(
                    t.quiet(Duration::from_millis(300)).await,
                    "a stale slot's on_ready ran a Setup, or its close a Disconnect"
                );
                assert_eq!(t.metrics.frames_acked.get(), 0);
                assert_eq!(t.metrics.disconnects.total(), 0);
                t.rdp
                    .send(RdpInput::OnReady {
                        slot: 1,
                        version: 0x8_0105,
                    })
                    .unwrap();
                assert!(egfx(&t.event().await).is_some(), "the current slot's Setup");
            })
            .await;
    }

    /// DC4 (PC13 m3 → here): `on_connection_info` pushes `SessionStart` and
    /// sends `Start` on the RDP thread, and the KVM side may answer `Start`
    /// before the shell next runs — both words are then queued at once. The
    /// `biased` select steps the RDP side first, so the KVM's first word for
    /// the generation (here an immediate auth refusal) finds its session.
    /// Taken the other way round it is dropped as another generation's, and
    /// the client waits with no picture and no cause.
    #[tokio::test(flavor = "current_thread")]
    async fn a_kvm_event_never_overtakes_its_sessions_start() {
        LocalSet::new()
            .run_until(async {
                let mut w = wired(); // the shell has not run yet
                let _chan = Egfx::build(&w.factory);
                w.h.on_connection_info(&info());
                // The KVM side hears Start and answers before the shell runs.
                let Ok(KvmCommand::Start { generation }) = w.cmds.try_recv() else {
                    panic!("no Start")
                };
                w.kvm
                    .try_send(KvmEvent::UpstreamFatal {
                        generation,
                        cause: Cause::KvmAuthFailed,
                    })
                    .unwrap();
                let ev = tokio::time::timeout(Duration::from_secs(2), w.events.recv())
                    .await
                    .expect("the KVM's word overtook its session's start and was dropped")
                    .unwrap();
                assert!(
                    matches!(
                        ev,
                        ServerEvent::Disconnect(ErrorInfo::ProtocolIndependentCode(
                            P::ServerInsufficientPrivileges
                        ))
                    ),
                    "{ev:?}"
                );
                assert_eq!(w.metrics.disconnects.get("kvm_auth_failed"), 1);
            })
            .await;
    }

    /// PC13 carry: IronRDP runs `on_close` at every connection's teardown,
    /// just before `on_disconnected`. A plain client disconnect from a live
    /// session is therefore not a cause: no close, no `Disconnect`, and
    /// `disconnects{no_avc420}` stays 0. (Without the generation filter in
    /// the `GfxClosed` arm every disconnect counted as `no_avc420`.)
    #[tokio::test(flavor = "current_thread")]
    async fn a_plain_client_disconnect_is_not_counted_as_no_avc420() {
        LocalSet::new()
            .run_until(async {
                let mut w = wired();
                let (chan, _) = w.live().await;
                w.teardown(chan);
                w.settled().await;
                assert_eq!(
                    w.metrics.disconnects.get("no_avc420"),
                    0,
                    "a plain disconnect was counted as no_avc420"
                );
                assert_eq!(w.metrics.disconnects.total(), 0);
                assert_eq!(w.metrics.release_all.get("closing"), 0);
                while let Ok(ev) = w.events.try_recv() {
                    assert!(!matches!(ev, ServerEvent::Disconnect(_)), "{ev:?}");
                }
            })
            .await;
    }

    /// PC11 n2 through the wiring: a client that closes its EGFX channel
    /// mid-session (a DVC Close PDU) is closed at once as `no_avc420` —
    /// release, then `Disconnect` with its ErrorInfo — and the connection's
    /// teardown that follows does not count it again.
    #[tokio::test(flavor = "current_thread")]
    async fn a_mid_session_egfx_close_closes_the_session_as_no_avc420() {
        LocalSet::new()
            .run_until(async {
                let mut w = wired();
                let (mut chan, _) = w.live().await;
                chan.close();
                loop {
                    match recv(&mut w.events).await {
                        ServerEvent::Disconnect(ErrorInfo::ProtocolIndependentCode(
                            P::ServerDeniedConnection,
                        )) => break,
                        ServerEvent::Egfx(_) => {}
                        other => panic!("{other:?}"),
                    }
                }
                assert_eq!(w.metrics.disconnects.get("no_avc420"), 1);
                assert_eq!(w.metrics.release_all.get("closing"), 1);
                w.teardown(chan);
                w.settled().await;
                assert_eq!(
                    w.metrics.disconnects.get("no_avc420"),
                    1,
                    "the teardown counted the close again"
                );
                assert_eq!(w.metrics.disconnects.total(), 1);
            })
            .await;
    }

    /// §8, §6.9: a `Fatal` from this session's CLIPRDR backend closes it —
    /// release (closing), then `Disconnect` with 0x7 — counted once, by
    /// the pump's `close` (D17).
    #[tokio::test(flavor = "current_thread")]
    async fn a_clipboard_oversize_from_this_sessions_backend_closes_it() {
        LocalSet::new()
            .run_until(async {
                let mut t = shell(|_| {});
                t.start();
                t.event().await; // the Setup
                t.rdp
                    .send(RdpInput::Fatal {
                        slot: 1,
                        cause: Cause::ClipboardOversize,
                    })
                    .unwrap();
                match t.event().await {
                    ServerEvent::Disconnect(ErrorInfo::ProtocolIndependentCode(
                        P::ServerDeniedConnection,
                    )) => {}
                    other => panic!("{other:?}"),
                }
                assert_eq!(t.metrics.disconnects.get("clipboard_oversize"), 1);
                assert_eq!(t.metrics.disconnects.total(), 1);
                assert_eq!(t.metrics.release_all.get("closing"), 1);
            })
            .await;
    }

    /// §4.3, design decision 8: a `Fatal` from another clip slot (a stale
    /// or rival connection's backend) or for an ended generation (read
    /// after `on_disconnected`) is dropped, as `GfxClosed` is; and the
    /// clipboard's other words never end the session.
    #[tokio::test(flavor = "current_thread")]
    async fn a_stale_slots_or_an_ended_sessions_clipboard_fatal_is_dropped() {
        LocalSet::new()
            .run_until(async {
                let mut t = shell(|_| {});
                let generation = t.start();
                t.event().await; // the Setup
                for slot in [0, 2, u64::MAX] {
                    t.rdp
                        .send(RdpInput::Fatal {
                            slot,
                            cause: Cause::ClipboardOversize,
                        })
                        .unwrap();
                }
                // This session's other clipboard words reach the input core
                // (Task 4.1), never the session's end.
                t.rdp
                    .send(RdpInput::ClipboardAvailable {
                        slot: 1,
                        offer: Offer::detached(true),
                    })
                    .unwrap();
                t.rdp
                    .send(RdpInput::ClipboardText {
                        slot: 1,
                        bytes: vec![0x41, 0],
                        answer: Answer::detached(),
                    })
                    .unwrap();
                t.rdp
                    .send(RdpInput::ClipboardFailed {
                        slot: 1,
                        answer: Answer::detached(),
                    })
                    .unwrap();
                assert!(
                    t.quiet(Duration::from_millis(300)).await,
                    "another slot's clipboard closed the session"
                );
                assert_eq!(t.metrics.disconnects.total(), 0);
                t.gens.end(); // on_disconnected ran; its SessionStop not yet sent
                t.rdp
                    .send(RdpInput::Fatal {
                        slot: 1,
                        cause: Cause::ClipboardOversize,
                    })
                    .unwrap();
                assert!(
                    t.quiet(Duration::from_millis(300)).await,
                    "an ended generation's clipboard sent a Disconnect"
                );
                assert_eq!(t.metrics.disconnects.total(), 0);
                assert_eq!(t.metrics.release_all.get("closing"), 0);
                t.rdp.send(RdpInput::SessionStop { generation }).unwrap();
            })
            .await;
    }

    /// Task 4.1: the shell tells the input core of each session and feeds
    /// it this session's clipboard words — availability, an answer, a
    /// failure, the answers lost behind one, the oversize answer it closes
    /// the session for — and drops another slot's (its place freed).
    #[tokio::test(flavor = "current_thread")]
    async fn this_sessions_clipboard_words_reach_the_input_core() {
        LocalSet::new()
            .run_until(async {
                let mut t = shell(|_| {});
                t.start();
                t.event().await; // the Setup
                let m = t.metrics.clone();
                let chord = |input: &InputShared, down: bool| {
                    for code in [0x1D, 0x38, 0x2A, 0x2F] {
                        input.keyboard(if down {
                            KeyboardEvent::Pressed {
                                code,
                                extended: false,
                            }
                        } else {
                            KeyboardEvent::Released {
                                code,
                                extended: false,
                            }
                        });
                    }
                };
                let unasked = |n| {
                    let m = m.clone();
                    move || m.clipboard_discarded.get("unasked") == n
                };
                // Another slot's offer is dropped: the chord finds no text.
                t.rdp
                    .send(RdpInput::ClipboardAvailable {
                        slot: 2,
                        offer: Offer::detached(true),
                    })
                    .unwrap();
                let marker = || RdpInput::ClipboardText {
                    slot: 1,
                    bytes: vec![0x41, 0],
                    answer: Answer::detached(),
                };
                t.rdp.send(marker()).unwrap();
                until("an unasked answer", unasked(1)).await;
                chord(&t.input, true);
                chord(&t.input, false);
                assert_eq!(m.paste_events.get("no_text"), 1);
                // This slot's offer is this session's.
                t.rdp
                    .send(RdpInput::ClipboardAvailable {
                        slot: 1,
                        offer: Offer::detached(true),
                    })
                    .unwrap();
                t.rdp.send(marker()).unwrap();
                until("an unasked answer", unasked(2)).await;
                chord(&t.input, true);
                assert_eq!(m.paste_events.get("started"), 1);
                // A failure ends the paste at once.
                t.rdp
                    .send(RdpInput::ClipboardFailed {
                        slot: 1,
                        answer: Answer::detached(),
                    })
                    .unwrap();
                until("the paste's abort", || {
                    m.paste_events.get("aborted_clipboard_failed") == 1
                })
                .await;
                chord(&t.input, false);
                // An answer types; a stale slot's answer is dropped first.
                chord(&t.input, true);
                t.rdp
                    .send(RdpInput::ClipboardText {
                        slot: 2,
                        bytes: vec![0x41, 0],
                        answer: Answer::detached(),
                    })
                    .unwrap();
                t.rdp
                    .send(RdpInput::ClipboardText {
                        slot: 1,
                        bytes: vec![0x68, 0, 0x69, 0],
                        answer: Answer::detached(),
                    })
                    .unwrap();
                chord(&t.input, false); // typing begins once the text is in
                until("the answer typed", || m.paste_events.get("done") == 1).await;
                assert_eq!(m.clipboard_discarded.total(), 2, "the stale answer counted");
                // The oversize answer ends the paste as `oversize`, then the
                // session.
                chord(&t.input, true);
                t.rdp
                    .send(RdpInput::Fatal {
                        slot: 1,
                        cause: Cause::ClipboardOversize,
                    })
                    .unwrap();
                match t.event().await {
                    ServerEvent::Disconnect(_) => {}
                    other => panic!("{other:?}"),
                }
                assert_eq!(m.paste_events.get("oversize"), 1);
            })
            .await;
    }

    /// PD8 review I1, the Preempt ordering: the evicted session's backend
    /// sends `Fatal`, then IronRDP runs that session's `on_disconnected`
    /// and the winner's `on_connection_info` before the shell reads it. A
    /// generation *is* current by then — the winner's — but not the link's:
    /// no close and no `clipboard_oversize` counted for a session the
    /// client left (D17). (A gate asking "is any generation current" passes
    /// every other case here.)
    #[tokio::test(flavor = "current_thread")]
    async fn an_evicted_sessions_fatal_read_after_the_winner_began_is_dropped() {
        LocalSet::new()
            .run_until(async {
                let mut t = shell(|_| {});
                t.start();
                t.event().await; // the Setup
                t.rdp
                    .send(RdpInput::Fatal {
                        slot: 1,
                        cause: Cause::ClipboardOversize,
                    })
                    .unwrap();
                t.gens.end(); // the evicted session's on_disconnected
                t.gens.begin(); // the winner's on_connection_info, its SessionStart not yet read
                assert!(t.quiet(Duration::from_millis(300)).await);
                assert_eq!(t.metrics.disconnects.total(), 0);
                assert_eq!(t.metrics.release_all.get("closing"), 0);
            })
            .await;
    }

    /// Design decision 8 through the wiring: the backend IronRDP built for
    /// this connection is the one `on_connection_info` binds, so an
    /// oversize answer from it closes the session — and one from an
    /// earlier connection's backend (built, then the connection never got
    /// a session) does not.
    #[tokio::test(flavor = "current_thread")]
    async fn an_oversize_answer_closes_only_the_session_it_belongs_to() {
        LocalSet::new()
            .run_until(async {
                let mut w = wired();
                let mut stale = w.clips.build_cliprdr_backend();
                let mut ours = w.clips.build_cliprdr_backend();
                let (chan, _) = w.live().await;
                let big = || FormatDataResponse::new_data(vec![0x41; CLIP_MAX + 1]);
                stale.on_format_data_response(big());
                assert!(
                    tokio::time::timeout(Duration::from_millis(300), w.events.recv())
                        .await
                        .is_err(),
                    "a stale backend's answer closed the session"
                );
                assert_eq!(w.metrics.disconnects.total(), 0);
                ours.on_format_data_response(big());
                loop {
                    match recv(&mut w.events).await {
                        ServerEvent::Disconnect(ErrorInfo::ProtocolIndependentCode(
                            P::ServerDeniedConnection,
                        )) => break,
                        ServerEvent::Egfx(_) => {}
                        other => panic!("{other:?}"),
                    }
                }
                assert_eq!(w.metrics.disconnects.get("clipboard_oversize"), 1);
                w.teardown(chan);
                w.settled().await;
                assert_eq!(w.metrics.disconnects.total(), 1);
            })
            .await;
    }

    /// D17 through the wiring: IronRDP can process an oversize answer and
    /// then the client's disconnect before the shell next runs. The
    /// `Fatal` is then read after `on_disconnected` ended its generation:
    /// no close, no `Disconnect`, no `clipboard_oversize` counted for a
    /// session the client ended.
    #[tokio::test(flavor = "current_thread")]
    async fn an_oversize_read_after_its_session_ended_is_not_counted() {
        LocalSet::new()
            .run_until(async {
                let mut w = wired();
                let mut ours = w.clips.build_cliprdr_backend();
                let (chan, _) = w.live().await;
                ours.on_format_data_response(FormatDataResponse::new_data(vec![
                    0x41;
                    CLIP_MAX + 1
                ]));
                w.teardown(chan); // before the shell reads the Fatal
                w.settled().await;
                assert_eq!(
                    w.metrics.disconnects.total(),
                    0,
                    "a disconnect was counted for a session the client ended"
                );
                assert_eq!(w.metrics.release_all.get("closing"), 0);
                while let Ok(ev) = w.events.try_recv() {
                    assert!(!matches!(ev, ServerEvent::Disconnect(_)), "{ev:?}");
                }
            })
            .await;
    }

    /// PD9 carry 3 (m2) through the wiring: a flood of answers from this
    /// connection's real backend, before the shell runs, is one word on the
    /// pump's channel; the shell feeds the input core that answer and the
    /// ones dropped behind it (counted `in_flight`, and answers all the
    /// same — none was asked for, so the one with text is `unasked`); its
    /// place is free again once the shell took it.
    #[tokio::test(flavor = "current_thread")]
    async fn a_backends_answer_flood_reaches_the_input_core_bounded() {
        LocalSet::new()
            .run_until(async {
                let mut w = wired();
                let mut ours = w.clips.build_cliprdr_backend();
                let (chan, _) = w.live().await;
                for _ in 0..1_000 {
                    ours.on_format_data_response(FormatDataResponse::new_unicode_string("x"));
                }
                let m = w.metrics.clone();
                until("the answer and the 999 behind it", || {
                    m.clipboard_discarded.get("unasked") == 1
                        && m.clipboard_discarded.get("in_flight") == 999
                })
                .await;
                ours.on_format_data_response(FormatDataResponse::new_error());
                until("the next answer, forwarded", || {
                    m.clipboard_discarded.get("unasked") == 2
                })
                .await;
                assert_eq!(m.clipboard_discarded.get("in_flight"), 999);
                w.teardown(chan);
                w.settled().await;
            })
            .await;
    }

    /// PD9 review I3: the shell feeds a word's own answer before the ones
    /// the backend dropped behind it — the order the client sent them.
    /// Paste 1 times out with its request outstanding; paste 2 asks; paste
    /// 1's late answer and paste 2's arrive before the shell runs — one word
    /// in flight, one lost behind it. The late answer is discarded (`late`),
    /// paste 2's lost answer ends it at once, and nothing is typed. Reversed,
    /// "old" would answer paste 2 and be typed. The same for a late failure.
    #[tokio::test(flavor = "current_thread")]
    async fn a_late_answer_and_the_one_lost_behind_it_keep_their_order() {
        for failed in [false, true] {
            LocalSet::new()
                .run_until(async {
                    let mut w = wired();
                    let mut ours = w.clips.build_cliprdr_backend();
                    let (chan, _) = w.live().await;
                    let m = w.metrics.clone();
                    let keys = |down: bool| {
                        for code in [0x1D, 0x38, 0x2A, 0x2F] {
                            w.input.keyboard(if down {
                                KeyboardEvent::Pressed {
                                    code,
                                    extended: false,
                                }
                            } else {
                                KeyboardEvent::Released {
                                    code,
                                    extended: false,
                                }
                            });
                        }
                    };
                    ours.on_remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]);
                    tokio::time::sleep(Duration::from_millis(20)).await; // the shell takes it
                    keys(true); // paste 1 asks
                    assert_eq!(m.paste_events.get("started"), 1, "failed: {failed}");
                    tokio::time::sleep(WIRED_WAIT + Duration::from_millis(50)).await;
                    keys(false); // paste 1 ends unanswered
                    assert_eq!(
                        m.paste_events.get("aborted_modifier_wait"),
                        1,
                        "failed: {failed}"
                    );
                    keys(true); // paste 2 asks
                    // Before the shell runs: paste 1's late answer, then 2's.
                    ours.on_format_data_response(if failed {
                        FormatDataResponse::new_error()
                    } else {
                        FormatDataResponse::new_unicode_string("old")
                    });
                    ours.on_format_data_response(FormatDataResponse::new_unicode_string("new"));
                    until("both answers", || {
                        m.clipboard_discarded.get("in_flight") == 1
                    })
                    .await;
                    assert_eq!(m.clipboard_discarded.get("late"), 1, "failed: {failed}");
                    assert_eq!(m.paste_aborts(), 2, "failed: {failed}");
                    keys(false);
                    let mut typed = Vec::new();
                    loop {
                        if w.h.hid.take_release() {
                            continue;
                        }
                        let Some(f) = w.h.hid.next_frame() else {
                            break;
                        };
                        if let kvm_proto::hid::HidFrame::Keyboard { keys, .. } = f
                            && keys[0] != 0
                        {
                            typed.push(keys[0]);
                        }
                    }
                    assert!(typed.is_empty(), "failed: {failed}: typed {typed:02x?}");
                    assert_eq!(m.paste_events.get("done"), 0);
                    w.teardown(chan);
                    w.settled().await;
                })
                .await;
        }
    }
    /// PC17 (found by L2's quick-reconnect case): a client re-advertises
    /// and disconnects at once. IronRDP runs the re-advertise's `on_ready`,
    /// then the teardown's `on_close` and `on_disconnected`, all before the
    /// shell next runs, so the shell reads that `OnReady` after its
    /// generation has ended. It is not a cause: no Setup on the closed
    /// channel — which IronRDP refuses, m7's `no_avc420` — no close, and no
    /// bridge-initiated disconnect counted for a session the client ended.
    #[tokio::test(flavor = "current_thread")]
    async fn an_on_ready_read_after_its_generation_ended_is_not_a_cause() {
        LocalSet::new()
            .run_until(async {
                let mut w = wired();
                let (mut chan, _) = w.live().await;
                chan.advertise();
                w.teardown(chan);
                w.settled().await;
                assert_eq!(
                    w.metrics.disconnects.get("no_avc420"),
                    0,
                    "a re-advertise read after the teardown was counted as no_avc420"
                );
                assert_eq!(w.metrics.disconnects.total(), 0);
                assert_eq!(w.metrics.release_all.get("closing"), 0);
                while let Ok(ev) = w.events.try_recv() {
                    assert!(!matches!(ev, ServerEvent::Disconnect(_)), "{ev:?}");
                }
            })
            .await;
    }

    /// PC17: the same window at a reactivation — IronRDP's `updates()` after
    /// a resize, then the client's teardown, both before the shell next
    /// runs. The `ReactivationComplete` it would step runs the Setup on the
    /// closed channel; read after the generation ended, it is not a cause.
    #[tokio::test(flavor = "current_thread")]
    async fn a_reactivation_read_after_its_generation_ended_is_not_a_cause() {
        LocalSet::new()
            .run_until(async {
                let mut w = wired();
                let (chan, generation) = w.live().await;
                let Input::SpsChanged { class, params } = rig::sps(ParamClass::Resize, P480) else {
                    unreachable!()
                };
                w.kvm
                    .send(KvmEvent::SpsChanged {
                        generation,
                        class,
                        params,
                    })
                    .await
                    .unwrap();
                // The resize is stepped: the pump waits for the reactivation.
                until("the resize to be stepped", || {
                    w.kvm.capacity() == w.kvm.max_capacity()
                })
                .await;
                tokio::task::yield_now().await;
                w.rdp.send(RdpInput::Updates).unwrap();
                w.teardown(chan);
                w.settled().await;
                assert_eq!(
                    w.metrics.disconnects.get("no_avc420"),
                    0,
                    "a reactivation read after the teardown was counted as no_avc420"
                );
                assert_eq!(w.metrics.disconnects.total(), 0);
            })
            .await;
    }

    /// PC17 I4: IronRDP writes EGFX events and display updates from two
    /// futures it runs concurrently (`dispatch_events`, `dispatch_display`),
    /// so a `DisplayUpdate::Resize` could overtake EGFX the pump sent
    /// before it — on a first Setup, the slate after its DeactivateAll.
    /// The resize waits until IronRDP's write counter shows every batch
    /// sent before it written; here the test is IronRDP. The tick is slowed
    /// to an hour: only the held resize's own re-read releases it.
    #[tokio::test(flavor = "current_thread")]
    async fn a_resize_waits_until_the_egfx_sent_before_it_is_written() {
        LocalSet::new()
            .run_until(async {
                let mut t = spawn(|_| {}, |s| s.with_tick(Duration::from_secs(3600)));
                let (dtx, _drx) = mpsc::unbounded_channel();
                let mut updates = crate::rdp::display::BridgeDisplay::new(t.display.clone(), dtx)
                    .updates()
                    .await
                    .unwrap();
                let generation = t.start();
                let mut sent = egfx(&t.event().await).unwrap().1; // the Setup
                t.first_idr(generation).await;
                sent += egfx(&t.event().await).unwrap().1; // the IDR
                let Input::SpsChanged { class, params } = rig::sps(ParamClass::Resize, P480) else {
                    unreachable!()
                };
                t.kvm
                    .send(KvmEvent::SpsChanged {
                        generation,
                        class,
                        params,
                    })
                    .await
                    .unwrap();
                let early =
                    tokio::time::timeout(Duration::from_millis(300), updates.next_update()).await;
                assert!(
                    early.is_err(),
                    "the resize went out before the EGFX sent ahead of it was written"
                );
                t.counter.store(sent - 1, Ordering::SeqCst); // all but the last byte
                let early =
                    tokio::time::timeout(Duration::from_millis(100), updates.next_update()).await;
                assert!(early.is_err(), "the resize went out a byte early");
                t.counter.store(sent, Ordering::SeqCst);
                match tokio::time::timeout(Duration::from_secs(2), updates.next_update())
                    .await
                    .expect("the resize was held after its EGFX was written")
                    .unwrap()
                {
                    Some(DisplayUpdate::Resize(s)) => {
                        assert_eq!((s.width, s.height), (854, 480));
                    }
                    other => panic!("{other:?}"),
                }
                assert_eq!(t.display.size(), (854, 480));
            })
            .await;
    }

    /// PC17 n1: a client that stops reading during a resize keeps it held
    /// for the session's life — nothing ends a session in WaitReactivation
    /// (§6.4, §6.6: the stall timer is frozen there) — so the held resize's
    /// re-read backs off, 5 ms doubling to 250 ms, instead of waking the RDP
    /// thread 200 times a second: a handful of re-reads in the first second,
    /// then four a second at the cap. Once the counter moves, the resize goes
    /// at the next re-read, and the next resize held starts again at 5 ms.
    /// The tick is slowed to an hour, so every loop turn here is a re-read
    /// (or the input that held a resize).
    #[tokio::test(flavor = "current_thread")]
    async fn a_held_resize_backs_off_its_re_read() {
        LocalSet::new()
            .run_until(async {
                let turns = Arc::new(AtomicU64::new(0));
                let c = turns.clone();
                let mut t = spawn(
                    |_| {},
                    move |s| s.with_tick(Duration::from_secs(3600)).with_turns(c),
                );
                let (dtx, _drx) = mpsc::unbounded_channel();
                let mut updates = crate::rdp::display::BridgeDisplay::new(t.display.clone(), dtx)
                    .updates()
                    .await
                    .unwrap();
                let generation = t.start();
                let mut sent = egfx(&t.event().await).unwrap().1;
                t.first_idr(generation).await;
                sent += egfx(&t.event().await).unwrap().1;
                let Input::SpsChanged { class, params } = rig::sps(ParamClass::Resize, P480) else {
                    unreachable!()
                };
                t.kvm
                    .send(KvmEvent::SpsChanged {
                        generation,
                        class,
                        params,
                    })
                    .await
                    .unwrap();
                until("the resize to be held", || t.display.size() == (854, 480)).await;
                let turns_in = |d: Duration| {
                    let turns = turns.clone();
                    let before = turns.load(Ordering::SeqCst);
                    async move {
                        tokio::time::sleep(d).await;
                        turns.load(Ordering::SeqCst) - before
                    }
                };
                let n = turns_in(Duration::from_secs(1)).await;
                assert!(
                    n <= 12,
                    "{n} loop turns in the first second of a held resize"
                );
                assert!(n >= 3, "the held resize was not re-read: {n} turns");
                let n = turns_in(Duration::from_secs(1)).await;
                assert!(
                    (2..=6).contains(&n),
                    "{n} re-reads in the second second (the 250 ms cap: 4)"
                );
                t.counter.store(sent, Ordering::SeqCst);
                let r = tokio::time::timeout(Duration::from_millis(600), updates.next_update())
                    .await
                    .expect("the resize was not sent within one backed-off re-read");
                assert!(matches!(r, Ok(Some(DisplayUpdate::Resize(_)))), "{r:?}");
                // The reactivation (a Setup at 854×480), then a resize back: a
                // new hold re-reads from 5 ms again.
                t.rdp.send(RdpInput::Updates).unwrap();
                assert!(egfx(&t.event().await).is_some(), "the reactivation's Setup");
                let Input::SpsChanged { class, params } = rig::sps(ParamClass::Resize, ES3) else {
                    unreachable!()
                };
                t.kvm
                    .send(KvmEvent::SpsChanged {
                        generation,
                        class,
                        params,
                    })
                    .await
                    .unwrap();
                until("the second resize to be held", || {
                    t.display.size() == (640, 360)
                })
                .await;
                let n = turns_in(Duration::from_millis(100)).await;
                assert!(
                    n >= 2,
                    "the second hold did not start at 5 ms: {n} turns in 100 ms"
                );
            })
            .await;
    }

    /// PC15 review m2: with no session the shell sleeps — no tick and no
    /// loop turn (the 50 ms tick was 354 RDP-thread wakeups in 10 s idle) —
    /// ticks while a session lives, and sleeps again once it stopped.
    #[tokio::test(flavor = "current_thread")]
    async fn the_shell_ticks_only_while_a_session_lives() {
        LocalSet::new()
            .run_until(async {
                let turns = Arc::new(AtomicU64::new(0));
                let c = turns.clone();
                let mut t = spawn(|_| {}, move |s| s.with_turns(c));
                let n = || turns.load(Ordering::SeqCst);
                tokio::time::sleep(TICK * 8).await;
                assert_eq!(n(), 0, "the shell woke with no session");
                let generation = t.start();
                t.event().await; // the Setup
                let at_start = n();
                tokio::time::sleep(TICK * 6).await;
                assert!(
                    n() >= at_start + 2,
                    "no ticks while a session lived: {}",
                    n() - at_start
                );
                t.gens.end();
                t.rdp.send(RdpInput::SessionStop { generation }).unwrap();
                tokio::time::sleep(TICK * 2).await;
                let stopped = n();
                tokio::time::sleep(TICK * 8).await;
                assert_eq!(n(), stopped, "the shell kept waking after the session");
            })
            .await;
    }

    /// PC15 review m2: gating the tick leaves every close tick-driven to its
    /// end. After an idle spell (no ticks), a session closed for shutdown
    /// whose client never answers is still aborted by the watchdog — a tick
    /// — which stops the KVM side; once the client is gone the shutdown is
    /// answered, and the shell sleeps again.
    #[tokio::test(flavor = "current_thread")]
    async fn a_close_after_an_idle_spell_still_runs_to_its_end() {
        LocalSet::new()
            .run_until(async {
                let wd = Duration::from_millis(300);
                let turns = Arc::new(AtomicU64::new(0));
                let c = turns.clone();
                let mut t = spawn(|_| {}, move |s| s.with_shutdown_watchdog(wd).with_turns(c));
                let n = || turns.load(Ordering::SeqCst);
                tokio::time::sleep(TICK * 6).await;
                assert_eq!(n(), 0, "the shell woke with no session");
                let generation = t.start();
                t.event().await; // the Setup
                assert!(matches!(t.cmd().await, KvmCommand::OpenFlv { .. }));
                let (done, mut rx) = oneshot::channel();
                t.rdp.send(RdpInput::Shutdown { done }).unwrap();
                loop {
                    if matches!(t.event().await, ServerEvent::Disconnect(_)) {
                        break;
                    }
                }
                let t0 = Instant::now();
                // The client never answers: the watchdog (a tick) aborts.
                assert!(matches!(
                    t.cmd().await,
                    KvmCommand::Stop { generation: g, done: None } if g == generation
                ));
                let took = t0.elapsed();
                assert!(took >= wd / 2 && took <= wd * 5, "{took:?}");
                assert!(rx.try_recv().is_err(), "answered before the session ended");
                // The client is gone: IronRDP's `on_disconnected`.
                t.gens.end();
                t.rdp.send(RdpInput::SessionStop { generation }).unwrap();
                tokio::time::timeout(Duration::from_secs(1), &mut rx)
                    .await
                    .expect("the shutdown was never answered")
                    .unwrap();
                tokio::time::sleep(TICK * 2).await;
                let ended = n();
                tokio::time::sleep(TICK * 8).await;
                assert_eq!(n(), ended, "the shell kept waking after the close");
            })
            .await;
    }
}
