//! The EGFX pump's sans-IO core (§4.3, §6.4–§6.6, §6.9). `step` takes one
//! input and the time, drives the `GraphicsPipelineServer` the caller has
//! locked — Setup, `send_avc420_frame` and `drain_output` in one hold — and
//! returns the commands the shell carries out. §6.4's state × input table is
//! the dispatch below (every cell is a case in Task 4.6).
use crate::hid::ReleaseTrigger;
use crate::metrics::Metrics;
use crate::msg::{Cause, FlvOrigin, Gen, KvmAu};
use crate::pump::debounce::{Debounce, Edge};
use crate::pump::flow::{Flow, Gate};
use crate::pump::idr::{IdrAction, IdrCore};
use crate::pump::slate::Slate;
use crate::pump::types::{Command, DvcBatch, Input, PumpConfig, State};
use ironrdp_egfx::pdu::Avc420Region;
use ironrdp_egfx::server::GraphicsPipelineServer;
use ironrdp_pdu::gcc::{Monitor, MonitorFlags};
use kvm_proto::video::{ParamClass, ParamSets};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct Pump {
    cfg: PumpConfig,
    metrics: Arc<Metrics>,
    slate: Option<Slate>,
    state: State,
    generation: Gen,
    started: Instant,
    /// The size `size()` reports and the next Setup uses (§5.1, §6.4).
    size: (u16, u16),
    /// `(surface id, width, height)` of the latest Setup.
    surface: Option<(u16, u16, u16)>,
    pending_size: Option<(u16, u16)>,
    return_to_paused: bool,
    /// An AVC420 `on_ready` was seen this session.
    ready_seen: bool,
    /// Any `on_ready` was seen this session: only the first negotiation
    /// without AVC420 waits for a better one (§6.7, m5).
    negotiated: bool,
    first_setup_done: bool,
    avc420_deadline: Option<Instant>,
    params: Option<ParamSets>,
    flow: Flow,
    idr: IdrCore,
    suppress: Debounce,
    suppressed: bool,
    /// A ReleaseAll already went out for the current suppression edge.
    released_for_edge: bool,
    kvm_frame_delivered: bool,
    closing: Option<(Instant, Duration)>,
    aborted: bool,
    next_probe: Option<Instant>,
    /// A burst chunk being filled (§6.5).
    batch: Option<DvcBatch>,
    /// The one reused Annex-B buffer (§6.2 ownership).
    annexb: Vec<u8>,
    /// The AUs handed to IronRDP since the last IDR on this surface, as
    /// (length, hash), and — after a `ReconnectFlv` swap — how far the
    /// candidate has replayed them (PC17 I2, N1).
    handed: Handed,
    replay_at: Option<usize>,
}

/// At most this many AUs are kept per IDR: a GOP is 60 at 30 fps on the
/// ES3 (PC17 N1).
const HANDED_RING: usize = 64;

/// What the client was sent since its last IDR: each AU as written (§6.3,
/// the SPS rewritten) by length and a 64-bit hash — never the bytes.
#[derive(Clone, Copy)]
struct Handed {
    ring: [(usize, u64); HANDED_RING],
    len: usize,
    /// More AUs than the ring holds were handed since the IDR: it is not
    /// matched at all.
    overflowed: bool,
}

impl Handed {
    const EMPTY: Handed = Handed {
        ring: [(0, 0); HANDED_RING],
        len: 0,
        overflowed: false,
    };

    fn clear(&mut self) {
        *self = Handed::EMPTY;
    }

    fn push(&mut self, key: (usize, u64)) {
        match self.ring.get_mut(self.len) {
            Some(slot) => {
                *slot = key;
                self.len = self.len.saturating_add(1);
            }
            None => self.overflowed = true,
        }
    }

    /// The `i`th AU handed since the IDR, if the ring can be matched there.
    fn at(&self, i: usize) -> Option<(usize, u64)> {
        if self.overflowed || i >= self.len {
            return None;
        }
        self.ring.get(i).copied()
    }

    /// The first entry from `i` on that is `key`.
    fn find_from(&self, i: usize, key: (usize, u64)) -> Option<usize> {
        if self.overflowed {
            return None;
        }
        (i..self.len).find(|j| self.ring.get(*j) == Some(&key))
    }
}

/// An AU's identity as written: its length and a fast 64-bit hash.
fn au_key(annex_b: &[u8]) -> (usize, u64) {
    let mut h = std::hash::DefaultHasher::new();
    std::hash::Hasher::write(&mut h, annex_b);
    (annex_b.len(), std::hash::Hasher::finish(&h))
}

impl Pump {
    #[must_use]
    pub fn new(cfg: PumpConfig, metrics: Arc<Metrics>) -> Pump {
        Pump::with_slate(cfg, metrics, Slate::embedded())
    }

    #[must_use]
    pub fn with_slate(cfg: PumpConfig, metrics: Arc<Metrics>, slate: Option<Slate>) -> Pump {
        Pump {
            flow: Flow::new(cfg.flow),
            idr: IdrCore::new(cfg.idr),
            suppress: Debounce::new(cfg.suppress_debounce),
            cfg,
            metrics,
            slate,
            state: State::Idle,
            generation: 0,
            started: Instant::now(),
            size: (0, 0),
            surface: None,
            pending_size: None,
            return_to_paused: false,
            ready_seen: false,
            negotiated: false,
            first_setup_done: false,
            avc420_deadline: None,
            params: None,
            suppressed: false,
            released_for_edge: false,
            kvm_frame_delivered: false,
            closing: None,
            aborted: false,
            next_probe: None,
            batch: None,
            annexb: Vec::new(),
            handed: Handed::EMPTY,
            replay_at: None,
        }
    }

    #[must_use]
    pub fn state(&self) -> State {
        self.state
    }

    #[must_use]
    pub fn generation(&self) -> Gen {
        self.generation
    }

    #[must_use]
    pub fn size(&self) -> (u16, u16) {
        self.size
    }

    pub fn step(
        &mut self,
        gfx: &mut GraphicsPipelineServer,
        now: Instant,
        input: Input,
    ) -> Vec<Command> {
        let mut out = Vec::new();
        // A burst chunk (§6.5) fills across consecutive burst AUs. The shell
        // samples `Suppress`, `Backlog` and acks between AUs (DC6); those
        // must not split a chunk, so they flush it only if they change the
        // state. Anything else — a live AU, a tick (every 50 ms), a session
        // or Setup input — flushes it first.
        let sample = matches!(
            &input,
            Input::Suppress(_) | Input::Backlog { .. } | Input::Rtt(_) | Input::FrameAck { .. }
        );
        if !sample && !matches!(&input, Input::Au(a) if a.au.burst) {
            self.flush_batch(&mut out);
        }
        let before = self.state;
        match input {
            Input::SessionStart { generation, size } => self.start(generation, size, now),
            Input::SessionStop { generation } => {
                if generation == self.generation {
                    self.reset();
                }
            }
            other if self.state != State::Idle => self.session_input(gfx, now, other, &mut out),
            Input::Au(_) => self.metrics.frames_dropped.inc("not_ready"),
            _ => {}
        }
        if sample
            && self.state != before
            && let Some(b) = self.batch.take()
        {
            // The chunk's frames came before the state change: send them first.
            out.insert(0, Command::SendDvc(b));
        }
        if self.state != State::Idle {
            self.gauges(gfx, now);
        }
        out
    }

    fn session_input(
        &mut self,
        gfx: &mut GraphicsPipelineServer,
        now: Instant,
        input: Input,
        out: &mut Vec<Command>,
    ) {
        match input {
            Input::UpstreamFatal(cause) => {
                self.close(now, cause, self.cfg.disconnect_watchdog, out)
            }
            Input::Shutdown { watchdog } => {
                let watchdog = watchdog.min(self.cfg.disconnect_watchdog);
                if self.state == State::Closing {
                    self.shorten_watchdog(now, watchdog);
                } else {
                    self.close(now, Cause::Shutdown, watchdog, out);
                }
            }
            Input::FrameAck {
                frame_id,
                queue_depth,
            } => {
                // §10.4 ack RTT: handed to IronRDP → acknowledged.
                if let Some(at) = self.flow.sent_at(frame_id) {
                    self.metrics
                        .ack_rtt
                        .observe(now.saturating_duration_since(at));
                }
                self.flow.on_ack(frame_id, queue_depth);
            }
            Input::Backlog { written } => self.flow.set_written(written),
            Input::Rtt(v) => {
                // Only a live sample shows: never the stale reference.
                if self.flow.rtt_sample(v) {
                    self.metrics.autodetect_rtt_ms.set(i64::from(v));
                }
            }
            Input::Tick => self.on_tick(gfx, now, out),
            Input::Au(_) if self.state == State::Closing => {
                self.metrics.frames_dropped.inc("closing")
            }
            _ if self.state == State::Closing => {}
            Input::OnReady { avc420 } => self.on_ready(gfx, now, avc420, out),
            Input::ReactivationComplete => self.on_reactivated(gfx, now, out),
            Input::Suppress(raw) => self.on_suppress(now, raw, out),
            Input::SpsChanged { class, params } => self.on_sps(now, class, params, out),
            Input::FlvOpened { origin } => self.on_flv_opened(now, origin, out),
            Input::Au(au) => self.on_au(gfx, now, au, out),
            Input::SessionStart { .. } | Input::SessionStop { .. } => {}
        }
    }

    fn start(&mut self, generation: Gen, size: (u16, u16), now: Instant) {
        self.reset();
        self.state = State::WaitReady;
        self.generation = generation;
        self.started = now;
        self.size = size;
        self.avc420_deadline = Some(now + self.cfg.avc420_timeout);
        self.next_probe = Some(now + self.cfg.rtt_probe_interval);
    }

    /// Fresh per-session state (generations never share anything, §4.3).
    fn reset(&mut self) {
        let (cfg, metrics, slate) = (self.cfg.clone(), self.metrics.clone(), self.slate.take());
        let annexb = std::mem::take(&mut self.annexb);
        *self = Pump::with_slate(cfg, metrics, slate);
        self.annexb = annexb;
    }

    fn set_state(&mut self, now: Instant, new: State, out: &mut Vec<Command>) {
        if self.state == new {
            return;
        }
        if self.state == State::NeedIdr && self.idr.resolve() {
            self.metrics.idr_cancelled.inc();
            out.push(Command::CancelIdrRequest);
        }
        self.flow
            .set_frozen(now, matches!(new, State::Paused | State::WaitReactivation));
        self.state = new;
    }

    /// Setup, or close when IronRDP refuses it (m7). IronRDP fails
    /// `create_surface` only outside Ready and Resizing: its EGFX channel was
    /// closed under us, so no picture can follow on this connection. The
    /// session must not wait in NeedIdr without the first Setup's `OpenFlv`
    /// and with nothing to time it out; no EGFX is §6.7's outcome,
    /// `no_avc420`. False when it closed.
    #[must_use]
    fn setup_or_close(
        &mut self,
        gfx: &mut GraphicsPipelineServer,
        now: Instant,
        out: &mut Vec<Command>,
    ) -> bool {
        if self.setup(gfx, now, out) {
            return true;
        }
        tracing::warn!("EGFX Setup refused: the channel is not ready; closing as no_avc420");
        self.close(now, Cause::NoAvc420, self.cfg.disconnect_watchdog, out);
        false
    }

    /// Setup (§6.4): ResetGraphics with one PRIMARY monitor (inclusive
    /// bounds), CreateSurface, MapSurfaceToOutput, the hard cap; the slate
    /// and `OpenFlv` on the connection's first Setup. False when IronRDP
    /// refused it (callers go through `setup_or_close`).
    #[must_use]
    fn setup(
        &mut self,
        gfx: &mut GraphicsPipelineServer,
        now: Instant,
        out: &mut Vec<Command>,
    ) -> bool {
        let (w, h) = self.size;
        let monitor = Monitor {
            left: 0,
            top: 0,
            right: i32::from(w).saturating_sub(1),
            bottom: i32::from(h).saturating_sub(1),
            flags: MonitorFlags::PRIMARY,
        };
        gfx.resize_with_monitors(w, h, vec![monitor]);
        let Some(sid) = gfx.create_surface(w, h) else {
            tracing::warn!("EGFX Setup failed: no surface");
            return false;
        };
        if !gfx.map_surface_to_output(sid, 0, 0) {
            return false;
        }
        gfx.set_max_frames_in_flight(self.cfg.hard_cap);
        self.surface = Some((sid, w, h));
        // A new surface has no picture: nothing on it can be replayed.
        self.handed.clear();
        self.flow.on_setup();
        out.push(Command::SurfaceSize {
            width: w,
            height: h,
        });
        let first = !self.first_setup_done;
        let mut frames = 0;
        if first
            && self.slate.as_ref().is_some_and(|s| s.size == (w, h))
            && self.send_slate(gfx, now)
        {
            frames = 1;
        }
        self.drain(gfx, out, None, frames, false);
        if first {
            self.first_setup_done = true;
            out.push(Command::OpenFlv);
        }
        true
    }

    fn send_slate(&mut self, gfx: &mut GraphicsPipelineServer, now: Instant) -> bool {
        let (Some(slate), Some((sid, w, h))) = (self.slate.as_ref(), self.surface) else {
            return false;
        };
        let region = Avc420Region::full_frame(w, h, self.cfg.region_qp);
        let suspended = gfx.is_ack_suspended();
        match gfx.send_avc420_frame(sid, &slate.annex_b, &[region], self.timestamp(now)) {
            Some(id) => {
                self.flow.record(id, now, false, true, suspended);
                true
            }
            None => false,
        }
    }

    fn timestamp(&self, now: Instant) -> u32 {
        let ms = now.saturating_duration_since(self.started).as_millis() & 0xFFFF_FFFF;
        u32::try_from(ms).unwrap_or(0)
    }

    /// Drain IronRDP's queue into one batch (or the burst chunk).
    fn drain(
        &mut self,
        gfx: &mut GraphicsPipelineServer,
        out: &mut Vec<Command>,
        received: Option<Instant>,
        frames: u32,
        burst: bool,
    ) {
        let messages = gfx.drain_output();
        if messages.is_empty() {
            return;
        }
        let Some(channel_id) = gfx.channel_id() else {
            return;
        };
        let weight = messages.iter().fold(0u64, |a, m| {
            a.saturating_add(u64::try_from(m.size()).unwrap_or(u64::MAX))
        });
        self.flow.add_handed(weight);
        if !burst {
            out.push(Command::SendDvc(DvcBatch {
                channel_id,
                messages,
                weight,
                frames,
                received,
                yield_after: false,
            }));
            return;
        }
        let full = {
            let b = self.batch.get_or_insert_with(|| DvcBatch {
                channel_id,
                messages: Vec::new(),
                weight: 0,
                frames: 0,
                received,
                yield_after: true,
            });
            b.messages.extend(messages);
            b.weight = b.weight.saturating_add(weight);
            b.frames = b.frames.saturating_add(frames);
            b.frames >= self.cfg.burst_chunk
        };
        if full {
            self.flush_batch(out);
        }
    }

    fn flush_batch(&mut self, out: &mut Vec<Command>) {
        if let Some(b) = self.batch.take() {
            out.push(Command::SendDvc(b));
        }
    }

    fn push_idr(&mut self, a: IdrAction, out: &mut Vec<Command>) {
        match a {
            IdrAction::RequestIdr => out.push(Command::RequestIdr),
            IdrAction::ReconnectFlv => out.push(Command::ReconnectFlv),
            IdrAction::FallbackReconnect => {
                self.metrics.idr_side_fallbacks.inc();
                out.push(Command::ReconnectFlv);
            }
        }
    }

    fn setup_cause(&mut self, now: Instant, out: &mut Vec<Command>) {
        if let Some(a) = self.idr.setup_cause(now) {
            self.push_idr(a, out);
        }
    }

    fn flow_cause(&mut self, now: Instant) {
        self.idr.flow_cause(now);
    }

    /// A Shutdown during an earlier close (m6, §5.2, DC13): the close keeps
    /// its cause and its one disconnect, but its watchdog fires no later
    /// than the shutdown's own — the 5 s exit budget — and never later than
    /// it already would.
    fn shorten_watchdog(&mut self, now: Instant, watchdog: Duration) {
        if let Some((since, running)) = self.closing {
            let remaining = running.saturating_sub(now.saturating_duration_since(since));
            if watchdog < remaining {
                self.closing = Some((now, watchdog));
            }
        }
    }

    fn close(&mut self, now: Instant, cause: Cause, watchdog: Duration, out: &mut Vec<Command>) {
        if self.state == State::Closing {
            return;
        }
        self.set_state(now, State::Closing, out);
        self.closing = Some((now, watchdog));
        // step() already flushed any pending chunk (this input is neither a
        // sample nor a burst AU); those frames were drained from IronRDP
        // before the cause was known. Nothing is encoded after this point
        // (§6.9).
        self.batch = None;
        self.avc420_deadline = None;
        self.metrics.disconnects.inc(cause.label());
        out.push(Command::ReleaseAll(ReleaseTrigger::Closing));
        out.push(Command::Disconnect(cause));
    }

    fn on_ready(
        &mut self,
        gfx: &mut GraphicsPipelineServer,
        now: Instant,
        avc420: bool,
        out: &mut Vec<Command>,
    ) {
        let first_negotiation = !self.negotiated;
        self.negotiated = true;
        if !avc420 {
            if self.state == State::WaitReady && first_negotiation {
                // First negotiation: wait `avc420_timeout` for a better one (§6.7).
                tracing::info!(
                    "EGFX negotiated without AVC420; waiting for a better capability set"
                );
                return;
            }
            self.close(now, Cause::NoAvc420, self.cfg.disconnect_watchdog, out);
            return;
        }
        match self.state {
            State::WaitReady => {
                self.ready_seen = true;
                self.avc420_deadline = None;
                if !self.setup_or_close(gfx, now, out) {
                    return;
                }
                match self.pending_size.take() {
                    Some(size) if size != self.size => self.start_resize(now, size, false, out),
                    _ => self.set_state(now, State::NeedIdr, out),
                }
            }
            State::NeedIdr | State::Live => {
                if !self.setup_or_close(gfx, now, out) {
                    return;
                }
                self.set_state(now, State::NeedIdr, out);
                self.setup_cause(now, out);
            }
            // Merged: the Setup runs at ReactivationComplete.
            State::WaitReactivation => self.ready_seen = true,
            State::Paused => {
                // Stays Paused either way; a refusal has closed the session.
                let _set_up = self.setup_or_close(gfx, now, out);
            }
            State::Idle | State::Closing => {}
        }
    }

    /// Start resize (§6.4): stop sends, take the new size, emit
    /// `DisplayUpdate::Resize`. The only resize path.
    fn start_resize(
        &mut self,
        now: Instant,
        size: (u16, u16),
        return_to_paused: bool,
        out: &mut Vec<Command>,
    ) {
        self.set_state(now, State::WaitReactivation, out);
        self.size = size;
        self.pending_size = None;
        self.return_to_paused = return_to_paused;
        // step() already flushed any pending chunk: every caller (OnReady,
        // ReactivationComplete, SpsChanged) is neither a sample nor a burst
        // AU (m8). A chunk dropped here would leave its bytes in the backlog
        // for the session (`add_handed` counted them at drain). Nothing is
        // encoded again before the reactivation's Setup.
        debug_assert!(self.batch.is_none(), "step() flushes before a resize");
        self.batch = None;
        out.push(Command::DisplayResize {
            width: size.0,
            height: size.1,
        });
    }

    fn on_reactivated(
        &mut self,
        gfx: &mut GraphicsPipelineServer,
        now: Instant,
        out: &mut Vec<Command>,
    ) {
        if self.state != State::WaitReactivation {
            return;
        }
        if self.ready_seen && !self.setup_or_close(gfx, now, out) {
            return;
        }
        if let Some(size) = self.pending_size.take()
            && size != self.size
        {
            let back = self.return_to_paused;
            self.start_resize(now, size, back, out);
            return;
        }
        if self.suppressed || self.return_to_paused {
            self.return_to_paused = false;
            self.enter_paused(now, out);
        } else if !self.ready_seen {
            self.set_state(now, State::WaitReady, out);
        } else {
            self.set_state(now, State::NeedIdr, out);
            self.setup_cause(now, out);
        }
    }

    fn enter_paused(&mut self, now: Instant, out: &mut Vec<Command>) {
        if !self.released_for_edge {
            self.released_for_edge = true;
            out.push(Command::ReleaseAll(ReleaseTrigger::Suppression));
        }
        self.set_state(now, State::Paused, out);
    }

    fn on_suppress(&mut self, now: Instant, raw: bool, out: &mut Vec<Command>) {
        if !self.kvm_frame_delivered {
            return; // mstsc pulses it during connect (§6.6)
        }
        let Some(edge) = self.suppress.sample(now, raw) else {
            return;
        };
        match edge {
            Edge::On => {
                self.suppressed = true;
                match self.state {
                    State::NeedIdr | State::Live => self.enter_paused(now, out),
                    State::WaitReactivation if !self.released_for_edge => {
                        self.released_for_edge = true;
                        out.push(Command::ReleaseAll(ReleaseTrigger::Suppression));
                    }
                    _ => {}
                }
            }
            Edge::Off => {
                self.suppressed = false;
                self.released_for_edge = false;
                // P5 (DC23): a resize started from Paused must not return
                // there once the suppression it paused for has ended — the
                // debouncer is settled at off, so no later edge would ever
                // leave that Paused.
                self.return_to_paused = false;
                if self.state == State::Paused {
                    self.set_state(now, State::NeedIdr, out);
                    self.setup_cause(now, out);
                }
            }
        }
    }

    fn on_sps(
        &mut self,
        now: Instant,
        class: ParamClass,
        params: ParamSets,
        out: &mut Vec<Command>,
    ) {
        let (Ok(w), Ok(h)) = (
            u16::try_from(params.summary.width),
            u16::try_from(params.summary.height),
        ) else {
            self.close(
                now,
                Cause::StreamIncompatible,
                self.cfg.disconnect_watchdog,
                out,
            );
            return;
        };
        let new = (w, h);
        let sized = matches!(class, ParamClass::Initial | ParamClass::Resize);
        let needs_resize = sized && new != self.size;
        let flow = !needs_resize && matches!(class, ParamClass::Other | ParamClass::Resize);
        self.params = Some(params);
        match self.state {
            State::WaitReady | State::WaitReactivation => {
                if sized {
                    self.pending_size = (new != self.size).then_some(new);
                }
            }
            State::NeedIdr => {
                if needs_resize {
                    self.start_resize(now, new, false, out);
                } else if flow {
                    self.flow_cause(now);
                }
            }
            State::Live => {
                if needs_resize {
                    self.start_resize(now, new, false, out);
                } else if flow {
                    self.set_state(now, State::NeedIdr, out);
                    self.flow_cause(now);
                }
            }
            State::Paused => {
                if needs_resize {
                    self.start_resize(now, new, true, out);
                }
            }
            State::Idle | State::Closing => {}
        }
    }

    fn on_flv_opened(&mut self, now: Instant, origin: FlvOrigin, out: &mut Vec<Command>) {
        // PC17 I2, N1: a swapped-in candidate may replay what the old FLV
        // already delivered.
        self.replay_at = (origin == FlvOrigin::Commanded).then_some(0);
        match self.state {
            State::Live | State::NeedIdr | State::Paused => {
                if self.state == State::Live {
                    self.set_state(now, State::NeedIdr, out);
                }
                // The NeedIdr waits for this connection's first IDR; an open
                // never requests one (§6.5). A deferred request it cancels is
                // counted like one cancelled by leaving NeedIdr (P26).
                if self.idr.flv_opened(now) {
                    self.metrics.idr_cancelled.inc();
                    out.push(Command::CancelIdrRequest);
                }
                self.flow.on_flv_opened();
            }
            State::WaitReady | State::WaitReactivation => {
                // m1 (§6.5): "Any FLV open … restarts both clocks", whatever
                // the state — every open forces an IDR on every viewer. The
                // table's "ignore" is the state transition. Nothing can be
                // deferred here: IdrCore is idle outside NeedIdr. (Grace is
                // re-armed by the Setup that precedes the next NeedIdr.)
                let cancelled = self.idr.flv_opened(now);
                debug_assert!(!cancelled, "IdrCore is idle outside NeedIdr");
            }
            State::Idle | State::Closing => {}
        }
    }

    fn on_au(
        &mut self,
        gfx: &mut GraphicsPipelineServer,
        now: Instant,
        a: KvmAu,
        out: &mut Vec<Command>,
    ) {
        if a.after_drop {
            // An AU was dropped on a full channel: a flow cause (DC12).
            match self.state {
                State::Live => {
                    self.set_state(now, State::NeedIdr, out);
                    self.flow_cause(now);
                }
                State::NeedIdr => self.flow_cause(now),
                _ => {}
            }
        }
        let dropped = match self.state {
            State::NeedIdr | State::Live => None,
            State::Paused => Some("paused"),
            State::WaitReactivation => Some("wait_reactivation"),
            State::WaitReady | State::Idle => Some("not_ready"),
            State::Closing => Some("closing"),
        };
        if let Some(reason) = dropped {
            self.metrics.frames_dropped.inc(reason);
            return;
        }
        // PC17 I2, N1 (§6.5 `reconnect`): the shared encoder sends the IDR a
        // candidate's open forces into the old FLV too, and the old FLV may
        // deliver it and the P frames after it before the candidate's first
        // tag swaps it in. The candidate then replays them. While its AUs
        // match what the client got since that IDR, in order, they are not
        // sent again — a repeated P frame would predict from the wrong
        // picture until the next IDR — and the IDR's match ends the swap's
        // NeedIdr. A candidate that left out an AU the client has resyncs to
        // the later entry it matches (PC17 N2). Past the ring, or from an AU
        // the ring never had at its first place, all goes out.
        if let Some(i) = self.replay_at {
            if let Some(j) = self.replayed_at(i, &a) {
                self.replay_at = Some(j.saturating_add(1));
                self.metrics.frames_dropped.inc("repeat");
                if j == 0 && self.state == State::NeedIdr {
                    let _ = self.flow.take_grace(true);
                    self.set_state(now, State::Live, out);
                }
                return;
            }
            self.replay_at = None;
            // PC17 N2: a P frame that diverges mid-replay predicts from the
            // candidate's previous picture, but the client's is the ring's
            // last: like a lost reference, it is dropped, and NeedIdr with a
            // flow cause asks for a clean IDR (§6.5's policy and clocks). An
            // IDR needs no reference and goes on as usual.
            if i > 0 && self.handed.at(i).is_some() && !a.au.idr {
                self.metrics.frames_dropped.inc("replay_diverged");
                if self.state == State::Live {
                    self.set_state(now, State::NeedIdr, out);
                }
                self.flow_cause(now);
                return;
            }
        }
        let suspended = gfx.is_ack_suspended();
        let gate = self
            .flow
            .gates(now, a.au.burst, suspended, gfx.should_backpressure());
        if self.state == State::NeedIdr {
            // Idr-wait is sampled on ticks only (m2, m3), never here: the
            // tick computes the gates without the burst soft-gate exemption,
            // so a burst AU never counts as open time; and the AU that
            // resolves NeedIdr never also requests the IDR it brings.
            if !a.au.idr {
                self.metrics.frames_dropped.inc("awaiting_idr");
                return;
            }
            if !gate.is_open() {
                self.metrics.frames_dropped.inc(gate.drop_reason());
                self.flow_cause(now);
                return;
            }
            if self.send_au(gfx, now, &a, out) {
                self.set_state(now, State::Live, out);
            } else {
                self.flow_cause(now);
            }
            return;
        }
        if !gate.is_open() {
            let reason = if a.au.burst && gate == Gate::Backpressure {
                "burst_truncated"
            } else {
                gate.drop_reason()
            };
            self.metrics.frames_dropped.inc(reason);
            self.set_state(now, State::NeedIdr, out);
            self.flow_cause(now);
            return;
        }
        if !self.send_au(gfx, now, &a, out) {
            self.set_state(now, State::NeedIdr, out);
            self.flow_cause(now);
        }
    }

    /// §6.3: [AUD] + SPS/PPS (IDR only) + VCL NALs, 4-byte start codes, one
    /// AU per `send_avc420_frame`, full-frame region at `region_qp`.
    fn send_au(
        &mut self,
        gfx: &mut GraphicsPipelineServer,
        now: Instant,
        a: &KvmAu,
        out: &mut Vec<Command>,
    ) -> bool {
        let (Some(params), Some((sid, w, h))) = (self.params.as_ref(), self.surface) else {
            self.metrics.frames_dropped.inc("not_ready");
            return false;
        };
        self.annexb.clear();
        a.au.write_annex_b(params, &mut self.annexb);
        let region = Avc420Region::full_frame(w, h, self.cfg.region_qp);
        let suspended = gfx.is_ack_suspended();
        let ts = self.timestamp(now);
        match gfx.send_avc420_frame(sid, &self.annexb, &[region], ts) {
            Some(id) => {
                if a.au.idr {
                    self.handed.clear();
                }
                self.handed.push(au_key(&self.annexb));
                let grace = self.flow.take_grace(a.au.idr);
                self.flow.record(id, now, a.au.burst, grace, suspended);
                self.kvm_frame_delivered = true;
                self.metrics.frames_sent.inc();
                self.drain(gfx, out, Some(a.received), 1, a.au.burst);
                true
            }
            None => {
                self.metrics.frames_dropped.inc("send_none");
                false
            }
        }
    }

    /// Where in the ring `a`, as it would go out (§6.3, its SPS rewritten;
    /// FLV timestamps, which differ per connection, are not part of it), was
    /// handed: at `i` for the replay's first AU (the IDR), else the first
    /// entry from `i` on — a candidate may have left some out (PC17 N2).
    fn replayed_at(&mut self, i: usize, a: &KvmAu) -> Option<usize> {
        let at_i = self.handed.at(i)?;
        let params = self.params.as_ref()?;
        self.annexb.clear();
        a.au.write_annex_b(params, &mut self.annexb);
        let key = au_key(&self.annexb);
        if i == 0 {
            return (at_i == key).then_some(0);
        }
        self.handed.find_from(i, key)
    }

    fn on_tick(&mut self, gfx: &mut GraphicsPipelineServer, now: Instant, out: &mut Vec<Command>) {
        if self.state == State::Closing {
            if let Some((since, watchdog)) = self.closing
                && !self.aborted
                && now.saturating_duration_since(since) >= watchdog
            {
                // §6.9: on_disconnected never came — release, stop, abort.
                self.aborted = true;
                out.push(Command::ReleaseAll(ReleaseTrigger::Watchdog));
                out.push(Command::Abort);
            }
            return;
        }
        if self.avc420_deadline.is_some_and(|d| now >= d) {
            self.close(now, Cause::NoAvc420, self.cfg.disconnect_watchdog, out);
            return;
        }
        if self.next_probe.is_some_and(|t| now >= t) {
            out.push(Command::ProbeRtt);
            self.next_probe = Some(now + self.cfg.rtt_probe_interval);
        }
        let suspended = gfx.is_ack_suspended();
        if self.flow.stall_expired(now, suspended)
            || self.flow.suspended_backlog_expired(now, suspended)
        {
            self.close(now, Cause::ClientStalled, self.cfg.disconnect_watchdog, out);
            return;
        }
        match self.state {
            State::Live => {
                let gate = self
                    .flow
                    .gates(now, false, suspended, gfx.should_backpressure());
                if !gate.is_open() {
                    self.set_state(now, State::NeedIdr, out);
                    self.flow_cause(now);
                }
            }
            State::NeedIdr => {
                let gate = self
                    .flow
                    .gates(now, false, suspended, gfx.should_backpressure());
                if !gate.is_open() {
                    self.flow_cause(now);
                }
                if let Some(a) = self.idr.observe_gates(now, gate.is_open()) {
                    self.push_idr(a, out);
                }
                if let Some(a) = self.idr.tick(now) {
                    self.push_idr(a, out);
                }
            }
            State::WaitReady
            | State::WaitReactivation
            | State::Paused
            | State::Idle
            | State::Closing => {}
        }
    }

    fn gauges(&self, gfx: &GraphicsPipelineServer, now: Instant) {
        let m = &self.metrics;
        m.egfx_in_flight.set(i64::from(gfx.frames_in_flight()));
        m.egfx_backlog_bytes
            .set(i64::try_from(self.flow.backlog()).unwrap_or(i64::MAX));
        m.egfx_ack_suspended.set(i64::from(gfx.is_ack_suspended()));
        m.egfx_oldest_unacked_ms
            .set(i64::try_from(self.flow.oldest_age(now).as_millis()).unwrap_or(i64::MAX));
        m.standing_delay_ms
            .set(self.flow.standing_delay_ms().map_or(-1, i64::from));
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
    use crate::msg::FlvOrigin;
    use crate::pump::rig::*;
    use ironrdp_egfx::pdu::{CapabilityVersion, GfxPdu, QueueDepth};

    fn count(k: &[&str], name: &str) -> usize {
        k.iter().filter(|x| **x == name).count()
    }

    /// §11.2 "Every policy": connecting costs exactly one FLV open, and the
    /// first FLV's NeedIdr requests nothing.
    #[test]
    fn connecting_costs_exactly_one_flv_open() {
        for policy in [IdrPolicy::Side, IdrPolicy::Reconnect, IdrPolicy::Wait] {
            let mut c = cfg();
            c.idr.policy = policy;
            let mut r = Rig::new(c);
            let mut out = r.start((640, 360));
            assert_eq!(r.pump.state(), State::WaitReady);
            out.extend(r.negotiate(census_caps()));
            assert_eq!(r.pump.state(), State::NeedIdr);
            out.extend(r.step(Input::FlvOpened {
                origin: FlvOrigin::First,
            }));
            out.extend(r.step(sps(ParamClass::Initial, ES3)));
            for i in 1..=20 {
                r.at(i * 100);
                out.extend(r.step(Input::Tick));
            }
            out.extend(r.step(au(true, false)));
            assert_eq!(r.pump.state(), State::Live);
            let k = kinds(&out);
            assert_eq!(
                k.iter().filter(|k| **k == "OpenFlv").count(),
                1,
                "{policy:?}"
            );
            assert!(
                !k.contains(&"RequestIdr") && !k.contains(&"ReconnectFlv"),
                "{policy:?}: {k:?}"
            );
        }
    }

    /// §6.3: the first KVM AU is an IDR carrying the cached SPS and PPS, on
    /// the current surface's full frame at `region_qp`.
    #[test]
    fn the_first_kvm_au_is_an_idr_carrying_sps_and_pps() {
        let mut r = Rig::new(cfg());
        r.need_idr();
        let out = r.step(au(true, false));
        assert_eq!(
            names(&pdus(&out)),
            ["StartFrame", "WireToSurface1", "EndFrame"]
        );
        let w = wire(&out);
        let (annex_b, qp, rect) = &w[0];
        assert_eq!(nal_types(annex_b), [7, 8, 5]);
        let p = params(ES3);
        assert!(
            annex_b.windows(p.sps.len()).any(|x| x == p.sps.as_ref()),
            "the rewritten SPS"
        );
        assert_eq!((*qp, *rect), (22, (0, 0, 640, 360)));
        assert_eq!(r.metrics.frames_sent.get(), 1);
        let later = r.step(au(false, false));
        assert_eq!(
            nal_types(&wire(&later)[0].0),
            [1],
            "P frames carry no parameter sets"
        );
    }

    #[test]
    fn p_frames_wait_for_an_idr() {
        let mut r = Rig::new(cfg());
        r.need_idr();
        assert!(pdus(&r.step(au(false, false))).is_empty());
        assert_eq!(r.metrics.frames_dropped.get("awaiting_idr"), 1);
        assert_eq!(r.pump.state(), State::NeedIdr);
    }

    /// §6.1's classes: `initial` at the current size raises no NeedIdr; at
    /// another size it starts a resize.
    #[test]
    fn an_initial_sps_resizes_only_at_another_size() {
        let mut r = Rig::new(cfg());
        r.live();
        r.step(sps(ParamClass::Initial, ES3));
        assert_eq!(r.pump.state(), State::Live);
        let out = r.step(sps(ParamClass::Initial, P480));
        assert_eq!(r.pump.state(), State::WaitReactivation);
        assert!(
            matches!(
                out.last(),
                Some(Command::DisplayResize {
                    width: 854,
                    height: 480
                })
            ),
            "{out:?}"
        );
        assert_eq!(r.pump.size(), (854, 480));
    }

    /// §6.1 `other`: a flow cause — NeedIdr, never a reconnect, and a request
    /// only after `idr_wait_max` of open gates, on the flow clock the first
    /// FLV open started.
    #[test]
    fn an_other_sps_is_a_flow_cause_never_a_reconnect() {
        let mut r = Rig::new(cfg());
        r.live();
        r.ack(0, QueueDepth::Unavailable);
        assert_eq!(
            r.metrics.ack_rtt.count(),
            1,
            "§10.4 ack RTT: handed → acknowledged"
        );
        let mut out = r.step(sps(ParamClass::Other, ES3));
        assert_eq!(r.pump.state(), State::NeedIdr);
        let mut requested_at = Vec::new();
        for i in 1..=105 {
            r.at(i * 100);
            let step = r.step(Input::Tick);
            if kinds(&step).contains(&"RequestIdr") {
                requested_at.push(i * 100);
            }
            out.extend(step);
        }
        let k = kinds(&out);
        assert!(!k.contains(&"ReconnectFlv"), "{k:?}");
        assert_eq!(
            k.iter().filter(|k| **k == "RequestIdr").count(),
            1,
            "deferred to the flow window's end"
        );
        // m4(c): idr-wait is satisfied at 3.1 s, but the request waits for
        // the flow window the first FLV open started at 0.
        assert_eq!(requested_at, [10_000], "at the flow window's end");
    }

    /// §6.6: `send_avc420_frame` returning `None` is a flow cause and a metric.
    #[test]
    fn send_none_drops_to_need_idr() {
        let mut r = Rig::new(cfg());
        r.live();
        r.advertise(v8_only()); // IronRDP renegotiated; the pump is not told yet
        assert!(pdus(&r.step(au(true, false))).is_empty());
        assert_eq!(r.pump.state(), State::NeedIdr);
        assert_eq!(r.metrics.frames_dropped.get("send_none"), 1);
    }

    /// §6.4 slate: on the first Setup, only when the surface matches it.
    #[test]
    fn the_slate_precedes_the_first_kvm_idr_only_when_the_surface_matches() {
        let mut r = Rig::with_slate(cfg(), Slate::embedded());
        r.start((1920, 1080));
        let n = names(&pdus(&r.negotiate(census_caps())));
        assert_eq!(
            n,
            [
                "ResetGraphics",
                "CreateSurface",
                "MapSurfaceToOutput",
                "StartFrame",
                "WireToSurface1",
                "EndFrame"
            ]
        );
        assert_eq!(
            r.metrics.frames_sent.get(),
            0,
            "the slate is not a KVM frame"
        );
        let mut r = Rig::with_slate(cfg(), Slate::embedded());
        r.start((640, 360));
        let n = names(&pdus(&r.negotiate(census_caps())));
        assert_eq!(n, ["ResetGraphics", "CreateSurface", "MapSurfaceToOutput"]);
    }

    /// §11.2: after Live, a second CapsAdvertise produces exactly
    /// CapabilitiesConfirm, ResetGraphics (w, h, one monitor), CreateSurface,
    /// MapSurfaceToOutput, StartFrame, WireToSurface1 (IDR with SPS/PPS),
    /// EndFrame — no DeleteSurface, no P-frame before the IDR.
    #[test]
    fn a_readvertise_after_live_is_exactly_setup_then_an_idr() {
        let mut r = Rig::new(cfg());
        r.live();
        let mut seen = r.advertise(census_caps());
        let avc420 = r.gfx.supports_avc420();
        let mut out = r.step(Input::OnReady { avc420 });
        out.extend(r.step(au(false, false)));
        out.extend(r.step(au(true, false)));
        seen.extend(pdus(&out));
        assert_eq!(
            names(&seen),
            [
                "CapabilitiesConfirm",
                "ResetGraphics",
                "CreateSurface",
                "MapSurfaceToOutput",
                "StartFrame",
                "WireToSurface1",
                "EndFrame"
            ]
        );
        let GfxPdu::ResetGraphics(rg) = &seen[1] else {
            panic!("{:?}", names(&seen))
        };
        assert_eq!((rg.width, rg.height, rg.monitors.len()), (640, 360, 1));
        assert_eq!(
            (rg.monitors[0].right, rg.monitors[0].bottom),
            (639, 359),
            "inclusive bounds (§6.4)"
        );
        assert_eq!(nal_types(&wire(&out)[0].0), [7, 8, 5]);
    }

    /// §11.2: each replayed advertise yields the confirm the census recorded.
    #[test]
    fn capability_replays_confirm_what_the_census_recorded() {
        let mut r = Rig::new(cfg());
        let c = r.advertise(census_caps());
        let [GfxPdu::CapabilitiesConfirm(c)] = c.as_slice() else {
            panic!("{c:?}")
        };
        assert_eq!(
            (c.0.version, c.0.data.as_slice()),
            (CapabilityVersion::V8_1, &[0x12, 0, 0, 0][..])
        );
        assert!(r.gfx.supports_avc420());
        let mut r = Rig::new(cfg());
        let c = r.advertise(full_ladder());
        let [GfxPdu::CapabilitiesConfirm(c)] = c.as_slice() else {
            panic!("{c:?}")
        };
        assert_eq!(c.0.version, CapabilityVersion::V10_7);
        assert!(r.gfx.supports_avc420());
        let mut r = Rig::new(cfg());
        r.advertise(v8_only());
        assert!(!r.gfx.supports_avc420());
    }

    /// §6.5 source bursts: exempt from the soft gate, sent in chunks of
    /// `burst_chunk` (one event each, with a yield), counted against the
    /// hard cap; past it, truncated — a flow cause.
    #[test]
    fn bursts_are_chunked_and_truncated_at_the_hard_cap() {
        let mut c = cfg();
        c.hard_cap = 12;
        let mut r = Rig::new(c);
        r.live(); // the IDR is in flight: 11 more fit
        let mut out = Vec::new();
        for _ in 0..20 {
            // As the shell feeds them (DC6): samples before every AU. They
            // must not flush a half-filled chunk.
            out.extend(r.step(Input::Suppress(false)));
            out.extend(r.step(Input::Backlog { written: 0 }));
            out.extend(r.step(au(false, true)));
        }
        out.extend(r.step(Input::Tick));
        let batches: Vec<(u32, bool)> = out
            .iter()
            .filter_map(|c| {
                if let Command::SendDvc(b) = c {
                    Some((b.frames, b.yield_after))
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(batches, [(8, true), (3, true)]);
        assert_eq!(r.metrics.frames_dropped.get("burst_truncated"), 1);
        assert_eq!(r.pump.state(), State::NeedIdr);
    }

    /// §4.3 generations: a stop for another generation is ignored; the
    /// current one's stop returns to Idle, where nothing reaches IronRDP.
    #[test]
    fn only_the_current_generations_stop_ends_the_session() {
        let mut r = Rig::new(cfg());
        r.live();
        r.step(Input::SessionStop { generation: 7 });
        assert_eq!(r.pump.state(), State::Live);
        r.step(Input::SessionStop { generation: 1 });
        assert_eq!((r.pump.state(), r.pump.generation()), (State::Idle, 0));
        assert!(r.step(au(true, false)).is_empty());
        assert!(r.step(Input::Tick).is_empty());
    }

    /// P5 (DC23): an Off edge recorded during a resize started from Paused
    /// clears `return_to_paused`, so the reactivation lands in NeedIdr (a
    /// Setup cause) — not in a Paused that only another Off edge, which the
    /// settled debouncer will never produce, could end.
    #[test]
    fn a_suppression_ending_during_a_resize_from_paused_lands_in_need_idr() {
        let mut r = Rig::new(cfg());
        r.live();
        r.hold_suppress(true);
        assert_eq!(r.pump.state(), State::Paused);
        r.step(sps(ParamClass::Resize, P480));
        assert_eq!(r.pump.state(), State::WaitReactivation);
        r.at(r.ms() + 10);
        r.hold_suppress(false);
        let out = r.step(Input::ReactivationComplete);
        assert_eq!(r.pump.state(), State::NeedIdr);
        let k = kinds(&out);
        assert!(!k.contains(&"ReleaseAll"), "{k:?}");
        assert_eq!(
            count(&k, "RequestIdr"),
            1,
            "leaving Paused is a Setup cause: {k:?}"
        );
    }

    /// P26: an FLV open that cancels a deferred request says so and counts
    /// it, as leaving NeedIdr does; one with nothing deferred says nothing.
    #[test]
    fn an_flv_open_cancelling_a_deferred_request_counts_it() {
        let mut r = Rig::new(cfg());
        let out = r.live();
        assert!(
            !kinds(&out).contains(&"CancelIdrRequest"),
            "the first FLV cancelled nothing"
        );
        r.ack(0, QueueDepth::Unavailable);
        r.at(200);
        let k = kinds(&r.negotiate(census_caps()));
        assert!(
            !k.contains(&"RequestIdr"),
            "a Setup cause inside the window is deferred: {k:?}"
        );
        r.at(500);
        let out = r.step(Input::FlvOpened {
            origin: FlvOrigin::Transient,
        });
        assert_eq!(kinds(&out), ["CancelIdrRequest"]);
        assert_eq!(r.metrics.idr_cancelled.get(), 1);
    }

    /// §6.4 NeedIdr: only an IDR handed to IronRDP ends it — not P frames,
    /// ticks, a request or its fallback, an FLV open, nor an IDR IronRDP
    /// refused.
    #[test]
    fn need_idr_is_held_until_an_idr_is_handed_to_ironrdp() {
        let mut r = Rig::new(cfg());
        let mut out = r.need_idr();
        r.at(1500);
        out.extend(r.negotiate(census_caps())); // a Setup cause: RequestIdr, its fallback at 2.5 s
        for i in 16..=50 {
            r.at(i * 100);
            if i == 27 {
                out.extend(r.step(Input::FlvOpened {
                    origin: FlvOrigin::Commanded,
                }));
            }
            out.extend(r.step(au(false, false)));
            out.extend(r.step(Input::Tick));
            assert_eq!(r.pump.state(), State::NeedIdr, "at {} ms", i * 100);
        }
        let k = kinds(&out);
        assert_eq!(
            (count(&k, "RequestIdr"), count(&k, "ReconnectFlv")),
            (1, 1),
            "{k:?}"
        );
        assert!(wire(&out).is_empty(), "no frame before the IDR");
        assert_eq!(r.metrics.frames_dropped.get("awaiting_idr"), 35);
        r.advertise(v8_only()); // IronRDP renegotiated; the pump is not told yet
        assert!(pdus(&r.step(au(true, false))).is_empty());
        assert_eq!(r.metrics.frames_dropped.get("send_none"), 1);
        assert_eq!(
            r.pump.state(),
            State::NeedIdr,
            "a refused IDR was not handed over"
        );
        r.negotiate(census_caps());
        let out = r.step(au(true, false));
        assert_eq!(nal_types(&wire(&out)[0].0), [7, 8, 5]);
        assert_eq!(r.pump.state(), State::Live);
        assert_eq!(r.metrics.frames_sent.get(), 1);
    }

    /// §6.5 `side` fallback: a request that brings no IDR within
    /// `idr_side_timeout` becomes exactly one `ReconnectFlv`, counted, not
    /// before; the FLV that opens for it ends the fallback (nothing more is
    /// requested), and that FLV's IDR ends NeedIdr.
    #[test]
    fn a_side_request_without_an_idr_falls_back_to_one_reconnect() {
        let mut r = Rig::new(cfg());
        r.live();
        r.ack(0, QueueDepth::Unavailable);
        r.at(1500);
        let mut out = r.negotiate(census_caps()); // a Setup cause outside the window
        assert_eq!(count(&kinds(&out), "RequestIdr"), 1);
        for i in 16..=24 {
            r.at(i * 100);
            out.extend(r.step(Input::Tick));
        }
        assert!(
            !kinds(&out).contains(&"ReconnectFlv"),
            "not before idr_side_timeout"
        );
        r.at(2500);
        let k = kinds(&r.step(Input::Tick));
        assert_eq!(
            (count(&k, "ReconnectFlv"), count(&k, "RequestIdr")),
            (1, 0),
            "{k:?}"
        );
        assert_eq!(r.metrics.idr_side_fallbacks.get(), 1);
        r.at(2700);
        r.step(Input::FlvOpened {
            origin: FlvOrigin::Commanded,
        });
        let mut later = Vec::new();
        for i in 28..=60 {
            r.at(i * 100);
            later.extend(r.step(Input::Tick));
        }
        let k = kinds(&later);
        assert!(
            !k.contains(&"RequestIdr") && !k.contains(&"ReconnectFlv"),
            "{k:?}"
        );
        assert_eq!(r.pump.state(), State::NeedIdr);
        r.step(au(true, false));
        assert_eq!(r.pump.state(), State::Live);
    }

    /// An AU whose one slice NAL carries `n`: a distinct picture per `n`.
    fn au_n(idr: bool, n: u8) -> Input {
        let Input::Au(mut a) = au(idr, false) else {
            unreachable!()
        };
        let head = if idr { 0x65 } else { 0x41 };
        a.au.vcl = vec![kvm_proto::flv::Nal {
            bytes: bytes::Bytes::from(vec![head, 0x88, n, 0x21]),
        }];
        Input::Au(a)
    }

    fn commanded() -> Input {
        Input::FlvOpened {
            origin: FlvOrigin::Commanded,
        }
    }

    /// The pictures `out` sent, as their `n` (`au_n`'s third NAL byte).
    fn sent_ns(out: &[Command]) -> Vec<u8> {
        wire(out)
            .iter()
            .map(|(annex_b, ..)| annex_b[annex_b.len() - 2])
            .collect()
    }

    /// Steps `aus` (`(idr, n)` each) and returns what went out.
    fn feed(r: &mut Rig, aus: &[(bool, u8)]) -> Vec<Command> {
        let mut out = Vec::new();
        for &(idr, n) in aus {
            out.extend(r.step(au_n(idr, n)));
        }
        out
    }

    /// PC17 I2, N1 (§6.5 `reconnect`): the shared encoder sends the IDR a
    /// `ReconnectFlv` candidate's open forces into the old FLV as well, and
    /// the old FLV may deliver it — and the P frames after it — before the
    /// candidate's first tag swaps it in. The candidate then replays them.
    /// Each AU handed to the client since the last IDR is kept as
    /// (length, hash); after the swap, candidate AUs matching that ring in
    /// order are dropped (counted), the IDR's match ends NeedIdr, and the
    /// first AU past the ring goes out. With the ES3's one reference frame
    /// a repeated P frame would predict from the wrong picture until the
    /// next IDR.
    #[test]
    fn a_candidates_replay_of_the_aus_already_sent_is_dropped() {
        // The old FLV delivered only the IDR.
        let mut r = Rig::new(cfg());
        r.need_idr();
        assert_eq!(sent_ns(&feed(&mut r, &[(true, 0)])), [0]);
        r.step(commanded());
        assert_eq!(r.pump.state(), State::NeedIdr);
        let out = feed(&mut r, &[(true, 0), (false, 1)]);
        assert_eq!(sent_ns(&out), [1], "the IDR went out twice");
        assert_eq!(r.metrics.frames_dropped.get("repeat"), 1);
        assert_eq!(r.pump.state(), State::Live);
        // The old FLV delivered the IDR, P1 and P2.
        let mut r = Rig::new(cfg());
        r.need_idr();
        assert_eq!(
            sent_ns(&feed(&mut r, &[(true, 0), (false, 1), (false, 2)])),
            [0, 1, 2]
        );
        r.step(commanded());
        let out = feed(&mut r, &[(true, 0), (false, 1), (false, 2), (false, 3)]);
        assert_eq!(sent_ns(&out), [3], "a replayed AU went out twice");
        assert_eq!(r.metrics.frames_dropped.get("repeat"), 3);
        assert_eq!(r.metrics.frames_sent.get(), 4);
        assert_eq!(r.pump.state(), State::Live);
        // A later IDR starts the ring again: the replay begins at that IDR.
        let mut r = Rig::new(cfg());
        r.need_idr();
        feed(&mut r, &[(true, 0), (false, 1), (true, 2), (false, 3)]);
        r.step(commanded());
        let out = feed(&mut r, &[(true, 2), (false, 3), (false, 4)]);
        assert_eq!(sent_ns(&out), [4]);
        assert_eq!(r.metrics.frames_dropped.get("repeat"), 2);
    }

    /// PC17 N2: a candidate that left out an AU the client has (a KVM that
    /// dropped a frame for that viewer) differs from the ring at its place
    /// but equals a later entry: the replay moves to that entry and goes on
    /// dropping; the first AU past the ring goes out.
    #[test]
    fn a_replay_resyncs_to_a_later_entry_the_candidate_skipped_to() {
        let mut r = Rig::new(cfg());
        r.need_idr();
        feed(&mut r, &[(true, 0), (false, 1), (false, 2), (false, 3)]);
        r.step(commanded());
        let out = feed(&mut r, &[(true, 0), (false, 1), (false, 3), (false, 4)]);
        assert_eq!(sent_ns(&out), [4]);
        assert_eq!(r.metrics.frames_dropped.get("repeat"), 3);
        assert_eq!(r.pump.state(), State::Live);
    }

    /// PC17 N2: a P frame that differs from the ring mid-replay and from
    /// every later entry would predict from a picture the client does not
    /// have (its reference is the ring's last, not the candidate's): it is
    /// dropped, the pump goes to NeedIdr with a flow cause — idr-wait, then
    /// a request under the usual policy and rate limit — and nothing goes
    /// out until an IDR.
    #[test]
    fn a_p_frame_diverging_mid_replay_is_held_until_an_idr() {
        let mut r = Rig::new(cfg());
        r.need_idr();
        feed(&mut r, &[(true, 0), (false, 1), (false, 2)]);
        for id in 0..3 {
            r.ack(id, QueueDepth::Unavailable);
        }
        r.step(commanded()); // at 0: the flow clock restarts
        let mut out = feed(&mut r, &[(true, 0), (false, 1), (false, 9), (false, 2)]);
        assert!(sent_ns(&out).is_empty(), "{:?}", sent_ns(&out));
        assert_eq!(r.metrics.frames_dropped.get("repeat"), 2);
        assert_eq!(r.metrics.frames_dropped.get("replay_diverged"), 1);
        assert_eq!(r.pump.state(), State::NeedIdr);
        let mut requested_at = Vec::new();
        for i in 1..=105 {
            r.at(i * 100);
            let step = r.step(Input::Tick);
            if kinds(&step).contains(&"RequestIdr") {
                requested_at.push(i * 100);
            }
            out.extend(step);
        }
        assert_eq!(
            requested_at,
            [10_000],
            "idr-wait, then the flow window the swap's open started"
        );
        out.extend(feed(&mut r, &[(false, 3)]));
        assert!(sent_ns(&out).is_empty(), "a P frame before the IDR");
        assert_eq!(sent_ns(&feed(&mut r, &[(true, 60), (false, 61)])), [60, 61]);
        assert_eq!(r.pump.state(), State::Live);
    }

    /// PC17 N2: off the ring at its first place the candidate is no replay
    /// (as before): a P frame there waits for the swap's IDR like any
    /// other, with no divergence and no flow cause.
    #[test]
    fn a_first_candidate_au_off_the_ring_is_not_a_divergence() {
        let mut r = Rig::new(cfg());
        r.need_idr();
        feed(&mut r, &[(true, 0), (false, 1)]);
        r.step(commanded());
        assert!(sent_ns(&feed(&mut r, &[(false, 7)])).is_empty());
        assert_eq!(r.metrics.frames_dropped.get("awaiting_idr"), 1);
        assert_eq!(r.metrics.frames_dropped.get("replay_diverged"), 0);
        assert_eq!(sent_ns(&feed(&mut r, &[(true, 8)])), [8]);
    }

    /// PC17 N2: an IDR that differs from the ring mid-replay ends the replay
    /// and goes out (it needs no reference); so does what follows it.
    #[test]
    fn an_idr_mid_replay_ends_it_and_goes_out() {
        let mut r = Rig::new(cfg());
        r.need_idr();
        feed(&mut r, &[(true, 0), (false, 1), (false, 2)]);
        r.step(commanded());
        let out = feed(&mut r, &[(true, 0), (false, 1), (true, 5), (false, 6)]);
        assert_eq!(sent_ns(&out), [5, 6]);
        assert_eq!(r.metrics.frames_dropped.get("repeat"), 2);
        assert_eq!(r.metrics.frames_dropped.get("replay_diverged"), 0);
    }

    /// PC17 N1: the ring is bounded (64 entries; a GOP is 60 at 30 fps).
    /// Past it nothing is matched: the candidate's stream goes out whole
    /// — a rewind from its IDR, which decodes — never a partial match that
    /// would forward a repeated P frame after a later one.
    #[test]
    fn a_replay_past_the_ring_is_not_matched() {
        let mut c = cfg();
        c.hard_cap = 128; // 65 frames in flight, unacknowledged
        let mut r = Rig::new(c.clone());
        r.need_idr();
        let old: Vec<(bool, u8)> = (0..=64).map(|n| (n == 0, n)).collect();
        assert_eq!(sent_ns(&feed(&mut r, &old)).len(), 65);
        r.step(commanded());
        let out = feed(&mut r, &[(true, 0), (false, 1)]);
        assert_eq!(sent_ns(&out), [0, 1]);
        assert_eq!(r.metrics.frames_dropped.get("repeat"), 0);
        // At the cap exactly, the whole replay is matched; the next goes out.
        let mut r = Rig::new(c);
        r.need_idr();
        let old: Vec<(bool, u8)> = (0..64).map(|n| (n == 0, n)).collect();
        assert_eq!(sent_ns(&feed(&mut r, &old)).len(), 64);
        r.step(commanded());
        let mut replay = old.clone();
        replay.push((false, 64));
        assert_eq!(sent_ns(&feed(&mut r, &replay)), [64]);
        assert_eq!(r.metrics.frames_dropped.get("repeat"), 64);
    }

    /// PC17 I2: only a repeat is dropped. A different first IDR from the
    /// candidate goes out; so does an identical one after a Setup (a new
    /// surface that has no picture yet), and one after an FLV open that no
    /// `ReconnectFlv` made.
    #[test]
    fn a_candidates_idr_that_is_not_a_repeat_is_forwarded() {
        // A different picture.
        let mut r = Rig::new(cfg());
        r.live();
        r.step(commanded());
        let out = r.step(au_n(true, 7));
        assert_eq!(nal_types(&wire(&out)[0].0), [7, 8, 5], "a different IDR");
        assert_eq!(r.pump.state(), State::Live);
        // The same bytes, but the client's surface is new since.
        let mut r = Rig::new(cfg());
        r.live();
        r.ack(0, QueueDepth::Unavailable);
        r.at(1500);
        r.negotiate(census_caps()); // a re-advertise: Setup, a new surface
        r.step(commanded());
        let out = r.step(au(true, false));
        assert_eq!(wire(&out).len(), 1, "an identical IDR after a Setup");
        // The same bytes after a transient reopen (not a make-before-break).
        let mut r = Rig::new(cfg());
        r.live();
        r.step(Input::FlvOpened {
            origin: FlvOrigin::Transient,
        });
        let out = r.step(au(true, false));
        assert_eq!(
            wire(&out).len(),
            1,
            "an identical IDR after a transient open"
        );
        assert_eq!(r.metrics.frames_dropped.get("repeat"), 0);
    }

    /// Ticks every 100 ms over (from, to].
    fn ticks(r: &mut Rig, from_ms: u64, to_ms: u64) -> Vec<Command> {
        let mut out = Vec::new();
        for i in from_ms / 100 + 1..=to_ms / 100 {
            r.at(i * 100);
            out.extend(r.step(Input::Tick));
        }
        out
    }

    fn requests(k: &[&str]) -> (usize, usize) {
        (count(k, "RequestIdr"), count(k, "ReconnectFlv"))
    }

    /// m1 (§6.5: "Any FLV open … restarts both clocks"): an FLV that opens
    /// while a resize is reactivating restarts them, so the reactivation's
    /// Setup cause is deferred, and that FLV's own IDR cancels it. Before,
    /// the clock still ran from the first open, and the Setup cause forced
    /// a second IDR on every viewer 40 ms after the open's.
    #[test]
    fn an_flv_open_during_reactivation_restarts_the_clocks() {
        let mut r = Rig::new(cfg());
        r.live();
        r.ack(0, QueueDepth::Unavailable);
        r.at(2000);
        r.step(sps(ParamClass::Resize, P480));
        assert_eq!(r.pump.state(), State::WaitReactivation);
        r.at(2010);
        assert!(
            r.step(Input::FlvOpened {
                origin: FlvOrigin::Transient
            })
            .is_empty()
        );
        r.at(2050);
        let k = kinds(&r.step(Input::ReactivationComplete));
        assert_eq!(r.pump.state(), State::NeedIdr);
        assert_eq!(requests(&k), (0, 0), "deferred to the open's window: {k:?}");
        r.at(2200);
        let out = r.step(au(true, false));
        assert_eq!(r.pump.state(), State::Live);
        assert!(
            kinds(&out).contains(&"CancelIdrRequest"),
            "{:?}",
            kinds(&out)
        );
        assert_eq!(r.metrics.idr_cancelled.get(), 1);
        r.ack(1, QueueDepth::Unavailable);
        assert_eq!(requests(&kinds(&ticks(&mut r, 2200, 6000))), (0, 0));
    }

    /// m2: the AU that resolves NeedIdr never also requests an IDR. Here the
    /// IDR arrives just as idr-wait crosses `idr_wait_max` (2.8 s of open
    /// gates sampled by ticks, then 300 ms more), after the flow window: it
    /// is sent and nothing is requested.
    #[test]
    fn the_idr_that_resolves_need_idr_requests_nothing() {
        let mut r = Rig::new(cfg());
        r.live();
        r.ack(0, QueueDepth::Unavailable);
        r.at(10_000);
        r.step(sps(ParamClass::Other, ES3));
        assert_eq!(r.pump.state(), State::NeedIdr);
        assert_eq!(requests(&kinds(&ticks(&mut r, 10_000, 12_900))), (0, 0));
        r.at(13_100);
        let out = r.step(au(true, false));
        assert_eq!(kinds(&out), ["SendDvc"]);
        assert_eq!(r.pump.state(), State::Live);
        r.ack(1, QueueDepth::Unavailable);
        assert_eq!(requests(&kinds(&ticks(&mut r, 13_100, 16_000))), (0, 0));
    }

    /// m3: idr-wait counts open time only as the ticks see it, without the
    /// burst soft-gate exemption. A live frame left unacked holds the soft
    /// gate shut; burst P frames every 10 ms in NeedIdr must not count as
    /// open time (they did: 40 ms of every 50, and a forced IDR at 10 s —
    /// one the still-shut soft gate would drop).
    #[test]
    fn burst_aus_never_count_as_open_gate_time() {
        let mut c = cfg();
        c.flow.stall_timeout = Duration::from_secs(30);
        let mut r = Rig::new(c);
        r.live();
        r.ack(0, QueueDepth::Unavailable);
        assert_eq!(
            wire(&r.step(au(false, false))).len(),
            1,
            "frame 1, never acked"
        );
        ticks(&mut r, 0, 500);
        assert_eq!(
            r.pump.state(),
            State::NeedIdr,
            "the soft gate shut at 500 ms"
        );
        let mut out = Vec::new();
        for t in (510..=12_000).step_by(10) {
            r.at(t);
            out.extend(r.step(au(false, true)));
            if t % 50 == 0 {
                out.extend(r.step(Input::Tick));
            }
        }
        assert_eq!(r.metrics.frames_dropped.get("awaiting_idr"), 1150);
        assert_eq!(requests(&kinds(&out)), (0, 0), "{:?}", kinds(&out));
        assert_eq!(r.pump.state(), State::NeedIdr);
    }

    fn disconnects(out: &[Command]) -> Vec<Cause> {
        out.iter()
            .filter_map(|c| {
                if let Command::Disconnect(c) = c {
                    Some(*c)
                } else {
                    None
                }
            })
            .collect()
    }

    /// m5 (§6.7): only a connection's first negotiation without AVC420
    /// waits `avc420_timeout` for a better one; a second one in WaitReady
    /// gives up at once.
    #[test]
    fn a_second_negotiation_without_avc420_gives_up_at_once() {
        let mut r = Rig::new(cfg());
        r.start((640, 360));
        assert!(r.negotiate(v8_only()).is_empty());
        assert_eq!(r.pump.state(), State::WaitReady);
        r.at(2000);
        assert_eq!(disconnects(&r.negotiate(v8_only())), [Cause::NoAvc420]);
        assert_eq!(r.pump.state(), State::Closing);
    }

    /// m6 (§5.2, DC13): a Shutdown during an earlier close brings its abort
    /// forward to the shutdown's own watchdog (the 5 s exit budget) — and
    /// never pushes it later. The close keeps its cause and disconnects once.
    #[test]
    fn a_shutdown_during_a_close_shortens_its_watchdog_never_lengthens_it() {
        let mut r = Rig::new(cfg());
        r.live();
        assert_eq!(
            kinds(&r.step(Input::UpstreamFatal(Cause::KvmUnreachable))),
            ["ReleaseAll", "Disconnect"]
        );
        r.at(100);
        assert!(
            r.step(Input::Shutdown {
                watchdog: Duration::from_secs(2)
            })
            .is_empty()
        );
        assert!(!kinds(&ticks(&mut r, 100, 2000)).contains(&"Abort"));
        assert_eq!(
            kinds(&ticks(&mut r, 2000, 2100)),
            ["ReleaseAll", "Abort"],
            "2.1 s, not 5 s"
        );
        assert!(ticks(&mut r, 2100, 6000).is_empty(), "aborts once");
        assert_eq!(r.metrics.disconnects.total(), 1);

        let mut r = Rig::new(cfg());
        r.live();
        r.step(Input::UpstreamFatal(Cause::KvmUnreachable));
        r.at(4000);
        r.step(Input::Shutdown {
            watchdog: Duration::from_secs(2),
        });
        assert!(!kinds(&ticks(&mut r, 4000, 4900)).contains(&"Abort"));
        assert_eq!(
            kinds(&ticks(&mut r, 4900, 5000)),
            ["ReleaseAll", "Abort"],
            "1 s was left: kept"
        );
    }

    /// m7: a Setup IronRDP refuses — its EGFX channel closed between the
    /// negotiation and the step (`create_surface` fails outside Ready and
    /// Resizing) — closes the session at every Setup site, never leaves a
    /// NeedIdr with no FLV and nothing to time it out.
    #[test]
    fn a_refused_setup_closes_the_session_at_every_site() {
        use ironrdp_dvc::DvcProcessor as _;
        for site in ["first", "readvertise", "paused", "reactivation"] {
            let mut r = Rig::new(cfg());
            let input = match site {
                "first" => {
                    r.start((640, 360));
                    r.advertise(census_caps());
                    Input::OnReady { avc420: true }
                }
                "readvertise" => {
                    r.live();
                    Input::OnReady { avc420: true }
                }
                "paused" => {
                    r.live();
                    r.hold_suppress(true);
                    assert_eq!(r.pump.state(), State::Paused);
                    Input::OnReady { avc420: true }
                }
                _ => {
                    r.live();
                    r.step(sps(ParamClass::Resize, P480));
                    Input::ReactivationComplete
                }
            };
            r.gfx.close(CHAN);
            let out = r.step(input);
            assert_eq!(r.pump.state(), State::Closing, "{site}: {:?}", kinds(&out));
            assert_eq!(disconnects(&out), [Cause::NoAvc420], "{site}");
            assert!(!kinds(&out).contains(&"OpenFlv"), "{site}");
        }
    }

    /// m8: a resize never discards a half-filled burst chunk. `step()`
    /// flushes it before the SPS (its bytes already count in the backlog),
    /// so `start_resize` never finds one.
    #[test]
    fn a_resize_sends_a_half_filled_burst_chunk_first() {
        let mut r = Rig::new(cfg());
        r.live();
        for _ in 0..3 {
            assert!(r.step(au(false, true)).is_empty(), "the chunk fills");
        }
        let out = r.step(sps(ParamClass::Resize, P480));
        assert_eq!(kinds(&out), ["SendDvc", "DisplayResize"]);
        let Command::SendDvc(b) = &out[0] else {
            panic!("{:?}", kinds(&out))
        };
        assert_eq!((b.frames, b.yield_after), (3, true));
    }
}

/// §11.2: resize, suppression, stall, suspension, closing and the IDR
/// policies (Task 4.5). `a_suppression_ending_during_a_resize_from_paused_
/// lands_in_need_idr` (P5/DC23) already lives in `core::tests` — it is not
/// duplicated here; the brief's 19 cases plus that one is the planned 20.
#[cfg(test)]
mod lifecycle {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]
    use super::*;
    use crate::config::IdrPolicy;
    use crate::msg::FlvOrigin;
    use crate::pump::rig::*;
    use ironrdp_egfx::pdu::{GfxPdu, QueueDepth};

    fn ticks(r: &mut Rig, from_ms: u64, to_ms: u64) -> Vec<Command> {
        let mut out = Vec::new();
        for i in from_ms / 100 + 1..=to_ms / 100 {
            r.at(i * 100);
            out.extend(r.step(Input::Tick));
        }
        out
    }

    fn disconnects(out: &[Command]) -> Vec<Cause> {
        out.iter()
            .filter_map(|c| {
                if let Command::Disconnect(c) = c {
                    Some(*c)
                } else {
                    None
                }
            })
            .collect()
    }

    fn frame_id(out: &[Command]) -> u32 {
        pdus(out)
            .iter()
            .find_map(|p| {
                if let GfxPdu::StartFrame(s) = p {
                    Some(s.frame_id)
                } else {
                    None
                }
            })
            .unwrap()
    }

    /// §11.2: a second resize SPS during WaitReactivation is carried out
    /// after the first reactivation; the surface ends at the latest size.
    #[test]
    fn a_second_resize_during_wait_reactivation_runs_after_the_first() {
        let mut r = Rig::new(cfg());
        r.live();
        let out = r.step(sps(ParamClass::Resize, P480));
        assert!(matches!(
            out.last(),
            Some(Command::DisplayResize {
                width: 854,
                height: 480
            })
        ));
        r.step(sps(ParamClass::Resize, ES3));
        let out = r.step(Input::ReactivationComplete);
        assert!(
            matches!(
                out.last(),
                Some(Command::DisplayResize {
                    width: 640,
                    height: 360
                })
            ),
            "{:?}",
            kinds(&out)
        );
        assert_eq!(r.pump.state(), State::WaitReactivation);
        let out = r.step(Input::ReactivationComplete);
        let reset = pdus(&out).into_iter().find_map(|p| {
            if let GfxPdu::ResetGraphics(g) = p {
                Some((g.width, g.height))
            } else {
                None
            }
        });
        assert_eq!(reset, Some((640, 360)));
        assert_eq!(r.pump.state(), State::NeedIdr);
    }

    /// §11.2: `on_ready` during WaitReactivation is merged into the one
    /// Setup at ReactivationComplete.
    #[test]
    fn on_ready_during_wait_reactivation_is_merged() {
        let mut r = Rig::new(cfg());
        r.live();
        r.step(sps(ParamClass::Resize, P480));
        r.advertise(census_caps());
        assert!(pdus(&r.step(Input::OnReady { avc420: true })).is_empty());
        let out = r.step(Input::ReactivationComplete);
        assert_eq!(
            names(&pdus(&out))
                .iter()
                .filter(|n| **n == "ResetGraphics")
                .count(),
            1
        );
        assert_eq!(r.pump.state(), State::NeedIdr);
    }

    #[test]
    fn reactivation_complete_outside_wait_reactivation_is_ignored() {
        let mut r = Rig::new(cfg());
        r.need_idr();
        assert!(r.step(Input::ReactivationComplete).is_empty());
        r.step(au(true, false));
        assert!(r.step(Input::ReactivationComplete).is_empty());
        assert_eq!(r.pump.state(), State::Live);
    }

    /// §11.2: a resize started from Paused returns to Paused, with no second
    /// release for the same suppression edge.
    #[test]
    fn a_resize_started_from_paused_returns_to_paused() {
        let mut r = Rig::new(cfg());
        r.live();
        r.hold_suppress(true);
        assert_eq!(r.pump.state(), State::Paused);
        r.step(sps(ParamClass::Resize, P480));
        assert_eq!(r.pump.state(), State::WaitReactivation);
        let out = r.step(Input::ReactivationComplete);
        assert_eq!(r.pump.state(), State::Paused);
        assert!(!kinds(&out).contains(&"ReleaseAll"));
    }

    /// §11.2 suppression: a short pulse does nothing; a held pulse pauses
    /// and releases; nothing is sent while Paused; the falling edge is a
    /// Setup cause.
    #[test]
    fn suppression_pauses_on_a_held_pulse_and_resumes_as_a_setup_cause() {
        let mut r = Rig::new(cfg());
        r.live();
        r.step(Input::Suppress(true));
        r.at(500);
        r.step(Input::Suppress(false));
        r.at(2_000);
        r.step(Input::Suppress(false));
        assert_eq!(r.pump.state(), State::Live, "a short pulse does nothing");
        let out = r.hold_suppress(true);
        assert_eq!(r.pump.state(), State::Paused);
        assert!(
            out.iter()
                .any(|c| matches!(c, Command::ReleaseAll(ReleaseTrigger::Suppression)))
        );
        assert!(pdus(&r.step(au(true, false))).is_empty());
        r.at(6_000);
        let out = r.hold_suppress(false);
        assert_eq!(r.pump.state(), State::NeedIdr);
        assert!(kinds(&out).contains(&"RequestIdr"), "{:?}", kinds(&out));
    }

    #[test]
    fn suppression_before_the_first_kvm_frame_is_ignored() {
        let mut r = Rig::new(cfg());
        r.need_idr();
        let out = r.hold_suppress(true);
        assert_eq!(r.pump.state(), State::NeedIdr);
        assert!(!kinds(&out).contains(&"ReleaseAll"));
    }

    /// §11.2: suppression arriving in WaitReactivation releases at once and
    /// lands in Paused after reactivation.
    #[test]
    fn suppression_in_wait_reactivation_releases_at_once_then_lands_in_paused() {
        let mut r = Rig::new(cfg());
        r.live();
        r.step(sps(ParamClass::Resize, P480));
        assert_eq!(kinds(&r.hold_suppress(true)), ["ReleaseAll"]);
        let out = r.step(Input::ReactivationComplete);
        assert_eq!(r.pump.state(), State::Paused);
        assert!(!kinds(&out).contains(&"ReleaseAll"), "one release per edge");
    }

    /// §11.2 stall: fires at `stall_timeout` after the first closure; any
    /// ack disarms it; frozen in Paused for longer than the timeout → no
    /// disconnect.
    #[test]
    fn the_stall_fires_disarms_on_an_ack_and_freezes_in_paused() {
        let mut r = Rig::new(cfg());
        r.live(); // the IDR (grace 1.6 s) is never acked
        let out = ticks(&mut r, 0, 12_000);
        assert_eq!(disconnects(&out), [Cause::ClientStalled]);

        let mut r = Rig::new(cfg());
        r.live();
        let mut out = ticks(&mut r, 0, 6_000);
        out.extend(r.ack(0, QueueDepth::Unavailable));
        out.extend(ticks(&mut r, 6_000, 14_000));
        assert_eq!(disconnects(&out), [], "any ack disarms");

        let mut r = Rig::new(cfg());
        r.live();
        ticks(&mut r, 0, 2_000); // armed at 1.6 s, NeedIdr
        r.hold_suppress(true);
        assert_eq!(r.pump.state(), State::Paused);
        let out = ticks(&mut r, 3_000, 20_000);
        assert_eq!(disconnects(&out), [], "frozen in Paused");
    }

    /// §11.2 suspension: frames keep flowing and are not recorded; the
    /// suspension survives a server resize and a re-advertise and the
    /// picture continues (fork patch 1).
    #[test]
    fn suspended_acks_keep_frames_flowing_across_a_resize_and_a_readvertise() {
        let mut c = cfg();
        c.hard_cap = 4;
        let mut r = Rig::new(c);
        r.live();
        r.ack(0, QueueDepth::Suspend);
        for _ in 0..10 {
            assert_eq!(
                wire(&r.step(au(false, false))).len(),
                1,
                "more than the hard cap, all accepted"
            );
        }
        r.step(sps(ParamClass::Resize, P480));
        r.step(Input::ReactivationComplete);
        assert!(r.gfx.is_ack_suspended());
        assert_eq!(wire(&r.step(au(true, false))).len(), 1);
        for _ in 0..10 {
            assert_eq!(wire(&r.step(au(false, false))).len(), 1);
        }
        r.negotiate(census_caps());
        assert!(r.gfx.is_ack_suspended());
        assert_eq!(wire(&r.step(au(true, false))).len(), 1);
        for _ in 0..10 {
            assert_eq!(wire(&r.step(au(false, false))).len(), 1);
        }
    }

    /// §11.2: suspended, a backlog spike ≥ the limit that drains costs an IDR
    /// and no disconnect; held ≥ the limit for `stall_timeout` it closes.
    #[test]
    fn a_suspended_backlog_spike_costs_an_idr_and_a_held_one_closes() {
        let mut c = cfg();
        c.flow.backlog_limit = 1000;
        let mut r = Rig::new(c);
        r.live();
        r.ack(0, QueueDepth::Suspend);
        r.step(Input::Backlog { written: 0 });
        for _ in 0..40 {
            r.step(au(false, false));
        }
        assert_eq!(r.pump.state(), State::NeedIdr);
        assert!(r.metrics.frames_dropped.get("backlog_gate") >= 1);
        r.step(Input::Backlog { written: u64::MAX });
        assert_eq!(disconnects(&ticks(&mut r, 0, 1_000)), []);
        assert_eq!(wire(&r.step(au(true, false))).len(), 1);
        assert_eq!(r.pump.state(), State::Live);
        r.step(Input::Backlog { written: 0 });
        assert_eq!(
            disconnects(&ticks(&mut r, 1_000, 12_500)),
            [Cause::ClientStalled]
        );
    }

    /// §11.2: a resume ack clears the unacked set and restores normal gating
    /// without closing the soft gate.
    #[test]
    fn a_resume_ack_restores_gating_without_closing_the_soft_gate() {
        let mut r = Rig::new(cfg());
        r.live();
        r.ack(0, QueueDepth::Suspend);
        let mut last = 0;
        for i in 1..=10 {
            r.at(i * 100);
            last = frame_id(&r.step(au(false, false)));
        }
        r.ack(last, QueueDepth::Unavailable);
        assert!(!r.gfx.is_ack_suspended());
        r.at(1_600);
        assert_eq!(wire(&r.step(au(false, false))).len(), 1);
        assert_eq!(r.pump.state(), State::Live);
    }

    /// §11.2 standing delay: a previous connection's samples never affect
    /// the next (IronRDP's handle is per server). The core owns DC6's
    /// reference rule: a generation's first sample is only a reference,
    /// never in the baseline, and the signal is live once the handle moves.
    #[test]
    fn a_previous_connections_rtt_never_gates_the_next() {
        let mut r = Rig::new(cfg());
        r.live();
        r.ack(0, QueueDepth::Unavailable);
        // 900: the handle's stale value (reference only); then a live 10 ms
        // baseline and a standing queue: median 650 − 10 = 640 ms ≥ 500.
        for v in [900, 10, 600, 650, 700, 620, 640, 660, 680] {
            r.step(Input::Rtt(v));
        }
        assert!(
            wire(&r.step(au(false, false))).is_empty(),
            "standing delay closes the gate"
        );
        assert_eq!(r.metrics.frames_dropped.get("standing_delay"), 1);
        r.step(Input::SessionStop { generation: 1 });
        r.new_connection();
        r.step(Input::SessionStart {
            generation: 2,
            size: (640, 360),
        });
        r.negotiate(census_caps());
        r.step(Input::FlvOpened {
            origin: FlvOrigin::First,
        });
        r.step(sps(ParamClass::Initial, ES3));
        r.step(Input::Rtt(680)); // the handle still holds the old value: a reference only
        assert_eq!(wire(&r.step(au(true, false))).len(), 1);
        assert_eq!(r.pump.state(), State::Live);
    }

    /// §11.2 Closing: EGFX sends stop before `Disconnect`; the watchdog
    /// releases keys, stops the KVM side and aborts — once.
    #[test]
    fn closing_stops_sends_then_the_watchdog_aborts_once() {
        let mut r = Rig::new(cfg());
        r.live();
        let out = r.step(Input::UpstreamFatal(Cause::StreamIncompatible));
        assert_eq!(kinds(&out), ["ReleaseAll", "Disconnect"]);
        assert!(r.step(au(true, false)).is_empty());
        let out = ticks(&mut r, 0, 6_000);
        assert_eq!(kinds(&out), ["ReleaseAll", "Abort"]);
        assert!(matches!(
            out[0],
            Command::ReleaseAll(ReleaseTrigger::Watchdog)
        ));
        assert_eq!(r.metrics.disconnects.get("stream_incompatible"), 1);
    }

    /// §5.2, DC13: shutdown closes with cause `shutdown` and its own watchdog.
    #[test]
    fn shutdown_closes_with_its_own_watchdog() {
        let mut r = Rig::new(cfg());
        r.live();
        let out = r.step(Input::Shutdown {
            watchdog: Duration::from_secs(2),
        });
        assert!(matches!(
            out.last(),
            Some(Command::Disconnect(Cause::Shutdown))
        ));
        assert_eq!(kinds(&ticks(&mut r, 0, 1_900)), Vec::<&str>::new());
        assert_eq!(kinds(&ticks(&mut r, 1_900, 2_000)), ["ReleaseAll", "Abort"]);
    }

    /// §6.7: a first negotiation without AVC420 waits `avc420_timeout` (and a
    /// better set before it is taken); a re-advertise without it closes at
    /// once; a client that never negotiates is `no_avc420` at the timeout.
    #[test]
    fn no_avc420_waits_on_first_negotiation_and_closes_on_a_readvertise() {
        let mut r = Rig::new(cfg());
        r.start((640, 360));
        assert!(r.negotiate(v8_only()).is_empty());
        assert_eq!(r.pump.state(), State::WaitReady);
        assert_eq!(disconnects(&ticks(&mut r, 0, 9_900)), []);
        assert_eq!(
            disconnects(&ticks(&mut r, 9_900, 10_000)),
            [Cause::NoAvc420]
        );

        let mut r = Rig::new(cfg());
        r.start((640, 360));
        r.negotiate(v8_only());
        assert!(kinds(&r.negotiate(census_caps())).contains(&"OpenFlv"));

        let mut r = Rig::new(cfg());
        r.live();
        assert_eq!(disconnects(&r.negotiate(v8_only())), [Cause::NoAvc420]);

        let mut r = Rig::new(cfg());
        r.start((640, 360));
        assert_eq!(disconnects(&ticks(&mut r, 0, 10_000)), [Cause::NoAvc420]);
    }

    /// §11.2 "Every policy": a later Setup → `RequestIdr` (side),
    /// `ReconnectFlv` (reconnect), nothing (wait).
    #[test]
    fn a_later_setup_requests_per_policy() {
        for (policy, want) in [
            (IdrPolicy::Side, Some("RequestIdr")),
            (IdrPolicy::Reconnect, Some("ReconnectFlv")),
            (IdrPolicy::Wait, None),
        ] {
            let mut c = cfg();
            c.idr.policy = policy;
            let mut r = Rig::new(c);
            r.live();
            r.ack(0, QueueDepth::Unavailable);
            r.at(2_000);
            let k = kinds(&r.negotiate(census_caps()));
            match want {
                Some(w) => assert_eq!(
                    k.iter().filter(|x| **x == w).count(),
                    1,
                    "{policy:?}: {k:?}"
                ),
                None => assert!(
                    !k.contains(&"RequestIdr") && !k.contains(&"ReconnectFlv"),
                    "{k:?}"
                ),
            }
        }
    }

    /// §11.2: a transient reconnect clears `idr_pending` (a deferred request)
    /// and restarts both clocks.
    #[test]
    fn a_transient_reconnect_cancels_a_deferred_request() {
        let mut r = Rig::new(cfg());
        r.live();
        r.ack(0, QueueDepth::Unavailable);
        r.at(200);
        r.negotiate(census_caps()); // a Setup cause inside the setup window: deferred to 1 s
        r.at(500);
        r.step(Input::FlvOpened {
            origin: FlvOrigin::Transient,
        });
        let out = ticks(&mut r, 500, 4_000);
        assert!(!kinds(&out).contains(&"RequestIdr"), "{:?}", kinds(&out));
    }

    /// §11.2: a deferred request whose NeedIdr an IDR resolves inside the
    /// window → `CancelIdrRequest`, counted, and nothing requested later.
    #[test]
    fn an_idr_inside_the_window_cancels_the_deferred_request() {
        let mut r = Rig::new(cfg());
        r.live();
        r.ack(0, QueueDepth::Unavailable);
        r.at(200);
        let k = kinds(&r.negotiate(census_caps())); // a Setup cause: deferred to 1 s
        assert!(!k.contains(&"RequestIdr"), "{k:?}");
        r.at(300);
        let out = r.step(au(true, false));
        assert_eq!(wire(&out).len(), 1);
        assert!(
            kinds(&out).contains(&"CancelIdrRequest"),
            "{:?}",
            kinds(&out)
        );
        assert_eq!(r.metrics.idr_cancelled.get(), 1);
        r.ack(frame_id(&out), QueueDepth::Unavailable);
        let later = kinds(&ticks(&mut r, 300, 3_000));
        assert!(
            !later.contains(&"RequestIdr") && !later.contains(&"ReconnectFlv"),
            "{later:?}"
        );
    }

    /// §11.2: an IDR dropped at a closed gate counts as a flow cause: the
    /// request comes after `idr_wait_max` of open gates, deferred to the
    /// flow clock's window (10 s from the FLV open). `stall_timeout` is set
    /// past that window: no ack can arrive (nothing was sent), so at the
    /// default 10 s the stall would close the session at the same tick.
    #[test]
    fn an_idr_dropped_at_a_closed_gate_is_a_flow_cause() {
        let mut c = cfg();
        c.flow.backlog_limit = 10;
        c.flow.stall_timeout = Duration::from_secs(30);
        let mut r = Rig::new(c);
        r.need_idr(); // the Setup batch alone is over 10 bytes, none written
        assert!(pdus(&r.step(au(true, false))).is_empty());
        assert_eq!(r.metrics.frames_dropped.get("backlog_gate"), 1);
        r.step(Input::Backlog { written: u64::MAX });
        let early = ticks(&mut r, 0, 9_900);
        assert!(
            !kinds(&early).contains(&"RequestIdr"),
            "not before the flow window's end: {:?}",
            kinds(&early)
        );
        let out = ticks(&mut r, 9_900, 10_500);
        assert_eq!(
            kinds(&out).iter().filter(|k| **k == "RequestIdr").count(),
            1,
            "at 10 000 ms, on the flow clock"
        );
        assert_eq!(disconnects(&early), []);
        assert_eq!(disconnects(&out), []);
    }

    /// Fix round 1, m1: the stall test above bounds its fire time to
    /// (6.0 s, 12.0 s] but never pins it to §6.6's `stall_timeout` (10 s)
    /// after the first closure. Kills the core-level wiring mutants S6, S7,
    /// S9 (1.5–5 s early) and S8 (300 ms late).
    #[test]
    fn the_stall_fires_at_the_timeout() {
        let mut r = Rig::new(cfg());
        r.live();
        assert_eq!(disconnects(&ticks(&mut r, 0, 11_500)), []);
        assert_eq!(
            disconnects(&ticks(&mut r, 11_500, 11_600)),
            [Cause::ClientStalled]
        );
    }

    /// Fix round 1, I1 (§6.4, §6.6, §11.2): "The stall timer is frozen in
    /// Paused **and WaitReactivation**" — only Paused was covered. Kills S2
    /// (`set_state`'s `matches!(new, State::Paused | State::WaitReactivation)`
    /// narrowed to `State::Paused` alone).
    #[test]
    fn the_stall_is_frozen_in_wait_reactivation() {
        let mut r = Rig::new(cfg());
        r.live();
        ticks(&mut r, 0, 2_000); // armed at 1.6 s, NeedIdr
        r.step(sps(ParamClass::Resize, P480));
        assert_eq!(r.pump.state(), State::WaitReactivation);
        assert_eq!(
            disconnects(&ticks(&mut r, 2_000, 20_000)),
            [],
            "frozen in WaitReactivation"
        );
    }

    /// Fix round 1, I2(a): "a backlog spike ≥ the limit that drains costs an
    /// IDR and no disconnect" is only exercised on the AU path, which drains
    /// before the first tick ever sees it, and "no disconnect" is only
    /// checked for 1 s past the drain, not past `stall_timeout`. Let a tick
    /// see the spike, then drain, then run past `stall_timeout`. Kills U7
    /// (`on_tick` computing `suspended = false`, which arms the stall
    /// instead of disarming it and closes `client_stalled` 10 s later).
    #[test]
    fn a_suspended_spike_ticks_see_then_drained_never_disconnects() {
        let mut c = cfg();
        c.flow.backlog_limit = 1000;
        let mut r = Rig::new(c);
        r.live();
        r.ack(0, QueueDepth::Suspend);
        r.step(Input::Backlog { written: 0 });
        for _ in 0..40 {
            r.step(au(false, false));
        }
        assert_eq!(r.pump.state(), State::NeedIdr);
        assert_eq!(
            disconnects(&ticks(&mut r, 0, 500)),
            [],
            "a tick sees the spike"
        );
        r.step(Input::Backlog { written: u64::MAX });
        assert_eq!(
            disconnects(&ticks(&mut r, 500, 15_000)),
            [],
            "drained, and no stall past stall_timeout"
        );
        assert_eq!(wire(&r.step(au(true, false))).len(), 1);
        assert_eq!(r.pump.state(), State::Live);
    }

    /// Fix round 1, I2(b): "frames keep flowing and are not recorded" while
    /// suspended is only established at `Flow` level
    /// (`flow::tests::suspended_acks_record_nothing_and_a_resume_clears_the_
    /// set`); the core-level suspension test above claims it in its doc but
    /// never checks it. Kills U2 (`send_au` passing `suspended = false` to
    /// `record`, which grows the unacked set and climbs
    /// `egfx_oldest_unacked_ms` for the whole suspension).
    #[test]
    fn suspended_frames_are_not_recorded() {
        let mut r = Rig::new(cfg());
        r.live();
        r.ack(0, QueueDepth::Suspend);
        for i in 1..=10 {
            r.at(i * 100);
            assert_eq!(wire(&r.step(au(false, false))).len(), 1);
        }
        r.at(2_000);
        r.step(Input::Tick);
        assert_eq!(r.metrics.egfx_oldest_unacked_ms.get(), 0);
    }
}

/// §11.2: every cell of §6.4's state × input table (Task 4.6).
#[cfg(test)]
mod table {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]
    use super::*;
    use crate::msg::FlvOrigin;
    use crate::pump::rig::*;
    use State::{Closing, Live, NeedIdr, Paused, WaitReactivation, WaitReady};

    /// §6.4's columns.
    #[derive(Debug, Clone, Copy)]
    enum Col {
        ReadyAvc,
        ReadyNoAvc,
        SpsNeedingResize,
        SpsSameOrOther,
        FlvOpened,
        Reactivated,
        SuppressOn,
        SuppressOff,
        IdrAu,
        PAu,
        GateCloses,
        Fatal,
    }
    use Col::*;

    /// Each row's canonical state; suppression counts in every one (a KVM
    /// frame was delivered) except WaitReady.
    fn rig_in(s: State) -> Rig {
        let mut r = Rig::new(cfg());
        match s {
            WaitReady => {
                r.start((640, 360));
            }
            NeedIdr => {
                r.live();
                r.step(Input::FlvOpened {
                    origin: FlvOrigin::Transient,
                });
            }
            Live => {
                r.live();
            }
            WaitReactivation => {
                r.live();
                r.step(sps(ParamClass::Resize, P480));
            }
            Paused => {
                r.live();
                r.hold_suppress(true);
            }
            Closing => {
                r.live();
                r.step(Input::UpstreamFatal(Cause::KvmUnreachable));
            }
            State::Idle => {}
        }
        r
    }

    /// Ticks every 100 ms over (from, to].
    fn ticks(r: &mut Rig, from_ms: u64, to_ms: u64) -> Vec<Command> {
        let mut out = Vec::new();
        for i in from_ms / 100 + 1..=to_ms / 100 {
            r.at(i * 100);
            out.extend(r.step(Input::Tick));
        }
        out
    }

    fn apply(r: &mut Rig, c: Col) -> Vec<Command> {
        let at_size = if r.pump.size() == (640, 360) {
            ES3
        } else {
            P480
        };
        let other_size = if r.pump.size() == (640, 360) {
            P480
        } else {
            ES3
        };
        match c {
            ReadyAvc => r.negotiate(census_caps()),
            ReadyNoAvc => r.negotiate(v8_only()),
            SpsNeedingResize => r.step(sps(ParamClass::Resize, other_size)),
            SpsSameOrOther => r.step(sps(ParamClass::Other, at_size)),
            FlvOpened => r.step(Input::FlvOpened {
                origin: FlvOrigin::Transient,
            }),
            Reactivated => r.step(Input::ReactivationComplete),
            SuppressOn => r.hold_suppress(true),
            SuppressOff => r.hold_suppress(false),
            IdrAu => r.step(au(true, false)),
            PAu => r.step(au(false, false)),
            GateCloses => {
                let later = r.ms() + 2_000; // the unacked IDR's grace runs out
                r.at(later);
                r.step(Input::Tick)
            }
            Fatal => r.step(Input::UpstreamFatal(Cause::StreamCorrupt)),
        }
    }

    const SEND: &str = "SendDvc";
    const RESIZE: &str = "DisplayResize";
    const RELEASE: &str = "ReleaseAll";
    const DISC: &str = "Disconnect";
    const OPEN: &str = "OpenFlv";

    /// (state, column, next state, must issue, must not issue).
    type Cell = (
        State,
        Col,
        State,
        &'static [&'static str],
        &'static [&'static str],
    );

    #[rustfmt::skip]
    const TABLE: &[Cell] = &[
        (WaitReady, ReadyAvc, NeedIdr, &[SEND, OPEN], &[]),
        (WaitReady, ReadyNoAvc, WaitReady, &[], &[DISC]),
        (WaitReady, SpsNeedingResize, WaitReady, &[], &[RESIZE]),
        (WaitReady, SpsSameOrOther, WaitReady, &[], &[SEND]),
        (WaitReady, FlvOpened, WaitReady, &[], &[SEND]),
        (WaitReady, Reactivated, WaitReady, &[], &[SEND]),
        (WaitReady, SuppressOn, WaitReady, &[], &[RELEASE]),
        (WaitReady, SuppressOff, WaitReady, &[], &[RELEASE]),
        (WaitReady, IdrAu, WaitReady, &[], &[SEND]),
        (WaitReady, PAu, WaitReady, &[], &[SEND]),
        (WaitReady, GateCloses, WaitReady, &[], &[SEND]),
        (WaitReady, Fatal, Closing, &[DISC], &[SEND]),

        (NeedIdr, ReadyAvc, NeedIdr, &[SEND], &[DISC]),
        (NeedIdr, ReadyNoAvc, Closing, &[DISC], &[SEND]),
        (NeedIdr, SpsNeedingResize, WaitReactivation, &[RESIZE], &[SEND]),
        (NeedIdr, SpsSameOrOther, NeedIdr, &[], &[SEND, "ReconnectFlv"]),
        (NeedIdr, FlvOpened, NeedIdr, &[], &[SEND, "RequestIdr"]),
        (NeedIdr, Reactivated, NeedIdr, &[], &[SEND]),
        (NeedIdr, SuppressOn, Paused, &[RELEASE], &[SEND]),
        (NeedIdr, SuppressOff, NeedIdr, &[], &[RELEASE]),
        (NeedIdr, IdrAu, Live, &[SEND], &[]),
        (NeedIdr, PAu, NeedIdr, &[], &[SEND]),
        (NeedIdr, GateCloses, NeedIdr, &[], &[SEND]),
        (NeedIdr, Fatal, Closing, &[DISC], &[SEND]),

        (Live, ReadyAvc, NeedIdr, &[SEND], &[DISC]),
        (Live, ReadyNoAvc, Closing, &[DISC], &[SEND]),
        (Live, SpsNeedingResize, WaitReactivation, &[RESIZE], &[SEND]),
        (Live, SpsSameOrOther, NeedIdr, &[], &[SEND, "ReconnectFlv"]),
        (Live, FlvOpened, NeedIdr, &[], &[SEND, "RequestIdr"]),
        (Live, Reactivated, Live, &[], &[SEND]),
        (Live, SuppressOn, Paused, &[RELEASE], &[SEND]),
        (Live, SuppressOff, Live, &[], &[RELEASE]),
        (Live, IdrAu, Live, &[SEND], &[]),
        (Live, PAu, Live, &[SEND], &[]),
        (Live, GateCloses, NeedIdr, &[], &[SEND]),
        (Live, Fatal, Closing, &[DISC], &[SEND]),

        (WaitReactivation, ReadyAvc, WaitReactivation, &[], &[SEND]),
        (WaitReactivation, ReadyNoAvc, Closing, &[DISC], &[SEND]),
        (WaitReactivation, SpsNeedingResize, WaitReactivation, &[], &[RESIZE, SEND]),
        (WaitReactivation, SpsSameOrOther, WaitReactivation, &[], &[SEND]),
        (WaitReactivation, FlvOpened, WaitReactivation, &[], &[SEND]),
        (WaitReactivation, Reactivated, NeedIdr, &[SEND], &[]),
        (WaitReactivation, SuppressOn, WaitReactivation, &[RELEASE], &[SEND]),
        (WaitReactivation, SuppressOff, WaitReactivation, &[], &[SEND]),
        (WaitReactivation, IdrAu, WaitReactivation, &[], &[SEND]),
        (WaitReactivation, PAu, WaitReactivation, &[], &[SEND]),
        (WaitReactivation, GateCloses, WaitReactivation, &[], &[SEND]),
        (WaitReactivation, Fatal, Closing, &[DISC], &[SEND]),

        (Paused, ReadyAvc, Paused, &[SEND], &[DISC]),
        (Paused, ReadyNoAvc, Closing, &[DISC], &[SEND]),
        (Paused, SpsNeedingResize, WaitReactivation, &[RESIZE], &[SEND]),
        (Paused, SpsSameOrOther, Paused, &[], &[SEND]),
        (Paused, FlvOpened, Paused, &[], &[SEND]),
        (Paused, Reactivated, Paused, &[], &[SEND]),
        (Paused, SuppressOn, Paused, &[], &[RELEASE]),
        (Paused, SuppressOff, NeedIdr, &[], &[RELEASE]),
        (Paused, IdrAu, Paused, &[], &[SEND]),
        (Paused, PAu, Paused, &[], &[SEND]),
        (Paused, GateCloses, Paused, &[], &[SEND]),
        (Paused, Fatal, Closing, &[DISC], &[SEND]),

        (Closing, ReadyAvc, Closing, &[], &[SEND, OPEN, DISC]),
        (Closing, ReadyNoAvc, Closing, &[], &[SEND, DISC]),
        (Closing, SpsNeedingResize, Closing, &[], &[RESIZE, SEND]),
        (Closing, SpsSameOrOther, Closing, &[], &[SEND]),
        (Closing, FlvOpened, Closing, &[], &[SEND]),
        (Closing, Reactivated, Closing, &[], &[SEND]),
        (Closing, SuppressOn, Closing, &[], &[RELEASE]),
        (Closing, SuppressOff, Closing, &[], &[RELEASE]),
        (Closing, IdrAu, Closing, &[], &[SEND]),
        (Closing, PAu, Closing, &[], &[SEND]),
        (Closing, GateCloses, Closing, &[], &[SEND, "Abort"]),
        (Closing, Fatal, Closing, &[], &[DISC]),
    ];

    #[test]
    fn every_cell_of_the_section_6_4_table() {
        assert_eq!(TABLE.len(), 72, "6 states × 12 inputs");
        let mut failures = Vec::new();
        for &(state, col, next, must, must_not) in TABLE {
            let mut r = rig_in(state);
            // m3: a bad canonical construction (e.g. a state-transition
            // mutant breaking `rig_in`'s own precondition) must not panic
            // and hide every other cell's report — record it and move on.
            if r.pump.state() != state {
                failures.push(format!(
                    "{state:?} × {col:?}: rig_in landed in {:?} instead of the canonical {state:?}",
                    r.pump.state()
                ));
                continue;
            }
            let out = apply(&mut r, col);
            let k = kinds(&out);
            if r.pump.state() != next {
                failures.push(format!(
                    "{state:?} × {col:?}: now {:?}, want {next:?} ({k:?})",
                    r.pump.state()
                ));
            }
            for m in must {
                if !k.contains(m) {
                    failures.push(format!("{state:?} × {col:?}: missing {m} ({k:?})"));
                }
            }
            for m in must_not {
                if k.contains(m) {
                    failures.push(format!("{state:?} × {col:?}: must not {m} ({k:?})"));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "{} cells wrong:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// Fix round 1, m4: only `TABLE.len() == 72` was checked, so a
    /// duplicated row silently replacing another would still pass.
    #[test]
    fn every_state_column_pair_in_the_table_is_distinct() {
        let mut seen: Vec<String> = TABLE
            .iter()
            .map(|&(s, c, ..)| format!("{s:?}×{c:?}"))
            .collect();
        let n = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), n, "a (state, col) pair repeats in TABLE");
    }

    /// Fix round 1, m2: the generic `rig_in(WaitReactivation)` is reached
    /// from `Live`, unsuppressed — so the table's own
    /// `(WaitReactivation, SuppressOff, WaitReactivation, …)` cell never
    /// delivers a real Off edge (the debouncer is already settled at off,
    /// so `hold_suppress(false)` is a no-op). T13 was killed only by
    /// `tests::a_suppression_ending_during_a_resize_from_paused_lands_in_
    /// need_idr`. Reach WaitReactivation through Paused instead, so a real
    /// On-then-Off pair crosses it, and also check the P5 invariant it
    /// depends on: reactivation still lands in NeedIdr, not back in Paused.
    #[test]
    fn suppress_off_in_wait_reactivation_reached_from_paused_still_just_records() {
        let mut r = Rig::new(cfg());
        r.live();
        r.hold_suppress(true);
        assert_eq!(r.pump.state(), Paused);
        r.step(sps(ParamClass::Resize, P480));
        assert_eq!(r.pump.state(), WaitReactivation);
        let out = r.hold_suppress(false);
        assert_eq!(
            r.pump.state(),
            WaitReactivation,
            "SuppressOff only records here (T13)"
        );
        assert!(!kinds(&out).contains(&"ReleaseAll"));
        let out = r.step(Input::ReactivationComplete);
        assert_eq!(
            r.pump.state(),
            NeedIdr,
            "the Off edge already cleared return_to_paused (P5)"
        );
        assert!(!kinds(&out).contains(&"ReleaseAll"));
    }

    /// Deviation from the brief (§6.5): `FlvOpened` while waiting
    /// (`WaitReady`, `WaitReactivation`) now restarts both IDR clocks
    /// instead of being "ignored" — the table's cells for these two rows
    /// are unconstrained on `RequestIdr`/`ReconnectFlv` (an absence-only
    /// effect per the reviewer's P30 ruling), so this asserts the restart
    /// directly rather than leaving it untested.
    ///
    /// `WaitReactivation`: an open just before `ReactivationComplete`
    /// pushes the setup clock's reference forward; without the restart the
    /// clock would still be at the connection's first FLV open (long since
    /// expired), and the reactivation's Setup cause would fire at once.
    #[test]
    fn flv_opened_in_wait_reactivation_restarts_the_clock_so_reactivation_requests_nothing() {
        let mut r = rig_in(WaitReactivation);
        r.at(1_500);
        assert!(apply(&mut r, FlvOpened).is_empty());
        r.at(1_550);
        let out = apply(&mut r, Reactivated);
        assert_eq!(r.pump.state(), NeedIdr);
        assert!(
            !kinds(&out).contains(&"RequestIdr"),
            "the open restarted the setup clock: {:?}",
            kinds(&out)
        );
        // Fix round 1, m5: the positive half — this is only an absence
        // check so far, so it would still pass if reactivation stopped
        // being a Setup cause at all (R1) instead of merely being deferred.
        // The deferred request still fires, at the open's window end
        // (1 500 + interval_setup = 2 500 ms), not before and not never.
        assert!(!kinds(&ticks(&mut r, 1_550, 2_400)).contains(&"RequestIdr"));
        let k = kinds(&ticks(&mut r, 2_400, 2_500));
        assert_eq!(k.iter().filter(|x| **x == "RequestIdr").count(), 1, "{k:?}");
    }

    /// `WaitReady`: an open before the connection's first `OnReady` sets a
    /// reference for the setup clock even though the first Setup never
    /// calls `setup_cause` itself (§6.5: "except the first Setup, whose
    /// `OpenFlv` serves"); a re-advertise shortly after must still see that
    /// reference and defer, not fire at once (which it would with no
    /// reference at all — the pre-fix "ignore" behaviour).
    #[test]
    fn flv_opened_in_wait_ready_restarts_the_clock_so_the_next_setup_cause_is_deferred() {
        let mut r = rig_in(WaitReady);
        r.at(100);
        assert!(apply(&mut r, FlvOpened).is_empty());
        let out = apply(&mut r, ReadyAvc);
        assert_eq!(r.pump.state(), NeedIdr);
        assert!(
            !kinds(&out).contains(&"RequestIdr"),
            "the first Setup: {:?}",
            kinds(&out)
        );
        r.at(150);
        let out = apply(&mut r, ReadyAvc);
        assert!(
            !kinds(&out).contains(&"RequestIdr"),
            "the open restarted the setup clock: {:?}",
            kinds(&out)
        );
    }
}
