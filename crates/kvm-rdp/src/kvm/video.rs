//! One session's main FLV (§6.2, §6.9): opened with the session's token,
//! every tag through `kvm_proto`'s demuxer and `VideoAdmission`, parameter
//! changes and AUs to the pump on the ordered stream (AUs by `try_send`,
//! DC12), and §6.9's response to each failure — transient reconnects with
//! backoff, the idle timeout, three framing violations a minute, the tag
//! deadline — plus `ReconnectFlv`'s make-before-break swap (§6.5).
use crate::kvm::endpoint::KvmEndpoint;
use crate::kvm::error::{FailClass, KvmError};
use crate::kvm::flv::FlvConn;
use crate::kvm::upstream::{Backoff, Deadline};
use crate::metrics::Metrics;
use crate::msg::{Cause, FlvOrigin, Gen, KvmAu, KvmEvent};
use bytes::Bytes;
use futures_util::future::BoxFuture;
use kvm_proto::Token;
use kvm_proto::flv::{FlvDemuxer, FlvError, FlvLimits, FlvTag};
use kvm_proto::video::{
    AccessUnit, AdmissionConfig, AdmissionError, ParamClass, VideoAdmission, ViolationVerdict,
    ViolationWindow,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{self, error::TrySendError};

pub struct FlvSettings {
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub deadline: Duration,
    pub admission: AdmissionConfig,
}

/// What `ready` produced, for `on_ready` (opaque to callers).
///
/// Contract: hand every `Ready` to `on_ready` before the next `ready()` or
/// any other call on the same `Video`. `ready()` has already taken a
/// finished open out of its slot (so polling again never re-polls a
/// completed future), which means a `Ready::Opened` dropped instead closes
/// that connection and leaves nothing scheduled to replace it — only the
/// next request or the upstream deadline would act.
pub enum Ready {
    Opened {
        res: Result<FlvConn, KvmError>,
        origin: FlvOrigin,
        seq: u64,
    },
    Main(Result<Option<Bytes>, KvmError>),
    Pending(Result<Option<Bytes>, KvmError>),
}

/// What the session must act on.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The FLV was refused for the token with this sequence number.
    Refused {
        seq: u64,
    },
    Fatal(Cause),
}

struct Stream {
    conn: FlvConn,
    demux: FlvDemuxer,
    got_tag: bool,
    /// The sequence number of the token it was opened with.
    seq: u64,
    /// When the connection opened: a `ReconnectFlv` candidate with no tag
    /// `connect_timeout` after this is abandoned (see `Video::tick`).
    since: Instant,
}

struct Opening {
    fut: BoxFuture<'static, Result<FlvConn, KvmError>>,
    origin: FlvOrigin,
    seq: u64,
}

pub struct Video {
    generation: Gen,
    ep: Arc<KvmEndpoint>,
    to_pump: mpsc::Sender<KvmEvent>,
    metrics: Arc<Metrics>,
    settings: FlvSettings,
    admission: VideoAdmission,
    violations: ViolationWindow,
    backoff: Backoff,
    deadline: Deadline,
    wanted: bool,
    waiting_token: bool,
    main: Option<Stream>,
    /// A `ReconnectFlv` candidate, read until its first tag (§6.5).
    pending: Option<Stream>,
    opening: Option<Opening>,
    retry_at: Option<Instant>,
    next_origin: FlvOrigin,
    last_tag: Instant,
    dropped: bool,
    /// The previous AU on this connection (§10.4 inter-arrival).
    last_au: Option<Instant>,
    fps: FpsMeter,
    /// The token a new main FLV proved by reaching its first tag, until
    /// the session takes it (`take_proven`).
    proven: Option<u64>,
    /// Each chunk's demuxed tags, one allocation reused for every chunk
    /// (Plan E Task 1.4); empty between chunks.
    tags: Vec<FlvTag>,
}

/// §10.4 fps: AUs admitted over the last whole second, published once a
/// second. Sans-IO: `au` takes `now`.
#[derive(Debug, Default)]
pub(crate) struct FpsMeter {
    since: Option<Instant>,
    count: u32,
}

impl FpsMeter {
    /// Count one AU; `Some(fps)` when a second (or more) has closed.
    pub(crate) fn au(&mut self, now: Instant) -> Option<u32> {
        let Some(since) = self.since else {
            self.since = Some(now);
            self.count = 1;
            return None;
        };
        let elapsed = now.saturating_duration_since(since);
        if elapsed < Duration::from_secs(1) {
            self.count = self.count.saturating_add(1);
            return None;
        }
        let ms = u64::try_from(elapsed.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let fps = u64::from(self.count).saturating_mul(1000) / ms;
        self.since = Some(now);
        self.count = 1;
        Some(u32::try_from(fps).unwrap_or(u32::MAX))
    }

    pub(crate) fn reset(&mut self) {
        *self = FpsMeter::default();
    }
}

pub(crate) fn class_label(c: ParamClass) -> &'static str {
    match c {
        ParamClass::Initial => "initial",
        ParamClass::Resize => "resize",
        ParamClass::Other => "other",
    }
}

/// Demux `bytes` into `tags`, the caller's reused buffer (Plan E Task 1.4:
/// no `Vec` per chunk).
fn drain(demux: &mut FlvDemuxer, bytes: &[u8], tags: &mut Vec<FlvTag>) -> Option<FlvError> {
    demux.push(bytes);
    loop {
        match demux.next_tag() {
            Ok(Some(t)) => tags.push(t),
            Ok(None) => return None,
            Err(e) => return Some(e),
        }
    }
}

/// The open in `slot`, taken out of it in the poll that completes it, so
/// a finished future is never polled again (m4). Cancel-safe: a poll that
/// does not complete leaves the slot as it was.
async fn opening_result(slot: &mut Option<Opening>) -> Ready {
    let Some(o) = slot.as_mut() else {
        return std::future::pending().await;
    };
    let res = (&mut o.fut).await;
    let (origin, seq) = (o.origin, o.seq);
    *slot = None;
    Ready::Opened { res, origin, seq }
}

async fn stream_chunk(slot: &mut Option<Stream>) -> Result<Option<Bytes>, KvmError> {
    match slot {
        Some(s) => s.conn.chunk().await,
        None => std::future::pending().await,
    }
}

impl Video {
    pub fn new(
        generation: Gen,
        ep: Arc<KvmEndpoint>,
        to_pump: mpsc::Sender<KvmEvent>,
        metrics: Arc<Metrics>,
        settings: FlvSettings,
        backoff: Backoff,
    ) -> Video {
        Video {
            generation,
            ep,
            to_pump,
            metrics,
            admission: VideoAdmission::new(settings.admission.clone()),
            violations: ViolationWindow::stream_corrupt(),
            deadline: Deadline::new(settings.deadline),
            settings,
            backoff,
            wanted: false,
            waiting_token: false,
            main: None,
            pending: None,
            opening: None,
            retry_at: None,
            next_origin: FlvOrigin::First,
            last_tag: Instant::now(),
            dropped: false,
            last_au: None,
            fps: FpsMeter::default(),
            proven: None,
            tags: Vec::with_capacity(8),
        }
    }

    /// `OpenFlv`: the first Setup wants video (§6.4).
    pub fn want(&mut self, now: Instant, token: Option<&(u64, Token)>) {
        if self.wanted {
            return;
        }
        self.wanted = true;
        self.next_origin = FlvOrigin::First;
        self.deadline.flv_wanted(now);
        match token {
            Some(t) => self.start_open(t, FlvOrigin::First),
            None => self.waiting_token = true,
        }
    }

    /// `ReconnectFlv`: open a second FLV and swap at its first tag (§6.5).
    /// At most one is in flight: every FLV open forces an IDR on every
    /// viewer of the shared encoder (census Leg A).
    ///
    /// With no main FLV there is nothing to make before breaking, and a
    /// reopen is always already scheduled (`retry_at`, after `lost` or a
    /// transient open failure), in flight (`opening`) or waiting for a new
    /// token (`waiting_token`, after a refusal); its `FlvOpened` serves the
    /// request. Opening here instead would bypass the backoff, or reuse the
    /// token just refused (m2, PC8 fix round 1).
    pub fn reconnect(&mut self, now: Instant, token: Option<&(u64, Token)>) {
        let Some(t) = token else { return };
        if !self.wanted {
            self.want(now, Some(t));
            return;
        }
        if self.main.is_none() {
            debug_assert!(
                self.opening.is_some() || self.retry_at.is_some() || self.waiting_token,
                "no main FLV and no reopen scheduled"
            );
            return;
        }
        if self.opening.is_some() || self.pending.is_some() {
            return;
        }
        self.metrics.idr_requests.inc("reconnect");
        self.start_open(t, FlvOrigin::Commanded);
    }

    /// A (new) token is available: open if we were waiting for one.
    pub fn token_ready(&mut self, token: &(u64, Token)) {
        if self.wanted && self.waiting_token && self.opening.is_none() && self.main.is_none() {
            self.start_open(token, self.next_origin);
        }
    }

    /// Drop every connection; nothing reopens.
    pub fn close(&mut self) {
        self.stopped_streaming();
        self.main = None;
        self.pending = None;
        self.opening = None;
        self.wanted = false;
        self.retry_at = None;
        self.waiting_token = false;
        self.proven = None;
    }

    /// The sequence number of the token a new main FLV proved by reaching
    /// its first tag since the last call (§6.9, rev 6.2: the KVM accepted
    /// it), for the session's `AuthGate`. Call after every `on_ready`.
    pub fn take_proven(&mut self) -> Option<u64> {
        self.proven.take()
    }

    fn start_open(&mut self, token: &(u64, Token), origin: FlvOrigin) {
        self.retry_at = None;
        self.waiting_token = false;
        let (ep, tok, ct) = (
            self.ep.clone(),
            token.1.clone(),
            self.settings.connect_timeout,
        );
        self.opening = Some(Opening {
            fut: Box::pin(async move { FlvConn::open(&ep, &tok, ct).await }),
            origin,
            seq: token.0,
        });
    }

    /// The next thing to act on. Cancel-safe; see [`Ready`] for what must
    /// happen to its result.
    pub async fn ready(&mut self) -> Ready {
        tokio::select! {
            r = opening_result(&mut self.opening) => r,
            c = stream_chunk(&mut self.pending) => Ready::Pending(c),
            c = stream_chunk(&mut self.main) => Ready::Main(c),
        }
    }

    /// Act on what `ready` produced.
    ///
    /// **Not cancel-safe**: run it to completion — in a `select!` arm's
    /// body, never as a branch. Cancelled once it has made a connection the
    /// main FLV, it loses that connection's `FlvOpened` and the chunk's
    /// tags, and the pump would wait on an FLV it never heard of. Its only
    /// awaits are the control sends to the pump (§4.3).
    pub async fn on_ready(&mut self, r: Ready, now: Instant) -> Option<Outcome> {
        match r {
            Ready::Opened { res, origin, seq } => {
                // `close()` ran since `ready`: nothing reopens.
                if !self.wanted {
                    return None;
                }
                match res {
                    Ok(conn) => self.opened(conn, origin, seq, now).await,
                    Err(e) => self.open_failed(e, origin, seq, now),
                }
            }
            Ready::Main(c) => self.main_chunk(c, now).await,
            Ready::Pending(c) => self.pending_chunk(c, now).await,
        }
    }

    /// Idle timeout, deadline, the `ReconnectFlv` candidate's bound and
    /// scheduled reconnects (§6.9).
    pub fn tick(&mut self, now: Instant, token: Option<&(u64, Token)>) -> Option<Outcome> {
        if !self.wanted {
            return None;
        }
        if self.deadline.expired(now) {
            self.close();
            return Some(Outcome::Fatal(Cause::KvmUnreachable));
        }
        if self.main.is_some()
            && now.saturating_duration_since(self.last_tag) >= self.settings.idle_timeout
        {
            self.lost("idle", now);
        }
        // A candidate still has no first tag `connect_timeout` after it
        // opened: a wedged or hostile KVM must not hold it — and with it
        // every later `ReconnectFlv`, the side request's fallback — for
        // the rest of the session. The main FLV is untouched.
        if self.pending.as_ref().is_some_and(|p| {
            now.saturating_duration_since(p.since) >= self.settings.connect_timeout
        }) {
            self.pending = None;
            self.metrics.upstream_reconnects.inc("commanded_failed");
        }
        // With a candidate in flight, the transient reopen waits for it to
        // swap in or be abandoned: a second new FLV beside it would force
        // one more IDR on every viewer (census Leg A).
        if self.main.is_none()
            && self.opening.is_none()
            && self.pending.is_none()
            && !self.waiting_token
            && self.retry_at.is_some_and(|t| now >= t)
        {
            match token {
                Some(t) => self.start_open(t, self.next_origin),
                None => self.waiting_token = true,
            }
        }
        None
    }

    async fn opened(
        &mut self,
        conn: FlvConn,
        origin: FlvOrigin,
        seq: u64,
        now: Instant,
    ) -> Option<Outcome> {
        let stream = Stream {
            conn,
            demux: FlvDemuxer::new(FlvLimits::default()),
            got_tag: false,
            seq,
            since: now,
        };
        if origin == FlvOrigin::Commanded && self.main.is_some() {
            self.pending = Some(stream);
            return None;
        }
        self.main = Some(stream);
        self.became_main(origin, now).await;
        None
    }

    async fn became_main(&mut self, origin: FlvOrigin, now: Instant) {
        self.last_tag = now;
        self.last_au = None; // inter-arrival is per FLV connection
        self.admission.flv_opened();
        self.send(KvmEvent::FlvOpened {
            generation: self.generation,
            origin,
        })
        .await;
    }

    fn open_failed(
        &mut self,
        e: KvmError,
        origin: FlvOrigin,
        seq: u64,
        now: Instant,
    ) -> Option<Outcome> {
        // A `ReconnectFlv` candidate, with the old FLV still flowing.
        let candidate = origin == FlvOrigin::Commanded && self.main.is_some();
        match e.class() {
            // §6.9 excludes only side FLVs from the auth class (m1, PC8 fix
            // round 1): a main-path refusal goes to the session's gate,
            // which re-logs in once. A flowing main needs no token, so only
            // a lost one waits for the next (a candidate must not leave
            // `waiting_token` set, or a later loss of the main is stranded).
            FailClass::Auth => {
                if candidate {
                    self.metrics.upstream_reconnects.inc("commanded_failed");
                } else {
                    self.waiting_token = true;
                }
                Some(Outcome::Refused { seq })
            }
            // Nor from the certificate class: fatal at once (§6.9).
            FailClass::Cert => {
                self.close();
                Some(Outcome::Fatal(Cause::KvmCertMismatch))
            }
            FailClass::Transient if candidate => {
                // The old FLV still flows; the IDR core asks again later.
                self.metrics.upstream_reconnects.inc("commanded_failed");
                None
            }
            FailClass::Transient => {
                self.metrics.upstream_reconnects.inc(e.kind());
                self.retry_at = Some(now + self.backoff.next_delay());
                None
            }
        }
    }

    async fn main_chunk(
        &mut self,
        c: Result<Option<Bytes>, KvmError>,
        now: Instant,
    ) -> Option<Outcome> {
        let bytes = match c {
            Ok(Some(b)) => b,
            Ok(None) => {
                self.lost("eof", now);
                return None;
            }
            Err(e) => {
                self.lost(e.kind(), now);
                return None;
            }
        };
        self.metrics
            .flv_bytes
            .add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        let s = self.main.as_mut()?;
        let mut tags = std::mem::take(&mut self.tags);
        tags.clear();
        let err = drain(&mut s.demux, &bytes, &mut tags);
        let outcome = self.admit_all(&mut tags, err, now).await;
        self.tags = tags;
        outcome
    }

    async fn pending_chunk(
        &mut self,
        c: Result<Option<Bytes>, KvmError>,
        now: Instant,
    ) -> Option<Outcome> {
        let Ok(Some(bytes)) = c else {
            self.pending = None;
            self.metrics.upstream_reconnects.inc("commanded_failed");
            return None;
        };
        // A candidate's bytes are FLV bytes too, the swap chunk's included.
        self.metrics
            .flv_bytes
            .add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        let p = self.pending.as_mut()?;
        let mut tags = std::mem::take(&mut self.tags);
        tags.clear();
        let err = drain(&mut p.demux, &bytes, &mut tags);
        if tags.is_empty() {
            // No first tag: a header-only chunk waits; an error means the
            // candidate failed and the old FLV keeps flowing (§6.5). It is
            // still the KVM's framing violation (§6.9): counted, and
            // toward the 3-in-60 s `stream_corrupt` rule.
            let Some(e) = err else {
                self.tags = tags;
                return None;
            };
            self.tags = tags;
            self.pending = None;
            self.metrics.upstream_reconnects.inc("commanded_failed");
            let e = AdmissionError::from(e);
            self.metrics.parse_errors.inc(e.kind());
            if matches!(self.violations.record(now), ViolationVerdict::Fatal) {
                self.close();
                return Some(Outcome::Fatal(Cause::StreamCorrupt));
            }
            return None;
        }
        // Its first tag: the old FLV closes now (make-before-break, §6.5).
        self.main = self.pending.take();
        self.became_main(FlvOrigin::Commanded, now).await;
        let outcome = self.admit_all(&mut tags, err, now).await;
        self.tags = tags;
        outcome
    }

    /// Admit a chunk's `tags` in order, leaving the buffer empty (an early
    /// return drops the rest, which belong to a dead stream).
    async fn admit_all(
        &mut self,
        tags: &mut Vec<FlvTag>,
        err: Option<FlvError>,
        now: Instant,
    ) -> Option<Outcome> {
        for tag in tags.drain(..) {
            // A tag that lost the main FLV (end of sequence, a framing
            // refusal) ends this chunk: the rest belongs to a dead stream.
            self.main.as_ref()?;
            if let Some(o) = self.admit(tag, now).await {
                return Some(o);
            }
        }
        match err {
            Some(e) if self.main.is_some() => self.refusal(AdmissionError::from(e), now),
            _ => None,
        }
    }

    async fn admit(&mut self, tag: FlvTag, now: Instant) -> Option<Outcome> {
        self.metrics.flv_tags.inc();
        self.last_tag = now;
        self.deadline.tag();
        if let Some(s) = self.main.as_mut()
            && !s.got_tag
        {
            s.got_tag = true;
            self.proven = Some(s.seq);
            self.backoff.reset();
        }
        match self.admission.admit(tag, now) {
            Ok(a) => {
                if let Some(p) = a.params {
                    let r = p.rewrites;
                    for (on, field) in [
                        (r.level, "level"),
                        (r.vui, "vui"),
                        (r.restriction, "restriction"),
                    ] {
                        if on {
                            self.metrics.sps_rewrites.inc(field);
                        }
                    }
                    self.metrics.sps_changes.inc(class_label(p.class));
                    self.send(KvmEvent::SpsChanged {
                        generation: self.generation,
                        class: p.class,
                        params: p.params,
                    })
                    .await;
                }
                if let Some(au) = a.au {
                    self.forward(au, now);
                }
                if a.end_of_sequence {
                    self.lost("end_of_sequence", now);
                }
                None
            }
            Err(e) => self.refusal(e, now),
        }
    }

    fn refusal(&mut self, e: AdmissionError, now: Instant) -> Option<Outcome> {
        match e {
            AdmissionError::Incompatible(_) => {
                tracing::warn!(kind = e.kind(), "kvm stream is incompatible");
                self.close();
                Some(Outcome::Fatal(Cause::StreamIncompatible))
            }
            AdmissionError::Framing(_) => {
                self.metrics.parse_errors.inc(e.kind());
                match self.violations.record(now) {
                    ViolationVerdict::Fatal => {
                        self.close();
                        Some(Outcome::Fatal(Cause::StreamCorrupt))
                    }
                    ViolationVerdict::Transient => {
                        self.lost("framing", now);
                        None
                    }
                }
            }
        }
    }

    fn lost(&mut self, reason: &'static str, now: Instant) {
        self.stopped_streaming();
        self.main = None;
        self.metrics.upstream_reconnects.inc(reason);
        self.next_origin = FlvOrigin::Transient;
        self.deadline.flv_lost(now);
        self.retry_at = Some(now + self.backoff.next_delay());
    }

    /// No main FLV: no inter-arrival across the gap, and fps reads 0.
    fn stopped_streaming(&mut self) {
        self.last_au = None;
        self.fps.reset();
        self.metrics.kvm_fps.set(0);
    }

    fn forward(&mut self, au: AccessUnit, now: Instant) {
        self.metrics.frames.inc(if au.idr { "idr" } else { "p" });
        if au.burst {
            self.metrics.bursts.inc();
        }
        // §10.4: frame bytes, inter-arrival on this connection, fps.
        let bytes = au.vcl.iter().fold(0u64, |a, n| {
            a.saturating_add(u64::try_from(n.bytes.len()).unwrap_or(u64::MAX))
        });
        self.metrics.frame_bytes.observe_bytes(bytes);
        if let Some(prev) = self.last_au.replace(now) {
            self.metrics
                .inter_arrival
                .observe(now.saturating_duration_since(prev));
        }
        if let Some(fps) = self.fps.au(now) {
            self.metrics.kvm_fps.set(i64::from(fps));
        }
        let ev = KvmEvent::Au {
            generation: self.generation,
            au: KvmAu {
                au,
                after_drop: self.dropped,
                received: now,
            },
        };
        match self.to_pump.try_send(ev) {
            Ok(()) => self.dropped = false,
            Err(TrySendError::Full(_)) => {
                self.dropped = true;
                self.metrics.frames_dropped.inc("channel_full");
            }
            Err(TrySendError::Closed(_)) => {}
        }
    }

    /// Control messages are never dropped (§4.3): the FLV pauses instead.
    /// `&mut self`, not `&self`: `Video` holds a `BoxFuture` (`Send` but not
    /// `Sync`), and a `&Video` held across this await would make the
    /// session's future `!Send` — `tokio::spawn(run_actor(..))` refuses it.
    async fn send(&mut self, ev: KvmEvent) {
        let _ = self.to_pump.send(ev).await;
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
    use crate::config::{BackoffConfig, Scheme, Secret};
    use crate::kvm::login::login;
    use crate::kvm::side::request_idr;
    use crate::kvm::upstream::Jitter;
    use kvm_proto::video::ParamClass;
    use kvm_sim::{Fault, KvmSim, Pacing, SimConfig, SimEvent, Source};

    const CT: Duration = Duration::from_secs(1);

    struct Rig {
        sim: KvmSim,
        ep: Arc<KvmEndpoint>,
        video: Video,
        rx: mpsc::Receiver<KvmEvent>,
        token: (u64, Token),
        metrics: Arc<Metrics>,
    }

    async fn rig(
        cap: usize,
        sim_cfg: impl FnOnce(&mut SimConfig),
        set: impl FnOnce(&mut FlvSettings),
    ) -> Rig {
        let mut cfg = SimConfig::es3(Source::fixture("360p30_es3like_poc0.h264").unwrap());
        sim_cfg(&mut cfg);
        let sim = KvmSim::start(cfg).await.unwrap();
        let p = sim.ports();
        let ep = Arc::new(KvmEndpoint::new(
            Scheme::Https,
            sim.host(),
            (p.web, p.video, p.control),
            sim.spki_sha256(),
        ));
        let token = login(&ep, &Secret::new(sim.password()), CT, CT * 2)
            .await
            .unwrap();
        let (tx, rx) = mpsc::channel(cap);
        let metrics = Arc::new(Metrics::default());
        let mut settings = FlvSettings {
            connect_timeout: CT,
            idle_timeout: Duration::from_secs(2),
            deadline: Duration::from_secs(5),
            admission: AdmissionConfig::default(),
        };
        set(&mut settings);
        let backoff = Backoff::new(
            BackoffConfig {
                initial: Duration::from_millis(50),
                factor: 2,
                max: Duration::from_millis(400),
                jitter_percent: 0,
            },
            Jitter::new(1),
        );
        let video = Video::new(1, ep.clone(), tx, metrics.clone(), settings, backoff);
        Rig {
            sim,
            ep,
            video,
            rx,
            token: (1, token),
            metrics,
        }
    }

    impl Rig {
        /// Run the state machine for up to `d`, collecting what reaches the
        /// pump; an outcome ends it early. `read` false leaves the pump's
        /// channel alone (it fills).
        async fn run(&mut self, d: Duration, read: bool) -> (Vec<KvmEvent>, Option<Outcome>) {
            let until = tokio::time::Instant::now() + d;
            let mut tick = tokio::time::interval(Duration::from_millis(20));
            let mut out = Vec::new();
            loop {
                tokio::select! {
                    r = self.video.ready() => {
                        // Bounded from outside: an AU path that waited on the
                        // full channel (the "never waited for" property of
                        // `a_full_channel_drops_aus_and_marks_the_next`) must
                        // fail the test, not hang it — `sleep_until` below
                        // cannot fire while this arm's body is blocked.
                        let step = tokio::time::timeout(Duration::from_secs(5), self.video.on_ready(r, Instant::now())).await;
                        let Ok(step) = step else {
                            panic!("on_ready blocked for 5 s: an AU send waited on the pump's channel (§4.3)");
                        };
                        if let Some(o) = step {
                            while let Ok(ev) = self.rx.try_recv() { out.push(ev); }
                            return (out, Some(o));
                        }
                    }
                    _ = tick.tick() => {
                        if let Some(o) = self.video.tick(Instant::now(), Some(&self.token)) {
                            return (out, Some(o));
                        }
                    }
                    ev = self.rx.recv(), if read => if let Some(ev) = ev { out.push(ev) },
                    () = tokio::time::sleep_until(until) => {
                        if read {
                            while let Ok(ev) = self.rx.try_recv() { out.push(ev); }
                        }
                        return (out, None);
                    }
                }
            }
        }

        /// Run until `done` holds over what reached the pump, or an outcome,
        /// for at most `t`: a positive outcome is waited for, not timed
        /// (§11.1 — a niced, loaded test host must not flake it).
        async fn run_until(
            &mut self,
            t: Duration,
            done: impl Fn(&[KvmEvent]) -> bool,
        ) -> (Vec<KvmEvent>, Option<Outcome>) {
            let t0 = Instant::now();
            let mut out = Vec::new();
            while t0.elapsed() < t {
                let (evs, o) = self.run(Duration::from_millis(50), true).await;
                out.extend(evs);
                if o.is_some() || done(&out) {
                    return (out, o);
                }
            }
            (out, None)
        }

        async fn relogin(&mut self) {
            let t = login(&self.ep, &Secret::new(self.sim.password()), CT, CT * 2)
                .await
                .unwrap();
            self.token = (self.token.0 + 1, t);
            self.video.token_ready(&self.token);
        }
    }

    fn kinds(evs: &[KvmEvent]) -> Vec<String> {
        evs.iter()
            .map(|e| match e {
                KvmEvent::FlvOpened { origin, .. } => format!("open:{}", origin.label()),
                KvmEvent::SpsChanged { class, .. } => format!("sps:{class:?}"),
                KvmEvent::Au { au, .. } => (if au.au.idr { "idr" } else { "p" }).to_owned(),
                KvmEvent::UpstreamFatal { cause, .. } => format!("fatal:{}", cause.label()),
            })
            .collect()
    }

    /// The events after the first `open:transient`, once two more arrived.
    fn reopened(evs: &[KvmEvent]) -> bool {
        let k = kinds(evs);
        k.iter()
            .position(|s| s == "open:transient")
            .is_some_and(|at| k.len() >= at + 3)
    }

    /// Every FLV kvm-sim has served, in open order.
    fn flv_opens(sim: &KvmSim) -> Vec<u64> {
        sim.events()
            .iter()
            .filter_map(|e| {
                if let SimEvent::FlvOpen { conn } = e {
                    Some(*conn)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Also §10.4: every admitted AU's bytes, the gaps between them, and fps.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_first_open_streams_initial_params_then_an_idr() {
        let mut r = rig(64, |_| {}, |_| {}).await;
        r.video.want(Instant::now(), Some(&r.token));
        let (evs, out) = r.run_until(Duration::from_secs(5), |e| e.len() > 12).await;
        assert_eq!(out, None);
        let k = kinds(&evs);
        assert_eq!(k[..3], ["open:first", "sps:Initial", "idr"], "{k:?}");
        assert!(k.len() > 10, "frames keep coming: {k:?}");
        assert_eq!(r.sim.stats().flv_open, 1);
        let aus = u64::try_from(k.iter().filter(|s| *s == "idr" || *s == "p").count()).unwrap();
        assert!(r.metrics.frame_bytes.count() >= aus, "frame bytes per AU");
        assert!(
            r.metrics.inter_arrival.count() >= aus - 1,
            "inter-arrival per AU after the first"
        );
    }

    /// §10.4 fps: 30 fps in, 30 out, once a second.
    #[test]
    fn the_fps_meter_publishes_once_a_second() {
        let t0 = Instant::now();
        let mut m = FpsMeter::default();
        let got: Vec<u32> = (0..64u64)
            .filter_map(|k| m.au(t0 + Duration::from_millis(k * 33)))
            .collect();
        assert_eq!(got, [30, 30]);
    }

    /// §6.9 transient: an FLV drop reconnects with backoff and the new
    /// connection's first SPS is `Initial` again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dropped_flv_reconnects_as_transient() {
        let mut r = rig(64, |_| {}, |_| {}).await;
        r.video.want(Instant::now(), Some(&r.token));
        r.run(Duration::from_millis(400), true).await;
        r.sim.inject(Fault::Close);
        let (evs, out) = r.run_until(Duration::from_secs(5), reopened).await;
        assert_eq!(out, None);
        let k = kinds(&evs);
        let at = k.iter().position(|s| s == "open:transient").unwrap();
        assert_eq!(k[at + 1..at + 3], ["sps:Initial", "idr"], "{k:?}");
        assert!(r.metrics.upstream_reconnects.total() >= 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_b_slice_is_stream_incompatible() {
        let mut r = rig(64, |_| {}, |_| {}).await;
        r.video.want(Instant::now(), Some(&r.token));
        r.run(Duration::from_millis(400), true).await;
        r.sim.inject(Fault::BSlice);
        let (_, out) = r.run(Duration::from_secs(2), true).await;
        assert_eq!(out, Some(Outcome::Fatal(Cause::StreamIncompatible)));
    }

    /// §6.9 framing: transient, but three within 60 s is `stream_corrupt`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn three_framing_violations_in_a_minute_are_stream_corrupt() {
        let mut r = rig(64, |_| {}, |_| {}).await;
        r.video.want(Instant::now(), Some(&r.token));
        r.run(Duration::from_millis(400), true).await;
        for _ in 0..2 {
            r.sim.inject(Fault::BadPrevTagSize);
            let (evs, out) = r.run_until(Duration::from_secs(5), reopened).await;
            assert_eq!(out, None);
            assert!(kinds(&evs).contains(&"open:transient".to_owned()));
        }
        r.sim.inject(Fault::BadPrevTagSize);
        let (_, out) = r.run(Duration::from_secs(2), true).await;
        assert_eq!(out, Some(Outcome::Fatal(Cause::StreamCorrupt)));
        assert_eq!(r.metrics.parse_errors.get("bad_prev_tag_size"), 3);
    }

    /// §6.9 auth: a refused reopen reports the token it used; with a new
    /// token the stream resumes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_expired_token_is_refused_with_its_sequence_number() {
        let mut r = rig(64, |_| {}, |_| {}).await;
        r.video.want(Instant::now(), Some(&r.token));
        r.run(Duration::from_millis(400), true).await;
        r.sim.expire_tokens();
        r.sim.inject(Fault::Close);
        let (_, out) = r.run(Duration::from_secs(2), true).await;
        assert_eq!(out, Some(Outcome::Refused { seq: 1 }));
        r.relogin().await;
        let (evs, out) = r.run_until(Duration::from_secs(5), |e| e.len() >= 2).await;
        assert_eq!(out, None);
        assert!(kinds(&evs).starts_with(&["open:transient".to_owned(), "sps:Initial".to_owned()]));
    }

    /// I1 (PC9 fix round 1): an FLV that reaches its first tag proves the
    /// token it was opened with — once per connection — so the session's
    /// gate counts that token's re-login as successful (§6.9, rev 6.2). A
    /// refused open proves nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_first_tag_proves_the_token_the_flv_was_opened_with() {
        let mut r = rig(64, |_| {}, |_| {}).await;
        assert_eq!(r.video.take_proven(), None);
        r.video.want(Instant::now(), Some(&r.token));
        r.run_until(Duration::from_secs(5), |e| {
            kinds(e).contains(&"idr".to_owned())
        })
        .await;
        assert_eq!(r.video.take_proven(), Some(1));
        r.run(Duration::from_millis(200), true).await;
        assert_eq!(r.video.take_proven(), None, "later tags prove nothing");
        r.sim.expire_tokens();
        r.sim.inject(Fault::Close);
        let (_, out) = r.run(Duration::from_secs(2), true).await;
        assert_eq!(out, Some(Outcome::Refused { seq: 1 }));
        assert_eq!(r.video.take_proven(), None, "a refused open proves nothing");
        r.relogin().await;
        r.run_until(Duration::from_secs(5), |e| {
            kinds(e).contains(&"open:transient".to_owned())
        })
        .await;
        r.run(Duration::from_millis(200), true).await;
        assert_eq!(r.video.take_proven(), Some(2));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_silent_flv_reconnects_after_the_idle_timeout() {
        let idle = Duration::from_millis(400);
        let mut r = rig(64, |_| {}, |s| s.idle_timeout = idle).await;
        r.video.want(Instant::now(), Some(&r.token));
        r.run(Duration::from_millis(400), true).await;
        r.sim.inject(Fault::Silence);
        let t0 = Instant::now();
        let mut reopened = None;
        while t0.elapsed() < idle * 5 && reopened.is_none() {
            let (evs, _) = r.run(Duration::from_millis(50), true).await;
            if kinds(&evs).contains(&"open:transient".to_owned()) {
                reopened = Some(t0.elapsed());
            }
        }
        let after = reopened.unwrap();
        assert!(after >= idle / 2, "{after:?}");
        assert_eq!(r.metrics.upstream_reconnects.get("idle"), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_tag_by_the_deadline_is_kvm_unreachable() {
        let deadline = Duration::from_millis(600);
        let mut r = rig(64, |_| {}, |s| s.deadline = deadline).await;
        r.sim.set_policy(|p| p.flv_status = Some(503));
        let t0 = Instant::now();
        r.video.want(t0, Some(&r.token));
        let (_, out) = r.run(deadline * 5, true).await;
        assert_eq!(out, Some(Outcome::Fatal(Cause::KvmUnreachable)));
        assert!(t0.elapsed() >= deadline / 2, "{:?}", t0.elapsed());
    }

    /// §4.3: AUs that do not fit are dropped, never waited for, and the next
    /// AU that fits carries `after_drop` (DC12).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_full_channel_drops_aus_and_marks_the_next() {
        let mut r = rig(8, |c| c.pacing = Pacing::Manual, |_| {}).await;
        r.video.want(Instant::now(), Some(&r.token));
        // Manual pacing writes only to FLVs already subscribed: let the
        // FLV open (sequence header) before encoding its first frame.
        let (mut evs, _) = r.run(Duration::from_millis(300), true).await;
        r.sim.advance(1);
        evs.extend(r.run(Duration::from_millis(400), true).await.0);
        assert_eq!(kinds(&evs)[..3], ["open:first", "sps:Initial", "idr"]);
        r.sim.advance(20);
        r.run(Duration::from_millis(600), false).await;
        assert!(r.metrics.frames_dropped.get("channel_full") >= 12);
        let mut queued = Vec::new();
        while let Ok(ev) = r.rx.try_recv() {
            queued.push(ev);
        }
        assert_eq!(queued.len(), 8);
        assert!(
            queued
                .iter()
                .all(|e| matches!(e, KvmEvent::Au { au, .. } if !au.after_drop))
        );
        r.sim.advance(1);
        let (evs, _) = r.run(Duration::from_millis(400), true).await;
        assert!(
            matches!(&evs[0], KvmEvent::Au { au, .. } if au.after_drop),
            "{:?}",
            kinds(&evs)
        );
    }

    /// §6.5 `reconnect`: the new FLV opens while the old one keeps flowing,
    /// and the old one closes only once the new one delivered its first tag.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconnect_is_make_before_break() {
        let mut r = rig(64, |_| {}, |_| {}).await;
        r.video.want(Instant::now(), Some(&r.token));
        r.run(Duration::from_millis(400), true).await;
        r.video.reconnect(Instant::now(), Some(&r.token));
        let commanded = |e: &[KvmEvent]| {
            let k = kinds(e);
            k.iter()
                .position(|s| s == "open:commanded")
                .is_some_and(|at| k.len() >= at + 3)
        };
        let (evs, out) = r.run_until(Duration::from_secs(5), commanded).await;
        assert_eq!(out, None);
        let k = kinds(&evs);
        let at = k.iter().position(|s| s == "open:commanded").unwrap();
        assert_eq!(k[at + 1..at + 3], ["sps:Initial", "idr"], "{k:?}");
        // The old connection's close reaches kvm-sim's log asynchronously.
        let log = r
            .sim
            .wait_for(Duration::from_secs(5), |l| {
                l.iter().any(|e| matches!(e, SimEvent::FlvClose { .. }))
            })
            .await
            .unwrap();
        let opens: Vec<u64> = log
            .iter()
            .filter_map(|e| {
                if let SimEvent::FlvOpen { conn } = e {
                    Some(*conn)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(opens.len(), 2);
        let pos = |want: &SimEvent| log.iter().position(|e| e == want).unwrap();
        assert!(
            pos(&SimEvent::FlvOpen { conn: opens[1] })
                < pos(&SimEvent::FlvClose { conn: opens[0] })
        );
        assert_eq!(r.sim.stats().flv_open, 1);
        assert_eq!(r.metrics.idr_requests.get("reconnect"), 1);
    }

    /// A `ReconnectFlv` candidate that delivers no first tag is abandoned
    /// `connect_timeout` after it opened — counted, the main FLV untouched —
    /// so a hostile or wedged KVM cannot hold it, and with it every later
    /// `ReconnectFlv` (the side request's fallback, §6.5), for the rest of
    /// the session. While it is in flight a second `reconnect` opens
    /// nothing (every open forces an IDR on every viewer, census Leg A);
    /// once it is gone the next one opens again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reconnect_candidate_with_no_tag_is_abandoned_and_unblocks_the_next() {
        let mut r = rig(
            64,
            |c| c.pacing = Pacing::Manual,
            |s| s.idle_timeout = Duration::from_secs(30),
        )
        .await;
        r.video.want(Instant::now(), Some(&r.token));
        let (mut evs, _) = r.run(Duration::from_millis(300), true).await;
        r.sim.advance(1);
        evs.extend(
            r.run_until(Duration::from_secs(5), |e| {
                kinds(e).contains(&"idr".to_owned())
            })
            .await
            .0,
        );
        assert_eq!(kinds(&evs)[..3], ["open:first", "sps:Initial", "idr"]);
        // The candidate gets an FLV header and nothing after it: no
        // sequence header, and Manual pacing encodes no frame.
        r.sim.set_policy(|p| p.skip_sequence_header = true);
        let t0 = Instant::now();
        r.video.reconnect(t0, Some(&r.token));
        while flv_opens(&r.sim).len() < 2 {
            assert!(t0.elapsed() < CT * 5, "the candidate never opened");
            r.run(Duration::from_millis(20), true).await;
        }
        r.video.reconnect(Instant::now(), Some(&r.token));
        let mut evs = Vec::new();
        while r.metrics.upstream_reconnects.get("commanded_failed") == 0 {
            assert!(
                t0.elapsed() < CT * 5,
                "the tagless candidate was never abandoned"
            );
            evs.extend(r.run(Duration::from_millis(20), true).await.0);
        }
        let took = t0.elapsed();
        assert!(took >= CT / 2, "abandoned too early: {took:?}");
        let opens = flv_opens(&r.sim);
        assert_eq!(
            opens.len(),
            2,
            "a reconnect while one was in flight opened another FLV"
        );
        assert!(
            !kinds(&evs).iter().any(|k| k.starts_with("open:")),
            "{:?}",
            kinds(&evs)
        );
        r.sim
            .wait_for(Duration::from_secs(5), |l| {
                l.contains(&SimEvent::FlvClose { conn: opens[1] })
            })
            .await
            .expect("the abandoned candidate was left open");
        assert!(
            !r.sim
                .events()
                .contains(&SimEvent::FlvClose { conn: opens[0] }),
            "the main FLV closed"
        );
        r.sim.set_policy(|p| p.skip_sequence_header = false);
        r.video.reconnect(Instant::now(), Some(&r.token));
        let (evs, out) = r
            .run_until(Duration::from_secs(5), |e| {
                kinds(e).contains(&"open:commanded".to_owned())
            })
            .await;
        assert_eq!(out, None);
        assert!(
            kinds(&evs).contains(&"open:commanded".to_owned()),
            "{:?}",
            kinds(&evs)
        );
        assert_eq!(flv_opens(&r.sim).len(), 3);
        assert_eq!(r.metrics.idr_requests.get("reconnect"), 2);
    }

    /// The main FLV lost while a `ReconnectFlv` candidate is in flight: the
    /// transient reopen waits until the candidate swaps in or is abandoned,
    /// rather than opening a second new FLV beside it (each forces an IDR
    /// on every viewer, census Leg A).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_main_lost_during_a_reconnect_waits_for_the_candidate() {
        let idle = Duration::from_millis(800);
        let mut r = rig(
            64,
            |c| c.pacing = Pacing::Manual,
            |s| {
                s.idle_timeout = idle;
                s.connect_timeout = Duration::from_secs(2);
            },
        )
        .await;
        r.video.want(Instant::now(), Some(&r.token));
        r.run(Duration::from_millis(300), true).await;
        r.sim.advance(1);
        r.run_until(Duration::from_secs(5), |e| {
            kinds(e).contains(&"idr".to_owned())
        })
        .await;
        r.sim.set_policy(|p| p.skip_sequence_header = true);
        let t0 = Instant::now();
        r.video.reconnect(t0, Some(&r.token));
        // The main goes idle at ~0.8 s; the tagless candidate is abandoned
        // at ~2 s; only then may the transient reopen run.
        let (evs, out) = r
            .run_until(Duration::from_secs(10), |e| {
                kinds(e).iter().any(|k| k.starts_with("open:"))
            })
            .await;
        assert_eq!(out, None);
        assert_eq!(
            kinds(&evs)
                .iter()
                .find(|k| k.starts_with("open:"))
                .map(String::as_str),
            Some("open:transient")
        );
        assert_eq!(r.metrics.upstream_reconnects.get("idle"), 1);
        assert_eq!(
            r.metrics.upstream_reconnects.get("commanded_failed"),
            1,
            "a transient FLV opened beside the candidate after {:?}",
            t0.elapsed()
        );
        assert_eq!(flv_opens(&r.sim).len(), 3);
    }

    /// I1 (PC8 fix round 1): a candidate whose first chunk is a framing
    /// error, with no tag yet, has not delivered its first tag (§6.5): it
    /// is dropped and the healthy main keeps flowing — no `FlvOpened`, no
    /// third FLV.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_candidate_failing_before_its_first_tag_keeps_the_main() {
        let mut r = rig(64, |_| {}, |s| s.idle_timeout = Duration::from_secs(30)).await;
        r.video.want(Instant::now(), Some(&r.token));
        r.run_until(Duration::from_secs(5), |e| {
            kinds(e).contains(&"idr".to_owned())
        })
        .await;
        let main = flv_opens(&r.sim)[0];
        r.sim.set_policy(|p| p.skip_sequence_header = true);
        r.video.reconnect(Instant::now(), Some(&r.token));
        let t0 = Instant::now();
        let mut evs = Vec::new();
        while r.metrics.parse_errors.get("nal_before_sequence_header") == 0 {
            assert!(
                t0.elapsed() < Duration::from_secs(5),
                "no framing error: {:?}",
                kinds(&evs)
            );
            evs.extend(r.run(Duration::from_millis(20), true).await.0);
        }
        r.sim.set_policy(|p| p.skip_sequence_header = false);
        evs.extend(r.run(Duration::from_millis(600), true).await.0);
        assert!(
            !r.sim.events().contains(&SimEvent::FlvClose { conn: main }),
            "the healthy main closed"
        );
        assert!(
            !kinds(&evs).iter().any(|k| k.starts_with("open:")),
            "{:?}",
            kinds(&evs)
        );
        assert_eq!(flv_opens(&r.sim).len(), 2);
        assert_eq!(r.metrics.upstream_reconnects.get("commanded_failed"), 1);
    }

    /// I1: the candidate's framing error is still the KVM's violation
    /// (§6.9's table does not distinguish connections), so two more on the
    /// main FLV within 60 s are `stream_corrupt`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_candidate_framing_error_counts_toward_stream_corrupt() {
        let mut r = rig(64, |_| {}, |s| s.idle_timeout = Duration::from_secs(30)).await;
        r.video.want(Instant::now(), Some(&r.token));
        r.run_until(Duration::from_secs(5), |e| {
            kinds(e).contains(&"idr".to_owned())
        })
        .await;
        r.sim.set_policy(|p| p.skip_sequence_header = true);
        r.video.reconnect(Instant::now(), Some(&r.token));
        let t0 = Instant::now();
        while r.metrics.parse_errors.get("nal_before_sequence_header") == 0 {
            assert!(
                t0.elapsed() < Duration::from_secs(5),
                "no framing error on the candidate"
            );
            let (_, out) = r.run(Duration::from_millis(20), true).await;
            assert_eq!(out, None);
        }
        r.sim.set_policy(|p| p.skip_sequence_header = false);
        r.sim.inject(Fault::BadPrevTagSize);
        let (evs, out) = r.run_until(Duration::from_secs(5), reopened).await;
        assert_eq!(out, None, "the second violation is transient");
        assert!(
            kinds(&evs).contains(&"open:transient".to_owned()),
            "{:?}",
            kinds(&evs)
        );
        r.sim.inject(Fault::BadPrevTagSize);
        let (_, out) = r.run(Duration::from_secs(2), true).await;
        assert_eq!(
            out,
            Some(Outcome::Fatal(Cause::StreamCorrupt)),
            "the candidate's violation was not counted"
        );
        assert_eq!(r.metrics.parse_errors.total(), 3);
    }

    /// m1 (PC8 fix round 1): §6.9 excludes only side FLVs from the auth
    /// class. A `ReconnectFlv` candidate refused for its token is
    /// `Refused` with that token's sequence number — the session's gate
    /// re-logs in — while the old FLV keeps flowing; and it does not leave
    /// the flowing main waiting for a token, so a later reopen is not
    /// stranded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_candidate_refused_for_its_token_goes_to_the_auth_gate() {
        let mut r = rig(64, |_| {}, |_| {}).await;
        r.video.want(Instant::now(), Some(&r.token));
        r.run(Duration::from_millis(400), true).await;
        r.sim.expire_tokens();
        r.video.reconnect(Instant::now(), Some(&r.token));
        let (evs, out) = r.run(Duration::from_secs(2), true).await;
        assert_eq!(out, Some(Outcome::Refused { seq: 1 }));
        assert!(
            !kinds(&evs).iter().any(|k| k.starts_with("open:")),
            "{:?}",
            kinds(&evs)
        );
        assert_eq!(r.metrics.upstream_reconnects.get("commanded_failed"), 1);
        let (evs, _) = r.run(Duration::from_millis(300), true).await;
        assert!(
            kinds(&evs).iter().any(|k| k == "p" || k == "idr"),
            "the main FLV stopped"
        );
        r.relogin().await;
        r.sim.inject(Fault::Close);
        let (evs, out) = r.run_until(Duration::from_secs(5), reopened).await;
        assert_eq!(out, None);
        assert!(
            kinds(&evs).contains(&"open:transient".to_owned()),
            "stranded: {:?}",
            kinds(&evs)
        );
    }

    /// m1: nor is a candidate excluded from §6.9's certificate class — an
    /// SPKI mismatch on it is fatal at once. The classification alone, with
    /// the failure fed in; over real TLS, after kvm-sim's mid-session
    /// `rotate_certificate`, it is L2's
    /// `faults::a_reconnect_candidate_meeting_a_changed_certificate_is_fatal`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_candidate_with_a_cert_mismatch_is_fatal() {
        let mut r = rig(64, |_| {}, |_| {}).await;
        r.video.want(Instant::now(), Some(&r.token));
        r.run_until(Duration::from_secs(5), |e| {
            kinds(e).contains(&"idr".to_owned())
        })
        .await;
        let out = r.video.open_failed(
            KvmError::CertMismatch,
            FlvOrigin::Commanded,
            1,
            Instant::now(),
        );
        assert_eq!(out, Some(Outcome::Fatal(Cause::KvmCertMismatch)));
    }

    /// m2 (PC8 fix round 1): with no main FLV there is nothing to make
    /// before breaking, so `reconnect` opens nothing — the reopen already
    /// scheduled, in flight or waiting for a token serves it. Here it is
    /// waiting for a new token, and the refused one must not be used again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reconnect_with_no_main_leaves_the_scheduled_reopen_to_serve() {
        let mut r = rig(64, |_| {}, |_| {}).await;
        r.video.want(Instant::now(), Some(&r.token));
        r.run(Duration::from_millis(400), true).await;
        r.sim.expire_tokens();
        r.sim.inject(Fault::Close);
        let (_, out) = r.run(Duration::from_secs(2), true).await;
        assert_eq!(out, Some(Outcome::Refused { seq: 1 }));
        r.video.reconnect(Instant::now(), Some(&r.token));
        let (_, out) = r.run(Duration::from_millis(300), true).await;
        assert_eq!(out, None, "the refused token was used again");
        let refused = r
            .sim
            .events()
            .iter()
            .filter(|e| matches!(e, SimEvent::FlvRefused { .. }))
            .count();
        assert_eq!(refused, 1);
        assert_eq!(r.metrics.idr_requests.get("reconnect"), 0);
        r.relogin().await;
        let (evs, out) = r.run_until(Duration::from_secs(5), |e| !e.is_empty()).await;
        assert_eq!(out, None);
        assert_eq!(
            kinds(&evs).first().map(String::as_str),
            Some("open:transient")
        );
    }

    /// m3 (PC8 fix round 1): a candidate's bytes count in `flv_bytes` like
    /// the main FLV's — here the 13-byte FLV header (with `PreviousTagSize0`)
    /// of a candidate that never sends a tag, while the main (Manual
    /// pacing) sends nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_candidates_bytes_are_counted() {
        let mut r = rig(
            64,
            |c| c.pacing = Pacing::Manual,
            |s| s.idle_timeout = Duration::from_secs(30),
        )
        .await;
        r.video.want(Instant::now(), Some(&r.token));
        r.run(Duration::from_millis(300), true).await;
        let b0 = r.metrics.flv_bytes.get();
        assert!(b0 > 0);
        r.sim.set_policy(|p| p.skip_sequence_header = true);
        r.video.reconnect(Instant::now(), Some(&r.token));
        let t0 = Instant::now();
        while flv_opens(&r.sim).len() < 2 {
            assert!(
                t0.elapsed() < Duration::from_secs(5),
                "the candidate never opened"
            );
            r.run(Duration::from_millis(20), true).await;
        }
        r.run(Duration::from_millis(200), true).await;
        assert_eq!(r.metrics.flv_bytes.get() - b0, 13);
    }

    /// m4 (PC8 fix round 1): `ready()` takes a finished open out of its
    /// slot as it completes, so a poll after a `Ready::Opened` that was not
    /// consumed (a contract breach) never re-polls the completed future,
    /// which would panic.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ready_never_repolls_a_finished_open() {
        let mut r = rig(64, |_| {}, |_| {}).await;
        r.video.want(Instant::now(), Some(&r.token));
        let first = tokio::time::timeout(Duration::from_secs(5), r.video.ready()).await;
        drop(first.expect("the open never completed"));
        let again = tokio::time::timeout(Duration::from_millis(200), r.video.ready()).await;
        assert!(again.is_err(), "nothing is left to be ready");
    }

    /// m4: an open that finished before `close()` opens nothing after it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_open_finished_before_close_is_dropped_after_it() {
        let mut r = rig(64, |_| {}, |_| {}).await;
        r.video.want(Instant::now(), Some(&r.token));
        let ready = tokio::time::timeout(Duration::from_secs(5), r.video.ready())
            .await
            .unwrap();
        r.video.close();
        assert_eq!(r.video.on_ready(ready, Instant::now()).await, None);
        assert!(r.video.main.is_none() && r.video.pending.is_none());
        assert!(r.rx.try_recv().is_err(), "an FlvOpened after close");
    }

    /// §6.5 `side`: one extra FLV, closed after its first tag; the main FLV
    /// never closes and carries the forced IDR.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_side_request_opens_one_flv_and_forces_an_idr_into_the_main_one() {
        let mut r = rig(64, |_| {}, |_| {}).await;
        r.video.want(Instant::now(), Some(&r.token));
        r.run(Duration::from_millis(500), true).await;
        let main = r
            .sim
            .events()
            .iter()
            .find_map(|e| {
                if let SimEvent::FlvOpen { conn } = e {
                    Some(*conn)
                } else {
                    None
                }
            })
            .unwrap();
        request_idr(r.ep.clone(), r.token.1.clone(), CT, CT)
            .await
            .unwrap();
        let (_, out) = r.run(Duration::from_millis(500), true).await;
        assert_eq!(out, None);
        let log = r.sim.events();
        let side = log
            .iter()
            .filter_map(|e| {
                if let SimEvent::FlvOpen { conn } = e {
                    Some(*conn)
                } else {
                    None
                }
            })
            .nth(1)
            .unwrap();
        let side_open = log
            .iter()
            .position(|e| *e == SimEvent::FlvOpen { conn: side })
            .unwrap();
        assert!(log.contains(&SimEvent::FlvClose { conn: side }));
        assert!(!log.contains(&SimEvent::FlvClose { conn: main }));
        assert!(
            log[side_open..]
                .iter()
                .any(|e| matches!(e, SimEvent::FlvAu { conn, idr: true, .. } if *conn == main))
        );
        assert_eq!(
            flv_opens(&r.sim).len(),
            2,
            "exactly one side FLV per request"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_side_request_is_an_error_never_a_retry() {
        let mut r = rig(64, |_| {}, |_| {}).await;
        r.video.want(Instant::now(), Some(&r.token));
        r.run(Duration::from_millis(400), true).await;
        r.sim.set_policy(|p| p.refuse_concurrent_flv = 1);
        let e = request_idr(r.ep.clone(), r.token.1.clone(), CT, CT)
            .await
            .unwrap_err();
        assert_eq!(e, KvmError::Http(503));
        r.run(Duration::from_millis(300), true).await;
        let refused = r
            .sim
            .events()
            .iter()
            .filter(|e| matches!(e, SimEvent::FlvRefused { .. }))
            .count();
        assert_eq!(refused, 1);
        assert_eq!(r.sim.stats().logins_ok, 1);
    }

    /// §6.5/§6.9: side FLVs are excluded from the auth class. A side FLV
    /// refused for its token (403 `result:403`) is an error for the caller
    /// to count under `auth` — one attempt, no login, no logout — and the
    /// main FLV, which never sees it, keeps flowing with no `Refused`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_side_request_refused_for_its_token_is_counted_never_relogged_in() {
        let mut r = rig(64, |_| {}, |_| {}).await;
        r.video.want(Instant::now(), Some(&r.token));
        r.run(Duration::from_millis(400), true).await;
        r.sim.expire_tokens();
        let e = request_idr(r.ep.clone(), r.token.1.clone(), CT, CT)
            .await
            .unwrap_err();
        assert_eq!((e.clone(), e.kind()), (KvmError::Auth, "auth"));
        let (evs, out) = r.run(Duration::from_millis(400), true).await;
        assert_eq!(out, None, "a side refusal reached the main FLV's auth path");
        assert!(
            kinds(&evs).iter().any(|k| k == "p" || k == "idr"),
            "the main FLV stopped: {:?}",
            kinds(&evs)
        );
        let refused: Vec<SimEvent> = r
            .sim
            .events()
            .into_iter()
            .filter(|e| matches!(e, SimEvent::FlvRefused { .. }))
            .collect();
        assert_eq!(
            refused,
            [SimEvent::FlvRefused { status: 403 }],
            "one attempt, never retried"
        );
        let s = r.sim.stats();
        assert_eq!(
            (s.logins_ok, s.logins_failed, s.logouts),
            (1, 0, 0),
            "no re-login, never a logout"
        );
    }

    /// §6.5: a side FLV that delivers no tag is closed `idr_side_timeout`
    /// after the request — bounded, and the socket does not linger.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_side_flv_with_no_tag_is_abandoned_at_the_side_timeout() {
        let r = rig(64, |c| c.pacing = Pacing::Manual, |_| {}).await;
        // An FLV header and nothing after it: no sequence header, and
        // Manual pacing encodes no frame.
        r.sim.set_policy(|p| p.skip_sequence_header = true);
        let side_timeout = Duration::from_millis(400);
        let t0 = Instant::now();
        let res = tokio::time::timeout(
            side_timeout * 5,
            request_idr(r.ep.clone(), r.token.1.clone(), CT, side_timeout),
        )
        .await;
        let took = t0.elapsed();
        assert_eq!(
            res.expect("the side request outlived 5x idr_side_timeout"),
            Err(KvmError::Timeout("side flv"))
        );
        assert!(took >= side_timeout / 2, "{took:?}");
        assert_eq!(flv_opens(&r.sim).len(), 1, "the side FLV did open");
        r.sim
            .wait_for(Duration::from_secs(5), |l| {
                l.iter().any(|e| matches!(e, SimEvent::FlvClose { .. }))
            })
            .await
            .expect("the side FLV was left open");
    }

    /// Compile-time only: Task 3.8 `tokio::spawn`s the actor that owns a
    /// `Video` and awaits these across its `select!`, so they must be
    /// `Send` (see `Video::send`'s note on `&mut self`).
    #[allow(dead_code)]
    fn video_and_its_futures_are_send(v: &mut Video, r: Ready) {
        fn send<T: Send>(_: T) {}
        send(v.ready());
        send(v.on_ready(r, Instant::now()));
    }

    #[test]
    fn class_labels() {
        assert_eq!(class_label(ParamClass::Initial), "initial");
        assert_eq!(class_label(ParamClass::Resize), "resize");
        assert_eq!(class_label(ParamClass::Other), "other");
    }

    /// Plan E Task 1.4 (the per-chunk `Vec<FlvTag>`): `drain` demuxes into
    /// the caller's buffer and never replaces it — once it holds a chunk's
    /// tags, its allocation is reused for every later chunk — and allocates
    /// nothing beside the demuxer's own (a twin demuxer fed the same chunks
    /// counts those), so no temporary `Vec` hides behind the reused one.
    #[test]
    fn drain_reuses_the_tag_buffer() {
        use crate::alloc_stats::this_thread;
        use kvm_proto::flv::mux::{
            TAG_VIDEO, avc_nalu_body, avc_sequence_header_body, write_flv_header, write_tag,
        };
        // `drain` only demuxes: the ES3 fixture's admitted parameter sets
        // (the L1 rig's) make a well-formed sequence header.
        let p = crate::pump::rig::params(crate::pump::rig::ES3);
        let pps: Vec<&[u8]> = p.pps.iter().map(|b| b.as_ref()).collect();
        let mut head = Vec::new();
        write_flv_header(&mut head, false, true);
        write_tag(
            &mut head,
            TAG_VIDEO,
            0,
            &avc_sequence_header_body(&[&p.sps], &pps, 4).unwrap(),
        )
        .unwrap();
        let mut chunks = vec![head];
        for i in 0..64u32 {
            let mut body = Vec::new();
            avc_nalu_body(&mut body, i == 0, 16, &[&[0x65, 0x88, 0x84, 0x21][..]], 4).unwrap();
            let mut tag = Vec::new();
            write_tag(&mut tag, TAG_VIDEO, (i + 1) * 33, &body).unwrap();
            chunks.push(tag);
        }
        let (mut demux, mut twin) = (
            FlvDemuxer::new(FlvLimits::default()),
            FlvDemuxer::new(FlvLimits::default()),
        );
        let mut tags = Vec::with_capacity(8);
        let (ptr, cap) = (tags.as_ptr(), tags.capacity());
        let (mut drained, mut demuxed) = (0u64, 0u64);
        for c in &chunks {
            tags.clear();
            let t0 = this_thread();
            assert!(drain(&mut demux, c, &mut tags).is_none());
            let t1 = this_thread();
            twin.push(c);
            while twin.next_tag().unwrap().is_some() {}
            let t2 = this_thread();
            drained += t1 - t0;
            demuxed += t2 - t1;
            assert_eq!(
                (tags.as_ptr(), tags.capacity()),
                (ptr, cap),
                "drain replaced the buffer"
            );
        }
        assert_eq!(drained, demuxed, "drain allocated beside the demuxer's own");
    }
}
