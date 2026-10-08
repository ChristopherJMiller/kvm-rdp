//! The L2 client (§11.3): IronRDP's own connector with NLA over TLS, a
//! capture `DvcProcessor` for EGFX that ZGFX-unwraps and records every
//! server PDU and acknowledges per mode — no H.264 decoder is ever an
//! oracle — and controls to re-advertise, stop reading or close. Each
//! client runs on its own thread and runtime and binds its own `127.0.0.N`
//! source address (§11.1). Each case uses a subset of these helpers.
#![allow(dead_code)]
use crate::harness::{NLA, T, USER};
use ironrdp_async::FramedWrite as _;
use ironrdp_connector::connection_activation::{
    ConnectionActivationFactory, ConnectionActivationState,
};
use ironrdp_connector::{ClientConnector, ConnectionResult, Credentials, DesktopSize};
use ironrdp_core::{ReadCursor, WriteBuf, decode, decode_cursor, impl_as_any};
use ironrdp_dvc::{DrdynvcClient, DvcClientProcessor, DvcMessage, DvcProcessor};
use ironrdp_egfx::pdu::{
    Avc420BitmapStream, CapabilitiesAdvertisePdu, CapabilityVersion, FrameAcknowledgePdu, GfxPdu,
    QueueDepth, RawCapabilitySet,
};
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_graphics::zgfx::Decompressor;
use ironrdp_pdu::rdp::capability_sets::{MajorPlatformType, RailSupportLevel};
use ironrdp_pdu::rdp::server_error_info::{ErrorInfo, ProtocolIndependentCode};
use ironrdp_pdu::{PduResult, gcc};
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput};
use ironrdp_svc::ChannelFlags;
use kvm_proto::h264::split_annex_b;
use kvm_rdp::msg::Cause;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::mpsc;

type Upgraded = ironrdp_tokio::TokioFramed<ironrdp_tls::TlsStream<TcpStream>>;
type Log = Arc<Mutex<Vec<Ev>>>;

/// The connect's own bound (TCP, TLS, CredSSP, finalization), under `T`:
/// `connected()` and `refused()` wait `T` for its outcome, so a hung
/// connect is a `ConnectFailed("timeout")` they report, never their own
/// timeout with an empty timeline.
pub const CONNECT_BOUND: Duration = T.saturating_sub(Duration::from_secs(1));
/// How often `wait_for` re-checks its predicate.
const POLL: Duration = Duration::from_millis(10);

/// The next poll's delay: `base`, or twice what the predicate took, so a
/// slow predicate (a timeline over hundreds of pictures) gets at most a
/// third of the test thread.
fn poll_after(base: Duration, took: Duration) -> Duration {
    base.max(took.saturating_mul(2))
}

fn lock<X>(m: &Mutex<X>) -> MutexGuard<'_, X> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ack {
    Normal,
    /// Never acknowledge (a stalled client).
    Withhold,
    /// Acknowledge with `queue_depth = SUSPEND` (MS-RDPEGFX 2.2.2.13).
    Suspend,
}

#[derive(Debug, Clone)]
pub enum Ev {
    Connected,
    ConnectFailed(String),
    Gfx(GfxPdu),
    DeactivateAll,
    Reactivated(u16, u16),
    /// `ActiveStageOutput::Terminate`: an ErrorInfo's description.
    Terminated(String),
    Closed(String),
}

pub struct Opts {
    source: u8,
    user: String,
    domain: Option<String>,
    password: String,
    credssp: bool,
    caps: Option<Vec<RawCapabilitySet>>,
    ack: Ack,
    /// `SO_RCVBUF` for the client socket (a client that stops reading
    /// should block the server's writes quickly).
    recv_buffer: Option<u32>,
}

impl Opts {
    /// `127.0.0.<source>`, `kvm` with the right password, NLA, the census pair.
    pub fn new(source: u8) -> Opts {
        Opts {
            source,
            user: USER.to_owned(),
            domain: None,
            password: NLA.to_owned(),
            credssp: true,
            caps: Some(census_caps()),
            ack: Ack::Normal,
            recv_buffer: None,
        }
    }
    pub fn user(mut self, u: &str) -> Opts {
        self.user = u.to_owned();
        self
    }
    /// `DOMAIN\user`, as FreeRDP sends it through rdpgw.
    pub fn domain(mut self, d: &str) -> Opts {
        self.domain = Some(d.to_owned());
        self
    }
    pub fn recv_buffer(mut self, bytes: u32) -> Opts {
        self.recv_buffer = Some(bytes);
        self
    }
    pub fn password(mut self, p: &str) -> Opts {
        self.password = p.to_owned();
        self
    }
    pub fn no_credssp(mut self) -> Opts {
        self.credssp = false;
        self
    }
    pub fn caps(mut self, caps: Vec<RawCapabilitySet>) -> Opts {
        self.caps = Some(caps);
        self
    }
    pub fn ack(mut self, ack: Ack) -> Opts {
        self.ack = ack;
        self
    }
}

/// FreeRDP's `/gfx:AVC420` pair (`census.md`, Legs B and C).
pub fn census_caps() -> Vec<RawCapabilitySet> {
    vec![
        RawCapabilitySet::new(CapabilityVersion::V8, vec![0x02, 0, 0, 0]),
        RawCapabilitySet::new(CapabilityVersion::V8_1, vec![0x12, 0, 0, 0]),
    ]
}

/// A client with no AVC420 decoder.
pub fn v8_only() -> Vec<RawCapabilitySet> {
    vec![RawCapabilitySet::new(
        CapabilityVersion::V8,
        vec![0x02, 0, 0, 0],
    )]
}

enum Ctl {
    StopReading,
    Readvertise,
    Close,
}

pub struct Client {
    log: Log,
    ack: Arc<Mutex<Ack>>,
    ctl: mpsc::UnboundedSender<Ctl>,
}

impl Client {
    pub fn connect(server: SocketAddr, opts: Opts) -> Client {
        let log: Log = Arc::default();
        let ack = Arc::new(Mutex::new(opts.ack));
        let (ctl, rx) = mpsc::unbounded_channel();
        let (l, a) = (log.clone(), ack.clone());
        std::thread::Builder::new()
            .name(format!("l2-client-{}", opts.source))
            .spawn(move || run(server, opts, l, a, rx))
            .unwrap();
        Client { log, ack, ctl }
    }

    /// `f` over the log, under the lock the client thread takes for every
    /// event it records (and before it sends the acks): keep `f` cheap. A
    /// predicate that decodes pictures (`timeline`, `nal_types`) belongs in
    /// `wait_for`/`never`, which run it on a snapshot.
    pub fn with_log<R>(&self, f: impl FnOnce(&[Ev]) -> R) -> R {
        f(&lock(&self.log))
    }

    pub fn events(&self) -> Vec<Ev> {
        lock(&self.log).clone()
    }

    /// Extend `snap` with what the client recorded since: only the new
    /// events are copied under the lock. The log only grows, so `snap` is
    /// always a prefix of it — a consistent view, read with no lock held.
    fn catch_up(&self, snap: &mut Vec<Ev>) {
        let log = lock(&self.log);
        if let Some(new) = log.get(snap.len()..) {
            snap.extend_from_slice(new);
        }
    }

    /// Wait until `pred` holds over the log; panic with the timeline if not.
    /// Returns the snapshot `pred` held on.
    pub async fn wait_for(&self, timeout: Duration, pred: impl Fn(&[Ev]) -> bool) -> Vec<Ev> {
        let t0 = Instant::now();
        let mut snap = Vec::new();
        loop {
            self.catch_up(&mut snap);
            let took = Instant::now();
            if pred(&snap) {
                return snap;
            }
            if t0.elapsed() > timeout {
                panic!(
                    "no match within {timeout:?}; timeline: {:?}",
                    timeline(&snap)
                );
            }
            tokio::time::sleep(poll_after(POLL, took.elapsed())).await;
        }
    }

    /// `pred` never holds for `d`: over every event recorded before `d`
    /// ends. The last check's snapshot is taken once the deadline has
    /// passed — read before it — and polls never sleep past the deadline,
    /// so an event in the last poll interval is judged too (PC16 re-review:
    /// the loop used to stop at its first wake-up past `d`, unchecked).
    pub async fn never(&self, d: Duration, pred: impl Fn(&[Ev]) -> bool) {
        let t0 = Instant::now();
        let mut snap = Vec::new();
        loop {
            let last = t0.elapsed() >= d;
            self.catch_up(&mut snap);
            let took = Instant::now();
            assert!(!pred(&snap), "it happened; timeline: {:?}", timeline(&snap));
            if last {
                return;
            }
            let left = d.saturating_sub(t0.elapsed());
            tokio::time::sleep(poll_after(POLL * 2, took.elapsed()).min(left)).await;
        }
    }

    async fn outcome(&self) -> Vec<Ev> {
        self.wait_for(T, |e| {
            e.iter()
                .any(|x| matches!(x, Ev::Connected | Ev::ConnectFailed(_)))
        })
        .await
    }

    pub async fn connected(&self) {
        let evs = self.outcome().await;
        if let Some(Ev::ConnectFailed(why)) = evs.iter().find(|x| matches!(x, Ev::ConnectFailed(_)))
        {
            panic!("connect failed: {why}");
        }
    }

    /// The connection was refused; why.
    pub async fn refused(&self) -> String {
        let evs = self.outcome().await;
        evs.iter()
            .find_map(|x| {
                if let Ev::ConnectFailed(w) = x {
                    Some(w.clone())
                } else {
                    None
                }
            })
            .expect("the connection was accepted")
    }

    pub fn set_ack(&self, ack: Ack) {
        *lock(&self.ack) = ack;
    }

    pub fn stop_reading(&self) {
        let _ = self.ctl.send(Ctl::StopReading);
    }

    /// Send the capabilities again on the open EGFX channel.
    pub fn readvertise(&self) {
        let _ = self.ctl.send(Ctl::Readvertise);
    }

    pub fn close(&self) {
        let _ = self.ctl.send(Ctl::Close);
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.ctl.send(Ctl::Close);
    }
}

fn push(log: &Log, ev: Ev) {
    lock(log).push(ev);
}

fn config(opts: &Opts) -> ironrdp_connector::Config {
    ironrdp_connector::Config {
        desktop_size: DesktopSize {
            width: 1920,
            height: 1080,
        },
        monitor_layout: None,
        desktop_scale_factor: 0,
        enable_tls: true,
        enable_credssp: opts.credssp,
        enable_standard_rdp_security: false,
        credentials: Credentials::UsernamePassword {
            username: opts.user.clone(),
            password: opts.password.clone(),
        },
        domain: opts.domain.clone(),
        client_build: 0,
        client_name: "kvm-rdp-l2".to_owned(),
        keyboard_type: gcc::KeyboardType::IBM_ENHANCED,
        keyboard_subtype: 0,
        keyboard_layout: 0x409,
        keyboard_functional_keys_count: 12,
        connection_type: gcc::ConnectionType::Lan,
        ime_file_name: String::new(),
        bitmap: None,
        dig_product_id: String::new(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
        platform: MajorPlatformType::UNIX,
        hardware_id: None,
        request_data: None,
        autologon: false,
        enable_audio_playback: false,
        enable_audio_capture: false,
        license_cache: None,
        compression_type: None,
        enable_server_pointer: true,
        pointer_software_rendering: true,
        multitransport_flags: None,
        support_dyn_vc_gfx_protocol: opts.caps.is_some(),
        performance_flags: Default::default(),
        timezone_info: Default::default(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        remote_application_mode: false,
        rail_support_level: RailSupportLevel::SUPPORTED,
    }
}

/// TCP from `127.0.0.<source>`, TLS, CredSSP, finalization.
async fn connect(
    server: SocketAddr,
    opts: &Opts,
    log: &Log,
    ack: &Arc<Mutex<Ack>>,
) -> Result<(Upgraded, ConnectionResult), String> {
    let socket = TcpSocket::new_v4().map_err(|e| e.to_string())?;
    if let Some(n) = opts.recv_buffer {
        socket
            .set_recv_buffer_size(n)
            .map_err(|e| format!("SO_RCVBUF: {e}"))?;
    }
    socket
        .bind(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, opts.source),
            0,
        )))
        .map_err(|e| format!("bind: {e}"))?;
    let tcp = socket
        .connect(server)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let client_addr = tcp.local_addr().map_err(|e| e.to_string())?;
    let mut framed = ironrdp_tokio::TokioFramed::new(tcp);
    let mut connector = ClientConnector::new(config(opts), client_addr);
    if let Some(caps) = &opts.caps {
        let capture = Capture {
            caps: caps.clone(),
            log: log.clone(),
            ack: ack.clone(),
            zgfx: Decompressor::new(),
            decoded: 0,
        };
        connector =
            connector.with_static_channel(DrdynvcClient::new().with_dynamic_channel(capture));
    }
    let should_upgrade = ironrdp_async::connect_begin(&mut framed, &mut connector)
        .await
        .map_err(|e| format!("begin: {e}"))?;
    let (upgraded, cert) = ironrdp_tls::upgrade_with_certificate_validation(
        framed.into_inner_no_leftover(),
        "localhost",
        ironrdp_tls::CertificateValidation::DangerouslyAcceptInvalidCertificate,
    )
    .await
    .map_err(|e| format!("tls: {e}"))?;
    let marked = ironrdp_async::mark_as_upgraded(should_upgrade, &mut connector);
    let mut framed = ironrdp_tokio::TokioFramed::new(upgraded);
    let key = ironrdp_tls::extract_tls_server_public_key(&cert)
        .ok_or("no server public key")?
        .to_owned();
    let result = ironrdp_async::connect_finalize(
        marked,
        connector,
        &mut framed,
        &mut ironrdp_tokio::reqwest::ReqwestNetworkClient::new(),
        "localhost".into(),
        key,
        None,
    )
    .await
    .map_err(|e| format!("finalize: {e}"))?;
    Ok((framed, result))
}

/// The Deactivation-Reactivation Sequence (as IronRDP's own e2e test).
async fn reactivate(
    framed: &mut Upgraded,
    factory: &ConnectionActivationFactory,
    stage: &mut ActiveStage,
) -> Result<(u16, u16), String> {
    let mut seq = factory.create();
    let mut buf = WriteBuf::new();
    loop {
        let written = ironrdp_async::single_sequence_step_read(framed, &mut seq, &mut buf)
            .await
            .map_err(|e| format!("reactivation: {e}"))?;
        if written.size().is_some() {
            framed
                .write_all(buf.filled())
                .await
                .map_err(|e| format!("reactivation write: {e}"))?;
        }
        if let ConnectionActivationState::Finalized {
            desktop_size,
            share_id,
            enable_server_pointer,
            pointer_software_rendering,
            static_channel_chunk_size,
            ..
        } = seq.connection_activation_state()
        {
            if !stage.reactivate(
                seq.io_channel_id(),
                seq.user_channel_id(),
                share_id,
                enable_server_pointer,
                pointer_software_rendering,
                static_channel_chunk_size,
            ) {
                return Err("reactivate refused".to_owned());
            }
            return Ok((desktop_size.width, desktop_size.height));
        }
    }
}

fn run(
    server: SocketAddr,
    opts: Opts,
    log: Log,
    ack: Arc<Mutex<Ack>>,
    mut ctl: mpsc::UnboundedReceiver<Ctl>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        let (mut framed, result) =
            match tokio::time::timeout(CONNECT_BOUND, connect(server, &opts, &log, &ack)).await {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => return push(&log, Ev::ConnectFailed(e)),
                Err(_) => return push(&log, Ev::ConnectFailed("timeout".to_owned())),
            };
        push(&log, Ev::Connected);
        let factory = result.activation_factory;
        let mut stage = ActiveStageBuilder {
            static_channels: result.static_channels,
            user_channel_id: result.user_channel_id,
            io_channel_id: result.io_channel_id,
            message_channel_id: result.message_channel_id,
            share_id: result.share_id,
            compression_type: result.compression_type,
            enable_server_pointer: result.enable_server_pointer,
            pointer_software_rendering: result.pointer_software_rendering,
        }
        .build();
        // EGFX only: no bitmap ever reaches this image.
        let mut image = DecodedImage::new(PixelFormat::RgbA32, 1920, 1080);
        let mut reading = true;
        loop {
            tokio::select! {
                c = ctl.recv() => match c {
                    Some(Ctl::StopReading) => reading = false,
                    Some(Ctl::Readvertise) => {
                        let Some(caps) = opts.caps.clone() else { continue };
                        let Some(cid) = stage.get_dvc::<Capture>().map(|c| c.channel_id()) else { continue };
                        let msg: DvcMessage = Box::new(GfxPdu::CapabilitiesAdvertise(CapabilitiesAdvertisePdu(caps)));
                        let bytes = ironrdp_dvc::encode_dvc_messages(cid, vec![msg], ChannelFlags::empty())
                            .map_err(|e| e.to_string())
                            .and_then(|svc| stage.encode_dvc_messages(svc).map_err(|e| e.to_string()));
                        match bytes {
                            Ok(b) => {
                                if framed.write_all(&b).await.is_err() {
                                    return push(&log, Ev::Closed("write".to_owned()));
                                }
                            }
                            Err(e) => push(&log, Ev::Closed(format!("readvertise: {e}"))),
                        }
                    }
                    Some(Ctl::Close) | None => {
                        if let Ok(out) = stage.graceful_shutdown() {
                            for o in out {
                                if let ActiveStageOutput::ResponseFrame(f) = o {
                                    let _ = framed.write_all(&f).await;
                                }
                            }
                        }
                        return push(&log, Ev::Closed("client".to_owned()));
                    }
                },
                pdu = framed.read_pdu(), if reading => {
                    let (action, frame) = match pdu {
                        Ok(v) => v,
                        Err(e) => return push(&log, Ev::Closed(format!("read: {e}"))),
                    };
                    let outputs = match stage.process(&mut image, action, &frame) {
                        Ok(o) => o,
                        Err(e) => return push(&log, Ev::Closed(format!("process: {e}"))),
                    };
                    for o in outputs {
                        match o {
                            ActiveStageOutput::ResponseFrame(f) => {
                                if framed.write_all(&f).await.is_err() {
                                    return push(&log, Ev::Closed("write".to_owned()));
                                }
                            }
                            ActiveStageOutput::DeactivateAll => {
                                push(&log, Ev::DeactivateAll);
                                match reactivate(&mut framed, &factory, &mut stage).await {
                                    Ok((w, h)) => push(&log, Ev::Reactivated(w, h)),
                                    Err(e) => return push(&log, Ev::Closed(e)),
                                }
                            }
                            ActiveStageOutput::Terminate(reason) => {
                                return push(&log, Ev::Terminated(reason.description()));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    });
}

/// EGFX's client side: records, and acknowledges each `EndFrame` per mode.
struct Capture {
    caps: Vec<RawCapabilitySet>,
    log: Log,
    ack: Arc<Mutex<Ack>>,
    zgfx: Decompressor,
    decoded: u32,
}

impl_as_any!(Capture);

impl DvcProcessor for Capture {
    fn channel_name(&self) -> &str {
        ironrdp_egfx::CHANNEL_NAME
    }

    fn start(&mut self, _channel_id: u32) -> PduResult<Vec<DvcMessage>> {
        Ok(vec![Box::new(GfxPdu::CapabilitiesAdvertise(
            CapabilitiesAdvertisePdu(self.caps.clone()),
        ))])
    }

    fn process(&mut self, _channel_id: u32, payload: &[u8]) -> PduResult<Vec<DvcMessage>> {
        let mut plain = Vec::new();
        if let Err(e) = self.zgfx.decompress(payload, &mut plain) {
            push(&self.log, Ev::Closed(format!("zgfx: {e:?}")));
            return Ok(Vec::new());
        }
        let mut cur = ReadCursor::new(&plain);
        let mut replies: Vec<DvcMessage> = Vec::new();
        while !cur.is_empty() {
            let pdu = match decode_cursor::<GfxPdu>(&mut cur) {
                Ok(p) => p,
                Err(e) => {
                    push(&self.log, Ev::Closed(format!("gfx decode: {e:?}")));
                    break;
                }
            };
            if let GfxPdu::EndFrame(end) = &pdu {
                self.decoded = self.decoded.wrapping_add(1);
                let depth = match *lock(&self.ack) {
                    Ack::Normal => Some(QueueDepth::Unavailable),
                    Ack::Suspend => Some(QueueDepth::Suspend),
                    Ack::Withhold => None,
                };
                if let Some(queue_depth) = depth {
                    replies.push(Box::new(GfxPdu::FrameAcknowledge(FrameAcknowledgePdu {
                        queue_depth,
                        frame_id: end.frame_id,
                        total_frames_decoded: self.decoded,
                    })));
                }
            }
            push(&self.log, Ev::Gfx(pdu));
        }
        Ok(replies)
    }
}

impl DvcClientProcessor for Capture {}

pub struct Picture {
    pub frame_id: u32,
    pub annex_b: Vec<u8>,
}

/// Every `WireToSurface1`'s Annex-B, with its `StartFrame`'s frame id.
pub fn pictures(evs: &[Ev]) -> Vec<Picture> {
    let mut frame_id = 0;
    let mut out = Vec::new();
    for e in evs {
        match e {
            Ev::Gfx(GfxPdu::StartFrame(s)) => frame_id = s.frame_id,
            Ev::Gfx(GfxPdu::WireToSurface1(w)) => {
                let s: Avc420BitmapStream<'_> = decode(&w.bitmap_data).unwrap();
                out.push(Picture {
                    frame_id,
                    annex_b: s.data.to_vec(),
                });
            }
            _ => {}
        }
    }
    out
}

pub fn nal_types(annex_b: &[u8]) -> Vec<u8> {
    split_annex_b(annex_b).map(|n| n[0] & 0x1F).collect()
}

/// The log as labels: `confirm`, `reset WxH`, `surface WxH`, `map`,
/// `idr`/`p`, `delete`, `deactivate`, `reactivated WxH`, `terminated`,
/// `closed`, `failed` (frame markers and acks omitted).
pub fn timeline(evs: &[Ev]) -> Vec<String> {
    evs.iter()
        .filter_map(|e| match e {
            Ev::Connected => None,
            Ev::ConnectFailed(_) => Some("failed".to_owned()),
            Ev::Gfx(GfxPdu::CapabilitiesConfirm(_)) => Some("confirm".to_owned()),
            Ev::Gfx(GfxPdu::ResetGraphics(r)) => Some(format!("reset {}x{}", r.width, r.height)),
            Ev::Gfx(GfxPdu::CreateSurface(s)) => Some(format!("surface {}x{}", s.width, s.height)),
            Ev::Gfx(GfxPdu::MapSurfaceToOutput(_)) => Some("map".to_owned()),
            Ev::Gfx(GfxPdu::DeleteSurface(_)) => Some("delete".to_owned()),
            Ev::Gfx(GfxPdu::WireToSurface1(w)) => {
                let s: Avc420BitmapStream<'_> = decode(&w.bitmap_data).unwrap();
                Some(
                    if nal_types(s.data).contains(&5) {
                        "idr"
                    } else {
                        "p"
                    }
                    .to_owned(),
                )
            }
            Ev::Gfx(_) => None,
            Ev::DeactivateAll => Some("deactivate".to_owned()),
            Ev::Reactivated(w, h) => Some(format!("reactivated {w}x{h}")),
            Ev::Terminated(_) => Some("terminated".to_owned()),
            Ev::Closed(_) => Some("closed".to_owned()),
        })
        .collect()
}

pub fn terminated(evs: &[Ev]) -> Option<String> {
    evs.iter().find_map(|e| {
        if let Ev::Terminated(s) = e {
            Some(s.clone())
        } else {
            None
        }
    })
}

/// What the client shows for `cause` (§6.9's ErrorInfo table).
pub fn description(cause: Cause) -> String {
    cause.error_info().description()
}

/// What an evicted client shows (Preempt, §6.9).
pub fn takeover() -> String {
    ErrorInfo::ProtocolIndependentCode(ProtocolIndependentCode::DisconnectedByOtherconnection)
        .description()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A client with no connection behind it: its log is the test's.
    fn detached() -> (Client, Log) {
        let log: Log = Arc::default();
        let (ctl, _) = mpsc::unbounded_channel();
        let client = Client {
            log: log.clone(),
            ack: Arc::new(Mutex::new(Ack::Normal)),
            ctl,
        };
        (client, log)
    }

    /// PC16 re-review: `never(d, ..)` must judge every event recorded
    /// before `d` ends, including one that lands after its last poll
    /// inside the window. The predicate records the event itself on its
    /// first call and then takes 300 ms, so the next poll is due 600 ms
    /// later — past the 500 ms window: only a check at the deadline sees
    /// an event that was recorded at the window's start.
    #[tokio::test]
    async fn never_judges_an_event_in_the_last_poll_of_its_window() {
        let (client, log) = detached();
        let pushed = Arc::new(AtomicBool::new(false));
        let p = pushed.clone();
        let pred = move |e: &[Ev]| {
            if !p.swap(true, Ordering::SeqCst) {
                push(&log, Ev::Closed("forbidden".to_owned()));
                std::thread::sleep(Duration::from_millis(300));
            }
            e.iter().any(|x| matches!(x, Ev::Closed(_)))
        };
        let r =
            tokio::spawn(async move { client.never(Duration::from_millis(500), pred).await }).await;
        assert!(pushed.load(Ordering::SeqCst), "the predicate never ran");
        assert!(
            r.is_err_and(|e| e.is_panic()),
            "never() missed an event recorded inside its window"
        );
    }
}
