//! kvm-bench's RDP client (§10.2; DE10): IronRDP's connector with NLA over
//! TLS and a lean EGFX `DvcProcessor` — ZGFX, decode, one `Rx` per frame at
//! its EndFrame (FrameId, arrival, IDR, VCL bytes), acks per `Shape` —
//! plus fast-path keys and, for the soak's paste, a CLIPRDR text holder.
//! Not L2's client: that one records every PDU for its oracles, which at
//! 1080p60 would be the measurement. Each client has its own thread and
//! runtime and binds `127.0.0.<source>` (Preempt's per-address cooldown).
use crate::bridge::{NLA_PASSWORD, USER};
use ironrdp_async::FramedWrite as _;
use ironrdp_cliprdr::CliprdrClient;
use ironrdp_cliprdr::backend::{ClipboardMessage, ClipboardMessageProxy, CliprdrBackend};
use ironrdp_cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest,
    FileContentsResponse, FormatDataRequest, FormatDataResponse, LockDataId,
    OwnedFormatDataResponse,
};
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
use ironrdp_pdu::input::fast_path::{FastPathInputEvent, KeyboardFlags};
use ironrdp_pdu::rdp::capability_sets::{MajorPlatformType, RailSupportLevel};
use ironrdp_pdu::{PduResult, gcc};
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput};
use ironrdp_svc::ChannelFlags;
use kvm_proto::h264::{frame_id, is_vcl, split_annex_b};
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::mpsc;

type Upgraded = ironrdp_tokio::TokioFramed<ironrdp_tls::TlsStream<TcpStream>>;
type Acks = Arc<Mutex<VecDeque<(Instant, FrameAcknowledgePdu)>>>;

fn lock<X>(m: &Mutex<X>) -> MutexGuard<'_, X> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckMode {
    Normal,
    /// Never acknowledge (a stalled client).
    Withhold,
    /// Acknowledge with `queue_depth = SUSPEND` (MS-RDPEGFX 2.2.2.13).
    Suspend,
}

/// §10.2's in-process shaping, changeable while connected.
#[derive(Debug, Clone, Copy)]
pub struct Shape {
    pub ack: AckMode,
    pub ack_delay: Duration,
    /// Read at most this many bits per second.
    pub read_bps: Option<u64>,
    pub reading: bool,
}

impl Default for Shape {
    fn default() -> Shape {
        Shape {
            ack: AckMode::Normal,
            ack_delay: Duration::ZERO,
            read_bps: None,
            reading: true,
        }
    }
}

/// One frame, at its EndFrame.
#[derive(Debug, Clone, Copy)]
pub struct Rx {
    pub frame_id: u64,
    pub at: Instant,
    pub idr: bool,
    pub vcl_bytes: usize,
}

#[derive(Debug, Default)]
pub struct Log {
    pub connected: Option<Instant>,
    pub ended: Option<(Instant, String)>,
    pub rx: Vec<Rx>,
    /// Each key press, `(scancode, written)` — when its PDU's write returned.
    pub keys: Vec<(u8, Instant)>,
    pub last_read: Option<Instant>,
}

pub struct Opts {
    pub source: u8,
    pub caps: Vec<RawCapabilitySet>,
    pub clipboard: Option<String>,
}

impl Opts {
    pub fn new(source: u8) -> Opts {
        Opts {
            source,
            caps: census_caps(),
            clipboard: None,
        }
    }
}

/// FreeRDP's `/gfx:AVC420` pair (census.md, Legs B and C).
pub fn census_caps() -> Vec<RawCapabilitySet> {
    vec![
        RawCapabilitySet::new(CapabilityVersion::V8, vec![0x02, 0, 0, 0]),
        RawCapabilitySet::new(CapabilityVersion::V8_1, vec![0x12, 0, 0, 0]),
    ]
}

enum Ctl {
    Key(u8, bool),
    Readvertise,
    Close,
}

pub struct BenchClient {
    log: Arc<Mutex<Log>>,
    shape: Arc<Mutex<Shape>>,
    ctl: mpsc::UnboundedSender<Ctl>,
}

impl BenchClient {
    pub fn connect(server: SocketAddr, opts: Opts) -> BenchClient {
        let (log, shape) = (
            Arc::new(Mutex::new(Log::default())),
            Arc::new(Mutex::new(Shape::default())),
        );
        let (ctl, rx) = mpsc::unbounded_channel();
        let (l, s) = (log.clone(), shape.clone());
        let source = opts.source;
        std::thread::Builder::new()
            .name(format!("bench-client-{source}"))
            .spawn(move || run(server, opts, l, s, rx))
            .expect("spawn the client thread");
        BenchClient { log, shape, ctl }
    }

    pub fn shape(&self, f: impl FnOnce(&mut Shape)) {
        f(&mut lock(&self.shape));
    }

    pub fn with_log<R>(&self, f: impl FnOnce(&Log) -> R) -> R {
        f(&lock(&self.log))
    }

    /// Until `pred` holds over the log (polled every 20 ms), or `limit`.
    pub async fn until(&self, limit: Duration, pred: impl Fn(&Log) -> bool) -> bool {
        let t0 = Instant::now();
        loop {
            if self.with_log(&pred) {
                return true;
            }
            if t0.elapsed() > limit {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    pub fn key(&self, scancode: u8, pressed: bool) {
        let _ = self.ctl.send(Ctl::Key(scancode, pressed));
    }

    pub fn readvertise(&self) {
        let _ = self.ctl.send(Ctl::Readvertise);
    }

    pub fn close(&self) {
        let _ = self.ctl.send(Ctl::Close);
    }
}

impl Drop for BenchClient {
    fn drop(&mut self) {
        self.close();
    }
}

fn end(log: &Arc<Mutex<Log>>, why: String) {
    let mut l = lock(log);
    if l.ended.is_none() {
        l.ended = Some((Instant::now(), why));
    }
}

fn config() -> ironrdp_connector::Config {
    ironrdp_connector::Config {
        desktop_size: DesktopSize {
            width: 1920,
            height: 1080,
        },
        monitor_layout: None,
        desktop_scale_factor: 0,
        enable_tls: true,
        enable_credssp: true,
        enable_standard_rdp_security: false,
        credentials: Credentials::UsernamePassword {
            username: USER.to_owned(),
            password: NLA_PASSWORD.to_owned(),
        },
        domain: None,
        client_build: 0,
        client_name: "kvm-bench".to_owned(),
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
        support_dyn_vc_gfx_protocol: true,
        performance_flags: Default::default(),
        timezone_info: Default::default(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        remote_application_mode: false,
        rail_support_level: RailSupportLevel::SUPPORTED,
    }
}

async fn connect(
    server: SocketAddr,
    opts: &Opts,
    capture: Capture,
    clip: mpsc::UnboundedSender<ClipboardMessage>,
) -> Result<(Upgraded, ConnectionResult), String> {
    let socket = TcpSocket::new_v4().map_err(|e| e.to_string())?;
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
    tcp.set_nodelay(true).map_err(|e| e.to_string())?;
    let client_addr = tcp.local_addr().map_err(|e| e.to_string())?;
    let mut framed = ironrdp_tokio::TokioFramed::new(tcp);
    let mut connector = ClientConnector::new(config(), client_addr)
        .with_static_channel(DrdynvcClient::new().with_dynamic_channel(capture));
    if let Some(text) = &opts.clipboard {
        let backend = ClientClip {
            text: text.clone(),
            proxy: ClipProxy(clip),
        };
        connector = connector.with_static_channel(CliprdrClient::new(Box::new(backend)));
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

/// The Deactivation-Reactivation Sequence (a server resize), as L2's client.
async fn reactivate(
    framed: &mut Upgraded,
    factory: &ConnectionActivationFactory,
    stage: &mut ActiveStage,
) -> Result<(), String> {
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
            return Ok(());
        }
    }
}

async fn sleep_until(t: Option<Instant>) {
    match t {
        Some(t) => tokio::time::sleep_until(t.into()).await,
        None => std::future::pending().await,
    }
}

fn run(
    server: SocketAddr,
    opts: Opts,
    log: Arc<Mutex<Log>>,
    shape: Arc<Mutex<Shape>>,
    mut ctl: mpsc::UnboundedReceiver<Ctl>,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("client runtime");
    rt.block_on(async move {
        let acks: Acks = Arc::default();
        let capture = Capture {
            caps: opts.caps.clone(),
            log: log.clone(),
            shape: shape.clone(),
            acks: acks.clone(),
            zgfx: Decompressor::new(),
            decoded: 0,
            pending: None,
        };
        let (clip_tx, mut clip_rx) = mpsc::unbounded_channel();
        let (mut framed, result) =
            match tokio::time::timeout(Duration::from_secs(10), connect(server, &opts, capture, clip_tx)).await {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => return end(&log, e),
                Err(_) => return end(&log, "connect timeout".to_owned()),
            };
        lock(&log).connected = Some(Instant::now());
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
        // EGFX only: no bitmap update ever lands here.
        let mut image = DecodedImage::new(PixelFormat::RgbA32, 1920, 1080);
        // §10.2's shaped link (pre-flight E62): a link of `read_bps` the
        // client reads through. Each PDU holds the link for len·8/bps after
        // it arrives, so an IDR serialises as on a real link, and no credit
        // accumulates while the source is quiet; a change of rate starts
        // the link afresh. While the link is busy the read arm is off and a
        // wake arm waits for it, so acks still fall due and go out.
        let (mut link_free, mut link_bps) = (Instant::now(), None::<u64>);
        let mut clip_open = true;
        loop {
            let s = *lock(&shape);
            if s.read_bps != link_bps {
                (link_free, link_bps) = (Instant::now(), s.read_bps);
            }
            let link_open = link_bps.is_none() || Instant::now() >= link_free;
            let next_ack = lock(&acks).front().map(|(t, _)| *t);
            tokio::select! {
                c = ctl.recv() => match c {
                    Some(Ctl::Key(code, pressed)) => {
                        let flags = if pressed { KeyboardFlags::empty() } else { KeyboardFlags::RELEASE };
                        let out = match stage.process_fastpath_input(&mut image, &[FastPathInputEvent::KeyboardEvent(flags, code)]) {
                            Ok(o) => o,
                            Err(e) => return end(&log, format!("input: {e}")),
                        };
                        for o in out {
                            if let ActiveStageOutput::ResponseFrame(f) = o
                                && framed.write_all(&f).await.is_err()
                            {
                                return end(&log, "write".to_owned());
                            }
                        }
                        if pressed {
                            lock(&log).keys.push((code, Instant::now()));
                        }
                    }
                    Some(Ctl::Readvertise) => {
                        let Some(cid) = stage.get_dvc::<Capture>().map(|c| c.channel_id()) else { continue };
                        let msg: DvcMessage = Box::new(GfxPdu::CapabilitiesAdvertise(CapabilitiesAdvertisePdu(opts.caps.clone())));
                        match ironrdp_dvc::encode_dvc_messages(cid, vec![msg], ChannelFlags::empty())
                            .map_err(|e| e.to_string())
                            .and_then(|svc| stage.encode_dvc_messages(svc).map_err(|e| e.to_string()))
                        {
                            Ok(b) => if framed.write_all(&b).await.is_err() { return end(&log, "write".to_owned()) },
                            Err(e) => return end(&log, format!("readvertise: {e}")),
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
                        return end(&log, "client".to_owned());
                    }
                },
                // Delayed acks (§10.2's ack delay): each sent when due, in order.
                () = sleep_until(next_ack) => {
                    let now = Instant::now();
                    let mut due: Vec<DvcMessage> = Vec::new();
                    {
                        let mut q = lock(&acks);
                        while q.front().is_some_and(|(t, _)| *t <= now) {
                            if let Some((_, a)) = q.pop_front() {
                                due.push(Box::new(GfxPdu::FrameAcknowledge(a)));
                            }
                        }
                    }
                    let Some(cid) = stage.get_dvc::<Capture>().map(|c| c.channel_id()) else { continue };
                    match ironrdp_dvc::encode_dvc_messages(cid, due, ChannelFlags::empty())
                        .map_err(|e| e.to_string())
                        .and_then(|svc| stage.encode_dvc_messages(svc).map_err(|e| e.to_string()))
                    {
                        Ok(b) => if framed.write_all(&b).await.is_err() { return end(&log, "write".to_owned()) },
                        Err(e) => return end(&log, format!("ack: {e}")),
                    }
                }
                m = clip_rx.recv(), if clip_open => {
                    let Some(m) = m else { clip_open = false; continue };
                    let Some(cliprdr) = stage.get_svc_processor_mut::<CliprdrClient>() else { continue };
                    let msgs = match m {
                        ClipboardMessage::SendInitiateCopy(formats) => cliprdr.initiate_copy(&formats),
                        ClipboardMessage::SendFormatData(r) => cliprdr.submit_format_data(r),
                        _ => continue,
                    };
                    match msgs.map_err(|e| e.to_string()).and_then(|m| stage.process_svc_processor_messages(m).map_err(|e| e.to_string())) {
                        Ok(b) => if framed.write_all(&b).await.is_err() { return end(&log, "write".to_owned()) },
                        Err(e) => return end(&log, format!("cliprdr: {e}")),
                    }
                }
                () = tokio::time::sleep_until(link_free.into()), if s.reading && !link_open => {}
                pdu = framed.read_pdu(), if s.reading && link_open => {
                    let (action, frame) = match pdu {
                        Ok(v) => v,
                        Err(e) => return end(&log, format!("read: {e}")),
                    };
                    lock(&log).last_read = Some(Instant::now());
                    if let Some(bps) = link_bps {
                        link_free = Instant::now() + Duration::from_secs_f64(frame.len() as f64 * 8.0 / bps as f64);
                    }
                    let outputs = match stage.process(&mut image, action, &frame) {
                        Ok(o) => o,
                        Err(e) => return end(&log, format!("process: {e}")),
                    };
                    for o in outputs {
                        match o {
                            ActiveStageOutput::ResponseFrame(f) => {
                                if framed.write_all(&f).await.is_err() {
                                    return end(&log, "write".to_owned());
                                }
                            }
                            ActiveStageOutput::DeactivateAll => {
                                if let Err(e) = reactivate(&mut framed, &factory, &mut stage).await {
                                    return end(&log, e);
                                }
                            }
                            ActiveStageOutput::Terminate(reason) => return end(&log, reason.description()),
                            _ => {}
                        }
                    }
                }
            }
        }
    });
}

/// EGFX's client side: one `Rx` per frame, acks per `Shape`.
struct Capture {
    caps: Vec<RawCapabilitySet>,
    log: Arc<Mutex<Log>>,
    shape: Arc<Mutex<Shape>>,
    acks: Acks,
    zgfx: Decompressor,
    decoded: u32,
    /// The frame between its WireToSurface1 and its EndFrame.
    pending: Option<(u64, bool, usize)>,
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
        if self.zgfx.decompress(payload, &mut plain).is_err() {
            return Ok(Vec::new());
        }
        let mut cur = ReadCursor::new(&plain);
        let mut replies: Vec<DvcMessage> = Vec::new();
        while !cur.is_empty() {
            let Ok(pdu) = decode_cursor::<GfxPdu>(&mut cur) else {
                break;
            };
            match pdu {
                GfxPdu::WireToSurface1(w) => {
                    if let Ok(s) = decode::<Avc420BitmapStream<'_>>(&w.bitmap_data) {
                        let vcl = || {
                            split_annex_b(s.data)
                                .filter(|n| n.first().is_some_and(|b| is_vcl(b & 0x1F)))
                        };
                        let idr = vcl().any(|n| n.first().is_some_and(|b| b & 0x1F == 5));
                        let bytes = vcl().map(<[u8]>::len).sum();
                        self.pending = Some((frame_id(vcl()), idr, bytes));
                    }
                }
                GfxPdu::EndFrame(end) => {
                    let at = Instant::now();
                    if let Some((frame_id, idr, vcl_bytes)) = self.pending.take() {
                        lock(&self.log).rx.push(Rx {
                            frame_id,
                            at,
                            idr,
                            vcl_bytes,
                        });
                    }
                    self.decoded = self.decoded.wrapping_add(1);
                    let s = *lock(&self.shape);
                    let depth = match s.ack {
                        AckMode::Normal => Some(QueueDepth::Unavailable),
                        AckMode::Suspend => Some(QueueDepth::Suspend),
                        AckMode::Withhold => None,
                    };
                    if let Some(queue_depth) = depth {
                        let ack = FrameAcknowledgePdu {
                            queue_depth,
                            frame_id: end.frame_id,
                            total_frames_decoded: self.decoded,
                        };
                        if s.ack_delay.is_zero() {
                            replies.push(Box::new(GfxPdu::FrameAcknowledge(ack)));
                        } else {
                            lock(&self.acks).push_back((at + s.ack_delay, ack));
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(replies)
    }
}

impl DvcClientProcessor for Capture {}

#[derive(Debug)]
struct ClipProxy(mpsc::UnboundedSender<ClipboardMessage>);

impl ClipboardMessageProxy for ClipProxy {
    fn send_clipboard_message(&self, message: ClipboardMessage) {
        let _ = self.0.send(message);
    }
}

/// The soak's clipboard (Task 5.5): offers CF_UNICODETEXT, answers with
/// its text — as L2's `ClientClip`, without the log.
struct ClientClip {
    text: String,
    proxy: ClipProxy,
}

impl_as_any!(ClientClip);

impl std::fmt::Debug for ClientClip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientClip")
            .field("text_len", &self.text.len())
            .finish_non_exhaustive()
    }
}

impl CliprdrBackend for ClientClip {
    fn temporary_directory(&self) -> &str {
        "."
    }
    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::empty()
    }
    fn on_ready(&mut self) {}
    fn on_request_format_list(&mut self) {
        self.proxy
            .send_clipboard_message(ClipboardMessage::SendInitiateCopy(vec![
                ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT),
            ]));
    }
    fn on_process_negotiated_capabilities(&mut self, _: ClipboardGeneralCapabilityFlags) {}
    fn on_remote_copy(&mut self, _: &[ClipboardFormat]) {}
    fn on_format_data_request(&mut self, req: FormatDataRequest) {
        let answer = if req.format == ClipboardFormatId::CF_UNICODETEXT {
            OwnedFormatDataResponse::new_unicode_string(&self.text)
        } else {
            OwnedFormatDataResponse::new_error()
        };
        self.proxy
            .send_clipboard_message(ClipboardMessage::SendFormatData(answer));
    }
    fn on_format_data_response(&mut self, _: FormatDataResponse<'_>) {}
    fn on_file_contents_request(&mut self, _: FileContentsRequest) {}
    fn on_file_contents_response(&mut self, _: FileContentsResponse<'_>) {}
    fn on_lock(&mut self, _: LockDataId) {}
    fn on_unlock(&mut self, _: LockDataId) {}
}
