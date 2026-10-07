//! `kvm-sim`: a fake Angeet/Yeeso ES3 for tests and benches (spec §11.5,
//! Milestone 2). It serves the ES3's three TLS ports on loopback with one
//! self-signed certificate — `login.lua` with global logout, `av.flv` from
//! one shared encoder in the ES3's measured stream shape, and the control
//! websocket recording every HID frame — and records everything it sees so
//! the bridge's L2/L3 tests and kvm-bench can assert on it. It replays
//! committed fixtures only, never KVM captures.

mod encoder;
mod flv;
mod http;
mod source;
// The websocket (Task 8.6) is the last user of `state`.
#[allow(dead_code)]
mod state;
mod tls;
mod web;

pub use source::{Frame, Source, SourceError, fixtures_dir};
pub use state::{Policy, PortKind, SimEvent, SimStats};

use encoder::EncoderHandle;
use state::{Shared, WsCmd};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::task::AbortHandle;
use tokio_rustls::TlsAcceptor;

/// The stream's shape on the wire (`census.md`, Artifacts: kvm-sim profile).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    /// Nominal frame rate: FLV timestamps and real-time pacing.
    pub fps: u32,
    /// AVCC NAL length size: 1, 2 or 4.
    pub length_size: u8,
    /// `CompositionTime` on every coded tag (0 on the sequence header).
    pub composition_time_ms: i32,
    /// A new FLV connection replays the GOP so far at once (a GOP-caching
    /// source; the ES3 does not).
    pub burst_on_connect: bool,
    /// Shared encoder: any new FLV connection forces an IDR into every open
    /// stream and restarts the GOP.
    pub idr_on_new_connection: bool,
    /// Keep in-band SPS/PPS in coded tags (the ES3 sends them only in the
    /// sequence header).
    pub inband_params: bool,
    /// Keep AUDs (the ES3 sends none).
    pub aud: bool,
    /// Keep SEI (the ES3 sends none).
    pub sei: bool,
    /// Append the ES3's trailing zero bytes to the sequence header's
    /// parameter sets — one after the SPS, two after the PPS — as the device
    /// does (`census.md` `sps_hex`, `pps_hex`).
    pub padded_param_sets: bool,
}

impl Profile {
    /// The ES3 as measured (`census.md`, Leg A — stream): 30 fps, length size
    /// 4, `CompositionTime` 16, no burst, shared encoder, tag = AU carrying
    /// only NAL types 1 and 5, and a sequence header whose SPS and PPS end in
    /// zero bytes.
    #[must_use]
    pub fn es3() -> Profile {
        Profile {
            fps: 30,
            length_size: 4,
            composition_time_ms: 16,
            burst_on_connect: false,
            idr_on_new_connection: true,
            inband_params: false,
            aud: false,
            sei: false,
            padded_param_sets: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pacing {
    /// One frame every `1 / Profile::fps`, never catching up (the ES3 sends
    /// one tag every 33 ms whether the screen moves or not).
    RealTime,
    /// Frames only on [`KvmSim::advance`]: deterministic tests.
    Manual,
}

/// How a source switch reaches viewers (§6.4, §11.3 resolution change).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResizeSignal {
    /// A new sequence header on every open FLV.
    SequenceHeader,
    /// The new SPS/PPS in-band in the next IDR's tag.
    InBandSps,
    /// Every open FLV closes (the ES3's observed preset change); new
    /// connections get the new source.
    CloseFlv,
}

/// One-shot faults, applied by every open FLV to its next tag (§6.9 cases).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    OversizeTag,
    BadPrevTagSize,
    EncryptedTag,
    BadStreamId,
    HevcCodecId,
    EnhancedHevc,
    /// The next coded tag's `CompositionTime`.
    CompositionTime(i32),
    /// The next two pictures in one tag.
    TwoPictures,
    BSlice,
    StartCodeInNal,
    ForbiddenBit,
    /// An `AVCPacketType 2` tag, now.
    EndOfSequence,
    /// 129 NALs in one tag.
    TooManyNals,
    /// Close every open FLV, now.
    Close,
    /// Stop writing on every open FLV, keeping it open.
    Silence,
}

pub struct SimConfig {
    pub password: String,
    pub profile: Profile,
    pub pacing: Pacing,
    pub source: Source,
    /// `SO_RCVBUF` for control-port sockets, so a test can make the
    /// bridge's websocket writes block quickly.
    pub control_recv_buffer: Option<u32>,
    /// `SO_SNDBUF` for video-port sockets, so a viewer that stops reading
    /// blocks its writer after little data.
    pub video_send_buffer: Option<u32>,
}

impl SimConfig {
    /// The ES3 profile, real-time, over `source`.
    #[must_use]
    pub fn es3(source: Source) -> SimConfig {
        SimConfig {
            password: "kvm-sim-password".to_owned(),
            profile: Profile::es3(),
            pacing: Pacing::RealTime,
            source,
            control_recv_buffer: None,
            video_send_buffer: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimPorts {
    pub web: u16,
    pub video: u16,
    pub control: u16,
}

/// A running simulated KVM. Dropping it stops everything.
pub struct KvmSim {
    ports: SimPorts,
    spki_sha256: String,
    password: String,
    shared: Arc<Shared>,
    enc: EncoderHandle,
    tasks: Arc<std::sync::Mutex<Vec<AbortHandle>>>,
}

async fn bind(recv_buffer: Option<u32>, send_buffer: Option<u32>) -> std::io::Result<TcpListener> {
    let sock = TcpSocket::new_v4()?;
    // Accepted sockets inherit the listener's buffer sizes.
    if let Some(n) = recv_buffer {
        sock.set_recv_buffer_size(n)?;
    }
    if let Some(n) = send_buffer {
        sock.set_send_buffer_size(n)?;
    }
    sock.bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    sock.listen(64)
}

/// Bound on TLS accept and request-head read for one connection.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// What every connection task shares.
struct ConnCtx {
    shared: Arc<Shared>,
    acceptor: TlsAcceptor,
    password: String,
    enc: EncoderHandle,
    profile: Profile,
}

/// One accepted connection: TLS, then its port's service. The websocket is
/// Task 8.6's; until then the control port answers 404.
async fn serve_connection(kind: PortKind, tcp: TcpStream, conn: u64, ctx: Arc<ConnCtx>) {
    let Ok(Ok(mut tls)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, ctx.acceptor.accept(tcp)).await
    else {
        return;
    };
    let Ok(Some(req)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, http::read_request(&mut tls)).await
    else {
        return;
    };
    match kind {
        PortKind::Web => web::serve(tls, req, &ctx.shared, &ctx.password).await,
        PortKind::Video => {
            let (shared, enc) = (ctx.shared.clone(), ctx.enc.clone());
            flv::serve(tls, req, conn, shared, enc, ctx.profile).await;
        }
        PortKind::Control => {
            let _ = http::respond(&mut tls, 404, "text/plain", b"not yet").await;
        }
    }
}

/// `Policy::blackhole`: an unreachable KVM (§11.3). The connection stays
/// open and silent — no TLS, no bytes — until the client gives up.
async fn hold_silent(mut tcp: TcpStream) {
    let mut sink = [0u8; 1024];
    while matches!(tcp.read(&mut sink).await, Ok(n) if n > 0) {}
}

impl KvmSim {
    pub async fn start(cfg: SimConfig) -> std::io::Result<KvmSim> {
        let id = tls::identity()?;
        let shared = Arc::new(Shared::default());
        let (enc, enc_task) = encoder::spawn(cfg.source, cfg.profile, cfg.pacing, shared.clone());
        let tasks = Arc::new(std::sync::Mutex::new(vec![enc_task.abort_handle()]));
        let (web, video, control) = (
            bind(None, None).await?,
            bind(None, cfg.video_send_buffer).await?,
            bind(cfg.control_recv_buffer, None).await?,
        );
        let ports = SimPorts {
            web: web.local_addr()?.port(),
            video: video.local_addr()?.port(),
            control: control.local_addr()?.port(),
        };
        let ctx = Arc::new(ConnCtx {
            shared: shared.clone(),
            acceptor: id.acceptor,
            password: cfg.password.clone(),
            enc: enc.clone(),
            profile: cfg.profile,
        });
        let next_conn = Arc::new(AtomicU64::new(1));
        for (listener, kind) in [
            (web, PortKind::Web),
            (video, PortKind::Video),
            (control, PortKind::Control),
        ] {
            let (ctx, tasks2, next_conn) = (ctx.clone(), tasks.clone(), next_conn.clone());
            let accept = tokio::spawn(async move {
                while let Ok((tcp, _)) = listener.accept().await {
                    ctx.shared.record(SimEvent::Accept { port: kind });
                    let _ = tcp.set_nodelay(true);
                    let conn = next_conn.fetch_add(1, Ordering::Relaxed);
                    let task = if ctx.shared.policy().blackhole {
                        tokio::spawn(hold_silent(tcp))
                    } else {
                        tokio::spawn(serve_connection(kind, tcp, conn, ctx.clone()))
                    };
                    if let Ok(mut t) = tasks2.lock() {
                        t.retain(|h| !h.is_finished());
                        t.push(task.abort_handle());
                    }
                }
            });
            if let Ok(mut t) = tasks.lock() {
                t.push(accept.abort_handle());
            }
        }
        Ok(KvmSim {
            ports,
            spki_sha256: id.spki_sha256,
            password: cfg.password,
            shared,
            enc,
            tasks,
        })
    }

    /// Always loopback.
    #[must_use]
    pub fn host(&self) -> &'static str {
        "127.0.0.1"
    }
    #[must_use]
    pub fn ports(&self) -> SimPorts {
        self.ports
    }
    /// The pin for the bridge's `kvm.spki_sha256` (one cert, all ports).
    #[must_use]
    pub fn spki_sha256(&self) -> &str {
        &self.spki_sha256
    }
    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }
    #[must_use]
    pub fn events(&self) -> Vec<SimEvent> {
        self.shared.events()
    }
    /// Events with the instant each was recorded (`FlvAu`: `sim_tx`).
    #[must_use]
    pub fn stamped_events(&self) -> Vec<(Instant, SimEvent)> {
        self.shared.stamped_events()
    }
    #[must_use]
    pub fn stats(&self) -> SimStats {
        self.shared.stats()
    }
    /// Wait until `pred` holds over the event log; `Err` carries the log at
    /// the timeout.
    pub async fn wait_for(
        &self,
        timeout: Duration,
        pred: impl Fn(&[SimEvent]) -> bool,
    ) -> Result<Vec<SimEvent>, Vec<SimEvent>> {
        self.shared.wait_for(timeout, pred).await
    }
    pub fn set_policy(&self, f: impl FnOnce(&mut Policy)) {
        self.shared.set_policy(f);
    }
    /// Invalidate every token without a logout request (token expiry).
    pub fn expire_tokens(&self) {
        self.shared.clear_tokens();
    }
    /// `Pacing::Manual`: encode `frames` frames now.
    pub fn advance(&self, frames: u32) {
        self.enc.advance(frames);
    }
    /// HDMI signal present (`false`: the NO SIGNAL card, every frame an IDR).
    pub fn set_signal(&self, present: bool) {
        self.enc.signal(present);
    }
    pub fn inject(&self, fault: Fault) {
        self.enc.inject(fault);
    }
    pub fn switch_source(&self, source: Source, signal: ResizeSignal) {
        self.enc.switch(source, signal);
    }
    pub fn close_websockets(&self) {
        self.shared.ws_broadcast(WsCmd::Close);
    }
    /// Send every open websocket a frame header declaring `declared_len`
    /// bytes (§3.2: the bridge closes at 4 KiB without buffering).
    pub fn send_ws_oversize(&self, declared_len: u64) {
        self.shared.ws_broadcast(WsCmd::Oversize(declared_len));
    }
}

impl Drop for KvmSim {
    fn drop(&mut self) {
        if let Ok(t) = self.tasks.lock() {
            t.iter().for_each(AbortHandle::abort);
        }
    }
}
