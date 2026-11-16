//! The null bridge (§10.1): a minimal IronRDP server — NLA, EGFX AVC420 —
//! sending a source's access units from memory on kvm-sim's schedule (one
//! every 1/fps from the first IDR, looped), so kvm-bench can report the
//! same client's end-to-end latency against it beside the bridge's: p50 and
//! p99 of each, never subtracted. One client at a time; information only.
//! Each send is stamped before it starts — before `send_avc420_frame` —
//! as kvm-sim stamps `sim_tx` as a tag's write starts (`SendLog`; PE12
//! review I1, re-review): the two distributions share one stamp point.
use crate::bridge::{NLA_PASSWORD, USER};
use ironrdp_dvc::{DvcMessage, encode_dvc_messages};
use ironrdp_egfx::pdu::{Avc420Region, CapabilitiesAdvertisePdu, CapabilitySet};
use ironrdp_egfx::server::{GraphicsPipelineHandler, GraphicsPipelineServer};
use ironrdp_pdu::gcc::{Monitor, MonitorFlags};
use ironrdp_server::{
    Credentials, DesktopSize, DisplayUpdate, EgfxServerMessage, GfxDvcBridge, GfxServerFactory,
    GfxServerHandle, KeyboardEvent, MouseEvent, RdpServer, RdpServerDisplay,
    RdpServerDisplayUpdates, RdpServerInputHandler, ServerEvent, ServerEventSender, ServerResult,
};
use ironrdp_svc::ChannelFlags;
use kvm_bench::frames::SendLog;
use kvm_proto::h264::{frame_id, is_vcl, parse_sps};
use kvm_sim::Source;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

type Slot = Arc<Mutex<Option<GfxServerHandle>>>;

/// The region QP the bridge's default `video.region_qp` sends (§6.4).
const REGION_QP: u8 = 22;
/// No flow control of the bridge's (§6.6): IronRDP's own cap only.
const MAX_IN_FLIGHT: u32 = 120;

fn lock<X>(m: &Mutex<X>) -> MutexGuard<'_, X> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

pub struct NullBridge {
    pub addr: SocketAddr,
    sent: SendLog,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl NullBridge {
    pub fn start(source: &Source, fps: u32) -> Result<NullBridge, String> {
        let sps = parse_sps(&source.sps).map_err(|e| format!("the source's SPS: {e:?}"))?;
        let size = (
            u16::try_from(sps.width).map_err(|_| "width".to_owned())?,
            u16::try_from(sps.height).map_err(|_| "height".to_owned())?,
        );
        let frames = annex_b(source);
        let sent = SendLog::default();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let (stop, stopped) = oneshot::channel();
        let s = sent.clone();
        let thread = std::thread::Builder::new()
            .name("null-bridge".to_owned())
            .spawn(move || {
                // `RdpServer` is `!Send`: the server and the shipper share
                // one thread, as the bridge's RDP runtime does.
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = addr_tx.send(Err(format!("the null bridge's runtime: {e}")));
                        return;
                    }
                };
                tokio::task::LocalSet::new()
                    .block_on(&rt, serve(frames, size, fps.max(1), s, addr_tx, stopped));
            })
            .map_err(|e| e.to_string())?;
        let addr = addr_rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| "the null bridge did not start".to_owned())??;
        Ok(NullBridge {
            addr,
            sent,
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    /// What the null bridge sent, `(frame_id, stamped before the send)`.
    pub fn sent(&self) -> Vec<(u64, Instant)> {
        self.sent.sent()
    }
}

impl Drop for NullBridge {
    fn drop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Each frame's FrameId and §6.3's Annex-B: SPS and PPS before an IDR, the
/// VCL NALs, 4-byte start codes — pre-converted, as §10.1 says.
fn annex_b(source: &Source) -> Vec<(u64, Vec<u8>)> {
    source
        .frames
        .iter()
        .map(|f| {
            let vcl: Vec<&[u8]> = f
                .nals
                .iter()
                .map(|n| n.as_ref())
                .filter(|n: &&[u8]| n.first().is_some_and(|b| is_vcl(b & 0x1F)))
                .collect();
            let mut out = Vec::new();
            let mut nals: Vec<&[u8]> = Vec::new();
            if f.idr {
                nals.push(&source.sps);
                nals.push(&source.pps);
            }
            nals.extend(vcl.iter().copied());
            for n in nals {
                out.extend_from_slice(&[0, 0, 0, 1]);
                out.extend_from_slice(n);
            }
            (frame_id(vcl.iter().copied()), out)
        })
        .collect()
}

/// A fresh self-signed identity on aws-lc-rs, and the certificate's
/// subjectPublicKey, which CredSSP binds to (as `rdp/tls.rs`).
fn tls() -> Result<(tokio_rustls::TlsAcceptor, Vec<u8>), String> {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .map_err(|e| e.to_string())?;
    let public_key = {
        let (_, cert) =
            x509_parser::parse_x509_certificate(ck.cert.der()).map_err(|e| e.to_string())?;
        cert.public_key().subject_public_key.data.to_vec()
    };
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(ck.key_pair.serialize_der().into());
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(vec![ck.cert.der().clone()], key)
        .map_err(|e| e.to_string())?;
    Ok((
        tokio_rustls::TlsAcceptor::from(Arc::new(config)),
        public_key,
    ))
}

struct Fixed(u16, u16);

#[async_trait::async_trait]
impl RdpServerDisplay for Fixed {
    async fn size(&mut self) -> DesktopSize {
        DesktopSize {
            width: self.0,
            height: self.1,
        }
    }
    async fn updates(&mut self) -> ServerResult<Box<dyn RdpServerDisplayUpdates>> {
        Ok(Box::new(Never))
    }
}

struct Never;

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for Never {
    async fn next_update(&mut self) -> ServerResult<Option<DisplayUpdate>> {
        std::future::pending().await
    }
}

struct NoInput;

impl RdpServerInputHandler for NoInput {
    fn keyboard(&mut self, _: KeyboardEvent) {}
    fn mouse(&mut self, _: MouseEvent) {}
}

/// Tells the shipper a connection's EGFX is ready. IronRDP calls it with
/// the handle's lock held: it only sends on a channel.
struct Ready(mpsc::UnboundedSender<()>);

impl GraphicsPipelineHandler for Ready {
    fn capabilities_advertise(&mut self, _: &CapabilitiesAdvertisePdu) {}
    fn on_ready(&mut self, _: &CapabilitySet) {
        let _ = self.0.send(());
    }
    fn max_frames_in_flight(&self) -> u32 {
        MAX_IN_FLIGHT
    }
}

struct NullGfx {
    slot: Slot,
    ready: mpsc::UnboundedSender<()>,
}

impl ServerEventSender for NullGfx {
    fn set_sender(&mut self, _: mpsc::UnboundedSender<ServerEvent>) {}
}

impl GfxServerFactory for NullGfx {
    fn build_gfx_handler(&self) -> Box<dyn GraphicsPipelineHandler> {
        Box::new(Ready(self.ready.clone()))
    }
    fn build_server_with_handle(&self) -> Option<(GfxDvcBridge, GfxServerHandle)> {
        let handle: GfxServerHandle = Arc::new(Mutex::new(GraphicsPipelineServer::new(Box::new(
            Ready(self.ready.clone()),
        ))));
        *lock(&self.slot) = Some(handle.clone());
        Some((GfxDvcBridge::new(handle.clone()), handle))
    }
}

async fn serve(
    frames: Vec<(u64, Vec<u8>)>,
    size: (u16, u16),
    fps: u32,
    sent: SendLog,
    addr: std::sync::mpsc::Sender<Result<SocketAddr, String>>,
    stop: oneshot::Receiver<()>,
) {
    let (acceptor, public_key) = match tls() {
        Ok(t) => t,
        Err(e) => {
            let _ = addr.send(Err(e));
            return;
        }
    };
    let slot: Slot = Arc::default();
    let (ready_tx, ready_rx) = mpsc::unbounded_channel();
    // The bridge's own builder order (`rdp/server.rs`), NLA only; no
    // connection handler, so IronRDP admits every connection — right for
    // one client.
    let mut server = RdpServer::builder()
        .with_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .with_hybrid(acceptor, public_key)
        .with_input_handler(NoInput)
        .with_display_handler(Fixed(size.0, size.1))
        .with_gfx_factory(Some(Box::new(NullGfx {
            slot: slot.clone(),
            ready: ready_tx,
        })))
        .build();
    server.set_credentials(Some(Credentials {
        username: USER.to_owned(),
        password: NLA_PASSWORD.to_owned(),
        domain: None,
    }));
    let events = server.event_sender().clone();
    let (tx, rx) = oneshot::channel();
    let _ = events.send(ServerEvent::GetLocalAddr(tx));
    tokio::task::spawn_local(async move {
        let got = rx
            .await
            .ok()
            .flatten()
            .ok_or_else(|| "no local address".to_owned());
        let _ = addr.send(got);
    });
    tokio::task::spawn_local(ship(frames, size, fps, slot, ready_rx, events, sent));
    tokio::select! {
        r = server.run() => if let Err(e) = r { eprintln!("null bridge: {e:#}") },
        _ = stop => {}
    }
}

/// Hands one batch to IronRDP's server loop, which writes it.
fn hand_off(
    events: &mpsc::UnboundedSender<ServerEvent>,
    channel_id: u32,
    msgs: Vec<DvcMessage>,
) -> Result<(), Unsent> {
    if msgs.is_empty() {
        return Ok(());
    }
    let svc = encode_dvc_messages(channel_id, msgs, ChannelFlags::SHOW_PROTOCOL)
        .map_err(|_| Unsent::Refused)?;
    events
        .send(ServerEvent::Egfx(EgfxServerMessage::send_messages(svc)))
        .map_err(|_| Unsent::Gone)
}

/// Why a frame was not sent.
enum Unsent {
    /// IronRDP refused it (not ready, at its in-flight cap, or its DVC
    /// encoding failed): skipped, as kvm-sim's schedule never catches up.
    Refused,
    /// The server is gone.
    Gone,
}

/// Per ready connection: the bridge's Setup (§6.4: ResetGraphics with one
/// primary monitor, CreateSurface, MapSurfaceToOutput), then one AU every
/// 1/fps from frame 0 (the source's first IDR). Each frame's send — from
/// `send_avc420_frame` to the hand-off to IronRDP's event queue — runs
/// inside `SendLog::send`, stamped before it starts.
async fn ship(
    frames: Vec<(u64, Vec<u8>)>,
    (w, h): (u16, u16),
    fps: u32,
    slot: Slot,
    mut ready: mpsc::UnboundedReceiver<()>,
    events: mpsc::UnboundedSender<ServerEvent>,
    sent: SendLog,
) {
    let region = [Avc420Region::full_frame(w, h, REGION_QP)];
    while ready.recv().await.is_some() {
        let Some(handle) = lock(&slot).clone() else {
            continue;
        };
        let setup = {
            let mut g = lock(&handle);
            let monitor = Monitor {
                left: 0,
                top: 0,
                right: i32::from(w) - 1,
                bottom: i32::from(h) - 1,
                flags: MonitorFlags::PRIMARY,
            };
            g.resize_with_monitors(w, h, vec![monitor]);
            let sid = g
                .create_surface(w, h)
                .filter(|s| g.map_surface_to_output(*s, 0, 0));
            g.set_max_frames_in_flight(MAX_IN_FLIGHT);
            (sid, g.channel_id(), g.drain_output())
        };
        let (Some(sid), Some(cid), msgs) = setup else {
            continue;
        };
        if let Err(Unsent::Gone) = hand_off(&events, cid, msgs) {
            return;
        }
        let mut tick = tokio::time::interval(Duration::from_secs(1) / fps);
        // kvm-sim's schedule (encoder.rs): a late tick is skipped, never
        // caught up in a burst — §10.1's "on the same schedule" (E71).
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let t0 = Instant::now();
        for (id, annexb) in frames.iter().cycle() {
            tick.tick().await;
            if !ready.is_empty() {
                break; // a new connection: set it up
            }
            let ts = u32::try_from(t0.elapsed().as_millis()).unwrap_or(u32::MAX);
            let shipped = sent.send(*id, || {
                let msgs = {
                    let mut g = lock(&handle);
                    g.send_avc420_frame(sid, annexb, &region, ts)
                        .ok_or(Unsent::Refused)?;
                    g.drain_output()
                };
                hand_off(&events, cid, msgs)
            });
            if let Err(Unsent::Gone) = shipped {
                return;
            }
        }
    }
}
