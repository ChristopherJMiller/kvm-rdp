//! THROWAWAY Milestone-0 Leg B spike: stock IronRDP HEAD (38b074e) vs Microsoft
//! Windows App. Replays a committed Annex-B fixture over EGFX AVC420 with
//! Hybrid/NLA. Logs every capability set, the confirmed set, every frame ack,
//! QoE, re-advertises and whether auto-detect is negotiated. NOT production code.

mod cfg {
    pub const RDP_LISTEN: &str = "0.0.0.0:3389";
    pub const NLA_USERNAME: &str = "kvm"; // must equal rdpgw's pre-filled username (Leg C)
    pub const NLA_PASSWORD: &str = "legb-spike-pw"; // throwaway; NLA needs it recoverable
    pub const FIXTURE_ENV: &str = "LEGB_FIXTURE"; // path to a committed Annex-B .h264 stream
    pub const HARD_CAP: u32 = 120; // ceil(2s * 60fps); static memory backstop (spec §6.6)
    pub const REGION_QP: u8 = 22; // spec §6.3 video.region_qp
}

mod display;
mod gfx;
mod replay;
mod ship;
mod tls;

use std::net::SocketAddr;
use std::time::Duration;

use ironrdp_server::{
    ConnectionHandler, ConnectionInfo, Credentials, PostConnectionAction, RdpServer, ServerError,
};

struct LogHandler;
impl ConnectionHandler for LogHandler {
    fn on_accept(&mut self, peer: std::net::SocketAddr) -> bool {
        tracing::info!(%peer, "LEGB_CONN on_accept");
        true
    }
    fn on_connection_info(&mut self, info: &ConnectionInfo) {
        tracing::info!(
            keyboard_layout = info.keyboard_layout,
            keyboard_type = ?info.keyboard_type,
            "LEGB_CONN on_connection_info"
        );
    }
    fn on_disconnected(
        &mut self,
        peer: std::net::SocketAddr,
        duration: Duration,
        error: Option<&ServerError>,
    ) -> PostConnectionAction {
        tracing::warn!(%peer, ?duration, error = ?error.map(|e| e.to_string()), "LEGB_CONN on_disconnected");
        PostConnectionAction::Continue
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // One crypto provider, aws-lc-rs, installed idempotently (spec §4.2).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                // `ironrdp_egfx=debug` surfaces IronRDP's own FrameAcknowledge
                // log (ironrdp-egfx/src/server.rs:2118-2130), which carries
                // `latency_us` computed from the library's own internal
                // `sent_at` Instant — a more precise ack-latency figure than
                // reconstructing it by correlating LEGB_SHIP/LEGB_ACK
                // timestamps by frame_id (I1).
                tracing_subscriber::EnvFilter::new("info,legb_winapp=debug,ironrdp_egfx=debug")
            }),
        )
        .init();

    let fixture = std::env::var(cfg::FIXTURE_ENV)
        .map_err(|_| anyhow::anyhow!("set {} to a committed Annex-B fixture", cfg::FIXTURE_ENV))?;
    let aus = replay::load_fixture(std::path::Path::new(&fixture))?;
    tracing::info!(fixture = %fixture, aus = aus.len(), "LEGB loaded fixture");

    // Dimensions: 1920x1080 default; override with LEGB_W/LEGB_H for a resize fixture.
    let w: u16 = std::env::var("LEGB_W")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1920);
    let h: u16 = std::env::var("LEGB_H")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1080);

    let tls = tls::self_signed("kvm-bridge.spike")?;
    let gfx = gfx::Gfx::new(cfg::HARD_CAP);
    let ctl = display::DisplayCtl::new(w, h);

    let addr: SocketAddr = cfg::RDP_LISTEN.parse()?;
    let mut server = RdpServer::builder()
        .with_addr(addr)
        .with_hybrid(tls.acceptor, tls.spki_pub_key)
        .with_input_handler(display::SpikeInput)
        .with_display_handler(display::SpikeDisplay { ctl: ctl.clone() })
        .with_gfx_factory(Some(Box::new(gfx.clone())))
        .with_connection_policy(ironrdp_server::ConnectionPolicy::Preempt)
        .with_connection_handler(Some(Box::new(LogHandler)))
        .build();

    server.set_credentials(Some(Credentials {
        username: cfg::NLA_USERNAME.to_owned(),
        password: cfg::NLA_PASSWORD.to_owned(),
        domain: None,
    }));
    server.enable_autodetect(); // RTT probes available if the client negotiates the channel

    let rtt_handle = server.autodetect_rtt_handle();

    // Target size for both resize paths. `resize` (the real path) pairs this
    // with LEGB_FIXTURE_RESIZE below; `resize-channel` (the old, channel-only
    // path, kept for comparison) uses the same size with no second fixture —
    // deviation from the brief's literal `ShipCmd::ResizeChannel(1280, 720)`
    // stdin mapping, which hardcoded the size inline: sharing LEGB_RESIZE_W/H
    // lets a census run configure one target size for both paths instead of
    // silently diverging if an operator only overrides one of them.
    let resize_w: u16 = std::env::var("LEGB_RESIZE_W")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1280);
    let resize_h: u16 = std::env::var("LEGB_RESIZE_H")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(720);

    // stdin command reader -> ship task.
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<ship::ShipCmd>(8);
    tokio::spawn(async move {
        use tokio::io::AsyncBufReadExt as _;
        let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let cmd = match line.trim() {
                "resize" => Some(ship::ShipCmd::Resize),
                "resize-channel" => Some(ship::ShipCmd::ResizeChannel(resize_w, resize_h)),
                "strand" => Some(ship::ShipCmd::Strand),
                "resume" => Some(ship::ShipCmd::Resume),
                other => {
                    tracing::warn!(%other, "unknown command (resize|resize-channel|strand|resume)");
                    None
                }
            };
            if let Some(c) = cmd {
                let _ = cmd_tx.send(c).await;
            }
        }
    });

    // The real resize path's second-size fixture (optional): `resize` on
    // stdin needs this set, or it logs an error and no-ops (ship.rs).
    let resize_to = match std::env::var("LEGB_FIXTURE_RESIZE") {
        Ok(p) => {
            let resize_aus = replay::load_fixture(std::path::Path::new(&p))?;
            tracing::info!(
                fixture = %p,
                aus = resize_aus.len(),
                w = resize_w,
                h = resize_h,
                "LEGB loaded resize fixture"
            );
            Some((resize_aus, resize_w, resize_h))
        }
        Err(_) => None,
    };

    tokio::spawn(ship::run_ship(
        gfx,
        aus,
        w,
        h,
        cfg::HARD_CAP,
        rtt_handle,
        cmd_rx,
        ctl.clone(),
        resize_to,
    ));

    tracing::info!(%addr, "LEGB listening (Hybrid/NLA, Preempt, autodetect on)");
    server.run().await?;
    Ok(())
}
