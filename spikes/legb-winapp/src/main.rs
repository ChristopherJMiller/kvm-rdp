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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // One crypto provider, aws-lc-rs, installed idempotently (spec §4.2).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,legb_winapp=debug")),
        )
        .init();

    tracing::info!("legb-winapp spike starting (placeholder main — wired up in later tasks)");
    Ok(())
}
