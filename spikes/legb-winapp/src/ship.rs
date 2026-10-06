use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use ironrdp_dvc::encode_dvc_messages;
use ironrdp_egfx::pdu::{Avc420Region, PixelFormat};
use ironrdp_pdu::gcc::{Monitor, MonitorFlags};
use ironrdp_server::{EgfxServerMessage, ServerEvent};
use ironrdp_svc::ChannelFlags;

use crate::gfx::Gfx;
use crate::replay::AccessUnit;

pub enum ShipCmd {
    Resize(u16, u16),
    Strand,
    Resume,
}

pub async fn run_ship(
    gfx: Gfx,
    aus: Vec<AccessUnit>,
    mut w: u16,
    mut h: u16,
    hard_cap: u32,
    rtt_handle: Arc<AtomicU32>,
    mut cmd_rx: tokio::sync::mpsc::Receiver<ShipCmd>,
) {
    // Wait for the connection to become AVC420-ready.
    let (handle, _avc, _sid) = loop {
        if let Some(s) = gfx.snapshot() {
            break s;
        }
        if let Ok(cmd) = cmd_rx.try_recv() {
            drain_cmd(cmd); // discard pre-ready commands
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    let sender = match gfx.sender() {
        Some(s) => s,
        None => {
            tracing::error!("LEGB_SHIP: no server-event sender");
            return;
        }
    };

    // ---- Setup (spec §6.4): resize_with_monitors -> create_surface -> map ----
    if let Err(e) = setup(&gfx, &handle, &sender, w, h, hard_cap) {
        tracing::error!(error = %e, "LEGB_SHIP: setup failed");
        return;
    }

    let epoch = Instant::now();
    let frame_dt = Duration::from_millis(1000 / 30); // fixture cadence (30 fps)
    let mut stranded = false;
    let mut rtt_tick = Instant::now();

    loop {
        for au in &aus {
            // Drain stdin-driven census commands between frames.
            while let Ok(cmd) = cmd_rx.try_recv() {
                match cmd {
                    ShipCmd::Strand => {
                        stranded = true;
                        tracing::warn!(
                            "LEGB_SHIP: STRAND — stopped sending (observe last-frame hold)"
                        );
                    }
                    ShipCmd::Resume => {
                        stranded = false;
                        tracing::warn!("LEGB_SHIP: RESUME");
                    }
                    ShipCmd::Resize(nw, nh) => {
                        w = nw;
                        h = nh;
                        tracing::warn!(
                            nw,
                            nh,
                            "LEGB_SHIP: server-initiated RESIZE (§6.4 Setup cause)"
                        );
                        if let Err(e) = setup(&gfx, &handle, &sender, w, h, hard_cap) {
                            tracing::error!(error = %e, "LEGB_SHIP: re-setup failed");
                        }
                    }
                }
            }

            // Periodic auto-detect probe + log whether the client answers.
            if rtt_tick.elapsed() >= Duration::from_millis(250) {
                let _ = sender.send(ServerEvent::AutoDetectRttRequest);
                let rtt = rtt_handle.load(Ordering::Relaxed);
                tracing::info!(
                    rtt_ms = rtt,
                    autodetect_answered = (rtt != u32::MAX),
                    "LEGB_AUTODETECT probe"
                );
                rtt_tick = Instant::now();
            }

            if !stranded {
                if let Err(e) = ship_one(&gfx, &handle, &sender, au, w, h, &epoch) {
                    tracing::error!(error = %e, "LEGB_SHIP: ship failed");
                }
            }
            tokio::time::sleep(frame_dt).await;
        }
    }
}

fn setup(
    gfx: &Gfx,
    handle: &ironrdp_server::GfxServerHandle,
    sender: &tokio::sync::mpsc::UnboundedSender<ServerEvent>,
    w: u16,
    h: u16,
    hard_cap: u32,
) -> anyhow::Result<()> {
    let (dvc, chan) = {
        let mut server = handle.lock().expect("gfx handle");
        server.set_output_dimensions(w, h);
        // Explicit single-monitor PRIMARY layout, inclusive bounds (spec §6.4).
        let monitor = Monitor {
            left: 0,
            top: 0,
            right: i32::from(w).saturating_sub(1),
            bottom: i32::from(h).saturating_sub(1),
            flags: MonitorFlags::PRIMARY,
        };
        server.resize_with_monitors(w, h, vec![monitor]);
        let sid = server
            .create_surface_with_format(w, h, PixelFormat::XRgb)
            .ok_or_else(|| anyhow::anyhow!("create_surface failed (not ready?)"))?;
        anyhow::ensure!(
            server.map_surface_to_output(sid, 0, 0),
            "map_surface_to_output failed"
        );
        server.set_max_frames_in_flight(hard_cap);
        gfx.set_surface(sid);
        let chan = server
            .channel_id()
            .ok_or_else(|| anyhow::anyhow!("no EGFX channel id"))?;
        (server.drain_output(), chan)
    };
    if !dvc.is_empty() {
        let msgs = encode_dvc_messages(chan, dvc, ChannelFlags::SHOW_PROTOCOL)?;
        sender
            .send(ServerEvent::Egfx(EgfxServerMessage::SendMessages {
                messages: msgs,
            }))
            .map_err(|_| anyhow::anyhow!("event loop closed"))?;
    }
    tracing::info!(
        w,
        h,
        hard_cap,
        "LEGB_SHIP: Setup emitted (ResetGraphics+CreateSurface+Map)"
    );
    Ok(())
}

fn ship_one(
    gfx: &Gfx,
    handle: &ironrdp_server::GfxServerHandle,
    sender: &tokio::sync::mpsc::UnboundedSender<ServerEvent>,
    au: &AccessUnit,
    w: u16,
    h: u16,
    epoch: &Instant,
) -> anyhow::Result<()> {
    let (dvc, chan, sid) = {
        let mut server = handle.lock().expect("gfx handle");
        let sid = match gfx.snapshot().and_then(|(_, _, s)| s) {
            Some(s) => s,
            None => return Ok(()), // no surface yet
        };
        let region = Avc420Region::full_frame(w, h, crate::cfg::REGION_QP);
        let ts = u32::try_from(epoch.elapsed().as_millis() % u128::from(u32::MAX)).unwrap_or(0);
        let sent = server.send_avc420_frame(sid, &au.annex_b, &[region], ts);
        match sent {
            Some(id) if au.is_idr => tracing::info!(frame_id = id, "LEGB_SHIP shipped IDR"),
            Some(id) => tracing::trace!(frame_id = id, "LEGB_SHIP shipped P"),
            None => tracing::warn!(idr = au.is_idr, "LEGB_SHIP send_avc420_frame returned None"),
        }
        let chan = server
            .channel_id()
            .ok_or_else(|| anyhow::anyhow!("no EGFX channel id"))?;
        (server.drain_output(), chan, sid)
    };
    let _ = sid;
    if dvc.is_empty() {
        return Ok(());
    }
    let msgs = encode_dvc_messages(chan, dvc, ChannelFlags::SHOW_PROTOCOL)?;
    sender
        .send(ServerEvent::Egfx(EgfxServerMessage::SendMessages {
            messages: msgs,
        }))
        .map_err(|_| anyhow::anyhow!("event loop closed"))?;
    Ok(())
}

fn drain_cmd(_c: ShipCmd) {}
