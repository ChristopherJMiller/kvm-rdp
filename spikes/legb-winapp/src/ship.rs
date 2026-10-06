use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use ironrdp_dvc::encode_dvc_messages;
use ironrdp_egfx::pdu::{Avc420Region, PixelFormat};
use ironrdp_pdu::gcc::{Monitor, MonitorFlags};
use ironrdp_server::{EgfxServerMessage, ServerEvent};
use ironrdp_svc::ChannelFlags;

use crate::display::DisplayCtl;
use crate::gfx::Gfx;
use crate::replay::AccessUnit;

pub enum ShipCmd {
    /// The real resize path (spec §6.4): `DisplayUpdate::Resize` on the
    /// current display-updates stream, wait for reactivation, Setup at the
    /// new size, then switch the replayed stream to `resize_to`'s fixture
    /// (passed into `run_ship`, not carried on the command itself — there is
    /// only one second-size fixture configured per run).
    Resize,
    /// The old path, kept for comparison: a channel-level Setup swap with no
    /// resize/reactivation and no stream switch (what Task 5's `resize`
    /// command did; the research saw it blink on Windows App).
    ResizeChannel(u16, u16),
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
    ctl: DisplayCtl,
    resize_to: Option<(Vec<AccessUnit>, u16, u16)>,
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
    // Absolute pacing clock (tokio's, so `sleep_until` can target it
    // directly) — kept separate from `epoch` above, which stamps the
    // wire-visible AU timestamp and has no reason to share a clock type
    // with the scheduler.
    let sched_epoch = tokio::time::Instant::now();
    // Exact 30fps (matches the fixtures' real `rate=30` encode,
    // scripts/gen-fixtures.sh), not `Duration::from_millis(1000 / 30)`
    // (33ms, truncated from 33.33ms — drifts low over a long run).
    let frame_dt = Duration::from_secs_f64(1.0 / 30.0);
    let mut stranded = false;
    let mut rtt_tick = Instant::now();
    // Index-based replay so the stream itself can be switched (the real
    // resize path hands `ShipCmd::Resize` a different fixture once the
    // reactivation completes): `current` is the AU list in flight, `i` the
    // index into it.
    let mut current = aus;
    let mut resize_to = resize_to;
    let mut i: usize = 0;
    // Frame index into the absolute schedule `sched_epoch + frame_idx *
    // frame_dt`: ticks every loop iteration regardless of `stranded`, so
    // pacing tracks wall-clock time instead of accumulating drift from
    // per-iteration `sleep(frame_dt)` calls that each start after a
    // variable amount of per-frame work. The end-of-loop step below detects
    // when a slot has already passed — e.g. the `Resize` branch can block
    // on reactivation for up to 10s — and skips forward to the next FUTURE
    // slot instead of letting `sleep_until` return immediately and firing a
    // burst of catch-up frames; see the end of the loop for the skip log.
    let mut frame_idx: u32 = 0;

    loop {
        // Drain stdin-driven census commands between frames.
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                ShipCmd::Strand => {
                    stranded = true;
                    tracing::warn!("LEGB_SHIP: STRAND — stopped sending (observe last-frame hold)");
                }
                ShipCmd::Resume => {
                    stranded = false;
                    tracing::warn!("LEGB_SHIP: RESUME");
                }
                ShipCmd::ResizeChannel(nw, nh) => {
                    // Old path, kept for comparison: channel-level re-Setup, same stream.
                    let t0 = Instant::now();
                    w = nw;
                    h = nh;
                    tracing::warn!(
                        nw,
                        nh,
                        "LEGB_SHIP: RESIZE-CHANNEL (channel-only Setup, same stream)"
                    );
                    if let Err(e) = setup(&gfx, &handle, &sender, w, h, hard_cap) {
                        tracing::error!(error = %e, "LEGB_SHIP: re-setup failed");
                    }
                    // Fix round 1 (a): same direct picture-return-time log as
                    // the real `Resize` path, anchored on this branch's own
                    // "emitted" instant. The next frame shipped (same stream,
                    // new size) is whichever one the watch captures.
                    gfx.arm_resize_watch("resize-channel", t0);
                }
                ShipCmd::Resize => {
                    let Some((next, nw, nh)) = resize_to.take() else {
                        tracing::error!("LEGB_SHIP: RESIZE needs LEGB_FIXTURE_RESIZE");
                        continue;
                    };
                    let t0 = Instant::now();
                    let before = ctl.updates_calls();
                    ctl.set_size(nw, nh);
                    if !ctl.send_resize(nw, nh) {
                        tracing::error!("LEGB_SHIP: no updates stream to send Resize on");
                        continue;
                    }
                    tracing::warn!(
                        nw,
                        nh,
                        "LEGB_SHIP: RESIZE emitted (DisplayUpdate::Resize); awaiting reactivation"
                    );
                    let deadline = Instant::now() + Duration::from_secs(10);
                    while ctl.updates_calls() == before && Instant::now() < deadline {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    tracing::warn!(
                        reactivated = ctl.updates_calls() != before,
                        ms = t0.elapsed().as_millis(),
                        "LEGB_SHIP: reactivation"
                    );
                    w = nw;
                    h = nh;
                    if let Err(e) = setup(&gfx, &handle, &sender, w, h, hard_cap) {
                        tracing::error!(error = %e, "LEGB_SHIP: post-resize setup failed");
                    }
                    current = next;
                    i = current.iter().position(|au| au.is_idr).unwrap_or(0);
                    tracing::warn!(
                        ms = t0.elapsed().as_millis(),
                        "LEGB_SHIP: new-size stream starts at IDR"
                    );
                    // Fix round 1 (a): arm the picture-return-time watch now
                    // — the very next frame shipped is the new-size stream's
                    // first IDR, and its ack is what closes the measurement
                    // (`t0` is this branch's "RESIZE emitted" instant).
                    gfx.arm_resize_watch("resize", t0);
                    // No explicit pacing resync here: the end-of-loop step
                    // below (shared with every other source of lateness —
                    // a stall, STRAND/RESUME) detects that the schedule has
                    // fallen behind `now` and skips forward to the next
                    // future slot rather than bursting, logging how many
                    // slots were skipped.
                }
            }
        }

        // Periodic auto-detect probe + log whether the client answers.
        if rtt_tick.elapsed() >= Duration::from_millis(250) {
            let _ = sender.send(ServerEvent::AutoDetectRttRequest);
            let rtt = rtt_handle.load(Ordering::Relaxed);
            let answered = rtt != u32::MAX;
            // I2: `rtt_ms` is only meaningful when the client actually
            // answered — the `u32::MAX` sentinel is not a millisecond
            // value, so it must never appear under a field literally
            // named `rtt_ms` (a naive downstream aggregation that
            // forgets to filter on `autodetect_answered` would average
            // in 4294967295).
            if answered {
                tracing::info!(
                    rtt_ms = rtt,
                    autodetect_answered = true,
                    "LEGB_AUTODETECT probe"
                );
            } else {
                tracing::info!(autodetect_answered = false, "LEGB_AUTODETECT probe");
            }
            rtt_tick = Instant::now();
        }

        if !stranded {
            if let Some(au) = current.get(i % current.len().max(1)) {
                if let Err(e) = ship_one(&gfx, &handle, &sender, au, w, h, &epoch) {
                    tracing::error!(error = %e, "LEGB_SHIP: ship failed");
                }
            }
            i = i.wrapping_add(1);
        }

        // Advance to the next absolute slot, skipping forward over any slot
        // already in the past (minor fix, carried from B15's re-review: no
        // catch-up burst after a stall, STRAND/RESUME, or a resize — this
        // loop ships at most one frame per iteration no matter how far
        // behind the schedule fell).
        frame_idx += 1;
        let mut target = sched_epoch + frame_dt * frame_idx;
        let now = tokio::time::Instant::now();
        if target <= now {
            let elapsed = now.saturating_duration_since(sched_epoch);
            let behind = (elapsed.as_secs_f64() / frame_dt.as_secs_f64()).floor() as u32 + 1;
            let skipped = behind.saturating_sub(frame_idx);
            if skipped > 0 {
                tracing::warn!(
                    skipped,
                    "LEGB_SHIP: pacing fell behind schedule, skipped frame slot(s) (no catch-up burst)"
                );
            }
            frame_idx = behind;
            target = sched_epoch + frame_dt * frame_idx;
        }
        tokio::time::sleep_until(target).await;
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
    let (dvc, chan, sid, sent) = {
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
        (server.drain_output(), chan, sid, sent)
    };
    let _ = sid;
    // Outside the `handle` lock (fix round 1 (a)): tell the resize-ack
    // watch, if armed, which frame_id to wait for. `note_shipped_frame`
    // only ever locks `gfx`'s own `ctx` mutex, never `handle` — no nesting
    // with the block above.
    if let Some(id) = sent {
        gfx.note_shipped_frame(id);
    }
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
