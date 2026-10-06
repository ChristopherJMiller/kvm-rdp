use std::sync::{Arc, Mutex};
use std::time::Instant;

use ironrdp_egfx::pdu::{
    CapabilitiesAdvertisePdu, CapabilitiesV8Flags, CapabilitiesV10Flags, CapabilitiesV81Flags,
    CapabilitiesV103Flags, CapabilitiesV104Flags, CapabilitiesV107Flags, CapabilitySet,
};
use ironrdp_egfx::server::{GraphicsPipelineHandler, GraphicsPipelineServer, QoeMetrics};
use ironrdp_server::{
    GfxDvcBridge, GfxServerFactory, GfxServerHandle, ServerEvent, ServerEventSender,
};
use tokio::sync::mpsc::UnboundedSender;

pub struct SpikeCtx {
    pub handle: GfxServerHandle,
    pub ready: bool,
    pub avc420: bool,
    pub ready_count: u32,
    pub surface_id: Option<u16>,
    pub resize_watch: Option<ResizeWatch>,
}

/// Fix round 1 (b): tracks one in-flight "picture return" measurement so
/// `on_frame_ack` can log `LEGB_RESIZE picture_return_ms` directly, instead
/// of leaving the census to correlate three separate log lines by hand.
/// Armed by `Gfx::arm_resize_watch` right after a resize (`resize` or
/// `resize-channel`) has re-run Setup; `frame_id` is filled in by
/// `Gfx::note_shipped_frame` on the first frame shipped afterward (whichever
/// stream that frame comes from — the switched one for `resize`, the same
/// one for `resize-channel`); `on_frame_ack` clears the watch once that
/// frame's ack arrives.
pub struct ResizeWatch {
    pub label: &'static str,
    pub t0: Instant,
    pub frame_id: Option<u32>,
}

#[derive(Clone)]
pub struct Gfx {
    hard_cap: u32,
    sender: Arc<Mutex<Option<UnboundedSender<ServerEvent>>>>,
    ctx: Arc<Mutex<Option<SpikeCtx>>>,
}

impl Gfx {
    pub fn new(hard_cap: u32) -> Self {
        Self {
            hard_cap,
            sender: Arc::new(Mutex::new(None)),
            ctx: Arc::new(Mutex::new(None)),
        }
    }

    pub fn sender(&self) -> Option<UnboundedSender<ServerEvent>> {
        self.sender.lock().expect("sender mutex").clone()
    }

    /// (handle, avc420-ready, surface_id) once on_ready has fired with AVC420.
    pub fn snapshot(&self) -> Option<(GfxServerHandle, bool, Option<u16>)> {
        let g = self.ctx.lock().expect("ctx mutex");
        g.as_ref()
            .filter(|c| c.ready && c.avc420)
            .map(|c| (c.handle.clone(), c.avc420, c.surface_id))
    }

    pub fn set_surface(&self, id: u16) {
        if let Some(c) = self.ctx.lock().expect("ctx mutex").as_mut() {
            c.surface_id = Some(id);
        }
    }

    /// Arm a picture-return-time watch: `on_frame_ack` will log
    /// `LEGB_RESIZE picture_return_ms` once the first frame shipped after
    /// this call is acknowledged. `label` distinguishes `"resize"` (the
    /// real path) from `"resize-channel"` (the old, channel-only path) in
    /// the log line.
    pub fn arm_resize_watch(&self, label: &'static str, t0: Instant) {
        if let Some(c) = self.ctx.lock().expect("ctx mutex").as_mut() {
            c.resize_watch = Some(ResizeWatch {
                label,
                t0,
                frame_id: None,
            });
        }
    }

    /// Called for every frame actually shipped. If a resize watch is armed
    /// and hasn't captured a frame yet, this is — by construction, since the
    /// caller arms the watch immediately before the next frame goes out —
    /// the one to wait for the ack of.
    pub fn note_shipped_frame(&self, frame_id: u32) {
        if let Some(c) = self.ctx.lock().expect("ctx mutex").as_mut() {
            if let Some(w) = c.resize_watch.as_mut() {
                if w.frame_id.is_none() {
                    w.frame_id = Some(frame_id);
                }
            }
        }
    }
}

impl ServerEventSender for Gfx {
    fn set_sender(&mut self, sender: UnboundedSender<ServerEvent>) {
        *self.sender.lock().expect("sender mutex") = Some(sender);
    }
}

impl GfxServerFactory for Gfx {
    fn build_gfx_handler(&self) -> Box<dyn GraphicsPipelineHandler> {
        // We override build_server_with_handle, so this is only a safety stub.
        Box::new(SpikeHandler {
            ctx: Arc::new(Mutex::new(None)),
            hard_cap: self.hard_cap,
        })
    }

    fn build_server_with_handle(&self) -> Option<(GfxDvcBridge, GfxServerHandle)> {
        let handler = Box::new(SpikeHandler {
            ctx: self.ctx.clone(),
            hard_cap: self.hard_cap,
        });
        let server = GraphicsPipelineServer::new(handler);
        let handle: GfxServerHandle = Arc::new(Mutex::new(server));
        *self.ctx.lock().expect("ctx mutex") = Some(SpikeCtx {
            handle: handle.clone(),
            ready: false,
            avc420: false,
            ready_count: 0,
            surface_id: None,
            resize_watch: None,
        });
        tracing::info!("EGFX: fresh GraphicsPipelineServer for new connection");
        Some((GfxDvcBridge::new(handle.clone()), handle))
    }
}

struct SpikeHandler {
    ctx: Arc<Mutex<Option<SpikeCtx>>>,
    hard_cap: u32,
}

impl GraphicsPipelineHandler for SpikeHandler {
    fn capabilities_advertise(&mut self, pdu: &CapabilitiesAdvertisePdu) {
        // pdu.0: Vec<RawCapabilitySet>. Log EACH raw set verbatim + parsed.
        for (i, raw) in pdu.0.iter().enumerate() {
            let parsed = raw.parsed().ok().flatten();
            tracing::info!(
                idx = i,
                version = ?raw.version,
                data_hex = %hex(&raw.data),
                parsed = ?parsed,
                "LEGB_CAP advertise entry"
            );
        }
        let avc = pdu
            .0
            .iter()
            .filter_map(|r| r.parsed().ok().flatten())
            .any(|c| caps_indicate_avc(&c));
        tracing::info!(
            count = pdu.0.len(),
            advertises_avc = avc,
            "LEGB_CAP advertise summary"
        );
    }

    fn on_ready(&mut self, negotiated: &CapabilitySet) {
        // C1 fix: do NOT lock `c.handle` in here. IronRDP invokes this
        // callback synchronously while it already holds that exact
        // GfxServerHandle mutex (GfxDvcBridge::process ->
        // GraphicsPipelineServer::process -> handle_capabilities_advertise ->
        // self.handler.on_ready — ironrdp-egfx/src/server.rs:2065,2107,
        // ironrdp-server/src/gfx.rs:76-81), all on one thread, under one
        // MutexGuard that only drops when `on_ready` returns. A second
        // `.lock()` here on that same, non-reentrant std::sync::Mutex
        // self-deadlocks on the very first successful negotiation — and
        // since the `ctx` lock is held across this whole block too,
        // `Gfx::snapshot()` (polled by `run_ship`'s readiness wait) wedges
        // right along with it. `avc` below is already authoritative:
        // `caps_indicate_avc` mirrors IronRDP's own
        // `CodecCapabilities::from_capability_set` exactly (see its doc
        // comment), so it agrees with what `supports_avc420()` would report
        // without re-entering the handle.
        let avc = caps_indicate_avc(negotiated);
        if let Some(c) = self.ctx.lock().expect("ctx mutex").as_mut() {
            c.ready = true;
            c.avc420 = avc;
            c.ready_count += 1;
            let is_readvertise = c.ready_count > 1;
            tracing::info!(
                confirmed = ?negotiated,
                confirmed_has_avc = avc,
                ready_count = c.ready_count,
                re_advertise = is_readvertise,
                "LEGB_READY on_ready (negotiated/confirmed capability set)"
            );
            if is_readvertise {
                // A re-advertise invalidates surfaces: force a fresh Setup.
                c.surface_id = None;
            }
        }
    }

    fn on_frame_ack(&mut self, frame_id: u32, queue_depth: u32, total_frames_decoded: u32) {
        let suspended = queue_depth == 0xFFFF_FFFF;
        tracing::info!(
            frame_id,
            queue_depth,
            suspended,
            total_frames_decoded,
            "LEGB_ACK on_frame_ack"
        );

        // Fix round 1 (a): if this ack matches the frame a resize watch is
        // waiting on, log the picture-return time as one line instead of
        // leaving the census to correlate "RESIZE emitted" / "new-size
        // stream starts at IDR" / "shipped IDR" / this ack by hand. Only
        // touches `ctx` (never `handle`), same as `on_ready` above — safe
        // under the same precondition (this callback runs under IronRDP's
        // own `handle` lock; C1).
        if let Some(c) = self.ctx.lock().expect("ctx mutex").as_mut() {
            let fire = c
                .resize_watch
                .as_ref()
                .is_some_and(|w| w.frame_id == Some(frame_id));
            if fire {
                let w = c.resize_watch.take().expect("checked Some above");
                tracing::warn!(
                    label = w.label,
                    frame_id,
                    picture_return_ms = w.t0.elapsed().as_millis(),
                    "LEGB_RESIZE picture_return_ms"
                );
            }
        }
    }

    fn on_qoe_metrics(&mut self, metrics: QoeMetrics) {
        tracing::info!(
            frame_id = metrics.frame_id,
            time_diff_se_us = metrics.time_diff_se,
            time_diff_dr_us = metrics.time_diff_dr,
            "LEGB_QOE on_qoe_metrics"
        );
    }

    /// Full capability ladder, pinned so the spike logs exactly what it offers
    /// (byte-identical to IronRDP HEAD's default at 38b074e — pinned on purpose).
    fn preferred_capabilities(&self) -> Vec<CapabilitySet> {
        vec![
            CapabilitySet::V10_7 {
                flags: CapabilitiesV107Flags::SMALL_CACHE,
            },
            CapabilitySet::V10_6Err {
                flags: CapabilitiesV104Flags::SMALL_CACHE,
            },
            CapabilitySet::V10_6 {
                flags: CapabilitiesV104Flags::SMALL_CACHE,
            },
            CapabilitySet::V10_5 {
                flags: CapabilitiesV104Flags::SMALL_CACHE,
            },
            CapabilitySet::V10_4 {
                flags: CapabilitiesV104Flags::SMALL_CACHE,
            },
            CapabilitySet::V10_3 {
                flags: CapabilitiesV103Flags::empty(),
            },
            CapabilitySet::V10_2 {
                flags: CapabilitiesV10Flags::SMALL_CACHE,
            },
            CapabilitySet::V10_1,
            CapabilitySet::V10 {
                flags: CapabilitiesV10Flags::SMALL_CACHE,
            },
            CapabilitySet::V8_1 {
                flags: CapabilitiesV81Flags::AVC420_ENABLED | CapabilitiesV81Flags::SMALL_CACHE,
            },
            CapabilitySet::V8 {
                flags: CapabilitiesV8Flags::SMALL_CACHE,
            },
        ]
    }

    fn max_frames_in_flight(&self) -> u32 {
        self.hard_cap
    }
}

/// AVC420 signal, kept byte-for-byte in agreement with IronRDP's own
/// `CodecCapabilities::from_capability_set`'s `avc420` field
/// (ironrdp-egfx/src/server.rs:730-779 at rev 38b074e). That function is
/// private to the `ironrdp-egfx` crate, so this mirrors its match arms
/// rather than calling it — in particular `V10_1` carries no flags at all,
/// and the library treats negotiating that version as unconditionally
/// AVC420/AVC444-capable (`avc420: true` there), NOT as "no signal" (C2:
/// an earlier version of this function wrongly matched V10_1 to `false`,
/// which would have silently stalled `run_ship`'s AVC420-ready wait on any
/// negotiation that landed on V10_1).
fn caps_indicate_avc(c: &CapabilitySet) -> bool {
    match c {
        CapabilitySet::V8 { .. } => false,
        CapabilitySet::V8_1 { flags } => flags.contains(CapabilitiesV81Flags::AVC420_ENABLED),
        CapabilitySet::V10 { flags } | CapabilitySet::V10_2 { flags } => {
            !flags.contains(CapabilitiesV10Flags::AVC_DISABLED)
        }
        CapabilitySet::V10_1 => true,
        CapabilitySet::V10_3 { flags } => !flags.contains(CapabilitiesV103Flags::AVC_DISABLED),
        CapabilitySet::V10_4 { flags }
        | CapabilitySet::V10_5 { flags }
        | CapabilitySet::V10_6 { flags }
        | CapabilitySet::V10_6Err { flags } => !flags.contains(CapabilitiesV104Flags::AVC_DISABLED),
        CapabilitySet::V10_7 { flags } => !flags.contains(CapabilitiesV107Flags::AVC_DISABLED),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    /// Every variant of `caps_indicate_avc`, cross-checked by hand against
    /// IronRDP's own `CodecCapabilities::from_capability_set` avc420 field
    /// (ironrdp-egfx/src/server.rs:730-779 at 38b074e) — the regression
    /// target for C2 (V10_1 must be `true`, not `false`).
    #[test]
    fn caps_indicate_avc_matches_ironrdp_codec_capabilities_for_every_version() {
        let cases: &[(CapabilitySet, bool)] = &[
            (
                CapabilitySet::V8 {
                    flags: CapabilitiesV8Flags::empty(),
                },
                false,
            ),
            (
                CapabilitySet::V8 {
                    flags: CapabilitiesV8Flags::SMALL_CACHE,
                },
                false,
            ),
            (
                CapabilitySet::V8_1 {
                    flags: CapabilitiesV81Flags::empty(),
                },
                false,
            ),
            (
                CapabilitySet::V8_1 {
                    flags: CapabilitiesV81Flags::AVC420_ENABLED,
                },
                true,
            ),
            (
                CapabilitySet::V10 {
                    flags: CapabilitiesV10Flags::empty(),
                },
                true,
            ),
            (
                CapabilitySet::V10 {
                    flags: CapabilitiesV10Flags::AVC_DISABLED,
                },
                false,
            ),
            (CapabilitySet::V10_1, true),
            (
                CapabilitySet::V10_2 {
                    flags: CapabilitiesV10Flags::empty(),
                },
                true,
            ),
            (
                CapabilitySet::V10_2 {
                    flags: CapabilitiesV10Flags::AVC_DISABLED,
                },
                false,
            ),
            (
                CapabilitySet::V10_3 {
                    flags: CapabilitiesV103Flags::empty(),
                },
                true,
            ),
            (
                CapabilitySet::V10_3 {
                    flags: CapabilitiesV103Flags::AVC_DISABLED,
                },
                false,
            ),
            (
                CapabilitySet::V10_4 {
                    flags: CapabilitiesV104Flags::empty(),
                },
                true,
            ),
            (
                CapabilitySet::V10_4 {
                    flags: CapabilitiesV104Flags::AVC_DISABLED,
                },
                false,
            ),
            (
                CapabilitySet::V10_5 {
                    flags: CapabilitiesV104Flags::empty(),
                },
                true,
            ),
            (
                CapabilitySet::V10_5 {
                    flags: CapabilitiesV104Flags::AVC_DISABLED,
                },
                false,
            ),
            (
                CapabilitySet::V10_6 {
                    flags: CapabilitiesV104Flags::empty(),
                },
                true,
            ),
            (
                CapabilitySet::V10_6 {
                    flags: CapabilitiesV104Flags::AVC_DISABLED,
                },
                false,
            ),
            (
                CapabilitySet::V10_6Err {
                    flags: CapabilitiesV104Flags::empty(),
                },
                true,
            ),
            (
                CapabilitySet::V10_6Err {
                    flags: CapabilitiesV104Flags::AVC_DISABLED,
                },
                false,
            ),
            (
                CapabilitySet::V10_7 {
                    flags: CapabilitiesV107Flags::empty(),
                },
                true,
            ),
            (
                CapabilitySet::V10_7 {
                    flags: CapabilitiesV107Flags::AVC_DISABLED,
                },
                false,
            ),
        ];
        for (cap, want) in cases {
            assert_eq!(
                caps_indicate_avc(cap),
                *want,
                "caps_indicate_avc({cap:?}) must be {want}"
            );
        }
    }

    /// Regression test for C1: the real IronRDP call path invokes
    /// `on_ready` while the caller already holds `handle`'s mutex
    /// (GfxDvcBridge::process -> GraphicsPipelineServer::process ->
    /// handle_capabilities_advertise -> handler.on_ready, all on one
    /// thread, under one guard). Reproduce that precondition — hold the
    /// lock here — then run `on_ready` on a second thread. A regression
    /// that re-locks `handle` inside `on_ready` blocks that thread for as
    /// long as this guard is held, so it never sends on `tx` in time and
    /// the `recv_timeout` below fails instead of hanging the whole suite.
    #[test]
    fn on_ready_does_not_relock_the_already_held_server_handle() {
        let inner_ctx = Arc::new(Mutex::new(None));
        let handle: GfxServerHandle = Arc::new(Mutex::new(GraphicsPipelineServer::new(Box::new(
            SpikeHandler {
                ctx: inner_ctx,
                hard_cap: 5,
            },
        ))));
        let ctx = Arc::new(Mutex::new(Some(SpikeCtx {
            handle: handle.clone(),
            ready: false,
            avc420: false,
            ready_count: 0,
            surface_id: None,
            resize_watch: None,
        })));
        let mut handler = SpikeHandler { ctx, hard_cap: 5 };

        let (tx, rx) = mpsc::channel();
        let outcome = {
            // Simulate the real call path: hold `handle`'s lock across the
            // whole `on_ready` call, exactly as IronRDP's own event loop does.
            let _guard = handle.lock().expect("gfx handle");
            std::thread::spawn(move || {
                handler.on_ready(&CapabilitySet::V10_1);
                let _ = tx.send(());
            });
            rx.recv_timeout(Duration::from_secs(2))
            // `_guard` drops here, after the recv attempt — releasing the
            // lock too early would let a buggy re-lock succeed and mask C1.
        };
        assert!(
            outcome.is_ok(),
            "on_ready did not return while the caller held `handle`'s lock — \
             it must not re-lock the server handle (C1)"
        );
    }
}
