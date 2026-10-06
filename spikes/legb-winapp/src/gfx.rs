use std::sync::{Arc, Mutex};

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
        let avc = caps_indicate_avc(negotiated);
        if let Some(c) = self.ctx.lock().expect("ctx mutex").as_mut() {
            c.ready = true;
            c.avc420 = avc;
            c.ready_count += 1;
            let is_readvertise = c.ready_count > 1;
            // Confirm against the server's own view too.
            let server_avc = c.handle.lock().expect("gfx handle").supports_avc420();
            tracing::info!(
                confirmed = ?negotiated,
                confirmed_has_avc = avc,
                server_supports_avc420 = server_avc,
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

/// Positive AVC420 signal only (mirrors macrdp's verified `caps_indicate_avc`).
fn caps_indicate_avc(c: &CapabilitySet) -> bool {
    match c {
        CapabilitySet::V8_1 { flags } => flags.contains(CapabilitiesV81Flags::AVC420_ENABLED),
        CapabilitySet::V10 { flags } | CapabilitySet::V10_2 { flags } => {
            !flags.contains(CapabilitiesV10Flags::AVC_DISABLED)
        }
        CapabilitySet::V10_3 { flags } => !flags.contains(CapabilitiesV103Flags::AVC_DISABLED),
        CapabilitySet::V10_4 { flags }
        | CapabilitySet::V10_5 { flags }
        | CapabilitySet::V10_6 { flags }
        | CapabilitySet::V10_6Err { flags } => !flags.contains(CapabilitiesV104Flags::AVC_DISABLED),
        CapabilitySet::V10_7 { flags } => !flags.contains(CapabilitiesV107Flags::AVC_DISABLED),
        CapabilitySet::V8 { .. } | CapabilitySet::V10_1 => false,
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
