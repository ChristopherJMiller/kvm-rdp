//! EGFX for each served connection (§4.3, DC4). IronRDP calls
//! `build_server_with_handle` once per served connection, and always before
//! that connection's `on_connection_info`: for a fresh connection in
//! `attach_channels`, before auth; for a Preempt winner in
//! `serve_negotiated`, after CredSSP (IronRDP builds a takeover candidate's
//! channels only once it has authenticated). Either way the factory
//! records `(slot, handle)` and `on_connection_info` takes the latest. The
//! callbacks run inside `GraphicsPipelineServer` with its mutex held: they
//! only push `RdpInput`s tagged with their slot, or bump a metric.
use crate::metrics::Metrics;
use crate::msg::{Cause, Gen, Generations, RdpInput};
use crate::pump::Input;
use ironrdp_egfx::pdu::{CapabilitiesAdvertisePdu, CapabilitySet};
use ironrdp_egfx::server::{GraphicsPipelineHandler, GraphicsPipelineServer, QoeMetrics};
use ironrdp_server::{
    GfxDvcBridge, GfxServerFactory, GfxServerHandle, ServerEvent, ServerEventSender,
};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;

/// The latest connection's EGFX handle and its slot.
pub type GfxSlot = Arc<Mutex<Option<(u64, GfxServerHandle)>>>;

pub struct GfxFactory {
    latest: GfxSlot,
    next_slot: AtomicU64,
    tx: UnboundedSender<RdpInput>,
    hard_cap: u32,
    metrics: Arc<Metrics>,
}

impl GfxFactory {
    #[must_use]
    pub fn new(
        latest: GfxSlot,
        tx: UnboundedSender<RdpInput>,
        hard_cap: u32,
        metrics: Arc<Metrics>,
    ) -> GfxFactory {
        GfxFactory {
            latest,
            next_slot: AtomicU64::new(0),
            tx,
            hard_cap,
            metrics,
        }
    }

    fn callbacks(&self, slot: u64) -> Box<dyn GraphicsPipelineHandler> {
        Box::new(GfxCallbacks {
            slot,
            tx: self.tx.clone(),
            hard_cap: self.hard_cap,
            metrics: self.metrics.clone(),
        })
    }
}

/// `on_connection_info`: take the handle built for this connection.
#[must_use]
pub fn take_latest(slot: &GfxSlot) -> Option<(u64, GfxServerHandle)> {
    slot.lock().unwrap_or_else(PoisonError::into_inner).take()
}

/// What the pump shell steps for an `RdpInput::GfxClosed` from its current
/// link's slot (PC11 n2), given that link's generation.
///
/// A client that closes its EGFX channel mid-session leaves IronRDP's
/// `GraphicsPipelineServer` `Closed` for good — IronRDP opens the channel
/// once per connection and never again — so no picture can follow. Without
/// this the pump would learn it only at its next Setup (which IronRDP then
/// refuses, m7) and could sit in NeedIdr until a resize. The core closes at
/// once with m7's cause, `no_avc420`, through the core input that closes a
/// session with a given cause (`UpstreamFatal`; no new core input).
///
/// `None` once the generation has ended. On its normal paths IronRDP drops
/// a connection's channels — which runs `on_close` — just before
/// `on_disconnected`, with no await between (`RdpServer::run`,
/// server.rs:2985 → 2988; `run_connection_with`, :2430), and the shell
/// shares that thread, so a teardown's close reads as stale here and a
/// mid-session close as current.
///
/// One window is accepted (PC13 review m1). A session that ends during a
/// Deactivation-Reactivation has its channels in the reactivation acceptor
/// (server.rs:5020-5024), dropped as the connection future completes; if a
/// Preempt candidate is negotiating, `run()` then awaits up to
/// `CANDIDATE_HANDOFF_GRACE` (750 ms, server.rs:2771-2777) before :2985 and
/// :2988. The shell can read that close while the generation is still
/// current and close an already-ending session as `no_avc420`: one
/// miscounted `disconnects{no_avc420}` and a log line. IronRDP discards
/// the stale `Disconnect` event before the next connection, and the late
/// abort reaches a per-connection `Notify` nobody waits on.
#[must_use]
pub fn closed_channel_input(gens: &Generations, generation: Gen) -> Option<Input> {
    gens.is_current(generation)
        .then_some(Input::UpstreamFatal(Cause::NoAvc420))
}

impl ServerEventSender for GfxFactory {
    fn set_sender(&mut self, _sender: UnboundedSender<ServerEvent>) {}
}

impl GfxServerFactory for GfxFactory {
    /// Unused while `build_server_with_handle` always answers; slot 0 never
    /// matches a session, so the pump drops its callbacks.
    fn build_gfx_handler(&self) -> Box<dyn GraphicsPipelineHandler> {
        self.callbacks(0)
    }

    fn build_server_with_handle(&self) -> Option<(GfxDvcBridge, GfxServerHandle)> {
        let slot = self
            .next_slot
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1)
            .max(1);
        let handle: GfxServerHandle = Arc::new(Mutex::new(GraphicsPipelineServer::new(
            self.callbacks(slot),
        )));
        *self.latest.lock().unwrap_or_else(PoisonError::into_inner) = Some((slot, handle.clone()));
        Some((GfxDvcBridge::new(handle.clone()), handle))
    }
}

/// `version:data` in hex, the census's notation; bounded, because the
/// client chose it (the `no_avc420` log line, §6.7).
#[must_use]
pub fn caps_hex(pdu: &CapabilitiesAdvertisePdu) -> Vec<String> {
    pdu.0
        .iter()
        .take(32)
        .map(|s| {
            let mut out = format!("{:08x}:", s.version.0);
            for b in s.data.iter().take(64) {
                let _ = write!(out, "{b:02x}");
            }
            out
        })
        .collect()
}

struct GfxCallbacks {
    slot: u64,
    tx: UnboundedSender<RdpInput>,
    hard_cap: u32,
    metrics: Arc<Metrics>,
}

impl GraphicsPipelineHandler for GfxCallbacks {
    fn capabilities_advertise(&mut self, pdu: &CapabilitiesAdvertisePdu) {
        let _ = self.tx.send(RdpInput::CapsAdvertised {
            slot: self.slot,
            sets: caps_hex(pdu),
        });
    }

    fn on_ready(&mut self, negotiated: &CapabilitySet) {
        let _ = self.tx.send(RdpInput::OnReady {
            slot: self.slot,
            version: negotiated.version().0,
        });
    }

    fn on_frame_ack(&mut self, frame_id: u32, queue_depth: u32, _total_frames_decoded: u32) {
        let _ = self.tx.send(RdpInput::FrameAck {
            slot: self.slot,
            frame_id,
            queue_depth,
        });
    }

    /// §10.4 QoE decode time (V10+ clients). MS-RDPEGFX's QoE frame
    /// acknowledgement gives `timeDiffEDR` in milliseconds (IronRDP's doc
    /// comment says µs; the wire value is the client's). A metric only —
    /// atomics, no lock, no generation needed (a Preempt candidate's sample
    /// is harmless).
    fn on_qoe_metrics(&mut self, m: QoeMetrics) {
        self.metrics
            .qoe_decode
            .observe(Duration::from_millis(u64::from(m.time_diff_dr)));
    }

    /// PC11 n2: the channel closed — a client's DVC Close, or the
    /// connection's teardown (`closed_channel_input` tells them apart).
    fn on_close(&mut self) {
        tracing::debug!(slot = self.slot, "EGFX channel closed");
        let _ = self.tx.send(RdpInput::GfxClosed { slot: self.slot });
    }

    fn max_frames_in_flight(&self) -> u32 {
        self.hard_cap
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]
    use super::*;
    use ironrdp_egfx::pdu::{CapabilityVersion, RawCapabilitySet};

    /// m4: the client chooses the advertise, and `caps_hex` feeds a log
    /// line, so the notation is bounded: at most 32 sets, each at most 64
    /// data bytes (`version:` — 9 characters — plus 128 hex digits).
    #[test]
    fn caps_hex_is_bounded_however_much_the_client_advertises() {
        let sets = (0..40u32)
            .map(|i| RawCapabilitySet::new(CapabilityVersion(0x8_0000 + i), vec![0xAB; 100]))
            .collect();
        let hex = caps_hex(&CapabilitiesAdvertisePdu(sets));
        assert_eq!(hex.len(), 32);
        for (i, s) in (0u32..).zip(&hex) {
            assert_eq!(s.len(), 9 + 128, "{s}");
            assert!(s.starts_with(&format!("{:08x}:abab", 0x8_0000 + i)), "{s}");
        }
    }
}
