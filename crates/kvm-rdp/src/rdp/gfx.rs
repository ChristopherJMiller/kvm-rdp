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
        let sets = caps_hex(pdu);
        // Once per client CapabilitiesAdvertise PDU (an authenticated client
        // may re-advertise); DEBUG, off at the default `info`; at most
        // ~4.4 KB (`caps_hex`). L3 reads FreeRDP's ladder from it (Plan E
        // Task 3.1, DC8). Client-chosen bytes, as hex: never text the
        // client typed.
        tracing::debug!(slot = self.slot, sets = %sets.join(","), "EGFX capabilities advertised");
        let _ = self.tx.send(RdpInput::CapsAdvertised {
            slot: self.slot,
            sets,
        });
    }

    fn on_ready(&mut self, negotiated: &CapabilitySet) {
        let _ = self.tx.send(RdpInput::OnReady {
            slot: self.slot,
            version: negotiated.version().0,
        });
    }

    fn on_frame_ack(&mut self, frame_id: u32, queue_depth: u32, total_frames_decoded: u32) {
        // §11.4 oracle 3: the client's own decode count (a metric only).
        self.metrics
            .egfx_client_frames_decoded
            .set(i64::from(total_frames_decoded));
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

    /// A `MakeWriter` into a shared buffer.
    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Buf {
            self.clone()
        }
    }

    /// Plan E Task 3.1 (§11.4 oracle 3, DE4): an ack sets the client's
    /// decode gauge; an advertise is logged at DEBUG in census notation
    /// (what L3 reads FreeRDP's ladder from) and still reaches the pump.
    #[test]
    fn an_ack_sets_the_decode_gauge_and_an_advertise_is_logged_at_debug() {
        let metrics = Arc::new(Metrics::default());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut cb = GfxCallbacks {
            slot: 3,
            tx,
            hard_cap: 60,
            metrics: metrics.clone(),
        };
        cb.on_frame_ack(7, 0, 41);
        assert_eq!(metrics.egfx_client_frames_decoded.get(), 41);
        let buf = Buf::default();
        let sub = crate::logging::subscriber("kvm_rdp=debug", buf.clone()).unwrap();
        let pdu = CapabilitiesAdvertisePdu(vec![
            RawCapabilitySet::new(CapabilityVersion::V8, vec![0x02, 0, 0, 0]),
            RawCapabilitySet::new(CapabilityVersion::V8_1, vec![0x12, 0, 0, 0]),
        ]);
        tracing::subscriber::with_default(sub, || cb.capabilities_advertise(&pdu));
        let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(text.contains("EGFX capabilities advertised"), "{text}");
        assert!(
            text.contains("00080004:02000000,00080105:12000000"),
            "{text}"
        );
        // The ack still reaches the pump, first: it was sent first.
        assert!(matches!(
            rx.try_recv(),
            Ok(RdpInput::FrameAck {
                slot: 3,
                frame_id: 7,
                queue_depth: 0
            })
        ));
        assert!(matches!(
            rx.try_recv(),
            Ok(RdpInput::CapsAdvertised { slot: 3, .. })
        ));
    }
}
