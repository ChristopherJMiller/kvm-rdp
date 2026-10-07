//! IronRDP goldens (§11.2) — required on every pin bump — and the three
//! fork patches Plan C depends on (§4.2): if a pin bump changes any of
//! these bytes or drops a patch, this file fails first.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use ironrdp_core::encode_vec;
use ironrdp_dvc::DvcProcessor as _;
use ironrdp_egfx::pdu::{
    Avc420Region, CapabilitiesAdvertisePdu, CapabilitiesV81Flags, CapabilitySet,
    FrameAcknowledgePdu, GfxPdu, QueueDepth, ResetGraphicsPdu, encode_avc420_bitmap_stream,
};
use ironrdp_egfx::server::{GraphicsPipelineHandler, GraphicsPipelineServer};
use ironrdp_pdu::gcc::{KeyboardType, Monitor, MonitorFlags};
use ironrdp_server::{ConnectionInfo, EgfxServerMessage};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

struct Null;
impl GraphicsPipelineHandler for Null {
    fn capabilities_advertise(&mut self, _pdu: &CapabilitiesAdvertisePdu) {}
    fn on_ready(&mut self, _negotiated: &CapabilitySet) {}
}

fn advertise_v8_1() -> Vec<u8> {
    encode_vec(&GfxPdu::CapabilitiesAdvertise(
        CapabilitiesAdvertisePdu::from_typed(&[CapabilitySet::V8_1 {
            flags: CapabilitiesV81Flags::AVC420_ENABLED | CapabilitiesV81Flags::SMALL_CACHE,
        }]),
    ))
    .unwrap()
}

#[test]
fn avc420_bitmap_stream_bytes_are_pinned() {
    let got = encode_avc420_bitmap_stream(
        &[Avc420Region::full_frame(640, 360, 22)],
        &[0, 0, 0, 1, 0x65, 0x88],
    );
    #[rustfmt::skip]
    let want = [
        1, 0, 0, 0,             // one region
        0, 0, 0, 0,             // left, top
        0x80, 0x02, 0x68, 0x01, // right 640, bottom 360 (exclusive)
        0x16, 0x64,             // QP 22, quality 100
        0, 0, 0, 1, 0x65, 0x88, // the Annex-B payload, verbatim
    ];
    assert_eq!(got, want);
}

#[test]
fn reset_graphics_monitor_bytes_are_pinned() {
    let pdu = GfxPdu::ResetGraphics(ResetGraphicsPdu {
        width: 1920,
        height: 1080,
        monitors: vec![Monitor {
            left: 0,
            top: 0,
            right: 1919,
            bottom: 1079,
            flags: MonitorFlags::PRIMARY,
        }],
    });
    let bytes = encode_vec(&pdu).unwrap();
    assert_eq!(
        bytes.len(),
        340,
        "RDPGFX_RESET_GRAPHICS_PDU is fixed at 340 bytes"
    );
    #[rustfmt::skip]
    let head = [
        0x0e, 0x00, 0x00, 0x00, 0x54, 0x01, 0x00, 0x00, // cmdId 0x000e, flags, length 340
        0x80, 0x07, 0, 0, 0x38, 0x04, 0, 0,             // 1920 × 1080
        1, 0, 0, 0,                                     // one monitor
        0, 0, 0, 0, 0, 0, 0, 0,                         // left 0, top 0
        0x7f, 0x07, 0, 0, 0x37, 0x04, 0, 0,             // right 1919, bottom 1079 (inclusive)
        1, 0, 0, 0,                                     // PRIMARY
    ];
    assert_eq!(&bytes[..40], &head);
    assert!(bytes[40..].iter().all(|&b| b == 0), "padding is zero");
}

#[test]
fn patch_1_ack_suspension_survives_a_reset_and_a_readvertise() {
    let mut s = GraphicsPipelineServer::new(Box::new(Null));
    s.start(7).unwrap();
    s.process(7, &advertise_v8_1()).unwrap();
    assert!(s.supports_avc420());
    let sid = s.create_surface(640, 360).unwrap();
    let id = s
        .send_avc420_frame(
            sid,
            &[0, 0, 0, 1, 0x65, 0x88],
            &[Avc420Region::full_frame(640, 360, 22)],
            0,
        )
        .unwrap();
    let _ = s.drain_output();
    let suspend = GfxPdu::FrameAcknowledge(FrameAcknowledgePdu {
        queue_depth: QueueDepth::Suspend,
        frame_id: id,
        total_frames_decoded: 1,
    });
    s.process(7, &encode_vec(&suspend).unwrap()).unwrap();
    assert!(s.is_ack_suspended());
    s.resize(640, 360);
    assert!(
        s.is_ack_suspended(),
        "FrameTracker::clear keeps the suspension (patch 1)"
    );
    s.process(7, &advertise_v8_1()).unwrap();
    assert!(
        s.is_ack_suspended(),
        "a re-advertise keeps it too (patch 1)"
    );
}

#[test]
fn patch_2_write_counter_rides_on_the_event() {
    let counter = Arc::new(AtomicU64::new(0));
    let ev =
        EgfxServerMessage::send_messages(Vec::new()).with_write_counter(Arc::clone(&counter), 42);
    assert!(matches!(ev, EgfxServerMessage::SendMessages { .. }));
    assert_eq!(
        Arc::strong_count(&counter),
        2,
        "the event holds the counter"
    );
}

// P13: the original form (`info.abort_handle().abort()` alone) asserts
// nothing — `abort()` returns `()` either way. The real behaviour (a
// disconnect on an unreachable KVM actually aborts) is proven by L2:
// Task 6.5's stalled client and Task 6.6's
// `shutdown_completes_with_the_kvm_unreachable`. This test only pins the
// API shape: the handle exists, and it is `Clone + Send + Sync + 'static`
// (so it can be stashed on `ConnectionInfo` and called from the shutdown
// watchdog on a different task).
#[test]
fn patch_3_abort_handle_api_is_present() {
    fn assert_handle<T: Clone + Send + Sync + 'static>(_: &T) {}
    let info = ConnectionInfo::new(0, KeyboardType::IBM_ENHANCED, String::new());
    assert_handle(&info.abort_handle());
    // Inert outside a live connection, by construction (patch 3).
    info.abort_handle().abort();
}
