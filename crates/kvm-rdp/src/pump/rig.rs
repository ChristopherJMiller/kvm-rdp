//! The L1 rig (§11.2): a real `GraphicsPipelineServer` driven in memory,
//! an injected clock, real parameter sets from the fixtures, and a decoder
//! for everything the pump hands IronRDP.
//! The decoder is hand-rolled over IronRDP's own PDU types rather than an
//! `ironrdp_egfx::client::GraphicsPipelineClient` (DC17): the client pulls in
//! a decoder trait and surface bookkeeping the L1 asserts do not need, and
//! the L2 client (Task 6.1) is where a real client stack runs.
//! `dead_code` is allowed: some helpers are first used by Tasks 4.5–4.6.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    dead_code
)]
use crate::config::IdrPolicy;
use crate::metrics::Metrics;
use crate::msg::{FlvOrigin, KvmAu};
use crate::pump::core::Pump;
use crate::pump::slate::Slate;
use crate::pump::types::{Command, FlowConfig, IdrConfig, Input, PumpConfig, State};
use bytes::Bytes;
use ironrdp_core::{ReadCursor, decode, decode_cursor, encode_vec};
use ironrdp_dvc::{DvcMessage, DvcProcessor as _};
use ironrdp_egfx::pdu::{
    Avc420BitmapStream, CapabilitiesAdvertisePdu, CapabilitySet, CapabilityVersion, Codec1Type,
    FrameAcknowledgePdu, GfxPdu, QueueDepth, RawCapabilitySet,
};
use ironrdp_egfx::server::{GraphicsPipelineHandler, GraphicsPipelineServer};
use ironrdp_graphics::zgfx::Decompressor;
use kvm_proto::flv::mux::{TAG_VIDEO, avc_sequence_header_body, write_flv_header, write_tag};
use kvm_proto::flv::{FlvDemuxer, FlvLimits, Nal};
use kvm_proto::h264::split_annex_b;
use kvm_proto::video::{AccessUnit, AdmissionConfig, ParamClass, ParamSets, VideoAdmission};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(crate) const CHAN: u32 = 7;
/// The ES3-shaped POC-0 fixture (640×360, Baseline) and the 480p one.
pub(crate) const ES3: &str = "360p30_es3like_poc0.h264";
pub(crate) const P480: &str = "480p30_main_full.h264";

pub(crate) struct Null;
impl GraphicsPipelineHandler for Null {
    fn capabilities_advertise(&mut self, _: &CapabilitiesAdvertisePdu) {}
    fn on_ready(&mut self, _: &CapabilitySet) {}
}

/// FreeRDP's `/gfx:AVC420` pair, as recorded in `census.md` (Legs B, C).
pub(crate) fn census_caps() -> Vec<RawCapabilitySet> {
    vec![
        RawCapabilitySet::new(CapabilityVersion::V8, vec![0x02, 0, 0, 0]),
        RawCapabilitySet::new(CapabilityVersion::V8_1, vec![0x12, 0, 0, 0]),
    ]
}

/// A client without AVC420.
pub(crate) fn v8_only() -> Vec<RawCapabilitySet> {
    vec![RawCapabilitySet::new(
        CapabilityVersion::V8,
        vec![0x02, 0, 0, 0],
    )]
}

/// IronRDP's own 11-set ladder (the shape of FreeRDP's no-`/gfx` ladder, DC8).
pub(crate) fn full_ladder() -> Vec<RawCapabilitySet> {
    CapabilitiesAdvertisePdu::from_typed(&Null.preferred_capabilities()).0
}

/// FreeRDP's 11-set ladder, as L3 recorded it (DC8; the fixture's first
/// line names the FreeRDP version).
pub(crate) fn freerdp_ladder() -> Vec<RawCapabilitySet> {
    include_str!("../../../../fixtures/freerdp-gfx-ladder.txt")
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let (v, hex) = l.split_once(':').unwrap();
            let data = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            RawCapabilitySet::new(CapabilityVersion(u32::from_str_radix(v, 16).unwrap()), data)
        })
        .collect()
}

/// The spec defaults (§4.4), `side` policy.
pub(crate) fn cfg() -> PumpConfig {
    PumpConfig {
        hard_cap: 60,
        flow: FlowConfig {
            soft_gate: Duration::from_millis(500),
            backlog_limit: 4 << 20,
            standing_delay_limit: Duration::from_millis(500),
            first_ack_grace: Duration::from_millis(1600),
            stall_timeout: Duration::from_secs(10),
        },
        idr: IdrConfig {
            policy: IdrPolicy::Side,
            side_timeout: Duration::from_secs(1),
            wait_max: Duration::from_secs(3),
            interval_setup: Duration::from_secs(1),
            interval_flow: Duration::from_secs(10),
        },
        rtt_probe_interval: Duration::from_millis(250),
        burst_chunk: 8,
        avc420_timeout: Duration::from_secs(10),
        suppress_debounce: Duration::from_secs(1),
        disconnect_watchdog: Duration::from_secs(5),
        region_qp: 22,
    }
}

/// A fixture's rewritten, admitted parameter sets (through kvm-proto).
pub(crate) fn params(fixture: &str) -> ParamSets {
    let src = kvm_sim::Source::fixture(fixture).unwrap();
    let mut flv = Vec::new();
    write_flv_header(&mut flv, false, true);
    let body = avc_sequence_header_body(&[&src.sps], &[&src.pps], 4).unwrap();
    write_tag(&mut flv, TAG_VIDEO, 0, &body).unwrap();
    let mut d = FlvDemuxer::new(FlvLimits::default());
    d.push(&flv);
    let tag = d.next_tag().unwrap().unwrap();
    let mut a = VideoAdmission::new(AdmissionConfig::default());
    a.flv_opened();
    a.admit(tag, Instant::now()).unwrap().params.unwrap().params
}

pub(crate) fn sps(class: ParamClass, fixture: &str) -> Input {
    Input::SpsChanged {
        class,
        params: params(fixture),
    }
}

/// A one-NAL access unit (the pump never parses slice data).
pub(crate) fn au(idr: bool, burst: bool) -> Input {
    let nal: &'static [u8] = if idr {
        &[0x65, 0x88, 0x84, 0x21]
    } else {
        &[0x41, 0x9a, 0x02, 0x10]
    };
    Input::Au(KvmAu {
        au: AccessUnit {
            flv_timestamp_ms: 0,
            idr,
            burst,
            aud: None,
            vcl: vec![Nal {
                bytes: Bytes::from_static(nal),
            }],
        },
        after_drop: false,
        received: Instant::now(),
    })
}

/// Every GFX PDU in a batch of server→client DVC messages (ZGFX-unwrapped).
pub(crate) fn decode_msgs(msgs: &[DvcMessage]) -> Vec<GfxPdu> {
    let mut out = Vec::new();
    for m in msgs {
        let wrapped = encode_vec(m.as_ref()).unwrap();
        let mut plain = Vec::new();
        Decompressor::new()
            .decompress(&wrapped, &mut plain)
            .unwrap();
        let mut cur = ReadCursor::new(&plain);
        while !cur.is_empty() {
            out.push(decode_cursor::<GfxPdu>(&mut cur).unwrap());
        }
    }
    out
}

pub(crate) fn pdus(cmds: &[Command]) -> Vec<GfxPdu> {
    cmds.iter()
        .filter_map(|c| {
            if let Command::SendDvc(b) = c {
                Some(decode_msgs(&b.messages))
            } else {
                None
            }
        })
        .flatten()
        .collect()
}

pub(crate) fn names(pdus: &[GfxPdu]) -> Vec<&'static str> {
    pdus.iter()
        .map(|p| match p {
            GfxPdu::CapabilitiesConfirm(_) => "CapabilitiesConfirm",
            GfxPdu::ResetGraphics(_) => "ResetGraphics",
            GfxPdu::CreateSurface(_) => "CreateSurface",
            GfxPdu::DeleteSurface(_) => "DeleteSurface",
            GfxPdu::MapSurfaceToOutput(_) => "MapSurfaceToOutput",
            GfxPdu::StartFrame(_) => "StartFrame",
            GfxPdu::WireToSurface1(_) => "WireToSurface1",
            GfxPdu::EndFrame(_) => "EndFrame",
            GfxPdu::CacheImportReply(_) => "CacheImportReply",
            _ => "Other",
        })
        .collect()
}

pub(crate) fn kinds(cmds: &[Command]) -> Vec<&'static str> {
    cmds.iter().map(Command::kind).collect()
}

/// One sent frame as `wire` reports it: the Annex-B payload, the QP and the
/// destination rectangle `(left, top, right, bottom)`. An alias only (the
/// tuple is clippy's `type_complexity` in a signature).
pub(crate) type Wired = (Vec<u8>, u8, (u16, u16, u16, u16));

/// Each `WireToSurface1`'s Annex-B payload, QP and destination rectangle;
/// every one must be AVC420 (§11.2: "only AVC420 `WireToSurface1` is ever
/// sent"), so every L1 case that looks at a frame asserts the codec.
pub(crate) fn wire(cmds: &[Command]) -> Vec<Wired> {
    pdus(cmds)
        .into_iter()
        .filter_map(|p| {
            if let GfxPdu::WireToSurface1(w) = p {
                Some(w)
            } else {
                None
            }
        })
        .map(|w| {
            assert_eq!(
                w.codec_id,
                Codec1Type::Avc420,
                "only AVC420 is ever sent (§11.2)"
            );
            let s: Avc420BitmapStream<'_> = decode(&w.bitmap_data).unwrap();
            let r = &s.rectangles[0];
            (
                s.data.to_vec(),
                s.quant_qual_vals[0].quantization_parameter,
                (r.left, r.top, r.right, r.bottom),
            )
        })
        .collect()
}

pub(crate) fn nal_types(annex_b: &[u8]) -> Vec<u8> {
    split_annex_b(annex_b).map(|n| n[0] & 0x1F).collect()
}

pub(crate) struct Rig {
    pub gfx: GraphicsPipelineServer,
    pub pump: Pump,
    pub cfg: PumpConfig,
    pub t0: Instant,
    pub now: Instant,
    pub metrics: Arc<Metrics>,
}

impl Rig {
    pub fn new(cfg: PumpConfig) -> Rig {
        Rig::with_slate(cfg, None)
    }

    pub fn with_slate(cfg: PumpConfig, slate: Option<Slate>) -> Rig {
        let mut gfx = GraphicsPipelineServer::new(Box::new(Null));
        gfx.start(CHAN).unwrap();
        let metrics = Arc::new(Metrics::default());
        let t0 = Instant::now();
        Rig {
            gfx,
            pump: Pump::with_slate(cfg.clone(), metrics.clone(), slate),
            cfg,
            t0,
            now: t0,
            metrics,
        }
    }

    pub fn at(&mut self, ms: u64) {
        self.now = self.t0 + Duration::from_millis(ms);
    }

    pub fn ms(&self) -> u64 {
        u64::try_from(self.now.duration_since(self.t0).as_millis()).unwrap()
    }

    pub fn step(&mut self, input: Input) -> Vec<Command> {
        self.pump.step(&mut self.gfx, self.now, input)
    }

    /// The client advertises; returns what IronRDP itself answered.
    pub fn advertise(&mut self, sets: Vec<RawCapabilitySet>) -> Vec<GfxPdu> {
        let pdu = GfxPdu::CapabilitiesAdvertise(CapabilitiesAdvertisePdu(sets));
        decode_msgs(&self.gfx.process(CHAN, &encode_vec(&pdu).unwrap()).unwrap())
    }

    /// Advertise, then tell the pump what IronRDP negotiated (`on_ready`).
    pub fn negotiate(&mut self, sets: Vec<RawCapabilitySet>) -> Vec<Command> {
        self.advertise(sets);
        let avc420 = self.gfx.supports_avc420();
        self.step(Input::OnReady { avc420 })
    }

    pub fn start(&mut self, size: (u16, u16)) -> Vec<Command> {
        self.step(Input::SessionStart {
            generation: 1,
            size,
        })
    }

    /// 640×360 session, census capabilities, the first FLV's Initial sets.
    pub fn need_idr(&mut self) -> Vec<Command> {
        let mut out = self.start((640, 360));
        out.extend(self.negotiate(census_caps()));
        out.extend(self.step(Input::FlvOpened {
            origin: FlvOrigin::First,
        }));
        out.extend(self.step(sps(ParamClass::Initial, ES3)));
        assert_eq!(self.pump.state(), State::NeedIdr);
        out
    }

    /// `need_idr` plus the first KVM IDR (frame id 0).
    pub fn live(&mut self) -> Vec<Command> {
        let mut out = self.need_idr();
        out.extend(self.step(au(true, false)));
        assert_eq!(self.pump.state(), State::Live);
        out
    }

    /// The client acknowledges `frame_id`: IronRDP first, then the pump.
    pub fn ack(&mut self, frame_id: u32, depth: QueueDepth) -> Vec<Command> {
        let queue_depth = depth.to_u32();
        let pdu = GfxPdu::FrameAcknowledge(FrameAcknowledgePdu {
            queue_depth: QueueDepth::from_u32(queue_depth),
            frame_id,
            total_frames_decoded: 0,
        });
        let _ = self.gfx.process(CHAN, &encode_vec(&pdu).unwrap()).unwrap();
        self.step(Input::FrameAck {
            frame_id,
            queue_depth,
        })
    }

    /// Suppression held at `on` for the debounce time (one edge).
    pub fn hold_suppress(&mut self, on: bool) -> Vec<Command> {
        let mut out = self.step(Input::Suppress(on));
        let later = self.ms() + u64::try_from(self.cfg.suppress_debounce.as_millis()).unwrap();
        self.at(later);
        out.extend(self.step(Input::Suppress(on)));
        out
    }

    /// A new RDP connection: a fresh `GraphicsPipelineServer` (one per
    /// connection, as IronRDP builds them), the same pump.
    pub fn new_connection(&mut self) {
        let mut gfx = GraphicsPipelineServer::new(Box::new(Null));
        gfx.start(CHAN).unwrap();
        self.gfx = gfx;
    }
}
