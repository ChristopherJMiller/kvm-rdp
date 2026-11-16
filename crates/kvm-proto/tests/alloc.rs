//! §10.1's bridge-owned allocation budget, kvm-proto's share (Plan E Task
//! 1.4, DE3 A): a committed fixture muxed as the ES3 sends it — the FLV
//! header and sequence header, then one tag per access unit, each tag one
//! network read — through `FlvDemuxer` → `VideoAdmission` →
//! `AccessUnit::write_annex_b` into one reused buffer, under a counting
//! allocator, minus what h264-reader's own slice-header parse allocates
//! for the same NALs on a twin context (see `measure`). Its own binary
//! with `harness = false`: the global allocator is this file's, and
//! nothing else runs while it counts.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::as_conversions
)]
use h264_reader::Context;
use h264_reader::nal::slice::SliceHeader;
use h264_reader::nal::{Nal as _, RefNal};
use kvm_proto::flv::mux::{
    TAG_VIDEO, avc_nalu_body, avc_sequence_header_body, write_flv_header, write_tag,
};
use kvm_proto::flv::{FlvDemuxer, FlvLimits};
use kvm_proto::h264::pps::check_pps;
use kvm_proto::h264::rewrite::rewrite_sps;
use kvm_proto::h264::{is_vcl, split_annex_b};
use kvm_proto::video::{AdmissionConfig, VideoAdmission};
use std::alloc::{GlobalAlloc, Layout, System};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

struct Counting;
static ALLOCS: AtomicU64 = AtomicU64::new(0);

// SAFETY: every method forwards to `System` unchanged; counting touches
// one atomic.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(p, l, n) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}

#[global_allocator]
static A: Counting = Counting;

/// kvm-proto's share of §10.1's ≤ 2 per frame (DE3): the per-tag NAL
/// `Vec` and the demuxer buffer's amortised growth.
const BUDGET: f64 = 1.5;
const WARM_UP: usize = 30;

fn main() {
    for name in ["360p30_es3like_poc0.h264", "480p30_main_full.h264"] {
        let m = measure(name);
        let per_au = m.own_per_au();
        println!(
            "alloc: {name}: {per_au:.3} bridge-owned allocations per access unit \
             ({} − h264-reader's {}, {} AUs; budget {BUDGET})",
            m.total, m.h264_reader, m.aus
        );
        assert!(
            per_au <= BUDGET,
            "{name}: {per_au:.3} > {BUDGET} allocations per AU (§10.1, DE3)"
        );
    }
}

/// The fixture's SPS, PPS and access units (VCL NALs only; an AU starts at
/// a VCL NAL whose `first_mb_in_slice` is 0 — the slice header's first
/// bit set).
fn split(data: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<Vec<Vec<u8>>>) {
    let (mut sps, mut pps, mut aus) = (None, None, Vec::<Vec<Vec<u8>>>::new());
    for nal in split_annex_b(data) {
        match nal[0] & 0x1F {
            7 => sps = sps.or_else(|| Some(nal.to_vec())),
            8 => pps = pps.or_else(|| Some(nal.to_vec())),
            t if is_vcl(t) => {
                if nal[1] & 0x80 != 0 || aus.is_empty() {
                    aus.push(Vec::new());
                }
                aus.last_mut().unwrap().push(nal.to_vec());
            }
            _ => {}
        }
    }
    (sps.unwrap(), pps.unwrap(), aus)
}

/// Allocations over the access units counted once warm.
struct Measured {
    /// Everything demux → admission → Annex-B allocated.
    total: u64,
    /// What h264-reader's `SliceHeader::from_bits` allocated for the same
    /// slices on the twin context.
    h264_reader: u64,
    aus: u64,
}

impl Measured {
    fn own_per_au(&self) -> f64 {
        (self.total as f64 - self.h264_reader as f64) / self.aus as f64
    }
}

/// The twin: one slice-header parse per VCL NAL — the same h264-reader call
/// on the same bytes as admission's `h264::picture::parse_slice`;
/// admission's truncation to `SLICE_HEADER_BOUND` and its `Budget` reader
/// allocate nothing — against a context holding the same (rewritten) SPS
/// and the same PPS. Returns what it allocated.
fn twin_parse(ctx: &Context, au: &[Vec<u8>]) -> u64 {
    let before = ALLOCS.load(Ordering::Relaxed);
    for nal in au {
        let refnal = RefNal::new(nal, &[], true);
        let header = refnal.header().unwrap();
        let parsed = SliceHeader::from_bits(ctx, &mut refnal.rbsp_bits(), header, None);
        drop(std::hint::black_box(parsed.unwrap()));
    }
    ALLOCS.load(Ordering::Relaxed) - before
}

/// DE3 A, net of the third-party slice-header parser (controller ruling
/// on PE3, as DE3 nets IronRDP out of C). Admission parses every slice
/// header with h264-reader 0.9's `SliceHeader::from_bits`, which allocates
/// a weighted-prediction table (`pred_weight_table`: 2 + N `Vec`s per P
/// slice with N active references) whenever the PPS sets
/// `weighted_pred_flag` — x264's default for Main, so the 480p Main fixture
/// pays 3 per P frame there. The ES3 sends Baseline, which forbids
/// weighted prediction, so on the ES3-shaped fixture the twin counts 0.
/// Those allocations are h264-reader's, not the bridge's; anything
/// kvm-proto itself allocates per AU still shows on both fixtures. The
/// whole-process budget (Task 5.1) counts h264-reader's share as well.
fn measure(name: &str) -> Measured {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name);
    let (sps, pps, aus) = split(&std::fs::read(path).unwrap());
    // The twin context, as admission builds its own: the rewritten SPS,
    // then the PPS checked against it.
    let mut ctx = Context::new();
    ctx.put_seq_param_set(
        rewrite_sps(&sps, &AdmissionConfig::default().rewrite)
            .unwrap()
            .parsed,
    );
    let checked = check_pps(&ctx, &pps).unwrap();
    ctx.put_pic_param_set(checked);
    // The network reads, built before anything is counted.
    let mut head = Vec::new();
    write_flv_header(&mut head, false, true);
    write_tag(
        &mut head,
        TAG_VIDEO,
        0,
        &avc_sequence_header_body(&[&sps], &[&pps], 4).unwrap(),
    )
    .unwrap();
    let mut chunks = vec![head];
    for (i, au) in aus.iter().enumerate() {
        let nals: Vec<&[u8]> = au.iter().map(Vec::as_slice).collect();
        let idr = au.iter().any(|n| n[0] & 0x1F == 5);
        let mut body = Vec::new();
        avc_nalu_body(&mut body, idr, 16, &nals, 4).unwrap();
        let mut tag = Vec::new();
        write_tag(&mut tag, TAG_VIDEO, (i as u32 + 1) * 33, &body).unwrap();
        chunks.push(tag);
    }
    let mut demux = FlvDemuxer::new(FlvLimits::default());
    let mut admission = VideoAdmission::new(AdmissionConfig::default());
    admission.flv_opened();
    let mut params = None;
    let mut annexb = Vec::with_capacity(1 << 20);
    let mut m = Measured {
        total: 0,
        h264_reader: 0,
        aus: 0,
    };
    for (i, chunk) in chunks.iter().enumerate() {
        let before = ALLOCS.load(Ordering::Relaxed);
        demux.push(chunk);
        while let Some(tag) = demux.next_tag().unwrap() {
            let a = admission.admit(tag, Instant::now()).unwrap();
            if let Some(p) = a.params {
                params = Some(p.params);
            }
            if let (Some(au), Some(p)) = (a.au, params.as_ref()) {
                annexb.clear();
                au.write_annex_b(p, &mut annexb);
            }
        }
        let after = ALLOCS.load(Ordering::Relaxed);
        if i > WARM_UP {
            // Chunk `i` carries AU `i - 1` (chunk 0 is the headers).
            m.total += after - before;
            m.h264_reader += twin_parse(&ctx, &aus[i - 1]);
            m.aus += 1;
        }
    }
    m
}
