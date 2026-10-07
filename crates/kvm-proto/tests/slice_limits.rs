//! Final review I1 (§9.3): a slice header whose ref-list-modification or
//! MMCO list runs on through the NAL is refused at H.264's ceiling while it
//! is being read. h264-reader's own parse allocates in proportion to such a
//! list (the review measured 87 MB peak for a 3.3 MB slice); admission must
//! not. A per-thread counting allocator measures what one `admit` call holds
//! at once, unaffected by tests running on other threads.
use kvm_proto::bits::{BitWriter, escape_rbsp_into};
use kvm_proto::flv::mux::{
    TAG_VIDEO, avc_nalu_body, avc_sequence_header_body, write_flv_header, write_tag,
};
use kvm_proto::flv::{FlvDemuxer, FlvLimits};
use kvm_proto::h264::picture::{HeaderLimit, SliceRefusal};
use kvm_proto::h264::pps::check_pps;
use kvm_proto::h264::rewrite::{RewriteConfig, rewrite_sps};
use kvm_proto::h264::split_annex_b;
use kvm_proto::video::{AdmissionConfig, AdmissionError, Incompatible, VideoAdmission};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::path::Path;
use std::time::Instant;

struct PerThread;

thread_local! {
    static LIVE: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
}

fn account(delta: isize) {
    let _ = LIVE.try_with(|live| {
        let now = live.get().wrapping_add(delta);
        live.set(now);
        let _ = PEAK.try_with(|peak| peak.set(peak.get().max(now)));
    });
}

// SAFETY: every call forwards to `System` unchanged; the bookkeeping
// touches only const-initialised thread-locals, which never allocate.
unsafe impl GlobalAlloc for PerThread {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            account(layout.size() as isize);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        account(-(layout.size() as isize));
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            account(new_size as isize - layout.size() as isize);
        }
        p
    }
}

#[global_allocator]
static ALLOC: PerThread = PerThread;

/// `f`'s result, and the most heap this thread held at once during `f`
/// beyond what it held before.
fn peak_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = LIVE.with(Cell::get);
    PEAK.with(|p| p.set(base));
    let out = f();
    let peak = PEAK.with(Cell::get);
    (out, usize::try_from(peak - base).unwrap_or(0))
}

/// The ES3-like fixture's first SPS, PPS and IDR slice.
fn es3like() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/360p30_es3like_poc0.h264");
    let data = std::fs::read(path).unwrap();
    let first = |t: u8| {
        split_annex_b(&data)
            .find(|n| n[0] & 0x1F == t)
            .unwrap()
            .to_vec()
    };
    (first(7), first(8), first(5))
}

/// A P slice against `sps`/`pps` (frame 1, POC lsb 2) whose header turns,
/// after the override flag, into `list_start` bits followed by 64 KiB of
/// `fill`: 0xFF reads as modifications `(0, 0)`, four per byte; 0x55 as
/// MMCO 1 with difference 0, two per byte. Neither list ever terminates.
fn runaway_slice(sps: &[u8], pps: &[u8], list_start: &[bool], fill: u8) -> Vec<u8> {
    let parsed = rewrite_sps(sps, &RewriteConfig::ES3).unwrap().parsed;
    let mut ctx = h264_reader::Context::new();
    ctx.put_seq_param_set(parsed.clone());
    let pps = check_pps(&ctx, pps).unwrap();
    assert!(
        !pps.bottom_field_pic_order_in_frame_present_flag
            && !pps.redundant_pic_cnt_present_flag
            && !pps.weighted_pred_flag,
        "the header layout below assumes none of these"
    );
    let h264_reader::nal::sps::PicOrderCntType::TypeZero {
        log2_max_pic_order_cnt_lsb_minus4,
    } = parsed.pic_order_cnt
    else {
        panic!("the ES3-like fixture is POC type 0");
    };
    let mut w = BitWriter::new();
    w.write_ue(0); // first_mb_in_slice
    w.write_ue(5); // slice_type: P (all)
    w.write_ue(0); // pic_parameter_set_id
    w.write_bits(1, u32::from(parsed.log2_max_frame_num())); // frame_num
    w.write_bits(2, u32::from(log2_max_pic_order_cnt_lsb_minus4) + 4);
    w.write_flag(false); // num_ref_idx_active_override_flag
    for &b in list_start {
        w.write_flag(b);
    }
    for _ in 0..64 * 1024 {
        w.write_u8(fill);
    }
    w.write_trailing_bits();
    let mut nal = vec![0x41]; // nal_ref_idc 2, non-IDR slice
    escape_rbsp_into(&w.into_rbsp(), &mut nal);
    nal
}

#[test]
fn a_header_list_running_through_64_kib_is_refused_without_allocating_for_it() {
    let (sps, pps, idr) = es3like();
    let cases = [
        (
            // ref_pic_list_modification_flag_l0 1
            "ref_pic_list_modification",
            vec![true],
            0xFF,
            HeaderLimit::RefPicListModifications { list: 0, max: 16 },
        ),
        (
            // no modifications; adaptive_ref_pic_marking_mode_flag 1
            "MMCO",
            vec![false, true],
            0x55,
            HeaderLimit::Mmco,
        ),
    ];
    for (name, list_start, fill, want) in cases {
        let slice = runaway_slice(&sps, &pps, &list_start, fill);
        let mut flv = Vec::new();
        write_flv_header(&mut flv, false, true);
        let seq = avc_sequence_header_body(&[&sps], &[&pps], 4).unwrap();
        write_tag(&mut flv, TAG_VIDEO, 0, &seq).unwrap();
        for (ts, (key, nal)) in [(true, &idr), (false, &slice)].into_iter().enumerate() {
            let mut body = Vec::new();
            avc_nalu_body(&mut body, key, 16, &[nal], 4).unwrap();
            write_tag(&mut flv, TAG_VIDEO, ts as u32 * 33, &body).unwrap();
        }
        let mut d = FlvDemuxer::new(FlvLimits::default());
        d.push(&flv);
        let mut a = VideoAdmission::new(AdmissionConfig::default());
        a.flv_opened();
        let now = Instant::now();
        for _ in 0..2 {
            a.admit(d.next_tag().unwrap().unwrap(), now).unwrap();
        }
        let tag = d.next_tag().unwrap().unwrap();
        let (r, peak) = peak_during(|| a.admit(tag, now));
        assert_eq!(
            r.err(),
            Some(AdmissionError::Incompatible(Incompatible::Slice(
                SliceRefusal::HeaderLimits(want)
            ))),
            "{name} (held {peak} bytes at once)"
        );
        assert!(
            peak < 16 * 1024,
            "{name}: admitting a {}-byte slice held {peak} bytes at once",
            slice.len()
        );
    }
}
