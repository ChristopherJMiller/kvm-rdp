//! §6.1 slice-header checks and the decode-order POC rule, on top of
//! h264-reader's slice-header parser with the admitted SPS and PPSs; and
//! §6.2's access unit delimiter, checked against the picture's slices.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use crate::h264::{parse_slice_header_prefix, slice_type_allowed};
use h264_reader::Context;
use h264_reader::nal::pps::PicParameterSet;
use h264_reader::nal::slice::{
    DecRefPicMarking, MemoryManagementControlOperation, ModificationOfPicNums, NumRefIdxActive,
    PicOrderCountLsb, RefPicListModifications, SliceHeader,
};
use h264_reader::nal::sps::{PicOrderCntType, SeqParameterSet};
use h264_reader::nal::{Nal as _, RefNal};
use h264_reader::rbsp::{BitRead, BitReaderError, Integer, Primitive};

/// Why a slice was refused (`stream_incompatible`, §6.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SliceRefusal {
    /// h264-reader could not parse the header (its error, as text) — this
    /// includes a `pic_parameter_set_id` with no admitted PPS, and a header
    /// that does not fit in [`SLICE_HEADER_BOUND`] bytes.
    Unparsable(String),
    /// `slice_type` not in `{0, 2, 5, 7}`: B, SP or SI (§6.1 admits P and I).
    SliceType(u32),
    /// `first_mb_in_slice >= PicSizeInMbs`.
    FirstMb { first_mb: u32, pic_size_in_mbs: u32 },
    /// POC not strictly increasing in decode order within a GOP.
    PocNotIncreasing { previous: i64, current: i64 },
    /// POC type 1 is refused by the SPS limits; never reaches here.
    PocType1,
    /// A list or count in the header past what H.264 allows (§6.1, §9.3;
    /// final review I1).
    HeaderLimits(HeaderLimit),
}

/// Bytes of a slice NAL its header is parsed from (§6.1; final review I1).
/// The rest is slice data, which nothing here reads.
///
/// The longest *conforming* header §6.1 can admit — 36 864 MBs (4096×2304),
/// an 8-bit 4:2:0 frame, one slice group, P or I, with every field at the
/// widest value its semantics allow and every list at its ceiling (16
/// modifications, a 16-reference weight table with chroma, 66 three-field
/// MMCOs) — is 5 604 bits, 701 bytes of RBSP. Emulation prevention adds at
/// most one byte per two, so with the NAL header byte that is at most
/// 1 053 bytes on the wire (and 1 473 bytes even with field coding's 32
/// references, which §6.1 does not admit). 4 KiB covers it nearly four
/// times over; x264's and the ES3's headers are under 20 bytes. A header
/// that does not fit is non-conforming and refused as `Unparsable`.
pub const SLICE_HEADER_BOUND: usize = 4096;

/// A slice-header list or count past what H.264 allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderLimit {
    /// `num_ref_idx_lX_active_minus1` above 15: a frame slice has at most
    /// 16 active references (7.4.3), and §6.1 admits frames only.
    NumRefIdx(u32),
    /// More entries in `ref_pic_list_modification` list `list` (0 or 1)
    /// than `max`: `num_ref_idx_lX_active_minus1 + 1` (7.4.3.1), or 16 —
    /// the most any admitted slice can have — when the list is cut off
    /// while it is still being read.
    RefPicListModifications { list: u8, max: u32 },
    /// More than 66 `memory_management_control_operation`s (ffmpeg's
    /// `MAX_MMCO_COUNT`).
    Mmco,
}

/// Most active references, hence most modifications per list, in a frame
/// slice (7.4.3: `num_ref_idx_lX_active_minus1` ≤ 15).
const MAX_REFS: u32 = 16;
/// Most memory-management operations in one header (ffmpeg's
/// `MAX_MMCO_COUNT`).
const MAX_MMCO: u32 = 66;

/// Why an access unit delimiter was refused (`stream_incompatible`, §6.9;
/// PB10 m2, folded into final review I1). The AUD reaches the client's
/// decoder (§6.3), so it is checked like a slice header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudRefusal {
    /// Not exactly `access_unit_delimiter_rbsp` (7.3.2.4): the NAL header,
    /// then one byte of `primary_pic_type`, the stop bit and four zero bits.
    Malformed,
    /// This `primary_pic_type`'s Table 7-5 set does not hold every slice
    /// type in the picture (7.4.2.4).
    PrimaryPicType(u8),
}

/// The `primary_pic_type` of an AUD that is exactly
/// `access_unit_delimiter_rbsp`. `aud` is a §6.2-trimmed NAL: the stop bit
/// keeps its payload byte non-zero, so a well-formed AUD is two bytes.
pub fn aud_primary_pic_type(aud: &[u8]) -> Result<u8, AudRefusal> {
    match aud {
        [_, payload] if payload & 0x1F == 0x10 => Ok(payload.wrapping_shr(5)),
        _ => Err(AudRefusal::Malformed),
    }
}

/// True when `primary_pic_type`'s Table 7-5 set holds every slice type of
/// a picture that has I slices (`intra`) and/or P slices (`predicted`) —
/// the only types §6.1 admits.
#[must_use]
pub fn primary_pic_type_covers(primary_pic_type: u8, intra: bool, predicted: bool) -> bool {
    // Table 7-5: 0 I · 1 I, P · 2 I, P, B · 3 SI · 4 SI, SP · 5 I, SI ·
    // 6 I, SI, P, SP · 7 every type.
    let has_i = matches!(primary_pic_type, 0 | 1 | 2 | 5 | 6 | 7);
    let has_p = matches!(primary_pic_type, 1 | 2 | 6 | 7);
    (!intra || has_i) && (!predicted || has_p)
}

/// The slice-header fields that identify a picture (7.4.1.2.4) and its POC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SliceInfo {
    pub first_mb_in_slice: u32,
    /// 0 or 5 (P), 2 or 7 (I): the types §6.1 admits.
    pub slice_type: u32,
    pub idr: bool,
    pub nal_ref_idc: u8,
    pub pps_id: u8,
    pub frame_num: u16,
    pub idr_pic_id: Option<u32>,
    pub pic_order_cnt_lsb: Option<u32>,
    pub delta_pic_order_cnt_bottom: i32,
    /// `memory_management_control_operation == 5` in this slice.
    pub mmco5: bool,
}

impl SliceInfo {
    /// True when `other` belongs to the same picture as `self` (7.4.1.2.4:
    /// every field that starts a new primary picture is equal).
    #[must_use]
    pub fn same_picture(&self, other: &SliceInfo) -> bool {
        self.idr == other.idr
            && (self.nal_ref_idc == 0) == (other.nal_ref_idc == 0)
            && self.pps_id == other.pps_id
            && self.frame_num == other.frame_num
            && self.idr_pic_id == other.idr_pic_id
            && self.pic_order_cnt_lsb == other.pic_order_cnt_lsb
            && self.delta_pic_order_cnt_bottom == other.delta_pic_order_cnt_bottom
    }
}

/// h264-reader reads both of a slice header's lists until their
/// terminators, with no count bound (`RefPicListModifications::read_list`,
/// `DecRefPicMarking::read`), so a hostile header makes it allocate in
/// proportion to the NAL (final review I1: 87 MB for a 3.3 MB slice). This
/// reader refuses the entry past each ceiling as it is read, so h264-reader
/// never holds more than `MAX_REFS` modifications or `MAX_MMCO` operations.
/// It knows the entries by the syntax-element names h264-reader 0.9 passes;
/// the tests that refuse an unterminated list and a 67th MMCO pin them.
struct Budget<R> {
    inner: R,
    /// `ref_pic_list_modification_flag`s read so far: the current list + 1.
    lists: u8,
    entries: u32,
    mmco: u32,
    exceeded: Option<HeaderLimit>,
}

impl<R: BitRead> Budget<R> {
    fn new(inner: R) -> Self {
        Budget {
            inner,
            lists: 0,
            entries: 0,
            mmco: 0,
            exceeded: None,
        }
    }

    /// Record `limit`; the error stops h264-reader, and `parse_slice`
    /// reports `limit` instead of it.
    fn exceed(&mut self, limit: HeaderLimit, name: &'static str) -> BitReaderError {
        self.exceeded = Some(limit);
        BitReaderError::ExpGolombTooLarge(name)
    }
}

impl<R: BitRead> BitRead for Budget<R> {
    fn read_ue(&mut self, name: &'static str) -> Result<u32, BitReaderError> {
        let value = self.inner.read_ue(name)?;
        match name {
            // 3 ends the list.
            "modification_of_pic_nums_idc" if value != 3 => {
                self.entries = self.entries.saturating_add(1);
                if self.entries > MAX_REFS {
                    let limit = HeaderLimit::RefPicListModifications {
                        list: self.lists.saturating_sub(1),
                        max: MAX_REFS,
                    };
                    return Err(self.exceed(limit, name));
                }
            }
            // 0 ends the list.
            "memory_management_control_operation" if value != 0 => {
                self.mmco = self.mmco.saturating_add(1);
                if self.mmco > MAX_MMCO {
                    return Err(self.exceed(HeaderLimit::Mmco, name));
                }
            }
            _ => {}
        }
        Ok(value)
    }

    fn read_bit(&mut self, name: &'static str) -> Result<bool, BitReaderError> {
        let bit = self.inner.read_bit(name)?;
        if name == "ref_pic_list_modification_flag" {
            self.lists = self.lists.saturating_add(1);
            self.entries = 0;
        }
        Ok(bit)
    }

    fn read_se(&mut self, name: &'static str) -> Result<i32, BitReaderError> {
        self.inner.read_se(name)
    }

    fn read<const BITS: u32, I: Integer>(
        &mut self,
        name: &'static str,
    ) -> Result<I, BitReaderError> {
        self.inner.read::<BITS, I>(name)
    }

    fn read_var<I: Integer>(
        &mut self,
        bit_count: u32,
        name: &'static str,
    ) -> Result<I, BitReaderError> {
        self.inner.read_var(bit_count, name)
    }

    fn read_to<V: Primitive>(&mut self, name: &'static str) -> Result<V, BitReaderError> {
        self.inner.read_to(name)
    }

    fn skip(&mut self, bit_count: u32, name: &'static str) -> Result<(), BitReaderError> {
        self.inner.skip(bit_count, name)
    }

    fn byte_aligned(&self) -> bool {
        self.inner.byte_aligned()
    }

    fn has_more_rbsp_data(&mut self, name: &'static str) -> Result<bool, BitReaderError> {
        self.inner.has_more_rbsp_data(name)
    }

    fn finish_rbsp(self) -> Result<(), BitReaderError> {
        self.inner.finish_rbsp()
    }

    fn finish_sei_payload(self) -> Result<(), BitReaderError> {
        self.inner.finish_sei_payload()
    }
}

/// §6.1's slice-header counts that need the parsed header: the active
/// reference counts, and each modification list against its own count.
fn check_header_limits(sh: &SliceHeader, pps: &PicParameterSet) -> Result<(), SliceRefusal> {
    let (l0, l1) = match &sh.num_ref_idx_active {
        None => (
            pps.num_ref_idx_l0_default_active_minus1,
            pps.num_ref_idx_l1_default_active_minus1,
        ),
        Some(NumRefIdxActive::P {
            num_ref_idx_l0_active_minus1,
        }) => (
            *num_ref_idx_l0_active_minus1,
            pps.num_ref_idx_l1_default_active_minus1,
        ),
        Some(NumRefIdxActive::B {
            num_ref_idx_l0_active_minus1,
            num_ref_idx_l1_active_minus1,
        }) => (*num_ref_idx_l0_active_minus1, *num_ref_idx_l1_active_minus1),
    };
    if let Some(&n) = [l0, l1].iter().find(|&&n| n >= MAX_REFS) {
        return Err(SliceRefusal::HeaderLimits(HeaderLimit::NumRefIdx(n)));
    }
    let none: &[ModificationOfPicNums] = &[];
    let (mods_l0, mods_l1) = match &sh.ref_pic_list_modification {
        Some(RefPicListModifications::P {
            ref_pic_list_modification_l0,
        }) => (ref_pic_list_modification_l0.as_slice(), none),
        Some(RefPicListModifications::B {
            ref_pic_list_modification_l0,
            ref_pic_list_modification_l1,
        }) => (
            ref_pic_list_modification_l0.as_slice(),
            ref_pic_list_modification_l1.as_slice(),
        ),
        Some(RefPicListModifications::I) | None => (none, none),
    };
    for (list, mods, minus1) in [(0, mods_l0, l0), (1, mods_l1, l1)] {
        let max = minus1.saturating_add(1);
        if u32::try_from(mods.len()).map_or(true, |n| n > max) {
            return Err(SliceRefusal::HeaderLimits(
                HeaderLimit::RefPicListModifications { list, max },
            ));
        }
    }
    Ok(())
}

/// Parse and check one slice NAL (type 1 or 5) against `ctx`. Only its
/// first [`SLICE_HEADER_BOUND`] bytes are read.
pub fn parse_slice(ctx: &Context, nal: &[u8]) -> Result<SliceInfo, SliceRefusal> {
    let unparsable = |e: &dyn core::fmt::Debug| SliceRefusal::Unparsable(format!("{e:?}"));
    let nal = nal.get(..SLICE_HEADER_BOUND).unwrap_or(nal);
    // The slice type is checked from the context-free prefix first, so a B
    // slice is refused as such whatever follows it.
    let prefix = parse_slice_header_prefix(nal).map_err(|e| unparsable(&e))?;
    if !slice_type_allowed(prefix.slice_type) {
        return Err(SliceRefusal::SliceType(prefix.slice_type));
    }
    let refnal = RefNal::new(nal, &[], true);
    let header = refnal.header().map_err(|e| unparsable(&e))?;
    let mut bits = Budget::new(refnal.rbsp_bits());
    let parsed = SliceHeader::from_bits(ctx, &mut bits, header, None);
    if let Some(limit) = bits.exceeded {
        return Err(SliceRefusal::HeaderLimits(limit));
    }
    let (sh, sps, pps) = parsed.map_err(|e| unparsable(&e))?;
    check_header_limits(&sh, pps)?;
    let pic_size_in_mbs = sps
        .pic_width_in_mbs()
        .saturating_mul(sps.pic_height_in_map_units());
    if sh.first_mb_in_slice >= pic_size_in_mbs {
        return Err(SliceRefusal::FirstMb {
            first_mb: sh.first_mb_in_slice,
            pic_size_in_mbs,
        });
    }
    let (lsb, delta_bottom) = match sh.pic_order_cnt_lsb {
        Some(PicOrderCountLsb::Frame(lsb)) => (Some(lsb), 0),
        Some(PicOrderCountLsb::FieldsAbsolute {
            pic_order_cnt_lsb,
            delta_pic_order_cnt_bottom,
        }) => (Some(pic_order_cnt_lsb), delta_pic_order_cnt_bottom),
        Some(PicOrderCountLsb::FieldsDelta(_)) => return Err(SliceRefusal::PocType1),
        None => (None, 0),
    };
    let mmco5 = matches!(
        &sh.dec_ref_pic_marking,
        Some(DecRefPicMarking::Adaptive(ops))
            if ops.iter().any(|op| matches!(op, MemoryManagementControlOperation::AllRefPicturesUnused))
    );
    Ok(SliceInfo {
        first_mb_in_slice: sh.first_mb_in_slice,
        slice_type: prefix.slice_type,
        idr: sh.idr_pic_id.is_some(),
        nal_ref_idc: header.nal_ref_idc(),
        pps_id: pps.pic_parameter_set_id.id(),
        frame_num: sh.frame_num,
        idr_pic_id: sh.idr_pic_id,
        pic_order_cnt_lsb: lsb,
        delta_pic_order_cnt_bottom: delta_bottom,
        mmco5,
    })
}

/// Decode-order picture order count (H.264 8.2.1.1 type 0 and 8.2.1.3
/// type 2, frames only) and §6.1's rule that it strictly increases within
/// a GOP. State is per FLV connection: `reset` on every open.
#[derive(Debug, Default, Clone)]
pub struct PocTracker {
    prev_msb: i64,
    prev_lsb: i64,
    prev_frame_num: i64,
    prev_frame_num_offset: i64,
    last_poc: Option<i64>,
}

impl PocTracker {
    pub fn reset(&mut self) {
        *self = PocTracker::default();
    }

    /// The POC of the picture whose first slice is `s`, refused when it does
    /// not exceed the previous picture's in this GOP. An IDR starts a GOP;
    /// so does a picture after one with MMCO 5 (its POC becomes 0).
    pub fn next(&mut self, sps: &SeqParameterSet, s: &SliceInfo) -> Result<i64, SliceRefusal> {
        if s.idr {
            *self = PocTracker::default();
        }
        let poc = match &sps.pic_order_cnt {
            PicOrderCntType::TypeZero {
                log2_max_pic_order_cnt_lsb_minus4,
            } => {
                let max_lsb = 1_i64
                    .wrapping_shl(u32::from(*log2_max_pic_order_cnt_lsb_minus4).saturating_add(4));
                let half = max_lsb.wrapping_shr(1);
                let lsb = i64::from(s.pic_order_cnt_lsb.unwrap_or(0));
                let msb = if lsb < self.prev_lsb && self.prev_lsb.saturating_sub(lsb) >= half {
                    self.prev_msb.saturating_add(max_lsb)
                } else if lsb > self.prev_lsb && lsb.saturating_sub(self.prev_lsb) > half {
                    self.prev_msb.saturating_sub(max_lsb)
                } else {
                    self.prev_msb
                };
                let top = msb.saturating_add(lsb);
                let poc = top.min(top.saturating_add(i64::from(s.delta_pic_order_cnt_bottom)));
                if s.nal_ref_idc != 0 {
                    if s.mmco5 {
                        self.prev_msb = 0;
                        self.prev_lsb = top.saturating_sub(poc);
                    } else {
                        self.prev_msb = msb;
                        self.prev_lsb = lsb;
                    }
                }
                poc
            }
            PicOrderCntType::TypeTwo => {
                let max_frame_num = 1_i64.wrapping_shl(u32::from(sps.log2_max_frame_num()));
                let frame_num = i64::from(s.frame_num);
                let offset = if s.idr {
                    0
                } else if self.prev_frame_num > frame_num {
                    self.prev_frame_num_offset.saturating_add(max_frame_num)
                } else {
                    self.prev_frame_num_offset
                };
                let base = offset.saturating_add(frame_num).saturating_mul(2);
                let poc = if s.idr {
                    0
                } else if s.nal_ref_idc == 0 {
                    base.saturating_sub(1)
                } else {
                    base
                };
                (self.prev_frame_num, self.prev_frame_num_offset) =
                    if s.mmco5 { (0, 0) } else { (frame_num, offset) };
                poc
            }
            PicOrderCntType::TypeOne { .. } => return Err(SliceRefusal::PocType1),
        };
        if let Some(previous) = self.last_poc
            && poc <= previous
        {
            return Err(SliceRefusal::PocNotIncreasing {
                previous,
                current: poc,
            });
        }
        self.last_poc = Some(if s.mmco5 { 0 } else { poc });
        Ok(poc)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
    use super::*;
    use crate::h264::rewrite::{RewriteConfig, rewrite_sps};
    use crate::h264::test_support::{PpsCfg, SliceCfg, SpsCfg};

    /// Baseline 1080p, `log2_max_frame_num` 4; POC type 2, or type 0 with
    /// a 5-bit `pic_order_cnt_lsb`.
    fn ctx(poc_type: u32) -> (Context, SeqParameterSet) {
        let mut c = SpsCfg::main_1080p();
        c.profile_idc = 66;
        c.pic_order_cnt_type = poc_type;
        c.log2_max_poc_lsb_minus4 = 1;
        let r = rewrite_sps(&c.build(), &RewriteConfig::ES3).unwrap();
        let mut ctx = Context::new();
        ctx.put_seq_param_set(r.parsed.clone());
        ctx.put_pic_param_set(
            crate::h264::pps::check_pps(&ctx, &PpsCfg::default().build()).unwrap(),
        );
        (ctx, r.parsed)
    }

    fn slice(ctx: &Context, s: &SliceCfg) -> SliceInfo {
        parse_slice(ctx, &s.build()).unwrap()
    }

    fn poc0(frame_num: u32, lsb: u32) -> SliceCfg {
        SliceCfg {
            poc_lsb: Some((lsb, 5)),
            ..SliceCfg::p(frame_num)
        }
    }

    #[test]
    fn poc_type_2_increases_across_a_frame_num_wrap() {
        let (ctx, sps) = ctx(2);
        let mut t = PocTracker::default();
        assert_eq!(t.next(&sps, &slice(&ctx, &SliceCfg::idr())), Ok(0));
        let pocs: Vec<i64> = [1, 2, 15, 0, 1]
            .iter()
            .map(|&f| t.next(&sps, &slice(&ctx, &SliceCfg::p(f))).unwrap())
            .collect();
        assert_eq!(pocs, [2, 4, 30, 32, 34]);
    }

    #[test]
    fn poc_type_0_follows_the_lsb_wrap_and_refuses_going_back() {
        let (ctx, sps) = ctx(0);
        let mut t = PocTracker::default();
        let idr = SliceCfg {
            poc_lsb: Some((0, 5)),
            ..SliceCfg::idr()
        };
        assert_eq!(t.next(&sps, &slice(&ctx, &idr)), Ok(0));
        // 8.2.1.1: a step of half MaxPicOrderCntLsb (16) or more is a wrap.
        let pocs: Vec<i64> = [(1, 10), (2, 20), (3, 30), (4, 8)]
            .iter()
            .map(|&(f, lsb)| t.next(&sps, &slice(&ctx, &poc0(f, lsb))).unwrap())
            .collect();
        assert_eq!(pocs, [10, 20, 30, 40]); // 8 after 30: the lsb wrapped
        assert_eq!(
            t.next(&sps, &slice(&ctx, &poc0(5, 30))),
            Err(SliceRefusal::PocNotIncreasing {
                previous: 40,
                current: 30
            })
        );
        // An IDR starts a new GOP: POC 0 is fine again.
        assert_eq!(t.next(&sps, &slice(&ctx, &idr)), Ok(0));
    }

    #[test]
    fn mmco5_restarts_the_order() {
        let (ctx, sps) = ctx(2);
        let mut t = PocTracker::default();
        t.next(&sps, &slice(&ctx, &SliceCfg::idr())).unwrap();
        t.next(&sps, &slice(&ctx, &SliceCfg::p(1))).unwrap();
        t.next(&sps, &slice(&ctx, &SliceCfg::p(2))).unwrap();
        let mmco5 = SliceCfg {
            mmco5: true,
            ..SliceCfg::p(3)
        };
        t.next(&sps, &slice(&ctx, &mmco5)).unwrap();
        // After MMCO 5 the next picture counts from frame_num 0 again.
        assert_eq!(t.next(&sps, &slice(&ctx, &SliceCfg::p(1))), Ok(2));
    }

    #[test]
    fn b_sp_and_si_are_refused_from_the_prefix() {
        let (ctx, _) = ctx(2);
        assert_eq!(
            parse_slice(&ctx, &[0x41, 0xAC]),
            Err(SliceRefusal::SliceType(1))
        );
        for t in [3u32, 4, 6, 8, 9] {
            let s = SliceCfg {
                slice_type: t,
                ..SliceCfg::p(1)
            };
            assert_eq!(
                parse_slice(&ctx, &s.build()),
                Err(SliceRefusal::SliceType(t))
            );
        }
    }

    #[test]
    fn first_mb_must_be_inside_the_picture() {
        let (ctx, _) = ctx(2);
        let s = SliceCfg {
            first_mb: 120 * 68 - 1,
            ..SliceCfg::p(1)
        };
        assert_eq!(slice(&ctx, &s).first_mb_in_slice, 8159);
        let s = SliceCfg {
            first_mb: 120 * 68,
            ..SliceCfg::p(1)
        };
        assert_eq!(
            parse_slice(&ctx, &s.build()),
            Err(SliceRefusal::FirstMb {
                first_mb: 8160,
                pic_size_in_mbs: 8160
            })
        );
    }

    /// A P slice with `n` `ref_pic_list_modification_l0` entries (idc 0,
    /// `abs_diff_pic_num_minus1` 0) against `ctx`'s PPS (one active
    /// reference by default).
    fn mods(n: usize) -> SliceCfg {
        SliceCfg {
            ref_list_mods: vec![(0, 0); n],
            ..SliceCfg::p(1)
        }
    }

    fn limit(l: HeaderLimit) -> Result<SliceInfo, SliceRefusal> {
        Err(SliceRefusal::HeaderLimits(l))
    }

    /// Final review I1: H.264 7.4.3.1 allows at most
    /// `num_ref_idx_l0_active_minus1 + 1` modifications per list.
    #[test]
    fn modifications_are_bounded_by_the_active_reference_count() {
        let (ctx, _) = ctx(2);
        assert!(parse_slice(&ctx, &mods(1).build()).is_ok());
        assert_eq!(
            parse_slice(&ctx, &mods(2).build()),
            limit(HeaderLimit::RefPicListModifications { list: 0, max: 1 })
        );
        let four = SliceCfg {
            num_ref_idx_override: Some(3),
            ..mods(4)
        };
        assert!(parse_slice(&ctx, &four.build()).is_ok());
        let five = SliceCfg {
            num_ref_idx_override: Some(3),
            ..mods(5)
        };
        assert_eq!(
            parse_slice(&ctx, &five.build()),
            limit(HeaderLimit::RefPicListModifications { list: 0, max: 4 })
        );
    }

    /// 7.4.3: `num_ref_idx_l0_active_minus1` is at most 15 in a frame slice,
    /// and §6.1 admits frames only — so no list ever needs more than 16
    /// modifications.
    #[test]
    fn a_frame_slice_has_at_most_16_active_references() {
        let (ctx, _) = ctx(2);
        let sixteen = SliceCfg {
            num_ref_idx_override: Some(15),
            ..mods(16)
        };
        assert!(parse_slice(&ctx, &sixteen.build()).is_ok());
        let seventeen = SliceCfg {
            num_ref_idx_override: Some(16),
            ..SliceCfg::p(1)
        };
        assert_eq!(
            parse_slice(&ctx, &seventeen.build()),
            limit(HeaderLimit::NumRefIdx(16))
        );
    }

    /// At most 66 memory-management operations, ffmpeg's `MAX_MMCO_COUNT`.
    #[test]
    fn mmco_operations_are_bounded_at_66() {
        let (ctx, _) = ctx(2);
        let ops = |n: usize| SliceCfg {
            mmco1: vec![0; n],
            ..SliceCfg::p(1)
        };
        assert!(parse_slice(&ctx, &ops(66).build()).is_ok());
        assert_eq!(
            parse_slice(&ctx, &ops(67).build()),
            limit(HeaderLimit::Mmco)
        );
    }

    /// A list is cut off at its ceiling while it is being read, not parsed
    /// to its end: these 100 entries never terminate, and an unbudgeted
    /// parse reads on through the slice data into an invalid
    /// `modification_of_pic_nums_idc` (`Unparsable`) instead. The input is
    /// under 64 bytes.
    #[test]
    fn an_unterminated_list_is_refused_at_the_ceiling_while_it_is_read() {
        let (ctx, _) = ctx(2);
        let nal = SliceCfg {
            terminate_lists: false,
            ..mods(100)
        }
        .build();
        assert!(nal.len() < 64, "{}", nal.len());
        assert_eq!(
            parse_slice(&ctx, &nal),
            limit(HeaderLimit::RefPicListModifications { list: 0, max: 16 })
        );
    }

    /// The header is read from a bounded prefix of the NAL; a slice whose
    /// data runs far past that prefix still parses.
    #[test]
    fn a_slice_far_longer_than_the_header_bound_still_parses() {
        let (ctx, _) = ctx(2);
        let nal = SliceCfg {
            slice_data: vec![0xA5; 64 * 1024],
            ..mods(1)
        }
        .build();
        assert!(nal.len() > 16 * SLICE_HEADER_BOUND);
        assert_eq!(parse_slice(&ctx, &nal), Ok(slice(&ctx, &mods(1))));
    }

    /// Only the first `SLICE_HEADER_BOUND` bytes are read. After the header,
    /// a one bit and a run of zero bits look like `rbsp_trailing_bits` until
    /// the 0xA5 after them: within the bound that byte is "more RBSP data"
    /// and the header parses; past it, the header seems to overrun the RBSP.
    #[test]
    fn only_the_first_4_kib_of_a_slice_are_read() {
        let (ctx, _) = ctx(2);
        let with_zeros = |zeros: usize| {
            SliceCfg {
                slice_data: [vec![0x80], vec![0; zeros], vec![0xA5]].concat(),
                ..SliceCfg::p(1)
            }
            .build()
        };
        let inside = with_zeros(2000);
        assert!(inside.len() < SLICE_HEADER_BOUND, "{}", inside.len());
        assert!(parse_slice(&ctx, &inside).is_ok());
        let past = with_zeros(4000);
        // Its one bits after the 0x80 are all in its last three bytes.
        assert!(past.len() > SLICE_HEADER_BOUND + 3, "{}", past.len());
        let r = parse_slice(&ctx, &past);
        assert!(
            matches!(&r, Err(SliceRefusal::Unparsable(e)) if e.contains("overran")),
            "{r:?}"
        );
    }

    #[test]
    fn same_picture_compares_the_7_4_1_2_4_fields() {
        let (ctx, _) = ctx(2);
        let a = slice(&ctx, &SliceCfg::p(1));
        assert!(a.same_picture(&slice(
            &ctx,
            &SliceCfg {
                first_mb: 10,
                ..SliceCfg::p(1)
            }
        )));
        assert!(!a.same_picture(&slice(
            &ctx,
            &SliceCfg {
                first_mb: 10,
                ..SliceCfg::p(2)
            }
        )));
        assert!(!a.same_picture(&slice(
            &ctx,
            &SliceCfg {
                first_mb: 10,
                header_byte: 0x01,
                ..SliceCfg::p(1)
            }
        )));
        assert!(!a.same_picture(&slice(&ctx, &SliceCfg::idr())));
    }
}
