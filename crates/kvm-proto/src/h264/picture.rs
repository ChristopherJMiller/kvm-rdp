//! §6.1 slice-header checks and the decode-order POC rule, on top of
//! h264-reader's slice-header parser with the admitted SPS and PPSs.
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
use h264_reader::nal::slice::{
    DecRefPicMarking, MemoryManagementControlOperation, PicOrderCountLsb, SliceHeader,
};
use h264_reader::nal::sps::{PicOrderCntType, SeqParameterSet};
use h264_reader::nal::{Nal as _, RefNal};

/// Why a slice was refused (`stream_incompatible`, §6.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SliceRefusal {
    /// h264-reader could not parse the header (its error, as text) — this
    /// includes a `pic_parameter_set_id` with no admitted PPS.
    Unparsable(String),
    /// `slice_type` not in `{0, 2, 5, 7}`: B, SP or SI (§6.1 admits P and I).
    SliceType(u32),
    /// `first_mb_in_slice >= PicSizeInMbs`.
    FirstMb { first_mb: u32, pic_size_in_mbs: u32 },
    /// POC not strictly increasing in decode order within a GOP.
    PocNotIncreasing { previous: i64, current: i64 },
    /// POC type 1 is refused by the SPS limits; never reaches here.
    PocType1,
}

/// The slice-header fields that identify a picture (7.4.1.2.4) and its POC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SliceInfo {
    pub first_mb_in_slice: u32,
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

/// Parse and check one slice NAL (type 1 or 5) against `ctx`.
pub fn parse_slice(ctx: &Context, nal: &[u8]) -> Result<SliceInfo, SliceRefusal> {
    let unparsable = |e: &dyn core::fmt::Debug| SliceRefusal::Unparsable(format!("{e:?}"));
    // The slice type is checked from the context-free prefix first, so a B
    // slice is refused as such whatever follows it.
    let prefix = parse_slice_header_prefix(nal).map_err(|e| unparsable(&e))?;
    if !slice_type_allowed(prefix.slice_type) {
        return Err(SliceRefusal::SliceType(prefix.slice_type));
    }
    let refnal = RefNal::new(nal, &[], true);
    let header = refnal.header().map_err(|e| unparsable(&e))?;
    let mut bits = refnal.rbsp_bits();
    let (sh, sps, pps) =
        SliceHeader::from_bits(ctx, &mut bits, header, None).map_err(|e| unparsable(&e))?;
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
