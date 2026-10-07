//! §6.1 PPS admission: parsed by h264-reader against the active (rewritten)
//! SPS, then held to the rules the ES3 meets (`census.md`: one slice group,
//! no scaling matrices).
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use h264_reader::Context;
use h264_reader::nal::pps::{PicParameterSet, PpsError};
use h264_reader::nal::{Nal as _, RefNal};

/// Why a PPS was refused (`stream_incompatible`, §6.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PpsRefusal {
    /// It names an SPS id that is not the active SPS.
    UnknownSps(u8),
    /// h264-reader could not parse it (its error, as text).
    Unparsable(String),
    /// `num_slice_groups_minus1 != 0`.
    SliceGroups,
    /// A `num_ref_idx_l{0,1}_default_active_minus1` above 15 (frames only).
    NumRefIdx(u32),
    /// `pic_scaling_matrix_present_flag == 1`.
    ScalingMatrix,
}

/// Highest `num_ref_idx_lX_default_active_minus1` for frame coding.
const MAX_NUM_REF_IDX_MINUS1: u32 = 15;

/// Parse a wire PPS NAL against `ctx` (holding the active SPS) and check it.
pub fn check_pps(ctx: &Context, nal: &[u8]) -> Result<PicParameterSet, PpsRefusal> {
    if nal.is_empty() {
        return Err(PpsRefusal::Unparsable("empty".into()));
    }
    let pps =
        PicParameterSet::from_bits(ctx, RefNal::new(nal, &[], true).rbsp_bits()).map_err(|e| {
            match e {
                PpsError::UnknownSeqParamSetId(id) => PpsRefusal::UnknownSps(id.id()),
                other => PpsRefusal::Unparsable(format!("{other:?}")),
            }
        })?;
    if pps.slice_groups.is_some() {
        return Err(PpsRefusal::SliceGroups);
    }
    for n in [
        pps.num_ref_idx_l0_default_active_minus1,
        pps.num_ref_idx_l1_default_active_minus1,
    ] {
        if n > MAX_NUM_REF_IDX_MINUS1 {
            return Err(PpsRefusal::NumRefIdx(n));
        }
    }
    if pps
        .extension
        .as_ref()
        .is_some_and(|x| x.pic_scaling_matrix.is_some())
    {
        return Err(PpsRefusal::ScalingMatrix);
    }
    Ok(pps)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::h264::rewrite::{RewriteConfig, rewrite_sps};
    use crate::h264::test_support::{PpsCfg, SpsCfg};

    fn ctx_for(sps: &[u8]) -> Context {
        let r = rewrite_sps(sps, &RewriteConfig::ES3).unwrap();
        let mut ctx = Context::new();
        ctx.put_seq_param_set(r.parsed);
        ctx
    }

    #[test]
    fn the_es3_pps_passes_with_or_without_its_trailing_zeros() {
        // census.md sps_hex / pps_hex
        let ctx = ctx_for(&[
            0x67, 0x42, 0x00, 0x1f, 0x96, 0x54, 0x03, 0xc0, 0x11, 0x2f, 0x2c, 0xdc, 0x14, 0x18,
            0x14, 0x08, 0x00,
        ]);
        let p = check_pps(&ctx, &[0x68, 0xce, 0x31, 0x12, 0x00, 0x00]).unwrap();
        assert!(!p.entropy_coding_mode_flag); // CAVLC
        assert!(p.deblocking_filter_control_present_flag);
        assert_eq!(p.chroma_qp_index_offset, 4);
        check_pps(&ctx, &[0x68, 0xce, 0x31, 0x12]).unwrap();
    }

    #[test]
    fn each_pps_rule_has_its_own_refusal() {
        let ctx = ctx_for(&SpsCfg::main_1080p().build());
        assert_eq!(
            check_pps(&ctx, &PpsCfg::default().build())
                .unwrap()
                .pic_parameter_set_id
                .id(),
            0
        );
        let refused = |c: PpsCfg| check_pps(&ctx, &c.build()).unwrap_err();
        assert_eq!(
            refused(PpsCfg {
                sps_id: 1,
                ..PpsCfg::default()
            }),
            PpsRefusal::UnknownSps(1)
        );
        assert_eq!(
            refused(PpsCfg {
                slice_groups: true,
                ..PpsCfg::default()
            }),
            PpsRefusal::SliceGroups
        );
        assert_eq!(
            refused(PpsCfg {
                num_ref_idx_l0_default_active_minus1: 16,
                ..PpsCfg::default()
            }),
            PpsRefusal::NumRefIdx(16)
        );
        assert_eq!(
            refused(PpsCfg {
                scaling_matrix: true,
                ..PpsCfg::default()
            }),
            PpsRefusal::ScalingMatrix
        );
        assert!(matches!(
            check_pps(&ctx, &[0x68]),
            Err(PpsRefusal::Unparsable(_))
        ));
        assert!(matches!(
            check_pps(&ctx, &[]),
            Err(PpsRefusal::Unparsable(_))
        ));
    }
}
