//! H.264 helpers: AVCC→Annex-B, NAL header/allowlist, SPS inspection and
//! change classification, slice-header prefix. Parsers face attacker input
//! (spec §2, §6.1, §6.2); the crate-root deny lints apply here too.

mod annexb;
pub use annexb::{AnnexBNals, AvccError, avcc_to_annex_b, frame_id, split_annex_b};
mod nal;
pub use nal::{NalHeader, NalHeaderError};
pub use nal::{is_aud, is_idr, is_parameter_set, is_vcl, nal_type_allowed};
mod sps;
pub use sps::{PinnedField, SpsChange, SpsIncompatibleReason, classify_sps_change};
pub use sps::{SpsLimitViolation, SpsLimits, check_sps_limits};
pub use sps::{SpsParseError, SpsSummary, SpsSummaryError, parse_sps};
mod slice;
pub use slice::{
    SliceHeaderPrefix, SliceParseError, parse_slice_header_prefix, slice_type_allowed,
};

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests {
    #[test]
    fn module_is_reachable() {
        assert_eq!(module_path!(), "kvm_proto::h264::tests");
    }
}
