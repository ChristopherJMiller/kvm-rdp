//! H.264 helpers: AVCC→Annex-B, NAL header/allowlist, SPS inspection and
//! change classification, slice-header prefix. Parsers face attacker input
//! (spec §2, §6.1, §6.2); the crate-root deny lints apply here too.

mod annexb;
pub use annexb::{AvccError, avcc_to_annex_b};
mod nal;
pub use nal::{NalHeader, NalHeaderError};
pub use nal::{is_aud, is_idr, is_parameter_set, is_vcl, nal_type_allowed};

#[cfg(test)]
mod tests {
    #[test]
    fn module_is_reachable() {
        assert_eq!(module_path!(), "kvm_proto::h264::tests");
    }
}
