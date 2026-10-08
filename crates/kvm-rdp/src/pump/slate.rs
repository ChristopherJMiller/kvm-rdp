//! The connecting slate (§6.4): a pre-encoded 1920×1080 "Connecting to
//! KVM…" IDR built by `gen-fixtures`, sent on the first Setup when the
//! surface has its size. Rebuilt once into §6.3's form — allowlisted NALs
//! only, 4-byte start codes. Not a KVM frame: it does not arm suppression
//! and does not count for delivery.
use kvm_proto::h264::{is_vcl, nal_type_allowed, parse_sps, split_annex_b};

const SLATE: &[u8] = include_bytes!("../../../../fixtures/slate_1080p.h264");

pub struct Slate {
    pub annex_b: Vec<u8>,
    pub size: (u16, u16),
}

impl Slate {
    #[must_use]
    pub fn embedded() -> Option<Slate> {
        Slate::from_annex_b(SLATE)
    }

    #[must_use]
    pub fn from_annex_b(data: &[u8]) -> Option<Slate> {
        let mut annex_b = Vec::with_capacity(data.len());
        let mut size = None;
        let mut picture = false;
        for nal in split_annex_b(data) {
            let t = nal.first()? & 0x1F;
            if !nal_type_allowed(t) {
                continue;
            }
            if t == 7 {
                let s = parse_sps(nal).ok()?;
                size = Some((u16::try_from(s.width).ok()?, u16::try_from(s.height).ok()?));
            }
            picture |= is_vcl(t);
            annex_b.extend_from_slice(&[0, 0, 0, 1]);
            annex_b.extend_from_slice(nal);
        }
        if !picture {
            return None;
        }
        Some(Slate {
            annex_b,
            size: size?,
        })
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

    /// §6.4: the slate is a 1920×1080 IDR; only allowlisted NALs survive
    /// (x264's SEI does not), each behind a 4-byte start code (§6.3).
    #[test]
    fn the_embedded_slate_is_a_1080p_idr_with_allowlisted_nals_only() {
        let s = Slate::embedded().unwrap();
        assert_eq!(s.size, (1920, 1080));
        assert_eq!(s.annex_b[..4], [0, 0, 0, 1]);
        let types: Vec<u8> = split_annex_b(&s.annex_b).map(|n| n[0] & 0x1F).collect();
        assert!(
            types.contains(&5) && types.contains(&7) && types.contains(&8),
            "{types:?}"
        );
        assert!(
            types.iter().all(|t| matches!(t, 1 | 5 | 7 | 8 | 9)),
            "{types:?}"
        );
    }

    #[test]
    fn a_stream_without_a_picture_is_no_slate() {
        assert!(Slate::from_annex_b(&[0, 0, 0, 1, 0x09, 0x10]).is_none());
        assert!(Slate::from_annex_b(&[]).is_none());
    }

    /// §6.3/§6.4 (m3): the embedded slate's NAL sequence is pinned exactly
    /// (AUD, SPS, PPS, IDR — the SEI dropped), and removing its one VCL NAL
    /// — leaving every other allowlisted NAL intact — still has no slate.
    /// `a_stream_without_a_picture_is_no_slate` above only ever fails
    /// earlier, on the missing SPS; this reaches the picture check itself.
    #[test]
    fn removing_the_only_picture_nal_from_the_slate_leaves_no_slate() {
        let s = Slate::embedded().unwrap();
        let types: Vec<u8> = split_annex_b(&s.annex_b).map(|n| n[0] & 0x1F).collect();
        assert_eq!(types, [9, 7, 8, 5]);

        let mut without_idr = Vec::new();
        for nal in split_annex_b(&s.annex_b) {
            if nal.first().map(|b| b & 0x1F) == Some(5) {
                continue;
            }
            without_idr.extend_from_slice(&[0, 0, 0, 1]);
            without_idr.extend_from_slice(nal);
        }
        assert!(Slate::from_annex_b(&without_idr).is_none());
    }
}
