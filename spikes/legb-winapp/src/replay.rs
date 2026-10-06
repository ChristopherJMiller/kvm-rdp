use std::path::Path;

use anyhow::Context as _;
use bytes::Bytes;

pub struct AccessUnit {
    pub annex_b: Bytes,
    pub is_idr: bool,
}

/// Split a trusted Annex-B fixture (4-byte start codes) into access units.
/// An AU boundary is the start of an AUD (NAL type 9) or an SPS (type 7) that
/// follows at least one VCL NAL. IDR = the AU contains a type-5 NAL.
pub fn load_fixture(path: &Path) -> anyhow::Result<Vec<AccessUnit>> {
    let raw = std::fs::read(path).with_context(|| format!("read fixture {}", path.display()))?;
    let starts = start_code_offsets(&raw);
    anyhow::ensure!(!starts.is_empty(), "no 4-byte start codes in fixture");

    // Real committed fixtures are all encoded with x264 `aud=1`
    // (scripts/gen-fixtures.sh), so an AUD (NAL type 9) always precedes
    // every access unit — including every slice of a multi-slice picture,
    // which must stay grouped under ONE AUD, not split per slice. Only a
    // fixture with no AUD anywhere falls back to one AU per VCL NAL ("one
    // AU per AUD, or per fixture record if no AUD").
    let has_aud = starts
        .iter()
        .any(|&(off, sc_len)| raw.get(off + sc_len).map(|b| b & 0x1f) == Some(9));

    let mut units: Vec<AccessUnit> = Vec::new();
    let mut cur_start = starts[0].0;
    let mut cur_has_vcl = false;
    let mut cur_is_idr = false;

    let push = |units: &mut Vec<AccessUnit>, data: &[u8], idr: bool| {
        units.push(AccessUnit {
            annex_b: Bytes::copy_from_slice(data),
            is_idr: idr,
        });
    };

    for (i, &(off, sc_len)) in starts.iter().enumerate() {
        let nal_type = raw.get(off + sc_len).map(|b| b & 0x1f).unwrap_or(0);
        let boundary = if has_aud {
            (nal_type == 9 || nal_type == 7) && cur_has_vcl
        } else {
            (nal_type == 1 || nal_type == 5) && cur_has_vcl
        };
        if boundary && off > cur_start {
            push(&mut units, &raw[cur_start..off], cur_is_idr);
            cur_start = off;
            cur_has_vcl = false;
            cur_is_idr = false;
        }
        if nal_type == 1 || nal_type == 5 {
            cur_has_vcl = true;
            if nal_type == 5 {
                cur_is_idr = true;
            }
        }
        if i + 1 == starts.len() {
            push(&mut units, &raw[cur_start..], cur_is_idr);
        }
    }

    anyhow::ensure!(!units.is_empty(), "fixture produced no access units");
    Ok(units)
}

/// Returns `(start_code_offset, start_code_len)` pairs. Annex-B legally mixes
/// 3-byte (`00 00 01`) and 4-byte (`00 00 00 01`) start codes — real x264/
/// ffmpeg output here only long-prefixes the first NAL of each AVPacket
/// (AUD/SPS/PPS) and short-prefixes the rest (SEI, slices), so matching only
/// the 4-byte form (as a naive scanner would) silently drops every slice NAL
/// and collapses the whole fixture into a single bogus access unit.
fn start_code_offsets(buf: &[u8]) -> Vec<(usize, usize)> {
    let mut v = Vec::new();
    let mut i = 0usize;
    while i + 3 <= buf.len() {
        if buf[i] == 0 && buf[i + 1] == 0 {
            if i + 4 <= buf.len() && buf[i + 2] == 0 && buf[i + 3] == 1 {
                v.push((i, 4));
                i += 4;
                continue;
            }
            if buf[i + 2] == 1 {
                v.push((i, 3));
                i += 3;
                continue;
            }
        }
        i += 1;
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_idr_then_p() {
        // SPS, PPS, IDR slice, then a P slice — two AUs, first is an IDR.
        let mut f = Vec::new();
        for (ty, body) in [
            (7u8, &[0x42u8][..]),
            (8, &[0x00]),
            (5, &[0x11]),
            (1, &[0x22]),
        ] {
            f.extend_from_slice(&[0, 0, 0, 1]);
            f.push(0x60 | ty); // nal_ref_idc set + type
            f.extend_from_slice(body);
        }
        let aus = load_fixture_from_bytes(&f);
        assert_eq!(aus.len(), 2);
        assert!(aus[0].is_idr);
        assert!(!aus[1].is_idr);
    }

    // Test seam so we don't touch the filesystem in a unit test.
    fn load_fixture_from_bytes(raw: &[u8]) -> Vec<AccessUnit> {
        let path = std::env::temp_dir().join("legb_fixture_test.h264");
        std::fs::write(&path, raw).unwrap();
        let r = super::load_fixture(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        r
    }
}

// Regression test for a real bug found while implementing this loader: real
// committed fixtures mix 3-byte and 4-byte Annex-B start codes (x264/ffmpeg
// only long-prefixes the first NAL of each AVPacket — AUD/SPS/PPS — and
// short-prefixes the rest, including every slice). A scanner that only
// recognises the 4-byte form never sees a single slice NAL and collapses
// each of these fixtures into one bogus access unit. Checked against each
// fixture's own manifest (`frames` / `key_frames`).
#[cfg(test)]
mod real_fixture_regression {
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures")).join(name)
    }

    fn check(name: &str, want_aus: usize, want_idr: usize) {
        let aus = super::load_fixture(&fixture(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(aus.len(), want_aus, "{name}: AU count");
        assert_eq!(
            aus.iter().filter(|a| a.is_idr).count(),
            want_idr,
            "{name}: IDR count"
        );
    }

    #[test]
    fn multi_slice_fixture_groups_under_aud() {
        // 90 frames, 12 slices/AU, 3 key frames.
        check("360p30_main_slices.h264", 90, 3);
    }

    #[test]
    fn long_gop_fixture() {
        check("360p30_main_longgop.h264", 330, 2);
    }

    #[test]
    fn norepeat_fixture_with_spliced_headers() {
        check("360p30_main_norepeat.h264", 90, 3);
    }

    #[test]
    fn single_frame_slate_fixture() {
        check("slate_1080p.h264", 1, 1);
    }
}
