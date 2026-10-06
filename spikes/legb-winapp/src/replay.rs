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
///
/// SPS/PPS are retained across AUs as they're seen and re-prepended on any
/// IDR AU that doesn't already carry its own copy (immediately after any
/// leading AUD) — a fixture like `360p30_main_norepeat.h264`
/// (repeat-headers=0) only has in-band SPS/PPS once, at the very start, so
/// its later IDRs would otherwise be undecodable on their own (brief
/// B14-brief.md:198; B14-review.md Important finding).
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
    let mut last_sps: Option<Vec<u8>> = None;
    let mut last_pps: Option<Vec<u8>> = None;

    let push = |units: &mut Vec<AccessUnit>,
                data: &[u8],
                idr: bool,
                last_sps: &Option<Vec<u8>>,
                last_pps: &Option<Vec<u8>>| {
        let bytes = if idr {
            ensure_leading_sps_pps(data, last_sps, last_pps)
        } else {
            data.to_vec()
        };
        units.push(AccessUnit {
            annex_b: Bytes::from(bytes),
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
            push(
                &mut units,
                &raw[cur_start..off],
                cur_is_idr,
                &last_sps,
                &last_pps,
            );
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
        if nal_type == 7 || nal_type == 8 {
            // Remember this NAL's own bytes (start code included) so a
            // later IDR AU that doesn't repeat its own copy can still get
            // one prepended.
            let nal_end = starts.get(i + 1).map(|&(o, _)| o).unwrap_or(raw.len());
            let nal_bytes = raw.get(off..nal_end).unwrap_or(&[]).to_vec();
            if nal_type == 7 {
                last_sps = Some(nal_bytes);
            } else {
                last_pps = Some(nal_bytes);
            }
        }
        if i + 1 == starts.len() {
            push(
                &mut units,
                &raw[cur_start..],
                cur_is_idr,
                &last_sps,
                &last_pps,
            );
        }
    }

    anyhow::ensure!(!units.is_empty(), "fixture produced no access units");
    Ok(units)
}

/// True if `data` (one AU's own Annex-B bytes) already begins — after
/// skipping at most one leading AUD (type 9) — with an SPS (type 7) NAL
/// immediately followed by a PPS (type 8) NAL.
fn starts_with_sps_pps(data: &[u8]) -> bool {
    let starts = start_code_offsets(data);
    let nal_type_at = |idx: usize| -> Option<u8> {
        let &(off, sc_len) = starts.get(idx)?;
        data.get(off + sc_len).map(|b| b & 0x1f)
    };
    let idx = if nal_type_at(0) == Some(9) { 1 } else { 0 };
    nal_type_at(idx) == Some(7) && nal_type_at(idx + 1) == Some(8)
}

/// If `data` (one IDR AU's own bytes) doesn't already carry a leading
/// SPS/PPS pair, prepend the most recently-seen ones (right after a leading
/// AUD, if `data` has one) so the AU is independently decodable.
fn ensure_leading_sps_pps(
    data: &[u8],
    last_sps: &Option<Vec<u8>>,
    last_pps: &Option<Vec<u8>>,
) -> Vec<u8> {
    if starts_with_sps_pps(data) {
        return data.to_vec();
    }
    let (Some(sps), Some(pps)) = (last_sps, last_pps) else {
        // Nothing seen yet to prepend (e.g. an IDR before any SPS/PPS at
        // all) — leave as-is rather than fabricate parameter sets.
        return data.to_vec();
    };

    let starts = start_code_offsets(data);
    let has_leading_aud = starts
        .first()
        .and_then(|&(off, sc_len)| data.get(off + sc_len))
        .map(|b| b & 0x1f)
        == Some(9);
    let insert_at = if has_leading_aud {
        starts.get(1).map(|&(off, _)| off).unwrap_or(data.len())
    } else {
        0
    };

    let mut out = Vec::with_capacity(data.len() + sps.len() + pps.len());
    out.extend_from_slice(data.get(..insert_at).unwrap_or(data));
    out.extend_from_slice(sps);
    out.extend_from_slice(pps);
    out.extend_from_slice(data.get(insert_at..).unwrap_or(&[]));
    out
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

    /// NAL types of an AU's own bytes, in order (reuses the production
    /// scanner — no duplicated start-code logic in the test).
    fn nal_type_sequence(data: &[u8]) -> Vec<u8> {
        super::start_code_offsets(data)
            .into_iter()
            .map(|(off, sc_len)| data.get(off + sc_len).map(|b| b & 0x1f).unwrap_or(0))
            .collect()
    }

    // Fix round 1 (B14-review.md, Important): the brief requires SPS/PPS to
    // be "retained and re-prepended on IDR AUs" so every IDR is
    // independently decodable, but the splitter only keeps SPS/PPS attached
    // to whichever AU they happen to sit next to *in the source bytes*.
    // `360p30_main_norepeat.h264` (repeat-headers=0) has SPS/PPS spliced in
    // only once, ahead of frame 0 — its later IDRs (frame 30, frame 60) have
    // none of their own, so a ship loop resuming/looping at one of them
    // would hand the client an undecodable IDR.
    #[test]
    fn norepeat_idr_aus_carry_leading_sps_pps() {
        let aus = super::load_fixture(&fixture("360p30_main_norepeat.h264")).unwrap();
        let idr_aus: Vec<_> = aus.iter().enumerate().filter(|(_, au)| au.is_idr).collect();
        assert_eq!(
            idr_aus.len(),
            3,
            "sanity: norepeat has 3 IDR AUs (frames 0/30/60)"
        );
        for (n, au) in idr_aus {
            let types = nal_type_sequence(&au.annex_b);
            // Skip at most one leading AUD (type 9) before checking for SPS, PPS.
            let rest: &[u8] = if types.first() == Some(&9) {
                &types[1..]
            } else {
                &types[..]
            };
            assert_eq!(
                rest.first_chunk::<2>(),
                Some(&[7u8, 8u8]),
                "IDR AU #{n} must start with SPS then PPS (after any leading AUD); got {rest:?}"
            );
        }
    }

    #[test]
    fn idr_au_with_native_sps_pps_is_not_doubled() {
        let aus = super::load_fixture(&fixture("360p30_main_norepeat.h264")).unwrap();
        // AU #0 (frame 0) already carries its own SPS/PPS natively (the
        // splice is ahead of the whole stream, so they land in this AU) —
        // the re-prepend fix must not stack a second copy on top of it.
        let types = nal_type_sequence(&aus[0].annex_b);
        assert_eq!(
            types.iter().filter(|&&t| t == 7).count(),
            1,
            "exactly one SPS, not doubled"
        );
        assert_eq!(
            types.iter().filter(|&&t| t == 8).count(),
            1,
            "exactly one PPS, not doubled"
        );
    }
}
