//! Oracle: ffmpeg's view of each committed fixture (its manifest) vs kvm-proto.
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn manifests() -> Vec<serde_json::Value> {
    let mut v: Vec<_> = std::fs::read_dir(root())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.to_string_lossy().ends_with(".manifest.json"))
        .map(|p| serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap())
        .collect();
    v.sort_by_key(|m: &serde_json::Value| m["name"].as_str().unwrap().to_owned());
    v
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(root().join(name)).unwrap()
}

/// NAL payloads of an Annex-B stream (3- or 4-byte start codes).
fn nals(b: &[u8]) -> Vec<&[u8]> {
    let mut starts = Vec::new(); // (start-code begin, payload begin)
    let mut i = 0;
    while i + 3 <= b.len() {
        if b[i] == 0 && b[i + 1] == 0 && b[i + 2] == 1 {
            let begin = if i > 0 && b[i - 1] == 0 { i - 1 } else { i };
            starts.push((begin, i + 3));
            i += 3;
        } else {
            i += 1;
        }
    }
    starts
        .iter()
        .enumerate()
        .map(|(k, &(_, p))| {
            let end = starts.get(k + 1).map_or(b.len(), |&(s, _)| s);
            &b[p..end]
        })
        .collect()
}

fn nal_type(n: &[u8]) -> u8 {
    n[0] & 0x1F
}

#[test]
fn committed_bytes_match_their_manifests() {
    let ms = manifests();
    assert_eq!(ms.len(), 11, "expected 11 committed fixtures");
    for m in &ms {
        let name = m["name"].as_str().unwrap();
        let bytes = read(name);
        assert_eq!(
            bytes.len() as u64,
            m["bytes"].as_u64().unwrap(),
            "{name} size"
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            m["sha256"].as_str().unwrap(),
            "{name} sha256 — regenerate with scripts/gen-fixtures.sh on the locked flake"
        );
    }
}

#[test]
fn kvm_proto_sps_parser_agrees_with_ffmpeg() {
    for m in manifests() {
        let name = m["name"].as_str().unwrap();
        if !name.ends_with(".h264") {
            continue;
        }
        let bytes = read(name);
        let sps = nals(&bytes)
            .into_iter()
            .find(|n| nal_type(n) == 7)
            .unwrap_or_else(|| panic!("{name}: no SPS"));
        if m.get("ffmpeg_level_vui_sps_hex").is_some() {
            continue; // the ES3-like fixture: es3like_fixture_is_refused_as_sent_and_rewritten_like_ffmpeg
        }
        let s = kvm_proto::h264::parse_sps(sps).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        // gen-fixtures asks x264 for BT.709 on every encode; a literal check
        // catches a dropped colorprim/colormatrix param the manifest would
        // simply repeat.
        assert_eq!(
            s.colour_primaries,
            Some(1),
            "{name} colour_primaries literal"
        );
        assert_eq!(
            s.matrix_coefficients,
            Some(1),
            "{name} matrix_coefficients literal"
        );
        assert_eq!(
            u64::from(s.width),
            m["width"].as_u64().unwrap(),
            "{name} width"
        );
        assert_eq!(
            u64::from(s.height),
            m["height"].as_u64().unwrap(),
            "{name} height"
        );
        assert_eq!(
            u64::from(s.profile_idc),
            m["profile_idc"].as_u64().unwrap(),
            "{name} profile"
        );
        assert_eq!(
            u64::from(s.level_idc),
            m["level_idc"].as_u64().unwrap(),
            "{name} level"
        );
        assert_eq!(
            u64::from(s.pic_order_cnt_type),
            m["pic_order_cnt_type"].as_u64().unwrap(),
            "{name} poc"
        );
        let full = m["video_full_range_flag"].as_u64().map(|v| v == 1);
        assert_eq!(s.video_full_range_flag, full, "{name} full range");
        let restriction = m["bitstream_restriction_flag"].as_u64() == Some(1);
        assert_eq!(
            s.max_num_reorder_frames.is_some(),
            restriction,
            "{name} bitstream_restriction"
        );

        // Controller ruling (VUI coverage): gen-fixtures.sh sets a bt709
        // colour description (colorprim/transfer/colormatrix=bt709) on every
        // encode and requests no HRD on any of them. Rather than hard-coding
        // `Some(1)` here, the expectation is derived from the manifest's
        // colour_primaries/matrix_coefficients fields (trace_headers' own
        // view, extended into the manifest schema for this purpose) so a
        // fixture that ever stopped carrying a colour description (e.g. if
        // the h264_metadata-based A/B twin were built differently) would
        // still be checked correctly instead of silently passing against a
        // hard-coded value.
        let colour_primaries = m["colour_primaries"].as_u64();
        assert_eq!(
            s.colour_primaries.map(u64::from),
            colour_primaries,
            "{name} colour_primaries"
        );
        let matrix_coefficients = m["matrix_coefficients"].as_u64();
        assert_eq!(
            s.matrix_coefficients.map(u64::from),
            matrix_coefficients,
            "{name} matrix_coefficients"
        );
        assert!(!s.nal_hrd_present, "{name} nal_hrd_present");
        assert!(!s.vcl_hrd_present, "{name} vcl_hrd_present");
    }
}

#[test]
fn colour_twin_differs_only_in_the_sps() {
    let a = read("360p30_main_limited.h264");
    let b = read("360p30_main_limited_flagfull.h264");
    let (na, nb) = (nals(&a), nals(&b));
    assert_eq!(na.len(), nb.len());
    for (x, y) in na.iter().zip(nb.iter()) {
        if nal_type(x) == 7 {
            continue;
        }
        assert_eq!(x, y, "non-SPS NAL differs between the A/B twins");
    }
}

#[test]
fn norepeat_has_one_sps_and_main_repeats_per_idr() {
    let one = nals(&read("360p30_main_norepeat.h264"))
        .into_iter()
        .filter(|n| nal_type(n) == 7)
        .count();
    assert_eq!(one, 1);
    let main = nals(&read("360p30_main_full.h264"))
        .into_iter()
        .filter(|n| nal_type(n) == 7)
        .count();
    assert_eq!(main, 3, "repeat-headers=1 with keyint 30 over 90 frames");
}

#[test]
fn slice_fixture_stays_within_the_per_au_nal_limit() {
    // AUs are AUD-delimited (aud=1); §6.2 caps 128 NALs per AU.
    let mut per_au = 0usize;
    let mut max = 0usize;
    for n in nals(&read("360p30_main_slices.h264")) {
        if nal_type(n) == 9 {
            per_au = 0;
        }
        per_au += 1;
        max = max.max(per_au);
    }
    assert!(max > 3, "expected several slices per AU, got {max}");
    assert!(
        max <= 128,
        "slice fixture exceeds §6.2's 128 NALs/AU: {max}"
    );
}

#[test]
fn es3like_fixture_is_refused_as_sent_and_rewritten_like_ffmpeg() {
    use kvm_proto::h264::rewrite::{RewriteConfig, rewrite_sps};
    let m = manifests()
        .into_iter()
        .find(|m| m["name"] == "360p30_es3like_poc0.h264")
        .unwrap();
    // The manifest is ffmpeg's view of the stream as generated: ES3-shaped.
    assert_eq!(
        (
            m["profile_idc"].as_u64(),
            m["level_idc"].as_u64(),
            m["pic_order_cnt_type"].as_u64()
        ),
        (Some(66), Some(21), Some(0))
    );
    assert_eq!(m["bitstream_restriction_flag"].as_u64(), Some(0));
    assert_eq!(
        (
            m["colour_primaries"].as_u64(),
            m["matrix_coefficients"].as_u64()
        ),
        (Some(5), Some(5))
    );
    assert_eq!(
        (m["keyint"].as_u64(), m["key_frames"].as_u64()),
        (Some(60), Some(2))
    );
    let bytes = read("360p30_es3like_poc0.h264");
    let sps = nals(&bytes).into_iter().find(|n| nal_type(n) == 7).unwrap();
    // Like the ES3's own SPS, h264-reader refuses it as sent (§6.8).
    assert!(kvm_proto::h264::parse_sps(sps).is_err());
    // kvm-proto's level + VUI rewrite is byte-identical to ffmpeg's
    // h264_metadata doing the same (an independent serialiser).
    let lv = rewrite_sps(
        sps,
        &RewriteConfig {
            restriction: false,
            ..RewriteConfig::ES3
        },
    )
    .unwrap();
    let hex: String = lv.nal.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, m["ffmpeg_level_vui_sps_hex"].as_str().unwrap());
    // The full rewrite: level 30 for 640×368 at 30 fps, BT.709 limited,
    // bitstream_restriction 0 / 1 added (gen-fixtures checks the same with
    // trace_headers and an unchanged decode).
    let full = rewrite_sps(sps, &RewriteConfig::ES3).unwrap();
    let s = &full.summary;
    assert_eq!(
        (s.width, s.height, s.level_idc, s.pic_order_cnt_type),
        (640, 360, 30, 0)
    );
    assert_eq!(s.video_full_range_flag, Some(false));
    assert_eq!(
        (s.colour_primaries, s.matrix_coefficients),
        (Some(1), Some(1))
    );
    assert_eq!(
        (s.max_num_reorder_frames, s.max_dec_frame_buffering),
        (Some(0), Some(1))
    );
}
