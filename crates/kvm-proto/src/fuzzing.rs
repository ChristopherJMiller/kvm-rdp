//! Fuzz-target bodies with their output invariants (§11.2 L0 fuzz). Each
//! function takes arbitrary bytes and panics only when an invariant breaks —
//! a panic is a finding. `fuzz/` calls them from libFuzzer; the unit tests
//! below run them over the committed seeds on stable, so every target is
//! exercised by plain `cargo test` too. Test-oracle code, not a parser: it
//! may panic by design, so it alone in kvm-proto opts out of the crate's
//! lint denies (deviation D8); only `fuzz/` enables its feature.
//!
//! The `pps` and `login` invariants restate the rule the code enforces;
//! those targets exist for panic and ASan freedom (preflight P5).
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use crate::flv::mux::{
    TAG_VIDEO, avc_end_of_sequence_body, avc_nalu_body, avc_sequence_header_body, write_flv_header,
    write_tag,
};
use crate::flv::{FlvDemuxer, FlvLimits, TagBody, VideoBody};
use crate::h264::rewrite::{RewriteConfig, RewriteError, rewrite_sps};
use crate::h264::sanitize::{NalVerdict, check_nal};
use crate::h264::sps_syntax::{BitstreamRestriction, ColourDescription, SpsSyntax};
use crate::h264::{SpsPins, avcc_to_annex_b, split_annex_b};
use crate::video::{AdmissionConfig, ParamSets, VideoAdmission};
use std::sync::OnceLock;
use std::time::Instant;

/// Feed the bytes after a selector byte to a demuxer with a 64 KiB tag
/// limit, in chunks of `1 + 16 × selector` bytes, draining after every chunk
/// as a consumer does: a body-level error leaves the stream aligned, a
/// framing error poisons the demuxer and empties its buffer. After each
/// drain the buffer holds less than one maximal tag — a bound that
/// `fuzz.sh`'s 256 KiB inputs can reach.
pub fn flv_demux(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let limits = FlvLimits {
        max_tag_size: 64 * 1024,
        ..FlvLimits::default()
    };
    let tag_bound = 11 + limits.max_tag_size as usize + 4;
    let mut d = FlvDemuxer::new(limits);
    for c in rest.chunks(1 + usize::from(sel) * 16) {
        d.push(c);
        loop {
            match d.next_tag() {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) if d.buffered_len() == 0 => break,
                Err(_) => {}
            }
        }
        assert!(
            d.buffered_len() < tag_bound,
            "demuxer kept {} bytes after draining",
            d.buffered_len()
        );
    }
}

/// Demux and admit everything; check every emitted parameter set and access
/// unit against §6.2/§6.3's output invariants.
pub fn admission(data: &[u8]) {
    let mut d = FlvDemuxer::new(FlvLimits::default());
    let mut a = VideoAdmission::new(AdmissionConfig::default());
    a.flv_opened();
    d.push(data);
    let mut params: Option<ParamSets> = None;
    let mut pins: Option<SpsPins> = None;
    let mut out = Vec::new();
    let now = Instant::now();
    while let Ok(Some(tag)) = d.next_tag() {
        let Ok(admitted) = a.admit(tag, now) else {
            return;
        };
        if let Some(change) = admitted.params {
            let p = change.params;
            // The emitted SPS is exactly the admitted (rewritten) one.
            assert_eq!(SpsSyntax::parse(&p.sps).unwrap().to_nal(), p.sps.as_ref());
            let now_pins = SpsPins::of(&p.summary);
            assert_eq!(
                *pins.get_or_insert(now_pins),
                now_pins,
                "pinned field moved"
            );
            params = Some(p);
        }
        if let Some(au) = admitted.au {
            let p = params.as_ref().expect("an AU before any parameter sets");
            out.clear();
            au.write_annex_b(p, &mut out);
            let mut expected: Vec<&[u8]> = Vec::new();
            expected.extend(au.aud.as_deref());
            if au.idr {
                expected.push(&p.sps);
                expected.extend(p.pps.iter().map(|b| b.as_ref()));
            }
            expected.extend(au.vcl.iter().map(|n| n.bytes.as_ref()));
            let resplit: Vec<&[u8]> = split_annex_b(&out).collect();
            assert_eq!(resplit, expected, "Annex-B re-split differs");
            for nal in resplit {
                assert!(
                    matches!(nal[0] & 0x1F, 1 | 5 | 7 | 8 | 9),
                    "type {}",
                    nal[0] & 0x1F
                );
                assert!(
                    !crate::bits::contains_start_code(nal),
                    "start code in {nal:02x?}"
                );
            }
            assert!(!au.vcl.is_empty());
        }
    }
}

/// `avcc_to_annex_b`: on success the output re-splits to exactly the input
/// NALs; on error `out` is untouched.
pub fn avcc(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let ls = [1usize, 2, 4][sel as usize % 3];
    let mut out = vec![0xEE];
    match avcc_to_annex_b(rest, ls, &mut out) {
        Err(_) => assert_eq!(out, [0xEE]),
        Ok(()) => {
            let mut nals = Vec::new();
            let mut r = rest;
            while !r.is_empty() {
                let (len, tail) = r.split_at(ls);
                let n = len.iter().fold(0usize, |v, b| v << 8 | *b as usize);
                nals.push(&tail[..n]);
                r = &tail[n..];
            }
            let mut want = vec![0xEE];
            for n in nals {
                want.extend_from_slice(&[0, 0, 0, 1]);
                want.extend_from_slice(n);
            }
            assert_eq!(out, want);
        }
    }
}

/// The rewriter (§6.8, §11.2): the output re-parses with every field equal to
/// the input's except `level_idc` (never lower), the VUI's video signal type
/// and colour description, `bitstream_restriction`, and — on a profile
/// 66/77/88 SPS whose level was raised — `constraint_set3_flag` (bit 0x10),
/// which the rewriter clears on every such raise (rulings RB3 amendment).
pub fn sps_rewrite(data: &[u8]) {
    let Ok(input) = SpsSyntax::parse(data) else {
        assert!(rewrite_sps(data, &RewriteConfig::ES3).is_err());
        return;
    };
    let r = match rewrite_sps(data, &RewriteConfig::ES3) {
        Ok(r) => r,
        // Legitimate refusals of an SPS kvm-proto reads: no level admits its
        // size, the level is undefined or names a level above 5.1
        // (`UnknownLevel`, rulings RB3 amendment), h264-reader refuses the
        // output, or the output has no summary.
        Err(
            RewriteError::NoLevel { .. }
            | RewriteError::UnknownLevel(_)
            | RewriteError::H264Reader(_)
            | RewriteError::Summary(_),
        ) => {
            return;
        }
        // Anything else is a finding: kvm-proto's own writer and reader
        // disagree (`SelfCheck`), or h264-reader read other fields than were
        // written (`Disagrees`) — an asymmetric field or an escaping bug.
        Err(e) => panic!("rewrite of {data:02x?}: {e:?}"),
    };
    let out = SpsSyntax::parse(&r.nal).unwrap();
    assert!(out.level_idc >= input.level_idc);
    let out_vui = out.vui.unwrap_or_default();
    let signal = out_vui.video_signal_type.unwrap();
    assert!(!signal.video_full_range_flag);
    assert_eq!(
        signal.colour_description,
        Some(ColourDescription {
            colour_primaries: 1,
            transfer_characteristics: 1,
            matrix_coefficients: 1,
        })
    );
    let mut expect = input.clone();
    expect.level_idc = out.level_idc;
    // RB3 amendment: a level raise on a 66/77/88 SPS clears
    // constraint_set3_flag unconditionally (the bit is reserved once
    // level_idc != 11), not only when the input itself was level 1b.
    // `r.changed.level` is exactly the rewriter's own condition for this.
    if matches!(input.profile_idc, 66 | 77 | 88) && r.changed.level {
        expect.constraint_flags &= !0x10;
    }
    let ev = expect.vui.get_or_insert_with(Default::default);
    ev.video_signal_type = out_vui.video_signal_type;
    if ev.bitstream_restriction.is_none() {
        let dpb = input.max_num_ref_frames.max(1);
        assert_eq!(
            out_vui.bitstream_restriction,
            Some(BitstreamRestriction::inferred(0, dpb))
        );
        ev.bitstream_restriction = out_vui.bitstream_restriction;
    }
    assert_eq!(out, expect);
    assert!(!crate::bits::contains_start_code(&r.nal));
}

struct Ctx {
    ctx: h264_reader::Context,
    sps: h264_reader::nal::sps::SeqParameterSet,
}

fn contexts() -> &'static [Ctx] {
    static CTX: OnceLock<Vec<Ctx>> = OnceLock::new();
    CTX.get_or_init(|| {
        [ES3_LIKE_PARAMS, MAIN_360P_PARAMS]
            .into_iter()
            .map(|(sps, pps)| {
                let r = rewrite_sps(sps, &RewriteConfig::ES3).unwrap();
                let mut ctx = h264_reader::Context::new();
                ctx.put_seq_param_set(r.parsed.clone());
                let p = crate::h264::pps::check_pps(&ctx, pps).unwrap();
                ctx.put_pic_param_set(p);
                Ctx { ctx, sps: r.parsed }
            })
            .collect()
    })
}

/// The ES3-like fixture's SPS (as sent) and PPS (CAVLC Baseline, POC 0).
pub const ES3_LIKE_PARAMS: (&[u8], &[u8]) = (
    &[
        0x67, 0x42, 0x00, 0x15, 0xe9, 0x01, 0x40, 0x5f, 0xf2, 0xe0, 0x2d, 0xc1, 0x41, 0x81, 0x50,
        0x00, 0x00, 0x03, 0x00, 0x10, 0x00, 0x00, 0x03, 0x03, 0xc8, 0x40,
    ],
    &[0x68, 0xce, 0x3c, 0x80],
);
/// `360p30_main_full`'s SPS and PPS (CABAC Main, POC 2).
pub const MAIN_360P_PARAMS: (&[u8], &[u8]) = (
    &[
        0x67, 0x4d, 0x40, 0x1f, 0xda, 0x02, 0x80, 0xbf, 0xe5, 0xc0, 0x5b, 0x80, 0x80, 0x80, 0xa0,
        0x00, 0x00, 0x03, 0x00, 0x20, 0x00, 0x00, 0x07, 0x91, 0xe3, 0x06, 0x54,
    ],
    &[0x68, 0xef, 0x3c, 0x80],
);

/// Slice-header checks and the POC tracker against an admitted context:
/// the first byte picks the context, the rest is a run of slice NALs
/// separated as Annex B. Every POC the tracker admits exceeds the last one
/// it admitted in that GOP (§6.1), which an IDR starts — as does the picture
/// after an MMCO 5.
pub fn slice(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let c = &contexts()[sel as usize % 2];
    let mut poc = crate::h264::picture::PocTracker::default();
    let mut last: Option<i64> = None;
    for nal in split_annex_b(rest) {
        if let Ok(info) = crate::h264::picture::parse_slice(&c.ctx, nal) {
            if info.idr {
                last = None;
            }
            if let Ok(p) = poc.next(&c.sps, &info) {
                assert!(last.is_none_or(|l| p > l), "POC {p} after {last:?}");
                last = Some(if info.mmco5 { 0 } else { p });
                // Independent of the tracker's own ordering check
                // (preflight P5): type 0 frames: POC ≡ pic_order_cnt_lsb
                // (mod MaxPicOrderCntLsb); type 2: an IDR is 0, a reference
                // picture even, a non-reference one odd.
                match &c.sps.pic_order_cnt {
                    h264_reader::nal::sps::PicOrderCntType::TypeZero {
                        log2_max_pic_order_cnt_lsb_minus4: n,
                    } => assert_eq!(
                        p.rem_euclid(1_i64 << (u32::from(*n) + 4)),
                        i64::from(info.pic_order_cnt_lsb.unwrap_or(0)),
                        "POC {p} vs lsb"
                    ),
                    _ if info.idr => assert_eq!(p, 0),
                    _ => assert_eq!(
                        p.rem_euclid(2) == 0,
                        info.nal_ref_idc != 0,
                        "POC {p} parity"
                    ),
                }
            }
        }
    }
}

/// PPS admission against an admitted context (the first byte picks it): an
/// accepted PPS has one slice group, `num_ref_idx` defaults of at most 15
/// and no scaling matrix (§6.1).
pub fn pps(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let c = &contexts()[sel as usize % 2];
    if let Ok(p) = crate::h264::pps::check_pps(&c.ctx, rest) {
        assert!(p.slice_groups.is_none());
        assert!(p.num_ref_idx_l0_default_active_minus1 <= 15);
        assert!(p.num_ref_idx_l1_default_active_minus1 <= 15);
        assert!(
            p.extension
                .as_ref()
                .is_none_or(|x| x.pic_scaling_matrix.is_none())
        );
    }
}

/// The §6.2 NAL sanitiser: a kept NAL is non-empty, on the allowlist, free
/// of start-code patterns, and its input with only trailing zeros trimmed.
pub fn sanitize(data: &[u8]) {
    let nal = bytes::Bytes::copy_from_slice(data);
    if let Ok(NalVerdict::Keep(h, kept)) = check_nal(&nal) {
        assert!(!kept.is_empty());
        assert!(
            matches!(h.nal_unit_type, 1 | 5 | 7 | 8 | 9),
            "type {}",
            h.nal_unit_type
        );
        assert_eq!(kept[0] & 0x1F, h.nal_unit_type);
        assert!(!crate::bits::contains_start_code(&kept));
        assert!(data.starts_with(&kept));
        assert!(data[kept.len()..].iter().all(|&b| b == 0));
    }
}

/// `parse_login_token`: a token, when returned, is `0.` and digits.
pub fn login(data: &[u8]) {
    if let Ok(t) = crate::login::parse_login_token(data) {
        let s = t.as_str();
        assert!(s.len() > 2 && s.starts_with("0.") && s[2..].bytes().all(|b| b.is_ascii_digit()));
    }
}

/// Differential mux → demux: tags generated from the bytes, muxed, then
/// demuxed, must come back field for field.
pub fn mux_demux(data: &[u8]) {
    let mut it = data.iter().copied();
    let ls = [1u8, 2, 4][it.next().unwrap_or(0) as usize % 3];
    let mut next = |n: usize| -> Vec<u8> { (0..n).map(|_| it.next().unwrap_or(0)).collect() };
    let mut flv = Vec::new();
    write_flv_header(&mut flv, false, true);
    let mut want: Vec<(u32, Vec<Vec<u8>>, i32)> = Vec::new();
    let seq = avc_sequence_header_body(&[&[0x67, 0x42]], &[&[0x68, 0xce]], ls).unwrap();
    write_tag(&mut flv, TAG_VIDEO, 0, &seq).unwrap();
    for i in 1..=8u32 {
        let spec = next(2);
        if spec[0] == 0xFF {
            write_tag(&mut flv, TAG_VIDEO, i, &avc_end_of_sequence_body()).unwrap();
            want.push((i, vec![], 0));
            continue;
        }
        let count = 1 + spec[0] as usize % 4;
        let nals: Vec<Vec<u8>> = (0..count)
            .map(|_| {
                let len = 1 + next(1)[0] as usize % 40;
                let mut n = next(len);
                n[0] = 0x41;
                n
            })
            .collect();
        let ct = i32::from(spec[1] as i8);
        let refs: Vec<&[u8]> = nals.iter().map(Vec::as_slice).collect();
        let mut body = Vec::new();
        avc_nalu_body(&mut body, false, ct, &refs, ls).unwrap();
        write_tag(&mut flv, TAG_VIDEO, i, &body).unwrap();
        want.push((i, nals, ct));
    }
    let mut d = FlvDemuxer::new(FlvLimits::default());
    d.push(&flv);
    assert!(matches!(
        d.next_tag().unwrap().unwrap().body,
        TagBody::Video(VideoBody::SequenceHeader(_))
    ));
    for (ts, nals, ct) in want {
        let tag = d.next_tag().unwrap().unwrap();
        assert_eq!(tag.timestamp, ts);
        match tag.body {
            TagBody::Video(VideoBody::EndOfSequence) => assert!(nals.is_empty()),
            TagBody::Video(VideoBody::Nalus {
                composition_time,
                nals: got,
                ..
            }) => {
                assert_eq!(composition_time, ct);
                let got: Vec<Vec<u8>> = got.iter().map(|n| n.bytes.to_vec()).collect();
                assert_eq!(got, nals);
            }
            other => panic!("{other:?}"),
        }
    }
    assert!(d.next_tag().unwrap().is_none());
}

/// AUD-delimited access units (every committed fixture has AUDs). Same
/// AUD-delimited split as `tests/admission.rs::access_units`: integration
/// tests cannot reach this cfg-gated module, so the helper is duplicated
/// rather than shared (preflight P7).
fn access_units(data: &[u8]) -> Vec<Vec<&[u8]>> {
    let mut aus: Vec<Vec<&[u8]>> = Vec::new();
    for nal in split_annex_b(data) {
        let has_vcl = aus
            .last()
            .is_some_and(|au| au.iter().any(|n| matches!(n[0] & 0x1F, 1 | 5)));
        if aus.is_empty() || (nal[0] & 0x1F == 9 && has_vcl) {
            aus.push(Vec::new());
        }
        aus.last_mut().unwrap().push(nal);
    }
    aus
}

/// Seed inputs for every target, derived from the committed fixtures:
/// `(target, file name, bytes)`. `scripts/fuzz.sh` writes them under
/// `target/` (they are regenerated, never committed); the unit test below
/// runs every target over them.
#[must_use]
pub fn seeds() -> Vec<(&'static str, String, Vec<u8>)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let read = |name: &str| std::fs::read(dir.join(name)).unwrap();
    let es3 = read("360p30_es3like_poc0.h264");
    let main = read("360p30_main_full.h264");
    let slices = read("360p30_main_slices.h264");
    let mut out = Vec::new();
    let flv = |data: &[u8], aus: usize, ls: u8, ct: i32, keep: fn(u8) -> bool| {
        let nals: Vec<&[u8]> = split_annex_b(data).collect();
        let sps = *nals.iter().find(|n| n[0] & 0x1F == 7).unwrap();
        let pps = *nals.iter().find(|n| n[0] & 0x1F == 8).unwrap();
        let mut f = Vec::new();
        write_flv_header(&mut f, false, true);
        write_tag(
            &mut f,
            TAG_VIDEO,
            0,
            &avc_sequence_header_body(&[sps], &[pps], ls).unwrap(),
        )
        .unwrap();
        for (i, au) in access_units(data).into_iter().take(aus).enumerate() {
            let au: Vec<&[u8]> = au.into_iter().filter(|n| keep(n[0] & 0x1F)).collect();
            let mut b = Vec::new();
            avc_nalu_body(&mut b, i == 0, ct, &au, ls).unwrap();
            write_tag(&mut f, TAG_VIDEO, i as u32 * 33, &b).unwrap();
        }
        f
    };
    let flvs = [
        ("es3.flv", flv(&es3, 8, 4, 16, |t| matches!(t, 1 | 5))),
        ("slices.flv", flv(&slices, 4, 1, 0, |t| t != 6)),
        (
            "ffmpeg_head.flv",
            read("360p30_main_full.flv")[..32 * 1024].to_vec(),
        ),
    ];
    for (name, bytes) in flvs {
        // flv_demux's first byte picks the chunk size: 0x10 = 257 bytes.
        out.push(("flv_demux", name.to_owned(), [&[0x10][..], &bytes].concat()));
        out.push(("admission", name.to_owned(), bytes));
    }
    // An in-band parameter-set flood at §6.2's per-tag cap (4 SPS, 16 PPS)
    // ahead of the ES3-like IDR; the fuzzer grows it past the cap (D10).
    let (es3_sps, es3_pps) = ES3_LIKE_PARAMS;
    let mut flood: Vec<&[u8]> = vec![es3_sps; 4];
    flood.extend(std::iter::repeat_n(es3_pps, 16));
    flood.extend(
        access_units(&es3)[0]
            .iter()
            .copied()
            .filter(|n| n[0] & 0x1F == 5),
    );
    let mut f = Vec::new();
    write_flv_header(&mut f, false, true);
    let seq = avc_sequence_header_body(&[es3_sps], &[es3_pps], 4).unwrap();
    write_tag(&mut f, TAG_VIDEO, 0, &seq).unwrap();
    let mut b = Vec::new();
    avc_nalu_body(&mut b, true, 16, &flood, 4).unwrap();
    write_tag(&mut f, TAG_VIDEO, 0, &b).unwrap();
    out.push(("admission", "inband_flood.flv".to_owned(), f));
    for (sel, name, pps) in [
        (0u8, "es3like", ES3_LIKE_PARAMS.1),
        (0, "es3_census", &ES3_PPS[..]),
        (1, "main", MAIN_360P_PARAMS.1),
    ] {
        out.push(("pps", name.to_owned(), [&[sel][..], pps].concat()));
    }
    out.push(("sanitize", "es3_census_pps".to_owned(), ES3_PPS.to_vec()));
    for (i, nal) in access_units(&main)[0].iter().enumerate() {
        out.push(("sanitize", format!("main_au0_{i}"), nal.to_vec()));
    }
    let first_au: Vec<u8> = access_units(&es3)[0]
        .iter()
        .filter(|n| matches!(n[0] & 0x1F, 1 | 5))
        .flat_map(|n| [&(n.len() as u32).to_be_bytes()[..], n].concat())
        .collect();
    out.push((
        "avcc",
        "es3_idr".to_owned(),
        [&[2u8][..], &first_au].concat(),
    ));
    for (name, sps) in [
        ("es3_census", ES3_SPS.to_vec()),
        ("es3like", ES3_LIKE_PARAMS.0.to_vec()),
        ("main", MAIN_360P_PARAMS.0.to_vec()),
    ] {
        out.push(("sps_rewrite", name.to_owned(), sps));
    }
    for (sel, name, data) in [(0u8, "es3like", &es3), (1, "main", &main)] {
        let aus: Vec<u8> = access_units(data)
            .into_iter()
            .take(3)
            .flatten()
            .filter(|n| matches!(n[0] & 0x1F, 1 | 5))
            .flat_map(|n| [&[0u8, 0, 0, 1][..], n].concat())
            .collect();
        out.push(("slice", name.to_owned(), [&[sel][..], &aus].concat()));
    }
    out.push((
        "login",
        "ok".to_owned(),
        br#"{"result":0,"token":"0.123456789","role":"admin"}"#.to_vec(),
    ));
    out.push((
        "login",
        "refused".to_owned(),
        br#"{"result":"invalid password","code":200}"#.to_vec(),
    ));
    out.push((
        "mux_demux",
        "short".to_owned(),
        b"\x02\x03\x10seed".to_vec(),
    ));
    out.push(("mux_demux", "long".to_owned(), (0u8..=255).collect()));
    out
}

/// `census.md` `sps_hex`.
const ES3_SPS: [u8; 17] = [
    0x67, 0x42, 0x00, 0x1f, 0x96, 0x54, 0x03, 0xc0, 0x11, 0x2f, 0x2c, 0xdc, 0x14, 0x18, 0x14, 0x08,
    0x00,
];
/// `census.md` `pps_hex`, trailing zeros included.
const ES3_PPS: [u8; 6] = [0x68, 0xce, 0x31, 0x12, 0x00, 0x00];

/// Run `target`'s body on `data` (the fuzz binaries and the seed test).
pub fn run(target: &str, data: &[u8]) {
    match target {
        "flv_demux" => flv_demux(data),
        "admission" => admission(data),
        "avcc" => avcc(data),
        "sps_rewrite" => sps_rewrite(data),
        "pps" => pps(data),
        "sanitize" => sanitize(data),
        "slice" => slice(data),
        "login" => login(data),
        "mux_demux" => mux_demux(data),
        other => panic!("no fuzz target {other}"),
    }
}

/// Every target, for `scripts/fuzz.sh` and CI.
pub const TARGETS: [&str; 9] = [
    "flv_demux",
    "admission",
    "avcc",
    "sps_rewrite",
    "pps",
    "sanitize",
    "slice",
    "login",
    "mux_demux",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_target_runs_clean_over_its_seeds() {
        let seeds = seeds();
        for t in TARGETS {
            assert!(seeds.iter().any(|(s, _, _)| *s == t), "no seed for {t}");
        }
        for (target, _, bytes) in &seeds {
            run(target, bytes);
            // Truncations exercise every partial-input path.
            for cut in [1, bytes.len() / 3, bytes.len() / 2] {
                run(target, &bytes[..cut.min(bytes.len())]);
            }
        }
    }

    #[test]
    fn the_es3_seed_admits_end_to_end() {
        let es3 = seeds()
            .into_iter()
            .find(|(t, n, _)| *t == "admission" && n == "es3.flv")
            .unwrap()
            .2;
        let mut d = FlvDemuxer::new(FlvLimits::default());
        let mut a = VideoAdmission::new(AdmissionConfig::default());
        a.flv_opened();
        d.push(&es3);
        let mut aus = 0;
        while let Some(tag) = d.next_tag().unwrap() {
            aus += usize::from(a.admit(tag, Instant::now()).unwrap().au.is_some());
        }
        assert_eq!(aus, 8);
    }

    /// Both `ES3_LIKE_PARAMS` and `MAIN_360P_PARAMS` are copies of fixture
    /// bytes; nothing ties them to the fixtures they were copied from, so a
    /// regenerated fixture could silently desynchronise the `slice` and
    /// `pps` contexts from the seeds (preflight P6).
    #[test]
    fn hard_coded_params_are_the_fixtures_own() {
        for (name, (sps, pps)) in [
            ("360p30_es3like_poc0.h264", ES3_LIKE_PARAMS),
            ("360p30_main_full.h264", MAIN_360P_PARAMS),
        ] {
            let data = std::fs::read(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../fixtures")
                    .join(name),
            )
            .unwrap();
            let first = |t: u8| {
                split_annex_b(&data)
                    .find(|n| n[0] & 0x1F == t)
                    .unwrap()
                    .to_vec()
            };
            assert_eq!((first(7), first(8)), (sps.to_vec(), pps.to_vec()), "{name}");
        }
    }
}
