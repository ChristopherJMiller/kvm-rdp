#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]
use super::*;
use crate::flv::mux::{
    TAG_VIDEO, avc_nalu_body, avc_sequence_header_body, write_flv_header, write_tag,
};
use crate::flv::{FlvDemuxer, FlvError, FlvLimits, FrameType};
use crate::h264::picture::{AudRefusal, HeaderLimit, SliceRefusal};
use crate::h264::sanitize::NalRefusal;
use crate::h264::test_support::{PpsCfg, SliceCfg, SpsCfg};
use crate::h264::{NalHeader, PinnedField, SpsIncompatibleReason};

/// A Baseline 1080p SPS (POC type 2, `log2_max_frame_num` 4) at level 40.
fn sps() -> Vec<u8> {
    let mut c = SpsCfg::main_1080p();
    c.profile_idc = 66;
    c.level_idc = 40;
    c.build()
}

fn idr() -> Vec<u8> {
    SliceCfg::idr().build()
}

fn p(frame_num: u32) -> Vec<u8> {
    SliceCfg::p(frame_num).build()
}

fn video(body: TagBody) -> FlvTag {
    FlvTag {
        tag_type: 9,
        data_size: 0,
        timestamp: 0,
        body,
    }
}

/// Mux a sequence header (`sps()`, default PPS) then one NALU tag per entry
/// `(composition_time, nals)` 33 ms apart, demux, and admit tag by tag until
/// the first refusal. Every tag is "received" at the same instant.
fn run(tags: &[(i32, Vec<Vec<u8>>)]) -> Vec<Result<Admitted, AdmissionError>> {
    let mut flv = Vec::new();
    write_flv_header(&mut flv, false, true);
    let (s, pps) = (sps(), PpsCfg::default().build());
    write_tag(
        &mut flv,
        TAG_VIDEO,
        0,
        &avc_sequence_header_body(&[&s], &[&pps], 4).unwrap(),
    )
    .unwrap();
    for (i, (ct, nals)) in tags.iter().enumerate() {
        let nals: Vec<&[u8]> = nals.iter().map(Vec::as_slice).collect();
        let mut b = Vec::new();
        avc_nalu_body(&mut b, false, *ct, &nals, 4).unwrap();
        write_tag(&mut flv, TAG_VIDEO, (i as u32 + 1) * 33, &b).unwrap();
    }
    let mut d = FlvDemuxer::new(FlvLimits::default());
    d.push(&flv);
    let mut a = VideoAdmission::new(AdmissionConfig::default());
    a.flv_opened();
    let t0 = Instant::now();
    let mut out = Vec::new();
    while let Some(t) = d.next_tag().unwrap() {
        let r = a.admit(t, t0);
        let stop = r.is_err();
        out.push(r);
        if stop {
            break;
        }
    }
    out
}

fn last(r: &[Result<Admitted, AdmissionError>]) -> &Result<Admitted, AdmissionError> {
    r.last().unwrap()
}

#[test]
fn a_clean_stream_admits_with_its_parameter_sets_first() {
    let r = run(&[(16, vec![idr()]), (16, vec![p(1)]), (16, vec![p(2)])]);
    assert!(r.iter().all(Result::is_ok), "{r:?}");
    let first = r[0].as_ref().unwrap();
    assert_eq!(first.params.as_ref().unwrap().class, ParamClass::Initial);
    assert!(first.au.is_none());
    let aus: Vec<bool> = r[1..]
        .iter()
        .map(|a| a.as_ref().unwrap().au.as_ref().unwrap().idr)
        .collect();
    assert_eq!(aus, [true, false, false]);
}

#[test]
fn constant_composition_time_16_is_admitted_and_a_change_refused() {
    assert!(
        run(&[(16, vec![idr()]), (16, vec![p(1)])])
            .iter()
            .all(Result::is_ok)
    );
    assert_eq!(
        last(&run(&[(16, vec![idr()]), (17, vec![p(1)])])),
        &Err(incompatible(Incompatible::CompositionTime {
            first: 16,
            now: 17
        }))
    );
}

/// One hostile vector per §6.1/§6.2 rule, each with its own error kind.
#[test]
fn each_admission_rule_has_its_own_refusal() {
    let mut b = SliceCfg::p(1);
    b.slice_type = 6;
    b.header_byte = 0x01;
    let mut cont = SliceCfg::p(1);
    cont.first_mb = 5;
    let mut far = SliceCfg::p(1);
    far.first_mb = 120 * 68;
    let mut other_pps = SliceCfg::p(1);
    other_pps.pps_id = 3;
    // A continuation slice (`first_mb != 0`) whose other picture-identity
    // fields (frame_num, idr) do not match the tag's first slice: it must
    // not be accepted as that picture's continuation (fix round 1, I1/M08).
    let mut continuation_other_picture = SliceCfg::p(1);
    continuation_other_picture.first_mb = 5;
    let (mut nonref1, mut nonref2) = (SliceCfg::p(1), SliceCfg::p(1));
    nonref1.header_byte = 0x01;
    nonref2.header_byte = 0x01;
    let mut start_code = p(1);
    start_code.splice(2..2, [0, 0, 1]);
    let mut forbidden = p(1);
    forbidden[0] |= 0x80;
    let pps = PpsCfg::default().build();
    let mut sps_flood = vec![sps(); 5];
    sps_flood.push(idr());
    let mut pps_flood = vec![pps; 17];
    pps_flood.push(idr());
    let aud = vec![0x09, 0xF0];
    type Case = (&'static str, Vec<(i32, Vec<Vec<u8>>)>, AdmissionError);
    let cases: Vec<Case> = vec![
        (
            "B slice",
            vec![(16, vec![idr()]), (16, vec![b.build()])],
            incompatible(Incompatible::Slice(SliceRefusal::SliceType(6))),
        ),
        (
            "first_mb out of range",
            vec![(16, vec![idr()]), (16, vec![far.build()])],
            incompatible(Incompatible::Slice(SliceRefusal::FirstMb {
                first_mb: 8160,
                pic_size_in_mbs: 8160,
            })),
        ),
        (
            "two pictures in one tag",
            vec![(16, vec![idr(), p(1)])],
            framing(Framing::NotOnePicture),
        ),
        (
            "first slice not at MB 0",
            vec![(16, vec![idr()]), (16, vec![cont.build()])],
            framing(Framing::NotOnePicture),
        ),
        (
            // Two slices with identical picture-identity headers, both at
            // MB 0: neither can be the other's continuation (first_mb == 0
            // for both), so the second starts an unwanted second picture.
            // Without the `first_mb_in_slice != 0` half of the check, this
            // passes (fix round 1, I1/M07).
            "two same-header pictures in one tag",
            vec![(16, vec![idr()]), (16, vec![p(1), p(1)])],
            framing(Framing::NotOnePicture),
        ),
        (
            // `first_mb != 0` alone does not make a slice a continuation of
            // the tag's first picture: its other picture-identity fields
            // must also match. Without the `same_picture` half of the
            // check, this passes (fix round 1, I1/M08).
            "a continuation slice belongs to a different picture",
            vec![(16, vec![idr(), continuation_other_picture.build()])],
            framing(Framing::NotOnePicture),
        ),
        (
            "no slice at all",
            vec![(16, vec![aud.clone()])],
            framing(Framing::NotOnePicture),
        ),
        (
            "second AUD",
            vec![(16, vec![aud.clone(), aud.clone(), idr()])],
            framing(Framing::NotOnePicture),
        ),
        (
            "AUD after a slice",
            vec![(16, vec![idr(), aud.clone()])],
            framing(Framing::NotOnePicture),
        ),
        (
            "start code inside a NAL",
            vec![(16, vec![idr()]), (16, vec![start_code])],
            framing(Framing::Nal(NalRefusal::StartCode)),
        ),
        (
            "forbidden bit",
            vec![(16, vec![idr()]), (16, vec![forbidden])],
            framing(Framing::Nal(NalRefusal::ForbiddenBit)),
        ),
        (
            "all-zero NAL",
            vec![(16, vec![idr()]), (16, vec![vec![0, 0]])],
            framing(Framing::Nal(NalRefusal::Empty)),
        ),
        (
            "unknown PPS id",
            vec![(16, vec![idr()]), (16, vec![other_pps.build()])],
            incompatible(Incompatible::Slice(SliceRefusal::Unparsable(
                "UndefinedPicParamSetId(PicParamSetId(3))".into(),
            ))),
        ),
        (
            "POC not increasing",
            vec![
                (16, vec![idr()]),
                (16, vec![nonref1.build()]),
                (16, vec![nonref2.build()]),
            ],
            incompatible(Incompatible::Slice(SliceRefusal::PocNotIncreasing {
                previous: 1,
                current: 1,
            })),
        ),
        (
            "five in-band SPSs in one tag",
            vec![(16, sps_flood)],
            AdmissionError::from(FlvError::ParamSetCount),
        ),
        (
            "seventeen in-band PPSs in one tag",
            vec![(16, pps_flood)],
            AdmissionError::from(FlvError::ParamSetCount),
        ),
    ];
    for (name, tags, want) in cases {
        assert_eq!(last(&run(&tags)), &Err(want), "{name}");
    }
}

/// The positive side of the one-picture rule (fix round 1, I1): H.264
/// permits arbitrary slice order (ASO) — later slices of a picture need
/// not run in MB order, only match the first slice's picture-identity
/// fields (`same_picture`) — and `write_annex_b` emits them in source order,
/// not sorted by `first_mb`.
#[test]
fn slices_in_arbitrary_order_are_one_access_unit() {
    let mbs = [0_u32, 2000, 1000, 4000];
    let nals: Vec<Vec<u8>> = mbs
        .iter()
        .map(|&m| {
            SliceCfg {
                first_mb: m,
                ..SliceCfg::idr()
            }
            .build()
        })
        .collect();
    let r = run(&[(16, nals.clone())]);
    let au = r[1].as_ref().unwrap().au.as_ref().unwrap();
    assert!(au.idr);
    // fix round 1, m4: the AU's own FLV timestamp, not a placeholder (this
    // is `run`'s first coded tag: timestamp `(0 + 1) * 33`).
    assert_eq!(au.flv_timestamp_ms, 33);
    let got: Vec<&[u8]> = au.vcl.iter().map(|n| n.bytes.as_ref()).collect();
    let want: Vec<&[u8]> = nals.iter().map(Vec::as_slice).collect();
    assert_eq!(got, want, "write_annex_b must preserve source order");
}

#[test]
fn tag_level_classes() {
    let mut a = VideoAdmission::new(AdmissionConfig::default());
    a.flv_opened();
    let now = Instant::now();
    assert_eq!(
        a.admit(
            FlvTag {
                tag_type: 8,
                data_size: 1,
                timestamp: 0,
                body: TagBody::Audio
            },
            now
        ),
        Ok(Admitted::default())
    );
    assert_eq!(
        a.admit(
            FlvTag {
                tag_type: 18,
                data_size: 1,
                timestamp: 0,
                body: TagBody::ScriptData
            },
            now
        ),
        Ok(Admitted::default())
    );
    assert_eq!(
        a.admit(
            FlvTag {
                tag_type: 3,
                data_size: 1,
                timestamp: 0,
                body: TagBody::Other(3)
            },
            now
        ),
        Err(framing(Framing::UnknownTagType(3)))
    );
    assert_eq!(
        a.admit(
            video(TagBody::Video(VideoBody::NonAvc {
                codec_id: 12,
                frame_type: FrameType::Key
            })),
            now
        ),
        Err(incompatible(Incompatible::Codec(12)))
    );
    assert_eq!(
        a.admit(
            video(TagBody::Video(VideoBody::Enhanced {
                packet_type: 1,
                frame_type: FrameType::Key,
                fourcc: *b"hvc1"
            })),
            now
        ),
        Err(incompatible(Incompatible::Enhanced(*b"hvc1")))
    );
    assert!(
        a.admit(video(TagBody::Video(VideoBody::EndOfSequence)), now)
            .unwrap()
            .end_of_sequence
    );
}

#[test]
fn config_record_entries_must_be_what_they_claim() {
    let mut a = VideoAdmission::new(AdmissionConfig::default());
    a.flv_opened();
    let pps = Bytes::from(PpsCfg::default().build());
    let cfg = AvcConfig {
        length_size_minus_one: 3,
        profile_idc: 66,
        level_idc: 40,
        sps: vec![pps.clone()],
        pps: vec![pps],
    };
    assert_eq!(
        a.admit(
            video(TagBody::Video(VideoBody::SequenceHeader(cfg))),
            Instant::now()
        ),
        Err(framing(Framing::ConfigNalType(8)))
    );
}

/// Fix round 1, I2: a new in-band PPS id is adopted (not just byte-identical
/// repeats, which PB9/4.6's other tests cover), raising `SpsChanged{other}`
/// (D4 — a PPS alone changing is `Other`), and every cached PPS — not only
/// the first — is written before the next IDR (§6.3).
#[test]
fn an_in_band_pps_is_adopted_and_every_cached_pps_precedes_an_idr() {
    let new_pps = PpsCfg {
        pps_id: 1,
        ..PpsCfg::default()
    }
    .build();
    let r = run(&[(16, vec![new_pps, idr()])]);
    let a = r[1].as_ref().unwrap();
    let change = a.params.as_ref().unwrap();
    assert_eq!(
        change.class,
        ParamClass::Other,
        "a PPS-only change is Other (D4)"
    );
    assert_eq!(
        change.params.pps.len(),
        2,
        "the cache now holds both PPS ids"
    );
    let au = a.au.as_ref().unwrap();
    let mut out = Vec::new();
    au.write_annex_b(&change.params, &mut out);
    let mut want = vec![0, 0, 0, 1];
    want.extend_from_slice(&change.params.sps);
    for p in &change.params.pps {
        want.extend_from_slice(&[0, 0, 0, 1]);
        want.extend_from_slice(p);
    }
    want.extend_from_slice(&[0, 0, 0, 1]);
    want.extend_from_slice(&idr());
    assert_eq!(out, want, "every cached PPS, in id order, before the IDR");
}

#[test]
fn in_band_parameter_sets_are_classified_and_removed_from_the_au() {
    let mut big = SpsCfg::main_1080p();
    big.profile_idc = 66;
    big.level_idc = 40;
    big.pic_width_in_mbs_minus1 = 79; // 1280 wide
    big.pic_height_in_map_units_minus1 = 44; // 720 high
    big.crop = None;
    let pps = PpsCfg::default().build();
    let sei = vec![0x06, 0x05, 0x01, 0xAA, 0x80];
    let r = run(&[
        (16, vec![sps(), pps.clone(), idr()]), // identical in-band sets: no event
        (16, vec![sei, p(1)]),                 // SEI dropped and counted
        (16, vec![big.build(), pps, idr()]),   // a new size in-band: Resize, then the IDR
    ]);
    let r: Vec<Admitted> = r.into_iter().map(Result::unwrap).collect();
    assert_eq!(r[1].params, None);
    assert_eq!(
        r[1].au.as_ref().unwrap().vcl.len(),
        1,
        "SPS/PPS never reach the AU"
    );
    assert_eq!(r[2].dropped_nals, 1);
    let resize = r[3].params.as_ref().unwrap();
    assert_eq!(resize.class, ParamClass::Resize);
    assert_eq!(
        (resize.params.summary.width, resize.params.summary.height),
        (1280, 720)
    );
    assert!(r[3].au.as_ref().unwrap().idr);
}

#[test]
fn annex_b_output_matches_section_6_3_and_frame_id_hashes_the_vcl() {
    let aud = vec![0x09, 0xF0];
    let r = run(&[
        (16, vec![aud.clone(), idr()]),
        (16, vec![aud.clone(), p(1)]),
    ]);
    let r: Vec<Admitted> = r.into_iter().map(Result::unwrap).collect();
    let params = r[0].params.as_ref().unwrap().params.clone();
    let (idr_au, p_au) = (r[1].au.as_ref().unwrap(), r[2].au.as_ref().unwrap());
    let mut out = Vec::new();
    idr_au.write_annex_b(&params, &mut out);
    let mut want = Vec::new();
    for nal in [&aud[..], &params.sps, &params.pps[0], &idr()] {
        want.extend_from_slice(&[0, 0, 0, 1]);
        want.extend_from_slice(nal);
    }
    assert_eq!(out, want);
    out.clear();
    p_au.write_annex_b(&params, &mut out);
    let mut want = vec![0, 0, 0, 1];
    want.extend_from_slice(&aud);
    want.extend_from_slice(&[0, 0, 0, 1]);
    want.extend_from_slice(&p(1));
    assert_eq!(out, want, "no parameter sets before a P frame");
    assert_eq!(p_au.frame_id(), crate::h264::frame_id([p(1).as_slice()]));
    assert_eq!(NalHeader::from_nal(&params.sps).unwrap().nal_unit_type, 7);
}

/// PB10 m2, folded into final review I1: an AUD is forwarded to the
/// client's decoder, so it must be exactly `access_unit_delimiter_rbsp` —
/// `primary_pic_type`, then the stop bit — and its Table 7-5 set must hold
/// every slice type in the picture (7.4.2.4). Anything else is refused,
/// never forwarded verbatim.
#[test]
fn an_aud_is_two_bytes_whose_primary_pic_type_covers_the_picture() {
    // x264's own (every committed fixture): 0x10 (I) before an IDR, 0x30
    // (I, P) before a P picture. 0xF0 (every type) and 0x50 (I, SI) / 0xD0
    // (I, SI, P, SP) fit too.
    for (before_idr, before_p) in [(0x10, 0x30), (0xF0, 0xF0), (0x50, 0xD0)] {
        let r = run(&[
            (16, vec![vec![0x09, before_idr], idr()]),
            (16, vec![vec![0x09, before_p], p(1)]),
        ]);
        assert!(
            r.iter().all(Result::is_ok),
            "{before_idr:#x}/{before_p:#x}: {r:?}"
        );
    }
    let aud = |r| Err(incompatible(Incompatible::Aud(r)));
    let before_p = |nal: Vec<u8>| last(&run(&[(16, vec![idr()]), (16, vec![nal, p(1)])])).clone();
    // One byte (also what `09 00` trims to), a byte too many, and 1000
    // bytes too many (PB10's probe was 100 KB).
    assert_eq!(before_p(vec![0x09]), aud(AudRefusal::Malformed));
    assert_eq!(before_p(vec![0x09, 0x30, 0x80]), aud(AudRefusal::Malformed));
    let long = [vec![0x09, 0x30], vec![0xAA; 1000]].concat();
    assert_eq!(before_p(long), aud(AudRefusal::Malformed));
    // `001 1 1000` and `001 0 0001`: no stop bit followed by zero bits.
    assert_eq!(before_p(vec![0x09, 0x38]), aud(AudRefusal::Malformed));
    assert_eq!(before_p(vec![0x09, 0x21]), aud(AudRefusal::Malformed));
    // 0 (I only) and 5 (I, SI) cannot announce a P picture.
    assert_eq!(
        before_p(vec![0x09, 0x10]),
        aud(AudRefusal::PrimaryPicType(0))
    );
    assert_eq!(
        before_p(vec![0x09, 0xB0]),
        aud(AudRefusal::PrimaryPicType(5))
    );
    // 3 (SI) and 4 (SI, SP) cannot announce an I picture.
    for ppt in [3u8, 4] {
        let r = run(&[(16, vec![vec![0x09, (ppt << 5) | 0x10], idr()])]);
        assert_eq!(last(&r), &aud(AudRefusal::PrimaryPicType(ppt)));
    }
}

/// Final review I1, end to end: a P slice whose modification list is
/// longer than its one active reference allows is refused as
/// `stream_incompatible`, not admitted and forwarded.
#[test]
fn an_oversized_slice_header_list_is_stream_incompatible() {
    let mut mods = SliceCfg::p(1);
    mods.ref_list_mods = vec![(0, 0); 2];
    let r = run(&[(16, vec![idr()]), (16, vec![mods.build()])]);
    let e = last(&r).clone().unwrap_err();
    assert_eq!(
        e,
        incompatible(Incompatible::Slice(SliceRefusal::HeaderLimits(
            HeaderLimit::RefPicListModifications { list: 0, max: 1 }
        )))
    );
    assert_eq!(e.kind(), "slice");
}

#[test]
fn bursts_are_marked_against_real_time() {
    // All tags "arrive" at t0 while their timestamps run 33 ms apart: the
    // fifth AU is 132 ms ahead of the first, past §6.2's 100 ms: a burst.
    let r = run(&[
        (16, vec![idr()]),
        (16, vec![p(1)]),
        (16, vec![p(2)]),
        (16, vec![p(3)]),
        (16, vec![p(4)]),
    ]);
    let bursts: Vec<bool> = r[1..]
        .iter()
        .map(|a| a.as_ref().unwrap().au.as_ref().unwrap().burst)
        .collect();
    assert_eq!(bursts, [false, false, false, false, true]);
}

/// A sequence-header tag carrying `sps` and the default PPS.
fn seq_tag(sps: Vec<u8>) -> FlvTag {
    video(TagBody::Video(VideoBody::SequenceHeader(AvcConfig {
        length_size_minus_one: 3,
        profile_idc: 66,
        level_idc: 40,
        sps: vec![Bytes::from(sps)],
        pps: vec![Bytes::from(PpsCfg::default().build())],
    })))
}

/// A coded tag: FLV timestamp `ts`, `CompositionTime` `ct`, one NAL.
fn coded_tag(ts: u32, ct: i32, nal: Vec<u8>) -> FlvTag {
    FlvTag {
        tag_type: 9,
        data_size: 0,
        timestamp: ts,
        body: TagBody::Video(VideoBody::Nalus {
            frame_type: FrameType::Key,
            composition_time: ct,
            nals: vec![Nal {
                bytes: Bytes::from(nal),
            }],
        }),
    }
}

#[test]
fn an_flv_reconnect_restarts_ct_poc_and_bursts_but_keeps_the_pins() {
    let now = Instant::now();
    let mut a = VideoAdmission::new(AdmissionConfig::default());
    a.flv_opened();
    a.admit(seq_tag(sps()), now).unwrap();
    for (ts, nal) in [(0, idr()), (33, p(1)), (66, p(2)), (99, p(3))] {
        let au = a.admit(coded_tag(ts, 16, nal), now).unwrap().au.unwrap();
        assert!(!au.burst);
    }
    a.flv_opened();
    // The same SPS is `Initial` again on the new connection.
    let again = a.admit(seq_tag(sps()), now).unwrap();
    assert_eq!(again.params.unwrap().class, ParamClass::Initial);
    // Its first coded tag sets a new CompositionTime (0, not 16), restarts
    // POC order (p(3) again is POC 6, which the old connection reached), and
    // is the new burst baseline although it is 5 s ahead of the old one.
    let au = a.admit(coded_tag(5_000, 0, p(3)), now).unwrap().au.unwrap();
    assert!(!au.burst);
    let au = a.admit(coded_tag(5_200, 0, p(4)), now).unwrap().au.unwrap();
    assert!(au.burst, "200 ms ahead of the new baseline");
    // The pins persist across the reconnect: a Main SPS is fatal …
    a.flv_opened();
    assert_eq!(
        a.admit(seq_tag(SpsCfg::main_1080p().build()), now),
        Err(incompatible(Incompatible::Sps(
            SpsIncompatibleReason::PinnedFieldChanged(PinnedField::ProfileIdc)
        )))
    );
    // … and only a new session (`Start`) resets them.
    let mut fresh = VideoAdmission::new(AdmissionConfig::default());
    fresh.flv_opened();
    let first = fresh.admit(seq_tag(SpsCfg::main_1080p().build()), now);
    assert_eq!(first.unwrap().params.unwrap().class, ParamClass::Initial);
}

#[test]
fn an_identical_sequence_header_mid_connection_raises_nothing() {
    let now = Instant::now();
    let mut a = VideoAdmission::new(AdmissionConfig::default());
    a.flv_opened();
    assert!(a.admit(seq_tag(sps()), now).unwrap().params.is_some());
    a.admit(coded_tag(0, 16, idr()), now).unwrap();
    assert_eq!(a.admit(seq_tag(sps()), now).unwrap().params, None);
    assert!(a.admit(coded_tag(33, 16, p(1)), now).unwrap().au.is_some());
}

#[test]
fn a_sequence_header_without_parameter_sets_leaves_no_stale_pps() {
    // The demuxer refuses an empty config record (`ParamSetCount`), but
    // `admit` is public: a hand-built one must drop every PPS from the
    // parse context too, not only from the sets it reports.
    let now = Instant::now();
    let mut a = VideoAdmission::new(AdmissionConfig::default());
    a.flv_opened();
    a.admit(seq_tag(sps()), now).unwrap();
    a.admit(coded_tag(0, 16, idr()), now).unwrap();
    let empty = video(TagBody::Video(VideoBody::SequenceHeader(AvcConfig {
        length_size_minus_one: 3,
        profile_idc: 66,
        level_idc: 40,
        sps: vec![],
        pps: vec![],
    })));
    let change = a.admit(empty, now).unwrap().params.unwrap();
    assert!(change.params.pps.is_empty());
    assert_eq!(
        a.admit(coded_tag(33, 16, p(1)), now),
        Err(incompatible(Incompatible::Slice(SliceRefusal::Unparsable(
            "UndefinedPicParamSetId(PicParamSetId(0))".into()
        ))))
    );
}

#[test]
fn in_band_parameter_sets_up_to_the_section_6_2_cap_are_admitted() {
    let mut nals = vec![sps(); 4];
    nals.extend(std::iter::repeat_n(PpsCfg::default().build(), 16));
    nals.push(idr());
    let r = run(&[(16, nals)]);
    let a = r[1].as_ref().unwrap();
    assert_eq!(a.params, None, "identical sets raise nothing");
    assert!(a.au.as_ref().unwrap().idr);
}

/// `census.md` `sps_hex` and `pps_hex`, trailing zero bytes included.
const CENSUS_SPS: [u8; 17] = [
    0x67, 0x42, 0x00, 0x1f, 0x96, 0x54, 0x03, 0xc0, 0x11, 0x2f, 0x2c, 0xdc, 0x14, 0x18, 0x14, 0x08,
    0x00,
];
const CENSUS_PPS: [u8; 6] = [0x68, 0xce, 0x31, 0x12, 0x00, 0x00];

#[test]
fn the_es3s_own_parameter_sets_admit_through_mux_and_demux() {
    // An IDR for the census SPS: log2_max_frame_num 8, POC type 0, 8-bit lsb.
    let idr = SliceCfg {
        log2_max_frame_num: 8,
        poc_lsb: Some((0, 8)),
        ..SliceCfg::idr()
    }
    .build();
    let mut flv = Vec::new();
    write_flv_header(&mut flv, false, true);
    let seq = avc_sequence_header_body(&[&CENSUS_SPS], &[&CENSUS_PPS], 4).unwrap();
    write_tag(&mut flv, TAG_VIDEO, 0, &seq).unwrap();
    let mut body = Vec::new();
    avc_nalu_body(&mut body, true, 16, &[&idr], 4).unwrap();
    write_tag(&mut flv, TAG_VIDEO, 0, &body).unwrap();
    let mut d = FlvDemuxer::new(FlvLimits::default());
    d.push(&flv);
    let mut a = VideoAdmission::new(AdmissionConfig::default());
    a.flv_opened();
    let now = Instant::now();
    let change = a
        .admit(d.next_tag().unwrap().unwrap(), now)
        .unwrap()
        .params
        .unwrap();
    assert_eq!(change.class, ParamClass::Initial);
    let hex: String = change
        .params
        .sps
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(hex, "67420028965403c0112f2cd40404041b41008540");
    assert_eq!(change.params.pps, [Bytes::from_static(&CENSUS_PPS[..4])]);
    let au = a
        .admit(d.next_tag().unwrap().unwrap(), now)
        .unwrap()
        .au
        .unwrap();
    assert!(au.idr);
    let mut out = Vec::new();
    au.write_annex_b(&change.params, &mut out);
    let nals: Vec<&[u8]> = crate::h264::split_annex_b(&out).collect();
    assert_eq!(nals, [&change.params.sps[..], &CENSUS_PPS[..4], &idr[..]]);
}
