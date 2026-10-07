//! Every committed fixture, muxed into FLV, demuxed and admitted: the AU and
//! IDR counts match ffprobe's (the manifest), and every emitted AU meets
//! §6.3's output contract. Plus the committed ffmpeg-muxed FLV as an
//! independent demux oracle (§11.2).
use kvm_proto::flv::mux::{
    TAG_VIDEO, avc_nalu_body, avc_sequence_header_body, write_flv_header, write_tag,
};
use kvm_proto::flv::{FlvDemuxer, FlvLimits};
use kvm_proto::h264::split_annex_b;
use kvm_proto::video::{AdmissionConfig, ParamClass, ParamSets, VideoAdmission};
use std::path::{Path, PathBuf};
use std::time::Instant;

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn manifest(name: &str) -> serde_json::Value {
    let p = dir().join(format!("{name}.manifest.json"));
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

/// Access units of an Annex-B stream: an AUD that follows a slice starts
/// the next one (every committed fixture has AUDs).
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

/// The stream as an FLV: its first SPS/PPS in the sequence header, one tag
/// per AU with `CompositionTime` 16. With 1-byte length prefixes the SEI
/// (x264's 695-byte version string) cannot be framed, so it is left out.
fn to_flv(data: &[u8], length_size: u8) -> Vec<u8> {
    let nals: Vec<&[u8]> = split_annex_b(data).collect();
    let sps = *nals.iter().find(|n| n[0] & 0x1F == 7).unwrap();
    let pps = *nals.iter().find(|n| n[0] & 0x1F == 8).unwrap();
    let mut flv = Vec::new();
    write_flv_header(&mut flv, false, true);
    let seq = avc_sequence_header_body(&[sps], &[pps], length_size).unwrap();
    write_tag(&mut flv, TAG_VIDEO, 0, &seq).unwrap();
    for (i, au) in access_units(data).iter().enumerate() {
        let key = au.iter().any(|n| n[0] & 0x1F == 5);
        let au: Vec<&[u8]> = au
            .iter()
            .copied()
            .filter(|n| length_size != 1 || n[0] & 0x1F != 6)
            .collect();
        let mut body = Vec::new();
        avc_nalu_body(&mut body, key, 16, &au, length_size).unwrap();
        let ts = u32::try_from(i * 1000 / 30).unwrap();
        write_tag(&mut flv, TAG_VIDEO, ts, &body).unwrap();
    }
    flv
}

/// Demux and admit `flv`; check §6.3 on every AU; return (AUs, IDRs, the
/// classes of every parameter-set change, the last sets).
fn admit_all(flv: &[u8]) -> (u64, u64, Vec<ParamClass>, ParamSets) {
    let mut d = FlvDemuxer::new(FlvLimits::default());
    let mut a = VideoAdmission::new(AdmissionConfig::default());
    a.flv_opened();
    d.push(flv);
    let (mut aus, mut idrs, mut classes, mut last) = (0, 0, Vec::new(), None);
    let mut out = Vec::new();
    let t0 = Instant::now();
    while let Some(tag) = d.next_tag().unwrap() {
        let ad = a.admit(tag, t0).unwrap();
        if let Some(pc) = ad.params {
            classes.push(pc.class);
            last = Some(pc.params);
        }
        if let Some(au) = ad.au {
            aus += 1;
            idrs += u64::from(au.idr);
            let ps = last.as_ref().unwrap();
            out.clear();
            au.write_annex_b(ps, &mut out);
            let mut expect: Vec<&[u8]> = Vec::new();
            expect.extend(au.aud.as_deref());
            if au.idr {
                expect.push(&ps.sps);
                expect.extend(ps.pps.iter().map(|p| p.as_ref()));
            }
            expect.extend(au.vcl.iter().map(|n| n.bytes.as_ref()));
            let resplit: Vec<&[u8]> = split_annex_b(&out).collect();
            assert_eq!(resplit, expect);
            for n in resplit {
                assert!(matches!(n[0] & 0x1F, 1 | 5 | 7 | 8 | 9));
                assert!(!n.windows(3).any(|w| w[0] == 0 && w[1] == 0 && w[2] <= 2));
            }
        }
    }
    (aus, idrs, classes, last.unwrap())
}

#[test]
fn every_fixture_admits_with_ffprobes_frame_counts() {
    let mut seen = 0;
    for e in std::fs::read_dir(dir()).unwrap() {
        let path = e.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.ends_with(".h264") {
            continue;
        }
        let m = manifest(&name);
        let length_size = if name.contains("slices") { 1 } else { 4 };
        let (aus, idrs, classes, last) =
            admit_all(&to_flv(&std::fs::read(&path).unwrap(), length_size));
        assert_eq!(Some(aus), m["frames"].as_u64(), "{name} AUs");
        assert_eq!(Some(idrs), m["key_frames"].as_u64(), "{name} IDRs");
        // Repeated in-band SPS/PPS (x264 repeat-headers) raise nothing new.
        assert_eq!(classes, [ParamClass::Initial], "{name}");
        // Every admitted SPS carries the rewritten VUI.
        assert_eq!(last.summary.video_full_range_flag, Some(false), "{name}");
        if name == "360p30_es3like_poc0.h264" {
            assert_eq!(
                (last.summary.level_idc, last.summary.pic_order_cnt_type),
                (30, 0)
            );
        }
        seen += 1;
    }
    assert_eq!(
        seen, 10,
        "every committed .h264 (the 11th manifest is the .flv)"
    );
}

#[test]
fn the_ffmpeg_muxed_flv_admits() {
    let flv = std::fs::read(dir().join("360p30_main_full.flv")).unwrap();
    let (aus, idrs, classes, _) = admit_all(&flv);
    assert_eq!((aus, idrs), (90, 3));
    assert_eq!(classes, [ParamClass::Initial]);
}
