//! kvm-probe, the census tool proven against the real ES3, measures kvm-sim
//! the way it measured the device (`census.md`, Leg A — stream).
use crate::support::{T, es3_sim, login, target};
use kvm_probe::capture::{StopAt, run};
use kvm_probe::captures::CaptureDir;
use kvm_probe::record::TagRecord;
use kvm_probe::report::summarize;
use kvm_sim::{Fault, KvmSim, Pacing, Profile, SimConfig, SimEvent, Source};

fn coded_aus(e: &[SimEvent]) -> usize {
    e.iter()
        .filter(|e| matches!(e, SimEvent::FlvAu { .. }))
        .count()
}

#[tokio::test]
async fn census_capture_sees_the_es3_profile() {
    // Manual pacing: once kvm-probe's FLV is open, kvm-sim sends exactly 130
    // frames (two whole GOPs and the start of a third) and then closes it, so
    // what is captured never depends on how loaded the host is.
    let sim = es3_sim(Pacing::Manual).await;
    let token = login(&sim).await;
    let tmp = tempfile::tempdir().unwrap();
    let dir = CaptureDir::create(&tmp.path().join("captures")).unwrap();
    let mut jsonl = Vec::new();
    let stop = StopAt {
        max_bytes: 8 << 20,
        max_duration: T,
    };
    let drive = async {
        sim.wait_for(T, |e| {
            e.iter().any(|e| matches!(e, SimEvent::FlvOpen { .. }))
        })
        .await
        .unwrap();
        sim.advance(130);
        sim.wait_for(T, |e| coded_aus(e) == 130).await.unwrap();
        sim.inject(Fault::Close);
    };
    let kvm = target(&sim);
    let capture = run(
        &kvm,
        Some(sim.spki_sha256()),
        &token,
        &dir,
        "sim.flv",
        &mut jsonl,
        stop,
    );
    let (stats, ()) = tokio::join!(capture, drive);
    assert_eq!(stats.unwrap().parse_errors, 0);
    let records: Vec<TagRecord> = String::from_utf8(jsonl)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let s = summarize(&records);
    assert_eq!(s.codecs, [7]);
    assert_eq!(
        (
            s.multi_picture_tags,
            s.continuation_tags,
            s.non_vcl_picture_tags,
            s.bad_header_nals
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(s.gop_len, Some(60));
    // Like the real ES3, the SPS as sent is refused by h264-reader (level),
    // and both parameter sets end in zero bytes (census.md sps_hex, pps_hex).
    assert!(s.sps[0].summary.is_err());
    assert!(s.sps[0].hex.ends_with("00") && s.pps_hex[0].ends_with("0000"));
    let coded: Vec<&TagRecord> = records
        .iter()
        .filter(|r| r.avc_packet_type == Some(1))
        .collect();
    assert_eq!(coded.len(), 130);
    for r in coded {
        assert_eq!(r.composition_time, 16);
        assert!(r.nal_types.iter().all(|t| matches!(t, 1 | 5)));
    }
    assert_eq!(sim.stats().logouts, 0);
}

#[tokio::test]
async fn first_idr_and_websocket_open_work_and_send_nothing() {
    // Real-time pacing at 120 fps: the first-IDR trial waits on frames.
    let mut cfg = SimConfig::es3(Source::fixture("360p30_es3like_poc0.h264").unwrap());
    cfg.profile = Profile {
        fps: 120,
        ..Profile::es3()
    };
    let sim = KvmSim::start(cfg).await.unwrap();
    let token = login(&sim).await;
    let latency =
        kvm_probe::trial::first_idr_latency(&target(&sim), Some(sim.spki_sha256()), &token, T)
            .await
            .unwrap();
    assert!(latency < T);
    kvm_probe::wsprobe::open_control_websocket(&target(&sim), Some(sim.spki_sha256()), &token)
        .await
        .unwrap();
    let ev = sim
        .wait_for(T, |e| {
            e.iter().any(|e| matches!(e, SimEvent::WsClose { .. }))
        })
        .await
        .unwrap();
    assert!(!ev.iter().any(|e| matches!(e, SimEvent::Hid { .. })));
}
