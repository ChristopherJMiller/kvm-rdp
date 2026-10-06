use crate::support;
use kvm_probe::capture::{StopAt, run};
use kvm_probe::captures::CaptureDir;
use kvm_probe::request::{KvmTarget, Scheme};

fn target(port: u16) -> KvmTarget {
    // login/control ports deliberately wrong: capture must use video_port.
    KvmTarget {
        scheme: Scheme::Https,
        host: "127.0.0.1".into(),
        login_port: 1,
        video_port: port,
        control_port: 1,
    }
}

#[tokio::test]
async fn whole_fixture_is_saved_and_every_tag_recorded() {
    let stub = support::start_flv_stub().await;
    let tmp = tempfile::tempdir().unwrap();
    let dir = CaptureDir::create(&tmp.path().join("captures")).unwrap();
    let mut jsonl = Vec::new();
    let stats = run(
        &target(stub.port),
        Some(&stub.pin_hex),
        "0.987654",
        &dir,
        "a.flv",
        &mut jsonl,
        StopAt::default(),
    )
    .await
    .unwrap();

    let fixture = support::flv_fixture();
    assert_eq!(stats.bytes, u64::try_from(fixture.len()).unwrap());
    assert_eq!(
        std::fs::read(dir.resolve("a.flv").unwrap()).unwrap(),
        fixture
    );
    assert_eq!(stats.parse_errors, 0, "{:?}", stats.first_error);
    let lines: Vec<serde_json::Value> = String::from_utf8(jsonl)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(u64::try_from(lines.len()).unwrap(), stats.tags);
    assert!(
        lines
            .iter()
            .any(|l| l["avc_packet_type"] == 0 && l["nal_types"] == serde_json::json!([7, 8]))
    );
    assert!(lines.iter().any(|l| {
        l["nal_types"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(5))
    }));
    assert!(lines.iter().all(|l| l["recv_ms"].is_u64()));
}

/// Capture the committed ffmpeg-muxed fixture through `run`, read its
/// JSONL back as `TagRecord`s exactly as `kvm-probe summarize` does, and
/// return the records with the fixture's manifest.
async fn fixture_records() -> (Vec<kvm_probe::record::TagRecord>, serde_json::Value) {
    let stub = support::start_flv_stub().await;
    let tmp = tempfile::tempdir().unwrap();
    let dir = CaptureDir::create(&tmp.path().join("captures")).unwrap();
    let mut jsonl = Vec::new();
    run(
        &target(stub.port),
        Some(&stub.pin_hex),
        "0.987654",
        &dir,
        "s.flv",
        &mut jsonl,
        StopAt::default(),
    )
    .await
    .unwrap();
    let records = String::from_utf8(jsonl)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let manifest = serde_json::from_slice(
        &std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/360p30_main_full.flv.manifest.json"
        ))
        .unwrap(),
    )
    .unwrap();
    (records, manifest)
}

/// I2 (final review), against real data: the x264 fixture is one picture
/// per FLV tag (`slices_per_au: 1`, `aud=1`), so summarize must report
/// tag = AU (all three counts 0) and the manifest's IDR count, frame count
/// and GOP (`key_frames`, `frames`, `keyint`) in pictures.
#[tokio::test]
async fn fixture_summary_is_tag_equals_au_with_the_manifest_gop() {
    let (records, m) = fixture_records().await;
    let s = kvm_probe::report::summarize(&records);
    assert_eq!(
        (
            s.multi_picture_tags,
            s.continuation_tags,
            s.non_vcl_picture_tags
        ),
        (0, 0, 0)
    );
    assert_eq!(
        u64::try_from(s.idr).unwrap(),
        m["key_frames"].as_u64().unwrap()
    );
    assert_eq!(
        u64::try_from(s.idr + s.p_slices).unwrap(),
        m["frames"].as_u64().unwrap()
    );
    assert_eq!(
        s.gop_len.map(|g| u64::try_from(g).unwrap()),
        m["keyint"].as_u64()
    );
}

/// I3 (final review), end to end: the fixture's SPS travels capture →
/// JSONL `param_sets_hex` → summarize → kvm-proto's parser, and comes out
/// matching ffmpeg's view of it (the manifest). x264 repeats SPS/PPS
/// in-band before every IDR; those byte-identical repeats are recorded in
/// the JSONL but reported once, as first seen in the sequence header. No
/// slice NAL is ever hexed: every recorded entry is an SPS (67…) or PPS
/// (68…).
#[tokio::test]
async fn fixture_sps_through_capture_and_summarize_matches_the_manifest() {
    let (records, m) = fixture_records().await;
    let in_band_entries = records
        .iter()
        .filter(|r| r.avc_packet_type == Some(1))
        .map(|r| r.param_sets_hex.len())
        .sum::<usize>();
    assert!(
        in_band_entries > 0,
        "expected x264's in-band SPS/PPS repeats"
    );
    assert!(
        records
            .iter()
            .flat_map(|r| r.param_sets_hex.iter())
            .all(|h| h.starts_with("67") || h.starts_with("68"))
    );

    let s = kvm_probe::report::summarize(&records);
    assert_eq!(s.sps.len(), 1, "{:?}", s.sps);
    assert_eq!(s.pps_hex.len(), 1, "{:?}", s.pps_hex);
    let rep = &s.sps[0];
    assert!(!rep.in_band, "first seen in the sequence header");
    let sum = rep.summary.as_ref().unwrap();
    assert_eq!(u64::from(sum.width), m["width"].as_u64().unwrap());
    assert_eq!(u64::from(sum.height), m["height"].as_u64().unwrap());
    assert_eq!(
        u64::from(sum.profile_idc),
        m["profile_idc"].as_u64().unwrap()
    );
    assert_eq!(u64::from(sum.level_idc), m["level_idc"].as_u64().unwrap());
    assert_eq!(
        u64::from(sum.pic_order_cnt_type),
        m["pic_order_cnt_type"].as_u64().unwrap()
    );
    assert_eq!(rep.limits, Some(Ok(())));
    assert_eq!(
        rep.change_vs_first,
        Some(kvm_proto::h264::SpsChange::Initial)
    );
    assert_eq!((s.param_sets_skipped, s.param_sets_unreported), (0, 0));
}

#[tokio::test]
async fn byte_cap_mid_tag_stops_cleanly() {
    let stub = support::start_flv_stub().await;
    let tmp = tempfile::tempdir().unwrap();
    let dir = CaptureDir::create(&tmp.path().join("captures")).unwrap();
    let mut jsonl = Vec::new();
    let stop = StopAt {
        max_bytes: 1000,
        max_duration: std::time::Duration::from_secs(10),
    };
    let stats = run(
        &target(stub.port),
        Some(&stub.pin_hex),
        "0.987654",
        &dir,
        "b.flv",
        &mut jsonl,
        stop,
    )
    .await
    .unwrap();
    assert!(stats.bytes >= 1000);
    assert_eq!(
        stats.parse_errors, 0,
        "a partial trailing tag is not an error"
    );
    // I4: the cap must actually have stopped the read early (this is the
    // guard the Global Review Focus names for "every capture is bounded by
    // bytes" — without it the test also passes when the whole fixture is
    // read), and the file on disk must match exactly what was counted.
    assert!(
        stats.bytes < u64::try_from(support::flv_fixture().len()).unwrap(),
        "the byte cap did not stop the read early: {} bytes read",
        stats.bytes
    );
    assert_eq!(
        std::fs::metadata(dir.resolve("b.flv").unwrap())
            .unwrap()
            .len(),
        stats.bytes
    );
}

/// I3: a symlink planted at the capture name (the threat the sandbox's
/// read-write `/cap` bind exists to guard against, per `sandbox.rs`) must
/// be refused, not followed — and the file it points at must be untouched.
#[tokio::test]
async fn symlink_at_capture_name_is_refused_and_target_is_untouched() {
    let stub = support::start_flv_stub().await;
    let tmp = tempfile::tempdir().unwrap();
    let dir = CaptureDir::create(&tmp.path().join("captures")).unwrap();

    let outside = tmp.path().join("outside.txt");
    std::fs::write(&outside, b"do not touch").unwrap();
    let evil_path = dir.resolve("evil.flv").unwrap();
    std::os::unix::fs::symlink(&outside, &evil_path).unwrap();

    let mut jsonl = Vec::new();
    let err = run(
        &target(stub.port),
        Some(&stub.pin_hex),
        "0.987654",
        &dir,
        "evil.flv",
        &mut jsonl,
        StopAt::default(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, kvm_probe::kvm::KvmError::Io(_)),
        "expected a clean Io error for a planted symlink, got {err:?}"
    );
    assert_eq!(
        std::fs::read(&outside).unwrap(),
        b"do not touch",
        "the symlink target must be left untouched"
    );
    // The symlink itself must still be a symlink, not replaced/followed.
    assert!(std::fs::symlink_metadata(&evil_path).unwrap().is_symlink());
}

/// I1: `run` must not hang past `max_duration` against a peer that accepts
/// the connection and never answers the `GET /av.flv` request — the
/// duration cap must cover `open_flv`, not just the body-read loop.
#[tokio::test]
async fn run_returns_within_max_duration_against_a_silent_video_peer() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _held = listener.accept().await;
        std::future::pending::<()>().await;
    });
    let t = KvmTarget {
        scheme: Scheme::Http,
        host: "127.0.0.1".into(),
        login_port: 1,
        video_port: port,
        control_port: 1,
    };
    let tmp = tempfile::tempdir().unwrap();
    let dir = CaptureDir::create(&tmp.path().join("captures")).unwrap();
    let mut jsonl = Vec::new();
    let stop = StopAt {
        max_bytes: u64::MAX,
        max_duration: std::time::Duration::from_millis(200),
    };

    let started = std::time::Instant::now();
    let err = run(&t, None, "0.987654", &dir, "timeout.flv", &mut jsonl, stop)
        .await
        .unwrap_err();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "run did not return promptly: took {:?}",
        started.elapsed()
    );
    assert!(matches!(err, kvm_probe::kvm::KvmError::Http(_)));
}

#[tokio::test]
async fn non_200_flv_is_an_http_error() {
    let stub =
        support::start_http_stub(support::http_response("403 Forbidden", "text/plain", b"no"))
            .await;
    let tmp = tempfile::tempdir().unwrap();
    let dir = CaptureDir::create(&tmp.path().join("captures")).unwrap();
    let mut jsonl = Vec::new();
    let err = run(
        &target(stub.port),
        Some(&stub.pin_hex),
        "0.987654",
        &dir,
        "c.flv",
        &mut jsonl,
        StopAt::default(),
    )
    .await
    .unwrap_err();
    assert!(format!("{err:?}").contains("403"));
}
