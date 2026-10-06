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
