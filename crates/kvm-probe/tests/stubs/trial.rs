//! Task 5.11: first-IDR latency is measured on the video port, bounded by
//! the caller's `timeout`.
use crate::support;
use kvm_probe::request::{KvmTarget, Scheme};
use std::time::Duration;

#[tokio::test]
async fn first_idr_latency_is_measured_on_the_video_port() {
    let stub = support::start_flv_stub().await;
    // login_port/control_port are deliberately bogus: the trial must use
    // video_port.
    let t = KvmTarget {
        scheme: Scheme::Https,
        host: "127.0.0.1".into(),
        login_port: 1,
        video_port: stub.port,
        control_port: 1,
    };
    let d = kvm_probe::trial::first_idr_latency(
        &t,
        Some(&stub.pin_hex),
        "0.987654",
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert!(d < Duration::from_secs(5));
}
