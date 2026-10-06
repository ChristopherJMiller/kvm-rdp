//! Task 5.10: the control-websocket open check must carry the token
//! cookie and must never send a data frame — no HID traffic reaches the
//! Mac from this probe.
use crate::support;
use kvm_probe::request::{KvmTarget, Scheme};
use std::sync::atomic::Ordering;
use std::time::Duration;

#[tokio::test]
async fn opens_with_cookie_and_sends_no_frames() {
    let stub = support::start_ws_stub().await;
    // login_port/video_port are deliberately bogus: the probe must use
    // control_port.
    let t = KvmTarget {
        scheme: Scheme::Https,
        host: "127.0.0.1".into(),
        login_port: 1,
        video_port: 1,
        control_port: stub.port,
    };
    let latency = kvm_probe::wsprobe::open_control_websocket(&t, Some(&stub.pin_hex), "0.987654")
        .await
        .unwrap();
    assert!(latency < Duration::from_secs(5));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        stub.saw_cookie.load(Ordering::SeqCst),
        "upgrade must carry the token cookie"
    );
    assert_eq!(
        stub.data_frames.load(Ordering::SeqCst),
        0,
        "probe must never send HID frames"
    );
}

/// R9: an `Https` target with no pin must be refused before any network
/// I/O — including for the control-websocket open check, which must not
/// construct an accept-any verifier to get further than `kvm::connect_to`.
#[tokio::test]
async fn https_without_pin_is_refused_before_any_network_io() {
    let t = KvmTarget {
        scheme: Scheme::Https,
        host: "127.0.0.1".into(),
        login_port: 1,
        video_port: 1,
        control_port: 1,
    };
    match kvm_probe::wsprobe::open_control_websocket(&t, None, "0.987654").await {
        Err(kvm_probe::kvm::KvmError::Tls(msg)) => {
            assert!(msg.contains("pin required for https"), "{msg}");
        }
        Ok(_) => panic!("expected Tls error for a missing pin, got Ok"),
        Err(e) => panic!("expected Tls error for a missing pin, got {e:?}"),
    }
}
