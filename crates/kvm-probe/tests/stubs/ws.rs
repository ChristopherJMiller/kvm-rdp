//! Task 5.10: the control-websocket open check must carry the token
//! cookie and must never send a data frame — no HID traffic reaches the
//! Mac from this probe.
use crate::support;
use kvm_probe::request::{KvmTarget, Scheme};
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::net::TcpListener;

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

/// B12 review fix round 1, I1: a TLS peer that completes the handshake but
/// never answers the HTTP upgrade must not hang `open_control_websocket`
/// forever. `UPGRADE_TIMEOUT` is an internal constant (10 s), not a
/// parameter, so — unlike the `trial` tests, which pass a short `timeout`
/// directly — paused time (the same idiom as `tests/stubs/login.rs`'s
/// `connect_to_times_out_against_a_silent_tls_peer`) is what keeps this
/// test from actually waiting 10 real seconds.
#[tokio::test(start_paused = true)]
async fn open_control_websocket_times_out_after_handshake_but_silent_upgrade() {
    let (acceptor, pin_hex) = support::tls_acceptor_and_pin();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };
        let Ok(_tls) = acceptor.accept(tcp).await else {
            return;
        };
        // TLS handshake complete; never read or write the HTTP upgrade.
        std::future::pending::<()>().await;
    });
    let t = KvmTarget {
        scheme: Scheme::Https,
        host: "127.0.0.1".into(),
        login_port: 1,
        video_port: 1,
        control_port: port,
    };
    match kvm_probe::wsprobe::open_control_websocket(&t, Some(&pin_hex), "0.987654").await {
        Err(kvm_probe::kvm::KvmError::Http(msg)) => {
            assert!(msg.to_ascii_lowercase().contains("time"), "{msg}");
        }
        other => panic!("expected a timeout error, got {other:?}"),
    }
}
