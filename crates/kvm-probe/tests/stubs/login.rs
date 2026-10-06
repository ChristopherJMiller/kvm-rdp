use crate::support;
use kvm_probe::request::{KvmTarget, Scheme};

fn target(port: u16) -> KvmTarget {
    KvmTarget {
        scheme: Scheme::Https,
        host: "127.0.0.1".into(),
        login_port: port,
        video_port: port,
        control_port: port,
    }
}

#[tokio::test]
async fn correct_pin_connects_wrong_pin_names_observed_fingerprint() {
    let stub = support::start_login_stub().await;
    let t = target(stub.port);
    assert!(
        kvm_probe::kvm::connect_to(&t, stub.port, Some(&stub.pin_hex))
            .await
            .is_ok()
    );

    let wrong = "0".repeat(64);
    let err = match kvm_probe::kvm::connect_to(&t, stub.port, Some(&wrong)).await {
        Ok(_) => panic!("wrong pin must refuse the connection"),
        Err(e) => format!("{e:?}"),
    };
    assert!(err.contains("kvm_cert_mismatch"), "{err}");
    assert!(
        err.contains(&stub.pin_hex),
        "error must name the observed pin: {err}"
    );
}

/// R9: an `Https` target with no pin must be refused before any network
/// I/O. Port 1 is a privileged port nothing here listens on; if
/// `connect_to` tried to dial it first, this would surface a `Connect`
/// error (or hang), not a clean `Tls` refusal.
#[tokio::test]
async fn https_without_pin_is_refused_before_any_network_io() {
    let t = KvmTarget {
        scheme: Scheme::Https,
        host: "127.0.0.1".into(),
        login_port: 1,
        video_port: 1,
        control_port: 1,
    };
    match kvm_probe::kvm::connect_to(&t, 1, None).await {
        Err(kvm_probe::kvm::KvmError::Tls(msg)) => {
            assert!(msg.contains("pin required for https"), "{msg}");
        }
        Ok(_) => panic!("expected Tls error for a missing pin, got Ok"),
        Err(e) => panic!("expected Tls error for a missing pin, got {e:?}"),
    }
}

#[tokio::test]
async fn login_returns_token_from_response() {
    let stub = support::start_login_stub().await;
    let token = kvm_probe::kvm::login(
        &target(stub.port),
        Some(&stub.pin_hex),
        "pw",
        1_759_680_000,
        "UTC",
    )
    .await
    .unwrap();
    assert_eq!(token, "0.987654");
}

#[tokio::test]
async fn non_200_login_is_a_clean_login_error() {
    let stub = support::start_http_stub(support::http_response(
        "302 Found",
        "text/html",
        b"<a href=\"./login.html\">moved</a>",
    ))
    .await;
    match kvm_probe::kvm::login(
        &target(stub.port),
        Some(&stub.pin_hex),
        "pw",
        1_759_680_000,
        "UTC",
    )
    .await
    {
        Err(kvm_probe::kvm::KvmError::Login(msg)) => assert!(msg.contains("302"), "{msg}"),
        other => panic!("expected KvmError::Login, got {other:?}"),
    }
}

#[tokio::test]
async fn rejected_password_body_is_a_clean_login_error() {
    let stub = support::start_http_stub(support::http_response(
        "200 OK",
        "application/json",
        br#"{"result":403}"#,
    ))
    .await;
    assert!(matches!(
        kvm_probe::kvm::login(
            &target(stub.port),
            Some(&stub.pin_hex),
            "pw",
            1_759_680_000,
            "UTC"
        )
        .await,
        Err(kvm_probe::kvm::KvmError::Login(_))
    ));
}
