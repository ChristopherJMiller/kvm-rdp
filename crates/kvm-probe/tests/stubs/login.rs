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

/// I1: a peer that accepts the TCP connection and the TLS handshake but
/// never answers the login request must not hang `login` forever. Paused
/// time lets `LOGIN_TIMEOUT`'s internal sleep auto-advance instantly
/// instead of a real multi-second wait.
#[tokio::test(start_paused = true)]
async fn login_times_out_against_a_silent_peer() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        // Accept and hold the connection open; never speak HTTP.
        let _held = listener.accept().await;
        std::future::pending::<()>().await;
    });
    let t = KvmTarget {
        scheme: Scheme::Http,
        host: "127.0.0.1".into(),
        login_port: port,
        video_port: port,
        control_port: port,
    };
    match kvm_probe::kvm::login(&t, None, "pw", 1_759_680_000, "UTC").await {
        Err(kvm_probe::kvm::KvmError::Login(msg)) => {
            assert!(msg.to_ascii_lowercase().contains("time"), "{msg}");
        }
        other => panic!("expected a timeout Login error, got {other:?}"),
    }
}

/// I1: a peer that accepts the TCP connection but never completes the TLS
/// handshake must not hang `connect_to` forever.
#[tokio::test(start_paused = true)]
async fn connect_to_times_out_against_a_silent_tls_peer() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _held = listener.accept().await;
        std::future::pending::<()>().await;
    });
    let t = KvmTarget {
        scheme: Scheme::Https,
        host: "127.0.0.1".into(),
        login_port: port,
        video_port: port,
        control_port: port,
    };
    let wrong = "0".repeat(64);
    match kvm_probe::kvm::connect_to(&t, port, Some(&wrong)).await {
        Err(kvm_probe::kvm::KvmError::Tls(msg)) => {
            assert!(msg.to_ascii_lowercase().contains("time"), "{msg}");
        }
        Ok(_) => panic!("expected a timeout Tls error, got Ok"),
        Err(e) => panic!("expected a timeout Tls error, got {e:?}"),
    }
}

/// M1: a login response body over the 64 KiB cap is a clean error, not a
/// hang or an unbounded buffer.
#[tokio::test]
async fn login_body_over_64kib_is_a_clean_login_error() {
    let body = vec![b'a'; 70 * 1024];
    let stub =
        support::start_http_stub(support::http_response("200 OK", "application/json", &body)).await;
    match kvm_probe::kvm::login(
        &target(stub.port),
        Some(&stub.pin_hex),
        "pw",
        1_759_680_000,
        "UTC",
    )
    .await
    {
        Err(kvm_probe::kvm::KvmError::Login(msg)) => {
            assert!(msg.contains("cap"), "{msg}");
        }
        other => panic!("expected a clean Login error for an oversize body, got {other:?}"),
    }
}

/// `fingerprint::observe` connects with no pin (record mode) and must
/// report the SPKI the stub actually presents.
#[tokio::test]
async fn observe_reports_the_stub_pin() {
    let stub = support::start_login_stub().await;
    let seen = kvm_probe::fingerprint::observe(&target(stub.port), stub.port)
        .await
        .unwrap();
    assert_eq!(seen, stub.pin_hex);
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

/// m1 (final review): logout is `GET /cgi-bin/login.lua?logout` (the
/// path of `request::logout_url`) on the web port, carrying the token
/// cookie (§3.2: the cookie goes on every request, logout included).
#[tokio::test]
async fn logout_sends_get_logout_with_the_token_cookie() {
    let stub = support::start_http_stub(support::http_response(
        "200 OK",
        "application/json",
        br#"{"result":0}"#,
    ))
    .await;
    kvm_probe::kvm::logout(&target(stub.port), Some(&stub.pin_hex), "0.987654")
        .await
        .unwrap();
    let reqs = stub.requests.lock().unwrap();
    let [head] = reqs.as_slice() else {
        panic!("expected exactly one request: {reqs:?}");
    };
    assert!(
        head.starts_with("GET /cgi-bin/login.lua?logout HTTP/1.1\r\n"),
        "{head}"
    );
    assert!(
        head.to_ascii_lowercase()
            .contains("\r\ncookie: token=0.987654\r\n"),
        "{head}"
    );
}

/// m1: a logged-in session logs out after its work — login, the work
/// with the token, then the logout carrying that token's cookie — so the
/// census's many runs never pile up live KVM sessions.
#[tokio::test]
async fn with_session_logs_out_after_the_work_with_the_token_cookie() {
    let stub = support::start_login_stub().await;
    let s = kvm_probe::kvm::with_session(
        &target(stub.port),
        Some(&stub.pin_hex),
        "pw",
        1_759_680_000,
        "UTC",
        async |token: &str| token.to_string(),
    )
    .await
    .unwrap();
    assert_eq!(s.output, "0.987654");
    assert!(s.logout.is_ok(), "{:?}", s.logout);
    let reqs = stub.requests.lock().unwrap();
    let [login, logout] = reqs.as_slice() else {
        panic!("expected login then logout: {reqs:?}");
    };
    assert!(
        login.starts_with("POST /cgi-bin/login.lua HTTP/1.1\r\n"),
        "{login}"
    );
    assert!(
        logout.starts_with("GET /cgi-bin/login.lua?logout HTTP/1.1\r\n"),
        "{logout}"
    );
    assert!(
        logout
            .to_ascii_lowercase()
            .contains("\r\ncookie: token=0.987654\r\n"),
        "{logout}"
    );
}

/// m1: the logout happens even when the work fails (a failed first-IDR
/// trial still releases its session).
#[tokio::test]
async fn with_session_logs_out_even_when_the_work_fails() {
    let stub = support::start_login_stub().await;
    let s = kvm_probe::kvm::with_session(
        &target(stub.port),
        Some(&stub.pin_hex),
        "pw",
        1_759_680_000,
        "UTC",
        async |_token: &str| -> Result<(), &str> { Err("trial failed") },
    )
    .await
    .unwrap();
    assert_eq!(s.output, Err("trial failed"));
    let reqs = stub.requests.lock().unwrap();
    assert_eq!(reqs.len(), 2, "{reqs:?}");
    assert!(
        reqs[1].starts_with("GET /cgi-bin/login.lua?logout "),
        "{reqs:?}"
    );
}

/// m1: no token, no logout — a failed login is the session's error and
/// nothing else is sent.
#[tokio::test]
async fn with_session_sends_no_logout_when_login_fails() {
    let stub = support::start_http_stub(support::http_response(
        "200 OK",
        "application/json",
        br#"{"result":403}"#,
    ))
    .await;
    let r = kvm_probe::kvm::with_session(
        &target(stub.port),
        Some(&stub.pin_hex),
        "pw",
        1_759_680_000,
        "UTC",
        async |_token: &str| (),
    )
    .await;
    assert!(
        matches!(r, Err(kvm_probe::kvm::KvmError::Login(_))),
        "{r:?}"
    );
    assert_eq!(stub.requests.lock().unwrap().len(), 1);
}

/// m1: logout is best effort but bounded — a peer that never answers it
/// gets a clean timeout error, never a hang (paused time: no real wait).
#[tokio::test(start_paused = true)]
async fn logout_is_bounded_against_a_silent_peer() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _held = listener.accept().await;
        std::future::pending::<()>().await;
    });
    let t = KvmTarget {
        scheme: Scheme::Http,
        host: "127.0.0.1".into(),
        login_port: port,
        video_port: 1,
        control_port: 1,
    };
    match kvm_probe::kvm::logout(&t, None, "0.987654").await {
        Err(kvm_probe::kvm::KvmError::Http(msg)) => {
            assert!(msg.to_ascii_lowercase().contains("time"), "{msg}");
        }
        other => panic!("expected a logout timeout, got {other:?}"),
    }
}

/// m1: a refused logout is an error naming only the status code — never
/// the device's body, which is hostile text.
#[tokio::test]
async fn refused_logout_names_the_status_but_never_the_body() {
    let stub = support::start_http_stub(support::http_response(
        "500 Internal Server Error",
        "text/html",
        b"\x1b]0;pwned\x07 device text",
    ))
    .await;
    let err = kvm_probe::kvm::logout(&target(stub.port), Some(&stub.pin_hex), "0.987654")
        .await
        .unwrap_err();
    let text = format!("{err:?}");
    assert!(text.contains("500"), "{text}");
    assert!(
        !text.contains("pwned") && !text.contains("device text"),
        "{text}"
    );
}
