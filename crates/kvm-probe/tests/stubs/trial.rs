//! Task 5.11: first-IDR latency is measured on the video port, bounded by
//! the caller's `timeout`.
use crate::support;
use kvm_probe::request::{KvmTarget, Scheme};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;

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

fn http_target(port: u16) -> KvmTarget {
    KvmTarget {
        scheme: Scheme::Http,
        host: "127.0.0.1".into(),
        login_port: 1,
        video_port: port,
        control_port: 1,
    }
}

/// B12 review fix round 1, I1: a peer that accepts the TCP connection and
/// never answers the `GET /av.flv` request at all must not hang
/// `first_idr_latency` past its `timeout` argument — the deadline must
/// cover the open, not just the body-read loop.
#[tokio::test]
async fn first_idr_latency_times_out_against_a_silent_peer() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _held = listener.accept().await;
        std::future::pending::<()>().await;
    });
    let started = Instant::now();
    let err = kvm_probe::trial::first_idr_latency(
        &http_target(port),
        None,
        "0.987654",
        Duration::from_millis(200),
    )
    .await
    .unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "first_idr_latency did not return promptly: took {:?}",
        started.elapsed()
    );
    assert!(matches!(err, kvm_probe::kvm::KvmError::Http(_)));
}

/// B12 review fix round 1, I1: a peer that sends `av.flv`'s 200 response
/// headers and then never sends a body must not hang `first_idr_latency`
/// past its `timeout` either — the single deadline must cover the
/// body-read loop too, not just the open.
#[tokio::test]
async fn first_idr_latency_times_out_when_headers_arrive_but_body_stalls() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let Ok((mut tcp, _)) = listener.accept().await else {
            return;
        };
        let _ = tcp
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: video/x-flv\r\nConnection: close\r\n\r\n")
            .await;
        std::future::pending::<()>().await;
    });
    let started = Instant::now();
    let err = kvm_probe::trial::first_idr_latency(
        &http_target(port),
        None,
        "0.987654",
        Duration::from_millis(200),
    )
    .await
    .unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "first_idr_latency did not return promptly: took {:?}",
        started.elapsed()
    );
    assert!(matches!(err, kvm_probe::kvm::KvmError::Http(_)));
}

/// Build one FLV tag: the 11-byte tag header, the body, and the trailing
/// 4-byte `PreviousTagSize` (that tag's own header+body length) — §6.2
/// framing, built by hand so the byte-cap test below doesn't need a real
/// encoder or the committed fixture.
fn flv_tag(tag_type: u8, body: &[u8]) -> Vec<u8> {
    let data_size = u32::try_from(body.len()).unwrap();
    let mut out = Vec::with_capacity(11 + body.len() + 4);
    out.push(tag_type);
    out.extend_from_slice(&data_size.to_be_bytes()[1..]); // u24 data_size
    out.extend_from_slice(&[0, 0, 0]); // timestamp u24 = 0
    out.push(0); // timestamp extension
    out.extend_from_slice(&[0, 0, 0]); // stream id u24 = 0
    out.extend_from_slice(body);
    let total = u32::try_from(11 + body.len()).unwrap();
    out.extend_from_slice(&total.to_be_bytes());
    out
}

/// The FLV file header + leading `PreviousTagSize0` (= 0) + one
/// `AVCDecoderConfigurationRecord` sequence-header tag (needed before any
/// NALU tag can be parsed), with a throwaway 1-byte SPS/PPS each.
fn flv_prelude() -> Vec<u8> {
    let mut out = vec![b'F', b'L', b'V', 1, 0x01];
    out.extend_from_slice(&9u32.to_be_bytes()); // DataOffset = 9
    out.extend_from_slice(&0u32.to_be_bytes()); // PreviousTagSize0 = 0
    let avc_config: [u8; 13] = [
        0x01, 0x42, 0x00, 0x1E, // version, profile_idc, compat, level_idc
        0xFF, // lengthSizeMinusOne = 3 (length_size = 4)
        0x01, 0x00, 0x01, 0x67, // 1 SPS, len=1, byte 0x67
        0x01, 0x00, 0x01, 0x68, // 1 PPS, len=1, byte 0x68
    ];
    let mut body = vec![0x17, 0x00, 0x00, 0x00, 0x00]; // key, AVC, seq-header, ct=0
    body.extend_from_slice(&avc_config);
    out.extend_from_slice(&flv_tag(9, &body));
    out
}

/// One AVC NALU video tag carrying a single non-IDR slice NAL (type 1) — a
/// stand-in "P-frame" that must never be mistaken for an IDR (type 5).
fn p_frame_tag() -> Vec<u8> {
    let nal: [u8; 3] = [0x21, 0x88, 0x80]; // forbidden=0, ref_idc=1, type=1
    let mut body = vec![0x27, 0x01, 0x00, 0x00, 0x00]; // inter, AVC, NALU, ct=0
    body.extend_from_slice(&u32::try_from(nal.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&nal);
    flv_tag(9, &body)
}

/// B12 review fix round 1, I1: `first_idr_latency` must stop at a byte cap
/// even against a peer that streams well-framed FLV P-frames (never an
/// IDR) without end. Exercised through the `_capped` seam with a small
/// cap so the test doesn't need to stream the real 64 MiB `MAX_BYTES`
/// bound — the public `first_idr_latency`'s signature is unchanged.
#[tokio::test]
async fn first_idr_latency_capped_stops_at_the_byte_cap_with_no_idr() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let Ok((mut tcp, _)) = listener.accept().await else {
            return;
        };
        let _ = tcp
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: video/x-flv\r\nConnection: close\r\n\r\n")
            .await;
        let mut flv = flv_prelude();
        let p_frame = p_frame_tag();
        for _ in 0..200 {
            flv.extend_from_slice(&p_frame);
        }
        // Well past the test's small byte cap; the client is expected to
        // stop reading long before this (or the connection) ends.
        let _ = tcp.write_all(&flv).await;
        std::future::pending::<()>().await;
    });
    let started = Instant::now();
    let err = kvm_probe::trial::first_idr_latency_capped(
        &http_target(port),
        None,
        "0.987654",
        Duration::from_secs(5),
        256,
    )
    .await
    .unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the byte cap did not stop the read promptly: took {:?}",
        started.elapsed()
    );
    assert!(
        format!("{err:?}").to_ascii_lowercase().contains("cap"),
        "{err:?}"
    );
}

/// One port serving login, av.flv and logout, as `start_kvm_stub` does.
fn kvm_target(port: u16) -> KvmTarget {
    KvmTarget {
        scheme: Scheme::Https,
        host: "127.0.0.1".into(),
        login_port: port,
        video_port: port,
        control_port: 1,
    }
}

fn plan(trials: u32) -> kvm_probe::trial::TrialPlan {
    kvm_probe::trial::TrialPlan {
        trials,
        timeout: Duration::from_secs(5),
        pause: Duration::from_millis(1),
    }
}

/// (logins, av.flv opens, logouts) in a stub's recorded requests, and
/// whether the first request was the login and the last the logout.
fn tally(reqs: &[String]) -> (usize, usize, usize, bool, bool) {
    let count = |p: &str| reqs.iter().filter(|r| r.starts_with(p)).count();
    (
        count("POST /cgi-bin/login.lua "),
        count("GET /av.flv?"),
        count("GET /cgi-bin/login.lua?logout "),
        reqs.first()
            .is_some_and(|r| r.starts_with("POST /cgi-bin/login.lua ")),
        reqs.last()
            .is_some_and(|r| r.starts_with("GET /cgi-bin/login.lua?logout ")),
    )
}

/// m1 correction (final review): a first-idr run logs in ONCE, every trial
/// reopens av.flv with that same token (the bridge's reconnect-on-same-
/// session path — a fresh login per trial could itself trigger an IDR and
/// bias the measurement), and logs out ONCE at the end — for any trial
/// count.
#[tokio::test]
async fn first_idr_run_logs_in_once_and_out_once_for_any_trial_count() {
    for trials in [1u32, 3] {
        let stub = support::start_kvm_stub(true).await;
        let mut lines = Vec::new();
        let s = kvm_probe::trial::first_idr_run(
            &kvm_target(stub.port),
            Some(&stub.pin_hex),
            Some(&stub.pin_hex),
            "pw",
            1_759_680_000,
            &plan(trials),
            |n, line| lines.push(format!("{n}: {line}")),
        )
        .await
        .unwrap();
        assert_eq!(
            s.output.successes.len(),
            usize::try_from(trials).unwrap(),
            "{lines:?} {:?}",
            s.output.failures
        );
        assert!(s.output.failures.is_empty());
        assert!(s.logout.is_ok(), "{:?}", s.logout);
        assert_eq!(lines.len(), usize::try_from(trials).unwrap());

        let reqs = stub.requests.lock().unwrap();
        let expected_opens = usize::try_from(trials).unwrap();
        assert_eq!(
            tally(&reqs),
            (1, expected_opens, 1, true, true),
            "trials={trials}: {reqs:#?}"
        );
        // Every trial carries the one login's token, as query and cookie.
        for r in reqs.iter().filter(|r| r.starts_with("GET /av.flv?")) {
            assert!(r.starts_with("GET /av.flv?token=0.987654 "), "{r}");
            assert!(
                r.to_ascii_lowercase()
                    .contains("\r\ncookie: token=0.987654\r\n"),
                "{r}"
            );
        }
    }
}

/// m1 correction: a trial that fails because the KVM refuses the token on
/// av.flv is recorded as a failed trial like any other, the run goes on,
/// and there is still exactly one login and one logout — the logout
/// happens even though every trial failed.
#[tokio::test]
async fn rejected_token_trials_fail_and_the_run_still_logs_out_once() {
    let stub = support::start_kvm_stub(false).await;
    let s = kvm_probe::trial::first_idr_run(
        &kvm_target(stub.port),
        Some(&stub.pin_hex),
        Some(&stub.pin_hex),
        "pw",
        1_759_680_000,
        &plan(3),
        |_, _| {},
    )
    .await
    .unwrap();
    assert!(s.output.successes.is_empty());
    assert_eq!(s.output.failures.len(), 3, "{:?}", s.output.failures);
    assert!(
        s.output.failures.iter().all(|f| f.contains("403")),
        "{:?}",
        s.output.failures
    );
    assert!(s.output.all_failed());
    assert!(s.logout.is_ok(), "{:?}", s.logout);
    let reqs = stub.requests.lock().unwrap();
    assert_eq!(tally(&reqs), (1, 3, 1, true, true), "{reqs:#?}");
}
