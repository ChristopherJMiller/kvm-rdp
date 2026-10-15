//! `ws-close`'s two census verdicts (§3.2: only an answered close frame is a
//! clean close) against in-process websocket stubs over pinned TLS, as on
//! the ES3. kvm-sim never answers a close frame (its loop ends on the
//! client's Close before the reply is flushed), so the answered branch is
//! proven here (PD2 review I1).
use crate::support;
use futures_util::StreamExt as _;
use kvm_probe::l4::ws::{self, Reply, TcpEnd, Upgrade};
use kvm_probe::request::{KvmTarget, Scheme};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

const T: Duration = Duration::from_secs(5);

/// One-connection websocket stub. `answer`: reply to the client's close
/// frame with one of its own, then close TLS and TCP cleanly; otherwise
/// drop the connection as soon as the client's close arrives, unanswered
/// (a bare EOF). Counts every data frame it receives.
async fn close_stub(answer: bool) -> (u16, String, Arc<AtomicUsize>) {
    let (acceptor, pin_hex) = support::tls_acceptor_and_pin();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let data_frames = Arc::new(AtomicUsize::new(0));
    let df = data_frames.clone();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(tls).await.unwrap();
        loop {
            match tokio::time::timeout(T, ws.next()).await {
                Ok(Some(Ok(Message::Close(_)))) if !answer => return,
                Ok(Some(Ok(m))) => {
                    if m.is_binary() || m.is_text() {
                        df.fetch_add(1, Ordering::SeqCst);
                    }
                }
                // The read after the client's Close flushes tungstenite's
                // queued answer, then ends the server's side.
                Ok(Some(Err(_)) | None) | Err(_) => break,
            }
        }
        let _ = ws.get_mut().shutdown().await;
    });
    (port, pin_hex, data_frames)
}

fn target(port: u16) -> KvmTarget {
    KvmTarget {
        scheme: Scheme::Https,
        host: "127.0.0.1".into(),
        login_port: 1,
        video_port: 1,
        control_port: port,
    }
}

async fn close_report(answer: bool) -> (ws::CloseReport, usize) {
    let (port, pin, data_frames) = close_stub(answer).await;
    let Ok(Upgrade::Accepted(w)) = ws::upgrade(&target(port), Some(&pin), Some("0.1"), T).await
    else {
        panic!("not upgraded")
    };
    let r = ws::close_form(*w, Duration::from_millis(200), Duration::from_secs(2)).await;
    (r, data_frames.load(Ordering::SeqCst))
}

/// A KVM that answers our close frame with its own: `Reply::CloseFrame`,
/// then a FIN — the clean close. The probe sent no data frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_close_reports_an_answered_close_frame() {
    let (r, data_frames) = close_report(true).await;
    assert!(!r.idle.closed_by_kvm, "{r:?}");
    assert!(matches!(r.reply, Reply::CloseFrame { .. }), "{r:?}");
    assert!(matches!(r.tcp, TcpEnd::Fin { .. }), "{r:?}");
    assert_eq!(data_frames, 0, "ws-close sent a data frame");
}

/// A KVM that drops the connection on our close frame without answering:
/// never reported as a close frame (nor as a timeout).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_close_never_reports_an_unanswered_close_as_a_close_frame() {
    let (r, data_frames) = close_report(false).await;
    assert!(
        matches!(r.reply, Reply::Error { .. } | Reply::Eof { .. }),
        "{r:?}"
    );
    assert!(!matches!(r.tcp, TcpEnd::Timeout), "{r:?}");
    assert_eq!(data_frames, 0, "ws-close sent a data frame");
}

/// PD3 I1 (c): a release is confirmed only when the KVM answers its close
/// frame — the stub that answers gives `Confirmed`, the one that drops the
/// connection gives `Unconfirmed`. Either way it got exactly the session
/// start's two reports and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_release_is_confirmed_only_by_an_answered_close_frame() {
    use kvm_probe::l4::hid::{self, Released};
    for (answer, want) in [(true, true), (false, false)] {
        let (port, pin, data_frames) = close_stub(answer).await;
        let r = hid::release(&target(port), Some(&pin), "0.1", None, T)
            .await
            .unwrap();
        assert_eq!(r == Released::Confirmed, want, "answer={answer}: {r:?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(data_frames.load(Ordering::SeqCst), 2, "answer={answer}");
    }
}

/// A websocket stub for any number of connections that answers every
/// close frame — a KVM that confirms releases. Records each connection's
/// data-frame count once it closes.
async fn answering_stub() -> (u16, String, Arc<std::sync::Mutex<Vec<usize>>>) {
    let (acceptor, pin_hex) = support::tls_acceptor_and_pin();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let closed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = closed.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, log) = (acceptor.clone(), log.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(mut ws) = tokio_tungstenite::accept_async(tls).await else {
                    return;
                };
                let mut frames = 0;
                // After the client's Close, the next read flushes the
                // queued answer and ends the stream.
                while let Ok(Some(Ok(m))) = tokio::time::timeout(T, ws.next()).await {
                    if m.is_binary() || m.is_text() {
                        frames += 1;
                    }
                }
                let _ = ws.get_mut().shutdown().await;
                log.lock().unwrap().push(frames);
            });
        }
    });
    (port, pin_hex, closed)
}

/// PD3 R-m1: a failed body whose releases the KVM confirmed ends with the
/// body's own error. KEY MAY BE HELD is for a failed run whose releases
/// nobody confirmed (the kvm-sim case, which answers no close frame).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_body_whose_releases_are_confirmed_keeps_its_own_error() {
    use kvm_probe::l4::hid::{self, HidWs};
    use kvm_proto::hid::HidFrame;
    let (port, pin, closed) = answering_stub().await;
    let t = target(port);
    let mut irq = hid::Interrupts::new().unwrap();
    let r: Result<(), _> = hid::guarded(&t, Some(&pin), "0.1", None, &mut irq, async {
        let mut w = HidWs::open(&t, Some(&pin), "0.1", T).await?;
        w.send(HidFrame::Keyboard {
            modifiers: 0,
            keys: [0x04, 0, 0, 0, 0],
        })
        .await?;
        Err(kvm_probe::kvm::KvmError::Io("the body failed".to_owned()))
    })
    .await;
    let e = format!("{:?}", r.unwrap_err());
    assert!(e.contains("the body failed"), "{e}");
    assert!(!e.contains("KEY MAY BE HELD"), "{e}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    // The body's websocket (its 3 frames) and both releases (2 each).
    let mut got = closed.lock().unwrap().clone();
    got.sort_unstable();
    assert_eq!(got, [2, 2, 3]);
}

/// How a plain-TCP websocket stub saw each connection end.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Ended {
    CloseFrame,
    Fin,
    Reset,
    Other(String),
}

/// A plain-TCP (no TLS, so a FIN and a reset are told apart cleanly)
/// websocket stub for any number of connections: records each one's data
/// frames and how it ended.
async fn end_stub() -> (u16, Arc<std::sync::Mutex<Vec<(Vec<Vec<u8>>, Ended)>>>) {
    use tokio_tungstenite::tungstenite::{Error, error::ProtocolError};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let log = log.clone();
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else {
                    return;
                };
                let mut frames = Vec::new();
                let ended = loop {
                    match tokio::time::timeout(T, ws.next()).await {
                        Ok(Some(Ok(Message::Close(_)))) => break Ended::CloseFrame,
                        Ok(Some(Ok(Message::Binary(b)))) => frames.push(b),
                        Ok(Some(Ok(_))) => {}
                        Ok(Some(Err(Error::Protocol(
                            ProtocolError::ResetWithoutClosingHandshake,
                        )))) => break Ended::Fin,
                        Ok(Some(Err(Error::Io(e))))
                            if e.kind() == std::io::ErrorKind::ConnectionReset =>
                        {
                            break Ended::Reset;
                        }
                        Ok(Some(Err(e))) => break Ended::Other(e.to_string()),
                        Ok(None) => break Ended::Other("eof".to_owned()),
                        Err(_) => break Ended::Other("timeout".to_owned()),
                    }
                };
                log.lock().unwrap().push((frames, ended));
            });
        }
    });
    (port, seen)
}

/// DC18's census fact is per end kind, so `hold_then_kill` must end the
/// websocket exactly as told: a close frame, a FIN, or a reset — each
/// after the session start and the one held '1', and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hid_hold_ends_its_websocket_the_way_it_was_told() {
    use kvm_probe::l4::hid::End;
    use kvm_probe::l4::hold;
    use kvm_proto::hid::HidFrame;
    let (port, seen) = end_stub().await;
    let t = KvmTarget {
        scheme: Scheme::Http,
        ..target(port)
    };
    let held = vec![
        HidFrame::SetMode { hid_type: 0 }.to_vec(),
        HidFrame::Keyboard {
            modifiers: 0,
            keys: [0; 5],
        }
        .to_vec(),
        HidFrame::Keyboard {
            modifiers: 0,
            keys: [0x1E, 0, 0, 0, 0],
        }
        .to_vec(),
    ];
    for (n, (end, want)) in [
        (End::CloseFrame, Ended::CloseFrame),
        (End::Fin, Ended::Fin),
        (End::Reset, Ended::Reset),
    ]
    .into_iter()
    .enumerate()
    {
        let r = hold::hold_then_kill(
            &t,
            None,
            "0.1",
            hold::HOLD_USAGE,
            end,
            Duration::from_millis(50),
        )
        .await
        .unwrap();
        assert_eq!(r.end, end);
        let deadline = std::time::Instant::now() + T;
        while seen.lock().unwrap().len() <= n {
            assert!(std::time::Instant::now() < deadline, "{end:?}: no end seen");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let got = seen.lock().unwrap()[n].clone();
        assert_eq!(got, (held.clone(), want), "{end:?}");
    }
}

/// D5 and PD3 R-m1, the other half: a KVM that confirms both releases
/// (it answers each close frame) — `hid-stale` ends Ok with its report,
/// after exactly two releases, each the session start alone; the burst's
/// websocket carried at most the session start and the 128 reports, the
/// fresh one the session start and the reset tap.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hid_stale_with_confirmed_releases_ends_ok_after_two_releases() {
    use kvm_probe::l4::hid;
    let (port, pin, closed) = answering_stub().await;
    let t = target(port);
    let mut irq = hid::Interrupts::new().unwrap();
    let mut lines = Vec::new();
    let r = hid::hid_stale(
        &t,
        Some(&pin),
        "0.1",
        Duration::from_millis(100),
        &mut irq,
        async |_: &str| Ok(()),
        |l| lines.push(l),
    )
    .await
    .unwrap();
    assert_eq!(r.pushed, 128);
    assert_eq!(lines.len(), 1, "{lines:?}");
    let deadline = std::time::Instant::now() + T;
    while closed.lock().unwrap().len() < 4 {
        assert!(std::time::Instant::now() < deadline, "{:?}", closed.lock());
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The burst's websocket was reset, so how much of it the stub read
    // before the reset may vary; the other three are exact.
    let got = closed.lock().unwrap().clone();
    assert_eq!(got.len(), 4, "a websocket too many or too few: {got:?}");
    assert!(got.iter().filter(|&&n| n == 2).count() >= 2, "{got:?}");
    assert!(got.contains(&4), "{got:?}");
    assert!(got.iter().all(|&n| n <= 130), "{got:?}");
}

/// `web-get` over a hostile page: the status, the `Server` header cut to
/// 120 bytes and the body's first 512 bytes, each escaped — no raw control
/// byte or non-ASCII byte reaches the terminal, however long the page.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn web_get_bounds_and_escapes_a_hostile_page() {
    use kvm_probe::l4::{escaped, web};
    let mut body = b"\x1b]0;owned\x07\x00".to_vec();
    body.extend(std::iter::repeat_n(b'\x1b', 100_000));
    let mut server = b"ES3 \"x\" \\ \xff\xfe ".to_vec();
    server.extend(std::iter::repeat_n(b'v', 300));
    let mut resp = b"HTTP/1.1 200 OK\r\nServer: ".to_vec();
    resp.extend_from_slice(&server);
    resp.extend_from_slice(
        format!(
            "\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    resp.extend_from_slice(&body);
    let stub = support::start_http_stub(resp).await;
    let t = KvmTarget {
        login_port: stub.port,
        ..target(1)
    };
    let p = web::get(&t, Some(&stub.pin_hex), "/about.html")
        .await
        .unwrap();
    assert_eq!(p.status, 200);
    assert_eq!(p.server.as_deref(), Some(escaped(&server, 120).as_str()));
    assert_eq!(p.snippet, escaped(&body, 512));
    for s in [p.server.as_deref().unwrap(), p.snippet.as_str()] {
        assert!(s.bytes().all(|b| (0x20..0x7f).contains(&b)), "{s:?}");
    }
    let req = stub.requests.lock().unwrap()[0].clone();
    assert!(req.starts_with("GET /about.html HTTP/1.1\r\n"), "{req}");
}
