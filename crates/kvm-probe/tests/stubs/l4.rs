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
