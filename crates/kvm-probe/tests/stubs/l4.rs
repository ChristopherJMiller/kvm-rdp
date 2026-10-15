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
use std::time::{Duration, Instant};
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

// --- Task 1.5: hid-hold and hid-stale against a ledger stub (PD4 fix
// round 1: I1, I2, I3, m4, m5).

/// How a ledger stub saw a connection end.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Ended {
    CloseFrame,
    Fin,
    Reset,
    Other(String),
}

/// What a ledger stub saw on one connection, in accept order.
#[derive(Debug, Clone)]
struct Seen {
    /// When it was accepted.
    opened: Instant,
    /// Each data frame and when it was read.
    frames: Vec<(Instant, Vec<u8>)>,
    ended: Option<(Instant, Ended)>,
    /// When it was accepted, the kernel's TCP state (`tcpi_state`) of every
    /// earlier connection, by index: `TCP_CLOSE` once a reset arrived,
    /// `TCP_CLOSE_WAIT` once a FIN did, `TCP_ESTABLISHED` before either.
    /// Read from the kernel, so it is exact whatever the stub's tasks were
    /// doing.
    states_at_open: Vec<u8>,
}

const TCP_ESTABLISHED: u8 = 1;
const TCP_CLOSE: u8 = 7;
const TCP_CLOSE_WAIT: u8 = 8;

/// The kernel's TCP state of `s` (`TCP_INFO`), read-only.
fn tcp_state(s: &socket2::Socket) -> u8 {
    use std::os::fd::AsRawFd as _;
    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            (&raw mut info).cast(),
            &raw mut len,
        )
    };
    assert_eq!(rc, 0, "TCP_INFO: {}", std::io::Error::last_os_error());
    info.tcpi_state
}

#[derive(Debug, Default, Clone, Copy)]
struct LedgerOpts {
    /// `(n, after, for)`: connection `n` reads nothing once it has read
    /// `after` frames, for `for` — its kernel still takes (and ACKs) what
    /// fits its receive buffer: a KVM whose handler is stuck.
    stall: Option<(usize, usize, Duration)>,
    /// `SO_RCVBUF` on the listener, inherited by each accepted socket.
    rcvbuf: Option<u32>,
}

type Ledger = Arc<std::sync::Mutex<Vec<Seen>>>;

/// A plain-TCP websocket stub (no TLS, so a FIN and a reset are told
/// apart cleanly) for any number of connections. It answers every close
/// frame — a KVM that confirms releases — and records `Seen` for each
/// connection.
async fn ledger_stub(opts: LedgerOpts) -> (u16, Ledger) {
    use tokio_tungstenite::tungstenite::{Error, error::ProtocolError};
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    if let Some(n) = opts.rcvbuf {
        sock.set_recv_buffer_size(n).unwrap();
    }
    sock.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = sock.listen(64).unwrap();
    let port = listener.local_addr().unwrap().port();
    let ledger: Ledger = Arc::default();
    let log = ledger.clone();
    tokio::spawn(async move {
        let mut socks: Vec<socket2::Socket> = Vec::new();
        while let Ok((tcp, _)) = listener.accept().await {
            let opened = Instant::now();
            let states_at_open = socks.iter().map(tcp_state).collect();
            socks.push(socket2::SockRef::from(&tcp).try_clone().unwrap());
            let n = {
                let mut l = log.lock().unwrap();
                l.push(Seen {
                    opened,
                    frames: Vec::new(),
                    ended: None,
                    states_at_open,
                });
                l.len() - 1
            };
            let log = log.clone();
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(tcp).await else {
                    return;
                };
                let mut stalled = false;
                let ended = loop {
                    if let Some((k, after, d)) = opts.stall
                        && k == n
                        && !stalled
                        && log.lock().unwrap()[n].frames.len() >= after
                    {
                        stalled = true;
                        tokio::time::sleep(d).await;
                    }
                    let got = tokio::time::timeout(Duration::from_secs(30), ws.next()).await;
                    let at = Instant::now();
                    match got {
                        Ok(Some(Ok(Message::Close(_)))) => {
                            // The next read flushes tungstenite's queued
                            // answer, then ends the stream.
                            let _ = tokio::time::timeout(T, ws.next()).await;
                            break (at, Ended::CloseFrame);
                        }
                        Ok(Some(Ok(Message::Binary(b)))) => {
                            log.lock().unwrap()[n].frames.push((at, b));
                        }
                        Ok(Some(Ok(_))) => {}
                        Ok(Some(Err(Error::Protocol(
                            ProtocolError::ResetWithoutClosingHandshake,
                        )))) => break (at, Ended::Fin),
                        Ok(Some(Err(Error::Io(e))))
                            if e.kind() == std::io::ErrorKind::ConnectionReset =>
                        {
                            break (at, Ended::Reset);
                        }
                        Ok(Some(Err(e))) => break (at, Ended::Other(e.to_string())),
                        Ok(None) => break (at, Ended::Other("eof".to_owned())),
                        Err(_) => break (at, Ended::Other("timeout".to_owned())),
                    }
                };
                log.lock().unwrap()[n].ended = Some(ended);
            });
        }
    });
    (port, ledger)
}

/// Wait (bounded) until the ledger has `n` connections and all have ended.
async fn all_ended(ledger: &Ledger, n: usize, within: Duration) -> Vec<Seen> {
    let deadline = Instant::now() + within;
    loop {
        {
            let l = ledger.lock().unwrap();
            if l.len() >= n && l.iter().all(|s| s.ended.is_some()) {
                return l.clone();
            }
        }
        assert!(
            Instant::now() < deadline,
            "{:?}",
            ledger
                .lock()
                .unwrap()
                .iter()
                .map(|s| (s.frames.len(), s.ended.clone()))
                .collect::<Vec<_>>()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn plain(port: u16) -> KvmTarget {
    KvmTarget {
        scheme: Scheme::Http,
        ..target(port)
    }
}

fn kbd(modifiers: u8, k: u8) -> Vec<u8> {
    kvm_proto::hid::HidFrame::Keyboard {
        modifiers,
        keys: [k, 0, 0, 0, 0],
    }
    .to_vec()
}

fn session_start() -> Vec<Vec<u8>> {
    vec![
        kvm_proto::hid::HidFrame::SetMode { hid_type: 0 }.to_vec(),
        kbd(0, 0),
    ]
}

fn frames(s: &Seen) -> Vec<Vec<u8>> {
    s.frames.iter().map(|(_, f)| f.clone()).collect()
}

/// The stale burst's 130 frames as the KVM reads them: the session start,
/// then 'a'..'t' (cycling) each followed by a zero report, 64 times.
fn whole_burst() -> Vec<Vec<u8>> {
    let mut v = session_start();
    for i in 0..64u8 {
        v.push(kbd(0, 0x04 + i % 20));
        v.push(kbd(0, 0));
    }
    v
}

/// One snapshot hook's calls: the suffix, the token it was given, when.
type Shots = Arc<std::sync::Mutex<Vec<(String, String, Instant)>>>;

/// DC18's census fact is per end kind, so `hold_then_kill` must end the
/// websocket exactly as told — a close frame, a FIN, or a reset — each
/// after the session start and the one held '1', and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hid_hold_ends_its_websocket_the_way_it_was_told() {
    use kvm_probe::l4::hid::End;
    use kvm_probe::l4::hold;
    let (port, ledger) = ledger_stub(LedgerOpts::default()).await;
    let held = [session_start(), vec![kbd(0, 0x1E)]].concat();
    for (n, (end, want)) in [
        (End::CloseFrame, Ended::CloseFrame),
        (End::Fin, Ended::Fin),
        (End::Reset, Ended::Reset),
    ]
    .into_iter()
    .enumerate()
    {
        let r = hold::hold_then_kill(
            &plain(port),
            None,
            "0.1",
            hold::HOLD_USAGE,
            end,
            Duration::from_millis(50),
        )
        .await
        .unwrap();
        assert_eq!(r.end, end);
        let seen = all_ended(&ledger, n + 1, T).await;
        assert_eq!(frames(&seen[n]), held, "{end:?}");
        assert_eq!(seen[n].ended.as_ref().unwrap().1, want, "{end:?}");
    }
}

/// I3 and I2 (PD4 fix round 1): `hid_hold` itself, once per end kind,
/// against a KVM that confirms releases. Each run:
/// - ends the held websocket as told (the kernel's view: closed by a
///   reset, half-closed by a FIN) before the release opens;
/// - takes `_held` no sooner than `observe` after the press arrived, and
///   before any release;
/// - releases twice, `SECOND_RELEASE_AFTER` apart, even though it
///   succeeded (its body left '1' last on a dead websocket);
/// - takes `_released` after both, with the token.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hid_hold_runs_each_end_kind_and_releases_twice() {
    use kvm_probe::l4::hid::{End, Interrupts};
    use kvm_probe::l4::hold;
    let observe = Duration::from_millis(1000);
    let one = async |end: End| {
        let (port, ledger) = ledger_stub(LedgerOpts::default()).await;
        let shots: Shots = Arc::default();
        let mut irq = Interrupts::new().unwrap();
        let r = hold::hid_hold(
            &plain(port),
            None,
            "0.1",
            &hold::HoldPlan::new(end, observe),
            &mut irq,
            async |suffix: &str, token: &str| {
                shots
                    .lock()
                    .unwrap()
                    .push((suffix.to_owned(), token.to_owned(), Instant::now()));
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(r.end, end);
        let seen = all_ended(&ledger, 3, T).await;
        (seen, shots.lock().unwrap().clone())
    };
    let ((close, close_shots), (fin, fin_shots), (reset, reset_shots)) =
        tokio::join!(one(End::CloseFrame), one(End::Fin), one(End::Reset));
    for (end, seen, shots, kind, state) in [
        (End::CloseFrame, close, close_shots, Ended::CloseFrame, None),
        (End::Fin, fin, fin_shots, Ended::Fin, Some(TCP_CLOSE_WAIT)),
        (
            End::Reset,
            reset,
            reset_shots,
            Ended::Reset,
            Some(TCP_CLOSE),
        ),
    ] {
        assert_eq!(seen.len(), 3, "{end:?}: {seen:?}");
        let (held, rel1, rel2) = (&seen[0], &seen[1], &seen[2]);
        assert_eq!(
            frames(held),
            [session_start(), vec![kbd(0, 0x1E)]].concat(),
            "{end:?}"
        );
        assert_eq!(held.ended.as_ref().unwrap().1, kind, "{end:?}");
        if let Some(s) = state {
            assert_eq!(
                rel1.states_at_open[0], s,
                "{end:?}: not ended before the release"
            );
        }
        for rel in [rel1, rel2] {
            assert_eq!(frames(rel), session_start(), "{end:?}");
            assert_eq!(rel.ended.as_ref().unwrap().1, Ended::CloseFrame, "{end:?}");
        }
        let apart = rel2.opened.saturating_duration_since(rel1.opened);
        assert!(apart >= Duration::from_millis(4500), "{end:?}: {apart:?}");
        let names: Vec<&str> = shots.iter().map(|(s, _, _)| s.as_str()).collect();
        assert_eq!(names, ["_held", "_released"], "{end:?}");
        assert!(shots.iter().all(|(_, tok, _)| tok == "0.1"), "{end:?}");
        let press_at = held.frames[2].0;
        let held_at = shots[0].2;
        assert!(
            held_at.saturating_duration_since(press_at) >= observe - Duration::from_millis(100),
            "{end:?}: _held came {:?} after the press",
            held_at.saturating_duration_since(press_at)
        );
        assert!(held_at <= rel1.opened, "{end:?}: _held after a release");
        assert!(
            shots[1].2 >= rel2.ended.as_ref().unwrap().0,
            "{end:?}: _released too early"
        );
    }
}

/// I3 (PD4 fix round 1): `hid_stale`'s mechanics, against a KVM that
/// confirms releases.
/// - The burst's websocket carries the session start and all 128 reports
///   (drained before the reset, I1) and ends by a reset — the kernel shows
///   it closed by a reset before the fresh websocket was accepted.
/// - The fresh one carries the session start and the reset tap, then a
///   close frame.
/// - The snapshot comes no sooner than `settle` after the fresh websocket
///   opened, after the report line (m4), and before any release.
/// - Two releases, `SECOND_RELEASE_AFTER` apart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hid_stale_resets_the_drained_burst_before_the_fresh_websocket_and_settles() {
    use kvm_probe::l4::hid::{self, Interrupts};
    let (port, ledger) = ledger_stub(LedgerOpts::default()).await;
    let settle = Duration::from_millis(1000);
    let lines = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let shots: Shots = Arc::default();
    let lines_at_shot = Arc::new(AtomicUsize::new(usize::MAX));
    let mut irq = Interrupts::new().unwrap();
    let r = hid::hid_stale(
        &plain(port),
        None,
        "0.1",
        &hid::StalePlan::new(settle),
        &mut irq,
        async |suffix: &str, token: &str| {
            lines_at_shot.store(lines.lock().unwrap().len(), Ordering::SeqCst);
            shots
                .lock()
                .unwrap()
                .push((suffix.to_owned(), token.to_owned(), Instant::now()));
            Ok(())
        },
        |l| lines.lock().unwrap().push(l),
    )
    .await
    .unwrap();
    assert_eq!(r.pushed, 128);
    let seen = all_ended(&ledger, 4, T).await;
    assert_eq!(seen.len(), 4, "{seen:?}");
    let (burst, fresh, rel1, rel2) = (&seen[0], &seen[1], &seen[2], &seen[3]);
    assert_eq!(frames(burst), whole_burst());
    assert_eq!(burst.ended.as_ref().unwrap().1, Ended::Reset);
    assert_eq!(
        fresh.states_at_open[0], TCP_CLOSE,
        "the burst's websocket was not reset before the fresh one opened"
    );
    assert_eq!(
        frames(fresh),
        [session_start(), vec![kbd(0x10, 0), kbd(0, 0)]].concat()
    );
    assert_eq!(fresh.ended.as_ref().unwrap().1, Ended::CloseFrame);
    let shots = shots.lock().unwrap().clone();
    assert_eq!(shots.len(), 1);
    assert_eq!(shots[0].0, "");
    assert_eq!(
        lines_at_shot.load(Ordering::SeqCst),
        1,
        "the report came after the snapshot"
    );
    let since_fresh = shots[0].2.saturating_duration_since(fresh.opened);
    assert!(
        since_fresh >= settle,
        "the snapshot came {since_fresh:?} after the fresh websocket"
    );
    assert!(
        shots[0].2 <= rel1.opened,
        "the snapshot came after a release"
    );
    for rel in [rel1, rel2] {
        assert_eq!(frames(rel), session_start());
        assert_eq!(rel.ended.as_ref().unwrap().1, Ended::CloseFrame);
        assert_eq!(rel.states_at_open[0], TCP_CLOSE);
    }
    let apart = rel2.opened.saturating_duration_since(rel1.opened);
    assert!(apart >= Duration::from_millis(4500), "{apart:?}");
    let lines = lines.lock().unwrap().clone();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("pushed: 128"), "{lines:?}");
}

/// I1 (PD4 fix round 1), the review's reproduction: the burst's handler
/// is stuck (it reads its session start, then nothing for 8 s) while
/// every other connection is read and its release confirmed at once. The
/// run waits for the burst to drain into the KVM's kernel before the
/// reset, so the stuck handler later reads the whole burst — after both
/// releases — and its last report is a zero: nothing is left held, and
/// the run's `pushed: 128` is what the KVM got.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hid_stale_drains_so_a_stuck_reader_still_ends_released() {
    use kvm_probe::l4::hid::{self, Interrupts};
    let (port, ledger) = ledger_stub(LedgerOpts {
        stall: Some((0, 2, Duration::from_secs(8))),
        ..LedgerOpts::default()
    })
    .await;
    let mut irq = Interrupts::new().unwrap();
    let r = hid::hid_stale(
        &plain(port),
        None,
        "0.1",
        &hid::StalePlan::new(Duration::from_millis(100)),
        &mut irq,
        async |_: &str, _: &str| Ok(()),
        |_| {},
    )
    .await
    .unwrap();
    assert_eq!(r.pushed, 128);
    let seen = all_ended(&ledger, 4, Duration::from_secs(20)).await;
    let burst = &seen[0];
    assert_eq!(
        frames(burst),
        whole_burst(),
        "the stuck handler got a cut burst"
    );
    assert_eq!(burst.frames.last().unwrap().1, kbd(0, 0));
    let second_release_end = seen[3].ended.as_ref().unwrap().0;
    assert!(
        burst.frames.last().unwrap().0 > second_release_end,
        "the backlog did not land after both releases: the case is not exercised"
    );
}

/// I1 (PD4 fix round 1): a burst that never drains — the stuck handler's
/// receive buffer is tiny, so its window closes — is never reset (which
/// would cut it at an arbitrary report): it is closed with a FIN, so the
/// KVM gets all of it, ending on a zero, once it reads again. The run is
/// loud whatever the releases said: KEY MAY BE HELD with the remedy, and
/// why. No fresh websocket is opened, and both releases run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hid_stale_never_cuts_a_burst_that_does_not_drain() {
    use kvm_probe::l4::hid::{self, Interrupts};
    let (port, ledger) = ledger_stub(LedgerOpts {
        stall: Some((0, 2, Duration::from_secs(4))),
        rcvbuf: Some(1),
    })
    .await;
    let mut irq = Interrupts::new().unwrap();
    let mut lines = Vec::new();
    let e = hid::hid_stale(
        &plain(port),
        None,
        "0.1",
        &hid::StalePlan::new(Duration::from_millis(100)),
        &mut irq,
        async |_: &str, _: &str| Ok(()),
        |l| lines.push(l),
    )
    .await
    .unwrap_err();
    let e = format!("{e:?}");
    assert!(
        e.contains("KEY MAY BE HELD") && e.contains("hid-release"),
        "{e}"
    );
    assert!(e.contains("drain"), "{e}");
    assert!(lines.is_empty(), "{lines:?}");
    let seen = all_ended(&ledger, 3, Duration::from_secs(20)).await;
    assert_eq!(seen.len(), 3, "a fresh websocket was opened: {seen:?}");
    assert_eq!(frames(&seen[0]), whole_burst(), "the burst was cut");
    assert_eq!(seen[0].ended.as_ref().unwrap().1, Ended::Fin);
    for rel in &seen[1..] {
        assert_eq!(frames(rel), session_start());
    }
}

/// m4 (PD4 fix round 1): the report line is out before the snapshot, so
/// a snapshot that fails never hides it; the section still releases twice
/// and the snapshot's error is the result (both releases confirmed).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hid_stale_prints_its_report_before_a_snapshot_that_fails() {
    use kvm_probe::l4::hid::{self, Interrupts};
    let (port, ledger) = ledger_stub(LedgerOpts::default()).await;
    let mut irq = Interrupts::new().unwrap();
    let mut lines = Vec::new();
    let e = hid::hid_stale(
        &plain(port),
        None,
        "0.1",
        &hid::StalePlan::new(Duration::from_millis(100)),
        &mut irq,
        async |_: &str, _: &str| {
            Err(kvm_probe::kvm::KvmError::Io(
                "the snapshot failed".to_owned(),
            ))
        },
        |l| lines.push(l),
    )
    .await
    .unwrap_err();
    assert!(format!("{e:?}").contains("the snapshot failed"), "{e:?}");
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("pushed: 128"), "{lines:?}");
    let seen = all_ended(&ledger, 4, T).await;
    assert_eq!(frames(&seen[2]), session_start());
    assert_eq!(frames(&seen[3]), session_start());
}

/// m2 (PD4 fix round 1): a TLS stub that writes `prefix` after reading
/// the request head, then holds the connection open for 30 s.
async fn hanging_http_stub(prefix: Vec<u8>) -> (u16, String) {
    use tokio::io::AsyncReadExt as _;
    let (acceptor, pin_hex) = support::tls_acceptor_and_pin();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, prefix) = (acceptor.clone(), prefix.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut head = vec![0u8; 4096];
                let _ = tls.read(&mut head).await;
                let _ = tls.write_all(&prefix).await;
                let _ = tls.flush().await;
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
        }
    });
    (port, pin_hex)
}

/// m2: `web-get` stops reading at its 512-byte snippet — a page that
/// promises 100 000 bytes, sends 600 and then stalls is answered at once,
/// not at the timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn web_get_stops_reading_at_its_snippet_bound() {
    use kvm_probe::l4::web;
    let mut resp =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 100000\r\n\r\n".to_vec();
    resp.extend(std::iter::repeat_n(b'x', 600));
    let (port, pin) = hanging_http_stub(resp).await;
    let t = KvmTarget {
        login_port: port,
        ..target(1)
    };
    let started = Instant::now();
    let p = tokio::time::timeout(Duration::from_secs(3), web::get(&t, Some(&pin), "/"))
        .await
        .expect("web-get read past its bound")
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(p.snippet, "x".repeat(512));
}

/// m2: a page that never answers ends at the GET's bound: `web::get` is
/// `get_within(GET_TIMEOUT)`, 10 s; here a 300 ms bound ends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn web_get_times_out_on_a_page_that_never_answers() {
    use kvm_probe::l4::web;
    assert_eq!(web::GET_TIMEOUT, Duration::from_secs(10));
    let (port, pin) = hanging_http_stub(Vec::new()).await;
    let t = KvmTarget {
        login_port: port,
        ..target(1)
    };
    let started = Instant::now();
    let e = tokio::time::timeout(
        Duration::from_secs(3),
        web::get_within(&t, Some(&pin), "/", Duration::from_millis(300)),
    )
    .await
    .expect("web-get never timed out")
    .unwrap_err();
    assert!(format!("{e:?}").contains("timed out"), "{e:?}");
    assert!(started.elapsed() >= Duration::from_millis(300));
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
