//! The control websocket's task (§7.3): opens the websocket with the
//! session's token, sends the session-start sequence (§3.3), then writes
//! HID reports — a pending release-all before anything else — each write
//! bounded by `hid_write_timeout` (a blocked write reconnects, §6.9).
//! Inbound data is read and discarded (§3.2); every reconnect is a
//! release-all trigger (§7.4). Auth failures go to the session, which owns
//! the token; this task never logs in (and nothing here can log out).
//! At most one websocket is open or opening at a time: a control message
//! during an open is answered without abandoning the handshake (P20).
//!
//! The backoff resets in `drive` right after the session-start writes
//! succeed: that is §4.4's reset point for the websocket ("once a reopened
//! websocket has sent the session-start sequence"). So a KVM that accepts
//! the websocket and drops it at once is retried at `kvm.backoff.initial`,
//! by the spec's rule, while one whose session-start writes fail keeps
//! backing off.
//!
//! A websocket ends with a FIN only after a close the KVM answered — it read
//! everything up to our close frame. Every other end (a failed or blocked
//! write, a lost read side, a close it never answered, the task aborted)
//! resets the connection (`SO_LINGER` 0), so a backlog of HID reports it had
//! not read is discarded with the connection rather than delivered after
//! the next websocket's session-start sequence (§7.4; PC9 fix round 1, I2).
//! What already sits in the KVM's own receive buffer it may still read: the
//! re-assert after a reconnect settles is Plan D's (§7.4, §9.3).
use crate::hid::{HidControl, ReleaseTrigger};
use crate::kvm::endpoint::{KvmEndpoint, SocketHandle};
use crate::kvm::error::FailClass;
use crate::kvm::upstream::Backoff;
use crate::kvm::ws::open_ws;
use crate::metrics::Metrics;
use futures_util::{Sink, SinkExt as _, Stream, StreamExt as _};
use kvm_proto::Token;
use kvm_proto::hid::HidFrame;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

/// A close may spend this long writing the release and the close frame.
const CLOSE_BUDGET: Duration = Duration::from_millis(400);

pub enum WsCtl {
    /// Write a pending release-all now, then ack.
    Flush { done: oneshot::Sender<()> },
    /// Write a pending release-all, close the websocket, end the task.
    Close { done: oneshot::Sender<()> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsEvent {
    /// The websocket upgraded with the token with this sequence number:
    /// the KVM accepted that token (§6.9, rev 6.2; `AuthGate::proven`).
    Up {
        seq: u64,
    },
    Down,
    /// The upgrade was refused for the token with this sequence number.
    AuthRefused {
        seq: u64,
    },
    CertMismatch,
}

/// The session's token and its sequence number (`AuthGate::seq`).
pub type TokenWatch = watch::Receiver<Option<(u64, Token)>>;

pub struct WsTask {
    pub ep: Arc<KvmEndpoint>,
    pub token: TokenWatch,
    pub ctl: mpsc::UnboundedReceiver<WsCtl>,
    pub events: mpsc::UnboundedSender<WsEvent>,
    pub hid: Arc<HidControl>,
    pub backoff: Backoff,
    pub connect_timeout: Duration,
    pub write_timeout: Duration,
    pub metrics: Arc<Metrics>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Exit {
    /// `WsCtl::Close`, answered by the KVM within `CLOSE_BUDGET`: end the
    /// task; the connection ends with a FIN.
    Closed,
    /// Told to close (or the session went away), but the KVM never answered
    /// the close: end the task; the connection is reset (I2).
    Abandoned,
    /// The websocket failed: reconnect.
    Failed,
}

/// Resets the websocket's connection when dropped unless the KVM answered
/// our close (I2). It lives in `run` beside the open websocket, so an abort
/// of the task — a Stop whose `Close` a blocked write never read — drops it
/// too.
struct ResetUnlessAnswered {
    sock: SocketHandle,
    answered: bool,
}

impl Drop for ResetUnlessAnswered {
    fn drop(&mut self) {
        if !self.answered {
            self.sock.reset_on_close();
        }
    }
}

impl WsTask {
    pub async fn run(mut self) {
        loop {
            let Some((seq, token)) = self.wait_token(None).await else {
                return;
            };
            // P20: one pinned open, polled across control messages — a
            // `Flush` (every shutdown sends one, §5.2) must not throw the
            // handshake away and start a second one. The block ends the
            // future's borrow of `self.ep` before `drive` takes `&mut self`.
            let opened = {
                let open = open_ws(&self.ep, &token, self.connect_timeout);
                tokio::pin!(open);
                loop {
                    tokio::select! {
                        r = &mut open => break r,
                        ctl = self.ctl.recv() => match ctl {
                            // Nothing is open, so nothing to flush: ack and
                            // keep opening.
                            Some(WsCtl::Flush { done }) => {
                                let _ = done.send(());
                            }
                            // Abandoning the open is the close: dropping it
                            // closes the TCP connection.
                            Some(WsCtl::Close { done }) => {
                                let _ = done.send(());
                                return;
                            }
                            None => return,
                        },
                    }
                }
            };
            match opened {
                Ok((ws, sock)) => {
                    // Dropped with this arm — or with the task, if it is
                    // aborted mid-write — it resets the connection unless
                    // the KVM answered our close (I2).
                    let mut reset = ResetUnlessAnswered {
                        sock,
                        answered: false,
                    };
                    let _ = self.events.send(WsEvent::Up { seq });
                    let (sink, stream) = ws.split();
                    let exit = self.drive(sink, stream).await;
                    reset.answered = exit == Exit::Closed;
                    drop(reset);
                    if exit != Exit::Failed {
                        return;
                    }
                    // P21: `drive` counted the loss under its one reason
                    // (`websocket` for the read side, `websocket_write`).
                    self.hid.release_all(ReleaseTrigger::WebsocketReconnect);
                    let _ = self.events.send(WsEvent::Down);
                    let d = self.backoff.next_delay();
                    if !self.sleep(d).await {
                        return;
                    }
                }
                Err(e) => match e.class() {
                    FailClass::Auth => {
                        let _ = self.events.send(WsEvent::AuthRefused { seq });
                        if self.wait_token(Some(seq)).await.is_none() {
                            return;
                        }
                    }
                    // P1: bind the message first — `idle_ctl(&mut self, ..)`
                    // cannot take `self.ctl.recv()` as its argument (E0499).
                    FailClass::Cert => {
                        let _ = self.events.send(WsEvent::CertMismatch);
                        loop {
                            let ctl = self.ctl.recv().await;
                            if self.idle_ctl(ctl) {
                                return;
                            }
                        }
                    }
                    FailClass::Transient => {
                        self.metrics.upstream_reconnects.inc("websocket_open");
                        let d = self.backoff.next_delay();
                        if !self.sleep(d).await {
                            return;
                        }
                    }
                },
            }
        }
    }

    /// The session's token, newer than `after`; `None` once told to close.
    async fn wait_token(&mut self, after: Option<u64>) -> Option<(u64, Token)> {
        loop {
            let current = self.token.borrow().clone();
            if let Some((seq, token)) = current
                && after.is_none_or(|a| seq > a)
            {
                return Some((seq, token));
            }
            tokio::select! {
                changed = self.token.changed() => if changed.is_err() {
                    return None;
                },
                ctl = self.ctl.recv() => if self.idle_ctl(ctl) {
                    return None;
                },
            }
        }
    }

    /// A control message while no websocket is open: true to end the task.
    fn idle_ctl(&mut self, ctl: Option<WsCtl>) -> bool {
        match ctl {
            Some(WsCtl::Flush { done }) => {
                let _ = done.send(());
                false
            }
            Some(WsCtl::Close { done }) => {
                let _ = done.send(());
                true
            }
            None => true,
        }
    }

    /// Back off for `d`, still answering control messages; false to end.
    async fn sleep(&mut self, d: Duration) -> bool {
        let until = tokio::time::Instant::now() + d;
        loop {
            tokio::select! {
                () = tokio::time::sleep_until(until) => return true,
                ctl = self.ctl.recv() => if self.idle_ctl(ctl) {
                    return false;
                },
            }
        }
    }

    /// Serve one open websocket until it fails or is closed.
    pub async fn drive<S, St>(&mut self, mut sink: S, mut stream: St) -> Exit
    where
        S: Sink<Message, Error = WsError> + Unpin,
        St: Stream<Item = Result<Message, WsError>> + Unpin,
    {
        self.hid.discard_queued();
        // The session-start sequence is itself a release (§3.3).
        let _ = self.hid.take_release();
        for f in self.hid.session_start_frames() {
            if !self.write(&mut sink, f).await {
                return Exit::Failed;
            }
        }
        self.backoff.reset();
        loop {
            if self.hid.take_release() {
                for f in self.hid.release_frames() {
                    if !self.write(&mut sink, f).await {
                        return Exit::Failed;
                    }
                }
                continue;
            }
            if let Some(f) = self.hid.next_frame() {
                if !self.write(&mut sink, f).await {
                    return Exit::Failed;
                }
                continue;
            }
            // P23: control first — it is rare and must not wait behind HID
            // traffic — then HID, then the inbound side.
            tokio::select! {
                biased;
                ctl = self.ctl.recv() => match ctl {
                    Some(WsCtl::Flush { done }) => {
                        let mut ok = true;
                        if self.hid.take_release() {
                            for f in self.hid.release_frames() {
                                ok = ok && self.write(&mut sink, f).await;
                            }
                        }
                        let _ = done.send(());
                        if !ok {
                            return Exit::Failed;
                        }
                    }
                    Some(WsCtl::Close { done }) => {
                        let mut answered = false;
                        let _ = tokio::time::timeout(CLOSE_BUDGET, async {
                            let mut written = true;
                            if self.hid.take_release() {
                                for f in self.hid.release_frames() {
                                    // PC7 m1: the task ends either way — a
                                    // failure here is not a reconnect.
                                    if !self.send_frame(&mut sink, f).await {
                                        written = false;
                                        break;
                                    }
                                }
                            }
                            let closed = sink.close().await.is_ok();
                            let sent = written && closed;
                            // Wait for the KVM's side of the close, so the
                            // next session's websocket never overlaps this
                            // one. Its close frame, or its end of the stream,
                            // means it read everything up to ours (I2).
                            loop {
                                match stream.next().await {
                                    Some(Ok(Message::Close(_))) => answered = sent,
                                    Some(Ok(_)) => {}
                                    Some(Err(_)) | None => {
                                        answered = sent;
                                        break;
                                    }
                                }
                            }
                        })
                        .await;
                        let _ = done.send(());
                        // Answered: a FIN delivers nothing late. Otherwise
                        // the connection is reset (I2).
                        return if answered { Exit::Closed } else { Exit::Abandoned };
                    }
                    None => return Exit::Abandoned,
                },
                () = self.hid.wait() => {}
                msg = stream.next() => match msg {
                    // P21: the read-side loss is counted here, once.
                    Some(Ok(Message::Close(_)) | Err(_)) | None => {
                        self.metrics.upstream_reconnects.inc("websocket");
                        return Exit::Failed;
                    }
                    Some(Ok(_)) => {}
                },
            }
        }
    }

    /// One write on a websocket that stays in service: a failure ends it
    /// with `Exit::Failed` and a reconnect, counted here once (P21).
    async fn write<S: Sink<Message, Error = WsError> + Unpin>(
        &self,
        sink: &mut S,
        f: HidFrame,
    ) -> bool {
        let ok = self.send_frame(sink, f).await;
        if !ok {
            self.metrics.upstream_reconnects.inc("websocket_write");
        }
        ok
    }

    /// One write bounded by `hid_write_timeout`; uncounted (PC7 m1).
    async fn send_frame<S: Sink<Message, Error = WsError> + Unpin>(
        &self,
        sink: &mut S,
        f: HidFrame,
    ) -> bool {
        match tokio::time::timeout(self.write_timeout, sink.send(Message::Binary(f.to_vec()))).await
        {
            Ok(Ok(())) => {
                self.hid.note_sent(&f);
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]
    use super::*;
    use crate::config::{BackoffConfig, Scheme, Secret};
    use crate::kvm::login::login;
    use crate::kvm::upstream::Jitter;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};
    use std::time::Instant;

    #[derive(Default)]
    struct Gate {
        open: bool,
        /// Every write fails at once (a dead socket).
        fail: bool,
        sent: Vec<Vec<u8>>,
        waker: Option<Waker>,
    }

    /// A sink a test can block and unblock; records every binary message.
    #[derive(Clone, Default)]
    struct GateSink(Arc<Mutex<Gate>>);

    impl GateSink {
        fn new(open: bool) -> GateSink {
            let s = GateSink::default();
            s.0.lock().unwrap().open = open;
            s
        }
        fn set(&self, open: bool) {
            let mut g = self.0.lock().unwrap();
            g.open = open;
            if let (true, Some(w)) = (open, g.waker.take()) {
                w.wake();
            }
        }
        fn sent(&self) -> Vec<Vec<u8>> {
            self.0.lock().unwrap().sent.clone()
        }
        fn fail(&self) {
            self.0.lock().unwrap().fail = true;
        }
    }

    impl Sink<Message> for GateSink {
        type Error = WsError;
        fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), WsError>> {
            let mut g = self.0.lock().unwrap();
            if g.fail {
                Poll::Ready(Err(WsError::ConnectionClosed))
            } else if g.open {
                Poll::Ready(Ok(()))
            } else {
                g.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
        fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), WsError> {
            if let Message::Binary(b) = item {
                self.0.lock().unwrap().sent.push(b);
            }
            Ok(())
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), WsError>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), WsError>> {
            Poll::Ready(Ok(()))
        }
    }

    const SET_MODE: [u8; 4] = [0x88, 0x88, 0x01, 0x30];
    const KBD_ZERO: [u8; 12] = [0xAA, 0xAA, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    fn kbd(k: u8) -> HidFrame {
        HidFrame::Keyboard {
            modifiers: 0,
            keys: [k, 0, 0, 0, 0],
        }
    }

    fn task(
        hid: Arc<HidControl>,
        write_timeout: Duration,
    ) -> (WsTask, mpsc::UnboundedSender<WsCtl>) {
        let (ctl_tx, ctl) = mpsc::unbounded_channel();
        let (events, _events_rx) = mpsc::unbounded_channel();
        let (_tok_tx, token) = watch::channel(None);
        let backoff = BackoffConfig {
            initial: Duration::from_millis(50),
            factor: 2,
            max: Duration::from_millis(400),
            jitter_percent: 0,
        };
        let t = WsTask {
            ep: Arc::new(KvmEndpoint::new(
                Scheme::Http,
                "127.0.0.1",
                (1, 1, 1),
                &"0".repeat(64),
            )),
            token,
            ctl,
            events,
            metrics: hid.metrics.clone(),
            hid,
            backoff: Backoff::new(backoff, Jitter::new(1)),
            connect_timeout: Duration::from_secs(1),
            write_timeout,
        };
        (t, ctl_tx)
    }

    async fn wait_sent(sink: &GateSink, n: usize) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while sink.sent().len() < n {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }

    async fn close(ctl: &mpsc::UnboundedSender<WsCtl>) {
        let (done, rx) = oneshot::channel();
        ctl.send(WsCtl::Close { done }).unwrap();
        tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .unwrap()
            .unwrap();
    }

    /// PC7 m4: a spawned `drive`, bounded from outside — a regression that
    /// acks `Close` and keeps looping fails the test instead of hanging it.
    async fn ended(drive: tokio::task::JoinHandle<Exit>) -> Exit {
        tokio::time::timeout(Duration::from_secs(5), drive)
            .await
            .expect("drive did not end after Close")
            .unwrap()
    }

    /// A loopback websocket endpoint that accepts TCP and answers the first
    /// upgrade only when the test says so; later connections are held open,
    /// never answered. Counts every accept; forwards each binary message of
    /// the first websocket.
    struct UpgradeStub {
        port: u16,
        accepts: Arc<AtomicUsize>,
        answer: Option<oneshot::Sender<()>>,
        got: mpsc::UnboundedReceiver<Vec<u8>>,
    }

    impl UpgradeStub {
        async fn start() -> UpgradeStub {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let accepts = Arc::new(AtomicUsize::new(0));
            let (answer, answer_rx) = oneshot::channel::<()>();
            let (got_tx, got) = mpsc::unbounded_channel::<Vec<u8>>();
            let a2 = accepts.clone();
            tokio::spawn(async move {
                let mut answer_rx = Some(answer_rx);
                let mut held = Vec::new();
                while let Ok((s, _)) = listener.accept().await {
                    a2.fetch_add(1, Ordering::SeqCst);
                    let Some(rx) = answer_rx.take() else {
                        held.push(s); // never answered
                        continue;
                    };
                    let got = got_tx.clone();
                    tokio::spawn(async move {
                        // Answer the upgrade only once the test says so.
                        let _ = rx.await;
                        let Ok(mut ws) = tokio_tungstenite::accept_async(s).await else {
                            return;
                        };
                        while let Some(Ok(m)) = ws.next().await {
                            if let Message::Binary(b) = m {
                                let _ = got.send(b);
                            }
                        }
                    });
                }
            });
            UpgradeStub {
                port,
                accepts,
                answer: Some(answer),
                got,
            }
        }

        fn accepts(&self) -> usize {
            self.accepts.load(Ordering::SeqCst)
        }

        async fn wait_accepts(&self, n: usize) {
            tokio::time::timeout(Duration::from_secs(2), async {
                while self.accepts() < n {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
        }

        fn answer(&mut self) {
            self.answer.take().unwrap().send(()).unwrap();
        }

        /// A task pointed at the stub, with a token and an open long
        /// enough (3 s) to outlast the test's control messages.
        fn task(&self) -> (WsTask, mpsc::UnboundedSender<WsCtl>) {
            let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
            let (mut t, ctl) = task(hid, Duration::from_secs(1));
            t.ep = Arc::new(KvmEndpoint::new(
                Scheme::Http,
                "127.0.0.1",
                (self.port, self.port, self.port),
                &"0".repeat(64),
            ));
            t.connect_timeout = Duration::from_secs(3);
            let token = kvm_proto::parse_login_token(br#"{"result":0,"token":"0.1"}"#).unwrap();
            // The sender is dropped: the current token stays readable.
            t.token = watch::channel(Some((1, token))).1;
            (t, ctl)
        }
    }

    /// §3.3: on open the session-start sequence goes first, with no pointer
    /// report before one was ever sent; reports made while down are gone.
    #[tokio::test]
    async fn the_session_start_sequence_comes_first() {
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        hid.push(kbd(9), false);
        let (mut t, ctl) = task(hid.clone(), Duration::from_secs(1));
        let sink = GateSink::new(true);
        let s2 = sink.clone();
        let drive = tokio::spawn(async move { t.drive(s2, futures_util::stream::pending()).await });
        wait_sent(&sink, 2).await;
        hid.push(kbd(5), false);
        wait_sent(&sink, 3).await;
        close(&ctl).await;
        // The stub never answers the close: reset, not FIN (I2).
        assert_eq!(ended(drive).await, Exit::Abandoned);
        assert_eq!(
            sink.sent(),
            [SET_MODE.to_vec(), KBD_ZERO.to_vec(), kbd(5).to_vec()]
        );
    }

    /// §11.3 Input: with reports queued behind a blocked write, a release
    /// trigger produces only the zero reports and then current state — no
    /// queued report is sent after it.
    #[tokio::test]
    async fn a_release_behind_a_blocked_write_sends_only_zeros_then_new_state() {
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        let (mut t, ctl) = task(hid.clone(), Duration::from_secs(5));
        let sink = GateSink::new(true);
        let s2 = sink.clone();
        let drive = tokio::spawn(async move { t.drive(s2, futures_util::stream::pending()).await });
        wait_sent(&sink, 2).await;
        sink.set(false);
        hid.push(kbd(1), false); // taken by the writer, blocked in poll_ready
        tokio::time::sleep(Duration::from_millis(50)).await;
        hid.push(kbd(2), false);
        hid.push(kbd(3), false);
        hid.release_all(ReleaseTrigger::Closing);
        hid.push(kbd(4), false);
        sink.set(true);
        wait_sent(&sink, 5).await;
        close(&ctl).await;
        // The stub never answers the close: reset, not FIN (I2).
        assert_eq!(ended(drive).await, Exit::Abandoned);
        let sent = sink.sent();
        assert_eq!(
            sent[2..],
            [kbd(1).to_vec(), KBD_ZERO.to_vec(), kbd(4).to_vec()]
        );
    }

    /// §6.9: a write that takes longer than `hid_write_timeout` ends the
    /// websocket (the task reconnects).
    #[tokio::test]
    async fn a_blocked_write_fails_within_the_write_timeout() {
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        let (mut t, _ctl) = task(hid.clone(), Duration::from_millis(100));
        let t0 = Instant::now();
        // Bounded from outside: a writer that lost its `hid_write_timeout`
        // must fail this test, not hang it.
        let exit = tokio::time::timeout(
            Duration::from_secs(5),
            t.drive(GateSink::new(false), futures_util::stream::pending()),
        )
        .await
        .expect("drive never returned: the write is not bounded by hid_write_timeout");
        assert_eq!(exit, Exit::Failed);
        assert!(
            t0.elapsed() >= Duration::from_millis(50) && t0.elapsed() < Duration::from_millis(500)
        );
        assert_eq!(hid.metrics.upstream_reconnects.get("websocket_write"), 1);
        // P21: one failure, one count.
        assert_eq!(hid.metrics.upstream_reconnects.total(), 1);
    }

    /// §3.2: inbound data is read and discarded; a stream error ends it.
    #[tokio::test]
    async fn inbound_data_is_discarded_and_an_error_ends_the_websocket() {
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        let (mut t, _ctl) = task(hid, Duration::from_secs(1));
        let sink = GateSink::new(true);
        let inbound = futures_util::stream::iter(vec![
            Ok(Message::Binary(vec![1, 2, 3])),
            Err(WsError::ConnectionClosed),
        ]);
        // P22: bounded from outside.
        let exit = tokio::time::timeout(Duration::from_secs(5), t.drive(sink.clone(), inbound))
            .await
            .expect("drive ignored the inbound error");
        assert_eq!(exit, Exit::Failed);
        assert_eq!(
            sink.sent().len(),
            2,
            "only the session-start sequence went out"
        );
        // P21: the read-side loss, counted once.
        assert_eq!(t.metrics.upstream_reconnects.get("websocket"), 1);
        assert_eq!(t.metrics.upstream_reconnects.total(), 1);
    }

    /// §7.3: `on_disconnected` releases and then closes over the same path —
    /// the zero reports are written before the close.
    #[tokio::test]
    async fn close_writes_a_pending_release_first() {
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        let (mut t, ctl) = task(hid.clone(), Duration::from_secs(1));
        let sink = GateSink::new(true);
        let s2 = sink.clone();
        let drive = tokio::spawn(async move { t.drive(s2, futures_util::stream::pending()).await });
        wait_sent(&sink, 2).await;
        hid.push(kbd(7), false);
        wait_sent(&sink, 3).await;
        hid.release_all(ReleaseTrigger::SessionEnd);
        close(&ctl).await;
        // The stub never answers the close: reset, not FIN (I2).
        assert_eq!(ended(drive).await, Exit::Abandoned);
        assert_eq!(sink.sent().last().unwrap(), &KBD_ZERO.to_vec());
    }

    /// End to end against kvm-sim: a dropped websocket is reopened with the
    /// session-start sequence, counted as a release-all trigger.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dropped_websocket_reopens_with_the_session_start_sequence() {
        use kvm_sim::{KvmSim, SimConfig, SimEvent, Source};
        let sim = KvmSim::start(SimConfig::es3(
            Source::fixture("360p30_es3like_poc0.h264").unwrap(),
        ))
        .await
        .unwrap();
        let p = sim.ports();
        let ep = Arc::new(KvmEndpoint::new(
            Scheme::Https,
            sim.host(),
            (p.web, p.video, p.control),
            sim.spki_sha256(),
        ));
        let token = login(
            &ep,
            &Secret::new(sim.password()),
            Duration::from_secs(1),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        let (mut t, ctl) = task(hid.clone(), Duration::from_secs(1));
        let (tok_tx, tok_rx) = watch::channel(Some((1, token)));
        t.token = tok_rx;
        t.ep = ep;
        let run = tokio::spawn(t.run());
        let hid_events = |e: &[SimEvent]| {
            e.iter()
                .filter(|e| matches!(e, SimEvent::Hid { .. }))
                .count()
        };
        sim.wait_for(Duration::from_secs(3), |e| hid_events(e) >= 2)
            .await
            .unwrap();
        sim.close_websockets();
        let log = sim
            .wait_for(Duration::from_secs(3), |e| hid_events(e) >= 4)
            .await
            .unwrap();
        let bytes: Vec<&Vec<u8>> = log
            .iter()
            .filter_map(|e| {
                if let SimEvent::Hid { bytes, .. } = e {
                    Some(bytes)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(
            bytes,
            [
                &SET_MODE.to_vec(),
                &KBD_ZERO.to_vec(),
                &SET_MODE.to_vec(),
                &KBD_ZERO.to_vec()
            ]
        );
        assert_eq!(hid.metrics.release_all.get("websocket_reconnect"), 1);
        // P21: one loss, counted once, under one reason.
        assert_eq!(hid.metrics.upstream_reconnects.get("websocket"), 1);
        assert_eq!(hid.metrics.upstream_reconnects.total(), 1);
        close(&ctl).await;
        // P22: bounded from outside.
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .expect("run did not end after Close")
            .unwrap();
        drop(tok_tx);
        sim.wait_for(Duration::from_secs(2), |_| sim.stats().ws_open == 0)
            .await
            .unwrap();
        assert_eq!(sim.stats().logouts, 0);
    }

    /// Census (§3.3, §7.3, §7.4): a key held when the websocket dies is
    /// released on the next open before any new input — the reopen's first
    /// frames are the session-start sequence — and a report made while the
    /// websocket is down is never sent on the new one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_key_held_when_the_websocket_dies_is_released_before_any_new_input() {
        use kvm_sim::{KvmSim, SimConfig, SimEvent, Source};
        let sim = KvmSim::start(SimConfig::es3(
            Source::fixture("360p30_es3like_poc0.h264").unwrap(),
        ))
        .await
        .unwrap();
        let p = sim.ports();
        let ep = Arc::new(KvmEndpoint::new(
            Scheme::Https,
            sim.host(),
            (p.web, p.video, p.control),
            sim.spki_sha256(),
        ));
        let token = login(
            &ep,
            &Secret::new(sim.password()),
            Duration::from_secs(1),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        let (mut t, ctl) = task(hid.clone(), Duration::from_secs(1));
        let (tok_tx, tok_rx) = watch::channel(Some((1, token)));
        let (ev_tx, mut ev) = mpsc::unbounded_channel();
        t.token = tok_rx;
        t.ep = ep;
        t.events = ev_tx;
        // A long first backoff, so the report made while down lands well
        // before the reopen.
        let slow = BackoffConfig {
            initial: Duration::from_millis(500),
            factor: 2,
            max: Duration::from_secs(1),
            jitter_percent: 0,
        };
        t.backoff = Backoff::new(slow, Jitter::new(1));
        let run = tokio::spawn(t.run());
        let frames = |e: &[SimEvent]| -> Vec<(u64, Vec<u8>)> {
            e.iter()
                .filter_map(|e| {
                    if let SimEvent::Hid { conn, bytes } = e {
                        Some((*conn, bytes.clone()))
                    } else {
                        None
                    }
                })
                .collect()
        };
        let next = async |ev: &mut mpsc::UnboundedReceiver<WsEvent>| {
            tokio::time::timeout(Duration::from_secs(3), ev.recv())
                .await
                .unwrap()
                .unwrap()
        };
        assert_eq!(next(&mut ev).await, WsEvent::Up { seq: 1 });
        sim.wait_for(Duration::from_secs(3), |e| frames(e).len() >= 2)
            .await
            .unwrap();
        hid.push(kbd(4), false); // key 4 goes down, and stays down
        sim.wait_for(Duration::from_secs(3), |e| frames(e).len() >= 3)
            .await
            .unwrap();
        sim.close_websockets();
        // The writer saw the loss, released, and is backing off.
        assert_eq!(next(&mut ev).await, WsEvent::Down);
        hid.push(kbd(5), false); // made while the websocket is down
        assert_eq!(next(&mut ev).await, WsEvent::Up { seq: 1 });
        sim.wait_for(Duration::from_secs(3), |e| frames(e).len() >= 5)
            .await
            .unwrap();
        hid.push(kbd(6), false); // the first new input after the reopen
        let log = sim
            .wait_for(Duration::from_secs(3), |e| frames(e).len() >= 6)
            .await
            .unwrap();
        let frames = frames(&log);
        let mut conns: Vec<u64> = frames.iter().map(|(c, _)| *c).collect();
        conns.dedup();
        assert_eq!(conns.len(), 2, "{conns:?}");
        let on = |c: u64| {
            frames
                .iter()
                .filter(|(k, _)| *k == c)
                .map(|(_, b)| b.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            on(conns[0]),
            [SET_MODE.to_vec(), KBD_ZERO.to_vec(), kbd(4).to_vec()]
        );
        assert_eq!(
            on(conns[1]),
            [SET_MODE.to_vec(), KBD_ZERO.to_vec(), kbd(6).to_vec()]
        );
        close(&ctl).await;
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .expect("run did not end after Close")
            .unwrap();
        drop(tok_tx);
        sim.wait_for(Duration::from_secs(2), |_| sim.stats().ws_open == 0)
            .await
            .unwrap();
        assert_eq!(sim.stats().logouts, 0);
    }

    /// P20 / census (never two control websockets at once): a control
    /// message while the open is in flight is answered without throwing that
    /// handshake away — the one connection completes and carries the
    /// session-start sequence, and no second connection is made beside it.
    #[tokio::test]
    async fn a_flush_during_the_open_keeps_the_one_handshake() {
        let mut stub = UpgradeStub::start().await;
        let (t, ctl) = stub.task();
        let run = tokio::spawn(t.run());
        stub.wait_accepts(1).await;
        for _ in 0..3 {
            let (done, rx) = oneshot::channel();
            ctl.send(WsCtl::Flush { done }).unwrap();
            tokio::time::timeout(Duration::from_secs(1), rx)
                .await
                .expect("a flush during the open was not acked")
                .unwrap();
        }
        stub.answer();
        let mut first = Vec::new();
        for _ in 0..2 {
            let m = tokio::time::timeout(Duration::from_secs(2), stub.got.recv())
                .await
                .expect("the in-flight handshake was thrown away")
                .unwrap();
            first.push(m);
        }
        assert_eq!(first, [SET_MODE.to_vec(), KBD_ZERO.to_vec()]);
        assert_eq!(
            stub.accepts(),
            1,
            "a second connection was opened beside the first"
        );
        close(&ctl).await;
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .expect("run did not end after Close")
            .unwrap();
    }

    /// PC7 m3 (W8), P20: `Close` while the open is in flight abandons it —
    /// acked, the task ends, nothing is ever written, and no second
    /// connection is made.
    #[tokio::test]
    async fn a_close_during_the_open_abandons_it() {
        let mut stub = UpgradeStub::start().await;
        let (t, ctl) = stub.task();
        let run = tokio::spawn(t.run());
        stub.wait_accepts(1).await;
        close(&ctl).await;
        tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("run kept opening after Close")
            .unwrap();
        // Answer the abandoned upgrade now: it must carry nothing.
        stub.answer();
        let late = tokio::time::timeout(Duration::from_millis(300), stub.got.recv()).await;
        assert!(late.is_err(), "a frame was written after Close: {late:?}");
        assert_eq!(stub.accepts(), 1, "a second connection was made");
    }

    /// PC7 m3 (W11), §4.4: the websocket's backoff resets once a reopened
    /// websocket has sent the session-start sequence — and not before, so a
    /// websocket whose session-start writes fail keeps backing off.
    #[tokio::test]
    async fn the_backoff_resets_only_after_the_session_start_sequence_is_written() {
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        let (mut t, _ctl) = task(hid, Duration::from_millis(50));
        // Two failed opens' worth of backoff (0 % jitter: 50 ms, 100 ms).
        assert_eq!(t.backoff.next_delay(), Duration::from_millis(50));
        assert_eq!(t.backoff.next_delay(), Duration::from_millis(100));
        // The first session-start write never completes: no reset.
        let exit = tokio::time::timeout(
            Duration::from_secs(5),
            t.drive(GateSink::new(false), futures_util::stream::pending()),
        )
        .await
        .expect("drive never returned");
        assert_eq!(exit, Exit::Failed);
        assert_eq!(
            t.backoff.next_delay(),
            Duration::from_millis(200),
            "reset before the session-start sequence was written"
        );
        // The sequence is written, then the websocket fails: reset.
        let sink = GateSink::new(true);
        let inbound =
            futures_util::stream::iter(vec![Err::<Message, _>(WsError::ConnectionClosed)]);
        let exit = tokio::time::timeout(Duration::from_secs(5), t.drive(sink.clone(), inbound))
            .await
            .expect("drive never returned");
        assert_eq!(exit, Exit::Failed);
        assert_eq!(sink.sent().len(), 2);
        assert_eq!(
            t.backoff.next_delay(),
            Duration::from_millis(50),
            "§4.4: no reset after the session-start sequence"
        );
    }

    /// PC7 m1, §10.4: a release write that fails inside `Close` ends the
    /// task — no reconnect follows, so `upstream_reconnects` does not count
    /// it.
    #[tokio::test]
    async fn a_release_write_failing_while_closing_is_not_a_reconnect() {
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        let (mut t, ctl) = task(hid.clone(), Duration::from_secs(1));
        let sink = GateSink::new(true);
        let s2 = sink.clone();
        let drive = tokio::spawn(async move { t.drive(s2, futures_util::stream::pending()).await });
        wait_sent(&sink, 2).await;
        // One turn of this current-thread runtime: a release, a socket that
        // now fails every write, and `Close` — which the biased select takes
        // first, so the release is written (and fails) inside the Close path.
        hid.release_all(ReleaseTrigger::SessionEnd);
        sink.fail();
        close(&ctl).await;
        // A failed release write and an unanswered close: reset (I2).
        assert_eq!(ended(drive).await, Exit::Abandoned);
        assert_eq!(sink.sent().len(), 2, "the dead socket took a frame");
        assert_eq!(hid.metrics.upstream_reconnects.total(), 0);
    }

    /// How the bridge ended a connection, as its peer reads it.
    #[derive(Debug, PartialEq, Eq)]
    enum Ending {
        /// EOF after the bytes: a FIN, so everything sent was delivered.
        Fin,
        /// ECONNRESET: a reset — what the bridge had not sent is gone.
        Reset,
        Other(std::io::ErrorKind),
    }

    /// One loopback websocket peer (plain `ws`) with a 4 KiB receive
    /// buffer. `reading`: it reads every message and answers a close.
    /// Otherwise it reads nothing — the bridge's writes back up and block —
    /// until `drain` fires. Then it reads the raw connection to its end and
    /// reports how the bridge ended it. Later connections are held open.
    struct Peer {
        port: u16,
        drain: Option<oneshot::Sender<()>>,
        ending: oneshot::Receiver<Ending>,
    }

    impl Peer {
        async fn start(reading: bool) -> Peer {
            use tokio::io::AsyncReadExt as _;
            let sock = tokio::net::TcpSocket::new_v4().unwrap();
            sock.set_recv_buffer_size(4096).unwrap();
            sock.bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
                .unwrap();
            let listener = sock.listen(8).unwrap();
            let port = listener.local_addr().unwrap().port();
            let (drain, drain_rx) = oneshot::channel::<()>();
            let (end_tx, ending) = oneshot::channel();
            tokio::spawn(async move {
                let Ok((s, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut held = Vec::new();
                    while let Ok((s, _)) = listener.accept().await {
                        held.push(s);
                    }
                });
                let Ok(mut ws) = tokio_tungstenite::accept_async(s).await else {
                    return;
                };
                if reading {
                    while let Some(Ok(_)) = ws.next().await {}
                } else {
                    let _ = drain_rx.await;
                }
                let tcp = ws.get_mut();
                let mut buf = vec![0u8; 64 * 1024];
                let end = loop {
                    match tokio::time::timeout(Duration::from_secs(10), tcp.read(&mut buf)).await {
                        Ok(Ok(0)) => break Ending::Fin,
                        Ok(Ok(_)) => {}
                        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                            break Ending::Reset;
                        }
                        Ok(Err(e)) => break Ending::Other(e.kind()),
                        Err(_) => break Ending::Other(std::io::ErrorKind::TimedOut),
                    }
                };
                let _ = end_tx.send(end);
            });
            Peer {
                port,
                drain: Some(drain),
                ending,
            }
        }

        /// A task pointed at this peer.
        fn task(
            &self,
            hid: Arc<HidControl>,
            write_timeout: Duration,
        ) -> (WsTask, mpsc::UnboundedSender<WsCtl>) {
            let (mut t, ctl) = task(hid, write_timeout);
            t.ep = Arc::new(KvmEndpoint::new(
                Scheme::Http,
                "127.0.0.1",
                (self.port, self.port, self.port),
                &"0".repeat(64),
            ));
            let token = kvm_proto::parse_login_token(br#"{"result":0,"token":"0.1"}"#).unwrap();
            t.token = watch::channel(Some((1, token))).1;
            (t, ctl)
        }

        /// Let it read; how did the bridge end the connection?
        async fn ending(&mut self) -> Ending {
            if let Some(d) = self.drain.take() {
                let _ = d.send(());
            }
            tokio::time::timeout(Duration::from_secs(15), &mut self.ending)
                .await
                .expect("the connection never ended")
                .unwrap()
        }
    }

    /// Push key presses until `done` holds (bounded: 15 s).
    async fn flood_until(hid: &HidControl, done: impl Fn() -> bool) {
        let t0 = Instant::now();
        let mut k = 0u8;
        while !done() {
            assert!(
                t0.elapsed() < Duration::from_secs(15),
                "the writes never blocked"
            );
            for _ in 0..64 {
                k = k.wrapping_add(1);
                hid.push(kbd(4 + k % 20), false);
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// I2 (PC9 fix round 1): a close the KVM answered — it read everything
    /// up to our close frame, then answered — ends with a FIN.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_answered_close_ends_with_a_fin() {
        let mut p = Peer::start(true).await;
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        let (t, ctl) = p.task(hid.clone(), Duration::from_secs(1));
        let run = tokio::spawn(t.run());
        flood_until(&hid, || hid.metrics.hid_reports_sent.get() >= 2).await;
        close(&ctl).await;
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(p.ending().await, Ending::Fin);
    }

    /// I2: a close the KVM never answers within `CLOSE_BUDGET` — it is not
    /// reading, so our release and close frame may sit unread behind older
    /// reports — is reset, not ended with a FIN that would deliver them
    /// after the next websocket's session start.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unanswered_close_resets_the_websocket() {
        let mut p = Peer::start(false).await;
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        let (t, ctl) = p.task(hid.clone(), Duration::from_secs(1));
        let run = tokio::spawn(t.run());
        flood_until(&hid, || hid.metrics.hid_reports_sent.get() >= 2).await;
        hid.release_all(ReleaseTrigger::SessionEnd);
        close(&ctl).await;
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(p.ending().await, Ending::Reset);
    }

    /// I2: a websocket given up on a blocked write (§6.9) is reset, so the
    /// backlog the KVM has not read is discarded with it rather than
    /// delivered after the next websocket's session start (§7.4).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_write_timeout_resets_the_websocket() {
        let mut p = Peer::start(false).await;
        let hid = Arc::new(HidControl::new(256, Arc::new(Metrics::default())));
        let (t, ctl) = p.task(hid.clone(), Duration::from_millis(200));
        let run = tokio::spawn(t.run());
        flood_until(&hid, || {
            hid.metrics.upstream_reconnects.get("websocket_write") == 1
        })
        .await;
        assert_eq!(p.ending().await, Ending::Reset);
        close(&ctl).await;
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .unwrap()
            .unwrap();
    }

    /// I2: an aborted websocket task — a Stop whose `Close` a blocked write
    /// never read (§5.2) — resets its connection: the drop guard, not the
    /// close path, decides. Aborted here with the session-start sequence
    /// unread by the peer; the blocked-write case end to end is the
    /// session's `a_stop_with_a_blocked_write_resets_the_websocket`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_aborted_websocket_task_resets_its_connection() {
        let mut p = Peer::start(false).await;
        let hid = Arc::new(HidControl::new(256, Arc::new(Metrics::default())));
        let (t, _ctl) = p.task(hid.clone(), Duration::from_secs(30));
        let run = tokio::spawn(t.run());
        flood_until(&hid, || hid.metrics.hid_reports_sent.get() >= 2).await;
        run.abort();
        let _ = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .unwrap();
        assert_eq!(p.ending().await, Ending::Reset);
    }
}
