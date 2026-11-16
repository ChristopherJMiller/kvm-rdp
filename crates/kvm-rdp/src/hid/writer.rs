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
//! backing off. A loss while input is held reopens without the backoff
//! (I2, Plan D final review) — at most once until a reopen has written its
//! session start (R-I1, the re-review of the final fix wave), so a KVM
//! that resets every websocket right after its upgrade still meets it.
//!
//! A websocket ends with a FIN only after a close the KVM answered with its
//! own close frame — it read everything up to ours (a bare EOF proves
//! nothing: it may be a half-close with our backlog unread). That the KVM
//! read the release is proved only by its pong to the close's ping or a
//! close frame echoing ours (`CLOSE_REASON`): a close it began may cross
//! ours before it read the release (r-m2, the re-review of the final fix
//! wave), and still ends with a FIN. Every other end (a failed or blocked
//! write, a lost read side, a close it never answered, the task aborted)
//! resets the connection (`SO_LINGER` 0), so a backlog of HID reports it had
//! not read is discarded with the connection rather than delivered after
//! the next websocket's session-start sequence (§7.4; PC9 fix round 1, I2).
//! What already sits in the KVM's own receive buffer it may still read — a
//! stale press landing after the new session-start zeros. So every open
//! re-asserts the full current state once, `reassert_after` past its
//! session-start sequence (PC9 fix 2, DD8): the queue's resync state, the
//! last keyboard and pointer reports, written once the queue is drained and
//! no release is pending — so it overtakes neither, and repeats what the
//! KVM should hold anyway (idempotent). The deadline is checked at the
//! loop's top, so no busy arm of the `select!` can starve it (D21); and if
//! reports keep the queue from ever draining (motion under backpressure),
//! it goes `reassert_after` past its deadline after one queued frame (PD9
//! review m1) — only while no keyboard report waits, and without its pointer
//! part while pointer reports wait (re-review R-I1): the newest state written
//! ahead of a queued report would type a key early and again, or break a
//! drag. The queue's pointer reports each carry the current buttons, so
//! the stale press this guards against is the keyboard's.
//!
//! A timed re-assert can fire while the KVM is not reading — a reconnect or
//! a takeover during a stall opens at once, the KVM still stalled — and
//! then waits in the new websocket's buffer with the session start, read
//! in no set order against the abandoned websocket's leftovers. So every
//! open writes a ping after its session start (`OPEN_PING`), and its pong —
//! the KVM reading this websocket again — re-arms the re-assert
//! `reassert_after` past it, once (R-I2, the re-review of the final fix
//! wave; the release websocket's pong-gated rule, DD8). The timed one stays
//! for a KVM that never answers a ping.
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
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

/// A close may spend this long writing the release and the close frame.
const CLOSE_BUDGET: Duration = Duration::from_millis(400);

/// I2 (Plan D final review): the payload of the ping written after a
/// websocket's last report — at a close, and on the release websocket
/// (`hid::release`). The KVM's pong to it proves it read everything up to
/// it (RFC 6455 §5.5.2: an endpoint must answer a ping); a pong with any
/// other payload (a heartbeat) proves nothing.
pub(crate) const RELEASE_PING: &[u8] = b"kvm-rdp release";

/// R-I2 (re-review of the final fix wave): the payload of the ping every
/// open writes after its session start. Its pong shows the KVM reads this
/// websocket again; the open re-asserts `reassert_after` past it. Never
/// `RELEASE_PING`: a late pong to it would pass for the close's proof.
pub(crate) const OPEN_PING: &[u8] = b"kvm-rdp open";

/// r-m2 (re-review of the final fix wave): the reason our close frame
/// carries, so the KVM's answer to it — a close frame echoing ours (RFC
/// 6455 §5.5.1) — can be told from a close the KVM began. Only the answer
/// proves the KVM read everything up to our close.
const CLOSE_REASON: &str = "kvm-rdp release";

/// Our close frame: a normal closure with `CLOSE_REASON`.
fn our_close() -> CloseFrame<'static> {
    CloseFrame {
        code: CloseCode::Normal,
        reason: CLOSE_REASON.into(),
    }
}

/// `input.reassert_after`'s default (DD8): 1 s past an open's session
/// start, until L4 measures how long stale reports keep landing (Task 6.1
/// retunes it).
pub const REASSERT_AFTER: Duration = Duration::from_secs(1);

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
    /// How long past each open's session start the full state is
    /// re-asserted, once (PC9 fix 2; `input.reassert_after`).
    pub reassert_after: Duration,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Exit {
    /// `WsCtl::Close`, answered by the KVM's close frame within `CLOSE_BUDGET`: end the
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
        // R-I1 (re-review of the final fix wave): the last loss skipped the
        // backoff, and no reopen has written its session start since. A
        // reopen whose session-start writes fail writes nothing, so
        // `input_held` still sees the old websocket's held key at the next
        // loss: without this, a KVM that resets every websocket right after
        // its upgrade was reopened as fast as it answered.
        let mut skipped = false;
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
                    let (mut sink, stream) = ws.split();
                    let exit = if self.start(&mut sink).await {
                        // R-I1: a session start written, so the next loss
                        // with input held may skip the backoff again.
                        skipped = false;
                        self.serve(sink, stream).await
                    } else {
                        Exit::Failed
                    };
                    reset.answered = exit == Exit::Closed;
                    drop(reset);
                    if exit != Exit::Failed {
                        return;
                    }
                    // P21: `drive` counted the loss under its one reason
                    // (`websocket` for the read side, `websocket_write`).
                    // I2 (Plan D final review): read before the release
                    // zeroes the queue's state.
                    let held = self.hid.input_held();
                    self.hid.release_all(ReleaseTrigger::WebsocketReconnect);
                    let _ = self.events.send(WsEvent::Down);
                    // I2: while input is held, the reopen skips the backoff
                    // — a KVM that keeps a key held across the loss repeats
                    // it until the session start lands. R-I1: at most once
                    // until a reopen has written its session start; until
                    // then every loss, and every failed open, backs off as
                    // ever.
                    if held && !skipped {
                        skipped = true;
                    } else {
                        let d = self.backoff.next_delay();
                        if !self.sleep(d).await {
                            return;
                        }
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

    /// Serve one open websocket until it fails or is closed: its session
    /// start (`start`), then `serve`.
    pub async fn drive<S, St>(&mut self, mut sink: S, stream: St) -> Exit
    where
        S: Sink<Message, Error = WsError> + Unpin,
        St: Stream<Item = Result<Message, WsError>> + Unpin,
    {
        if !self.start(&mut sink).await {
            return Exit::Failed;
        }
        self.serve(sink, stream).await
    }

    /// An open websocket's session-start sequence (§3.3); true once it is
    /// written, and then the backoff resets (§4.4).
    async fn start<S: Sink<Message, Error = WsError> + Unpin>(&mut self, sink: &mut S) -> bool {
        // What was queued while down is dropped — as a release if it held
        // anything (I1, Plan D final review): a paste then aborts.
        self.hid.discard_queued();
        // The session-start sequence is itself a release (§3.3).
        let _ = self.hid.take_release();
        for f in self.hid.session_start_frames() {
            if !self.write(sink, f).await {
                return false;
            }
        }
        self.backoff.reset();
        true
    }

    /// An open websocket past its session start, until it fails or is
    /// closed.
    async fn serve<S, St>(&mut self, mut sink: S, mut stream: St) -> Exit
    where
        S: Sink<Message, Error = WsError> + Unpin,
        St: Stream<Item = Result<Message, WsError>> + Unpin,
    {
        // R-I2 (re-review of the final fix wave): a ping after the session
        // start. A KVM stalled while this websocket opened — a reconnect or
        // a takeover during the stall — reads the timed re-assert below
        // with the session start once it reads again, in no set order
        // against what the abandoned websocket left in its buffer; its pong
        // to this ping shows it reads again, and the re-assert goes once
        // more `reassert_after` past that (DD8's rule, pong-gated, as the
        // release websocket's is). Its own payload: a late pong to
        // `RELEASE_PING` would pass for the close's proof.
        if !self.ping(&mut sink).await {
            return Exit::Failed;
        }
        let mut pong_awaited = true;
        // PC9 fix 2: once, `reassert_after` past the session start (`None`
        // once done; bounded config, so the add never overflows) — the
        // re-assert for a KVM that never answers a ping.
        let mut reassert_at = tokio::time::Instant::now().checked_add(self.reassert_after);
        // m1 (PD9 review): the latest it may wait for the queue to empty.
        let mut reassert_by = reassert_at.and_then(|at| at.checked_add(self.reassert_after));
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
                // m1: reports arriving as fast as the KVM takes them (motion
                // under backpressure) keep the queue from ever emptying at
                // the loop top; past `reassert_by` the re-assert goes after
                // this one queued frame instead of waiting for a lull — but
                // only while no keyboard report waits, and with the pointer
                // part only while no pointer report does (R-I1): the newest
                // state written ahead of them would type a key early and
                // again, or break a drag. `reassert` decides that under the
                // queue lock (`HidControl::reassert_frames`, which checks
                // `keyboard_queued`): pushes come from the RDP thread while
                // this task runs on the KVM runtime.
                if reassert_by.is_some_and(|by| tokio::time::Instant::now() >= by) {
                    match self.reassert(&mut sink).await {
                        Some(false) => return Exit::Failed,
                        Some(true) => (reassert_at, reassert_by) = (None, None),
                        // A keyboard report waits: not yet.
                        None => {}
                    }
                }
                continue;
            }
            // D21: checked here, with the release and the queue served
            // first, whatever arm of the `select!` below is ready.
            if reassert_at.is_some_and(|at| tokio::time::Instant::now() >= at) {
                match self.reassert(&mut sink).await {
                    Some(false) => return Exit::Failed,
                    Some(true) => (reassert_at, reassert_by) = (None, None),
                    // A report pushed since the queue drained: serve it first.
                    None => {}
                }
                continue;
            }
            let reassert_wake = reassert_at;
            // P23: control first — it is rare and must not wait behind HID
            // traffic — then HID, then the inbound side; the re-assert's
            // deadline only wakes the loop.
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
                            // I2 (Plan D final review): a ping after the
                            // last report. Its pong proves the KVM read the
                            // release (`HidControl::confirm_read`), so the
                            // session needs no release websocket; a KVM
                            // that answers no close frame (kvm-sim, perhaps
                            // the ES3) still answers a ping.
                            let pinged = written
                                && sink.send(Message::Ping(RELEASE_PING.to_vec())).await.is_ok();
                            // r-m2: our close carries `CLOSE_REASON`, so the
                            // KVM's answer can be told from a close it began.
                            let closed = sink.send(Message::Close(Some(our_close()))).await.is_ok()
                                && sink.close().await.is_ok();
                            let sent = written && closed;
                            // Wait for the KVM's side of the close, so the
                            // next session's websocket never overlaps this
                            // one. Only its close frame ends it with a FIN
                            // (I2, n1): an EOF or an error may be a
                            // half-close with our backlog unread. Once it
                            // has closed we are done — it may wait for our
                            // FIN before closing (n2). What proves it read
                            // the release is its pong, or its answer to our
                            // close — a close frame echoing ours (r-m2): a
                            // close it began may have crossed ours before it
                            // read the release.
                            loop {
                                match stream.next().await {
                                    Some(Ok(Message::Close(frame))) => {
                                        answered = sent;
                                        if sent && frame == Some(our_close()) {
                                            let _ = self.hid.confirm_read();
                                        }
                                        break;
                                    }
                                    Some(Ok(Message::Pong(p)))
                                        if pinged && p == RELEASE_PING =>
                                    {
                                        let _ = self.hid.confirm_read();
                                    }
                                    Some(Ok(_)) => {}
                                    Some(Err(_)) | None => break,
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
                    // R-I2: the KVM reads this websocket again — the state
                    // once more, `reassert_after` past this pong. Once: a
                    // KVM repeating it cannot hold the re-assert off. It
                    // proves nothing about a release (`confirm_read`): it
                    // answers a ping written before the reports after it.
                    Some(Ok(Message::Pong(p))) if pong_awaited && p == OPEN_PING => {
                        pong_awaited = false;
                        reassert_at = tokio::time::Instant::now().checked_add(self.reassert_after);
                        reassert_by = reassert_at.and_then(|at| at.checked_add(self.reassert_after));
                    }
                    Some(Ok(_)) => {}
                },
                () = async move {
                    match reassert_wake {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending().await,
                    }
                } => {}
            }
        }
    }

    /// PC9 fix 2: write the current state (the queue's resync state) once,
    /// and count it — less what would overtake a queued report
    /// (`HidControl::reassert_frames`, R-I1). `None`: a keyboard report
    /// waits, so nothing is written yet; `Some(false)`: a write failed (a
    /// reconnect).
    async fn reassert<S: Sink<Message, Error = WsError> + Unpin>(
        &self,
        sink: &mut S,
    ) -> Option<bool> {
        let frames = self.hid.reassert_frames()?;
        for f in frames {
            if !self.write(sink, f).await {
                return Some(false);
            }
        }
        self.metrics.hid_reasserts.inc();
        Some(true)
    }

    /// R-I2: the open's ping (`OPEN_PING`), bounded by `hid_write_timeout`;
    /// a failure is a write's (`write`).
    async fn ping<S: Sink<Message, Error = WsError> + Unpin>(&self, sink: &mut S) -> bool {
        let ping = sink.send(Message::Ping(OPEN_PING.to_vec()));
        let ok = matches!(
            tokio::time::timeout(self.write_timeout, ping).await,
            Ok(Ok(()))
        );
        if !ok {
            self.metrics.upstream_reconnects.inc("websocket_write");
        }
        ok
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
        /// Every ping's payload (R-I2).
        pings: Vec<Vec<u8>>,
        /// Every close frame sent as a message (r-m2).
        closes: Vec<Option<CloseFrame<'static>>>,
        waker: Option<Waker>,
    }

    /// A sink a test can block and unblock; records every binary message,
    /// and every ping and close frame apart.
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
        fn pings(&self) -> Vec<Vec<u8>> {
            self.0.lock().unwrap().pings.clone()
        }
        fn closes(&self) -> Vec<Option<CloseFrame<'static>>> {
            self.0.lock().unwrap().closes.clone()
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
            match item {
                Message::Binary(b) => self.0.lock().unwrap().sent.push(b),
                Message::Ping(p) => self.0.lock().unwrap().pings.push(p),
                Message::Close(c) => self.0.lock().unwrap().closes.push(c),
                _ => {}
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
            reassert_after: REASSERT_AFTER,
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

    /// §5.2 W5 (PC9 fix round 1, m1): a release pending when `Flush`
    /// arrives — whichever came first, with no turn of the runtime between
    /// them, so the writer sees both at once — is written by the `Flush`
    /// arm before it acks: the biased select takes control first, whatever
    /// order the wake-ups came in. The socket is blocked, so an ack that
    /// did not wait for the write shows while the write is still pending.
    #[tokio::test]
    async fn flush_writes_the_pending_release_before_it_acks() {
        for flush_first in [false, true] {
            let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
            let (mut t, ctl) = task(hid.clone(), Duration::from_secs(5));
            let sink = GateSink::new(true);
            let s2 = sink.clone();
            let drive =
                tokio::spawn(async move { t.drive(s2, futures_util::stream::pending()).await });
            wait_sent(&sink, 2).await;
            sink.set(false);
            let (done, mut ack) = oneshot::channel();
            if flush_first {
                ctl.send(WsCtl::Flush { done }).unwrap();
                hid.release_all(ReleaseTrigger::Shutdown);
            } else {
                hid.release_all(ReleaseTrigger::Shutdown);
                ctl.send(WsCtl::Flush { done }).unwrap();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(
                matches!(
                    ack.try_recv(),
                    Err(tokio::sync::oneshot::error::TryRecvError::Empty)
                ),
                "Flush acked before the pending release was written (flush first: {flush_first})"
            );
            sink.set(true);
            tokio::time::timeout(Duration::from_secs(2), ack)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                sink.sent(),
                [SET_MODE.to_vec(), KBD_ZERO.to_vec(), KBD_ZERO.to_vec()]
            );
            close(&ctl).await;
            ended(drive).await;
        }
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

    /// §6.9's certificate row, rev 6.3 (PD11a review I1): a reopen that
    /// meets a certificate other than the pinned one — kvm-sim's, swapped
    /// mid-session — is reported once (`WsEvent::CertMismatch`), and the
    /// writer then idles: no reconnect however long nobody stops it, and a
    /// Close still ends it. The L2 case cannot show the idle, since there the
    /// session's Stop ends the writer within its first backoff; here nothing
    /// stops it for three times `backoff.max`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reopen_meeting_a_changed_certificate_idles_until_closed() {
        use kvm_sim::{KvmSim, SimConfig, SimEvent, Source};
        const WAIT: Duration = Duration::from_secs(3);
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
        // `task`'s backoff: 50 ms, doubling, at most 400 ms.
        let idle = Duration::from_millis(400) * 3;
        let (ev_tx, mut events) = mpsc::unbounded_channel();
        t.events = ev_tx;
        let (tok_tx, tok_rx) = watch::channel(Some((1, token)));
        t.token = tok_rx;
        t.ep = ep;
        let run = tokio::spawn(t.run());
        let mut next = async || {
            tokio::time::timeout(WAIT, events.recv())
                .await
                .expect("no writer event")
        };
        assert_eq!(next().await, Some(WsEvent::Up { seq: 1 }));
        let hid_events = |e: &[SimEvent]| {
            e.iter()
                .filter(|e| matches!(e, SimEvent::Hid { .. }))
                .count()
        };
        sim.wait_for(WAIT, |e| hid_events(e) >= 2).await.unwrap();
        let before = sim.stats().accepts_control;
        sim.rotate_certificate().unwrap();
        sim.close_websockets();
        assert_eq!(next().await, Some(WsEvent::Down));
        assert_eq!(next().await, Some(WsEvent::CertMismatch));
        // Nobody stops it: the ctl channel stays open, the token stays.
        tokio::time::sleep(idle).await;
        assert_eq!(
            sim.stats().accepts_control,
            before + 1,
            "the writer reconnected after the mismatch"
        );
        assert!(
            events.try_recv().is_err(),
            "a writer event after the mismatch"
        );
        assert_eq!(
            sim.stats().ws_open,
            0,
            "a websocket over the new certificate"
        );
        close(&ctl).await;
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .expect("run did not end after Close")
            .unwrap();
        drop(tok_tx);
        assert_eq!(sim.stats().logouts, 0);
    }

    /// I2 (Plan D final review): a close that the KVM reads proves the
    /// release landed — its pong to the ping written after the release
    /// (kvm-sim answers pings; it never answers a close frame) — so the KVM
    /// holds nothing of ours, and no release websocket is needed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_close_the_kvm_reads_proves_the_release_landed() {
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
        hid.push(kbd(4), false);
        sim.wait_for(Duration::from_secs(3), |e| hid_events(e) >= 3)
            .await
            .unwrap();
        // Waited for, not read once: the writer notes a report (`note_sent`,
        // which sets `may_hold`) only after its write returns, so kvm-sim
        // can record the held key first — the race 48c15d5 fixed in
        // `session.rs`'s `hold_cmd` (PE16 review, Plan E Task 6.1).
        let held = tokio::time::timeout(Duration::from_secs(3), async {
            while !hid.kvm_may_hold() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .is_ok();
        assert!(held, "a held key was written");
        hid.release_all(ReleaseTrigger::SessionEnd);
        close(&ctl).await;
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .expect("run did not end after Close")
            .unwrap();
        assert!(
            !hid.kvm_may_hold(),
            "the KVM's pong did not prove the release"
        );
        drop(tok_tx);
        assert_eq!(sim.stats().logouts, 0);
    }

    /// I2: a close the KVM never reads — it is not reading — proves nothing:
    /// the release written ahead of it may never land.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_close_the_kvm_never_reads_leaves_the_release_unproved() {
        let mut p = Peer::start(false).await;
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        let (t, ctl) = p.task(hid.clone(), Duration::from_secs(1));
        let run = tokio::spawn(t.run());
        flood_until(&hid, || hid.metrics.hid_reports_sent.get() >= 3).await;
        hid.release_all(ReleaseTrigger::SessionEnd);
        close(&ctl).await;
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .unwrap()
            .unwrap();
        assert!(hid.kvm_may_hold());
        assert_eq!(p.ending().await, Ending::Reset);
    }

    /// I2: only the pong to the bridge's own ping proves the read — a pong
    /// with any other payload (a heartbeat) is not the KVM's answer.
    #[tokio::test]
    async fn only_the_pong_to_the_release_ping_proves_the_read() {
        for (payload, proved) in [(&b"heartbeat"[..], false), (RELEASE_PING, true)] {
            let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
            let (mut t, ctl) = task(hid.clone(), Duration::from_secs(1));
            let sink = GateSink::new(true);
            let s2 = sink.clone();
            let (in_tx, mut in_rx) = mpsc::unbounded_channel::<Result<Message, WsError>>();
            let inbound = futures_util::stream::poll_fn(move |cx| in_rx.poll_recv(cx));
            let drive = tokio::spawn(async move { t.drive(s2, inbound).await });
            wait_sent(&sink, 2).await;
            hid.push(kbd(4), false);
            wait_sent(&sink, 3).await;
            hid.release_all(ReleaseTrigger::SessionEnd);
            let (done, ack) = oneshot::channel();
            ctl.send(WsCtl::Close { done }).unwrap();
            // The Close arm has written the release, the ping and the close
            // frame, and waits for the KVM's side: it answers.
            wait_sent(&sink, 4).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            in_tx.send(Ok(Message::Pong(payload.to_vec()))).unwrap();
            drop(in_tx);
            tokio::time::timeout(Duration::from_secs(2), ack)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(ended(drive).await, Exit::Abandoned);
            assert_eq!(
                hid.kvm_may_hold(),
                !proved,
                "a pong of {payload:?} proved the read: {}",
                !hid.kvm_may_hold()
            );
        }
    }

    /// r-m2 (re-review of the final fix wave): a close frame read after
    /// ours proves the KVM read the release only when it answers ours — it
    /// echoes our close (RFC 6455 §5.5.1). A close the KVM began, crossing
    /// ours — perhaps before it read the release — proves nothing: its own
    /// payload, none, or our code alone. Any close frame still decides the
    /// FIN: the KVM is closing, and whatever it reads next ends with ours.
    #[tokio::test]
    async fn only_an_answer_to_our_close_proves_the_read() {
        let own = |code, reason: &str| {
            Some(CloseFrame {
                code,
                reason: reason.to_owned().into(),
            })
        };
        for (frame, proved) in [
            (None, false),
            (own(CloseCode::Normal, ""), false),
            (own(CloseCode::Away, CLOSE_REASON), false),
            (own(CloseCode::Normal, "bye"), false),
            (Some(our_close()), true),
        ] {
            let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
            let (mut t, ctl) = task(hid.clone(), Duration::from_secs(1));
            let sink = GateSink::new(true);
            let s2 = sink.clone();
            let (in_tx, mut in_rx) = mpsc::unbounded_channel::<Result<Message, WsError>>();
            let inbound = futures_util::stream::poll_fn(move |cx| in_rx.poll_recv(cx));
            let drive = tokio::spawn(async move { t.drive(s2, inbound).await });
            wait_sent(&sink, 2).await;
            hid.push(kbd(4), false);
            wait_sent(&sink, 3).await;
            hid.release_all(ReleaseTrigger::SessionEnd);
            let (done, ack) = oneshot::channel();
            ctl.send(WsCtl::Close { done }).unwrap();
            // The Close arm has written the release, the ping and our close
            // frame, and waits for the KVM's side: a close frame.
            wait_sent(&sink, 4).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(sink.closes(), [Some(our_close())], "our close frame");
            in_tx.send(Ok(Message::Close(frame.clone()))).unwrap();
            tokio::time::timeout(Duration::from_secs(2), ack)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(ended(drive).await, Exit::Closed, "{frame:?}: no FIN");
            assert_eq!(
                hid.kvm_may_hold(),
                !proved,
                "a close of {frame:?} proved the read: {}",
                !hid.kvm_may_hold()
            );
        }
    }

    /// I2 (Plan D final review): while input is held — a key written when
    /// the websocket dies — the reopen skips the backoff: a KVM that keeps
    /// the key held across the loss auto-repeats it until the session-start
    /// sequence lands — once per loss, and again after a reopen has written
    /// its session start. With nothing held, the reopen backs off as ever.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn while_input_is_held_a_reconnect_skips_the_backoff() {
        use kvm_sim::{KvmSim, SimConfig, Source};
        const BACKOFF: Duration = Duration::from_secs(2);
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
        let slow = BackoffConfig {
            initial: BACKOFF,
            factor: 2,
            max: BACKOFF,
            jitter_percent: 0,
        };
        t.backoff = Backoff::new(slow, Jitter::new(1));
        let run = tokio::spawn(t.run());
        let mut next = async || {
            tokio::time::timeout(Duration::from_secs(5), ev.recv())
                .await
                .unwrap()
                .unwrap()
        };
        assert_eq!(next().await, WsEvent::Up { seq: 1 });
        let sent = |n: u64| {
            let m = hid.metrics.clone();
            async move {
                tokio::time::timeout(Duration::from_secs(3), async {
                    while m.hid_reports_sent.get() < n {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .unwrap();
            }
        };
        sent(2).await;
        // R-I1: the skip is once per loss, not once per task — each reopen
        // that wrote its session start lets the next loss with a key held
        // skip it again.
        for (held, want_fast) in [(true, true), (true, true), (false, false)] {
            if held {
                let n = hid.metrics.hid_reports_sent.get();
                hid.push(kbd(4), false); // held, and written
                sent(n + 1).await;
            }
            assert_eq!(hid.input_held(), held);
            // R-I3 (re-review of the final fix wave): counted before the
            // close. Read after `Up`, the reopen may already have written
            // its session start, and a target past it is never reached.
            let base = hid.metrics.hid_reports_sent.get();
            sim.close_websockets();
            assert_eq!(next().await, WsEvent::Down);
            let t0 = Instant::now();
            assert_eq!(next().await, WsEvent::Up { seq: 1 });
            let took = t0.elapsed();
            if want_fast {
                assert!(took < BACKOFF / 2, "held: the reopen backed off {took:?}");
            } else {
                assert!(took >= BACKOFF * 3 / 4, "nothing held: it took {took:?}");
            }
            // The reopen's session start: nothing held from here on.
            sent(base + 2).await;
        }
        close(&ctl).await;
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .expect("run did not end after Close")
            .unwrap();
        drop(tok_tx);
        assert_eq!(sim.stats().logouts, 0);
    }

    /// R-I1 (re-review of the final fix wave): a hostile or failing KVM
    /// answers every websocket upgrade and resets the connection at once,
    /// so every session-start write fails. The previous websocket wrote a
    /// held key, and a reopen that writes nothing never overwrites that, so
    /// `input_held()` stays true at every loss — yet the backoff is skipped
    /// only once until a reopen has written its session start. Without that
    /// bound the bridge reopened as fast as the KVM answered: 909–3 206
    /// opens in 2 s. The backoff here (50 ms doubling to 400 ms, no jitter)
    /// allows 9 in 2 s, the one skip included.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_kvm_that_resets_every_websocket_after_its_upgrade_is_not_reopened_hot() {
        const WATCH: Duration = Duration::from_secs(2);
        /// The backoff's 9, with room for a session start that lands
        /// before the reset (it resets the backoff, §4.4).
        const MAX_OPENS: usize = 12;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepts = Arc::new(AtomicUsize::new(0));
        let a2 = accepts.clone();
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                a2.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    if let Ok(ws) = tokio_tungstenite::accept_async(s).await {
                        // SO_LINGER 0: the drop is a reset.
                        let _ =
                            socket2::SockRef::from(ws.get_ref()).set_linger(Some(Duration::ZERO));
                        drop(ws);
                    }
                });
            }
        });
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        hid.note_sent(&kbd(4)); // the previous websocket wrote a held key
        assert!(hid.input_held());
        let (mut t, ctl) = task(hid.clone(), Duration::from_secs(1));
        t.ep = Arc::new(KvmEndpoint::new(
            Scheme::Http,
            "127.0.0.1",
            (port, port, port),
            &"0".repeat(64),
        ));
        let token = kvm_proto::parse_login_token(br#"{"result":0,"token":"0.1"}"#).unwrap();
        t.token = watch::channel(Some((1, token))).1;
        let run = tokio::spawn(t.run());
        tokio::time::sleep(WATCH).await;
        let opens = accepts.load(Ordering::SeqCst);
        close(&ctl).await;
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .expect("run did not end after Close")
            .unwrap();
        assert!(opens >= 2, "the KVM was never reopened: {opens}");
        assert!(
            opens <= MAX_OPENS,
            "a hot reconnect loop: {opens} opens in {WATCH:?} (the backoff allows 9)"
        );
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
        // I2: with key 4 held the reopen skips the backoff, so kvm-sim
        // refuses it — then the writer backs off, and the report below is
        // made while the websocket is down.
        let refused = |e: &[SimEvent]| {
            e.iter()
                .filter(|e| matches!(e, SimEvent::WsRefused { .. }))
                .count()
        };
        sim.set_policy(|p| p.ws_status = Some(503));
        sim.close_websockets();
        // The writer saw the loss, released, and is backing off.
        assert_eq!(next(&mut ev).await, WsEvent::Down);
        sim.wait_for(Duration::from_secs(3), |e| refused(e) >= 1)
            .await
            .unwrap();
        hid.push(kbd(5), false); // made while the websocket is down
        sim.set_policy(|p| p.ws_status = None);
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
        /// Not reading: shut its write side (a FIN, no close frame) now.
        half_close: Option<oneshot::Sender<()>>,
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
            let (half_close, mut half_rx) = oneshot::channel::<()>();
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
                    let mut drain_rx = drain_rx;
                    tokio::select! {
                        _ = &mut drain_rx => {}
                        Ok(()) = &mut half_rx => {
                            use tokio::io::AsyncWriteExt as _;
                            let _ = ws.get_mut().shutdown().await;
                            let _ = drain_rx.await;
                        }
                    }
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
                half_close: Some(half_close),
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
    /// up to our close frame, then answered — ends with a FIN. n2 (fix
    /// round 2): the answer is its close frame, so a KVM that then waits
    /// for our FIN before closing its side (as RFC 6455 lets a server do)
    /// costs the Stop nothing — not the whole `CLOSE_BUDGET`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_answered_close_ends_with_a_fin() {
        let mut p = Peer::start(true).await;
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        let (t, ctl) = p.task(hid.clone(), Duration::from_secs(1));
        let run = tokio::spawn(t.run());
        flood_until(&hid, || hid.metrics.hid_reports_sent.get() >= 2).await;
        let t0 = Instant::now();
        close(&ctl).await;
        let took = t0.elapsed();
        assert!(
            took < CLOSE_BUDGET / 2,
            "the close waited {took:?} for the KVM's FIN after its close frame"
        );
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(p.ending().await, Ending::Fin);
    }

    /// n1 (PC9 fix round 2): only the KVM's close frame answers our close.
    /// A KVM that stopped reading with a backlog queued and then half-closes
    /// — an EOF, no close frame — has read none of it; a FIN would deliver
    /// the whole backlog, release last, after the next websocket's session
    /// start. It is reset instead.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_half_close_with_a_backlog_unread_is_reset() {
        let mut p = Peer::start(false).await;
        let hid = Arc::new(HidControl::new(1024, Arc::new(Metrics::default())));
        let (t, ctl) = p.task(hid.clone(), Duration::from_secs(5));
        let run = tokio::spawn(t.run());
        flood_until(&hid, || hid.metrics.hid_reports_sent.get() >= 2).await;
        // A backlog the peer has not read, short of blocking a write.
        for k in 0..300u32 {
            hid.push(kbd(4 + u8::try_from(k % 20).unwrap()), false);
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while hid.metrics.hid_reports_sent.get() < 302 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the backlog blocked a write");
        hid.release_all(ReleaseTrigger::SessionEnd);
        let (done, ack) = oneshot::channel();
        ctl.send(WsCtl::Close { done }).unwrap();
        // The release and our close frame are written; the Close arm waits
        // for an answer (`CLOSE_BUDGET`, 400 ms). The peer half-closes.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = p.half_close.take().unwrap().send(());
        tokio::time::timeout(Duration::from_secs(2), ack)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(p.ending().await, Ending::Reset);
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

    // ---- Task 4.2: the re-assert once a reconnect settles (PC9 fix 2).

    /// PC9 fix 2 / DD8: after the session-start sequence, the writer
    /// re-asserts the current full state once, REASSERT_AFTER later, so a
    /// stale press the KVM read from its own buffer is overwritten. `drive`
    /// discards what was queued before it (writer.rs:254), so the reports
    /// are pushed after the session start (D2c).
    #[test]
    fn the_writer_reasserts_the_full_state_after_a_reconnect() {
        // PD9 review I5: a real-time bound on the paused clock.
        crate::testkit::paused_within(crate::testkit::PAUSED_WATCHDOG, || async {
            let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
            let (mut t, _ctl) = task(hid.clone(), Duration::from_secs(5));
            t.reassert_after = Duration::from_millis(500);
            let sink = GateSink::new(true);
            let s2 = sink.clone();
            let drive =
                tokio::spawn(async move { t.drive(s2, futures_util::stream::pending()).await });
            wait_sent(&sink, 2).await; // SET_MODE, KBD_ZERO
            // The client has 'a' down and the pointer at (300, 400).
            hid.push(kbd(0x04), false);
            hid.push(HidFrame::abs_mouse(0, 300, 400), false);
            wait_sent(&sink, 4).await;
            let before = sink.sent().len(); // 4
            tokio::time::sleep(Duration::from_millis(600)).await;
            // One re-assert: the current keyboard and mouse state again.
            let after = sink.sent();
            assert_eq!(after.len(), before + 2, "{after:?}");
            assert_eq!(after[4], kbd(0x04).to_vec());
            assert_eq!(after[5], HidFrame::abs_mouse(0, 300, 400).to_vec());
            assert_eq!(hid.metrics.hid_reasserts.get(), 1);
            drive.abort();
        });
    }

    /// The re-assert happens once per websocket, not repeatedly.
    #[test]
    fn the_reassert_is_once_per_websocket() {
        // PD9 review I5: a real-time bound on the paused clock.
        crate::testkit::paused_within(crate::testkit::PAUSED_WATCHDOG, || async {
            let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
            let (mut t, _ctl) = task(hid.clone(), Duration::from_secs(5));
            t.reassert_after = Duration::from_millis(200);
            let sink = GateSink::new(true);
            let s2 = sink.clone();
            let drive =
                tokio::spawn(async move { t.drive(s2, futures_util::stream::pending()).await });
            wait_sent(&sink, 2).await;
            hid.push(kbd(0x04), false);
            wait_sent(&sink, 3).await;
            tokio::time::sleep(Duration::from_secs(2)).await;
            assert_eq!(hid.metrics.hid_reasserts.get(), 1);
            drive.abort();
        });
    }

    /// R-I2 (re-review of the final fix wave): every open writes a ping
    /// after its session start — its own payload, never the close's — and
    /// re-asserts `reassert_after` past the KVM's pong to it. A KVM stalled
    /// past the timed re-assert reads that one with the open's other
    /// frames, in no set order against what an abandoned websocket left in
    /// its buffer; the one after the pong lands once it reads again. The
    /// timed one stays, for a KVM that never answers a ping. Only the first
    /// pong to the open's ping counts, and it proves nothing about a
    /// release: it answers a ping written before the reports after it.
    #[test]
    fn every_open_reasserts_past_the_kvms_pong_to_its_ping() {
        crate::testkit::paused_within(crate::testkit::PAUSED_WATCHDOG, || async {
            const AFTER: Duration = Duration::from_millis(500);
            const MARGIN: Duration = Duration::from_millis(100);
            let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
            let (mut t, _ctl) = task(hid.clone(), Duration::from_secs(5));
            t.reassert_after = AFTER;
            let sink = GateSink::new(true);
            let s2 = sink.clone();
            let (in_tx, mut in_rx) = mpsc::unbounded_channel::<Result<Message, WsError>>();
            let inbound = futures_util::stream::poll_fn(move |cx| in_rx.poll_recv(cx));
            let drive = tokio::spawn(async move { t.drive(s2, inbound).await });
            wait_sent(&sink, 2).await;
            assert_eq!(
                sink.pings(),
                [OPEN_PING.to_vec()],
                "no ping of its own after the session start"
            );
            // A key pressed and released: the KVM may hold it until it
            // proves it read the release.
            hid.push(kbd(0x04), false);
            hid.push(kbd(0), false);
            wait_sent(&sink, 4).await;
            let reasserts = || hid.metrics.hid_reasserts.get();
            // The KVM stalls: the timed re-assert still goes out.
            tokio::time::sleep(AFTER + MARGIN).await;
            assert_eq!(reasserts(), 1, "no timed re-assert");
            // A pong of another payload — a heartbeat's, or the close's —
            // re-arms nothing.
            for p in [&b"heartbeat"[..], RELEASE_PING] {
                in_tx.send(Ok(Message::Pong(p.to_vec()))).unwrap();
            }
            tokio::time::sleep(AFTER * 2).await;
            assert_eq!(reasserts(), 1, "another payload's pong re-armed it");
            // The KVM reads again: the state once more, `reassert_after`
            // past its pong.
            in_tx.send(Ok(Message::Pong(OPEN_PING.to_vec()))).unwrap();
            tokio::time::sleep(AFTER - MARGIN).await;
            assert_eq!(
                reasserts(),
                1,
                "re-asserted before reassert_after past the pong"
            );
            tokio::time::sleep(MARGIN * 2).await;
            assert_eq!(reasserts(), 2, "no re-assert past the pong");
            assert_eq!(sink.sent().last().unwrap(), &KBD_ZERO.to_vec());
            // Once: a second pong re-arms nothing.
            in_tx.send(Ok(Message::Pong(OPEN_PING.to_vec()))).unwrap();
            tokio::time::sleep(AFTER * 2).await;
            assert_eq!(reasserts(), 2, "a second pong re-armed it");
            assert!(hid.kvm_may_hold(), "the open's pong proved the release");
            assert_eq!(sink.pings(), [OPEN_PING.to_vec()]);
            drive.abort();
        });
    }

    /// D21: continuous motion keeps the HID side busy, and the re-assert
    /// still goes out at its deadline.
    #[test]
    fn the_reassert_is_not_starved_by_motion() {
        // PD9 review I5: a real-time bound on the paused clock.
        crate::testkit::paused_within(crate::testkit::PAUSED_WATCHDOG, || async {
            let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
            let (mut t, _ctl) = task(hid.clone(), Duration::from_secs(5));
            t.reassert_after = Duration::from_millis(100);
            let sink = GateSink::new(true);
            let s2 = sink.clone();
            let drive =
                tokio::spawn(async move { t.drive(s2, futures_util::stream::pending()).await });
            wait_sent(&sink, 2).await;
            for i in 0..40u16 {
                hid.push(HidFrame::abs_mouse(0, i, i), true);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert_eq!(hid.metrics.hid_reasserts.get(), 1);
            drive.abort();
        });
    }

    /// D21, with an arm ahead of the re-assert's wake ready at every
    /// select: the KVM never stops sending (an inbound message is always
    /// ready). The deadline is checked at the loop top, not only by a
    /// select arm that never wins, so the re-assert still goes out — and
    /// the inbound side ends the drive once it has (bounded: 10 s).
    #[tokio::test(flavor = "current_thread")]
    async fn the_reassert_is_not_starved_by_an_always_ready_arm() {
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        let (mut t, _ctl) = task(hid.clone(), Duration::from_secs(5));
        t.reassert_after = Duration::from_millis(50);
        let metrics = hid.metrics.clone();
        let until = Instant::now() + Duration::from_secs(10);
        let chatter = futures_util::stream::poll_fn(move |_| {
            if metrics.hid_reasserts.get() > 0 || Instant::now() > until {
                std::task::Poll::Ready(None)
            } else {
                std::task::Poll::Ready(Some(Ok(Message::Ping(Vec::new()))))
            }
        });
        let exit = t.drive(GateSink::new(true), chatter).await;
        assert_eq!(exit, Exit::Failed, "the inbound side ended the drive");
        assert_eq!(hid.metrics.hid_reasserts.get(), 1, "starved");
    }

    /// The full state re-asserted is the queue's own resync state: the last
    /// keyboard report and the last pointer report, zeroed by a release;
    /// before any report, nothing (and none is counted as re-asserted
    /// state, only the re-assert itself).
    #[test]
    fn the_current_state_is_the_resync_state() {
        let hid = HidControl::new(16, Arc::new(Metrics::default()));
        assert!(hid.current_state_frames().is_empty());
        hid.push(kbd(0x04), false);
        assert_eq!(hid.current_state_frames(), [kbd(0x04)]);
        hid.push(HidFrame::abs_mouse(1, 7, 9), false);
        hid.push(HidFrame::abs_mouse(1, 8, 9), true);
        hid.push(kbd(0x05), false);
        assert_eq!(
            hid.current_state_frames(),
            [kbd(0x05), HidFrame::abs_mouse(1, 8, 9)]
        );
        hid.release_all(ReleaseTrigger::Suppression);
        assert_eq!(
            hid.current_state_frames(),
            [kbd(0), HidFrame::abs_mouse(0, 8, 9)]
        );
    }

    /// A re-assert's frames go out after a release pending at its deadline
    /// (the loop serves the release first), and it re-asserts the released
    /// state: no key the release cleared comes back.
    #[test]
    fn the_reassert_never_brings_back_a_released_key() {
        // PD9 review I5: a real-time bound on the paused clock.
        crate::testkit::paused_within(crate::testkit::PAUSED_WATCHDOG, || async {
            let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
            let (mut t, _ctl) = task(hid.clone(), Duration::from_secs(5));
            t.reassert_after = Duration::from_millis(100);
            let sink = GateSink::new(true);
            let s2 = sink.clone();
            let drive =
                tokio::spawn(async move { t.drive(s2, futures_util::stream::pending()).await });
            wait_sent(&sink, 2).await;
            sink.set(false); // the KVM stops reading for a while
            hid.push(kbd(0x04), false); // taken, its write blocked
            tokio::time::sleep(Duration::from_millis(50)).await;
            hid.push(kbd(0x05), false); // queued behind it
            hid.release_all(ReleaseTrigger::KeyRepeat);
            tokio::time::sleep(Duration::from_millis(100)).await; // past the deadline
            sink.set(true);
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(hid.metrics.hid_reasserts.get(), 1);
            // The blocked 'a', the release's zero, then the re-assert: zero.
            assert_eq!(
                sink.sent(),
                [
                    SET_MODE.to_vec(),
                    KBD_ZERO.to_vec(),
                    kbd(0x04).to_vec(),
                    KBD_ZERO.to_vec(),
                    KBD_ZERO.to_vec(),
                ]
            );
            drive.abort();
        });
    }

    /// A sink each write of which brings a new pointer report — reports
    /// arriving as fast as the KVM takes them, so the queue is never empty
    /// at the loop top — until a re-assert has gone out (then it fails,
    /// ending the drive) or `until` (bounded).
    struct Refill {
        hid: Arc<HidControl>,
        n: u16,
        until: Instant,
    }

    impl Sink<Message> for Refill {
        type Error = WsError;
        fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), WsError>> {
            if self.hid.metrics.hid_reasserts.get() > 0 || Instant::now() > self.until {
                Poll::Ready(Err(WsError::ConnectionClosed))
            } else {
                Poll::Ready(Ok(()))
            }
        }
        fn start_send(mut self: Pin<&mut Self>, _: Message) -> Result<(), WsError> {
            self.n = self.n % 30_000 + 1;
            let n = self.n;
            let _ = self.hid.push(HidFrame::abs_mouse(0, n, n), true);
            Ok(())
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), WsError>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), WsError>> {
            Poll::Ready(Ok(()))
        }
    }

    /// PD9 review m1: a queue that never empties at the loop top (continuous
    /// motion under backpressure) defers the re-assert at most
    /// `reassert_after` past its deadline — it then goes out after one
    /// queued frame — rather than until the traffic pauses. Real time: the
    /// drive never yields here, so a paused clock would never move.
    #[tokio::test(flavor = "current_thread")]
    async fn the_reassert_is_not_deferred_forever_by_a_queue_that_never_empties() {
        let hid = Arc::new(HidControl::new(16, Arc::new(Metrics::default())));
        let (mut t, _ctl) = task(hid.clone(), Duration::from_secs(5));
        t.reassert_after = Duration::from_millis(50);
        let t0 = Instant::now();
        let sink = Refill {
            hid: hid.clone(),
            n: 0,
            until: t0 + Duration::from_secs(10),
        };
        let exit = t.drive(sink, futures_util::stream::pending()).await;
        assert_eq!(exit, Exit::Failed, "the sink ended the drive");
        assert_eq!(hid.metrics.hid_reasserts.get(), 1, "deferred forever");
        assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
    }

    /// What a `Backlog` sink pushed and saw written.
    #[derive(Default)]
    struct Log {
        pushed: Vec<HidFrame>,
        written: Vec<Vec<u8>>,
    }

    /// A sink each write of which brings up to two more reports from
    /// `script` (frame `i`, its `motion_only`), keeping a backlog of about
    /// 32 queued — input faster than the KVM drains — until `stop_at`.
    /// Never yields; the test bounds the drive.
    struct Backlog {
        hid: Arc<HidControl>,
        script: fn(u64) -> HidFrame,
        i: u64,
        stop_at: Instant,
        log: Arc<Mutex<Log>>,
    }

    impl Sink<Message> for Backlog {
        type Error = WsError;
        fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), WsError>> {
            Poll::Ready(Ok(()))
        }
        fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), WsError> {
            if let Message::Binary(b) = item {
                self.log.lock().unwrap().written.push(b);
            }
            for _ in 0..2 {
                if Instant::now() >= self.stop_at || self.hid.queued() >= 32 {
                    break;
                }
                let f = (self.script)(self.i);
                self.i += 1;
                let _ = self.hid.push(f, false);
                self.log.lock().unwrap().pushed.push(f);
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

    /// Drive `script` as a backlog for 300 ms past a 50 ms re-assert (so
    /// well past `reassert_by`), then let it drain; what was pushed and
    /// written. Real time, bounded at 1.5 s.
    async fn backlog_run(script: fn(u64) -> HidFrame) -> Log {
        let hid = Arc::new(HidControl::new(256, Arc::new(Metrics::default())));
        let (mut t, _ctl) = task(hid.clone(), Duration::from_secs(5));
        t.reassert_after = Duration::from_millis(50);
        let log = Arc::new(Mutex::new(Log::default()));
        let sink = Backlog {
            hid: hid.clone(),
            script,
            i: 0,
            stop_at: Instant::now() + Duration::from_millis(300),
            log: log.clone(),
        };
        let _ = tokio::time::timeout(
            Duration::from_millis(1_500),
            t.drive(sink, futures_util::stream::pending()),
        )
        .await;
        assert_eq!(hid.metrics.hid_reasserts.get(), 1, "no re-assert at all");
        Arc::try_unwrap(log).ok().unwrap().into_inner().unwrap()
    }

    /// The written frames after the session start (`SET_MODE`, `KBD_ZERO`)
    /// are the pushed ones, in their order — a re-assert may only repeat
    /// the newest state once the backlog has drained, at the end.
    fn assert_in_order(log: &Log) {
        let body = &log.written[2..];
        let pushed: Vec<Vec<u8>> = log.pushed.iter().map(HidFrame::to_vec).collect();
        assert!(pushed.len() > 100, "no backlog: {} pushed", pushed.len());
        let n = body.len().min(pushed.len());
        for k in 0..n {
            assert_eq!(
                body[k], pushed[k],
                "frame {k} written out of order (a re-assert overtook the queue)"
            );
        }
        for extra in &body[n..] {
            assert!(
                pushed.last() == Some(extra),
                "a frame after the drain that is not the newest state"
            );
        }
    }

    /// PD9 re-review R-I1: typing faster than the KVM drains, past
    /// `reassert_by`. The bounded re-assert must not write the newest
    /// keyboard state ahead of queued keyboard reports — that typed a
    /// letter early and then again in order (the reviewer's S4). It waits
    /// for the keyboard reports to go out.
    #[tokio::test(flavor = "current_thread")]
    async fn a_reassert_never_overtakes_queued_keyboard_reports() {
        fn typing(i: u64) -> HidFrame {
            let k = 0x04 + u8::try_from((i / 2) % 26).unwrap();
            if i.is_multiple_of(2) { kbd(k) } else { kbd(0) }
        }
        assert_in_order(&backlog_run(typing).await);
    }

    /// R-I1, the pointer: a drag (press, moves, release) queued past the
    /// bound is never overtaken by the newest pointer state — that would
    /// drop the drag and re-press it.
    #[tokio::test(flavor = "current_thread")]
    async fn a_reassert_never_overtakes_a_queued_drag() {
        fn drag(i: u64) -> HidFrame {
            let n = u16::try_from(i % 6).unwrap();
            let buttons = u8::from(n < 4);
            HidFrame::abs_mouse(buttons, 100 + n, 100 + n)
        }
        assert_in_order(&backlog_run(drag).await);
    }

    /// R-I1's rule, directly: nothing while a keyboard report waits (in the
    /// queue or a resync's output); the keyboard state alone while pointer
    /// reports wait; both once nothing does.
    #[test]
    fn what_a_reassert_may_write_never_overtakes_a_queued_report() {
        let hid = HidControl::new(2, Arc::new(Metrics::default()));
        assert_eq!(hid.reassert_frames(), Some(vec![]));
        hid.push(kbd(0x04), false);
        hid.push(HidFrame::abs_mouse(1, 5, 5), false);
        assert!(hid.keyboard_queued());
        assert_eq!(hid.reassert_frames(), None);
        assert_eq!(hid.next_frame(), Some(kbd(0x04)));
        assert!(!hid.keyboard_queued());
        assert_eq!(
            hid.reassert_frames(),
            Some(vec![kbd(0x04)]),
            "pointer waits"
        );
        assert_eq!(hid.next_frame(), Some(HidFrame::abs_mouse(1, 5, 5)));
        assert_eq!(
            hid.reassert_frames(),
            Some(vec![kbd(0x04), HidFrame::abs_mouse(1, 5, 5)])
        );
        // A pending resync re-sends the newest state itself: a re-assert
        // ahead of it writes the same frames, overtaking nothing.
        hid.push(kbd(0x05), false);
        hid.push(kbd(0x06), false);
        hid.push(kbd(0x07), false); // past the capacity of 2: a resync
        assert_eq!(
            hid.reassert_frames(),
            Some(vec![kbd(0x07), HidFrame::abs_mouse(1, 5, 5)])
        );
        // Once the resync's frames are out, the one still waiting counts.
        assert_eq!(hid.next_frame(), Some(kbd(0x07)));
        assert_eq!(
            hid.reassert_frames(),
            Some(vec![kbd(0x07)]),
            "its pointer frame waits"
        );
    }
}
