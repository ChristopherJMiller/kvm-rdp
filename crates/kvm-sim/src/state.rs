//! State shared by kvm-sim's listeners and its test-facing handle: the
//! event log, counters, live tokens and the fault policy.
use std::collections::HashSet;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, mpsc};

/// Which of the three ES3 service ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortKind {
    /// Login/logout (443 on the ES3).
    Web,
    /// `av.flv` (8881).
    Video,
    /// The control websocket (8889).
    Control,
}

/// Everything kvm-sim observed, in order. L2 tests assert on these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimEvent {
    /// A TCP connection was accepted (before TLS).
    Accept {
        port: PortKind,
    },
    Login {
        ok: bool,
    },
    /// `GET /cgi-bin/login.lua?logout`: every token was invalidated.
    Logout,
    FlvOpen {
        conn: u64,
    },
    FlvRefused {
        status: u16,
    },
    FlvClose {
        conn: u64,
    },
    /// One coded tag written; `at` of the stamped event is `sim_tx` (the
    /// moment `write_all` of its last byte returned, §10.1).
    FlvAu {
        conn: u64,
        seq: u64,
        /// The source frame's index: the fixture's barcode value.
        source_index: usize,
        frame_id: u64,
        idr: bool,
    },
    WsOpen {
        conn: u64,
    },
    WsRefused {
        status: u16,
    },
    WsClose {
        conn: u64,
    },
    /// One websocket data message, verbatim (§3.3 HID frames).
    Hid {
        conn: u64,
        bytes: Vec<u8>,
    },
}

/// Counters and gauges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SimStats {
    pub accepts_web: u64,
    pub accepts_video: u64,
    pub accepts_control: u64,
    pub logins_ok: u64,
    pub logins_failed: u64,
    pub logouts: u64,
    pub flv_open: u64,
    pub ws_open: u64,
    pub ws_max_open: u64,
    pub frames_sent: u64,
    /// Frames a viewer's queue had no room for (it was not reading).
    pub frames_dropped: u64,
    /// Events past the log's cap (`MAX_EVENTS`): counted, not recorded.
    pub events_dropped: u64,
    /// Longest single FLV `write_all` (§10.2: never above 100 ms).
    pub max_flv_write_block: Duration,
}

/// Behaviour switches a test flips at any time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    /// Every login answers `result` ≠ 0.
    pub reject_logins: bool,
    /// Answer `av.flv` with this HTTP status instead of a stream.
    pub flv_status: Option<u16>,
    /// The next N `av.flv` opens made while another FLV is open get 503
    /// (side connections refused); each refusal decrements it.
    pub refuse_concurrent_flv: u32,
    /// Answer the websocket upgrade with this HTTP status.
    pub ws_status: Option<u16>,
    /// Stop reading websockets (the bridge's writes back up).
    pub pause_ws_reads: bool,
    /// New FLV connections start with a NALU tag, no sequence header.
    pub skip_sequence_header: bool,
    /// New TCP connections are accepted, then left silent — no TLS, no
    /// bytes — until the client gives up: an unreachable KVM (§11.3).
    pub blackhole: bool,
}

/// A command for every open websocket.
#[derive(Debug, Clone, Copy)]
pub(crate) enum WsCmd {
    Close,
    /// Write a frame header declaring this payload length, then 4 KiB.
    Oversize(u64),
}

#[derive(Default)]
struct Inner {
    events: Vec<SimEvent>,
    /// When each of `events` was recorded (`FlvAu`: `sim_tx`).
    stamps: Vec<Instant>,
    stats: SimStats,
    tokens: HashSet<String>,
    next_token: u64,
    policy: Policy,
    ws: Vec<mpsc::UnboundedSender<WsCmd>>,
}

/// Cap on recorded events (a 1 h soak at 30 fps is ~110 k; the cap is at
/// most ~70 MB of log). Past it, events are only counted.
const MAX_EVENTS: usize = 1_000_000;

#[derive(Default)]
pub(crate) struct Shared {
    inner: Mutex<Inner>,
    changed: Notify,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn record(&self, event: SimEvent) {
        self.record_at(Instant::now(), event);
    }

    pub(crate) fn record_at(&self, at: Instant, event: SimEvent) {
        {
            let mut g = self.lock();
            let s = &mut g.stats;
            match &event {
                SimEvent::Accept { port } => match port {
                    PortKind::Web => s.accepts_web += 1,
                    PortKind::Video => s.accepts_video += 1,
                    PortKind::Control => s.accepts_control += 1,
                },
                SimEvent::Login { ok: true } => s.logins_ok += 1,
                SimEvent::Login { ok: false } => s.logins_failed += 1,
                SimEvent::Logout => s.logouts += 1,
                SimEvent::FlvOpen { .. } => s.flv_open += 1,
                SimEvent::FlvClose { .. } => s.flv_open = s.flv_open.saturating_sub(1),
                SimEvent::FlvAu { .. } => s.frames_sent += 1,
                SimEvent::WsOpen { .. } => {
                    s.ws_open += 1;
                    s.ws_max_open = s.ws_max_open.max(s.ws_open);
                }
                SimEvent::WsClose { .. } => s.ws_open = s.ws_open.saturating_sub(1),
                _ => {}
            }
            if g.events.len() < MAX_EVENTS {
                g.events.push(event);
                g.stamps.push(at);
            } else {
                g.stats.events_dropped += 1;
            }
        }
        self.changed.notify_waiters();
    }

    pub(crate) fn frame_dropped(&self) {
        self.lock().stats.frames_dropped += 1;
    }

    pub(crate) fn write_blocked(&self, d: Duration) {
        let mut g = self.lock();
        g.stats.max_flv_write_block = g.stats.max_flv_write_block.max(d);
    }

    pub(crate) fn events(&self) -> Vec<SimEvent> {
        self.lock().events.clone()
    }

    pub(crate) fn stamped_events(&self) -> Vec<(Instant, SimEvent)> {
        let g = self.lock();
        g.stamps
            .iter()
            .copied()
            .zip(g.events.iter().cloned())
            .collect()
    }

    pub(crate) fn stats(&self) -> SimStats {
        self.lock().stats.clone()
    }

    pub(crate) fn policy(&self) -> Policy {
        self.lock().policy.clone()
    }

    pub(crate) fn set_policy(&self, f: impl FnOnce(&mut Policy)) {
        f(&mut self.lock().policy);
    }

    /// `true` exactly for the one `av.flv` open that spends the policy's
    /// refusal (P3): `flv_open > 0` and `refuse_concurrent_flv > 0` are
    /// tested and the latter decremented under the same lock acquisition,
    /// so two concurrent opens racing a count of 1 cannot both read "still
    /// refusing" before either decrements (fix round 1, m3 — `policy()`
    /// then a separate `set_policy()` call let that happen).
    pub(crate) fn take_flv_refusal(&self) -> bool {
        let mut g = self.lock();
        if g.stats.flv_open > 0 && g.policy.refuse_concurrent_flv > 0 {
            g.policy.refuse_concurrent_flv = g.policy.refuse_concurrent_flv.saturating_sub(1);
            true
        } else {
            false
        }
    }

    /// Mint a `0.<digits>` token (§3.1); logins coexist (§3.2).
    pub(crate) fn mint_token(&self) -> String {
        let mut g = self.lock();
        g.next_token += 1;
        let t = format!("0.{}", 100_000_000 + g.next_token);
        g.tokens.insert(t.clone());
        t
    }

    pub(crate) fn token_valid(&self, token: &str) -> bool {
        self.lock().tokens.contains(token)
    }

    /// Logout is global on the ES3 (§3.2): every token dies at once.
    pub(crate) fn clear_tokens(&self) {
        self.lock().tokens.clear();
    }

    pub(crate) fn add_ws(&self, tx: mpsc::UnboundedSender<WsCmd>) {
        self.lock().ws.push(tx);
    }

    pub(crate) fn ws_broadcast(&self, cmd: WsCmd) {
        self.lock().ws.retain(|tx| tx.send(cmd).is_ok());
    }

    /// Wait until `pred` holds over the event log, or `timeout`. `pred` runs
    /// on the log under the lock, so a wake-up copies nothing; the log is
    /// cloned once, for the result.
    pub(crate) async fn wait_for(
        &self,
        timeout: Duration,
        pred: impl Fn(&[SimEvent]) -> bool,
    ) -> Result<Vec<SimEvent>, Vec<SimEvent>> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.changed.notified();
            {
                let g = self.lock();
                if pred(&g.events) {
                    return Ok(g.events.clone());
                }
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return Err(self.lock().events.clone());
            }
        }
    }
}
