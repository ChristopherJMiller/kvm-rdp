//! DC18's session questions: how long an abandoned token stays valid, and
//! whether the KVM caps concurrent sessions. A token is probed with a bare
//! websocket upgrade — accepted or refused, then closed with no data frame.
use super::RefusalForm;
use super::ws::{self, Upgrade};
use crate::kvm::{self, KvmError, PROBE_TIMEZONE};
use crate::request::KvmTarget;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Accepted,
    Refused(RefusalForm),
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifeProbe {
    pub age: Duration,
    pub outcome: Outcome,
}

pub async fn probe_token(
    t: &KvmTarget,
    control_pin: Option<&str>,
    token: &str,
    timeout: Duration,
) -> Outcome {
    match ws::upgrade(t, control_pin, Some(token), timeout).await {
        Ok(Upgrade::Accepted(mut w)) => {
            // Bounded: a KVM that never reads can stall the close frame.
            let _ = tokio::time::timeout(timeout, w.close(None)).await;
            Outcome::Accepted
        }
        Ok(Upgrade::Refused(f)) => Outcome::Refused(f),
        Err(e) => Outcome::Failed(kvm::bounded_debug(&e)),
    }
}

async fn fresh_token(
    t: &KvmTarget,
    web_pin: Option<&str>,
    password: &str,
) -> Result<String, KvmError> {
    kvm::login(t, web_pin, password, super::now_unix(), PROBE_TIMEZONE).await
}

/// `token-life`: one login per age now, then each token probed once, when
/// it reaches its age — probing a token only once means a use cannot have
/// refreshed it.
pub async fn token_life(
    t: &KvmTarget,
    web_pin: Option<&str>,
    control_pin: Option<&str>,
    password: &str,
    ages: &[Duration],
    timeout: Duration,
    mut on: impl FnMut(&LifeProbe),
) -> Result<Vec<LifeProbe>, KvmError> {
    let mut order: Vec<(Duration, String)> = Vec::with_capacity(ages.len());
    for age in ages {
        order.push((*age, fresh_token(t, web_pin, password).await?));
    }
    order.sort_by_key(|(age, _)| *age);
    let t0 = Instant::now();
    let mut out = Vec::with_capacity(order.len());
    for (age, token) in order {
        let at = t0.checked_add(age).unwrap_or(t0);
        tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await;
        let probe = LifeProbe {
            age,
            outcome: probe_token(t, control_pin, &token, timeout).await,
        };
        on(&probe);
        out.push(probe);
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapReport {
    pub logins: u32,
    /// Why the run stopped before `max`, if it did.
    pub stopped: Option<String>,
}

/// `session-cap`: up to `max` logins; after each, the newest and the first
/// token must both still upgrade. A refused first login is the error.
pub async fn session_cap(
    t: &KvmTarget,
    web_pin: Option<&str>,
    control_pin: Option<&str>,
    password: &str,
    max: u32,
    timeout: Duration,
    mut on: impl FnMut(u32, &str),
) -> Result<CapReport, KvmError> {
    let first = fresh_token(t, web_pin, password).await?;
    on(1, "login ok");
    let mut logins = 1u32;
    for i in 2..=max {
        let token = match fresh_token(t, web_pin, password).await {
            Ok(tok) => tok,
            Err(e) => {
                return Ok(CapReport {
                    logins,
                    stopped: Some(format!("login {i} refused: {}", kvm::bounded_debug(&e))),
                });
            }
        };
        logins = i;
        let newest = probe_token(t, control_pin, &token, timeout).await;
        let oldest = probe_token(t, control_pin, &first, timeout).await;
        on(i, &format!("newest {newest:?}; first {oldest:?}"));
        if oldest != Outcome::Accepted {
            return Ok(CapReport {
                logins,
                stopped: Some(format!(
                    "the first token stopped working after login {i}: {oldest:?}"
                )),
            });
        }
        if newest != Outcome::Accepted {
            return Ok(CapReport {
                logins,
                stopped: Some(format!("login {i}'s token was refused: {newest:?}")),
            });
        }
    }
    Ok(CapReport {
        logins,
        stopped: None,
    })
}

/// `logout-watch` (controller ruling 1): how often to poll, and for how long.
#[derive(Debug, Clone, Copy)]
pub struct WatchPlan {
    pub max: Duration,
    pub poll: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchReport {
    /// How long after READY the probe's token was first refused; `None` if
    /// it never was within `max` (the owner did not log out, or the logout
    /// is not global after all).
    pub logged_out_after: Option<Duration>,
    /// The FLV and websocket refusal forms for the logged-out token.
    pub flv_form: Option<RefusalForm>,
    pub ws_form: Option<RefusalForm>,
    /// The websocket opened before the logout showed no close frame, EOF or
    /// error after it.
    pub ws_survived: bool,
    /// One all-zero keyboard report (a release) written on it afterwards
    /// succeeded.
    pub ws_write_ok: bool,
    /// The FLV opened before the logout still delivered tags afterwards.
    pub flv_survived: bool,
}

/// `logout-watch`: the probe NEVER logs out (§3.2, DD1). It logs in, opens
/// the control websocket and an FLV on its token, calls `ready` (the CLI
/// prints `READY: log out of the KVM web UI now` — the OWNER logs out), then
/// polls a fresh FLV open on the same token every `plan.poll` until it is
/// refused or `plan.max` passes. It records the FLV and websocket refusal
/// forms after the logout, and whether the pre-opened websocket and FLV
/// survived it — the facts the Plan A assumption and PC6's classifier rest
/// on. Both held streams are read all along, as the bridge reads its own, so
/// a KVM that drops a reader that stalled (an unanswered ping, a full
/// window) is not mistaken for one whose logout closed it.
pub async fn logout_watch(
    t: &KvmTarget,
    web_pin: Option<&str>,
    video_pin: Option<&str>,
    control_pin: Option<&str>,
    password: &str,
    plan: WatchPlan,
    ready: impl FnOnce(),
) -> Result<WatchReport, KvmError> {
    use futures_util::{SinkExt as _, StreamExt as _};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use tokio_tungstenite::tungstenite::Message;
    let open_wait = Duration::from_secs(10);
    let token = fresh_token(t, web_pin, password).await?;
    let held_ws = match ws::upgrade(t, control_pin, Some(&token), open_wait).await? {
        Upgrade::Accepted(w) => w,
        Upgrade::Refused(f) => {
            return Err(KvmError::Http(format!(
                "websocket refused before the logout: {f}"
            )));
        }
    };
    let mut held_flv = match super::flv::open(t, video_pin, Some(&token), open_wait).await? {
        super::flv::FlvOpen::Stream(s) => s,
        super::flv::FlvOpen::Refused(f) => {
            return Err(KvmError::Http(format!(
                "av.flv refused before the logout: {f}"
            )));
        }
    };
    // The held FLV lives as long as the watch: cap it for that life, not at
    // the 64 MiB that a 300 s watch on a moving screen would pass.
    held_flv.set_max_bytes(held_flv_cap(plan.max));
    let tags = Arc::new(AtomicU64::new(0));
    let counted = tags.clone();
    let reader = tokio::spawn(async move {
        while let Ok(Some(_)) = held_flv.next_tag().await {
            counted.fetch_add(1, Ordering::Relaxed);
        }
    });
    // The held websocket is read all along (D32: so a close is seen, and
    // the KVM's pings are answered); the probe writes on it only once, the
    // all-zero release below.
    let (mut ws_tx, mut ws_rx) = (*held_ws).split();
    let ws_ended = Arc::new(AtomicBool::new(false));
    let ended = ws_ended.clone();
    let ws_reader = tokio::spawn(async move {
        while let Some(Ok(m)) = ws_rx.next().await {
            if matches!(m, Message::Close(_)) {
                break;
            }
        }
        ended.store(true, Ordering::Relaxed);
    });
    ready();
    let t0 = Instant::now();
    let until = t0.checked_add(plan.max).unwrap_or(t0);
    let mut report = WatchReport {
        logged_out_after: None,
        flv_form: None,
        ws_form: None,
        ws_survived: false,
        ws_write_ok: false,
        flv_survived: false,
    };
    while Instant::now() < until {
        // A poll is a plain FLV open (it forces an IDR into every viewer —
        // harmless); dropped at once when it is served.
        if let Ok(super::flv::FlvOpen::Refused(f)) =
            super::flv::open(t, video_pin, Some(&token), open_wait).await
        {
            report.logged_out_after = Some(t0.elapsed());
            report.flv_form = Some(f);
            break;
        }
        tokio::time::sleep(plan.poll).await;
    }
    if report.logged_out_after.is_some() {
        report.ws_form = match ws::upgrade(t, control_pin, Some(&token), open_wait).await {
            Ok(Upgrade::Refused(f)) => Some(f),
            _ => None,
        };
        // A close the KVM sent at the logout has had the refusal's round
        // trips to land; give it 200 ms more.
        tokio::time::sleep(Duration::from_millis(200)).await;
        report.ws_survived = !ws_ended.load(Ordering::Relaxed);
        let zero = kvm_proto::hid::HidFrame::Keyboard {
            modifiers: 0,
            keys: [0; 5],
        };
        report.ws_write_ok = matches!(
            tokio::time::timeout(
                Duration::from_secs(1),
                ws_tx.send(Message::Binary(zero.to_vec()))
            )
            .await,
            Ok(Ok(()))
        );
        let before = tags.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_secs(1)).await;
        report.flv_survived = tags.load(Ordering::Relaxed) > before;
    }
    let _ = tokio::time::timeout(Duration::from_secs(1), ws_tx.close()).await;
    ws_reader.abort();
    reader.abort();
    Ok(report)
}

/// The held FLV's byte cap in `logout-watch`: 1 MiB for each second the
/// watch can last (`max`, plus a minute for the opens and checks around
/// it) — four times the ES3's ~2 Mbit/s (census Leg A) — and never below
/// `flv::MAX_BYTES`. Still finite (§9.2); it only stops the cap from ending
/// the FLV before the watch does, which would read as "did not survive".
fn held_flv_cap(max: Duration) -> u64 {
    const PER_SEC: u64 = 1024 * 1024;
    PER_SEC
        .saturating_mul(max.as_secs().saturating_add(60))
        .max(super::flv::MAX_BYTES)
}
