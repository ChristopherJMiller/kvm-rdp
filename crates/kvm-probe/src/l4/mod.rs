//! Plan D's L4 hardware checks (spec §11.6). None logs out (kvm-probe
//! cannot, §3.2; `web` refuses any path that could). The non-HID checks
//! send no HID frame except `logout-watch`'s one all-zero release; the HID
//! checks (`hid`, `hold`) end every run released (`hid::guarded`) and send
//! only the test page's pattern (`page`), `hold`'s one '1' and `hid`'s
//! bounded stale burst — never Esc, Alt/Option or Cmd. Device text reaches
//! the terminal only escaped and bounded (§9.2): `escaped`, `RefusalForm`.
pub mod flv;
pub mod hid;
pub mod hold;
pub mod page;
pub mod session;
pub mod snapshot;
pub mod web;
pub mod ws;

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A token the KVM never issued (DD1: the refusal forms are measured
/// without a logout).
pub const NEVER_ISSUED: &str = "0.0";

/// How much of a refusal's body is kept.
pub const FORM_BODY_MAX: usize = 64;

/// How the KVM refused a request: status, Content-Type and the start of
/// the body, each escaped and bounded — derived facts for census.md.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalForm {
    pub status: u16,
    pub content_type: String,
    pub body: String,
}

impl RefusalForm {
    #[must_use]
    pub fn new(status: u16, content_type: Option<&[u8]>, body: &[u8]) -> RefusalForm {
        RefusalForm {
            status,
            content_type: escaped(content_type.unwrap_or_default(), FORM_BODY_MAX),
            body: escaped(body, FORM_BODY_MAX),
        }
    }
}

impl std::fmt::Display for RefusalForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "status {} content-type \"{}\" body \"{}\"",
            self.status, self.content_type, self.body
        )
    }
}

/// At most `max` bytes, every byte outside printable ASCII (and `"`, `\`)
/// escaped as `std::ascii::escape_default` does.
#[must_use]
pub fn escaped(bytes: &[u8], max: usize) -> String {
    bytes
        .iter()
        .take(max)
        .flat_map(|b| std::ascii::escape_default(*b))
        .map(char::from)
        .collect()
}

/// Seconds since the Unix epoch, for the login body's `time`.
#[must_use]
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

#[must_use]
pub fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Milliseconds from `t0` to `t` (0 if `t` is earlier).
#[must_use]
pub fn since(t0: Instant, t: Instant) -> u64 {
    ms(t.saturating_duration_since(t0))
}

/// `now + d` on tokio's clock, saturating.
#[must_use]
pub fn deadline(d: Duration) -> tokio::time::Instant {
    let now = tokio::time::Instant::now();
    now.checked_add(d).unwrap_or(now)
}
