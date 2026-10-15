//! The bridge's one TOML file (spec §4.4). Every key has the §4.4 default;
//! secrets come only from files named here (§9.2) and live in [`Secret`],
//! whose `Debug` never shows them. Validation happens before anything binds,
//! and bounds every duration to [`MAX_DURATION`] so `Instant + d` in the
//! sans-IO cores cannot overflow. Only `KVM_RDP_CONFIG` is ever read from
//! the environment, by `main` (DC5).
use kvm_proto::h264::rewrite::RewriteConfig;
use kvm_proto::video::AdmissionConfig;
use serde::Deserialize;
use std::fmt;
use std::io::Read as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Longest accepted duration for any key.
pub const MAX_DURATION: Duration = Duration::from_secs(3600);
/// §9.1: the NLA password is ≥ 128 random bits — 22 characters of base64.
pub const MIN_NLA_PASSWORD: usize = 22;
const MAX_SECRET_FILE: u64 = 4096;
/// Largest config file read: a real one is a few KiB.
pub const MAX_CONFIG: u64 = 1 << 20;

/// A secret read from a file. Never `Display`; `Debug` is redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Secret {
        Secret(s.into())
    }
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// What a config file's TOML can be wrong with: the only words a parse error
/// carries besides its position (I1, PC15 re-review). toml's and serde's
/// own text echoes the file — keys, values, the source line — and cannot be
/// made safe by redaction, so none of it is kept.
pub const PARSE_CATEGORIES: [&str; 7] = [
    "unknown key",
    "wrong value type",
    "missing required key",
    "duplicate key",
    "syntax error",
    "file too large",
    "not UTF-8",
];

#[derive(Debug)]
pub enum ConfigError {
    /// The config file itself (the path the command line named).
    Read {
        path: PathBuf,
        kind: std::io::ErrorKind,
    },
    /// A file a `*_file` key names: the key and the I/O kind only — never
    /// the value, which may be the secret itself written where the file
    /// name goes (C1, final review; §4.4).
    File {
        key: &'static str,
        kind: std::io::ErrorKind,
    },
    /// Where (1-based line and column, when toml says) and a category from
    /// `PARSE_CATEGORIES` — never toml's or serde's text.
    Parse {
        at: Option<(usize, usize)>,
        what: &'static str,
    },
    Invalid(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Read { path, kind } => write!(f, "cannot read {}: {kind}", path.display()),
            ConfigError::File { key, kind } => write!(f, "{key}: cannot read the file: {kind}"),
            ConfigError::Parse {
                at: Some((line, column)),
                what,
            } => write!(f, "invalid TOML at line {line}, column {column}: {what}"),
            ConfigError::Parse { at: None, what } => write!(f, "invalid TOML: {what}"),
            ConfigError::Invalid(e) => write!(f, "invalid config: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

fn invalid(msg: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(msg.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Https,
    Http,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdrPolicy {
    Side,
    Reconnect,
    Wait,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Multiline {
    Enter,
    Refuse,
}

/// `kvm.backoff` (§4.4): `initial` ×`factor` up to `max`, ±`jitter_percent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffConfig {
    pub initial: Duration,
    pub factor: u32,
    pub max: Duration,
    pub jitter_percent: u32,
}

/// `video.sps_rewrite` (§6.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SpsRewrite {
    pub level: bool,
    pub vui: bool,
    pub restriction: bool,
}

#[derive(Clone)]
pub struct RdpConfig {
    pub listen: SocketAddr,
    pub username: String,
    pub nla_password: Secret,
    pub tls_cert_file: PathBuf,
    pub tls_key_file: PathBuf,
    pub cert_poll_interval: Duration,
}

/// The TLS paths are redacted like the secrets: a `*_file` value may be a
/// secret or a pasted PEM written where the file name goes (C1).
impl fmt::Debug for RdpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RdpConfig")
            .field("listen", &self.listen)
            .field("username", &self.username)
            .field("nla_password", &self.nla_password)
            .field("tls_cert_file", &format_args!("<path>"))
            .field("tls_key_file", &format_args!("<path>"))
            .field("cert_poll_interval", &self.cert_poll_interval)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct AdminConfig {
    pub listen: SocketAddr,
    pub liveness_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct KvmConfig {
    pub host: String,
    /// Lowercase hex SHA-256 of the KVM certificate's SPKI (§3.2).
    pub spki_sha256: String,
    pub scheme: Scheme,
    pub web_port: u16,
    pub video_port: u16,
    pub control_port: u16,
    pub password: Secret,
    pub connect_timeout: Duration,
    pub login_timeout: Duration,
    pub backoff: BackoffConfig,
    pub upstream_deadline: Duration,
}

#[derive(Debug, Clone)]
pub struct VideoConfig {
    pub default_size: (u16, u16),
    pub max_fps: u32,
    pub soft_gate: Duration,
    pub hard_cap: Duration,
    pub backlog_limit: u64,
    pub standing_delay_limit: Duration,
    pub rtt_probe_interval: Duration,
    pub first_ack_grace: Duration,
    pub stall_timeout: Duration,
    pub idr_policy: IdrPolicy,
    pub idr_side_timeout: Duration,
    pub idr_wait_max: Duration,
    pub flv_reconnect_interval_setup: Duration,
    pub flv_reconnect_interval_flow: Duration,
    pub flv_idle_timeout: Duration,
    pub burst_chunk: u32,
    pub sps_rewrite: SpsRewrite,
    pub avc420_timeout: Duration,
    pub suppress_debounce: Duration,
    pub disconnect_watchdog: Duration,
    pub region_qp: u8,
}

impl VideoConfig {
    /// §6.6: ceil(`hard_cap` × `max_fps`) + the census maximum burst (0).
    #[must_use]
    pub fn hard_cap_frames(&self) -> u32 {
        let millis = self
            .hard_cap
            .as_millis()
            .saturating_mul(u128::from(self.max_fps));
        u32::try_from(millis.div_ceil(1000)).unwrap_or(u32::MAX)
    }

    /// The admission settings §6.1/§6.2/§6.8 derive from `video.*`.
    #[must_use]
    pub fn admission(&self) -> AdmissionConfig {
        AdmissionConfig {
            rewrite: RewriteConfig {
                level: self.sps_rewrite.level,
                vui: self.sps_rewrite.vui,
                restriction: self.sps_rewrite.restriction,
                max_fps: self.max_fps,
            },
            ..AdmissionConfig::default()
        }
    }
}

#[derive(Debug, Clone)]
pub struct InputConfig {
    pub queue: usize,
    pub hid_write_timeout: Duration,
    pub key_repeat_timeout: Duration,
    pub modifier_idle_timeout: Duration,
    pub mac_remap: bool,
    /// How long past each websocket open's session start the full HID state
    /// is re-asserted, once (§3.2, §7.4; PC9 fix 2, DD8). 1 s until L4
    /// retunes it (Task 6.1).
    pub reassert_after: Duration,
}

/// `paste.*` (§8). `chord` is parsed at load (DD11); it is config, not
/// input, so the derived `Debug` is safe.
#[derive(Debug, Clone)]
pub struct PasteConfig {
    pub chord: kvm_proto::keymap::Chord,
    pub pace: Duration,
    pub max_chars: usize,
    pub max_bytes: usize,
    pub modifier_wait: Duration,
    pub multiline: Multiline,
}

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub accept_rate: u32,
    pub accept_window: Duration,
}

#[derive(Debug, Clone)]
pub struct LogConfig {
    pub filter: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub rdp: RdpConfig,
    pub admin: AdminConfig,
    pub kvm: KvmConfig,
    pub video: VideoConfig,
    pub input: InputConfig,
    pub paste: PasteConfig,
    pub security: SecurityConfig,
    pub log: LogConfig,
}

impl Config {
    /// Read and validate the config file; secrets resolve against its
    /// directory.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let read = |e: std::io::Error| ConfigError::Read {
            path: path.to_owned(),
            kind: e.kind(),
        };
        // Through a hard cap (one byte past it is how "over" is seen), so a
        // wrong path such as /dev/zero cannot exhaust memory.
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .map_err(read)?
            .take(MAX_CONFIG + 1)
            .read_to_end(&mut bytes)
            .map_err(read)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CONFIG {
            return Err(ConfigError::Parse {
                at: None,
                what: "file too large",
            });
        }
        let text = String::from_utf8(bytes).map_err(|_| ConfigError::Parse {
            at: None,
            what: "not UTF-8",
        })?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        Config::from_toml(&text, base)
    }

    pub fn from_toml(text: &str, base: &Path) -> Result<Config, ConfigError> {
        let raw: Raw = toml::from_str(text).map_err(|e| parse_error(text, &e))?;
        build(raw, base)
    }
}

/// I1 (PC15 review and re-review, §9.2): a parse error is a position and a
/// category, never text. toml's `Display` quotes the source line, and its
/// message quotes keys and values in ways no redaction can bound (a key
/// holding a backtick, a value holding ", expected "), so the message is
/// only matched against known prefixes to pick a category; none of it is
/// kept.
fn parse_error(text: &str, e: &toml::de::Error) -> ConfigError {
    ConfigError::Parse {
        at: e.span().map(|span| position(text, span.start)),
        what: category(e.message()),
    }
}

/// The category for a toml or serde message, by its leading words (which
/// are theirs, not the file's); anything else is a syntax error. Only the
/// `&'static str` chosen here leaves — never the message.
fn category(message: &str) -> &'static str {
    const BY_PREFIX: [(&str, &str); 8] = [
        ("unknown field", "unknown key"),
        ("invalid type", "wrong value type"),
        ("invalid value", "wrong value type"),
        ("invalid length", "wrong value type"),
        ("unknown variant", "wrong value type"),
        ("missing field", "missing required key"),
        ("duplicate key", "duplicate key"),
        ("duplicate field", "duplicate key"),
    ];
    BY_PREFIX
        .iter()
        .find(|(prefix, _)| message.starts_with(prefix))
        .map_or("syntax error", |&(_, what)| what)
}

/// `--config <file>` or `--config=<file>`, else `KVM_RDP_CONFIG` (§4.4) —
/// the only environment variable the bridge reads. `args` excludes argv[0].
pub fn config_path(
    args: impl IntoIterator<Item = std::ffi::OsString>,
    env: Option<std::ffi::OsString>,
) -> Result<PathBuf, ConfigError> {
    let mut args = args.into_iter();
    let mut found = None;
    while let Some(a) = args.next() {
        if a == "--config" {
            found = Some(PathBuf::from(
                args.next()
                    .ok_or_else(|| invalid("--config needs a file"))?,
            ));
        } else if let Some(v) = a.to_str().and_then(|s| s.strip_prefix("--config=")) {
            found = Some(PathBuf::from(v));
        } else {
            return Err(invalid(format!(
                "unknown argument {a:?} (usage: kvm-rdp --config <file>)"
            )));
        }
    }
    found
        .or_else(|| env.map(PathBuf::from))
        .ok_or_else(|| invalid("no config: pass --config <file> or set KVM_RDP_CONFIG"))
}

/// The 1-based line and column (in characters) of byte `offset` in `text`;
/// an offset inside a character rounds down, one past the end clamps.
fn position(text: &str, offset: usize) -> (usize, usize) {
    let mut end = offset.min(text.len());
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let before = text.get(..end).unwrap_or("");
    let line = before.matches('\n').count().saturating_add(1);
    let column = before
        .rsplit('\n')
        .next()
        .map_or(0, |l| l.chars().count())
        .saturating_add(1);
    (line, column)
}

/// `main`'s config step (§4.4): the path from the command line or
/// `KVM_RDP_CONFIG`, then that file, loaded and validated. `Err` is the line
/// `main` prints to stderr before exiting 2 — fixed text, the path and a
/// position, never the file's contents (§9.2).
pub fn from_command_line(
    args: impl IntoIterator<Item = std::ffi::OsString>,
    env: Option<std::ffi::OsString>,
) -> Result<Config, String> {
    let path = config_path(args, env).map_err(|e| format!("kvm-rdp: {e}"))?;
    Config::load(&path).map_err(|e| format!("kvm-rdp: {}: {e}", path.display()))
}

/// `"250ms"`, `"1.6s"`, `"10s"`: a non-negative number of ms or s, ≤ 1 h.
#[must_use]
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    let (num, scale) = if let Some(n) = s.strip_suffix("ms") {
        (n, 0.001)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1.0)
    } else {
        return None;
    };
    let v: f64 = num.trim().parse().ok()?;
    let secs = v * scale;
    if !secs.is_finite() || secs < 0.0 || secs > MAX_DURATION.as_secs_f64() {
        return None;
    }
    Some(Duration::from_secs_f64(secs))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct Raw {
    rdp: RawRdp,
    admin: RawAdmin,
    kvm: RawKvm,
    video: RawVideo,
    input: RawInput,
    paste: RawPaste,
    security: RawSecurity,
    log: RawLog,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct RawRdp {
    listen: Option<String>,
    username: Option<String>,
    nla_password_file: Option<PathBuf>,
    tls_cert_file: Option<PathBuf>,
    tls_key_file: Option<PathBuf>,
    cert_poll_interval: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct RawAdmin {
    listen: Option<String>,
    liveness_timeout: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct RawBackoff {
    initial: Option<String>,
    factor: Option<u32>,
    max: Option<String>,
    jitter_percent: Option<u32>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct RawKvm {
    host: Option<String>,
    spki_sha256: Option<String>,
    scheme: Option<String>,
    web_port: Option<u16>,
    video_port: Option<u16>,
    control_port: Option<u16>,
    password_file: Option<PathBuf>,
    connect_timeout: Option<String>,
    login_timeout: Option<String>,
    backoff: RawBackoff,
    upstream_deadline: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct RawVideo {
    default_size: Option<String>,
    max_fps: Option<u32>,
    soft_gate: Option<String>,
    hard_cap: Option<String>,
    backlog_limit: Option<u64>,
    standing_delay_limit: Option<String>,
    rtt_probe_interval: Option<String>,
    first_ack_grace: Option<String>,
    stall_timeout: Option<String>,
    idr_policy: Option<String>,
    idr_side_timeout: Option<String>,
    idr_wait_max: Option<String>,
    flv_reconnect_interval_setup: Option<String>,
    flv_reconnect_interval_flow: Option<String>,
    flv_idle_timeout: Option<String>,
    burst_chunk: Option<u32>,
    sps_rewrite: Option<Vec<String>>,
    avc420_timeout: Option<String>,
    suppress_debounce: Option<String>,
    disconnect_watchdog: Option<String>,
    region_qp: Option<u8>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct RawInput {
    queue: Option<usize>,
    hid_write_timeout: Option<String>,
    key_repeat_timeout: Option<String>,
    modifier_idle_timeout: Option<String>,
    mac_remap: Option<bool>,
    reassert_after: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct RawPaste {
    chord: Option<String>,
    pace: Option<String>,
    max_chars: Option<usize>,
    max_bytes: Option<usize>,
    modifier_wait: Option<String>,
    multiline: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct RawSecurity {
    accept_rate: Option<u32>,
    accept_window: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
struct RawLog {
    filter: Option<String>,
}

fn dur(v: Option<&String>, default: Duration, key: &str) -> Result<Duration, ConfigError> {
    let d = match v {
        None => default,
        Some(s) => parse_duration(s).ok_or_else(|| {
            // Named, not quoted: a config error never echoes the file (I1).
            invalid(format!(
                "{key} is not a duration like \"250ms\" or \"1.6s\" (at most 1 h)"
            ))
        })?,
    };
    if d.is_zero() {
        return Err(invalid(format!("{key} must be more than zero")));
    }
    Ok(d)
}

fn dur_or_zero(v: Option<&String>, default: Duration, key: &str) -> Result<Duration, ConfigError> {
    match v {
        None => Ok(default),
        Some(s) => parse_duration(s).ok_or_else(|| invalid(format!("{key} is not a duration"))),
    }
}

fn addr(v: Option<&String>, default: &str, key: &str) -> Result<SocketAddr, ConfigError> {
    v.map_or(default, String::as_str)
        .parse()
        .map_err(|_| invalid(format!("{key} must be an ip:port")))
}

fn ranged<T: PartialOrd + Copy + fmt::Display>(
    v: Option<T>,
    default: T,
    lo: T,
    hi: T,
    key: &str,
) -> Result<T, ConfigError> {
    let x = v.unwrap_or(default);
    if x < lo || x > hi {
        return Err(invalid(format!("{key} must be between {lo} and {hi}")));
    }
    Ok(x)
}

fn size(v: Option<&String>) -> Result<(u16, u16), ConfigError> {
    let Some(s) = v else { return Ok((1920, 1080)) };
    let bad = || invalid("video.default_size must be WIDTHxHEIGHT, even, 16..=4096 × 16..=2304");
    let (w, h) = s.split_once('x').ok_or_else(bad)?;
    let w: u16 = w.trim().parse().map_err(|_| bad())?;
    let h: u16 = h.trim().parse().map_err(|_| bad())?;
    if !(16..=4096).contains(&w)
        || !(16..=2304).contains(&h)
        || !w.is_multiple_of(2)
        || !h.is_multiple_of(2)
    {
        return Err(bad());
    }
    Ok((w, h))
}

fn required_path(v: Option<PathBuf>, key: &str) -> Result<PathBuf, ConfigError> {
    v.ok_or_else(|| invalid(format!("{key} is required")))
}

/// A secret file: ≤ 4 KiB, UTF-8, exactly one trailing `\n` or `\r\n`
/// removed, not empty after that. Read through a hard cap (one byte past
/// the limit) rather than trusting `metadata().len()`, which a FIFO or a
/// file growing underneath us would not bound (P16). An error names `key`,
/// never the path (C1): the value may be the secret itself.
fn read_secret(base: &Path, rel: &Path, key: &'static str) -> Result<Secret, ConfigError> {
    let unreadable = |e: std::io::Error| ConfigError::File {
        key,
        kind: e.kind(),
    };
    let mut bytes = Vec::new();
    std::fs::File::open(base.join(rel))
        .map_err(unreadable)?
        .take(MAX_SECRET_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(unreadable)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_SECRET_FILE {
        return Err(invalid(format!("{key}: larger than 4 KiB")));
    }
    let text = String::from_utf8(bytes).map_err(|_| invalid(format!("{key}: not UTF-8")))?;
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(&text);
    if text.is_empty() {
        return Err(invalid(format!("{key}: empty")));
    }
    Ok(Secret(text.to_owned()))
}

fn build(raw: Raw, base: &Path) -> Result<Config, ConfigError> {
    let ms = Duration::from_millis;
    let s = Duration::from_secs;

    let username = raw.rdp.username.unwrap_or_else(|| "kvm".to_owned());
    if username.is_empty() {
        return Err(invalid("rdp.username must not be empty"));
    }
    let nla_password = read_secret(
        base,
        &required_path(raw.rdp.nla_password_file, "rdp.nla_password_file")?,
        "rdp.nla_password_file",
    )?;
    if nla_password.expose().chars().count() < MIN_NLA_PASSWORD {
        return Err(invalid(
            "rdp.nla_password_file: at least 22 characters (128 random bits, §9.1)",
        ));
    }
    let rdp = RdpConfig {
        listen: addr(raw.rdp.listen.as_ref(), "0.0.0.0:3389", "rdp.listen")?,
        username,
        nla_password,
        tls_cert_file: base.join(required_path(raw.rdp.tls_cert_file, "rdp.tls_cert_file")?),
        tls_key_file: base.join(required_path(raw.rdp.tls_key_file, "rdp.tls_key_file")?),
        cert_poll_interval: dur(
            raw.rdp.cert_poll_interval.as_ref(),
            s(60),
            "rdp.cert_poll_interval",
        )?,
    };
    let admin = AdminConfig {
        listen: addr(raw.admin.listen.as_ref(), "0.0.0.0:9464", "admin.listen")?,
        liveness_timeout: dur(
            raw.admin.liveness_timeout.as_ref(),
            s(10),
            "admin.liveness_timeout",
        )?,
    };

    let host = raw
        .kvm
        .host
        .ok_or_else(|| invalid("kvm.host is required"))?;
    if host.is_empty() || host.contains(|c: char| c.is_whitespace() || c == '/') {
        return Err(invalid("kvm.host must be a bare host name or address"));
    }
    let pin = raw
        .kvm
        .spki_sha256
        .ok_or_else(|| invalid("kvm.spki_sha256 is required"))?;
    if pin.len() != 64 || !pin.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid(
            "kvm.spki_sha256 must be 64 hex digits (kvm-probe fingerprint)",
        ));
    }
    let scheme = match raw.kvm.scheme.as_deref().unwrap_or("https") {
        "https" => Scheme::Https,
        "http" => Scheme::Http,
        _ => return Err(invalid("kvm.scheme must be \"https\" or \"http\"")),
    };
    let (dw, dv, dc) = match scheme {
        Scheme::Https => (443, 8881, 8889),
        Scheme::Http => (80, 8880, 8888),
    };
    let rb = &raw.kvm.backoff;
    let backoff = BackoffConfig {
        initial: dur(rb.initial.as_ref(), ms(250), "kvm.backoff.initial")?,
        factor: ranged(rb.factor, 2, 1, 16, "kvm.backoff.factor")?,
        max: dur(rb.max.as_ref(), s(8), "kvm.backoff.max")?,
        jitter_percent: ranged(rb.jitter_percent, 20, 0, 50, "kvm.backoff.jitter_percent")?,
    };
    if backoff.initial > backoff.max {
        return Err(invalid(
            "kvm.backoff.initial must not exceed kvm.backoff.max",
        ));
    }
    let kvm = KvmConfig {
        host,
        spki_sha256: pin.to_ascii_lowercase(),
        scheme,
        web_port: raw.kvm.web_port.unwrap_or(dw),
        video_port: raw.kvm.video_port.unwrap_or(dv),
        control_port: raw.kvm.control_port.unwrap_or(dc),
        password: read_secret(
            base,
            &required_path(raw.kvm.password_file, "kvm.password_file")?,
            "kvm.password_file",
        )?,
        connect_timeout: dur(
            raw.kvm.connect_timeout.as_ref(),
            s(3),
            "kvm.connect_timeout",
        )?,
        login_timeout: dur(raw.kvm.login_timeout.as_ref(), s(5), "kvm.login_timeout")?,
        backoff,
        upstream_deadline: dur(
            raw.kvm.upstream_deadline.as_ref(),
            s(20),
            "kvm.upstream_deadline",
        )?,
    };

    let rv = &raw.video;
    let idr_policy = match rv.idr_policy.as_deref().unwrap_or("side") {
        "side" => IdrPolicy::Side,
        "reconnect" => IdrPolicy::Reconnect,
        "wait" => IdrPolicy::Wait,
        _ => return Err(invalid("video.idr_policy must be side, reconnect or wait")),
    };
    let mut sps_rewrite = SpsRewrite::default();
    let names = rv
        .sps_rewrite
        .clone()
        .unwrap_or_else(|| vec!["level".into(), "vui".into(), "restriction".into()]);
    for name in &names {
        match name.as_str() {
            "level" => sps_rewrite.level = true,
            "vui" => sps_rewrite.vui = true,
            "restriction" => sps_rewrite.restriction = true,
            _ => {
                return Err(invalid(
                    "video.sps_rewrite holds only level, vui, restriction",
                ));
            }
        }
    }
    // §6.8: the rewrite is required, never pass-through — without `level`
    // every ES3 session would end `stream_incompatible` with nothing at
    // startup to say why. The key stays (§4.4) but must name all three.
    if !(sps_rewrite.level && sps_rewrite.vui && sps_rewrite.restriction) {
        return Err(invalid(
            "video.sps_rewrite must hold level, vui and restriction (§6.8: the rewrite is required)",
        ));
    }
    let video = VideoConfig {
        default_size: size(rv.default_size.as_ref())?,
        max_fps: ranged(rv.max_fps, 30, 1, 60, "video.max_fps")?,
        soft_gate: dur(rv.soft_gate.as_ref(), ms(500), "video.soft_gate")?,
        hard_cap: dur(rv.hard_cap.as_ref(), s(2), "video.hard_cap")?,
        backlog_limit: ranged(rv.backlog_limit, 4 << 20, 1, 1 << 30, "video.backlog_limit")?,
        standing_delay_limit: dur(
            rv.standing_delay_limit.as_ref(),
            ms(500),
            "video.standing_delay_limit",
        )?,
        rtt_probe_interval: dur(
            rv.rtt_probe_interval.as_ref(),
            ms(250),
            "video.rtt_probe_interval",
        )?,
        first_ack_grace: dur(
            rv.first_ack_grace.as_ref(),
            ms(1600),
            "video.first_ack_grace",
        )?,
        stall_timeout: dur(rv.stall_timeout.as_ref(), s(10), "video.stall_timeout")?,
        idr_policy,
        idr_side_timeout: dur(rv.idr_side_timeout.as_ref(), s(1), "video.idr_side_timeout")?,
        idr_wait_max: dur(rv.idr_wait_max.as_ref(), s(3), "video.idr_wait_max")?,
        flv_reconnect_interval_setup: dur(
            rv.flv_reconnect_interval_setup.as_ref(),
            s(1),
            "video.flv_reconnect_interval_setup",
        )?,
        flv_reconnect_interval_flow: dur(
            rv.flv_reconnect_interval_flow.as_ref(),
            s(10),
            "video.flv_reconnect_interval_flow",
        )?,
        flv_idle_timeout: dur(
            rv.flv_idle_timeout.as_ref(),
            s(10),
            "video.flv_idle_timeout",
        )?,
        burst_chunk: ranged(rv.burst_chunk, 8, 1, 64, "video.burst_chunk")?,
        sps_rewrite,
        avc420_timeout: dur(rv.avc420_timeout.as_ref(), s(10), "video.avc420_timeout")?,
        suppress_debounce: dur(
            rv.suppress_debounce.as_ref(),
            s(1),
            "video.suppress_debounce",
        )?,
        disconnect_watchdog: dur(
            rv.disconnect_watchdog.as_ref(),
            s(5),
            "video.disconnect_watchdog",
        )?,
        region_qp: ranged(rv.region_qp, 22, 0, 51, "video.region_qp")?,
    };
    if !(1..=4096).contains(&video.hard_cap_frames()) {
        return Err(invalid(
            "video.hard_cap × video.max_fps must be 1..=4096 frames",
        ));
    }

    let ri = &raw.input;
    let input = InputConfig {
        // PD9 carry 5 (PD7 m4): room for the Typist's 8 reports a step and
        // typing's start one more (DD6), or typing overflows into a resync.
        queue: ranged(
            ri.queue,
            256,
            crate::input::paste::TYPIST_ROOM.saturating_add(1),
            4096,
            "input.queue",
        )?,
        hid_write_timeout: dur(
            ri.hid_write_timeout.as_ref(),
            s(1),
            "input.hid_write_timeout",
        )?,
        key_repeat_timeout: dur(
            ri.key_repeat_timeout.as_ref(),
            s(10),
            "input.key_repeat_timeout",
        )?,
        modifier_idle_timeout: dur(
            ri.modifier_idle_timeout.as_ref(),
            s(30),
            "input.modifier_idle_timeout",
        )?,
        mac_remap: ri.mac_remap.unwrap_or(false),
        reassert_after: dur(ri.reassert_after.as_ref(), s(1), "input.reassert_after")?,
    };
    let rp = &raw.paste;
    // DD11: one or more distinct modifiers, then one letter or digit. The
    // message is fixed: it never echoes the value (C1).
    let chord_text = rp.chord.as_deref().unwrap_or("ctrl+option+shift+v");
    let chord = kvm_proto::keymap::Chord::parse(chord_text).ok_or_else(|| {
        invalid(
            "paste.chord must be one or more modifiers (ctrl/shift/alt/option/cmd/win) \
             then one letter or digit, e.g. \"ctrl+option+shift+v\"",
        )
    })?;
    let paste = PasteConfig {
        chord,
        pace: dur_or_zero(rp.pace.as_ref(), ms(15), "paste.pace")?,
        max_chars: ranged(rp.max_chars, 4096, 1, 1 << 20, "paste.max_chars")?,
        max_bytes: ranged(rp.max_bytes, 64 << 10, 1, 16 << 20, "paste.max_bytes")?,
        modifier_wait: dur(rp.modifier_wait.as_ref(), s(5), "paste.modifier_wait")?,
        multiline: match rp.multiline.as_deref().unwrap_or("enter") {
            "enter" => Multiline::Enter,
            "refuse" => Multiline::Refuse,
            _ => return Err(invalid("paste.multiline must be enter or refuse")),
        },
    };
    let security = SecurityConfig {
        accept_rate: ranged(
            raw.security.accept_rate,
            30,
            1,
            10_000,
            "security.accept_rate",
        )?,
        accept_window: dur(
            raw.security.accept_window.as_ref(),
            s(60),
            "security.accept_window",
        )?,
    };
    let log = LogConfig {
        filter: raw.log.filter.unwrap_or_else(|| "info".to_owned()),
    };
    Ok(Config {
        rdp,
        admin,
        kvm,
        video,
        input,
        paste,
        security,
        log,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]
    use super::*;
    use std::path::Path;

    const PIN: &str = "F94841875EC7FA56220D48FFADAA5C0F2D84FFBBD1BEEB060245DED1419B614F";
    const NLA: &str = "0123456789abcdefghijklmnop";

    fn write(dir: &Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).unwrap();
    }

    /// The four secret files and the smallest valid config.
    fn minimal(dir: &Path) -> String {
        write(dir, "kvm.pass", "kvm-secret\n");
        write(dir, "nla.pass", &format!("{NLA}\n"));
        write(dir, "cert.pem", "not read by config\n");
        write(dir, "key.pem", "not read by config\n");
        format!(
            "[rdp]\nnla_password_file = \"nla.pass\"\ntls_cert_file = \"cert.pem\"\n\
             tls_key_file = \"key.pem\"\n[kvm]\nhost = \"192.168.0.50\"\n\
             spki_sha256 = \"{PIN}\"\npassword_file = \"kvm.pass\"\n"
        )
    }

    fn load(dir: &Path, toml: &str) -> Result<Config, ConfigError> {
        Config::from_toml(toml, dir)
    }

    #[test]
    fn defaults_match_the_spec_table() {
        let d = tempfile::tempdir().unwrap();
        let c = load(d.path(), &minimal(d.path())).unwrap();
        let s = Duration::from_secs;
        let ms = Duration::from_millis;
        assert_eq!(c.rdp.listen.to_string(), "0.0.0.0:3389");
        assert_eq!(c.rdp.username, "kvm");
        assert_eq!(c.rdp.cert_poll_interval, s(60));
        assert_eq!(c.admin.listen.to_string(), "0.0.0.0:9464");
        assert_eq!(c.admin.liveness_timeout, s(10));
        assert_eq!(c.kvm.spki_sha256, PIN.to_ascii_lowercase());
        assert_eq!(c.kvm.scheme, Scheme::Https);
        assert_eq!(
            (c.kvm.web_port, c.kvm.video_port, c.kvm.control_port),
            (443, 8881, 8889)
        );
        assert_eq!((c.kvm.connect_timeout, c.kvm.login_timeout), (s(3), s(5)));
        assert_eq!(
            c.kvm.backoff,
            BackoffConfig {
                initial: ms(250),
                factor: 2,
                max: s(8),
                jitter_percent: 20
            }
        );
        assert_eq!(c.kvm.upstream_deadline, s(20));
        let v = &c.video;
        assert_eq!((v.default_size, v.max_fps), ((1920, 1080), 30));
        assert_eq!(
            (v.soft_gate, v.hard_cap, v.backlog_limit),
            (ms(500), s(2), 4 << 20)
        );
        assert_eq!(v.hard_cap_frames(), 60);
        assert_eq!(
            (v.standing_delay_limit, v.rtt_probe_interval),
            (ms(500), ms(250))
        );
        assert_eq!((v.first_ack_grace, v.stall_timeout), (ms(1600), s(10)));
        assert_eq!(
            (v.idr_policy, v.idr_side_timeout, v.idr_wait_max),
            (IdrPolicy::Side, s(1), s(3))
        );
        assert_eq!(
            (
                v.flv_reconnect_interval_setup,
                v.flv_reconnect_interval_flow
            ),
            (s(1), s(10))
        );
        assert_eq!((v.flv_idle_timeout, v.burst_chunk), (s(10), 8));
        assert_eq!(
            v.sps_rewrite,
            SpsRewrite {
                level: true,
                vui: true,
                restriction: true
            }
        );
        assert_eq!(
            (v.avc420_timeout, v.suppress_debounce, v.disconnect_watchdog),
            (s(10), s(1), s(5))
        );
        assert_eq!(v.region_qp, 22);
        assert_eq!(v.admission().rewrite, RewriteConfig::ES3);
        let i = &c.input;
        assert_eq!(
            (i.queue, i.hid_write_timeout, i.key_repeat_timeout),
            (256, s(1), s(10))
        );
        assert_eq!((i.modifier_idle_timeout, i.mac_remap), (s(30), false));
        // Task 4.2 (DD8): 1 s until L4 retunes it (Task 6.1).
        assert_eq!(i.reassert_after, s(1));
        let p = &c.paste;
        assert_eq!(
            (p.chord, p.pace, p.max_chars),
            (
                kvm_proto::keymap::Chord::parse("ctrl+option+shift+v").unwrap(),
                ms(15),
                4096
            )
        );
        assert_eq!(
            (p.max_bytes, p.modifier_wait, p.multiline),
            (64 << 10, s(5), Multiline::Enter)
        );
        assert_eq!(
            (c.security.accept_rate, c.security.accept_window),
            (30, s(60))
        );
        assert_eq!(c.log.filter, "info");
        assert_eq!(c.kvm.password.expose(), "kvm-secret");
        assert_eq!(c.rdp.nla_password.expose(), NLA);
    }

    /// DD11: `paste.chord` is parsed at load — one or more distinct
    /// modifiers, then one letter or digit. A chord with no modifier would
    /// swallow plain typing; one that cannot parse would never fire.
    #[test]
    fn the_paste_chord_parses_at_load() {
        let d = tempfile::tempdir().unwrap();
        let c = load(d.path(), &minimal(d.path())).unwrap();
        assert_eq!(
            c.paste.chord,
            kvm_proto::keymap::Chord::parse("ctrl+option+shift+v").unwrap()
        );
        let bad = format!("{}[paste]\nchord = \"v\"\n", minimal(d.path()));
        assert!(load(d.path(), &bad).is_err(), "a chord with no modifier");
        // Beyond the plan's listing: any spelling Chord::parse takes loads;
        // anything else is the fixed rule message, never the value.
        let with = |chord: &str| format!("{}[paste]\nchord = \"{chord}\"\n", minimal(d.path()));
        let c = load(d.path(), &with("Cmd + 1")).unwrap();
        assert_eq!(
            c.paste.chord,
            kvm_proto::keymap::Chord::parse("cmd+1").unwrap()
        );
        for bad in ["", "ctrl+ctrl+v", "ctrl+f1", "ctrl+", "shift+ctrl"] {
            let e = load(d.path(), &with(bad)).unwrap_err().to_string();
            assert!(
                e.starts_with("invalid config: paste.chord must be"),
                "{bad:?}: {e}"
            );
        }
    }

    /// Review Focus 2: `echo` adds `\n`, Windows adds `\r\n`; exactly one
    /// line ending goes, everything else (spaces too) stays.
    #[test]
    fn secret_files_lose_one_line_ending_only() {
        let d = tempfile::tempdir().unwrap();
        let toml = minimal(d.path());
        for (body, want) in [
            ("kvm-secret\n", "kvm-secret"),
            ("kvm-secret\r\n", "kvm-secret"),
            ("kvm-secret", "kvm-secret"),
            (" spaced secret \n", " spaced secret "),
            ("two\n\n", "two\n"),
        ] {
            write(d.path(), "kvm.pass", body);
            assert_eq!(
                load(d.path(), &toml).unwrap().kvm.password.expose(),
                want,
                "{body:?}"
            );
        }
        write(d.path(), "kvm.pass", "\n");
        assert!(matches!(
            load(d.path(), &toml),
            Err(ConfigError::Invalid(_))
        ));
        write(d.path(), "kvm.pass", &"x".repeat(5000));
        assert!(matches!(
            load(d.path(), &toml),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn relative_secret_paths_resolve_against_the_config_directory() {
        let d = tempfile::tempdir().unwrap();
        let toml = minimal(d.path());
        let file = d.path().join("kvm-rdp.toml");
        std::fs::write(&file, toml).unwrap();
        assert_eq!(
            Config::load(&file).unwrap().kvm.password.expose(),
            "kvm-secret"
        );
        let missing = Config::load(&d.path().join("absent.toml"));
        assert!(matches!(missing, Err(ConfigError::Read { .. })));
    }

    #[test]
    fn bad_values_are_refused_before_anything_binds() {
        let d = tempfile::tempdir().unwrap();
        let base = minimal(d.path());
        for (extra, what) in [
            ("[video]\nbogus = 1\n", "unknown key"),
            ("[video]\nsoft_gate = \"10000000s\"\n", "duration above 1 h"),
            ("[video]\nsoft_gate = \"fast\"\n", "duration syntax"),
            ("[video]\nstall_timeout = \"0s\"\n", "zero duration"),
            ("[video]\nregion_qp = 52\n", "QP above 51"),
            ("[video]\ndefault_size = \"1921x1080\"\n", "odd width"),
            ("[video]\nidr_policy = \"magic\"\n", "unknown policy"),
            (
                "[video]\nsps_rewrite = [\"level\", \"colour\"]\n",
                "unknown rewrite",
            ),
            (
                "[video]\nsps_rewrite = [\"vui\", \"restriction\"]\n",
                "rewrite without level",
            ),
            ("[video]\nsps_rewrite = []\n", "no rewrite"),
            ("[video]\nmax_fps = 0\n", "zero fps"),
            ("[input]\nqueue = 0\n", "empty HID queue"),
            // PD9 carry 5 (PD7 m4): the Typist takes up to 8 reports a
            // step and typing's start one more (DD6).
            ("[input]\nqueue = 8\n", "an HID queue below DD6's 9"),
            (
                "[input]\nreassert_after = \"0s\"\n",
                "a zero re-assert wait",
            ),
            (
                "[input]\nreassert_after = \"7200s\"\n",
                "a re-assert wait above 1 h",
            ),
        ] {
            let r = load(d.path(), &format!("{base}{extra}"));
            assert!(
                matches!(r, Err(ConfigError::Invalid(_) | ConfigError::Parse { .. })),
                "{what}: {r:?}"
            );
        }
        let swap = |from: &str, to: &str| load(d.path(), &base.replace(from, to));
        assert!(
            swap("host = \"192.168.0.50\"\n", "").is_err(),
            "missing kvm.host"
        );
        assert!(swap(PIN, "abcd").is_err(), "short pin");
        assert!(
            swap("[kvm]\n", "[kvm]\nscheme = \"ftp\"\n").is_err(),
            "scheme"
        );
        // DD6's least queue loads, and the message names the bound only.
        assert_eq!(
            load(d.path(), &format!("{base}[input]\nqueue = 9\n"))
                .unwrap()
                .input
                .queue,
            9
        );
        assert_eq!(
            load(d.path(), &format!("{base}[input]\nqueue = 8\n"))
                .unwrap_err()
                .to_string(),
            "invalid config: input.queue must be between 9 and 4096"
        );
        write(d.path(), "nla.pass", "short\n");
        assert!(
            load(d.path(), &base).is_err(),
            "NLA password under 22 characters"
        );
    }

    #[test]
    fn secrets_never_show_in_debug() {
        let d = tempfile::tempdir().unwrap();
        let c = load(d.path(), &minimal(d.path())).unwrap();
        let shown = format!("{c:?}");
        assert!(
            !shown.contains("kvm-secret") && !shown.contains(NLA),
            "{shown}"
        );
        assert!(shown.contains("Secret(<redacted>)"));
    }

    #[test]
    fn durations_parse_and_are_bounded() {
        assert_eq!(parse_duration("250ms"), Some(Duration::from_millis(250)));
        assert_eq!(parse_duration("1.6s"), Some(Duration::from_millis(1600)));
        assert_eq!(parse_duration(" 10s "), Some(Duration::from_secs(10)));
        assert_eq!(parse_duration("3600s"), Some(MAX_DURATION));
        for bad in ["3601s", "-1s", "1h", "s", "", "NaNs", "infs"] {
            assert_eq!(parse_duration(bad), None, "{bad}");
        }
    }

    /// What the leak shapes embed: a word; digits (serde echoes integers in
    /// backticks); a date and an invalid date (toml echoes date-times).
    pub(crate) const SENTINELS: [&str; 4] =
        ["SNTL7qZq7vP2", "7531902468", "2975-03-19", "2975-13-45"];

    /// I1 (PC15 re-review): every shape the two reviews probed — a secret
    /// written into the config as a key, a value or a header, in every TOML
    /// syntax, next to a backtick or `, expected `; a secret file passed as
    /// the config; a file that is not UTF-8. `(file bytes, what)`.
    pub(crate) fn leak_shapes(dir: &Path) -> Vec<(Vec<u8>, &'static str)> {
        let [s, n, d, bad_date] = SENTINELS;
        let base = minimal(dir);
        let rdp = |line: String| base.replace("[rdp]\n", &format!("[rdp]\n{line}\n"));
        let kvm = |line: String| base.replace("[kvm]\n", &format!("[kvm]\n{line}\n"));
        let admin = |line: String| format!("{base}[admin]\n{line}\n");
        let video = |line: String| format!("{base}[video]\n{line}\n");
        // A `*_file` key's own line rewritten in place: a second one would be
        // a duplicate-key error that never reaches the read.
        let file = |line: &str, value: String| {
            let (key, _) = line.split_once(" = ").unwrap();
            assert!(base.contains(line), "minimal() has no {line}");
            base.replace(line, &format!("{key} = {value}"))
        };
        let t = |text: String, what: &'static str| (text.into_bytes(), what);
        vec![
            // C1 (final review): a secret written where a file name goes —
            // every `*_file` key; a TLS key path may be a pasted PEM. The
            // TLS pair is read at startup, not by the loader (§4.4), so
            // those three shapes load and fail in `tls::load`.
            t(
                file("nla_password_file = \"nla.pass\"", format!("\"{s}\"")),
                "an inline NLA password as rdp.nla_password_file",
            ),
            t(
                file("password_file = \"kvm.pass\"", format!("\"{s}\"")),
                "an inline KVM password as kvm.password_file",
            ),
            t(
                file("tls_cert_file = \"cert.pem\"", format!("\"{s}\"")),
                "a secret as rdp.tls_cert_file",
            ),
            t(
                file("tls_key_file = \"key.pem\"", format!("\"{s}\"")),
                "a secret as rdp.tls_key_file",
            ),
            t(
                file(
                    "tls_key_file = \"key.pem\"",
                    format!(
                        "\"\"\"-----BEGIN PRIVATE KEY-----\n{s}\n-----END PRIVATE KEY-----\n\"\"\""
                    ),
                ),
                "a pasted PEM key as rdp.tls_key_file",
            ),
            // The seven the re-review found leaking through fix round 1.
            t(admin(format!("\"a`b {s}\" = 1")), "a key with a backtick"),
            t(
                admin(format!("\"x, expected y {s}\" = 1")),
                "a key holding ', expected '",
            ),
            t(
                kvm(format!("web_port = \"x, expected y {s}\"")),
                "a wrong-typed value holding ', expected '",
            ),
            t(
                kvm(format!("web_port = 'x, expected y {s}'")),
                "the same, as a literal string",
            ),
            t(
                admin(format!("\"`x`, expected `y`, {s}\" = 1")),
                "a key of backticks and ', expected '",
            ),
            t(
                admin(format!("\"a\\\\` {s}\" = 1")),
                "a key with an escaped backslash and a backtick",
            ),
            t(
                admin(format!("\"\\\"`{s}\" = 1")),
                "a key with an escaped quote and a backtick",
            ),
            // A secret file passed as the config.
            t(format!("{s}\n"), "a secret file as the config"),
            t(format!("{s} word two\n"), "a secret file with spaces"),
            // An inline secret under a key the schema refuses.
            t(
                rdp(format!("nla_password = \"{s}\"")),
                "an inline secret, basic string",
            ),
            t(
                rdp(format!("nla_password = '{s}'")),
                "an inline secret, literal string",
            ),
            // Headers.
            t(format!("{base}[{s}]\n"), "a table header"),
            t(format!("{base}[[{s}]]\n"), "an array-of-tables header"),
            t(format!("{base}[{s}\n"), "an unclosed header"),
            t(format!("{base}[\"{s}\"]\n"), "a quoted header"),
            t(
                format!("{base}[rdp]\nlisten = \"{s}\"\n"),
                "a duplicate table",
            ),
            // Keys.
            t(admin(format!("{s} = 1")), "a secret as a key"),
            t(admin(format!("{s} =")), "a key with no value"),
            t(admin(format!("a.{s} = 1")), "a dotted key"),
            t(admin(format!("{n} = 1")), "an integer-looking key"),
            t(admin(format!("\"{s}\\\"q\" = 1")), "a key holding a quote"),
            t(
                admin(format!("\"{s}\\nx\" = 1")),
                "a key holding a newline escape",
            ),
            // Values.
            t(admin(format!("listen = {s}")), "a bare-word value"),
            t(
                kvm(format!("web_port = {n}{s}")),
                "an integer-looking value",
            ),
            t(
                rdp(format!("username = {n}")),
                "an integer where a string goes",
            ),
            t(kvm(format!("web_port = {n}{n}{n}")), "an integer overflow"),
            t(kvm(format!("web_port = {n}")), "a port out of range"),
            t(
                kvm(format!("web_port = {d}T02:46:51Z")),
                "an offset date-time",
            ),
            t(kvm(format!("web_port = {d}")), "a local date"),
            t(kvm(format!("web_port = 02:46:51.{n}")), "a local time"),
            t(kvm(format!("web_port = {bad_date}")), "an invalid date"),
            t(
                kvm(format!("web_port = \"\"\"{s}\nline\"\"\"")),
                "a multi-line basic string",
            ),
            t(
                kvm(format!("web_port = '''{s}\nline'''")),
                "a multi-line literal string",
            ),
            t(kvm(format!("web_port = \"{s}")), "an unterminated string"),
            t(
                kvm(format!("web_port = \"\"\"{s}")),
                "an unterminated multi-line string",
            ),
            t(
                kvm(format!("web_port = '{s}\\\"'")),
                "a literal string holding \\\"",
            ),
            t(kvm(format!("web_port = [\"{s}\"]")), "an array of strings"),
            t(kvm(format!("web_port = [{s}]")), "an array of bare words"),
            t(kvm(format!("web_port = [1, \"{s}\"]")), "a mixed array"),
            t(
                kvm(format!("web_port = {{ {s} = 1 }}")),
                "an inline table keyed by the secret",
            ),
            t(
                rdp(format!("username = {{ x = \"{s}\" }}")),
                "an inline table where a string goes",
            ),
            t(kvm(format!("web_port = \"\\q{s}\"")), "an invalid escape"),
            t(
                kvm(format!("web_port = \"{s}\u{1}\"")),
                "a control character",
            ),
            t(kvm(format!("web_port = 1.5{s}")), "a float with a suffix"),
            t(
                kvm(format!("web_port = {n}.5")),
                "a float where a port goes",
            ),
            // Validation, after the parse.
            t(kvm(format!("scheme = \"{s}\"")), "a bad scheme"),
            t(
                video(format!("idr_side_timeout = \"{s}\"")),
                "a bad duration",
            ),
            t(format!("{base}[paste]\npace = \"{s}\"\n"), "a bad pace"),
            // PD9 carry 5 (C1 rule): `input.queue`'s bound changed.
            t(
                format!("{base}[input]\nqueue = {n}\n"),
                "an input.queue out of range",
            ),
            // Task 4.2 (D10a, C1 rule): the new key.
            t(
                format!("{base}[input]\nreassert_after = \"{s}\"\n"),
                "a bad reassert_after",
            ),
            // DD11 (PD7, C1 rule): `paste.chord` is a validated value now.
            t(format!("{base}[paste]\nchord = \"{s}\"\n"), "a bad chord"),
            t(
                format!("{base}[paste]\nchord = \"ctrl+{s}\"\n"),
                "a chord whose key is a word",
            ),
            t(
                format!("{base}[paste]\nchord = \"{s}+v\"\n"),
                "a chord whose modifier is a word",
            ),
            t(
                format!("{base}[paste]\nchord = {n}\n"),
                "a number where a chord goes",
            ),
            t(
                video(format!("default_size = \"{s}\"")),
                "a bad default size",
            ),
            t(
                video(format!("sps_rewrite = [\"{s}\"]")),
                "a bad SPS rewrite",
            ),
            // Not UTF-8.
            (
                [
                    format!("{base}[admin]\nlisten = \"").as_bytes(),
                    b"\xff\xfe",
                    s.as_bytes(),
                    b"\"\n",
                ]
                .concat(),
                "a file that is not UTF-8",
            ),
            // Over the 1 MiB cap: refused before it is parsed.
            t(s.repeat((2 << 20) / s.len()), "a file over 1 MiB"),
        ]
    }

    /// How many of `leak_shapes` load: the TLS file shapes, whose error
    /// comes from `tls::load` at startup.
    pub(crate) const STARTUP_SHAPES: usize = 3;

    /// I1 (PC15 review and re-review; §4.4, §9.2): a config error never
    /// echoes the file. For every shape above, no sentinel reaches the
    /// error's `Display` or `Debug` — nor, for a shape that loads (a TLS
    /// file key, C1), the config's `Debug` and the startup error the bridge
    /// stops on (the binary's stderr and log are pinned through the
    /// binary's own body in `cli`).
    #[test]
    fn config_errors_never_echo_the_file() {
        let d = tempfile::tempdir().unwrap();
        let shapes = leak_shapes(d.path());
        assert!(shapes.len() >= 40, "{} shapes", shapes.len());
        let toml = d.path().join("kvm-rdp.toml");
        let mut leaks = Vec::new();
        let mut loaded = 0;
        for (bytes, what) in &shapes {
            std::fs::write(&toml, bytes).unwrap();
            let shown = match Config::load(&toml) {
                Err(e) => {
                    if let ConfigError::Parse { what: category, .. } = e {
                        assert!(PARSE_CATEGORIES.contains(&category), "{what}: {category}");
                    }
                    format!("{e} | {e:?}")
                }
                Ok(c) => {
                    loaded += 1;
                    let e = crate::rdp::tls::load(&c.rdp.tls_cert_file, &c.rdp.tls_key_file)
                        .err()
                        .expect(what);
                    let e = crate::bridge::BridgeError::Tls(e);
                    format!("{c:?} | {e} | {e:?}")
                }
            };
            if SENTINELS.iter().any(|s| shown.contains(s)) {
                leaks.push(format!("{what}: {shown}"));
            }
        }
        assert!(
            leaks.is_empty(),
            "{}/{} shapes leaked:\n{}",
            leaks.len(),
            shapes.len(),
            leaks.join("\n")
        );
        assert_eq!(loaded, STARTUP_SHAPES, "only the TLS file shapes load");
    }

    /// C1 (final review; §4.4, §9.2): a secret file that cannot be read is
    /// named by its key, with the I/O kind — never by its value, which may
    /// be the secret itself written where the file name goes. One that is
    /// not UTF-8 is named so.
    #[test]
    fn an_unreadable_secret_file_is_named_by_its_key() {
        let d = tempfile::tempdir().unwrap();
        let base = minimal(d.path());
        for (from, key) in [
            ("\"nla.pass\"", "rdp.nla_password_file"),
            ("\"kvm.pass\"", "kvm.password_file"),
        ] {
            let e = load(d.path(), &base.replace(from, "\"absent.pass\"")).unwrap_err();
            assert_eq!(
                e.to_string(),
                format!("{key}: cannot read the file: entity not found")
            );
            assert!(!format!("{e:?}").contains("absent"), "{e:?}");
        }
        std::fs::write(d.path().join("kvm.pass"), b"\xff\xfe-not-utf8\n").unwrap();
        let e = load(d.path(), &base).unwrap_err();
        assert_eq!(
            e.to_string(),
            "invalid config: kvm.password_file: not UTF-8"
        );
    }

    /// PC15 re-review minor: the config file is read through a 1 MiB cap —
    /// a bigger one is refused unparsed ("file too large"), so a wrong path
    /// such as /dev/zero cannot exhaust memory — and one that is not UTF-8
    /// is named so, with no byte of it shown.
    #[test]
    fn the_config_read_is_capped_and_must_be_utf8() {
        let d = tempfile::tempdir().unwrap();
        let toml = d.path().join("kvm-rdp.toml");
        std::fs::write(&toml, "#".repeat(2 << 20)).unwrap();
        assert!(
            matches!(
                Config::load(&toml),
                Err(ConfigError::Parse {
                    at: None,
                    what: "file too large"
                })
            ),
            "a 2 MiB config was read"
        );
        // An endless file: the cap ends the read (unbounded, this test
        // would run out of memory instead of failing).
        assert!(matches!(
            Config::load(Path::new("/dev/zero")),
            Err(ConfigError::Parse {
                at: None,
                what: "file too large"
            })
        ));
        assert_eq!(MAX_CONFIG, 1 << 20);
        std::fs::write(&toml, b"[rdp]\nusername = \"\xff\"\n").unwrap();
        assert!(matches!(
            Config::load(&toml),
            Err(ConfigError::Parse {
                at: None,
                what: "not UTF-8"
            })
        ));
    }

    /// I1: the category is picked from toml's and serde's leading words —
    /// never their text — and anything unrecognised is a syntax error.
    #[test]
    fn a_parse_error_is_named_by_its_category() {
        let d = tempfile::tempdir().unwrap();
        let base = minimal(d.path());
        for (extra, want) in [
            ("[admin]\nnla_password = 1\n", "unknown key"),
            ("[admin]\nlisten = 1\n", "wrong value type"),
            ("[input]\nqueue = -1\n", "wrong value type"),
            ("[video]\nsps_rewrite = \"level\"\n", "wrong value type"),
            ("[rdp]\nlisten = \"127.0.0.1:1\"\n", "duplicate key"),
            ("[admin]\nlisten =\n", "syntax error"),
            ("[admin\n", "syntax error"),
        ] {
            let e = load(d.path(), &format!("{base}{extra}")).unwrap_err();
            assert!(
                matches!(e, ConfigError::Parse { at: Some(_), what } if what == want),
                "{extra:?}: {e:?}"
            );
        }
        assert_eq!(category("missing field `x`"), "missing required key");
        assert_eq!(category("duplicate field `x`"), "duplicate key");
        assert_eq!(
            category("unknown variant `x`, expected `a`"),
            "wrong value type"
        );
        assert_eq!(category("invalid length 3, expected 2"), "wrong value type");
        assert_eq!(category("anything else, expected `=`"), "syntax error");
    }

    /// The parse error's position: 1-based line and column (characters).
    #[test]
    fn a_parse_error_names_its_line_and_column() {
        let d = tempfile::tempdir().unwrap();
        let e = load(d.path(), "[rdp]\n\u{e9}t\u{e9} =\n").unwrap_err();
        assert!(
            matches!(
                &e,
                ConfigError::Parse {
                    at: Some((2, _)),
                    what: "syntax error"
                }
            ),
            "{e:?}"
        );
        assert_eq!(position("ab\ncd\u{e9}f", 7), (2, 4));
        assert_eq!(position("ab", 99), (1, 3));
        assert_eq!(
            position("\u{e9}", 1),
            (1, 1),
            "mid-character offsets round down"
        );
    }

    #[test]
    fn the_config_path_comes_from_the_flag_or_the_variable() {
        use std::ffi::OsString;
        let os = |v: &[&str]| v.iter().map(OsString::from).collect::<Vec<_>>();
        let p = PathBuf::from;
        assert_eq!(
            config_path(os(&["--config", "/a.toml"]), Some("/b.toml".into())).unwrap(),
            p("/a.toml")
        );
        assert_eq!(
            config_path(os(&["--config=/a.toml"]), None).unwrap(),
            p("/a.toml")
        );
        assert_eq!(
            config_path(os(&[]), Some("/b.toml".into())).unwrap(),
            p("/b.toml")
        );
        assert!(config_path(os(&[]), None).is_err());
        assert!(config_path(os(&["--config"]), None).is_err());
        assert!(config_path(os(&["--verbose"]), None).is_err());
    }
}
