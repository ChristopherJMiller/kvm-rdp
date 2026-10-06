//! `kvm-probe` CLI entry point (§12 Leg A). Installing the aws-lc-rs crypto
//! provider is the very first thing this binary does (R20) so every TLS
//! path below has a default provider to use.

use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;

use kvm_probe::captures::{self, CaptureDir};
use kvm_probe::cli::{Cli, Cmd, Conn, Port, SchemeArg};
use kvm_probe::kvm::KvmError;
use kvm_probe::request::{KvmTarget, Scheme};
use kvm_probe::{capture, fingerprint, kvm, report, sandbox, secret, trial, wsprobe};

/// The repo-root `/captures/` directory (gitignored, §11.5) — anchored at
/// build time via `CARGO_MANIFEST_DIR`, never relative to the operator's
/// current directory (I5): a run from any cwd must land captures in the
/// one place `.gitignore`'s anchored `/captures/` actually excludes,
/// exactly as `sandbox.rs`'s `live_sample_range` test is anchored (R12).
const CAPTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../captures");

/// Cap on `summarize`'s JSONL read (I3): large enough for any real
/// capture, but never unbounded.
const SUMMARIZE_MAX_BYTES: usize = 64 * 1024 * 1024;

fn target(conn: &Conn) -> KvmTarget {
    match conn.scheme {
        SchemeArg::Https => KvmTarget {
            scheme: Scheme::Https,
            host: conn.host.clone(),
            login_port: 443,
            video_port: 8881,
            control_port: 8889,
        },
        SchemeArg::Http => KvmTarget {
            scheme: Scheme::Http,
            host: conn.host.clone(),
            login_port: 80,
            video_port: 8880,
            control_port: 8888,
        },
    }
}

/// The KVM password, from `--password-file` only (§9.2), read once per run.
fn password(conn: &Conn) -> Result<String, String> {
    secret::read_password_file(&conn.password_file)
}

/// Log in on the web port, run `work` with the token, then — only when
/// `conn.logout` (`--logout`) is set — log out with it, even if the work
/// failed (final review m1, `kvm::with_session`). Off by default: logout
/// is global on this KVM (R21) and would end every other open session,
/// including the vendor web UI. A failed login is this function's error;
/// a failed logout (only possible with `--logout`) is best effort: printed
/// (escaped and bounded, never the token or device text beyond that) and
/// otherwise ignored.
async fn session<T>(
    conn: &Conn,
    password: &str,
    work: impl AsyncFnOnce(&str) -> T,
) -> Result<T, KvmError> {
    let s = kvm::with_session(
        &target(conn),
        conn.pin_for(Port::Web),
        password,
        unix_now()?,
        kvm::PROBE_TIMEZONE,
        conn.logout,
        work,
    )
    .await?;
    warn_if_logout_failed(&s.logout);
    Ok(s.output)
}

/// Seconds since the Unix epoch, for the login body's `time` field.
fn unix_now() -> Result<i64, KvmError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| KvmError::Io(format!("system clock: {e}")))?;
    i64::try_from(now.as_secs()).map_err(|e| KvmError::Io(e.to_string()))
}

/// A failed logout is best effort (final review m1): one line, escaped and
/// bounded (never the token or device text beyond that), then carry on.
/// `None` means logout was never attempted (the default: no `--logout`) —
/// nothing to warn about.
fn warn_if_logout_failed(logout: &Option<Result<(), KvmError>>) {
    if let Some(Err(e)) = logout {
        eprintln!(
            "kvm-probe: logout failed (best effort, ignored): {}",
            kvm::bounded_debug(e)
        );
    }
}

fn captures_dir() -> Result<CaptureDir, String> {
    CaptureDir::create(Path::new(CAPTURES_DIR)).map_err(|e| format!("{e:?}"))
}

/// Create `<dir>/<name>` for writing, via the same no-clobber,
/// no-symlink-follow, 0600 discipline as every other capture output
/// (`create_new` + `mode(0o600)`; never `File::create`).
fn create_output_file(dir: &CaptureDir, name: &str) -> Result<std::fs::File, String> {
    let path = dir.resolve(name).map_err(|e| format!("{e:?}"))?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))
}

/// Write out and fsync the tag JSONL (final review m6). `into_inner`
/// flushes the buffer and returns its error instead of dropping it.
fn finish_jsonl(jsonl: std::io::BufWriter<std::fs::File>) -> Result<(), String> {
    let file = jsonl
        .into_inner()
        .map_err(|e| format!("writing the tag JSONL: {}", e.error()))?;
    file.sync_all()
        .map_err(|e| format!("syncing the tag JSONL: {e}"))
}

async fn run(cli: Cli) -> Result<(), String> {
    match cli.cmd {
        Cmd::Fingerprint { host, port } => {
            let t = KvmTarget {
                scheme: Scheme::Https,
                host,
                login_port: port,
                video_port: port,
                control_port: port,
            };
            println!(
                "{}",
                fingerprint::observe(&t, port)
                    .await
                    .map_err(|e| format!("{e:?}"))?
            );
        }
        Cmd::Capture {
            conn,
            name,
            seconds,
            max_mb,
        } => {
            let pw = password(&conn)?;
            let t = target(&conn);
            let s = session(
                &conn,
                &pw,
                async |tok: &str| -> Result<capture::Stats, String> {
                    let dir = captures_dir()?;
                    let jsonl_file = create_output_file(&dir, &format!("{name}.jsonl"))?;
                    let mut jsonl = std::io::BufWriter::new(jsonl_file);
                    let stop = capture::StopAt {
                        max_bytes: max_mb.saturating_mul(1024 * 1024),
                        max_duration: Duration::from_secs(seconds),
                    };
                    let result = capture::run(
                        &t,
                        conn.pin_for(Port::Video),
                        tok,
                        &dir,
                        &name,
                        &mut jsonl,
                        stop,
                    )
                    .await
                    .map_err(|e| format!("{e:?}"));
                    // m6: write out and fsync the JSONL on every path, success
                    // or not, and report a failure — never leave it to the
                    // `BufWriter`'s drop, which swallows the error.
                    let finished = finish_jsonl(jsonl);
                    match (result, finished) {
                        (Ok(s), Ok(())) => Ok(s),
                        (Err(e), Ok(())) | (Ok(_), Err(e)) => Err(e),
                        (Err(e), Err(f)) => Err(format!("{e}; and {f}")),
                    }
                },
            )
            .await
            .map_err(|e| format!("{e:?}"))??;
            println!(
                "tags={} bytes={} parse_errors={} first_error={:?}",
                s.tags, s.bytes, s.parse_errors, s.first_error
            );
        }
        Cmd::FirstIdr { conn, trials } => {
            let pw = password(&conn)?;
            let plan = trial::TrialPlan {
                trials,
                timeout: Duration::from_secs(10),
                pause: Duration::from_secs(1),
            };
            // m1 (corrected): ONE login, every trial reopens av.flv on that
            // token. R21: no logout by default (global on this KVM); with
            // `--logout`, ONE best-effort logout at the end. m7: a failed
            // trial is printed with a bounded, escaped reason and the run
            // goes on.
            let s = trial::first_idr_run(
                &target(&conn),
                conn.pin_for(Port::Web),
                conn.pin_for(Port::Video),
                &pw,
                unix_now().map_err(|e| format!("{e:?}"))?,
                &plan,
                conn.logout,
                |n, line| println!("trial {n}/{trials}: {line}"),
            )
            .await
            .map_err(|e| format!("{e:?}"))?;
            warn_if_logout_failed(&s.logout);
            println!("{}", s.output.summary());
            if s.output.all_failed() {
                return Err(format!(
                    "no first-idr trial succeeded ({} of {trials} failed)",
                    s.output.failures.len()
                ));
            }
        }
        Cmd::WsOpen { conn } => {
            let pw = password(&conn)?;
            let t = target(&conn);
            let d = session(&conn, &pw, async |tok: &str| {
                wsprobe::open_control_websocket(&t, conn.pin_for(Port::Control), tok).await
            })
            .await
            .and_then(|opened| opened)
            .map_err(|e| format!("{e:?}"))?;
            println!("websocket upgrade: {} ms", d.as_millis());
        }
        Cmd::SampleRange {
            name,
            width,
            height,
        } => {
            let ffmpeg = sandbox::resolve_ffmpeg().map_err(|e| e.to_string())?;
            let out = sandbox::run_sample_range(&ffmpeg, &captures_dir()?, &name, width, height)
                .map_err(|e| e.to_string())?;
            println!("{out:?}");
        }
        Cmd::Summarize { name } => {
            let dir = captures_dir()?;
            let jsonl_name = format!("{name}.jsonl");
            let path = dir.resolve(&jsonl_name).map_err(|e| format!("{e:?}"))?;
            // I3: never follow a symlink, never block on a FIFO, never
            // buffer past the cap — the captures dir is rw-mounted into
            // the ffmpeg sandbox, so a compromised decode could have
            // planted any entry type at this name.
            let bytes = captures::read_capped(&dir, &jsonl_name, SUMMARIZE_MAX_BYTES)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            let text = String::from_utf8(bytes)
                .map_err(|_| format!("{} is not valid UTF-8", path.display()))?;
            let mut recs = Vec::new();
            for (i, line) in text.lines().enumerate() {
                // M5: name the path and the 1-based line number, not just
                // serde's own ever-"line 1" (each line is parsed on its own).
                let n = i.saturating_add(1);
                let rec: kvm_probe::record::TagRecord = serde_json::from_str(line)
                    .map_err(|e| format!("{}: line {n}: {e}", path.display()))?;
                recs.push(rec);
            }
            println!("{:#?}", report::summarize(&recs));
        }
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cli = Cli::parse();
    // I1: catches `scheme == Https` (explicit or default) without `--pin`
    // — `required_if_eq` alone misses the default-scheme case. `exit()`
    // prints clap's usual usage-error text and exits with its usual code.
    if let Err(e) = cli.validate() {
        e.exit();
    }
    if let Err(e) = run(cli).await {
        eprintln!("kvm-probe: {e}");
        std::process::exit(1);
    }
}
