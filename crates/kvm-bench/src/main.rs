//! kvm-bench (spec §10.2): kvm-sim and a lean IronRDP client in this
//! process, the bridge under test as a subprocess — a release build with
//! `--features alloc-stats,test-hooks`:
//!   kvm-bench --bridge target/release/kvm-rdp [--thresholds ci|strict] [--out DIR] SCENARIO...
//! `ci` and `all` name scenario sets (`all` is every scenario but `soak`).
//! Each scenario writes `<name>.json`; the exit status is 0 only if every
//! check of every report passed.
// The harness's API, as tests/l2/client.rs: with Task 5.5's soak every
// scenario is in, and three items are still unread (`Bridge::sigterm`,
// `Rx::idr`, `Mark::rx`) — kept for the next scenario, not trimmed.
#[allow(dead_code)]
mod bridge;
#[allow(dead_code)]
mod client;
mod null_bridge;
#[allow(dead_code)]
mod scenarios;
mod soak;
mod streams;

use clap::{Parser, ValueEnum};
use kvm_bench::report::Thresholds;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

#[derive(Clone, Copy, ValueEnum)]
enum Mode {
    Ci,
    Strict,
}

#[derive(Parser)]
#[command(about = "kvm-rdp's perf harness (spec §10.2)")]
struct Args {
    /// The bridge under test: built --release --features alloc-stats,test-hooks.
    #[arg(long)]
    bridge: PathBuf,
    /// strict: §10.1's absolute targets; ci: 10× looser (§10.2).
    #[arg(long, value_enum, default_value = "ci")]
    thresholds: Mode,
    /// Where each report goes, as <scenario>.json.
    #[arg(long, default_value = "target/kvm-bench")]
    out: PathBuf,
    /// The soak's length (Task 5.5; CI only at 60m, §13).
    #[arg(long, default_value = "60m", value_parser = duration)]
    soak_duration: Duration,
    /// The soak's churn period (§10.1: every 5 minutes).
    #[arg(long, default_value = "5m", value_parser = duration)]
    churn_every: Duration,
    /// Scenario names, or `ci` (the per-PR set) or `all` (all but the soak).
    #[arg(required = true)]
    scenarios: Vec<String>,
}

fn duration(s: &str) -> Result<Duration, String> {
    let (n, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = n
        .parse()
        .map_err(|_| format!("{s:?} is not a duration like 90s or 60m"))?;
    match unit {
        "s" => Ok(Duration::from_secs(n)),
        "m" => Ok(Duration::from_secs(n * 60)),
        _ => Err(format!("{s:?} is not a duration like 90s or 60m")),
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> ExitCode {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let args = Args::parse();
    let cx = scenarios::Ctx {
        bridge: args.bridge,
        thresholds: match args.thresholds {
            Mode::Ci => Thresholds::Ci,
            Mode::Strict => Thresholds::Strict,
        },
        soak_duration: args.soak_duration,
        churn_every: args.churn_every,
    };
    let names: Vec<String> = args
        .scenarios
        .iter()
        .flat_map(|n| match n.as_str() {
            "ci" => scenarios::CI.iter().map(|s| (*s).to_owned()).collect(),
            "all" => scenarios::ALL.iter().map(|s| (*s).to_owned()).collect(),
            other => vec![other.to_owned()],
        })
        .collect();
    if std::fs::create_dir_all(&args.out).is_err() {
        eprintln!("kvm-bench: cannot create {}", args.out.display());
        return ExitCode::FAILURE;
    }
    let mut all_passed = true;
    for name in names {
        let t0 = std::time::Instant::now();
        let report = match scenarios::run(&name, &cx).await {
            Ok(r) => r,
            Err(e) => {
                let mut r = kvm_bench::report::Report::new(&name, cx.thresholds);
                r.holds("the scenario ran", false);
                r.note(e);
                r
            }
        };
        let path = args.out.join(format!("{name}.json"));
        let _ = std::fs::write(
            &path,
            serde_json::to_string_pretty(&report).unwrap_or_default(),
        );
        let failed: Vec<&str> = report
            .checks
            .iter()
            .filter(|c| !c.pass)
            .map(|c| c.name.as_str())
            .collect();
        println!(
            "kvm-bench: {name}: {} in {:.0} s{} ({})",
            if report.passed() { "PASS" } else { "FAIL" },
            t0.elapsed().as_secs_f64(),
            if failed.is_empty() {
                String::new()
            } else {
                format!(" — {}", failed.join("; "))
            },
            path.display()
        );
        all_passed &= report.passed();
    }
    if all_passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
