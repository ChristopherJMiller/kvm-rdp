//! `kvm-rdp` (spec §4.4, §5.2): read the config named by `--config` or
//! `KVM_RDP_CONFIG` — the only environment variable read — start the
//! bridge, and run until SIGTERM, SIGINT or a certificate change; exit 0
//! after §5.2's shutdown. Exit 1 if startup failed or the RDP server
//! stopped on its own, 2 on a config or logging error.
use kvm_rdp::bridge;
use kvm_rdp::config;
use std::process::ExitCode;

fn main() -> ExitCode {
    // The error is a line that never carries the file's contents (§9.2).
    let cfg = match config::from_command_line(
        std::env::args_os().skip(1),
        std::env::var_os("KVM_RDP_CONFIG"),
    ) {
        Ok(c) => c,
        Err(line) => {
            eprintln!("{line}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = kvm_rdp::logging::init(&cfg.log.filter) {
        eprintln!("kvm-rdp: {e}");
        return ExitCode::from(2);
    }
    let handle = match bridge::spawn(cfg) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "startup failed");
            return ExitCode::FAILURE;
        }
    };
    // 0 after a signal or a certificate change, 1 if the server stopped.
    ExitCode::from(handle.run_until_signal().code())
}
