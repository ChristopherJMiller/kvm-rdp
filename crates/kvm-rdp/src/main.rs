//! `kvm-rdp` (spec §4.4, §5.2): `kvm-rdp --config <file>` (or
//! `KVM_RDP_CONFIG`). The body is `kvm_rdp::cli::main`; exit 0 after a
//! signal or a certificate change, 1 if startup failed or the RDP server
//! stopped on its own, 2 on a config or logging error.

// Spec §5.2 (DE7): release builds abort on a panic. A crash cannot release
// keys either way, but an unwinding release build could keep serving NLA
// with a task it cannot run without gone. Every build without debug
// assertions — the release profile, the image, kvm-bench's bridge — must
// use the release profile's `panic = "abort"`; a release build that turns
// debug assertions on is outside this guard, and the image sets neither.
// (`cargo test --release`
// still builds — test harnesses unwind and the binary L2 spawns aborts —
// but `a_panicked_pump_shell_ends_the_binary_with_exit_1` then sees
// SIGABRT; only the debug profile is a supported test invocation.)
#[cfg(all(not(debug_assertions), not(panic = "abort")))]
compile_error!("kvm-rdp: a build without debug assertions must use panic = \"abort\" (spec §5.2)");

use std::process::ExitCode;

// §10.4 (Plan E Task 1.4): an `alloc-stats` build (kvm-bench's bridge)
// counts every allocation and exports the totals on `/metrics`. Every
// other build, the image's included, keeps the default allocator.
#[cfg(feature = "alloc-stats")]
#[global_allocator]
static ALLOC: kvm_rdp::alloc_stats::Counting = kvm_rdp::alloc_stats::Counting;

fn main() -> ExitCode {
    ExitCode::from(kvm_rdp::cli::main(
        std::env::args_os().skip(1),
        std::env::var_os("KVM_RDP_CONFIG"),
    ))
}
