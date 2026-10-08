//! `kvm-rdp` (spec §4.4, §5.2): `kvm-rdp --config <file>` (or
//! `KVM_RDP_CONFIG`). The body is `kvm_rdp::cli::main`; exit 0 after a
//! signal or a certificate change, 1 if startup failed or the RDP server
//! stopped on its own, 2 on a config or logging error.
use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(kvm_rdp::cli::main(
        std::env::args_os().skip(1),
        std::env::var_os("KVM_RDP_CONFIG"),
    ))
}
