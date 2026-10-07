//! Write the fuzz seeds (`kvm_proto::fuzzing::seeds`) under DIR, one
//! subdirectory per target: `cargo run -p kvm-proto --features fuzzing
//! --example fuzz_seeds -- DIR`. DIR is required (scripts/fuzz.sh passes
//! `$CARGO_TARGET_DIR/fuzz-seeds`), so nothing lands in a per-worktree
//! `target/`.
fn main() -> std::io::Result<()> {
    let Some(dir) = std::env::args().nth(1) else {
        return Err(std::io::Error::other("usage: fuzz_seeds DIR"));
    };
    for (target, name, bytes) in kvm_proto::fuzzing::seeds() {
        let d = std::path::Path::new(&dir).join(target);
        std::fs::create_dir_all(&d)?;
        std::fs::write(d.join(name), bytes)?;
    }
    Ok(())
}
