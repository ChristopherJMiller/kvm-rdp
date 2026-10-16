//! §10.2's bench streams, generated on demand by `scripts/gen-fixtures.sh
//! bench` into the shared target dir and never committed.
use kvm_sim::Source;
use std::path::{Path, PathBuf};

pub fn dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"))
        .join("bench-streams")
}

pub fn load(name: &str) -> Result<Source, String> {
    let path = dir().join(name);
    let data = std::fs::read(&path).map_err(|e| {
        format!(
            "{}: {e} — generate the bench streams: scripts/gen-fixtures.sh bench",
            path.display()
        )
    })?;
    Source::from_annex_b(name, &data).map_err(|e| format!("{name}: {e:?}"))
}
