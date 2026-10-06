use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

#[derive(Debug)]
pub enum CaptureError {
    Unsafe(String),
    Io(std::io::Error),
}

impl From<std::io::Error> for CaptureError {
    fn from(e: std::io::Error) -> Self {
        CaptureError::Io(e)
    }
}

pub struct CaptureDir {
    root: PathBuf,
}

fn is_safe_name(name: &str) -> bool {
    if name.is_empty() || name.contains('\0') {
        return false;
    }
    let mut comps = Path::new(name).components();
    match (comps.next(), comps.next()) {
        (Some(Component::Normal(c)), None) => c == std::ffi::OsStr::new(name),
        _ => false,
    }
}

impl CaptureDir {
    /// Create `root` (and parents) with mode 0700; tighten if it already exists.
    pub fn create(root: &Path) -> Result<CaptureDir, CaptureError> {
        if let Some(parent) = root.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut b = std::fs::DirBuilder::new();
        b.mode(0o700);
        match b.create(root) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(CaptureError::Io(e)),
        }
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        Ok(CaptureDir {
            root: root.to_path_buf(),
        })
    }

    /// Join a single safe filename under the capture root; refuse anything else.
    pub fn resolve(&self, name: &str) -> Result<PathBuf, CaptureError> {
        if !is_safe_name(name) {
            return Err(CaptureError::Unsafe(name.to_string()));
        }
        Ok(self.root.join(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp_root() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("kvm-probe-cap-{}", std::process::id()));
        p.push("captures");
        p
    }

    #[test]
    fn create_is_0700_and_resolves_only_simple_names() {
        let root = tmp_root();
        let _ = std::fs::remove_dir_all(root.parent().unwrap());
        let dir = CaptureDir::create(&root).unwrap();

        let mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);

        assert_eq!(
            dir.resolve("capture-001.flv").unwrap(),
            root.join("capture-001.flv")
        );

        for bad in ["../x", "/etc/passwd", "a/b", "", ".", "..", "with\0null"] {
            assert!(
                matches!(dir.resolve(bad), Err(CaptureError::Unsafe(_))),
                "accepted {bad:?}"
            );
        }
        let _ = std::fs::remove_dir_all(root.parent().unwrap());
    }
}
