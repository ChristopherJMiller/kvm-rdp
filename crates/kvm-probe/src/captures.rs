use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

#[derive(Debug)]
pub enum CaptureError {
    Unsafe(String),
    NotADirectory(PathBuf),
    Io(std::io::Error),
}

impl From<std::io::Error> for CaptureError {
    fn from(e: std::io::Error) -> Self {
        CaptureError::Io(e)
    }
}

#[derive(Debug)]
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
    ///
    /// Refuses to proceed if `root` already exists as anything other than a
    /// genuine directory: a symlink (even one pointing at a real directory)
    /// or a regular file is rejected rather than silently followed/reused —
    /// §11.5 containment must not be defeatable by a planted link.
    pub fn create(root: &Path) -> Result<CaptureDir, CaptureError> {
        if let Some(parent) = root.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match std::fs::symlink_metadata(root) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    return Err(CaptureError::NotADirectory(root.to_path_buf()));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut b = std::fs::DirBuilder::new();
                b.mode(0o700);
                b.create(root)?;
            }
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

    /// A fresh, uniquely-named base dir for one test (never created on disk here).
    fn tmp_base(label: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("kvm-probe-cap-{}-{label}", std::process::id()));
        p
    }

    #[test]
    fn create_is_0700_and_resolves_only_simple_names() {
        let base = tmp_base("basic");
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("captures");
        let dir = CaptureDir::create(&root).unwrap();

        let mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);

        assert_eq!(
            dir.resolve("capture-001.flv").unwrap(),
            root.join("capture-001.flv")
        );

        for bad in [
            "../x",
            "/etc/passwd",
            "a/b",
            "",
            ".",
            "..",
            "with\0null",
            "a.flv/",
        ] {
            assert!(
                matches!(dir.resolve(bad), Err(CaptureError::Unsafe(_))),
                "accepted {bad:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn create_tightens_a_preexisting_0755_directory() {
        let base = tmp_base("tighten");
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("captures");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();

        let mode_before = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode_before, 0o755, "fixture setup sanity check");

        let _dir = CaptureDir::create(&root).unwrap();

        let mode_after = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode_after, 0o700,
            "pre-existing directory must be tightened to 0700"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn create_refuses_a_preexisting_symlink_root() {
        let base = tmp_base("symlink");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();

        let target = base.join("evil_target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();

        let root = base.join("captures");
        std::os::unix::fs::symlink(&target, &root).unwrap();

        let result = CaptureDir::create(&root);
        assert!(
            matches!(result, Err(CaptureError::NotADirectory(_))),
            "accepted a symlink root: {result:?}"
        );

        let target_mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            target_mode, 0o755,
            "symlink target's mode must be left untouched"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn create_refuses_a_preexisting_regular_file_root() {
        let base = tmp_base("file");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();

        let root = base.join("captures");
        std::fs::write(&root, b"not a directory").unwrap();

        let result = CaptureDir::create(&root);
        assert!(
            matches!(result, Err(CaptureError::NotADirectory(_))),
            "accepted a regular-file root: {result:?}"
        );

        let _ = std::fs::remove_dir_all(&base);
    }
}
