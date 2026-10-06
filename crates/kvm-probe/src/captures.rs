use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
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

/// Lets callers that return `std::io::Result` use `?` directly on a
/// `CaptureDir` method (e.g. `resolve`) without a manual `map_err`.
impl From<CaptureError> for std::io::Error {
    fn from(e: CaptureError) -> Self {
        match e {
            CaptureError::Io(io_err) => io_err,
            CaptureError::Unsafe(name) => std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsafe capture name: {name}"),
            ),
            CaptureError::NotADirectory(path) => std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("not a directory: {}", path.display()),
            ),
        }
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

/// Read `<dir>/<name>` the way anything reading sandbox-writable output
/// must (I3, §11.5): the captures dir is bound read-write into the ffmpeg
/// sandbox (`sandbox.rs`), so a compromised decode could have planted any
/// kind of entry — symlink, FIFO, device — at any name a later step reads.
///
/// - Opens with `O_NOFOLLOW` (refuses a symlink outright) and `O_NONBLOCK`
///   (on Linux, opening a FIFO for reading with this flag returns
///   immediately whether or not a writer exists, instead of blocking
///   forever waiting for one that will never come — the sandbox is dead by
///   the time anything reads its output).
/// - `fstat`s the *opened* file descriptor (`File::metadata`, not a
///   path-based `stat` that could race a swap) and requires a regular
///   file; a FIFO, device, directory or anything else is refused before a
///   single byte is read.
/// - Reads at most `max_bytes + 1` bytes and errors if that's exceeded,
///   so a huge or endless file is detected, never buffered unboundedly.
pub fn read_capped(dir: &CaptureDir, name: &str, max_bytes: usize) -> std::io::Result<Vec<u8>> {
    let path = dir.resolve(name)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)?;

    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other(format!(
            "{} is not a regular file",
            path.display()
        )));
    }

    let cap = u64::try_from(max_bytes.saturating_add(1)).unwrap_or(u64::MAX);
    let mut limited = file.take(cap);
    let mut buf = Vec::new();
    limited.read_to_end(&mut buf)?;
    if buf.len() > max_bytes {
        return Err(std::io::Error::other(format!(
            "{} exceeds the {max_bytes}-byte cap",
            path.display()
        )));
    }
    Ok(buf)
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

    #[test]
    fn read_capped_refuses_a_symlink() {
        let base = tmp_base("readcap-symlink");
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("captures");
        let dir = CaptureDir::create(&root).unwrap();

        let real = root.join("real.bin");
        std::fs::write(&real, [1u8, 2, 3]).unwrap();
        std::os::unix::fs::symlink(&real, root.join("link.bin")).unwrap();

        let result = read_capped(&dir, "link.bin", 10);
        assert!(result.is_err(), "a symlink must never be followed");

        let _ = std::fs::remove_dir_all(&base);
    }

    /// I3: a FIFO planted at the output name must be refused promptly, not
    /// hang waiting for a writer that — the sandbox being dead — will
    /// never come.
    #[test]
    fn read_capped_refuses_a_fifo_promptly() {
        let base = tmp_base("readcap-fifo");
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("captures");
        let dir = CaptureDir::create(&root).unwrap();

        let fifo_path = root.join("fifo.bin");
        let c_path = std::ffi::CString::new(fifo_path.to_str().unwrap()).unwrap();
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo failed: {}", std::io::Error::last_os_error());

        let started = std::time::Instant::now();
        let result = read_capped(&dir, "fifo.bin", 10);
        let elapsed = started.elapsed();
        assert!(result.is_err(), "a FIFO must never be read as a capture");
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "must fail promptly, not hang: took {elapsed:?}"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn read_capped_errors_when_oversize() {
        let base = tmp_base("readcap-oversize");
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("captures");
        let dir = CaptureDir::create(&root).unwrap();
        std::fs::write(root.join("big.bin"), vec![7u8; 1000]).unwrap();

        let result = read_capped(&dir, "big.bin", 10);
        assert!(result.is_err(), "a file over the cap must be refused");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn read_capped_reads_a_short_file_fully() {
        let base = tmp_base("readcap-short");
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("captures");
        let dir = CaptureDir::create(&root).unwrap();
        std::fs::write(root.join("small.bin"), [9u8, 8, 7]).unwrap();

        let bytes = read_capped(&dir, "small.bin", 10).unwrap();
        assert_eq!(bytes, vec![9u8, 8, 7]);

        let _ = std::fs::remove_dir_all(&base);
    }
}
