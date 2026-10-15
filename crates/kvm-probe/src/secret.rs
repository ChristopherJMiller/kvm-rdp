//! Secret material that must never be echoed, logged, or accepted from
//! argv or the environment (§9.2). Currently just the KVM password file
//! (M7: moved out of the binary and into the lib so it's unit-testable).

use std::io::Read;
use std::path::Path;

/// Local-file bound on the password file: never buffer an unbounded file,
/// local or not. 4 KiB is generous for any real password.
pub const MAX_PASSWORD_FILE_BYTES: u64 = 4 * 1024;

/// Strip exactly one trailing newline (`\n` or `\r\n`), the way a text
/// editor or `echo` leaves one at end of file. Never strips more than one,
/// so a password that itself ends in a blank line is not silently mangled.
pub fn strip_one_trailing_newline(mut s: String) -> String {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
    s
}

/// Read the KVM password from `path` — the only place a password may come
/// from; it is never accepted as a CLI argument or an environment variable
/// (§9.2). The read is bounded at `MAX_PASSWORD_FILE_BYTES` (refused, not
/// truncated, past that) and one trailing newline is stripped. No error
/// names the path — a password written where the path goes would otherwise
/// be echoed (C1 class) — only `--password-file`, the I/O kind or the rule;
/// none shows the file's contents, and the password
/// itself is never logged, printed, or included in any error produced
/// anywhere in this crate.
pub fn read_password_file(path: &Path) -> Result<String, String> {
    let unreadable =
        |e: std::io::Error| format!("--password-file: cannot read the file: {}", e.kind());
    let mut file = std::fs::File::open(path).map_err(unreadable)?;
    let cap = MAX_PASSWORD_FILE_BYTES.saturating_add(1);
    let mut limited = (&mut file).take(cap);
    let mut buf = Vec::new();
    limited.read_to_end(&mut buf).map_err(unreadable)?;
    let len = u64::try_from(buf.len()).unwrap_or(u64::MAX);
    if len > MAX_PASSWORD_FILE_BYTES {
        return Err(format!(
            "--password-file: over the {MAX_PASSWORD_FILE_BYTES}-byte cap"
        ));
    }
    let text = String::from_utf8(buf).map_err(|_| "--password-file: not UTF-8".to_owned())?;
    Ok(strip_one_trailing_newline(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_file(label: &str, contents: &[u8]) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("kvm-probe-secret-{}-{label}", std::process::id()));
        std::fs::write(&p, contents).unwrap();
        p
    }

    #[test]
    fn exactly_4096_bytes_is_accepted() {
        let path = tmp_file("4096", &vec![b'x'; 4096]);
        let pw = read_password_file(&path).unwrap();
        assert_eq!(pw.len(), 4096);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn exactly_4097_bytes_is_refused() {
        let path = tmp_file("4097", &vec![b'x'; 4097]);
        let err = read_password_file(&path).unwrap_err();
        assert!(!err.contains(&path.display().to_string()), "{err}");
        assert!(err.contains("4096"));
        // The error must never echo the file's contents (a run of the
        // password-filler byte, as opposed to the incidental 'x' in
        // English words like "exceeds").
        assert!(!err.contains("xxxx"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn strips_exactly_one_trailing_lf() {
        let path = tmp_file("lf", b"s3cret\n");
        assert_eq!(read_password_file(&path).unwrap(), "s3cret");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn strips_exactly_one_trailing_crlf() {
        let path = tmp_file("crlf", b"s3cret\r\n");
        assert_eq!(read_password_file(&path).unwrap(), "s3cret");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn strips_only_one_trailing_newline_not_more() {
        let path = tmp_file("blankline", b"s3cret\n\n");
        assert_eq!(read_password_file(&path).unwrap(), "s3cret\n");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn errors_never_name_the_path() {
        let missing =
            std::env::temp_dir().join(format!("kvm-probe-secret-missing-{}", std::process::id()));
        let _ = std::fs::remove_file(&missing);
        let err = read_password_file(&missing).unwrap_err();
        assert!(!err.contains(&missing.display().to_string()), "{err}");
        assert_eq!(
            err,
            "--password-file: cannot read the file: entity not found"
        );
    }

    /// C1 class (Plan C final review, d7c6dc9): a password pasted where the
    /// path goes never reaches the terminal through the error.
    #[test]
    fn a_password_passed_as_the_path_is_never_echoed() {
        let err = read_password_file(Path::new("/nonexistent/SNTL7qZq7vP2")).unwrap_err();
        assert!(!err.contains("SNTL7qZq7vP2"), "{err}");
        assert!(err.starts_with("--password-file: "), "{err}");
    }

    #[test]
    fn a_non_utf8_file_is_named_by_the_flag_only() {
        let path = tmp_file("notutf8", b"\xff\xfe");
        let err = read_password_file(&path).unwrap_err();
        assert_eq!(err, "--password-file: not UTF-8");
        let _ = std::fs::remove_file(&path);
    }
}
