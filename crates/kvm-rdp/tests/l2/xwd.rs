//! L3's oracles (Plan E Task 3.1): the picture FreeRDP decoded, read back
//! from Xvfb's `-fbdir` framebuffer (an XWD file, the X server's own
//! pixels), §11.5's 16-bit barcode in it, and FreeRDP's process group,
//! killed whole when a case ends however it ends (Review Focus 5).
use std::path::Path;
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

/// A ZPixmap XWD image with 32-bit pixels (Xvfb's at depth 24).
pub struct Framebuffer {
    width: u32,
    height: u32,
    bytes_per_line: usize,
    lsb_first: bool,
    masks: [u32; 3],
    start: usize,
    data: Vec<u8>,
}

impl Framebuffer {
    pub fn read(path: &Path) -> Option<Framebuffer> {
        Framebuffer::parse(std::fs::read(path).ok()?)
    }

    /// XWDFileHeader: 25 big-endian CARD32s (X11's XWDFile.h), then the
    /// window name (to `header_size`), `ncolors` 12-byte XWDColors, then
    /// `height` lines of `bytes_per_line`. The sizes are the file's, so
    /// their arithmetic is checked: one that overflows is no image.
    pub fn parse(data: Vec<u8>) -> Option<Framebuffer> {
        let word = |i: usize| -> Option<u32> {
            let b = data.get(i * 4..i * 4 + 4)?;
            Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        };
        let size = |i: usize| -> Option<usize> { usize::try_from(word(i)?).ok() };
        if word(1)? != 7 || word(11)? != 32 {
            return None; // XWD_FILE_VERSION 7; 32 bits per pixel only
        }
        let (width, height) = (word(4)?, word(5)?);
        let bytes_per_line = size(12)?;
        let start = size(0)?.checked_add(size(19)?.checked_mul(12)?)?;
        let end = bytes_per_line
            .checked_mul(usize::try_from(height).ok()?)?
            .checked_add(start)?;
        if data.len() < end {
            return None;
        }
        Some(Framebuffer {
            width,
            height,
            bytes_per_line,
            lsb_first: word(7)? == 0,
            masks: [word(14)?, word(15)?, word(16)?],
            start,
            data,
        })
    }

    pub fn rgb(&self, x: u32, y: u32) -> Option<[u8; 3]> {
        if x >= self.width || y >= self.height {
            return None;
        }
        let off = usize::try_from(y)
            .ok()?
            .checked_mul(self.bytes_per_line)?
            .checked_add(usize::try_from(x).ok()?.checked_mul(4)?)?
            .checked_add(self.start)?;
        let b = self.data.get(off..off.checked_add(4)?)?;
        let px = if self.lsb_first {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        };
        // In u64: a mask as wide as 32 bits times 255 does not fit a u32.
        let channel = |mask: u32| -> u8 {
            if mask == 0 {
                return 0;
            }
            let shift = mask.trailing_zeros();
            let max = u64::from(mask >> shift);
            u8::try_from(u64::from((px & mask) >> shift) * 255 / max).unwrap_or(255)
        };
        Some([
            channel(self.masks[0]),
            channel(self.masks[1]),
            channel(self.masks[2]),
        ])
    }
}

/// §11.5's barcode at `(x0, y0)`: block k white when bit k is set, read at
/// three points per block; `None` unless every point is clean black
/// (luma < 64) or white (> 192) and a block's points agree — a torn or
/// half-decoded picture never reads as a frame number.
pub fn barcode(fb: &Framebuffer, x0: u32, y0: u32, bw: u32, bh: u32) -> Option<u16> {
    let mut value = 0u16;
    for k in 0..16u32 {
        let mut white = None;
        for (dx, dy) in [(bw / 2, bh / 2), (bw / 4, bh / 4), (3 * bw / 4, 3 * bh / 4)] {
            let [r, g, b] = fb.rgb(x0 + k * bw + dx, y0 + dy)?;
            let luma = (u32::from(r) * 299 + u32::from(g) * 587 + u32::from(b) * 114) / 1000;
            let w = match luma {
                0..=63 => false,
                193..=255 => true,
                _ => return None,
            };
            if *white.get_or_insert(w) != w {
                return None;
            }
        }
        if white == Some(true) {
            value |= 1 << k;
        }
    }
    Some(value)
}

/// How long a dropped group has after its SIGTERM before the SIGKILL.
const GRACE: Duration = Duration::from_secs(2);

/// A child in its own process group; dropping it ends the whole group.
pub struct Group {
    child: Child,
    pub pgid: libc::pid_t,
}

impl Group {
    pub fn spawn(mut cmd: Command) -> std::io::Result<Group> {
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
        let child = cmd.spawn()?;
        let pgid = libc::pid_t::try_from(child.id()).map_err(std::io::Error::other)?;
        Ok(Group { child, pgid })
    }

    pub fn running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// The leader's exit, if it comes within `limit`.
    pub fn wait_exit(&mut self, limit: Duration) -> Option<ExitStatus> {
        let t0 = Instant::now();
        loop {
            if let Ok(Some(s)) = self.child.try_wait() {
                return Some(s);
            }
            if t0.elapsed() > limit {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Whether any process of the group is left: `kill(-pgid, 0)` fails
    /// with ESRCH once none is. The leader is reaped first (a zombie still
    /// counts); the others' parents, or the subreaper they are reparented
    /// to, reap them.
    fn any_left(&mut self) -> bool {
        let _ = self.child.try_wait();
        // SAFETY: signal 0 to our own process group probes it, sends nothing.
        let probe = unsafe { libc::kill(-self.pgid, 0) };
        !(probe == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH))
    }
}

impl Drop for Group {
    /// SIGTERM to the group, then up to `GRACE` for the whole group — not
    /// only its leader: xvfb-run's shell dies at TERM at once, while FreeRDP
    /// and Xvfb shut down (PE8 review I2) — and only then SIGKILL to what
    /// is left, which a TERM-ignoring member is.
    fn drop(&mut self) {
        // SAFETY: signalling our own process group.
        unsafe { libc::kill(-self.pgid, libc::SIGTERM) };
        let t0 = Instant::now();
        while self.any_left() && t0.elapsed() < GRACE {
            std::thread::sleep(Duration::from_millis(20));
        }
        if self.any_left() {
            // SAFETY: as above; the group still has a member, so its id
            // is still ours.
            unsafe { libc::kill(-self.pgid, libc::SIGKILL) };
        }
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An XWD image as Xvfb 21.1.24's -fbdir writes one: a big-endian
    /// header with a 60-byte window name (`header_size` 160), 256 colormap
    /// entries (`ncolors` 256, each a zeroed 12-byte XWDColor), so the
    /// pixels start at 3232 as on a live Xvfb; 32-bit LSBFirst TrueColor.
    fn xwd(w: u32, h: u32, px: impl Fn(u32, u32) -> [u8; 3]) -> Vec<u8> {
        let mut name = b"Xvfb main window".to_vec();
        name.resize(60, 0);
        let header = 100 + u32::try_from(name.len()).unwrap();
        let words = [
            header,
            7,
            2,
            24,
            w,
            h,
            0,
            0,
            32,
            0,
            32,
            32,
            w * 4,
            4,
            0x00FF_0000,
            0x0000_FF00,
            0x0000_00FF,
            8,
            256,
            256,
            w,
            h,
            0,
            0,
            0,
        ];
        let mut out: Vec<u8> = words.iter().flat_map(|v| v.to_be_bytes()).collect();
        out.extend_from_slice(&name);
        out.resize(out.len() + 256 * 12, 0);
        assert_eq!(out.len(), 3232, "Xvfb's pixel offset");
        for y in 0..h {
            for x in 0..w {
                let [r, g, b] = px(x, y);
                out.extend_from_slice(&[b, g, r, 0]);
            }
        }
        out
    }

    #[test]
    fn a_synthetic_framebuffer_reads_back_its_pixels() {
        let fb = Framebuffer::parse(xwd(8, 4, |x, y| [x as u8 * 10, y as u8 * 20, 7])).unwrap();
        assert_eq!(fb.rgb(3, 2), Some([30, 40, 7]));
        assert_eq!(fb.rgb(8, 0), None, "outside the image");
        assert!(Framebuffer::parse(vec![0; 50]).is_none(), "a short file");
    }

    /// Header word `i` (a big-endian CARD32) set to `v`.
    fn set_word(data: &mut [u8], i: usize, v: u32) {
        data[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }

    /// PE8 review m2: the file's header values are checked, never trusted —
    /// sizes that overflow are no image (not a panic), a mask wider than
    /// 24 bits still reads, and a file one byte short of its last pixel is
    /// no image.
    #[test]
    fn an_overflowing_or_truncated_file_is_no_framebuffer() {
        let good = xwd(8, 4, |_, _| [235, 235, 235]);
        assert!(Framebuffer::parse(good.clone()).is_some());
        // bytes_per_line, height, ncolors, header_size: alone and together.
        for words in [&[12][..], &[5], &[19], &[0], &[12, 5, 19], &[0, 12, 5, 19]] {
            let mut bad = good.clone();
            for &w in words {
                set_word(&mut bad, w, u32::MAX);
            }
            assert!(
                Framebuffer::parse(bad).is_none(),
                "words {words:?} = u32::MAX"
            );
        }
        // A 32-bit red mask over a pixel whose pad byte is set: 0xFFEBEBEB
        // times 255 overflows a u32.
        let mut wide = good.clone();
        set_word(&mut wide, 14, u32::MAX);
        wide[3232 + 3] = 0xFF;
        let fb = Framebuffer::parse(wide).unwrap();
        assert_eq!(fb.rgb(0, 0), Some([254, 235, 235]), "a 32-bit red mask");
        let mut short = good;
        short.truncate(short.len() - 1);
        assert!(Framebuffer::parse(short).is_none(), "one byte short");
    }

    /// §11.5's barcode: block k white when bit k of the frame index is set.
    #[test]
    fn the_barcode_decodes_and_an_unclean_one_does_not() {
        let value = 0xA5C3u16;
        let fb = Framebuffer::parse(xwd(640, 40, |x, y| {
            let on = y < 32 && value >> (x / 40) & 1 == 1;
            if on { [235, 235, 235] } else { [16, 16, 16] }
        }))
        .unwrap();
        assert_eq!(barcode(&fb, 0, 0, 40, 32), Some(value));
        let grey = Framebuffer::parse(xwd(640, 40, |_, _| [128, 128, 128])).unwrap();
        assert_eq!(
            barcode(&grey, 0, 0, 40, 32),
            None,
            "neither black nor white"
        );
        // Black is a clean reading of 0 — and Xvfb's root and FreeRDP's
        // empty window are black: why `L3::barcode_within` skips 0.
        let black = Framebuffer::parse(xwd(640, 40, |_, _| [0, 0, 0])).unwrap();
        assert_eq!(barcode(&black, 0, 0, 40, 32), Some(0));
    }

    /// Review Focus 5: dropping a group kills every process in it — the
    /// leader and what it started (Xvfb under xvfb-run, here two sleeps),
    /// one of which ignores SIGTERM, so only the SIGKILL ends it (PE8
    /// review m1).
    #[test]
    fn a_dropped_group_leaves_no_process_behind() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "(trap '' TERM; sleep 60) & sleep 60"]);
        let g = Group::spawn(cmd).unwrap();
        let pgid = g.pgid;
        std::thread::sleep(Duration::from_millis(100));
        // SAFETY: signal 0 probes our own process group.
        assert_eq!(unsafe { libc::kill(-pgid, 0) }, 0, "the group runs");
        drop(g);
        let gone = (0..100).any(|_| {
            std::thread::sleep(Duration::from_millis(20));
            // SAFETY: as above.
            let probe = unsafe { libc::kill(-pgid, 0) };
            probe == -1
        });
        assert!(gone, "a process of the group outlived its drop");
    }

    /// PE8 review I2: the TERM is the group's shutdown and the KILL only its
    /// backstop. Drop waits for the whole group, not only its leader (here,
    /// as xvfb-run's shell, one that dies at TERM at once), so a member that
    /// cleans up on TERM (FreeRDP, Xvfb) finishes — and drop returns once
    /// the group is empty, not after the whole grace.
    #[test]
    fn a_dropped_group_lets_its_members_shut_down_before_the_kill() {
        let dir = tempfile::tempdir().unwrap();
        let done = dir.path().join("shut-down");
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(format!(
            "(trap 'sleep 0.3; touch {}; exit 0' TERM; while :; do sleep 0.05; done) & sleep 60",
            done.display()
        ));
        let g = Group::spawn(cmd).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        let t0 = Instant::now();
        drop(g);
        let took = t0.elapsed();
        assert!(
            done.exists(),
            "drop killed a member mid-shutdown ({took:?})"
        );
        assert!(took < GRACE, "drop waited out its grace: {took:?}");
    }

    /// `wait_exit` (Task 3.2's `L3::freerdp_exit`): the leader's own exit
    /// within the limit, `None` past it.
    #[test]
    fn wait_exit_reports_the_leaders_exit_within_its_limit() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "exit 3"]);
        let mut g = Group::spawn(cmd).unwrap();
        let status = g.wait_exit(Duration::from_secs(5));
        assert_eq!(status.and_then(|s| s.code()), Some(3));
        let mut cmd = Command::new("sleep");
        cmd.arg("60");
        let mut g = Group::spawn(cmd).unwrap();
        assert!(g.wait_exit(Duration::from_millis(100)).is_none());
        assert!(g.running());
    }
}
