//! The paste state machine (§8), sans-IO: the core calls into it per event
//! and per step. It owns no clock; `Ctx::now` and the deadlines come from
//! the core. The Typist is the only keyboard source while typing; client
//! keyboard input is swallowed (Esc aborts), mouse motion passes, a mouse
//! button or a §7.4 trigger aborts.
//!
//! Pasted text is as sensitive as a password (§4.5, §9.2): `State` holds it
//! and has a redacted `Debug` (its kind and counts). `PasteOutcome` and
//! `PasteRefusal` hold no text — counts and fixed labels only, the form
//! §9.2 logs paste activity in — so theirs are derived.
use kvm_proto::paste::Typist;
use std::time::{Duration, Instant};

/// How soon a typing step that found no HID queue room looks again (DD6):
/// short against any pace, long enough that the driver never spins.
pub const ROOM_POLL: Duration = Duration::from_millis(2);

/// The most Typist reports one step pushes (DD6, D2b): the shell reports
/// `TYPIST_ROOM − queued` as `Ctx::queue_room`, and the core clamps to it
/// whatever it is told (PD9 carry 5), so with `input.queue` ≥ 9 typing —
/// up to 8 reports, and typing's start one more — never overflows the
/// queue into a resync that would lose characters.
pub const TYPIST_ROOM: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasteRefusal {
    NoText,
    CapsLock,
    Multiline,
    /// The shell's (Task 3.3): the core never builds it.
    Oversize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasteOutcome {
    Started,
    Refused(PasteRefusal),
    Done {
        typed: usize,
        skipped: usize,
    },
    /// `"esc"`, `"key"`, `"mouse"`, `"release"`, `"modifier_wait"`; the
    /// answer the paste waited for failed (`"clipboard_failed"`) or was
    /// dropped in flight (`"clipboard_lost"`); or its session ended
    /// (`"session"`, from `InputCore::on_generation`).
    Aborted(&'static str),
}

pub enum State {
    Idle,
    /// Waiting for the clipboard text and for every physical modifier to
    /// release, until `deadline`.
    Pending {
        deadline: Instant,
        /// Clipboard answers due before this paste's own (PD9 carry 3a):
        /// the requests still unanswered when it asked, less those answered or
        /// retired since (I2). CLIPRDR answers in order, so its answer is the
        /// one that comes when this is 0.
        ahead: u32,
        text: Option<Vec<char>>,
        skipped: usize,
    },
    /// Typing; `next_report_at` paces the Typist.
    Typing {
        typist: Typist,
        typed: usize,
        skipped: usize,
        next_report_at: Instant,
    },
}

/// §9.2: the kind, whether the text has come, and counts — never a
/// character, a stroke or a time.
impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            State::Idle => f.write_str("Idle"),
            State::Pending {
                ahead,
                text,
                skipped,
                ..
            } => f
                .debug_struct("Pending")
                .field("ahead", ahead)
                .field("text_chars", &text.as_ref().map(Vec::len))
                .field("skipped", skipped)
                .finish_non_exhaustive(),
            State::Typing {
                typist,
                typed,
                skipped,
                ..
            } => f
                .debug_struct("Typing")
                .field("typist", typist)
                .field("typed", typed)
                .field("skipped", skipped)
                .finish_non_exhaustive(),
        }
    }
}

impl State {
    #[must_use]
    pub fn is_active(&self) -> bool {
        !matches!(self, State::Idle)
    }

    /// When the core next needs a step for the paste: Pending's deadline,
    /// or Typing's next report.
    #[must_use]
    pub fn deadline(&self) -> Option<Instant> {
        match self {
            State::Idle => None,
            State::Pending { deadline, .. } => Some(*deadline),
            State::Typing { next_report_at, .. } => Some(*next_report_at),
        }
    }
}
