//! Clipboard paste as typing (§8): the US-layout text handling and the
//! Typist, pure functions of the clipboard bytes and `paste.*`. Hostile
//! input (a client's `CF_UNICODETEXT`), so panic-free and bounded by the
//! crate lints.
//!
//! Pasted text is as sensitive as a password (§4.5, §9.2): no type here
//! that holds it — `Prepared`, `Typist` — derives `Debug`; theirs show
//! counts only, never a character, a stroke or a usage.
use crate::hid::HidFrame;
use crate::keymap::{MOD_LSHIFT, Stroke, us_stroke};

/// An all-zero keyboard report: the release after every typed character.
pub const RELEASE: HidFrame = HidFrame::Keyboard {
    modifiers: 0,
    keys: [0; 5],
};

/// Decode `bytes` as UTF-16LE, replacing each ill-formed unit (a lone
/// surrogate, or a trailing odd byte) with U+FFFD and counting it. The
/// text ends at its first U+0000 (CF_UNICODETEXT's terminator); nothing
/// after it is text, so nothing after it is counted either (D4). Each
/// U+FFFD is one scalar `prepare` skips and counts, so a caller that counts
/// `prepare`'s skips has every ill-formed unit counted once already.
#[must_use]
pub fn decode_utf16le(bytes: &[u8]) -> (String, usize) {
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
    let mut it = bytes.chunks_exact(2);
    for c in it.by_ref() {
        if let &[lo, hi] = c {
            units.push(u16::from_le_bytes([lo, hi]));
        }
    }
    let mut odd = !it.remainder().is_empty();
    if let Some(end) = units.iter().position(|&u| u == 0) {
        units.truncate(end);
        odd = false;
    }
    let mut out = String::with_capacity(units.len().saturating_add(1));
    let mut bad = 0usize;
    for r in char::decode_utf16(units) {
        match r {
            Ok(c) => out.push(c),
            Err(_) => {
                bad = bad.saturating_add(1);
                out.push('\u{FFFD}');
            }
        }
    }
    if odd {
        bad = bad.saturating_add(1);
        out.push('\u{FFFD}');
    }
    (out, bad)
}

/// `paste.multiline` and `paste.max_chars`, as `prepare` needs them (no
/// text: a derived `Debug` is safe).
#[derive(Debug, Clone, Copy)]
pub struct PastePolicy {
    pub multiline_refuse: bool,
    pub max_chars: usize,
}

/// The text `prepare` leaves to type, or its refusal.
#[derive(Clone, PartialEq, Eq)]
pub enum Prepared {
    Text(Vec<char>),
    RefusedMultiline,
}

/// §9.2: the prepared text is the pasted text — `Debug` shows its length
/// only.
impl core::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Prepared::Text(v) => f
                .debug_struct("Text")
                .field("chars", &v.len())
                .finish_non_exhaustive(),
            Prepared::RefusedMultiline => f.write_str("RefusedMultiline"),
        }
    }
}

/// What `prepare` kept and skipped, counted per Unicode scalar (counts
/// only: a derived `Debug` is safe).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Skips {
    pub kept: usize,
    pub skipped: usize,
}

/// §8: skip the controls and characters the US layout cannot type (each
/// Unicode scalar counted, `'\r'` excepted: it is a line break); then, on
/// what is left, drop one trailing CRLF/CR/LF; with `multiline_refuse`,
/// refuse any text that still holds a break; turn CRLF/CR/LF into one
/// Return each and keep Tab; cap at `max_chars`. A skip is counted only
/// while the cap has room (what lies past the cap is not looked at).
///
/// Skipping first (PD7 review m1, re-review m1-r) means no skipped scalar
/// — an ill-formed unit's U+FFFD, a control, a zero-width space — changes
/// which break is the trailing one, or splits a CRLF into a typed CR and a
/// trimmed LF: appending or inserting such a unit never turns a copied
/// line's break into a typed Enter.
#[must_use]
pub fn prepare(text: &str, policy: &PastePolicy) -> (Prepared, Skips) {
    let is_skipped = |c: char| c != '\r' && us_stroke(c).is_none();
    // What survives the skip: typeable scalars and the line breaks.
    let left: Vec<char> = text.chars().filter(|c| !is_skipped(*c)).collect();
    let trailing = match left.as_slice() {
        [.., '\r', '\n'] => 2,
        [.., '\n' | '\r'] => 1,
        _ => 0,
    };
    let body = left
        .get(..left.len().saturating_sub(trailing))
        .unwrap_or(&[]);
    if policy.multiline_refuse && body.iter().any(|c| matches!(c, '\n' | '\r')) {
        return (
            Prepared::RefusedMultiline,
            Skips {
                kept: 0,
                skipped: 0,
            },
        );
    }
    // In the text's own order: the body's scalars, CRLF/CR/LF as one
    // Return each (an LF right after a CR, skipped scalars between them or
    // not, is that CR's), and the skips, counted while the cap has room.
    let mut kept: Vec<char> = Vec::new();
    let mut skipped = 0usize;
    let mut body_left = body.len();
    let mut after_cr = false;
    for c in text.chars() {
        if kept.len() >= policy.max_chars {
            break;
        }
        if is_skipped(c) {
            skipped = skipped.saturating_add(1);
            continue;
        }
        if body_left == 0 {
            continue; // the trailing break: dropped
        }
        body_left = body_left.saturating_sub(1);
        match c {
            '\n' if after_cr => after_cr = false, // a CRLF's LF
            '\r' => {
                after_cr = true;
                kept.push('\n');
            }
            other => {
                after_cr = false;
                kept.push(other);
            }
        }
    }
    let kept_len = kept.len();
    (
        Prepared::Text(kept),
        Skips {
            kept: kept_len,
            skipped,
        },
    )
}

/// Emits the §8 report sequence for a prepared character list: a press
/// (Shift in the modifier byte for a shifted character), then an all-zero
/// release, one character at a time.
pub struct Typist {
    strokes: Vec<Stroke>,
    i: usize,
    release_next: bool,
}

/// §9.2: the Typist holds the pasted text as strokes — `Debug` shows how
/// many there are and whether it is done, never one of them.
impl core::fmt::Debug for Typist {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Typist")
            .field("strokes", &self.strokes.len())
            .field("done", &self.is_done())
            .finish_non_exhaustive()
    }
}

impl Typist {
    #[must_use]
    pub fn new(chars: &[char]) -> Typist {
        Typist {
            strokes: chars.iter().filter_map(|c| us_stroke(*c)).collect(),
            i: 0,
            release_next: false,
        }
    }

    #[must_use]
    pub fn is_done(&self) -> bool {
        self.i >= self.strokes.len() && !self.release_next
    }
}

impl Iterator for Typist {
    type Item = HidFrame;

    /// The next report, or `None` when done.
    fn next(&mut self) -> Option<HidFrame> {
        if self.release_next {
            self.release_next = false;
            self.i = self.i.saturating_add(1);
            return Some(RELEASE);
        }
        let s = self.strokes.get(self.i)?;
        self.release_next = true;
        Some(HidFrame::Keyboard {
            modifiers: if s.shift { MOD_LSHIFT } else { 0 },
            keys: [s.usage, 0, 0, 0, 0],
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;

    fn policy(multiline_refuse: bool, max_chars: usize) -> PastePolicy {
        PastePolicy {
            multiline_refuse,
            max_chars,
        }
    }
    fn chars(p: &Prepared) -> &[char] {
        match p {
            Prepared::Text(v) => v,
            Prepared::RefusedMultiline => panic!("refused"),
        }
    }

    #[test]
    fn utf16le_decodes_and_counts_ill_formed_units() {
        let (s, bad) = decode_utf16le(&[b'h', 0, b'i', 0]);
        assert_eq!((s.as_str(), bad), ("hi", 0));
        // A lone high surrogate (D800) is ill-formed: counted, replaced.
        let (s, bad) = decode_utf16le(&[0x00, 0xD8, b'x', 0]);
        assert_eq!(bad, 1);
        assert!(s.ends_with('x'));
        // An odd trailing byte is dropped and counted.
        let (_, bad) = decode_utf16le(&[b'a', 0, b'b']);
        assert_eq!(bad, 1);
    }

    /// D4: CF_UNICODETEXT is NUL-terminated (IronRDP's `new_unicode_string`,
    /// Windows and FreeRDP all append U+0000). The text ends there, so a
    /// copied line's trailing break is still the last thing §8 sees — and
    /// is removed, never typed as a Return.
    #[test]
    fn the_cf_unicodetext_terminator_ends_the_text() {
        assert_eq!(
            decode_utf16le(&[b'l', 0, b's', 0, b'\r', 0, b'\n', 0, 0, 0, b'x', 0]),
            ("ls\r\n".to_owned(), 0)
        );
        assert_eq!(
            prepare(
                &decode_utf16le(&[b'l', 0, b's', 0, b'\r', 0, b'\n', 0, 0, 0]).0,
                &policy(false, 4096)
            ),
            (
                Prepared::Text(vec!['l', 's']),
                Skips {
                    kept: 2,
                    skipped: 0
                }
            )
        );
        assert_eq!(
            prepare(
                &decode_utf16le(&[b'a', 0, b'\n', 0, 0, 0]).0,
                &policy(true, 4096)
            )
            .0,
            Prepared::Text(vec!['a']),
            "multiline = refuse still types a copied single line"
        );
    }

    /// §8 text handling, in order: a trailing line break is removed; CRLF,
    /// CR and LF each become one Return ('\n'); Tab stays; other C0 and
    /// untypeable scalars are skipped and counted.
    #[test]
    fn prepare_follows_section_8() {
        let (p, s) = prepare("a\r\nb\tc\u{1F600}\n", &policy(false, 4096));
        assert_eq!(chars(&p), ['a', '\n', 'b', '\t', 'c']); // trailing \n removed, emoji skipped
        assert_eq!((s.kept, s.skipped), (5, 1));
        assert_eq!(
            prepare("a\r", &policy(false, 4096)).0,
            Prepared::Text(vec!['a'])
        );
        assert_eq!(
            prepare("\n", &policy(false, 4096)).0,
            Prepared::Text(vec![])
        );
    }

    #[test]
    fn multiline_refuse_refuses_an_inner_break_but_types_a_trailing_one() {
        assert_eq!(
            prepare("a\nb", &policy(true, 4096)).0,
            Prepared::RefusedMultiline
        );
        assert_eq!(
            prepare("a\n", &policy(true, 4096)).0,
            Prepared::Text(vec!['a'])
        );
    }

    #[test]
    fn max_chars_caps_after_the_other_steps() {
        let (p, s) = prepare("abcdef", &policy(false, 3));
        assert_eq!(chars(&p), ['a', 'b', 'c']);
        assert_eq!(s.kept, 3);
    }

    /// §8 report sequence: press (Shift in the modifier byte for a shifted
    /// character), then an all-zero release, per character.
    #[test]
    fn the_typist_emits_press_release_pairs() {
        let mut t = Typist::new(&['a', 'B', '\n', '\t']);
        let press = |m, k| HidFrame::Keyboard {
            modifiers: m,
            keys: [k, 0, 0, 0, 0],
        };
        let got: Vec<_> = std::iter::from_fn(|| t.next()).collect();
        assert_eq!(
            got,
            [
                press(0, 0x04),
                RELEASE, // a
                press(MOD_LSHIFT, 0x05),
                RELEASE, // B
                press(0, 0x28),
                RELEASE, // Return
                press(0, 0x2B),
                RELEASE, // Tab
            ]
        );
        assert!(t.is_done());
    }

    // ---- Beyond the plan's listing.

    /// D4: an ill-formed unit or an odd byte after the terminator is not
    /// text, so it is not counted; a NUL in the first unit leaves nothing.
    #[test]
    fn nothing_after_the_terminator_is_text_or_counted() {
        assert_eq!(
            decode_utf16le(&[b'a', 0, 0, 0, 0x00, 0xD8, b'z']),
            ("a".to_owned(), 0)
        );
        assert_eq!(decode_utf16le(&[0, 0, b'a', 0]), (String::new(), 0));
        assert_eq!(decode_utf16le(&[]), (String::new(), 0));
        // A NUL's high byte alone is not a terminator: 0x0100 is 'Ā'.
        assert_eq!(decode_utf16le(&[0, 1, 0, 0]), ("\u{100}".to_owned(), 0));
    }

    /// An ill-formed unit — a lone surrogate either half, or the trailing
    /// odd byte (as the doc says) — is one U+FFFD: `prepare` skips and counts
    /// it once, so a caller counting `prepare`'s skips counts it once.
    #[test]
    fn each_ill_formed_unit_is_one_replacement_skipped_once() {
        let (s, bad) = decode_utf16le(&[b'a', 0, 0x00, 0xDC, 0x00, 0xD8, b'b', 0, b'c']);
        assert_eq!(
            (s.as_str(), bad),
            ("a\u{FFFD}\u{FFFD}b\u{FFFD}", 3),
            "DC00 then D800 is not a pair (high must come first): two lone halves"
        );
        let (p, skips) = prepare(&s, &policy(false, 4096));
        assert_eq!(p, Prepared::Text(vec!['a', 'b']));
        assert_eq!(skips.skipped, bad, "one count per ill-formed unit");
        // A well-formed pair is one scalar: decoded, then skipped once.
        let (s, bad) = decode_utf16le(&[0x3D, 0xD8, 0x00, 0xDE]);
        assert_eq!((s.as_str(), bad), ("\u{1F600}", 0));
        assert_eq!(prepare(&s, &policy(false, 4096)).1.skipped, 1);
    }

    /// PD7 review m1: a trailing line break followed only by what §8 skips
    /// — an odd byte or a lone surrogate (each a U+FFFD), a zero-width or a
    /// no-break space, a control — is still the trailing break: removed,
    /// never typed as a Return, and never refused as multiline. A hostile
    /// client cannot turn a copied line's break into an Enter by appending
    /// one ill-formed unit. What the tail holds is still skipped and counted.
    #[test]
    fn a_trailing_break_followed_only_by_skipped_units_is_still_trimmed() {
        let mut bytes: Vec<u8> = "ls\r\n".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let golden = |bytes: &[u8], what: &str| {
            let (text, bad) = decode_utf16le(bytes);
            for refuse in [false, true] {
                let (p, s) = prepare(&text, &policy(refuse, 4096));
                assert_eq!(p, Prepared::Text(vec!['l', 's']), "{what}, refuse={refuse}");
                assert_eq!(
                    s,
                    Skips {
                        kept: 2,
                        skipped: 1
                    },
                    "{what}"
                );
            }
            bad
        };
        // The review's case: "ls\r\n" and one odd byte, no terminator.
        let mut odd = bytes.clone();
        odd.push(0x41);
        assert_eq!(golden(&odd, "an odd byte"), 1);
        // A lone surrogate tail, either half.
        for half in [0xD8u8, 0xDC] {
            let mut lone = bytes.clone();
            lone.extend_from_slice(&[0x00, half]);
            assert_eq!(golden(&lone, "a lone surrogate"), 1);
        }
        // A skipped-scalar tail: well-formed, but untypeable.
        for tail in ["\u{200B}", "\u{A0}", "\u{1F600}", "\u{7}", "\u{FEFF}"] {
            let mut t: Vec<u8> = tail.encode_utf16().flat_map(u16::to_le_bytes).collect();
            t.splice(0..0, bytes.iter().copied());
            assert_eq!(golden(&t, tail), 0);
        }
        // Several skipped units, and a bare LF or CR before them.
        bytes = "ls\n\u{200B}\u{A0}"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        bytes.push(0x41);
        let (p, s) = prepare(&decode_utf16le(&bytes).0, &policy(true, 4096));
        assert_eq!((p, s.skipped), (Prepared::Text(vec!['l', 's']), 3));
        assert_eq!(
            prepare("ls\r\u{7}", &policy(true, 4096)).0,
            Prepared::Text(vec!['l', 's'])
        );
        // What is typeable after the break — a Tab, a space, a letter — is
        // text: the break is inside it, and is typed (or refused).
        for tail in ["\t", " ", "x"] {
            let text = format!("ls\r\n{tail}");
            let (p, _) = prepare(&text, &policy(false, 4096));
            let mut want = vec!['l', 's', '\n'];
            want.extend(tail.chars());
            assert_eq!(p, Prepared::Text(want), "{tail:?}");
            assert_eq!(
                prepare(&text, &policy(true, 4096)).0,
                Prepared::RefusedMultiline
            );
        }
        // Only one trailing break goes, skipped tail or not.
        assert_eq!(
            prepare("a\r\n\r\n\u{200B}", &policy(false, 4096)).0,
            Prepared::Text(vec!['a', '\n'])
        );
    }

    /// PD7 re-review m1-r: a skipped unit *inside* the trailing CRLF — a
    /// lone surrogate or an untypeable scalar between its CR and its LF —
    /// does not split it into a typed CR and a trimmed LF. Untypeable
    /// scalars are skipped first, so the CRLF is still one trailing break:
    /// removed, never an Enter, never refused; the unit is still counted.
    #[test]
    fn a_skipped_unit_inside_the_trailing_crlf_does_not_split_it() {
        let units = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(u16::to_le_bytes).collect() };
        // The review's case: "ls\r" + D800 + "\n" + the terminator.
        let mut bytes = units("ls\r");
        bytes.extend_from_slice(&[0x00, 0xD8]);
        bytes.extend(units("\n"));
        bytes.extend_from_slice(&[0, 0]);
        let (text, bad) = decode_utf16le(&bytes);
        assert_eq!((text.as_str(), bad), ("ls\r\u{FFFD}\n", 1));
        for refuse in [false, true] {
            assert_eq!(
                prepare(&text, &policy(refuse, 4096)),
                (
                    Prepared::Text(vec!['l', 's']),
                    Skips {
                        kept: 2,
                        skipped: 1
                    }
                ),
                "refuse={refuse}"
            );
        }
        // CR, skipped units, LF: any number, any kind, and more after.
        for mid in [
            "\u{FFFD}",
            "\u{200B}",
            "\u{7}",
            "\u{A0}\u{FEFF}",
            "\u{1F600}",
        ] {
            let n = mid.chars().count();
            for after in ["", "\u{200B}"] {
                let text = format!("ls\r{mid}\n{after}");
                let want = n + after.chars().count();
                for refuse in [false, true] {
                    let (p, s) = prepare(&text, &policy(refuse, 4096));
                    assert_eq!(
                        p,
                        Prepared::Text(vec!['l', 's']),
                        "{text:?} refuse={refuse}"
                    );
                    assert_eq!(s.skipped, want, "{text:?}");
                }
            }
        }
        // Inside, the same rule: a skipped unit between CR and LF leaves
        // one Return, not two.
        assert_eq!(
            prepare("a\r\u{200B}\nb", &policy(false, 4096)).0,
            Prepared::Text(vec!['a', '\n', 'b'])
        );
        // And a second trailing break around a skipped CRLF still types
        // exactly one Return.
        assert_eq!(
            prepare("a\r\u{200B}\n\r\u{FFFD}\n", &policy(false, 4096)).0,
            Prepared::Text(vec!['a', '\n'])
        );
    }

    /// PD7 re-review m7: '\r' is a line break, never a skipped scalar — a
    /// CR before the trailing one is a Return (refused under refuse), and a
    /// trailing CR is trimmed, not counted.
    #[test]
    fn a_carriage_return_is_a_break_never_a_skip() {
        assert_eq!(
            prepare("a\r\r", &policy(false, 4096)),
            (
                Prepared::Text(vec!['a', '\n']),
                Skips {
                    kept: 2,
                    skipped: 0
                }
            )
        );
        assert_eq!(
            prepare("a\r\r", &policy(true, 4096)).0,
            Prepared::RefusedMultiline
        );
        assert_eq!(
            prepare("a\r", &policy(false, 4096)),
            (
                Prepared::Text(vec!['a']),
                Skips {
                    kept: 1,
                    skipped: 0
                }
            )
        );
        assert_eq!(
            prepare("a\r\n\r", &policy(false, 4096)).0,
            Prepared::Text(vec!['a', '\n'])
        );
    }

    /// §8: CR, LF and CRLF are one Return each inside the text; only one
    /// trailing break is removed, and multiline = refuse sees what is left.
    #[test]
    fn breaks_inside_the_text_are_one_return_each() {
        let p = |s| prepare(s, &policy(false, 4096)).0;
        assert_eq!(
            p("a\rb\nc\r\nd"),
            Prepared::Text(vec!['a', '\n', 'b', '\n', 'c', '\n', 'd'])
        );
        assert_eq!(p("a\n\r\nb"), Prepared::Text(vec!['a', '\n', '\n', 'b']));
        assert_eq!(p("a\r\n\r\n"), Prepared::Text(vec!['a', '\n']));
        assert_eq!(p("\r\n"), Prepared::Text(vec![]));
        assert_eq!(
            prepare("a\r\n\r\n", &policy(true, 4096)).0,
            Prepared::RefusedMultiline,
            "two trailing breaks: one is removed, one is inside"
        );
        assert_eq!(
            prepare("a\rb", &policy(true, 4096)).0,
            Prepared::RefusedMultiline
        );
    }

    /// §8: other C0 controls, DEL and every non-ASCII scalar are skipped and
    /// counted once each (an emoji is one scalar, two UTF-16 units); the
    /// cap counts kept characters, and what lies past it is not counted.
    #[test]
    fn skips_count_scalars_and_the_cap_counts_kept_characters() {
        let (p, s) = prepare("\u{1b}a\u{7f}é\u{0}b\u{1F600}", &policy(false, 4096));
        assert_eq!(p, Prepared::Text(vec!['a', 'b']));
        assert_eq!(
            s,
            Skips {
                kept: 2,
                skipped: 5
            }
        );
        let (p, s) = prepare("é a b é c", &policy(false, 3));
        assert_eq!(p, Prepared::Text(vec![' ', 'a', ' ']));
        assert_eq!(
            s,
            Skips {
                kept: 3,
                skipped: 1
            }
        );
        let (p, s) = prepare("ab", &policy(false, 0));
        assert_eq!(
            (p, s),
            (
                Prepared::Text(vec![]),
                Skips {
                    kept: 0,
                    skipped: 0
                }
            )
        );
    }

    #[test]
    fn an_empty_typist_is_done_and_types_nothing() {
        let mut t = Typist::new(&[]);
        assert!(t.is_done());
        assert_eq!(t.next(), None);
        // Untypeable characters never reach a stroke.
        let mut t = Typist::new(&['é', '\r']);
        assert!(t.is_done());
        assert_eq!(t.next(), None);
        let mut t = Typist::new(&['x']);
        assert!(!t.is_done());
        t.next();
        assert!(!t.is_done(), "its release is still owed");
        assert_eq!(t.next(), Some(RELEASE));
        assert!(t.is_done());
        assert_eq!(t.next(), None);
    }

    /// §9.2 (PD7 rule: pasted text is as sensitive as a password): the
    /// prepared text and the Typist print counts only — never a character,
    /// a usage or a Shift.
    #[test]
    fn debug_never_prints_the_text() {
        let a = prepare("Zq~", &policy(false, 4096)).0;
        let b = prepare("ab1", &policy(false, 4096)).0;
        let mut ta = Typist::new(&['Z', 'q', '~']);
        let mut tb = Typist::new(&['a', 'b', '1']);
        for _ in 0..3 {
            for (fa, fb) in [
                (format!("{a:?}"), format!("{b:?}")),
                (format!("{a:#?}"), format!("{b:#?}")),
                (format!("{ta:?}"), format!("{tb:?}")),
                (format!("{ta:#?}"), format!("{tb:#?}")),
            ] {
                assert_eq!(fa, fb, "Debug shows the text");
                for leak in ["Z", "q", "~", "'", "29", "20", "53", "0x", "usage", "shift"] {
                    assert!(!fa.contains(leak), "{leak} in {fa}");
                }
            }
            ta.next();
            tb.next();
        }
        assert!(format!("{a:?}").contains('3'), "the length is shown");
    }

    /// xorshift64*: a fixed, seedable sequence for the property below.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
    }

    /// Hostile bytes (§4.1): any `CF_UNICODETEXT` payload decodes, prepares
    /// and types without a panic; the text ends at the first U+0000; at most
    /// `max_chars` characters are typed; the report sequence is press then
    /// all-zero release per character, one key and at most Shift each, and
    /// it always ends released.
    #[test]
    fn any_bytes_type_as_press_release_pairs_and_end_released() {
        #![allow(clippy::arithmetic_side_effects, clippy::as_conversions)]
        let alphabet: [u16; 14] = [
            0,
            b'a' as u16,
            b'Z' as u16,
            b'\r' as u16,
            b'\n' as u16,
            b'\t' as u16,
            b' ' as u16,
            b'~' as u16,
            0x7F,
            0xE9,
            0xD800,
            0xDC00,
            0xD83D,
            0xFFFF,
        ];
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for round in 0..4_000 {
            let len = (rng.next() % 64) as usize;
            let mut bytes = Vec::new();
            for _ in 0..len {
                let u = if rng.next().is_multiple_of(4) {
                    rng.next() as u16
                } else {
                    alphabet[(rng.next() % alphabet.len() as u64) as usize]
                };
                bytes.extend_from_slice(&u.to_le_bytes());
            }
            if rng.next().is_multiple_of(3) {
                bytes.push(rng.next() as u8);
            }
            let (mut text, _) = decode_utf16le(&bytes);
            assert!(!text.contains('\0'), "round {round}");
            // Half the payloads end in a line break, as a copied line does.
            if rng.next().is_multiple_of(2) {
                text.push_str(["\r\n", "\n", "\r"][(rng.next() % 3) as usize]);
            }
            let max = (rng.next() % 40) as usize;
            let refuse = rng.next().is_multiple_of(2);
            let (p, s) = prepare(&text, &policy(refuse, max));
            // m1, m1-r: what §8 skips, appended, inserted anywhere, or put
            // before, inside or after the trailing break, never changes what
            // is typed or refused — only the count (when the cap has room).
            let units = ["\u{FFFD}", "\u{200B}", "\u{7}", "\u{1F600}\u{A0}"];
            let unit = units[(rng.next() % 4) as usize];
            let scalars: Vec<char> = text.chars().collect();
            let n = scalars.len();
            let mut places = vec![n, (rng.next() % (n as u64 + 1)) as usize];
            if text.ends_with("\r\n") {
                places.extend([n - 2, n - 1]);
            } else if text.ends_with(['\n', '\r']) {
                places.push(n - 1);
            }
            for at in places {
                let mut v = scalars.clone();
                v.splice(at..at, unit.chars());
                let with: String = v.into_iter().collect();
                let (p2, s2) = prepare(&with, &policy(refuse, max));
                assert_eq!(
                    p2, p,
                    "round {round}: a skipped unit at {at} changed the text"
                );
                assert_eq!(s2.kept, s.kept, "round {round}");
                assert!(s2.skipped >= s.skipped, "round {round}");
            }
            // A trailing line break is never typed: k trailing breaks (in
            // what survives the skip) type k - 1 Returns at the end.
            let left: String = text
                .chars()
                .filter(|c| *c == '\r' || us_stroke(*c).is_some())
                .collect::<String>()
                .replace("\r\n", "\n")
                .replace('\r', "\n");
            let breaks = left.chars().rev().take_while(|c| *c == '\n').count();
            if let Prepared::Text(v) = &p
                && v.len() < max
                && breaks > 0
            {
                let typed = v.iter().rev().take_while(|c| **c == '\n').count();
                assert_eq!(
                    typed,
                    breaks - 1,
                    "round {round}: a trailing break was typed"
                );
            }
            let chars = match p {
                Prepared::RefusedMultiline => {
                    assert!(refuse, "round {round}");
                    continue;
                }
                Prepared::Text(chars) => chars,
            };
            assert_eq!(s.kept, chars.len(), "round {round}");
            assert!(chars.len() <= max, "round {round}");
            assert!(
                chars.iter().all(|c| us_stroke(*c).is_some()),
                "round {round}"
            );
            let frames: Vec<HidFrame> = Typist::new(&chars).collect();
            assert_eq!(frames.len(), 2 * chars.len(), "round {round}");
            for (pair, c) in frames.chunks(2).zip(&chars) {
                let st = us_stroke(*c).unwrap();
                let want = HidFrame::Keyboard {
                    modifiers: if st.shift { MOD_LSHIFT } else { 0 },
                    keys: [st.usage, 0, 0, 0, 0],
                };
                assert_eq!(pair, [want, RELEASE], "round {round}");
            }
            assert!(frames.last().is_none_or(|f| *f == RELEASE), "round {round}");
        }
    }
}
