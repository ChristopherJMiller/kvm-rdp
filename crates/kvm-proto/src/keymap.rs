//! Keyboard tables (spec §7.1, §8): scancode set 1 → USB HID usages
//! (keyboard page 0x07), the US layout for Unicode key events and pasted
//! text, and `paste.chord`. Tables only; the oracle in `tests` is
//! Microsoft's published translation table (§11.1).

/// The §3.3 keyboard frame's modifier byte.
pub const MOD_LCTRL: u8 = 0x01;
pub const MOD_LSHIFT: u8 = 0x02;
pub const MOD_LALT: u8 = 0x04;
pub const MOD_LGUI: u8 = 0x08;
pub const MOD_RCTRL: u8 = 0x10;
pub const MOD_RSHIFT: u8 = 0x20;
pub const MOD_RALT: u8 = 0x40;
pub const MOD_RGUI: u8 = 0x80;

/// A modifier whichever side it is on (a chord's matching unit).
pub const CLASS_CTRL: u8 = 0x01;
pub const CLASS_SHIFT: u8 = 0x02;
pub const CLASS_ALT: u8 = 0x04;
pub const CLASS_GUI: u8 = 0x08;

pub const USAGE_RETURN: u8 = 0x28;
pub const USAGE_ESC: u8 = 0x29;
pub const USAGE_BACKSPACE: u8 = 0x2A;
pub const USAGE_CAPS_LOCK: u8 = 0x39;

/// The usage for a set-1 make code; `extended` is the `E0` prefix. Pause
/// (`E1 …`) never arrives as such: IronRDP drops EXTENDED1, so it is
/// LCtrl + NumLock (§7.1). Keyboard Power (`E0 5E`) is never sent (DD7).
#[must_use]
pub fn usage_for_scancode(code: u8, extended: bool) -> Option<u8> {
    let usage = if extended {
        extended_usage(code)
    } else {
        base_usage(code)
    };
    (usage != 0).then_some(usage)
}

const fn base_usage(code: u8) -> u8 {
    match code {
        0x01 => 0x29,
        0x02 => 0x1E,
        0x03 => 0x1F,
        0x04 => 0x20,
        0x05 => 0x21,
        0x06 => 0x22,
        0x07 => 0x23,
        0x08 => 0x24,
        0x09 => 0x25,
        0x0A => 0x26,
        0x0B => 0x27,
        0x0C => 0x2D,
        0x0D => 0x2E,
        0x0E => 0x2A,
        0x0F => 0x2B,
        0x10 => 0x14,
        0x11 => 0x1A,
        0x12 => 0x08,
        0x13 => 0x15,
        0x14 => 0x17,
        0x15 => 0x1C,
        0x16 => 0x18,
        0x17 => 0x0C,
        0x18 => 0x12,
        0x19 => 0x13,
        0x1A => 0x2F,
        0x1B => 0x30,
        0x1C => 0x28,
        0x1D => 0xE0,
        0x1E => 0x04,
        0x1F => 0x16,
        0x20 => 0x07,
        0x21 => 0x09,
        0x22 => 0x0A,
        0x23 => 0x0B,
        0x24 => 0x0D,
        0x25 => 0x0E,
        0x26 => 0x0F,
        0x27 => 0x33,
        0x28 => 0x34,
        0x29 => 0x35,
        0x2A => 0xE1,
        0x2B => 0x31,
        0x2C => 0x1D,
        0x2D => 0x1B,
        0x2E => 0x06,
        0x2F => 0x19,
        0x30 => 0x05,
        0x31 => 0x11,
        0x32 => 0x10,
        0x33 => 0x36,
        0x34 => 0x37,
        0x35 => 0x38,
        0x36 => 0xE5,
        0x37 => 0x55,
        0x38 => 0xE2,
        0x39 => 0x2C,
        0x3A => 0x39,
        0x3B => 0x3A,
        0x3C => 0x3B,
        0x3D => 0x3C,
        0x3E => 0x3D,
        0x3F => 0x3E,
        0x40 => 0x3F,
        0x41 => 0x40,
        0x42 => 0x41,
        0x43 => 0x42,
        0x44 => 0x43,
        0x45 => 0x53,
        0x46 => 0x47,
        0x47 => 0x5F,
        0x48 => 0x60,
        0x49 => 0x61,
        0x4A => 0x56,
        0x4B => 0x5C,
        0x4C => 0x5D,
        0x4D => 0x5E,
        0x4E => 0x57,
        0x4F => 0x59,
        0x50 => 0x5A,
        0x51 => 0x5B,
        0x52 => 0x62,
        0x53 => 0x63,
        0x56 => 0x64,
        0x57 => 0x44,
        0x58 => 0x45,
        0x59 => 0x67,
        0x64 => 0x68,
        0x65 => 0x69,
        0x66 => 0x6A,
        0x67 => 0x6B,
        0x68 => 0x6C,
        0x69 => 0x6D,
        0x6A => 0x6E,
        0x6B => 0x6F,
        0x6C => 0x70,
        0x6D => 0x71,
        0x6E => 0x72,
        0x70 => 0x88,
        0x73 => 0x87,
        0x76 => 0x73,
        0x79 => 0x8A,
        0x7B => 0x8B,
        0x7D => 0x89,
        0x7E => 0x85,
        _ => 0,
    }
}

const fn extended_usage(code: u8) -> u8 {
    match code {
        0x1C => 0x58,
        0x1D => 0xE4,
        0x35 => 0x54,
        0x37 => 0x46,
        0x38 => 0xE6,
        0x47 => 0x4A,
        0x48 => 0x52,
        0x49 => 0x4B,
        0x4B => 0x50,
        0x4D => 0x4F,
        0x4F => 0x4D,
        0x50 => 0x51,
        0x51 => 0x4E,
        0x52 => 0x49,
        0x53 => 0x4C,
        0x5B => 0xE3,
        0x5C => 0xE7,
        0x5D => 0x65,
        _ => 0,
    }
}

/// 0xE0..=0xE7 → its bit in the modifier byte.
#[must_use]
pub const fn modifier_bit(usage: u8) -> Option<u8> {
    match usage {
        0xE0 => Some(MOD_LCTRL),
        0xE1 => Some(MOD_LSHIFT),
        0xE2 => Some(MOD_LALT),
        0xE3 => Some(MOD_LGUI),
        0xE4 => Some(MOD_RCTRL),
        0xE5 => Some(MOD_RSHIFT),
        0xE6 => Some(MOD_RALT),
        0xE7 => Some(MOD_RGUI),
        _ => None,
    }
}

/// Modifier bits → class bits: the right-hand nibble folded onto the left.
#[must_use]
pub fn modifier_classes(bits: u8) -> u8 {
    (bits & 0x0F) | (bits & 0xF0).rotate_right(4)
}

/// One key of the US layout: its usage, and whether Shift is needed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Stroke {
    pub usage: u8,
    pub shift: bool,
}

/// §9.2 (PD5 ruling): the Typist types pasted text as strokes, so a
/// stroke's `Debug` shows nothing of the character.
impl core::fmt::Debug for Stroke {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Stroke").finish_non_exhaustive()
    }
}

/// The key a live Unicode key event types (§7.1, rev 6.3; PD11b I5): the US
/// layout's stroke (`us_stroke`), plus the three control keys a client in
/// its Unicode keyboard mode may send as units — CR as Return, BS as
/// Backspace, ESC as Esc, each with no Shift. Paste (§8) keeps `us_stroke`:
/// there CR is a line break and BS and ESC are skipped, never typed.
#[must_use]
pub fn unicode_key_stroke(c: char) -> Option<Stroke> {
    let usage = match c {
        '\r' => USAGE_RETURN,
        '\u{8}' => USAGE_BACKSPACE,
        '\u{1b}' => USAGE_ESC,
        _ => return us_stroke(c),
    };
    Some(Stroke {
        usage,
        shift: false,
    })
}

/// What the US layout types `c` with: printable ASCII, Tab, and `'\n'` as
/// Return (§8 turns CR/LF/CRLF into `'\n'` first). Anything else — control
/// characters, DEL, non-ASCII — has no stroke and is skipped by the caller.
/// (Live Unicode key events go through `unicode_key_stroke`.)
#[must_use]
pub fn us_stroke(c: char) -> Option<Stroke> {
    let b = u8::try_from(c).ok()?;
    let (usage, shift) = match b {
        b'a'..=b'z' => (0x04u8.wrapping_add(b.wrapping_sub(b'a')), false),
        b'A'..=b'Z' => (0x04u8.wrapping_add(b.wrapping_sub(b'A')), true),
        b'1'..=b'9' => (0x1Eu8.wrapping_add(b.wrapping_sub(b'1')), false),
        b'0' => (0x27, false),
        b'!' => (0x1E, true),
        b'@' => (0x1F, true),
        b'#' => (0x20, true),
        b'$' => (0x21, true),
        b'%' => (0x22, true),
        b'^' => (0x23, true),
        b'&' => (0x24, true),
        b'*' => (0x25, true),
        b'(' => (0x26, true),
        b')' => (0x27, true),
        b'\n' => (0x28, false),
        b'\t' => (0x2B, false),
        b' ' => (0x2C, false),
        b'-' => (0x2D, false),
        b'_' => (0x2D, true),
        b'=' => (0x2E, false),
        b'+' => (0x2E, true),
        b'[' => (0x2F, false),
        b'{' => (0x2F, true),
        b']' => (0x30, false),
        b'}' => (0x30, true),
        b'\\' => (0x31, false),
        b'|' => (0x31, true),
        b';' => (0x33, false),
        b':' => (0x33, true),
        b'\'' => (0x34, false),
        b'"' => (0x34, true),
        b'`' => (0x35, false),
        b'~' => (0x35, true),
        b',' => (0x36, false),
        b'<' => (0x36, true),
        b'.' => (0x37, false),
        b'>' => (0x37, true),
        b'/' => (0x38, false),
        b'?' => (0x38, true),
        _ => return None,
    };
    Some(Stroke { usage, shift })
}

/// `paste.chord` (§8): matched on raw client scancodes, before any remap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chord {
    /// `CLASS_*` bits that must be held — exactly these.
    pub classes: u8,
    /// The key's set-1 make code (never extended).
    pub code: u8,
}

impl Chord {
    /// `ctrl+option+shift+v`: one or more distinct modifiers (`ctrl` or
    /// `control`, `shift`, `alt` or `option`, `cmd` or `win`), then one
    /// letter or digit; case and spaces around `+` ignored (DD11).
    #[must_use]
    pub fn parse(s: &str) -> Option<Chord> {
        let parts: Vec<&str> = s.split('+').map(str::trim).collect();
        let (key, mods) = parts.split_last()?;
        if mods.is_empty() {
            return None;
        }
        let mut classes = 0u8;
        for m in mods {
            let class = match m.to_ascii_lowercase().as_str() {
                "ctrl" | "control" => CLASS_CTRL,
                "shift" => CLASS_SHIFT,
                "alt" | "option" => CLASS_ALT,
                "cmd" | "win" => CLASS_GUI,
                _ => return None,
            };
            if classes & class != 0 {
                return None;
            }
            classes |= class;
        }
        let mut chars = key.chars();
        let (Some(k), None) = (chars.next(), chars.next()) else {
            return None;
        };
        if !k.is_ascii_alphanumeric() {
            return None;
        }
        let usage = us_stroke(k.to_ascii_lowercase())?.usage;
        let code = (0x01..=0x7Fu8).find(|c| base_usage(*c) == usage)?;
        Some(Chord { classes, code })
    }

    /// A press of the chord's key with exactly its modifier classes held.
    #[must_use]
    pub fn matches(&self, code: u8, extended: bool, held_modifier_bits: u8) -> bool {
        !extended && code == self.code && modifier_classes(held_modifier_bits) == self.classes
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic
    )]
    use super::*;
    use std::collections::HashMap;

    /// Microsoft, "USB HID to PS/2 Scan Code Translation Table" (Keyboard
    /// Scan Code Specification, Appendix C), Scan Code Set 1 make codes:
    /// (usage, make bytes). The independent oracle §11.1 names.
    const MS_SET1: &[(u8, &[u8])] = &[
        (0x04, &[0x1E]),
        (0x05, &[0x30]),
        (0x06, &[0x2E]),
        (0x07, &[0x20]),
        (0x08, &[0x12]),
        (0x09, &[0x21]),
        (0x0A, &[0x22]),
        (0x0B, &[0x23]),
        (0x0C, &[0x17]),
        (0x0D, &[0x24]),
        (0x0E, &[0x25]),
        (0x0F, &[0x26]),
        (0x10, &[0x32]),
        (0x11, &[0x31]),
        (0x12, &[0x18]),
        (0x13, &[0x19]),
        (0x14, &[0x10]),
        (0x15, &[0x13]),
        (0x16, &[0x1F]),
        (0x17, &[0x14]),
        (0x18, &[0x16]),
        (0x19, &[0x2F]),
        (0x1A, &[0x11]),
        (0x1B, &[0x2D]),
        (0x1C, &[0x15]),
        (0x1D, &[0x2C]),
        (0x1E, &[0x02]),
        (0x1F, &[0x03]),
        (0x20, &[0x04]),
        (0x21, &[0x05]),
        (0x22, &[0x06]),
        (0x23, &[0x07]),
        (0x24, &[0x08]),
        (0x25, &[0x09]),
        (0x26, &[0x0A]),
        (0x27, &[0x0B]),
        (0x28, &[0x1C]),
        (0x29, &[0x01]),
        (0x2A, &[0x0E]),
        (0x2B, &[0x0F]),
        (0x2C, &[0x39]),
        (0x2D, &[0x0C]),
        (0x2E, &[0x0D]),
        (0x2F, &[0x1A]),
        (0x30, &[0x1B]),
        (0x31, &[0x2B]),
        (0x33, &[0x27]),
        (0x34, &[0x28]),
        (0x35, &[0x29]),
        (0x36, &[0x33]),
        (0x37, &[0x34]),
        (0x38, &[0x35]),
        (0x39, &[0x3A]),
        (0x3A, &[0x3B]),
        (0x3B, &[0x3C]),
        (0x3C, &[0x3D]),
        (0x3D, &[0x3E]),
        (0x3E, &[0x3F]),
        (0x3F, &[0x40]),
        (0x40, &[0x41]),
        (0x41, &[0x42]),
        (0x42, &[0x43]),
        (0x43, &[0x44]),
        (0x44, &[0x57]),
        (0x45, &[0x58]),
        (0x46, &[0xE0, 0x37]),
        (0x47, &[0x46]),
        (0x49, &[0xE0, 0x52]),
        (0x4A, &[0xE0, 0x47]),
        (0x4B, &[0xE0, 0x49]),
        (0x4C, &[0xE0, 0x53]),
        (0x4D, &[0xE0, 0x4F]),
        (0x4E, &[0xE0, 0x51]),
        (0x4F, &[0xE0, 0x4D]),
        (0x50, &[0xE0, 0x4B]),
        (0x51, &[0xE0, 0x50]),
        (0x52, &[0xE0, 0x48]),
        (0x53, &[0x45]),
        (0x54, &[0xE0, 0x35]),
        (0x55, &[0x37]),
        (0x56, &[0x4A]),
        (0x57, &[0x4E]),
        (0x58, &[0xE0, 0x1C]),
        (0x59, &[0x4F]),
        (0x5A, &[0x50]),
        (0x5B, &[0x51]),
        (0x5C, &[0x4B]),
        (0x5D, &[0x4C]),
        (0x5E, &[0x4D]),
        (0x5F, &[0x47]),
        (0x60, &[0x48]),
        (0x61, &[0x49]),
        (0x62, &[0x52]),
        (0x63, &[0x53]),
        (0x64, &[0x56]),
        (0x65, &[0xE0, 0x5D]),
        (0x67, &[0x59]),
        (0x68, &[0x64]),
        (0x69, &[0x65]),
        (0x6A, &[0x66]),
        (0x6B, &[0x67]),
        (0x6C, &[0x68]),
        (0x6D, &[0x69]),
        (0x6E, &[0x6A]),
        (0x6F, &[0x6B]),
        (0x70, &[0x6C]),
        (0x71, &[0x6D]),
        (0x72, &[0x6E]),
        (0x73, &[0x76]),
        (0x85, &[0x7E]),
        (0x87, &[0x73]),
        (0x88, &[0x70]),
        (0x89, &[0x7D]),
        (0x8A, &[0x79]),
        (0x8B, &[0x7B]),
        (0xE0, &[0x1D]),
        (0xE1, &[0x2A]),
        (0xE2, &[0x38]),
        (0xE3, &[0xE0, 0x5B]),
        (0xE4, &[0xE0, 0x1D]),
        (0xE5, &[0x36]),
        (0xE6, &[0xE0, 0x38]),
        (0xE7, &[0xE0, 0x5C]),
    ];

    /// Rows of the same table the bridge leaves out, and why: 0x32 (non-US
    /// #) shares 0x31's make code `2B`, which maps to 0x31; 0x48 Pause
    /// (`E1 1D 45`) reaches the server as LCtrl + NumLock with EXTENDED1
    /// dropped (§7.1); 0x66 Keyboard Power (`E0 5E`) is never sent (DD7);
    /// 0x90/0x91 LANG1/LANG2 (`F2`/`F1`) have no break code; 0x8C (Int'l 6,
    /// `5C`) and 0x92–0x94 (LANG3–5, `78`/`77`/`76`) are Japanese/Korean
    /// keys the US Mac never sees — 0x94 (LANG5) shares F24's `76` (D11).
    const EXCLUDED: &[u8] = &[0x32, 0x48, 0x66, 0x8C, 0x90, 0x91, 0x92, 0x93, 0x94];

    #[test]
    fn every_set1_make_code_maps_exactly_as_microsofts_table() {
        let mut want: HashMap<(u8, bool), u8> = HashMap::new();
        for (usage, make) in MS_SET1 {
            assert!(!EXCLUDED.contains(usage));
            let key = match make {
                [c] => (*c, false),
                [0xE0, c] => (*c, true),
                other => panic!("{other:?}"),
            };
            assert!(want.insert(key, *usage).is_none(), "{key:?} twice");
        }
        for code in 0..=255u8 {
            for extended in [false, true] {
                assert_eq!(
                    usage_for_scancode(code, extended),
                    want.get(&(code, extended)).copied(),
                    "{code:#04x} extended={extended}"
                );
            }
        }
        // The fake shifts of Print Screen's make sequence (E0 2A, E0 36)
        // are never mistaken for Shift.
        assert_eq!(usage_for_scancode(0x2A, true), None);
        assert_eq!(usage_for_scancode(0x36, true), None);
        assert_eq!(usage_for_scancode(0x5E, true), None, "Keyboard Power");
    }

    #[test]
    fn modifier_bits_and_classes() {
        let bits: Vec<_> = (0xE0..=0xE7u8).map(|u| modifier_bit(u).unwrap()).collect();
        assert_eq!(bits, [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]);
        assert_eq!(modifier_bit(0xDF), None);
        assert_eq!(modifier_bit(0x04), None);
        // Census: Cmd is the GUI bit 0x08 (`census.md`, Derived decisions).
        assert_eq!(
            modifier_bit(usage_for_scancode(0x5B, true).unwrap()),
            Some(MOD_LGUI)
        );
        assert_eq!(
            modifier_classes(MOD_LCTRL | MOD_RALT),
            CLASS_CTRL | CLASS_ALT
        );
        assert_eq!(modifier_classes(MOD_RSHIFT | MOD_LSHIFT), CLASS_SHIFT);
        assert_eq!(modifier_classes(MOD_RGUI), CLASS_GUI);
        assert_eq!(modifier_classes(0), 0);
    }

    /// The US layout, row by row: (usage, unshifted, shifted).
    const US_ROWS: &[(u8, char, char)] = &[
        (0x1E, '1', '!'),
        (0x1F, '2', '@'),
        (0x20, '3', '#'),
        (0x21, '4', '$'),
        (0x22, '5', '%'),
        (0x23, '6', '^'),
        (0x24, '7', '&'),
        (0x25, '8', '*'),
        (0x26, '9', '('),
        (0x27, '0', ')'),
        (0x2D, '-', '_'),
        (0x2E, '=', '+'),
        (0x2F, '[', '{'),
        (0x30, ']', '}'),
        (0x31, '\\', '|'),
        (0x33, ';', ':'),
        (0x34, '\'', '"'),
        (0x35, '`', '~'),
        (0x36, ',', '<'),
        (0x37, '.', '>'),
        (0x38, '/', '?'),
    ];

    #[test]
    fn the_us_layout_types_every_printable_ascii_character() {
        let k = |usage, shift| Some(Stroke { usage, shift });
        for (i, (lower, upper)) in ('a'..='z').zip('A'..='Z').enumerate() {
            let usage = 0x04 + u8::try_from(i).unwrap();
            assert_eq!(us_stroke(lower), k(usage, false), "{lower}");
            assert_eq!(us_stroke(upper), k(usage, true), "{upper}");
        }
        for (usage, plain, shifted) in US_ROWS {
            assert_eq!(us_stroke(*plain), k(*usage, false), "{plain}");
            assert_eq!(us_stroke(*shifted), k(*usage, true), "{shifted}");
        }
        assert_eq!(us_stroke(' '), k(0x2C, false));
        assert_eq!(us_stroke('\t'), k(0x2B, false));
        assert_eq!(us_stroke('\n'), k(0x28, false));
        let typeable = (0u32..=0xFF)
            .filter_map(char::from_u32)
            .filter(|c| us_stroke(*c).is_some())
            .count();
        assert_eq!(typeable, 95 + 2, "printable ASCII, Tab and Return only");
        for c in ['\r', '\u{7f}', '\u{1b}', 'é', '€', '\u{1F600}', '\0'] {
            assert_eq!(us_stroke(c), None, "{c:?}");
        }
    }

    /// Rev 6.3 (PD11b I5): a live Unicode key event's stroke is the US
    /// layout's, plus CR as Return, BS as Backspace and ESC as Esc (no
    /// Shift) — and only those three: every other scalar maps exactly as
    /// `us_stroke` does, and `us_stroke` (paste's table, §8) still has none
    /// of the three.
    #[test]
    fn a_unicode_key_adds_return_backspace_and_esc_to_the_us_layout() {
        let k = |usage, shift| Some(Stroke { usage, shift });
        assert_eq!(unicode_key_stroke('\r'), k(0x28, false));
        assert_eq!(unicode_key_stroke('\u{8}'), k(0x2A, false));
        assert_eq!(unicode_key_stroke('\u{1b}'), k(0x29, false));
        assert_eq!(unicode_key_stroke('\n'), k(0x28, false));
        for c in ['\r', '\u{8}', '\u{1b}'] {
            assert_eq!(us_stroke(c), None, "{c:?}: paste's table changed");
        }
        for c in (0u32..=0x3_0000).filter_map(char::from_u32) {
            if !matches!(c, '\r' | '\u{8}' | '\u{1b}') {
                assert_eq!(unicode_key_stroke(c), us_stroke(c), "{c:?}");
            }
        }
        assert_eq!(
            (USAGE_RETURN, USAGE_BACKSPACE, USAGE_ESC),
            (0x28, 0x2A, 0x29)
        );
    }

    /// PD5 ruling (§9.2): the Typist turns pasted text into strokes, so a
    /// `Stroke`'s `Debug` shows nothing of the character it types.
    #[test]
    fn a_strokes_debug_prints_nothing_typed() {
        let a = us_stroke('}').unwrap(); // usage 0x30, Shift
        let b = us_stroke('a').unwrap();
        for (fa, fb) in [
            (format!("{a:?}"), format!("{b:?}")),
            (format!("{a:#?}"), format!("{b:#?}")),
        ] {
            assert_eq!(fa, fb, "Debug shows the stroke");
            for leak in ["48", "30", "true", "usage", "shift"] {
                assert!(!fa.contains(leak), "{leak} in {fa}");
            }
        }
    }

    #[test]
    fn chords_parse_and_match_on_raw_modifier_classes() {
        let want = Chord {
            classes: CLASS_CTRL | CLASS_ALT | CLASS_SHIFT,
            code: 0x2F,
        };
        assert_eq!(Chord::parse("ctrl+option+shift+v"), Some(want));
        assert_eq!(Chord::parse("Ctrl + Alt + Shift + V"), Some(want));
        assert_eq!(
            Chord::parse("cmd+1"),
            Some(Chord {
                classes: CLASS_GUI,
                code: 0x02
            })
        );
        for bad in [
            "",
            "v",
            "ctrl+",
            "ctrl+ctrl+v",
            "ctrl+f1",
            "ctrl+vv",
            "hyper+v",
            "ctrl+shift",
            "+v",
            "ctrl+-",
        ] {
            assert_eq!(Chord::parse(bad), None, "{bad:?}");
        }
        // Either side of each modifier counts; nothing more may be held.
        assert!(want.matches(0x2F, false, MOD_LCTRL | MOD_LALT | MOD_RSHIFT));
        assert!(want.matches(0x2F, false, MOD_RCTRL | MOD_RALT | MOD_LSHIFT | MOD_RSHIFT));
        assert!(!want.matches(0x2F, false, MOD_LCTRL | MOD_LALT));
        assert!(!want.matches(0x2F, false, MOD_LCTRL | MOD_LALT | MOD_LSHIFT | MOD_LGUI));
        assert!(!want.matches(0x2F, true, MOD_LCTRL | MOD_LALT | MOD_LSHIFT));
        assert!(!want.matches(0x2E, false, MOD_LCTRL | MOD_LALT | MOD_LSHIFT));
    }
}
