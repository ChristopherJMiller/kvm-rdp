//! The keyboard's authoritative HID state (§7.1, §7.4): five key slots, the
//! modifier byte (raw, as the client holds it), the released-by-bridge set
//! for keys and modifiers, Caps-Lock tracking, Unicode typing through the
//! US layout with its own Shift, and the Mac remap — applied only when a
//! report is built (DD3). Synchronous and O(1); it builds full-state §3.3
//! frames and nothing else.
use kvm_proto::hid::HidFrame;
use kvm_proto::keymap::{
    CLASS_CTRL, MOD_LCTRL, MOD_LGUI, MOD_LSHIFT, MOD_RCTRL, MOD_RGUI, Stroke, USAGE_CAPS_LOCK,
    modifier_bit, modifier_classes, us_stroke, usage_for_scancode,
};

/// At most this many non-modifier keys are tracked at once (DD9); a press
/// past it is dropped and counted. Five are reported (the device's slots).
const MAX_TRACKED: usize = 16;
/// At most this many released-by-bridge usages are remembered (DD9).
const MAX_RBB: usize = 32;

/// DD3: the chords Windows App rewrites from Cmd+letter to Ctrl+letter
/// (§7.1). With `mac_remap` on, a report that holds Ctrl and one of these
/// sends GUI in Ctrl's place; every other Ctrl chord is left alone.
const REMAP_USAGES: [u8; 7] = [0x06, 0x19, 0x1B, 0x04, 0x1D, 0x09, 0x1A]; // c v x a z f w

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyReport {
    /// The full-state keyboard frame after this event.
    pub frame: HidFrame,
    /// No frame need be sent: a held key's repeat, a released-by-bridge
    /// key's repeat, the release of a key not down, or a dropped event.
    pub ignored: bool,
    /// Dropped and counted (DD7, DD9): an untypeable or surrogate Unicode
    /// unit, a press past `MAX_TRACKED`, or (from `release_all`) a held key
    /// `MAX_RBB` had no room to remember. Always `ignored` too, except from
    /// `release_all`, whose zero frame is always sent.
    pub dropped: bool,
}

#[derive(Debug, Default)]
pub struct Keyboard {
    /// Raw modifier bits as the client holds them; never remapped (§8: the
    /// chord is matched before any remap).
    modifiers: u8,
    /// Non-modifier usages currently down, in press order (first five report).
    down: Vec<u8>,
    /// The usages in `down` a Unicode event pressed (D8b). Always a subset
    /// of `down`: whatever brings a usage up removes it here too.
    unicode_down: Vec<u8>,
    /// The latest accepted Unicode press needed Shift; reports carry LShift
    /// while a Unicode-pressed key is down (D8b), and never longer.
    unicode_shift: bool,
    /// Usages (keys and modifiers) released by the bridge whose client
    /// `Released` has not come: their `Pressed` repeats are ignored (§7.4).
    rbb: Vec<u8>,
    caps_lock: bool,
    mac_remap: bool,
}

impl Keyboard {
    pub fn set_mac_remap(&mut self, on: bool) {
        self.mac_remap = on;
    }

    #[must_use]
    pub fn held_modifier_bits(&self) -> u8 {
        self.modifiers
    }

    #[must_use]
    pub fn held_nonmodifier_usages(&self) -> usize {
        self.down.len()
    }

    #[must_use]
    pub fn is_down(&self, usage: u8) -> bool {
        self.down.contains(&usage)
    }

    #[must_use]
    pub fn is_released_by_bridge(&self, usage: u8) -> bool {
        self.rbb.contains(&usage)
    }

    #[must_use]
    pub fn caps_lock_on(&self) -> bool {
        self.caps_lock
    }

    pub fn set_caps_lock(&mut self, on: bool) {
        self.caps_lock = on;
    }

    fn report(&self) -> HidFrame {
        let mut keys = [0u8; 5];
        for (slot, usage) in keys.iter_mut().zip(self.down.iter()) {
            *slot = *usage;
        }
        let mut modifiers = self.modifiers;
        if self.mac_remap
            && modifier_classes(modifiers) & CLASS_CTRL != 0
            && keys.iter().any(|k| REMAP_USAGES.contains(k))
        {
            if modifiers & MOD_LCTRL != 0 {
                modifiers = (modifiers & !MOD_LCTRL) | MOD_LGUI;
            }
            if modifiers & MOD_RCTRL != 0 {
                modifiers = (modifiers & !MOD_RCTRL) | MOD_RGUI;
            }
        }
        if self.unicode_shift {
            modifiers |= MOD_LSHIFT;
        }
        HidFrame::Keyboard { modifiers, keys }
    }

    fn out(&self, ignored: bool, dropped: bool) -> KeyReport {
        KeyReport {
            frame: self.report(),
            ignored,
            dropped,
        }
    }

    /// A scancode press. `None` only when the key maps to nothing.
    pub fn press(&mut self, code: u8, extended: bool) -> Option<KeyReport> {
        let usage = usage_for_scancode(code, extended)?;
        Some(self.press_usage(usage))
    }

    /// A scancode release. `None` only when the key maps to nothing.
    pub fn release(&mut self, code: u8, extended: bool) -> Option<KeyReport> {
        let usage = usage_for_scancode(code, extended)?;
        Some(self.release_usage(usage))
    }

    /// A Unicode key event: the US-layout stroke's usage, with Shift from
    /// this press alone (D8b). An untypeable or surrogate unit is dropped
    /// (DD7). Always `Some`.
    pub fn unicode_press(&mut self, unit: u16) -> Option<KeyReport> {
        let Some(Stroke { usage, shift }) = char::from_u32(u32::from(unit)).and_then(us_stroke)
        else {
            return Some(self.out(true, true));
        };
        let r = self.press_usage(usage);
        if r.ignored {
            return Some(r);
        }
        self.unicode_shift = shift;
        if !self.unicode_down.contains(&usage) {
            self.unicode_down.push(usage);
        }
        Some(self.out(false, false))
    }

    /// A Unicode key release, by its unit's usage. Always `Some`.
    pub fn unicode_release(&mut self, unit: u16) -> Option<KeyReport> {
        let Some(Stroke { usage, .. }) = char::from_u32(u32::from(unit)).and_then(us_stroke) else {
            return Some(self.out(true, true));
        };
        Some(self.release_usage(usage))
    }

    fn press_usage(&mut self, usage: u8) -> KeyReport {
        if self.rbb.contains(&usage) {
            return self.out(true, false); // §7.4: released by the bridge
        }
        if let Some(bit) = modifier_bit(usage) {
            if self.modifiers & bit != 0 {
                return self.out(true, false);
            }
            self.modifiers |= bit;
            return self.out(false, false);
        }
        if self.down.contains(&usage) {
            return self.out(true, false);
        }
        if self.down.len() >= MAX_TRACKED {
            return self.out(true, true); // DD9: bounded, counted
        }
        self.down.push(usage);
        if usage == USAGE_CAPS_LOCK {
            self.caps_lock = !self.caps_lock; // DD5
        }
        self.out(false, false)
    }

    fn release_usage(&mut self, usage: u8) -> KeyReport {
        self.rbb.retain(|u| *u != usage);
        if let Some(bit) = modifier_bit(usage) {
            if self.modifiers & bit == 0 {
                return self.out(true, false);
            }
            self.modifiers &= !bit;
            return self.out(false, false);
        }
        // Whichever release brings a Unicode-pressed usage up — by unit or
        // by scancode — ends its Shift with it: LShift is never left in the
        // reports once nothing the timers watch is held (§7.4).
        self.unicode_down.retain(|u| *u != usage);
        if self.unicode_down.is_empty() {
            self.unicode_shift = false;
        }
        let before = self.down.len();
        self.down.retain(|u| *u != usage);
        if self.down.len() == before {
            return self.out(true, false);
        }
        self.out(false, false)
    }

    /// Remember `usage` as released by the bridge (§7.4): its presses are
    /// ignored until its release. False when `MAX_RBB` is full.
    pub fn mark_released_by_bridge(&mut self, usage: u8) -> bool {
        if self.rbb.contains(&usage) {
            return true;
        }
        if self.rbb.len() >= MAX_RBB {
            return false;
        }
        self.rbb.push(usage);
        true
    }

    /// §7.4: everything up, zeroed. Held keys AND held modifiers (D3a)
    /// become released-by-bridge, so their repeats are ignored until the
    /// client releases them; `dropped` if `MAX_RBB` could not hold one.
    pub fn release_all(&mut self) -> KeyReport {
        let mods = self.modifiers;
        let mut held: Vec<u8> = (0xE0..=0xE7u8)
            .filter(|u| modifier_bit(*u).is_some_and(|b| mods & b != 0))
            .collect();
        held.append(&mut self.down);
        let mut dropped = false;
        for usage in held {
            dropped |= !self.mark_released_by_bridge(usage);
        }
        self.modifiers = 0;
        self.unicode_down.clear();
        self.unicode_shift = false;
        KeyReport {
            frame: self.report(),
            ignored: false,
            dropped,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;
    use kvm_proto::keymap::Chord;

    fn kbd(modifiers: u8, keys: [u8; 5]) -> HidFrame {
        HidFrame::Keyboard { modifiers, keys }
    }

    fn one(modifiers: u8, k: u8) -> HidFrame {
        kbd(modifiers, [k, 0, 0, 0, 0])
    }

    /// The frame of a report that must be sent.
    fn sent(r: Option<KeyReport>) -> HidFrame {
        let r = r.unwrap();
        assert!(!r.ignored && !r.dropped, "{r:?}");
        r.frame
    }

    fn ignored(r: Option<KeyReport>) -> bool {
        let r = r.unwrap();
        r.ignored && !r.dropped
    }

    #[test]
    fn five_slots_then_a_sixth_reported_when_one_frees() {
        let mut k = Keyboard::default();
        for code in [0x1E, 0x1F, 0x20, 0x21, 0x22] {
            sent(k.press(code, false));
        }
        // 'h': tracked, but every slot is full, so the frame is unchanged.
        assert_eq!(
            sent(k.press(0x23, false)),
            kbd(0, [0x04, 0x16, 0x07, 0x09, 0x0A])
        );
        assert_eq!(k.held_nonmodifier_usages(), 6);
        // 'a' up: 'h' moves into the fifth slot.
        assert_eq!(
            sent(k.release(0x1E, false)),
            kbd(0, [0x16, 0x07, 0x09, 0x0A, 0x0B])
        );
    }

    #[test]
    fn a_repeat_is_ignored() {
        let mut k = Keyboard::default();
        assert_eq!(sent(k.press(0x1E, false)), one(0, 0x04));
        let r = k.press(0x1E, false).unwrap();
        assert_eq!((r.frame, r.ignored, r.dropped), (one(0, 0x04), true, false));
        assert_eq!(k.held_nonmodifier_usages(), 1);
        assert_eq!(sent(k.press(0x2A, false)), one(0x02, 0x04));
        assert!(ignored(k.press(0x2A, false)), "a modifier's repeat too");
    }

    #[test]
    fn modifiers_go_to_the_byte_either_side() {
        let mut k = Keyboard::default();
        assert_eq!(sent(k.press(0x2A, false)), one(0x02, 0)); // LShift
        assert_eq!(sent(k.press(0x1D, true)), one(0x12, 0)); // RCtrl
        assert_eq!(sent(k.press(0x36, false)), one(0x32, 0)); // RShift
        assert_eq!(sent(k.press(0x5B, true)), one(0x3A, 0)); // LGUI
        assert_eq!(
            k.held_nonmodifier_usages(),
            0,
            "a modifier never takes a slot"
        );
        assert_eq!(sent(k.release(0x2A, false)), one(0x38, 0));
        assert_eq!(k.held_modifier_bits(), 0x38);
    }

    /// §7.4 (D3a): keys AND modifiers held at a release are released by
    /// the bridge; their repeats change nothing until the client's release.
    #[test]
    fn release_all_marks_keys_and_modifiers_released_by_bridge() {
        let mut k = Keyboard::default();
        sent(k.press(0x1D, false));
        assert_eq!(sent(k.press(0x1E, false)), one(0x01, 0x04));
        let r = k.release_all();
        assert_eq!((r.frame, r.ignored, r.dropped), (one(0, 0), false, false));
        assert!(ignored(k.press(0x1E, false)), "a's repeat");
        assert!(ignored(k.press(0x1D, false)), "LCtrl's repeat");
        assert_eq!(k.held_modifier_bits(), 0);
        assert!(ignored(k.release(0x1D, false)), "the KVM already has it up");
        assert_eq!(sent(k.press(0x1D, false)), one(0x01, 0));
        assert!(ignored(k.release(0x1E, false)));
        assert_eq!(sent(k.press(0x1E, false)), one(0x01, 0x04));
    }

    /// §7.1, D8b: a Unicode key types its US stroke; Shift comes only from
    /// the latest accepted Unicode press and never clears a physical Shift;
    /// repeats and released-by-bridge units are ignored; a lone surrogate
    /// or an untypeable unit is dropped (counted, DD7).
    #[test]
    fn unicode_keys_type_through_the_us_layout_and_follow_the_rbb_rule() {
        let mut k = Keyboard::default();
        assert_eq!(sent(k.unicode_press(u16::from(b'A'))), one(0x02, 0x04));
        assert!(ignored(k.unicode_press(u16::from(b'A'))), "a repeat");
        // '1' while 'A' is still down: unshifted — '1', never '!'.
        assert_eq!(
            sent(k.unicode_press(u16::from(b'1'))),
            kbd(0, [0x04, 0x1E, 0, 0, 0])
        );
        sent(k.unicode_release(u16::from(b'1')));
        assert_eq!(sent(k.unicode_release(u16::from(b'A'))), one(0, 0));
        assert_eq!(sent(k.unicode_press(u16::from(b'1'))), one(0, 0x1E));
        k.release_all();
        assert!(
            ignored(k.unicode_press(u16::from(b'1'))),
            "released by the bridge"
        );
        assert!(ignored(k.unicode_release(u16::from(b'1'))));
        assert_eq!(sent(k.unicode_press(u16::from(b'1'))), one(0, 0x1E));
        sent(k.unicode_release(u16::from(b'1')));
        // A physical Shift survives a Unicode release.
        sent(k.press(0x2A, false));
        sent(k.unicode_press(u16::from(b'a')));
        assert_eq!(sent(k.unicode_release(u16::from(b'a'))), one(0x02, 0));
        for unit in [0xD800u16, 0x00E9] {
            let r = k.unicode_press(unit).unwrap();
            assert!(r.ignored && r.dropped, "{unit:#x}: {r:?}");
            assert_eq!(r.frame, one(0x02, 0));
        }
    }

    /// The Unicode Shift lives only as long as a Unicode-pressed key is
    /// down, however that key comes up: a scancode release of the same
    /// usage must not leave LShift in every later report with nothing the
    /// timers watch still held (§7.4: a key is never left held).
    #[test]
    fn a_unicode_shift_ends_when_its_key_comes_up_by_any_release() {
        let mut k = Keyboard::default();
        assert_eq!(sent(k.unicode_press(u16::from(b'A'))), one(0x02, 0x04));
        // The client releases 'a' by scancode, not by unit.
        assert_eq!(sent(k.release(0x1E, false)), one(0, 0));
        assert_eq!(
            (k.held_modifier_bits(), k.held_nonmodifier_usages()),
            (0, 0)
        );
        assert_eq!(sent(k.press(0x30, false)), one(0, 0x05), "'b' is not 'B'");
        sent(k.release(0x30, false));
        // A second Unicode key still down keeps its Shift.
        sent(k.unicode_press(u16::from(b'A')));
        assert_eq!(
            sent(k.unicode_press(u16::from(b'B'))),
            kbd(0x02, [0x04, 0x05, 0, 0, 0])
        );
        assert_eq!(sent(k.release(0x1E, false)), one(0x02, 0x05));
        assert_eq!(sent(k.unicode_release(u16::from(b'B'))), one(0, 0));
    }

    /// DD3 (D8a): with the remap on, Ctrl becomes GUI only beside
    /// C/V/X/A/Z/F/W; other Ctrl chords, the raw held bits (which the
    /// paste chord reads, §8) and a real GUI are left alone.
    #[test]
    fn mac_remap_moves_ctrl_to_gui_only_for_the_set() {
        let mut k = Keyboard::default();
        k.set_mac_remap(true);
        sent(k.press(0x1D, false));
        assert_eq!(
            sent(k.press(0x2E, false)),
            one(0x08, 0x06),
            "Ctrl+C → Cmd+C"
        );
        sent(k.release(0x2E, false));
        assert_eq!(sent(k.press(0x14, false)), one(0x01, 0x17), "Ctrl+T stays");
        sent(k.release(0x14, false));
        sent(k.release(0x1D, false));
        sent(k.press(0x1D, true));
        assert_eq!(
            sent(k.press(0x2F, false)),
            one(0x80, 0x19),
            "RCtrl+V → RCmd+V"
        );
        sent(k.release(0x2F, false));
        sent(k.release(0x1D, true));
        sent(k.press(0x1D, false));
        sent(k.press(0x38, false));
        sent(k.press(0x2A, false));
        let chord = Chord::parse("ctrl+option+shift+v").unwrap();
        assert!(
            chord.matches(0x2F, false, k.held_modifier_bits()),
            "the chord sees raw bits"
        );
        // With C held as well the report remaps, but the held bits — and
        // with them the chord — stay raw.
        assert_eq!(sent(k.press(0x2E, false)), one(0x0E, 0x06));
        assert_eq!(k.held_modifier_bits(), 0x07);
        assert!(chord.matches(0x2F, false, k.held_modifier_bits()));
        let mut k = Keyboard::default();
        k.set_mac_remap(true);
        assert_eq!(sent(k.press(0x5B, true)), one(0x08, 0));
        assert_eq!(sent(k.press(0x1D, false)), one(0x09, 0));
        assert_eq!(
            sent(k.release(0x1D, false)),
            one(0x08, 0),
            "a real GUI stays held"
        );
    }

    /// DD3's set, exactly: of every mapped non-modifier key, with LCtrl held
    /// and the remap on, only C, V, X, A, Z, F and W carry GUI instead; with
    /// the remap off, none does.
    #[test]
    fn the_remap_set_is_exactly_c_v_x_a_z_f_w() {
        let mut remapped = Vec::new();
        for extended in [false, true] {
            for code in 0..=0x7Fu8 {
                let Some(usage) = usage_for_scancode(code, extended) else {
                    continue;
                };
                if modifier_bit(usage).is_some() {
                    continue;
                }
                let mut k = Keyboard::default();
                sent(k.press(0x1D, false));
                assert_eq!(
                    sent(k.press(code, extended)),
                    one(0x01, usage),
                    "off: {code:#x}"
                );
                let mut k = Keyboard::default();
                k.set_mac_remap(true);
                sent(k.press(0x1D, false));
                let f = sent(k.press(code, extended));
                if f == one(0x08, usage) {
                    remapped.push((code, extended));
                } else {
                    assert_eq!(f, one(0x01, usage), "on: {code:#x}");
                }
            }
        }
        // Set-1 make codes: w a f z x c v.
        let want: Vec<(u8, bool)> = [0x11, 0x1E, 0x21, 0x2C, 0x2D, 0x2E, 0x2F]
            .map(|c| (c, false))
            .to_vec();
        assert_eq!(remapped, want);
    }

    /// DD5 (D8c): Caps Lock follows each fresh press; a repeat or a
    /// released-by-bridge press does not toggle it.
    #[test]
    fn caps_lock_toggles_on_each_fresh_press() {
        let mut k = Keyboard::default();
        k.set_caps_lock(false);
        sent(k.press(0x3A, false));
        assert!(k.caps_lock_on());
        assert!(ignored(k.press(0x3A, false)));
        assert!(k.caps_lock_on(), "a repeat does not toggle");
        sent(k.release(0x3A, false));
        sent(k.press(0x3A, false));
        assert!(!k.caps_lock_on());
        k.release_all();
        assert!(ignored(k.press(0x3A, false)));
        assert!(
            !k.caps_lock_on(),
            "a released-by-bridge repeat does not toggle"
        );
    }

    /// DD9: at most 16 non-modifier keys are tracked; the rest are dropped
    /// and counted, and the frame stays one constant-size report.
    #[test]
    fn a_flood_of_distinct_presses_is_bounded() {
        let mut k = Keyboard::default();
        let codes: Vec<u8> = (0x10..=0x1B)
            .chain(0x1E..=0x28)
            .chain(0x2C..=0x35)
            .chain(0x02..=0x08)
            .collect();
        assert_eq!(codes.len(), 40);
        let dropped = codes
            .iter()
            .filter(|c| k.press(**c, false).unwrap().dropped)
            .count();
        assert_eq!((k.held_nonmodifier_usages(), dropped), (16, 24));
        assert_eq!(k.release_all().frame, one(0, 0));
    }

    #[test]
    fn an_unmapped_scancode_maps_to_nothing() {
        let mut k = Keyboard::default();
        assert!(k.press(0x54, false).is_none());
        assert!(k.release(0x54, false).is_none());
    }

    /// D3c's hook: a key the paste path swallowed is released by the
    /// bridge, so its repeats after the paste are not fresh presses.
    #[test]
    fn a_key_marked_released_by_bridge_waits_for_its_release() {
        let mut k = Keyboard::default();
        assert!(k.mark_released_by_bridge(0x19));
        assert!(k.is_released_by_bridge(0x19));
        assert!(ignored(k.press(0x2F, false)));
        assert!(ignored(k.release(0x2F, false)));
        assert_eq!(sent(k.press(0x2F, false)), one(0, 0x19));
        assert!(k.is_down(0x19));
    }

    /// xorshift64*: a fixed, seedable sequence for the property test.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
        }

        fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
            xs[self.below(xs.len())]
        }
    }

    fn unit_usage(unit: u16) -> Option<u8> {
        char::from_u32(u32::from(unit))
            .and_then(us_stroke)
            .map(|s| s.usage)
    }

    /// One frame against what the client holds: (1) it holds nothing the
    /// client does not; (2) whatever it holds, `held_*` — what the core's
    /// two timers watch (Task 2.2) — says something is held, so a timer can
    /// always release it.
    fn check(
        k: &Keyboard,
        f: HidFrame,
        codes_down: &[(u8, bool)],
        units_down: &[u16],
        remap: bool,
    ) {
        let HidFrame::Keyboard { modifiers, keys } = f else {
            panic!("{f:?}");
        };
        let held: Vec<u8> = codes_down
            .iter()
            .filter_map(|(c, e)| usage_for_scancode(*c, *e))
            .chain(units_down.iter().filter_map(|u| unit_usage(*u)))
            .collect();
        let typing = units_down.iter().any(|u| unit_usage(*u).is_some());
        for key in keys.iter().filter(|key| **key != 0) {
            assert!(
                held.contains(key),
                "{key:#x} held in {f:?}, client holds {held:x?}"
            );
        }
        for i in 0..8u8 {
            let bit = 1u8 << i;
            if modifiers & bit == 0 {
                continue;
            }
            let ok = held.contains(&(0xE0 + i))
                || (bit == MOD_LSHIFT && typing)
                || (remap && bit == MOD_LGUI && held.contains(&0xE0))
                || (remap && bit == MOD_RGUI && held.contains(&0xE4));
            assert!(ok, "{bit:#x} held in {f:?}, client holds {held:x?}");
        }
        if f != one(0, 0) {
            assert!(
                k.held_nonmodifier_usages() > 0 || k.held_modifier_bits() != 0,
                "{f:?} is held but no timer would see it"
            );
        }
        assert!(k.held_nonmodifier_usages() <= MAX_TRACKED);
    }

    /// The core property (§7.4: "every HID path ends released"): over any
    /// interleaving of presses, repeats, stray releases, Unicode events,
    /// releases-all, bridge marks and remap or Caps-Lock changes, every
    /// frame passes `check`, and once the client has let go of everything
    /// the frame is all zero.
    #[test]
    fn no_sequence_of_events_leaves_a_key_held() {
        // Letters (the remap's set among them), digits, both sides of every
        // modifier, Caps Lock, extended keys, and an unmapped code.
        let codes: Vec<(u8, bool)> = (0x10..=0x1B)
            .chain(0x1E..=0x26)
            .chain(0x2C..=0x32)
            .chain(0x02..=0x04)
            .map(|c| (c, false))
            .chain([
                (0x1D, false),
                (0x1D, true),
                (0x2A, false),
                (0x36, false),
                (0x38, false),
                (0x38, true),
                (0x5B, true),
                (0x5C, true),
                (0x3A, false),
                (0x48, true),
                (0x54, false),
            ])
            .collect();
        let units: Vec<u16> = "AaVvZz1!\n"
            .encode_utf16()
            .chain([0xD800, 0x00E9])
            .collect();
        for seed in 1..=64u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let mut k = Keyboard::default();
            let mut codes_down: Vec<(u8, bool)> = Vec::new();
            let mut units_down: Vec<u16> = Vec::new();
            let mut remap = false;
            for _ in 0..2_000 {
                let r = match rng.below(16) {
                    0..=4 => {
                        let c = rng.pick(&codes);
                        if !codes_down.contains(&c) {
                            codes_down.push(c);
                        }
                        k.press(c.0, c.1)
                    }
                    5..=7 => {
                        // Mostly a held key; sometimes a stray release.
                        let c = if !codes_down.is_empty() && rng.below(4) != 0 {
                            rng.pick(&codes_down)
                        } else {
                            rng.pick(&codes)
                        };
                        codes_down.retain(|d| *d != c);
                        k.release(c.0, c.1)
                    }
                    8..=9 => {
                        let u = rng.pick(&units);
                        if !units_down.contains(&u) {
                            units_down.push(u);
                        }
                        k.unicode_press(u)
                    }
                    10..=11 => {
                        let u = if !units_down.is_empty() && rng.below(4) != 0 {
                            rng.pick(&units_down)
                        } else {
                            rng.pick(&units)
                        };
                        units_down.retain(|d| *d != u);
                        k.unicode_release(u)
                    }
                    12 => {
                        // Its zero frame is always sent, dropped or not.
                        let r = k.release_all();
                        assert!(!r.ignored);
                        assert_eq!(r.frame, one(0, 0));
                        check(&k, r.frame, &codes_down, &units_down, remap);
                        None
                    }
                    13 => {
                        let (c, e) = rng.pick(&codes);
                        if let Some(usage) = usage_for_scancode(c, e) {
                            k.mark_released_by_bridge(usage);
                        }
                        None
                    }
                    14 => {
                        remap = rng.below(2) == 0;
                        k.set_mac_remap(remap);
                        None
                    }
                    _ => {
                        k.set_caps_lock(rng.below(2) == 0);
                        None
                    }
                };
                if let Some(r) = r {
                    assert!(!r.dropped || r.ignored, "dropped is always ignored: {r:?}");
                    check(&k, r.frame, &codes_down, &units_down, remap);
                }
            }
            // The client lets go of everything, in its own order.
            while !codes_down.is_empty() {
                let c = codes_down.remove(rng.below(codes_down.len()));
                if let Some(r) = k.release(c.0, c.1) {
                    check(&k, r.frame, &codes_down, &units_down, remap);
                }
            }
            while !units_down.is_empty() {
                let u = units_down.remove(rng.below(units_down.len()));
                let r = k.unicode_release(u).unwrap();
                check(&k, r.frame, &codes_down, &units_down, remap);
            }
            assert_eq!(
                (k.held_modifier_bits(), k.held_nonmodifier_usages()),
                (0, 0)
            );
            // F12 is never pressed: its release only reads the state.
            let r = k.release(0x58, false).unwrap();
            assert!(r.ignored);
            assert_eq!(r.frame, one(0, 0), "seed {seed}: a key was left held");
        }
    }
}
