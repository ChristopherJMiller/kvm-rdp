//! The pointer's authoritative state (§7.2): absolute position scaled to
//! the current surface, the three-button mask with the released-by-bridge
//! rule (§7.4), and wheel-notch accumulation. It builds §3.3 frames; no I/O.
use kvm_proto::hid::{HidFrame, Wheel, scale_abs};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Button {
    Left,
    Right,
    Middle,
}

impl Button {
    const fn bit(self) -> u8 {
        match self {
            Button::Left => 0x01,
            Button::Right => 0x02,
            Button::Middle => 0x04,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerReport {
    pub frame: HidFrame,
}

#[derive(Debug)]
pub struct Pointer {
    /// The surface's size (Setup sets it, §6.4); before the first Setup,
    /// the advertised default.
    surface: (u16, u16),
    buttons: u8,
    /// Buttons released by the bridge whose client release has not come:
    /// their presses change nothing (§7.4, D3b).
    rbb_buttons: u8,
    pos: Option<(u16, u16)>,
    /// RDP ±120-per-notch rotation, accumulated.
    wheel_accum: i32,
}

impl Default for Pointer {
    fn default() -> Pointer {
        Pointer {
            surface: (1920, 1080),
            buttons: 0,
            rbb_buttons: 0,
            pos: None,
            wheel_accum: 0,
        }
    }
}

impl Pointer {
    pub fn set_surface(&mut self, w: u16, h: u16) {
        self.surface = (w, h);
    }

    fn scaled(&self, x: u16, y: u16) -> (u16, u16) {
        (scale_abs(x, self.surface.0), scale_abs(y, self.surface.1))
    }

    fn at(&mut self, x: u16, y: u16) -> PointerReport {
        let (hx, hy) = self.scaled(x, y);
        self.pos = Some((hx, hy));
        PointerReport {
            frame: HidFrame::AbsMouse {
                buttons: self.buttons,
                x: hx,
                y: hy,
            },
        }
    }

    pub fn moved(&mut self, x: u16, y: u16) -> PointerReport {
        self.at(x, y)
    }

    /// A button event at the client's (x, y) — IronRDP's button events
    /// carry the click position (D8d). A press of a released-by-bridge
    /// button changes nothing (`None`); its release clears the mark.
    pub fn button(&mut self, b: Button, pressed: bool, x: u16, y: u16) -> Option<PointerReport> {
        let bit = b.bit();
        if pressed {
            if self.rbb_buttons & bit != 0 {
                return None;
            }
            self.buttons |= bit;
        } else {
            self.buttons &= !bit;
            self.rbb_buttons &= !bit;
        }
        Some(self.at(x, y))
    }

    /// §7.4: the device's buttons are zeroed by the release the shell sends;
    /// this zeroes the mask to match and marks the held buttons released
    /// by the bridge, so nothing re-presses them (D3b).
    pub fn release_all(&mut self) {
        self.rbb_buttons |= self.buttons;
        self.buttons = 0;
    }

    /// RDP's ±120-per-notch rotation accumulated; one wheel frame per whole
    /// notch (§7.2, §3.3), with the current button mask.
    pub fn wheel(&mut self, units: i16) -> Vec<HidFrame> {
        self.wheel_accum = self.wheel_accum.saturating_add(i32::from(units));
        let mut out = Vec::new();
        while self.wheel_accum >= 120 {
            self.wheel_accum -= 120;
            out.push(HidFrame::Wheel {
                buttons: self.buttons,
                wheel: Wheel::Up,
            });
        }
        while self.wheel_accum <= -120 {
            self.wheel_accum += 120;
            out.push(HidFrame::Wheel {
                buttons: self.buttons,
                wheel: Wheel::Down,
            });
        }
        out
    }

    #[must_use]
    pub fn last(&self) -> Option<(u16, u16)> {
        self.pos
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;
    use kvm_proto::hid::ABS_MAX;

    fn abs(buttons: u8, x: u16, y: u16) -> HidFrame {
        HidFrame::AbsMouse { buttons, x, y }
    }

    #[test]
    fn moves_scale_to_the_surface() {
        let mut p = Pointer::default();
        assert_eq!(
            p.moved(1919, 1079).frame,
            abs(0, 32_767, 32_767),
            "the default 1920×1080"
        );
        p.set_surface(1280, 720);
        assert_eq!(p.moved(0, 0).frame, abs(0, 0, 0));
        assert_eq!(p.moved(1279, 719).frame, abs(0, 32_767, 32_767));
        assert_eq!(p.last(), Some((32_767, 32_767)));
    }

    #[test]
    fn coordinates_outside_the_surface_clamp() {
        let mut p = Pointer::default();
        assert_eq!(p.moved(5000, 5000).frame, abs(0, 32_767, 32_767));
    }

    #[test]
    fn the_button_mask_and_wheel_notches() {
        let mut p = Pointer::default();
        assert_eq!(
            p.button(Button::Left, true, 0, 0).unwrap().frame,
            abs(0x01, 0, 0)
        );
        assert_eq!(
            p.button(Button::Right, true, 0, 0).unwrap().frame,
            abs(0x03, 0, 0)
        );
        assert_eq!(
            p.button(Button::Middle, true, 0, 0).unwrap().frame,
            abs(0x07, 0, 0)
        );
        assert_eq!(
            p.button(Button::Right, false, 0, 0).unwrap().frame,
            abs(0x05, 0, 0)
        );
        assert_eq!(
            p.wheel(240),
            vec![
                HidFrame::Wheel {
                    buttons: 0x05,
                    wheel: Wheel::Up
                };
                2
            ]
        );
        assert!(p.wheel(60).is_empty(), "half a notch accumulates");
        assert_eq!(
            p.wheel(-180),
            vec![HidFrame::Wheel {
                buttons: 0x05,
                wheel: Wheel::Down
            }]
        );
    }

    /// D8d: a click carries its own position — with no prior move it goes
    /// where it was made, never to (0, 0) (§3.3).
    #[test]
    fn a_click_with_no_prior_move_uses_its_own_position() {
        let mut p = Pointer::default();
        assert_eq!(
            p.button(Button::Left, true, 960, 540).unwrap().frame,
            abs(0x01, 16_392, 16_398)
        );
        assert_eq!(p.last(), Some((16_392, 16_398)));
    }

    /// §7.4 (D3b): buttons held at a release are released by the bridge; a
    /// press of one changes nothing until the client's release.
    #[test]
    fn release_all_marks_buttons_released_by_bridge() {
        let mut p = Pointer::default();
        p.button(Button::Left, true, 10, 10).unwrap();
        p.release_all();
        assert_eq!(p.moved(10, 10).frame, abs(0, 170, 303));
        assert!(p.button(Button::Left, true, 10, 10).is_none());
        assert_eq!(
            p.button(Button::Left, false, 10, 10).unwrap().frame,
            abs(0, 170, 303)
        );
        assert_eq!(
            p.button(Button::Left, true, 10, 10).unwrap().frame,
            abs(0x01, 170, 303)
        );
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

    /// §7.4 for the pointer: over any interleaving of presses, releases,
    /// moves, wheel turns, releases-all and surface changes, no frame holds
    /// a button the client does not, every coordinate is in 0..=32767, and
    /// once the client has let go of every button, none is held.
    #[test]
    fn no_sequence_of_events_leaves_a_button_held() {
        let buttons = [Button::Left, Button::Right, Button::Middle];
        let coords = [0u16, 1, 10, 639, 960, 1919, 1920, 5000, u16::MAX];
        let spans = [0u16, 1, 2, 640, 1080, 1920, u16::MAX];
        for seed in 1..=64u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let mut p = Pointer::default();
            let mut down = 0u8; // what the client holds
            for _ in 0..1_000 {
                let (x, y) = (rng.pick(&coords), rng.pick(&coords));
                let frames: Vec<HidFrame> = match rng.below(8) {
                    0..=1 => {
                        let b = rng.pick(&buttons);
                        down |= b.bit();
                        p.button(b, true, x, y)
                            .map(|r| r.frame)
                            .into_iter()
                            .collect()
                    }
                    2..=3 => {
                        let b = rng.pick(&buttons);
                        down &= !b.bit();
                        p.button(b, false, x, y)
                            .map(|r| r.frame)
                            .into_iter()
                            .collect()
                    }
                    4 => vec![p.moved(x, y).frame],
                    5 => p.wheel(rng.pick(&[-240i16, -120, -60, 60, 120, 360])),
                    6 => {
                        p.release_all();
                        Vec::new()
                    }
                    _ => {
                        p.set_surface(rng.pick(&spans), rng.pick(&spans));
                        Vec::new()
                    }
                };
                for f in frames {
                    let held = match f {
                        HidFrame::AbsMouse { buttons, x, y } => {
                            assert!(x <= ABS_MAX && y <= ABS_MAX, "{f:?}");
                            buttons
                        }
                        HidFrame::Wheel { buttons, .. } => buttons,
                        other => panic!("{other:?}"),
                    };
                    assert_eq!(
                        held & !down,
                        0,
                        "seed {seed}: {f:?} holds what the client does not"
                    );
                }
            }
            for b in buttons {
                down &= !b.bit();
                p.button(b, false, 1, 1);
            }
            assert_eq!(down, 0);
            p.set_surface(1920, 1080);
            assert_eq!(
                p.moved(1, 1).frame,
                abs(0, 17, 30),
                "seed {seed}: a button was left held"
            );
        }
    }
}
