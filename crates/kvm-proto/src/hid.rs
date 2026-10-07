//! The ES3's websocket HID frames (§3.3), byte-exact with the vendor's
//! `kvm.js`: the encoders the bridge sends with, and the decoder kvm-sim
//! records with.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

/// Largest absolute coordinate (§3.3: x, y in 0..=32767).
pub const ABS_MAX: u16 = 32_767;

/// Wheel direction: one notch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wheel {
    Up,
    Down,
}

/// One HID frame on the control websocket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidFrame {
    /// `88 88 01 <0x30 + hid_type>`; type 0 is absolute mouse.
    SetMode { hid_type: u8 },
    /// `AA AA 08 00 mod 00 00 k1 k2 k3 k4 k5` (12 bytes).
    Keyboard { modifiers: u8, keys: [u8; 5] },
    /// `AA AA 05 51 btn xLo xHi yLo yHi` (9 bytes), x and y ≤ 32767.
    AbsMouse { buttons: u8, x: u16, y: u16 },
    /// `AA AA 04 20 btn 00 00 w` (8 bytes), `w` = `01` up / `FF` down.
    Wheel { buttons: u8, wheel: Wheel },
}

/// Why a websocket message is not a §3.3 HID frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidDecodeError {
    Unknown,
    BadLength,
    CoordinateOutOfRange,
}

impl HidFrame {
    /// Absolute-mouse frame with x and y clamped to `ABS_MAX`.
    #[must_use]
    pub fn abs_mouse(buttons: u8, x: u16, y: u16) -> HidFrame {
        HidFrame::AbsMouse {
            buttons,
            x: x.min(ABS_MAX),
            y: y.min(ABS_MAX),
        }
    }

    /// Append the frame's bytes to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match *self {
            HidFrame::SetMode { hid_type } => {
                out.extend_from_slice(&[0x88, 0x88, 0x01, 0x30_u8.wrapping_add(hid_type)]);
            }
            HidFrame::Keyboard { modifiers, keys } => {
                out.extend_from_slice(&[0xAA, 0xAA, 0x08, 0x00, modifiers, 0x00, 0x00]);
                out.extend_from_slice(&keys);
            }
            HidFrame::AbsMouse { buttons, x, y } => {
                let [x_lo, x_hi] = x.min(ABS_MAX).to_le_bytes();
                let [y_lo, y_hi] = y.min(ABS_MAX).to_le_bytes();
                out.extend_from_slice(&[0xAA, 0xAA, 0x05, 0x51, buttons, x_lo, x_hi, y_lo, y_hi]);
            }
            HidFrame::Wheel { buttons, wheel } => {
                let w = match wheel {
                    Wheel::Up => 0x01,
                    Wheel::Down => 0xFF,
                };
                out.extend_from_slice(&[0xAA, 0xAA, 0x04, 0x20, buttons, 0x00, 0x00, w]);
            }
        }
    }

    /// The frame's bytes.
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(12);
        self.encode(&mut v);
        v
    }

    /// Decode one websocket message.
    pub fn decode(msg: &[u8]) -> Result<HidFrame, HidDecodeError> {
        match msg {
            [0x88, 0x88, 0x01, t] => t
                .checked_sub(0x30)
                .map(|hid_type| HidFrame::SetMode { hid_type })
                .ok_or(HidDecodeError::Unknown),
            [0xAA, 0xAA, 0x08, 0x00, m, 0x00, 0x00, k1, k2, k3, k4, k5] => Ok(HidFrame::Keyboard {
                modifiers: *m,
                keys: [*k1, *k2, *k3, *k4, *k5],
            }),
            [0xAA, 0xAA, 0x05, 0x51, b, x_lo, x_hi, y_lo, y_hi] => {
                let x = u16::from_le_bytes([*x_lo, *x_hi]);
                let y = u16::from_le_bytes([*y_lo, *y_hi]);
                if x > ABS_MAX || y > ABS_MAX {
                    return Err(HidDecodeError::CoordinateOutOfRange);
                }
                Ok(HidFrame::AbsMouse { buttons: *b, x, y })
            }
            [0xAA, 0xAA, 0x04, 0x20, b, 0x00, 0x00, w] => match w {
                0x01 => Ok(HidFrame::Wheel {
                    buttons: *b,
                    wheel: Wheel::Up,
                }),
                0xFF => Ok(HidFrame::Wheel {
                    buttons: *b,
                    wheel: Wheel::Down,
                }),
                _ => Err(HidDecodeError::Unknown),
            },
            [0x88, 0x88, 0x01, ..] | [0xAA, 0xAA, 0x08 | 0x05 | 0x04, ..] => {
                Err(HidDecodeError::BadLength)
            }
            _ => Err(HidDecodeError::Unknown),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// Goldens from §3.3's byte layouts (independent of the encoder).
    #[test]
    fn encoders_match_section_3_3() {
        assert_eq!(
            HidFrame::SetMode { hid_type: 0 }.to_vec(),
            [0x88, 0x88, 0x01, 0x30]
        );
        // Shift + 'a' (usage 0x04) in slot 1.
        assert_eq!(
            HidFrame::Keyboard {
                modifiers: 0x02,
                keys: [0x04, 0, 0, 0, 0]
            }
            .to_vec(),
            [
                0xAA, 0xAA, 0x08, 0x00, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00
            ]
        );
        // Left button at (16384, 8192): little-endian coordinates.
        assert_eq!(
            HidFrame::abs_mouse(0x01, 16_384, 8_192).to_vec(),
            [0xAA, 0xAA, 0x05, 0x51, 0x01, 0x00, 0x40, 0x00, 0x20]
        );
        assert_eq!(
            HidFrame::abs_mouse(0, 32_767, 0).to_vec(),
            [0xAA, 0xAA, 0x05, 0x51, 0x00, 0xFF, 0x7F, 0x00, 0x00]
        );
        assert_eq!(
            HidFrame::Wheel {
                buttons: 0x01,
                wheel: Wheel::Up
            }
            .to_vec(),
            [0xAA, 0xAA, 0x04, 0x20, 0x01, 0x00, 0x00, 0x01]
        );
        assert_eq!(
            HidFrame::Wheel {
                buttons: 0,
                wheel: Wheel::Down
            }
            .to_vec(),
            [0xAA, 0xAA, 0x04, 0x20, 0x00, 0x00, 0x00, 0xFF]
        );
    }

    #[test]
    fn coordinates_clamp_to_32767() {
        assert_eq!(
            HidFrame::abs_mouse(0, u16::MAX, 40_000),
            HidFrame::AbsMouse {
                buttons: 0,
                x: 32_767,
                y: 32_767
            }
        );
    }

    #[test]
    fn decode_inverts_encode_and_refuses_the_rest() {
        let frames = [
            HidFrame::SetMode { hid_type: 0 },
            HidFrame::Keyboard {
                modifiers: 0x08,
                keys: [0x06, 0x19, 0, 0, 0],
            },
            HidFrame::abs_mouse(0x07, 123, 32_767),
            HidFrame::Wheel {
                buttons: 0,
                wheel: Wheel::Down,
            },
        ];
        for f in frames {
            assert_eq!(HidFrame::decode(&f.to_vec()), Ok(f));
        }
        assert_eq!(
            HidFrame::decode(&[0xAA, 0xAA, 0x08]),
            Err(HidDecodeError::BadLength)
        );
        assert_eq!(
            HidFrame::decode(&[0xAA, 0xAA, 0x05, 0x51, 0, 0x00, 0x80, 0, 0]),
            Err(HidDecodeError::CoordinateOutOfRange)
        );
        assert_eq!(
            HidFrame::decode(&[0x88, 0x88, 0x03, b'h']),
            Err(HidDecodeError::Unknown)
        );
        assert_eq!(HidFrame::decode(&[]), Err(HidDecodeError::Unknown));
    }
}
