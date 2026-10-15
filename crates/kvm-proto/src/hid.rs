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

/// §7.2: scale a client coordinate `v` on a `span`-wide (or -tall) axis to
/// 0..=`ABS_MAX`, clamped. `span <= 1` (an unknown or degenerate surface)
/// maps everything to 0.
#[must_use]
pub fn scale_abs(v: u16, span: u16) -> u16 {
    let Some(last) = span.checked_sub(1) else {
        return 0;
    };
    let v = u32::from(v.min(last));
    let scaled = v
        .saturating_mul(u32::from(ABS_MAX))
        .checked_div(u32::from(last))
        .unwrap_or(0);
    u16::try_from(scaled).unwrap_or(ABS_MAX)
}

/// Wheel direction: one notch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wheel {
    Up,
    Down,
}

/// One HID frame on the control websocket. Its `Debug` is redacted: see
/// the impl.
#[derive(Clone, Copy, PartialEq, Eq)]
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

/// §4.5, §9.2 (PD5 ruling): a frame is a keystroke — as sensitive as a
/// password typed through RDP — or the pointer's state. `Debug` names the
/// kind and the wire length only, never a key, modifier, button,
/// coordinate or wheel direction; every type that holds a frame inherits
/// that. A test that needs the detail prints `to_vec()`.
impl core::fmt::Debug for HidFrame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (kind, len): (&str, usize) = match self {
            HidFrame::SetMode { .. } => ("SetMode", 4),
            HidFrame::Keyboard { .. } => ("Keyboard", 12),
            HidFrame::AbsMouse { .. } => ("AbsMouse", 9),
            HidFrame::Wheel { .. } => ("Wheel", 8),
        };
        f.debug_struct("HidFrame")
            .field("kind", &kind)
            .field("len", &len)
            .finish_non_exhaustive()
    }
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

    /// §7.2: x_hid = x * 32767 / (w-1), clamped at the edges; a 1-wide or
    /// 0-wide span maps everything to 0 (no division by zero).
    #[test]
    fn scale_abs_matches_section_7_2() {
        assert_eq!(scale_abs(0, 1920), 0);
        assert_eq!(scale_abs(1919, 1920), 32_767);
        assert_eq!(scale_abs(960, 1920), 16_392); // 960·32767/1919, §7.2
        assert_eq!(scale_abs(959, 1919), 16_383); // the exact half
        assert_eq!(scale_abs(5000, 1920), 32_767, "past the edge clamps");
        assert_eq!(scale_abs(0, 1), 0);
        assert_eq!(scale_abs(7, 0), 0);
        assert_eq!(scale_abs(719, 720), 32_767);
        // One past the edge: unclamped, 1920·32767/1919 = 32 784 still fits
        // a u16, so only the clamp keeps it in 0..=32767 (§3.3).
        assert_eq!(scale_abs(1920, 1920), 32_767, "one past the edge clamps");
        assert_eq!(scale_abs(u16::MAX, u16::MAX), 32_767);
        assert_eq!(scale_abs(u16::MAX, 2), 32_767);
        assert_eq!(scale_abs(u16::MAX, 1), 0);
    }

    /// PD5 ruling (§4.5, §9.2): no rendering of any of `values` — decimal,
    /// hex in either case, `0x`-prefixed or two-digit — appears in `s`.
    /// Renderings shorter than two characters are skipped (a count may
    /// show them); the value-invariance checks cover those.
    fn assert_no_value(s: &str, values: &[u64]) {
        for v in values {
            for r in [
                format!("{v}"),
                format!("{v:x}"),
                format!("{v:X}"),
                format!("{v:#x}"),
                format!("{v:02x}"),
                format!("{v:02X}"),
            ] {
                assert!(r.len() < 2 || !s.contains(&r), "{r} appears in {s}");
            }
        }
    }

    /// PD5 ruling (§4.5, §9.2): a frame is a keystroke or the pointer's
    /// state. Its `Debug`, `{:?}` and `{:#?}`, names the kind and the wire
    /// length and nothing else: frames of one kind print alike whatever
    /// they hold, and no key, modifier, button, coordinate or mode byte
    /// appears.
    #[test]
    fn debug_names_the_kind_and_length_only() {
        let pairs = [
            (
                HidFrame::Keyboard {
                    modifiers: 0xA7,
                    keys: [0x1E, 0x2C, 0x3B, 0x5D, 0x6F],
                },
                HidFrame::Keyboard {
                    modifiers: 0,
                    keys: [0; 5],
                },
            ),
            (
                HidFrame::AbsMouse {
                    buttons: 0x06,
                    x: 12_345,
                    y: 23_456,
                },
                HidFrame::AbsMouse {
                    buttons: 0,
                    x: 0,
                    y: 0,
                },
            ),
            (
                HidFrame::Wheel {
                    buttons: 0x05,
                    wheel: Wheel::Down,
                },
                HidFrame::Wheel {
                    buttons: 0,
                    wheel: Wheel::Up,
                },
            ),
            (
                HidFrame::SetMode { hid_type: 0x3C },
                HidFrame::SetMode { hid_type: 0 },
            ),
        ];
        let values = [0xA7, 0x1E, 0x2C, 0x3B, 0x5D, 0x6F, 12_345, 23_456, 0x3C];
        for (a, b) in pairs {
            for (fa, fb) in [
                (format!("{a:?}"), format!("{b:?}")),
                (format!("{a:#?}"), format!("{b:#?}")),
            ] {
                assert_eq!(fa, fb, "Debug shows what the frame holds");
                assert_no_value(&fa, &values);
            }
        }
        assert_eq!(
            format!("{:?}", pairs[0].0),
            "HidFrame { kind: \"Keyboard\", len: 12, .. }"
        );
        assert_eq!(
            format!("{:?}", pairs[1].0),
            "HidFrame { kind: \"AbsMouse\", len: 9, .. }"
        );
        for (a, _) in pairs {
            let len = format!("len: {}", a.to_vec().len());
            assert!(format!("{a:?}").contains(&len), "{a:?}");
        }
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
