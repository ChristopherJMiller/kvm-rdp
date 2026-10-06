//! Forward-only, panic-free reads over a byte slice. Every bounds and
//! arithmetic operation is checked so parser modules can deny the
//! panicking clippy lints (§6.2).

pub(crate) struct Cur<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cur<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    pub(crate) fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        self.take(1).and_then(|s| s.first().copied())
    }
    pub(crate) fn u16(&mut self) -> Option<u16> {
        let a: [u8; 2] = self.take(2)?.try_into().ok()?;
        Some(u16::from_be_bytes(a))
    }
    pub(crate) fn u24(&mut self) -> Option<u32> {
        let s = self.take(3)?;
        Some(u32::from_be_bytes([0, *s.first()?, *s.get(1)?, *s.get(2)?]))
    }
    pub(crate) fn u32(&mut self) -> Option<u32> {
        let a: [u8; 4] = self.take(4)?.try_into().ok()?;
        Some(u32::from_be_bytes(a))
    }
    pub(crate) fn i24(&mut self) -> Option<i32> {
        let s = self.take(3)?;
        let (b0, b1, b2) = (*s.first()?, *s.get(1)?, *s.get(2)?);
        let ext = if b0 & 0x80 != 0 { 0xFF } else { 0x00 };
        Some(i32::from_be_bytes([ext, b0, b1, b2]))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::as_conversions
    )]
    use super::*;

    #[test]
    fn reads_be_integers_and_stops_at_end() {
        let data = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];
        let mut c = Cur::new(&data);
        assert_eq!(c.u8(), Some(0x01));
        assert_eq!(c.u16(), Some(0x0203));
        assert_eq!(c.u24(), Some(0x0004_0506));
        assert_eq!(c.u32(), Some(0x0708_090A));
        assert_eq!(c.u8(), None);
    }

    #[test]
    fn i24_sign_extends_and_bounds_check() {
        assert_eq!(Cur::new(&[0xFFu8, 0xFF, 0xFF]).i24(), Some(-1));
        assert_eq!(Cur::new(&[0x00u8, 0x00, 0x2A]).i24(), Some(42));
        assert_eq!(Cur::new(&[0x00u8, 0x01]).i24(), None);
    }
}
