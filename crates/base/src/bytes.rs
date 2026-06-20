//! Length-bounded byte buffers.

use core::fmt;
use core::hash::{Hash, Hasher};
use core::ops::Deref;
use subtle::ConstantTimeEq;

/// Error returned when a byte sequence is longer than the buffer's maximum length `MAX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooLong {
    /// Length of the rejected byte sequence.
    pub len: usize,
    /// Maximum length allowed.
    pub max: usize,
}

impl fmt::Display for TooLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "byte sequence of {} bytes exceeds the maximum of {}",
            self.len, self.max
        )
    }
}

impl core::error::Error for TooLong {}

/// A variable-length byte buffer holding at most `MAX` bytes.
///
/// Backed by a fixed-capacity inline buffer (no heap), so it carries its worst-case
/// size and never allocates. Construction rejects any sequence longer than `MAX`.
/// Equality is **constant-time** (see the `ConstantTimeEq` / `PartialEq` impls below),
/// so comparing secret material never leaks through timing.
#[derive(Debug, Clone, Default)]
pub struct Bytes<const MAX: usize>(heapless::Vec<u8, MAX>);

impl<const MAX: usize> Bytes<MAX> {
    /// Creates an empty buffer.
    pub const fn new() -> Self {
        Bytes(heapless::Vec::new())
    }

    /// Returns the contents as a byte slice.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<const MAX: usize> TryFrom<&[u8]> for Bytes<MAX> {
    type Error = TooLong;

    fn try_from(bytes: &[u8]) -> Result<Self, TooLong> {
        heapless::Vec::from_slice(bytes)
            .map(Self)
            .map_err(|_| TooLong {
                len: bytes.len(),
                max: MAX,
            })
    }
}

impl<const MAX: usize> AsRef<[u8]> for Bytes<MAX> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<const MAX: usize> Deref for Bytes<MAX> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<const MAX: usize> PartialEq for Bytes<MAX> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<const MAX: usize> Eq for Bytes<MAX> {}

impl<const MAX: usize> Hash for Bytes<MAX> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_slice().hash(state);
    }
}

impl<const MAX: usize> ConstantTimeEq for Bytes<MAX> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        // Length is public; equal-length contents are compared with no early exit.
        self.0.as_slice().ct_eq(other.0.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_up_to_max() {
        let bytes = [0u8; 4];
        for len in 0..=4 {
            let r = Bytes::<4>::try_from(&bytes[..len]);
            assert!(r.is_ok(), "len {len} should be accepted");
            assert_eq!(r.unwrap().as_slice(), &bytes[..len]);
        }
    }

    #[test]
    fn rejects_over_max() {
        let bytes = [0u8; 5];
        let r = Bytes::<4>::try_from(&bytes[..]);
        assert_eq!(r, Err(TooLong { len: 5, max: 4 }));
    }

    #[test]
    fn behaves_like_a_byte_slice() {
        let b = Bytes::<4>::try_from(&[1u8, 2, 3][..]).unwrap();
        assert_eq!(b.len(), 3); // Deref -> slice::len
        assert!(!b.is_empty()); // Deref -> slice::is_empty
        assert_eq!(b[1], 2); // Deref -> slice indexing
        assert_eq!(b.first(), Some(&1)); // Deref -> slice::first
    }
}
