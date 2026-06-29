//! Length-bounded byte buffers.

use core::fmt;
use core::hash::{Hash, Hasher};
use core::ops::Deref;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Errors from constructing a [`Bytes`] buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BytesError {
    /// The byte sequence is longer than the buffer's maximum length `MAX`.
    TooLong { len: usize, max: usize },
    /// An exact-length constructor received a sequence of the wrong length.
    WrongLength { expected: usize, got: usize },
}

impl fmt::Display for BytesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BytesError::TooLong { len, max } => {
                write!(f, "byte sequence of {len} bytes exceeds the maximum of {max}")
            }
            BytesError::WrongLength { expected, got } => {
                write!(f, "expected exactly {expected} bytes, got {got}")
            }
        }
    }
}

impl core::error::Error for BytesError {}

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

    /// Creates a buffer that must contain exactly `MAX` bytes -- for fixed-size values
    /// (keys, nonces, digests), where a wrong length is an error in its own right rather
    /// than just an over-long buffer.
    pub fn try_from_exact(bytes: &[u8]) -> Result<Self, BytesError> {
        if bytes.len() != MAX {
            return Err(BytesError::WrongLength {
                expected: MAX,
                got: bytes.len(),
            });
        }
        Self::try_from(bytes) // len == MAX, so this cannot be TooLong
    }
}

impl<const MAX: usize> TryFrom<&[u8]> for Bytes<MAX> {
    type Error = BytesError;

    fn try_from(bytes: &[u8]) -> Result<Self, BytesError> {
        heapless::Vec::from_slice(bytes)
            .map(Self)
            .map_err(|_| BytesError::TooLong {
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

impl<const MAX: usize> Zeroize for Bytes<MAX> {
    fn zeroize(&mut self) {
        // Overwrite the live bytes in place. `zeroize` uses volatile writes, so the
        // compiler cannot optimize the wipe away; the length is left unchanged.
        self.0.as_mut_slice().zeroize();
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
        assert_eq!(r, Err(BytesError::TooLong { len: 5, max: 4 }));
    }

    #[test]
    fn try_from_exact_requires_max_len() {
        assert!(Bytes::<4>::try_from_exact(&[1, 2, 3, 4]).is_ok());
        assert_eq!(
            Bytes::<4>::try_from_exact(&[1, 2, 3]),
            Err(BytesError::WrongLength { expected: 4, got: 3 })
        );
        assert_eq!(
            Bytes::<4>::try_from_exact(&[1, 2, 3, 4, 5]),
            Err(BytesError::WrongLength { expected: 4, got: 5 })
        );
    }

    #[test]
    fn behaves_like_a_byte_slice() {
        let b = Bytes::<4>::try_from(&[1u8, 2, 3][..]).unwrap();
        assert_eq!(b.len(), 3); // Deref -> slice::len
        assert!(!b.is_empty()); // Deref -> slice::is_empty
        assert_eq!(b[1], 2); // Deref -> slice indexing
        assert_eq!(b.first(), Some(&1)); // Deref -> slice::first
    }

    #[test]
    fn equality_is_value_based() {
        use subtle::ConstantTimeEq;
        let a = Bytes::<8>::try_from(&[1, 2, 3][..]).unwrap();
        let b = Bytes::<8>::try_from(&[1, 2, 3][..]).unwrap();
        let c = Bytes::<8>::try_from(&[1, 2, 4][..]).unwrap();
        let short = Bytes::<8>::try_from(&[1, 2][..]).unwrap();

        // `==` is now constant-time but still means value equality.
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, short);

        // The constant-time primitive agrees.
        assert!(bool::from(a.ct_eq(&b)));
        assert!(!bool::from(a.ct_eq(&c)));
    }

    #[test]
    fn zeroize_overwrites_the_bytes() {
        let mut b = Bytes::<8>::try_from(&[1, 2, 3, 4][..]).unwrap();
        b.zeroize();
        assert_eq!(b.as_slice(), &[0, 0, 0, 0]);
    }
}
