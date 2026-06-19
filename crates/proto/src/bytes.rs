//! Length-bounded byte buffers.

use core::fmt;
use core::ops::Deref;

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
/// Backed by a fixed-capacity inline buffer (no heap). Encoded on the wire as a
/// CBOR byte string; decoding rejects any byte string longer than `MAX`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct BoundedBytes<const MAX: usize>(heapless::Vec<u8, MAX>);

impl<const MAX: usize> BoundedBytes<MAX> {
    pub const fn new() -> Self {
        BoundedBytes(heapless::Vec::new())
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<const MAX: usize> TryFrom<&[u8]> for BoundedBytes<MAX> {
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

impl<const MAX: usize> Deref for BoundedBytes<MAX> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<const MAX: usize> AsRef<[u8]> for BoundedBytes<MAX> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}
