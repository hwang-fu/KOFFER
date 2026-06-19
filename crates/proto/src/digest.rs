//! Fixed-size cryptographic digests.

/// A fixed-size hash digest of `N` bytes.
///
/// Encoded on the wire as a CBOR byte string (never an array of integers); decoding
/// rejects any byte string whose length is not exactly `N`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest<const N: usize>([u8; N]);

/// SHA-256 digest (32 bytes).
pub type Digest256 = Digest<32>;
/// SHA-512 digest (64 bytes).
pub type Digest512 = Digest<64>;

impl<const N: usize> Digest<N> {
    /// Wrap raw digest bytes.
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// The digest bytes.
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> From<[u8; N]> for Digest<N> {
    fn from(bytes: [u8; N]) -> Self {
        Digest::<N>::new(bytes)
    }
}
