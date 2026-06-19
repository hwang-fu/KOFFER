//! Fixed-size cryptographic digests.

use crate::codec::{Decode, DecodeError, Decoder, Encode, EncodeError, Encoder, Write};

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

impl<const N: usize> AsRef<[u8]> for Digest<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<C, const N: usize> Encode<C> for Digest<N> {
    fn encode<W: Write>(&self, e: &mut Encoder<W>, _: &mut C) -> Result<(), EncodeError<W::Error>> {
        e.bytes(&self.0)?.ok()
    }
}

impl<'b, C, const N: usize> Decode<'b, C> for Digest<N> {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, DecodeError> {
        let bytes = d.bytes()?;
        let array = <[u8; N]>::try_from(bytes)
            .map_err(|_| DecodeError::message("digest has wrong length"))?;
        Ok(Self(array))
    }
}
