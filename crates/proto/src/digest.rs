//! Fixed-size cryptographic digests.

use minicbor::encode::Write;

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

impl<C, const N: usize> minicbor::Encode<C> for Digest<N> {
    fn encode<W>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>>
    where
        W: Write,
    {
        e.bytes(&self.0)?.ok()
    }
}

impl<'b, C, const N: usize> minicbor::Decode<'b, C> for Digest<N> {
    fn decode(d: &mut minicbor::Decoder<'b>, _: &mut C) -> Result<Self, minicbor::decode::Error> {
        let bytes = d.bytes()?;
        let array = <[u8; N]>::try_from(bytes)
            .map_err(|_| minicbor::decode::Error::message("digest has wrong length"))?;
        Ok(Self::new(array))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec;
    use crate::testutil::BYTE_STRING;

    #[test]
    fn decodes_fixed_length_byte_string_without_alloc() {
        // CBOR byte string of length 4, then the digest bytes.
        let wire = [BYTE_STRING | 4, 0xDE, 0xAD, 0xBE, 0xEF];
        let d: Digest<4> = codec::decode(&wire).expect("decode");
        assert_eq!(d.as_bytes(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn decode_rejects_wrong_length() {
        // Byte string of length 3 decoded as Digest<4>.
        let wire = [BYTE_STRING | 3, 0x01, 0x02, 0x03];
        let r: Result<Digest<4>, _> = codec::decode(&wire);
        assert!(r.is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn encodes_as_byte_string_not_array() {
        let d = Digest::<3>::new([0x01, 0x02, 0x03]);
        // CBOR byte string of length 3, then the raw bytes.
        // A derived encode of [u8; 3] would instead emit 0x83 (array of 3 integers).
        assert_eq!(
            codec::encode(&d).expect("encode"),
            [BYTE_STRING | 3, 0x01, 0x02, 0x03]
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn round_trip() {
        let original = Digest256::new([7u8; 32]);
        let bytes = codec::encode(&original).expect("encode");
        let decoded: Digest256 = codec::decode(&bytes).expect("decode");
        assert_eq!(decoded, original);
        // Deterministic: re-encoding yields identical bytes.
        assert_eq!(codec::encode(&decoded).expect("re-encode"), bytes);
    }
}

#[cfg(all(test, feature = "alloc"))]
mod proptests {
    use super::*;
    use crate::codec;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn digest_round_trips(bytes in any::<[u8; 32]>()) {
            let original = Digest::<32>::new(bytes);
            let encoded = codec::encode(&original).unwrap();
            let decoded: Digest<32> = codec::decode(&encoded).unwrap();
            let reencoded = codec::encode(&decoded).unwrap();
            prop_assert_eq!(decoded, original);
            prop_assert_eq!(reencoded, encoded);
        }
    }
}
