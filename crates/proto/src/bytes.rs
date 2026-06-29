//! CBOR-serializable bounded byte buffers for the wire.

use base::bytes::{Bytes, TooLong};
use core::ops::Deref;
use minicbor::encode::Write;

/// A wire byte string of at most `MAX` bytes.
///
/// Wraps a `base::Bytes<MAX>` (the no-heap storage) and adds the CBOR encoding:
/// it encodes as a CBOR byte string, and decoding rejects any byte string longer
/// than `MAX`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct CborBytes<const MAX: usize>(Bytes<MAX>);

impl<const MAX: usize> CborBytes<MAX> {
    /// Creates an empty buffer.
    pub const fn new() -> Self {
        CborBytes(Bytes::new())
    }

    /// Returns the contents as a byte slice.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<const MAX: usize> TryFrom<&[u8]> for CborBytes<MAX> {
    type Error = TooLong;

    fn try_from(bytes: &[u8]) -> Result<Self, TooLong> {
        Bytes::try_from(bytes).map(Self)
    }
}

impl<const MAX: usize> Deref for CborBytes<MAX> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<const MAX: usize> AsRef<[u8]> for CborBytes<MAX> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<C, const MAX: usize> minicbor::Encode<C> for CborBytes<MAX> {
    fn encode<W>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>>
    where
        W: Write,
    {
        e.bytes(self.as_slice())?.ok()
    }
}

impl<'b, C, const MAX: usize> minicbor::Decode<'b, C> for CborBytes<MAX> {
    fn decode(d: &mut minicbor::Decoder<'b>, _: &mut C) -> Result<Self, minicbor::decode::Error> {
        let bytes = d.bytes()?;
        Self::try_from(bytes).map_err(|_| {
            minicbor::decode::Error::message("byte sequence exceeds the maximum length")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec;
    use crate::testutil::BYTE_STRING;

    #[test]
    fn decodes_byte_string_without_alloc() {
        // CBOR byte string of length 3, then the bytes.
        let wire = [BYTE_STRING | 3, 0xAA, 0xBB, 0xCC];
        let cb: CborBytes<8> = codec::decode(&wire).expect("decode");
        assert_eq!(cb.as_slice(), &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn decode_rejects_over_max_on_the_wire() {
        // A 3-byte byte string decoded into a CborBytes<2>.
        let wire = [BYTE_STRING | 3, 0x01, 0x02, 0x03];
        let r: Result<CborBytes<2>, _> = codec::decode(&wire);
        assert!(r.is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn encodes_as_byte_string() {
        let cb = CborBytes::<8>::try_from(&[1u8, 2, 3][..]).unwrap();
        // CBOR byte string of length 3, then the raw bytes.
        assert_eq!(
            codec::encode(&cb).expect("encode"),
            [BYTE_STRING | 3, 1, 2, 3]
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn round_trip() {
        let original = CborBytes::<16>::try_from(&[9u8; 10][..]).unwrap();
        let bytes = codec::encode(&original).expect("encode");
        let decoded: CborBytes<16> = codec::decode(&bytes).expect("decode");
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
        fn cbor_bytes_round_trips(bytes in proptest::collection::vec(any::<u8>(), 0..=32usize)) {
            let original = CborBytes::<32>::try_from(bytes.as_slice()).unwrap();
            let encoded = codec::encode(&original).unwrap();
            let decoded: CborBytes<32> = codec::decode(&encoded).unwrap();
            let reencoded = codec::encode(&decoded).unwrap();
            prop_assert_eq!(decoded, original);
            prop_assert_eq!(reencoded, encoded);
        }
    }
}
