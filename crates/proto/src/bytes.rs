//! Length-bounded byte buffers.

use crate::codec::{Decode, DecodeError, Decoder, Encode, EncodeError, Encoder, Write};
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

impl<C, const MAX: usize> Encode<C> for BoundedBytes<MAX> {
    fn encode<W: Write>(&self, e: &mut Encoder<W>, _: &mut C) -> Result<(), EncodeError<W::Error>> {
        e.bytes(self.as_slice())?.ok()
    }
}

impl<'b, C, const MAX: usize> Decode<'b, C> for BoundedBytes<MAX> {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, DecodeError> {
        let bytes = d.bytes()?;
        Self::try_from(bytes)
            .map_err(|_| DecodeError::message("byte sequence exceeds the maximum length"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec;

    #[test]
    fn accepts_up_to_max() {
        let bytes = [0u8; 4];
        for len in 0..=4 {
            let r = BoundedBytes::<4>::try_from(&bytes[..len]);
            assert!(r.is_ok(), "len {len} should be accepted");
            assert_eq!(r.unwrap().as_slice(), &bytes[..len]);
        }
    }

    #[test]
    fn rejects_over_max() {
        let bytes = [0u8; 5];
        let r = BoundedBytes::<4>::try_from(&bytes[..]);
        assert_eq!(r, Err(TooLong { len: 5, max: 4 }));
    }

    #[test]
    fn behaves_like_a_byte_slice() {
        let bb = BoundedBytes::<4>::try_from(&[1u8, 2, 3][..]).unwrap();
        assert_eq!(bb.len(), 3); // Deref -> slice::len
        assert!(!bb.is_empty()); // Deref -> slice::is_empty
        assert_eq!(bb[1], 2); // Deref -> slice indexing
        assert_eq!(bb.first(), Some(&1)); // Deref -> slice::first
    }

    #[test]
    fn decodes_byte_string_without_alloc() {
        // CBOR byte string of length 3: 0x43 = major type 2 | length 3, then the bytes.
        let wire = [0x43, 0xAA, 0xBB, 0xCC];
        let bb: BoundedBytes<8> = codec::decode(&wire).expect("decode");
        assert_eq!(bb.as_slice(), &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn decode_rejects_over_max_on_the_wire() {
        // A 3-byte byte string decoded into a BoundedBytes<2>.
        let wire = [0x43, 0x01, 0x02, 0x03];
        let r: Result<BoundedBytes<2>, _> = codec::decode(&wire);
        assert!(r.is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn encodes_as_byte_string() {
        let bb = BoundedBytes::<8>::try_from(&[1u8, 2, 3][..]).unwrap();
        // 0x43 = CBOR byte string of length 3, then the raw bytes.
        assert_eq!(codec::encode(&bb).expect("encode"), [0x43, 1, 2, 3]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn round_trip() {
        let original = BoundedBytes::<16>::try_from(&[9u8; 10][..]).unwrap();
        let bytes = codec::encode(&original).expect("encode");
        let decoded: BoundedBytes<16> = codec::decode(&bytes).expect("decode");
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
        fn bounded_bytes_round_trips(bytes in proptest::collection::vec(any::<u8>(), 0..=32usize)) {
            let original = BoundedBytes::<32>::try_from(bytes.as_slice()).unwrap();
            let encoded = codec::encode(&original).unwrap();
            let decoded: BoundedBytes<32> = codec::decode(&encoded).unwrap();
            let reencoded = codec::encode(&decoded).unwrap();
            prop_assert_eq!(decoded, original);
            prop_assert_eq!(reencoded, encoded);
        }
    }
}
