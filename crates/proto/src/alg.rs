//! Algorithm identifiers carried on the wire.

use crate::codec::{Decode, DecodeError, Decoder, Encode, EncodeError, Encoder, Write};

/// A COSE algorithm identifier (codepoint), carried opaquely.
///
/// proto only ferries the integer; mapping an id to an algorithm lives in the crypto
/// layer. Encoded on the wire as a bare CBOR integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AlgId(i64);

impl AlgId {
    pub const fn new(id: i64) -> Self {
        Self(id)
    }

    pub const fn get(self) -> i64 {
        self.0
    }
}

impl From<i64> for AlgId {
    fn from(id: i64) -> Self {
        Self::new(id)
    }
}

impl<C> Encode<C> for AlgId {
    fn encode<W: Write>(&self, e: &mut Encoder<W>, _: &mut C) -> Result<(), EncodeError<W::Error>> {
        e.i64(self.0)?.ok()
    }
}

impl<'b, C> Decode<'b, C> for AlgId {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, DecodeError> {
        Ok(Self::new(d.i64()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec;

    #[test]
    fn from_and_get_round_trip() {
        assert_eq!(AlgId::from(-46).get(), -46);
        assert_eq!(AlgId::new(7).get(), 7);
    }

    #[test]
    fn decodes_bare_integer_without_alloc() {
        // CBOR unsigned integer 1 is a single byte: 0x01.
        let wire = [0x01];
        let id: AlgId = codec::decode(&wire).expect("decode");
        assert_eq!(id, AlgId::new(1));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn encodes_as_bare_integer() {
        // A bare CBOR integer, not wrapped in an array.
        // A derived struct encode would instead prefix 0x81 (array of 1).
        assert_eq!(codec::encode(&AlgId::new(1)).expect("encode"), [0x01]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn round_trip_negative_and_positive() {
        for raw in [-46, -1, 0, 1, 1000] {
            let original = AlgId::new(raw);
            let bytes = codec::encode(&original).expect("encode");
            let decoded: AlgId = codec::decode(&bytes).expect("decode");
            assert_eq!(decoded, original);
            // Deterministic: re-encoding yields identical bytes.
            assert_eq!(codec::encode(&decoded).expect("re-encode"), bytes);
        }
    }
}

#[cfg(all(test, feature = "alloc"))]
mod proptests {
    use super::*;
    use crate::codec;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn alg_id_round_trips(raw in any::<i64>()) {
            let original = AlgId::new(raw);
            let encoded = codec::encode(&original).unwrap();
            let decoded: AlgId = codec::decode(&encoded).unwrap();
            let reencoded = codec::encode(&decoded).unwrap();
            prop_assert_eq!(decoded, original);
            prop_assert_eq!(reencoded, encoded);
        }
    }
}
