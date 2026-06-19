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
