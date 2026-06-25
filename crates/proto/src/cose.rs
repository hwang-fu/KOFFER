//! COSE structures (RFC 9052): the `COSE_Sign1` signed-message envelope and the
//! canonical `Sig_structure` (the exact to-be-signed bytes).
//!
//! proto builds and parses the bytes and ferries the algorithm codepoint; the
//! actual signing and verifying live in the crypto layer, wired by a consumer.

use minicbor::encode::write::Cursor;

use crate::alg::AlgId;
use crate::codec::{Decode, DecodeError, Decoder, Encode, EncodeError, Encoder, Write};

/// COSE header label for the algorithm identifier (RFC 9052 Table 2).
const LABEL_ALG: u8 = 1;

/// Upper bound on the encoded protected-header map `{1: alg}`: the map and label
/// prefix (`0xa1 0x01`) plus a maximum 9-byte CBOR integer for the algorithm.
const PROTECTED_MAX: usize = 16;

/// The COSE protected header: the metadata the signature covers.
///
/// For a `COSE_Sign1` this carries the algorithm identifier. On the wire it is a
/// CBOR byte string wrapping the canonical CBOR of the header map `{1: alg}`; that
/// wrapping is what binds the algorithm into the signed bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectedHeader {
    alg: AlgId,
}

impl ProtectedHeader {
    /// Creates a protected header carrying `alg`.
    pub const fn new(alg: AlgId) -> Self {
        Self { alg }
    }

    /// The algorithm identifier.
    pub const fn alg(&self) -> AlgId {
        self.alg
    }
}

impl<C> Encode<C> for ProtectedHeader {
    fn encode<W: Write>(&self, e: &mut Encoder<W>, _: &mut C) -> Result<(), EncodeError<W::Error>> {
        // The protected header is `bstr .cbor {1: alg}`: build the canonical map in a
        // bounded stack buffer (it cannot exceed PROTECTED_MAX), then emit it as a
        // byte string.
        let mut map = Cursor::new([0u8; PROTECTED_MAX]);
        Encoder::new(&mut map)
            .map(1)
            .and_then(|m| m.u8(LABEL_ALG))
            .and_then(|m| m.i64(self.alg.get()))
            .map_err(|_| EncodeError::message("protected header exceeds PROTECTED_MAX"))?;
        let n = map.position();
        e.bytes(&map.get_ref()[..n])?.ok()
    }
}

impl<'b, C> Decode<'b, C> for ProtectedHeader {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, DecodeError> {
        // Read the wrapping byte string, then decode the canonical {1: alg} map from
        // it, rejecting anything that is not exactly that single-entry map.
        let protected = d.bytes()?;
        let mut inner = Decoder::new(protected);
        if inner.map()? != Some(1) {
            return Err(DecodeError::message(
                "protected header must be a definite single-entry map",
            ));
        }
        if inner.u8()? != LABEL_ALG {
            return Err(DecodeError::message(
                "protected header missing algorithm label",
            ));
        }
        let alg = AlgId::new(inner.i64()?);
        if inner.position() != protected.len() {
            return Err(DecodeError::message("protected header has trailing bytes"));
        }
        Ok(Self::new(alg))
    }
}
