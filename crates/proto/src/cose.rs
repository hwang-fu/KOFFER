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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec;
    use crate::testutil::BYTE_STRING;

    #[test]
    fn decodes_protected_header_without_alloc() {
        // bstr(3) wrapping {1: -7}: 0x43 a1 01 26  (-7 is the ES256 codepoint).
        let wire = [BYTE_STRING | 3, 0xa1, 0x01, 0x26];
        let ph: ProtectedHeader = codec::decode(&wire).expect("decode");
        assert_eq!(ph.alg(), AlgId::new(-7));
    }

    #[test]
    fn rejects_non_single_entry_map() {
        // bstr(1) wrapping the empty map {}: 0x41 a0.
        let wire = [BYTE_STRING | 1, 0xa0];
        let r: Result<ProtectedHeader, _> = codec::decode(&wire);
        assert!(r.is_err());
    }

    #[test]
    fn rejects_trailing_bytes() {
        // bstr(4) wrapping {1: -7} plus a stray 0x00: 0x44 a1 01 26 00.
        let wire = [BYTE_STRING | 4, 0xa1, 0x01, 0x26, 0x00];
        let r: Result<ProtectedHeader, _> = codec::decode(&wire);
        assert!(r.is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn encodes_as_bstr_wrapped_map() {
        let ph = ProtectedHeader::new(AlgId::new(-7));
        // 0x43 (bstr len 3) then the canonical map a1 01 26.
        assert_eq!(
            codec::encode(&ph).expect("encode"),
            [0x43, 0xa1, 0x01, 0x26]
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn round_trip_and_deterministic() {
        for raw in [-7i64, -46, 1, 1000, -65537] {
            let original = ProtectedHeader::new(AlgId::new(raw));
            let bytes = codec::encode(&original).expect("encode");
            let decoded: ProtectedHeader = codec::decode(&bytes).expect("decode");
            assert_eq!(decoded, original);
            assert_eq!(codec::encode(&decoded).expect("re-encode"), bytes);
        }
    }
}
