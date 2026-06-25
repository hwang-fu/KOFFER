//! COSE structures (RFC 9052): the `COSE_Sign1` signed-message envelope and the
//! canonical `Sig_structure` (the exact to-be-signed bytes).
//!
//! proto builds and parses the bytes and ferries the algorithm codepoint; the
//! actual signing and verifying live in the crypto layer, wired by a consumer.

use minicbor::data::Type;
use minicbor::encode::write::Cursor;

use crate::alg::AlgId;
use crate::ascii::AsciiStr;
use crate::codec::{Decode, DecodeError, Decoder, Encode, EncodeError, Encoder, Write};

/// COSE header label for the algorithm identifier (RFC 9052 Table 2).
const LABEL_ALG: u8 = 1;

/// Upper bound on the encoded protected-header map `{1: alg}`: the map and label
/// prefix (`0xa1 0x01`) plus a maximum 9-byte CBOR integer for the algorithm.
const PROTECTED_MAX: usize = 16;

/// COSE header label for the key identifier (RFC 9052 Table 2).
const LABEL_KID: u8 = 4;

/// The COSE context string for a `COSE_Sign1` signature.
const CONTEXT_SIGNATURE1: &str = "Signature1";

/// The payload slot of a `COSE_Sign1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Payload<'b> {
    /// Detached: the slot is CBOR `nil`; the real payload is supplied separately and
    /// identified by its digest (which the SUIT manifest carries).
    Detached,
    /// Attached: the payload bytes are carried inline as a CBOR byte string.
    Attached(&'b [u8]),
}

/// The COSE protected header: the metadata the signature covers.
///
/// For a `COSE_Sign1` this carries the algorithm identifier. On the wire it is a
/// CBOR byte string wrapping the canonical CBOR of the header map `{1: alg}`; that
/// wrapping is what binds the algorithm into the signed bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectedHeader {
    alg: AlgId,
}

/// A `COSE_Sign1` single-signer signed message (RFC 9052).
///
/// The 4-element CBOR array `[protected, unprotected, payload-or-nil, signature]`.
/// Borrows its variable-length fields from the input, so decoding is zero-copy with
/// no size cap. proto carries these bytes; it never signs or verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoseSign1<'b> {
    protected: ProtectedHeader,
    kid: Option<AsciiStr<'b>>,
    payload: Payload<'b>,
    signature: &'b [u8],
}

/// The COSE `Sig_structure`: the exact canonical bytes a `COSE_Sign1` signature is
/// computed over (RFC 9052 Sec 4.4).
///
/// `["Signature1", body_protected, external_aad, payload]`. Both signer and verifier
/// rebuild this identically and run the signature over it -- deterministic encoding
/// is what makes them agree. `external_aad` is empty unless the application binds
/// extra context; `payload` is the signed content (the attached bytes, or the
/// externally-supplied bytes in detached mode).
pub struct SigStructure<'a> {
    protected: ProtectedHeader,
    external_aad: &'a [u8],
    payload: &'a [u8],
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

impl<'b> CoseSign1<'b> {
    /// Assembles a `COSE_Sign1` from its parts (the signature comes from the crypto layer).
    pub fn new(
        alg: AlgId,
        kid: Option<AsciiStr<'b>>,
        payload: Payload<'b>,
        signature: &'b [u8],
    ) -> Self {
        Self {
            protected: ProtectedHeader::new(alg),
            kid,
            payload,
            signature,
        }
    }

    /// The algorithm identifier (from the protected header).
    pub fn alg(&self) -> AlgId {
        self.protected.alg()
    }

    /// The key identifier, if present.
    pub fn kid(&self) -> Option<AsciiStr<'b>> {
        self.kid
    }

    /// The payload.
    pub fn payload(&self) -> Payload<'b> {
        self.payload
    }

    /// The signature bytes.
    pub fn signature(&self) -> &'b [u8] {
        self.signature
    }
}

impl<'a> SigStructure<'a> {
    /// Builds the Sig_structure for a signature over `payload` with `alg`.
    pub fn new(alg: AlgId, external_aad: &'a [u8], payload: &'a [u8]) -> Self {
        Self {
            protected: ProtectedHeader::new(alg),
            external_aad,
            payload,
        }
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

impl<C> Encode<C> for CoseSign1<'_> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), EncodeError<W::Error>> {
        e.array(4)?;
        self.protected.encode(e, ctx)?;
        match self.kid {
            Some(kid) => {
                e.map(1)?.u8(LABEL_KID)?;
                kid.encode(e, ctx)?;
            }
            None => {
                e.map(0)?;
            }
        }
        match self.payload {
            Payload::Detached => {
                e.null()?;
            }
            Payload::Attached(bytes) => {
                e.bytes(bytes)?;
            }
        }
        e.bytes(self.signature)?.ok()
    }
}

impl<'b, C> Decode<'b, C> for CoseSign1<'b> {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, DecodeError> {
        if d.array()? != Some(4) {
            return Err(DecodeError::message("COSE_Sign1 must be a 4-element array"));
        }
        let protected: ProtectedHeader = d.decode()?;
        let kid = match d.map()? {
            Some(0) => None,
            Some(1) => {
                if d.u8()? != LABEL_KID {
                    return Err(DecodeError::message("unexpected unprotected header label"));
                }
                let kid: AsciiStr = d.decode()?; // F15-validated on decode
                Some(kid)
            }
            _ => return Err(DecodeError::message("unexpected unprotected header")),
        };
        let payload = if d.datatype()? == Type::Null {
            d.null()?;
            Payload::Detached
        } else {
            Payload::Attached(d.bytes()?)
        };
        let signature = d.bytes()?;
        Ok(Self {
            protected,
            kid,
            payload,
            signature,
        })
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

    #[cfg(feature = "alloc")]
    #[test]
    fn round_trips_detached() {
        let kid = AsciiStr::try_from("device-root").unwrap();
        let sig = [0xABu8; 8];
        let original = CoseSign1::new(AlgId::new(-7), Some(kid), Payload::Detached, &sig);
        let bytes = codec::encode(&original).expect("encode");
        let decoded: CoseSign1 = codec::decode(&bytes).expect("decode");
        assert_eq!(decoded, original);
        assert_eq!(codec::encode(&decoded).expect("re-encode"), bytes); // deterministic
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn round_trips_attached() {
        let sig = [0xCDu8; 8];
        let original = CoseSign1::new(AlgId::new(-7), None, Payload::Attached(b"firmware"), &sig);
        let bytes = codec::encode(&original).expect("encode");
        let decoded: CoseSign1 = codec::decode(&bytes).expect("decode");
        assert_eq!(decoded, original);
        assert_eq!(codec::encode(&decoded).expect("re-encode"), bytes);
    }

    #[test]
    fn decodes_detached_without_alloc() {
        // [ bstr{1:-7}, {}, nil, bstr(2) ]
        let wire = [0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0xf6, 0x42, 0xAB, 0xCD];
        let decoded: CoseSign1 = codec::decode(&wire).expect("decode");
        assert_eq!(decoded.alg(), AlgId::new(-7));
        assert!(decoded.kid().is_none());
        assert_eq!(decoded.payload(), Payload::Detached);
        assert_eq!(decoded.signature(), &[0xAB, 0xCD]);
    }

    #[test]
    fn rejects_non_ascii_kid() {
        // unprotected {4: "café"} -- the kid's 'é' (c3 a9) is non-ASCII -> F15 reject.
        let wire = [
            0x84, 0x43, 0xa1, 0x01, 0x26, // array(4), protected bstr{1:-7}
            0xa1, 0x04, 0x65, 0x63, 0x61, 0x66, 0xc3, 0xa9, // {4: "café"}
            0xf6, 0x41, 0xAB, // nil payload, bstr(1) signature
        ];
        let r: Result<CoseSign1, _> = codec::decode(&wire);
        assert!(r.is_err());
    }

    #[test]
    fn rejects_non_4_element_array() {
        let wire = [0x83, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0xf6]; // a 3-element array
        let r: Result<CoseSign1, _> = codec::decode(&wire);
        assert!(r.is_err());
    }
}
