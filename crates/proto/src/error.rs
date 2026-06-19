//! Protocol error codes.

use crate::codec::{Decode, DecodeError, Decoder, Encode, EncodeError, Encoder, Write};

/// A protocol or parse error code, carried in the wire `Error` reply.
///
/// Each named variant has a stable codepoint. A code we don't recognize decodes to
/// `Unknown`, keeping the raw value for forward compatibility. Encoded on the wire as
/// a CBOR unsigned integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// The request could not be parsed (bad CBOR, bad structure, or non-ASCII text).
    Malformed,
    /// The requested signing or encryption algorithm is not supported.
    UnsupportedAlgorithm,
    /// The request kind is not recognized or supported.
    UnknownRequest,
    /// The operation needs earlier setup that has not happened yet.
    NotReady,
    /// The user did not confirm the operation (declined or timed out).
    ConsentDenied,
    /// A signature or integrity check failed.
    VerificationFailed,
    /// An unexpected device-side failure.
    Internal,
    /// A code with no named variant, kept verbatim. Produced only for codes not
    /// assigned above; do not construct it with an already-assigned code.
    Unknown(u32),
}

impl ErrorCode {
    /// The stable wire codepoint for this error.
    pub const fn codepoint(self) -> u32 {
        match self {
            ErrorCode::Malformed => 1,
            ErrorCode::UnsupportedAlgorithm => 2,
            ErrorCode::UnknownRequest => 3,
            ErrorCode::NotReady => 4,
            ErrorCode::ConsentDenied => 5,
            ErrorCode::VerificationFailed => 6,
            ErrorCode::Internal => 7,
            ErrorCode::Unknown(code) => code,
        }
    }
}

impl From<u32> for ErrorCode {
    fn from(code: u32) -> Self {
        match code {
            1 => ErrorCode::Malformed,
            2 => ErrorCode::UnsupportedAlgorithm,
            3 => ErrorCode::UnknownRequest,
            4 => ErrorCode::NotReady,
            5 => ErrorCode::ConsentDenied,
            6 => ErrorCode::VerificationFailed,
            7 => ErrorCode::Internal,
            other => ErrorCode::Unknown(other),
        }
    }
}

impl<C> Encode<C> for ErrorCode {
    fn encode<W: Write>(&self, e: &mut Encoder<W>, _: &mut C) -> Result<(), EncodeError<W::Error>> {
        e.u32(self.codepoint())?.ok()
    }
}

impl<'b, C> Decode<'b, C> for ErrorCode {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, DecodeError> {
        Ok(Self::from(d.u32()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec;

    const NAMED: [ErrorCode; 7] = [
        ErrorCode::Malformed,
        ErrorCode::UnsupportedAlgorithm,
        ErrorCode::UnknownRequest,
        ErrorCode::NotReady,
        ErrorCode::ConsentDenied,
        ErrorCode::VerificationFailed,
        ErrorCode::Internal,
    ];

    #[test]
    fn codepoints_are_stable() {
        assert_eq!(ErrorCode::Malformed.codepoint(), 1);
        assert_eq!(ErrorCode::UnsupportedAlgorithm.codepoint(), 2);
        assert_eq!(ErrorCode::UnknownRequest.codepoint(), 3);
        assert_eq!(ErrorCode::NotReady.codepoint(), 4);
        assert_eq!(ErrorCode::ConsentDenied.codepoint(), 5);
        assert_eq!(ErrorCode::VerificationFailed.codepoint(), 6);
        assert_eq!(ErrorCode::Internal.codepoint(), 7);
    }

    #[test]
    fn known_codes_map_to_named_variants() {
        for code in NAMED {
            // Each codepoint maps back to its named variant, never to Unknown.
            assert_eq!(ErrorCode::from(code.codepoint()), code);
        }
    }

    #[test]
    fn unknown_code_is_preserved() {
        assert_eq!(ErrorCode::from(99), ErrorCode::Unknown(99));
        assert_eq!(ErrorCode::Unknown(99).codepoint(), 99);
    }

    #[test]
    fn decodes_bare_integer_without_alloc() {
        // CBOR unsigned integer 1 is a single byte: 0x01.
        let wire = [0x01];
        let code: ErrorCode = codec::decode(&wire).expect("decode");
        assert_eq!(code, ErrorCode::Malformed);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn encodes_as_bare_integer() {
        // Malformed (codepoint 1) is the single byte 0x01, not a wrapped form.
        assert_eq!(
            codec::encode(&ErrorCode::Malformed).expect("encode"),
            [0x01]
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn round_trip_named_and_unknown() {
        for code in NAMED.into_iter().chain([ErrorCode::Unknown(99)]) {
            let bytes = codec::encode(&code).expect("encode");
            let decoded: ErrorCode = codec::decode(&bytes).expect("decode");
            assert_eq!(decoded, code);
            // Deterministic: re-encoding yields identical bytes.
            assert_eq!(codec::encode(&decoded).expect("re-encode"), bytes);
        }
    }
}
