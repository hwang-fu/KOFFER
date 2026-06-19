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
