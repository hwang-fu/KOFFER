//! Protocol error codes.

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
