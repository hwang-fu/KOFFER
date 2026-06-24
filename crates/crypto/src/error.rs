//! Error types for the crate's cryptographic operations.
//!
//! Each operation -- signing, verifying, and key-exchange -- has its own error
//! enum that lists only the cases that operation can produce. The enums are
//! marked non-exhaustive, because more cases may be added as the concrete
//! algorithm backends land; code that matches on them must keep a catch-all arm.

/// What can go wrong while producing a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignError {
    /// The one-time signing budget is spent. The stateful hash-based scheme may
    /// sign only a fixed number of times, and a one-time key must never be
    /// reused, so once the budget is exhausted the device refuses to sign.
    KeyExhausted,
    /// The supplied signing-key bytes are not a valid key.
    MalformedKey,
    /// The requested algorithm is not built into this device.
    UnsupportedAlgorithm,
    /// An unexpected device-side failure, such as the randomness source failing.
    Internal,
}

/// What can go wrong while verifying a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyError {
    /// The signature is well-formed but does not match the key and message. This
    /// is the ordinary "not a valid signature" answer.
    VerificationFailed,
    /// The signature bytes are the wrong length or shape and cannot be read as a
    /// signature at all.
    MalformedSignature,
    /// The supplied public-key bytes are not a valid key.
    MalformedKey,
    /// The requested algorithm is not built into this device.
    UnsupportedAlgorithm,
}

/// What can go wrong during key-exchange (encapsulation or decapsulation).
///
/// There is deliberately no "decapsulation failed" case: a conforming KEM
/// returns a deterministic dummy shared secret for an invalid-but-well-formed
/// ciphertext instead of reporting an error, so the outcome never depends on the
/// secret key. `MalformedCiphertext` covers only a structurally broken
/// ciphertext, whose length is public information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KemError {
    /// A supplied key is not valid: the public key when encapsulating, or the
    /// secret key when decapsulating.
    MalformedKey,
    /// The ciphertext is the wrong length or shape and cannot be read.
    MalformedCiphertext,
    /// The requested algorithm is not built into this device.
    UnsupportedAlgorithm,
    /// An unexpected device-side failure, such as the randomness source failing
    /// during encapsulation.
    Internal,
}

/// What can go wrong during authenticated encryption (sealing or opening).
///
/// `OpenFailed` is the security-critical case: the authentication tag did not
/// match, so the ciphertext or the associated data was altered (or the wrong
/// key or nonce was used). No plaintext is ever released in that case, and every
/// authentication failure returns this same error -- the caller is told nothing
/// that could distinguish why opening failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AeadError {
    /// Authentication failed: the tag did not match the ciphertext, associated
    /// data, key, and nonce. No plaintext is released.
    OpenFailed,
    /// The supplied key bytes are not a valid AEAD key (wrong length).
    MalformedKey,
    /// The supplied nonce is not the size the AEAD requires.
    MalformedNonce,
    /// The requested algorithm is not built into this device.
    UnsupportedAlgorithm,
    /// An unexpected device-side failure, such as the input exceeding the
    /// AEAD's maximum length.
    Internal,
}
