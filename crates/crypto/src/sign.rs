//! Signing-side value types: keys and signatures.

use crate::error::{SignError, VerifyError};

// Provisional capacities -- each sized to the largest supported algorithm for its
// role. Placeholders pending the full set of supported algorithms; not final sizes.
const SIGNING_KEY_MAX: usize = 4896; // ML-DSA-87 secret key
const VERIFYING_KEY_MAX: usize = 2592; // ML-DSA-87 public key
const SIGNATURE_MAX: usize = 4627; // ML-DSA-87 signature (HSS may exceed this)

byte_value! {
    /// A secret signing key, as raw bytes.
    SigningKey, SIGNING_KEY_MAX
}

byte_value! {
    /// A public verifying key, as raw bytes.
    VerifyingKey, VERIFYING_KEY_MAX
}

byte_value! {
    /// A signature, as raw bytes.
    Signature, SIGNATURE_MAX
}

/// A signing backend: produces a signature over a message with a secret key.
///
/// Each signing scheme implements `Signer`; the right one is selected by algorithm
/// at the call site.
pub trait Signer {
    /// Signs `message` with `key`.
    fn sign(&self, key: &SigningKey, message: &[u8]) -> Result<Signature, SignError>;
}

/// A verifying backend: checks a signature against a verifying key and message.
pub trait Verifier {
    /// Checks `signature` over `message` against `key`.
    ///
    /// `Ok(())` means valid; `Err(VerifyError::VerificationFailed)` means the signature
    /// is well-formed but does not match.
    fn verify(
        &self,
        key: &VerifyingKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), VerifyError>;
}
