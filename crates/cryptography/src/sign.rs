//! Signing-side value types: keys and signatures.

use koffer_common::bytes::Bytes;
use koffer_derive::{ByteNewtype, SecretByteNewtype};

use crate::error::{SignError, VerifyError};

// Buffer capacities, each the largest over the supported signature algorithms.
// ML-DSA-87 is the largest for the key sizes; the HSS/LMS keys are much smaller.
const SIGNING_KEY_MAX: usize = 4896; // ML-DSA-87 secret key
const VERIFYING_KEY_MAX: usize = 2592; // ML-DSA-87 public key

// Largest over the supported signature algorithms: ML-DSA-87's signature. The
// HSS/LMS parameters are now fixed, and its largest signature (2-level HSS, H=10,
// w=8, SHA-256) is about 2964 bytes -- comfortably under this.
const SIGNATURE_MAX: usize = 4627; // ML-DSA-87 signature

/// A secret signing key, as raw bytes.
#[derive(Clone, PartialEq, Eq, SecretByteNewtype)]
pub struct SigningKey(Bytes<SIGNING_KEY_MAX>);

/// A public verifying key, as raw bytes.
#[derive(Debug, Clone, PartialEq, Eq, ByteNewtype)]
pub struct VerifyingKey(Bytes<VERIFYING_KEY_MAX>);

/// A signature, as raw bytes.
#[derive(Debug, Clone, PartialEq, Eq, ByteNewtype)]
pub struct Signature(Bytes<SIGNATURE_MAX>);

/// A signing backend: produces a signature over a message with a secret key.
///
/// Each signing scheme implements `Signer`; the right one is selected by algorithm
/// at the call site.
pub trait Signer {
    /// Signs `message` with `key`.
    fn sign(&self, key: &SigningKey, message: &[u8]) -> Result<Signature, SignError>;
}

/// A stateful signing backend for hash-based schemes (LMS/HSS).
///
/// Each signature consumes a one-time key, so the signer advances the private-key
/// state and -- before returning the signature -- hands the advanced key bytes to
/// `persist` for durable storage. This is the write-before-use discipline: if the
/// caller crashes after signing, it restarts from the persisted (advanced) state
/// and never reuses a one-time key.
pub trait StatefulSigner {
    /// Signs `message` with `key`, calling `persist` with the advanced private-key
    /// bytes before the signature is returned. A `persist` failure aborts the sign
    /// (no signature is released), so the stored state and the returned signature
    /// can never disagree.
    fn sign(
        &self,
        key: &SigningKey,
        message: &[u8],
        persist: &mut dyn FnMut(&[u8]) -> Result<(), SignError>,
    ) -> Result<Signature, SignError>;
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
