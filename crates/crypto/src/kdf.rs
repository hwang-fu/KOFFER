//! Key-derivation (KDF) trait and the HKDF backend.
//!
//! A key-derivation function turns one secret -- such as a shared secret from a
//! key exchange -- plus context into one or more uniformly-random keys. HKDF is
//! the "extract-and-expand" KDF built on HMAC: it first compresses the input
//! keying material into a fixed-size pseudorandom key, then expands that into the
//! requested number of output bytes.
//!
//! The backend is generic over the hash `H` -- `Sha256` for the showcase profile,
//! `Sha384` for the CNSA 2.0 profile -- mirroring the LMS backend's `Lms<H>`.
//! `derive` writes into a caller-provided buffer, so it needs no heap and runs on
//! the embedded target.

use core::marker::PhantomData;

use crate::error::KdfError;

/// A key-derivation backend: expand a secret plus context into output key bytes.
pub trait Kdf {
    /// Derives `okm.len()` bytes of output keying material into `okm`.
    ///
    /// `salt` is optional non-secret randomness (an empty slice means "no salt"),
    /// `ikm` is the input keying material (the secret), and `info` is a context
    /// label that binds the output to its purpose. Fails only if `okm` is longer
    /// than the KDF can produce.
    fn derive(&self, salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), KdfError>;
}

/// The HKDF backend over hash `H`: `Sha256` (showcase) or `Sha384` (CNSA 2.0).
pub struct Hkdf<H>(PhantomData<H>);

impl<H> Hkdf<H> {
    /// Creates the backend.
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<H> Default for Hkdf<H> {
    fn default() -> Self {
        Self::new()
    }
}
