//! LMS/HSS hash-based signature backend, wrapping the `hbs-lms` crate.
//!
//! Generic over the hash chain `H`: `Sha256_256` for the showcase profile,
//! `Sha256_192` (the SHA-256/192 truncated set) for the CNSA 2.0 profile.

use core::marker::PhantomData;

use hbs_lms::HashChain;

use crate::{
    error::VerifyError,
    sign::{Signature, Verifier, VerifyingKey},
};

/// The LMS/HSS backend over hash chain `H`.
pub struct Lms<H: HashChain>(PhantomData<H>);

impl<H: HashChain> Lms<H> {
    /// Creates the backend.
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<H: HashChain> Default for Lms<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: HashChain> Verifier for Lms<H> {
    fn verify(
        &self,
        key: &VerifyingKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), VerifyError> {
        // hbs-lms returns an opaque error; any failure -- bad signature, malformed
        // bytes, or a hash typecode that does not match `H` -- is a verify failure.
        hbs_lms::verify::<H>(message, signature.as_slice(), key.as_slice())
            .map_err(|_| VerifyError::VerificationFailed)
    }
}
