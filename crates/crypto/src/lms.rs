//! LMS/HSS hash-based signature backend, wrapping the `hbs-lms` crate.
//!
//! Generic over the hash chain `H`: `Sha256_256` for the showcase profile,
//! `Sha256_192` (the SHA-256/192 truncated set) for the CNSA 2.0 profile.

use core::marker::PhantomData;

use hbs_lms::{
    HashChain, HssParameter, LmotsAlgorithm, LmsAlgorithm, Seed, Sha256_192, Sha256_256,
};

use crate::{
    error::{SignError, VerifyError},
    sign::{Signature, SigningKey, StatefulSigner, Verifier, VerifyingKey},
};

/// The LMS/HSS backend over hash chain `H`.
pub struct Lms<H: HashChain>(PhantomData<H>);

impl<H: HashChain> Lms<H> {
    /// Creates the backend.
    pub const fn new() -> Self {
        Self(PhantomData)
    }

    /// Generates a key pair for `params`, drawing the seed from `entropy`, which must
    /// be at least the hash output size (32 bytes for SHA-256, 24 for SHA-256/192).
    /// The device supplies TRNG bytes here; tests supply a fixed seed.
    pub fn keygen(
        &self,
        params: &[HssParameter<H>],
        entropy: &[u8],
    ) -> Result<(SigningKey, VerifyingKey), SignError> {
        let seed = seed_from_entropy::<H>(entropy)?;
        let aux_data: Option<&mut &mut [u8]> = None;
        let (sk, vk) =
            hbs_lms::keygen::<H>(params, &seed, aux_data).map_err(|_| SignError::Internal)?;
        Ok((
            SigningKey::try_from(sk.as_slice()).map_err(|_| SignError::Internal)?,
            VerifyingKey::try_from(vk.as_slice()).map_err(|_| SignError::Internal)?,
        ))
    }
}

impl<H: HashChain> Default for Lms<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: HashChain> StatefulSigner for Lms<H> {
    fn sign(
        &self,
        key: &SigningKey,
        message: &[u8],
        persist: &mut dyn FnMut(&[u8]) -> Result<(), SignError>,
    ) -> Result<Signature, SignError> {
        // hbs-lms's update callback returns `Result<(), ()>`, so we stash our richer
        // `SignError` in `persist_error` to surface a real persist failure instead of
        // a generic one. The advanced-key bytes pass straight through to `persist`.
        let mut persist_error: Option<SignError> = None;
        let aux_data: Option<&mut &mut [u8]> = None;
        let result = {
            let mut update = |advanced: &[u8]| -> Result<(), ()> {
                match persist(advanced) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        persist_error = Some(e);
                        Err(())
                    }
                }
            };
            hbs_lms::sign::<H>(message, key.as_slice(), &mut update, aux_data)
        };

        match result {
            Ok(sig) => Signature::try_from(sig.as_ref()).map_err(|_| SignError::Internal),
            Err(_) => Err(persist_error.unwrap_or(SignError::Internal)),
        }
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

/// Profile S parameters: 2-level HSS, height 10 per level, Winternitz w=8, SHA-256.
pub fn showcase_params() -> [HssParameter<Sha256_256>; 2] {
    [
        HssParameter::new(LmotsAlgorithm::LmotsW8, LmsAlgorithm::LmsH10),
        HssParameter::new(LmotsAlgorithm::LmotsW8, LmsAlgorithm::LmsH10),
    ]
}

/// Profile C parameters: single-tree LMS, height 10, Winternitz w=8, SHA-256/192.
pub fn cnsa20_params() -> [HssParameter<Sha256_192>; 1] {
    [HssParameter::new(
        LmotsAlgorithm::LmotsW8,
        LmsAlgorithm::LmsH10,
    )]
}

/// Copies the hash's seed-length bytes out of `entropy` into an hbs-lms `Seed`.
fn seed_from_entropy<H: HashChain>(entropy: &[u8]) -> Result<Seed<H>, SignError> {
    let mut seed = Seed::<H>::default();
    let dst = seed.as_mut_slice();
    let n = dst.len();
    if entropy.len() < n {
        return Err(SignError::Internal);
    }
    dst.copy_from_slice(&entropy[..n]);
    Ok(seed)
}
