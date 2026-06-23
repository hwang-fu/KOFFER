//! ML-DSA lattice-based signature backend, wrapping the RustCrypto `ml-dsa` crate.
//!
//! Generic over the parameter set `P`: `MlDsa65` for the showcase profile,
//! `MlDsa87` for the CNSA 2.0 profile. The scheme is stateless, so it implements
//! the plain `Signer` rather than the stateful one the hash-based backend needs.

use core::marker::PhantomData;

use ml_dsa::{KeyInit, Keypair, MlDsaParams, Signer as _, Verifier as _};

use crate::{
    error::{SignError, VerifyError},
    sign::{Signature, Signer, SigningKey, Verifier, VerifyingKey},
};

/// The ML-DSA backend over parameter set `P`.
pub struct MlDsa<P: MlDsaParams>(PhantomData<P>);

impl<P: MlDsaParams> MlDsa<P> {
    /// Creates the backend.
    pub const fn new() -> Self {
        Self(PhantomData)
    }

    /// Generates a key pair from `entropy`, which must be at least 32 bytes -- the
    /// ML-DSA seed length. The device supplies TRNG bytes here; tests supply a fixed
    /// seed. The secret key is returned as that 32-byte seed (the smallest secret to
    /// hold and zeroize); the public key as its FIPS 204 byte encoding.
    pub fn keygen(&self, entropy: &[u8]) -> Result<(SigningKey, VerifyingKey), SignError> {
        let seed = entropy.get(..32).ok_or(SignError::Internal)?;
        let signing_key =
            ml_dsa::SigningKey::<P>::new_from_slice(seed).map_err(|_| SignError::Internal)?;
        let verifying_key = signing_key.verifying_key();
        Ok((
            SigningKey::try_from(seed).map_err(|_| SignError::Internal)?,
            VerifyingKey::try_from(verifying_key.encode().as_ref())
                .map_err(|_| SignError::Internal)?,
        ))
    }
}

impl<P: MlDsaParams> Default for MlDsa<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: MlDsaParams> Signer for MlDsa<P> {
    fn sign(&self, key: &SigningKey, message: &[u8]) -> Result<Signature, SignError> {
        // Our signing key is the 32-byte seed; re-expand it for each signature. ML-DSA
        // signing is deterministic, so this needs no randomness.
        let signing_key = ml_dsa::SigningKey::<P>::new_from_slice(key.as_slice())
            .map_err(|_| SignError::MalformedKey)?;
        let signature = signing_key
            .try_sign(message)
            .map_err(|_| SignError::Internal)?;
        Signature::try_from(signature.encode().as_ref()).map_err(|_| SignError::Internal)
    }
}

impl<P: MlDsaParams> Verifier for MlDsa<P> {
    fn verify(
        &self,
        key: &VerifyingKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), VerifyError> {
        // Distinguish a malformed public key, an unreadable signature, and a genuine
        // mismatch -- ml-dsa surfaces each separately, unlike the opaque hash-based path.
        let verifying_key = ml_dsa::VerifyingKey::<P>::new_from_slice(key.as_slice())
            .map_err(|_| VerifyError::MalformedKey)?;
        let signature = ml_dsa::Signature::<P>::try_from(signature.as_slice())
            .map_err(|_| VerifyError::MalformedSignature)?;
        verifying_key
            .verify(message, &signature)
            .map_err(|_| VerifyError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::{MlDsa65, MlDsa87};

    fn round_trip<P: MlDsaParams>(backend: &MlDsa<P>) {
        let (sk, vk) = backend.keygen(&[0x42u8; 32]).unwrap();
        let message = b"firmware image";
        let signature = backend.sign(&sk, message).unwrap();
        backend.verify(&vk, message, &signature).unwrap();
    }

    #[test]
    fn mldsa65_round_trips() {
        round_trip(&MlDsa::<MlDsa65>::new());
    }

    #[test]
    fn mldsa87_round_trips() {
        round_trip(&MlDsa::<MlDsa87>::new());
    }
}
