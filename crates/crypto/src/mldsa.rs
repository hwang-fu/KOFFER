//! ML-DSA lattice-based signature backend, wrapping the RustCrypto `ml-dsa` crate.
//!
//! Generic over the parameter set `P`: `MlDsa65` for the showcase profile,
//! `MlDsa87` for the CNSA 2.0 profile. The scheme is stateless, so it implements
//! the plain `Signer` rather than the stateful one the hash-based backend needs.

use core::marker::PhantomData;

use ml_dsa::{KeyInit, Keypair, MlDsaParams};

use crate::{
    error::SignError,
    sign::{SigningKey, VerifyingKey},
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
