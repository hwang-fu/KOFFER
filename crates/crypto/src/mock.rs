//! Mock backend implementing every crypto trait with fake, deterministic data,
//! proving the trait seam composes end to end before any real scheme exists.
//! The whole module is test-only.

use crate::error::{KemError, SignError, VerifyError};
use crate::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, Kem, SharedSecret};
use crate::sign::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// A stand-in backend: no real cryptography, just enough for a roundtrip.
struct Mock;

impl Signer for Mock {
    fn sign(&self, _key: &SigningKey, message: &[u8]) -> Result<Signature, SignError> {
        // The "signature" is the message itself, so `verify` can recognize it.
        Signature::try_from(message).map_err(|_| SignError::Internal)
    }
}

impl Verifier for Mock {
    fn verify(
        &self,
        _key: &VerifyingKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), VerifyError> {
        if signature.as_slice() == message {
            Ok(())
        } else {
            Err(VerifyError::VerificationFailed)
        }
    }
}

impl Kem for Mock {
    fn encapsulate(
        &self,
        _key: &EncapsulationKey,
        rng: &mut dyn rand_core::CryptoRngCore,
    ) -> Result<(Ciphertext, SharedSecret), KemError> {
        // Draw the shared secret from the RNG and carry it verbatim in the
        // ciphertext, so `decapsulate` recovers it.
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let ciphertext = Ciphertext::try_from(&bytes[..]).map_err(|_| KemError::Internal)?;
        let secret = SharedSecret::try_from(&bytes[..]).map_err(|_| KemError::Internal)?;
        Ok((ciphertext, secret))
    }

    fn decapsulate(
        &self,
        _key: &DecapsulationKey,
        ciphertext: &Ciphertext,
    ) -> Result<SharedSecret, KemError> {
        SharedSecret::try_from(ciphertext.as_slice()).map_err(|_| KemError::Internal)
    }
}
