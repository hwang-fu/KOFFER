//! Mock backend implementing every crypto trait with fake, deterministic data,
//! proving the trait seam composes end to end before any real scheme exists.
//! The whole module is test-only.

use crate::error::{KemError, SignError, VerifyError};
use crate::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, Kem, SharedSecret};
use crate::profile::CryptoProfile;
use crate::sign::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use koffer_testutil::TestRng;

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
        rng: &mut dyn rand_core::CryptoRng,
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

#[test]
fn seam_composes_end_to_end() {
    let backend = Mock;
    let profile = CryptoProfile::Showcase;

    // The flow begins at profile selection. There is no dispatch table yet, so the
    // mock does not branch on the chosen algorithm -- we just exercise the selector.
    let _sig_alg = profile.general_sig();
    let _kem_alg = profile.kem();

    // Sign / verify: the roundtrip accepts; a tampered message is rejected.
    let signing_key = SigningKey::try_from(&[0u8; 4][..]).unwrap();
    let verifying_key = VerifyingKey::try_from(&[0u8; 4][..]).unwrap();
    let message = b"hello koffer";
    let signature = backend.sign(&signing_key, message).unwrap();
    backend.verify(&verifying_key, message, &signature).unwrap();
    assert!(
        backend
            .verify(&verifying_key, b"tampered", &signature)
            .is_err()
    );

    // Encapsulate / decapsulate: both sides agree on the shared secret.
    let mut rng = TestRng::new(0);
    let ek = EncapsulationKey::try_from(&[0u8; 4][..]).unwrap();
    let dk = DecapsulationKey::try_from(&[0u8; 4][..]).unwrap();
    let (ciphertext, secret) = backend.encapsulate(&ek, &mut rng).unwrap();
    let recovered = backend.decapsulate(&dk, &ciphertext).unwrap();
    assert_eq!(secret.as_slice(), recovered.as_slice());
}
