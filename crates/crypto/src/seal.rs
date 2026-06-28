//! HPKE-style KEM+DEM seal/open core.
//!
//! Encrypt a payload to a recipient's KEM public key by combining a KEM with the AEAD:
//! encapsulate a fresh shared secret to the recipient, derive an AEAD key and nonce from
//! it via the KDF, then AEAD-encrypt the payload. Only the holder of the KEM private key
//! can decapsulate and open it (RFC 9180-aligned). The components are returned as raw
//! bytes; the `COSE_Encrypt` framing is applied by the consumer, so this crate stays
//! independent of `koffer-proto`.

use crate::{
    aead::{self, Aead},
    error::{AeadError, KdfError, KemError},
    kdf::Kdf,
    kem::{Ciphertext, DecapsulationKey, EncapsulationKey, Kem, SharedSecret},
};
use zeroize::Zeroize;

/// Domain-separation label bound into the key/nonce derivation.
const LABEL: &[u8] = b"koffer-seal-v1";

/// The raw components of a sealed payload (the ciphertext stays in the caller's buffer).
///
/// The consumer frames these into a `COSE_Encrypt` container: the KEM ciphertext into the
/// recipient, the nonce into the IV, and `ciphertext || tag` into the content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// The KEM encapsulation (lets the private-key holder recover the shared secret).
    pub kem_ciphertext: Ciphertext,
    /// The AEAD nonce.
    pub nonce: aead::Nonce,
    /// The AEAD authentication tag.
    pub tag: aead::Tag,
}

/// An error from sealing or opening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// The KEM step failed (malformed key or ciphertext).
    Kem(KemError),
    /// The KDF step failed.
    Kdf(KdfError),
    /// The AEAD step failed; `Aead(AeadError::OpenFailed)` means tampering or the wrong key.
    Aead(AeadError),
    /// An internal invariant was violated (should not happen).
    Internal,
}

impl From<KemError> for SealError {
    fn from(e: KemError) -> Self {
        SealError::Kem(e)
    }
}

impl From<KdfError> for SealError {
    fn from(e: KdfError) -> Self {
        SealError::Kdf(e)
    }
}

impl From<AeadError> for SealError {
    fn from(e: AeadError) -> Self {
        SealError::Aead(e)
    }
}

/// Derives the AEAD key and nonce from the KEM shared secret.
///
/// One KDF expansion bound to a fixed domain-separation label; the output is split into the
/// key and the nonce. The scratch buffer is zeroized before returning. The shared secret is
/// already bound to the exact KEM ciphertext by the KEM itself (ML-KEM's implicit rejection /
/// the hybrid combiner), so the ciphertext is not re-bound here.
fn derive_key_nonce<D: Kdf>(
    kdf: &D,
    shared_secret: &SharedSecret,
) -> Result<(aead::Key, aead::Nonce), SealError> {
    let mut okm = [0u8; aead::KEY_LEN + aead::NONCE_LEN];
    kdf.derive(&[], shared_secret.as_slice(), LABEL, &mut okm)?;
    let key = aead::Key::try_from(&okm[..aead::KEY_LEN]).map_err(|_| SealError::Internal)?;
    let nonce = aead::Nonce::try_from(&okm[aead::KEY_LEN..]).map_err(|_| SealError::Internal)?;
    okm.zeroize();
    Ok((key, nonce))
}

/// Seals `buffer` (plaintext -> ciphertext in place) to `recipient`, returning the components.
///
/// Encapsulates a fresh shared secret to `recipient`, derives the AEAD key and nonce from it,
/// and AEAD-encrypts `buffer` with `aad`. Works with any KEM (plain ML-KEM or hybrid), KDF,
/// and AEAD.
pub fn seal<K: Kem, D: Kdf, A: Aead>(
    kem: &K,
    kdf: &D,
    aead: &A,
    recipient: &EncapsulationKey,
    aad: &[u8],
    buffer: &mut [u8],
    rng: &mut dyn rand_core::CryptoRng,
) -> Result<Sealed, SealError> {
    let (kem_ciphertext, shared_secret) = kem.encapsulate(recipient, rng)?;
    let (key, nonce) = derive_key_nonce(kdf, &shared_secret)?;
    let tag = aead.seal(&key, &nonce, aad, buffer)?;
    Ok(Sealed {
        kem_ciphertext,
        nonce,
        tag,
    })
}

/// Unseals `buffer` (ciphertext -> plaintext in place) using `recipient` and the sealed components.
///
/// Decapsulates the shared secret, re-derives the AEAD key, and AEAD-decrypts-and-verifies.
/// Fails if the ciphertext, nonce, or KEM encapsulation was tampered, or the key is wrong.
pub fn unseal<K: Kem, D: Kdf, A: Aead>(
    kem: &K,
    kdf: &D,
    aead: &A,
    recipient: &DecapsulationKey,
    sealed: &Sealed,
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<(), SealError> {
    let shared_secret = kem.decapsulate(recipient, &sealed.kem_ciphertext)?;
    let (key, _derived_nonce) = derive_key_nonce(kdf, &shared_secret)?;
    aead.open(&key, &sealed.nonce, aad, buffer, &sealed.tag)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::Aes256Gcm;
    use crate::hybrid::{X25519MlKem1024, X25519MlKem768};
    use crate::kdf::Hkdf;
    use crate::mlkem::MlKem;
    use core::convert::Infallible;
    use rand_core::{TryCryptoRng, TryRng};
    use sha2::{Sha256, Sha384};

    /// Fixed entropy for keygen (>= 64 bytes for ML-KEM, >= 96 for hybrid).
    const ENTROPY: [u8; 96] = [0x07; 96];

    /// Deterministic counter RNG (round-trips do not depend on the RNG value).
    struct TestRng(u64);

    impl TryRng for TestRng {
        type Error = Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Infallible> {
            Ok(self.try_next_u64()? as u32)
        }
        fn try_next_u64(&mut self) -> Result<u64, Infallible> {
            self.0 = self.0.wrapping_add(1);
            Ok(self.0)
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
            for chunk in dst.chunks_mut(8) {
                let value = self.try_next_u64()?.to_le_bytes();
                chunk.copy_from_slice(&value[..chunk.len()]);
            }
            Ok(())
        }
    }
    impl TryCryptoRng for TestRng {}

    /// `seal -> unseal` recovers the exact plaintext, for any KEM/KDF/AEAD combo.
    fn roundtrip<K: Kem, D: Kdf, A: Aead>(
        kem: &K,
        kdf: &D,
        aead: &A,
        ek: &EncapsulationKey,
        dk: &DecapsulationKey,
    ) {
        let plaintext = [0xABu8; 40];
        let aad = b"koffer seal roundtrip";
        let mut rng = TestRng(0);
        let mut buffer = plaintext;

        let sealed = seal(kem, kdf, aead, ek, aad, &mut buffer, &mut rng).expect("seal");
        assert_ne!(buffer, plaintext, "buffer should be encrypted in place");

        unseal(kem, kdf, aead, dk, &sealed, aad, &mut buffer).expect("unseal");
        assert_eq!(buffer, plaintext, "unseal should recover the exact plaintext");
    }

    #[test]
    fn roundtrip_showcase_mlkem() {
        let kem = MlKem::<ml_kem::MlKem768>::new();
        let (ek, dk) = kem.keygen(&ENTROPY).unwrap();
        roundtrip(&kem, &Hkdf::<Sha256>::new(), &Aes256Gcm, &ek, &dk);
    }

    #[test]
    fn roundtrip_showcase_hybrid() {
        let kem = X25519MlKem768;
        let (ek, dk) = kem.keygen(&ENTROPY).unwrap();
        roundtrip(&kem, &Hkdf::<Sha256>::new(), &Aes256Gcm, &ek, &dk);
    }

    #[test]
    fn roundtrip_cnsa20_mlkem() {
        let kem = MlKem::<ml_kem::MlKem1024>::new();
        let (ek, dk) = kem.keygen(&ENTROPY).unwrap();
        roundtrip(&kem, &Hkdf::<Sha384>::new(), &Aes256Gcm, &ek, &dk);
    }

    #[test]
    fn roundtrip_cnsa20_hybrid() {
        let kem = X25519MlKem1024;
        let (ek, dk) = kem.keygen(&ENTROPY).unwrap();
        roundtrip(&kem, &Hkdf::<Sha384>::new(), &Aes256Gcm, &ek, &dk);
    }
}
