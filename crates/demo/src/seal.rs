//! Seal a payload with the KEM+DEM core and frame it as a `COSE_Encrypt`, then open it,
//! with the backends selected by the integer COSE codepoint.
//!
//! `crypto::seal`/`unseal` are generic free functions, so -- unlike the signer -- the demo
//! cannot hand them a boxed backend. The dispatch helpers below `match` the profile (seal
//! side) or the wire codepoint (open side) and call `seal::<concrete>` inside each arm; the
//! flow itself never names a scheme. The KDF is not carried on the wire -- it is pinned to
//! the KEM level (which identifies the profile), so the open side derives it from the KEM
//! codepoint. The KEM is the hybrid X25519 + ML-KEM; the AEAD is AES-256-GCM.

use crypto::aead::Aes256Gcm;
use crypto::alg::KemAlg;
use crypto::hybrid::{X25519MlKem768, X25519MlKem1024};
use crypto::kdf::Hkdf;
use crypto::kem::{DecapsulationKey, EncapsulationKey};
use crypto::profile::CryptoProfile;
use crypto::seal::{Sealed, seal, unseal};
use proto::alg::AlgId;
use rand_core::CryptoRng;
use sha2::{Sha256, Sha384};

// Per-scheme knowledge lives only in the three helpers below; the flow never names a scheme.

/// Generates the recipient keypair for `profile`'s hybrid KEM.
fn keygen_recipient(
    profile: CryptoProfile,
    entropy: &[u8],
) -> (EncapsulationKey, DecapsulationKey) {
    match profile {
        CryptoProfile::Showcase => X25519MlKem768.keygen(entropy),
        CryptoProfile::Cnsa20 => X25519MlKem1024.keygen(entropy),
    }
    .expect("hybrid KEM keygen")
}

/// Seals `buffer` in place (KEM + KDF + AEAD chosen by `profile`); returns the `Sealed` parts.
fn seal_with_profile(
    profile: CryptoProfile,
    recipient: &EncapsulationKey,
    aad: &[u8],
    buffer: &mut [u8],
    rng: &mut dyn CryptoRng,
) -> Sealed {
    match profile {
        CryptoProfile::Showcase => seal(
            &X25519MlKem768,
            &Hkdf::<Sha256>::new(),
            &Aes256Gcm,
            recipient,
            aad,
            buffer,
            rng,
        ),
        CryptoProfile::Cnsa20 => seal(
            &X25519MlKem1024,
            &Hkdf::<Sha384>::new(),
            &Aes256Gcm,
            recipient,
            aad,
            buffer,
            rng,
        ),
    }
    .expect("seal")
}

/// Unseals `buffer` in place, selecting the KEM (and its pinned KDF) from the wire codepoint.
fn unseal_from_codepoint(
    kem_alg: AlgId,
    decapsulation_key: &DecapsulationKey,
    sealed: &Sealed,
    aad: &[u8],
    buffer: &mut [u8],
) -> bool {
    match KemAlg::from_cose_id(kem_alg.get() as i32) {
        Some(KemAlg::X25519MlKem768) => unseal(
            &X25519MlKem768,
            &Hkdf::<Sha256>::new(),
            &Aes256Gcm,
            decapsulation_key,
            sealed,
            aad,
            buffer,
        )
        .is_ok(),
        Some(KemAlg::X25519MlKem1024) => unseal(
            &X25519MlKem1024,
            &Hkdf::<Sha384>::new(),
            &Aes256Gcm,
            decapsulation_key,
            sealed,
            aad,
            buffer,
        )
        .is_ok(),
        other => panic!("unsupported KEM codepoint: {other:?}"),
    }
}
