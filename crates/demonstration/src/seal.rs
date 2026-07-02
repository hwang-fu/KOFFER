//! Seal a payload with the KEM+DEM core and frame it as a `COSE_Encrypt`, then unseal it,
//! with the backends selected by the integer COSE codepoint.
//!
//! `koffer_cryptography::seal`/`unseal` are generic free functions, so -- unlike the signer -- the demo
//! cannot hand them a boxed backend. The dispatch helpers below `match` the profile (seal
//! side) or the wire codepoint (unseal side) and call `seal::<concrete>` inside each arm; the
//! flow itself never names a scheme. The KDF is not carried on the wire -- it is pinned to
//! the KEM level (which identifies the profile), so the unseal side derives it from the KEM
//! codepoint. The KEM is the hybrid X25519 + ML-KEM; the AEAD is AES-256-GCM.

use koffer_cryptography::{
    aead::{Aes256Gcm, Nonce, TAG_LEN, Tag},
    alg::KemAlg,
    hybrid::{X25519MlKem768, X25519MlKem1024},
    kdf::Hkdf,
    kem::{Ciphertext, DecapsulationKey, EncapsulationKey},
    profile::CryptoProfile,
    seal::{Sealed, seal, unseal},
};
use koffer_wire::{
    alg::AlgId,
    codec,
    cose::{CoseEncrypt, Recipient},
};
use rand_core::CryptoRng;
use sha2::{Sha256, Sha384};

/// Seals `plaintext` to a fresh recipient keypair under `profile` and frames it as an
/// encoded `COSE_Encrypt`. Returns the encoding and the decapsulation key that unseals it.
pub fn seal_payload(
    profile: CryptoProfile,
    plaintext: &[u8],
    aad: &[u8],
    rng: &mut dyn CryptoRng,
) -> (Vec<u8>, DecapsulationKey) {
    let mut keygen_entropy = [0u8; 96];
    rng.fill_bytes(&mut keygen_entropy);
    let (encapsulation_key, decapsulation_key) = keygen_recipient(profile, &keygen_entropy);

    let mut buffer = plaintext.to_vec();
    let sealed = seal_with_profile(profile, &encapsulation_key, aad, &mut buffer, rng);
    buffer.extend_from_slice(sealed.tag.as_slice()); // frame ciphertext || tag

    let recipient = Recipient::new(
        AlgId::new(profile.hybrid_kem().cose_id() as i64),
        None,
        sealed.kem_ciphertext.as_slice(),
    );
    let cose = CoseEncrypt::new(
        AlgId::new(profile.aead().cose_id() as i64),
        sealed.nonce.as_slice(),
        &buffer,
        recipient,
    );
    (
        codec::encode(&cose).expect("encode COSE_Encrypt"),
        decapsulation_key,
    )
}

/// Unseals an encoded `COSE_Encrypt` with `decapsulation_key`, recovering the plaintext. The
/// KEM/AEAD backends are chosen purely from the wire codepoints; `None` on any failure.
pub fn unseal_payload(
    cose_bytes: &[u8],
    decapsulation_key: &DecapsulationKey,
    aad: &[u8],
) -> Option<Vec<u8>> {
    let cose = codec::decode::<CoseEncrypt>(cose_bytes).ok()?;
    let recipient = cose.recipient();
    let body = cose.ciphertext();
    if body.len() < TAG_LEN {
        return None;
    }
    let (ciphertext, tag) = body.split_at(body.len() - TAG_LEN);
    let sealed = Sealed {
        kem_ciphertext: Ciphertext::try_from(recipient.encapsulation()).ok()?,
        nonce: Nonce::try_from(cose.nonce()).ok()?,
        tag: Tag::try_from(tag).ok()?,
    };

    let mut buffer = ciphertext.to_vec();
    unseal_from_codepoint(
        recipient.kem_alg(),
        decapsulation_key,
        &sealed,
        aad,
        &mut buffer,
    )
    .then_some(buffer)
}

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

#[cfg(test)]
mod tests {
    use koffer_testutil::TestRng;

    use super::*;

    #[test]
    fn seal_then_unseal_round_trips() {
        let (cose, dk) = seal_payload(
            CryptoProfile::Showcase,
            b"payload",
            b"ctx",
            &mut TestRng::new(1),
        );
        assert_eq!(
            unseal_payload(&cose, &dk, b"ctx").as_deref(),
            Some(&b"payload"[..])
        );
    }

    #[test]
    fn tampered_container_is_rejected() {
        let (mut cose, dk) = seal_payload(
            CryptoProfile::Showcase,
            b"payload",
            b"ctx",
            &mut TestRng::new(1),
        );
        let mid = cose.len() / 2;
        cose[mid] ^= 0x01;
        assert!(unseal_payload(&cose, &dk, b"ctx").is_none());
    }
}
