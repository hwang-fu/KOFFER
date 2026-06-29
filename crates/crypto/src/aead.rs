//! Authenticated encryption (AEAD) value types and the AES-256-GCM and ChaCha20-Poly1305 backends.
//!
//! "Authenticated encryption with associated data" gives confidentiality and
//! tamper-detection together: `unseal` decrypts only if the ciphertext and the
//! associated data are exactly what `seal` produced, and otherwise fails the tag
//! check without releasing any plaintext.
//!
//! The API works in place on a caller-provided buffer and returns the
//! authentication tag separately (a "detached" tag), so it needs no heap and
//! runs on the embedded target. The nonce is supplied by the caller -- the
//! primitive never generates one, which keeps responsibility for using a fresh
//! nonce per key with the composition that owns the key.

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{AeadInPlace, Aes256Gcm as GcmCipher, KeyInit};
// `AeadInPlace`, `KeyInit`, and `GenericArray` above come from the `aead` crate that both
// RustCrypto AEADs re-export, so the ChaCha20-Poly1305 cipher reuses them; only the type differs.
use chacha20poly1305::ChaCha20Poly1305 as ChaChaCipher;

use crate::error::AeadError;

// Fixed AEAD sizes, shared by both backends: AES-256-GCM and ChaCha20-Poly1305
// (RFC 8439) use a 32-byte key, a 12-byte nonce, and a 16-byte tag.
pub const KEY_LEN: usize = 32; // AES-256 key
pub const NONCE_LEN: usize = 12; // 96-bit GCM nonce
pub const TAG_LEN: usize = 16; // 128-bit GCM tag

secret_bytes_newtype! {
    /// A symmetric AEAD key, as raw bytes. 32 bytes for both backends.
    Key, KEY_LEN
}

bytes_newtype! {
    /// An AEAD nonce ("number used once"), as raw bytes. 12 bytes for both backends.
    Nonce, NONCE_LEN
}

bytes_newtype! {
    /// An AEAD authentication tag, as raw bytes. 16 bytes for both backends.
    Tag, TAG_LEN
}

/// An authenticated-encryption backend operating in place on a caller buffer.
///
/// `seal` encrypts the buffer and returns the tag; `unseal` verifies the tag and
/// decrypts. The nonce is caller-supplied and MUST be unique per key -- reusing a
/// nonce under one key breaks the security of GCM.
pub trait Aead {
    /// Encrypts `buffer` in place (plaintext -> ciphertext) and returns the
    /// authentication tag over the ciphertext and `aad`.
    fn seal(
        &self,
        key: &Key,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, AeadError>;

    /// Verifies `tag` over `buffer` and `aad`, then decrypts `buffer` in place.
    ///
    /// Returns `Err(AeadError::UnsealFailed)` if authentication fails, leaving the
    /// buffer's contents unauthenticated and no plaintext trusted.
    fn unseal(
        &self,
        key: &Key,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), AeadError>;
}

// The seal and open bodies are generic over the cipher type; the two backends differ
// only by which RustCrypto cipher they instantiate (both share the `aead` crate traits).

/// Validates the nonce length and copies it into a fixed array.
fn nonce_bytes(nonce: &Nonce) -> Result<[u8; NONCE_LEN], AeadError> {
    nonce
        .as_slice()
        .try_into()
        .map_err(|_| AeadError::MalformedNonce)
}

/// Loads an AEAD cipher from a key, mapping a wrong-length key to `MalformedKey`.
fn load_cipher<C: KeyInit>(key: &Key) -> Result<C, AeadError> {
    C::new_from_slice(key.as_slice()).map_err(|_| AeadError::MalformedKey)
}

/// Seals `buffer` in place with cipher `C` and returns the detached tag.
fn seal_with<C: AeadInPlace + KeyInit>(
    key: &Key,
    nonce: &Nonce,
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<Tag, AeadError> {
    let cipher = load_cipher::<C>(key)?;
    let nonce = nonce_bytes(nonce)?;
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(&nonce), aad, buffer)
        .map_err(|_| AeadError::Internal)?;
    Tag::try_from(tag.as_slice()).map_err(|_| AeadError::Internal)
}

/// Verifies `tag` over `buffer` and `aad`, then decrypts `buffer` in place with cipher `C`.
fn unseal_with<C: AeadInPlace + KeyInit>(
    key: &Key,
    nonce: &Nonce,
    aad: &[u8],
    buffer: &mut [u8],
    tag: &Tag,
) -> Result<(), AeadError> {
    let cipher = load_cipher::<C>(key)?;
    let nonce = nonce_bytes(nonce)?;
    // A wrong-length tag cannot authenticate, so it is reported as a plain
    // unseal failure rather than a distinct error.
    let tag: [u8; TAG_LEN] = tag
        .as_slice()
        .try_into()
        .map_err(|_| AeadError::UnsealFailed)?;
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(&nonce),
            aad,
            buffer,
            GenericArray::from_slice(&tag),
        )
        .map_err(|_| AeadError::UnsealFailed)
}

/// The AES-256-GCM AEAD backend.
pub struct Aes256Gcm;

impl Aead for Aes256Gcm {
    fn seal(
        &self,
        key: &Key,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, AeadError> {
        seal_with::<GcmCipher>(key, nonce, aad, buffer)
    }

    fn unseal(
        &self,
        key: &Key,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), AeadError> {
        unseal_with::<GcmCipher>(key, nonce, aad, buffer, tag)
    }
}

/// The ChaCha20-Poly1305 AEAD backend (RFC 8439).
pub struct ChaCha20Poly1305;

impl Aead for ChaCha20Poly1305 {
    fn seal(
        &self,
        key: &Key,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, AeadError> {
        seal_with::<ChaChaCipher>(key, nonce, aad, buffer)
    }

    fn unseal(
        &self,
        key: &Key,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), AeadError> {
        unseal_with::<ChaChaCipher>(key, nonce, aad, buffer, tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kat::{assert_field, parse};
    use proptest::prelude::*;

    const CAVP_AES_256_GCM: &str = include_str!("../../../kat/aead/cavp-aes-256-gcm.kat");
    const RFC8439_CHACHA20_POLY1305: &str =
        include_str!("../../../kat/aead/rfc8439-chacha20-poly1305.kat");

    // Runs the published known-answer vectors in `kat_text` against `backend`: seal must
    // reproduce each record's ciphertext and tag, and unseal must recover the plaintext.
    fn check_kat(backend: &dyn Aead, kat_text: &str) {
        let records = parse(kat_text).unwrap();
        for record in &records {
            let key = Key::try_from(record.field("key").unwrap()).unwrap();
            let nonce = Nonce::try_from(record.field("nonce").unwrap()).unwrap();
            let aad = record.field("aad").unwrap();
            let plaintext = record.field("plaintext").unwrap();

            // seal: encrypt in place, then check the ciphertext and tag match.
            let mut buffer = plaintext.to_vec();
            let tag = backend.seal(&key, &nonce, aad, &mut buffer).unwrap();
            assert_field(record, "ciphertext", &buffer);
            assert_field(record, "tag", tag.as_slice());

            // unseal: verify against the published tag and decrypt back in place.
            let tag = Tag::try_from(record.field("tag").unwrap()).unwrap();
            backend
                .unseal(&key, &nonce, aad, &mut buffer, &tag)
                .unwrap();
            assert_eq!(buffer.as_slice(), plaintext);
        }
    }

    #[test]
    fn cavp_aes_256_gcm_vectors() {
        check_kat(&Aes256Gcm, CAVP_AES_256_GCM);
    }

    #[test]
    fn rfc8439_chacha20_poly1305_vectors() {
        check_kat(&ChaCha20Poly1305, RFC8439_CHACHA20_POLY1305);
    }

    // The tests below exercise the `Aead` contract itself, so each runs through a `&dyn Aead`
    // and can cover every backend. Per-backend known-answer vectors stay separate (the CAVP
    // test above; the ChaCha20-Poly1305 vectors are added alongside it).

    // seal -> unseal recovers the plaintext for the given key, nonce, AAD, and message.
    fn check_roundtrip(
        backend: &dyn Aead,
        key: &Key,
        nonce: &Nonce,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(), TestCaseError> {
        let mut buffer = plaintext.to_vec();
        let tag = backend.seal(key, nonce, aad, &mut buffer).unwrap();
        backend.unseal(key, nonce, aad, &mut buffer, &tag).unwrap();
        prop_assert_eq!(buffer.as_slice(), plaintext);
        Ok(())
    }

    proptest! {
        #[test]
        fn seal_open_roundtrip(
            key in prop::array::uniform32(any::<u8>()),
            nonce in prop::array::uniform12(any::<u8>()),
            aad in prop::collection::vec(any::<u8>(), 0..64),
            plaintext in prop::collection::vec(any::<u8>(), 0..256),
        ) {
            let key = Key::try_from(&key[..]).unwrap();
            let nonce = Nonce::try_from(&nonce[..]).unwrap();
            check_roundtrip(&Aes256Gcm, &key, &nonce, &aad, &plaintext)?;
            check_roundtrip(&ChaCha20Poly1305, &key, &nonce, &aad, &plaintext)?;
        }
    }

    /// Seals a fixed message with `backend` and returns the parts, for the tamper tests.
    fn seal_fixture(backend: &dyn Aead) -> (Key, Nonce, &'static [u8], Vec<u8>, Tag) {
        let key = Key::try_from(&[0x11u8; KEY_LEN][..]).unwrap();
        let nonce = Nonce::try_from(&[0x22u8; NONCE_LEN][..]).unwrap();
        let aad: &[u8] = b"header";
        let mut buffer = b"secret payload".to_vec();
        let tag = backend.seal(&key, &nonce, aad, &mut buffer).unwrap();
        (key, nonce, aad, buffer, tag)
    }

    fn check_rejects_tampered_ciphertext(backend: &dyn Aead) {
        let (key, nonce, aad, mut buffer, tag) = seal_fixture(backend);
        buffer[0] ^= 0x01;
        assert_eq!(
            backend.unseal(&key, &nonce, aad, &mut buffer, &tag),
            Err(AeadError::UnsealFailed)
        );
    }

    fn check_rejects_tampered_tag(backend: &dyn Aead) {
        let (key, nonce, aad, mut buffer, tag) = seal_fixture(backend);
        let mut bytes = tag.as_slice().to_vec();
        bytes[0] ^= 0x01;
        let tag = Tag::try_from(&bytes[..]).unwrap();
        assert_eq!(
            backend.unseal(&key, &nonce, aad, &mut buffer, &tag),
            Err(AeadError::UnsealFailed)
        );
    }

    fn check_rejects_tampered_aad(backend: &dyn Aead) {
        let (key, nonce, _aad, mut buffer, tag) = seal_fixture(backend);
        assert_eq!(
            backend.unseal(&key, &nonce, b"HEADER", &mut buffer, &tag),
            Err(AeadError::UnsealFailed)
        );
    }

    fn check_rejects_malformed_key_and_nonce(backend: &dyn Aead) {
        let nonce = Nonce::try_from(&[0u8; NONCE_LEN][..]).unwrap();
        let mut buffer = [0u8; 4];

        // A 16-byte value is a valid `Key` newtype but not a valid 256-bit AEAD key.
        let short_key = Key::try_from(&[0u8; 16][..]).unwrap();
        assert_eq!(
            backend.seal(&short_key, &nonce, &[], &mut buffer),
            Err(AeadError::MalformedKey)
        );

        // An 8-byte nonce is a valid `Nonce` newtype but not a 96-bit AEAD nonce.
        let key = Key::try_from(&[0u8; KEY_LEN][..]).unwrap();
        let short_nonce = Nonce::try_from(&[0u8; 8][..]).unwrap();
        assert_eq!(
            backend.seal(&key, &short_nonce, &[], &mut buffer),
            Err(AeadError::MalformedNonce)
        );
    }

    #[test]
    fn unseal_rejects_tampered_ciphertext() {
        check_rejects_tampered_ciphertext(&Aes256Gcm);
        check_rejects_tampered_ciphertext(&ChaCha20Poly1305);
    }

    #[test]
    fn unseal_rejects_tampered_tag() {
        check_rejects_tampered_tag(&Aes256Gcm);
        check_rejects_tampered_tag(&ChaCha20Poly1305);
    }

    #[test]
    fn unseal_rejects_tampered_aad() {
        check_rejects_tampered_aad(&Aes256Gcm);
        check_rejects_tampered_aad(&ChaCha20Poly1305);
    }

    #[test]
    fn rejects_malformed_key_and_nonce() {
        check_rejects_malformed_key_and_nonce(&Aes256Gcm);
        check_rejects_malformed_key_and_nonce(&ChaCha20Poly1305);
    }
}
