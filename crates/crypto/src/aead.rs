//! Authenticated encryption (AEAD) value types and the AES-256-GCM backend.
//!
//! "Authenticated encryption with associated data" gives confidentiality and
//! tamper-detection together: `open` decrypts only if the ciphertext and the
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

use crate::error::AeadError;

// AES-256-GCM fixed sizes. A future ChaCha20-Poly1305 backend shares all three,
// so these bounds are exact for every AEAD this crate plans to support.
pub const KEY_LEN: usize = 32; // AES-256 key
pub const NONCE_LEN: usize = 12; // 96-bit GCM nonce
pub const TAG_LEN: usize = 16; // 128-bit GCM tag

secret_bytes_newtype! {
    /// A symmetric AEAD key, as raw bytes. 32 bytes for AES-256-GCM.
    Key, KEY_LEN
}

bytes_newtype! {
    /// An AEAD nonce ("number used once"), as raw bytes. 12 bytes for AES-256-GCM.
    Nonce, NONCE_LEN
}

bytes_newtype! {
    /// An AEAD authentication tag, as raw bytes. 16 bytes for AES-256-GCM.
    Tag, TAG_LEN
}

/// An authenticated-encryption backend operating in place on a caller buffer.
///
/// `seal` encrypts the buffer and returns the tag; `open` verifies the tag and
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
    /// Returns `Err(AeadError::OpenFailed)` if authentication fails, leaving the
    /// buffer's contents unauthenticated and no plaintext trusted.
    fn open(
        &self,
        key: &Key,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), AeadError>;
}

/// The AES-256-GCM AEAD backend.
pub struct Aes256Gcm;

impl Aes256Gcm {
    /// Loads the cipher from a key, mapping a wrong-length key to `MalformedKey`.
    fn cipher(key: &Key) -> Result<GcmCipher, AeadError> {
        GcmCipher::new_from_slice(key.as_slice()).map_err(|_| AeadError::MalformedKey)
    }

    /// Validates the nonce length and copies it into a fixed array.
    fn nonce_bytes(nonce: &Nonce) -> Result<[u8; NONCE_LEN], AeadError> {
        nonce
            .as_slice()
            .try_into()
            .map_err(|_| AeadError::MalformedNonce)
    }
}

impl Aead for Aes256Gcm {
    fn seal(
        &self,
        key: &Key,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, AeadError> {
        let cipher = Self::cipher(key)?;
        let nonce = Self::nonce_bytes(nonce)?;
        let tag = cipher
            .encrypt_in_place_detached(GenericArray::from_slice(&nonce), aad, buffer)
            .map_err(|_| AeadError::Internal)?;
        Tag::try_from(tag.as_slice()).map_err(|_| AeadError::Internal)
    }

    fn open(
        &self,
        key: &Key,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), AeadError> {
        let cipher = Self::cipher(key)?;
        let nonce = Self::nonce_bytes(nonce)?;
        // A wrong-length tag cannot authenticate, so it is reported as a plain
        // open failure rather than a distinct error.
        let tag: [u8; TAG_LEN] = tag
            .as_slice()
            .try_into()
            .map_err(|_| AeadError::OpenFailed)?;
        cipher
            .decrypt_in_place_detached(
                GenericArray::from_slice(&nonce),
                aad,
                buffer,
                GenericArray::from_slice(&tag),
            )
            .map_err(|_| AeadError::OpenFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kat::{assert_field, parse};
    use proptest::prelude::*;

    const CAVP: &str = include_str!("../../../kat/aead/cavp-aes-256-gcm.kat");

    #[test]
    fn cavp_aes_256_gcm_vectors() {
        let records = parse(CAVP).unwrap();
        let backend = Aes256Gcm;
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

            // open: verify against the published tag and decrypt back in place.
            let tag = Tag::try_from(record.field("tag").unwrap()).unwrap();
            backend.open(&key, &nonce, aad, &mut buffer, &tag).unwrap();
            assert_eq!(buffer.as_slice(), plaintext);
        }
    }

    // seal -> open recovers the plaintext for arbitrary key, nonce, AAD, and message.
    proptest! {
        #[test]
        fn seal_open_roundtrip(
            key in prop::array::uniform32(any::<u8>()),
            nonce in prop::array::uniform12(any::<u8>()),
            aad in prop::collection::vec(any::<u8>(), 0..64),
            plaintext in prop::collection::vec(any::<u8>(), 0..256),
        ) {
            let backend = Aes256Gcm;
            let key = Key::try_from(&key[..]).unwrap();
            let nonce = Nonce::try_from(&nonce[..]).unwrap();

            let mut buffer = plaintext.clone();
            let tag = backend.seal(&key, &nonce, &aad, &mut buffer).unwrap();
            backend.open(&key, &nonce, &aad, &mut buffer, &tag).unwrap();
            prop_assert_eq!(buffer, plaintext);
        }
    }

    /// Seals a fixed message and returns the parts, for the tamper tests.
    fn sealed() -> (Aes256Gcm, Key, Nonce, &'static [u8], Vec<u8>, Tag) {
        let backend = Aes256Gcm;
        let key = Key::try_from(&[0x11u8; 32][..]).unwrap();
        let nonce = Nonce::try_from(&[0x22u8; 12][..]).unwrap();
        let aad: &[u8] = b"header";
        let mut buffer = b"secret payload".to_vec();
        let tag = backend.seal(&key, &nonce, aad, &mut buffer).unwrap();
        (backend, key, nonce, aad, buffer, tag)
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let (backend, key, nonce, aad, mut buffer, tag) = sealed();
        buffer[0] ^= 0x01;
        assert_eq!(
            backend.open(&key, &nonce, aad, &mut buffer, &tag),
            Err(AeadError::OpenFailed)
        );
    }

    #[test]
    fn open_rejects_tampered_tag() {
        let (backend, key, nonce, aad, mut buffer, tag) = sealed();
        let mut bytes = tag.as_slice().to_vec();
        bytes[0] ^= 0x01;
        let tag = Tag::try_from(&bytes[..]).unwrap();
        assert_eq!(
            backend.open(&key, &nonce, aad, &mut buffer, &tag),
            Err(AeadError::OpenFailed)
        );
    }

    #[test]
    fn open_rejects_tampered_aad() {
        let (backend, key, nonce, _aad, mut buffer, tag) = sealed();
        assert_eq!(
            backend.open(&key, &nonce, b"HEADER", &mut buffer, &tag),
            Err(AeadError::OpenFailed)
        );
    }

    #[test]
    fn rejects_malformed_key_and_nonce() {
        let backend = Aes256Gcm;
        let nonce = Nonce::try_from(&[0u8; 12][..]).unwrap();
        let mut buffer = [0u8; 4];

        // A 16-byte value is a valid `Key` newtype but not a valid AES-256 key.
        let short_key = Key::try_from(&[0u8; 16][..]).unwrap();
        assert_eq!(
            backend.seal(&short_key, &nonce, &[], &mut buffer),
            Err(AeadError::MalformedKey)
        );

        // An 8-byte nonce is a valid `Nonce` newtype but not a 96-bit GCM nonce.
        let key = Key::try_from(&[0u8; 32][..]).unwrap();
        let short_nonce = Nonce::try_from(&[0u8; 8][..]).unwrap();
        assert_eq!(
            backend.seal(&key, &short_nonce, &[], &mut buffer),
            Err(AeadError::MalformedNonce)
        );
    }
}
