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
const KEY_LEN: usize = 32; // AES-256 key
const NONCE_LEN: usize = 12; // 96-bit GCM nonce
const TAG_LEN: usize = 16; // 128-bit GCM tag

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
