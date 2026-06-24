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
