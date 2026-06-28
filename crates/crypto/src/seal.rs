//! HPKE-style KEM+DEM seal/open core.
//!
//! Encrypt a payload to a recipient's KEM public key by combining a KEM with the AEAD:
//! encapsulate a fresh shared secret to the recipient, derive an AEAD key and nonce from
//! it via the KDF, then AEAD-encrypt the payload. Only the holder of the KEM private key
//! can decapsulate and open it (RFC 9180-aligned). The components are returned as raw
//! bytes; the `COSE_Encrypt` framing is applied by the consumer, so this crate stays
//! independent of `koffer-proto`.

use crate::{aead, kem::Ciphertext};

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
