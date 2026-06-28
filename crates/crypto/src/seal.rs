//! HPKE-style KEM+DEM seal/open core.
//!
//! Encrypt a payload to a recipient's KEM public key by combining a KEM with the AEAD:
//! encapsulate a fresh shared secret to the recipient, derive an AEAD key and nonce from
//! it via the KDF, then AEAD-encrypt the payload. Only the holder of the KEM private key
//! can decapsulate and open it (RFC 9180-aligned). The components are returned as raw
//! bytes; the `COSE_Encrypt` framing is applied by the consumer, so this crate stays
//! independent of `koffer-proto`.
