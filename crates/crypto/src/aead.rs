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
