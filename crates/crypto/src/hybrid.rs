//! Hybrid KEM: X25519 + ML-KEM, combined into one shared secret.
//!
//! The hybrid runs both component key-exchanges and binds their two shared secrets
//! into a single one, so the result stays secure if *either* X25519 or ML-KEM is
//! broken. The binding is a dual-PRF HKDF combiner: one shared secret is the HKDF
//! salt and the other the input keying material (so HMAC's dual-PRF property gives
//! security if either is random), and the full transcript -- the hybrid ciphertext
//! -- goes into `info`, tying the combined secret to this exact exchange.
