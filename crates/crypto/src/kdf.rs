//! Key-derivation (KDF) trait and the HKDF backend.
//!
//! A key-derivation function turns one secret -- such as a shared secret from a
//! key exchange -- plus context into one or more uniformly-random keys. HKDF is
//! the "extract-and-expand" KDF built on HMAC: it first compresses the input
//! keying material into a fixed-size pseudorandom key, then expands that into the
//! requested number of output bytes.
//!
//! The backend is generic over the hash `H` -- `Sha256` for the showcase profile,
//! `Sha384` for the CNSA 2.0 profile -- mirroring the LMS backend's `Lms<H>`.
//! `derive` writes into a caller-provided buffer, so it needs no heap and runs on
//! the embedded target.
