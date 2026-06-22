//! LMS/HSS hash-based signature backend, wrapping the `hbs-lms` crate.
//!
//! Generic over the hash chain `H`: `Sha256_256` for the showcase profile,
//! `Sha256_192` (the SHA-256/192 truncated set) for the CNSA 2.0 profile.
