//! Error types for the crate's cryptographic operations.
//!
//! Each operation -- signing, verifying, and key-exchange -- has its own error
//! enum that lists only the cases that operation can produce. The enums are
//! marked non-exhaustive, because more cases may be added as the concrete
//! algorithm backends land; code that matches on them must keep a catch-all arm.
