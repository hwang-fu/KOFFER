//! End-to-end software demo that wires `koffer-proto` and `koffer-crypto`
//! together. It builds a SUIT manifest, signs it as a `COSE_Sign1`
//! and verifies it, then seals a payload with the KEM+DEM core into a `COSE_Encrypt`
//! and opens it -- the whole flow in both crypto profiles, with the integer COSE
//! codepoint on the wire selecting the backend.
//!
//! This is the first crate that depends on both foundation crates. It is host-only
//! and is never part of the firmware build.
