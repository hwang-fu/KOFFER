//! Differential tests for the ML-DSA verify path: our `koffer-crypto` backend
//! against the independent `oqs` (liboqs) reference.
//!
//! Three groups: the Wycheproof verify vectors replayed through both backends,
//! randomized valid and tampered signatures, and a meta-test proving the harness
//! actually catches a disagreeing reference.
