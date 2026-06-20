//! Catalog of the signature and KEM algorithms KOFFER supports.
//!
//! Each supported algorithm is one variant of `SigAlg` or `KemAlg` -- small tag
//! values chosen at the call site to select a backend.

/// A supported signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigAlg {
    /// HSS/LMS hash-based signatures, SHA-256.
    HssLmsSha256,
    /// Single-tree LMS hash-based signatures, SHA-256.
    LmsSha256,
    /// ML-DSA-65 lattice signatures.
    MlDsa65,
    /// ML-DSA-87 lattice signatures.
    MlDsa87,
}

/// A supported key-encapsulation (KEM) algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemAlg {
    /// ML-KEM-768.
    MlKem768,
    /// ML-KEM-1024.
    MlKem1024,
    /// Hybrid X25519 + ML-KEM-768.
    X25519MlKem768,
    /// Hybrid X25519 + ML-KEM-1024.
    X25519MlKem1024,
}

// COSE algorithm codepoints. `-46` is the IANA-registered HSS-LMS identifier
// (RFC 8778). The others have no stable COSE registration yet, so they are
// pinned to project-local values in COSE's Private Use range (codepoints below
// -65536, which IANA will not assign) -- swap to official codepoints if those
// are registered later. Signatures and KEMs share one COSE codepoint namespace,
// so every value below is distinct.
const COSE_HSS_LMS: i32 = -46;
const COSE_ML_DSA_65: i32 = -65537;
const COSE_ML_DSA_87: i32 = -65538;
const COSE_ML_KEM_768: i32 = -65539;
const COSE_ML_KEM_1024: i32 = -65540;
const COSE_X25519_ML_KEM_768: i32 = -65541;
const COSE_X25519_ML_KEM_1024: i32 = -65542;
