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
