//! Catalog of the signature and KEM algorithms KOFFER supports.
//!
//! Each supported algorithm is one variant of `SigAlg` or `KemAlg` -- small tag
//! values chosen at the call site to select a backend.

/// A supported signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigAlg {
    /// HSS/LMS hash-based signatures, SHA-256.
    HssLmsSha256,
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

impl SigAlg {
    /// The COSE algorithm codepoint that identifies this algorithm on the wire.
    pub fn cose_id(self) -> i32 {
        match self {
            SigAlg::HssLmsSha256 => COSE_HSS_LMS,
            SigAlg::MlDsa65 => COSE_ML_DSA_65,
            SigAlg::MlDsa87 => COSE_ML_DSA_87,
        }
    }

    /// The algorithm for a COSE codepoint, or `None` if it is not recognized.
    pub fn from_cose_id(id: i32) -> Option<Self> {
        match id {
            COSE_HSS_LMS => Some(SigAlg::HssLmsSha256),
            COSE_ML_DSA_65 => Some(SigAlg::MlDsa65),
            COSE_ML_DSA_87 => Some(SigAlg::MlDsa87),
            _ => None,
        }
    }
}

impl KemAlg {
    /// The COSE algorithm codepoint that identifies this algorithm on the wire.
    pub fn cose_id(self) -> i32 {
        match self {
            KemAlg::MlKem768 => COSE_ML_KEM_768,
            KemAlg::MlKem1024 => COSE_ML_KEM_1024,
            KemAlg::X25519MlKem768 => COSE_X25519_ML_KEM_768,
            KemAlg::X25519MlKem1024 => COSE_X25519_ML_KEM_1024,
        }
    }

    /// The algorithm for a COSE codepoint, or `None` if it is not recognized.
    pub fn from_cose_id(id: i32) -> Option<Self> {
        match id {
            COSE_ML_KEM_768 => Some(KemAlg::MlKem768),
            COSE_ML_KEM_1024 => Some(KemAlg::MlKem1024),
            COSE_X25519_ML_KEM_768 => Some(KemAlg::X25519MlKem768),
            COSE_X25519_ML_KEM_1024 => Some(KemAlg::X25519MlKem1024),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIG_ALGS: [SigAlg; 3] = [SigAlg::HssLmsSha256, SigAlg::MlDsa65, SigAlg::MlDsa87];
    const KEM_ALGS: [KemAlg; 4] = [
        KemAlg::MlKem768,
        KemAlg::MlKem1024,
        KemAlg::X25519MlKem768,
        KemAlg::X25519MlKem1024,
    ];

    #[test]
    fn sig_alg_codepoints_round_trip() {
        for alg in SIG_ALGS {
            assert_eq!(SigAlg::from_cose_id(alg.cose_id()), Some(alg));
        }
    }

    #[test]
    fn kem_alg_codepoints_round_trip() {
        for alg in KEM_ALGS {
            assert_eq!(KemAlg::from_cose_id(alg.cose_id()), Some(alg));
        }
    }

    #[test]
    fn unknown_codepoint_is_none() {
        assert_eq!(SigAlg::from_cose_id(0), None);
        assert_eq!(KemAlg::from_cose_id(0), None);
    }

    #[test]
    fn all_codepoints_are_distinct() {
        let ids = [
            SigAlg::HssLmsSha256.cose_id(),
            SigAlg::MlDsa65.cose_id(),
            SigAlg::MlDsa87.cose_id(),
            KemAlg::MlKem768.cose_id(),
            KemAlg::MlKem1024.cose_id(),
            KemAlg::X25519MlKem768.cose_id(),
            KemAlg::X25519MlKem1024.cose_id(),
        ];
        for (i, a) in ids.iter().enumerate() {
            for b in &ids[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }
}
