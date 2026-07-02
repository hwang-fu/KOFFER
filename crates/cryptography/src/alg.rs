//! Catalog of the cryptographic algorithms KOFFER supports.
//!
//! Each supported algorithm is one variant of an enum here -- small tag values
//! chosen at the call site to select a backend. The signature and KEM algorithms
//! (`SigAlg`, `KemAlg`) also map to a stable integer COSE codepoint, the only form
//! that travels on the wire; the symmetric and hashing algorithms do not carry a
//! codepoint yet.

/// A supported signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SigAlg {
    /// HSS/LMS hash-based signatures, SHA-256.
    HssLmsSha256 = COSE_HSS_LMS,
    /// ML-DSA-65 lattice signatures.
    MlDsa65 = COSE_ML_DSA_65,
    /// ML-DSA-87 lattice signatures.
    MlDsa87 = COSE_ML_DSA_87,
}

/// A supported key-encapsulation (KEM) algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum KemAlg {
    /// ML-KEM-768.
    MlKem768 = COSE_ML_KEM_768,
    /// ML-KEM-1024.
    MlKem1024 = COSE_ML_KEM_1024,
    /// Hybrid X25519 + ML-KEM-768.
    X25519MlKem768 = COSE_X25519_ML_KEM_768,
    /// Hybrid X25519 + ML-KEM-1024.
    X25519MlKem1024 = COSE_X25519_ML_KEM_1024,
}

/// A supported authenticated-encryption (AEAD) algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum AeadAlg {
    /// AES-256-GCM.
    Aes256Gcm = COSE_AES_256_GCM,
    /// ChaCha20-Poly1305.
    ChaCha20Poly1305 = COSE_CHACHA20_POLY1305,
}

/// A supported key-derivation function (KDF).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfAlg {
    /// HKDF with SHA-256.
    HkdfSha256,
    /// HKDF with SHA-384.
    HkdfSha384,
}

/// A supported hash function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
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

// AEAD codepoints are IANA-registered (RFC 9053), unlike the project-local PQC values above.
const COSE_AES_256_GCM: i32 = 3;
const COSE_CHACHA20_POLY1305: i32 = 24;

impl SigAlg {
    /// The COSE algorithm codepoint that identifies this algorithm on the wire.
    pub fn cose_id(self) -> i32 {
        self as i32
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
        self as i32
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

impl AeadAlg {
    /// The COSE algorithm codepoint that identifies this AEAD on the wire.
    pub fn cose_id(self) -> i32 {
        self as i32
    }

    /// The AEAD for a COSE codepoint, or `None` if it is not recognized.
    pub fn from_cose_id(id: i32) -> Option<Self> {
        match id {
            COSE_AES_256_GCM => Some(AeadAlg::Aes256Gcm),
            COSE_CHACHA20_POLY1305 => Some(AeadAlg::ChaCha20Poly1305),
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
    fn aead_alg_codepoints_round_trip() {
        for alg in [AeadAlg::Aes256Gcm, AeadAlg::ChaCha20Poly1305] {
            assert_eq!(AeadAlg::from_cose_id(alg.cose_id()), Some(alg));
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
