//! The crypto profile: one value that selects every algorithm for a deployment.
//!
//! Switching profile is a single value change with no per-scheme code edits --
//! this is the crypto-agility seam. The build defaults to the showcase profile.

use crate::alg::{AeadAlg, HashAlg, KdfAlg, KemAlg, SigAlg};

/// A bundle of algorithm choices selected together.
///
/// Each profile fixes one algorithm per role; the accessors return them. The
/// hash-based signature roles (device root, online signer) are added when the
/// hash-based signing backend is implemented, once their parameters are fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CryptoProfile {
    /// The showcase profile -- the default build.
    #[default]
    Showcase,
    /// The CNSA 2.0 profile.
    Cnsa20,
}

impl CryptoProfile {
    /// The general-purpose (lattice) signature algorithm.
    pub fn general_sig(self) -> SigAlg {
        match self {
            CryptoProfile::Showcase => SigAlg::MlDsa65,
            CryptoProfile::Cnsa20 => SigAlg::MlDsa87,
        }
    }

    /// The key-encapsulation algorithm.
    pub fn kem(self) -> KemAlg {
        match self {
            CryptoProfile::Showcase => KemAlg::MlKem768,
            CryptoProfile::Cnsa20 => KemAlg::MlKem1024,
        }
    }

    /// The hybrid key-encapsulation algorithm.
    pub fn hybrid_kem(self) -> KemAlg {
        match self {
            CryptoProfile::Showcase => KemAlg::X25519MlKem768,
            CryptoProfile::Cnsa20 => KemAlg::X25519MlKem1024,
        }
    }

    /// The authenticated-encryption (AEAD) algorithm.
    pub fn aead(self) -> AeadAlg {
        match self {
            CryptoProfile::Showcase => AeadAlg::Aes256Gcm,
            CryptoProfile::Cnsa20 => AeadAlg::Aes256Gcm,
        }
    }

    /// The key-derivation function.
    pub fn kdf(self) -> KdfAlg {
        match self {
            CryptoProfile::Showcase => KdfAlg::HkdfSha256,
            CryptoProfile::Cnsa20 => KdfAlg::HkdfSha384,
        }
    }

    /// The general-purpose hash function.
    pub fn hash(self) -> HashAlg {
        match self {
            CryptoProfile::Showcase => HashAlg::Sha256,
            CryptoProfile::Cnsa20 => HashAlg::Sha384,
        }
    }
}
