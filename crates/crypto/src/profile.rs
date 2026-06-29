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

    /// Whether `alg` is a permitted AEAD under this profile. AES-256-GCM is required by both
    /// profiles; ChaCha20-Poly1305 is an alternative offered only by the showcase profile
    /// (the CNSA 2.0 profile is AES-256-GCM only).
    pub fn allows_aead(self, alg: AeadAlg) -> bool {
        match alg {
            AeadAlg::Aes256Gcm => true,
            AeadAlg::ChaCha20Poly1305 => matches!(self, CryptoProfile::Showcase),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn showcase_profile_bundle() {
        let p = CryptoProfile::Showcase;
        assert_eq!(p.general_sig(), SigAlg::MlDsa65);
        assert_eq!(p.kem(), KemAlg::MlKem768);
        assert_eq!(p.hybrid_kem(), KemAlg::X25519MlKem768);
        assert_eq!(p.aead(), AeadAlg::Aes256Gcm);
        assert_eq!(p.kdf(), KdfAlg::HkdfSha256);
        assert_eq!(p.hash(), HashAlg::Sha256);
    }

    #[test]
    fn cnsa20_profile_bundle() {
        let p = CryptoProfile::Cnsa20;
        assert_eq!(p.general_sig(), SigAlg::MlDsa87);
        assert_eq!(p.kem(), KemAlg::MlKem1024);
        assert_eq!(p.hybrid_kem(), KemAlg::X25519MlKem1024);
        assert_eq!(p.aead(), AeadAlg::Aes256Gcm);
        assert_eq!(p.kdf(), KdfAlg::HkdfSha384);
        assert_eq!(p.hash(), HashAlg::Sha384);
    }

    #[test]
    fn default_is_showcase() {
        assert_eq!(CryptoProfile::default(), CryptoProfile::Showcase);
    }

    #[test]
    fn aead_gating() {
        // AES-256-GCM is required by both profiles.
        assert!(CryptoProfile::Showcase.allows_aead(AeadAlg::Aes256Gcm));
        assert!(CryptoProfile::Cnsa20.allows_aead(AeadAlg::Aes256Gcm));
        // ChaCha20-Poly1305 is a showcase-only alternative.
        assert!(CryptoProfile::Showcase.allows_aead(AeadAlg::ChaCha20Poly1305));
        assert!(!CryptoProfile::Cnsa20.allows_aead(AeadAlg::ChaCha20Poly1305));
        // A profile always permits the AEAD it defaults to.
        assert!(CryptoProfile::Showcase.allows_aead(CryptoProfile::Showcase.aead()));
        assert!(CryptoProfile::Cnsa20.allows_aead(CryptoProfile::Cnsa20.aead()));
    }
}
