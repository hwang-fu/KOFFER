//! The crypto profile: one value that selects every algorithm for a deployment.
//!
//! Switching profile is a single value change with no per-scheme code edits --
//! this is the crypto-agility seam. The build defaults to the showcase profile.

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
