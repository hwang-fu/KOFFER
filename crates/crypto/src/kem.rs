//! Key-exchange (KEM) value types: keys, ciphertext, and shared secret.

use crate::error::KemError;

// Buffer capacities, each the largest over the supported KEM algorithms -- the
// hybrid X25519 + ML-KEM-1024 sizes. The key and ciphertext figures add X25519's
// 32 bytes to the ML-KEM-1024 size; the shared secret is the combiner's output.
const ENCAPSULATION_KEY_MAX: usize = 1600; // X25519 (32) + ML-KEM-1024 ek (1568)
const DECAPSULATION_KEY_MAX: usize = 3200; // X25519 (32) + ML-KEM-1024 dk (3168)
const CIPHERTEXT_MAX: usize = 1600; // X25519 (32) + ML-KEM-1024 ct (1568)
const SHARED_SECRET_MAX: usize = 32; // combiner output

byte_value! {
    /// A public encapsulation key, as raw bytes.
    EncapsulationKey, ENCAPSULATION_KEY_MAX
}

secret_byte_value! {
    /// A secret decapsulation key, as raw bytes.
    DecapsulationKey, DECAPSULATION_KEY_MAX
}

byte_value! {
    /// A KEM ciphertext (the sealed value), as raw bytes.
    Ciphertext, CIPHERTEXT_MAX
}

secret_byte_value! {
    /// A derived shared secret, as raw bytes.
    SharedSecret, SHARED_SECRET_MAX
}

/// A key-encapsulation backend: agree a shared secret using a peer's public key.
///
/// `encapsulate` draws randomness from the supplied source -- on the device, the
/// firmware's TRNG-backed entropy; in tests, a seeded deterministic RNG.
/// `decapsulate` is deterministic.
pub trait Kem {
    /// Generates a fresh shared secret for `key`, returned with the ciphertext that
    /// lets the holder of the matching decapsulation key recover it.
    fn encapsulate(
        &self,
        key: &EncapsulationKey,
        rng: &mut dyn rand_core::CryptoRngCore,
    ) -> Result<(Ciphertext, SharedSecret), KemError>;

    /// Recovers the shared secret from `ciphertext` using `key`.
    fn decapsulate(
        &self,
        key: &DecapsulationKey,
        ciphertext: &Ciphertext,
    ) -> Result<SharedSecret, KemError>;
}
