//! Key-exchange (KEM) value types: keys, ciphertext, and shared secret.

// Provisional capacities -- the hybrid figures add X25519's 32 bytes to the
// ML-KEM-1024 sizes. Placeholders pending the full set of supported algorithms.
const ENCAPSULATION_KEY_MAX: usize = 1600; // X25519 (32) + ML-KEM-1024 ek (1568)
const DECAPSULATION_KEY_MAX: usize = 3200; // X25519 (32) + ML-KEM-1024 dk (3168)
const CIPHERTEXT_MAX: usize = 1600; // X25519 (32) + ML-KEM-1024 ct (1568)
const SHARED_SECRET_MAX: usize = 32; // combiner output

byte_value! {
    /// A public encapsulation key, as raw bytes.
    EncapsulationKey, ENCAPSULATION_KEY_MAX
}

byte_value! {
    /// A secret decapsulation key, as raw bytes.
    DecapsulationKey, DECAPSULATION_KEY_MAX
}

byte_value! {
    /// A KEM ciphertext (the sealed value), as raw bytes.
    Ciphertext, CIPHERTEXT_MAX
}

byte_value! {
    /// A derived shared secret, as raw bytes.
    SharedSecret, SHARED_SECRET_MAX
}
