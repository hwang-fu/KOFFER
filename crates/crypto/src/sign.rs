//! Signing-side value types: keys and signatures.

// Provisional capacities -- each sized to the largest supported algorithm for its
// role. Placeholders pending the full set of supported algorithms; not final sizes.
const SIGNING_KEY_MAX: usize = 4896; // ML-DSA-87 secret key
const VERIFYING_KEY_MAX: usize = 2592; // ML-DSA-87 public key
const SIGNATURE_MAX: usize = 4627; // ML-DSA-87 signature (HSS may exceed this)

byte_value! {
    /// A secret signing key, as raw bytes.
    SigningKey, SIGNING_KEY_MAX
}

byte_value! {
    /// A public verifying key, as raw bytes.
    VerifyingKey, VERIFYING_KEY_MAX
}

byte_value! {
    /// A signature, as raw bytes.
    Signature, SIGNATURE_MAX
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructs_from_bytes_and_reads_back() {
        let k = SigningKey::try_from(&[1, 2, 3][..]).unwrap();
        assert_eq!(k.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn rejects_over_capacity() {
        let too_long = [0u8; SIGNING_KEY_MAX + 1];
        assert!(SigningKey::try_from(&too_long[..]).is_err());
    }
}
