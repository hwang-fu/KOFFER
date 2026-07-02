//! Post-quantum cryptographic primitives and crypto-agility traits for KOFFER.
//!
//! `no_std` by default; enable the `alloc` or `std` feature for heap-backed APIs.
//!
//! # Secret hygiene and constant-time conventions
//!
//! - **Secrets compare in constant time.** The secret value types wrap `koffer_common::Bytes`,
//!   whose `PartialEq` routes through `ConstantTimeEq`, so comparing keys or shared
//!   secrets does not leak their contents through timing.
//! - **Secrets wipe on drop and redact their `Debug`.** `SigningKey`, `DecapsulationKey`,
//!   and `SharedSecret` overwrite their bytes when dropped and print only their type
//!   name, never their contents.
//! - **Constant-time *operations* are each backend's responsibility.** This crate
//!   defines the interfaces and value types; keeping the operations themselves
//!   constant-time -- ML-KEM decapsulation, for instance -- falls to the backend that
//!   implements these traits, not to this layer.

#![cfg_attr(not(test), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod aead;
pub mod alg;
pub mod error;
pub mod hybrid;
pub mod kdf;
pub mod kem;
pub mod lms;
pub mod mldsa;
pub mod mlkem;
pub mod profile;
pub mod seal;
pub mod sign;

mod x25519;

#[cfg(test)]
mod kat;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests {
    use koffer_common::bytes::Bytes;
    use koffer_derive::{ByteNewtype, SecretByteNewtype};

    const TEST_MAX: usize = 4;

    /// Throwaway value type, defined only to exercise the `ByteNewtype` derive that the
    /// real `sign` / `kem` value types all use.
    #[derive(Debug, Clone, PartialEq, Eq, ByteNewtype)]
    struct TestValue(Bytes<TEST_MAX>);

    #[test]
    fn constructs_from_bytes_and_reads_back() {
        let v = TestValue::try_from(&[1, 2, 3][..]).unwrap();
        assert_eq!(v.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn rejects_over_capacity() {
        let over = [0u8; TEST_MAX + 1];
        assert!(TestValue::try_from(&over[..]).is_err());
    }

    /// Throwaway secret type, defined only to exercise the `SecretByteNewtype` derive
    /// that the real secret value types all use.
    #[derive(Clone, PartialEq, Eq, SecretByteNewtype)]
    struct SecretTestValue(Bytes<TEST_MAX>);

    #[test]
    fn secret_debug_is_redacted() {
        let v = SecretTestValue::try_from(&[1, 2, 3][..]).unwrap();
        assert_eq!(v.as_slice(), &[1, 2, 3]);
        assert_eq!(format!("{v:?}"), "SecretTestValue { .. }");
    }
}
