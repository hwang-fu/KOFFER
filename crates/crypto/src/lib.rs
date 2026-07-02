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

/// Defines a byte-backed crypto value: a distinct newtype over `koffer_common::Bytes<MAX>`,
/// constructed from a length-checked byte slice and -- via `koffer_common::Bytes` -- compared
/// in constant time. Used for the value types in `sign` and `kem`.
macro_rules! bytes_newtype {
    ($(#[$attr:meta])* $name:ident, $max:ident) => {
        $(#[$attr])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name(koffer_common::bytes::Bytes<$max>);

        impl $name {
            /// Returns the value's bytes.
            pub fn as_slice(&self) -> &[u8] {
                self.0.as_slice()
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = koffer_common::bytes::BytesError;

            fn try_from(bytes: &[u8]) -> Result<Self, koffer_common::bytes::BytesError> {
                koffer_common::bytes::Bytes::try_from(bytes).map(Self)
            }
        }
    };
}

/// Like `bytes_newtype!`, but for secret material: the value wipes its bytes on drop,
/// and its `Debug` is redacted so the secret never reaches a log or panic message.
macro_rules! secret_bytes_newtype {
    ($(#[$attr:meta])* $name:ident, $max:ident) => {
        $(#[$attr])*
        #[derive(Clone, PartialEq, Eq)]
        pub struct $name(koffer_common::bytes::Bytes<$max>);

        impl $name {
            /// Returns the value's bytes.
            pub fn as_slice(&self) -> &[u8] {
                self.0.as_slice()
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = koffer_common::bytes::BytesError;

            fn try_from(bytes: &[u8]) -> Result<Self, koffer_common::bytes::BytesError> {
                koffer_common::bytes::Bytes::try_from(bytes).map(Self)
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                // Redacted: print only the type name, never the secret bytes.
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                use zeroize::Zeroize;
                self.0.zeroize();
            }
        }
    };
}

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
    const TEST_MAX: usize = 4;

    bytes_newtype! {
        /// Throwaway value type, defined only to exercise the `bytes_newtype!` macro
        /// that the real `sign` / `kem` value types are all generated from.
        TestValue, TEST_MAX
    }

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

    secret_bytes_newtype! {
        /// Throwaway secret type, defined only to exercise the `secret_bytes_newtype!`
        /// macro that the real secret value types are generated from.
        SecretTestValue, TEST_MAX
    }

    #[test]
    fn secret_debug_is_redacted() {
        let v = SecretTestValue::try_from(&[1, 2, 3][..]).unwrap();
        assert_eq!(v.as_slice(), &[1, 2, 3]);
        assert_eq!(format!("{v:?}"), "SecretTestValue { .. }");
    }
}
