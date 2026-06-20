//! Post-quantum cryptographic primitives and crypto-agility traits for KOFFER.
//!
//! `no_std` by default; enable the `alloc` or `std` feature for heap-backed APIs.

#![cfg_attr(not(test), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

/// Defines a byte-backed crypto value: a distinct newtype over `base::Bytes<MAX>`,
/// constructed from a length-checked byte slice and -- via `base::Bytes` -- compared
/// in constant time. Used for the value types in `sign` and `kem`.
macro_rules! byte_value {
      ($(#[$attr:meta])* $name:ident, $max:ident) => {
          $(#[$attr])*
          #[derive(Debug, Clone, PartialEq, Eq)]
          pub struct $name(base::bytes::Bytes<$max>);

          impl $name {
              /// Returns the value's bytes.
              pub fn as_slice(&self) -> &[u8] {
                  self.0.as_slice()
              }
          }

          impl TryFrom<&[u8]> for $name {
              type Error = base::bytes::TooLong;

              fn try_from(bytes: &[u8]) -> Result<Self, base::bytes::TooLong> {
                  base::bytes::Bytes::try_from(bytes).map(Self)
              }
          }
      };
  }

pub mod alg;
pub mod error;
pub mod kem;
pub mod sign;

#[cfg(test)]
mod tests {
    const TEST_MAX: usize = 4;

    byte_value! {
        /// Throwaway value type, defined only to exercise the `byte_value!` macro
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
}
