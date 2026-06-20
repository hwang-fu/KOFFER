//! Post-quantum cryptographic primitives and crypto-agility traits for KOFFER.
//!
//! `no_std` by default; enable the `alloc` or `std` feature for heap-backed APIs.

#![cfg_attr(not(test), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod error;

#[cfg(test)]
mod tests {
}
