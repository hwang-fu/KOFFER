//! Shared protocol types, wire formats, and message definitions for KOFFER.
//!
//! `no_std` by default; enable the `alloc` or `std` feature for heap-backed APIs.

#![cfg_attr(not(test), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod alg;
pub mod ascii;
pub mod bytes;
pub mod codec;
pub mod digest;
pub mod error;
