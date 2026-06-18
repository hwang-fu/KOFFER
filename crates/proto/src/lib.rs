//! Shared protocol types, wire formats, and message definitions for KOFFER.
//!
//! `no_std` by default; enable the `alloc` or `std` feature for heap-backed APIs.

#![cfg_attr(not(test), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        let sum = 2 + 2;
        assert_eq!(sum, 4);
    }
}
