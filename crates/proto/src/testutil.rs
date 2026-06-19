//! Test-only helpers shared across the crate's unit tests.

/// CBOR initial-byte bases for the major types we assert on the wire (RFC 8949 sec 3).
/// OR with a definite length (under 24) to form the header byte.
pub(crate) const BYTE_STRING: u8 = 0x40; // major type 2
pub(crate) const TEXT_STRING: u8 = 0x60; // major type 3
