//! Printable-ASCII-validated strings for externally-supplied text.
//!
//! Identifiers, labels, and displayed strings are constrained to printable 7-bit US-ASCII
//! (0x20-0x7E). Bytes outside that range are rejected at the parse boundary, never silently
//! transcoded.

use core::{fmt, ops::Deref};

/// Error returned when input contains a byte outside printable 7-bit US-ASCII (0x20-0x7E).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsciiError;

impl fmt::Display for AsciiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("input is not printable 7-bit US-ASCII")
    }
}

impl core::error::Error for AsciiError {}

/// `Ok` only if every byte is printable 7-bit US-ASCII (0x20-0x7E).
fn validate(bytes: &[u8]) -> Result<(), AsciiError> {
    if bytes.iter().all(|b| (0x20u8..=0x7E).contains(b)) {
        Ok(())
    } else {
        Err(AsciiError)
    }
}
