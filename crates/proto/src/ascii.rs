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
