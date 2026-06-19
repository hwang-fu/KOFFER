//! Printable-ASCII-validated strings for externally-supplied text.
//!
//! Identifiers, labels, and displayed strings are constrained to printable 7-bit US-ASCII
//! (0x20-0x7E). Bytes outside that range are rejected at the parse boundary, never silently
//! transcoded.
