//! Printable-ASCII-validated strings for externally-supplied text.
//!
//! Identifiers, labels, and displayed strings are constrained to printable 7-bit US-ASCII
//! (0x20-0x7E). Bytes outside that range are rejected at the parse boundary, never silently
//! transcoded.

use core::fmt;
use core::ops::Deref;

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

/// A borrowed string validated to contain only printable 7-bit US-ASCII.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AsciiStr<'a>(&'a str);

impl<'a> AsciiStr<'a> {
    pub fn as_str(&self) -> &str {
        self.0
    }
}

impl AsRef<str> for AsciiStr<'_> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> TryFrom<&'a str> for AsciiStr<'a> {
    type Error = AsciiError;

    fn try_from(s: &'a str) -> Result<Self, AsciiError> {
        validate(s.as_bytes())?;
        Ok(Self(s))
    }
}

impl<'a> TryFrom<&'a [u8]> for AsciiStr<'a> {
    type Error = AsciiError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, AsciiError> {
        // Reject invalid UTF-8 first; printable ASCII is a subset, so no valid input is lost.
        let s = core::str::from_utf8(bytes).map_err(|_| AsciiError)?;
        Self::try_from(s)
    }
}

impl Deref for AsciiStr<'_> {
    type Target = str;

    fn deref(&self) -> &str {
        self.0
    }
}

impl fmt::Display for AsciiStr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// An owned string validated to contain only printable 7-bit US-ASCII.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AsciiString(alloc::string::String);

#[cfg(feature = "alloc")]
impl AsciiString {
    /// The validated string slice.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Borrow this as an [`AsciiStr`] (no re-validation -- already validated on construction).
    pub fn as_ascii_str(&self) -> AsciiStr<'_> {
        AsciiStr(self.0.as_str())
    }
}

#[cfg(feature = "alloc")]
impl AsRef<str> for AsciiString {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}
