//! Printable-ASCII-validated strings for externally-supplied text.
//!
//! Identifiers, labels, and displayed strings are constrained to printable 7-bit US-ASCII
//! (0x20-0x7E). Bytes outside that range are rejected at the parse boundary, never silently
//! transcoded.

use crate::codec::{Decode, DecodeError, Decoder, Encode, EncodeError, Encoder, Write};
#[cfg(feature = "alloc")]
use alloc::string::String;
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

/// Inclusive range of printable 7-bit US-ASCII (space `0x20` through `~` `0x7E`).
const PRINTABLE_ASCII: core::ops::RangeInclusive<u8> = 0x20..=0x7E;

/// `Ok` only if every byte is printable 7-bit US-ASCII (0x20-0x7E).
fn validate(bytes: &[u8]) -> Result<(), AsciiError> {
    if bytes.iter().all(|b| PRINTABLE_ASCII.contains(b)) {
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

impl<C> Encode<C> for AsciiStr<'_> {
    fn encode<W: Write>(&self, e: &mut Encoder<W>, _: &mut C) -> Result<(), EncodeError<W::Error>> {
        e.str(self.0)?.ok()
    }
}

impl<'b, C> Decode<'b, C> for AsciiStr<'b> {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, DecodeError> {
        let s = d.str()?;
        validate(s.as_bytes())
            .map_err(|_| DecodeError::message("input is not printable 7-bit US-ASCII"))?;
        Ok(Self(s))
    }
}

/// An owned string validated to contain only printable 7-bit US-ASCII.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AsciiString(String);

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

#[cfg(feature = "alloc")]
impl TryFrom<&str> for AsciiString {
    type Error = AsciiError;

    fn try_from(s: &str) -> Result<Self, AsciiError> {
        validate(s.as_bytes())?;
        Ok(Self(String::from(s)))
    }
}

#[cfg(feature = "alloc")]
impl TryFrom<String> for AsciiString {
    type Error = AsciiError;

    fn try_from(s: String) -> Result<Self, AsciiError> {
        validate(s.as_bytes())?;
        Ok(Self(s))
    }
}

#[cfg(feature = "alloc")]
impl Deref for AsciiString {
    type Target = str;

    fn deref(&self) -> &str {
        self.0.as_str()
    }
}

#[cfg(feature = "alloc")]
impl fmt::Display for AsciiString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

#[cfg(feature = "alloc")]
impl<C> Encode<C> for AsciiString {
    fn encode<W: Write>(&self, e: &mut Encoder<W>, _: &mut C) -> Result<(), EncodeError<W::Error>> {
        e.str(self.0.as_str())?.ok()
    }
}

#[cfg(feature = "alloc")]
impl<'b, C> Decode<'b, C> for AsciiString {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, DecodeError> {
        let s = d.str()?;
        validate(s.as_bytes())
            .map_err(|_| DecodeError::message("input is not printable 7-bit US-ASCII"))?;
        Ok(Self(String::from(s)))
    }
}
