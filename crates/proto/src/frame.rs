//! Length-delimited framing for the USB CDC-ACM byte stream.
//!
//! USB CDC-ACM is a byte stream with no message boundaries. Each message travels as a
//! frame: a 4-byte big-endian length prefix giving the body length, followed by the
//! body bytes (the CBOR message). The receiver reads the 4-byte length, then exactly
//! that many body bytes, so a continuous stream splits cleanly back into messages.
//!
//! This module frames and reassembles bytes; the bodies are produced and parsed by the
//! `message` module.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Width of the big-endian length prefix, in bytes.
pub const LEN_PREFIX: usize = 4;

/// Error from framing a body into bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The output buffer cannot hold `LEN_PREFIX + body.len()` bytes.
    BufferTooSmall,
    /// The body is longer than the `u32` length prefix can describe.
    TooLong,
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FrameError::BufferTooSmall => f.write_str("output buffer too small for the frame"),
            FrameError::TooLong => f.write_str("frame body exceeds the u32 length prefix"),
        }
    }
}

impl core::error::Error for FrameError {}

/// Writes `len(u32 big-endian) || body` into `out`, returning the total frame length.
///
/// The length prefix counts only the body, not itself. Fails if `out` cannot hold the
/// whole frame, or the body is too long for the `u32` prefix.
pub fn encode_into(body: &[u8], out: &mut [u8]) -> Result<usize, FrameError> {
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLong)?;
    let total = LEN_PREFIX + body.len();
    let out = out.get_mut(..total).ok_or(FrameError::BufferTooSmall)?;
    out[..LEN_PREFIX].copy_from_slice(&len.to_be_bytes());
    out[LEN_PREFIX..].copy_from_slice(body);
    Ok(total)
}

/// Frames `body` into a newly allocated `len(u32 big-endian) || body` vector.
#[cfg(feature = "alloc")]
pub fn encode(body: &[u8]) -> Result<Vec<u8>, FrameError> {
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLong)?;
    let mut out = Vec::with_capacity(LEN_PREFIX + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}
