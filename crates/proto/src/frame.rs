//! Length-delimited framing for the USB CDC-ACM byte stream.
//!
//! USB CDC-ACM is a byte stream with no message boundaries. Each message travels as a
//! frame: a 4-byte big-endian length prefix giving the body length, followed by the
//! body bytes (the CBOR message). The receiver reads the 4-byte length, then exactly
//! that many body bytes, so a continuous stream splits cleanly back into messages.
//!
//! This module frames and reassembles bytes; the bodies are produced and parsed by the
//! `message` module.

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
