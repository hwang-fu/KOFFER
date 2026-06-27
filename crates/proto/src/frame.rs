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

/// Error from framing or reassembling bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The output buffer cannot hold `LEN_PREFIX + body.len()` bytes.
    BufferTooSmall,
    /// The body is longer than the `u32` length prefix can describe.
    TooLong,
    /// An incoming frame's declared length exceeds the reader's capacity.
    FrameTooLarge,
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FrameError::BufferTooSmall => f.write_str("output buffer too small for the frame"),
            FrameError::TooLong => f.write_str("frame body exceeds the u32 length prefix"),
            FrameError::FrameTooLarge => f.write_str("incoming frame exceeds the reader capacity"),
        }
    }
}

impl core::error::Error for FrameError {}

/// Reassembles length-delimited frames from a USB byte stream into complete frames.
///
/// Holds a fixed `[u8; CAP]` buffer (no heap); `CAP` is the largest total frame -- prefix
/// plus body -- it accepts. Feed stream bytes with [`push`](Self::push) and drain complete
/// frames with [`next_frame`](Self::next_frame). An incoming frame whose declared length
/// exceeds `CAP` is rejected (`FrameTooLarge`) the moment the prefix is read, so a bogus
/// length never causes unbounded buffering. `CAP` must exceed the largest expected frame.
pub struct FrameReader<const CAP: usize> {
    buf: [u8; CAP],
    /// Valid buffered bytes, at `buf[..len]`.
    len: usize,
    /// Length of a frame returned by `next_frame` but not yet compacted out (0 = none).
    pending: usize,
}

impl<const CAP: usize> Default for FrameReader<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAP: usize> FrameReader<CAP> {
    /// Creates an empty reader.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; CAP],
            len: 0,
            pending: 0,
        }
    }

    /// Feeds stream bytes, buffering as many as fit, and returns how many were consumed.
    ///
    /// Stops at the buffer's free space, so a feed larger than the remaining room is
    /// taken in part -- drain with `next_frame`, then push the rest. Rejects a frame
    /// whose declared length exceeds `CAP`.
    pub fn push(&mut self, data: &[u8]) -> Result<usize, FrameError> {
        self.compact();
        let take = (CAP - self.len).min(data.len());
        self.buf[self.len..self.len + take].copy_from_slice(&data[..take]);
        self.len += take;
        if self.len >= LEN_PREFIX && self.body_len() > CAP.saturating_sub(LEN_PREFIX) {
            return Err(FrameError::FrameTooLarge);
        }
        Ok(take)
    }

    /// Returns the next complete frame's body, or `None` if one has not fully arrived.
    ///
    /// The returned slice borrows the reader's buffer; it is valid until the next call
    /// to `push` or `next_frame`.
    pub fn next_frame(&mut self) -> Option<&[u8]> {
        self.compact();
        if self.len < LEN_PREFIX {
            return None;
        }
        let total = LEN_PREFIX + self.body_len();
        if self.len < total {
            return None;
        }
        self.pending = total;
        Some(&self.buf[LEN_PREFIX..total])
    }

    /// Drops a previously returned frame by shifting the remaining bytes to the front.
    fn compact(&mut self) {
        if self.pending > 0 {
            self.buf.copy_within(self.pending..self.len, 0);
            self.len -= self.pending;
            self.pending = 0;
        }
    }

    /// The body length declared by the buffered 4-byte prefix. Only valid when `len >= LEN_PREFIX`.
    fn body_len(&self) -> usize {
        let prefix: [u8; LEN_PREFIX] = self.buf[..LEN_PREFIX]
            .try_into()
            .expect("slice is LEN_PREFIX bytes");
        u32::from_be_bytes(prefix) as usize
    }
}

impl<const CAP: usize> core::fmt::Debug for FrameReader<CAP> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FrameReader")
            .field("cap", &CAP)
            .field("buffered", &self.len)
            .finish()
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_into_writes_length_prefixed_frame() {
        let mut out = [0u8; 16];
        let n = encode_into(&[0xAA, 0xBB, 0xCC], &mut out).expect("encode");
        assert_eq!(n, 7);
        assert_eq!(&out[..n], &[0x00, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn encode_into_rejects_small_buffer() {
        let mut out = [0u8; 6]; // a 3-byte body needs 7
        assert_eq!(
            encode_into(&[0xAA, 0xBB, 0xCC], &mut out),
            Err(FrameError::BufferTooSmall)
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn encode_matches_the_framed_layout() {
        let body = [0x01, 0x02, 0x03, 0x04, 0x05];
        let v = encode(&body).expect("encode");
        assert_eq!(v, [0x00, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]);
    }
}
