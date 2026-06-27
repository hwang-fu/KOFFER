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

    #[test]
    fn empty_reader_yields_no_frame() {
        let mut r = FrameReader::<16>::new();
        assert!(r.next_frame().is_none());
    }

    #[test]
    fn reads_one_frame_from_one_push() {
        let mut r = FrameReader::<16>::new();
        let n = r.push(&[0, 0, 0, 3, 0xA0, 0xA1, 0xA2]).unwrap();
        assert_eq!(n, 7);
        assert_eq!(r.next_frame(), Some(&[0xA0, 0xA1, 0xA2][..]));
        assert_eq!(r.next_frame(), None);
    }

    #[test]
    fn reassembles_frame_split_across_pushes() {
        let mut r = FrameReader::<16>::new();
        r.push(&[0, 0, 0, 3, 0xA0]).unwrap(); // prefix + 1 body byte
        assert_eq!(r.next_frame(), None); // incomplete
        r.push(&[0xA1, 0xA2]).unwrap(); // rest of body
        assert_eq!(r.next_frame(), Some(&[0xA0, 0xA1, 0xA2][..]));
        assert_eq!(r.next_frame(), None);
    }

    #[test]
    fn reads_back_to_back_frames_in_one_push() {
        let mut r = FrameReader::<16>::new();
        // body [A0 A1 A2] then body [B0 B1], packed = 13 bytes <= 16
        let n = r
            .push(&[0, 0, 0, 3, 0xA0, 0xA1, 0xA2, 0, 0, 0, 2, 0xB0, 0xB1])
            .unwrap();
        assert_eq!(n, 13);
        assert_eq!(r.next_frame(), Some(&[0xA0, 0xA1, 0xA2][..]));
        assert_eq!(r.next_frame(), Some(&[0xB0, 0xB1][..]));
        assert_eq!(r.next_frame(), None);
    }

    #[test]
    fn reassembles_one_byte_at_a_time() {
        let mut r = FrameReader::<16>::new();
        let wire = [0, 0, 0, 3, 0xA0, 0xA1, 0xA2];
        for (i, b) in wire.iter().enumerate() {
            r.push(&[*b]).unwrap();
            if i < wire.len() - 1 {
                assert!(r.next_frame().is_none());
            }
        }
        assert_eq!(r.next_frame(), Some(&[0xA0, 0xA1, 0xA2][..]));
    }

    #[test]
    fn rejects_oversize_frame() {
        let mut r = FrameReader::<8>::new(); // max body = 4
        // prefix declares body length 100 -> too large for CAP
        assert_eq!(r.push(&[0, 0, 0, 100]), Err(FrameError::FrameTooLarge));
    }

    #[test]
    fn feeds_more_than_capacity_via_repush() {
        let mut r = FrameReader::<8>::new(); // holds one small frame at a time
        // two 6-byte frames = 12 bytes > CAP 8, so push consumes in steps
        let stream = [0, 0, 0, 2, 0xB0, 0xB1, 0, 0, 0, 2, 0xC0, 0xC1];
        let mut rest = &stream[..];
        let mut bodies = [[0u8; 2]; 2];
        let mut got = 0;
        while !rest.is_empty() {
            let n = r.push(rest).unwrap();
            rest = &rest[n..];
            while let Some(frame) = r.next_frame() {
                bodies[got].copy_from_slice(frame);
                got += 1;
            }
        }
        assert_eq!(got, 2);
        assert_eq!(bodies, [[0xB0, 0xB1], [0xC0, 0xC1]]);
    }

    #[test]
    fn reassembles_at_every_split_point() {
        // Two frames back-to-back; feed as two chunks split at every offset.
        let stream = [0, 0, 0, 3, 0xA0, 0xA1, 0xA2, 0, 0, 0, 2, 0xB0, 0xB1];
        for split in 0..=stream.len() {
            let mut r = FrameReader::<16>::new();
            let mut a = [0u8; 3];
            let mut b = [0u8; 2];
            let mut got = 0;
            for chunk in [&stream[..split], &stream[split..]] {
                let mut rest = chunk;
                while !rest.is_empty() {
                    let n = r.push(rest).unwrap();
                    rest = &rest[n..];
                    while let Some(frame) = r.next_frame() {
                        match got {
                            0 => a.copy_from_slice(frame),
                            1 => b.copy_from_slice(frame),
                            _ => panic!("unexpected third frame at split {split}"),
                        }
                        got += 1;
                    }
                }
            }
            assert_eq!(got, 2, "split {split}");
            assert_eq!(a, [0xA0, 0xA1, 0xA2], "split {split}");
            assert_eq!(b, [0xB0, 0xB1], "split {split}");
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn encode_matches_the_framed_layout() {
        let body = [0x01, 0x02, 0x03, 0x04, 0x05];
        let v = encode(&body).expect("encode");
        assert_eq!(v, [0x00, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]);
    }
}

#[cfg(all(test, feature = "alloc"))]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    const CAP: usize = 128;
    const MAX_BODY: usize = CAP - LEN_PREFIX;

    proptest! {
        #[test]
        fn reader_recovers_all_frames(
            bodies in proptest::collection::vec(
                proptest::collection::vec(any::<u8>(), 0..=MAX_BODY),
                0..=8,
            ),
            chunk_sizes in proptest::collection::vec(1usize..=40, 1..=32),
        ) {
            // One stream holding every framed body, back to back.
            let mut stream = Vec::new();
            for body in &bodies {
                stream.extend_from_slice(&encode(body).unwrap());
            }
            // Feed the stream in chunks of the given sizes (cycling), draining frames.
            let mut reader = FrameReader::<CAP>::new();
            let mut got: Vec<Vec<u8>> = Vec::new();
            let mut offset = 0;
            let mut i = 0;
            while offset < stream.len() {
                let size = chunk_sizes[i % chunk_sizes.len()].min(stream.len() - offset);
                let mut rest = &stream[offset..offset + size];
                offset += size;
                i += 1;
                while !rest.is_empty() {
                    let n = reader.push(rest).unwrap();
                    rest = &rest[n..];
                    while let Some(frame) = reader.next_frame() {
                        got.push(frame.to_vec());
                    }
                }
            }
            prop_assert_eq!(got, bodies);
        }
    }
}
