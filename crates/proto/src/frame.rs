//! Length-delimited framing for the USB CDC-ACM byte stream.
//!
//! USB CDC-ACM is a byte stream with no message boundaries. Each message travels as a
//! frame: a 4-byte big-endian length prefix giving the body length, followed by the
//! body bytes (the CBOR message). The receiver reads the 4-byte length, then exactly
//! that many body bytes, so a continuous stream splits cleanly back into messages.
//!
//! This module frames and reassembles bytes; the bodies are produced and parsed by the
//! `message` module.
