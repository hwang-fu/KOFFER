//! Host<->device request/response messages (the USB-CDC protocol payloads).
//!
//! Each message encodes as a flat CBOR array led by an integer tag: `[tag, ...fields]`.
//! `Request` (host -> device) and `Response` (device -> host) are separate enums with
//! separate tag spaces; the body bytes travel inside a frame (see the `frame` module).
//! Text fields are printable-ASCII (F15); byte fields borrow the input, zero-copy, like
//! the COSE and manifest types.

use crate::alg::AlgId;

/// Maximum number of algorithm identifiers carried in an `Info` list.
pub const MAX_ALGS: usize = 8;

/// A bounded, heap-free list of algorithm identifiers.
pub type AlgList = heapless::Vec<AlgId, MAX_ALGS>;

/// A request from host to device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// Report device capabilities (`-> Response::Info`).
    GetInfo,
    /// Generate the signing and KEM key pairs (`-> Response::PublicKeys`).
    InitKeys { sig_alg: AlgId, kem_alg: AlgId },
}
