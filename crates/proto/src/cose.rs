//! COSE structures (RFC 9052): the `COSE_Sign1` signed-message envelope and the
//! canonical `Sig_structure` (the exact to-be-signed bytes).
//!
//! proto builds and parses the bytes and ferries the algorithm codepoint; the
//! actual signing and verifying live in the crypto layer, wired by a consumer.

use crate::alg::AlgId;

/// COSE header label for the algorithm identifier (RFC 9052 Table 2).
const LABEL_ALG: u8 = 1;

/// Upper bound on the encoded protected-header map `{1: alg}`: the map and label
/// prefix (`0xa1 0x01`) plus a maximum 9-byte CBOR integer for the algorithm.
const PROTECTED_MAX: usize = 16;

/// The COSE protected header: the metadata the signature covers.
///
/// For a `COSE_Sign1` this carries the algorithm identifier. On the wire it is a
/// CBOR byte string wrapping the canonical CBOR of the header map `{1: alg}`; that
/// wrapping is what binds the algorithm into the signed bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectedHeader {
    alg: AlgId,
}

impl ProtectedHeader {
    /// Creates a protected header carrying `alg`.
    pub const fn new(alg: AlgId) -> Self {
        Self { alg }
    }

    /// The algorithm identifier.
    pub const fn alg(&self) -> AlgId {
        self.alg
    }
}
