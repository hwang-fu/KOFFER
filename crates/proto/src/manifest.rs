//! SUIT-aligned firmware/update manifest.
//!
//! The signed "packing slip" for an update: it binds the (possibly encrypted)
//! payload by digest plus metadata, and is itself signed via `COSE_Sign1` (detached
//! by default -- the image ships unchanged, referenced by its digest). This is a
//! flat local profile of the IETF SUIT manifest model: the descriptive and binding
//! fields, without the SUIT command-sequence machinery.
//!
//! proto frames and parses the bytes; hashing the image and checking the signature
//! are the crypto / verifier layer's job.

use crate::alg::AlgId;

/// A SUIT-style digest: the hash algorithm plus the digest bytes (`[alg, bstr]`).
///
/// Carrying the algorithm makes the binding profile-agnostic -- SHA-256 or SHA-384 --
/// rather than locking the manifest to one hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuitDigest<'b> {
    alg: AlgId,
    bytes: &'b [u8],
}

impl<'b> SuitDigest<'b> {
    /// Creates a digest binding from a hash algorithm and its digest bytes.
    pub fn new(alg: AlgId, bytes: &'b [u8]) -> Self {
        Self { alg, bytes }
    }

    /// The hash algorithm identifier.
    pub fn alg(&self) -> AlgId {
        self.alg
    }

    /// The digest bytes.
    pub fn bytes(&self) -> &'b [u8] {
        self.bytes
    }
}
