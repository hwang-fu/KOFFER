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

use crate::{alg::AlgId, ascii::AsciiStr};

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

/// A SUIT-aligned update manifest (KOFFER local profile).
///
/// A CBOR map binding the payload by digest plus update metadata. Required:
/// `version`, `sequence` (anti-rollback), `class_id` (device-class compatibility),
/// `payload_digest` (the image binding), `target_slot`. Optional: `version_string`,
/// and -- for encrypted updates -- `encrypted_digest` + `key_ref`. Borrowed from the
/// input, like the COSE types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Manifest<'b> {
    version: u8,
    sequence: u64,
    class_id: AsciiStr<'b>,
    payload_digest: SuitDigest<'b>,
    target_slot: u8,
    version_string: Option<AsciiStr<'b>>,
    encrypted_digest: Option<SuitDigest<'b>>,
    key_ref: Option<AsciiStr<'b>>,
}

impl<'b> Manifest<'b> {
    /// Creates a manifest with the required fields; the optional fields start absent
    /// (set them with `with_version_string` / `with_encrypted`).
    pub fn new(
        version: u8,
        sequence: u64,
        class_id: AsciiStr<'b>,
        payload_digest: SuitDigest<'b>,
        target_slot: u8,
    ) -> Self {
        Self {
            version,
            sequence,
            class_id,
            payload_digest,
            target_slot,
            version_string: None,
            encrypted_digest: None,
            key_ref: None,
        }
    }

    /// Sets the optional human version/label string.
    pub fn with_version_string(mut self, version_string: AsciiStr<'b>) -> Self {
        self.version_string = Some(version_string);
        self
    }

    /// Sets the encrypted-update fields together: the encrypted payload's digest and
    /// the reference to its key info.
    pub fn with_encrypted(mut self, digest: SuitDigest<'b>, key_ref: AsciiStr<'b>) -> Self {
        self.encrypted_digest = Some(digest);
        self.key_ref = Some(key_ref);
        self
    }

    /// The manifest profile version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// The anti-rollback sequence number.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The device-class compatibility identifier.
    pub fn class_id(&self) -> AsciiStr<'b> {
        self.class_id
    }

    /// The payload digest binding.
    pub fn payload_digest(&self) -> SuitDigest<'b> {
        self.payload_digest
    }

    /// The install target slot.
    pub fn target_slot(&self) -> u8 {
        self.target_slot
    }

    /// The optional human version/label string.
    pub fn version_string(&self) -> Option<AsciiStr<'b>> {
        self.version_string
    }

    /// The optional encrypted-payload digest.
    pub fn encrypted_digest(&self) -> Option<SuitDigest<'b>> {
        self.encrypted_digest
    }

    /// The optional key-info reference.
    pub fn key_ref(&self) -> Option<AsciiStr<'b>> {
        self.key_ref
    }
}
