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

use crate::codec::{Decode, DecodeError, Decoder, Encode, EncodeError, Encoder, Write};
use crate::{alg::AlgId, ascii::AsciiStr};

const LABEL_VERSION: u8 = 1;
const LABEL_SEQUENCE: u8 = 2;
const LABEL_CLASS_ID: u8 = 3;
const LABEL_PAYLOAD_DIGEST: u8 = 4;
const LABEL_TARGET_SLOT: u8 = 5;
const LABEL_VERSION_STRING: u8 = 6;
const LABEL_ENCRYPTED_DIGEST: u8 = 7;
const LABEL_KEY_REF: u8 = 8;

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

impl<C> Encode<C> for SuitDigest<'_> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), EncodeError<W::Error>> {
        e.array(2)?;
        self.alg.encode(e, ctx)?;
        e.bytes(self.bytes)?.ok()
    }
}

impl<'b, C> Decode<'b, C> for SuitDigest<'b> {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, DecodeError> {
        if d.array()? != Some(2) {
            return Err(DecodeError::message(
                "SUIT digest must be a 2-element array",
            ));
        }
        let alg = d.decode()?;
        let bytes = d.bytes()?;
        Ok(Self { alg, bytes })
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

impl<C> Encode<C> for Manifest<'_> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), EncodeError<W::Error>> {
        let entries = 5
            + self.version_string.is_some() as u64
            + self.encrypted_digest.is_some() as u64
            + self.key_ref.is_some() as u64;
        e.map(entries)?;
        // ascending label order (canonical, so the signed bytes are stable).
        e.u8(LABEL_VERSION)?.u8(self.version)?;
        e.u8(LABEL_SEQUENCE)?.u64(self.sequence)?;
        e.u8(LABEL_CLASS_ID)?;
        self.class_id.encode(e, ctx)?;
        e.u8(LABEL_PAYLOAD_DIGEST)?;
        self.payload_digest.encode(e, ctx)?;
        e.u8(LABEL_TARGET_SLOT)?.u8(self.target_slot)?;
        if let Some(version_string) = self.version_string {
            e.u8(LABEL_VERSION_STRING)?;
            version_string.encode(e, ctx)?;
        }
        if let Some(encrypted_digest) = self.encrypted_digest {
            e.u8(LABEL_ENCRYPTED_DIGEST)?;
            encrypted_digest.encode(e, ctx)?;
        }
        if let Some(key_ref) = self.key_ref {
            e.u8(LABEL_KEY_REF)?;
            key_ref.encode(e, ctx)?;
        }
        Ok(())
    }
}

impl<'b, C> Decode<'b, C> for Manifest<'b> {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, DecodeError> {
        let entries = d
            .map()?
            .ok_or_else(|| DecodeError::message("manifest must be a definite map"))?;
        let mut version = None;
        let mut sequence = None;
        let mut class_id = None;
        let mut payload_digest = None;
        let mut target_slot = None;
        let mut version_string = None;
        let mut encrypted_digest = None;
        let mut key_ref = None;
        for _ in 0..entries {
            match d.u8()? {
                LABEL_VERSION => version = Some(d.u8()?),
                LABEL_SEQUENCE => sequence = Some(d.u64()?),
                LABEL_CLASS_ID => class_id = Some(d.decode()?),
                LABEL_PAYLOAD_DIGEST => payload_digest = Some(d.decode()?),
                LABEL_TARGET_SLOT => target_slot = Some(d.u8()?),
                LABEL_VERSION_STRING => version_string = Some(d.decode()?),
                LABEL_ENCRYPTED_DIGEST => encrypted_digest = Some(d.decode()?),
                LABEL_KEY_REF => key_ref = Some(d.decode()?),
                _ => return Err(DecodeError::message("unknown manifest label")),
            }
        }
        // The encrypted-update fields are paired: both present or both absent.
        if encrypted_digest.is_some() != key_ref.is_some() {
            return Err(DecodeError::message(
                "encrypted_digest and key_ref must both be present or both absent",
            ));
        }
        Ok(Self {
            version: version.ok_or_else(|| DecodeError::message("manifest missing version"))?,
            sequence: sequence.ok_or_else(|| DecodeError::message("manifest missing sequence"))?,
            class_id: class_id.ok_or_else(|| DecodeError::message("manifest missing class_id"))?,
            payload_digest: payload_digest
                .ok_or_else(|| DecodeError::message("manifest missing payload_digest"))?,
            target_slot: target_slot
                .ok_or_else(|| DecodeError::message("manifest missing target_slot"))?,
            version_string,
            encrypted_digest,
            key_ref,
        })
    }
}
