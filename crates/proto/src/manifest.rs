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

    /// Whether this manifest binds the given payload digest: whether the supplied
    /// digest -- produced by hashing the actual image -- matches the one the manifest
    /// commits to, in both algorithm and bytes. Signing the small manifest then
    /// authenticates the large image, since the manifest commits to its digest.
    ///
    /// Variable-time comparison is correct here: both digests are public (the
    /// committed one ships inside the signed manifest), so no secret can leak.
    pub fn binds(&self, computed: SuitDigest<'_>) -> bool {
        self.payload_digest == computed
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec;

    #[test]
    fn decodes_required_only_without_alloc() {
        // map(5) { 1: 1, 2: 5, 3: "kof", 4: [-16, h'ABCD'], 5: 0 }
        let wire = [
            0xa5, // map(5)
            0x01, 0x01, // version = 1
            0x02, 0x05, // sequence = 5
            0x03, 0x63, b'k', b'o', b'f', // class_id = "kof"
            0x04, 0x82, 0x2f, 0x42, 0xAB, 0xCD, // payload_digest = [-16, h'ABCD']
            0x05, 0x00, // target_slot = 0
        ];
        let m: Manifest = codec::decode(&wire).expect("decode");
        assert_eq!(m.version(), 1);
        assert_eq!(m.sequence(), 5);
        assert_eq!(m.class_id().as_str(), "kof");
        assert_eq!(m.payload_digest().alg(), AlgId::new(-16));
        assert_eq!(m.payload_digest().bytes(), &[0xAB, 0xCD]);
        assert_eq!(m.target_slot(), 0);
        assert!(m.version_string().is_none());
        assert!(m.encrypted_digest().is_none());
        assert!(m.key_ref().is_none());
    }

    #[test]
    fn binds_matches_alg_and_bytes() {
        let class_id = AsciiStr::try_from("acme-rtos").unwrap();
        let payload_digest = SuitDigest::new(AlgId::new(-16), &[0xAB, 0xCD, 0xEF]);
        let manifest = Manifest::new(1, 7, class_id, payload_digest, 0);

        // Same algorithm and bytes -> binds.
        assert!(manifest.binds(SuitDigest::new(AlgId::new(-16), &[0xAB, 0xCD, 0xEF])));
        // Different bytes -> does not bind.
        assert!(!manifest.binds(SuitDigest::new(AlgId::new(-16), &[0xAB, 0xCD, 0x00])));
        // Same bytes, different hash algorithm -> does not bind.
        assert!(!manifest.binds(SuitDigest::new(AlgId::new(-43), &[0xAB, 0xCD, 0xEF])));
    }

    #[test]
    fn rejects_non_ascii_class_id() {
        // class_id (label 3) = "café"; the 'é' (c3 a9) is non-ASCII -> rejected.
        let wire = [
            0xa5, // map(5)
            0x01, 0x01, // version
            0x02, 0x05, // sequence
            0x03, 0x65, 0x63, 0x61, 0x66, 0xc3, 0xa9, // class_id = "café"
            0x04, 0x82, 0x2f, 0x42, 0xAB, 0xCD, // payload_digest
            0x05, 0x00, // target_slot
        ];
        let r: Result<Manifest, _> = codec::decode(&wire);
        assert!(r.is_err());
    }

    #[test]
    fn rejects_unknown_label() {
        // map(6) whose 6th key is the unknown label 9.
        let wire = [
            0xa6, // map(6)
            0x01, 0x01, //
            0x02, 0x05, //
            0x03, 0x63, b'k', b'o', b'f', //
            0x04, 0x82, 0x2f, 0x42, 0xAB, 0xCD, //
            0x05, 0x00, //
            0x09, 0x00, // label 9 (unknown) -> reject
        ];
        let r: Result<Manifest, _> = codec::decode(&wire);
        assert!(r.is_err());
    }

    #[test]
    fn rejects_missing_required_field() {
        // map(4) missing target_slot (label 5).
        let wire = [
            0xa4, // map(4)
            0x01, 0x01, //
            0x02, 0x05, //
            0x03, 0x63, b'k', b'o', b'f', //
            0x04, 0x82, 0x2f, 0x42, 0xAB, 0xCD, //
        ];
        let r: Result<Manifest, _> = codec::decode(&wire);
        assert!(r.is_err());
    }

    #[test]
    fn rejects_encrypted_digest_without_key_ref() {
        // map(6) with encrypted_digest (label 7) but no key_ref (label 8).
        let wire = [
            0xa6, // map(6)
            0x01, 0x01, //
            0x02, 0x05, //
            0x03, 0x63, b'k', b'o', b'f', //
            0x04, 0x82, 0x2f, 0x42, 0xAB, 0xCD, //
            0x05, 0x00, //
            0x07, 0x82, 0x2f, 0x42, 0xBB, 0xCC, // encrypted_digest, no key_ref -> reject
        ];
        let r: Result<Manifest, _> = codec::decode(&wire);
        assert!(r.is_err());
    }

    #[test]
    fn rejects_indefinite_map() {
        // 0xbf is an indefinite-length map; canonical decode requires definite length.
        let wire = [
            0xbf, // map(*) indefinite
            0x01, 0x01, //
            0x02, 0x05, //
            0x03, 0x63, b'k', b'o', b'f', //
            0x04, 0x82, 0x2f, 0x42, 0xAB, 0xCD, //
            0x05, 0x00, //
            0xff, // break
        ];
        let r: Result<Manifest, _> = codec::decode(&wire);
        assert!(r.is_err());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn round_trips_required_only() {
        let class_id = AsciiStr::try_from("acme-rtos").unwrap();
        let payload_digest = SuitDigest::new(AlgId::new(-16), &[0x11; 32]);
        let original = Manifest::new(2, 100, class_id, payload_digest, 1);
        let bytes = codec::encode(&original).expect("encode");
        let decoded: Manifest = codec::decode(&bytes).expect("decode");
        assert_eq!(decoded, original);
        assert_eq!(codec::encode(&decoded).expect("re-encode"), bytes); // deterministic
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn round_trips_with_all_optionals() {
        let class_id = AsciiStr::try_from("acme-rtos").unwrap();
        let payload_digest = SuitDigest::new(AlgId::new(-16), &[0x22; 32]);
        let version_string = AsciiStr::try_from("1.2.3").unwrap();
        let encrypted_digest = SuitDigest::new(AlgId::new(-16), &[0x33; 32]);
        let key_ref = AsciiStr::try_from("device-root").unwrap();
        let original = Manifest::new(1, 42, class_id, payload_digest, 0)
            .with_version_string(version_string)
            .with_encrypted(encrypted_digest, key_ref);
        let bytes = codec::encode(&original).expect("encode");
        let decoded: Manifest = codec::decode(&bytes).expect("decode");
        assert_eq!(decoded, original);
        assert_eq!(codec::encode(&decoded).expect("re-encode"), bytes); // deterministic
    }

    /// Lowercase hex of the encoded bytes, for the frozen-vector comparison.
    #[cfg(feature = "alloc")]
    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn matches_frozen_vector() {
        // Self-consistency vector: a local-profile manifest has no published KAT, so we
        // freeze a fixed manifest <-> these exact bytes as a determinism/regression guard.
        // version 1, sequence 42, class_id "acme-rtos", SHA-256 (-16) digests,
        // target_slot 0, version_string "1.2.3", key_ref "device-root".
        const KAT_HEX: &str = "a8010102182a036961636d652d72746f7304822f5820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa05000665312e322e3307822f5820bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb086b6465766963652d726f6f74";

        let class_id = AsciiStr::try_from("acme-rtos").unwrap();
        let payload_digest = SuitDigest::new(AlgId::new(-16), &[0xAA; 32]);
        let version_string = AsciiStr::try_from("1.2.3").unwrap();
        let encrypted_digest = SuitDigest::new(AlgId::new(-16), &[0xBB; 32]);
        let key_ref = AsciiStr::try_from("device-root").unwrap();
        let original = Manifest::new(1, 42, class_id, payload_digest, 0)
            .with_version_string(version_string)
            .with_encrypted(encrypted_digest, key_ref);

        // Encode direction: the structure produces exactly the frozen bytes.
        let bytes = codec::encode(&original).expect("encode");
        assert_eq!(to_hex(&bytes), KAT_HEX);

        // Decode direction: those bytes read back to the same structure.
        let decoded: Manifest = codec::decode(&bytes).expect("decode");
        assert_eq!(decoded, original);
    }
}

#[cfg(all(test, feature = "alloc"))]
mod proptests {
    use super::*;
    use crate::codec;
    use proptest::prelude::*;

    const MAX_LEN: usize = 64;

    proptest! {
        #[test]
        fn manifest_round_trips(
            version in any::<u8>(),
            sequence in any::<u64>(),
            class_id in proptest::collection::vec(0x20u8..=0x7E, 1..=16),
            digest_alg in any::<i64>(),
            digest_bytes in proptest::collection::vec(any::<u8>(), 0..=MAX_LEN),
            target_slot in any::<u8>(),
            version_string in proptest::option::of(proptest::collection::vec(0x20u8..=0x7E, 0..=16)),
            encrypted in proptest::option::of((
                any::<i64>(),
                proptest::collection::vec(any::<u8>(), 0..=MAX_LEN),
                proptest::collection::vec(0x20u8..=0x7E, 1..=16),
            )),
        ) {
            // Owned backing for every borrowed field, all outliving the manifest below.
            let class_id = String::from_utf8(class_id).unwrap();
            let version_string = version_string.map(|b| String::from_utf8(b).unwrap());
            let encrypted = encrypted.map(|(alg, bytes, key)| (alg, bytes, String::from_utf8(key).unwrap()));

            let payload_digest = SuitDigest::new(AlgId::new(digest_alg), &digest_bytes);
            let mut manifest = Manifest::new(
                version,
                sequence,
                AsciiStr::try_from(class_id.as_str()).unwrap(),
                payload_digest,
                target_slot,
            );
            if let Some(s) = version_string.as_deref() {
                manifest = manifest.with_version_string(AsciiStr::try_from(s).unwrap());
            }
            if let Some((alg, bytes, key)) = encrypted.as_ref() {
                let digest = SuitDigest::new(AlgId::new(*alg), bytes);
                manifest = manifest.with_encrypted(digest, AsciiStr::try_from(key.as_str()).unwrap());
            }

            let encoded = codec::encode(&manifest).unwrap();
            let decoded: Manifest = codec::decode(&encoded).unwrap();
            let reencoded = codec::encode(&decoded).unwrap();
            prop_assert_eq!(decoded, manifest);
            // Deterministic: re-encoding the decoded structure is byte-identical.
            prop_assert_eq!(reencoded, encoded);
        }
    }
}
