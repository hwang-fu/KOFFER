//! Host-only differential test harness for the KOFFER crypto backend.
//!
//! Runs the production `koffer-crypto` backend and an independent reference
//! implementation over the same inputs (the frozen `kat/` vectors plus
//! randomized `proptest` cases) and asserts the two agree. This guards against
//! a defect that the wrapped upstream crates and our own tests might share.
//!
//! This crate is host-only and is never part of the firmware build: the
//! embedded target builds only the protocol and crypto crates, so this harness
//! and its (potentially C-backed) reference libraries are excluded by
//! construction.

use crypto::{
    kem::{Ciphertext, Kem},
    sign::{Signature, Verifier, VerifyingKey},
};

/// Parser for the project's `name = hex` known-answer-test files.
///
/// The crypto crate has its own parser, but it is private to that crate, so the
/// harness carries a small independent copy.
pub mod kat {
    /// One record: its Wycheproof `tcId` (from the preceding `# tcId N:` comment, if
    /// any) and its named, hex-decoded fields in file order.
    pub struct Record {
        tc_id: Option<u32>,
        fields: Vec<(String, Vec<u8>)>,
    }

    impl Record {
        /// The record's test-case id, or `None` if it had no `# tcId N:` comment.
        pub fn tc_id(&self) -> Option<u32> {
            self.tc_id
        }

        /// The bytes of field `name`, or `None` if this record has no such field.
        pub fn field(&self, name: &str) -> Option<&[u8]> {
            self.fields
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_slice())
        }
    }

    /// Splits KAT text into records. A blank line ends a record; a `# tcId N:` comment
    /// sets the next record's test-case id; other `#` lines are ignored; every other
    /// line is `name = hex`. Panics on a malformed line, which can only mean a corrupt
    /// static vector file.
    pub fn parse(text: &str) -> Vec<Record> {
        let mut records = Vec::new();
        let mut fields: Vec<(String, Vec<u8>)> = Vec::new();
        let mut tc_id: Option<u32> = None;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                if !fields.is_empty() {
                    records.push(Record {
                        tc_id,
                        fields: std::mem::take(&mut fields),
                    });
                    tc_id = None;
                }
                continue;
            }
            if let Some(rest) = line.strip_prefix("# tcId ") {
                tc_id = rest.split(':').next().and_then(|n| n.trim().parse().ok());
                continue;
            }
            if line.starts_with('#') {
                continue;
            }
            let (name, value) = line.split_once('=').expect("KAT line is `name = hex`");
            fields.push((name.trim().to_string(), hex_decode(value.trim())));
        }
        if !fields.is_empty() {
            records.push(Record { tc_id, fields });
        }
        records
    }

    fn hex_decode(hex: &str) -> Vec<u8> {
        assert!(hex.len().is_multiple_of(2), "hex value has even length");
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex digit"))
            .collect()
    }
}

/// The ML-DSA parameter set under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaSet {
    /// ML-DSA-65 (showcase profile).
    MlDsa65,
    /// ML-DSA-87 (CNSA 2.0 profile).
    MlDsa87,
}

/// An independent ML-DSA verifier -- the reference side of the differential.
///
/// `verify` returns whether the reference accepts. A wrong-length key or
/// signature is a rejection, not a panic, so malformed-input vectors compare
/// cleanly against our backend.
pub trait MlDsaReference {
    /// Whether the reference accepts `signature` over `message` under `public_key`.
    fn verify(&self, set: MlDsaSet, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

/// The liboqs reference, via the `oqs` crate.
pub struct OqsMlDsa;

impl MlDsaReference for OqsMlDsa {
    fn verify(&self, set: MlDsaSet, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        oqs::init();
        let algorithm = match set {
            MlDsaSet::MlDsa65 => oqs::sig::Algorithm::MlDsa65,
            MlDsaSet::MlDsa87 => oqs::sig::Algorithm::MlDsa87,
        };
        let scheme = oqs::sig::Sig::new(algorithm).expect("oqs is built with ML-DSA enabled");
        // A wrong-length key or signature is a rejection, matching our backend.
        let (Some(pk), Some(sig)) = (
            scheme.public_key_from_bytes(public_key),
            scheme.signature_from_bytes(signature),
        ) else {
            return false;
        };
        scheme.verify(message, sig, pk).is_ok()
    }
}

/// Verifies with our `koffer-crypto` ML-DSA backend -- the implementation under test.
///
/// A wrong-length key or signature is a rejection, mirroring the reference.
pub fn our_verify(set: MlDsaSet, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    match set {
        MlDsaSet::MlDsa65 => our_verify_with::<ml_dsa::MlDsa65>(public_key, message, signature),
        MlDsaSet::MlDsa87 => our_verify_with::<ml_dsa::MlDsa87>(public_key, message, signature),
    }
}

fn our_verify_with<P: ml_dsa::MlDsaParams>(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    let (Ok(key), Ok(sig)) = (
        VerifyingKey::try_from(public_key),
        Signature::try_from(signature),
    ) else {
        return false;
    };
    crypto::mldsa::MlDsa::<P>::new()
        .verify(&key, message, &sig)
        .is_ok()
}

/// The two backends disagreed on one input -- the differential found a defect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mismatch {
    /// What our backend answered (true = accept).
    pub ours: bool,
    /// What the reference answered (true = accept).
    pub reference: bool,
}

/// Runs our backend and `reference` on the same verify input and compares them.
///
/// `Ok(accepted)` means they agree (and `accepted` is their shared answer);
/// `Err(Mismatch)` means they disagree, which is a finding.
pub fn differential_verify(
    reference: &dyn MlDsaReference,
    set: MlDsaSet,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, Mismatch> {
    let ours = our_verify(set, public_key, message, signature);
    let theirs = reference.verify(set, public_key, message, signature);
    if ours == theirs {
        Ok(ours)
    } else {
        Err(Mismatch {
            ours,
            reference: theirs,
        })
    }
}

/// The ML-KEM parameter set under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemSet {
    /// ML-KEM-768 (showcase profile).
    MlKem768,
    /// ML-KEM-1024 (CNSA 2.0 profile).
    MlKem1024,
}

/// An independent ML-KEM decapsulator -- the reference side of the differential.
///
/// `decapsulate` derives the keypair from `seed` (the same seed our backend uses),
/// then recovers the shared secret for `ciphertext`. A wrong-length seed or ciphertext
/// is `None`, not a panic, so malformed inputs compare cleanly against our backend.
pub trait MlKemReference {
    /// The shared secret from decapsulating `ciphertext` under the keypair derived from
    /// `seed`, or `None` if an input is the wrong length.
    fn decapsulate(&self, set: MlKemSet, seed: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>>;
}

/// The liboqs reference, via the `oqs` crate.
pub struct OqsMlKem;

impl MlKemReference for OqsMlKem {
    fn decapsulate(&self, set: MlKemSet, seed: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        oqs::init();
        let algorithm = match set {
            MlKemSet::MlKem768 => oqs::kem::Algorithm::MlKem768,
            MlKemSet::MlKem1024 => oqs::kem::Algorithm::MlKem1024,
        };
        let kem = oqs::kem::Kem::new(algorithm).expect("oqs is built with ML-KEM enabled");
        // liboqs derives its keypair from the same seed. A wrong-length seed or
        // ciphertext is a malformed input, matching our backend.
        let seed = kem.keypair_seed_from_bytes(seed)?;
        let (_encapsulation_key, secret_key) = kem.keypair_derand(seed).ok()?;
        let ciphertext = kem.ciphertext_from_bytes(ciphertext)?;
        Some(kem.decapsulate(&secret_key, ciphertext).ok()?.into_vec())
    }
}

// FFI to the vendored mlkem-native multilevel build (`build.rs` compiles it). Each level
// exposes a derandomized keypair (from 64-byte coins) and a decapsulate; both return 0 on
// success.
unsafe extern "C" {
    fn mlkem768_keypair_derand(pk: *mut u8, sk: *mut u8, coins: *const u8) -> core::ffi::c_int;
    fn mlkem768_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> core::ffi::c_int;
    fn mlkem1024_keypair_derand(pk: *mut u8, sk: *mut u8, coins: *const u8) -> core::ffi::c_int;
    fn mlkem1024_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> core::ffi::c_int;
}

/// The mlkem-native reference (vendored, formally-verified C), the higher-assurance ML-KEM
/// cross-check alongside liboqs.
pub struct MlKemNative;

impl MlKemReference for MlKemNative {
    fn decapsulate(&self, set: MlKemSet, seed: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        // The seed is the 64-byte FIPS 203 keygen coins (d || z); a wrong length is a
        // malformed input, matching our backend.
        let coins: [u8; 64] = seed.try_into().ok()?;

        // Buffer sizes are fixed per parameter set, so expand per level. `pk` is written by
        // the keypair derivation but unused afterward -- only `sk` feeds decapsulation.
        macro_rules! decapsulate_with {
            ($pk_len:literal, $sk_len:literal, $ct_len:literal, $keypair:ident, $dec:ident) => {{
                if ciphertext.len() != $ct_len {
                    return None;
                }
                let mut pk = [0u8; $pk_len];
                let mut sk = [0u8; $sk_len];
                let mut shared_secret = [0u8; 32];
                // SAFETY: each pointer is valid for the fixed length the C function reads or
                // writes -- `coins` is 64 bytes, `ciphertext` is the checked length, and the
                // `pk`/`sk`/`shared_secret` buffers are sized to the parameter set.
                unsafe {
                    if $keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), coins.as_ptr()) != 0 {
                        return None;
                    }
                    if $dec(shared_secret.as_mut_ptr(), ciphertext.as_ptr(), sk.as_ptr()) != 0 {
                        return None;
                    }
                }
                Some(shared_secret.to_vec())
            }};
        }

        match set {
            MlKemSet::MlKem768 => {
                decapsulate_with!(1184, 2400, 1088, mlkem768_keypair_derand, mlkem768_dec)
            }
            MlKemSet::MlKem1024 => {
                decapsulate_with!(1568, 3168, 1568, mlkem1024_keypair_derand, mlkem1024_dec)
            }
        }
    }
}

/// Decapsulates with our `koffer-crypto` ML-KEM backend -- the implementation under test.
///
/// Derives the keypair from `seed`, then recovers the shared secret for `ciphertext`.
/// A wrong-length seed or ciphertext is `None`, mirroring the reference.
pub fn our_decapsulate(set: MlKemSet, seed: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let ct = Ciphertext::try_from(ciphertext).ok()?;
    // `ml-kem`'s parameter bound is private, so a generic helper cannot name it; expand
    // the concrete keygen + decapsulate per parameter set.
    macro_rules! decapsulate_with {
        ($param:ty) => {{
            let backend = crypto::mlkem::MlKem::<$param>::new();
            let (_encapsulation_key, decapsulation_key) = backend.keygen(seed).ok()?;
            backend
                .decapsulate(&decapsulation_key, &ct)
                .ok()
                .map(|secret| secret.as_slice().to_vec())
        }};
    }
    match set {
        MlKemSet::MlKem768 => decapsulate_with!(ml_kem::MlKem768),
        MlKemSet::MlKem1024 => decapsulate_with!(ml_kem::MlKem1024),
    }
}

/// The two backends produced different shared secrets for the same input -- a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KemMismatch {
    /// What our backend produced (`None` = it treated the input as malformed).
    pub ours: Option<Vec<u8>>,
    /// What the reference produced.
    pub reference: Option<Vec<u8>>,
}

/// Runs our backend and `reference` decapsulate on the same input and compares them.
///
/// `Ok(secret)` means they agree (the shared secret, or `None` if both rejected the
/// input as malformed); `Err(KemMismatch)` means they disagree.
pub fn differential_decapsulate(
    reference: &dyn MlKemReference,
    set: MlKemSet,
    seed: &[u8],
    ciphertext: &[u8],
) -> Result<Option<Vec<u8>>, KemMismatch> {
    let ours = our_decapsulate(set, seed, ciphertext);
    let theirs = reference.decapsulate(set, seed, ciphertext);
    if ours == theirs {
        Ok(ours)
    } else {
        Err(KemMismatch {
            ours,
            reference: theirs,
        })
    }
}

// FFI to the vendored Cisco hash-sigs verify entry point (`build.rs` compiles it).
unsafe extern "C" {
    fn hss_validate_signature(
        public_key: *const u8,
        message: *const core::ffi::c_void,
        message_len: usize,
        signature: *const u8,
        signature_len: usize,
        info: *mut core::ffi::c_void,
    ) -> bool;
}

/// An independent LMS/HSS verifier -- the reference side of the differential.
///
/// `verify` returns whether the reference accepts. A wrong-length key or signature is a
/// rejection, not a panic, so malformed inputs compare cleanly against our backend.
pub trait LmsReference {
    /// Whether the reference accepts `signature` over `message` under `public_key`.
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

/// The Cisco hash-sigs reference, via the vendored C verify path.
pub struct HashSigs;

impl LmsReference for HashSigs {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        // SAFETY: each slice is valid for reads of its length for the duration of the
        // call; `hss_validate_signature` only reads them. The optional `info`
        // out-parameter is passed as null.
        unsafe {
            hss_validate_signature(
                public_key.as_ptr(),
                message.as_ptr() as *const core::ffi::c_void,
                message.len(),
                signature.as_ptr(),
                signature.len(),
                core::ptr::null_mut(),
            )
        }
    }
}

/// Verifies with our `koffer-crypto` LMS backend -- the implementation under test.
///
/// Showcase profile (2-level HSS, SHA-256). A wrong-length key or signature is a
/// rejection, mirroring the reference.
pub fn our_lms_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(key), Ok(sig)) = (
        VerifyingKey::try_from(public_key),
        Signature::try_from(signature),
    ) else {
        return false;
    };
    crypto::lms::Lms::<hbs_lms::Sha256_256>::new()
        .verify(&key, message, &sig)
        .is_ok()
}

/// Runs our backend and `reference` on the same LMS verify input and compares them.
///
/// `Ok(accepted)` means they agree (and `accepted` is their shared answer);
/// `Err(Mismatch)` means they disagree. Reuses [`Mismatch`] -- the same accept/reject
/// shape as the ML-DSA differential.
pub fn differential_lms_verify(
    reference: &dyn LmsReference,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, Mismatch> {
    let ours = our_lms_verify(public_key, message, signature);
    let theirs = reference.verify(public_key, message, signature);
    if ours == theirs {
        Ok(ours)
    } else {
        Err(Mismatch {
            ours,
            reference: theirs,
        })
    }
}
