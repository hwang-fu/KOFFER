//! Differential tests for the ML-DSA verify path: our `koffer-crypto` backend
//! against the independent `oqs` (liboqs) reference.
//!
//! Three groups: the Wycheproof verify vectors replayed through both backends,
//! randomized valid and tampered signatures, and a meta-test proving the harness
//! actually catches a disagreeing reference.

use crypto::mldsa::MlDsa;
use crypto::sign::{Signer, SigningKey, VerifyingKey};
use koffer_difftest::{Mismatch, MlDsaReference, MlDsaSet, OqsMlDsa, differential_verify, kat};
use ml_dsa::MlDsa65;
use proptest::prelude::*;

const VERIFY_65: &str = include_str!("../../../kat/mldsa/wycheproof-verify-65.kat");
const VERIFY_87: &str = include_str!("../../../kat/mldsa/wycheproof-verify-87.kat");

// (parameter set, tcId) cases where liboqs is known to diverge from our backend and
// FIPS 204. Each entry is a documented reference leniency, not a bug in our backend.
const KNOWN_OQS_DIVERGENCES: &[(MlDsaSet, u32)] = &[
    // liboqs 0.13.0 accepts a signature whose `z` vector violates the FIPS 204
    // infinity-norm bound; our backend and the Wycheproof vector both reject it.
    (MlDsaSet::MlDsa65, 84),
];

// Group 1: the Wycheproof verify vectors. Our backend and oqs must agree and match the
// vector, except on the documented liboqs divergences above.
fn verify_kat_differential(set: MlDsaSet, vectors: &str) {
    let records = kat::parse(vectors);
    assert!(!records.is_empty());
    let mut diverged = Vec::new();
    let mut unexpected = Vec::new();
    for r in &records {
        let tc_id = r.tc_id().expect("each vector has a tcId");
        let public_key = r.field("public_key").unwrap();
        let message = r.field("message").unwrap();
        let signature = r.field("signature").unwrap();
        let expected = r.field("result").unwrap()[0] == 0x01;
        match differential_verify(&OqsMlDsa, set, public_key, message, signature) {
            Ok(agreed) => assert_eq!(
                agreed, expected,
                "{set:?} tcId {tc_id}: agreed answer differs from the vector"
            ),
            Err(mismatch) => {
                diverged.push(tc_id);
                let documented = KNOWN_OQS_DIVERGENCES.contains(&(set, tc_id));
                let ours_matches_vector = mismatch.ours == expected;
                if !(documented && ours_matches_vector) {
                    unexpected.push((tc_id, mismatch));
                }
            }
        }
    }
    assert!(
        unexpected.is_empty(),
        "{set:?}: unexpected differential divergences (tcId, mismatch): {unexpected:?}"
    );
    // Each documented divergence must still occur; a missing one means liboqs changed
    // and the entry is stale.
    for &(divergent_set, tc_id) in KNOWN_OQS_DIVERGENCES {
        if divergent_set == set {
            assert!(
                diverged.contains(&tc_id),
                "{set:?} tcId {tc_id}: documented divergence no longer occurs; remove it"
            );
        }
    }
}

#[test]
fn wycheproof_verify_differential() {
    verify_kat_differential(MlDsaSet::MlDsa65, VERIFY_65);
    verify_kat_differential(MlDsaSet::MlDsa87, VERIFY_87);
}

// Group 2: randomized valid and tampered signatures. ML-DSA-65 only; ML-DSA-87 random
// signing is slow, and its verify path is already exercised differentially in group 1.
fn mldsa65_keypair() -> &'static (SigningKey, VerifyingKey) {
    static KP: std::sync::OnceLock<(SigningKey, VerifyingKey)> = std::sync::OnceLock::new();
    KP.get_or_init(|| MlDsa::<MlDsa65>::new().keygen(&[0x42u8; 32]).unwrap())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

    // A genuine signature: both backends accept, and they agree.
    #[test]
    fn valid_signature_both_accept(message in prop::collection::vec(any::<u8>(), 0..512)) {
        let (signing_key, verifying_key) = mldsa65_keypair();
        let signature = MlDsa::<MlDsa65>::new().sign(signing_key, &message).unwrap();
        let agreed = differential_verify(
            &OqsMlDsa,
            MlDsaSet::MlDsa65,
            verifying_key.as_slice(),
            &message,
            signature.as_slice(),
        )
        .expect("backends agree on a genuine signature");
        prop_assert!(agreed);
    }

    // One flipped signature byte: both backends reject, and they agree.
    #[test]
    fn tampered_signature_both_reject(
        message in prop::collection::vec(any::<u8>(), 0..512),
        flip in any::<usize>(),
    ) {
        let (signing_key, verifying_key) = mldsa65_keypair();
        let signature = MlDsa::<MlDsa65>::new().sign(signing_key, &message).unwrap();
        let mut bytes = signature.as_slice().to_vec();
        let at = flip % bytes.len();
        bytes[at] ^= 0x01;
        let agreed = differential_verify(
            &OqsMlDsa,
            MlDsaSet::MlDsa65,
            verifying_key.as_slice(),
            &message,
            &bytes,
        )
        .expect("backends agree on a tampered signature");
        prop_assert!(!agreed);
    }
}

// Group 3: the negative meta-test -- the harness is not a no-op.
/// A deliberately-wrong reference that accepts everything.
struct AlwaysAccept;

impl MlDsaReference for AlwaysAccept {
    fn verify(
        &self,
        _set: MlDsaSet,
        _public_key: &[u8],
        _message: &[u8],
        _signature: &[u8],
    ) -> bool {
        true
    }
}

#[test]
fn differential_catches_a_wrong_reference() {
    // On a must-reject vector our backend rejects while `AlwaysAccept` accepts, so the
    // differential must surface a mismatch instead of a false agreement.
    let records = kat::parse(VERIFY_65);
    let reject = records
        .iter()
        .find(|r| r.field("result").unwrap()[0] == 0x00)
        .expect("a must-reject vector exists");
    let result = differential_verify(
        &AlwaysAccept,
        MlDsaSet::MlDsa65,
        reject.field("public_key").unwrap(),
        reject.field("message").unwrap(),
        reject.field("signature").unwrap(),
    );
    assert_eq!(
        result,
        Err(Mismatch {
            ours: false,
            reference: true
        })
    );
}
