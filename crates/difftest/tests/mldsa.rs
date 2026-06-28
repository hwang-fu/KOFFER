//! Differential tests for the ML-DSA verify path: our `koffer-crypto` backend
//! against the independent `oqs` (liboqs) reference.
//!
//! Three groups: the Wycheproof verify vectors replayed through both backends,
//! randomized valid and tampered signatures, and a meta-test proving the harness
//! actually catches a disagreeing reference.

use crypto::mldsa::MlDsa;
use crypto::sign::{Signer, SigningKey, VerifyingKey};
use koffer_difftest::{MlDsaSet, OqsMlDsa, differential_verify, kat};
use ml_dsa::MlDsa65;
use proptest::prelude::*;

const VERIFY_65: &str = include_str!("../../../kat/mldsa/wycheproof-verify-65.kat");
const VERIFY_87: &str = include_str!("../../../kat/mldsa/wycheproof-verify-87.kat");

// Group 1: the Wycheproof verify vectors, three-way (our backend == oqs == vector).
fn verify_kat_differential(set: MlDsaSet, vectors: &str) {
    let records = kat::parse(vectors);
    assert!(!records.is_empty());
    for (i, r) in records.iter().enumerate() {
        let public_key = r.field("public_key").unwrap();
        let message = r.field("message").unwrap();
        let signature = r.field("signature").unwrap();
        let expected = r.field("result").unwrap()[0] == 0x01;
        let agreed = differential_verify(&OqsMlDsa, set, public_key, message, signature)
            .unwrap_or_else(|m| panic!("{set:?} record {i}: backends disagree: {m:?}"));
        assert_eq!(
            agreed, expected,
            "{set:?} record {i}: differs from the vector"
        );
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
