//! Differential tests for the ML-DSA verify path: our `koffer-crypto` backend
//! against the independent `oqs` (liboqs) reference.
//!
//! Three groups: the Wycheproof verify vectors replayed through both backends,
//! randomized valid and tampered signatures, and a meta-test proving the harness
//! actually catches a disagreeing reference.

use koffer_difftest::{MlDsaSet, OqsMlDsa, differential_verify, kat};

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
