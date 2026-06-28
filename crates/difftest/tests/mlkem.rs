//! Differential tests for the ML-KEM decapsulate path: our `koffer-crypto` backend
//! against the independent `oqs` (liboqs) reference.
//!
//! Three groups: the Wycheproof decapsulation vectors replayed through both backends,
//! a randomized implicit-rejection proptest, and a meta-test proving the harness
//! catches a disagreeing reference.

use koffer_difftest::{MlKemSet, OqsMlKem, differential_decapsulate, kat};

const KEM_768: &str = include_str!("../../../kat/mlkem/wycheproof-768.kat");
const KEM_1024: &str = include_str!("../../../kat/mlkem/wycheproof-1024.kat");

// Group 1: the Wycheproof decapsulation vectors, three-way (ours == oqs == vector).
fn decapsulate_kat_differential(set: MlKemSet, vectors: &str) {
    let records = kat::parse(vectors);
    assert!(!records.is_empty());
    for r in &records {
        let tc_id = r.tc_id().expect("each vector has a tcId");
        let seed = r.field("seed").unwrap();
        let ciphertext = r.field("ciphertext").unwrap();
        let expected = r.field("shared_secret").unwrap();
        let agreed = differential_decapsulate(&OqsMlKem, set, seed, ciphertext)
            .unwrap_or_else(|m| panic!("{set:?} tcId {tc_id}: backends disagree: {m:?}"));
        assert_eq!(
            agreed.as_deref(),
            Some(expected),
            "{set:?} tcId {tc_id}: agreed secret differs from the vector"
        );
    }
}

#[test]
fn wycheproof_decapsulate_differential() {
    decapsulate_kat_differential(MlKemSet::MlKem768, KEM_768);
    decapsulate_kat_differential(MlKemSet::MlKem1024, KEM_1024);
}
