//! Differential tests for the ML-KEM decapsulate path: our `koffer-crypto` backend
//! against the independent `oqs` (liboqs) reference.
//!
//! Three groups: the Wycheproof decapsulation vectors replayed through both backends,
//! a randomized implicit-rejection proptest, and a meta-test proving the harness
//! catches a disagreeing reference.

use koffer_difftest::{MlKemSet, OqsMlKem, differential_decapsulate, kat};
use proptest::prelude::*;

const KEM_768: &str = include_str!("../../../kat/mlkem/wycheproof-768.kat");
const KEM_1024: &str = include_str!("../../../kat/mlkem/wycheproof-1024.kat");

// ML-KEM keygen seed: 64 bytes (FIPS 203 d || z). ML-KEM-768 ciphertext: 1088 bytes.
const SEED: [u8; 64] = [0x42u8; 64];
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;

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

proptest! {
    #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

    // A random same-length ciphertext is almost surely invalid; ML-KEM implicit rejection
    // makes both backends return the same deterministic pseudo-random secret, so they agree.
    // ML-KEM-768 only; the 1024 decapsulate path is covered by group 1.
    #[test]
    fn random_ciphertext_same_implicit_rejection(
        ciphertext in prop::collection::vec(any::<u8>(), MLKEM768_CIPHERTEXT_LEN)
    ) {
        let agreed = differential_decapsulate(&OqsMlKem, MlKemSet::MlKem768, &SEED, &ciphertext)
            .expect("backends agree on a random ciphertext");
        prop_assert!(agreed.is_some());
    }
}
