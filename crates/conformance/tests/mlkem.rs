//! Differential tests for the ML-KEM decapsulate path: our `koffer-cryptography` backend
//! against the independent `oqs` (liboqs) reference.
//!
//! Three groups: the Wycheproof decapsulation vectors replayed through both backends,
//! a randomized implicit-rejection proptest, and a meta-test proving the harness
//! catches a disagreeing reference.

use koffer_conformance::{
    Mismatch, MlKemNative, MlKemReference, MlKemSet, OqsMlKem, differential_decapsulate, kat,
};
use proptest::prelude::*;

const KEM_768: &str = include_str!("../../../kat/mlkem/wycheproof-768.kat");
const KEM_1024: &str = include_str!("../../../kat/mlkem/wycheproof-1024.kat");

// ML-KEM keygen seed: 64 bytes (FIPS 203 d || z). ML-KEM-768 ciphertext: 1088 bytes.
const SEED: [u8; 64] = [0x42u8; 64];
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;

// The independent references the ML-KEM differential runs against: liboqs (widely deployed)
// and mlkem-native (formally verified). Every vector is checked against both.
fn references() -> [(&'static str, &'static dyn MlKemReference); 2] {
    [("oqs", &OqsMlKem), ("mlkem-native", &MlKemNative)]
}

// Group 1: the Wycheproof decapsulation vectors, three-way (ours == oqs == vector).
fn decapsulate_kat_differential(
    name: &str,
    reference: &dyn MlKemReference,
    set: MlKemSet,
    vectors: &str,
) {
    let records = kat::parse(vectors);
    assert!(!records.is_empty());
    for r in &records {
        let tc_id = r.tc_id().expect("each vector has a tcId");
        let seed = r.field("seed").unwrap();
        let ciphertext = r.field("ciphertext").unwrap();
        let expected = r.field("shared_secret").unwrap();
        let agreed = differential_decapsulate(reference, set, seed, ciphertext)
            .unwrap_or_else(|m| panic!("{name} {set:?} tcId {tc_id}: backends disagree: {m:?}"));
        assert_eq!(
            agreed.as_deref(),
            Some(expected),
            "{name} {set:?} tcId {tc_id}: agreed secret differs from the vector"
        );
    }
}

#[test]
fn wycheproof_decapsulate_differential() {
    for (name, reference) in references() {
        decapsulate_kat_differential(name, reference, MlKemSet::MlKem768, KEM_768);
        decapsulate_kat_differential(name, reference, MlKemSet::MlKem1024, KEM_1024);
    }
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
        for (name, reference) in references() {
            let agreed = differential_decapsulate(reference, MlKemSet::MlKem768, &SEED, &ciphertext);
            prop_assert!(
                matches!(agreed, Ok(Some(_))),
                "{name}: expected agreement, got {agreed:?}"
            );
        }
    }
}

// A deliberately-wrong reference that returns a fixed bogus secret.
struct WrongSecret;

impl MlKemReference for WrongSecret {
    fn decapsulate(&self, _set: MlKemSet, _seed: &[u8], _ciphertext: &[u8]) -> Option<Vec<u8>> {
        Some(vec![0u8; 32])
    }
}

#[test]
fn differential_catches_a_wrong_reference() {
    // On a real vector our backend returns the true secret while `WrongSecret` returns
    // zeros, so the differential must surface a mismatch instead of a false agreement.
    let records = kat::parse(KEM_768);
    let r = records.first().expect("at least one vector");
    let expected = r.field("shared_secret").unwrap();
    match differential_decapsulate(
        &WrongSecret,
        MlKemSet::MlKem768,
        r.field("seed").unwrap(),
        r.field("ciphertext").unwrap(),
    ) {
        Err(Mismatch { ours, reference }) => {
            assert_eq!(ours.as_deref(), Some(expected));
            assert_eq!(reference, Some(vec![0u8; 32]));
        }
        Ok(_) => panic!("differential failed to catch the wrong reference"),
    }
}
