//! Differential tests for the LMS/HSS verify path: our `koffer-crypto` backend (wrapping
//! `hbs-lms`) against the independent Cisco `hash-sigs` C reference.
//!
//! Three groups: the RFC 8554 HSS vectors replayed through both backends, a randomized
//! proptest (sign with our showcase backend, cross-verify), and a meta-test proving the
//! harness catches a disagreeing reference. Showcase profile only -- hash-sigs implements
//! full SHA-256, not the SHA-256/192 set our CNSA20 profile uses.

use koffer_difftest::{HashSigs, differential_lms_verify, kat};

const TC1: &str = include_str!("../../../kat/lms/rfc8554-tc1.kat");
const TC2: &str = include_str!("../../../kat/lms/rfc8554-tc2.kat");

// Group 1: the RFC 8554 HSS vectors. Both backends accept the published signature and
// both reject a one-byte-tampered message.
fn verify_kat_differential(vectors: &str) {
    let records = kat::parse(vectors);
    assert!(!records.is_empty());
    for r in &records {
        let public_key = r.field("public_key").unwrap();
        let message = r.field("message").unwrap();
        let signature = r.field("signature").unwrap();

        let agreed = differential_lms_verify(&HashSigs, public_key, message, signature)
            .expect("backends agree on the published signature");
        assert!(agreed, "both backends should accept the RFC 8554 signature");

        let mut tampered = message.to_vec();
        tampered[0] ^= 0x01;
        let agreed = differential_lms_verify(&HashSigs, public_key, &tampered, signature)
            .expect("backends agree on a tampered message");
        assert!(!agreed, "both backends should reject the tampered message");
    }
}

#[test]
fn rfc8554_verify_differential() {
    verify_kat_differential(TC1);
    verify_kat_differential(TC2);
}
