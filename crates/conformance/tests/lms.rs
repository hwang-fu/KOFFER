//! Differential tests for the LMS/HSS verify path: our `koffer-cryptography` backend (wrapping
//! `hbs-lms`) against the independent Cisco `hash-sigs` C reference.
//!
//! Three groups: the RFC 8554 HSS vectors replayed through both backends, a randomized
//! proptest (sign with our showcase backend, cross-verify), and a meta-test proving the
//! harness catches a disagreeing reference. Showcase profile only -- hash-sigs implements
//! full SHA-256, not the SHA-256/192 set our CNSA20 profile uses.

use koffer_cryptography::{
    lms::{Lms, showcase_params},
    sign::{SigningKey, StatefulSigner, VerifyingKey},
};
use hbs_lms::Sha256_256;
use koffer_conformance::{HashSigs, LmsReference, Mismatch, differential_lms_verify, kat};
use proptest::prelude::*;

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

// Group 2: sign random messages with our showcase backend, then cross-verify. Keygen/sign
// is O(2^h), so key once and cap cases. Each case re-signs with the same one-time key
// (state is not persisted) -- fine, since each signature still verifies.
fn showcase_keypair() -> &'static (SigningKey, VerifyingKey) {
    static KP: std::sync::OnceLock<(SigningKey, VerifyingKey)> = std::sync::OnceLock::new();
    KP.get_or_init(|| {
        Lms::<Sha256_256>::new()
            .keygen(&showcase_params(), &[0x42u8; 32])
            .unwrap()
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 8, ..ProptestConfig::default() })]

    // A genuine signature from our backend: both verifiers accept, and they agree.
    #[test]
    fn signed_message_both_accept(message in prop::collection::vec(any::<u8>(), 0..512)) {
        let (signing_key, verifying_key) = showcase_keypair();
        let signature = Lms::<Sha256_256>::new()
            .sign(signing_key, &message, &mut |_| Ok(()))
            .unwrap();
        let agreed = differential_lms_verify(
            &HashSigs,
            verifying_key.as_slice(),
            &message,
            signature.as_slice(),
        )
        .expect("backends agree on a genuine signature");
        prop_assert!(agreed);
    }

    // One flipped message byte: both verifiers reject, and they agree.
    #[test]
    fn tampered_message_both_reject(
        message in prop::collection::vec(any::<u8>(), 1..512),
        flip in any::<usize>(),
    ) {
        let (signing_key, verifying_key) = showcase_keypair();
        let signature = Lms::<Sha256_256>::new()
            .sign(signing_key, &message, &mut |_| Ok(()))
            .unwrap();
        let mut tampered = message.clone();
        let at = flip % tampered.len();
        tampered[at] ^= 0x01;
        let agreed = differential_lms_verify(
            &HashSigs,
            verifying_key.as_slice(),
            &tampered,
            signature.as_slice(),
        )
        .expect("backends agree on a tampered message");
        prop_assert!(!agreed);
    }
}

// A deliberately-wrong reference that accepts everything.
struct AlwaysAccept;

impl LmsReference for AlwaysAccept {
    fn verify(&self, _public_key: &[u8], _message: &[u8], _signature: &[u8]) -> bool {
        true
    }
}

#[test]
fn differential_catches_a_wrong_reference() {
    // On a tampered message our backend rejects while `AlwaysAccept` accepts, so the
    // differential must surface a mismatch instead of a false agreement.
    let records = kat::parse(TC1);
    let r = records.first().expect("a vector");
    let public_key = r.field("public_key").unwrap();
    let signature = r.field("signature").unwrap();
    let mut tampered = r.field("message").unwrap().to_vec();
    tampered[0] ^= 0x01;
    let result = differential_lms_verify(&AlwaysAccept, public_key, &tampered, signature);
    assert_eq!(
        result,
        Err(Mismatch {
            ours: false,
            reference: true
        })
    );
}
