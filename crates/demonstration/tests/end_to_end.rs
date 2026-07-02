//! End-to-end integration test: the full manifest sign/verify + payload seal/unseal flow,
//! run in both crypto profiles, with tamper-negative cases on each path.

use koffer_cryptography::profile::CryptoProfile;
use koffer_demonstration::{run, seal, sign};
use koffer_testutil::TestRng;
use koffer_wire::{
    alg::AlgId,
    ascii::AsciiStr,
    manifest::{Manifest, SuitDigest},
};

#[test]
fn full_flow_runs_in_both_profiles() {
    assert!(run::run(CryptoProfile::Showcase, &mut TestRng::new(1)).ok());
    assert!(run::run(CryptoProfile::Cnsa20, &mut TestRng::new(1)).ok());
}

#[test]
fn tampered_signature_and_container_are_rejected() {
    let class_id = AsciiStr::try_from("koffer-device").unwrap();
    let digest_bytes = [0xA5u8; 32];
    let digest = SuitDigest::new(AlgId::new(-16), &digest_bytes);
    let manifest = Manifest::new(1, 42, class_id, digest, 0);

    let (mut signed, vk) = sign::sign_manifest(CryptoProfile::Cnsa20, &manifest, &[0x11u8; 32]);
    let i = signed.len() / 2;
    signed[i] ^= 0x01;
    assert!(!sign::verify_manifest(&signed, &vk));

    let (mut sealed, dk) = seal::seal_payload(
        CryptoProfile::Cnsa20,
        b"payload",
        b"aad",
        &mut TestRng::new(2),
    );
    let i = sealed.len() / 2;
    sealed[i] ^= 0x01;
    assert!(seal::unseal_payload(&sealed, &dk, b"aad").is_none());
}
