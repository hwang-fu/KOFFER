//! End-to-end integration test: the full manifest sign/verify + payload seal/unseal flow,
//! run in both crypto profiles, with tamper-negative cases on each path.

use core::convert::Infallible;
use crypto::profile::CryptoProfile;
use koffer_demo::{run, seal, sign};
use proto::alg::AlgId;
use proto::ascii::AsciiStr;
use proto::manifest::{Manifest, SuitDigest};

struct TestRng(u64);
impl rand_core::TryRng for TestRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(self.try_next_u64()? as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.0 = self.0.wrapping_add(1);
        Ok(self.0)
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for chunk in dst.chunks_mut(8) {
            chunk.copy_from_slice(&self.try_next_u64()?.to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}
impl rand_core::TryCryptoRng for TestRng {}

#[test]
fn full_flow_runs_in_both_profiles() {
    assert!(run::run(CryptoProfile::Showcase, &mut TestRng(1)).ok());
    assert!(run::run(CryptoProfile::Cnsa20, &mut TestRng(1)).ok());
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

    let (mut sealed, dk) =
        seal::seal_payload(CryptoProfile::Cnsa20, b"payload", b"aad", &mut TestRng(2));
    let i = sealed.len() / 2;
    sealed[i] ^= 0x01;
    assert!(seal::unseal_payload(&sealed, &dk, b"aad").is_none());
}
