//! Sign a SUIT manifest as a `COSE_Sign1` and verify it, with the signature backend
//! selected by the integer COSE codepoint.
//!
//! The sign side picks the algorithm from the profile; the verify side picks it purely
//! from the codepoint carried in the `COSE_Sign1`. The flow never names a parameter set
//! -- all per-scheme knowledge lives in the two dispatch helpers at the bottom, so the
//! profile is the only switch. The general signer is ML-DSA.

use crypto::alg::SigAlg;
use crypto::mldsa::MlDsa;
use crypto::profile::CryptoProfile;
use crypto::sign::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ml_dsa::{MlDsa65, MlDsa87};
use proto::alg::AlgId;
use proto::codec;
use proto::cose::{CoseSign1, Payload, SigStructure};
use proto::manifest::Manifest;

/// Signs `manifest` under `profile`'s signature algorithm; returns the encoded
/// `COSE_Sign1` and the verifying key needed to check it.
pub fn sign_manifest(
    profile: CryptoProfile,
    manifest: &Manifest,
    entropy: &[u8],
) -> (Vec<u8>, VerifyingKey) {
    let alg = profile.general_sig();
    let alg_id = AlgId::new(alg.cose_id() as i64);
    let manifest_bytes = codec::encode(manifest).expect("encode manifest");

    let (signer, signing_key, verifying_key) = make_signer(alg, entropy);
    let to_be_signed = codec::encode(&SigStructure::new(alg_id, &[], &manifest_bytes))
        .expect("encode Sig_structure");
    let signature = signer
        .sign(&signing_key, &to_be_signed)
        .expect("sign Sig_structure");

    let cose = CoseSign1::new(
        alg_id,
        None,
        Payload::Attached(&manifest_bytes),
        signature.as_slice(),
    );
    (
        codec::encode(&cose).expect("encode COSE_Sign1"),
        verifying_key,
    )
}

/// Verifies an encoded `COSE_Sign1` against `verifying_key`. The verifier backend is
/// chosen purely from the codepoint carried in the structure -- the agility proof.
pub fn verify_manifest(cose_bytes: &[u8], verifying_key: &VerifyingKey) -> bool {
    let Ok(cose) = codec::decode::<CoseSign1>(cose_bytes) else {
        return false;
    };
    let Payload::Attached(manifest_bytes) = cose.payload() else {
        return false;
    };
    let Ok(signature) = Signature::try_from(cose.signature()) else {
        return false;
    };
    let Ok(to_be_signed) = codec::encode(&SigStructure::new(cose.alg(), &[], manifest_bytes))
    else {
        return false;
    };
    verifier_from_codepoint(cose.alg())
        .verify(verifying_key, &to_be_signed, &signature)
        .is_ok()
}

/// Selects the signer for `alg` (sign side, driven by the profile) and generates a keypair.
fn make_signer(alg: SigAlg, entropy: &[u8]) -> (Box<dyn Signer>, SigningKey, VerifyingKey) {
    match alg {
        SigAlg::MlDsa65 => {
            let backend = MlDsa::<MlDsa65>::new();
            let (sk, vk) = backend.keygen(entropy).expect("ML-DSA keygen");
            (Box::new(backend), sk, vk)
        }
        SigAlg::MlDsa87 => {
            let backend = MlDsa::<MlDsa87>::new();
            let (sk, vk) = backend.keygen(entropy).expect("ML-DSA keygen");
            (Box::new(backend), sk, vk)
        }
        SigAlg::HssLmsSha256 => unreachable!("the general signer is ML-DSA"),
    }
}

/// Selects the verifier from the wire codepoint (verify side).
fn verifier_from_codepoint(alg_id: AlgId) -> Box<dyn Verifier> {
    match SigAlg::from_cose_id(alg_id.get() as i32) {
        Some(SigAlg::MlDsa65) => Box::new(MlDsa::<MlDsa65>::new()),
        Some(SigAlg::MlDsa87) => Box::new(MlDsa::<MlDsa87>::new()),
        other => panic!("unsupported signature codepoint: {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::ascii::AsciiStr;
    use proto::manifest::SuitDigest;

    #[test]
    fn sign_then_verify_round_trips() {
        let class_id = AsciiStr::try_from("device").expect("ascii");
        let digest_bytes = [0xABu8; 32];
        let digest = SuitDigest::new(AlgId::new(-16), &digest_bytes);
        let manifest = Manifest::new(1, 7, class_id, digest, 0);
        let (cose, vk) = sign_manifest(CryptoProfile::Showcase, &manifest, &[0x42u8; 32]);
        assert!(verify_manifest(&cose, &vk));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let class_id = AsciiStr::try_from("device").expect("ascii");
        let digest_bytes = [0xABu8; 32];
        let digest = SuitDigest::new(AlgId::new(-16), &digest_bytes);
        let manifest = Manifest::new(1, 7, class_id, digest, 0);
        let (mut cose, vk) = sign_manifest(CryptoProfile::Showcase, &manifest, &[0x42u8; 32]);
        let mid = cose.len() / 2;
        cose[mid] ^= 0x01;
        assert!(!verify_manifest(&cose, &vk));
    }
}
