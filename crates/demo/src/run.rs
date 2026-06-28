use crypto::profile::CryptoProfile;
use proto::alg::AlgId;
use proto::ascii::AsciiStr;
use proto::manifest::{Manifest, SuitDigest};

/// Runs the whole flow under `profile`: build a SUIT manifest, sign and verify it, then seal
/// and open a payload. Returns whether everything round-trips. One code path, both profiles --
/// the only switch is `profile`.
pub fn run(profile: CryptoProfile, rng: &mut dyn rand_core::CryptoRng) -> bool {
    let Ok(class_id) = AsciiStr::try_from("koffer-device") else {
        return false;
    };
    let digest = SuitDigest::new(AlgId::new(-16), &[0xA5u8; 32]);
    let manifest = Manifest::new(1, 42, class_id, digest, 0);

    let (signed, verifying_key) = crate::sign::sign_manifest(profile, &manifest, &[0x11u8; 32]);
    if !crate::sign::verify_manifest(&signed, &verifying_key) {
        return false;
    }

    let payload = b"firmware image";
    let aad = b"firmware-update";
    let (sealed, decapsulation_key) = crate::seal::seal_payload(profile, payload, aad, rng);
    crate::seal::unseal_payload(&sealed, &decapsulation_key, aad).as_deref() == Some(&payload[..])
}
