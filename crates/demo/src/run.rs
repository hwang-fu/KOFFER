use crypto::profile::CryptoProfile;
use proto::{
    alg::AlgId,
    ascii::AsciiStr,
    manifest::{Manifest, SuitDigest},
};

/// The observable outcome of one `run`: the encoded size of each artifact and whether each
/// check passed. It lets a caller print a per-step trace without the flow itself doing any I/O.
pub struct RunReport {
    pub profile: CryptoProfile,
    pub signed_len: usize,
    pub verified: bool,
    pub sealed_len: usize,
    pub unsealed: bool,
}

impl RunReport {
    /// Whether the full round-trip succeeded: signature verified and payload unsealed.
    pub fn ok(&self) -> bool {
        self.verified && self.unsealed
    }
}

/// Runs the whole flow under `profile`: build a SUIT manifest, sign and verify it, then seal
/// and unseal a payload. Returns a report of each step's outcome. One code path, both profiles --
/// the only switch is `profile`.
pub fn run(profile: CryptoProfile, rng: &mut dyn rand_core::CryptoRng) -> RunReport {
    let class_id = AsciiStr::try_from("koffer-device").expect("ascii class id");
    let digest = SuitDigest::new(AlgId::new(-16), &[0xA5u8; 32]);
    let manifest = Manifest::new(1, 42, class_id, digest, 0);

    let (signed, verifying_key) = crate::sign::sign_manifest(profile, &manifest, &[0x11u8; 32]);
    let verified = crate::sign::verify_manifest(&signed, &verifying_key);

    let payload = b"firmware image";
    let aad = b"firmware-update";
    let (sealed, decapsulation_key) = crate::seal::seal_payload(profile, payload, aad, rng);
    let unsealed = crate::seal::unseal_payload(&sealed, &decapsulation_key, aad).as_deref()
        == Some(&payload[..]);

    RunReport {
        profile,
        signed_len: signed.len(),
        verified,
        sealed_len: sealed.len(),
        unsealed,
    }
}
