//! Hybrid KEM: X25519 + ML-KEM, combined into one shared secret.
//!
//! The hybrid runs both component key-exchanges and binds their two shared secrets
//! into a single one, so the result stays secure if *either* X25519 or ML-KEM is
//! broken. The binding is a dual-PRF HKDF combiner: one shared secret is the HKDF
//! salt and the other the input keying material (so HMAC's dual-PRF property gives
//! security if either is random), and the full transcript -- the hybrid ciphertext
//! -- goes into `info`, tying the combined secret to this exact exchange.

use ml_kem::{MlKem768, MlKem1024};
use sha2::{Sha256, Sha384};
use zeroize::Zeroize;

use crate::{
    error::KemError,
    kdf::{Hkdf, Kdf},
    kem::{Ciphertext, DecapsulationKey, EncapsulationKey, Kem, SharedSecret},
    mlkem::MlKem,
};

// Domain-separation labels, one per variant, so a combined secret is bound to its
// algorithm and cannot be confused with any other HKDF output.
const LABEL_768: &[u8] = b"hybrid-x25519-mlkem768-v1";
const LABEL_1024: &[u8] = b"hybrid-x25519-mlkem1024-v1";

// Upper bound on the `info` buffer: the longest label plus the largest hybrid
// ciphertext (ML-KEM-1024 ciphertext 1568 + the 32-byte X25519 ephemeral key).
const INFO_MAX: usize = 26 + 1568 + 32;

/// Combines the two component shared secrets into one, binding the transcript.
///
/// `ss_x25519` is the HKDF salt and `ss_mlkem` the IKM (the dual-PRF that makes the
/// result secure if either component is); `label || ciphertext` is the `info`.
fn combine_shared_secrets<K: Kdf>(
    kdf: &K,
    label: &[u8],
    ss_x25519: &[u8],
    ss_mlkem: &[u8],
    ciphertext: &[u8],
) -> Result<SharedSecret, KemError> {
    // info = label || the full hybrid ciphertext (ml-kem ct || x25519 ephemeral key).
    let mut info = [0u8; INFO_MAX];
    let len = label.len() + ciphertext.len();
    let info = info.get_mut(..len).ok_or(KemError::Internal)?;
    info[..label.len()].copy_from_slice(label);
    info[label.len()..].copy_from_slice(ciphertext);

    let mut okm = [0u8; 32];
    kdf.derive(ss_x25519, ss_mlkem, info, &mut okm)
        .map_err(|_| KemError::Internal)?;
    let combined = SharedSecret::try_from(&okm[..]).map_err(|_| KemError::Internal);
    okm.zeroize();
    combined
}

// Stack-buffer capacity for assembling a concatenated value: the biggest hybrid
// key or ciphertext (the ML-KEM-1024 part plus the 32-byte X25519 part).
const CONCAT_MAX: usize = 1600;

/// Splits hybrid bytes into the ML-KEM part (all but the last 32 bytes) and the
/// 32-byte X25519 part. `None` if there are fewer than 32 bytes.
fn split_last_32(bytes: &[u8]) -> Option<(&[u8], [u8; 32])> {
    let n = bytes.len().checked_sub(32)?;
    let tail: [u8; 32] = bytes[n..].try_into().ok()?;
    Some((&bytes[..n], tail))
}

/// Concatenates `head || tail` into `buf`, returning the filled slice (or
/// `Internal` if the buffer is too small).
fn concat<'b>(buf: &'b mut [u8], head: &[u8], tail: &[u8; 32]) -> Result<&'b [u8], KemError> {
    let n = head.len() + tail.len();
    {
        let out = buf.get_mut(..n).ok_or(KemError::Internal)?;
        out[..head.len()].copy_from_slice(head);
        out[head.len()..].copy_from_slice(tail);
    }
    Ok(&buf[..n])
}

/// Concatenates `head || tail` in a scratch buffer and builds the bounded newtype
/// `T` from the result, wiping the scratch buffer before returning. The wipe matters
/// because the buffer may briefly hold secret key material (the decapsulation key).
fn concat_into<T>(head: &[u8], tail: &[u8; 32]) -> Result<T, KemError>
where
    for<'a> T: TryFrom<&'a [u8]>,
{
    let mut buf = [0u8; CONCAT_MAX];
    let joined = concat(&mut buf, head, tail)
        .and_then(|bytes| T::try_from(bytes).map_err(|_| KemError::Internal));
    buf.zeroize();
    joined
}

/// Generates a concrete hybrid backend for one (ML-KEM parameter set, hash, label)
/// triple: a unit struct with `keygen` plus the `Kem` encapsulate / decapsulate.
macro_rules! impl_hybrid_backend {
    ($name:ident, $mlkem:ty, $hash:ty, $label:expr) => {
        /// A hybrid KEM backend combining X25519 with ML-KEM.
        pub struct $name;

        impl $name {
            /// Generates a hybrid keypair: the first 64 bytes of `entropy` seed
            /// ML-KEM and the next 32 seed X25519, so `entropy` must be >= 96 bytes.
            pub fn keygen(
                &self,
                entropy: &[u8],
            ) -> Result<(EncapsulationKey, DecapsulationKey), KemError> {
                let mlkem_entropy = entropy.get(..64).ok_or(KemError::Internal)?;
                let mut x25519_entropy: [u8; 32] = entropy
                    .get(64..96)
                    .ok_or(KemError::Internal)?
                    .try_into()
                    .map_err(|_| KemError::Internal)?;

                let (mlkem_ek, mlkem_dk) = MlKem::<$mlkem>::new().keygen(mlkem_entropy)?;
                let (mut x25519_sk, x25519_pk) =
                    crate::x25519::keypair_from_entropy(&x25519_entropy);
                x25519_entropy.zeroize();

                let encapsulation_key =
                    concat_into::<EncapsulationKey>(mlkem_ek.as_slice(), &x25519_pk)?;
                let decapsulation_key =
                    concat_into::<DecapsulationKey>(mlkem_dk.as_slice(), &x25519_sk)?;
                x25519_sk.zeroize();
                Ok((encapsulation_key, decapsulation_key))
            }
        }

        impl Kem for $name {
            fn encapsulate(
                &self,
                key: &EncapsulationKey,
                rng: &mut dyn rand_core::CryptoRng,
            ) -> Result<(Ciphertext, SharedSecret), KemError> {
                let (mlkem_ek, x25519_pk) =
                    split_last_32(key.as_slice()).ok_or(KemError::MalformedKey)?;
                let mlkem_ek =
                    EncapsulationKey::try_from(mlkem_ek).map_err(|_| KemError::MalformedKey)?;
                let (mlkem_ct, ss_mlkem) = MlKem::<$mlkem>::new().encapsulate(&mlkem_ek, rng)?;

                let mut eph_entropy = [0u8; 32];
                rng.fill_bytes(&mut eph_entropy);
                let (mut eph_sk, eph_pk) = crate::x25519::keypair_from_entropy(&eph_entropy);
                eph_entropy.zeroize();
                let mut ss_x25519 = crate::x25519::dh(&eph_sk, &x25519_pk);
                eph_sk.zeroize();

                let ciphertext = concat_into::<Ciphertext>(mlkem_ct.as_slice(), &eph_pk)?;
                let shared = combine_shared_secrets(
                    &Hkdf::<$hash>::new(),
                    $label,
                    &ss_x25519,
                    ss_mlkem.as_slice(),
                    ciphertext.as_slice(),
                );
                ss_x25519.zeroize();
                Ok((ciphertext, shared?))
            }

            fn decapsulate(
                &self,
                key: &DecapsulationKey,
                ciphertext: &Ciphertext,
            ) -> Result<SharedSecret, KemError> {
                let (mlkem_seed, mut x25519_sk) =
                    split_last_32(key.as_slice()).ok_or(KemError::MalformedKey)?;
                let (mlkem_ct, eph_pk) =
                    split_last_32(ciphertext.as_slice()).ok_or(KemError::MalformedCiphertext)?;

                let mlkem_dk =
                    DecapsulationKey::try_from(mlkem_seed).map_err(|_| KemError::MalformedKey)?;
                let mlkem_ct =
                    Ciphertext::try_from(mlkem_ct).map_err(|_| KemError::MalformedCiphertext)?;
                let ss_mlkem = MlKem::<$mlkem>::new().decapsulate(&mlkem_dk, &mlkem_ct)?;

                let mut ss_x25519 = crate::x25519::dh(&x25519_sk, &eph_pk);
                x25519_sk.zeroize();

                let shared = combine_shared_secrets(
                    &Hkdf::<$hash>::new(),
                    $label,
                    &ss_x25519,
                    ss_mlkem.as_slice(),
                    ciphertext.as_slice(),
                );
                ss_x25519.zeroize();
                shared
            }
        }
    };
}

impl_hybrid_backend!(X25519MlKem768, MlKem768, Sha256, LABEL_768);
impl_hybrid_backend!(X25519MlKem1024, MlKem1024, Sha384, LABEL_1024);

#[cfg(test)]
mod tests {
    use koffer_testutil::TestRng;
    use proptest::prelude::*;
    use sha2::Sha256;

    use super::*;
    use crate::{
        kat::{assert_field, parse},
        kdf::Hkdf,
    };

    const SS_MLKEM: [u8; 32] = [0x01; 32];
    const SS_X25519: [u8; 32] = [0x02; 32];
    const CIPHERTEXT: [u8; 64] = [0x03; 64];

    #[test]
    fn combine_is_deterministic() {
        let kdf = Hkdf::<Sha256>::new();
        let a =
            combine_shared_secrets(&kdf, LABEL_768, &SS_MLKEM, &SS_X25519, &CIPHERTEXT).unwrap();
        let b =
            combine_shared_secrets(&kdf, LABEL_768, &SS_MLKEM, &SS_X25519, &CIPHERTEXT).unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn combine_binds_every_input() {
        let kdf = Hkdf::<Sha256>::new();
        let base =
            combine_shared_secrets(&kdf, LABEL_768, &SS_MLKEM, &SS_X25519, &CIPHERTEXT).unwrap();

        // Each input -- both secrets, the transcript, and the label -- changes the output.
        let mut ss_mlkem = SS_MLKEM;
        ss_mlkem[0] ^= 1;
        let a =
            combine_shared_secrets(&kdf, LABEL_768, &ss_mlkem, &SS_X25519, &CIPHERTEXT).unwrap();
        assert_ne!(a.as_slice(), base.as_slice());

        let mut ss_x25519 = SS_X25519;
        ss_x25519[0] ^= 1;
        let b =
            combine_shared_secrets(&kdf, LABEL_768, &SS_MLKEM, &ss_x25519, &CIPHERTEXT).unwrap();
        assert_ne!(b.as_slice(), base.as_slice());

        let mut ciphertext = CIPHERTEXT;
        ciphertext[0] ^= 1;
        let c =
            combine_shared_secrets(&kdf, LABEL_768, &SS_MLKEM, &SS_X25519, &ciphertext).unwrap();
        assert_ne!(c.as_slice(), base.as_slice());

        let d =
            combine_shared_secrets(&kdf, LABEL_1024, &SS_MLKEM, &SS_X25519, &CIPHERTEXT).unwrap();
        assert_ne!(d.as_slice(), base.as_slice());
    }

    const KAT_768: &str = include_str!("../../../kat/hybrid/self-consistency-768.kat");
    const KAT_1024: &str = include_str!("../../../kat/hybrid/self-consistency-1024.kat");

    macro_rules! self_consistency_test {
        ($name:ident, $backend:expr, $kat:expr) => {
            #[test]
            fn $name() {
                let records = parse($kat).unwrap();
                let record = &records[0];
                let backend = $backend;

                // keygen reproduces the frozen keypair.
                let entropy = record.field("entropy").unwrap();
                let (ek, dk) = backend.keygen(entropy).unwrap();
                assert_field(record, "encapsulation_key", ek.as_slice());
                assert_field(record, "decapsulation_key", dk.as_slice());

                // encapsulate (fixed RNG) reproduces the frozen ciphertext + secret.
                let mut rng = TestRng::new(0);
                let (ct, ss) = backend.encapsulate(&ek, &mut rng).unwrap();
                assert_field(record, "ciphertext", ct.as_slice());
                assert_field(record, "shared_secret", ss.as_slice());

                // decapsulate recovers that same secret (roundtrip inside the vector).
                let recovered = backend.decapsulate(&dk, &ct).unwrap();
                assert_field(record, "shared_secret", recovered.as_slice());
            }
        };
    }

    self_consistency_test!(self_consistency_768, X25519MlKem768, KAT_768);
    self_consistency_test!(self_consistency_1024, X25519MlKem1024, KAT_1024);

    // encapsulate -> decapsulate recovers the same shared secret, over random
    // keypairs and random encapsulation randomness.
    macro_rules! roundtrip_proptest {
        ($name:ident, $backend:expr) => {
            proptest! {
                #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]
                #[test]
                fn $name(
                    entropy in prop::collection::vec(any::<u8>(), 96),
                    seed in any::<u64>(),
                ) {
                    let backend = $backend;
                    let (ek, dk) = backend.keygen(&entropy).unwrap();
                    let mut rng = TestRng::new(seed);
                    let (ct, ss) = backend.encapsulate(&ek, &mut rng).unwrap();
                    let recovered = backend.decapsulate(&dk, &ct).unwrap();
                    prop_assert_eq!(ss.as_slice(), recovered.as_slice());
                }
            }
        };
    }

    roundtrip_proptest!(hybrid_768_roundtrip, X25519MlKem768);
    roundtrip_proptest!(hybrid_1024_roundtrip, X25519MlKem1024);

    // Corrupting either component of the ciphertext changes the decapsulated
    // secret (binding). Neither corruption errors -- X25519 DH always returns a
    // value and ML-KEM uses implicit rejection -- but the combined secret differs.
    macro_rules! binding_test {
        ($name:ident, $backend:expr) => {
            #[test]
            fn $name() {
                let backend = $backend;
                let entropy = [0x07u8; 96];
                let (ek, dk) = backend.keygen(&entropy).unwrap();
                let mut rng = TestRng::new(0);
                let (ct, ss) = backend.encapsulate(&ek, &mut rng).unwrap();

                // Baseline: the untouched ciphertext recovers the secret.
                let recovered = backend.decapsulate(&dk, &ct).unwrap();
                assert_eq!(recovered.as_slice(), ss.as_slice());

                // Corrupt the X25519 part (the last 32 bytes).
                let mut bytes = ct.as_slice().to_vec();
                let last = bytes.len() - 1;
                bytes[last] ^= 0x01;
                let tampered = Ciphertext::try_from(bytes.as_slice()).unwrap();
                let recovered = backend.decapsulate(&dk, &tampered).unwrap();
                assert_ne!(recovered.as_slice(), ss.as_slice());

                // Corrupt the ML-KEM part (a byte at the front).
                let mut bytes = ct.as_slice().to_vec();
                bytes[0] ^= 0x01;
                let tampered = Ciphertext::try_from(bytes.as_slice()).unwrap();
                let recovered = backend.decapsulate(&dk, &tampered).unwrap();
                assert_ne!(recovered.as_slice(), ss.as_slice());
            }
        };
    }

    binding_test!(hybrid_768_binding, X25519MlKem768);
    binding_test!(hybrid_1024_binding, X25519MlKem1024);
}
