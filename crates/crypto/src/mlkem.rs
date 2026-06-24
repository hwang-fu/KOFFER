//! ML-KEM lattice key-encapsulation backend, wrapping the RustCrypto `ml-kem` crate.
//!
//! Specialized to the parameter set `P`: `MlKem768` for the showcase profile,
//! `MlKem1024` for the CNSA 2.0 profile. The decapsulation key is stored as its
//! 64-byte seed; decapsulation is constant-time with FIPS 203 implicit rejection.

use core::marker::PhantomData;

use ml_kem::{Decapsulate as _, Encapsulate as _, KeyExport as _};

use crate::{
    error::KemError,
    kem::{Ciphertext, DecapsulationKey, EncapsulationKey, Kem, SharedSecret},
};

/// The ML-KEM backend over parameter set `P`.
pub struct MlKem<P>(PhantomData<P>);

impl<P> MlKem<P> {
    /// Creates the backend.
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<P> Default for MlKem<P> {
    fn default() -> Self {
        Self::new()
    }
}

// `ml-kem`'s parameter bound (`KemParams`) is private, so a generic `impl` cannot name
// it. We generate a concrete keygen + `Kem` impl per parameter set instead.
macro_rules! impl_backend {
    ($param:ty) => {
        impl MlKem<$param> {
            /// Generates a key pair from `entropy`, which must be at least 64 bytes -- the
            /// ML-KEM seed length. The secret key is returned as that 64-byte seed (the
            /// smallest secret to hold and zeroize); the public key as its FIPS 203 encoding.
            pub fn keygen(
                &self,
                entropy: &[u8],
            ) -> Result<(EncapsulationKey, DecapsulationKey), KemError> {
                let seed_bytes = entropy.get(..64).ok_or(KemError::Internal)?;
                let seed = ml_kem::Seed::try_from(seed_bytes).map_err(|_| KemError::Internal)?;
                let decapsulation_key = ml_kem::DecapsulationKey::<$param>::from_seed(seed);
                let encapsulation_key = decapsulation_key.encapsulation_key();
                Ok((
                    EncapsulationKey::try_from(encapsulation_key.to_bytes().as_slice())
                        .map_err(|_| KemError::Internal)?,
                    DecapsulationKey::try_from(seed_bytes).map_err(|_| KemError::Internal)?,
                ))
            }
        }

        impl Kem for MlKem<$param> {
            fn encapsulate(
                &self,
                key: &EncapsulationKey,
                rng: &mut dyn rand_core::CryptoRng,
            ) -> Result<(Ciphertext, SharedSecret), KemError> {
                let encoded = ml_kem::array::Array::try_from(key.as_slice())
                    .map_err(|_| KemError::MalformedKey)?;
                let encapsulation_key = ml_kem::EncapsulationKey::<$param>::new(&encoded)
                    .map_err(|_| KemError::MalformedKey)?;
                let (ciphertext, shared) = encapsulation_key.encapsulate_with_rng(rng);
                Ok((
                    Ciphertext::try_from(ciphertext.as_slice()).map_err(|_| KemError::Internal)?,
                    SharedSecret::try_from(shared.as_slice()).map_err(|_| KemError::Internal)?,
                ))
            }

            fn decapsulate(
                &self,
                key: &DecapsulationKey,
                ciphertext: &Ciphertext,
            ) -> Result<SharedSecret, KemError> {
                // The decapsulation key is its 64-byte seed; re-derive it each call. ML-KEM
                // decapsulation is constant-time and implicitly rejecting -- a well-formed but
                // invalid ciphertext yields a pseudorandom secret, never an error.
                let seed =
                    ml_kem::Seed::try_from(key.as_slice()).map_err(|_| KemError::MalformedKey)?;
                let decapsulation_key = ml_kem::DecapsulationKey::<$param>::from_seed(seed);
                let shared = decapsulation_key
                    .decapsulate_slice(ciphertext.as_slice())
                    .map_err(|_| KemError::MalformedCiphertext)?;
                SharedSecret::try_from(shared.as_slice()).map_err(|_| KemError::Internal)
            }
        }
    };
}

impl_backend!(ml_kem::MlKem768);
impl_backend!(ml_kem::MlKem1024);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kat::parse;
    use core::convert::Infallible;

    // A deterministic CryptoRng for tests -- enough randomness for encapsulation.
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
                let value = self.try_next_u64()?.to_le_bytes();
                chunk.copy_from_slice(&value[..chunk.len()]);
            }
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for TestRng {}

    // The backend impls are concrete per parameter set (private `KemParams`), so a generic
    // test helper cannot call `keygen`; generate the tests per parameter set instead.
    macro_rules! backend_tests {
        ($param:ty, $round_trip:ident, $implicit_rejection:ident) => {
            #[test]
            fn $round_trip() {
                let backend = MlKem::<$param>::new();
                let (ek, dk) = backend.keygen(&[0x42u8; 64]).unwrap();
                let (ciphertext, sent) = backend.encapsulate(&ek, &mut TestRng(1)).unwrap();
                let recovered = backend.decapsulate(&dk, &ciphertext).unwrap();
                assert_eq!(sent.as_slice(), recovered.as_slice());
            }

            #[test]
            fn $implicit_rejection() {
                let backend = MlKem::<$param>::new();
                let (ek, dk) = backend.keygen(&[0x42u8; 64]).unwrap();
                let (ciphertext, sent) = backend.encapsulate(&ek, &mut TestRng(1)).unwrap();

                // Flip a byte well inside the ciphertext -- still the right length.
                let mut bytes = ciphertext.as_slice().to_vec();
                let mid = bytes.len() / 2;
                bytes[mid] ^= 0x01;
                let tampered = Ciphertext::try_from(bytes.as_slice()).unwrap();

                // Implicit rejection: no error, a pseudorandom secret distinct from the real
                // one, and deterministic (same tampered ciphertext -> same secret).
                let rejected = backend.decapsulate(&dk, &tampered).unwrap();
                assert_ne!(rejected.as_slice(), sent.as_slice());
                assert_eq!(
                    rejected.as_slice(),
                    backend.decapsulate(&dk, &tampered).unwrap().as_slice()
                );
            }
        };
    }

    backend_tests!(
        ml_kem::MlKem768,
        mlkem768_round_trips,
        mlkem768_implicit_rejection
    );
    backend_tests!(
        ml_kem::MlKem1024,
        mlkem1024_round_trips,
        mlkem1024_implicit_rejection
    );

    // keyGen (seed -> public key) and decapsulation (seed + ciphertext -> shared secret),
    // replayed against the Wycheproof vectors.
    macro_rules! kat_tests {
        ($param:ty, $name:ident, $vectors:expr) => {
            #[test]
            fn $name() {
                let backend = MlKem::<$param>::new();
                let records = parse($vectors).unwrap();
                assert!(!records.is_empty());
                for r in &records {
                    let (ek, dk) = backend.keygen(r.field("seed").unwrap()).unwrap();
                    assert_eq!(ek.as_slice(), r.field("public_key").unwrap());
                    let ct = Ciphertext::try_from(r.field("ciphertext").unwrap()).unwrap();
                    let shared = backend.decapsulate(&dk, &ct).unwrap();
                    assert_eq!(shared.as_slice(), r.field("shared_secret").unwrap());
                }
            }
        };
    }

    kat_tests!(
        ml_kem::MlKem768,
        mlkem768_wycheproof_kat,
        include_str!("../../../kat/mlkem/wycheproof-768.kat")
    );
    kat_tests!(
        ml_kem::MlKem1024,
        mlkem1024_wycheproof_kat,
        include_str!("../../../kat/mlkem/wycheproof-1024.kat")
    );
}
