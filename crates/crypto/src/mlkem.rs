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
