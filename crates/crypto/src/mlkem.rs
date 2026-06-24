//! ML-KEM lattice key-encapsulation backend, wrapping the RustCrypto `ml-kem` crate.
//!
//! Specialized to the parameter set `P`: `MlKem768` for the showcase profile,
//! `MlKem1024` for the CNSA 2.0 profile. The decapsulation key is stored as its
//! 64-byte seed; decapsulation is constant-time with FIPS 203 implicit rejection.

use core::marker::PhantomData;

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
