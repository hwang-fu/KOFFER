//! Key-derivation (KDF) trait and the HKDF backend.
//!
//! A key-derivation function turns one secret -- such as a shared secret from a
//! key exchange -- plus context into one or more uniformly-random keys. HKDF is
//! the "extract-and-expand" KDF built on HMAC: it first compresses the input
//! keying material into a fixed-size pseudorandom key, then expands that into the
//! requested number of output bytes.
//!
//! The backend is generic over the hash `H` -- `Sha256` for the showcase profile,
//! `Sha384` for the CNSA 2.0 profile -- mirroring the LMS backend's `Lms<H>`.
//! `derive` writes into a caller-provided buffer, so it needs no heap and runs on
//! the embedded target.

use core::marker::PhantomData;

use sha2::{Sha256, Sha384};

use crate::error::KdfError;

/// A key-derivation backend: expand a secret plus context into output key bytes.
pub trait Kdf {
    /// Derives `okm.len()` bytes of output keying material into `okm`.
    ///
    /// `salt` is optional non-secret randomness (an empty slice means "no salt"),
    /// `ikm` is the input keying material (the secret), and `info` is a context
    /// label that binds the output to its purpose. Fails only if `okm` is longer
    /// than the KDF can produce.
    fn derive(&self, salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), KdfError>;
}

/// The HKDF backend over hash `H`: `Sha256` (showcase) or `Sha384` (CNSA 2.0).
pub struct Hkdf<H>(PhantomData<H>);

impl<H> Hkdf<H> {
    /// Creates the backend.
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<H> Default for Hkdf<H> {
    fn default() -> Self {
        Self::new()
    }
}

/// Generates a concrete `Kdf` impl for `Hkdf<$hash>`. One impl per hash: the
/// useful `hkdf` bound is sealed, so a single generic impl is not nameable here.
macro_rules! impl_hkdf_backend {
    ($hash:ty) => {
        impl Kdf for Hkdf<$hash> {
            fn derive(
                &self,
                salt: &[u8],
                ikm: &[u8],
                info: &[u8],
                okm: &mut [u8],
            ) -> Result<(), KdfError> {
                // RFC 5869: an empty salt means "no salt" -- HKDF then uses a
                // string of hash-length zero bytes in its place.
                let salt = if salt.is_empty() { None } else { Some(salt) };
                let hkdf = hkdf::Hkdf::<$hash>::new(salt, ikm);
                hkdf.expand(info, okm)
                    .map_err(|_| KdfError::InvalidOutputLength)
            }
        }
    };
}

impl_hkdf_backend!(Sha256);
impl_hkdf_backend!(Sha384);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kat::{assert_field, parse};

    const RFC5869: &str = include_str!("../../../kat/kdf/rfc5869-hkdf-sha256.kat");
    const WYCHEPROOF_384: &str = include_str!("../../../kat/kdf/wycheproof-hkdf-sha384.kat");

    fn check_vectors<K: Kdf>(backend: &K, vectors: &str) {
        let records = parse(vectors).unwrap();
        for record in &records {
            let salt = record.field("salt").unwrap();
            let ikm = record.field("ikm").unwrap();
            let info = record.field("info").unwrap();
            let expected = record.field("okm").unwrap();

            let mut okm = vec![0u8; expected.len()];
            backend.derive(salt, ikm, info, &mut okm).unwrap();
            assert_field(record, "okm", &okm);
        }
    }

    #[test]
    fn rfc5869_hkdf_sha256_vectors() {
        check_vectors(&Hkdf::<Sha256>::new(), RFC5869);
    }

    #[test]
    fn wycheproof_hkdf_sha384_vectors() {
        check_vectors(&Hkdf::<Sha384>::new(), WYCHEPROOF_384);
    }

    #[test]
    fn derive_length_is_a_prefix() {
        // HKDF expands a stream and truncates, so a shorter output is a prefix
        // of a longer one derived from the same inputs.
        let backend = Hkdf::<Sha256>::new();
        let mut short = [0u8; 16];
        let mut long = [0u8; 64];
        backend
            .derive(b"salt", b"ikm", b"info", &mut short)
            .unwrap();
        backend.derive(b"salt", b"ikm", b"info", &mut long).unwrap();
        assert_eq!(&long[..16], &short[..]);
    }

    #[test]
    fn different_info_diverges() {
        let backend = Hkdf::<Sha256>::new();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        backend
            .derive(b"salt", b"ikm", b"context-a", &mut a)
            .unwrap();
        backend
            .derive(b"salt", b"ikm", b"context-b", &mut b)
            .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_salt_diverges() {
        let backend = Hkdf::<Sha256>::new();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        backend.derive(b"salt-a", b"ikm", b"info", &mut a).unwrap();
        backend.derive(b"salt-b", b"ikm", b"info", &mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn exceeds_max_output_length_errors() {
        // HKDF caps output at 255 * hash_len; for SHA-256 that is 255 * 32 bytes.
        let backend = Hkdf::<Sha256>::new();
        let mut okm = vec![0u8; 255 * 32 + 1];
        assert_eq!(
            backend.derive(b"salt", b"ikm", b"info", &mut okm),
            Err(KdfError::InvalidOutputLength)
        );
    }
}
