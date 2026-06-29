//! Test-only helpers shared across the KOFFER crates' tests.
//!
//! This crate is a dev-dependency only -- it never enters a normal or release build's
//! dependency graph, so nothing here can reach the firmware or any crate's public API.

#![no_std]

use core::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};

/// A deterministic counter-based RNG, for reproducible tests.
///
/// It is **not** cryptographically secure -- it simply returns an incrementing counter.
/// Use it only to make test runs reproducible; never for real key material.
pub struct TestRng(u64);

impl TestRng {
    /// Creates a counter RNG seeded at `seed`; successive draws return `seed + 1`,
    /// `seed + 2`, and so on.
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }
}

impl TryRng for TestRng {
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

impl TryCryptoRng for TestRng {}
