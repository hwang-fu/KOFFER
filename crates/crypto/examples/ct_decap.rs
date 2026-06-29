//! dudect-style constant-time timing harness for ML-KEM decapsulation.
//! Best-effort empirical evidence that decapsulation does not leak through timing, within
//! the measured budget -- not a proof. Run with:
//!   cargo run -p koffer-crypto --release --example ct_decap
//!
//! Method: dudect's fixed-vs-random t-test. The secret decapsulation key is fixed. The
//! `Left` class decapsulates one fixed VALID ciphertext (the real-secret path); the `Right`
//! class decapsulates random ciphertexts of the correct length -- well-formed but invalid,
//! so decapsulation takes the FIPS 203 implicit-rejection path. If the valid path and the
//! rejection path differ in timing, dudect flags it.

use core::convert::Infallible;

use dudect_bencher::rand::RngExt;
use dudect_bencher::{BenchRng, Class, CtRunner, ctbench_main};
use koffer_crypto::kem::{Ciphertext, Kem};
use koffer_crypto::mlkem::MlKem;
use ml_kem::MlKem768;

// Measurements built per harness run. dudect accumulates statistics across runs; tune this
// down if the up-front input set uses too much memory.
const SAMPLES: usize = 100_000;

// A deterministic rand_core 0.10 RNG, used only for the one-off prep encapsulation that
// builds the fixed valid ciphertext. The harness's own `BenchRng` is a different rand_core
// version, so it cannot drive `koffer-crypto`'s `encapsulate`.
struct PrepRng(u64);
impl rand_core::TryRng for PrepRng {
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
impl rand_core::TryCryptoRng for PrepRng {}

fn ct_decap(runner: &mut CtRunner, rng: &mut BenchRng) {
    let backend = MlKem::<MlKem768>::new();

    // Fixed secret key, and one fixed valid ciphertext for the Left class.
    let (ek, dk) = backend.keygen(&[0x42u8; 64]).expect("ML-KEM keygen");
    let (valid, _) = backend
        .encapsulate(&ek, &mut PrepRng(1))
        .expect("ML-KEM encapsulate");
    let valid_bytes = valid.as_slice().to_vec();
    let ct_len = valid_bytes.len();

    // Build all inputs up front, outside the timed region: Left repeats the fixed valid
    // ciphertext; Right is a fresh random ciphertext of the same length.
    let mut inputs: Vec<(Class, Ciphertext)> = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        if rng.random::<bool>() {
            let ct = Ciphertext::try_from(valid_bytes.as_slice()).expect("ciphertext length");
            inputs.push((Class::Left, ct));
        } else {
            let mut bytes = vec![0u8; ct_len];
            rng.fill(&mut bytes[..]);
            let ct = Ciphertext::try_from(bytes.as_slice()).expect("ciphertext length");
            inputs.push((Class::Right, ct));
        }
    }

    // Time only decapsulation. black_box keeps it from being optimized away.
    for (class, ct) in inputs {
        runner.run_one(class, || {
            core::hint::black_box(backend.decapsulate(&dk, &ct))
        });
    }
}

ctbench_main!(ct_decap);
