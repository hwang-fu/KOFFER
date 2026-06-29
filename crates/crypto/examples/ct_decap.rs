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
//!
//! Two benches run. `ct_decap` measures real decapsulation and should report a small t (no
//! leak). `leak_canary` is a deliberately secret-dependent function and must report a large
//! t. The canary proves the harness can actually detect a leak, so a small `ct_decap` t is
//! meaningful rather than just "the detector never fires."

use core::convert::Infallible;

use dudect_bencher::{BenchRng, Class, CtRunner, ctbench_main, rand::RngExt};
use koffer_crypto::{
    kem::{Ciphertext, Kem},
    mlkem::MlKem,
};
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

// The negative meta-test ("leak canary"). NOT real crypto: a deliberately secret-dependent
// function whose timing depends on a secret byte, so dudect must flag it with a large t. It
// validates the detector -- without it, a harness that never fires would look identical to a
// clean constant-time result.
fn leak_canary(runner: &mut CtRunner, rng: &mut BenchRng) {
    for _ in 0..SAMPLES {
        // Left: secret 0 -> fast path. Right: a random nonzero secret -> slow, secret-
        // dependent path. The systematic gap between the two classes is the injected leak.
        let (class, secret) = if rng.random::<bool>() {
            (Class::Left, 0u8)
        } else {
            (Class::Right, rng.random::<u8>() | 1)
        };
        runner.run_one(class, || leaky_branch(secret));
    }
}

// The branch on the secret. The slow path does clearly more work, so the timing gap
// dominates measurement noise and the reported t is large on any machine.
fn leaky_branch(secret: u8) -> u64 {
    let mut acc = 0u64;
    if secret != 0 {
        for i in 0..4096u64 {
            acc = acc.wrapping_add(core::hint::black_box(i));
        }
    }
    core::hint::black_box(acc)
}

ctbench_main!(ct_decap, leak_canary);
