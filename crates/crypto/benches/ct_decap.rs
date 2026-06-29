//! dudect-style constant-time timing harness for ML-KEM decapsulation.
//!
//! Best-effort empirical evidence that the secret-dependent path does not leak through
//! timing, within the measured budget -- not a proof. Run with:
//!   cargo bench -p koffer-crypto --bench ct_decap
//!
//! This scaffold only proves the harness is wired; the real decapsulation measurement and
//! the leak meta-test arrive in the following chunks.

use dudect_bencher::{BenchRng, Class, CtRunner, ctbench_main};

fn ct_decap(runner: &mut CtRunner, _rng: &mut BenchRng) {
    // Placeholder: two classes timing an identical no-op, so the harness runs end to end
    // and reports no leak. Real fixed-vs-random decapsulation inputs come next.
    for i in 0..10_000u32 {
        let class = if i % 2 == 0 {
            Class::Left
        } else {
            Class::Right
        };
        runner.run_one(class, || core::hint::black_box(i));
    }
}

ctbench_main!(ct_decap);
