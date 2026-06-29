# benches

Benchmark harnesses and scaling sweeps (criterion and scripted runs).

## Constant-time measurement (dudect)

`crates/crypto/examples/ct_decap.rs` is a timing-leakage harness for ML-KEM decapsulation, using the dudect method (a statistical test that checks whether an operation's running time depends on secret data). Run it with:

```sh
cargo run -p koffer-crypto --release --example ct_decap
```

It prints two benches. `ct_decap` measures real decapsulation and should report a small t-value (no timing leak). `leak_canary` is a deliberately secret-dependent function that must report a large t-value, which proves the detector actually fires. The result is best-effort empirical evidence within the measured budget, not a proof: timing is noisy, so run it on a quiet machine and do not read a single spike as a verdict.
