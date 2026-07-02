# Vendored: mlkem-native (formally-verified ML-KEM)

A second, independent ML-KEM reference for the host-only differential test harness, alongside the liboqs (`oqs`) one. mlkem-native's C is machine-checked for correctness and memory-safety, so it is the higher-assurance cross-check for ML-KEM decapsulation.

- **Upstream:** https://github.com/pq-code-package/mlkem-native
- **Version:** `v1.2.0` (commit `0ba906cb14b1c241476134d7403a811b382ca498`)
- **License:** your choice of Apache-2.0 OR ISC OR MIT (see `LICENSE`).

## What is vendored

The upstream **monolithic multi-level** integration pattern (`examples/monolithic_build_multilevel`), so all parameter sets build in one C compilation unit with namespaced symbols (`mlkem768_*`, `mlkem1024_*`):

- `mlkem_native/` -- the source tree (`mlkem_native.c` single compilation unit, `mlkem_native.h` API, config header, and `src/` including the portable C FIPS-202 / SHA-3).
- `mlkem_native_all.c` / `mlkem_native_all.h` -- the upstream multilevel wrappers, which `#include mlkem_native.c` once per security level.
- `randombytes_stub.c` -- a local stub (see below).

`crates/conformance/build.rs` compiles `mlkem_native_all.c` with `cc` (include path `mlkem_native/`); the harness calls four functions -- `mlkem768_keypair_derand` / `mlkem768_dec` and the 1024 pair -- through hand-written `extern "C"` declarations (no `bindgen`, so no `libclang` dependency). Host-only; never part of the firmware build.

## Local additions and omissions

- **C backend only.** The native arithmetic and FIPS-202 assembly backends (`mlkem_native/src/native`, `mlkem_native/src/fips202/native`) are omitted -- the build uses the portable C backend, which gives byte-identical results and needs no per-architecture asm. No upstream `.c`/`.h` file is modified.
- **`randombytes_stub.c`** is ours, not upstream. mlkem-native's randomized keypair/encapsulate reference `randombytes()`; we only ever call the derandomized API, so the stub aborts if invoked rather than returning insecure bytes.

## Updating

Re-copy `mlkem_native/`, `mlkem_native_all.c`, and `mlkem_native_all.h` from `examples/monolithic_build_multilevel` of a newer tag, drop the two `native` asm directories again, and update the version here.
