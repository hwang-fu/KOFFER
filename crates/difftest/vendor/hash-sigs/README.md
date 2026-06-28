# Vendored: Cisco `hash-sigs` (verify subset)

Independent LMS/HSS verifier used as the reference side of the host-only differential test harness. Our own backend wraps the `hbs-lms` crate, which is binary-compatible with this implementation, so this is the natural independent cross-check for LMS/HSS verification.

- **Upstream:** https://github.com/cisco/hash-sigs
- **Commit:** `0335491815c908cad85d6035d43785693a4e91f9`
- **License:** BSD 3-Clause (see `license.txt`). Copyright 2017 Cisco Systems, Inc.

## What is vendored

Only the **verify** path -- the exact source set of the upstream `hss_verify.a` Makefile target -- not keygen or signing:

- 12 `.c` files: `hss_verify.c`, `hss_verify_inc.c`, `hss_common.c`, `hss_thread_single.c`, `hss_zeroize.c`, `lm_common.c`, `lm_ots_common.c`, `lm_ots_verify.c`, `lm_verify.c`, `endian.c`, `hash.c`, `sha256.c`.
- 16 `.h` files: the header closure those sources include (computed with `gcc -MM`).

`crates/difftest/build.rs` compiles these with the `cc` crate; the harness calls a single function, `hss_validate_signature`, through one hand-written `extern "C"` declaration (no `bindgen`, so no `libclang` dependency). The build is host-only and is never part of the firmware build.

## Local modification

One line, in `sha256.h`: `USE_OPENSSL` changed from upstream `1` to `0`, so the bundled portable SHA-256 is used and the build needs no OpenSSL. No other files are modified. Single-threaded operation comes from vendoring `hss_thread_single.c` (not the pthread variant).

## Updating

Re-copy the file set above from a newer upstream commit, re-apply the one-line `sha256.h` change, and update the commit hash here.
