<div align="center">

# KOFFER

A post-quantum hardware root of trust and security module, written in Rust.

[![CI](https://github.com/hwang-fu/KOFFER/actions/workflows/ci.yml/badge.svg)](https://github.com/hwang-fu/KOFFER/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-1.96-orange.svg)](rust-toolchain.toml)

</div>

## The name

**KOFFER** is German for "case" -- the secure case you carry your root of trust in, sized for a portable hardware token. The letters spell its pillars:

- **K**eystore
- **O**ne-time-safe
- **F**irmware-signing
- **F**orward-secret
- **E**ndorsement
- **R**oot

## Workspace layout

| Folder | Package | Description |
|--------|---------|-------------|
| `crates/common` | `koffer-common` | Shared foundation primitives reused across crates (`no_std`). |
| `crates/wire` | `koffer-wire` | Shared protocol types, wire formats, and messages (`no_std`). |
| `crates/cryptography` | `koffer-cryptography` | Post-quantum crypto primitives and agility traits (`no_std`). |

Folder names are short for readability; each crate's package keeps the `koffer-` prefix so the names stay unambiguous in tooling and publishable. A consumer depends on a crate by its package name and imports it under that same name:

```toml
koffer-wire = { path = "../wire" }
```

so code reads `use koffer_wire::...`.

## Building

```sh
cargo build      # host
cargo test       # host tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check

# embedded (Cortex-M33F)
cargo build --target thumbv8m.main-none-eabihf -p koffer-common -p koffer-wire -p koffer-cryptography
```

The toolchain -- Rust 1.96.0, the `clippy` and `rustfmt` components, and the `thumbv8m.main-none-eabihf` target -- is pinned in `rust-toolchain.toml`, so `rustup` provisions it automatically on the first build.

## Demo

Run the full sign/verify and seal/open flow in software, in both crypto profiles:

```sh
cargo run -p koffer-demonstration
```

See [docs/demo.md](docs/demo.md) for a step-by-step walkthrough.

## Editor setup

`rust-analyzer` is an editor tool rather than a build component, so it is deliberately not pinned in `rust-toolchain.toml`. If your editor runs the `rustup`-proxied `rust-analyzer`, the pin makes it resolve against `1.96.0`, which does not ship the component, so the language server fails to start in this repo. Add it to the pinned toolchain once, **from inside the repo** so the toolchain override targets the right version:

```sh
rustup component add rust-analyzer
```
