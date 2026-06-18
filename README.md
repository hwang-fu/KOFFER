<div align="center">

# KOFFER

A post-quantum hardware root of trust and security module, written in Rust.

[![CI](https://github.com/hwang-fu/KOFFER/actions/workflows/ci.yml/badge.svg)](https://github.com/hwang-fu/KOFFER/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-1.96-orange.svg)](rust-toolchain.toml)

</div>

## Workspace layout

| Folder | Package | Description |
|--------|---------|-------------|
| `crates/proto` | `koffer-proto` | Shared protocol types, wire formats, and messages (`no_std`). |
| `crates/crypto` | `koffer-crypto` | Post-quantum crypto primitives and agility traits (`no_std`). |

Folder names are short for readability, but each crate's package keeps the `koffer-` prefix so the names stay unambiguous in tooling and publishable. A consumer renames the dependency locally for clean `use` paths:

```toml
proto = { package = "koffer-proto", path = "../proto" }
```

so code reads `use proto::...` instead of `use koffer_proto::...`.

## Building

```sh
cargo build      # host
cargo test       # host tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check

# embedded (Cortex-M33F)
cargo build --target thumbv8m.main-none-eabihf -p koffer-proto -p koffer-crypto
```

The toolchain -- Rust 1.96.0, the `clippy` and `rustfmt` components, and the `thumbv8m.main-none-eabihf` target -- is pinned in `rust-toolchain.toml`, so `rustup` provisions it automatically on the first build.
