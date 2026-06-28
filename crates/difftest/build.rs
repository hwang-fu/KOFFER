//! Compiles the vendored C reference libraries into static libs the harness links: Cisco
//! hash-sigs (LMS/HSS verify) and mlkem-native (formally-verified ML-KEM). Host-only: the
//! firmware build only ever builds the protocol and crypto crates, never this one, so no C
//! reaches the device by construction.

use std::path::Path;

fn main() {
    build_hash_sigs();
    build_mlkem_native();
}

fn build_hash_sigs() {
    let dir = Path::new("vendor/hash-sigs");

    // The upstream `hss_verify.a` object set -- the verify path only, no keygen or sign.
    let sources = [
        "hss_verify.c",
        "hss_verify_inc.c",
        "hss_common.c",
        "hss_thread_single.c",
        "hss_zeroize.c",
        "lm_common.c",
        "lm_ots_common.c",
        "lm_ots_verify.c",
        "lm_verify.c",
        "endian.c",
        "hash.c",
        "sha256.c",
    ];

    let mut build = cc::Build::new();
    // Third-party C: do not police its warnings with our build.
    build.include(dir).warnings(false);
    for source in sources {
        build.file(dir.join(source));
    }
    build.compile("hash_sigs_verify");

    println!("cargo:rerun-if-changed=vendor/hash-sigs");
}

fn build_mlkem_native() {
    let dir = Path::new("vendor/mlkem-native");

    // The monolithic multilevel unit (`mlkem_native_all.c` includes `mlkem_native.c` once
    // per level) builds all parameter sets with namespaced symbols (`mlkem768_*`,
    // `mlkem1024_*`), portable C backend. The stub satisfies the randombytes() symbol that
    // the randomized API references but the harness never calls.
    cc::Build::new()
        .include(dir.join("mlkem_native"))
        .warnings(false)
        .file(dir.join("mlkem_native_all.c"))
        .file(dir.join("randombytes_stub.c"))
        .compile("mlkem_native_multilevel");

    println!("cargo:rerun-if-changed=vendor/mlkem-native");
}
