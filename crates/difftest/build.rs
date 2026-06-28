//! Compiles the vendored Cisco hash-sigs verify subset into a static library that the
//! harness links for an independent LMS/HSS verification reference. Host-only: the
//! firmware build only ever builds the protocol and crypto crates, never this one, so
//! no C reaches the device by construction.

use std::path::Path;

fn main() {
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
