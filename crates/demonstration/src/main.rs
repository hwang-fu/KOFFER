//! Runnable demonstration: runs the end-to-end sign/verify + seal/unseal flow in both crypto
//! profiles and prints a readable trace. It uses a fixed-seed deterministic RNG, so the run
//! is reproducible and pulls in no operating-system entropy source.

use core::convert::Infallible;
use std::process::ExitCode;

use koffer_cryptography::profile::CryptoProfile;
use koffer_demonstration::run::{RunReport, run};

// Deterministic counter RNG. A demonstration does not need real entropy; a fixed seed keeps
// the run reproducible. Kept local to the binary, not exposed in the library's public API.
struct DemoRng(u64);
impl rand_core::TryRng for DemoRng {
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
impl rand_core::TryCryptoRng for DemoRng {}

fn main() -> ExitCode {
    println!("KOFFER end-to-end demo\n");

    let mut all_ok = true;
    for profile in [CryptoProfile::Showcase, CryptoProfile::Cnsa20] {
        let report = run(profile, &mut DemoRng(1));
        print_report(&report);
        all_ok &= report.ok();
    }

    println!("all profiles: {}", pass(all_ok));
    if all_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn print_report(report: &RunReport) {
    let p = report.profile;
    println!(
        "== {:?}: sig {:?}, kem {:?}, aead {:?}, kdf {:?} ==",
        p,
        p.general_sig(),
        p.hybrid_kem(),
        p.aead(),
        p.kdf(),
    );
    println!(
        "  {:<28}: {} bytes",
        "sign manifest -> COSE_Sign1", report.signed_len
    );
    println!("  {:<28}: {}", "verify", pass(report.verified));
    println!(
        "  {:<28}: {} bytes",
        "seal payload -> COSE_Encrypt", report.sealed_len
    );
    println!("  {:<28}: {}", "unseal", pass(report.unsealed));
    println!("  {:<28}: {}", "result", pass(report.ok()));
    println!();
}

fn pass(ok: bool) -> &'static str {
    if ok { "OK" } else { "FAIL" }
}
