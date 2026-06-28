//! Host-only differential test harness for the KOFFER crypto backend.
//!
//! Runs the production `koffer-crypto` backend and an independent reference
//! implementation over the same inputs (the frozen `kat/` vectors plus
//! randomized `proptest` cases) and asserts the two agree. This guards against
//! a defect that the wrapped upstream crates and our own tests might share.
//!
//! This crate is host-only and is never part of the firmware build: the
//! embedded target builds only the protocol and crypto crates, so this harness
//! and its (potentially C-backed) reference libraries are excluded by
//! construction.
