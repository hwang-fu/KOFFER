//! X25519 Diffie-Hellman key agreement, wrapping `x25519-dalek`.
//!
//! "X25519" is Diffie-Hellman on Curve25519: each side holds a 32-byte secret and
//! a 32-byte public key, and one side combines its secret with the other's public
//! key to reach the same 32-byte shared secret. This is an internal helper for the
//! hybrid KEM and is deliberately never exposed as a standalone key-exchange --
//! X25519 alone is classical, not post-quantum.
//!
//! Secrets are built from caller-supplied entropy via `StaticSecret::from`, so this
//! module never uses `x25519-dalek`'s own RNG (which is a different `rand_core`
//! major); the hybrid supplies the random bytes.
