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

use x25519_dalek::{PublicKey, StaticSecret};

/// Derives an X25519 keypair from 32 bytes of entropy, returning (secret, public).
pub(crate) fn keypair_from_entropy(entropy: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::from(*entropy);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

/// X25519 Diffie-Hellman: combines our `secret` with a `peer_public` key to reach
/// the shared secret both sides agree on.
pub(crate) fn dh(secret: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*secret);
    let peer = PublicKey::from(*peer_public);
    secret.diffie_hellman(&peer).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_parties_agree() {
        let (a_secret, a_public) = keypair_from_entropy(&[0x11; 32]);
        let (b_secret, b_public) = keypair_from_entropy(&[0x22; 32]);
        // Each side combines its own secret with the peer's public key.
        assert_eq!(dh(&a_secret, &b_public), dh(&b_secret, &a_public));
    }

    #[test]
    fn distinct_entropy_yields_distinct_keys() {
        let (_, a_public) = keypair_from_entropy(&[0x11; 32]);
        let (_, b_public) = keypair_from_entropy(&[0x22; 32]);
        assert_ne!(a_public, b_public);
    }
}
