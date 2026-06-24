//! Hybrid KEM: X25519 + ML-KEM, combined into one shared secret.
//!
//! The hybrid runs both component key-exchanges and binds their two shared secrets
//! into a single one, so the result stays secure if *either* X25519 or ML-KEM is
//! broken. The binding is a dual-PRF HKDF combiner: one shared secret is the HKDF
//! salt and the other the input keying material (so HMAC's dual-PRF property gives
//! security if either is random), and the full transcript -- the hybrid ciphertext
//! -- goes into `info`, tying the combined secret to this exact exchange.

use zeroize::Zeroize;

use crate::error::KemError;
use crate::kdf::Kdf;
use crate::kem::SharedSecret;

// Domain-separation labels, one per variant, so a combined secret is bound to its
// algorithm and cannot be confused with any other HKDF output.
const LABEL_768: &[u8] = b"hybrid-x25519-mlkem768-v1";
const LABEL_1024: &[u8] = b"hybrid-x25519-mlkem1024-v1";

// Upper bound on the `info` buffer: the longest label plus the largest hybrid
// ciphertext (ML-KEM-1024 ciphertext 1568 + the 32-byte X25519 ephemeral key).
const INFO_MAX: usize = 26 + 1568 + 32;

/// Combines the two component shared secrets into one, binding the transcript.
///
/// `ss_x25519` is the HKDF salt and `ss_mlkem` the IKM (the dual-PRF that makes the
/// result secure if either component is); `label || ciphertext` is the `info`.
fn combine<K: Kdf>(
    kdf: &K,
    label: &[u8],
    ss_mlkem: &[u8],
    ss_x25519: &[u8],
    ciphertext: &[u8],
) -> Result<SharedSecret, KemError> {
    // info = label || the full hybrid ciphertext (ml-kem ct || x25519 ephemeral key).
    let mut info = [0u8; INFO_MAX];
    let len = label.len() + ciphertext.len();
    let info = info.get_mut(..len).ok_or(KemError::Internal)?;
    info[..label.len()].copy_from_slice(label);
    info[label.len()..].copy_from_slice(ciphertext);

    let mut okm = [0u8; 32];
    kdf.derive(ss_x25519, ss_mlkem, info, &mut okm)
        .map_err(|_| KemError::Internal)?;
    let combined = SharedSecret::try_from(&okm[..]).map_err(|_| KemError::Internal);
    okm.zeroize();
    combined
}

// Stack-buffer capacity for assembling a concatenated value: the biggest hybrid
// key or ciphertext (the ML-KEM-1024 part plus the 32-byte X25519 part).
const JOIN_MAX: usize = 1600;

/// Splits hybrid bytes into the ML-KEM part (all but the last 32 bytes) and the
/// 32-byte X25519 part. `None` if there are fewer than 32 bytes.
fn split_last_32(bytes: &[u8]) -> Option<(&[u8], [u8; 32])> {
    let n = bytes.len().checked_sub(32)?;
    let tail: [u8; 32] = bytes[n..].try_into().ok()?;
    Some((&bytes[..n], tail))
}

/// Concatenates `head || tail` into `buf`, returning the filled slice (or
/// `Internal` if the buffer is too small).
fn join<'b>(buf: &'b mut [u8], head: &[u8], tail: &[u8; 32]) -> Result<&'b [u8], KemError> {
    let n = head.len() + tail.len();
    {
        let out = buf.get_mut(..n).ok_or(KemError::Internal)?;
        out[..head.len()].copy_from_slice(head);
        out[head.len()..].copy_from_slice(tail);
    }
    Ok(&buf[..n])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::Hkdf;
    use sha2::Sha256;

    const SS_MLKEM: [u8; 32] = [0x01; 32];
    const SS_X25519: [u8; 32] = [0x02; 32];
    const CIPHERTEXT: [u8; 64] = [0x03; 64];

    #[test]
    fn combine_is_deterministic() {
        let kdf = Hkdf::<Sha256>::new();
        let a = combine(&kdf, LABEL_768, &SS_MLKEM, &SS_X25519, &CIPHERTEXT).unwrap();
        let b = combine(&kdf, LABEL_768, &SS_MLKEM, &SS_X25519, &CIPHERTEXT).unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn combine_binds_every_input() {
        let kdf = Hkdf::<Sha256>::new();
        let base = combine(&kdf, LABEL_768, &SS_MLKEM, &SS_X25519, &CIPHERTEXT).unwrap();

        // Each input -- both secrets, the transcript, and the label -- changes the output.
        let mut ss_mlkem = SS_MLKEM;
        ss_mlkem[0] ^= 1;
        let a = combine(&kdf, LABEL_768, &ss_mlkem, &SS_X25519, &CIPHERTEXT).unwrap();
        assert_ne!(a.as_slice(), base.as_slice());

        let mut ss_x25519 = SS_X25519;
        ss_x25519[0] ^= 1;
        let b = combine(&kdf, LABEL_768, &SS_MLKEM, &ss_x25519, &CIPHERTEXT).unwrap();
        assert_ne!(b.as_slice(), base.as_slice());

        let mut ciphertext = CIPHERTEXT;
        ciphertext[0] ^= 1;
        let c = combine(&kdf, LABEL_768, &SS_MLKEM, &SS_X25519, &ciphertext).unwrap();
        assert_ne!(c.as_slice(), base.as_slice());

        let d = combine(&kdf, LABEL_1024, &SS_MLKEM, &SS_X25519, &CIPHERTEXT).unwrap();
        assert_ne!(d.as_slice(), base.as_slice());
    }
}
