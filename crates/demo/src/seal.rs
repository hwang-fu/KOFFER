//! Seal a payload with the KEM+DEM core and frame it as a `COSE_Encrypt`, then open it,
//! with the backends selected by the integer COSE codepoint.
//!
//! `crypto::seal`/`unseal` are generic free functions, so -- unlike the signer -- the demo
//! cannot hand them a boxed backend. The dispatch helpers below `match` the profile (seal
//! side) or the wire codepoint (open side) and call `seal::<concrete>` inside each arm; the
//! flow itself never names a scheme. The KDF is not carried on the wire -- it is pinned to
//! the KEM level (which identifies the profile), so the open side derives it from the KEM
//! codepoint. The KEM is the hybrid X25519 + ML-KEM; the AEAD is AES-256-GCM.
