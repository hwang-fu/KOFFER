//! COSE structures (RFC 9052): the `COSE_Sign1` signed-message envelope and the
//! canonical `Sig_structure` (the exact to-be-signed bytes).
//!
//! proto builds and parses the bytes and ferries the algorithm codepoint; the
//! actual signing and verifying live in the crypto layer, wired by a consumer.
