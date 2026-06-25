//! SUIT-aligned firmware/update manifest.
//!
//! The signed "packing slip" for an update: it binds the (possibly encrypted)
//! payload by digest plus metadata, and is itself signed via `COSE_Sign1` (detached
//! by default -- the image ships unchanged, referenced by its digest). This is a
//! flat local profile of the IETF SUIT manifest model: the descriptive and binding
//! fields, without the SUIT command-sequence machinery.
//!
//! proto frames and parses the bytes; hashing the image and checking the signature
//! are the crypto / verifier layer's job.
