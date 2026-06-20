//! Known-answer-test (KAT) harness: load published test vectors and check a
//! backend's output against them. Test-only; the real vectors and the per-backend
//! wiring arrive with each scheme.

use std::collections::BTreeMap;

/// One test vector: a set of named byte fields (`pk`, `msg`, `sig`, `ek`, `ct`, ...).
pub(crate) struct KatRecord {
    fields: BTreeMap<String, Vec<u8>>,
}

impl KatRecord {
    /// Returns the bytes of field `name`, or an error if the record has no such field.
    pub(crate) fn field(&self, name: &str) -> Result<&[u8], KatError> {
        self.fields
            .get(name)
            .map(Vec::as_slice)
            .ok_or_else(|| KatError::MissingField(name.to_string()))
    }
}

/// A failure while loading or reading a KAT vector.
#[derive(Debug)]
pub(crate) enum KatError {
    /// A line was not of the form `name = hexvalue`.
    MalformedLine(String),
    /// A field's value was not valid hex.
    BadHex(String),
    /// A record was missing a field the test asked for.
    MissingField(String),
}
