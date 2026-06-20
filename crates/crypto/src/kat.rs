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

/// Decodes a hex string to bytes; errors on an odd length or a non-hex digit.
fn decode_hex(s: &str) -> Result<Vec<u8>, KatError> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }

    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(KatError::BadHex(s.to_string()));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = nibble(pair[0]).ok_or_else(|| KatError::BadHex(s.to_string()))?;
        let lo = nibble(pair[1]).ok_or_else(|| KatError::BadHex(s.to_string()))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// Parses the line-based KAT format: one `name = hexvalue` per line, blank lines
/// separating records, `#` comment lines ignored. Every value is hex.
pub(crate) fn parse(input: &str) -> Result<Vec<KatRecord>, KatError> {
    let mut records = Vec::new();
    let mut current = BTreeMap::new();

    for raw in input.lines() {
        let line = raw.trim();
        if line.starts_with('#') {
            continue;
        }
        if line.is_empty() {
            if !current.is_empty() {
                records.push(KatRecord {
                    fields: std::mem::take(&mut current),
                });
            }
            continue;
        }
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| KatError::MalformedLine(line.to_string()))?;
        current.insert(name.trim().to_string(), decode_hex(value.trim())?);
    }
    if !current.is_empty() {
        records.push(KatRecord { fields: current });
    }
    Ok(records)
}

/// Asserts that `actual` matches the record's `name` field, panicking with a
/// message naming the field on mismatch or if the field is absent. For KAT tests.
pub(crate) fn assert_field(record: &KatRecord, name: &str, actual: &[u8]) {
    let expected = record
        .field(name)
        .unwrap_or_else(|e| panic!("KAT field `{name}`: {e:?}"));
    assert_eq!(actual, expected, "KAT field `{name}` does not match");
}
