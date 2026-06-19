//! Algorithm identifiers carried on the wire.

/// A COSE algorithm identifier (codepoint), carried opaquely.
///
/// proto only ferries the integer; mapping an id to an algorithm lives in the crypto
/// layer. Encoded on the wire as a bare CBOR integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AlgId(i64);

impl AlgId {
    pub const fn new(id: i64) -> Self {
        Self(id)
    }

    pub const fn get(self) -> i64 {
        self.0
    }
}

impl From<i64> for AlgId {
    fn from(id: i64) -> Self {
        Self::new(id)
    }
}
