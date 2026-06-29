//! CBOR codec for koffer-proto: a thin, backend-agnostic layer over the CBOR backend.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use core::convert::Infallible;

/// Encode a value to a CBOR byte vector. Requires the `alloc` feature.
#[cfg(feature = "alloc")]
pub fn encode<T>(value: &T) -> Result<Vec<u8>, minicbor::encode::Error<Infallible>>
where
    T: minicbor::Encode<()>,
{
    minicbor::to_vec(value)
}

/// Decode a value from CBOR bytes.
pub fn decode<'b, T>(bytes: &'b [u8]) -> Result<T, minicbor::decode::Error>
where
    T: minicbor::Decode<'b, ()>,
{
    minicbor::decode(bytes)
}

/// Reads a definite-length CBOR array header and checks it has exactly `len` elements.
///
/// Rejects the indefinite-length form and any other element count, so a decoder cannot
/// silently accept a non-canonical or wrong-shaped array. Used by the fixed-shape types.
pub(crate) fn expect_array(
    d: &mut minicbor::Decoder<'_>,
    len: u64,
    message: &'static str,
) -> Result<(), minicbor::decode::Error> {
    if d.array()? != Some(len) {
        return Err(minicbor::decode::Error::message(message));
    }
    Ok(())
}

/// Reads a definite-length CBOR map header and checks it has exactly `len` entries.
pub(crate) fn expect_map(
    d: &mut minicbor::Decoder<'_>,
    len: u64,
    message: &'static str,
) -> Result<(), minicbor::decode::Error> {
    if d.map()? != Some(len) {
        return Err(minicbor::decode::Error::message(message));
    }
    Ok(())
}

/// Reads a definite-length CBOR map header, returning its entry count.
///
/// For maps whose length is not fixed and the caller loops over the entries, unlike
/// `expect_map`, which pins an exact count. Rejects the indefinite-length form.
pub(crate) fn definite_map(
    d: &mut minicbor::Decoder<'_>,
    message: &'static str,
) -> Result<u64, minicbor::decode::Error> {
    d.map()?
        .ok_or_else(|| minicbor::decode::Error::message(message))
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::{decode, encode};

    #[derive(minicbor::Encode, minicbor::Decode, Debug, PartialEq)]
    struct Sample {
        #[n(0)]
        a: u32,
        #[n(1)]
        b: u32,
    }

    #[test]
    fn round_trip() {
        let value = Sample { a: 7, b: 42 };

        let bytes = encode(&value).expect("encode");
        let decoded: Sample = decode(&bytes).expect("decode");
        assert_eq!(decoded, value);

        // deterministic: re-encoding the same value yields identical bytes
        let bytes2 = encode(&decoded).expect("re-encode");
        assert_eq!(bytes, bytes2);
    }
}
