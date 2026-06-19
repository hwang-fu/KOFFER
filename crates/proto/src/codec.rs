//! CBOR codec for koffer-proto: a thin, backend-agnostic layer over the CBOR backend.

pub use minicbor::{Decode, Encode};

/// Encode a value to a CBOR byte vector. Requires the `alloc` feature.
#[cfg(feature = "alloc")]
pub fn to_cbor<T>(
    value: &T,
) -> Result<alloc::vec::Vec<u8>, minicbor::encode::Error<core::convert::Infallible>>
where
    T: Encode<()>,
{
    minicbor::to_vec(value)
}

/// Decode a value from CBOR bytes.
pub fn from_cbor<'b, T>(bytes: &'b [u8]) -> Result<T, minicbor::decode::Error>
where
    T: Decode<'b, ()>,
{
    minicbor::decode(bytes)
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::{Decode, Encode, from_cbor, to_cbor};

    #[derive(Encode, Decode, Debug, PartialEq)]
    struct Sample {
        #[n(0)]
        a: u32,
        #[n(1)]
        b: u32,
    }

    #[test]
    fn round_trip() {
        let value = Sample { a: 7, b: 42 };

        let bytes = to_cbor(&value).expect("encode");
        let decoded: Sample = from_cbor(&bytes).expect("decode");
        assert_eq!(decoded, value);

        // deterministic: re-encoding the same value yields identical bytes
        let bytes2 = to_cbor(&decoded).expect("re-encode");
        assert_eq!(bytes, bytes2);
    }
}
