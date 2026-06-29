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
