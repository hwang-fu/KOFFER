//! CBOR codec for koffer-proto: a thin, backend-agnostic layer over the CBOR backend.

pub use minicbor::decode::Error as DecodeError;
pub use minicbor::encode::{Error as EncodeError, Write};
pub use minicbor::{Decode, Decoder, Encode, Encoder};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use core::convert::Infallible;

/// Encode a value to a CBOR byte vector. Requires the `alloc` feature.
#[cfg(feature = "alloc")]
pub fn encode<T>(value: &T) -> Result<Vec<u8>, EncodeError<Infallible>>
where
    T: Encode<()>,
{
    minicbor::to_vec(value)
}

/// Decode a value from CBOR bytes.
pub fn decode<'b, T>(bytes: &'b [u8]) -> Result<T, DecodeError>
where
    T: Decode<'b, ()>,
{
    minicbor::decode(bytes)
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::{Decode, Encode, decode, encode};

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

        let bytes = encode(&value).expect("encode");
        let decoded: Sample = decode(&bytes).expect("decode");
        assert_eq!(decoded, value);

        // deterministic: re-encoding the same value yields identical bytes
        let bytes2 = encode(&decoded).expect("re-encode");
        assert_eq!(bytes, bytes2);
    }
}
