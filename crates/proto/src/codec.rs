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
