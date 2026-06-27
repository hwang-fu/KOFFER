//! Host<->device request/response messages (the USB-CDC protocol payloads).
//!
//! Each message encodes as a flat CBOR array led by an integer tag: `[tag, ...fields]`.
//! `Request` (host -> device) and `Response` (device -> host) are separate enums with
//! separate tag spaces; the body bytes travel inside a frame (see the `frame` module).
//! Text fields are printable-ASCII (F15); byte fields borrow the input, zero-copy, like
//! the COSE and manifest types.

use crate::{
    alg::AlgId,
    ascii::AsciiStr,
    codec::{Decode, DecodeError, Decoder, Encode, EncodeError, Encoder, Write},
    cose::CoseSign1,
    error::ErrorCode,
    manifest::{Manifest, SuitDigest},
};

// Request tags (host -> device).
const REQ_HANDSHAKE: u8 = 1;
const REQ_GET_INFO: u8 = 2;
const REQ_INIT_KEYS: u8 = 3;
const REQ_SIGN: u8 = 4;
const REQ_INSTALL_IMAGE: u8 = 5;
const REQ_ATTEST: u8 = 6;

// Response tags (device -> host).
const RESP_INFO: u8 = 1;
const RESP_PUBLIC_KEYS: u8 = 2;
const RESP_COSE_SIGN1: u8 = 3;
const RESP_BOOT_DECISION: u8 = 4;
const RESP_ATTESTATION: u8 = 5;
const RESP_ERROR: u8 = 6;

/// Maximum number of algorithm identifiers carried in an `Info` list.
pub const MAX_ALGS: usize = 8;

/// A bounded, heap-free list of algorithm identifiers.
pub type AlgList = heapless::Vec<AlgId, MAX_ALGS>;

/// A request from host to device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request<'b> {
    /// Channel-setup handshake message (placeholder; the secure-channel handshake
    /// logic is implemented later).
    Handshake { payload: &'b [u8] },
    /// Report device capabilities (`-> Response::Info`).
    GetInfo,
    /// Generate the signing and KEM key pairs (`-> Response::PublicKeys`).
    InitKeys { sig_alg: AlgId, kem_alg: AlgId },
    /// Sign a digest with the given algorithm (`-> Response::CoseSign1`).
    Sign {
        /// Signature algorithm to use.
        alg: AlgId,
        /// The digest to sign.
        digest: SuitDigest<'b>,
        /// Human-readable summary shown on the device display for consent.
        summary: AsciiStr<'b>,
    },
    /// Install an encrypted firmware image (`-> Response::BootDecision`).
    InstallEncryptedImage {
        /// KEM algorithm of the wrapped content key.
        kem_alg: AlgId,
        /// The AEAD-encrypted image.
        ciphertext: &'b [u8],
        /// The signed manifest binding the image.
        manifest: Manifest<'b>,
    },
    /// Request a signed attestation over a challenge nonce (`-> Response::Attestation`).
    Attest { nonce: &'b [u8] },
}

impl<C> Encode<C> for Request<'_> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), EncodeError<W::Error>> {
        match self {
            Request::Handshake { payload } => {
                e.array(2)?.u8(REQ_HANDSHAKE)?;
                e.bytes(payload)?;
            }
            Request::GetInfo => {
                e.array(1)?.u8(REQ_GET_INFO)?;
            }
            Request::InitKeys { sig_alg, kem_alg } => {
                e.array(3)?.u8(REQ_INIT_KEYS)?;
                sig_alg.encode(e, ctx)?;
                kem_alg.encode(e, ctx)?;
            }
            Request::Sign {
                alg,
                digest,
                summary,
            } => {
                e.array(4)?.u8(REQ_SIGN)?;
                alg.encode(e, ctx)?;
                digest.encode(e, ctx)?;
                summary.encode(e, ctx)?;
            }
            Request::InstallEncryptedImage {
                kem_alg,
                ciphertext,
                manifest,
            } => {
                e.array(4)?.u8(REQ_INSTALL_IMAGE)?;
                kem_alg.encode(e, ctx)?;
                e.bytes(ciphertext)?;
                manifest.encode(e, ctx)?;
            }
            Request::Attest { nonce } => {
                e.array(2)?.u8(REQ_ATTEST)?;
                e.bytes(nonce)?;
            }
        }
        Ok(())
    }
}

impl<'b, C> Decode<'b, C> for Request<'b> {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, DecodeError> {
        let len = d
            .array()?
            .ok_or_else(|| DecodeError::message("request must be a definite array"))?;
        match d.u8()? {
            REQ_HANDSHAKE => {
                expect_len(len, 2)?;
                let payload = d.bytes()?;
                Ok(Request::Handshake { payload })
            }
            REQ_GET_INFO => {
                expect_len(len, 1)?;
                Ok(Request::GetInfo)
            }
            REQ_INIT_KEYS => {
                expect_len(len, 3)?;
                let sig_alg = d.decode()?;
                let kem_alg = d.decode()?;
                Ok(Request::InitKeys { sig_alg, kem_alg })
            }
            REQ_SIGN => {
                expect_len(len, 4)?;
                let alg = d.decode()?;
                let digest = d.decode()?;
                let summary = d.decode()?;
                Ok(Request::Sign {
                    alg,
                    digest,
                    summary,
                })
            }
            REQ_INSTALL_IMAGE => {
                expect_len(len, 4)?;
                let kem_alg = d.decode()?;
                let ciphertext = d.bytes()?;
                let manifest = d.decode()?;
                Ok(Request::InstallEncryptedImage {
                    kem_alg,
                    ciphertext,
                    manifest,
                })
            }
            REQ_ATTEST => {
                expect_len(len, 2)?;
                let nonce = d.bytes()?;
                Ok(Request::Attest { nonce })
            }
            _ => Err(DecodeError::message("unknown request tag")),
        }
    }
}

/// A response from device to host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response<'b> {
    /// Device capabilities and current state.
    Info {
        /// Firmware version string.
        fw: AsciiStr<'b>,
        /// Supported signature algorithms.
        sig_algs: AlgList,
        /// Supported KEM algorithms.
        kem_algs: AlgList,
        /// Whether the device key pairs have been generated.
        keys_present: bool,
        /// Whether the entropy source is currently healthy.
        entropy_healthy: bool,
    },
    /// The public keys generated by `InitKeys`.
    PublicKeys {
        /// Algorithm of the signing public key.
        sig_alg: AlgId,
        /// The signing public key bytes.
        sig_public_key: &'b [u8],
        /// Algorithm of the KEM public key.
        kem_alg: AlgId,
        /// The KEM public key bytes.
        kem_public_key: &'b [u8],
    },
    /// A signed message (the `Sign` reply).
    CoseSign1(CoseSign1<'b>),
    /// The outcome of an encrypted-image install (the `InstallEncryptedImage` reply).
    BootDecision {
        /// Whether the image was accepted and booted.
        accepted: bool,
        /// A measurement of the installed image.
        measurement: &'b [u8],
    },
    /// A signed attestation over the challenge nonce (the `Attest` reply).
    Attestation(CoseSign1<'b>),
    /// An error reply.
    Error {
        /// The error code.
        code: ErrorCode,
        /// A human-readable detail string (may be empty).
        detail: AsciiStr<'b>,
    },
}

impl<C> Encode<C> for Response<'_> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), EncodeError<W::Error>> {
        match self {
            Response::Info {
                fw,
                sig_algs,
                kem_algs,
                keys_present,
                entropy_healthy,
            } => {
                e.array(6)?.u8(RESP_INFO)?;
                fw.encode(e, ctx)?;
                encode_alg_list(e, sig_algs, ctx)?;
                encode_alg_list(e, kem_algs, ctx)?;
                e.bool(*keys_present)?.bool(*entropy_healthy)?;
            }
            Response::PublicKeys {
                sig_alg,
                sig_public_key,
                kem_alg,
                kem_public_key,
            } => {
                e.array(5)?.u8(RESP_PUBLIC_KEYS)?;
                sig_alg.encode(e, ctx)?;
                e.bytes(sig_public_key)?;
                kem_alg.encode(e, ctx)?;
                e.bytes(kem_public_key)?;
            }
            Response::CoseSign1(sig) => {
                e.array(2)?.u8(RESP_COSE_SIGN1)?;
                sig.encode(e, ctx)?;
            }
            Response::BootDecision {
                accepted,
                measurement,
            } => {
                e.array(3)?.u8(RESP_BOOT_DECISION)?;
                e.bool(*accepted)?;
                e.bytes(measurement)?;
            }
            Response::Attestation(att) => {
                e.array(2)?.u8(RESP_ATTESTATION)?;
                att.encode(e, ctx)?;
            }
            Response::Error { code, detail } => {
                e.array(3)?.u8(RESP_ERROR)?;
                code.encode(e, ctx)?;
                detail.encode(e, ctx)?;
            }
        }
        Ok(())
    }
}

impl<'b, C> Decode<'b, C> for Response<'b> {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, DecodeError> {
        let len = d
            .array()?
            .ok_or_else(|| DecodeError::message("response must be a definite array"))?;
        match d.u8()? {
            RESP_INFO => {
                expect_len(len, 6)?;
                let fw = d.decode()?;
                let sig_algs = decode_alg_list(d)?;
                let kem_algs = decode_alg_list(d)?;
                let keys_present = d.bool()?;
                let entropy_healthy = d.bool()?;
                Ok(Response::Info {
                    fw,
                    sig_algs,
                    kem_algs,
                    keys_present,
                    entropy_healthy,
                })
            }
            RESP_PUBLIC_KEYS => {
                expect_len(len, 5)?;
                let sig_alg = d.decode()?;
                let sig_public_key = d.bytes()?;
                let kem_alg = d.decode()?;
                let kem_public_key = d.bytes()?;
                Ok(Response::PublicKeys {
                    sig_alg,
                    sig_public_key,
                    kem_alg,
                    kem_public_key,
                })
            }
            RESP_COSE_SIGN1 => {
                expect_len(len, 2)?;
                let sig = d.decode()?;
                Ok(Response::CoseSign1(sig))
            }
            RESP_BOOT_DECISION => {
                expect_len(len, 3)?;
                let accepted = d.bool()?;
                let measurement = d.bytes()?;
                Ok(Response::BootDecision {
                    accepted,
                    measurement,
                })
            }
            RESP_ATTESTATION => {
                expect_len(len, 2)?;
                let att = d.decode()?;
                Ok(Response::Attestation(att))
            }
            RESP_ERROR => {
                expect_len(len, 3)?;
                let code = d.decode()?;
                let detail = d.decode()?;
                Ok(Response::Error { code, detail })
            }
            _ => Err(DecodeError::message("unknown response tag")),
        }
    }
}

/// Checks that a tagged message's array length matches the variant's arity.
fn expect_len(actual: u64, expected: u64) -> Result<(), DecodeError> {
    if actual == expected {
        Ok(())
    } else {
        Err(DecodeError::message("message array has the wrong length"))
    }
}

/// Encodes an algorithm list as a definite CBOR array of identifiers.
fn encode_alg_list<C, W: Write>(
    e: &mut Encoder<W>,
    list: &AlgList,
    ctx: &mut C,
) -> Result<(), EncodeError<W::Error>> {
    e.array(list.len() as u64)?;
    for alg in list {
        alg.encode(e, ctx)?;
    }
    Ok(())
}

/// Decodes a definite CBOR array of algorithm identifiers, rejecting overflow past `MAX_ALGS`.
fn decode_alg_list(d: &mut Decoder<'_>) -> Result<AlgList, DecodeError> {
    let len = d
        .array()?
        .ok_or_else(|| DecodeError::message("algorithm list must be a definite array"))?;
    let mut list = AlgList::new();
    for _ in 0..len {
        let alg: AlgId = d.decode()?;
        list.push(alg)
            .map_err(|_| DecodeError::message("too many algorithms in list"))?;
    }
    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec;

    #[test]
    fn decodes_get_info_without_alloc() {
        let wire = [0x81, REQ_GET_INFO]; // array(1) [ tag ]
        let r: Request = codec::decode(&wire).expect("decode");
        assert_eq!(r, Request::GetInfo);
    }

    #[test]
    fn decodes_init_keys_without_alloc() {
        let wire = [0x83, REQ_INIT_KEYS, 0x01, 0x02]; // array(3) [ tag, 1, 2 ]
        let r: Request = codec::decode(&wire).expect("decode");
        assert_eq!(
            r,
            Request::InitKeys {
                sig_alg: AlgId::new(1),
                kem_alg: AlgId::new(2),
            }
        );
    }

    #[test]
    fn decodes_attest_without_alloc() {
        let wire = [0x82, REQ_ATTEST, 0x43, 0xAA, 0xBB, 0xCC]; // array(2) [ tag, h'AABBCC' ]
        let r: Request = codec::decode(&wire).expect("decode");
        assert_eq!(
            r,
            Request::Attest {
                nonce: &[0xAA, 0xBB, 0xCC],
            }
        );
    }

    #[test]
    fn rejects_unknown_request_tag() {
        let wire = [0x81, 0x09]; // array(1), unknown tag 9
        let r: Result<Request, _> = codec::decode(&wire);
        assert!(r.is_err());
    }

    #[test]
    fn rejects_wrong_request_array_length() {
        let wire = [0x82, REQ_INIT_KEYS, 0x01]; // InitKeys tag but array(2)
        let r: Result<Request, _> = codec::decode(&wire);
        assert!(r.is_err());
    }

    #[test]
    fn rejects_non_ascii_error_detail() {
        let wire = [
            0x83, RESP_ERROR, 0x01, // array(3), Error tag, code 1
            0x65, 0x63, 0x61, 0x66, 0xc3, 0xa9, // detail = "café"
        ];
        let r: Result<Response, _> = codec::decode(&wire);
        assert!(r.is_err());
    }

    #[test]
    fn alg_list_decode_rejects_overflow() {
        // A CBOR array of MAX_ALGS + 1 small-integer ids.
        let mut wire = [0u8; 1 + (MAX_ALGS + 1)];
        wire[0] = 0x80 | (MAX_ALGS as u8 + 1);
        for i in 0..=MAX_ALGS {
            wire[1 + i] = i as u8;
        }
        let mut d = Decoder::new(&wire);
        assert!(decode_alg_list(&mut d).is_err());
    }

    #[cfg(feature = "alloc")]
    fn round_trip_request(original: Request) {
        let bytes = codec::encode(&original).expect("encode");
        let decoded: Request = codec::decode(&bytes).expect("decode");
        assert_eq!(decoded, original);
        assert_eq!(codec::encode(&decoded).expect("re-encode"), bytes); // deterministic
    }

    #[cfg(feature = "alloc")]
    fn round_trip_response(original: Response) {
        let bytes = codec::encode(&original).expect("encode");
        let decoded: Response = codec::decode(&bytes).expect("decode");
        assert_eq!(decoded, original);
        assert_eq!(codec::encode(&decoded).expect("re-encode"), bytes); // deterministic
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn request_get_info_round_trips() {
        round_trip_request(Request::GetInfo);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn request_init_keys_round_trips() {
        round_trip_request(Request::InitKeys {
            sig_alg: AlgId::new(-7),
            kem_alg: AlgId::new(-48),
        });
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn response_info_round_trips() {
        let fw = AsciiStr::try_from("koffer 0.1").unwrap();
        let mut sig_algs = AlgList::new();
        sig_algs.push(AlgId::new(-7)).unwrap();
        let mut kem_algs = AlgList::new();
        kem_algs.push(AlgId::new(-48)).unwrap();
        kem_algs.push(AlgId::new(-49)).unwrap();
        round_trip_response(Response::Info {
            fw,
            sig_algs,
            kem_algs,
            keys_present: true,
            entropy_healthy: true,
        });
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn response_public_keys_round_trips() {
        let sig_pk = [0x11u8; 32];
        let kem_pk = [0x22u8; 16];
        round_trip_response(Response::PublicKeys {
            sig_alg: AlgId::new(-7),
            sig_public_key: &sig_pk,
            kem_alg: AlgId::new(-48),
            kem_public_key: &kem_pk,
        });
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn response_error_round_trips() {
        let detail = AsciiStr::try_from("bad request").unwrap();
        round_trip_response(Response::Error {
            code: ErrorCode::Malformed,
            detail,
        });
    }
}
