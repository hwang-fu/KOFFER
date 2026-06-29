//! Host<->device request/response messages (the USB-CDC protocol payloads).
//!
//! Each message encodes as a flat CBOR array led by an integer tag: `[tag, ...fields]`.
//! `Request` (host -> device) and `Response` (device -> host) are separate enums with
//! separate tag spaces; the body bytes travel inside a frame (see the `frame` module).
//! Text fields are printable-ASCII (F15); byte fields borrow the input, zero-copy, like
//! the COSE and manifest types.

use minicbor::{Encode, encode::Write};

use crate::{
    alg::AlgId,
    ascii::AsciiStr,
    cose::{CoseEncrypt, CoseSign1},
    error::ErrorCode,
    manifest::{Manifest, SuitDigest},
};

/// Wire tag for each `Request` variant (host -> device): the leading integer of the
/// message's CBOR array. The `#[repr(u8)]` discriminant is the on-wire byte value.
#[repr(u8)]
enum RequestTag {
    Handshake = 1,
    GetInfo = 2,
    InitKeys = 3,
    Sign = 4,
    InstallEncryptedImage = 5,
    Attest = 6,
}

impl TryFrom<u8> for RequestTag {
    type Error = ();

    fn try_from(tag: u8) -> Result<Self, ()> {
        Ok(match tag {
            1 => RequestTag::Handshake,
            2 => RequestTag::GetInfo,
            3 => RequestTag::InitKeys,
            4 => RequestTag::Sign,
            5 => RequestTag::InstallEncryptedImage,
            6 => RequestTag::Attest,
            _ => return Err(()),
        })
    }
}

/// Wire tag for each `Response` variant (device -> host): the leading integer of the
/// message's CBOR array. The `#[repr(u8)]` discriminant is the on-wire byte value.
#[repr(u8)]
enum ResponseTag {
    Info = 1,
    PublicKeys = 2,
    CoseSign1 = 3,
    BootDecision = 4,
    Attestation = 5,
    Error = 6,
}

impl TryFrom<u8> for ResponseTag {
    type Error = ();

    fn try_from(tag: u8) -> Result<Self, ()> {
        Ok(match tag {
            1 => ResponseTag::Info,
            2 => ResponseTag::PublicKeys,
            3 => ResponseTag::CoseSign1,
            4 => ResponseTag::BootDecision,
            5 => ResponseTag::Attestation,
            6 => ResponseTag::Error,
            _ => return Err(()),
        })
    }
}

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
        sig_alg: AlgId,
        /// The digest to sign.
        digest: SuitDigest<'b>,
        /// Human-readable consent prompt shown on the device display.
        prompt: AsciiStr<'b>,
    },
    /// Install an encrypted firmware image (`-> Response::BootDecision`).
    InstallEncryptedImage {
        /// The encrypted image as a `COSE_Encrypt`: the AEAD algorithm, nonce, the
        /// encrypted bytes, and the recipient holding the wrapped content key.
        image: CoseEncrypt<'b>,
        /// The signed manifest binding the image.
        manifest: Manifest<'b>,
    },
    /// Request a signed attestation over a challenge nonce (`-> Response::Attestation`).
    Attest { challenge: &'b [u8] },
}

impl<C> minicbor::Encode<C> for Request<'_> {
    fn encode<W>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>>
    where
        W: Write,
    {
        match self {
            Request::Handshake { payload } => {
                e.array(2)?.u8(RequestTag::Handshake as u8)?;
                e.bytes(payload)?;
            }
            Request::GetInfo => {
                e.array(1)?.u8(RequestTag::GetInfo as u8)?;
            }
            Request::InitKeys { sig_alg, kem_alg } => {
                e.array(3)?.u8(RequestTag::InitKeys as u8)?;
                sig_alg.encode(e, ctx)?;
                kem_alg.encode(e, ctx)?;
            }
            Request::Sign {
                sig_alg,
                digest,
                prompt,
            } => {
                e.array(4)?.u8(RequestTag::Sign as u8)?;
                sig_alg.encode(e, ctx)?;
                digest.encode(e, ctx)?;
                prompt.encode(e, ctx)?;
            }
            Request::InstallEncryptedImage { image, manifest } => {
                e.array(3)?.u8(RequestTag::InstallEncryptedImage as u8)?;
                image.encode(e, ctx)?;
                manifest.encode(e, ctx)?;
            }
            Request::Attest { challenge } => {
                e.array(2)?.u8(RequestTag::Attest as u8)?;
                e.bytes(challenge)?;
            }
        }
        Ok(())
    }
}

impl<'b, C> minicbor::Decode<'b, C> for Request<'b> {
    fn decode(d: &mut minicbor::Decoder<'b>, _: &mut C) -> Result<Self, minicbor::decode::Error> {
        let len = d
            .array()?
            .ok_or_else(|| minicbor::decode::Error::message("request must be a definite array"))?;
        let tag = RequestTag::try_from(d.u8()?)
            .map_err(|_| minicbor::decode::Error::message("unknown request tag"))?;
        match tag {
            RequestTag::Handshake => {
                expect_len(len, 2)?;
                let payload = d.bytes()?;
                Ok(Request::Handshake { payload })
            }
            RequestTag::GetInfo => {
                expect_len(len, 1)?;
                Ok(Request::GetInfo)
            }
            RequestTag::InitKeys => {
                expect_len(len, 3)?;
                let sig_alg = d.decode()?;
                let kem_alg = d.decode()?;
                Ok(Request::InitKeys { sig_alg, kem_alg })
            }
            RequestTag::Sign => {
                expect_len(len, 4)?;
                let sig_alg = d.decode()?;
                let digest = d.decode()?;
                let prompt = d.decode()?;
                Ok(Request::Sign {
                    sig_alg,
                    digest,
                    prompt,
                })
            }
            RequestTag::InstallEncryptedImage => {
                expect_len(len, 3)?;
                let image = d.decode()?;
                let manifest = d.decode()?;
                Ok(Request::InstallEncryptedImage { image, manifest })
            }
            RequestTag::Attest => {
                expect_len(len, 2)?;
                let challenge = d.bytes()?;
                Ok(Request::Attest { challenge })
            }
        }
    }
}

/// A response from device to host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response<'b> {
    /// Device capabilities and current state.
    Info {
        /// Firmware version string.
        firmware_version: AsciiStr<'b>,
        /// Supported signature algorithms.
        sig_algs: AlgList,
        /// Supported KEM algorithms.
        kem_algs: AlgList,
        /// Whether the device key pairs have been generated.
        keys_are_present: bool,
        /// Whether the entropy source is currently healthy.
        entropy_is_healthy: bool,
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
        image_is_accepted: bool,
        /// A digest of the installed image, as evidence of what was installed.
        image_digest: &'b [u8],
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

impl<C> minicbor::Encode<C> for Response<'_> {
    fn encode<W>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>>
    where
        W: Write,
    {
        match self {
            Response::Info {
                firmware_version,
                sig_algs,
                kem_algs,
                keys_are_present,
                entropy_is_healthy,
            } => {
                e.array(6)?.u8(ResponseTag::Info as u8)?;
                firmware_version.encode(e, ctx)?;
                encode_alg_list(e, sig_algs, ctx)?;
                encode_alg_list(e, kem_algs, ctx)?;
                e.bool(*keys_are_present)?.bool(*entropy_is_healthy)?;
            }
            Response::PublicKeys {
                sig_alg,
                sig_public_key,
                kem_alg,
                kem_public_key,
            } => {
                e.array(5)?.u8(ResponseTag::PublicKeys as u8)?;
                sig_alg.encode(e, ctx)?;
                e.bytes(sig_public_key)?;
                kem_alg.encode(e, ctx)?;
                e.bytes(kem_public_key)?;
            }
            Response::CoseSign1(sig) => {
                e.array(2)?.u8(ResponseTag::CoseSign1 as u8)?;
                sig.encode(e, ctx)?;
            }
            Response::BootDecision {
                image_is_accepted,
                image_digest,
            } => {
                e.array(3)?.u8(ResponseTag::BootDecision as u8)?;
                e.bool(*image_is_accepted)?;
                e.bytes(image_digest)?;
            }
            Response::Attestation(att) => {
                e.array(2)?.u8(ResponseTag::Attestation as u8)?;
                att.encode(e, ctx)?;
            }
            Response::Error { code, detail } => {
                e.array(3)?.u8(ResponseTag::Error as u8)?;
                code.encode(e, ctx)?;
                detail.encode(e, ctx)?;
            }
        }
        Ok(())
    }
}

impl<'b, C> minicbor::Decode<'b, C> for Response<'b> {
    fn decode(d: &mut minicbor::Decoder<'b>, _: &mut C) -> Result<Self, minicbor::decode::Error> {
        let len = d
            .array()?
            .ok_or_else(|| minicbor::decode::Error::message("response must be a definite array"))?;
        let tag = ResponseTag::try_from(d.u8()?)
            .map_err(|_| minicbor::decode::Error::message("unknown response tag"))?;
        match tag {
            ResponseTag::Info => {
                expect_len(len, 6)?;
                let firmware_version = d.decode()?;
                let sig_algs = decode_alg_list(d)?;
                let kem_algs = decode_alg_list(d)?;
                let keys_are_present = d.bool()?;
                let entropy_is_healthy = d.bool()?;
                Ok(Response::Info {
                    firmware_version,
                    sig_algs,
                    kem_algs,
                    keys_are_present,
                    entropy_is_healthy,
                })
            }
            ResponseTag::PublicKeys => {
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
            ResponseTag::CoseSign1 => {
                expect_len(len, 2)?;
                let sig = d.decode()?;
                Ok(Response::CoseSign1(sig))
            }
            ResponseTag::BootDecision => {
                expect_len(len, 3)?;
                let image_is_accepted = d.bool()?;
                let image_digest = d.bytes()?;
                Ok(Response::BootDecision {
                    image_is_accepted,
                    image_digest,
                })
            }
            ResponseTag::Attestation => {
                expect_len(len, 2)?;
                let att = d.decode()?;
                Ok(Response::Attestation(att))
            }
            ResponseTag::Error => {
                expect_len(len, 3)?;
                let code = d.decode()?;
                let detail = d.decode()?;
                Ok(Response::Error { code, detail })
            }
        }
    }
}

/// Checks that a tagged message's array length matches the variant's arity.
fn expect_len(actual: u64, expected: u64) -> Result<(), minicbor::decode::Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(minicbor::decode::Error::message(
            "message array has the wrong length",
        ))
    }
}

/// Encodes an algorithm list as a definite CBOR array of identifiers.
fn encode_alg_list<C, W>(
    e: &mut minicbor::Encoder<W>,
    list: &AlgList,
    ctx: &mut C,
) -> Result<(), minicbor::encode::Error<W::Error>>
where
    W: Write,
{
    e.array(list.len() as u64)?;
    for alg in list {
        alg.encode(e, ctx)?;
    }
    Ok(())
}

/// Decodes a definite CBOR array of algorithm identifiers, rejecting overflow past `MAX_ALGS`.
fn decode_alg_list(d: &mut minicbor::Decoder<'_>) -> Result<AlgList, minicbor::decode::Error> {
    let len = d.array()?.ok_or_else(|| {
        minicbor::decode::Error::message("algorithm list must be a definite array")
    })?;
    let mut list = AlgList::new();
    for _ in 0..len {
        let alg: AlgId = d.decode()?;
        list.push(alg)
            .map_err(|_| minicbor::decode::Error::message("too many algorithms in list"))?;
    }
    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec;

    #[test]
    fn decodes_get_info_without_alloc() {
        let wire = [0x81, RequestTag::GetInfo as u8]; // array(1) [ tag ]
        let r: Request = codec::decode(&wire).expect("decode");
        assert_eq!(r, Request::GetInfo);
    }

    #[test]
    fn decodes_init_keys_without_alloc() {
        let wire = [0x83, RequestTag::InitKeys as u8, 0x01, 0x02]; // array(3) [ tag, 1, 2 ]
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
        let wire = [0x82, RequestTag::Attest as u8, 0x43, 0xAA, 0xBB, 0xCC]; // array(2) [ tag, h'AABBCC' ]
        let r: Request = codec::decode(&wire).expect("decode");
        assert_eq!(
            r,
            Request::Attest {
                challenge: &[0xAA, 0xBB, 0xCC],
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
        let wire = [0x82, RequestTag::InitKeys as u8, 0x01]; // InitKeys tag but array(2)
        let r: Result<Request, _> = codec::decode(&wire);
        assert!(r.is_err());
    }

    #[test]
    fn rejects_non_ascii_error_detail() {
        let wire = [
            0x83,
            ResponseTag::Error as u8,
            0x01, // array(3), Error tag, code 1
            0x65,
            0x63,
            0x61,
            0x66,
            0xc3,
            0xa9, // detail = "café"
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
        let mut d = minicbor::Decoder::new(&wire);
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
    fn request_handshake_round_trips() {
        let payload = [0x01, 0x02, 0x03, 0x04];
        round_trip_request(Request::Handshake { payload: &payload });
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn request_sign_round_trips() {
        let digest_bytes = [0x55u8; 32];
        let digest = SuitDigest::new(AlgId::new(-16), &digest_bytes);
        let prompt = AsciiStr::try_from("sign firmware v2").unwrap();
        round_trip_request(Request::Sign {
            sig_alg: AlgId::new(-7),
            digest,
            prompt,
        });
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn request_install_encrypted_image_round_trips() {
        use crate::cose::Recipient;
        let class_id = AsciiStr::try_from("acme-rtos").unwrap();
        let digest_bytes = [0x11u8; 32];
        let payload_digest = SuitDigest::new(AlgId::new(-16), &digest_bytes);
        let manifest = Manifest::new(1, 7, class_id, payload_digest, 0);
        let encapsulation = [0xEEu8; 32];
        let recipient = Recipient::new(AlgId::new(-48), None, &encapsulation);
        let nonce = [0x22u8; 12];
        let ciphertext = [0xCDu8; 48];
        let image = CoseEncrypt::new(AlgId::new(3), &nonce, &ciphertext, recipient);
        round_trip_request(Request::InstallEncryptedImage { image, manifest });
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn request_attest_round_trips() {
        let challenge = [0x99u8; 16];
        round_trip_request(Request::Attest {
            challenge: &challenge,
        });
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn response_info_round_trips() {
        let firmware_version = AsciiStr::try_from("koffer 0.1").unwrap();
        let mut sig_algs = AlgList::new();
        sig_algs.push(AlgId::new(-7)).unwrap();
        let mut kem_algs = AlgList::new();
        kem_algs.push(AlgId::new(-48)).unwrap();
        kem_algs.push(AlgId::new(-49)).unwrap();
        round_trip_response(Response::Info {
            firmware_version,
            sig_algs,
            kem_algs,
            keys_are_present: true,
            entropy_is_healthy: true,
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

    #[cfg(feature = "alloc")]
    #[test]
    fn response_cose_sign1_round_trips() {
        use crate::cose::Payload;
        let kid = AsciiStr::try_from("device-root").unwrap();
        let signature = [0xABu8; 64];
        round_trip_response(Response::CoseSign1(CoseSign1::new(
            AlgId::new(-7),
            Some(kid),
            Payload::Detached,
            &signature,
        )));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn response_boot_decision_round_trips() {
        let image_digest = [0x77u8; 32];
        round_trip_response(Response::BootDecision {
            image_is_accepted: true,
            image_digest: &image_digest,
        });
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn response_attestation_round_trips() {
        use crate::cose::Payload;
        let kid = AsciiStr::try_from("endorsement").unwrap();
        let measurement = [0x33u8; 20];
        let signature = [0xCDu8; 64];
        round_trip_response(Response::Attestation(CoseSign1::new(
            AlgId::new(-49),
            Some(kid),
            Payload::Attached(&measurement),
            &signature,
        )));
    }

    #[test]
    fn rejects_non_ascii_info_fw() {
        // Info with a non-ASCII fw string -> F15 reject.
        let wire = [
            0x86,
            ResponseTag::Info as u8, // array(6), Info tag
            0x65,
            0x63,
            0x61,
            0x66,
            0xc3,
            0xa9, // fw = "café"
        ];
        let r: Result<Response, _> = codec::decode(&wire);
        assert!(r.is_err());
    }

    #[test]
    fn rejects_non_ascii_sign_summary() {
        // Sign with valid alg + digest, then a non-ASCII summary -> F15 reject.
        let wire = [
            0x84,
            RequestTag::Sign as u8, // array(4), Sign tag
            0x26,                   // alg = -7
            0x82,
            0x2f,
            0x42,
            0xAB,
            0xCD, // digest = [-16, h'ABCD']
            0x65,
            0x63,
            0x61,
            0x66,
            0xc3,
            0xa9, // summary = "café"
        ];
        let r: Result<Request, _> = codec::decode(&wire);
        assert!(r.is_err());
    }

    #[cfg(feature = "alloc")]
    use crate::testutil::to_hex;

    #[cfg(feature = "alloc")]
    fn check_request_kat(msg: Request, expected_hex: &str) {
        let bytes = codec::encode(&msg).expect("encode");
        assert_eq!(to_hex(&bytes), expected_hex);
        let decoded: Request = codec::decode(&bytes).expect("decode");
        assert_eq!(decoded, msg);
    }

    #[cfg(feature = "alloc")]
    fn check_response_kat(msg: Response, expected_hex: &str) {
        let bytes = codec::encode(&msg).expect("encode");
        assert_eq!(to_hex(&bytes), expected_hex);
        let decoded: Response = codec::decode(&bytes).expect("decode");
        assert_eq!(decoded, msg);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn request_kats() {
        check_request_kat(Request::GetInfo, "8102");
        check_request_kat(
            Request::InitKeys {
                sig_alg: AlgId::new(-7),
                kem_alg: AlgId::new(-48),
            },
            "830326382f",
        );
        let dbytes = [0xAA, 0xBB, 0xCC, 0xDD];
        check_request_kat(
            Request::Sign {
                sig_alg: AlgId::new(-7),
                digest: SuitDigest::new(AlgId::new(-16), &dbytes),
                prompt: AsciiStr::try_from("sign").unwrap(),
            },
            "840426822f44aabbccdd647369676e",
        );
        let mdig = [0xAB, 0xCD];
        let manifest = Manifest::new(
            1,
            1,
            AsciiStr::try_from("kof").unwrap(),
            SuitDigest::new(AlgId::new(-16), &mdig),
            0,
        );
        let nonce = [0xAA, 0xBB];
        let ct = [0xCD, 0xCE];
        let enc = [0xEE, 0xFF];
        let recipient = crate::cose::Recipient::new(AlgId::new(-48), None, &enc);
        let image = CoseEncrypt::new(AlgId::new(3), &nonce, &ct, recipient);
        check_request_kat(
            Request::InstallEncryptedImage { image, manifest },
            "83058443a10103a10542aabb42cdce818344a101382fa042eeffa50101020103636b6f6604822f42abcd0500",
        );
        let challenge = [0x99, 0x88];
        check_request_kat(
            Request::Attest {
                challenge: &challenge,
            },
            "8206429988",
        );
        let hp = [0x01, 0x02];
        check_request_kat(Request::Handshake { payload: &hp }, "8201420102");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn response_kats() {
        use crate::cose::Payload;
        let mut sig_algs = AlgList::new();
        sig_algs.push(AlgId::new(-7)).unwrap();
        let mut kem_algs = AlgList::new();
        kem_algs.push(AlgId::new(-48)).unwrap();
        check_response_kat(
            Response::Info {
                firmware_version: AsciiStr::try_from("kof").unwrap(),
                sig_algs,
                kem_algs,
                keys_are_present: true,
                entropy_is_healthy: false,
            },
            "8601636b6f66812681382ff5f4",
        );
        let spk = [0x11, 0x22];
        let kpk = [0x33, 0x44];
        check_response_kat(
            Response::PublicKeys {
                sig_alg: AlgId::new(-7),
                sig_public_key: &spk,
                kem_alg: AlgId::new(-48),
                kem_public_key: &kpk,
            },
            "850226421122382f423344",
        );
        let sig1 = [0xAB, 0xCD];
        check_response_kat(
            Response::CoseSign1(CoseSign1::new(
                AlgId::new(-7),
                Some(AsciiStr::try_from("kid").unwrap()),
                Payload::Detached,
                &sig1,
            )),
            "82038443a10126a104636b6964f642abcd",
        );
        let meas = [0x77, 0x88];
        check_response_kat(
            Response::BootDecision {
                image_is_accepted: true,
                image_digest: &meas,
            },
            "8304f5427788",
        );
        let amsg = [0x33];
        let asig = [0xCD];
        check_response_kat(
            Response::Attestation(CoseSign1::new(
                AlgId::new(-49),
                Some(AsciiStr::try_from("kid").unwrap()),
                Payload::Attached(&amsg),
                &asig,
            )),
            "82058444a1013830a104636b6964413341cd",
        );
        check_response_kat(
            Response::Error {
                code: ErrorCode::Malformed,
                detail: AsciiStr::try_from("bad").unwrap(),
            },
            "83060163626164",
        );
    }
}

#[cfg(all(test, feature = "alloc"))]
mod proptests {
    use super::*;
    use crate::codec;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn info_round_trips(
            fw in proptest::collection::vec(0x20u8..=0x7E, 0..=16),
            sig in proptest::collection::vec(any::<i64>(), 0..=MAX_ALGS),
            kem in proptest::collection::vec(any::<i64>(), 0..=MAX_ALGS),
            keys_are_present in any::<bool>(),
            entropy_is_healthy in any::<bool>(),
        ) {
            let fw = String::from_utf8(fw).unwrap();
            let mut sig_algs = AlgList::new();
            for a in sig {
                sig_algs.push(AlgId::new(a)).unwrap();
            }
            let mut kem_algs = AlgList::new();
            for a in kem {
                kem_algs.push(AlgId::new(a)).unwrap();
            }
            let original = Response::Info {
                firmware_version: AsciiStr::try_from(fw.as_str()).unwrap(),
                sig_algs,
                kem_algs,
                keys_are_present,
                entropy_is_healthy,
            };
            let encoded = codec::encode(&original).unwrap();
            let decoded: Response = codec::decode(&encoded).unwrap();
            let reencoded = codec::encode(&decoded).unwrap();
            prop_assert_eq!(decoded, original);
            // Deterministic: re-encoding the decoded message is byte-identical.
            prop_assert_eq!(reencoded, encoded);
        }
    }
}
