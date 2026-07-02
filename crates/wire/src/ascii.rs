//! Printable-ASCII-validated strings for externally-supplied text.
//!
//! Identifiers, labels, and displayed strings are constrained to printable 7-bit US-ASCII
//! (0x20-0x7E). Bytes outside that range are rejected at the parse boundary, never silently
//! transcoded.

use core::{fmt, ops::Deref};

use minicbor::encode::Write;

/// Error returned when input contains a byte outside printable 7-bit US-ASCII (0x20-0x7E).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsciiError;

/// The rejection message, shared by the `Display` impl and the CBOR decoder.
const NOT_PRINTABLE_ASCII: &str = "input is not printable 7-bit US-ASCII";

impl fmt::Display for AsciiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(NOT_PRINTABLE_ASCII)
    }
}

impl core::error::Error for AsciiError {}

/// Inclusive range of printable 7-bit US-ASCII (space `0x20` through `~` `0x7E`).
const PRINTABLE_ASCII: core::ops::RangeInclusive<u8> = 0x20..=0x7E;

/// `Ok` only if every byte is printable 7-bit US-ASCII (0x20-0x7E).
fn validate(bytes: &[u8]) -> Result<(), AsciiError> {
    if bytes.iter().all(|b| PRINTABLE_ASCII.contains(b)) {
        Ok(())
    } else {
        Err(AsciiError)
    }
}

/// A borrowed string validated to contain only printable 7-bit US-ASCII.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AsciiStr<'a>(&'a str);

impl<'a> AsciiStr<'a> {
    pub fn as_str(&self) -> &str {
        self.0
    }
}

impl AsRef<str> for AsciiStr<'_> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> TryFrom<&'a str> for AsciiStr<'a> {
    type Error = AsciiError;

    fn try_from(s: &'a str) -> Result<Self, AsciiError> {
        validate(s.as_bytes())?;
        Ok(Self(s))
    }
}

impl<'a> TryFrom<&'a [u8]> for AsciiStr<'a> {
    type Error = AsciiError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, AsciiError> {
        // Reject invalid UTF-8 first; printable ASCII is a subset, so no valid input is lost.
        let s = core::str::from_utf8(bytes).map_err(|_| AsciiError)?;
        Self::try_from(s)
    }
}

impl Deref for AsciiStr<'_> {
    type Target = str;

    fn deref(&self) -> &str {
        self.0
    }
}

impl fmt::Display for AsciiStr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl<C> minicbor::Encode<C> for AsciiStr<'_> {
    fn encode<W>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>>
    where
        W: Write,
    {
        e.str(self.0)?.ok()
    }
}

impl<'b, C> minicbor::Decode<'b, C> for AsciiStr<'b> {
    fn decode(d: &mut minicbor::Decoder<'b>, _: &mut C) -> Result<Self, minicbor::decode::Error> {
        let s = d.str()?;
        validate(s.as_bytes())
            .map_err(|_| minicbor::decode::Error::message(NOT_PRINTABLE_ASCII))?;
        Ok(Self(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{codec, testutil::TEXT_STRING};

    #[test]
    fn accepts_every_printable_byte() {
        for b in PRINTABLE_ASCII {
            assert!(
                AsciiStr::try_from([b].as_slice()).is_ok(),
                "0x{b:02X} should be accepted"
            );
        }
    }

    #[test]
    fn accepts_printable_string_and_preserves_content() {
        let s = AsciiStr::try_from("Hello, KOFFER! ~").unwrap();
        assert_eq!(s.as_str(), "Hello, KOFFER! ~");
    }

    #[test]
    fn rejects_c0_control_bytes() {
        for b in 0..*PRINTABLE_ASCII.start() {
            assert_eq!(
                AsciiStr::try_from([b].as_slice()),
                Err(AsciiError),
                "control 0x{b:02X} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_just_outside_the_range() {
        let below = *PRINTABLE_ASCII.start() - 1; // 0x1F
        let above = *PRINTABLE_ASCII.end() + 1; // 0x7F (DEL)
        assert!(AsciiStr::try_from([below].as_slice()).is_err());
        assert!(AsciiStr::try_from([above].as_slice()).is_err());
    }

    #[test]
    fn rejects_non_ascii_utf8_text() {
        // Valid UTF-8, but 'é' is two bytes both above 0x7E.
        assert!(AsciiStr::try_from("café").is_err());
    }

    #[test]
    fn rejects_invalid_utf8_bytes() {
        // 0x80 is a stray UTF-8 continuation byte, rejected before the range check.
        assert!(AsciiStr::try_from([0x80u8].as_slice()).is_err());
    }

    #[test]
    fn asciistr_decodes_from_cbor_without_alloc() {
        // CBOR text string of length 3, then "abc".
        let bytes = [TEXT_STRING | 3, b'a', b'b', b'c'];
        let s: AsciiStr = codec::decode(&bytes).expect("decode");
        assert_eq!(s.as_str(), "abc");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn asciistr_cbor_round_trip() {
        let original = AsciiStr::try_from("firmware-slot-0").unwrap();
        let bytes = codec::encode(&original).expect("encode");
        let decoded: AsciiStr = codec::decode(&bytes).expect("decode");
        assert_eq!(decoded, original);
        // Deterministic: re-encoding yields identical bytes.
        assert_eq!(codec::encode(&decoded).expect("re-encode"), bytes);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn cbor_decode_rejects_non_ascii_on_the_wire() {
        // A valid CBOR text string whose content is not printable ASCII.
        let wire = codec::encode(&"café").expect("encode");
        let decoded: Result<AsciiStr, _> = codec::decode(&wire);
        assert!(decoded.is_err());
    }

    // ---- Input-canonicalization corpus ----

    // Characters that look like printable ASCII but are not (homograph threat).
    // Written as `\u{...}` escapes so the source stays ASCII and each one is explicit.
    const CONFUSABLES: &[&str] = &[
        "\u{0430}", // CYRILLIC SMALL LETTER A  (looks like 'a')
        "\u{0435}", // CYRILLIC SMALL LETTER IE (looks like 'e')
        "\u{043E}", // CYRILLIC SMALL LETTER O  (looks like 'o')
        "\u{0440}", // CYRILLIC SMALL LETTER ER (looks like 'p')
        "\u{0441}", // CYRILLIC SMALL LETTER ES (looks like 'c')
        "\u{0445}", // CYRILLIC SMALL LETTER HA (looks like 'x')
        "\u{03BF}", // GREEK SMALL LETTER OMICRON (looks like 'o')
        "\u{0391}", // GREEK CAPITAL LETTER ALPHA (looks like 'A')
        "\u{FF21}", // FULLWIDTH LATIN CAPITAL LETTER A
        "\u{FF10}", // FULLWIDTH DIGIT ZERO
        "\u{2044}", // FRACTION SLASH (looks like '/')
        "\u{2010}", // HYPHEN (looks like '-')
        "\u{2018}", // LEFT SINGLE QUOTATION MARK (looks like '\'')
        "\u{00A0}", // NO-BREAK SPACE (looks like ' ')
        "\u{200B}", // ZERO WIDTH SPACE (invisible)
        "\u{FEFF}", // ZERO WIDTH NO-BREAK SPACE / BOM (invisible)
    ];

    #[test]
    fn rejects_unicode_confusables() {
        for s in CONFUSABLES {
            assert!(
                AsciiStr::try_from(*s).is_err(),
                "confusable {s:?} should be rejected"
            );
        }
    }

    // Malformed UTF-8: overlong encodings, stray bytes, truncations, a surrogate.
    const MALFORMED_UTF8: &[&[u8]] = &[
        &[0xC0, 0xAF],             // overlong 2-byte '/'
        &[0xC0, 0x80],             // overlong 2-byte NUL
        &[0xC1, 0x81],             // overlong 2-byte 'A'
        &[0xE0, 0x80, 0xAF],       // overlong 3-byte '/'
        &[0xF0, 0x80, 0x80, 0xAF], // overlong 4-byte '/'
        &[0x80],                   // lone continuation byte
        &[0xFF],                   // invalid lead byte
        &[0xC3],                   // truncated 2-byte sequence
        &[0xE2, 0x82],             // truncated 3-byte sequence
        &[0xED, 0xA0, 0x80],       // UTF-16 surrogate U+D800 (invalid in UTF-8)
    ];

    #[test]
    fn rejects_malformed_utf8_corpus() {
        for bytes in MALFORMED_UTF8 {
            assert!(
                AsciiStr::try_from(*bytes).is_err(),
                "malformed {bytes:02X?} should be rejected"
            );
        }
    }
}

#[cfg(all(test, feature = "alloc"))]
mod proptests {
    use proptest::prelude::*;

    use super::*;

    // Upper bound on the length of generated inputs.
    const MAX_LEN: usize = 64;

    proptest! {
        // Construction succeeds iff the input is valid UTF-8 and every byte is printable ASCII.
        #[test]
        fn ascii_accepts_iff_printable(bytes in proptest::collection::vec(any::<u8>(), 0..=MAX_LEN)) {
            let accepted = AsciiStr::try_from(bytes.as_slice()).is_ok();
            let expected = core::str::from_utf8(&bytes)
                .map(|s| s.bytes().all(|b| PRINTABLE_ASCII.contains(&b)))
                .unwrap_or(false);
            prop_assert_eq!(accepted, expected);
        }
    }
}
