//! Base64 encoding (RFC 4648 sec.4), for the places a signature format
//! insists on it.
//!
//! `ASiC` manifests and `XAdES` carry digests and certificates as base64
//! inside XML, because XML cannot hold arbitrary octets. Encoding only:
//! nothing in this crate consumes base64 that it did not produce, and a
//! decoder invites input this module has no business accepting.

/// The standard alphabet (RFC 4648 sec.4). Not the URL-safe variant --
/// XML has no objection to `+` or `/`.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Input octets per encoded quantum.
const QUANTUM_IN: usize = 3;

/// Output characters per encoded quantum.
const QUANTUM_OUT: usize = 4;

/// Bits carried by one output character.
const BITS_PER_CHARACTER: usize = 6;

/// Mask selecting one output character's worth of bits.
const CHARACTER_MASK: usize = 0x3F;

/// Bits in an octet.
const BITS_PER_OCTET: usize = 8;

/// Encode `input` as base64 with the standard alphabet and padding.
#[must_use]
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(QUANTUM_IN) * QUANTUM_OUT);
    for chunk in input.chunks(QUANTUM_IN) {
        // Pack the chunk right-aligned into a 24-bit accumulator, so a
        // short final chunk simply leaves the low bits zero.
        let mut packed = 0_usize;
        for index in 0..QUANTUM_IN {
            packed <<= BITS_PER_OCTET;
            packed |= usize::from(chunk.get(index).copied().unwrap_or(0));
        }
        // Every chunk yields four characters; the ones with no input
        // behind them become padding below.
        for index in 0..QUANTUM_OUT {
            let shift = BITS_PER_CHARACTER * (QUANTUM_OUT - 1 - index);
            let sextet = (packed >> shift) & CHARACTER_MASK;
            // `index <= chunk.len()` is the count of characters carrying
            // real input: one more than the octets supplied.
            if index <= chunk.len() {
                out.push(char::from(ALPHABET[sextet]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

const ALPHABET_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode `input` as URL-safe base64 without padding (RFC 4648 sec.5).
#[must_use]
pub fn encode_url_unpadded(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(QUANTUM_IN) * QUANTUM_OUT);
    for chunk in input.chunks(QUANTUM_IN) {
        let mut packed = 0_usize;
        for index in 0..QUANTUM_IN {
            packed <<= BITS_PER_OCTET;
            packed |= usize::from(chunk.get(index).copied().unwrap_or(0));
        }
        let out_chars = match chunk.len() {
            1 => 2,
            2 => 3,
            _ => 4,
        };
        for index in 0..out_chars {
            let shift = BITS_PER_CHARACTER * (QUANTUM_OUT - 1 - index);
            let sextet = (packed >> shift) & CHARACTER_MASK;
            out.push(char::from(ALPHABET_URL[sextet]));
        }
    }
    out
}

/// Decode URL-safe unpadded base64 (RFC 4648 sec.5).
pub fn decode_url_unpadded(input: &str) -> Result<Vec<u8>, &'static str> {
    let input_bytes = input.as_bytes();
    if input_bytes.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity((input_bytes.len() * 3) / 4);
    let mut buf = 0_u32;
    let mut bits = 0;

    for &b in input_bytes {
        let val = match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a' + 26) as u32,
            b'0'..=b'9' => (b - b'0' + 52) as u32,
            b'-' => 62,
            b'_' => 63,
            b'=' => continue,
            _ => return Err("invalid base64url character"),
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc_4648_vectors() {
        // RFC 4648 sec.10, verbatim.
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64url_round_trip() {
        let test_cases: &[&[u8]] = &[
            b"",
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            &[0xFF, 0x00, 0xAA, 0x55],
        ];
        for tc in test_cases {
            let enc = encode_url_unpadded(tc);
            assert!(!enc.contains('='));
            assert!(!enc.contains('+'));
            assert!(!enc.contains('/'));
            let dec = decode_url_unpadded(&enc).expect("valid base64url");
            assert_eq!(&dec, tc);
        }
    }

    #[test]
    fn encodes_every_octet_value() {
        // All 256 values, so a sign-extension or alphabet-index slip
        // cannot hide in the range nothing else exercises.
        let all: Vec<u8> = (0..=u8::MAX).collect();
        let encoded = encode(&all);
        assert_eq!(encoded.len(), 344);
        assert!(encoded.starts_with("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g"));
        assert!(encoded.ends_with("+/w=="));
    }
}
