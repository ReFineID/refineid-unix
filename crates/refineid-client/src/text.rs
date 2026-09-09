// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! Tiny text-codec helpers shared across CLI modules.
//!
//! base64 decode + PEM auto-detect. Both are minimal
//! RFC 4648 / RFC 7468 implementations -- enough for cert /
//! CSCA loading without reaching for the `base64` / `pem`
//! crates.

/// DER SEQUENCE tag byte (universal class, constructed, tag 16).
/// A DER-encoded `Certificate`, `SubjectPublicKeyInfo`, etc. all
/// start with this byte.
const DER_SEQUENCE_TAG: u8 = 0x30;

/// Base64 alphabet offset: `'a'..='z'` decode to indices 26..=51.
const BASE64_LOWERCASE_OFFSET: u8 = 26;
/// Base64 alphabet offset: `'0'..='9'` decode to indices 52..=61.
const BASE64_DIGIT_OFFSET: u8 = 52;
/// Base64 alphabet index for `'+'`.
const BASE64_PLUS: u8 = 62;
/// Base64 alphabet index for `'/'`.
const BASE64_SLASH: u8 = 63;
/// Bytes per base64 quantum on the wire.
const BASE64_QUANTUM_IN: usize = 4;
/// Decoded bytes per base64 quantum.
const BASE64_QUANTUM_OUT: usize = 3;

/// Auto-detect a certificate blob's wire form.
///
/// Accepts either raw DER (starts with `0x30` SEQUENCE tag) or a
/// PEM `CERTIFICATE` block (RFC 7468), and returns the decoded DER
/// body. Whitespace inside the base64 body is stripped before
/// decode. Every caller loads certificates, so the PEM label is
/// fixed rather than a parameter.
///
/// Returns `None` for input that's neither.
#[must_use]
pub(crate) fn decode_cert_pem_or_der(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.first() == Some(&DER_SEQUENCE_TAG) {
        return Some(bytes.to_vec());
    }
    let s = core::str::from_utf8(bytes).ok()?;
    let begin_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";
    let begin = s.find(begin_marker)?;
    let body_start = begin.checked_add(begin_marker.len())?;
    let tail = s.get(begin..)?;
    let end_offset = tail.find(end_marker)?;
    let body_end = begin.checked_add(end_offset)?;
    if body_end < body_start {
        return None;
    }
    let body = s.get(body_start..body_end)?;
    let cleaned: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    base64_decode(&cleaned)
}

/// Minimal RFC 4648 base64 decoder (standard alphabet, padded).
/// Returns `None` if the input length isn't a multiple of 4 or if
/// any non-alphabet character appears.
#[must_use]
pub(crate) fn base64_decode(s: &str) -> Option<Vec<u8>> {
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "match arms restrict b to the ASCII alphabet ranges; b - 'A' / b - 'a' + 26 / b - '0' + 52 are bounded by construction"
    )]
    const fn val(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + BASE64_LOWERCASE_OFFSET),
            b'0'..=b'9' => Some(b - b'0' + BASE64_DIGIT_OFFSET),
            b'+' => Some(BASE64_PLUS),
            b'/' => Some(BASE64_SLASH),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(BASE64_QUANTUM_IN) {
        return None;
    }
    // bytes.len() is a multiple of 4 here, so `len / 4` is exact and
    // `* 3` cannot overflow on any realistic input (we'd OOM first).
    let capacity = bytes
        .len()
        .checked_div(BASE64_QUANTUM_IN)
        .and_then(|q| q.checked_mul(BASE64_QUANTUM_OUT))
        .unwrap_or(0);
    let mut out = Vec::with_capacity(capacity);
    let mut i = 0_usize;
    while i < bytes.len() {
        // Safe to index: i is multiple of 4, bytes.len() is multiple
        // of 4, and the loop guard is i < bytes.len(). But use .get()
        // to stay panic-free as a discipline.
        let q: [u8; BASE64_QUANTUM_IN] = [
            *bytes.get(i)?,
            *bytes.get(i.checked_add(1)?)?,
            *bytes.get(i.checked_add(2)?)?,
            *bytes.get(i.checked_add(3)?)?,
        ];
        let v0 = val(q[0])?;
        let v1 = val(q[1])?;
        let v2 = if q[2] == b'=' { 0_u8 } else { val(q[2])? };
        let v3 = if q[3] == b'=' { 0_u8 } else { val(q[3])? };
        // All base64 digits fit in 6 bits; the shifts below stay
        // within u8 and the bit-or composes the result.
        out.push((v0 << 2_u32) | (v1 >> 4_u32));
        if q[2] != b'=' {
            out.push((v1 << 4_u32) | (v2 >> 2_u32));
        }
        if q[3] != b'=' {
            out.push((v2 << 6_u32) | v3);
        }
        i = i.checked_add(BASE64_QUANTUM_IN)?;
    }
    Some(out)
}

/// Render a [`DateTime`](refineid_lib_core::x509::DateTime) as
/// RFC 3339 `YYYY-MM-DDTHH:MM:SSZ` for the `card`/`cert` reports.
///
/// The trailing `Z` is fixed: `der::DateTime` is always UTC (RFC
/// 5280 sec.4.1.2.5 -- certs encode `UTCTime` / `GeneralizedTime`
/// in UTC). Zero-padding keeps report columns aligned.
#[must_use]
pub(crate) fn fmt_rfc3339(t: refineid_lib_core::x509::DateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(),
        t.month(),
        t.day(),
        t.hour(),
        t.minutes(),
        t.seconds()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_known_vectors() {
        assert_eq!(base64_decode("").as_deref(), Some(b"".as_slice()));
        assert_eq!(base64_decode("Zg==").as_deref(), Some(b"f".as_slice()));
        assert_eq!(base64_decode("Zm8=").as_deref(), Some(b"fo".as_slice()));
        assert_eq!(base64_decode("Zm9v").as_deref(), Some(b"foo".as_slice()));
        assert_eq!(
            base64_decode("Zm9vYg==").as_deref(),
            Some(b"foob".as_slice())
        );
        assert_eq!(
            base64_decode("Zm9vYmE=").as_deref(),
            Some(b"fooba".as_slice())
        );
        assert_eq!(
            base64_decode("Zm9vYmFy").as_deref(),
            Some(b"foobar".as_slice())
        );
    }

    #[test]
    fn base64_rejects_garbage() {
        assert!(base64_decode("ZZZ!").is_none()); // non-alphabet char
        assert!(base64_decode("AAA").is_none()); // length not %4
    }

    #[test]
    fn pem_with_matching_label_decodes() {
        let pem = b"-----BEGIN CERTIFICATE-----\nZm9vYmFy\n-----END CERTIFICATE-----\n";
        assert_eq!(decode_cert_pem_or_der(pem), Some(b"foobar".to_vec()));
    }

    #[test]
    fn pem_with_wrong_label_rejected() {
        let pem = b"-----BEGIN PRIVATE KEY-----\nZm9vYmFy\n-----END PRIVATE KEY-----\n";
        assert!(decode_cert_pem_or_der(pem).is_none());
    }

    #[test]
    fn raw_der_passes_through() {
        let der: Vec<u8> = vec![
            0x30_u8, 0x05_u8, 0xAA_u8, 0xBB_u8, 0xCC_u8, 0xDD_u8, 0xEE_u8,
        ];
        assert_eq!(decode_cert_pem_or_der(&der), Some(der));
    }
}
