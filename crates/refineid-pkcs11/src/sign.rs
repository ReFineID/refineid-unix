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

//! Sign path: parse the caller's input for the active mechanism,
//! then drive the FINEID card's pre-hashed PSO chain via
//! `refineid-lib-core`'s [`SignOps`].
//!
//! Two mechanisms are supported, one per card profile:
//!
//! - [`Mechanism::RsaPkcs`] ([`crate::ck::CKM_RSA_PKCS`]) for the
//!   RSA-3072 card (S4-1 v3.1). NSS hands us a full PKCS#1 v1.5
//!   `DigestInfo` DER; we accept exactly SHA-256, extract the
//!   32-byte digest, and the card produces the 384-byte PKCS#1
//!   signature.
//! - [`Mechanism::Ecdsa`] ([`crate::ck::CKM_ECDSA`]) for the ECC
//!   P-384 card (v4.0). NSS hands us the raw digest for whatever
//!   hash the TLS peer negotiated, fitted to the card's 48-byte
//!   slot by [`CkEcdsaDigest`]; the card returns the raw
//!   `r || s` (96 bytes), which is
//!   already the PKCS#11 `CKM_ECDSA` output format -- no DER
//!   wrapping (contrast the TLS backend, which DER-wraps for the
//!   wire).
//!
//! The digest parser is pure and unit-tested here; the card leg is
//! generic over any [`CardTransport`], so it sits behind a mockable
//! seam even though we do not ship a full-chain hardware mock.

use refineid_lib_core::crypto::digest::{Sha256, Sha384};
use refineid_lib_core::sign::KeyRef;
use refineid_lib_core::sign::SignOps as _;
use refineid_lib_core::transport::CardTransport;

use crate::ck::{
    CKM_ECDSA, CKM_RSA_PKCS, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR,
    CkMechanismType, CkRv,
};

/// RSA-3072 signature length in bytes (modulus `k`, RFC 8017 s3.1).
/// FINEID S4-1 v3.1 auth key; the two-call `C_Sign` size query
/// answers with this without touching the card.
pub const RSA3072_SIGNATURE_BYTES: usize = 384;
/// ECDSA P-384 raw signature length in bytes: `r || s`, each the
/// 48-byte field size (FIPS 186-4 / SEC1). This is the PKCS#11
/// `CKM_ECDSA` output length.
pub const ECDSA_P384_SIGNATURE_BYTES: usize = 96;
/// SHA-256 digest length in bytes (FIPS 180-4).
const SHA256_DIGEST_BYTES: usize = 32;
/// SHA-384 digest length in bytes (FIPS 180-4).
const SHA384_DIGEST_BYTES: usize = 48;

/// ASN.1 DER tag for `SEQUENCE` (X.690 s8.9; universal 16,
/// constructed).
const DER_TAG_SEQUENCE: u8 = 0x30;
/// ASN.1 DER tag for `OBJECT IDENTIFIER` (X.690 s8.19; universal 6).
const DER_TAG_OID: u8 = 0x06;
/// ASN.1 DER tag for `NULL` (X.690 s8.8; universal 5).
const DER_TAG_NULL: u8 = 0x05;
/// ASN.1 DER tag for `OCTET STRING` (X.690 s8.7; universal 4).
const DER_TAG_OCTET_STRING: u8 = 0x04;
/// X.690 s8.1.3.5: a length octet with bit 8 set marks long-form /
/// indefinite length. Every structure this parser accepts is short
/// (well under 128 bytes), so a value at or above this is rejected.
const DER_LONG_FORM_FLAG: u8 = 0x80;

/// DER value bytes of the SHA-256 OID `2.16.840.1.101.3.4.2.1`
/// (RFC 5754 s2.2; NIST). These are the OID contents (no tag/length)
/// carried inside a PKCS#1 v1.5 `DigestInfo` `AlgorithmIdentifier`.
const SHA256_OID_VALUE: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

/// The sign mechanism selected at `C_SignInit`, one per card
/// profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    /// `CKM_RSA_PKCS`: input is a PKCS#1 v1.5 `DigestInfo`; we accept
    /// SHA-256 only.
    RsaPkcs,
    /// `CKM_ECDSA`: input is the raw digest; we accept 48 bytes
    /// (SHA-384) only.
    Ecdsa,
}

impl Mechanism {
    /// Signature length this mechanism yields on its FINEID card
    /// profile. Used to answer the two-call `C_Sign` size query
    /// without a card round trip.
    #[must_use]
    pub(crate) const fn signature_len(self) -> usize {
        match self {
            Self::RsaPkcs => RSA3072_SIGNATURE_BYTES,
            Self::Ecdsa => ECDSA_P384_SIGNATURE_BYTES,
        }
    }

    /// The PKCS#11 mechanism type constant for this mechanism.
    #[must_use]
    pub(crate) const fn ck_type(self) -> CkMechanismType {
        match self {
            Self::RsaPkcs => CKM_RSA_PKCS,
            Self::Ecdsa => CKM_ECDSA,
        }
    }

    /// Map a PKCS#11 mechanism type to a supported [`Mechanism`], or
    /// `None` when the type is not one this module signs with.
    #[must_use]
    pub(crate) const fn from_ck_type(mechanism: CkMechanismType) -> Option<Self> {
        match mechanism {
            CKM_RSA_PKCS => Some(Self::RsaPkcs),
            CKM_ECDSA => Some(Self::Ecdsa),
            _ => None,
        }
    }
}

/// Reject a digest whose big-endian integer value is one of the
/// degenerate sentinels 0, 1 or -1 (all-`0x00`, all-`0x00` ending
/// `0x01`, all-`0xFF`), plus the little-endian rendering of 1.
///
/// No real hash of anything lands on these values -- but a zeroed
/// buffer (`memset(0)`, uninitialised struct), an off-by-one
/// length bug or an erased-flash fill does, and a signature over
/// such a "digest" would otherwise leave the module looking valid.
/// Same fail-closed posture as `Aes256Key::from_bytes` refusing
/// the all-zero / all-ones sentinels.
fn reject_degenerate_digest(digest: &[u8]) -> Result<(), CkRv> {
    let all_zero = digest.iter().all(|&b| b == 0);
    let all_ones = digest.iter().all(|&b| b == u8::MAX);
    let zeros_except_last = digest
        .split_last()
        .is_some_and(|(&last, head)| last == 1 && head.iter().all(|&b| b == 0));
    let zeros_except_first = digest
        .split_first()
        .is_some_and(|(&first, tail)| first == 1 && tail.iter().all(|&b| b == 0));
    if all_zero || all_ones || zeros_except_last || zeros_except_first {
        return Err(CKR_DATA_INVALID);
    }
    Ok(())
}

/// Split one DER TLV off the front of `data`, returning
/// `(tag, value, rest)`. Short-form lengths only (see
/// [`DER_LONG_FORM_FLAG`]); returns `None` on any truncation or
/// long-form length.
fn read_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (tag, after_tag) = data.split_first()?;
    let (len_byte, after_len) = after_tag.split_first()?;
    if *len_byte >= DER_LONG_FORM_FLAG {
        return None;
    }
    let len = usize::from(*len_byte);
    let value = after_len.get(..len)?;
    let rest = after_len.get(len..)?;
    Some((*tag, value, rest))
}

/// Parse a PKCS#1 v1.5 `DigestInfo` and return the embedded SHA-256
/// digest.
///
/// Accepts both the NULL-parameters and absent-parameters encodings
/// of the `AlgorithmIdentifier` (RFC 5754 s2 notes both appear in
/// the wild). Any non-SHA-256 digest OID, malformed structure, or a
/// digest of the wrong length is rejected with
/// [`CKR_DATA_INVALID`]: the mechanism (`CKM_RSA_PKCS`) is valid;
/// the caller data is not something this sign-only auth key will
/// produce.
///
/// # Errors
/// [`CKR_DATA_INVALID`] on any structural or digest-algorithm
/// mismatch.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is used by sibling token module and tests; plain pub would violate the public-surface typing grep"
)]
pub(super) fn parse_sha256_digest_info(input: &[u8]) -> Result<[u8; SHA256_DIGEST_BYTES], CkRv> {
    let (outer_tag, outer_body, outer_rest) = read_tlv(input).ok_or(CKR_DATA_INVALID)?;
    if outer_tag != DER_TAG_SEQUENCE || !outer_rest.is_empty() {
        return Err(CKR_DATA_INVALID);
    }
    let (alg_tag, alg_body, after_alg) = read_tlv(outer_body).ok_or(CKR_DATA_INVALID)?;
    if alg_tag != DER_TAG_SEQUENCE {
        return Err(CKR_DATA_INVALID);
    }
    let (oid_tag, oid_body, after_oid) = read_tlv(alg_body).ok_or(CKR_DATA_INVALID)?;
    if oid_tag != DER_TAG_OID || oid_body != SHA256_OID_VALUE {
        return Err(CKR_DATA_INVALID);
    }
    // Algorithm parameters: either absent, or an explicit NULL.
    match read_tlv(after_oid) {
        None => {
            if !after_oid.is_empty() {
                return Err(CKR_DATA_INVALID);
            }
        }
        Some((null_tag, null_body, after_null)) => {
            if null_tag != DER_TAG_NULL || !null_body.is_empty() || !after_null.is_empty() {
                return Err(CKR_DATA_INVALID);
            }
        }
    }
    let (digest_tag, digest_body, after_digest) = read_tlv(after_alg).ok_or(CKR_DATA_INVALID)?;
    if digest_tag != DER_TAG_OCTET_STRING || !after_digest.is_empty() {
        return Err(CKR_DATA_INVALID);
    }
    reject_degenerate_digest(digest_body)?;
    digest_body
        .try_into()
        .map_err(|_wrong_len| CKR_DATA_INVALID)
}

/// Run the card sign for `mechanism` over `input`.
///
/// The caller has already opened the card, selected the PKCS#15
/// application, and verified PIN1 on this connection (the FINEID
/// applet keeps the auth state for the subsequent PSO chain). For
/// RSA the input is a `DigestInfo`; for ECDSA it is the raw
/// digest, fitted to the card's 48-byte slot by
/// [`CkEcdsaDigest`].
///
/// # Errors
/// [`CKR_DATA_INVALID`] / [`CKR_DATA_LEN_RANGE`] on bad input,
/// [`CKR_DEVICE_ERROR`] if the card leg fails.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is used by sibling token module; plain pub would violate the public-surface typing grep"
)]
pub(super) fn sign_with_card<T: CardTransport>(
    transport: &mut T,
    mechanism: Mechanism,
    input: &[u8],
) -> Result<Vec<u8>, CkRv> {
    match mechanism {
        Mechanism::RsaPkcs => {
            let digest = parse_sha256_digest_info(input)?;
            let hash = Sha256::from_bytes(digest);
            let signature = transport
                .sign_pre_hashed_sha256_rsa_auth(hash)
                .map_err(|_sign_err| CKR_DEVICE_ERROR)?;
            Ok(signature.into_bytes())
        }
        Mechanism::Ecdsa => {
            let digest = CkEcdsaDigest::fit_p384(input)?;
            let signature = transport
                .sign_pre_hashed_sha384_ecdsa_p384(KeyRef::Auth, digest.into_card_hash())
                .map_err(|_sign_err| CKR_DEVICE_ERROR)?;
            // Raw r || s -- already the CKM_ECDSA output format.
            Ok(signature.into_bytes())
        }
    }
}

/// A `CKM_ECDSA` digest fitted to the 48 bytes the P-384 card leg
/// signs.
///
/// `CKM_ECDSA` (PKCS#11 v2.40 s6.4.1) takes the hash as an opaque
/// integer and leaves the hash choice to the consumer: NSS pairs
/// this key with whatever hash the TLS peer negotiated, so SHA-256
/// (32 bytes) arrives from a TLS 1.2 `CertificateRequest` just as
/// legitimately as SHA-384. The FINEID card leg is stricter -- its
/// SHA384-ECDSA algRef takes exactly 48 bytes -- so this type owns
/// the fit: ECDSA reduces the digest to an integer, meaning a
/// shorter digest is left-padded with zeros (the same integer) and
/// a longer one keeps its leftmost 384 bits (the spec's truncation
/// rule; `OpenSC` pads to the field length the same way). Empty and
/// degenerate (0 / 1 / -1 sentinel) inputs are refused -- see
/// [`reject_degenerate_digest`].
struct CkEcdsaDigest([u8; SHA384_DIGEST_BYTES]);

impl CkEcdsaDigest {
    /// Fit a raw `CKM_ECDSA` input to the P-384 field length.
    ///
    /// # Errors
    /// [`CKR_DATA_LEN_RANGE`] on an empty input;
    /// [`CKR_DATA_INVALID`] on a degenerate (0 / 1 / -1 sentinel)
    /// digest value -- see [`reject_degenerate_digest`].
    fn fit_p384(input: &[u8]) -> Result<Self, CkRv> {
        if input.is_empty() {
            return Err(CKR_DATA_LEN_RANGE);
        }
        reject_degenerate_digest(input)?;
        let mut digest = [0_u8; SHA384_DIGEST_BYTES];
        let take = input.len().min(SHA384_DIGEST_BYTES);
        let src = input.get(..take).ok_or(CKR_DATA_LEN_RANGE)?;
        let dst = digest
            .get_mut(SHA384_DIGEST_BYTES.saturating_sub(src.len())..)
            .ok_or(CKR_DATA_LEN_RANGE)?;
        dst.copy_from_slice(src);
        Ok(Self(digest))
    }

    /// Hand the fitted bytes to the card's SHA384-ECDSA leg.
    ///
    /// The card treats the 48 bytes as the integer to sign; it
    /// never re-hashes, so a fitted non-SHA-384 digest rides the
    /// same algRef and verifies under the consumer's hash choice.
    fn into_card_hash(self) -> Sha384 {
        Sha384::from_bytes(self.0)
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "unit tests build DigestInfo fixtures from compile-time byte literals and assert on known-good offsets; production code stays panic-free."
)]
mod tests {
    use super::{
        CKR_DATA_INVALID, CkEcdsaDigest, ECDSA_P384_SIGNATURE_BYTES, Mechanism,
        RSA3072_SIGNATURE_BYTES, parse_sha256_digest_info,
    };

    #[test]
    fn ecdsa_digest_sha384_passes_through() {
        let input: Vec<u8> = (0_u8..48_u8).collect();
        let digest = CkEcdsaDigest::fit_p384(&input).unwrap();
        assert_eq!(digest.0.as_slice(), input.as_slice());
    }

    #[test]
    fn ecdsa_digest_sha256_left_pads_to_the_same_integer() {
        let input: Vec<u8> = (1_u8..=32_u8).collect();
        let digest = CkEcdsaDigest::fit_p384(&input).unwrap();
        assert!(digest.0[..16].iter().all(|&byte| byte == 0));
        assert_eq!(&digest.0[16..], input.as_slice());
    }

    #[test]
    fn ecdsa_digest_sha512_keeps_the_leftmost_384_bits() {
        let input: Vec<u8> = (0_u8..64_u8).collect();
        let digest = CkEcdsaDigest::fit_p384(&input).unwrap();
        assert_eq!(digest.0.as_slice(), &input[..48]);
    }

    #[test]
    fn ecdsa_digest_rejects_empty_input() {
        assert!(CkEcdsaDigest::fit_p384(&[]).is_err());
    }

    /// The degenerate sentinels -- 0, -1 (`memset` / erased-flash
    /// fills) and 1 in either byte order -- are never the SHA-2
    /// output of anything; they are the signature of an
    /// uninitialised buffer upstream. Fail closed instead of
    /// signing them.
    #[test]
    fn ecdsa_digest_rejects_degenerate_values() {
        assert!(
            matches!(CkEcdsaDigest::fit_p384(&[0_u8; 48]), Err(CKR_DATA_INVALID)),
            "all-zero digest (integer 0)"
        );
        assert!(
            matches!(
                CkEcdsaDigest::fit_p384(&[u8::MAX; 32]),
                Err(CKR_DATA_INVALID)
            ),
            "all-ones digest (integer -1)"
        );
        let mut one_big_endian = [0_u8; 48];
        one_big_endian[47] = 1;
        assert!(
            matches!(
                CkEcdsaDigest::fit_p384(&one_big_endian),
                Err(CKR_DATA_INVALID)
            ),
            "big-endian integer 1"
        );
        let mut one_little_endian = [0_u8; 48];
        one_little_endian[0] = 1;
        assert!(
            matches!(
                CkEcdsaDigest::fit_p384(&one_little_endian),
                Err(CKR_DATA_INVALID)
            ),
            "little-endian integer 1"
        );
        // A single extra bit clears the sentinel test: the rule is
        // "not an uninitialised fill", not "high entropy".
        let mut nearly_one = [0_u8; 48];
        nearly_one[47] = 1;
        nearly_one[0] = 2;
        CkEcdsaDigest::fit_p384(&nearly_one).unwrap();
    }

    /// Same guard on the RSA `DigestInfo` leg.
    #[test]
    fn rsa_digest_info_rejects_all_zero_digest() {
        let mut info = digest_info_sha256_with_null();
        let digest_start = info.len() - 32;
        for byte in &mut info[digest_start..] {
            *byte = 0;
        }
        assert_eq!(parse_sha256_digest_info(&info), Err(CKR_DATA_INVALID));
    }

    /// A well-formed SHA-256 `DigestInfo` with explicit NULL
    /// parameters (RFC 8017 A.2.4), digest bytes 0x00..0x1F.
    fn digest_info_sha256_with_null() -> Vec<u8> {
        let mut out = vec![
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ];
        out.extend(0_u8..32_u8);
        out
    }

    /// The same digest with the `AlgorithmIdentifier` parameters
    /// absent instead of an explicit NULL.
    fn digest_info_sha256_absent_params() -> Vec<u8> {
        let mut out = vec![
            0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x04, 0x20,
        ];
        out.extend(0_u8..32_u8);
        out
    }

    #[test]
    fn accepts_sha256_with_null_params() {
        let info = digest_info_sha256_with_null();
        let digest = parse_sha256_digest_info(&info).unwrap();
        let expected: Vec<u8> = (0_u8..32_u8).collect();
        assert_eq!(digest.as_slice(), expected.as_slice());
    }

    #[test]
    fn accepts_sha256_with_absent_params() {
        let info = digest_info_sha256_absent_params();
        let digest = parse_sha256_digest_info(&info).unwrap();
        let expected: Vec<u8> = (0_u8..32_u8).collect();
        assert_eq!(digest.as_slice(), expected.as_slice());
    }

    #[test]
    fn rejects_sha1_digest_info() {
        // SHA-1 DigestInfo (RFC 8017 A.2.4): OID 1.3.14.3.2.26,
        // 20-byte digest.
        let mut info = vec![
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ];
        info.extend(core::iter::repeat_n(0_u8, 20));
        assert_eq!(parse_sha256_digest_info(&info), Err(CKR_DATA_INVALID));
    }

    #[test]
    fn rejects_sha384_digest_info() {
        // SHA-384 DigestInfo: OID 2.16.840.1.101.3.4.2.2, 48 bytes.
        let mut info = vec![
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ];
        info.extend(core::iter::repeat_n(0_u8, 48));
        assert_eq!(parse_sha256_digest_info(&info), Err(CKR_DATA_INVALID));
    }

    #[test]
    fn rejects_sha512_digest_info() {
        // SHA-512 DigestInfo: OID 2.16.840.1.101.3.4.2.3, 64 bytes.
        let mut info = vec![
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ];
        info.extend(core::iter::repeat_n(0_u8, 64));
        assert_eq!(parse_sha256_digest_info(&info), Err(CKR_DATA_INVALID));
    }

    #[test]
    fn rejects_truncated_and_trailing_garbage() {
        const STRAY_TRAILING_BYTE: u8 = 0;
        let info = digest_info_sha256_with_null();
        // Drop the last digest byte.
        let truncated = &info[..info.len().saturating_sub(1)];
        assert_eq!(parse_sha256_digest_info(truncated), Err(CKR_DATA_INVALID));
        // Append a stray byte after a complete structure.
        let mut trailing = info.clone();
        trailing.push(STRAY_TRAILING_BYTE);
        assert_eq!(parse_sha256_digest_info(&trailing), Err(CKR_DATA_INVALID));
    }

    #[test]
    fn mechanism_signature_lengths_match_card_profiles() {
        assert_eq!(Mechanism::RsaPkcs.signature_len(), RSA3072_SIGNATURE_BYTES);
        assert_eq!(Mechanism::Ecdsa.signature_len(), ECDSA_P384_SIGNATURE_BYTES);
    }
}
