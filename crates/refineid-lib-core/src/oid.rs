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

//! `Oid<'der>` -- typed wrapper around ASN.1 OBJECT IDENTIFIER
//! bytes.
//!
//! An OID at the wire is a single TLV value: BER tag `0x06`,
//! length, content bytes. Content bytes encode arcs in the
//! base-128 scheme of X.690 §8.19. Refineid handles a small
//! finite set of OIDs (signature algorithms, public-key
//! algorithms, named curves, X.500 DN attributes, X.509
//! extensions, ETSI QC statements, ICAO PKD identifiers), each
//! a constant lifted directly from the relevant RFC / spec.
//!
//! Strong-typing rationale: at every parser entry point we
//! already check `tlv.tag == 0x06`, but the resulting OID
//! bytes flow through the code as bare `&[u8]` -- the same
//! shape as any other byte slice. That permits a class of
//! mistakes the compiler should reject:
//!
//! - Comparing an OID against a signature value or a DN
//!   attribute *value* by accident.
//! - Passing arbitrary bytes where an OID is expected.
//! - Re-validating "is this an OID" downstream.
//!
//! `Oid<'der>` is a borrow over OID content bytes (the value
//! field of an OBJECT IDENTIFIER TLV, **not** including the
//! tag/length prefix). Construction does not reparse; it
//! tags an already-parsed byte slice as semantically an OID.
//! See [`doc/typing-discipline.md`][doc].
//!
//! [doc]: ../../../../doc/typing-discipline.md

use core::error::Error as CoreError;
use core::fmt;

/// Define an `Oid<'static>` from its dotted-decimal notation, parsed to
/// DER value bytes at compile time by `const_oid`. The OID's identity
/// (`2.16.840.1.101.3.4.2.1`) is what appears in source -- no
/// hand-transcribed hex to mis-key or mis-read. The `ObjectIdentifier`
/// temporary is const-promoted to `'static`, and its const `as_bytes()`
/// yields the tag/length-free body that our borrowed [`Oid`] wraps.
macro_rules! oid_dotted {
    ($dotted:literal) => {
        $crate::oid::Oid::const_new(::const_oid::ObjectIdentifier::new_unwrap($dotted).as_bytes())
    };
}

/// Borrowed OID content bytes. Constructor-tagged; downstream
/// `&Oid` consumers can rely on the value being an OID by
/// construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Oid<'der>(&'der [u8]);

/// Error returned by [`Oid::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OidError {
    /// Zero-length OID content. BER forbids this -- every OID
    /// has at least two arcs, encoded in at least one byte.
    Empty,
    /// Final byte has the high bit set, meaning the base-128
    /// arc is unterminated. Malformed per X.690 §8.19.
    UnterminatedArc,
}

impl<'der> Oid<'der> {
    /// The raw OID content bytes.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &'der [u8] {
        self.0
    }

    /// Wrap `bytes` as an OID without the structural check.
    ///
    /// Available in const context for static OID tables. The
    /// caller is responsible for the bytes actually being a
    /// valid OID; this is fine for hard-coded spec constants
    /// (e.g. `1.2.840.113549.1.1.13`) where the byte sequence
    /// is verifiable by inspection.
    #[inline]
    #[must_use]
    pub const fn const_new(bytes: &'der [u8]) -> Self {
        Self(bytes)
    }

    /// Wrap `bytes` as an OID after a structural check.
    ///
    /// `bytes` must be the **content** of an OBJECT IDENTIFIER
    /// TLV -- i.e. the value field, not the tag/length-prefixed
    /// encoding.
    ///
    /// # Errors
    /// - [`OidError::Empty`] on zero-length input.
    /// - [`OidError::UnterminatedArc`] when the final byte's
    ///   high bit is set (X.690 §8.19 forbids).
    #[inline]
    pub const fn new(bytes: &'der [u8]) -> Result<Self, OidError> {
        // `split_last` returns `None` on empty input and yields a
        // direct reference to the final byte otherwise -- avoids
        // both the `bytes.len() - 1` underflow concern and the
        // `bytes[...]` panic-on-OOB in a `const fn` context where
        // `?` and `.get(...).copied().ok_or(...)` aren't available.
        let Some((last, _)) = bytes.split_last() else {
            return Err(OidError::Empty);
        };
        if *last & 0x80 != 0 {
            return Err(OidError::UnterminatedArc);
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for Oid<'_> {
    /// Dotted-decimal X.660 representation, e.g.
    /// `1.2.840.113549.1.1.13`. Always rejects-or-renders
    /// based on the byte content; never panics, because
    /// well-formed OIDs always have at least one byte and
    /// our constructor enforces that.
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        /// First-byte arc divisor: arc1 = first / 40 (X.690 §8.19.4).
        const ARC_BASE: u8 = 40_u8;
        /// arc1 is clamped to {0, 1, 2}.
        const ARC1_CLAMP: u8 = 2_u8;
        /// When arc1 == 2 the first-byte bias is 80 = 2 * 40.
        const ARC2_BIAS: u8 = 80_u8;
        /// Base-128 shift per continuation byte.
        const ARC_SHIFT: u32 = 7_u32;
        /// Low-seven-bit mask for the arc value within a continuation byte.
        const CONT_MASK: u8 = 0x7F_u8;
        /// High bit marks "another byte follows" in the base-128 form.
        const END_MASK: u8 = 0x80_u8;
        // First byte encodes the first two arcs: `arc1 * 40 + arc2`.
        // `split_first` lets us peel `first` off and walk the
        // remaining bytes without indexing or sub-slicing the input.
        let Some((&first, rest)) = self.0.split_first() else {
            // Defensive: const_new could in principle produce
            // an empty Oid. Render as the literal empty form
            // rather than panicking.
            return f.write_str("(empty-oid)");
        };
        // X.690 §8.19.4: arc1 is in {0, 1, 2}; first-byte values
        // < 80 mean `arc1 in {0, 1}` (via `first / 40`), values
        // >= 80 mean `arc1 == 2` with the overflow rolled into
        // arc2 (`first - 80`). `u8::div_euclid(40)` / `rem_euclid`
        // make the truncation explicit; the `saturating_sub(80)`
        // can never saturate because we only enter the branch
        // when `first / 40 > 2` i.e. `first >= 80`.
        let arc1_raw = first.div_euclid(ARC_BASE);
        let arc2_raw = first.rem_euclid(ARC_BASE);
        let (arc1, arc2) = if arc1_raw > ARC1_CLAMP {
            (ARC1_CLAMP, first.saturating_sub(ARC2_BIAS))
        } else {
            (arc1_raw, arc2_raw)
        };
        write!(f, "{arc1}.{arc2}")?;
        // Subsequent arcs: base-128 with high-bit continuation.
        // The `<< 7` shift can technically overflow u128 for a
        // pathologically long arc (>18 continuation bytes); the
        // wire form caps every arc at ~127 bits in practice, but
        // wrapping is the documented protocol-defensive choice.
        let mut acc = 0_u128;
        for &byte in rest {
            acc = (acc.wrapping_shl(ARC_SHIFT)) | u128::from(byte & CONT_MASK);
            if byte & END_MASK == 0 {
                write!(f, ".{acc}")?;
                acc = 0_u128;
            }
        }
        Ok(())
    }
}

impl fmt::Display for OidError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Empty => f.write_str("OID content cannot be empty"),
            Self::UnterminatedArc => {
                f.write_str("OID's final byte has the high bit set (arc unterminated)")
            }
        }
    }
}

impl CoreError for OidError {}

impl PartialEq<&[u8]> for Oid<'_> {
    #[inline]
    fn eq(&self, other: &&[u8]) -> bool {
        self.0 == *other
    }
}

impl<'der> PartialEq<Oid<'der>> for &[u8] {
    #[inline]
    fn eq(&self, other: &Oid<'der>) -> bool {
        *self == other.0
    }
}

/// Static, well-known OIDs refineid recognises. Defined once
/// here; modules that need a particular OID re-export the
/// constant they care about rather than duplicating the byte
/// arrays.
///
/// Each constant is written in its dotted-decimal notation and
/// parsed to DER value bytes at compile time by `const_oid` (via
/// the `oid_dotted!` macro), so the OID's *identity* is what
/// appears in source -- no hand-transcribed hex to mis-key.
pub mod known {
    use super::Oid;

    // ---- AIA access methods ----

    /// `1.3.6.1.5.5.7.48.2` -- id-ad-caIssuers.
    pub const AD_CA_ISSUERS: Oid<'static> = oid_dotted!("1.3.6.1.5.5.7.48.2");

    /// `1.3.6.1.5.5.7.48.1` -- id-ad-ocsp.
    pub const AD_OCSP: Oid<'static> = oid_dotted!("1.3.6.1.5.5.7.48.1");

    // ---- PKIX private extensions (RFC 5280, id-pkix.1) ----

    /// `1.3.6.1.5.5.7.1.1` -- id-pe-authorityInfoAccess.
    pub const AUTHORITY_INFO_ACCESS: Oid<'static> = oid_dotted!("1.3.6.1.5.5.7.1.1");

    // ---- X.509 standard extensions (RFC 5280, id-ce = 2.5.29) ----

    /// `2.5.29.19` -- id-ce-basicConstraints (critical in FINEID S2).
    pub const BASIC_CONSTRAINTS: Oid<'static> = oid_dotted!("2.5.29.19");

    /// `2.5.29.32` -- id-ce-certificatePolicies.
    pub const CERTIFICATE_POLICIES: Oid<'static> = oid_dotted!("2.5.29.32");

    // ---- Named elliptic curves ----

    /// `1.3.36.3.3.2.8.1.1.7` -- brainpoolP256r1.
    pub const BRAINPOOL_P256R1: Oid<'static> = oid_dotted!("1.3.36.3.3.2.8.1.1.7");

    /// `1.3.36.3.3.2.8.1.1.11` -- brainpoolP384r1.
    pub const BRAINPOOL_P384R1: Oid<'static> = oid_dotted!("1.3.36.3.3.2.8.1.1.11");

    // ---- X.500 directory attribute types (RFC 4519, X.520) ----

    /// `2.5.4.3` -- id-at-commonName.
    pub const COMMON_NAME: Oid<'static> = oid_dotted!("2.5.4.3");

    /// `2.5.4.6` -- id-at-countryName.
    pub const COUNTRY_NAME: Oid<'static> = oid_dotted!("2.5.4.6");

    /// `2.5.29.31` -- id-ce-cRLDistributionPoints.
    pub const CRL_DISTRIBUTION_POINTS: Oid<'static> = oid_dotted!("2.5.29.31");

    /// `2.5.29.21` -- id-ce-cRLReason.
    pub const CRL_REASON: Oid<'static> = oid_dotted!("2.5.29.21");

    /// `1.2.840.10045.4.3.2` -- ecdsa-with-SHA256.
    pub const ECDSA_WITH_SHA256: Oid<'static> = oid_dotted!("1.2.840.10045.4.3.2");

    /// `1.2.840.10045.4.3.3` -- ecdsa-with-SHA384 (FINEID ECC cert signature alg).
    pub const ECDSA_WITH_SHA384: Oid<'static> = oid_dotted!("1.2.840.10045.4.3.3");

    /// `1.2.840.10045.4.3.4` -- ecdsa-with-SHA512.
    pub const ECDSA_WITH_SHA512: Oid<'static> = oid_dotted!("1.2.840.10045.4.3.4");

    /// `1.2.840.10045.2.1` -- ecPublicKey.
    pub const EC_PUBLIC_KEY: Oid<'static> = oid_dotted!("1.2.840.10045.2.1");

    /// `2.5.29.37` -- id-ce-extKeyUsage.
    pub const EXT_KEY_USAGE: Oid<'static> = oid_dotted!("2.5.29.37");

    /// `2.5.4.42` -- id-at-givenName.
    pub const GIVEN_NAME: Oid<'static> = oid_dotted!("2.5.4.42");

    // ---- ICAO PKD ----

    /// `2.23.136.1.1.1` -- id-icao-mrtd-security-ldsSecurityObject
    /// (ICAO 9303-10) -- the SOD eContentType.
    pub const ICAO_LDS_SECURITY_OBJECT: Oid<'static> = oid_dotted!("2.23.136.1.1.1");

    /// `2.23.136.1.1.3` -- id-icao-cscaMasterListSignedData (ICAO 9303-12).
    pub const ICAO_ML_SIGNER: Oid<'static> = oid_dotted!("2.23.136.1.1.3");

    /// `2.5.29.15` -- id-ce-keyUsage (critical in FINEID S2).
    pub const KEY_USAGE: Oid<'static> = oid_dotted!("2.5.29.15");

    /// `2.5.29.30` -- id-ce-nameConstraints.
    pub const NAME_CONSTRAINTS: Oid<'static> = oid_dotted!("2.5.29.30");

    // ---- Extended key usage purposes (RFC 5280) ----

    /// `1.3.6.1.5.5.7.3.2` -- id-kp-clientAuth.
    pub const KP_CLIENT_AUTH: Oid<'static> = oid_dotted!("1.3.6.1.5.5.7.3.2");

    /// `1.3.6.1.5.5.7.3.3` -- id-kp-codeSigning.
    pub const KP_CODE_SIGNING: Oid<'static> = oid_dotted!("1.3.6.1.5.5.7.3.3");

    /// `1.3.6.1.5.5.7.3.4` -- id-kp-emailProtection.
    pub const KP_EMAIL_PROTECTION: Oid<'static> = oid_dotted!("1.3.6.1.5.5.7.3.4");

    /// `1.3.6.1.5.5.7.3.9` -- id-kp-OCSPSigning.
    pub const KP_OCSP_SIGNING: Oid<'static> = oid_dotted!("1.3.6.1.5.5.7.3.9");

    /// `1.3.6.1.5.5.7.48.1.5` -- id-pkix-ocsp-nocheck.
    pub const OCSP_NO_CHECK: Oid<'static> = oid_dotted!("1.3.6.1.5.5.7.48.1.5");

    /// `1.3.6.1.5.5.7.3.1` -- id-kp-serverAuth.
    pub const KP_SERVER_AUTH: Oid<'static> = oid_dotted!("1.3.6.1.5.5.7.3.1");

    /// `1.3.6.1.5.5.7.3.8` -- id-kp-timeStamping.
    pub const KP_TIME_STAMPING: Oid<'static> = oid_dotted!("1.3.6.1.5.5.7.3.8");

    // ---- Signature & public-key algorithms (PKCS #1, ANSI X9.62) ----
    //
    // FINEID S2 v5.2 §6.2.2 / §6.3.7 pins the citizen-card set:
    // - sha512WithRSAEncryption + rsaEncryption for RSA chains
    // - ecdsa-with-SHA384 + ecPublicKey on secp256r1 / secp384r1
    //   for ECC chains.

    /// `1.2.840.113549.1.1.1` -- rsaEncryption (PKCS #1).
    pub const RSA_ENCRYPTION: Oid<'static> = oid_dotted!("1.2.840.113549.1.1.1");

    /// `1.2.840.113549.1.1.10` -- id-RSASSA-PSS (PKCS #1).
    pub const RSASSA_PSS: Oid<'static> = oid_dotted!("1.2.840.113549.1.1.10");

    /// `1.2.840.10045.3.1.7` -- secp256r1 / prime256v1 (FINEID citizen ECC).
    pub const SECP256R1: Oid<'static> = oid_dotted!("1.2.840.10045.3.1.7");

    /// `1.3.132.0.34` -- secp384r1 (FINEID citizen ECC and everything else ECC).
    pub const SECP384R1: Oid<'static> = oid_dotted!("1.3.132.0.34");

    /// `2.5.4.5` -- id-at-serialNumber.
    pub const SERIAL_NUMBER: Oid<'static> = oid_dotted!("2.5.4.5");

    /// `1.2.840.113549.1.1.11` -- sha256WithRSAEncryption.
    pub const SHA256_WITH_RSA: Oid<'static> = oid_dotted!("1.2.840.113549.1.1.11");

    /// `1.3.14.3.2.26` -- id-sha1 (OIW). Referenced only to PROVE
    /// rejection: SHA-1 is not accepted anywhere on the citizen path.
    pub const SHA1: Oid<'static> = oid_dotted!("1.3.14.3.2.26");

    /// `1.2.840.113549.1.1.12` -- sha384WithRSAEncryption.
    pub const SHA384_WITH_RSA: Oid<'static> = oid_dotted!("1.2.840.113549.1.1.12");

    /// `1.2.840.113549.1.1.13` -- sha512WithRSAEncryption (FINEID RSA cert signature alg).
    pub const SHA512_WITH_RSA: Oid<'static> = oid_dotted!("1.2.840.113549.1.1.13");

    /// `2.5.29.17` -- id-ce-subjectAltName.
    pub const SUBJECT_ALT_NAME: Oid<'static> = oid_dotted!("2.5.29.17");

    /// `2.5.29.14` -- id-ce-subjectKeyIdentifier.
    pub const SUBJECT_KEY_IDENTIFIER: Oid<'static> = oid_dotted!("2.5.29.14");

    /// `2.5.4.4` -- id-at-surname.
    pub const SURNAME: Oid<'static> = oid_dotted!("2.5.4.4");

    // ---- Message-digest algorithms (NIST, FIPS 180-4) ----

    /// `2.16.840.1.101.3.4.2.1` -- id-sha256.
    pub const SHA256: Oid<'static> = oid_dotted!("2.16.840.1.101.3.4.2.1");

    /// `2.16.840.1.101.3.4.2.2` -- id-sha384.
    pub const SHA384: Oid<'static> = oid_dotted!("2.16.840.1.101.3.4.2.2");

    /// `2.16.840.1.101.3.4.2.3` -- id-sha512.
    pub const SHA512: Oid<'static> = oid_dotted!("2.16.840.1.101.3.4.2.3");

    // ---- CMS / PKCS#7 (RFC 5652) ----

    /// `1.2.840.113549.1.7.1` -- id-data.
    pub const DATA: Oid<'static> = oid_dotted!("1.2.840.113549.1.7.1");

    /// `1.2.840.113549.1.7.2` -- id-signedData.
    pub const SIGNED_DATA: Oid<'static> = oid_dotted!("1.2.840.113549.1.7.2");

    /// `1.2.840.113549.1.9.3` -- id-contentType (CMS signed attribute).
    pub const CONTENT_TYPE: Oid<'static> = oid_dotted!("1.2.840.113549.1.9.3");

    /// `1.2.840.113549.1.9.4` -- id-messageDigest (CMS signed attribute).
    pub const MESSAGE_DIGEST: Oid<'static> = oid_dotted!("1.2.840.113549.1.9.4");

    /// `1.2.840.113549.1.9.5` -- id-signingTime (CMS signed attribute).
    pub const SIGNING_TIME: Oid<'static> = oid_dotted!("1.2.840.113549.1.9.5");

    /// `1.2.840.113549.1.9.16.1.4` -- id-ct-TSTInfo.
    ///
    /// RFC 3161. This is the eContentType of a `TimeStampToken`'s CMS
    /// `SignedData`; the signed eContent is a DER `TSTInfo`.
    pub const TST_INFO: Oid<'static> = oid_dotted!("1.2.840.113549.1.9.16.1.4");

    /// `1.3.6.1.5.5.7.16.2` -- id-ri-ocsp-response.
    ///
    /// RFC 5940. Names an OCSP response inside a CMS `crls` field,
    /// which has no CHOICE for one of its own.
    pub const OCSP_RESPONSE_REVOCATION_INFO: Oid<'static> = oid_dotted!("1.3.6.1.5.5.7.16.2");

    /// `1.2.840.113549.1.9.16.2.14` -- id-aa-signatureTimeStampToken.
    ///
    /// RFC 3161 appendix A. Carries a TSA's token as an *unsigned*
    /// attribute: it is computed over the signature, so it cannot be
    /// inside what the signature covers.
    pub const SIGNATURE_TIME_STAMP_TOKEN: Oid<'static> = oid_dotted!("1.2.840.113549.1.9.16.2.14");

    /// `1.2.840.113549.1.9.16.2.47` -- id-aa-signingCertificateV2.
    ///
    /// RFC 5035 sec.3, and mandatory in `CAdES`: it binds the signature
    /// to the one certificate that made it, so a signature cannot be
    /// replayed against another certificate carrying the same key.
    pub const SIGNING_CERTIFICATE_V2: Oid<'static> = oid_dotted!("1.2.840.113549.1.9.16.2.47");

    /// `1.2.840.113549.1.9.16.2.12` -- id-aa-signingCertificate.
    ///
    /// RFC 2634 sec.5.4.1. This is the original SHA-1 ESS certificate
    /// binding; RFC 3161 requires a signing-certificate attribute, while
    /// RFC 5035 defines the SHA-2-capable v2 replacement above.
    pub const SIGNING_CERTIFICATE: Oid<'static> = oid_dotted!("1.2.840.113549.1.9.16.2.12");

    // ---- OCSP response types (RFC 6960) ----

    /// `1.3.6.1.5.5.7.48.1.1` -- id-pkix-ocsp-basic.
    pub const BASIC_OCSP_RESPONSE: Oid<'static> = oid_dotted!("1.3.6.1.5.5.7.48.1.1");

    // ---- EC field type (ANSI X9.62) ----

    /// `1.2.840.10045.1.1` -- prime-field.
    pub const PRIME_FIELD: Oid<'static> = oid_dotted!("1.2.840.10045.1.1");

    // ---- ICAO PKD (additional) ----

    /// `2.23.136.1.1.2` -- id-icao-cscaMasterList (CMS eContentType).
    pub const CSCA_MASTER_LIST: Oid<'static> = oid_dotted!("2.23.136.1.1.2");

    // ---- PACE mechanism (BSI TR-03110-3) ----

    /// `0.4.0.127.0.7.2.2.4.2.4` -- id-PACE-ECDH-GM-AES-CBC-CMAC-256.
    /// The OID body (no DER tag/length): pasted into the MSE:Set AT
    /// mechanism DO and wrapped in `06` for the PACE auth-tag MAC input.
    pub const PACE_ECDH_GM_AES_CBC_CMAC_256: Oid<'static> = oid_dotted!("0.4.0.127.0.7.2.2.4.2.4");
}

#[cfg(test)]
mod tests {

    use super::{Oid, OidError, known};

    #[test]
    fn rejects_empty() {
        assert_eq!(Oid::new(&[]), Err(OidError::Empty));
    }

    #[test]
    fn rejects_unterminated_arc() {
        // Final byte's MSB set -- malformed.
        assert_eq!(
            Oid::new(&[0x55, 0x04, 0x83]),
            Err(OidError::UnterminatedArc)
        );
    }

    #[test]
    fn accepts_three_arc_dn_oid() {
        let oid = Oid::new(&[0x55, 0x04, 0x03]).expect("commonName DER encoding parses");
        assert_eq!(oid.as_bytes(), &[0x55, 0x04, 0x03]);
    }

    #[test]
    fn partialeq_against_byte_slice() {
        let oid = Oid::new(&[0x55, 0x04, 0x03]).expect("commonName DER encoding parses");
        let bytes: &[u8] = &[0x55, 0x04, 0x03];
        assert_eq!(oid, bytes);
        assert_eq!(bytes, oid);
    }

    #[test]
    fn display_dn_common_name() {
        assert_eq!(format!("{}", known::COMMON_NAME), "2.5.4.3");
    }

    #[test]
    fn display_dn_country_name() {
        assert_eq!(format!("{}", known::COUNTRY_NAME), "2.5.4.6");
    }

    #[test]
    fn display_dn_given_name() {
        // 0x2A = 42, a single-byte arc value past 40, so the
        // dotted form uses 42 directly.
        assert_eq!(format!("{}", known::GIVEN_NAME), "2.5.4.42");
    }

    #[test]
    fn display_rsa_signature() {
        assert_eq!(
            format!("{}", known::SHA512_WITH_RSA),
            "1.2.840.113549.1.1.13"
        );
    }

    #[test]
    fn display_rsa_encryption() {
        assert_eq!(format!("{}", known::RSA_ENCRYPTION), "1.2.840.113549.1.1.1");
    }

    #[test]
    fn display_ecdsa_signature() {
        assert_eq!(
            format!("{}", known::ECDSA_WITH_SHA384),
            "1.2.840.10045.4.3.3"
        );
    }

    #[test]
    fn display_ec_public_key() {
        assert_eq!(format!("{}", known::EC_PUBLIC_KEY), "1.2.840.10045.2.1");
    }

    #[test]
    fn display_secp256r1() {
        assert_eq!(format!("{}", known::SECP256R1), "1.2.840.10045.3.1.7");
    }

    #[test]
    fn display_secp384r1() {
        assert_eq!(format!("{}", known::SECP384R1), "1.3.132.0.34");
    }

    #[test]
    fn display_key_usage() {
        assert_eq!(format!("{}", known::KEY_USAGE), "2.5.29.15");
    }

    #[test]
    fn display_basic_constraints() {
        assert_eq!(format!("{}", known::BASIC_CONSTRAINTS), "2.5.29.19");
    }

    #[test]
    fn display_aia() {
        assert_eq!(
            format!("{}", known::AUTHORITY_INFO_ACCESS),
            "1.3.6.1.5.5.7.1.1"
        );
    }

    #[test]
    fn display_ad_ocsp() {
        assert_eq!(format!("{}", known::AD_OCSP), "1.3.6.1.5.5.7.48.1");
    }

    #[test]
    fn display_icao_ml_signer() {
        // 2.23.136.1.1.3 -- 2*40+23=103 doesn't fit in one byte
        // so first byte is 0x67 = 103; remaining arcs are
        // 136, 1, 1, 3 base-128 encoded.
        assert_eq!(format!("{}", known::ICAO_ML_SIGNER), "2.23.136.1.1.3");
    }

    #[test]
    fn const_new_byte_equality() {
        // Bytes match between const_new and runtime new of the
        // same OID -- the const constructor doesn't mangle.
        let runtime = Oid::new(&[0x55, 0x04, 0x03]).expect("commonName DER encoding parses");
        assert_eq!(known::COMMON_NAME.as_bytes(), runtime.as_bytes());
    }
}
