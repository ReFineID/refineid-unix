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

//! Minimal X.509 v3 certificate parser, scoped to what
//! card-status needs.
//!
//! Extracts: serial number, issuer DN bytes, subject DN bytes,
//! the subject's common name, the validity window, the CRL
//! distribution-point URLs, and the OCSP responder URLs carried
//! in v3 extensions.
//!
//! Layered on `ber`; no full ASN.1 stack pulled in. The
//! parser is deliberately narrow: it does **not** verify
//! signatures, does **not** parse public-key parameters (that
//! lives in `crypto::*` once the PIN-protected paths port), and
//! does **not** interpret name attributes beyond the subject CN.
//! Fields hold references into the input DER -- the caller owns
//! the backing buffer.

use crate::ber::Oid as BerOid;
use crate::ber::{
    BerError, BerTag, BerTlv, BerTlvAny, BerTlvIter, BitString, Boolean, Integer, OctetString,
    Sequence,
};
use crate::crypto::container::{
    EcdsaDer, RsaPkcs1Sha256, RsaPkcs1Sha384, RsaPkcs1Sha512, RsaPssSha256, Signature,
};
use crate::crypto::ecdsa::{
    EcdsaError, Sec1UncompressedPoint, extract_ec_pubkey, verify_prehashed,
};
use crate::crypto::rsa::{
    RsaModulus, RsaPublicExponent, RsaPublicKey, RsaVerifyError, verify_pkcs1v15_sha384,
    verify_pkcs1v15_sha512,
};
use crate::oid::{Oid, known};
use spki::der::asn1::AnyRef;

// Module-local context-specific markers. The universal-class
// tags come from `ber`; these are the X.509-specific [n]
// wrappers RFC 5280 mandates.

/// `[0] EXPLICIT` (tag 0xA0). RFC 5280 uses this for the TBS
/// `Version` field and for the `OtherName` `GeneralName`
/// variant inside SAN extensions.
#[derive(Debug, Clone, Copy)]
pub struct X509ContextExplicit0;
impl BerTag for X509ContextExplicit0 {
    const TAG: u16 = 0xA0;
}

/// `[3] EXPLICIT` (tag 0xA3). RFC 5280 §4.1's TBS Extensions
/// wrapper.
#[derive(Debug, Clone, Copy)]
pub struct X509ContextExplicit3;
impl BerTag for X509ContextExplicit3 {
    const TAG: u16 = 0xA3;
}

// SAN GeneralName tags (IMPLICIT [n])
/// `TAG_GN_RFC822_NAME` constant.
const TAG_GN_RFC822_NAME: u16 = 0x81; // [1] IA5String -- email
/// `TAG_GN_URI` constant.
const TAG_GN_URI: u16 = 0x86; // [6] IA5String

/// Universal ASN.1 NULL tag used by the OCSP no-check extension.
const TAG_NULL: u16 = 0x05;

// CRL DistributionPoint internal tags
/// `TAG_DP_DISTRIBUTION_POINT_NAME` constant.
const TAG_DP_DISTRIBUTION_POINT_NAME: u16 = 0xA0; // [0] EXPLICIT
/// `TAG_DP_FULL_NAME` constant.
const TAG_DP_FULL_NAME: u16 = 0xA0; // [0] IMPLICIT GeneralNames

// ----- OIDs -----
//
// Aliases of the canonical `crate::oid::known` constants
// (typed `Oid<'static>`), kept under their familiar short
// local names so call sites read naturally. One source of
// truth for the byte sequences is in `crate::oid`; if you
// need a new OID, add it there and re-alias here.

/// `OID_COMMON_NAME` constant.
const OID_COMMON_NAME: Oid<'static> = known::COMMON_NAME;
/// `OID_COUNTRY_NAME` constant.
const OID_COUNTRY_NAME: Oid<'static> = known::COUNTRY_NAME;
/// `OID_SURNAME` constant.
const OID_SURNAME: Oid<'static> = known::SURNAME;
/// id-at-serialNumber (the DN attribute -- distinct from the
/// certificate's own serialNumber INTEGER). FINEID puts the
/// PEUIN here.
const OID_DN_SERIAL_NUMBER: Oid<'static> = known::SERIAL_NUMBER;
/// `OID_GIVEN_NAME` constant.
const OID_GIVEN_NAME: Oid<'static> = known::GIVEN_NAME;
/// `OID_KEY_USAGE` constant.
const OID_KEY_USAGE: Oid<'static> = known::KEY_USAGE;
/// `OID_BASIC_CONSTRAINTS` constant.
const OID_BASIC_CONSTRAINTS: Oid<'static> = known::BASIC_CONSTRAINTS;
/// id-icao-mlSigner -- EKU OID that ICAO Doc 9303 §12
/// requires on a CSCA Master List Signer cert.
pub const OID_ICAO_ML_SIGNER: Oid<'static> = known::ICAO_ML_SIGNER;
/// `OID_SUBJECT_ALT_NAME` constant.
const OID_SUBJECT_ALT_NAME: Oid<'static> = known::SUBJECT_ALT_NAME;
/// `OID_CRL_DISTRIBUTION_POINTS` constant.
const OID_CRL_DISTRIBUTION_POINTS: Oid<'static> = known::CRL_DISTRIBUTION_POINTS;
/// `OID_EXT_KEY_USAGE` constant.
const OID_EXT_KEY_USAGE: Oid<'static> = known::EXT_KEY_USAGE;

/// `OID_RSA_ENCRYPTION` constant.
const OID_RSA_ENCRYPTION: Oid<'static> = known::RSA_ENCRYPTION;
/// `OID_EC_PUBLIC_KEY` constant.
const OID_EC_PUBLIC_KEY: Oid<'static> = known::EC_PUBLIC_KEY;

/// `OID_SECP384R1` constant.
const OID_SECP384R1: Oid<'static> = known::SECP384R1;
/// `OID_SECP256R1` constant.
const OID_SECP256R1: Oid<'static> = known::SECP256R1;
/// `OID_BRAINPOOL_P384R1` constant.
const OID_BRAINPOOL_P384R1: Oid<'static> = known::BRAINPOOL_P384R1;
/// `OID_BRAINPOOL_P256R1` constant.
const OID_BRAINPOOL_P256R1: Oid<'static> = known::BRAINPOOL_P256R1;

/// `OID_KP_SERVER_AUTH` constant.
const OID_KP_SERVER_AUTH: Oid<'static> = known::KP_SERVER_AUTH;
/// `OID_KP_CLIENT_AUTH` constant.
const OID_KP_CLIENT_AUTH: Oid<'static> = known::KP_CLIENT_AUTH;
/// `OID_KP_CODE_SIGNING` constant.
const OID_KP_CODE_SIGNING: Oid<'static> = known::KP_CODE_SIGNING;
/// `OID_KP_EMAIL_PROTECTION` constant.
const OID_KP_EMAIL_PROTECTION: Oid<'static> = known::KP_EMAIL_PROTECTION;
/// `OID_KP_TIME_STAMPING` constant.
const OID_KP_TIME_STAMPING: Oid<'static> = known::KP_TIME_STAMPING;
/// `OID_KP_OCSP_SIGNING` constant.
const OID_KP_OCSP_SIGNING: Oid<'static> = known::KP_OCSP_SIGNING;
/// `OID_AUTHORITY_INFO_ACCESS` constant.
const OID_AUTHORITY_INFO_ACCESS: Oid<'static> = known::AUTHORITY_INFO_ACCESS;
/// `OID_AD_OCSP` constant.
const OID_AD_OCSP: Oid<'static> = known::AD_OCSP;
/// `OID_AD_CA_ISSUERS` constant.
const OID_AD_CA_ISSUERS: Oid<'static> = known::AD_CA_ISSUERS;

// ----- Errors -----

/// Parse errors from the X.509 decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X509Error {
    /// BER / DER-level decode failure inside the cert body
    /// (mismatched tag, truncated length, etc.). The wrapped
    /// `BerError` carries the specific failure mode.
    Ber(BerError),
    /// Top-level shape doesn't match `Certificate ::= SEQUENCE {
    /// TBSCertificate, AlgorithmIdentifier, BIT STRING }`. The
    /// `&'static str` payload names the substructure that
    /// failed to match (e.g. `"tbsCertificate"`).
    UnexpectedStructure(&'static str),
    /// `UTCTime` / `GeneralizedTime` body didn't parse.
    InvalidTime,
    /// String body wasn't valid UTF-8 / printable ASCII.
    InvalidString,
    /// BER-level decode failure at a known structural position.
    /// The `&'static str` names the substructure (as for
    /// [`X509Error::UnexpectedStructure`]); the wrapped
    /// `BerError` carries the specific BER-layer failure mode
    /// (truncated, unexpected tag, ...).
    BerInContext(BerError, &'static str),
}

impl From<BerError> for X509Error {
    #[inline]
    fn from(e: BerError) -> Self {
        Self::Ber(e)
    }
}

impl core::fmt::Display for X509Error {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ber(e) => write!(f, "X.509 BER: {e}"),
            Self::UnexpectedStructure(s) => write!(f, "X.509: unexpected structure ({s})"),
            Self::InvalidTime => write!(f, "X.509: invalid time encoding"),
            Self::InvalidString => write!(f, "X.509: invalid string encoding"),
            Self::BerInContext(e, s) => write!(f, "X.509: BER decode at {s}: {e}"),
        }
    }
}

impl core::error::Error for X509Error {}

// ----- Types -----

/// X.509 v3 certificate, parsed for card-status purposes.
///
/// `Copy` since every field is either an `&'a [u8]` borrow or a
/// `Copy` typed wrapper -- the struct is just a bundle of views
/// over the same input buffer. Cheap to pass by value.
#[derive(Debug, Clone, Copy)]
pub struct Certificate<'a> {
    /// Whole certificate DER as handed in.
    pub raw_der: &'a [u8],
    /// `tbsCertificate` SEQUENCE bytes including its outer tag +
    /// length -- exactly the bytes covered by the signature.
    pub tbs_der: &'a [u8],
    /// `serialNumber` INTEGER value bytes (no tag, no length).
    /// Preserved as-is so the leading sign byte (if any) is
    /// caller-visible for OCSP and CRL comparisons.
    pub serial_der: &'a [u8],
    /// `issuer` Distinguished Name (the whole `Name` SEQUENCE,
    /// outer tag/length included). Typed [`Name`] so attribute
    /// lookups are methods and the DN bytes -- needed for an OCSP
    /// `IssuerNameHash` -- come out via [`Name::as_der`].
    pub issuer: Name<'a>,
    /// `subject` Distinguished Name as a typed [`Name`] view.
    pub subject: Name<'a>,
    /// `notBefore` from the cert's validity window (RFC 5280
    /// §4.1.2.5). Decoded from `UTCTime` / `GeneralizedTime` by
    /// x509-cert -- the `UTCTime` year is normalised to 4 digits
    /// per RFC 5280 §4.1.2.5.1.
    pub not_before: DateTime,
    /// `notAfter` from the cert's validity window. See
    /// [`Certificate::not_before`] for the encoding rules; the
    /// pair `(not_before, not_after)` defines the cert's
    /// temporal validity per RFC 5280 §4.1.2.5.
    pub not_after: DateTime,
    /// `subjectPublicKeyInfo`, parse-validated at cert-parse
    /// time. Access the DER bytes via [`SpkiDer::as_der`] and
    /// the algorithm summary via [`SpkiDer::algorithm`].
    pub spki: SpkiDer<'a>,
    /// `extensions` SEQUENCE value bytes (inside the `[3]` EXPLICIT
    /// wrapper) -- a sequence of Extension SEQUENCEs, ready for
    /// per-OID lookup. `None` for cert v1.
    pub extensions: Option<&'a [u8]>,
    /// Signature algorithm OID body (the value of the `06 LL`
    /// TLV inside `signatureAlgorithm`). E.g.
    /// `1.2.840.113549.1.1.11` for sha256WithRSAEncryption.
    /// Typed via [`crate::oid::Oid`] -- the parser validates the
    /// OID structure at the cert-parse trust boundary.
    pub signature_alg_oid: Oid<'a>,
    /// `signature` BIT STRING value bytes, with the leading
    /// "unused bits" byte stripped. RSA signatures are `k`
    /// bytes (modulus length); ECDSA signatures are a DER
    /// `SEQUENCE { r, s }`.
    pub signature_bits: &'a [u8],
}

impl Certificate<'_> {
    /// Typed serial-number view over the parser's `serial_der`
    /// borrow. Allocates the wrapper's owned byte buffer so the
    /// returned [`crate::identity::CertSerial`] is independent
    /// of the certificate borrow.
    #[must_use]
    #[inline]
    pub fn serial(&self) -> crate::identity::CertSerial {
        crate::identity::CertSerial::from_bytes(self.serial_der.to_vec())
    }

    /// Verify that this certificate was signed by `issuer`. Looks
    /// up the signature algorithm from `self` and pulls the
    /// issuer's public key from the issuer cert's SPKI.
    ///
    /// `issuer` is taken by value (`Certificate<'_>` is a small
    /// `Copy`-friendly view of borrowed fields, so this is no
    /// more expensive than passing a reference).
    ///
    /// # Errors
    /// [`VerifyError`] as for the inner signature-verification
    /// helpers (unsupported algorithm, RSA verify failure, etc.).
    #[inline]
    pub fn verify_signed_by(&self, issuer: Certificate<'_>) -> Result<(), VerifyError> {
        verify_tbs_signature(TbsSignature {
            tbs_der: self.tbs_der,
            signature_alg_oid: self.signature_alg_oid.as_bytes(),
            signature_bits: self.signature_bits,
            issuer_spki_der: issuer.spki.as_der(),
        })
    }
}

/// A typed X.509 `Name` (Distinguished Name) view.
///
/// Wraps the DER bytes of a `RDNSequence`, with attribute lookups as
/// methods so callers pass a `Name`, never a raw `&[u8]` DN blob. The
/// bytes are already parse-validated when the `Name` comes from a
/// [`Certificate`]; [`Name::try_from`] is the boundary that mints one
/// from raw bytes.
///
/// `PartialEq`/`Eq` compare the underlying DN DER byte-for-byte --
/// the exact-match test certificate-chain building uses to pair a
/// subject DN against an issuer DN (RFC 5280 §6.1 name chaining,
/// the byte-identical case).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Name<'a> {
    /// DER bytes of the `RDNSequence` (the whole `Name` SEQUENCE).
    dn_der: &'a [u8],
}

impl<'a> Name<'a> {
    /// Wrap DN bytes already validated upstream (e.g. the
    /// `subject`/`issuer` field of a parsed [`Certificate`]). No
    /// re-check -- the cert parse established the structure.
    #[must_use]
    #[inline]
    pub(crate) const fn from_validated(dn_der: &'a [u8]) -> Self {
        Self { dn_der }
    }

    /// The DN's DER bytes (e.g. for an OCSP `IssuerNameHash`).
    #[must_use]
    #[inline]
    pub const fn as_der(&self) -> &'a [u8] {
        self.dn_der
    }

    /// `commonName` (X.520 `cn`, OID 2.5.4.3).
    #[must_use]
    #[inline]
    pub fn common_name(&self) -> Option<crate::identity::CommonName> {
        crate::identity::CommonName::new(self.dn_attribute(OID_COMMON_NAME)?).ok()
    }

    /// `surname` (X.520 `sn`, OID 2.5.4.4).
    #[must_use]
    #[inline]
    pub fn surname(&self) -> Option<crate::identity::Surname> {
        crate::identity::Surname::new(self.dn_attribute(OID_SURNAME)?).ok()
    }

    /// `givenName` (X.520 `gn`, OID 2.5.4.42), split into typed slots.
    #[must_use]
    #[inline]
    pub fn given_names(&self) -> crate::identity::SplitGivenNames {
        self.dn_attribute(OID_GIVEN_NAME).map_or_else(
            crate::identity::SplitGivenNames::default,
            |raw| {
                crate::identity::GivenNamesText::new(raw).map_or_else(
                    |_err| crate::identity::SplitGivenNames::default(),
                    |text| text.split(),
                )
            },
        )
    }

    /// PEUIN / SATU from the `serialNumber` DN attribute (OID 2.5.4.5).
    #[must_use]
    #[inline]
    pub fn peuin(&self) -> Option<crate::identity::Peuin> {
        crate::identity::Peuin::new(&self.dn_attribute(OID_DN_SERIAL_NUMBER)?).ok()
    }

    /// `countryName` (OID 2.5.4.6) as a typed ISO 3166-1 alpha-2.
    #[must_use]
    #[inline]
    pub fn country(&self) -> Option<crate::country::IsoAlpha2> {
        crate::country::IsoAlpha2::new(self.dn_attribute(OID_COUNTRY_NAME)?.trim()).ok()
    }

    /// Return the first DN attribute whose OID body matches `oid_body`.
    fn dn_attribute(&self, oid_body: Oid<'_>) -> Option<String> {
        use spki::der::asn1::AnyRef;
        use spki::der::{Decode as _, Reader as _, SliceReader, Tag, Tagged as _};

        let name = AnyRef::from_der(self.dn_der).ok()?;
        if name.tag() != Tag::Sequence {
            return None;
        }
        let mut rdns = SliceReader::new(name.value()).ok()?;
        let mut found: Option<String> = None;
        while !rdns.is_finished() {
            let rdn = AnyRef::from_der(rdns.tlv_bytes().ok()?).ok()?;
            if rdn.tag() != Tag::Set {
                continue;
            }
            let mut atvs = SliceReader::new(rdn.value()).ok()?;
            while !atvs.is_finished() {
                let atv = AnyRef::from_der(atvs.tlv_bytes().ok()?).ok()?;
                if atv.tag() != Tag::Sequence {
                    continue;
                }
                let mut fields = SliceReader::new(atv.value()).ok()?;
                let oid = AnyRef::from_der(fields.tlv_bytes().ok()?).ok()?;
                let val = AnyRef::from_der(fields.tlv_bytes().ok()?).ok()?;
                if oid.tag() == Tag::ObjectIdentifier
                    && oid.value() == oid_body.as_bytes()
                    && let Some(s) = X509Helpers::decode_directory_string(val)
                {
                    found = Some(s);
                }
            }
        }
        found
    }
}

/// Boundary parser: mint a [`Name`] from raw DN DER, validating it
/// decodes as a `RDNSequence` SEQUENCE.
impl<'a> TryFrom<&'a [u8]> for Name<'a> {
    type Error = X509Error;
    #[inline]
    fn try_from(dn_der: &'a [u8]) -> Result<Self, X509Error> {
        use spki::der::asn1::AnyRef;
        use spki::der::{Decode as _, Tag, Tagged as _};
        let any = AnyRef::from_der(dn_der)
            .map_err(|_ignored| X509Error::UnexpectedStructure("Name not a TLV"))?;
        if any.tag() != Tag::Sequence {
            return Err(X509Error::UnexpectedStructure("Name not SEQUENCE"));
        }
        Ok(Self::from_validated(dn_der))
    }
}

/// Owning wrapper around a parsed X.509 certificate.
///
/// Holds the cert's DER bytes plus a re-parseable view. Public
/// entry point under typing-discipline rule D: free
/// `parse_certificate` returns `Certificate<'_>` (a borrowed
/// view tied to the input) so the rule-D-clean form is to wrap
/// the bytes in an [`OwnedCert`] and call [`OwnedCert::view`]
/// when a borrowed view is needed.
#[derive(Debug, Clone)]
pub struct OwnedCert {
    /// `der` field.
    der: Vec<u8>,
}

impl OwnedCert {
    /// Parse `der` as an X.509 certificate, allocating an owned
    /// copy of the bytes so the wrapper is independent of the
    /// input borrow.
    ///
    /// # Errors
    /// [`X509Error`] from the cert parser.
    #[inline]
    pub fn from_der<B: AsRef<[u8]>>(der: B) -> Result<Self, X509Error> {
        let bytes = der.as_ref().to_vec();
        Certificate::from_der(&bytes)?;
        Ok(Self { der: bytes })
    }

    /// Re-parse the owned DER and hand back the borrowed view.
    ///
    /// # Performance
    /// Parses the DER on **every call** (O(n) in the DER length). For
    /// repeated field access bind the view once (`let cert = owned.view();`)
    /// and reuse it, rather than calling `view()` per field.
    ///
    /// # Panics
    /// Never -- [`from_der`] validated at construction.
    ///
    /// [`from_der`]: Self::from_der.
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "invariant: OwnedCert::from_der ran parse_certificate over the same byte buffer; re-parse of identical bytes cannot fail."
    )]
    #[inline]
    pub fn view(&self) -> Certificate<'_> {
        Certificate::from_der(&self.der).expect("invariant: from_der validated DER at construction")
    }

    /// Raw DER bytes the wrapper owns.
    #[must_use]
    #[inline]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }

    /// Consume the wrapper and return the owned DER bytes.
    #[must_use]
    #[inline]
    pub fn into_der(self) -> Vec<u8> {
        self.der
    }

    /// Typed serial-number view; see [`Certificate::serial`].
    #[must_use]
    #[inline]
    pub fn serial(&self) -> crate::identity::CertSerial {
        self.view().serial()
    }
}

/// X.509 validity / revocation instants are surfaced as the `der`
/// crate's [`DateTime`] (`der::DateTime`), re-exported here so the
/// whole workspace shares one canonical time type. Both `UTCTime`
/// (`17`) and `GeneralizedTime` (`18`) decode into it; the x509-cert
/// decoders normalise a `UTCTime` `YY` per RFC 5280 §4.1.2.5.1
/// (`YY < 50 -> 20YY`, else `19YY`).
///
/// `der::DateTime` is anchored to the Unix epoch, so its floor is
/// 1970-01-01 and it carries `Ord` / `unix_duration` directly. X.509
/// postdates 1970, so the floor never excludes a real certificate
/// instant.
pub use spki::der::DateTime;

// ----- Public parsing entrypoint -----

/// Parse a complete X.509 v3 certificate DER blob.
///
/// # Errors
/// Any BER-level decode failure, or a top-level shape that
/// doesn't look like `Certificate ::= SEQUENCE { TBSCertificate,
/// AlgorithmIdentifier, BIT STRING }`.
impl<'a> Certificate<'a> {
    /// Parse a complete X.509 v3 certificate DER blob.
    ///
    /// # Errors
    /// Any BER-level decode failure, or a top-level shape that does not
    /// look like `Certificate ::= SEQUENCE { TBSCertificate,
    /// AlgorithmIdentifier, BIT STRING }`.
    pub(crate) fn from_der(der: &'a [u8]) -> Result<Self, X509Error> {
        // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
        // signature }. Walk the three children with the vetted `der`
        // reader, capturing each as its exact input-borrowed TLV slice
        // (Reader::tlv_bytes) -- tbsCertificate therefore stays the
        // precise signed bytes (no re-encode), with no hand-rolled walk.
        use spki::der::asn1::AnyRef;
        use spki::der::{Decode as _, Reader as _, SliceReader, Tag, Tagged as _};

        let cert = AnyRef::from_der(der)
            .map_err(|_ignored| X509Error::UnexpectedStructure("Certificate not a TLV"))?;
        if cert.tag() != Tag::Sequence {
            return Err(X509Error::UnexpectedStructure("Certificate not SEQUENCE"));
        }
        let mut reader = SliceReader::new(cert.value())
            .map_err(|_ignored| X509Error::UnexpectedStructure("Certificate body"))?;
        // tbsCertificate -- the exact bytes the issuer signed.
        let tbs_der = reader
            .tlv_bytes()
            .map_err(|_ignored| X509Error::UnexpectedStructure("tbsCertificate"))?;
        let sig_alg_tlv = reader
            .tlv_bytes()
            .map_err(|_ignored| X509Error::UnexpectedStructure("signatureAlgorithm"))?;
        let sig_tlv = reader
            .tlv_bytes()
            .map_err(|_ignored| X509Error::UnexpectedStructure("signature"))?;

        // signatureAlgorithm SEQUENCE { OID, params? } -- the OID body
        // (input-borrowed) feeds the project's Oid wrapper. `Oid::new`
        // rejects empty content / unterminated arcs.
        let sig_alg = AnyRef::from_der(sig_alg_tlv).map_err(|_ignored| {
            X509Error::UnexpectedStructure("signatureAlgorithm not SEQUENCE")
        })?;
        let mut alg_reader = SliceReader::new(sig_alg.value())
            .map_err(|_ignored| X509Error::UnexpectedStructure("signatureAlgorithm body"))?;
        let oid_tlv = alg_reader
            .tlv_bytes()
            .map_err(|_ignored| X509Error::UnexpectedStructure("signatureAlgorithm OID missing"))?;
        let oid_any = AnyRef::from_der(oid_tlv).map_err(|_ignored| {
            X509Error::UnexpectedStructure("signatureAlgorithm OID malformed")
        })?;
        let signature_alg_oid = Oid::new(oid_any.value()).or(Err(
            X509Error::UnexpectedStructure("signatureAlgorithm OID malformed"),
        ))?;

        // signature BIT STRING -- strip the leading "unused bits" octet.
        let sig_any = AnyRef::from_der(sig_tlv)
            .map_err(|_ignored| X509Error::UnexpectedStructure("signature not a TLV"))?;
        let signature_bits = sig_any
            .value()
            .get(1..)
            .ok_or(X509Error::UnexpectedStructure(
                "signature BIT STRING missing",
            ))?;

        parse_tbs(tbs_der, der, signature_alg_oid, signature_bits)
    }
}

/// Decode a `TBSCertificate` SEQUENCE into a borrowing
/// [`Certificate`].
///
/// RFC 5280 §4.1.2 -- `TBSCertificate` carries every field
/// covered by the issuer's signature. `tbs_der` is the
/// unwrapped SEQUENCE bytes (the parser pre-strips the outer
/// tag); `raw` is the full certificate DER; `signature_alg_oid`
/// and `signature_bits` come from the outer wrapper. Caller
/// has already verified that the wrapper's `signatureAlgorithm`
/// matches the TBS's inner `signature` field.
fn parse_tbs<'a>(
    tbs_der: &'a [u8],
    raw: &'a [u8],
    signature_alg_oid: Oid<'a>,
    signature_bits: &'a [u8],
) -> Result<Certificate<'a>, X509Error> {
    // tbsCertificate ::= SEQUENCE {
    //     version         [0] EXPLICIT Version DEFAULT v1,
    //     serialNumber    INTEGER,
    //     signature       AlgorithmIdentifier,
    //     issuer          Name,
    //     validity        SEQUENCE { notBefore Time, notAfter Time },
    //     subject         Name,
    //     subjectPublicKeyInfo SubjectPublicKeyInfo,
    //     ...
    //     extensions      [3] EXPLICIT Extensions OPTIONAL
    // }
    use spki::der::asn1::AnyRef;
    use spki::der::{Decode as _, Reader as _, SliceReader, Tag, TagNumber, Tagged as _};

    // [0] EXPLICIT version wrapper / [3] EXPLICIT extensions wrapper
    // context tags (constructed).
    const VERSION_TAG: Tag = Tag::ContextSpecific {
        constructed: true,
        number: TagNumber(0),
    };
    const EXTENSIONS_TAG: Tag = Tag::ContextSpecific {
        constructed: true,
        number: TagNumber(3),
    };

    let tbs = AnyRef::from_der(tbs_der)
        .map_err(|_ignored| X509Error::UnexpectedStructure("tbsCertificate not a TLV"))?;
    if tbs.tag() != Tag::Sequence {
        return Err(X509Error::UnexpectedStructure(
            "tbsCertificate not SEQUENCE",
        ));
    }
    let mut reader = SliceReader::new(tbs.value())
        .map_err(|_ignored| X509Error::UnexpectedStructure("tbsCertificate body"))?;

    // version [0] EXPLICIT (optional) then serialNumber INTEGER. Read
    // the first child; if it is the [0] wrapper, the serial is next.
    let first = AnyRef::from_der(
        reader
            .tlv_bytes()
            .map_err(|_ignored| X509Error::UnexpectedStructure("TBS first field"))?,
    )
    .map_err(|_ignored| X509Error::UnexpectedStructure("TBS first field"))?;
    let serial_any = if first.tag() == VERSION_TAG {
        AnyRef::from_der(
            reader
                .tlv_bytes()
                .map_err(|_ignored| X509Error::UnexpectedStructure("serialNumber"))?,
        )
        .map_err(|_ignored| X509Error::UnexpectedStructure("serialNumber"))?
    } else {
        first
    };
    // serialNumber INTEGER value bytes (no tag/length), as before.
    let serial_der = serial_any.value();

    // signature AlgorithmIdentifier -- skip wholesale.
    reader
        .tlv_bytes()
        .map_err(|_ignored| X509Error::UnexpectedStructure("TBS signature alg"))?;

    // issuer Name -- the whole SEQUENCE bytes (tag/len/value).
    // The cert-parse walk validated the SEQUENCE structure, so wrap
    // via the already-validated constructor.
    let issuer = Name::from_validated(
        reader
            .tlv_bytes()
            .map_err(|_ignored| X509Error::UnexpectedStructure("issuer"))?,
    );

    // validity SEQUENCE { notBefore, notAfter } -- decoded by
    // x509-cert from the whole TLV bytes.
    let validity_tlv = reader
        .tlv_bytes()
        .map_err(|_ignored| X509Error::UnexpectedStructure("validity"))?;
    let validity =
        x509_cert::time::Validity::<x509_cert::certificate::Rfc5280>::from_der(validity_tlv)
            .map_err(|_ignored| X509Error::InvalidTime)?;
    let (not_before, not_after) = (
        validity.not_before.to_date_time(),
        validity.not_after.to_date_time(),
    );

    // subject Name -- the whole SEQUENCE bytes.
    let subject = Name::from_validated(
        reader
            .tlv_bytes()
            .map_err(|_ignored| X509Error::UnexpectedStructure("subject"))?,
    );

    // subjectPublicKeyInfo -- whole SEQUENCE bytes, parse-validated
    // via SpkiDer.
    let spki_der_bytes = reader
        .tlv_bytes()
        .map_err(|_ignored| X509Error::UnexpectedStructure("subjectPublicKeyInfo"))?;
    let spki: SpkiDer<'_> = spki_der_bytes.try_into()?;

    // Remaining children may be issuerUniqueID [1], subjectUniqueID
    // [2], and extensions [3] EXPLICIT. We only care about extensions.
    let mut extensions: Option<&[u8]> = None;
    while !reader.is_finished() {
        let child = AnyRef::from_der(
            reader
                .tlv_bytes()
                .map_err(|_ignored| X509Error::UnexpectedStructure("TBS trailing field"))?,
        )
        .map_err(|_ignored| X509Error::UnexpectedStructure("TBS trailing field"))?;
        if child.tag() == EXTENSIONS_TAG {
            // [3] EXPLICIT wraps a SEQUENCE OF Extension; carry that
            // inner SEQUENCE's value bytes.
            let inner_seq = AnyRef::from_der(child.value())
                .map_err(|_ignored| X509Error::UnexpectedStructure("extensions not SEQUENCE"))?;
            extensions = Some(inner_seq.value());
        }
    }

    Ok(Certificate {
        raw_der: raw,
        tbs_der,
        serial_der,
        issuer,
        subject,
        not_before,
        not_after,
        spki,
        extensions,
        signature_alg_oid,
        signature_bits,
    })
}

/// Borrowed certificate extensions block.
#[derive(Clone, Copy)]
struct ExtensionBytes<'a> {
    /// SEQUENCE OF Extension value bytes.
    value: &'a [u8],
}

/// Helpers hosted on a unit struct (typing-discipline: no
/// free fns with borrowed parameters; see
/// `doc/typing-discipline.md`).
struct X509Helpers;

impl X509Helpers {
    /// Walk the Authority Information Access extension and collect
    /// the URI `accessLocation`s for one `accessMethod` OID
    /// (`id-ad-ocsp` or `id-ad-caIssuers`), RFC 5280 sec.4.2.2.1.
    ///
    /// ```text
    /// AuthorityInfoAccessSyntax ::= SEQUENCE OF AccessDescription
    /// AccessDescription ::= SEQUENCE { accessMethod OID,
    ///                                  accessLocation GeneralName }
    /// ```
    fn aia_urls_for(
        extensions: ExtensionBytes<'_>,
        access_method: Oid<'_>,
    ) -> Vec<crate::text::Uri> {
        use spki::der::asn1::AnyRef;
        use spki::der::{Decode as _, Reader as _, SliceReader, Tag, TagNumber, Tagged as _};

        // GeneralName uniformResourceIdentifier [6] IMPLICIT IA5String.
        const GN_URI: Tag = Tag::ContextSpecific {
            constructed: false,
            number: TagNumber(6),
        };

        let mut urls = Vec::new();
        let Some(extn_value) = Self::find_extension(extensions.value, OID_AUTHORITY_INFO_ACCESS)
        else {
            return urls;
        };
        let Ok(outer) = AnyRef::from_der(extn_value) else {
            return urls;
        };
        if outer.tag() != Tag::Sequence {
            return urls;
        }
        let Ok(mut reader) = SliceReader::new(outer.value()) else {
            return urls;
        };
        while !reader.is_finished() {
            let Ok(ad_bytes) = reader.tlv_bytes() else {
                break;
            };
            let Ok(ad) = AnyRef::from_der(ad_bytes) else {
                continue;
            };
            if ad.tag() != Tag::Sequence {
                continue;
            }
            let Ok(mut fields) = SliceReader::new(ad.value()) else {
                continue;
            };
            let Ok(oid) = fields.tlv_bytes().map(AnyRef::from_der) else {
                continue;
            };
            let Ok(oid) = oid else { continue };
            if oid.tag() != Tag::ObjectIdentifier || oid.value() != access_method.as_bytes() {
                continue;
            }
            let Ok(loc) = fields.tlv_bytes().map(AnyRef::from_der) else {
                continue;
            };
            let Ok(loc) = loc else { continue };
            if loc.tag() == GN_URI
                && let Ok(s) = core::str::from_utf8(loc.value())
                && let Ok(url) = crate::text::Uri::parse(s.to_owned())
            {
                urls.push(url);
            }
        }
        urls
    }

    /// `decode_directory_string` associated function.
    fn decode_directory_string(value: AnyRef<'_>) -> Option<String> {
        use spki::der::{Tag, Tagged as _};
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "der::Tag has ~25 variants; only the DirectoryString string types decode to text, every other ASN.1 tag is None"
        )]
        match value.tag() {
            Tag::Utf8String => core::str::from_utf8(value.value()).ok().map(String::from),
            Tag::PrintableString | Tag::Ia5String | Tag::TeletexString => value
                .value()
                .iter()
                .all(u8::is_ascii)
                .then(|| String::from_utf8_lossy(value.value()).into_owned()),
            Tag::BmpString => {
                if !value.value().len().is_multiple_of(2) {
                    return None;
                }
                // UTF-16 code units are pairs of bytes; the
                // multiple-of-2 guard above makes the divide exact.
                let cap = value.value().len().div_euclid(2);
                let mut out = String::with_capacity(cap);
                for chunk in value.value().chunks_exact(2) {
                    // chunks_exact(2) yields slices of length exactly 2;
                    // .first() / .get(1) on each cannot return None.
                    let hi = *chunk.first()?;
                    let lo = *chunk.get(1)?;
                    let code = u32::from(u16::from_be_bytes([hi, lo]));
                    out.push(char::from_u32(code)?);
                }
                Some(out)
            }
            _ => None,
        }
    }

    /// Find the first extension whose OID matches `oid_value`
    /// and return the wrapped `extnValue` OCTET STRING contents
    /// (the inner DER). The extension SEQUENCE is `{ OID,
    /// BOOLEAN critical OPTIONAL, OCTET STRING extnValue }`.
    fn find_extension<'a>(extensions: &'a [u8], oid_value: Oid<'_>) -> Option<&'a [u8]> {
        find_extension_with_meta(extensions, oid_value).map(|m| m.value)
    }
}

/// Same as `find_extension` but also reports whether the
/// extension carried `critical = TRUE`. Per RFC 5280 the
/// `critical` BOOLEAN defaults to FALSE when absent.
#[must_use]
pub(crate) fn find_extension_with_meta<'a>(
    extensions: &'a [u8],
    oid_value: Oid<'_>,
) -> Option<ExtensionMeta<'a>> {
    use spki::der::asn1::AnyRef;
    use spki::der::{Decode as _, Reader as _, SliceReader, Tag, Tagged as _};

    // Walk the SEQUENCE OF Extension with the vetted der reader.
    let mut reader = SliceReader::new(extensions).ok()?;
    while !reader.is_finished() {
        let ext = AnyRef::from_der(reader.tlv_bytes().ok()?).ok()?;
        if ext.tag() != Tag::Sequence {
            continue;
        }
        // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN
        // DEFAULT FALSE, extnValue OCTET STRING }.
        let mut fields = SliceReader::new(ext.value()).ok()?;
        let oid = AnyRef::from_der(fields.tlv_bytes().ok()?).ok()?;
        if oid.tag() != Tag::ObjectIdentifier || oid.value() != oid_value.as_bytes() {
            continue;
        }
        // Optional `critical BOOLEAN` -- absent encodes FALSE.
        let mut next = AnyRef::from_der(fields.tlv_bytes().ok()?).ok()?;
        let mut critical = false;
        if next.tag() == Tag::Boolean {
            critical = next.value().first().is_some_and(|&b| b != 0);
            next = AnyRef::from_der(fields.tlv_bytes().ok()?).ok()?;
        }
        if next.tag() != Tag::OctetString {
            return None;
        }
        return Some(ExtensionMeta {
            value: next.value(),
            critical,
        });
    }
    None
}

/// Per-extension metadata returned by `find_extension_with_meta`.
#[derive(Debug, Clone, Copy)]
pub struct ExtensionMeta<'a> {
    /// The `extnValue` OCTET STRING contents (the inner DER).
    pub value: &'a [u8],
    /// `true` when the extension carried `critical = TRUE`. RFC
    /// 5280 defaults absent to FALSE.
    pub critical: bool,
}

/// Extract CRL distribution-point URLs from a parsed extensions
/// block. Returns an empty vector when the cert has no CDP
/// extension or no URI-typed `GeneralName` inside.
///
/// ```text
/// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
/// DistributionPoint ::= SEQUENCE {
///     distributionPoint   [0] DistributionPointName OPTIONAL,
///     reasons             [1] ReasonFlags OPTIONAL,
///     cRLIssuer           [2] GeneralNames OPTIONAL }
/// DistributionPointName ::= CHOICE {
///     fullName            [0] GeneralNames,
///     nameRelativeToCRLIssuer [1] RelativeDistinguishedName }
/// ```
#[must_use]
#[inline]
pub fn extract_crl_distribution_urls<B: AsRef<[u8]>>(extensions: B) -> Vec<crate::text::Uri> {
    let extensions = extensions.as_ref();
    let Some(extn_value) = X509Helpers::find_extension(extensions, OID_CRL_DISTRIBUTION_POINTS)
    else {
        return Vec::new();
    };
    let Ok(outer) = BerTlv::<Sequence>::parse(extn_value) else {
        return Vec::new();
    };
    let mut urls = Vec::new();
    for dp in BerTlvIter::new(outer.value) {
        let Ok(dp) = dp.and_then(BerTlvAny::expect::<Sequence>) else {
            continue;
        };
        // Walk the inner fields, looking for [0] distributionPoint.
        for field in BerTlvIter::new(dp.value) {
            let Ok(field) = field else { continue };
            if field.tag != TAG_DP_DISTRIBUTION_POINT_NAME {
                continue;
            }
            // Inside the EXPLICIT [0] we expect the CHOICE
            // DistributionPointName encoded with its IMPLICIT tag
            // [0] GeneralNames -> 0xA0 (constructed) holding
            // GeneralName entries with their own context tags.
            for gn_wrap in BerTlvIter::new(field.value) {
                let Ok(gn_wrap) = gn_wrap else { continue };
                if gn_wrap.tag != TAG_DP_FULL_NAME {
                    continue;
                }
                for gn in BerTlvIter::new(gn_wrap.value) {
                    let Ok(gn) = gn else { continue };
                    // Filter URI GeneralNames to http(s) at parse
                    // time -- S2 §6.3.8.5 deprecates LDAP CDP and
                    // refineid's HTTP client doesn't speak other
                    // schemes anyway. Uri::parse rejects.
                    if gn.tag == TAG_GN_URI
                        && let Ok(s) = core::str::from_utf8(gn.value)
                        && let Ok(url) = crate::text::Uri::parse(s.to_owned())
                    {
                        urls.push(url);
                    }
                }
            }
        }
    }
    urls
}

/// Extract OCSP responder URLs from the Authority Information
/// Access extension. Returns an empty vector when the cert has
/// no AIA extension or no id-ad-ocsp `accessDescription`.
///
/// ```text
/// AuthorityInfoAccessSyntax ::= SEQUENCE OF AccessDescription
/// AccessDescription ::= SEQUENCE {
///     accessMethod    OBJECT IDENTIFIER,
///     accessLocation  GeneralName }
/// ```
#[must_use]
#[inline]
pub fn extract_ocsp_urls<B: AsRef<[u8]>>(extensions: B) -> Vec<crate::text::Uri> {
    X509Helpers::aia_urls_for(
        ExtensionBytes {
            value: extensions.as_ref(),
        },
        OID_AD_OCSP,
    )
}

/// Extract `caIssuers` URLs from the Authority Information
/// Access extension (RFC 5280 sec.4.2.2.1).
///
/// Each URL points to a HTTP-fetchable copy of the issuer cert
/// -- useful for computing the issuer-key SHA-1 that the OCSP
/// `CertID` requires.
#[must_use]
#[inline]
pub fn extract_ca_issuers_urls<B: AsRef<[u8]>>(extensions: B) -> Vec<crate::text::Uri> {
    X509Helpers::aia_urls_for(
        ExtensionBytes {
            value: extensions.as_ref(),
        },
        OID_AD_CA_ISSUERS,
    )
}

/// Extract email addresses from a `subjectAltName` extension's
/// `rfc822Name` entries.
///
/// Filter at parse time: a `GeneralName` whose `rfc822Name`
/// payload doesn't pass `identity::EmailAddress::new`
/// (missing `@`, whitespace, multiple `@`, empty local/domain)
/// is silently dropped. Cert subjects in the wild list well-
/// formed addresses; anything off-shape is more likely
/// extension misuse than a real email refineid should
/// surface.
#[must_use]
#[inline]
pub fn extract_subject_alt_emails<B: AsRef<[u8]>>(
    extensions: B,
) -> Vec<crate::identity::EmailAddress> {
    let extensions = extensions.as_ref();
    let Some(extn_value) = X509Helpers::find_extension(extensions, OID_SUBJECT_ALT_NAME) else {
        return Vec::new();
    };
    let Ok(outer) = BerTlv::<Sequence>::parse(extn_value) else {
        return Vec::new();
    };
    let mut emails = Vec::new();
    for gn in BerTlvIter::new(outer.value) {
        let Ok(gn) = gn else { continue };
        if gn.tag == TAG_GN_RFC822_NAME
            && let Ok(s) = core::str::from_utf8(gn.value)
            && let Ok(email) = crate::identity::EmailAddress::new(s)
        {
            emails.push(email);
        }
    }
    emails
}

// ----- Signature algorithm + verification -----

/// `OID_SHA256_WITH_RSA` constant.
const OID_SHA256_WITH_RSA: Oid<'static> = known::SHA256_WITH_RSA;
/// `OID_SHA384_WITH_RSA` constant.
const OID_SHA384_WITH_RSA: Oid<'static> = known::SHA384_WITH_RSA;
/// `OID_SHA512_WITH_RSA` constant.
const OID_SHA512_WITH_RSA: Oid<'static> = known::SHA512_WITH_RSA;
/// `OID_ECDSA_SHA256` constant.
const OID_ECDSA_SHA256: Oid<'static> = known::ECDSA_WITH_SHA256;
/// `OID_ECDSA_SHA384` constant.
const OID_ECDSA_SHA384: Oid<'static> = known::ECDSA_WITH_SHA384;
/// `OID_ECDSA_SHA512` constant.
const OID_ECDSA_SHA512: Oid<'static> = known::ECDSA_WITH_SHA512;

/// Subset of `signatureAlgorithm` OIDs we know how to verify.
///
/// Constructed from a parsed OID via
/// [`SignatureAlgorithm::from_oid`]. Each named variant maps to
/// a single OID; unrecognised algorithms collapse to
/// [`SignatureAlgorithm::Other`] so the cert chain can still
/// report a meaningful error rather than panicking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// `sha256WithRSAEncryption` -- RSASSA-PKCS1-v1_5 over
    /// SHA-256 (OID `1.2.840.113549.1.1.11`). The DVV G3 / G4R
    /// chains use this.
    Sha256WithRsa,
    /// `sha384WithRSAEncryption` -- RSASSA-PKCS1-v1_5 over
    /// SHA-384 (OID `1.2.840.113549.1.1.12`).
    Sha384WithRsa,
    /// `sha512WithRSAEncryption` -- RSASSA-PKCS1-v1_5 over
    /// SHA-512 (OID `1.2.840.113549.1.1.13`).
    Sha512WithRsa,
    /// `ecdsa-with-SHA256` (OID `1.2.840.10045.4.3.2`).
    EcdsaWithSha256,
    /// `ecdsa-with-SHA384` (OID `1.2.840.10045.4.3.3`). FINEID
    /// G4E chains use this.
    EcdsaWithSha384,
    /// `ecdsa-with-SHA512` (OID `1.2.840.10045.4.3.4`).
    EcdsaWithSha512,
    /// Any OID this matcher doesn't recognise. Verification
    /// callers surface this as an "unsupported algorithm"
    /// error rather than attempting to verify.
    Other,
}

impl SignatureAlgorithm {
    /// Resolve a `signatureAlgorithm` OID body to its named
    /// variant. Returns [`SignatureAlgorithm::Other`] for any
    /// OID this matcher doesn't recognise.
    #[must_use]
    #[inline]
    pub fn from_oid<B: AsRef<[u8]>>(oid: B) -> Self {
        let oid = oid.as_ref();
        match oid {
            v if v == OID_SHA256_WITH_RSA => Self::Sha256WithRsa,
            v if v == OID_SHA384_WITH_RSA => Self::Sha384WithRsa,
            v if v == OID_SHA512_WITH_RSA => Self::Sha512WithRsa,
            v if v == OID_ECDSA_SHA256 => Self::EcdsaWithSha256,
            v if v == OID_ECDSA_SHA384 => Self::EcdsaWithSha384,
            v if v == OID_ECDSA_SHA512 => Self::EcdsaWithSha512,
            _ => Self::Other,
        }
    }

    /// Short human-readable label for the algorithm (e.g.
    /// `"sha256WithRSAEncryption"`). Used by diagnostic output
    /// in `card check` / `cert show`.
    #[must_use]
    #[inline]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Sha256WithRsa => "sha256WithRSAEncryption",
            Self::Sha384WithRsa => "sha384WithRSAEncryption",
            Self::Sha512WithRsa => "sha512WithRSAEncryption",
            Self::EcdsaWithSha256 => "ecdsa-with-SHA256",
            Self::EcdsaWithSha384 => "ecdsa-with-SHA384",
            Self::EcdsaWithSha512 => "ecdsa-with-SHA512",
            Self::Other => "unrecognised",
        }
    }
}

/// Outcome of a signature verification attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// Algorithm OID isn't one this codec implements yet.
    /// Supported today: RSA-PKCS1v15 SHA-256/384/512 and ECDSA
    /// over P-256 / P-384 / P-521 / brainpool* with SHA-256 /
    /// SHA-384 / SHA-512.
    Unsupported(SignatureAlgorithm),
    /// Issuer's SPKI didn't parse as the expected key type for
    /// the chosen signature algorithm (RSA SPKI when the sig
    /// alg is RSA-*, EC SPKI when the sig alg is ECDSA-*).
    BadIssuerKey,
    /// Underlying RSA verifier rejected the signature.
    Rsa(RsaVerifyError),
    /// Underlying ECDSA verifier rejected the signature.
    Ecdsa(EcdsaError),
}

impl core::fmt::Display for VerifyError {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unsupported(a) => write!(f, "unsupported signature algorithm: {}", a.label()),
            Self::BadIssuerKey => write!(f, "issuer SPKI shape doesn't match the signature alg"),
            Self::Rsa(e) => write!(f, "RSA verify: {e}"),
            Self::Ecdsa(e) => write!(f, "ECDSA verify: {e}"),
        }
    }
}

impl core::error::Error for VerifyError {}

/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent
/// INTEGER }` (RFC 8017 A.1.1) as the two canonical big-endian
/// magnitudes.
///
/// Written out rather than delegated to `pkcs1`, whose only released
/// version speaks the previous `der`. It is two INTEGERs, and the one
/// subtlety is theirs rather than ours: DER prepends a zero octet
/// when the top bit of the magnitude would otherwise read as a sign,
/// and PKCS#1 magnitudes carry no such octet. Stripping it here means
/// callers get what `try_from_pkcs1` expects.
fn rsa_public_key_parts(der: &[u8]) -> Option<(&[u8], &[u8])> {
    use spki::der::asn1::AnyRef;
    use spki::der::{Decode as _, Reader as _, SliceReader, Tag, Tagged as _};

    /// One INTEGER, as its magnitude.
    fn magnitude<'a>(reader: &mut SliceReader<'a>) -> Option<&'a [u8]> {
        const INTEGER_SIGN_OCTET: u8 = 0;
        const INTEGER_SIGN_BIT: u8 = 1 << (u8::BITS - 1);

        let any = AnyRef::from_der(reader.tlv_bytes().ok()?).ok()?;
        if any.tag() != Tag::Integer {
            return None;
        }
        match any.value() {
            // A positive DER INTEGER needs one sign octet exactly when
            // the magnitude starts with its sign bit set. Reject a
            // redundant sign octet instead of normalizing non-DER input.
            [INTEGER_SIGN_OCTET, first, rest @ ..] if first & INTEGER_SIGN_BIT != 0 => {
                let magnitude_len = rest.len().checked_add(1)?;
                any.value().get(1..=magnitude_len)
            }
            // No sign octet is valid only when the first magnitude bit
            // is clear. Empty, zero and negative INTEGERs are not RSA
            // public-key components.
            [first, ..] if *first != INTEGER_SIGN_OCTET && first & INTEGER_SIGN_BIT == 0 => {
                Some(any.value())
            }
            _ => None,
        }
    }

    let sequence = AnyRef::from_der(der).ok()?;
    if sequence.tag() != Tag::Sequence {
        return None;
    }
    let mut reader = SliceReader::new(sequence.value()).ok()?;
    let modulus = magnitude(&mut reader)?;
    let exponent = magnitude(&mut reader)?;
    reader.is_finished().then_some((modulus, exponent))
}

/// Parse an RSA public key out of a `SubjectPublicKeyInfo` DER
/// blob. Returns `None` if the SPKI is not an RSA key or the
/// structure is malformed.
#[must_use]
#[inline]
pub fn extract_rsa_public_key<B: AsRef<[u8]>>(spki_der: B) -> Option<RsaPublicKey> {
    use spki::SubjectPublicKeyInfoRef;
    use spki::der::Decode as _;

    // Standards-based decode: `spki` for the envelope, the typed
    // The `SEQUENCE { modulus, exponent }`
    // inside the BIT STRING -- no hand-rolled BerTlv walk.
    let info = SubjectPublicKeyInfoRef::from_der(spki_der.as_ref()).ok()?;
    if info.algorithm.oid.as_bytes() != OID_RSA_ENCRYPTION {
        return None;
    }
    rsa_key_from_subject_public_key(info.subject_public_key)
}

/// Parse the narrowly restricted `id-RSASSA-PSS` SPKI currently used
/// by Germany's trusted-list signer.
///
/// An absent parameter field does not describe a reusable RSA-PSS
/// profile. The caller therefore exposes this key only for the fixed
/// SHA-256/MGF1-SHA-256/salt-32 XML method; ordinary RSA extraction
/// deliberately refuses it.
fn extract_rsa_pss_public_key_with_absent_parameters<B: AsRef<[u8]>>(
    spki_der: B,
) -> Option<RsaPublicKey> {
    use spki::SubjectPublicKeyInfoRef;
    use spki::der::Decode as _;

    let info = SubjectPublicKeyInfoRef::from_der(spki_der.as_ref()).ok()?;
    if info.algorithm.oid.as_bytes() != known::RSASSA_PSS || info.algorithm.parameters.is_some() {
        return None;
    }
    rsa_key_from_subject_public_key(info.subject_public_key)
}

fn rsa_key_from_subject_public_key(
    subject_public_key: spki::der::asn1::BitStringRef<'_>,
) -> Option<RsaPublicKey> {
    // RSA's DER RSAPublicKey is octet-aligned. `as_bytes`, unlike
    // `raw_bytes`, refuses a BIT STRING with declared unused bits.
    let (modulus_bytes, exponent_bytes) = rsa_public_key_parts(subject_public_key.as_bytes()?)?;
    let modulus = RsaModulus::try_from_pkcs1(modulus_bytes).ok()?;
    let exponent = RsaPublicExponent::try_from_pkcs1(exponent_bytes).ok()?;
    Some(RsaPublicKey { modulus, exponent })
}

/// Message-signature profiles used outside an X.509
/// `signatureAlgorithm` field.
///
/// `XMLDSig` identifies algorithms with URI strings rather than OIDs;
/// callers map a strictly allowed URI and parameter set to this enum
/// before asking a typed SPKI to verify the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageSignatureAlgorithm {
    /// RSA PKCS#1 v1.5 with SHA-256.
    RsaPkcs1Sha256,
    /// RSA PKCS#1 v1.5 with SHA-384.
    RsaPkcs1Sha384,
    /// RSA PKCS#1 v1.5 with SHA-512.
    RsaPkcs1Sha512,
    /// RSA-PSS with SHA-256, MGF1-SHA-256 and a 32-byte salt.
    RsaPssSha256,
    /// Raw-concatenation ECDSA with SHA-256.
    EcdsaSha256Raw,
    /// Raw-concatenation ECDSA with SHA-384.
    EcdsaSha384Raw,
    /// Raw-concatenation ECDSA with SHA-512.
    EcdsaSha512Raw,
}

/// Inputs needed to verify one TBS signature.
pub(crate) struct TbsSignature<'a> {
    /// DER bytes covered by the signature.
    pub tbs_der: &'a [u8],
    /// Signature algorithm OID.
    pub signature_alg_oid: &'a [u8],
    /// Signature BIT STRING payload.
    pub signature_bits: &'a [u8],
    /// Issuer `SubjectPublicKeyInfo` DER.
    pub issuer_spki_der: &'a [u8],
}

/// Verify a signature against a TBS body.
///
/// `signature_bits` is the raw signature, `signature_alg_oid`
/// picks the verifier, and the issuer's `spki_der` gives the
/// public key. Used for cert chain, CRL,
/// and basic-OCSP-response verification.
///
/// # Errors
/// [`VerifyError`] variants as listed; only RSA-PKCS1v15 SHA-256
/// is implemented today.
pub(crate) fn verify_tbs_signature(
    TbsSignature {
        tbs_der,
        signature_alg_oid,
        signature_bits,
        issuer_spki_der,
    }: TbsSignature<'_>,
) -> Result<(), VerifyError> {
    use crate::crypto::container::{RsaPkcs1Sha256, RsaPkcs1Sha384, RsaPkcs1Sha512, Signature};
    use sha2::{Digest as _, Sha256, Sha384, Sha512};
    let alg = SignatureAlgorithm::from_oid(signature_alg_oid);
    match alg {
        SignatureAlgorithm::Sha256WithRsa => {
            let k = extract_rsa_public_key(issuer_spki_der).ok_or(VerifyError::BadIssuerKey)?;
            let sig = Signature::<RsaPkcs1Sha256>::new(signature_bits.to_vec());
            k.verify_pkcs1v15_sha256(tbs_der, &sig)
                .map_err(VerifyError::Rsa)
        }
        SignatureAlgorithm::Sha384WithRsa => {
            let k = extract_rsa_public_key(issuer_spki_der).ok_or(VerifyError::BadIssuerKey)?;
            let sig = Signature::<RsaPkcs1Sha384>::new(signature_bits.to_vec());
            verify_pkcs1v15_sha384(&k, tbs_der, &sig).map_err(VerifyError::Rsa)
        }
        SignatureAlgorithm::Sha512WithRsa => {
            let k = extract_rsa_public_key(issuer_spki_der).ok_or(VerifyError::BadIssuerKey)?;
            let sig = Signature::<RsaPkcs1Sha512>::new(signature_bits.to_vec());
            verify_pkcs1v15_sha512(&k, tbs_der, &sig).map_err(VerifyError::Rsa)
        }
        SignatureAlgorithm::EcdsaWithSha256
        | SignatureAlgorithm::EcdsaWithSha384
        | SignatureAlgorithm::EcdsaWithSha512 => {
            let (curve, pubkey) =
                extract_ec_pubkey(issuer_spki_der).ok_or(VerifyError::BadIssuerKey)?;
            // Caller picks the hash via the signature-alg OID;
            // we feed `verify_prehashed` the digest of the TBS
            // bytes under that hash.
            let digest: Vec<u8> = match alg {
                SignatureAlgorithm::EcdsaWithSha256 => Sha256::digest(tbs_der).to_vec(),
                SignatureAlgorithm::EcdsaWithSha384 => Sha384::digest(tbs_der).to_vec(),
                SignatureAlgorithm::EcdsaWithSha512 => Sha512::digest(tbs_der).to_vec(),
                SignatureAlgorithm::Sha256WithRsa
                | SignatureAlgorithm::Sha384WithRsa
                | SignatureAlgorithm::Sha512WithRsa
                | SignatureAlgorithm::Other => unreachable!("guarded by outer match"),
            };
            let sig = Signature::<EcdsaDer>::new(signature_bits.to_vec());
            verify_prehashed(&curve, &pubkey, &sig, &digest).map_err(VerifyError::Ecdsa)
        }
        SignatureAlgorithm::Other => Err(VerifyError::Unsupported(alg)),
    }
}

// `verify_certificate_signed_by` is a method on Certificate; see
// `Certificate::verify_signed_by` below.

// ----- SubjectPublicKeyInfo -----

/// `SubjectPublicKeyInfo` DER bytes, parse-validated at the
/// trust boundary.
///
/// Constructor `SpkiDer::try_from_der` runs
/// [`parse_subject_public_key_info`] to confirm the SEQUENCE-of-
/// AlgorithmIdentifier-plus-BIT-STRING shape per RFC 5280 §4.1
/// and pins the parsed algorithm summary into the value. The
/// borrowed bytes stored inside are guaranteed to be a valid
/// SPKI DER blob; downstream code reads the algorithm without
/// re-checking, and re-emits the DER bytes via
/// [`SpkiDer::as_der`].
///
/// `Copy` because the value is a borrow + a tiny algorithm
/// summary; passing it by value is no more expensive than
/// passing a reference.
#[derive(Debug, Clone, Copy)]
pub struct SpkiDer<'a> {
    /// Validated SPKI DER bytes (SEQUENCE { `AlgorithmIdentifier`,
    /// BIT STRING }, including the outer SEQUENCE tag + length).
    der: &'a [u8],
    /// Parsed algorithm summary -- the result of
    /// [`parse_subject_public_key_info`], pinned at construction
    /// so callers don't pay the parse cost twice.
    algorithm: PublicKeyAlgorithm,
    /// `subjectPublicKey` BIT STRING value (unused-bits octet
    /// stripped), captured at construction so key-material
    /// operations are total -- no re-parse, no `Option`.
    subject_public_key: &'a [u8],
}

impl<'a> SpkiDer<'a> {
    /// Validated DER bytes for wire re-emission (OCSP request,
    /// PEM body, ...).
    #[must_use]
    #[inline]
    pub const fn as_der(&self) -> &'a [u8] {
        self.der
    }

    /// Parsed algorithm summary from the `AlgorithmIdentifier`
    /// section.
    #[must_use]
    #[inline]
    pub const fn algorithm(&self) -> PublicKeyAlgorithm {
        self.algorithm
    }

    /// Extract the EC public point as a typed
    /// [`Sec1UncompressedPoint`].
    ///
    /// Returns `None` when the SPKI is RSA, holds a compressed
    /// / hybrid SEC1 point (refineid only accepts uncompressed),
    /// or the BIT STRING is malformed. SEC1 §2.3.3 uncompressed
    /// form is `0x04 || X || Y`.
    #[must_use]
    #[inline]
    pub fn ec_public_key_point(&self) -> Option<Sec1UncompressedPoint> {
        Sec1UncompressedPoint::from_bytes(self.subject_public_key.to_vec()).ok()
    }

    /// Verify a message signature under a strictly selected external
    /// signature profile.
    ///
    /// RSA signatures use their native byte representation. ECDSA
    /// signatures use `XMLDSig`'s fixed-width `r || s` form and are
    /// converted to DER internally before verification.
    ///
    /// # Errors
    /// [`VerifyError`] when the key does not match the selected profile,
    /// the signature encoding is malformed, or verification fails.
    pub fn verify_message_signature(
        self,
        algorithm: MessageSignatureAlgorithm,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), VerifyError> {
        use sha2::{Digest as _, Sha256, Sha384, Sha512};

        match algorithm {
            MessageSignatureAlgorithm::RsaPkcs1Sha256 => {
                let key = extract_rsa_public_key(self.der).ok_or(VerifyError::BadIssuerKey)?;
                key.verify_pkcs1v15_sha256(
                    message,
                    &Signature::<RsaPkcs1Sha256>::new(signature.to_vec()),
                )
                .map_err(VerifyError::Rsa)
            }
            MessageSignatureAlgorithm::RsaPkcs1Sha384 => {
                let key = extract_rsa_public_key(self.der).ok_or(VerifyError::BadIssuerKey)?;
                key.verify_pkcs1v15_sha384(
                    message,
                    &Signature::<RsaPkcs1Sha384>::new(signature.to_vec()),
                )
                .map_err(VerifyError::Rsa)
            }
            MessageSignatureAlgorithm::RsaPkcs1Sha512 => {
                let key = extract_rsa_public_key(self.der).ok_or(VerifyError::BadIssuerKey)?;
                key.verify_pkcs1v15_sha512(
                    message,
                    &Signature::<RsaPkcs1Sha512>::new(signature.to_vec()),
                )
                .map_err(VerifyError::Rsa)
            }
            MessageSignatureAlgorithm::RsaPssSha256 => {
                let key = extract_rsa_public_key(self.der)
                    .or_else(|| extract_rsa_pss_public_key_with_absent_parameters(self.der))
                    .ok_or(VerifyError::BadIssuerKey)?;
                key.verify_pss_sha256(message, &Signature::<RsaPssSha256>::new(signature.to_vec()))
                    .map_err(VerifyError::Rsa)
            }
            MessageSignatureAlgorithm::EcdsaSha256Raw
            | MessageSignatureAlgorithm::EcdsaSha384Raw
            | MessageSignatureAlgorithm::EcdsaSha512Raw => {
                let (curve, public_key) =
                    extract_ec_pubkey(self.der).ok_or(VerifyError::BadIssuerKey)?;
                let expected_raw_len = public_key
                    .len()
                    .checked_sub(1)
                    .ok_or(VerifyError::BadIssuerKey)?;
                if signature.len() != expected_raw_len {
                    return Err(VerifyError::Ecdsa(EcdsaError::BadSignature));
                }
                let digest = match algorithm {
                    MessageSignatureAlgorithm::EcdsaSha256Raw => Sha256::digest(message).to_vec(),
                    MessageSignatureAlgorithm::EcdsaSha384Raw => Sha384::digest(message).to_vec(),
                    MessageSignatureAlgorithm::EcdsaSha512Raw => Sha512::digest(message).to_vec(),
                    MessageSignatureAlgorithm::RsaPkcs1Sha256
                    | MessageSignatureAlgorithm::RsaPkcs1Sha384
                    | MessageSignatureAlgorithm::RsaPkcs1Sha512
                    | MessageSignatureAlgorithm::RsaPssSha256 => {
                        unreachable!("guarded by ECDSA match arm")
                    }
                };
                let signature = Signature::<EcdsaDer>::from_raw_concatenation(signature)
                    .map_err(VerifyError::Ecdsa)?;
                verify_prehashed(&curve, &public_key, &signature, &digest)
                    .map_err(VerifyError::Ecdsa)
            }
        }
    }

    /// The `subjectPublicKey` BIT STRING contents -- the raw
    /// public-key material with the leading "unused bits" octet
    /// stripped, captured at construction. The leaf bytes feed a
    /// hash (RFC 6960 `issuerKeyHash = SHA-1(subjectPublicKey)`) or
    /// a SEC1 point decode; they are reached only through this typed
    /// SPKI, never by handing a bare `&[u8]` to a free function.
    ///
    /// Total: a constructed `SpkiDer` already validated its envelope,
    /// so there is no re-parse and no `Option`.
    ///
    /// Crate-internal: the raw key material is reached only through
    /// typed operations ([`Self::ec_public_key_point`],
    /// [`crate::ocsp::IssuerKeyHash::from_subject_public_key`]) so
    /// no external caller names a bare `&[u8]` of a public key.
    #[must_use]
    #[inline]
    pub(crate) const fn subject_public_key_bits(&self) -> &'a [u8] {
        self.subject_public_key
    }
}

/// Boundary parser: build [`SpkiDer`] from raw
/// `SubjectPublicKeyInfo` DER bytes. The conversion fails
/// when the bytes don't parse as
/// `SEQUENCE { AlgorithmIdentifier, BIT STRING }`.
impl<'a> TryFrom<&'a [u8]> for SpkiDer<'a> {
    type Error = X509Error;
    #[inline]
    fn try_from(der: &'a [u8]) -> Result<Self, X509Error> {
        use spki::SubjectPublicKeyInfoRef;
        use spki::der::Decode as _;
        // Decode the envelope once here (the sole fallible boundary);
        // pin both the algorithm summary and the key bits so every
        // later operation on this value is total.
        let info = SubjectPublicKeyInfoRef::from_der(der)
            .map_err(|_ignored| X509Error::UnexpectedStructure("malformed SubjectPublicKeyInfo"))?;
        let subject_public_key =
            info.subject_public_key
                .as_bytes()
                .ok_or(X509Error::UnexpectedStructure(
                    "non-octet-aligned SubjectPublicKeyInfo",
                ))?;
        let algorithm = PublicKeyAlgorithm::from_spki(&info).ok_or(
            X509Error::UnexpectedStructure("malformed SubjectPublicKeyInfo"),
        )?;
        Ok(Self {
            der,
            algorithm,
            subject_public_key,
        })
    }
}

/// Public-key algorithm + identifying details surfaced by
/// [`parse_subject_public_key_info`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyAlgorithm {
    /// RSA key, identified by the `rsaEncryption` OID
    /// (`1.2.840.113549.1.1.1`) in the SPKI `AlgorithmIdentifier`.
    Rsa {
        /// Bit length of the public modulus -- 2048 / 3072 /
        /// 4096 in practice. Computed from the parsed
        /// [`RsaModulus`] at parse time;
        /// `usize` is the natural fit.
        modulus_bits: usize,
    },
    /// EC key on a known named curve, identified by the
    /// `id-ecPublicKey` OID + a named-curve OID. The wrapped
    /// [`EcCurve`] carries the specific curve.
    Ec(EcCurve),
    /// EC key with explicit curve parameters (parameters
    /// encoded inline as an `ECParameters` SEQUENCE rather than
    /// referenced by a named-curve OID). Used by (e.g.) Finnish
    /// eMRTD DSCs.
    EcExplicit {
        /// Field prime's bit length, decoded from the inline
        /// `ECParameters` SEQUENCE. `usize` is the natural fit.
        bits: usize,
    },
    /// Unrecognised algorithm OID. The caller still gets the
    /// raw OID bytes for diagnostics.
    Other,
}

/// Subset of EC curves the FINEID stack is expected to see.
///
/// Constructed at the SPKI parse boundary from the
/// `AlgorithmIdentifier`'s named-curve OID; unrecognised curves
/// collapse to [`EcCurve::Other`] so downstream code can
/// surface a meaningful error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcCurve {
    /// NIST P-256 / secp256r1 (`1.2.840.10045.3.1.7`).
    Secp256r1,
    /// NIST P-384 / secp384r1 (`1.3.132.0.34`). FINEID G4E
    /// chains use this.
    Secp384r1,
    /// Brainpool P-256r1 (`1.3.36.3.3.2.8.1.1.7`).
    BrainpoolP256r1,
    /// Brainpool P-384r1 (`1.3.36.3.3.2.8.1.1.11`). FINEID
    /// PACE / eMRTD AA use this.
    BrainpoolP384r1,
    /// Unrecognised curve OID.
    Other,
}

impl EcCurve {
    /// Short human-readable label for the curve (e.g.
    /// `"secp256r1 (P-256)"`). Used by diagnostic output in
    /// `card check` / `cert show`.
    #[must_use]
    #[inline]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Secp256r1 => "secp256r1 (P-256)",
            Self::Secp384r1 => "secp384r1 (P-384)",
            Self::BrainpoolP256r1 => "brainpoolP256r1",
            Self::BrainpoolP384r1 => "brainpoolP384r1",
            Self::Other => "unrecognised curve",
        }
    }

    /// Bit length of the field prime for the curve (256 for
    /// secp256r1 / brainpoolP256r1, 384 for secp384r1 /
    /// brainpoolP384r1). [`EcCurve::Other`] returns 0 so the
    /// caller can pattern-match on "unknown size".
    #[must_use]
    #[inline]
    pub const fn bits(self) -> usize {
        match self {
            Self::Secp256r1 | Self::BrainpoolP256r1 => 256,
            Self::Secp384r1 | Self::BrainpoolP384r1 => 384,
            Self::Other => 0,
        }
    }
}

impl PublicKeyAlgorithm {
    /// Short human-readable label for the algorithm
    /// (e.g. `"RSA, 2048-bit modulus"`). Used by diagnostic
    /// output in `card check` / `cert show`.
    #[must_use]
    #[inline]
    pub fn label(self) -> String {
        match self {
            Self::Rsa { modulus_bits } => format!("RSA, {modulus_bits}-bit modulus"),
            Self::Ec(curve) => format!("EC on {}", curve.label()),
            Self::EcExplicit { bits } => {
                format!("EC with explicit parameters ({bits}-bit field)")
            }
            Self::Other => "unrecognised algorithm".to_owned(),
        }
    }
}

/// Explicit `ECParameters` sequence value.
struct ExplicitCurveParams<'a> {
    /// `ECParameters` `SEQUENCE` value bytes.
    seq_value: &'a [u8],
}

/// Walk an explicit-parameters EC `ECParameters` SEQUENCE and
/// return the field prime's bit length. Returns `None` on
/// shape mismatch.
impl X509Helpers {
    /// `explicit_curve_field_bits` associated function.
    fn explicit_curve_field_bits(params: &ExplicitCurveParams<'_>) -> Option<usize> {
        let mut it = BerTlvIter::new(params.seq_value);
        let _version = it.next()?.ok()?;
        let field_id = it.next()?.ok()?;
        if field_id.tag != <Sequence as BerTag>::TAG {
            return None;
        }
        let mut fit = BerTlvIter::new(field_id.value);
        let _field_type_oid = fit.next()?.ok()?;
        let prime = fit.next()?.ok()?;
        if prime.tag != <Integer as BerTag>::TAG {
            return None;
        }
        let bytes = prime.value.strip_prefix(&[0_u8]).unwrap_or(prime.value);
        let first = *bytes.first()?;
        // `u8::leading_zeros` is in 0..=8; widens to usize losslessly.
        let leading_zeros = usize::try_from(first.leading_zeros()).ok()?;
        // `bytes` non-empty (first() succeeded), so `bytes.len() >= 1`
        // and `bytes.len() * 8 >= 8 > leading_zeros`; both ops can't
        // overflow within reasonable EC parameter sizes.
        let total_bits = bytes.len().checked_mul(8)?;
        total_bits.checked_sub(leading_zeros)
    }
}

impl PublicKeyAlgorithm {
    /// Classify an already-decoded `SubjectPublicKeyInfoRef` into its
    /// [`PublicKeyAlgorithm`] summary -- a smart constructor on the
    /// type it yields. Shared by the byte-entry
    /// [`parse_subject_public_key_info`] and `SpkiDer::try_from`, so a
    /// constructed `SpkiDer` decodes the envelope exactly once.
    fn from_spki(info: &spki::SubjectPublicKeyInfoRef<'_>) -> Option<Self> {
        use spki::der::asn1::ObjectIdentifier;

        let alg_oid = info.algorithm.oid;
        if alg_oid.as_bytes() == OID_RSA_ENCRYPTION {
            // The subjectPublicKey BIT STRING wraps
            // `RSAPublicKey ::= SEQUENCE { modulus, publicExponent }`.
            let (magnitude, _exponent) = rsa_public_key_parts(info.subject_public_key.raw_bytes())?;
            let first = *magnitude.first()?;
            // `u8::leading_zeros` is in 0..=8; widens to usize losslessly.
            let leading_zeros = usize::try_from(first.leading_zeros()).ok()?;
            let total_bits = magnitude.len().checked_mul(8)?;
            let modulus_bits = total_bits.checked_sub(leading_zeros)?;
            Some(Self::Rsa { modulus_bits })
        } else if alg_oid.as_bytes() == OID_EC_PUBLIC_KEY {
            // EC: AlgorithmIdentifier.parameters is a named-curve OID or
            // an explicit-parameters SEQUENCE.
            let params = info.algorithm.parameters?;
            match params.decode_as::<ObjectIdentifier>() {
                Ok(curve_oid) => {
                    let curve = match curve_oid.as_bytes() {
                        v if v == OID_SECP256R1 => EcCurve::Secp256r1,
                        v if v == OID_SECP384R1 => EcCurve::Secp384r1,
                        v if v == OID_BRAINPOOL_P256R1 => EcCurve::BrainpoolP256r1,
                        v if v == OID_BRAINPOOL_P384R1 => EcCurve::BrainpoolP384r1,
                        _ => EcCurve::Other,
                    };
                    Some(Self::Ec(curve))
                }
                // Explicit ECParameters SEQUENCE -- field prime size for
                // display. This esoteric form has no `spki` type, so the
                // small structural walk stays hand-rolled.
                Err(_ignored) => {
                    let bits = X509Helpers::explicit_curve_field_bits(&ExplicitCurveParams {
                        seq_value: params.value(),
                    })
                    .unwrap_or(0);
                    Some(Self::EcExplicit { bits })
                }
            }
        } else {
            Some(Self::Other)
        }
    }
}

/// Decode an SPKI's `AlgorithmIdentifier` and surface the
/// [`PublicKeyAlgorithm`] summary.
///
/// Returns `None` if the SPKI envelope is malformed (caller is
/// expected to pass the `spki_der` field of a [`Certificate`]).
#[must_use]
#[inline]
pub fn parse_subject_public_key_info<B: AsRef<[u8]>>(spki_der: B) -> Option<PublicKeyAlgorithm> {
    use spki::SubjectPublicKeyInfoRef;
    use spki::der::Decode as _;
    let info = SubjectPublicKeyInfoRef::from_der(spki_der.as_ref()).ok()?;
    PublicKeyAlgorithm::from_spki(&info)
}

// ----- Key Usage + Extended Key Usage -----

/// Key usage bits per RFC 5280 sec.4.2.1.3.
///
/// Bit indices match the ASN.1 BIT STRING bit positions; higher
/// bits map to lower indices (`digitalSignature` is bit 0 of
/// the leftmost byte).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
// Nine flag-bits genuinely live here, one per RFC 5280 named
// usage; refactoring to enums would just hide the spec mapping.
#[expect(
    clippy::struct_excessive_bools,
    reason = "RFC 5280 §4.2.1.3 KeyUsage BIT STRING is exactly 9 boolean flags; mirroring the wire shape is the point."
)]
pub struct KeyUsage {
    /// RFC 5280 §4.2.1.3 bit 0: signing for entity
    /// authentication or to provide a data-origin
    /// authentication service. FINEID auth-slot cert.
    pub digital_signature: bool,
    /// Bit 1: non-repudiation (a.k.a. content commitment in
    /// RFC 5280 §4.2.1.3). MUST NOT combine with any other
    /// usage bit per §4.2.1.3. FINEID signature-slot cert.
    pub non_repudiation: bool,
    /// Bit 2: key transport (RSA key encryption).
    pub key_encipherment: bool,
    /// Bit 3: direct encryption of user data (not a session
    /// key). Rare in practice.
    pub data_encipherment: bool,
    /// Bit 4: key-agreement (e.g. ECDH).
    pub key_agreement: bool,
    /// Bit 5: signing of other certificates. CA / issuer cert.
    pub key_cert_sign: bool,
    /// Bit 6: signing of CRLs. CA / issuer cert.
    pub crl_sign: bool,
    /// Bit 7: key-agreement that may only be used to
    /// encipher data (paired with `key_agreement`).
    pub encipher_only: bool,
    /// Bit 8: key-agreement that may only be used to
    /// decipher data (paired with `key_agreement`).
    pub decipher_only: bool,
}

impl core::fmt::Display for KeyUsage {
    /// Renders the same RFC 5280 §4.2.1.3 flag-name list as
    /// [`KeyUsage::label`], so error-message format strings that
    /// embed `{key_usage}` produce a human-readable spec-named
    /// flag list (`digitalSignature, nonRepudiation`) rather than
    /// the struct's debug shape.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.label())
    }
}

impl KeyUsage {
    /// Render as a comma-separated list of the bits that are set.
    /// Empty string if no bits are set (which a real cert never
    /// emits; the extension would be absent).
    #[must_use]
    #[inline]
    pub fn label(self) -> String {
        let mut parts: Vec<&'static str> = Vec::new();
        if self.digital_signature {
            parts.push("digitalSignature");
        }
        if self.non_repudiation {
            parts.push("nonRepudiation");
        }
        if self.key_encipherment {
            parts.push("keyEncipherment");
        }
        if self.data_encipherment {
            parts.push("dataEncipherment");
        }
        if self.key_agreement {
            parts.push("keyAgreement");
        }
        if self.key_cert_sign {
            parts.push("keyCertSign");
        }
        if self.crl_sign {
            parts.push("cRLSign");
        }
        if self.encipher_only {
            parts.push("encipherOnly");
        }
        if self.decipher_only {
            parts.push("decipherOnly");
        }
        parts.join(", ")
    }
}

/// Extract the `KeyUsage` BIT STRING from a parsed extensions
/// block. Returns `None` when the extension is absent or
/// malformed.
#[must_use]
#[inline]
pub fn extract_key_usage<B: AsRef<[u8]>>(extensions: B) -> Option<KeyUsage> {
    let extensions = extensions.as_ref();
    let extn_value = X509Helpers::find_extension(extensions, OID_KEY_USAGE)?;
    let bit_string = BerTlv::<BitString>::parse(extn_value).ok()?;
    // First byte = unused-bits count; we don't need it. `.get(1..)?`
    // is `None` exactly when the BIT STRING value is empty.
    let bytes = bit_string.value.get(1..)?;
    let b0 = bytes.first().copied().unwrap_or(0);
    let b1 = bytes.get(1).copied().unwrap_or(0);
    // BIT STRING bits are numbered from MSB (named bit 0 = bit 7 of
    // the first byte).
    Some(KeyUsage {
        digital_signature: b0 & 0x80 != 0,
        non_repudiation: b0 & 0x40 != 0,
        key_encipherment: b0 & 0x20 != 0,
        data_encipherment: b0 & 0x10 != 0,
        key_agreement: b0 & 0x08 != 0,
        key_cert_sign: b0 & 0x04 != 0,
        crl_sign: b0 & 0x02 != 0,
        encipher_only: b0 & 0x01 != 0,
        decipher_only: b1 & 0x80 != 0,
    })
}

/// Extract Extended Key Usage (RFC 5280 sec.4.2.1.12).
///
/// Returns a list of human-readable strings -- recognised OIDs
/// get a friendly label, others fall through to
/// `"oid:1.2.3.4..."`. Empty when the extension is absent.
#[must_use]
#[inline]
pub fn extract_extended_key_usage<B: AsRef<[u8]>>(extensions: B) -> Vec<String> {
    let extensions = extensions.as_ref();
    let Some(extn_value) = X509Helpers::find_extension(extensions, OID_EXT_KEY_USAGE) else {
        return Vec::new();
    };
    let Ok(outer) = BerTlv::<Sequence>::parse(extn_value) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in BerTlvIter::new(outer.value) {
        let Ok(entry) = entry else { continue };
        if entry.tag != <BerOid as BerTag>::TAG {
            continue;
        }
        if let Ok(oid) = Oid::new(entry.value) {
            out.push(X509Helpers::eku_label(oid));
        }
    }
    out
}

/// Parsed Extended Key Usage extension with raw OID bytes.
///
/// Carries the OID values plus the critical-flag, for callers
/// that need exact-OID comparison (e.g. ICAO Doc 9303 §12
/// mandates EKU `id-icao-mlSigner` critical on every Master
/// List Signer cert).
#[derive(Debug, Clone)]
pub struct ExtendedKeyUsage<'a> {
    /// EKU OID values from the `KeyPurposeId` SEQUENCE (RFC
    /// 5280 §4.2.1.12). Each `Oid<'a>` is borrow-validated at
    /// the BER trust boundary; consumers compare against
    /// constants from [`crate::oid::known`] without re-parsing.
    pub oids: Vec<Oid<'a>>,
    /// The extension's `critical` flag (RFC 5280 §4.2). When
    /// set, a relying party that doesn't recognise every OID
    /// in `oids` must reject the cert.
    pub critical: bool,
}

/// Owned counterpart of [`ExtendedKeyUsage<'_>`]. Used at trust-
/// boundary returns where the result can't borrow from the input
/// extensions buffer (rule-D-clean signature).
#[derive(Debug, Clone)]
pub struct ExtendedKeyUsageOwned {
    /// Raw OID body bytes per entry. Compare with [`Oid::as_bytes`]
    /// against a `pub const Oid<'static>` constant. The owned
    /// `Vec<Vec<u8>>` is a Tier 0 anti-shape (bytes inside bytes,
    /// no validation that each inner Vec is a well-formed OID
    /// body); the bytes ARE validated at parse, but the field
    /// type doesn't carry the invariant. Tighter form is
    /// `Vec<OwnedOid>` once `OwnedOid` lands.
    pub oids: Vec<Vec<u8>>,
    /// The extension's `critical` flag (RFC 5280 §4.2).
    pub critical: bool,
}

impl ExtendedKeyUsageOwned {
    /// `true` if any OID matches `target`'s body bytes.
    #[must_use]
    #[inline]
    pub fn contains(&self, target: Oid<'_>) -> bool {
        self.oids.iter().any(|o| o.as_slice() == target.as_bytes())
    }
}

/// Extract Extended Key Usage with criticality + raw OID bytes.
/// Returns `None` when the extension is absent.
#[must_use]
#[inline]
pub fn extract_extended_key_usage_meta<B: AsRef<[u8]>>(
    extensions: B,
) -> Option<ExtendedKeyUsageOwned> {
    let extensions = extensions.as_ref();
    let meta = find_extension_with_meta(extensions, OID_EXT_KEY_USAGE)?;
    let outer = BerTlv::<Sequence>::parse(meta.value).ok()?;
    let mut oids: Vec<Vec<u8>> = Vec::new();
    for entry in BerTlvIter::new(outer.value) {
        let Ok(entry) = entry else { continue };
        if entry.tag != <BerOid as BerTag>::TAG {
            continue;
        }
        // Tag already checked == 0x06; entry.value is the OID
        // content bytes.
        oids.push(entry.value.to_vec());
    }
    Some(ExtendedKeyUsageOwned {
        oids,
        critical: meta.critical,
    })
}

/// Parsed Key Usage extension with criticality.
///
/// Carries the `KeyUsage` flags and the critical-flag. ICAO
/// Doc 9303 requires DSC certs to carry `Key Usage` critical
/// with only `digitalSignature` asserted; CSCA certs to carry
/// critical `keyCertSign | cRLSign`.
#[derive(Debug, Clone, Copy)]
pub struct KeyUsageMeta {
    /// The parsed Key Usage flags. See [`KeyUsage`] for the
    /// nine bit semantics.
    pub key_usage: KeyUsage,
    /// The extension's `critical` flag (RFC 5280 §4.2).
    pub critical: bool,
}

/// Extract Key Usage with criticality. Returns `None` when the
/// extension is absent or malformed.
#[must_use]
#[inline]
pub fn extract_key_usage_meta<B: AsRef<[u8]>>(extensions: B) -> Option<KeyUsageMeta> {
    let extensions = extensions.as_ref();
    let meta = find_extension_with_meta(extensions, OID_KEY_USAGE)?;
    let bit_string = BerTlv::<BitString>::parse(meta.value).ok()?;
    // First byte = unused-bits count; we don't need it. `.get(1..)?`
    // is `None` exactly when the BIT STRING value is empty.
    let bytes = bit_string.value.get(1..)?;
    let b0 = bytes.first().copied().unwrap_or(0);
    let b1 = bytes.get(1).copied().unwrap_or(0);
    Some(KeyUsageMeta {
        key_usage: KeyUsage {
            digital_signature: b0 & 0x80 != 0,
            non_repudiation: b0 & 0x40 != 0,
            key_encipherment: b0 & 0x20 != 0,
            data_encipherment: b0 & 0x10 != 0,
            key_agreement: b0 & 0x08 != 0,
            key_cert_sign: b0 & 0x04 != 0,
            crl_sign: b0 & 0x02 != 0,
            encipher_only: b0 & 0x01 != 0,
            decipher_only: b1 & 0x80 != 0,
        },
        critical: meta.critical,
    })
}

/// Parsed Basic Constraints (RFC 5280 sec.4.2.1.9). The
/// `cA` flag indicates whether the subject is a CA; `path_len`
/// (when present) caps the length of subsequent issued
/// intermediate certs.
#[derive(Debug, Clone, Copy)]
pub struct BasicConstraints {
    /// Subject is a CA when `true`. Per RFC 5280 §4.2.1.9, the
    /// CA flag identifies whether the subject can issue
    /// further certificates.
    pub ca: bool,
    /// When `Some(n)`, the cert can issue intermediates `n`
    /// levels deep. `None` means no path-length constraint
    /// applies (the field is OPTIONAL in the extension).
    pub path_len: Option<u32>,
    /// The extension's `critical` flag (RFC 5280 §4.2). RFC
    /// 5280 §4.2.1.9 mandates that a CA cert MUST mark
    /// `BasicConstraints` critical; user / DSC certs typically
    /// omit the extension entirely.
    pub critical: bool,
    /// `true` when the extension was present at all. `false`
    /// means the cert had no Basic Constraints extension, which
    /// per RFC 5280 means "not a CA"; a non-CA leaf cert may
    /// legitimately omit it.
    pub present: bool,
}

/// Strictly parsed certificate-extension facts needed by path construction.
///
/// This is intentionally narrower than a general X.509 extension model. It
/// exposes only constraints that the path builder can either enforce or reject
/// explicitly; unknown non-critical extensions remain ignorable as RFC 5280
/// permits.
#[derive(Debug, Clone, Copy)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "this strict parsed profile records independent presence and policy facts"
)]
pub struct PathExtensionProfile {
    /// Basic Constraints, or `present = false` when the extension is absent.
    pub basic_constraints: BasicConstraints,
    /// Key Usage with its critical flag, when present.
    pub key_usage: Option<KeyUsageMeta>,
    /// Whether an Extended Key Usage extension is present and well formed.
    pub extended_key_usage_present: bool,
    /// Whether the strict Extended Key Usage contains `id-kp-OCSPSigning`.
    pub ocsp_signing_extended_key_usage: bool,
    /// Whether an exact, non-critical `id-pkix-ocsp-nocheck` is present.
    pub ocsp_no_check_present: bool,
    /// Whether Name Constraints is present. The path builder currently rejects
    /// this rather than silently ignoring constraints it cannot enforce.
    pub name_constraints_present: bool,
}

/// Failure while decoding the certificate extensions used for path policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathExtensionError {
    /// An Extension or a supported extension value is not strict DER.
    Malformed(&'static str),
    /// Two extensions carry the same OID.
    Duplicate,
    /// A critical extension is outside the small set the path builder handles.
    UnsupportedCritical,
    /// `id-pkix-ocsp-nocheck` was critical or did not contain exactly DER NULL.
    InvalidOcspNoCheck,
}

impl core::fmt::Display for PathExtensionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(detail) => write!(f, "malformed certificate extension: {detail}"),
            Self::Duplicate => f.write_str("duplicate certificate extension"),
            Self::UnsupportedCritical => f.write_str("unsupported critical certificate extension"),
            Self::InvalidOcspNoCheck => f.write_str("malformed id-pkix-ocsp-nocheck extension"),
        }
    }
}

impl core::error::Error for PathExtensionError {}

/// Strictly parse path-relevant certificate extensions.
///
/// Basic Constraints, Key Usage, and Extended Key Usage are decoded rather
/// than merely recognized. Name Constraints is reported to the path builder,
/// which must either enforce or reject it. Any other critical extension fails
/// closed; unknown non-critical extensions are retained as ignorable input.
///
/// # Errors
/// [`PathExtensionError`] for malformed, duplicate, or unsupported critical
/// extensions.
pub fn path_extension_profile(
    extensions: &[u8],
) -> Result<PathExtensionProfile, PathExtensionError> {
    let absent_constraints = BasicConstraints {
        ca: false,
        path_len: None,
        critical: false,
        present: false,
    };
    let mut profile = PathExtensionProfile {
        basic_constraints: absent_constraints,
        key_usage: None,
        extended_key_usage_present: false,
        ocsp_signing_extended_key_usage: false,
        ocsp_no_check_present: false,
        name_constraints_present: false,
    };
    let mut seen = Vec::new();

    for extension in BerTlvIter::new(extensions) {
        let extension = extension
            .map_err(|_ignored| PathExtensionError::Malformed("Extension encoding"))?
            .expect::<Sequence>()
            .map_err(|_ignored| PathExtensionError::Malformed("Extension is not a SEQUENCE"))?;
        let mut fields = extension.iter_children();
        let oid = fields
            .next()
            .ok_or(PathExtensionError::Malformed("Extension has no OID"))?
            .map_err(|_ignored| PathExtensionError::Malformed("Extension OID encoding"))?
            .expect::<BerOid>()
            .map_err(|_ignored| PathExtensionError::Malformed("Extension OID tag"))?;
        let oid = Oid::new(oid.value)
            .map_err(|_ignored| PathExtensionError::Malformed("Extension OID value"))?;
        if seen.contains(&oid) {
            return if oid == known::OCSP_NO_CHECK {
                Err(PathExtensionError::InvalidOcspNoCheck)
            } else {
                Err(PathExtensionError::Duplicate)
            };
        }
        seen.push(oid);

        let next = fields
            .next()
            .ok_or(PathExtensionError::Malformed("Extension has no value"))?
            .map_err(|_ignored| PathExtensionError::Malformed("Extension value encoding"))?;
        let (critical, value) = if next.tag == <Boolean as BerTag>::TAG {
            if next.value != [u8::MAX] {
                return Err(PathExtensionError::Malformed(
                    "critical BOOLEAN is not canonical TRUE",
                ));
            }
            let value = fields
                .next()
                .ok_or(PathExtensionError::Malformed("Extension has no value"))?
                .map_err(|_ignored| PathExtensionError::Malformed("Extension value encoding"))?
                .expect::<OctetString>()
                .map_err(|_ignored| PathExtensionError::Malformed("extnValue tag"))?;
            (true, value)
        } else {
            let value = next
                .expect::<OctetString>()
                .map_err(|_ignored| PathExtensionError::Malformed("extnValue tag"))?;
            (false, value)
        };
        if fields.next().is_some() {
            return Err(PathExtensionError::Malformed(
                "Extension has trailing fields",
            ));
        }

        if oid == known::BASIC_CONSTRAINTS {
            profile.basic_constraints = parse_path_basic_constraints(value.value, critical)?;
        } else if oid == known::KEY_USAGE {
            profile.key_usage = Some(parse_path_key_usage(value.value, critical)?);
        } else if oid == known::EXT_KEY_USAGE {
            profile.ocsp_signing_extended_key_usage = parse_path_extended_key_usage(value.value)?;
            profile.extended_key_usage_present = true;
        } else if oid == known::NAME_CONSTRAINTS {
            profile.name_constraints_present = true;
        } else if oid == known::OCSP_NO_CHECK {
            parse_path_ocsp_no_check(value.value, critical)?;
            profile.ocsp_no_check_present = true;
        } else if critical {
            return Err(PathExtensionError::UnsupportedCritical);
        }
    }

    Ok(profile)
}

fn parse_path_basic_constraints(
    value: &[u8],
    critical: bool,
) -> Result<BasicConstraints, PathExtensionError> {
    let outer = exact_path_extension_tlv::<Sequence>(value, "Basic Constraints")?;
    let mut fields = outer.iter_children();
    let mut ca = false;
    let mut next = fields
        .next()
        .transpose()
        .map_err(|_ignored| PathExtensionError::Malformed("Basic Constraints child encoding"))?;
    if next.is_some_and(|field| field.tag == <Boolean as BerTag>::TAG) {
        let flag = next.ok_or(PathExtensionError::Malformed(
            "Basic Constraints cA is absent",
        ))?;
        match flag.value {
            [0] => {
                // DVV cardholder certificates explicitly encode the DEFAULT
                // FALSE value. DER would omit it, but accepting the exact
                // canonical FALSE value is safe: it cannot grant CA status.
            }
            [u8::MAX] => ca = true,
            _ => {
                return Err(PathExtensionError::Malformed(
                    "Basic Constraints cA is not a canonical DER BOOLEAN",
                ));
            }
        }
        next = fields.next().transpose().map_err(|_ignored| {
            PathExtensionError::Malformed("Basic Constraints pathLen encoding")
        })?;
    }
    let path_len = if let Some(path_len) = next {
        let path_len = path_len
            .expect::<Integer>()
            .map_err(|_ignored| PathExtensionError::Malformed("Basic Constraints pathLen tag"))?;
        if !ca {
            return Err(PathExtensionError::Malformed(
                "Basic Constraints pathLen without cA",
            ));
        }
        Some(parse_path_length(path_len.value)?)
    } else {
        None
    };
    if fields.next().is_some() {
        return Err(PathExtensionError::Malformed(
            "Basic Constraints has trailing fields",
        ));
    }
    Ok(BasicConstraints {
        ca,
        path_len,
        critical,
        present: true,
    })
}

fn parse_path_length(value: &[u8]) -> Result<u32, PathExtensionError> {
    const INTEGER_SIGN_BIT: u8 = 1_u8 << 7_u32;
    /// Maximum number of value octets representable by the public `u32` field.
    const MAX_PATH_LENGTH_OCTETS: usize = 4;
    let Some((&first, rest)) = value.split_first() else {
        return Err(PathExtensionError::Malformed(
            "Basic Constraints pathLen is empty",
        ));
    };
    if first & INTEGER_SIGN_BIT != 0 {
        return Err(PathExtensionError::Malformed(
            "Basic Constraints pathLen is negative",
        ));
    }
    let magnitude = if first == 0 {
        let Some(&second) = rest.first() else {
            return Ok(0);
        };
        if second & INTEGER_SIGN_BIT == 0 {
            return Err(PathExtensionError::Malformed(
                "Basic Constraints pathLen is not DER-minimal",
            ));
        }
        rest
    } else {
        value
    };
    if magnitude.len() > MAX_PATH_LENGTH_OCTETS {
        return Err(PathExtensionError::Malformed(
            "Basic Constraints pathLen is too large",
        ));
    }
    Ok(magnitude
        .iter()
        .fold(0_u32, |length, byte| (length << 8_u32) | u32::from(*byte)))
}

fn parse_path_key_usage(value: &[u8], critical: bool) -> Result<KeyUsageMeta, PathExtensionError> {
    /// Maximum DER BIT STRING count of unused bits in its final octet.
    const MAX_UNUSED_BITS: u8 = 7;
    /// First Key Usage octet: digitalSignature.
    const DIGITAL_SIGNATURE: u8 = 1_u8 << 7_u32;
    /// First Key Usage octet: contentCommitment.
    const CONTENT_COMMITMENT: u8 = 1_u8 << 6_u32;
    /// First Key Usage octet: keyEncipherment.
    const KEY_ENCIPHERMENT: u8 = 1_u8 << 5_u32;
    /// First Key Usage octet: dataEncipherment.
    const DATA_ENCIPHERMENT: u8 = 1_u8 << 4_u32;
    /// First Key Usage octet: keyAgreement.
    const KEY_AGREEMENT: u8 = 1_u8 << 3_u32;
    /// First Key Usage octet: keyCertSign.
    const KEY_CERT_SIGN: u8 = 1_u8 << 2_u32;
    /// First Key Usage octet: cRLSign.
    const CRL_SIGN: u8 = 1_u8 << 1_u32;
    /// First Key Usage octet: encipherOnly.
    const ENCIPHER_ONLY: u8 = 1;
    /// Second Key Usage octet: decipherOnly.
    const DECIPHER_ONLY: u8 = 1_u8 << 7_u32;

    let bit_string = exact_path_extension_tlv::<BitString>(value, "Key Usage")?;
    let Some((&unused, bits)) = bit_string.value.split_first() else {
        return Err(PathExtensionError::Malformed("Key Usage is empty"));
    };
    if unused > MAX_UNUSED_BITS || bits.is_empty() || bits.len() > 2 {
        return Err(PathExtensionError::Malformed("Key Usage width"));
    }
    let last = bits
        .last()
        .copied()
        .ok_or(PathExtensionError::Malformed("Key Usage bits are empty"))?;
    let unused_mask = if unused == 0 {
        0
    } else {
        u8::MAX >> u32::from(8_u8.saturating_sub(unused))
    };
    if last & unused_mask != 0 || last == 0 || last.trailing_zeros() != u32::from(unused) {
        return Err(PathExtensionError::Malformed(
            "Key Usage is not a DER named bit list",
        ));
    }
    let first = bits.first().copied().unwrap_or(0);
    let second = bits.get(1).copied().unwrap_or(0);
    if second & !DECIPHER_ONLY != 0 {
        return Err(PathExtensionError::Malformed("Key Usage has unknown bits"));
    }
    Ok(KeyUsageMeta {
        key_usage: KeyUsage {
            digital_signature: first & DIGITAL_SIGNATURE != 0,
            non_repudiation: first & CONTENT_COMMITMENT != 0,
            key_encipherment: first & KEY_ENCIPHERMENT != 0,
            data_encipherment: first & DATA_ENCIPHERMENT != 0,
            key_agreement: first & KEY_AGREEMENT != 0,
            key_cert_sign: first & KEY_CERT_SIGN != 0,
            crl_sign: first & CRL_SIGN != 0,
            encipher_only: first & ENCIPHER_ONLY != 0,
            decipher_only: second & DECIPHER_ONLY != 0,
        },
        critical,
    })
}

fn parse_path_extended_key_usage(value: &[u8]) -> Result<bool, PathExtensionError> {
    let outer = exact_path_extension_tlv::<Sequence>(value, "Extended Key Usage")?;
    let mut seen = Vec::new();
    for purpose in outer.iter_children() {
        let purpose = purpose
            .map_err(|_ignored| PathExtensionError::Malformed("Extended Key Usage entry"))?
            .expect::<BerOid>()
            .map_err(|_ignored| PathExtensionError::Malformed("Extended Key Usage entry tag"))?;
        let purpose = Oid::new(purpose.value)
            .map_err(|_ignored| PathExtensionError::Malformed("Extended Key Usage OID"))?;
        if seen.contains(&purpose) {
            return Err(PathExtensionError::Malformed(
                "duplicate Extended Key Usage purpose",
            ));
        }
        seen.push(purpose);
    }
    if seen.is_empty() {
        return Err(PathExtensionError::Malformed("Extended Key Usage is empty"));
    }
    Ok(seen.contains(&known::KP_OCSP_SIGNING))
}

fn parse_path_ocsp_no_check(value: &[u8], critical: bool) -> Result<(), PathExtensionError> {
    if critical {
        return Err(PathExtensionError::InvalidOcspNoCheck);
    }
    let null =
        BerTlvAny::parse(value).map_err(|_ignored| PathExtensionError::InvalidOcspNoCheck)?;
    if null.tag != TAG_NULL || !null.value.is_empty() || null.size != value.len() {
        return Err(PathExtensionError::InvalidOcspNoCheck);
    }
    Ok(())
}

fn exact_path_extension_tlv<'a, T: BerTag>(
    value: &'a [u8],
    label: &'static str,
) -> Result<BerTlv<'a, T>, PathExtensionError> {
    let parsed =
        BerTlv::<T>::parse(value).map_err(|_ignored| PathExtensionError::Malformed(label))?;
    if parsed.size != value.len() {
        return Err(PathExtensionError::Malformed(
            "extension value has trailing bytes",
        ));
    }
    Ok(parsed)
}

/// Extract Basic Constraints. Returns a `BasicConstraints`
/// whose `present` flag distinguishes "extension present and
/// parsed" from "extension absent" -- both are valid states
/// for a non-CA cert.
#[must_use]
#[inline]
pub fn extract_basic_constraints<B: AsRef<[u8]>>(extensions: B) -> BasicConstraints {
    let extensions = extensions.as_ref();
    let absent = BasicConstraints {
        ca: false,
        path_len: None,
        critical: false,
        present: false,
    };
    let Some(meta) = find_extension_with_meta(extensions, OID_BASIC_CONSTRAINTS) else {
        return absent;
    };
    let Ok(outer) = BerTlv::<Sequence>::parse(meta.value) else {
        return absent;
    };
    let it = BerTlvIter::new(outer.value);
    let mut ca = false;
    let mut path_len: Option<u32> = None;
    for child in it {
        let Ok(child) = child else { break };
        match child.tag {
            <Boolean as BerTag>::TAG => {
                // Promote through the typed `Boolean` marker (not just its
                // TAG const) so the tag type is exercised as a value, the
                // same idiom the other BER markers use across the crate.
                // The tag already matched, so `expect` cannot fail here.
                if let Ok(flag) = child.expect::<Boolean>() {
                    ca = flag.value.first().is_some_and(|&b| b != 0);
                }
            }
            <Integer as BerTag>::TAG => {
                let mut acc: u32 = 0;
                for &b in child.value {
                    // Path-length INTEGERs in BasicConstraints are
                    // bounded by the cert format; 4 bytes (32 bits)
                    // shifted in -- the wrapping form is the intent
                    // for a u32-sized accumulator.
                    acc = acc.wrapping_shl(8_u32) | u32::from(b);
                }
                path_len = Some(acc);
            }
            _ => {}
        }
    }
    BasicConstraints {
        ca,
        path_len,
        critical: meta.critical,
        present: true,
    }
}

impl X509Helpers {
    /// `eku_label` associated function.
    fn eku_label(oid: Oid<'_>) -> String {
        let oid_bytes = oid.as_bytes();
        let name = match oid_bytes {
            v if v == OID_KP_SERVER_AUTH => "serverAuth",
            v if v == OID_KP_CLIENT_AUTH => "clientAuth",
            v if v == OID_KP_CODE_SIGNING => "codeSigning",
            v if v == OID_KP_EMAIL_PROTECTION => "emailProtection",
            v if v == OID_KP_TIME_STAMPING => "timeStamping",
            v if v == OID_KP_OCSP_SIGNING => "ocspSigning",
            _ => "",
        };
        if name.is_empty() {
            format!("oid:{}", Self::oid_dot_notation(oid))
        } else {
            name.to_owned()
        }
    }

    /// Render a DER-encoded OID body (without the `06 LL`
    /// header) as dotted decimal -- e.g. `[0x2A, 0x86, 0x48,
    /// 0x86, 0xF7, 0x0D]` -> `"1.2.840.113549"`.
    fn oid_dot_notation(oid: Oid<'_>) -> String {
        use core::fmt::Write as _;

        let bytes = oid.as_bytes();
        let mut out = String::new();
        if let Some(&first) = bytes.first() {
            // X.690 §8.19 packs the first two arcs as `first*40 + second`,
            // with the first arc in 0..=2. The divisor is the non-zero
            // constant 40; integer division and modulo are exact.
            let x = u32::from(first.div_euclid(40));
            let y = u32::from(first.rem_euclid(40));
            let _fmt: core::fmt::Result = write!(out, "{x}.{y}");
            let mut acc: u32 = 0;
            // `bytes` is non-empty (first() succeeded), so `bytes.get(1..)`
            // never returns None.
            let tail = bytes.get(1..).unwrap_or(&[]);
            for &b in tail {
                // Subsequent arc bytes pack 7 bits per byte, top bit
                // = "more bytes". A 32-bit accumulator overflows on
                // arcs longer than ~4.6 bytes; FINEID OIDs stay well
                // under that, so wrapping is the chosen failure mode
                // (a 32-bit arc would already be a malformed input).
                acc = acc.wrapping_shl(7_u32) | u32::from(b & 0x7F);
                if b & 0x80 == 0 {
                    let _fmt: core::fmt::Result = write!(out, ".{acc}");
                    acc = 0;
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {

    use super::{
        Certificate, DateTime, X509Error, extract_crl_distribution_urls, extract_ocsp_urls,
        extract_subject_alt_emails, parse_path_basic_constraints,
    };

    // CRL distribution points and OCSP responder URLs are HTTP by
    // spec (RFC 5280 §4.2.1.13 / RFC 6960) -- the payloads are
    // signed by the CA, so transport security adds nothing and
    // HTTPS creates chicken-and-egg trust problems. One
    // suppression here covers every use of these URLs below.
    // noinspection HttpUrlsUsage
    const TEST_CRL_URL: &str = "http://crl.example.com/example.crl";
    // noinspection HttpUrlsUsage
    const TEST_OCSP_URL: &str = "http://ocsp.example.com/";

    #[test]
    fn path_constraints_accept_dvv_explicit_false_without_ca_authority() {
        let constraints = parse_path_basic_constraints(&[0x30, 0x03, 0x01, 0x01, 0x00], true)
            .expect("deployed DVV cardholder encoding is accepted");
        assert!(constraints.present);
        assert!(constraints.critical);
        assert!(!constraints.ca);
        assert_eq!(constraints.path_len, None);
    }

    #[test]
    fn path_constraints_reject_noncanonical_true() {
        let error = parse_path_basic_constraints(&[0x30, 0x03, 0x01, 0x01, 0x01], true)
            .expect_err("TRUE other than ff must remain rejected");
        assert_eq!(
            error,
            super::PathExtensionError::Malformed(
                "Basic Constraints cA is not a canonical DER BOOLEAN"
            )
        );
    }

    #[test]
    fn path_constraints_reject_path_length_after_false() {
        let error =
            parse_path_basic_constraints(&[0x30, 0x06, 0x01, 0x01, 0x00, 0x02, 0x01, 0x00], true)
                .expect_err("a non-CA cannot carry pathLen");
        assert_eq!(
            error,
            super::PathExtensionError::Malformed("Basic Constraints pathLen without cA")
        );
    }

    /// Fixture TLV input for DER test builders.
    #[derive(Clone, Copy)]
    struct TlvFixture<'a> {
        /// ASN.1 tag octet.
        tag: u8,
        /// TLV value bytes.
        value: &'a [u8],
    }

    /// Fixture certificate parts for the parser tests.
    #[derive(Clone, Copy)]
    struct CertFixture<'a> {
        /// Optional explicit version TLV.
        version_explicit: Option<&'a [u8]>,
        /// Serial INTEGER value bytes.
        serial: &'a [u8],
        /// Issuer Name DER.
        issuer: &'a [u8],
        /// notBefore Time TLV.
        not_before: &'a [u8],
        /// notAfter Time TLV.
        not_after: &'a [u8],
        /// Subject Name DER.
        subject: &'a [u8],
        /// Optional extensions list bytes.
        extensions: Option<&'a [u8]>,
    }

    /// Build the smallest possible self-signed-looking certificate
    /// DER from constituent pieces. The signature bytes are pure
    /// padding -- this module doesn't verify them.
    fn build_cert(fixture: CertFixture<'_>) -> Vec<u8> {
        // Algorithm identifier: SEQUENCE { OID 1.2.840.113549.1.1.11 sha256WithRSAEncryption, NULL }
        let sig_alg: Vec<u8> = vec![
            0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05,
            0x00,
        ];
        // SubjectPublicKeyInfo: SEQUENCE { sig_alg, BIT STRING (4 bytes) }
        let spki = {
            let mut v = Vec::new();
            v.push(0x30);
            let body: Vec<u8> = {
                let mut b = sig_alg.clone();
                b.extend_from_slice(&[0x03, 0x05, 0x00, 0xAA, 0xBB, 0xCC, 0xDD]);
                b
            };
            push_len(&mut v, body.len());
            v.extend_from_slice(&body);
            v
        };
        // validity: SEQUENCE { notBefore, notAfter }
        let validity = {
            let mut body = Vec::new();
            body.extend_from_slice(fixture.not_before);
            body.extend_from_slice(fixture.not_after);
            wrap(TlvFixture {
                tag: 0x30,
                value: &body,
            })
        };
        // tbsCertificate body
        let mut tbs_body = Vec::new();
        if let Some(v) = fixture.version_explicit {
            tbs_body.extend_from_slice(v);
        }
        // fixture.serialNumber INTEGER
        tbs_body.extend_from_slice(&wrap(TlvFixture {
            tag: 0x02,
            value: fixture.serial,
        }));
        tbs_body.extend_from_slice(&sig_alg);
        tbs_body.extend_from_slice(fixture.issuer);
        tbs_body.extend_from_slice(&validity);
        tbs_body.extend_from_slice(fixture.subject);
        tbs_body.extend_from_slice(&spki);
        if let Some(ext_list_bytes) = fixture.extensions {
            // Extensions ::= SEQUENCE OF Extension -- wrap the
            // caller-supplied Extension list bytes in their outer
            // SEQUENCE, then in the [3] EXPLICIT TBSCertificate
            // wrapper.
            let ext_seq = wrap(TlvFixture {
                tag: 0x30,
                value: ext_list_bytes,
            });
            let ext_wrap = wrap(TlvFixture {
                tag: 0xA3,
                value: &ext_seq,
            });
            tbs_body.extend_from_slice(&ext_wrap);
        }
        let tbs = wrap(TlvFixture {
            tag: 0x30,
            value: &tbs_body,
        });
        let signature_bit_string: Vec<u8> = vec![0x03, 0x05, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        let mut outer_body = Vec::new();
        outer_body.extend_from_slice(&tbs);
        outer_body.extend_from_slice(&sig_alg);
        outer_body.extend_from_slice(&signature_bit_string);
        wrap(TlvFixture {
            tag: 0x30,
            value: &outer_body,
        })
    }

    const DER_SHORT_FORM_CEILING: u8 = 0x80;

    fn push_len(out: &mut Vec<u8>, n: usize) {
        match u8::try_from(n) {
            Ok(short) if short < DER_SHORT_FORM_CEILING => out.push(short),
            Ok(short) => {
                out.push(0x81);
                out.push(short);
            }
            Err(_) => {
                let long = u16::try_from(n).expect("test TLV lengths fit in u16");
                let [high_byte, low_byte] = long.to_be_bytes();
                out.push(0x82);
                out.push(high_byte);
                out.push(low_byte);
            }
        }
    }

    fn wrap(tlv: TlvFixture<'_>) -> Vec<u8> {
        let mut v = Vec::with_capacity(tlv.value.len() + 4);
        v.push(tlv.tag);
        push_len(&mut v, tlv.value.len());
        v.extend_from_slice(tlv.value);
        v
    }

    /// `CN=Hello`.
    fn name_cn_hello() -> Vec<u8> {
        // ATV: SEQUENCE { OID 2.5.4.3, UTF8String "Hello" }
        let atv_body = {
            let mut b = vec![0x06, 0x03, 0x55, 0x04, 0x03];
            b.extend_from_slice(&[0x0C, 0x05, b'H', b'e', b'l', b'l', b'o']);
            b
        };
        let atv = wrap(TlvFixture {
            tag: 0x30,
            value: &atv_body,
        });
        let rdn = wrap(TlvFixture {
            tag: 0x31,
            value: &atv,
        });
        wrap(TlvFixture {
            tag: 0x30,
            value: &rdn,
        })
    }

    /// `CN=Sample Subject`.
    fn name_cn_sample() -> Vec<u8> {
        let cn_bytes = b"Sample Subject";
        let cn_len = u8::try_from(cn_bytes.len()).expect("14-byte CN fits in u8");
        let atv_body = {
            let mut b = vec![0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, cn_len];
            b.extend_from_slice(cn_bytes);
            b
        };
        let atv = wrap(TlvFixture {
            tag: 0x30,
            value: &atv_body,
        });
        let rdn = wrap(TlvFixture {
            tag: 0x31,
            value: &atv,
        });
        wrap(TlvFixture {
            tag: 0x30,
            value: &rdn,
        })
    }

    /// A valid civil [`DateTime`] for time fixtures.
    fn dt(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> DateTime {
        DateTime::new(year, month, day, hour, minute, second).expect("valid fixture date")
    }

    /// The `UTCTime` TLV for a fixture instant, encoded by der
    /// (`YYMMDDHHMMSSZ`). Requires `dt` in the 1950..=2049 window.
    fn utc_time(dt: DateTime) -> Vec<u8> {
        use spki::der::Encode as _;
        use spki::der::asn1::UtcTime;
        UtcTime::from_date_time(dt)
            .expect("fixture date in the UTCTime window")
            .to_der()
            .expect("UTCTime encodes")
    }

    /// The `GeneralizedTime` TLV for a fixture instant, encoded by
    /// der (`YYYYMMDDHHMMSSZ`).
    fn gen_time(dt: DateTime) -> Vec<u8> {
        use spki::der::Encode as _;
        use spki::der::asn1::GeneralizedTime;
        GeneralizedTime::from_date_time(dt)
            .to_der()
            .expect("GeneralizedTime encodes")
    }

    #[test]
    fn parses_minimal_v3_cert_without_extensions() {
        let cert = build_cert(CertFixture {
            version_explicit: Some(&[0xA0, 0x03, 0x02, 0x01, 0x02]),
            serial: &[0x01, 0x23, 0x45],
            issuer: &name_cn_hello(),
            not_before: &utc_time(dt(2026, 1, 1, 0, 0, 0)),
            not_after: &utc_time(dt(2031, 1, 1, 0, 0, 0)),
            subject: &name_cn_sample(),
            extensions: None,
        });
        let parsed = Certificate::from_der(&cert).expect("parses");
        assert_eq!(parsed.serial_der, &[0x01, 0x23, 0x45]);
        assert_eq!(
            parsed.not_before,
            DateTime::new(2026, 1, 1, 0, 0, 0).expect("valid notBefore")
        );
        assert_eq!(
            parsed.not_after,
            DateTime::new(2031, 1, 1, 0, 0, 0).expect("valid notAfter")
        );
        assert!(parsed.extensions.is_none());
        assert_eq!(
            parsed.subject.common_name().as_deref(),
            Some("Sample Subject")
        );
        assert_eq!(parsed.issuer.common_name().as_deref(), Some("Hello"));
    }

    #[test]
    fn parses_generalized_time() {
        let cert = build_cert(CertFixture {
            version_explicit: Some(&[0xA0, 0x03, 0x02, 0x01, 0x02]),
            serial: &[0x01],
            issuer: &name_cn_hello(),
            not_before: &gen_time(dt(2100, 1, 1, 12, 0, 0)),
            not_after: &gen_time(dt(2150, 1, 1, 12, 0, 0)),
            subject: &name_cn_sample(),
            extensions: None,
        });
        let parsed = Certificate::from_der(&cert).expect("parses");
        assert_eq!(parsed.not_before.year(), 2100);
        assert_eq!(parsed.not_before.hour(), 12);
        assert_eq!(parsed.not_after.year(), 2150);
    }

    #[test]
    fn utc_time_yy_below_50_is_2000s() {
        let cert = build_cert(CertFixture {
            version_explicit: None,
            serial: &[0x01],
            issuer: &name_cn_hello(),
            not_before: &utc_time(dt(2049, 1, 1, 0, 0, 0)),
            // YY >= 50 -> 19YY; 99 -> 1999, which stays within
            // der::DateTime's 1970 floor (X.509 postdates 1970).
            not_after: &utc_time(dt(1999, 1, 1, 0, 0, 0)),
            subject: &name_cn_sample(),
            extensions: None,
        });
        let parsed = Certificate::from_der(&cert).expect("parses");
        assert_eq!(parsed.not_before.year(), 2049);
        assert_eq!(parsed.not_after.year(), 1999);
    }

    #[test]
    fn rejects_garbage_time() {
        // 13-char body but the digits are wrong.
        let bad_time = {
            let mut v = vec![0x17, 13];
            v.extend_from_slice(b"YYMMDDHHMMSSZ");
            v
        };
        let cert = build_cert(CertFixture {
            version_explicit: None,
            serial: &[0x01],
            issuer: &name_cn_hello(),
            not_before: &bad_time,
            not_after: &utc_time(dt(2031, 1, 1, 0, 0, 0)),
            subject: &name_cn_sample(),
            extensions: None,
        });
        let err = Certificate::from_der(&cert).expect_err("non-digit time body is rejected");
        assert!(matches!(err, X509Error::InvalidTime));
    }

    #[test]
    fn extracts_crl_distribution_urls() {
        // GeneralName URI with our URL.
        let url = TEST_CRL_URL.as_bytes();
        let url_len = u8::try_from(url.len()).expect("test CRL URL fits in u8");
        let mut gn = vec![0x86, url_len];
        gn.extend_from_slice(url);
        // [0] IMPLICIT GeneralNames wrapper = 0xA0 holding the GeneralName.
        let dp_full = wrap(TlvFixture {
            tag: 0xA0,
            value: &gn,
        });
        // [0] EXPLICIT DistributionPointName wrapping the above.
        let dp_name = wrap(TlvFixture {
            tag: 0xA0,
            value: &dp_full,
        });
        // DistributionPoint SEQUENCE { distributionPoint [0] ... }
        let dp = wrap(TlvFixture {
            tag: 0x30,
            value: &dp_name,
        });
        // CRLDistributionPoints SEQUENCE OF DistributionPoint
        let cdp_seq = wrap(TlvFixture {
            tag: 0x30,
            value: &dp,
        });
        // OCTET STRING extnValue wrapping the CDP SEQUENCE
        let extn_value = wrap(TlvFixture {
            tag: 0x04,
            value: &cdp_seq,
        });
        // Extension { OID 2.5.29.31, extnValue }
        let mut ext_body = vec![0x06, 0x03, 0x55, 0x1D, 0x1F];
        ext_body.extend_from_slice(&extn_value);
        let extension = wrap(TlvFixture {
            tag: 0x30,
            value: &ext_body,
        });
        // Extensions SEQUENCE OF Extension
        let extensions_seq_body = extension;
        let cert = build_cert(CertFixture {
            version_explicit: Some(&[0xA0, 0x03, 0x02, 0x01, 0x02]),
            serial: &[0x01],
            issuer: &name_cn_hello(),
            not_before: &utc_time(dt(2026, 1, 1, 0, 0, 0)),
            not_after: &utc_time(dt(2031, 1, 1, 0, 0, 0)),
            subject: &name_cn_sample(),
            extensions: Some(&extensions_seq_body),
        });
        let parsed = Certificate::from_der(&cert).expect("parses");
        let exts = parsed.extensions.expect("extensions present");
        let urls = extract_crl_distribution_urls(exts);
        let rendered: Vec<String> = urls.iter().map(ToString::to_string).collect();
        assert_eq!(rendered, vec![TEST_CRL_URL.to_owned()]);
    }

    #[test]
    fn extracts_ocsp_urls() {
        let url = TEST_OCSP_URL.as_bytes();
        let url_len = u8::try_from(url.len()).expect("test OCSP URL fits in u8");
        let mut gn = vec![0x86, url_len];
        gn.extend_from_slice(url);
        // AccessDescription { OID 1.3.6.1.5.5.7.48.1 id-ad-ocsp, GeneralName URI }
        let mut ad_body = vec![0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
        ad_body.extend_from_slice(&gn);
        let ad = wrap(TlvFixture {
            tag: 0x30,
            value: &ad_body,
        });
        let aia_seq = wrap(TlvFixture {
            tag: 0x30,
            value: &ad,
        });
        let extn_value = wrap(TlvFixture {
            tag: 0x04,
            value: &aia_seq,
        });
        let mut ext_body = vec![0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];
        ext_body.extend_from_slice(&extn_value);
        let extension = wrap(TlvFixture {
            tag: 0x30,
            value: &ext_body,
        });
        let cert = build_cert(CertFixture {
            version_explicit: Some(&[0xA0, 0x03, 0x02, 0x01, 0x02]),
            serial: &[0x01],
            issuer: &name_cn_hello(),
            not_before: &utc_time(dt(2026, 1, 1, 0, 0, 0)),
            not_after: &utc_time(dt(2031, 1, 1, 0, 0, 0)),
            subject: &name_cn_sample(),
            extensions: Some(&extension),
        });
        let parsed = Certificate::from_der(&cert).expect("parses");
        let urls = extract_ocsp_urls(parsed.extensions.expect("extensions present"));
        let rendered: Vec<String> = urls.iter().map(ToString::to_string).collect();
        assert_eq!(rendered, vec![TEST_OCSP_URL.to_owned()]);
    }

    #[test]
    fn extracts_subject_alt_emails() {
        let email = b"holder@example.fi";
        let email_len = u8::try_from(email.len()).expect("17-byte email fits in u8");
        let mut gn = vec![0x81, email_len];
        gn.extend_from_slice(email);
        let san_seq = wrap(TlvFixture {
            tag: 0x30,
            value: &gn,
        });
        let extn_value = wrap(TlvFixture {
            tag: 0x04,
            value: &san_seq,
        });
        let mut ext_body = vec![0x06, 0x03, 0x55, 0x1D, 0x11];
        ext_body.extend_from_slice(&extn_value);
        let extension = wrap(TlvFixture {
            tag: 0x30,
            value: &ext_body,
        });
        let cert = build_cert(CertFixture {
            version_explicit: None,
            serial: &[0x01],
            issuer: &name_cn_hello(),
            not_before: &utc_time(dt(2026, 1, 1, 0, 0, 0)),
            not_after: &utc_time(dt(2031, 1, 1, 0, 0, 0)),
            subject: &name_cn_sample(),
            extensions: Some(&extension),
        });
        let parsed = Certificate::from_der(&cert).expect("parses");
        let emails = extract_subject_alt_emails(parsed.extensions.expect("extensions present"));
        assert_eq!(emails, vec!["holder@example.fi"]);
    }

    #[test]
    fn datetime_ordering_matches_lex_order() {
        let a = DateTime::new(2026, 5, 23, 12, 0, 0).expect("valid a");
        let b = DateTime::new(2026, 5, 23, 12, 0, 1).expect("valid b");
        let c = DateTime::new(2027, 1, 1, 0, 0, 0).expect("valid c");
        assert!(a < b);
        assert!(b < c);
        assert!(a < c);
    }
}
