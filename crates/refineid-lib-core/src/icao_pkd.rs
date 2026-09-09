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

//! ICAO PKD Master List parsing.
//!
//! ICAO 9303 Part 12 Appendix C defines the `CscaMasterList`.
//!
//! The bundle is an ASN.1 structure: a CMS `SignedData` whose
//! eContent is
//!
//! ```asn1
//! CscaMasterList ::= SEQUENCE {
//!     version    INTEGER,
//!     certList   SET OF Certificate
//! }
//! ```
//!
//! and whose eContentType OID is `2.23.136.1.1.2`
//! (`id-icao-cscaMasterList`). One file = N CSCA roots bundled
//! into one atom signed by the ICAO PKD Master List Signer
//! (MLS) cert.
//!
//! This module:
//!
//! 1. parses the CMS wrapper,
//! 2. verifies the eContentType is the master list OID,
//! 3. verifies the CMS signature against the embedded signer
//!    cert (proves the bundle wasn't tampered with after the
//!    signer signed it),
//! 4. walks the certList, parsing each entry as X.509 and
//!    extracting subject CN / country / validity / fingerprint
//!    for indexing.
//!
//! **What this does NOT do:** verify the signer cert against a
//! pinned root. The signer cert chains to the ICAO PKD root
//! ("Country Signing CA - Master List Signer Root") whose
//! SHA-256 we don't currently pin. Callers that need
//! cryptographic trust in the bundle source must independently
//! verify the signer cert against a known anchor; for now the
//! operator is the trust source ("I downloaded this from the
//! ICAO PKD"), mirroring how `--crl-file` works.
//!
//! Sourcing: ICAO publishes Master Lists monthly through the
//! ICAO PKD distribution channel (LDAP / authenticated
//! download). There is no public HTTP endpoint, so refineid
//! takes the bundle as a file path -- the operator pulls it
//! out-of-band.

use crate::cms::{CmsError, SignedData};
use crate::country::IsoAlpha2;
use crate::crypto::digest::Sha256;
use crate::ldif::{self, LdifError};
use crate::oid::known;
use crate::x509::{Certificate, DateTime, X509Error};

// The eContentType for a CMS-wrapped ICAO PKD CSCA Master List
// (`id-icao-cscaMasterList`, ICAO 9303 Part 12 Appendix C) is
// `known::CSCA_MASTER_LIST`.

/// Result of parsing + verifying one CSCA Master List file.
#[derive(Debug, Clone)]
pub struct IcaoMasterList {
    /// `master list signer` info derived from the first embedded
    /// signer certificate. Operators visually check this matches
    /// the published ICAO PKD signer identity (e.g. "United
    /// Nations CSCA") before trusting the unpacked CSCA list.
    pub signer_subject_cn: Option<crate::identity::CommonName>,
    /// ISO 3166-1 alpha-2 country code from the signer cert's
    /// subject DN `C=` attribute. Used to cross-check the
    /// signer's nationality against the ML's expected origin.
    pub signer_country: Option<IsoAlpha2>,
    /// DER bytes of the embedded ML signer cert. Caller may
    /// fingerprint and pin separately.
    pub signer_cert_der: Vec<u8>,
    /// All certs embedded in the CMS `SignedData.certificates`
    /// field, in the order they appeared. Typically this is
    /// `[signer, signer-issuer]` -- the signer plus the ICAO
    /// PKD root that issued it -- so a verifier can chain to
    /// the root using bytes from the ML itself rather than
    /// fishing for the root externally. The first entry is the
    /// same DER as `signer_cert_der`.
    pub embedded_certs_der: Vec<Vec<u8>>,
    /// Each CSCA cert in the list, parsed for indexing fields.
    pub cscas: Vec<CscaEntry>,
}

/// One CSCA cert lifted from the Master List's certList.
#[derive(Debug, Clone)]
pub struct CscaEntry {
    /// Raw X.509 DER bytes.
    pub der: Vec<u8>,
    /// `subject.countryName` (ISO 3166-1 alpha-2) when present
    /// on the CSCA subject DN. Used to index "which CSCA verifies
    /// passports issued by country X".
    pub country_iso: Option<IsoAlpha2>,
    /// `subject.commonName` attribute when present on the CSCA's
    /// subject DN (RFC 5280 §4.1.2.6).
    pub subject_cn: Option<crate::identity::CommonName>,
    /// X.509 cert serial number.
    pub serial: crate::identity::CertSerial,
    /// SHA-256 fingerprint of `der`.
    pub sha256: Sha256,
    /// `notBefore` of the `TBSCertificate` per RFC 5280 §4.1.2.5.
    pub not_before: DateTime,
    /// `notAfter` of the `TBSCertificate` per RFC 5280 §4.1.2.5.
    pub not_after: DateTime,
}

/// Error returned from the ICAO PKD Master List parser.
#[derive(Debug)]
pub enum IcaoMlError {
    /// Top-level CMS parse failure.
    Cms(CmsError),
    /// CMS eContentType OID wasn't `id-icao-cscaMasterList`
    /// per ICAO 9303 Part 12 Appendix C.
    UnexpectedContentType {
        /// Hex rendering of the unexpected OID body. Tier 0
        /// `String`; presentational copy of the observed bytes.
        got_hex: String,
    },
    /// CMS `SignedData.certificates` was empty -- the ICAO PKD
    /// convention always embeds the signer cert.
    SignerNotEmbedded,
    /// CMS signature didn't verify against the embedded signer's
    /// SPKI; carries the underlying `CmsError`.
    SignatureInvalid(CmsError),
    /// Master List inner payload structure didn't match the
    /// expected shape. Tier 0 `&'static str` from a fixed
    /// compile-time set.
    PayloadStructure(&'static str),
    /// One of the embedded CSCAs failed X.509 DER parse.
    CertParse {
        /// 0-based index of the offending cert in the certList.
        /// Tier 0 `usize`; arithmetic count.
        index: usize,
        /// Underlying `X509Error` from the certificate parser.
        source: X509Error,
    },
    /// LDIF wrapper parse failure (when loading from an LDIF
    /// PKD distribution rather than a single `.ml` DER).
    Ldif(LdifError),
    /// LDIF parsed but contained no Master Lists.
    LdifNoMasterLists,
}

impl core::fmt::Display for IcaoMlError {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cms(e) => write!(f, "CMS parse: {e}"),
            Self::UnexpectedContentType { got_hex } => write!(
                f,
                "unexpected eContentType: got {got_hex}, expected id-icao-cscaMasterList \
                 (2.23.136.1.1.2)"
            ),
            Self::SignerNotEmbedded => write!(
                f,
                "no signer cert embedded in the SignedData (CMS spec allows this but ICAO ML \
                 always carries the MLS cert)"
            ),
            Self::SignatureInvalid(e) => write!(f, "ML signature verify: {e}"),
            Self::PayloadStructure(s) => write!(f, "CscaMasterList structure: {s}"),
            Self::CertParse { index, source } => {
                write!(f, "CSCA #{index}: cert parse: {source}")
            }
            Self::Ldif(e) => write!(f, "LDIF parse: {e}"),
            Self::LdifNoMasterLists => write!(
                f,
                "LDIF contained no records with objectclass=pkdMasterList \
                 (this LDIF doesn't carry any Master Lists)"
            ),
        }
    }
}

impl core::error::Error for IcaoMlError {}

impl From<CmsError> for IcaoMlError {
    #[inline]
    fn from(e: CmsError) -> Self {
        Self::Cms(e)
    }
}

impl From<LdifError> for IcaoMlError {
    #[inline]
    fn from(e: LdifError) -> Self {
        Self::Ldif(e)
    }
}

/// Parse + verify a CSCA Master List DER blob.
///
/// Verification gates:
///
/// 1. eContentType must be `id-icao-cscaMasterList`.
/// 2. CMS signature must verify against the first embedded
///    signer cert's SPKI.
/// 3. eContent must decode as `CscaMasterList`'s SEQUENCE shape.
///
/// Each entry in the certList is best-effort parsed: a single
/// malformed cert causes [`IcaoMlError::CertParse`] with the
/// offending index, so callers can surface it without losing
/// the well-formed entries before it.
///
/// # Errors
/// Any of the verification gates failing, or X.509 parse failure
/// on an individual CSCA entry.
#[inline]
pub fn parse_master_list<B: AsRef<[u8]>>(der: B) -> Result<IcaoMasterList, IcaoMlError> {
    let signed = SignedData::parse(der.as_ref())?;
    if signed.econtent_type_oid.as_bytes() != known::CSCA_MASTER_LIST.as_bytes() {
        return Err(IcaoMlError::UnexpectedContentType {
            got_hex: crate::hex::Hex::encode(signed.econtent_type_oid.as_bytes()),
        });
    }

    let signer_der: &[u8] = signed
        .certificates_der
        .first()
        .copied()
        .ok_or(IcaoMlError::SignerNotEmbedded)?;
    let signer_cert = Certificate::from_der(signer_der).map_err(|e| IcaoMlError::CertParse {
        index: usize::MAX,
        source: e,
    })?;
    signed
        .verify(signer_cert.spki.as_der())
        .map_err(IcaoMlError::SignatureInvalid)?;

    let csca_list = IcaoMasterList::parse_certlist(signed.econtent_der)?;
    let mut cscas = Vec::with_capacity(csca_list.len());
    for (index, cert_der) in csca_list.into_iter().enumerate() {
        let cert = Certificate::from_der(cert_der)
            .map_err(|source| IcaoMlError::CertParse { index, source })?;
        cscas.push(CscaEntry::from_cert(cert_der, &cert));
    }

    Ok(IcaoMasterList {
        signer_subject_cn: signer_cert.subject.common_name(),
        signer_country: signer_cert.subject.country(),
        signer_cert_der: signer_der.to_vec(),
        embedded_certs_der: signed
            .certificates_der
            .iter()
            .map(|der| der.to_vec())
            .collect(),
        cscas,
    })
}

/// Extract every embedded Master List DER blob from an ICAO PKD
/// `icaopkd-002-...ldif` distribution file.
///
/// The 002 LDIF subtree carries one record per participating
/// state's signed Master List. Each record uses the
/// `pkdMasterList` object class and the
/// `pkdMasterListContent;binary::<base64>` attribute carries
/// the DER bytes of that state's `.ml` file. This function
/// returns those raw DER blobs; callers feed each one into
/// [`parse_master_list`] to verify + index it independently.
///
/// # Errors
/// LDIF parse failure surfaces as [`IcaoMlError::Ldif`];
/// [`IcaoMlError::LdifNoMasterLists`] when the file contained
/// no `pkdMasterList` records (e.g. the operator pointed at
/// the 001 / 003 / 004 / 005 LDIFs by mistake).
#[inline]
pub fn extract_master_list_ders_from_ldif<S: AsRef<str>>(
    text: S,
) -> Result<Vec<Vec<u8>>, IcaoMlError> {
    let records = ldif::parse(text)?;
    let mut out: Vec<Vec<u8>> = Vec::new();
    for record in &records {
        if !record.has_object_class("pkdMasterList") {
            continue;
        }
        for blob in record.binary_values("pkdMasterListContent") {
            out.push(blob.to_vec());
        }
    }
    if out.is_empty() {
        Err(IcaoMlError::LdifNoMasterLists)
    } else {
        Ok(out)
    }
}

// `cscas_for_country` is a method on `IcaoMasterList`; see
// `IcaoMasterList::cscas_for_country` below.

impl CscaEntry {
    /// Lift a parsed X.509 `Certificate` into a `CscaEntry`,
    /// computing the SHA-256 fingerprint over `der` and pulling
    /// country / CN / serial / validity off the cert.
    fn from_cert(der: &[u8], cert: &Certificate<'_>) -> Self {
        Self {
            der: der.to_vec(),
            country_iso: cert.subject.country(),
            subject_cn: cert.subject.common_name(),
            serial: cert.serial(),
            sha256: Sha256::of(der),
            not_before: cert.not_before,
            not_after: cert.not_after,
        }
    }
}

impl IcaoMasterList {
    /// Collect every CSCA whose subject country matches
    /// `iso_2letter`.
    ///
    /// ICAO Master Lists carry multiple generations of CSCAs per
    /// country (old + current), so this returns a `Vec` rather
    /// than a single entry.
    #[must_use]
    #[inline]
    pub fn cscas_for_country(&self, iso_2letter: &IsoAlpha2) -> Vec<&CscaEntry> {
        self.cscas
            .iter()
            .filter(|c| c.country_iso.as_ref() == Some(iso_2letter))
            .collect()
    }

    /// Decode the eContent's `CscaMasterList ::= SEQUENCE {
    /// INTEGER, SET OF Certificate }` and return the certList
    /// children as borrowed slices (each one is a full
    /// Certificate TLV, tag + length + value, ready to feed
    /// straight into the X.509 parser).
    fn parse_certlist(econtent: &[u8]) -> Result<Vec<&[u8]>, IcaoMlError> {
        use crate::ber::{BerTlv, BerTlvAny, BerTlvIter, Sequence, Set};

        let seq = BerTlv::<Sequence>::parse(econtent)
            .map_err(|_ber_err| IcaoMlError::PayloadStructure("outer SEQUENCE"))?;
        let mut iter = BerTlvIter::new(seq.value);
        let _version = iter
            .next()
            .ok_or(IcaoMlError::PayloadStructure("missing version INTEGER"))?
            .map_err(|_ber_err| IcaoMlError::PayloadStructure("malformed version INTEGER"))?;
        let cert_set_any: BerTlvAny<'_> = iter
            .next()
            .ok_or(IcaoMlError::PayloadStructure("missing certList SET"))?
            .map_err(|_ber_err| IcaoMlError::PayloadStructure("malformed certList SET"))?;
        let cert_set_tlv = cert_set_any
            .expect::<Set>()
            .map_err(|_ber_err| IcaoMlError::PayloadStructure("certList tag is not SET"))?;
        // Walk by-cursor so we can hand each child's FULL bytes
        // (tag + length + value) to the X.509 parser. The
        // iterator yields value-only slices.
        let mut out = Vec::new();
        let mut cursor = 0_usize;
        while cursor < cert_set_tlv.value.len() {
            let from_cursor = cert_set_tlv
                .value
                .get(cursor..)
                .ok_or(IcaoMlError::PayloadStructure("certList cursor past end"))?;
            let child = BerTlvAny::parse(from_cursor)
                .map_err(|_ber_err| IcaoMlError::PayloadStructure("certList entry"))?;
            child.expect::<Sequence>().map_err(|_ber_err| {
                IcaoMlError::PayloadStructure("certList entry is not a Certificate SEQUENCE")
            })?;
            let next_cursor = cursor
                .checked_add(child.size)
                .ok_or(IcaoMlError::PayloadStructure("certList cursor overflow"))?;
            let entry = cert_set_tlv
                .value
                .get(cursor..next_cursor)
                .ok_or(IcaoMlError::PayloadStructure("certList entry past end"))?;
            out.push(entry);
            cursor = next_cursor;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {

    use crate::oid::known;

    #[test]
    fn ml_oid_encoding() {
        // 2.23.136.1.1.2 -- first two arcs (2.23) encode as
        // 40*2+23 = 103 = 0x67, then 136 = 0x81 0x08 in base-128,
        // then 1, 1, 2 = 0x01 0x01 0x02. Confirms the dotted-decimal
        // `known::CSCA_MASTER_LIST` parses to the spec encoding.
        assert_eq!(
            known::CSCA_MASTER_LIST.as_bytes(),
            &[0x67, 0x81, 0x08, 0x01, 0x01, 0x02][..]
        );
    }
}
