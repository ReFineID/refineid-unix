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

//! `refineid cert show PATH`: pretty-print a DER or PEM cert.
//!
//! No card required. Surfaces subject CN, issuer CN, serial,
//! validity window, key usage, public-key shape, SHA-256
//! fingerprint, and any AIA / CRL / OCSP / SAN-email URLs that
//! live in v3 extensions. Useful for inspecting saved cert DERs
//! (`card status --save-cert DIR`), DSCs extracted from EF.SOD
//! (`card emrtd --save-dsc`), or CSCAs fetched from third-party
//! channels.

use alloc::fmt;
use std::path::{Path, PathBuf};

use crate::text::decode_cert_pem_or_der;
use refineid_lib_core::crypto::digest::Sha256;
use refineid_lib_core::x509::{
    DateTime, OwnedCert, X509Error, extract_ca_issuers_urls, extract_crl_distribution_urls,
    extract_extended_key_usage, extract_key_usage, extract_ocsp_urls, extract_subject_alt_emails,
    parse_subject_public_key_info,
};

/// One pretty-printed cert.
#[derive(Debug)]
pub struct CertShowReport {
    /// Filesystem path the cert was loaded from. Kept so the
    /// report header can name the input file without re-deriving
    /// it from the caller.
    pub path: PathBuf,
    /// Wire form the file was in: DER (raw ASN.1 bytes) or PEM
    /// (base64-armoured). Surfaced so the operator can confirm
    /// they're inspecting what they think they are.
    pub source_form: SourceForm,
    /// Common Name attribute from the cert's subject DN per
    /// RFC 5280 §4.1.2.6. `None` if absent / unparseable.
    pub subject_cn: Option<refineid_lib_core::identity::CommonName>,
    /// Common Name attribute from the cert's issuer DN per
    /// RFC 5280 §4.1.2.4. `None` if absent / unparseable.
    pub issuer_cn: Option<refineid_lib_core::identity::CommonName>,
    /// X.509 INTEGER serial number per RFC 5280 §4.1.2.2.
    pub serial: refineid_lib_core::identity::CertSerial,
    /// `notBefore` of the `TBSCertificate` per RFC 5280 §4.1.2.5.
    pub not_before: DateTime,
    /// `notAfter` of the `TBSCertificate` per RFC 5280 §4.1.2.5.
    pub not_after: DateTime,
    /// Human-readable summary of the `SubjectPublicKeyInfo` per
    /// RFC 5280 §4.1.2.7 (e.g. "RSA 3072-bit", "ECDSA P-384").
    /// Tier 0 `String` -- presentational; the typed form is
    /// `PublicKeyAlgorithm` from `lib-core::x509`.
    pub public_key_summary: String,
    /// RFC 5280 §4.2.1.3 `KeyUsage` bit names that are asserted
    /// (e.g. `["digitalSignature", "nonRepudiation"]`). Tier 0
    /// `Vec<&'static str>` -- presentational; the typed form is
    /// `KeyUsage` with per-bit booleans.
    pub key_usage: Vec<&'static str>,
    /// RFC 5280 §4.2.1.12 `ExtendedKeyUsage` OIDs in dotted form.
    /// Tier 0 `Vec<String>` -- presentational; the typed form is
    /// `Vec<Oid<'a>>`.
    pub extended_key_usage: Vec<String>,
    /// `rfc822Name` SAN entries per RFC 5280 §4.2.1.6, each
    /// RFC 822 form-validated at parse time.
    pub san_emails: Vec<refineid_lib_core::identity::EmailAddress>,
    /// `cRLDistributionPoints` HTTP/HTTPS URLs per RFC 5280
    /// §4.2.1.13.
    pub crl_urls: Vec<refineid_lib_core::text::Uri>,
    /// `authorityInfoAccess` OCSP URLs per RFC 5280 §4.2.2.1
    /// (accessMethod = `id-ad-ocsp`).
    pub ocsp_urls: Vec<refineid_lib_core::text::Uri>,
    /// `authorityInfoAccess` caIssuers URLs per RFC 5280 §4.2.2.1
    /// (accessMethod = `id-ad-caIssuers`).
    pub ca_issuers_urls: Vec<refineid_lib_core::text::Uri>,
    /// SHA-256 of the full DER encoding (recomputed after PEM
    /// decoding when source was PEM). The fingerprint operators
    /// compare against pinned roots.
    pub sha256_fingerprint: Sha256,
    /// Signature algorithm OID bytes (the value content of the
    /// `AlgorithmIdentifier`'s OID TLV). Rendered to dotted
    /// form via [`refineid_lib_core::oid::Oid`]'s `Display`
    /// impl at format time; stored as raw bytes here so the
    /// typed view doesn't need a lifetime tie to the cert.
    pub signature_alg_oid: Vec<u8>,
}

/// Wire form the cert file was in before decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceForm {
    /// Raw ASN.1 DER bytes -- first byte is `0x30` (SEQUENCE).
    Der,
    /// Base64-armoured PEM with `-----BEGIN CERTIFICATE-----`
    /// header per RFC 7468.
    Pem,
}

/// Error returned from `show_cert`.
#[derive(Debug)]
pub enum CertShowError {
    /// File I/O failed (`NotFound`, `PermissionDenied`, ...).
    Read {
        /// Filesystem path the read was attempted against.
        path: PathBuf,
        /// Underlying `std::io::Error`.
        source: std::io::Error,
    },
    /// File loaded but didn't decode as DER or PEM, or the
    /// decoded bytes weren't a valid X.509 certificate.
    Decode {
        /// Filesystem path the decode was attempted against.
        path: PathBuf,
        /// Human-readable decoder / parser error. Tier 0
        /// `String`; presentational.
        detail: String,
    },
}

impl fmt::Display for CertShowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => write!(f, "read {}: {source}", path.display()),
            Self::Decode { path, detail } => write!(f, "decode {}: {detail}", path.display()),
        }
    }
}

impl core::error::Error for CertShowError {}

/// Load `path` and parse it as a cert. Returns a printable report.
///
/// # Errors
/// I/O failure on the file, or a DER / PEM parse failure.
pub(crate) fn show_cert(path: &Path) -> Result<CertShowReport, CertShowError> {
    let bytes = std::fs::read(path).map_err(|source| CertShowError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let source_form = if bytes.first() == Some(&0x30) {
        SourceForm::Der
    } else {
        SourceForm::Pem
    };
    let der = decode_cert_pem_or_der(&bytes).ok_or_else(|| CertShowError::Decode {
        path: path.to_path_buf(),
        detail: "not PEM (-----BEGIN CERTIFICATE-----) or DER (SEQUENCE 0x30)".to_owned(),
    })?;
    let cert_owned = OwnedCert::from_der(&der).map_err(|e: X509Error| CertShowError::Decode {
        path: path.to_path_buf(),
        detail: format!("parse: {e}"),
    })?;
    let cert = cert_owned.view();

    let subject_cn = cert.subject.common_name();
    let issuer_cn = cert.issuer.common_name();
    let serial = cert.serial();
    let public_key_summary = parse_subject_public_key_info(cert.spki.as_der()).map_or_else(
        || "unknown public-key encoding".to_owned(),
        refineid_lib_core::x509::PublicKeyAlgorithm::label,
    );
    let (key_usage, extended_key_usage, san_emails, crl_urls, ocsp_urls, ca_issuers_urls) =
        cert.extensions.map_or_else(
            || {
                (
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                )
            },
            |ext| {
                (
                    key_usage_labels(extract_key_usage(ext)),
                    extract_extended_key_usage(ext),
                    extract_subject_alt_emails(ext),
                    extract_crl_distribution_urls(ext),
                    extract_ocsp_urls(ext),
                    extract_ca_issuers_urls(ext),
                )
            },
        );
    let sha256_fingerprint = Sha256::of(cert.raw_der);
    let signature_alg_oid = cert.signature_alg_oid.as_bytes().to_vec();

    Ok(CertShowReport {
        path: path.to_path_buf(),
        source_form,
        subject_cn,
        issuer_cn,
        serial,
        not_before: cert.not_before,
        not_after: cert.not_after,
        public_key_summary,
        key_usage,
        extended_key_usage,
        san_emails,
        crl_urls,
        ocsp_urls,
        ca_issuers_urls,
        sha256_fingerprint,
        signature_alg_oid,
    })
}

/// Convert a parsed `KeyUsage` extension bit-set into the
/// ordered list of `&'static str` labels the report emits.
///
/// RFC 5280 §4.2.1.3. Returns labels in spec order
/// (digitalSignature, nonRepudiation, ...). An absent
/// extension returns an empty vector; the report treats
/// "extension absent" identically to "extension present but
/// no bits asserted" because both are observationally
/// indistinguishable for the cardholder-facing summary.
fn key_usage_labels(ku: Option<refineid_lib_core::x509::KeyUsage>) -> Vec<&'static str> {
    let Some(ku) = ku else { return Vec::new() };
    let mut out = Vec::new();
    if ku.digital_signature {
        out.push("digitalSignature");
    }
    if ku.non_repudiation {
        out.push("nonRepudiation");
    }
    if ku.key_encipherment {
        out.push("keyEncipherment");
    }
    if ku.data_encipherment {
        out.push("dataEncipherment");
    }
    if ku.key_agreement {
        out.push("keyAgreement");
    }
    if ku.key_cert_sign {
        out.push("keyCertSign");
    }
    if ku.crl_sign {
        out.push("cRLSign");
    }
    out
}

impl fmt::Display for CertShowReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{} ({})",
            self.path.display(),
            match self.source_form {
                SourceForm::Der => "DER",
                SourceForm::Pem => "PEM",
            }
        )?;
        if let Some(cn) = &self.subject_cn {
            writeln!(f, "  subject CN:       {cn}")?;
        }
        if let Some(cn) = &self.issuer_cn {
            writeln!(f, "  issuer CN:        {cn}")?;
        }
        writeln!(f, "  serial:           {}", self.serial)?;
        writeln!(
            f,
            "  not before:       {}",
            crate::text::fmt_rfc3339(self.not_before)
        )?;
        writeln!(
            f,
            "  not after:        {}",
            crate::text::fmt_rfc3339(self.not_after)
        )?;
        writeln!(f, "  public key:       {}", self.public_key_summary)?;
        writeln!(
            f,
            "  signature alg:    {}",
            refineid_lib_core::oid::Oid::const_new(&self.signature_alg_oid)
        )?;
        if !self.key_usage.is_empty() {
            writeln!(f, "  key usage:        {}", self.key_usage.join(", "))?;
        }
        if !self.extended_key_usage.is_empty() {
            writeln!(
                f,
                "  ext key usage:    {}",
                self.extended_key_usage.join(", ")
            )?;
        }
        for url in &self.crl_urls {
            writeln!(f, "  CRL:              {url}")?;
        }
        for url in &self.ocsp_urls {
            writeln!(f, "  OCSP:             {url}")?;
        }
        for url in &self.ca_issuers_urls {
            writeln!(f, "  CA issuers:       {url}")?;
        }
        for email in &self.san_emails {
            writeln!(f, "  email (SAN):      {email}")?;
        }
        writeln!(f, "  sha256:           {}", self.sha256_fingerprint)?;
        Ok(())
    }
}

// The previous oid_to_dotted helper + its tests live now in
// `refineid_lib_core::oid::Oid` (Display impl + the `known`
// constant table). Tests there cover the dotted-decimal
// rendering for every shipped OID, including the
// sha256WithRSAEncryption value that used to be tested here.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{TempDir, TestResult, check, check_true};
    use refineid_lib_core::x509::KeyUsage;

    // Real, bundled certs (also the production trust anchors).
    // `show_cert` reads from a path, so each is staged into a
    // temp file first.
    const ICAO_CSCA_PEM: &[u8] = include_bytes!("../trust-anchors/icao-pkd-un-csca-2.pem");
    const DVV_ROOT_RSA_DER: &[u8] = include_bytes!("../trust-anchors/dvv-gov-root-ca-g3-rsa.der");
    const DVV_ROOT_ECC_DER: &[u8] = include_bytes!("../trust-anchors/dvv-gov-root-ca-g3-ecc.der");

    #[test]
    fn shows_a_pem_rsa_csca_with_all_fields() -> TestResult {
        let dir = TempDir::new("cert-show-pem")?;
        let path = dir.write("csca.pem", ICAO_CSCA_PEM)?;
        let report = show_cert(&path).map_err(|e| format!("show_cert: {e}"))?;

        // PEM is sniffed from the first byte (not 0x30 SEQUENCE).
        check_true(report.source_form == SourceForm::Pem, "source form PEM")?;
        check_true(
            report.subject_cn.as_deref() == Some("United Nations CSCA"),
            "subject CN",
        )?;
        // CSCA root: subject == issuer.
        check_true(
            report.issuer_cn.as_deref() == Some("United Nations CSCA"),
            "issuer CN",
        )?;
        check_true(report.public_key_summary.contains("RSA"), "RSA key")?;
        check_true(report.public_key_summary.contains("3072"), "3072-bit")?;
        // CA cert: keyCertSign + cRLSign asserted.
        check_true(
            report.key_usage.contains(&"keyCertSign") && report.key_usage.contains(&"cRLSign"),
            "CA key usage",
        )?;
        check_true(
            report.san_emails.iter().any(|e| *e == "travel@un.org"),
            "SAN email",
        )?;
        check_true(!report.crl_urls.is_empty(), "has CRL distribution point")?;

        // The fingerprint is SHA-256 over the *decoded* DER, even
        // for PEM input.
        let der = decode_cert_pem_or_der(ICAO_CSCA_PEM).ok_or("decode pem")?;
        check(
            &report.sha256_fingerprint,
            &Sha256::of(&der),
            "fingerprint over decoded DER",
        )
    }

    #[test]
    fn shows_a_der_rsa_4096_root() -> TestResult {
        let dir = TempDir::new("cert-show-der-rsa")?;
        let path = dir.write("root.der", DVV_ROOT_RSA_DER)?;
        let report = show_cert(&path).map_err(|e| format!("show_cert: {e}"))?;

        // First byte 0x30 -> DER.
        check_true(report.source_form == SourceForm::Der, "source form DER")?;
        check_true(report.public_key_summary.contains("RSA"), "RSA key")?;
        check_true(report.public_key_summary.contains("4096"), "4096-bit")?;
        check_true(
            report.subject_cn.as_deref() == Some("DVV Gov. Root CA - G3 RSA"),
            "subject CN",
        )?;
        // Fingerprint over the raw DER file bytes (DER in = DER out).
        check(
            &report.sha256_fingerprint,
            &Sha256::of(DVV_ROOT_RSA_DER),
            "fingerprint",
        )
    }

    #[test]
    fn shows_a_der_ec_p384_root() -> TestResult {
        let dir = TempDir::new("cert-show-der-ecc")?;
        let path = dir.write("root.der", DVV_ROOT_ECC_DER)?;
        let report = show_cert(&path).map_err(|e| format!("show_cert: {e}"))?;
        check_true(report.source_form == SourceForm::Der, "source form DER")?;
        check_true(report.public_key_summary.contains("EC"), "EC key")?;
        check_true(report.public_key_summary.contains("384"), "P-384")
    }

    #[test]
    fn missing_file_is_a_read_error() -> TestResult {
        let dir = TempDir::new("cert-show-missing")?;
        let path = dir.path().join("nope.der");
        check_true(
            matches!(show_cert(&path), Err(CertShowError::Read { .. })),
            "Read error",
        )
    }

    #[test]
    fn garbage_bytes_are_a_decode_error() -> TestResult {
        let dir = TempDir::new("cert-show-garbage")?;
        // Leading 0x30 makes the sniffer call it DER, but it isn't
        // a valid certificate -> Decode, not Read.
        let path = dir.write("junk.der", b"\x30\x01\x02\x03not a cert")?;
        check_true(
            matches!(show_cert(&path), Err(CertShowError::Decode { .. })),
            "Decode error",
        )
    }

    #[test]
    fn cert_show_error_display() -> TestResult {
        check_true(
            CertShowError::Read {
                path: PathBuf::from("/c.der"),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "gone"),
            }
            .to_string()
            .contains("read /c.der: gone"),
            "read display",
        )?;
        check_true(
            CertShowError::Decode {
                path: PathBuf::from("/c.der"),
                detail: "bad TLV".to_owned(),
            }
            .to_string()
            .contains("decode /c.der: bad TLV"),
            "decode display",
        )
    }

    // ---- key_usage_labels: the bit-set -> spec-ordered label
    // list. Tested directly because the report only surfaces the
    // CA-cert combination via the bundled fixtures. ----

    fn ku_all_false() -> KeyUsage {
        KeyUsage {
            digital_signature: false,
            non_repudiation: false,
            key_encipherment: false,
            data_encipherment: false,
            key_agreement: false,
            key_cert_sign: false,
            crl_sign: false,
            encipher_only: false,
            decipher_only: false,
        }
    }

    #[test]
    fn key_usage_labels_absent_extension_is_empty() -> TestResult {
        check(
            &key_usage_labels(None),
            &Vec::<&str>::new(),
            "None -> empty",
        )
    }

    #[test]
    fn key_usage_labels_no_bits_set_is_empty() -> TestResult {
        check(
            &key_usage_labels(Some(ku_all_false())),
            &Vec::<&str>::new(),
            "all-false -> empty",
        )
    }

    #[test]
    fn key_usage_labels_emits_asserted_bits_in_spec_order() -> TestResult {
        // End-entity FINEID auth cert shape: digitalSignature only.
        let mut ku = ku_all_false();
        ku.digital_signature = true;
        check(
            &key_usage_labels(Some(ku)),
            &vec!["digitalSignature"],
            "digitalSignature only",
        )?;

        // CA shape, plus an out-of-order pair to prove ordering is
        // by spec bit, not insertion: set crl_sign and key_cert_sign.
        let mut ca = ku_all_false();
        ca.crl_sign = true;
        ca.key_cert_sign = true;
        check(
            &key_usage_labels(Some(ca)),
            &vec!["keyCertSign", "cRLSign"],
            "keyCertSign before cRLSign",
        )
    }

    #[test]
    fn report_display_renders_key_lines() -> TestResult {
        let dir = TempDir::new("cert-show-display")?;
        let path = dir.write("csca.pem", ICAO_CSCA_PEM)?;
        let s = show_cert(&path)
            .map_err(|e| format!("show_cert: {e}"))?
            .to_string();
        check_true(s.contains("(PEM)"), "form tag")?;
        check_true(s.contains("subject CN:"), "subject line")?;
        check_true(s.contains("public key:"), "public key line")?;
        check_true(s.contains("key usage:"), "key usage line")?;
        check_true(s.contains("sha256:"), "fingerprint line")
    }
}
