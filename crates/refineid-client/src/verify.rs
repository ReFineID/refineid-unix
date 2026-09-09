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

//! `refineid verify`: offline RSA-PKCS1v15-SHA256 signature verify.
//!
//! No card required -- given a cert (PEM or DER), a message, and
//! a signature, run `verify_pkcs1v15_sha256(cert_pubkey, message,
//! signature)` from lib-core and report ok / FAILED. Pairs with
//! `card sign-auth` / `card sign-qualified`: anyone receiving the
//! signature + cert pair can verify with just this binary.

use alloc::fmt;
use std::path::PathBuf;

use refineid_lib_core::crypto::container::{RsaPkcs1Sha256, Signature};
use refineid_lib_core::crypto::rsa::RsaVerifyError;
use refineid_lib_core::x509::{OwnedCert, extract_rsa_public_key};

use crate::text::decode_cert_pem_or_der;

/// Inputs.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    /// Filesystem path to the cert that signed `message`. Wire
    /// form (PEM vs DER) is sniffed at decode time.
    pub cert: PathBuf,
    /// Filesystem path to the original message bytes that were
    /// hashed and signed.
    pub message: PathBuf,
    /// Filesystem path to the raw RSA-PKCS#1 v1.5 signature
    /// bytes (no PEM armour, no DER envelope).
    pub signature: PathBuf,
}

/// One verify-run's result. Not `Clone` -- lib-core's
/// [`RsaVerifyError`] isn't `Clone` and there's no reason to
/// copy a verify report anyway.
#[derive(Debug)]
pub struct VerifyReport {
    /// Path that was passed in as `cert`; carried through so the
    /// report header can name the cert without re-deriving it.
    pub cert_path: PathBuf,
    /// Subject Common Name extracted from the cert per RFC 5280
    /// §4.1.2.6, for the operator to see "who signed". `None` if
    /// absent / unparseable.
    pub cert_subject_cn: Option<refineid_lib_core::identity::CommonName>,
    /// Path that was passed in as `message`.
    pub message_path: PathBuf,
    /// Length in bytes of the message file. Tier 0 `u64` -- file
    /// size from `std::fs::metadata`, no domain bound.
    pub message_len: u64,
    /// Path that was passed in as `signature`.
    pub signature_path: PathBuf,
    /// Length in bytes of the signature file (modulus-octet
    /// count for the RSA-PKCS#1 v1.5 form). Tier 0 `usize`.
    pub signature_len: usize,
    /// `true` when the signature verified against the cert's
    /// public key, `false` when it didn't. The lib-core verdict
    /// is captured here so the CLI can pick its exit code.
    pub ok: bool,
    /// On failure, the lib-core error that fired. `None` on success.
    pub failure_reason: Option<RsaVerifyError>,
}

/// Error returned from `verify_offline` for problems that
/// prevent the verify from even running.
///
/// Causes covered: file I/O, parse, algorithm mismatch. The
/// signature-doesn't-verify outcome is surfaced via
/// [`VerifyReport::ok`], not as an error.
#[derive(Debug)]
pub enum VerifyErrorKind {
    /// Cert file I/O failure (`NotFound`, `PermissionDenied`, ...).
    CertRead {
        /// Filesystem path the read was attempted against.
        path: PathBuf,
        /// Underlying `std::io::Error`.
        source: std::io::Error,
    },
    /// Message file I/O failure.
    MessageRead {
        /// Filesystem path the read was attempted against.
        path: PathBuf,
        /// Underlying `std::io::Error`.
        source: std::io::Error,
    },
    /// Signature file I/O failure.
    SignatureRead {
        /// Filesystem path the read was attempted against.
        path: PathBuf,
        /// Underlying `std::io::Error`.
        source: std::io::Error,
    },
    /// Couldn't decode the cert as PEM or DER.
    CertDecode {
        /// Filesystem path the decode was attempted against.
        path: PathBuf,
        /// Human-readable decoder / parser error. Tier 0
        /// `String`; presentational.
        detail: String,
    },
    /// Parsed cert exists but doesn't carry an RSA public key the
    /// lib-core parser recognises.
    CertNotRsa(PathBuf),
}

impl fmt::Display for VerifyErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CertRead { path, source } => write!(f, "read cert {}: {source}", path.display()),
            Self::MessageRead { path, source } => {
                write!(f, "read message {}: {source}", path.display())
            }
            Self::SignatureRead { path, source } => {
                write!(f, "read signature {}: {source}", path.display())
            }
            Self::CertDecode { path, detail } => {
                write!(f, "decode cert {}: {detail}", path.display())
            }
            Self::CertNotRsa(path) => write!(
                f,
                "cert {} is not RSA; verify is RSA-PKCS1v15-SHA256 only",
                path.display()
            ),
        }
    }
}

impl core::error::Error for VerifyErrorKind {}

/// Run an offline signature verify.
///
/// # Errors
/// Cert / message / signature read or parse failures. A
/// `signature != message-hash` outcome is *not* an error; it lands
/// on the report as `ok = false` with the lib-core
/// [`RsaVerifyError`] preserved in `failure_reason` so the CLI
/// can choose its own exit code.
pub(crate) fn verify_offline(options: &VerifyOptions) -> Result<VerifyReport, VerifyErrorKind> {
    let cert_bytes = std::fs::read(&options.cert).map_err(|source| VerifyErrorKind::CertRead {
        path: options.cert.clone(),
        source,
    })?;
    let cert_der =
        decode_cert_pem_or_der(&cert_bytes).ok_or_else(|| VerifyErrorKind::CertDecode {
            path: options.cert.clone(),
            detail: "not PEM or DER cert bytes".to_owned(),
        })?;
    let cert_owned = OwnedCert::from_der(&cert_der).map_err(|e| VerifyErrorKind::CertDecode {
        path: options.cert.clone(),
        detail: format!("parse: {e}"),
    })?;
    let cert = cert_owned.view();
    let cert_subject_cn = cert.subject.common_name();
    let Some(pubkey) = extract_rsa_public_key(cert.spki.as_der()) else {
        return Err(VerifyErrorKind::CertNotRsa(options.cert.clone()));
    };

    let message =
        std::fs::read(&options.message).map_err(|source| VerifyErrorKind::MessageRead {
            path: options.message.clone(),
            source,
        })?;
    // `Vec<u8>::len()` is bounded by addressable memory; on 64-bit
    // targets `usize` is `u64`, on 32-bit it fits.
    let message_len: u64 = u64::try_from(message.len()).unwrap_or(u64::MAX);

    let sig_bytes =
        std::fs::read(&options.signature).map_err(|source| VerifyErrorKind::SignatureRead {
            path: options.signature.clone(),
            source,
        })?;
    let signature_len = sig_bytes.len();
    let signature: Signature<RsaPkcs1Sha256> = Signature::new(sig_bytes);

    let (ok, failure_reason) = match pubkey.verify_pkcs1v15_sha256(message, &signature) {
        Ok(()) => (true, None),
        Err(e) => (false, Some(e)),
    };

    Ok(VerifyReport {
        cert_path: options.cert.clone(),
        cert_subject_cn,
        message_path: options.message.clone(),
        message_len,
        signature_path: options.signature.clone(),
        signature_len,
        ok,
        failure_reason,
    })
}

impl fmt::Display for VerifyReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "cert: {}", self.cert_path.display())?;
        if let Some(cn) = &self.cert_subject_cn {
            writeln!(f, "cert subject CN: {cn}")?;
        }
        writeln!(
            f,
            "message: {} ({} bytes)",
            self.message_path.display(),
            self.message_len
        )?;
        writeln!(
            f,
            "signature: {} ({} bytes)",
            self.signature_path.display(),
            self.signature_len
        )?;
        if self.ok {
            writeln!(f, "verify: ok")?;
        } else {
            writeln!(
                f,
                "verify: FAILED ({})",
                self.failure_reason
                    .as_ref()
                    .map_or_else(|| "no detail".to_owned(), ToString::to_string)
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{TempDir, TestResult, check, check_true};

    const ICAO_CSCA_PEM: &[u8] = include_bytes!("../trust-anchors/icao-pkd-un-csca-2.pem");
    const DVV_ROOT_ECC_DER: &[u8] = include_bytes!("../trust-anchors/dvv-gov-root-ca-g3-ecc.der");

    /// The TBS bytes + signature of the bundled CSCA. A
    /// self-signed `sha256WithRSAEncryption` cert IS a valid
    /// RSA-PKCS1v15-SHA256 signature by its own key over its own
    /// TBS, so feeding (cert, tbs, signature) to `verify_offline`
    /// is a genuine accept case -- no private key needed.
    fn csca_tbs_and_signature() -> Result<(Vec<u8>, Vec<u8>), Box<dyn core::error::Error>> {
        let der = decode_cert_pem_or_der(ICAO_CSCA_PEM).ok_or("decode pem")?;
        let cert = OwnedCert::from_der(&der).map_err(|e| format!("parse: {e}"))?;
        let view = cert.view();
        Ok((view.tbs_der.to_vec(), view.signature_bits.to_vec()))
    }

    #[test]
    fn valid_self_signature_verifies_ok() -> TestResult {
        let (tbs, sig) = csca_tbs_and_signature()?;
        let dir = TempDir::new("verify-ok")?;
        let opts = VerifyOptions {
            cert: dir.write("c.pem", ICAO_CSCA_PEM)?,
            message: dir.write("m.bin", &tbs)?,
            signature: dir.write("s.bin", &sig)?,
        };
        let report = verify_offline(&opts).map_err(|e| format!("verify_offline: {e}"))?;
        check_true(report.ok, "ok=true on a valid signature")?;
        check_true(report.failure_reason.is_none(), "no failure reason")?;
        check_true(
            report.cert_subject_cn.as_deref() == Some("United Nations CSCA"),
            "subject CN surfaced",
        )?;
        let expected_len = u64::try_from(tbs.len()).unwrap_or(u64::MAX);
        check(&report.message_len, &expected_len, "message length")?;
        check(&report.signature_len, &sig.len(), "signature length")
    }

    #[test]
    fn tampered_signature_reports_not_ok_without_erroring() -> TestResult {
        let (tbs, mut sig) = csca_tbs_and_signature()?;
        // Flip a byte: length is unchanged (still the modulus
        // octet count), so it passes the length gate and fails the
        // digest/padding check inside lib-core.
        *sig.first_mut().ok_or("empty signature")? ^= 0xFF;
        let dir = TempDir::new("verify-bad")?;
        let opts = VerifyOptions {
            cert: dir.write("c.pem", ICAO_CSCA_PEM)?,
            message: dir.write("m.bin", &tbs)?,
            signature: dir.write("s.bin", &sig)?,
        };
        // A non-verifying signature is a report outcome, NOT an
        // Err -- the CLI picks the exit code from `ok`.
        let report = verify_offline(&opts).map_err(|e| format!("verify_offline: {e}"))?;
        check_true(!report.ok, "ok=false on a tampered signature")?;
        check_true(report.failure_reason.is_some(), "failure reason present")
    }

    #[test]
    fn ec_cert_is_rejected_as_not_rsa() -> TestResult {
        // verify is RSA-only; an EC cert is refused before the
        // message/signature are even read.
        let dir = TempDir::new("verify-ec")?;
        let opts = VerifyOptions {
            cert: dir.write("c.der", DVV_ROOT_ECC_DER)?,
            message: dir.path().join("missing-msg"),
            signature: dir.path().join("missing-sig"),
        };
        check_true(
            matches!(verify_offline(&opts), Err(VerifyErrorKind::CertNotRsa(_))),
            "CertNotRsa",
        )
    }

    #[test]
    fn missing_cert_is_a_cert_read_error() -> TestResult {
        let dir = TempDir::new("verify-nocert")?;
        let opts = VerifyOptions {
            cert: dir.path().join("nope.pem"),
            message: dir.path().join("m"),
            signature: dir.path().join("s"),
        };
        check_true(
            matches!(verify_offline(&opts), Err(VerifyErrorKind::CertRead { .. })),
            "CertRead",
        )
    }

    #[test]
    fn garbage_cert_is_a_cert_decode_error() -> TestResult {
        let dir = TempDir::new("verify-badcert")?;
        let opts = VerifyOptions {
            cert: dir.write("c.pem", b"not a certificate at all")?,
            message: dir.path().join("m"),
            signature: dir.path().join("s"),
        };
        check_true(
            matches!(
                verify_offline(&opts),
                Err(VerifyErrorKind::CertDecode { .. })
            ),
            "CertDecode",
        )
    }

    #[test]
    fn missing_message_and_signature_files_map_to_their_errors() -> TestResult {
        // Valid RSA cert, but the message file is missing: the
        // read order is cert -> message -> signature.
        let dir = TempDir::new("verify-readorder")?;
        let cert_path = dir.write("c.pem", ICAO_CSCA_PEM)?;
        let opts_no_msg = VerifyOptions {
            cert: cert_path.clone(),
            message: dir.path().join("missing-msg"),
            signature: dir.path().join("missing-sig"),
        };
        check_true(
            matches!(
                verify_offline(&opts_no_msg),
                Err(VerifyErrorKind::MessageRead { .. })
            ),
            "MessageRead",
        )?;

        // Message present, signature missing -> SignatureRead.
        let opts_no_sig = VerifyOptions {
            cert: cert_path,
            message: dir.write("m.bin", b"hello")?,
            signature: dir.path().join("missing-sig"),
        };
        check_true(
            matches!(
                verify_offline(&opts_no_sig),
                Err(VerifyErrorKind::SignatureRead { .. })
            ),
            "SignatureRead",
        )
    }

    #[test]
    fn error_display_includes_paths() -> TestResult {
        check_true(
            VerifyErrorKind::CertNotRsa(PathBuf::from("/c.der"))
                .to_string()
                .contains("/c.der is not RSA"),
            "not-rsa display",
        )?;
        check_true(
            VerifyErrorKind::MessageRead {
                path: PathBuf::from("/m"),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "gone"),
            }
            .to_string()
            .contains("read message /m: gone"),
            "message-read display",
        )
    }

    #[test]
    fn report_display_ok_and_failed_branches() -> TestResult {
        let ok = VerifyReport {
            cert_path: PathBuf::from("/c.pem"),
            cert_subject_cn: None,
            message_path: PathBuf::from("/m"),
            message_len: 5,
            signature_path: PathBuf::from("/s"),
            signature_len: 384,
            ok: true,
            failure_reason: None,
        };
        check_true(ok.to_string().contains("verify: ok"), "ok branch")?;

        let failed = VerifyReport {
            cert_path: PathBuf::from("/c.pem"),
            cert_subject_cn: None,
            message_path: PathBuf::from("/m"),
            message_len: 5,
            signature_path: PathBuf::from("/s"),
            signature_len: 384,
            ok: false,
            failure_reason: Some(RsaVerifyError::BadDigest),
        };
        let s = failed.to_string();
        check_true(s.contains("verify: FAILED ("), "failed branch")?;
        check_true(s.contains("digest"), "failure detail rendered")
    }
}
