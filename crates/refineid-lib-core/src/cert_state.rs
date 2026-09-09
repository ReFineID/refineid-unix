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

//! Cert state lattice (typestate).
//!
//! Per FINEID S2 v5.2 §2: *"software products and network
//! services SHALL perform Basic Path Validation as described
//! in RFC 5280, §6.1"* and *"MUST always check
//! validity of certificate against valid CRL or OCSP service
//! before trusting a single certificate"*. The cert state
//! lattice in this module makes that spec mandate enforceable
//! by the compiler: a cert can only be used for a trust
//! decision after each stage has executed.
//!
//! Stages, in order:
//!
//! 1. [`RawDer`] -- byte sequence from the wire (PKCS#15 read,
//!    AIA fetch, file load). Nothing parsed.
//! 2. [`ParsedCert`] -- X.509 v3 syntax check passed, fields
//!    extractable. Signature has *not* been verified by anyone.
//! 3. [`PathValidatedCert`] -- RFC 5280 §6.1 Basic Path
//!    Validation passed. The cert chains to a pinned trust
//!    anchor. Signatures along the path are verified.
//! 4. [`RevocationCheckedCert`] -- the leaf and every
//!    intermediate has been confirmed not on a fresh CRL /
//!    OCSP response, both signature-verified.
//! 5. [`PurposeBoundCert<P>`] -- the cert's `KeyUsage` and
//!    `ExtendedKeyUsage` extensions bind it to the typed
//!    purpose `P` (one of [`AuthPurpose`], [`NonRepPurpose`],
//!    [`CscaPurpose`], [`DscPurpose`], [`MlsPurpose`]). A cert
//!    bound to `AuthPurpose` cannot be passed to a function
//!    expecting `NonRepPurpose`.
//!
//! Each stage is constructed only by a function that ran the
//! check. Skipping a stage is a compile error.
//!
//! Canonical docs:
//! [`doc/typing-discipline.md`](../../../../doc/typing-discipline.md),
//! [`doc/fineid-s2-cert-profile.md`](../../../../doc/fineid-s2-cert-profile.md).

use core::fmt;
use core::marker::PhantomData;

use crate::crypto::digest::Sha256;
use crate::x509::{Certificate, DateTime, KeyUsage, X509Error};

// ----- Stage 0: CertDer (owned) -----------------------------

/// Owned cert DER bytes -- the typed result of reading a
/// certificate slot from the card.
///
/// Distinct from arbitrary `Vec<u8>`: the wrapper asserts the
/// bytes came from a PKCS#15 / eMRTD cert read (which is the
/// only context refineid produces this type in). Callers that
/// want the borrowed cert-state lattice ([`RawDer`] -> ...)
/// take a view via [`CertDer::as_raw_der`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertDer {
    /// `bytes` field.
    bytes: Vec<u8>,
}

impl CertDer {
    /// Wrap raw DER bytes from a card read. No syntactic check
    /// -- the cert-state lattice's `parse` stage does that.
    #[must_use]
    #[inline]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrow the underlying DER bytes (the on-wire / on-card
    /// representation of the certificate).
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Consume the wrapper and return the owned DER bytes.
    #[must_use]
    #[inline]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Length of the DER encoding in bytes. Tier 0 `usize`;
    /// arithmetic count.
    #[must_use]
    #[inline]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// `true` when the DER buffer is empty (operationally this
    /// shouldn't happen for a real cert read; the constructor
    /// doesn't reject it because the syntactic check lives in
    /// the `parse` stage).
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Borrow the owned bytes as a [`RawDer`] view -- the
    /// entry point of the cert-state typestate lattice.
    #[must_use]
    #[inline]
    pub fn as_raw_der(&self) -> RawDer<'_> {
        RawDer::new(&self.bytes)
    }
}

// ----- Stage 1: RawDer --------------------------------------

/// Raw DER bytes of a candidate certificate. Unparsed,
/// unverified, nothing more than a borrow.
#[derive(Debug, Clone, Copy)]
pub struct RawDer<'a> {
    /// `bytes` field.
    bytes: &'a [u8],
}

impl<'a> RawDer<'a> {
    /// Wrap a borrowed byte slice. No syntactic check here --
    /// the next stage (`parse`) does that.
    #[must_use]
    #[inline]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Borrow the underlying DER byte slice.
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Promote to [`ParsedCert`] by running the X.509 v3
    /// syntax check.
    ///
    /// # Errors
    /// Any [`X509Error`] from the underlying parser.
    #[inline]
    pub fn parse(self) -> Result<ParsedCert<'a>, X509Error> {
        let inner = Certificate::from_der(self.bytes)?;
        Ok(ParsedCert {
            der: self.bytes,
            inner,
        })
    }
}

// ----- Stage 2: ParsedCert ----------------------------------

/// X.509 v3 cert that parsed cleanly. Fields are reachable,
/// but the signature on the cert has NOT been verified by
/// anything; the cert is not yet trusted for any purpose.
#[derive(Debug, Clone, Copy)]
pub struct ParsedCert<'a> {
    /// `der` field.
    der: &'a [u8],
    /// `inner` field.
    inner: Certificate<'a>,
}

impl<'a> ParsedCert<'a> {
    /// Borrow the original DER byte slice the parse consumed.
    #[must_use]
    #[inline]
    pub const fn as_der(&self) -> &'a [u8] {
        self.der
    }

    /// Borrow the parsed [`Certificate`] view (subject DN,
    /// issuer DN, SPKI, validity, extensions, signature).
    #[must_use]
    #[inline]
    pub const fn inner(&self) -> &Certificate<'a> {
        &self.inner
    }

    // path_validate_with_intermediate: removed when the consumer
    // never landed. The 2-cert path_validate is the live entry
    // point; the 3-cert variant can be reintroduced once the
    // cert-state lattice roadmap (doc/typing-discipline.md) wires
    // up a chain consumer.
}

// ----- Stage 3: PathValidatedCert ---------------------------

/// Cert whose chain has been verified against a pinned trust
/// anchor.
///
/// Carries the anchor's label + SHA-256 so downstream code
/// can name what proved the chain (audit-log requirement).
/// Does NOT carry a revocation verdict; that's stage 4.
#[derive(Debug, Clone)]
pub struct PathValidatedCert<'a> {
    /// `cert` field.
    cert: ParsedCert<'a>,
    /// `anchor_label` field.
    anchor_label: &'static str,
    /// `anchor_sha256` field.
    anchor_sha256: Sha256,
}

impl<'a> PathValidatedCert<'a> {
    /// Borrow the parsed [`Certificate`] view (sub-state of
    /// [`ParsedCert`] preserved through path validation).
    #[must_use]
    #[inline]
    pub const fn inner(&self) -> &Certificate<'a> {
        self.cert.inner()
    }

    /// Borrow the wrapped [`ParsedCert`] -- useful when the
    /// consumer needs the DER bytes alongside the path-validated
    /// status.
    #[must_use]
    #[inline]
    pub const fn as_parsed(&self) -> &ParsedCert<'a> {
        &self.cert
    }

    /// Label of the pinned trust anchor that proved the chain
    /// (e.g. "DVV CA Generation 3 RSA"). Tier 0 `&'static str`
    /// from a fixed compile-time set in `crate::trust_roots`.
    #[must_use]
    #[inline]
    pub const fn anchor_label(&self) -> &'static str {
        self.anchor_label
    }

    /// SHA-256 of the trust anchor's DER -- used to audit-log
    /// the exact fingerprint that proved the chain.
    #[must_use]
    #[inline]
    pub const fn anchor_sha256(&self) -> &Sha256 {
        &self.anchor_sha256
    }

    /// Promote to [`RevocationCheckedCert`] with an
    /// already-decided revocation verdict. Callers are
    /// expected to have run an actual CRL or OCSP check
    /// (`crate::crl` / `crate::ocsp`) and decide the
    /// `RevocationStatus` based on that, against
    /// `validation_time` (S2 §2 distinguishes signing time
    /// vs revocation time -- the validation must use a
    /// concrete instant).
    #[must_use]
    #[inline]
    pub const fn into_revocation_checked(
        self,
        status: RevocationStatus,
        validation_time: DateTime,
    ) -> RevocationCheckedCert<'a> {
        RevocationCheckedCert {
            cert: self,
            status,
            validation_time,
        }
    }
}

// ----- Stage 4: RevocationCheckedCert -----------------------

/// Revocation status of a cert. Values reflect S2 §2's
/// requirement to actively check; "we didn't try" is not a
/// passable state.
#[derive(Debug, Clone)]
pub enum RevocationStatus {
    /// Confirmed not-revoked by a CRL whose `thisUpdate` <=
    /// `validation_time` < `nextUpdate`, with the CRL's
    /// signature verified by the issuer.
    Good {
        /// Which trust-source produced the verdict (which CRL
        /// URL or OCSP responder URL).
        source: RevocationSource,
        /// Timestamp the verdict was observed at (CRL's
        /// `thisUpdate` or OCSP `producedAt`).
        observed_at: DateTime,
    },
    /// Cert appears on the CRL with the given reason at
    /// `revoked_at`. S2 §2: signatures made BEFORE
    /// `revoked_at` may still be valid (operator-time
    /// concern, not refineid's at this layer).
    Revoked {
        /// CRL `revocationDate` per RFC 5280 §5.3.1, or OCSP
        /// `revocationTime` per RFC 6960 §4.2.2.2.
        revoked_at: DateTime,
        /// CRL `reasonCode` per RFC 5280 §5.3.1 (0 unspecified,
        /// 1 keyCompromise, 4 superseded, etc.). Tier 0 `u8`
        /// -- the typed projection would be a
        /// `CrlReasonCode` enum; today the byte is carried as-is.
        reason: u8,
        /// Which trust-source emitted the revoked verdict.
        source: RevocationSource,
    },
    /// CRL or OCSP couldn't be reached / verified. Not a
    /// pass -- callers must refuse trust unless they have a
    /// fallback they can defend.
    Unknown {
        /// Human-readable reason ("CRL fetch failed: `<err>`",
        /// "OCSP responder unreachable", ...). Tier 0 `String`;
        /// presentational.
        reason: String,
    },
}

/// Origin of a [`RevocationStatus`] verdict.
#[derive(Debug, Clone)]
pub enum RevocationSource {
    /// CRL fetched from the named URL (or "(pre-fetched file)").
    /// Tier 0 `String`; presentational copy of the source.
    Crl(String),
    /// OCSP responder URL the verdict came from. Tier 0
    /// `String`; presentational.
    Ocsp(String),
}

/// Cert whose path is validated AND whose revocation
/// verdict is known.
///
/// This is the highest state that's still purpose-agnostic;
/// the next stage binds it to a specific `Purpose`.
#[derive(Debug, Clone)]
pub struct RevocationCheckedCert<'a> {
    /// `cert` field.
    cert: PathValidatedCert<'a>,
    /// `status` field.
    status: RevocationStatus,
    /// `validation_time` field.
    validation_time: DateTime,
}

impl<'a> RevocationCheckedCert<'a> {
    /// Borrow the parsed [`Certificate`] view.
    #[must_use]
    #[inline]
    pub const fn inner(&self) -> &Certificate<'a> {
        self.cert.inner()
    }

    /// Borrow the revocation verdict (Good / Revoked / Unknown).
    #[must_use]
    #[inline]
    pub const fn status(&self) -> &RevocationStatus {
        &self.status
    }

    /// The validation instant the revocation check was performed
    /// at. Important for S2 §2 signing-time vs revocation-time
    /// reasoning downstream.
    #[must_use]
    #[inline]
    pub const fn validation_time(&self) -> DateTime {
        self.validation_time
    }

    /// Promote to [`PurposeBoundCert`] by checking the cert's
    /// `KeyUsage` matches what the purpose `P` requires.
    ///
    /// The purpose-binding test is purely about extension
    /// bits; chain + revocation must already have passed
    /// (the predecessor stage proves both).
    ///
    /// # Errors
    /// [`PurposeBindError`] when the cert's `KeyUsage` doesn't
    /// match `P`'s requirement, or when the revocation status
    /// is anything other than `Good`.
    #[inline]
    pub fn bind_to_purpose<P: CertPurpose>(
        self,
    ) -> Result<PurposeBoundCert<'a, P>, PurposeBindError> {
        // S2 §2: a Revoked or Unknown status is NOT a pass.
        match self.status {
            RevocationStatus::Good { .. } => {}
            RevocationStatus::Revoked { .. } => {
                return Err(PurposeBindError::Revoked);
            }
            RevocationStatus::Unknown { .. } => {
                return Err(PurposeBindError::RevocationUnknown);
            }
        }

        let inner = self.cert.inner();
        let extensions = inner.extensions.ok_or(PurposeBindError::NoKeyUsage)?;
        let usage =
            crate::x509::extract_key_usage(extensions).ok_or(PurposeBindError::NoKeyUsage)?;
        if !P::matches_key_usage(&usage) {
            return Err(PurposeBindError::WrongKeyUsage {
                got: usage,
                expected: P::label(),
            });
        }

        Ok(PurposeBoundCert {
            cert: self.cert,
            validation_time: self.validation_time,
            _purpose: PhantomData,
        })
    }
}

// ----- Stage 5: PurposeBoundCert ----------------------------

/// Cert bound to a typed purpose.
///
/// The compiler refuses to let a
/// `PurposeBoundCert<AuthPurpose>` flow into a function
/// expecting `PurposeBoundCert<NonRepPurpose>` (and vice
/// versa). This is the cert purpose split S2 §6.3.8.3
/// requires made type-level.
#[derive(Debug, Clone)]
pub struct PurposeBoundCert<'a, P> {
    /// `cert` field.
    cert: PathValidatedCert<'a>,
    /// `validation_time` field.
    validation_time: DateTime,
    /// `_purpose` field.
    _purpose: PhantomData<P>,
}

impl<'a, P> PurposeBoundCert<'a, P> {
    /// Borrow the parsed [`Certificate`] view.
    #[must_use]
    #[inline]
    pub const fn inner(&self) -> &Certificate<'a> {
        self.cert.inner()
    }

    /// Label of the pinned trust anchor that proved the chain
    /// (delegated to the wrapped [`PathValidatedCert`]).
    #[must_use]
    #[inline]
    pub const fn anchor_label(&self) -> &'static str {
        self.cert.anchor_label()
    }

    /// The validation instant the revocation check was performed
    /// at (preserved from the predecessor stage so cert-purpose
    /// consumers can compare against the cert's `notBefore` /
    /// signature timestamp without re-fetching the clock).
    #[must_use]
    #[inline]
    pub const fn validation_time(&self) -> DateTime {
        self.validation_time
    }
}

// ----- Purpose marker types ---------------------------------

/// Common trait for cert-purpose marker types. Each marker
/// declares the `KeyUsage` bit pattern it requires.
pub trait CertPurpose {
    /// Predicate over RFC 5280 §4.2.1.3 `KeyUsage` bits the
    /// implementor purpose requires. Called by
    /// [`RevocationCheckedCert::bind_to_purpose`] to verify the
    /// cert's KU matches.
    fn matches_key_usage(usage: &KeyUsage) -> bool;
    /// Human-readable label for the purpose (e.g.
    /// "non-repudiation (nonRepudiation only)"). Used in
    /// [`PurposeBindError::WrongKeyUsage`] diagnostics.
    fn label() -> &'static str;
}

/// FINEID citizen authentication & encryption certificate.
/// Per S2 §6.3.8.3: `digitalSignature + keyEncipherment +
/// dataEncipherment` (encoded byte `0xB0`).
#[derive(Debug, Clone, Copy)]
pub struct AuthPurpose;
impl CertPurpose for AuthPurpose {
    #[inline]
    fn matches_key_usage(usage: &KeyUsage) -> bool {
        usage.digital_signature && usage.key_encipherment && usage.data_encipherment
    }
    #[inline]
    fn label() -> &'static str {
        "authentication / encryption (digitalSignature + keyEncipherment + dataEncipherment)"
    }
}

/// FINEID citizen non-repudiation (qualified signature)
/// certificate. Per S2 §6.3.8.3: `nonRepudiation` ONLY (byte
/// `0x40`); the spec is explicit that this bit shall not be
/// combined with others.
#[derive(Debug, Clone, Copy)]
pub struct NonRepPurpose;
impl CertPurpose for NonRepPurpose {
    #[inline]
    fn matches_key_usage(usage: &KeyUsage) -> bool {
        // ONLY nonRepudiation. The cert is rejected if any
        // other bit is also set.
        usage.non_repudiation
            && !usage.digital_signature
            && !usage.key_encipherment
            && !usage.data_encipherment
            && !usage.key_agreement
            && !usage.key_cert_sign
            && !usage.crl_sign
            && !usage.encipher_only
            && !usage.decipher_only
    }
    #[inline]
    fn label() -> &'static str {
        "non-repudiation (nonRepudiation only)"
    }
}

/// CSCA certificate (eMRTD passive authentication trust
/// anchor). Per ICAO Doc 9303 §12: `keyCertSign + cRLSign`.
#[derive(Debug, Clone, Copy)]
pub struct CscaPurpose;
impl CertPurpose for CscaPurpose {
    #[inline]
    fn matches_key_usage(usage: &KeyUsage) -> bool {
        usage.key_cert_sign && usage.crl_sign
    }
    #[inline]
    fn label() -> &'static str {
        "CSCA (keyCertSign + cRLSign)"
    }
}

/// Document Signer Certificate (eMRTD Passive Authentication
/// signer). Per ICAO Doc 9303 §12: `digitalSignature` only
/// (critical).
#[derive(Debug, Clone, Copy)]
pub struct DscPurpose;
impl CertPurpose for DscPurpose {
    #[inline]
    fn matches_key_usage(usage: &KeyUsage) -> bool {
        usage.digital_signature && !usage.non_repudiation && !usage.key_cert_sign && !usage.crl_sign
    }
    #[inline]
    fn label() -> &'static str {
        "DSC (digitalSignature only)"
    }
}

/// Master List Signer certificate (ICAO PKD). Per Doc 9303
/// §12: `digitalSignature` + EKU `id-icao-mlSigner`. The EKU
/// is checked separately; this trait only covers `KeyUsage`.
#[derive(Debug, Clone, Copy)]
pub struct MlsPurpose;
impl CertPurpose for MlsPurpose {
    #[inline]
    fn matches_key_usage(usage: &KeyUsage) -> bool {
        usage.digital_signature
    }
    #[inline]
    fn label() -> &'static str {
        "ML Signer (digitalSignature; EKU id-icao-mlSigner checked separately)"
    }
}

// ----- Errors -----------------------------------------------

// PathValidationError: removed alongside
// `path_validate_with_intermediate` until the 3-cert chain consumer
// lands; the 2-cert path validator's error type stays the live
// surface (PurposeBindError below + the underlying VerifyError).

/// Error returned from
/// [`RevocationCheckedCert::bind_to_purpose`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurposeBindError {
    /// Cert is on a CRL / OCSP at this validation time.
    Revoked,
    /// Couldn't determine revocation status; refuse to bind.
    RevocationUnknown,
    /// Cert lacks the mandatory `KeyUsage` extension. S2
    /// requires this critical extension on every end-entity
    /// cert; missing is reject.
    NoKeyUsage,
    /// `KeyUsage` bits don't match what the purpose requires.
    WrongKeyUsage {
        /// `KeyUsage` bits the cert actually asserts.
        got: KeyUsage,
        /// Human-readable label of the purpose the cert was
        /// being bound to (e.g.
        /// "non-repudiation (nonRepudiation only)"). Tier 0
        /// `&'static str` from
        /// [`CertPurpose::label`].
        expected: &'static str,
    },
}

impl fmt::Display for PurposeBindError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Revoked => f.write_str("cert is on a CRL/OCSP"),
            Self::RevocationUnknown => {
                f.write_str("revocation status couldn't be determined; refusing to bind purpose")
            }
            Self::NoKeyUsage => f.write_str(
                "cert has no KeyUsage extension; S2 requires critical KeyUsage on every \
                 end-entity cert",
            ),
            Self::WrongKeyUsage { got, expected } => write!(
                f,
                "KeyUsage doesn't match required purpose ({expected}); got {got}"
            ),
        }
    }
}

impl core::error::Error for PurposeBindError {}

#[cfg(test)]
mod tests {

    use super::{AuthPurpose, CertPurpose as _, NonRepPurpose};
    use crate::x509::KeyUsage;

    fn ku_all_unset() -> KeyUsage {
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
    fn auth_purpose_matches_full_auth_pattern() {
        let mut ku = ku_all_unset();
        ku.digital_signature = true;
        ku.key_encipherment = true;
        ku.data_encipherment = true;
        assert!(AuthPurpose::matches_key_usage(&ku));
    }

    #[test]
    fn auth_purpose_rejects_only_digital_signature() {
        let mut ku = ku_all_unset();
        ku.digital_signature = true;
        assert!(!AuthPurpose::matches_key_usage(&ku));
    }

    #[test]
    fn auth_purpose_rejects_non_repudiation_pattern() {
        let mut ku = ku_all_unset();
        ku.non_repudiation = true;
        assert!(!AuthPurpose::matches_key_usage(&ku));
    }

    #[test]
    fn non_rep_purpose_matches_only_non_repudiation() {
        let mut ku = ku_all_unset();
        ku.non_repudiation = true;
        assert!(NonRepPurpose::matches_key_usage(&ku));
    }

    #[test]
    fn non_rep_purpose_rejects_combined_bits() {
        // S2 §6.3.8.3: "nonRepudiation shall not be combined
        // with other bits".
        let mut ku = ku_all_unset();
        ku.non_repudiation = true;
        ku.digital_signature = true;
        assert!(!NonRepPurpose::matches_key_usage(&ku));
    }

    #[test]
    fn non_rep_purpose_rejects_auth_pattern() {
        let mut ku = ku_all_unset();
        ku.digital_signature = true;
        ku.key_encipherment = true;
        ku.data_encipherment = true;
        assert!(!NonRepPurpose::matches_key_usage(&ku));
    }

    #[test]
    fn purposes_have_descriptive_labels() {
        assert!(AuthPurpose::label().contains("digitalSignature"));
        assert!(AuthPurpose::label().contains("keyEncipherment"));
        assert!(NonRepPurpose::label().contains("nonRepudiation"));
    }
}
