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

//! `refineid card sign-auth` + `refineid card sign-qualified`.
//!
//! SHA-256 the input file, VERIFY the appropriate PIN, drive the
//! SHA-256+RSA-PKCS1v15 sign chain against the chosen FINEID key
//! slot, write the raw 384-byte RSA signature to disk, and
//! locally verify it against the public key in the on-card cert.
//!
//! - `sign-auth`: VERIFY PIN1, sign with the **auth key** (key
//!   ref `0x01`), verify against the EF.4331 cert.
//! - `sign-qualified`: VERIFY PIN2, sign with the **qualified-
//!   signature key** (key ref `0x02`), verify against the
//!   EF.4332 cert. PIN2 has a 6-digit floor (FINEID S1 v4.2 §3.5).
//!
//! Both paths share the same option / report / error types and a
//! shared internal driver (`sign_with_slot`) so the wire
//! choreography stays in lockstep.

use alloc::fmt;
use std::path::PathBuf;

use refineid_lib_core::apdu::status_word::StatusWord;
use refineid_lib_core::auth::{
    AuthError, PinOps as _, PinPolicyReason, PinReferenceScheme, PinSlot, VerifyOutcome,
};
use refineid_lib_core::backend::{
    ReaderAccessCap, ReaderBackend as _, ReaderBackendOps as _, ReaderPickError,
};
use refineid_lib_core::can::Can;
use refineid_lib_core::cert_state::CertDer;
use refineid_lib_core::crypto::digest::{Sha256, Sha384};
use refineid_lib_core::identity::{CommonName, TokenSerial, render_token_serial};
use refineid_lib_core::pace;
use refineid_lib_core::pin::PinBytes;
use refineid_lib_core::pkcs15::Pkcs15Ops as _;
use refineid_lib_core::pkcs15::{CertSlot, Pkcs15Error};
use refineid_lib_core::secure_messaging::SmTransport;
use refineid_lib_core::sign::asic::DataObject;
use refineid_lib_core::sign::cades::{
    DigestAlgorithm, SignatureAlgorithm, SignerParameters, SigningTime,
};
use refineid_lib_core::sign::document::{self, DocumentError, DocumentPlan, Format};
use refineid_lib_core::sign::pades::{SignatureInk, SignatureMetadata, VisibleSignature};
use refineid_lib_core::sign::timestamp::{self, TimestampError, VerifiedTimestampToken};
use refineid_lib_core::sign::validation::ValidationMaterial;
use refineid_lib_core::sign::{KeyRef, SignError, SignOps as _};
use refineid_lib_core::transport::CardTransport;
use refineid_lib_core::x509::{
    Certificate, DateTime, EcCurve, OwnedCert, PublicKeyAlgorithm, extract_rsa_public_key,
};
use refineid_lib_pcsc::{PcscBackend, PcscError};
use zeroize::Zeroizing;

use crate::validation_material::{ChainStart, NoncePolicy};

/// Maximum tolerated difference between this host and a live TSA.
///
/// A nonce proves that a response belongs to this request, but does not
/// make an authority's asserted time sensible. A newly requested token
/// outside this window must not choose the certificate-validation instant.
const MAX_TIMESTAMP_CLOCK_SKEW: core::time::Duration = core::time::Duration::from_mins(5);

/// Initial wait after a transient timestamp-authority failure.
const TIMESTAMP_RETRY_INITIAL_DELAY: core::time::Duration = core::time::Duration::from_secs(1);
/// Ceiling for repeated timestamp-authority retries.
const TIMESTAMP_RETRY_MAX_DELAY: core::time::Duration = core::time::Duration::from_mins(1);

/// Candidate EU-qualified timestamp endpoints used by first-party clients.
///
/// Whoever configures an authority answers for it: every returned
/// token is cryptographically verified against the request digest and
/// nonce, and nothing beyond that is checked about the operator.
pub const EU_QUALIFIED_TIMESTAMP_AUTHORITIES: &[&str] = &[
    "https://timestamp.aped.gov.gr/qtss",
    "http://tss.accv.es:8318/tsa",
];

/// The timestamp authority used when the operator configures none.
///
/// The Sectigo qualified endpoint, shared by every first-party
/// `ReFineID` client and documented at
/// <https://www.sectigo.com/resource-library/time-stamping-server>.
pub const DEFAULT_TIMESTAMP_AUTHORITY: &str = "http://timestamp.sectigo.com/qualified";

/// HTTP Basic credentials for one explicitly configured timestamp authority.
///
/// Both fields and the derived authorization header are zeroized on drop. The
/// custom [`Debug`] implementation deliberately exposes neither field.
#[derive(Clone)]
pub struct TimestampCredentials {
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}

impl TimestampCredentials {
    /// Construct credentials supplied by an interactive caller.
    ///
    /// # Errors
    /// An empty username or a username containing the Basic-auth separator is
    /// rejected before any network request is attempted.
    pub fn new(username: String, password: String) -> Result<Self, &'static str> {
        let username = Zeroizing::new(username);
        let password = Zeroizing::new(password);
        if username.is_empty() {
            return Err("timestamp username is empty");
        }
        if username.contains(':') {
            return Err("timestamp username cannot contain ':'");
        }
        Ok(Self { username, password })
    }

    fn authorization_header(&self) -> Zeroizing<String> {
        let mut plain = Zeroizing::new(Vec::with_capacity(
            self.username.len() + 1 + self.password.len(),
        ));
        plain.extend_from_slice(self.username.as_bytes());
        plain.push(b':');
        plain.extend_from_slice(self.password.as_bytes());
        let encoded = Zeroizing::new(refineid_lib_core::base64::encode(&plain));
        let mut header = Zeroizing::new(String::with_capacity(6 + encoded.len()));
        header.push_str("Basic ");
        header.push_str(&encoded);
        header
    }

    fn with_authorization_header<T>(&self, operation: impl FnOnce(&str) -> T) -> T {
        let header = self.authorization_header();
        operation(header.as_str())
    }
}

impl fmt::Debug for TimestampCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TimestampCredentials(REDACTED)")
    }
}

/// Which on-card key slot to sign with.
///
/// The choice picks PIN (1 vs 2), key reference byte (0x01 vs
/// 0x02), and the cert slot (EF.4331 vs EF.4332) used for the
/// local verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignSlot {
    /// **Auth key** -- TLS client-cert / SSH / agent identity.
    /// PIN1-gated, key ref 0x01, EF.4331 cert.
    Auth,
    /// **Qualified-signature key** -- non-repudiation per eIDAS
    /// QES. PIN2-gated, key ref 0x02, EF.4332 cert.
    Qualified,
}

impl SignSlot {
    /// PKCS#15 key reference for this signing slot.
    ///
    /// FINEID S1 v4.2 §3.5 -- auth key uses `KeyRef::Auth`
    /// (ref `0x01`), qualified-signature key uses
    /// `KeyRef::Sign` (ref `0x02`). Used as the `MSE:SET DST`
    /// data byte.
    /// Operator-facing name of the slot, for diagnostics.
    const fn label(self) -> &'static str {
        match self {
            Self::Auth => "authentication",
            Self::Qualified => "qualified-signature",
        }
    }

    const fn key_ref(self) -> KeyRef {
        match self {
            Self::Auth => KeyRef::Auth,
            Self::Qualified => KeyRef::Sign,
        }
    }
    /// PIN slot that gates use of this signing key.
    ///
    /// FINEID S1 v4.2 §3.5 -- PIN1 -> auth key, PIN2 ->
    /// qualified-signature key. Used so the verify-PIN step
    /// before the signing APDU pulls the right slot's
    /// counter.
    const fn pin_slot(self) -> PinSlot {
        match self {
            Self::Auth => PinSlot::Pin1,
            Self::Qualified => PinSlot::Pin2,
        }
    }
    /// PKCS#15 certificate slot whose public key pairs with
    /// this signing key for the verify-after-sign step
    /// (Rule E7).
    ///
    /// EF.4331 for auth, EF.4332 for qualified. The cert is
    /// read once at session start and reused by the local
    /// verify before the signature is handed back.
    const fn cert_slot(self) -> CertSlot {
        match self {
            Self::Auth => CertSlot::Authentication,
            Self::Qualified => CertSlot::Signature,
        }
    }
    /// Human label for the PIN slot, used in CLI prompts and
    /// the `Display` impl. `"PIN1"` / `"PIN2"` -- matches the
    /// labels printed on FINEID activation letters so the
    /// cardholder sees the same wording in both places.
    const fn pin_label(self) -> &'static str {
        match self {
            Self::Auth => "PIN1",
            Self::Qualified => "PIN2",
        }
    }
    /// Human label for the signing slot itself, used in the
    /// report header (`"auth"` / `"qualified-signature"`).
    /// Distinct from [`Self::pin_label`] because the PIN and
    /// slot labels appear on different lines.
    const fn slot_label(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Qualified => "qualified-signature",
        }
    }
}

/// A document signature rather than a bare one.
///
/// Present in [`SignOptions`] when the operator asked for a format
/// rather than raw signature bytes. The difference reaches all the way
/// into the card session: a document signature covers a structure that
/// names the signing certificate, so it cannot be built until the
/// certificate has been read off the card.
#[derive(Debug, Clone)]
pub struct DocumentRequest {
    /// Which format to produce.
    pub format: Format,
    /// Files beyond [`SignOptions::input`]. Only the container formats
    /// accept any; the rest refuse a set rather than sign the first.
    pub additional_inputs: Vec<PathBuf>,
    /// Claimed signing time, supplied by the caller.
    ///
    /// Read from the clock in the CLI layer rather than here, so this
    /// module stays deterministic and the claim stays the caller's to
    /// make.
    pub signing_time: SigningTime,
    /// What to record in the signature. Used by `PAdES` only.
    pub metadata: SignatureMetadata,
    /// Full PKCS#15 serial of the card the operator was shown, when a
    /// trusted inspection view captured one. Verified against the live
    /// card before PIN verification, whatever the format, so a card
    /// swap cannot spend the PIN on an undisplayed identity. `None`
    /// only for flows that sign whichever card is present (the CLI).
    pub expected_serial: Option<TokenSerial>,
    /// Optional visible mark for `PAdES`.
    ///
    /// The caller supplies only optional card-carried handwriting. The
    /// name and SATU are always read from the live signing certificate.
    pub visible_signature: Option<VisibleSignatureRequest>,
    /// Add an archive timestamp over the finished document, raising it
    /// to level LTA.
    ///
    /// This implies [`Self::long_term`] even when a direct API caller
    /// leaves that field false: an archive timestamp is added only
    /// after complete LT material has been collected and embedded.
    ///
    /// Implemented for `PAdES` and `ASiC-E` with `CAdES`. Standalone
    /// `CAdES`, `XAdES`, and `ASiC-E` with `XAdES` need different
    /// archive constructions that are not implemented yet.
    pub archive: bool,
    /// Collect and embed the chain and revocation answers, raising the
    /// signature to level LT.
    ///
    /// Costs a handful of network round trips at signing time and buys
    /// a signature that still checks when the responder is gone.
    /// [`Self::archive`] always enables this operation too.
    pub long_term: bool,
    /// URLs of RFC 3161 Time Stamp Authorities, when the signature is
    /// to carry an attested time rather than a claimed one.
    ///
    /// Empty leaves the signature at baseline level `B`: the time in it
    /// is the signer's word. More than one is allowed and they are
    /// alternatives, not a sequence -- each attests the same signature,
    /// so the signature keeps a proven time for as long as any one of
    /// them is still trusted.
    pub timestamp_authorities: Vec<String>,
    /// Optional credentials for the sole configured timestamp authority.
    ///
    /// Credentials are deliberately limited to one authority so they can
    /// never be replayed to a fallback host.
    pub timestamp_credentials: Option<TimestampCredentials>,
}

/// User-interface material for a certificate-derived visible PDF signature.
#[derive(Debug, Clone)]
pub struct VisibleSignatureRequest {
    /// Optional DG7 handwriting read from the displayed card.
    pub handwriting: Option<SignatureInk>,
}

impl DocumentRequest {
    /// Whether this request must collect and embed complete LT material.
    ///
    /// Kept at the API boundary rather than only in CLI argument
    /// normalization: callers may construct this public type directly,
    /// and LTA without the preceding LT evidence is not a valid level.
    const fn requires_long_term_material(&self) -> bool {
        self.long_term || self.archive
    }

    /// Reject an impossible requested level before opening a reader or
    /// asking for a PIN. Archive still normalizes to LT through
    /// [`Self::requires_long_term_material`]; this only catches missing
    /// authorities and formats whose archive construction is absent.
    fn validate_signing_policy(&self) -> Result<(), SignErrorKind> {
        if self.requires_long_term_material() && self.timestamp_authorities.is_empty() {
            return Err(SignErrorKind::Timestamp(
                "LT and LTA signatures need at least one timestamp authority".to_owned(),
            ));
        }
        if self.timestamp_credentials.is_some() {
            if self.timestamp_authorities.len() != 1 {
                return Err(SignErrorKind::Timestamp(
                    "timestamp credentials require exactly one authority".to_owned(),
                ));
            }
            let authority =
                refineid_lib_core::text::Uri::parse(self.timestamp_authorities[0].clone())
                    .map_err(|error| SignErrorKind::Timestamp(error.to_string()))?;
            if authority.scheme() != refineid_lib_core::text::Scheme::Https {
                return Err(SignErrorKind::Timestamp(
                    "timestamp credentials require HTTPS".to_owned(),
                ));
            }
        }
        if self.archive && !matches!(self.format, Format::Pades | Format::AsicECades) {
            return Err(SignErrorKind::Document(DocumentError::ArchiveUnsupported));
        }
        Ok(())
    }
}

/// Inputs.
#[derive(Debug)]
pub struct SignOptions {
    /// Filesystem path to the message bytes to sign. Loaded
    /// whole-file; the SHA-256 hash is computed inside refineid
    /// and sent to the card via `PSO:HASH` per FINEID S1
    /// v4.2 §3.5.
    pub input: PathBuf,
    /// Filesystem path where the resulting raw RSA-PKCS#1 v1.5
    /// signature bytes will be written (no envelope).
    pub output: PathBuf,
    /// PIN value the operator entered for the targeted slot.
    /// Consumed and zeroized at function return.
    pub pin: PinBytes,
    /// Optional output path for the DER bytes of the on-card cert
    /// that produced the signature. Pairs the signature with the
    /// cert it can be verified against -- enables offline
    /// third-party verify with no card.
    pub save_cert: Option<PathBuf>,
    /// Optional substring match against reader names. Required
    /// when more than one card is present; the picker errors
    /// out rather than guess.
    pub reader_filter: Option<String>,
    /// Card Access Number for the contactless interface, where
    /// the card seals PKCS#15 behind PACE. `None` on the contact
    /// interface. When the seal is hit and this is `None`, the
    /// flow fails with [`SignErrorKind::NeedCan`] so the CLI can
    /// prompt and retry. Never logged.
    pub can: Option<Can>,
    /// Produce a signed document rather than raw signature bytes.
    ///
    /// `None` keeps the original behaviour: `--out` receives the
    /// signature the card computed over the input file, and nothing
    /// else.
    pub document: Option<DocumentRequest>,
}

/// One reader's worth of sign output.
#[derive(Debug, Clone)]
pub struct SignReport {
    /// PC/SC reader name the sign APDU chain landed against.
    /// Tier 0 `String` from `ReaderId::as_str().to_owned()`.
    pub reader: String,
    /// Which sign slot the operation targeted (auth key /
    /// non-repudiation key).
    pub slot: SignSlot,
    /// Length of the input file in bytes.
    pub input_len: u64,
    /// SHA-256 of the input.
    pub input_sha256: Sha256,
    /// Where the signature was written.
    pub signature_path: PathBuf,
    /// Where the cert DER was written, when `save_cert` was set.
    pub cert_path: Option<PathBuf>,
    /// Signature length in bytes (384 for RSA-3072, 96 for P-384).
    pub signature_len: usize,
    /// How many timestamp tokens were actually obtained.
    ///
    /// This includes the outer archive timestamp for an LTA document,
    /// in addition to the signature timestamps. It is a token count,
    /// not a count of distinct authorities: one authority may issue
    /// both kinds of token.
    pub timestamps: usize,
    /// Size of the file that was written.
    ///
    /// Equal to `signature_len` for a bare sign, and the size of the
    /// finished document otherwise -- which is the number an operator
    /// looking at `--out` expects to see.
    pub output_len: usize,
    /// Subject CN of the on-card cert, when we could parse it.
    pub cert_subject_cn: Option<CommonName>,
    /// PIN retries reported by the card when VERIFY succeeded
    /// without an explicit retry counter. `None` means the card
    /// returned plain `0x9000` (no count surfaced).
    pub pin_retries_after: Option<u8>,
    /// Local-verify outcome.
    ///
    /// Whether refineid re-verified the card-produced signature
    /// against the on-card cert's public key before returning.
    /// Distinguishes "verified ok", "verified failed", and
    /// "skipped" (e.g. ECDSA local verify not yet wired) so the
    /// CLI exit-status and the human report don't conflate the
    /// three.
    pub local_verify: LocalVerifyOutcome,
}

/// Whether refineid re-verified the on-card signature against
/// the cert's public key before reporting success.
#[derive(Debug, Clone)]
pub enum LocalVerifyOutcome {
    /// `verify_pkcs1v15_sha256(pubkey, input, signature)` (RSA
    /// path) or the equivalent ECDSA verify returned `Ok(())`.
    Ok,
    /// Local verify ran and rejected the signature. The carried
    /// string is the diagnostic from the lower-level verifier.
    Failed(String),
    /// Local verify was not performed for this signature. Used
    /// today for the ECDSA-P384 chain (the raw-r||s -> DER
    /// conversion + pub exposure of the verify primitives are
    /// the follow-on commit). Tier 0 `&'static str`; describes
    /// why the skip happened.
    Skipped(&'static str),
}

impl LocalVerifyOutcome {
    /// `true` iff the variant is [`LocalVerifyOutcome::Ok`].
    /// Used by the CLI to map the verify result onto an exit
    /// status without losing the distinction between Failed and
    /// Skipped (both are not-Ok, but only Failed is a sign-flow
    /// failure).
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }

    /// `true` iff the variant is [`LocalVerifyOutcome::Failed`].
    /// Distinguishes the "verify rejected the signature" case
    /// from [`LocalVerifyOutcome::Skipped`] (verify not run).
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }
}

impl fmt::Display for LocalVerifyOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => write!(f, "ok"),
            Self::Failed(s) => write!(f, "FAILED: {s}"),
            Self::Skipped(reason) => write!(f, "skipped ({reason})"),
        }
    }
}

/// Error returned from the sign entrypoints.
///
/// Card-side outcomes that don't preclude further action
/// (wrong-PIN with retries left, etc.) are folded into
/// `PinRejected`; cryptographic and transport failures use
/// the per-stage variants.
#[derive(Debug)]
pub enum SignErrorKind {
    /// Reader-selection failure (none / multiple / bad filter).
    ReaderPick(ReaderPickError),
    /// The requested document format could not be built. Raised
    /// before the card signs anything, except for the PDF
    /// "signature did not fit" case, which is only knowable after.
    Document(DocumentError),
    /// A visible signature could not be bound to the live card and signing
    /// certificate before PIN verification.
    VisibleSignature(String),
    /// The live card is not the card the operator was shown; refused
    /// before PIN verification.
    DisplayedCard(String),
    /// The slot's certificate uses a key this crate can build a
    /// document signature with, but whose digest pairing is not one
    /// the formats name.
    UnsupportedDocumentKey(SignSlot),
    /// The chain or revocation answers could not be collected.
    ///
    /// Raised rather than falling back to a shorter-lived signature: a
    /// caller who asked for LT and silently got T would not be able to
    /// tell from the output.
    Material(String),
    /// The Time Stamp Authority could not be reached or refused.
    ///
    /// Raised rather than silently dropping the token: a caller who
    /// asked for an attested time and got a claimed one would not be
    /// able to tell from the output.
    Timestamp(String),
    /// PC/SC connect / transmit error.
    Pcsc(PcscError),
    /// Input file I/O failure (`NotFound`, `PermissionDenied`, ...).
    InputRead {
        /// Filesystem path the read was attempted against.
        path: PathBuf,
        /// Underlying `std::io::Error`.
        source: std::io::Error,
    },
    /// Signature output I/O failure.
    SignatureWrite {
        /// Filesystem path the write was attempted against.
        path: PathBuf,
        /// Underlying `std::io::Error`.
        source: std::io::Error,
    },
    /// VERIFY of the slot's PIN returned a non-Ok outcome.
    PinRejected {
        /// Which sign slot the VERIFY targeted.
        slot: SignSlot,
        /// Card-side outcome (`WrongPin{retries}`, `Locked`,
        /// `AuthenticationFailed`, ...).
        outcome: VerifyOutcome,
    },
    /// Local-policy rejection (PIN length / non-digit) before any
    /// APDU went out. Counter is unaffected.
    PinPolicy {
        /// Which sign slot the would-be VERIFY targeted.
        slot: SignSlot,
        /// Specific local-policy failure (e.g. `TooShort`,
        /// `NonDigit`).
        reason: PinPolicyReason,
    },
    /// Card returned an unexpected status word at one of the
    /// sign-chain stages.
    SignSw {
        /// Pipeline stage label (e.g. "MSE:SET DST",
        /// "PSO:HASH", "PSO:Compute Digital Signature"). Tier 0
        /// `&'static str` from a fixed compile-time set.
        stage: &'static str,
        /// Card-returned status word per ISO 7816-4 §5.1.3.
        /// Tier 0 `u16` -- the typed projection is `StatusWord`
        /// from `lib-core::apdu`; this field carries the raw
        /// wire value for the diagnostic.
        sw: u16,
    },
    /// Card returned a signature with the wrong length (e.g. an
    /// ECDSA card on this RSA-pinned path).
    UnexpectedSignatureLength(usize),
    /// Signing input cannot be represented by the card command.
    InputTooLong(usize),
    /// The on-card cert is missing or unparseable.
    CertUnavailable {
        /// Which sign slot the cert read targeted.
        slot: SignSlot,
        /// Human-readable detail from the cert reader / parser.
        /// Tier 0 `String`; presentational.
        detail: String,
    },
    /// Cert was readable but its public key type is not supported
    /// (not RSA, not ECDSA P-384, or uses explicit EC params).
    UnsupportedKeyType(SignSlot),
    /// Cert carries an EC key on a curve other than secp384r1.
    /// The Newer-scheme sign chain handles only secp384r1 + SHA-384
    /// (S4-1 v4.2 §4.2); the other supported curve OIDs land here
    /// rather than at the wire layer where the card would reject
    /// the algRef byte.
    UnsupportedCurve {
        /// Which sign slot's cert carried the unsupported curve.
        slot: SignSlot,
        /// Curve the cert was issued on.
        curve: EcCurve,
    },
    /// Cert + signature parsed but local PKCS1v15-SHA256 verify
    /// failed -- card returned a signature that doesn't match the
    /// on-card public key over our input.
    LocalVerifyFailed(String),
    /// Lower-level transport / APDU failure not covered by the
    /// per-stage variants. Tier 0 `String`; presentational copy
    /// of the upstream error.
    Transport(String),
    /// The card sealed PKCS#15 behind PACE (contactless
    /// interface) and no CAN was provided to open it.
    NeedCan,
    /// PACE failed with the wrong-CAN signature: card-reported
    /// authentication failure or a mutual-auth tag mismatch.
    BadCan,
    /// PACE establishment failed for a non-CAN reason. Tier 0
    /// `String`; presentational copy of the upstream error.
    Pace(String),
}

impl fmt::Display for SignErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReaderPick(e) => write!(f, "{e}"),
            Self::Pcsc(e) => write!(f, "PC/SC: {e}"),
            Self::Document(e) => write!(f, "{e}"),
            Self::VisibleSignature(detail) => write!(f, "visible signature: {detail}"),
            Self::DisplayedCard(detail) => write!(f, "displayed card: {detail}"),
            Self::Material(detail) => write!(f, "validation material: {detail}"),
            Self::Timestamp(detail) => write!(f, "timestamp: {detail}"),
            Self::UnsupportedDocumentKey(slot) => write!(
                f,
                "the {} certificate's key type cannot produce a document signature",
                slot.label()
            ),
            Self::InputRead { path, source } => {
                write!(f, "read input {}: {source}", path.display())
            }
            Self::SignatureWrite { path, source } => {
                write!(f, "write signature {}: {source}", path.display())
            }
            Self::PinRejected {
                slot,
                outcome: VerifyOutcome::WrongPin { retries_left },
            } => {
                write!(
                    f,
                    "{} rejected (wrong PIN, {retries_left} retries left)",
                    slot.pin_label()
                )
            }
            Self::PinRejected {
                slot,
                outcome: VerifyOutcome::Locked,
            } => {
                write!(
                    f,
                    "{} is blocked -- card needs a PUK unblock",
                    slot.pin_label()
                )
            }
            Self::PinRejected {
                slot,
                outcome: VerifyOutcome::Other(sw),
            } => {
                write!(f, "{} verify: unexpected SW={sw:#06X}", slot.pin_label())
            }
            Self::PinRejected {
                outcome: VerifyOutcome::Ok,
                ..
            } => write!(f, "internal: PinRejected(Ok) is not an error state"),
            Self::PinPolicy { slot, reason } => {
                write!(f, "{} rejected locally: {reason}", slot.pin_label())
            }
            Self::SignSw { stage, sw } => {
                write!(f, "sign chain failed at {stage}: SW={sw:#06X}")
            }
            Self::UnexpectedSignatureLength(n) => {
                write!(
                    f,
                    "card returned {n}-byte signature; expected 384 (RSA-3072)"
                )
            }
            Self::InputTooLong(n) => {
                write!(f, "{n}-byte signing input exceeds the card command length")
            }
            Self::CertUnavailable { slot, detail } => {
                write!(
                    f,
                    "{} cert unavailable for local verify: {detail}",
                    slot.slot_label()
                )
            }
            Self::UnsupportedKeyType(slot) => {
                write!(
                    f,
                    "{} cert has an unsupported key type (not RSA, not ECDSA P-384, or explicit EC params)",
                    slot.slot_label()
                )
            }
            Self::UnsupportedCurve { slot, curve } => {
                write!(
                    f,
                    "{} cert is EC on {} ({}-bit); refineid currently only signs ECDSA on secp384r1",
                    slot.slot_label(),
                    curve.label(),
                    curve.bits()
                )
            }
            Self::LocalVerifyFailed(s) => write!(f, "local verify failed: {s}"),
            Self::Transport(s) => write!(f, "transport: {s}"),
            Self::NeedCan => write!(
                f,
                "contactless card: the PKCS#15 application is sealed behind \
                 PACE; provide the CAN (six digits printed on the card front) \
                 via --can or the prompt"
            ),
            Self::BadCan => write!(f, "PACE failed: the CAN did not match the card"),
            Self::Pace(s) => write!(f, "PACE: {s}"),
        }
    }
}

impl core::error::Error for SignErrorKind {}

impl From<PcscError> for SignErrorKind {
    fn from(e: PcscError) -> Self {
        Self::Pcsc(e)
    }
}

impl From<ReaderPickError> for SignErrorKind {
    fn from(e: ReaderPickError) -> Self {
        Self::ReaderPick(e)
    }
}

/// Drive the sign chain for `slot` on the first reader with a
/// card. `options` is taken by value so the embedded
/// [`PinBytes`] drops (and zeroes) when this function returns,
/// regardless of branch.
///
/// # Errors
/// PC/SC enumeration / connect failure, PIN policy / verify
/// failure, sign-chain SW failure, signature-length mismatch,
/// cert read or parse failure, local-verify failure, or
/// input / output I/O failure.
// sign_with_slot is a flat sequence of open -> read input -> hash
// -> read cert -> VERIFY PIN -> sign chain -> local verify ->
// write. Splitting into helpers would just shuttle locals across
// boundaries; the body reads top-to-bottom as one operation.
/// Dispatch the per-cert sign chain: RSA (PKCS#1 v1.5 SHA-256) or
/// ECDSA P-384 SHA-384, returning the raw signature bytes plus the
/// local-verify outcome. Unsupported curves / non-RSA SPKIs raise
/// the typed error kind without doing any APDU.
fn sign_dispatch_by_alg<T: CardTransport>(
    transport: &mut T,
    slot: SignSlot,
    scheme: PinReferenceScheme,
    cert: &Certificate<'_>,
    cert_algorithm: PublicKeyAlgorithm,
    input_bytes: &[u8],
    input_sha256: Sha256,
) -> Result<(Vec<u8>, LocalVerifyOutcome), SignErrorKind> {
    match cert_algorithm {
        PublicKeyAlgorithm::Rsa { .. } => {
            let pubkey = extract_rsa_public_key(cert.spki.as_der())
                .ok_or(SignErrorKind::UnsupportedKeyType(slot))?;
            // The organizational platform has no external-hash
            // PSO:HASH: the off-card digest rides in PSO:CDS's data
            // field there (organizational cards specification
            // §6.6.2.3).
            let signature = match scheme {
                PinReferenceScheme::Citizen => transport
                    .sign_pre_hashed_sha256_rsa(slot.key_ref(), input_sha256)
                    .map_err(sign_err_to_kind)?,
                PinReferenceScheme::Organizational => transport
                    .sign_pre_hashed_sha256_rsa_hash_in_command(slot.key_ref(), input_sha256)
                    .map_err(sign_err_to_kind)?,
            };
            let verify = match pubkey.verify_pkcs1v15_sha256(input_bytes, &signature) {
                Ok(()) => LocalVerifyOutcome::Ok,
                Err(e) => {
                    return Err(SignErrorKind::LocalVerifyFailed(format!("{e}")));
                }
            };
            Ok((signature.into_bytes(), verify))
        }
        PublicKeyAlgorithm::Ec(EcCurve::Secp384r1) => {
            let hash_sha384 = Sha384::of(input_bytes);
            let signature = transport
                .sign_pre_hashed_sha384_ecdsa_p384(slot.key_ref(), hash_sha384)
                .map_err(sign_err_to_kind)?;
            let pubkey =
                cert.spki
                    .ec_public_key_point()
                    .ok_or_else(|| SignErrorKind::CertUnavailable {
                        slot,
                        detail: "EC public-key point unavailable from cert SPKI".to_owned(),
                    })?;
            let verify = match pubkey.verify_p384_sha384_raw(signature.clone(), hash_sha384) {
                Ok(()) => LocalVerifyOutcome::Ok,
                Err(e) => {
                    return Err(SignErrorKind::LocalVerifyFailed(format!("{e}")));
                }
            };
            Ok((signature.into_bytes(), verify))
        }
        PublicKeyAlgorithm::Ec(curve) => Err(SignErrorKind::UnsupportedCurve { slot, curve }),
        PublicKeyAlgorithm::EcExplicit { .. } | PublicKeyAlgorithm::Other => {
            Err(SignErrorKind::UnsupportedKeyType(slot))
        }
    }
}

/// Drive the full sign flow for one [`SignSlot`].
///
/// FINEID S1 v4.2 §3.5 + §3.6 + §3.7. Steps:
///
///   1. Open a transport against the picked reader.
///   2. Select the FINEID PKCS#15 application, then the slot's
///      cert; read the SPKI for the local verify step.
///   3. VERIFY the slot's PIN; consume `options` so the
///      [`PinBytes`] zeroize on return (Rule E1).
///   4. MSE:SET DST -> PSO:HASH -> PSO:CDS chain.
///   5. Local verify against the SPKI (Rule E7); refuse to
///      hand back a signature that doesn't verify.
///
/// Returns a [`SignReport`] carrying the signature bytes,
/// local-verify outcome, and audit metadata. Errors surface
/// as [`SignErrorKind`] -- the function never panics across
/// the FFI / CLI boundary.
pub(crate) fn sign_with_slot(
    backend: PcscBackend,
    slot: SignSlot,
    options: SignOptions,
) -> Result<SignReport, SignErrorKind> {
    if let Some(request) = options.document.as_ref() {
        request.validate_signing_policy()?;
    }
    let reader_id = backend.pick_single_reader(
        options
            .reader_filter
            .clone()
            .map(refineid_lib_core::backend::ReaderFilter::new),
    )?;

    let input_bytes = std::fs::read(&options.input).map_err(|source| SignErrorKind::InputRead {
        path: options.input.clone(),
        source,
    })?;
    // `Vec<u8>::len()` is bounded by available RAM; `usize`-to-`u64`
    // is a widening conversion on every target we ship (32-bit
    // `usize` fits in `u64`; 64-bit `usize` IS `u64`).
    let input_len: u64 = u64::try_from(input_bytes.len()).unwrap_or(u64::MAX);
    let input_sha256 = Sha256::of(&input_bytes);

    // Stays Read (not PinSequence) deliberately: for document
    // output, sign_chain calls assemble_document, which fetches
    // timestamps from network authorities WHILE this transport is
    // alive -- a held transaction across network IO would trip
    // the resource manager's idle reset. PinSequence becomes
    // possible here once document assembly moves after the card
    // session closes.
    let mut transport = backend.open_session(&reader_id, ReaderAccessCap::Read)?;

    // SELECT the FINEID PKCS#15 application first. The qualified-
    // signature cert (EF.4332) lives under DF.5016 and the card
    // needs the PKCS#15 application active before we can navigate
    // there from the post-ATR state. Without this the SELECT
    // chain on EF.4332 returns SW=6A82 ("file not found"). For
    // the auth slot the read_certificate path does its own SELECT
    // PKCS#15, so this is a no-op-with-extra-APDU there.
    //
    // Over the contactless interface the card refuses every
    // pre-PACE command with SW 6982 -- PKCS#15 only opens inside
    // a PACE secure channel keyed from the CAN. On that answer,
    // establish PACE and run the identical chain through the SM
    // wrapper: the ops traits are generic over `CardTransport`
    // and `SmTransport` is one, so the chain code is shared. The
    // sign key's access condition is plain CHV with no interface
    // restriction (FINEID S4-1 v4.2 s8.1.7-9), which is what
    // licenses contactless signing at all.
    let chain = match transport.select_pkcs15_application() {
        Ok(()) => sign_chain(&mut transport, slot, &options, &input_bytes, input_sha256)?,
        Err(Pkcs15Error::Sw(sw))
            if StatusWord::from_u16(sw) == StatusWord::SecurityNotSatisfied =>
        {
            let Some(can) = options.can else {
                return Err(SignErrorKind::NeedCan);
            };
            // Start PACE from a clean card. The reset clears two
            // states that otherwise make PACE fail for reasons
            // that have nothing to do with the CAN the operator
            // typed: the probe SELECT above (which left the card
            // outside MF, so MSE:Set AT answers SW=0x6999), and a
            // CAN suspended by an earlier failed PACE, which the
            // card reports exactly like a wrong CAN until it is
            // reset (BSI TR-03110-3 §2.4). Both observed on a
            // production card over an ACR1581 PICC slot,
            // 2026-07-24.
            transport
                .reset()
                .map_err(|e| SignErrorKind::Pace(format!("reset before PACE: {e}")))?;
            // PACE's MSE:Set AT is only accepted in MF context.
            // The reset lands the card there already; this makes
            // the requirement explicit and survives a backend
            // whose reset leaves selection elsewhere. The proven
            // contactless flow in refineid-lib-ffi does the same.
            transport
                .select_mf()
                .map_err(|e| SignErrorKind::Pace(format!("SELECT MF before PACE: {e}")))?;
            let session =
                pace::run_pace_with_can(&mut transport, can).map_err(|e| pace_err_to_kind(&e))?;
            let mut sm = SmTransport::new(transport, session);
            sm.select_pkcs15_application()
                .map_err(|e| SignErrorKind::CertUnavailable {
                    slot,
                    detail: format!("select pkcs15 app under SM: {e}"),
                })?;
            sign_chain(&mut sm, slot, &options, &input_bytes, input_sha256)?
        }
        Err(e) => {
            return Err(SignErrorKind::CertUnavailable {
                slot,
                detail: format!("select pkcs15 app: {e}"),
            });
        }
    };

    let signature_len = chain.signature_bytes.len();
    let output_len = chain.output_bytes.len();
    std::fs::write(&options.output, &chain.output_bytes).map_err(|source| {
        SignErrorKind::SignatureWrite {
            path: options.output.clone(),
            source,
        }
    })?;

    let cert_path = if let Some(path) = &options.save_cert {
        std::fs::write(path, chain.cert_der.as_bytes()).map_err(|source| {
            SignErrorKind::SignatureWrite {
                path: path.clone(),
                source,
            }
        })?;
        Some(path.clone())
    } else {
        None
    };

    Ok(SignReport {
        reader: reader_id.as_str().to_owned(),
        slot,
        input_len,
        input_sha256,
        signature_path: options.output,
        cert_path,
        signature_len,
        timestamps: chain.timestamps,
        output_len,
        cert_subject_cn: chain.cert_subject_cn,
        pin_retries_after: chain.pin_retries_after,
        local_verify: chain.local_verify,
    })
}

/// Output of [`sign_chain`]: what `sign_with_slot` still needs
/// once the card-facing work is done.
struct SignChainOutput {
    /// DER of the slot cert that produced the signature.
    cert_der: CertDer,
    /// Subject CN for the report.
    cert_subject_cn: Option<CommonName>,
    /// Retry count surfaced by a non-Ok VERIFY status word; see
    /// [`SignReport::pin_retries_after`].
    pin_retries_after: Option<u8>,
    /// Raw signature bytes off the card.
    signature_bytes: Vec<u8>,
    /// Timestamp tokens actually obtained.
    timestamps: usize,
    /// What gets written to `--out`: the raw signature for a bare
    /// sign, or the finished document when a format was asked for.
    output_bytes: Vec<u8>,
    /// Rule E7 local-verify outcome.
    local_verify: LocalVerifyOutcome,
}

/// The card-facing sign chain both interface paths share once
/// the PKCS#15 application is selected on `transport`: cert
/// read + parse, VERIFY of the slot PIN, and the MSE/PSO sign
/// dispatch with its local verify. Generic over
/// [`CardTransport`] so the same code runs on the plain contact
/// channel and inside the PACE [`SmTransport`] on contactless.
fn sign_chain<T: CardTransport>(
    transport: &mut T,
    slot: SignSlot,
    options: &SignOptions,
    input_bytes: &[u8],
    input_sha256: Sha256,
) -> Result<SignChainOutput, SignErrorKind> {
    let cert_der = transport.read_certificate(slot.cert_slot()).map_err(|e| {
        SignErrorKind::CertUnavailable {
            slot,
            detail: format!("read: {e}"),
        }
    })?;
    let cert_owned =
        OwnedCert::from_der(cert_der.as_bytes()).map_err(|e| SignErrorKind::CertUnavailable {
            slot,
            detail: format!("parse: {e}"),
        })?;
    // Bind the view once: `view()` re-parses the DER on each call.
    let cert = cert_owned.view();
    let cert_subject_cn = cert.subject.common_name();
    let cert_algorithm = cert.spki.algorithm();

    // What the card actually signs. For a raw signature that is the
    // input file. For a document it is a structure built around the
    // certificate we just read -- CAdES signed attributes, or a
    // canonical ds:SignedInfo -- which is why this cannot happen
    // before the card is open.
    let document = match options.document {
        None => None,
        Some(ref request) => {
            ensure_displayed_card(transport, request)?;
            let parameters = document_signer(&cert, cert_algorithm, slot, request.signing_time)?;
            let objects = load_data_objects(options, request, input_bytes)?;
            let metadata = document_metadata(&cert, request)?;
            let plan = document::plan(request.format, objects, &parameters, &metadata)
                .map_err(SignErrorKind::Document)?;
            Some((plan, parameters))
        }
    };
    let signed_octets: &[u8] = match document {
        None => input_bytes,
        Some((ref plan, _)) => plan.to_be_signed(),
    };

    // VERIFY PIN only after the document and any visible identity have been
    // bound to this live card. A card swap or malformed appearance request
    // therefore cannot consume a PIN retry.
    //
    // The reference numbering is the card's to declare (citizen
    // S1 v4.2 vs organizational S4-2 v4.0), resolved by
    // counter-safe probes before the typed PIN is spent.
    let scheme = transport
        .resolve_pin_reference_scheme()
        .map_err(|e| match e {
            AuthError::Transport(t) => SignErrorKind::Transport(format!("{t}")),
            AuthError::PinPolicy(reason) => SignErrorKind::PinPolicy { slot, reason },
        })?;
    let outcome = transport
        .verify_pin_with_scheme(slot.pin_slot(), scheme, options.pin.clone())
        .map_err(|e| match e {
            AuthError::Transport(t) => SignErrorKind::Transport(format!("{t}")),
            AuthError::PinPolicy(reason) => SignErrorKind::PinPolicy { slot, reason },
        })?;
    let pin_retries_after = match outcome {
        VerifyOutcome::Ok => None,
        rejected @ (VerifyOutcome::WrongPin { .. }
        | VerifyOutcome::Locked
        | VerifyOutcome::Other(_)) => {
            return Err(SignErrorKind::PinRejected {
                slot,
                outcome: rejected,
            });
        }
    };

    // The RSA path signs this digest; the ECDSA path recomputes its
    // own SHA-384 from the same octets. Both stay in step with the
    // digest named in `document_signer`.
    let signed_sha256 = match document {
        None => input_sha256,
        Some(_) => Sha256::of(signed_octets),
    };

    // Branch on cert public-key shape per FINEID S4-1 v4.2 §4.2:
    // Older-scheme cards have an RSA-3072 auth key; Newer-scheme
    // cards have ECC P-384 (secp384r1) + SHA-384. The PSO chain
    // selects the right algRef, the right PSO:HASH hash size,
    // and the right signature-length expectation for each.
    let (signature_bytes, local_verify) = sign_dispatch_by_alg(
        transport,
        slot,
        scheme,
        &cert_owned.view(),
        cert_algorithm,
        signed_octets,
        signed_sha256,
    )?;

    // Local verify above proved the card signed what we asked it to.
    // Only now is it worth assembling, because assembly can still
    // fail -- a CAdES that outgrew the hole reserved in a PDF.
    let (output_bytes, timestamps) = match document {
        None => (signature_bytes.clone(), 0),
        Some((plan, parameters)) => {
            assemble_document(options, plan, &parameters, &signature_bytes, &cert_der)?
        }
    };

    Ok(SignChainOutput {
        cert_der,
        cert_subject_cn,
        pin_retries_after,
        signature_bytes,
        timestamps,
        output_bytes,
        local_verify,
    })
}

/// Resolve a visible PDF mark from the live signing certificate.
///
/// This runs before PIN verification, after the displayed-card check
/// has bound the session to the card the UI showed.
fn document_metadata(
    certificate: &Certificate<'_>,
    request: &DocumentRequest,
) -> Result<SignatureMetadata, SignErrorKind> {
    let Some(visible) = request.visible_signature.as_ref() else {
        return Ok(request.metadata.clone());
    };
    if request.format != Format::Pades {
        return Err(SignErrorKind::VisibleSignature(
            "visible marks are supported only for PAdES".to_owned(),
        ));
    }

    let names = certificate.subject.given_names();
    let first = names.first.ok_or_else(|| {
        SignErrorKind::VisibleSignature(
            "signing certificate has no structured given name".to_owned(),
        )
    })?;
    let surname = certificate.subject.surname().ok_or_else(|| {
        SignErrorKind::VisibleSignature("signing certificate has no structured surname".to_owned())
    })?;
    let identifier = certificate.subject.peuin().ok_or_else(|| {
        SignErrorKind::VisibleSignature("signing certificate has no SATU identifier".to_owned())
    })?;
    let display_name = format!("{} {}", first.to_native(), surname.to_native());
    let appearance = VisibleSignature::new(
        &display_name,
        identifier.as_str(),
        visible.handwriting.clone(),
    )
    .ok_or_else(|| {
        SignErrorKind::VisibleSignature(
            "certificate identity cannot be rendered safely in the PDF".to_owned(),
        )
    })?;
    let mut metadata = request.metadata.clone();
    metadata.visible_signature = Some(appearance);
    Ok(metadata)
}

/// Refuse to sign when the live card is not the one the operator saw.
///
/// Runs before PIN verification for every document request carrying a
/// displayed serial, whatever the format produces.
fn ensure_displayed_card<T: CardTransport>(
    transport: &mut T,
    request: &DocumentRequest,
) -> Result<(), SignErrorKind> {
    let Some(expected) = request.expected_serial.as_ref() else {
        return Ok(());
    };
    let token = transport.read_token_info().map_err(|error| {
        SignErrorKind::DisplayedCard(format!("cannot re-read EF.TokenInfo: {error}"))
    })?;
    let live = token.serial_number_hex.map(render_token_serial);
    ensure_expected_serial(expected, live.as_ref())
}

fn ensure_expected_serial(
    expected: &TokenSerial,
    live: Option<&TokenSerial>,
) -> Result<(), SignErrorKind> {
    match live {
        Some(live) if live == expected => Ok(()),
        Some(_different) => Err(SignErrorKind::DisplayedCard(
            "the card in the reader is not the card displayed by the application".to_owned(),
        )),
        None => Err(SignErrorKind::DisplayedCard(
            "the card does not publish a PKCS#15 serial for session binding".to_owned(),
        )),
    }
}

/// Ask a Time Stamp Authority to attest the signature's time.
///
/// The digest goes over the signature value as the format will store
/// it, which [`DocumentPlan::timestamp_digest`] works out; this only
/// carries it there and back.
fn fetch_timestamp(
    url: &str,
    credentials: Option<&TimestampCredentials>,
    retry_transient: bool,
    plan: &DocumentPlan,
    parameters: &SignerParameters<'_>,
    signature: &[u8],
    algorithm: DigestAlgorithm,
) -> Result<VerifiedTimestampToken, SignErrorKind> {
    /// A timestamp token with the TSA's certificate in it. Comfortably
    /// above what any TSA returns, and a bound rather than a promise.
    const MAX_RESPONSE: usize = 64 * 1024;
    /// Nonce width. RFC 3161 sets no size; 64 bits is what the TSA
    /// needs to tell one request from another.
    const NONCE_BYTES: usize = 8;

    // What gets timestamped depends on the format, so the plan is
    // asked rather than assumed.
    let digest = plan
        .timestamp_digest(parameters, signature, algorithm)
        .map_err(SignErrorKind::Document)?;
    let nonce = refineid_lib_core::rng::array::<NONCE_BYTES>()
        .map_err(|e| SignErrorKind::Timestamp(format!("no random nonce: {e}")))?;
    let timestamp_query_der = timestamp::request(&digest, algorithm, Some(&nonce), true);

    let uri = refineid_lib_core::text::Uri::parse(url.to_owned())
        .map_err(|e| SignErrorKind::Timestamp(format!("{url}: {e}")))?;
    let requested_at = crate::card_check::now_date_time();
    let response = post_timestamp_query(
        &uri,
        &timestamp_query_der,
        MAX_RESPONSE,
        credentials,
        retry_transient,
    )
    .map_err(|e| SignErrorKind::Timestamp(format!("POST {url}: {e}")))?;
    let received_at = crate::card_check::now_date_time();

    // Bound to this request: the digest we sent and the nonce we drew.
    // Authenticated transport alone would still not prove that a valid
    // old token answered this particular request.
    let token = timestamp::verified_token(&response, &digest, algorithm, Some(&nonce))
        .map_err(|e: TimestampError| SignErrorKind::Timestamp(format!("{e}")))?;
    require_live_timestamp_time(&token, requested_at, received_at)?;
    Ok(token)
}

fn post_timestamp_query(
    uri: &refineid_lib_core::text::Uri,
    timestamp_query_der: &[u8],
    max_response: usize,
    credentials: Option<&TimestampCredentials>,
    retry_transient: bool,
) -> Result<Vec<u8>, crate::http::HttpError> {
    if !retry_transient {
        return post_timestamp_query_once(uri, timestamp_query_der, max_response, credentials);
    }
    retry_timestamp_query(
        || post_timestamp_query_once(uri, timestamp_query_der, max_response, credentials),
        |delay, error| {
            eprintln!(
                "timestamp authority temporarily unavailable ({error}); retrying in {} seconds",
                delay.as_secs()
            );
            std::thread::sleep(delay);
        },
    )
}

fn post_timestamp_query_once(
    uri: &refineid_lib_core::text::Uri,
    timestamp_query_der: &[u8],
    max_response: usize,
    credentials: Option<&TimestampCredentials>,
) -> Result<Vec<u8>, crate::http::HttpError> {
    credentials.map_or_else(
        || {
            crate::http::post_authority(
                uri,
                "application/timestamp-query",
                timestamp_query_der,
                max_response,
                crate::user_agent::honest(),
                None,
            )
        },
        |credentials| {
            credentials.with_authorization_header(|header| {
                crate::http::post_authority(
                    uri,
                    "application/timestamp-query",
                    timestamp_query_der,
                    max_response,
                    crate::user_agent::honest(),
                    Some(header),
                )
            })
        },
    )
}

fn retry_timestamp_query<T>(
    mut post: impl FnMut() -> Result<T, crate::http::HttpError>,
    mut wait: impl FnMut(core::time::Duration, &crate::http::HttpError),
) -> Result<T, crate::http::HttpError> {
    let mut delay = TIMESTAMP_RETRY_INITIAL_DELAY;
    loop {
        match post() {
            Ok(response) => return Ok(response),
            Err(error) if error.is_retryable_authority_failure() => {
                wait(delay, &error);
                delay = delay
                    .checked_mul(2)
                    .unwrap_or(TIMESTAMP_RETRY_MAX_DELAY)
                    .min(TIMESTAMP_RETRY_MAX_DELAY);
            }
            Err(error) => return Err(error),
        }
    }
}

const fn retry_transient_authority_failures(authority_count: usize) -> bool {
    authority_count == 1
}

/// Require a nonce-bound response to describe the exchange that just ran.
fn require_live_timestamp_time(
    token: &VerifiedTimestampToken,
    requested_at: DateTime,
    received_at: DateTime,
) -> Result<(), SignErrorKind> {
    let earliest = requested_at
        .unix_duration()
        .saturating_sub(MAX_TIMESTAMP_CLOCK_SKEW);
    let latest = received_at
        .unix_duration()
        .saturating_add(MAX_TIMESTAMP_CLOCK_SKEW);
    let generated = token.generated_at.unix_duration();
    if generated < earliest || generated > latest {
        return Err(SignErrorKind::Timestamp(format!(
            "authenticated genTime {} is outside this request's clock-skew window",
            token.generated_at
        )));
    }
    Ok(())
}

struct CollectedTimestamps {
    tokens: Vec<VerifiedTimestampToken>,
    material: ValidationMaterial,
}

/// Obtain and verify every signature timestamp that remains usable.
///
/// Authorities are alternatives: a refused answer is reported and
/// skipped, while loss of every requested answer is fatal. The
/// authority itself is trusted as configured -- whoever names one
/// answers for it. LT/LTA additionally collects chain and current
/// revocation evidence for each retained token, anchored on the
/// certificates the token itself carries.
fn collect_document_timestamps(
    request: Option<&DocumentRequest>,
    authorities: &[String],
    plan: &DocumentPlan,
    parameters: &SignerParameters<'_>,
    signature_bytes: &[u8],
) -> Result<CollectedTimestamps, SignErrorKind> {
    let keep_material = request.is_some_and(DocumentRequest::requires_long_term_material);
    let credentials = request.and_then(|request| request.timestamp_credentials.as_ref());
    let mut tokens = Vec::with_capacity(authorities.len());
    let mut material = ValidationMaterial::default();
    let mut refusals = Vec::new();
    for url in authorities {
        let token = match fetch_timestamp(
            url,
            credentials,
            retry_transient_authority_failures(authorities.len()),
            plan,
            parameters,
            signature_bytes,
            parameters.digest_algorithm,
        ) {
            Ok(token) => token,
            Err(why) => {
                refusals.push(format!("{url}: {why}"));
                continue;
            }
        };
        if keep_material {
            match timestamp_validation_material(&token) {
                Ok(evidence) => merge_material(&mut material, evidence),
                Err(why) => {
                    refusals.push(format!(
                        "{url}: returned a cryptographically valid token, but complete current validation evidence for its chain could not be collected: {why}"
                    ));
                    continue;
                }
            }
        }
        tokens.push(token);
    }
    if (!authorities.is_empty()
        || request.is_some_and(DocumentRequest::requires_long_term_material))
        && tokens.is_empty()
    {
        let detail = if refusals.is_empty() {
            "no timestamp authority was configured".to_owned()
        } else {
            refusals.join("; ")
        };
        return Err(SignErrorKind::Timestamp(format!(
            "no timestamp authority produced an acceptable token, so the signature would carry no attested time -- {detail}"
        )));
    }
    for refusal in &refusals {
        eprintln!("timestamp authority declined, continuing without it -- {refusal}");
    }
    Ok(CollectedTimestamps { tokens, material })
}

/// Fetch the timestamps and evidence a document signature asked for,
/// then assemble it.
///
/// Everything here needs the network and the signature both, so it can
/// only run once the card has answered -- and it runs with the card
/// still held, because the signer parameters borrow a certificate that
/// lives only for this session.
fn assemble_document(
    options: &SignOptions,
    plan: DocumentPlan,
    parameters: &SignerParameters<'_>,
    signature_bytes: &[u8],
    cert_der: &CertDer,
) -> Result<(Vec<u8>, usize), SignErrorKind> {
    // The timestamp is over the signature, so it can only be
    // fetched now. That is a network round trip with the card
    // still held exclusively; the alternative is dropping the
    // card and re-reading the certificate to rebuild
    // `parameters`, which trades a held reader for a second
    // card session.
    let request = options.document.as_ref();
    let authorities = options
        .document
        .as_ref()
        .map(|request| request.timestamp_authorities.as_slice())
        .unwrap_or_default();
    let CollectedTimestamps {
        tokens,
        material: mut timestamp_material,
    } = collect_document_timestamps(request, authorities, &plan, parameters, signature_bytes)?;
    let keep_material = request.is_some_and(DocumentRequest::requires_long_term_material);
    let material = if keep_material {
        // The tokens go in too, so the store answers for the
        // authorities that attested the time as well as for the
        // signer. The archive timestamp below cannot add new evidence
        // after this store is written without changing the bytes it
        // signs. It must therefore reuse a TSA path already frozen here;
        // selection checks that exact coverage and revalidates current
        // evidence before accepting the outer token. A later archive
        // revision is where refreshed evidence for that token belongs.
        let signer_anchors: Vec<&[u8]> = crate::trust_roots::PINNED_ROOT_DER
            .iter()
            .map(|(_label, der)| *der)
            .collect();
        let reference_time = tokens
            .iter()
            .map(|token| token.generated_at)
            .min()
            .unwrap_or_else(crate::card_check::now_date_time);
        let signer_material = crate::validation_material::collect_chains(&[ChainStart {
            leaf_der: cert_der.as_bytes(),
            reference_time,
            approved_anchor_ders: &signer_anchors,
            nonce_policy: NoncePolicy::RequireEcho,
            include_leaf: false,
            include_anchor: false,
        }])
        .map_err(|e| SignErrorKind::Material(format!("signer path: {e}")))?;
        merge_material(&mut timestamp_material, signer_material);
        timestamp_material
    } else {
        ValidationMaterial::default()
    };
    let token_bytes: Vec<Vec<u8>> = tokens.iter().map(|token| token.token.clone()).collect();
    // ASiC-E CAdES archives through a second manifest and a
    // timestamp over it, not through the signature, so it
    // branches here rather than after assembly.
    if request.is_some_and(|r| r.archive)
        && let Some(manifest) =
            plan.archive_manifest(parameters, signature_bytes, parameters.digest_algorithm)
    {
        let digest = parameters.digest_algorithm.digest(&manifest);
        let token = first_answering_token(
            authorities,
            request.and_then(|request| request.timestamp_credentials.as_ref()),
            &digest,
            parameters.digest_algorithm,
            &material,
        )?;
        let archived = plan
            .finish_archived(
                parameters,
                signature_bytes,
                &token_bytes,
                &material,
                &manifest,
                &token.token,
            )
            .map_err(SignErrorKind::Document)?;
        return Ok((archived, reported_timestamp_tokens(tokens.len(), true)));
    }
    let document = plan
        .finish(parameters, signature_bytes, &token_bytes, &material)
        .map_err(SignErrorKind::Document)?;
    // The archive timestamp goes over the finished document,
    // validation store and all, so it can only be taken once
    // everything else is in place.
    let (bytes, archive_timestamp_obtained) = if request.is_some_and(|r| r.archive) {
        (
            archive_timestamp(
                &document,
                authorities,
                request.and_then(|request| request.timestamp_credentials.as_ref()),
                parameters.digest_algorithm,
                &material,
            )?,
            true,
        )
    } else {
        (document, false)
    };
    Ok((
        bytes,
        reported_timestamp_tokens(tokens.len(), archive_timestamp_obtained),
    ))
}

fn reported_timestamp_tokens(
    signature_timestamps: usize,
    archive_timestamp_obtained: bool,
) -> usize {
    signature_timestamps.saturating_add(usize::from(archive_timestamp_obtained))
}

/// One RFC 3161 token from one authority, over `digest`.
///
/// The nonce is checked back, so an answer replayed from an earlier
/// exchange is refused rather than accepted as fresh.
fn request_token(
    url: &str,
    credentials: Option<&TimestampCredentials>,
    retry_transient: bool,
    digest: &[u8],
    algorithm: DigestAlgorithm,
) -> Result<VerifiedTimestampToken, SignErrorKind> {
    /// Nonce width, as for the signature timestamps.
    const NONCE_BYTES: usize = 8;
    /// Cap on the authority's answer.
    const MAX_RESPONSE: usize = 64 * 1024;

    let nonce = refineid_lib_core::rng::array::<NONCE_BYTES>()
        .map_err(|e| SignErrorKind::Timestamp(format!("no random nonce: {e}")))?;
    let timestamp_query_der = timestamp::request(digest, algorithm, Some(&nonce), true);
    let uri = refineid_lib_core::text::Uri::parse(url.to_owned())
        .map_err(|e| SignErrorKind::Timestamp(format!("{url}: {e}")))?;
    let requested_at = crate::card_check::now_date_time();
    let response = post_timestamp_query(
        &uri,
        &timestamp_query_der,
        MAX_RESPONSE,
        credentials,
        retry_transient,
    )
    .map_err(|e| SignErrorKind::Timestamp(format!("POST {url}: {e}")))?;
    let received_at = crate::card_check::now_date_time();
    let token = timestamp::verified_token(&response, digest, algorithm, Some(&nonce))
        .map_err(|e: TimestampError| SignErrorKind::Timestamp(format!("{e}")))?;
    require_live_timestamp_time(&token, requested_at, received_at)?;
    Ok(token)
}

/// Wrap `pdf` in a `PAdES` document timestamp.
///
/// A further revision whose `/Contents` is an RFC 3161 token over the
/// whole file, this dictionary included. It attests that the signature
/// and the evidence beside it existed intact at a time a third party
/// vouches for -- which is what makes the evidence archivable rather
/// than merely present.
fn archive_timestamp(
    pdf: &[u8],
    urls: &[String],
    credentials: Option<&TimestampCredentials>,
    algorithm: DigestAlgorithm,
    covered_material: &ValidationMaterial,
) -> Result<Vec<u8>, SignErrorKind> {
    /// Room for the token. Generous: a token with the authority's
    /// certificate chain in it runs to a few kilobytes.
    const CAPACITY: usize = 16_384;
    let placeholder = refineid_lib_core::sign::pades::prepare_document_timestamp(pdf, CAPACITY)
        .map_err(|e| SignErrorKind::Document(DocumentError::Pdf(e)))?;
    let token = first_answering_token(
        urls,
        credentials,
        &placeholder.digest(algorithm),
        algorithm,
        covered_material,
    )?;
    placeholder
        .finish(&token.token)
        .map_err(|e| SignErrorKind::Document(DocumentError::Pdf(e)))
}

/// A token from the first authority that answers.
///
/// An archive timestamp is one token, not a set: the PDF revision has a
/// single `/Contents` and the `ASiC` archive manifest names a single
/// file. The authorities are tried in the order given, so put the one
/// most trusted first; a refusal moves to the next rather than ending
/// the signing, and only silence from all of them is fatal.
fn first_answering_token(
    urls: &[String],
    credentials: Option<&TimestampCredentials>,
    digest: &[u8],
    algorithm: DigestAlgorithm,
    covered_material: &ValidationMaterial,
) -> Result<VerifiedTimestampToken, SignErrorKind> {
    let mut refusals = Vec::new();
    for url in urls {
        match request_token(
            url,
            credentials,
            retry_transient_authority_failures(urls.len()),
            digest,
            algorithm,
        ) {
            Ok(token) => {
                if let Err(why) = authenticate_archive_timestamp(&token, covered_material) {
                    refusals.push(format!(
                        "{url} returned an archive timestamp without complete current validation evidence ({why}), trying the next"
                    ));
                    continue;
                }
                for refusal in &refusals {
                    eprintln!("archive timestamp: {refusal}");
                }
                return Ok(token);
            }
            Err(why) => refusals.push(format!("{url} declined ({why}), trying the next")),
        }
    }
    Err(SignErrorKind::Timestamp(if urls.is_empty() {
        "an archive timestamp needs an authority".to_owned()
    } else {
        format!(
            "no authority produced an acceptable archive timestamp -- {}",
            refusals.join("; ")
        )
    }))
}

/// Prove the outer timestamp has complete current validation evidence
/// before selecting it.
///
/// The returned evidence is deliberately only an acceptance gate. It
/// cannot be embedded in the revision the token signs without changing
/// those signed bytes; a later archive revision is where evidence for
/// the preceding outer timestamp belongs.
fn authenticate_archive_timestamp(
    token: &VerifiedTimestampToken,
    covered_material: &ValidationMaterial,
) -> Result<(), String> {
    authenticate_archive_timestamp_with(token, covered_material, timestamp_validation_material)
}

fn authenticate_archive_timestamp_with<F>(
    token: &VerifiedTimestampToken,
    covered_material: &ValidationMaterial,
    collect_evidence: F,
) -> Result<(), String>
where
    F: FnOnce(&VerifiedTimestampToken) -> Result<ValidationMaterial, String>,
{
    let path = embedded_timestamp_path(token)?;
    require_archive_path_covered(&path, covered_material)?;
    let _verified_current_evidence = collect_evidence(token)?;
    Ok(())
}

/// Require every certificate verified for the outer token to be
/// inside the LT store that token is about to cover.
///
/// Exact DER comparison includes the TSA leaf, intermediates, and the
/// chain's anchor. A signer rotation after the inner signature
/// timestamps were collected therefore moves to the next authority
/// instead of producing an archive whose path is outside its signed
/// validation store.
fn require_archive_path_covered(
    path: &[Vec<u8>],
    covered_material: &ValidationMaterial,
) -> Result<(), String> {
    if path.is_empty() {
        return Err("outer timestamp has an empty authenticated certificate path".to_owned());
    }
    if path
        .iter()
        .all(|certificate| covered_material.certificates.contains(certificate))
    {
        return Ok(());
    }
    Err(
        "outer timestamp certificate path is not byte-for-byte covered by embedded LT material"
            .to_owned(),
    )
}

/// The token's certificate path, verified within its own embedded
/// chain.
///
/// The authority is trusted as configured -- whoever names one answers
/// for it. What is still verified is internal consistency: the signer
/// must chain, with valid signatures and validity windows, to an
/// anchor the token itself carries.
fn embedded_timestamp_path(token: &VerifiedTimestampToken) -> Result<Vec<Vec<u8>>, String> {
    let anchors = embedded_anchor_ders(token);
    if anchors.is_empty() {
        return Err("the token embeds no certificate usable as its chain anchor".to_owned());
    }
    let embedded: Vec<&[u8]> = token
        .embedded_certificates
        .iter()
        .map(Vec::as_slice)
        .collect();
    crate::validation_material::verify_chain_to_approved_anchor(
        &token.signer_certificate,
        token.generated_at,
        &anchors,
        &embedded,
    )
    .map_err(|e| format!("no valid path within the token's embedded chain: {e}"))
}

/// The embedded certificates a token's path may stop at: the
/// self-issued ones, or every embedded certificate when none is.
///
/// Preferring self-issued anchors makes the path run as deep as the
/// token allows, so LT evidence covers the intermediates rather than
/// stopping at the signer's immediate issuer.
fn embedded_anchor_ders(token: &VerifiedTimestampToken) -> Vec<&[u8]> {
    let self_issued: Vec<&[u8]> = token
        .embedded_certificates
        .iter()
        .filter(|der| {
            OwnedCert::from_der(der).is_ok_and(|certificate| {
                let view = certificate.view();
                view.issuer.as_der() == view.subject.as_der()
            })
        })
        .map(Vec::as_slice)
        .collect();
    if self_issued.is_empty() {
        token
            .embedded_certificates
            .iter()
            .map(Vec::as_slice)
            .collect()
    } else {
        self_issued
    }
}

/// Collect chain and current revocation evidence for one token,
/// anchored on the certificates the token itself carries.
///
/// LT and LTA retain the result for their validation store; level T
/// has no store and skips this entirely.
fn timestamp_validation_material(
    token: &VerifiedTimestampToken,
) -> Result<ValidationMaterial, String> {
    let anchors = embedded_anchor_ders(token);
    if anchors.is_empty() {
        return Err("the token embeds no certificate usable as its chain anchor".to_owned());
    }
    let candidates: Vec<&[u8]> = token
        .embedded_certificates
        .iter()
        .map(Vec::as_slice)
        .collect();
    crate::validation_material::collect_chains_with_candidates(
        &[ChainStart {
            leaf_der: &token.signer_certificate,
            reference_time: token.generated_at,
            approved_anchor_ders: &anchors,
            nonce_policy: NoncePolicy::AllowMissingEcho,
            include_leaf: true,
            include_anchor: true,
        }],
        &candidates,
    )
    .map_err(|e| e.to_string())
}

/// Merge independently authenticated evidence without storing the same
/// DER object more than once.
fn merge_material(into: &mut ValidationMaterial, from: ValidationMaterial) {
    merge_unique(&mut into.certificates, from.certificates);
    merge_unique(&mut into.ocsp_responses, from.ocsp_responses);
    merge_unique(&mut into.crls, from.crls);
}

fn merge_unique(into: &mut Vec<Vec<u8>>, from: Vec<Vec<u8>>) {
    for item in from {
        if !into.contains(&item) {
            into.push(item);
        }
    }
}

/// The signer parameters a document signature is built from.
///
/// Digest and signature algorithm are taken from the certificate
/// rather than chosen: the card will sign with the key the
/// certificate names, under the one chain `sign_dispatch_by_alg`
/// drives for that key shape. Naming a different digest here would
/// produce a structure that claims one thing and carries another.
const fn document_signer<'a>(
    cert: &'a Certificate<'a>,
    cert_algorithm: PublicKeyAlgorithm,
    slot: SignSlot,
    signing_time: SigningTime,
) -> Result<SignerParameters<'a>, SignErrorKind> {
    let (digest_algorithm, signature_algorithm) = match cert_algorithm {
        PublicKeyAlgorithm::Rsa { .. } => {
            (DigestAlgorithm::Sha256, SignatureAlgorithm::RsaPkcs1Sha256)
        }
        PublicKeyAlgorithm::Ec(EcCurve::Secp384r1) => {
            (DigestAlgorithm::Sha384, SignatureAlgorithm::EcdsaSha384)
        }
        PublicKeyAlgorithm::Ec(_)
        | PublicKeyAlgorithm::EcExplicit { .. }
        | PublicKeyAlgorithm::Other => {
            return Err(SignErrorKind::UnsupportedDocumentKey(slot));
        }
    };
    Ok(SignerParameters {
        certificate: cert,
        digest_algorithm,
        signature_algorithm,
        signing_time: Some(signing_time),
    })
}

/// Read every file the request covers, in the order it named them.
///
/// The primary input is already in memory, so it is reused rather
/// than read twice; a container that signed a file which changed
/// between the two reads would attest something that never existed.
fn load_data_objects(
    options: &SignOptions,
    request: &DocumentRequest,
    input_bytes: &[u8],
) -> Result<Vec<DataObject>, SignErrorKind> {
    let mut objects = vec![data_object(&options.input, input_bytes.to_vec())];
    for path in &request.additional_inputs {
        let content = std::fs::read(path).map_err(|source| SignErrorKind::InputRead {
            path: path.clone(),
            source,
        })?;
        objects.push(data_object(path, content));
    }
    Ok(objects)
}

/// Name and media type for one file inside a container.
///
/// The name is the file name alone: a container entry called
/// `/home/someone/dossier.pdf` would leak a path and break the
/// archive layout both.
fn data_object(path: &std::path::Path, content: Vec<u8>) -> DataObject {
    let name = path
        .file_name()
        .map_or_else(|| "file".to_owned(), |n| n.to_string_lossy().into_owned());
    DataObject {
        mime_type: media_type_for(path).to_owned(),
        name,
        content,
    }
}

/// Media type guessed from the extension.
///
/// A guess is all this can be, and it is recorded in the signature,
/// so the fallback is the honest one rather than a plausible one.
fn media_type_for(path: &std::path::Path) -> &'static str {
    match path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .as_deref()
    {
        Some("pdf") => "application/pdf",
        Some("txt") => "text/plain",
        Some("xml") => "text/xml",
        Some("html" | "htm") => "text/html",
        Some("json") => "application/json",
        Some("csv") => "text/csv",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("odt") => "application/vnd.oasis.opendocument.text",
        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        _ => "application/octet-stream",
    }
}

/// Hoist [`pace::PaceError`] onto [`SignErrorKind`], with the
/// same wrong-CAN classification `emrtd::read_personal_data`
/// applies: a card-reported authentication failure or a
/// mutual-auth tag mismatch both mean the CAN-derived key
/// disagreed with the card.
fn pace_err_to_kind<TE: fmt::Display>(e: &pace::PaceError<TE>) -> SignErrorKind {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "PaceError is #[non_exhaustive]; the fallback arm absorbs every non-CAN variant into the presentational Pace(String)"
    )]
    match e {
        pace::PaceError::Sw(_, sw)
            if StatusWord::from_u16(*sw) == StatusWord::AuthenticationFailed =>
        {
            SignErrorKind::BadCan
        }
        pace::PaceError::AuthMismatch => SignErrorKind::BadCan,
        _ => SignErrorKind::Pace(format!("{e}")),
    }
}

/// Hoist [`SignError`] (lib-core) variants onto
/// [`SignErrorKind`] (client). Kept as a single function so the
/// RSA and ECDSA branches of `sign_with_slot` use the same
/// mapping.
fn sign_err_to_kind<TE: fmt::Display>(e: SignError<TE>) -> SignErrorKind {
    match e {
        SignError::Transport(t) => SignErrorKind::Transport(format!("{t}")),
        SignError::Sw(stage, sw) => SignErrorKind::SignSw { stage, sw },
        SignError::UnexpectedSignatureLength(n) => SignErrorKind::UnexpectedSignatureLength(n),
        SignError::InputTooLong(n) => SignErrorKind::InputTooLong(n),
    }
}

/// Auth-slot wrapper kept for the existing CLI subcommand.
///
/// # Errors
/// See [`sign_with_slot`].
pub(crate) fn sign_auth_first(
    backend: PcscBackend,
    options: SignOptions,
) -> Result<SignReport, SignErrorKind> {
    sign_with_slot(backend, SignSlot::Auth, options)
}

/// Qualified-signature wrapper. PIN2-gated.
///
/// # Errors
/// See [`sign_with_slot`].
pub(crate) fn sign_qualified_first(
    backend: PcscBackend,
    options: SignOptions,
) -> Result<SignReport, SignErrorKind> {
    sign_with_slot(backend, SignSlot::Qualified, options)
}

impl fmt::Display for SignReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "reader: {}", self.reader)?;
        writeln!(
            f,
            "slot: {} (key ref {:#04X})",
            self.slot.slot_label(),
            self.slot.key_ref().as_u8()
        )?;
        if let Some(cn) = &self.cert_subject_cn {
            writeln!(f, "cert subject CN: {cn}")?;
        }
        writeln!(f, "input length: {} bytes", self.input_len)?;
        writeln!(f, "input sha256: {}", self.input_sha256)?;
        writeln!(
            f,
            "output: {} ({} bytes)",
            self.signature_path.display(),
            self.output_len
        )?;
        // Named separately from the file size, which for a document
        // format is the whole document rather than the signature.
        writeln!(f, "card signature: {} bytes", self.signature_len)?;
        // How many tokens were obtained, including the outer archive
        // timestamp. This is deliberately not called an authority
        // count because one authority may issue both kinds of token.
        if self.timestamps > 0 {
            writeln!(f, "timestamp tokens obtained: {}", self.timestamps)?;
        }
        if let Some(p) = &self.cert_path {
            writeln!(f, "cert DER: {}", p.display())?;
        }
        if let Some(r) = self.pin_retries_after {
            writeln!(f, "{} retries after verify: {r}", self.slot.pin_label())?;
        }
        writeln!(
            f,
            "local verify (against on-card {} cert pubkey): {}",
            self.slot.slot_label(),
            self.local_verify,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{TestResult, check, check_true};
    use refineid_lib_core::apdu::status_word::PinRetries;

    // ---- SignSlot: the FINEID slot -> {key ref, PIN, cert}
    // mapping (S1 v4.2 §3.5). Getting any of these wrong signs
    // with the wrong key or gates on the wrong PIN, so the table
    // is pinned explicitly. ----

    #[test]
    fn auth_slot_maps_to_pin1_keyref01_ef4331() -> TestResult {
        let s = SignSlot::Auth;
        check(&s.key_ref().as_u8(), &0x01_u8, "auth key ref")?;
        check_true(matches!(s.pin_slot(), PinSlot::Pin1), "auth pin slot")?;
        check_true(
            matches!(s.cert_slot(), CertSlot::Authentication),
            "auth cert slot",
        )?;
        check(&s.pin_label(), &"PIN1", "auth pin label")?;
        check(&s.slot_label(), &"auth", "auth slot label")
    }

    #[test]
    fn qualified_slot_maps_to_pin2_keyref02_ef4332() -> TestResult {
        let s = SignSlot::Qualified;
        check(&s.key_ref().as_u8(), &0x02_u8, "qualified key ref")?;
        check_true(matches!(s.pin_slot(), PinSlot::Pin2), "qualified pin slot")?;
        check_true(
            matches!(s.cert_slot(), CertSlot::Signature),
            "qualified cert slot",
        )?;
        check(&s.pin_label(), &"PIN2", "qualified pin label")?;
        check(
            &s.slot_label(),
            &"qualified-signature",
            "qualified slot label",
        )
    }

    #[test]
    fn timestamp_credentials_are_encoded_and_redacted() -> TestResult {
        let credentials = TimestampCredentials::new("Aladdin".to_owned(), "open sesame".to_owned())
            .map_err(str::to_owned)?;
        check(
            &credentials.authorization_header().as_str(),
            &"Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
            "RFC 7617 Basic header",
        )?;
        check_true(
            !format!("{credentials:?}").contains("Aladdin")
                && !format!("{credentials:?}").contains("sesame"),
            "credential debug output is redacted",
        )
    }

    #[test]
    fn timestamp_retry_uses_capped_exponential_backoff_until_success() {
        assert!(retry_transient_authority_failures(1));
        assert!(!retry_transient_authority_failures(2));
        let mut attempts = 0_u8;
        let mut delays = Vec::new();
        let token = retry_timestamp_query(
            || {
                attempts = attempts.saturating_add(1);
                if attempts <= 8 {
                    Err(crate::http::HttpError::HttpStatus {
                        code: 429,
                        reason: "Too Many Requests".to_owned(),
                        location: None,
                    })
                } else {
                    Ok("timestamp")
                }
            },
            |delay, _error| delays.push(delay),
        )
        .expect("a later attempt succeeds");
        assert_eq!(token, "timestamp");
        assert_eq!(attempts, 9);
        assert_eq!(
            delays,
            [1, 2, 4, 8, 16, 32, 60, 60].map(core::time::Duration::from_secs)
        );
    }

    #[test]
    fn timestamp_retry_does_not_repeat_authentication_failure() {
        let mut attempts = 0_u8;
        let error = retry_timestamp_query(
            || {
                attempts = attempts.saturating_add(1);
                Err::<(), _>(crate::http::HttpError::HttpStatus {
                    code: 401,
                    reason: "Unauthorized".to_owned(),
                    location: None,
                })
            },
            |_delay, _error| panic!("permanent failure must not wait"),
        )
        .expect_err("authentication failure is permanent");
        assert!(matches!(
            error,
            crate::http::HttpError::HttpStatus { code: 401, .. }
        ));
        assert_eq!(attempts, 1);
    }

    // ---- LocalVerifyOutcome: is_ok / is_failed keep "rejected"
    // and "not run" distinct, because the CLI maps only Failed to
    // a sign-flow failure. ----

    #[test]
    fn local_verify_predicates_separate_ok_failed_skipped() -> TestResult {
        check_true(LocalVerifyOutcome::Ok.is_ok(), "Ok.is_ok")?;
        check_true(!LocalVerifyOutcome::Ok.is_failed(), "Ok.is_failed")?;

        let failed = LocalVerifyOutcome::Failed("nope".to_owned());
        check_true(!failed.is_ok(), "Failed.is_ok")?;
        check_true(failed.is_failed(), "Failed.is_failed")?;

        let skipped = LocalVerifyOutcome::Skipped("ECDSA verify not wired");
        check_true(!skipped.is_ok(), "Skipped.is_ok")?;
        check_true(!skipped.is_failed(), "Skipped.is_failed")
    }

    #[test]
    fn local_verify_display() -> TestResult {
        check(&LocalVerifyOutcome::Ok.to_string(), &"ok".to_owned(), "ok")?;
        check(
            &LocalVerifyOutcome::Failed("bad sig".to_owned()).to_string(),
            &"FAILED: bad sig".to_owned(),
            "failed",
        )?;
        check(
            &LocalVerifyOutcome::Skipped("p384").to_string(),
            &"skipped (p384)".to_owned(),
            "skipped",
        )
    }

    #[test]
    fn archive_request_implies_lt_material_for_direct_api_callers() -> TestResult {
        let mut request = DocumentRequest {
            format: Format::Pades,
            additional_inputs: Vec::new(),
            signing_time: SigningTime {
                year: 2026,
                month: 8,
                day: 4,
                hour: 12,
                minute: 0,
                second: 0,
            },
            metadata: SignatureMetadata::default(),
            expected_serial: None,
            visible_signature: None,
            archive: true,
            long_term: false,
            timestamp_authorities: Vec::new(),
            timestamp_credentials: None,
        };
        check_true(
            request.requires_long_term_material(),
            "archive implies complete LT collection independently of CLI normalization",
        )?;
        check_true(
            request.validate_signing_policy().is_err(),
            "missing archive authority is rejected before card access",
        )?;
        request
            .timestamp_authorities
            .push("https://tsa.example/qualified".to_owned());
        check_true(
            request.validate_signing_policy().is_ok(),
            "archive with authority is normalized to LT",
        )?;
        request.timestamp_credentials = Some(
            TimestampCredentials::new("user".to_owned(), "password".to_owned())
                .map_err(str::to_owned)?,
        );
        check_true(
            request.validate_signing_policy().is_ok(),
            "one HTTPS authority may carry credentials",
        )?;
        request.timestamp_authorities[0] = "http://tsa.example/qualified".to_owned();
        check_true(
            request.validate_signing_policy().is_err(),
            "credential transport is rejected before card access",
        )?;
        request.timestamp_authorities[0] = "https://tsa.example/qualified".to_owned();
        request.timestamp_credentials = None;
        request.format = Format::Cades;
        check_true(
            matches!(
                request.validate_signing_policy(),
                Err(SignErrorKind::Document(DocumentError::ArchiveUnsupported))
            ),
            "unsupported archive format rejected before card access",
        )
    }

    #[test]
    fn signing_is_bound_to_the_displayed_card() -> TestResult {
        let displayed = TokenSerial::new("displayed-card".to_owned());
        let same = TokenSerial::new("displayed-card".to_owned());
        let replacement = TokenSerial::new("replacement-card".to_owned());
        ensure_expected_serial(&displayed, Some(&same))?;
        check_true(
            ensure_expected_serial(&displayed, Some(&replacement)).is_err(),
            "card swap is refused",
        )?;
        check_true(
            ensure_expected_serial(&displayed, None).is_err(),
            "missing live serial is refused",
        )
    }

    #[test]
    fn successful_archive_timestamp_is_included_in_reported_token_count() -> TestResult {
        check(
            &reported_timestamp_tokens(2, true),
            &3_usize,
            "two signature timestamps and one archive timestamp",
        )?;
        check(
            &reported_timestamp_tokens(2, false),
            &2_usize,
            "signature timestamps without archive",
        )
    }

    fn self_anchored_token_fixture() -> Result<VerifiedTimestampToken, Box<dyn core::error::Error>>
    {
        let signer_der = crate::trust_roots::PINNED_ROOT_DER
            .first()
            .map(|(_label, der)| *der)
            .ok_or("missing test trust anchor")?;
        let signer = OwnedCert::from_der(signer_der)?;
        let generated_at = signer.view().not_before;
        Ok(VerifiedTimestampToken {
            token: vec![1],
            signer_certificate: signer_der.to_vec(),
            embedded_certificates: vec![signer_der.to_vec()],
            generated_at,
        })
    }

    #[test]
    fn embedded_path_terminates_at_the_tokens_own_anchor() -> TestResult {
        let token = self_anchored_token_fixture()?;
        let path = embedded_timestamp_path(&token)?;
        check(
            &path,
            &vec![token.signer_certificate],
            "the embedded self-issued certificate terminates the path",
        )
    }

    #[test]
    fn archive_rejects_a_token_without_current_complete_evidence() -> TestResult {
        let token = self_anchored_token_fixture()?;
        let covered_material = ValidationMaterial {
            certificates: vec![token.signer_certificate.clone()],
            ..ValidationMaterial::default()
        };
        let error = authenticate_archive_timestamp_with(&token, &covered_material, |_token| {
            Err("current validation evidence unavailable".to_owned())
        })
        .err()
        .ok_or("archive token unexpectedly survived missing validation evidence")?;
        check(
            &error,
            &"current validation evidence unavailable".to_owned(),
            "archive evidence failure",
        )
    }

    #[test]
    fn archive_path_must_be_frozen_in_the_covered_lt_store() -> TestResult {
        let leaf = b"archive-tsa-leaf".to_vec();
        let identity = b"archive-tsa-service-identity".to_vec();
        let covered_material = ValidationMaterial {
            certificates: vec![leaf.clone(), identity.clone()],
            ..ValidationMaterial::default()
        };
        check(
            &require_archive_path_covered(&[leaf, identity.clone()], &covered_material),
            &Ok(()),
            "covered archive path",
        )?;

        let rotated = b"rotated-archive-tsa-leaf".to_vec();
        let error = require_archive_path_covered(&[rotated, identity], &covered_material)
            .err()
            .ok_or("rotated outer timestamp path unexpectedly passed LT coverage")?;
        check_true(
            error.contains("not byte-for-byte covered"),
            "rotated path is rejected",
        )
    }

    #[test]
    fn validation_material_merge_deduplicates_each_der_collection() -> TestResult {
        let mut material = ValidationMaterial {
            certificates: vec![vec![1]],
            ocsp_responses: vec![vec![2]],
            crls: vec![vec![3]],
        };
        merge_material(
            &mut material,
            ValidationMaterial {
                certificates: vec![vec![1], vec![4]],
                ocsp_responses: vec![vec![2], vec![5]],
                crls: vec![vec![3], vec![6]],
            },
        );
        check(
            &material,
            &ValidationMaterial {
                certificates: vec![vec![1], vec![4]],
                ocsp_responses: vec![vec![2], vec![5]],
                crls: vec![vec![3], vec![6]],
            },
            "merged material",
        )
    }

    #[test]
    fn live_timestamp_time_is_bounded_by_the_exchange() -> TestResult {
        let requested_at =
            DateTime::from_unix_duration(core::time::Duration::from_secs(1_700_000_000))?;
        let received_at =
            DateTime::from_unix_duration(core::time::Duration::from_secs(1_700_000_030))?;
        let token_at = |seconds| -> Result<VerifiedTimestampToken, Box<dyn core::error::Error>> {
            Ok(VerifiedTimestampToken {
                token: Vec::new(),
                signer_certificate: Vec::new(),
                embedded_certificates: Vec::new(),
                generated_at: DateTime::from_unix_duration(core::time::Duration::from_secs(
                    seconds,
                ))?,
            })
        };

        require_live_timestamp_time(&token_at(1_699_999_700)?, requested_at, received_at)?;
        require_live_timestamp_time(&token_at(1_700_000_330)?, requested_at, received_at)?;
        check_true(
            require_live_timestamp_time(&token_at(1_699_999_699)?, requested_at, received_at)
                .is_err(),
            "materially backdated token rejected",
        )?;
        check_true(
            require_live_timestamp_time(&token_at(1_700_000_331)?, requested_at, received_at)
                .is_err(),
            "future token rejected",
        )
    }

    #[test]
    #[ignore = "needs the live Sectigo qualified timestamp service"]
    fn live_sectigo_timestamp_response_verifies_directly() -> TestResult {
        let digest = DigestAlgorithm::Sha384.digest(b"ReFineID Sectigo interoperability probe");
        let token = request_token(
            "http://timestamp.sectigo.com/qualified",
            None,
            false,
            &digest,
            DigestAlgorithm::Sha384,
        )?;
        check_true(!token.token.is_empty(), "timestamp token returned")?;
        check_true(
            !token.signer_certificate.is_empty(),
            "timestamp signer certificate authenticated",
        )?;
        check_true(
            token.embedded_certificates.len() >= 2,
            "timestamp signer chain retained",
        )?;
        let path = embedded_timestamp_path(&token)?;
        check_true(!path.is_empty(), "timestamp path verified")?;
        let material = timestamp_validation_material(&token)?;
        check_true(
            !material.certificates.is_empty(),
            "timestamp path and LT evidence collected",
        )
    }

    #[test]
    #[ignore = "needs live timestamp authorities and revocation services"]
    fn live_qualified_timestamp_and_lt_evidence_probe() -> TestResult {
        let digest = [0_u8; 32];
        let mut successes = 0_usize;
        let mut failures = Vec::new();
        for url in [
            "https://timestamp.aped.gov.gr/qtss",
            "http://tss.accv.es:8318/tsa",
        ] {
            let token = match request_token(url, None, false, &digest, DigestAlgorithm::Sha256) {
                Ok(token) => token,
                Err(error) => {
                    failures.push(format!("{url}: {error}"));
                    continue;
                }
            };
            if let Err(error) = embedded_timestamp_path(&token) {
                failures.push(format!("{url}: path: {error}"));
                continue;
            }
            match timestamp_validation_material(&token) {
                Ok(material) if !material.certificates.is_empty() => {
                    successes = successes.saturating_add(1);
                }
                Ok(_empty) => failures.push(format!("{url}: LT material was empty")),
                Err(error) => failures.push(format!("{url}: LT evidence: {error}")),
            }
        }
        for failure in &failures {
            eprintln!("{failure}");
        }
        check_true(
            successes > 0,
            "at least one configured authority produced a token with complete LT evidence",
        )
    }

    // ---- SignErrorKind Display: each arm renders an
    // operator-facing line; the PIN arms also pivot on the slot
    // label and the VerifyOutcome shape. ----

    fn pin_retries(n: u8) -> Result<PinRetries, Box<dyn core::error::Error>> {
        PinRetries::from_nibble(n).ok_or_else(|| "bad nibble".into())
    }

    #[test]
    fn pin_rejected_display_renders_slot_and_outcome() -> TestResult {
        let wrong = SignErrorKind::PinRejected {
            slot: SignSlot::Auth,
            outcome: VerifyOutcome::WrongPin {
                retries_left: pin_retries(2)?,
            },
        }
        .to_string();
        check_true(wrong.contains("PIN1"), "wrong-pin slot label")?;
        check_true(wrong.contains("wrong PIN"), "wrong-pin reason")?;
        check_true(wrong.contains("retries left"), "wrong-pin counter")?;

        let locked = SignErrorKind::PinRejected {
            slot: SignSlot::Qualified,
            outcome: VerifyOutcome::Locked,
        }
        .to_string();
        check_true(locked.contains("PIN2"), "locked slot label")?;
        check_true(locked.contains("blocked"), "locked reason")?;

        let other = SignErrorKind::PinRejected {
            slot: SignSlot::Auth,
            outcome: VerifyOutcome::Other(0x6A88),
        }
        .to_string();
        check_true(other.contains("0x6A88"), "other sw rendered")?;

        // The internal "can't happen" arm still renders a line
        // rather than panicking.
        let internal = SignErrorKind::PinRejected {
            slot: SignSlot::Auth,
            outcome: VerifyOutcome::Ok,
        }
        .to_string();
        check_true(internal.contains("internal"), "ok-outcome guard")
    }

    #[test]
    fn sign_chain_and_crypto_error_display() -> TestResult {
        check_true(
            SignErrorKind::PinPolicy {
                slot: SignSlot::Auth,
                reason: PinPolicyReason::NonDigit { byte_offset: 1 },
            }
            .to_string()
            .contains("PIN1 rejected locally"),
            "pin policy",
        )?;
        check_true(
            SignErrorKind::SignSw {
                stage: "PSO:HASH",
                sw: 0x6A80,
            }
            .to_string()
            .contains("PSO:HASH: SW=0x6A80"),
            "sign sw stage + sw",
        )?;
        check_true(
            SignErrorKind::UnexpectedSignatureLength(256)
                .to_string()
                .contains("256-byte signature; expected 384"),
            "bad sig length",
        )?;
        check_true(
            SignErrorKind::CertUnavailable {
                slot: SignSlot::Auth,
                detail: "read: timeout".to_owned(),
            }
            .to_string()
            .contains("auth cert unavailable for local verify: read: timeout"),
            "cert unavailable",
        )?;
        check_true(
            SignErrorKind::UnsupportedKeyType(SignSlot::Qualified)
                .to_string()
                .contains("qualified-signature cert has an unsupported key type"),
            "unsupported key type",
        )?;
        check_true(
            SignErrorKind::UnsupportedCurve {
                slot: SignSlot::Auth,
                curve: EcCurve::Secp256r1,
            }
            .to_string()
            .contains("only signs ECDSA on secp384r1"),
            "unsupported curve",
        )?;
        check_true(
            SignErrorKind::LocalVerifyFailed("digest mismatch".to_owned())
                .to_string()
                .contains("local verify failed: digest mismatch"),
            "local verify failed",
        )?;
        check_true(
            SignErrorKind::Transport("reader vanished".to_owned())
                .to_string()
                .contains("transport: reader vanished"),
            "transport",
        )
    }

    #[test]
    fn io_error_display_includes_path() -> TestResult {
        let err = SignErrorKind::InputRead {
            path: PathBuf::from("/tmp/msg"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"),
        };
        let s = err.to_string();
        check_true(s.contains("/tmp/msg"), "io error path")?;
        check_true(s.contains("no such file"), "io error source")
    }

    // ---- sign_err_to_kind: lib-core SignError -> client
    // SignErrorKind, shared by the RSA and ECDSA branches. ----

    #[test]
    fn sign_err_to_kind_maps_each_variant() -> TestResult {
        check_true(
            matches!(
                sign_err_to_kind(SignError::<&str>::Transport("boom")),
                SignErrorKind::Transport(_)
            ),
            "transport",
        )?;
        check_true(
            matches!(
                sign_err_to_kind(SignError::<&str>::Sw("PSO:CDS", 0x6982)),
                SignErrorKind::SignSw {
                    stage: "PSO:CDS",
                    sw: 0x6982
                }
            ),
            "sw",
        )?;
        check_true(
            matches!(
                sign_err_to_kind(SignError::<&str>::UnexpectedSignatureLength(48)),
                SignErrorKind::UnexpectedSignatureLength(48)
            ),
            "unexpected length",
        )
    }

    // ---- SignReport Display ----

    fn sample_report(cn: Option<CommonName>) -> SignReport {
        SignReport {
            reader: "OMNIKEY 5422".to_owned(),
            slot: SignSlot::Auth,
            input_len: 11,
            input_sha256: Sha256::of(b"hello world"),
            signature_path: PathBuf::from("/tmp/out.sig"),
            cert_path: Some(PathBuf::from("/tmp/out.crt")),
            signature_len: 384,
            timestamps: 0,
            output_len: 384,
            cert_subject_cn: cn,
            pin_retries_after: None,
            local_verify: LocalVerifyOutcome::Ok,
        }
    }

    #[test]
    fn sign_report_display_renders_all_present_fields() -> TestResult {
        // Pull a real CommonName off a bundled cert rather than
        // constructing one (the field is private to lib-core).
        let cert = OwnedCert::from_der(
            include_bytes!("../trust-anchors/dvv-gov-root-ca-g3-rsa.der").as_slice(),
        )
        .map_err(|e| format!("parse anchor: {e}"))?;
        let cn = cert.view().subject.common_name();
        check_true(cn.is_some(), "anchor has a CN")?;

        let s = sample_report(cn).to_string();
        check_true(s.contains("reader: OMNIKEY 5422"), "reader line")?;
        check_true(
            s.contains("slot: auth (key ref 0x01)"),
            "slot line with key ref",
        )?;
        check_true(s.contains("cert subject CN: DVV"), "subject cn line")?;
        check_true(s.contains("input length: 11 bytes"), "input length")?;
        check_true(s.contains("input sha256: "), "input sha256")?;
        check_true(
            s.contains("output: /tmp/out.sig (384 bytes)"),
            "output line",
        )?;
        check_true(
            s.contains("card signature: 384 bytes"),
            "card signature line",
        )?;
        check_true(s.contains("cert DER: /tmp/out.crt"), "cert der line")?;
        check_true(
            s.contains("local verify (against on-card auth cert pubkey): ok"),
            "local verify line",
        )
    }

    #[test]
    fn sign_report_labels_timestamp_tokens_without_calling_them_authorities() -> TestResult {
        let mut report = sample_report(None);
        report.timestamps = 2;
        let rendered = report.to_string();
        check_true(
            rendered.contains("timestamp tokens obtained: 2"),
            "inner and archive token count",
        )?;
        check_true(
            !rendered.contains("timestamp authorities"),
            "token count is not mislabeled as distinct authorities",
        )
    }

    #[test]
    fn sign_report_display_omits_absent_optionals() -> TestResult {
        // No CN, no saved cert, no retry counter -> those lines
        // are skipped entirely.
        let s = sample_report(None).to_string();
        check_true(!s.contains("cert subject CN:"), "no cn line")?;
        // cert_path is Some in sample_report; flip it for this case.
        let mut report = sample_report(None);
        report.cert_path = None;
        let s2 = report.to_string();
        check_true(!s2.contains("cert DER:"), "no cert der line")?;
        check_true(!s2.contains("retries after verify"), "no retry line")
    }
}
