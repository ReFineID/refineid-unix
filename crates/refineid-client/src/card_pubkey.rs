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

//! `refineid card pubkey`: read an on-card cert and emit its
//! public key in a portable text format.
//!
//! Two output formats:
//! - `ssh`: OpenSSH wire format -- `ssh-rsa BASE64 comment\n`.
//!   Drop this into `~/.ssh/authorized_keys` to use the card as
//!   an SSH identity (when a matching PKCS#11 agent is loaded).
//! - `pem`: PEM-wrapped `SubjectPublicKeyInfo` DER. The familiar
//!   `-----BEGIN PUBLIC KEY-----` block that openssl / Python /
//!   most TLS libs accept directly.
//!
//! No PIN is needed: cert + pubkey are card-public.

use alloc::fmt;
use std::path::PathBuf;

/// Helpers hosted on a unit struct (typing-discipline: no
/// free fns with borrowed parameters; see
/// `doc/typing-discipline.md`).
struct CardPubkeyHelpers;

use refineid_lib_core::backend::{ReaderAccessCap, ReaderBackend as _, ReaderId};
use refineid_lib_core::crypto::ecdsa::Sec1UncompressedPoint;
use refineid_lib_core::crypto::rsa::RsaPublicKey;
use refineid_lib_core::identity::{CredentialIdentity, derive_printed_serial, render_token_serial};
use refineid_lib_core::pkcs15::CertSlot;
use refineid_lib_core::pkcs15::Pkcs15Ops as _;
use refineid_lib_core::x509::{EcCurve, OwnedCert, PublicKeyAlgorithm, extract_rsa_public_key};
use refineid_lib_pcsc::{PcscBackend, PcscError};

/// SSH key-line comment: the optional free text that appears
/// after the base64 key on an `authorized_keys` entry, e.g.
/// `ssh-rsa AAAA... comment-here`. Constructor validates:
///
/// - no embedded newline (CR or LF) -- would break the
///   one-key-per-line `authorized_keys` format;
/// - length cap of [`SshComment::MAX_BYTES`] bytes -- OpenSSH
///   doesn't fix a hard limit but very long comments are
///   pathological;
/// - UTF-8 already-guaranteed by `String`.
///
/// `as_str()` returns the validated text for emission. An empty
/// comment is allowed (no text after the key); it's distinct
/// from `None` at the call site (some emitters omit the
/// trailing space entirely when the comment is empty).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshComment(String);

/// Reason an SSH comment string was rejected at construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshCommentError {
    /// Comment contains an embedded LF (0x0A) or CR (0x0D); would
    /// break the one-line-per-key `authorized_keys` format
    /// (OpenSSH sshd(8)).
    EmbeddedNewline,
    /// Comment exceeds [`SshComment::MAX_BYTES`].
    TooLong {
        /// Length of the would-be comment in UTF-8 bytes.
        /// Tier 0 `usize` -- arithmetic count.
        bytes: usize,
        /// The cap that was breached (mirrors
        /// [`SshComment::MAX_BYTES`] at the time of construction).
        max: usize,
    },
}

impl fmt::Display for SshCommentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmbeddedNewline => write!(
                f,
                "SSH comment: contains LF / CR; would break authorized_keys line format"
            ),
            Self::TooLong { bytes, max } => {
                write!(f, "SSH comment: {bytes} bytes, max is {max}")
            }
        }
    }
}

impl core::error::Error for SshCommentError {}

impl SshComment {
    /// 1024 bytes -- well above any sensible human-readable
    /// comment (typical PKCS#11 / FINEID comments are around 60
    /// bytes); the cap exists to bound work in path-length-
    /// sensitive code paths.
    pub const MAX_BYTES: usize = 1024;

    /// Borrow the validated comment text for emission. Guaranteed
    /// to be LF/CR-free and within `MAX_BYTES`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `true` when the comment carries no characters (the key
    /// line emits the trailing space-comment block omitted).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Boundary parser: build [`SshComment`] from an owned
/// `String`. Validates no embedded LF/CR and the length cap.
impl TryFrom<String> for SshComment {
    type Error = SshCommentError;
    fn try_from(s: String) -> Result<Self, SshCommentError> {
        if s.len() > Self::MAX_BYTES {
            return Err(SshCommentError::TooLong {
                bytes: s.len(),
                max: Self::MAX_BYTES,
            });
        }
        if s.bytes().any(|b| b == b'\n' || b == b'\r') {
            return Err(SshCommentError::EmbeddedNewline);
        }
        Ok(Self(s))
    }
}

/// Which on-card cert slot to read the pubkey from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PubkeySlot {
    /// Authentication slot (EF.4331 per FINEID S1 v4.2 §3.1).
    Auth,
    /// Non-repudiation / qualified-signature slot (EF.4332 per
    /// FINEID S1 v4.2 §3.1).
    Qualified,
}

impl PubkeySlot {
    /// Project to the lib-core [`CertSlot`] used to address the
    /// EF.4331 / EF.4332 PKCS#15 cert file.
    #[must_use]
    pub const fn cert_slot(self) -> CertSlot {
        match self {
            Self::Auth => CertSlot::Authentication,
            Self::Qualified => CertSlot::Signature,
        }
    }
    /// User-facing label ("auth" / "qualified-signature") used
    /// in CLI reports and error messages.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Qualified => "qualified-signature",
        }
    }
}

/// Output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PubkeyFormat {
    /// OpenSSH wire format -- `ssh-rsa BASE64 comment\n`.
    Ssh,
    /// PEM `SubjectPublicKeyInfo`.
    Pem,
}

/// Inputs.
#[derive(Debug, Clone)]
pub struct PubkeyOptions {
    /// Which slot's cert to read the pubkey from.
    pub slot: PubkeySlot,
    /// Output encoding (OpenSSH wire line vs PEM SPKI).
    pub format: PubkeyFormat,
    /// Optional output path. When `None`, the result is written
    /// to stdout via the [`fmt::Display`] impl on
    /// [`PubkeyReport`]. With multiple cards, every block is
    /// concatenated into the same file.
    pub output: Option<PathBuf>,
    /// Optional substring match against reader names. `None`
    /// processes every reader with a card present; `Some("ACS")`
    /// would target only the ACS reader.
    pub reader_filter: Option<String>,
    /// SSH comment text. `None` -> auto-build as the
    /// `CredentialIdentity::to_ssh_comment` form:
    /// `<surname> <given_names> <peuin>
    /// <plastic-printed card serial>`. Matches the existing
    /// PKCS#11-tooling convention of person-first comments so
    /// any tool grepping on the CN still works, extended with
    /// the printed card identifier (so a person's two cards
    /// are distinguishable in `authorized_keys` even by a
    /// reader who only has the physical card in hand). The
    /// long chip-side PKCS#15 serial is deliberately excluded
    /// from the auto-built comment -- it isn't cross-referable
    /// against anything a remote reader has access to.
    /// `Some("")` -> emit no comment. `Some(s)` -> emit `s`
    /// literally.
    pub comment: Option<String>,
}

/// One reader's worth of pubkey export.
#[derive(Debug, Clone)]
pub struct PubkeyReport {
    /// PC/SC reader name the cert was read from. Tier 0 `String`
    /// from `ReaderId::as_str().to_owned()`.
    pub reader: String,
    /// Which slot the cert came from (auth / qualified).
    pub slot: PubkeySlot,
    /// Encoding format the `encoded` string uses.
    pub format: PubkeyFormat,
    /// Cert subject CN, used as the SSH key comment when present.
    pub subject_cn: Option<refineid_lib_core::identity::CommonName>,
    /// The encoded pubkey -- either a single ssh-rsa line or a
    /// PEM block, both terminated with a trailing newline.
    pub encoded: String,
    /// Where the encoded pubkey was written, when `output` was
    /// set.
    pub output_path: Option<PathBuf>,
}

/// Error returned from the pubkey export entrypoint.
#[derive(Debug)]
pub enum PubkeyError {
    /// PC/SC reported zero connected readers.
    NoReaders,
    /// At least one reader is connected but none has a card
    /// present.
    NoCardPresent,
    /// `--reader SUBSTR` was given but didn't match any
    /// connected reader.
    NoMatchingReader {
        /// The filter string supplied on the command line.
        /// Tier 0 `String`; presentational.
        filter: String,
        /// Connected-reader names presented back to the operator
        /// so they can correct the filter. Tier 0 `Vec<String>`
        /// from `ReaderId::as_str()`; presentational.
        available: Vec<String>,
    },
    /// PC/SC connect / transmit error.
    Pcsc(PcscError),
    /// `SELECT PKCS#15 application` failed. Tier 0 `String`;
    /// presentational copy of the upstream error.
    Pkcs15Select(String),
    /// Cert in the targeted slot couldn't be read or parsed.
    CertUnavailable {
        /// Which slot the cert read targeted.
        slot: PubkeySlot,
        /// Human-readable detail from the cert reader / parser.
        /// Tier 0 `String`; presentational.
        detail: String,
    },
    /// The cert's public key is on a curve / algorithm OpenSSH
    /// doesn't natively wire (e.g. brainpoolP384r1). PEM-SPKI
    /// works for any cert; only the SSH path has this limit.
    SshUnsupportedKey {
        /// Which slot the cert came from.
        slot: PubkeySlot,
        /// Human-readable detail naming the unsupported algorithm
        /// / curve. Tier 0 `String`; presentational.
        detail: String,
    },
    /// Output file write failed.
    Write {
        /// Filesystem path the write was attempted against.
        path: PathBuf,
        /// Underlying `std::io::Error`.
        source: std::io::Error,
    },
}

impl fmt::Display for PubkeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoReaders => write!(f, "no PC/SC readers connected"),
            Self::NoCardPresent => write!(f, "no card present in any reader"),
            Self::NoMatchingReader { filter, available } => write!(
                f,
                "no reader matched --reader {filter:?}; connected readers: [{}]",
                available.join(", ")
            ),
            Self::Pcsc(e) => write!(f, "PC/SC: {e}"),
            Self::Pkcs15Select(s) => write!(f, "SELECT PKCS#15 app: {s}"),
            Self::CertUnavailable { slot, detail } => {
                write!(f, "{} cert unavailable: {detail}", slot.label())
            }
            Self::SshUnsupportedKey { slot, detail } => write!(
                f,
                "{} cert: SSH wire format unavailable ({detail}); try --format pem",
                slot.label()
            ),
            Self::Write { path, source } => write!(f, "write {}: {source}", path.display()),
        }
    }
}

impl core::error::Error for PubkeyError {}

impl From<PcscError> for PubkeyError {
    fn from(e: PcscError) -> Self {
        Self::Pcsc(e)
    }
}

/// Read the cert in `options.slot` from every reader with a
/// card present (filtered by `options.reader_filter` when set)
/// and emit one [`PubkeyReport`] per card.
///
/// When `options.output` is set, every block is concatenated
/// into the same file in reader order. When unset, the CLI
/// renders each report to stdout in turn.
///
/// # Errors
/// PC/SC enumeration / connect failure, PKCS#15 / cert-read /
/// parse / I/O failures on any reader. The first failure aborts
/// the whole walk -- partial results aren't returned, so a bad
/// card doesn't silently skip past a key the user wanted.
pub(crate) fn pubkey_all(
    backend: PcscBackend,
    options: &PubkeyOptions,
) -> Result<Vec<PubkeyReport>, PubkeyError> {
    let readers = backend.enumerate()?;
    if readers.is_empty() {
        return Err(PubkeyError::NoReaders);
    }
    let present: Vec<_> = readers.into_iter().filter(|r| r.card_present).collect();
    if present.is_empty() {
        return Err(PubkeyError::NoCardPresent);
    }
    let targeted: Vec<_> = match &options.reader_filter {
        Some(filter) => {
            let matched: Vec<_> = present
                .iter()
                .filter(|r| r.id.as_str().contains(filter.as_str()))
                .cloned()
                .collect();
            if matched.is_empty() {
                return Err(PubkeyError::NoMatchingReader {
                    filter: filter.clone(),
                    available: present.iter().map(|r| r.id.as_str().to_owned()).collect(),
                });
            }
            matched
        }
        None => present,
    };

    let mut reports = Vec::with_capacity(targeted.len());
    for info in targeted {
        reports.push(pubkey_one(backend, &info.id, options)?);
    }

    // When --out is set with multiple cards, concatenate every
    // block into the same file in reader order. Each report
    // still carries the same `output_path` so the CLI's display
    // logic stays uniform; the actual write happens once here.
    if let Some(path) = &options.output {
        let mut buf = String::new();
        for r in &reports {
            buf.push_str(&r.encoded);
        }
        std::fs::write(path, buf.as_bytes()).map_err(|source| PubkeyError::Write {
            path: path.clone(),
            source,
        })?;
    }
    Ok(reports)
}

/// Single-reader building block for [`pubkey_all`]. Same
/// `PcscBackend` shape as the other entry points in this
/// crate.
fn pubkey_one(
    backend: PcscBackend,
    reader_id: &ReaderId,
    options: &PubkeyOptions,
) -> Result<PubkeyReport, PubkeyError> {
    let mut transport = backend.open_session(reader_id, ReaderAccessCap::Read)?;
    transport
        .select_pkcs15_application()
        .map_err(|e| PubkeyError::Pkcs15Select(format!("{e}")))?;

    let cert_der = transport
        .read_certificate(options.slot.cert_slot())
        .map_err(|e| PubkeyError::CertUnavailable {
            slot: options.slot,
            detail: format!("read: {e}"),
        })?;
    let cert_owned =
        OwnedCert::from_der(cert_der.as_bytes()).map_err(|e| PubkeyError::CertUnavailable {
            slot: options.slot,
            detail: format!("parse: {e}"),
        })?;
    let cert = cert_owned.view();
    // Subject identity: read structured DN attributes directly
    // (no CN-splitting heuristic, so multi-word surnames work).
    // Subject CN is kept too for the report's human header.
    let subject_cn = cert.subject.common_name();
    // Token serial: read EF.TokenInfo and surface both the full
    // PKCS#15 form and the plastic-printed form. derive_printed_*
    // recognises v3.1 and v4.0+ chip-serial layouts by shape;
    // None when the input doesn't match a known generation.
    // The full chip serial is computed only to derive the
    // printed form; `CredentialIdentity` no longer carries
    // the full form (that's session-binding state, not
    // person identity).
    let token_full = transport
        .read_token_info()
        .ok()
        .and_then(|t| t.serial_number_hex)
        .map(render_token_serial);
    let printed_serial = token_full.as_ref().and_then(derive_printed_serial);
    let given_names = cert.subject.given_names();
    let mut identity = CredentialIdentity::new();
    if let Some(s) = cert.subject.surname() {
        identity = identity.with_surname(s);
    }
    if let Some(n) = given_names.first {
        identity = identity.with_first_name(n);
    }
    if let Some(n) = given_names.second {
        identity = identity.with_second_name(n);
    }
    identity = identity.with_additional_names(given_names.additional);
    if let Some(p) = cert.subject.peuin() {
        identity = identity.with_peuin(p);
    }
    // date_of_birth -- future eMRTD DG1 source.
    if let Some(s) = printed_serial {
        identity = identity.with_printed_serial(s);
    }

    // Comment: caller-supplied override wins. Default is the
    // SSH-comment-specific render -- printed serial only, never
    // the long chip-side form. An SSH public key in
    // authorized_keys travels publicly to readers who can only
    // see the plastic-printed card identifier; the full chip
    // serial is unrecognisable to them and just noise. When the
    // printed form isn't derivable, the serial is omitted from
    // the comment entirely (name + PEUIN still uniquely
    // identifies the credential holder).
    let comment_str = options
        .comment
        .as_ref()
        .map_or_else(|| identity.to_ssh_comment(), String::clone);
    let comment: SshComment =
        comment_str
            .try_into()
            .map_err(|e: SshCommentError| PubkeyError::SshUnsupportedKey {
                slot: options.slot,
                detail: format!("comment rejected: {e}"),
            })?;
    let encoded = match options.format {
        PubkeyFormat::Pem => CardPubkeyHelpers::encode_pem_spki(&cert.spki),
        PubkeyFormat::Ssh => CardPubkeyHelpers::encode_ssh(options.slot, &cert.spki, &comment)?,
    };

    Ok(PubkeyReport {
        reader: reader_id.as_str().to_owned(),
        slot: options.slot,
        format: options.format,
        subject_cn,
        encoded,
        // The shared --out write happens in pubkey_all; this
        // field just mirrors what the user passed so the
        // display path can show it.
        output_path: options.output.clone(),
    })
}

impl fmt::Display for PubkeyReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(p) = &self.output_path {
            writeln!(f, "reader: {}", self.reader)?;
            writeln!(f, "slot: {}", self.slot.label())?;
            if let Some(cn) = &self.subject_cn {
                writeln!(f, "subject CN: {cn}")?;
            }
            writeln!(
                f,
                "format: {}",
                match self.format {
                    PubkeyFormat::Ssh => "openssh (ssh-rsa)",
                    PubkeyFormat::Pem => "PEM SubjectPublicKeyInfo",
                }
            )?;
            writeln!(f, "wrote: {}", p.display())?;
        } else {
            // No output path: print the encoded pubkey itself so
            // the user can pipe / redirect.
            f.write_str(&self.encoded)?;
        }
        Ok(())
    }
}

impl CardPubkeyHelpers {
    /// Render an X.509 `SubjectPublicKeyInfo` as a textual PEM
    /// `-----BEGIN PUBLIC KEY-----` block (RFC 7468 §13).
    ///
    /// Body wraps at 64 characters per RFC 7468 §2; our
    /// base64 alphabet is the standard `+/` set with `=`
    /// padding. The encoder is allocation-conscious but not
    /// constant-time -- this is public-key material, no side-
    /// channel concern.
    fn encode_pem_spki(spki: &refineid_lib_core::x509::SpkiDer<'_>) -> String {
        /// PEM body wraps every 64 characters per RFC 7468 §2
        /// "generators MAY wrap at a max of 64".
        const PEM_LINE_WIDTH: usize = 64;
        let b64 = Self::base64_encode(spki.as_der());
        // base64_encode emits one byte per char from a fixed ASCII
        // alphabet (RFC 4648 + '=' padding); every byte index is
        // a char boundary, so `&str`-slice operations are safe.
        let mut out = String::with_capacity(b64.len().saturating_add(PEM_LINE_WIDTH));
        out.push_str("-----BEGIN PUBLIC KEY-----\n");
        let mut start: usize = 0;
        while let Some(end) = start.checked_add(PEM_LINE_WIDTH)
            && let Some(chunk) = b64.get(start..end)
        {
            out.push_str(chunk);
            out.push('\n');
            start = end;
        }
        if let Some(tail) = b64.get(start..)
            && !tail.is_empty()
        {
            out.push_str(tail);
            out.push('\n');
        }
        out.push_str("-----END PUBLIC KEY-----\n");
        out
    }
}

/// Dispatch the SPKI to the appropriate OpenSSH wire format.
/// RSA -> ssh-rsa, EC P-256/P-384 -> ecdsa-sha2-nistp{256,384}.
/// Anything else (brainpool, explicit-curve, unrecognised) is
/// rejected with [`PubkeyError::SshUnsupportedKey`]; the user
/// can fall back to `--format pem` which works for any SPKI.
impl CardPubkeyHelpers {
    /// Dispatch an SPKI to its OpenSSH wire format
    /// (`ssh-rsa` / `ecdsa-sha2-nistp{256,384}`).
    ///
    /// RFC 4253 §6.6 (RSA), RFC 5656 §3.1 (ECDSA).
    /// brainpoolP* and explicit-parameter curves have no
    /// OpenSSH wire format and are rejected with
    /// [`PubkeyError::SshUnsupportedKey`]; callers can fall
    /// back to PEM-SPKI which works for any key.
    fn encode_ssh(
        slot: PubkeySlot,
        spki: &refineid_lib_core::x509::SpkiDer<'_>,
        comment: &SshComment,
    ) -> Result<String, PubkeyError> {
        let spki_der = spki.as_der();
        if let Some(rsa) = extract_rsa_public_key(spki_der) {
            return Ok(Self::encode_ssh_rsa(&rsa, comment));
        }
        match spki.algorithm() {
            PublicKeyAlgorithm::Ec(curve @ (EcCurve::Secp256r1 | EcCurve::Secp384r1)) => {
                let q =
                    spki.ec_public_key_point()
                        .ok_or_else(|| PubkeyError::SshUnsupportedKey {
                            slot,
                            detail:
                                "EC SPKI is missing the public point or isn't SEC1-uncompressed"
                                    .to_owned(),
                        })?;
                Ok(Self::encode_ssh_ecdsa(curve, &q, comment))
            }
            PublicKeyAlgorithm::Ec(EcCurve::BrainpoolP256r1 | EcCurve::BrainpoolP384r1) => {
                Err(PubkeyError::SshUnsupportedKey {
                    slot,
                    detail: "OpenSSH has no standard wire format for brainpoolP* curves".to_owned(),
                })
            }
            PublicKeyAlgorithm::Ec(EcCurve::Other) => Err(PubkeyError::SshUnsupportedKey {
                slot,
                detail: "unrecognised EC named curve".to_owned(),
            }),
            PublicKeyAlgorithm::EcExplicit { .. } => Err(PubkeyError::SshUnsupportedKey {
                slot,
                detail: "EC with explicit parameters -- OpenSSH only wires named curves".to_owned(),
            }),
            PublicKeyAlgorithm::Rsa { .. } | PublicKeyAlgorithm::Other => {
                // RSA case was caught above by extract_rsa_public_key
                // returning Some; Other shouldn't have come this far
                // since the SPKI parsed.
                Err(PubkeyError::SshUnsupportedKey {
                    slot,
                    detail: "no SSH wire mapping for this SPKI".to_owned(),
                })
            }
        }
    }
}

impl CardPubkeyHelpers {
    /// Render an RSA public key as the OpenSSH `ssh-rsa` line.
    ///
    /// RFC 4253 §6.6. Wire body is `string "ssh-rsa" || mpint e
    /// || mpint n`; output line is base64'd body + optional
    /// comment. Comment is omitted when empty so the line
    /// matches OpenSSH's `authorized_keys` grammar.
    fn encode_ssh_rsa(key: &RsaPublicKey, comment: &SshComment) -> String {
        let mut blob = Vec::new();
        Self::ssh_write_string(&mut blob, b"ssh-rsa");
        Self::ssh_write_mpint(&mut blob, key.exponent.as_bytes());
        Self::ssh_write_mpint(&mut blob, key.modulus.as_bytes());
        let b64 = Self::base64_encode(&blob);
        if comment.is_empty() {
            format!("ssh-rsa {b64}\n")
        } else {
            format!("ssh-rsa {b64} {}\n", comment.as_str())
        }
    }
}

/// OpenSSH ECDSA wire format per RFC 5656 §3.1:
///
/// ```text
///   string   "ecdsa-sha2-nistp{256,384,521}"
///   string   "nistp{256,384,521}"   (the curve identifier)
///   string   Q                       (SEC1 uncompressed point)
/// ```
///
/// FINEID cards we've seen ship P-256 / P-384 keys (the new
/// G4E chain is P-384). brainpoolP* + explicit-params curves
/// reject upstream in `encode_ssh`.
impl CardPubkeyHelpers {
    /// Render an EC named-curve public key as the OpenSSH
    /// `ecdsa-sha2-nistp{256,384}` line.
    ///
    /// RFC 5656 §3.1. `point` is SEC1 uncompressed (`04 || X
    /// || Y`). The `unreachable!` arm guards against an
    /// upstream filter regression -- the caller
    /// (`encode_ssh`) only forwards Secp256r1 / Secp384r1
    /// here.
    fn encode_ssh_ecdsa(
        curve: EcCurve,
        point: &Sec1UncompressedPoint,
        comment: &SshComment,
    ) -> String {
        let (key_type, curve_name) = match curve {
            EcCurve::Secp256r1 => ("ecdsa-sha2-nistp256", "nistp256"),
            EcCurve::Secp384r1 => ("ecdsa-sha2-nistp384", "nistp384"),
            // Caller filters everything else.
            EcCurve::BrainpoolP256r1 | EcCurve::BrainpoolP384r1 | EcCurve::Other => {
                unreachable!("encode_ssh_ecdsa: unsupported curve {curve:?}")
            }
        };
        let mut blob = Vec::new();
        Self::ssh_write_string(&mut blob, key_type.as_bytes());
        Self::ssh_write_string(&mut blob, curve_name.as_bytes());
        Self::ssh_write_string(&mut blob, point.as_bytes());
        let b64 = Self::base64_encode(&blob);
        if comment.is_empty() {
            format!("{key_type} {b64}\n")
        } else {
            format!("{key_type} {b64} {}\n", comment.as_str())
        }
    }
}

impl CardPubkeyHelpers {
    /// Append an SSH wire-format `string` (`u32 length || bytes`)
    /// to `out`.
    ///
    /// RFC 4251 §5. The length is BE u32; refineid's call
    /// sites pass short tags (ssh-rsa name, curve name, EC
    /// point) all well under `u32::MAX`. The `expect`
    /// documents that bound, not a runtime check.
    fn ssh_write_string(out: &mut Vec<u8>, s: &[u8]) {
        // Callers pass: ssh-rsa/ecdsa-sha2-nistp* key-type tags
        // (<= 32 bytes), the matching curve-name tag (<= 16 bytes),
        // or a SEC1 uncompressed point (<= 1 + 2 * 66 = 133 bytes
        // even for secp521r1). All far below u32::MAX.
        #[expect(
            clippy::expect_used,
            reason = "ssh wire string length is bounded above by RSA modulus / curve point bytes; never anywhere near u32::MAX"
        )]
        let len_u32 = u32::try_from(s.len()).expect("ssh string fits in u32 length");
        out.extend_from_slice(&len_u32.to_be_bytes());
        out.extend_from_slice(s);
    }
}

/// SSH `mpint` per RFC 4251 §5: length-prefixed big-endian.
/// Positive integers whose MSB is set get a leading zero byte so
/// the value isn't sign-extended into a negative.
impl CardPubkeyHelpers {
    /// Append an SSH wire-format `mpint` (RFC 4251 §5) to
    /// `out`.
    ///
    /// `mpint` is a length-prefixed positive integer in
    /// big-endian. Leading `0x00` bytes are stripped first
    /// (defence-in-depth -- callers should already supply
    /// magnitude bytes), then a single `0x00` is prepended
    /// when the high bit would otherwise make the value
    /// negative.
    fn ssh_write_mpint(out: &mut Vec<u8>, value: &[u8]) {
        // SSH mpint (RFC 4251 §5): the integer in minimal-length
        // big-endian, with a single 0x00 re-added below if the MSB
        // is set (to keep it non-negative). Stripping leading zero
        // bytes to reach minimal form is part of the encoding --
        // this encoder canonicalises whatever integer it is handed,
        // it does not "re-check" a caller.
        const LEADING_ZERO_BYTE: u8 = 0;
        let mut trimmed = value;
        while let Some((&first, rest)) = trimmed.split_first()
            && first == LEADING_ZERO_BYTE
            && !rest.is_empty()
        {
            trimmed = rest;
        }
        let needs_pad = trimmed.first().is_some_and(|&b| b & 0x80 != 0);
        let len = if needs_pad {
            trimmed.len().saturating_add(1)
        } else {
            trimmed.len()
        };
        // RSA modulus bytes (<= 512 for RSA-4096) or EC scalar bytes
        // (<= 66 for secp521r1) -- well below u32::MAX.
        #[expect(
            clippy::expect_used,
            reason = "ssh mpint length is bounded above by RSA modulus byte length; never anywhere near u32::MAX"
        )]
        let len_u32 = u32::try_from(len).expect("ssh mpint fits in u32 length");
        out.extend_from_slice(&len_u32.to_be_bytes());
        if needs_pad {
            out.push(0x00);
        }
        out.extend_from_slice(trimmed);
    }
}

/// Minimal RFC 4648 base64 encoder. Inlined to keep
/// `refineid-client` free of yet another external dep -- the
/// alternative `base64` crate would be the only other consumer.
impl CardPubkeyHelpers {
    /// RFC 4648 §4 base64 encoder.
    ///
    /// Inlined to avoid pulling the `base64` crate just for
    /// one pubkey-export path. Uses the standard `+/`
    /// alphabet with `=` padding; not constant-time but the
    /// input is public-key material so side-channels are
    /// not in scope.
    fn base64_encode(input: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        /// 6-bit field mask applied to each base64 sextet.
        const SEXTET_MASK: u32 = 0x3F;
        /// Bit shifts for the four sextets that make up one
        /// 24-bit input triple. Listed high-to-low so the output
        /// order matches the input byte order (`b0 b1 b2`).
        const SHIFT_HIGH: u32 = 18;
        const SHIFT_HIGH_MID: u32 = 12;
        const SHIFT_LOW_MID: u32 = 6;
        const SHIFT_BYTE: u32 = 8;
        const SHIFT_HIGH_BYTE: u32 = 16;
        // Pick the base64 character for one sextet. The sextet
        // is masked to 6 bits inside; the index is always in
        // `0..64` and the alphabet lookup never falls back.
        let sextet = |sextet_bits: u32| -> char {
            // `sextet_bits & SEXTET_MASK` is in `0..64`, which is
            // exactly `ALPHABET.len()` -- the alphabet lookup
            // never falls back to the default.
            #[expect(
                clippy::as_conversions,
                reason = "value masked to 6 bits; result is in 0..64 and always fits in usize"
            )]
            let idx = (sextet_bits & SEXTET_MASK) as usize;
            let byte = ALPHABET.get(idx).copied().unwrap_or(b'A');
            // Every alphabet byte is ASCII (< 0x80), so the
            // conversion to char is lossless.
            char::from(byte)
        };
        let mut out = String::with_capacity(input.len().div_ceil(3).saturating_mul(4));
        let mut chunks = input.chunks_exact(3);
        for chunk in chunks.by_ref() {
            // `chunks_exact(3)` only yields full-length slices, so
            // the `&[a, b, c]` pattern always matches; `else
            // continue` is the typing-discipline-clean way to
            // restate that invariant without `panic!` or `expect`.
            let &[b0, b1, b2] = chunk else { continue };
            let n =
                (u32::from(b0) << SHIFT_HIGH_BYTE) | (u32::from(b1) << SHIFT_BYTE) | u32::from(b2);
            out.push(sextet(n >> SHIFT_HIGH));
            out.push(sextet(n >> SHIFT_HIGH_MID));
            out.push(sextet(n >> SHIFT_LOW_MID));
            out.push(sextet(n));
        }
        match *chunks.remainder() {
            [b0] => {
                let n = u32::from(b0) << SHIFT_HIGH_BYTE;
                out.push(sextet(n >> SHIFT_HIGH));
                out.push(sextet(n >> SHIFT_HIGH_MID));
                out.push('=');
                out.push('=');
            }
            [b0, b1] => {
                let n = (u32::from(b0) << SHIFT_HIGH_BYTE) | (u32::from(b1) << SHIFT_BYTE);
                out.push(sextet(n >> SHIFT_HIGH));
                out.push(sextet(n >> SHIFT_HIGH_MID));
                out.push(sextet(n >> SHIFT_LOW_MID));
                out.push('=');
            }
            _ => {}
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{TestResult, check, check_true};
    use refineid_lib_core::crypto::rsa::{RsaModulus, RsaPublicExponent};

    #[test]
    fn base64_known_vectors() -> TestResult {
        // RFC 4648 §10 test vectors.
        check(
            &CardPubkeyHelpers::base64_encode(b""),
            &String::new(),
            "empty",
        )?;
        check(
            &CardPubkeyHelpers::base64_encode(b"f"),
            &"Zg==".to_owned(),
            "f",
        )?;
        check(
            &CardPubkeyHelpers::base64_encode(b"fo"),
            &"Zm8=".to_owned(),
            "fo",
        )?;
        check(
            &CardPubkeyHelpers::base64_encode(b"foo"),
            &"Zm9v".to_owned(),
            "foo",
        )?;
        check(
            &CardPubkeyHelpers::base64_encode(b"foob"),
            &"Zm9vYg==".to_owned(),
            "foob",
        )?;
        check(
            &CardPubkeyHelpers::base64_encode(b"fooba"),
            &"Zm9vYmE=".to_owned(),
            "fooba",
        )?;
        check(
            &CardPubkeyHelpers::base64_encode(b"foobar"),
            &"Zm9vYmFy".to_owned(),
            "foobar",
        )
    }

    #[test]
    fn ssh_mpint_zero_value() -> TestResult {
        let mut buf = Vec::new();
        CardPubkeyHelpers::ssh_write_mpint(&mut buf, &[0x00_u8]);
        // Single 0x00 -- leading-zero strip leaves [0x00], MSB
        // bit is clear, so no pad. Length = 1, value = 0x00.
        check(
            buf.as_slice(),
            &[0x00_u8, 0x00_u8, 0x00_u8, 0x01_u8, 0x00_u8][..],
            "mpint(0x00)",
        )
    }

    #[test]
    fn ssh_mpint_msb_set_gets_leading_zero() -> TestResult {
        let mut buf = Vec::new();
        // value = 0xFF -- MSB set; mpint prepends 0x00.
        CardPubkeyHelpers::ssh_write_mpint(&mut buf, &[0xFF_u8]);
        check(
            buf.as_slice(),
            &[0x00_u8, 0x00_u8, 0x00_u8, 0x02_u8, 0x00_u8, 0xFF_u8][..],
            "mpint(0xFF)",
        )
    }

    #[test]
    fn ssh_mpint_msb_clear_no_pad() -> TestResult {
        let mut buf = Vec::new();
        CardPubkeyHelpers::ssh_write_mpint(&mut buf, &[0x7F_u8]);
        check(
            buf.as_slice(),
            &[0x00_u8, 0x00_u8, 0x00_u8, 0x01_u8, 0x7F_u8][..],
            "mpint(0x7F)",
        )
    }

    // ssh_ecdsa_p384_line_shape retired: building a synthetic
    // Sec1UncompressedPoint from raw bytes requires the lib-core
    // constructor that's intentionally pub(crate). The typed
    // entry point is `SpkiDer::ec_public_key_point()`, which
    // needs a real EC SPKI fixture (cert / DER blob) to drive.
    // Wire-format-shape verification moves to integration tests
    // against a real EC cert (FINEID G4E ECDSA chain) when that
    // surface lands.

    #[test]
    fn ssh_rsa_line_shape() -> TestResult {
        // Smallest valid RsaModulus (512-bit floor, odd low byte,
        // canonical PKCS#1 form) + the standard e=65537.
        const TEST_MODULUS_BYTE_LEN: usize = 64;
        const TEST_MODULUS_FILL: u8 = 0xC1;
        let modulus = RsaModulus::try_from_pkcs1(vec![TEST_MODULUS_FILL; TEST_MODULUS_BYTE_LEN])
            .map_err(|e| format!("test fixture modulus: {e}"))?;
        let key = RsaPublicKey {
            modulus,
            exponent: RsaPublicExponent::e_65537(),
        };
        let comment: SshComment = "test-comment"
            .to_owned()
            .try_into()
            .map_err(|e| format!("test fixture comment: {e}"))?;
        let line = CardPubkeyHelpers::encode_ssh_rsa(&key, &comment);
        check_true(line.starts_with("ssh-rsa "), "starts_with ssh-rsa")?;
        check_true(line.ends_with(" test-comment\n"), "ends_with comment")
    }

    // pem_spki_wraps_at_64 retired: encode_pem_spki now takes
    // `&SpkiDer<'_>`, and the SPKI parse-validator rejects the
    // raw 96-byte test fixture this test used to use. PEM
    // wrapping behaviour is exercised by the higher-level
    // integration tests against real card certs; the standalone
    // unit test would require a synthetic well-formed SPKI
    // fixture, which is more setup than the one-line chunk(64)
    // logic warrants.
}
