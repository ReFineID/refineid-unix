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

//! `refineid card`: unified per-card readout.
//!
//! Walks every FINEID-responding reader (filterable via
//! `--reader SUBSTR`) and produces one report block per card.
//! The report always includes:
//!
//! - ATR, EF.TokenInfo, PACE protocol info from EF.CardAccess,
//!   identity derived from the auth-cert subject;
//! - every cert slot's full metadata (subject / issuer CN,
//!   serial, SHA-256 fingerprint, validity, public-key and
//!   signature algorithms, key usage, AIA / CRL / OCSP / SAN
//!   extensions);
//! - chain walk against the on-card root with the AIA-fetched
//!   intermediate; with revocation status from the CRL and
//!   OCSP (both signature-verified against the issuer key);
//! - PIN1 / PIN2 and PUK retry-counter probes (counter-safe
//!   forms, FINEID S1 v4.2 sections 3.5 and 3.15).
//!
//! `--offline` suppresses every network fetch (CRL + OCSP +
//! AIA caIssuers); cert metadata + chain checks against the
//! on-card root + PIN probes still print. `--crl-file PATH`
//! replaces the CRL fetch with a pre-fetched file.
//!
//! When a CAN is supplied (either via `--can NNNNNN` or via
//! the interactive prompt that the bare-command CLI runs), the
//! eMRTD application is also opened: MRZ, face / signature
//! images, EF.SOD, DG14 / DG15 metadata, Active Authentication
//! and Chip Authentication round-trip outcomes, document
//! expiry, and the BSI TR-03135-1 §4.6.4.5 issuing-state
//! cross-check.

use alloc::fmt;
use std::path::PathBuf;

/// Helpers hosted on a unit struct (typing-discipline: no
/// free fns with borrowed parameters; see
/// `doc/typing-discipline.md`).
struct CardCheckHelpers;

use refineid_lib_core::apdu::status_word::StatusWord;
use refineid_lib_core::auth::{
    CredentialPolicyCounters, PinOps as _, PinReferenceScheme, PinSlot, PinStatus, PukStatus,
    UnblockingCounter, UsageCounter,
};
use refineid_lib_core::backend::{ReaderAccessCap, ReaderBackend as _, ReaderPickError};
use refineid_lib_core::card_access::{CardAccess, CardAccessOps as _};
use refineid_lib_core::cert_state::CertDer;
use refineid_lib_core::crl::OwnedCrl;
use refineid_lib_core::crypto::digest::Sha256;
use refineid_lib_core::emrtd::{EmrtdError, EmrtdPersonalData, read_personal_data};
use refineid_lib_core::icao_pkd::{
    CscaEntry, IcaoMasterList, extract_master_list_ders_from_ldif, parse_master_list,
};
use refineid_lib_core::identity::CredentialIdentity;
use refineid_lib_core::ocsp::{self, OcspResponseStatus};
use refineid_lib_core::pkcs15::{
    CertSlot, FineidReaderPick, FineidReaderPicker as _, Pkcs15Error, Pkcs15Ops as _, TokenInfo,
};
use refineid_lib_core::revocation::{
    RevocationStatus, check_against_crl, check_against_ocsp_response,
};
use refineid_lib_core::secure_messaging::SmTransport;
use refineid_lib_core::x509::{
    Certificate, DateTime, KeyUsage, Name, OID_ICAO_ML_SIGNER, OwnedCert, PublicKeyAlgorithm,
    SignatureAlgorithm, extract_basic_constraints, extract_ca_issuers_urls,
    extract_crl_distribution_urls, extract_extended_key_usage, extract_extended_key_usage_meta,
    extract_key_usage, extract_key_usage_meta, extract_ocsp_urls, extract_subject_alt_emails,
    parse_subject_public_key_info,
};
use refineid_lib_pcsc::{PcscBackend, PcscError};
use sha1::{Digest as Sha1Digest, Sha1};

use crate::http;
use crate::trust_roots::{ICAO_PKD_ROOT_PEMS, ICAO_PKD_ROOT_SHA256, is_pinned_root};
use crate::user_agent;

/// Hard ceiling on a fetched CRL response body. Real DVV CRLs
/// are ~13 MB today; 32 MiB leaves headroom.
const CRL_MAX_BYTES: usize = 32 * 1024 * 1024;
/// Issuer certs and OCSP responses are small (<= 8 KiB).
const SMALL_HTTP_MAX_BYTES: usize = 64 * 1024;
/// ASN.1 DER SEQUENCE tag, used for coarse CMS/LDIF sniffing.
const DER_SEQUENCE_TAG: u8 = 0x30;
/// SHA-1 output width in bytes.
const SHA1_OUTPUT_LEN: usize = 20;

/// Inputs to one `refineid card` invocation.
#[derive(Debug, Clone, Default)]
pub struct CardCheckOptions<'a> {
    /// Optional substring match against reader names. `None`
    /// walks every FINEID-responding reader. `Some(s)` filters
    /// to readers whose name contains `s`.
    pub reader_filter: Option<String>,
    /// When `true`, suppress every network fetch (CRL + OCSP +
    /// AIA caIssuers).
    pub offline: bool,
    /// Six-digit Card Access Number from the card front.
    /// `Some` runs the eMRTD section; `None` skips it.
    pub can: Option<&'a refineid_lib_core::can::Can>,
    /// Pre-fetched CRL file. When set, replaces the CRL fetch.
    pub crl_file: Option<PathBuf>,
    /// Directory to dump each slot's cert DER to.
    pub save_cert_dir: Option<PathBuf>,
    /// Path to ICAO PKD input -- either a single signed Master
    /// List `*.ml` file (DER, CMS-wrapped) or a `*.ldif` file
    /// from the canonical PKD distribution (typically
    /// `icaopkd-002-complete-N.ldif` carrying N per-state
    /// Master Lists). The format is sniffed at load time. Used
    /// as the DSC trust anchor source for Passive
    /// Authentication's DSC -> CSCA hop. Useful when combined
    /// with --can.
    pub icao_pkd: Option<PathBuf>,
    /// "Now" used for freshness + days-until-expiry. Defaults
    /// to the system clock through [`now_date_time`].
    pub now: Option<DateTime>,
}

/// One reader's worth of `refineid card` output.
#[derive(Debug, Clone)]
pub struct CardCheckReport {
    /// PC/SC reader name the card was talked to through; populated
    /// from `ReaderId::as_str().to_owned()`. Tier 0 `String`
    /// inside Tier 1 `ReaderId` upstream; the bound (non-empty,
    /// platform-supplied) is enforced where `ReaderId` is built,
    /// not by the field type. Tighter form would be `ReaderId`
    /// directly.
    pub reader: String,
    /// Person identity extracted from the auth cert's subject DN
    /// per FINEID S2 §6.3.8.3 (surname / given names / PEUIN /
    /// `DoB` / email when present).
    pub identity: CredentialIdentity,
    /// Lowercase hex rendering of the card's ISO 7816-3 Answer
    /// to Reset bytes (length 4..=33 per ISO 7816-3 §8). Tier 0
    /// `String` -- the structure (TS, T0, interface, historical)
    /// is decoded into `Atr` elsewhere; this field carries the
    /// wire form for the report's text output.
    pub atr_hex: String,
    /// PKCS#15 `EF.TokenInfo` contents (label, manufacturer,
    /// serial). Empty `TokenInfo::default()` when the read failed.
    pub token_info: TokenInfo,
    /// `EF.CardAccess` contents (ICAO Doc 9303-11 `SecurityInfos`:
    /// PACE parameter sets, chip authentication info, etc.) Empty
    /// `CardAccess::default()` when the read failed.
    pub card_access: CardAccess,
    /// One [`CertReport`] per slot the card returned a DER for.
    /// Order is `CertSlot::all()` iteration order; mandatory
    /// authentication-cert slot is always first.
    pub certs: Vec<CertReport>,
    /// Which credential reference numbering the card answered to:
    /// citizen (FINEID S1 v4.2 §3.5.2) or organizational
    /// (FINEID S4-2 v4.0 §4.2), resolved by counter-safe probes.
    pub pin_reference_scheme: PinReferenceScheme,
    /// PIN1 (authentication PIN) retry counter probe outcome.
    /// `None` when the counter-safe empty-Lc VERIFY didn't return
    /// a status word.
    pub pin1: Option<PinStatus>,
    /// PIN2 (non-repudiation PIN) retry counter probe outcome.
    /// `None` when the counter-safe empty-Lc VERIFY didn't return
    /// a status word.
    pub pin2: Option<PinStatus>,
    /// Shared PUK retry counter queried through the PUK PIN-container
    /// reference. `None` when the counter-safe `GET DATA`
    /// DATA command did not return a status word.
    pub puk: Option<PukStatus>,
    /// Card-reported PIN1 successful-use and recovery allowances.
    pub pin1_policy: Option<CredentialPolicyCounters>,
    /// Card-reported PIN2 successful-use and recovery allowances.
    pub pin2_policy: Option<CredentialPolicyCounters>,
    /// Card-reported shared-PUK successful-use allowance.
    pub puk_policy: Option<CredentialPolicyCounters>,
    /// PIN1 "PIN changed" flag probe outcome per FINEID S1 v4.2
    /// §3.15.2 Table 19 (`DF 2F`). `Some(true)` if PIN1 has been
    /// changed since manufacture (factory-set value rewritten),
    /// `Some(false)` if still at the factory value (fresh new-
    /// scheme card), `None` if the card declined the probe
    /// (older firmware without the GET DATA PIN-container
    /// implementation, or the optional flag parameter is off).
    /// Counter-safe; no try-counter mutation.
    pub pin1_changed: Option<bool>,
    /// Same as [`pin1_changed`](Self::pin1_changed) for PIN2.
    pub pin2_changed: Option<bool>,
    /// `Some` when --can was supplied and the eMRTD reads
    /// completed.
    pub emrtd: Option<EmrtdPersonalData>,
    /// `Some` when --can was supplied but the eMRTD read failed
    /// (`BadCan`, SM glitch, parse error). The report still
    /// ships so the rest of the per-card data is visible.
    pub emrtd_error: Option<String>,
    /// DSC -> CSCA verification outcome when --icao-pkd was
    /// supplied and the eMRTD read produced a DSC. `None` when
    /// either input is absent.
    pub dsc_csca_check: Option<DscCscaCheck>,
}

/// Per-card outcome of the DSC -> CSCA hop, using the trusted
/// Master List CSCAs from the `--icao-pkd` pool as the
/// candidate trust anchors.
#[derive(Debug, Clone)]
pub enum DscCscaCheck {
    /// DSC cleared Doc 9303 §7.1.1 `KeyUsage` compliance AND
    /// chained to a trusted CSCA from the pool.
    Ok {
        /// Common Name attribute (RFC 5280 §4.1.2.6) extracted
        /// from the verifying CSCA's subject DN. `None` when the
        /// CN attribute is absent or unparseable.
        csca_subject_cn: Option<refineid_lib_core::identity::CommonName>,
        /// ISO 3166-1 alpha-2 country code from the CSCA's
        /// subject DN `C=` attribute (Doc 9303-12 §4.2). `None`
        /// when the C= attribute is absent.
        csca_country: Option<refineid_lib_core::country::IsoAlpha2>,
        /// SHA-256 of the verifying CSCA's full DER encoding,
        /// per the operator-pin fingerprint convention.
        csca_sha256: Sha256,
    },
    /// DSC failed Doc 9303 §7.1.1 `KeyUsage` compliance. The
    /// CSCA chain check was *not* attempted -- a non-compliant
    /// DSC fails Passive Authentication regardless of which
    /// CSCA issued it.
    KeyUsageNonCompliant(DscKeyUsageCheck),
    /// CSCA candidate(s) for the country exist but no signature
    /// verification succeeded against them.
    NoMatch {
        /// ISO 3166-1 alpha-2 country extracted from the DSC's
        /// issuer DN. Equal to the key used to look up candidates.
        country_iso: refineid_lib_core::country::IsoAlpha2,
        /// Number of CSCAs in the pool with this country code
        /// that were tried before giving up. Tier 0 `usize` --
        /// arithmetic count, no domain meaning beyond "how many
        /// signatures were attempted".
        candidates: usize,
    },
    /// The ML had no CSCAs for the DSC's issuing country at all.
    CountryAbsent {
        /// ISO 3166-1 alpha-2 country extracted from the DSC's
        /// issuer DN that wasn't represented in the trust pool.
        country_iso: refineid_lib_core::country::IsoAlpha2,
    },
    /// The DSC didn't expose a country we could look up.
    DscCountryUnknown,
    /// EF.SOD didn't carry a DSC to verify.
    NoDscInSod,
    /// DSC was present but couldn't be parsed as X.509.
    DscParseFailed,
}

/// Doc 9303 §7.1.1 Key Usage compliance check on a DSC.
/// Informational; future versions may promote to blocking.
#[derive(Debug, Clone)]
pub enum DscKeyUsageCheck {
    /// KU extension present, critical, asserts exactly
    /// `digitalSignature` and nothing else.
    Compliant,
    /// KU extension absent.
    ExtensionMissing,
    /// KU extension present but not marked critical.
    NotCritical,
    /// KU present and critical but missing `digitalSignature`.
    MissingDigitalSignature,
    /// KU present and critical and includes `digitalSignature`
    /// but also asserts other bits. The `extra` string lists
    /// the offending bit labels.
    ExtraBitsAsserted {
        /// Comma-joined list of RFC 5280 §4.2.1.3 `KeyUsage` bit
        /// names that are asserted alongside `digitalSignature`
        /// (e.g. "keyCertSign, cRLSign"). Tier 0 `String` --
        /// presentational; the bit-typed form is `KeyUsage`
        /// with the individual flags.
        extra: String,
    },
}

impl DscKeyUsageCheck {
    /// Render the DSC `keyUsage` check outcome as a one-line
    /// human string for the report.
    ///
    /// ICAO 9303 Part 12 §7.1.1 requires DSCs to assert exactly
    /// `digitalSignature` with the extension critical; the
    /// strings here mirror the spec language so a reader can
    /// cross-reference. Used only for the `card check` CLI
    /// output, not parsed by anything.
    fn describe(&self) -> String {
        match self {
            Self::Compliant => "ok (digitalSignature critical, only)".to_owned(),
            Self::ExtensionMissing => {
                "MISSING -- Doc 9303 \u{00a7}7.1.1 requires KU on DSC".to_owned()
            }
            Self::NotCritical => {
                "NOT CRITICAL -- Doc 9303 \u{00a7}7.1.1 requires critical KU".to_owned()
            }
            Self::MissingDigitalSignature => {
                "MISSING digitalSignature -- DSC must assert it".to_owned()
            }
            Self::ExtraBitsAsserted { extra } => {
                format!("FAIL -- KU asserts non-digitalSignature bits: {extra}")
            }
        }
    }
}

impl CardCheckHelpers {
    /// Inspect a DSC's `keyUsage` extension and classify it for
    /// the ICAO 9303 Part 12 §7.1.1 conformance check.
    ///
    /// Returns the most-specific failure variant: missing
    /// extension -> not critical -> missing `digitalSignature`
    /// bit -> extra non-`digitalSignature` bits asserted. The
    /// `Compliant` case is reserved for DSCs that assert
    /// exactly `digitalSignature` and nothing else.
    fn check_dsc_key_usage(dsc: &Certificate<'_>) -> DscKeyUsageCheck {
        let Some(extensions) = dsc.extensions else {
            return DscKeyUsageCheck::ExtensionMissing;
        };
        let Some(ku_meta) = extract_key_usage_meta(extensions) else {
            return DscKeyUsageCheck::ExtensionMissing;
        };
        if !ku_meta.critical {
            return DscKeyUsageCheck::NotCritical;
        }
        let ku = &ku_meta.key_usage;
        if !ku.digital_signature {
            return DscKeyUsageCheck::MissingDigitalSignature;
        }
        let mut extra_bits: Vec<&str> = Vec::new();
        if ku.non_repudiation {
            extra_bits.push("nonRepudiation");
        }
        if ku.key_encipherment {
            extra_bits.push("keyEncipherment");
        }
        if ku.data_encipherment {
            extra_bits.push("dataEncipherment");
        }
        if ku.key_agreement {
            extra_bits.push("keyAgreement");
        }
        if ku.key_cert_sign {
            extra_bits.push("keyCertSign");
        }
        if ku.crl_sign {
            extra_bits.push("cRLSign");
        }
        if ku.encipher_only {
            extra_bits.push("encipherOnly");
        }
        if ku.decipher_only {
            extra_bits.push("decipherOnly");
        }
        if !extra_bits.is_empty() {
            return DscKeyUsageCheck::ExtraBitsAsserted {
                extra: extra_bits.join(", "),
            };
        }
        DscKeyUsageCheck::Compliant
    }
}

/// One certificate slot's worth of output.
#[derive(Debug, Clone)]
pub struct CertReport {
    /// Which certificate slot this report covers. Rendered via
    /// [`CertSlot::label`] at display time ("Authentication",
    /// "Signature", "Root CA", ...).
    pub slot: CertSlot,
    /// Common Name attribute from the cert's subject DN per
    /// RFC 5280 §4.1.2.6. `None` if absent / unparseable.
    pub subject_cn: Option<refineid_lib_core::identity::CommonName>,
    /// Common Name attribute from the cert's issuer DN per
    /// RFC 5280 §4.1.2.4. `None` if absent / unparseable.
    pub issuer_cn: Option<refineid_lib_core::identity::CommonName>,
    /// X.509 INTEGER serial number per RFC 5280 §4.1.2.2 (positive
    /// integer, up to 20 octets). Tier 1 newtype carrying the
    /// signed-integer-bytes invariant from the BER parser.
    pub serial: refineid_lib_core::identity::CertSerial,
    /// SHA-256 of the full DER encoding -- the value pinned roots
    /// are compared against and the value `--save-cert-dir` files
    /// are named after.
    pub sha256: Sha256,
    /// `notBefore` field of the `TBSCertificate` per RFC 5280
    /// §4.1.2.5; the earliest UTC instant at which the cert is
    /// valid.
    pub not_before: DateTime,
    /// `notAfter` field of the `TBSCertificate` per RFC 5280
    /// §4.1.2.5; the latest UTC instant at which the cert is
    /// valid.
    pub not_after: DateTime,
    /// Signed days from "now" (the `VerifyContext::now`) to
    /// `not_after`. Negative when the cert has already expired.
    /// Tier 0 `i64` -- arithmetic count, no domain wrapper.
    pub days_until_expiry: i64,
    /// Parsed `SubjectPublicKeyInfo` algorithm per RFC 5280
    /// §4.1.2.7 (RSA modulus bits, EC named curve, etc.). `None`
    /// when the SPKI parse failed.
    pub key_alg: Option<PublicKeyAlgorithm>,
    /// Decoded `keyUsage` extension per RFC 5280 §4.2.1.3. `None`
    /// when the extension is absent (rare for FINEID end-entity
    /// certs).
    pub key_usage: Option<KeyUsage>,
    /// `extendedKeyUsage` OIDs in dotted-decimal form per RFC 5280
    /// §4.2.1.12. Tier 0 `Vec<String>` -- the typed form is
    /// `Vec<Oid<'a>>`; tighter form would be a typed
    /// `ExtendedKeyUsage` enum set.
    pub eku: Vec<String>,
    /// `cRLDistributionPoints` HTTP/HTTPS URLs per RFC 5280
    /// §4.2.1.13. LDAP DPs and non-HTTP schemes are filtered
    /// at parse time.
    pub crl_urls: Vec<refineid_lib_core::text::Uri>,
    /// `authorityInfoAccess` OCSP URLs per RFC 5280 §4.2.2.1
    /// (accessMethod = `id-ad-ocsp`).
    pub ocsp_urls: Vec<refineid_lib_core::text::Uri>,
    /// `authorityInfoAccess` caIssuers URLs per RFC 5280 §4.2.2.1
    /// (accessMethod = `id-ad-caIssuers`). Used to fetch the
    /// intermediate cert for chain construction.
    pub ca_issuers_urls: Vec<refineid_lib_core::text::Uri>,
    /// `rfc822Name` SAN entries per RFC 5280 §4.2.1.6, each
    /// validated as RFC 822 form by `EmailAddress::new` at parse.
    pub san_emails: Vec<refineid_lib_core::identity::EmailAddress>,
    /// Decoded signature algorithm from the cert's
    /// `signatureAlgorithm` field per RFC 5280 §4.1.1.2.
    pub signature_alg: SignatureAlgorithm,
    /// Chain-walk outcome (leaf -> AIA intermediate -> on-card
    /// root). `None` for the root cert itself (no chain to walk)
    /// or when `--offline` suppresses the AIA fetch.
    pub chain_check: Option<SignatureCheck>,
    /// CRL-based revocation outcome. `None` for the root cert or
    /// when `--offline` suppresses the CRL fetch.
    pub crl_check: Option<CheckOutcome>,
    /// OCSP-based revocation outcome. `None` for the root cert
    /// or when `--offline` suppresses the OCSP POST.
    pub ocsp_check: Option<CheckOutcome>,
}

/// Result of one cryptographic signature check (cert -> issuer,
/// CRL signature, OCSP response signature, OCSP nonce match).
#[derive(Debug, Clone)]
pub enum SignatureCheck {
    /// Signature verified mathematically against the expected key.
    Ok,
    /// Precondition wasn't met (no key, no signature, offline
    /// mode, ...). The wrapped string is a human-readable reason.
    /// Tier 0 `String` -- presentational; reasons aren't compared.
    Skipped(String),
    /// Signature was checked but didn't verify. The wrapped string
    /// names the failing hop (e.g. "leaf -> intermediate: `<err>`").
    /// Tier 0 `String`; presentational.
    Failed(String),
}

/// Outcome of one revocation check (CRL or OCSP) for one cert.
#[derive(Debug, Clone)]
pub enum CheckOutcome {
    /// Fetch and parse succeeded; carries the revocation verdict
    /// plus auxiliary signature / nonce checks.
    Status {
        /// Origin label: URL string for live fetches,
        /// `(pre-fetched file)` for `--crl-file`. Tier 0 `String`;
        /// presentational.
        source: String,
        /// Decoded RFC 5280 §5.3.1 / RFC 6960 §4.2.1 status:
        /// Unknown, Good, Revoked{at, reason}, Stale, Inapplicable.
        status: RevocationStatus,
        /// Signature verification of the CRL / OCSP response
        /// itself against the issuer's SPKI.
        signature: SignatureCheck,
        /// OCSP-only: nonce echo check per RFC 8954. `None` for
        /// CRL outcomes (no nonce concept).
        nonce: Option<SignatureCheck>,
    },
    /// Fetch or parse failed; the verdict can't be computed.
    Skipped {
        /// Same `source` semantics as the `Status` variant.
        source: String,
        /// Human-readable reason ("fetch failed: `<io err>`",
        /// "CRL parse: `<ber err>`", ...). Tier 0 `String`;
        /// presentational.
        why: String,
    },
}

/// Error returned from `check_all` / `check_for_reader`.
#[derive(Debug)]
pub enum CardCheckError {
    /// Reader enumeration / filter resolution failed (no readers,
    /// no FINEID-responding reader, ambiguous filter, ...).
    ReaderPick(ReaderPickError),
    /// The card sealed PKCS#15 behind PACE (contactless
    /// interface) and no CAN was supplied to open it. Unlike the
    /// eMRTD section, which is simply skipped without a CAN, the
    /// whole readout lives behind PKCS#15 -- so there is nothing
    /// to report until PACE runs.
    NeedCan,
    /// PACE failed with the wrong-CAN signature: card-reported
    /// authentication failure or a mutual-auth tag mismatch.
    BadCan,
    /// PACE establishment failed for a non-CAN reason. Tier 0
    /// `String`; presentational copy of the upstream error.
    Pace(String),
    /// PC/SC connect / transmit error on a specific reader.
    Pcsc(PcscError),
    /// Reading the *mandatory* authentication cert from EF.4331
    /// failed. The wrapped string is the upstream error message.
    /// Tier 0 `String` -- presentational; the typed source is the
    /// underlying transport error rendered via `to_string()`.
    CertRead(String),
    /// X.509 DER parse failed on a slot we just read off the card.
    /// Tier 0 `String`; presentational copy of the BER parser
    /// error.
    CertParse(String),
    /// The OS CSPRNG was unavailable when drawing an OCSP request
    /// nonce. A dead RNG means no crypto on this host can be trusted,
    /// so the check aborts rather than send a replayable request.
    /// Tier 0 `String`; presentational copy of the `rng::Error`.
    Rng(String),
    /// `--crl-file` / `--save-cert-dir` I/O error.
    CrlRead {
        /// Filesystem path the read was attempted against.
        path: PathBuf,
        /// Underlying `std::io::Error` (`NotFound`,
        /// `PermissionDenied`, ...).
        source: std::io::Error,
    },
    /// `--icao-pkd` file read failed before any parse was tried.
    IcaoPkdRead {
        /// Filesystem path the read was attempted against.
        path: PathBuf,
        /// Underlying `std::io::Error`.
        source: std::io::Error,
    },
    /// `--icao-pkd` file parsed unsuccessfully (DER vs LDIF sniff
    /// produced no usable Master Lists).
    IcaoPkdParse {
        /// Filesystem path the parse was attempted against.
        path: PathBuf,
        /// Human-readable BER / LDIF parser error. Tier 0
        /// `String`; presentational copy of the upstream error.
        source: String,
    },
}

impl fmt::Display for CardCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReaderPick(e) => write!(f, "{e}"),
            Self::Pcsc(e) => write!(f, "PC/SC: {e}"),
            Self::CertRead(s) => write!(f, "cert read: {s}"),
            Self::CertParse(s) => write!(f, "cert parse: {s}"),
            Self::Rng(s) => write!(f, "OS RNG unavailable: {s}"),
            Self::CrlRead { path, source } => {
                write!(f, "CRL read {}: {source}", path.display())
            }
            Self::IcaoPkdRead { path, source } => {
                write!(f, "ICAO PKD read {}: {source}", path.display())
            }
            Self::IcaoPkdParse { path, source } => {
                write!(f, "ICAO PKD parse {}: {source}", path.display())
            }
            Self::NeedCan => write!(
                f,
                "contactless card: everything on this card is sealed behind \
                 PACE; pass --can NNNNNN (six digits printed on the card \
                 front) so the readout can open a secure channel"
            ),
            Self::BadCan => write!(f, "PACE failed: the CAN did not match the card"),
            Self::Pace(s) => write!(f, "PACE: {s}"),
        }
    }
}

/// Hoist [`refineid_lib_core::pace::PaceError`] onto
/// [`CardCheckError`], classifying wrong-CAN exactly as the
/// eMRTD and sign paths do: a card-reported authentication
/// failure or a mutual-auth tag mismatch both mean the
/// CAN-derived key disagreed with the card.
fn pace_err_to_check_error<TE: fmt::Display>(
    e: &refineid_lib_core::pace::PaceError<TE>,
) -> CardCheckError {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "PaceError is #[non_exhaustive]; the fallback arm absorbs every non-CAN variant into the presentational Pace(String)"
    )]
    match e {
        refineid_lib_core::pace::PaceError::Sw(_, sw)
            if StatusWord::from_u16(*sw) == StatusWord::AuthenticationFailed =>
        {
            CardCheckError::BadCan
        }
        refineid_lib_core::pace::PaceError::AuthMismatch => CardCheckError::BadCan,
        _ => CardCheckError::Pace(format!("{e}")),
    }
}

impl core::error::Error for CardCheckError {}

impl From<PcscError> for CardCheckError {
    fn from(e: PcscError) -> Self {
        Self::Pcsc(e)
    }
}

impl From<ReaderPickError> for CardCheckError {
    fn from(e: ReaderPickError) -> Self {
        Self::ReaderPick(e)
    }
}

/// Walk every FINEID-responding reader (or the subset filtered
/// by `options.reader_filter`) and produce one
/// [`CardCheckReport`] per card.
///
/// # Errors
/// PC/SC enumeration / reader-pick errors, or any per-card
/// failure (cert read, CRL file read, etc.).
pub fn check_all(
    backend: PcscBackend,
    options: &CardCheckOptions<'_>,
) -> Result<Vec<CardCheckReport>, CardCheckError> {
    // Pre-load + verify the ICAO PKD input once for the whole
    // walk so a bad bundle fails fast (before any card I/O) and
    // the parsed tree is shared across every per-card check.
    let icao_pkd: Option<IcaoTrustPool> = match &options.icao_pkd {
        Some(path) => Some(CardCheckHelpers::load_icao_pkd(path)?),
        None => None,
    };

    let filter = options
        .reader_filter
        .clone()
        .map(refineid_lib_core::backend::ReaderFilter::new);
    let mut picks = backend.enumerate_fineid_readers(filter.as_ref())?;
    if picks.is_empty() {
        // Nothing answered the PKCS#15 probe. Over contactless
        // that is expected rather than "no card": the application
        // is sealed until PACE runs, so the probe can never see
        // it. Fall back to the readers whose card serves
        // EF.CardAccess -- the one file exposed pre-PACE -- and
        // let `check_for_reader` open the channel. The identity
        // is empty because none is knowable before PACE; the
        // report's cert section carries it once the channel is up.
        picks = backend
            .enumerate_contactless_readers(filter.as_ref())?
            .into_iter()
            .map(|reader_id| FineidReaderPick {
                reader_id,
                identity: CredentialIdentity::new(),
            })
            .collect();
    }
    let mut out = Vec::with_capacity(picks.len());
    for pick in picks {
        out.push(check_for_reader(backend, pick, options, icao_pkd.as_ref())?);
    }
    Ok(out)
}

/// One Master List that has been parsed and trust-checked.
/// Kept around per-source so the report can attribute each CSCA
/// to its source ML and signer if needed.
#[derive(Debug, Clone)]
struct LoadedMl {
    /// Parsed CSCA Master List body (RFC 5652 `SignedData` with
    /// `cscaMasterListData` `eContentType` per ICAO 9303 Part 12
    /// §6.4).
    ml: IcaoMasterList,
    /// Result of chaining the ML signer back to a pinned ICAO
    /// PKD root. `Pinned` is the only outcome that lets the
    /// ML's CSCAs feed the trust pool.
    trust: MlSignerTrust,
    /// Whether the signer asserts the critical `id-icao-mlSigner`
    /// EKU per ICAO 9303 Part 12 §7.1.4 -- a hard requirement
    /// for ML acceptance.
    eku: SignerEkuCheck,
    /// Whether the signer's `BasicConstraints` extension is
    /// either absent or `CA=false`; an `mlSigner` cert acting
    /// as a CA is a Doc 9303 violation.
    basic_constraints: SignerBasicConstraintsCheck,
}

/// In-memory trust pool assembled from one `--icao-pkd PATH`
/// argument. Either:
///
/// - exactly one `LoadedMl` when the path was a single signed
///   `*.ml` (DER) file, or
/// - N `LoadedMl`s when the path was an LDIF carrying N
///   per-state Master Lists.
///
/// `trusted_cscas` only returns CSCA entries whose source ML
/// passed every Doc 9303 §12 gate -- chain to a pinned ICAO PKD
/// root, EKU `id-icao-mlSigner` critical present, and
/// `BasicConstraints` CA not asserted. Untrusted MLs are still
/// retained so the load-line summary can report what failed.
#[derive(Debug, Clone)]
pub struct IcaoTrustPool {
    /// All Master Lists loaded from one `--icao-pkd PATH`
    /// invocation. Holds both trusted and untrusted entries so
    /// the report can attribute load-line outcomes; only the
    /// trusted-ML subset feeds [`Self::trusted_cscas`].
    mls: Vec<LoadedMl>,
}

impl IcaoTrustPool {
    /// Yield every CSCA from every fully-trusted ML in the pool.
    ///
    /// "Fully trusted" means the ML chains to a pinned ICAO PKD
    /// root, asserts the critical `id-icao-mlSigner` EKU, and
    /// does not assert CA in `BasicConstraints`. CSCAs from
    /// untrusted MLs never reach a card's trust chain --
    /// surfacing them would defeat the pinning guarantee.
    fn trusted_cscas(&self) -> impl Iterator<Item = &CscaEntry> {
        self.mls
            .iter()
            .filter(|m| is_ml_fully_trusted(m))
            .flat_map(|m| m.ml.cscas.iter())
    }
}

/// Raw bytes read from the operator-supplied ICAO PKD input path.
struct IcaoPkdFileBytes {
    /// Verbatim file contents, format not yet classified.
    bytes: Vec<u8>,
}

impl IcaoPkdFileBytes {
    /// Heuristic file-format sniff: DER CMS starts with SEQUENCE.
    fn looks_like_der_sequence(&self) -> bool {
        self.bytes.first() == Some(&DER_SEQUENCE_TAG)
    }

    /// Borrow the file bytes for UTF-8/LDIF parsing.
    const fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Consume the file bytes after the DER sniff has classified them.
    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// `true` iff the ML passes every gate required to feed its
/// CSCAs into the trust pool: pinned-root chain + Doc 9303
/// EKU + Doc 9303 `BasicConstraints`.
const fn is_ml_fully_trusted(m: &LoadedMl) -> bool {
    matches!(m.trust, MlSignerTrust::Pinned { .. })
        && matches!(m.eku, SignerEkuCheck::Compliant)
        && matches!(m.basic_constraints, SignerBasicConstraintsCheck::Compliant)
}

/// Read the path, sniff DER vs LDIF, parse all Master Lists
/// it contains, run the signer-trust check on each, return the
/// combined pool.
impl CardCheckHelpers {
    /// Load and parse a `--icao-pkd PATH` argument into an
    /// [`IcaoTrustPool`].
    ///
    /// Auto-sniffs DER (single `cscaMasterListData` blob) vs
    /// LDIF (per-state attribute records carrying N Master
    /// Lists). DER failures abort the load -- the operator
    /// gave us one file and there's nothing to fall back on.
    /// LDIF failures are per-record lenient -- partial loads
    /// are useful when only a few states' MLs are malformed.
    fn load_icao_pkd(path: &std::path::Path) -> Result<IcaoTrustPool, CardCheckError> {
        let input = IcaoPkdFileBytes {
            bytes: std::fs::read(path).map_err(|source| CardCheckError::IcaoPkdRead {
                path: path.to_path_buf(),
                source,
            })?,
        };
        let is_der = input.looks_like_der_sequence();
        let mls_der: Vec<Vec<u8>> = if is_der {
            vec![input.into_bytes()]
        } else {
            let text = core::str::from_utf8(input.as_bytes()).map_err(|e| {
                CardCheckError::IcaoPkdParse {
                    path: path.to_path_buf(),
                    source: format!("not DER and not UTF-8 text: {e}"),
                }
            })?;
            extract_master_list_ders_from_ldif(text).map_err(|e| CardCheckError::IcaoPkdParse {
                path: path.to_path_buf(),
                source: format!("{e}"),
            })?
        };
        let source_label = if is_der {
            format!("DER .ml: {}", path.display())
        } else {
            format!("LDIF: {}", path.display())
        };

        // Per-ML failure handling differs by source kind:
        //
        // - DER input (single ML): fail the whole load. Operator's
        //   one file was bad; there's nothing salvageable.
        // - LDIF input (N MLs): be lenient. Per-state Master Lists
        //   in the 002 LDIF use a variety of signature algorithms
        //   (ECC curves we don't implement, RSA-PSS variants, etc.)
        //   and one country's malformed ML shouldn't void the
        //   bundle. Log the failure to stderr and keep the rest.
        let mut loaded: Vec<LoadedMl> = Vec::with_capacity(mls_der.len());
        let mut load_failures: Vec<String> = Vec::new();
        for (idx, der) in mls_der.iter().enumerate() {
            match parse_master_list(der) {
                Ok(ml) => {
                    let trust = Self::check_ml_signer_trust(&ml);
                    let (eku, basic_constraints) = OwnedCert::from_der(&ml.signer_cert_der).map_or(
                        (
                            SignerEkuCheck::ExtensionMissing,
                            SignerBasicConstraintsCheck::Compliant,
                        ),
                        |signer_owned| {
                            let signer = signer_owned.view();
                            (
                                Self::check_signer_eku(&signer),
                                Self::check_signer_basic_constraints(&signer),
                            )
                        },
                    );
                    loaded.push(LoadedMl {
                        ml,
                        trust,
                        eku,
                        basic_constraints,
                    });
                }
                Err(e) => {
                    if is_der {
                        return Err(CardCheckError::IcaoPkdParse {
                            path: path.to_path_buf(),
                            source: format!("{e}"),
                        });
                    }
                    load_failures.push(format!("ML #{idx}: {e}"));
                }
            }
        }

        let total = loaded.len();
        let trusted_count = loaded.iter().filter(|m| is_ml_fully_trusted(m)).count();
        let total_cscas: usize = loaded.iter().map(|m| m.ml.cscas.len()).sum();

        if let (1, true, Some(m)) = (total, load_failures.is_empty(), loaded.first()) {
            eprintln!(
                "ICAO PKD loaded ({source_label}): 1 ML, {} CSCAs",
                m.ml.cscas.len()
            );
            eprintln!(
                "  signer:               {}",
                m.ml.signer_subject_cn.as_deref().unwrap_or("<unparsed>")
            );
            eprintln!("  trust:                {}", m.trust.describe());
            eprintln!("  Doc 9303 EKU:         {}", m.eku.describe());
            eprintln!("  Doc 9303 BasicCons:   {}", m.basic_constraints.describe());
        } else {
            eprintln!(
                "ICAO PKD loaded ({source_label}): {total} MLs ({trusted_count} trusted, \
             {} unparseable), {total_cscas} CSCAs total before dedup",
                load_failures.len(),
            );
            for (idx, m) in loaded.iter().enumerate() {
                eprintln!(
                    "  ML #{idx}: {} CSCAs, signer {} ({}; EKU: {}; BC: {})",
                    m.ml.cscas.len(),
                    m.ml.signer_subject_cn.as_deref().unwrap_or("<unparsed>"),
                    m.trust.describe(),
                    m.eku.describe(),
                    m.basic_constraints.describe(),
                );
            }
            for f in &load_failures {
                eprintln!("  skipped: {f}");
            }
        }

        Ok(IcaoTrustPool { mls: loaded })
    }
}

/// Outcome of verifying the ML signer cert's chain to a pinned
/// ICAO PKD root.
///
/// Computed once per ML load and surfaced in the "ICAO ML
/// loaded" startup line so the operator immediately sees
/// whether the bundle's *signer* (not just structure) is
/// trustworthy.
#[derive(Debug, Clone, Copy)]
pub enum MlSignerTrust {
    /// Signer cert verifies against a pinned root and the
    /// pinned root's SHA-256 cross-check passes.
    Pinned {
        /// Human-readable name of the matching pinned root (e.g.
        /// "ICAO CSCA Master List Signer"). Sourced from the
        /// paired entry in `ICAO_PKD_ROOT_PEMS`; the value is a
        /// compile-time string set so the Tier 0 `&'static str`
        /// is acceptable.
        root_label: &'static str,
    },
    /// Bundled PEM is present but its actual SHA-256 doesn't
    /// match the paired pin -- a tamper signal on the source
    /// tree. Refuse the trust verdict.
    PinHashMismatch,
    /// Signer cert's issuer DN didn't match any pinned root's
    /// subject DN.
    NoMatchingIssuer,
    /// Issuer was found but signer-signed-by-issuer didn't
    /// verify cryptographically.
    SignatureFailed,
}

impl MlSignerTrust {
    /// Render the trust-evaluation outcome as a one-line
    /// human string for the ICAO-PKD load-line report.
    ///
    /// Each variant carries enough context to identify the
    /// failure mode at a glance (pinned root label, hash
    /// mismatch, no matching issuer, signature failure).
    fn describe(&self) -> String {
        match self {
            Self::Pinned { root_label } => format!("signer trusts to pinned {root_label}"),
            Self::PinHashMismatch => {
                "BUNDLED-PIN HASH MISMATCH -- refusing to assert trust".to_owned()
            }
            Self::NoMatchingIssuer => "UNPINNED -- signer's issuer not in trust_roots".to_owned(),
            Self::SignatureFailed => {
                "UNPINNED -- candidate root found but signer signature did not verify".to_owned()
            }
        }
    }
}

/// Doc 9303 §12 Extended Key Usage compliance check on the ML
/// signer cert. Informational alongside [`MlSignerTrust`] for
/// now; failures don't block trust yet.
#[derive(Debug, Clone, Copy)]
pub enum SignerEkuCheck {
    /// EKU extension present, marked critical, contains
    /// `id-icao-mlSigner` (2.23.136.1.1.3).
    Compliant,
    /// EKU extension absent. Doc 9303 §12 requires it.
    ExtensionMissing,
    /// EKU extension present but not marked critical.
    NotCritical,
    /// EKU extension present and critical but doesn't include
    /// `id-icao-mlSigner`.
    MissingMlSignerOid,
}

impl SignerEkuCheck {
    /// One-line human string identifying the EKU compliance
    /// outcome, sourced verbatim into the load-line report.
    ///
    /// ICAO 9303 Part 12 §7.1.4 spells out the requirement
    /// (`id-icao-mlSigner` present, critical); the variant
    /// strings name each failure mode so the operator can
    /// fix it directly.
    const fn describe(self) -> &'static str {
        match self {
            Self::Compliant => "ok (id-icao-mlSigner critical)",
            Self::ExtensionMissing => "MISSING -- Doc 9303 \u{00a7}12 requires EKU on MLS",
            Self::NotCritical => "NOT CRITICAL -- Doc 9303 \u{00a7}12 requires critical EKU",
            Self::MissingMlSignerOid => {
                "WRONG -- EKU present but does not include id-icao-mlSigner"
            }
        }
    }
}

/// Doc 9303 §12 `BasicConstraints` compliance check on the MLS.
#[derive(Debug, Clone, Copy)]
pub enum SignerBasicConstraintsCheck {
    /// CA flag not asserted (extension absent, or present with
    /// CA=false). Either form is acceptable for a leaf MLS.
    Compliant,
    /// CA=true asserted -- non-compliant per Doc 9303 §12.
    CaAsserted,
}

impl SignerBasicConstraintsCheck {
    /// Human label for the MLS `BasicConstraints` outcome.
    ///
    /// ICAO 9303 Part 12 forbids `CA=true` on an MLS leaf cert;
    /// a `Compliant` variant covers both "extension absent"
    /// and "extension present with CA=false" because the
    /// audit reader cares only about whether CA is asserted.
    const fn describe(self) -> &'static str {
        match self {
            Self::Compliant => "ok (CA not asserted)",
            Self::CaAsserted => "FAIL -- BasicConstraints CA=true on MLS cert",
        }
    }
}

/// EF.SOD DER bytes from a parsed eMRTD read.
#[derive(Clone, Copy)]
struct SodDer<'a> {
    /// Borrowed EF.SOD DER from the eMRTD readout.
    bytes: &'a [u8],
}

impl<'a> SodDer<'a> {
    /// Project the optional EF.SOD field out of the typed eMRTD readout.
    fn from_personal_data(data: &'a EmrtdPersonalData) -> Option<Self> {
        data.sod_der.as_deref().map(|bytes| Self { bytes })
    }

    /// Borrow the EF.SOD DER bytes for the CMS parser boundary.
    const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
}

impl CardCheckHelpers {
    /// Classify the ML signer's EKU extension against ICAO 9303
    /// Part 12 §7.1.4.
    ///
    /// Returns the most-specific failure variant in order:
    /// missing -> not critical -> wrong-OID-list. The trust
    /// pipeline (`is_ml_fully_trusted`) only accepts the
    /// `Compliant` variant; other outcomes leave the ML in
    /// the report but exclude its CSCAs.
    fn check_signer_eku(signer: &Certificate<'_>) -> SignerEkuCheck {
        let Some(extensions) = signer.extensions else {
            return SignerEkuCheck::ExtensionMissing;
        };
        let Some(eku) = extract_extended_key_usage_meta(extensions) else {
            return SignerEkuCheck::ExtensionMissing;
        };
        if !eku.critical {
            return SignerEkuCheck::NotCritical;
        }
        if !eku.contains(OID_ICAO_ML_SIGNER) {
            return SignerEkuCheck::MissingMlSignerOid;
        }
        SignerEkuCheck::Compliant
    }
}

impl CardCheckHelpers {
    /// Classify the ML signer's `BasicConstraints` against ICAO
    /// 9303 Part 12 §7.1.3.
    ///
    /// Absent extension and present-with-`CA=false` are both
    /// `Compliant`; only an asserted CA flag fails. The MLS is a
    /// leaf-only cert -- treating it as a CA would let it
    /// issue further certs, breaking the trust model.
    fn check_signer_basic_constraints(signer: &Certificate<'_>) -> SignerBasicConstraintsCheck {
        let Some(extensions) = signer.extensions else {
            return SignerBasicConstraintsCheck::Compliant;
        };
        let bc = extract_basic_constraints(extensions);
        if bc.ca {
            SignerBasicConstraintsCheck::CaAsserted
        } else {
            SignerBasicConstraintsCheck::Compliant
        }
    }
}

/// Verify the ML signer cert chains to a pinned ICAO PKD root.
///
/// Algorithm:
///
/// 1. Cross-check each `ICAO_PKD_ROOT_PEMS` entry's actual
///    SHA-256 against the paired `ICAO_PKD_ROOT_SHA256` pin. A
///    mismatch is a tamper signal; the bundled PEM is ignored
///    for trust purposes but the pin still applies.
/// 2. Walk the ML's `embedded_certs_der` and treat any cert
///    whose SHA-256 matches one of the surviving pins as a
///    candidate root.
/// 3. For each candidate, try
///    `verify_certificate_signed_by(signer, root)`. First
///    success wins.
///
/// Step 2 looks up the root *by fingerprint*, not by DN
/// matching, so it stays robust even when the signer cert's
/// embedded issuer DN encodes string types differently from the
/// bundled PEM's subject DN (which happens in practice -- the
/// bundled "United Nations CSCA 2.pem" encodes some attributes
/// as `UTF8String` whereas the ML-embedded copy encodes them
/// as `PrintableString`).
impl CardCheckHelpers {
    /// Run the three-step pin-based trust check on a Master
    /// List's signer.
    ///
    /// See the module-level comment above for the algorithm.
    /// Key property: the candidate root is identified by
    /// SHA-256 fingerprint, not by DN equality, so the check
    /// survives the practical DN-encoding mismatches that occur
    /// when the bundled root PEM and the ML-embedded root
    /// disagree on `UTF8String` vs `PrintableString`.
    fn check_ml_signer_trust(ml: &IcaoMasterList) -> MlSignerTrust {
        let Ok(signer_owned) = OwnedCert::from_der(&ml.signer_cert_der) else {
            return MlSignerTrust::SignatureFailed;
        };
        let signer = signer_owned.view();
        let mut hash_mismatch = false;
        let mut surviving_pins: Vec<(&str, CertSha256)> = Vec::new();
        for ((label, pem_bytes), (_label_pin, expected_fp)) in
            ICAO_PKD_ROOT_PEMS.iter().zip(ICAO_PKD_ROOT_SHA256.iter())
        {
            match crate::text::decode_cert_pem_or_der(pem_bytes) {
                Some(der) if CertSha256::of(&der) == *expected_fp => {
                    surviving_pins.push((label, *expected_fp));
                }
                Some(_) => {
                    hash_mismatch = true;
                }
                None => {
                    // Couldn't decode the bundled PEM; still keep the
                    // SHA-256 pin alive so an ML that embeds a matching
                    // cert can verify.
                    surviving_pins.push((label, *expected_fp));
                }
            }
        }
        if surviving_pins.is_empty() {
            return if hash_mismatch {
                MlSignerTrust::PinHashMismatch
            } else {
                MlSignerTrust::NoMatchingIssuer
            };
        }
        let mut found_match = false;
        for cand_der in &ml.embedded_certs_der {
            let actual_fp = CertSha256::of(cand_der);
            let Some((root_label, _pin_fp)) =
                surviving_pins.iter().find(|(_, pin)| pin == &actual_fp)
            else {
                continue;
            };
            found_match = true;
            let Ok(root_owned) = OwnedCert::from_der(cand_der) else {
                continue;
            };
            let root = root_owned.view();
            if signer.verify_signed_by(root).is_ok() {
                return MlSignerTrust::Pinned { root_label };
            }
        }
        // If found_match is true at this point, a candidate matched
        // a pinned root by SHA-256 but the signature did NOT verify
        // (we'd have returned MlSignerTrust::Pinned otherwise). The
        // post-loop branch reflects that contract: matched-but-
        // unverified collapses to SignatureFailed.
        if found_match {
            MlSignerTrust::SignatureFailed
        } else {
            MlSignerTrust::NoMatchingIssuer
        }
    }
}

/// Per-card check for one already-probed reader.
///
/// `pick` carries the reader id + identity from the FINEID
/// probe so the per-card section can lead with "we're talking
/// to `identity` in `reader`" before any I/O lands.
///
/// # Errors
/// PC/SC connect failure, mandatory-slot cert-read failure, or
/// `--crl-file` read failure.
/// Read every available cert slot from `transport`. The
/// Authentication slot is mandatory; everything else falls back to
/// a `note:` line if the read fails.
/// Everything in the readout that lives behind the PKCS#15
/// application: token info, every cert slot's DER, and the
/// counter-safe PIN / PUK probes.
///
/// Collected as a unit because the whole block shares one
/// precondition -- the PKCS#15 application must be reachable.
/// On the contact interface that is true straight after connect;
/// over contactless it only becomes true inside a PACE secure
/// channel, and this struct is what
/// [`read_pkcs15_section`] returns from either.
struct Pkcs15Section {
    /// EF.TokenInfo contents; defaulted when unreadable.
    token_info: TokenInfo,
    /// Every provisioned cert slot's DER.
    slot_ders: Vec<(CertSlot, CertDer)>,
    /// Which credential reference numbering the card answered to
    /// (citizen S1 v4.2 vs organizational S4-2 v4.0).
    pin_reference_scheme: PinReferenceScheme,
    /// PIN1 status from the counter-safe probe.
    pin1: Option<PinStatus>,
    /// PIN2 status from the counter-safe probe.
    pin2: Option<PinStatus>,
    /// PUK status from the counter-safe probe.
    puk: Option<PukStatus>,
    /// PIN1 policy counters (max / remaining), when published.
    pin1_policy: Option<CredentialPolicyCounters>,
    /// PIN2 policy counters (max / remaining), when published.
    pin2_policy: Option<CredentialPolicyCounters>,
    /// PUK policy counters (max / remaining), when published.
    puk_policy: Option<CredentialPolicyCounters>,
    /// PIN1 changed-from-issue flag, when the card publishes it.
    pin1_changed: Option<bool>,
    /// PIN2 changed-from-issue flag, when the card publishes it.
    pin2_changed: Option<bool>,
}

/// Reach the PKCS#15 application on `transport` and read the
/// whole gated section from it.
///
/// On the contact interface the application is available
/// straight after connect. Over contactless the card seals it
/// until PACE has run, answering this first SELECT with SW 6982;
/// on that answer the CAN opens a secure channel and the
/// identical readout runs inside it.
///
/// Takes the transport **by value** and drops it on return, so
/// this PKCS#15 session is closed before the caller opens the
/// separate eMRTD one.
///
/// # Errors
/// [`CardCheckError::NeedCan`] when the card is sealed and no CAN
/// was supplied, PACE failures, or a failed authentication-slot
/// cert read.
fn open_pkcs15_section(
    mut transport: refineid_lib_pcsc::PcscCard,
    can: Option<&refineid_lib_core::can::Can>,
) -> Result<Pkcs15Section, CardCheckError> {
    match transport.select_pkcs15_application() {
        Ok(()) => read_pkcs15_section(&mut transport, false),
        Err(Pkcs15Error::Sw(sw))
            if StatusWord::from_u16(sw) == StatusWord::SecurityNotSatisfied =>
        {
            let Some(can) = can else {
                return Err(CardCheckError::NeedCan);
            };
            // Start PACE from a clean card: the probe SELECT above
            // left it outside MF (MSE:Set AT then answers SW 6999),
            // and an earlier failed PACE leaves the CAN suspended,
            // which the card reports exactly like a wrong CAN until
            // it is power-cycled (BSI TR-03110-3 §2.4).
            transport
                .reset()
                .map_err(|e| CardCheckError::Pace(format!("reset before PACE: {e}")))?;
            transport
                .select_mf()
                .map_err(|e| CardCheckError::Pace(format!("SELECT MF before PACE: {e}")))?;
            let session = refineid_lib_core::pace::run_pace_with_can(&mut transport, *can)
                .map_err(|e| pace_err_to_check_error(&e))?;
            let mut sm = SmTransport::new(transport, session);
            sm.select_pkcs15_application()
                .map_err(|e| CardCheckError::Pace(format!("select pkcs15 app under SM: {e}")))?;
            read_pkcs15_section(&mut sm, true)
        }
        Err(e) => Err(CardCheckError::CertRead(format!("select pkcs15 app: {e}"))),
    }
}

/// Read the PKCS#15-gated part of the readout off `transport`.
///
/// Generic over [`CardTransport`] so the identical sequence runs
/// on the plain contact channel and inside a PACE
/// `SmTransport` on contactless -- the ops traits are blanket-
/// implemented for any `CardTransport`, so there is one copy of
/// this choreography, not two.
///
/// # Errors
/// Only a failed **authentication**-slot cert read is fatal
/// (mirroring [`read_all_cert_slots`]); every probe here is
/// best-effort and degrades to `None`.
fn read_pkcs15_section<T: refineid_lib_core::transport::CardTransport>(
    transport: &mut T,
    secure_channel: bool,
) -> Result<Pkcs15Section, CardCheckError> {
    let token_info = transport.read_token_info().unwrap_or_default();
    let slot_ders = read_all_cert_slots(transport, secure_channel)?;
    // PIN status probes (counter-safe empty-Lc VERIFY form).
    // Best-effort; failure surfaces as `None`.
    //
    // The Apple-reference sequence has established that the
    // counter-safe PIN1 and PIN2 VERIFY probes work inside the
    // PACE channel. The PUK GET DATA probe can answer 6988 and
    // make the next protected command fail with 6999, so PUK
    // and the DF.5016-only policy/changed probes stay disabled
    // on a secure channel.
    // The reference numbering is the card's to declare: an
    // organization card (FINEID S4-2 v4.0 §4.2) numbers its
    // credentials by SDO identifier, not the citizen S1 v4.2
    // references. Resolution is itself two counter-safe probes.
    let pin_reference_scheme = transport
        .resolve_pin_reference_scheme()
        .unwrap_or(PinReferenceScheme::Citizen);
    let pin1 = transport
        .pin_status_with_scheme(PinSlot::Pin1, pin_reference_scheme)
        .ok();
    let pin2 = transport
        .pin_status_with_scheme(PinSlot::Pin2, pin_reference_scheme)
        .ok();
    let puk = (!secure_channel)
        .then(|| transport.puk_status_with_scheme(pin_reference_scheme).ok())
        .flatten();
    let pin1_policy = transport.pin_policy_counters(PinSlot::Pin1).ok().flatten();
    let pin2_policy = (!secure_channel)
        .then(|| transport.pin_policy_counters(PinSlot::Pin2).ok().flatten())
        .flatten();
    let puk_policy = (!secure_channel)
        .then(|| transport.puk_policy_counters().ok().flatten())
        .flatten();
    // PIN-changed flag probes (S1 v4.2 §3.15.2; counter-safe GET
    // DATA on the PIN container). Best-effort like pin_status:
    // older firmware that doesn't implement the PIN-info GET DATA
    // surfaces as `None`. `Ok(None)` vs `Err(_)` both collapse to
    // `None` -- we treat the call site as flag-indeterminate.
    let pin1_changed = transport.pin_changed_flag(PinSlot::Pin1).ok().flatten();
    let pin2_changed = (!secure_channel)
        .then(|| transport.pin_changed_flag(PinSlot::Pin2).ok().flatten())
        .flatten();
    if secure_channel {
        eprintln!(
            "note: PUK and DF.5016-only policy counters not probed because \
             that query can end the PACE channel (contactless)"
        );
    }
    Ok(Pkcs15Section {
        token_info,
        slot_ders,
        pin_reference_scheme,
        pin1,
        pin2,
        puk,
        pin1_policy,
        pin2_policy,
        puk_policy,
        pin1_changed,
        pin2_changed,
    })
}

fn read_all_cert_slots<T: refineid_lib_core::transport::CardTransport>(
    transport: &mut T,
    secure_channel: bool,
) -> Result<Vec<(CertSlot, CertDer)>, CardCheckError> {
    let mut slot_ders: Vec<(CertSlot, CertDer)> = Vec::new();
    for slot in CertSlot::all() {
        // Over a PACE channel, reaching a slot via the MF tears
        // the channel down and takes the rest of the readout --
        // including the PIN counters -- with it. Skip those
        // slots rather than trade them for everything else.
        if secure_channel && slot.requires_mf_traversal() {
            eprintln!(
                "note: {} cert not read: reaching it selects the MF, which \
                 ends the PACE channel (contactless)",
                slot.label()
            );
            continue;
        }
        match transport.read_certificate(slot) {
            Ok(der) => slot_ders.push((slot, der)),
            // Absent slot: the SELECT returns FileNotFound (SW 0x6A82),
            // which means "not provisioned" rather than a real failure.
            Err(Pkcs15Error::Sw(sw)) if StatusWord::from_u16(sw) == StatusWord::FileNotFound => {}
            Err(e) => {
                if slot == CertSlot::Authentication {
                    return Err(CardCheckError::CertRead(e.to_string()));
                }
                eprintln!("note: {} cert unavailable: {e}", slot.label());
            }
        }
    }
    Ok(slot_ders)
}

/// Save each `(slot, der)` pair to `dir/EF.<fid>.der`.
fn save_slot_ders(
    dir: &std::path::Path,
    slot_ders: &[(CertSlot, CertDer)],
) -> Result<(), CardCheckError> {
    std::fs::create_dir_all(dir).map_err(|source| CardCheckError::CrlRead {
        path: dir.to_path_buf(),
        source,
    })?;
    for (slot, der) in slot_ders {
        let fid = slot.fid();
        let path = dir.join(format!("EF.{:02x}{:02x}.der", fid[0], fid[1]));
        std::fs::write(&path, der.as_bytes())
            .map_err(|source| CardCheckError::CrlRead { path, source })?;
    }
    Ok(())
}

/// Optional eMRTD personal-data read against a second transport
/// session. Returns `(Some(data), None)` on success, `(None,
/// Some(message))` on read failure, and `(None, None)` when no
/// CAN is configured.
fn read_emrtd_section_for(
    backend: PcscBackend,
    reader_id: &refineid_lib_core::backend::ReaderId,
    can: Option<refineid_lib_core::can::Can>,
) -> (Option<EmrtdPersonalData>, Option<String>) {
    let Some(can) = can else {
        return (None, None);
    };
    match backend.open_session(reader_id, ReaderAccessCap::Read) {
        Ok(transport) => match read_personal_data(transport, can) {
            Ok(data) => (Some(data), None),
            Err(EmrtdError::BadCan) => (
                None,
                Some(
                    "CAN did not match this card -- verify the printed CAN on the card front"
                        .to_owned(),
                ),
            ),
            Err(e) => (None, Some(format!("{e}"))),
        },
        Err(e) => (None, Some(format!("PC/SC: {e}"))),
    }
}

/// Run the full `card check` flow against one reader the
/// FINEID-aware picker already confirmed.
///
/// Two transport sessions:
///
///   1. PKCS#15 session for ATR, `CardAccess`, `TokenInfo`, every
///      cert slot's DER, and PIN1 / PIN2 retry-counter probes.
///   2. Optional eMRTD session (DG1/2/11/12/14, SOD). Separate
///      open because PACE consumes a fresh card state and we
///      want the rest of the report to ship even if the eMRTD
///      read fails (wrong CAN, missing card profile, etc.).
///
/// The optional DSC->CSCA hop runs only when both an ICAO PKD
/// trust pool is supplied and the eMRTD read produced a SOD;
/// otherwise the field stays `None`.
pub(crate) fn check_for_reader(
    backend: PcscBackend,
    pick: FineidReaderPick,
    options: &CardCheckOptions<'_>,
    icao_pkd: Option<&IcaoTrustPool>,
) -> Result<CardCheckReport, CardCheckError> {
    let FineidReaderPick {
        reader_id,
        identity,
    } = pick;

    // PKCS#15 session: ATR + CardAccess + TokenInfo + every
    // cert slot's DER + PIN1 / PIN2 probes. One transport open,
    // one drop.
    let mut transport = backend.open_session(&reader_id, ReaderAccessCap::Read)?;
    // Diagnostic readout: show the parsed ATR's wire bytes, or the
    // parse error inline (never fatal -- this is a readout).
    let atr_hex = refineid_lib_core::transport::CardTransport::atr(&transport).map_or_else(
        |e| format!("<unparseable: {e}>"),
        |atr| hex::encode(atr.to_wire_bytes()),
    );
    let card_access = transport.read_card_access().unwrap_or_default();

    let pre_fetched_crl: Option<Vec<u8>> = match &options.crl_file {
        Some(path) => Some(
            std::fs::read(path).map_err(|source| CardCheckError::CrlRead {
                path: path.clone(),
                source,
            })?,
        ),
        None => None,
    };

    let now = options.now.unwrap_or_else(now_date_time);

    let section = open_pkcs15_section(transport, options.can)?;
    let Pkcs15Section {
        token_info,
        slot_ders,
        pin_reference_scheme,
        pin1,
        pin2,
        puk,
        pin1_policy,
        pin2_policy,
        puk_policy,
        pin1_changed,
        pin2_changed,
    } = section;

    if let Some(dir) = &options.save_cert_dir {
        save_slot_ders(dir, &slot_ders)?;
    }

    let root_der: Option<&CertDer> = slot_ders
        .iter()
        .find(|(s, _)| *s == CertSlot::RootCa)
        .map(|(_, der)| der);
    let root_trusted: bool =
        root_der.is_some_and(|der| is_pinned_root(CertSha256::of(der.as_bytes())));
    let root_cert_owned: Option<OwnedCert> =
        root_der.and_then(|der| OwnedCert::from_der(der.as_bytes()).ok());
    let root = root_cert_owned.as_ref().map(|cert| OnCardRoot {
        cert,
        trusted: root_trusted,
    });

    let ctx = VerifyContext {
        offline: options.offline,
        now,
        pre_fetched_crl: pre_fetched_crl.as_deref(),
        root,
    };
    let mut certs = Vec::new();
    for (slot, der) in &slot_ders {
        certs.push(build_cert_report(*slot, der, &ctx)?);
    }

    // Optional eMRTD section. Separate transport session because
    // PACE consumes a clean card state, and we want the rest of
    // the report to ship even if the eMRTD read fails (e.g.
    // BadCan against a wrong-card guess in multi-card mode).
    let (emrtd, emrtd_error) = read_emrtd_section_for(backend, &reader_id, options.can.copied());

    // DSC -> CSCA hop, gated on both an ICAO PKD pool being
    // supplied *and* the eMRTD read having produced a usable SOD.
    let dsc_csca_check = match (icao_pkd, emrtd.as_ref()) {
        (Some(pool), Some(data)) => Some(CardCheckHelpers::run_dsc_csca_check(data, pool)),
        _ => None,
    };

    Ok(CardCheckReport {
        reader: reader_id.as_str().to_owned(),
        identity,
        atr_hex,
        token_info,
        card_access,
        certs,
        pin_reference_scheme,
        pin1,
        pin2,
        puk,
        pin1_policy,
        pin2_policy,
        puk_policy,
        pin1_changed,
        pin2_changed,
        emrtd,
        emrtd_error,
        dsc_csca_check,
    })
}

/// Look up the DSC in the SOD, try to verify it against the
/// combined pool of trusted CSCAs. Returns one of the
/// [`DscCscaCheck`] variants without ever failing the whole
/// report -- the result is informational.
impl CardCheckHelpers {
    /// Resolve the DSC inside the SOD and verify its signature
    /// against the trust pool's CSCAs.
    ///
    /// Steps:
    ///   1. Parse SOD `SignedData`; the first embedded cert is
    ///      the DSC (ICAO 9303 Part 10 §4.6.2.2).
    ///   2. Apply the Doc 9303 §7.1.1 DSC `keyUsage` gate; a
    ///      non-compliant DSC short-circuits the chain walk.
    ///   3. Filter trusted CSCAs by ISO country; refuse the
    ///      chain if the DSC's issuing country has no CSCA in
    ///      the pool.
    ///   4. Try each candidate (DN equality first, then signature
    ///      verification). First success wins.
    ///
    /// Returns one of the [`DscCscaCheck`] variants; never
    /// fails the surrounding report.
    fn run_dsc_csca_check(data: &EmrtdPersonalData, pool: &IcaoTrustPool) -> DscCscaCheck {
        // The DSC -> CSCA verdict depends only on the EF.SOD bytes,
        // so delegate to the narrower [`Self::dsc_csca_check_for_sod`].
        // The narrower signature is both the honest dependency and the
        // unit-testable surface (no need to build a whole
        // `EmrtdPersonalData` to exercise the chain walk).
        Self::dsc_csca_check_for_sod(SodDer::from_personal_data(data), pool)
    }

    /// Resolve the DSC inside `sod_der` (the EF.SOD CMS `SignedData`
    /// bytes) and verify its signature against the trust pool's
    /// CSCAs.
    ///
    /// Carries the full algorithm documented on
    /// [`Self::run_dsc_csca_check`]; the wrapper exists only to
    /// project an [`EmrtdPersonalData`] down to its EF.SOD bytes.
    fn dsc_csca_check_for_sod(sod_der: Option<SodDer<'_>>, pool: &IcaoTrustPool) -> DscCscaCheck {
        let Some(sod) = sod_der else {
            return DscCscaCheck::NoDscInSod;
        };
        let Ok(signed_owned) = refineid_lib_core::cms::OwnedSignedData::from_der(sod.as_bytes())
        else {
            return DscCscaCheck::NoDscInSod;
        };
        let signed = signed_owned.view();
        let Some(dsc_der) = signed.certificates_der.first() else {
            return DscCscaCheck::NoDscInSod;
        };
        let Ok(dsc_owned) = OwnedCert::from_der(dsc_der) else {
            return DscCscaCheck::DscParseFailed;
        };
        let dsc = dsc_owned.view();

        // Doc 9303 §7.1.1 KeyUsage compliance is a precondition on
        // the DSC -- a non-compliant DSC fails PA regardless of
        // which CSCA issued it. Short-circuit before the chain walk.
        let ku = Self::check_dsc_key_usage(&dsc);
        if !matches!(ku, DscKeyUsageCheck::Compliant) {
            return DscCscaCheck::KeyUsageNonCompliant(ku);
        }

        let Some(country) = dsc.issuer.country() else {
            return DscCscaCheck::DscCountryUnknown;
        };

        let candidates: Vec<&CscaEntry> = pool
            .trusted_cscas()
            .filter(|c| c.country_iso.as_ref() == Some(&country))
            .collect();
        if candidates.is_empty() {
            return DscCscaCheck::CountryAbsent {
                country_iso: country,
            };
        }

        for cand in &candidates {
            let Ok(csca_cert_owned) = OwnedCert::from_der(&cand.der) else {
                continue;
            };
            let csca_cert = csca_cert_owned.view();
            if csca_cert.subject != dsc.issuer {
                continue;
            }
            if dsc.verify_signed_by(csca_cert).is_ok() {
                return DscCscaCheck::Ok {
                    csca_subject_cn: cand.subject_cn.clone(),
                    csca_country: cand.country_iso.clone(),
                    csca_sha256: cand.sha256,
                };
            }
        }
        DscCscaCheck::NoMatch {
            country_iso: country,
            candidates: candidates.len(),
        }
    }
}

/// Parsed AIA caIssuers certificate fetched for a leaf slot.
struct AiaIssuerCert {
    /// Owning parse of the fetched caIssuers DER.
    cert: OwnedCert,
}

impl AiaIssuerCert {
    /// Parse fetched AIA caIssuers DER into an owning certificate.
    fn from_der(bytes: &[u8]) -> Result<Self, String> {
        OwnedCert::from_der(bytes)
            .map(|cert| Self { cert })
            .map_err(|e| e.to_string())
    }

    /// Borrow the parsed certificate view.
    fn view(&self) -> Certificate<'_> {
        self.cert.view()
    }
}

/// Fetch/parse state for the AIA caIssuers certificate.
enum AiaIssuerCertStatus {
    /// No caIssuers bytes were fetched for this slot.
    Unavailable,
    /// Fetched bytes did not parse as a certificate.
    ParseFailed(String),
    /// Fetched bytes parsed into a certificate.
    Parsed(AiaIssuerCert),
}

/// Parsed on-card root plus its pinning verdict.
#[derive(Clone, Copy)]
struct OnCardRoot<'a> {
    /// Parsed root certificate read from the card.
    cert: &'a OwnedCert,
    /// Whether the root matched the pinned DVV trust anchors.
    trusted: bool,
}

/// Per-card verify-time inputs shared across the cert reports.
///
/// Built once at the start of [`check_for_reader`] and threaded
/// through every [`build_cert_report`] call so each per-slot
/// report sees the same wall-clock time, CRL bytes, on-card
/// root, and offline policy.
struct VerifyContext<'a> {
    /// Refuse network calls (OCSP, CRL fetch). Pinned to
    /// CLI `--offline`. Pre-fetched data still applies.
    offline: bool,
    /// Snapshot of "now" used by every validity check; defaults
    /// to wall clock at session start so a long-running scan
    /// doesn't drift across slots.
    now: DateTime,
    /// Bytes of a CRL pre-fetched from `--crl-file PATH`, if
    /// any. Shared so multiple slots issued by the same CA
    /// don't re-parse the CRL.
    pre_fetched_crl: Option<&'a [u8]>,
    /// Parsed on-card root CA cert (`EF.4334`), when present, plus
    /// the pinning verdict needed before it can anchor a chain.
    root: Option<OnCardRoot<'a>>,
}

use refineid_lib_core::crypto::digest::Sha256 as CertSha256;

/// Build one [`CertReport`] entry for a slot whose DER bytes
/// have already been read off the card.
///
/// Aggregates everything the report needs to display per slot:
/// subject/issuer CN, serial, SHA-256 fingerprint, signature
/// algorithm, key algorithm, AIA/CDP/SAN extensions, key
/// usage, EKU, validity, OCSP / CRL outcomes, and revocation
/// status. `ctx` carries the per-card invariants
/// (`now`, root, offline policy) so each call works against the
/// same reference clock.
fn build_cert_report(
    slot: CertSlot,
    der: &CertDer,
    ctx: &VerifyContext<'_>,
) -> Result<CertReport, CardCheckError> {
    let cert_owned = OwnedCert::from_der(der.as_bytes())
        .map_err(|e| CardCheckError::CertParse(e.to_string()))?;
    let cert = cert_owned.view();
    let subject_cn = cert.subject.common_name();
    let issuer_cn = cert.issuer.common_name();
    let serial = cert.serial();
    let sha256 = CertSha256::of(der.as_bytes());
    let signature_alg = SignatureAlgorithm::from_oid(cert.signature_alg_oid.as_bytes());

    let key_alg = parse_subject_public_key_info(cert.spki.as_der());
    let (crl_urls, ocsp_urls, ca_issuers_urls, san_emails, key_usage, eku) =
        cert.extensions.map_or_else(
            || {
                (
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    None,
                    Vec::new(),
                )
            },
            |exts| {
                (
                    extract_crl_distribution_urls(exts),
                    extract_ocsp_urls(exts),
                    extract_ca_issuers_urls(exts),
                    extract_subject_alt_emails(exts),
                    extract_key_usage(exts),
                    extract_extended_key_usage(exts),
                )
            },
        );

    let issuer_cert = if slot == CertSlot::RootCa || ctx.offline {
        AiaIssuerCertStatus::Unavailable
    } else if let Some(url) = ca_issuers_urls.first() {
        http::get(url, SMALL_HTTP_MAX_BYTES, user_agent::honest()).map_or(
            AiaIssuerCertStatus::Unavailable,
            |bytes| match AiaIssuerCert::from_der(&bytes) {
                Ok(cert) => AiaIssuerCertStatus::Parsed(cert),
                Err(e) => AiaIssuerCertStatus::ParseFailed(e),
            },
        )
    } else {
        AiaIssuerCertStatus::Unavailable
    };

    let chain_check = if slot == CertSlot::RootCa {
        None
    } else if ctx.offline {
        Some(SignatureCheck::Skipped("offline".to_owned()))
    } else {
        Some(run_chain_check(&cert, &issuer_cert, ctx))
    };

    let crl_check = if ctx.offline || slot == CertSlot::RootCa {
        None
    } else {
        run_crl_check(&cert, &crl_urls, ctx, &issuer_cert)
    };
    let ocsp_check = if ctx.offline || slot == CertSlot::RootCa {
        None
    } else {
        run_ocsp_check(&cert, &ocsp_urls, &issuer_cert, ctx)?
    };

    let days_until_expiry = days_between(ctx.now, cert.not_after);

    Ok(CertReport {
        slot,
        subject_cn,
        issuer_cn,
        serial,
        sha256,
        not_before: cert.not_before,
        not_after: cert.not_after,
        days_until_expiry,
        key_alg,
        key_usage,
        eku,
        crl_urls,
        ocsp_urls,
        ca_issuers_urls,
        san_emails,
        signature_alg,
        chain_check,
        crl_check,
        ocsp_check,
    })
}

/// Verify the leaf-cert chain to a pinned trust anchor.
///
/// FINEID S4-1 v4.2 §4.5 stipulates both the DVV root and the
/// issuing intermediate sit in the card's MF; this verifier
/// uses them first. On dual-algorithm cards the on-card root
/// may use a different signature algorithm than the
/// intermediate, in which case we fall back to the matching
/// pinned root from [`crate::trust_roots::PINNED_ROOT_DER`].
///
/// Returns the most-specific outcome:
/// `Skipped` when there's no fetched intermediate or the on-
/// card root isn't pinned, `Failed` when a verify step
/// returns an error, `Ok` only when every hop verifies and
/// the terminal anchor is pinned.
fn run_chain_check(
    leaf: &Certificate<'_>,
    intermediate_cert: &AiaIssuerCertStatus,
    ctx: &VerifyContext<'_>,
) -> SignatureCheck {
    let intermediate_owned = match intermediate_cert {
        AiaIssuerCertStatus::Parsed(cert) => cert,
        AiaIssuerCertStatus::Unavailable => {
            return SignatureCheck::Skipped("no AIA caIssuers cert fetched".to_owned());
        }
        AiaIssuerCertStatus::ParseFailed(e) => {
            return SignatureCheck::Skipped(format!("intermediate parse: {e}"));
        }
    };
    let intermediate = intermediate_owned.view();
    if let Err(e) = leaf.verify_signed_by(intermediate) {
        return SignatureCheck::Failed(format!("leaf -> intermediate: {e}"));
    }
    // Try the on-card root first; that's the path the spec
    // intends (S4-1 v4.2 §4.5: "DVV Root certificate and issuing
    // intermediate CA shall be stored into the FINEID application
    // on the token"). On dual-algorithm cards where the on-card
    // root doesn't match the intermediate's signature alg, fall
    // back to the matching embedded pinned root from
    // `crate::trust_roots::PINNED_ROOT_DER`.
    if let Some(root) = ctx.root {
        match intermediate.verify_signed_by(root.cert.view()) {
            Ok(()) => {
                if !root.trusted {
                    return SignatureCheck::Skipped(
                        "chain verified, but on-card root is not in PINNED_ROOT_SHA256".to_owned(),
                    );
                }
                return SignatureCheck::Ok;
            }
            Err(_e) => {
                // Fall through to the pinned-root fallback below.
            }
        }
    }
    // Pinned-root fallback. Try every embedded DVV root DER
    // against the intermediate -- the right one verifies, the
    // wrong one rejects on algorithm mismatch or signature
    // verify. This covers the S4-1 v4.2 §4.5 case where the
    // card only stores the primary root and the chain needs
    // the secondary (other-algorithm) root.
    for (_label, root_der) in crate::trust_roots::PINNED_ROOT_DER {
        let Ok(root_owned) = OwnedCert::from_der(root_der) else {
            continue;
        };
        if intermediate.verify_signed_by(root_owned.view()).is_ok() {
            // Pinned by SHA-256 already: the embedded DER's
            // fingerprint is in PINNED_ROOT_SHA256 by
            // construction (tests in trust_roots verify the
            // pair stays consistent).
            return SignatureCheck::Ok;
        }
    }
    if ctx.root.is_none() {
        SignatureCheck::Skipped(
            "leaf -> intermediate verified, but no trust anchor matched (on-card root \
             absent and no pinned root DER matched the intermediate's signature alg)"
                .to_owned(),
        )
    } else {
        SignatureCheck::Failed(
            "intermediate -> root: no trust anchor verified (tried on-card root + every pinned \
             PINNED_ROOT_DER entry)"
                .to_owned(),
        )
    }
}

/// Look up `cert` in the cert's CRL distribution point.
///
/// RFC 5280 §5 -- CRL retrieval is at most one HTTP GET per
/// run; the first URL from the CDP is tried, with a
/// pre-fetched local file taking precedence. The CRL is
/// signature-verified against the issuer before its
/// `revokedCertificates` list is consulted. Returns `None`
/// when there's no CRL source to consult; otherwise one of
/// the [`CheckOutcome`] variants describing the lookup.
fn run_crl_check(
    cert: &Certificate<'_>,
    crl_urls: &[refineid_lib_core::text::Uri],
    ctx: &VerifyContext<'_>,
    issuer_cert: &AiaIssuerCertStatus,
) -> Option<CheckOutcome> {
    let (source, bytes) = if let Some(b) = ctx.pre_fetched_crl {
        ("(pre-fetched file)".to_owned(), b.to_vec())
    } else {
        let url = crl_urls.first()?;
        match http::get(url, CRL_MAX_BYTES, user_agent::honest()) {
            Ok(b) => (url.to_string(), b),
            Err(e) => {
                return Some(CheckOutcome::Skipped {
                    source: url.to_string(),
                    why: format!("fetch failed: {e}"),
                });
            }
        }
    };
    let crl_owned = match OwnedCrl::from_der(&bytes) {
        Ok(c) => c,
        Err(e) => {
            return Some(CheckOutcome::Skipped {
                source,
                why: format!("CRL parse: {e}"),
            });
        }
    };
    let crl = crl_owned.view();
    // Trust by construction: verify the CRL signature FIRST. The
    // revocation list can only be consulted via the resulting
    // VerifiedCrl, so an unverifiable CRL yields no status (Skipped).
    let verified = match verify_crl(&crl, issuer_cert) {
        Ok(v) => v,
        Err(why) => return Some(CheckOutcome::Skipped { source, why }),
    };
    Some(CheckOutcome::Status {
        source,
        status: check_against_crl(*cert, &verified, ctx.now),
        signature: SignatureCheck::Ok,
        nonce: None,
    })
}

/// Verify a CRL's signature against its claimed issuer and return
/// the [`refineid_lib_core::crl::VerifiedCrl`] -- the only handle
/// from which a revocation list can be consulted.
///
/// RFC 5280 §5.1.1.2. Requires DN equality between CRL issuer and
/// the supplied issuer cert's subject before the cryptographic
/// verify -- a CRL whose issuer doesn't match the chain's
/// intermediate is by definition not the right CRL to consult.
fn verify_crl<'a>(
    crl: &refineid_lib_core::crl::Crl<'a>,
    issuer_cert: &AiaIssuerCertStatus,
) -> Result<refineid_lib_core::crl::VerifiedCrl<'a>, String> {
    let issuer_owned = match issuer_cert {
        AiaIssuerCertStatus::Parsed(cert) => cert,
        AiaIssuerCertStatus::Unavailable => {
            return Err("no AIA caIssuers cert to verify against".to_owned());
        }
        AiaIssuerCertStatus::ParseFailed(e) => return Err(format!("intermediate parse: {e}")),
    };
    let issuer = issuer_owned.view();
    if crl.issuer != issuer.subject {
        return Err("CRL issuer DN does not match AIA intermediate's subject".to_owned());
    }
    refineid_lib_core::crl::VerifiedCrl::verify(crl, issuer).map_err(|e| format!("{e}"))
}

/// Issue an OCSP query for `cert` against its responder URL.
///
/// RFC 6960 + RFC 8954 (nonce). One HTTP POST per call; the
/// request includes a 16-byte fresh nonce when the OS RNG is
/// available so responders that echo nonces (RFC 8954
/// requires support) defeat replay of a stale signed
/// response. Returns `None` when the cert has no OCSP URL.
/// Surfaces every failure mode (parse, transport, signature,
/// nonce mismatch) as a structured [`CheckOutcome`] so the
/// report can attribute the outcome to a specific cause.
fn run_ocsp_check(
    cert: &Certificate<'_>,
    ocsp_urls: &[refineid_lib_core::text::Uri],
    issuer_cert: &AiaIssuerCertStatus,
    ctx: &VerifyContext<'_>,
) -> Result<Option<CheckOutcome>, CardCheckError> {
    let Some(first_url) = ocsp_urls.first() else {
        return Ok(None);
    };
    let ocsp_url = first_url.to_string();
    let issuer_cert_owned = match issuer_cert {
        AiaIssuerCertStatus::Parsed(cert) => cert,
        AiaIssuerCertStatus::Unavailable => {
            return Ok(Some(CheckOutcome::Skipped {
                source: ocsp_url,
                why: "no AIA caIssuers cert; cannot derive issuer key hash".to_owned(),
            }));
        }
        AiaIssuerCertStatus::ParseFailed(e) => {
            return Ok(Some(CheckOutcome::Skipped {
                source: ocsp_url,
                why: format!("issuer parse: {e}"),
            }));
        }
    };
    let issuer_cert = issuer_cert_owned.view();
    // Typed flow: the validated SpkiDer yields the issuer-key hash
    // directly (total -- the raw key bytes never surface as a `&[u8]`
    // here, and there is no "did not parse" branch: the SpkiDer in
    // `issuer_cert.spki` was validated when the issuer cert parsed).
    let key_hash = ocsp::IssuerKeyHash::from_subject_public_key(&issuer_cert.spki);
    let name_hash = CardCheckHelpers::issuer_name_hash(&cert.issuer);
    let serial = cert.serial();
    // A dead OS RNG means nothing on this host can be trusted: abort the
    // whole check rather than send a replayable, nonce-less request. Same
    // fail-closed posture as the PACE / AA / CA draws in lib-core.
    let nonce = ocsp::OcspNonce::random().map_err(|e| CardCheckError::Rng(e.to_string()))?;
    let request = ocsp::build_request_with_nonce(name_hash, key_hash, &serial, &nonce);
    let body = match http::post(
        first_url,
        "application/ocsp-request",
        request.as_der(),
        SMALL_HTTP_MAX_BYTES,
        user_agent::honest(),
    ) {
        Ok(b) => b,
        Err(e) => {
            return Ok(Some(CheckOutcome::Skipped {
                source: ocsp_url,
                why: format!("OCSP POST: {e}"),
            }));
        }
    };
    let response_owned = match ocsp::OwnedOcspResponse::from_der(&body) {
        Ok(r) => r,
        Err(e) => {
            return Ok(Some(CheckOutcome::Skipped {
                source: ocsp_url,
                why: format!("OCSP parse: {e}"),
            }));
        }
    };
    let response = response_owned.view();
    if response.status != OcspResponseStatus::Successful {
        return Ok(Some(CheckOutcome::Skipped {
            source: ocsp_url,
            why: format!("OCSP responseStatus: {:?}", response.status),
        }));
    }
    let Some(basic) = response.basic.as_ref() else {
        return Ok(Some(CheckOutcome::Skipped {
            source: ocsp_url,
            why: "OCSP response was not basic-OCSP".to_owned(),
        }));
    };
    // Trust by construction: verify the responder signature FIRST.
    // A revocation status can only be read from the resulting
    // VerifiedOcspResponse, so an unverifiable reply yields no status
    // at all (Skipped) -- never a "good status, signature failed".
    let verified = match verify_ocsp_response(basic, &issuer_cert) {
        Ok(v) => v,
        Err(why) => {
            return Ok(Some(CheckOutcome::Skipped {
                source: ocsp_url,
                why: format!("OCSP signature: {why}"),
            }));
        }
    };
    Ok(Some(CheckOutcome::Status {
        source: ocsp_url,
        status: check_against_ocsp_response(*cert, &verified, ctx.now),
        signature: SignatureCheck::Ok,
        nonce: Some(ocsp_nonce_check(&nonce, basic)),
    }))
}

/// Compare the OCSP responder's echoed nonce against the one we
/// sent (RFC 8954), reporting Ok / mismatch / skipped.
fn ocsp_nonce_check(
    nonce: &ocsp::OcspNonce,
    basic: &ocsp::BasicOcspResponse<'_>,
) -> SignatureCheck {
    let echoed = basic.nonce.as_deref();
    match echoed {
        Some(returned) if returned == nonce.as_bytes() => SignatureCheck::Ok,
        Some(returned) => SignatureCheck::Failed(format!(
            "nonce mismatch: sent {} got {}",
            hex::encode(nonce.as_bytes()),
            hex::encode(returned)
        )),
        None => SignatureCheck::Skipped(
            "responder did not echo the nonce (RFC 8954 makes it optional)".to_owned(),
        ),
    }
}

/// Verify the OCSP responder signature and return the
/// [`ocsp::VerifiedOcspResponse`] -- the only handle from which a
/// revocation status can be read.
///
/// RFC 6960 §4.2.2.2. The responder may sign directly with the CA
/// key, or with a delegated cert the CA has cross-signed. Both
/// paths are tried: first the issuer's public key, then every cert
/// embedded in the response (checking it chains to the issuer
/// before trusting its signature).
fn verify_ocsp_response<'a>(
    basic: &ocsp::BasicOcspResponse<'a>,
    issuer: &Certificate<'_>,
) -> Result<ocsp::VerifiedOcspResponse<'a>, String> {
    if let Ok(verified) = ocsp::VerifiedOcspResponse::verify(basic, *issuer, *issuer) {
        return Ok(verified);
    }
    for embedded_der in &basic.embedded_cert_ders {
        let Ok(embedded_owned) = OwnedCert::from_der(embedded_der) else {
            continue;
        };
        let embedded = embedded_owned.view();
        if let Ok(verified) = ocsp::VerifiedOcspResponse::verify(basic, embedded, *issuer) {
            return Ok(verified);
        }
    }
    Err("response signature did not verify against CA or any embedded responder cert".to_owned())
}

impl CardCheckHelpers {
    /// SHA-1 of a certificate issuer name as an OCSP `IssuerNameHash`.
    fn issuer_name_hash(issuer: &Name<'_>) -> ocsp::IssuerNameHash {
        let mut h = <Sha1 as Sha1Digest>::new();
        h.update(issuer.as_der());
        let out = h.finalize();
        let mut buf = [0_u8; SHA1_OUTPUT_LEN];
        buf.copy_from_slice(&out);
        ocsp::IssuerNameHash::new(buf)
    }
}

/// Days from `a` to `b` (positive when `b` is in the future).
#[must_use]
#[expect(
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    reason = "der::DateTime is bounded to year 9999, so its Unix-second count fits i64; the difference and /86400 cannot overflow."
)]
pub fn days_between(a: DateTime, b: DateTime) -> i64 {
    let secs = |t: DateTime| i64::try_from(t.unix_duration().as_secs()).unwrap_or(i64::MAX);
    (secs(b) - secs(a)) / 86_400
}

/// The current system-clock instant as a UTC [`DateTime`].
///
/// Total by saturation: a pre-1970 clock maps to the Unix epoch, a
/// post-9999 clock to [`DateTime::INFINITY`] -- neither reachable on
/// a sane host.
#[must_use]
pub fn now_date_time() -> DateTime {
    use core::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    DateTime::from_unix_duration(Duration::from_secs(secs)).unwrap_or(DateTime::INFINITY)
}

// ---------- Display ----------

impl CardCheckReport {
    /// Write the "Reader & card" header section (reader id,
    /// ATR, card serial).
    ///
    /// First section in the `Display` output; comes before any
    /// trust-relevant data so the reader knows which physical
    /// card the rest of the report describes.
    fn fmt_reader_card(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Reader & card ===")?;
        writeln!(f, "reader:           {}", self.reader)?;
        writeln!(f, "ATR:              {}", self.atr_hex)?;
        if let Some(serial) = self.identity.best_serial() {
            writeln!(f, "card serial:      {serial}")?;
        }
        writeln!(f)
    }

    /// Write the "Identity" section listing the cardholder
    /// attributes extracted from the auth-cert subject DN
    /// (CN, given/family name, FINUID, etc.).
    ///
    /// Reads `(no auth-cert subject readable)` when the
    /// identity probe couldn't parse anything -- a malformed
    /// auth cert or no auth slot.
    fn fmt_identity(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Identity ===")?;
        if self.identity.is_empty() {
            writeln!(f, "(no auth-cert subject readable)")?;
        } else {
            writeln!(f, "{}", self.identity.to_kv_string())?;
        }
        writeln!(f)
    }

    /// Write the "Card metadata (PKCS#15)" section: token-info
    /// label, manufacturer id, and each `SecurityInfo` from
    /// EF.CardAccess (PACE protocol/version/parameter).
    ///
    /// EF.CardAccess is read at session open without
    /// authentication; this section therefore lights up even
    /// when the cardholder hasn't entered a PIN/CAN yet.
    fn fmt_card_metadata(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Card metadata (PKCS#15) ===")?;
        if let Some(label) = &self.token_info.label {
            writeln!(f, "label:            {label}")?;
        }
        if let Some(manuf) = &self.token_info.manufacturer_id {
            writeln!(f, "manufacturer:     {manuf}")?;
        }
        for info in &self.card_access.security_infos {
            writeln!(
                f,
                "PACE protocol:    {} v{} ({})",
                info.protocol.label(),
                info.version,
                info.parameter_label()
            )?;
        }
        writeln!(f)
    }

    /// Write the "Cert slots" section: one block per
    /// `CertReport` (auth, signature, alt slots, root).
    ///
    /// Blank-separated between entries so the operator can
    /// visually slice the output by slot when scanning across
    /// multiple cards. `(no certificates)` reads when the slot
    /// scan returned an empty list.
    fn fmt_cert_slots(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Cert slots ===")?;
        if self.certs.is_empty() {
            writeln!(f, "(no certificates)")?;
        }
        for (i, c) in self.certs.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            writeln!(f, "[cert {}: {}]", i.saturating_add(1), c.slot.label())?;
            write!(f, "{c}")?;
        }
        writeln!(f)
    }

    /// Write the retry-counter section for PIN1, PIN2, and the
    /// shared PUK, plus the PIN-changed flags.
    ///
    /// The retry-counter probe uses the counter-safe empty-Lc
    /// VERIFY form per FINEID S1 v4.2 §3.5.4, so this
    /// section is safe to run on every `card check` -- it
    /// never decrements the counter.
    fn fmt_pin_counters(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== PIN retry counters ===")?;
        writeln!(
            f,
            "PIN references:           {}",
            match self.pin_reference_scheme {
                PinReferenceScheme::Citizen => "citizen (FINEID S1)",
                PinReferenceScheme::Organizational => "organizational (FINEID S4-2)",
            }
        )?;
        writeln!(
            f,
            "PIN1 (auth):              {} (changed since manufacture: {}; usage: {}; unblocks: {})",
            CardCheckHelpers::render_pin_status(self.pin1.as_ref()),
            CardCheckHelpers::render_pin_changed(self.pin1_changed),
            CardCheckHelpers::render_usage_counter(self.pin1_policy.as_ref()),
            CardCheckHelpers::render_unblocking_counter(self.pin1_policy.as_ref()),
        )?;
        writeln!(
            f,
            "PIN2 (qualified-sig):     {} (changed since manufacture: {}; usage: {}; unblocks: {})",
            CardCheckHelpers::render_pin_status(self.pin2.as_ref()),
            CardCheckHelpers::render_pin_changed(self.pin2_changed),
            CardCheckHelpers::render_usage_counter(self.pin2_policy.as_ref()),
            CardCheckHelpers::render_unblocking_counter(self.pin2_policy.as_ref()),
        )?;
        writeln!(
            f,
            "PUK (shared recovery):    {} (usage: {})",
            CardCheckHelpers::render_puk_status(self.puk.as_ref()),
            CardCheckHelpers::render_usage_counter(self.puk_policy.as_ref()),
        )
    }

    /// Write the optional eMRTD section (MRZ, DG11/12 fields,
    /// images, DSC->CSCA outcome).
    ///
    /// Three states: present + parsed (emit the full eMRTD
    /// block), absent + error (emit a "FAILED:" line so the
    /// operator can see the read failed), absent + no error
    /// (emit nothing -- the section is opt-in).
    fn fmt_emrtd_block(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.emrtd, &self.emrtd_error) {
            (Some(emrtd), _) => {
                writeln!(f)?;
                CardCheckHelpers::write_emrtd_section(f, emrtd)?;
                if let Some(check) = &self.dsc_csca_check {
                    writeln!(
                        f,
                        "DSC -> CSCA:         {}",
                        CardCheckHelpers::render_dsc_csca(check)
                    )?;
                }
                Ok(())
            }
            (None, Some(err)) => {
                writeln!(f)?;
                writeln!(f, "=== eMRTD (read via PACE / --can) ===")?;
                writeln!(f, "FAILED: {err}")
            }
            (None, None) => Ok(()),
        }
    }
}

impl fmt::Display for CardCheckReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_reader_card(f)?;
        self.fmt_identity(f)?;
        self.fmt_card_metadata(f)?;
        self.fmt_cert_slots(f)?;
        self.fmt_pin_counters(f)?;
        self.fmt_emrtd_block(f)
    }
}

impl CardCheckHelpers {
    /// Render the DSC->CSCA verification outcome as a one-line
    /// human string for the eMRTD section.
    ///
    /// Each variant produces a different shape so the operator
    /// can immediately see whether trust closed, which CSCA
    /// did the closing, and (on failure) why -- DSC keyUsage
    /// non-compliance, no matching CSCA, missing country, no
    /// DSC in SOD, etc.
    fn render_dsc_csca(check: &DscCscaCheck) -> String {
        match check {
            DscCscaCheck::Ok {
                csca_subject_cn,
                csca_country,
                csca_sha256,
            } => format!(
                "ok via {} ({}) sha256 {csca_sha256}",
                csca_subject_cn.as_deref().unwrap_or("<unparsed CN>"),
                csca_country.as_ref().map_or("??", |c| c.as_str()),
            ),
            DscCscaCheck::KeyUsageNonCompliant(ku) => {
                format!(
                    "FAILED -- Doc 9303 §7.1.1 DSC KeyUsage non-compliant: {}",
                    ku.describe()
                )
            }
            DscCscaCheck::NoMatch {
                country_iso,
                candidates,
            } => format!(
                "FAILED -- {candidates} candidate(s) for {country_iso} in ML, none verified the DSC"
            ),
            DscCscaCheck::CountryAbsent { country_iso } => {
                format!("ML has no CSCA for {country_iso}")
            }
            DscCscaCheck::DscCountryUnknown => {
                "DSC issuer DN has no countryName -- can't index into ML".to_owned()
            }
            DscCscaCheck::NoDscInSod => "EF.SOD carried no DSC".to_owned(),
            DscCscaCheck::DscParseFailed => "DSC failed to parse as X.509".to_owned(),
        }
    }
}

impl CardCheckHelpers {
    /// Write the MRZ section of the eMRTD report (document
    /// type, country, number, names, DOB, expiry, sex).
    ///
    /// Format mirrors the on-card MRZ field order so a reader
    /// can cross-check against ICAO 9303-3 TD1 line layouts.
    /// Issuing-state coherence is appended when the SOD lets
    /// us cross-check the MRZ country against the DSC issuer.
    fn write_emrtd_mrz(f: &mut fmt::Formatter<'_>, emrtd: &EmrtdPersonalData) -> fmt::Result {
        let m = &emrtd.mrz;
        writeln!(
            f,
            "doc type / country:  {} / {}",
            m.document_type, m.issuing_country
        )?;
        writeln!(f, "document number:     {}", m.document_number)?;
        writeln!(
            f,
            "names:               {} / {}",
            m.primary_identifier.spaced(),
            m.secondary_identifier.spaced()
        )?;
        writeln!(f, "date of birth:       {}", m.date_of_birth)?;
        // The MRZ "date of expiry" is the *document's* expiry, not the
        // holder's -- label it as the card's so it doesn't read as a
        // person attribute sitting next to name / date of birth.
        writeln!(
            f,
            "card expiry:         {}",
            Self::render_mrz_expiry(&m.date_of_expiry)
        )?;
        writeln!(
            f,
            "sex:                 {} ({})",
            // ICAO 9303-3 §4.2.4: MRZ sex byte is one ASCII char
            // from {'M', 'F', '<'}; `char::from(u8)` is lossless.
            char::from(m.sex.as_mrz_byte()),
            m.sex
        )?;
        if let Some(line) =
            render_country_cross_check(&m.issuing_country, SodDer::from_personal_data(emrtd))
        {
            writeln!(f, "issuing state check: {line}")?;
        }
        Ok(())
    }

    /// Write the eMRTD images line (DG2 face JPEG/JPEG2000,
    /// DG7 signature image, DG11/12 document images).
    ///
    /// Reports format + byte length only -- the image bytes
    /// themselves go to `--save-cert-dir` when that flag is
    /// set. Each image type has a stable line so the
    /// operator can diff against a known-good card.
    fn write_emrtd_images(f: &mut fmt::Formatter<'_>, emrtd: &EmrtdPersonalData) -> fmt::Result {
        match &emrtd.face {
            Some(refineid_lib_core::emrtd::DocumentImage::Jpeg(b)) => {
                writeln!(f, "face image (DG2):    JPEG, {} bytes", b.len())?;
            }
            Some(refineid_lib_core::emrtd::DocumentImage::Jpeg2000(b)) => {
                writeln!(f, "face image (DG2):    JPEG2000, {} bytes", b.len())?;
            }
            None => writeln!(f, "face image (DG2):    <none>")?,
        }
        match (&emrtd.signature_image, &emrtd.dg7_der) {
            (Some(refineid_lib_core::emrtd::DocumentImage::Jpeg(b)), _) => {
                writeln!(f, "signature (DG7):     JPEG, {} bytes", b.len())?;
            }
            (Some(refineid_lib_core::emrtd::DocumentImage::Jpeg2000(b)), _) => {
                writeln!(f, "signature (DG7):     JPEG2000, {} bytes", b.len())?;
            }
            (None, Some(raw)) => {
                writeln!(
                    f,
                    "signature (DG7):     {} raw bytes (no JPEG/JP2 magic)",
                    raw.len()
                )?;
            }
            (None, None) => {}
        }
        Ok(())
    }

    /// Write the eMRTD security section: SOD / DG14 / DG15
    /// presence + parsed contents, plus AA and CA outcomes.
    ///
    /// ICAO 9303 Part 10 §4 -- SOD carries the DSC and
    /// passive-authentication digests, DG14 holds chip-auth
    /// security infos, DG15 the AA public key. Each block
    /// surfaces a byte count + structured parse so the
    /// operator can audit coverage at a glance.
    fn write_emrtd_security(f: &mut fmt::Formatter<'_>, emrtd: &EmrtdPersonalData) -> fmt::Result {
        if let Some(sod) = &emrtd.sod_der {
            writeln!(f, "EF.SOD:              {} bytes", sod.len())?;
        }
        if let Some(dg14) = &emrtd.dg14_der {
            writeln!(f, "DG14 (security):     {} bytes", dg14.len())?;
            if let Ok(dg14_typed) = refineid_lib_core::emrtd::Dg14Bytes::try_from(dg14.as_slice()) {
                for info in refineid_lib_core::emrtd::parse_dg14(dg14_typed) {
                    render_dg14_info(f, &info)?;
                }
            }
        }
        if let Some(dg15) = &emrtd.dg15_der {
            writeln!(f, "DG15 (AA pubkey):    {} bytes", dg15.len())?;
            if let Ok(dg15_typed) = refineid_lib_core::emrtd::Dg15Bytes::try_from(dg15.as_slice())
                && let Some(alg) = parse_subject_public_key_info(
                    refineid_lib_core::emrtd::parse_dg15_spki(dg15_typed),
                )
            {
                writeln!(f, "                     {}", alg.label())?;
            }
        }
        if let Some(aa) = &emrtd.aa_result {
            writeln!(f, "Active Auth (DG15):  {}", Self::render_aa_outcome(aa))?;
        }
        if let Some(ca) = &emrtd.ca_result {
            writeln!(f, "Chip Auth (DG14):    {}", Self::render_ca_outcome(ca))?;
        }
        Ok(())
    }

    /// Top-level dispatcher for the full eMRTD section.
    ///
    /// Composes the MRZ -> images -> security sub-blocks in
    /// that order; called once from [`CardCheckReport::fmt_emrtd_block`]
    /// when both an `EmrtdPersonalData` and (optionally) a
    /// DSC->CSCA outcome are present.
    fn write_emrtd_section(f: &mut fmt::Formatter<'_>, emrtd: &EmrtdPersonalData) -> fmt::Result {
        writeln!(f, "=== eMRTD (read via PACE / --can) ===")?;
        Self::write_emrtd_mrz(f, emrtd)?;
        Self::write_emrtd_images(f, emrtd)?;
        Self::write_emrtd_security(f, emrtd)
    }
}

impl fmt::Display for CertReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "  subject CN:       {}",
            self.subject_cn.as_deref().unwrap_or("<absent>")
        )?;
        writeln!(
            f,
            "  issuer CN:        {}",
            self.issuer_cn.as_deref().unwrap_or("<absent>")
        )?;
        writeln!(f, "  serial:           {}", self.serial)?;
        writeln!(f, "  sha256:           {}", self.sha256)?;
        writeln!(
            f,
            "  not before:       {}",
            crate::text::fmt_rfc3339(self.not_before)
        )?;
        writeln!(
            f,
            "  not after:        {}  ({} day{} remaining)",
            crate::text::fmt_rfc3339(self.not_after),
            self.days_until_expiry,
            if self.days_until_expiry == 1 { "" } else { "s" },
        )?;
        if let Some(alg) = self.key_alg {
            writeln!(f, "  public key:       {}", alg.label())?;
        }
        writeln!(f, "  signature alg:    {}", self.signature_alg.label())?;
        if let Some(ku) = self.key_usage {
            writeln!(f, "  key usage:        {}", ku.label())?;
        }
        if !self.eku.is_empty() {
            writeln!(f, "  extended use:     {}", self.eku.join(", "))?;
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
        for e in &self.san_emails {
            writeln!(f, "  email (SAN):      {e}")?;
        }
        if let Some(check) = &self.chain_check {
            writeln!(
                f,
                "  chain verified:   {}",
                CardCheckHelpers::fmt_signature_check(check)
            )?;
        }
        if let Some(check) = &self.crl_check {
            fmt_check_outcome(f, CheckOutcomeSection::Crl, check)?;
        }
        if let Some(check) = &self.ocsp_check {
            fmt_check_outcome(f, CheckOutcomeSection::Ocsp, check)?;
        }
        Ok(())
    }
}

impl CardCheckHelpers {
    /// Format a [`SignatureCheck`] outcome as a single line.
    ///
    /// `ok` (verified), `skipped (...)` (preconditions
    /// missing), `FAILED (...)` (verification ran and rejected).
    /// The variant text is sourced verbatim from the
    /// underlying check so the operator sees the actual
    /// failure reason, not a translated one.
    fn fmt_signature_check(check: &SignatureCheck) -> String {
        match check {
            SignatureCheck::Ok => "ok".to_owned(),
            SignatureCheck::Skipped(why) => format!("skipped ({why})"),
            SignatureCheck::Failed(why) => format!("FAILED ({why})"),
        }
    }
}

/// Report section for a CRL or OCSP probe.
#[derive(Clone, Copy)]
enum CheckOutcomeSection {
    /// CRL probe section.
    Crl,
    /// OCSP probe section.
    Ocsp,
}

impl CheckOutcomeSection {
    /// Indented prefix for the transport ("via") line.
    const VIA_LINE: &'static str = "    via:            ";

    /// First line prefix for this report section.
    const fn label_line(self) -> &'static str {
        match self {
            Self::Crl => "  CRL check:        ",
            Self::Ocsp => "  OCSP check:       ",
        }
    }
}

/// Render a `CheckOutcome` for a CRL or OCSP probe as the
/// report block (section line + source line + indented fields).
///
/// The CRL and OCSP blocks share this formatter because their
/// outcome shapes are isomorphic (source URL, revocation
/// verdict, signature check, optional nonce check); only the
/// labels differ. Keeping the format in one function means
/// the two sections stay visually aligned in the report.
fn fmt_check_outcome(
    f: &mut fmt::Formatter<'_>,
    section: CheckOutcomeSection,
    outcome: &CheckOutcome,
) -> fmt::Result {
    let label_line = section.label_line();
    let via_line = CheckOutcomeSection::VIA_LINE;
    match outcome {
        CheckOutcome::Status {
            source,
            status,
            signature,
            nonce,
        } => {
            writeln!(
                f,
                "{label_line}{}",
                CardCheckHelpers::fmt_revocation(status)
            )?;
            writeln!(f, "{via_line}{source}")?;
            writeln!(
                f,
                "    signature:    {}",
                CardCheckHelpers::fmt_signature_check(signature)
            )?;
            if let Some(nonce) = nonce {
                writeln!(
                    f,
                    "    nonce:        {}",
                    CardCheckHelpers::fmt_signature_check(nonce)
                )?;
            }
        }
        CheckOutcome::Skipped { source, why } => {
            writeln!(f, "{label_line}skipped ({why})")?;
            writeln!(f, "{via_line}{source}")?;
        }
    }
    Ok(())
}

impl CardCheckHelpers {
    /// Render a [`RevocationStatus`] verdict in the form the
    /// report expects.
    ///
    /// `good` / `unknown` are plain words; `REVOKED` includes
    /// the revocation timestamp and reason code (with the
    /// RFC 5280 §5.3.1 reason label); `stale` indicates the
    /// CRL passed `nextUpdate`; `inapplicable` carries the
    /// caller-supplied reason (e.g. "self-issued root").
    fn fmt_revocation(s: &RevocationStatus) -> String {
        match s {
            RevocationStatus::Good => "good".to_owned(),
            RevocationStatus::Revoked { at, reason } => format!(
                "REVOKED at {} (reason: {})",
                crate::text::fmt_rfc3339(*at),
                reason.map_or_else(|| "<none>".to_owned(), |r| r.to_string())
            ),
            RevocationStatus::Unknown => "unknown".to_owned(),
            RevocationStatus::Inapplicable(why) => format!("inapplicable ({why})"),
            RevocationStatus::Stale => "stale (past nextUpdate)".to_owned(),
        }
    }
}

impl CardCheckHelpers {
    /// Convert a [`PinStatus`] (or absent probe) into the
    /// human string the PIN-counter section emits.
    ///
    /// `Verified` here means the slot has been verified
    /// earlier in the session (refineid never verifies during
    /// `card check`); `Remaining(n)` is the retry counter;
    /// `Locked` indicates a `63C0` or equivalent (needs PUK).
    /// `None` collapses to "(probe failed)" -- the probe is
    /// best-effort so missing data isn't a hard error.
    fn render_pin_status(s: Option<&PinStatus>) -> String {
        match s {
            Some(PinStatus::Verified) => "verified (this session)".to_owned(),
            Some(PinStatus::Remaining(n)) => format!("{n} retries left"),
            Some(PinStatus::NoInfo) => "no retry information (probably exhausted)".to_owned(),
            Some(PinStatus::Locked) => "BLOCKED -- needs PUK unblock".to_owned(),
            Some(PinStatus::Other(sw)) => format!("unexpected SW={sw:#06X}"),
            None => "(probe failed)".to_owned(),
        }
    }

    /// Convert the typed PUK retry-query outcome to operator text.
    fn render_puk_status(s: Option<&PukStatus>) -> String {
        match s {
            Some(PukStatus::Remaining(n)) => format!("{n} retries left"),
            Some(PukStatus::NoInfo) => "no retry information".to_owned(),
            Some(PukStatus::Locked) => "BLOCKED -- card replacement required".to_owned(),
            Some(PukStatus::Invalidated) => {
                "INVALIDATED -- selected PIN cannot be recovered".to_owned()
            }
            Some(PukStatus::Other(sw)) => format!("unexpected SW={sw:#06X}"),
            None => "(probe failed)".to_owned(),
        }
    }

    /// Human rendering of the card-reported successful-use allowance.
    fn render_usage_counter(policy: Option<&CredentialPolicyCounters>) -> String {
        match policy.map(|value| value.usage) {
            Some(UsageCounter::Exhausted) => "exhausted".to_owned(),
            Some(UsageCounter::Limited(remaining)) => format!("{remaining} left"),
            Some(UsageCounter::NoLimit) => "no limit".to_owned(),
            None => "not reported".to_owned(),
        }
    }

    /// Human rendering of the card-reported PIN recovery allowance.
    fn render_unblocking_counter(policy: Option<&CredentialPolicyCounters>) -> String {
        match policy.map(|value| value.unblocking) {
            Some(UnblockingCounter::Exhausted) => "exhausted".to_owned(),
            Some(UnblockingCounter::Limited(remaining)) => format!("{remaining} left"),
            Some(UnblockingCounter::NoLimit) => "no limit".to_owned(),
            None => "not reported".to_owned(),
        }
    }

    /// Human label for the PIN-changed-since-factory flag.
    ///
    /// FINEID S1 v4.2 §3.15.2 specifies a card-resident
    /// boolean reflecting whether the cardholder has ever
    /// changed the slot's PIN from its factory value. `None`
    /// covers older firmware that does not implement the
    /// GET DATA at `DF2F` -- the indeterminate result is
    /// surfaced explicitly, not silently treated as "no".
    const fn render_pin_changed(flag: Option<bool>) -> &'static str {
        match flag {
            Some(true) => "yes",
            Some(false) => "no (still factory value)",
            None => "indeterminate (card did not return DF2F)",
        }
    }
}

/// Render a typed MRZ expiry as `YYYY-MM-DD` plus a "valid for
/// N days" / "EXPIRED N days ago" suffix, per BSI TR-03135-1
/// §4.7.1.
///
/// Century resolution comes from `MrzDate` (50/50 split per
/// ICAO 9303-3 §4.5). For the FINEID expiry-date use case this
/// matches the near-future heuristic for any YY < 50 -- which
/// is true for every FINEID expiry we'll see this side of 2050.
impl CardCheckHelpers {
    /// Render an MRZ expiry as `YYYY-MM-DD` plus a
    /// validity-window suffix.
    ///
    /// BSI TR-03135-1 §4.7.1 -- the report distinguishes "valid;
    /// N days remaining" from "EXPIRED N days ago". MRZ century
    /// resolution is already done by the `MrzDate`
    /// constructor (50/50 split per ICAO 9303-3 §4.5).
    #[must_use]
    fn render_mrz_expiry(date: &refineid_lib_core::identity::MrzDate) -> String {
        // The MrzDate already holds an Iso8601::Date with the year
        // resolved at construction. Read the components through the
        // semantic projection.
        let iso = date.date();
        let now = now_date_time();
        let Ok(expiry) = DateTime::new(iso.year(), iso.month(), iso.day(), 0, 0, 0) else {
            return format!("{iso}  (invalid date)");
        };
        let days = days_between(now, expiry);
        // ISO 8601 Display on the inner Date renders YYYY-MM-DD.
        let resolved = format!("{iso}");
        if days >= 0 {
            format!("{resolved}  (valid; {days} days remaining)")
        } else {
            format!("{resolved}  (EXPIRED {} days ago)", days.saturating_neg())
        }
    }
}

/// Cross-check DG1's [`IcaoCountry`] issuing-state code against
/// the embedded DSC's [`IsoAlpha2`] `countryName`. Per BSI
/// TR-03135-1 §4.6.4.5.
///
/// [`IcaoCountry`]: refineid_lib_core::country::IcaoCountry
/// [`IsoAlpha2`]: refineid_lib_core::country::IsoAlpha2
#[must_use]
fn render_country_cross_check(
    dg1_icao: &refineid_lib_core::country::IcaoCountry,
    sod_der: Option<SodDer<'_>>,
) -> Option<String> {
    let sod = sod_der?;
    let signed_owned = refineid_lib_core::cms::OwnedSignedData::from_der(sod.as_bytes()).ok()?;
    let signed = signed_owned.view();
    let dsc_der = signed.certificates_der.first()?;
    let dsc_owned = OwnedCert::from_der(dsc_der).ok()?;
    let dsc = dsc_owned.view();
    let dsc_country = dsc.issuer.country()?;
    let expected_iso = dg1_icao.to_iso_alpha2();
    match expected_iso {
        Some(iso) if iso == dsc_country => Some(format!(
            "{dg1_icao} matches DSC issuer {dsc_country} (ICAO->ISO mapping)"
        )),
        Some(iso) => Some(format!(
            "{dg1_icao} -> {iso} but DSC issuer says {dsc_country} -- MISMATCH"
        )),
        None => Some(format!(
            "{dg1_icao}: no ICAO->ISO mapping in our table (DSC says {dsc_country})"
        )),
    }
}

/// Write one parsed `Dg14SecurityInfo` line into the eMRTD
/// security report block.
///
/// DG14 enumerates the chip-authentication / terminal-
/// authentication / PACE protocols the chip supports
/// (ICAO 9303 Part 11 §9.2.6). Each variant renders to a
/// labelled line; unknown OID variants emit the raw OID hex
/// rather than dropping silently.
fn render_dg14_info(
    f: &mut fmt::Formatter<'_>,
    info: &refineid_lib_core::emrtd::Dg14SecurityInfo,
) -> fmt::Result {
    use refineid_lib_core::emrtd::Dg14SecurityInfo;
    match info {
        Dg14SecurityInfo::ChipAuthenticationInfo {
            protocol_label,
            version,
            ..
        } => {
            let v = version.map_or_else(String::new, |n| format!(" v{n}"));
            writeln!(f, "                     CA protocol: {protocol_label}{v}")?;
        }
        Dg14SecurityInfo::ChipAuthenticationPublicKeyInfo { spki_der, .. } => {
            let alg = parse_subject_public_key_info(spki_der)
                .map_or_else(|| "unknown".to_owned(), PublicKeyAlgorithm::label);
            writeln!(f, "                     CA pubkey:   {alg}")?;
        }
        Dg14SecurityInfo::TerminalAuthenticationInfo { .. } => {
            writeln!(
                f,
                "                     TA info:     present (citizen reader can't use)"
            )?;
        }
        Dg14SecurityInfo::PaceInfo { .. } => {
            writeln!(
                f,
                "                     PACE info:   present (also in EF.CardAccess)"
            )?;
        }
        Dg14SecurityInfo::Other { oid } => {
            writeln!(f, "                     other OID:   {}", hex::encode(oid))?;
        }
    }
    Ok(())
}

impl CardCheckHelpers {
    /// Render a Chip-Authentication outcome as a one-line
    /// string for the eMRTD security block.
    ///
    /// BSI TR-03110-3 §3.4 (CA protocol). The outcome
    /// distinguishes a successful rekey + post-rekey MAC'd
    /// probe ("not cloned") from each failure mode (MSE
    /// rejected, GA rejected, post-rekey probe failed,
    /// unsupported curve / protocol).
    fn render_ca_outcome(o: &refineid_lib_core::ca::CaOutcome) -> String {
        use refineid_lib_core::ca::CaOutcome;
        match o {
            CaOutcome::Verified { protocol_label } => {
                format!(
                    "verified via {protocol_label} -- chip not cloned (post-rekey probe MAC'd ok)"
                )
            }
            CaOutcome::VerificationFailed { detail } => {
                format!("rekey done but post-rekey probe FAILED: {detail}")
            }
            CaOutcome::MseRejected { sw } => {
                format!("card rejected MSE:Set AT (SW={sw:#06X})")
            }
            CaOutcome::GaRejected { sw } => {
                format!("card rejected General Authenticate (SW={sw:#06X})")
            }
            CaOutcome::NoSupportedProtocol => {
                "no supported CA protocol in DG14 (skipped)".to_owned()
            }
            CaOutcome::UnsupportedCurve => "CA pubkey curve not supported (skipped)".to_owned(),
        }
    }
}

impl CardCheckHelpers {
    /// Render an Active-Authentication outcome as a one-line
    /// string for the eMRTD security block.
    ///
    /// ICAO 9303 Part 11 §6.1 (AA protocol). Reports the hash
    /// algorithm and M1 length when verification succeeded;
    /// otherwise names the failure (SPKI parse, INTERNAL
    /// AUTHENTICATE rejected, sig verify failed, AA disabled).
    fn render_aa_outcome(o: &refineid_lib_core::aa::AaOutcome) -> String {
        use refineid_lib_core::aa::AaOutcome;
        use refineid_lib_core::crypto::rsa::HashAlg;
        let hash_label = |h: HashAlg| match h {
            HashAlg::Sha1 => "SHA-1",
            HashAlg::Sha256 => "SHA-256",
            HashAlg::Sha384 => "SHA-384",
            HashAlg::Sha512 => "SHA-512",
        };
        match o {
            AaOutcome::Verified { hash, m1_len } => format!(
                "verified ({} hash, {} bytes M1) -- chip not cloned",
                hash_label(*hash),
                m1_len,
            ),
            AaOutcome::CardRejected { sw } => {
                format!("card rejected INTERNAL AUTHENTICATE (SW={sw:#06X})")
            }
            AaOutcome::SignatureInvalid { detail } => {
                format!("signature INVALID -- {detail}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the pure policy/orchestration logic in
    //! `card_check`: DSC `keyUsage` compliance, Master List signer
    //! trust evaluation, trust-anchor pinning (chain walk),
    //! CRL verdict orchestration, the DSC -> CSCA hop, and the
    //! human-string renderers.
    //!
    //! No card or network is touched. Certificates / CRLs / EF.SOD
    //! CMS blobs are built as DER in-process; the few signature
    //! verifications that must succeed reuse the real self-signed
    //! pinned roots (DVV G3 RSA/ECC, UN CSCA 2) shipped in
    //! `trust-anchors/`, since a self-signed root verifies against
    //! itself. Crate-private typed values (`CommonName`,
    //! `IsoAlpha2`, `CertSerial`) are obtained by parsing built
    //! certs, exactly as production does -- their constructors are
    //! `pub(crate)` to `refineid-lib-core`.
    //!
    //! Tests return [`TestResult`] and propagate through `?` per
    //! the crate-wide no-panic test convention (`test_util`).

    use super::{
        AiaIssuerCert, AiaIssuerCertStatus, CardCheckError, CardCheckHelpers, CheckOutcome,
        CheckOutcomeSection, DER_SEQUENCE_TAG, DscCscaCheck, DscKeyUsageCheck, IcaoPkdFileBytes,
        IcaoTrustPool, LoadedMl, MlSignerTrust, SignatureCheck, SignerBasicConstraintsCheck,
        SignerEkuCheck, SodDer, VerifyContext, days_between, fmt_check_outcome,
        is_ml_fully_trusted, now_date_time, run_chain_check, verify_crl,
    };
    use crate::test_util::{TestResult, check, check_true};
    use crate::trust_roots::{ICAO_PKD_ROOT_PEMS, PINNED_ROOT_DER};
    use alloc::fmt;
    use refineid_lib_core::aa::AaOutcome;
    use refineid_lib_core::apdu::status_word::PinRetries;
    use refineid_lib_core::auth::{
        CredentialPolicyCounters, PinStatus, PukStatus, UnblockingCounter, UsageCounter,
    };
    use refineid_lib_core::ca::CaOutcome;
    use refineid_lib_core::cms::OwnedSignedData;
    use refineid_lib_core::crl::OwnedCrl;
    use refineid_lib_core::crypto::digest::Sha256;
    use refineid_lib_core::crypto::rsa::HashAlg;
    use refineid_lib_core::icao_pkd::{CscaEntry, IcaoMasterList};
    use refineid_lib_core::identity::MrzDate;
    use refineid_lib_core::revocation::{InapplicableReason, RevocationStatus};
    use refineid_lib_core::x509::{DateTime, OwnedCert};

    // ---------- DER construction toolkit ----------
    //
    // Minimal, lint-clean (no panics / casts / indexing) BER/DER
    // builders. They produce structurally-valid TLVs; signature
    // bytes are padding -- the functions under test that verify
    // signatures are driven with the real self-signed roots
    // instead.

    /// `id-at-commonName` OID body (2.5.4.3).
    const OID_CN: [u8; 3] = [0x55, 0x04, 0x03];
    /// `id-at-countryName` OID body (2.5.4.6).
    const OID_C: [u8; 3] = [0x55, 0x04, 0x06];
    /// `id-ce-keyUsage` OID body (2.5.29.15).
    const OID_KU: [u8; 3] = [0x55, 0x1D, 0x0F];
    /// `id-ce-extKeyUsage` OID body (2.5.29.37).
    const OID_EKU: [u8; 3] = [0x55, 0x1D, 0x25];
    /// `id-ce-basicConstraints` OID body (2.5.29.19).
    const OID_BC: [u8; 3] = [0x55, 0x1D, 0x13];
    /// `id-icao-mlSigner` OID body (2.23.136.1.1.3).
    const OID_ML_SIGNER: [u8; 6] = [0x67, 0x81, 0x08, 0x01, 0x01, 0x03];
    /// `id-kp-serverAuth` OID body (1.3.6.1.5.5.7.3.1) -- a
    /// recognised but non-mlSigner EKU OID.
    const OID_SERVER_AUTH: [u8; 8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
    /// `id-signedData` OID body (1.2.840.113549.1.7.2).
    const OID_SIGNED_DATA: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
    /// `id-data` OID body (1.2.840.113549.1.7.1) -- arbitrary
    /// eContentType for the synthetic EF.SOD.
    const OID_ID_DATA: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
    /// `id-sha256` OID body (2.16.840.1.101.3.4.2.1).
    const OID_SHA256: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    /// `sha256WithRSAEncryption` OID body (1.2.840.113549.1.1.11).
    const OID_SHA256_RSA: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
    const DER_SHORT_FORM_LIMIT: usize = 0x80;
    const DER_LEN_LONG_ONE: u8 = 0x81;
    const DER_LEN_LONG_TWO: u8 = 0x82;
    const DER_TAG_BOOLEAN: u8 = 0x01;
    const DER_TAG_INTEGER: u8 = 0x02;
    const DER_TAG_BIT_STRING: u8 = 0x03;
    const DER_TAG_OCTET_STRING: u8 = 0x04;
    const DER_TAG_OBJECT_IDENTIFIER: u8 = 0x06;
    const DER_TAG_UTF8_STRING: u8 = 0x0C;
    const DER_TAG_PRINTABLE_STRING: u8 = 0x13;
    const DER_TAG_UTC_TIME: u8 = 0x17;
    const DER_TAG_SEQUENCE: u8 = 0x30;
    const DER_TAG_SET: u8 = 0x31;
    const DER_TAG_CONTEXT_0: u8 = 0xA0;
    const DER_TAG_CONTEXT_3: u8 = 0xA3;
    const DER_NULL: [u8; 2] = [0x05, 0x00];
    const DER_TRUE: [u8; 1] = [0xFF];
    const DER_FALSE_BYTE: u8 = 0x00;
    const DER_UNUSED_BITS_ZERO: u8 = 0x00;
    const CERT_VERSION_V3: [u8; 5] = [0xA0, 0x03, 0x02, 0x01, 0x02];
    const FIXTURE_SPKI_BITS: [u8; 7] = [0x03, 0x05, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];
    const FIXTURE_SIGNATURE_BITS: [u8; 7] = [0x03, 0x05, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
    const CERT_SERIAL_ONE: u8 = 0x01;
    const CMS_SIGNED_DATA_VERSION: [u8; 1] = [0x03];
    const CMS_SIGNER_INFO_VERSION: [u8; 1] = [0x01];
    const CMS_ISSUER_SERIAL_PLACEHOLDER: [u8; 1] = [0x00];
    const CRL_VERSION_V2: [u8; 1] = [0x01];

    /// Shared DER byte builder for synthetic test fixtures.
    #[derive(Clone)]
    struct FixtureDer(Vec<u8>);

    impl FixtureDer {
        fn empty() -> Self {
            Self(Vec::new())
        }

        fn from_array<const N: usize>(bytes: [u8; N]) -> Self {
            Self(bytes.to_vec())
        }

        fn as_slice(&self) -> &[u8] {
            self.0.as_slice()
        }

        fn into_vec(self) -> Vec<u8> {
            self.0
        }

        fn len(&self) -> usize {
            self.0.len()
        }

        fn push_der(&mut self, der: &Self) {
            self.0.extend_from_slice(der.as_slice());
        }

        fn push_array<const N: usize>(&mut self, bytes: [u8; N]) {
            self.0.extend_from_slice(&bytes);
        }
    }

    #[derive(Clone, Copy)]
    enum EkuFixtureOid {
        MlSigner,
        ServerAuth,
    }

    impl EkuFixtureOid {
        fn to_tlv(self) -> FixtureDer {
            match self {
                Self::MlSigner => oid_tlv(&OID_ML_SIGNER),
                Self::ServerAuth => oid_tlv(&OID_SERVER_AUTH),
            }
        }
    }

    #[derive(Clone, Copy)]
    enum DvvRootNeedle {
        Rsa,
        Ecc,
    }

    impl DvvRootNeedle {
        const fn as_str(self) -> &'static str {
            match self {
                Self::Rsa => "RSA",
                Self::Ecc => "ECC",
            }
        }
    }

    /// Append a DER definite-length octet sequence for `n`.
    /// Handles the short form, one-byte long form, and two-byte
    /// long form -- enough for every fixture here (all < 64 KiB).
    fn push_len(out: &mut Vec<u8>, n: usize) {
        match u8::try_from(n) {
            Ok(short) if n < DER_SHORT_FORM_LIMIT => out.push(short),
            Ok(short) => out.extend_from_slice(&[DER_LEN_LONG_ONE, short]),
            // Two-byte long form; every fixture here is < 64 KiB.
            Err(_) => {
                let [hi, lo] = u16::try_from(n).unwrap_or(0).to_be_bytes();
                out.extend_from_slice(&[DER_LEN_LONG_TWO, hi, lo]);
            }
        }
    }

    /// Build a single TLV (`tag` + DER length + `value`).
    fn tlv(tag: u8, value: &FixtureDer) -> FixtureDer {
        let mut out = Vec::with_capacity(value.len().saturating_add(4));
        out.push(tag);
        push_len(&mut out, value.len());
        out.extend_from_slice(value.as_slice());
        FixtureDer(out)
    }

    /// Build a single TLV from a fixed-size fixture byte array.
    fn tlv_array<const N: usize>(tag: u8, value: [u8; N]) -> FixtureDer {
        tlv(tag, &FixtureDer::from_array(value))
    }

    /// Wrap `body` as an OID TLV.
    fn oid_tlv<const N: usize>(body: &[u8; N]) -> FixtureDer {
        tlv_array(DER_TAG_OBJECT_IDENTIFIER, *body)
    }

    /// `AlgorithmIdentifier` for `sha256WithRSAEncryption` with the
    /// `NULL` parameters, as a SEQUENCE TLV.
    fn sig_alg_seq() -> FixtureDer {
        let mut body = oid_tlv(&OID_SHA256_RSA);
        body.push_array(DER_NULL);
        tlv(DER_TAG_SEQUENCE, &body)
    }

    /// One `RelativeDistinguishedName` (SET of one ATV) for the
    /// given attribute type OID, value string-tag, and value bytes.
    fn rdn<const OID_LEN: usize, const VAL_LEN: usize>(
        oid_body: &[u8; OID_LEN],
        val_tag: u8,
        val: &[u8; VAL_LEN],
    ) -> FixtureDer {
        let mut atv = oid_tlv(oid_body);
        atv.push_der(&tlv_array(val_tag, *val));
        let atv_seq = tlv(DER_TAG_SEQUENCE, &atv);
        tlv(DER_TAG_SET, &atv_seq)
    }

    /// `RDNSequence` carrying only `CN=cn` (`UTF8String`).
    fn dn_cn<const N: usize>(cn: &[u8; N]) -> FixtureDer {
        tlv(DER_TAG_SEQUENCE, &rdn(&OID_CN, DER_TAG_UTF8_STRING, cn))
    }

    /// `RDNSequence` carrying `CN=cn` then `C=country`
    /// (`PrintableString` country).
    fn dn_cn_country<const CN_LEN: usize, const COUNTRY_LEN: usize>(
        cn: &[u8; CN_LEN],
        country: &[u8; COUNTRY_LEN],
    ) -> FixtureDer {
        let mut body = rdn(&OID_CN, DER_TAG_UTF8_STRING, cn);
        body.push_der(&rdn(&OID_C, DER_TAG_PRINTABLE_STRING, country));
        tlv(DER_TAG_SEQUENCE, &body)
    }

    /// A `UTCTime` TLV from a `YYMMDDHHMMSS` string (Z-terminated).
    fn utc_time<const N: usize>(yymmddhhmmss: &[u8; N]) -> FixtureDer {
        let mut body = yymmddhhmmss.to_vec();
        body.push(b'Z');
        tlv(DER_TAG_UTC_TIME, &FixtureDer(body))
    }

    /// One X.509 `Extension` (`extnID` + optional critical BOOLEAN
    /// + `extnValue` OCTET STRING wrapping `inner`).
    fn ext<const N: usize>(oid_body: &[u8; N], critical: bool, inner: &FixtureDer) -> FixtureDer {
        let mut body = oid_tlv(oid_body);
        if critical {
            body.push_der(&tlv_array(DER_TAG_BOOLEAN, DER_TRUE));
        }
        body.push_der(&tlv(DER_TAG_OCTET_STRING, inner));
        tlv(DER_TAG_SEQUENCE, &body)
    }

    /// A `keyUsage` extension. `first_byte` carries named bits 0..7
    /// (MSB = `digitalSignature`); `second_byte` carries bit 8
    /// (`decipherOnly`) when present. The unused-bits count is left
    /// at 0 -- the extractor skips it.
    fn ku_ext(critical: bool, first_byte: u8, second_byte: Option<u8>) -> FixtureDer {
        let mut bits = FixtureDer(vec![DER_UNUSED_BITS_ZERO, first_byte]);
        if let Some(extra) = second_byte {
            bits.0.push(extra);
        }
        let inner = tlv(DER_TAG_BIT_STRING, &bits);
        ext(&OID_KU, critical, &inner)
    }

    /// An `extKeyUsage` extension listing `oid_bodies`.
    fn eku_ext<const N: usize>(critical: bool, oid_bodies: [EkuFixtureOid; N]) -> FixtureDer {
        let mut seq = FixtureDer::empty();
        for body in oid_bodies {
            seq.push_der(&body.to_tlv());
        }
        let inner = tlv(DER_TAG_SEQUENCE, &seq);
        ext(&OID_EKU, critical, &inner)
    }

    /// A `basicConstraints` extension asserting the given `cA` flag.
    fn bc_ext(critical: bool, ca: bool) -> FixtureDer {
        let ca_byte = if ca { DER_TRUE } else { [DER_FALSE_BYTE] };
        let inner = tlv(DER_TAG_SEQUENCE, &tlv_array(DER_TAG_BOOLEAN, ca_byte));
        ext(&OID_BC, critical, &inner)
    }

    /// Build the smallest parseable v3 certificate DER from the
    /// given serial, issuer/subject DN bytes, and a pre-built
    /// `Extension`-list concatenation (already individual
    /// `Extension` SEQUENCEs, this wraps them in the outer
    /// SEQUENCE + `[3]`). The SPKI and signature are padding.
    fn build_cert<const SERIAL_LEN: usize>(
        serial: [u8; SERIAL_LEN],
        issuer_dn: &FixtureDer,
        subject_dn: &FixtureDer,
        extensions: Option<&FixtureDer>,
    ) -> FixtureDer {
        let sig_alg = sig_alg_seq();
        let spki = {
            let mut body = sig_alg.clone();
            body.push_array(FIXTURE_SPKI_BITS);
            tlv(DER_TAG_SEQUENCE, &body)
        };
        let validity = {
            let mut body = utc_time(b"200101000000");
            body.push_der(&utc_time(b"310101000000"));
            tlv(DER_TAG_SEQUENCE, &body)
        };
        let mut tbs_body = FixtureDer::empty();
        // version [0] EXPLICIT INTEGER 2 (v3)
        tbs_body.push_array(CERT_VERSION_V3);
        tbs_body.push_der(&tlv_array(DER_TAG_INTEGER, serial));
        tbs_body.push_der(&sig_alg);
        tbs_body.push_der(issuer_dn);
        tbs_body.push_der(&validity);
        tbs_body.push_der(subject_dn);
        tbs_body.push_der(&spki);
        if let Some(exts) = extensions {
            let ext_seq = tlv(DER_TAG_SEQUENCE, exts);
            tbs_body.push_der(&tlv(DER_TAG_CONTEXT_3, &ext_seq));
        }
        let tbs = tlv(DER_TAG_SEQUENCE, &tbs_body);
        let mut outer = tbs;
        outer.push_der(&sig_alg);
        outer.push_array(FIXTURE_SIGNATURE_BITS);
        tlv(DER_TAG_SEQUENCE, &outer)
    }

    /// Build a minimal parseable CMS `SignedData` (`ContentInfo`
    /// wrapper) embedding `certs` in the `certificates [0]` field.
    /// The `signerInfo` and signature are structural padding -- the
    /// DSC -> CSCA check only reads the first embedded certificate.
    fn build_sod(certs: &[&FixtureDer]) -> FixtureDer {
        let version = tlv_array(DER_TAG_INTEGER, CMS_SIGNED_DATA_VERSION);
        let digest_algos = tlv(DER_TAG_SET, &tlv(DER_TAG_SEQUENCE, &oid_tlv(&OID_SHA256)));
        let encap = {
            let mut body = oid_tlv(&OID_ID_DATA);
            body.push_der(&tlv(
                DER_TAG_CONTEXT_0,
                &tlv(DER_TAG_OCTET_STRING, &FixtureDer::empty()),
            ));
            tlv(DER_TAG_SEQUENCE, &body)
        };
        let signer_info = {
            let mut sid = tlv(DER_TAG_SEQUENCE, &FixtureDer::empty());
            sid.push_der(&tlv_array(DER_TAG_INTEGER, CMS_ISSUER_SERIAL_PLACEHOLDER));
            let mut body = tlv_array(DER_TAG_INTEGER, CMS_SIGNER_INFO_VERSION);
            body.push_der(&tlv(DER_TAG_SEQUENCE, &sid));
            body.push_der(&tlv(DER_TAG_SEQUENCE, &oid_tlv(&OID_SHA256)));
            body.push_der(&tlv(DER_TAG_SEQUENCE, &oid_tlv(&OID_SHA256_RSA)));
            body.push_der(&tlv(DER_TAG_OCTET_STRING, &FixtureDer::empty()));
            tlv(DER_TAG_SEQUENCE, &body)
        };
        let signer_infos = tlv(DER_TAG_SET, &signer_info);
        let mut sd_body = version;
        sd_body.push_der(&digest_algos);
        sd_body.push_der(&encap);
        if !certs.is_empty() {
            let mut cert_field = FixtureDer::empty();
            for c in certs {
                cert_field.push_der(c);
            }
            sd_body.push_der(&tlv(DER_TAG_CONTEXT_0, &cert_field));
        }
        sd_body.push_der(&signer_infos);
        let signed_data = tlv(DER_TAG_SEQUENCE, &sd_body);
        let mut ci_body = oid_tlv(&OID_SIGNED_DATA);
        ci_body.push_der(&tlv(DER_TAG_CONTEXT_0, &signed_data));
        tlv(DER_TAG_SEQUENCE, &ci_body)
    }

    /// Borrow a synthetic EF.SOD fixture through the production SOD type.
    fn sod_der(sod: &FixtureDer) -> SodDer<'_> {
        SodDer {
            bytes: sod.as_slice(),
        }
    }

    /// Build a minimal parseable CRL whose `issuer` is `issuer_dn`.
    /// (`thisUpdate`/`nextUpdate` are present for structural validity;
    /// freshness is consulted by `check_against_crl`, not by the
    /// `verify_crl` path these fixtures drive.)
    fn build_crl(issuer_dn: &FixtureDer) -> FixtureDer {
        let sig_alg = sig_alg_seq();
        let mut tbs_body = tlv_array(DER_TAG_INTEGER, CRL_VERSION_V2);
        tbs_body.push_der(&sig_alg);
        tbs_body.push_der(issuer_dn);
        tbs_body.push_der(&utc_time(b"260520120000"));
        tbs_body.push_der(&utc_time(b"310520120000"));
        let tbs = tlv(DER_TAG_SEQUENCE, &tbs_body);
        let mut outer = tbs;
        outer.push_der(&sig_alg);
        outer.push_array(FIXTURE_SIGNATURE_BITS);
        tlv(DER_TAG_SEQUENCE, &outer)
    }

    // ---------- fixture helpers ----------

    /// Parse `der` into an owning certificate, surfacing the parse
    /// error as a `String` for `?` propagation.
    fn parse_cert(der: &FixtureDer) -> Result<OwnedCert, String> {
        OwnedCert::from_der(der.as_slice()).map_err(|e| format!("cert parse: {e}"))
    }

    /// Build a [`CscaEntry`] from cert DER, deriving the typed
    /// indexing fields by parsing (the constructors are crate-
    /// private to `refineid-lib-core`).
    fn csca_entry(der: FixtureDer) -> Result<CscaEntry, String> {
        let owned = parse_cert(&der)?;
        let view = owned.view();
        let sha256 = Sha256::of(der.as_slice());
        Ok(CscaEntry {
            country_iso: view.subject.country(),
            subject_cn: view.subject.common_name(),
            serial: view.serial(),
            sha256,
            not_before: view.not_before,
            not_after: view.not_after,
            der: der.into_vec(),
        })
    }

    /// A fully-trusted Master List carrying `cscas` (pinned signer,
    /// compliant EKU + `BasicConstraints`), so its CSCAs feed the
    /// trust pool.
    fn trusted_ml(cscas: Vec<CscaEntry>) -> LoadedMl {
        LoadedMl {
            ml: IcaoMasterList {
                signer_subject_cn: None,
                signer_country: None,
                signer_cert_der: Vec::new(),
                embedded_certs_der: Vec::new(),
                cscas,
            },
            trust: MlSignerTrust::Pinned {
                root_label: "test root",
            },
            eku: SignerEkuCheck::Compliant,
            basic_constraints: SignerBasicConstraintsCheck::Compliant,
        }
    }

    /// The decoded DER of the pinned UN CSCA 2 root (self-signed).
    fn un_root_der() -> Result<Vec<u8>, String> {
        let pem = ICAO_PKD_ROOT_PEMS
            .first()
            .map(|entry| entry.1)
            .ok_or_else(|| "no UN root PEM pinned".to_owned())?;
        crate::text::decode_cert_pem_or_der(pem).ok_or_else(|| "decode UN root PEM".to_owned())
    }

    /// DER of a pinned DVV G3 root whose label contains `needle`.
    fn dvv_root_der(needle: DvvRootNeedle) -> Result<&'static [u8], String> {
        PINNED_ROOT_DER
            .iter()
            .find(|entry| entry.0.contains(needle.as_str()))
            .map(|entry| entry.1)
            .ok_or_else(|| format!("no pinned DVV root labelled with {:?}", needle.as_str()))
    }

    /// A `VerifyContext` with the given on-card root state; the
    /// time is fixed and the CRL slot empty.
    fn ctx_with_root(
        root_cert: Option<&OwnedCert>,
        root_trusted: bool,
    ) -> Result<VerifyContext<'_>, String> {
        let now = DateTime::new(2026, 6, 1, 0, 0, 0).map_err(|e| format!("now: {e}"))?;
        let root = root_cert.map(|cert| super::OnCardRoot {
            cert,
            trusted: root_trusted,
        });
        Ok(VerifyContext {
            offline: false,
            now,
            pre_fetched_crl: None,
            root,
        })
    }

    /// Newtype that renders a [`CheckOutcome`] through the
    /// `fmt_check_outcome` formatter for assertion.
    struct ShowOutcome<'a>(&'a CheckOutcome);

    impl fmt::Display for ShowOutcome<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt_check_outcome(f, CheckOutcomeSection::Crl, self.0)
        }
    }

    // ---------- DSC KeyUsage compliance (Doc 9303 Part 12 sec.7.1.1) ----------

    #[test]
    fn dsc_key_usage_compliant_when_digital_signature_only_and_critical() -> TestResult {
        let der = build_cert(
            [0x01],
            &dn_cn(b"Issuer"),
            &dn_cn(b"DSC"),
            Some(&ku_ext(true, 0x80, None)),
        );
        let owned = parse_cert(&der)?;
        let cert = owned.view();
        check_true(
            matches!(
                CardCheckHelpers::check_dsc_key_usage(&cert),
                DscKeyUsageCheck::Compliant
            ),
            "digitalSignature-only critical KU is compliant",
        )
    }

    #[test]
    fn dsc_key_usage_extension_missing_when_no_extensions() -> TestResult {
        let der = build_cert([0x01], &dn_cn(b"Issuer"), &dn_cn(b"DSC"), None);
        let owned = parse_cert(&der)?;
        let cert = owned.view();
        check_true(
            matches!(
                CardCheckHelpers::check_dsc_key_usage(&cert),
                DscKeyUsageCheck::ExtensionMissing
            ),
            "no extensions -> ExtensionMissing",
        )
    }

    #[test]
    fn dsc_key_usage_not_critical_flagged() -> TestResult {
        let der = build_cert(
            [0x01],
            &dn_cn(b"Issuer"),
            &dn_cn(b"DSC"),
            Some(&ku_ext(false, 0x80, None)),
        );
        let owned = parse_cert(&der)?;
        let cert = owned.view();
        check_true(
            matches!(
                CardCheckHelpers::check_dsc_key_usage(&cert),
                DscKeyUsageCheck::NotCritical
            ),
            "non-critical KU -> NotCritical",
        )
    }

    #[test]
    fn dsc_key_usage_missing_digital_signature_flagged() -> TestResult {
        // nonRepudiation (bit 1 = 0x40) only, critical, no digitalSignature.
        let der = build_cert(
            [0x01],
            &dn_cn(b"Issuer"),
            &dn_cn(b"DSC"),
            Some(&ku_ext(true, 0x40, None)),
        );
        let owned = parse_cert(&der)?;
        let cert = owned.view();
        check_true(
            matches!(
                CardCheckHelpers::check_dsc_key_usage(&cert),
                DscKeyUsageCheck::MissingDigitalSignature
            ),
            "critical KU without digitalSignature -> MissingDigitalSignature",
        )
    }

    #[test]
    fn dsc_key_usage_extra_bits_listed() -> TestResult {
        // digitalSignature (0x80) + keyCertSign (0x04) + cRLSign (0x02).
        let der = build_cert(
            [0x01],
            &dn_cn(b"Issuer"),
            &dn_cn(b"DSC"),
            Some(&ku_ext(true, 0x86, None)),
        );
        let owned = parse_cert(&der)?;
        let cert = owned.view();
        let outcome = CardCheckHelpers::check_dsc_key_usage(&cert);
        if let DscKeyUsageCheck::ExtraBitsAsserted { extra } = &outcome {
            check_true(extra.contains("keyCertSign"), "extra lists keyCertSign")?;
            check_true(extra.contains("cRLSign"), "extra lists cRLSign")
        } else {
            Err(format!("expected ExtraBitsAsserted, got {outcome:?}").into())
        }
    }

    #[test]
    fn dsc_key_usage_extra_bits_lists_every_offending_label() -> TestResult {
        // All eight first-byte bits set (0xFF, so digitalSignature plus
        // every other named bit through encipherOnly) plus the
        // second-byte decipherOnly (0x80) -- the only test that drives
        // the second KU byte and every individual extra-bit arm.
        let der = build_cert(
            [0x01],
            &dn_cn(b"Issuer"),
            &dn_cn(b"DSC"),
            Some(&ku_ext(true, 0xFF, Some(0x80))),
        );
        let owned = parse_cert(&der)?;
        let cert = owned.view();
        let outcome = CardCheckHelpers::check_dsc_key_usage(&cert);
        if let DscKeyUsageCheck::ExtraBitsAsserted { extra } = &outcome {
            for label in [
                "nonRepudiation",
                "keyEncipherment",
                "dataEncipherment",
                "keyAgreement",
                "keyCertSign",
                "cRLSign",
                "encipherOnly",
                "decipherOnly",
            ] {
                check_true(extra.contains(label), label)?;
            }
            Ok(())
        } else {
            Err(format!("expected ExtraBitsAsserted, got {outcome:?}").into())
        }
    }

    #[test]
    fn dsc_key_usage_describe_strings_match_spec_language() -> TestResult {
        check(
            DscKeyUsageCheck::Compliant.describe().as_str(),
            "ok (digitalSignature critical, only)",
            "Compliant describe",
        )?;
        check_true(
            DscKeyUsageCheck::ExtensionMissing
                .describe()
                .contains("MISSING"),
            "ExtensionMissing describe mentions MISSING",
        )?;
        check_true(
            DscKeyUsageCheck::NotCritical
                .describe()
                .contains("NOT CRITICAL"),
            "NotCritical describe mentions NOT CRITICAL",
        )?;
        check_true(
            DscKeyUsageCheck::ExtraBitsAsserted {
                extra: "keyCertSign".to_owned(),
            }
            .describe()
            .contains("keyCertSign"),
            "ExtraBitsAsserted describe embeds the offending bits",
        )
    }

    // ---------- Master List signer trust evaluation (Doc 9303 Part 12) ----------

    #[test]
    fn signer_eku_compliant_with_critical_ml_signer_oid() -> TestResult {
        let der = build_cert(
            [0x01],
            &dn_cn(b"Root"),
            &dn_cn(b"MLS"),
            Some(&eku_ext(true, [EkuFixtureOid::MlSigner])),
        );
        let owned = parse_cert(&der)?;
        let cert = owned.view();
        check_true(
            matches!(
                CardCheckHelpers::check_signer_eku(&cert),
                SignerEkuCheck::Compliant
            ),
            "critical id-icao-mlSigner EKU is compliant",
        )
    }

    #[test]
    fn signer_eku_extension_missing_when_no_eku() -> TestResult {
        let der = build_cert([0x01], &dn_cn(b"Root"), &dn_cn(b"MLS"), None);
        let owned = parse_cert(&der)?;
        let cert = owned.view();
        check_true(
            matches!(
                CardCheckHelpers::check_signer_eku(&cert),
                SignerEkuCheck::ExtensionMissing
            ),
            "no EKU -> ExtensionMissing",
        )
    }

    #[test]
    fn signer_eku_not_critical_flagged() -> TestResult {
        let der = build_cert(
            [0x01],
            &dn_cn(b"Root"),
            &dn_cn(b"MLS"),
            Some(&eku_ext(false, [EkuFixtureOid::MlSigner])),
        );
        let owned = parse_cert(&der)?;
        let cert = owned.view();
        check_true(
            matches!(
                CardCheckHelpers::check_signer_eku(&cert),
                SignerEkuCheck::NotCritical
            ),
            "non-critical EKU -> NotCritical",
        )
    }

    #[test]
    fn signer_eku_missing_ml_signer_oid_flagged() -> TestResult {
        let der = build_cert(
            [0x01],
            &dn_cn(b"Root"),
            &dn_cn(b"MLS"),
            Some(&eku_ext(true, [EkuFixtureOid::ServerAuth])),
        );
        let owned = parse_cert(&der)?;
        let cert = owned.view();
        check_true(
            matches!(
                CardCheckHelpers::check_signer_eku(&cert),
                SignerEkuCheck::MissingMlSignerOid
            ),
            "critical EKU without id-icao-mlSigner -> MissingMlSignerOid",
        )
    }

    #[test]
    fn signer_basic_constraints_ca_true_is_noncompliant() -> TestResult {
        let der = build_cert(
            [0x01],
            &dn_cn(b"Root"),
            &dn_cn(b"MLS"),
            Some(&bc_ext(true, true)),
        );
        let owned = parse_cert(&der)?;
        let cert = owned.view();
        check_true(
            matches!(
                CardCheckHelpers::check_signer_basic_constraints(&cert),
                SignerBasicConstraintsCheck::CaAsserted
            ),
            "CA=true on MLS -> CaAsserted",
        )
    }

    #[test]
    fn signer_basic_constraints_ca_false_is_compliant() -> TestResult {
        let der = build_cert(
            [0x01],
            &dn_cn(b"Root"),
            &dn_cn(b"MLS"),
            Some(&bc_ext(true, false)),
        );
        let owned = parse_cert(&der)?;
        let cert = owned.view();
        check_true(
            matches!(
                CardCheckHelpers::check_signer_basic_constraints(&cert),
                SignerBasicConstraintsCheck::Compliant
            ),
            "CA=false -> Compliant",
        )
    }

    #[test]
    fn signer_basic_constraints_absent_is_compliant() -> TestResult {
        // Has an (unrelated) KU extension but no BasicConstraints.
        let der = build_cert(
            [0x01],
            &dn_cn(b"Root"),
            &dn_cn(b"MLS"),
            Some(&ku_ext(true, 0x80, None)),
        );
        let owned = parse_cert(&der)?;
        let cert = owned.view();
        check_true(
            matches!(
                CardCheckHelpers::check_signer_basic_constraints(&cert),
                SignerBasicConstraintsCheck::Compliant
            ),
            "absent BasicConstraints -> Compliant",
        )
    }

    #[test]
    fn ml_signer_trust_pinned_for_self_signed_un_root() -> TestResult {
        // The UN CSCA 2 root is self-signed: using it as both the
        // ML signer and the (pin-matching) embedded issuer drives
        // the real signature verification to success.
        let un = un_root_der()?;
        let ml = IcaoMasterList {
            signer_subject_cn: None,
            signer_country: None,
            signer_cert_der: un.clone(),
            embedded_certs_der: vec![un],
            cscas: Vec::new(),
        };
        check_true(
            matches!(
                CardCheckHelpers::check_ml_signer_trust(&ml),
                MlSignerTrust::Pinned { .. }
            ),
            "self-signed UN root verifies and pins",
        )
    }

    #[test]
    fn ml_signer_trust_signature_failed_when_pinned_root_did_not_sign_signer() -> TestResult {
        // Embedded root matches a pin by fingerprint, but the
        // signer was not issued by it -> matched-but-unverified.
        let un = un_root_der()?;
        let signer = build_cert([0x09], &dn_cn(b"Other"), &dn_cn(b"Other"), None);
        let ml = IcaoMasterList {
            signer_subject_cn: None,
            signer_country: None,
            signer_cert_der: signer.into_vec(),
            embedded_certs_der: vec![un],
            cscas: Vec::new(),
        };
        check_true(
            matches!(
                CardCheckHelpers::check_ml_signer_trust(&ml),
                MlSignerTrust::SignatureFailed
            ),
            "pin-matched embedded root that did not sign signer -> SignatureFailed",
        )
    }

    #[test]
    fn ml_signer_trust_no_matching_issuer_when_no_embedded_pin_match() -> TestResult {
        let signer = build_cert([0x09], &dn_cn(b"Other"), &dn_cn(b"Other"), None);
        let ml = IcaoMasterList {
            signer_subject_cn: None,
            signer_country: None,
            signer_cert_der: signer.into_vec(),
            embedded_certs_der: Vec::new(),
            cscas: Vec::new(),
        };
        check_true(
            matches!(
                CardCheckHelpers::check_ml_signer_trust(&ml),
                MlSignerTrust::NoMatchingIssuer
            ),
            "no embedded cert matching a pin -> NoMatchingIssuer",
        )
    }

    #[test]
    fn ml_signer_trust_signature_failed_when_signer_der_unparseable() -> TestResult {
        let ml = IcaoMasterList {
            signer_subject_cn: None,
            signer_country: None,
            signer_cert_der: vec![0x00, 0x01, 0x02],
            embedded_certs_der: Vec::new(),
            cscas: Vec::new(),
        };
        check_true(
            matches!(
                CardCheckHelpers::check_ml_signer_trust(&ml),
                MlSignerTrust::SignatureFailed
            ),
            "unparseable signer DER -> SignatureFailed",
        )
    }

    #[test]
    fn is_ml_fully_trusted_requires_all_three_gates() -> TestResult {
        let pass = trusted_ml(Vec::new());
        check_true(
            is_ml_fully_trusted(&pass),
            "all three gates pass -> trusted",
        )?;

        let bad_trust = LoadedMl {
            trust: MlSignerTrust::NoMatchingIssuer,
            ..trusted_ml(Vec::new())
        };
        check_true(
            !is_ml_fully_trusted(&bad_trust),
            "unpinned signer -> not trusted",
        )?;

        let bad_eku = LoadedMl {
            eku: SignerEkuCheck::ExtensionMissing,
            ..trusted_ml(Vec::new())
        };
        check_true(!is_ml_fully_trusted(&bad_eku), "missing EKU -> not trusted")?;

        let bad_bc = LoadedMl {
            basic_constraints: SignerBasicConstraintsCheck::CaAsserted,
            ..trusted_ml(Vec::new())
        };
        check_true(
            !is_ml_fully_trusted(&bad_bc),
            "CA-asserted MLS -> not trusted",
        )
    }

    #[test]
    fn trust_pool_only_yields_cscas_from_fully_trusted_mls() -> TestResult {
        let fi_a = csca_entry(build_cert(
            [0x01],
            &dn_cn(b"Root"),
            &dn_cn_country(b"CSCA FI A", b"FI"),
            None,
        ))?;
        let fi_b = csca_entry(build_cert(
            [0x02],
            &dn_cn(b"Root"),
            &dn_cn_country(b"CSCA FI B", b"FI"),
            None,
        ))?;
        let de = csca_entry(build_cert(
            [0x03],
            &dn_cn(b"Root"),
            &dn_cn_country(b"CSCA DE", b"DE"),
            None,
        ))?;
        let untrusted = LoadedMl {
            trust: MlSignerTrust::NoMatchingIssuer,
            ..trusted_ml(vec![de])
        };
        let pool = IcaoTrustPool {
            mls: vec![trusted_ml(vec![fi_a, fi_b]), untrusted],
        };
        check(
            &pool.trusted_cscas().count(),
            &2,
            "only the 2 CSCAs from the trusted ML are yielded",
        )
    }

    #[test]
    fn ml_trust_describe_strings_identify_each_outcome() -> TestResult {
        check_true(
            MlSignerTrust::Pinned {
                root_label: "United Nations CSCA 2",
            }
            .describe()
            .contains("United Nations CSCA 2"),
            "Pinned describe names the root",
        )?;
        check_true(
            MlSignerTrust::PinHashMismatch
                .describe()
                .contains("HASH MISMATCH"),
            "PinHashMismatch describe",
        )?;
        check_true(
            MlSignerTrust::NoMatchingIssuer
                .describe()
                .contains("UNPINNED"),
            "NoMatchingIssuer describe",
        )?;
        check_true(
            MlSignerTrust::SignatureFailed
                .describe()
                .contains("did not verify"),
            "SignatureFailed describe",
        )?;
        check(
            SignerEkuCheck::Compliant.describe(),
            "ok (id-icao-mlSigner critical)",
            "EKU Compliant describe",
        )?;
        check(
            SignerBasicConstraintsCheck::CaAsserted.describe(),
            "FAIL -- BasicConstraints CA=true on MLS cert",
            "BC CaAsserted describe",
        )
    }

    // ---------- Trust-anchor pinning: the chain walk ----------

    #[test]
    fn chain_check_ok_when_pinned_on_card_root_closes_chain() -> TestResult {
        // Self-signed DVV RSA root used as leaf, intermediate, and
        // on-card root: every hop verifies and the anchor is pinned.
        let rsa = dvv_root_der(DvvRootNeedle::Rsa)?;
        let leaf_owned = OwnedCert::from_der(rsa).map_err(|e| format!("cert parse: {e}"))?;
        let leaf = leaf_owned.view();
        let ctx = ctx_with_root(Some(&leaf_owned), true)?;
        let issuer = AiaIssuerCertStatus::Parsed(AiaIssuerCert::from_der(rsa)?);
        check_true(
            matches!(run_chain_check(&leaf, &issuer, &ctx), SignatureCheck::Ok),
            "pinned on-card root closes chain -> Ok",
        )
    }

    #[test]
    fn chain_check_skipped_when_on_card_root_not_pinned() -> TestResult {
        let rsa = dvv_root_der(DvvRootNeedle::Rsa)?;
        let leaf_owned = OwnedCert::from_der(rsa).map_err(|e| format!("cert parse: {e}"))?;
        let leaf = leaf_owned.view();
        let ctx = ctx_with_root(Some(&leaf_owned), false)?;
        let issuer = AiaIssuerCertStatus::Parsed(AiaIssuerCert::from_der(rsa)?);
        let outcome = run_chain_check(&leaf, &issuer, &ctx);
        if let SignatureCheck::Skipped(why) = &outcome {
            check_true(
                why.contains("not in PINNED_ROOT_SHA256"),
                "names the pin gap",
            )
        } else {
            Err(format!("expected Skipped, got {outcome:?}").into())
        }
    }

    #[test]
    fn chain_check_skipped_when_no_intermediate_fetched() -> TestResult {
        let rsa = dvv_root_der(DvvRootNeedle::Rsa)?;
        let leaf_owned = OwnedCert::from_der(rsa).map_err(|e| format!("cert parse: {e}"))?;
        let leaf = leaf_owned.view();
        let ctx = ctx_with_root(Some(&leaf_owned), true)?;
        let issuer = AiaIssuerCertStatus::Unavailable;
        let outcome = run_chain_check(&leaf, &issuer, &ctx);
        if let SignatureCheck::Skipped(why) = &outcome {
            check_true(
                why.contains("no AIA caIssuers"),
                "names the missing intermediate",
            )
        } else {
            Err(format!("expected Skipped, got {outcome:?}").into())
        }
    }

    #[test]
    fn chain_check_skipped_when_intermediate_unparseable() -> TestResult {
        let rsa = dvv_root_der(DvvRootNeedle::Rsa)?;
        let leaf_owned = OwnedCert::from_der(rsa).map_err(|e| format!("cert parse: {e}"))?;
        let leaf = leaf_owned.view();
        let ctx = ctx_with_root(Some(&leaf_owned), true)?;
        let issuer = AiaIssuerCertStatus::ParseFailed("fixture parse failure".to_owned());
        let outcome = run_chain_check(&leaf, &issuer, &ctx);
        if let SignatureCheck::Skipped(why) = &outcome {
            check_true(
                why.contains("intermediate parse"),
                "names the parse failure",
            )
        } else {
            Err(format!("expected Skipped, got {outcome:?}").into())
        }
    }

    #[test]
    fn chain_check_failed_when_leaf_not_signed_by_intermediate() -> TestResult {
        // RSA root as leaf, ECC root as claimed intermediate: the
        // leaf -> intermediate hop cannot verify.
        let rsa = dvv_root_der(DvvRootNeedle::Rsa)?;
        let ecc = dvv_root_der(DvvRootNeedle::Ecc)?;
        let leaf_owned = OwnedCert::from_der(rsa).map_err(|e| format!("cert parse: {e}"))?;
        let leaf = leaf_owned.view();
        let ctx = ctx_with_root(Some(&leaf_owned), true)?;
        let issuer = AiaIssuerCertStatus::Parsed(AiaIssuerCert::from_der(ecc)?);
        let outcome = run_chain_check(&leaf, &issuer, &ctx);
        if let SignatureCheck::Failed(why) = &outcome {
            check_true(
                why.contains("leaf -> intermediate"),
                "names the failing hop",
            )
        } else {
            Err(format!("expected Failed, got {outcome:?}").into())
        }
    }

    #[test]
    fn chain_check_skipped_when_no_anchor_and_on_card_root_absent() -> TestResult {
        // Self-signed UN root (not a pinned DVV root) as leaf and
        // intermediate: leaf -> intermediate verifies, but no
        // trust anchor matches and there is no on-card root.
        let un = un_root_der()?;
        let leaf_owned = OwnedCert::from_der(&un).map_err(|e| format!("cert parse: {e}"))?;
        let leaf = leaf_owned.view();
        let ctx = ctx_with_root(None, false)?;
        let issuer = AiaIssuerCertStatus::Parsed(AiaIssuerCert::from_der(&un)?);
        let outcome = run_chain_check(&leaf, &issuer, &ctx);
        if let SignatureCheck::Skipped(why) = &outcome {
            check_true(
                why.contains("no trust anchor matched"),
                "names the missing anchor (root absent)",
            )
        } else {
            Err(format!("expected Skipped, got {outcome:?}").into())
        }
    }

    #[test]
    fn chain_check_failed_when_no_anchor_and_on_card_root_present() -> TestResult {
        // Same as above but an (irrelevant) on-card root is present
        // -> the verdict is a hard Failed, not Skipped.
        let un = un_root_der()?;
        let rsa = dvv_root_der(DvvRootNeedle::Rsa)?;
        let root_owned = OwnedCert::from_der(rsa).map_err(|e| format!("root parse: {e}"))?;
        let leaf_owned = OwnedCert::from_der(&un).map_err(|e| format!("cert parse: {e}"))?;
        let leaf = leaf_owned.view();
        let ctx = ctx_with_root(Some(&root_owned), true)?;
        let issuer = AiaIssuerCertStatus::Parsed(AiaIssuerCert::from_der(&un)?);
        let outcome = run_chain_check(&leaf, &issuer, &ctx);
        if let SignatureCheck::Failed(why) = &outcome {
            check_true(
                why.contains("no trust anchor verified"),
                "names the anchor failure (root present)",
            )
        } else {
            Err(format!("expected Failed, got {outcome:?}").into())
        }
    }

    // ---------- DSC -> CSCA chaining ----------

    #[test]
    fn dsc_csca_no_dsc_when_sod_absent() -> TestResult {
        let pool = IcaoTrustPool { mls: Vec::new() };
        check_true(
            matches!(
                CardCheckHelpers::dsc_csca_check_for_sod(None, &pool),
                DscCscaCheck::NoDscInSod
            ),
            "absent SOD -> NoDscInSod",
        )
    }

    #[test]
    fn dsc_csca_no_dsc_when_sod_unparseable() -> TestResult {
        // Deliberately not a DER SEQUENCE, so the CMS parse fails.
        const NOT_CMS: [u8; 3] = [0x01, 0x02, 0x03];
        let pool = IcaoTrustPool { mls: Vec::new() };
        check_true(
            matches!(
                CardCheckHelpers::dsc_csca_check_for_sod(Some(SodDer { bytes: &NOT_CMS }), &pool,),
                DscCscaCheck::NoDscInSod
            ),
            "unparseable CMS -> NoDscInSod",
        )
    }

    #[test]
    fn dsc_csca_no_dsc_when_sod_has_no_certificates() -> TestResult {
        let pool = IcaoTrustPool { mls: Vec::new() };
        let sod = build_sod(&[]);
        // Guard: the empty SOD really parses as CMS with zero certs, so
        // the NoDscInSod verdict below is reached via the empty-cert-list
        // branch -- not via a CMS parse failure, which returns the same
        // variant and would otherwise mask a regression in build_sod.
        let signed = OwnedSignedData::from_der(sod.as_slice())
            .map_err(|e| format!("empty SOD must parse: {e}"))?;
        check_true(
            signed.view().certificates_der.is_empty(),
            "empty SOD parses with zero embedded certs",
        )?;
        check_true(
            matches!(
                CardCheckHelpers::dsc_csca_check_for_sod(Some(sod_der(&sod)), &pool),
                DscCscaCheck::NoDscInSod
            ),
            "SOD with no embedded cert -> NoDscInSod",
        )
    }

    #[test]
    fn dsc_csca_parse_failed_when_embedded_cert_not_x509() -> TestResult {
        let pool = IcaoTrustPool { mls: Vec::new() };
        // A SEQUENCE that is structurally a cert slot but not a cert.
        let fake_cert = tlv(
            DER_TAG_SEQUENCE,
            &tlv_array(DER_TAG_INTEGER, [CERT_SERIAL_ONE]),
        );
        let sod = build_sod(&[&fake_cert]);
        check_true(
            matches!(
                CardCheckHelpers::dsc_csca_check_for_sod(Some(sod_der(&sod)), &pool),
                DscCscaCheck::DscParseFailed
            ),
            "embedded non-cert SEQUENCE -> DscParseFailed",
        )
    }

    #[test]
    fn dsc_csca_key_usage_noncompliant_short_circuits() -> TestResult {
        let pool = IcaoTrustPool { mls: Vec::new() };
        // DSC with a CA-style KU (digitalSignature + keyCertSign).
        let dsc = build_cert(
            [0x01],
            &dn_cn_country(b"DSC issuer", b"FI"),
            &dn_cn(b"DSC"),
            Some(&ku_ext(true, 0x84, None)),
        );
        let sod = build_sod(&[&dsc]);
        check_true(
            matches!(
                CardCheckHelpers::dsc_csca_check_for_sod(Some(sod_der(&sod)), &pool),
                DscCscaCheck::KeyUsageNonCompliant(_)
            ),
            "non-compliant DSC KU short-circuits before the chain walk",
        )
    }

    #[test]
    fn dsc_csca_country_unknown_when_issuer_has_no_country() -> TestResult {
        let pool = IcaoTrustPool { mls: Vec::new() };
        let dsc = build_cert(
            [0x01],
            &dn_cn(b"DSC issuer no country"),
            &dn_cn(b"DSC"),
            Some(&ku_ext(true, 0x80, None)),
        );
        let sod = build_sod(&[&dsc]);
        check_true(
            matches!(
                CardCheckHelpers::dsc_csca_check_for_sod(Some(sod_der(&sod)), &pool),
                DscCscaCheck::DscCountryUnknown
            ),
            "compliant DSC without issuer country -> DscCountryUnknown",
        )
    }

    #[test]
    fn dsc_csca_country_absent_when_pool_lacks_the_country() -> TestResult {
        // DSC issued by FI, but the pool only carries a DE CSCA.
        let de = csca_entry(build_cert(
            [0x03],
            &dn_cn(b"Root"),
            &dn_cn_country(b"CSCA DE", b"DE"),
            None,
        ))?;
        let pool = IcaoTrustPool {
            mls: vec![trusted_ml(vec![de])],
        };
        let dsc = build_cert(
            [0x01],
            &dn_cn_country(b"DSC issuer", b"FI"),
            &dn_cn(b"DSC"),
            Some(&ku_ext(true, 0x80, None)),
        );
        let sod = build_sod(&[&dsc]);
        let outcome = CardCheckHelpers::dsc_csca_check_for_sod(Some(sod_der(&sod)), &pool);
        if let DscCscaCheck::CountryAbsent { country_iso } = &outcome {
            check(country_iso.as_str(), "FI", "country absent reports FI")
        } else {
            Err(format!("expected CountryAbsent, got {outcome:?}").into())
        }
    }

    // NOTE: the positive `DscCscaCheck::Ok` verdict is intentionally not
    // unit-tested here. Reaching it needs `dsc.verify_signed_by(csca)` to
    // succeed, i.e. a DSC carrying a real CSCA signature AND a compliant
    // `digitalSignature`-only KU. The only self-verifying certificates
    // available in-process are the pinned CA roots, which assert
    // `keyCertSign`/`cRLSign` and so fail the Doc 9303 sec.7.1.1 KU gate
    // before the chain walk. A faithful Ok test needs either a checked-in
    // real DSC+CSCA fixture pair or an in-crate signing helper (the crypto
    // layer is verify-only by design); it belongs in an integration test.

    #[test]
    fn dsc_csca_no_match_when_candidate_dn_differs() -> TestResult {
        // The pool has an FI CSCA, but its subject DN differs from the
        // DSC issuer DN, so every candidate is dropped at the DN gate
        // before any signature check.
        let fi = csca_entry(build_cert(
            [0x02],
            &dn_cn(b"Root"),
            &dn_cn_country(b"Some other FI CSCA", b"FI"),
            None,
        ))?;
        let pool = IcaoTrustPool {
            mls: vec![trusted_ml(vec![fi])],
        };
        let dsc = build_cert(
            [0x01],
            &dn_cn_country(b"DSC issuer", b"FI"),
            &dn_cn(b"DSC"),
            Some(&ku_ext(true, 0x80, None)),
        );
        let sod = build_sod(&[&dsc]);
        let outcome = CardCheckHelpers::dsc_csca_check_for_sod(Some(sod_der(&sod)), &pool);
        if let DscCscaCheck::NoMatch {
            country_iso,
            candidates,
        } = &outcome
        {
            check(country_iso.as_str(), "FI", "no-match reports FI")?;
            check(candidates, &1, "one FI candidate was tried")
        } else {
            Err(format!("expected NoMatch, got {outcome:?}").into())
        }
    }

    #[test]
    fn dsc_csca_no_match_when_candidate_signature_fails() -> TestResult {
        // The CSCA subject DN is byte-identical to the DSC issuer DN, so
        // the DN-equality gate passes and the candidate reaches the real
        // `verify_signed_by` step -- which fails (padding signature). This
        // exercises the signature-verify branch of NoMatch that the
        // DN-differs case never reaches.
        let issuer_dn = dn_cn_country(b"DSC issuer", b"FI");
        let fi = csca_entry(build_cert([0x02], &dn_cn(b"Root"), &issuer_dn, None))?;
        let pool = IcaoTrustPool {
            mls: vec![trusted_ml(vec![fi])],
        };
        let dsc = build_cert(
            [0x01],
            &issuer_dn,
            &dn_cn(b"DSC"),
            Some(&ku_ext(true, 0x80, None)),
        );
        let sod = build_sod(&[&dsc]);
        let outcome = CardCheckHelpers::dsc_csca_check_for_sod(Some(sod_der(&sod)), &pool);
        if let DscCscaCheck::NoMatch {
            country_iso,
            candidates,
        } = &outcome
        {
            check(country_iso.as_str(), "FI", "no-match reports FI")?;
            check(candidates, &1, "the one DN-matching candidate was tried")
        } else {
            Err(format!("expected NoMatch, got {outcome:?}").into())
        }
    }

    #[test]
    fn render_dsc_csca_covers_every_variant() -> TestResult {
        // Typed CommonName / IsoAlpha2 come from parsing a built cert
        // (their constructors are crate-private to refineid-lib-core).
        let owned = parse_cert(&build_cert(
            [0x01],
            &dn_cn(b"Root"),
            &dn_cn_country(b"CSCA FI", b"FI"),
            None,
        ))?;
        let view = owned.view();
        let cn = view.subject.common_name();
        let country = view.subject.country();
        let iso = country
            .clone()
            .ok_or_else(|| "FI country parses".to_owned())?;

        // Ok with populated CN + country exercises the non-fallback
        // format path (not the "<unparsed CN>" / "??" arms).
        let ok_rendered = CardCheckHelpers::render_dsc_csca(&DscCscaCheck::Ok {
            csca_subject_cn: cn,
            csca_country: country,
            csca_sha256: Sha256::of(b"csca"),
        });
        check_true(ok_rendered.starts_with("ok via"), "Ok render prefix")?;
        check_true(
            ok_rendered.contains("CSCA FI"),
            "Ok render names the CSCA CN",
        )?;
        check_true(
            ok_rendered.contains("(FI)"),
            "Ok render names the CSCA country",
        )?;

        check_true(
            CardCheckHelpers::render_dsc_csca(&DscCscaCheck::KeyUsageNonCompliant(
                DscKeyUsageCheck::ExtensionMissing,
            ))
            .contains("KeyUsage non-compliant"),
            "KeyUsageNonCompliant render",
        )?;
        let no_match = CardCheckHelpers::render_dsc_csca(&DscCscaCheck::NoMatch {
            country_iso: iso.clone(),
            candidates: 3,
        });
        check_true(
            no_match.contains("3 candidate"),
            "NoMatch render names the count",
        )?;
        check_true(no_match.contains("FI"), "NoMatch render names the country")?;
        check_true(
            CardCheckHelpers::render_dsc_csca(&DscCscaCheck::CountryAbsent { country_iso: iso })
                .contains("FI"),
            "CountryAbsent render names the country",
        )?;
        check_true(
            CardCheckHelpers::render_dsc_csca(&DscCscaCheck::DscCountryUnknown)
                .contains("no countryName"),
            "DscCountryUnknown render",
        )?;
        check_true(
            CardCheckHelpers::render_dsc_csca(&DscCscaCheck::NoDscInSod).contains("no DSC"),
            "NoDscInSod render",
        )?;
        check_true(
            CardCheckHelpers::render_dsc_csca(&DscCscaCheck::DscParseFailed)
                .contains("failed to parse"),
            "DscParseFailed render",
        )
    }

    // ---------- CRL verdict orchestration ----------

    #[test]
    fn verify_crl_errors_without_issuer_cert() -> TestResult {
        let crl_der = build_crl(&dn_cn(b"Alice"));
        let owned =
            OwnedCrl::from_der(crl_der.as_slice()).map_err(|e| format!("crl parse: {e}"))?;
        let crl = owned.view();
        let issuer = AiaIssuerCertStatus::Unavailable;
        match verify_crl(&crl, &issuer) {
            Err(why) => check_true(why.contains("no AIA caIssuers"), "names the missing issuer"),
            Ok(_) => Err("verify_crl unexpectedly succeeded without an issuer".into()),
        }
    }

    #[test]
    fn verify_crl_errors_on_issuer_dn_mismatch() -> TestResult {
        let crl_der = build_crl(&dn_cn(b"Alice"));
        let owned =
            OwnedCrl::from_der(crl_der.as_slice()).map_err(|e| format!("crl parse: {e}"))?;
        let crl = owned.view();
        // Issuer cert subject is "Bob" -- different DN than the CRL issuer.
        let issuer = build_cert([0x01], &dn_cn(b"Bob"), &dn_cn(b"Bob"), None);
        let issuer = AiaIssuerCertStatus::Parsed(AiaIssuerCert::from_der(issuer.as_slice())?);
        match verify_crl(&crl, &issuer) {
            Err(why) => check_true(why.contains("does not match"), "names the DN mismatch"),
            Ok(_) => Err("verify_crl unexpectedly succeeded on a DN mismatch".into()),
        }
    }

    #[test]
    fn verify_crl_reaches_signature_check_on_dn_match() -> TestResult {
        // Issuer cert subject DN equals the CRL issuer DN, so the
        // DN gate passes and the (padding) signature is actually
        // verified -- which fails. The point is that the
        // orchestration advanced past the DN gate to the crypto
        // check rather than short-circuiting.
        let crl_der = build_crl(&dn_cn(b"Alice"));
        let owned =
            OwnedCrl::from_der(crl_der.as_slice()).map_err(|e| format!("crl parse: {e}"))?;
        let crl = owned.view();
        let issuer = build_cert([0x01], &dn_cn(b"Issuer"), &dn_cn(b"Alice"), None);
        let issuer = AiaIssuerCertStatus::Parsed(AiaIssuerCert::from_der(issuer.as_slice())?);
        match verify_crl(&crl, &issuer) {
            Err(why) => check_true(
                !why.contains("does not match") && !why.contains("no AIA caIssuers"),
                "reached the signature verify stage (not a precondition error)",
            ),
            Ok(_) => Err("padding-signed CRL must not verify".into()),
        }
    }

    #[test]
    fn fmt_check_outcome_renders_status_and_skipped() -> TestResult {
        let status = CheckOutcome::Status {
            source: "http://crl.example/test.crl".to_owned(),
            status: RevocationStatus::Good,
            signature: SignatureCheck::Ok,
            nonce: None,
        };
        let rendered = format!("{}", ShowOutcome(&status));
        check_true(rendered.contains("good"), "status renders the verdict")?;
        check_true(
            rendered.contains("signature:"),
            "status renders the signature line",
        )?;
        check_true(
            rendered.contains("http://crl.example/test.crl"),
            "status renders the source",
        )?;

        let skipped = CheckOutcome::Skipped {
            source: "(pre-fetched file)".to_owned(),
            why: "CRL parse: bad".to_owned(),
        };
        let rendered = format!("{}", ShowOutcome(&skipped));
        check_true(
            rendered.contains("skipped (CRL parse: bad)"),
            "skipped renders the reason",
        )
    }

    #[test]
    fn fmt_revocation_covers_each_status() -> TestResult {
        check(
            CardCheckHelpers::fmt_revocation(&RevocationStatus::Good).as_str(),
            "good",
            "Good",
        )?;
        check(
            CardCheckHelpers::fmt_revocation(&RevocationStatus::Unknown).as_str(),
            "unknown",
            "Unknown",
        )?;
        check_true(
            CardCheckHelpers::fmt_revocation(&RevocationStatus::Stale).contains("stale"),
            "Stale",
        )?;
        let at = DateTime::new(2026, 1, 2, 3, 4, 5).map_err(|e| format!("date: {e}"))?;
        check_true(
            CardCheckHelpers::fmt_revocation(&RevocationStatus::Revoked { at, reason: None })
                .contains("REVOKED at"),
            "Revoked",
        )?;
        check_true(
            CardCheckHelpers::fmt_revocation(&RevocationStatus::Inapplicable(
                InapplicableReason::CrlIssuerMismatch,
            ))
            .contains("inapplicable"),
            "Inapplicable",
        )
    }

    #[test]
    fn fmt_signature_check_covers_each_variant() -> TestResult {
        check(
            CardCheckHelpers::fmt_signature_check(&SignatureCheck::Ok).as_str(),
            "ok",
            "Ok",
        )?;
        check(
            CardCheckHelpers::fmt_signature_check(&SignatureCheck::Skipped("offline".to_owned()))
                .as_str(),
            "skipped (offline)",
            "Skipped",
        )?;
        check(
            CardCheckHelpers::fmt_signature_check(&SignatureCheck::Failed("bad sig".to_owned()))
                .as_str(),
            "FAILED (bad sig)",
            "Failed",
        )
    }

    // ---------- PIN / outcome / arithmetic renderers ----------

    #[test]
    fn render_pin_status_covers_each_variant() -> TestResult {
        check_true(
            CardCheckHelpers::render_pin_status(Some(&PinStatus::Verified)).contains("verified"),
            "Verified",
        )?;
        let three = PinRetries::from_nibble(3).ok_or("3 is a valid nibble")?;
        check_true(
            CardCheckHelpers::render_pin_status(Some(&PinStatus::Remaining(three)))
                .contains("3 retries left"),
            "Remaining",
        )?;
        check_true(
            CardCheckHelpers::render_pin_status(Some(&PinStatus::Locked)).contains("BLOCKED"),
            "Locked",
        )?;
        check_true(
            CardCheckHelpers::render_pin_status(Some(&PinStatus::NoInfo)).contains("no retry"),
            "NoInfo",
        )?;
        check_true(
            CardCheckHelpers::render_pin_status(None).contains("probe failed"),
            "absent probe",
        )
    }

    #[test]
    fn render_puk_status_covers_counter_and_terminal_states() -> TestResult {
        let four = PinRetries::from_nibble(4).ok_or("4 is a valid nibble")?;
        check_true(
            CardCheckHelpers::render_puk_status(Some(&PukStatus::Remaining(four)))
                .contains("4 retries left"),
            "PUK remaining",
        )?;
        check_true(
            CardCheckHelpers::render_puk_status(Some(&PukStatus::Locked)).contains("BLOCKED"),
            "PUK locked",
        )?;
        check_true(
            CardCheckHelpers::render_puk_status(Some(&PukStatus::Invalidated))
                .contains("INVALIDATED"),
            "PUK invalidated",
        )?;
        check_true(
            CardCheckHelpers::render_puk_status(None).contains("probe failed"),
            "PUK absent probe",
        )
    }

    #[test]
    fn render_policy_counters_reports_card_no_limit() -> TestResult {
        let policy = CredentialPolicyCounters {
            usage: UsageCounter::NoLimit,
            unblocking: UnblockingCounter::NoLimit,
        };
        check(
            CardCheckHelpers::render_usage_counter(Some(&policy)).as_str(),
            "no limit",
            "usage",
        )?;
        check(
            CardCheckHelpers::render_unblocking_counter(Some(&policy)).as_str(),
            "no limit",
            "unblocking",
        )
    }

    #[test]
    fn render_pin_changed_covers_each_state() -> TestResult {
        check(
            CardCheckHelpers::render_pin_changed(Some(true)),
            "yes",
            "changed",
        )?;
        check_true(
            CardCheckHelpers::render_pin_changed(Some(false)).contains("factory"),
            "factory",
        )?;
        check_true(
            CardCheckHelpers::render_pin_changed(None).contains("indeterminate"),
            "indeterminate",
        )
    }

    #[test]
    fn render_ca_outcome_covers_each_variant() -> TestResult {
        check_true(
            CardCheckHelpers::render_ca_outcome(&CaOutcome::Verified {
                protocol_label: "id-CA-ECDH-AES-CBC-CMAC-256",
            })
            .contains("not cloned"),
            "Verified",
        )?;
        check_true(
            CardCheckHelpers::render_ca_outcome(&CaOutcome::VerificationFailed {
                detail: "MAC mismatch".to_owned(),
            })
            .contains("FAILED"),
            "VerificationFailed",
        )?;
        check_true(
            CardCheckHelpers::render_ca_outcome(&CaOutcome::MseRejected { sw: 0x6A80 })
                .contains("MSE:Set AT"),
            "MseRejected",
        )?;
        check_true(
            CardCheckHelpers::render_ca_outcome(&CaOutcome::GaRejected { sw: 0x6A80 })
                .contains("General Authenticate"),
            "GaRejected",
        )?;
        check_true(
            CardCheckHelpers::render_ca_outcome(&CaOutcome::NoSupportedProtocol)
                .contains("no supported"),
            "NoSupportedProtocol",
        )?;
        check_true(
            CardCheckHelpers::render_ca_outcome(&CaOutcome::UnsupportedCurve)
                .contains("not supported"),
            "UnsupportedCurve",
        )
    }

    #[test]
    fn render_aa_outcome_covers_each_variant() -> TestResult {
        check_true(
            CardCheckHelpers::render_aa_outcome(&AaOutcome::Verified {
                hash: HashAlg::Sha256,
                m1_len: 202,
            })
            .contains("SHA-256"),
            "Verified",
        )?;
        check_true(
            CardCheckHelpers::render_aa_outcome(&AaOutcome::CardRejected { sw: 0x6982 })
                .contains("INTERNAL AUTHENTICATE"),
            "CardRejected",
        )?;
        check_true(
            CardCheckHelpers::render_aa_outcome(&AaOutcome::SignatureInvalid {
                detail: "bad trailer".to_owned(),
            })
            .contains("INVALID"),
            "SignatureInvalid",
        )
    }

    #[test]
    fn days_between_is_signed_and_symmetric() -> TestResult {
        let a = DateTime::new(2026, 1, 1, 0, 0, 0).map_err(|e| format!("a: {e}"))?;
        let b = DateTime::new(2026, 1, 11, 0, 0, 0).map_err(|e| format!("b: {e}"))?;
        check(&days_between(a, b), &10, "10 days forward")?;
        check(&days_between(b, a), &-10, "10 days backward is negative")?;
        check(&days_between(a, a), &0, "same instant is zero")
    }

    #[test]
    fn looks_like_der_sequence_sniffs_first_byte() -> TestResult {
        let der = IcaoPkdFileBytes {
            bytes: vec![DER_SEQUENCE_TAG, 0x82, 0x01, 0x00],
        };
        let ldif = IcaoPkdFileBytes {
            bytes: b"version: 1\n".to_vec(),
        };
        let empty = IcaoPkdFileBytes { bytes: Vec::new() };
        check_true(der.looks_like_der_sequence(), "leading SEQUENCE tag -> DER")?;
        check_true(!ldif.looks_like_der_sequence(), "ASCII LDIF -> not DER")?;
        check_true(!empty.looks_like_der_sequence(), "empty input -> not DER")
    }

    #[test]
    fn now_date_time_is_a_sane_recent_instant() -> TestResult {
        let now = now_date_time();
        check_true(now.year() >= 2024, "clock is not before 2024")?;
        check_true(now.year() <= 9999, "clock is within DateTime range")
    }

    #[test]
    fn render_mrz_expiry_distinguishes_valid_from_expired() -> TestResult {
        // YY < 50 resolves to the 2000s (ICAO 9303-3 sec.4.5). 2049 is
        // future relative to any plausible run date; 2020 is past.
        let future = MrzDate::from_mrz_yymmdd(*b"491231").map_err(|e| format!("future: {e}"))?;
        let rendered = CardCheckHelpers::render_mrz_expiry(&future);
        check_true(
            rendered.contains("2049-12-31"),
            "renders the resolved ISO date",
        )?;
        check_true(rendered.contains("valid"), "future expiry reads as valid")?;
        let past = MrzDate::from_mrz_yymmdd(*b"200101").map_err(|e| format!("past: {e}"))?;
        check_true(
            CardCheckHelpers::render_mrz_expiry(&past).contains("EXPIRED"),
            "past expiry reads as EXPIRED",
        )
    }

    // ---------- load_icao_pkd error paths ----------

    #[test]
    fn load_icao_pkd_surfaces_read_error_for_missing_file() -> TestResult {
        let path = std::path::Path::new("/nonexistent/refineid/card-check/does-not-exist.ml");
        match CardCheckHelpers::load_icao_pkd(path) {
            Err(CardCheckError::IcaoPkdRead { .. }) => Ok(()),
            Err(other) => Err(format!("expected IcaoPkdRead, got {other:?}").into()),
            Ok(_) => Err("loading a missing file unexpectedly succeeded".into()),
        }
    }

    #[test]
    fn load_icao_pkd_rejects_der_that_fails_to_parse() -> TestResult {
        // Leading 0x30 -> sniffed as DER, but the body is not a valid
        // CMS Master List, so the single-DER load aborts with IcaoPkdParse.
        let path = std::env::temp_dir().join("refineid_card_check_der_junk.ml");
        std::fs::write(&path, [0x30_u8, 0x03, 0x02, 0x01, 0x01])
            .map_err(|e| format!("write: {e}"))?;
        let result = CardCheckHelpers::load_icao_pkd(&path);
        std::fs::remove_file(&path).map_err(|e| format!("cleanup: {e}"))?;
        match result {
            Err(CardCheckError::IcaoPkdParse { .. }) => Ok(()),
            Err(other) => Err(format!("expected IcaoPkdParse, got {other:?}").into()),
            Ok(_) => Err("DER junk unexpectedly loaded".into()),
        }
    }

    #[test]
    fn load_icao_pkd_rejects_input_that_is_neither_der_nor_utf8() -> TestResult {
        // Leading byte != 0x30 -> not DER; the bytes are not valid UTF-8
        // either, so the LDIF text decode fails with IcaoPkdParse.
        let path = std::env::temp_dir().join("refineid_card_check_non_utf8.ml");
        std::fs::write(&path, [0xFF_u8, 0xFE, 0x00, 0x01]).map_err(|e| format!("write: {e}"))?;
        let result = CardCheckHelpers::load_icao_pkd(&path);
        std::fs::remove_file(&path).map_err(|e| format!("cleanup: {e}"))?;
        match result {
            Err(CardCheckError::IcaoPkdParse { .. }) => Ok(()),
            Err(other) => Err(format!("expected IcaoPkdParse, got {other:?}").into()),
            Ok(_) => Err("non-DER non-UTF8 input unexpectedly loaded".into()),
        }
    }

    #[test]
    fn card_check_error_display_is_prefixed() -> TestResult {
        let err = CardCheckError::CertParse("bad tag".to_owned());
        check(
            format!("{err}").as_str(),
            "cert parse: bad tag",
            "CertParse display",
        )?;
        let err = CardCheckError::Rng("no entropy".to_owned());
        check_true(
            format!("{err}").contains("OS RNG unavailable"),
            "Rng display",
        )
    }
}
