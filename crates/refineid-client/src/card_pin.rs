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

//! `refineid card change-pin{1,2}` / `card unblock-pin{1,2}` /
//! `card pin-status`.
//!
//! PIN-management surface for both FINEID PIN slots:
//! - PIN1 (auth, ref `0x11`) gates the auth key.
//! - PIN2 (qualified-signature, ref `0x82`) gates the QES key.
//!
//! The PUK (ref `0x83`) unblocks either
//! slot per FINEID S4-1 v3.1 §4.1 -- the same 8-digit secret is
//! the recovery path for both PIN1 and PIN2.
//!
//! PIN bytes never reach argv, env, or any log line; the prompts
//! use rpassword (or stdin bufread when no tty) and the move into
//! [`PinBytes`] is immediate so the buffer zeroes on drop.

use alloc::fmt;

use refineid_lib_core::auth::{
    AuthError, ChangePinOutcome, PinOps as _, PinPolicyReason, PinSlot, PinStatus, UnblockOutcome,
};
use refineid_lib_core::backend::{
    ReaderAccessCap, ReaderBackend as _, ReaderFilter, ReaderPickError,
};
use refineid_lib_core::crypto::digest::Sha256;
use refineid_lib_core::fineid_card::{CardClassificationError, FineidCardModel};
use refineid_lib_core::pin::{
    ActivationCode, ActivationPinEight, ActivationPinSeven, PinBytes, Puk,
};
use refineid_lib_core::pin_retry_risk::PinRetryRisk;
use refineid_lib_core::pkcs15::{
    CardGeneration, CertSlot, FineidReaderPick, classify_card_generation,
    classify_card_generation_by_issuance,
};
use refineid_lib_core::pkcs15::{FineidReaderPicker as _, Pkcs15Ops as _};
use refineid_lib_core::x509::{DateTime, OwnedCert};
use refineid_lib_pcsc::{PcscBackend, PcscError};

/// Which PIN slot a manage-PIN operation targets. Thin layer over
/// [`PinSlot`] that also carries the user-facing label so error
/// messages and reports read naturally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinManageSlot {
    /// Authentication PIN (FINEID S4-1 v3.1 §4.1.1, PIN reference
    /// `0x11`); gates the authentication key.
    Pin1,
    /// Qualified-signature PIN (FINEID S4-1 v3.1 §4.1.1, PIN
    /// reference `0x82`); gates the non-repudiation signing key.
    Pin2,
}

impl PinManageSlot {
    /// Project to the lib-core [`PinSlot`] enum used by transport-
    /// level APDU builders. Drops the CLI-only label and keeps
    /// only the reference-byte mapping.
    #[must_use]
    pub const fn as_pin_slot(self) -> PinSlot {
        match self {
            Self::Pin1 => PinSlot::Pin1,
            Self::Pin2 => PinSlot::Pin2,
        }
    }
    /// User-facing label ("PIN1" / "PIN2") for prompts and report
    /// strings. `&'static str` from a fixed compile-time set.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pin1 => "PIN1",
            Self::Pin2 => "PIN2",
        }
    }
}

/// Inputs for `card change-pin{1,2}`.
#[derive(Debug)]
pub struct ChangePinOptions {
    /// Which PIN slot to rotate. Drives both the APDU PIN
    /// reference byte and the spec rule applied to the new PIN
    /// length policy.
    pub slot: PinManageSlot,
    /// Current PIN value (the one the operator typed in the
    /// "current PIN" prompt). Consumed and zeroized at function
    /// return.
    pub current: PinBytes,
    /// New PIN value (the one the operator typed in the
    /// "new PIN" prompt). Consumed and zeroized at function
    /// return.
    pub new: PinBytes,
    /// Optional substring match against reader names; same
    /// semantics as the rest of the client crate. `None` accepts
    /// any single FINEID-responding reader (errors on ambiguity).
    /// Tier 0 `String` -- carried verbatim to
    /// `ReaderFilter::new`; tighter form would be `ReaderFilter`.
    pub reader_filter: Option<String>,
}

/// One reader's worth of change-pin output.
#[derive(Debug, Clone)]
pub struct ChangePinReport {
    /// PC/SC reader name the modify APDU landed against. Tier 0
    /// `String` from `ReaderId::as_str().to_owned()`; tighter
    /// form would be `ReaderId`.
    pub reader: String,
    /// `CredentialIdentity::best_serial()` of the trust-gated
    /// card: PKCS#15 token serial when present, else printed /
    /// PEUIN form. Empty string when nothing was readable.
    /// Surfaced so the operator can confirm which physical card
    /// the PIN op landed against when multiple readers are
    /// connected.
    pub card_serial: String,
    /// `CredentialIdentity::person_string()` rendering --
    /// "SURNAME GIVENS PEUIN" form (still uppercase per
    /// DVV-emitted cert subject; the typed [`NativeName`]
    /// rendering is a separate concern).
    ///
    /// [`NativeName`]: refineid_lib_core::identity::NativeName
    pub person: String,
    /// Which PIN slot the modify APDU targeted.
    pub slot: PinManageSlot,
    /// Card-side outcome from `CHANGE REFERENCE DATA`
    /// (FINEID S4-1 v3.1 §4.1.3 / ISO 7816-4 §7.5.7): Ok,
    /// `WrongCurrentPin` with retries, Locked, etc.
    pub outcome: ChangePinOutcome,
}

/// Inputs for `card unblock-pin{1,2}`.
#[derive(Debug)]
pub struct UnblockPinOptions {
    /// Which PIN slot to unblock. Both PIN1 and PIN2 share the
    /// same PUK reference (`0x83`) per FINEID S4-1 v3.1 §4.1.
    pub slot: PinManageSlot,
    /// The 7-or-8-digit PUK code. Typed [`Puk`] forces construction
    /// via [`Puk::new`] at the operator-input boundary, so a
    /// non-PUK `PinBytes` value (e.g. a PIN or activation code)
    /// can't reach the `RESET RETRY COUNTER` APDU by accident.
    pub puk: Puk,
    /// New PIN value to set after the unblock succeeds. Consumed
    /// and zeroized at function return.
    pub new_pin: PinBytes,
    /// Optional substring match against reader names; same
    /// semantics as [`ChangePinOptions::reader_filter`]. Tier 0
    /// `String` -- presentational input to `ReaderFilter::new`.
    pub reader_filter: Option<String>,
}

/// One reader's worth of unblock output.
#[derive(Debug, Clone)]
pub struct UnblockPinReport {
    /// See [`ChangePinReport::reader`].
    pub reader: String,
    /// See [`ChangePinReport::card_serial`].
    pub card_serial: String,
    /// See [`ChangePinReport::person`].
    pub person: String,
    /// Which PIN slot the unblock APDU targeted.
    pub slot: PinManageSlot,
    /// Card-side outcome from `RESET RETRY COUNTER`
    /// (FINEID S4-1 v3.1 §4.1.4 / ISO 7816-4 §7.5.10): Ok,
    /// `WrongPuk` with retries, `PukLocked`, etc.
    pub outcome: UnblockOutcome,
}

/// Error returned from the PIN-management entrypoints
/// (`card change-pin*`, `card unblock-pin*`, `card activate`).
#[derive(Debug)]
pub enum CardPinError {
    /// Reader enumeration / filter resolution failed.
    ReaderPick(ReaderPickError),
    /// PC/SC transport / transmit error.
    Pcsc(PcscError),
    /// Local-policy rejection (length / non-digit) before any
    /// APDU went out. Retry counter is unaffected.
    PinPolicy(PinPolicyReason),
    /// Couldn't SELECT the PKCS#15 application. FINEID gates the
    /// PIN-management INS bytes (0x20 status-form, 0x24, 0x2C)
    /// behind app SELECT -- SW=6D00 otherwise.
    Pkcs15Select(String),
    /// Lower-level transport / APDU failure not specific to PKCS#15
    /// SELECT (cert read, EF.TokenInfo read, ...). Tier 0 `String`
    /// -- presentational rendering of the upstream error.
    Transport(String),
    /// `card activate` only: the activation PIN length the
    /// operator entered doesn't match what the classified card
    /// generation requires. Reported *before* any modify APDU,
    /// so the card-side try counter is untouched.
    ActivationLengthMismatch {
        /// Card generation that was detected by classification.
        generation: CardGeneration,
        /// Activation-PIN length the spec requires for that
        /// generation (7 for newer, 8 for older). Tier 0 `usize`
        /// -- the typed projection is
        /// `CardGeneration::activation_pin_length()`; this field
        /// just carries the per-call expected value for the
        /// error message.
        expected: usize,
    },
    /// `card activate` only: refineid couldn't classify the
    /// card generation and won't guess at activation-PIN length
    /// on the operator's behalf.
    UnknownCardGeneration,
    /// `card activate` only: the card's data couldn't be
    /// authenticated against a pinned anchor. The activation
    /// flow refuses to use untrusted card-side data (issuance
    /// date, etc.) for type selection -- without a verified
    /// chain anchor the data could be from a counterfeit card.
    CardDataUntrusted {
        /// Human-readable detail from
        /// `CardTrustAttestation::describe` explaining which
        /// trust gate failed (no pinned root match, cert read
        /// error, etc.). Tier 0 `String`; presentational.
        description: String,
    },
    /// The trusted card session was invalidated between the
    /// trust gate and the operation. Possible causes: card
    /// removed from reader mid-flow, reader unplugged, a
    /// different card inserted, the same physical port re-
    /// enumerated as a different reader. Trust does not survive
    /// any of these; the operator must re-run.
    CardSessionRevoked {
        /// Human-readable detail from
        /// `re_verify_session` explaining which invariant
        /// diverged (serial mismatch, EF.TokenInfo unreadable,
        /// ...). Tier 0 `String`; presentational.
        reason: String,
    },
    /// The card's contact-interface ATR doesn't match any
    /// FINEID card model refineid currently supports. See
    /// `doc/fineid-card-models.md` for the in-scope set and
    /// the validity-window reasoning behind it. Out-of-scope
    /// cards (older expired models, social welfare /
    /// organizational, health care) land here, as does any
    /// non-FINEID smartcard inserted in the reader.
    CardModelNotSupported(CardClassificationError),
    /// `card change-pin*` / `card unblock-pin*`: the PIN slot's
    /// pre-flight `pin_status` probe (counter-safe empty-Lc
    /// VERIFY) reported a state inconsistent with an activated
    /// card -- typically the slot has never been set. Refineid
    /// refuses before any modify APDU goes out so a wrong-state
    /// attempt cannot burn a try-counter slot. The operator
    /// should run `refineid card activate` first.
    CardLooksUnactivated {
        /// Which PIN slot the probe targeted.
        slot: PinManageSlot,
        /// Raw probe outcome (`PinStatus::NoInfo` or
        /// `Other(sw)` typically). `None` when the probe APDU
        /// itself failed to return a status word.
        probe: Option<PinStatus>,
    },
    /// A consumer UI refused a PIN change to preserve attempts for expert
    /// recovery. The CLI deliberately does not apply this floor.
    ConsumerRetryFloor {
        /// PIN slot protected by the consumer floor.
        slot: PinManageSlot,
        /// Live, side-effect-free status that triggered the refusal.
        probe: PinStatus,
    },
}

impl fmt::Display for CardPinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReaderPick(e) => write!(f, "{e}"),
            Self::Pcsc(e) => write!(f, "PC/SC: {e}"),
            Self::PinPolicy(r) => write!(f, "PIN / PUK rejected locally: {r}"),
            Self::Pkcs15Select(s) => write!(f, "SELECT PKCS#15 app: {s}"),
            Self::Transport(s) => write!(f, "transport: {s}"),
            Self::ActivationLengthMismatch {
                generation,
                expected,
            } => write!(
                f,
                "activation PIN length wrong for this card: {generation:?} card \
                 expects {expected} digits. Sending it anyway would \
                 burn a card-side try; refusing"
            ),
            Self::UnknownCardGeneration => write!(
                f,
                "couldn't classify this card's generation (auth-cert issuer CN \
                 didn't match any known DVV family); refusing to guess at \
                 activation PIN length. See doc/dvv-terminology.md"
            ),
            Self::CardDataUntrusted { description } => write!(
                f,
                "card-side data not trusted -- {description}. The activation \
                 flow refuses to use unverified card data; verify you're using \
                 a real DVV-issued FINEID card, or update PINNED_ROOT_SHA256 \
                 to include this card's root if it's a genuine new generation"
            ),
            Self::CardSessionRevoked { reason } => write!(
                f,
                "trusted card session revoked between trust gate and operation: \
                 {reason}. Trust does not survive card removal, reader unplug, \
                 reader rename, or card swap. Re-run the command after restoring \
                 the original reader + card."
            ),
            Self::CardModelNotSupported(e) => write!(f, "{e}"),
            Self::CardLooksUnactivated { slot, probe } => {
                let probe_desc = probe
                    .as_ref()
                    .map_or_else(|| "no probe result".to_owned(), |s| format!("{s:?}"));
                write!(
                    f,
                    "{} looks unactivated (pin_status probe: {probe_desc}); refusing to send \
                     a modify APDU that could land on an unset slot. Run `refineid card activate` \
                     first to set PIN1 and PIN2.",
                    slot.label()
                )
            }
            Self::ConsumerRetryFloor { slot, probe } => write!(
                f,
                "{} retry safety floor reached ({probe:?}); the graphical Card Manager will not \
                 send a PIN-bearing command. Use the expert CLI only after verifying the card and \
                 retry risk.",
                slot.label()
            ),
        }
    }
}

impl core::error::Error for CardPinError {}

impl From<PcscError> for CardPinError {
    fn from(e: PcscError) -> Self {
        Self::Pcsc(e)
    }
}

impl From<ReaderPickError> for CardPinError {
    fn from(e: ReaderPickError) -> Self {
        Self::ReaderPick(e)
    }
}

/// Map a lib-core `AuthError<TE>` into the client-side
/// [`CardPinError`] surface.
///
/// Transport errors stringify through the inner `Display` so
/// the CLI can show the underlying PC/SC message without
/// leaking the typed error to the public surface. PIN-policy
/// reasons (digit-only, length bounds) pass through as
/// `PinPolicy` because they are local-policy hits -- no
/// counter-burning APDU went out.
fn auth_to_card_pin(e: AuthError<impl fmt::Display>) -> CardPinError {
    match e {
        AuthError::Transport(t) => CardPinError::Transport(format!("{t}")),
        AuthError::PinPolicy(r) => CardPinError::PinPolicy(r),
    }
}

/// Trust-gated card session.
///
/// The trust gate has passed and a long-serial has been
/// bound. Activation-state is *not* yet known; downstream
/// operations must promote this into either
/// [`ActivationCardContext`] (for `card activate`) or
/// [`PinManagementCardContext`] (for `card change-pin*` /
/// `card unblock-pin*`).
///
/// Built by `establish_trusted_session`: card is identified
/// by ATR against the in-scope FINEID model set, its on-card
/// root is pinned against `PINNED_ROOT_SHA256`, and its
/// PKCS#15 long serial is captured so any later step can
/// detect a card swap mid-flow.
#[derive(Debug, Clone)]
pub struct TrustedCardSession {
    /// PC/SC reader id captured at trust-gate time; every
    /// subsequent re-open in the flow uses exactly this id.
    pub reader_id: refineid_lib_core::backend::ReaderId,
    /// Person identity extracted from the auth cert's subject DN
    /// (FINEID S2 §6.3.8.3). Read once at trust-gate time so PIN
    /// reports can show "who" without re-reading the cert.
    pub identity: refineid_lib_core::identity::CredentialIdentity,
    /// Attestation that justified using this card's data.
    /// `is_trusted()` returns `true` only for
    /// `PinnedRootMatched`.
    pub trust: CardTrustAttestation,
    /// PKCS#15 long serial bound at trust-gate time; every
    /// subsequent step re-reads and compares against this value
    /// to detect a card swap.
    pub bound_serial: refineid_lib_core::identity::TokenSerial,
    /// ATR-classified FINEID card model from the in-scope set
    /// (see `doc/fineid-card-models.md`). Not a trust signal on
    /// its own; the trust signal is [`trust`](Self::trust).
    pub model: FineidCardModel,
}

impl TrustedCardSession {
    /// Promote a trusted session into the
    /// [`PinManagementCardContext`] typestate, the input
    /// shape for `change_pin_first` and
    /// `unblock_pin_first`. By calling this constructor the
    /// caller asserts operator intent: the operator chose a
    /// PIN-management command (not `card activate`), so they
    /// are claiming the card is in an already-activated
    /// state and the modify APDU is appropriate. The compiler
    /// then enforces that no `card activate` code path can
    /// consume this value.
    ///
    /// This split is the type-level half of the safety; the
    /// runtime half (`pin_status` preflight + card-side
    /// counter on wrong PIN attempts) is in the modify
    /// functions themselves. Neither half alone catches every
    /// "operator inserted the wrong card" case; together they
    /// raise the floor.
    #[must_use]
    pub const fn into_pin_management_context(self) -> PinManagementCardContext {
        PinManagementCardContext { session: self }
    }
}

/// Card session promoted from a trusted base into the
/// "operator intends a PIN-management operation on an
/// already-activated card" typestate.
///
/// The type is opaque: there is no public field set, only a
/// borrow path back to the inner [`TrustedCardSession`].
/// Construct via
/// [`TrustedCardSession::into_pin_management_context`] from
/// the CLI's `card change-pin*` / `card unblock-pin*`
/// dispatch. Code in the `card activate` dispatch cannot
/// produce this typestate by construction.
#[derive(Debug, Clone)]
pub struct PinManagementCardContext {
    /// Inner trusted session this context was promoted from.
    /// Held privately so callers can only reach
    /// reader id / identity / serial via the inherent methods,
    /// preventing accidental construction of an unrelated
    /// `PinManagementCardContext` from a stale session value.
    session: TrustedCardSession,
}

impl PinManagementCardContext {
    /// Borrow the reader id this context is bound to.
    #[must_use]
    pub const fn reader_id(&self) -> &refineid_lib_core::backend::ReaderId {
        &self.session.reader_id
    }
    /// Borrow the person identity captured at trust-gate time.
    #[must_use]
    pub const fn identity(&self) -> &refineid_lib_core::identity::CredentialIdentity {
        &self.session.identity
    }
    /// Borrow the trust attestation that justified building this
    /// context (always `PinnedRootMatched` once the type is
    /// constructed; other variants short-circuit in
    /// `establish_trusted_session`).
    #[must_use]
    pub const fn trust(&self) -> &CardTrustAttestation {
        &self.session.trust
    }
    /// Borrow the PKCS#15 long serial bound at trust-gate time.
    /// `re_verify_session` compares the on-card serial against
    /// this value before every modify APDU.
    #[must_use]
    pub const fn bound_serial(&self) -> &refineid_lib_core::identity::TokenSerial {
        &self.session.bound_serial
    }
    /// ATR-classified FINEID card model captured at trust-gate
    /// time. `Copy` because [`FineidCardModel`] is a small enum.
    #[must_use]
    pub const fn model(&self) -> FineidCardModel {
        self.session.model
    }
}

/// Run the trust-gate setup against the picked reader.
///
/// Phases (in order):
/// 1. Pick the FINEID-shape reader (or apply `reader_filter`).
/// 2. Open the transport, read the ATR, classify against the
///    in-scope `FineidCardModel` set
///    ([`doc/fineid-card-models.md`][card]).
/// 3. SELECT the PKCS#15 application.
/// 4. Read the on-card root cert (`EF.4334`), hash, match
///    against the pinned set ([`doc/fineid-s2-cert-profile.md`][s2]).
/// 5. Capture the PKCS#15 long serial for session binding.
///
/// Returns a [`TrustedCardSession`] the caller flows into the
/// modify step. The transport from this call is dropped; the
/// caller re-opens against `session.reader_id` and uses
/// `re_verify_session` before each modify APDU.
///
/// # Errors
/// - `CardModelNotSupported` -- ATR didn't classify.
/// - `CardDataUntrusted` -- on-card root not pinned, or
///   PKCS#15 serial unavailable.
/// - PC/SC / SELECT / cert-read failures.
///
/// [card]: ../../../doc/fineid-card-models.md
/// [s2]: ../../../doc/fineid-s2-cert-profile.md
pub fn establish_trusted_session(
    backend: PcscBackend,
    reader_filter: Option<&ReaderFilter>,
) -> Result<TrustedCardSession, CardPinError> {
    use refineid_lib_core::transport::CardTransport as _;

    let FineidReaderPick {
        reader_id,
        identity,
    } = backend.pick_fineid_reader(reader_filter)?;
    let mut transport = backend.open_session(&reader_id, ReaderAccessCap::Read)?;

    // ATR classify -- public protocol-level signal; rejects
    // out-of-scope cards before any card-side data read.
    let atr = transport
        .atr()
        .map_err(|e| CardPinError::Transport(format!("ATR length: {e}")))?;
    let model = atr
        .classify()
        .map_err(CardPinError::CardModelNotSupported)?;

    transport
        .select_pkcs15_application()
        .map_err(|e| CardPinError::Pkcs15Select(format!("{e}")))?;

    // Pinned-root trust gate: hash the on-card root, look up
    // its label in PINNED_ROOT_SHA256 (G3 RSA + G3 ECC both
    // pinned per doc/fineid-s2-cert-profile.md).
    let trust = match transport.read_certificate(CertSlot::RootCa) {
        Ok(root_der) => {
            let actual = Sha256::of(root_der.as_bytes());
            crate::trust_roots::pinned_root_label(actual).map_or(
                CardTrustAttestation::PinnedRootMismatch {
                    actual_sha256: actual,
                },
                |label| CardTrustAttestation::PinnedRootMatched {
                    root_label: label,
                    root_sha256: actual,
                },
            )
        }
        Err(e) => CardTrustAttestation::RootCertUnavailable {
            reason: format!("{e}"),
        },
    };
    if !trust.is_trusted() {
        return Err(CardPinError::CardDataUntrusted {
            description: trust.describe(),
        });
    }

    // Bind the PKCS#15 long serial; `re_verify_session` checks
    // against this on every subsequent step. The serial is
    // session state (binds this transport to a specific
    // physical card for swap detection), not person identity,
    // so it doesn't live on `CredentialIdentity` -- read it
    // here directly from EF.TokenInfo.
    let token = transport
        .read_token_info()
        .map_err(|e| CardPinError::Transport(format!("EF.TokenInfo read: {e}")))?;
    let bound_serial = match token.serial_number_hex {
        Some(hex) => refineid_lib_core::identity::render_token_serial(hex),
        None => {
            return Err(CardPinError::CardDataUntrusted {
                description: "card did not publish a PKCS#15 serial; can't pin session identity"
                    .to_owned(),
            });
        }
    };

    Ok(TrustedCardSession {
        reader_id,
        identity,
        trust,
        bound_serial,
        model,
    })
}

/// `true` when a `pin_status` probe reports a state consistent
/// with an activated card (PIN slot exists and has a counter).
/// Mirror of `ActivatePreflightOutcome::looks_activated`, used
/// by the PIN-management flows to refuse on the inverse.
#[must_use]
const fn pin_looks_activated(probe: Option<&PinStatus>) -> bool {
    matches!(
        probe,
        Some(PinStatus::Remaining(_) | PinStatus::Verified | PinStatus::Locked)
    )
}

const fn card_manager_pin_change_available(probe: Option<&PinStatus>) -> bool {
    match probe {
        Some(PinStatus::Remaining(retries)) => match PinRetryRisk::from_retries(*retries) {
            Some(risk) => risk.permits_consumer(),
            None => false,
        },
        Some(PinStatus::Verified) => true,
        Some(PinStatus::Locked | PinStatus::NoInfo | PinStatus::Other(_)) | None => false,
    }
}

/// Rotate the PIN in `options.slot`. The card's own outcome
/// (wrong-current-PIN with retries-left, locked, etc.) is
/// surfaced via [`ChangePinReport::outcome`], not as an error.
///
/// `options` is taken by value so both embedded [`PinBytes`]
/// drop (and zeroize) when this returns.
///
/// # Errors
/// PC/SC / PKCS#15 / local-policy / transport failures.
/// PC/SC / PKCS#15 / local-policy / transport failures.
pub fn change_pin_first(
    backend: PcscBackend,
    ctx: PinManagementCardContext,
    options: ChangePinOptions,
) -> Result<ChangePinReport, CardPinError> {
    change_pin_first_for_cli(backend, ctx, options)
}

/// Read the live, side-effect-free retry status for the CLI confirmation gate.
pub(crate) fn probe_pin_status_for_cli(
    backend: PcscBackend,
    ctx: &PinManagementCardContext,
    slot: PinManageSlot,
) -> Result<PinStatus, CardPinError> {
    let mut transport = backend.open_session(ctx.reader_id(), ReaderAccessCap::Read)?;
    transport
        .select_pkcs15_application()
        .map_err(|error| CardPinError::Pkcs15Select(format!("{error}")))?;
    re_verify_session(&mut transport, ctx.bound_serial())?;
    transport
        .pin_status(slot.as_pin_slot())
        .map_err(auth_to_card_pin)
}

/// CLI-only PIN change. Refuses on the shared retry floor before any modify
/// APDU, so a PIN one or two attempts from lockout is never touched.
pub(crate) fn change_pin_first_for_cli(
    backend: PcscBackend,
    ctx: PinManagementCardContext,
    options: ChangePinOptions,
) -> Result<ChangePinReport, CardPinError> {
    // The typestate parameter `ctx` proves the caller is on a
    // PIN-management command path (operator intent: card is
    // activated). The compiler refuses to let
    // `ActivationCardContext` flow into this signature; the
    // `card activate` dispatch cannot reach this function.
    let person = ctx.identity().person_string();
    let card_serial = ctx.identity().best_serial().unwrap_or("").to_owned();
    crate::events::CardTarget {
        device: ctx.reader_id().as_str(),
        card: &card_serial,
        person: &person,
    }
    .emit();

    // Re-open against the bound reader, SELECT, and re-verify
    // the bound serial -- catches a card swap between the
    // trust gate and the modify APDU. PinSequence: both PINs
    // arrived in `options` (prompts ran between sessions), so
    // the whole SELECT -> re-verify -> probe -> CHANGE span is
    // card-bound and runs inside one held PC/SC transaction.
    let mut transport = backend.open_session(ctx.reader_id(), ReaderAccessCap::PinSequence)?;
    transport
        .select_pkcs15_application()
        .map_err(|e| CardPinError::Pkcs15Select(format!("{e}")))?;
    re_verify_session(&mut transport, ctx.bound_serial())?;

    // Counter-safe pin_status probe -- partial defense; see
    // the function-level comment for the limitation on Thales
    // MultiApp v5.0.
    let slot = options.slot.as_pin_slot();
    let probe = transport.pin_status(slot).ok();
    if !pin_looks_activated(probe.as_ref()) {
        return Err(CardPinError::CardLooksUnactivated {
            slot: options.slot,
            probe,
        });
    }
    if !card_manager_pin_change_available(probe.as_ref())
        && let Some(probe) = probe
    {
        return Err(CardPinError::ConsumerRetryFloor {
            slot: options.slot,
            probe,
        });
    }

    re_verify_session(&mut transport, ctx.bound_serial())?;

    let outcome = transport
        .change_pin(slot, options.current.clone(), options.new.clone())
        .map_err(auth_to_card_pin)?;
    let report = ChangePinReport {
        reader: ctx.reader_id().as_str().to_owned(),
        card_serial,
        person,
        slot: options.slot,
        outcome,
    };
    drop(options);
    drop(ctx);
    Ok(report)
}

/// PUK-driven unblock + replace PIN in `options.slot`.
///
/// **Danger:** a wrong PUK decrements the PUK try counter. Once
/// exhausted the card is dead -- no software recovery, DVV
/// reissue required. The card's own outcome (wrong-PUK with
/// retries-left, PUK locked, etc.) is surfaced via
/// [`UnblockPinReport::outcome`].
///
/// # Errors
/// PC/SC / PKCS#15 / local-policy / transport failures.
#[expect(
    clippy::needless_pass_by_value,
    reason = "UnblockPinOptions embeds PUK + new-PIN PinBytes; consumed by value so both drop+zeroize at function return."
)]
pub fn unblock_pin_first(
    backend: PcscBackend,
    ctx: PinManagementCardContext,
    options: UnblockPinOptions,
) -> Result<UnblockPinReport, CardPinError> {
    let person = ctx.identity().person_string();
    let card_serial = ctx.identity().best_serial().unwrap_or("").to_owned();
    crate::events::CardTarget {
        device: ctx.reader_id().as_str(),
        card: &card_serial,
        person: &person,
    }
    .emit();

    // PinSequence: PUK and the new PIN arrived in `options`
    // (the CLI prompts before this call), so the unblock span
    // is card-bound inside one held PC/SC transaction.
    let mut transport = backend.open_session(ctx.reader_id(), ReaderAccessCap::PinSequence)?;
    transport
        .select_pkcs15_application()
        .map_err(|e| CardPinError::Pkcs15Select(format!("{e}")))?;
    re_verify_session(&mut transport, ctx.bound_serial())?;

    let slot = options.slot.as_pin_slot();
    let probe = transport.pin_status(slot).ok();
    if !pin_looks_activated(probe.as_ref()) {
        return Err(CardPinError::CardLooksUnactivated {
            slot: options.slot,
            probe,
        });
    }

    re_verify_session(&mut transport, ctx.bound_serial())?;

    // Bridge typed Puk to the auth primitive's PinBytes. The
    // transient PinBytes zeroizes on drop, same as every other
    // secret material.
    let puk_bytes = options.puk.to_pin_bytes();
    let outcome = transport
        .reset_retry_counter(slot, puk_bytes, options.new_pin.clone())
        .map_err(auth_to_card_pin)?;
    Ok(UnblockPinReport {
        reader: ctx.reader_id().as_str().to_owned(),
        card_serial,
        person,
        slot: options.slot,
        outcome,
    })
}

impl fmt::Display for ChangePinReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "reader: {}", self.reader)?;
        if !self.card_serial.is_empty() {
            writeln!(f, "card:   {}", self.card_serial)?;
        }
        if !self.person.is_empty() {
            writeln!(f, "person: {}", self.person)?;
        }
        let label = self.slot.label();
        match &self.outcome {
            ChangePinOutcome::Ok => writeln!(
                f,
                "{label} changed; retry counter reset; re-VERIFY required for further ops"
            )?,
            ChangePinOutcome::WrongCurrentPin { retries_left } => {
                writeln!(f, "current {label} was wrong ({retries_left} retries left)")?;
            }
            ChangePinOutcome::Locked => writeln!(
                f,
                "{label} is blocked -- use the PUK to unblock before retrying"
            )?,
            ChangePinOutcome::LengthError => {
                writeln!(f, "card rejected APDU length (SW=6700) -- host bug")?;
            }
            ChangePinOutcome::Other(sw) => writeln!(f, "card returned unexpected SW={sw:#06X}")?,
        }
        Ok(())
    }
}

impl fmt::Display for UnblockPinReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "reader: {}", self.reader)?;
        if !self.card_serial.is_empty() {
            writeln!(f, "card:   {}", self.card_serial)?;
        }
        if !self.person.is_empty() {
            writeln!(f, "person: {}", self.person)?;
        }
        let label = self.slot.label();
        match &self.outcome {
            UnblockOutcome::Ok => writeln!(
                f,
                "{label} unblocked; retry counter reset to max; re-VERIFY required for further ops"
            )?,
            UnblockOutcome::WrongPuk { retries_left } => writeln!(
                f,
                "PUK was wrong ({retries_left} retries left on the PUK itself; \
                 exhausting it permanently bricks the card)"
            )?,
            UnblockOutcome::PukLocked => writeln!(
                f,
                "PUK is itself blocked -- card needs DVV reissue, no software recovery"
            )?,
            UnblockOutcome::Invalidated => writeln!(
                f,
                "PIN unblock counter or PUK usage counter exhausted -- card needs DVV reissue"
            )?,
            UnblockOutcome::LengthError => {
                writeln!(f, "card rejected APDU length (SW=6700) -- host bug")?;
            }
            UnblockOutcome::Other(sw) => writeln!(f, "card returned unexpected SW={sw:#06X}")?,
        }
        Ok(())
    }
}

// ---- card activate -- first-time setup flow --------------------

/// Outcome of verifying that card-side data can be trusted
/// before it drives type selection.
///
/// Per the typing-discipline rule "you cannot pass on
/// information that is not verified": the activation flow must
/// not use `cert.not_before` to choose an
/// [`refineid_lib_core::pin::ActivationCode`] variant until the
/// card itself has been authenticated against a pinned anchor.
///
/// Today this gate is the on-card root cert's SHA-256 matching
/// [`crate::trust_roots::PINNED_ROOT_SHA256`]. Full chain walk
/// (auth -> AIA-fetched intermediate -> on-card root) is a
/// follow-up; the pin-match alone defeats the "counterfeit
/// card with forged on-card data" attack because an attacker
/// can't put DVV's real root cert on a counterfeit card without
/// also forging a chain that signs it, which is the
/// cryptographic gate the pin enforces.
#[derive(Debug, Clone)]
pub enum CardTrustAttestation {
    /// On-card root cert's SHA-256 matched a pinned anchor.
    /// Card data may be used for type selection.
    PinnedRootMatched {
        /// Human-readable label of the pinned root that matched
        /// (e.g. "DVV CA Generation 3 RSA"). Sourced from
        /// `crate::trust_roots::PINNED_ROOT_SHA256`; the value
        /// is a compile-time string set so `&'static str` is
        /// acceptable.
        root_label: &'static str,
        /// SHA-256 of the on-card root DER -- the digest that
        /// matched the pin. Surfaced so logs can audit which
        /// fingerprint passed.
        root_sha256: Sha256,
    },
    /// On-card root cert was read but its SHA-256 doesn't match
    /// any pinned anchor. Card data MUST NOT be used.
    PinnedRootMismatch {
        /// Actual SHA-256 of the on-card root DER. Reported so
        /// the operator can confirm whether they're looking at a
        /// genuinely new generation (update the pin list) or a
        /// counterfeit / corrupted card.
        actual_sha256: Sha256,
    },
    /// On-card root cert couldn't be read at all (file absent,
    /// transport error). Card data MUST NOT be used.
    RootCertUnavailable {
        /// Underlying transport / parse error rendered via
        /// `to_string()`. Tier 0 `String`; presentational.
        reason: String,
    },
}

impl CardTrustAttestation {
    /// `true` only when card data may be passed forward to
    /// type-selection logic.
    #[must_use]
    pub const fn is_trusted(&self) -> bool {
        matches!(self, Self::PinnedRootMatched { .. })
    }

    /// Render the trust attestation as a one-line human
    /// string for the PIN-flow reports.
    ///
    /// Three shapes: positive (pinned to a labelled root with
    /// SHA-256), negative-pinning (root present but
    /// fingerprint unpinned), unavailable (could not read the
    /// root). The positive case is the only one with
    /// [`Self::is_trusted`] returning `true`.
    fn describe(&self) -> String {
        match self {
            Self::PinnedRootMatched {
                root_label,
                root_sha256,
            } => format!("on-card root pinned to {root_label} (sha256 {root_sha256})"),
            Self::PinnedRootMismatch { actual_sha256 } => format!(
                "ON-CARD ROOT NOT PINNED (actual sha256 {actual_sha256}); refusing to trust card data"
            ),
            Self::RootCertUnavailable { reason } => {
                format!("on-card root cert unreadable ({reason}); refusing to trust card data")
            }
        }
    }
}

/// Pre-activation card context.
///
/// Built only after [`CardTrustAttestation`] verifies the card
/// can be trusted. The CLI uses the included issuance date and
/// generation to name the expected activation-PIN length in
/// its prompt and construct the right typed
/// [`refineid_lib_core::pin::ActivationCode`] variant.
///
/// The context also pins the **session identity** -- reader
/// name + card's long serial -- captured at trust-gate time.
/// Any subsequent step in the activation flow re-reads the
/// card's serial and refuses to continue if it doesn't match
/// (or if the transport fails outright, which covers card
/// removal / reader unplug / reader rename). Trust does not
/// survive a physical-state change.
#[derive(Debug, Clone)]
pub struct ActivationCardContext {
    /// PC/SC reader id captured at trust-gate time; subsequent
    /// re-opens in the activate flow use exactly this id.
    pub reader_id: refineid_lib_core::backend::ReaderId,
    /// Person identity extracted from the auth cert's subject DN
    /// at trust-gate time. Surfaced in activate report output.
    pub identity: refineid_lib_core::identity::CredentialIdentity,
    /// Auth-cert `notBefore`. Source of truth for the
    /// `CardGeneration` classification (DVV cutoff 2026-01-13).
    /// Only populated when `trust.is_trusted()` -- otherwise
    /// `classify_card_for_activation` returns
    /// `CardPinError::CardDataUntrusted` rather than this
    /// struct.
    pub issuance_date: DateTime,
    /// Generation derived from [`issuance_date`](Self::issuance_date).
    pub generation: CardGeneration,
    /// CN-based fallback classification. Should agree with
    /// `generation` for every well-formed FINEID card; a
    /// disagreement is a signal to inspect the cert (logged but
    /// not blocking).
    pub generation_by_issuer_cn: CardGeneration,
    /// Attestation that justified using the card data.
    pub trust: CardTrustAttestation,
    /// PKCS#15 EF.TokenInfo serial (long form) captured at
    /// trust-gate time. Any subsequent operation re-reads this
    /// and must match -- a different value means a card swap
    /// happened mid-flow, which revokes the trust.
    pub bound_serial: refineid_lib_core::identity::TokenSerial,
    /// The FINEID card model identified by ATR matching at
    /// session open, from refineid's in-scope set (see
    /// [`doc/fineid-card-models.md`][doc]).
    ///
    /// ATR is a protocol-level public value -- the card emits
    /// it at electrical reset, before any application is
    /// selected. We classify on it before the pinned-root
    /// trust gate so a non-FINEID card (or an out-of-scope
    /// expired model) gets rejected at the earliest possible
    /// point. ATR matching is **not** a trust signal on its
    /// own; the pinned-root SHA-256 in [`trust`](Self::trust)
    /// is.
    ///
    /// [doc]: ../../../doc/fineid-card-models.md
    pub model: FineidCardModel,
}

impl ActivationCardContext {
    /// Expected activation-PIN length for the classified
    /// generation. `None` only when the classification didn't
    /// resolve (which shouldn't happen for a real FINEID card
    /// that passed the trust gate).
    #[must_use]
    pub const fn expected_activation_pin_length(&self) -> Option<usize> {
        self.generation.activation_pin_length()
    }
}

/// Read the auth cert + on-card root from the picked FINEID
/// reader, verify the root against a pinned anchor, and (only
/// if that succeeds) classify the card's generation by the
/// auth cert's `notBefore`.
///
/// Per typing-discipline: we cannot pass on information that
/// hasn't been verified. The on-card root pin is the minimum
/// trust gate; until it matches, the issuance date isn't
/// trustworthy enough to drive type selection.
///
/// # Errors
/// - `CardDataUntrusted` when the on-card root doesn't match a
///   pinned anchor (or can't be read).
/// - PC/SC / PKCS#15 / cert-read / reader-pick failures.
pub fn classify_card_for_activation(
    backend: PcscBackend,
    reader_filter: Option<&ReaderFilter>,
) -> Result<ActivationCardContext, CardPinError> {
    // Phase 1: shared trust gate (ATR + root pin + serial bind).
    let session = establish_trusted_session(backend, reader_filter)?;

    // Phase 2: re-open against the bound reader to read the
    // auth cert. The re-open + re-verify pattern matches every
    // other PIN-management entrypoint; the auth cert read is
    // activation-specific because notBefore drives the
    // activation-PIN-length classification.
    let mut transport = backend.open_session(&session.reader_id, ReaderAccessCap::Read)?;
    transport
        .select_pkcs15_application()
        .map_err(|e| CardPinError::Pkcs15Select(format!("{e}")))?;
    re_verify_session(&mut transport, &session.bound_serial)?;

    let der = transport
        .read_certificate(CertSlot::Authentication)
        .map_err(|e| CardPinError::Transport(format!("auth cert read: {e}")))?;
    let cert_owned = OwnedCert::from_der(der.as_bytes())
        .map_err(|e| CardPinError::Transport(format!("auth cert parse: {e}")))?;
    let cert = cert_owned.view();
    let issuance_date = cert.not_before;
    let generation = classify_card_generation_by_issuance(issuance_date);
    let generation_by_issuer_cn = classify_card_generation(cert.issuer);
    Ok(ActivationCardContext {
        reader_id: session.reader_id,
        identity: session.identity,
        issuance_date,
        generation,
        generation_by_issuer_cn,
        trust: session.trust,
        bound_serial: session.bound_serial,
        model: session.model,
    })
}

/// Re-verify the trusted card session: the reader's still the
/// one we picked, the card's still there, and its long serial
/// still matches what we pinned at trust-gate time.
///
/// Called before every card-touching step in the activation
/// flow so a card swap / reader unplug / card removal between
/// the trust gate and the modify APDU is detected and refused.
///
/// # Errors
/// `CardSessionRevoked` on any divergence. Trust state cannot
/// be re-established by retrying -- the operator must re-run
/// the whole command.
fn re_verify_session<T: refineid_lib_core::transport::CardTransport>(
    transport: &mut T,
    bound_serial: &refineid_lib_core::identity::TokenSerial,
) -> Result<(), CardPinError> {
    use refineid_lib_core::identity::render_token_serial;
    use refineid_lib_core::pkcs15::Pkcs15Ops as _;
    let token = transport
        .read_token_info()
        .map_err(|e| CardPinError::CardSessionRevoked {
            reason: format!("re-read EF.TokenInfo failed: {e}"),
        })?;
    let now_serial =
        token
            .serial_number_hex
            .as_ref()
            .ok_or_else(|| CardPinError::CardSessionRevoked {
                reason: "card no longer publishes EF.TokenInfo serial".to_owned(),
            })?;
    let current_full = render_token_serial(now_serial.clone());
    if &current_full != bound_serial {
        return Err(CardPinError::CardSessionRevoked {
            reason: format!(
                "card serial changed mid-flow: bound to {bound_serial:?}, \
                 reader now reports {current_full:?}"
            ),
        });
    }
    Ok(())
}

/// Inputs for `card activate` -- the one-time DVV activation flow
/// that consumes the *activation PIN* (aktivointitunnusluku) from
/// the activation letter and sets the initial values of PIN1 and
/// PIN2.
#[derive(Debug)]
pub struct ActivateOptions {
    /// Typed activation code parsed from the DVV activation
    /// letter -- [`ActivationCode::Seven`] for cards issued on
    /// or after 2026-01-13, [`ActivationCode::Eight`] for older
    /// cards. The variant must match the card-side
    /// [`CardGeneration`] detected during activation; mismatch
    /// is reported as
    /// [`CardPinError::ActivationLengthMismatch`].
    pub activation_pin: ActivationCode,
    /// New basic PIN (PIN1, 4-12 digits).
    pub new_pin1: PinBytes,
    /// New signature PIN (PIN2, 6-12 digits).
    pub new_pin2: PinBytes,
    /// Override the pre-flight refusal when PIN-probes suggest
    /// the card is already activated. Defaults to refuse-on-
    /// already-set; flip to `true` only when the operator
    /// genuinely intends to overwrite an active card's PINs
    /// (rare; requires the activation PIN to still be unused).
    pub allow_reactivate: bool,
}

/// One reader's worth of activate output.
#[derive(Debug, Clone)]
pub struct ActivateReport {
    /// PC/SC reader name the activation APDUs landed against.
    /// Tier 0 `String` from `ReaderId::as_str().to_owned()`.
    pub reader: String,
    /// PIN-status pre-flight result. Surfaced so the operator
    /// can see whether refineid found the card unactivated /
    /// activated when it ran.
    pub preflight: ActivatePreflightOutcome,
    /// Card's outcome for the PIN1 `RESET RETRY COUNTER` call.
    /// `None` when the pre-flight refusal aborted the flow before
    /// any APDU went out.
    pub pin1_outcome: Option<UnblockOutcome>,
    /// Same for PIN2. `None` when either the pre-flight refused
    /// or PIN1 setup failed (we don't burn a second activation
    /// attempt against a card that's already rejected the code).
    pub pin2_outcome: Option<UnblockOutcome>,
}

/// What the PIN-status preflight saw before any modification was
/// attempted. Informational on success; the source of
/// `ActivateOutcome::Refused` when the operator didn't pass
/// `--allow-reactivate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivatePreflightOutcome {
    /// PIN1 probe returned a state consistent with an
    /// un-activated card. Activation proceeded.
    LooksUnactivated {
        /// Raw PIN1 probe outcome (typically `NoInfo` or
        /// `Other(sw)` for fresh cards). `None` when the probe
        /// itself didn't return a status word.
        pin1: Option<PinStatus>,
        /// Raw PIN2 probe outcome. Same conventions as `pin1`.
        pin2: Option<PinStatus>,
    },
    /// PIN1 probe returned a healthy counter, locked state, or
    /// otherwise looked like an activated card. Activation was
    /// refused (operator can override with `--allow-reactivate`).
    LooksActivated {
        /// PIN1 probe outcome that triggered the refusal -- a
        /// healthy `Remaining(_)`, `Verified`, or `Locked`. Not
        /// `Option`-wrapped because at least one such value is
        /// what built the variant.
        pin1: PinStatus,
        /// PIN2 probe outcome; auxiliary information. `None` if
        /// PIN2 probe failed; not used in the
        /// `LooksActivated` classification logic.
        pin2: Option<PinStatus>,
    },
}

impl ActivatePreflightOutcome {
    /// `true` when PIN1 probe returned a healthy counter or
    /// locked state, signalling the card has likely been
    /// activated already. The CLI uses this to abort activation
    /// unless `--allow-reactivate` was passed.
    #[must_use]
    pub const fn looks_activated(&self) -> bool {
        matches!(self, Self::LooksActivated { .. })
    }
}

/// Classify the PIN1/PIN2 probes into a preflight verdict.
///
/// Scheme-aware (FINEID S4-1 v4.2 §4.6):
///
/// - **Older cards (old scheme, §4.6.1):** PIN1 ships BLOCKED.
///   Any "healthy" PIN1 status (`Remaining(_)`, `Verified`, or
///   `Locked`) means the slot has been written to since
///   manufacture -- evidence of prior activation. `NoInfo` /
///   `Other(sw)` / no-probe-result is inconclusive and the flow
///   proceeds.
/// - **Newer cards (new scheme, §4.6.2):** PIN1 ships SET to
///   the 7-digit activation PIN, so `PinStatus::Remaining(5)` is
///   the *expected* fresh state. The authoritative signal is
///   the GET DATA "PIN changed" flag (`DF 2F`, S1 v4.2 §3.15.2
///   Table 19): `Some(true)` means the slot has been rewritten,
///   so the card is already activated; `Some(false)` or `None`
///   leaves the flow free to proceed. PIN1's flag dominates;
///   PIN2's flag is auxiliary.
const fn classify_preflight(
    pin1: Option<PinStatus>,
    pin2: Option<PinStatus>,
    generation: CardGeneration,
    pin1_changed: Option<bool>,
    _pin2_changed: Option<bool>,
) -> ActivatePreflightOutcome {
    if matches!(generation, CardGeneration::Newer) {
        if matches!(pin1_changed, Some(true)) {
            // The factory activation PIN has been replaced;
            // re-running activate against this card would burn a
            // wrong-current-PIN counter. Synthesise a Remaining
            // status for the LooksActivated payload.
            return match pin1 {
                Some(s) => ActivatePreflightOutcome::LooksActivated { pin1: s, pin2 },
                None => ActivatePreflightOutcome::LooksUnactivated { pin1, pin2 },
            };
        }
        return ActivatePreflightOutcome::LooksUnactivated { pin1, pin2 };
    }
    match pin1 {
        Some(s @ (PinStatus::Remaining(_) | PinStatus::Verified | PinStatus::Locked)) => {
            ActivatePreflightOutcome::LooksActivated { pin1: s, pin2 }
        }
        _ => ActivatePreflightOutcome::LooksUnactivated { pin1, pin2 },
    }
}

/// Map a `CHANGE REFERENCE DATA` outcome onto the
/// `UnblockOutcome` shape so [`ActivateReport`] can carry either
/// scheme's per-slot result behind a single field. The user-
/// facing semantics line up: a wrong "current PIN" on the new
/// scheme decrements the same five-try budget that a wrong PUK
/// burns on the old scheme, and the recovery path on either
/// terminal failure is the same DVV PUK-order procedure (S4-1
/// v4.2 §4.6.2 "When PIN(s) is/are blocked").
const fn change_to_unblock(o: ChangePinOutcome) -> UnblockOutcome {
    match o {
        ChangePinOutcome::Ok => UnblockOutcome::Ok,
        ChangePinOutcome::WrongCurrentPin { retries_left } => {
            UnblockOutcome::WrongPuk { retries_left }
        }
        ChangePinOutcome::Locked => UnblockOutcome::PukLocked,
        ChangePinOutcome::LengthError => UnblockOutcome::LengthError,
        ChangePinOutcome::Other(sw) => UnblockOutcome::Other(sw),
    }
}

/// Activate the picked FINEID card.
///
/// Two activation schemes per FINEID S4-1 v4.2 §4.6:
///
/// - **Old scheme (§4.6.1, [`CardGeneration::Older`]):** PIN1
///   and PIN2 ship BLOCKED. The 8-digit activation PIN is the
///   PUK that unblocks them. Activation sends `RESET RETRY
///   COUNTER` (`INS=0x2C`) twice -- once per slot -- with
///   `(activation_pin, new_pin)`.
/// - **New scheme (§4.6.2, [`CardGeneration::Newer`]):** PIN1
///   and PIN2 ship SET to the same random 7-digit activation
///   PIN; no PUK is delivered. Activation sends `CHANGE
///   REFERENCE DATA` (`INS=0x24`) twice with
///   `(current=activation_pin, new=new_pin)`.
///
/// Flow:
///
/// 1. Open the reader, SELECT the PKCS#15 application,
///    re-verify the trusted-session binding.
/// 2. Cross-check the variant-vs-generation invariant:
///    [`ActivationCode::Seven`] requires
///    [`CardGeneration::Newer`] and vice versa. Mismatch
///    surfaces as [`CardPinError::ActivationLengthMismatch`]
///    *before* any modify APDU.
/// 3. Probe PIN1/PIN2 status (counter-safe empty-Lc `VERIFY`).
///    The preflight only refuses on Older cards -- on Newer
///    cards a healthy PIN1 status is the expected fresh state,
///    so we cannot derive activation status from it (would need
///    GET DATA PIN-changed-flag, not implemented yet).
/// 4. Per-scheme PIN1 setup. If the card returns anything other
///    than `Ok`, abort the second slot too -- a single-shot
///    invocation per the panic-brake design.
/// 5. Per-scheme PIN2 setup.
///
/// # Errors
/// PC/SC, PKCS#15-SELECT, reader-pick, or local-policy failures.
/// Card-side outcomes (wrong activation PIN, locked, etc.) are
/// surfaced via [`ActivateReport`], not as `Err`.
///
/// `options` is taken by value so the embedded [`PinBytes`]
/// instances drop (and zeroize) when this returns.
/// Per-slot setup for [`activate_first`]: dispatch the
/// generation-appropriate APDU (`CHANGE REFERENCE DATA` for newer
/// cards, `RESET RETRY COUNTER` for older) and return the typed
/// [`UnblockOutcome`].
///
/// `activation_pin_bytes` and `new_pin` are consumed by value so
/// the PIN material drops + zeroizes at function return.
fn activate_slot_setup<T: refineid_lib_core::transport::CardTransport>(
    transport: &mut crate::apdu_trace::ApduTraceTransport<T>,
    slot: PinSlot,
    generation: CardGeneration,
    activation_pin_bytes: PinBytes,
    new_pin: PinBytes,
) -> Result<UnblockOutcome, CardPinError> {
    match generation {
        CardGeneration::Newer => transport
            .change_pin(slot, activation_pin_bytes, new_pin)
            .map(change_to_unblock)
            .map_err(auth_to_card_pin),
        CardGeneration::Older => transport
            .reset_retry_counter(slot, activation_pin_bytes, new_pin)
            .map_err(auth_to_card_pin),
        CardGeneration::Unknown => Err(CardPinError::UnknownCardGeneration),
    }
}

const fn activation_continues_after_pin1(outcome: UnblockOutcome) -> bool {
    matches!(outcome, UnblockOutcome::Ok)
}

/// Drive the `card activate` flow: trust-gated card -> factory
/// activation PIN -> fresh PIN1/PIN2.
///
/// FINEID S4-1 v4.2 §4.6. Steps:
///
///   1. Open a transport session against the bound reader.
///   2. Probe both PIN slots' status and PIN-changed flags
///      (counter-safe, never burns retries).
///   3. Refuse without `--allow-reactivate` if the card looks
///      already activated -- the factory PIN is single-use.
///   4. Issue the generation-appropriate APDU (`CHANGE
///      REFERENCE DATA` newer / `RESET RETRY COUNTER` older).
///   5. Emit per-step events; return the typed
///      [`ActivateReport`] so the CLI can summarise outcomes
///      without leaking PIN bytes.
///
/// `options` (and the inner [`PinBytes`]) is consumed by value
/// per Rule E1 -- on return the activation PIN + new PIN1/PIN2
/// are zeroized.
///
/// # Errors
/// Returns card selection, transport, PIN-policy, or activation failures.
#[expect(
    clippy::needless_pass_by_value,
    reason = "ActivateOptions embeds activation PIN + new PIN1/PIN2 PinBytes; consumed by value so all drop+zeroize at function return."
)]
pub fn activate_first(
    backend: PcscBackend,
    ctx: ActivationCardContext,
    options: ActivateOptions,
) -> Result<ActivateReport, CardPinError> {
    let person = ctx.identity.person_string();
    crate::events::CardTarget {
        device: ctx.reader_id.as_str(),
        card: ctx.identity.best_serial().unwrap_or(""),
        person: &person,
    }
    .emit();

    // Validate the variant-vs-generation invariant *before*
    // opening the reader so a mismatch surfaces a structured
    // length_mismatch event and the typed
    // `CardPinError::ActivationLengthMismatch` without burning
    // PC/SC resources.
    let reader_label = ctx.reader_id.as_str().to_owned();
    if let Some(err) =
        ActivateGuard::check_length_match(&reader_label, &options.activation_pin, ctx.generation)
    {
        return Err(err);
    }

    // PinSequence: the activation PIN and the new PINs arrived
    // in `options`, so the activation sequence is card-bound
    // inside one held PC/SC transaction (the trace wrapper does
    // not affect the hold; it lives in the inner PcscCard).
    let inner = backend.open_session(&ctx.reader_id, ReaderAccessCap::PinSequence)?;
    let mut transport = crate::apdu_trace::ApduTraceTransport::new(inner);
    transport
        .select_pkcs15_application()
        .map_err(|e| CardPinError::Pkcs15Select(format!("{e}")))?;

    // Session re-verification: the card we are about to touch
    // must be the same physical card the trust gate matched
    // against the pinned root. A card swap / reader rename /
    // reader unplug between the trust gate and here revokes
    // trust before any modify APDU lands.
    re_verify_session(&mut transport, &ctx.bound_serial)?;

    let pin1_probe = transport.pin_status(PinSlot::Pin1).ok();
    let pin2_probe = transport.pin_status(PinSlot::Pin2).ok();
    // S1 v4.2 §3.15.2 GET DATA on the PIN container, DF 2F flag.
    // Best-effort: a card that doesn't implement the optional
    // "Return PIN changed flag" parameter returns `Ok(None)` and
    // refineid falls back to the existing PinStatus-only logic.
    let pin1_changed = transport.pin_changed_flag(PinSlot::Pin1).ok().flatten();
    let pin2_changed = transport.pin_changed_flag(PinSlot::Pin2).ok().flatten();
    ActivateGuard::emit_pin_changed_probed(pin1_changed, pin2_changed);
    let preflight = classify_preflight(
        pin1_probe,
        pin2_probe,
        ctx.generation,
        pin1_changed,
        pin2_changed,
    );

    if !options.allow_reactivate && preflight.looks_activated() {
        if let ActivatePreflightOutcome::LooksActivated { pin1, pin2 } = &preflight {
            crate::events::CardActivatePreflightRefused {
                reader: &reader_label,
                pin1_status: &format!("{pin1:?}"),
                pin2_status: &pin2.as_ref().map_or_else(String::new, |s| format!("{s:?}")),
            }
            .emit();
        }
        return Ok(ActivateReport {
            reader: reader_label,
            preflight,
            pin1_outcome: None,
            pin2_outcome: None,
        });
    }

    ActivateGuard::emit_scheme_selected(ctx.generation);

    // Re-verify session before the first modify APDU.
    re_verify_session(&mut transport, &ctx.bound_serial)?;

    // The per-PIN setup APDU takes PinBytes by value; build a
    // transient PinBytes from the typed activation code's inner
    // bytes. Done per-call so the typed wrapper stays the source
    // of truth at the API boundary; the transient PinBytes
    // zeroizes on drop just like every other secret material.
    let activation_pin_bytes = options.activation_pin.to_pin_bytes();
    let pin1_outcome = activate_slot_setup(
        &mut transport,
        PinSlot::Pin1,
        ctx.generation,
        activation_pin_bytes.clone(),
        options.new_pin1.clone(),
    )?;

    crate::events::CardActivatePin1Set {
        reader: &reader_label,
        outcome: &format!("{pin1_outcome:?}"),
    }
    .emit();

    // Single-shot: if PIN1 setup rejected the activation PIN
    // (wrong code, locked slot, anything other than Ok), don't
    // burn a second card-side try on the PIN2 slot. The operator
    // re-runs after fixing the input.
    if !activation_continues_after_pin1(pin1_outcome) {
        return Ok(ActivateReport {
            reader: reader_label,
            preflight,
            pin1_outcome: Some(pin1_outcome),
            pin2_outcome: None,
        });
    }

    // Re-verify session before the second modify APDU. A card
    // swap between PIN1 and PIN2 setup is the canonical TOCTOU
    // case this gate defends against.
    re_verify_session(&mut transport, &ctx.bound_serial)?;

    let pin2_outcome = activate_slot_setup(
        &mut transport,
        PinSlot::Pin2,
        ctx.generation,
        activation_pin_bytes,
        options.new_pin2,
    )?;

    crate::events::CardActivatePin2Set {
        reader: &reader_label,
        outcome: &format!("{pin2_outcome:?}"),
    }
    .emit();

    Ok(ActivateReport {
        reader: reader_label,
        preflight,
        pin1_outcome: Some(pin1_outcome),
        pin2_outcome: Some(pin2_outcome),
    })
}

/// Activate-flow pre-flight helpers. Hosted on a unit struct per
/// typing-discipline (`doc/typing-discipline.md`).
struct ActivateGuard;

impl ActivateGuard {
    /// Variant-vs-generation invariant. Emits the
    /// `card.activate.preflight.length_mismatch` event for the
    /// length-mismatch arms; returns the typed error so the
    /// caller can short-circuit.
    fn check_length_match(
        reader_label: &str,
        activation_pin: &ActivationCode,
        generation: CardGeneration,
    ) -> Option<CardPinError> {
        match (activation_pin, generation) {
            (ActivationCode::Seven(_), CardGeneration::Newer)
            | (ActivationCode::Eight(_), CardGeneration::Older) => None,
            (_, CardGeneration::Unknown) => Some(CardPinError::UnknownCardGeneration),
            (ActivationCode::Seven(_), CardGeneration::Older) => {
                let expected = ActivationPinEight::LENGTH;
                Self::emit_length_mismatch(reader_label, generation, expected);
                Some(CardPinError::ActivationLengthMismatch {
                    generation,
                    expected,
                })
            }
            (ActivationCode::Eight(_), CardGeneration::Newer) => {
                let expected = ActivationPinSeven::LENGTH;
                Self::emit_length_mismatch(reader_label, generation, expected);
                Some(CardPinError::ActivationLengthMismatch {
                    generation,
                    expected,
                })
            }
        }
    }

    /// Emit the `card.activate.preflight.length_mismatch`
    /// event when the operator-supplied activation PIN length
    /// doesn't fit the card generation.
    ///
    /// FINEID S4-1 §4.6.1/4.6.2 -- older-generation cards use
    /// an 8-digit activation PIN, newer use 7. The event is
    /// emitted *before* the typed error is returned so the
    /// audit trail captures the local-policy refusal even on
    /// pipelines that swallow the error string.
    fn emit_length_mismatch(reader_label: &str, generation: CardGeneration, expected: usize) {
        crate::events::CardActivatePreflightLengthMismatch {
            reader: reader_label,
            generation: &format!("{generation:?}"),
            expected_length: &format!("{expected}"),
        }
        .emit();
    }

    /// Emit the `card.activate.preflight.pin_changed_probed`
    /// event with the per-slot PIN-changed flag values.
    ///
    /// FINEID S1 v4.2 §3.15.2 -- the card-side flag indicates
    /// whether the slot's PIN has been changed from its
    /// factory value. `None` collapses to "indeterminate"
    /// (older firmware doesn't expose the GET DATA); the
    /// activate flow uses this purely as a preflight signal,
    /// not as a gate.
    fn emit_pin_changed_probed(pin1: Option<bool>, pin2: Option<bool>) {
        let render = |flag: Option<bool>| -> &'static str {
            match flag {
                Some(true) => "yes",
                Some(false) => "no",
                None => "indeterminate",
            }
        };
        crate::events::CardActivatePreflightPinChangedProbed {
            pin1_changed: render(pin1),
            pin2_changed: render(pin2),
        }
        .emit();
    }

    /// Emit the `card.activate.scheme_selected` event naming
    /// the APDU scheme chosen for this card generation.
    ///
    /// FINEID S4-1 §4.6.1 / §4.6.2 -- newer cards use the
    /// `CHANGE REFERENCE DATA` form (INS=`24`), older use
    /// `RESET RETRY COUNTER` (INS=`2C`). Emitted before the
    /// modify APDU goes out so the audit trail shows which
    /// path the activate flow took.
    fn emit_scheme_selected(generation: CardGeneration) {
        let (scheme, apdu_ins, section) = match generation {
            CardGeneration::Newer => ("new", "24", "4.6.2"),
            CardGeneration::Older => ("old", "2c", "4.6.1"),
            CardGeneration::Unknown => ("unknown", "", ""),
        };
        crate::events::CardActivateSchemeSelected {
            scheme,
            apdu_ins,
            fineid_s4_1_section: section,
        }
        .emit();
    }
}

impl fmt::Display for ActivateReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "reader: {}", self.reader)?;
        match &self.preflight {
            ActivatePreflightOutcome::LooksUnactivated { .. } => {
                writeln!(f, "preflight: card looks un-activated; proceeding")?;
            }
            ActivatePreflightOutcome::LooksActivated { pin1, pin2 } => {
                writeln!(
                    f,
                    "preflight: card looks ALREADY ACTIVATED \
                     (PIN1: {pin1:?}, PIN2: {pin2:?})"
                )?;
                if self.pin1_outcome.is_none() {
                    writeln!(
                        f,
                        "  refused without --allow-reactivate; the activation PIN \
                         is single-use, applying it to an already-active card may \
                         consume the only chance to set fresh PIN1/PIN2 values"
                    )?;
                    return Ok(());
                }
            }
        }
        if let Some(o) = self.pin1_outcome {
            writeln!(f, "PIN1 setup: {}", CardPinHelpers::fmt_unblock(o, "PIN1"))?;
        }
        if let Some(o) = self.pin2_outcome {
            writeln!(f, "PIN2 setup: {}", CardPinHelpers::fmt_unblock(o, "PIN2"))?;
        } else if matches!(self.pin1_outcome, Some(UnblockOutcome::Ok)) {
            // Shouldn't happen -- if PIN1 succeeded we always try PIN2.
            writeln!(f, "PIN2 setup: not attempted")?;
        } else if self.pin1_outcome.is_some() {
            writeln!(
                f,
                "PIN2 setup: not attempted (PIN1 setup failed; re-run after fixing \
                 the activation PIN -- each invocation consumes one card-side try)"
            )?;
        } else {
            // No PIN setup attempted yet; nothing to report for PIN2.
        }
        Ok(())
    }
}

/// Helpers hosted on a unit struct (typing-discipline: no
/// free fns with borrowed parameters; see
/// `doc/typing-discipline.md`).
struct CardPinHelpers;

impl CardPinHelpers {
    /// Render an [`UnblockOutcome`] for the activation / PIN-
    /// change reports.
    ///
    /// Each variant names the card-side condition in a way
    /// the operator can act on: `Ok` confirms counter reset,
    /// `WrongPuk` shows the remaining attempts, `PukLocked`
    /// names the DVV-paid reissue path, etc. `LengthError`
    /// is a host-side bug -- if the card returned `6700`,
    /// refineid sent a malformed APDU.
    fn fmt_unblock(o: UnblockOutcome, label: &str) -> String {
        match o {
            UnblockOutcome::Ok => format!("ok ({label} set; retry counter reset to max)"),
            UnblockOutcome::WrongPuk { retries_left } => {
                format!(
                    "WRONG activation PIN ({retries_left} card-side tries left; lockout pending)"
                )
            }
            UnblockOutcome::PukLocked => {
                "ACTIVATION PIN LOCKED -- order a PUK from DVV to recover (paid)".to_owned()
            }
            UnblockOutcome::Invalidated => {
                "card invalidated the activation PIN -- DVV reissue may be required".to_owned()
            }
            UnblockOutcome::LengthError => {
                "card rejected APDU length (SW=6700) -- host bug".to_owned()
            }
            UnblockOutcome::Other(sw) => format!("card returned unexpected SW={sw:#06X}"),
        }
    }
}

#[cfg(test)]
mod activate_tests {
    use refineid_lib_core::apdu::status_word::PinRetries;

    use super::{
        ActivatePreflightOutcome, CardGeneration, CardPinError, ChangePinOutcome, PinStatus,
        UnblockOutcome, activation_continues_after_pin1, card_manager_pin_change_available,
        change_to_unblock, classify_preflight,
    };
    use crate::test_util::{TestResult, check_true};
    use refineid_lib_core::pin::ActivationPinSeven;

    #[test]
    fn card_manager_allows_three_attempts_but_reserves_two() -> TestResult {
        let three = PinRetries::from_nibble(3).ok_or("PinRetries::from_nibble(3)")?;
        let two = PinRetries::from_nibble(2).ok_or("PinRetries::from_nibble(2)")?;
        check_true(
            card_manager_pin_change_available(Some(&PinStatus::Remaining(three))),
            "three attempts remain available to Card Manager",
        )?;
        check_true(
            !card_manager_pin_change_available(Some(&PinStatus::Remaining(two))),
            "two attempts remain reserved for expert recovery",
        )
    }

    /// New-scheme preflight (S4-1 v4.2 §4.6.2) with the DF2F
    /// "PIN changed" flag indeterminate (card declined the
    /// probe): pre-flight cannot decide, so it lets the flow
    /// proceed even though PIN1 status reads `Remaining(5)`
    /// (which is the *expected* fresh state for a new-scheme
    /// card).
    #[test]
    fn newer_preflight_changed_flag_indeterminate_proceeds() -> TestResult {
        let five = PinRetries::from_nibble(5).ok_or("PinRetries::from_nibble(5)")?;
        let pf = classify_preflight(
            Some(PinStatus::Remaining(five)),
            Some(PinStatus::Remaining(five)),
            CardGeneration::Newer,
            None,
            None,
        );
        check_true(
            matches!(pf, ActivatePreflightOutcome::LooksUnactivated { .. }),
            "LooksUnactivated",
        )
    }

    /// New-scheme preflight, PIN1 changed flag = false: this is
    /// a genuine fresh card, proceed.
    #[test]
    fn newer_preflight_changed_flag_false_proceeds() -> TestResult {
        let five = PinRetries::from_nibble(5).ok_or("PinRetries::from_nibble(5)")?;
        let pf = classify_preflight(
            Some(PinStatus::Remaining(five)),
            Some(PinStatus::Remaining(five)),
            CardGeneration::Newer,
            Some(false),
            Some(false),
        );
        check_true(
            matches!(pf, ActivatePreflightOutcome::LooksUnactivated { .. }),
            "LooksUnactivated",
        )
    }

    /// New-scheme preflight, PIN1 changed flag = true: card has
    /// been activated already; refuse the flow so the second-
    /// activation wrong-PIN doesn't decrement PIN1's counter.
    #[test]
    fn newer_preflight_changed_flag_true_refuses() -> TestResult {
        let five = PinRetries::from_nibble(5).ok_or("PinRetries::from_nibble(5)")?;
        let pf = classify_preflight(
            Some(PinStatus::Remaining(five)),
            Some(PinStatus::Remaining(five)),
            CardGeneration::Newer,
            Some(true),
            Some(true),
        );
        check_true(
            matches!(pf, ActivatePreflightOutcome::LooksActivated { .. }),
            "LooksActivated",
        )
    }

    /// Old-scheme preflight (S4-1 v4.2 §4.6.1): PIN1 ships
    /// BLOCKED. A Remaining(_) reading means somebody has already
    /// written to the slot -- evidence of prior activation; refuse
    /// without --allow-reactivate. Changed-flag probe is
    /// informational only on Older cards.
    #[test]
    fn older_preflight_with_healthy_pin1_refuses() -> TestResult {
        let five = PinRetries::from_nibble(5).ok_or("PinRetries::from_nibble(5)")?;
        let pf = classify_preflight(
            Some(PinStatus::Remaining(five)),
            None,
            CardGeneration::Older,
            None,
            None,
        );
        check_true(
            matches!(pf, ActivatePreflightOutcome::LooksActivated { .. }),
            "LooksActivated",
        )
    }

    /// Old-scheme preflight: inconclusive PIN1 reading
    /// (`PinStatus::NoInfo`) proceeds. Fresh old-scheme cards
    /// report this for the blocked PIN1 on some Thales
    /// `MultiApp` variants.
    #[test]
    fn older_preflight_no_info_proceeds() -> TestResult {
        let pf = classify_preflight(
            Some(PinStatus::NoInfo),
            None,
            CardGeneration::Older,
            None,
            None,
        );
        check_true(
            matches!(pf, ActivatePreflightOutcome::LooksUnactivated { .. }),
            "LooksUnactivated",
        )
    }

    /// Unknown generation is treated like Older (the existing
    /// behaviour). Activation should already have errored out
    /// upstream with [`CardPinError::UnknownCardGeneration`], so
    /// this is defense in depth.
    #[test]
    fn unknown_generation_keeps_old_scheme_classification() -> TestResult {
        let five = PinRetries::from_nibble(5).ok_or("PinRetries::from_nibble(5)")?;
        let pf = classify_preflight(
            Some(PinStatus::Remaining(five)),
            None,
            CardGeneration::Unknown,
            None,
            None,
        );
        check_true(
            matches!(pf, ActivatePreflightOutcome::LooksActivated { .. }),
            "LooksActivated",
        )
    }

    /// New-scheme PIN setup uses `CHANGE REFERENCE DATA`; the
    /// outcome is `ChangePinOutcome`. `ActivateReport` carries
    /// the unified `UnblockOutcome` form -- check the variant
    /// mapping covers every case.
    #[test]
    fn change_to_unblock_covers_every_variant() -> TestResult {
        let three = PinRetries::from_nibble(3).ok_or("PinRetries::from_nibble(3)")?;
        check_true(
            matches!(change_to_unblock(ChangePinOutcome::Ok), UnblockOutcome::Ok),
            "Ok -> Ok",
        )?;
        check_true(
            matches!(
                change_to_unblock(ChangePinOutcome::WrongCurrentPin {
                    retries_left: three
                }),
                UnblockOutcome::WrongPuk { .. }
            ),
            "WrongCurrentPin -> WrongPuk",
        )?;
        check_true(
            matches!(
                change_to_unblock(ChangePinOutcome::Locked),
                UnblockOutcome::PukLocked
            ),
            "Locked -> PukLocked",
        )?;
        check_true(
            matches!(
                change_to_unblock(ChangePinOutcome::LengthError),
                UnblockOutcome::LengthError
            ),
            "LengthError -> LengthError",
        )?;
        check_true(
            matches!(
                change_to_unblock(ChangePinOutcome::Other(0x6A88)),
                UnblockOutcome::Other(0x6A88)
            ),
            "Other -> Other",
        )
    }

    #[test]
    fn activation_failure_never_proceeds_to_pin2() -> TestResult {
        let three = PinRetries::from_nibble(3).ok_or("PinRetries::from_nibble(3)")?;
        check_true(
            activation_continues_after_pin1(UnblockOutcome::Ok),
            "successful PIN1 activation proceeds to PIN2",
        )?;
        for outcome in [
            UnblockOutcome::WrongPuk {
                retries_left: three,
            },
            UnblockOutcome::PukLocked,
            UnblockOutcome::Invalidated,
            UnblockOutcome::LengthError,
            UnblockOutcome::Other(0x6A80),
        ] {
            check_true(
                !activation_continues_after_pin1(outcome),
                "failed PIN1 activation stops before PIN2",
            )?;
        }
        Ok(())
    }

    #[test]
    fn activation_length_mismatch_debug_and_display_do_not_leak_candidate_length() -> TestResult {
        let err = CardPinError::ActivationLengthMismatch {
            generation: CardGeneration::Newer,
            expected: ActivationPinSeven::LENGTH,
        };
        let expected_debug = format!(
            "ActivationLengthMismatch {{ generation: Newer, expected: {} }}",
            ActivationPinSeven::LENGTH
        );
        check_true(format!("{err:?}") == expected_debug, "debug format")?;
        check_true(
            err.to_string().contains("Newer card expects 7 digits"),
            "display format",
        )?;
        Ok(())
    }
}
