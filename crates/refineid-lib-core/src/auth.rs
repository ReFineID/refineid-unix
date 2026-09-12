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

//! VERIFY PIN1 / PIN2 against a FINEID card.
//!
//! ISO 7816-4 §7.5.6 VERIFY against PKCS#15 PIN references. The
//! ASCII PIN bytes the user typed are right-padded with
//! [`PIN_PAD_BYTE`] (`0x00`) up to the slot's stored length (12)
//! and shipped as the APDU data field. Status-word classification
//! is done locally so callers can branch on
//! [`VerifyOutcome::WrongPin { retries_left }`] /
//! [`VerifyOutcome::Locked`] without re-parsing the SW.
//!
//! Reference FINEID S1 v4.2 §3.5 PIN management; ISO 7816-4 §7.5.6.
//!
//! Wire format (PIN1, slot reference `0x11`):
//!
//! ```text
//!  CLA INS P1 P2  Lc  data...
//!  00  20  00 11  0C  <12 bytes: ASCII PIN + 0x00 padding>
//! ```
//!
//! Local-policy gating (digit-only, length bounds) happens before
//! any APDU goes out -- a malformed PIN never reaches the card, so
//! it doesn't burn a retry counter slot.

pub mod commands;

pub use refineid_auth::{
    ActivationReport, ActivationScheme, CACHE_FINGERPRINT_KEY_LEN, CACHE_FINGERPRINT_LEN,
    CardActivationNeeds, CredentialHealthReport, ManageOutcome, PinChangeRecord, PinManageOps,
    PinRetryRisk, classify_manage_sw, pin1_status_permits_consumer_authentication,
    pin1_status_permits_reusable_cache, pin2_status_permits_qualified_signature,
    read_pin_change_record, read_puk_status_from_container,
};

use crate::apdu::iso7816::ApduClass;
use crate::apdu::status_word::{PinRetries, StatusWord};
use crate::pin::PinBytes;
use crate::transport::{CardTransport, TransportDispatchError};

/// Shortened alias for the transport-error variant produced by a
/// dispatch on a `CardTransport`-implementing type. Used to keep
/// the auth-flow signatures readable when the same nested generic
/// would otherwise repeat on every error-returning function.
type TxError<T> = TransportDispatchError<<T as CardTransport>::Error>;

/// PKCS#15 PIN1 reference -- auth PIN (digital signature for TLS
/// client cert / SSH / agent). FINEID S1 v4.2 §3.5.1.
pub const PIN1_REFERENCE_PKCS15: u8 = 0x11;

/// PKCS#15 PIN2 reference -- qualified-signature PIN (non-
/// repudiation). FINEID S1 v4.2 §3.5.2.
pub const PIN2_REFERENCE_PKCS15: u8 = 0x82;
/// PKCS#15 PUK reference shared by PIN1 and PIN2 recovery.
pub const PUK_REFERENCE_PKCS15: u8 = 0x83;

/// Organization-card PIN1 reference -- the PIN AUTH security data
/// object identifier. FINEID S4-2 v4.0 §4.2 / §4.3.1.
pub const PIN1_REFERENCE_ORGANIZATIONAL: u8 = 0x03;

/// Organization-card PIN2 reference -- the PIN SIG security data
/// object identifier. FINEID S4-2 v4.0 §4.2 / §4.3.3.
pub const PIN2_REFERENCE_ORGANIZATIONAL: u8 = 0x04;

/// Organization-card unblock reference -- the PIN PUK security data
/// object identifier; the card's own EF.AOD labels the credential
/// "aktivointitunnusluku". FINEID S4-2 v4.0 §4.2 / §4.3.2.
///
/// S4-2 v4.0 §4.3.2 marks this credential's own CHANGE REFERENCE
/// DATA and RESET RETRY COUNTER as Never: it cannot be changed and
/// cannot be recovered once spent to zero.
pub const PUK_REFERENCE_ORGANIZATIONAL: u8 = 0x12;

/// FINEID stored-length for both PIN slots: 12 bytes. PIN1 / PIN2
/// share the same encoding -- the difference is the slot reference,
/// not the length.
pub const PIN1_STORED_LENGTH: usize = 12;
/// See [`PIN1_STORED_LENGTH`].
pub const PIN2_STORED_LENGTH: usize = 12;

/// Padding byte applied to the right of the typed ASCII digits up
/// to [`PIN1_STORED_LENGTH`]. FINEID cards reject any non-`0x00`
/// padding byte with `SW=6A80`.
pub const PIN_PAD_BYTE: u8 = 0x00;

/// Minimum PIN1 length per FINEID S1 v4.2 §3.5.1: 4 digits.
pub const PIN1_MIN_LENGTH: usize = 4;
/// Minimum PIN2 length per FINEID S1 v4.2 §3.5.2: 6 digits.
pub const PIN2_MIN_LENGTH: usize = 6;

/// Organization-card typed-length ceiling for every credential.
///
/// FINEID S4-2 v4.0 §4.3 caps PIN AUTH, PIN SIG and PIN PUK at
/// eight characters. The card stores each credential at its typed
/// length -- its EF.AOD publishes no padding, and FINEID S1 v3.0
/// §3.5.1.1 requires the entered length to equal the stored one,
/// so a padded block fails the comparison and spends a retry.
pub const ORGANIZATIONAL_PIN_MAX_LENGTH: usize = 8;

/// Organization-card credential floor (S4-2 v4.0 §4.3: 04 Min).
pub const ORGANIZATIONAL_PIN_MIN_LENGTH: usize = 4;

/// PUK stored-length: 12 bytes, padded with [`PIN_PAD_BYTE`].
///
/// The PUK uses the same 12-byte padded slot as the PIN1 / PIN2
/// references. A PUK is 8 to 12 digits independent of card generation.
///
/// "PUK" here refers to the unblock-counter password in card
/// slot ref `0x83` -- the `RESET RETRY COUNTER` surface. Only
/// on cards issued **before 2026-01-13** does the activation
/// letter's 8-digit *aktivointitunnusluku* double as this PUK
/// (reusable -- effectively a permanent PIN-reset code, which
/// is why newer cards dropped the scheme). Cards issued on or
/// after 2026-01-13 ship a 7-digit **single-use** activation
/// code that is consumed by activation (`CHANGE REFERENCE
/// DATA`, not this path) and can never unblock anything; their
/// separately ordered PUK is 8 to 12 digits; its length is not selected
/// from card generation.
/// See `doc/dvv-terminology.md` and `pin::ActivationPinSeven`
/// / `pin::ActivationPinEight` / `pin::Puk`.
pub const PUK_STORED_LENGTH: usize = 12;
/// Minimum PUK length (FINEID S4-1 v4.2 section 8.1.5, EF.AOD).
pub const PUK_MIN_LENGTH: usize = 8;
/// Maximum PUK length: the stored (padded) block length.
pub const PUK_MAX_LENGTH: usize = 12;

/// Which PIN slot a `verify_pin` call targets. `Pin1` is the auth
/// PIN (digital signature, TLS client cert, SSH); `Pin2` is the
/// qualified-signature PIN (non-repudiation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinSlot {
    /// PIN1 -- authentication / digital-signature PIN.
    Pin1,
    /// PIN2 -- qualified-signature / non-repudiation PIN.
    Pin2,
}

impl PinSlot {
    /// VERIFY APDU P2 byte -- the PKCS#15 reference for this slot.
    #[must_use]
    pub const fn p2_reference(self) -> u8 {
        match self {
            Self::Pin1 => PIN1_REFERENCE_PKCS15,
            Self::Pin2 => PIN2_REFERENCE_PKCS15,
        }
    }

    /// Card-side stored length for this slot. Local padding pads
    /// to this many bytes.
    #[must_use]
    pub const fn stored_length(self) -> usize {
        match self {
            Self::Pin1 => PIN1_STORED_LENGTH,
            Self::Pin2 => PIN2_STORED_LENGTH,
        }
    }

    /// Smallest accepted typed PIN length. Local-policy gate; the
    /// card itself doesn't see the un-padded length.
    #[must_use]
    pub const fn min_length(self) -> usize {
        match self {
            Self::Pin1 => PIN1_MIN_LENGTH,
            Self::Pin2 => PIN2_MIN_LENGTH,
        }
    }
}

/// Which credential reference numbering the card in session uses.
///
/// Citizen cards number their credentials as FINEID S1 v4.2 §3.5.2
/// reads: global PIN1 `0x11`, local PIN2 `0x82`, PUK `0x83`.
/// Organization cards number them by their FINEID S4-2 v4.0 §4.2
/// security-data-object identifiers instead: PIN AUTH `0x03`,
/// PIN SIG `0x04`, PIN PUK `0x12`.
///
/// The S4-2 v4.0 §5.2 EF.AOD *sample* prints references `0x11` /
/// `0x0095`, contradicting the same document's §4.2 tables and
/// shipped cards; the sample is stale. Resolution therefore asks
/// the card ([`PinOps::resolve_pin_reference_scheme`]) rather than
/// trusting any printed sample: a VERIFY status probe against an
/// absent reference answers `SW=6A88` without touching any retry
/// counter, so the probe costs one command and no risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinReferenceScheme {
    /// FINEID S1 v4.2 §3.5.2 numbering -- the citizen cards.
    Citizen,
    /// FINEID S4-2 v4.0 §4.2 numbering -- the organization cards.
    Organizational,
}

impl PinReferenceScheme {
    /// VERIFY / CHANGE REFERENCE DATA / RESET RETRY COUNTER P2 byte
    /// for `slot` under this numbering.
    #[must_use]
    pub const fn p2_reference(self, slot: PinSlot) -> u8 {
        match (self, slot) {
            (Self::Citizen, PinSlot::Pin1) => PIN1_REFERENCE_PKCS15,
            (Self::Citizen, PinSlot::Pin2) => PIN2_REFERENCE_PKCS15,
            (Self::Organizational, PinSlot::Pin1) => PIN1_REFERENCE_ORGANIZATIONAL,
            (Self::Organizational, PinSlot::Pin2) => PIN2_REFERENCE_ORGANIZATIONAL,
        }
    }

    /// The unblock credential's own reference under this numbering.
    #[must_use]
    pub const fn puk_reference(self) -> u8 {
        match self {
            Self::Citizen => PUK_REFERENCE_PKCS15,
            Self::Organizational => PUK_REFERENCE_ORGANIZATIONAL,
        }
    }
}

/// Outcome of a `pin_status` probe (`VERIFY P1=0x00 Lc=0`).
///
/// FINEID-S1 §4.1.2 / IAS-ECC §7.5.6 make this APDU explicitly
/// side-effect-free: neither path decrements the PIN's retry
/// counter or its usage counter, so this is the safe pre-flight
/// probe to run before any operation that would burn a retry on
/// a PIN mistake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinStatus {
    /// `SW = 0x9000` -- PIN already verified in this card session.
    /// Subsequent PIN-protected ops won't prompt again until a
    /// SELECT or RESET clears the session.
    Verified,
    /// `SW = 0x63CX` -- PIN not currently verified, `X` retries
    /// left before lockout. `X = 0` means *the next* VERIFY
    /// failure will lock the card.
    Remaining(PinRetries),
    /// `SW = 0x6300` -- "verification failed, no retries
    /// information". Some cards return this when retries=0 or
    /// when the PIN is in an indeterminate state (locked but not
    /// yet 6983).
    NoInfo,
    /// `SW = 0x6983` / `0x6984` -- PIN method blocked or usage
    /// counter exhausted. PUK unblock is the only recovery path.
    Locked,
    /// Anything else -- surfaced opaquely for the caller.
    Other(u16),
}

/// Outcome of the counter-safe PUK retry probe through the FINEID
/// PIN-container `GET DATA` command from S1 v4.2 section 3.15.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PukStatus {
    /// PIN-container attributes report X PUK presentations remain.
    Remaining(PinRetries),
    /// The card supplied no parseable retry-counter value.
    NoInfo,
    /// `SW=6983`: the shared PUK is blocked.
    Locked,
    /// `SW=6984`: the target PIN recovery data or PUK is invalidated.
    Invalidated,
    /// Any other status word, preserved for diagnostics.
    Other(u16),
}

/// Card-reported credential usage allowance from FINEID S1 v4.2
/// section 3.15.3, PIN attributes field 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageCounter {
    /// No successful uses remain.
    Exhausted,
    /// A finite number of successful uses remain.
    Limited(std::num::NonZeroU8),
    /// The card reports no usage limit.
    NoLimit,
}

/// Card-reported PIN recovery allowance from FINEID S1 v4.2
/// section 3.15.3, PIN attributes field 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnblockingCounter {
    /// No recoveries remain, or recovery is not applicable to this
    /// credential.
    Exhausted,
    /// A finite number of recoveries remain.
    Limited(std::num::NonZeroU8),
    /// The card reports no recovery limit.
    NoLimit,
}

/// Typed policy counters returned by the card's counter-safe PIN-info
/// `GET DATA` command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialPolicyCounters {
    /// Successful-use allowance for the queried credential.
    pub usage: UsageCounter,
    /// Recovery allowance for the queried credential.
    pub unblocking: UnblockingCounter,
}

/// Outcome of a VERIFY round trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// `SW = 0x9000` -- PIN accepted. The card stays in the
    /// user-authenticated state until a SELECT or RESET clears it.
    Ok,
    /// `SW = 0x63CX` -- wrong PIN, `X` retries left. `X = 0`
    /// means the next failed VERIFY will lock the slot.
    WrongPin {
        /// Number of attempts remaining before the slot locks
        /// (PIN counter nibble from SW `63Cx`).
        retries_left: PinRetries,
    },
    /// `SW = 0x6983` / `0x6984` -- authentication method blocked.
    /// The card won't accept any VERIFY until a PUK unblock.
    Locked,
    /// Anything else -- surfaced as opaque SW for the caller to map.
    Other(u16),
}

/// Reasons a PIN gets rejected locally, before any APDU goes out.
///
/// The wire-shape variants (`WrongLength`, `NonDigit`) are
/// enforced by `verify_pin` / `change_pin` directly because
/// they describe shapes the card can't even accept. The
/// protocol layer stays policy-light beyond that: PIN quality
/// is the citizen's call (and the consumer UI's, if it wants
/// to advise) -- lib-core ships no strength policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PinPolicyReason {
    /// Typed length is outside `[slot.min_length(),
    /// slot.stored_length()]`.
    WrongLength {
        /// Minimum length the slot accepts.
        min: usize,
        /// Maximum length the slot accepts.
        max: usize,
    },
    /// Non-digit ASCII byte encountered. PIN bytes must all
    /// be in `b'0'..=b'9'`.
    NonDigit,
}

impl core::fmt::Display for PinPolicyReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongLength { min, max } => {
                write!(f, "pin length outside accepted range {min}..={max}")
            }
            Self::NonDigit => {
                write!(f, "pin must contain only ASCII digits")
            }
        }
    }
}

/// VERIFY-path errors.
#[derive(Debug)]
pub enum AuthError<TE> {
    /// Transport-layer failure -- PC/SC error, reader removed,
    /// card reset, etc.
    Transport(TE),
    /// Locally-rejected PIN; no APDU was sent.
    PinPolicy(PinPolicyReason),
}

impl<TE: core::fmt::Display> core::fmt::Display for AuthError<TE> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "auth transport: {e}"),
            Self::PinPolicy(reason) => write!(f, "auth pin policy: {reason}"),
        }
    }
}

impl<TE: core::fmt::Debug + core::fmt::Display + 'static> core::error::Error for AuthError<TE> {}

/// Local-policy gate for a PIN-shape ASCII buffer: length within
/// `[min, stored]` and every byte an ASCII digit. Returns the
/// matching [`AuthError::PinPolicy`] variant on failure, `Ok(())`
/// otherwise.
///
/// Centralises the wire-shape check used by `verify_pin`,
/// `change_pin`, and `reset_retry_counter`. Failing locally
/// (before the card sees the APDU) never decrements a card-side
/// retry counter, so this gate is cheap insurance against typos.
///
/// The error type is parameterised by the caller's transport
/// error so a single helper composes into every on-card path.
/// Local-policy gate for `ascii` PIN bytes. Unit struct hosting
/// the validator inside an `impl` block (typing-discipline:
/// no free fns with borrowed parameters; see
/// `doc/typing-discipline.md`).
struct PinPolicyCheck;

impl PinPolicyCheck {
    /// `ascii` must be in `[min, stored]` length and contain
    /// only ASCII digits. Maps the failure to [`AuthError`] so
    /// callers can `?` it directly.
    fn validate_ascii<TE>(ascii: &[u8], min: usize, stored: usize) -> Result<(), AuthError<TE>> {
        if ascii.len() < min || ascii.len() > stored {
            return Err(AuthError::PinPolicy(PinPolicyReason::WrongLength {
                min,
                max: stored,
            }));
        }
        if ascii.iter().any(|b| !b.is_ascii_digit()) {
            return Err(AuthError::PinPolicy(PinPolicyReason::NonDigit));
        }
        Ok(())
    }
}

/// PIN-management operations layered as default-impl methods on
/// every [`CardTransport`].
///
/// The trait is the typed receiver that keeps these APIs out of
/// the "`pub fn` with borrowed parameters" category -- see
/// `doc/typing-discipline.md`. Import it via
/// `use refineid_lib_core::auth::PinOps;` to put the methods in
/// scope; the blanket impl below applies to every transport.
pub trait PinOps: CardTransport {
    /// VERIFY APDU `00 20 00 P2 LC <padded-pin>`.
    ///
    /// Generic over [`PinSlot`] so PIN1 (`P2 = 0x11`, auth) and PIN2
    /// (`P2 = 0x82`, qualified-sig) share the same wire path. Typed
    /// PIN bytes are right-padded with [`PIN_PAD_BYTE`] to
    /// `slot.stored_length()`.
    ///
    /// Local-policy gates: length must be in `[slot.min_length(),
    /// slot.stored_length()]`, every byte must be an ASCII digit. A
    /// rejection here doesn't burn a card-side retry counter slot.
    ///
    /// `pin` is consumed by value -- typed receivers and owned
    /// secrets cross the API boundary; the underlying buffer is
    /// `ZeroizeOnDrop` so the caller doesn't leak it by passing
    /// ownership in.
    ///
    /// # Errors
    /// [`AuthError::PinPolicy`] when local policy rejects the typed
    /// PIN; [`AuthError::Transport`] when the underlying transport
    /// fails.
    fn verify_pin(
        &mut self,
        slot: PinSlot,
        pin: PinBytes,
    ) -> Result<VerifyOutcome, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.verify_pin_with_scheme(slot, PinReferenceScheme::Citizen, pin)
    }

    /// [`Self::verify_pin`] under an explicit reference numbering.
    ///
    /// Resolve the numbering first ([`Self::resolve_pin_reference_scheme`])
    /// -- a VERIFY against the wrong one answers `SW=6A88` without
    /// burning a retry, but the caller has then spent the typed PIN
    /// for nothing.
    ///
    /// # Errors
    /// As [`Self::verify_pin`].
    fn verify_pin_with_scheme(
        &mut self,
        slot: PinSlot,
        scheme: PinReferenceScheme,
        pin: PinBytes,
    ) -> Result<VerifyOutcome, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        let mut block = credential_block(
            scheme,
            slot.min_length(),
            slot.stored_length(),
            pin.as_bytes(),
        )?;
        let apdu = commands::Verify {
            class: ApduClass::Plain,
            mode: commands::VerifyMode::Verify,
            slot,
            scheme,
            data: commands::VerifyData::PinBlock(block.clone()),
        }
        .into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(AuthError::Transport)?;
        // Wipe the block; it carries the typed PIN bytes.
        zeroize::Zeroize::zeroize(&mut block);
        Ok(classify_verify_sw(r.status_word()))
    }

    /// Convenience for the PIN1 (auth) slot.
    ///
    /// # Errors
    /// See [`PinOps::verify_pin`].
    fn verify_pin1(&mut self, pin: PinBytes) -> Result<VerifyOutcome, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.verify_pin(PinSlot::Pin1, pin)
    }

    /// `CHANGE REFERENCE DATA` per ISO 7816-4 §7.5.7. Local-policy
    /// gates apply to both the current and new PIN; see
    /// [`PinOps::verify_pin`] for the gate semantics.
    ///
    /// # Errors
    /// [`AuthError::PinPolicy`] on local rejection;
    /// [`AuthError::Transport`] on transport failure.
    fn change_pin(
        &mut self,
        slot: PinSlot,
        current_pin: PinBytes,
        new_pin: PinBytes,
    ) -> Result<ChangePinOutcome, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.change_pin_with_scheme(slot, PinReferenceScheme::Citizen, current_pin, new_pin)
    }

    /// [`Self::change_pin`] under an explicit reference numbering.
    ///
    /// # Errors
    /// As [`Self::change_pin`].
    fn change_pin_with_scheme(
        &mut self,
        slot: PinSlot,
        scheme: PinReferenceScheme,
        current_pin: PinBytes,
        new_pin: PinBytes,
    ) -> Result<ChangePinOutcome, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        let stored = slot.stored_length();
        let min = slot.min_length();
        let mut current_block = credential_block(scheme, min, stored, current_pin.as_bytes())?;
        let mut new_block = credential_block(scheme, min, stored, new_pin.as_bytes())?;
        let mut pair = current_block.clone();
        pair.extend_from_slice(&new_block);

        let apdu = commands::ChangeReferenceData {
            slot,
            scheme,
            padded_pair: pair.clone(),
        }
        .into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(AuthError::Transport)?;
        zeroize::Zeroize::zeroize(&mut current_block);
        zeroize::Zeroize::zeroize(&mut new_block);
        zeroize::Zeroize::zeroize(&mut pair);
        Ok(classify_change_pin_sw(r.status_word()))
    }

    /// Convenience for the PIN1 (auth) slot.
    ///
    /// # Errors
    /// See [`PinOps::change_pin`].
    fn change_pin1(
        &mut self,
        current_pin: PinBytes,
        new_pin: PinBytes,
    ) -> Result<ChangePinOutcome, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.change_pin(PinSlot::Pin1, current_pin, new_pin)
    }

    /// `RESET RETRY COUNTER` per ISO 7816-4 §7.5.10 (PUK-driven
    /// unblock). See the standalone doc comment on
    /// [`UnblockOutcome`] for the wire path and side-effect rules.
    ///
    /// # Errors
    /// [`AuthError::PinPolicy`] on local rejection;
    /// [`AuthError::Transport`] on transport failure.
    fn reset_retry_counter(
        &mut self,
        target: PinSlot,
        puk: PinBytes,
        new_pin: PinBytes,
    ) -> Result<UnblockOutcome, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.reset_retry_counter_with_scheme(target, PinReferenceScheme::Citizen, puk, new_pin)
    }

    /// [`Self::reset_retry_counter`] under an explicit reference
    /// numbering. The P2 byte names the target PIN in both
    /// numberings; the unblock credential itself rides in the data
    /// field.
    ///
    /// # Errors
    /// As [`Self::reset_retry_counter`].
    fn reset_retry_counter_with_scheme(
        &mut self,
        target: PinSlot,
        scheme: PinReferenceScheme,
        puk: PinBytes,
        new_pin: PinBytes,
    ) -> Result<UnblockOutcome, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        match scheme {
            PinReferenceScheme::Citizen => {
                let puk_ascii = puk.as_bytes();
                let new_ascii = new_pin.as_bytes();
                let target_min = target.min_length();
                let target_stored = target.stored_length();
                PinPolicyCheck::validate_ascii(puk_ascii, PUK_MIN_LENGTH, PUK_MAX_LENGTH)?;
                PinPolicyCheck::validate_ascii(new_ascii, target_min, target_stored)?;

                let mut padded =
                    vec![PIN_PAD_BYTE; PUK_STORED_LENGTH.saturating_add(target_stored)];
                #[expect(
                    clippy::indexing_slicing,
                    clippy::arithmetic_side_effects,
                    reason = "validate_ascii above proves puk_ascii.len() <= PUK_STORED_LENGTH and new_ascii.len() <= target_stored; padded was allocated at PUK_STORED_LENGTH+target_stored, so all index ranges are in-bounds."
                )]
                {
                    padded[..puk_ascii.len()].copy_from_slice(puk_ascii);
                    padded[PUK_STORED_LENGTH..PUK_STORED_LENGTH + new_ascii.len()]
                        .copy_from_slice(new_ascii);
                }

                let apdu = commands::ResetRetryCounter {
                    target_slot: target,
                    scheme,
                    padded_pair: padded.clone(),
                }
                .into_apdu();
                let r = self
                    .transmit(apdu.as_bytes())
                    .map_err(AuthError::Transport)?;
                zeroize::Zeroize::zeroize(&mut padded);
                Ok(classify_reset_retry_sw(r.status_word()))
            }
            PinReferenceScheme::Organizational => {
                // The S4-2 v4.0 SDO tables gate RESET RETRY COUNTER
                // on SE#03: the unblock credential is verified as
                // its own object first, then the reset carries only
                // the new PIN (Idemia organizational cards
                // specification §4.1.6, P1 02).
                let mut code_block = credential_block(
                    scheme,
                    ORGANIZATIONAL_PIN_MIN_LENGTH,
                    ORGANIZATIONAL_PIN_MAX_LENGTH,
                    puk.as_bytes(),
                )?;
                let mut new_block = credential_block(
                    scheme,
                    target.min_length(),
                    ORGANIZATIONAL_PIN_MAX_LENGTH,
                    new_pin.as_bytes(),
                )?;
                let verify = commands::VerifyPuk {
                    scheme,
                    block: code_block.clone(),
                }
                .into_apdu();
                let verified = self
                    .transmit(verify.as_bytes())
                    .map_err(AuthError::Transport)?;
                zeroize::Zeroize::zeroize(&mut code_block);
                match classify_verify_sw(verified.status_word()) {
                    VerifyOutcome::Ok => {}
                    VerifyOutcome::WrongPin { retries_left } => {
                        zeroize::Zeroize::zeroize(&mut new_block);
                        return Ok(UnblockOutcome::WrongPuk { retries_left });
                    }
                    VerifyOutcome::Locked => {
                        zeroize::Zeroize::zeroize(&mut new_block);
                        return Ok(UnblockOutcome::PukLocked);
                    }
                    VerifyOutcome::Other(sw) => {
                        zeroize::Zeroize::zeroize(&mut new_block);
                        return Ok(UnblockOutcome::Other(sw));
                    }
                }
                let reset = commands::ResetRetryCounterVerifiedPuk {
                    target_slot: target,
                    scheme,
                    new_block: new_block.clone(),
                }
                .into_apdu();
                let r = self
                    .transmit(reset.as_bytes())
                    .map_err(AuthError::Transport)?;
                zeroize::Zeroize::zeroize(&mut new_block);
                Ok(classify_reset_retry_sw(r.status_word()))
            }
        }
    }

    /// Convenience for the PIN1 slot (`target = PinSlot::Pin1`).
    ///
    /// # Errors
    /// See [`PinOps::reset_retry_counter`].
    fn unblock_pin1(
        &mut self,
        puk: PinBytes,
        new_pin: PinBytes,
    ) -> Result<UnblockOutcome, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.reset_retry_counter(PinSlot::Pin1, puk, new_pin)
    }

    /// Probe the card's PIN state for `slot` without touching its
    /// retry counter. Side-effect-free.
    ///
    /// # Errors
    /// Transport failure.
    fn pin_status(&mut self, slot: PinSlot) -> Result<PinStatus, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.pin_status_with_scheme(slot, PinReferenceScheme::Citizen)
    }

    /// [`Self::pin_status`] under an explicit reference numbering.
    ///
    /// # Errors
    /// Transport failure.
    fn pin_status_with_scheme(
        &mut self,
        slot: PinSlot,
        scheme: PinReferenceScheme,
    ) -> Result<PinStatus, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        let apdu = commands::Verify {
            class: ApduClass::Plain,
            mode: commands::VerifyMode::Verify,
            slot,
            scheme,
            data: commands::VerifyData::Probe,
        }
        .into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(AuthError::Transport)?;
        Ok(classify_pin_status_sw(r.status_word()))
    }

    /// Ask the card which reference numbering it uses, spending two
    /// counter-safe probes at most and no retries.
    ///
    /// The citizen PIN1 reference is probed first: any recognised
    /// PIN state means the citizen numbering ([`PinReferenceScheme`])
    /// is live. `SW=6A88` -- reference not found -- is the
    /// organization card's signature, confirmed by probing the
    /// S4-2 numbering the same way. A card that answers neither
    /// probe recognisably resolves to citizen, which preserves the
    /// behaviour every existing caller had before this seam existed.
    ///
    /// # Errors
    /// Transport failure.
    fn resolve_pin_reference_scheme(
        &mut self,
    ) -> Result<PinReferenceScheme, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        let citizen = reference_probe_sw(self, PinReferenceScheme::Citizen)?;
        if !matches!(citizen, StatusWord::ReferenceDataNotFound) {
            return Ok(PinReferenceScheme::Citizen);
        }
        let organizational = reference_probe_sw(self, PinReferenceScheme::Organizational)?;
        Ok(match classify_pin_status_sw(organizational) {
            PinStatus::Verified
            | PinStatus::Remaining(_)
            | PinStatus::Locked
            | PinStatus::NoInfo => PinReferenceScheme::Organizational,
            PinStatus::Other(_) => PinReferenceScheme::Citizen,
        })
    }

    /// Read the shared PUK retry counter without presenting a PUK.
    ///
    /// The command reads the PUK PIN-container object, carries no
    /// credential data, and does not decrement retry or usage counters.
    ///
    /// # Errors
    /// Transport failure.
    fn puk_status(&mut self) -> Result<PukStatus, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        let apdu = commands::GetPukInfo.into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(AuthError::Transport)?;
        if r.is_ok() {
            return Ok(
                commands::PinInfoResponse::try_counter_from_response_body(&r.body)
                    .map_or(PukStatus::NoInfo, PukStatus::Remaining),
            );
        }
        Ok(classify_puk_status_sw(r.status_word()))
    }

    /// [`Self::puk_status`] under an explicit reference numbering.
    ///
    /// The citizen numbering reads the PUK PIN-container (GET
    /// DATA); the organizational numbering probes its PIN PUK
    /// security data object with the counter-safe VERIFY status
    /// form instead (S4-2 v4.0 §4.3.2), since the container does
    /// not exist there.
    ///
    /// # Errors
    /// Transport failure.
    fn puk_status_with_scheme(
        &mut self,
        scheme: PinReferenceScheme,
    ) -> Result<PukStatus, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        match scheme {
            PinReferenceScheme::Citizen => self.puk_status(),
            PinReferenceScheme::Organizational => {
                let apdu = commands::VerifyPukProbe { scheme }.into_apdu();
                let r = self
                    .transmit(apdu.as_bytes())
                    .map_err(AuthError::Transport)?;
                Ok(match classify_pin_status_sw(r.status_word()) {
                    PinStatus::Remaining(retries) => PukStatus::Remaining(retries),
                    PinStatus::Verified | PinStatus::NoInfo => PukStatus::NoInfo,
                    PinStatus::Locked => PukStatus::Locked,
                    PinStatus::Other(sw) => PukStatus::Other(sw),
                })
            }
        }
    }

    /// Read PIN1 or PIN2 usage and recovery allowances without
    /// presenting a credential or changing any card counter.
    ///
    /// # Errors
    /// Transport failure while querying the card.
    fn pin_policy_counters(
        &mut self,
        slot: PinSlot,
    ) -> Result<Option<CredentialPolicyCounters>, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        let apdu = commands::GetPinInfo { slot }.into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(AuthError::Transport)?;
        if !r.is_ok() {
            return Ok(None);
        }
        Ok(commands::PinInfoResponse::policy_counters_from_response_body(&r.body))
    }

    /// Read shared-PUK usage and recovery allowances without
    /// presenting the PUK or changing any card counter.
    ///
    /// # Errors
    /// Transport failure while querying the card.
    fn puk_policy_counters(
        &mut self,
    ) -> Result<Option<CredentialPolicyCounters>, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        let apdu = commands::GetPukInfo.into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(AuthError::Transport)?;
        if !r.is_ok() {
            return Ok(None);
        }
        Ok(commands::PinInfoResponse::policy_counters_from_response_body(&r.body))
    }

    /// Probe the FINEID "PIN changed" flag for `slot` per S1 v4.2
    /// §3.15.2 Table 19 (`DF 2F 01 xx`).
    ///
    /// Returns:
    /// - `Ok(Some(true))` if the PIN has been changed since
    ///   manufacture (the FINEID activation-state signal for new-
    ///   scheme cards),
    /// - `Ok(Some(false))` if it is still at the factory value,
    /// - `Ok(None)` for any card response that did not yield a
    ///   parseable `DF 2F` flag -- either the card returned a
    ///   non-success SW (pre-FINEID-S1-v4.0 cards may not
    ///   implement GET DATA for the PIN container at all and
    ///   reply `SW=6A88` "Referenced data not found"), or the
    ///   response body did not carry a DF2F TLV (the spec marks
    ///   the flag as returned only if the "Return PIN changed
    ///   flag" parameter is set, S1 v4.2 §3.15.2 caveat below
    ///   Table 16). Callers should treat `None` as "flag
    ///   indeterminate; proceed with the existing preflight."
    ///
    /// Side effects: **none**. Counter-safe -- neither the PIN try
    /// counter nor the PIN usage counter is decremented. Same
    /// risk profile as [`PinOps::pin_status`].
    ///
    /// # Errors
    /// Transport failure only. Non-success status words are
    /// absorbed into the `Ok(None)` arm because every known
    /// non-success path here is "card does not implement this
    /// probe" rather than "operation failed".
    fn pin_changed_flag(&mut self, slot: PinSlot) -> Result<Option<bool>, AuthError<TxError<Self>>>
    where
        Self: Sized,
    {
        let apdu = commands::GetPinInfo { slot }.into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(AuthError::Transport)?;
        if !r.is_ok() {
            return Ok(None);
        }
        Ok(commands::PinInfoResponse::changed_flag_from_response_body(
            &r.body,
        ))
    }
}

impl<T: CardTransport + ?Sized> PinOps for T {}

/// Outcome of a `CHANGE REFERENCE DATA` (PIN rotation) round trip.
///
/// On `Ok`, the target PIN's retry counter is reset to its maximum
/// and the PIN's reference value has been replaced with `new_pin`.
/// Per IAS-ECC §9.4.2 the card clears the PIN-presentation flag as
/// part of the rotation: callers that want continued access to
/// PIN-protected ops MUST re-VERIFY with the new PIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangePinOutcome {
    /// `SW = 0x9000` -- PIN replaced, retry counter reset, PIN
    /// presentation cleared (a fresh VERIFY is required next).
    Ok,
    /// `SW = 0x63CX` -- current PIN was wrong, `X` retries left.
    WrongCurrentPin {
        /// Number of attempts remaining before the slot locks.
        retries_left: PinRetries,
    },
    /// `SW = 0x6983` / `0x6984` -- card is blocked or PIN usage
    /// counter exhausted; PUK-driven unblock is the only recovery.
    Locked,
    /// `SW = 0x6700` -- Lc / data-field length didn't match the
    /// card's stored-length expectation. Indicates a host bug.
    LengthError,
    /// Anything else -- surfaced as opaque SW for the caller.
    Other(u16),
}

/// Outcome of a `RESET RETRY COUNTER` (PUK-driven unblock) round
/// trip.
///
/// On `Ok`, the target PIN's retry counter is reset to its max
/// AND the PIN's reference value has been replaced with the
/// caller-supplied `new_pin`. The card is **not** left in a
/// PIN-presentation-satisfied state -- callers must VERIFY the new
/// PIN before any PIN-protected operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnblockOutcome {
    /// `SW = 0x9000` -- PUK accepted, target PIN reset to the new
    /// value, PIN's retry counter back to its maximum.
    Ok,
    /// `SW = 0x63CX` -- PUK was wrong, `X` retries left on the PUK
    /// itself. When `X = 0` the next failure exhausts the PUK try
    /// counter and the card becomes permanently unrecoverable
    /// (DVV reissue required).
    WrongPuk {
        /// Number of PUK attempts remaining before the card
        /// becomes unrecoverable (the PUK try counter is
        /// `X` after the failure).
        retries_left: PinRetries,
    },
    /// `SW = 0x6983` -- the PUK itself is blocked. No software
    /// recovery; the card is dead.
    PukLocked,
    /// `SW = 0x6984` -- the target PIN's unblocking counter is
    /// exhausted, *or* the PUK's try/usage counter has reached
    /// zero. Both terminal -- card needs DVV reissue.
    Invalidated,
    /// `SW = 0x6700` -- Lc / data-field length mismatch.
    /// Indicates a host bug.
    LengthError,
    /// Anything else -- surface as opaque SW for the caller.
    Other(u16),
}

// `reset_retry_counter` / `unblock_pin1` are methods on [`PinOps`].
// See the trait definition above.

/// Decode the RESET RETRY COUNTER response status word.
#[must_use]
pub const fn classify_reset_retry_sw(sw: StatusWord) -> UnblockOutcome {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "catch-and-wrap: UnblockOutcome::Other(u16) absorbs unenumerated card status words verbatim; enumerating every StatusWord variant would duplicate the StatusWord::Other(u16) escape hatch already documented on the source enum."
    )]
    match sw {
        StatusWord::Success => UnblockOutcome::Ok,
        StatusWord::PinIncorrect { retries } => UnblockOutcome::WrongPuk {
            retries_left: retries,
        },
        StatusWord::AuthenticationBlocked => UnblockOutcome::PukLocked,
        StatusWord::ReferenceDataInvalidated => UnblockOutcome::Invalidated,
        StatusWord::WrongLength => UnblockOutcome::LengthError,
        other => UnblockOutcome::Other(other.as_u16()),
    }
}

/// Decode the counter-safe PUK retry-query response.
#[must_use]
pub const fn classify_puk_status_sw(sw: StatusWord) -> PukStatus {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "PukStatus::Other preserves unenumerated card status words."
    )]
    match sw {
        StatusWord::PinIncorrect { retries } => PukStatus::Remaining(retries),
        StatusWord::AuthenticationFailed => PukStatus::NoInfo,
        StatusWord::AuthenticationBlocked => PukStatus::Locked,
        StatusWord::ReferenceDataInvalidated => PukStatus::Invalidated,
        other => PukStatus::Other(other.as_u16()),
    }
}

/// Decode the CHANGE REFERENCE DATA response status word.
#[must_use]
pub const fn classify_change_pin_sw(sw: StatusWord) -> ChangePinOutcome {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "catch-and-wrap: ChangePinOutcome::Other(u16) absorbs unenumerated card status words verbatim; enumerating every StatusWord variant would duplicate the StatusWord::Other(u16) escape hatch already documented on the source enum."
    )]
    match sw {
        StatusWord::Success => ChangePinOutcome::Ok,
        StatusWord::PinIncorrect { retries } => ChangePinOutcome::WrongCurrentPin {
            retries_left: retries,
        },
        StatusWord::AuthenticationBlocked | StatusWord::ReferenceDataInvalidated => {
            ChangePinOutcome::Locked
        }
        StatusWord::WrongLength => ChangePinOutcome::LengthError,
        other => ChangePinOutcome::Other(other.as_u16()),
    }
}

// `pin_status` is a method on [`PinOps`]. See the trait definition
// above.

/// One credential's wire block under `scheme`.
///
/// The citizen card compares a block padded to the stored length
/// with [`PIN_PAD_BYTE`]; the organization card compares the typed
/// digits at their own length, because its EF.AOD publishes no
/// padding and the S1 v3.0 §3.5.1.1 rule makes any other length a
/// failed -- and counted -- comparison.
fn credential_block<TE>(
    scheme: PinReferenceScheme,
    minimum: usize,
    stored: usize,
    ascii: &[u8],
) -> Result<Vec<u8>, AuthError<TE>> {
    match scheme {
        PinReferenceScheme::Citizen => {
            PinPolicyCheck::validate_ascii(ascii, minimum, stored)?;
            let mut padded = vec![PIN_PAD_BYTE; stored];
            #[expect(
                clippy::indexing_slicing,
                reason = "validate_ascii above proves ascii.len() in [minimum, stored]; padded was allocated at length stored, so padded[..ascii.len()] is in-bounds."
            )]
            padded[..ascii.len()].copy_from_slice(ascii);
            Ok(padded)
        }
        PinReferenceScheme::Organizational => {
            PinPolicyCheck::validate_ascii(ascii, minimum, ORGANIZATIONAL_PIN_MAX_LENGTH)?;
            Ok(ascii.to_vec())
        }
    }
}

/// Send the counter-safe PIN1 VERIFY status probe under `scheme`
/// and hand back the raw status word for scheme resolution.
fn reference_probe_sw<T: CardTransport>(
    transport: &mut T,
    scheme: PinReferenceScheme,
) -> Result<StatusWord, AuthError<TxError<T>>> {
    let apdu = commands::Verify {
        class: ApduClass::Plain,
        mode: commands::VerifyMode::Verify,
        slot: PinSlot::Pin1,
        scheme,
        data: commands::VerifyData::Probe,
    }
    .into_apdu();
    let r = transport
        .transmit(apdu.as_bytes())
        .map_err(AuthError::Transport)?;
    Ok(r.status_word())
}

/// Decode the VERIFY (status-check) response status word.
#[must_use]
pub const fn classify_pin_status_sw(sw: StatusWord) -> PinStatus {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "catch-and-wrap: PinStatus::Other(u16) absorbs unenumerated card status words verbatim; enumerating every StatusWord variant would duplicate the StatusWord::Other(u16) escape hatch already documented on the source enum."
    )]
    match sw {
        StatusWord::Success => PinStatus::Verified,
        StatusWord::PinIncorrect { retries } => PinStatus::Remaining(retries),
        StatusWord::AuthenticationFailed => PinStatus::NoInfo,
        StatusWord::AuthenticationBlocked | StatusWord::ReferenceDataInvalidated => {
            PinStatus::Locked
        }
        other => PinStatus::Other(other.as_u16()),
    }
}

/// Decode the VERIFY response status word into an outcome. Public
/// so other paths (e.g. signing) can classify a PIN-state status
/// word they get back from an unrelated operation.
#[must_use]
pub const fn classify_verify_sw(sw: StatusWord) -> VerifyOutcome {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "catch-and-wrap: VerifyOutcome::Other(u16) absorbs unenumerated card status words verbatim; enumerating every StatusWord variant would duplicate the StatusWord::Other(u16) escape hatch already documented on the source enum."
    )]
    match sw {
        StatusWord::Success => VerifyOutcome::Ok,
        StatusWord::PinIncorrect { retries } => VerifyOutcome::WrongPin {
            retries_left: retries,
        },
        StatusWord::AuthenticationBlocked | StatusWord::ReferenceDataInvalidated => {
            VerifyOutcome::Locked
        }
        other => VerifyOutcome::Other(other.as_u16()),
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::atr::{Atr, AtrError, MINIMAL_DIRECT_ATR};
    use crate::transport::{CommandApdu, ResponseApdu, TransportOutcome};

    struct MockTx {
        expected: Vec<u8>,
        response: ResponseApdu,
        seen: bool,
    }
    impl CardTransport for MockTx {
        type Error = String;
        fn transmit_outcome(
            &mut self,
            apdu: &CommandApdu,
        ) -> Result<TransportOutcome, Self::Error> {
            assert_eq!(apdu.as_bytes(), self.expected.as_slice(), "APDU mismatch");
            self.seen = true;
            Ok(TransportOutcome::Response(self.response.clone()))
        }
        fn atr(&self) -> Result<Atr, AtrError> {
            Atr::new(MINIMAL_DIRECT_ATR)
        }
    }

    fn ok() -> ResponseApdu {
        ResponseApdu {
            body: vec![],
            sw1: 0x90,
            sw2: 0x00,
        }
    }
    fn sw(sw1: u8, sw2: u8) -> ResponseApdu {
        ResponseApdu {
            body: vec![],
            sw1,
            sw2,
        }
    }
    fn pb<const N: usize>(bytes: &[u8; N]) -> PinBytes {
        PinBytes::try_from(*bytes).expect("valid test PIN")
    }

    /// Multi-step transport: each transmit must match the next
    /// scripted request and answers with its paired response.
    struct SteppedTx {
        script: Vec<(Vec<u8>, ResponseApdu)>,
        cursor: usize,
    }
    impl CardTransport for SteppedTx {
        type Error = String;
        fn transmit_outcome(
            &mut self,
            apdu: &CommandApdu,
        ) -> Result<TransportOutcome, Self::Error> {
            let Some((expected, response)) = self.script.get(self.cursor) else {
                return Err(format!("script exhausted at step {}", self.cursor));
            };
            assert_eq!(
                apdu.as_bytes(),
                expected.as_slice(),
                "APDU mismatch at step {}",
                self.cursor
            );
            self.cursor = self.cursor.saturating_add(1);
            Ok(TransportOutcome::Response(response.clone()))
        }
        fn atr(&self) -> Result<Atr, AtrError> {
            Atr::new(MINIMAL_DIRECT_ATR)
        }
    }

    /// APDU bytes shared by the scheme tests, named once here so
    /// no bare hex appears in the expected wire vectors.
    const PLAIN_CLASS: u8 = 0x00;
    /// ISO 7816-4 VERIFY instruction.
    const VERIFY_INSTRUCTION: u8 = 0x20;
    /// VERIFY P1: verify mode.
    const VERIFY_MODE: u8 = 0x00;
    /// Lc of the empty-data probe form (S1 v4.2 §3.5.1.1).
    const PROBE_LC: u8 = 0x00;
    /// SW1 of the `63Cx` retry-counter family.
    const SW1_RETRY_COUNTER: u8 = 0x63;
    /// SW2: three retries left.
    const SW2_THREE_RETRIES: u8 = 0xC3;
    /// SW2: five retries left.
    const SW2_FIVE_RETRIES: u8 = 0xC5;
    /// SW1 of the `6Axx` wrong-parameters family.
    const SW1_WRONG_PARAMETERS: u8 = 0x6A;
    /// SW2: referenced data not found (with SW1 `6A`).
    const SW2_REFERENCE_NOT_FOUND: u8 = 0x88;
    /// SW2: incorrect P1-P2 (with SW1 `6A`).
    const SW2_INCORRECT_P1_P2: u8 = 0x86;

    fn citizen_pin1_probe() -> Vec<u8> {
        vec![
            PLAIN_CLASS,
            VERIFY_INSTRUCTION,
            VERIFY_MODE,
            PIN1_REFERENCE_PKCS15,
            PROBE_LC,
        ]
    }

    fn organizational_pin1_probe() -> Vec<u8> {
        vec![
            PLAIN_CLASS,
            VERIFY_INSTRUCTION,
            VERIFY_MODE,
            PIN1_REFERENCE_ORGANIZATIONAL,
            PROBE_LC,
        ]
    }

    #[test]
    fn resolve_scheme_stops_at_citizen_when_reference_answers() {
        // Citizen PIN1 probe answers a retry count: citizen
        // numbering is live, no second probe goes out.
        let mut tx = SteppedTx {
            script: vec![(
                citizen_pin1_probe(),
                sw(SW1_RETRY_COUNTER, SW2_THREE_RETRIES),
            )],
            cursor: 0,
        };
        let scheme = tx
            .resolve_pin_reference_scheme()
            .expect("resolution succeeds");
        assert_eq!(scheme, PinReferenceScheme::Citizen);
        assert_eq!(tx.cursor, tx.script.len());
    }

    #[test]
    fn resolve_scheme_finds_organizational_numbering() {
        // Citizen PIN1 reference is absent (SW=6A88); the S4-2
        // PIN AUTH reference answers a retry count.
        let mut tx = SteppedTx {
            script: vec![
                (
                    citizen_pin1_probe(),
                    sw(SW1_WRONG_PARAMETERS, SW2_REFERENCE_NOT_FOUND),
                ),
                (
                    organizational_pin1_probe(),
                    sw(SW1_RETRY_COUNTER, SW2_FIVE_RETRIES),
                ),
            ],
            cursor: 0,
        };
        let scheme = tx
            .resolve_pin_reference_scheme()
            .expect("resolution succeeds");
        assert_eq!(scheme, PinReferenceScheme::Organizational);
        assert_eq!(tx.cursor, tx.script.len());
    }

    #[test]
    fn resolve_scheme_defaults_to_citizen_when_neither_answers() {
        let mut tx = SteppedTx {
            script: vec![
                (
                    citizen_pin1_probe(),
                    sw(SW1_WRONG_PARAMETERS, SW2_REFERENCE_NOT_FOUND),
                ),
                (
                    organizational_pin1_probe(),
                    sw(SW1_WRONG_PARAMETERS, SW2_INCORRECT_P1_P2),
                ),
            ],
            cursor: 0,
        };
        let scheme = tx
            .resolve_pin_reference_scheme()
            .expect("resolution succeeds");
        assert_eq!(scheme, PinReferenceScheme::Citizen);
        assert_eq!(tx.cursor, tx.script.len());
    }

    #[test]
    fn organizational_pin1_verify_sends_typed_length() {
        // The organization card compares the typed digits at their
        // own length: no padding, Lc = digit count (S1 v3.0
        // §3.5.1.1; the card's EF.AOD publishes no padding).
        const TYPED_LENGTH: u8 = 0x04;
        let mut expected = vec![
            PLAIN_CLASS,
            VERIFY_INSTRUCTION,
            VERIFY_MODE,
            PIN1_REFERENCE_ORGANIZATIONAL,
            TYPED_LENGTH,
        ];
        expected.extend_from_slice(b"1234");
        let mut tx = MockTx {
            expected,
            response: ok(),
            seen: false,
        };
        let outcome = tx
            .verify_pin_with_scheme(
                PinSlot::Pin1,
                PinReferenceScheme::Organizational,
                pb(b"1234"),
            )
            .expect("organizational PIN1 verify succeeds");
        assert_eq!(outcome, VerifyOutcome::Ok);
        assert!(tx.seen);
    }

    #[test]
    fn organizational_pin2_verify_sends_typed_length() {
        const TYPED_LENGTH: u8 = 0x06;
        let mut expected = vec![
            PLAIN_CLASS,
            VERIFY_INSTRUCTION,
            VERIFY_MODE,
            PIN2_REFERENCE_ORGANIZATIONAL,
            TYPED_LENGTH,
        ];
        expected.extend_from_slice(b"123456");
        let mut tx = MockTx {
            expected,
            response: ok(),
            seen: false,
        };
        let outcome = tx
            .verify_pin_with_scheme(
                PinSlot::Pin2,
                PinReferenceScheme::Organizational,
                pb(b"123456"),
            )
            .expect("organizational PIN2 verify succeeds");
        assert_eq!(outcome, VerifyOutcome::Ok);
        assert!(tx.seen);
    }

    #[test]
    fn organizational_change_sends_bare_concatenation() {
        // CHANGE REFERENCE DATA on the organization card: current
        // and new PIN concatenated at their typed lengths (Idemia
        // organizational cards specification §4.1.7, boundaries
        // 2*Lmin..2*Lmax).
        const CHANGE_REFERENCE_DATA_INSTRUCTION: u8 = 0x24;
        const REPLACE_MODE: u8 = 0x00;
        const PAIR_LENGTH: u8 = 0x0A;
        let mut expected = vec![
            PLAIN_CLASS,
            CHANGE_REFERENCE_DATA_INSTRUCTION,
            REPLACE_MODE,
            PIN1_REFERENCE_ORGANIZATIONAL,
            PAIR_LENGTH,
        ];
        expected.extend_from_slice(b"1234");
        expected.extend_from_slice(b"567890");
        let mut tx = MockTx {
            expected,
            response: ok(),
            seen: false,
        };
        let outcome = tx
            .change_pin_with_scheme(
                PinSlot::Pin1,
                PinReferenceScheme::Organizational,
                pb(b"1234"),
                pb(b"567890"),
            )
            .expect("organizational change succeeds");
        assert_eq!(outcome, ChangePinOutcome::Ok);
        assert!(tx.seen);
    }

    #[test]
    fn organizational_unblock_verifies_puk_then_resets() {
        // The organizational unblock is two commands: VERIFY of the
        // PIN PUK object itself (S4-2 v4.0 SE#03), then RESET RETRY
        // COUNTER with P1=02 carrying only the new PIN (Idemia
        // organizational cards specification §4.1.6).
        const RESET_RETRY_COUNTER_INSTRUCTION: u8 = 0x2C;
        const NEW_REFERENCE_DATA_MODE: u8 = 0x02;
        const CODE_LENGTH: u8 = 0x08;
        const NEW_PIN_LENGTH: u8 = 0x04;
        let mut verify_step = vec![
            PLAIN_CLASS,
            VERIFY_INSTRUCTION,
            VERIFY_MODE,
            PUK_REFERENCE_ORGANIZATIONAL,
            CODE_LENGTH,
        ];
        verify_step.extend_from_slice(b"12345678");
        let mut reset_step = vec![
            PLAIN_CLASS,
            RESET_RETRY_COUNTER_INSTRUCTION,
            NEW_REFERENCE_DATA_MODE,
            PIN1_REFERENCE_ORGANIZATIONAL,
            NEW_PIN_LENGTH,
        ];
        reset_step.extend_from_slice(b"1234");
        let mut tx = SteppedTx {
            script: vec![(verify_step, ok()), (reset_step, ok())],
            cursor: 0,
        };
        let outcome = tx
            .reset_retry_counter_with_scheme(
                PinSlot::Pin1,
                PinReferenceScheme::Organizational,
                pb(b"12345678"),
                pb(b"1234"),
            )
            .expect("organizational unblock succeeds");
        assert_eq!(outcome, UnblockOutcome::Ok);
        assert_eq!(tx.cursor, tx.script.len());
    }

    #[test]
    fn organizational_unblock_stops_on_wrong_code() {
        // A refused unblock credential ends the flow before any
        // RESET RETRY COUNTER goes out.
        const CODE_LENGTH: u8 = 0x08;
        let mut verify_step = vec![
            PLAIN_CLASS,
            VERIFY_INSTRUCTION,
            VERIFY_MODE,
            PUK_REFERENCE_ORGANIZATIONAL,
            CODE_LENGTH,
        ];
        verify_step.extend_from_slice(b"12345678");
        let mut tx = SteppedTx {
            script: vec![(verify_step, sw(SW1_RETRY_COUNTER, SW2_THREE_RETRIES))],
            cursor: 0,
        };
        let outcome = tx
            .reset_retry_counter_with_scheme(
                PinSlot::Pin1,
                PinReferenceScheme::Organizational,
                pb(b"12345678"),
                pb(b"1234"),
            )
            .expect("refusal classifies, does not error");
        assert_eq!(
            outcome,
            UnblockOutcome::WrongPuk {
                retries_left: PinRetries::from_nibble(3).expect("valid retry nibble")
            }
        );
        assert_eq!(tx.cursor, tx.script.len());
    }

    #[test]
    fn organizational_puk_probe_reads_retry_counter() {
        let mut tx = SteppedTx {
            script: vec![(
                vec![
                    PLAIN_CLASS,
                    VERIFY_INSTRUCTION,
                    VERIFY_MODE,
                    PUK_REFERENCE_ORGANIZATIONAL,
                    PROBE_LC,
                ],
                sw(SW1_RETRY_COUNTER, SW2_FIVE_RETRIES),
            )],
            cursor: 0,
        };
        let status = tx
            .puk_status_with_scheme(PinReferenceScheme::Organizational)
            .expect("organizational PUK probe succeeds");
        assert_eq!(
            status,
            PukStatus::Remaining(PinRetries::from_nibble(5).expect("valid retry nibble"))
        );
        assert_eq!(tx.cursor, tx.script.len());
    }

    #[test]
    fn pin1_padded_to_stored_length() {
        // ASCII "1234" + 8 bytes 0x00 padding = 12 bytes.
        let mut expected = vec![0x00, 0x20, 0x00, 0x11, 0x0C];
        expected.extend_from_slice(b"1234");
        expected.extend_from_slice(&[0x00; 8]);
        let mut tx = MockTx {
            expected,
            response: ok(),
            seen: false,
        };
        let outcome = tx
            .verify_pin1(pb(b"1234"))
            .expect("padded PIN1 verify succeeds");
        assert_eq!(outcome, VerifyOutcome::Ok);
        assert!(tx.seen);
    }

    #[test]
    fn pin2_uses_reference_82() {
        let mut expected = vec![0x00, 0x20, 0x00, 0x82, 0x0C];
        expected.extend_from_slice(b"123456");
        expected.extend_from_slice(&[0x00; 6]);
        let mut tx = MockTx {
            expected,
            response: ok(),
            seen: false,
        };
        let outcome = tx
            .verify_pin(PinSlot::Pin2, pb(b"123456"))
            .expect("PIN2 verify succeeds");
        assert_eq!(outcome, VerifyOutcome::Ok);
        assert!(tx.seen);
    }

    #[test]
    fn puk_status_probe_returns_counter_without_credential_data() {
        const PLAIN_CLASS: u8 = 0x00;
        const GET_DATA_INSTRUCTION: u8 = 0xCB;
        const GET_DATA_P1: u8 = 0x00;
        const GET_DATA_P2: u8 = 0xFF;
        const PIN_TEMPLATE_LENGTH: u8 = 0x05;
        const PIN_TEMPLATE_TAG: u8 = 0xA0;
        const PIN_TEMPLATE_VALUE_LENGTH: u8 = 0x03;
        const PIN_REFERENCE_TAG: u8 = 0x83;
        const PIN_REFERENCE_LENGTH: u8 = 0x01;
        const PUK_REFERENCE: u8 = 0x83;
        const MAX_RESPONSE_LENGTH: u8 = 0x00;
        const PIN_ATTRIBUTES_TAG_HI: u8 = 0xDF;
        const PIN_ATTRIBUTES_TAG_LO: u8 = 0x21;
        const PIN_ATTRIBUTES_LENGTH: u8 = 0x04;
        const FOUR_RETRIES: u8 = 0x04;
        const UNLIMITED_USAGE: u8 = 0xFF;
        const NO_UNBLOCKING: u8 = 0x00;
        const SUCCESS_STATUS_HI: u8 = 0x90;
        const SUCCESS_STATUS_LO: u8 = 0x00;

        let mut tx = MockTx {
            expected: vec![
                PLAIN_CLASS,
                GET_DATA_INSTRUCTION,
                GET_DATA_P1,
                GET_DATA_P2,
                PIN_TEMPLATE_LENGTH,
                PIN_TEMPLATE_TAG,
                PIN_TEMPLATE_VALUE_LENGTH,
                PIN_REFERENCE_TAG,
                PIN_REFERENCE_LENGTH,
                PUK_REFERENCE,
                MAX_RESPONSE_LENGTH,
            ],
            response: ResponseApdu {
                body: vec![
                    PIN_ATTRIBUTES_TAG_HI,
                    PIN_ATTRIBUTES_TAG_LO,
                    PIN_ATTRIBUTES_LENGTH,
                    FOUR_RETRIES,
                    UNLIMITED_USAGE,
                    NO_UNBLOCKING,
                    NO_UNBLOCKING,
                ],
                sw1: SUCCESS_STATUS_HI,
                sw2: SUCCESS_STATUS_LO,
            },
            seen: false,
        };
        let outcome = tx.puk_status().expect("PUK counter probe succeeds");
        let four = PinRetries::from_nibble(4).expect("nibble");
        assert_eq!(outcome, PukStatus::Remaining(four));
        assert!(tx.seen);
    }

    #[test]
    fn wrong_pin_with_retries_classified() {
        let mut expected = vec![0x00, 0x20, 0x00, 0x11, 0x0C];
        expected.extend_from_slice(b"9999");
        expected.extend_from_slice(&[0x00; 8]);
        let mut tx = MockTx {
            expected,
            response: sw(0x63, 0xC2),
            seen: false,
        };
        let outcome = tx
            .verify_pin1(pb(b"9999"))
            .expect("wrong-PIN verify still returns an outcome");
        let two = PinRetries::from_nibble(2).expect("nibble");
        assert_eq!(outcome, VerifyOutcome::WrongPin { retries_left: two });
    }

    #[test]
    fn locked_sw_classified() {
        let mut expected = vec![0x00, 0x20, 0x00, 0x11, 0x0C];
        expected.extend_from_slice(b"1234");
        expected.extend_from_slice(&[0x00; 8]);
        let mut tx = MockTx {
            expected,
            response: sw(0x69, 0x83),
            seen: false,
        };
        let outcome = tx
            .verify_pin1(pb(b"1234"))
            .expect("locked-card verify still returns an outcome");
        assert_eq!(outcome, VerifyOutcome::Locked);
    }

    #[test]
    fn other_sw_passes_through() {
        assert_eq!(
            classify_verify_sw(StatusWord::from_u16(0x6A82)),
            VerifyOutcome::Other(0x6A82)
        );
        assert_eq!(
            classify_verify_sw(StatusWord::from_u16(0x9000)),
            VerifyOutcome::Ok
        );
        let zero = PinRetries::from_nibble(0).expect("nibble");
        assert_eq!(
            classify_verify_sw(StatusWord::from_u16(0x63C0)),
            VerifyOutcome::WrongPin { retries_left: zero }
        );
    }

    #[test]
    fn puk_status_classifies_terminal_states() {
        const AUTHENTICATION_BLOCKED: u16 = 0x6983;
        const REFERENCE_DATA_INVALIDATED: u16 = 0x6984;

        assert_eq!(
            classify_puk_status_sw(StatusWord::from_u16(AUTHENTICATION_BLOCKED)),
            PukStatus::Locked
        );
        assert_eq!(
            classify_puk_status_sw(StatusWord::from_u16(REFERENCE_DATA_INVALIDATED)),
            PukStatus::Invalidated
        );
    }

    struct ShouldNotTransmitTx;
    impl CardTransport for ShouldNotTransmitTx {
        type Error = String;
        fn transmit_outcome(
            &mut self,
            _apdu: &CommandApdu,
        ) -> Result<TransportOutcome, Self::Error> {
            panic!("transport must not be touched on local-policy rejection");
        }
        fn atr(&self) -> Result<Atr, AtrError> {
            Atr::new(MINIMAL_DIRECT_ATR)
        }
    }

    #[test]
    fn pin2_below_role_minimum_rejected_locally() {
        let mut tx = ShouldNotTransmitTx;
        let err = tx
            .verify_pin(PinSlot::Pin2, pb(b"1234"))
            .expect_err("four-digit PIN2 is rejected locally");
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "PinPolicyReason is #[non_exhaustive]; an explicit catch-all is required by the language to match nested non-WrongLength variants."
        )]
        match err {
            AuthError::PinPolicy(PinPolicyReason::WrongLength { min, max }) => {
                assert_eq!(min, PIN2_MIN_LENGTH);
                assert_eq!(max, PIN2_STORED_LENGTH);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn change_pin1_apdu_layout_4_to_4_digit() {
        // change_pin is policy-light: 1234 -> 4321 is wire-shape-
        // valid and the card sees the APDU. PIN quality is the
        // citizen's call -- lib-core ships no strength policy.
        // 00 24 00 11 18  <12B current-padded || 12B new-padded>
        let mut expected = vec![0x00, 0x24, 0x00, 0x11, 0x18];
        expected.extend_from_slice(b"1234");
        expected.extend_from_slice(&[0x00; 8]);
        expected.extend_from_slice(b"4321");
        expected.extend_from_slice(&[0x00; 8]);
        let mut tx = MockTx {
            expected,
            response: ok(),
            seen: false,
        };
        let outcome = tx
            .change_pin1(pb(b"1234"), pb(b"4321"))
            .expect("PIN1 change succeeds");
        assert_eq!(outcome, ChangePinOutcome::Ok);
        assert!(tx.seen);
    }

    #[test]
    fn change_pin1_wrong_current_classified() {
        let mut expected = vec![0x00, 0x24, 0x00, 0x11, 0x18];
        expected.extend_from_slice(b"9999");
        expected.extend_from_slice(&[0x00; 8]);
        expected.extend_from_slice(b"4321");
        expected.extend_from_slice(&[0x00; 8]);
        let mut tx = MockTx {
            expected,
            response: sw(0x63, 0xC2),
            seen: false,
        };
        let outcome = tx
            .change_pin1(pb(b"9999"), pb(b"4321"))
            .expect("wrong-current-PIN change still returns an outcome");
        let two = PinRetries::from_nibble(2).expect("nibble");
        assert_eq!(
            outcome,
            ChangePinOutcome::WrongCurrentPin { retries_left: two }
        );
    }

    #[test]
    fn change_pin1_accepts_weak_new_pin() {
        // 1234 -> 1234 same-as-old is wire-shape-valid; lib-core
        // doesn't reject it -- no strength policy in the library.
        let mut expected = vec![0x00, 0x24, 0x00, 0x11, 0x18];
        expected.extend_from_slice(b"1234");
        expected.extend_from_slice(&[0x00; 8]);
        expected.extend_from_slice(b"1234");
        expected.extend_from_slice(&[0x00; 8]);
        let mut tx = MockTx {
            expected,
            response: ok(),
            seen: false,
        };
        let outcome = tx
            .change_pin1(pb(b"1234"), pb(b"1234"))
            .expect("weak new PIN is accepted by the library");
        assert_eq!(outcome, ChangePinOutcome::Ok);
    }

    #[test]
    fn change_pin_sw_classification() {
        assert_eq!(
            classify_change_pin_sw(StatusWord::from_u16(0x9000)),
            ChangePinOutcome::Ok
        );
        let three = PinRetries::from_nibble(3).expect("nibble");
        assert_eq!(
            classify_change_pin_sw(StatusWord::from_u16(0x63C3)),
            ChangePinOutcome::WrongCurrentPin {
                retries_left: three
            }
        );
        assert_eq!(
            classify_change_pin_sw(StatusWord::from_u16(0x6983)),
            ChangePinOutcome::Locked
        );
        assert_eq!(
            classify_change_pin_sw(StatusWord::from_u16(0x6700)),
            ChangePinOutcome::LengthError
        );
        assert_eq!(
            classify_change_pin_sw(StatusWord::from_u16(0x6A82)),
            ChangePinOutcome::Other(0x6A82)
        );
    }

    #[test]
    fn pin_status_sends_empty_lc_verify() {
        // 00 20 00 11 00 -- empty Lc form, no body. Counter-safe.
        let mut tx = MockTx {
            expected: vec![0x00, 0x20, 0x00, 0x11, 0x00],
            response: sw(0x63, 0xC3),
            seen: false,
        };
        let status = tx
            .pin_status(PinSlot::Pin1)
            .expect("PIN1 status query succeeds");
        let three = PinRetries::from_nibble(3).expect("nibble");
        assert_eq!(status, PinStatus::Remaining(three));
        assert!(tx.seen);
    }

    #[test]
    fn pin_status_verified() {
        let mut tx = MockTx {
            expected: vec![0x00, 0x20, 0x00, 0x11, 0x00],
            response: ok(),
            seen: false,
        };
        let status = tx
            .pin_status(PinSlot::Pin1)
            .expect("PIN1 status query succeeds");
        assert_eq!(status, PinStatus::Verified);
    }

    #[test]
    fn pin_status_pin2_uses_reference_82() {
        let mut tx = MockTx {
            expected: vec![0x00, 0x20, 0x00, 0x82, 0x00],
            response: sw(0x63, 0xC2),
            seen: false,
        };
        let status = tx
            .pin_status(PinSlot::Pin2)
            .expect("PIN2 status query succeeds");
        let two = PinRetries::from_nibble(2).expect("nibble");
        assert_eq!(status, PinStatus::Remaining(two));
    }

    #[test]
    fn pin_status_sw_classification() {
        let five = PinRetries::from_nibble(5).expect("nibble");
        let zero = PinRetries::from_nibble(0).expect("nibble");
        assert_eq!(
            classify_pin_status_sw(StatusWord::from_u16(0x9000)),
            PinStatus::Verified
        );
        assert_eq!(
            classify_pin_status_sw(StatusWord::from_u16(0x63C5)),
            PinStatus::Remaining(five)
        );
        assert_eq!(
            classify_pin_status_sw(StatusWord::from_u16(0x63C0)),
            PinStatus::Remaining(zero)
        );
        assert_eq!(
            classify_pin_status_sw(StatusWord::from_u16(0x6300)),
            PinStatus::NoInfo
        );
        assert_eq!(
            classify_pin_status_sw(StatusWord::from_u16(0x6983)),
            PinStatus::Locked
        );
        assert_eq!(
            classify_pin_status_sw(StatusWord::from_u16(0x6984)),
            PinStatus::Locked
        );
        assert_eq!(
            classify_pin_status_sw(StatusWord::from_u16(0x6A82)),
            PinStatus::Other(0x6A82)
        );
    }

    #[test]
    fn unblock_pin1_apdu_layout_8puk_4pin() {
        // 00 2C 00 11 18  <12B PUK-padded || 12B new-PIN-padded>
        let mut expected = vec![0x00, 0x2C, 0x00, 0x11, 0x18];
        expected.extend_from_slice(b"12345678");
        expected.extend_from_slice(&[0x00; 4]);
        expected.extend_from_slice(b"4321");
        expected.extend_from_slice(&[0x00; 8]);
        let mut tx = MockTx {
            expected,
            response: ok(),
            seen: false,
        };
        let outcome = tx
            .unblock_pin1(pb(b"12345678"), pb(b"4321"))
            .expect("PIN1 unblock succeeds");
        assert_eq!(outcome, UnblockOutcome::Ok);
        assert!(tx.seen);
    }

    #[test]
    fn unblock_pin1_apdu_layout_12puk_4pin() {
        const PLAIN_CLASS: u8 = 0x00;
        const RESET_RETRY_COUNTER_INSTRUCTION: u8 = 0x2C;
        const RESET_AND_REPLACE_MODE: u8 = 0x00;
        const PADDED_PAIR_LENGTH: u8 = 0x18;
        const PAD_BYTE: u8 = 0x00;
        let mut expected = vec![
            PLAIN_CLASS,
            RESET_RETRY_COUNTER_INSTRUCTION,
            RESET_AND_REPLACE_MODE,
            PIN1_REFERENCE_PKCS15,
            PADDED_PAIR_LENGTH,
        ];
        // A twelve-digit PUK fills the stored block with no padding.
        expected.extend_from_slice(b"490712345678");
        expected.extend_from_slice(b"4907");
        expected.extend_from_slice(&[PAD_BYTE; 8]);
        let mut tx = MockTx {
            expected,
            response: ok(),
            seen: false,
        };
        let outcome = tx
            .unblock_pin1(pb(b"490712345678"), pb(b"4907"))
            .expect("twelve-digit PUK reaches PIN1 unblock");
        assert_eq!(outcome, UnblockOutcome::Ok);
        assert!(tx.seen);
    }

    #[test]
    fn unblock_pin1_wrong_puk_classified() {
        let mut expected = vec![0x00, 0x2C, 0x00, 0x11, 0x18];
        expected.extend_from_slice(b"99999999");
        expected.extend_from_slice(&[0x00; 4]);
        expected.extend_from_slice(b"4321");
        expected.extend_from_slice(&[0x00; 8]);
        let mut tx = MockTx {
            expected,
            response: sw(0x63, 0xC4),
            seen: false,
        };
        let outcome = tx
            .unblock_pin1(pb(b"99999999"), pb(b"4321"))
            .expect("wrong-PUK unblock still returns an outcome");
        let four = PinRetries::from_nibble(4).expect("nibble");
        assert_eq!(outcome, UnblockOutcome::WrongPuk { retries_left: four });
    }

    #[test]
    fn unblock_pin1_short_puk_rejected_locally() {
        let mut tx = ShouldNotTransmitTx;
        // 6 < PUK_MIN_LENGTH=8
        let err = tx
            .unblock_pin1(pb(b"123456"), pb(b"4321"))
            .expect_err("short PUK is rejected locally");
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "PinPolicyReason is #[non_exhaustive]; an explicit catch-all is required by the language to match nested non-WrongLength variants."
        )]
        match err {
            AuthError::PinPolicy(PinPolicyReason::WrongLength { min, max }) => {
                assert_eq!(min, PUK_MIN_LENGTH);
                assert_eq!(max, PUK_MAX_LENGTH);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn unblock_pin1_seven_digit_activation_code_rejected_locally() {
        let mut tx = ShouldNotTransmitTx;
        // Seven digits is the new-card activation code, not a PUK.
        let err = tx
            .unblock_pin1(pb(b"1234567"), pb(b"4321"))
            .expect_err("short PUK is rejected locally");
        assert!(matches!(
            err,
            AuthError::PinPolicy(PinPolicyReason::WrongLength {
                min: PUK_MIN_LENGTH,
                max: PUK_MAX_LENGTH
            })
        ));
    }

    #[test]
    fn reset_retry_sw_classification() {
        assert_eq!(
            classify_reset_retry_sw(StatusWord::from_u16(0x9000)),
            UnblockOutcome::Ok
        );
        let three = PinRetries::from_nibble(3).expect("nibble");
        assert_eq!(
            classify_reset_retry_sw(StatusWord::from_u16(0x63C3)),
            UnblockOutcome::WrongPuk {
                retries_left: three
            }
        );
        assert_eq!(
            classify_reset_retry_sw(StatusWord::from_u16(0x6983)),
            UnblockOutcome::PukLocked
        );
        assert_eq!(
            classify_reset_retry_sw(StatusWord::from_u16(0x6984)),
            UnblockOutcome::Invalidated
        );
        assert_eq!(
            classify_reset_retry_sw(StatusWord::from_u16(0x6700)),
            UnblockOutcome::LengthError
        );
        assert_eq!(
            classify_reset_retry_sw(StatusWord::from_u16(0x6A82)),
            UnblockOutcome::Other(0x6A82)
        );
    }

    #[test]
    fn pin_policy_reason_debug_does_not_leak_candidate_length_or_offset() {
        let err_wrong_len: Result<(), AuthError<()>> =
            PinPolicyCheck::validate_ascii(b"12", PIN1_MIN_LENGTH, PIN1_STORED_LENGTH);
        let AuthError::PinPolicy(reason) = err_wrong_len.expect_err("below min length") else {
            panic!("expected PinPolicy");
        };
        let expected_debug = format!(
            "WrongLength {{ min: {}, max: {} }}",
            PIN1_MIN_LENGTH, PIN1_STORED_LENGTH
        );
        assert_eq!(format!("{reason:?}"), expected_debug);

        let err_non_digit: Result<(), AuthError<()>> =
            PinPolicyCheck::validate_ascii(b"12a4", PIN1_MIN_LENGTH, PIN1_STORED_LENGTH);
        let AuthError::PinPolicy(reason_non_digit) = err_non_digit.expect_err("contains non-digit")
        else {
            panic!("expected PinPolicy");
        };
        assert_eq!(format!("{reason_non_digit:?}"), "NonDigit");
    }

    #[test]
    fn pin_policy_reason_display_is_always_shape_only() {
        let wrong_len = PinPolicyReason::WrongLength {
            min: PIN1_MIN_LENGTH,
            max: PIN1_STORED_LENGTH,
        };
        let expected_wrong_len = format!(
            "pin length outside accepted range {}..={}",
            PIN1_MIN_LENGTH, PIN1_STORED_LENGTH
        );
        assert_eq!(wrong_len.to_string(), expected_wrong_len);

        let non_digit = PinPolicyReason::NonDigit;
        assert_eq!(non_digit.to_string(), "pin must contain only ASCII digits");
    }
}
