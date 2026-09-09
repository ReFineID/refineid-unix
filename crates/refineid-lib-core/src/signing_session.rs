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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The signing-session seam between the card layer and a front-end.
//!
//! A batch signer advances one document at a time. The driver never
//! prompts and never blocks on a human: it does the counter-safe work,
//! then hands the front-end exactly one [`SigningStep`] and waits. The
//! front-end -- a native GUI dialog, the browser SCS `reasonCode`, or a
//! PKCS#11 return value -- decides whether to prompt, refuse, or report,
//! and drives the session forward. Keeping the prompt out of the driver
//! is the entire point of this seam.
//!
//! # The retry floor is baked into the transitions
//!
//! Before it would spend a PIN, the driver reads the live retry counter
//! with the side-effect-free probe ([`crate::auth::PinStatus`]) and acts
//! only in the safe band: remaining attempts of five, four, or three.
//!
//! - Three, four, five -> [`SigningStep::NeedsPin`] (or a signature, when
//!   a verified PIN is already held).
//! - One or two -> [`SigningStep::RefusedLowRetries`]. No APDU is sent;
//!   the front-end routes to a trusted terminal or a PUK, and must not
//!   offer another PIN entry. The software refuses to be what walks the
//!   card from two to one to locked.
//! - Zero -> [`SigningStep::Locked`]. Already locked, so there is nothing
//!   to protect; the driver reports the plain truth from the probe rather
//!   than pre-refusing. Recovery needs the PUK.
//!
//! # Convenience windows
//!
//! A verified PIN may be retained so a batch does not prompt per
//! document. PIN1 (authentication) is held for fifteen minutes, refreshed
//! on each use. PIN2 (qualified signature) is held for one minute from
//! entry -- a bounded consent window that comfortably covers a realistic
//! batch yet keeps the signature PIN from being kept alive indefinitely
//! by a stream of signing calls. When the window lapses mid-batch, the
//! next step is a fresh [`SigningStep::NeedsPin`] with progress attached,
//! so the front-end can prompt once and resume where it stopped.
//!
//! # Front-end mapping
//!
//! | [`SigningStep`]              | Native GUI                              | SCS `status`/`reasonCode`     | PKCS#11               |
//! |-----------------------------|-----------------------------------------|-------------------------------|-----------------------|
//! | `Signed` / `Finished`       | advance progress / done                 | `ok`                          | `CKR_OK`              |
//! | `NeedsPin` (`NotCached`)    | "Enter the signature PIN (7 of 20)"     | authentication-needed         | `CKR_USER_NOT_LOGGED_IN` |
//! | `NeedsPin` (card rejected)  | "Wrong PIN -- N attempts left"          | wrong-PIN, N left             | `CKR_PIN_INCORRECT`   |
//! | `NeedsPin` (refused locally)| "That PIN was already refused -- try another or restart" | wrong-PIN | `CKR_PIN_INCORRECT` |
//! | `RefusedLowRetries`         | "Stopped for safety -- N left, use a trusted terminal / order a PUK" | refused | `CKR_PIN_LOCKED` (with N) |
//! | `Locked`                    | "Signature PIN locked -- order a PUK"   | blocked                       | `CKR_PIN_LOCKED`      |

use crate::apdu::status_word::PinRetries;
use crate::auth::PinSlot;
use crate::pin::PinBytes;

/// How far a batch has progressed. Every [`SigningStep`] carries one so a
/// prompt or a report can show position without threading its own counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchProgress {
    /// Documents signed so far.
    pub signed: usize,
    /// Documents in the batch.
    pub total: usize,
}

impl BatchProgress {
    /// Documents not yet signed.
    #[must_use]
    pub const fn remaining(self) -> usize {
        self.total.saturating_sub(self.signed)
    }

    /// Whether every document is signed.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.signed >= self.total
    }
}

/// Why the driver is asking for a PIN. It tunes the front-end's wording;
/// the handling -- prompt, then call [`SigningSession::supply_pin`] -- is
/// the same for all three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinPromptReason {
    /// No verified PIN is held: the first prompt of the session, or the
    /// convenience window lapsed.
    NotCached,
    /// The value passed to the previous [`SigningSession::supply_pin`] was
    /// rejected by the card. The step's `remaining` reflects the
    /// decremented counter.
    PreviousAttemptRejectedByCard,
    /// The value passed to the previous [`SigningSession::supply_pin`] was
    /// already recorded as rejected in this process, so it was refused
    /// locally and never reached the card; the counter is unchanged. A
    /// different value may still be entered -- the same value needs a
    /// process restart, by design.
    PreviousAttemptRefusedLocally,
}

/// The result of advancing a signing session by one step.
///
/// Every variant is an expected branch the front-end must handle; that is
/// why the enum is exhaustive, so a new state cannot be added without the
/// compiler making every front-end account for it. Hard faults -- card
/// removed, transport error, malformed request -- are the `Err` arm of the
/// [`SigningSession`] methods, not a variant here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningStep {
    /// One document was signed and the batch has more to go. Call
    /// [`SigningSession::advance`] again.
    Signed {
        /// Position after this signature.
        progress: BatchProgress,
    },
    /// Every document is signed. Terminal.
    Finished {
        /// Final position (`signed == total`).
        progress: BatchProgress,
    },
    /// A PIN is needed before the next signature, and the card has a safe
    /// retry count. The front-end prompts and calls
    /// [`SigningSession::supply_pin`].
    NeedsPin {
        /// Which PIN: `Pin2` for a qualified document signature, `Pin1`
        /// for an authentication signature.
        slot: PinSlot,
        /// Position; the batch has not moved.
        progress: BatchProgress,
        /// Attempts left before lockout (three, four, or five here).
        remaining: PinRetries,
        /// What to tell the user.
        reason: PinPromptReason,
    },
    /// Refused locally because only one or two attempts remain. No APDU
    /// was sent. The front-end must route to a trusted terminal or a PUK
    /// and must not offer another PIN entry.
    RefusedLowRetries {
        /// Which PIN is near lockout.
        slot: PinSlot,
        /// Position; the batch has not moved.
        progress: BatchProgress,
        /// Attempts left (one or two).
        remaining: PinRetries,
    },
    /// The PIN is blocked (zero attempts). Recovery needs the PUK.
    Locked {
        /// Which PIN is blocked.
        slot: PinSlot,
        /// Position; the batch has not moved.
        progress: BatchProgress,
    },
}

impl SigningStep {
    /// The batch position this step reports, whichever variant it is.
    #[must_use]
    pub const fn progress(&self) -> BatchProgress {
        match *self {
            Self::Signed { progress }
            | Self::Finished { progress }
            | Self::NeedsPin { progress, .. }
            | Self::RefusedLowRetries { progress, .. }
            | Self::Locked { progress, .. } => progress,
        }
    }

    /// The PIN slot this step concerns, or `None` for a signature or a
    /// completed batch.
    #[must_use]
    pub const fn pin_slot(&self) -> Option<PinSlot> {
        match *self {
            Self::NeedsPin { slot, .. }
            | Self::RefusedLowRetries { slot, .. }
            | Self::Locked { slot, .. } => Some(slot),
            Self::Signed { .. } | Self::Finished { .. } => None,
        }
    }
}

/// The pull-model contract a front-end drives.
///
/// The driver owns the card, the convenience cache, and the batch cursor;
/// the front-end owns the prompt. `advance` moves forward until it signs a
/// document, finishes, or needs a PIN. `supply_pin` answers a
/// [`SigningStep::NeedsPin`]. `cancel` abandons the rest, keeping the
/// signatures already produced. None of these prompt.
pub trait SigningSession {
    /// Hard-fault type: card removed, transport error, malformed request.
    /// Expected control flow travels through [`SigningStep`], not here.
    type Error;

    /// Do the counter-safe work for the next document and return the one
    /// step the front-end must react to.
    ///
    /// # Errors
    /// Returns [`Self::Error`] only for a hard fault; a missing PIN, a low
    /// counter, or a lock are [`SigningStep`] variants, not errors.
    fn advance(&mut self) -> Result<SigningStep, Self::Error>;

    /// Answer a [`SigningStep::NeedsPin`] with the entered PIN and take the
    /// next step. A card rejection or a locally-refused value comes back as
    /// another [`SigningStep::NeedsPin`] with the matching
    /// [`PinPromptReason`], never as an error.
    ///
    /// # Errors
    /// Returns [`Self::Error`] only for a hard fault.
    fn supply_pin(&mut self, pin: PinBytes) -> Result<SigningStep, Self::Error>;

    /// Abandon the remaining documents. Returns the final progress so the
    /// front-end can report how many of the batch were signed.
    fn cancel(self) -> BatchProgress;
}
