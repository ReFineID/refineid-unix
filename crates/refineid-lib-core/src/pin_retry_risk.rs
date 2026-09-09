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

//! Refined FINEID PIN retry-risk states and consumer safety floors.

use crate::apdu::status_word::PinRetries;
use crate::auth::PinStatus;

/// Security severity derived from the FINEID five-attempt PIN counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PinRetryRisk {
    /// Five attempts remain: normal operating conditions.
    NormalOperatingConditions,
    /// Four attempts remain: a disturbance was detected.
    DisturbanceDetected,
    /// Three attempts remain: a security incident is declared.
    SecurityIncidentDeclared,
    /// Two attempts remain: only an explicitly authorized expert may proceed.
    CriticalThreatLevel,
    /// One attempt remains: card credential lockout is imminent.
    LockdownImminent,
    /// No attempts remain: the card credential is locked.
    DefencesFallen,
}

impl PinRetryRisk {
    /// Classify a FINEID retry counter. Values above the DVV limit of five are
    /// rejected rather than assigned a misleading risk state.
    #[must_use]
    pub const fn from_retries(retries: PinRetries) -> Option<Self> {
        match retries.get() {
            5 => Some(Self::NormalOperatingConditions),
            4 => Some(Self::DisturbanceDetected),
            3 => Some(Self::SecurityIncidentDeclared),
            2 => Some(Self::CriticalThreatLevel),
            1 => Some(Self::LockdownImminent),
            0 => Some(Self::DefencesFallen),
            _ => None,
        }
    }

    /// The one blocked band is one or two attempts remaining. Every other
    /// state passes: pristine, disturbed, security-incident, and even
    /// already-locked. Refusing exactly `{1, 2}` is what keeps this software
    /// from ever spending the next-to-last or last attempt, so a lockout is
    /// never its doing; a zero-attempt card is let through to surface its
    /// locked state or route to an unblock, with nothing left to protect.
    #[must_use]
    pub const fn permits_pkcs11(self) -> bool {
        !matches!(self, Self::CriticalThreatLevel | Self::LockdownImminent)
    }

    /// Ordinary graphical and system interfaces block the same one-or-two
    /// band and pass everything else. See [`Self::permits_pkcs11`].
    #[must_use]
    pub const fn permits_consumer(self) -> bool {
        !matches!(self, Self::CriticalThreatLevel | Self::LockdownImminent)
    }

    /// Reusable PIN1 caching requires a pristine five-attempt state. This is a
    /// separate, stricter gate for *arming* the cache, not the operate floor.
    #[must_use]
    pub const fn permits_reusable_cache(self) -> bool {
        matches!(self, Self::NormalOperatingConditions)
    }

    /// SCS terminates rather than operate in the blocked one-or-two band,
    /// matching the repo-wide floor.
    #[must_use]
    pub const fn requires_scs_shutdown(self) -> bool {
        matches!(self, Self::CriticalThreatLevel | Self::LockdownImminent)
    }
}

/// Whether a live PIN1 retry result permits an ordinary consumer
/// authentication operation.
///
/// PIN2 and PUK are intentionally absent: authentication cannot consume
/// either credential, so their state must not block PIN1. Unknown, malformed,
/// and locked states fail closed. `Verified` is safe because the card has
/// already accepted PIN1 in the current security context.
#[must_use]
pub const fn pin1_status_permits_consumer_authentication(pin1: PinStatus) -> bool {
    match pin1 {
        PinStatus::Verified => true,
        PinStatus::Remaining(retries) => matches!(
            PinRetryRisk::from_retries(retries),
            Some(risk) if risk.permits_consumer()
        ),
        PinStatus::Locked | PinStatus::NoInfo | PinStatus::Other(_) => false,
    }
}

/// Whether PIN1 may be retained for reusable authentication.
///
/// Only PIN1 is relevant. Four remaining attempts may still permit a
/// one-shot operation in adapters with an explicit retry floor, but not a
/// reusable cache entry.
#[must_use]
pub const fn pin1_status_permits_reusable_cache(pin1: PinStatus) -> bool {
    matches!(
        pin1,
        PinStatus::Remaining(retries)
            if matches!(
                PinRetryRisk::from_retries(retries),
                Some(risk) if risk.permits_reusable_cache()
            )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn risk(retries: u8) -> Option<PinRetryRisk> {
        PinRetries::from_nibble(retries).and_then(PinRetryRisk::from_retries)
    }

    #[test]
    fn five_attempt_risk_ladder_is_total_and_ordered() {
        assert_eq!(risk(5), Some(PinRetryRisk::NormalOperatingConditions));
        assert_eq!(risk(4), Some(PinRetryRisk::DisturbanceDetected));
        assert_eq!(risk(3), Some(PinRetryRisk::SecurityIncidentDeclared));
        assert_eq!(risk(2), Some(PinRetryRisk::CriticalThreatLevel));
        assert_eq!(risk(1), Some(PinRetryRisk::LockdownImminent));
        assert_eq!(risk(0), Some(PinRetryRisk::DefencesFallen));
        assert_eq!(risk(6), None);
    }

    #[test]
    fn floors_block_only_one_and_two_attempts() {
        // Reusable caching stays stricter: a pristine five is required to arm.
        assert!(PinRetryRisk::NormalOperatingConditions.permits_reusable_cache());
        assert!(!PinRetryRisk::DisturbanceDetected.permits_reusable_cache());

        // The operate floor passes every state except one or two attempts,
        // including an already-locked card.
        for permitted in [
            PinRetryRisk::NormalOperatingConditions,
            PinRetryRisk::DisturbanceDetected,
            PinRetryRisk::SecurityIncidentDeclared,
            PinRetryRisk::DefencesFallen,
        ] {
            assert!(permitted.permits_pkcs11(), "{permitted:?} permits pkcs11");
            assert!(
                permitted.permits_consumer(),
                "{permitted:?} permits consumer"
            );
            assert!(
                !permitted.requires_scs_shutdown(),
                "{permitted:?} keeps SCS up"
            );
        }
        for blocked in [
            PinRetryRisk::CriticalThreatLevel,
            PinRetryRisk::LockdownImminent,
        ] {
            assert!(!blocked.permits_pkcs11(), "{blocked:?} blocks pkcs11");
            assert!(!blocked.permits_consumer(), "{blocked:?} blocks consumer");
            assert!(
                blocked.requires_scs_shutdown(),
                "{blocked:?} shuts SCS down"
            );
        }
    }

    #[test]
    fn consumer_pin1_authentication_depends_only_on_pin1_retry_floor() {
        let remaining = |count| {
            PinStatus::Remaining(
                PinRetries::from_nibble(count).expect("test retry count fits one nibble"),
            )
        };
        assert!(pin1_status_permits_consumer_authentication(remaining(5)));
        assert!(pin1_status_permits_consumer_authentication(remaining(4)));
        assert!(pin1_status_permits_consumer_authentication(remaining(3)));
        assert!(!pin1_status_permits_consumer_authentication(remaining(2)));
        assert!(!pin1_status_permits_consumer_authentication(remaining(1)));
        // Zero attempts passes the floor -- nothing left to protect; the card
        // surfaces its locked state or a recovery routes to an unblock.
        assert!(pin1_status_permits_consumer_authentication(remaining(0)));
        assert!(pin1_status_permits_consumer_authentication(
            PinStatus::Verified
        ));
        assert!(!pin1_status_permits_consumer_authentication(
            PinStatus::Locked
        ));
        assert!(!pin1_status_permits_consumer_authentication(
            PinStatus::NoInfo
        ));
        assert!(!pin1_status_permits_consumer_authentication(
            PinStatus::Other(0x63_00)
        ));
    }

    #[test]
    fn reusable_pin1_cache_requires_only_pin1_at_five() {
        let remaining = |count| {
            PinStatus::Remaining(
                PinRetries::from_nibble(count).expect("test retry count fits one nibble"),
            )
        };
        assert!(pin1_status_permits_reusable_cache(remaining(5)));
        assert!(!pin1_status_permits_reusable_cache(remaining(4)));
        assert!(!pin1_status_permits_reusable_cache(remaining(3)));
        assert!(!pin1_status_permits_reusable_cache(PinStatus::Verified));
    }
}
