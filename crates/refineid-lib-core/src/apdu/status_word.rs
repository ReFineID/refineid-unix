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

//! ISO 7816-4 status word, decoded into refineid's known cases.
//!
//! The two trailing bytes (`SW1`, `SW2`) of every APDU response
//! together identify how the card processed the command. ISO
//! 7816-4 §5.1.3 lists the standard values; cards extend the
//! space with vendor / proprietary codes. Refineid's higher
//! layers used to compare `sw1: u8, sw2: u8` against literal
//! hex constants (`if response.sw() == 0x6983 { ... }`); this
//! module replaces that with a typed enum so a missing case is
//! a compile-time error (match exhaustiveness) and a misspelled
//! literal cannot silently slip through.
//!
//! Coverage is **specific to what refineid currently uses**.
//! When a new protocol layer matches on an additional SW, add
//! a variant here rather than introducing a new raw literal.
//! Unrecognised SWs land in [`StatusWord::Other`] carrying the
//! raw 16-bit value so the caller can still surface it.

use core::fmt;

/// PIN / PUK retries-remaining counter as carried by SW `0x63Cx`.
///
/// ISO 7816-4 §5.1.3 reserves `SW = 63 Cx` for "counter from 0
/// to 15 provided by `x`" -- the low nibble of `SW2`. The
/// constructor [`PinRetries::from_nibble`] is the trust
/// boundary: it asserts the value fits the 4-bit field.
/// Construction from the SW byte stream is structurally
/// validated (`(sw & 0x000F) as u8` always fits), so the
/// fallible constructor is the safety net for any future caller
/// that synthesises a `PinRetries` from a different source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PinRetries(u8);

impl PinRetries {
    /// Wrap a nibble-sized retries counter (`0..=15`).
    ///
    /// Returns `None` if `n > 15` -- the value cannot have come
    /// from a `63 Cx` status word.
    #[inline]
    #[must_use]
    pub const fn from_nibble(n: u8) -> Option<Self> {
        if n > 0x0F { None } else { Some(Self(n)) }
    }

    /// The raw 4-bit counter value (`0..=15`).
    #[inline]
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// `true` when the counter has reached zero. Cards typically
    /// emit [`StatusWord::AuthenticationBlocked`] alongside or
    /// instead of `63 C0`, but a defensive check belongs here.
    #[inline]
    #[must_use]
    pub const fn is_exhausted(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for PinRetries {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Decoded ISO 7816-4 status word.
///
/// Construct via [`StatusWord::from_u16`] /
/// [`StatusWord::from_bytes`]; query via the named variants or
/// [`StatusWord::as_u16`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatusWord {
    /// `0x6983` -- authentication method blocked (PIN or PUK
    /// retry counter exhausted; the credential is locked).
    AuthenticationBlocked,
    /// `0x6300` -- authentication / verification failed,
    /// without a retry counter. Some cards emit this instead
    /// of `0x63Cx` when no per-secret counter exists.
    AuthenticationFailed,
    /// `0x6282` -- end of file or record reached before reading
    /// the requested Le bytes. The response body up to the
    /// boundary is still valid; many callers treat this as
    /// non-fatal.
    EndOfFile,
    /// `0x6A82` -- file or application not found (SELECT
    /// against an absent AID / EF / DF).
    FileNotFound,
    /// Any SW refineid doesn't currently model. The raw
    /// `(SW1 << 8) | SW2` value is carried verbatim so callers
    /// can surface it for diagnostics without losing
    /// information.
    Other(u16),
    /// `0x63Cx` -- PIN / PUK verification failed; `retries` is
    /// the low nibble of `SW2` (counter remaining before the
    /// secret locks). `retries.is_exhausted()` is unusual; cards
    /// typically use [`StatusWord::AuthenticationBlocked`]
    /// (`0x6983`) once the counter hits zero.
    PinIncorrect {
        /// Number of attempts remaining before the slot locks
        /// (the low nibble of SW2). Typed via `PinRetries`.
        retries: PinRetries,
    },
    /// `0x6984` -- referenced data invalidated. Typical after a
    /// PUK unblock that resets a PIN to a known weak default.
    ReferenceDataInvalidated,
    /// `0x6A88` -- referenced data not found (key / PIN slot
    /// the command pointed at doesn't exist).
    ReferenceDataNotFound,
    /// `0x6982` -- security status not satisfied (a precondition
    /// like "PIN must be verified" wasn't met).
    SecurityNotSatisfied,
    /// `0x6988` -- secure-messaging data objects incorrect (the
    /// SM wrapping has a malformed DO 87 / DO 8E / DO 99).
    SmDataObjectsIncorrect,
    /// `0x9000` -- normal processing, no further information.
    Success,
    /// `0x6700` -- wrong length (`Lc` inconsistent with
    /// command, or the body length doesn't match the command
    /// shape).
    WrongLength,
}

impl StatusWord {
    // Raw ISO 7816-4 / proprietary status-word codes, each named
    // exactly once here so no bare hex literal is compared or
    // matched in the dispatch below (Rule E, No Magic Numbers --
    // doc/typing-discipline.md; the hex-offender gate flagged the
    // old `0x9000 => ...` arms). The human meaning lives on the
    // matching `StatusWord` variant; these are the single source
    // of truth for the wire encoding.
    /// `Success` -- normal processing, no further information.
    const SW_SUCCESS: u16 = 0x9000;
    /// `EndOfFile` -- end of file/record before `Le` bytes.
    const SW_END_OF_FILE: u16 = 0x6282;
    /// `AuthenticationFailed` -- verify failed, no counter.
    const SW_AUTHENTICATION_FAILED: u16 = 0x6300;
    /// `WrongLength` -- `Lc` inconsistent with the command.
    const SW_WRONG_LENGTH: u16 = 0x6700;
    /// `SecurityNotSatisfied` -- precondition (e.g. PIN) unmet.
    const SW_SECURITY_NOT_SATISFIED: u16 = 0x6982;
    /// `AuthenticationBlocked` -- retry counter exhausted/locked.
    const SW_AUTHENTICATION_BLOCKED: u16 = 0x6983;
    /// `ReferenceDataInvalidated` -- e.g. PIN reset to weak default.
    const SW_REFERENCE_DATA_INVALIDATED: u16 = 0x6984;
    /// `SmDataObjectsIncorrect` -- malformed SM DO 87/8E/99.
    const SW_SM_DATA_OBJECTS_INCORRECT: u16 = 0x6988;
    /// `FileNotFound` -- SELECT against an absent AID/EF/DF.
    const SW_FILE_NOT_FOUND: u16 = 0x6A82;
    /// `ReferenceDataNotFound` -- key/PIN slot doesn't exist.
    const SW_REFERENCE_DATA_NOT_FOUND: u16 = 0x6A88;
    /// PIN/PUK retry-counter family `0x63Cx`: a SW whose high 12
    /// bits (`& SW_PIN_COUNTER_MASK`) equal this prefix carries the
    /// remaining-retries count in the low nibble of `SW2`.
    const SW_PIN_COUNTER_PREFIX: u16 = 0x63C0;
    /// Mask selecting the high 12 bits, to test the `0x63Cx` family
    /// independently of the low-nibble counter value.
    const SW_PIN_COUNTER_MASK: u16 = 0xFFF0;

    /// Re-encode to the raw 16-bit wire value. Inverse of
    /// [`StatusWord::from_u16`] for every named variant; the
    /// `Other` variant round-trips through its carried `u16`.
    #[inline]
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::AuthenticationBlocked => Self::SW_AUTHENTICATION_BLOCKED,
            Self::AuthenticationFailed => Self::SW_AUTHENTICATION_FAILED,
            Self::EndOfFile => Self::SW_END_OF_FILE,
            Self::FileNotFound => Self::SW_FILE_NOT_FOUND,
            Self::Other(sw) => sw,
            Self::PinIncorrect { retries } => {
                // Build the SW2 byte (0xCn) directly, then
                // assemble the u16 from_be_bytes -- no `as u16`
                // widening cast. The high byte / nibble come from
                // the named counter prefix.
                let [sw1, prefix_sw2] = Self::SW_PIN_COUNTER_PREFIX.to_be_bytes();
                let sw2 = prefix_sw2 | (retries.0 & 0x0F);
                u16::from_be_bytes([sw1, sw2])
            }
            Self::ReferenceDataInvalidated => Self::SW_REFERENCE_DATA_INVALIDATED,
            Self::ReferenceDataNotFound => Self::SW_REFERENCE_DATA_NOT_FOUND,
            Self::SecurityNotSatisfied => Self::SW_SECURITY_NOT_SATISFIED,
            Self::SmDataObjectsIncorrect => Self::SW_SM_DATA_OBJECTS_INCORRECT,
            Self::Success => Self::SW_SUCCESS,
            Self::WrongLength => Self::SW_WRONG_LENGTH,
        }
    }

    /// Decode from the raw `(SW1, SW2)` byte pair.
    #[inline]
    #[must_use]
    pub const fn from_bytes(sw1: u8, sw2: u8) -> Self {
        // `u16::from_be_bytes` is const and avoids any `as u16`
        // widening cast.
        Self::from_u16(u16::from_be_bytes([sw1, sw2]))
    }

    /// Decode a 16-bit status-word value (`(SW1 << 8) | SW2`).
    #[inline]
    #[must_use]
    pub const fn from_u16(sw: u16) -> Self {
        match sw {
            Self::SW_SUCCESS => Self::Success,
            Self::SW_END_OF_FILE => Self::EndOfFile,
            Self::SW_AUTHENTICATION_FAILED => Self::AuthenticationFailed,
            Self::SW_WRONG_LENGTH => Self::WrongLength,
            Self::SW_SECURITY_NOT_SATISFIED => Self::SecurityNotSatisfied,
            Self::SW_AUTHENTICATION_BLOCKED => Self::AuthenticationBlocked,
            Self::SW_REFERENCE_DATA_INVALIDATED => Self::ReferenceDataInvalidated,
            Self::SW_SM_DATA_OBJECTS_INCORRECT => Self::SmDataObjectsIncorrect,
            Self::SW_FILE_NOT_FOUND => Self::FileNotFound,
            Self::SW_REFERENCE_DATA_NOT_FOUND => Self::ReferenceDataNotFound,
            // 0x63Cx -- PIN counter family. SW2 low nibble is
            // the retry count; using to_be_bytes()[1] reads the
            // raw SW2 byte directly so the 4-bit nibble extraction
            // never needs an `as u8` cast.
            counter if (counter & Self::SW_PIN_COUNTER_MASK) == Self::SW_PIN_COUNTER_PREFIX => {
                let sw2 = counter.to_be_bytes()[1];
                let nibble = sw2 & 0x0F;
                Self::PinIncorrect {
                    retries: PinRetries(nibble),
                }
            }
            other => Self::Other(other),
        }
    }

    /// `true` iff this is the success code `0x9000`.
    #[inline]
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }

    /// Number of remaining PIN / PUK retries if this status
    /// word is the `0x63Cx` counter family. `None` for every
    /// other variant (including the bare `0x6300` no-counter
    /// case and `0x6983` already-locked case).
    #[inline]
    #[must_use]
    pub const fn pin_retries(self) -> Option<PinRetries> {
        match self {
            Self::PinIncorrect { retries } => Some(retries),
            Self::AuthenticationBlocked
            | Self::AuthenticationFailed
            | Self::EndOfFile
            | Self::FileNotFound
            | Self::Other(_)
            | Self::ReferenceDataInvalidated
            | Self::ReferenceDataNotFound
            | Self::SecurityNotSatisfied
            | Self::SmDataObjectsIncorrect
            | Self::Success
            | Self::WrongLength => None,
        }
    }
}

impl fmt::Display for StatusWord {
    /// Operator-friendly rendering. Always includes the raw
    /// hex `(SW1, SW2)` so the wire value is visible alongside
    /// the human label.
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let raw = self.as_u16();
        match *self {
            Self::AuthenticationBlocked => write!(f, "{raw:#06X} (AuthenticationBlocked)"),
            Self::AuthenticationFailed => write!(f, "{raw:#06X} (AuthenticationFailed)"),
            Self::EndOfFile => write!(f, "{raw:#06X} (EndOfFile)"),
            Self::FileNotFound => write!(f, "{raw:#06X} (FileNotFound)"),
            Self::Other(sw) => write!(f, "{sw:#06X} (Other)"),
            Self::PinIncorrect { retries } => {
                write!(f, "{raw:#06X} (PIN incorrect, {retries} retries left)")
            }
            Self::ReferenceDataInvalidated => {
                write!(f, "{raw:#06X} (ReferenceDataInvalidated)")
            }
            Self::ReferenceDataNotFound => write!(f, "{raw:#06X} (ReferenceDataNotFound)"),
            Self::SecurityNotSatisfied => write!(f, "{raw:#06X} (SecurityNotSatisfied)"),
            Self::SmDataObjectsIncorrect => {
                write!(f, "{raw:#06X} (SmDataObjectsIncorrect)")
            }
            Self::Success => write!(f, "{raw:#06X} (Success)"),
            Self::WrongLength => write!(f, "{raw:#06X} (WrongLength)"),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn success_round_trips() {
        let sw = StatusWord::from_u16(0x9000);
        assert!(matches!(sw, StatusWord::Success));
        assert!(sw.is_success());
        assert_eq!(sw.as_u16(), 0x9000);
    }

    #[test]
    fn pin_incorrect_carries_retries() {
        let sw = StatusWord::from_u16(0x63C3);
        let three = PinRetries::from_nibble(3).expect("nibble");
        assert_eq!(sw, StatusWord::PinIncorrect { retries: three });
        assert_eq!(sw.pin_retries(), Some(three));
        assert_eq!(sw.as_u16(), 0x63C3);
        assert_eq!(three.get(), 3);
        assert!(!three.is_exhausted());
    }

    #[test]
    fn pin_counter_low_nibble_zero_is_distinct_from_authentication_blocked() {
        // 0x63C0 -- counter explicitly at zero, but reported via
        // the counter family rather than 0x6983.
        let sw = StatusWord::from_u16(0x63C0);
        let zero = PinRetries::from_nibble(0).expect("nibble");
        assert_eq!(sw, StatusWord::PinIncorrect { retries: zero });
        assert!(zero.is_exhausted());
        // 0x6983 -- authentication method blocked (different SW).
        assert_eq!(
            StatusWord::from_u16(0x6983),
            StatusWord::AuthenticationBlocked
        );
    }

    #[test]
    fn pin_retries_rejects_out_of_nibble_range() {
        assert!(PinRetries::from_nibble(16).is_none());
        assert!(PinRetries::from_nibble(0xFF).is_none());
        assert_eq!(
            PinRetries::from_nibble(0x0F).map(PinRetries::get),
            Some(0x0F)
        );
    }

    #[test]
    fn from_bytes_matches_from_u16() {
        let combined = StatusWord::from_u16(0x6A82);
        let split = StatusWord::from_bytes(0x6A, 0x82);
        assert_eq!(combined, split);
        assert_eq!(split, StatusWord::FileNotFound);
    }

    #[test]
    fn unknown_sw_falls_through_to_other() {
        let sw = StatusWord::from_u16(0x6F00);
        assert_eq!(sw, StatusWord::Other(0x6F00));
        assert_eq!(sw.as_u16(), 0x6F00);
        assert!(!sw.is_success());
        assert!(sw.pin_retries().is_none());
    }

    #[test]
    fn every_named_variant_round_trips_through_u16() {
        let cases: &[u16] = &[
            0x9000, 0x6282, 0x6300, 0x6700, 0x6982, 0x6983, 0x6984, 0x6988, 0x6A82, 0x6A88,
        ];
        for &sw in cases {
            assert_eq!(StatusWord::from_u16(sw).as_u16(), sw);
        }
        // PIN counter family: 0x63C0..=0x63CF.
        for retries in 0_u8..=15 {
            let sw = 0x63C0 | u16::from(retries);
            assert_eq!(StatusWord::from_u16(sw).as_u16(), sw);
        }
    }

    #[test]
    fn display_includes_raw_hex_and_human_label() {
        let five = PinRetries::from_nibble(5).expect("nibble");
        let s = format!("{}", StatusWord::PinIncorrect { retries: five });
        assert!(s.contains("0x63C5"));
        assert!(s.contains("5 retries"));
    }
}
