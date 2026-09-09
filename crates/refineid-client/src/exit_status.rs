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

//! Typed exit status for the `refineid` binary.
//!
//! Replaces scattered `ExitCode::from(64)` / `ExitCode::from(70)`
//! / `ExitCode::from(77)` / ... literals with named variants
//! that carry the documented meaning of each code. The numeric
//! mapping matches the convention block at the top of
//! `bin/refineid.rs`.

use std::process::ExitCode;

/// Process-exit reasons as named variants. The wire byte
/// follows the BSD `sysexits.h` family conventions where they
/// fit:
///
/// - `Ok = 0` -- success.
/// - `VerifyFailed = 1` -- offline verify rejected the signature.
/// - `BadInvocation = 64` -- argv shape rejected (= `EX_USAGE`).
/// - `NoReaders = 65` -- PC/SC: no readers connected.
/// - `NoCardPresent = 66` -- readers present but no card.
/// - `RuntimeFailure = 70` -- generic transport / parse / sign
///   failure (= `EX_SOFTWARE`).
/// - `CardCredentialRejected = 77` -- PIN / PUK rejected by the
///   card or local policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ExitStatus {
    /// Success (`0`).
    Ok = 0,
    /// Offline `verify` rejected the signature (`1`).
    VerifyFailed = 1,
    /// argv shape rejected (`64` = `EX_USAGE`).
    BadInvocation = 64,
    /// PC/SC reported zero connected readers (`65`).
    NoReaders = 65,
    /// At least one reader connected but no card present (`66`).
    NoCardPresent = 66,
    /// Generic transport / parse / sign failure
    /// (`70` = `EX_SOFTWARE`).
    RuntimeFailure = 70,
    /// PIN / PUK rejected by the card or by local policy (`77`).
    CardCredentialRejected = 77,
}

impl ExitStatus {
    /// The numeric wire byte the kernel sees.
    #[must_use]
    #[expect(
        clippy::as_conversions,
        reason = "ExitStatus is #[repr(u8)] with explicit discriminants; `self as u8` is the canonical (and only stable) way to read the discriminant"
    )]
    #[inline]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

impl From<ExitStatus> for ExitCode {
    #[inline]
    fn from(status: ExitStatus) -> Self {
        Self::from(status.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_match_documented_convention() {
        assert_eq!(ExitStatus::Ok.code(), 0_u8);
        assert_eq!(ExitStatus::VerifyFailed.code(), 1_u8);
        assert_eq!(ExitStatus::BadInvocation.code(), 64_u8);
        assert_eq!(ExitStatus::NoReaders.code(), 65_u8);
        assert_eq!(ExitStatus::NoCardPresent.code(), 66_u8);
        assert_eq!(ExitStatus::RuntimeFailure.code(), 70_u8);
        assert_eq!(ExitStatus::CardCredentialRejected.code(), 77_u8);
    }
}
