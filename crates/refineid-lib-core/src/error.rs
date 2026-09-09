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

//! Transport and policy errors at the use-case boundary.
//!
//! Variants for PIN / sign / PKCS#15 paths are absent from this
//! initial port and land when those subsystems clear the
//! live-validation gate.

use core::fmt;

/// Unexpected technical failure. Adapters typically log and show
/// a generic card-error message to the user.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum IoError {
    /// Transport-layer failure (PC/SC error, USB CCID, ...).
    /// Tier 0 `String`; presentational copy of the adapter
    /// error.
    Transport(String),
    /// Card-session was torn down (card reset, reader unplugged
    /// mid-flow). Tier 0 `String`; presentational.
    SessionLost(String),
    /// Card-session may or may not have completed -- the host
    /// observed a timeout. Tier 0 `String`; presentational.
    SessionStateUnknown(String),
    /// Host-policy rejection (PIN length / character class, ...).
    /// Tier 0 `String`; presentational.
    Policy(String),
    /// PC/SC reported zero connected readers.
    NoReaders,
    /// At least one reader is connected but none has a card.
    NoCard,
    /// Reader unplugged / session terminated.
    ReaderRemoved,
    /// `--reader` filter didn't match any connected reader.
    /// Tier 0 `String`; presentational copy of the filter.
    ReaderNotFound(String),
}

impl fmt::Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(s) => write!(f, "transport: {s}"),
            Self::SessionLost(s) => write!(f, "session lost: {s}"),
            Self::SessionStateUnknown(s) => write!(f, "session state unknown: {s}"),
            Self::Policy(s) => write!(f, "policy: {s}"),
            Self::NoReaders => write!(f, "no PC/SC readers available"),
            Self::NoCard => write!(f, "no card present in reader"),
            Self::ReaderRemoved => write!(f, "reader or card removed"),
            Self::ReaderNotFound(s) => write!(f, "reader not found: {s}"),
        }
    }
}

impl core::error::Error for IoError {}
