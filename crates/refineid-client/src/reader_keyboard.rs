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

//! `reader keyboard` -- ACS reader host-interface (keyboard
//! emulation) control.
//!
//! The ACR1581 is a composite USB device that can expose a HID
//! keyboard interface next to its CCID reader interfaces
//! ("keyboard wedge"). iOS suppresses the on-screen keyboard
//! whenever any hardware keyboard is attached, so a reader in
//! wedge mode makes a phone's PIN prompt untypable.
//!
//! The mode is a persistent reader setting, reachable with the
//! `Set Host Interface` escape command (ACR1581U Reference
//! Manual s6.1.14.7-8, sent to the PICC interface):
//!
//! ```text
//! get:  E0 00 00 93 00       ->  E1 00 00 00 01 <mode>
//! set:  E0 00 00 93 01 <mode> -> E1 00 00 00 01 <mode>
//! mode: 00 keyboard only, 01 CCID only, 02 keyboard + CCID
//! ```
//!
//! A mode change takes effect at the next USB enumeration --
//! the operator replugs the reader.

use refineid_lib_core::backend::{ReaderBackend as _, ReaderId};
use refineid_lib_pcsc::{PcscBackend, PcscError, reader_escape};

/// `Get Host Interface` escape command.
const GET_HOST_INTERFACE: [u8; 5] = [0xE0, 0x00, 0x00, 0x93, 0x00];
/// `Set Host Interface` escape command prefix; the mode byte
/// follows.
const SET_HOST_INTERFACE: [u8; 5] = [0xE0, 0x00, 0x00, 0x93, 0x01];
/// Escape commands go to the contactless interface per the
/// manual ("Escape Command for PICC").
const ESCAPE_SLOT_MARKER: &str = "PICC";

/// USB host-interface mode of the reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostInterface {
    /// `00h`: HID keyboard only -- no smart card function at all.
    KeyboardOnly,
    /// `01h`: CCID reader only -- the factory default, and the
    /// mode that makes phones show their on-screen keyboard.
    CcidOnly,
    /// `02h`: HID keyboard + CCID reader -- the wedge mode that
    /// suppresses on-screen keyboards.
    KeyboardAndCcid,
}

impl HostInterface {
    const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Self::KeyboardOnly),
            0x01 => Some(Self::CcidOnly),
            0x02 => Some(Self::KeyboardAndCcid),
            _ => None,
        }
    }

    const fn byte(self) -> u8 {
        match self {
            Self::KeyboardOnly => 0x00,
            Self::CcidOnly => 0x01,
            Self::KeyboardAndCcid => 0x02,
        }
    }

    const fn describe(self) -> &'static str {
        match self {
            Self::KeyboardOnly => "00 keyboard only (no smart card function!)",
            Self::CcidOnly => "01 CCID reader only",
            Self::KeyboardAndCcid => "02 keyboard + CCID (suppresses on-screen keyboards)",
        }
    }
}

/// What `reader keyboard` should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyboardAction {
    /// Report the current host-interface mode.
    Status,
    /// Set CCID-only (disable the keyboard wedge).
    Off,
    /// Set keyboard + CCID (enable the keyboard wedge).
    On,
}

/// `reader keyboard` failure.
#[derive(Debug)]
pub enum KeyboardError {
    /// No PC/SC readers at all.
    NoReaders,
    /// Readers exist but none matched the filter / PICC marker.
    NoEscapeReader,
    /// Escape transport failure.
    Pcsc(PcscError),
    /// The reader answered, but not in the documented shape.
    BadResponse(Vec<u8>),
}

impl core::fmt::Display for KeyboardError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoReaders => write!(f, "no PC/SC readers connected"),
            Self::NoEscapeReader => {
                write!(
                    f,
                    "no contactless (PICC) reader interface found for escape commands"
                )
            }
            Self::Pcsc(e) => write!(f, "escape command failed: {e}"),
            Self::BadResponse(bytes) => {
                write!(f, "unexpected escape response:")?;
                for b in bytes {
                    write!(f, " {b:02x}")?;
                }
                Ok(())
            }
        }
    }
}

impl core::error::Error for KeyboardError {}

impl From<PcscError> for KeyboardError {
    fn from(e: PcscError) -> Self {
        Self::Pcsc(e)
    }
}

/// Parse the documented `E1 00 00 00 01 <mode>` response.
fn parse_mode(response: &[u8]) -> Result<HostInterface, KeyboardError> {
    match response {
        [0xE1, 0x00, 0x00, 0x00, 0x01, mode] => HostInterface::from_byte(*mode)
            .ok_or_else(|| KeyboardError::BadResponse(response.to_vec())),
        _other => Err(KeyboardError::BadResponse(response.to_vec())),
    }
}

/// Run the action against every matching PICC reader interface
/// and return the report lines.
///
/// # Errors
/// No readers, no matching PICC interface, escape transport
/// failure, or an undocumented response shape.
pub fn run(
    action: KeyboardAction,
    reader_filter: Option<&str>,
) -> Result<Vec<String>, KeyboardError> {
    let readers = PcscBackend.enumerate()?;
    if readers.is_empty() {
        return Err(KeyboardError::NoReaders);
    }
    let targets: Vec<ReaderId> = readers
        .into_iter()
        .map(|info| info.id)
        .filter(|id| id.as_str().contains(ESCAPE_SLOT_MARKER))
        .filter(|id| reader_filter.is_none_or(|f| id.as_str().contains(f)))
        .collect();
    if targets.is_empty() {
        return Err(KeyboardError::NoEscapeReader);
    }

    let mut lines = Vec::new();
    for reader in &targets {
        let current = parse_mode(&reader_escape(reader, &GET_HOST_INTERFACE)?)?;
        lines.push(reader.as_str().to_owned());
        lines.push(format!("  host interface: {}", current.describe()));

        let wanted = match action {
            KeyboardAction::Status => continue,
            KeyboardAction::Off => HostInterface::CcidOnly,
            KeyboardAction::On => HostInterface::KeyboardAndCcid,
        };
        if current == wanted {
            lines.push("  already in the requested mode; nothing to do".to_owned());
            continue;
        }
        let mut set = SET_HOST_INTERFACE.to_vec();
        set.push(wanted.byte());
        let after = parse_mode(&reader_escape(reader, &set)?)?;
        lines.push(format!("  set host interface: {}", after.describe()));
        if after == wanted {
            lines.push("  done -- replug the reader for the change to take effect".to_owned());
        } else {
            lines.push("  WARNING: reader did not accept the requested mode".to_owned());
        }
    }
    Ok(lines)
}
