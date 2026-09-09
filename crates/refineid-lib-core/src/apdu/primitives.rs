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

//! Shared APDU primitives used across protocol modules.
//!
//! Per `doc/typing-discipline.md`, every byte sequence crossing
//! the card boundary needs a typed container that names its
//! role. This module hosts the small set of role types that
//! refineid's APDU command structs (`pace::commands`,
//! `auth::commands`, `pkcs15::commands`, ...) compose from:
//! class / instruction bytes, application identifiers, short-
//! file identifiers, P1 / P2 reference bytes.
//!
//! Each primitive is a newtype with construction-time validation
//! and a clear semantic role. Encoding into the wire byte stream
//! happens at each protocol-specific command's `into_apdu`
//! boundary -- this module is the type layer, not the encoder.

use core::error::Error as CoreError;
use core::fmt;

/// ISO 7816-4 application identifier.
///
/// Per ISO 7816-5 an AID is 5..=16 bytes. SELECT-by-AID
/// commands (CLA INS=0xA4 P1=0x04) pass the AID in the data
/// field; this type captures the length constraint at
/// construction so a 4-byte or 17-byte AID never reaches the
/// card.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Aid {
    /// AID bytes; constructor invariant guarantees `5..=16`.
    bytes: Vec<u8>,
}

/// Error returned by [`Aid::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AidError {
    /// Per ISO 7816-5: AID must be 5..=16 bytes.
    LengthOutOfRange {
        /// Length of the rejected input in bytes.
        got: usize,
    },
}

impl Aid {
    /// Borrow the underlying AID bytes (5..=16 bytes).
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Construct from a borrowed slice; copies into an owned
    /// buffer. See [`Self::new`] for the validation contract.
    ///
    /// # Errors
    /// See [`Aid::new`].
    #[inline]
    pub(crate) fn from_slice(bytes: &[u8]) -> Result<Self, AidError> {
        Self::new(bytes.to_vec())
    }

    /// `true` when the AID buffer is empty. Always `false` per
    /// the constructor's `5..=16` invariant; retained for
    /// idiomatic API symmetry with `len`.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        // Per the length-range invariant this is always false,
        // but the trait conventionally pairs with `len`.
        self.bytes.is_empty()
    }

    /// Length of the AID in bytes. Always in `5..=16` by
    /// constructor invariant.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Construct from a byte vector. Validates the ISO 7816-5
    /// length range.
    ///
    /// # Errors
    /// [`AidError::LengthOutOfRange`] when `bytes.len()` is
    /// outside `5..=16`.
    #[inline]
    pub fn new<B: Into<Box<[u8]>>>(bytes: B) -> Result<Self, AidError> {
        let boxed: Box<[u8]> = bytes.into();
        let owned = boxed.into_vec();
        if !(5..=16).contains(&owned.len()) {
            return Err(AidError::LengthOutOfRange { got: owned.len() });
        }
        Ok(Self { bytes: owned })
    }
}

impl fmt::Display for Aid {
    /// Render as hyphen-grouped uppercase hex (`A0:00:00:24:35`)
    /// for compact diagnostic output.
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for byte in &self.bytes {
            if first {
                first = false;
            } else {
                match f.write_str(":") {
                    Ok(()) => (),
                    Err(err) => return Err(err),
                }
            }
            match write!(f, "{byte:02X}") {
                Ok(()) => (),
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }
}

impl fmt::Display for AidError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthOutOfRange { got } => {
                write!(f, "AID length {got} outside ISO 7816-5 range 5..=16 bytes")
            }
        }
    }
}

impl CoreError for AidError {}

/// ISO 7816-4 Short File Identifier (SFI).
///
/// Five-bit value 1..=30; encoded in P1 of the READ BINARY
/// short-form `00 B0 (80|SFI) <offset>` shape. Refineid uses
/// SFIs to read eMRTD data groups (DG1 = SFI 0x01, DG2 = SFI
/// 0x02, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sfi(u8);

/// Error returned by [`Sfi::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SfiError {
    /// Value was 0 or > 30 (outside the ISO 7816-4 SFI range).
    OutOfRange {
        /// The rejected value.
        got: u8,
    },
}

impl Sfi {
    /// Encode as the P1 byte for a SFI-form READ BINARY (high
    /// bit set: `0x80 | sfi`).
    #[inline]
    #[must_use]
    pub const fn as_p1_short_form(self) -> u8 {
        0x80 | self.0
    }

    /// Const-context constructor for compile-time-known SFI
    /// values (e.g. ICAO 9303-10 data-group SFI constants).
    /// Panics at compile time if the value is outside 1..=30.
    ///
    /// # Panics
    /// At compile time when `value` is 0 or > 30.
    #[inline]
    #[must_use]
    #[expect(
        clippy::panic,
        reason = "Const-eval boundary: `from_const` builds SFI constants at compile time (e.g. ICAO 9303-10 DG SFI table). A panic inside a const fn produces a compile error -- never a runtime panic -- so the panic here is the well-formedness gate, not a runtime hazard."
    )]
    pub const fn from_const(value: u8) -> Self {
        match Self::new(value) {
            Ok(sfi) => sfi,
            Err(_) => panic!("SFI out of 1..=30 range"),
        }
    }

    /// # Errors
    /// [`SfiError::OutOfRange`] when `value` is not in `1..=30`.
    #[inline]
    pub const fn new(value: u8) -> Result<Self, SfiError> {
        if value == 0 || value > 30 {
            return Err(SfiError::OutOfRange { got: value });
        }
        Ok(Self(value))
    }

    /// Return the raw SFI value as the inner `u8` (`1..=30` by
    /// constructor invariant).
    #[inline]
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl fmt::Display for Sfi {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SFI 0x{:02X}", self.0)
    }
}

impl fmt::Display for SfiError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange { got } => {
                write!(f, "SFI {got} outside ISO 7816-4 range 1..=30")
            }
        }
    }
}

impl CoreError for SfiError {}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn aid_accepts_valid_length() -> Result<(), AidError> {
        let aid = Aid::from_slice(&[0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01])?;
        assert_eq!(aid.len(), 7);
        assert_eq!(format!("{aid}"), "A0:00:00:02:47:10:01");
        Ok(())
    }

    #[test]
    fn aid_rejects_too_short() {
        assert!(matches!(
            Aid::from_slice(&[0xA0, 0x00, 0x00, 0x02]),
            Err(AidError::LengthOutOfRange { got: 4 })
        ));
    }

    #[test]
    fn aid_rejects_too_long() {
        let too_long = vec![0_u8; 17];
        assert!(matches!(
            Aid::from_slice(&too_long),
            Err(AidError::LengthOutOfRange { got: 17 })
        ));
    }

    #[test]
    fn sfi_accepts_valid_range() -> Result<(), SfiError> {
        let s = Sfi::new(1)?;
        assert_eq!(s.value(), 1);
        assert_eq!(s.as_p1_short_form(), 0x81);
        let s = Sfi::new(30)?;
        assert_eq!(s.as_p1_short_form(), 0x9E);
        Ok(())
    }

    #[test]
    fn sfi_rejects_zero_and_overflow() {
        assert!(matches!(Sfi::new(0), Err(SfiError::OutOfRange { got: 0 })));
        assert!(matches!(
            Sfi::new(31),
            Err(SfiError::OutOfRange { got: 31 })
        ));
    }
}
