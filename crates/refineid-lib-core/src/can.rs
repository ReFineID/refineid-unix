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

//! Card Access Number -- typed wrapper around the 6-digit code
//! printed on the FINEID card's front face.
//!
//! See [`doc/typing-discipline.md`][doc] for why we newtype
//! values that cross trust boundaries. The CAN crosses a real
//! one: it's operator input (typed at a CLI prompt or piped
//! from an LDIF / config) and reaches the card via the PACE
//! key-derivation path. A wrong CAN does not consume a retry
//! counter, but the card can suspend it until a power reset.
//!
//! The CAN is **not secret** -- it's optically public on the
//! card front. We type it for *shape*, not for confidentiality
//! (compare `PinBytes`). Constructor-only construction means
//! downstream code taking `&Can` can assume well-formed bytes
//! without re-validating; CLI parse-don't-validate replaces
//! the previous `validate_can(&str) -> Result<(), _>` shape
//! where the raw `&str` survived the check.
//!
//! [doc]: ../../../../doc/typing-discipline.md

use core::fmt;

/// Number of ASCII digits in a CAN. FINEID and ICAO 9303 §6.2
/// both fix this at 6.
pub const CAN_DIGITS: usize = 6;

/// A FINEID Card Access Number, validated at construction.
///
/// Always 6 ASCII digits. The internal byte array is the only
/// representation; conversions to `&str` and `Display` are
/// guaranteed-valid because the constructor rejects everything
/// else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Can([u8; CAN_DIGITS]);

/// Error returned by [`Can::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanError {
    /// Input was empty.
    Empty,
    /// Input was the wrong length. CAN is exactly 6 digits.
    WrongLength {
        /// Length of the rejected input in bytes. Tier 0
        /// `usize`; arithmetic count.
        got: usize,
    },
    /// A non-digit byte appeared. `at` is the zero-based byte
    /// offset; `byte` is the offending value.
    NonDigit {
        /// Byte index of the offending value.
        at: usize,
        /// The offending byte (anything outside `0..=9`).
        byte: u8,
    },
    /// The CAN was all zeros (`000000`). Syntactically a 6-digit
    /// CAN, but never a real issued value on a production card --
    /// an all-zero CAN means the input was lost / uninitialised /
    /// zeroed somewhere upstream, not entered. Rejected as a
    /// data-integrity sentinel. (This is the *only* "value" CAN
    /// rejects beyond shape; we do not police other unlikely-but-
    /// possible CANs -- the card is the authority on correctness.)
    AllZeros,
}

impl fmt::Display for CanError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "CAN cannot be empty"),
            Self::WrongLength { got } => {
                write!(f, "CAN must be exactly {CAN_DIGITS} digits, got {got}")
            }
            Self::NonDigit { at, byte } => write!(
                f,
                "CAN must be ASCII digits only; non-digit at offset {at}: byte {byte:#04x}"
            ),
            Self::AllZeros => write!(
                f,
                "CAN was all zeros (000000); never a valid production CAN -- input was likely lost or zeroed upstream"
            ),
        }
    }
}

impl core::error::Error for CanError {}

impl Can {
    /// Parse `s` as a CAN. Accepts exactly 6 ASCII-digit bytes;
    /// rejects anything else with a specific [`CanError`].
    ///
    /// # Errors
    /// Empty input, wrong length, or any non-digit byte.
    #[inline]
    pub fn new<S: AsRef<str>>(s: S) -> Result<Self, CanError> {
        let bytes = s.as_ref().as_bytes();
        if bytes.is_empty() {
            return Err(CanError::Empty);
        }
        if bytes.len() != CAN_DIGITS {
            return Err(CanError::WrongLength { got: bytes.len() });
        }
        for (i, &b) in bytes.iter().enumerate() {
            if !b.is_ascii_digit() {
                return Err(CanError::NonDigit { at: i, byte: b });
            }
        }
        // All-zero CAN: well-formed shape, but never a real issued
        // value -- treat it as a lost-data sentinel, not a CAN.
        if bytes.iter().all(|&b| b == b'0') {
            return Err(CanError::AllZeros);
        }
        let mut buf = [0_u8; CAN_DIGITS];
        buf.copy_from_slice(bytes);
        Ok(Self(buf))
    }

    /// The 6 ASCII digit bytes that make up the CAN.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CAN_DIGITS] {
        &self.0
    }

    /// String view of the CAN. Always valid UTF-8 because the
    /// constructor only accepts ASCII digits.
    ///
    /// # Panics
    /// Never under correct construction; the constructor
    /// rejects every byte that would break UTF-8. A panic here
    /// would indicate the type's invariant was violated by
    /// unsafe code or a serde bypass.
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "Invariant proof: Can::new only accepts ASCII-digit bytes, which is a strict subset of UTF-8. The expect message documents the invariant; reaching the Err arm would require an unsafe / serde bypass that violates the type."
    )]
    #[inline]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.0).expect("Can bytes are ASCII digits by construction")
    }
}

impl fmt::Display for Can {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {

    use super::{Can, CanError};

    #[test]
    fn happy_path() {
        let c = Can::new("123456").expect("six digits is a valid CAN");
        assert_eq!(c.as_str(), "123456");
        assert_eq!(c.as_bytes(), b"123456");
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(Can::new(""), Err(CanError::Empty));
    }

    #[test]
    fn rejects_too_short() {
        assert!(matches!(
            Can::new("12345"),
            Err(CanError::WrongLength { got: 5 })
        ));
    }

    #[test]
    fn rejects_too_long() {
        assert!(matches!(
            Can::new("1234567"),
            Err(CanError::WrongLength { got: 7 })
        ));
    }

    #[test]
    fn rejects_letter() {
        assert!(matches!(
            Can::new("12a456"),
            Err(CanError::NonDigit { at: 2, byte: b'a' })
        ));
    }

    #[test]
    fn rejects_dash() {
        assert!(matches!(
            Can::new("12-456"),
            Err(CanError::NonDigit { at: 2, .. })
        ));
    }

    #[test]
    fn display_round_trips() {
        let c = Can::new("987654").expect("six digits is a valid CAN");
        assert_eq!(format!("{c}"), "987654");
    }

    /// `000000` is shape-valid (six ASCII digits) but never a real
    /// issued CAN -- an all-zero value means the input was lost or
    /// zeroed upstream. Rejected as a data-integrity sentinel.
    #[test]
    fn rejects_all_zeros() {
        assert_eq!(Can::new("000000"), Err(CanError::AllZeros));
    }

    /// The all-zero reject is the *only* value-level rule: a CAN
    /// that merely contains zeros (leading, trailing, or interior)
    /// is accepted. We don't police "unlikely" CANs -- the card is
    /// the authority on correctness.
    #[test]
    fn accepts_cans_with_some_zeros() {
        for can in ["000001", "100000", "012300", "010101"] {
            assert!(Can::new(can).is_ok(), "{can} should be accepted");
        }
    }
}
