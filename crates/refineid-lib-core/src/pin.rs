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

//! Secret-code newtype.
//!
//! `PinBytes` owns validated PIN material between the point it's read
//! from a user-input source (echo-off stdin, a GUI prompt, the
//! `C_Login` PKCS#11 surface, ...) and the point it's encoded into
//! a VERIFY APDU. The buffer zeroes on drop so a memory dump after
//! the call doesn't yield residue.
//!
//! - `Debug` is intentionally lossy (`PinBytes([redacted])`); never
//!   log the raw bytes.
//! - The wrapper isn't a strong secrecy boundary against a hostile
//!   in-process attacker, just a hygienic default that keeps stale
//!   PIN bytes out of long-lived heap pages.
//! - The type is `Clone` because PKCS#11 / agent callers
//!   occasionally need to retry a VERIFY without re-prompting the
//!   user. Both clones zeroize independently on drop.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A syntactically valid FINEID PIN-family code: 4-12 ASCII digits.
///
/// Role-specific types and operations may impose tighter bounds. For
/// example, PIN2 requires at least 6 digits and activation codes have
/// an exact length. Padding to the card's stored length is done
/// downstream in `auth::verify_pin`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PinBytes {
    bytes: [u8; Self::MAX_LENGTH],
    length: u8,
}

impl PinBytes {
    /// Shortest code accepted by any FINEID PIN-family role.
    pub const MIN_LENGTH: usize = 4;
    /// Longest code accepted by any FINEID PIN-family role.
    pub const MAX_LENGTH: usize = 12;

    /// Validate and take ownership of `bytes`.
    ///
    /// The caller's `Vec` is moved in and zeroized after validation.
    /// Valid digits are copied into the type's fixed-capacity storage;
    /// rejected input is zeroized before its allocation is released.
    ///
    /// # Errors
    /// Returns [`PinRoleError`] unless `bytes` contains 4-12 ASCII
    /// digits.
    pub fn new(mut bytes: Vec<u8>) -> Result<Self, PinRoleError> {
        if let Err(error) = validate_digits(&bytes, Self::MIN_LENGTH, Self::MAX_LENGTH) {
            bytes.zeroize();
            return Err(error);
        }
        let Ok(length) = u8::try_from(bytes.len()) else {
            bytes.zeroize();
            return Err(PinRoleError::WrongLength {
                expected_min: Self::MIN_LENGTH,
                expected_max: Self::MAX_LENGTH,
            });
        };
        let mut storage = [0; Self::MAX_LENGTH];
        storage[..bytes.len()].copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(Self {
            bytes: storage,
            length,
        })
    }

    /// Borrow the inner bytes for a verify call. Callers must not
    /// store the slice beyond the lifetime of `self`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.digit_count()]
    }

    /// Number of ASCII digits in the code.
    #[must_use]
    pub const fn digit_count(&self) -> usize {
        self.length as usize
    }
}

impl TryFrom<Vec<u8>> for PinBytes {
    type Error = PinRoleError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(bytes)
    }
}

impl<const N: usize> TryFrom<[u8; N]> for PinBytes {
    type Error = PinRoleError;

    fn try_from(mut bytes: [u8; N]) -> Result<Self, Self::Error> {
        if let Err(error) = validate_digits(&bytes, Self::MIN_LENGTH, Self::MAX_LENGTH) {
            bytes.zeroize();
            return Err(error);
        }
        let Ok(length) = u8::try_from(N) else {
            bytes.zeroize();
            return Err(PinRoleError::WrongLength {
                expected_min: Self::MIN_LENGTH,
                expected_max: Self::MAX_LENGTH,
            });
        };
        let mut storage = [0; Self::MAX_LENGTH];
        storage[..N].copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(Self {
            bytes: storage,
            length,
        })
    }
}

impl core::fmt::Debug for PinBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PinBytes([redacted])")
    }
}

// ---- Role-tagged PIN code newtypes ----
//
// PinBytes is the validated zeroizing secret carrier; the wrappers
// below tag the role so the type system enforces "this is a
// PUK, not an activation PIN" at every API boundary. Per
// `doc/typing-discipline.md`, the PIN AUTH / PIN SIG / PIN PUK
// / activation-PIN distinction must be type-enforced. PIN1 /
// PIN2 remain paired with `PinSlot` in the auth API (slot
// already disambiguates); PUK and activation PIN get their own
// types because they are semantically distinct roles even on
// cards where the card-side slot is shared.

/// Error returned by the role-tagged PIN newtype constructors.
///
/// Not PIN-bearing: variants carry only structural diagnostics
/// (length bounds). Per Rule E1 in `doc/security/excellence-rules.md`,
/// `Copy` is forbidden only on types that hold PIN / PUK / activation-PIN / CAN material
/// in their fields; this error enum holds none of those.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinRoleError {
    /// Input was empty.
    Empty,
    /// Input had a length outside the allowed range for this
    /// role.
    WrongLength {
        /// Minimum length the role accepts. Tier 0 `usize`.
        expected_min: usize,
        /// Maximum length the role accepts. Tier 0 `usize`.
        expected_max: usize,
    },
    /// Input contained a non-ASCII-digit byte.
    NonDigit,
}

impl core::fmt::Display for PinRoleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => write!(f, "PIN code cannot be empty"),
            Self::WrongLength {
                expected_min,
                expected_max,
            } => {
                if expected_min == expected_max {
                    write!(
                        f,
                        "PIN code wrong length: expected exactly {expected_min} digits"
                    )
                } else {
                    write!(
                        f,
                        "PIN code wrong length: expected {expected_min}-{expected_max} digits"
                    )
                }
            }
            Self::NonDigit => write!(f, "PIN code must be ASCII digits only"),
        }
    }
}

impl core::error::Error for PinRoleError {}

fn validate_digits(bytes: &[u8], min: usize, max: usize) -> Result<(), PinRoleError> {
    if bytes.is_empty() {
        return Err(PinRoleError::Empty);
    }
    if bytes.len() < min || bytes.len() > max {
        return Err(PinRoleError::WrongLength {
            expected_min: min,
            expected_max: max,
        });
    }
    if bytes.iter().any(|b| !b.is_ascii_digit()) {
        return Err(PinRoleError::NonDigit);
    }
    Ok(())
}

impl PinBytes {
    /// Validate that the held bytes are between `min` and `max`
    /// (inclusive) bytes long and contain only ASCII digits.
    /// Used by [`Puk`] / [`ActivationPinSeven`] /
    /// [`ActivationPinEight`] constructors at their trust
    /// boundaries.
    ///
    /// # Errors
    /// [`PinRoleError`] for empty, wrong-length, or non-digit
    /// input.
    pub fn validate_digits(&self, min: usize, max: usize) -> Result<(), PinRoleError> {
        validate_digits(self.as_bytes(), min, max)
    }
}

/// PUK code for the `RESET RETRY COUNTER` APDU (`card
/// unblock-pin1` / `card unblock-pin2`).
///
/// 8 to 12 ASCII digits (FINEID S4-1 v4.2 section 8.1.5, EF.AOD:
/// minLength 8, storedLength 12), independent of card generation.
///
/// The separately-ordered PUK and the older card's reusable
/// 8-digit activation PIN are valid here; the newer card's
/// 7-digit activation code is single-use and cannot unblock, so
/// it is a distinct type ([`ActivationPinSeven`]), not a PUK.
///
/// Distinct from `ActivationPin` in the type system, even
/// though the card-side mechanism may be the same slot
/// (`0x83`). See `doc/dvv-terminology.md`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Puk(PinBytes);

impl Puk {
    /// Shortest accepted PUK length.
    pub const MIN_LENGTH: usize = 8;
    /// Longest accepted PUK length: the stored (padded) block length.
    pub const MAX_LENGTH: usize = 12;

    /// Parse `bytes` as a PUK code.
    ///
    /// # Errors
    /// Empty, a length outside [`Self::MIN_LENGTH`]..=[`Self::MAX_LENGTH`],
    /// or any non-digit byte.
    pub fn new(bytes: PinBytes) -> Result<Self, PinRoleError> {
        bytes.validate_digits(Self::MIN_LENGTH, Self::MAX_LENGTH)?;
        Ok(Self(bytes))
    }

    /// Borrow the inner secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Copy the validated code into the generic PIN-family type.
    #[must_use]
    pub fn to_pin_bytes(&self) -> PinBytes {
        self.0.clone()
    }

    /// Number of ASCII digits in the PUK.
    #[must_use]
    pub const fn digit_count(&self) -> usize {
        self.0.digit_count()
    }
}

impl core::fmt::Debug for Puk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Puk([redacted])")
    }
}

/// Activation PIN for FINEID cards issued **on or after
/// 13 January 2026**. 7 ASCII digits exactly.
///
/// **Single-use**: consumed by card activation; cannot
/// subsequently unblock PIN1 / PIN2. After activation it has
/// no further role. If lost / locked, the citizen must order a
/// separate [`Puk`] from the Police (subject to a fee).
///
/// Source: <https://dvv.fi/en/activation-of-the-citizen-certificate>.
///
/// Distinct type from [`ActivationPinEight`] (older-card form)
/// and [`Puk`] (unblock code) so the compiler enforces "this
/// activation PIN is for the new-card single-use flow".
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ActivationPinSeven(PinBytes);

impl ActivationPinSeven {
    /// 7 ASCII digits exactly.
    pub const LENGTH: usize = 7;

    /// Parse `bytes` as a new-card activation PIN.
    ///
    /// # Errors
    /// Empty, wrong length (not exactly 7), or any non-digit
    /// byte.
    pub fn new(bytes: PinBytes) -> Result<Self, PinRoleError> {
        bytes.validate_digits(Self::LENGTH, Self::LENGTH)?;
        Ok(Self(bytes))
    }

    /// Borrow the inner secret bytes (7 ASCII digits).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Number of ASCII digits. Always
    /// [`LENGTH`](Self::LENGTH) after successful construction.
    #[must_use]
    pub const fn digit_count(&self) -> usize {
        self.0.digit_count()
    }
}

impl core::fmt::Debug for ActivationPinSeven {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ActivationPinSeven([redacted])")
    }
}

/// Activation PIN for FINEID cards issued **before
/// 13 January 2026**. 8 ASCII digits exactly.
///
/// **Reusable**: the same 8-digit code from the activation
/// letter doubles as the card's PUK -- it can unblock PIN1 /
/// PIN2 after they get locked, in addition to its primary
/// activation role. On these cards, exhausting this code via 5
/// wrong activation attempts permanently locks the chip for
/// e-services (the card still works as an ID document and
/// travel document, but no online services). Recovery requires
/// a new card from the Police.
///
/// Source: <https://dvv.fi/en/activation-of-the-citizen-certificate>.
///
/// Distinct type from [`ActivationPinSeven`] (new-card form).
/// Wire-shape identical to [`Puk`] (both are 8 ASCII digits)
/// but the operator-intent distinction is preserved at the
/// type level -- this is "the code from the activation letter",
/// while `Puk` is "the code separately ordered for unblock".
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ActivationPinEight(PinBytes);

impl ActivationPinEight {
    /// 8 ASCII digits exactly.
    pub const LENGTH: usize = 8;

    /// Parse `bytes` as an old-card activation PIN.
    ///
    /// # Errors
    /// Empty, wrong length (not exactly 8), or any non-digit
    /// byte.
    pub fn new(bytes: PinBytes) -> Result<Self, PinRoleError> {
        bytes.validate_digits(Self::LENGTH, Self::LENGTH)?;
        Ok(Self(bytes))
    }

    /// Borrow the inner secret bytes (8 ASCII digits).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Number of ASCII digits. Always
    /// [`LENGTH`](Self::LENGTH) after successful construction.
    #[must_use]
    pub const fn digit_count(&self) -> usize {
        self.0.digit_count()
    }
}

impl core::fmt::Debug for ActivationPinEight {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ActivationPinEight([redacted])")
    }
}

/// API sum-type for "either activation PIN form".
///
/// Consumers like `card_pin::activate_first` take this and
/// dispatch based on which variant the operator constructed at
/// the input-parsing boundary (the variant choice corresponds
/// to the card's issuance date per DVV's 2026-01-13 cutoff).
///
/// The variants carry the two distinct types from this module;
/// the enum exists only to give callers a single function
/// parameter that can be either. Inside that function the
/// match arms operate on the typed inner value.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub enum ActivationCode {
    /// 7 ASCII digits; new-card single-use flow.
    Seven(ActivationPinSeven),
    /// 8 ASCII digits; old-card reusable flow.
    Eight(ActivationPinEight),
}

impl ActivationCode {
    /// Borrow the inner secret bytes (length depends on
    /// variant; check via [`Self::variant_label`] if needed).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Seven(p) => p.as_bytes(),
            Self::Eight(p) => p.as_bytes(),
        }
    }

    /// Copy the validated code into the generic PIN-family type.
    #[must_use]
    pub fn to_pin_bytes(&self) -> PinBytes {
        match self {
            Self::Seven(pin) => pin.0.clone(),
            Self::Eight(pin) => pin.0.clone(),
        }
    }

    /// Human label for the variant. Useful in error messages
    /// like "card-side generation mismatch: card is older but
    /// you supplied an `ActivationPinSeven`."
    #[must_use]
    pub const fn variant_label(&self) -> &'static str {
        match self {
            Self::Seven(_) => "ActivationPinSeven",
            Self::Eight(_) => "ActivationPinEight",
        }
    }
}

impl core::fmt::Debug for ActivationCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ActivationCode::{}([redacted])", self.variant_label())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn pin<const N: usize>(bytes: &[u8; N]) -> PinBytes {
        PinBytes::try_from(*bytes).expect("valid test PIN")
    }

    #[test]
    fn debug_does_not_leak_bytes() {
        let p = pin(b"1234");
        let s = format!("{p:?}");
        assert_eq!(s, "PinBytes([redacted])");
    }

    #[test]
    fn len_tracks_inner() {
        let p = pin(b"1234");
        assert_eq!(p.digit_count(), 4);
    }

    #[test]
    fn rejects_empty_short_and_long_inputs() {
        assert!(matches!(
            PinBytes::new(Vec::new()),
            Err(PinRoleError::Empty)
        ));
        assert!(matches!(
            PinBytes::try_from(*b"123"),
            Err(PinRoleError::WrongLength {
                expected_min: PinBytes::MIN_LENGTH,
                expected_max: PinBytes::MAX_LENGTH,
            })
        ));
        assert!(matches!(
            PinBytes::try_from([b'1'; PinBytes::MAX_LENGTH + 1]),
            Err(PinRoleError::WrongLength {
                expected_min: PinBytes::MIN_LENGTH,
                expected_max: PinBytes::MAX_LENGTH,
            })
        ));
    }

    #[test]
    fn rejects_non_digit_input() {
        assert!(matches!(
            PinBytes::try_from(*b"12a4"),
            Err(PinRoleError::NonDigit)
        ));
    }

    #[test]
    fn as_bytes_returns_input() {
        let p = pin(b"1234");
        assert_eq!(p.as_bytes(), b"1234");
    }

    #[test]
    fn puk_accepts_eight_digits() {
        let p = Puk::new(pin(b"12345678")).expect("eight-digit PUK is valid");
        assert_eq!(p.digit_count(), 8);
        assert_eq!(p.as_bytes(), b"12345678");
    }

    #[test]
    fn puk_accepts_twelve_digits() {
        let p = Puk::new(pin(b"123456789012")).expect("twelve-digit PUK is valid");
        assert_eq!(p.digit_count(), 12);
        assert_eq!(p.as_bytes(), b"123456789012");
    }

    #[test]
    fn puk_rejects_lengths_below_eight() {
        // Seven digits is the new-card single-use activation code, not a
        // PUK; the PUK is eight to twelve digits.
        assert!(matches!(
            Puk::new(pin(b"1234567")),
            Err(PinRoleError::WrongLength {
                expected_min: Puk::MIN_LENGTH,
                expected_max: Puk::MAX_LENGTH,
            })
        ));
        assert!(matches!(
            Puk::new(pin(b"123456")),
            Err(PinRoleError::WrongLength {
                expected_min: Puk::MIN_LENGTH,
                expected_max: Puk::MAX_LENGTH,
            })
        ));
    }

    #[test]
    fn pin_bytes_rejects_letter_before_puk_construction() {
        assert!(matches!(
            PinBytes::try_from(*b"1234567a"),
            Err(PinRoleError::NonDigit)
        ));
    }

    #[test]
    fn activation_pin_seven_accepts_seven_digits() {
        let a =
            ActivationPinSeven::new(pin(b"1234567")).expect("seven-digit activation PIN is valid");
        assert_eq!(a.digit_count(), 7);
    }

    #[test]
    fn activation_pin_seven_rejects_eight_digits() {
        assert!(matches!(
            ActivationPinSeven::new(pin(b"12345678")),
            Err(PinRoleError::WrongLength {
                expected_min: ActivationPinSeven::LENGTH,
                expected_max: ActivationPinSeven::LENGTH,
            })
        ));
    }

    #[test]
    fn activation_pin_eight_accepts_eight_digits() {
        let a =
            ActivationPinEight::new(pin(b"12345678")).expect("eight-digit activation PIN is valid");
        assert_eq!(a.digit_count(), 8);
    }

    #[test]
    fn activation_pin_eight_rejects_seven_digits() {
        assert!(matches!(
            ActivationPinEight::new(pin(b"1234567")),
            Err(PinRoleError::WrongLength {
                expected_min: ActivationPinEight::LENGTH,
                expected_max: ActivationPinEight::LENGTH,
            })
        ));
    }

    #[test]
    fn activation_code_seven_variant() {
        let a =
            ActivationPinSeven::new(pin(b"1234567")).expect("seven-digit activation PIN is valid");
        let c = ActivationCode::Seven(a);
        assert_eq!(c.variant_label(), "ActivationPinSeven");
        assert_eq!(c.as_bytes(), b"1234567");
    }

    #[test]
    fn activation_code_eight_variant() {
        let a =
            ActivationPinEight::new(pin(b"12345678")).expect("eight-digit activation PIN is valid");
        let c = ActivationCode::Eight(a);
        assert_eq!(c.variant_label(), "ActivationPinEight");
        assert_eq!(c.as_bytes(), b"12345678");
    }

    #[test]
    fn puk_debug_redacts() {
        let p = Puk::new(pin(b"12345678")).expect("eight-digit PUK is valid");
        assert_eq!(format!("{p:?}"), "Puk([redacted])");
    }

    #[test]
    fn activation_pin_seven_debug_redacts() {
        let a =
            ActivationPinSeven::new(pin(b"1234567")).expect("seven-digit activation PIN is valid");
        assert_eq!(format!("{a:?}"), "ActivationPinSeven([redacted])");
    }

    #[test]
    fn activation_pin_eight_debug_redacts() {
        let a =
            ActivationPinEight::new(pin(b"12345678")).expect("eight-digit activation PIN is valid");
        assert_eq!(format!("{a:?}"), "ActivationPinEight([redacted])");
    }

    #[test]
    fn activation_code_debug_redacts_and_labels_variant() {
        let s = ActivationCode::Seven(
            ActivationPinSeven::new(pin(b"1234567")).expect("seven-digit activation PIN is valid"),
        );
        assert_eq!(
            format!("{s:?}"),
            "ActivationCode::ActivationPinSeven([redacted])"
        );
        let e = ActivationCode::Eight(
            ActivationPinEight::new(pin(b"12345678")).expect("eight-digit activation PIN is valid"),
        );
        assert_eq!(
            format!("{e:?}"),
            "ActivationCode::ActivationPinEight([redacted])"
        );
    }

    #[test]
    fn pin_role_error_debug_does_not_leak_candidate_length_or_offset() {
        let err = validate_digits(b"12", PinBytes::MIN_LENGTH, PinBytes::MAX_LENGTH)
            .expect_err("fixture is below minimum length");
        let expected_debug = format!(
            "WrongLength {{ expected_min: {}, expected_max: {} }}",
            PinBytes::MIN_LENGTH,
            PinBytes::MAX_LENGTH
        );
        assert_eq!(format!("{err:?}"), expected_debug);

        let err_non_digit = validate_digits(b"12a4", PinBytes::MIN_LENGTH, PinBytes::MAX_LENGTH)
            .expect_err("fixture contains a non-digit byte");
        assert_eq!(format!("{err_non_digit:?}"), "NonDigit");
    }

    #[test]
    fn pin_role_error_display_is_always_shape_only() {
        let err_empty = validate_digits(b"", PinBytes::MIN_LENGTH, PinBytes::MAX_LENGTH)
            .expect_err("fixture is empty");
        assert_eq!(err_empty.to_string(), "PIN code cannot be empty");

        let err_wrong_len = validate_digits(b"12", PinBytes::MIN_LENGTH, PinBytes::MAX_LENGTH)
            .expect_err("fixture is below minimum length");
        let expected_wrong_len = format!(
            "PIN code wrong length: expected {}-{} digits",
            PinBytes::MIN_LENGTH,
            PinBytes::MAX_LENGTH
        );
        assert_eq!(err_wrong_len.to_string(), expected_wrong_len);

        let err_exact_len = validate_digits(
            b"12",
            ActivationPinSeven::LENGTH,
            ActivationPinSeven::LENGTH,
        )
        .expect_err("fixture is below exact length");
        let expected_exact_len = format!(
            "PIN code wrong length: expected exactly {} digits",
            ActivationPinSeven::LENGTH
        );
        assert_eq!(err_exact_len.to_string(), expected_exact_len);

        let err_non_digit = validate_digits(b"12a4", PinBytes::MIN_LENGTH, PinBytes::MAX_LENGTH)
            .expect_err("fixture contains a non-digit byte");
        assert_eq!(
            err_non_digit.to_string(),
            "PIN code must be ASCII digits only"
        );
    }
}
