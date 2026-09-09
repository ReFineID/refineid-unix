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

//! `BrainpoolP384r1` elliptic curve, RFC 5639 sec.3.6.
//!
//! Why an in-tree implementation:
//!
//! - `RustCrypto/elliptic-curves` does not ship Brainpool curves at
//!   the toolchain version this project targets; the `brainpool`
//!   crate on crates.io is unmaintained.
//! - PACE on the FINEID card uses `BrainpoolP384r1` specifically
//!   (per FINEID S4-2 sec.4 and `EF.CardAccess` on real cards).
//! - Linking `BoringSSL` just for Brainpool would re-introduce the
//!   `OpenSSL` / `CCryptoBoringSSL` collision that was already
//!   navigated on the iOS side. Pure Rust avoids it.
//!
//! Implementation:
//!
//! - Field arithmetic via `crypto_bigint::ConstMontyForm` with the
//!   Brainpool prime as the modulus; `crypto-bigint`'s Montgomery
//!   form gives add, sub, mul, square, invert in constant time.
//! - Affine point coordinates are stored as `U384`; arithmetic ops
//!   lift to Montgomery form, do the work, lower back. Cheap
//!   (sub-microsecond per conversion) and avoids exposing the
//!   `ConstMontyParams` machinery in the public API.
//! - Side-channel posture: scalar multiplication is the standard
//!   double-and-add, which leaks the bit count of the scalar
//!   through timing. Acceptable for v0.1 because PACE keys are
//!   ephemeral single-use; a constant-time scalar multiplication
//!   (e.g. Montgomery ladder over short Weierstrass) is a known
//!   hardening item.
//!
//! Validated by two property tests against the curve generator:
//! `n*G = infinity` (subgroup order) and `(a+b)*G = a*G + b*G`
//! (group homomorphism). Together they rule out almost every
//! plausible arithmetic bug without externally sourced test
//! vectors.
//!
//! Consumed by [`crate::pace`] and [`crate::ca`].

use crypto_bigint::{U384, const_monty_params, modular::ConstMontyForm};
use subtle::ConstantTimeEq;

// Curve parameters (RFC 5639 sec.3.6) ---------------------------------------

/// Field prime `p`.
pub const P_HEX: &str = "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53";

/// Curve coefficient `a` in `y^2 = x^3 + a*x + b (mod p)`.
pub const A_HEX: &str = "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826";

/// Curve coefficient `b`.
pub const B_HEX: &str = "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11";

/// Generator x-coordinate.
pub const G_X_HEX: &str = "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E";

/// Generator y-coordinate.
pub const G_Y_HEX: &str = "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315";

/// Subgroup order `n`.
pub const N_HEX: &str = "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565";

/// Cofactor -- always 1 for `BrainpoolP384r1`.
pub const H: u32 = 1;

/// Field prime `p` for `BrainpoolP384r1` as a `U384` constant.
#[must_use]
#[inline]
pub const fn p() -> U384 {
    U384::from_be_hex(P_HEX)
}

/// Curve coefficient `a` for `BrainpoolP384r1` as a `U384`.
#[must_use]
#[inline]
pub const fn a() -> U384 {
    U384::from_be_hex(A_HEX)
}

/// Curve coefficient `b` for `BrainpoolP384r1` as a `U384`.
#[must_use]
#[inline]
pub const fn b() -> U384 {
    U384::from_be_hex(B_HEX)
}

/// Subgroup order `n` for `BrainpoolP384r1` as a `U384`.
#[must_use]
#[inline]
pub const fn n() -> U384 {
    U384::from_be_hex(N_HEX)
}

// Field arithmetic over GF(p) via Montgomery form ------------------------

const_monty_params!(BrainpoolPrime, U384, P_HEX);

/// Field element in GF(p) for `brainpoolP384r1`, represented in
/// Montgomery form so squaring and multiplication share the
/// constant-time reduction path of [`crypto_bigint`]. The choice
/// of Montgomery (rather than Barrett) keeps the inner loop free
/// of data-dependent branches -- a side-channel requirement for
/// PACE-CAM and chip-authentication on the FINEID curve.
type Fe = ConstMontyForm<BrainpoolPrime, { U384::LIMBS }>;

/// Lift a big-integer residue into Montgomery form.
///
/// Preserves constant-time semantics from [`ConstMontyForm::new`].
/// Used by the arithmetic constructors below; the indirection
/// exists so callers don't have to spell out the Montgomery
/// parameter type at every use site.
#[inline]
const fn fe(x: &U384) -> Fe {
    Fe::new(x)
}

/// Montgomery field element for the constant `3`, used in the
/// EC doubling formula `3 * X^2 + a * Z^4`.
///
/// Not declared `const fn` because `U384::from(3u32)` is not yet
/// const in crypto-bigint 0.7 even though the rest of the call
/// chain is. Flip to `const fn` once the upstream gains a const
/// `from(u32)`; the function body needs no other change.
#[inline]
fn fe_three() -> Fe {
    fe(&U384::from(3_u32))
}

/// Montgomery field element for the curve coefficient `a` of
/// `brainpoolP384r1` (RFC 5639 §3.6).
///
/// Pre-lifted once at call so the EC formulas don't re-encode
/// the curve constant on every doubling.
#[inline]
const fn fe_a() -> Fe {
    fe(&a())
}

/// Montgomery field element for the curve coefficient `b` of
/// `brainpoolP384r1` (RFC 5639 §3.6).
///
/// Pre-lifted; see [`fe_a`] for the rationale.
#[inline]
const fn fe_b() -> Fe {
    fe(&b())
}

// Affine point representation --------------------------------------------

/// Affine point on `BrainpoolP384r1`.
///
/// `coords == None` is the point at infinity (additive identity);
/// `coords == Some((x, y))` is a finite point. Coordinates are
/// stored in canonical form (less than `p`); arithmetic ops lift to
/// Montgomery for the actual computation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct AffinePoint {
    /// Coordinates of the affine point. `None` is the point at
    /// infinity (additive identity); `Some((x, y))` is a finite
    /// point with both coordinates in canonical form (less than
    /// `p`).
    pub coords: Option<(U384, U384)>,
}

/// A `BrainpoolP384r1` point in SEC1 uncompressed encoding:
/// `04 || X || Y`, 97 bytes (1 tag byte + two 48-byte big-endian
/// coordinates; SEC1 v2 §2.3.3).
///
/// The **only** constructor is [`AffinePoint::encode_uncompressed`],
/// so a value of this type is proof of a finite, on-curve point's
/// canonical encoding -- not a bare `[u8; 97]` that could be
/// swapped with any other 97-byte buffer (e.g. a zeroed scratch
/// array). Passes straight to the BER encoders via its
/// [`AsRef<[u8]>`] impl.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sec1UncompressedPoint([u8; 97]);

impl Sec1UncompressedPoint {
    /// Borrow the 97 encoded bytes (`04 || X || Y`).
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 97] {
        &self.0
    }
}

impl AsRef<[u8]> for Sec1UncompressedPoint {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AffinePoint {
    /// Point at infinity (additive identity).
    pub const INFINITY: Self = Self { coords: None };

    /// Curve generator `G = (Gx, Gy)` for `BrainpoolP384r1` per
    /// RFC 5639 §3.4.
    #[inline]
    #[must_use]
    pub const fn generator() -> Self {
        Self {
            coords: Some((U384::from_be_hex(G_X_HEX), U384::from_be_hex(G_Y_HEX))),
        }
    }

    /// `true` when this is the point at infinity.
    #[inline]
    #[must_use]
    pub const fn is_infinity(&self) -> bool {
        self.coords.is_none()
    }

    /// Check the curve equation `y^2 == x^3 + a*x + b (mod p)`.
    /// Used as an invariant check after decode and as a property
    /// test.
    #[inline]
    #[must_use]
    pub fn is_on_curve(&self) -> bool {
        let Some((x_u, y_u)) = self.coords.as_ref() else {
            return true; // infinity is trivially on-curve
        };
        let x = fe(x_u);
        let y = fe(y_u);
        let lhs = y.square();
        let rhs = x.square().mul(&x).add(&fe_a().mul(&x)).add(&fe_b());
        lhs.retrieve() == rhs.retrieve()
    }

    /// SEC1 point-encoding tag for the uncompressed form
    /// (`04 || X || Y`), SEC1 v2 §2.3.3.
    const SEC1_UNCOMPRESSED_TAG: u8 = 0x04;

    /// Encode this point in SEC1 uncompressed form (`04 || X || Y`).
    ///
    /// `None` for the point at infinity (additive identity): it has
    /// no finite affine coordinates, so no uncompressed encoding.
    /// Callers in PACE / Chip Auth treat that as a hard fail rather
    /// than transmitting a degenerate point.
    #[inline]
    #[must_use]
    pub fn encode_uncompressed(&self) -> Option<Sec1UncompressedPoint> {
        let (x, y) = self.coords?;
        let mut out = [0_u8; 97];
        out[0] = Self::SEC1_UNCOMPRESSED_TAG;
        out[1..49].copy_from_slice(&x.to_be_bytes());
        out[49..97].copy_from_slice(&y.to_be_bytes());
        Some(Sec1UncompressedPoint(out))
    }

    /// Decode the SEC1 uncompressed form. Returns `None` on a
    /// wrong leading tag, mismatched length, or a point not on the
    /// curve.
    #[must_use]
    pub(crate) fn decode_uncompressed(bytes: &[u8]) -> Option<Self> {
        let arr: &[u8; 97] = bytes.try_into().ok()?;
        if *arr.first()? != Self::SEC1_UNCOMPRESSED_TAG {
            return None;
        }
        let x = U384::from_be_slice(arr.get(1..49)?);
        let y = U384::from_be_slice(arr.get(49..97)?);
        let pt = Self {
            coords: Some((x, y)),
        };
        pt.is_on_curve().then_some(pt)
    }

    /// Negation: `-(x, y) = (x, -y mod p)`. The identity stays
    /// invariant.
    #[inline]
    #[must_use]
    pub const fn neg(&self) -> Self {
        match &self.coords {
            None => Self::INFINITY,
            Some((x, y)) => {
                let neg_y = fe(y).neg().retrieve();
                Self {
                    coords: Some((*x, neg_y)),
                }
            }
        }
    }

    /// Point doubling. Standard affine formula:
    ///
    /// ```text
    /// lambda = (3*x^2 + a) * (2*y)^-1  mod p
    /// x' = lambda^2 - 2*x  mod p
    /// y' = lambda*(x - x') - y  mod p
    /// ```
    #[inline]
    #[must_use]
    pub fn double(&self) -> Self {
        let Some((x_u, y_u)) = &self.coords else {
            return Self::INFINITY;
        };
        let x = fe(x_u);
        let y = fe(y_u);

        // 2y == 0 => point of order 2 => doubling gives infinity. On
        // BrainpoolP384r1 there is no point of order 2 (since `n`
        // is odd and prime), so this branch is unreachable for
        // valid points. Kept for safety.
        let two_y = y.add(&y);
        let Some(two_y_inv): Option<Fe> = Option::from(two_y.invert()) else {
            return Self::INFINITY;
        };

        let three_x_sq = x.square().mul(&fe_three());
        let lambda = three_x_sq.add(&fe_a()).mul(&two_y_inv);

        let two_x = x.add(&x);
        let x3 = lambda.square().sub(&two_x);
        let y3 = lambda.mul(&x.sub(&x3)).sub(&y);

        Self {
            coords: Some((x3.retrieve(), y3.retrieve())),
        }
    }

    /// Point addition. Falls back to [`Self::double`] when `self ==
    /// other`; returns [`Self::INFINITY`] when `self == -other`.
    #[must_use]
    pub(crate) fn add(&self, other: &Self) -> Self {
        let Some((x1_u, y1_u)) = &self.coords else {
            return *other;
        };
        let Some((x2_u, y2_u)) = &other.coords else {
            return *self;
        };

        if x1_u == x2_u {
            if y1_u == y2_u {
                return self.double();
            }
            // x equal, y differ => y2 = -y1 => sum is infinity.
            return Self::INFINITY;
        }

        let x1 = fe(x1_u);
        let y1 = fe(y1_u);
        let x2 = fe(x2_u);
        let y2 = fe(y2_u);

        let Some(dx_inv): Option<Fe> = Option::from(x2.sub(&x1).invert()) else {
            // unreachable if x1 != x2
            return Self::INFINITY;
        };
        let lambda = y2.sub(&y1).mul(&dx_inv);

        let x3 = lambda.square().sub(&x1).sub(&x2);
        let y3 = lambda.mul(&x1.sub(&x3)).sub(&y1);

        Self {
            coords: Some((x3.retrieve(), y3.retrieve())),
        }
    }

    /// Scalar multiplication via double-and-add. Not constant
    /// time; see module-level docs.
    #[must_use]
    pub(crate) fn scalar_mul(&self, scalar: &U384) -> Self {
        let bytes = scalar.to_be_bytes();
        let mut result = Self::INFINITY;
        let mut started = false;
        for &byte in bytes.iter() {
            for bit_idx in (0_u32..8_u32).rev() {
                if started {
                    result = result.double();
                }
                let bit = (byte >> bit_idx) & 1;
                if bit == 1 {
                    if started {
                        result = result.add(self);
                    } else {
                        result = *self;
                        started = true;
                    }
                }
            }
        }
        result
    }
}

impl ConstantTimeEq for AffinePoint {
    #[inline]
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        match (&self.coords, &other.coords) {
            (None, None) => subtle::Choice::from(1),
            (None, Some(_)) | (Some(_), None) => subtle::Choice::from(0),
            (Some((x1, y1)), Some((x2, y2))) => {
                let xe = x1.to_be_bytes().ct_eq(&x2.to_be_bytes());
                let ye = y1.to_be_bytes().ct_eq(&y2.to_be_bytes());
                xe & ye
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use core::ops::Add as _;

    use super::{AffinePoint, a, b, n, p};
    use crypto_bigint::U384;

    #[test]
    fn curve_params_parse() {
        const HIGH_BIT_SET: u8 = 0x80;
        // Trip each constructor to confirm the hex literals parse;
        // results are unused but the calls themselves are the test.
        let _p: U384 = p();
        let _a: U384 = a();
        let _b: U384 = b();
        let _n: U384 = n();
        // For BrainpoolP384r1, p > 2^383, so the high bit of the
        // 48-byte big-endian encoding is set. Cheap sanity check
        // that the hex literal hasn't been truncated by mistake.
        assert!(p().to_be_bytes().first().copied().unwrap_or(0) >= HIGH_BIT_SET);
    }

    #[test]
    fn generator_is_on_curve() {
        let g = AffinePoint::generator();
        assert!(g.is_on_curve());
    }

    #[test]
    fn generator_round_trips_through_sec1() {
        let g = AffinePoint::generator();
        let encoded = g.encode_uncompressed();
        assert!(encoded.is_some(), "generator encodes to uncompressed SEC1");
        let bytes = encoded.map_or([0; 97], |p| *p.as_bytes());
        let round = AffinePoint::decode_uncompressed(&bytes);
        assert!(
            round.is_some(),
            "encoded generator round-trips through decode"
        );
        assert_eq!(round.unwrap_or(AffinePoint::INFINITY), g);
    }

    #[test]
    fn negation_is_involutive() {
        let g = AffinePoint::generator();
        assert_eq!(g.neg().neg(), g);
        assert!(g.add(&g.neg()).is_infinity());
    }

    #[test]
    fn doubling_is_on_curve() {
        let g = AffinePoint::generator();
        let g2 = g.double();
        assert!(g2.is_on_curve());
        assert_ne!(g2, g);
    }

    #[test]
    fn addition_matches_doubling() {
        let g = AffinePoint::generator();
        let g_plus_g = g.add(&g);
        let g_dbl = g.double();
        assert_eq!(g_plus_g, g_dbl);
    }

    #[test]
    fn scalar_mul_one_is_identity() {
        let g = AffinePoint::generator();
        let one = U384::from(1_u32);
        assert_eq!(g.scalar_mul(&one), g);
    }

    #[test]
    fn scalar_mul_two_equals_double() {
        let g = AffinePoint::generator();
        let two = U384::from(2_u32);
        assert_eq!(g.scalar_mul(&two), g.double());
    }

    #[test]
    fn scalar_mul_three_equals_double_plus_g() {
        let g = AffinePoint::generator();
        let three = U384::from(3_u32);
        let expected = g.double().add(&g);
        assert_eq!(g.scalar_mul(&three), expected);
    }

    /// `n * G = infinity`. The single most powerful property test
    /// for an elliptic-curve implementation -- the only way this
    /// passes by accident is if the curve order, the generator,
    /// and every arithmetic op collectively conspire, which is
    /// vanishingly unlikely.
    #[test]
    fn generator_times_n_is_infinity() {
        let g = AffinePoint::generator();
        let result = g.scalar_mul(&n());
        assert!(
            result.is_infinity(),
            "n*G should be infinity but got coords {:?}",
            result.coords
        );
    }

    /// Group homomorphism: `(a + b)*G = a*G + b*G`. Catches
    /// additive errors that the `n*G` test would not (a sign flip
    /// in doubling that gets cancelled going around the cycle, for
    /// example).
    #[test]
    fn scalar_mul_is_homomorphic() {
        let g = AffinePoint::generator();
        let a = U384::from(0x1234_5678_u64);
        let b = U384::from(0xDEAD_BEEF_u64);
        let sum = a.add(&b);
        let lhs = g.scalar_mul(&sum);
        let rhs = g.scalar_mul(&a).add(&g.scalar_mul(&b));
        assert_eq!(lhs, rhs);
    }
}
