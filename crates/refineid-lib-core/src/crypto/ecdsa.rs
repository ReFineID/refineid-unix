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

//! Generic ECDSA-over-prime-field signature verification.
//!
//! Curve parameters arrive at runtime via [`Curve`] -- the
//! caller supplies the field prime `p`, the curve coefficients
//! `a` / `b`, the base point `G` (as affine `(Gx, Gy)`), and
//! the group order `n`. This lets the same verifier handle:
//!
//! - Named curves (P-256, P-384, P-521, brainpoolP*) when the
//!   caller looks them up from a constant table.
//! - **Explicit-parameter curves** carried in the cert's SPKI,
//!   which is what Finnish CSCA-signed eMRTD DSCs use today
//!   (brainpoolP512r1 transmitted in `prime-field` form, not by
//!   OID).
//!
//! Verify-only: this module never holds a private key. Builds on
//! `crypto-bigint::BoxedUint` + `BoxedMontyForm` for
//! arbitrary-precision modular arithmetic.
//!
//! Constant-time is **not** a goal: we only see CA-published
//! signatures, no secret-dependent branching surface here.

#![expect(
    clippy::similar_names,
    reason = "EC coordinate naming follows the math convention in the EC literature (Hankerson/Menezes/Vanstone, IEEE 1363, RFC 5480): px / py for point P's coordinates, qx / qy for Q's, gx / gy for the generator G's, with the `_mont` / `_m` suffix denoting Montgomery form. The one-letter coordinate distinction is the notation, not an accident; renaming to `point_x_montgomery` etc. would obscure the textbook mapping that lets a cryptographer read the code against the spec."
)]

use crypto_bigint::{
    BoxedUint, Odd, Resize as _,
    modular::{BoxedMontyForm, BoxedMontyParams},
};

use crate::ber::{BerTlv, BerTlvAny, BerTlvIter, Integer, OctetString, Oid, Sequence};
use crate::crypto::container::{EcdsaDer, EcdsaP256, EcdsaP384, Signature};
use crate::crypto::digest::{Sha1, Sha224, Sha256, Sha384, Sha512};
use crate::hex::Hex;
use crate::oid::{Oid as KnownOid, known};

/// SEC1 uncompressed-point tag byte.
const SEC1_UNCOMPRESSED_TAG: u8 = 0x04;
/// DER INTEGER sign-padding byte.
const DER_SIGN_PAD: u8 = 0;
/// One-byte DER INTEGER sign-padding prefix.
const DER_SIGN_PAD_PREFIX: [u8; 1] = [DER_SIGN_PAD];

/// Curve parameters in unsigned big-endian byte form.
///
/// Sizes don't have to match each other exactly -- the verifier
/// rounds them up to a common limb precision internally. Each
/// integer field carries any leading sign byte stripped (ASN.1
/// INTEGER form is **not** required; bare PKCS#1-style bytes
/// are fine).
#[derive(Debug, Clone)]
pub struct Curve {
    /// Field prime `p` (unsigned big-endian).
    pub p: Vec<u8>,
    /// Curve coefficient `a` (unsigned big-endian).
    pub a: Vec<u8>,
    /// Curve coefficient `b` (unsigned big-endian).
    pub b: Vec<u8>,
    /// X coordinate of the base point `G` (unsigned big-endian).
    pub gx: Vec<u8>,
    /// Y coordinate of the base point `G` (unsigned big-endian).
    pub gy: Vec<u8>,
    /// Subgroup order `n` (unsigned big-endian).
    pub n: Vec<u8>,
}

/// Error returned from the ECDSA verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaError {
    /// Curve modulus `p` is malformed (empty or even).
    BadModulus,
    /// Public key `(Q.x, Q.y)` was not on the curve or had the
    /// wrong encoding (we accept only the uncompressed
    /// `04 || X || Y` SEC1 form).
    BadPublicKey,
    /// Signature parse failed -- ECDSA signatures are DER
    /// `SEQUENCE { r INTEGER, s INTEGER }`.
    BadSignature,
    /// `r` or `s` not in `[1, n-1]`.
    SigOutOfRange,
    /// `s` had no inverse mod `n` (can't really happen for a
    /// valid signature; flagged for completeness).
    NotInvertible,
    /// Final compare: `r' != r mod n` -- the signature does not
    /// verify against the supplied public key and message.
    VerifyFailed,
}

impl core::fmt::Display for EcdsaError {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadModulus => write!(f, "ECDSA: curve modulus malformed"),
            Self::BadPublicKey => write!(f, "ECDSA: public key off-curve or bad encoding"),
            Self::BadSignature => write!(f, "ECDSA: signature SEQUENCE malformed"),
            Self::SigOutOfRange => write!(f, "ECDSA: r or s out of [1, n-1]"),
            Self::NotInvertible => write!(f, "ECDSA: s has no inverse mod n"),
            Self::VerifyFailed => write!(f, "ECDSA: verification rejected"),
        }
    }
}

impl core::error::Error for EcdsaError {}

/// Uncompressed SEC1 elliptic-curve point: `0x04 || X || Y`.
///
/// The constructor `Sec1UncompressedPoint::from_bytes` is the
/// trust boundary: it asserts the leading 0x04 marker, the even
/// body length, and a non-empty body. Compressed (`0x02` /
/// `0x03`) and hybrid (`0x06` / `0x07`) SEC1 forms are *not* a
/// `Sec1UncompressedPoint` -- this codebase only verifies
/// uncompressed-form keys (CSCA-published DSCs always ship
/// uncompressed).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sec1UncompressedPoint {
    /// SEC1 uncompressed-form payload: `0x04 || X || Y`, X and Y equal-length.
    bytes: Vec<u8>,
}

/// Parse error for `Sec1UncompressedPoint::from_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sec1ParseError {
    /// Buffer empty or doesn't start with the uncompressed-form
    /// magic byte 0x04.
    BadFormatByte,
    /// `04 || X || Y` requires `X` and `Y` of equal length;
    /// odd-length body or empty body are both rejected here.
    BadBodyLength,
}

impl core::fmt::Display for Sec1ParseError {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadFormatByte => write!(f, "SEC1 point: expected uncompressed-form leading 0x04"),
            Self::BadBodyLength => write!(f, "SEC1 point: body must be 2*coord-len, > 0"),
        }
    }
}

impl core::error::Error for Sec1ParseError {}

impl Sec1UncompressedPoint {
    /// Wrap raw SEC1 bytes. Validates the leading 0x04 byte and
    /// the even-length body invariant.
    ///
    /// # Errors
    /// [`Sec1ParseError`] if the buffer is empty, doesn't start
    /// with 0x04, or has an odd-length body.
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Result<Self, Sec1ParseError> {
        if bytes.first().copied() != Some(SEC1_UNCOMPRESSED_TAG) {
            return Err(Sec1ParseError::BadFormatByte);
        }
        let body_len = bytes
            .len()
            .checked_sub(1)
            .ok_or(Sec1ParseError::BadFormatByte)?;
        if body_len == 0 || !body_len.is_multiple_of(2) {
            return Err(Sec1ParseError::BadBodyLength);
        }
        Ok(Self { bytes })
    }
}

impl Sec1UncompressedPoint {
    /// Borrow the underlying SEC1 bytes (`04 || X || Y`).
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Consume the wrapper and return the owned SEC1 bytes.
    #[inline]
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Length of the encoded point in bytes (`1 + 2 * coord_len`).
    /// Tier 0 `usize`; arithmetic count.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// `true` when the underlying buffer is empty (constructor
    /// rejects this; method retained for API symmetry).
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Internal handle for one curve. Holds the precomputed
/// Montgomery params for `p` and for `n`, plus the base point
/// in affine form.
struct CurveCtx {
    /// Bit precision used for `p`-side arithmetic (multiple of 64).
    bits_p: u32,
    /// Bit precision used for `n`-side arithmetic.
    bits_n: u32,
    /// Montgomery parameters for the prime field modulus `p`.
    p_params: BoxedMontyParams,
    /// Montgomery parameters for the subgroup order `n`.
    n_params: BoxedMontyParams,
    /// Weierstrass coefficient `a` in `y^2 = x^3 + ax + b`.
    a: BoxedUint,
    /// Weierstrass coefficient `b` in `y^2 = x^3 + ax + b`.
    b: BoxedUint,
    /// Subgroup order `n`, in non-Montgomery form for boundary checks.
    n_uint: BoxedUint,
    /// Base point `G` in affine coordinates.
    g: AffinePoint,
}

/// Affine point on a short-Weierstrass curve, with an explicit
/// sentinel for the point at infinity.
///
/// SEC1 §2.3.3. Using `Option<(x, y)>` for the infinity sentinel
/// keeps the type total without smuggling an out-of-band value
/// (e.g. `x = 0`) that would collide with a legitimate
/// coordinate on some curves.
#[derive(Clone)]
struct AffinePoint {
    /// `None` is the point at infinity.
    xy: Option<(BoxedUint, BoxedUint)>,
}

impl AffinePoint {
    /// Construct the additive identity (point at infinity).
    ///
    /// SEC1 §2.2.1 -- O is the identity of the EC group; required
    /// as the seed for scalar multiplication's binary-ladder
    /// initial accumulator.
    const fn infinity() -> Self {
        Self { xy: None }
    }
    /// Whether this point is the additive identity.
    ///
    /// The doubling and addition formulae have a degenerate case
    /// when either operand is `O`; callers short-circuit through
    /// this predicate rather than hitting a divide-by-zero in
    /// the lambda computation.
    const fn is_infinity(&self) -> bool {
        self.xy.is_none()
    }
}

impl Curve {
    /// Decode the `ECParameters` SEQUENCE body of an explicit-
    /// parameter EC `SubjectPublicKeyInfo` into a [`Curve`].
    ///
    /// RFC 5480 §2.1.1 / SEC1 §C.2. Only `prime-field`
    /// curves are recognised here -- characteristic-two fields
    /// are out of scope for FINEID. The optional `seed` BIT
    /// STRING inside the `Curve` SEQUENCE is parsed-and-ignored;
    /// it is auditing metadata, not a public-key component.
    fn parse_explicit(seq_value: &[u8]) -> Result<Self, EcdsaError> {
        // ECParameters ::= SEQUENCE {
        //   version INTEGER (= 1),
        //   fieldID SEQUENCE { OID prime-field, prime INTEGER },
        //   curve   SEQUENCE { a OCTET STRING, b OCTET STRING, seed? },
        //   base    OCTET STRING (uncompressed point),
        //   order   INTEGER,
        //   cofactor INTEGER OPTIONAL
        // }
        let mut it = BerTlvIter::new(seq_value);
        let _version = EcdsaHelpers::next_child(&mut it)?
            .expect::<Integer>()
            .map_err(EcdsaHelpers::bad_modulus)?;
        let field_id = EcdsaHelpers::next_child(&mut it)?
            .expect::<Sequence>()
            .map_err(EcdsaHelpers::bad_modulus)?;
        let mut field_iter = field_id.iter_children();
        let field_type = EcdsaHelpers::next_child(&mut field_iter)?
            .expect::<Oid>()
            .map_err(EcdsaHelpers::bad_modulus)?;
        if field_type.value != known::PRIME_FIELD.as_bytes() {
            return Err(EcdsaError::BadModulus);
        }
        let prime_tlv = EcdsaHelpers::next_child(&mut field_iter)?
            .expect::<Integer>()
            .map_err(EcdsaHelpers::bad_modulus)?;
        let p = EcdsaHelpers::strip_sign(prime_tlv.value);
        let curve_seq = EcdsaHelpers::next_child(&mut it)?
            .expect::<Sequence>()
            .map_err(EcdsaHelpers::bad_modulus)?;
        let mut curve_it = curve_seq.iter_children();
        let a_tlv = EcdsaHelpers::next_child(&mut curve_it)?
            .expect::<OctetString>()
            .map_err(EcdsaHelpers::bad_modulus)?;
        let a = a_tlv.value.to_vec();
        let b_tlv = EcdsaHelpers::next_child(&mut curve_it)?
            .expect::<OctetString>()
            .map_err(EcdsaHelpers::bad_modulus)?;
        let b = b_tlv.value.to_vec();
        // Optional seed BIT STRING -- ignore.

        let base_tlv = EcdsaHelpers::next_child(&mut it)?
            .expect::<OctetString>()
            .map_err(EcdsaHelpers::bad_modulus)?;
        if base_tlv.value.first().copied() != Some(SEC1_UNCOMPRESSED_TAG) {
            return Err(EcdsaError::BadModulus);
        }
        let g_body = base_tlv.value.get(1..).ok_or(EcdsaError::BadModulus)?;
        if !g_body.len().is_multiple_of(2) || g_body.is_empty() {
            return Err(EcdsaError::BadModulus);
        }
        // g_body.len() is even (checked above); bit-shift sidesteps
        // clippy::integer_division, exact for even values.
        let half: usize = g_body.len() >> 1_u32;
        let (gx_bytes, gy_bytes) = g_body.split_at(half);
        let gx = gx_bytes.to_vec();
        let gy = gy_bytes.to_vec();
        let order_tlv = EcdsaHelpers::next_child(&mut it)?
            .expect::<Integer>()
            .map_err(EcdsaHelpers::bad_modulus)?;
        let n = EcdsaHelpers::strip_sign(order_tlv.value);
        Ok(Self { p, a, b, gx, gy, n })
    }
}

/// Helpers hosted on a unit struct (typing-discipline: no
/// free fns with borrowed parameters; see
/// `doc/typing-discipline.md`).
struct EcdsaHelpers;

impl EcdsaHelpers {
    /// Round a byte length up to the next 64-bit boundary, in
    /// bits, with a floor of 64.
    ///
    /// `BoxedUint` needs its bit-width specified at construction
    /// and represents the value in 64-bit limbs; this helper
    /// picks the smallest representable bit-width that fits
    /// `bytes`. Saturates rather than panicking on absurd input
    /// (`u32::MAX`-byte slice) so the parser-side surface never
    /// aborts.
    fn bits_for_len(byte_len: usize) -> u32 {
        let nominal = u32::try_from(byte_len)
            .unwrap_or(u32::MAX)
            .saturating_mul(8);
        nominal.next_multiple_of(64).max(64)
    }

    /// Decode a big-endian integer slice into a `BoxedUint` of
    /// the given bit width.
    ///
    /// Wraps the upstream conversion to map width-mismatch errors
    /// to a domain-specific [`EcdsaError::BadModulus`] -- the
    /// only legitimate failure here is a curve constant that
    /// doesn't fit the limb count `bits_for` chose for it.
    fn boxed(bytes: &[u8], bits: u32) -> Result<BoxedUint, EcdsaError> {
        BoxedUint::from_be_slice(bytes, bits).map_err(|_e| EcdsaError::BadModulus)
    }
}

// Variable names `px`/`py`, `qx`/`qy`, and their Montgomery
// counterparts (`px_m`, `py_m`, `qx_m`, `qy_m`, `px_mont`,
// `py_mont`) match the affine short-Weierstrass formulae as
// written in SEC1 / RFC 6979 -- renaming them would obscure the
// cross-reference.
impl CurveCtx {
    /// Build a precomputed verification context from a
    /// runtime-supplied [`Curve`].
    ///
    /// SEC1 §2.2.1 -- the Montgomery parameters depend only on
    /// `p` and `n`, so doing the conversion once per curve and
    /// then sharing the `CurveCtx` across many verifications is
    /// constant-folded work. Returns
    /// [`EcdsaError::BadModulus`] if `p` or `n` are even
    /// (Montgomery requires odd modulus) or if any constant is
    /// wider than the chosen `bits_for` width.
    fn new(curve: &Curve) -> Result<Self, EcdsaError> {
        let bits_p = EcdsaHelpers::bits_for_len(curve.p.len());
        let bits_n = EcdsaHelpers::bits_for_len(curve.n.len());
        let p_uint = EcdsaHelpers::boxed(curve.p.as_slice(), bits_p)?;
        let n_uint = EcdsaHelpers::boxed(curve.n.as_slice(), bits_n)?;
        let a = EcdsaHelpers::boxed(curve.a.as_slice(), bits_p)?;
        let b = EcdsaHelpers::boxed(curve.b.as_slice(), bits_p)?;
        let gx = EcdsaHelpers::boxed(curve.gx.as_slice(), bits_p)?;
        let gy = EcdsaHelpers::boxed(curve.gy.as_slice(), bits_p)?;
        let p_odd: Odd<BoxedUint> = Option::from(Odd::new(p_uint)).ok_or(EcdsaError::BadModulus)?;
        let n_odd: Odd<BoxedUint> =
            Option::from(Odd::new(n_uint.clone())).ok_or(EcdsaError::BadModulus)?;
        let p_params = BoxedMontyParams::new(p_odd);
        let n_params = BoxedMontyParams::new(n_odd);
        Ok(Self {
            bits_p,
            bits_n,
            p_params,
            n_params,
            a,
            b,
            n_uint,
            g: AffinePoint { xy: Some((gx, gy)) },
        })
    }

    /// Lift `x` into Montgomery form modulo the field prime `p`.
    ///
    /// Used for coordinate-domain arithmetic (point doubling,
    /// addition, multiplication). The Montgomery params are
    /// shared across calls; the per-call work is the constant-
    /// time conversion only.
    fn p_mont(&self, x: &BoxedUint) -> BoxedMontyForm {
        BoxedMontyForm::new(x.clone(), &self.p_params)
    }
    /// Lift `x` into Montgomery form modulo the subgroup order
    /// `n`.
    ///
    /// Used for scalar-domain arithmetic (the ECDSA verify
    /// equation operates on `r`, `s`, `e mod n`). Distinct from
    /// [`Self::p_mont`] because `p` and `n` are different moduli
    /// with different Montgomery parameter sets.
    fn n_mont(&self, x: &BoxedUint) -> BoxedMontyForm {
        BoxedMontyForm::new(x.clone(), &self.n_params)
    }

    /// Point doubling on `y^2 = x^3 + ax + b`. Standard short
    /// Weierstrass formulae, affine coords.
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "BoxedMontyForm Add/Sub/Mul are GF(p) field ops with well-defined modular results; clippy's overflow heuristic doesn't apply to modular arithmetic."
    )]
    fn double(&self, p: &AffinePoint) -> AffinePoint {
        let Some((px, py)) = &p.xy else {
            return AffinePoint::infinity();
        };
        // py == 0 -> infinity.
        let py_mont = self.p_mont(py);
        let zero = self.p_mont(&BoxedUint::zero_with_precision(self.bits_p));
        if py_mont == zero {
            return AffinePoint::infinity();
        }
        // lambda = (3*px^2 + a) / (2*py)
        let three = self.p_mont(&BoxedUint::from(3_u32).resize(self.bits_p));
        let two = self.p_mont(&BoxedUint::from(2_u32).resize(self.bits_p));
        let a_mont = self.p_mont(&self.a);
        let px_mont = self.p_mont(px);
        let num = &(&three * &(&px_mont * &px_mont)) + &a_mont;
        // `2y` is invertible mod p: we just checked `py != 0`, p is
        // prime, and 2 is coprime with p (p is odd). If invert()
        // ever returns None anyway, fail closed by returning
        // infinity -- the subsequent verify step will reject.
        let Some(den_inv): Option<BoxedMontyForm> = Option::from((&two * &py_mont).invert()) else {
            return AffinePoint::infinity();
        };
        let lambda = &num * &den_inv;
        let lambda_sq = &lambda * &lambda;
        let rx = &(&lambda_sq - &px_mont) - &px_mont;
        let ry = &(&lambda * &(&px_mont - &rx)) - &py_mont;
        AffinePoint {
            xy: Some((rx.retrieve(), ry.retrieve())),
        }
    }

    /// Point addition (affine). Handles infinity + match cases.
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "BoxedMontyForm Add/Sub/Mul are GF(p) field ops with well-defined modular results; clippy's overflow heuristic doesn't apply to modular arithmetic."
    )]
    fn add(&self, p: &AffinePoint, q: &AffinePoint) -> AffinePoint {
        let (Some((px, py)), Some((qx, qy))) = (p.xy.as_ref(), q.xy.as_ref()) else {
            return if p.is_infinity() {
                q.clone()
            } else {
                p.clone()
            };
        };
        if px == qx {
            if py == qy {
                return self.double(p);
            }
            // P + (-P) = infinity.
            return AffinePoint::infinity();
        }
        let px_m = self.p_mont(px);
        let py_m = self.p_mont(py);
        let qx_m = self.p_mont(qx);
        let qy_m = self.p_mont(qy);
        let num = &qy_m - &py_m;
        // `qx - px` is non-zero (we just checked `px != qx`) so its
        // modular inverse exists for prime p. Fail closed otherwise.
        let Some(den_inv): Option<BoxedMontyForm> = Option::from((&qx_m - &px_m).invert()) else {
            return AffinePoint::infinity();
        };
        let lambda = &num * &den_inv;
        let lambda_sq = &lambda * &lambda;
        let rx = &(&lambda_sq - &px_m) - &qx_m;
        let ry = &(&lambda * &(&px_m - &rx)) - &py_m;
        AffinePoint {
            xy: Some((rx.retrieve(), ry.retrieve())),
        }
    }

    /// Scalar multiplication `k * P` using double-and-add (the
    /// constant-time hardening doesn't matter -- we only multiply
    /// scalars that came from the *signature*, no secrets).
    fn scalar_mul(&self, k: &BoxedUint, point: &AffinePoint) -> AffinePoint {
        if point.is_infinity() {
            return AffinePoint::infinity();
        }
        let mut acc = AffinePoint::infinity();
        let mut addend = point.clone();
        let bits = k.bits_vartime();
        for i in 0..bits {
            if k.bit_vartime(i) {
                acc = self.add(&acc, &addend);
            }
            addend = self.double(&addend);
        }
        acc
    }

    /// Test `Q.y^2 == Q.x^3 + a*Q.x + b mod p`.
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "BoxedMontyForm Add/Sub/Mul are GF(p) field ops with well-defined modular results; clippy's overflow heuristic doesn't apply to modular arithmetic."
    )]
    fn is_on_curve(&self, q: &AffinePoint) -> bool {
        let Some((qx, qy)) = &q.xy else { return false };
        let qx_m = self.p_mont(qx);
        let qy_m = self.p_mont(qy);
        let lhs = &qy_m * &qy_m;
        let a_m = self.p_mont(&self.a);
        let b_m = self.p_mont(&self.b);
        let rhs_no_b = &(&(&qx_m * &qx_m) * &qx_m) + &(&a_m * &qx_m);
        let rhs = &rhs_no_b + &b_m;
        lhs == rhs
    }
}

/// Verify an ECDSA signature.
///
/// - `curve` -- field prime, coefficients, base point, order.
/// - `pubkey_sec1` -- uncompressed SEC1 point: `04 || X || Y`,
///   each coordinate `ceil(bits(p) / 8)` bytes.
/// - `signature_der` -- DER `SEQUENCE { r INTEGER, s INTEGER }`.
/// - `message_digest` -- already-hashed message (caller picks
///   the hash so we don't need a `HashAlgorithm` parameter
///   here).
///
/// # Errors
/// [`EcdsaError`] on any of the verifier's reject branches.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "BoxedMontyForm Mul (e_mont * w_mont, r_mont * w_mont) is modular arithmetic mod n with a well-defined wrap; clippy's integer-overflow heuristic doesn't apply."
)]
pub(crate) fn verify_prehashed(
    curve: &Curve,
    pubkey_sec1: &Sec1UncompressedPoint,
    signature_der: &Signature<EcdsaDer>,
    message_digest: &[u8],
) -> Result<(), EcdsaError> {
    let ctx = CurveCtx::new(curve)?;
    let q = pubkey_sec1.parse_affine(ctx.bits_p)?;
    if !ctx.is_on_curve(&q) {
        return Err(EcdsaError::BadPublicKey);
    }
    let (r_bytes, s_bytes) = signature_der.parse_ecdsa_signature()?;
    let r = EcdsaHelpers::boxed(r_bytes.as_slice(), ctx.bits_n)?;
    let s = EcdsaHelpers::boxed(s_bytes.as_slice(), ctx.bits_n)?;
    let one = BoxedUint::one_with_precision(ctx.bits_n);
    if r < one || r >= ctx.n_uint || s < one || s >= ctx.n_uint {
        return Err(EcdsaError::SigOutOfRange);
    }
    // e := leftmost min(bits(n), bits(hash)) bits of the digest,
    // interpreted as a big-endian integer (RFC 6979 sec.2.3.2).
    let e_uint = EcdsaHelpers::digest_to_scalar(message_digest, &ctx);
    let s_mont = ctx.n_mont(&s);
    let w_mont: BoxedMontyForm = Option::from(s_mont.invert()).ok_or(EcdsaError::NotInvertible)?;
    let e_mont = ctx.n_mont(&e_uint);
    let r_mont = ctx.n_mont(&r);
    let u1 = (&e_mont * &w_mont).retrieve();
    let u2 = (&r_mont * &w_mont).retrieve();
    let point_a = ctx.scalar_mul(&u1, &ctx.g);
    let point_b = ctx.scalar_mul(&u2, &q);
    let sum = ctx.add(&point_a, &point_b);
    let Some((sx, _)) = sum.xy else {
        return Err(EcdsaError::VerifyFailed);
    };
    // sx mod n
    let sx_n = EcdsaHelpers::bytes_into_n(&sx, &ctx);
    if sx_n == r {
        Ok(())
    } else {
        Err(EcdsaError::VerifyFailed)
    }
}

impl Sec1UncompressedPoint {
    /// Decode a SEC1-uncompressed EC point (`04 || X || Y`) into
    /// an [`AffinePoint`].
    ///
    /// SEC1 §2.3.4. Rejects compressed (`02`/`03`) and hybrid
    /// (`06`/`07`) encodings -- the FINEID profile pins
    /// uncompressed form (FINEID S2 §5.1) -- and rejects bodies
    /// whose length is not twice the coordinate width. Does not
    /// run the on-curve check; the caller (`verify_prehashed`)
    /// does that next.
    fn parse_affine(&self, bits_p: u32) -> Result<AffinePoint, EcdsaError> {
        let bytes = self.as_bytes();
        if bytes.first().copied() != Some(SEC1_UNCOMPRESSED_TAG) {
            return Err(EcdsaError::BadPublicKey);
        }
        let body = bytes.get(1..).ok_or(EcdsaError::BadPublicKey)?;
        if !body.len().is_multiple_of(2) || body.is_empty() {
            return Err(EcdsaError::BadPublicKey);
        }
        // body.len() is even and non-zero so `body.len() >> 1` is
        // exact and >= 1; bit-shift sidesteps clippy::integer_division.
        let half: usize = body.len() >> 1_u32;
        let (x_bytes, y_bytes) = body.split_at(half);
        let x = EcdsaHelpers::boxed(x_bytes, bits_p)?;
        let y = EcdsaHelpers::boxed(y_bytes, bits_p)?;
        Ok(AffinePoint { xy: Some((x, y)) })
    }
}

impl Signature<EcdsaDer> {
    /// Convert `XMLDSig`'s raw fixed-width `r || s` representation into
    /// the DER `Ecdsa-Sig-Value` consumed by the verifier.
    ///
    /// # Errors
    /// [`EcdsaError::BadSignature`] when the input is empty or has an
    /// odd length, so it cannot contain two equally sized components.
    pub fn from_raw_concatenation(raw: &[u8]) -> Result<Self, EcdsaError> {
        /// ASN.1 SEQUENCE tag per X.690.
        const ASN1_SEQUENCE_TAG: u8 = 0x30;
        /// Capacity slack for the SEQUENCE tag and DER length.
        const SEQUENCE_HEADER_SLACK: usize = 4;
        /// Per-INTEGER tag, length and possible sign octet.
        const INTEGER_OVERHEAD_SLACK: usize = 4;

        if raw.is_empty() || !raw.len().is_multiple_of(2) {
            return Err(EcdsaError::BadSignature);
        }
        let half = raw.len() >> 1_u32;
        let (r, s) = raw.split_at(half);
        let mut body = Vec::with_capacity(
            raw.len()
                .saturating_add(INTEGER_OVERHEAD_SLACK.saturating_mul(2)),
        );
        EcdsaHelpers::encode_der_integer(&mut body, r);
        EcdsaHelpers::encode_der_integer(&mut body, s);
        let mut out = Vec::with_capacity(body.len().saturating_add(SEQUENCE_HEADER_SLACK));
        out.push(ASN1_SEQUENCE_TAG);
        EcdsaHelpers::encode_der_length(&mut out, body.len());
        out.extend_from_slice(&body);
        Ok(Self::new(out))
    }

    /// Decode an ECDSA `Ecdsa-Sig-Value` SEQUENCE into raw `r`,
    /// `s` magnitude bytes.
    ///
    /// RFC 3279 §2.2.3 / RFC 5480 §2.2. The leading `0x00` that
    /// DER prepends to INTEGERs with the high bit set is
    /// stripped here so downstream big-integer code sees pure
    /// magnitude bytes. Any structural error (wrong outer tag,
    /// missing `s` INTEGER, truncated body) maps to
    /// [`EcdsaError::BadSignature`].
    fn parse_ecdsa_signature(&self) -> Result<(Vec<u8>, Vec<u8>), EcdsaError> {
        let outer =
            BerTlv::<Sequence>::parse(self.as_bytes()).map_err(|_e| EcdsaError::BadSignature)?;
        let r_tlv = BerTlv::<Integer>::parse(outer.value).map_err(|_e| EcdsaError::BadSignature)?;
        let after_r = outer
            .value
            .get(r_tlv.size..)
            .ok_or(EcdsaError::BadSignature)?;
        let s_tlv = BerTlv::<Integer>::parse(after_r).map_err(|_e| EcdsaError::BadSignature)?;
        Ok((
            r_tlv
                .value
                .strip_prefix(&DER_SIGN_PAD_PREFIX)
                .unwrap_or(r_tlv.value)
                .to_vec(),
            s_tlv
                .value
                .strip_prefix(&DER_SIGN_PAD_PREFIX)
                .unwrap_or(s_tlv.value)
                .to_vec(),
        ))
    }
}

impl EcdsaHelpers {
    /// Append an ASN.1 DER `INTEGER` (tag `0x02`) wrapping a
    /// big-endian unsigned magnitude `value` to `out`.
    ///
    /// Strips redundant leading zero bytes (DER integers are
    /// minimal-form) and prepends a single `0x00` when the
    /// resulting high bit is set (to keep the integer positive
    /// under the two's-complement DER interpretation, per
    /// X.690 §8.3.3 / RFC 3279 §2.2.3). The mirror of
    /// the ECDSA signature parser's integer decode.
    fn encode_der_integer(out: &mut Vec<u8>, value: &[u8]) {
        /// ASN.1 INTEGER tag per X.690 §8.3.
        const ASN1_INTEGER_TAG: u8 = 0x02;
        // DER INTEGER is signed: a leading byte whose high bit is set
        // needs a 0x00 sign pad prepended so the value stays positive.
        const HIGH_BIT_SET: u8 = 0x80;
        // Strip leading zeros, but keep at least one byte so a
        // zero integer encodes as `02 01 00` rather than the
        // invalid `02 00`.
        let mut start: usize = 0;
        while start.saturating_add(1) < value.len() && value.get(start).copied() == Some(0) {
            start = start.saturating_add(1);
        }
        let trimmed = value.get(start..).unwrap_or(&[]);
        let needs_pad = trimmed.first().is_some_and(|&b| b >= HIGH_BIT_SET);
        let int_len = trimmed.len().saturating_add(usize::from(needs_pad));
        out.push(ASN1_INTEGER_TAG);
        Self::encode_der_length(out, int_len);
        if needs_pad {
            out.push(DER_SIGN_PAD);
        }
        out.extend_from_slice(trimmed);
    }

    /// Append an ASN.1 DER length octet sequence for `len` to
    /// `out`. Short form for `len < 128`; long form
    /// (`0x81 LL`, `0x82 HH LL`) for larger values. Caps at
    /// 65535 -- ECDSA signatures over any practical curve fit
    /// well under that. Values beyond 65535 are clamped to
    /// 0xFFFF (saturating, fail-closed); the surrounding
    /// `into_der` only ever feeds body lengths under 300 bytes.
    fn encode_der_length(out: &mut Vec<u8>, len: usize) {
        /// DER long-form length-of-length marker for 1 follow-up byte.
        const DER_LONG_FORM_1B: u8 = 0x81;
        /// DER long-form length-of-length marker for 2 follow-up bytes.
        const DER_LONG_FORM_2B: u8 = 0x82;
        /// First length value that requires long form (0x80).
        const SHORT_FORM_CEILING: usize = 0x80;
        /// First length value that requires the 2-byte form (0x100).
        const ONE_BYTE_FORM_CEILING: usize = 0x100;
        if len < SHORT_FORM_CEILING {
            // Bounded by check; fits in u8.
            let b = u8::try_from(len).unwrap_or(u8::MAX);
            out.push(b);
        } else if len < ONE_BYTE_FORM_CEILING {
            out.push(DER_LONG_FORM_1B);
            let b = u8::try_from(len).unwrap_or(u8::MAX);
            out.push(b);
        } else {
            out.push(DER_LONG_FORM_2B);
            // Saturate to u16::MAX for any value beyond the
            // 2-byte form -- callers only ever pass body lengths
            // well under 300 bytes (ECDSA signatures).
            let clamped = u16::try_from(len).unwrap_or(u16::MAX);
            let [hi, lo] = clamped.to_be_bytes();
            out.push(hi);
            out.push(lo);
        }
    }

    /// Map a hash digest to the ECDSA scalar `e` per RFC 6979
    /// §2.3.2.
    ///
    /// Takes the leftmost `min(bits(n), bits(hash))` bits of the
    /// digest, interpreted big-endian, and right-shifts the
    /// remaining low bits when the truncation falls inside a
    /// byte (i.e. `bits(n) mod 8 != 0`). The shift is a no-op
    /// for the common case of curves whose order is a multiple
    /// of 8 bits (P-256, P-384, `brainpoolP384r1`).
    fn digest_to_scalar(digest: &[u8], ctx: &CurveCtx) -> BoxedUint {
        let n_bits = ctx.n_uint.bits_vartime();
        let n_bytes = usize::try_from(n_bits.div_ceil(8)).unwrap_or(usize::MAX);
        let take = digest.len().min(n_bytes);
        let mut buf = digest.get(..take).unwrap_or(&[]).to_vec();
        // If the hash is wider than n in bytes but n's bit-length is
        // not a multiple of 8, right-shift the leading byte to keep
        // only `n_bits % 8` high bits (RFC 6979 sec.2.3.2). For the
        // 512-bit hash + 512-bit n case this is a no-op.
        // n_bits is a u32 from bits_vartime(); `% 8` is in [0, 7]
        // and trivially fits u32.
        let n_bits_mod_8: u32 = n_bits.rem_euclid(8).clamp(0, 7);
        let extra_bits = 8_u32.saturating_sub(n_bits_mod_8).rem_euclid(8);
        if extra_bits != 0 && !buf.is_empty() {
            // `extra_bits` in [1, 7] from the modulo above; shift
            // amounts stay well under u8 bit width.
            let inv_bits = 8_u32.saturating_sub(extra_bits);
            let mask = u8::try_from(1_u32.checked_shl(extra_bits).unwrap_or(1))
                .unwrap_or(0)
                .saturating_sub(1);
            // We need to shift the WHOLE buf right by `extra_bits`.
            let mut carry: u8 = 0;
            for b in &mut buf {
                let new_carry = *b & mask;
                *b = (*b >> extra_bits) | (carry << inv_bits);
                carry = new_carry;
            }
        }
        BoxedUint::from_be_slice(&buf, ctx.bits_n)
            .unwrap_or_else(|_e| BoxedUint::zero_with_precision(ctx.bits_n))
    }

    /// Reduce a field element (mod p) into the scalar field
    /// (mod n). In practice for ECDSA's final compare, `sx <
    /// p` but might be `>= n` if `p > n`. Cheapest correct
    /// reduction: subtract n when `sx >= n`.
    fn bytes_into_n(sx: &BoxedUint, ctx: &CurveCtx) -> BoxedUint {
        let sx_at_n = sx.resize(ctx.bits_n);
        if sx_at_n >= ctx.n_uint {
            let (diff, _borrow) = sx_at_n.borrowing_sub(&ctx.n_uint, crypto_bigint::Limb::ZERO);
            diff
        } else {
            sx_at_n
        }
    }
}

// ----- SPKI parsing: extract Curve from id-ecPublicKey -----

// The SPKI algorithm OID for named-curve and explicit-parameter EC
// public keys is `known::EC_PUBLIC_KEY` (id-ecPublicKey); the prime-field
// OID inside `ECParameters.fieldID` is `known::PRIME_FIELD`.

/// Pull a [`Curve`] out of an SPKI BIT STRING wrapper.
///
/// The `subjectPublicKeyInfo` SEQUENCE the caller hands in.
/// Both named-curve (where parameters is just an OID we don't
/// currently recognise here) and explicit-parameter
/// (`prime-field` form) layouts are accepted.
///
/// Returns `Some(curve_params, sec1_pubkey_bytes)` or `None`
/// if the SPKI isn't an EC key, the explicit params don't parse,
/// or the public key BIT STRING is malformed.
#[must_use]
pub(crate) fn extract_ec_pubkey(spki_der: &[u8]) -> Option<(Curve, Sec1UncompressedPoint)> {
    use spki::SubjectPublicKeyInfoRef;
    use spki::der::Decode as _;
    use spki::der::asn1::ObjectIdentifier;

    // Standards-based SPKI envelope decode (RustCrypto `spki`/`der`);
    // the named-curve-OID and explicit-ECParameters helpers stay
    // (FINEID's explicit-parameters form has no ecosystem type).
    let info = SubjectPublicKeyInfoRef::from_der(spki_der).ok()?;
    if info.algorithm.oid.as_bytes() != known::EC_PUBLIC_KEY.as_bytes() {
        return None;
    }
    let params = info.algorithm.parameters?;
    let curve = match params.decode_as::<ObjectIdentifier>() {
        // Named curve: parameters is the curve OID.
        Ok(curve_oid) => {
            let oid = KnownOid::new(curve_oid.as_bytes()).ok()?;
            EcdsaHelpers::named_curve_from_oid(oid)?
        }
        // Explicit ECParameters SEQUENCE.
        Err(_ignored) => Curve::parse_explicit(params.value()).ok()?,
    };
    // An EC point is octet-aligned. `as_bytes`, unlike `raw_bytes`,
    // refuses a BIT STRING that declares unused trailing bits.
    let pubkey =
        Sec1UncompressedPoint::from_bytes(info.subject_public_key.as_bytes()?.to_vec()).ok()?;
    Some((curve, pubkey))
}

// `field_id` (the ECParameters.fieldID SEQUENCE TLV) and
// `field_iter` (an iterator over its contents) read naturally,
// but trigger clippy's similar_names. The names mirror the
// X9.62 / SEC1 ASN.1 grammar, so a localized allow is better
// than renaming.
impl EcdsaHelpers {
    /// Pop the next child out of `it`, mapping both "end of
    /// children" and "BER parse failure" to
    /// [`EcdsaError::BadModulus`].
    fn next_child<'der>(it: &mut BerTlvIter<'der>) -> Result<BerTlvAny<'der>, EcdsaError> {
        it.next()
            .ok_or(EcdsaError::BadModulus)?
            .map_err(|_e| EcdsaError::BadModulus)
    }

    /// Collapse any parse-side error into [`EcdsaError::BadModulus`].
    ///
    /// Curve parameters arrive as DER fragments that the BER
    /// layer could reject in several ways (wrong tag, truncated
    /// INTEGER, etc.); from the ECDSA verifier's perspective
    /// every one of those is "the curve isn't usable", so the
    /// helper lets call sites stay readable via `.map_err(Self::bad_modulus)`.
    fn bad_modulus<E>(_e: E) -> EcdsaError {
        EcdsaError::BadModulus
    }

    /// Strip a single leading `0x00` byte from a DER INTEGER
    /// magnitude.
    ///
    /// X.690 §8.3.3 forces a leading zero when the top bit of
    /// the magnitude would otherwise mean a negative integer.
    /// Curve constants are always positive, so the sign byte is
    /// inert padding and we want the raw magnitude downstream.
    fn strip_sign(value: &[u8]) -> Vec<u8> {
        value
            .strip_prefix(&DER_SIGN_PAD_PREFIX)
            .unwrap_or(value)
            .to_vec()
    }
}

// Named-curve OIDs: `known::SECP256R1` (prime256v1 / NIST P-256) and
// `known::SECP384R1` (NIST P-384).

impl Signature<EcdsaP384> {
    /// Convert this raw `r || s` ECDSA signature into ASN.1 DER
    /// `SEQUENCE { INTEGER r, INTEGER s }` form. r and s are
    /// extracted as the first half / second half of the bytes
    /// (FINEID S1 v4.2 §3.8.3 guarantees the card writes equal-
    /// sized halves; the trait-level
    /// [`sign_pre_hashed_sha384_ecdsa_p384`] enforces the
    /// 96-byte total before constructing this typed value).
    ///
    /// Pure local re-encoding; no card touch, no fallible
    /// inputs beyond the structural invariant the type carries.
    ///
    /// [`sign_pre_hashed_sha384_ecdsa_p384`]: crate::sign::SignOps::sign_pre_hashed_sha384_ecdsa_p384
    ///
    /// # Panics
    /// On odd input length. Unreachable in practice: the typed
    /// constructor at the sign-path boundary enforces an even
    /// length (48 + 48 = 96 for P-384).
    #[inline]
    #[must_use]
    pub fn into_der(self) -> Signature<EcdsaDer> {
        // SEQUENCE tag (0x30 per X.690 §8.6); SEQUENCE-of-INTEGER
        // shape per RFC 3279 §2.2.3 (ECDSA signatures).
        const ASN1_SEQUENCE_TAG: u8 = 0x30;
        /// Slack for the SEQUENCE header (tag + 1/3-byte length).
        const SEQUENCE_HEADER_SLACK: usize = 4;
        /// Per-INTEGER overhead: 1 (tag) + 1-2 (length) + 1 (sign-byte padding).
        const INTEGER_OVERHEAD_SLACK: usize = 4;
        /// Combined slack for two INTEGERs (r + s); a single named
        /// constant avoids the multiplication-by-literal in the
        /// capacity calc.
        const BODY_SLACK: usize = INTEGER_OVERHEAD_SLACK.saturating_add(INTEGER_OVERHEAD_SLACK);
        let raw = self.into_bytes();
        assert!(
            raw.len().is_multiple_of(2),
            "Signature<EcdsaP384> must have even length (r||s)"
        );
        // Bit-shift instead of `/ 2` to bypass the
        // clippy::integer_division_remainder_used lint; the even-
        // length invariant is asserted above, so `>> 1` is exact.
        let half: usize = raw.len() >> 1_u32;
        let (r, s) = raw.split_at(half);
        let mut body = Vec::with_capacity(raw.len().saturating_add(BODY_SLACK));
        EcdsaHelpers::encode_der_integer(&mut body, r);
        EcdsaHelpers::encode_der_integer(&mut body, s);
        let mut out = Vec::with_capacity(body.len().saturating_add(SEQUENCE_HEADER_SLACK));
        out.push(ASN1_SEQUENCE_TAG);
        EcdsaHelpers::encode_der_length(&mut out, body.len());
        out.extend_from_slice(&body);
        Signature::new(out)
    }
}

impl Signature<EcdsaP256> {
    /// Convert this raw `r || s` ECDSA signature into ASN.1 DER
    /// `SEQUENCE { INTEGER r, INTEGER s }` form. This is the
    /// P-256 companion to [`Signature<EcdsaP384>::into_der`];
    /// the raw input is 32 + 32 bytes.
    ///
    /// Pure local re-encoding; no card touch, no fallible
    /// inputs beyond the structural invariant the type carries.
    ///
    /// # Panics
    /// On odd input length. Unreachable in practice: the typed
    /// constructor at the sign-path boundary enforces an even
    /// length (32 + 32 = 64 for P-256).
    #[inline]
    #[must_use]
    pub fn into_der(self) -> Signature<EcdsaDer> {
        const ASN1_SEQUENCE_TAG: u8 = 0x30;
        const SEQUENCE_HEADER_SLACK: usize = 4;
        const INTEGER_OVERHEAD_SLACK: usize = 4;
        const BODY_SLACK: usize = INTEGER_OVERHEAD_SLACK.saturating_add(INTEGER_OVERHEAD_SLACK);
        let raw = self.into_bytes();
        assert!(
            raw.len().is_multiple_of(2),
            "Signature<EcdsaP256> must have even length (r||s)"
        );
        let half: usize = raw.len() >> 1_u32;
        let (r, s) = raw.split_at(half);
        let mut body = Vec::with_capacity(raw.len().saturating_add(BODY_SLACK));
        EcdsaHelpers::encode_der_integer(&mut body, r);
        EcdsaHelpers::encode_der_integer(&mut body, s);
        let mut out = Vec::with_capacity(body.len().saturating_add(SEQUENCE_HEADER_SLACK));
        out.push(ASN1_SEQUENCE_TAG);
        EcdsaHelpers::encode_der_length(&mut out, body.len());
        out.extend_from_slice(&body);
        Signature::new(out)
    }
}

impl Sec1UncompressedPoint {
    /// Verify an ECDSA P-384 + SHA-384 signature against this
    /// public key. Accepts the card-native raw `r || s` form
    /// FINEID PSO:CDS returns (96 bytes for secp384r1 per S1
    /// v4.2 §3.8.3); the conversion to DER for the underlying
    /// verifier is internal.
    ///
    /// `signature_raw` and `message_digest` are taken by value
    /// per typing-discipline Rule B (no `&T` on pub-fn params);
    /// callers that want to keep the signature around clone it
    /// at the call site, which is cheap (96-byte Vec).
    ///
    /// # Errors
    /// [`EcdsaError`] on any reject branch -- curve construct
    /// failure, off-curve pubkey, r/s out of `[1, n-1]`, s
    /// not invertible mod n, or final verification mismatch.
    #[inline]
    pub fn verify_p384_sha384_raw(
        &self,
        signature_raw: Signature<EcdsaP384>,
        message_digest: Sha384,
    ) -> Result<(), EcdsaError> {
        let curve =
            EcdsaHelpers::named_curve_from_oid(known::SECP384R1).ok_or(EcdsaError::BadModulus)?;
        let signature_der = signature_raw.into_der();
        verify_prehashed(&curve, self, &signature_der, message_digest.as_bytes())
    }

    /// Verify a P-384 ECDSA signature over a SHA-1 digest. Same
    /// curve and verifier as the SHA-384 path; ECDSA is hash-agnostic,
    /// so only the digest length differs (20 bytes).
    ///
    /// # Errors
    /// [`EcdsaError`] on any reject branch, as `verify_p384_sha384_raw`.
    #[inline]
    pub fn verify_p384_sha1_raw(
        &self,
        signature_raw: Signature<EcdsaP384>,
        message_digest: Sha1,
    ) -> Result<(), EcdsaError> {
        let curve =
            EcdsaHelpers::named_curve_from_oid(known::SECP384R1).ok_or(EcdsaError::BadModulus)?;
        let signature_der = signature_raw.into_der();
        verify_prehashed(&curve, self, &signature_der, message_digest.as_bytes())
    }

    /// Verify a P-384 ECDSA signature over a SHA-224 digest. Same
    /// curve and verifier as the SHA-384 path; ECDSA is hash-agnostic,
    /// so only the digest length differs (28 bytes).
    ///
    /// # Errors
    /// [`EcdsaError`] on any reject branch, as `verify_p384_sha384_raw`.
    #[inline]
    pub fn verify_p384_sha224_raw(
        &self,
        signature_raw: Signature<EcdsaP384>,
        message_digest: Sha224,
    ) -> Result<(), EcdsaError> {
        let curve =
            EcdsaHelpers::named_curve_from_oid(known::SECP384R1).ok_or(EcdsaError::BadModulus)?;
        let signature_der = signature_raw.into_der();
        verify_prehashed(&curve, self, &signature_der, message_digest.as_bytes())
    }

    /// Verify a P-384 ECDSA signature over a SHA-256 digest. Same
    /// curve and verifier as the SHA-384 path; ECDSA is hash-agnostic,
    /// so only the digest length differs (32 bytes). Used to locally
    /// confirm the card's ECDSA+SHA-256 signature (the TLS-1.2
    /// `CertificateVerify` hash macOS requests for suomi.fi).
    ///
    /// # Errors
    /// [`EcdsaError`] on any reject branch, as `verify_p384_sha384_raw`.
    #[inline]
    pub fn verify_p384_sha256_raw(
        &self,
        signature_raw: Signature<EcdsaP384>,
        message_digest: Sha256,
    ) -> Result<(), EcdsaError> {
        let curve =
            EcdsaHelpers::named_curve_from_oid(known::SECP384R1).ok_or(EcdsaError::BadModulus)?;
        let signature_der = signature_raw.into_der();
        verify_prehashed(&curve, self, &signature_der, message_digest.as_bytes())
    }

    /// Verify a P-384 ECDSA signature over a SHA-512 digest. Same
    /// curve and verifier as the SHA-384 path; ECDSA is hash-agnostic,
    /// so only the digest length differs (64 bytes).
    ///
    /// # Errors
    /// [`EcdsaError`] on any reject branch, as `verify_p384_sha384_raw`.
    #[inline]
    pub fn verify_p384_sha512_raw(
        &self,
        signature_raw: Signature<EcdsaP384>,
        message_digest: Sha512,
    ) -> Result<(), EcdsaError> {
        let curve =
            EcdsaHelpers::named_curve_from_oid(known::SECP384R1).ok_or(EcdsaError::BadModulus)?;
        let signature_der = signature_raw.into_der();
        verify_prehashed(&curve, self, &signature_der, message_digest.as_bytes())
    }
}

/// Translate well-known EC named-curve OIDs to a [`Curve`].
///
/// Today this covers `secp256r1` (NIST P-256) and `secp384r1`
/// (NIST P-384) -- the curves FINEID's G4E chain and most
/// modern CSCAs use. Brainpool + P-521 named-curve SPKIs land
/// here as `None`; if they're ever needed extend the table
/// rather than the verifier.
///
/// Parameter values are the canonical SEC 2 / FIPS 186-4 byte
/// forms, copied as bare big-endian (no ASN.1 INTEGER sign
/// byte, matching the `Curve` struct's documented convention).
/// NIST P-256 field prime `p` (FIPS 186-4 D.1.2.3 / SEC 2 2.4.2).
const SECP256R1_P: [u8; 32] = Hex::decode_const(concat!(
    "FFFFFFFF000000010000000000000000",
    "00000000FFFFFFFFFFFFFFFFFFFFFFFF",
));
/// NIST P-256 curve coefficient `a`.
const SECP256R1_A: [u8; 32] = Hex::decode_const(concat!(
    "FFFFFFFF000000010000000000000000",
    "00000000FFFFFFFFFFFFFFFFFFFFFFFC",
));
/// NIST P-256 curve coefficient `b`.
const SECP256R1_B: [u8; 32] = Hex::decode_const(concat!(
    "5AC635D8AA3A93E7B3EBBD55769886BC",
    "651D06B0CC53B0F63BCE3C3E27D2604B",
));
/// NIST P-256 base point `G` x coordinate.
const SECP256R1_GX: [u8; 32] = Hex::decode_const(concat!(
    "6B17D1F2E12C4247F8BCE6E563A440F2",
    "77037D812DEB33A0F4A13945D898C296",
));
/// NIST P-256 base point `G` y coordinate.
const SECP256R1_GY: [u8; 32] = Hex::decode_const(concat!(
    "4FE342E2FE1A7F9B8EE7EB4A7C0F9E16",
    "2BCE33576B315ECECBB6406837BF51F5",
));
/// NIST P-256 subgroup order `n`.
const SECP256R1_N: [u8; 32] = Hex::decode_const(concat!(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFF",
    "BCE6FAADA7179E84F3B9CAC2FC632551",
));
/// NIST P-384 field prime `p` (FIPS 186-4 D.1.2.4 / SEC 2 2.5.1).
const SECP384R1_P: [u8; 48] = Hex::decode_const(concat!(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE",
    "FFFFFFFF0000000000000000FFFFFFFF",
));
/// NIST P-384 curve coefficient `a`.
const SECP384R1_A: [u8; 48] = Hex::decode_const(concat!(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE",
    "FFFFFFFF0000000000000000FFFFFFFC",
));
/// NIST P-384 curve coefficient `b`.
const SECP384R1_B: [u8; 48] = Hex::decode_const(concat!(
    "B3312FA7E23EE7E4988E056BE3F82D19",
    "181D9C6EFE8141120314088F5013875A",
    "C656398D8A2ED19D2A85C8EDD3EC2AEF",
));
/// NIST P-384 base point `G` x coordinate.
const SECP384R1_GX: [u8; 48] = Hex::decode_const(concat!(
    "AA87CA22BE8B05378EB1C71EF320AD74",
    "6E1D3B628BA79B9859F741E082542A38",
    "5502F25DBF55296C3A545E3872760AB7",
));
/// NIST P-384 base point `G` y coordinate.
const SECP384R1_GY: [u8; 48] = Hex::decode_const(concat!(
    "3617DE4A96262C6F5D9E98BF9292DC29",
    "F8F41DBD289A147CE9DA3113B5F0B8C0",
    "0A60B1CE1D7E819D7A431D7C90EA0E5F",
));
/// NIST P-384 subgroup order `n`.
const SECP384R1_N: [u8; 48] = Hex::decode_const(concat!(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "FFFFFFFFFFFFFFFFC7634D81F4372DDF",
    "581A0DB248B0A77AECEC196ACCC52973",
));

impl EcdsaHelpers {
    /// Translate a named-curve OID to the corresponding [`Curve`]
    /// constants.
    ///
    /// Returns `None` for any unrecognised OID; the verifier
    /// then either falls through to explicit-params parsing or
    /// rejects the SPKI. Constants are inlined here so the
    /// build does not depend on a runtime curve table; the SEC1
    /// / FIPS 186-4 byte forms are decoded at const-eval time,
    /// so a mistyped digit fails compilation.
    fn named_curve_from_oid(oid: KnownOid<'_>) -> Option<Curve> {
        if oid == known::SECP256R1 {
            return Some(Curve {
                p: SECP256R1_P.to_vec(),
                a: SECP256R1_A.to_vec(),
                b: SECP256R1_B.to_vec(),
                gx: SECP256R1_GX.to_vec(),
                gy: SECP256R1_GY.to_vec(),
                n: SECP256R1_N.to_vec(),
            });
        }
        if oid == known::SECP384R1 {
            return Some(Curve {
                p: SECP384R1_P.to_vec(),
                a: SECP384R1_A.to_vec(),
                b: SECP384R1_B.to_vec(),
                gx: SECP384R1_GX.to_vec(),
                gy: SECP384R1_GY.to_vec(),
                n: SECP384R1_N.to_vec(),
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{EcdsaError, EcdsaHelpers};
    use crate::crypto::container::{EcdsaDer, EcdsaP384, Signature};

    /// P-384 `r||s` sample with the high bit set on both `r[0]`
    /// and `s[0]` -- exercises the leading-`0x00` padding branch
    /// of [`EcdsaHelpers::encode_der_integer`].
    fn raw_rs_p384_high_bit_set() -> Vec<u8> {
        // r: 48 bytes starting 0xFE; s: 48 bytes starting 0x80.
        let mut v = vec![0xFE; 48];
        v.extend(core::iter::once(0x80).chain(core::iter::repeat_n(0x11, 47)));
        v
    }

    /// P-384 `r||s` sample with the high bit clear on both halves
    /// -- exercises the no-padding branch.
    fn raw_rs_p384_high_bit_clear() -> Vec<u8> {
        let mut v = vec![0x01; 48];
        v.extend(core::iter::repeat_n(0x7F, 48));
        v
    }

    /// P-384 `r||s` sample with leading zeros in `r` -- exercises
    /// the leading-zero strip in
    /// [`EcdsaHelpers::encode_der_integer`].
    fn raw_rs_p384_leading_zeros() -> Vec<u8> {
        let mut v = vec![0x00; 5];
        v.extend(core::iter::repeat_n(0xAB, 43));
        v.extend(core::iter::repeat_n(0x33, 48));
        v
    }

    fn without_leading_zeros(magnitude: &[u8]) -> &[u8] {
        let mut i: usize = 0;
        while i.saturating_add(1) < magnitude.len() && magnitude.get(i).copied() == Some(0) {
            i = i.saturating_add(1);
        }
        magnitude.get(i..).unwrap_or(&[])
    }

    #[test]
    fn into_der_round_trips_through_parser() {
        for raw in [
            raw_rs_p384_high_bit_set(),
            raw_rs_p384_high_bit_clear(),
            raw_rs_p384_leading_zeros(),
        ] {
            let (r_slice, s_slice) = raw.split_at(raw.len() >> 1);
            let r_expected = r_slice.to_vec();
            let s_expected = s_slice.to_vec();
            let sig: Signature<EcdsaP384> = Signature::new(raw);
            let der = sig.into_der();
            let Ok((r_parsed, s_parsed)) = der.parse_ecdsa_signature() else {
                unreachable!("DER from into_der parses back");
            };
            // The parser strips a leading 0x00 if present;
            // r_expected might have trailing meaningful zeros
            // matched by left-strip. Compare big-endian magnitudes
            // by stripping any leading zeros from BOTH sides via
            // the helper above.
            assert_eq!(
                without_leading_zeros(r_parsed.as_slice()),
                without_leading_zeros(r_expected.as_slice())
            );
            assert_eq!(
                without_leading_zeros(s_parsed.as_slice()),
                without_leading_zeros(s_expected.as_slice())
            );
        }
    }

    #[test]
    fn encode_der_length_short_form_under_128() {
        let mut out = Vec::new();
        EcdsaHelpers::encode_der_length(&mut out, 0);
        assert_eq!(out, [0x00]);
        out.clear();
        EcdsaHelpers::encode_der_length(&mut out, 0x7F);
        assert_eq!(out, [0x7F]);
    }

    #[test]
    fn encode_der_length_one_byte_long_form() {
        let mut out = Vec::new();
        EcdsaHelpers::encode_der_length(&mut out, 0x80);
        assert_eq!(out, [0x81, 0x80]);
        out.clear();
        EcdsaHelpers::encode_der_length(&mut out, 0xFF);
        assert_eq!(out, [0x81, 0xFF]);
    }

    #[test]
    fn encode_der_length_two_byte_long_form() {
        let mut out = Vec::new();
        EcdsaHelpers::encode_der_length(&mut out, 0x0100);
        assert_eq!(out, [0x82, 0x01, 0x00]);
        out.clear();
        EcdsaHelpers::encode_der_length(&mut out, 0xFFFF);
        assert_eq!(out, [0x82, 0xFF, 0xFF]);
    }

    #[test]
    fn encode_der_integer_zero_emits_single_byte() {
        let mut out = Vec::new();
        EcdsaHelpers::encode_der_integer(&mut out, &[0x00]);
        assert_eq!(out, [0x02, 0x01, 0x00]);
    }

    #[test]
    fn encode_der_integer_high_bit_set_pads_with_zero() {
        let mut out = Vec::new();
        EcdsaHelpers::encode_der_integer(&mut out, &[0xFF]);
        assert_eq!(out, [0x02, 0x02, 0x00, 0xFF]);
    }

    #[test]
    fn encode_der_integer_strips_leading_zeros() {
        let mut out = Vec::new();
        EcdsaHelpers::encode_der_integer(&mut out, &[0x00, 0x00, 0x42, 0xAB]);
        assert_eq!(out, [0x02, 0x02, 0x42, 0xAB]);
    }

    #[test]
    fn xml_raw_signature_converts_to_der_components() {
        const COMPONENT_BYTES: usize = 4;
        const HIGH_BIT_VALUE: u8 = 128;
        let raw = [0, 0, 1, 2, HIGH_BIT_VALUE, 3, 4, 5];
        let converted = Signature::<EcdsaDer>::from_raw_concatenation(&raw);
        let Ok(signature) = converted else {
            unreachable!("valid equal-width XML signature components must convert")
        };
        let Ok((r, s)) = signature.parse_ecdsa_signature() else {
            unreachable!("converted signature must be valid DER")
        };
        assert_eq!(r, raw[2..COMPONENT_BYTES]);
        assert_eq!(s, raw[COMPONENT_BYTES..]);
    }

    #[test]
    fn xml_raw_signature_rejects_missing_or_unequal_components() {
        assert!(matches!(
            Signature::<EcdsaDer>::from_raw_concatenation(&[]),
            Err(EcdsaError::BadSignature)
        ));
        assert!(matches!(
            Signature::<EcdsaDer>::from_raw_concatenation(&[1, 2, 3]),
            Err(EcdsaError::BadSignature)
        ));
    }
}
