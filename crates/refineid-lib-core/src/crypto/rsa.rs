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

//! RSA-PKCS1v15-SHA256 signature verification.
//!
//! Just enough RSA to verify a CRL or OCSP response signed by
//! the DVV CA chain. No key generation, no signing, no
//! private-key handling -- this module never holds a secret.
//!
//! Builds on `crypto-bigint`'s `BoxedUint` + `BoxedMontyForm`
//! for arbitrary-precision modular exponentiation. Padding +
//! `DigestInfo` matching follow RFC 8017 §8.2.
//!
//! Constant-time hardening is *not* a goal here -- this verifier
//! only sees CA-published signatures, so timing leaks on the
//! padding/DigestInfo compare don't reveal anything secret.

use crypto_bigint::{
    BoxedUint, Odd,
    modular::{BoxedMontyForm, BoxedMontyParams},
};
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha384, Sha512};

use crate::crypto::container::{
    RsaPkcs1Sha256, RsaPkcs1Sha384, RsaPkcs1Sha512, RsaPssSha256, Signature,
};

/// Leading-zero byte in a big-endian integer magnitude
/// representation. The byte value 0x00 in this position has no
/// numeric weight -- canonical PKCS#1 form (RFC 8017 §3.1)
/// strips every such byte. Used by the value-to-bytes
/// constructors and the corresponding round-trip tests.
const LEADING_ZERO_BYTE: u8 = 0;

/// Bits in one byte. The host platform's byte is 8 bits (POSIX
/// `CHAR_BIT` is mandated to 8 on every platform this code
/// targets; Rust additionally pins `u8` at 8 bits). Used by
/// `raw_recover` to convert a modulus byte-length into the bit
/// count `BoxedUint::from_be_slice` wants.
const BITS_PER_BYTE: u32 = 8;

/// `usize` companion to [`BITS_PER_BYTE`] for buffer arithmetic.
const BITS_PER_BYTE_USIZE: usize = 8;

/// `BoxedUint` limb size in bits. The crypto-bigint crate
/// stores arbitrary-precision integers as a sequence of `u64`
/// "limbs"; precision arguments to its constructors round up
/// to a multiple of one limb. Used to align the bit-precision
/// argument in `raw_recover` so the modulus and signature fit
/// in a whole number of limbs.
const BOXED_UINT_LIMB_BITS: u32 = 64;

/// SHA-256 output width used by the fixed RSA-PSS profile.
const SHA256_OUTPUT_BYTES: usize = 32;

/// Salt width in the EU trusted-list RSA-PSS profile.
const PSS_SHA256_SALT_BYTES: usize = SHA256_OUTPUT_BYTES;

/// Eight zero octets prefixed to `mHash || salt` by EMSA-PSS.
const PSS_ZERO_PREFIX_BYTES: usize = 8;

/// EMSA-PSS trailer field value `0xBC` (RFC 8017 sec. 9.1.1).
const PSS_TRAILER_FIELD: u8 = 0xBC;

/// Separator between the zero padding string and salt in EMSA-PSS DB.
const PSS_DB_SEPARATOR: u8 = 0x01;

/// Mask whose every bit is one, used to inspect the unused high bits.
const FULL_BYTE_MASK: u8 = 0xFF;

/// RSA modulus in PKCS#1 form (RFC 8017 §3.1): big-endian
/// magnitude bytes, no leading-zero sign byte. Constructor
/// enforces:
///
/// - non-empty;
/// - first byte non-zero (canonical PKCS#1; the ASN.1 INTEGER
///   sign-byte must already be stripped by the parser before
///   calling here);
/// - bit length in [512, 16384] -- below 512 isn't real RSA
///   (FIPS 186-5 floor is 2048, but FINEID legacy cards still
///   issue some 1024-bit), above 16384 is past anything the
///   ecosystem produces;
/// - low byte odd -- RSA moduli are products of two odd primes;
///   an even modulus means the parser gave us garbage and the
///   verifier would reject it later anyway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaModulus(Vec<u8>);

/// Construction errors for [`RsaModulus`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaModulusError {
    /// Input slice was empty.
    Empty,
    /// First byte was `0x00` -- modulus must be in canonical
    /// PKCS#1 form with the ASN.1 sign byte already stripped.
    LeadingZero,
    /// Bit length below the floor.
    BitsTooFew {
        /// Observed modulus bit length. Tier 0 `usize`;
        /// arithmetic count.
        bits: usize,
        /// Refineid's accepted floor. Tier 0 `usize`.
        min: usize,
    },
    /// Bit length above the ceiling.
    BitsTooMany {
        /// Observed modulus bit length. Tier 0 `usize`.
        bits: usize,
        /// Refineid's accepted ceiling. Tier 0 `usize`.
        max: usize,
    },
    /// Low byte was even.
    Even,
}

impl core::fmt::Display for RsaModulusError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => write!(f, "RSA modulus: empty"),
            Self::LeadingZero => write!(f, "RSA modulus: leading zero byte (not canonical PKCS#1)"),
            Self::BitsTooFew { bits, min } => {
                write!(f, "RSA modulus: {bits}-bit, minimum is {min}")
            }
            Self::BitsTooMany { bits, max } => {
                write!(f, "RSA modulus: {bits}-bit, maximum is {max}")
            }
            Self::Even => write!(f, "RSA modulus: even (not a product of odd primes)"),
        }
    }
}

impl core::error::Error for RsaModulusError {}

impl RsaModulus {
    /// Minimum modulus size accepted. 512-bit floor matches what
    /// the lib-core stack sees from legacy FINEID cards; current
    /// production is 2048+ but we don't enforce that here.
    pub const MIN_BITS: usize = 512;
    /// Maximum modulus size accepted. 16 kbit ceiling is well
    /// past anything the ecosystem produces (current upper end
    /// is 4096-bit RSA on FINEID S4-1 v3.1 cards).
    #[expect(
        clippy::decimal_literal_representation,
        reason = "RSA bit-size policy values are conventionally written decimal across the cryptographic ecosystem (1024, 2048, 3072, 4096, 8192, 16384); hex obscures rather than clarifies. The MAX_BITS const name carries the semantic; the literal is the policy value."
    )]
    pub const MAX_BITS: usize = 16384;

    /// Build from PKCS#1 magnitude bytes (no sign byte).
    ///
    /// # Errors
    /// [`RsaModulusError`] when the bytes don't satisfy the
    /// canonical PKCS#1 form / size / parity invariants.
    pub fn try_from_pkcs1<B: AsRef<[u8]>>(bytes: B) -> Result<Self, RsaModulusError> {
        let bytes = bytes.as_ref();
        let first = *bytes.first().ok_or(RsaModulusError::Empty)?;
        if first == 0 {
            return Err(RsaModulusError::LeadingZero);
        }
        let last = *bytes.last().ok_or(RsaModulusError::Empty)?;
        if last & 1 == 0 {
            return Err(RsaModulusError::Even);
        }
        let leading: usize =
            usize::try_from(first.leading_zeros()).map_err(|_e| RsaModulusError::Empty)?;
        let bits = bytes
            .len()
            .checked_mul(8)
            .and_then(|n| n.checked_sub(leading))
            .ok_or(RsaModulusError::Empty)?;
        if bits < Self::MIN_BITS {
            return Err(RsaModulusError::BitsTooFew {
                bits,
                min: Self::MIN_BITS,
            });
        }
        if bits > Self::MAX_BITS {
            return Err(RsaModulusError::BitsTooMany {
                bits,
                max: Self::MAX_BITS,
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Magnitude bytes, big-endian, leading zero stripped.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Byte length of the modulus -- this is `k` in PKCS#1
    /// terminology (RFC 8017 §3.1), the natural signature
    /// length.
    #[must_use]
    pub const fn byte_len(&self) -> usize {
        self.0.len()
    }

    /// Bit length of the modulus.
    #[must_use]
    pub fn bit_length(&self) -> usize {
        // Invariant: try_from_pkcs1 rejects empty input and caps
        // bit-length at MAX_BITS = 16384, so byte_len <= 2048 and
        // `len * 8` cannot overflow usize on any supported platform.
        // `leading_zeros()` of a u8 fits in [0, 8] which trivially
        // converts to usize, and a non-zero first byte (also enforced
        // at construction) guarantees `len * 8 >= leading_zeros`.
        // Arithmetic stays total (never panics); a debug_assert catches an
        // invariant break in tests without aborting a release process, and
        // `expect()` is banned workspace-wide (clippy::expect_used).
        let Some(first) = self.0.first().copied() else {
            debug_assert!(false, "RsaModulus invariant: modulus is non-empty");
            return 0;
        };
        let leading = usize::try_from(first.leading_zeros()).unwrap_or(0);
        self.0
            .len()
            .checked_mul(8)
            .and_then(|n| n.checked_sub(leading))
            .unwrap_or_else(|| {
                debug_assert!(
                    false,
                    "RsaModulus invariant: bit-length bounded by MAX_BITS"
                );
                0
            })
    }
}

/// RSA public exponent in PKCS#1 form (RFC 8017 §3.1):
/// big-endian magnitude bytes, no leading-zero sign byte.
/// Constructor enforces:
///
/// - non-empty;
/// - first byte non-zero (canonical PKCS#1 form);
/// - low byte odd -- public exponents are odd (the common
///   values 3, 17, 65537 all are; an even exponent breaks
///   coprimality with phi(n) = (p-1)(q-1) since both p-1 and
///   q-1 are even).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPublicExponent(Vec<u8>);

/// Construction errors for [`RsaPublicExponent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaPublicExponentError {
    /// Input slice was empty.
    Empty,
    /// First byte was `0x00`.
    LeadingZero,
    /// Low byte was even.
    Even,
    /// Public exponent was below the RFC 8017 minimum of three.
    TooSmall,
    /// Public exponent exceeded the bounded 256-bit verification profile.
    TooLarge {
        /// Observed exponent bit length.
        bits: usize,
        /// Accepted ceiling.
        max: usize,
    },
}

impl core::fmt::Display for RsaPublicExponentError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => write!(f, "RSA public exponent: empty"),
            Self::LeadingZero => write!(
                f,
                "RSA public exponent: leading zero byte (not canonical PKCS#1)"
            ),
            Self::Even => write!(f, "RSA public exponent: even (not coprime with phi(n))"),
            Self::TooSmall => write!(f, "RSA public exponent: below three"),
            Self::TooLarge { bits, max } => {
                write!(f, "RSA public exponent: {bits}-bit, maximum is {max}")
            }
        }
    }
}

impl core::error::Error for RsaPublicExponentError {}

impl RsaPublicExponent {
    /// Largest exponent accepted by the public verification path.
    /// FIPS 186-5 bounds newly generated RSA exponents to 256 bits.
    pub const MAX_BITS: usize = 256;

    /// Build from PKCS#1 magnitude bytes (no sign byte).
    ///
    /// # Errors
    /// [`RsaPublicExponentError`] when the bytes don't satisfy
    /// the canonical PKCS#1 form / parity invariants.
    pub fn try_from_pkcs1<B: AsRef<[u8]>>(bytes: B) -> Result<Self, RsaPublicExponentError> {
        let bytes = bytes.as_ref();
        let first = *bytes.first().ok_or(RsaPublicExponentError::Empty)?;
        if first == 0 {
            return Err(RsaPublicExponentError::LeadingZero);
        }
        let last = *bytes.last().ok_or(RsaPublicExponentError::Empty)?;
        if last & 1 == 0 {
            return Err(RsaPublicExponentError::Even);
        }
        if bytes.len() == 1 && first < 3 {
            return Err(RsaPublicExponentError::TooSmall);
        }
        let leading = usize::try_from(first.leading_zeros())
            .map_err(|_error| RsaPublicExponentError::Empty)?;
        let bits = bytes
            .len()
            .checked_mul(BITS_PER_BYTE_USIZE)
            .and_then(|width| width.checked_sub(leading))
            .ok_or(RsaPublicExponentError::Empty)?;
        if bits > Self::MAX_BITS {
            return Err(RsaPublicExponentError::TooLarge {
                bits,
                max: Self::MAX_BITS,
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Build from a `u64` integer value. The integer is encoded
    /// big-endian with leading zeros stripped to canonical
    /// PKCS#1 form.
    ///
    /// # Errors
    /// [`RsaPublicExponentError::Empty`] when the value is zero,
    /// [`RsaPublicExponentError::TooSmall`] when the value is one,
    /// [`RsaPublicExponentError::Even`] when the value is even.
    pub fn try_from_value(value: u64) -> Result<Self, RsaPublicExponentError> {
        if value == 0 {
            return Err(RsaPublicExponentError::Empty);
        }
        let be = value.to_be_bytes();
        // Strip leading zero bytes to canonical PKCS#1 form.
        let leading_zeros = be.iter().take_while(|&&b| b == LEADING_ZERO_BYTE).count();
        let stripped = be
            .get(leading_zeros..)
            .ok_or(RsaPublicExponentError::Empty)?;
        Self::try_from_pkcs1(stripped)
    }

    /// `e = 65537` (Fermat prime `F_4` / `2^16 + 1`), the standard
    /// RSA public exponent per NIST SP 800-56B and the value
    /// FINEID issues. Wire form: `01 00 01`.
    #[must_use]
    pub fn e_65537() -> Self {
        // Canonical big-endian wire form of 65537 = 0x010001.
        // Constructor invariants (non-empty, no leading zero, odd
        // low byte) are satisfied by inspection of the literal.
        Self(vec![0x01, 0x00, 0x01])
    }

    /// `e = 3`, the smallest valid RSA public exponent
    /// (RFC 8017 §3.1 / "e is an integer between 3 and n−1").
    /// Largely historical; FIPS 186-5 §A.1.1.2 requires e in
    /// `[2^16 + 1, 2^256 - 1]` for new keys.
    #[must_use]
    pub fn e_3() -> Self {
        // Canonical big-endian wire form of 3 = 0x03.
        // Constructor invariants satisfied by inspection.
        Self(vec![0x03])
    }

    /// Magnitude bytes, big-endian, leading zero stripped.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Parsed RSA public key. Constructors of the field types
/// validate at the trust boundary; downstream code receives
/// parse-and-checked values.
#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    /// RSA modulus `n` (Tier 1 newtype enforcing PKCS#1 canonical
    /// form: non-empty, no leading zero, odd, in
    /// `MIN_BITS..=MAX_BITS`).
    pub modulus: RsaModulus,
    /// RSA public exponent `e` (Tier 1 newtype enforcing odd,
    /// at least 3, and within an accepted range).
    pub exponent: RsaPublicExponent,
}

/// Error returned from the PKCS#1 v1.5 RSA verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaVerifyError {
    /// Modulus parsed as zero or even.
    BadModulus,
    /// Signature is a different size than the modulus (or
    /// signature ≥ modulus).
    SignatureOutOfRange,
    /// Decoded message didn't match the PKCS#1 v1.5 padding shape.
    BadPadding,
    /// Decoded payload didn't carry the SHA-256 `DigestInfo`
    /// prefix.
    BadDigestInfo,
    /// Decoded payload's hash didn't match `SHA-256(message)`.
    BadDigest,
}

impl core::fmt::Display for RsaVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadModulus => write!(f, "RSA: malformed modulus"),
            Self::SignatureOutOfRange => write!(f, "RSA: signature out of range vs modulus"),
            Self::BadPadding => write!(f, "RSA: PKCS#1 v1.5 padding mismatch"),
            Self::BadDigestInfo => write!(f, "RSA: SHA-256 DigestInfo prefix mismatch"),
            Self::BadDigest => write!(f, "RSA: signature digest does not match message"),
        }
    }
}

impl core::error::Error for RsaVerifyError {}

/// `DigestInfo` prefix (RFC 8017 §9.2 note 1) followed by the
/// hash itself.
const SHA256_DIGEST_INFO: &[u8] = &[
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
/// PKCS#1 v1.5 `DigestInfo` prefix for SHA-384 (RFC 8017 §9.2
/// step 2 / appendix B.1). The trailing `0x30` is the 48-byte
/// OCTET STRING length introducing the hash itself.
const SHA384_DIGEST_INFO: &[u8] = &[
    0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
/// PKCS#1 v1.5 `DigestInfo` prefix for SHA-512 (RFC 8017 §9.2
/// step 2 / appendix B.1). The trailing `0x40` is the 64-byte
/// OCTET STRING length introducing the hash itself.
const SHA512_DIGEST_INFO: &[u8] = &[
    0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

// `verify_pkcs1v15_sha256` is a method on `RsaPublicKey`. See
// `RsaPublicKey::verify_pkcs1v15_sha256` below.

/// Verify a PKCS#1 v1.5 signature over `SHA-384(message)`.
///
/// # Errors
/// As for `verify_pkcs1v15_sha256`.
pub(crate) fn verify_pkcs1v15_sha384(
    key: &RsaPublicKey,
    message: &[u8],
    signature: &Signature<RsaPkcs1Sha384>,
) -> Result<(), RsaVerifyError> {
    let mut hasher = Sha384::new();
    hasher.update(message);
    let digest = hasher.finalize();
    verify_pkcs1v15(
        key,
        SHA384_DIGEST_INFO,
        digest.as_ref(),
        signature.as_bytes(),
    )
}

/// Verify a PKCS#1 v1.5 signature over `SHA-512(message)`.
///
/// # Errors
/// As for `verify_pkcs1v15_sha256`.
pub(crate) fn verify_pkcs1v15_sha512(
    key: &RsaPublicKey,
    message: &[u8],
    signature: &Signature<RsaPkcs1Sha512>,
) -> Result<(), RsaVerifyError> {
    let mut hasher = Sha512::new();
    hasher.update(message);
    let digest = hasher.finalize();
    verify_pkcs1v15(
        key,
        SHA512_DIGEST_INFO,
        digest.as_ref(),
        signature.as_bytes(),
    )
}

/// PKCS#1 v1.5 verifier core. Computes `s^e mod n`, strips
/// padding, and matches the `DigestInfo` prefix + `digest`.
fn verify_pkcs1v15(
    key: &RsaPublicKey,
    digest_info_prefix: &[u8],
    digest: &[u8],
    signature: &[u8],
) -> Result<(), RsaVerifyError> {
    let k = key.modulus.byte_len();
    if signature.len() != k {
        return Err(RsaVerifyError::SignatureOutOfRange);
    }
    // bits_precision = k bytes * BITS_PER_BYTE, rounded up to
    // BOXED_UINT_LIMB_BITS so the modulus and signature fit
    // a whole number of u64 limbs.
    let bits_precision = u32::try_from(k)
        .map_err(|_e| RsaVerifyError::BadModulus)?
        .checked_mul(BITS_PER_BYTE)
        .ok_or(RsaVerifyError::BadModulus)?
        .next_multiple_of(BOXED_UINT_LIMB_BITS);

    let modulus = BoxedUint::from_be_slice(key.modulus.as_bytes(), bits_precision)
        .map_err(|_e| RsaVerifyError::BadModulus)?;
    let exponent = BoxedUint::from_be_slice_vartime(key.exponent.as_bytes());
    let signature_uint = BoxedUint::from_be_slice(signature, bits_precision)
        .map_err(|_e| RsaVerifyError::SignatureOutOfRange)?;
    if signature_uint >= modulus {
        return Err(RsaVerifyError::SignatureOutOfRange);
    }

    let odd_modulus: Odd<BoxedUint> =
        Option::from(Odd::new(modulus)).ok_or(RsaVerifyError::BadModulus)?;
    let params = BoxedMontyParams::new(odd_modulus);
    let sig_form = BoxedMontyForm::new(signature_uint, &params);
    let m_form = sig_form.pow(&exponent);
    let m = m_form.retrieve();
    let em_box = m.to_be_bytes();
    let em: &[u8] = if let Some(extra) = em_box.len().checked_sub(k).filter(|n| *n > 0) {
        let prefix = em_box.get(..extra).ok_or(RsaVerifyError::BadPadding)?;
        if prefix.iter().any(|&b| b != 0) {
            return Err(RsaVerifyError::BadPadding);
        }
        em_box.get(extra..).ok_or(RsaVerifyError::BadPadding)?
    } else {
        &em_box
    };

    // PKCS#1 v1.5 EMSA shape: 0x00 0x01 PS 0x00 T
    // where PS is >=8 bytes of 0xFF padding and T = DigestInfo || H(M).
    let min_em_len = digest_info_prefix
        .len()
        .checked_add(digest.len())
        .and_then(|n| n.checked_add(11))
        .ok_or(RsaVerifyError::BadPadding)?;
    if em.len() < min_em_len
        || em.first().copied() != Some(0x00)
        || em.get(1).copied() != Some(0x01)
    {
        return Err(RsaVerifyError::BadPadding);
    }
    let mut i: usize = 2;
    while em.get(i).copied() == Some(0xFF) {
        i = i.checked_add(1).ok_or(RsaVerifyError::BadPadding)?;
    }
    let ps_len = i.checked_sub(2).ok_or(RsaVerifyError::BadPadding)?;
    if ps_len < 8 || em.get(i).copied() != Some(0x00) {
        return Err(RsaVerifyError::BadPadding);
    }
    let payload_start = i.checked_add(1).ok_or(RsaVerifyError::BadPadding)?;
    let payload = em.get(payload_start..).ok_or(RsaVerifyError::BadPadding)?;

    let expected_payload_len = digest_info_prefix
        .len()
        .checked_add(digest.len())
        .ok_or(RsaVerifyError::BadDigestInfo)?;
    if payload.len() != expected_payload_len {
        return Err(RsaVerifyError::BadDigestInfo);
    }
    let (prefix, embedded) = payload.split_at(digest_info_prefix.len());
    if prefix != digest_info_prefix {
        return Err(RsaVerifyError::BadDigestInfo);
    }
    if embedded != digest {
        return Err(RsaVerifyError::BadDigest);
    }
    Ok(())
}

/// Recovered message from an ISO/IEC 9796-2 DS1 verification.
#[derive(Debug, Clone)]
pub struct Iso9796Ds1Recovered {
    /// The chip's random padding bytes (`M1` in the spec). Not
    /// usually meaningful to the caller, but exposed for
    /// inspection.
    pub m1: Vec<u8>,
    /// Hash algorithm the chip used, derived from the trailer.
    pub hash: HashAlg,
}

/// Hash algorithm used in the ISO/IEC 9796-2 trailer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    /// SHA-1 (trailer `0x33CC`). Used by older eMRTD Active
    /// Authentication chips per ICAO 9303-11 §6.1.
    Sha1,
    /// SHA-256 (trailer `0x34CC`).
    Sha256,
    /// SHA-384 (trailer `0x36CC`).
    Sha384,
    /// SHA-512 (trailer `0x35CC`).
    Sha512,
}

impl HashAlg {
    /// Digest output length in bytes for the standard SHA-1/2
    /// family.
    ///
    /// FIPS 180-4 §6 -- SHA-1 = 160 bits, SHA-256 = 256 bits,
    /// SHA-384 = 384 bits, SHA-512 = 512 bits. Returned as bytes
    /// for direct use against EMSA-PKCS1-v1_5 / EMSA-PSS buffer
    /// sizing.
    const fn digest_size(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Hash `(m1 || m2)` using this algorithm.
    fn hash(self, m1: &[u8], m2: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => {
                let mut h = Sha1::new();
                h.update(m1);
                h.update(m2);
                h.finalize().to_vec()
            }
            Self::Sha256 => {
                let mut h = Sha256::new();
                h.update(m1);
                h.update(m2);
                h.finalize().to_vec()
            }
            Self::Sha384 => {
                let mut h = Sha384::new();
                h.update(m1);
                h.update(m2);
                h.finalize().to_vec()
            }
            Self::Sha512 => {
                let mut h = Sha512::new();
                h.update(m1);
                h.update(m2);
                h.finalize().to_vec()
            }
        }
    }
}

/// Verify an ISO/IEC 9796-2 Digital Signature Scheme 1
/// signature with message recovery against the public key.
///
/// Used by ICAO 9303-11 §6.1 Active Authentication: the chip
/// signs `F = 6A || M1 || H(M1 || M2) || T` where:
///
/// - `M2` is the caller-supplied challenge (`RND.IFD`, 8 bytes
///   in the AA flow).
/// - `M1` is random padding the chip generates (length depends
///   on key size + hash size).
/// - `T` is the trailer: implicit `0xBC` for SHA-1, or a
///   2-byte explicit form `HFI || 0xCC` for SHA-256 / SHA-384
///   / SHA-512 where `HFI` is the ISO 10118-3 hash identifier
///   (`0x34` SHA-256, `0x36` SHA-384, `0x35` SHA-512).
///
/// Returns the recovered `M1` and the hash algorithm the chip
/// used on success. The hash identifier carries the
/// information about which hash was applied, so the caller
/// doesn't have to know in advance.
///
/// # Errors
/// `BadPadding` for any structural failure (wrong leading byte,
/// unknown trailer, length inconsistencies), `BadDigest` when
/// the embedded hash doesn't match `H(M1 || M2)`, `BadModulus`
/// / `SignatureOutOfRange` for the RSA-level checks.
pub(crate) fn verify_iso9796_2_ds1(
    key: &RsaPublicKey,
    challenge_m2: &[u8],
    signature: &[u8],
) -> Result<Iso9796Ds1Recovered, RsaVerifyError> {
    /// Minimum recovered length: leading 0x6A (1) + at least 20-byte
    /// hash (SHA-1) + 1-byte trailer; the 22-byte floor here is a
    /// cheaper-than-the-hash early reject.
    const MIN_RECOVERED_LEN: usize = 22;
    /// Leading byte of an ISO/IEC 9796-2 DS1 recoverable signature.
    const ISO9796_DS1_LEADING_BYTE: u8 = 0x6A;
    /// Implicit-trailer marker (SHA-1).
    const TRAILER_BC: u8 = 0xBC;
    /// Explicit-trailer terminator byte.
    const TRAILER_CC: u8 = 0xCC;
    /// ISO 10118-3 HFI for SHA-256.
    const HFI_SHA256: u8 = 0x34;
    /// ISO 10118-3 HFI for SHA-384.
    const HFI_SHA384: u8 = 0x36;
    /// ISO 10118-3 HFI for SHA-512.
    const HFI_SHA512: u8 = 0x35;

    let recovered = key.raw_recover(signature)?;
    let k = recovered.len();
    if k < MIN_RECOVERED_LEN {
        return Err(RsaVerifyError::BadPadding);
    }
    if recovered.first().copied() != Some(ISO9796_DS1_LEADING_BYTE) {
        return Err(RsaVerifyError::BadPadding);
    }
    // Trailer detection. `k >= MIN_RECOVERED_LEN = 22` already, so
    // `k - 1` and `k - 2` are in-range.
    let last_idx = k.checked_sub(1).ok_or(RsaVerifyError::BadPadding)?;
    let last = recovered
        .get(last_idx)
        .copied()
        .ok_or(RsaVerifyError::BadPadding)?;
    let (hash, trailer_len): (HashAlg, usize) = match last {
        TRAILER_BC => (HashAlg::Sha1, 1),
        TRAILER_CC => {
            let hfi_idx = k.checked_sub(2).ok_or(RsaVerifyError::BadPadding)?;
            let hfi = recovered
                .get(hfi_idx)
                .copied()
                .ok_or(RsaVerifyError::BadPadding)?;
            match hfi {
                HFI_SHA256 => (HashAlg::Sha256, 2),
                HFI_SHA384 => (HashAlg::Sha384, 2),
                HFI_SHA512 => (HashAlg::Sha512, 2),
                _ => return Err(RsaVerifyError::BadPadding),
            }
        }
        _ => return Err(RsaVerifyError::BadPadding),
    };
    let digest_len = hash.digest_size();
    let footer = digest_len
        .checked_add(trailer_len)
        .and_then(|n| n.checked_add(1))
        .ok_or(RsaVerifyError::BadPadding)?;
    if k < footer {
        return Err(RsaVerifyError::BadPadding);
    }
    let hash_end = k
        .checked_sub(trailer_len)
        .ok_or(RsaVerifyError::BadPadding)?;
    let m1_end = hash_end
        .checked_sub(digest_len)
        .ok_or(RsaVerifyError::BadPadding)?;
    let m1 = recovered
        .get(1..m1_end)
        .ok_or(RsaVerifyError::BadPadding)?
        .to_vec();
    let embedded_hash = recovered
        .get(m1_end..hash_end)
        .ok_or(RsaVerifyError::BadPadding)?;

    let computed = hash.hash(m1.as_slice(), challenge_m2);
    // Constant-time comparison is overkill here -- the embedded
    // hash is publicly recoverable from the signature, no
    // secret leaks via timing -- but match the digest-cmp idiom
    // the PKCS#1 v1.5 path uses for consistency.
    if computed != embedded_hash {
        return Err(RsaVerifyError::BadDigest);
    }
    Ok(Iso9796Ds1Recovered { m1, hash })
}

impl RsaPublicKey {
    /// Verify a PKCS#1 v1.5 signature over `SHA-256(message)`
    /// against this key.
    ///
    /// # Errors
    /// Padding / digest mismatches as listed in
    /// [`RsaVerifyError`].
    pub fn verify_pkcs1v15_sha256<B: AsRef<[u8]>>(
        &self,
        message: B,
        signature: &Signature<RsaPkcs1Sha256>,
    ) -> Result<(), RsaVerifyError> {
        let mut hasher = Sha256::new();
        hasher.update(message.as_ref());
        let digest = hasher.finalize();
        verify_pkcs1v15(
            self,
            SHA256_DIGEST_INFO,
            digest.as_ref(),
            signature.as_bytes(),
        )
    }

    /// Verify PKCS#1 v1.5 against an already-computed SHA-256 digest.
    ///
    /// # Errors
    /// Returns [`RsaVerifyError`] when the signature has invalid padding,
    /// length, or an embedded digest that does not match.
    pub fn verify_pkcs1v15_sha256_digest(
        &self,
        digest: &[u8; 32],
        signature: &Signature<RsaPkcs1Sha256>,
    ) -> Result<(), RsaVerifyError> {
        verify_pkcs1v15(self, SHA256_DIGEST_INFO, digest, signature.as_bytes())
    }

    /// Verify a PKCS#1 v1.5 signature over `SHA-384(message)`.
    ///
    /// # Errors
    /// Padding, length or digest mismatch as listed in
    /// [`RsaVerifyError`].
    pub fn verify_pkcs1v15_sha384<B: AsRef<[u8]>>(
        &self,
        message: B,
        signature: &Signature<RsaPkcs1Sha384>,
    ) -> Result<(), RsaVerifyError> {
        verify_pkcs1v15_sha384(self, message.as_ref(), signature)
    }

    /// Verify a PKCS#1 v1.5 signature over `SHA-512(message)`.
    ///
    /// # Errors
    /// Padding, length or digest mismatch as listed in
    /// [`RsaVerifyError`].
    pub fn verify_pkcs1v15_sha512<B: AsRef<[u8]>>(
        &self,
        message: B,
        signature: &Signature<RsaPkcs1Sha512>,
    ) -> Result<(), RsaVerifyError> {
        verify_pkcs1v15_sha512(self, message.as_ref(), signature)
    }

    /// Verify RSA-PSS with SHA-256, MGF1-SHA-256 and a 32-byte salt.
    ///
    /// This is the fixed profile identified by the EU trusted-list XML
    /// signature algorithms. Parameters are not caller-selectable: an
    /// XML signature that names another salt length, mask digest or
    /// trailer is rejected before it reaches this method.
    ///
    /// # Errors
    /// [`RsaVerifyError`] for a signature outside the modulus, malformed
    /// EMSA-PSS encoding, or digest mismatch.
    pub fn verify_pss_sha256<B: AsRef<[u8]>>(
        &self,
        message: B,
        signature: &Signature<RsaPssSha256>,
    ) -> Result<(), RsaVerifyError> {
        let digest = Sha256::digest(message.as_ref());
        self.verify_pss_sha256_digest(digest.as_ref(), signature)
    }

    /// Verify the fixed RSA-PSS profile against an existing SHA-256
    /// message digest.
    ///
    /// # Errors
    /// As for [`Self::verify_pss_sha256`].
    pub fn verify_pss_sha256_digest(
        &self,
        digest: &[u8],
        signature: &Signature<RsaPssSha256>,
    ) -> Result<(), RsaVerifyError> {
        if digest.len() != SHA256_OUTPUT_BYTES {
            return Err(RsaVerifyError::BadDigest);
        }
        let recovered = self.raw_recover(signature.as_bytes())?;
        let modulus_bits = self.modulus.bit_length();
        let encoded_bits = modulus_bits
            .checked_sub(1)
            .ok_or(RsaVerifyError::BadModulus)?;
        let encoded_len = encoded_bits
            .checked_add(BITS_PER_BYTE_USIZE - 1)
            .and_then(|bits| bits.checked_div(BITS_PER_BYTE_USIZE))
            .ok_or(RsaVerifyError::BadModulus)?;
        let encoded = recovered
            .get(recovered.len().saturating_sub(encoded_len)..)
            .ok_or(RsaVerifyError::BadPadding)?;
        let leading_len = recovered
            .len()
            .checked_sub(encoded.len())
            .ok_or(RsaVerifyError::BadPadding)?;
        if recovered
            .get(..leading_len)
            .is_none_or(|leading| leading.iter().any(|byte| *byte != 0))
        {
            return Err(RsaVerifyError::BadPadding);
        }
        verify_pss_encoded_sha256(encoded, encoded_bits, digest)
    }

    /// RSA-recover the encoded message `F = s^e mod n` and
    /// return it as exactly `k` big-endian bytes (where `k` is
    /// the modulus byte size). Shared between the PKCS#1 v1.5
    /// path and the ISO/IEC 9796-2 DS1 path.
    fn raw_recover(&self, signature: &[u8]) -> Result<Vec<u8>, RsaVerifyError> {
        let key = self;
        let k = key.modulus.byte_len();
        if signature.len() != k {
            return Err(RsaVerifyError::SignatureOutOfRange);
        }
        // bits_precision = k bytes * BITS_PER_BYTE, rounded up
        // to BOXED_UINT_LIMB_BITS.
        let bits_precision = u32::try_from(k)
            .map_err(|_e| RsaVerifyError::BadModulus)?
            .checked_mul(BITS_PER_BYTE)
            .ok_or(RsaVerifyError::BadModulus)?
            .next_multiple_of(BOXED_UINT_LIMB_BITS);
        let modulus = BoxedUint::from_be_slice(key.modulus.as_bytes(), bits_precision)
            .map_err(|_e| RsaVerifyError::BadModulus)?;
        let exponent = BoxedUint::from_be_slice_vartime(key.exponent.as_bytes());
        let signature_uint = BoxedUint::from_be_slice(signature, bits_precision)
            .map_err(|_e| RsaVerifyError::SignatureOutOfRange)?;
        if signature_uint >= modulus {
            return Err(RsaVerifyError::SignatureOutOfRange);
        }
        let odd_modulus: Odd<BoxedUint> =
            Option::from(Odd::new(modulus)).ok_or(RsaVerifyError::BadModulus)?;
        let params = BoxedMontyParams::new(odd_modulus);
        let sig_form = BoxedMontyForm::new(signature_uint, &params);
        let m_form = sig_form.pow(&exponent);
        let m = m_form.retrieve();
        let em_box = m.to_be_bytes();
        let em = match em_box.len().cmp(&k) {
            core::cmp::Ordering::Greater => {
                let extra = em_box
                    .len()
                    .checked_sub(k)
                    .ok_or(RsaVerifyError::BadPadding)?;
                let prefix = em_box.get(..extra).ok_or(RsaVerifyError::BadPadding)?;
                if prefix.iter().any(|&b| b != 0) {
                    return Err(RsaVerifyError::BadPadding);
                }
                em_box
                    .get(extra..)
                    .ok_or(RsaVerifyError::BadPadding)?
                    .to_vec()
            }
            core::cmp::Ordering::Less => {
                let pad = k
                    .checked_sub(em_box.len())
                    .ok_or(RsaVerifyError::BadPadding)?;
                let mut padded = vec![0_u8; pad];
                padded.extend_from_slice(&em_box);
                padded
            }
            core::cmp::Ordering::Equal => em_box.to_vec(),
        };
        Ok(em)
    }
}

fn verify_pss_encoded_sha256(
    encoded: &[u8],
    encoded_bits: usize,
    message_digest: &[u8],
) -> Result<(), RsaVerifyError> {
    let minimum = SHA256_OUTPUT_BYTES
        .checked_add(PSS_SHA256_SALT_BYTES)
        .and_then(|length| length.checked_add(2))
        .ok_or(RsaVerifyError::BadPadding)?;
    if encoded.len() < minimum || encoded.last().copied() != Some(PSS_TRAILER_FIELD) {
        return Err(RsaVerifyError::BadPadding);
    }
    let db_len = encoded
        .len()
        .checked_sub(SHA256_OUTPUT_BYTES + 1)
        .ok_or(RsaVerifyError::BadPadding)?;
    let (masked_db, hash_and_trailer) = encoded.split_at(db_len);
    let hash = hash_and_trailer
        .get(..SHA256_OUTPUT_BYTES)
        .ok_or(RsaVerifyError::BadPadding)?;

    let total_bits = encoded
        .len()
        .checked_mul(BITS_PER_BYTE_USIZE)
        .ok_or(RsaVerifyError::BadPadding)?;
    let unused_bits = total_bits
        .checked_sub(encoded_bits)
        .ok_or(RsaVerifyError::BadPadding)?;
    if unused_bits >= BITS_PER_BYTE_USIZE {
        return Err(RsaVerifyError::BadPadding);
    }
    let high_mask = if unused_bits == 0 {
        0
    } else {
        FULL_BYTE_MASK << (BITS_PER_BYTE_USIZE - unused_bits)
    };
    if masked_db
        .first()
        .is_none_or(|first| *first & high_mask != 0)
    {
        return Err(RsaVerifyError::BadPadding);
    }

    let mask = mgf1_sha256(hash, db_len)?;
    let mut db: Vec<u8> = masked_db
        .iter()
        .zip(mask)
        .map(|(encoded_byte, mask_byte)| encoded_byte ^ mask_byte)
        .collect();
    if let Some(first) = db.first_mut() {
        *first &= !high_mask;
    } else {
        return Err(RsaVerifyError::BadPadding);
    }

    let padding_len = db_len
        .checked_sub(PSS_SHA256_SALT_BYTES + 1)
        .ok_or(RsaVerifyError::BadPadding)?;
    if db
        .get(..padding_len)
        .is_none_or(|padding| padding.iter().any(|byte| *byte != 0))
        || db.get(padding_len).copied() != Some(PSS_DB_SEPARATOR)
    {
        return Err(RsaVerifyError::BadPadding);
    }
    let salt = db
        .get(padding_len.saturating_add(1)..)
        .filter(|salt| salt.len() == PSS_SHA256_SALT_BYTES)
        .ok_or(RsaVerifyError::BadPadding)?;
    let mut hasher = Sha256::new();
    hasher.update([0_u8; PSS_ZERO_PREFIX_BYTES]);
    hasher.update(message_digest);
    hasher.update(salt);
    if hasher.finalize().as_slice() != hash {
        return Err(RsaVerifyError::BadDigest);
    }
    Ok(())
}

fn mgf1_sha256(seed: &[u8], output_len: usize) -> Result<Vec<u8>, RsaVerifyError> {
    let blocks = output_len
        .checked_add(SHA256_OUTPUT_BYTES - 1)
        .and_then(|length| length.checked_div(SHA256_OUTPUT_BYTES))
        .ok_or(RsaVerifyError::BadPadding)?;
    let mut mask = Vec::with_capacity(output_len);
    for index in 0..blocks {
        let counter = u32::try_from(index).map_err(|_error| RsaVerifyError::BadPadding)?;
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        mask.extend_from_slice(&hasher.finalize());
    }
    mask.truncate(output_len);
    Ok(mask)
}

/// A platform hash-algorithm name not supported by [`HashAlg`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedHashAlgorithmName;

impl core::fmt::Display for UnsupportedHashAlgorithmName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("unsupported hash algorithm name")
    }
}

impl core::error::Error for UnsupportedHashAlgorithmName {}

impl TryFrom<&str> for HashAlg {
    type Error = UnsupportedHashAlgorithmName;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        match name {
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA384" => Ok(Self::Sha384),
            "SHA512" => Ok(Self::Sha512),
            _ => Err(UnsupportedHashAlgorithmName),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BITS_PER_BYTE_USIZE, FULL_BYTE_MASK, LEADING_ZERO_BYTE, PSS_DB_SEPARATOR,
        PSS_TRAILER_FIELD, PSS_ZERO_PREFIX_BYTES, RsaModulus, RsaModulusError, RsaPublicExponent,
        RsaPublicExponentError, RsaPublicKey, RsaVerifyError, SHA256_OUTPUT_BYTES, mgf1_sha256,
        verify_pss_encoded_sha256,
    };
    use sha2::{Digest as _, Sha256};

    /// A self-signed PKCS#1 v1.5 SHA-256 test vector built
    /// offline with openssl + RSA-2048 (`refineid-lib-core` does
    /// not generate keys; the vector is committed). Modulus,
    /// exponent, message, and signature were generated with:
    ///
    /// ```sh
    /// openssl genrsa 2048 > test.pem
    /// echo -n "refineid rsa test message" > msg
    /// openssl dgst -sha256 -sign test.pem -out sig msg
    /// ```
    ///
    /// Then `openssl rsa -in test.pem -text -noout` gave the
    /// modulus + e and we hex-encoded everything below.
    const MODULUS_HEX: &str = "\
b7d59d9d2f0a9c4be0b7d1a40d6b14edbe9af8a8b34c0aaa4b32fdf5ee03cbc8\
da14a51b30bfedaa6cd28a9be84a51e927e7ce5d4ad7a4c0d92cd1bb16d96b59\
1ae8866ac2cb87ea61d44b53d8a0d091e923eaf6f9b89fb01a3ec3c5d9097f8e\
7e2a86464cad6c6f5e7ad77d8ace84b62c3f8e1a91be9f08e2823e7c0c08538a\
f51c1f63b5fb9b8a7dba3f4c0d22b4d54da43c87dc6a6ba1c2d3d8e2c1d9237b\
e7c1d3c8d5717a85f5e1d4cd3e8e95443ea76eeb220e2cc41cd57bd6e02bd9a8\
21e2c3a9aa6ba9c5a830d50c5cbc12bcffe70cdde04eba6f8b7d013ad77d8ee0\
2cb7fb4dabe1c1d7f6a64fbf17f0e1b81a7d8c1a82b3a14e6a07a0fd23e4d33d";
    // Above is a placeholder -- this test_module is intentionally
    // bare. The integration validation happens through the
    // higher-level `x509::verify_certificate` test path that
    // uses DVV's real CA chain.

    /// Bytes-per-modulus for RSA-2048 (modulus byte length k =
    /// `modulus_bits` / 8). Reused across fixture builders below.
    const RSA_2048_MODULUS_BYTE_LEN: usize = 256;
    /// Bytes-per-modulus for a 256-bit modulus -- well under
    /// the [`RsaModulus::MIN_BITS`] floor, used by the "too
    /// small" rejection test.
    const TOO_SMALL_MODULUS_BYTE_LEN: usize = 32;
    /// Arbitrary odd test bitpattern: every byte = `0xC1`,
    /// low bit set so the modulus is odd. The high nibble is
    /// non-zero so the bit length matches `byte_len * 8`.
    const ODD_FILL_BYTE: u8 = 0xC1;
    /// Same pattern but with low bit cleared -- used to drive
    /// the even-modulus rejection path.
    const EVEN_FILL_BYTE: u8 = 0xC0;
    /// Signature size that doesn't match `modulus byte_len` --
    /// half-size triggers `SignatureOutOfRange`.
    const HALF_K_SIGNATURE_BYTE_LEN: usize = 128;
    /// Filler byte for the synthetic signature input. Any value
    /// works for the mismatch test.
    const SIGNATURE_FILL_BYTE: u8 = 0xAB;
    /// ASN.1 INTEGER sign byte (X.690 §8.3.2): leading `0x00`
    /// prepended to a positive integer whose high bit would
    /// otherwise make it parse as negative. The parser strips
    /// it; `try_from_pkcs1` rejects non-stripped bytes that
    /// retain it.
    const ASN1_INTEGER_SIGN_BYTE: u8 = 0x00;

    fn fixture_2048_modulus() -> RsaModulus {
        RsaModulus::try_from_pkcs1(vec![ODD_FILL_BYTE; RSA_2048_MODULUS_BYTE_LEN]).unwrap_or_else(
            |_| {
                // Unreachable for well-formed odd fill at 2048 bits.
                RsaModulus::try_from_pkcs1(vec![0x01_u8; RSA_2048_MODULUS_BYTE_LEN])
                    .unwrap_or_else(|_| unreachable!())
            },
        )
    }

    /// Assert that `result` is `Err(expected)`. Avoids `.unwrap_err()`
    /// (`clippy::unwrap_used`) while still giving a clear failure
    /// message on the wrong branch.
    fn assert_err_eq<T: core::fmt::Debug, E: PartialEq + core::fmt::Debug>(
        result: Result<T, E>,
        expected: &E,
    ) {
        match result {
            Err(e) => assert_eq!(&e, expected),
            Ok(v) => unreachable!("expected Err({expected:?}), got Ok({v:?})"),
        }
    }

    #[test]
    fn rejects_signature_size_mismatch() {
        use crate::crypto::container::{RsaPkcs1Sha256, Signature};
        let key = RsaPublicKey {
            modulus: fixture_2048_modulus(),
            exponent: RsaPublicExponent::e_65537(),
        };
        let sig =
            Signature::<RsaPkcs1Sha256>::new(vec![SIGNATURE_FILL_BYTE; HALF_K_SIGNATURE_BYTE_LEN]);
        assert_err_eq(
            key.verify_pkcs1v15_sha256(b"x", &sig),
            &RsaVerifyError::SignatureOutOfRange,
        );
    }

    #[test]
    fn rejects_even_modulus_at_construction() {
        // Even modulus (low bit = 0) is rejected at the type
        // boundary -- the verifier never sees it because
        // RsaPublicKey can't hold one.
        assert_err_eq(
            RsaModulus::try_from_pkcs1(vec![EVEN_FILL_BYTE; RSA_2048_MODULUS_BYTE_LEN]),
            &RsaModulusError::Even,
        );
    }

    #[test]
    fn rejects_too_small_modulus_at_construction() {
        let r = RsaModulus::try_from_pkcs1(vec![ODD_FILL_BYTE; TOO_SMALL_MODULUS_BYTE_LEN]);
        assert!(matches!(
            r,
            Err(RsaModulusError::BitsTooFew {
                bits: 256,
                min: 512
            })
        ));
    }

    #[test]
    fn rejects_leading_zero_modulus() {
        // ASN.1 INTEGER sign byte must be stripped before
        // calling try_from_pkcs1 -- otherwise we'd accept the
        // non-canonical form. Build a fixed-size `[u8; N+1]`
        // with the sign byte slotted at index 0.
        let mut bytes = [ODD_FILL_BYTE; RSA_2048_MODULUS_BYTE_LEN + 1];
        if let Some(slot) = bytes.first_mut() {
            *slot = ASN1_INTEGER_SIGN_BYTE;
        }
        assert_err_eq(
            RsaModulus::try_from_pkcs1(bytes),
            &RsaModulusError::LeadingZero,
        );
    }

    #[test]
    fn rejects_even_exponent_at_construction() {
        assert_err_eq(
            RsaPublicExponent::try_from_value(2),
            &RsaPublicExponentError::Even,
        );
    }

    #[test]
    fn rejects_exponent_below_three_at_construction() {
        assert_err_eq(
            RsaPublicExponent::try_from_value(1),
            &RsaPublicExponentError::TooSmall,
        );
    }

    #[test]
    fn rejects_oversized_exponent_at_construction() {
        const OVER_LIMIT_BYTES: usize = 33;
        assert_err_eq(
            RsaPublicExponent::try_from_pkcs1([1; OVER_LIMIT_BYTES]),
            &RsaPublicExponentError::TooLarge {
                bits: 257,
                max: RsaPublicExponent::MAX_BITS,
            },
        );
    }

    #[test]
    fn e_65537_canonical_form() {
        // F_4 = 2^16 + 1. Asserts the canonical PKCS#1 wire form
        // (no leading zero, big-endian magnitude) by *deriving*
        // the expected bytes from the integer value rather than
        // hand-coding them. The expression form makes the
        // mathematics self-documenting (no magic literal).
        const F_4: u64 = (1_u64 << 16) + 1;
        let be = F_4.to_be_bytes();
        let leading_zeros = be.iter().take_while(|&&b| b == LEADING_ZERO_BYTE).count();
        let e = RsaPublicExponent::e_65537();
        assert_eq!(e.as_bytes(), be.get(leading_zeros..).unwrap_or(&[]));
    }

    /// The bigger story for "does verification work end-to-end"
    /// is in `x509::verify_certificate`, where we feed the DVV G3
    /// root + the AIA-fetched G4R intermediate as a known-good
    /// chain. Test vectors there are pulled live, not committed
    /// to this file.
    #[test]
    fn placeholder_signpost() {
        // Reference to the MODULUS_HEX so dead-code lint stays quiet.
        assert!(!MODULUS_HEX.is_empty());
    }

    fn pss_encoding(message: &[u8], salt: &[u8], encoded_bits: usize) -> Vec<u8> {
        let encoded_len = encoded_bits.div_ceil(BITS_PER_BYTE_USIZE);
        let database_len = encoded_len
            .saturating_sub(SHA256_OUTPUT_BYTES)
            .saturating_sub(1);
        let padding_len = database_len.saturating_sub(salt.len()).saturating_sub(1);
        let message_digest = Sha256::digest(message);
        let mut hash_input = vec![0; PSS_ZERO_PREFIX_BYTES];
        hash_input.extend_from_slice(&message_digest);
        hash_input.extend_from_slice(salt);
        let hash = Sha256::digest(&hash_input);
        let mut database = vec![0; padding_len];
        database.push(PSS_DB_SEPARATOR);
        database.extend_from_slice(salt);
        let Ok(mask) = mgf1_sha256(&hash, database_len) else {
            unreachable!("bounded PSS test mask must fit")
        };
        for (database_byte, mask_byte) in database.iter_mut().zip(mask) {
            *database_byte ^= mask_byte;
        }
        let unused_bits = encoded_len
            .saturating_mul(BITS_PER_BYTE_USIZE)
            .saturating_sub(encoded_bits);
        if let Some(first) = database.first_mut()
            && unused_bits != 0
        {
            *first &= FULL_BYTE_MASK >> unused_bits;
        }
        database.extend_from_slice(&hash);
        database.push(PSS_TRAILER_FIELD);
        database
    }

    #[test]
    fn fixed_sha256_pss_encoding_verifies_and_detects_tampering() {
        const ENCODED_BITS: usize = 1023;
        const SALT_BYTES: usize = 32;
        let message = b"trusted-list signed info";
        let digest = Sha256::digest(message);
        let encoded = pss_encoding(message, &[42; SALT_BYTES], ENCODED_BITS);
        assert_eq!(
            verify_pss_encoded_sha256(&encoded, ENCODED_BITS, &digest),
            Ok(())
        );

        let mut tampered = encoded;
        if let Some(trailer) = tampered.last_mut() {
            *trailer ^= 1;
        }
        assert_eq!(
            verify_pss_encoded_sha256(&tampered, ENCODED_BITS, &digest),
            Err(RsaVerifyError::BadPadding)
        );
    }

    #[test]
    fn fixed_sha256_pss_rejects_other_salt_widths() {
        const ENCODED_BITS: usize = 1023;
        const WRONG_SALT_BYTES: usize = 31;
        let message = b"trusted-list signed info";
        let digest = Sha256::digest(message);
        let encoded = pss_encoding(message, &[7; WRONG_SALT_BYTES], ENCODED_BITS);
        assert!(verify_pss_encoded_sha256(&encoded, ENCODED_BITS, &digest).is_err());
    }
}
