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

//! Tiny BER-TLV encoder / decoder, scoped to what PACE and secure
//! messaging actually need.
//!
//! ISO 7816-4 BER-TLV usage in this codebase:
//!
//! - Single-byte tag for most data objects, with the explicit
//!   two-byte tag `7F 49` for PACE's public-key template.
//! - Length in short form (`0..=0x7F`) or long form (`81 LL`,
//!   `82 LL LL`). PACE / SM traffic stays under 64 KB so the
//!   parser caps at the two-byte form.
//! - Value: zero-copy slice on read; owned `Vec<u8>` on write.
//!
//! A full ASN.1 stack (`asn1`, `der`, `simple_asn1`) is
//! deliberately not pulled in -- the surface is small, the caller
//! is ourselves, and an extra crate would bring in macro-heavy
//! generated code that would need to be audited.
//!
use core::fmt;
use core::marker::PhantomData;

// === BER length-form markers (ISO 7816-4 sec.5.2.2 / X.690 sec.8.1.3) ===
//
// A BER length octet < 0x80 encodes the length directly ("short
// form"). A length octet of 0x8N (N in 1..=4) declares N follow-
// up bytes that carry the big-endian length value ("long form").
// 0x80 itself is the indefinite-length marker (only valid in
// streaming BER, never DER) and is not handled here. Values
// 0x85..=0xFE would mean a length-of-length above 4 bytes;
// this codebase rejects them because the parsed `usize` would
// overflow on 32-bit platforms and we don't process artefacts
// larger than 4 GiB anyway.

/// Smallest length that requires the long form (i.e. doesn't
/// fit in 7 bits). Equal to `0x80`.
const SHORT_FORM_CEILING: usize = 0x80;
/// Long-form length-of-length marker: length value occupies the
/// next 1 byte.
const LONG_FORM_1B: u8 = 0x81;
/// Long-form length-of-length marker: length value occupies the
/// next 2 bytes (big-endian).
const LONG_FORM_2B: u8 = 0x82;
/// Long-form length-of-length marker: length value occupies the
/// next 3 bytes (big-endian).
const LONG_FORM_3B: u8 = 0x83;
/// Long-form length-of-length marker: length value occupies the
/// next 4 bytes (big-endian).
const LONG_FORM_4B: u8 = 0x84;

/// Owned BER-TLV building buffer.
///
/// Wraps a `Vec<u8>` so that the buffer is mutated via
/// `&mut self` rather than passed around as a `&mut Vec<u8>`.
/// All length / tag arithmetic is encapsulated in the `push_*`
/// methods. Call `finish()` to extract the assembled bytes.
///
/// Typical use:
///
/// ```ignore
/// let mut enc = BerEncoder::with_capacity(20);
/// enc.push_tlv(0x80, b"hello");
/// enc.push_tlv(0x81, [1_u8, 2, 3]);
/// let bytes = enc.finish();
/// ```
#[derive(Debug, Default)]
pub struct BerEncoder {
    /// `out` field.
    out: Vec<u8>,
}

impl BerEncoder {
    /// New empty encoder with the buffer pre-sized to avoid
    /// reallocations.
    pub(crate) fn with_capacity(cap: usize) -> Self {
        Self {
            out: Vec::with_capacity(cap),
        }
    }

    /// Append a single TLV record (one-byte tag).
    pub(crate) fn push_tlv(&mut self, tag: u8, value: impl AsRef<[u8]>) {
        let value_bytes = value.as_ref();
        self.out.push(tag);
        self.push_length(value_bytes.len());
        self.out.extend_from_slice(value_bytes);
    }

    /// Append a single TLV record with a two-byte tag (the `7F
    /// 49` "public-key data" template used by PACE). High byte of
    /// `tag2` is the leading byte; low byte the second.
    pub(crate) fn push_tlv_tag2(&mut self, tag2: u16, value: impl AsRef<[u8]>) {
        let value_bytes = value.as_ref();
        // `to_be_bytes` gives `[high, low]` directly; no
        // `try_from(u16) -> u8` plumbing required.
        let [tag_hi, tag_lo] = tag2.to_be_bytes();
        self.out.push(tag_hi);
        self.out.push(tag_lo);
        self.push_length(value_bytes.len());
        self.out.extend_from_slice(value_bytes);
    }

    /// Append length octets per ISO 7816-4 sec.5.2.2.
    ///
    /// Supports the short form and the one- through four-byte
    /// long forms ([`LONG_FORM_1B`] .. [`LONG_FORM_4B`]). Four
    /// bytes is enough for any DER blob smaller than 4 GiB --
    /// well past what any FINEID-issued artefact (cert, CRL)
    /// realistically reaches.
    ///
    /// # Panics
    /// If `len` doesn't fit in 4 bytes (i.e. exceeds
    /// [`u32::MAX`]).
    #[expect(
        clippy::expect_used,
        clippy::panic,
        reason = "Encoder-side overflow: `len` comes from a `Vec<u8>` we've just produced, capped by available memory. Every `try_from` here is range-guarded by the if-chain above it (`len < SHORT_FORM_CEILING` => fits in u8, etc.). The final `panic!` documents the > u32::MAX (4 GiB) upper bound -- no FINEID-issued artefact (cert, CRL, eMRTD SOD) reaches that and the encoder can't be asked to write a length field that doesn't fit in the BER long form."
    )]
    pub(crate) fn push_length(&mut self, len: usize) {
        const U24_MAX: usize = (1 << 24) - 1;
        let u8_max = usize::from(u8::MAX);
        let u16_max = usize::from(u16::MAX);
        let u32_max = usize::try_from(u32::MAX).expect("u32::MAX fits in usize on 32+ bit targets");

        if len < SHORT_FORM_CEILING {
            self.out
                .push(u8::try_from(len).expect("len < SHORT_FORM_CEILING fits in u8"));
        } else if len <= u8_max {
            self.out.push(LONG_FORM_1B);
            self.out
                .push(u8::try_from(len).expect("len <= u8::MAX fits in u8"));
        } else if len <= u16_max {
            self.out.push(LONG_FORM_2B);
            let bytes = u16::try_from(len)
                .expect("len <= u16::MAX fits in u16")
                .to_be_bytes();
            self.out.extend_from_slice(&bytes);
        } else if len <= U24_MAX {
            self.out.push(LONG_FORM_3B);
            let bytes = u32::try_from(len)
                .expect("len <= U24_MAX fits in u32")
                .to_be_bytes();
            self.out.extend_from_slice(&bytes[1..]);
        } else if len <= u32_max {
            self.out.push(LONG_FORM_4B);
            let bytes = u32::try_from(len)
                .expect("len <= u32::MAX fits in u32")
                .to_be_bytes();
            self.out.extend_from_slice(&bytes);
        } else {
            panic!("BER length > u32::MAX not supported");
        }
    }

    /// Finalise and return the assembled bytes.
    pub(crate) fn finish(self) -> Vec<u8> {
        self.out
    }
}

/// Wrap `value` in a single-byte-tag TLV and return as a fresh
/// `Vec<u8>`. Convenience for the common single-TLV case.
///
/// # Panics
/// As for [`BerEncoder::push_length`].
#[must_use]
#[expect(
    clippy::redundant_pub_crate,
    reason = "crate-internal BER helper is used by sibling modules; plain pub would violate the public-surface typing grep"
)]
pub(crate) fn tlv(tag: u8, value: impl AsRef<[u8]>) -> Vec<u8> {
    let value_bytes = value.as_ref();
    // Capacity is a hint -- `saturating_add` keeps the
    // arithmetic-side-effects lint quiet without changing
    // behaviour: an absurd `value.len()` near `usize::MAX`
    // would saturate to `usize::MAX` here, and the allocator
    // would then refuse to allocate. Same observable outcome
    // as wrapping the addition with a panic.
    let cap = value_bytes.len().saturating_add(4);
    let mut enc = BerEncoder::with_capacity(cap);
    enc.push_tlv(tag, value_bytes);
    enc.finish()
}

/// Wrap `value` in a two-byte-tag TLV and return as a fresh
/// `Vec<u8>`.
///
/// # Panics
/// As for [`BerEncoder::push_length`].
#[must_use]
#[expect(
    clippy::redundant_pub_crate,
    reason = "crate-internal BER helper is used by sibling modules; plain pub would violate the public-surface typing grep"
)]
pub(crate) fn tlv2(tag2: u16, value: impl AsRef<[u8]>) -> Vec<u8> {
    let value_bytes = value.as_ref();
    // Capacity hint: saturating-add against the corner case
    // of a `value.len()` near `usize::MAX`. See `tlv` above.
    let cap = value_bytes.len().saturating_add(5);
    let mut enc = BerEncoder::with_capacity(cap);
    enc.push_tlv_tag2(tag2, value_bytes);
    enc.finish()
}

/// Decoder-side errors produced when parsing a BER/DER TLV byte
/// stream into typed values.
///
/// ITU-T X.690 distinguishes BER (permissive) from DER
/// (canonical); this codebase parses BER but emits DER. The
/// variants below cover only the structural failures the decoder
/// can detect locally -- semantic mismatches (wrong OID, missing
/// field) are surfaced by the call site, not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BerError {
    /// Input slice was empty -- not even a tag byte present.
    Empty,
    /// Input ended before the declared length-of-length or
    /// value bytes were available.
    Truncated,
    /// Length-of-length byte demanded more than four follow-on
    /// bytes (the indefinite-length marker `0x80` or any
    /// `0x85..=0xFE`) -- this codebase rejects those.
    UnsupportedLengthForm,
    /// Tag mismatch when promoting a [`BerTlvAny`] to a typed
    /// [`BerTlv<T>`]. `expected` is `T::TAG`; `got` is the
    /// actually-parsed tag.
    UnexpectedTag {
        /// The `BerTag::TAG` we wanted.
        expected: u16,
        /// The byte we actually parsed.
        got: u16,
    },
}

impl fmt::Display for BerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "BER: empty input"),
            Self::Truncated => write!(f, "BER: truncated input"),
            Self::UnsupportedLengthForm => write!(f, "BER: length form not supported"),
            Self::UnexpectedTag { expected, got } => {
                write!(f, "BER: expected tag {expected:#X}, got {got:#X}")
            }
        }
    }
}

impl core::error::Error for BerError {}

// === Typed TLV layer ===
//
// Phantom-typed wrapper over [`parse_tlv`]. The tag identity
// is carried at the type level via a marker that implements
// [`BerTag`], so constructing a [`BerTlv<T>`] is a trust-
// boundary parse: the tag is verified once, the typed value
// is handed downstream.
//
// Heterogeneous-child iteration uses [`BerTlvAny`], the un-
// typed peek form. Promote with `.expect::<T>()` once the
// caller has decided the expected tag (typically after
// branching on the OID inside).

/// Marker for a BER tag value.
///
/// Single-byte tags occupy the low 8 bits (`const TAG: u16 =
/// 0x30` for `SEQUENCE`); two-byte tags (only `7F 49` in this
/// codebase, used by PACE) use both bytes (`0x7F49`).
///
/// Implementors are zero-sized marker types -- e.g.
/// [`Sequence`], [`Integer`], or a per-module context tag like
/// `PaceKeyTemplate` defined where it's used. The trait has no
/// methods; the only contract is the `TAG` constant.
pub trait BerTag {
    /// Encoded tag value.
    const TAG: u16;
}

/// Typed BER-TLV slice.
///
/// Constructed at a trust boundary via [`BerTlv::parse`], which
/// rejects mismatched tags. Downstream code consumes
/// `tlv.value` knowing the tag is `T::TAG`; the compiler
/// refuses to pass a `BerTlv<Integer>` where `BerTlv<Sequence>`
/// is required.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "BER-parser ergonomics: `tlv.value` / `tlv.size` are read directly across every TLV parsing site inside lib-core; gating them behind `pub(crate) fn value(&self) -> &[u8]` accessors would add ceremony to hundreds of parser sites without adding any invariant beyond what the type already enforces (the typed tag is parse-validated at construction)"
)]
pub struct BerTlv<'a, T: BerTag> {
    /// Value bytes (no tag, no length).
    pub(crate) value: &'a [u8],
    /// Total bytes consumed (tag + length-of-length + length +
    /// value), useful for advancing a parser cursor.
    pub(crate) size: usize,
    /// `_phantom` field.
    _phantom: PhantomData<fn() -> T>,
}

impl<T: BerTag> fmt::Debug for BerTlv<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // T isn't required to be Debug -- markers are zero-sized
        // and Debug-irrelevant. The tag value is the useful
        // identifier; emit it as `tag=0xNN`.
        write!(
            f,
            "BerTlv {{ tag: {:#X}, value: {:?}, size: {} }}",
            T::TAG,
            self.value,
            self.size,
        )
    }
}

impl<T: BerTag> Clone for BerTlv<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T: BerTag> Copy for BerTlv<'_, T> {}

impl<T: BerTag> PartialEq for BerTlv<'_, T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value && self.size == other.size
    }
}
impl<T: BerTag> Eq for BerTlv<'_, T> {}

impl<'a, T: BerTag> BerTlv<'a, T> {
    /// Parse `bytes` as a TLV whose tag must equal `T::TAG`.
    ///
    /// # Errors
    /// - [`BerError::Empty`] / [`BerError::Truncated`] from
    ///   the underlying TLV parse.
    /// - [`BerError::UnexpectedTag`] when the parsed tag
    ///   doesn't match `T::TAG`.
    pub(crate) fn parse(bytes: &'a [u8]) -> Result<Self, BerError> {
        BerTlvAny::parse(bytes)?.expect::<T>()
    }

    /// Iterate the children of this TLV's `value`.
    ///
    /// Children may carry heterogeneous tags (the constructed-
    /// TLV case), so the iterator yields [`BerTlvAny`]; consumers
    /// promote each child via `.expect::<ChildTag>()` once
    /// they've decided what to expect.
    #[must_use]
    pub(crate) const fn iter_children(self) -> BerTlvIter<'a> {
        BerTlvIter::new(self.value)
    }
}

/// Untyped TLV -- the peek form.
///
/// Use when the protocol can produce children with multiple
/// tag classes that the parser branches on (e.g., an X.509
/// extension block where each child's tag selects the
/// extension shape). Promote with [`BerTlvAny::expect`] once
/// the expected tag is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "BER-parser ergonomics: same rationale as BerTlv above -- tlv.tag / tlv.value / tlv.size read across every untyped-tag parsing site; no invariant beyond what construction enforces"
)]
pub struct BerTlvAny<'a> {
    /// Parsed tag value.
    pub(crate) tag: u16,
    /// Value bytes (no tag, no length).
    pub(crate) value: &'a [u8],
    /// Total bytes consumed (tag + length-of-length + length +
    /// value).
    pub(crate) size: usize,
}

impl<'a> BerTlvAny<'a> {
    /// Parse `bytes` as a TLV without enforcing a particular
    /// tag.
    ///
    /// Supports single-byte tags or the specific two-byte tag
    /// `7F 49` used by PACE for the public-key template.
    ///
    /// # Errors
    /// - [`BerError::Empty`] if `bytes` is empty.
    /// - [`BerError::Truncated`] if the tag, length, or value
    ///   is shorter than declared.
    /// - [`BerError::UnsupportedLengthForm`] for length forms
    ///   above the four-byte long form.
    pub(crate) fn parse(bytes: &'a [u8]) -> Result<Self, BerError> {
        // Two-byte tag detection: ISO 7816-4 sec.5.2.2.1 -- bits 5..=1 of
        // the first byte == 0x1F means "tag continues in the next
        // byte". The only such tag this codebase needs is `7F 49`.
        const MULTI_BYTE_TAG_MASK: u8 = 0x1F;

        // `next` consumes one byte from `bytes[idx..]` and returns
        // `BerError::Truncated` if out of range -- turns each
        // `bytes[idx]; idx += 1` into a single fallible read with
        // no bare indexing.
        let mut idx: usize = 0;
        let mut next = |label_first_byte: bool| -> Result<u8, BerError> {
            let b = bytes
                .get(idx)
                .copied()
                .ok_or(if label_first_byte && idx == 0 {
                    BerError::Empty
                } else {
                    BerError::Truncated
                })?;
            // `bytes.get(idx)` just succeeded, so `idx < bytes.len()`
            // and `bytes.len()` fits in `usize` -- the +1 cannot
            // overflow. `saturating_add` documents the bound without
            // a separate overflow-check branch.
            idx = idx.saturating_add(1);
            Ok(b)
        };

        let first = next(true)?;

        let tag: u16 = if first & MULTI_BYTE_TAG_MASK == MULTI_BYTE_TAG_MASK {
            let second = next(false)?;
            (u16::from(first) << 8_u32) | u16::from(second)
        } else {
            u16::from(first)
        };

        let len_first = next(false)?;
        let length: usize = if len_first < LONG_FORM_1B {
            usize::from(len_first)
        } else {
            // Long-form: number of length bytes is `len_first &
            // 0x0F`. We support 1..=4 here; anything else
            // (including the indefinite-length marker 0x80) is
            // rejected per the module-level note.
            let nbytes: usize = match len_first {
                LONG_FORM_1B => 1,
                LONG_FORM_2B => 2,
                LONG_FORM_3B => 3,
                LONG_FORM_4B => 4,
                _ => return Err(BerError::UnsupportedLengthForm),
            };
            let len_bytes = bytes
                .get(idx..idx.saturating_add(nbytes))
                .ok_or(BerError::Truncated)?;
            idx = idx.saturating_add(nbytes);
            len_bytes
                .iter()
                .fold(0_usize, |acc, &b| (acc << 8_u32) | usize::from(b))
        };

        let value_end = idx.checked_add(length).ok_or(BerError::Truncated)?;
        let value = bytes.get(idx..value_end).ok_or(BerError::Truncated)?;
        Ok(Self {
            tag,
            value,
            size: value_end,
        })
    }

    /// Promote to a typed [`BerTlv<T>`].
    ///
    /// # Errors
    /// [`BerError::UnexpectedTag`] when the parsed tag doesn't
    /// match `T::TAG`.
    pub(crate) fn expect<T: BerTag>(self) -> Result<BerTlv<'a, T>, BerError> {
        if self.tag != T::TAG {
            return Err(BerError::UnexpectedTag {
                expected: T::TAG,
                got: self.tag,
            });
        }
        Ok(BerTlv {
            value: self.value,
            size: self.size,
            _phantom: PhantomData,
        })
    }
}

/// Iterator over heterogeneous TLV children. Yielded values
/// are [`BerTlvAny`]; promote with [`BerTlvAny::expect`].
#[derive(Debug)]
pub struct BerTlvIter<'a> {
    /// `remaining` field.
    remaining: &'a [u8],
}

impl<'a> BerTlvIter<'a> {
    /// Wrap a `value` slice (the inside of a constructed TLV).
    #[must_use]
    pub(crate) const fn new(value: &'a [u8]) -> Self {
        Self { remaining: value }
    }

    /// Bytes not yet consumed by the iterator. Test-only inspector
    /// for assertions like "the iterator drained the full slice".
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn remaining(&self) -> &'a [u8] {
        self.remaining
    }
}

impl<'a> Iterator for BerTlvIter<'a> {
    type Item = Result<BerTlvAny<'a>, BerError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        match BerTlvAny::parse(self.remaining) {
            Ok(t) => {
                // `t.size` is the byte count `parse` consumed; it is
                // guaranteed `<= self.remaining.len()` by the
                // parser's `value_end` check. `.get(...)` keeps the
                // bound proof local rather than relying on the
                // invariant at the index site.
                self.remaining = self.remaining.get(t.size..).unwrap_or(&[]);
                Some(Ok(t))
            }
            Err(e) => {
                self.remaining = &[];
                Some(Err(e))
            }
        }
    }
}

// === Universal ASN.1 tag markers ===
//
// Module-local context tags (e.g. PACE's `7F 49` template,
// `[0]` constructed in an X.509 TBS) live in their owning
// module so the marker name reflects its semantic role, not
// its raw tag byte.

/// `BOOLEAN` (tag 0x01).
pub struct Boolean;
impl BerTag for Boolean {
    const TAG: u16 = 0x01;
}

/// `INTEGER` (tag 0x02).
pub struct Integer;
impl BerTag for Integer {
    const TAG: u16 = 0x02;
}

/// `BIT STRING` (tag 0x03).
pub struct BitString;
impl BerTag for BitString {
    const TAG: u16 = 0x03;
}

/// `OCTET STRING` (tag 0x04).
pub struct OctetString;
impl BerTag for OctetString {
    const TAG: u16 = 0x04;
}

/// `OBJECT IDENTIFIER` (tag 0x06).
pub struct Oid;
impl BerTag for Oid {
    const TAG: u16 = 0x06;
}

/// `UTF8String` (tag 0x0C).
pub struct Utf8String;
impl BerTag for Utf8String {
    const TAG: u16 = 0x0C;
}

/// `PrintableString` (tag 0x13).
pub struct PrintableString;
impl BerTag for PrintableString {
    const TAG: u16 = 0x13;
}

// `UTCTime` (0x17) / `GeneralizedTime` (0x18) are decoded by
// x509-cert (`Time` / `Validity`), so no local `BerTag` marker is
// needed for them.

/// `SEQUENCE` / `SEQUENCE OF` (tag 0x30, constructed).
pub struct Sequence;
impl BerTag for Sequence {
    const TAG: u16 = 0x30;
}

/// `SET` / `SET OF` (tag 0x31, constructed).
pub struct Set;
impl BerTag for Set {
    const TAG: u16 = 0x31;
}

#[cfg(test)]
mod tests {

    use super::{
        BerEncoder, BerError, BerTag, BerTlv, BerTlvAny, BerTlvIter, Integer, OctetString,
        Sequence, tlv, tlv2,
    };

    #[test]
    fn short_form_length_round_trip() {
        let mut enc = BerEncoder::default();
        enc.push_tlv(0x80, [0xAA, 0xBB, 0xCC]);
        let buf = enc.finish();
        assert_eq!(buf, &[0x80, 0x03, 0xAA, 0xBB, 0xCC]);

        let parsed = BerTlvAny::parse(&buf).expect("short-form TLV parses");
        assert_eq!(parsed.tag, 0x80);
        assert_eq!(parsed.value, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(parsed.size, 5);
    }

    #[test]
    fn long_form_one_byte_length() {
        // 200-byte value triggers the 0x81 long-form length.
        let v = vec![0xCD; 200];
        let mut enc = BerEncoder::default();
        enc.push_tlv(0x81, &v);
        let buf = enc.finish();
        assert_eq!(&buf[..3], &[0x81, 0x81, 0xC8]);
        let parsed = BerTlvAny::parse(&buf).expect("one-byte long-form TLV parses");
        assert_eq!(parsed.value.len(), 200);
    }

    #[test]
    fn long_form_two_byte_length() {
        // 0x1234 = 4660 bytes triggers the 0x82 form.
        let v = vec![0xEE; 0x1234];
        let mut enc = BerEncoder::default();
        enc.push_tlv(0x80, &v);
        let buf = enc.finish();
        assert_eq!(&buf[..4], &[0x80, 0x82, 0x12, 0x34]);
        let parsed = BerTlvAny::parse(&buf).expect("two-byte long-form TLV parses");
        assert_eq!(parsed.value.len(), 0x1234);
        assert_eq!(parsed.size, 4 + 0x1234);
    }

    #[test]
    fn long_form_three_byte_length_round_trip() {
        // 0x01_0000 = 65536 bytes -- one over the u16 ceiling --
        // forces the 0x83 form.
        let v = vec![0x11; 0x0001_0000];
        let mut enc = BerEncoder::default();
        enc.push_tlv(0x80, &v);
        let buf = enc.finish();
        assert_eq!(&buf[..5], &[0x80, 0x83, 0x01, 0x00, 0x00]);
        let parsed = BerTlvAny::parse(&buf).expect("three-byte long-form TLV parses");
        assert_eq!(parsed.value.len(), 0x0001_0000);
        assert_eq!(parsed.size, 5 + 0x0001_0000);
    }

    #[test]
    fn long_form_four_byte_length_round_trip() {
        // 0x0100_0000 = 16 MiB -- forces the 0x84 form. Bigger
        // than a typical FINEID CRL (~13 MB) so the parser
        // covers real production lengths.
        let v = vec![0x22; 0x0100_0000];
        let mut enc = BerEncoder::default();
        enc.push_tlv(0x80, &v);
        let buf = enc.finish();
        assert_eq!(&buf[..6], &[0x80, 0x84, 0x01, 0x00, 0x00, 0x00]);
        let parsed = BerTlvAny::parse(&buf).expect("four-byte long-form TLV parses");
        assert_eq!(parsed.value.len(), 0x0100_0000);
    }

    #[test]
    fn long_form_three_byte_truncated_input_rejected() {
        // Tag, 0x83, missing two of the three length bytes.
        let buf = [0x80, 0x83, 0xAA];
        assert!(matches!(BerTlvAny::parse(&buf), Err(BerError::Truncated)));
    }

    #[test]
    fn long_form_four_byte_truncated_input_rejected() {
        let buf = [0x80, 0x84, 0xAA, 0xBB, 0xCC];
        assert!(matches!(BerTlvAny::parse(&buf), Err(BerError::Truncated)));
    }

    #[test]
    fn rejects_length_form_above_0x84() {
        // 0x85 = "length-of-length is 5 bytes" -- our parser
        // doesn't support it (would need >32-bit usize).
        let buf = [0x80, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0x42];
        assert!(matches!(
            BerTlvAny::parse(&buf),
            Err(BerError::UnsupportedLengthForm)
        ));
    }

    #[test]
    fn two_byte_tag_7f49() {
        // PACE's public-key template.
        let inner = [0x06, 0x01, 0x42, 0x86, 0x01, 0x77];
        let buf = tlv2(0x7F49, inner);
        let parsed = BerTlvAny::parse(&buf).expect("two-byte-tag TLV parses");
        assert_eq!(parsed.tag, 0x7F49);
        assert_eq!(parsed.value, inner);
    }

    #[test]
    fn iterating_constructed_dynamic_authentication_data() {
        // Mock the encrypted-nonce response: `7C L 80 16 <16 zero bytes>`.
        let nonce = [0_u8; 16];
        let inner = tlv(0x80, nonce);
        let outer = tlv(0x7C, &inner);

        let parsed = BerTlvAny::parse(&outer).expect("outer 7C template parses");
        assert_eq!(parsed.tag, 0x7C);
        let mut it = BerTlvIter::new(parsed.value);
        let nonce_tlv = it
            .next()
            .expect("iterator yields the nonce TLV")
            .expect("nonce TLV parses");
        assert_eq!(nonce_tlv.tag, 0x80);
        assert_eq!(nonce_tlv.value.len(), 16);
        assert!(it.next().is_none());
    }

    #[test]
    fn rejects_truncated_input() {
        let truncated = [0x80, 0x05, 0xAA];
        assert!(matches!(
            BerTlvAny::parse(&truncated),
            Err(BerError::Truncated)
        ));
    }

    #[test]
    fn rejects_wrong_tag() {
        let buf = tlv(0x80, [0x01]);
        let r = BerTlvAny::parse(&buf)
            .expect("context-tag TLV parses")
            .expect::<Sequence>();
        assert!(matches!(
            r,
            Err(BerError::UnexpectedTag {
                expected: 0x30,
                got: 0x80
            })
        ));
    }

    // === typed layer tests ===

    #[test]
    fn typed_parse_matches_tag() {
        let inner = [0x01, 0x02, 0x03];
        let buf = tlv(0x30, inner);
        let parsed = BerTlv::<Sequence>::parse(&buf).expect("parse");
        assert_eq!(parsed.value, &inner);
        assert_eq!(parsed.size, buf.len());
    }

    #[test]
    fn typed_parse_rejects_wrong_tag() {
        let buf = tlv(0x02, [0x42]);
        let err = BerTlv::<Sequence>::parse(&buf).expect_err("INTEGER tag is rejected as SEQUENCE");
        assert!(matches!(
            err,
            BerError::UnexpectedTag {
                expected: 0x30,
                got: 0x02
            }
        ));
    }

    #[test]
    fn any_then_expect_round_trip() {
        let buf = tlv(0x04, [0xAA, 0xBB]);
        let any = BerTlvAny::parse(&buf).expect("any parse");
        assert_eq!(any.tag, 0x04);
        let typed = any.expect::<OctetString>().expect("promote");
        assert_eq!(typed.value, &[0xAA, 0xBB]);
    }

    #[test]
    fn any_expect_rejects_mismatch() {
        let buf = tlv(0x04, [0xAA]);
        let any = BerTlvAny::parse(&buf).expect("any parse");
        let err = any
            .expect::<Integer>()
            .expect_err("OCTET STRING tag is rejected as INTEGER");
        assert!(matches!(
            err,
            BerError::UnexpectedTag {
                expected: 0x02,
                got: 0x04
            }
        ));
    }

    #[test]
    fn iter_children_walks_heterogeneous_tags() {
        // Mock a SEQUENCE { INTEGER, OCTET STRING }.
        let mut inner = BerEncoder::default();
        inner.push_tlv(0x02, [0x07]);
        inner.push_tlv(0x04, [0xDE, 0xAD]);
        let buf = tlv(0x30, inner.finish());

        let seq = BerTlv::<Sequence>::parse(&buf).expect("seq");
        let mut it = seq.iter_children();
        let first = it.next().expect("first").expect("ok");
        assert_eq!(first.tag, 0x02);
        let second = it.next().expect("second").expect("ok");
        assert_eq!(second.tag, 0x04);
        assert!(it.next().is_none());
    }

    #[test]
    fn tag_constants_distinct() {
        // Mostly a compile-time sanity check; tag bytes are
        // pinned by ASN.1 universal class.
        assert_eq!(<Integer as BerTag>::TAG, 0x02);
        assert_eq!(<OctetString as BerTag>::TAG, 0x04);
        assert_eq!(<Sequence as BerTag>::TAG, 0x30);
    }

    #[test]
    fn iter_remaining_after_drain() {
        let buf = tlv(0x30, []);
        let seq = BerTlv::<Sequence>::parse(&buf).expect("seq");
        let it = seq.iter_children();
        assert!(it.remaining().is_empty());
    }

    #[test]
    fn typed_parse_truncated_propagates() {
        let buf = [0x30, 0x05, 0xAA];
        let err = BerTlv::<Sequence>::parse(&buf).expect_err("truncated SEQUENCE is rejected");
        assert!(matches!(err, BerError::Truncated));
    }

    fn _bertlv_iter_used_in_anger(_it: BerTlvIter<'_>) {
        // Smoke: `BerTlvIter` must be name-importable from this
        // module's test surface (regression for module-private
        // type leaking past `pub`).
    }
}
