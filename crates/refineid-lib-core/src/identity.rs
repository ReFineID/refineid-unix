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

//! Credential-and-holder identity.
//!
//! [`CredentialIdentity`] is refineid's canonical "this person,
//! this credential instance" descriptor. Same shape works for:
//!
//! - FINEID smartcards: surname / given names / PEUIN parsed
//!   from the cert DN, token serial from EF.TokenInfo.
//! - Future EUDI Wallet credentials, mDoc bindings, attestation
//!   profiles: same field set, different sources.
//!
//! The type is deliberately small and slot-agnostic. A card has
//! multiple keys; when a context needs to talk about a specific
//! key, it decorates the identity with a slot label rather than
//! baking the slot into the identity. Same with chain context,
//! validity windows, fingerprints -- they live alongside the
//! identity, not inside it.
//!
//! Multiple render paths, one struct:
//!
//! | Context              | How to render
//! |----------------------|-----------------------------------------
//! | SSH key comment      | `to_ssh_comment` -- printed serial only
//! | CLI report header    | `Display` or [`to_kv_string`]
//! | PKCS#11 `CKA_LABEL`  | `Display` (or `to_prompt_label` w/ budget)
//! | Audit / agent CBOR   | serde derives (feature-gated, future)
//! | HTTP / JSON output   | `serde_json` (feature-gated, future)
//!
//! Each render path picks the serial form that suits its context:
//! `Display` prefers the printed form but falls back to the full
//! PKCS#15 chip serial when no printed form is known (useful in
//! operator-facing CLI output where the full serial is meaningful);
//! `to_ssh_comment` uses the printed form **only**, never the
//! full chip serial -- an SSH public key travels to people who see
//! only the plastic-printed card identifier, so a 17-or-20-char
//! chip serial they can't cross-reference is just noise.
//!
//! serde derives stay off-by-default to keep lib-core's
//! dependency surface tight; callers that need CBOR / JSON
//! enable the future `serde` feature when it lands.
//!
//! [`to_kv_string`]: CredentialIdentity::to_kv_string

use core::fmt;
use core::ops::Deref;

/// Full chip-side card identifier.
///
/// Derived from the PKCS#15 EF.TokenInfo `serialNumber` octet
/// string via [`render_token_serial`]. Format varies by chip
/// generation (ASCII on v4.0+ cards, hex-of-BCD on v3.1), but
/// the value is stable per physical card and serves as the
/// "session identity" binding for trust-gated flows: read once
/// at session open, re-read before each modify APDU, compare
/// for equality. Different physical card => different value =>
/// session revocation.
///
/// Distinct from [`PrintedSerial`] (the plastic-printed
/// truncation) and from `Certificate.serialNumber` (the X.509
/// integer). Strong typing keeps these three independently-
/// typed even though all are string-shaped on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenSerial(String);

impl TokenSerial {
    /// Wrap an already-rendered token serial. No structural
    /// check (format varies per chip generation); the type
    /// only carries the "this is a PKCS#15 long serial"
    /// semantic.
    #[must_use]
    pub const fn new(s: String) -> Self {
        Self(s)
    }

    /// Borrow the underlying serial string for emission.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Decode this token serial as ASCII hex bytes.
    #[must_use]
    fn decoded_hex_bytes(&self) -> Option<Vec<u8>> {
        let s = self.as_str();
        if !s.len().is_multiple_of(2) {
            return None;
        }
        let bytes = s.as_bytes();
        let cap = s.len().div_euclid(2);
        let mut out = Vec::with_capacity(cap);
        for pair in bytes.chunks_exact(2) {
            let &[hi_byte, lo_byte] = pair else {
                return None;
            };
            let h = nybble(hi_byte)?;
            let l = nybble(lo_byte)?;
            let byte = h.wrapping_shl(4) | l;
            out.push(byte);
        }
        Some(out)
    }
}

impl Deref for TokenSerial {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for TokenSerial {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TokenSerial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<str> for TokenSerial {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for TokenSerial {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// Plastic-printed card identifier.
///
/// Derived from a [`TokenSerial`] by per-chip-generation
/// truncation (see [`derive_printed_serial`]). What a
/// cardholder reads off the plastic and quotes to DVV; what an
/// SSH key comment carries (never the full chip serial -- the
/// reader's of an SSH key see only the printed form). Cannot
/// be cross-substituted with [`TokenSerial`] -- they identify
/// the same card but in different forms aimed at different
/// audiences.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PrintedSerial(String);

impl PrintedSerial {
    /// Wrap an already-rendered printed serial. No structural
    /// check; the type only carries the "this is the plastic-
    /// printed form" semantic. Constructed by the per-chip-
    /// generation derivation in [`derive_printed_serial`].
    #[must_use]
    pub const fn new(s: String) -> Self {
        Self(s)
    }

    /// Borrow the underlying serial string for emission.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for PrintedSerial {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for PrintedSerial {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PrintedSerial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<str> for PrintedSerial {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for PrintedSerial {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// Personal Electronic Unique Identification Number.
///
/// Per FINEID S2 v5.2 §6.3.6.1: `SerialNumber` attribute
/// contains a unique identifier (8 digits + checksum
/// character) for a person that within Finland identifies the
/// subject of certification from other persons having exactly
/// the same name. Also known as SATU in Finnish-language
/// FINEID material.
///
/// Constructor enforces the shape (9 ASCII bytes: 8 digits
/// followed by one alphanumeric character). Code that consumes
/// `&Peuin` can rely on those invariants without re-validating
/// at every use site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Peuin([u8; 9]);

/// Construction errors emitted by `Peuin::new`.
///
/// Diagnostic-shaped: each variant carries the offending value
/// plus the expectation it failed, so the CLI can render a
/// human-readable error without re-extracting the inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeuinError {
    /// Input wasn't exactly 9 bytes (8 ASCII digits + 1
    /// checksum character).
    WrongLength {
        /// Number of bytes actually given.
        got: usize,
    },
    /// One of positions 0..8 wasn't an ASCII digit. PEUIN is
    /// strictly numeric in those slots.
    NonDigit {
        /// Byte offset (0-based) where the bad character lives.
        at: usize,
        /// The offending byte value at `at`.
        byte: u8,
    },
    /// Position 8 (the checksum) didn't match the computed
    /// checksum for positions 0..8. The DVV PEUIN spec uses a
    /// mod-31 weighted sum over the 8 leading digits.
    BadChecksum {
        /// The byte value at position 8 that failed the check.
        byte: u8,
    },
}

impl fmt::Display for PeuinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { got } => write!(
                f,
                "PEUIN must be exactly 9 characters (8 digits + 1 checksum), got {got}"
            ),
            Self::NonDigit { at, byte } => write!(
                f,
                "PEUIN positions 0..8 must be ASCII digits; non-digit at offset {at}: {byte:#04x}"
            ),
            Self::BadChecksum { byte } => write!(
                f,
                "PEUIN checksum (position 8) must be ASCII alphanumeric; got {byte:#04x}"
            ),
        }
    }
}

impl core::error::Error for PeuinError {}

impl Peuin {
    /// Parse `s` as a PEUIN. 9 ASCII bytes: positions `0..=7`
    /// must be digits, position `8` must be alphanumeric (the
    /// checksum). Anything else is rejected with a specific
    /// [`PeuinError`].
    ///
    /// The checksum value itself is not verified against the
    /// 8-digit body -- DVV's checksum algorithm is the
    /// reference, and the cert issuer is the authority; we
    /// trust the cert's value.
    ///
    /// # Errors
    /// [`PeuinError`] variants for wrong length, non-digit in
    /// the body, or a bad checksum character.
    pub(crate) fn new(s: &str) -> Result<Self, PeuinError> {
        let bytes = s.as_bytes();
        if bytes.len() != 9 {
            return Err(PeuinError::WrongLength { got: bytes.len() });
        }
        // bytes.len() == 9 verified above; build the 9-byte buf
        // up front so we can index it as an array (no .get()/
        // .expect() chain).
        let mut buf = [0_u8; 9];
        buf.copy_from_slice(bytes);
        for (i, &b) in buf.iter().take(8).enumerate() {
            if !b.is_ascii_digit() {
                return Err(PeuinError::NonDigit { at: i, byte: b });
            }
        }
        let checksum_byte = buf[8];
        if !checksum_byte.is_ascii_alphanumeric() {
            return Err(PeuinError::BadChecksum {
                byte: checksum_byte,
            });
        }
        Ok(Self(buf))
    }

    /// String view. Always valid UTF-8 because the constructor
    /// rejected every byte that wasn't 7-bit ASCII.
    ///
    /// # Panics
    /// Never under correct construction; the constructor only
    /// accepts ASCII alphanumerics, which are UTF-8 by
    /// definition.
    #[must_use]
    pub fn as_str(&self) -> &str {
        #[expect(
            clippy::expect_used,
            reason = "Peuin::new accepts only ASCII alphanumerics, which are always valid UTF-8; the expect documents the proven invariant."
        )]
        let s = core::str::from_utf8(&self.0).expect("Peuin bytes are ASCII by construction");
        s
    }

    /// Borrow the underlying 9-byte array (ICAO 9303 PEUIN: 8
    /// alphanumeric characters + 1 checksum character).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 9] {
        &self.0
    }
}

impl Deref for Peuin {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for Peuin {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Peuin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PartialEq<str> for Peuin {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for Peuin {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

/// Family name as it appears in the cert subject DN
/// (X.520 `surName`, OID 2.5.4.4).
///
/// Validated only as "non-empty" -- FINEID stores the family
/// name as a `UTF8String` with ISO 8859-1 characters, and
/// that's the strictest constraint we can apply without
/// baking in locale-specific rules about hyphens, apostrophes,
/// etc. Strong typing is for slot identity, not for surname
/// validation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Surname(String);

/// Construction error shared by every free-text identity
/// newtype (names, titles, places, free-form DG11 / DG12
/// fields).
///
/// We deliberately validate only **non-empty** and **bounded
/// byte length**: per FINEID S2 v5.2 §6.3.4 cert subject
/// strings are UTF-8 with ISO 8859-1 codepoints, and ICAO
/// 9303-10 DG11/DG12 free-text fields are UTF-8 with no
/// repertoire constraint. We trust the issuer's encoding and
/// pass UTF-8 through verbatim -- diacritics (Š, Ž, Õ, Ć, Ł,
/// ß, ...) preserved as-is. Type construction is the trust
/// boundary, not the codepoint police.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreeTextError {
    /// Input was zero bytes.
    Empty,
    /// Input exceeded the per-field byte budget.
    ///
    /// Budgets are generous (1024 bytes) but bounded so a
    /// runaway DG read cannot DOS the renderer with a multi-MB
    /// "name" field.
    TooLong {
        /// Length of the rejected input in UTF-8 bytes. Tier 0
        /// `usize`; arithmetic count.
        got: usize,
        /// The per-field byte cap that was breached (mirrors
        /// [`FREE_TEXT_MAX_BYTES`] today). Tier 0 `usize`.
        max: usize,
    },
}

impl fmt::Display for FreeTextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("free-text value cannot be empty"),
            Self::TooLong { got, max } => {
                write!(f, "free-text length {got} bytes exceeds maximum {max}")
            }
        }
    }
}

impl core::error::Error for FreeTextError {}

/// Maximum byte length accepted by every free-text newtype.
///
/// 1024 is well above any realistic on-card field size (DG11
/// `personal_summary` is the largest expected payload at a few
/// hundred bytes) while still bounding pathological input.
pub const FREE_TEXT_MAX_BYTES: usize = 1024;

/// Borrowed free-text candidate validated at the identity boundary.
///
/// Private proof type used by the many slot-specific newtypes below: the
/// wrapped string is non-empty and within [`FREE_TEXT_MAX_BYTES`].
struct FreeText<'a> {
    /// Validated free-text string.
    value: &'a str,
}

impl<'a> FreeText<'a> {
    /// Validate a borrowed free-text value.
    ///
    /// # Errors
    /// [`FreeTextError::Empty`] if the string is empty,
    /// [`FreeTextError::TooLong`] if it exceeds [`FREE_TEXT_MAX_BYTES`].
    const fn parse(value: &'a str) -> Result<Self, FreeTextError> {
        if value.is_empty() {
            return Err(FreeTextError::Empty);
        }
        if value.len() > FREE_TEXT_MAX_BYTES {
            return Err(FreeTextError::TooLong {
                got: value.len(),
                max: FREE_TEXT_MAX_BYTES,
            });
        }
        Ok(Self { value })
    }
}

/// Free-text source being normalized from issuer uppercase to native case.
struct LegacyUppercaseName<'a> {
    /// Validated source string.
    source: FreeText<'a>,
}

impl<'a> LegacyUppercaseName<'a> {
    /// Build from a slot value whose constructor already validated
    /// the free-text invariant.
    const fn from_validated(source: FreeText<'a>) -> Self {
        Self { source }
    }

    /// Validate the source string before case normalization.
    ///
    /// # Errors
    /// [`FreeTextError`] if the source is empty or too long.
    fn parse(source: &'a str) -> Result<Self, FreeTextError> {
        Ok(Self {
            source: FreeText::parse(source)?,
        })
    }

    /// Title-case each whitespace- or hyphen-delimited segment using
    /// Unicode `to_uppercase` / `to_lowercase`.
    fn title_case_segments(&self) -> String {
        let s = self.source.value;
        let mut out = String::with_capacity(s.len());
        let mut at_segment_start = true;
        for c in s.chars() {
            if c.is_whitespace() || c == '-' {
                out.push(c);
                at_segment_start = true;
            } else if at_segment_start {
                for upper in c.to_uppercase() {
                    out.push(upper);
                }
                at_segment_start = false;
            } else {
                for lower in c.to_lowercase() {
                    out.push(lower);
                }
            }
        }
        out
    }
}

/// Personal name in its "native" form -- the case-normalized
/// rendering of a name slot that the operator should see in
/// reports.
///
/// FINEID DVV-issued cards publish cert subject DN attributes
/// (`Surname`, `GivenName`, `CommonName`) in uppercase across
/// the entire string, mirroring MRZ conventions. The MRZ itself
/// is uppercase A-Z + `<` by ICAO 9303-3 §6. DG11 `0x5F0E`
/// `Dg11FullName` is the spec slot that would carry the native
/// UTF-8 form with proper case and diacritics, but DVV doesn't
/// currently provision DG11 on citizen ID cards.
///
/// `NativeName` is the typed result of running a simple
/// case-normalization heuristic over an uppercase source:
///
/// 1. Split into segments on whitespace (`' '`, `'\t'`, ...) or
///    hyphen (`'-'`). Hyphenated names like "MARIA-LIISA"
///    decompose into two segments so each side title-cases
///    independently.
/// 2. For each segment, the first character maps to its
///    Unicode-uppercase form and every subsequent character to
///    its Unicode-lowercase form. The mapping is locale-
///    independent (Rust's `char::to_uppercase` /
///    `char::to_lowercase`).
/// 3. Separators (whitespace runs, hyphens) are preserved
///    verbatim.
///
/// Result on the Finnish Police's published SPECIMEN identity:
/// `"VILMA"` -> `"Vilma"`, `"SOFIA"` -> `"Sofia"`,
/// `"SPECIMEN-TRAVEL"` -> `"Specimen-Travel"` (hyphen segment
/// boundary). Diacritic-bearing input round-trips through
/// Unicode case mapping: e.g. `"SÄÄTILA"` -> `"Säätila"`.
///
/// Known limitations of the v1 heuristic (acceptable per the
/// "simple rule for a start" framing):
///
/// - No special handling for Irish prefixes (`"MCCABE"` ->
///   `"Mccabe"` rather than `"McCabe"`).
/// - No special handling for Dutch/Spanish lowercase particles
///   ("VAN DER BERG" -> "Van Der Berg" rather than "van der
///   Berg").
/// - No special handling for apostrophes ("O'BRIEN" ->
///   "O'brien" rather than "O'Brien"; apostrophe is not
///   currently a segment boundary).
///
/// When DG11's already-native form becomes available on a card,
/// callers should use that source directly and skip the
/// normalization step entirely. `NativeName` is primarily for
/// the uppercase-source path that today's FINEID cards force.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NativeName(String);

impl NativeName {
    /// Normalize an uppercase / mixed-case name slot to its
    /// native title-case form. Sole constructor; only entry
    /// point that can build a `NativeName`.
    ///
    /// `s` is taken from a typed name newtype's storage (e.g.
    /// [`Surname::as_str`]) where the free-text validation
    /// non-empty + bounded-length invariants already hold. The
    /// constructor preserves the structural validation by
    /// running `FreeText::parse` again.
    ///
    /// # Errors
    /// [`FreeTextError::Empty`] if `s` is empty,
    /// [`FreeTextError::TooLong`] if `s` exceeds
    /// [`FREE_TEXT_MAX_BYTES`].
    pub(crate) fn from_legacy_uppercase(s: &str) -> Result<Self, FreeTextError> {
        let source = LegacyUppercaseName::parse(s)?;
        Ok(Self(source.title_case_segments()))
    }

    /// Borrow the title-cased native name string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for NativeName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for NativeName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NativeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Surname {
    /// # Errors
    /// [`FreeTextError::Empty`] if `s` is empty,
    /// [`FreeTextError::TooLong`] if `s` exceeds
    /// [`FREE_TEXT_MAX_BYTES`].
    pub fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying surname string (UTF-8 with
    /// ISO 8859-1 codepoints as DVV emits).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Render this `Surname` as its case-normalized
    /// [`NativeName`].
    ///
    /// Equivalent to `NativeName::from_legacy_uppercase(self.as_str())`
    /// but infallible: `Surname`'s constructor has already
    /// validated the inner string against
    /// `FreeText::parse`, so the conversion can't fail
    /// at this point.
    #[must_use]
    pub fn to_native(&self) -> NativeName {
        NativeName(
            LegacyUppercaseName::from_validated(FreeText { value: &self.0 }).title_case_segments(),
        )
    }

    /// MRZ transliteration source for this surname.
    #[must_use]
    pub(crate) fn to_mrz_text(&self) -> NativeMrzText {
        NativeMrzText(self.0.clone())
    }
}

impl Deref for Surname {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Surname {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Surname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<str> for Surname {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Surname {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// X.509 certificate serial number.
///
/// The INTEGER value of the cert's `serialNumber` field (RFC
/// 5280 §4.1.2.2). Distinct from [`TokenSerial`] (the chip-
/// side PKCS#15 serial) and from [`Peuin`] (the subject DN
/// `serialNumber` attribute holding the person identifier).
/// Strong typing keeps these three independently-named even
/// though all are "serial" by name.
///
/// Stored as the raw INTEGER content bytes (sign+magnitude
/// per X.690 §8.3); Display renders as lowercase hex matching
/// the conventional `openssl x509 -noout -serial` form.
/// `CA/Browser Forum Baseline Requirements` mandate >= 64
/// bits of entropy in the value but refineid does not enforce
/// that at this layer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertSerial(Vec<u8>);

impl CertSerial {
    /// Wrap a borrowed byte slice. No structural check; the
    /// type tags an already-extracted INTEGER content as
    /// semantically the cert's serial.
    #[must_use]
    pub(crate) fn from_bytes<I>(bytes: I) -> Self
    where
        I: IntoIterator<Item = u8>,
    {
        Self(bytes.into_iter().collect())
    }

    /// Borrow the raw INTEGER content bytes (sign-magnitude per
    /// X.690 §8.3).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for CertSerial {
    /// Lowercase hex of the raw INTEGER bytes, no separators
    /// (matches `openssl x509 -serial` output once the
    /// leading `serial=` is stripped).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Email address (RFC 5321 / RFC 822 form).
///
/// Used in `subjectAltName` `rfc822Name` `GeneralName`
/// entries and in FINEID service certificates (S2 §6.3.6.4.4).
/// Validated at construction: contains at least one `@`,
/// non-empty local and domain parts, no whitespace, total
/// length within RFC 5321 §4.5.3.1 limits (320 octets is the
/// practical upper bound; we accept 254 for the address as a
/// whole, the SMTP path-length cap that mail servers
/// commonly enforce).
///
/// The validator is intentionally permissive: it rejects
/// shape-broken inputs (`alice`, `@example.com`, `a@`,
/// `a@b@c`, ` a@b`) without parsing the local-part's quoting
/// rules from RFC 5322. Cert subjects in the wild use the
/// simple form; over-strict parsing would reject valid
/// addresses needlessly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EmailAddress(String);

/// Construction errors emitted by `EmailAddress::new`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailAddressError {
    /// Input was the empty string.
    Empty,
    /// Input exceeded the byte-length cap.
    TooLong {
        /// Actual byte length.
        got: usize,
        /// Cap (254 octets, the SMTP path-length cap most
        /// mail servers enforce).
        max: usize,
    },
    /// Input contained no `@` separator.
    NoAtSign,
    /// Input contained more than one `@`. Some quoted-local-
    /// part forms allow this per RFC 5322; refineid rejects
    /// the unquoted multi-`@` shape outright since cert
    /// subjects in the wild don't use quoted locals.
    MultipleAtSigns {
        /// Number of `@` characters counted in the input.
        count: usize,
    },
    /// Substring before `@` was empty (e.g. `@example.com`).
    EmptyLocalPart,
    /// Substring after `@` was empty (e.g. `alice@`).
    EmptyDomainPart,
    /// Input contained a whitespace character; ASCII space,
    /// tab, CR, or LF -- none are legal anywhere in the
    /// unquoted form.
    Whitespace {
        /// Byte offset (0-based) where the whitespace lives.
        at: usize,
    },
}

impl fmt::Display for EmailAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("email address cannot be empty"),
            Self::TooLong { got, max } => {
                write!(f, "email too long: {got} > {max} octets")
            }
            Self::NoAtSign => f.write_str("email missing '@' separator"),
            Self::MultipleAtSigns { count } => {
                write!(f, "email has {count} '@' characters, expected exactly 1")
            }
            Self::EmptyLocalPart => f.write_str("email local-part is empty"),
            Self::EmptyDomainPart => f.write_str("email domain part is empty"),
            Self::Whitespace { at } => {
                write!(f, "email contains whitespace at offset {at}")
            }
        }
    }
}

impl core::error::Error for EmailAddressError {}

impl EmailAddress {
    /// # Errors
    /// [`EmailAddressError`] variants for empty input, length
    /// over 254 octets, missing or duplicated `@`, empty
    /// local/domain part, or any whitespace.
    ///
    /// # Panics
    /// Never. The single `.expect()` on `str::split` relies on
    /// the documented invariant that `split` always yields at
    /// least one element (the first call to `.next()` is
    /// guaranteed `Some`); this is a proven invariant of the
    /// Rust stdlib, not an assumption about the input.
    pub(crate) fn new(s: &str) -> Result<Self, EmailAddressError> {
        const MAX_LEN: usize = 254;
        if s.is_empty() {
            return Err(EmailAddressError::Empty);
        }
        if s.len() > MAX_LEN {
            return Err(EmailAddressError::TooLong {
                got: s.len(),
                max: MAX_LEN,
            });
        }
        if let Some((i, _)) = s.char_indices().find(|(_, c)| c.is_whitespace()) {
            return Err(EmailAddressError::Whitespace { at: i });
        }
        // Single-pass split-at-@: counts and locates
        // simultaneously. str::split always yields at least
        // one element, so the .expect on the first .next is a
        // proven stdlib invariant (see # Panics above).
        let mut parts = s.split('@');
        #[expect(
            clippy::expect_used,
            reason = "str::split is documented to always yield at least one element on any input (incl. empty); the expect documents that proven stdlib invariant."
        )]
        let local = parts
            .next()
            .expect("str::split always yields at least one element");
        let Some(domain) = parts.next() else {
            return Err(EmailAddressError::NoAtSign);
        };
        // Any further parts means more than one '@'.
        if parts.next().is_some() {
            let count = s.bytes().filter(|&b| b == b'@').count();
            return Err(EmailAddressError::MultipleAtSigns { count });
        }
        if local.is_empty() {
            return Err(EmailAddressError::EmptyLocalPart);
        }
        if domain.is_empty() {
            return Err(EmailAddressError::EmptyDomainPart);
        }
        Ok(Self(s.to_owned()))
    }

    /// Borrow the underlying email-address string (UTF-8, no
    /// whitespace, exactly one `@`, both halves non-empty).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for EmailAddress {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for EmailAddress {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<str> for EmailAddress {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for EmailAddress {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// X.509 subject (or issuer) `commonName` attribute value
/// (OID 2.5.4.3).
///
/// In FINEID citizen certs the subject CN is composed of
/// `surname + givenName + serialNumber(PEUIN)` per S2 v5.2
/// §6.3.6.1 (example: `"Tormanen Paivi 12345678N"`). Issuer
/// CN is the issuing sub-CA's name (`"DVV Citizen
/// Certificates - G4R"` etc.). Strong typing distinguishes
/// the value from arbitrary strings without imposing the
/// composition rule on the type -- callers that need to
/// parse the composed form do so at the rendering boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommonName(String);

impl CommonName {
    /// # Errors
    /// [`FreeTextError::Empty`] if `s` is empty,
    /// [`FreeTextError::TooLong`] if `s` exceeds
    /// [`FREE_TEXT_MAX_BYTES`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying common-name string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for CommonName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for CommonName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CommonName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<str> for CommonName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for CommonName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

// =========================================================
// Per-slot given-name newtypes.
//
// FINEID's cert id-at-givenName (2.5.4.42) and ICAO 9303-10
// DG11 0x5F0E both carry **all** given names joined as one
// string. Downstream consumers want them split per slot --
// first name for the "Hi, Yrjö!" greeting, second name and
// further names available distinctly so the compiler refuses
// silent role swaps.
//
// Splitting is whitespace-based at the parse boundary.
// Hyphenated or apostrophe-bearing single names (Marie-Claire,
// O'Brien) stay inside one slot.
// =========================================================

/// Result of splitting a cert `id-at-givenName` (or DG11 full-
/// name) attribute into the three per-slot newtypes.
///
/// Parse-at-boundary: the raw attribute value enters
/// `split_given_names` once at the source side (cert parser
/// or DG11 parser); from there on the typed parts flow through
/// the rest of the pipeline.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SplitGivenNames {
    /// First given name; `None` when the source attribute had
    /// no tokens or every token failed validation.
    pub first: Option<FirstName>,
    /// Second given name when the source attribute had at least
    /// two tokens.
    pub second: Option<SecondName>,
    /// Third and subsequent given names, one per token in source
    /// order.
    pub additional: Vec<AdditionalName>,
}

/// Validated source text containing one or more given-name tokens.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct GivenNamesText(String);

impl GivenNamesText {
    /// Validate a raw cert or DG11 given-name attribute before splitting.
    ///
    /// # Errors
    /// [`FreeTextError`] if the source is empty or too long.
    pub(crate) fn new(value: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&value)?;
        Ok(Self(value))
    }

    /// Split into the three per-slot given-name types.
    ///
    /// Whitespace-tokenises the input; empty tokens are skipped. Tokens
    /// that fail [`FreeTextError`] validation are dropped.
    #[must_use]
    pub(crate) fn split(&self) -> SplitGivenNames {
        let mut out = SplitGivenNames::default();
        let mut slot = 0_usize;
        for tok in self.0.split_whitespace() {
            if tok.is_empty() {
                continue;
            }
            let owned = tok.to_owned();
            match slot {
                0 => {
                    if let Ok(n) = FirstName::new(owned) {
                        out.first = Some(n);
                        slot = 1;
                    }
                }
                1 => {
                    if let Ok(n) = SecondName::new(owned) {
                        out.second = Some(n);
                        slot = 2;
                    }
                }
                _ => {
                    if let Ok(n) = AdditionalName::new(owned) {
                        out.additional.push(n);
                    }
                }
            }
        }
        out
    }
}

/// First given name -- the "Hi, X!" slot.
///
/// Conventionally the calling name (Finnish `kutsumanimi`).
/// Some Finnish citizens identify by their second given name
/// instead; refineid does not encode that preference here.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FirstName(String);

impl FirstName {
    /// # Errors
    /// [`FreeTextError::Empty`] if empty, [`FreeTextError::TooLong`]
    /// if it exceeds [`FREE_TEXT_MAX_BYTES`].
    pub fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying first-name string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Render as case-normalized [`NativeName`]. See
    /// [`Surname::to_native`] for the heuristic.
    #[must_use]
    pub fn to_native(&self) -> NativeName {
        NativeName(
            LegacyUppercaseName::from_validated(FreeText { value: &self.0 }).title_case_segments(),
        )
    }

    /// MRZ transliteration source for this given-name slot.
    #[must_use]
    pub(crate) fn to_mrz_text(&self) -> NativeMrzText {
        NativeMrzText(self.0.clone())
    }
}

impl Deref for FirstName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for FirstName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FirstName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Second given name.
///
/// Distinct type from [`FirstName`] so the compiler refuses
/// to greet someone with their second name where the first
/// was intended.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecondName(String);

impl SecondName {
    /// # Errors
    /// See [`FreeTextError`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying second-name string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Render as case-normalized [`NativeName`]. See
    /// [`Surname::to_native`] for the heuristic.
    #[must_use]
    pub fn to_native(&self) -> NativeName {
        NativeName(
            LegacyUppercaseName::from_validated(FreeText { value: &self.0 }).title_case_segments(),
        )
    }

    /// MRZ transliteration source for this given-name slot.
    #[must_use]
    pub(crate) fn to_mrz_text(&self) -> NativeMrzText {
        NativeMrzText(self.0.clone())
    }
}

impl Deref for SecondName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for SecondName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecondName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Third-or-further given name.
///
/// Bag of additional given names beyond first and second. A
/// person with names "Anna Maria Helena Sofia" yields
/// `FirstName("Anna")`, `SecondName("Maria")`, and a vector
/// `[AdditionalName("Helena"), AdditionalName("Sofia")]`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AdditionalName(String);

impl AdditionalName {
    /// # Errors
    /// See [`FreeTextError`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying additional-name string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Render as case-normalized [`NativeName`]. See
    /// [`Surname::to_native`] for the heuristic.
    #[must_use]
    pub fn to_native(&self) -> NativeName {
        NativeName(
            LegacyUppercaseName::from_validated(FreeText { value: &self.0 }).title_case_segments(),
        )
    }

    /// MRZ transliteration source for this given-name slot.
    #[must_use]
    pub(crate) fn to_mrz_text(&self) -> NativeMrzText {
        NativeMrzText(self.0.clone())
    }
}

impl Deref for AdditionalName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for AdditionalName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AdditionalName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// =========================================================
// DG11 free-text newtypes.
//
// Each ICAO 9303-10 DG11 free-text field gets its own type so
// no consumer can silently swap a title for a profession or
// an address for a personal summary. All are UTF-8 verbatim;
// diacritics preserved.
// =========================================================

/// Personal honorific (DG11 tag `0x5F14`).
///
/// "Mr", "Mrs", "Prof.", "Dr", "Tri.". ICAO leaves this field
/// as free-text with no enumerated vocabulary; Finnish DVV
/// citizen cards seldom populate it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Title(String);

impl Title {
    /// # Errors
    /// See [`FreeTextError`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying title string verbatim.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for Title {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Title {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Title {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Profession / occupation (DG11 tag `0x5F13`).
///
/// "Lääkäri", "Software Engineer". Distinct from [`Title`] --
/// honorific vs job. Free-text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Profession(String);

impl Profession {
    /// # Errors
    /// See [`FreeTextError`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying profession string verbatim.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for Profession {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Profession {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Profession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Personal summary (DG11 tag `0x5F15`).
///
/// Free-form notes about the holder. Rarely populated.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PersonalSummary(String);

impl PersonalSummary {
    /// # Errors
    /// See [`FreeTextError`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying personal-summary string verbatim.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for PersonalSummary {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for PersonalSummary {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PersonalSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Place of birth (DG11 tag `0x5F11`).
///
/// Sub-fields are separated by `<` per ICAO 9303-10; the
/// newtype carries the whole on-card value verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PlaceOfBirth(String);

impl PlaceOfBirth {
    /// # Errors
    /// See [`FreeTextError`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying place-of-birth string (sub-fields
    /// separated by `<` per ICAO 9303-10).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for PlaceOfBirth {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for PlaceOfBirth {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PlaceOfBirth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Permanent address (DG11 tag `0x5F42`).
///
/// Sub-fields are separated by `<` per ICAO 9303-10.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PermanentAddress(String);

impl PermanentAddress {
    /// # Errors
    /// See [`FreeTextError`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying permanent-address string (sub-fields
    /// separated by `<` per ICAO 9303-10).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for PermanentAddress {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for PermanentAddress {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PermanentAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Telephone number (DG11 tag `0x5F12`).
///
/// Free-text on the card -- no E.164 normalisation enforced.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Telephone(String);

impl Telephone {
    /// # Errors
    /// See [`FreeTextError`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying telephone-number string verbatim
    /// (no E.164 normalisation enforced).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for Telephone {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Telephone {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Telephone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Custody information (DG11 tag `0x5F18`).
///
/// Per ICAO 9303-10 Table 71 the slot is reserved for custody
/// information. Earlier refineid releases mislabelled this as
/// "tax / exit requirements"; that label belongs to DG12
/// `0x5F1C` ([`TaxExit`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CustodyInformation(String);

impl CustodyInformation {
    /// # Errors
    /// See [`FreeTextError`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying custody-information string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for CustodyInformation {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for CustodyInformation {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CustodyInformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One travel-document number from DG11 tag `0x5F17`.
///
/// Cards may carry several; the on-card field separates them
/// with `<`. The TLV walker splits and emits `Vec<OtherTdNumber>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OtherTdNumber(String);

impl OtherTdNumber {
    /// # Errors
    /// See [`FreeTextError`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying alternative TD-number string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for OtherTdNumber {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for OtherTdNumber {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OtherTdNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One alternative / former name from DG11 tag `0x5F0F`.
///
/// Nested under the `0xA0` content-specific wrapper with an
/// `0x02` instance-count byte; per ICAO 9303-10 the field may
/// repeat. The TLV walker emits `Vec<OtherName>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OtherName(String);

impl OtherName {
    /// # Errors
    /// See [`FreeTextError`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying alternative-name string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for OtherName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for OtherName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OtherName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Holder's full name in the native form (DG11 tag `0x5F0E`).
///
/// On-card encoding is variable -- ICAO 9303-10 §4.7.11.4 leaves
/// the field as a single free-text string. Implementations
/// typically write `Surname<<Given1<Given2<...` (MRZ-style with
/// filler `<` separators) but with diacritics preserved (UTF-8).
/// We hold the bytes verbatim; [`try_split_into_parts`] attempts
/// the best-effort decomposition into typed [`Surname`] +
/// [`SplitGivenNames`].
///
/// [`try_split_into_parts`]: Dg11FullName::try_split_into_parts
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dg11FullName(String);

impl Dg11FullName {
    /// # Errors
    /// See [`FreeTextError`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying full-name string verbatim (MRZ-style
    /// `<<` separator between surname and given names not yet
    /// expanded; use [`try_split_into_parts`](Self::try_split_into_parts)
    /// to decompose).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Best-effort decomposition into `(surname, given_names)`.
    ///
    /// Strategy, in order:
    /// 1. Split on `<<` if present (MRZ-style separator).
    /// 2. Otherwise treat the last whitespace-separated token as
    ///    the surname and the rest as given names.
    ///
    /// Filler `<` characters in the given-names half are
    /// rewritten to spaces before tokenisation. Returns `None`
    /// when the value doesn't yield a non-empty surname AND at
    /// least one given name.
    #[must_use]
    pub fn try_split_into_parts(&self) -> Option<(Surname, SplitGivenNames)> {
        let raw = self.0.as_str();
        let (surname_raw, given_raw): (String, String) = if let Some((s, g)) = raw.split_once("<<")
        {
            (
                s.replace('<', " ").trim().to_owned(),
                g.replace('<', " ").trim().to_owned(),
            )
        } else {
            // Fallback: last whitespace token = surname.
            let trimmed = raw.replace('<', " ");
            let mut tokens: Vec<String> = trimmed.split_whitespace().map(str::to_owned).collect();
            if tokens.len() < 2 {
                return None;
            }
            let surname = tokens.pop()?;
            (surname, tokens.join(" "))
        };
        let surname = Surname::new(surname_raw).ok()?;
        let given = GivenNamesText::new(given_raw).ok()?.split();
        // Require at least a first given name; otherwise the
        // parsed shape isn't useful for any caller. The discard
        // via `let _` keeps the `unused_must_use` lint happy
        // without re-binding the borrowed name.
        let _: &FirstName = given.first.as_ref()?;
        Some((surname, given))
    }
}

impl Deref for Dg11FullName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Dg11FullName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Dg11FullName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Personal number from DG11 tag `0x5F10`.
///
/// Distinct from [`Peuin`] (the cert subject DN `serialNumber`
/// attribute): DG11's personal number is the issuing-state
/// identifier in its natural format -- in Finland this is the
/// HETU (DDMMYY+sign+NNN+check). PEUIN derives from HETU but
/// has a different shape. Different types, different domain
/// values.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PersonalNumber(String);

impl PersonalNumber {
    /// # Errors
    /// See [`FreeTextError`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying personal-number string (issuing-state
    /// native format; HETU for Finland).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for PersonalNumber {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for PersonalNumber {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PersonalNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// =========================================================
// DG12 free-text newtypes.
//
// Additional document data per ICAO 9303-10 §4.7.12 Table 73.
// =========================================================

/// Issuing authority (DG12 tag `0x5F19`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IssuingAuthority(String);

impl IssuingAuthority {
    /// # Errors
    /// See [`FreeTextError`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying issuing-authority string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for IssuingAuthority {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for IssuingAuthority {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IssuingAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Endorsements / observations (DG12 tag `0x5F1B`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endorsements(String);

impl Endorsements {
    /// # Errors
    /// See [`FreeTextError`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying endorsements-and-observations string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for Endorsements {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Endorsements {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Endorsements {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Tax / exit requirements (DG12 tag `0x5F1C`).
///
/// Distinct from [`CustodyInformation`] (DG11 `0x5F18`) --
/// different DG, different slot, different semantics.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TaxExit(String);

impl TaxExit {
    /// # Errors
    /// See [`FreeTextError`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying tax / exit-requirements string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for TaxExit {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for TaxExit {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TaxExit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Name of another person referenced on the document
/// (DG12 tag `0x5F1A`).
///
/// Nested under `0xA0` with an `0x02` instance-count byte;
/// may repeat per ICAO 9303-10. Emitted as `Vec<OtherPerson>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OtherPerson(String);

impl OtherPerson {
    /// # Errors
    /// See [`FreeTextError`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying other-person name string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for OtherPerson {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for OtherPerson {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OtherPerson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Serial number of the personalisation system that wrote the
/// document (DG12 tag `0x5F56`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PersonalisationDeviceSerial(String);

impl PersonalisationDeviceSerial {
    /// # Errors
    /// See [`FreeTextError`].
    pub(crate) fn new(s: String) -> Result<Self, FreeTextError> {
        FreeText::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying personalisation-device serial string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for PersonalisationDeviceSerial {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for PersonalisationDeviceSerial {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PersonalisationDeviceSerial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `TryFrom<String>` impls for the free-text typed wrappers
/// whose `new` constructor is `pub(crate)` (typing-discipline
/// rule D: no `pub fn` taking `String`). The trait impl `fn` is
/// not `pub fn` so it satisfies the rule, while still giving
/// cross-crate callers a typed way to construct these from
/// owned strings -- the natural shape for test fixtures and
/// external configuration parsers.
macro_rules! impl_try_from_string_via_new {
    ($t:ty) => {
        impl TryFrom<String> for $t {
            type Error = FreeTextError;
            fn try_from(s: String) -> Result<Self, Self::Error> {
                Self::new(s)
            }
        }
    };
}

impl_try_from_string_via_new!(PlaceOfBirth);
impl_try_from_string_via_new!(Profession);
impl_try_from_string_via_new!(Title);
impl_try_from_string_via_new!(OtherTdNumber);
impl_try_from_string_via_new!(IssuingAuthority);
impl_try_from_string_via_new!(OtherPerson);

// =========================================================
// MRZ (DG1) transliterated names.
//
// ICAO 9303-3 §6 restricts the MRZ character set to A-Z plus
// `<` (filler). Names with non-Latin or accented characters
// undergo a normative transliteration: ä->AE, ö->OE, å->AA,
// ß->SS, š->S, ž->Z, ç->C, etc. The native form lives in the
// cert subject DN and DG11 0x5F0E; MRZ form lives in DG1.
//
// Distinct types from the native [`Surname`] / [`FirstName`]
// so the compiler refuses to compare a native string against
// a transliterated string silently.
// =========================================================

/// Error returned by `MrzSurname::new` / `MrzGivenName::new`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MrzNameError {
    /// Input was zero bytes.
    Empty,
    /// Input exceeded the per-field byte budget.
    TooLong {
        /// Length of the rejected input in bytes. Tier 0 `usize`.
        got: usize,
        /// The cap that was breached (mirrors
        /// [`MRZ_NAME_MAX_BYTES`]). Tier 0 `usize`.
        max: usize,
    },
    /// Input contained a byte outside the ICAO 9303-3 §6
    /// character set (A-Z and `<` only).
    InvalidChar {
        /// Byte index at which the offending value was found.
        /// Tier 0 `usize` -- arithmetic offset.
        at: usize,
        /// The offending byte value. Tier 0 `u8` -- the spec
        /// allows only `0x3C` (`<`) or `0x41..=0x5A` (`A..=Z`);
        /// any other byte triggers this variant.
        byte: u8,
    },
}

impl fmt::Display for MrzNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("MRZ name cannot be empty"),
            Self::TooLong { got, max } => {
                write!(f, "MRZ name length {got} bytes exceeds maximum {max}")
            }
            Self::InvalidChar { at, byte } => {
                write!(
                    f,
                    "MRZ name byte {byte:#04x} at index {at} is not in [A-Z<]"
                )
            }
        }
    }
}

impl core::error::Error for MrzNameError {}

/// Maximum byte length for one MRZ name identifier.
///
/// Total name area on TD3 MRZ is 39 bytes (line 1 cols 6-44),
/// shared between primary and secondary identifiers via the
/// `<<` separator. The longest a single identifier can be
/// after the separator is therefore 37 bytes. 39 leaves room
/// for off-spec emitters.
pub const MRZ_NAME_MAX_BYTES: usize = 39;

/// MRZ identifier proof constructor validated against ICAO 9303.
struct MrzNameInput;

impl MrzNameInput {
    /// Validate an MRZ identifier against ICAO 9303-3 sec. 4.1.1.
    ///
    /// # Errors
    /// [`MrzNameError`] when the value is empty, too long, or outside
    /// the MRZ `A-Z` plus filler alphabet.
    fn parse(value: &str) -> Result<Self, MrzNameError> {
        if value.is_empty() {
            return Err(MrzNameError::Empty);
        }
        if value.len() > MRZ_NAME_MAX_BYTES {
            return Err(MrzNameError::TooLong {
                got: value.len(),
                max: MRZ_NAME_MAX_BYTES,
            });
        }
        for (i, b) in value.bytes().enumerate() {
            if !(b.is_ascii_uppercase() || b == b'<') {
                return Err(MrzNameError::InvalidChar { at: i, byte: b });
            }
        }
        Ok(Self)
    }
}

/// MRZ primary identifier (surname), transliterated.
///
/// DG1 line 1 columns 6 to the first `<<` separator.
/// Character set: A-Z + `<` only.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MrzSurname(String);

impl MrzSurname {
    /// # Errors
    /// See [`MrzNameError`].
    pub(crate) fn new(s: String) -> Result<Self, MrzNameError> {
        MrzNameInput::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying MRZ surname string (ASCII A-Z + `<`
    /// only). Use [`spaced`](Self::spaced) for an operator-
    /// friendly form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Presentation form: inner `<` filler bytes replaced with
    /// spaces, trailing fillers trimmed. Useful when rendering
    /// the MRZ name to an operator where the spec's `<` syntax
    /// just looks like noise. The on-card form is still
    /// available via [`Self::as_str`].
    #[must_use]
    pub fn spaced(&self) -> String {
        self.0.trim_end_matches('<').replace('<', " ")
    }

    /// Render as case-normalized [`NativeName`].
    ///
    /// Applies [`Self::spaced`] to remove the MRZ `<` fillers,
    /// then runs the title-case heuristic on the resulting
    /// space- and hyphen-separated segments. The result is the
    /// best operator-friendly approximation available when the
    /// chip doesn't provision DG11 -- it does *not* recover
    /// ICAO 9303-3 §6 transliterations (`AE` stays `Ae`, not
    /// `Ä`; `OE` stays `Oe`, not `Ö`). Use DG11 instead when
    /// the chip publishes it.
    ///
    /// # Errors
    /// [`FreeTextError::Empty`] if the spaced form is empty
    /// (a pure-filler MRZ field).
    pub fn to_native(&self) -> Result<NativeName, FreeTextError> {
        NativeName::from_legacy_uppercase(&self.spaced())
    }
}

impl Deref for MrzSurname {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for MrzSurname {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MrzSurname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<str> for MrzSurname {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for MrzSurname {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// MRZ secondary identifier (given names), transliterated.
///
/// DG1 line 1 columns after the first `<<` separator.
/// Character set: A-Z + `<` only. Multiple given names join
/// with single `<`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MrzGivenName(String);

impl MrzGivenName {
    /// # Errors
    /// See [`MrzNameError`].
    pub(crate) fn new(s: String) -> Result<Self, MrzNameError> {
        MrzNameInput::parse(&s)?;
        Ok(Self(s))
    }

    /// Borrow the underlying MRZ given-name string (ASCII A-Z +
    /// `<` only). Use [`spaced`](Self::spaced) for an operator-
    /// friendly form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Presentation form: inner `<` filler bytes replaced with
    /// spaces, trailing fillers trimmed. See [`MrzSurname::spaced`].
    #[must_use]
    pub fn spaced(&self) -> String {
        self.0.trim_end_matches('<').replace('<', " ")
    }

    /// Render as case-normalized [`NativeName`]. See
    /// [`MrzSurname::to_native`] for the transliteration
    /// caveat.
    ///
    /// # Errors
    /// [`FreeTextError::Empty`] if the spaced form is empty.
    pub fn to_native(&self) -> Result<NativeName, FreeTextError> {
        NativeName::from_legacy_uppercase(&self.spaced())
    }
}

impl Deref for MrzGivenName {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for MrzGivenName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MrzGivenName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<str> for MrzGivenName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for MrzGivenName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// ICAO 9303-3 §6 transliteration: render one native-form
/// character as the zero-to-three ASCII bytes the MRZ uses for
/// it.
///
/// Coverage targets the characters that appear in Finnish-state
/// names (Ä, Ö, Å, Š, Ž, Ü, ß, plus the German/Slavic / Romance
/// diacritics commonly seen in resident names). The table is
/// not exhaustive -- ICAO Doc 9303 part 3 §6 is the normative
/// reference and includes more than 60 mappings.
///
/// Returns `None` for characters that map to themselves
/// (already A-Z or `<`) so the caller can short-circuit.
///
/// The match arms are intentionally grouped by source
/// (Latin-1, Latin Extended A, Slavic acutes, ...) so the
/// table reads against the ICAO 9303-3 §6 layout. Several
/// groups have identical right-hand sides; clippy's
/// `match_same_arms` lint would have us flatten them into one
/// arm each and lose that grouping.
#[expect(
    clippy::match_same_arms,
    reason = "ICAO 9303-3 §6 transliteration table: arms intentionally grouped by source script (Latin-1, Latin Extended A, Slavic acutes, ...); flattening identical RHS would lose the spec layout."
)]
const fn transliterate_char(c: char) -> Option<&'static str> {
    Some(match c {
        // Direct double-letter expansions (Latin-1 / Latin-Ext).
        'Ä' | 'ä' => "AE",
        'Ö' | 'ö' => "OE",
        'Ü' | 'ü' => "UE",
        'ß' => "SS",
        // Single-letter folds.
        'Å' | 'å' => "AA",
        'Æ' | 'æ' => "AE",
        'Ø' | 'ø' => "OE",
        'Œ' | 'œ' => "OE",
        'Ç' | 'ç' => "C",
        'Š' | 'š' | 'Ś' | 'ś' | 'Ş' | 'ş' => "S",
        'Ž' | 'ž' | 'Ź' | 'ź' | 'Ż' | 'ż' => "Z",
        'Ñ' | 'ñ' => "N",
        'Ł' | 'ł' => "L",
        'Ð' | 'ð' => "D",
        'Þ' | 'þ' => "TH",
        // Acutes / graves / circumflexes / tildes -- base letter.
        'À' | 'Á' | 'Â' | 'Ã' | 'à' | 'á' | 'â' | 'ã' => "A",
        'È' | 'É' | 'Ê' | 'Ë' | 'è' | 'é' | 'ê' | 'ë' => "E",
        'Ì' | 'Í' | 'Î' | 'Ï' | 'ì' | 'í' | 'î' | 'ï' => "I",
        'Ò' | 'Ó' | 'Ô' | 'Õ' | 'ò' | 'ó' | 'ô' | 'õ' => "O",
        'Ù' | 'Ú' | 'Û' | 'ù' | 'ú' | 'û' => "U",
        'Ý' | 'ý' | 'ÿ' => "Y",
        'Č' | 'č' | 'Ć' | 'ć' => "C",
        'Ě' | 'ě' => "E",
        'Ř' | 'ř' => "R",
        'Ť' | 'ť' => "T",
        'Ň' | 'ň' => "N",
        'Ď' | 'ď' => "D",
        'Ľ' | 'ľ' => "L",
        // Lowercase ASCII -> uppercase ASCII via the typed lookup.
        // Match arm 'a'..='z' bounds c to ASCII lowercase; the
        // table lookup uses `match` arms exhaustively so no
        // indexing / cast / arithmetic happens at this site.
        'a' => "A",
        'b' => "B",
        'c' => "C",
        'd' => "D",
        'e' => "E",
        'f' => "F",
        'g' => "G",
        'h' => "H",
        'i' => "I",
        'j' => "J",
        'k' => "K",
        'l' => "L",
        'm' => "M",
        'n' => "N",
        'o' => "O",
        'p' => "P",
        'q' => "Q",
        'r' => "R",
        's' => "S",
        't' => "T",
        'u' => "U",
        'v' => "V",
        'w' => "W",
        'x' => "X",
        'y' => "Y",
        'z' => "Z",
        _ => return None,
    })
}

/// Validated native-form text ready for ICAO 9303 MRZ transliteration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct NativeMrzText(String);

impl NativeMrzText {
    /// Render into MRZ-shape (A-Z + `<`) per ICAO 9303-3 sec. 6.
    ///
    /// Whitespace and hyphens become filler `<`. Apostrophes are
    /// dropped (`O'Brien` -> `OBRIEN`). Characters not covered by
    /// [`transliterate_char`] are emitted as `<`.
    #[must_use]
    pub(crate) fn to_mrz(&self) -> String {
        let mut out = String::with_capacity(self.0.len());
        for c in self.0.chars() {
            match c {
                'A'..='Z' => out.push(c),
                ' ' | '-' => out.push('<'),
                '\'' => {}
                other => {
                    if let Some(expansion) = transliterate_char(other) {
                        out.push_str(expansion);
                    } else {
                        out.push('<');
                    }
                }
            }
        }
        out
    }
}

/// Transliterate a native [`Surname`] into an [`MrzSurname`].
///
/// Always succeeds: [`transliterate_to_mrz`] guarantees the
/// output is composed of A-Z and `<` bytes only.
///
/// # Panics
/// Panics if the transliterated value exceeds
/// [`MRZ_NAME_MAX_BYTES`] -- only possible for pathologically
/// long input surnames (>39 bytes after transliteration) which
/// the upstream `FreeTextError` cap effectively prevents.
#[must_use]
pub(crate) fn transliterate_surname(surname: &Surname) -> MrzSurname {
    let raw = surname.to_mrz_text().to_mrz();
    #[expect(
        clippy::expect_used,
        reason = "transliterate_to_mrz emits only A-Z and `<`; MrzSurname::new accepts that alphabet, so the only failure shape (overlength) is documented in the function's # Panics."
    )]
    let out = MrzSurname::new(raw).expect("transliteration yields only A-Z and `<`");
    out
}

/// Transliterate the typed given-name slots into an
/// [`MrzGivenName`], joining multiple given names with `<`.
#[must_use]
pub(crate) fn transliterate_given_names(
    first: Option<&FirstName>,
    second: Option<&SecondName>,
    additional: &[AdditionalName],
) -> Option<MrzGivenName> {
    let mut parts: Vec<String> = Vec::new();
    if let Some(n) = first {
        parts.push(n.to_mrz_text().to_mrz());
    }
    if let Some(n) = second {
        parts.push(n.to_mrz_text().to_mrz());
    }
    for n in additional {
        parts.push(n.to_mrz_text().to_mrz());
    }
    let joined = parts.join("<");
    if joined.is_empty() {
        return None;
    }
    MrzGivenName::new(joined).ok()
}

/// Result of cross-correlating the identity-bearing data a
/// FINEID card may carry: cert subject DN (native), DG11
/// (native, both name and birth date), DG1 MRZ (transliterated,
/// both name and birth date).
///
/// Each flag is `Some(true)` when both sources are available
/// and the comparison passed, `Some(false)` when both were
/// available but mismatched, and `None` when at least one
/// source was absent so the comparison wasn't meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EmrtdConsistency {
    /// Cert subject `surname` matches DG11 0x5F0E parsed surname.
    pub cert_matches_dg11_surname: Option<bool>,
    /// Cert subject `givenName` (split into slots) matches DG11
    /// 0x5F0E parsed given names.
    pub cert_matches_dg11_given: Option<bool>,
    /// Cert subject `surname` transliterated matches DG1 MRZ
    /// primary identifier.
    pub cert_transliterates_to_mrz_surname: Option<bool>,
    /// Cert subject given names transliterated and joined match
    /// the DG1 MRZ secondary identifier.
    pub cert_transliterates_to_mrz_given: Option<bool>,
    /// DG1 MRZ date of birth (century-resolved via the 50/50
    /// rule) matches DG11 0x5F2B's typed date of birth.
    pub mrz_dob_matches_dg11_dob: Option<bool>,
}

/// Cross-correlate the identity-bearing data a FINEID card may
/// carry and emit an [`EmrtdConsistency`] report.
///
/// Comparison rules:
/// - **cert vs DG11**: byte-equal compare of the typed values
///   (native UTF-8 on both sides). DG11 0x5F0E is parsed via
///   [`Dg11FullName::try_split_into_parts`]; comparisons that
///   require a successful split are left `None` on failure.
/// - **cert -> MRZ**: cert side runs through ICAO 9303-3 §6
///   transliteration (`transliterate_to_mrz`); MRZ side has
///   trailing `<` fillers trimmed before compare.
/// - **MRZ vs DG11 birth date**: MRZ side runs through century
///   resolution (`MrzDate::resolve_as_date_of_birth`); both
///   ends are typed [`DateOfBirth`] values, compared directly.
///
/// Each flag is `None` when at least one of its sources is
/// absent. `Some(false)` is a real mismatch (operator should
/// investigate); `Some(true)` is a positive cross-check.
/// Borrowed inputs for [`verify_emrtd_consistency`]. Bundles
/// the three sources (cert subject, DG11, DG1 MRZ) into one
/// argument so the verifier function signature stays under
/// clippy's argument-count ceiling and each call site reads
/// naturally as a struct literal.
#[derive(Debug, Clone, Copy)]
pub struct EmrtdConsistencyInputs<'a> {
    /// Cert subject surname per RFC 5280 §4.1.2.6 / X.520 §6.2.4.
    /// `None` when the cert didn't carry one (rare for FINEID).
    pub cert_surname: Option<&'a Surname>,
    /// Cert subject first given name (first token of the
    /// `givenName` attribute split at whitespace).
    pub cert_first: Option<&'a FirstName>,
    /// Cert subject second given name (second token).
    pub cert_second: Option<&'a SecondName>,
    /// Cert subject third and subsequent given names (remaining
    /// tokens). Empty slice when no additional names exist.
    pub cert_additional: &'a [AdditionalName],
    /// DG11 0x5F0E full-name field (native form). `None` when
    /// DG11 wasn't provisioned or the read failed.
    pub dg11_full_name: Option<&'a Dg11FullName>,
    /// DG11 0x5F2B date-of-birth field (native form).
    pub dg11_dob: Option<&'a DateOfBirth>,
    /// DG1 MRZ primary identifier (transliterated surname).
    pub mrz_primary: Option<&'a MrzSurname>,
    /// DG1 MRZ secondary identifier (transliterated given names).
    pub mrz_secondary: Option<&'a MrzGivenName>,
    /// DG1 MRZ date-of-birth field (`YYMMDD`, century-resolved
    /// at compare time).
    pub mrz_dob: Option<&'a MrzDate>,
}

/// Cross-correlate the identity-bearing sources in `inputs` and
/// emit a populated [`EmrtdConsistency`] verdict. See
/// [`EmrtdConsistency`] for the per-flag semantics.
#[must_use]
pub fn verify_emrtd_consistency(inputs: EmrtdConsistencyInputs<'_>) -> EmrtdConsistency {
    let EmrtdConsistencyInputs {
        cert_surname,
        cert_first,
        cert_second,
        cert_additional,
        dg11_full_name,
        dg11_dob,
        mrz_primary,
        mrz_secondary,
        mrz_dob,
    } = inputs;
    let mut report = EmrtdConsistency::default();
    let dg11_parts = dg11_full_name.and_then(Dg11FullName::try_split_into_parts);

    // Cert subject surname vs DG11 parsed surname.
    if let (Some(c), Some((d, _))) = (cert_surname, dg11_parts.as_ref()) {
        report.cert_matches_dg11_surname = Some(c == d);
    }

    // Cert subject given-name slots vs DG11 parsed given names.
    if let Some((_, dg)) = dg11_parts.as_ref()
        && (cert_first.is_some() || dg.first.is_some())
    {
        let first_match = cert_first.map(FirstName::as_str) == dg.first.as_deref();
        let second_match = cert_second.map(SecondName::as_str) == dg.second.as_deref();
        let additional_match = cert_additional.len() == dg.additional.len()
            && cert_additional
                .iter()
                .zip(dg.additional.iter())
                .all(|(a, b)| a.as_str() == b.as_str());
        report.cert_matches_dg11_given = Some(first_match && second_match && additional_match);
    }

    // Cert surname transliterates to MRZ primary identifier.
    if let (Some(c), Some(m)) = (cert_surname, mrz_primary) {
        let expected = transliterate_surname(c);
        let actual = m.as_str().trim_end_matches('<');
        report.cert_transliterates_to_mrz_surname = Some(expected.as_str() == actual);
    }

    // Cert given names transliterate to MRZ secondary identifier.
    if let Some(m) = mrz_secondary
        && let Some(expected) = transliterate_given_names(cert_first, cert_second, cert_additional)
    {
        let actual = m.as_str().trim_end_matches('<');
        report.cert_transliterates_to_mrz_given = Some(expected.as_str() == actual);
    }

    // MRZ date of birth vs DG11 date of birth -- both wrap the
    // canonical Iso8601 internally, so equality compares the
    // resolved calendar dates directly through the `date()`
    // semantic projection.
    if let (Some(mrz), Some(dg)) = (mrz_dob, dg11_dob) {
        report.mrz_dob_matches_dg11_dob = Some(mrz.date() == dg.date());
    }

    report
}

/// MRZ sex code per ICAO 9303-3 §4.5.
///
/// Valid byte values: `M` (male), `F` (female), `<`
/// (unspecified). Any other byte parses as `Unspecified`
/// (defensive -- the slot is one byte and unknown values
/// shouldn't crash the reader).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MrzSex {
    /// MRZ byte `M` per ICAO 9303-3 §4.5.
    Male,
    /// MRZ byte `F` per ICAO 9303-3 §4.5.
    Female,
    /// MRZ byte `<` (or anything else) per ICAO 9303-3 §4.5;
    /// unknown values fold into this variant defensively.
    Unspecified,
}

impl MrzSex {
    /// Parse the single MRZ byte at TD1 line 2 column 8 (or
    /// TD3 line 2 column 21) into the typed enum.
    #[must_use]
    pub const fn from_mrz_byte(b: u8) -> Self {
        match b {
            b'M' => Self::Male,
            b'F' => Self::Female,
            _ => Self::Unspecified,
        }
    }

    /// Inverse of [`from_mrz_byte`] -- the single byte the
    /// value occupies in the MRZ.
    ///
    /// [`from_mrz_byte`]: MrzSex::from_mrz_byte
    #[must_use]
    pub const fn as_mrz_byte(self) -> u8 {
        match self {
            Self::Male => b'M',
            Self::Female => b'F',
            Self::Unspecified => b'<',
        }
    }

    /// Fluent-friendly token (`"male"` / `"female"` /
    /// `"unspecified"`) for i18n message variant selection.
    /// Picked at the message-routing boundary, not embedded in
    /// rendered strings.
    #[must_use]
    pub const fn fluent_token(self) -> &'static str {
        match self {
            Self::Male => "male",
            Self::Female => "female",
            Self::Unspecified => "unspecified",
        }
    }
}

impl fmt::Display for MrzSex {
    /// Engineering-canonical token (`"male"` / `"female"` /
    /// `"unspecified"`). Locale-specific rendering belongs in
    /// the l10n layer (see `doc/i18n-l10n.md`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.fluent_token())
    }
}

// =========================================================
// Role-specific date wrappers.
//
// Each is a thin newtype around `iso8601::Iso8601` -- refineid's
// canonical time storage. The semantic role (who the date is
// for) lives at the wrapper type; the underlying calendar /
// datetime representation lives on `iso8601`. Per
// `doc/typing-discipline.md` the wrappers expose only semantic
// projections (`date()` returns `&iso8601::Date`), never an
// `inner()` / `as_iso8601()` umbrella escape hatch.
//
// The variant invariant (e.g. "DateOfBirth holds an
// `Iso8601::Date`, never `Iso8601::DateTime`") is enforced at
// every constructor and trusted by every projection -- this is
// the one runtime invariant the design consciously accepts in
// exchange for the conceptual unity of a single internal time.
// =========================================================

/// Date of birth.
///
/// Sources: cert subject DN (future), DG11 tag `0x5F2B`, MRZ
/// DG1 after century resolution. Internally always
/// `Iso8601::Date`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DateOfBirth {
    /// Invariant: always [`Iso8601::Date`] (never `DateTime`).
    /// The constructor narrows the enum; the [`Self::date`]
    /// projection trusts this narrowing.
    ///
    /// [`Iso8601::Date`]: crate::iso8601::Iso8601::Date
    value: crate::iso8601::Iso8601,
}

impl DateOfBirth {
    /// Construct from validated calendar components.
    ///
    /// # Errors
    /// [`crate::iso8601::Iso8601Error`] for year / month / day
    /// out of range.
    pub fn from_calendar(
        year: u16,
        month: u8,
        day: u8,
    ) -> Result<Self, crate::iso8601::Iso8601Error> {
        let date = crate::iso8601::Date::new(year, month, day)?;
        Ok(Self {
            value: crate::iso8601::Iso8601::Date(date),
        })
    }

    /// Parse the ICAO 9303-10 `YYYYMMDD` wire form (DG11 tag
    /// `0x5F2B`).
    ///
    /// # Errors
    /// See [`crate::iso8601::Date::from_yyyymmdd`].
    pub fn from_yyyymmdd(bytes: [u8; 8]) -> Result<Self, crate::iso8601::Iso8601Error> {
        let date = crate::iso8601::Date::from_yyyymmdd(bytes)?;
        Ok(Self {
            value: crate::iso8601::Iso8601::Date(date),
        })
    }

    /// Semantic projection: the calendar-date payload. Used for
    /// representation-level operations (cross-source equality
    /// against another role's date, ordering, ...).
    ///
    /// Infallible by invariant -- the constructor only admits
    /// `Iso8601::Date`. The [`unreachable!`] arm exists for
    /// completeness (every match must cover both variants); it
    /// is the single runtime invariant the role wrapper
    /// consciously accepts.
    #[must_use]
    pub fn date(&self) -> &crate::iso8601::Date {
        match &self.value {
            crate::iso8601::Iso8601::Date(d) => d,
            crate::iso8601::Iso8601::DateTime(_) => {
                unreachable!("DateOfBirth invariant: inner is always Iso8601::Date")
            }
        }
    }
}

impl fmt::Display for DateOfBirth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt(f)
    }
}

/// Document issue date (DG12 tag `0x5F26`, ICAO 9303-10).
///
/// Internally always [`Iso8601::Date`]. Distinct newtype from
/// [`DateOfBirth`] -- the compiler refuses to assign one to the
/// other -- but the inner calendar-date representation is
/// identical, so cross-role equality via the [`date`]
/// projection is meaningful.
///
/// [`Iso8601::Date`]: crate::iso8601::Iso8601::Date
/// [`date`]: IssueDate::date
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IssueDate {
    /// Invariant: always [`Iso8601::Date`] -- DG12 tag `0x5F26`
    /// is calendar-date-only, no time component.
    ///
    /// [`Iso8601::Date`]: crate::iso8601::Iso8601::Date
    value: crate::iso8601::Iso8601,
}

impl IssueDate {
    /// Construct from validated calendar components.
    ///
    /// # Errors
    /// See `iso8601::Date::new`.
    pub fn from_calendar(
        year: u16,
        month: u8,
        day: u8,
    ) -> Result<Self, crate::iso8601::Iso8601Error> {
        let date = crate::iso8601::Date::new(year, month, day)?;
        Ok(Self {
            value: crate::iso8601::Iso8601::Date(date),
        })
    }

    /// Parse the ICAO 9303-10 `YYYYMMDD` wire form.
    ///
    /// # Errors
    /// See [`crate::iso8601::Date::from_yyyymmdd`].
    pub fn from_yyyymmdd(bytes: [u8; 8]) -> Result<Self, crate::iso8601::Iso8601Error> {
        let date = crate::iso8601::Date::from_yyyymmdd(bytes)?;
        Ok(Self {
            value: crate::iso8601::Iso8601::Date(date),
        })
    }

    /// Semantic projection: the calendar-date payload.
    /// Infallible by invariant.
    #[must_use]
    pub fn date(&self) -> &crate::iso8601::Date {
        match &self.value {
            crate::iso8601::Iso8601::Date(d) => d,
            crate::iso8601::Iso8601::DateTime(_) => {
                unreachable!("IssueDate invariant: inner is always Iso8601::Date")
            }
        }
    }
}

impl fmt::Display for IssueDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt(f)
    }
}

/// MRZ date (ICAO 9303-3 §4.5).
///
/// Semantic role: "a date that arrived through the MRZ wire
/// form" -- either DG1 birth date or DG1 expiry date. Internally
/// always [`Iso8601::Date`] (the 6-digit `YYMMDD` form is
/// resolved into a full calendar date at construction via the
/// 50/50 century rule, then stored canonically).
///
/// The MRZ wire-form emitter ([`to_mrz_yymmdd`]) round-trips
/// back to the on-card 6-digit form when needed.
///
/// [`Iso8601::Date`]: crate::iso8601::Iso8601::Date
/// [`to_mrz_yymmdd`]: MrzDate::to_mrz_yymmdd
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MrzDate {
    /// Invariant: always [`Iso8601::Date`]. The MRZ wire form
    /// is `YYMMDD`; century resolution happens at construction,
    /// then the full calendar date is stored.
    ///
    /// [`Iso8601::Date`]: crate::iso8601::Iso8601::Date
    value: crate::iso8601::Iso8601,
}

impl MrzDate {
    /// Parse the 6-digit MRZ wire form (`YYMMDD`).
    ///
    /// # Errors
    /// See [`crate::iso8601::Date::from_mrz_yymmdd`].
    pub fn from_mrz_yymmdd(bytes: [u8; 6]) -> Result<Self, crate::iso8601::Iso8601Error> {
        let date = crate::iso8601::Date::from_mrz_yymmdd(bytes)?;
        Ok(Self {
            value: crate::iso8601::Iso8601::Date(date),
        })
    }

    /// Construct directly from validated calendar components --
    /// for synthetic data / tests where no wire string exists.
    ///
    /// # Errors
    /// See `iso8601::Date::new`.
    pub fn from_calendar(
        year: u16,
        month: u8,
        day: u8,
    ) -> Result<Self, crate::iso8601::Iso8601Error> {
        let date = crate::iso8601::Date::new(year, month, day)?;
        Ok(Self {
            value: crate::iso8601::Iso8601::Date(date),
        })
    }

    /// Semantic projection: the calendar-date payload.
    /// Infallible by invariant.
    #[must_use]
    pub fn date(&self) -> &crate::iso8601::Date {
        match &self.value {
            crate::iso8601::Iso8601::Date(d) => d,
            crate::iso8601::Iso8601::DateTime(_) => {
                unreachable!("MrzDate invariant: inner is always Iso8601::Date")
            }
        }
    }

    /// Emit the on-card MRZ 6-digit form (`YYMMDD`, century
    /// stripped). [`Display`] emits the canonical ISO 8601 form
    /// (`YYYY-MM-DD`) instead.
    ///
    /// [`Display`]: fmt::Display
    #[must_use]
    pub fn to_mrz_yymmdd(&self) -> String {
        self.date().to_mrz_yymmdd()
    }
}

impl fmt::Display for MrzDate {
    /// Canonical ISO 8601 form (`YYYY-MM-DD`). For the on-card
    /// 6-digit wire form use [`MrzDate::to_mrz_yymmdd`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt(f)
    }
}

/// Document personalisation timestamp (DG12 tag `0x5F55`).
///
/// Wire form is ICAO 9303-10's 14-digit `YYYYMMDDhhmmss` ASCII
/// (or sometimes BCD-encoded by off-spec issuers; refineid only
/// supports the ASCII form). Internally always
/// [`Iso8601::DateTime`] with [`TimeOffset::Unspecified`] -- the
/// wire form carries no zone designator.
///
/// [`Iso8601::DateTime`]: crate::iso8601::Iso8601::DateTime
/// [`TimeOffset::Unspecified`]: crate::iso8601::TimeOffset::Unspecified
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PersonalisationTime {
    /// Invariant: always [`Iso8601::DateTime`] with
    /// [`TimeOffset::Unspecified`]. DG12 tag `0x5F55` is a
    /// 14-digit zoneless ASCII timestamp; the projection
    /// `Self::date_time` trusts this narrowing.
    ///
    /// [`Iso8601::DateTime`]: crate::iso8601::Iso8601::DateTime
    /// [`TimeOffset::Unspecified`]: crate::iso8601::TimeOffset::Unspecified
    value: crate::iso8601::Iso8601,
}

impl PersonalisationTime {
    /// Parse the 14-digit `YYYYMMDDhhmmss` wire form.
    ///
    /// # Errors
    /// See [`crate::iso8601::DateTime::from_yyyymmddhhmmss`].
    pub fn from_yyyymmddhhmmss(bytes: [u8; 14]) -> Result<Self, crate::iso8601::Iso8601Error> {
        let dt = crate::iso8601::DateTime::from_yyyymmddhhmmss(bytes)?;
        Ok(Self {
            value: crate::iso8601::Iso8601::DateTime(dt),
        })
    }

    /// Semantic projection: the date+time payload. Infallible
    /// by the construction invariant -- `value` always holds
    /// [`Iso8601::DateTime`].
    ///
    /// [`Iso8601::DateTime`]: crate::iso8601::Iso8601::DateTime
    #[must_use]
    pub fn datetime(&self) -> &crate::iso8601::DateTime {
        match &self.value {
            crate::iso8601::Iso8601::DateTime(dt) => dt,
            crate::iso8601::Iso8601::Date(_) => {
                unreachable!("PersonalisationTime invariant: inner is always Iso8601::DateTime")
            }
        }
    }
}

impl fmt::Display for PersonalisationTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt(f)
    }
}

/// Cardholder + credential-instance identifier.
///
/// Every field is optional so the type degrades gracefully:
/// offline cert inspection (no card session) populates only the
/// DN-derived fields; PIN-status probes that don't read a cert
/// populate only the serial(s); future EUDI Wallet bindings
/// may populate `peuin` + `token_serial_*` only.
///
/// Constructed via [`new`] + the `with_*` builder methods, or
/// via struct literal (every field is public).
///
/// [`new`]: CredentialIdentity::new
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CredentialIdentity {
    /// Personal honorific. Source: DG11 tag `0x5F14`. Cert
    /// subject DN does not carry an honorific, so this field
    /// is always `None` on cert-only identity probes.
    pub title: Option<Title>,
    /// First given name -- the "Hi, X!" slot. Source: split
    /// from X.520 `givenName` (OID 2.5.4.42, whitespace
    /// tokens). Same source as [`second_name`] and
    /// [`additional_names`]; the cert attribute carries all
    /// given names joined.
    ///
    /// [`second_name`]: CredentialIdentity::second_name
    /// [`additional_names`]: CredentialIdentity::additional_names
    pub first_name: Option<FirstName>,
    /// Second given name (if any). Split from X.520
    /// `givenName`.
    pub second_name: Option<SecondName>,
    /// Third-and-further given names (if any). Split from
    /// X.520 `givenName`. Empty vector when the holder has at
    /// most two given names.
    pub additional_names: Vec<AdditionalName>,
    /// X.520 `surName` (OID 2.5.4.4). FINEID stores the family
    /// name as a single value here.
    pub surname: Option<Surname>,
    /// Personal Electronic Unique Identification Number per the
    /// Finnish administrative-terminology service. Held in the
    /// `serialNumber` DN attribute (OID 2.5.4.5) -- distinct
    /// from `Certificate.serialNumber`. Also known as `SATU` in
    /// Finnish-language FINEID material.
    pub peuin: Option<Peuin>,
    /// Date of birth. Future source: eMRTD DG1 MRZ when the
    /// eMRTD reader surface lands. Currently always `None`
    /// from cert-only identity probes (FINEID cert subject DN
    /// does not carry DOB).
    pub date_of_birth: Option<DateOfBirth>,
    /// Identifier as printed on the card's physical surface.
    /// The form a citizen quotes to DVV and cross-references
    /// against the plastic when responding to a PIN prompt.
    /// `None` when the chip-side full serial doesn't decode to
    /// a known printed-shape (older generations etc.).
    ///
    /// Note: `CredentialIdentity` no longer carries the full
    /// chip-side serial ([`TokenSerial`]). That value is
    /// session state, not person identity, and lives on the
    /// trust-gated card session (`bound_serial` field).
    pub printed_serial: Option<PrintedSerial>,
}

impl CredentialIdentity {
    /// Empty identity. Equivalent to [`Default::default`].
    /// Build up by chaining the `with_*` setters.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the [`title`](Self::title) and return `self`.
    #[must_use]
    pub fn with_title(mut self, value: Title) -> Self {
        self.title = Some(value);
        self
    }

    /// Set the [`first_name`](Self::first_name) and return `self`.
    #[must_use]
    pub fn with_first_name(mut self, value: FirstName) -> Self {
        self.first_name = Some(value);
        self
    }

    /// Set the [`second_name`](Self::second_name) and return `self`.
    #[must_use]
    pub fn with_second_name(mut self, value: SecondName) -> Self {
        self.second_name = Some(value);
        self
    }

    /// Append one entry to [`additional_names`](Self::additional_names).
    #[must_use]
    pub fn with_additional_name(mut self, value: AdditionalName) -> Self {
        self.additional_names.push(value);
        self
    }

    /// Replace [`additional_names`](Self::additional_names) wholesale.
    #[must_use]
    pub fn with_additional_names(mut self, values: Vec<AdditionalName>) -> Self {
        self.additional_names = values;
        self
    }

    /// Set the [`surname`](Self::surname) and return `self`.
    #[must_use]
    pub fn with_surname(mut self, value: Surname) -> Self {
        self.surname = Some(value);
        self
    }

    /// Set the [`peuin`](Self::peuin) and return `self`.
    #[must_use]
    pub const fn with_peuin(mut self, value: Peuin) -> Self {
        self.peuin = Some(value);
        self
    }

    /// Set the [`date_of_birth`](Self::date_of_birth) and return `self`.
    #[must_use]
    pub const fn with_date_of_birth(mut self, value: DateOfBirth) -> Self {
        self.date_of_birth = Some(value);
        self
    }

    /// Set the [`printed_serial`](Self::printed_serial) and return `self`.
    #[must_use]
    pub fn with_printed_serial(mut self, value: PrintedSerial) -> Self {
        self.printed_serial = Some(value);
        self
    }

    /// Best available serial for human-facing render paths.
    /// Now just the printed form (the full chip serial moved
    /// out of `CredentialIdentity`); callers that want the
    /// full serial pull `bound_serial` from the trust-gated
    /// session.
    #[must_use]
    pub fn best_serial(&self) -> Option<&str> {
        self.printed_serial.as_deref()
    }

    /// "Person" portion of the identity -- surname, given names,
    /// PEUIN -- space-separated, `None` fields elided. Empty
    /// string when none of those are known.
    ///
    /// Given-name slots concatenate in canonical order: first,
    /// second, then each additional name in stored order. Title
    /// is not included here -- the person-string is used as a
    /// log/audit value, not a salutation.
    ///
    /// Complements [`best_serial`]: the serial identifies the
    /// *card*, the person string identifies *who's on it*. The
    /// pre-op identity log line in `card activate` /
    /// `card emrtd` keeps them as separate fields so structured
    /// output can be parsed without splitting on whitespace.
    ///
    /// [`best_serial`]: CredentialIdentity::best_serial
    #[must_use]
    pub fn person_string(&self) -> String {
        let mut parts: Vec<&str> = Vec::new();
        if let Some(s) = self.surname.as_deref()
            && !s.is_empty()
        {
            parts.push(s);
        }
        for given in self.iter_given_names() {
            if !given.is_empty() {
                parts.push(given);
            }
        }
        if let Some(s) = self.peuin.as_deref()
            && !s.is_empty()
        {
            parts.push(s);
        }
        parts.join(" ")
    }

    /// Iterate every given-name slot in canonical order:
    /// first, second, then each additional name.
    pub fn iter_given_names(&self) -> impl Iterator<Item = &str> {
        self.first_name
            .as_deref()
            .into_iter()
            .chain(self.second_name.as_deref())
            .chain(self.additional_names.iter().map(AsRef::as_ref))
    }

    /// `true` when every field is `None` / empty. Render paths
    /// skip emitting an "identity:" line at all in that case.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.title.is_none()
            && self.first_name.is_none()
            && self.second_name.is_none()
            && self.additional_names.is_empty()
            && self.surname.is_none()
            && self.peuin.is_none()
            && self.date_of_birth.is_none()
            && self.printed_serial.is_none()
    }

    /// Render for a PIN / PUK prompt with a bounded byte
    /// budget.
    ///
    /// Shape: `<token_serial> <surname> <given_names>` --
    /// serial-first, opposite of the SSH-comment ordering.
    /// Reasoning: a PIN prompt is read by the user *right now*
    /// deciding whether to type a secret, and the question
    /// they're answering is "is this the card I'm holding?".
    /// The serial cross-references the plastic-printed card
    /// number; the name is decorative recognition. Putting the
    /// serial first forces the visual check.
    ///
    /// Truncation rules:
    /// - The token serial is **never** truncated. A truncated
    ///   serial wouldn't disambiguate the card; if even the
    ///   serial overshoots the budget, the serial is still
    ///   emitted in full (the budget is a soft hint when it
    ///   conflicts with the safety invariant).
    /// - Surname is dropped wholesale if it doesn't fit -- we
    ///   don't truncate the surname mid-character because a
    ///   partial surname is worse than no surname (false
    ///   recognition risk).
    /// - Given names truncate from the right to fill whatever
    ///   space remains, at a UTF-8 character boundary.
    ///
    /// `None` fields are skipped; the output never contains
    /// double-spaces or trailing spaces.
    #[must_use]
    pub fn to_prompt_label(&self, budget: usize) -> String {
        let serial = self.best_serial().unwrap_or("");
        let mut out = String::from(serial);

        // Surname only if it fits whole (serial + ' ' + surname).
        if let Some(surname) = self.surname.as_deref()
            && !surname.is_empty()
        {
            let sep_len = usize::from(!out.is_empty());
            if out
                .len()
                .saturating_add(sep_len)
                .saturating_add(surname.len())
                <= budget
            {
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push_str(surname);
            } else {
                // No room for surname -> no room for given names
                // either (positional invariant). Done.
                return out;
            }
        }

        // Given names: fill whatever's left, truncating at a
        // char boundary. Slots concatenate left-to-right
        // (first, second, additionals), each separated by a
        // single space; truncation may stop mid-list when the
        // budget runs out, dropping later slots.
        let joined = self
            .iter_given_names()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        if !joined.is_empty() {
            let sep_len = usize::from(!out.is_empty());
            let used = out.len().saturating_add(sep_len);
            if used < budget {
                let room = budget.saturating_sub(used);
                let truncated = if joined.len() <= room {
                    joined.as_str()
                } else {
                    let mut boundary = room;
                    while boundary > 0 && !joined.is_char_boundary(boundary) {
                        boundary = boundary.saturating_sub(1);
                    }
                    joined.get(..boundary).unwrap_or("")
                };
                if !truncated.is_empty() {
                    if !out.is_empty() {
                        out.push(' ');
                    }
                    out.push_str(truncated);
                }
            }
        }

        out
    }

    /// Render for an SSH key comment.
    ///
    /// Positional: `<surname> <given_names> <peuin>
    /// <token_serial_printed>`, single spaces, `None` fields
    /// elided. Same person-first ordering as `Display`, but the
    /// serial slot is filled with the **printed** form only --
    /// never the full PKCS#15 chip serial.
    ///
    /// Why printed-only: an SSH public key in `authorized_keys`
    /// or a project repo travels to people who see only the
    /// plastic-printed card identifier. A 17-or-20-char chip
    /// serial they have no way to cross-reference against
    /// anything is just noise. When the printed form isn't known
    /// (the caller passed `token_serial_printed: None`), the
    /// serial is omitted entirely rather than substituted with
    /// the full form.
    ///
    /// Callers wanting the full chip serial in their output use
    /// `Display` or [`to_kv_string`] instead.
    ///
    /// [`to_kv_string`]: CredentialIdentity::to_kv_string
    #[must_use]
    pub fn to_ssh_comment(&self) -> String {
        let mut out = String::new();
        let mut push = |s: &str| {
            if s.is_empty() {
                return;
            }
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(s);
        };
        if let Some(s) = self.surname.as_deref() {
            push(s);
        }
        for given in self.iter_given_names() {
            push(given);
        }
        if let Some(s) = self.peuin.as_deref() {
            push(s);
        }
        if let Some(s) = self.printed_serial.as_deref() {
            push(s);
        }
        out
    }

    /// `key=value` form, fields separated by single spaces,
    /// `None`s elided. Reads naturally when an identity is
    /// embedded in structured log lines / config files where
    /// the positional `Display` form would be ambiguous.
    ///
    /// Field names match the struct's; values render verbatim
    /// (no shell or YAML escaping -- if a caller needs that
    /// they wrap downstream).
    #[must_use]
    pub fn to_kv_string(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(t) = &self.title {
            parts.push(format!("title={t}"));
        }
        if let Some(s) = &self.surname {
            parts.push(format!("surname={s}"));
        }
        if let Some(s) = &self.first_name {
            parts.push(format!("first_name={s}"));
        }
        if let Some(s) = &self.second_name {
            parts.push(format!("second_name={s}"));
        }
        for (i, n) in self.additional_names.iter().enumerate() {
            parts.push(format!("additional_name_{}={n}", i.saturating_add(1)));
        }
        if let Some(s) = &self.peuin {
            parts.push(format!("peuin={s}"));
        }
        if let Some(d) = &self.date_of_birth {
            parts.push(format!("date_of_birth={d}"));
        }
        if let Some(s) = &self.printed_serial {
            parts.push(format!("printed_serial={s}"));
        }
        parts.join(" ")
    }
}

impl fmt::Display for CredentialIdentity {
    /// Positional form: `<surname> <given_names> <peuin>
    /// <serial>`, single spaces, `None` fields elided. This is
    /// the SSH-comment shape; it also reads cleanly as a CLI
    /// report line and matches the long-standing
    /// "cert-CN-as-comment" convention. Uses [`best_serial`]
    /// so the plastic-printed form wins over the full PKCS#15
    /// form when both are known.
    ///
    /// [`best_serial`]: CredentialIdentity::best_serial
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut emit = |s: &str, f: &mut fmt::Formatter<'_>| -> fmt::Result {
            if s.is_empty() {
                return Ok(());
            }
            if !first {
                f.write_str(" ")?;
            }
            f.write_str(s)?;
            first = false;
            Ok(())
        };
        if let Some(s) = self.surname.as_deref() {
            emit(s, f)?;
        }
        for given in self.iter_given_names() {
            emit(given, f)?;
        }
        if let Some(s) = self.peuin.as_deref() {
            emit(s, f)?;
        }
        if let Some(s) = self.best_serial() {
            emit(s, f)?;
        }
        Ok(())
    }
}

/// Convert an EF.TokenInfo `serialNumber` hex string to the
/// most human-friendly form.
///
/// FINEID v4.0+ chips store the serial as printable ASCII
/// directly, so the hex decodes to a `DEMO0001AB1234567`-shape
/// string. Older v3.1 chips use BCD-style binary bytes whose
/// hex form happens to be all-decimal but doesn't decode to
/// printable ASCII -- we keep the hex string for those.
///
/// Both forms are stable per card; the heuristic just picks the
/// most readable representation per generation.
#[must_use]
pub fn render_token_serial(hex_token: TokenSerial) -> TokenSerial {
    if let Some(bytes) = hex_token.decoded_hex_bytes()
        && !bytes.is_empty()
        && bytes.iter().all(|&b| (0x20..=0x7E).contains(&b))
        && let Ok(s) = core::str::from_utf8(&bytes)
    {
        return TokenSerial::new(s.to_owned());
    }
    hex_token
}

/// Derive the plastic-printed card-side serial from the full
/// PKCS#15 EF.TokenInfo serial.
///
/// The truncation rule varies per FINEID chip generation, and
/// each generation has a distinct surface shape we can recognise
/// without consulting the card variant:
///
/// - **v4.0+ cards:** [`render_token_serial`] decodes the
///   EF.TokenInfo bytes to printable ASCII like
///   `XXXXNNNNAB1234567` (17 chars: 4-char series + 4-char
///   batch + 9-char card identifier). The form printed on the
///   plastic is the last 9 characters (`AB1234567`). Heuristic:
///   any ASCII alphabetic char anywhere in the string flags
///   this shape; take the last 9 chars.
/// - **v3.1 cards:** [`render_token_serial`] returns the original
///   20-hex-digit string (because the BCD bytes don't decode to
///   printable ASCII). The form printed on the plastic is
///   characters `[10..19]` of the 20-char string (9 chars).
///   Heuristic: exactly 20 chars, all ASCII digits.
///
/// Returns `None` when the input doesn't match either shape, so
/// callers don't put a misleading partial serial in a portable
/// artifact. The caller's choice in that case is to omit the
/// serial entirely rather than fall back to the full form.
///
/// Designed for the SSH-comment path ([`to_ssh_comment`]) and the
/// future PKCS#11 cdylib's `CK_TOKEN_INFO.label` build-up; both
/// want the form a human reading the plastic can cross-reference.
///
/// [`to_ssh_comment`]: CredentialIdentity::to_ssh_comment
#[must_use]
pub fn derive_printed_serial(full: &TokenSerial) -> Option<PrintedSerial> {
    let s = full.as_str();
    let bytes = s.as_bytes();
    // Both shapes are FINEID token serials -- the constructor's
    // intent is all-ASCII regardless of v3.1 / v4.0+ generation.
    // Reject non-ASCII defensively so the byte-slicing below
    // remains UTF-8-safe by construction.
    if !s.is_ascii() {
        return None;
    }
    if bytes.iter().any(u8::is_ascii_alphabetic) {
        // v4.0+ ASCII shape: last 9 chars.
        let tail_start = bytes.len().checked_sub(9)?;
        let tail = s.get(tail_start..)?;
        Some(PrintedSerial::new(tail.to_owned()))
    } else if bytes.len() == 20 && bytes.iter().all(u8::is_ascii_digit) {
        // v3.1 BCD-hex shape: chars [10..19], i.e. 9-char window
        // after the 10-char series/batch prefix.
        let window = s.get(10..19)?;
        Some(PrintedSerial::new(window.to_owned()))
    } else {
        None
    }
}

/// Module-local hex-nybble decoder used by
/// [`TokenSerial::decoded_hex_bytes`].
///
/// Distinct from the one in [`crate::crypto::ecdsa`] only because
/// this is a `const fn` and lives in a non-`crypto` module. The
/// subtractions are `wrapping_*` only because the match arms
/// pre-validate the input range; they can never actually wrap.
const fn nybble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(b.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    // Test fixtures use the Finnish Police's published SPECIMEN
    // identity for FINEID-from-2023-03-13 cards (Police PDF
    // "Henkilökortit, 13.3.2023 alkaen myönnetty malli"): an
    // explicitly synthetic identity used for documentation and
    // inspector training. Cards are watermarked SPECIMEN; the
    // names, card number, and CAN are not assigned to any
    // real person.
    //
    // The Police PDF publishes HETU (the printed "Tunnus" field)
    // but not SATU (the cert-CN serial-number DN attribute), so
    // SAMPLE_PEUIN below is a clearly-synthetic SATU placeholder.
    const SAMPLE_SURNAME: &str = "SPECIMEN-TRAVEL";
    const SAMPLE_GIVEN: &str = "VILMA SOFIA";
    const SAMPLE_FIRST: &str = "VILMA";
    const SAMPLE_SECOND: &str = "SOFIA";
    const SAMPLE_PEUIN: &str = "12345678X";
    // Demo card number from the published specimen, used as the
    // plastic-printed serial here. The PKCS#15 chip-side full
    // serial isn't published; we use a synthetic with a DEMO
    // prefix that contains the published card number for
    // recognisability.
    const SAMPLE_SERIAL: &str = "DEMO0001XA1000084";
    const SAMPLE_PRINTED: &str = "XA1000084";

    fn sample_identity() -> CredentialIdentity {
        CredentialIdentity::new()
            .with_surname(Surname::new(SAMPLE_SURNAME.to_owned()).expect("sample surname is valid"))
            .with_first_name(
                FirstName::new(SAMPLE_FIRST.to_owned()).expect("sample first name is valid"),
            )
            .with_second_name(
                SecondName::new(SAMPLE_SECOND.to_owned()).expect("sample second name is valid"),
            )
            .with_peuin(Peuin::new(SAMPLE_PEUIN).expect("sample PEUIN is valid"))
    }

    fn full_with_both_serials() -> CredentialIdentity {
        sample_identity().with_printed_serial(PrintedSerial::new(SAMPLE_PRINTED.to_owned()))
    }

    fn full_full_serial_only() -> CredentialIdentity {
        sample_identity()
    }

    #[test]
    fn display_prefers_printed_serial_when_both_present() {
        // best_serial picks the printed form.
        assert_eq!(
            format!("{}", full_with_both_serials()),
            format!("{SAMPLE_SURNAME} {SAMPLE_GIVEN} {SAMPLE_PEUIN} {SAMPLE_PRINTED}")
        );
    }

    #[test]
    fn display_omits_serial_when_printed_none() {
        // After CredentialIdentity dropped token_serial_full,
        // a printed-None identity has no serial to render. The
        // chip-side full form lives on the trust-gated session,
        // not in CredentialIdentity.
        assert_eq!(
            format!("{}", full_full_serial_only()),
            format!("{SAMPLE_SURNAME} {SAMPLE_GIVEN} {SAMPLE_PEUIN}")
        );
    }

    #[test]
    fn display_skips_none_fields() {
        let id = CredentialIdentity::new()
            .with_surname(Surname::new(SAMPLE_SURNAME.to_owned()).expect("sample surname is valid"))
            .with_peuin(Peuin::new(SAMPLE_PEUIN).expect("sample PEUIN is valid"));
        assert_eq!(format!("{id}"), format!("{SAMPLE_SURNAME} {SAMPLE_PEUIN}"));
    }

    #[test]
    fn display_empty_when_all_none() {
        let id = CredentialIdentity::default();
        assert_eq!(format!("{id}"), "");
        assert!(id.is_empty());
    }

    #[test]
    fn display_handles_multi_given_names() {
        let id = CredentialIdentity::new()
            .with_surname(
                Surname::new("LONGSURNAME".to_owned()).expect("surname LONGSURNAME is valid"),
            )
            .with_first_name(FirstName::new("FIRST".to_owned()).expect("first name FIRST is valid"))
            .with_second_name(
                SecondName::new("SECOND".to_owned()).expect("second name SECOND is valid"),
            )
            .with_additional_name(
                AdditionalName::new("THIRD".to_owned()).expect("additional name THIRD is valid"),
            )
            .with_peuin(Peuin::new("87654321Y").expect("PEUIN 87654321Y is valid"))
            .with_printed_serial(PrintedSerial::new("CARD9999".to_owned()));
        assert_eq!(
            format!("{id}"),
            "LONGSURNAME FIRST SECOND THIRD 87654321Y CARD9999"
        );
    }

    #[test]
    fn kv_string_emits_full_set() {
        assert_eq!(
            full_with_both_serials().to_kv_string(),
            format!(
                "surname={SAMPLE_SURNAME} first_name={SAMPLE_FIRST} \
                 second_name={SAMPLE_SECOND} peuin={SAMPLE_PEUIN} \
                 printed_serial={SAMPLE_PRINTED}"
            )
        );
    }

    #[test]
    fn kv_string_skips_none_fields() {
        let id = CredentialIdentity::new()
            .with_surname(Surname::new(SAMPLE_SURNAME.to_owned()).expect("sample surname is valid"))
            .with_peuin(Peuin::new(SAMPLE_PEUIN).expect("sample PEUIN is valid"));
        assert_eq!(
            id.to_kv_string(),
            format!("surname={SAMPLE_SURNAME} peuin={SAMPLE_PEUIN}")
        );
    }

    #[test]
    fn kv_string_emits_additional_names_with_indexed_keys() {
        let id = CredentialIdentity::new()
            .with_first_name(FirstName::new("Anna".to_owned()).expect("first name Anna is valid"))
            .with_second_name(
                SecondName::new("Maria".to_owned()).expect("second name Maria is valid"),
            )
            .with_additional_name(
                AdditionalName::new("Helena".to_owned()).expect("additional name Helena is valid"),
            )
            .with_additional_name(
                AdditionalName::new("Sofia".to_owned()).expect("additional name Sofia is valid"),
            );
        assert_eq!(
            id.to_kv_string(),
            "first_name=Anna second_name=Maria \
             additional_name_1=Helena additional_name_2=Sofia"
        );
    }

    #[test]
    fn token_serial_prefers_ascii_when_printable() {
        // Hex of SAMPLE_SERIAL (a synthetic v4.0-shape ASCII
        // serial). Use a small ASCII-only helper to keep the
        // test free of an external hex crate.
        let synthetic_ascii = SAMPLE_SERIAL;
        let mut hex_form = String::with_capacity(synthetic_ascii.len() * 2);
        for b in synthetic_ascii.as_bytes() {
            let _fmt: fmt::Result = fmt::write(&mut hex_form, format_args!("{b:02x}"));
        }
        assert_eq!(
            render_token_serial(TokenSerial::new(hex_form)),
            synthetic_ascii
        );
    }

    #[test]
    fn token_serial_keeps_hex_when_bytes_are_binary() {
        // Synthetic 20-decimal-digit form a la v3.1 cards. The
        // hex decodes to bytes that aren't printable ASCII, so
        // the original hex stays as-is.
        let hex = "10000000000000000000";
        assert_eq!(render_token_serial(TokenSerial::new(hex.to_owned())), hex);
    }

    #[test]
    fn token_serial_rejects_odd_length_hex() {
        // Falls through to returning the input unchanged.
        assert_eq!(
            render_token_serial(TokenSerial::new("abc".to_owned())),
            "abc"
        );
    }

    // ----- to_prompt_label -----

    fn sample_with_short_serial(serial: PrintedSerial) -> CredentialIdentity {
        // Use the printed-serial slot here so the prompt-label
        // render sees it as the "best serial" (matching how a
        // real PKCS#11 module would populate this field).
        sample_identity().with_printed_serial(serial)
    }

    #[test]
    fn prompt_label_serial_first() {
        // Full identity fits in 64 bytes with headroom; verify
        // the serial-first ordering when nothing has to drop.
        let id = sample_with_short_serial(PrintedSerial::new(SAMPLE_PRINTED.to_owned()));
        assert_eq!(
            id.to_prompt_label(64),
            format!("{SAMPLE_PRINTED} {SAMPLE_SURNAME} {SAMPLE_GIVEN}")
        );
    }

    #[test]
    fn prompt_label_truncates_given_names_under_pressure() {
        // Tight budget: serial + space + surname + space + N
        // chars of given names. Pick a value where surname fits
        // but given names can only fit partially.
        let id = sample_with_short_serial(PrintedSerial::new(SAMPLE_PRINTED.to_owned()));
        // SAMPLE_PRINTED (9) + " " + SAMPLE_SURNAME (15) + " " +
        // 2 chars of SAMPLE_GIVEN = 28 bytes total.
        let budget = SAMPLE_PRINTED.len() + 1 + SAMPLE_SURNAME.len() + 1 + 2;
        let out = id.to_prompt_label(budget);
        assert!(out.starts_with(&format!("{SAMPLE_PRINTED} {SAMPLE_SURNAME} ")));
        assert!(out.len() <= budget);
        assert!(out.len() >= SAMPLE_PRINTED.len() + 1 + SAMPLE_SURNAME.len() + 2);
    }

    #[test]
    fn prompt_label_drops_surname_wholesale_when_too_tight() {
        // Budget large enough only for the serial.
        let id = sample_with_short_serial(PrintedSerial::new(SAMPLE_PRINTED.to_owned()));
        let out = id.to_prompt_label(SAMPLE_PRINTED.len() + 2); // can't fit " SURNAME"
        assert_eq!(out, SAMPLE_PRINTED);
    }

    #[test]
    fn prompt_label_serial_emitted_even_when_over_budget() {
        // Budget smaller than the serial itself: serial wins
        // anyway. A truncated serial wouldn't identify the card.
        let long_serial = "VERYLONGSERIAL123456";
        let id = sample_with_short_serial(PrintedSerial::new(long_serial.to_owned()));
        let out = id.to_prompt_label(8);
        assert_eq!(out, long_serial);
    }

    #[test]
    fn prompt_label_handles_missing_serial() {
        let id = CredentialIdentity::new()
            .with_surname(Surname::new(SAMPLE_SURNAME.to_owned()).expect("sample surname is valid"))
            .with_first_name(
                FirstName::new(SAMPLE_FIRST.to_owned()).expect("sample first name is valid"),
            )
            .with_second_name(
                SecondName::new(SAMPLE_SECOND.to_owned()).expect("sample second name is valid"),
            );
        // No serial -> surname first, no leading space.
        assert_eq!(
            id.to_prompt_label(32),
            format!("{SAMPLE_SURNAME} {SAMPLE_GIVEN}")
        );
    }

    #[test]
    fn prompt_label_handles_missing_person() {
        let id = CredentialIdentity::new()
            .with_printed_serial(PrintedSerial::new(SAMPLE_PRINTED.to_owned()));
        assert_eq!(id.to_prompt_label(32), SAMPLE_PRINTED);
    }

    #[test]
    fn prompt_label_prefers_printed_when_both_serials_set() {
        let id = CredentialIdentity::new()
            .with_surname(Surname::new(SAMPLE_SURNAME.to_owned()).expect("sample surname is valid"))
            .with_printed_serial(PrintedSerial::new(SAMPLE_PRINTED.to_owned()));
        // 32-byte budget; printed wins over full.
        let out = id.to_prompt_label(32);
        assert!(out.starts_with(SAMPLE_PRINTED));
        assert!(!out.contains(SAMPLE_SERIAL));
    }

    #[test]
    fn prompt_label_starts_empty_when_no_printed_serial() {
        // After CredentialIdentity dropped token_serial_full,
        // an identity with no printed_serial has no serial to
        // lead the prompt with -- it shows the name only.
        let id = CredentialIdentity::new().with_surname(
            Surname::new(SAMPLE_SURNAME.to_owned()).expect("sample surname is valid"),
        );
        let out = id.to_prompt_label(32);
        assert_eq!(out, SAMPLE_SURNAME);
    }

    #[test]
    fn prompt_label_empty_when_all_none() {
        assert_eq!(CredentialIdentity::default().to_prompt_label(32), "");
    }

    #[test]
    fn prompt_label_truncates_at_utf8_boundary() {
        // Multi-byte given name. The é is 2 bytes; truncation
        // can't land inside it.
        let id = CredentialIdentity::new()
            .with_surname(Surname::new("SHORT".to_owned()).expect("surname SHORT is valid"))
            .with_first_name(
                FirstName::new("Andr\u{00e9}e".to_owned())
                    .expect("first name with e-acute is valid"),
            )
            .with_second_name(
                SecondName::new("M\u{00e9}gane".to_owned())
                    .expect("second name with e-acute is valid"),
            )
            .with_printed_serial(PrintedSerial::new("SER123".to_owned()));
        let out = id.to_prompt_label(18);
        // Result is valid UTF-8 ending at a char boundary,
        // starting with the serial + surname prefix.
        assert!(out.is_char_boundary(out.len()));
        assert!(out.starts_with("SER123 SHORT "));
    }

    #[test]
    fn prompt_label_zero_budget_still_emits_serial() {
        // Edge case: budget == 0. Serial wins.
        let id = sample_with_short_serial(PrintedSerial::new(SAMPLE_PRINTED.to_owned()));
        assert_eq!(id.to_prompt_label(0), SAMPLE_PRINTED);
    }

    // ----- to_ssh_comment -----

    #[test]
    fn ssh_comment_uses_printed_serial_only() {
        // Both serials present -> the SSH comment carries the
        // short printed form; the long chip serial is dropped.
        let id = full_with_both_serials();
        let comment = id.to_ssh_comment();
        assert_eq!(
            comment,
            format!("{SAMPLE_SURNAME} {SAMPLE_GIVEN} {SAMPLE_PEUIN} {SAMPLE_PRINTED}")
        );
        assert!(!comment.contains(SAMPLE_SERIAL));
    }

    #[test]
    fn ssh_comment_omits_serial_when_only_full_known() {
        // Caller knows only the full chip serial. SSH comment
        // drops the serial entirely rather than embedding the
        // long-and-unreferable chip form.
        let id = full_full_serial_only();
        let comment = id.to_ssh_comment();
        assert_eq!(
            comment,
            format!("{SAMPLE_SURNAME} {SAMPLE_GIVEN} {SAMPLE_PEUIN}")
        );
        assert!(!comment.contains(SAMPLE_SERIAL));
    }

    #[test]
    fn ssh_comment_skips_none_fields() {
        let id = CredentialIdentity::new()
            .with_surname(Surname::new(SAMPLE_SURNAME.to_owned()).expect("sample surname is valid"))
            .with_peuin(Peuin::new(SAMPLE_PEUIN).expect("sample PEUIN is valid"))
            .with_printed_serial(PrintedSerial::new(SAMPLE_PRINTED.to_owned()));
        assert_eq!(
            id.to_ssh_comment(),
            format!("{SAMPLE_SURNAME} {SAMPLE_PEUIN} {SAMPLE_PRINTED}")
        );
    }

    #[test]
    fn ssh_comment_empty_when_all_none() {
        assert_eq!(CredentialIdentity::default().to_ssh_comment(), "");
    }

    // ----- derive_printed_serial -----

    #[test]
    fn derive_printed_v4_ascii_takes_last_nine() {
        // v4.0-shape: 17-char ASCII with alphabetic chars.
        // Take the last 9 chars.
        assert_eq!(
            derive_printed_serial(&TokenSerial::new("DEMO0001XA1000084".to_owned())).as_deref(),
            Some("XA1000084")
        );
        assert_eq!(
            derive_printed_serial(&TokenSerial::new("DEMO0001AB1234567".to_owned())).as_deref(),
            Some("AB1234567")
        );
    }

    #[test]
    fn derive_printed_v3_1_takes_middle_nine() {
        // v3.1-shape: 20 ASCII digits, chars [10..19].
        // "12345678901234567890"[10..19] = "123456789".
        assert_eq!(
            derive_printed_serial(&TokenSerial::new("12345678901234567890".to_owned())).as_deref(),
            Some("123456789")
        );
        // All-zeros middle window.
        assert_eq!(
            derive_printed_serial(&TokenSerial::new("10000000000000000000".to_owned())).as_deref(),
            Some("000000000")
        );
    }

    #[test]
    fn derive_printed_rejects_unknown_shapes() {
        // Too short for v4.0 take-last-9.
        assert!(derive_printed_serial(&TokenSerial::new("SHORT".to_owned())).is_none());
        // All-digit but wrong length for v3.1.
        assert!(derive_printed_serial(&TokenSerial::new("1234567890".to_owned())).is_none());
        assert!(
            derive_printed_serial(&TokenSerial::new("123456789012345678901".to_owned())).is_none()
        );
        // Empty.
        assert!(derive_printed_serial(&TokenSerial::new(String::new())).is_none());
    }

    #[test]
    fn derive_printed_exact_nine_ascii_returns_whole_input() {
        // v4.0 path: exactly 9 chars and has an alphabetic.
        // Last 9 == the whole thing.
        assert_eq!(
            derive_printed_serial(&TokenSerial::new("AB1234567".to_owned())).as_deref(),
            Some("AB1234567")
        );
    }

    // ----- Peuin -----

    #[test]
    fn peuin_accepts_eight_digits_plus_alpha_checksum() {
        let p = Peuin::new("12345678X").expect("eight digits plus alpha checksum parses");
        assert_eq!(p.as_str(), "12345678X");
    }

    #[test]
    fn peuin_accepts_digit_checksum() {
        // The checksum character is alphanumeric -- digit is OK.
        let p = Peuin::new("123456789").expect("digit checksum parses");
        assert_eq!(p.as_str(), "123456789");
    }

    #[test]
    fn peuin_rejects_wrong_length() {
        assert!(matches!(
            Peuin::new("1234567"),
            Err(PeuinError::WrongLength { got: 7 })
        ));
        assert!(matches!(
            Peuin::new("1234567890"),
            Err(PeuinError::WrongLength { got: 10 })
        ));
        assert!(matches!(
            Peuin::new(""),
            Err(PeuinError::WrongLength { got: 0 })
        ));
    }

    #[test]
    fn peuin_rejects_non_digit_in_body() {
        match Peuin::new("12X45678Y") {
            Err(PeuinError::NonDigit { at: 2, byte: b'X' }) => {}
            other => panic!("expected NonDigit at offset 2, got {other:?}"),
        }
    }

    #[test]
    fn peuin_rejects_non_alphanumeric_checksum() {
        match Peuin::new("12345678!") {
            Err(PeuinError::BadChecksum { byte: b'!' }) => {}
            other => panic!("expected BadChecksum, got {other:?}"),
        }
    }

    #[test]
    fn peuin_displays_as_str() {
        let p = Peuin::new("87654321Y").expect("PEUIN 87654321Y is valid");
        assert_eq!(format!("{p}"), "87654321Y");
    }

    #[test]
    fn peuin_partial_eq_against_str() {
        let p = Peuin::new("11111111A").expect("PEUIN 11111111A is valid");
        assert_eq!(p, "11111111A");
    }

    // ----- Surname / GivenName -----

    #[test]
    fn surname_accepts_non_empty() {
        let s = Surname::new("Smith".to_owned()).expect("non-empty surname parses");
        assert_eq!(s.as_str(), "Smith");
    }

    #[test]
    fn surname_rejects_empty() {
        assert!(matches!(
            Surname::new(String::new()),
            Err(FreeTextError::Empty)
        ));
    }

    #[test]
    fn surname_rejects_too_long() {
        let huge = "a".repeat(FREE_TEXT_MAX_BYTES + 1);
        assert!(matches!(
            Surname::new(huge),
            Err(FreeTextError::TooLong { .. })
        ));
    }

    #[test]
    fn split_given_names_handles_one_name() {
        let s = GivenNamesText::new("MATTI".to_owned())
            .expect("single given name is valid")
            .split();
        assert_eq!(s.first.as_deref(), Some("MATTI"));
        assert!(s.second.is_none());
        assert!(s.additional.is_empty());
    }

    #[test]
    fn split_given_names_handles_two_names() {
        let s = GivenNamesText::new("MATTI JUHANI".to_owned())
            .expect("two given names are valid")
            .split();
        assert_eq!(s.first.as_deref(), Some("MATTI"));
        assert_eq!(s.second.as_deref(), Some("JUHANI"));
        assert!(s.additional.is_empty());
    }

    #[test]
    fn split_given_names_handles_four_names() {
        let s = GivenNamesText::new("ANNA MARIA HELENA SOFIA".to_owned())
            .expect("four given names are valid")
            .split();
        assert_eq!(s.first.as_deref(), Some("ANNA"));
        assert_eq!(s.second.as_deref(), Some("MARIA"));
        assert_eq!(s.additional.len(), 2);
        assert_eq!(s.additional[0].as_str(), "HELENA");
        assert_eq!(s.additional[1].as_str(), "SOFIA");
    }

    #[test]
    fn split_given_names_collapses_multiple_spaces() {
        let s = GivenNamesText::new("  MATTI   JUHANI  ".to_owned())
            .expect("whitespace-padded given names are valid")
            .split();
        assert_eq!(s.first.as_deref(), Some("MATTI"));
        assert_eq!(s.second.as_deref(), Some("JUHANI"));
    }

    #[test]
    fn split_given_names_empty_input_yields_default() {
        let s = GivenNamesText::new(String::new())
            .map_or_else(|_err| SplitGivenNames::default(), |text| text.split());
        assert!(s.first.is_none());
        assert!(s.second.is_none());
        assert!(s.additional.is_empty());
    }

    #[test]
    fn split_given_names_keeps_hyphenated_name_in_one_slot() {
        // Hyphenated single names stay together (no whitespace split).
        let s = GivenNamesText::new("Marie-Claire Sofia".to_owned())
            .expect("hyphenated given name is valid")
            .split();
        assert_eq!(s.first.as_deref(), Some("Marie-Claire"));
        assert_eq!(s.second.as_deref(), Some("Sofia"));
    }

    // ----- Role-typed date wrappers around Iso8601 -----
    //
    // Calendar / wire-form validation lives in iso8601.rs tests;
    // these tests pin only the role-wrapper concerns: the
    // constructor enforces the variant invariant, Display
    // renders ISO 8601, the semantic projection works, and the
    // distinct types refuse cross-assignment.

    #[test]
    fn date_of_birth_constructs_and_displays() -> Result<(), crate::iso8601::Iso8601Error> {
        let dob = DateOfBirth::from_calendar(1974, 11, 30)?;
        assert_eq!(format!("{dob}"), "1974-11-30");
        // Semantic projection: representation-level access for
        // operations that need year/month/day numbers.
        assert_eq!(dob.date().year(), 1974);
        assert_eq!(dob.date().month(), 11);
        assert_eq!(dob.date().day(), 30);
        Ok(())
    }

    #[test]
    fn date_of_birth_parses_yyyymmdd_wire_form() -> Result<(), crate::iso8601::Iso8601Error> {
        let dob = DateOfBirth::from_yyyymmdd(*b"19741130")?;
        assert_eq!(format!("{dob}"), "1974-11-30");
        Ok(())
    }

    #[test]
    fn date_of_birth_propagates_iso8601_error_for_bad_input() {
        assert!(matches!(
            DateOfBirth::from_calendar(1899, 1, 1),
            Err(crate::iso8601::Iso8601Error::YearOutOfRange { .. })
        ));
        // Wrong-shape input is caught at the [u8; 8] coercion layer
        // (compile time) -- a 6-byte literal won't even type-check.
        // Bad-but-shaped input still produces ParseShape via the
        // ascii-digit check failing on a "1974111x" style byte.
        assert!(matches!(
            DateOfBirth::from_yyyymmdd(*b"1974111x"),
            Err(crate::iso8601::Iso8601Error::ParseChars { .. })
        ));
    }

    #[test]
    fn issue_date_round_trips_from_yyyymmdd() -> Result<(), crate::iso8601::Iso8601Error> {
        let d = IssueDate::from_yyyymmdd(*b"20210101")?;
        assert_eq!(format!("{d}"), "2021-01-01");
        assert_eq!(d.date().year(), 2021);
        Ok(())
    }

    #[test]
    fn mrz_date_parses_yymmdd_with_50_50_century() -> Result<(), crate::iso8601::Iso8601Error> {
        // YY < 50 -> 20YY, else 19YY.
        assert_eq!(MrzDate::from_mrz_yymmdd(*b"740812")?.date().year(), 1974);
        assert_eq!(MrzDate::from_mrz_yymmdd(*b"260520")?.date().year(), 2026);
        assert_eq!(MrzDate::from_mrz_yymmdd(*b"490101")?.date().year(), 2049);
        assert_eq!(MrzDate::from_mrz_yymmdd(*b"500101")?.date().year(), 1950);
        Ok(())
    }

    #[test]
    fn mrz_date_displays_iso_8601_form() -> Result<(), crate::iso8601::Iso8601Error> {
        let d = MrzDate::from_mrz_yymmdd(*b"740812")?;
        // Canonical Display is ISO 8601; the on-card MRZ form
        // round-trips via .to_mrz_yymmdd().
        assert_eq!(format!("{d}"), "1974-08-12");
        assert_eq!(d.to_mrz_yymmdd(), "740812");
        Ok(())
    }

    #[test]
    fn mrz_date_rejects_bad_input() {
        assert!(matches!(
            MrzDate::from_mrz_yymmdd(*b"<<<<<<"),
            Err(crate::iso8601::Iso8601Error::ParseChars { .. })
        ));
        assert!(matches!(
            MrzDate::from_mrz_yymmdd(*b"741312"),
            Err(crate::iso8601::Iso8601Error::MonthOutOfRange { month: 13 })
        ));
    }

    #[test]
    fn cross_role_equality_via_semantic_projection() -> Result<(), crate::iso8601::Iso8601Error> {
        // The whole point of the shared Iso8601 inner: when two
        // role-typed values refer to the same calendar date,
        // their semantic projections compare equal.
        let dg11_dob = DateOfBirth::from_yyyymmdd(*b"19740812")?;
        let mrz_dob = MrzDate::from_mrz_yymmdd(*b"740812")?;
        assert_eq!(dg11_dob.date(), mrz_dob.date());
        Ok(())
    }

    #[test]
    fn role_types_render_canonically() -> Result<(), crate::iso8601::Iso8601Error> {
        // String render of all three role types -- the typing
        // discipline that DateOfBirth != IssueDate != MrzDate
        // is enforced by the compiler; this test pins only that
        // Display threads through the inner Iso8601 correctly.
        let dob = DateOfBirth::from_calendar(1974, 11, 30)?;
        let issue = IssueDate::from_calendar(2021, 1, 1)?;
        let mrz = MrzDate::from_calendar(1974, 11, 30)?;
        assert_eq!(format!("{dob}"), "1974-11-30");
        assert_eq!(format!("{issue}"), "2021-01-01");
        assert_eq!(format!("{mrz}"), "1974-11-30");
        Ok(())
    }

    // ----- CommonName -----

    #[test]
    fn common_name_accepts_non_empty() {
        let cn = CommonName::new("DVV Citizen Certificates - G4R".to_owned())
            .expect("non-empty common name parses");
        assert_eq!(cn.as_str(), "DVV Citizen Certificates - G4R");
    }

    #[test]
    fn common_name_rejects_empty() {
        assert!(matches!(
            CommonName::new(String::new()),
            Err(FreeTextError::Empty)
        ));
    }

    // ----- EmailAddress -----

    #[test]
    fn email_accepts_simple_address() {
        let e = EmailAddress::new("alice@example.test").expect("simple email address parses");
        assert_eq!(e.as_str(), "alice@example.test");
    }

    #[test]
    fn email_accepts_plus_addressing() {
        let _email =
            EmailAddress::new("alice+tag@example.test").expect("plus-addressed email parses");
    }

    #[test]
    fn email_accepts_subdomains() {
        let _email = EmailAddress::new("u@a.b.c.example").expect("subdomain email parses");
    }

    #[test]
    fn email_rejects_empty() {
        assert!(matches!(
            EmailAddress::new(""),
            Err(EmailAddressError::Empty)
        ));
    }

    #[test]
    fn email_rejects_no_at() {
        assert!(matches!(
            EmailAddress::new("alice"),
            Err(EmailAddressError::NoAtSign)
        ));
    }

    #[test]
    fn email_rejects_multiple_ats() {
        assert!(matches!(
            EmailAddress::new("a@b@c"),
            Err(EmailAddressError::MultipleAtSigns { count: 2 })
        ));
    }

    #[test]
    fn email_rejects_empty_local() {
        assert!(matches!(
            EmailAddress::new("@example.test"),
            Err(EmailAddressError::EmptyLocalPart)
        ));
    }

    #[test]
    fn email_rejects_empty_domain() {
        assert!(matches!(
            EmailAddress::new("alice@"),
            Err(EmailAddressError::EmptyDomainPart)
        ));
    }

    #[test]
    fn email_rejects_whitespace() {
        assert!(matches!(
            EmailAddress::new("a lice@example.test"),
            Err(EmailAddressError::Whitespace { at: 1 })
        ));
        assert!(matches!(
            EmailAddress::new("alice@example .test"),
            Err(EmailAddressError::Whitespace { .. })
        ));
    }

    #[test]
    fn email_rejects_too_long() {
        let s = format!("{}@example.test", "x".repeat(250));
        assert!(matches!(
            EmailAddress::new(&s),
            Err(EmailAddressError::TooLong { .. })
        ));
    }

    #[test]
    fn email_partial_eq_against_str() {
        let e = EmailAddress::new("a@b.test").expect("short email address parses");
        assert_eq!(e, "a@b.test");
    }

    // ----- CertSerial -----

    #[test]
    fn cert_serial_renders_lowercase_hex_no_separators() {
        let s = CertSerial::from_bytes(vec![0x3C, 0x40, 0xE4, 0x23]);
        assert_eq!(format!("{s}"), "3c40e423");
    }

    #[test]
    fn cert_serial_round_trips_bytes() {
        let bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let s = CertSerial::from_bytes(bytes.clone());
        assert_eq!(s.as_bytes(), bytes.as_slice());
    }

    #[test]
    fn cert_serial_empty_bytes_render_empty_string() {
        // Edge case -- a degenerate INTEGER (refineid parser
        // wouldn't produce this, but the type permits it).
        let s = CertSerial::from_bytes(Vec::new());
        assert_eq!(format!("{s}"), "");
    }

    // ----- Per-slot name newtypes -----

    #[test]
    fn first_name_accepts_native_form() {
        let n =
            FirstName::new("Yrj\u{00f6}".to_owned()).expect("first name with o-umlaut is valid");
        assert_eq!(n.as_str(), "Yrj\u{00f6}");
        assert_eq!(format!("{n}"), "Yrj\u{00f6}");
    }

    #[test]
    fn first_name_rejects_empty() {
        assert!(matches!(
            FirstName::new(String::new()),
            Err(FreeTextError::Empty)
        ));
    }

    #[test]
    fn second_name_accepts_native_form() {
        let n = SecondName::new("Antero".to_owned()).expect("second name Antero is valid");
        assert_eq!(n.as_str(), "Antero");
    }

    #[test]
    fn additional_name_accepts_native_form() {
        let n = AdditionalName::new("Juhani".to_owned()).expect("additional name Juhani is valid");
        assert_eq!(n.as_str(), "Juhani");
    }

    #[test]
    fn names_preserve_latin_extended_diacritics() {
        // Š, Ž (Latin Extended A) -- outside ISO 8859-1 but
        // valid UTF-8 and a real Finnish-resident name case.
        let n =
            FirstName::new("\u{0160}andor".to_owned()).expect("first name with S-caron is valid");
        assert_eq!(n.as_str(), "\u{0160}andor");
        let n = AdditionalName::new("\u{017d}".to_owned())
            .expect("additional name with Z-caron is valid");
        assert_eq!(n.as_str(), "\u{017d}");
    }

    // ----- DG11 free-text newtypes -----

    #[test]
    fn title_round_trips() {
        let t = Title::new("Prof.".to_owned()).expect("title Prof. is valid");
        assert_eq!(t.as_str(), "Prof.");
    }

    #[test]
    fn profession_distinct_type_from_title() {
        // Compile-test by construction. Title and Profession
        // are nominally different even if the strings match.
        let t = Title::new("Mr".to_owned()).expect("title Mr is valid");
        let p = Profession::new("Mr".to_owned()).expect("profession Mr is valid");
        assert_eq!(t.as_str(), p.as_str()); // string equality OK
        // `t == p` would fail to compile (no PartialEq between
        // Title and Profession).
    }

    #[test]
    fn personal_summary_accepts_long_text() {
        let s = "Lorem ipsum ".repeat(20);
        let _summary = PersonalSummary::new(s).expect("long personal summary within limit parses");
    }

    #[test]
    fn free_text_rejects_over_max() {
        let huge = "a".repeat(FREE_TEXT_MAX_BYTES + 1);
        assert!(matches!(
            Title::new(huge),
            Err(FreeTextError::TooLong { .. })
        ));
    }

    #[test]
    fn place_of_birth_carries_filler_separators() {
        // ICAO 9303-10 separates city / region / country with `<`.
        let p = PlaceOfBirth::new("HELSINKI<UUSIMAA<FIN".to_owned())
            .expect("place of birth with filler separators parses");
        assert_eq!(p.as_str(), "HELSINKI<UUSIMAA<FIN");
    }

    #[test]
    fn permanent_address_round_trips() {
        let a = PermanentAddress::new("Mannerheimintie 1<00100 Helsinki".to_owned())
            .expect("permanent address parses");
        assert_eq!(a.as_str(), "Mannerheimintie 1<00100 Helsinki");
    }

    #[test]
    fn telephone_round_trips() {
        let t = Telephone::new("+358401234567".to_owned()).expect("telephone number parses");
        assert_eq!(t.as_str(), "+358401234567");
    }

    #[test]
    fn custody_information_round_trips() {
        let c = CustodyInformation::new("Parent or legal guardian".to_owned())
            .expect("custody information parses");
        assert_eq!(c.as_str(), "Parent or legal guardian");
    }

    #[test]
    fn other_td_number_round_trips() {
        let n =
            OtherTdNumber::new("P1234567".to_owned()).expect("other travel document number parses");
        assert_eq!(n.as_str(), "P1234567");
    }

    #[test]
    fn other_name_round_trips() {
        let n = OtherName::new("n\u{00e9}e Virtanen".to_owned()).expect("other name parses");
        assert_eq!(n.as_str(), "n\u{00e9}e Virtanen");
    }

    #[test]
    fn dg11_full_name_splits_double_filler() {
        let fn_ = Dg11FullName::new("M\u{00c4}KINEN<<YRJ\u{00d6}<ANTERO".to_owned())
            .expect("DG11 full name with double filler parses");
        let (surname, given) = fn_
            .try_split_into_parts()
            .expect("full name splits into surname and given names");
        assert_eq!(surname.as_str(), "M\u{00c4}KINEN");
        assert_eq!(given.first.as_deref(), Some("YRJ\u{00d6}"));
        assert_eq!(given.second.as_deref(), Some("ANTERO"));
    }

    #[test]
    fn dg11_full_name_falls_back_to_whitespace_last_token_surname() {
        let fn_ = Dg11FullName::new("Yrj\u{00f6} Antero M\u{00e4}kinen".to_owned())
            .expect("whitespace-separated full name parses");
        let (surname, given) = fn_
            .try_split_into_parts()
            .expect("full name splits into surname and given names");
        assert_eq!(surname.as_str(), "M\u{00e4}kinen");
        assert_eq!(given.first.as_deref(), Some("Yrj\u{00f6}"));
        assert_eq!(given.second.as_deref(), Some("Antero"));
    }

    #[test]
    fn dg11_full_name_single_token_yields_none() {
        // Only one token - can't split into surname + given.
        let fn_ =
            Dg11FullName::new("M\u{00e4}kinen".to_owned()).expect("single-token full name parses");
        assert!(fn_.try_split_into_parts().is_none());
    }

    #[test]
    fn personal_number_round_trips() {
        // PersonalNumber is the DG11 0x5F10 wrapper. Not validated
        // as HETU at this layer -- generic; the issuing state
        // defines the shape. We use a deliberately non-HETU value
        // so gitleaks' fineid-pic rule (and any future PII
        // scanners) see no structural match.
        let n = PersonalNumber::new("FI-PN-OPAQUE-001".to_owned())
            .expect("opaque personal number parses");
        assert_eq!(n.as_str(), "FI-PN-OPAQUE-001");
    }

    // ----- DG12 free-text newtypes -----

    #[test]
    fn issuing_authority_round_trips() {
        let a = IssuingAuthority::new("DVV".to_owned()).expect("issuing authority DVV parses");
        assert_eq!(a.as_str(), "DVV");
    }

    #[test]
    fn endorsements_round_trips() {
        let e =
            Endorsements::new("Renewed 2026-05-19".to_owned()).expect("endorsements text parses");
        assert_eq!(e.as_str(), "Renewed 2026-05-19");
    }

    #[test]
    fn tax_exit_round_trips() {
        let t = TaxExit::new("None".to_owned()).expect("tax exit text parses");
        assert_eq!(t.as_str(), "None");
    }

    #[test]
    fn other_person_round_trips() {
        let p = OtherPerson::new("KORHONEN<MAIJA".to_owned()).expect("other person name parses");
        assert_eq!(p.as_str(), "KORHONEN<MAIJA");
    }

    #[test]
    fn personalisation_device_serial_round_trips() {
        let s = PersonalisationDeviceSerial::new("DVV-WS-042".to_owned())
            .expect("personalisation device serial parses");
        assert_eq!(s.as_str(), "DVV-WS-042");
    }

    // ----- MRZ identifiers -----

    #[test]
    fn mrz_surname_accepts_transliterated() {
        let m = MrzSurname::new("MAEKINEN".to_owned()).expect("transliterated MRZ surname parses");
        assert_eq!(m.as_str(), "MAEKINEN");
    }

    #[test]
    fn mrz_surname_accepts_filler() {
        // Field is `<`-padded; the type permits the filler.
        let m = MrzSurname::new("MAEKINEN<<<<<<<".to_owned())
            .expect("filler-padded MRZ surname parses");
        assert_eq!(m.as_str(), "MAEKINEN<<<<<<<");
    }

    #[test]
    fn mrz_surname_rejects_lowercase() {
        let err = MrzSurname::new("Maekinen".to_owned())
            .expect_err("lowercase letter rejected in MRZ surname");
        assert!(matches!(err, MrzNameError::InvalidChar { .. }));
    }

    #[test]
    fn mrz_surname_rejects_diacritic() {
        // The whole point of the MRZ form is that diacritics
        // were already transliterated. Reject any non-ASCII byte.
        let err = MrzSurname::new("M\u{00c4}KINEN".to_owned())
            .expect_err("diacritic rejected in MRZ surname");
        assert!(matches!(err, MrzNameError::InvalidChar { .. }));
    }

    #[test]
    fn mrz_surname_rejects_digit() {
        let err =
            MrzSurname::new("MAKE5INEN".to_owned()).expect_err("digit rejected in MRZ surname");
        assert!(matches!(err, MrzNameError::InvalidChar { at: 4, .. }));
    }

    #[test]
    fn mrz_given_name_accepts_inner_filler() {
        // Multiple given names join with single `<`.
        let m = MrzGivenName::new("YRJOE<ANTERO<JUHANI".to_owned())
            .expect("MRZ given names with inner filler parse");
        assert_eq!(m.as_str(), "YRJOE<ANTERO<JUHANI");
    }

    #[test]
    fn mrz_given_name_rejects_empty() {
        assert!(matches!(
            MrzGivenName::new(String::new()),
            Err(MrzNameError::Empty)
        ));
    }

    #[test]
    fn mrz_name_rejects_too_long() {
        let too_big = "A".repeat(MRZ_NAME_MAX_BYTES + 1);
        assert!(matches!(
            MrzSurname::new(too_big),
            Err(MrzNameError::TooLong { .. })
        ));
    }

    #[test]
    fn mrz_surname_spaced_strips_trailing_and_converts_inner() {
        let m = MrzSurname::new("MAEKINEN<YRJOE<<<<".to_owned())
            .expect("MRZ surname with inner and trailing filler parses");
        assert_eq!(m.spaced(), "MAEKINEN YRJOE");
    }

    // ----- ICAO 9303-3 §6 transliteration -----

    #[test]
    fn transliterate_finnish_diacritics_to_mrz() {
        assert_eq!(
            NativeMrzText("M\u{00e4}kinen".to_owned()).to_mrz(),
            "MAEKINEN"
        );
        assert_eq!(NativeMrzText("Yrj\u{00f6}".to_owned()).to_mrz(), "YRJOE");
        assert_eq!(NativeMrzText("\u{00c5}ke".to_owned()).to_mrz(), "AAKE");
    }

    #[test]
    fn transliterate_german_sharp_s() {
        assert_eq!(
            NativeMrzText("Stra\u{00df}e".to_owned()).to_mrz(),
            "STRASSE"
        );
    }

    #[test]
    fn transliterate_slavic_diacritics() {
        assert_eq!(NativeMrzText("\u{0160}andor".to_owned()).to_mrz(), "SANDOR");
        assert_eq!(
            NativeMrzText("\u{017d}i\u{017e}ek".to_owned()).to_mrz(),
            "ZIZEK"
        );
        assert_eq!(
            NativeMrzText("\u{0141}\u{00f3}d\u{017a}".to_owned()).to_mrz(),
            "LODZ"
        );
    }

    #[test]
    fn transliterate_replaces_spaces_with_filler() {
        assert_eq!(
            NativeMrzText("VAN DER BERG".to_owned()).to_mrz(),
            "VAN<DER<BERG"
        );
    }

    #[test]
    fn transliterate_drops_apostrophe() {
        assert_eq!(NativeMrzText("O'Brien".to_owned()).to_mrz(), "OBRIEN");
    }

    #[test]
    fn transliterate_surname_round_trips_native_to_mrz() {
        let s = Surname::new("T\u{00f6}rm\u{00e4}nen".to_owned())
            .expect("surname with umlauts is valid");
        let mrz = transliterate_surname(&s);
        assert_eq!(mrz.as_str(), "TOERMAENEN");
    }

    #[test]
    fn transliterate_given_names_joins_with_filler() {
        let first =
            FirstName::new("P\u{00e4}ivi".to_owned()).expect("first name with a-umlaut is valid");
        let second = SecondName::new("Maria".to_owned()).expect("second name Maria is valid");
        let mrz = transliterate_given_names(Some(&first), Some(&second), &[])
            .expect("two given names transliterate");
        assert_eq!(mrz.as_str(), "PAEIVI<MARIA");
    }

    #[test]
    fn transliterate_given_names_handles_additional_slots() {
        let first = FirstName::new("Anna".to_owned()).expect("first name Anna is valid");
        let second = SecondName::new("Maria".to_owned()).expect("second name Maria is valid");
        let third =
            AdditionalName::new("Helena".to_owned()).expect("additional name Helena is valid");
        let mrz = transliterate_given_names(Some(&first), Some(&second), &[third])
            .expect("three given names transliterate");
        assert_eq!(mrz.as_str(), "ANNA<MARIA<HELENA");
    }

    #[test]
    fn transliterate_given_names_none_when_empty() {
        assert!(transliterate_given_names(None, None, &[]).is_none());
    }

    // ----- EmrtdConsistency cross-correlation -----

    fn empty_inputs() -> EmrtdConsistencyInputs<'static> {
        EmrtdConsistencyInputs {
            cert_surname: None,
            cert_first: None,
            cert_second: None,
            cert_additional: &[],
            dg11_full_name: None,
            dg11_dob: None,
            mrz_primary: None,
            mrz_secondary: None,
            mrz_dob: None,
        }
    }

    #[test]
    fn emrtd_consistency_ok_across_all_three_sources() -> Result<(), Box<dyn core::error::Error>> {
        let surname = Surname::new("M\u{00e4}kinen".to_owned())?;
        let first = FirstName::new("Yrj\u{00f6}".to_owned())?;
        let second = SecondName::new("Antero".to_owned())?;
        let dg11 = Dg11FullName::new("M\u{00e4}kinen<<Yrj\u{00f6}<Antero".to_owned())?;
        let dg11_dob = DateOfBirth::from_calendar(1974, 8, 12)?;
        let mrz_p = MrzSurname::new("MAEKINEN<<<<<<<".to_owned())?;
        let mrz_s = MrzGivenName::new("YRJOE<ANTERO<<<".to_owned())?;
        let mrz_dob = MrzDate::from_mrz_yymmdd(*b"740812")?;

        let report = verify_emrtd_consistency(EmrtdConsistencyInputs {
            cert_surname: Some(&surname),
            cert_first: Some(&first),
            cert_second: Some(&second),
            cert_additional: &[],
            dg11_full_name: Some(&dg11),
            dg11_dob: Some(&dg11_dob),
            mrz_primary: Some(&mrz_p),
            mrz_secondary: Some(&mrz_s),
            mrz_dob: Some(&mrz_dob),
        });
        assert_eq!(report.cert_matches_dg11_surname, Some(true));
        assert_eq!(report.cert_matches_dg11_given, Some(true));
        assert_eq!(report.cert_transliterates_to_mrz_surname, Some(true));
        assert_eq!(report.cert_transliterates_to_mrz_given, Some(true));
        assert_eq!(report.mrz_dob_matches_dg11_dob, Some(true));
        Ok(())
    }

    #[test]
    fn emrtd_consistency_flags_dg11_surname_mismatch() {
        let surname =
            Surname::new("M\u{00e4}kinen".to_owned()).expect("surname with a-umlaut is valid");
        let first =
            FirstName::new("Yrj\u{00f6}".to_owned()).expect("first name with o-umlaut is valid");
        let dg11 = Dg11FullName::new("Virtanen<<Yrj\u{00f6}".to_owned())
            .expect("mismatching DG11 full name parses");
        let report = verify_emrtd_consistency(EmrtdConsistencyInputs {
            cert_surname: Some(&surname),
            cert_first: Some(&first),
            dg11_full_name: Some(&dg11),
            ..empty_inputs()
        });
        assert_eq!(report.cert_matches_dg11_surname, Some(false));
        assert_eq!(report.cert_matches_dg11_given, Some(true));
        assert!(report.cert_transliterates_to_mrz_surname.is_none());
        assert!(report.mrz_dob_matches_dg11_dob.is_none());
    }

    #[test]
    fn emrtd_consistency_flags_mrz_transliteration_mismatch() {
        let surname =
            Surname::new("M\u{00e4}kinen".to_owned()).expect("surname with a-umlaut is valid");
        let mrz_p =
            MrzSurname::new("MAKINEN".to_owned()).expect("non-transliterated MRZ surname parses");
        let report = verify_emrtd_consistency(EmrtdConsistencyInputs {
            cert_surname: Some(&surname),
            mrz_primary: Some(&mrz_p),
            ..empty_inputs()
        });
        assert_eq!(report.cert_transliterates_to_mrz_surname, Some(false));
    }

    #[test]
    fn emrtd_consistency_flags_dob_mismatch() -> Result<(), crate::iso8601::Iso8601Error> {
        let dg11_dob = DateOfBirth::from_calendar(1974, 8, 12)?;
        let mrz_dob = MrzDate::from_mrz_yymmdd(*b"750812")?;
        let report = verify_emrtd_consistency(EmrtdConsistencyInputs {
            dg11_dob: Some(&dg11_dob),
            mrz_dob: Some(&mrz_dob),
            ..empty_inputs()
        });
        assert_eq!(report.mrz_dob_matches_dg11_dob, Some(false));
        Ok(())
    }

    #[test]
    fn emrtd_consistency_none_when_sources_absent() {
        let report = verify_emrtd_consistency(empty_inputs());
        assert!(report.cert_matches_dg11_surname.is_none());
        assert!(report.cert_matches_dg11_given.is_none());
        assert!(report.cert_transliterates_to_mrz_surname.is_none());
        assert!(report.cert_transliterates_to_mrz_given.is_none());
        assert!(report.mrz_dob_matches_dg11_dob.is_none());
    }

    #[test]
    fn emrtd_consistency_handles_three_given_names() {
        let surname = Surname::new("Korhonen".to_owned()).expect("surname Korhonen is valid");
        let first = FirstName::new("Anna".to_owned()).expect("first name Anna is valid");
        let second = SecondName::new("Maria".to_owned()).expect("second name Maria is valid");
        let helena =
            AdditionalName::new("Helena".to_owned()).expect("additional name Helena is valid");
        let dg11 = Dg11FullName::new("Korhonen<<Anna<Maria<Helena".to_owned())
            .expect("DG11 full name with three given names parses");
        let report = verify_emrtd_consistency(EmrtdConsistencyInputs {
            cert_surname: Some(&surname),
            cert_first: Some(&first),
            cert_second: Some(&second),
            cert_additional: core::slice::from_ref(&helena),
            dg11_full_name: Some(&dg11),
            ..empty_inputs()
        });
        assert_eq!(report.cert_matches_dg11_surname, Some(true));
        assert_eq!(report.cert_matches_dg11_given, Some(true));
    }

    #[test]
    fn native_name_title_cases_single_segment() -> Result<(), FreeTextError> {
        let n = NativeName::from_legacy_uppercase(SAMPLE_FIRST)?;
        assert_eq!(n.as_str(), "Vilma");
        Ok(())
    }

    #[test]
    fn native_name_title_cases_hyphenated_segments_independently() -> Result<(), FreeTextError> {
        let n = NativeName::from_legacy_uppercase(SAMPLE_SURNAME)?;
        assert_eq!(n.as_str(), "Specimen-Travel");
        Ok(())
    }

    #[test]
    fn native_name_title_cases_whitespace_segments_independently() -> Result<(), FreeTextError> {
        let n = NativeName::from_legacy_uppercase(SAMPLE_GIVEN)?;
        assert_eq!(n.as_str(), "Vilma Sofia");
        Ok(())
    }

    #[test]
    fn native_name_preserves_unicode_diacritics() -> Result<(), FreeTextError> {
        // Made-up uppercase word with Finnish/Estonian diacritics --
        // not a person's name, just exercising the case-mapping path.
        let n = NativeName::from_legacy_uppercase("S\u{00c4}\u{00c4}TILA")?;
        assert_eq!(n.as_str(), "S\u{00e4}\u{00e4}tila");
        Ok(())
    }

    #[test]
    fn native_name_already_titlecased_round_trips() -> Result<(), FreeTextError> {
        // DG11's already-native form should survive the heuristic
        // unchanged when it happens to be applied to it.
        let n = NativeName::from_legacy_uppercase("Vilma")?;
        assert_eq!(n.as_str(), "Vilma");
        Ok(())
    }

    #[test]
    fn native_name_rejects_empty() {
        let err = NativeName::from_legacy_uppercase("").expect_err("empty native name rejected");
        assert!(matches!(err, FreeTextError::Empty));
    }

    #[test]
    fn surname_to_native_renders_titlecase() -> Result<(), FreeTextError> {
        let s = Surname::new(SAMPLE_SURNAME.to_owned())?;
        assert_eq!(s.to_native().as_str(), "Specimen-Travel");
        Ok(())
    }

    #[test]
    fn first_name_to_native_renders_titlecase() -> Result<(), FreeTextError> {
        let f = FirstName::new(SAMPLE_FIRST.to_owned())?;
        assert_eq!(f.to_native().as_str(), "Vilma");
        Ok(())
    }

    #[test]
    fn second_name_to_native_renders_titlecase() -> Result<(), FreeTextError> {
        let f = SecondName::new(SAMPLE_SECOND.to_owned())?;
        assert_eq!(f.to_native().as_str(), "Sofia");
        Ok(())
    }
}
