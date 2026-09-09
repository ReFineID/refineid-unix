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

//! Minimal LDIF v1 parser, sufficient for ICAO PKD downloads.
//!
//! LDIF (RFC 2849) is the standard distribution format for the
//! ICAO Public Key Directory. Each subtree of the PKD ships as
//! one LDIF file:
//!
//! - 001 -- DSC certificates
//! - 002 -- per-state Master Lists
//! - 003 -- CRLs
//! - 004 -- deviation lists
//! - 005 -- defect lists
//!
//! For now this module exists to support 002 (and indirectly any
//! other subtree that wraps DER blobs in
//! `<attr>;binary::<base64>` attributes). The parser is record-
//! oriented and stays well below the full RFC -- it handles line
//! folding, comments, blank-line separators, `version:`
//! preamble, `:` text values, and `::` base64 values. It does
//! **not** implement `:< url` value references, change records
//! (`changetype:`), or modifications.
//!
//! Record-level helpers (`LdifRecord::has_object_class`,
//! `LdifRecord::binary_values`) are case-insensitive on
//! attribute and object-class names, matching LDIF conventions.

use core::fmt;

/// One LDIF record (a DN plus its attributes).
#[derive(Debug, Clone)]
pub struct LdifRecord {
    /// Attribute name (lowercased, options like `;binary`
    /// stripped) paired with the decoded value.
    attrs: Vec<(String, AttrValue)>,
}

/// One attribute value in an [`LdifRecord`].
#[derive(Debug, Clone)]
pub enum AttrValue {
    /// Plain UTF-8 text value (LDIF `:` separator).
    Text(String),
    /// Raw bytes (LDIF `::` base64-encoded separator).
    Binary(Vec<u8>),
}

impl LdifRecord {
    /// Return every value of `name` (case-insensitive lookup).
    /// Attribute options (`;binary`, `;lang-XX`) are ignored
    /// for matching purposes -- the binary-ness shows up in
    /// the returned [`AttrValue`] variant.
    pub(crate) fn values(&self, name: &str) -> impl Iterator<Item = &AttrValue> {
        let needle = name.to_ascii_lowercase();
        self.attrs
            .iter()
            .filter_map(move |(k, v)| (*k == needle).then_some(v))
    }

    /// Return every binary value of `name`. Convenience over
    /// [`Self::values`] for callers that already know the
    /// attribute is a `;binary::base64` shape.
    pub(crate) fn binary_values(&self, name: &str) -> impl Iterator<Item = &[u8]> {
        self.values(name).filter_map(|v| match v {
            AttrValue::Binary(b) => Some(b.as_slice()),
            AttrValue::Text(_) => None,
        })
    }

    /// `true` if this record carries `objectclass: class`
    /// (case-insensitive on both the attribute name and the
    /// class value).
    #[must_use]
    pub(crate) fn has_object_class(&self, class: &str) -> bool {
        let needle = class.to_ascii_lowercase();
        self.values("objectclass").any(|v| match v {
            AttrValue::Text(s) => s.eq_ignore_ascii_case(&needle),
            AttrValue::Binary(_) => false,
        })
    }
}

/// Error returned by the LDIF parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdifError {
    /// `attribute: value` separator missing on a non-empty line.
    MissingColon {
        /// 1-based line number where the parse failed.
        line_number: usize,
    },
    /// Base64 decode failure on a `::` value.
    BadBase64 {
        /// 1-based line number of the offending value.
        line_number: usize,
    },
    /// Continuation line (` <text>`) before any attribute line.
    OrphanContinuation {
        /// 1-based line number of the orphan continuation.
        line_number: usize,
    },
    /// Input wasn't valid UTF-8.
    NotUtf8,
}

impl fmt::Display for LdifError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingColon { line_number } => {
                write!(f, "LDIF line {line_number}: missing `:` separator")
            }
            Self::BadBase64 { line_number } => {
                write!(f, "LDIF line {line_number}: base64 decode failed")
            }
            Self::OrphanContinuation { line_number } => write!(
                f,
                "LDIF line {line_number}: continuation line before any attribute"
            ),
            Self::NotUtf8 => write!(f, "LDIF input is not valid UTF-8"),
        }
    }
}

impl core::error::Error for LdifError {}

/// Parse LDIF text into records. The input must be UTF-8;
/// callers reading from disk should `str::from_utf8` first and
/// surface the `NotUtf8` variant via [`parse_bytes`] for
/// convenience.
///
/// # Errors
/// Any [`LdifError`] variant.
#[inline]
pub fn parse<S: AsRef<str>>(input: S) -> Result<Vec<LdifRecord>, LdifError> {
    let text = input.as_ref();
    // Phase 1: unfold continuation lines into logical lines.
    // Per RFC 2849 a continuation line begins with a single
    // SPACE (or TAB) and is concatenated to the prior line
    // after removing that one leading byte.
    let mut logical: Vec<(usize, String)> = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        // Lines in any plausible LDIF file fit far below usize::MAX;
        // `idx + 1` cannot overflow in practice.
        let line_number = idx.saturating_add(1);
        if let Some(rest) = raw.strip_prefix(' ').or_else(|| raw.strip_prefix('\t')) {
            let Some((_, last)) = logical.last_mut() else {
                return Err(LdifError::OrphanContinuation { line_number });
            };
            last.push_str(rest);
        } else {
            logical.push((line_number, raw.to_owned()));
        }
    }

    // Phase 2: group logical lines into records, separated by
    // blank lines. Skip comments (`#`) and the optional
    // `version:` preamble.
    let mut records: Vec<LdifRecord> = Vec::new();
    let mut current: Vec<(String, AttrValue)> = Vec::new();
    for (line_number, line) in &logical {
        if line.is_empty() {
            if !current.is_empty() {
                records.push(LdifRecord {
                    attrs: core::mem::take(&mut current),
                });
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        if let Some(_rest) = line.strip_prefix("version:") {
            // Spec allows `version: 1` only as the first non-
            // comment line; we accept it anywhere and ignore.
            continue;
        }
        let (name_with_opts, value) = LdifHelpers::parse_attribute_line(line, *line_number)?;
        let canonical_name = LdifHelpers::canonical_attribute_name(&name_with_opts);
        current.push((canonical_name, value));
    }
    if !current.is_empty() {
        records.push(LdifRecord { attrs: current });
    }
    Ok(records)
}

/// Parse from raw bytes, surfacing `NotUtf8` if the input isn't
/// valid UTF-8.
///
/// # Errors
/// Any [`LdifError`] variant, including [`LdifError::NotUtf8`]
/// when the input bytes don't decode as UTF-8.
#[inline]
pub fn parse_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Vec<LdifRecord>, LdifError> {
    let text = core::str::from_utf8(bytes.as_ref()).map_err(|_utf8_err| LdifError::NotUtf8)?;
    parse(text)
}

/// Helpers hosted on a unit struct (typing-discipline: no
/// free fns with borrowed parameters; see
/// `doc/typing-discipline.md`).
struct LdifHelpers;

impl LdifHelpers {
    /// Split one logical line into `(attribute_name_with_options,
    /// value)`. The separator is `:` (text) or `::` (base64).
    fn parse_attribute_line(
        line: &str,
        line_number: usize,
    ) -> Result<(String, AttrValue), LdifError> {
        let colon = line
            .find(':')
            .ok_or(LdifError::MissingColon { line_number })?;
        // `colon` is the byte offset of an ASCII `:`; both
        // `..colon` and `colon + 1..` land on UTF-8 boundaries.
        // The `+ 1` cannot overflow because `colon < line.len() <= usize::MAX`.
        let name = line
            .get(..colon)
            .ok_or(LdifError::MissingColon { line_number })?;
        let rest_start = colon.saturating_add(1);
        let rest = line
            .get(rest_start..)
            .ok_or(LdifError::MissingColon { line_number })?;
        if let Some(b64) = rest.strip_prefix(':') {
            let trimmed: String = b64.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            let decoded =
                Self::base64_decode_strict(&trimmed).ok_or(LdifError::BadBase64 { line_number })?;
            Ok((name.to_owned(), AttrValue::Binary(decoded)))
        } else {
            let value = rest.trim_start_matches(' ').to_owned();
            Ok((name.to_owned(), AttrValue::Text(value)))
        }
    }

    /// Lowercase the attribute name and strip `;option` suffixes
    /// like `;binary` or `;lang-fi` so callers can match on the
    /// canonical attribute name regardless of options applied to
    /// a given encoding.
    fn canonical_attribute_name(name_with_opts: &str) -> String {
        let head = name_with_opts.split(';').next().unwrap_or("");
        head.to_ascii_lowercase()
    }
}

/// One sextet (0..=63) decoded from a base64 alphabet byte, or
/// `None` for any non-alphabet character.
const fn base64_sextet(c: u8) -> Option<u8> {
    // Each arm's pattern guard guarantees `c` is at least the
    // base byte (`b'A'`, `b'a'`, `b'0'`), so the subtraction
    // can't underflow. The additions to 26 / 52 stay within
    // 0..=63 by the upper match bound.
    match c {
        b'A'..=b'Z' => Some(c.wrapping_sub(b'A')),
        b'a'..=b'z' => Some(c.wrapping_sub(b'a').wrapping_add(26)),
        b'0'..=b'9' => Some(c.wrapping_sub(b'0').wrapping_add(52)),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

impl LdifHelpers {
    /// Standard-alphabet base64 decoder with padding. Mirrors
    /// the behaviour of the small decoder in the client crate's
    /// `text.rs`, kept module-local here so `lib-core` doesn't
    /// grow a dependency on `text.rs`.
    fn base64_decode_strict(s: &str) -> Option<Vec<u8>> {
        if !s.len().is_multiple_of(4) {
            return None;
        }
        let bytes = s.as_bytes();
        // Output capacity hint: each 4 chars -> at most 3 bytes.
        // `len/4*3` rewritten via `div_euclid` (exact -- the
        // multiple-of-4 check above) and `saturating_mul` (the
        // multiplication can't overflow a usize whose value is
        // already smaller).
        let chunks_count = s.len().div_euclid(4);
        let cap = chunks_count.saturating_mul(3);
        let mut out = Vec::with_capacity(cap);
        for chunk in bytes.chunks(4) {
            let pad = chunk.iter().rev().take_while(|&&b| b == b'=').count();
            if pad > 2 {
                return None;
            }
            // `pad` is 0..=2; `4 - pad` is 2..=4. Use saturating_sub
            // so the lint sees no naked arithmetic; the value is
            // exact given the guard above.
            let data_len = 4_usize.saturating_sub(pad);
            let mut v = [0_u8; 4];
            for (i, &c) in chunk.iter().enumerate() {
                // Position-safe index into the 4-byte `v`. `i` comes
                // from `.iter().enumerate()` on a slice of length at
                // most 4, so `.get_mut(i)` is the same as the bare
                // index, expressed in a form the lint accepts.
                let slot = v.get_mut(i)?;
                if c == b'=' {
                    if i < data_len {
                        return None;
                    }
                    *slot = 0;
                } else {
                    *slot = base64_sextet(c)?;
                }
            }
            // Pack the four sextets into a 24-bit value and slice
            // it into three bytes. `to_be_bytes()[1..]` gives the
            // low 24 bits as a 3-byte big-endian slice -- the
            // shift-and-mask form below picks the same bytes
            // without any `as u8` truncation.
            let triple = (u32::from(*v.first()?) << 18_u32)
                | (u32::from(*v.get(1)?) << 12_u32)
                | (u32::from(*v.get(2)?) << 6_u32)
                | u32::from(*v.get(3)?);
            let be = triple.to_be_bytes();
            // be = [0x00, byte0, byte1, byte2] -- the high byte is
            // always 0 because `triple < 1 << 24`.
            out.push(*be.get(1)?);
            if pad < 2 {
                out.push(*be.get(2)?);
            }
            if pad < 1 {
                out.push(*be.get(3)?);
            }
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {

    use super::{AttrValue, parse};

    #[test]
    fn parses_minimal_record() {
        let text = "version: 1\n\ndn: cn=x\ncn: x\nobjectclass: top\n\n";
        let records = parse(text).expect("parse");
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert!(r.has_object_class("top"));
        assert!(r.has_object_class("TOP"));
        let cn: Vec<&AttrValue> = r.values("cn").collect();
        assert_eq!(cn.len(), 1);
        match cn[0] {
            AttrValue::Text(s) => assert_eq!(s, "x"),
            AttrValue::Binary(_) => panic!("expected text"),
        }
    }

    #[test]
    fn handles_line_folding() {
        let text = "dn: cn=x\ndescription: hello\n  world\n\n";
        let records = parse(text).expect("parse");
        let r = &records[0];
        let desc: Vec<&AttrValue> = r.values("description").collect();
        match desc[0] {
            AttrValue::Text(s) => assert_eq!(s, "hello world"),
            AttrValue::Binary(_) => panic!("expected text"),
        }
    }

    #[test]
    fn decodes_base64_attribute() {
        // "hello" base64 = "aGVsbG8="
        let text = "dn: cn=x\npayload;binary:: aGVsbG8=\n\n";
        let records = parse(text).expect("parse");
        let r = &records[0];
        let v: Vec<&[u8]> = r.binary_values("payload").collect();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0], b"hello");
    }

    #[test]
    fn separates_records_on_blank_line() {
        let text = "dn: cn=a\ncn: a\n\ndn: cn=b\ncn: b\n\n";
        let records = parse(text).expect("parse");
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn skips_comments() {
        let text = "# a comment\ndn: cn=x\ncn: x\n\n";
        let records = parse(text).expect("parse");
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn case_insensitive_lookup() {
        let text = "dn: cn=x\nObjectClass: pkdMasterList\nObjectClass: top\n\n";
        let records = parse(text).expect("parse");
        let r = &records[0];
        assert!(r.has_object_class("pkdmasterlist"));
        assert!(r.has_object_class("TOP"));
        assert!(!r.has_object_class("other"));
    }
}
