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

//! Deterministic CBOR codec (RFC 8949 core deterministic subset).
//!
//! Provides canonical encoding and validation for RAPP messages and wire envelopes.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// Maximum nesting depth for containers.
pub const MAX_NESTING_DEPTH: usize = 8;
/// Maximum text length in bytes.
pub const MAX_TEXT_SIZE: usize = 4096;
/// Maximum frame plaintext length in bytes.
pub const MAX_FRAME_PLAINTEXT: usize = 65519;

/// Errors arising from wire decoding or encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// Input was truncated before a complete value could be read.
    Truncated,
    /// Trailing unparsed bytes remain after decoding a value.
    TrailingData,
    /// Maximum nesting depth exceeded.
    NestingTooDeep,
    /// Text string exceeds the maximum allowed size.
    TextTooLong {
        /// Actual text length received in bytes.
        got: usize,
    },
    /// Plaintext exceeds maximum frame plaintext size.
    OversizedPlaintext {
        /// Actual plaintext length received in bytes.
        got: usize,
    },
    /// Invalid UTF-8 text.
    InvalidUtf8,
    /// Decoded value does not match canonical re-encoding.
    NonCanonical,
    /// Forbidden CBOR type or tag encountered.
    ForbiddenCborType,
    /// Map key is not a text string.
    NonTextMapKey,
    /// Duplicate map key encountered.
    DuplicateMapKey,
    /// Integer overflow or invalid range.
    IntegerOverflow,
    /// Declared collection size exceeds remaining input bytes.
    CollectionTooLarge {
        /// Count of elements declared.
        got: usize,
    },
    /// Missing required field in envelope or map.
    MissingField {
        /// Name of the missing field.
        field: &'static str,
    },
    /// Wrong type for field.
    WrongType {
        /// Name of the field with incorrect type.
        field: &'static str,
    },
    /// Unknown or unrecognized field.
    UnknownField,
    /// Unsupported protocol wire version.
    UnsupportedVersion,
    /// Unknown envelope message type.
    UnknownMessageType,
    /// Invalid field length.
    WrongLength {
        /// Field name.
        field: &'static str,
        /// Expected byte length.
        expected: usize,
        /// Received byte length.
        got: usize,
    },
    /// Invalid enum discriminant or value.
    InvalidValue {
        /// Name of the field containing an invalid value.
        field: &'static str,
    },
    /// Critical extension named in header is missing from extensions map.
    CriticalExtensionMissing,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "wire truncated"),
            Self::TrailingData => write!(f, "trailing data after wire value"),
            Self::NestingTooDeep => write!(f, "nesting depth exceeded"),
            Self::TextTooLong { got } => write!(f, "text string too long: {got} bytes"),
            Self::OversizedPlaintext { got } => write!(f, "oversized plaintext: {got} bytes"),
            Self::InvalidUtf8 => write!(f, "invalid utf-8"),
            Self::NonCanonical => write!(f, "non-canonical deterministic cbor"),
            Self::ForbiddenCborType => write!(f, "forbidden cbor type"),
            Self::NonTextMapKey => write!(f, "map key is not text"),
            Self::DuplicateMapKey => write!(f, "duplicate map key"),
            Self::IntegerOverflow => write!(f, "integer overflow"),
            Self::CollectionTooLarge { got } => write!(f, "collection too large: {got}"),
            Self::MissingField { field } => write!(f, "missing field: {field}"),
            Self::WrongType { field } => write!(f, "wrong type for field: {field}"),
            Self::UnknownField => write!(f, "unknown field"),
            Self::UnsupportedVersion => write!(f, "unsupported wire version"),
            Self::UnknownMessageType => write!(f, "unknown message type"),
            Self::WrongLength {
                field,
                expected,
                got,
            } => write!(
                f,
                "wrong length for {field}: expected {expected}, got {got}"
            ),
            Self::InvalidValue { field } => write!(f, "invalid value for {field}"),
            Self::CriticalExtensionMissing => write!(f, "critical extension missing"),
        }
    }
}

impl core::error::Error for WireError {}

/// The restricted value space RAPP encodes, in RFC 8949 core deterministic form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireValue {
    /// Major type 0: Unsigned integer.
    Unsigned(u64),
    /// Major type 1: Negative integer.
    Negative(i64),
    /// Major type 2: Byte string.
    Bytes(Vec<u8>),
    /// Major type 3: UTF-8 text string.
    Text(String),
    /// Major type 4: Array of values.
    Array(Vec<Self>),
    /// Major type 5: Map of text keys to values.
    Map(BTreeMap<String, Self>),
    /// Major type 7: Boolean.
    Boolean(bool),
    /// Major type 7: Null.
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MajorType {
    Unsigned = 0,
    Negative = 1,
    Bytes = 2,
    Text = 3,
    Array = 4,
    Map = 5,
    Simple = 7,
}

const MAJOR_SHIFT: u8 = 5;
const ADD_INFO_MASK: u8 = 0x1F;

const ARG_ONE_BYTE: u8 = 24;
const ARG_TWO_BYTES: u8 = 25;
const ARG_FOUR_BYTES: u8 = 26;
const ARG_EIGHT_BYTES: u8 = 27;

const SIMPLE_FALSE: u8 = 20;
const SIMPLE_TRUE: u8 = 21;
const SIMPLE_NULL: u8 = 22;

fn encode_header(major: MajorType, value: u64, out: &mut Vec<u8>) {
    let prefix = (major as u8) << MAJOR_SHIFT;
    if value < 24 {
        out.push(prefix | (value as u8));
    } else if value <= 0xFF {
        out.push(prefix | ARG_ONE_BYTE);
        out.push(value as u8);
    } else if value <= 0xFFFF {
        out.push(prefix | ARG_TWO_BYTES);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= 0xFFFF_FFFF {
        out.push(prefix | ARG_FOUR_BYTES);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(prefix | ARG_EIGHT_BYTES);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

impl WireValue {
    /// Deterministically encode this value into bytes according to RFC 8949.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        self.encode_into(&mut out, 0)?;
        Ok(out)
    }

    fn encode_into(&self, out: &mut Vec<u8>, depth: usize) -> Result<(), WireError> {
        if depth > MAX_NESTING_DEPTH {
            return Err(WireError::NestingTooDeep);
        }
        match self {
            Self::Unsigned(val) => {
                encode_header(MajorType::Unsigned, *val, out);
            }
            Self::Negative(val) => {
                if *val >= 0 {
                    return Err(WireError::InvalidValue { field: "negative" });
                }
                let raw = (!*val) as u64;
                encode_header(MajorType::Negative, raw, out);
            }
            Self::Bytes(bytes) => {
                encode_header(MajorType::Bytes, bytes.len() as u64, out);
                out.extend_from_slice(bytes);
            }
            Self::Text(text) => {
                let bytes = text.as_bytes();
                if bytes.len() > MAX_TEXT_SIZE {
                    return Err(WireError::TextTooLong { got: bytes.len() });
                }
                encode_header(MajorType::Text, bytes.len() as u64, out);
                out.extend_from_slice(bytes);
            }
            Self::Array(items) => {
                encode_header(MajorType::Array, items.len() as u64, out);
                for item in items {
                    item.encode_into(out, depth + 1)?;
                }
            }
            Self::Map(entries) => {
                encode_header(MajorType::Map, entries.len() as u64, out);
                // RFC 8949 Canonical order: keys sorted by length first, then bytewise lexicographically
                let mut encoded_entries = Vec::with_capacity(entries.len());
                for (k, v) in entries {
                    let mut key_bytes = Vec::new();
                    Self::Text(k.clone()).encode_into(&mut key_bytes, depth + 1)?;
                    encoded_entries.push((key_bytes, v));
                }
                encoded_entries.sort_by(|(a_key, _), (b_key, _)| {
                    if a_key.len() == b_key.len() {
                        a_key.cmp(b_key)
                    } else {
                        a_key.len().cmp(&b_key.len())
                    }
                });
                for (k_bytes, v) in encoded_entries {
                    out.extend_from_slice(&k_bytes);
                    v.encode_into(out, depth + 1)?;
                }
            }
            Self::Boolean(b) => {
                let val = if *b { SIMPLE_TRUE } else { SIMPLE_FALSE };
                out.push(((MajorType::Simple as u8) << MAJOR_SHIFT) | val);
            }
            Self::Null => {
                out.push(((MajorType::Simple as u8) << MAJOR_SHIFT) | SIMPLE_NULL);
            }
        }
        Ok(())
    }
}

/// Decode and validate deterministic CBOR from bytes.
pub fn decode_deterministic_cbor(bytes: &[u8]) -> Result<WireValue, WireError> {
    if bytes.len() > MAX_FRAME_PLAINTEXT {
        return Err(WireError::OversizedPlaintext { got: bytes.len() });
    }
    let mut decoder = WireDecoder::new(bytes);
    let value = decoder.decode_value(0)?;
    if !decoder.is_at_end() {
        return Err(WireError::TrailingData);
    }
    // Canonicality verification: re-encode and match input exactly
    let re_encoded = value.encode()?;
    if re_encoded != bytes {
        return Err(WireError::NonCanonical);
    }
    Ok(value)
}

struct WireDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> WireDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_at_end(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn byte(&mut self) -> Result<u8, WireError> {
        if self.offset < self.bytes.len() {
            let b = self.bytes[self.offset];
            self.offset += 1;
            Ok(b)
        } else {
            Err(WireError::Truncated)
        }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], WireError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(WireError::IntegerOverflow)?;
        if end <= self.bytes.len() {
            let slice = &self.bytes[self.offset..end];
            self.offset = end;
            Ok(slice)
        } else {
            Err(WireError::Truncated)
        }
    }

    fn decode_argument(&mut self, add_info: u8) -> Result<u64, WireError> {
        match add_info {
            0..=23 => Ok(add_info as u64),
            ARG_ONE_BYTE => Ok(self.byte()? as u64),
            ARG_TWO_BYTES => {
                let bytes = self.take(2)?;
                Ok(u16::from_be_bytes([bytes[0], bytes[1]]) as u64)
            }
            ARG_FOUR_BYTES => {
                let bytes = self.take(4)?;
                Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64)
            }
            ARG_EIGHT_BYTES => {
                let bytes = self.take(8)?;
                Ok(u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]))
            }
            _ => Err(WireError::ForbiddenCborType),
        }
    }

    fn decode_value(&mut self, depth: usize) -> Result<WireValue, WireError> {
        if depth > MAX_NESTING_DEPTH {
            return Err(WireError::NestingTooDeep);
        }
        let initial = self.byte()?;
        let major = initial >> MAJOR_SHIFT;
        let add_info = initial & ADD_INFO_MASK;

        match major {
            0 => {
                let val = self.decode_argument(add_info)?;
                Ok(WireValue::Unsigned(val))
            }
            1 => {
                let raw = self.decode_argument(add_info)?;
                if raw > (i64::MAX as u64) {
                    return Err(WireError::IntegerOverflow);
                }
                let val = -1 - (raw as i64);
                Ok(WireValue::Negative(val))
            }
            2 => {
                let len = self.decode_argument(add_info)? as usize;
                let bytes = self.take(len)?.to_vec();
                Ok(WireValue::Bytes(bytes))
            }
            3 => {
                let len = self.decode_argument(add_info)? as usize;
                if len > MAX_TEXT_SIZE {
                    return Err(WireError::TextTooLong { got: len });
                }
                let bytes = self.take(len)?;
                let text = core::str::from_utf8(bytes).map_err(|_| WireError::InvalidUtf8)?;
                Ok(WireValue::Text(text.into()))
            }
            4 => {
                let count = self.decode_argument(add_info)? as usize;
                if count > self.bytes.len() - self.offset {
                    return Err(WireError::CollectionTooLarge { got: count });
                }
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(self.decode_value(depth + 1)?);
                }
                Ok(WireValue::Array(items))
            }
            5 => {
                let count = self.decode_argument(add_info)? as usize;
                if count * 2 > self.bytes.len() - self.offset {
                    return Err(WireError::CollectionTooLarge { got: count });
                }
                let mut map = BTreeMap::new();
                for _ in 0..count {
                    let key = match self.decode_value(depth + 1)? {
                        WireValue::Text(s) => s,
                        _ => return Err(WireError::NonTextMapKey),
                    };
                    let val = self.decode_value(depth + 1)?;
                    if map.insert(key, val).is_some() {
                        return Err(WireError::DuplicateMapKey);
                    }
                }
                Ok(WireValue::Map(map))
            }
            7 => match add_info {
                SIMPLE_FALSE => Ok(WireValue::Boolean(false)),
                SIMPLE_TRUE => Ok(WireValue::Boolean(true)),
                SIMPLE_NULL => Ok(WireValue::Null),
                _ => Err(WireError::ForbiddenCborType),
            },
            _ => Err(WireError::ForbiddenCborType),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_cbor_primitives() {
        assert_eq!(WireValue::Unsigned(0).encode().expect("ok"), [0x00]);
        assert_eq!(WireValue::Unsigned(23).encode().expect("ok"), [0x17]);
        assert_eq!(WireValue::Unsigned(24).encode().expect("ok"), [0x18, 0x18]);
        assert_eq!(WireValue::Unsigned(255).encode().expect("ok"), [0x18, 0xFF]);
        assert_eq!(
            WireValue::Unsigned(256).encode().expect("ok"),
            [0x19, 0x01, 0x00]
        );
        assert_eq!(WireValue::Negative(-1).encode().expect("ok"), [0x20]);
        assert_eq!(WireValue::Negative(-24).encode().expect("ok"), [0x37]);
        assert_eq!(WireValue::Negative(-25).encode().expect("ok"), [0x38, 0x18]);
        assert_eq!(WireValue::Boolean(true).encode().expect("ok"), [0xF5]);
        assert_eq!(WireValue::Boolean(false).encode().expect("ok"), [0xF4]);
        assert_eq!(WireValue::Null.encode().expect("ok"), [0xF6]);
        assert_eq!(
            WireValue::Text("RAPP".into()).encode().expect("ok"),
            [0x64, b'R', b'A', b'P', b'P']
        );
        assert_eq!(
            WireValue::Bytes(vec![0x00, 0x01, 0xFF])
                .encode()
                .expect("ok"),
            [0x43, 0x00, 0x01, 0xFF]
        );
    }

    #[test]
    fn round_trip_map_sorting() {
        let mut map = BTreeMap::new();
        map.insert("b".into(), WireValue::Unsigned(2));
        map.insert("a".into(), WireValue::Unsigned(1));
        map.insert("aa".into(), WireValue::Unsigned(3));
        let val = WireValue::Map(map);
        let encoded = val.encode().expect("ok");
        let decoded = decode_deterministic_cbor(&encoded).expect("ok");
        assert_eq!(val, decoded);
    }
}
