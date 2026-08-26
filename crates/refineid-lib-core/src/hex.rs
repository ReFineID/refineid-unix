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

//! Hex encode helpers.
//!
//! Tiny in-tree implementation; no runtime crate dep. Used
//! where bytes need to be printed for operator-facing output
//! (serial numbers, fingerprints, raw error context).

/// Hex encode/decode namespace.
///
/// All entry points are associated functions on this unit
/// struct so callers read as `Hex::encode(bytes)`. The unit
/// struct exists only to host the methods inside an `impl`
/// block (typing-discipline: no free fns with borrowed
/// parameters; see `doc/typing-discipline.md`).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Hex;

impl Hex {
    /// Encode bytes as lowercase ASCII hex with no separator.
    ///
    /// Output capacity uses `saturating_mul` -- on a hypothetical
    /// `usize::MAX/2`-byte input the capacity hint saturates
    /// rather than overflowing; the actual `write!` calls grow
    /// the buffer as needed.
    #[inline]
    #[must_use]
    pub fn encode(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        let mut out = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            // write! to String is infallible.
            if write!(out, "{byte:02x}").is_err() {
                break;
            }
        }
        out
    }

    /// Decode one ASCII hex digit at const-eval time.
    ///
    /// Panics (= compile error in const context) on anything that
    /// is not `0-9A-Fa-f`.
    #[expect(
        clippy::arithmetic_side_effects,
        clippy::panic,
        reason = "the panic IS the validation: every caller is a const item, so a \
                  non-hex digit or out-of-range subtraction fails the build instead \
                  of ever reaching a citizen; match arms bound each subtraction"
    )]
    const fn nibble(digit: u8) -> u8 {
        match digit {
            b'0'..=b'9' => digit - b'0',
            b'A'..=b'F' => digit - b'A' + 10,
            b'a'..=b'f' => digit - b'a' + 10,
            _ => panic!("hex constant contains a non-hex digit"),
        }
    }

    /// Decode a hex string literal into a fixed-size byte array at
    /// const-eval time.
    ///
    /// This is the "parse, don't validate" form for spec constants
    /// (FIPS 186-4 curve parameters, NIST KAT vectors): a mistyped
    /// digit or a length mismatch fails compilation, so no runtime
    /// path ever sees a malformed constant.
    #[expect(
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "const-eval hex decode: the length assert above the loop bounds every \
                  index and product, and every caller is a const item, so any slip is \
                  a compile error rather than a runtime panic"
    )]
    pub(crate) const fn decode_const<const N: usize>(hex_digits: &str) -> [u8; N] {
        let src = hex_digits.as_bytes();
        assert!(
            src.len() == 2 * N,
            "hex constant length does not match the declared byte width"
        );
        let mut out = [0_u8; N];
        let mut i = 0;
        while i < N {
            out[i] = (Self::nibble(src[2 * i]) << 4_u32) | Self::nibble(src[2 * i + 1]);
            i += 1;
        }
        out
    }
}
