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

//! Typed digest values.
//!
//! Fingerprint newtypes that carry the algorithm in their name. The
//! benefit isn't confidentiality (these are public values); it's
//! *traceability* and a *typing invariant* `digest::Output<D>` cannot
//! give -- see `doc/typing-discipline.md` -> "Refining an ecosystem
//! base type". Concretely, all three of:
//!
//! - **Nominal identity.** `Output<D>` is keyed by output *size*:
//!   `Output<Sha256>` and `Output<Sha3_256>` are both `Array<u8, U32>`,
//!   so the compiler can't stop a 32-byte SHA3 digest landing where a
//!   SHA-256 pin is expected. `Sha256` is a distinct nominal type, and
//!   raw `[u8; 32]` cannot become one implicitly (no `From`; only the
//!   explicit `from_bytes`). The `compile_fail` doc-test below proves
//!   it.
//! - **By-construction hex `Display`.** Logs, reports, and the
//!   `card.*.signer.fingerprint` field all render lowercase hex without
//!   a per-site `hex::encode`. `Output<D>` has no such `Display`.
//! - **`const` pin tables.** `trust_roots.rs` builds `const`
//!   pinned-root / CSCA / ICAO fingerprint tables via `from_bytes`;
//!   `Array` / `GenericArray` isn't const-constructible from a literal
//!   array there.
//!
//! The bytes themselves are *not* hand-rolled: [`Sha256::of`] /
//! [`Sha384::of`] delegate to `RustCrypto` `sha2`, whose one-shot
//! `digest()` returns the ecosystem `Output<D>` we copy in. The
//! wrapper adds only the name, the rendering, and the const table --
//! never a hash implementation. Both types come from a single
//! `digest_newtype!` definition so the shared surface can't drift.
//!
//! See [`doc/typing-discipline.md`][doc] for the project's position on
//! newtyping at trust boundaries. Cert fingerprints drive pin matching
//! -- one of the highest-impact boundaries in refineid.
//!
//! [doc]: ../../../../../doc/typing-discipline.md

use core::fmt;

/// Define a fixed-length fingerprint newtype over a `sha2` hasher.
///
/// One definition for both [`Sha256`] and [`Sha384`]: the wrapper
/// (nominal type, hex `Display`, `const` `from_bytes` for pin tables)
/// is generated, while `of()` delegates to the `RustCrypto` `$hasher`
/// (its one-shot `digest()` yields the ecosystem `Output<$hasher>`,
/// which we copy into the `[u8; $len]` backing store). `$len` MUST
/// equal the hasher's output size; the `copy_from_slice` in `of()`
/// panics at first use otherwise, so a wrong constant cannot ship
/// silently.
macro_rules! digest_newtype {
    ($(#[$meta:meta])* $name:ident, $hasher:ty, $len:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Compute the digest of `input` via `RustCrypto` `sha2`.
            #[inline]
            #[must_use]
            pub fn of<B: AsRef<[u8]>>(input: B) -> Self {
                use sha2::Digest as _;
                // One-shot digest -> ecosystem `Output<$hasher>`.
                let out = <$hasher>::digest(input);
                let mut buf = [0_u8; $len];
                buf.copy_from_slice(&out);
                Self(buf)
            }

            /// Wrap an existing digest. Used by the `const` pinned-trust
            /// tables (and test fixtures) where the bytes are known at
            /// compile time and weren't produced by a live hash call.
            #[inline]
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// The raw digest bytes.
            #[inline]
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl fmt::Display for $name {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for b in &self.0 {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
        }

        impl fmt::Debug for $name {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({self})", stringify!($name))
            }
        }
    };
}

digest_newtype! {
    /// A SHA-1 digest. Always 20 bytes; `Display` is lowercase hex.
    Sha1, sha1::Sha1, 20
}

digest_newtype! {
    /// A SHA-256 digest. Always 32 bytes; `Display` is lowercase hex.
    ///
    /// Nominal, not size-keyed: raw bytes cannot become a `Sha256`
    /// implicitly --
    ///
    /// ```compile_fail
    /// use refineid_lib_core::crypto::digest::Sha256;
    /// // `Array<u8, U32>` (= digest::Output<Sha256>) has From<[u8; 32]>;
    /// // `Sha256` deliberately does not, so this does not compile.
    /// let _fp: Sha256 = [0_u8; 32];
    /// ```
    Sha256, sha2::Sha256, 32
}

digest_newtype! {
    /// A SHA-224 digest. Always 28 bytes; `Display` is lowercase hex.
    ///
    /// Some trust-service profiles accept SHA-224 alongside SHA-256 for
    /// ECDSA client-auth shapes. This type keeps that digest distinct
    /// from the 32-byte SHA-256 and 48-byte SHA-384 paths.
    Sha224, sha2::Sha224, 28
}

digest_newtype! {
    /// A SHA-384 digest. Always 48 bytes; `Display` is lowercase hex.
    ///
    /// FINEID Newer-scheme (S4-1 v4.2 sec.4.2 ECC P-384) signing pairs
    /// the auth and qualified-signature keys with SHA-384. This type
    /// carries the digest at the trust boundary between
    /// `refineid-client` (computes it via `sha2`) and the on-card
    /// PSO: HASH external-hash data object (S1 v4.2 sec.3.7.2.3).
    Sha384, sha2::Sha384, 48
}

digest_newtype! {
    /// A SHA-512 digest. Always 64 bytes; `Display` is lowercase hex.
    Sha512, sha2::Sha512, 64
}

#[cfg(test)]
mod tests {
    use super::{Sha1, Sha224, Sha256, Sha384, Sha512};

    #[test]
    fn known_vector_empty_input() {
        // SHA-256("") = e3b0c442 98fc1c14 9afbf4c8 996fb924
        //               27ae41e4 649b934c a495991b 7852b855
        let s = Sha256::of(b"");
        assert_eq!(
            format!("{s}"),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha1_known_vector_abc() {
        // SHA-1("abc") per FIPS 180-4 example.
        let s = Sha1::of(b"abc");
        assert_eq!(format!("{s}"), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn known_vector_abc() {
        // SHA-256("abc") = ba7816bf 8f01cfea 414140de 5dae2223
        //                  b00361a3 96177a9c b410ff61 f20015ad
        let s = Sha256::of(b"abc");
        assert_eq!(
            format!("{s}"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha384_known_vector_abc() {
        // SHA-384("abc") per FIPS 180-4 example.
        let s = Sha384::of(b"abc");
        assert_eq!(
            format!("{s}"),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[test]
    fn sha512_known_vector_abc() {
        // SHA-512("abc") per FIPS 180-4 example.
        let s = Sha512::of(b"abc");
        assert_eq!(
            format!("{s}"),
            "ddaf35a193617abacc417349ae204131\
             12e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd\
             454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn sha224_known_vector_abc() {
        // SHA-224("abc") per FIPS 180-4 example.
        let s = Sha224::of(b"abc");
        assert_eq!(
            format!("{s}"),
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        );
    }

    #[test]
    fn from_bytes_round_trip() {
        let bytes = [0_u8; 32];
        let s = Sha256::from_bytes(bytes);
        assert_eq!(s.as_bytes(), &bytes);
    }

    #[test]
    fn equality_works() {
        assert_eq!(Sha256::of(b"x"), Sha256::of(b"x"));
        assert_ne!(Sha256::of(b"x"), Sha256::of(b"y"));
    }

    #[test]
    fn display_is_64_lowercase_hex_chars() {
        let s = Sha256::of(b"anything");
        let r = format!("{s}");
        assert_eq!(r.len(), 64);
        assert!(
            r.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn debug_names_the_algorithm() {
        let s = Sha256::from_bytes([0_u8; 32]);
        assert!(format!("{s:?}").starts_with("Sha256("));
    }
}
