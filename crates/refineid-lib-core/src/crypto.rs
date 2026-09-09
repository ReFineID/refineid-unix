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

//! Cryptographic primitives the protocol layer needs but the
//! `RustCrypto` stack does not currently ship as a single
//! integrated piece.
//!
//! - [`brainpool_p384`] -- `BrainpoolP384r1` over `crypto-bigint`.
//!   Not in `RustCrypto/elliptic-curves` at our toolchain version.
//! - [`rsa`] -- PKCS#1 v1.5 SHA-256 signature verification.
//!   Verify-only; no key generation or signing here. Used by
//!   the cert chain / CRL / OCSP signature checks.
//! - [`symmetric`] -- AES-256 CBC / ECB + AES-256-CMAC + the ICAO
//!   Doc 9303 Part 11 KDF. Combines the `aes`, `cbc`, `cmac`, and
//!   `sha2` crates into the small surface PACE and secure
//!   messaging actually use.

pub mod brainpool_p384;
pub mod container;
pub mod digest;
pub mod ecdsa;
pub mod rsa;
pub mod symmetric;
