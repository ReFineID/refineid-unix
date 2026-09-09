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

//! Minimal read-only, sign-only PKCS#11 v2.40 module for FINEID.
//!
//! Purpose: let Firefox / NSS (and later OpenSSL's pkcs11-provider,
//! via p11-kit) do client-certificate TLS authentication with a
//! Finnish FINEID card on Fedora Linux. The module exposes the card's
//! authentication certificate and private key, takes PIN1 through
//! `C_Login`, and signs TLS `CertificateVerify` digests on the card.
//!
//! A thin C-ABI adapter over the shared card-edge protocol in
//! `refineid-lib-core`; it does not reimplement FINEID mechanics.
//!
//! Card access mode. This module opens the reader directly over
//! PC/SC for the moment it takes to read the certificate or run a
//! signature, then drops it -- it never holds the card open across
//! PKCS#11 calls, so the desktop CLI can share the reader.
//!
//! PIN1 secrecy (AGENTS.md hard rule #5). PIN1 lives only in a zeroizing
//! `refineid_lib_core::pin::PinBytes`, is never logged or rendered,
//! is verified on the card inside each signature (not cached on the
//! card), and is dropped on `C_Logout`, the last `C_CloseSession`,
//! card removal, and `C_Finalize`.
//!
//! Panics. The workspace builds with `panic = "abort"`, so a panic
//! aborts the host process rather than unwinding across the C ABI
//! (defined behaviour, never UB). The code is panic-free by
//! construction under the workspace clippy gate (no `unwrap` /
//! `expect` / indexing / unchecked arithmetic), so no `catch_unwind`
//! shim is needed in this minimal scope.

// This crate is unsafe FFI by construction: PKCS#11 is a C function
// table the caller (NSS / p11-kit) invokes through raw pointers.
// Workspace lints deny `unsafe_code` everywhere else; this cdylib
// is one of the few places that
// legitimately needs it. Every `unsafe` block stays explicit
// (`unsafe_op_in_unsafe_fn` denied below) with a `// SAFETY:` note.
#![expect(
    unsafe_code,
    reason = "PKCS#11 is a C ABI module -- extern \"C\" FFI over caller-provided pointers is the entire point"
)]
#![deny(unsafe_op_in_unsafe_fn)]
#![expect(
    clippy::missing_const_for_fn,
    reason = "the PKCS#11 dispatch surface is 60-plus `extern \"C\"` entry points, which cannot be `const fn` in edition 2024; const-promotion of the handful of pure helpers is a per-site judgment, not a workspace gate (see the note by this lint in the root Cargo.toml)"
)]

extern crate alloc;

mod api;
pub mod ck;
mod diag;
mod sign;
mod state;
mod token;

use crate::ck::{CkFunctionListPtrPtr, CkRv};

/// `C_GetFunctionList`: the sole symbol callers resolve by name
/// (OASIS PKCS#11 v2.40 s5.6.4). It returns a pointer to the static
/// [`api::FUNCTION_LIST`] vtable through which every other function
/// is reached. p11-kit / NSS load the shared object and call this
/// first.
///
/// # Safety
/// `list` must be a valid, writable location for one
/// `CK_FUNCTION_LIST_PTR`, per the PKCS#11 caller contract.
#[unsafe(no_mangle)]
unsafe extern "C" fn C_GetFunctionList(list: CkFunctionListPtrPtr) -> CkRv {
    // SAFETY: `list` validity is the caller's PKCS#11 contract;
    // `c_get_function_list` null-checks it before writing.
    unsafe { api::c_get_function_list(list) }
}
