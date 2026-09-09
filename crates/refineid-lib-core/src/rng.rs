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

//! The single OS-CSPRNG seam for this crate.
//!
//! Every random draw in `lib-core` goes through here so the fail-closed
//! policy lives in exactly one place: a failed OS RNG is always a hard
//! [`Failure`], propagated by the caller, never silently swallowed into a
//! weakened mode (a dropped nonce, a predictable IV). A dead OS RNG means
//! no cryptographic operation on this host can be trusted, so the only
//! correct response is to abort.
//!
//! Domain nonce / key types ([`crate::ocsp::OcspNonce`], the PACE / AA / CA
//! ephemeral draws) build on [`fill`] / [`array()`] rather than calling
//! `getrandom` directly. `getrandom` is banned outside this module by
//! policy, so a new call site cannot
//! reintroduce a "draw, swallow the error, continue" path -- the mistake
//! this seam exists to make unrepresentable.

/// The OS CSPRNG was unavailable.
///
/// Re-exported from `getrandom` so callers keep storing the concrete cause;
/// this alias is the crate's one RNG error type.
pub type Failure = getrandom::Error;

/// Fill `buf` with OS CSPRNG bytes, or fail.
///
/// # Errors
/// Returns [`Failure`] if the OS RNG is unavailable. Propagate it; never
/// proceed with a partially-filled or zero buffer.
#[inline]
pub fn fill(buf: &mut [u8]) -> Result<(), Failure> {
    getrandom::fill(buf)
}

/// Draw a fresh `N`-byte array from the OS CSPRNG, or fail.
///
/// # Errors
/// Returns [`Failure`] if the OS RNG is unavailable.
#[inline]
pub fn array<const N: usize>() -> Result<[u8; N], Failure> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes)?;
    Ok(bytes)
}
