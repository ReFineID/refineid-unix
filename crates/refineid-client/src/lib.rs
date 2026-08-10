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

//! `ReFineID` client library.
//!
//! Surfaces the high-level operations the CLI binary
//! (`refineid`) and future GUI peers call. The flagship is
//! [`card_check`]: one walk produces a full per-card report
//! (identity, cert chain with revocation, PIN counters, and
//! optionally the eMRTD layer behind a CAN). Action verbs
//! (sign, decrypt, change-PIN, etc.) live in their own
//! modules.

#![forbid(unsafe_code)]
// Crate-level CLI-output lint carve-outs.
//
// `refineid-client` is a CLI library + binary surface. It
// produces operator-facing reports (cert chain + revocation
// outcomes, eMRTD per-data-group readout, PIN-counter state)
// that go directly to stdout/stderr in human-readable form.
// Per `doc/observability.md -> What this is not -> Not for
// primary output`: events are OBSERVATIONS about operations
// (handled via `refineid_lib_core::events`); these prints are
// the CLI's PRIMARY OUTPUT, the answer the user invoked the
// command to see. The carve-out is per-crate (this lib +
// the refineid bin); library crates (`refineid-lib-core`,
// `refineid-lib-pcsc`) keep
// `print_stderr` / `print_stdout` warned via the workspace
// `restriction` group so any future attempt to add a raw
// print there stays visible.

extern crate alloc;

pub mod apdu_trace;
pub mod card_check;
pub mod card_decrypt;
pub mod card_emrtd;
pub mod card_export;
pub mod card_manager;
pub mod card_pin;
pub mod card_pubkey;
pub mod card_sign;
pub mod cert_chain;
pub mod cert_show;
pub mod cli;
pub mod events;
pub mod exit_status;
pub mod http;
pub mod reader_keyboard;
pub mod text;
pub mod trust_roots;
pub mod user_agent;
pub mod validation_material;
pub mod verify;

#[cfg(test)]
pub mod test_util {
    //! Test-only assertion helpers shared by every `*::tests`
    //! module.
    //!
    //! Tests return `Result<(), Box<dyn core::error::Error>>`
    //! and propagate mismatches through `?` rather than letting
    //! `assert_eq!` / `assert!` panic; that avoids the
    //! workspace-deny `clippy::panic_in_result_fn` exception
    //! that the per-file test blocks used to carry.

    use core::error::Error;
    use core::fmt::Debug;
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::path::{Path, PathBuf};

    /// `Result` shape every `#[test]` in client `tests` modules
    /// returns.
    pub type TestResult = Result<(), Box<dyn Error>>;

    /// Self-cleaning temporary directory for tests that drive the
    /// file-path-taking entrypoints (`show_cert`, `walk_chain`,
    /// `verify_offline`, `write_file`, ...).
    ///
    /// The crate has no `tempfile` dependency and the production
    /// code reads from `&Path`, so tests stage their fixtures on
    /// disk. The directory name is made unique per process *and*
    /// per construction (PID + a monotonic counter) so parallel
    /// `cargo test` threads -- and concurrent test processes --
    /// never collide. The tree is removed on `Drop`; a failed
    /// removal is swallowed because a leaked temp dir must not
    /// turn a passing test red.
    pub(crate) struct TempDir {
        /// Absolute path to the created directory.
        path: PathBuf,
    }

    impl TempDir {
        /// Create a fresh, empty directory under the OS temp dir.
        ///
        /// `tag` is folded into the directory name purely as a
        /// human-readable hint when inspecting leftover dirs from
        /// a crashed run; uniqueness comes from PID + counter, not
        /// from `tag`.
        ///
        /// # Errors
        /// Propagates the `create_dir_all` I/O error.
        pub(crate) fn new(tag: &str) -> std::io::Result<Self> {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("refineid-test-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&path)?;
            Ok(Self { path })
        }

        /// Borrow the directory path.
        pub(crate) fn path(&self) -> &Path {
            &self.path
        }

        /// Write `bytes` to `name` inside the directory and return
        /// the full path to the new file.
        ///
        /// # Errors
        /// Propagates the `write` I/O error.
        pub(crate) fn write(&self, name: &str, bytes: &[u8]) -> std::io::Result<PathBuf> {
            let p = self.path.join(name);
            std::fs::write(&p, bytes)?;
            Ok(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            // Best-effort cleanup: a leaked temp dir is harmless and
            // must never fail an otherwise-passing test.
            let _ignored = std::fs::remove_dir_all(&self.path);
        }
    }

    /// `assert_eq!`-style check that maps the failure to an
    /// `Err(...)` instead of a panic. `label` is the
    /// human-readable field name shown in the error message on
    /// mismatch.
    ///
    /// # Errors
    /// Returns an `Err` containing the `label`, the expected
    /// value, and the actual value when `actual != expected`.
    #[inline]
    pub(crate) fn check<T: PartialEq + Debug + ?Sized>(
        actual: &T,
        expected: &T,
        label: &str,
    ) -> TestResult {
        if actual == expected {
            Ok(())
        } else {
            Err(format!("{label}: expected {expected:?}, got {actual:?}").into())
        }
    }

    /// `assert!`-style check that maps `cond == false` to `Err`.
    ///
    /// # Errors
    /// Returns an `Err` carrying `label` when `cond` is false.
    #[inline]
    pub(crate) fn check_true(cond: bool, label: &str) -> TestResult {
        if cond {
            Ok(())
        } else {
            Err(format!("{label}: condition was false").into())
        }
    }
}
