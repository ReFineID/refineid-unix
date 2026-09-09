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

//! Env-gated diagnostic logging for tracing the NSS call sequence.
//!
//! Off by default. `REFINEID_PKCS11_LOG=<path>` appends lines to an
//! operator-chosen file; otherwise `REFINEID_DEBUG=1` writes to
//! stderr; otherwise every call is a no-op. The environment is read
//! once per process (this cdylib lives as long as the browser, and a
//! long-lived module must not re-read its configuration per call).
//!
//! There is deliberately NO default file path: this code runs inside
//! the browser's address space, and an implicit well-known location
//! in a world-writable directory such as `/tmp` is a symlink-attack
//! surface. The operator names the file explicitly or gets no file.
//!
//! PIN secrecy (AGENTS.md): call sites log function names, handles,
//! flag words, and byte lengths only -- never PIN bytes, never
//! attribute or signature values.

use std::io::Write as _;
use std::sync::{Mutex, OnceLock};

/// Where diagnostic lines go, decided once from the environment.
enum Sink {
    /// `REFINEID_DEBUG=1`: write to the process stderr.
    Stderr,
    /// `REFINEID_PKCS11_LOG=<path>`: append to the named file.
    File(Mutex<std::fs::File>),
}

/// The process-wide sink; `None` inside means logging is disabled.
static SINK: OnceLock<Option<Sink>> = OnceLock::new();

/// Resolve the sink, reading the environment on first use only.
fn sink() -> Option<&'static Sink> {
    SINK.get_or_init(|| {
        if let Ok(path) = std::env::var("REFINEID_PKCS11_LOG")
            && !path.is_empty()
        {
            return std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .ok()
                .map(|file| Sink::File(Mutex::new(file)));
        }
        (std::env::var("REFINEID_DEBUG").ok().as_deref() == Some("1")).then_some(Sink::Stderr)
    })
    .as_ref()
}

/// Whether diagnostic logging is active. Callers gate on this before
/// formatting so a disabled sink costs no allocation.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is called from the sibling api module; plain pub would violate the public-surface typing grep"
)]
pub(super) fn enabled() -> bool {
    sink().is_some()
}

/// Append one line to the active sink. Every failure is swallowed: a
/// diagnostics problem must never disturb the hosting caller (NSS
/// expects deterministic returns from a passive module).
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is called from the sibling api module; plain pub would violate the public-surface typing grep"
)]
pub(super) fn write_line(line: &str) {
    match sink() {
        Some(Sink::Stderr) => {
            let mut err = std::io::stderr().lock();
            let _ = writeln!(err, "refineid-pkcs11[{}]: {line}", std::process::id());
        }
        Some(Sink::File(file)) => {
            if let Ok(mut file) = file.lock() {
                let _ = writeln!(file, "refineid-pkcs11[{}]: {line}", std::process::id());
            }
        }
        None => {}
    }
}

/// Log one diagnostic line, formatting lazily (the arguments are
/// evaluated only when a sink is active). Never pass PIN bytes or
/// attribute values.
macro_rules! diag {
    ($($arg:tt)*) => {
        if crate::diag::enabled() {
            crate::diag::write_line(&format!($($arg)*));
        }
    };
}
pub(crate) use diag;
