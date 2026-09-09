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

//! Shared CLI helpers used across multiple verb handlers.
//!
//! The three helpers here all touch operator I/O (stdin / stderr)
//! or map the shared [`ReaderPickError`] family to typed
//! [`ExitStatus`] -- both are concerns the verb-specific
//! handlers share via call, not via duplicated logic.

use std::io::{BufRead as _, IsTerminal};
use std::process::ExitCode;

use refineid_lib_core::backend::ReaderPickError;
use refineid_lib_core::can::Can;
use refineid_lib_core::pin::PinBytes;

use crate::exit_status::ExitStatus;

/// Map a [`ReaderPickError`] to the project's exit-status
/// convention.
///
/// - `NoReaders` -> `NoReaders` (65)
/// - `NoCardPresent` -> `NoCardPresent` (66)
/// - `MultipleReadersNoFilter` / `NoMatchingReader` /
///   `AmbiguousFilter` -> `BadInvocation` (64); the operator
///   resolves these by adjusting argv.
/// - Anything else (`#[non_exhaustive]` enum, future variant)
///   -> `RuntimeFailure` (70).
///
/// Pure mapping (no I/O) so the table is unit-testable on a
/// comparable [`ExitStatus`] rather than the opaque [`ExitCode`]
/// returned by [`reader_pick_exit`].
pub const fn reader_pick_status(err: &ReaderPickError) -> ExitStatus {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "ReaderPickError is #[non_exhaustive]; today's only fallback is NoFineidCard (probe failure on every card-present reader), and any future variant maps to the catch-all RuntimeFailure (70) exit per the doc comment above."
    )]
    match err {
        ReaderPickError::NoReaders => ExitStatus::NoReaders,
        ReaderPickError::NoCardPresent => ExitStatus::NoCardPresent,
        ReaderPickError::MultipleReadersNoFilter { .. }
        | ReaderPickError::NoMatchingReader { .. }
        | ReaderPickError::AmbiguousFilter { .. } => ExitStatus::BadInvocation,
        _ => ExitStatus::RuntimeFailure,
    }
}

/// Render an operator-facing `cmd: <error>` line to stderr, then
/// map the [`ReaderPickError`] to its process [`ExitCode`] via
/// [`reader_pick_status`].
pub(super) fn reader_pick_exit(cmd: &str, err: &ReaderPickError) -> ExitCode {
    eprintln!("{cmd}: {err}");
    reader_pick_status(err).into()
}

/// Interactive, masked CAN prompt with TTY detection.
///
/// Returns `Some(can)` when the operator typed 6 digits and
/// pressed Enter; returns `None` when stdin isn't a TTY (no
/// prompt issued) or when the operator pressed Enter without
/// typing anything. Malformed input (non-empty, non-6-digit)
/// prints a one-line error and re-tries up to twice before
/// falling through to `None`.
///
/// Parse-don't-validate at the prompt boundary: hands back a
/// typed `Can`, not a raw `String`, so downstream code can't
/// accidentally bypass the digit check.
#[must_use]
pub fn prompt_can_if_tty() -> Option<Can> {
    /// Maximum number of CAN re-prompts before giving up. Three
    /// matches the "1 + 2 retries" feel an operator expects.
    const CAN_PROMPT_MAX_TRIES: u32 = 3;

    if !std::io::stdin().is_terminal() {
        return None;
    }
    let mut tries_left: u32 = CAN_PROMPT_MAX_TRIES;
    while tries_left > 0 {
        tries_left = tries_left.saturating_sub(1);
        let config = rpassword::ConfigBuilder::new()
            .password_feedback_mask('*')
            .build();
        let entered = match rpassword::prompt_password_with_config(
            "CAN (6 digits, printed on card front, or Enter to skip): ",
            config,
        ) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("CAN prompt failed: {error}");
                return None;
            }
        };
        if entered.is_empty() {
            return None;
        }
        match Can::new(&entered) {
            Ok(c) => return Some(c),
            Err(e) => {
                eprintln!("CAN {e}");
            }
        }
    }
    eprintln!("CAN: too many bad entries; skipping eMRTD section");
    None
}

/// Read a PIN, consulting an environment variable first only when
/// the `pin-env-debug` feature is enabled, otherwise prompting.
///
/// This is the single consolidated home for what used to be a
/// per-module `read_pin_env_or_prompt` (card sign / activate /
/// change-pin) and the inline `read_pin1` in the login verbs.
///
/// The env-var branch is a compile-time alpha-period debug aid:
/// env-var PINs show up in `ps` and are inherited by child
/// processes, so the shipped beta build (feature off) never reads
/// them and jumps straight to [`prompt_pin`]. WARNING.md documents
/// the alpha exception as removed at the beta tag; gating it off by
/// default is that removal, while keeping a CI/automation opt-in.
///
/// # Errors
/// Propagates [`prompt_pin`]'s error when the interactive read
/// fails (or when the feature is off / the variable is empty).
pub(super) fn pin_env_or_prompt(
    cmd: &str,
    env_var: &str,
    prompt: &str,
) -> Result<PinBytes, ExitCode> {
    #[cfg(feature = "pin-env-debug")]
    {
        if let Ok(val) = std::env::var(env_var) {
            let bytes = val.into_bytes();
            if !bytes.is_empty() {
                eprintln!("{cmd}: reading {env_var} from environment (alpha-period debug aid)");
                return PinBytes::new(bytes).map_err(|error| {
                    eprintln!("{cmd}: invalid PIN: {error}");
                    ExitCode::from(ExitStatus::BadInvocation)
                });
            }
        }
    }
    // Silence the unused-parameter warning when the feature is off;
    // `env_var` names the variable the debug build would consult.
    #[cfg(not(feature = "pin-env-debug"))]
    let _ = env_var;
    prompt_pin(cmd, prompt)
}

/// New-PIN counterpart of [`pin_env_or_prompt`]: env-var first
/// under the `pin-env-debug` feature, otherwise the confirm-twice
/// [`prompt_new_pin_pair`]. Same alpha-period gating rationale.
///
/// # Errors
/// Propagates [`prompt_new_pin_pair`]'s error (stdin failure or
/// new/confirm mismatch) when the interactive read is used.
pub(super) fn new_pin_env_or_prompt(
    cmd: &str,
    env_var: &str,
    label: &str,
    digit_hint: Option<&str>,
) -> Result<PinBytes, ExitCode> {
    #[cfg(feature = "pin-env-debug")]
    {
        if let Ok(val) = std::env::var(env_var) {
            let bytes = val.into_bytes();
            if !bytes.is_empty() {
                eprintln!("{cmd}: reading {env_var} from environment (alpha-period debug aid)");
                return PinBytes::new(bytes).map_err(|error| {
                    eprintln!("{cmd}: invalid PIN: {error}");
                    ExitCode::from(ExitStatus::BadInvocation)
                });
            }
        }
    }
    #[cfg(not(feature = "pin-env-debug"))]
    let _ = env_var;
    prompt_new_pin_pair(cmd, label, digit_hint)
}

/// Prompt for a single PIN / PUK once and fold the stdin /
/// prompt failure into the standard `cmd: <error>` stderr line
/// + `RuntimeFailure` exit.
///
/// Thin shim over [`read_pin_masked`]: takes the `cmd` label
/// each handler already passes around and returns the typed
/// [`ExitCode`] the handler is going to return anyway. Drops
/// the repeated `match Ok(p) => p, Err(msg) => { eprintln!;
/// return ExitStatus::RuntimeFailure.into() }` block at every
/// call site.
///
/// # Errors
/// Returns `ExitStatus::RuntimeFailure` when the prompt or
/// stdin read fails. The stderr line is already written.
pub(super) fn prompt_pin(cmd: &str, prompt: &str) -> Result<PinBytes, ExitCode> {
    read_pin_masked(prompt).map_err(|msg| {
        eprintln!("{cmd}: {msg}");
        ExitCode::from(ExitStatus::RuntimeFailure)
    })
}

/// Prompt for a new PIN twice (new + confirm), masked, and
/// return the value if both entries match.
///
/// Centralises the duplicate prompt-pair pattern used by
/// `card activate`, `card change-pin{1,2}`, and `card
/// unblock-pin{1,2}`. Emits one of two stderr lines on error
/// (`cmd: <stdin-failure>` or `cmd: new <label> entries didn't
/// match`) and folds those into the matching [`ExitStatus`]:
///
/// - stdin / prompt error -> `RuntimeFailure`
/// - new/confirm mismatch -> `BadInvocation`
///
/// `label` is the short PIN name (`"PIN1"`, `"PIN2"`), shown in
/// both the first and the confirm prompt and in the mismatch
/// error. `digit_hint`, when `Some`, is appended in parens to
/// the first prompt only -- `Some("4-12 digits")` gives `"new
/// PIN1 (4-12 digits): "` then `"new PIN1 (confirm): "`. Pass
/// `None` for change-pin / unblock-pin where no length hint is
/// shown.
///
/// # Errors
/// Returns the matching [`ExitCode`] when the operator's input
/// is unusable.
pub(super) fn prompt_new_pin_pair(
    cmd: &str,
    label: &str,
    digit_hint: Option<&str>,
) -> Result<PinBytes, ExitCode> {
    let first_prompt = digit_hint.map_or_else(
        || format!("new {label}: "),
        |hint| format!("new {label} ({hint}): "),
    );
    let new1 = prompt_pin(cmd, &first_prompt)?;
    let new2 = prompt_pin(cmd, &format!("new {label} (confirm): "))?;
    if new1.as_bytes() != new2.as_bytes() {
        eprintln!("{cmd}: new {label} entries didn't match");
        return Err(ExitStatus::BadInvocation.into());
    }
    drop(new2);
    Ok(new1)
}

/// Read a PIN from stdin, showing one `*` per entered character when
/// stdin is a TTY,
/// line-read when it isn't. Returns the bytes wrapped in a
/// [`PinBytes`] (which zeroizes on drop).
///
/// # Errors
/// Returns the prompt failure or stdin read failure as a
/// human-readable string. The caller maps it to an exit code.
pub(super) fn read_pin_masked(prompt: &str) -> Result<PinBytes, String> {
    let pin_str = if IsTerminal::is_terminal(&std::io::stdin()) {
        let config = rpassword::ConfigBuilder::new()
            .password_feedback_mask('*')
            .build();
        rpassword::prompt_password_with_config(prompt, config)
            .map_err(|e| format!("PIN prompt failed: {e}"))?
    } else {
        let mut line = String::new();
        let stdin = std::io::stdin();
        {
            let mut guard = stdin.lock();
            let _read_bytes: usize = guard
                .read_line(&mut line)
                .map_err(|e| format!("PIN read from stdin failed: {e}"))?;
        }
        // Strip trailing newline / carriage return (lf or crlf).
        while matches!(line.as_bytes().last(), Some(b'\n' | b'\r')) {
            let _popped: Option<char> = line.pop();
        }
        line
    };
    PinBytes::new(pin_str.into_bytes()).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{TestResult, check};

    // The reader-filter-error -> exit-status table. The
    // distinction that matters operationally: "no hardware"
    // (NoReaders/NoCardPresent) vs "your argv didn't pin a unique
    // card" (BadInvocation) vs "everything else" (RuntimeFailure).
    // The interactive prompt helpers (prompt_pin / prompt_can /
    // read_pin_masked) read stdin and are deliberately left
    // untested: under `cargo test` stdin is often still a TTY, so
    // exercising them would block the harness on a real read.

    #[test]
    fn no_readers_maps_to_no_readers() -> TestResult {
        check(
            &reader_pick_status(&ReaderPickError::NoReaders),
            &ExitStatus::NoReaders,
            "NoReaders",
        )
    }

    #[test]
    fn no_card_present_maps_to_no_card_present() -> TestResult {
        check(
            &reader_pick_status(&ReaderPickError::NoCardPresent),
            &ExitStatus::NoCardPresent,
            "NoCardPresent",
        )
    }

    #[test]
    fn ambiguous_argv_shapes_map_to_bad_invocation() -> TestResult {
        // All three "the operator must narrow argv" shapes share
        // the EX_USAGE (64) exit.
        check(
            &reader_pick_status(&ReaderPickError::MultipleReadersNoFilter {
                available: vec!["OMNIKEY".to_owned(), "ACR".to_owned()],
            }),
            &ExitStatus::BadInvocation,
            "MultipleReadersNoFilter",
        )?;
        check(
            &reader_pick_status(&ReaderPickError::NoMatchingReader {
                filter: "zzz".to_owned(),
                available: vec!["OMNIKEY".to_owned()],
            }),
            &ExitStatus::BadInvocation,
            "NoMatchingReader",
        )?;
        check(
            &reader_pick_status(&ReaderPickError::AmbiguousFilter {
                filter: "key".to_owned(),
                matched: vec!["OMNIKEY 1".to_owned(), "OMNIKEY 2".to_owned()],
            }),
            &ExitStatus::BadInvocation,
            "AmbiguousFilter",
        )
    }

    #[test]
    fn no_fineid_card_falls_through_to_runtime_failure() -> TestResult {
        // The catch-all: a card-present-but-not-FINEID outcome is
        // not an argv problem, so it lands on RuntimeFailure (70)
        // rather than BadInvocation.
        check(
            &reader_pick_status(&ReaderPickError::NoFineidCard {
                available: vec!["YubiKey CCID".to_owned()],
            }),
            &ExitStatus::RuntimeFailure,
            "NoFineidCard",
        )
    }
}
