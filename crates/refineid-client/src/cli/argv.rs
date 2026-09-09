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

//! Typed wrapper for the process argv vector.
//!
//! `std::env::args().collect::<Vec<String>>()` is the
//! OS-handoff trust boundary: the kernel hands the process a
//! sequence of bytes, the standard library reinterprets them
//! as UTF-8 strings (and panics on a non-UTF-8 arg). Past that
//! single point of capture, downstream code should consume a
//! typed wrapper rather than re-passing the raw vector.
//!
//! [`ProcessArgv`] is that wrapper. The constructor
//! [`ProcessArgv::from_env`] is the one place
//! `std::env::args()` is allowed to be called; every other
//! piece of code takes a `&ProcessArgv` or
//! [`ProcessArgv::after_program`] for the post-`argv[0]` slice
//! that subcommand-dispatch consumes.

/// Owned, captured process argv -- the raw token vector handed
/// to the program by the kernel (or test harness), with
/// `args[0]` conventionally being the program name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessArgv {
    /// Raw token vector as received from `std::env::args` (or
    /// the test harness). `args[0]` is the program name by
    /// convention. The verb parser consumes this and produces
    /// a [`RemainingArgv`].
    args: Vec<String>,
}

/// Owned, post-subcommand argv.
///
/// The slice of tokens that follows the program name and the
/// subcommand identifier(s). Constructed by
/// [`super::verb::parse_argv`] and consumed by-value by every
/// per-subcommand `*Args::parse(RemainingArgv)` (a single-shot
/// move; the bytes are walked once).
///
/// Separate type from [`ProcessArgv`] so the compiler refuses
/// to feed an unparsed full argv (including `argv[0]` and the
/// subcommand verb) into a parser that expects the verbs to
/// be already-consumed. Construction is locked to two paths:
/// the subcommand parser (production), and
/// `RemainingArgv::from_slice` (test fixtures).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RemainingArgv {
    /// Tokens that follow the subcommand verb. Owned `String`s
    /// (not borrows) so per-subcommand parsers can move them
    /// around without lifetime gymnastics; the cost is one
    /// allocation per token at construction.
    tokens: Vec<String>,
}

impl RemainingArgv {
    /// Wrap a borrowed slice of post-subcommand argv tokens.
    /// Production construction goes through the subcommand
    /// parser; this constructor exists for unit tests and
    /// programmatic argv synthesis.
    #[must_use]
    pub(crate) fn from_slice(tokens: &[String]) -> Self {
        Self {
            tokens: tokens.to_vec(),
        }
    }

    /// Take ownership of a token vector.
    #[must_use]
    pub const fn from_vec(tokens: Vec<String>) -> Self {
        Self { tokens }
    }

    /// Borrow the token slice for iteration inside a typed
    /// `*Args::parse`.
    #[must_use]
    pub const fn as_slice(&self) -> &[String] {
        self.tokens.as_slice()
    }

    /// `true` when no tokens follow the subcommand verb -- the
    /// "bare subcommand" case (e.g. plain `refineid card`).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// Number of remaining argv tokens.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Consume the wrapper and return its inner token vector.
    /// Use this inside an owning `*Args::parse(argv:
    /// RemainingArgv)` to actually move the tokens out of the
    /// wrapper -- otherwise `clippy::needless_pass_by_value`
    /// will (correctly) point out that the by-value parameter
    /// is only borrowed.
    #[must_use]
    pub fn into_vec(self) -> Vec<String> {
        self.tokens
    }
}

impl IntoIterator for RemainingArgv {
    type Item = String;
    type IntoIter = alloc::vec::IntoIter<String>;
    fn into_iter(self) -> Self::IntoIter {
        self.tokens.into_iter()
    }
}

impl ProcessArgv {
    /// Capture `std::env::args()` into the typed wrapper. The
    /// only place in the crate that should call
    /// `std::env::args()`.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            args: std::env::args().collect(),
        }
    }

    /// Build from a borrowed slice. Useful for unit tests and
    /// for callers that want to drive the dispatch with a
    /// programmatically-built argv (test harness, bench
    /// driver, etc.) rather than the process's own argv.
    #[must_use]
    #[cfg(test)]
    pub(crate) const fn from_slice(args: Vec<String>) -> Self {
        Self { args }
    }

    /// Borrow the full argv slice (including `argv[0]`).
    #[must_use]
    pub fn as_slice(&self) -> &[String] {
        &self.args
    }

    /// Borrow the post-`argv[0]` slice -- the subcommand token
    /// plus its arguments. Empty when only the program name
    /// was supplied (or the argv is empty).
    #[must_use]
    pub fn after_program(&self) -> &[String] {
        self.args.get(1..).unwrap_or(&[])
    }

    /// `argv[0]` -- conventionally the program name. `None`
    /// when argv is empty (which the kernel doesn't normally
    /// produce, but the type doesn't rule out).
    #[must_use]
    pub fn program_name(&self) -> Option<&str> {
        self.args.first().map(String::as_str)
    }

    /// `true` when any token past `argv[0]` is `--help`,
    /// `-h`, or `help`. The CLI surfaces a help short-circuit
    /// before subcommand dispatch via this predicate.
    #[must_use]
    pub fn wants_help(&self) -> bool {
        self.after_program()
            .iter()
            .any(|a| a == "--help" || a == "-h" || a == "help")
    }

    /// Resolve this argv into a parsed [`Verb`], or
    /// already-rendered exit code on help / parse failure.
    ///
    /// This is the entire pre-dispatch pipeline:
    ///
    /// 1. `--help` / `-h` / `help` past `argv[0]` -- print
    ///    `usage` to stderr, return `Err(ExitStatus::Ok)`.
    /// 2. Verb dispatch or per-subcommand Args parse fails --
    ///    print the typed error line + `usage` to stderr,
    ///    return `Err(ExitStatus::BadInvocation)`.
    /// 3. Otherwise -- return `Ok(Verb)` for the caller
    ///    to dispatch on.
    ///
    /// `usage` is the operator-facing USAGE block; it's
    /// CLI-specific and lives in the binary, so the caller
    /// passes it in.
    ///
    /// # Errors
    /// Help short-circuit returns
    /// `Err(ExitStatus::Ok.into())`; parse failure returns
    /// `Err(ExitStatus::BadInvocation.into())`. The exit code
    /// is the rendering of the outcome, not a failure to do
    /// work.
    ///
    /// [`Verb`]: super::verb::Verb
    pub fn resolve_command_line(
        self,
        usage: super::Usage<'_>,
    ) -> Result<super::verb::Verb, std::process::ExitCode> {
        use crate::exit_status::ExitStatus;
        if self.wants_help() {
            eprint!("{usage}");
            return Err(ExitStatus::Ok.into());
        }
        super::verb::parse_argv(&self).map_err(|e| {
            eprintln!("{e}");
            eprint!("{usage}");
            ExitStatus::BadInvocation.into()
        })
    }
}

/// Test-only argv fixture builders, shared by every
/// per-subcommand test module. One definition instead of a
/// copy-pasted helper per file; import with
/// `use crate::cli::argv::fixtures::remaining_argv as argv;`.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::{ProcessArgv, RemainingArgv};

    /// Owned [`RemainingArgv`] from string literals.
    pub(in crate::cli) fn remaining_argv(s: &[&str]) -> RemainingArgv {
        RemainingArgv::from_slice(&s.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>())
    }

    /// Owned [`ProcessArgv`] from string literals.
    pub(in crate::cli) fn process_argv(s: &[&str]) -> ProcessArgv {
        ProcessArgv::from_slice(s.iter().map(|x| (*x).to_owned()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::process_argv as argv;
    use super::*;

    #[test]
    fn after_program_strips_argv0() {
        let a = argv(&["refineid", "card", "--no-can"]);
        assert_eq!(
            a.after_program(),
            &["card".to_owned(), "--no-can".to_owned()]
        );
    }

    #[test]
    fn after_program_on_argv0_only_is_empty() {
        let a = argv(&["refineid"]);
        assert!(a.after_program().is_empty());
    }

    #[test]
    fn after_program_on_empty_argv_is_empty() {
        let a = argv(&[]);
        assert!(a.after_program().is_empty());
    }

    #[test]
    fn program_name_returns_argv0() {
        let a = argv(&["refineid", "card"]);
        assert_eq!(a.program_name(), Some("refineid"));
    }

    #[test]
    fn program_name_is_none_for_empty_argv() {
        let a = argv(&[]);
        assert!(a.program_name().is_none());
    }

    #[test]
    fn wants_help_matches_long_short_and_bare_forms() {
        assert!(argv(&["refineid", "--help"]).wants_help());
        assert!(argv(&["refineid", "-h"]).wants_help());
        assert!(argv(&["refineid", "help"]).wants_help());
        assert!(argv(&["refineid", "card", "--help"]).wants_help());
        assert!(!argv(&["refineid", "card", "--no-can"]).wants_help());
    }

    #[test]
    fn wants_help_ignores_argv0() {
        // Even if argv0 itself happens to be `--help`, it
        // doesn't trigger the help short-circuit.
        let a = argv(&["--help"]);
        assert!(!a.wants_help());
    }

    #[test]
    fn remaining_argv_from_slice_round_trips() {
        let r = RemainingArgv::from_slice(&["--reader".to_owned(), "OMNIKEY".to_owned()]);
        assert_eq!(r.len(), 2_usize);
        assert!(!r.is_empty());
        assert_eq!(r.as_slice().first().map(String::as_str), Some("--reader"));
    }

    #[test]
    fn remaining_argv_default_is_empty() {
        let r = RemainingArgv::default();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0_usize);
    }
}
