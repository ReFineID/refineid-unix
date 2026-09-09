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

//! `card export-all` typed arguments.

use std::path::PathBuf;

use super::{ArgParseError, argv::RemainingArgv, verb::VerbTag};

/// Parsed `card export-all DIR [--reader SUBSTR]` arguments.
///
/// Construction is exclusively via [`ExportAllArgs::parse`];
/// the field set is `pub` so the handler can move them into
/// [`crate::card_export::ExportAllOptions`] without reflection
/// or further re-validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportAllArgs {
    /// Output directory for the per-cert + EF.SOD + EF.TokenInfo
    /// DER files. Required positional argument.
    pub directory: PathBuf,
    /// Optional substring match against reader names. `None` is
    /// the "first reader with a card present" default.
    pub reader_filter: Option<String>,
}

impl ExportAllArgs {
    /// Execute the `card export-all` verb.
    #[must_use]
    pub fn run(self) -> std::process::ExitCode {
        let Self {
            directory,
            reader_filter,
        } = self;
        let options = crate::card_export::ExportAllOptions {
            directory,
            reader_filter,
        };
        let backend = refineid_lib_pcsc::PcscBackend;
        match crate::card_export::export_all_first(backend, &options) {
            Ok(report) => {
                print!("{report}");
                crate::exit_status::ExitStatus::Ok.into()
            }
            Err(crate::card_export::ExportError::ReaderPick(pe)) => {
                super::util::reader_pick_exit("card export-all", &pe)
            }
            Err(e) => {
                eprintln!("card export-all: {e}");
                crate::exit_status::ExitStatus::RuntimeFailure.into()
            }
        }
    }

    /// Parse the post-subcommand argv slice.
    ///
    /// Trust-boundary constructor: validates the flag shape
    /// (no duplicate / missing-value / unknown-flag cases),
    /// enforces the required positional, and wraps the result
    /// as the typed [`ExportAllArgs`]. No further validation
    /// of `directory` is performed here -- existence /
    /// permissions are checked by the export action itself
    /// when it writes.
    ///
    /// # Errors
    /// [`ArgParseError`] for any shape violation.
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let mut directory: Option<PathBuf> = None;
        let mut reader_filter: Option<String> = None;
        let tokens = argv.into_vec();
        let mut iter = tokens.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--reader" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardExportAll,
                        flag: "--reader",
                    })?;
                    reader_filter = Some(value.clone());
                }
                other if !other.starts_with('-') && directory.is_none() => {
                    directory = Some(PathBuf::from(other));
                }
                other => {
                    return Err(ArgParseError::Unexpected {
                        cmd: VerbTag::CardExportAll,
                        got: other.to_owned(),
                    });
                }
            }
        }
        let directory = directory.ok_or(ArgParseError::Required {
            cmd: VerbTag::CardExportAll,
            name: "DIR (positional output directory)",
        })?;
        Ok(Self {
            directory,
            reader_filter,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::argv::fixtures::remaining_argv as argv;
    use crate::test_util::{TestResult, check, check_true};

    #[test]
    fn parses_positional_directory_only() -> TestResult {
        let args = ExportAllArgs::parse(argv(&["/tmp/out"]))?;
        check(&args.directory, &PathBuf::from("/tmp/out"), "directory")?;
        check_true(args.reader_filter.is_none(), "reader_filter=None")
    }

    #[test]
    fn parses_directory_with_reader_filter() -> TestResult {
        let args = ExportAllArgs::parse(argv(&["/tmp/out", "--reader", "OMNIKEY"]))?;
        check(&args.directory, &PathBuf::from("/tmp/out"), "directory")?;
        check(
            &args.reader_filter.as_deref(),
            &Some("OMNIKEY"),
            "reader_filter",
        )
    }

    #[test]
    fn parses_reader_filter_before_directory() -> TestResult {
        let args = ExportAllArgs::parse(argv(&["--reader", "ACS", "/tmp/out"]))?;
        check(
            &args.reader_filter.as_deref(),
            &Some("ACS"),
            "reader_filter",
        )?;
        check(&args.directory, &PathBuf::from("/tmp/out"), "directory")
    }

    #[test]
    fn missing_directory_rejected() -> TestResult {
        let r = ExportAllArgs::parse(argv(&[]));
        check_true(matches!(r, Err(ArgParseError::Required { .. })), "Required")
    }

    #[test]
    fn unknown_flag_rejected() -> TestResult {
        let r = ExportAllArgs::parse(argv(&["/tmp/out", "--bogus"]));
        match r {
            Err(ArgParseError::Unexpected { cmd, got }) => {
                check(&cmd, &VerbTag::CardExportAll, "cmd")?;
                check(got.as_str(), "--bogus", "got")
            }
            other => Err(format!("expected Unexpected, got {other:?}").into()),
        }
    }

    #[test]
    fn reader_flag_without_value_rejected() -> TestResult {
        let r = ExportAllArgs::parse(argv(&["/tmp/out", "--reader"]));
        check_true(
            matches!(r, Err(ArgParseError::MissingValue { .. })),
            "MissingValue",
        )
    }

    #[test]
    fn second_positional_rejected_as_unexpected() -> TestResult {
        let r = ExportAllArgs::parse(argv(&["/tmp/out", "/tmp/out2"]));
        check_true(
            matches!(r, Err(ArgParseError::Unexpected { .. })),
            "Unexpected",
        )
    }
}
