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

//! `card pubkey` typed arguments.

use std::path::PathBuf;

use crate::card_pubkey::{PubkeyFormat, PubkeySlot};

use super::{ArgParseError, argv::RemainingArgv, verb::VerbTag};

/// Parsed `card pubkey [--slot auth|qualified]
/// [--format ssh|pem] [--out PATH] [--reader SUBSTR]
/// [--comment STR]` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PubkeyArgs {
    /// Which slot's cert to read (`--slot auth|qualified`).
    pub slot: PubkeySlot,
    /// Output encoding (`--format ssh|pem`).
    pub format: PubkeyFormat,
    /// Output file, or stdout when `None` (`--out PATH`).
    pub output: Option<PathBuf>,
    /// Optional reader-name substring (`--reader SUBSTR`).
    /// Tier 0 `String`; presentational input to `ReaderFilter`.
    pub reader_filter: Option<String>,
    /// Optional SSH comment override (`--comment STR`); see
    /// [`crate::card_pubkey::PubkeyOptions::comment`] for the
    /// auto-build rule when `None`. `Some("")` emits no comment.
    pub comment: Option<String>,
}

impl PubkeyArgs {
    /// Execute the `card pubkey` verb.
    #[must_use]
    pub fn run(self) -> std::process::ExitCode {
        let Self {
            slot,
            format,
            output,
            reader_filter,
            comment,
        } = self;
        let options = crate::card_pubkey::PubkeyOptions {
            slot,
            format,
            output,
            reader_filter,
            comment,
        };
        let backend = refineid_lib_pcsc::PcscBackend;
        match crate::card_pubkey::pubkey_all(backend, &options) {
            Ok(reports) => {
                for r in &reports {
                    print!("{r}");
                }
                crate::exit_status::ExitStatus::Ok.into()
            }
            Err(crate::card_pubkey::PubkeyError::NoReaders) => {
                eprintln!("no PC/SC readers connected");
                crate::exit_status::ExitStatus::NoReaders.into()
            }
            Err(crate::card_pubkey::PubkeyError::NoCardPresent) => {
                eprintln!("no card present in any reader");
                crate::exit_status::ExitStatus::NoCardPresent.into()
            }
            Err(e) => {
                eprintln!("card pubkey: {e}");
                crate::exit_status::ExitStatus::RuntimeFailure.into()
            }
        }
    }

    /// Parse the post-subcommand argv slice.
    ///
    /// # Errors
    /// [`ArgParseError`] for any shape violation, including
    /// `--slot` / `--format` values that aren't in the closed
    /// enum sets.
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let mut slot = PubkeySlot::Auth;
        let mut format = PubkeyFormat::Ssh;
        let mut output: Option<PathBuf> = None;
        let mut reader_filter: Option<String> = None;
        let mut comment: Option<String> = None;
        let tokens = argv.into_vec();
        let mut iter = tokens.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--slot" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardPubkey,
                        flag: "--slot",
                    })?;
                    slot = match value.as_str() {
                        "auth" => PubkeySlot::Auth,
                        "qualified" => PubkeySlot::Qualified,
                        other => {
                            return Err(ArgParseError::BadValue {
                                cmd: VerbTag::CardPubkey,
                                flag: "--slot",
                                value: other.to_owned(),
                                reason: "must be auth|qualified".to_owned(),
                            });
                        }
                    };
                }
                "--format" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardPubkey,
                        flag: "--format",
                    })?;
                    format = match value.as_str() {
                        "ssh" => PubkeyFormat::Ssh,
                        "pem" => PubkeyFormat::Pem,
                        other => {
                            return Err(ArgParseError::BadValue {
                                cmd: VerbTag::CardPubkey,
                                flag: "--format",
                                value: other.to_owned(),
                                reason: "must be ssh|pem".to_owned(),
                            });
                        }
                    };
                }
                "--out" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardPubkey,
                        flag: "--out",
                    })?;
                    output = Some(PathBuf::from(value));
                }
                "--reader" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardPubkey,
                        flag: "--reader",
                    })?;
                    reader_filter = Some(value.clone());
                }
                "--comment" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardPubkey,
                        flag: "--comment",
                    })?;
                    comment = Some(value.clone());
                }
                other => {
                    return Err(ArgParseError::Unexpected {
                        cmd: VerbTag::CardPubkey,
                        got: other.to_owned(),
                    });
                }
            }
        }
        Ok(Self {
            slot,
            format,
            output,
            reader_filter,
            comment,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::argv::fixtures::remaining_argv as argv;
    use crate::test_util::{TestResult, check, check_true};

    #[test]
    fn defaults_when_no_flags() -> TestResult {
        let a = PubkeyArgs::parse(argv(&[]))?;
        check(&a.slot, &PubkeySlot::Auth, "slot")?;
        check(&a.format, &PubkeyFormat::Ssh, "format")?;
        check_true(a.output.is_none(), "output=None")
    }

    #[test]
    fn slot_and_format_set() -> TestResult {
        let a = PubkeyArgs::parse(argv(&["--slot", "qualified", "--format", "pem"]))?;
        check(&a.slot, &PubkeySlot::Qualified, "slot")?;
        check(&a.format, &PubkeyFormat::Pem, "format")
    }

    #[test]
    fn bad_slot_value_rejected() -> TestResult {
        let r = PubkeyArgs::parse(argv(&["--slot", "root"]));
        check_true(
            matches!(r, Err(ArgParseError::BadValue { flag: "--slot", .. })),
            "BadValue(--slot)",
        )
    }

    #[test]
    fn bad_format_value_rejected() -> TestResult {
        let r = PubkeyArgs::parse(argv(&["--format", "xml"]));
        check_true(
            matches!(
                r,
                Err(ArgParseError::BadValue {
                    flag: "--format",
                    ..
                })
            ),
            "BadValue(--format)",
        )
    }

    #[test]
    fn out_path_recorded() -> TestResult {
        let a = PubkeyArgs::parse(argv(&["--out", "/tmp/k.pub"]))?;
        check(&a.output, &Some(PathBuf::from("/tmp/k.pub")), "output")
    }

    #[test]
    fn missing_flag_value_rejected() -> TestResult {
        let r = PubkeyArgs::parse(argv(&["--out"]));
        check_true(
            matches!(r, Err(ArgParseError::MissingValue { flag: "--out", .. })),
            "MissingValue(--out)",
        )
    }

    #[test]
    fn unknown_flag_rejected() -> TestResult {
        let r = PubkeyArgs::parse(argv(&["--bogus"]));
        check_true(
            matches!(r, Err(ArgParseError::Unexpected { .. })),
            "Unexpected",
        )
    }
}
