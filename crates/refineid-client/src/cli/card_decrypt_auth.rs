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

//! `card decrypt-auth` typed arguments.

use std::path::PathBuf;

use super::{ArgParseError, argv::RemainingArgv, verb::VerbTag};

/// Parsed `card decrypt-auth --in PATH --out PATH
/// [--reader SUBSTR]` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptAuthArgs {
    /// Input ciphertext file (`--in PATH`); must be exactly the
    /// RSA-3072 modulus length (384 bytes).
    pub input: PathBuf,
    /// Output plaintext file (`--out PATH`); receives the
    /// PKCS#1 v1.5-unpadded plaintext payload.
    pub output: PathBuf,
    /// Optional reader-name substring (`--reader SUBSTR`).
    /// Tier 0 `String`; presentational input to `ReaderFilter`.
    pub reader_filter: Option<String>,
}

impl DecryptAuthArgs {
    /// Execute the `card decrypt-auth` verb.
    #[must_use]
    pub fn run(self) -> std::process::ExitCode {
        let Self {
            input,
            output,
            reader_filter,
        } = self;
        let cmd = "card decrypt-auth";
        let pin = match super::util::prompt_pin(cmd, "PIN1: ") {
            Ok(p) => p,
            Err(exit) => return exit,
        };
        let options = crate::card_decrypt::DecryptAuthOptions {
            input,
            output,
            pin,
            reader_filter,
        };
        let backend = refineid_lib_pcsc::PcscBackend;
        match crate::card_decrypt::decrypt_auth_first(backend, options) {
            Ok(report) => {
                print!("{report}");
                crate::exit_status::ExitStatus::Ok.into()
            }
            Err(crate::card_decrypt::DecryptAuthError::ReaderPick(pe)) => {
                super::util::reader_pick_exit(cmd, &pe)
            }
            Err(e)
                if matches!(
                    &e,
                    crate::card_decrypt::DecryptAuthError::PinRejected(_)
                        | crate::card_decrypt::DecryptAuthError::PinPolicy(_)
                ) =>
            {
                eprintln!("{cmd}: {e}");
                if matches!(
                    &e,
                    crate::card_decrypt::DecryptAuthError::PinRejected(
                        refineid_lib_core::auth::VerifyOutcome::Locked
                    )
                ) {
                    eprintln!("  -> use the PUK to unblock PIN1 before retrying");
                }
                crate::exit_status::ExitStatus::CardCredentialRejected.into()
            }
            Err(e) => {
                eprintln!("{cmd}: {e}");
                crate::exit_status::ExitStatus::RuntimeFailure.into()
            }
        }
    }

    /// Parse the post-subcommand argv slice.
    ///
    /// # Errors
    /// [`ArgParseError`] for any shape violation, including
    /// missing required `--in` / `--out`.
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let mut input: Option<PathBuf> = None;
        let mut output: Option<PathBuf> = None;
        let mut reader_filter: Option<String> = None;
        let tokens = argv.into_vec();
        let mut iter = tokens.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--in" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardDecryptAuth,
                        flag: "--in",
                    })?;
                    input = Some(PathBuf::from(value));
                }
                "--out" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardDecryptAuth,
                        flag: "--out",
                    })?;
                    output = Some(PathBuf::from(value));
                }
                "--reader" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardDecryptAuth,
                        flag: "--reader",
                    })?;
                    reader_filter = Some(value.clone());
                }
                other => {
                    return Err(ArgParseError::Unexpected {
                        cmd: VerbTag::CardDecryptAuth,
                        got: other.to_owned(),
                    });
                }
            }
        }
        let input = input.ok_or(ArgParseError::Required {
            cmd: VerbTag::CardDecryptAuth,
            name: "--in PATH",
        })?;
        let output = output.ok_or(ArgParseError::Required {
            cmd: VerbTag::CardDecryptAuth,
            name: "--out PATH",
        })?;
        Ok(Self {
            input,
            output,
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
    fn parses_required_in_and_out() -> TestResult {
        let a = DecryptAuthArgs::parse(argv(&["--in", "/tmp/i", "--out", "/tmp/o"]))?;
        check(&a.input, &PathBuf::from("/tmp/i"), "input")?;
        check(&a.output, &PathBuf::from("/tmp/o"), "output")
    }

    #[test]
    fn missing_input_rejected() -> TestResult {
        let r = DecryptAuthArgs::parse(argv(&["--out", "/tmp/o"]));
        check_true(
            matches!(r, Err(ArgParseError::Required { name, .. }) if name == "--in PATH"),
            "Required(--in PATH)",
        )
    }

    #[test]
    fn missing_output_rejected() -> TestResult {
        let r = DecryptAuthArgs::parse(argv(&["--in", "/tmp/i"]));
        check_true(
            matches!(r, Err(ArgParseError::Required { name, .. }) if name == "--out PATH"),
            "Required(--out PATH)",
        )
    }
}
