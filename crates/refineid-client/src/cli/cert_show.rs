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

//! `cert show` typed arguments.

use std::path::PathBuf;

use super::{ArgParseError, argv::RemainingArgv, verb::VerbTag};

/// Parsed `cert show PATH` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertShowArgs {
    /// Filesystem path to the cert file to load. Wire form (DER
    /// vs PEM) is sniffed at decode time.
    pub path: PathBuf,
}

impl CertShowArgs {
    /// Execute the `cert show` verb.
    #[must_use]
    pub fn run(self) -> std::process::ExitCode {
        let Self { path } = self;
        match crate::cert_show::show_cert(&path) {
            Ok(report) => {
                print!("{report}");
                crate::exit_status::ExitStatus::Ok.into()
            }
            Err(e) => {
                eprintln!("cert show: {e}");
                crate::exit_status::ExitStatus::RuntimeFailure.into()
            }
        }
    }

    /// Parse the post-subcommand argv slice. Accepts exactly
    /// one positional `PATH`; no flags.
    ///
    /// # Errors
    /// [`ArgParseError`] when zero or more-than-one positional
    /// is given, or any flag is supplied.
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let tokens = argv.into_vec();
        match tokens.as_slice() {
            [path] => {
                if path.starts_with('-') {
                    return Err(ArgParseError::Unexpected {
                        cmd: VerbTag::CertShow,
                        got: path.clone(),
                    });
                }
                Ok(Self {
                    path: PathBuf::from(path),
                })
            }
            [] => Err(ArgParseError::Required {
                cmd: VerbTag::CertShow,
                name: "PATH (positional cert file)",
            }),
            [_, second, ..] => Err(ArgParseError::Unexpected {
                cmd: VerbTag::CertShow,
                got: second.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::argv::fixtures::remaining_argv as argv;
    use crate::test_util::{TestResult, check, check_true};

    #[test]
    fn parses_single_path() -> TestResult {
        let a = CertShowArgs::parse(argv(&["/tmp/auth.der"]))?;
        check(&a.path, &PathBuf::from("/tmp/auth.der"), "path")
    }

    #[test]
    fn missing_path_rejected() -> TestResult {
        let r = CertShowArgs::parse(argv(&[]));
        check_true(matches!(r, Err(ArgParseError::Required { .. })), "Required")
    }

    #[test]
    fn extra_positional_rejected() -> TestResult {
        let r = CertShowArgs::parse(argv(&["a", "b"]));
        check_true(
            matches!(r, Err(ArgParseError::Unexpected { .. })),
            "Unexpected",
        )
    }

    #[test]
    fn leading_dash_rejected_as_flag() -> TestResult {
        let r = CertShowArgs::parse(argv(&["--foo"]));
        check_true(
            matches!(r, Err(ArgParseError::Unexpected { .. })),
            "Unexpected",
        )
    }
}
