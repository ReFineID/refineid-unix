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

//! `verify` (offline signature verify) typed arguments.

use std::path::PathBuf;

use super::{ArgParseError, argv::RemainingArgv, verb::VerbTag};

/// Parsed `verify --cert PATH --in PATH --sig PATH` arguments.
/// All three are required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyArgs {
    /// Cert file (PEM or DER) carrying the public key to verify
    /// against (`--cert PATH`).
    pub cert: PathBuf,
    /// Original message file whose bytes were hashed and signed
    /// (`--in PATH`).
    pub message: PathBuf,
    /// Raw RSA-PKCS#1 v1.5 signature bytes (`--sig PATH`).
    pub signature: PathBuf,
}

impl VerifyArgs {
    /// Execute the `verify` (offline RSA verify) verb.
    #[must_use]
    pub fn run(self) -> std::process::ExitCode {
        let Self {
            cert,
            message,
            signature,
        } = self;
        let options = crate::verify::VerifyOptions {
            cert,
            message,
            signature,
        };
        match crate::verify::verify_offline(&options) {
            Ok(report) => {
                print!("{report}");
                if report.ok {
                    crate::exit_status::ExitStatus::Ok.into()
                } else {
                    crate::exit_status::ExitStatus::VerifyFailed.into()
                }
            }
            Err(e) => {
                eprintln!("verify: {e}");
                crate::exit_status::ExitStatus::RuntimeFailure.into()
            }
        }
    }

    /// Parse the post-subcommand argv slice.
    ///
    /// # Errors
    /// [`ArgParseError`] for any shape violation, including a
    /// missing required flag.
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let mut cert: Option<PathBuf> = None;
        let mut message: Option<PathBuf> = None;
        let mut signature: Option<PathBuf> = None;
        let tokens = argv.into_vec();
        let mut iter = tokens.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--cert" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::Verify,
                        flag: "--cert",
                    })?;
                    cert = Some(PathBuf::from(value));
                }
                "--in" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::Verify,
                        flag: "--in",
                    })?;
                    message = Some(PathBuf::from(value));
                }
                "--sig" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::Verify,
                        flag: "--sig",
                    })?;
                    signature = Some(PathBuf::from(value));
                }
                other => {
                    return Err(ArgParseError::Unexpected {
                        cmd: VerbTag::Verify,
                        got: other.to_owned(),
                    });
                }
            }
        }
        let cert = cert.ok_or(ArgParseError::Required {
            cmd: VerbTag::Verify,
            name: "--cert PATH",
        })?;
        let message = message.ok_or(ArgParseError::Required {
            cmd: VerbTag::Verify,
            name: "--in PATH",
        })?;
        let signature = signature.ok_or(ArgParseError::Required {
            cmd: VerbTag::Verify,
            name: "--sig PATH",
        })?;
        Ok(Self {
            cert,
            message,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::argv::fixtures::remaining_argv as argv;
    use crate::test_util::{TestResult, check, check_true};

    #[test]
    fn parses_all_three() -> TestResult {
        let a = VerifyArgs::parse(argv(&["--cert", "/c", "--in", "/m", "--sig", "/s"]))?;
        check(&a.cert, &PathBuf::from("/c"), "cert")?;
        check(&a.message, &PathBuf::from("/m"), "message")?;
        check(&a.signature, &PathBuf::from("/s"), "signature")
    }

    #[test]
    fn missing_cert_rejected() -> TestResult {
        let r = VerifyArgs::parse(argv(&["--in", "/m", "--sig", "/s"]));
        check_true(
            matches!(r, Err(ArgParseError::Required { name, .. }) if name == "--cert PATH"),
            "Required(--cert PATH)",
        )
    }

    #[test]
    fn missing_message_rejected() -> TestResult {
        let r = VerifyArgs::parse(argv(&["--cert", "/c", "--sig", "/s"]));
        check_true(
            matches!(r, Err(ArgParseError::Required { name, .. }) if name == "--in PATH"),
            "Required(--in PATH)",
        )
    }

    #[test]
    fn missing_signature_rejected() -> TestResult {
        let r = VerifyArgs::parse(argv(&["--cert", "/c", "--in", "/m"]));
        check_true(
            matches!(r, Err(ArgParseError::Required { name, .. }) if name == "--sig PATH"),
            "Required(--sig PATH)",
        )
    }
}
