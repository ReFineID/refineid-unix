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

//! `cert chain` typed arguments.

use std::path::PathBuf;

use super::{ArgParseError, argv::RemainingArgv, verb::VerbTag};

/// Parsed `cert chain CERT [--issuer-dir DIR] [--aia-fetch]`
/// arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertChainArgs {
    /// Path to the leaf cert (the `CERT` positional). The chain
    /// walk starts here and proceeds upward toward a self-signed
    /// root.
    pub leaf: PathBuf,
    /// Optional on-disk pool of issuer certs (`--issuer-dir DIR`).
    /// Searched first at every hop; AIA-fetch is the fallback.
    pub issuer_dir: Option<PathBuf>,
    /// When `true`, missing issuers trigger an HTTP fetch against
    /// the child's RFC 5280 §4.2.2.1 `caIssuers` AIA URL.
    pub aia_fetch: bool,
}

impl CertChainArgs {
    /// Execute the `cert chain` verb.
    #[must_use]
    pub fn run(self) -> std::process::ExitCode {
        let Self {
            leaf,
            issuer_dir,
            aia_fetch,
        } = self;
        match crate::cert_chain::walk_chain(&leaf, issuer_dir.as_deref(), aia_fetch) {
            Ok(report) => {
                print!("{report}");
                if report.reaches_self_signed_root {
                    crate::exit_status::ExitStatus::Ok.into()
                } else {
                    crate::exit_status::ExitStatus::VerifyFailed.into()
                }
            }
            Err(e) => {
                eprintln!("cert chain: {e}");
                crate::exit_status::ExitStatus::RuntimeFailure.into()
            }
        }
    }

    /// Parse the post-subcommand argv slice.
    ///
    /// # Errors
    /// [`ArgParseError`] for any shape violation, including a
    /// missing positional `CERT`.
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let mut leaf: Option<PathBuf> = None;
        let mut issuer_dir: Option<PathBuf> = None;
        let mut aia_fetch = false;
        let tokens = argv.into_vec();
        let mut iter = tokens.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--issuer-dir" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CertChain,
                        flag: "--issuer-dir",
                    })?;
                    issuer_dir = Some(PathBuf::from(value));
                }
                "--aia-fetch" => aia_fetch = true,
                other if !other.starts_with('-') && leaf.is_none() => {
                    leaf = Some(PathBuf::from(other));
                }
                other => {
                    return Err(ArgParseError::Unexpected {
                        cmd: VerbTag::CertChain,
                        got: other.to_owned(),
                    });
                }
            }
        }
        let leaf = leaf.ok_or(ArgParseError::Required {
            cmd: VerbTag::CertChain,
            name: "CERT (positional leaf cert)",
        })?;
        Ok(Self {
            leaf,
            issuer_dir,
            aia_fetch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::argv::fixtures::remaining_argv as argv;
    use crate::test_util::{TestResult, check, check_true};

    #[test]
    fn parses_leaf_only() -> TestResult {
        let a = CertChainArgs::parse(argv(&["/tmp/leaf.der"]))?;
        check(&a.leaf, &PathBuf::from("/tmp/leaf.der"), "leaf")?;
        check_true(a.issuer_dir.is_none(), "issuer_dir=None")?;
        check_true(!a.aia_fetch, "aia_fetch=false")
    }

    #[test]
    fn parses_leaf_with_issuer_dir() -> TestResult {
        let a = CertChainArgs::parse(argv(&["/leaf", "--issuer-dir", "/issuers"]))?;
        check(
            &a.issuer_dir,
            &Some(PathBuf::from("/issuers")),
            "issuer_dir",
        )
    }

    #[test]
    fn aia_fetch_is_flag() -> TestResult {
        let a = CertChainArgs::parse(argv(&["/leaf", "--aia-fetch"]))?;
        check_true(a.aia_fetch, "aia_fetch=true")
    }

    #[test]
    fn missing_leaf_rejected() -> TestResult {
        let r = CertChainArgs::parse(argv(&[]));
        check_true(matches!(r, Err(ArgParseError::Required { .. })), "Required")
    }
}
