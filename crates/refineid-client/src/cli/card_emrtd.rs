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

//! `card emrtd` typed arguments.

use std::path::PathBuf;

use refineid_lib_core::can::Can;

use super::{ArgParseError, argv::RemainingArgv, verb::VerbTag};

/// Parsed `card emrtd --can NNNNNN [--save-face PATH]
/// [--save-signature PATH] [--save-sod PATH] [--save-dsc PATH]
/// [--csca-dir DIR] [--reader SUBSTR]` arguments.
///
/// `can` is the typed [`Can`] -- the 6-digit value is
/// validated at this trust boundary via `Can::new`, so the
/// emrtd action never sees an out-of-shape CAN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmrtdArgs {
    /// Six-digit Card Access Number from the card front
    /// (`--can NNNNNN`). Already validated by `Can::new` at
    /// parse time.
    pub can: Can,
    /// Optional path to save DG2 face image (`--save-face PATH`).
    pub save_face: Option<PathBuf>,
    /// Optional path to save DG7 displayed signature image
    /// (`--save-signature PATH`).
    pub save_signature: Option<PathBuf>,
    /// Optional path to save the EF.SOD CMS `SignedData` bytes
    /// (`--save-sod PATH`). Useful for offline PA verification.
    pub save_sod: Option<PathBuf>,
    /// Optional path to save the Document Signer Certificate
    /// extracted from EF.SOD (`--save-dsc PATH`).
    pub save_dsc: Option<PathBuf>,
    /// Optional trusted-CSCA pool directory (`--csca-dir DIR`)
    /// for the DSC -> CSCA hop in Passive Authentication.
    pub csca_dir: Option<PathBuf>,
    /// Optional substring match against reader names
    /// (`--reader SUBSTR`). Tier 0 `String`; presentational
    /// input to `ReaderFilter::new`.
    pub reader_filter: Option<String>,
}

impl EmrtdArgs {
    /// Execute the `card emrtd` verb.
    #[must_use]
    pub fn run(self) -> std::process::ExitCode {
        let Self {
            can,
            save_face,
            save_signature,
            save_sod,
            save_dsc,
            csca_dir,
            reader_filter,
        } = self;
        let backend = refineid_lib_pcsc::PcscBackend;
        let options = crate::card_emrtd::EmrtdReadOptions {
            can,
            save_face,
            save_sod,
            save_dsc,
            save_signature,
            csca_dir,
            reader_filter,
        };
        match crate::card_emrtd::read_first(backend, &options) {
            Ok(report) => {
                print!("{report}");
                crate::exit_status::ExitStatus::Ok.into()
            }
            Err(crate::card_emrtd::EmrtdReadError::ReaderPick(pe)) => {
                super::util::reader_pick_exit("card emrtd", &pe)
            }
            Err(e) => {
                eprintln!("card emrtd: {e}");
                crate::exit_status::ExitStatus::RuntimeFailure.into()
            }
        }
    }

    /// Parse the post-subcommand argv slice.
    ///
    /// # Errors
    /// [`ArgParseError`] for any shape violation, including
    /// missing required `--can` or a CAN value that doesn't
    /// pass `Can::new`.
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let mut can_raw: Option<String> = None;
        let mut save_face: Option<PathBuf> = None;
        let mut save_signature: Option<PathBuf> = None;
        let mut save_sod: Option<PathBuf> = None;
        let mut save_dsc: Option<PathBuf> = None;
        let mut csca_dir: Option<PathBuf> = None;
        let mut reader_filter: Option<String> = None;
        let tokens = argv.into_vec();
        let mut iter = tokens.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--can" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardEmrtd,
                        flag: "--can",
                    })?;
                    can_raw = Some(value.clone());
                }
                "--save-face" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardEmrtd,
                        flag: "--save-face",
                    })?;
                    save_face = Some(PathBuf::from(value));
                }
                "--save-signature" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardEmrtd,
                        flag: "--save-signature",
                    })?;
                    save_signature = Some(PathBuf::from(value));
                }
                "--save-sod" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardEmrtd,
                        flag: "--save-sod",
                    })?;
                    save_sod = Some(PathBuf::from(value));
                }
                "--save-dsc" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardEmrtd,
                        flag: "--save-dsc",
                    })?;
                    save_dsc = Some(PathBuf::from(value));
                }
                "--csca-dir" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardEmrtd,
                        flag: "--csca-dir",
                    })?;
                    csca_dir = Some(PathBuf::from(value));
                }
                "--reader" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardEmrtd,
                        flag: "--reader",
                    })?;
                    reader_filter = Some(value.clone());
                }
                other => {
                    return Err(ArgParseError::Unexpected {
                        cmd: VerbTag::CardEmrtd,
                        got: other.to_owned(),
                    });
                }
            }
        }
        let can_raw = can_raw.ok_or(ArgParseError::Required {
            cmd: VerbTag::CardEmrtd,
            name: "--can NNNNNN",
        })?;
        let can = Can::new(&can_raw).map_err(|e| ArgParseError::BadValue {
            cmd: VerbTag::CardEmrtd,
            flag: "--can",
            value: can_raw,
            reason: format!("{e}"),
        })?;
        Ok(Self {
            can,
            save_face,
            save_signature,
            save_sod,
            save_dsc,
            csca_dir,
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
    fn parses_can_only() -> TestResult {
        let a = EmrtdArgs::parse(argv(&["--can", "123456"]))?;
        check_true(a.save_face.is_none(), "save_face=None")?;
        check_true(a.csca_dir.is_none(), "csca_dir=None")
        // SPECIMEN-TRAVEL CAN is 797449; pick a generic in-shape value
        // for the unit test.
    }

    #[test]
    fn missing_can_rejected() -> TestResult {
        let r = EmrtdArgs::parse(argv(&[]));
        check_true(
            matches!(r, Err(ArgParseError::Required { name, .. }) if name == "--can NNNNNN"),
            "Required(--can NNNNNN)",
        )
    }

    #[test]
    fn malformed_can_rejected() -> TestResult {
        let r = EmrtdArgs::parse(argv(&["--can", "abc"]));
        check_true(
            matches!(r, Err(ArgParseError::BadValue { flag: "--can", .. })),
            "BadValue(--can)",
        )
    }

    #[test]
    fn save_paths_recorded() -> TestResult {
        let a = EmrtdArgs::parse(argv(&[
            "--can",
            "123456",
            "--save-face",
            "/f",
            "--save-sod",
            "/s",
        ]))?;
        check(&a.save_face, &Some(PathBuf::from("/f")), "save_face")?;
        check(&a.save_sod, &Some(PathBuf::from("/s")), "save_sod")
    }
}
