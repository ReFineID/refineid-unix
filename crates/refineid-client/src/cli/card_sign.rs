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

//! `card sign-auth` / `card sign-qualified` typed arguments.

use std::path::PathBuf;

use refineid_lib_core::can::Can;

use super::{ArgParseError, argv::RemainingArgv, verb::VerbTag};
use crate::card_sign::SignSlot;

/// Parsed `card sign-{auth,qualified} --in PATH --out PATH
/// [--save-cert PATH] [--reader SUBSTR] [--can NNNNNN]`
/// arguments.
///
/// `slot` is set by the dispatcher at parse time: which
/// subcommand fired (`sign-auth` vs `sign-qualified`) is the
/// only signal for the PIN1-gated auth slot vs the PIN2-gated
/// qualified-signature slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignArgs {
    /// Which sign slot the operation targets; set by the
    /// dispatcher at parse time based on which subcommand fired.
    pub slot: SignSlot,
    /// Input message file (`--in PATH`); whole-file load, then
    /// SHA-256 + on-card sign.
    pub input: PathBuf,
    /// Output path for the raw RSA-PKCS#1 v1.5 signature bytes
    /// (`--out PATH`).
    pub output: PathBuf,
    /// Optional output path for the on-card cert DER
    /// (`--save-cert PATH`). When set, pairs the signature with
    /// the cert it can be verified against.
    pub save_cert: Option<PathBuf>,
    /// Optional substring match against reader names
    /// (`--reader SUBSTR`). Required when more than one card is
    /// present; the picker errors out rather than guess. Tier 0
    /// `String`; presentational input to `ReaderFilter::new`.
    pub reader_filter: Option<String>,
    /// Optional Card Access Number (`--can NNNNNN`) for signing
    /// over the contactless interface, where the card seals
    /// PKCS#15 behind PACE. Left `None` on the contact
    /// interface; when the seal is hit without it, `run` prompts
    /// on a TTY and retries.
    pub can: Option<Can>,
}

impl SignArgs {
    /// Execute the `card sign-{auth,qualified}` verb.
    #[must_use]
    pub fn run(self) -> std::process::ExitCode {
        let Self {
            slot,
            input,
            output,
            save_cert,
            reader_filter,
            can,
        } = self;
        let (sub, pin_prompt, env_var) = match slot {
            SignSlot::Auth => (VerbTag::CardSignAuth, "PIN1: ", "REFINEID_PIN1"),
            SignSlot::Qualified => (VerbTag::CardSignQualified, "PIN2: ", "REFINEID_PIN2"),
        };
        let cmd = sub.label();
        let pin = match super::util::pin_env_or_prompt(cmd, env_var, pin_prompt) {
            Ok(p) => p,
            Err(exit) => return exit,
        };
        let backend = refineid_lib_pcsc::PcscBackend;
        let run_once = |can: Option<Can>| {
            let options = crate::card_sign::SignOptions {
                input: input.clone(),
                output: output.clone(),
                pin: pin.clone(),
                save_cert: save_cert.clone(),
                reader_filter: reader_filter.clone(),
                can,
                // The bare verbs produce signature bytes; the format
                // choice lives in `card sign-document`.
                document: None,
            };
            match slot {
                SignSlot::Auth => crate::card_sign::sign_auth_first(backend, options),
                SignSlot::Qualified => crate::card_sign::sign_qualified_first(backend, options),
            }
        };
        let mut result = run_once(can);
        // Contactless card and no CAN yet: the card told us
        // PKCS#15 is sealed behind PACE. Prompt (TTY only) and
        // retry once. Nothing has touched the PIN counter at
        // this point -- the seal is reported by the very first
        // SELECT, long before VERIFY.
        if matches!(result, Err(crate::card_sign::SignErrorKind::NeedCan))
            && let Some(prompted) = super::util::prompt_can_if_tty()
        {
            result = run_once(Some(prompted));
        }
        match result {
            Ok(report) => {
                print!("{report}");
                // Failed local verify is a sign-flow failure; Skipped
                // (e.g. ECDSA P-384 local verify not yet wired) is
                // not -- the card-side sign chain still completed.
                if report.local_verify.is_failed() {
                    crate::exit_status::ExitStatus::RuntimeFailure.into()
                } else {
                    crate::exit_status::ExitStatus::Ok.into()
                }
            }
            Err(crate::card_sign::SignErrorKind::ReaderPick(pe)) => {
                super::util::reader_pick_exit(cmd, &pe)
            }
            Err(e)
                if matches!(
                    &e,
                    crate::card_sign::SignErrorKind::PinRejected { .. }
                        | crate::card_sign::SignErrorKind::PinPolicy { .. }
                ) =>
            {
                eprintln!("{cmd}: {e}");
                if matches!(
                    &e,
                    crate::card_sign::SignErrorKind::PinRejected {
                        outcome: refineid_lib_core::auth::VerifyOutcome::Locked,
                        ..
                    }
                ) {
                    eprintln!("  -> use the PUK to unblock before retrying");
                }
                crate::exit_status::ExitStatus::CardCredentialRejected.into()
            }
            Err(e) => {
                eprintln!("{cmd}: {e}");
                crate::exit_status::ExitStatus::RuntimeFailure.into()
            }
        }
    }

    /// Parse the post-subcommand argv slice for the given
    /// `slot`. The caller (the verb dispatcher) selects the
    /// slot from which subcommand fired and we carry it into
    /// the typed [`SignArgs`] so [`Self::run`] needs no extra
    /// argument.
    ///
    /// # Errors
    /// [`ArgParseError`] for any shape violation, including
    /// missing required `--in` / `--out`.
    pub fn parse(slot: SignSlot, argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let cmd = match slot {
            SignSlot::Auth => VerbTag::CardSignAuth,
            SignSlot::Qualified => VerbTag::CardSignQualified,
        };
        let mut input: Option<PathBuf> = None;
        let mut output: Option<PathBuf> = None;
        let mut save_cert: Option<PathBuf> = None;
        let mut reader_filter: Option<String> = None;
        let mut can_raw: Option<String> = None;
        let tokens = argv.into_vec();
        let mut iter = tokens.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--in" => {
                    let value = iter
                        .next()
                        .ok_or(ArgParseError::MissingValue { cmd, flag: "--in" })?;
                    input = Some(PathBuf::from(value));
                }
                "--out" => {
                    let value = iter
                        .next()
                        .ok_or(ArgParseError::MissingValue { cmd, flag: "--out" })?;
                    output = Some(PathBuf::from(value));
                }
                "--save-cert" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd,
                        flag: "--save-cert",
                    })?;
                    save_cert = Some(PathBuf::from(value));
                }
                "--reader" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd,
                        flag: "--reader",
                    })?;
                    reader_filter = Some(value.clone());
                }
                "--can" => {
                    let value = iter
                        .next()
                        .ok_or(ArgParseError::MissingValue { cmd, flag: "--can" })?;
                    can_raw = Some(value.clone());
                }
                other => {
                    return Err(ArgParseError::Unexpected {
                        cmd,
                        got: other.to_owned(),
                    });
                }
            }
        }
        let input = input.ok_or(ArgParseError::Required {
            cmd,
            name: "--in PATH",
        })?;
        let output = output.ok_or(ArgParseError::Required {
            cmd,
            name: "--out PATH",
        })?;
        // Optional here, unlike `card emrtd`: the contact
        // interface needs no CAN at all, and on contactless the
        // run loop prompts when the card reports the PACE seal.
        let can = can_raw
            .map(|raw| {
                Can::new(&raw).map_err(|e| ArgParseError::BadValue {
                    cmd,
                    flag: "--can",
                    value: raw.clone(),
                    reason: format!("{e}"),
                })
            })
            .transpose()?;
        Ok(Self {
            slot,
            input,
            output,
            save_cert,
            reader_filter,
            can,
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
        let a = SignArgs::parse(SignSlot::Auth, argv(&["--in", "/tmp/i", "--out", "/tmp/o"]))?;
        check(&a.input, &PathBuf::from("/tmp/i"), "input")?;
        check(&a.output, &PathBuf::from("/tmp/o"), "output")?;
        check(&a.slot, &SignSlot::Auth, "slot")
    }

    #[test]
    fn missing_input_rejected() -> TestResult {
        let r = SignArgs::parse(SignSlot::Auth, argv(&["--out", "/tmp/o"]));
        check_true(
            matches!(r, Err(ArgParseError::Required { name, .. }) if name == "--in PATH"),
            "Required(--in PATH)",
        )
    }

    #[test]
    fn missing_output_rejected() -> TestResult {
        let r = SignArgs::parse(SignSlot::Qualified, argv(&["--in", "/tmp/i"]));
        check_true(
            matches!(r, Err(ArgParseError::Required { name, .. }) if name == "--out PATH"),
            "Required(--out PATH)",
        )
    }

    #[test]
    fn save_cert_optional() -> TestResult {
        let a = SignArgs::parse(
            SignSlot::Auth,
            argv(&["--in", "/tmp/i", "--out", "/tmp/o", "--save-cert", "/tmp/c"]),
        )?;
        check(&a.save_cert, &Some(PathBuf::from("/tmp/c")), "save_cert")
    }

    #[test]
    fn qualified_slot_captured() -> TestResult {
        let a = SignArgs::parse(
            SignSlot::Qualified,
            argv(&["--in", "/tmp/i", "--out", "/tmp/o"]),
        )?;
        check(&a.slot, &SignSlot::Qualified, "slot")
    }

    /// `--can` is optional: the contact interface needs none, and
    /// on contactless `run` prompts when the card reports the
    /// PACE seal. Absent must parse to `None`, not a failure.
    #[test]
    fn can_absent_is_none() -> TestResult {
        let a = SignArgs::parse(SignSlot::Auth, argv(&["--in", "/tmp/i", "--out", "/tmp/o"]))?;
        check(&a.can, &None, "can")
    }

    #[test]
    fn can_parsed_when_supplied() -> TestResult {
        let a = SignArgs::parse(
            SignSlot::Auth,
            argv(&["--in", "/tmp/i", "--out", "/tmp/o", "--can", "123456"]),
        )?;
        check_true(a.can.is_some(), "can parsed")
    }

    /// A malformed CAN is rejected at parse time, before any
    /// card contact -- same boundary as `card emrtd`.
    #[test]
    fn bad_can_rejected_at_parse() -> TestResult {
        let r = SignArgs::parse(
            SignSlot::Auth,
            argv(&["--in", "/tmp/i", "--out", "/tmp/o", "--can", "12x456"]),
        );
        check_true(r.is_err(), "malformed CAN rejected")
    }
}
