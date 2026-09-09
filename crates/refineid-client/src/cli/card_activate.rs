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

//! `card activate` typed arguments.

use std::process::ExitCode;

/// Helpers hosted on a unit struct (typing-discipline: no
/// free fns with borrowed parameters; see
/// `doc/typing-discipline.md`).
struct CardActivateHelpers;

use refineid_lib_core::auth::UnblockOutcome;
use refineid_lib_core::pin::ActivationCode;

use super::{ArgParseError, argv::RemainingArgv, verb::VerbTag};
use crate::card_pin::{ActivateReport, ActivationCardContext, CardPinError, CardTrustAttestation};
use crate::exit_status::ExitStatus;

/// Parsed `card activate [--allow-reactivate] [--reader SUBSTR]`
/// arguments.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ActivateArgs {
    /// Override the pre-flight refusal on an apparently-
    /// activated card. Rarely the right answer; the prompt
    /// in the activate flow itself explains the trade-off.
    pub allow_reactivate: bool,
    /// Optional reader-name substring (`--reader SUBSTR`).
    /// Tier 0 `String`; presentational input to `ReaderFilter`.
    pub reader_filter: Option<String>,
}

/// CLI verb tag inserted into every operator-facing error
/// message. Lets `eprintln!` lines start with the standard
/// `"card activate: ..."` prefix without hard-coding the
/// string at each call site.
const CMD: &str = "card activate";

/// Env var consulted (alpha-period debug aid) for the 7-/8-digit
/// activation PIN before the interactive prompt. See
/// [`CardActivateHelpers::read_pin_env_or_prompt`] for the
/// semantics and the AGENTS.md §6 alpha exception.
const ENV_ACTIVATION_PIN: &str = "REFINEID_ACTIVATION_PIN";
/// Env var consulted (alpha-period debug aid) for the new PIN1
/// value before the interactive new-PIN prompt + confirm.
const ENV_NEW_PIN1: &str = "REFINEID_NEW_PIN1";
/// Env var consulted (alpha-period debug aid) for the new PIN2
/// value before the interactive new-PIN prompt + confirm.
const ENV_NEW_PIN2: &str = "REFINEID_NEW_PIN2";

impl ActivateArgs {
    /// Execute the `card activate` verb.
    #[must_use]
    pub fn run(self) -> ExitCode {
        let Self {
            allow_reactivate,
            reader_filter,
        } = self;
        let backend = refineid_lib_pcsc::PcscBackend;
        let typed_reader_filter = reader_filter
            .as_deref()
            .map(refineid_lib_core::backend::ReaderFilter::new);
        let ctx = match crate::card_pin::classify_card_for_activation(
            backend,
            typed_reader_filter.as_ref(),
        ) {
            Ok(c) => c,
            Err(CardPinError::ReaderPick(pe)) => {
                return super::util::reader_pick_exit(CMD, &pe);
            }
            Err(e) => {
                eprintln!("{CMD}: {e}");
                return ExitStatus::RuntimeFailure.into();
            }
        };
        let Some(expected_len) = ctx.expected_activation_pin_length() else {
            eprintln!(
                "{CMD}: couldn't classify card generation from auth cert; \
                 refusing to guess at activation PIN length"
            );
            return ExitStatus::RuntimeFailure.into();
        };
        CardActivateHelpers::warn_on_generation_disagreement(&ctx);
        CardActivateHelpers::emit_preflight_event(&ctx, expected_len);
        let activation_pin = match CardActivateHelpers::prompt_activation_pin(expected_len) {
            Ok(p) => p,
            Err(exit) => return exit,
        };
        let pin1_new = match super::util::new_pin_env_or_prompt(
            CMD,
            ENV_NEW_PIN1,
            "PIN1",
            Some("basic, 4-12 digits"),
        ) {
            Ok(p) => p,
            Err(exit) => return exit,
        };
        let pin2_new = match super::util::new_pin_env_or_prompt(
            CMD,
            ENV_NEW_PIN2,
            "PIN2",
            Some("signature, 6-12 digits"),
        ) {
            Ok(p) => p,
            Err(exit) => return exit,
        };
        let options = crate::card_pin::ActivateOptions {
            activation_pin,
            new_pin1: pin1_new,
            new_pin2: pin2_new,
            allow_reactivate,
        };
        drop(reader_filter);
        match crate::card_pin::activate_first(backend, ctx, options) {
            Ok(report) => {
                print!("{report}");
                CardActivateHelpers::activate_outcome_exit(&report)
            }
            Err(CardPinError::ReaderPick(pe)) => super::util::reader_pick_exit(CMD, &pe),
            Err(e @ CardPinError::PinPolicy(_)) => {
                eprintln!("{CMD}: {e}");
                ExitStatus::CardCredentialRejected.into()
            }
            Err(e) => {
                eprintln!("{CMD}: {e}");
                ExitStatus::RuntimeFailure.into()
            }
        }
    }

    /// Parse the post-subcommand argv slice.
    ///
    /// # Errors
    /// [`ArgParseError`] for any shape violation.
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let mut allow_reactivate = false;
        let mut reader_filter: Option<String> = None;
        let tokens = argv.into_vec();
        let mut iter = tokens.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--allow-reactivate" => allow_reactivate = true,
                "--reader" => {
                    let value = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardActivate,
                        flag: "--reader",
                    })?;
                    reader_filter = Some(value.clone());
                }
                other => {
                    return Err(ArgParseError::Unexpected {
                        cmd: VerbTag::CardActivate,
                        got: other.to_owned(),
                    });
                }
            }
        }
        Ok(Self {
            allow_reactivate,
            reader_filter,
        })
    }
}

/// Single-line note when the issuance-date generation verdict
/// disagrees with the issuer-CN heuristic. The issuance-date
/// verdict wins regardless; the line just records the
/// disagreement for the operator's log.
impl CardActivateHelpers {
    /// Print a one-line operator note when the two card-
    /// generation signals disagree.
    ///
    /// The card-issuance-date signal (FINEID S4-1 v4.2 §1.3
    /// table) and the auth-cert issuer-CN heuristic should
    /// usually agree on whether this is a 7- or 8-digit-PIN
    /// generation. Disagreement is uncommon but not fatal --
    /// the issuance-date verdict wins and the flow continues;
    /// the note exists so the discrepancy lands in the audit
    /// log.
    fn warn_on_generation_disagreement(ctx: &ActivationCardContext) {
        if ctx.generation != ctx.generation_by_issuer_cn
            && ctx.generation_by_issuer_cn != refineid_lib_core::pkcs15::CardGeneration::Unknown
        {
            eprintln!(
                "{CMD}: note: card generation by issuance-date ({:?}) disagrees with \
             issuer-CN heuristic ({:?}); proceeding with the issuance-date verdict",
                ctx.generation, ctx.generation_by_issuer_cn,
            );
        }
    }
}

/// Emit the JSONL pre-flight event with trust-state + card-model
/// metadata. The operator's `card activate` invocation flushes
/// this *before* the activation-PIN prompt so log scrapers can
/// pair the prompt with the targeted card.
impl CardActivateHelpers {
    /// Emit the `card.activate.preflight.ready` JSONL event.
    ///
    /// Captures the trust state, card-model facts, and the
    /// declared activation-PIN length *before* the operator
    /// is prompted for the PIN, so a downstream scraper can
    /// pair the JSONL line with the human prompt. Required by
    /// `doc/observability.md` -- the pre-flight event is part
    /// of the audit baseline.
    fn emit_preflight_event(ctx: &ActivationCardContext, expected_len: usize) {
        let (trust_root_label, trust_root_sha256_hex) = match &ctx.trust {
            CardTrustAttestation::PinnedRootMatched {
                root_label,
                root_sha256,
            } => (*root_label, format!("{root_sha256}")),
            CardTrustAttestation::PinnedRootMismatch { .. }
            | CardTrustAttestation::RootCertUnavailable { .. } => ("", String::new()),
        };
        let card_issued = format!(
            "{:04}-{:02}-{:02}",
            ctx.issuance_date.year(),
            ctx.issuance_date.month(),
            ctx.issuance_date.day(),
        );
        let activation_pin_length_str = format!("{expected_len}");
        let model = ctx.model;
        crate::events::CardActivatePreflightReady {
            trust_state: "pinned_root_matched",
            trust_root_label,
            trust_root_sha256: &trust_root_sha256_hex,
            card_issued: &card_issued,
            card_type: model.card_type().as_dvv_label(),
            card_vendor: model.vendor().as_dvv_label(),
            card_vendor_product: model.vendor_product(),
            card_vendor_product_version: model.vendor_product_version(),
            fineid_specification: model.fineid_specification(),
            fineid_specification_version: model.fineid_specification_version(),
            activation_pin_length: &activation_pin_length_str,
            wrong_tries_to_lock: "5",
            attempts_this_invocation: "1",
        }
        .emit();
    }
}

/// Prompt for the activation PIN and wrap it in the typed
/// [`ActivationCode`] variant that matches `expected_len` (7
/// for current-generation DVV cards, 8 for legacy). Either
/// length-typed constructor rejects a mistyped value at the
/// trust boundary so the activate call only sees the in-shape
/// form.
impl CardActivateHelpers {
    /// Prompt for the activation PIN and lift it into the
    /// length-typed [`ActivationCode`] variant.
    ///
    /// FINEID S4-1 §4.6 -- 7 digits for newer cards, 8 for
    /// older. The length-typed constructor rejects out-of-shape
    /// input at the trust boundary so downstream code only
    /// ever sees an in-shape value. An "unexpected length
    /// contract" return is a host bug, not a card outcome --
    /// the calling site should already have classified the
    /// generation.
    fn prompt_activation_pin(expected_len: usize) -> Result<ActivationCode, ExitCode> {
        let prompt = format!("activation PIN ({expected_len} digits): ");
        let raw = super::util::pin_env_or_prompt(CMD, ENV_ACTIVATION_PIN, &prompt)?;
        match expected_len {
            7 => refineid_lib_core::pin::ActivationPinSeven::new(raw)
                .map(ActivationCode::Seven)
                .map_err(|e| {
                    eprintln!("{CMD}: activation PIN: {e}");
                    ExitCode::from(ExitStatus::BadInvocation)
                }),
            8 => refineid_lib_core::pin::ActivationPinEight::new(raw)
                .map(ActivationCode::Eight)
                .map_err(|e| {
                    eprintln!("{CMD}: activation PIN: {e}");
                    ExitCode::from(ExitStatus::BadInvocation)
                }),
            other => {
                eprintln!("{CMD}: unexpected activation PIN length contract: {other}");
                Err(ExitStatus::RuntimeFailure.into())
            }
        }
    }
}

/// Map the card-side per-PIN outcome pair to the project's exit
/// status convention:
///
/// - Both PINs Ok -> `Ok`.
/// - Pre-flight refused (rerun with `--allow-reactivate`) ->
///   `NoReaders` (no-cards-applied "config-like" exit; not a
///   hard failure).
/// - Either PIN rejected by card (wrong PUK / locked /
///   invalidated) -> `CardCredentialRejected`.
/// - Anything else -> `RuntimeFailure`.
impl CardActivateHelpers {
    /// Translate the [`ActivateReport`] into an
    /// [`ExitStatus`].
    ///
    /// `Ok` only when both PINs succeeded; otherwise the
    /// mapping is per the project exit-status contract:
    /// pre-flight refusal -> `NoReaders`,
    /// `WrongPuk`/`PukLocked`/`Invalidated` ->
    /// `CardCredentialRejected`, anything else ->
    /// `RuntimeFailure`. The mapping table is the single
    /// source of truth; the CLI shell honours it for the
    /// process exit code.
    fn activate_outcome_exit(report: &ActivateReport) -> ExitCode {
        match (&report.pin1_outcome, &report.pin2_outcome) {
            (Some(UnblockOutcome::Ok), Some(UnblockOutcome::Ok)) => ExitStatus::Ok.into(),
            (None, None) => ExitStatus::NoReaders.into(),
            (Some(o1), o2)
                if matches!(
                    o1,
                    UnblockOutcome::WrongPuk { .. }
                        | UnblockOutcome::PukLocked
                        | UnblockOutcome::Invalidated
                ) || matches!(
                    o2,
                    Some(
                        UnblockOutcome::WrongPuk { .. }
                            | UnblockOutcome::PukLocked
                            | UnblockOutcome::Invalidated
                    )
                ) =>
            {
                ExitStatus::CardCredentialRejected.into()
            }
            _ => ExitStatus::RuntimeFailure.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::argv::fixtures::remaining_argv as argv;
    use crate::test_util::{TestResult, check, check_true};

    #[test]
    fn defaults() -> TestResult {
        let a = ActivateArgs::parse(argv(&[]))?;
        check_true(!a.allow_reactivate, "allow_reactivate=false")?;
        check_true(a.reader_filter.is_none(), "reader_filter=None")
    }

    #[test]
    fn parses_allow_reactivate_and_reader() -> TestResult {
        let a = ActivateArgs::parse(argv(&["--allow-reactivate", "--reader", "ACS"]))?;
        check_true(a.allow_reactivate, "allow_reactivate=true")?;
        check(&a.reader_filter.as_deref(), &Some("ACS"), "reader_filter")
    }

    #[test]
    fn unknown_flag_rejected() -> TestResult {
        let r = ActivateArgs::parse(argv(&["--enforce-strong"]));
        check_true(
            matches!(r, Err(ArgParseError::Unexpected { .. })),
            "Unexpected(--enforce-strong)",
        )
    }
}
