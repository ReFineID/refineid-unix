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

//! `card sign-document` typed arguments.
//!
//! The bare `card sign-{auth,qualified}` verbs hand back the signature
//! the card computed and nothing else, which is only useful to someone
//! who already knows what to wrap it in. This produces the wrapped
//! form: a signed PDF, a container, a `CMS` structure -- something a
//! counterparty can open.

use std::path::PathBuf;

use refineid_lib_core::can::Can;
use refineid_lib_core::sign::cades::SigningTime;
use refineid_lib_core::sign::document::Format;
use refineid_lib_core::sign::pades::SignatureMetadata;

use super::{ArgParseError, argv::RemainingArgv, verb::VerbTag};
use crate::card_sign::{
    DEFAULT_TIMESTAMP_AUTHORITY, DocumentRequest, EU_QUALIFIED_TIMESTAMP_AUTHORITIES, SignSlot,
};

/// This verb's tag, for error messages.
const CMD: VerbTag = VerbTag::CardSignDocument;

/// Parsed `card sign-document --format F --in PATH [--in PATH ...]
/// --out PATH [--slot auth|qualified] [--reason TEXT]
/// [--location TEXT] [--reader SUBSTR] [--can NNNNNN]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignDocumentArgs {
    /// Which format to produce (`--format`).
    pub format: Format,
    /// Files to sign, in the order given (`--in`, repeatable).
    pub inputs: Vec<PathBuf>,
    /// Where the finished document goes (`--out`).
    pub output: PathBuf,
    /// Which key signs.
    ///
    /// Defaults to the qualified-signature slot. That is the one whose
    /// certificate carries a non-repudiation key usage, which is what
    /// makes the result a signature rather than a proof of presence;
    /// the authentication key is available for the cases where a
    /// counterparty asks for it specifically.
    pub slot: SignSlot,
    /// `PAdES` `/Reason` (`--reason`).
    pub reason: Option<String>,
    /// `PAdES` `/Location` (`--location`).
    pub location: Option<String>,
    /// Optional substring match against reader names (`--reader`).
    pub reader_filter: Option<String>,
    /// Card Access Number for contactless (`--can`).
    pub can: Option<Can>,
    /// Add an archive timestamp over the finished document
    /// (`--archive`). Implies `--long-term`.
    ///
    /// `PAdES` archives with a document timestamp revision; `ASiC-E`
    /// with `CAdES` archives with a second manifest and a token over
    /// it. The other formats archive through signature attributes this
    /// crate does not build.
    pub archive: bool,
    /// Embed the chain and revocation answers (`--long-term`).
    ///
    /// Raises the signature from level T to LT. Requires at least one
    /// timestamp: evidence about a certificate is only useful next to
    /// an attested time to evaluate it at.
    pub long_term: bool,
    /// RFC 3161 Time Stamp Authority URLs (`--timestamp`, repeatable).
    ///
    /// Empty leaves the signature at baseline `B`, where the time is
    /// the signer's own claim. Supplying one raises it to `T`, where a
    /// third party attests the signature existed by then -- which is
    /// what keeps it checkable after the certificate expires.
    ///
    /// Repeating it adds independent attestations of the same
    /// signature. They are alternatives: the signature keeps a proven
    /// time while any one of the authorities is still trusted, which
    /// is worth having when the certificate outlives the news cycle of
    /// any particular trust service provider.
    pub timestamp_authorities: Vec<String>,
}

impl SignDocumentArgs {
    /// Execute the verb.
    #[must_use]
    pub fn run(self) -> std::process::ExitCode {
        let Self {
            format,
            mut inputs,
            output,
            slot,
            reason,
            location,
            reader_filter,
            can,
            timestamp_authorities,
            long_term,
            archive,
        } = self;
        let cmd = CMD.label();
        let (pin_prompt, env_var) = match slot {
            SignSlot::Auth => ("PIN1: ", "REFINEID_PIN1"),
            SignSlot::Qualified => ("PIN2: ", "REFINEID_PIN2"),
        };
        let pin = match super::util::pin_env_or_prompt(cmd, env_var, pin_prompt) {
            Ok(p) => p,
            Err(exit) => return exit,
        };

        // `parse` guarantees at least one; `remove(0)` splits the
        // primary from the rest the way `SignOptions` is shaped.
        if inputs.is_empty() {
            eprintln!("{cmd}: no input files");
            return crate::exit_status::ExitStatus::RuntimeFailure.into();
        }
        let primary = inputs.remove(0);
        let metadata = SignatureMetadata {
            reason,
            location,
            ..SignatureMetadata::default()
        };
        let signing_time = now_signing_time();

        let backend = refineid_lib_pcsc::PcscBackend;
        let run_once = |can: Option<Can>| {
            let options = crate::card_sign::SignOptions {
                input: primary.clone(),
                output: output.clone(),
                pin: pin.clone(),
                save_cert: None,
                reader_filter: reader_filter.clone(),
                can,
                document: Some(DocumentRequest {
                    format,
                    additional_inputs: inputs.clone(),
                    signing_time,
                    metadata: metadata.clone(),
                    // The CLI signs whichever card is present; there is
                    // no prior inspection view to bind to.
                    expected_serial: None,
                    visible_signature: None,
                    timestamp_authorities: timestamp_authorities.clone(),
                    timestamp_credentials: None,
                    long_term,
                    archive,
                }),
            };
            crate::card_sign::sign_with_slot(backend, slot, options)
        };

        let mut result = run_once(can);
        // Same contactless retry as the bare sign verbs: the PACE seal
        // is reported by the first SELECT, before any PIN counter has
        // been touched.
        if matches!(result, Err(crate::card_sign::SignErrorKind::NeedCan))
            && let Some(prompted) = super::util::prompt_can_if_tty()
        {
            result = run_once(Some(prompted));
        }

        report_outcome(cmd, result, format, long_term, archive)
    }

    /// Parse the post-subcommand argv slice.
    ///
    /// `--timestamp` takes a URL or the name of a set; the private
    /// `expand_authority` helper applies that distinction.
    ///
    /// # Errors
    /// [`ArgParseError`] for any shape violation, including a missing
    /// `--format`, `--in` or `--out`.
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let mut format_raw: Option<String> = None;
        let mut inputs: Vec<PathBuf> = Vec::new();
        let mut output: Option<PathBuf> = None;
        let mut slot_raw: Option<String> = None;
        let mut reason: Option<String> = None;
        let mut location: Option<String> = None;
        let mut reader_filter: Option<String> = None;
        let mut can_raw: Option<String> = None;
        let mut timestamp_authorities: Vec<String> = Vec::new();
        let mut no_timestamp = false;
        let mut no_long_term = false;
        let mut no_archive = false;
        let mut long_term = false;
        let mut archive = false;

        let tokens = argv.into_vec();
        let mut iter = tokens.iter();
        while let Some(arg) = iter.next() {
            let mut value_for = |flag: &'static str| {
                iter.next()
                    .ok_or(ArgParseError::MissingValue { cmd: CMD, flag })
            };
            match arg.as_str() {
                "--format" => format_raw = Some(value_for("--format")?.clone()),
                "--in" => inputs.push(PathBuf::from(value_for("--in")?)),
                "--out" => output = Some(PathBuf::from(value_for("--out")?)),
                "--slot" => slot_raw = Some(value_for("--slot")?.clone()),
                "--reason" => reason = Some(value_for("--reason")?.clone()),
                "--location" => location = Some(value_for("--location")?.clone()),
                "--reader" => reader_filter = Some(value_for("--reader")?.clone()),
                "--can" => can_raw = Some(value_for("--can")?.clone()),
                "--timestamp" => {
                    let value = value_for("--timestamp")?.clone();
                    for url in expand_authority(&value)? {
                        // Asking one authority twice yields two tokens
                        // from the same unit under the same anchor,
                        // which is a round trip for no extra evidence.
                        if !timestamp_authorities.contains(&url) {
                            timestamp_authorities.push(url);
                        }
                    }
                }
                "--no-timestamp" => no_timestamp = true,
                "--no-long-term" => no_long_term = true,
                "--no-archive" => no_archive = true,
                "--long-term" => long_term = true,
                "--archive" => archive = true,
                other => {
                    return Err(ArgParseError::Unexpected {
                        cmd: CMD,
                        got: other.to_owned(),
                    });
                }
            }
        }

        Self::resolve(
            format_raw,
            inputs,
            output,
            slot_raw.as_deref(),
            reason,
            location,
            reader_filter,
            can_raw,
            long_term,
            archive,
            timestamp_authorities,
            no_timestamp,
            no_long_term,
            no_archive,
        )
    }

    /// Turn the collected flags into typed arguments.
    ///
    /// Split from the loop above because the two do different jobs: one
    /// reads tokens, the other decides whether what they add up to is a
    /// command that can run.
    #[expect(
        clippy::too_many_arguments,
        clippy::fn_params_excessive_bools,
        reason = "one parameter per flag; bundling them into a struct would name the same fields twice"
    )]
    fn resolve(
        format_raw: Option<String>,
        inputs: Vec<PathBuf>,
        output: Option<PathBuf>,
        slot_raw: Option<&str>,
        reason: Option<String>,
        location: Option<String>,
        reader_filter: Option<String>,
        can_raw: Option<String>,
        long_term: bool,
        archive: bool,
        mut timestamp_authorities: Vec<String>,
        no_timestamp: bool,
        no_long_term: bool,
        no_archive: bool,
    ) -> Result<Self, ArgParseError> {
        if no_timestamp && !timestamp_authorities.is_empty() {
            return Err(ArgParseError::BadValue {
                cmd: CMD,
                flag: "--no-timestamp",
                value: "--timestamp".to_owned(),
                reason: "choose an authority or none, not both".to_owned(),
            });
        }
        // The Sectigo qualified endpoint is the default across the
        // first-party ReFineID clients; --no-timestamp is the explicit
        // route to an unattested level-B signature.
        if timestamp_authorities.is_empty() && !no_timestamp {
            timestamp_authorities.push(DEFAULT_TIMESTAMP_AUTHORITY.to_owned());
        }
        let format_raw = format_raw.ok_or(ArgParseError::Required {
            cmd: CMD,
            name: "--format NAME",
        })?;
        let format = parse_format(&format_raw)?;
        if inputs.is_empty() {
            return Err(ArgParseError::Required {
                cmd: CMD,
                name: "--in PATH",
            });
        }
        // Caught here rather than at the card, so a mistyped command
        // costs nothing: a PIN prompt the operator answers before
        // being told the arguments were wrong is a PIN typed for
        // nothing.
        if format.is_single_file() && inputs.len() > 1 {
            return Err(ArgParseError::BadValue {
                cmd: CMD,
                flag: "--in",
                value: format!("{} files", inputs.len()),
                reason: format!("{format_raw} signs one file; use asice or bdoc to cover a set"),
            });
        }
        let output = output.ok_or(ArgParseError::Required {
            cmd: CMD,
            name: "--out PATH",
        })?;
        let slot = match slot_raw {
            None | Some("qualified") => SignSlot::Qualified,
            Some("auth") => SignSlot::Auth,
            Some(other) => {
                return Err(ArgParseError::BadValue {
                    cmd: CMD,
                    flag: "--slot",
                    value: other.to_owned(),
                    reason: "expected auth or qualified".to_owned(),
                });
            }
        };
        let (long_term, archive) = resolve_levels(
            format,
            long_term,
            archive,
            no_timestamp,
            no_long_term,
            no_archive,
        )?;
        check_level_is_reachable(long_term, timestamp_authorities.len())?;
        let can = can_raw
            .map(|raw| {
                Can::new(&raw).map_err(|e| ArgParseError::BadValue {
                    cmd: CMD,
                    flag: "--can",
                    value: raw.clone(),
                    reason: format!("{e}"),
                })
            })
            .transpose()?;

        Ok(Self {
            format,
            inputs,
            output,
            slot,
            reason,
            location,
            reader_filter,
            can,
            archive,
            long_term,
            timestamp_authorities,
        })
    }
}

/// The ETSI level the requested options add up to.
fn describe_level(timestamp_tokens: usize, long_term: bool, archive: bool) -> String {
    // A successful archive operation adds exactly one outer token. It
    // may come from the same authority as an inner signature token, so
    // do not report the total token count as distinct authorities.
    let signature_timestamps = timestamp_tokens.saturating_sub(usize::from(archive));
    let plural = if signature_timestamps == 1 {
        "authority"
    } else {
        "authorities"
    };
    match (signature_timestamps, long_term, archive) {
        (0, _, _) => "B (time claimed by the signer)".to_owned(),
        (n, false, _) => format!("B-T (time attested by {n} timestamp {plural})"),
        (n, true, false) => {
            format!("B-LT (time attested by {n} timestamp {plural}, evidence embedded)")
        }
        (n, true, true) => format!(
            "B-LTA (time attested by {n} timestamp {plural}, evidence embedded, plus one archive timestamp)"
        ),
    }
}

/// Turn the signing outcome into a report and an exit code.
fn report_outcome(
    cmd: &str,
    result: Result<crate::card_sign::SignReport, crate::card_sign::SignErrorKind>,
    format: Format,
    long_term: bool,
    archive: bool,
) -> std::process::ExitCode {
    match result {
        Ok(report) => {
            let level = describe_level(report.timestamps, long_term, archive);
            print!("{report}");
            println!("format:           {}", format_label(format));
            println!("signature level:  {level}");
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
            crate::exit_status::ExitStatus::CardCredentialRejected.into()
        }
        Err(e) => {
            eprintln!("{cmd}: {e}");
            crate::exit_status::ExitStatus::RuntimeFailure.into()
        }
    }
}

/// Refuse level LT when nothing attests the time.
///
/// Embedding evidence about a certificate says nothing without an
/// attested time to judge it at, so the combination is a category error
/// rather than a weaker signature. Caught before the PIN prompt: a PIN
/// typed for a command that was never going to run is a PIN typed for
/// nothing.
/// Apply the level defaults and their opt-outs.
///
/// Signing defaults to the highest level the format supports: LTA for
/// pades and asice-cades, LT for the rest. Each opt-out steps one
/// level down; an archive timestamp is only meaningful over embedded
/// evidence, so archive implies LT. Returns `(long_term, archive)`.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "one parameter per flag; bundling them into a struct would name the same fields twice"
)]
fn resolve_levels(
    format: Format,
    long_term: bool,
    archive: bool,
    no_timestamp: bool,
    no_long_term: bool,
    no_archive: bool,
) -> Result<(bool, bool), ArgParseError> {
    if no_long_term && (long_term || archive) {
        return Err(ArgParseError::BadValue {
            cmd: CMD,
            flag: "--no-long-term",
            value: if archive { "--archive" } else { "--long-term" }.to_owned(),
            reason: "choose a level or its opt-out, not both".to_owned(),
        });
    }
    if no_archive && archive {
        return Err(ArgParseError::BadValue {
            cmd: CMD,
            flag: "--no-archive",
            value: "--archive".to_owned(),
            reason: "choose a level or its opt-out, not both".to_owned(),
        });
    }
    if archive && !matches!(format, Format::Pades | Format::AsicECades) {
        return Err(ArgParseError::BadValue {
            cmd: CMD,
            flag: "--archive",
            value: format!("{format:?}"),
            reason: "archive timestamps are built for pades and asice-cades; the CAdES and \
                     XAdES archive attributes cover a different construction that is not \
                     implemented"
                .to_owned(),
        });
    }
    let archive = if no_timestamp || no_long_term || no_archive {
        false
    } else {
        archive || matches!(format, Format::Pades | Format::AsicECades)
    };
    let long_term = long_term || archive || !(no_timestamp || no_long_term);
    Ok((long_term, archive))
}

fn check_level_is_reachable(long_term: bool, timestamps: usize) -> Result<(), ArgParseError> {
    if long_term && timestamps == 0 {
        return Err(ArgParseError::BadValue {
            cmd: CMD,
            flag: "--long-term",
            value: "no timestamp".to_owned(),
            reason: "level LT needs at least one --timestamp to evaluate the evidence against"
                .to_owned(),
        });
    }
    Ok(())
}

/// Map the `--format` word onto a [`Format`].
///
/// `bdoc` and `asice` produce identical bytes: `BDOC 2.1` is `ASiC-E`
/// with `XAdES`, and only the file extension differs. Both spellings
/// are accepted because a counterparty will ask for one or the other by
/// name.
fn parse_format(raw: &str) -> Result<Format, ArgParseError> {
    match raw {
        "pades" | "pdf" => Ok(Format::Pades),
        "cades" => Ok(Format::Cades),
        "cades-detached" => Ok(Format::CadesDetached),
        "asice" | "asice-xades" | "bdoc" => Ok(Format::AsicEXades),
        "asice-cades" => Ok(Format::AsicECades),
        other => Err(ArgParseError::BadValue {
            cmd: CMD,
            flag: "--format",
            value: other.to_owned(),
            reason: "expected pades, cades, cades-detached, asice, asice-cades or bdoc".to_owned(),
        }),
    }
}

/// What the report calls the format it produced.
const fn format_label(format: Format) -> &'static str {
    match format {
        Format::Pades => "PAdES (signature inside the PDF)",
        Format::Cades => "CAdES, content attached",
        Format::CadesDetached => "CAdES, detached",
        Format::AsicECades => "ASiC-E with CAdES",
        Format::AsicEXades => "ASiC-E with XAdES (also .bdoc)",
    }
}

/// The current UTC instant as a [`SigningTime`].
///
/// A signature's claimed time is an assertion by whoever made it, not a
/// fact established by anything on the card. Raising it to a fact needs
/// a timestamp token from a `TSA`, which is a network round trip and a
/// different signature level.
fn now_signing_time() -> SigningTime {
    let now = crate::card_check::now_date_time();
    SigningTime {
        year: now.year(),
        month: now.month(),
        day: now.day(),
        hour: now.hour(),
        minute: now.minutes(),
        second: now.seconds(),
    }
}

/// Named sets `--timestamp` accepts in place of a URL, in request
/// order. Naming a set confers nothing beyond the URLs it stands for:
/// whoever configures an authority answers for its standing.
const AUTHORITY_SETS: &[(&str, &[&str])] = &[("eu-qualified", EU_QUALIFIED_TIMESTAMP_AUTHORITIES)];

/// One `--timestamp` value as the URLs it stands for.
///
/// A value carrying a scheme is a URL and is taken as given -- the
/// tool has no opinion about whose authority you use. A value without
/// one is the name of a set, and an unrecognised name is an error
/// rather than a URL that happens not to resolve.
///
/// That distinction is the point of having names at all. A mistyped
/// URL is survivable now: the authority is unreachable, it is named on
/// stderr, and the signature is built from the rest. Three URLs typed by
/// hand is exactly where that happens, and the result is a weaker
/// signature than was asked for with nothing but a line of output to
/// say so. A mistyped name cannot do that -- it stops before the card
/// is touched.
///
/// # Errors
/// [`ArgParseError::BadValue`] for a name that is not a known set.
fn expand_authority(value: &str) -> Result<Vec<String>, ArgParseError> {
    if value.contains("://") {
        return Ok(vec![value.to_owned()]);
    }
    for (name, urls) in AUTHORITY_SETS {
        if value == *name {
            return Ok(urls.iter().map(|u| (*u).to_owned()).collect());
        }
    }
    let known = AUTHORITY_SETS
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(", ");
    Err(ArgParseError::BadValue {
        cmd: CMD,
        flag: "--timestamp",
        value: value.to_owned(),
        reason: format!("not a URL and not a known set of them (known: {known})"),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_TIMESTAMP_AUTHORITY, Format, SignDocumentArgs, SignSlot, describe_level,
        parse_format,
    };
    use crate::cli::ArgParseError;
    use crate::cli::argv::fixtures::remaining_argv as argv;
    use crate::test_util::{TestResult, check, check_true};

    #[test]
    fn parses_a_minimal_pades_command() -> TestResult {
        let a = SignDocumentArgs::parse(argv(&[
            "--format",
            "pades",
            "--in",
            "/tmp/d.pdf",
            "--out",
            "/tmp/s.pdf",
        ]))?;
        check(&a.format, &Format::Pades, "format")?;
        check(&a.inputs.len(), &1, "input count")?;
        // The qualified slot is the default: it is the key whose
        // certificate carries non-repudiation.
        check(&a.slot, &SignSlot::Qualified, "slot")?;
        // The Sectigo qualified endpoint is the first-party default.
        check(
            &a.timestamp_authorities,
            &vec![DEFAULT_TIMESTAMP_AUTHORITY.to_owned()],
            "default authority",
        )?;
        // The default is the highest level the format supports.
        check(&a.archive, &true, "pades defaults to LTA")?;
        check(&a.long_term, &true, "archive implies LT")
    }

    #[test]
    fn formats_without_archive_support_default_to_lt() -> TestResult {
        let a = SignDocumentArgs::parse(argv(&[
            "--format",
            "asice",
            "--in",
            "/tmp/d.odt",
            "--out",
            "/tmp/s.asice",
        ]))?;
        check(&a.archive, &false, "no archive construction for XAdES")?;
        check(&a.long_term, &true, "still LT")
    }

    #[test]
    fn opt_outs_step_down_one_level_each() -> TestResult {
        let base = [
            "--format",
            "pades",
            "--in",
            "/tmp/d.pdf",
            "--out",
            "/tmp/s.pdf",
        ];
        let mut with_no_archive = base.to_vec();
        with_no_archive.push("--no-archive");
        let a = SignDocumentArgs::parse(argv(&with_no_archive))?;
        check(&a.archive, &false, "LT")?;
        check(&a.long_term, &true, "LT keeps evidence")?;
        let mut with_no_long_term = base.to_vec();
        with_no_long_term.push("--no-long-term");
        let a = SignDocumentArgs::parse(argv(&with_no_long_term))?;
        check(&a.archive, &false, "T has no archive")?;
        check(&a.long_term, &false, "T has no evidence")?;
        check(&a.timestamp_authorities.len(), &1, "T is still attested")
    }

    #[test]
    fn a_level_and_its_opt_out_conflict() -> TestResult {
        let base = [
            "--format",
            "pades",
            "--in",
            "/tmp/d.pdf",
            "--out",
            "/tmp/s.pdf",
        ];
        let mut conflicting = base.to_vec();
        conflicting.extend(["--no-long-term", "--archive"]);
        check_true(
            SignDocumentArgs::parse(argv(&conflicting)).is_err(),
            "a level and its opt-out cannot both be asked for",
        )
    }

    #[test]
    fn no_timestamp_is_the_explicit_route_to_level_b() -> TestResult {
        let a = SignDocumentArgs::parse(argv(&[
            "--format",
            "pades",
            "--in",
            "/tmp/d.pdf",
            "--out",
            "/tmp/s.pdf",
            "--no-timestamp",
        ]))?;
        check(&a.timestamp_authorities.len(), &0, "no authority")
    }

    #[test]
    fn no_timestamp_refuses_a_named_authority() -> TestResult {
        check_true(
            SignDocumentArgs::parse(argv(&[
                "--format",
                "pades",
                "--in",
                "/tmp/d.pdf",
                "--out",
                "/tmp/s.pdf",
                "--no-timestamp",
                "--timestamp",
                "http://tsa.example",
            ]))
            .is_err(),
            "an authority and none cannot both be asked for",
        )
    }

    #[test]
    fn no_timestamp_cannot_reach_level_lt() -> TestResult {
        check_true(
            SignDocumentArgs::parse(argv(&[
                "--format",
                "pades",
                "--in",
                "/tmp/d.pdf",
                "--out",
                "/tmp/s.pdf",
                "--no-timestamp",
                "--long-term",
            ]))
            .is_err(),
            "LT evidence needs an attested time",
        )
    }

    #[test]
    fn archive_level_does_not_count_outer_token_as_another_authority() -> TestResult {
        check(
            &describe_level(2, true, true),
            &"B-LTA (time attested by 1 timestamp authority, evidence embedded, plus one archive timestamp)".to_owned(),
            "one signature token plus one archive token",
        )
    }

    #[test]
    fn repeated_in_builds_a_set_for_containers() -> TestResult {
        let a = SignDocumentArgs::parse(argv(&[
            "--format",
            "asice",
            "--in",
            "/tmp/a.pdf",
            "--in",
            "/tmp/b.txt",
            "--out",
            "/tmp/o.asice",
        ]))?;
        check(&a.inputs.len(), &2, "input count")?;
        check(&a.format, &Format::AsicEXades, "format")
    }

    /// A one-file format given a set is refused at parse time, before
    /// the operator has been asked for a PIN.
    #[test]
    fn single_file_formats_refuse_a_set_before_the_pin_prompt() -> TestResult {
        for format in ["pades", "cades", "cades-detached"] {
            let r = SignDocumentArgs::parse(argv(&[
                "--format", format, "--in", "/a", "--in", "/b", "--out", "/o",
            ]));
            check_true(
                matches!(r, Err(ArgParseError::BadValue { flag: "--in", .. })),
                "two files refused",
            )?;
        }
        Ok(())
    }

    /// `.bdoc` and `.asice` are the same format under two names, so
    /// both spellings must land on the same variant.
    #[test]
    fn bdoc_and_asice_are_one_format() -> TestResult {
        check(
            &parse_format("bdoc").map_err(|_| "bdoc")?,
            &parse_format("asice").map_err(|_| "asice")?,
            "bdoc == asice",
        )
    }

    #[test]
    fn unknown_format_rejected() -> TestResult {
        let r = SignDocumentArgs::parse(argv(&[
            "--format",
            "xades-enveloped",
            "--in",
            "/a",
            "--out",
            "/o",
        ]));
        check_true(
            matches!(
                r,
                Err(ArgParseError::BadValue {
                    flag: "--format",
                    ..
                })
            ),
            "unknown format rejected",
        )
    }

    #[test]
    fn missing_format_in_and_out_are_each_required() -> TestResult {
        check_true(
            matches!(
                SignDocumentArgs::parse(argv(&["--in", "/a", "--out", "/o"])),
                Err(ArgParseError::Required { name, .. }) if name == "--format NAME"
            ),
            "format required",
        )?;
        check_true(
            matches!(
                SignDocumentArgs::parse(argv(&["--format", "pades", "--out", "/o"])),
                Err(ArgParseError::Required { name, .. }) if name == "--in PATH"
            ),
            "input required",
        )?;
        check_true(
            matches!(
                SignDocumentArgs::parse(argv(&["--format", "pades", "--in", "/a"])),
                Err(ArgParseError::Required { name, .. }) if name == "--out PATH"
            ),
            "output required",
        )
    }

    #[test]
    fn slot_can_be_chosen() -> TestResult {
        let a = SignDocumentArgs::parse(argv(&[
            "--format", "cades", "--in", "/a", "--out", "/o", "--slot", "auth",
        ]))?;
        check(&a.slot, &SignSlot::Auth, "slot")?;
        check_true(
            matches!(
                SignDocumentArgs::parse(argv(&[
                    "--format",
                    "cades",
                    "--in",
                    "/a",
                    "--out",
                    "/o",
                    "--slot",
                    "signature",
                ])),
                Err(ArgParseError::BadValue { flag: "--slot", .. })
            ),
            "unknown slot rejected",
        )
    }

    #[test]
    fn eu_qualified_expands_in_order() -> TestResult {
        let a = SignDocumentArgs::parse(argv(&[
            "--format",
            "pades",
            "--in",
            "/a.pdf",
            "--out",
            "/o.pdf",
            "--timestamp",
            "eu-qualified",
        ]))?;
        check(&a.timestamp_authorities.len(), &2, "two authorities")?;
        check(
            &a.timestamp_authorities[0].as_str(),
            &"https://timestamp.aped.gov.gr/qtss",
            "best first",
        )
    }

    #[test]
    fn a_set_and_a_url_compose_without_repeating() -> TestResult {
        let a = SignDocumentArgs::parse(argv(&[
            "--format",
            "pades",
            "--in",
            "/a.pdf",
            "--out",
            "/o.pdf",
            "--timestamp",
            "eu-qualified",
            "--timestamp",
            "http://tsa.example/tsa",
            "--timestamp",
            "https://timestamp.aped.gov.gr/qtss",
        ]))?;
        // Two named, one custom, and one duplicate of the set.
        check(&a.timestamp_authorities.len(), &3, "no duplicate")?;
        check(
            &a.timestamp_authorities[2].as_str(),
            &"http://tsa.example/tsa",
            "own authority kept",
        )
    }

    #[test]
    fn long_term_requires_qualification_even_for_a_direct_url() -> TestResult {
        let level_t = SignDocumentArgs::parse(argv(&[
            "--format",
            "pades",
            "--in",
            "/a.pdf",
            "--out",
            "/o.pdf",
            "--timestamp",
            "https://tsa.example/tsa",
            "--no-long-term",
        ]))?;
        check_true(!level_t.long_term, "an explicit level T stays at T")?;

        let defaulted = SignDocumentArgs::parse(argv(&[
            "--format",
            "pades",
            "--in",
            "/a.pdf",
            "--out",
            "/o.pdf",
            "--timestamp",
            "https://tsa.example/tsa",
        ]))?;
        check_true(defaulted.long_term, "the default level embeds evidence")
    }

    #[test]
    fn a_mistyped_set_stops_before_the_card() -> TestResult {
        check_true(
            matches!(
                SignDocumentArgs::parse(argv(&[
                    "--format",
                    "pades",
                    "--in",
                    "/a.pdf",
                    "--out",
                    "/o.pdf",
                    "--timestamp",
                    "eu-qualifed",
                ])),
                Err(ArgParseError::BadValue {
                    flag: "--timestamp",
                    ..
                })
            ),
            "unknown set rejected rather than treated as a URL",
        )
    }

    #[test]
    fn pades_metadata_is_optional() -> TestResult {
        let a = SignDocumentArgs::parse(argv(&[
            "--format",
            "pades",
            "--in",
            "/a.pdf",
            "--out",
            "/o.pdf",
            "--reason",
            "Declaration ANSSI",
            "--location",
            "Helsinki",
        ]))?;
        check(&a.reason, &Some("Declaration ANSSI".to_owned()), "reason")?;
        check(&a.location, &Some("Helsinki".to_owned()), "location")
    }
}
