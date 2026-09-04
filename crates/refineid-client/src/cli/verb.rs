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

//! Top-level subcommand dispatch.
//!
//! [`Verb`] is the typed enumeration of every operation
//! the `refineid` binary supports. Each variant *carries its
//! already-parsed typed `Args`*; [`parse_argv`] does verb
//! dispatch + Args parsing in a single trust-boundary call. The
//! consuming dispatch then matches a fully-typed value -- no
//! `RemainingArgv` survives into `main`.
//!
//! [`VerbTag`] is the data-less, operator-facing label form.
//! It's what [`super::ArgParseError`] carries for attribution
//! (a parse failure has no Args yet, so the data-carrying
//! [`Verb`] shape doesn't apply). [`VerbTag`] is finer-grained
//! than [`Verb`] for pair-shaped subcommands: where
//! `change-pin1` and `change-pin2` collapse into a single
//! `Verb::CardChangePin(ChangePinArgs)` (the slot lives inside
//! the Args), [`VerbTag`] keeps `CardChangePin1` and
//! `CardChangePin2` distinct so error wording can name the
//! exact subcommand that fired.
//!
//! Adding a new subcommand: add a [`VerbTag`] variant + its
//! `label()` arm; add a [`Verb`] variant carrying the typed
//! Args (or extend an existing pair-shape Args with a new slot
//! enum value); add a `parse_argv` arm that runs the verb
//! match then the Args parse. Match-exhaustiveness catches
//! omissions.

/// Data-less subcommand identifier. Used in
/// [`super::ArgParseError`] so an argv shape failure can name
/// which subcommand it refers to without needing a (yet
/// unconstructed) typed Args value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerbTag {
    /// `card` -- per-card readout (the default).
    CardCheck,
    /// `card emrtd` -- eMRTD data-group read via PACE.
    CardEmrtd,
    /// `card sign-auth` -- PIN1-gated RSA signature on the
    /// auth key.
    CardSignAuth,
    /// `card sign-qualified` -- PIN2-gated RSA signature on
    /// the non-repudiation key.
    CardSignQualified,
    /// `card sign-document` -- a signature in a format a
    /// counterparty can open: `PAdES`, `CAdES`, `ASiC-E` or `BDOC`.
    CardSignDocument,
    /// `card decrypt-auth` -- PIN1-gated RSA decrypt on the
    /// auth key.
    CardDecryptAuth,
    /// `card pubkey` -- read pub key from a slot's cert and
    /// emit as OpenSSH wire or PEM SPKI.
    CardPubkey,
    /// `card export-all` -- bulk export of every readable
    /// slot's cert + pub key.
    CardExportAll,
    /// `card activate` -- one-time DVV activation flow.
    CardActivate,
    /// `card change-pin1` -- rotate PIN1.
    CardChangePin1,
    /// `card change-pin2` -- rotate PIN2.
    CardChangePin2,
    /// `card unblock-pin1` -- PUK-driven unblock of PIN1.
    CardUnblockPin1,
    /// `card unblock-pin2` -- PUK-driven unblock of PIN2.
    CardUnblockPin2,
    /// `reader keyboard` -- ACS reader host-interface
    /// (keyboard wedge) status / control.
    ReaderKeyboard,
    /// `verify` -- offline RSA-PKCS#1 v1.5 signature verify.
    Verify,
    /// `cert show` -- pretty-print a DER/PEM cert.
    CertShow,
    /// `cert chain` -- walk a cert's chain to a self-signed
    /// root.
    CertChain,
    /// `pair` -- pair with a mobile device (iPhone/Android).
    CardPair,
    /// `pairs` -- list paired mobile devices.
    CardPairs,
    /// `unpair` -- revoke and delete a paired mobile device.
    CardUnpair,
    /// `auth` -- authenticate to a TLS site via paired mobile device.
    CardAuth,
}

impl VerbTag {
    /// Operator-facing label, e.g. `"card change-pin1"`. Single
    /// source of truth for subcommand strings -- consumed by
    /// [`super::ArgParseError`]'s `Display` impl.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CardCheck => "card",
            Self::CardEmrtd => "card emrtd",
            Self::CardSignAuth => "card sign-auth",
            Self::CardSignQualified => "card sign-qualified",
            Self::CardSignDocument => "card sign-document",
            Self::CardDecryptAuth => "card decrypt-auth",
            Self::CardPubkey => "card pubkey",
            Self::CardExportAll => "card export-all",
            Self::CardActivate => "card activate",
            Self::CardChangePin1 => "card change-pin1",
            Self::CardChangePin2 => "card change-pin2",
            Self::CardUnblockPin1 => "card unblock-pin1",
            Self::CardUnblockPin2 => "card unblock-pin2",
            Self::ReaderKeyboard => "reader keyboard",
            Self::Verify => "verify",
            Self::CertShow => "cert show",
            Self::CertChain => "cert chain",
            Self::CardPair => "pair",
            Self::CardPairs => "pairs",
            Self::CardUnpair => "unpair",
            Self::CardAuth => "auth",
        }
    }
}

/// Fully-parsed subcommand: variant identifies the operation,
/// payload is the typed Args struct that operation consumes.
///
/// Produced by [`parse_argv`] (the single trust boundary for
/// CLI input). The dispatch in `main` matches arms that are
/// all the uniform `Self::X(args) => args.run()` shape -- no
/// argv-string handling, no untyped slice survives.
///
/// Variant-pair subcommands (`sign-auth` vs `sign-qualified`,
/// `change-pin1` vs `change-pin2`, ...) collapse to a single
/// `Verb` variant; the slot identity is carried inside the
/// typed Args (`SignArgs::slot`, `ChangePinArgs::slot`, ...).
/// [`VerbTag`] *does* split them because it's the error-
/// attribution label and operator messages need to name the
/// exact subcommand that fired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verb {
    /// `card` -- per-card readout (the default).
    CardCheck(super::card::CardArgs),
    /// `card emrtd` -- eMRTD data-group read via PACE.
    CardEmrtd(super::card_emrtd::EmrtdArgs),
    /// `card sign-auth` / `card sign-qualified` (slot pivot
    /// inside `SignArgs::slot`).
    CardSign(super::card_sign::SignArgs),
    /// `card sign-document` -- a signed document rather than
    /// signature bytes.
    CardSignDocument(super::card_sign_document::SignDocumentArgs),
    /// `card decrypt-auth`.
    CardDecryptAuth(super::card_decrypt_auth::DecryptAuthArgs),
    /// `card pubkey`.
    CardPubkey(super::card_pubkey::PubkeyArgs),
    /// `card export-all`.
    CardExportAll(super::card_export_all::ExportAllArgs),
    /// `card activate`.
    CardActivate(super::card_activate::ActivateArgs),
    /// `card change-pin1` / `card change-pin2` (slot pivot
    /// inside `ChangePinArgs::slot`).
    CardChangePin(super::card_change_pin::ChangePinArgs),
    /// `card unblock-pin1` / `card unblock-pin2` (slot pivot
    /// inside `UnblockPinArgs::slot`).
    CardUnblockPin(super::card_unblock_pin::UnblockPinArgs),
    /// `reader keyboard` -- ACS reader host-interface control.
    ReaderKeyboard(super::reader_keyboard::ReaderKeyboardArgs),
    /// `verify` -- offline signature verify.
    Verify(super::verify::VerifyArgs),
    /// `cert show` -- pretty-print a cert file.
    CertShow(super::cert_show::CertShowArgs),
    /// `cert chain` -- chain walk.
    CertChain(super::cert_chain::CertChainArgs),
    /// `pair` -- pair with mobile device.
    CardPair(super::card_pair::PairArgs),
    /// `pairs` -- list paired mobile devices.
    CardPairs(super::card_pair::PairsArgs),
    /// `unpair` -- revoke paired mobile device.
    CardUnpair(super::card_pair::UnpairArgs),
    /// `auth` -- authenticate to a TLS site via paired mobile device.
    CardAuth(super::card_pair::AuthArgs),
}

impl Verb {
    /// The data-less tag identifying which subcommand this is.
    ///
    /// For variant-pair shapes (sign / change-pin / unblock-pin)
    /// the tag pivots off the slot field inside the Args.
    #[must_use]
    pub const fn tag(&self) -> VerbTag {
        use crate::card_pin::PinManageSlot;
        use crate::card_sign::SignSlot;
        match self {
            Self::CardCheck(_) => VerbTag::CardCheck,
            Self::CardEmrtd(_) => VerbTag::CardEmrtd,
            Self::CardSign(a) => match a.slot {
                SignSlot::Auth => VerbTag::CardSignAuth,
                SignSlot::Qualified => VerbTag::CardSignQualified,
            },
            Self::CardSignDocument(_) => VerbTag::CardSignDocument,
            Self::CardDecryptAuth(_) => VerbTag::CardDecryptAuth,
            Self::CardPubkey(_) => VerbTag::CardPubkey,
            Self::CardExportAll(_) => VerbTag::CardExportAll,
            Self::CardActivate(_) => VerbTag::CardActivate,
            Self::CardChangePin(a) => match a.slot {
                PinManageSlot::Pin1 => VerbTag::CardChangePin1,
                PinManageSlot::Pin2 => VerbTag::CardChangePin2,
            },
            Self::CardUnblockPin(a) => match a.slot {
                PinManageSlot::Pin1 => VerbTag::CardUnblockPin1,
                PinManageSlot::Pin2 => VerbTag::CardUnblockPin2,
            },
            Self::ReaderKeyboard(_) => VerbTag::ReaderKeyboard,
            Self::Verify(_) => VerbTag::Verify,
            Self::CertShow(_) => VerbTag::CertShow,
            Self::CertChain(_) => VerbTag::CertChain,
            Self::CardPair(_) => VerbTag::CardPair,
            Self::CardPairs(_) => VerbTag::CardPairs,
            Self::CardUnpair(_) => VerbTag::CardUnpair,
            Self::CardAuth(_) => VerbTag::CardAuth,
        }
    }

    /// Execute the parsed verb. Every arm is uniform `Self::X(a)
    /// => a.run()`. The slot identity (where it matters) was
    /// written into the typed Args by the parser, so the
    /// dispatch carries no per-subcommand plumbing.
    #[must_use]
    pub fn run(self) -> std::process::ExitCode {
        match self {
            Self::CardCheck(a) => a.run(),
            Self::CardEmrtd(a) => a.run(),
            Self::CardSign(a) => a.run(),
            Self::CardSignDocument(a) => a.run(),
            Self::CardDecryptAuth(a) => a.run(),
            Self::CardPubkey(a) => a.run(),
            Self::CardExportAll(a) => a.run(),
            Self::CardActivate(a) => a.run(),
            Self::CardChangePin(a) => a.run(),
            Self::CardUnblockPin(a) => a.run(),
            Self::ReaderKeyboard(a) => a.run(),
            Self::Verify(a) => a.run(),
            Self::CertShow(a) => a.run(),
            Self::CertChain(a) => a.run(),
            Self::CardPair(a) => a.run(),
            Self::CardPairs(a) => a.run(),
            Self::CardUnpair(a) => a.run(),
            Self::CardAuth(a) => a.run(),
        }
    }
}

/// Top-level subcommand parse failure -- verb dispatch only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerbParseError {
    /// `args[1..]` didn't contain a subcommand at all (just the
    /// program name, or empty).
    Missing,
    /// `args[1..]` named something we don't recognise.
    Unrecognized {
        /// The literal argv token that wasn't recognised as a
        /// subcommand. Tier 0 `String` from `std::env::args()`.
        got: String,
    },
    /// `refineid cert <verb>` reached without a recognised
    /// `<verb>` (`show` / `chain`).
    UnknownCertVerb {
        /// The literal argv token after `cert` that wasn't
        /// recognised. Tier 0 `String` from `std::env::args()`.
        got: String,
    },
}

impl core::fmt::Display for VerbParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Missing => f.write_str("no subcommand supplied"),
            Self::Unrecognized { got } => write!(f, "unrecognised subcommand {got:?}"),
            Self::UnknownCertVerb { got } => {
                write!(f, "unknown `cert` verb {got:?}; try `show` or `chain`")
            }
        }
    }
}

impl core::error::Error for VerbParseError {}

/// Combined parse failure -- verb dispatch failure (no Args
/// even attempted) OR per-subcommand argv shape failure (verb
/// recognised, Args parse rejected).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Top-level verb-dispatch failure (subcommand missing /
    /// unrecognised). No `Args` parse was attempted.
    Verb(VerbParseError),
    /// Verb recognised; the per-subcommand `Args` parse rejected
    /// the argv shape.
    Args(super::ArgParseError),
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Verb(e) => write!(f, "{e}"),
            Self::Args(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for ParseError {}

impl From<VerbParseError> for ParseError {
    fn from(e: VerbParseError) -> Self {
        Self::Verb(e)
    }
}

impl From<super::ArgParseError> for ParseError {
    fn from(e: super::ArgParseError) -> Self {
        Self::Args(e)
    }
}

/// Parse a [`super::argv::ProcessArgv`] into a fully-typed
/// [`Verb`].
///
/// The single trust boundary for CLI input: verb dispatch +
/// per-subcommand Args parsing happen here, so downstream code
/// sees only a parsed-and-typed value.
///
/// # Errors
/// [`ParseError::Verb`] on verb dispatch failure (no
/// subcommand / unrecognised / unknown cert verb);
/// [`ParseError::Args`] when the verb is recognised but the
/// subcommand's typed Args parser rejects the remaining argv.
pub fn parse_argv(argv: &super::argv::ProcessArgv) -> Result<Verb, ParseError> {
    use super::argv::RemainingArgv;
    let (top, rest) = match argv.as_slice() {
        // Explicit `card <verb>` arms must precede the catch-all
        // bare `card` arm so action verbs win.
        [_, c, v, rest @ ..] if c == "card" => (TopLevel::Card(Some(v.as_str())), rest),
        [_, c, rest @ ..] if c == "card" => (TopLevel::Card(None), rest),
        [_, c, v, rest @ ..] if c == "cert" => (TopLevel::Cert(v.as_str()), rest),
        [_, c, ..] if c == "cert" => {
            return Err(VerbParseError::UnknownCertVerb { got: String::new() }.into());
        }
        [_, c, rest @ ..] if c == "verify" => (TopLevel::Verify, rest),
        [_, c, rest @ ..] if c == "pair" => (TopLevel::Pair, rest),
        [_, c, rest @ ..] if c == "pairs" => (TopLevel::Pairs, rest),
        [_, c, rest @ ..] if c == "unpair" => (TopLevel::Unpair, rest),
        [_, c, rest @ ..] if c == "auth" => (TopLevel::Auth, rest),
        [_, c, v, rest @ ..] if c == "reader" => (TopLevel::Reader(v.as_str()), rest),
        [_, c, ..] if c == "reader" => {
            return Err(VerbParseError::Unrecognized {
                got: "reader (missing sub-verb, try: reader keyboard)".to_owned(),
            }
            .into());
        }
        [_, other, ..] => {
            return Err(VerbParseError::Unrecognized { got: other.clone() }.into());
        }
        _ => return Err(VerbParseError::Missing.into()),
    };
    let rest = RemainingArgv::from_slice(rest);
    Ok(match top {
        TopLevel::Card(Some("emrtd")) => {
            Verb::CardEmrtd(super::card_emrtd::EmrtdArgs::parse(rest)?)
        }
        TopLevel::Card(Some("pair")) | TopLevel::Pair => {
            Verb::CardPair(super::card_pair::PairArgs::parse(rest)?)
        }
        TopLevel::Card(Some("pairs")) | TopLevel::Pairs => {
            Verb::CardPairs(super::card_pair::PairsArgs::parse(rest)?)
        }
        TopLevel::Card(Some("unpair")) | TopLevel::Unpair => {
            Verb::CardUnpair(super::card_pair::UnpairArgs::parse(rest)?)
        }
        TopLevel::Card(Some("auth")) | TopLevel::Auth => {
            Verb::CardAuth(super::card_pair::AuthArgs::parse(rest)?)
        }
        TopLevel::Card(Some("sign-auth")) => Verb::CardSign(super::card_sign::SignArgs::parse(
            crate::card_sign::SignSlot::Auth,
            rest,
        )?),
        TopLevel::Card(Some("sign-qualified")) => Verb::CardSign(
            super::card_sign::SignArgs::parse(crate::card_sign::SignSlot::Qualified, rest)?,
        ),
        TopLevel::Card(Some("sign-document")) => {
            Verb::CardSignDocument(super::card_sign_document::SignDocumentArgs::parse(rest)?)
        }
        TopLevel::Card(Some("decrypt-auth")) => {
            Verb::CardDecryptAuth(super::card_decrypt_auth::DecryptAuthArgs::parse(rest)?)
        }
        TopLevel::Card(Some("pubkey")) => {
            Verb::CardPubkey(super::card_pubkey::PubkeyArgs::parse(rest)?)
        }
        TopLevel::Card(Some("export-all")) => {
            Verb::CardExportAll(super::card_export_all::ExportAllArgs::parse(rest)?)
        }
        TopLevel::Card(Some("activate")) => {
            Verb::CardActivate(super::card_activate::ActivateArgs::parse(rest)?)
        }
        TopLevel::Card(Some("change-pin1")) => {
            Verb::CardChangePin(super::card_change_pin::ChangePinArgs::parse(
                crate::card_pin::PinManageSlot::Pin1,
                rest,
            )?)
        }
        TopLevel::Card(Some("change-pin2")) => {
            Verb::CardChangePin(super::card_change_pin::ChangePinArgs::parse(
                crate::card_pin::PinManageSlot::Pin2,
                rest,
            )?)
        }
        TopLevel::Card(Some("unblock-pin1")) => {
            Verb::CardUnblockPin(super::card_unblock_pin::UnblockPinArgs::parse(
                crate::card_pin::PinManageSlot::Pin1,
                rest,
            )?)
        }
        TopLevel::Card(Some("unblock-pin2")) => {
            Verb::CardUnblockPin(super::card_unblock_pin::UnblockPinArgs::parse(
                crate::card_pin::PinManageSlot::Pin2,
                rest,
            )?)
        }
        // The bare-`card` catch-all must accept any non-recognised
        // `card <flag>` as flags to CardCheck; an unknown `card
        // <verb>` token would already have been rejected by
        // CardArgs::parse if it didn't start with `--`.
        TopLevel::Card(None | Some(_)) => {
            // Re-include the verb token (it's actually a flag the
            // operator passed to bare `card`) in the args.
            let mut full = Vec::with_capacity(rest.len().saturating_add(1));
            if let TopLevel::Card(Some(token)) = top {
                full.push(token.to_owned());
            }
            full.extend(rest.into_vec());
            Verb::CardCheck(super::card::CardArgs::parse(RemainingArgv::from_vec(full))?)
        }
        TopLevel::Cert("show") => Verb::CertShow(super::cert_show::CertShowArgs::parse(rest)?),
        TopLevel::Cert("chain") => Verb::CertChain(super::cert_chain::CertChainArgs::parse(rest)?),
        TopLevel::Cert(other) => {
            return Err(VerbParseError::UnknownCertVerb {
                got: other.to_owned(),
            }
            .into());
        }
        TopLevel::Reader("keyboard") => {
            Verb::ReaderKeyboard(super::reader_keyboard::ReaderKeyboardArgs::parse(rest)?)
        }
        TopLevel::Reader(other) => {
            return Err(VerbParseError::Unrecognized {
                got: format!("reader {other}"),
            }
            .into());
        }
        TopLevel::Verify => Verb::Verify(super::verify::VerifyArgs::parse(rest)?),
    })
}

/// Internal: which top-level verb (and optional sub-verb) was
/// matched while tokenising argv. The `Card(None)` shape
/// covers bare `card` / `card --flags`; `Card(Some(flag))`
/// captures the awkward case where the operator wrote
/// `card --flag arg ...` and the second token (`--flag`)
/// needs to feed back into `CardArgs::parse` as a flag rather
/// than be interpreted as a sub-verb. Distinct from the
/// outer [`Verb`] enum, which carries already-parsed Args.
enum TopLevel<'a> {
    /// `card` family. `Some(flag)` carries a `--flag` that
    /// appeared in sub-verb position (e.g. `card --reader X`);
    /// `None` means a bare `card` with no sub-verb.
    Card(Option<&'a str>),
    /// `cert` family. Always carries the sub-verb name
    /// (`cert show` / `cert chain` etc.) since there is no
    /// "bare cert" verb.
    Cert(&'a str),
    /// `reader` family. Always carries the sub-verb name
    /// (`reader keyboard`); there is no bare `reader` verb.
    Reader(&'a str),
    /// The standalone `verify` verb (cert + signature input).
    Verify,
    /// `pair` verb.
    Pair,
    /// `pairs` verb.
    Pairs,
    /// `unpair` verb.
    Unpair,
    /// `auth` verb.
    Auth,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::argv::fixtures::process_argv as argv;
    use crate::test_util::{TestResult, check, check_true};

    #[test]
    fn bare_card_dispatches_to_check() -> TestResult {
        let sub = parse_argv(&argv(&["refineid", "card"]))?;
        check(&sub.tag(), &VerbTag::CardCheck, "tag")
    }

    #[test]
    fn card_with_flags_dispatches_to_check() -> TestResult {
        let sub = parse_argv(&argv(&["refineid", "card", "--offline", "--no-can"]))?;
        check(&sub.tag(), &VerbTag::CardCheck, "tag")
    }

    #[test]
    fn card_emrtd_wins_over_card_catch_all() -> TestResult {
        let sub = parse_argv(&argv(&["refineid", "card", "emrtd", "--can", "123456"]))?;
        check(&sub.tag(), &VerbTag::CardEmrtd, "tag")
    }

    #[test]
    fn each_card_verb_has_a_dispatch() -> TestResult {
        // Each verb with the minimum argv it needs to parse.
        for (verb, extra, expected) in [
            ("emrtd", vec!["--can", "123456"], VerbTag::CardEmrtd),
            (
                "sign-auth",
                vec!["--in", "/i", "--out", "/o"],
                VerbTag::CardSignAuth,
            ),
            (
                "sign-qualified",
                vec!["--in", "/i", "--out", "/o"],
                VerbTag::CardSignQualified,
            ),
            (
                "sign-document",
                vec!["--format", "pades", "--in", "/i.pdf", "--out", "/o.pdf"],
                VerbTag::CardSignDocument,
            ),
            (
                "decrypt-auth",
                vec!["--in", "/i", "--out", "/o"],
                VerbTag::CardDecryptAuth,
            ),
            ("pubkey", vec![], VerbTag::CardPubkey),
            ("export-all", vec!["/out"], VerbTag::CardExportAll),
            ("activate", vec![], VerbTag::CardActivate),
            ("change-pin1", vec![], VerbTag::CardChangePin1),
            ("change-pin2", vec![], VerbTag::CardChangePin2),
            ("unblock-pin1", vec![], VerbTag::CardUnblockPin1),
            ("unblock-pin2", vec![], VerbTag::CardUnblockPin2),
        ] {
            let mut a = vec!["refineid", "card", verb];
            a.extend(extra.iter().copied());
            let sub = parse_argv(&argv(&a).clone())?;
            check(&sub.tag(), &expected, &format!("tag for verb {verb}"))?;
        }
        Ok(())
    }

    #[test]
    fn verify_subcommand() -> TestResult {
        let sub = parse_argv(&argv(&[
            "refineid", "verify", "--cert", "/c", "--in", "/i", "--sig", "/s",
        ]))?;
        check(&sub.tag(), &VerbTag::Verify, "tag")
    }

    #[test]
    fn cert_show_and_chain() -> TestResult {
        let sub = parse_argv(&argv(&["refineid", "cert", "show", "/c"]))?;
        check(&sub.tag(), &VerbTag::CertShow, "show tag")?;
        let sub = parse_argv(&argv(&["refineid", "cert", "chain", "/c"]))?;
        check(&sub.tag(), &VerbTag::CertChain, "chain tag")
    }

    #[test]
    fn unknown_cert_verb_rejected() -> TestResult {
        let r = parse_argv(&argv(&["refineid", "cert", "bogus"]));
        check_true(
            matches!(
                r,
                Err(ParseError::Verb(VerbParseError::UnknownCertVerb { .. }))
            ),
            "UnknownCertVerb",
        )
    }

    #[test]
    fn unknown_top_level_subcommand_rejected() -> TestResult {
        let r = parse_argv(&argv(&["refineid", "bogus"]));
        match r {
            Err(ParseError::Verb(VerbParseError::Unrecognized { got })) => {
                check(got.as_str(), "bogus", "got")
            }
            other => Err(format!("expected Unrecognized, got {other:?}").into()),
        }
    }

    #[test]
    fn no_subcommand_rejected() -> TestResult {
        let r = parse_argv(&argv(&["refineid"]));
        check_true(
            matches!(r, Err(ParseError::Verb(VerbParseError::Missing))),
            "Missing",
        )
    }

    #[test]
    fn malformed_args_surface_as_args_error() -> TestResult {
        let r = parse_argv(&argv(&["refineid", "card", "emrtd", "--can", "abc"]));
        check_true(matches!(r, Err(ParseError::Args(_))), "Args(_)")
    }

    #[test]
    fn pair_and_auth_subcommands() -> TestResult {
        let sub = parse_argv(&argv(&["refineid", "pair", "--port", "9999"]))?;
        check(&sub.tag(), &VerbTag::CardPair, "pair tag")?;
        let sub = parse_argv(&argv(&["refineid", "pairs"]))?;
        check(&sub.tag(), &VerbTag::CardPairs, "pairs tag")?;
        let sub = parse_argv(&argv(&[
            "refineid",
            "unpair",
            "0123456789abcdef0123456789abcdef",
        ]))?;
        check(&sub.tag(), &VerbTag::CardUnpair, "unpair tag")?;
        let sub = parse_argv(&argv(&["refineid", "auth", "https://card.refineid.fi"]))?;
        check(&sub.tag(), &VerbTag::CardAuth, "auth tag")?;
        let sub = parse_argv(&argv(&["refineid", "card", "auth"]))?;
        check(&sub.tag(), &VerbTag::CardAuth, "card auth tag")
    }
}
