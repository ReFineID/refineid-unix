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

//! Portable application facade for graphical card-management clients.
//!
//! This module exposes user-goal operations without terminal prompts,
//! command-line parsing, file output, or UI-toolkit dependencies. Native
//! desktop clients supply typed secret values at their secure-input boundary
//! and render the returned reports using their platform conventions.

use refineid_lib_core::backend::{ReaderBackend as _, ReaderFilter};
use refineid_lib_core::can::Can;
use std::path::PathBuf;

use refineid_lib_core::identity::TokenSerial;
use refineid_lib_core::pin::PinBytes;
use refineid_lib_core::sign::cades::SigningTime;
use refineid_lib_core::sign::document::Format;
use refineid_lib_core::sign::pades::{SignatureInk, SignatureMetadata};
use refineid_lib_pcsc::PcscBackend;

use crate::card_check::{CardCheckError, CardCheckOptions, CardCheckReport};
use crate::card_emrtd::{EmrtdReadError, EmrtdReadOptions, EmrtdReadReport};
use crate::card_pin::{
    ActivateOptions, ActivateReport, ActivationCardContext, CardPinError, ChangePinOptions,
    ChangePinReport, UnblockPinOptions, UnblockPinReport,
};
use crate::card_sign::{
    DocumentRequest, SignErrorKind, SignOptions, SignReport, TimestampCredentials,
    VisibleSignatureRequest,
};

/// Inputs for one visible qualified PDF signature from the graphical client.
#[derive(Debug)]
pub struct PdfSignOptions {
    /// Existing PDF chosen by the user.
    pub input: PathBuf,
    /// Distinct destination chosen before the card PIN is used.
    pub output: PathBuf,
    /// Qualified-signature PIN, consumed and zeroized by the sign operation.
    pub pin2: PinBytes,
    /// Optional CAN for contactless signing and DG7 access.
    pub can: Option<Can>,
    /// Reader shown in the card-manager view.
    pub reader_filter: Option<String>,
    /// Full serial captured when that view inspected the card.
    pub expected_serial: TokenSerial,
    /// Optional card-carried handwriting already decoded to RGBA ink.
    pub handwriting: Option<SignatureInk>,
    /// Sole qualified RFC 3161 authority selected in the graphical client.
    pub timestamp_authority: String,
    /// Optional in-memory HTTP Basic credentials for that authority.
    pub timestamp_credentials: Option<TimestampCredentials>,
}

/// Inputs for one qualified `ASiC-E` container signature from the
/// graphical client.
///
/// No visible-signature request: the container carries the file
/// unchanged, so there is no signed revision to draw a mark into.
#[derive(Debug)]
pub struct AsicSignOptions {
    /// Existing document of any type chosen by the user.
    pub input: PathBuf,
    /// Distinct destination chosen before the card PIN is used.
    pub output: PathBuf,
    /// Qualified-signature PIN, consumed and zeroized by the sign operation.
    pub pin2: PinBytes,
    /// Optional CAN for contactless signing.
    pub can: Option<Can>,
    /// Reader shown in the card-manager view.
    pub reader_filter: Option<String>,
    /// Full serial captured when that view inspected the card.
    pub expected_serial: TokenSerial,
    /// Sole qualified RFC 3161 authority selected in the graphical client.
    pub timestamp_authority: String,
    /// Optional in-memory HTTP Basic credentials for that authority.
    pub timestamp_credentials: Option<TimestampCredentials>,
}

/// Lightweight PC/SC reader-presence snapshot used only to detect changes.
///
/// The reader names may include unrelated smart cards. Callers must inspect
/// changed readers before treating any card as a supported FINEID card.
///
/// # Errors
/// Returns the PC/SC context or reader-enumeration failure.
pub fn present_readers() -> Result<Vec<String>, refineid_lib_pcsc::PcscError> {
    let mut readers = PcscBackend
        .enumerate()?
        .into_iter()
        .filter(|reader| reader.card_present)
        .map(|reader| reader.id.as_str().to_owned())
        .collect::<Vec<_>>();
    readers.sort_unstable();
    Ok(readers)
}

/// Inspect every connected FINEID card without network access or secret input.
///
/// The report includes certificate-derived identity, card metadata, and PIN
/// retry status. Portrait and displayed-signature images remain unavailable
/// until the caller explicitly supplies the card's CAN to [`read_images`].
///
/// # Errors
/// PC/SC enumeration, reader selection, or card-read failure.
pub fn inspect_cards(
    reader_filter: Option<String>,
) -> Result<Vec<CardCheckReport>, CardCheckError> {
    let options = CardCheckOptions {
        reader_filter,
        offline: true,
        can: None,
        crl_file: None,
        save_cert_dir: None,
        icao_pkd: None,
        now: None,
    };
    crate::card_check::check_all(PcscBackend, &options)
}

/// Read CAN-protected eMRTD personal data, including DG2 portrait and DG7
/// displayed-signature images when provisioned by the card issuer.
///
/// No image is written to disk. The caller owns display and explicit clipboard
/// actions, and should discard the returned report when the view is closed.
///
/// # Errors
/// Reader selection, PC/SC, PACE/CAN, secure-messaging, or data parsing failure.
pub fn read_images(
    can: Can,
    reader_filter: Option<String>,
) -> Result<EmrtdReadReport, EmrtdReadError> {
    let options = EmrtdReadOptions {
        can,
        save_face: None,
        save_sod: None,
        save_dsc: None,
        save_signature: None,
        csca_dir: None,
        reader_filter,
    };
    crate::card_emrtd::read_first(PcscBackend, &options)
}

/// Produce a visible qualified `PAdES-LTA` signature.
///
/// The visible name and SATU are resolved from the live signing certificate;
/// the request carries only the displayed card serial and optional DG7 ink.
/// The original input is read before the destination is written.
///
/// # Errors
/// Reader/card access, card-swap binding, PIN, document construction,
/// timestamp, revocation-evidence, or output-write failure.
pub fn sign_pdf(options: PdfSignOptions) -> Result<SignReport, SignErrorKind> {
    let PdfSignOptions {
        input,
        output,
        pin2,
        can,
        reader_filter,
        expected_serial,
        handwriting,
        timestamp_authority,
        timestamp_credentials,
    } = options;
    if input == output {
        return Err(SignErrorKind::SignatureWrite {
            path: output,
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "signed PDF destination must differ from the original",
            ),
        });
    }
    let document = pdf_document_request(
        expected_serial,
        handwriting,
        timestamp_authority,
        timestamp_credentials,
    );
    crate::card_sign::sign_qualified_first(
        PcscBackend,
        SignOptions {
            input,
            output,
            pin: pin2,
            save_cert: None,
            reader_filter,
            can,
            document: Some(document),
        },
    )
}

/// Produce an `ASiC-E` container carrying an `XAdES-LT` signature.
///
/// The `.asice`/`.bdoc` format Estonian `DigiDoc` and other Baltic
/// tooling exchanges (`ETSI EN 319 162-1`, `BDOC 2.1`): the file
/// travels unchanged inside the archive beside a signature that
/// covers it, with a signature timestamp and the collected chain and
/// revocation evidence. The original input is read before the
/// destination is written.
///
/// # Errors
/// Reader/card access, PIN, document construction, timestamp,
/// revocation-evidence, or output-write failure.
pub fn sign_asice(options: AsicSignOptions) -> Result<SignReport, SignErrorKind> {
    let AsicSignOptions {
        input,
        output,
        pin2,
        can,
        reader_filter,
        expected_serial,
        timestamp_authority,
        timestamp_credentials,
    } = options;
    if input == output {
        return Err(SignErrorKind::SignatureWrite {
            path: output,
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "signed container destination must differ from the original",
            ),
        });
    }
    let now = crate::card_check::now_date_time();
    let document = DocumentRequest {
        format: Format::AsicEXades,
        additional_inputs: Vec::new(),
        signing_time: SigningTime {
            year: now.year(),
            month: now.month(),
            day: now.day(),
            hour: now.hour(),
            minute: now.minutes(),
            second: now.seconds(),
        },
        metadata: SignatureMetadata::default(),
        expected_serial: Some(expected_serial),
        visible_signature: None,
        // Level LT: an archive construction for `ASiC-E` with `XAdES`
        // is not implemented, and the format refuses to pretend.
        archive: false,
        long_term: true,
        timestamp_authorities: vec![timestamp_authority],
        timestamp_credentials,
    };
    crate::card_sign::sign_qualified_first(
        PcscBackend,
        SignOptions {
            input,
            output,
            pin: pin2,
            save_cert: None,
            reader_filter,
            can,
            document: Some(document),
        },
    )
}

fn pdf_document_request(
    expected_serial: TokenSerial,
    handwriting: Option<SignatureInk>,
    timestamp_authority: String,
    timestamp_credentials: Option<TimestampCredentials>,
) -> DocumentRequest {
    let now = crate::card_check::now_date_time();
    DocumentRequest {
        format: Format::Pades,
        additional_inputs: Vec::new(),
        signing_time: SigningTime {
            year: now.year(),
            month: now.month(),
            day: now.day(),
            hour: now.hour(),
            minute: now.minutes(),
            second: now.seconds(),
        },
        metadata: SignatureMetadata::default(),
        expected_serial: Some(expected_serial),
        visible_signature: Some(VisibleSignatureRequest { handwriting }),
        archive: true,
        long_term: true,
        timestamp_authorities: vec![timestamp_authority],
        timestamp_credentials,
    }
}

/// Establish the trust-gated context needed by a card-activation screen.
///
/// The returned context identifies the card, reports the expected activation
/// code length, and binds later activation to the same reader and card serial.
///
/// # Errors
/// Reader/card access failure or failure of the FINEID root trust gate.
pub fn prepare_activation(
    reader_filter: Option<&ReaderFilter>,
) -> Result<ActivationCardContext, CardPinError> {
    crate::card_pin::classify_card_for_activation(PcscBackend, reader_filter)
}

/// Activate the card represented by `context` using typed, zeroizing secrets.
///
/// # Errors
/// Card swap, policy, PC/SC, PKCS#15, or activation transport failure.
pub fn activate(
    context: ActivationCardContext,
    options: ActivateOptions,
) -> Result<ActivateReport, CardPinError> {
    crate::card_pin::activate_first(PcscBackend, context, options)
}

/// Change PIN1 or PIN2 on the displayed card after a fresh trust-gated session.
///
/// `expected_serial` must be the full serial captured when the caller displayed
/// the card to the operator. A mismatch is refused before the modify APDU.
///
/// # Errors
/// Reader/card access, trust-gate, card-swap, PIN-policy, or transport failure.
pub fn change_pin(
    expected_serial: &TokenSerial,
    options: ChangePinOptions,
) -> Result<ChangePinReport, CardPinError> {
    let reader_filter = options.reader_filter.as_deref().map(ReaderFilter::new);
    let session = crate::card_pin::establish_trusted_session(PcscBackend, reader_filter.as_ref())?;
    ensure_displayed_serial(expected_serial, &session.bound_serial)?;
    crate::card_pin::change_pin_first(PcscBackend, session.into_pin_management_context(), options)
}

/// Unblock PIN1 or PIN2 on the displayed card with the typed PUK.
///
/// `expected_serial` is checked before the PUK-bearing modify APDU.
///
/// # Errors
/// Reader/card access, trust-gate, card-swap, PIN-policy, or transport failure.
pub fn unblock_pin(
    expected_serial: &TokenSerial,
    options: UnblockPinOptions,
) -> Result<UnblockPinReport, CardPinError> {
    let reader_filter = options.reader_filter.as_deref().map(ReaderFilter::new);
    let session = crate::card_pin::establish_trusted_session(PcscBackend, reader_filter.as_ref())?;
    ensure_displayed_serial(expected_serial, &session.bound_serial)?;
    crate::card_pin::unblock_pin_first(PcscBackend, session.into_pin_management_context(), options)
}

fn ensure_displayed_serial(
    expected_serial: &TokenSerial,
    live_serial: &TokenSerial,
) -> Result<(), CardPinError> {
    if expected_serial == live_serial {
        return Ok(());
    }
    Err(CardPinError::CardSessionRevoked {
        reason: format!(
            "displayed card serial {expected_serial:?} does not match live card serial {live_serial:?}"
        ),
    })
}

#[cfg(test)]
mod tests {
    use refineid_lib_core::identity::TokenSerial;

    use super::{ensure_displayed_serial, pdf_document_request};

    #[test]
    fn displayed_serial_mismatch_is_refused() {
        let displayed = TokenSerial::new("displayed-card".to_owned());
        let live = TokenSerial::new("replacement-card".to_owned());
        assert!(ensure_displayed_serial(&displayed, &live).is_err());
    }

    #[test]
    fn displayed_serial_match_is_accepted() {
        let serial = TokenSerial::new("same-card".to_owned());
        assert!(ensure_displayed_serial(&serial, &serial).is_ok());
    }

    #[test]
    fn graphical_pdf_signing_requests_qualified_lta() {
        let serial = TokenSerial::new("same-card".to_owned());
        let request = pdf_document_request(
            serial.clone(),
            None,
            "https://timestamp.sectigo.com/qualified".to_owned(),
            None,
        );
        assert_eq!(
            request.format,
            refineid_lib_core::sign::document::Format::Pades
        );
        assert!(request.archive);
        assert!(request.long_term);
        assert_eq!(
            request.timestamp_authorities,
            ["https://timestamp.sectigo.com/qualified"]
        );
        assert_eq!(request.expected_serial, Some(serial));
        let visible = request
            .visible_signature
            .expect("visible signature request");
        assert!(visible.handwriting.is_none());
    }
}
