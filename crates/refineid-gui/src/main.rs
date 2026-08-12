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

//! Portable desktop application for FINEID card management.

#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::Duration;

use arboard::{Clipboard, ImageData};
use image::{ImageDecoder as _, ImageFormat};
use refineid_client::card_pin::{
    ActivateOptions, ChangePinOptions, PinManageSlot, UnblockPinOptions,
};
use refineid_lib_core::auth::{PinStatus, PukStatus};
use refineid_lib_core::backend::ReaderFilter;
use refineid_lib_core::emrtd::DocumentImage;
use refineid_lib_core::identity::{TokenSerial, render_token_serial};
use refineid_lib_core::pin::{
    ActivationCode, ActivationPinEight, ActivationPinSeven, PinBytes, Puk,
};
use refineid_lib_core::pin_retry_risk::PinRetryRisk;
use refineid_lib_core::pkcs15::CardGeneration;
use refineid_lib_core::sign::document::Format;
use refineid_lib_core::sign::pades::SignatureInk;
use slint::{ComponentHandle as _, Image, Rgba8Pixel, SharedPixelBuffer};

/// How long one blocking presence wait parks before re-arming. The
/// monitor wakes on card insertion/removal and reader arrival, not on
/// a schedule; this bound only lets the loop notice a torn-down PC/SC
/// service. Idle steady-state performs no card opens at all.
const CARD_PRESENCE_WAIT: Duration = Duration::from_secs(30);
/// Grace period between a detected presence change and the full
/// inspection, so a just-inserted card finishes powering up.
const CARD_PRESENCE_SETTLE: Duration = Duration::from_millis(300);
/// Backoff after a presence-monitor error (PC/SC service restart)
/// before retrying, so a dead service is not spun on.
const CARD_PRESENCE_ERROR_BACKOFF: Duration = Duration::from_secs(5);
/// Short event-loop tick used only to collect completed background card reads.
const CARD_INSPECTION_RESULT_INTERVAL: Duration = Duration::from_millis(50);

const DENIED_PINS: &[&[u8]] = &[
    b"1122", b"1004", b"2000", b"2001", b"2002", b"2020", b"2580", b"5683", b"0852", b"112233",
    b"123321", b"147258", b"159753", b"258036", b"654321",
];

#[allow(
    missing_debug_implementations,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    reason = "Slint-generated module code is outside Rust source control and triggers lints that application code cannot repair"
)]
mod generated_ui {
    slint::include_modules!();
}

fn unblock_result_message(
    slot: PinManageSlot,
    outcome: refineid_lib_core::auth::UnblockOutcome,
) -> String {
    match outcome {
        refineid_lib_core::auth::UnblockOutcome::Ok => {
            format!("{} reactivated successfully.", slot.label())
        }
        refineid_lib_core::auth::UnblockOutcome::WrongPuk { retries_left } => {
            format!("Wrong PUK. {retries_left} attempts remaining.")
        }
        refineid_lib_core::auth::UnblockOutcome::PukLocked => {
            "The PUK is locked. The card must be replaced.".to_owned()
        }
        refineid_lib_core::auth::UnblockOutcome::Invalidated => {
            "The card can no longer be reactivated. The card must be replaced.".to_owned()
        }
        refineid_lib_core::auth::UnblockOutcome::LengthError => {
            "The card rejected the reactivation data.".to_owned()
        }
        refineid_lib_core::auth::UnblockOutcome::Other(status_word) => {
            format!("The card rejected the reactivation request (status {status_word:#06x}).")
        }
    }
}

const fn pin_locked(status: Option<&PinStatus>) -> bool {
    matches!(status, Some(PinStatus::Locked))
        || matches!(status, Some(PinStatus::Remaining(tries)) if tries.is_exhausted())
}

const fn pin_change_available(status: Option<&PinStatus>) -> bool {
    match status {
        Some(PinStatus::Remaining(tries)) => match PinRetryRisk::from_retries(*tries) {
            Some(risk) => risk.permits_consumer(),
            None => false,
        },
        Some(PinStatus::Verified) => true,
        Some(PinStatus::Locked | PinStatus::NoInfo | PinStatus::Other(_)) | None => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecoveryAvailability {
    pin1: bool,
    pin2: bool,
}

const fn recovery_availability(
    activation_available: bool,
    pin1_status: Option<&PinStatus>,
    pin2_status: Option<&PinStatus>,
) -> RecoveryAvailability {
    RecoveryAvailability {
        pin1: !activation_available && pin_locked(pin1_status),
        pin2: !activation_available && pin_locked(pin2_status),
    }
}

/// Distinguish an older card's factory activation state from a personalized
/// PIN1 that was later locked. Only the former requires replacing both PINs.
const fn legacy_activation_required(
    pin1_status: Option<&PinStatus>,
    definitely_unchanged_from_factory: bool,
) -> bool {
    pin_locked(pin1_status) && definitely_unchanged_from_factory
}

#[derive(Clone)]
struct ManagedCard {
    report: refineid_client::card_check::CardCheckReport,
    activation_context: Option<refineid_client::card_pin::ActivationCardContext>,
}

type CardInspectionResult = Result<Vec<ManagedCard>, String>;
type PdfSignResult = Result<String, String>;

struct PdfSigningJob {
    input: PathBuf,
    /// Further documents carried in the same container. Always empty
    /// for `PAdES`, which signs the one PDF it is given.
    additional_inputs: Vec<PathBuf>,
    output: PathBuf,
    pin2: PinBytes,
    can: Option<refineid_lib_core::can::Can>,
    reader: String,
    expected_serial: TokenSerial,
    handwriting: Option<SignatureInk>,
    timestamp_authority: String,
    timestamp_credentials: Option<refineid_client::card_sign::TimestampCredentials>,
    format: Format,
}

/// Start a full card inspection without blocking Slint's event loop.
fn request_card_inspection(
    window: &RefineIdWindow,
    sender: &mpsc::Sender<CardInspectionResult>,
    inspection_in_flight: &AtomicBool,
) {
    if inspection_in_flight
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    window.set_busy(true);
    let sender = sender.clone();
    thread::spawn(move || {
        let result = refineid_client::card_manager::inspect_cards(None)
            .map(deduplicate_cards)
            .map_err(|error| error.to_string());
        let _ = sender.send(result);
    });
}

#[derive(Clone)]
struct CachedImages {
    can: String,
    portrait: Option<UiImage>,
    signature: Option<UiImage>,
}

/// Condense a PC/SC reader name for display.
///
/// pcsc-lite composes reader names as `<vendor> <product> [<product>]
/// <interface> <slot>`, typically repeating the product name inside
/// the brackets and appending `00 00` for a sole reader. Drop the
/// bracketed segment when the surrounding text already contains it,
/// and the all-zero index suffix; non-zero indices still distinguish
/// multiple identical readers.
fn condense_reader_name(reader: &str) -> String {
    let mut name = reader.trim().to_owned();
    if let (Some(open), Some(close)) = (name.find('['), name.rfind(']'))
        && open < close
    {
        let inner = name[open + 1..close].trim().to_lowercase();
        let outer = format!("{} {}", &name[..open], &name[close + 1..]).to_lowercase();
        if !inner.is_empty() && outer.contains(&inner) {
            name.replace_range(open..=close, "");
        }
    }
    let mut words: Vec<&str> = name.split_whitespace().collect();
    if words.ends_with(&["00", "00"]) {
        words.truncate(words.len() - 2);
    }
    words.join(" ")
}

fn card_tab_label(card: &ManagedCard) -> String {
    let model = card
        .activation_context
        .as_ref()
        .map(|context| {
            format!(
                " / {} {} v{}",
                context.model.vendor(),
                context.model.vendor_product(),
                context.model.vendor_product_version()
            )
        })
        .unwrap_or_default();
    format!(
        "{} / {}{model}",
        card.report.identity.person_string(),
        condense_reader_name(&card.report.reader)
    )
}

fn clear_card_data(
    window: &RefineIdWindow,
    _portrait: &RefCell<Option<UiImage>>,
    _signature: &RefCell<Option<UiImage>>,
) {
    window.set_card_present(false);
    window.set_selected_view(0);
    window.set_person_name("".into());
    window.set_reader_name("".into());
    window.set_pin1_status("".into());
    window.set_pin2_status("".into());
    window.set_puk_status("".into());
    disarm_management_forms(window);
    disarm_pdf_signing(window);
    window.set_can_text("".into());
    window.set_signature_supported(false);
    window.set_pin1_change_available(false);
    window.set_pin2_change_available(false);
    window.set_activation_available(false);
    window.set_legacy_activation(false);
    window.set_pin1_unblock_available(false);
    window.set_pin2_unblock_available(false);
    window.set_unblock_uses_activation_code(false);
    // Portrait and signature are read-only data. Preserve them after card
    // removal or reader uncertainty so the user can still inspect them.
}

fn disarm_pdf_signing(window: &RefineIdWindow) {
    window.set_pdf_pin2("".into());
    window.set_pdf_sign_result("".into());
}

/// Remove every PIN-management credential and result from the UI model.
///
/// A refresh, selection, management-mode change, or view change invalidates the
/// operator context in which every one of these values was entered.
fn disarm_management_forms(window: &RefineIdWindow) {
    window.set_activation_code("".into());
    window.set_activation_pin1("".into());
    window.set_activation_pin1_confirm("".into());
    window.set_activation_pin2("".into());
    window.set_activation_pin2_confirm("".into());
    window.set_activation_result("".into());
    window.set_current_pin1("".into());
    window.set_new_pin1("".into());
    window.set_new_pin1_confirm("".into());
    window.set_current_pin2("".into());
    window.set_new_pin2("".into());
    window.set_new_pin2_confirm("".into());
    window.set_pin1_change_result("".into());
    window.set_pin2_change_result("".into());
    disarm_recovery_form(window);
}

/// Remove all one-shot PUK recovery state from the UI model.
///
/// This is called before the unblock callback validates or opens a card session,
/// and whenever the displayed-card or view context changes. The local `PinBytes`
/// moved out of the model remains available only to the in-flight callback.
fn disarm_recovery_form(window: &RefineIdWindow) {
    window.set_puk_code("".into());
    window.set_replacement_pin1("".into());
    window.set_replacement_pin1_confirm("".into());
    window.set_replacement_pin2("".into());
    window.set_replacement_pin2_confirm("".into());
    window.set_replacement_pin1_error("".into());
    window.set_replacement_pin2_error("".into());
    window.set_unblock_pin1_ready(false);
    window.set_unblock_pin2_ready(false);
    window.set_reactivation_result("".into());
}

/// Recovery inputs destructively removed from the Slint model for one callback.
struct RecoverySubmissionInputs {
    puk: Result<PinBytes, String>,
    new_pin: Result<PinBytes, String>,
    confirmation: Result<PinBytes, String>,
}

/// Move one slot's recovery inputs into callback-local refined values.
///
/// The entire recovery form is disarmed before this returns. A queued callback
/// therefore receives empty, locally rejected inputs and cannot reach card I/O.
fn take_recovery_submission(
    window: &RefineIdWindow,
    slot: PinManageSlot,
) -> RecoverySubmissionInputs {
    let puk = window.get_puk_code();
    let (new_pin, confirmation) = match slot {
        PinManageSlot::Pin1 => (
            window.get_replacement_pin1(),
            window.get_replacement_pin1_confirm(),
        ),
        PinManageSlot::Pin2 => (
            window.get_replacement_pin2(),
            window.get_replacement_pin2_confirm(),
        ),
    };
    disarm_recovery_form(window);
    refine_recovery_submission(puk, new_pin, confirmation)
}

fn refine_recovery_submission(
    puk: slint::SharedString,
    new_pin: slint::SharedString,
    confirmation: slint::SharedString,
) -> RecoverySubmissionInputs {
    RecoverySubmissionInputs {
        puk: secret(puk),
        new_pin: secret(new_pin),
        confirmation: secret(confirmation),
    }
}

fn validate_pin_confirmation(
    pin: &PinBytes,
    confirmation: &PinBytes,
    label: &str,
) -> Result<(), String> {
    if pin.as_bytes() != confirmation.as_bytes() {
        return Err(format!("{label} entries do not match"));
    }
    Ok(())
}

fn validate_replacement_pin(pin: &str, confirmation: &str, minimum: usize) -> (String, bool) {
    if pin.is_empty() || confirmation.is_empty() {
        return (String::new(), false);
    }
    if pin.len() != confirmation.len() {
        return ("new PIN entries do not match".to_owned(), false);
    }
    let result = secret(pin.into()).and_then(|pin| {
        let confirmation = secret(confirmation.into())?;
        validate_gui_pin(&pin, "new PIN", minimum)
            .and_then(|()| validate_pin_confirmation(&pin, &confirmation, "new PIN"))
    });
    (
        result.as_ref().err().cloned().unwrap_or_default(),
        result.is_ok(),
    )
}

fn card_key(card: &refineid_client::card_check::CardCheckReport) -> String {
    card.token_info.serial_number_hex.as_ref().map_or_else(
        || {
            format!(
                "fallback:{}\u{1f}{}",
                card.identity.person_string(),
                card.atr_hex
            )
        },
        |serial| format!("serial:{serial}"),
    )
}

fn deduplicate_cards(
    reports: Vec<refineid_client::card_check::CardCheckReport>,
) -> Vec<ManagedCard> {
    let mut cards = Vec::<ManagedCard>::new();
    for report in reports {
        if !cards
            .iter()
            .any(|card| card_key(&card.report) == card_key(&report))
        {
            let reader_filter = ReaderFilter::new(&report.reader);
            let activation_context =
                refineid_client::card_manager::prepare_activation(Some(&reader_filter)).ok();
            cards.push(ManagedCard {
                report,
                activation_context,
            });
        }
    }
    cards
}

fn management_state_matches(current: &[ManagedCard], fresh: &[ManagedCard]) -> bool {
    current.len() == fresh.len()
        && current.iter().all(|old| {
            fresh.iter().any(|new| {
                old.report.reader == new.report.reader
                    && old.report.token_info.serial_number_hex.is_some()
                    && old.report.token_info.serial_number_hex
                        == new.report.token_info.serial_number_hex
                    && old.report.pin1 == new.report.pin1
                    && old.report.pin2 == new.report.pin2
                    && old.report.puk == new.report.puk
                    && old.report.pin1_changed == new.report.pin1_changed
                    && old.report.pin2_changed == new.report.pin2_changed
            })
        })
}

fn show_selected_card(
    window: &RefineIdWindow,
    cards: &[ManagedCard],
    selected: usize,
    displayed_serial: &RefCell<Option<TokenSerial>>,
    portrait: &RefCell<Option<UiImage>>,
    signature: &RefCell<Option<UiImage>>,
    image_cache: &RefCell<HashMap<String, CachedImages>>,
) {
    let Some(card) = cards.get(selected) else {
        displayed_serial.borrow_mut().take();
        clear_card_data(window, portrait, signature);
        return;
    };
    *displayed_serial.borrow_mut() = card
        .report
        .token_info
        .serial_number_hex
        .clone()
        .map(render_token_serial);
    window.set_card_present(true);
    window.set_selected_card(i32::try_from(selected).unwrap_or(i32::MAX));
    window.set_person_name(card.report.identity.person_string().into());
    window.set_reader_name(card.report.reader.clone().into());
    window.set_pin1_status(pin_status(card.report.pin1.as_ref()).into());
    window.set_pin2_status(pin_status(card.report.pin2.as_ref()).into());
    window.set_puk_status(puk_status(card.report.puk.as_ref()).into());
    window.set_pin1_change_result("".into());
    window.set_pin2_change_result("".into());
    let mut pin1_change_available = pin_change_available(card.report.pin1.as_ref());
    let mut pin2_change_available = pin_change_available(card.report.pin2.as_ref());
    let mut activation_available = false;
    let mut legacy_activation = false;
    let mut pin1_unblock_available = false;
    let mut pin2_unblock_available = false;
    if let Some(context) = card.activation_context.as_ref() {
        window.set_reader_name(
            format!(
                "{} / {} {} v{}",
                condense_reader_name(&card.report.reader),
                context.model.vendor(),
                context.model.vendor_product(),
                context.model.vendor_product_version()
            )
            .into(),
        );
        window.set_signature_supported(context.generation == CardGeneration::Newer);
        legacy_activation = context.generation == CardGeneration::Older
            && legacy_activation_required(
                card.report.pin1.as_ref(),
                card.report.pin1_changed == Some(false),
            );
        activation_available = (context.generation == CardGeneration::Newer
            && card.report.pin1_changed == Some(false))
            || legacy_activation;
        let recovery = recovery_availability(
            activation_available,
            card.report.pin1.as_ref(),
            card.report.pin2.as_ref(),
        );
        pin1_unblock_available = recovery.pin1;
        pin2_unblock_available = recovery.pin2;
        window.set_unblock_uses_activation_code(context.generation == CardGeneration::Older);
    }
    if activation_available {
        pin1_change_available = false;
        pin2_change_available = false;
    }
    window.set_pin1_change_available(pin1_change_available);
    window.set_pin2_change_available(pin2_change_available);
    window.set_activation_available(activation_available);
    window.set_legacy_activation(legacy_activation);
    window.set_pin1_unblock_available(pin1_unblock_available);
    window.set_pin2_unblock_available(pin2_unblock_available);
    window.set_security_operation(if activation_available {
        0
    } else if pin1_unblock_available {
        3
    } else if pin2_unblock_available {
        4
    } else if pin1_change_available {
        1
    } else if pin2_change_available {
        2
    } else {
        -1
    });
    show_cached_images(window, card, portrait, signature, image_cache);
}

fn show_cached_images(
    window: &RefineIdWindow,
    card: &ManagedCard,
    portrait: &RefCell<Option<UiImage>>,
    signature: &RefCell<Option<UiImage>>,
    image_cache: &RefCell<HashMap<String, CachedImages>>,
) {
    if let Some(cached) = image_cache.borrow().get(&card_key(&card.report)).cloned() {
        window.set_can_text(cached.can.into());
        window.set_portrait(
            cached
                .portrait
                .as_ref()
                .map_or_else(Image::default, UiImage::image),
        );
        window.set_signature(
            cached
                .signature
                .as_ref()
                .map_or_else(Image::default, UiImage::image),
        );
        window.set_portrait_available(cached.portrait.is_some());
        window.set_signature_available(cached.signature.is_some());
        *portrait.borrow_mut() = cached.portrait;
        *signature.borrow_mut() = cached.signature;
    } else {
        window.set_can_text("".into());
        window.set_portrait(Image::default());
        window.set_signature(Image::default());
        window.set_portrait_available(false);
        window.set_signature_available(false);
        portrait.borrow_mut().take();
        signature.borrow_mut().take();
    }
}

fn refresh_cards(
    window: &RefineIdWindow,
    cards_state: &RefCell<Vec<ManagedCard>>,
    selected_reader: &RefCell<Option<String>>,
    displayed_serial: &RefCell<Option<TokenSerial>>,
    portrait: &RefCell<Option<UiImage>>,
    signature: &RefCell<Option<UiImage>>,
    image_cache: &RefCell<HashMap<String, CachedImages>>,
) {
    window.set_busy(true);
    match refineid_client::card_manager::inspect_cards(None).map(deduplicate_cards) {
        Ok(cards) => apply_inspected_cards(
            window,
            cards_state,
            selected_reader,
            displayed_serial,
            ImageStateRefs {
                portrait,
                signature,
                cache: image_cache,
            },
            cards,
        ),
        Err(error) => {
            clear_card_context(
                window,
                cards_state,
                selected_reader,
                displayed_serial,
                portrait,
                signature,
            );
            window.set_status_text(
                format!("Card refresh failed; card context cleared: {error}").into(),
            );
        }
    }
    window.set_busy(false);
}

#[derive(Clone, Copy)]
struct ImageStateRefs<'a> {
    portrait: &'a RefCell<Option<UiImage>>,
    signature: &'a RefCell<Option<UiImage>>,
    cache: &'a RefCell<HashMap<String, CachedImages>>,
}

fn apply_inspected_cards(
    window: &RefineIdWindow,
    cards_state: &RefCell<Vec<ManagedCard>>,
    selected_reader: &RefCell<Option<String>>,
    displayed_serial: &RefCell<Option<TokenSerial>>,
    images: ImageStateRefs<'_>,
    cards: Vec<ManagedCard>,
) {
    disarm_management_forms(window);
    disarm_pdf_signing(window);
    displayed_serial.borrow_mut().take();
    if cards.is_empty() {
        clear_card_context(
            window,
            cards_state,
            selected_reader,
            displayed_serial,
            images.portrait,
            images.signature,
        );
        window.set_status_text("No FINEID card is present.".into());
        return;
    }
    let selected = selected_reader
        .borrow()
        .as_ref()
        .and_then(|reader| cards.iter().position(|card| card.report.reader == *reader))
        .unwrap_or(0);
    let labels = cards
        .iter()
        .map(|card| card_tab_label(card).into())
        .collect::<Vec<slint::SharedString>>();
    window.set_card_tabs(Rc::new(slint::VecModel::from(labels)).into());
    *selected_reader.borrow_mut() = Some(cards[selected].report.reader.clone());
    *cards_state.borrow_mut() = cards;
    show_selected_card(
        window,
        &cards_state.borrow(),
        selected,
        displayed_serial,
        images.portrait,
        images.signature,
        images.cache,
    );
    window.set_status_text("".into());
}

/// Destroy all UI state that is valid only while a displayed card remains known.
fn clear_card_context(
    window: &RefineIdWindow,
    cards_state: &RefCell<Vec<ManagedCard>>,
    selected_reader: &RefCell<Option<String>>,
    displayed_serial: &RefCell<Option<TokenSerial>>,
    portrait: &RefCell<Option<UiImage>>,
    signature: &RefCell<Option<UiImage>>,
) {
    cards_state.borrow_mut().clear();
    selected_reader.borrow_mut().take();
    displayed_serial.borrow_mut().take();
    window.set_card_tabs(Rc::new(slint::VecModel::from(Vec::<slint::SharedString>::new())).into());
    clear_card_data(window, portrait, signature);
}

use generated_ui::RefineIdWindow;

#[derive(Clone)]
struct UiImage {
    pixels: SharedPixelBuffer<Rgba8Pixel>,
}

impl UiImage {
    fn image(&self) -> Image {
        Image::from_rgba8(self.pixels.clone())
    }

    fn signature_ink(&self) -> Option<SignatureInk> {
        SignatureInk::from_rgba(
            self.pixels.width(),
            self.pixels.height(),
            self.pixels.as_bytes(),
        )
    }

    fn copy_to_clipboard(&self) -> Result<(), String> {
        let data = ImageData {
            width: self.pixels.width() as usize,
            height: self.pixels.height() as usize,
            bytes: Cow::Borrowed(self.pixels.as_bytes()),
        };
        Clipboard::new()
            .and_then(|mut clipboard| clipboard.set_image(data))
            .map_err(|error| format!("clipboard: {error}"))
    }

    fn save_as_png(&self, default_name: &str) -> Result<bool, String> {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("PNG image", &["png"])
            .set_file_name(default_name)
            .save_file()
        else {
            return Ok(false);
        };
        let image = image::RgbaImage::from_raw(
            self.pixels.width(),
            self.pixels.height(),
            self.pixels.as_bytes().to_vec(),
        )
        .ok_or_else(|| "invalid image buffer".to_owned())?;
        image
            .save_with_format(path, ImageFormat::Png)
            .map_err(|error| format!("save PNG: {error}"))?;
        Ok(true)
    }
}

fn run_pdf_signing(job: PdfSigningJob) -> PdfSignResult {
    let PdfSigningJob {
        input,
        additional_inputs,
        output,
        pin2,
        can,
        reader,
        expected_serial,
        handwriting,
        timestamp_authority,
        timestamp_credentials,
        format,
    } = job;
    // The container carries the files unchanged, so there is no signed
    // revision to draw a visible mark into - the card images are not
    // read at all.
    if format == Format::AsicEXades {
        // What the container covers, said only when it is more than the
        // one document whose name the window shows.
        let carried = match additional_inputs.len() {
            0 => String::new(),
            rest => format!(" of {} documents", rest + 1),
        };
        refineid_client::card_manager::sign_asice(refineid_client::card_manager::AsicSignOptions {
            input,
            additional_inputs,
            output: output.clone(),
            pin2,
            can,
            reader_filter: Some(reader),
            expected_serial,
            timestamp_authority,
            timestamp_credentials,
        })
        .map_err(|error| error.to_string())?;
        return Ok(format!(
            "Signed container{carried} saved to {}.",
            output.display()
        ));
    }
    // Without the stamp feature no mark is requested, so the card is
    // not read for ink it would never draw.
    let handwriting = match (handwriting, can) {
        _ if !cfg!(feature = "pdf-stamp") => None,
        (Some(ink), _) => Some(ink),
        (None, Some(can)) => {
            let images = refineid_client::card_manager::read_images(can, Some(reader.clone()))
                .map_err(|error| format!("Cannot read the card handwriting: {error}"))?;
            images
                .data
                .signature_image
                .as_ref()
                .map(decode_image)
                .transpose()?
                .and_then(|image| image.signature_ink())
        }
        (None, None) => None,
    };
    refineid_client::card_manager::sign_pdf(refineid_client::card_manager::PdfSignOptions {
        input,
        output: output.clone(),
        pin2,
        can,
        reader_filter: Some(reader),
        expected_serial,
        handwriting,
        timestamp_authority,
        timestamp_credentials,
    })
    .map_err(|error| error.to_string())?;
    Ok(format!("Signed PDF saved to {}.", output.display()))
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "consuming the UI string keeps secret-bearing temporaries scoped to the PinBytes conversion"
)]
fn secret(value: slint::SharedString) -> Result<PinBytes, String> {
    PinBytes::new(value.as_bytes().to_vec()).map_err(|error| error.to_string())
}

fn numeric_input(value: &str) -> String {
    value
        .chars()
        .filter(char::is_ascii_digit)
        .take(12)
        .collect()
}

fn normalized_puk_input(value: &str) -> String {
    numeric_input(value)
}

fn image_file_name(person_name: &str, image_label: &str) -> String {
    let safe_name = person_name
        .chars()
        .map(|character| match character {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            _ => character,
        })
        .collect::<String>();
    if safe_name.trim().is_empty() {
        format!("Card - {image_label}.png")
    } else {
        format!("{safe_name} - {image_label}.png")
    }
}

/// The signed document's suggested name: the original's, with the UTC
/// signing instant, colons replaced so the name is safe everywhere.
///
/// The extension follows the format: the PDF keeps its own, a
/// container is named `.asice`.
fn signed_document_file_name(
    input: &std::path::Path,
    signed_at: &refineid_lib_core::x509::DateTime,
    extension: &str,
) -> String {
    let stem = input
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .filter(|stem| !stem.trim().is_empty())
        .unwrap_or("Document");
    let instant = signed_at.to_string().replace(':', "-");
    format!("{stem} - signed at {instant}.{extension}")
}

/// What a set of chosen documents becomes, said only when it is more
/// than one file: a single row already says everything about itself.
///
/// A container carries the set under one signature; `PAdES` signs the
/// one PDF it is given, so a set never takes that shape.
fn chosen_documents_summary(paths: &[PathBuf]) -> String {
    match paths.len() {
        0 | 1 => String::new(),
        count => format!("{count} documents in one container"),
    }
}

/// The file names shown for the documents waiting to be signed.
///
/// The name alone, never the path: the window is not the place a
/// holder's directory layout is published, and the name is what the
/// container will carry the file under.
fn chosen_document_names(paths: &[PathBuf]) -> Vec<slint::SharedString> {
    paths
        .iter()
        .map(|path| {
            path.file_name()
                .and_then(std::ffi::OsStr::to_str)
                .unwrap_or("Document")
                .into()
        })
        .collect()
}

/// Shows the documents waiting to be signed, and the shape they can
/// take.
///
/// One place decides all three, because they are one fact: a set that
/// lost a row and kept its count, or kept `PAdES` offered after a
/// spreadsheet joined it, would be describing documents that are no
/// longer there. One PDF alone can carry its own signature and
/// defaults to that; anything else - another file type, or a set of
/// them - signs into one `ASiC-E` container covered by one signature,
/// with the choice shown locked rather than hidden.
fn show_chosen_documents(window: &RefineIdWindow, documents: &[PathBuf]) {
    window.set_pdf_documents(slint::ModelRc::new(slint::VecModel::from(
        chosen_document_names(documents),
    )));
    window.set_pdf_document_summary(chosen_documents_summary(documents).into());
    let signs_in_place = matches!(documents, [only] if is_pdf(only));
    window.set_sign_format_locked(!signs_in_place);
    window.set_sign_format(i32::from(!signs_in_place));
}

/// Whether a chosen file can hold a `PAdES` signature at all.
fn is_pdf(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|extension| extension.eq_ignore_ascii_case("pdf"))
}

fn timestamp_authority_url(scheme: i32, host_path: &str) -> Result<String, String> {
    let scheme = match scheme {
        0 => "https",
        1 => "http",
        _ => return Err("Choose HTTP or HTTPS for the timestamp authority.".to_owned()),
    };
    let host_path = host_path.trim();
    if host_path.is_empty() {
        return Err("Enter the timestamp authority host and path.".to_owned());
    }
    if host_path.contains("://") || host_path.starts_with('/') {
        return Err("Enter only the timestamp authority host and path.".to_owned());
    }
    let url = format!("{scheme}://{host_path}");
    refineid_lib_core::text::Uri::parse(url.clone())
        .map_err(|error| format!("Invalid timestamp authority: {error}"))?;
    Ok(url)
}

fn timestamp_credentials(
    username: &str,
    password: &str,
) -> Result<Option<refineid_client::card_sign::TimestampCredentials>, String> {
    match (username.is_empty(), password.is_empty()) {
        (true, true) => Ok(None),
        (true, false) => Err("Enter the timestamp username.".to_owned()),
        (false, true) => Err("Enter the timestamp password.".to_owned()),
        (false, false) => refineid_client::card_sign::TimestampCredentials::new(
            username.to_owned(),
            password.to_owned(),
        )
        .map(Some)
        .map_err(str::to_owned),
    }
}

fn optional_can(value: &str) -> Result<Option<refineid_lib_core::can::Can>, String> {
    if value.trim().is_empty() {
        Ok(None)
    } else {
        refineid_lib_core::can::Can::new(value)
            .map(Some)
            .map_err(|error| format!("Invalid CAN: {error}"))
    }
}

fn validate_gui_numeric(
    value: &PinBytes,
    label: &str,
    expected_length: Option<usize>,
) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(format!("{label} must contain digits only"));
    }
    if let Some(expected) = expected_length
        && bytes.len() != expected
    {
        return Err(format!("{label} must be exactly {expected} digits"));
    }
    Ok(())
}

fn validate_gui_pin(value: &PinBytes, label: &str, minimum: usize) -> Result<(), String> {
    validate_gui_pin_format(value, label, minimum)?;
    let bytes = value.as_bytes();
    let ascending = bytes
        .windows(2)
        .all(|pair| pair[1] == b'0' + (pair[0] - b'0' + 1) % 10);
    let descending = bytes
        .windows(2)
        .all(|pair| pair[1] == b'0' + (pair[0] - b'0' + 9) % 10);
    let repeated_pattern = (1..=bytes.len() / 2).any(|pattern_length| {
        bytes.len().is_multiple_of(pattern_length)
            && bytes[pattern_length..] == bytes[..bytes.len() - pattern_length]
    });
    if ascending || descending {
        return Err(format!(
            "{label} is too easy to guess because it uses consecutive digits"
        ));
    }
    if repeated_pattern {
        return Err(format!(
            "{label} is too easy to guess because it repeats a pattern"
        ));
    }
    if DENIED_PINS.contains(&bytes) {
        return Err(format!("{label} is too common and cannot be used"));
    }
    Ok(())
}

fn validate_gui_puk(value: &PinBytes) -> Result<(), String> {
    validate_gui_numeric(value, "PUK", None)?;
    if !(Puk::MIN_LENGTH..=Puk::MAX_LENGTH).contains(&value.digit_count()) {
        return Err(format!(
            "PUK must contain {} or {} digits",
            Puk::MIN_LENGTH,
            Puk::MAX_LENGTH
        ));
    }
    Ok(())
}

fn validate_gui_pin_format(value: &PinBytes, label: &str, minimum: usize) -> Result<(), String> {
    validate_gui_numeric(value, label, None)?;
    let bytes = value.as_bytes();
    if !(minimum..=12).contains(&bytes.len()) {
        return Err(format!("{label} must contain {minimum} to 12 digits"));
    }
    Ok(())
}

fn validate_pin_pair(
    current: &PinBytes,
    new: &PinBytes,
    slot: PinManageSlot,
) -> Result<(), String> {
    let (label, minimum) = match slot {
        PinManageSlot::Pin1 => ("authentication PIN", 4),
        PinManageSlot::Pin2 => ("signing PIN", 6),
    };
    validate_gui_pin_format(current, &format!("current {label}"), minimum)?;
    validate_gui_pin(new, &format!("new {label}"), minimum)
}

fn activation_code(bytes: PinBytes, expected_length: usize) -> Result<ActivationCode, String> {
    match expected_length {
        ActivationPinSeven::LENGTH => ActivationPinSeven::new(bytes)
            .map(ActivationCode::Seven)
            .map_err(|error| error.to_string()),
        ActivationPinEight::LENGTH => ActivationPinEight::new(bytes)
            .map(ActivationCode::Eight)
            .map_err(|error| error.to_string()),
        other => Err(format!("unsupported activation-code length {other}")),
    }
}

fn decode_image(document: &DocumentImage) -> Result<UiImage, String> {
    let decoded = match document {
        DocumentImage::Jpeg(bytes) => image::load_from_memory_with_format(bytes, ImageFormat::Jpeg)
            .map_err(|error| format!("decode JPEG card image: {error}"))?,
        DocumentImage::Jpeg2000(bytes) => {
            let decoder =
                pdfluent_jpeg2000::integration::Jp2Decoder::new(std::io::Cursor::new(bytes))
                    .map_err(|error| format!("decode JPEG2000 card image header: {error}"))?;
            let (width, height) = decoder.dimensions();
            let color = decoder.color_type();
            let raw_len = usize::try_from(decoder.total_bytes())
                .map_err(|_| "JPEG2000 card image is too large for this platform".to_owned())?;
            let mut raw = vec![0_u8; raw_len];
            decoder
                .read_image(&mut raw)
                .map_err(|error| format!("decode JPEG2000 card image: {error}"))?;
            match color {
                image::ColorType::L8 => image::GrayImage::from_raw(width, height, raw)
                    .map(image::DynamicImage::ImageLuma8),
                image::ColorType::La8 => image::GrayAlphaImage::from_raw(width, height, raw)
                    .map(image::DynamicImage::ImageLumaA8),
                image::ColorType::Rgb8 => image::RgbImage::from_raw(width, height, raw)
                    .map(image::DynamicImage::ImageRgb8),
                image::ColorType::Rgba8 => image::RgbaImage::from_raw(width, height, raw)
                    .map(image::DynamicImage::ImageRgba8),
                other => return Err(format!("unsupported JPEG2000 output color type {other:?}")),
            }
            .ok_or_else(|| "JPEG2000 decoder returned an invalid image buffer length".to_owned())?
        }
    };
    let decoded = decoded.to_rgba8();
    let (width, height) = decoded.dimensions();
    let pixels = SharedPixelBuffer::<Rgba8Pixel>::clone_from_slice(decoded.as_raw(), width, height);
    Ok(UiImage { pixels })
}

fn pin_status(status: Option<&PinStatus>) -> String {
    match status {
        Some(PinStatus::Remaining(tries)) => format!("{tries} attempts remaining"),
        Some(PinStatus::Verified) => "Verified".to_owned(),
        Some(PinStatus::Locked) => "Locked".to_owned(),
        Some(PinStatus::NoInfo) => "No retry information".to_owned(),
        Some(PinStatus::Other(status_word)) => {
            format!("Card returned status {status_word:#06x}")
        }
        None => "Unavailable".to_owned(),
    }
}

fn puk_status(status: Option<&PukStatus>) -> String {
    match status {
        Some(PukStatus::Remaining(tries)) => format!("{tries} attempts remaining"),
        Some(PukStatus::Locked) => "Locked".to_owned(),
        Some(PukStatus::Invalidated) => "Invalidated".to_owned(),
        Some(PukStatus::NoInfo) => "No retry information".to_owned(),
        Some(PukStatus::Other(status_word)) => {
            format!("Card returned status {status_word:#06x}")
        }
        None => "Unavailable".to_owned(),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "Slint callback registration is one ownership graph; splitting it would multiply weak handles and obscure UI state lifetimes"
)]
fn main() -> Result<(), slint::PlatformError> {
    let window = RefineIdWindow::new()?;
    window.set_window_title(format!("ReFineID {}", env!("REFINEID_GUI_BUILD_VERSION")).into());
    let portrait = Rc::new(RefCell::new(None::<UiImage>));
    let signature = Rc::new(RefCell::new(None::<UiImage>));
    let image_cache = Rc::new(RefCell::new(HashMap::<String, CachedImages>::new()));
    let cards = Rc::new(RefCell::new(Vec::<ManagedCard>::new()));
    // Every document chosen in one go, in the order it will be carried.
    // Empty until something is chosen; more than one means a container.
    let pdf_document = Rc::new(RefCell::new(Vec::<PathBuf>::new()));
    {
        let weak = window.as_weak();
        window.on_puk_code_edited(move |value| {
            let Some(window) = weak.upgrade() else {
                return;
            };
            let digits = normalized_puk_input(value.as_str());
            if digits != value.as_str() {
                window.set_puk_code(digits.into());
            }
        });
    }
    {
        let weak = window.as_weak();
        window.on_pin_input_edited(move |value, field| {
            let Some(window) = weak.upgrade() else {
                return;
            };
            let digits = numeric_input(value.as_str());
            if digits == value.as_str() {
                return;
            }
            let value = slint::SharedString::from(digits);
            match field {
                0 => window.set_activation_code(value),
                1 => window.set_activation_pin1(value),
                2 => window.set_activation_pin1_confirm(value),
                3 => window.set_activation_pin2(value),
                4 => window.set_activation_pin2_confirm(value),
                5 => window.set_current_pin1(value),
                6 => window.set_new_pin1(value),
                7 => window.set_new_pin1_confirm(value),
                8 => window.set_current_pin2(value),
                9 => window.set_new_pin2(value),
                10 => window.set_new_pin2_confirm(value),
                11 => window.set_replacement_pin1(value),
                12 => window.set_replacement_pin1_confirm(value),
                13 => window.set_replacement_pin2(value),
                14 => window.set_replacement_pin2_confirm(value),
                15 => window.set_pdf_pin2(value),
                _ => {}
            }
        });
    }
    {
        let weak = window.as_weak();
        window.on_reactivation_inputs_edited(move || {
            let Some(window) = weak.upgrade() else {
                return;
            };
            let puk_valid = secret(window.get_puk_code())
                .and_then(|puk| validate_gui_puk(&puk))
                .is_ok();
            let pin1 = window.get_replacement_pin1();
            let pin1_confirmation = window.get_replacement_pin1_confirm();
            let (pin1_error, pin1_valid) =
                validate_replacement_pin(pin1.as_str(), pin1_confirmation.as_str(), 4);
            let pin2 = window.get_replacement_pin2();
            let pin2_confirmation = window.get_replacement_pin2_confirm();
            let (pin2_error, pin2_valid) =
                validate_replacement_pin(pin2.as_str(), pin2_confirmation.as_str(), 6);
            window.set_replacement_pin1_error(pin1_error.into());
            window.set_replacement_pin2_error(pin2_error.into());
            window.set_unblock_pin1_ready(puk_valid && pin1_valid);
            window.set_unblock_pin2_ready(puk_valid && pin2_valid);
        });
    }
    let selected_reader = Rc::new(RefCell::new(None::<String>));
    let displayed_serial = Rc::new(RefCell::new(None::<TokenSerial>));
    let inspection_result_timer = slint::Timer::default();
    let pdf_sign_result_timer = slint::Timer::default();
    let (inspection_sender, inspection_receiver) = mpsc::channel::<CardInspectionResult>();
    let (pdf_sign_sender, pdf_sign_receiver) = mpsc::channel::<PdfSignResult>();
    let inspection_in_flight = Arc::new(AtomicBool::new(false));

    {
        let weak = window.as_weak();
        window.on_can_text_edited(move |value| {
            if value.len() > 6
                && let Some(window) = weak.upgrade()
            {
                window.set_can_text(value.chars().take(6).collect::<String>().into());
            }
        });
    }

    {
        let weak = window.as_weak();
        let inspection_sender = inspection_sender.clone();
        let inspection_in_flight = Arc::clone(&inspection_in_flight);
        window.on_refresh_card(move || {
            let Some(window) = weak.upgrade() else {
                return;
            };
            request_card_inspection(&window, &inspection_sender, &inspection_in_flight);
        });
    }

    {
        let weak = window.as_weak();
        let cards_state = Rc::clone(&cards);
        let selected_reader_state = Rc::clone(&selected_reader);
        let displayed_serial_state = Rc::clone(&displayed_serial);
        let portrait_state = Rc::clone(&portrait);
        let signature_state = Rc::clone(&signature);
        let image_cache_state = Rc::clone(&image_cache);
        let inspection_in_flight = Arc::clone(&inspection_in_flight);
        inspection_result_timer.start(
            slint::TimerMode::Repeated,
            CARD_INSPECTION_RESULT_INTERVAL,
            move || {
                let Some(window) = weak.upgrade() else {
                    return;
                };
                match inspection_receiver.try_recv() {
                    Ok(Ok(fresh)) => {
                        inspection_in_flight.store(false, Ordering::Release);
                        if !management_state_matches(&cards_state.borrow(), &fresh) {
                            apply_inspected_cards(
                                &window,
                                &cards_state,
                                &selected_reader_state,
                                &displayed_serial_state,
                                ImageStateRefs {
                                    portrait: &portrait_state,
                                    signature: &signature_state,
                                    cache: &image_cache_state,
                                },
                                fresh,
                            );
                        }
                        window.set_busy(false);
                    }
                    Ok(Err(error)) => {
                        inspection_in_flight.store(false, Ordering::Release);
                        clear_card_context(
                            &window,
                            &cards_state,
                            &selected_reader_state,
                            &displayed_serial_state,
                            &portrait_state,
                            &signature_state,
                        );
                        window.set_status_text(
                            format!("Card status monitoring failed; card context cleared: {error}")
                                .into(),
                        );
                        window.set_busy(false);
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => {
                        inspection_in_flight.store(false, Ordering::Release);
                        window.set_busy(false);
                    }
                }
            },
        );
    }

    {
        let weak = window.as_weak();
        let pdf_document_state = Rc::clone(&pdf_document);
        window.on_choose_pdf(move || {
            let Some(window) = weak.upgrade() else {
                return;
            };
            // The permissive filter is offered first because it is the
            // true one: a container carries any file type, and a
            // dialog opening on "PDF document" shows an empty folder
            // to someone signing a spreadsheet, which reads as a
            // format this cannot sign rather than as a filter.
            let Some(paths) = rfd::FileDialog::new()
                .add_filter("Any document", &["*"])
                .add_filter("PDF document", &["pdf"])
                .pick_files()
            else {
                return;
            };
            if paths.is_empty() {
                return;
            }
            // Chosen documents are added to what is already waiting, so
            // a set can be gathered from more than one folder without
            // the second visit discarding the first.
            let mut documents = pdf_document_state.borrow_mut();
            for path in paths {
                if !documents.contains(&path) {
                    documents.push(path);
                }
            }
            show_chosen_documents(&window, &documents);
            drop(documents);
            window.set_pdf_sign_result("".into());
        });
    }

    {
        let weak = window.as_weak();
        let pdf_document_state = Rc::clone(&pdf_document);
        window.on_remove_pdf_document(move |index| {
            let Some(window) = weak.upgrade() else {
                return;
            };
            if window.get_busy() {
                return;
            }
            let mut documents = pdf_document_state.borrow_mut();
            let Ok(index) = usize::try_from(index) else {
                return;
            };
            if index >= documents.len() {
                return;
            }
            documents.remove(index);
            show_chosen_documents(&window, &documents);
            drop(documents);
            window.set_pdf_sign_result("".into());
        });
    }

    {
        let weak = window.as_weak();
        let pdf_document_state = Rc::clone(&pdf_document);
        window.on_clear_pdf_documents(move || {
            let Some(window) = weak.upgrade() else {
                return;
            };
            if window.get_busy() {
                return;
            }
            let mut documents = pdf_document_state.borrow_mut();
            documents.clear();
            show_chosen_documents(&window, &documents);
            drop(documents);
            window.set_pdf_sign_result("".into());
        });
    }

    {
        let weak = window.as_weak();
        let pdf_document_state = Rc::clone(&pdf_document);
        let selected_reader_state = Rc::clone(&selected_reader);
        let displayed_serial_state = Rc::clone(&displayed_serial);
        let signature_state = Rc::clone(&signature);
        let result_sender = pdf_sign_sender;
        window.on_sign_pdf(move || {
            let Some(window) = weak.upgrade() else {
                return;
            };
            if window.get_busy() {
                return;
            }
            let chosen = pdf_document_state.borrow().clone();
            let Some((input, additional_inputs)) = chosen
                .split_first()
                .map(|(first, rest)| (first.clone(), rest.to_vec()))
            else {
                window.set_pdf_sign_result("Choose a document first.".into());
                return;
            };
            let format = if window.get_sign_format() == 1 {
                Format::AsicEXades
            } else {
                Format::Pades
            };
            // A PDF carries its own signature and cannot carry another
            // document's, so a set has only the container shape. The
            // chooser already locks this; refused here too, because a
            // format that signed one file of a chosen set would leave
            // the rest unsigned without saying so.
            if format == Format::Pades && !additional_inputs.is_empty() {
                window.set_pdf_sign_result(
                    "Several documents can only be signed into one ASiC-E container.".into(),
                );
                return;
            }
            let (filter_name, extension) = match format {
                Format::AsicEXades => ("ASiC-E container", "asice"),
                _ => ("PDF document", "pdf"),
            };
            let default_name = signed_document_file_name(
                &input,
                &refineid_client::card_check::now_date_time(),
                extension,
            );
            let mut dialog = rfd::FileDialog::new()
                .add_filter(filter_name, &[extension])
                .set_file_name(&default_name);
            if let Some(parent) = input.parent() {
                dialog = dialog.set_directory(parent);
            }
            let Some(mut output) = dialog.save_file() else {
                return;
            };
            if output.extension().is_none() {
                output.set_extension(extension);
            }
            if output == input || additional_inputs.contains(&output) {
                window.set_pdf_sign_result(
                    "Choose a destination different from the original documents.".into(),
                );
                return;
            }

            let pin2 = secret(window.get_pdf_pin2());
            window.set_pdf_pin2("".into());
            let job: Result<PdfSigningJob, String> = (|| {
                let pin2 = pin2?;
                validate_gui_pin_format(&pin2, "PIN2", 6)?;
                let timestamp_authority = timestamp_authority_url(
                    window.get_timestamp_scheme(),
                    window.get_timestamp_host_path().as_str(),
                )?;
                let timestamp_credentials = timestamp_credentials(
                    window.get_timestamp_username().as_str(),
                    window.get_timestamp_password().as_str(),
                )?;
                if window.get_timestamp_scheme() == 1 && timestamp_credentials.is_some() {
                    return Err(
                        "Timestamp username and password may only be sent over HTTPS.".to_owned(),
                    );
                }
                let can = optional_can(window.get_can_text().as_str())?;
                let reader = selected_reader_state
                    .borrow()
                    .clone()
                    .ok_or_else(|| "The displayed card has no reader.".to_owned())?;
                let expected_serial = displayed_serial_state
                    .borrow()
                    .clone()
                    .ok_or_else(|| "The displayed card has no session serial.".to_owned())?;
                let handwriting = signature_state
                    .borrow()
                    .as_ref()
                    .and_then(UiImage::signature_ink);
                Ok(PdfSigningJob {
                    input,
                    additional_inputs,
                    output,
                    pin2,
                    can,
                    reader,
                    expected_serial,
                    handwriting,
                    timestamp_authority,
                    timestamp_credentials,
                    format,
                })
            })();
            let job = match job {
                Ok(job) => job,
                Err(error) => {
                    window.set_pdf_sign_result(error.into());
                    return;
                }
            };
            window.set_pdf_sign_result("Signing and collecting validation evidence...".into());
            window.set_busy(true);
            let sender = result_sender.clone();
            thread::spawn(move || {
                let _ignored = sender.send(run_pdf_signing(job));
            });
        });
    }

    {
        let weak = window.as_weak();
        pdf_sign_result_timer.start(
            slint::TimerMode::Repeated,
            CARD_INSPECTION_RESULT_INTERVAL,
            move || {
                let Some(window) = weak.upgrade() else {
                    return;
                };
                match pdf_sign_receiver.try_recv() {
                    Ok(Ok(message)) => {
                        window.set_pdf_sign_result(message.into());
                        window.set_busy(false);
                    }
                    Ok(Err(error)) => {
                        window.set_pdf_sign_result(format!("PDF signing failed: {error}").into());
                        window.set_busy(false);
                    }
                    Err(TryRecvError::Empty | TryRecvError::Disconnected) => {}
                }
            },
        );
    }

    for is_portrait in [true, false] {
        let weak = window.as_weak();
        let state = if is_portrait {
            Rc::clone(&portrait)
        } else {
            Rc::clone(&signature)
        };
        let handler = move || {
            let Some(window) = weak.upgrade() else {
                return;
            };
            let label = if is_portrait { "Portrait" } else { "Signature" };
            let default_name = image_file_name(window.get_person_name().as_str(), label);
            let result = state
                .borrow()
                .as_ref()
                .ok_or_else(|| format!("{} is not loaded", label.to_lowercase()))
                .and_then(|image| image.save_as_png(&default_name));
            window.set_status_text(match result {
                Ok(true) => format!("{label} saved as PNG.").into(),
                Ok(false) => "Save cancelled.".into(),
                Err(error) => format!("Save failed: {error}").into(),
            });
        };
        if is_portrait {
            window.on_save_portrait(handler);
        } else {
            window.on_save_signature(handler);
        }
    }

    {
        // Event-driven presence monitor: parks in SCardGetStatusChange
        // and requests one full inspection per card insertion/removal
        // or reader arrival. No timed polling -- a peer holding the
        // card (Firefox mid-handshake) is never disturbed, and an idle
        // application performs no card traffic at all.
        let weak = window.as_weak();
        let inspection_sender = inspection_sender.clone();
        let inspection_in_flight = Arc::clone(&inspection_in_flight);
        thread::spawn(move || {
            let mut baseline = refineid_lib_pcsc::presence_signature().unwrap_or_default();
            loop {
                match refineid_lib_pcsc::wait_for_presence_change(&baseline, CARD_PRESENCE_WAIT) {
                    Ok(true) => {
                        thread::sleep(CARD_PRESENCE_SETTLE);
                        baseline = refineid_lib_pcsc::presence_signature().unwrap_or(baseline);
                        let sender = inspection_sender.clone();
                        let in_flight = Arc::clone(&inspection_in_flight);
                        let dispatched = weak.upgrade_in_event_loop(move |window| {
                            if !window.get_busy() {
                                request_card_inspection(&window, &sender, &in_flight);
                            }
                        });
                        if dispatched.is_err() {
                            // Event loop gone: the application is
                            // shutting down.
                            break;
                        }
                    }
                    Ok(false) => {}
                    Err(_service_down) => thread::sleep(CARD_PRESENCE_ERROR_BACKOFF),
                }
            }
        });
    }

    {
        let weak = window.as_weak();
        let cards_state = Rc::clone(&cards);
        let selected_reader_state = Rc::clone(&selected_reader);
        let displayed_serial_state = Rc::clone(&displayed_serial);
        let portrait_state = Rc::clone(&portrait);
        let signature_state = Rc::clone(&signature);
        let image_cache_state = Rc::clone(&image_cache);
        window.on_select_card(move |index| {
            let Some(window) = weak.upgrade() else {
                return;
            };
            let Ok(index) = usize::try_from(index) else {
                return;
            };
            let cards = cards_state.borrow();
            if let Some(card) = cards.get(index) {
                disarm_management_forms(&window);
                disarm_pdf_signing(&window);
                displayed_serial_state.borrow_mut().take();
                *selected_reader_state.borrow_mut() = Some(card.report.reader.clone());
                show_selected_card(
                    &window,
                    &cards,
                    index,
                    &displayed_serial_state,
                    &portrait_state,
                    &signature_state,
                    &image_cache_state,
                );
            }
        });
    }

    {
        let weak = window.as_weak();
        let selected_reader_state = Rc::clone(&selected_reader);
        let displayed_serial_state = Rc::clone(&displayed_serial);
        let cards_state = Rc::clone(&cards);
        let portrait_state = Rc::clone(&portrait);
        let signature_state = Rc::clone(&signature);
        let image_cache_state = Rc::clone(&image_cache);
        window.on_load_images(move || {
            let Some(window) = weak.upgrade() else {
                return;
            };
            let selected_reader = selected_reader_state.borrow().clone();
            let card_is_present = selected_reader.as_ref().is_some_and(|reader| {
                refineid_client::card_manager::present_readers()
                    .is_ok_and(|readers| readers.contains(reader))
            });
            if !card_is_present {
                clear_card_context(
                    &window,
                    &cards_state,
                    &selected_reader_state,
                    &displayed_serial_state,
                    &portrait_state,
                    &signature_state,
                );
                window.set_status_text("Card removed. Displayed card data was cleared.".into());
                return;
            }
            let can = match refineid_lib_core::can::Can::new(window.get_can_text().as_str()) {
                Ok(can) => can,
                Err(error) => {
                    window.set_status_text(format!("Invalid CAN: {error}").into());
                    return;
                }
            };
            window.set_busy(true);
            window.set_portrait_available(false);
            window.set_signature_available(false);
            portrait_state.borrow_mut().take();
            signature_state.borrow_mut().take();
            let selected_reader_for_cache = selected_reader.clone();
            match refineid_client::card_manager::read_images(can, selected_reader) {
                Ok(report) => {
                    let mut messages = Vec::new();
                    if let Some(document) = report.data.face.as_ref() {
                        match decode_image(document) {
                            Ok(decoded) => {
                                window.set_portrait(decoded.image());
                                window.set_portrait_available(true);
                                *portrait_state.borrow_mut() = Some(decoded);
                            }
                            Err(error) => messages.push(format!("portrait: {error}")),
                        }
                    } else {
                        messages.push("portrait not present".to_owned());
                    }
                    if let Some(document) = report.data.signature_image.as_ref() {
                        match decode_image(document) {
                            Ok(decoded) => {
                                window.set_signature(decoded.image());
                                window.set_signature_available(true);
                                *signature_state.borrow_mut() = Some(decoded);
                            }
                            Err(error) => messages.push(format!("signature: {error}")),
                        }
                    } else if window.get_signature_supported() {
                        messages.push("signature not present".to_owned());
                    }
                    window.set_status_text(if messages.is_empty() {
                        "".into()
                    } else {
                        messages.join("; ").into()
                    });
                }
                Err(error) => window.set_status_text(format!("Image read failed: {error}").into()),
            }
            if let Some(card) = cards_state.borrow().iter().find(|card| {
                selected_reader_for_cache.as_deref() == Some(card.report.reader.as_str())
            }) {
                image_cache_state.borrow_mut().insert(
                    card_key(&card.report),
                    CachedImages {
                        can: window.get_can_text().to_string(),
                        portrait: portrait_state.borrow().clone(),
                        signature: signature_state.borrow().clone(),
                    },
                );
            }
            window.set_busy(false);
        });
    }

    {
        let weak = window.as_weak();
        let state = Rc::clone(&portrait);
        window.on_copy_portrait(move || {
            let Some(window) = weak.upgrade() else {
                return;
            };
            let result = state
                .borrow()
                .as_ref()
                .ok_or_else(|| "portrait is not loaded".to_owned())
                .and_then(UiImage::copy_to_clipboard);
            window.set_status_text(match result {
                Ok(()) => "Portrait copied to clipboard.".into(),
                Err(error) => format!("Copy failed: {error}").into(),
            });
        });
    }

    {
        let weak = window.as_weak();
        let state = Rc::clone(&signature);
        window.on_copy_signature(move || {
            let Some(window) = weak.upgrade() else {
                return;
            };
            let result = state
                .borrow()
                .as_ref()
                .ok_or_else(|| "signature is not loaded".to_owned())
                .and_then(UiImage::copy_to_clipboard);
            window.set_status_text(match result {
                Ok(()) => "Signature copied to clipboard.".into(),
                Err(error) => format!("Copy failed: {error}").into(),
            });
        });
    }

    {
        let weak = window.as_weak();
        let selected_reader_state = Rc::clone(&selected_reader);
        window.on_activate_card(move || {
            let Some(window) = weak.upgrade() else {
                return;
            };
            let activation = secret(window.get_activation_code());
            let pin1 = secret(window.get_activation_pin1());
            let pin2 = secret(window.get_activation_pin2());
            let pin1_confirmation = secret(window.get_activation_pin1_confirm());
            let pin2_confirmation = secret(window.get_activation_pin2_confirm());
            window.set_activation_code("".into());
            window.set_activation_pin1("".into());
            window.set_activation_pin2("".into());
            window.set_activation_pin1_confirm("".into());
            window.set_activation_pin2_confirm("".into());
            window.set_busy(true);
            let reader = selected_reader_state.borrow().clone();
            let result: Result<_, refineid_client::card_pin::CardPinError> = (|| {
                let activation =
                    activation.map_err(refineid_client::card_pin::CardPinError::Transport)?;
                let pin1 = pin1.map_err(refineid_client::card_pin::CardPinError::Transport)?;
                let pin2 = pin2.map_err(refineid_client::card_pin::CardPinError::Transport)?;
                let pin1_confirmation = pin1_confirmation
                    .map_err(refineid_client::card_pin::CardPinError::Transport)?;
                let pin2_confirmation = pin2_confirmation
                    .map_err(refineid_client::card_pin::CardPinError::Transport)?;
                let reader_filter = reader.as_deref().map(ReaderFilter::new);
                let context =
                    refineid_client::card_manager::prepare_activation(reader_filter.as_ref())?;
                let expected = context.expected_activation_pin_length().ok_or_else(|| {
                    refineid_client::card_pin::CardPinError::Transport(
                        "card generation did not determine activation-code length".to_owned(),
                    )
                })?;
                validate_gui_numeric(&activation, "activation code", Some(expected))
                    .and_then(|()| validate_gui_pin(&pin1, "new authentication PIN", 4))
                    .and_then(|()| validate_gui_pin(&pin2, "new signing PIN", 6))
                    .and_then(|()| {
                        validate_pin_confirmation(&pin1, &pin1_confirmation, "authentication PIN")
                    })
                    .and_then(|()| {
                        validate_pin_confirmation(&pin2, &pin2_confirmation, "signing PIN")
                    })
                    .map_err(refineid_client::card_pin::CardPinError::Transport)?;
                let activation_pin = activation_code(activation, expected)
                    .map_err(refineid_client::card_pin::CardPinError::Transport)?;
                refineid_client::card_manager::activate(
                    context,
                    ActivateOptions {
                        activation_pin,
                        new_pin1: pin1,
                        new_pin2: pin2,
                        allow_reactivate: false,
                    },
                )
            })();
            let message = match result {
                Ok(report)
                    if matches!(
                        report.pin1_outcome,
                        Some(refineid_lib_core::auth::UnblockOutcome::Ok)
                    ) && matches!(
                        report.pin2_outcome,
                        Some(refineid_lib_core::auth::UnblockOutcome::Ok)
                    ) =>
                {
                    "Card activated successfully. PIN1 and PIN2 are ready to use.".to_owned()
                }
                Ok(report) => format!(
                    "Card activation did not succeed. PIN1: {:?}; PIN2: {:?}.",
                    report.pin1_outcome, report.pin2_outcome
                ),
                Err(error) => format!("Activation failed: {error}"),
            };
            window.set_activation_result(message.clone().into());
            window.set_status_text(message.into());
            window.set_busy(false);
        });
    }

    for slot in [PinManageSlot::Pin1, PinManageSlot::Pin2] {
        let weak = window.as_weak();
        let selected_reader_state = Rc::clone(&selected_reader);
        let displayed_serial_state = Rc::clone(&displayed_serial);
        let handler = move || {
            let Some(window) = weak.upgrade() else {
                return;
            };
            match slot {
                PinManageSlot::Pin1 => window.set_pin1_change_result("".into()),
                PinManageSlot::Pin2 => window.set_pin2_change_result("".into()),
            }
            let (current, new, confirmation) = match slot {
                PinManageSlot::Pin1 => {
                    let values = (
                        secret(window.get_current_pin1()),
                        secret(window.get_new_pin1()),
                        secret(window.get_new_pin1_confirm()),
                    );
                    window.set_current_pin1("".into());
                    window.set_new_pin1("".into());
                    window.set_new_pin1_confirm("".into());
                    values
                }
                PinManageSlot::Pin2 => {
                    let values = (
                        secret(window.get_current_pin2()),
                        secret(window.get_new_pin2()),
                        secret(window.get_new_pin2_confirm()),
                    );
                    window.set_current_pin2("".into());
                    window.set_new_pin2("".into());
                    window.set_new_pin2_confirm("".into());
                    values
                }
            };
            window.set_busy(true);
            let result: Result<_, refineid_client::card_pin::CardPinError> = (|| {
                let current =
                    current.map_err(refineid_client::card_pin::CardPinError::Transport)?;
                let new = new.map_err(refineid_client::card_pin::CardPinError::Transport)?;
                let confirmation =
                    confirmation.map_err(refineid_client::card_pin::CardPinError::Transport)?;
                let expected_serial = displayed_serial_state.borrow().clone().ok_or_else(|| {
                    refineid_client::card_pin::CardPinError::CardSessionRevoked {
                        reason:
                            "displayed card has no full token serial; refresh before changing a PIN"
                                .to_owned(),
                    }
                })?;
                validate_pin_pair(&current, &new, slot)
                    .and_then(|()| validate_pin_confirmation(&new, &confirmation, slot.label()))
                    .map_err(refineid_client::card_pin::CardPinError::Transport)?;
                refineid_client::card_manager::change_pin(
                    &expected_serial,
                    ChangePinOptions {
                        slot,
                        current,
                        new,
                        reader_filter: selected_reader_state.borrow().clone(),
                    },
                )
            })();
            let message = match result {
                Ok(report)
                    if matches!(
                        report.outcome,
                        refineid_lib_core::auth::ChangePinOutcome::Ok
                    ) =>
                {
                    format!("{} changed successfully.", slot.label())
                }
                Ok(report) => format!(
                    "{} change was not completed: {:?}",
                    slot.label(),
                    report.outcome
                ),
                Err(error) => format!("{} change failed: {error}", slot.label()),
            };
            match slot {
                PinManageSlot::Pin1 => window.set_pin1_change_result(message.clone().into()),
                PinManageSlot::Pin2 => window.set_pin2_change_result(message.clone().into()),
            }
            window.set_status_text(message.into());
            window.set_busy(false);
        };
        match slot {
            PinManageSlot::Pin1 => window.on_change_pin1(handler),
            PinManageSlot::Pin2 => window.on_change_pin2(handler),
        }
    }

    for slot in [PinManageSlot::Pin1, PinManageSlot::Pin2] {
        let weak = window.as_weak();
        let cards_state = Rc::clone(&cards);
        let selected_reader_state = Rc::clone(&selected_reader);
        let displayed_serial_state = Rc::clone(&displayed_serial);
        let portrait_state = Rc::clone(&portrait);
        let signature_state = Rc::clone(&signature);
        let image_cache_state = Rc::clone(&image_cache);
        let handler = move || {
            let Some(window) = weak.upgrade() else {
                return;
            };
            if window.get_busy() {
                return;
            }
            window.set_busy(true);
            let submission = take_recovery_submission(&window, slot);
            let result = (|| {
                let puk = submission.puk?;
                let new_pin = submission.new_pin?;
                let confirmation = submission.confirmation?;
                let expected_serial = displayed_serial_state.borrow().clone().ok_or_else(|| {
                    "Displayed card has no full token serial; refresh before reactivating."
                        .to_owned()
                })?;
                validate_gui_puk(&puk)
                    .and_then(|()| {
                        validate_gui_pin(
                            &new_pin,
                            "new PIN",
                            match slot {
                                PinManageSlot::Pin1 => 4,
                                PinManageSlot::Pin2 => 6,
                            },
                        )
                    })
                    .and_then(|()| validate_pin_confirmation(&new_pin, &confirmation, "new PIN"))
                    .and_then(|()| Puk::new(puk).map_err(|error| error.to_string()))
                    .and_then(|puk| {
                        refineid_client::card_manager::unblock_pin(
                            &expected_serial,
                            UnblockPinOptions {
                                slot,
                                puk,
                                new_pin,
                                reader_filter: selected_reader_state.borrow().clone(),
                            },
                        )
                        .map_err(|error| error.to_string())
                    })
            })();
            let message = match &result {
                Ok(report) => unblock_result_message(slot, report.outcome),
                Err(error) => format!("{} reactivation failed: {error}", slot.label()),
            };
            let succeeded = matches!(
                &result,
                Ok(report) if matches!(report.outcome, refineid_lib_core::auth::UnblockOutcome::Ok)
            );
            if succeeded {
                refresh_cards(
                    &window,
                    &cards_state,
                    &selected_reader_state,
                    &displayed_serial_state,
                    &portrait_state,
                    &signature_state,
                    &image_cache_state,
                );
            } else {
                window.set_reactivation_result(message.clone().into());
            }
            window.set_status_text(message.into());
            window.set_busy(false);
        };
        match slot {
            PinManageSlot::Pin1 => window.on_unblock_pin1(handler),
            PinManageSlot::Pin2 => window.on_unblock_pin2(handler),
        }
    }

    {
        let weak = window.as_weak();
        window.on_security_operation_selected(move |_| {
            if let Some(window) = weak.upgrade() {
                disarm_management_forms(&window);
            }
        });
    }
    {
        let weak = window.as_weak();
        window.on_sign_operation_selected(move |_| {
            if let Some(window) = weak.upgrade() {
                disarm_pdf_signing(&window);
            }
        });
    }
    {
        let weak = window.as_weak();
        window.on_view_selected(move |_| {
            if let Some(window) = weak.upgrade() {
                disarm_management_forms(&window);
                disarm_pdf_signing(&window);
            }
        });
    }

    request_card_inspection(&window, &inspection_sender, &inspection_in_flight);
    window.run()
}

#[cfg(test)]
mod tests {
    use super::{
        CARD_PRESENCE_WAIT, PathBuf, chosen_document_names, chosen_documents_summary,
        condense_reader_name, legacy_activation_required, normalized_puk_input, optional_can,
        pin_change_available, puk_status, recovery_availability, refine_recovery_submission,
        secret, signed_document_file_name, timestamp_authority_url, timestamp_credentials,
        validate_gui_pin, validate_gui_pin_format, validate_gui_puk, validate_replacement_pin,
    };
    use refineid_lib_core::apdu::status_word::PinRetries;
    use refineid_lib_core::auth::{PinStatus, PukStatus};

    #[test]
    fn reader_name_drops_the_repeated_bracket_and_zero_indices() {
        assert_eq!(
            condense_reader_name(
                "HID Global OMNIKEY 3x21 Smart Card Reader [OMNIKEY 3x21 Smart Card Reader] 00 00"
            ),
            "HID Global OMNIKEY 3x21 Smart Card Reader"
        );
    }

    #[test]
    fn reader_name_keeps_an_informative_bracket_and_distinguishing_indices() {
        assert_eq!(
            condense_reader_name("Broadcom Corp 58200 [Contacted SmartCard] 01 00"),
            "Broadcom Corp 58200 [Contacted SmartCard] 01 00"
        );
    }

    #[test]
    fn presence_wait_parks_long_enough_to_be_event_driven() {
        // The monitor is woken by SCardGetStatusChange events, not by
        // this bound expiring; a short bound would degenerate back
        // into polling.
        assert!(CARD_PRESENCE_WAIT.as_secs() >= 30);
    }

    #[test]
    fn signed_pdf_keeps_the_source_name_without_overwriting_it() {
        let input = std::path::Path::new("/documents/Agreement.pdf");
        let instant =
            refineid_lib_core::x509::DateTime::new(2026, 8, 5, 14, 30, 12).expect("valid instant");
        assert_eq!(
            signed_document_file_name(input, &instant, "pdf"),
            "Agreement - signed at 2026-08-05T14-30-12Z.pdf"
        );
    }

    #[test]
    fn signed_container_is_named_asice_whatever_the_source_was() {
        let input = std::path::Path::new("/documents/Agreement.odt");
        let instant =
            refineid_lib_core::x509::DateTime::new(2026, 8, 5, 14, 30, 12).expect("valid instant");
        assert_eq!(
            signed_document_file_name(input, &instant, "asice"),
            "Agreement - signed at 2026-08-05T14-30-12Z.asice"
        );
    }

    /// Every document is listed by name, and the path it came from is
    /// not: the window is not where a holder's directory layout is
    /// published, and the name is what the container carries it under.
    #[test]
    fn documents_are_listed_by_name_alone() {
        let documents = [
            PathBuf::from("/home/someone/private/Agreement.odt"),
            PathBuf::from("/photos/Site.jpg"),
        ];
        assert_eq!(
            chosen_document_names(&documents),
            ["Agreement.odt", "Site.jpg"]
        );
        assert!(chosen_document_names(&[]).is_empty());
    }

    /// A single row says everything about itself; a set says what it
    /// becomes, so a container covering several is not read as
    /// covering the one whose name happens to be first.
    #[test]
    fn only_a_set_says_what_it_becomes() {
        let one = [PathBuf::from("/documents/Agreement.odt")];
        assert_eq!(chosen_documents_summary(&one), "");
        let several = [
            PathBuf::from("/documents/Agreement.odt"),
            PathBuf::from("/documents/Annex.xlsx"),
            PathBuf::from("/photos/Site.jpg"),
        ];
        assert_eq!(
            chosen_documents_summary(&several),
            "3 documents in one container"
        );
        assert_eq!(chosen_documents_summary(&[]), "");
    }

    #[test]
    fn only_a_pdf_extension_offers_the_pades_shape() {
        assert!(super::is_pdf(std::path::Path::new("/a/b.PDF")));
        assert!(!super::is_pdf(std::path::Path::new("/a/b.odt")));
        assert!(!super::is_pdf(std::path::Path::new("/a/b")));
    }

    #[test]
    fn signing_can_is_optional_but_strict_when_present() {
        assert!(optional_can("").expect("empty CAN is optional").is_none());
        assert_eq!(
            optional_can("123456")
                .expect("six-digit CAN")
                .expect("present CAN")
                .as_str(),
            "123456"
        );
        assert!(optional_can("123").is_err());
    }

    #[test]
    fn timestamp_authority_keeps_scheme_separate_from_host_and_path() {
        assert_eq!(
            timestamp_authority_url(0, "timestamp.sectigo.com/qualified")
                .expect("default Sectigo authority"),
            "https://timestamp.sectigo.com/qualified"
        );
        assert_eq!(
            timestamp_authority_url(1, "tsa.example.test/path").expect("HTTP authority"),
            "http://tsa.example.test/path"
        );
        assert!(timestamp_authority_url(0, "https://tsa.example.test").is_err());
    }

    #[test]
    fn timestamp_credentials_require_both_gui_fields() {
        assert!(
            timestamp_credentials("", "")
                .expect("blank credentials are optional")
                .is_none()
        );
        assert!(timestamp_credentials("user", "").is_err());
        assert!(timestamp_credentials("", "password").is_err());
        assert!(
            timestamp_credentials("user", "password")
                .expect("complete credentials")
                .is_some()
        );
    }

    #[test]
    fn recovery_displays_the_live_puk_retry_counter() {
        let retries = PinRetries::from_nibble(4).expect("four fits the retry-counter nibble");
        assert_eq!(
            puk_status(Some(&PukStatus::Remaining(retries))),
            "4 attempts remaining"
        );
        assert_eq!(puk_status(Some(&PukStatus::Locked)), "Locked");
        assert_eq!(puk_status(None), "Unavailable");
    }

    #[test]
    fn card_manager_reserves_two_pin_attempts_for_expert_recovery() {
        let retries = |count| {
            PinRetries::from_nibble(count).expect("test retry count fits the status-word nibble")
        };

        assert!(pin_change_available(Some(&PinStatus::Remaining(retries(
            3
        )))));
        assert!(!pin_change_available(Some(&PinStatus::Remaining(retries(
            2
        )))));
        assert!(!pin_change_available(Some(&PinStatus::NoInfo)));
    }

    #[test]
    fn personalized_locked_legacy_pin1_uses_pin1_only_recovery() {
        assert!(!legacy_activation_required(Some(&PinStatus::Locked), false));
    }

    #[test]
    fn zero_attempt_pin_slots_remain_available_for_puk_recovery() {
        let zero = PinRetries::from_nibble(0).expect("zero fits the retry-counter nibble");
        let status = PinStatus::Remaining(zero);
        let availability = recovery_availability(false, Some(&status), Some(&status));
        assert!(availability.pin1);
        assert!(availability.pin2);
    }

    #[test]
    fn factory_locked_legacy_pin1_requires_full_activation() {
        assert!(legacy_activation_required(Some(&PinStatus::Locked), true));
    }

    #[test]
    fn uncertain_legacy_pin_state_never_forces_both_pin_replacements() {
        assert!(!legacy_activation_required(Some(&PinStatus::Locked), false));
    }

    #[test]
    fn recovery_exposes_only_the_locked_pin() {
        let pin1 = recovery_availability(false, Some(&PinStatus::Locked), Some(&PinStatus::NoInfo));
        assert!(pin1.pin1);
        assert!(!pin1.pin2);

        let pin2 = recovery_availability(false, Some(&PinStatus::NoInfo), Some(&PinStatus::Locked));
        assert!(!pin2.pin1);
        assert!(pin2.pin2);
    }

    #[test]
    fn factory_activation_hides_individual_recovery() {
        let recovery =
            recovery_availability(true, Some(&PinStatus::Locked), Some(&PinStatus::Locked));
        assert!(!recovery.pin1);
        assert!(!recovery.pin2);
    }

    #[test]
    fn keeps_an_eight_digit_puk() {
        assert_eq!(normalized_puk_input("12345678"), "12345678");
    }

    #[test]
    fn preserves_an_invalid_puk_for_local_rejection() {
        let value = normalized_puk_input("12x3456789");
        assert_eq!(value, "123456789");
        let puk = secret(value.into()).expect("test PUK has valid PIN-family syntax");
        assert!(validate_gui_puk(&puk).is_err());
    }

    #[test]
    fn accepts_only_seven_or_eight_digit_puks() {
        for puk in ["4907123", "49071234", "00000000", "11111111"] {
            let value = secret(puk.into()).expect("test PUK has valid PIN-family syntax");
            validate_gui_puk(&value).expect("seven or eight digit PUK should be accepted");
        }
        for puk in ["490712", "490712345"] {
            let value = secret(puk.into()).expect("test PUK has valid PIN-family syntax");
            assert!(
                validate_gui_puk(&value).is_err(),
                "invalid PUK {puk} was accepted"
            );
        }
    }

    #[test]
    fn reports_replacement_pin_length_mismatch() {
        let (error, valid) = validate_replacement_pin("4907", "49071", 4);
        assert_eq!(error, "new PIN entries do not match");
        assert!(!valid);
    }

    #[test]
    fn reports_replacement_pin_below_role_minimum() {
        let (error, valid) = validate_replacement_pin("4907", "4907", 6);
        assert_eq!(error, "new PIN must contain 6 to 12 digits");
        assert!(!valid);
    }

    #[test]
    fn rejects_weak_new_pins_before_card_access() {
        for pin in [
            "0000",
            "1111",
            "2222",
            "3333",
            "999999",
            "11111111111",
            "1234",
            "1234567890",
            "4321",
            "1212",
            "1122",
        ] {
            let value = secret(pin.into()).expect("test PIN has valid syntax");
            let result = validate_gui_pin(&value, "new PIN", 4);
            assert!(result.is_err(), "weak PIN {pin} was accepted");
        }
    }

    #[test]
    fn accepts_nontrivial_new_pins() {
        let value = secret("4907".into()).expect("test PIN has valid syntax");
        validate_gui_pin(&value, "new PIN", 4).expect("nontrivial PIN should be accepted");
    }

    #[test]
    fn queued_empty_recovery_submission_is_locally_rejected() {
        let first = refine_recovery_submission("49071234".into(), "4907".into(), "4907".into());
        assert_eq!(
            first.puk.expect("first PUK is present").as_bytes(),
            b"49071234"
        );
        assert_eq!(
            first.new_pin.expect("first PIN is present").as_bytes(),
            b"4907"
        );
        assert_eq!(
            first
                .confirmation
                .expect("first confirmation is present")
                .as_bytes(),
            b"4907"
        );

        let queued = refine_recovery_submission("".into(), "".into(), "".into());
        assert!(queued.puk.is_err());
        assert!(queued.new_pin.is_err());
        assert!(queued.confirmation.is_err());
    }

    #[test]
    fn permits_replacing_an_existing_weak_pin() {
        let value = secret("1234".into()).expect("test PIN has valid syntax");
        validate_gui_pin_format(&value, "current PIN", 4)
            .expect("current PIN policy must not prevent replacing a weak PIN");
    }
}
