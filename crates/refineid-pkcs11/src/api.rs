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

//! The PKCS#11 v2.40 C entry points and the static
//! [`FUNCTION_LIST`] vtable.
//!
//! Every one of the 68 v2.40 functions has a slot in
//! [`FUNCTION_LIST`]; the implemented subset (initialise, slot /
//! token enumeration, session and login lifecycle, object find /
//! attribute read, and single-part sign) does real work, and the
//! remainder return [`CKR_FUNCTION_NOT_SUPPORTED`]. Only
//! [`c_get_function_list`] is re-exported under the C name
//! `C_GetFunctionList` (see `crate::lib`); callers reach every other
//! function through this vtable.
//!
//! Pointer discipline: each `unsafe extern "C"` entry validates its
//! caller-supplied pointers, then delegates the real logic to small
//! safe helpers so the FFI surface stays thin and auditable.

use core::ptr;

use refineid_lib_core::auth::PinStatus;
#[cfg(feature = "pin-change")]
use refineid_lib_core::backend::ReaderId;
use refineid_lib_core::pin::{PinBytes, PinRoleError};
use refineid_lib_core::pin_retry_risk::PinRetryRisk;

// Only the login-only (default) build reports the token
// write-protected; the pin-change build drops the flag.
#[cfg(not(feature = "pin-change"))]
use crate::ck::CKF_WRITE_PROTECTED;
use crate::ck::{
    CK_EFFECTIVELY_INFINITE, CK_UNAVAILABLE_INFORMATION, CKF_DONT_BLOCK, CKF_EC_F_P,
    CKF_EC_NAMEDCURVE, CKF_EC_UNCOMPRESS, CKF_HW_SLOT, CKF_LOGIN_REQUIRED, CKF_REMOVABLE_DEVICE,
    CKF_SERIAL_SESSION, CKF_SIGN, CKF_TOKEN_INITIALIZED, CKF_TOKEN_PRESENT, CKF_USER_PIN_COUNT_LOW,
    CKF_USER_PIN_FINAL_TRY, CKF_USER_PIN_INITIALIZED, CKF_USER_PIN_LOCKED, CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID, CKR_BUFFER_TOO_SMALL,
    CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR,
    CKR_FUNCTION_NOT_PARALLEL, CKR_FUNCTION_NOT_SUPPORTED, CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_KEY_HANDLE_INVALID, CKR_KEY_INDIGESTIBLE,
    CKR_MECHANISM_INVALID, CKR_NO_EVENT, CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_OPERATION_ACTIVE,
    CKR_OPERATION_NOT_INITIALIZED, CKR_PIN_INVALID, CKR_PIN_LEN_RANGE,
    CKR_RANDOM_SEED_NOT_SUPPORTED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID,
    CKR_SESSION_PARALLEL_NOT_SUPPORTED, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT,
    CKR_TOKEN_WRITE_PROTECTED, CKR_USER_ALREADY_LOGGED_IN, CKR_USER_NOT_LOGGED_IN,
    CKR_USER_TYPE_INVALID, CKU_USER, CkAttributePtr, CkBbool, CkBytePtr, CkCInitializeArgs,
    CkFlags, CkFunctionList, CkFunctionListPtrPtr, CkInfo, CkInfoPtr, CkMechanismInfo,
    CkMechanismInfoPtr, CkMechanismPtr, CkMechanismType, CkMechanismTypePtr, CkNotify,
    CkObjectHandle, CkObjectHandlePtr, CkRv, CkSessionHandle, CkSessionHandlePtr, CkSessionInfo,
    CkSessionInfoPtr, CkSlotId, CkSlotIdPtr, CkSlotInfo, CkSlotInfoPtr, CkTokenInfo,
    CkTokenInfoPtr, CkUlong, CkUlongPtr, CkUserType, CkUtf8Char, CkUtf8CharPtr, CkVersion,
    CkVoidPtr,
};
use crate::diag::diag;
use crate::sign::Mechanism;
use crate::state::{
    MODULE, ModuleState, PIN1_MAX_DIGITS, PIN1_MIN_DIGITS, Session, SlotRecord, session_state,
};
use crate::token::{AttrValue, ObjectKind, TokenObjects};

/// Cryptoki interface version this module implements (`2.40`, OASIS
/// PKCS#11 v2.40). Reported in [`CkInfo::cryptoki_version`] and the
/// vtable version.
const CRYPTOKI_VERSION: CkVersion = CkVersion {
    major: 2,
    minor: 40,
};
/// This module's own version: the `CalVer` `year.month` from the
/// Cargo compatibility version (`YY.M.D`), derived at
/// compile time by [`version_component`] so it cannot drift.
/// Reported in [`CkInfo::library_version`].
const LIBRARY_VERSION: CkVersion = CkVersion {
    major: version_component(env!("CARGO_PKG_VERSION_MAJOR")),
    minor: version_component(env!("CARGO_PKG_VERSION_MINOR")),
};
/// Token hardware version: the `CalVer` `year.month` release stream.
/// The FINEID card exposes no hardware version through PKCS#15, so
/// this reports the middleware release instead.
const TOKEN_HARDWARE_VERSION: CkVersion = LIBRARY_VERSION;
include!(concat!(env!("OUT_DIR"), "/token-version.rs"));

/// Parse one decimal component of `CARGO_PKG_VERSION` into the `u8`
/// a [`CkVersion`] field carries.
///
/// Const-evaluated at build time: an empty string, a non-digit
/// byte, or a value above 255 aborts compilation, so the reported
/// module / token versions can never drift from the workspace
/// `version` in `Cargo.toml`.
#[expect(
    clippy::panic,
    reason = "runs only during const evaluation of version constants; a malformed Cargo version stamp must abort the build, and panic is the const-eval abort mechanism"
)]
const fn version_component(text: &str) -> u8 {
    let mut bytes = text.as_bytes();
    assert!(!bytes.is_empty(), "empty Cargo version component");
    let mut value: u8 = 0;
    while let [digit, rest @ ..] = bytes {
        assert!(digit.is_ascii_digit(), "non-digit Cargo version byte");
        value = match (value.checked_mul(10), digit.checked_sub(b'0')) {
            (Some(scaled), Some(units)) => match scaled.checked_add(units) {
                Some(total) => total,
                None => panic!("Cargo version component exceeds 255"),
            },
            (None, Some(_) | None) | (Some(_), None) => {
                panic!("Cargo version component exceeds 255")
            }
        };
        bytes = rest;
    }
    value
}

/// RSA-3072 modulus size in bits, reported as the min/max key size
/// for [`crate::ck::CKM_RSA_PKCS`] (FINEID S4-1 v3.1 auth key).
const RSA_KEY_BITS: CkUlong = 3072;
/// secp384r1 field size in bits, reported as the min/max key size for
/// [`crate::ck::CKM_ECDSA`] (FINEID v4.0 auth key).
const EC_KEY_BITS: CkUlong = 384;

/// Convert a `usize` length to [`CkUlong`], saturating at the maximum
/// (never truncates silently; the [`CK_UNAVAILABLE_INFORMATION`]
/// sentinel is `CkUlong::MAX`).
fn ulong_from_usize(value: usize) -> CkUlong {
    CkUlong::try_from(value).unwrap_or(CkUlong::MAX)
}

/// Convert a [`CkUlong`] to `usize`, saturating at the maximum.
fn usize_from_ulong(value: CkUlong) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// Space-pad `text` into a fixed-width PKCS#11 field. Fields are
/// blank-padded (0x20), never NUL-terminated; over-long text is
/// truncated to `N` bytes.
fn padded_field<const N: usize>(text: &str) -> [CkUtf8Char; N] {
    let mut out = [b' '; N];
    for (slot, byte) in out.iter_mut().zip(text.bytes()) {
        *slot = byte;
    }
    out
}

/// Space-pad `text` into a fixed-width PKCS#11 field, keeping the
/// TAIL when over-long. Used for the token serial: the normal case
/// is the 9-char plastic-printed identifier (fits), but the
/// fallback full chip serial (17-20 chars on unrecognised shapes)
/// exceeds the 16-byte `CK_TOKEN_INFO.serialNumber` field, and the
/// printed identifier is the SUFFIX, so dropping leading bytes
/// preserves the identity a citizen can check against the card
/// body; `OpenSC` truncates the same way.
fn tail_padded_field<const N: usize>(text: &str) -> [CkUtf8Char; N] {
    let mut out = [b' '; N];
    let skip = text.len().saturating_sub(N);
    for (slot, byte) in out.iter_mut().zip(text.bytes().skip(skip)) {
        *slot = byte;
    }
    out
}

/// Copy `src` into a caller output buffer following the PKCS#11
/// two-call length-negotiation rule (v2.40 s5.2): a NULL `dst`
/// reports the required length; a too-small `dst` reports the
/// required length and returns [`CKR_BUFFER_TOO_SMALL`]; otherwise
/// the bytes are copied and the exact length written.
///
/// # Safety
/// `dst_len` must be a valid, writable [`CkUlongPtr`]; when `dst` is
/// non-NULL it must point to at least `*dst_len` writable bytes.
unsafe fn deliver_bytes(dst: CkBytePtr, dst_len: CkUlongPtr, src: &[u8]) -> CkRv {
    if dst.is_null() {
        // SAFETY: caller guarantees dst_len is writable.
        unsafe {
            dst_len.write(ulong_from_usize(src.len()));
        }
        return CKR_OK;
    }
    // SAFETY: caller guarantees dst_len is readable.
    let capacity = usize_from_ulong(unsafe { dst_len.read() });
    if capacity < src.len() {
        // SAFETY: caller guarantees dst_len is writable.
        unsafe {
            dst_len.write(ulong_from_usize(src.len()));
        }
        return CKR_BUFFER_TOO_SMALL;
    }
    // SAFETY: dst has at least src.len() writable bytes per the
    // capacity check, and src is a valid slice.
    unsafe {
        ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
    }
    // SAFETY: caller guarantees dst_len is writable.
    unsafe {
        dst_len.write(ulong_from_usize(src.len()));
    }
    CKR_OK
}

/// Acquire the module lock. Maps a poisoned mutex to
/// [`CKR_GENERAL_ERROR`].
fn lock_module() -> Result<std::sync::MutexGuard<'static, Option<ModuleState>>, CkRv> {
    MODULE.lock().map_err(|_poisoned| CKR_GENERAL_ERROR)
}

/// `C_Initialize`: bring up module state (v2.40 s5.6.1).
///
/// Accepts a NULL argument or a [`CkCInitializeArgs`] with or without
/// [`CKF_OS_LOCKING_OK`] (the module uses a Rust `Mutex`, so either
/// is fine); rejects a non-NULL `pReserved`.
unsafe extern "C" fn c_initialize(init_args: CkVoidPtr) -> CkRv {
    if !init_args.is_null() {
        let args_ptr = init_args.cast::<CkCInitializeArgs>();
        // SAFETY: a non-NULL pInitArgs must point to a valid
        // CK_C_INITIALIZE_ARGS per the caller contract.
        let args = unsafe { args_ptr.read() };
        if !args.p_reserved.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // Both locking modes are accepted: this module serializes all
        // state through a Rust Mutex, so it is safe whether or not the
        // caller sets CKF_OS_LOCKING_OK and whether or not it supplies
        // its own locking callbacks.
    }
    diag!("C_Initialize");
    let mut guard = match lock_module() {
        Ok(guard) => guard,
        Err(err) => return err,
    };
    if guard.is_some() {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    match ModuleState::new() {
        Ok(state) => {
            *guard = Some(state);
            CKR_OK
        }
        Err(err) => err,
    }
}

/// `C_Finalize`: tear down module state, dropping sessions and
/// zeroizing any cached PIN1 (v2.40 s5.6.2).
unsafe extern "C" fn c_finalize(reserved: CkVoidPtr) -> CkRv {
    diag!("C_Finalize");
    if !reserved.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut guard = match lock_module() {
        Ok(guard) => guard,
        Err(err) => return err,
    };
    if guard.is_none() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if let Some(module) = guard.as_ref() {
        module.clear_all_positive_pins();
    }
    *guard = None;
    CKR_OK
}

/// `C_GetInfo`: report cryptoki + library versions and identity
/// (v2.40 s5.6.3).
unsafe extern "C" fn c_get_info(info: CkInfoPtr) -> CkRv {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let value = CkInfo {
        cryptoki_version: CRYPTOKI_VERSION,
        manufacturer_id: padded_field("ReFineID"),
        flags: 0,
        library_description: padded_field("ReFineID FINEID PKCS11"),
        library_version: LIBRARY_VERSION,
    };
    // SAFETY: caller guarantees info is a writable CK_INFO pointer.
    unsafe {
        info.write(value);
    }
    CKR_OK
}

/// `C_GetFunctionList`: hand back a pointer to the static vtable
/// (v2.40 s5.6.4). The one function callers resolve by symbol.
pub unsafe extern "C" fn c_get_function_list(list: CkFunctionListPtrPtr) -> CkRv {
    if list.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    // SAFETY: caller guarantees `list` is a writable location for one
    // CK_FUNCTION_LIST_PTR; the static outlives every caller.
    unsafe {
        list.write(ptr::addr_of!(FUNCTION_LIST).cast_mut());
    }
    CKR_OK
}

/// `C_GetSlotList`: enumerate slots, optionally only those with a
/// token present (v2.40 s5.5.5). Refreshes the reader table first.
unsafe extern "C" fn c_get_slot_list(
    token_present: CkBbool,
    slot_list: CkSlotIdPtr,
    count: CkUlongPtr,
) -> CkRv {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut guard = match lock_module() {
        Ok(guard) => guard,
        Err(err) => return err,
    };
    let Some(module) = guard.as_mut() else {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    };
    if let Err(err) = module.refresh_slots() {
        return err;
    }
    let only_present = token_present != 0;
    let ids: Vec<CkSlotId> = module
        .slot_ids()
        .into_iter()
        .filter(|id| !only_present || module.slot(*id).is_some_and(SlotRecord::card_present))
        .collect();
    drop(guard);
    diag!(
        "C_GetSlotList token_present={only_present} slots={}",
        ids.len()
    );
    // SAFETY: caller guarantees `count` is a readable/writable
    // CK_ULONG; when slot_list is non-NULL it holds `*count` entries.
    unsafe { write_handle_list(slot_list, count, &ids) }
}

/// Write a slice of [`CkSlotId`] into a caller array with the
/// two-call length rule.
///
/// # Safety
/// `count` must be a valid readable/writable [`CkUlongPtr`]; when
/// `list` is non-NULL it must point to at least `*count` writable
/// [`CkSlotId`] slots.
unsafe fn write_handle_list(list: CkSlotIdPtr, count: CkUlongPtr, ids: &[CkSlotId]) -> CkRv {
    if list.is_null() {
        // SAFETY: caller guarantees count is writable.
        unsafe {
            count.write(ulong_from_usize(ids.len()));
        }
        return CKR_OK;
    }
    // SAFETY: caller guarantees count is readable.
    let capacity = usize_from_ulong(unsafe { count.read() });
    if capacity < ids.len() {
        // SAFETY: caller guarantees count is writable.
        unsafe {
            count.write(ulong_from_usize(ids.len()));
        }
        return CKR_BUFFER_TOO_SMALL;
    }
    for (index, id) in ids.iter().enumerate() {
        // SAFETY: index < ids.len() <= capacity, so list.add(index)
        // is in bounds and writable.
        let slot = unsafe { list.add(index) };
        // SAFETY: slot is a valid, writable CK_SLOT_ID cell per the
        // bounds check above.
        unsafe {
            slot.write(*id);
        }
    }
    // SAFETY: caller guarantees count is writable.
    unsafe {
        count.write(ulong_from_usize(ids.len()));
    }
    CKR_OK
}

/// `C_GetSlotInfo`: describe a slot / reader (v2.40 s5.5.6).
unsafe extern "C" fn c_get_slot_info(slot_id: CkSlotId, info: CkSlotInfoPtr) -> CkRv {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let guard = match lock_module() {
        Ok(guard) => guard,
        Err(err) => return err,
    };
    let Some(module) = guard.as_ref() else {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    };
    let Some(slot) = module.slot(slot_id) else {
        return CKR_SLOT_ID_INVALID;
    };
    let mut flags = CKF_HW_SLOT | CKF_REMOVABLE_DEVICE;
    if slot.card_present() {
        flags |= CKF_TOKEN_PRESENT;
    }
    // The slot describes the physical reader, not this module:
    // vendor and IFD version come from the reader driver's own
    // attributes (mirrors OpenSC's init_slot_info). PC/SC exposes
    // one VENDOR_IFD_VERSION value rather than a separate hardware /
    // firmware pair, so report it in both PKCS#11 fields instead of
    // throwing away the reader firmware value as 0.0.
    let identity = slot.reader_identity();
    let manufacturer = identity.vendor_name.clone().unwrap_or_default();
    let hardware_version = identity
        .ifd_version
        .map_or(CkVersion { major: 0, minor: 0 }, |ifd| CkVersion {
            major: ifd.major,
            minor: ifd.minor,
        });
    let firmware_version = hardware_version;
    let value = CkSlotInfo {
        slot_description: padded_field(slot.reader_name()),
        manufacturer_id: padded_field(&manufacturer),
        flags,
        hardware_version,
        firmware_version,
    };
    drop(guard);
    // SAFETY: caller guarantees info is a writable CK_SLOT_INFO.
    unsafe {
        info.write(value);
    }
    CKR_OK
}

/// `C_GetTokenInfo`: describe the token in a slot (v2.40 s5.5.7).
unsafe extern "C" fn c_get_token_info(slot_id: CkSlotId, info: CkTokenInfoPtr) -> CkRv {
    diag!("C_GetTokenInfo slot={slot_id}");
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut guard = match lock_module() {
        Ok(guard) => guard,
        Err(err) => return err,
    };
    let Some(module) = guard.as_mut() else {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    };
    let Some(slot) = module.slot(slot_id) else {
        return CKR_SLOT_ID_INVALID;
    };
    if !slot.card_present() {
        return CKR_TOKEN_NOT_PRESENT;
    }
    let reader_name = slot.reader_name().to_owned();
    // The serial comes from the cached card read (the card's own
    // EF.TokenInfo). Do not manufacture a FINEID token for a card
    // that cannot provide its FINEID authentication certificate.
    let serial = match module.ensure_token(slot_id) {
        Ok(objects) => objects.token_serial().to_owned(),
        Err(error) => return error,
    };
    drop(guard);
    let pin1_status = match crate::token::card_pin1_status(&reader_name) {
        Ok(status) => status,
        Err(error) => return error,
    };
    // SAFETY: caller guarantees info is a writable CK_TOKEN_INFO.
    unsafe {
        info.write(token_info_value(&serial, pin1_status));
    }
    CKR_OK
}

/// Fixed token label for the authentication (PIN1) token.
///
/// This is what NSS puts verbatim in its PIN-prompt dialog ("Enter
/// password for Basic (PIN 1)") and what keys the `pkcs11:token=`
/// URI.  The label must name the *purpose / credential*, not the
/// plastic: the card's own EF.TokenInfo carries "HENKILOKORTTI".
/// When the qualified-signature (PIN2) slot lands it will carry
/// "Signature (PIN 2)", and the label pair is what keeps a citizen
/// from typing PIN2 into a PIN1 prompt.  The serial still names the
/// physical card.
///
/// The string matches the Apple `TokenExtension` localisation key:
///   English  "Basic (PIN 1)"
///   Finnish  "Perus (PIN 1)"
///   Swedish  "Bas (PIN 1)"
const TOKEN_LABEL_IDENTIFY: &str = "Basic (PIN 1)";

/// Build the token-info payload. Fixed-width fields are space-padded;
/// unknown counters use [`CK_UNAVAILABLE_INFORMATION`].
///
/// The label is the fixed [`TOKEN_LABEL_IDENTIFY`] (see its doc);
/// `serial` comes from the card's own PKCS#15 EF.TokenInfo (the
/// printed card identifier). The model is the fixed card family,
/// FINEID (the openssl backend's default URI matches on it). The
/// manufacturer names this software, `ReFineID`: `C_GetInfo`
/// carries the module identity in principle, but `p11-kit-proxy`
/// masks it with its own, so the token manufacturer is the only
/// producer hint that reaches proxy consumers.
fn token_info_value(serial: &str, pin1_status: PinStatus) -> CkTokenInfo {
    // With `pin-change` enabled the token is not write-protected, so
    // NSS offers "Change Password" -> C_SetPIN. In the default
    // (login-only) build the token reports write-protected and NSS
    // greys the change dialog out; object mutation is refused
    // per-function (`C_CreateObject` and friends are stubs) either way.
    #[cfg(feature = "pin-change")]
    let flags = CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;
    #[cfg(not(feature = "pin-change"))]
    let flags =
        CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED | CKF_WRITE_PROTECTED;
    let flags = flags | user_pin_status_flags(pin1_status);
    CkTokenInfo {
        label: padded_field(TOKEN_LABEL_IDENTIFY),
        manufacturer_id: padded_field("ReFineID"),
        model: padded_field("FINEID"),
        serial_number: tail_padded_field(serial),
        flags,
        ul_max_session_count: CK_EFFECTIVELY_INFINITE,
        ul_session_count: CK_UNAVAILABLE_INFORMATION,
        ul_max_rw_session_count: CK_EFFECTIVELY_INFINITE,
        ul_rw_session_count: CK_UNAVAILABLE_INFORMATION,
        ul_max_pin_len: ulong_from_usize(PIN1_MAX_DIGITS),
        ul_min_pin_len: ulong_from_usize(PIN1_MIN_DIGITS),
        ul_total_public_memory: CK_UNAVAILABLE_INFORMATION,
        ul_free_public_memory: CK_UNAVAILABLE_INFORMATION,
        ul_total_private_memory: CK_UNAVAILABLE_INFORMATION,
        ul_free_private_memory: CK_UNAVAILABLE_INFORMATION,
        hardware_version: TOKEN_HARDWARE_VERSION,
        firmware_version: TOKEN_FIRMWARE_VERSION,
        utc_time: padded_field(""),
    }
}

/// Translate the side-effect-free live PIN1 status to PKCS #11 token flags.
const fn user_pin_status_flags(status: PinStatus) -> CkFlags {
    let PinStatus::Remaining(retries) = status else {
        return if matches!(status, PinStatus::Locked) {
            CKF_USER_PIN_LOCKED
        } else {
            0
        };
    };
    match PinRetryRisk::from_retries(retries) {
        Some(PinRetryRisk::NormalOperatingConditions) | None => 0,
        Some(PinRetryRisk::DisturbanceDetected) => CKF_USER_PIN_COUNT_LOW,
        Some(PinRetryRisk::SecurityIncidentDeclared) => {
            CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY
        }
        Some(
            PinRetryRisk::CriticalThreatLevel
            | PinRetryRisk::LockdownImminent
            | PinRetryRisk::DefencesFallen,
        ) => CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_LOCKED,
    }
}

/// `C_GetMechanismList`: the single sign mechanism this card profile
/// supports (v2.40 s5.5.8). Reads the card to learn RSA vs ECC.
unsafe extern "C" fn c_get_mechanism_list(
    slot_id: CkSlotId,
    mechanism_list: CkMechanismTypePtr,
    count: CkUlongPtr,
) -> CkRv {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mechanism = match card_mechanism(slot_id) {
        Ok(mechanism) => mechanism,
        Err(err) => return err,
    };
    let types = [mechanism.ck_type()];
    if mechanism_list.is_null() {
        // SAFETY: caller guarantees count is writable.
        unsafe {
            count.write(ulong_from_usize(types.len()));
        }
        return CKR_OK;
    }
    // SAFETY: caller guarantees count is readable.
    let capacity = usize_from_ulong(unsafe { count.read() });
    if capacity < types.len() {
        // SAFETY: caller guarantees count is writable.
        unsafe {
            count.write(ulong_from_usize(types.len()));
        }
        return CKR_BUFFER_TOO_SMALL;
    }
    for (index, mech) in types.iter().enumerate() {
        // SAFETY: index < types.len() <= capacity.
        let cell = unsafe { mechanism_list.add(index) };
        // SAFETY: cell is a valid, writable CK_MECHANISM_TYPE per the
        // bounds check above.
        unsafe {
            cell.write(*mech);
        }
    }
    // SAFETY: caller guarantees count is writable.
    unsafe {
        count.write(ulong_from_usize(types.len()));
    }
    CKR_OK
}

/// `C_GetMechanismInfo`: key-size bounds and capability flags for a
/// mechanism (v2.40 s5.5.9).
unsafe extern "C" fn c_get_mechanism_info(
    slot_id: CkSlotId,
    mechanism: CkMechanismType,
    info: CkMechanismInfoPtr,
) -> CkRv {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let card_mech = match card_mechanism(slot_id) {
        Ok(mechanism) => mechanism,
        Err(err) => return err,
    };
    if Mechanism::from_ck_type(mechanism) != Some(card_mech) {
        return CKR_MECHANISM_INVALID;
    }
    // The EC capability bits (v2.40 s11.7) name the curve family,
    // parameter form, and point form this module actually emits;
    // some consumers filter on CKF_EC_NAMEDCURVE before offering an
    // EC key at all.
    let (key_bits, flags) = match card_mech {
        Mechanism::RsaPkcs => (RSA_KEY_BITS, CKF_SIGN),
        Mechanism::Ecdsa => (
            EC_KEY_BITS,
            CKF_SIGN | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS,
        ),
    };
    let value = CkMechanismInfo {
        ul_min_key_size: key_bits,
        ul_max_key_size: key_bits,
        flags,
    };
    // SAFETY: caller guarantees info is a writable CK_MECHANISM_INFO.
    unsafe {
        info.write(value);
    }
    CKR_OK
}

/// Resolve the sign mechanism for a slot's card by reading its
/// certificate. Maps an absent card to [`CKR_TOKEN_NOT_PRESENT`].
fn card_mechanism(slot_id: CkSlotId) -> Result<Mechanism, CkRv> {
    let mut guard = lock_module()?;
    let module = guard.as_mut().ok_or(CKR_CRYPTOKI_NOT_INITIALIZED)?;
    let slot = module.slot(slot_id).ok_or(CKR_SLOT_ID_INVALID)?;
    if !slot.card_present() {
        return Err(CKR_TOKEN_NOT_PRESENT);
    }
    let mechanism = module.ensure_token(slot_id)?.mechanism();
    drop(guard);
    Ok(mechanism)
}

/// `C_OpenSession`: open a serial session on a slot (v2.40 s5.6.1).
unsafe extern "C" fn c_open_session(
    slot_id: CkSlotId,
    flags: CkFlags,
    _application: CkVoidPtr,
    _notify: CkNotify,
    session: CkSessionHandlePtr,
) -> CkRv {
    if session.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if flags & CKF_SERIAL_SESSION == 0 {
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }
    let mut guard = match lock_module() {
        Ok(guard) => guard,
        Err(err) => return err,
    };
    let Some(module) = guard.as_mut() else {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    };
    let Some(slot) = module.slot(slot_id) else {
        return CKR_SLOT_ID_INVALID;
    };
    if !slot.card_present() {
        return CKR_TOKEN_NOT_PRESENT;
    }
    let handle = module.open_session(slot_id, flags);
    drop(guard);
    diag!("C_OpenSession slot={slot_id} flags={flags:#06x} session={handle}");
    // SAFETY: caller guarantees session is a writable handle slot.
    unsafe {
        session.write(handle);
    }
    CKR_OK
}

/// `C_CloseSession`: close one session (v2.40 s5.6.2).
unsafe extern "C" fn c_close_session(session: CkSessionHandle) -> CkRv {
    diag!("C_CloseSession session={session}");
    let mut guard = match lock_module() {
        Ok(guard) => guard,
        Err(err) => return err,
    };
    let Some(module) = guard.as_mut() else {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    };
    let closed = module.close_session(session);
    drop(guard);
    if closed {
        CKR_OK
    } else {
        CKR_SESSION_HANDLE_INVALID
    }
}

/// `C_CloseAllSessions`: close every session on a slot (v2.40
/// s5.6.3).
unsafe extern "C" fn c_close_all_sessions(slot_id: CkSlotId) -> CkRv {
    let mut guard = match lock_module() {
        Ok(guard) => guard,
        Err(err) => return err,
    };
    let Some(module) = guard.as_mut() else {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    };
    if module.slot(slot_id).is_none() {
        return CKR_SLOT_ID_INVALID;
    }
    module.close_all_sessions(slot_id);
    drop(guard);
    CKR_OK
}

/// `C_GetSessionInfo`: report a session's slot, state, and flags
/// (v2.40 s5.6.4).
unsafe extern "C" fn c_get_session_info(session: CkSessionHandle, info: CkSessionInfoPtr) -> CkRv {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut guard = match lock_module() {
        Ok(guard) => guard,
        Err(err) => return err,
    };
    let Some(module) = guard.as_mut() else {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    };
    let Some(session_state_ref) = module.session(session) else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    let slot_id = session_state_ref.slot_id();
    let flags = session_state_ref.flags();
    let logged_in = module.is_logged_in(slot_id);
    let value = CkSessionInfo {
        slot_id,
        state: session_state(flags, logged_in),
        flags,
        ul_device_error: 0,
    };
    drop(guard);
    // SAFETY: caller guarantees info is a writable CK_SESSION_INFO.
    unsafe {
        info.write(value);
    }
    CKR_OK
}

/// `C_Login`: store PIN1 for the token (`CKU_USER` only) (v2.40
/// s5.6.5).
///
/// The PIN is validated as 4..=12 ASCII digits, verified once on the
/// live card, and cached only after definite success. It is never logged.
unsafe extern "C" fn c_login(
    session: CkSessionHandle,
    user_type: CkUserType,
    pin_ptr: CkUtf8CharPtr,
    pin_len: CkUlong,
) -> CkRv {
    if user_type != CKU_USER {
        return CKR_USER_TYPE_INVALID;
    }
    if pin_ptr.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let length = usize_from_ulong(pin_len);
    // The PIN length is loggable; the PIN bytes never are.
    diag!("C_Login session={session} user_type={user_type} pin_len={length}");
    // SAFETY: caller guarantees pin_ptr points to `pin_len` bytes;
    // the bytes are copied straight into a zeroizing PinBytes and
    // never logged (PIN secrecy rule).
    let caller_bytes = unsafe { core::slice::from_raw_parts(pin_ptr, length) }.to_vec();

    // When the `test-pin-env` feature is active and the environment
    // variable `REFINEID_TEST_PIN1` is set, override the caller-supplied
    // PIN with the env value.  This lets Firefox skip its GUI PIN dialog
    // in fully automated test runs (Marionette / CI headless).  The feature
    // is never compiled into production (non-test) builds.
    #[cfg(feature = "test-pin-env")]
    let caller_bytes = std::env::var("REFINEID_TEST_PIN1").map_or(caller_bytes, |env_pin| {
        diag!("C_Login: REFINEID_TEST_PIN1 env override (test-pin-env feature)");
        env_pin.into_bytes()
    });

    let pin1 = match PinBytes::new(caller_bytes) {
        Ok(pin) => pin,
        Err(error) => return classify_pin_error(error),
    };
    if let Err(_role_err) = pin1.validate_digits(PIN1_MIN_DIGITS, PIN1_MAX_DIGITS) {
        return CKR_PIN_LEN_RANGE;
    }
    let mut guard = match lock_module() {
        Ok(guard) => guard,
        Err(err) => return err,
    };
    let Some(module) = guard.as_mut() else {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    };
    let Some(session_ref) = module.session(session) else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    let slot_id = session_ref.slot_id();
    if module.is_logged_in(slot_id) {
        return CKR_USER_ALREADY_LOGGED_IN;
    }
    let Some(reader_name) = module.reader_name(slot_id) else {
        return CKR_DEVICE_ERROR;
    };
    let pin_cache = match module.pin_cache(slot_id) {
        Ok(cache) => cache,
        Err(error) => return error,
    };
    drop(guard);
    let rv = match crate::token::card_login(&reader_name, &pin_cache, pin1) {
        Ok(()) => CKR_OK,
        Err(error) => error,
    };
    diag!("C_Login rv={rv:#06x}");
    rv
}

/// Classify a rejected PIN1 without disclosing its bytes: a
/// length-policy failure is [`CKR_PIN_LEN_RANGE`]; a non-digit byte
/// is [`CKR_PIN_INVALID`], the v2.40 s11.7 code for invalid
/// characters in a PIN. The rejection is local -- the card was never
/// contacted -- so [`CKR_PIN_INCORRECT`] would falsely tell the
/// caller a retry attempt was consumed (a wrong-window paste of an
/// SSH passphrase must not read as a burned FINEID retry). Only the
/// byte length and digit-ness are inspected here.
const fn classify_pin_error(error: PinRoleError) -> CkRv {
    match error {
        PinRoleError::NonDigit { .. } => CKR_PIN_INVALID,
        PinRoleError::Empty | PinRoleError::WrongLength { .. } => CKR_PIN_LEN_RANGE,
    }
}

/// `C_Logout`: drop the token's cached PIN1 (v2.40 s5.6.6).
unsafe extern "C" fn c_logout(session: CkSessionHandle) -> CkRv {
    diag!("C_Logout session={session}");
    let mut guard = match lock_module() {
        Ok(guard) => guard,
        Err(err) => return err,
    };
    let Some(module) = guard.as_mut() else {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    };
    let Some(session_ref) = module.session(session) else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    let slot_id = session_ref.slot_id();
    if !module.is_logged_in(slot_id) {
        return CKR_USER_NOT_LOGGED_IN;
    }
    module.logout(slot_id);
    drop(guard);
    CKR_OK
}

/// Read one `C_FindObjects` / `C_GetAttributeValue` template into a
/// vector of `(type, value-bytes)` pairs.
///
/// # Safety
/// `template` must point to `count` valid [`CkAttribute`] entries;
/// each entry's `p_value` must point to `ul_value_len` readable bytes
/// or be NULL.
unsafe fn read_template(
    template: CkAttributePtr,
    count: CkUlong,
) -> Vec<(CkMechanismType, Vec<u8>)> {
    let entries = usize_from_ulong(count);
    let mut out = Vec::with_capacity(entries);
    for index in 0..entries {
        // SAFETY: index < count and the caller guarantees `count`
        // valid entries.
        let cell = unsafe { template.add(index) };
        // SAFETY: cell points at a valid CK_ATTRIBUTE per the caller
        // contract.
        let entry = unsafe { cell.read() };
        let length = usize_from_ulong(entry.ul_value_len);
        let value = if entry.p_value.is_null() || length == 0 {
            Vec::new()
        } else {
            // SAFETY: p_value points to `length` readable bytes per
            // the caller contract.
            unsafe { core::slice::from_raw_parts(entry.p_value.cast::<u8>(), length) }.to_vec()
        };
        out.push((entry.attr_type, value));
    }
    out
}

/// `C_FindObjectsInit`: begin a search, computing the matching object
/// handles up front (v2.40 s5.7.1).
unsafe extern "C" fn c_find_objects_init(
    session: CkSessionHandle,
    template: CkAttributePtr,
    count: CkUlong,
) -> CkRv {
    // A NULL template is only legal for the match-everything search
    // (count == 0); with a nonzero count it cannot describe `count`
    // readable entries, so reject it before `read_template` walks it.
    if template.is_null() && count != 0 {
        return CKR_ARGUMENTS_BAD;
    }
    // SAFETY: caller guarantees `template`/`count` describe a valid
    // attribute array; the NULL/nonzero-count combination was
    // rejected above.
    let parsed = unsafe { read_template(template, count) };
    // Attribute types and value lengths only -- template values (an
    // object class, a CKA_ID) stay out of the log.
    diag!(
        "C_FindObjectsInit session={session} template=[{}]",
        parsed
            .iter()
            .map(|(attr, value)| format!("{attr:#06x}:{}B", value.len()))
            .collect::<Vec<_>>()
            .join(",")
    );
    let mut guard = match lock_module() {
        Ok(guard) => guard,
        Err(err) => return err,
    };
    let Some(module) = guard.as_mut() else {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    };
    let Some(slot_id) = module.session(session).map(Session::slot_id) else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    let token = match module.ensure_token(slot_id) {
        Ok(token) => token,
        Err(err) => return err,
    };
    let matches = matching_handles(&token, &parsed);
    let Some(session_mut) = module.session_mut(session) else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    session_mut.begin_find(matches);
    drop(guard);
    CKR_OK
}

/// Compute the object handles whose attributes satisfy a find
/// template.
fn matching_handles(
    token: &TokenObjects,
    template: &[(CkMechanismType, Vec<u8>)],
) -> Vec<CkObjectHandle> {
    ObjectKind::ALL
        .into_iter()
        .filter(|kind| token.matches(*kind, template))
        .map(ObjectKind::handle)
        .collect()
}

/// `C_FindObjects`: return the next batch of matching handles (v2.40
/// s5.7.2).
unsafe extern "C" fn c_find_objects(
    session: CkSessionHandle,
    object: CkObjectHandlePtr,
    max_count: CkUlong,
    count: CkUlongPtr,
) -> CkRv {
    if object.is_null() || count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut guard = match lock_module() {
        Ok(guard) => guard,
        Err(err) => return err,
    };
    let Some(module) = guard.as_mut() else {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    };
    let Some(session_mut) = module.session_mut(session) else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    let Some(batch) = session_mut.next_find_batch(usize_from_ulong(max_count)) else {
        return CKR_OPERATION_NOT_INITIALIZED;
    };
    drop(guard);
    diag!("C_FindObjects session={session} returned={}", batch.len());
    for (index, handle) in batch.iter().enumerate() {
        // SAFETY: index < wanted <= max_count, so object.add(index)
        // is within the caller's array.
        let cell = unsafe { object.add(index) };
        // SAFETY: cell is a valid, writable CK_OBJECT_HANDLE per the
        // bounds check above.
        unsafe {
            cell.write(*handle);
        }
    }
    // SAFETY: caller guarantees count is writable.
    unsafe {
        count.write(ulong_from_usize(batch.len()));
    }
    CKR_OK
}

/// `C_FindObjectsFinal`: end a search (v2.40 s5.7.3).
unsafe extern "C" fn c_find_objects_final(session: CkSessionHandle) -> CkRv {
    let mut guard = match lock_module() {
        Ok(guard) => guard,
        Err(err) => return err,
    };
    let Some(module) = guard.as_mut() else {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    };
    let Some(session_mut) = module.session_mut(session) else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    let had_find = session_mut.take_find();
    drop(guard);
    if had_find {
        CKR_OK
    } else {
        CKR_OPERATION_NOT_INITIALIZED
    }
}

/// `C_GetAttributeValue`: read object attributes with the two-call
/// length rule (v2.40 s5.7.5).
unsafe extern "C" fn c_get_attribute_value(
    session: CkSessionHandle,
    object: CkObjectHandle,
    template: CkAttributePtr,
    count: CkUlong,
) -> CkRv {
    if template.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    diag!("C_GetAttributeValue session={session} object={object} count={count}");
    let Some(kind) = ObjectKind::from_handle(object) else {
        return CKR_OBJECT_HANDLE_INVALID;
    };
    let mut guard = match lock_module() {
        Ok(guard) => guard,
        Err(err) => return err,
    };
    let Some(module) = guard.as_mut() else {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    };
    let Some(slot_id) = module.session(session).map(Session::slot_id) else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    let token = match module.ensure_token(slot_id) {
        Ok(token) => token,
        Err(err) => return err,
    };
    drop(guard);
    // SAFETY: caller guarantees `template`/`count` describe a valid,
    // writable attribute array.
    unsafe { fill_attributes(&token, kind, template, count) }
}

/// Fill each template entry from the object's attributes, tracking
/// the worst outcome across entries.
///
/// # Safety
/// `template` must point to `count` writable [`CkAttribute`] entries.
unsafe fn fill_attributes(
    token: &TokenObjects,
    kind: ObjectKind,
    template: CkAttributePtr,
    count: CkUlong,
) -> CkRv {
    let entries = usize_from_ulong(count);
    let mut result = CKR_OK;
    for index in 0..entries {
        // SAFETY: index < count and the caller guarantees `count`
        // valid, writable entries.
        let entry_ptr = unsafe { template.add(index) };
        // SAFETY: entry_ptr is valid per the loop bound.
        let attr_type = unsafe { entry_ptr.read() }.attr_type;
        // SAFETY: entry_ptr is valid and writable.
        let entry_result =
            unsafe { fill_one_attribute(entry_ptr, token.attribute(kind, attr_type)) };
        if entry_result != CKR_OK {
            result = entry_result;
        }
    }
    result
}

/// Write one attribute value into a template entry.
///
/// # Safety
/// `entry` must be a valid, writable [`CkAttribute`]; when its
/// `p_value` is non-NULL it must hold `ul_value_len` writable bytes.
unsafe fn fill_one_attribute(entry: CkAttributePtr, value: Option<AttrValue<'_>>) -> CkRv {
    // SAFETY: entry is a valid, readable CK_ATTRIBUTE.
    let current = unsafe { entry.read() };
    match value {
        None => {
            // SAFETY: entry is writable.
            unsafe {
                set_value_len(entry, CK_UNAVAILABLE_INFORMATION);
            }
            CKR_ATTRIBUTE_TYPE_INVALID
        }
        Some(AttrValue::Sensitive) => {
            // SAFETY: entry is writable.
            unsafe {
                set_value_len(entry, CK_UNAVAILABLE_INFORMATION);
            }
            CKR_ATTRIBUTE_SENSITIVE
        }
        Some(val) => {
            let bytes = val.as_bytes().unwrap_or(&[]);
            if current.p_value.is_null() {
                // SAFETY: entry is writable.
                unsafe {
                    set_value_len(entry, ulong_from_usize(bytes.len()));
                }
                return CKR_OK;
            }
            if usize_from_ulong(current.ul_value_len) < bytes.len() {
                // SAFETY: entry is writable.
                unsafe {
                    set_value_len(entry, ulong_from_usize(bytes.len()));
                }
                return CKR_BUFFER_TOO_SMALL;
            }
            // SAFETY: p_value holds at least bytes.len() writable
            // bytes per the capacity check.
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), current.p_value.cast::<u8>(), bytes.len());
            }
            // SAFETY: entry is writable.
            unsafe {
                set_value_len(entry, ulong_from_usize(bytes.len()));
            }
            CKR_OK
        }
    }
}

/// Write only the `ul_value_len` field of a template entry, leaving
/// `attr_type` and `p_value` untouched.
///
/// # Safety
/// `entry` must be a valid, writable [`CkAttribute`].
unsafe fn set_value_len(entry: CkAttributePtr, length: CkUlong) {
    // SAFETY: entry is a valid, readable/writable CK_ATTRIBUTE.
    let mut current = unsafe { entry.read() };
    current.ul_value_len = length;
    // SAFETY: entry is writable.
    unsafe {
        entry.write(current);
    }
}

/// `C_SignInit`: select the sign mechanism for a session (v2.40
/// s5.9.1).
unsafe extern "C" fn c_sign_init(
    session: CkSessionHandle,
    mechanism: CkMechanismPtr,
    key: CkObjectHandle,
) -> CkRv {
    if mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if key != crate::token::OBJ_PRIVATE_KEY {
        return CKR_KEY_HANDLE_INVALID;
    }
    // SAFETY: caller guarantees mechanism is a valid CK_MECHANISM.
    let requested = unsafe { mechanism.read() }.mechanism;
    diag!("C_SignInit session={session} mechanism={requested:#06x}");
    let Some(requested_mechanism) = Mechanism::from_ck_type(requested) else {
        return CKR_MECHANISM_INVALID;
    };
    let mut guard = match lock_module() {
        Ok(guard) => guard,
        Err(err) => return err,
    };
    let Some(module) = guard.as_mut() else {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    };
    let Some(slot_id) = module.session(session).map(Session::slot_id) else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    if module
        .session(session)
        .is_some_and(Session::has_active_sign)
    {
        return CKR_OPERATION_ACTIVE;
    }
    let token = match module.ensure_token(slot_id) {
        Ok(token) => token,
        Err(err) => return err,
    };
    if token.mechanism() != requested_mechanism {
        return CKR_MECHANISM_INVALID;
    }
    let Some(session_mut) = module.session_mut(session) else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    session_mut.begin_sign(requested_mechanism);
    drop(guard);
    CKR_OK
}

/// `C_Sign`: single-part sign on the card (v2.40 s5.9.2).
///
/// Supports the two-call length query (NULL signature buffer) without
/// touching the card, and only runs the card operation once the
/// caller has provided a large-enough buffer, so a size probe never
/// wastes a card round trip.
unsafe extern "C" fn c_sign(
    session: CkSessionHandle,
    data: CkBytePtr,
    data_len: CkUlong,
    signature: CkBytePtr,
    signature_len: CkUlongPtr,
) -> CkRv {
    if signature_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut guard = match lock_module() {
        Ok(guard) => guard,
        Err(err) => return err,
    };
    let Some(module) = guard.as_mut() else {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    };
    let Some(session_ref) = module.session(session) else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    let slot_id = session_ref.slot_id();
    let Some(sign_state) = session_ref.sign_state() else {
        return CKR_OPERATION_NOT_INITIALIZED;
    };
    let mechanism = sign_state.mechanism();
    if signature.is_null() {
        // SAFETY: signature_len is writable per the caller contract.
        unsafe {
            signature_len.write(ulong_from_usize(mechanism.signature_len()));
        }
        return CKR_OK;
    }
    // SAFETY: signature_len is readable per the caller contract.
    let capacity = usize_from_ulong(unsafe { signature_len.read() });
    if capacity < mechanism.signature_len() {
        // SAFETY: signature_len is writable.
        unsafe {
            signature_len.write(ulong_from_usize(mechanism.signature_len()));
        }
        return CKR_BUFFER_TOO_SMALL;
    }
    let Some(reader_name) = module.reader_name(slot_id) else {
        clear_sign(module, session);
        return CKR_DEVICE_ERROR;
    };
    let pin_cache = match module.pin_cache(slot_id) {
        Ok(cache) => cache,
        Err(error) => {
            clear_sign(module, session);
            return error;
        }
    };
    // The sign operation is single-shot: terminate it now, before the
    // card round trip, so the module lock is not held across card IO
    // (an unrelated PKCS#11 call must not block on the card).
    clear_sign(module, session);
    drop(guard);
    let input_len = usize_from_ulong(data_len);
    let input = if data.is_null() || input_len == 0 {
        Vec::new()
    } else {
        // SAFETY: data points to `data_len` readable bytes per the
        // caller contract.
        unsafe { core::slice::from_raw_parts(data, input_len) }.to_vec()
    };
    diag!("C_Sign session={session} data_len={input_len}");
    let outcome = crate::token::card_sign(&reader_name, &pin_cache, mechanism, &input);
    let rv = match outcome {
        Ok(bytes) => {
            // The module lock was dropped across the card round trip,
            // so another thread may have closed this session (or torn
            // the module down) while the card signed. Re-validate the
            // handle before writing into the caller's buffer: a
            // signature must not be delivered into a context the
            // caller already tore down (v2.40 [`CKR_SESSION_CLOSED`]:
            // "the session was closed during the execution").
            let guard = match lock_module() {
                Ok(guard) => guard,
                Err(err) => return err,
            };
            let Some(module) = guard.as_ref() else {
                return CKR_CRYPTOKI_NOT_INITIALIZED;
            };
            if module.session(session).is_none() {
                return CKR_SESSION_CLOSED;
            }
            drop(guard);
            // SAFETY: signature has capacity >= mechanism length >=
            // bytes.len(), and signature_len is writable.
            unsafe { deliver_bytes(signature, signature_len, &bytes) }
        }
        // `card_sign` destructively checks the cache out before any
        // VERIFY and restores it only after the entire operation succeeds.
        Err(err) => err,
    };
    diag!("C_Sign rv={rv:#06x}");
    rv
}

/// `C_SetPIN` (login-only build): PIN change is gated off until the
/// counter-safe path is hardware-proven on a 2026 ECC card. Matches
/// the write-protected token flag NSS sees. Build with
/// `--features pin-change` to enable the real implementation below.
#[cfg(not(feature = "pin-change"))]
unsafe extern "C" fn c_set_pin(
    _session: CkSessionHandle,
    _old_pin: CkUtf8CharPtr,
    _old_len: CkUlong,
    _new_pin: CkUtf8CharPtr,
    _new_len: CkUlong,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_SetPIN`: change PIN1 via `CHANGE REFERENCE DATA` (v2.40
/// s5.6.7). The current and new PIN ride in one card command, so no
/// prior login is required (matching the card's own semantics). On
/// success the card has cleared its PIN presentation and reset the
/// retry counter; the cached login PIN1 is invalidated so later
/// signs verify a fresh `C_Login` rather than a dead value.
#[cfg(feature = "pin-change")]
unsafe extern "C" fn c_set_pin(
    session: CkSessionHandle,
    old_pin: CkUtf8CharPtr,
    old_len: CkUlong,
    new_pin: CkUtf8CharPtr,
    new_len: CkUlong,
) -> CkRv {
    if old_pin.is_null() || new_pin.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    // SAFETY: caller guarantees old_pin points to `old_len` bytes;
    // the bytes are copied straight into a zeroizing PinBytes and
    // never logged (PIN secrecy rule).
    let current = match PinBytes::new(
        unsafe { core::slice::from_raw_parts(old_pin, usize_from_ulong(old_len)) }.to_vec(),
    ) {
        Ok(pin) => pin,
        Err(error) => return classify_pin_error(error),
    };
    // SAFETY: caller guarantees new_pin points to `new_len` bytes;
    // same zeroizing, never-logged handling.
    let new = match PinBytes::new(
        unsafe { core::slice::from_raw_parts(new_pin, usize_from_ulong(new_len)) }.to_vec(),
    ) {
        Ok(pin) => pin,
        Err(error) => return classify_pin_error(error),
    };
    if let Err(_role_err) = current.validate_digits(PIN1_MIN_DIGITS, PIN1_MAX_DIGITS) {
        return CKR_PIN_LEN_RANGE;
    }
    if let Err(_role_err) = new.validate_digits(PIN1_MIN_DIGITS, PIN1_MAX_DIGITS) {
        return CKR_PIN_LEN_RANGE;
    }
    let mut guard = match lock_module() {
        Ok(guard) => guard,
        Err(err) => return err,
    };
    let Some(module) = guard.as_mut() else {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    };
    let Some(session_ref) = module.session(session) else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    let slot_id = session_ref.slot_id();
    let Some(reader_name) = module.reader_name(slot_id) else {
        return CKR_DEVICE_ERROR;
    };
    // Invalidate the cached login PIN1 *before* the card round trip.
    // The module re-verifies the cached PIN inside every sign; once
    // CHANGE REFERENCE DATA runs, the old cached value is dead, so a
    // stale cache would make each later sign re-verify the wrong PIN
    // and burn a retry per operation -- straight to a lockout. On
    // 2026 cards that lockout is unrecoverable, so this invalidation
    // is a card-safety measure, not a nicety. Dropping the login
    // (rather than replacing it with the new value) forces a fresh
    // C_Login with the new PIN, so the module never *assumes* a PIN
    // it has not seen the card accept via a real VERIFY.
    module.logout(slot_id);
    if reader_name.starts_with("rapp:") {
        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    // Drop the lock before card IO (an unrelated PKCS#11 call must
    // not block on the card round trip).
    drop(guard);
    if let Err(err) = crate::token::card_change_pin1(&ReaderId::new(reader_name), current, new) {
        return err;
    }
    CKR_OK
}

/// Clear a session's active sign operation, ignoring an unknown
/// handle (the operation is terminated on completion or error).
fn clear_sign(module: &mut ModuleState, session: CkSessionHandle) {
    if let Some(session_mut) = module.session_mut(session) {
        session_mut.clear_sign();
    }
}

/// `C_WaitForSlotEvent`: non-blocking slot-event poll (v2.40 s5.5.10).
///
/// A non-blocking poll ([`CKF_DONT_BLOCK`]) refreshes the slot table
/// (the same FINEID-proven probe `C_GetSlotList` runs) and reports
/// the first slot whose card presence changed since the last
/// report -- so NSS notices card insertion and removal on its own
/// polling cadence without a browser restart. Each change is
/// reported exactly once. A blocking call would need a dedicated
/// event thread inside the host process and stays unsupported.
unsafe extern "C" fn c_wait_for_slot_event(
    flags: CkFlags,
    slot: CkSlotIdPtr,
    _reserved: CkVoidPtr,
) -> CkRv {
    if flags & CKF_DONT_BLOCK == 0 {
        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    if slot.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut guard = match lock_module() {
        Ok(guard) => guard,
        Err(err) => return err,
    };
    let Some(module) = guard.as_mut() else {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    };
    if let Err(err) = module.refresh_slots() {
        return err;
    }
    let event = module.take_slot_event();
    drop(guard);
    let Some(slot_id) = event else {
        return CKR_NO_EVENT;
    };
    diag!("C_WaitForSlotEvent slot={slot_id}");
    // SAFETY: caller guarantees `slot` is a writable CK_SLOT_ID
    // location (checked non-NULL above).
    unsafe {
        slot.write(slot_id);
    }
    CKR_OK
}

// ---- Unsupported-function stubs ----
//
// Each remaining v2.40 slot must be non-NULL; per spec an
// unimplemented function returns CKR_FUNCTION_NOT_SUPPORTED. The
// signatures mirror the vtable field types exactly.

/// `C_InitToken` stub: token init is out of scope. The FINEID card
/// is personalised by DVV and this token is write-protected, so the
/// specific v2.40 code is [`CKR_TOKEN_WRITE_PROTECTED`], not the
/// generic not-supported.
unsafe extern "C" fn c_init_token(
    _slot: CkSlotId,
    _pin: CkUtf8CharPtr,
    _pin_len: CkUlong,
    _label: CkUtf8CharPtr,
) -> CkRv {
    CKR_TOKEN_WRITE_PROTECTED
}

/// `C_InitPIN` stub: PIN management is out of scope.
unsafe extern "C" fn c_init_pin(
    _session: CkSessionHandle,
    _pin: CkUtf8CharPtr,
    _pin_len: CkUlong,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_GetOperationState` stub: operation-state save/restore is out of
/// scope.
unsafe extern "C" fn c_get_operation_state(
    _session: CkSessionHandle,
    _state: CkBytePtr,
    _state_len: CkUlongPtr,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_SetOperationState` stub: operation-state save/restore is out of
/// scope.
unsafe extern "C" fn c_set_operation_state(
    _session: CkSessionHandle,
    _state: CkBytePtr,
    _state_len: CkUlong,
    _encryption_key: CkObjectHandle,
    _authentication_key: CkObjectHandle,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_CreateObject` stub: this token is read-only.
unsafe extern "C" fn c_create_object(
    _session: CkSessionHandle,
    _template: CkAttributePtr,
    _count: CkUlong,
    _object: CkObjectHandlePtr,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_CopyObject` stub: this token is read-only.
unsafe extern "C" fn c_copy_object(
    _session: CkSessionHandle,
    _object: CkObjectHandle,
    _template: CkAttributePtr,
    _count: CkUlong,
    _new_object: CkObjectHandlePtr,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_DestroyObject` stub: this token is read-only.
unsafe extern "C" fn c_destroy_object(_session: CkSessionHandle, _object: CkObjectHandle) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_GetObjectSize` stub: not exposed by this module.
unsafe extern "C" fn c_get_object_size(
    _session: CkSessionHandle,
    _object: CkObjectHandle,
    _size: CkUlongPtr,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_SetAttributeValue` stub: this token is read-only.
unsafe extern "C" fn c_set_attribute_value(
    _session: CkSessionHandle,
    _object: CkObjectHandle,
    _template: CkAttributePtr,
    _count: CkUlong,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_EncryptInit` stub: encryption is out of scope (sign-only).
unsafe extern "C" fn c_encrypt_init(
    _session: CkSessionHandle,
    _mechanism: CkMechanismPtr,
    _key: CkObjectHandle,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_Encrypt` stub: encryption is out of scope.
unsafe extern "C" fn c_encrypt(
    _session: CkSessionHandle,
    _data: CkBytePtr,
    _data_len: CkUlong,
    _encrypted: CkBytePtr,
    _encrypted_len: CkUlongPtr,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_EncryptUpdate` stub: encryption is out of scope.
unsafe extern "C" fn c_encrypt_update(
    _session: CkSessionHandle,
    _part: CkBytePtr,
    _part_len: CkUlong,
    _encrypted: CkBytePtr,
    _encrypted_len: CkUlongPtr,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_EncryptFinal` stub: encryption is out of scope.
unsafe extern "C" fn c_encrypt_final(
    _session: CkSessionHandle,
    _encrypted: CkBytePtr,
    _encrypted_len: CkUlongPtr,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_DecryptInit` stub: decryption is out of scope.
unsafe extern "C" fn c_decrypt_init(
    _session: CkSessionHandle,
    _mechanism: CkMechanismPtr,
    _key: CkObjectHandle,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_Decrypt` stub: decryption is out of scope.
unsafe extern "C" fn c_decrypt(
    _session: CkSessionHandle,
    _encrypted: CkBytePtr,
    _encrypted_len: CkUlong,
    _data: CkBytePtr,
    _data_len: CkUlongPtr,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_DecryptUpdate` stub: decryption is out of scope.
unsafe extern "C" fn c_decrypt_update(
    _session: CkSessionHandle,
    _encrypted: CkBytePtr,
    _encrypted_len: CkUlong,
    _data: CkBytePtr,
    _data_len: CkUlongPtr,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_DecryptFinal` stub: decryption is out of scope.
unsafe extern "C" fn c_decrypt_final(
    _session: CkSessionHandle,
    _data: CkBytePtr,
    _data_len: CkUlongPtr,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_DigestInit` stub: digesting is done off-card by the caller.
unsafe extern "C" fn c_digest_init(_session: CkSessionHandle, _mechanism: CkMechanismPtr) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_Digest` stub: digesting is out of scope.
unsafe extern "C" fn c_digest(
    _session: CkSessionHandle,
    _data: CkBytePtr,
    _data_len: CkUlong,
    _digest: CkBytePtr,
    _digest_len: CkUlongPtr,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_DigestUpdate` stub: digesting is out of scope.
unsafe extern "C" fn c_digest_update(
    _session: CkSessionHandle,
    _part: CkBytePtr,
    _part_len: CkUlong,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_DigestKey` stub: no key on this token can be digested, which
/// v2.40 names [`CKR_KEY_INDIGESTIBLE`].
unsafe extern "C" fn c_digest_key(_session: CkSessionHandle, _key: CkObjectHandle) -> CkRv {
    CKR_KEY_INDIGESTIBLE
}

/// `C_DigestFinal` stub: digesting is out of scope.
unsafe extern "C" fn c_digest_final(
    _session: CkSessionHandle,
    _digest: CkBytePtr,
    _digest_len: CkUlongPtr,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_SignUpdate` stub: only single-part `C_Sign` is supported; NSS
/// TLS client auth uses single-part signing.
unsafe extern "C" fn c_sign_update(
    _session: CkSessionHandle,
    _part: CkBytePtr,
    _part_len: CkUlong,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_SignFinal` stub: only single-part `C_Sign` is supported.
unsafe extern "C" fn c_sign_final(
    _session: CkSessionHandle,
    _signature: CkBytePtr,
    _signature_len: CkUlongPtr,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_SignRecoverInit` stub: the FINEID auth key signs without
/// message recovery, so the specific code is
/// [`CKR_KEY_FUNCTION_NOT_PERMITTED`].
unsafe extern "C" fn c_sign_recover_init(
    _session: CkSessionHandle,
    _mechanism: CkMechanismPtr,
    _key: CkObjectHandle,
) -> CkRv {
    CKR_KEY_FUNCTION_NOT_PERMITTED
}

/// `C_SignRecover` stub: sign-recover is out of scope.
unsafe extern "C" fn c_sign_recover(
    _session: CkSessionHandle,
    _data: CkBytePtr,
    _data_len: CkUlong,
    _signature: CkBytePtr,
    _signature_len: CkUlongPtr,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_VerifyInit`: select the software-verify mechanism for a
/// session (v2.40 s5.10.1). Verification is pure host-side
/// computation against the cached certificate public key -- the
/// key handle must be the token's public-key object.
unsafe extern "C" fn c_verify_init(
    session: CkSessionHandle,
    mechanism: CkMechanismPtr,
    key: CkObjectHandle,
) -> CkRv {
    if mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if key != crate::token::OBJ_PUBLIC_KEY {
        return CKR_KEY_HANDLE_INVALID;
    }
    // SAFETY: caller guarantees mechanism is a valid CK_MECHANISM.
    let requested = unsafe { mechanism.read() }.mechanism;
    diag!("C_VerifyInit session={session} mechanism={requested:#06x}");
    let Some(requested_mechanism) = Mechanism::from_ck_type(requested) else {
        return CKR_MECHANISM_INVALID;
    };
    let mut guard = match lock_module() {
        Ok(guard) => guard,
        Err(err) => return err,
    };
    let Some(module) = guard.as_mut() else {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    };
    let Some(slot_id) = module.session(session).map(Session::slot_id) else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    if module
        .session(session)
        .is_some_and(Session::has_active_verify)
    {
        return CKR_OPERATION_ACTIVE;
    }
    let token = match module.ensure_token(slot_id) {
        Ok(token) => token,
        Err(err) => return err,
    };
    if token.mechanism() != requested_mechanism {
        return CKR_MECHANISM_INVALID;
    }
    let Some(session_mut) = module.session_mut(session) else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    session_mut.begin_verify(requested_mechanism);
    drop(guard);
    CKR_OK
}

/// `C_Verify`: single-part software verification (v2.40 s5.10.2).
/// No card IO and no PIN: the check runs against the cached
/// certificate public key. Input shapes mirror `C_Sign` exactly
/// (`CKM_RSA_PKCS`: `DigestInfo || SHA-256 hash`; `CKM_ECDSA`:
/// raw digest + raw `r || s`).
unsafe extern "C" fn c_verify(
    session: CkSessionHandle,
    data: CkBytePtr,
    data_len: CkUlong,
    signature: CkBytePtr,
    signature_len: CkUlong,
) -> CkRv {
    let mut guard = match lock_module() {
        Ok(guard) => guard,
        Err(err) => return err,
    };
    let Some(module) = guard.as_mut() else {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    };
    let Some(session_ref) = module.session(session) else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    let slot_id = session_ref.slot_id();
    let Some(verify_state) = session_ref.verify_state() else {
        return CKR_OPERATION_NOT_INITIALIZED;
    };
    let mechanism = verify_state.mechanism();
    let token = match module.ensure_token(slot_id) {
        Ok(token) => token,
        Err(err) => return err,
    };
    // Single-shot: the operation terminates now, whatever the
    // outcome (v2.40 s5.10.2).
    if let Some(session_mut) = module.session_mut(session) {
        session_mut.clear_verify();
    }
    drop(guard);
    let input_len = usize_from_ulong(data_len);
    let input = if data.is_null() || input_len == 0 {
        Vec::new()
    } else {
        // SAFETY: data points to `data_len` readable bytes per the
        // caller contract.
        unsafe { core::slice::from_raw_parts(data, input_len) }.to_vec()
    };
    let sig_len = usize_from_ulong(signature_len);
    let sig = if signature.is_null() || sig_len == 0 {
        Vec::new()
    } else {
        // SAFETY: signature points to `signature_len` readable
        // bytes per the caller contract.
        unsafe { core::slice::from_raw_parts(signature, sig_len) }.to_vec()
    };
    let rv = token.verify_signature(mechanism, &input, &sig);
    diag!("C_Verify session={session} data_len={input_len} sig_len={sig_len} rv={rv:#06x}");
    rv
}

/// `C_VerifyUpdate` stub: verification is out of scope.
unsafe extern "C" fn c_verify_update(
    _session: CkSessionHandle,
    _part: CkBytePtr,
    _part_len: CkUlong,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_VerifyFinal` stub: verification is out of scope.
unsafe extern "C" fn c_verify_final(
    _session: CkSessionHandle,
    _signature: CkBytePtr,
    _signature_len: CkUlong,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_VerifyRecoverInit` stub: verify-recover is out of scope.
unsafe extern "C" fn c_verify_recover_init(
    _session: CkSessionHandle,
    _mechanism: CkMechanismPtr,
    _key: CkObjectHandle,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_VerifyRecover` stub: verify-recover is out of scope.
unsafe extern "C" fn c_verify_recover(
    _session: CkSessionHandle,
    _signature: CkBytePtr,
    _signature_len: CkUlong,
    _data: CkBytePtr,
    _data_len: CkUlongPtr,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_DigestEncryptUpdate` stub: dual-function ops are out of scope.
unsafe extern "C" fn c_digest_encrypt_update(
    _session: CkSessionHandle,
    _part: CkBytePtr,
    _part_len: CkUlong,
    _encrypted: CkBytePtr,
    _encrypted_len: CkUlongPtr,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_DecryptDigestUpdate` stub: dual-function ops are out of scope.
unsafe extern "C" fn c_decrypt_digest_update(
    _session: CkSessionHandle,
    _encrypted: CkBytePtr,
    _encrypted_len: CkUlong,
    _part: CkBytePtr,
    _part_len: CkUlongPtr,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_SignEncryptUpdate` stub: dual-function ops are out of scope.
unsafe extern "C" fn c_sign_encrypt_update(
    _session: CkSessionHandle,
    _part: CkBytePtr,
    _part_len: CkUlong,
    _encrypted: CkBytePtr,
    _encrypted_len: CkUlongPtr,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_DecryptVerifyUpdate` stub: dual-function ops are out of scope.
unsafe extern "C" fn c_decrypt_verify_update(
    _session: CkSessionHandle,
    _encrypted: CkBytePtr,
    _encrypted_len: CkUlong,
    _part: CkBytePtr,
    _part_len: CkUlongPtr,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_GenerateKey` stub: key generation is out of scope.
unsafe extern "C" fn c_generate_key(
    _session: CkSessionHandle,
    _mechanism: CkMechanismPtr,
    _template: CkAttributePtr,
    _count: CkUlong,
    _key: CkObjectHandlePtr,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_GenerateKeyPair` stub: key generation is out of scope.
unsafe extern "C" fn c_generate_key_pair(
    _session: CkSessionHandle,
    _mechanism: CkMechanismPtr,
    _public_template: CkAttributePtr,
    _public_count: CkUlong,
    _private_template: CkAttributePtr,
    _private_count: CkUlong,
    _public_key: CkObjectHandlePtr,
    _private_key: CkObjectHandlePtr,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_WrapKey` stub: key wrap is out of scope.
unsafe extern "C" fn c_wrap_key(
    _session: CkSessionHandle,
    _mechanism: CkMechanismPtr,
    _wrapping_key: CkObjectHandle,
    _key: CkObjectHandle,
    _wrapped: CkBytePtr,
    _wrapped_len: CkUlongPtr,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_UnwrapKey` stub: no key on this token can unwrap
/// ([`CKR_KEY_FUNCTION_NOT_PERMITTED`]; the token is also read-only
/// so the unwrapped key could never be stored).
unsafe extern "C" fn c_unwrap_key(
    _session: CkSessionHandle,
    _mechanism: CkMechanismPtr,
    _unwrapping_key: CkObjectHandle,
    _wrapped: CkBytePtr,
    _wrapped_len: CkUlong,
    _template: CkAttributePtr,
    _count: CkUlong,
    _key: CkObjectHandlePtr,
) -> CkRv {
    CKR_KEY_FUNCTION_NOT_PERMITTED
}

/// `C_DeriveKey` stub: key derivation is out of scope.
unsafe extern "C" fn c_derive_key(
    _session: CkSessionHandle,
    _mechanism: CkMechanismPtr,
    _base_key: CkObjectHandle,
    _template: CkAttributePtr,
    _count: CkUlong,
    _key: CkObjectHandlePtr,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_SeedRandom` stub: this token accepts no seed material, which
/// v2.40 names [`CKR_RANDOM_SEED_NOT_SUPPORTED`].
unsafe extern "C" fn c_seed_random(
    _session: CkSessionHandle,
    _seed: CkBytePtr,
    _seed_len: CkUlong,
) -> CkRv {
    CKR_RANDOM_SEED_NOT_SUPPORTED
}

/// `C_GenerateRandom` stub: RNG services are out of scope.
unsafe extern "C" fn c_generate_random(
    _session: CkSessionHandle,
    _random: CkBytePtr,
    _random_len: CkUlong,
) -> CkRv {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// `C_GetFunctionStatus` stub: legacy parallel-function call. v2.40
/// s11.16 mandates [`CKR_FUNCTION_NOT_PARALLEL`] as its return.
unsafe extern "C" fn c_get_function_status(_session: CkSessionHandle) -> CkRv {
    CKR_FUNCTION_NOT_PARALLEL
}

/// `C_CancelFunction` stub: legacy parallel-function call. v2.40
/// s11.16 mandates [`CKR_FUNCTION_NOT_PARALLEL`] as its return.
unsafe extern "C" fn c_cancel_function(_session: CkSessionHandle) -> CkRv {
    CKR_FUNCTION_NOT_PARALLEL
}

/// The static PKCS#11 v2.40 vtable. Every slot is non-NULL as the
/// spec requires; the implemented functions do real work and the
/// stubs return [`CKR_FUNCTION_NOT_SUPPORTED`]. Field order matches
/// the canonical `pkcs11f.h` declaration order exactly.
pub static FUNCTION_LIST: CkFunctionList = CkFunctionList {
    version: CRYPTOKI_VERSION,
    C_Initialize: c_initialize,
    C_Finalize: c_finalize,
    C_GetInfo: c_get_info,
    C_GetFunctionList: c_get_function_list,
    C_GetSlotList: c_get_slot_list,
    C_GetSlotInfo: c_get_slot_info,
    C_GetTokenInfo: c_get_token_info,
    C_GetMechanismList: c_get_mechanism_list,
    C_GetMechanismInfo: c_get_mechanism_info,
    C_InitToken: c_init_token,
    C_InitPIN: c_init_pin,
    C_SetPIN: c_set_pin,
    C_OpenSession: c_open_session,
    C_CloseSession: c_close_session,
    C_CloseAllSessions: c_close_all_sessions,
    C_GetSessionInfo: c_get_session_info,
    C_GetOperationState: c_get_operation_state,
    C_SetOperationState: c_set_operation_state,
    C_Login: c_login,
    C_Logout: c_logout,
    C_CreateObject: c_create_object,
    C_CopyObject: c_copy_object,
    C_DestroyObject: c_destroy_object,
    C_GetObjectSize: c_get_object_size,
    C_GetAttributeValue: c_get_attribute_value,
    C_SetAttributeValue: c_set_attribute_value,
    C_FindObjectsInit: c_find_objects_init,
    C_FindObjects: c_find_objects,
    C_FindObjectsFinal: c_find_objects_final,
    C_EncryptInit: c_encrypt_init,
    C_Encrypt: c_encrypt,
    C_EncryptUpdate: c_encrypt_update,
    C_EncryptFinal: c_encrypt_final,
    C_DecryptInit: c_decrypt_init,
    C_Decrypt: c_decrypt,
    C_DecryptUpdate: c_decrypt_update,
    C_DecryptFinal: c_decrypt_final,
    C_DigestInit: c_digest_init,
    C_Digest: c_digest,
    C_DigestUpdate: c_digest_update,
    C_DigestKey: c_digest_key,
    C_DigestFinal: c_digest_final,
    C_SignInit: c_sign_init,
    C_Sign: c_sign,
    C_SignUpdate: c_sign_update,
    C_SignFinal: c_sign_final,
    C_SignRecoverInit: c_sign_recover_init,
    C_SignRecover: c_sign_recover,
    C_VerifyInit: c_verify_init,
    C_Verify: c_verify,
    C_VerifyUpdate: c_verify_update,
    C_VerifyFinal: c_verify_final,
    C_VerifyRecoverInit: c_verify_recover_init,
    C_VerifyRecover: c_verify_recover,
    C_DigestEncryptUpdate: c_digest_encrypt_update,
    C_DecryptDigestUpdate: c_decrypt_digest_update,
    C_SignEncryptUpdate: c_sign_encrypt_update,
    C_DecryptVerifyUpdate: c_decrypt_verify_update,
    C_GenerateKey: c_generate_key,
    C_GenerateKeyPair: c_generate_key_pair,
    C_WrapKey: c_wrap_key,
    C_UnwrapKey: c_unwrap_key,
    C_DeriveKey: c_derive_key,
    C_SeedRandom: c_seed_random,
    C_GenerateRandom: c_generate_random,
    C_GetFunctionStatus: c_get_function_status,
    C_CancelFunction: c_cancel_function,
    C_WaitForSlotEvent: c_wait_for_slot_event,
};

#[cfg(test)]
mod tests {
    use refineid_lib_core::apdu::status_word::PinRetries;
    use refineid_lib_core::auth::PinStatus;

    use super::{FUNCTION_LIST, c_sign, padded_field, user_pin_status_flags};
    use crate::ck::{
        CKF_USER_PIN_COUNT_LOW, CKF_USER_PIN_FINAL_TRY, CKF_USER_PIN_LOCKED, CkBytePtr, CkRv,
        CkSessionHandle, CkUlong, CkUlongPtr, CkVersion,
    };

    #[test]
    fn versions_are_calver_and_v240() {
        assert_eq!(
            FUNCTION_LIST.version,
            CkVersion {
                major: 2,
                minor: 40
            }
        );
    }

    #[test]
    fn function_list_sign_slot_points_at_c_sign() {
        // The C_Sign slot must point at our single-part c_sign, and
        // must be a distinct pointer from the multi-part C_SignUpdate
        // slot.
        let expected: unsafe extern "C" fn(
            CkSessionHandle,
            CkBytePtr,
            CkUlong,
            CkBytePtr,
            CkUlongPtr,
        ) -> CkRv = c_sign;
        assert!(core::ptr::fn_addr_eq(FUNCTION_LIST.C_Sign, expected));
        assert!(!core::ptr::fn_addr_eq(
            FUNCTION_LIST.C_Sign,
            FUNCTION_LIST.C_SignUpdate
        ));
    }

    #[test]
    fn padded_field_is_space_padded_and_truncated() {
        let field: [u8; 4] = padded_field("AB");
        assert_eq!(&field, b"AB  ");
        let truncated: [u8; 2] = padded_field("ABCD");
        assert_eq!(&truncated, b"AB");
    }

    #[test]
    fn user_pin_flags_follow_live_five_try_policy() {
        let retries = |count| {
            PinRetries::from_nibble(count).expect("test retry count fits the status-word nibble")
        };

        assert_eq!(user_pin_status_flags(PinStatus::Remaining(retries(5))), 0);
        assert_eq!(
            user_pin_status_flags(PinStatus::Remaining(retries(4))),
            CKF_USER_PIN_COUNT_LOW
        );
        assert_eq!(
            user_pin_status_flags(PinStatus::Remaining(retries(3))),
            CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY
        );
        assert_eq!(
            user_pin_status_flags(PinStatus::Remaining(retries(2))),
            CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_LOCKED
        );
        assert_eq!(
            user_pin_status_flags(PinStatus::Remaining(retries(1))),
            CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_LOCKED
        );
        assert_eq!(
            user_pin_status_flags(PinStatus::Remaining(retries(0))),
            CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_LOCKED
        );
        assert_eq!(
            user_pin_status_flags(PinStatus::Locked),
            CKF_USER_PIN_LOCKED
        );
        assert_eq!(user_pin_status_flags(PinStatus::NoInfo), 0);
    }
}
