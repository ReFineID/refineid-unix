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

//! Hand-written PKCS#11 v2.40 C ABI: the scalar typedefs, the
//! `#[repr(C)]` structures, the function-list vtable, and the named
//! constants this module needs.
//!
//! Everything here is transcribed from the OASIS "PKCS#11
//! Cryptographic Token Interface Base Specification Version 2.40"
//! (Plus Errata 01) and its companion header `pkcs11t.h`. We do not
//! depend on a `-sys` binding crate (supply-chain gate); the layout
//! is the Unix default-alignment `pkcs11.h` -- there are no packing
//! pragmas on Unix, so plain `#[repr(C)]` is byte-compatible with
//! every consumer (`NSS`, `p11-kit`, `pkcs11-provider`).
//!
//! Per house rule "no naked hex", every `0x` value below is a named
//! constant carrying its spec origin in a doc comment.

// ck.rs is the crate's transcription of the PKCS#11 v2.40 constant
// namespace and C ABI. It intentionally defines the full set of
// return values, flags, and sentinels from the specification, not
// only the subset the current entry points reference, so the header
// stays a faithful, stable reference and later functions need not
// re-derive spec values (risking a naked-hex or transcription slip).

use core::ffi::{c_ulong, c_void};

// ---- Scalar typedefs (pkcs11t.h "General data types") ----

/// `CK_BYTE`: an unsigned 8-bit byte.
pub type CkByte = u8;
/// `CK_CHAR`: an 8-bit character (same width as [`CkByte`]).
pub type CkChar = CkByte;
/// `CK_UTF8CHAR`: a UTF-8 code unit (same width as [`CkByte`]).
pub type CkUtf8Char = CkByte;
/// `CK_BBOOL`: a boolean, [`CK_TRUE`] or [`CK_FALSE`].
pub type CkBbool = CkByte;
/// `CK_ULONG`: the platform `unsigned long`. On Unix LP64 this is
/// 64-bit; the whole ABI keys off this width.
pub type CkUlong = c_ulong;
/// `CK_FLAGS`: a bit-field, always a [`CkUlong`].
pub type CkFlags = CkUlong;
/// `CK_RV`: a return value / status code, a [`CkUlong`].
pub type CkRv = CkUlong;
/// `CK_SLOT_ID`: a slot identifier, a [`CkUlong`].
pub type CkSlotId = CkUlong;
/// `CK_SESSION_HANDLE`: an open-session handle, a [`CkUlong`].
pub type CkSessionHandle = CkUlong;
/// `CK_OBJECT_HANDLE`: a token/session object handle, a [`CkUlong`].
pub type CkObjectHandle = CkUlong;
/// `CK_USER_TYPE`: the login user type, a [`CkUlong`].
pub type CkUserType = CkUlong;
/// `CK_STATE`: a session state, a [`CkUlong`].
pub type CkState = CkUlong;
/// `CK_ATTRIBUTE_TYPE`: an object attribute selector, a [`CkUlong`].
pub type CkAttributeType = CkUlong;
/// `CK_MECHANISM_TYPE`: a mechanism selector, a [`CkUlong`].
pub type CkMechanismType = CkUlong;

/// `CK_VOID_PTR`: an untyped pointer.
pub type CkVoidPtr = *mut c_void;
/// `CK_BYTE_PTR`: pointer to [`CkByte`] data.
pub type CkBytePtr = *mut CkByte;
/// `CK_ULONG_PTR`: pointer to a [`CkUlong`].
pub type CkUlongPtr = *mut CkUlong;
/// `CK_UTF8CHAR_PTR`: pointer to UTF-8 data.
pub type CkUtf8CharPtr = *mut CkUtf8Char;
/// `CK_SLOT_ID_PTR`: pointer to a [`CkSlotId`] (array).
pub type CkSlotIdPtr = *mut CkSlotId;
/// `CK_ATTRIBUTE_PTR`: pointer to a [`CkAttribute`] (template array).
pub type CkAttributePtr = *mut CkAttribute;
/// `CK_MECHANISM_PTR`: pointer to a [`CkMechanism`].
pub type CkMechanismPtr = *mut CkMechanism;
/// `CK_OBJECT_HANDLE_PTR`: pointer to a [`CkObjectHandle`] (array).
pub type CkObjectHandlePtr = *mut CkObjectHandle;
/// `CK_SESSION_HANDLE_PTR`: pointer to a [`CkSessionHandle`].
pub type CkSessionHandlePtr = *mut CkSessionHandle;
/// `CK_INFO_PTR`: pointer to a [`CkInfo`].
pub type CkInfoPtr = *mut CkInfo;
/// `CK_SLOT_INFO_PTR`: pointer to a [`CkSlotInfo`].
pub type CkSlotInfoPtr = *mut CkSlotInfo;
/// `CK_TOKEN_INFO_PTR`: pointer to a [`CkTokenInfo`].
pub type CkTokenInfoPtr = *mut CkTokenInfo;
/// `CK_SESSION_INFO_PTR`: pointer to a [`CkSessionInfo`].
pub type CkSessionInfoPtr = *mut CkSessionInfo;
/// `CK_MECHANISM_INFO_PTR`: pointer to a [`CkMechanismInfo`].
pub type CkMechanismInfoPtr = *mut CkMechanismInfo;
/// `CK_MECHANISM_TYPE_PTR`: pointer to a [`CkMechanismType`] (array).
pub type CkMechanismTypePtr = *mut CkMechanismType;
/// `CK_FUNCTION_LIST_PTR`: pointer to a [`CkFunctionList`].
pub type CkFunctionListPtr = *mut CkFunctionList;
/// `CK_FUNCTION_LIST_PTR_PTR`: out-pointer used by
/// `C_GetFunctionList` to hand back the module's static vtable.
pub type CkFunctionListPtrPtr = *mut CkFunctionListPtr;

/// `CK_NOTIFY`: the session event callback. Modelled as an untyped
/// pointer -- it is pointer-sized (ABI-identical to the real
/// function-pointer typedef) and this module never invokes it.
pub type CkNotify = CkVoidPtr;

// ---- Structures (pkcs11t.h). Unix default alignment, no packing. ----

/// `CK_VERSION`: a two-part version number (`major.minor`, where
/// `minor` counts hundredths).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CkVersion {
    /// Integer part of the version.
    pub major: CkByte,
    /// Hundredths part of the version (e.g. `40` for `x.40`).
    pub minor: CkByte,
}

/// `CK_INFO`: general Cryptoki library information returned by
/// `C_GetInfo`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CkInfo {
    /// Cryptoki interface version implemented.
    pub cryptoki_version: CkVersion,
    /// Library manufacturer, space-padded (not NUL-terminated).
    pub manufacturer_id: [CkUtf8Char; 32],
    /// Reserved; must be zero per spec.
    pub flags: CkFlags,
    /// Library description, space-padded.
    pub library_description: [CkUtf8Char; 32],
    /// Library implementation version.
    pub library_version: CkVersion,
}

/// `CK_SLOT_INFO`: information about a slot, returned by
/// `C_GetSlotInfo`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CkSlotInfo {
    /// Slot description, space-padded.
    pub slot_description: [CkUtf8Char; 64],
    /// Slot manufacturer, space-padded.
    pub manufacturer_id: [CkUtf8Char; 32],
    /// Slot capability flags ([`CKF_TOKEN_PRESENT`] etc.).
    pub flags: CkFlags,
    /// Slot hardware version.
    pub hardware_version: CkVersion,
    /// Slot firmware version.
    pub firmware_version: CkVersion,
}

/// `CK_TOKEN_INFO`: information about a token, returned by
/// `C_GetTokenInfo`. All char arrays are space-padded, never
/// NUL-terminated.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CkTokenInfo {
    /// Token label, space-padded.
    pub label: [CkUtf8Char; 32],
    /// Token manufacturer, space-padded.
    pub manufacturer_id: [CkUtf8Char; 32],
    /// Token model, space-padded.
    pub model: [CkUtf8Char; 16],
    /// Token serial number, space-padded.
    pub serial_number: [CkChar; 16],
    /// Token capability flags ([`CKF_LOGIN_REQUIRED`] etc.).
    pub flags: CkFlags,
    /// Maximum number of concurrently open sessions.
    pub ul_max_session_count: CkUlong,
    /// Sessions currently open.
    pub ul_session_count: CkUlong,
    /// Maximum number of concurrently open R/W sessions.
    pub ul_max_rw_session_count: CkUlong,
    /// R/W sessions currently open.
    pub ul_rw_session_count: CkUlong,
    /// Maximum PIN length in bytes.
    pub ul_max_pin_len: CkUlong,
    /// Minimum PIN length in bytes.
    pub ul_min_pin_len: CkUlong,
    /// Total public memory in bytes.
    pub ul_total_public_memory: CkUlong,
    /// Free public memory in bytes.
    pub ul_free_public_memory: CkUlong,
    /// Total private memory in bytes.
    pub ul_total_private_memory: CkUlong,
    /// Free private memory in bytes.
    pub ul_free_private_memory: CkUlong,
    /// Token hardware version.
    pub hardware_version: CkVersion,
    /// Token firmware version.
    pub firmware_version: CkVersion,
    /// Current token time, space-padded (unused here).
    pub utc_time: [CkChar; 16],
}

/// `CK_SESSION_INFO`: session information returned by
/// `C_GetSessionInfo`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CkSessionInfo {
    /// Slot the session is bound to.
    pub slot_id: CkSlotId,
    /// Session state ([`CKS_RO_PUBLIC_SESSION`] etc.).
    pub state: CkState,
    /// Session flags ([`CKF_SERIAL_SESSION`] etc.).
    pub flags: CkFlags,
    /// Device-dependent error code; always zero here.
    pub ul_device_error: CkUlong,
}

/// `CK_MECHANISM_INFO`: capability limits of a mechanism, returned
/// by `C_GetMechanismInfo`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CkMechanismInfo {
    /// Minimum key size the mechanism accepts.
    pub ul_min_key_size: CkUlong,
    /// Maximum key size the mechanism accepts.
    pub ul_max_key_size: CkUlong,
    /// Mechanism capability flags ([`CKF_SIGN`] etc.).
    pub flags: CkFlags,
}

/// `CK_ATTRIBUTE`: one entry of an object attribute template.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CkAttribute {
    /// Which attribute this entry selects ([`CKA_CLASS`] etc.).
    pub attr_type: CkAttributeType,
    /// Caller buffer (in) or value source; may be NULL for a
    /// length query.
    pub p_value: CkVoidPtr,
    /// Length in bytes of the buffer at `p_value` (in/out).
    pub ul_value_len: CkUlong,
}

/// `CK_MECHANISM`: a mechanism plus its optional parameters.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CkMechanism {
    /// Mechanism selector ([`CKM_RSA_PKCS`] etc.).
    pub mechanism: CkMechanismType,
    /// Optional mechanism parameter block.
    pub p_parameter: CkVoidPtr,
    /// Length in bytes of the block at `p_parameter`.
    pub ul_parameter_len: CkUlong,
}

/// `CK_C_INITIALIZE_ARGS`: the argument block optionally passed to
/// `C_Initialize`.
///
/// The four mutex callbacks are pointer-sized and
/// unused by this module (we lock with a Rust mutex), so they are
/// typed as untyped pointers.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CkCInitializeArgs {
    /// Caller-supplied mutex-create callback (ignored).
    pub create_mutex: CkVoidPtr,
    /// Caller-supplied mutex-destroy callback (ignored).
    pub destroy_mutex: CkVoidPtr,
    /// Caller-supplied mutex-lock callback (ignored).
    pub lock_mutex: CkVoidPtr,
    /// Caller-supplied mutex-unlock callback (ignored).
    pub unlock_mutex: CkVoidPtr,
    /// Threading flags ([`CKF_OS_LOCKING_OK`] etc.).
    pub flags: CkFlags,
    /// Reserved; must be NULL.
    pub p_reserved: CkVoidPtr,
}

/// One `extern "C"` cryptoki entry point returning a [`CkRv`], with
/// its argument list erased.
///
/// The [`CkFunctionList`] vtable is a
/// table of concrete signatures; this alias documents the shared
/// shape. Every stored pointer is non-NULL for the v2.40 full list.
pub type CkEntry = unsafe extern "C" fn() -> CkRv;

/// `CK_FUNCTION_LIST`: the v2.40 dispatch vtable.
///
/// Field order is the
/// canonical `pkcs11f.h` order and MUST NOT be reordered -- callers
/// index it positionally. Every slot is populated (spec 2.40 ships a
/// complete list); unimplemented entries point at stubs returning
/// [`CKR_FUNCTION_NOT_SUPPORTED`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[expect(
    non_snake_case,
    reason = "field names mirror the exact C identifiers from pkcs11f.h so the vtable reads 1:1 against the spec and against every other PKCS#11 module."
)]
pub struct CkFunctionList {
    /// Interface version this vtable implements (`2.40`).
    pub version: CkVersion,
    /// `C_Initialize` slot.
    pub C_Initialize: unsafe extern "C" fn(CkVoidPtr) -> CkRv,
    /// `C_Finalize` slot.
    pub C_Finalize: unsafe extern "C" fn(CkVoidPtr) -> CkRv,
    /// `C_GetInfo` slot.
    pub C_GetInfo: unsafe extern "C" fn(CkInfoPtr) -> CkRv,
    /// `C_GetFunctionList` slot.
    pub C_GetFunctionList: unsafe extern "C" fn(CkFunctionListPtrPtr) -> CkRv,
    /// `C_GetSlotList` slot.
    pub C_GetSlotList: unsafe extern "C" fn(CkBbool, CkSlotIdPtr, CkUlongPtr) -> CkRv,
    /// `C_GetSlotInfo` slot.
    pub C_GetSlotInfo: unsafe extern "C" fn(CkSlotId, CkSlotInfoPtr) -> CkRv,
    /// `C_GetTokenInfo` slot.
    pub C_GetTokenInfo: unsafe extern "C" fn(CkSlotId, CkTokenInfoPtr) -> CkRv,
    /// `C_GetMechanismList` slot.
    pub C_GetMechanismList: unsafe extern "C" fn(CkSlotId, CkMechanismTypePtr, CkUlongPtr) -> CkRv,
    /// `C_GetMechanismInfo` slot.
    pub C_GetMechanismInfo:
        unsafe extern "C" fn(CkSlotId, CkMechanismType, CkMechanismInfoPtr) -> CkRv,
    /// `C_InitToken` slot (unsupported).
    pub C_InitToken: unsafe extern "C" fn(CkSlotId, CkUtf8CharPtr, CkUlong, CkUtf8CharPtr) -> CkRv,
    /// `C_InitPIN` slot (unsupported).
    pub C_InitPIN: unsafe extern "C" fn(CkSessionHandle, CkUtf8CharPtr, CkUlong) -> CkRv,
    /// `C_SetPIN` slot (unsupported).
    pub C_SetPIN: unsafe extern "C" fn(
        CkSessionHandle,
        CkUtf8CharPtr,
        CkUlong,
        CkUtf8CharPtr,
        CkUlong,
    ) -> CkRv,
    /// `C_OpenSession` slot.
    pub C_OpenSession:
        unsafe extern "C" fn(CkSlotId, CkFlags, CkVoidPtr, CkNotify, CkSessionHandlePtr) -> CkRv,
    /// `C_CloseSession` slot.
    pub C_CloseSession: unsafe extern "C" fn(CkSessionHandle) -> CkRv,
    /// `C_CloseAllSessions` slot.
    pub C_CloseAllSessions: unsafe extern "C" fn(CkSlotId) -> CkRv,
    /// `C_GetSessionInfo` slot.
    pub C_GetSessionInfo: unsafe extern "C" fn(CkSessionHandle, CkSessionInfoPtr) -> CkRv,
    /// `C_GetOperationState` slot (unsupported).
    pub C_GetOperationState: unsafe extern "C" fn(CkSessionHandle, CkBytePtr, CkUlongPtr) -> CkRv,
    /// `C_SetOperationState` slot (unsupported).
    pub C_SetOperationState: unsafe extern "C" fn(
        CkSessionHandle,
        CkBytePtr,
        CkUlong,
        CkObjectHandle,
        CkObjectHandle,
    ) -> CkRv,
    /// `C_Login` slot.
    pub C_Login: unsafe extern "C" fn(CkSessionHandle, CkUserType, CkUtf8CharPtr, CkUlong) -> CkRv,
    /// `C_Logout` slot.
    pub C_Logout: unsafe extern "C" fn(CkSessionHandle) -> CkRv,
    /// `C_CreateObject` slot (unsupported).
    pub C_CreateObject:
        unsafe extern "C" fn(CkSessionHandle, CkAttributePtr, CkUlong, CkObjectHandlePtr) -> CkRv,
    /// `C_CopyObject` slot (unsupported).
    pub C_CopyObject: unsafe extern "C" fn(
        CkSessionHandle,
        CkObjectHandle,
        CkAttributePtr,
        CkUlong,
        CkObjectHandlePtr,
    ) -> CkRv,
    /// `C_DestroyObject` slot (unsupported).
    pub C_DestroyObject: unsafe extern "C" fn(CkSessionHandle, CkObjectHandle) -> CkRv,
    /// `C_GetObjectSize` slot (unsupported).
    pub C_GetObjectSize: unsafe extern "C" fn(CkSessionHandle, CkObjectHandle, CkUlongPtr) -> CkRv,
    /// `C_GetAttributeValue` slot.
    pub C_GetAttributeValue:
        unsafe extern "C" fn(CkSessionHandle, CkObjectHandle, CkAttributePtr, CkUlong) -> CkRv,
    /// `C_SetAttributeValue` slot (unsupported).
    pub C_SetAttributeValue:
        unsafe extern "C" fn(CkSessionHandle, CkObjectHandle, CkAttributePtr, CkUlong) -> CkRv,
    /// `C_FindObjectsInit` slot.
    pub C_FindObjectsInit: unsafe extern "C" fn(CkSessionHandle, CkAttributePtr, CkUlong) -> CkRv,
    /// `C_FindObjects` slot.
    pub C_FindObjects:
        unsafe extern "C" fn(CkSessionHandle, CkObjectHandlePtr, CkUlong, CkUlongPtr) -> CkRv,
    /// `C_FindObjectsFinal` slot.
    pub C_FindObjectsFinal: unsafe extern "C" fn(CkSessionHandle) -> CkRv,
    /// `C_EncryptInit` slot (unsupported).
    pub C_EncryptInit:
        unsafe extern "C" fn(CkSessionHandle, CkMechanismPtr, CkObjectHandle) -> CkRv,
    /// `C_Encrypt` slot (unsupported).
    pub C_Encrypt:
        unsafe extern "C" fn(CkSessionHandle, CkBytePtr, CkUlong, CkBytePtr, CkUlongPtr) -> CkRv,
    /// `C_EncryptUpdate` slot (unsupported).
    pub C_EncryptUpdate:
        unsafe extern "C" fn(CkSessionHandle, CkBytePtr, CkUlong, CkBytePtr, CkUlongPtr) -> CkRv,
    /// `C_EncryptFinal` slot (unsupported).
    pub C_EncryptFinal: unsafe extern "C" fn(CkSessionHandle, CkBytePtr, CkUlongPtr) -> CkRv,
    /// `C_DecryptInit` slot (unsupported).
    pub C_DecryptInit:
        unsafe extern "C" fn(CkSessionHandle, CkMechanismPtr, CkObjectHandle) -> CkRv,
    /// `C_Decrypt` slot (unsupported).
    pub C_Decrypt:
        unsafe extern "C" fn(CkSessionHandle, CkBytePtr, CkUlong, CkBytePtr, CkUlongPtr) -> CkRv,
    /// `C_DecryptUpdate` slot (unsupported).
    pub C_DecryptUpdate:
        unsafe extern "C" fn(CkSessionHandle, CkBytePtr, CkUlong, CkBytePtr, CkUlongPtr) -> CkRv,
    /// `C_DecryptFinal` slot (unsupported).
    pub C_DecryptFinal: unsafe extern "C" fn(CkSessionHandle, CkBytePtr, CkUlongPtr) -> CkRv,
    /// `C_DigestInit` slot (unsupported).
    pub C_DigestInit: unsafe extern "C" fn(CkSessionHandle, CkMechanismPtr) -> CkRv,
    /// `C_Digest` slot (unsupported).
    pub C_Digest:
        unsafe extern "C" fn(CkSessionHandle, CkBytePtr, CkUlong, CkBytePtr, CkUlongPtr) -> CkRv,
    /// `C_DigestUpdate` slot (unsupported).
    pub C_DigestUpdate: unsafe extern "C" fn(CkSessionHandle, CkBytePtr, CkUlong) -> CkRv,
    /// `C_DigestKey` slot (unsupported).
    pub C_DigestKey: unsafe extern "C" fn(CkSessionHandle, CkObjectHandle) -> CkRv,
    /// `C_DigestFinal` slot (unsupported).
    pub C_DigestFinal: unsafe extern "C" fn(CkSessionHandle, CkBytePtr, CkUlongPtr) -> CkRv,
    /// `C_SignInit` slot.
    pub C_SignInit: unsafe extern "C" fn(CkSessionHandle, CkMechanismPtr, CkObjectHandle) -> CkRv,
    /// `C_Sign` slot.
    pub C_Sign:
        unsafe extern "C" fn(CkSessionHandle, CkBytePtr, CkUlong, CkBytePtr, CkUlongPtr) -> CkRv,
    /// `C_SignUpdate` slot (unsupported: single-part only).
    pub C_SignUpdate: unsafe extern "C" fn(CkSessionHandle, CkBytePtr, CkUlong) -> CkRv,
    /// `C_SignFinal` slot (unsupported: single-part only).
    pub C_SignFinal: unsafe extern "C" fn(CkSessionHandle, CkBytePtr, CkUlongPtr) -> CkRv,
    /// `C_SignRecoverInit` slot (unsupported).
    pub C_SignRecoverInit:
        unsafe extern "C" fn(CkSessionHandle, CkMechanismPtr, CkObjectHandle) -> CkRv,
    /// `C_SignRecover` slot (unsupported).
    pub C_SignRecover:
        unsafe extern "C" fn(CkSessionHandle, CkBytePtr, CkUlong, CkBytePtr, CkUlongPtr) -> CkRv,
    /// `C_VerifyInit` slot (unsupported).
    pub C_VerifyInit: unsafe extern "C" fn(CkSessionHandle, CkMechanismPtr, CkObjectHandle) -> CkRv,
    /// `C_Verify` slot (unsupported).
    pub C_Verify:
        unsafe extern "C" fn(CkSessionHandle, CkBytePtr, CkUlong, CkBytePtr, CkUlong) -> CkRv,
    /// `C_VerifyUpdate` slot (unsupported).
    pub C_VerifyUpdate: unsafe extern "C" fn(CkSessionHandle, CkBytePtr, CkUlong) -> CkRv,
    /// `C_VerifyFinal` slot (unsupported).
    pub C_VerifyFinal: unsafe extern "C" fn(CkSessionHandle, CkBytePtr, CkUlong) -> CkRv,
    /// `C_VerifyRecoverInit` slot (unsupported).
    pub C_VerifyRecoverInit:
        unsafe extern "C" fn(CkSessionHandle, CkMechanismPtr, CkObjectHandle) -> CkRv,
    /// `C_VerifyRecover` slot (unsupported).
    pub C_VerifyRecover:
        unsafe extern "C" fn(CkSessionHandle, CkBytePtr, CkUlong, CkBytePtr, CkUlongPtr) -> CkRv,
    /// `C_DigestEncryptUpdate` slot (unsupported).
    pub C_DigestEncryptUpdate:
        unsafe extern "C" fn(CkSessionHandle, CkBytePtr, CkUlong, CkBytePtr, CkUlongPtr) -> CkRv,
    /// `C_DecryptDigestUpdate` slot (unsupported).
    pub C_DecryptDigestUpdate:
        unsafe extern "C" fn(CkSessionHandle, CkBytePtr, CkUlong, CkBytePtr, CkUlongPtr) -> CkRv,
    /// `C_SignEncryptUpdate` slot (unsupported).
    pub C_SignEncryptUpdate:
        unsafe extern "C" fn(CkSessionHandle, CkBytePtr, CkUlong, CkBytePtr, CkUlongPtr) -> CkRv,
    /// `C_DecryptVerifyUpdate` slot (unsupported).
    pub C_DecryptVerifyUpdate:
        unsafe extern "C" fn(CkSessionHandle, CkBytePtr, CkUlong, CkBytePtr, CkUlongPtr) -> CkRv,
    /// `C_GenerateKey` slot (unsupported).
    pub C_GenerateKey: unsafe extern "C" fn(
        CkSessionHandle,
        CkMechanismPtr,
        CkAttributePtr,
        CkUlong,
        CkObjectHandlePtr,
    ) -> CkRv,
    /// `C_GenerateKeyPair` slot (unsupported).
    pub C_GenerateKeyPair: unsafe extern "C" fn(
        CkSessionHandle,
        CkMechanismPtr,
        CkAttributePtr,
        CkUlong,
        CkAttributePtr,
        CkUlong,
        CkObjectHandlePtr,
        CkObjectHandlePtr,
    ) -> CkRv,
    /// `C_WrapKey` slot (unsupported).
    pub C_WrapKey: unsafe extern "C" fn(
        CkSessionHandle,
        CkMechanismPtr,
        CkObjectHandle,
        CkObjectHandle,
        CkBytePtr,
        CkUlongPtr,
    ) -> CkRv,
    /// `C_UnwrapKey` slot (unsupported).
    pub C_UnwrapKey: unsafe extern "C" fn(
        CkSessionHandle,
        CkMechanismPtr,
        CkObjectHandle,
        CkBytePtr,
        CkUlong,
        CkAttributePtr,
        CkUlong,
        CkObjectHandlePtr,
    ) -> CkRv,
    /// `C_DeriveKey` slot (unsupported).
    pub C_DeriveKey: unsafe extern "C" fn(
        CkSessionHandle,
        CkMechanismPtr,
        CkObjectHandle,
        CkAttributePtr,
        CkUlong,
        CkObjectHandlePtr,
    ) -> CkRv,
    /// `C_SeedRandom` slot (unsupported).
    pub C_SeedRandom: unsafe extern "C" fn(CkSessionHandle, CkBytePtr, CkUlong) -> CkRv,
    /// `C_GenerateRandom` slot (unsupported).
    pub C_GenerateRandom: unsafe extern "C" fn(CkSessionHandle, CkBytePtr, CkUlong) -> CkRv,
    /// `C_GetFunctionStatus` slot (legacy; unsupported).
    pub C_GetFunctionStatus: unsafe extern "C" fn(CkSessionHandle) -> CkRv,
    /// `C_CancelFunction` slot (legacy; unsupported).
    pub C_CancelFunction: unsafe extern "C" fn(CkSessionHandle) -> CkRv,
    /// `C_WaitForSlotEvent` slot.
    pub C_WaitForSlotEvent: unsafe extern "C" fn(CkFlags, CkSlotIdPtr, CkVoidPtr) -> CkRv,
}

// ---- Boolean + sentinel constants ----

/// `CK_TRUE` (pkcs11t.h): the true value of a [`CkBbool`].
pub const CK_TRUE: CkBbool = 0x01;
/// `CK_FALSE` (pkcs11t.h): the false value of a [`CkBbool`].
pub const CK_FALSE: CkBbool = 0x00;
/// `CK_UNAVAILABLE_INFORMATION` (pkcs11t.h): `(~0UL)`, written into
/// `ulValueLen` when an attribute value cannot be revealed.
pub const CK_UNAVAILABLE_INFORMATION: CkUlong = CkUlong::MAX;
/// `CK_EFFECTIVELY_INFINITE` (pkcs11t.h): `0`, reported for an
/// unbounded token counter (e.g. max session count).
pub const CK_EFFECTIVELY_INFINITE: CkUlong = 0;
/// `CK_INVALID_HANDLE` (pkcs11t.h): `0`, the never-valid session /
/// object handle.
pub const CK_INVALID_HANDLE: CkUlong = 0;

// ---- Return values (CKR_*, pkcs11t.h) ----

/// `CKR_OK`: the call succeeded.
pub const CKR_OK: CkRv = 0x0000_0000;
/// `CKR_CANCEL`: the call was cancelled.
pub const CKR_CANCEL: CkRv = 0x0000_0001;
/// `CKR_HOST_MEMORY`: host out of memory.
pub const CKR_HOST_MEMORY: CkRv = 0x0000_0002;
/// `CKR_SLOT_ID_INVALID`: the slot id is not valid.
pub const CKR_SLOT_ID_INVALID: CkRv = 0x0000_0003;
/// `CKR_GENERAL_ERROR`: an unrecoverable error occurred.
pub const CKR_GENERAL_ERROR: CkRv = 0x0000_0005;
/// `CKR_FUNCTION_FAILED`: the function failed.
pub const CKR_FUNCTION_FAILED: CkRv = 0x0000_0006;
/// `CKR_ARGUMENTS_BAD`: bad arguments were supplied.
pub const CKR_ARGUMENTS_BAD: CkRv = 0x0000_0007;
/// `CKR_NO_EVENT`: no slot event pending (`C_WaitForSlotEvent`).
pub const CKR_NO_EVENT: CkRv = 0x0000_0008;
/// `CKR_ATTRIBUTE_SENSITIVE`: attribute value is sensitive.
pub const CKR_ATTRIBUTE_SENSITIVE: CkRv = 0x0000_0011;
/// `CKR_ATTRIBUTE_TYPE_INVALID`: object lacks the attribute type.
pub const CKR_ATTRIBUTE_TYPE_INVALID: CkRv = 0x0000_0012;
/// `CKR_ATTRIBUTE_VALUE_INVALID`: attribute value is invalid.
pub const CKR_ATTRIBUTE_VALUE_INVALID: CkRv = 0x0000_0013;
/// `CKR_DATA_INVALID`: input data is invalid.
pub const CKR_DATA_INVALID: CkRv = 0x0000_0020;
/// `CKR_DATA_LEN_RANGE`: input data length is out of range.
pub const CKR_DATA_LEN_RANGE: CkRv = 0x0000_0021;
/// `CKR_DEVICE_ERROR`: the token or reader errored.
pub const CKR_DEVICE_ERROR: CkRv = 0x0000_0030;
/// `CKR_DEVICE_REMOVED`: the token was removed mid-operation.
pub const CKR_DEVICE_REMOVED: CkRv = 0x0000_0032;
/// `CKR_FUNCTION_NOT_SUPPORTED`: the function is not implemented.
pub const CKR_FUNCTION_NOT_SUPPORTED: CkRv = 0x0000_0054;
/// `CKR_FUNCTION_NOT_PARALLEL`: v2.40 s11.16 return for the legacy
/// parallel-execution calls `C_GetFunctionStatus` / `C_CancelFunction`
/// (the spec mandates this exact value for both).
pub const CKR_FUNCTION_NOT_PARALLEL: CkRv = 0x0000_0055;
/// `CKR_KEY_HANDLE_INVALID`: the key handle is not valid.
pub const CKR_KEY_HANDLE_INVALID: CkRv = 0x0000_0060;
/// `CKR_OBJECT_HANDLE_INVALID`: the object handle is not valid.
pub const CKR_OBJECT_HANDLE_INVALID: CkRv = 0x0000_0082;
/// `CKR_KEY_TYPE_INCONSISTENT`: key type does not match mechanism.
pub const CKR_KEY_TYPE_INCONSISTENT: CkRv = 0x0000_0063;
/// `CKR_KEY_INDIGESTIBLE`: the key cannot be digested (`C_DigestKey`).
pub const CKR_KEY_INDIGESTIBLE: CkRv = 0x0000_0067;
/// `CKR_KEY_FUNCTION_NOT_PERMITTED`: key cannot perform the op.
pub const CKR_KEY_FUNCTION_NOT_PERMITTED: CkRv = 0x0000_0068;
/// `CKR_MECHANISM_INVALID`: the mechanism is not valid.
pub const CKR_MECHANISM_INVALID: CkRv = 0x0000_0070;
/// `CKR_MECHANISM_PARAM_INVALID`: the mechanism parameter is bad.
pub const CKR_MECHANISM_PARAM_INVALID: CkRv = 0x0000_0071;
/// `CKR_OPERATION_ACTIVE`: an operation is already active.
pub const CKR_OPERATION_ACTIVE: CkRv = 0x0000_0090;
/// `CKR_OPERATION_NOT_INITIALIZED`: no operation is active.
pub const CKR_OPERATION_NOT_INITIALIZED: CkRv = 0x0000_0091;
/// `CKR_PIN_INCORRECT`: the supplied PIN is incorrect.
pub const CKR_PIN_INCORRECT: CkRv = 0x0000_00A0;
/// `CKR_PIN_INVALID`: the supplied PIN has invalid characters.
pub const CKR_PIN_INVALID: CkRv = 0x0000_00A1;
/// `CKR_PIN_LEN_RANGE`: the supplied PIN length is out of range.
pub const CKR_PIN_LEN_RANGE: CkRv = 0x0000_00A2;
/// `CKR_PIN_LOCKED`: the PIN is locked (retry counter exhausted).
pub const CKR_PIN_LOCKED: CkRv = 0x0000_00A4;
/// `CKR_SESSION_CLOSED`: the session was closed mid-operation.
pub const CKR_SESSION_CLOSED: CkRv = 0x0000_00B0;
/// `CKR_SESSION_COUNT`: too many sessions open.
pub const CKR_SESSION_COUNT: CkRv = 0x0000_00B1;
/// `CKR_SESSION_HANDLE_INVALID`: the session handle is not valid.
pub const CKR_SESSION_HANDLE_INVALID: CkRv = 0x0000_00B3;
/// `CKR_SESSION_PARALLEL_NOT_SUPPORTED`: parallel sessions are not
/// supported; the caller omitted [`CKF_SERIAL_SESSION`].
pub const CKR_SESSION_PARALLEL_NOT_SUPPORTED: CkRv = 0x0000_00B4;
/// `CKR_SESSION_READ_ONLY`: the session is read-only.
pub const CKR_SESSION_READ_ONLY: CkRv = 0x0000_00B5;
/// `CKR_SIGNATURE_INVALID`: the signature is invalid.
pub const CKR_SIGNATURE_INVALID: CkRv = 0x0000_00C0;
/// `CKR_SIGNATURE_LEN_RANGE`: the signature length is wrong for
/// the mechanism/key.
pub const CKR_SIGNATURE_LEN_RANGE: CkRv = 0x0000_00C1;
/// `CKR_TOKEN_NOT_PRESENT`: no token is present in the slot.
pub const CKR_TOKEN_NOT_PRESENT: CkRv = 0x0000_00E0;
/// `CKR_TOKEN_WRITE_PROTECTED`: the operation needs a writable token
/// but the token is write-protected (`C_InitToken` here).
pub const CKR_TOKEN_WRITE_PROTECTED: CkRv = 0x0000_00E2;
/// `CKR_USER_ALREADY_LOGGED_IN`: a user is already logged in.
pub const CKR_USER_ALREADY_LOGGED_IN: CkRv = 0x0000_0100;
/// `CKR_USER_NOT_LOGGED_IN`: no user is logged in.
pub const CKR_USER_NOT_LOGGED_IN: CkRv = 0x0000_0101;
/// `CKR_USER_PIN_NOT_INITIALIZED`: the user PIN is not set.
pub const CKR_USER_PIN_NOT_INITIALIZED: CkRv = 0x0000_0102;
/// `CKR_USER_TYPE_INVALID`: the requested user type is not valid.
pub const CKR_USER_TYPE_INVALID: CkRv = 0x0000_0103;
/// `CKR_RANDOM_SEED_NOT_SUPPORTED`: the token's RNG accepts no
/// caller-supplied seed material (`C_SeedRandom`).
pub const CKR_RANDOM_SEED_NOT_SUPPORTED: CkRv = 0x0000_0120;
/// `CKR_BUFFER_TOO_SMALL`: the caller buffer is too small.
pub const CKR_BUFFER_TOO_SMALL: CkRv = 0x0000_0150;
/// `CKR_CRYPTOKI_NOT_INITIALIZED`: `C_Initialize` was not called.
pub const CKR_CRYPTOKI_NOT_INITIALIZED: CkRv = 0x0000_0190;
/// `CKR_CRYPTOKI_ALREADY_INITIALIZED`: `C_Initialize` already ran.
pub const CKR_CRYPTOKI_ALREADY_INITIALIZED: CkRv = 0x0000_0191;

// ---- Object classes (CKO_*), key + cert types ----

/// `CKO_CERTIFICATE`: object class for a certificate.
pub const CKO_CERTIFICATE: CkUlong = 0x0000_0001;
/// `CKO_PUBLIC_KEY`: object class for a public key.
pub const CKO_PUBLIC_KEY: CkUlong = 0x0000_0002;
/// `CKO_PRIVATE_KEY`: object class for a private key.
pub const CKO_PRIVATE_KEY: CkUlong = 0x0000_0003;
/// `CKC_X_509`: certificate type for an X.509 public-key cert.
pub const CKC_X_509: CkUlong = 0x0000_0000;
/// `CK_CERTIFICATE_CATEGORY` value `token user` (v2.40 s4.6.2 table
/// 24: 0 = unspecified, 1 = token user, 2 = authority, 3 = other
/// entity). The FINEID auth certificate belongs to the cardholder.
pub const CK_CERTIFICATE_CATEGORY_TOKEN_USER: CkUlong = 0x0000_0001;
/// `CK_CERTIFICATE_CATEGORY` value `authority` (v2.40 s4.6.2 table 24).
/// Used for CA certificates exposed by the token to build the certificate chain.
pub const CK_CERTIFICATE_CATEGORY_AUTHORITY: CkUlong = 0x0000_0002;
/// `CKK_RSA`: key type for an RSA key.
pub const CKK_RSA: CkUlong = 0x0000_0000;
/// `CKK_EC`: key type for an elliptic-curve key (aka `CKK_ECDSA`).
pub const CKK_EC: CkUlong = 0x0000_0003;

// ---- Attribute types (CKA_*) ----

/// `CKA_CLASS`: object class.
pub const CKA_CLASS: CkAttributeType = 0x0000_0000;
/// `CKA_TOKEN`: token-object flag.
pub const CKA_TOKEN: CkAttributeType = 0x0000_0001;
/// `CKA_PRIVATE`: private-object flag.
pub const CKA_PRIVATE: CkAttributeType = 0x0000_0002;
/// `CKA_LABEL`: human-readable label.
pub const CKA_LABEL: CkAttributeType = 0x0000_0003;
/// `CKA_VALUE`: object value (cert DER; sensitive on a key).
pub const CKA_VALUE: CkAttributeType = 0x0000_0011;
/// `CKA_CERTIFICATE_TYPE`: certificate type.
pub const CKA_CERTIFICATE_TYPE: CkAttributeType = 0x0000_0080;
/// `CKA_ISSUER`: certificate issuer DN (DER).
pub const CKA_ISSUER: CkAttributeType = 0x0000_0081;
/// `CKA_SERIAL_NUMBER`: certificate serial number (DER INTEGER).
pub const CKA_SERIAL_NUMBER: CkAttributeType = 0x0000_0082;
/// `CKA_TRUSTED`: the certificate / key is a trust anchor (false
/// here; the auth certificate is an end-entity credential).
pub const CKA_TRUSTED: CkAttributeType = 0x0000_0086;
/// `CKA_CERTIFICATE_CATEGORY`: certificate ownership category
/// ([`CK_CERTIFICATE_CATEGORY_TOKEN_USER`] here).
pub const CKA_CERTIFICATE_CATEGORY: CkAttributeType = 0x0000_0087;
/// `CKA_KEY_TYPE`: key type.
pub const CKA_KEY_TYPE: CkAttributeType = 0x0000_0100;
/// `CKA_SUBJECT`: certificate / key subject DN (DER).
pub const CKA_SUBJECT: CkAttributeType = 0x0000_0101;
/// `CKA_ID`: byte string pairing a cert with its key.
pub const CKA_ID: CkAttributeType = 0x0000_0102;
/// `CKA_SENSITIVE`: sensitive-value flag on a key.
pub const CKA_SENSITIVE: CkAttributeType = 0x0000_0103;
/// `CKA_ENCRYPT`: key-can-encrypt flag.
pub const CKA_ENCRYPT: CkAttributeType = 0x0000_0104;
/// `CKA_WRAP`: key-can-wrap flag.
pub const CKA_WRAP: CkAttributeType = 0x0000_0106;
/// `CKA_UNWRAP`: key-can-unwrap flag.
pub const CKA_UNWRAP: CkAttributeType = 0x0000_0107;
/// `CKA_SIGN`: key-can-sign flag.
pub const CKA_SIGN: CkAttributeType = 0x0000_0108;
/// `CKA_SIGN_RECOVER`: key-can-sign-with-recovery flag.
pub const CKA_SIGN_RECOVER: CkAttributeType = 0x0000_0109;
/// `CKA_VERIFY`: key-can-verify flag.
pub const CKA_VERIFY: CkAttributeType = 0x0000_010A;
/// `CKA_DERIVE`: key-supports-derivation flag.
pub const CKA_DERIVE: CkAttributeType = 0x0000_010C;
/// `CKA_MODULUS`: RSA modulus (big-endian magnitude).
pub const CKA_MODULUS: CkAttributeType = 0x0000_0120;
/// `CKA_MODULUS_BITS`: RSA modulus bit length.
pub const CKA_MODULUS_BITS: CkAttributeType = 0x0000_0121;
/// `CKA_PUBLIC_EXPONENT`: RSA public exponent (big-endian).
pub const CKA_PUBLIC_EXPONENT: CkAttributeType = 0x0000_0122;
/// `CKA_EXTRACTABLE`: the key can be extracted (false: FINEID
/// private keys never leave the card).
pub const CKA_EXTRACTABLE: CkAttributeType = 0x0000_0162;
/// `CKA_LOCAL`: the object was generated locally on the token.
pub const CKA_LOCAL: CkAttributeType = 0x0000_0163;
/// `CKA_NEVER_EXTRACTABLE`: the key has never been extractable.
pub const CKA_NEVER_EXTRACTABLE: CkAttributeType = 0x0000_0164;
/// `CKA_ALWAYS_SENSITIVE`: the key has always been sensitive.
pub const CKA_ALWAYS_SENSITIVE: CkAttributeType = 0x0000_0165;
/// `CKA_EC_PARAMS`: EC domain parameters (named-curve OID DER).
pub const CKA_EC_PARAMS: CkAttributeType = 0x0000_0180;
/// `CKA_EC_POINT`: EC public point (DER OCTET STRING of SEC1 point).
pub const CKA_EC_POINT: CkAttributeType = 0x0000_0181;
/// `CKA_ALWAYS_AUTHENTICATE`: per-op re-auth flag (false here).
pub const CKA_ALWAYS_AUTHENTICATE: CkAttributeType = 0x0000_0202;

// ---- Mechanism types (CKM_*) ----

/// `CKM_RSA_PKCS`: RSA PKCS#1 v1.5 sign/verify/encrypt.
pub const CKM_RSA_PKCS: CkMechanismType = 0x0000_0001;
/// `CKM_ECDSA`: raw ECDSA over a pre-computed digest.
pub const CKM_ECDSA: CkMechanismType = 0x0000_1041;

// ---- User + session state ----

/// `CKU_SO`: the security-officer user type (rejected here).
pub const CKU_SO: CkUserType = 0x0000_0000;
/// `CKU_USER`: the normal-user user type.
pub const CKU_USER: CkUserType = 0x0000_0001;
/// `CKS_RO_PUBLIC_SESSION`: read-only, no user logged in.
pub const CKS_RO_PUBLIC_SESSION: CkState = 0x0000_0000;
/// `CKS_RO_USER_FUNCTIONS`: read-only, normal user logged in.
pub const CKS_RO_USER_FUNCTIONS: CkState = 0x0000_0001;
/// `CKS_RW_PUBLIC_SESSION`: read/write, no user logged in.
pub const CKS_RW_PUBLIC_SESSION: CkState = 0x0000_0002;
/// `CKS_RW_USER_FUNCTIONS`: read/write, normal user logged in.
pub const CKS_RW_USER_FUNCTIONS: CkState = 0x0000_0003;

// ---- Flag bits (CKF_*) ----

/// `CKF_TOKEN_PRESENT`: a token is present in the slot.
pub const CKF_TOKEN_PRESENT: CkFlags = 0x0000_0001;
/// `CKF_REMOVABLE_DEVICE`: the reader accepts removable tokens.
pub const CKF_REMOVABLE_DEVICE: CkFlags = 0x0000_0002;
/// `CKF_HW_SLOT`: the slot is a hardware slot.
pub const CKF_HW_SLOT: CkFlags = 0x0000_0004;
/// `CKF_WRITE_PROTECTED`: the token is write-protected.
pub const CKF_WRITE_PROTECTED: CkFlags = 0x0000_0002;
/// `CKF_LOGIN_REQUIRED`: login is required before private ops.
pub const CKF_LOGIN_REQUIRED: CkFlags = 0x0000_0004;
/// `CKF_USER_PIN_INITIALIZED`: the user PIN is initialised.
pub const CKF_USER_PIN_INITIALIZED: CkFlags = 0x0000_0008;
/// `CKF_USER_PIN_COUNT_LOW`: at least one user-PIN attempt has failed.
pub const CKF_USER_PIN_COUNT_LOW: CkFlags = 0x0001_0000;
/// `CKF_USER_PIN_FINAL_TRY`: one wrong user-PIN attempt will lock it.
pub const CKF_USER_PIN_FINAL_TRY: CkFlags = 0x0002_0000;
/// `CKF_USER_PIN_LOCKED`: user login is not possible until PIN recovery.
pub const CKF_USER_PIN_LOCKED: CkFlags = 0x0004_0000;
/// `CKF_TOKEN_INITIALIZED`: the token is initialised.
pub const CKF_TOKEN_INITIALIZED: CkFlags = 0x0000_0400;
/// `CKF_RW_SESSION`: the session is read/write.
pub const CKF_RW_SESSION: CkFlags = 0x0000_0002;
/// `CKF_SERIAL_SESSION`: the session is serial (always set).
pub const CKF_SERIAL_SESSION: CkFlags = 0x0000_0004;
/// `CKF_HW`: the mechanism is performed by hardware.
pub const CKF_HW: CkFlags = 0x0000_0001;
/// `CKF_SIGN`: the mechanism can sign.
pub const CKF_SIGN: CkFlags = 0x0000_0800;
/// `CKF_EC_F_P`: the EC mechanism supports prime-field curves
/// (v2.40 s11.7; secp384r1 is `F_p`).
pub const CKF_EC_F_P: CkFlags = 0x0010_0000;
/// `CKF_EC_NAMEDCURVE`: the EC mechanism accepts named-curve
/// [`CKA_EC_PARAMS`] (the only form this module emits).
pub const CKF_EC_NAMEDCURVE: CkFlags = 0x0080_0000;
/// `CKF_EC_UNCOMPRESS`: the EC mechanism handles uncompressed
/// points (the SEC1 form in [`CKA_EC_POINT`] here).
pub const CKF_EC_UNCOMPRESS: CkFlags = 0x0100_0000;
/// `CKF_OS_LOCKING_OK`: the caller permits OS-native locking.
pub const CKF_OS_LOCKING_OK: CkFlags = 0x0000_0002;
/// `CKF_LIBRARY_CANT_CREATE_OS_THREADS`: the caller forbids the
/// library from spawning OS threads (we never do).
pub const CKF_LIBRARY_CANT_CREATE_OS_THREADS: CkFlags = 0x0000_0001;
/// `CKF_DONT_BLOCK`: `C_WaitForSlotEvent` must not block.
pub const CKF_DONT_BLOCK: CkFlags = 0x0000_0001;
