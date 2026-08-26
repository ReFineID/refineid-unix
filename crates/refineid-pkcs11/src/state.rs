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

//! Module and session state.
//!
//! One process-global [`MODULE`] holds the live [`ModuleState`]
//! between `C_Initialize` and `C_Finalize`: the stable slot table,
//! open sessions, the per-token PIN1 login state, and the cached
//! token objects. All access is serialised by a [`Mutex`]; the module
//! advertises Rust-side locking, so it accepts both a NULL
//! `C_Initialize` arg and `CKF_OS_LOCKING_OK`.
//!
//! PIN1 secrecy: the login secret lives only in [`PinSafetyCache`] here,
//! is never logged or rendered, and is dropped (zeroized by
//! `PinBytes`) on `C_Logout`, `C_CloseSession` of the last session,
//! card removal, and `C_Finalize`.

use alloc::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use refineid_lib_core::backend::{ReaderAccessCap, ReaderBackend as _, ReaderId};
use refineid_lib_core::pin_cache::PinSafetyCache;
use refineid_lib_core::pkcs15::{Pkcs15Error, Pkcs15Ops as _};
use refineid_lib_pcsc::{PcscBackend, ReaderIdentity, read_reader_identity};

use crate::ck::{
    CKF_RW_SESSION, CKR_DEVICE_ERROR, CKS_RO_PUBLIC_SESSION, CKS_RO_USER_FUNCTIONS,
    CKS_RW_PUBLIC_SESSION, CKS_RW_USER_FUNCTIONS, CkFlags, CkObjectHandle, CkRv, CkSessionHandle,
    CkSlotId, CkState,
};
use crate::sign::Mechanism;
use crate::token::{TokenObjects, build_token_objects};

/// First slot id handed out. Slot ids are stable per reader name for
/// the process lifetime; starting at 1 keeps 0 (a common "invalid"
/// sentinel in caller code) out of the slot-id space.
const SLOT_ID_BASE: CkSlotId = 1;
/// First session handle handed out. 0 is
/// [`crate::ck::CK_INVALID_HANDLE`] and must never be a live handle.
const SESSION_HANDLE_BASE: CkSessionHandle = 1;
/// PIN1 minimum length in ASCII digits accepted by `C_Login`
/// (DVV FINEID PIN1 policy).
pub const PIN1_MIN_DIGITS: usize = 4;
/// PIN1 maximum length in ASCII digits accepted by `C_Login`
/// (DVV FINEID PIN1 policy).
pub const PIN1_MAX_DIGITS: usize = 12;

/// The process-global module state, `Some` between `C_Initialize` and
/// `C_Finalize`. [`Mutex::new`] is `const`, so this needs no lazy
/// initialiser.
pub static MODULE: Mutex<Option<ModuleState>> = Mutex::new(None);

/// Per-reader rejection memory survives PKCS#11 finalize/reinitialize for
/// the lifetime of the hosting process. Finalize clears positive secrets.
static PROCESS_PIN_CACHES: Mutex<BTreeMap<String, Arc<Mutex<PinSafetyCache>>>> =
    Mutex::new(BTreeMap::new());

/// One PKCS#11 slot, bound to a PC/SC reader by name.
#[derive(Debug, Clone)]
pub struct SlotRecord {
    /// Stable slot id for this reader for the process lifetime.
    id: CkSlotId,
    /// PC/SC reader name backing the slot.
    reader_name: String,
    /// Whether a validated FINEID card was present at the last
    /// slot-table refresh.
    card_present: bool,
    /// The reader's own vendor / IFD-version attributes, read once
    /// when the slot is first seen (direct-mode, card-less).
    /// Reported in `CK_SLOT_INFO`: the slot describes the physical
    /// reader, not this module.
    reader_identity: ReaderIdentity,
}

impl SlotRecord {
    /// The PC/SC reader name backing this slot.
    pub(crate) fn reader_name(&self) -> &str {
        &self.reader_name
    }

    /// Whether a card was present at the last slot-table refresh.
    pub(crate) const fn card_present(&self) -> bool {
        self.card_present
    }

    /// The reader's driver-reported identity attributes.
    pub(crate) const fn reader_identity(&self) -> &ReaderIdentity {
        &self.reader_identity
    }
}

/// An in-progress `C_FindObjects` operation on a session: the object
/// handles still to be returned.
#[derive(Debug, Clone, Default)]
pub struct FindState {
    /// Handles matching the active template not yet returned to the
    /// caller.
    remaining: Vec<CkObjectHandle>,
}

/// An in-progress `C_Sign` operation on a session.
#[derive(Debug, Clone, Copy)]
pub struct SignState {
    /// The mechanism selected at `C_SignInit`.
    mechanism: Mechanism,
}

impl SignState {
    /// The mechanism selected at `C_SignInit`.
    pub(crate) const fn mechanism(self) -> Mechanism {
        self.mechanism
    }
}

/// One open session on a slot.
#[derive(Debug, Clone, Default)]
pub struct Session {
    /// The slot this session belongs to.
    slot_id: CkSlotId,
    /// Session flags as passed to `C_OpenSession`.
    flags: CkFlags,
    /// Active find operation, if `C_FindObjectsInit` has run.
    find: Option<FindState>,
    /// Active sign operation, if `C_SignInit` has run.
    sign: Option<SignState>,
    /// Active software verify operation, if `C_VerifyInit` has
    /// run. Independent of `sign` per v2.40 (one active
    /// operation per category).
    verify: Option<SignState>,
}

impl Session {
    /// The slot this session belongs to.
    pub(crate) const fn slot_id(&self) -> CkSlotId {
        self.slot_id
    }

    /// The session flags passed to `C_OpenSession`.
    pub(crate) const fn flags(&self) -> CkFlags {
        self.flags
    }

    /// The active sign operation, if any.
    pub(crate) const fn sign_state(&self) -> Option<SignState> {
        self.sign
    }

    /// Whether a sign operation is already active on this session.
    pub(crate) const fn has_active_sign(&self) -> bool {
        self.sign.is_some()
    }

    /// Begin a find operation with the given matching handles.
    pub(crate) fn begin_find(&mut self, handles: Vec<CkObjectHandle>) {
        self.find = Some(FindState { remaining: handles });
    }

    /// Return the next batch of up to `max` find handles, or `None`
    /// when no find operation is active.
    pub(crate) fn next_find_batch(&mut self, max: usize) -> Option<Vec<CkObjectHandle>> {
        let find = self.find.as_mut()?;
        let wanted = max.min(find.remaining.len());
        Some(find.remaining.drain(..wanted).collect())
    }

    /// End the active find operation, reporting whether one was
    /// active.
    pub(crate) fn take_find(&mut self) -> bool {
        self.find.take().is_some()
    }

    /// Begin a sign operation with the given mechanism.
    pub(crate) fn begin_sign(&mut self, mechanism: Mechanism) {
        self.sign = Some(SignState { mechanism });
    }

    /// Clear any active sign operation.
    pub(crate) fn clear_sign(&mut self) {
        self.sign = None;
    }

    /// The active verify operation, if any.
    pub(crate) const fn verify_state(&self) -> Option<SignState> {
        self.verify
    }

    /// Whether a verify operation is already active on this session.
    pub(crate) const fn has_active_verify(&self) -> bool {
        self.verify.is_some()
    }

    /// Begin a verify operation with the given mechanism.
    pub(crate) fn begin_verify(&mut self, mechanism: Mechanism) {
        self.verify = Some(SignState { mechanism });
    }

    /// Clear any active verify operation.
    pub(crate) fn clear_verify(&mut self) {
        self.verify = None;
    }
}

/// Live module state between `C_Initialize` and `C_Finalize`.
#[derive(Debug)]
pub struct ModuleState {
    /// Stable slot table; entries are appended, never removed, so
    /// slot ids stay stable per reader for the process lifetime.
    slots: Vec<SlotRecord>,
    /// Next slot id to assign to a newly-seen reader.
    next_slot_id: CkSlotId,
    /// Open sessions keyed by handle.
    sessions: BTreeMap<CkSessionHandle, Session>,
    /// Next session handle to assign.
    next_session_handle: CkSessionHandle,
    /// Per-slot five-minute positive PIN1 state plus process-lifetime
    /// rejection memory. Entries survive logout/removal so rejection
    /// fingerprints cannot be bypassed without restarting the process.
    pin_caches: BTreeMap<CkSlotId, Arc<Mutex<PinSafetyCache>>>,
    /// Cached token objects per slot while the same card stays
    /// present.
    token_cache: BTreeMap<CkSlotId, TokenObjects>,
    /// Per-slot card presence as last reported through
    /// `C_WaitForSlotEvent`. Absent entry = never reported, so a
    /// slot's first sighting counts as an event (the caller has
    /// not seen it yet).
    event_reported: BTreeMap<CkSlotId, bool>,
}

impl ModuleState {
    /// Build empty module state with an initial slot-table refresh.
    ///
    /// # Errors
    /// [`CKR_DEVICE_ERROR`] if the reader backend cannot be queried.
    pub(crate) fn new() -> Result<Self, CkRv> {
        let mut state = Self {
            slots: Vec::new(),
            next_slot_id: SLOT_ID_BASE,
            sessions: BTreeMap::new(),
            next_session_handle: SESSION_HANDLE_BASE,
            pin_caches: BTreeMap::new(),
            token_cache: BTreeMap::new(),
            event_reported: BTreeMap::new(),
        };
        state.refresh_slots()?;
        Ok(state)
    }

    /// Re-enumerate readers, appending readers only after their
    /// inserted card proves that it is FINEID and updating FINEID-card
    /// presence. When a card leaves a slot, its cached objects and
    /// login state are dropped.
    ///
    /// Proof of FINEID has two stages. Answering the PKCS#15 AID
    /// SELECT ([`probe_fineid_card`]) is the cheap steady-state
    /// check, but it is not sufficient: an unrelated token could
    /// answer that SELECT and still surface as a slot to NSS. A card
    /// TRANSITIONING into presence must additionally yield a
    /// parseable authentication certificate
    /// ([`build_token_objects`]) -- the same bar the CLI reader
    /// picker sets -- and the parsed objects are cached for the new
    /// slot, so the stronger proof costs nothing extra
    /// ([`Self::ensure_token`] needed them anyway). A transient read
    /// failure on a genuine card self-heals on the next refresh
    /// (the transition re-runs until the proof succeeds).
    ///
    /// # Errors
    /// [`CKR_DEVICE_ERROR`] if the reader backend cannot be queried.
    pub(crate) fn refresh_slots(&mut self) -> Result<(), CkRv> {
        self.refresh_slots_with(&PcscProber)
    }

    /// [`Self::refresh_slots`] over an injected [`SlotProber`], so
    /// the admission logic (AID probe + cert-proven transition) is
    /// testable without PC/SC hardware.
    fn refresh_slots_with(&mut self, prober: &impl SlotProber) -> Result<(), CkRv> {
        let readers = match prober.enumerate() {
            Ok(readers) => readers,
            Err(error) => {
                self.clear_all_positive_pins();
                return Err(error);
            }
        };
        for reader in readers {
            let name = reader.id.as_str();
            let observation = if reader.card_present {
                prober.probe(&reader.id)
            } else {
                FineidCardObservation::Absent
            };
            if observation.preserves_last_known_state() {
                // Another process can temporarily own the PC/SC reader.
                // That is not evidence that the card changed or left.
                continue;
            }
            let aid_present = matches!(observation, FineidCardObservation::Present);
            if let Some(pos) = self.slots.iter().position(|s| s.reader_name == name) {
                let (id, was_present) = match self.slots.get(pos) {
                    Some(slot) => (slot.id, slot.card_present),
                    None => continue,
                };
                if aid_present && !was_present {
                    // Transition into presence: demand the
                    // cert-proven objects before the slot reports a
                    // token.
                    let Ok(objects) = prober.build_objects(name) else {
                        continue;
                    };
                    if let Some(slot) = self.slots.get_mut(pos) {
                        slot.card_present = true;
                    }
                    self.invalidate_slot(id);
                    self.token_cache.insert(id, objects);
                } else if was_present && !aid_present {
                    if let Some(slot) = self.slots.get_mut(pos) {
                        slot.card_present = false;
                    }
                    self.invalidate_slot(id);
                }
            } else if aid_present {
                // New reader with a card: same cert-proven bar
                // before a slot exists at all.
                let Ok(objects) = prober.build_objects(name) else {
                    continue;
                };
                let id = self.next_slot_id;
                self.next_slot_id = self.next_slot_id.saturating_add(1);
                self.slots.push(SlotRecord {
                    id,
                    reader_name: name.to_owned(),
                    card_present: true,
                    reader_identity: prober.reader_identity(&reader.id),
                });
                self.token_cache.insert(id, objects);
            }
        }

        // Discover paired remote RAPP mobile readers (iPhone/Android)
        let vault = refineid_lib_core::rapp::RappDeviceVault::new_default();
        if let Ok(pairs) = vault.active_pairs() {
            for pair in pairs {
                let name = format!(
                    "rapp:{}",
                    refineid_lib_core::hex::Hex::encode(&pair.pair_id)
                );
                let card_present = true;
                if let Some(pos) = self.slots.iter().position(|s| s.reader_name == name) {
                    if let Some(slot) = self.slots.get_mut(pos) {
                        slot.card_present = card_present;
                    }
                    if let Some(ref cert) = pair.cached_auth_cert
                        && let Ok(objects) = TokenObjects::from_cert_der(cert.clone())
                    {
                        let id = self.slots[pos].id;
                        self.token_cache.insert(id, objects);
                    }
                } else {
                    let id = self.next_slot_id;
                    self.next_slot_id = self.next_slot_id.saturating_add(1);
                    let product_name = pair.display_name.as_deref().unwrap_or("Phone");
                    self.slots.push(SlotRecord {
                        id,
                        reader_name: name,
                        card_present,
                        reader_identity: ReaderIdentity {
                            vendor_name: Some(format!("ReFineID Remote ({product_name})")),
                            ifd_version: None,
                        },
                    });
                    if let Some(ref cert) = pair.cached_auth_cert
                        && let Ok(objects) = TokenObjects::from_cert_der(cert.clone())
                    {
                        self.token_cache.insert(id, objects);
                    }
                }
            }
        }
        Ok(())
    }

    /// Drop cached objects and PIN1 login for a slot (on card
    /// removal). Zeroizes the PIN1 secret via `PinBytes`'s drop.
    fn invalidate_slot(&mut self, slot_id: CkSlotId) {
        self.token_cache.remove(&slot_id);
        if let Some(cache) = self.pin_caches.get(&slot_id)
            && let Ok(mut cache) = cache.lock()
        {
            cache.clear_positive();
        }
    }

    /// All slot ids in assignment order.
    #[must_use]
    pub(crate) fn slot_ids(&self) -> Vec<CkSlotId> {
        self.slots.iter().map(|s| s.id).collect()
    }

    /// Slot record for `id`, if it exists.
    #[must_use]
    pub(crate) fn slot(&self, id: CkSlotId) -> Option<&SlotRecord> {
        self.slots.iter().find(|s| s.id == id)
    }

    /// Reader name backing `slot_id`, if the slot exists.
    #[must_use]
    pub(crate) fn reader_name(&self, slot_id: CkSlotId) -> Option<String> {
        self.slot(slot_id).map(|s| s.reader_name.clone())
    }

    /// Open a new session on `slot_id` and return its handle.
    pub(crate) fn open_session(&mut self, slot_id: CkSlotId, flags: CkFlags) -> CkSessionHandle {
        let handle = self.next_session_handle;
        self.next_session_handle = self.next_session_handle.saturating_add(1);
        self.sessions.insert(
            handle,
            Session {
                slot_id,
                flags,
                find: None,
                sign: None,
                verify: None,
            },
        );
        handle
    }

    /// Borrow a session by handle.
    #[must_use]
    pub(crate) fn session(&self, handle: CkSessionHandle) -> Option<&Session> {
        self.sessions.get(&handle)
    }

    /// Mutably borrow a session by handle.
    pub(crate) fn session_mut(&mut self, handle: CkSessionHandle) -> Option<&mut Session> {
        self.sessions.get_mut(&handle)
    }

    /// Close one session. Returns `false` if the handle was unknown.
    /// When a slot loses its last session, its PIN1 login is dropped.
    pub(crate) fn close_session(&mut self, handle: CkSessionHandle) -> bool {
        let Some(session) = self.sessions.remove(&handle) else {
            return false;
        };
        self.forget_login_if_no_sessions(session.slot_id);
        true
    }

    /// Close every session on `slot_id` and drop that slot's PIN1
    /// login.
    pub(crate) fn close_all_sessions(&mut self, slot_id: CkSlotId) {
        self.sessions
            .retain(|_handle, session| session.slot_id != slot_id);
        self.logout(slot_id);
    }

    /// Drop a slot's PIN1 login once no sessions remain on it (per
    /// PKCS#11 the token login state ends when the last session
    /// closes).
    fn forget_login_if_no_sessions(&self, slot_id: CkSlotId) {
        let still_open = self
            .sessions
            .values()
            .any(|session| session.slot_id == slot_id);
        if !still_open {
            self.logout(slot_id);
        }
    }

    /// Return the process-lifetime safety cache for a slot, creating it
    /// before card I/O when needed.
    pub(crate) fn pin_cache(
        &mut self,
        slot_id: CkSlotId,
    ) -> Result<Arc<Mutex<PinSafetyCache>>, CkRv> {
        if let Some(cache) = self.pin_caches.get(&slot_id) {
            return Ok(Arc::clone(cache));
        }
        let reader_name = self.reader_name(slot_id).ok_or(CKR_DEVICE_ERROR)?;
        let mut process_caches = PROCESS_PIN_CACHES.lock().map_err(|_| CKR_DEVICE_ERROR)?;
        let cache = if let Some(cache) = process_caches.get(&reader_name) {
            Arc::clone(cache)
        } else {
            let cache = Arc::new(Mutex::new(
                PinSafetyCache::new().map_err(|_| CKR_DEVICE_ERROR)?,
            ));
            process_caches.insert(reader_name, Arc::clone(&cache));
            cache
        };
        drop(process_caches);
        self.pin_caches.insert(slot_id, Arc::clone(&cache));
        Ok(cache)
    }

    /// Drop a slot's PIN1 login state (`C_Logout`).
    pub(crate) fn logout(&self, slot_id: CkSlotId) {
        if let Some(cache) = self.pin_caches.get(&slot_id)
            && let Ok(mut cache) = cache.lock()
        {
            cache.clear_positive();
        }
    }

    /// Whether a user is logged in on `slot_id`.
    #[must_use]
    pub(crate) fn is_logged_in(&self, slot_id: CkSlotId) -> bool {
        self.pin_caches.get(&slot_id).is_some_and(|cache| {
            cache
                .lock()
                .is_ok_and(|mut cache| cache.has_positive_pin1())
        })
    }

    /// Report the next pending slot event: the first slot whose
    /// card presence differs from what `C_WaitForSlotEvent` last
    /// reported. Consumes the event (the snapshot is updated), so
    /// each change is reported exactly once. A slot never reported
    /// before counts as an event on first sighting.
    ///
    /// The caller refreshes the slot table first; this method is
    /// pure bookkeeping so it stays testable without hardware.
    pub(crate) fn take_slot_event(&mut self) -> Option<CkSlotId> {
        for slot in &self.slots {
            let last = self.event_reported.get(&slot.id).copied();
            if last != Some(slot.card_present) {
                self.event_reported.insert(slot.id, slot.card_present);
                return Some(slot.id);
            }
        }
        None
    }

    pub(crate) fn clear_all_positive_pins(&self) {
        for cache in self.pin_caches.values() {
            if let Ok(mut cache) = cache.lock() {
                cache.clear_positive();
            }
        }
    }

    /// Return the cached token objects for `slot_id`, building and
    /// caching them from the card on first need.
    ///
    /// # Errors
    /// [`CKR_DEVICE_ERROR`] if the slot is unknown or the card read /
    /// parse fails.
    pub(crate) fn ensure_token(&mut self, slot_id: CkSlotId) -> Result<TokenObjects, CkRv> {
        if let Some(cached) = self.token_cache.get(&slot_id) {
            return Ok(cached.clone());
        }
        let reader_name = self.reader_name(slot_id).ok_or(CKR_DEVICE_ERROR)?;
        if let Some(hex_id) = reader_name.strip_prefix("rapp:") {
            let vault = refineid_lib_core::rapp::RappDeviceVault::new_default();
            let pairs = vault.active_pairs().map_err(|_| CKR_DEVICE_ERROR)?;
            let pair = pairs
                .into_iter()
                .find(|p| refineid_lib_core::hex::Hex::encode(&p.pair_id) == hex_id)
                .ok_or(CKR_DEVICE_ERROR)?;

            let cert_der = if let Some(ref cert) = pair.cached_auth_cert {
                cert.clone()
            } else {
                let op = refineid_lib_core::rapp::CardOperation::ReadCertificate {
                    kind: "authentication".into(),
                };
                let res = refineid_lib_core::rapp::execute_operation_with_pair(&pair, &op)
                    .map_err(|_| CKR_DEVICE_ERROR)?;
                match res {
                    refineid_lib_core::rapp::CardOperationResult::Certificate {
                        der_bytes, ..
                    } => {
                        let _ = vault.update_cached_auth_cert(&pair.pair_id, &der_bytes);
                        der_bytes
                    }
                    _ => return Err(CKR_DEVICE_ERROR),
                }
            };

            let objects = TokenObjects::from_cert_der(cert_der)?;
            self.token_cache.insert(slot_id, objects.clone());
            return Ok(objects);
        }
        let objects = build_token_objects(&reader_name)?;
        self.token_cache.insert(slot_id, objects.clone());
        Ok(objects)
    }

    /// The number of open sessions (used by tests / diagnostics).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Test-only constructor that injects a fixed slot table so the
    /// session / slot bookkeeping can be exercised without hardware.
    #[cfg(test)]
    pub(crate) fn from_parts_for_test(slots: Vec<SlotRecord>, next_slot_id: CkSlotId) -> Self {
        Self {
            slots,
            next_slot_id,
            sessions: BTreeMap::new(),
            next_session_handle: SESSION_HANDLE_BASE,
            pin_caches: BTreeMap::new(),
            token_cache: BTreeMap::new(),
            event_reported: BTreeMap::new(),
        }
    }
}

/// Probe a card-present reader for the FINEID PKCS#15 application.
///
/// The module owns only FINEID tokens. A card-present reader can host an
/// unrelated token such as a `YubiKey`, which must never appear under the
/// `ReFineID` NSS module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FineidCardObservation {
    Present,
    Absent,
    TemporarilyUnavailable,
}

impl FineidCardObservation {
    const fn preserves_last_known_state(self) -> bool {
        matches!(self, Self::TemporarilyUnavailable)
    }
}

fn probe_fineid_card(reader: &ReaderId) -> FineidCardObservation {
    let backend = PcscBackend;
    let Ok(mut card) = backend.open_session(reader, ReaderAccessCap::Read) else {
        return FineidCardObservation::TemporarilyUnavailable;
    };
    match card.select_pkcs15_application() {
        Ok(()) => FineidCardObservation::Present,
        Err(Pkcs15Error::Transport(_)) => FineidCardObservation::TemporarilyUnavailable,
        Err(
            Pkcs15Error::Sw(_)
            | Pkcs15Error::Aid(_)
            | Pkcs15Error::Empty
            | Pkcs15Error::TooLarge
            | Pkcs15Error::InvalidData(_),
        ) => FineidCardObservation::Absent,
    }
}

/// Seam over the hardware probes [`ModuleState::refresh_slots`]
/// drives, so the slot-admission logic (AID probe + cert-proven
/// transition) is testable without a PC/SC stack. Production is
/// [`PcscProber`]; tests script the answers.
trait SlotProber {
    /// Enumerate readers with their raw card-present flags.
    fn enumerate(&self) -> Result<Vec<refineid_lib_core::backend::ReaderInfo>, CkRv>;
    /// Cheap FINEID probe: does the inserted card answer the
    /// PKCS#15 AID SELECT?
    fn probe(&self, reader: &ReaderId) -> FineidCardObservation;
    /// Strong FINEID proof: read and parse the token objects
    /// (EF.TokenInfo + authentication certificate).
    fn build_objects(&self, reader_name: &str) -> Result<TokenObjects, CkRv>;
    /// The reader's own driver-reported identity attributes.
    fn reader_identity(&self, reader: &ReaderId) -> ReaderIdentity;
}

/// Production [`SlotProber`] over the live PC/SC stack.
struct PcscProber;

impl SlotProber for PcscProber {
    fn enumerate(&self) -> Result<Vec<refineid_lib_core::backend::ReaderInfo>, CkRv> {
        PcscBackend
            .enumerate()
            .map_err(|_enum_err| CKR_DEVICE_ERROR)
    }

    fn probe(&self, reader: &ReaderId) -> FineidCardObservation {
        probe_fineid_card(reader)
    }

    fn build_objects(&self, reader_name: &str) -> Result<TokenObjects, CkRv> {
        build_token_objects(reader_name)
    }

    fn reader_identity(&self, reader: &ReaderId) -> ReaderIdentity {
        read_reader_identity(reader)
    }
}

/// Derive the PKCS#11 session state ([`CkState`]) from the session's
/// read/write flag and the token's login state.
#[must_use]
pub fn session_state(flags: CkFlags, logged_in: bool) -> CkState {
    let read_write = flags & CKF_RW_SESSION != 0;
    match (read_write, logged_in) {
        (false, false) => CKS_RO_PUBLIC_SESSION,
        (false, true) => CKS_RO_USER_FUNCTIONS,
        (true, false) => CKS_RW_PUBLIC_SESSION,
        (true, true) => CKS_RW_USER_FUNCTIONS,
    }
}

#[cfg(test)]
mod tests {
    use super::{FineidCardObservation, ModuleState, ReaderIdentity, SlotRecord, session_state};
    use crate::ck::{
        CKF_RW_SESSION, CKF_SERIAL_SESSION, CKS_RO_PUBLIC_SESSION, CKS_RO_USER_FUNCTIONS,
        CKS_RW_USER_FUNCTIONS, CkSlotId,
    };
    use refineid_lib_core::pin::PinBytes;

    /// Build module state without touching hardware by injecting a
    /// fixed slot table.
    fn state_with_slots(names: &[&str]) -> ModuleState {
        let mut slots = Vec::new();
        let mut next: CkSlotId = 1;
        for name in names {
            slots.push(SlotRecord {
                id: next,
                reader_name: (*name).to_owned(),
                card_present: true,
                reader_identity: ReaderIdentity::default(),
            });
            next = next.saturating_add(1);
        }
        ModuleState::from_parts_for_test(slots, next)
    }

    #[test]
    fn slot_ids_are_stable_and_ordered() {
        let state = state_with_slots(&["Reader A", "Reader B"]);
        assert_eq!(state.slot_ids(), vec![1, 2]);
        assert_eq!(state.reader_name(1).as_deref(), Some("Reader A"));
        assert_eq!(state.reader_name(2).as_deref(), Some("Reader B"));
    }

    #[test]
    fn sessions_open_and_close() {
        let mut state = state_with_slots(&["Reader A"]);
        let handle = state.open_session(1, CKF_SERIAL_SESSION);
        assert_eq!(state.session_count(), 1);
        assert!(state.session(handle).is_some());
        assert!(state.close_session(handle));
        assert_eq!(state.session_count(), 0);
        assert!(!state.close_session(handle));
    }

    #[test]
    fn session_state_mapping() {
        assert_eq!(
            session_state(CKF_SERIAL_SESSION, false),
            CKS_RO_PUBLIC_SESSION
        );
        assert_eq!(
            session_state(CKF_SERIAL_SESSION, true),
            CKS_RO_USER_FUNCTIONS
        );
        assert_eq!(
            session_state(CKF_SERIAL_SESSION | CKF_RW_SESSION, true),
            CKS_RW_USER_FUNCTIONS
        );
    }

    #[test]
    fn temporary_reader_contention_is_not_a_card_state_change() {
        assert!(FineidCardObservation::TemporarilyUnavailable.preserves_last_known_state());
        assert!(!FineidCardObservation::Absent.preserves_last_known_state());
        assert!(!FineidCardObservation::Present.preserves_last_known_state());
    }

    /// Scripted [`SlotProber`]: one card-present reader whose
    /// probe / object-build answers are fixed by the test.
    struct ScriptedProber {
        observation: FineidCardObservation,
        objects_ok: bool,
    }

    impl super::SlotProber for ScriptedProber {
        fn enumerate(&self) -> Result<Vec<refineid_lib_core::backend::ReaderInfo>, super::CkRv> {
            Ok(vec![refineid_lib_core::backend::ReaderInfo {
                id: refineid_lib_core::backend::ReaderId::new("Scripted Reader".to_owned()),
                card_present: true,
            }])
        }

        fn probe(&self, _reader: &refineid_lib_core::backend::ReaderId) -> FineidCardObservation {
            self.observation
        }

        fn build_objects(
            &self,
            _reader_name: &str,
        ) -> Result<crate::token::TokenObjects, super::CkRv> {
            // A scripted prober cannot mint real TokenObjects (they
            // parse a certificate); the tests below only exercise
            // REFUSAL paths, so `objects_ok` must stay false.
            assert!(
                !self.objects_ok,
                "scripted prober cannot produce TokenObjects"
            );
            Err(crate::ck::CKR_DEVICE_ERROR)
        }

        fn reader_identity(
            &self,
            _reader: &refineid_lib_core::backend::ReaderId,
        ) -> ReaderIdentity {
            ReaderIdentity::default()
        }
    }

    /// A card that refuses the PKCS#15 AID SELECT (a `YubiKey` in
    /// CCID mode, any non-FINEID smartcard) must never surface as
    /// a slot to NSS.
    #[test]
    fn select_refusing_card_yields_no_slot() {
        let mut state = ModuleState::from_parts_for_test(Vec::new(), 1);
        state
            .refresh_slots_with(&ScriptedProber {
                observation: FineidCardObservation::Absent,
                objects_ok: false,
            })
            .expect("refresh succeeds");
        assert!(state.slot_ids().is_empty());
    }

    /// A card that answers the AID SELECT but cannot yield a
    /// parseable FINEID authentication certificate must not
    /// surface as a slot either -- answering the SELECT is not
    /// proof of FINEID.
    #[test]
    fn aid_answering_cert_failing_card_yields_no_slot() {
        let mut state = ModuleState::from_parts_for_test(Vec::new(), 1);
        state
            .refresh_slots_with(&ScriptedProber {
                observation: FineidCardObservation::Present,
                objects_ok: false,
            })
            .expect("refresh succeeds");
        assert!(state.slot_ids().is_empty());
    }

    /// Slot events are reported exactly once per presence change:
    /// first sighting counts, a steady state does not, a removal
    /// (card stops answering the AID probe) does.
    #[test]
    fn slot_events_report_each_presence_change_once() {
        let mut state = state_with_slots(&["Scripted Reader"]);
        // First sighting of the pre-existing present slot.
        assert_eq!(state.take_slot_event(), Some(1));
        // Steady state: no further event.
        assert_eq!(state.take_slot_event(), None);
        // The card stops answering the AID probe -> removal event.
        state
            .refresh_slots_with(&ScriptedProber {
                observation: FineidCardObservation::Absent,
                objects_ok: false,
            })
            .expect("refresh succeeds");
        assert_eq!(state.take_slot_event(), Some(1));
        assert_eq!(state.take_slot_event(), None);
    }

    /// Reader contention while a slot's card was present must
    /// preserve the slot's last known state, not evict it.
    #[test]
    fn contention_preserves_existing_slot_presence() {
        let mut state = state_with_slots(&["Scripted Reader"]);
        state
            .refresh_slots_with(&ScriptedProber {
                observation: FineidCardObservation::TemporarilyUnavailable,
                objects_ok: false,
            })
            .expect("refresh succeeds");
        assert!(state.slot(1).is_some_and(SlotRecord::card_present));
    }

    #[test]
    fn rejected_pin_survives_logout_and_session_close() {
        let mut state = state_with_slots(&["Reader A"]);
        let handle = state.open_session(1, CKF_SERIAL_SESSION);
        let pin = PinBytes::try_from(*b"1234").expect("valid PIN1");
        let serial = refineid_lib_core::identity::TokenSerial::new("CARD-A".to_owned());
        let cache = state.pin_cache(1).expect("cache created");
        {
            let mut cache = cache.lock().expect("cache lock");
            cache
                .store_pin1(serial.clone(), pin.clone())
                .expect("first login accepted");
            cache.record_rejected(&serial, refineid_lib_core::auth::PinSlot::Pin1, &pin);
        }
        state.logout(1);
        assert!(state.close_session(handle));
        assert!(cache.lock().expect("cache lock").is_rejected(
            &serial,
            refineid_lib_core::auth::PinSlot::Pin1,
            &pin
        ));
    }

    #[test]
    fn rejected_pin_survives_module_state_recreation() {
        let reader = "Process Lifetime Negative Cache Reader";
        let pin = PinBytes::try_from(*b"2468").expect("valid PIN1");
        let serial = refineid_lib_core::identity::TokenSerial::new("CARD-PROCESS".to_owned());
        {
            let mut state = state_with_slots(&[reader]);
            let cache = state.pin_cache(1).expect("cache created");
            cache.lock().expect("cache lock").record_rejected(
                &serial,
                refineid_lib_core::auth::PinSlot::Pin1,
                &pin,
            );
            state.clear_all_positive_pins();
        }
        let mut recreated = state_with_slots(&[reader]);
        let cache = recreated.pin_cache(1).expect("process cache reused");
        assert!(cache.lock().expect("cache lock").is_rejected(
            &serial,
            refineid_lib_core::auth::PinSlot::Pin1,
            &pin
        ));
    }
}
