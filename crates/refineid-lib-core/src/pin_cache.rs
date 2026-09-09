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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Process-local PIN retry protection.
//!
//! A successfully verified PIN1 may be retained for at most fifteen minutes,
//! refreshed on each use -- an idle window for an authentication session. A
//! verified PIN2 may be retained for one minute measured from entry and never
//! refreshed -- a bounded consent window that lets a signing batch run without
//! prompting per document, yet cannot be kept alive indefinitely by a stream
//! of signatures.
//!
//! A PIN1 or PIN2 value rejected by a card is remembered until process exit
//! and refused locally thereafter, so software cannot burn another card retry
//! with the same value. Rejected values are represented only by a fingerprint
//! keyed with fresh process-local random material; raw PIN bytes are never
//! retained by the negative cache.

use std::time::{Duration, Instant};

use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::auth::PinSlot;
use crate::identity::TokenSerial;
use crate::pin::PinBytes;

/// Maximum lifetime of a positively cached PIN1, refreshed on each use.
pub const PIN1_CACHE_LIFETIME: Duration = Duration::from_mins(15);
/// Maximum staging time for a PIN1 that may be used for one operation only.
const PIN1_ONE_SHOT_LIFETIME: Duration = Duration::from_secs(30);
/// Maximum lifetime of a positively cached PIN2, measured from entry and
/// never refreshed -- a bounded consent window for one signing batch.
pub const PIN2_CACHE_LIFETIME: Duration = Duration::from_mins(1);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pin1Retention {
    Reusable,
    OneShot,
}

/// A previously card-rejected PIN was offered again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreviouslyRejectedPin {
    /// Slot for which the PIN was rejected.
    pub slot: PinSlot,
}

impl core::fmt::Display for PreviouslyRejectedPin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let label = match self.slot {
            PinSlot::Pin1 => "PIN1",
            PinSlot::Pin2 => "PIN2",
        };
        write!(f, "{label} was previously rejected by the card")
    }
}

impl core::error::Error for PreviouslyRejectedPin {}

struct CachedPin1 {
    serial: TokenSerial,
    pin: PinBytes,
    last_successful_use: Instant,
    generation: u64,
    retention: Pin1Retention,
}

/// Destructively checked-out PIN1 state for one live card serial.
///
/// Dropping this value destroys the PIN. It can return to the cache
/// only through [`Self::restore_after_success`], after the caller has
/// received a definite successful card-side VERIFY result.
pub struct CheckedOutPin1 {
    entry: CachedPin1,
}

impl CheckedOutPin1 {
    /// Borrow the PIN for the single VERIFY associated with this checkout.
    #[must_use]
    pub const fn pin(&self) -> &PinBytes {
        &self.entry.pin
    }

    /// Restore this entry and refresh its idle deadline after definite
    /// card-side success. Concurrent or intervening invalidation wins.
    pub fn restore_after_success(self, cache: &mut PinSafetyCache) {
        self.restore_after_success_at(cache, Instant::now());
    }

    fn restore_after_success_at(mut self, cache: &mut PinSafetyCache, now: Instant) {
        if self.entry.retention == Pin1Retention::OneShot {
            return;
        }
        if cache.generation != self.entry.generation || cache.positive_pin1.is_some() {
            return;
        }
        self.entry.last_successful_use = now;
        cache.positive_pin1 = Some(self.entry);
    }
}

impl core::fmt::Debug for CheckedOutPin1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CheckedOutPin1")
            .field("serial", &self.entry.serial)
            .finish_non_exhaustive()
    }
}

/// A verified PIN2 held for the bounded consent window. Kept distinct from
/// [`CachedPin1`] on purpose: PIN2's window is anchored at entry and is never
/// refreshed by use, so a signing batch cannot extend it.
struct CachedPin2 {
    serial: TokenSerial,
    pin: PinBytes,
    entered_at: Instant,
    generation: u64,
}

/// Destructively checked-out PIN2 state for one live card serial.
///
/// As with [`CheckedOutPin1`], dropping this destroys the PIN; it returns to
/// the cache only through [`Self::restore_after_success`], after a definite
/// card-side success, and only if no invalidation intervened. Restoring does
/// *not* extend the window -- PIN2 expires a fixed [`PIN2_CACHE_LIFETIME`]
/// after it was entered, however many signatures it served in between.
pub struct CheckedOutPin2 {
    entry: CachedPin2,
}

impl CheckedOutPin2 {
    /// Borrow the PIN for the single signature associated with this checkout.
    #[must_use]
    pub const fn pin(&self) -> &PinBytes {
        &self.entry.pin
    }

    /// Restore this entry after a definite card-side success, keeping its
    /// original entry deadline. Concurrent or intervening invalidation wins.
    pub fn restore_after_success(self, cache: &mut PinSafetyCache) {
        if cache.generation_pin2 != self.entry.generation || cache.positive_pin2.is_some() {
            return;
        }
        cache.positive_pin2 = Some(self.entry);
    }
}

impl core::fmt::Debug for CheckedOutPin2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CheckedOutPin2")
            .field("serial", &self.entry.serial)
            .finish_non_exhaustive()
    }
}

/// Opaque keyed mark for one rejected PIN value.
#[derive(Zeroize)]
struct RejectedPinFingerprint([u8; 32]);

/// Positive PIN1 cache plus process-lifetime negative PIN1/PIN2 cache.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PinSafetyCache {
    #[zeroize(skip)]
    positive_pin1: Option<CachedPin1>,
    #[zeroize(skip)]
    positive_pin2: Option<CachedPin2>,
    #[zeroize(skip)]
    generation: u64,
    #[zeroize(skip)]
    generation_pin2: u64,
    fingerprint_key: [u8; 32],
    rejected_pin1: Vec<RejectedPinFingerprint>,
    rejected_pin2: Vec<RejectedPinFingerprint>,
}

impl PinSafetyCache {
    /// Construct an empty cache with a fresh process-local fingerprint key.
    ///
    /// # Errors
    /// Returns the OS random-source failure rather than creating a predictable
    /// rejection fingerprint key.
    pub fn new() -> Result<Self, crate::rng::Failure> {
        Ok(Self {
            positive_pin1: None,
            positive_pin2: None,
            generation: 0,
            generation_pin2: 0,
            fingerprint_key: crate::rng::array()?,
            rejected_pin1: Vec::new(),
            rejected_pin2: Vec::new(),
        })
    }

    /// Positively cache a just-verified PIN1 for at most five minutes.
    ///
    /// # Errors
    /// Refuses a value that this process has already seen the card reject.
    pub fn store_pin1(
        &mut self,
        serial: TokenSerial,
        pin: PinBytes,
    ) -> Result<(), PreviouslyRejectedPin> {
        self.store_pin1_at(serial, pin, Pin1Retention::Reusable, Instant::now())
    }

    /// Stage a just-verified PIN1 for exactly one checkout.
    ///
    /// The entry expires after 30 seconds and is destroyed after checkout even
    /// when the card accepts it. This bridges PKCS #11 `C_Login` to the
    /// immediately following operation without enabling the five-minute cache.
    ///
    /// # Errors
    /// Refuses a value that this process has already seen the card reject.
    pub fn stage_pin1_once(
        &mut self,
        serial: TokenSerial,
        pin: PinBytes,
    ) -> Result<(), PreviouslyRejectedPin> {
        self.store_pin1_at(serial, pin, Pin1Retention::OneShot, Instant::now())
    }

    /// Destructively check out PIN1 only for the freshly read live serial.
    /// Expiry or mismatch destroys the positive entry.
    pub fn checkout_pin1(&mut self, live_serial: &TokenSerial) -> Option<CheckedOutPin1> {
        self.checkout_pin1_at(live_serial, Instant::now())
    }

    /// Whether unexpired positive PIN1 state exists. This does not expose
    /// the secret or authorize card use; checkout still requires a freshly
    /// read matching full serial.
    pub fn has_positive_pin1(&mut self) -> bool {
        let now = Instant::now();
        let live = self.positive_pin1.as_ref().is_some_and(|entry| {
            now.checked_duration_since(entry.last_successful_use)
                .is_some_and(|age| age < entry.retention.lifetime())
        });
        if !live {
            self.clear_positive();
        }
        live
    }

    /// Positively cache a just-verified PIN2 for the bounded consent window.
    ///
    /// # Errors
    /// Refuses a value that this process has already seen the card reject.
    pub fn store_pin2(
        &mut self,
        serial: TokenSerial,
        pin: PinBytes,
    ) -> Result<(), PreviouslyRejectedPin> {
        self.store_pin2_at(serial, pin, Instant::now())
    }

    /// Destructively check out PIN2 only for the freshly read live serial.
    /// Expiry or mismatch destroys the positive entry.
    pub fn checkout_pin2(&mut self, live_serial: &TokenSerial) -> Option<CheckedOutPin2> {
        self.checkout_pin2_at(live_serial, Instant::now())
    }

    /// Whether unexpired positive PIN2 state exists. This does not expose the
    /// secret or authorize card use; checkout still requires a freshly read
    /// matching full serial.
    pub fn has_positive_pin2(&mut self) -> bool {
        let now = Instant::now();
        let live = self.positive_pin2.as_ref().is_some_and(|entry| {
            now.checked_duration_since(entry.entered_at)
                .is_some_and(|age| age < PIN2_CACHE_LIFETIME)
        });
        if !live {
            self.positive_pin2 = None;
        }
        live
    }

    /// Purge positive PIN1 material without weakening process-lifetime
    /// rejection memory. PIN2 has its own [`Self::clear_positive_pin2`] and its
    /// own generation counter, so a PIN1 event never disturbs an in-flight
    /// signing batch.
    pub fn clear_positive(&mut self) {
        self.positive_pin1 = None;
        self.generation = self.generation.wrapping_add(1);
    }

    /// Purge positive PIN2 material, independent of PIN1.
    pub fn clear_positive_pin2(&mut self) {
        self.positive_pin2 = None;
        self.generation_pin2 = self.generation_pin2.wrapping_add(1);
    }

    /// Whether `pin` has already been rejected by the card for `slot`.
    #[must_use]
    pub fn is_rejected(&self, serial: &TokenSerial, slot: PinSlot, pin: &PinBytes) -> bool {
        let candidate = self.fingerprint(serial, slot, pin);
        self.rejected(slot)
            .iter()
            .any(|known| bool::from(known.0.ct_eq(&candidate.0)))
    }

    /// Record a card-side wrong-PIN response for the rest of this process.
    /// Also purges positive PIN1 material because card authentication state is
    /// now known to have changed.
    pub fn record_rejected(&mut self, serial: &TokenSerial, slot: PinSlot, pin: &PinBytes) {
        self.clear_positive();
        self.clear_positive_pin2();
        let fingerprint = self.fingerprint(serial, slot, pin);
        let rejected = self.rejected_mut(slot);
        if !rejected
            .iter()
            .any(|known| bool::from(known.0.ct_eq(&fingerprint.0)))
        {
            rejected.push(fingerprint);
        }
    }

    fn store_pin1_at(
        &mut self,
        serial: TokenSerial,
        pin: PinBytes,
        retention: Pin1Retention,
        now: Instant,
    ) -> Result<(), PreviouslyRejectedPin> {
        if self.is_rejected(&serial, PinSlot::Pin1, &pin) {
            return Err(PreviouslyRejectedPin {
                slot: PinSlot::Pin1,
            });
        }
        self.clear_positive();
        self.positive_pin1 = Some(CachedPin1 {
            serial,
            pin,
            last_successful_use: now,
            generation: self.generation,
            retention,
        });
        Ok(())
    }

    fn checkout_pin1_at(
        &mut self,
        live_serial: &TokenSerial,
        now: Instant,
    ) -> Option<CheckedOutPin1> {
        let live = self.positive_pin1.as_ref().is_some_and(|entry| {
            entry.serial == *live_serial
                && now
                    .checked_duration_since(entry.last_successful_use)
                    .is_some_and(|age| age < entry.retention.lifetime())
        });
        if !live {
            self.clear_positive();
            return None;
        }
        self.positive_pin1
            .take()
            .map(|entry| CheckedOutPin1 { entry })
    }

    fn store_pin2_at(
        &mut self,
        serial: TokenSerial,
        pin: PinBytes,
        now: Instant,
    ) -> Result<(), PreviouslyRejectedPin> {
        if self.is_rejected(&serial, PinSlot::Pin2, &pin) {
            return Err(PreviouslyRejectedPin {
                slot: PinSlot::Pin2,
            });
        }
        self.clear_positive_pin2();
        self.positive_pin2 = Some(CachedPin2 {
            serial,
            pin,
            entered_at: now,
            generation: self.generation_pin2,
        });
        Ok(())
    }

    fn checkout_pin2_at(
        &mut self,
        live_serial: &TokenSerial,
        now: Instant,
    ) -> Option<CheckedOutPin2> {
        let live = self.positive_pin2.as_ref().is_some_and(|entry| {
            entry.serial == *live_serial
                && now
                    .checked_duration_since(entry.entered_at)
                    .is_some_and(|age| age < PIN2_CACHE_LIFETIME)
        });
        if !live {
            self.clear_positive_pin2();
            return None;
        }
        self.positive_pin2
            .take()
            .map(|entry| CheckedOutPin2 { entry })
    }

    fn fingerprint(
        &self,
        serial: &TokenSerial,
        slot: PinSlot,
        pin: &PinBytes,
    ) -> RejectedPinFingerprint {
        let slot_tag = match slot {
            PinSlot::Pin1 => 1_u8,
            PinSlot::Pin2 => 2_u8,
        };
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&self.fingerprint_key) else {
            // A fixed 32-byte HMAC-SHA-256 key is valid. Fail closed if
            // that invariant ever changes: all values then share one mark
            // and are refused after the first rejection, never replayed.
            return RejectedPinFingerprint([0_u8; 32]);
        };
        let Ok(digit_count) = u8::try_from(pin.digit_count()) else {
            return RejectedPinFingerprint([0_u8; 32]);
        };
        let Ok(serial_len) = u32::try_from(serial.as_str().len()) else {
            return RejectedPinFingerprint([0_u8; 32]);
        };
        mac.update(&serial_len.to_be_bytes());
        mac.update(serial.as_str().as_bytes());
        mac.update(&[slot_tag]);
        mac.update(&[digit_count]);
        mac.update(pin.as_bytes());
        RejectedPinFingerprint(mac.finalize().into_bytes().into())
    }

    fn rejected(&self, slot: PinSlot) -> &[RejectedPinFingerprint] {
        match slot {
            PinSlot::Pin1 => &self.rejected_pin1,
            PinSlot::Pin2 => &self.rejected_pin2,
        }
    }

    const fn rejected_mut(&mut self, slot: PinSlot) -> &mut Vec<RejectedPinFingerprint> {
        match slot {
            PinSlot::Pin1 => &mut self.rejected_pin1,
            PinSlot::Pin2 => &mut self.rejected_pin2,
        }
    }
}

impl Pin1Retention {
    const fn lifetime(self) -> Duration {
        match self {
            Self::Reusable => PIN1_CACHE_LIFETIME,
            Self::OneShot => PIN1_ONE_SHOT_LIFETIME,
        }
    }
}

impl core::fmt::Debug for PinSafetyCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PinSafetyCache")
            .field("positive_pin1", &self.positive_pin1.is_some())
            .field("positive_pin2", &self.positive_pin2.is_some())
            .field("generation", &self.generation)
            .field("generation_pin2", &self.generation_pin2)
            .field("rejected_pin1_count", &self.rejected_pin1.len())
            .field("rejected_pin2_count", &self.rejected_pin2.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin<const N: usize>(digits: &[u8; N]) -> PinBytes {
        PinBytes::try_from(*digits).expect("valid test PIN")
    }

    fn serial(value: &str) -> TokenSerial {
        TokenSerial::new(value.to_owned())
    }

    fn cache() -> PinSafetyCache {
        PinSafetyCache {
            positive_pin1: None,
            positive_pin2: None,
            generation: 0,
            generation_pin2: 0,
            fingerprint_key: [0xA5_u8; 32],
            rejected_pin1: Vec::new(),
            rejected_pin2: Vec::new(),
        }
    }

    #[test]
    fn positive_pin1_expires_at_its_lifetime() {
        let now = Instant::now();
        let card = serial("CARD-A-FULL-SERIAL");
        let mut cache = cache();
        cache
            .store_pin1_at(card.clone(), pin(b"1357"), Pin1Retention::Reusable, now)
            .expect("fresh PIN is accepted");
        let just_before_expiry = (now + PIN1_CACHE_LIFETIME)
            .checked_sub(Duration::from_millis(1))
            .expect("one millisecond is less than five minutes");
        let checkout = cache
            .checkout_pin1_at(&card, just_before_expiry)
            .expect("entry remains live before the boundary");
        checkout.restore_after_success_at(&mut cache, now);
        assert!(
            cache
                .checkout_pin1_at(&card, now + PIN1_CACHE_LIFETIME)
                .is_none()
        );
    }

    #[test]
    fn clearing_positive_preserves_negative_memory() {
        let mut cache = cache();
        let card = serial("CARD-A-FULL-SERIAL");
        let rejected = pin(b"1357");
        cache.record_rejected(&card, PinSlot::Pin1, &rejected);
        cache.clear_positive();
        assert!(cache.is_rejected(&card, PinSlot::Pin1, &rejected));
    }

    #[test]
    fn rejection_is_bound_to_slot_and_value() {
        let mut cache = cache();
        let card = serial("CARD-A-FULL-SERIAL");
        let rejected = pin(b"135790");
        cache.record_rejected(&card, PinSlot::Pin2, &rejected);
        assert!(cache.is_rejected(&card, PinSlot::Pin2, &rejected));
        assert!(!cache.is_rejected(&card, PinSlot::Pin1, &rejected));
        assert!(!cache.is_rejected(&card, PinSlot::Pin2, &pin(b"246802")));
    }

    #[test]
    fn rejected_pin1_cannot_reenter_positive_cache() {
        let mut cache = cache();
        let card = serial("CARD-A-FULL-SERIAL");
        let rejected = pin(b"1357");
        cache.record_rejected(&card, PinSlot::Pin1, &rejected);
        assert_eq!(
            cache.store_pin1(card, rejected),
            Err(PreviouslyRejectedPin {
                slot: PinSlot::Pin1
            })
        );
    }

    #[test]
    fn serial_mismatch_destroys_positive_entry() {
        let now = Instant::now();
        let card_a = serial("CARD-A-FULL-SERIAL");
        let card_b = serial("CARD-B-FULL-SERIAL");
        let mut cache = cache();
        cache
            .store_pin1_at(card_a.clone(), pin(b"1357"), Pin1Retention::Reusable, now)
            .expect("fresh PIN is accepted");
        assert!(cache.checkout_pin1_at(&card_b, now).is_none());
        assert!(cache.checkout_pin1_at(&card_a, now).is_none());
    }

    #[test]
    fn rejection_is_bound_to_full_serial() {
        let card_a = serial("CARD-A-FULL-SERIAL");
        let card_b = serial("CARD-B-FULL-SERIAL");
        let rejected = pin(b"1357");
        let mut cache = cache();
        cache.record_rejected(&card_a, PinSlot::Pin1, &rejected);
        assert!(cache.is_rejected(&card_a, PinSlot::Pin1, &rejected));
        assert!(!cache.is_rejected(&card_b, PinSlot::Pin1, &rejected));
    }

    #[test]
    fn checkout_drop_does_not_restore_entry() {
        let now = Instant::now();
        let card = serial("CARD-A-FULL-SERIAL");
        let mut cache = cache();
        cache
            .store_pin1_at(card.clone(), pin(b"1357"), Pin1Retention::Reusable, now)
            .expect("fresh PIN is accepted");
        let checkout = cache
            .checkout_pin1_at(&card, now)
            .expect("entry can be checked out once");
        drop(checkout);
        assert!(cache.checkout_pin1_at(&card, now).is_none());
    }

    #[test]
    fn one_shot_pin1_is_destroyed_after_successful_checkout() {
        let now = Instant::now();
        let card = serial("CARD-A-FULL-SERIAL");
        let mut cache = cache();
        cache
            .store_pin1_at(card.clone(), pin(b"1357"), Pin1Retention::OneShot, now)
            .expect("fresh PIN is accepted");
        let checkout = cache
            .checkout_pin1_at(&card, now)
            .expect("one-shot entry permits one checkout");
        checkout.restore_after_success_at(&mut cache, now);
        assert!(cache.checkout_pin1_at(&card, now).is_none());
    }

    #[test]
    fn unused_one_shot_pin1_expires_after_thirty_seconds() {
        let now = Instant::now();
        let card = serial("CARD-A-FULL-SERIAL");
        let mut cache = cache();
        cache
            .store_pin1_at(card.clone(), pin(b"1357"), Pin1Retention::OneShot, now)
            .expect("fresh PIN is accepted");
        assert!(
            cache
                .checkout_pin1_at(&card, now + PIN1_ONE_SHOT_LIFETIME)
                .is_none()
        );
    }

    #[test]
    fn successful_use_refreshes_idle_timeout() {
        let now = Instant::now();
        let card = serial("CARD-A-FULL-SERIAL");
        let mut cache = cache();
        cache
            .store_pin1_at(card.clone(), pin(b"1357"), Pin1Retention::Reusable, now)
            .expect("fresh PIN is accepted");
        let use_time = now + Duration::from_mins(4);
        let checkout = cache
            .checkout_pin1_at(&card, use_time)
            .expect("entry remains live at four minutes");
        checkout.restore_after_success_at(&mut cache, use_time);
        assert!(
            cache
                .checkout_pin1_at(&card, now + Duration::from_mins(8))
                .is_some()
        );
    }

    #[test]
    fn invalidation_prevents_checked_out_entry_resurrection() {
        let now = Instant::now();
        let card = serial("CARD-A-FULL-SERIAL");
        let mut cache = cache();
        cache
            .store_pin1_at(card.clone(), pin(b"1357"), Pin1Retention::Reusable, now)
            .expect("fresh PIN is accepted");
        let checkout = cache
            .checkout_pin1_at(&card, now)
            .expect("entry can be checked out");
        cache.clear_positive();
        checkout.restore_after_success_at(&mut cache, now);
        assert!(cache.checkout_pin1_at(&card, now).is_none());
    }

    #[test]
    fn pin2_is_reusable_within_its_window_then_expires_from_entry() {
        let now = Instant::now();
        let card = serial("CARD-A-FULL-SERIAL");
        let mut cache = cache();
        cache
            .store_pin2_at(card.clone(), pin(b"135790"), now)
            .expect("fresh PIN2 is accepted");
        // Reusable for several signatures inside the consent window.
        for offset_secs in [0_u64, 20, 40] {
            let at = now + Duration::from_secs(offset_secs);
            let checkout = cache
                .checkout_pin2_at(&card, at)
                .expect("PIN2 remains live inside the consent window");
            checkout.restore_after_success(&mut cache);
        }
        // The window is measured from entry, so it lapses at the deadline.
        assert!(
            cache
                .checkout_pin2_at(&card, now + PIN2_CACHE_LIFETIME)
                .is_none()
        );
    }

    #[test]
    fn pin2_window_is_not_extended_by_use() {
        let now = Instant::now();
        let card = serial("CARD-A-FULL-SERIAL");
        let mut cache = cache();
        cache
            .store_pin2_at(card.clone(), pin(b"135790"), now)
            .expect("fresh PIN2 is accepted");
        // A use late in the window does not buy another full minute.
        let late = (now + PIN2_CACHE_LIFETIME)
            .checked_sub(Duration::from_secs(1))
            .expect("one second is less than the PIN2 lifetime");
        let checkout = cache
            .checkout_pin2_at(&card, late)
            .expect("PIN2 live just before expiry");
        checkout.restore_after_success(&mut cache);
        assert!(
            cache
                .checkout_pin2_at(&card, now + PIN2_CACHE_LIFETIME)
                .is_none()
        );
    }

    #[test]
    fn rejected_pin2_cannot_enter_positive_cache() {
        let mut cache = cache();
        let card = serial("CARD-A-FULL-SERIAL");
        let rejected = pin(b"135790");
        cache.record_rejected(&card, PinSlot::Pin2, &rejected);
        assert_eq!(
            cache.store_pin2(card, rejected),
            Err(PreviouslyRejectedPin {
                slot: PinSlot::Pin2
            })
        );
    }

    #[test]
    fn pin2_serial_mismatch_destroys_positive_entry() {
        let now = Instant::now();
        let card_a = serial("CARD-A-FULL-SERIAL");
        let card_b = serial("CARD-B-FULL-SERIAL");
        let mut cache = cache();
        cache
            .store_pin2_at(card_a.clone(), pin(b"135790"), now)
            .expect("fresh PIN2 is accepted");
        assert!(cache.checkout_pin2_at(&card_b, now).is_none());
        assert!(cache.checkout_pin2_at(&card_a, now).is_none());
    }

    #[test]
    fn clearing_pin2_prevents_checked_out_entry_resurrection() {
        let now = Instant::now();
        let card = serial("CARD-A-FULL-SERIAL");
        let mut cache = cache();
        cache
            .store_pin2_at(card.clone(), pin(b"135790"), now)
            .expect("fresh PIN2 is accepted");
        let checkout = cache
            .checkout_pin2_at(&card, now)
            .expect("entry can be checked out");
        cache.clear_positive_pin2();
        checkout.restore_after_success(&mut cache);
        assert!(cache.checkout_pin2_at(&card, now).is_none());
    }

    #[test]
    fn pin1_event_does_not_disturb_a_cached_pin2() {
        let now = Instant::now();
        let card = serial("CARD-A-FULL-SERIAL");
        let mut cache = cache();
        cache
            .store_pin2_at(card.clone(), pin(b"135790"), now)
            .expect("fresh PIN2 is accepted");
        // A PIN1 invalidation bumps only the PIN1 generation.
        cache.clear_positive();
        // The signing batch's PIN2 survives untouched.
        let checkout = cache
            .checkout_pin2_at(&card, now)
            .expect("PIN2 is unaffected by a PIN1 event");
        checkout.restore_after_success(&mut cache);
        assert!(cache.checkout_pin2_at(&card, now).is_some());
    }
}
