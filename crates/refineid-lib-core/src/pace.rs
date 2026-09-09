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

//! PACE (Password-Authenticated Connection Establishment) - the
//! protocol the `FINeID` card requires before it will let any APDU
//! through on the *contactless* (NFC) interface.
//!
//! It is also accepted - though not strictly required - on the
//! contact (PCSC) interface for SM-protected reads.
//!
//! References:
//!
//! - BSI TR-03110-3 §A.5 (Generic Mapping; the variant `FINeID` uses).
//! - ICAO Doc 9303 Part 11 §9.7.1 (key derivation function).
//! - `FINeID` S4-2 §4.7 (which PACE algorithm to use for which card).
//!
//! Variant pinned for v0.1: **`id-PACE-ECDH-GM-AES-CBC-CMAC-256`**
//! over **`brainpoolP384r1`**, with **CAN** as the password. This is
//! what the published EF.CardAccess on `FINeID` S4-2 RSA-variant cards
//! advertises as the preferred algorithm and what the Swift
//! `refineid-core` reference implementation uses.
//!
//! Wire-level flow, four GENERAL AUTHENTICATE rounds (chained CLA
//! `0x10` for the first three, plain `0x00` for the last):
//!
//! 1. **MSE:Set AT** - `00 22 C1 A4` with the OID + password ref +
//!    domain ref. Card responds 0x9000.
//! 2. **Encrypted nonce** - request `7C 00`; card returns
//!    `7C L 80 10 <z>`. Decrypt `s = AES-256-CBC(K_pi, IV=0, z)` with
//!    `K_pi = KDF(CAN, c=3)`.
//! 3. **Map nonce** - pick ephemeral `x_pcd  in  [1, n)`, send
//!    `X_pcd = x_pcd * G` as `7C L 81 <97> ...`. Card returns
//!    `Y_picc` in `82`. Compute `H = x_pcd * Y_picc`. Mapped
//!    generator `G' = s * G + H`.
//! 4. **Key agreement** - pick ephemeral `u_pcd`, send
//!    `U_pcd = u_pcd * G'` in `83`. Card returns `V_picc` in `84`.
//!    Shared point `K = u_pcd * V_picc`; session keys derived from
//!    its x-coordinate.
//! 5. **Mutual authentication** - derive `K_enc = KDF(K_x, c=1)`,
//!    `K_mac = KDF(K_x, c=2)`. Compute auth tag `T_PCD` over the
//!    *card's* public point V; send in `85`. Card returns its tag
//!    `T_PICC` over our U; verify it.
//!
//! On success we return a [`PaceSession`] holding the two session
//! keys plus the all-zero Send Sequence Counter the SM layer will
//! increment on every wrap/unwrap.
//!
//! Wired consumers today: the eMRTD read path
//! (`emrtd::read_personal_data`) and, since the iPhone-NFC Stage-1
//! work, the FFI card-operation surface (`refineid-lib-ffi`),
//! which drives [`run_pace_with_can`] over a callback transport
//! (`CoreNFC` on iOS) and wraps the result in
//! `secure_messaging::SmTransport` for the FINEID PIN / sign
//! chain. Still-reserved-for-future: the runtime negotiation hook
//! in `Session::attach` (today the *caller* decides whether PACE
//! runs; on contact it's bypassed, on contactless the card
//! requires it).
use crypto_bigint::U384;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

pub mod commands;

use crate::ber::{self, BerTag, BerTlv};

// PACE-protocol context tags. The numeric values come from BSI
// TR-03110-3 §A.2.4 / §A.5: every PACE GENERAL AUTHENTICATE
// payload is wrapped in a `DynamicAuthData` (0x7C) constructed
// TLV, with the inner tag selecting the protocol round.
//
// Markers live in this module (not in `ber`) so the names
// reflect their semantic role -- `EncryptedNonce` rather than
// "context-specific primitive [0]".

/// `Dynamic Authentication Data` template (tag 0x7C). Every
/// PACE GENERAL AUTHENTICATE request and response is wrapped
/// in this constructed TLV.
#[derive(Debug, Clone, Copy)]
pub struct DynamicAuthData;
impl BerTag for DynamicAuthData {
    const TAG: u16 = 0x7C;
}

/// Encrypted nonce -- card's step-2 response payload (tag 0x80).
#[derive(Debug, Clone, Copy)]
pub struct EncryptedNonce;
impl BerTag for EncryptedNonce {
    const TAG: u16 = 0x80;
}

/// Card's mapping-data response (`Y_picc`) in step 3 (tag 0x82).
#[derive(Debug, Clone, Copy)]
pub struct MappingDataOut;
impl BerTag for MappingDataOut {
    const TAG: u16 = 0x82;
}

/// Card's key-agreement response (`V_picc`) in step 4 (tag 0x84).
#[derive(Debug, Clone, Copy)]
pub struct KeyAgreeOut;
impl BerTag for KeyAgreeOut {
    const TAG: u16 = 0x84;
}

/// Card's authentication-token response (`T_PICC`) in step 5
/// (tag 0x86).
#[derive(Debug, Clone, Copy)]
pub struct AuthTokenOut;
impl BerTag for AuthTokenOut {
    const TAG: u16 = 0x86;
}
use crate::crypto::brainpool_p384::{AffinePoint, n as brainpool_n};
use crate::crypto::container::{AesCbc, Ciphertext};
use crate::crypto::symmetric::{
    Aes256Key, KdfParam, aes256_cbc_decrypt_no_padding, aes256_cmac_truncated, kdf_aes256,
};
use crate::oid::known::PACE_ECDH_GM_AES_CBC_CMAC_256 as PACE_MECHANISM_OID;
use crate::transport::{CardTransport, TransportDispatchError};

/// Shortened transport-error alias for the PACE state-machine
/// dispatchers. PACE crosses many APDU boundaries; the alias
/// keeps `Result<_, TxError<T>>` signatures readable without
/// repeating the nested generic at each step.
type TxError<T> = TransportDispatchError<<T as CardTransport>::Error>;

// MARK: - Protocol constants
//
// The PACE mechanism `id-PACE-ECDH-GM-AES-CBC-CMAC-256` (OID
// `0.4.0.127.0.7.2.2.4.2.4`) is the typed `PACE_MECHANISM_OID` imported
// above; its `.as_bytes()` (OID body, no DER tag/length) is pasted into
// the MSE:Set AT `0x80` DO and wrapped in `06` for the auth-tag MAC input.

/// Password reference values (BSI TR-03110-3 §B.11.1).
pub const PASSWORD_REF_MRZ: u8 = 0x01;
/// Password reference for the printed CAN (BSI TR-03110-3 §B.11.1).
pub const PASSWORD_REF_CAN: u8 = 0x02;
/// Password reference for the cardholder PIN (BSI TR-03110-3 §B.11.1).
pub const PASSWORD_REF_PIN: u8 = 0x03;
/// Password reference for the PUK (BSI TR-03110-3 §B.11.1).
pub const PASSWORD_REF_PUK: u8 = 0x04;

/// FINEID's card-specific PACE domain parameter ID for `BrainpoolP384r1`.
///
/// The BSI TR-03110-3 §A.6.6.1 *standardized* registry assigns
/// 0x0B (decimal 11) to `BrainpoolP384r1`, but the real FINEID
/// cards in the field declare a non-standard 0x10 in their
/// EF.CardAccess `PACEInfo` (empirically confirmed against a
/// FINEID-S4-1 v3.1 citizen card on 2026-05-21; the same value is
/// hard-coded in the legacy iOS reader at
/// `legacy/refinneid-core/Sources/RefinneidCore/PACE.swift` as
/// `static let paramId: UInt8 = 0x10`). Until / unless this Rust
/// PACE driver grows EF.CardAccess parsing and discovers the
/// paramId at runtime, this constant has to match what FINEID
/// actually expects, not what the BSI registry says.
///
/// The previous value `0x0D` came from BSI TR-03111 §3.1.1 (an
/// ECC-curve registry, not the PACE domain-parameter registry --
/// the wrong table) and got `SW=0x6A88` ("reference data not
/// found") from the card.
pub const DOMAIN_REF_BRAINPOOL_P384_R1: u8 = 0x10;

/// Card-side IV for the encrypted-nonce decryption: all-zero, per
/// BSI TR-03110-3 §A.5.1.2.
const ZERO_IV: [u8; 16] = [0_u8; 16];

/// AES-256-CBC encrypted-nonce length.
const NONCE_LEN: usize = 16;

/// PACE BER-TLV data-object tags (BSI TR-03110-3 §A.5).
///
/// Tag bytes are reused across PACE steps; the constant name
/// records the *role* in a specific step or template so call-
/// sites read as protocol structure rather than raw hex.
mod tags {
    // ---- MSE:Set AT data (BSI TR-03110-3 §A.5.1) ----

    /// Cryptographic mechanism reference (OID body).
    pub(super) const MSE_MECHANISM: u8 = 0x80;
    /// Password reference DO.
    pub(super) const MSE_PASSWORD: u8 = 0x83;
    /// Domain-parameter reference DO.
    pub(super) const MSE_DOMAIN: u8 = 0x84;

    // ---- Dynamic Authentication Data envelope (§A.5.1.2--.5) ----

    /// Outer GA envelope tag.
    pub(super) const DYNAMIC_AUTH: u8 = 0x7C;
    /// Step 2 (encrypted nonce response): the nonce blob.
    #[expect(
        dead_code,
        reason = "Parsed via BerTlv typed marker; named for symmetry with the other PACE tags."
    )]
    pub(super) const ENC_NONCE: u8 = 0x80;
    /// Step 3 (map nonce request): PCD ephemeral public key.
    pub(super) const MAP_PCD_PUB: u8 = 0x81;
    /// Step 3 (map nonce response): PICC ephemeral public key.
    #[expect(
        dead_code,
        reason = "Parsed via BerTlv typed marker; named for symmetry."
    )]
    pub(super) const MAP_PICC_PUB: u8 = 0x82;
    /// Step 4 (key agreement request): PCD ephemeral public key.
    pub(super) const KA_PCD_PUB: u8 = 0x83;
    /// Step 4 (key agreement response): PICC ephemeral public key.
    #[expect(
        dead_code,
        reason = "Parsed via BerTlv typed marker; named for symmetry."
    )]
    pub(super) const KA_PICC_PUB: u8 = 0x84;
    /// Step 5 request: authentication token `T_PCD` (CMAC over `PK_PICC`).
    pub(super) const AUTH_TOKEN_PCD: u8 = 0x85;
    /// Step 5 response: authentication token `T_PICC` (CMAC over `PK_PCD`).
    /// Production parser branches on tag bytes inline; tests
    /// reference this name when constructing canned wire-format
    /// fixtures.
    #[cfg(test)]
    pub(super) const AUTH_TOKEN_PICC: u8 = 0x86;

    // ---- Public-key data template (§B.7), used in MAC input ----

    /// `7F49` public-key data object (BSI TR-03110-3 §B.7).
    pub(super) const PK_DATA_OBJECT: u16 = 0x7F49;
    /// ASN.1 universal OBJECT IDENTIFIER tag (X.690 §8.19).
    pub(super) const ASN1_OID: u8 = 0x06;
    /// EC point inside the [`PK_DATA_OBJECT`] template.
    pub(super) const PK_EC_POINT: u8 = 0x86;
}

// MARK: - Public API

/// Outcome of a successful PACE handshake.
//
// Deliberately NOT Copy: PaceSession holds AES-256 session-key
// material; making it Copy would silently duplicate secret bytes
// at every move and defeat the discipline that key material is
// consumed once. (The missing_copy_implementations lint doesn't
// fire on this struct today, so the constraint is documentation
// rather than a machine-enforced check.)
#[derive(Clone)]
#[non_exhaustive]
pub struct PaceSession {
    /// AES-256 key for SM payload encryption (`K_enc`). Typed
    /// [`Aes256Key`]: zeroized on drop, redacted from any formatter.
    pub k_enc: Aes256Key,
    /// AES-256-CMAC key for SM message authentication (`K_mac`).
    /// Same [`Aes256Key`] zeroize-on-drop hygiene as `k_enc`.
    pub k_mac: Aes256Key,
    /// Send Sequence Counter, [`Ssc::INITIAL`] on a fresh session;
    /// the SM wrapper increments it before each MAC computation.
    pub ssc: Ssc,
}

impl core::fmt::Debug for PaceSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Avoid dumping keys to logs; show their fingerprints
        // (first/last 4 bytes) and the SSC fully.
        f.debug_struct("PaceSession")
            .field("k_enc", &PaceHelpers::fingerprint(self.k_enc.as_bytes()))
            .field("k_mac", &PaceHelpers::fingerprint(self.k_mac.as_bytes()))
            .field("ssc", &PaceHelpers::hex_short(self.ssc.as_bytes()))
            .finish()
    }
}

/// PACE / secure-messaging Send Sequence Counter (BSI TR-03110-3
/// §F.4): a 16-byte big-endian counter incremented before every SM
/// wrap and unwrap, the PCD and PICC stepping it in lockstep.
///
/// A distinct type from an IV or AES block -- both are also
/// `[u8; 16]` and both start all-zero (see `ZERO_IV`), so a raw
/// representation invites feeding a counter where an IV belongs (or
/// vice-versa) into `aes256_ecb_encrypt_block`. The type makes that
/// swap a compile error and keeps the big-endian increment in one
/// place instead of loose in the SM wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ssc([u8; 16]);

impl Ssc {
    /// The fresh-session counter, all zero (BSI TR-03110-3 §A.5).
    pub const INITIAL: Self = Self([0_u8; 16]);

    /// Increment the counter by one, big-endian, wrapping at the
    /// 16-byte boundary (matches the card's SSC arithmetic).
    #[inline]
    pub fn increment(&mut self) {
        for byte in self.0.iter_mut().rev() {
            if *byte == u8::MAX {
                *byte = 0;
            } else {
                *byte = byte.wrapping_add(1);
                return;
            }
        }
    }

    /// Borrow the 16 counter bytes (for IV derivation / MAC input).
    #[must_use]
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Wrap raw counter bytes. Test-only: production SSCs start at
    /// [`Ssc::INITIAL`] and only move via [`Ssc::increment`].
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

/// Error returned from the PACE protocol driver (BSI TR-03110-2
/// §4.2 / ICAO Doc 9303-11 §4).
#[non_exhaustive]
#[derive(Debug)]
pub enum PaceError<TE> {
    /// Transport-level failure (PC/SC error, SM glitch).
    Transport(TE),
    /// BER / TLV parse failure on a card response.
    Ber(ber::BerError),
    /// Card returned a non-success status word at a PACE stage.
    /// Carries the stage name (compile-time set: "MSE:Set AT",
    /// "GA-1 encrypted nonce", ...) plus the raw SW. Tier 0
    /// `u16` -- the typed projection is `StatusWord`; the raw
    /// bytes stay for the diagnostic.
    Sw(&'static str, u16),
    /// Card response shape didn't match the expected PACE
    /// step layout. Tier 0 `&'static str` from a fixed
    /// compile-time set naming the offending shape.
    UnexpectedResponse(&'static str),
    /// EC point validation failed (off-curve point or wrong
    /// SEC1 encoding).
    InvalidPoint,
    /// Mutual-auth tag check failed -- the card and host derived
    /// different keys, almost always because the operator entered
    /// the wrong CAN / MRZ / PIN. Surfaced separately so the
    /// CLI can suggest "check the CAN printed on the card front".
    AuthMismatch,
    /// `getrandom` failed to supply nonce / ephemeral-key bytes.
    Random(crate::rng::Failure),
}

impl<TE: core::fmt::Display> core::fmt::Display for PaceError<TE> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "PACE transport: {e}"),
            Self::Ber(e) => write!(f, "PACE BER: {e}"),
            Self::Sw(stage, sw) => write!(f, "PACE {stage}: card returned SW={sw:#06X}"),
            Self::UnexpectedResponse(w) => write!(f, "PACE unexpected response: {w}"),
            Self::InvalidPoint => write!(f, "PACE: card sent an off-curve EC point"),
            Self::AuthMismatch => write!(f, "PACE: mutual auth tag did not match"),
            Self::Random(e) => write!(f, "PACE random: {e}"),
        }
    }
}

impl<TE: core::fmt::Debug + core::fmt::Display + 'static> core::error::Error for PaceError<TE> {}

impl<TE> From<ber::BerError> for PaceError<TE> {
    fn from(e: ber::BerError) -> Self {
        Self::Ber(e)
    }
}

/// Outcome of the steps 1-4 portion of the PACE handshake. Held
/// over to step 5 (the mutual-auth + KDF tail) which is landed in
/// the next M3 commit.
#[expect(
    missing_debug_implementations,
    reason = "PaceMidwayState holds the ephemeral private scalar `u_pcd` derived for this PACE session; deriving Debug would route a secret scalar into any `{:?}` / dbg!() call by accident. Manual omission is the safer default."
)]
#[non_exhaustive]
pub struct PaceMidwayState {
    /// Mapped generator G' = s*G + H. Step 4 used this; step 5
    /// keeps it for the auth-tag computation if needed.
    pub mapped_g: AffinePoint,
    /// Card's public point `V_picc` from step 4. Step 5 MACs over its
    /// encoded form to produce `T_PCD`.
    pub v_picc: AffinePoint,
    /// Our ephemeral private scalar from step 4. Step 5 derives the
    /// shared secret K = `u_pcd` * `V_picc` and passes K's x-coordinate
    /// through the KDF.
    pub u_pcd: U384,
    /// Our public point `U_pcd` from step 4. Step 5's symmetric path:
    /// the card MACs over `encode(U_pcd)` to produce `T_PICC`, which we
    /// verify against its 86 reply.
    pub u_pcd_pub: AffinePoint,
}

/// Drive the full PACE-with-CAN handshake. `can` is the 6-digit
/// number on the front of the card. Returns session keys + SSC for
/// SM.
///
/// Context precondition: the card must be at MF level. FINEID
/// cards refuse the opening MSE:Set AT with SW=0x6985 from an
/// applet context (observed live over `CoreNFC`, where discovery
/// leaves the eMRTD applet selected); send SELECT MF first --
/// `pkcs15::Pkcs15Ops::select_mf` -- when the prior session
/// state is unknown.
///
/// This is the public PACE entry point for transport adapters:
/// on success, wrap the same transport in
/// `secure_messaging::SmTransport::new(transport, session)` and
/// run the protected command chain through that. On failure the
/// transport is returned to the caller untouched (the `&mut`
/// borrow ends); whether the card is still in a usable state
/// depends on the failure. A wrong CAN consumes no retry counter,
/// but the card can suspend the password until a power reset; a
/// card reset ends the session entirely.
///
/// Thales `MultiApp` v5 also applies a progressive delay after
/// unsuccessful CAN-PACE attempts. Callers must not retry automatically;
/// see `doc/bugs/2026-08-09-thales-can-pace-delay.md`.
///
/// # Errors
/// Transport, BER-decode, card status-word, off-curve-point, or
/// auth-tag mismatch failures encountered during the five PACE
/// rounds; see [`PaceError`]. `Sw(_, 0x6300)` and `AuthMismatch`
/// both mean the CAN-derived key disagreed with the card: i.e.
/// wrong CAN (the mapping `emrtd::read_personal_data` applies).
#[inline]
pub fn run_pace_with_can<T: CardTransport>(
    transport: &mut T,
    can: crate::can::Can,
) -> Result<PaceSession, PaceError<TxError<T>>> {
    let state = run_pace_with_can_through_step_4(transport, can)?;
    run_pace_step_5(transport, state)
}

/// Internal: runs steps 1-4. Useful as its own entry point so a
/// hardware-gated integration test can verify the four GA rounds
/// land cleanly before step 5 is in.
///
/// # Errors
/// As for [`run_pace_with_can`], but only the step-1-to-4 subset.
#[inline]
pub(crate) fn run_pace_with_can_through_step_4<T: CardTransport>(
    transport: &mut T,
    can: crate::can::Can,
) -> Result<PaceMidwayState, PaceError<TxError<T>>> {
    set_authentication_template(transport, PASSWORD_REF_CAN)?;
    let nonce_s = get_encrypted_nonce(transport, can)?;
    map_nonce_and_key_agreement(transport, &nonce_s)
}

// MARK: - Step 1: MSE:Set AT
//
// `00 22 C1 A4 LC 80 0A <oid-body> 83 01 <pw-ref> 84 01 <domain-ref>`
// Card responds 0x9000.

/// Step 1 of the PACE protocol: announce the algorithm,
/// password reference, and domain parameters to the card.
///
/// ICAO 9303 Part 11 §4.4.3 / BSI TR-03110-3 §B.11.1. The MSE:
/// Set AT command pins the OID for `id-PACE-ECDH-GM-AES-CBC-
/// CMAC-256`, the password slot (CAN, MRZ, PIN, PUK), and the
/// EC domain (brainpoolP384r1 for FINEID). The card validates
/// the algorithm-password-domain triple before any keying
/// material is exchanged; a `6A80`/`6A88` here means the card
/// won't run PACE with the requested configuration.
fn set_authentication_template<T: CardTransport>(
    transport: &mut T,
    password_ref: u8,
) -> Result<(), PaceError<TxError<T>>> {
    let mut enc = ber::BerEncoder::with_capacity(20);
    enc.push_tlv(tags::MSE_MECHANISM, PACE_MECHANISM_OID.as_bytes());
    enc.push_tlv(tags::MSE_PASSWORD, [password_ref]);
    enc.push_tlv(tags::MSE_DOMAIN, [DOMAIN_REF_BRAINPOOL_P384_R1]);

    let apdu = commands::MseSetAt { data: enc.finish() }.into_apdu();
    let r = transport
        .transmit(apdu.as_bytes())
        .map_err(PaceError::Transport)?;
    if !r.is_ok() {
        return Err(PaceError::Sw("MSE:Set AT", r.sw()));
    }
    Ok(())
}

// MARK: - Step 2: Encrypted nonce
//
// Request: `00 86 00 00 02 7C 00 00`
// Response: `7C L 80 10 <z> 9000`
// Decrypt s = AES-256-CBC(K_pi, IV=0, z), where K_pi = KDF(CAN, c=3).

/// Step 2 of PACE: fetch + decrypt the card's nonce `s`.
///
/// ICAO 9303 Part 11 §4.4.3.3 / BSI TR-03110-3 §B.11.2. The
/// card emits an AES-CBC ciphertext under `K_pi = KDF(CAN,
/// c=3)`; refineid recomputes `K_pi` from the operator-supplied
/// CAN and decrypts. The 16-byte nonce is the input to the
/// step-3 generic-mapping computation. A wrong CAN here
/// produces an `s` that won't match the card's curve point
/// later -- the card never decrements a retry counter on this
/// step; the only signal is the eventual step-5 auth-tag mismatch.
fn get_encrypted_nonce<T: CardTransport>(
    transport: &mut T,
    can: crate::can::Can,
) -> Result<[u8; NONCE_LEN], PaceError<TxError<T>>> {
    // 7C 00 - empty Dynamic Authentication Data.
    let request_payload = ber::tlv(tags::DYNAMIC_AUTH, []);
    let apdu = PaceHelpers::wrap_general_authenticate(true, &request_payload);
    let r = transport.transmit(&apdu).map_err(PaceError::Transport)?;
    if !r.is_ok() {
        return Err(PaceError::Sw("GA-1 encrypted nonce", r.sw()));
    }
    let outer = BerTlv::<DynamicAuthData>::parse(&r.body)?;
    let inner = BerTlv::<EncryptedNonce>::parse(outer.value)?;
    if inner.value.len() != NONCE_LEN {
        return Err(PaceError::UnexpectedResponse(
            "encrypted nonce wrong length",
        ));
    }

    // K_pi = KDF(CAN, c=3). The CAN bytes are ASCII digits per BSI
    // TR-03110-3 §A.5.1.1; we just hand them to the KDF as-is.
    let k_pi = kdf_aes256(can.as_bytes(), KdfParam::Password);
    // ^ `can.as_bytes()` returns &[u8; 6]; coerces to &[u8] for the KDF.
    // The PACE step-2 encrypted nonce is an AES-CBC ciphertext;
    // wrap into the typed container before decrypt.
    let cipher = Ciphertext::<AesCbc>::new(inner.value.to_vec());
    // NONCE_LEN == AES_BLOCK == 16; the length check above guarantees the
    // ciphertext is exactly one block, so alignment cannot fail -- map it to
    // a typed error anyway (fail-closed; `expect()` is banned workspace-wide).
    let plaintext = aes256_cbc_decrypt_no_padding(k_pi.as_bytes(), &ZERO_IV, &cipher)
        .map_err(|_unaligned| PaceError::UnexpectedResponse("encrypted nonce not block-aligned"))?;
    if plaintext.len() != NONCE_LEN {
        return Err(PaceError::UnexpectedResponse(
            "decrypted nonce wrong length",
        ));
    }
    let mut s = [0_u8; NONCE_LEN];
    s.copy_from_slice(&plaintext);
    Ok(s)
}

// MARK: - Steps 3 + 4: Map nonce + key agreement
//
// We fold these into one function because they share state: the
// mapped generator G' is computed from step 3's exchange and used
// in step 4. Both steps follow the same 7C-wrapped public-key
// exchange shape - only the inner tag differs (0x81/0x82 for map,
// 0x83/0x84 for key-agree).
//
// Returns (mapped_generator_G', card_pubkey_V_for_auth_tag) - V
// is needed by step 5 to compute T_PCD = MAC(K_mac, encode(V)).

/// Steps 3 + 4 of PACE: nonce-mapping and ephemeral key
/// agreement, fused into one function.
///
/// ICAO 9303 Part 11 §4.4.3.4-§4.4.3.5 / BSI TR-03110-3
/// §B.11.3-§B.11.4. Step 3 maps the static curve generator `G`
/// to a session-specific `G' = s*G + H`, where `H` is the
/// shared point derived from `nonce_s`. Step 4 uses `G'` to run
/// an ECDH on a fresh ephemeral key pair. Fused because step 4
/// depends on `G'` from step 3, and isolating the intermediate
/// state buys nothing for the audit reader. Returns `G'` and
/// the card's authenticated public-key `V` for the step-5
/// auth-tag computation.
fn map_nonce_and_key_agreement<T: CardTransport>(
    transport: &mut T,
    nonce_s: &[u8; NONCE_LEN],
) -> Result<PaceMidwayState, PaceError<TxError<T>>> {
    // --- Step 3: map the nonce ---

    // Ephemeral private key x_pcd  in  [1, n). Random + reject-resample.
    let x_pcd = random_scalar_mod_n()?;
    let x_pcd_pub = AffinePoint::generator().scalar_mul(&x_pcd);

    let our_x_bytes = x_pcd_pub
        .encode_uncompressed()
        .ok_or(PaceError::InvalidPoint)?;
    let payload = ber::tlv(tags::DYNAMIC_AUTH, ber::tlv(tags::MAP_PCD_PUB, our_x_bytes));
    let apdu = PaceHelpers::wrap_general_authenticate(true, &payload);
    let r = transport.transmit(&apdu).map_err(PaceError::Transport)?;
    if !r.is_ok() {
        return Err(PaceError::Sw("GA-2 map nonce", r.sw()));
    }
    let outer = BerTlv::<DynamicAuthData>::parse(&r.body)?;
    let card_y = BerTlv::<MappingDataOut>::parse(outer.value)?;
    let y_picc = AffinePoint::decode_uncompressed(card_y.value).ok_or(PaceError::InvalidPoint)?;

    // Shared point H = x_pcd * Y_picc. New base point G' = s*G + H.
    let h = y_picc.scalar_mul(&x_pcd);
    let s_scalar = PaceHelpers::scalar_from_nonce(nonce_s);
    let s_g = AffinePoint::generator().scalar_mul(&s_scalar);
    let mapped_g = s_g.add(&h);

    // --- Step 4: key agreement on G' ---

    let u_pcd = random_scalar_mod_n()?;
    let u_pcd_pub = mapped_g.scalar_mul(&u_pcd);

    let pcd_u_bytes = u_pcd_pub
        .encode_uncompressed()
        .ok_or(PaceError::InvalidPoint)?;
    let payload = ber::tlv(tags::DYNAMIC_AUTH, ber::tlv(tags::KA_PCD_PUB, pcd_u_bytes));
    let apdu = PaceHelpers::wrap_general_authenticate(true, &payload);
    let r = transport.transmit(&apdu).map_err(PaceError::Transport)?;
    if !r.is_ok() {
        return Err(PaceError::Sw("GA-3 key agreement", r.sw()));
    }
    let outer = BerTlv::<DynamicAuthData>::parse(&r.body)?;
    let card_v = BerTlv::<KeyAgreeOut>::parse(outer.value)?;
    let v_picc = AffinePoint::decode_uncompressed(card_v.value).ok_or(PaceError::InvalidPoint)?;

    Ok(PaceMidwayState {
        mapped_g,
        v_picc,
        u_pcd,
        u_pcd_pub,
    })
}

// MARK: - Step 5: mutual authentication + session-key derivation
//
// Final GENERAL AUTHENTICATE round, CLA=0x00 (no chaining):
//
//   K_x   = x-coordinate of (u_pcd * V_picc), 48 big-endian bytes
//   K_enc = KDF(K_x, c=1)
//   K_mac = KDF(K_x, c=2)
//   T_PCD  = AES-256-CMAC(K_mac, PaceHelpers::encode_auth_token(V_picc))[..8]
//   T_PICC = AES-256-CMAC(K_mac, PaceHelpers::encode_auth_token(U_pcd))[..8]   (expected)
//
// `encode_auth_token` is BSI TR-03110-3 §A.2.4's Authentication Token
// Input: `7F49 L (06 || L_OID || OID)(86 || L_pt || 04||X||Y)`. We
// send `7C L 85 08 <T_PCD>` and expect `7C L 86 08 <T_PICC>`. On
// match, return `PaceSession { K_enc, K_mac, ssc=[0;16] }`.

/// Run the final round of PACE - mutual auth tag exchange + session
/// key derivation. Consumes the midway state from steps 1-4.
///
/// # Errors
/// Transport / BER / status-word failures, an off-curve shared
/// point, or [`PaceError::AuthMismatch`] if the card's `T_PICC`
/// does not match the locally recomputed tag.
// `PaceMidwayState` is intentionally consumed by value: the
// midway ephemeral scalars / points are dead after step 5 and
// reusing them would be a protocol bug. The compiler's move
// check is the enforcement -- once step 5 returns, the state
// has been moved and the caller's binding is unusable. A
// `&PaceMidwayState` parameter would compile but would silently
// allow a caller to invoke step 5 twice on the same state,
// which the protocol forbids.
#[expect(
    clippy::needless_pass_by_value,
    reason = "PaceMidwayState consumed by value so Rust's move-check forbids step-5-twice-on-the-same-state, which the PACE protocol forbids; the lint's body-level scan can't see the anti-reuse policy (Rule E1 sibling -- ephemeral PACE scalars are key-material-adjacent)"
)]
#[inline]
pub(crate) fn run_pace_step_5<T: CardTransport>(
    transport: &mut T,
    state: PaceMidwayState,
) -> Result<PaceSession, PaceError<TxError<T>>> {
    // Shared point K = u_pcd * V_picc. Its x-coordinate (48B BE) is
    // the input to the KDF for both K_enc and K_mac.
    let shared = state.v_picc.scalar_mul(&state.u_pcd);
    let (k_x, _k_y) = shared.coords.ok_or(PaceError::InvalidPoint)?;
    // The raw x-coordinate is unprotected ECDH keying material.
    // Hold the serialized bytes in a zeroize-on-drop buffer so they
    // are wiped once the KDF has consumed them, rather than left as
    // stack residue for the rest of the function. (crypto-bigint's
    // `EncodedUint` is not itself `Zeroize`, so copy into a `Vec`.)
    let k_x_bytes = Zeroizing::new(k_x.to_be_bytes().as_ref().to_vec());

    let k_enc = kdf_aes256(&k_x_bytes, KdfParam::Encryption);
    let k_mac = kdf_aes256(&k_x_bytes, KdfParam::Mac);

    // T_PCD: prove knowledge of K_mac by MACing the *card's* public
    // point. Card returns T_PICC over *our* point - we recompute and
    // compare in constant time.
    let token_for_card =
        PaceHelpers::encode_auth_token(&state.v_picc).ok_or(PaceError::InvalidPoint)?;
    let t_pcd = aes256_cmac_truncated(k_mac.as_bytes(), &token_for_card);

    let payload = ber::tlv(
        tags::DYNAMIC_AUTH,
        ber::tlv(tags::AUTH_TOKEN_PCD, t_pcd.as_bytes()),
    );
    let apdu = PaceHelpers::wrap_general_authenticate(false, &payload);
    let r = transport.transmit(&apdu).map_err(PaceError::Transport)?;
    if !r.is_ok() {
        return Err(PaceError::Sw("GA-4 mutual auth", r.sw()));
    }

    let outer = BerTlv::<DynamicAuthData>::parse(&r.body)?;
    let card_tag = BerTlv::<AuthTokenOut>::parse(outer.value)?;
    if card_tag.value.len() != 8 {
        return Err(PaceError::UnexpectedResponse("card auth tag wrong length"));
    }

    let token_for_us =
        PaceHelpers::encode_auth_token(&state.u_pcd_pub).ok_or(PaceError::InvalidPoint)?;
    let expected = aes256_cmac_truncated(k_mac.as_bytes(), &token_for_us);
    if expected.as_bytes().ct_eq(card_tag.value).unwrap_u8() != 1 {
        return Err(PaceError::AuthMismatch);
    }

    Ok(PaceSession {
        k_enc,
        k_mac,
        ssc: Ssc::INITIAL,
    })
}

/// BSI TR-03110-3 §A.2.4 Authentication Token Input over a public
/// point with the PACE OID:
///
/// ```text
/// 7F49 || L || 06 || L_OID || OID || 86 || L_pt || (04 || X || Y)
/// ```
///
/// Returns `None` if the point is the point at infinity (which never
/// happens in a healthy PACE handshake - but we'd rather flag it than
/// MAC a degenerate input).
/// Helpers hosted on a unit struct (typing-discipline: no
/// free fns with borrowed parameters; see
/// `doc/typing-discipline.md`).
struct PaceHelpers;

impl PaceHelpers {
    /// Build the PACE auth-token MAC input over `point`.
    ///
    /// BSI TR-03110-3 §A.2.4. Wraps the public-key data object
    /// (`7F49`) around an `OID || EC point` payload; the MAC of
    /// this byte sequence is the PACE step-5 auth tag the card
    /// and terminal cross-check. Returns `None` when the point
    /// is the point at infinity -- a degenerate handshake the
    /// caller treats as a hard fail rather than MAC'ing an
    /// out-of-band value.
    fn encode_auth_token(point: &AffinePoint) -> Option<Vec<u8>> {
        let pt_bytes = point.encode_uncompressed()?; // 0x04 || X || Y, 97 bytes
        // Capacity hint only: OID body is the 10-byte compile-time
        // `PACE_MECHANISM_OID`; pt_bytes is at
        // most ~97 bytes (SEC1 uncompressed P-384). Sum is well
        // under `usize::MAX`; use `saturating_add` so a hint
        // overflow couldn't crash even if the bounds ever shifted.
        let cap = 2_usize
            .saturating_add(PACE_MECHANISM_OID.as_bytes().len())
            .saturating_add(2)
            .saturating_add(pt_bytes.as_ref().len());
        let mut inner = ber::BerEncoder::with_capacity(cap);
        inner.push_tlv(tags::ASN1_OID, PACE_MECHANISM_OID.as_bytes());
        inner.push_tlv(tags::PK_EC_POINT, pt_bytes);
        Some(ber::tlv2(tags::PK_DATA_OBJECT, inner.finish()))
    }

    /// Wrap GENERAL AUTHENTICATE: APDU header `00/10 86 00 00`,
    /// payload is one TLV (the `7C` envelope), Le=00 to request
    /// response.
    fn wrap_general_authenticate(chain: bool, payload: &[u8]) -> Vec<u8> {
        commands::GeneralAuthenticate {
            chain,
            payload: payload.to_vec(),
        }
        .into_apdu()
        .into_bytes()
    }
}

/// Generate a random scalar in [1, n). Rejection sampling: pull 48
/// bytes, accept only if non-zero and less than n.
fn random_scalar_mod_n<TE>() -> Result<U384, PaceError<TE>> {
    let n = brainpool_n();
    loop {
        let mut buf = [0_u8; 48];
        crate::rng::fill(&mut buf).map_err(PaceError::Random)?;
        let cand = U384::from_be_slice(&buf);
        let zero = U384::ZERO;
        if cand != zero && cand < n {
            return Ok(cand);
        }
    }
}

impl PaceHelpers {
    /// Lift a 16-byte AES nonce to a 384-bit scalar. The
    /// mapping is "left-pad with zeros to 48 bytes, big-endian";
    /// the result is always less than `n` because
    /// 2^128 << n ~= 2^383.
    fn scalar_from_nonce(s: &[u8; NONCE_LEN]) -> U384 {
        let mut padded = [0_u8; 48];
        padded[48 - NONCE_LEN..].copy_from_slice(s);
        U384::from_be_slice(&padded)
    }

    /// Compact 11-character hex preview of `bytes` (`AABBCCDD...EEFFGGHH`).
    ///
    /// Used inside PACE trace events to identify a curve point
    /// or session-key fingerprint without leaking the full key
    /// material to the log stream (Rule E6). Never appears in
    /// production logs for PIN-bearing types.
    fn fingerprint(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        let mut s = String::with_capacity(11);
        for b in bytes.iter().take(4) {
            let _fmt: core::fmt::Result = write!(s, "{b:02x}");
        }
        s.push_str("...");
        let tail_start = bytes.len().saturating_sub(4);
        // `tail_start <= bytes.len()` by construction; slice never panics.
        if let Some(tail) = bytes.get(tail_start..) {
            for b in tail {
                let _fmt: core::fmt::Result = write!(s, "{b:02x}");
            }
        }
        s
    }

    /// Hex-encode `bytes` as a `String` (no separators, lower-
    /// case), used by PACE trace events for short fixed-size
    /// buffers (SSC, `K_enc` fingerprint, etc.).
    ///
    /// Distinct from [`Self::fingerprint`] in that the full
    /// content is rendered; callers must ensure the bytes are
    /// not secret material before invoking. The capacity hint is
    /// `saturating_mul`'d to keep an arithmetic-overflow lint
    /// quiet even though no PACE buffer is large enough to wrap.
    fn hex_short(bytes: &[u8]) -> String {
        use core::fmt::Write as _;
        // `bytes.len() * 2` is a capacity hint; SSC and other PACE
        // byte buffers in this module are tens of bytes max, well
        // below `usize::MAX / 2`. `saturating_mul` so a hint
        // overflow could never panic even if the bound shifted.
        let mut s = String::with_capacity(bytes.len().saturating_mul(2));
        for b in bytes {
            let _fmt: core::fmt::Result = write!(s, "{b:02x}");
        }
        s
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::atr::{Atr, AtrError, MINIMAL_DIRECT_ATR};

    /// Constants sanity: the OID body is the right length (10 bytes,
    /// the body of 0.4.0.127.0.7.2.2.4.2.4).
    #[test]
    fn pace_oid_length() {
        assert_eq!(PACE_MECHANISM_OID.as_bytes().len(), 10);
    }

    /// MSE:Set AT data layout. The trailing `84 01 10` carries
    /// FINEID's card-specific Brainpool P-384 paramId (see the
    /// comment on `DOMAIN_REF_BRAINPOOL_P384_R1`); the BSI
    /// TR-03110-3 example uses 0x0B here, FINEID uses 0x10.
    #[test]
    fn mse_set_at_payload_layout() {
        let mut enc = ber::BerEncoder::default();
        enc.push_tlv(tags::MSE_MECHANISM, PACE_MECHANISM_OID.as_bytes());
        enc.push_tlv(tags::MSE_PASSWORD, [PASSWORD_REF_CAN]);
        enc.push_tlv(tags::MSE_DOMAIN, [DOMAIN_REF_BRAINPOOL_P384_R1]);
        let data = enc.finish();
        assert_eq!(
            hex::encode(&data),
            "800a04007f000702020402048301028401\
             10",
        );
    }

    /// Random scalars are non-zero and less than n.
    #[test]
    fn random_scalar_in_range() {
        for _ in 0..16 {
            let k: U384 = random_scalar_mod_n::<core::convert::Infallible>()
                .expect("scalar generation succeeds");
            assert_ne!(k, U384::ZERO);
            assert!(k < brainpool_n());
        }
    }

    /// Nonce-to-scalar lift round-trips a known value.
    #[test]
    fn scalar_from_nonce_zero_pad_be() {
        // Distinct byte per position (1, 2, ..., 16), not an
        // all-equal fill -- so the assertion catches a byte-order /
        // placement bug, not merely the bytes' presence. Fixed,
        // not random: a unit test must reproduce on failure.
        let nonce: [u8; 16] = core::array::from_fn(|i| u8::try_from(i + 1).unwrap_or(0));
        let k = PaceHelpers::scalar_from_nonce(&nonce);
        // A 16-byte nonce lifts to a 48-byte big-endian scalar: the
        // high 32 bytes are zero, the low 16 are the nonce verbatim
        // and in order.
        let bytes = k.to_be_bytes();
        assert!(bytes[..32].iter().all(|&b| b == 0));
        assert_eq!(&bytes[32..], &nonce[..]);
    }

    /// The Authentication Token Input wraps the PACE OID and the
    /// uncompressed point in a single `7F49` template:
    ///
    /// ```text
    /// 7F49 L_outer
    ///   06 L_oid <OID body>             // 10-byte OID body
    ///   86 L_pt  04 || X (48B) || Y (48B)
    /// ```
    ///
    /// Inner = 12 (OID DO) + 99 (point DO) = 111 bytes - short-form
    /// length (< 128). Outer wrap is `7F 49 6F <111 bytes>` = 114.
    #[test]
    fn auth_token_input_layout() {
        let g = AffinePoint::generator();
        let token = PaceHelpers::encode_auth_token(&g).expect("generator encodes");

        // Outer template: 7F 49 6F ...
        assert_eq!(&token[0..2], &[0x7F, 0x49]);
        assert_eq!(token[2], 0x6F); // 111 inner bytes, short-form length
        assert_eq!(token.len(), 3 + 111);

        // OID DO: 06 0A <10-byte body>
        assert_eq!(token[3], 0x06);
        assert_eq!(token[4], 0x0A);
        assert_eq!(&token[5..15], PACE_MECHANISM_OID.as_bytes());

        // Point DO: 86 61 04 || X || Y  (97 = 1 + 48 + 48)
        assert_eq!(token[15], 0x86);
        assert_eq!(token[16], 0x61);
        assert_eq!(token[17], 0x04);
        let expected_pt = g.encode_uncompressed().expect("generator is not infinity");
        assert_eq!(&token[17..114], expected_pt.as_ref());
    }

    /// `run_pace_step_5` derives `K_enc`/`K_mac` deterministically from
    /// `K_x = x(u_pcd * V_picc)` and verifies the card's tag in
    /// constant time. This test runs the full step-5 path against an
    /// in-memory transport that plays the role of a card-side PACE
    /// peer - same shared secret, so its `T_PICC` must match what we'd
    /// recompute, and its KDF outputs must match ours.
    #[test]
    fn step_5_round_trip_against_synthetic_peer() {
        // A "card-side" private scalar v_picc; its public point is
        // V_picc = v * G. We use G as the mapped generator (i.e.
        // pretend steps 3+4 mapped trivially) - that's not what a
        // real card does, but the auth-tag derivation only depends
        // on the *resulting* points, not how they were obtained.
        let v_picc_scalar = U384::from_be_hex(
            "00000000000000000000000000000000\
             00000000000000000000000000000001\
             23456789ABCDEF0123456789ABCDEF01",
        );
        let u_pcd_scalar = U384::from_be_hex(
            "00000000000000000000000000000000\
             0000000000000000000000000000FEDC\
             BA9876543210FEDCBA9876543210FEDC",
        );
        let g = AffinePoint::generator();
        let v_picc = g.scalar_mul(&v_picc_scalar);
        let u_pcd_pub = g.scalar_mul(&u_pcd_scalar);

        // Card-side compute: K = v_picc * U_pcd; we (PCD-side)
        // compute K = u_pcd * V_picc. ECDH guarantees these are
        // the same point.
        let k_card = u_pcd_pub.scalar_mul(&v_picc_scalar);
        let k_pcd = v_picc.scalar_mul(&u_pcd_scalar);
        assert_eq!(k_card.coords, k_pcd.coords);

        // Card-side derives K_mac and produces T_PICC over our
        // public point.
        let k_x = k_card
            .coords
            .expect("shared ECDH point is not infinity")
            .0
            .to_be_bytes();
        let k_mac_card = kdf_aes256(k_x.as_ref(), KdfParam::Mac);
        let token_for_us =
            PaceHelpers::encode_auth_token(&u_pcd_pub).expect("PCD public point encodes");
        let t_picc = aes256_cmac_truncated(k_mac_card.as_bytes(), &token_for_us);

        // PCD-side will MAC over V_picc - that's T_PCD on the wire.
        let token_for_card =
            PaceHelpers::encode_auth_token(&v_picc).expect("card public point encodes");
        let t_pcd_expected = aes256_cmac_truncated(
            kdf_aes256(k_x.as_ref(), KdfParam::Mac).as_bytes(),
            &token_for_card,
        );

        // Build the script: one 7C-wrapped step-5 round.
        let request_payload = ber::tlv(
            tags::DYNAMIC_AUTH,
            ber::tlv(tags::AUTH_TOKEN_PCD, t_pcd_expected.as_bytes()),
        );
        let request_apdu = PaceHelpers::wrap_general_authenticate(false, &request_payload);
        let response_body = ber::tlv(
            tags::DYNAMIC_AUTH,
            ber::tlv(tags::AUTH_TOKEN_PICC, t_picc.as_bytes()),
        );

        let state = PaceMidwayState {
            mapped_g: g,
            v_picc,
            u_pcd: u_pcd_scalar,
            u_pcd_pub,
        };

        let mut tx = StepFiveMock {
            expected: request_apdu,
            response: ResponseApdu {
                body: response_body,
                sw1: 0x90,
                sw2: 0x00,
            },
            called: false,
        };
        let session = run_pace_step_5(&mut tx, state).expect("step 5 succeeds");
        assert!(tx.called);
        assert_eq!(session.ssc, Ssc::INITIAL);
        assert_eq!(
            session.k_enc.as_bytes(),
            kdf_aes256(k_x.as_ref(), KdfParam::Encryption).as_bytes()
        );
        assert_eq!(
            session.k_mac.as_bytes(),
            kdf_aes256(k_x.as_ref(), KdfParam::Mac).as_bytes()
        );
    }

    /// Step 5 rejects a tampered card tag in constant time.
    #[test]
    fn step_5_rejects_bad_card_tag() {
        let v_picc_scalar = U384::from_be_hex(
            "00000000000000000000000000000000\
             00000000000000000000000000000001\
             23456789ABCDEF0123456789ABCDEF01",
        );
        let u_pcd_scalar = U384::from_be_hex(
            "00000000000000000000000000000000\
             0000000000000000000000000000FEDC\
             BA9876543210FEDCBA9876543210FEDC",
        );
        let g = AffinePoint::generator();
        let v_picc = g.scalar_mul(&v_picc_scalar);
        let u_pcd_pub = g.scalar_mul(&u_pcd_scalar);
        let k_card = u_pcd_pub.scalar_mul(&v_picc_scalar);
        let k_x = k_card
            .coords
            .expect("shared ECDH point is not infinity")
            .0
            .to_be_bytes();
        let k_mac = kdf_aes256(k_x.as_ref(), KdfParam::Mac);
        let token_card =
            PaceHelpers::encode_auth_token(&v_picc).expect("card public point encodes");
        let t_pcd = aes256_cmac_truncated(k_mac.as_bytes(), &token_card);
        let request = PaceHelpers::wrap_general_authenticate(
            false,
            &ber::tlv(
                tags::DYNAMIC_AUTH,
                ber::tlv(tags::AUTH_TOKEN_PCD, t_pcd.as_bytes()),
            ),
        );

        // Wrong T_PICC: flip a bit.
        let mut bad_tag = [0_u8; 8];
        bad_tag[0] = 0xFF;
        let response_body = ber::tlv(tags::DYNAMIC_AUTH, ber::tlv(tags::AUTH_TOKEN_PICC, bad_tag));

        let state = PaceMidwayState {
            mapped_g: g,
            v_picc,
            u_pcd: u_pcd_scalar,
            u_pcd_pub,
        };
        let mut tx = StepFiveMock {
            expected: request,
            response: ResponseApdu {
                body: response_body,
                sw1: 0x90,
                sw2: 0x00,
            },
            called: false,
        };
        let err =
            run_pace_step_5(&mut tx, state).expect_err("flipped T_PICC bit fails the tag check");
        assert!(matches!(err, PaceError::AuthMismatch));
    }

    use crate::transport::ResponseApdu;

    /// Tiny in-test transport - one expected APDU, one response. The
    /// crate's full `MockTransport` is private to its `transport`
    /// module's test scope; replicating the bare minimum here is
    /// cleaner than punching holes in module visibility.
    struct StepFiveMock {
        expected: Vec<u8>,
        response: ResponseApdu,
        called: bool,
    }

    impl CardTransport for StepFiveMock {
        type Error = String;
        fn transmit_outcome(
            &mut self,
            apdu: &crate::transport::CommandApdu,
        ) -> Result<crate::transport::TransportOutcome, Self::Error> {
            if self.called {
                return Err("StepFiveMock: called twice".into());
            }
            if apdu.as_bytes() != self.expected {
                return Err(format!(
                    "StepFiveMock: expected {} but got {}",
                    hex::encode(&self.expected),
                    hex::encode(apdu.as_bytes()),
                ));
            }
            self.called = true;
            Ok(crate::transport::TransportOutcome::Response(
                self.response.clone(),
            ))
        }
        fn atr(&self) -> Result<Atr, AtrError> {
            Atr::new(MINIMAL_DIRECT_ATR)
        }
    }
}
