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

//! Typed APDU commands for the PACE protocol.
//!
//! PACE uses two ISO 7816-4 commands:
//!
//! - `MSE:Set AT` (`00 22 C1 A4`) at the start, carrying the
//!   protocol OID + password reference + domain parameter ID
//!   in BER-TLV form. Selects the PACE variant the card will
//!   run for this session.
//! - `GENERAL AUTHENTICATE` (`INS=0x86 P1=0x00 P2=0x00`) four
//!   times, each carrying a different payload (encrypted nonce,
//!   mapped point exchange, key agreement, mutual auth). The
//!   first three rounds set the command-chaining bit
//!   (`CLA=0x10`); the last round uses `CLA=0x00`.
//!
//! Each typed struct here owns the byte serialisation; the
//! protocol driver in [`crate::pace`] picks the right command
//! for each step and reads the typed result.

use crate::transport::CommandApdu;

/// ISO 7816-4 short-form command APDU header: CLA + INS + P1 + P2.
const APDU_HEADER_LEN: usize = 4;
/// ISO 7816-4 CLA byte for a chained `GENERAL AUTHENTICATE` step
/// (PACE rounds 1-3 set the chaining bit).
const CLA_CHAINED_GA: u8 = 0x10;
/// ISO 7816-4 CLA byte for the final (non-chained) `GENERAL
/// AUTHENTICATE` step (PACE round 4 / 5).
const CLA_FINAL_GA: u8 = 0x00;
/// `Le = 0` in ISO 7816-4 short form means "return all available
/// response bytes up to 256". Used by PACE GENERAL AUTHENTICATE.
const LE_AS_MUCH_AS_CARD_HAS: u8 = 0x00;

/// `GENERAL AUTHENTICATE` (`INS=0x86 P1=0x00 P2=0x00`) carrying
/// a step-specific BER-TLV payload wrapped in `7C L <inner>`.
///
/// `chain == true` sets the command-chaining bit on CLA
/// (`0x10`) -- used for PACE steps 1-3 to tell the card more
/// command-chaining APDUs follow.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct GeneralAuthenticate {
    /// `true` for the chained steps (1-3); `false` for the
    /// final step.
    pub chain: bool,
    /// `7C`-wrapped payload as built by the protocol driver.
    pub payload: Vec<u8>,
}

impl GeneralAuthenticate {
    /// ISO 7816-8 `GENERAL AUTHENTICATE` instruction.
    pub const INS: u8 = 0x86;
    /// P1: reserved (`0x00`).
    pub const P1: u8 = 0x00;
    /// P2: reserved (`0x00`).
    pub const P2: u8 = 0x00;

    /// Serialise into the wire APDU.
    ///
    /// # Panics
    /// If `self.payload.len() > 255`. PACE payloads fit comfortably
    /// (`~100` bytes max for the largest step).
    #[inline]
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        // Length bound enforced by assert; the subsequent
        // `try_from` is infallible (fallback to u8::MAX = 255 is
        // the asserted upper bound) and the saturating arithmetic
        // is a tightness check, not a safety net.
        assert!(
            self.payload.len() <= 255,
            "GENERAL AUTHENTICATE payload too large for short Lc"
        );
        let cla = if self.chain {
            CLA_CHAINED_GA
        } else {
            CLA_FINAL_GA
        };
        let lc = u8::try_from(self.payload.len()).unwrap_or(u8::MAX);
        let cap = APDU_HEADER_LEN
            .saturating_add(1) // Lc
            .saturating_add(self.payload.len())
            .saturating_add(1); // Le
        let mut out = Vec::with_capacity(cap);
        out.extend_from_slice(&[cla, Self::INS, Self::P1, Self::P2]);
        out.push(lc);
        out.extend_from_slice(&self.payload);
        out.push(LE_AS_MUCH_AS_CARD_HAS);
        CommandApdu::new(out)
    }
}

/// `MSE:Set Authentication Template` (`00 22 C1 A4 Lc <data>`).
///
/// The `data` field is a BER-TLV concatenation produced by the
/// caller (OID DO `80`, password-ref DO `83`, domain-ref DO
/// `84`); refineid's PACE driver assembles those tags before
/// constructing this command. A future iteration will move the
/// TLV assembly inside the struct, but that requires typed OID
/// and `PaceDomain` values that the protocol layer doesn't have
/// yet.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MseSetAt {
    /// Pre-assembled BER-TLV data field for the SET-AT command:
    /// `80 LL <oid_body> 83 01 <password_ref>` (+ `84 01 <domain>`
    /// when needed). Tier 0 `Vec<u8>` -- a tighter form would be
    /// a `MseSetAtData` struct over (oid, `password_ref`, domain).
    pub data: Vec<u8>,
}

impl MseSetAt {
    /// ISO 7816-4 class byte `0x00`.
    pub const CLA: u8 = 0x00;
    /// ISO 7816-8 `MANAGE SECURITY ENVIRONMENT` instruction.
    pub const INS: u8 = 0x22;
    /// P1: SET for verify (`0xC1`).
    pub const P1: u8 = 0xC1;
    /// P2: Authentication Template (`0xA4`).
    pub const P2: u8 = 0xA4;

    /// Serialise into the wire APDU.
    ///
    /// # Panics
    /// If `self.data.len() > 255`. Refineid's PACE driver builds
    /// data fields of ~20 bytes (one short OID DO plus two
    /// 1-byte DOs), well under the short-form Lc limit; the
    /// caller-side contract bounds the length to fit `u8`.
    #[inline]
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        // Single source of truth for the length bound: an assert
        // followed by `u8::try_from` infallible (since the assert
        // proved the bound). After this, every downstream
        // arithmetic op is bounded by u8::MAX so the
        // `saturating_add` chain is a tightness check, not a
        // safety net.
        assert!(self.data.len() <= 255, "MSE:Set AT data field too large");
        let lc = u8::try_from(self.data.len()).unwrap_or(u8::MAX);
        let cap = APDU_HEADER_LEN
            .saturating_add(1)
            .saturating_add(self.data.len());
        let mut out = Vec::with_capacity(cap);
        out.extend_from_slice(&[Self::CLA, Self::INS, Self::P1, Self::P2]);
        out.push(lc);
        out.extend_from_slice(&self.data);
        CommandApdu::new(out)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn mse_set_at_round_trips() {
        let apdu = MseSetAt {
            data: vec![0x80, 0x01, 0xAA],
        }
        .into_apdu();
        assert_eq!(
            apdu.as_bytes(),
            &[0x00, 0x22, 0xC1, 0xA4, 0x03, 0x80, 0x01, 0xAA]
        );
    }

    #[test]
    fn general_authenticate_chained_sets_cla_0x10() {
        let apdu = GeneralAuthenticate {
            chain: true,
            payload: vec![0x7C, 0x00],
        }
        .into_apdu();
        assert_eq!(
            apdu.as_bytes(),
            &[0x10, 0x86, 0x00, 0x00, 0x02, 0x7C, 0x00, 0x00]
        );
    }

    #[test]
    fn general_authenticate_final_uses_cla_0x00() {
        let apdu = GeneralAuthenticate {
            chain: false,
            payload: vec![0x7C, 0x00],
        }
        .into_apdu();
        assert_eq!(
            apdu.as_bytes(),
            &[0x00, 0x86, 0x00, 0x00, 0x02, 0x7C, 0x00, 0x00]
        );
    }
}
