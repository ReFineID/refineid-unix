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

//! FINEID card identity: types, classification by ATR/ATS,
//! and the canonical strings refineid emits for each card.
//!
//! Canonical taxonomy:
//! [`doc/fineid-card-models.md`](../../../../doc/fineid-card-models.md).
//! This module is the type-system projection of that doc;
//! every variant, accessor, and ATR/ATS literal here has a
//! corresponding entry in the table there. Adding a model
//! means updating both.

// Library-facade re-export: `fineid_card::Atr` is the entry
// point external consumers reach for FINEID card-model
// classification.  Atr / AtrError / the length constants are
// canonically defined in `crate::atr`; re-exporting them here
// collects all the model-classification types in one namespace
// (matches the lib.rs doc-link layout at lines 42-46).
// Per-item `#[expect(clippy::pub_use)]` is rejected by rustc as
// "useless lint attribute" -- the lint fires at module scope,
// not on the use-item -- so the suppression lives as a
// module-level inner attribute here.
#![expect(
    clippy::pub_use,
    reason = "library-facade pattern: the FINEID-model docs collect Atr / AtrError / ATR_MAX_LEN / ATR_MIN_LEN under fineid_card::* so external consumers don't split their imports between two adjacent modules"
)]

use core::fmt;

use crate::atr::HistoricalDataObject;
pub use crate::atr::{ATR_MAX_LEN, ATR_MIN_LEN, Atr, AtrError};

/// FINEID interpretation of the ISO 7816-4 pre-issuing data
/// (compact-TLV tag 6), per FINEID S4-1 §3.3.1.
///
/// ISO 7816-4 leaves the pre-issuing interior to the card
/// manufacturer/personalizer; the generic layer keeps it as opaque
/// bytes ([`HistoricalDataObject::PreIssuingData`]). This is the
/// FINEID layer's reading: a 5-byte block naming the product family
/// and versions. The field names follow FINEID's *contact*-interface
/// gloss (§3.3.1); FINEID's contactless table (§3.3.2) labels the
/// same five bytes more coarsely as "hardmask identification", so
/// treat the finer names as FINEID's intent, not an ISO guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FineidPreIssuingData {
    /// Byte 1 -- family name marker (`B0h` on observed FINEID cards).
    pub family_name: u8,
    /// Byte 2 -- product name marker (`85h`).
    pub product_name: u8,
    /// Byte 3 -- OS version. Distinguishes the generation:
    /// `05h` = `MultiApp` v5.0 (Thales), `04h` = v4.2 (Gemalto).
    pub os_version: u8,
    /// Byte 4 -- program version.
    pub program_version: u8,
    /// Byte 5 -- chip identifier (varies by chip revision).
    pub chip_id: u8,
}

impl FineidPreIssuingData {
    /// Build from the five pre-issuing value bytes. A fixed-size
    /// array (not a slice) keeps the raw bytes off the signature
    /// surface -- the sanctioned typing-discipline conversion shape.
    #[inline]
    #[must_use]
    pub const fn from_array(bytes: [u8; 5]) -> Self {
        let [
            family_name,
            product_name,
            os_version,
            program_version,
            chip_id,
        ] = bytes;
        Self {
            family_name,
            product_name,
            os_version,
            program_version,
            chip_id,
        }
    }
}

impl Atr {
    /// The FINEID pre-issuing data (compact-TLV tag 6, 5 bytes), if
    /// present and well-formed.
    ///
    /// Reads the generic ISO [`HistoricalDataObject::PreIssuingData`]
    /// and applies the FINEID §3.3.1 interpretation. `None` when the
    /// historical bytes carry no 5-byte pre-issuing object (e.g. a
    /// non-FINEID card).
    #[must_use]
    pub fn fineid_pre_issuing(&self) -> Option<FineidPreIssuingData> {
        self.historical_bytes()
            .data_objects()
            .into_iter()
            .find_map(|object| {
                let HistoricalDataObject::PreIssuingData(bytes) = object else {
                    return None;
                };
                match bytes.as_slice() {
                    &[b0, b1, b2, b3, b4] => {
                        Some(FineidPreIssuingData::from_array([b0, b1, b2, b3, b4]))
                    }
                    _ => None,
                }
            })
    }

    /// Classify this ATR to a known FINEID card model.
    ///
    /// Field-driven (FINEID S4-1 §3.3.1): reads the typed pre-issuing
    /// data's family / product / OS-version markers rather than
    /// matching the whole ATR against fixed byte tables. This
    /// recognises a model across chip revisions (which change only
    /// the program-version / chip-id bytes) without enumerating every
    /// observed ATR. [`FineidCardModel::contact_atr_byte_sets`]
    /// remains as the field-observed record.
    ///
    /// # Errors
    /// [`CardClassificationError::UnknownOrUnsupportedAtr`] when the
    /// ATR carries no FINEID pre-issuing data or its markers match no
    /// in-scope model.
    pub fn classify(&self) -> Result<FineidCardModel, CardClassificationError> {
        self.fineid_pre_issuing()
            .and_then(FineidCardModel::from_pre_issuing)
            .ok_or_else(|| CardClassificationError::UnknownOrUnsupportedAtr {
                observed: self.clone(),
            })
    }
}

/// Answer-To-Select bytes from a contactless (ISO 14443-4)
/// session.
///
/// ATS is not bounded by the ATR length window; ISO 14443-4
/// allows up to 254 bytes. We still enforce a minimum so an
/// empty value can't masquerade as a successful ATS read.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ats(Vec<u8>);

/// Error returned by [`Ats::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtsError {
    /// Input was zero bytes (an empty ATS is meaningless;
    /// ISO 14443-4 requires at least one byte).
    Empty,
    /// Input exceeded the 254-byte ISO 14443-4 cap.
    TooLong {
        /// Length of the rejected input in bytes. Tier 0 `usize`.
        got: usize,
    },
}

impl fmt::Display for AtsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("ATS cannot be empty"),
            Self::TooLong { got } => {
                write!(f, "ATS too long: got {got} bytes, ISO 14443-4 caps at 254")
            }
        }
    }
}

impl core::error::Error for AtsError {}

impl Ats {
    /// Wrap a byte sequence as an ATS.
    ///
    /// # Errors
    /// Returns [`AtsError::Empty`] for zero-length input,
    /// [`AtsError::TooLong`] for > 254 bytes.
    pub fn new<B: AsRef<[u8]>>(bytes: B) -> Result<Self, AtsError> {
        let v = bytes.as_ref().to_vec();
        if v.is_empty() {
            return Err(AtsError::Empty);
        }
        if v.len() > 254 {
            return Err(AtsError::TooLong { got: v.len() });
        }
        Ok(Self(v))
    }

    /// Borrow the underlying ATS byte sequence (TL +
    /// per-protocol interface bytes + historical bytes).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Ats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
}

/// DVV's category label for a certificate card.
///
/// Three values, only [`Self::CitizenEid`] is currently in
/// scope for refineid. The labels here are exactly the
/// strings DVV uses in the ATR/ATS technology note, minus
/// the trailing "card" / "cards" plural.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CardType {
    /// DVV's "Citizen eID" category -- the only in-scope card
    /// type for refineid.
    CitizenEid,
    /// DVV's "Social welfare and organizational" category.
    /// Out of scope today.
    SocialWelfareAndOrganizational,
    /// DVV's "Health care and organizational" category. Out
    /// of scope today.
    HealthCareAndOrganizational,
}

impl CardType {
    /// The DVV-published literal string used on the wire.
    #[must_use]
    pub const fn as_dvv_label(self) -> &'static str {
        match self {
            Self::CitizenEid => "Citizen eID",
            Self::SocialWelfareAndOrganizational => "Social welfare and organizational",
            Self::HealthCareAndOrganizational => "Health care and organizational",
        }
    }
}

impl fmt::Display for CardType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_dvv_label())
    }
}

/// Vendor of the smart-card hardware as DVV publishes it.
///
/// "Gemalto" became "Thales" after the 2019 acquisition;
/// both labels appear in DVV's current ATR/ATS table because
/// pre-acquisition Gemalto cards are still in the field.
/// Strong typing here means a Gemalto-branded card cannot
/// silently identify itself as Thales-branded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CardVendor {
    /// Thales (post-2019 Gemalto acquisition).
    Thales,
    /// Gemalto (pre-2019 acquisition); preserved as a distinct
    /// variant so older-card identification stays exact.
    Gemalto,
}

impl CardVendor {
    /// DVV-published literal string used on the wire.
    #[must_use]
    pub const fn as_dvv_label(self) -> &'static str {
        match self {
            Self::Thales => "Thales",
            Self::Gemalto => "Gemalto",
        }
    }
}

impl fmt::Display for CardVendor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_dvv_label())
    }
}

/// The set of FINEID card models refineid currently
/// recognises.
///
/// Strictly the in-scope subset of DVV's ATR/ATS note; see
/// `doc/fineid-card-models.md` for the validity-window math
/// that defines "in scope".
///
/// Adding a model: extend this enum, fill in every accessor
/// match arm (the compiler will list them), add the ATR /
/// ATS bytes verbatim from DVV, update the doc.
// Variant names preserve DVV's FINEID card-model labels verbatim
// (V5_0, V4_2) so the enum reads against the
// doc/fineid-card-models.md ATR/ATS table; rustc doesn't flag
// the trailing _N pieces under non_camel_case_types today, but
// the convention is documented here so future maintainers don't
// "normalize" the labels away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FineidCardModel {
    /// Thales `MultiApp` v5.0 -- Citizen eID, FINEID S4-1 v4.0.
    /// In production 2023-03-13 -> .
    ThalesMultiAppV5_0,
    /// Gemalto `MultiApp` v4.2 -- Citizen eID, FINEID S4-1 v3.1.
    /// In production 2021-01-11 - 2023-03-12.
    GemaltoMultiAppV4_2,
}

/// FINEID pre-issuing family-name marker (byte 1) on observed
/// `MultiApp` cards (FINEID S4-1 §3.3.1).
const FINEID_PRE_ISSUING_FAMILY: u8 = 0xB0;
/// FINEID pre-issuing product-name marker (byte 2).
const FINEID_PRE_ISSUING_PRODUCT: u8 = 0x85;
/// Pre-issuing OS-version marker (byte 3) for `MultiApp` v5.0 (Thales).
const FINEID_OS_VERSION_THALES_V5_0: u8 = 0x05;
/// Pre-issuing OS-version marker (byte 3) for `MultiApp` v4.2 (Gemalto).
const FINEID_OS_VERSION_GEMALTO_V4_2: u8 = 0x04;

impl FineidCardModel {
    /// All in-scope models, in no particular order.
    #[must_use]
    pub const fn all_known() -> &'static [Self] {
        &[Self::ThalesMultiAppV5_0, Self::GemaltoMultiAppV4_2]
    }

    /// Identify the model from the FINEID pre-issuing data markers
    /// (FINEID S4-1 §3.3.1): the family/product bytes confirm a
    /// FINEID `MultiApp` card, and the OS-version byte selects the
    /// generation. `None` when the markers match no in-scope model
    /// (e.g. the expired v3.0 generation, OS version `03h`).
    ///
    /// This is generation-stable: chip revisions vary the
    /// program-version / chip-id bytes but keep the OS-version
    /// marker, so a new revision of a known model still classifies.
    #[must_use]
    pub const fn from_pre_issuing(pre: FineidPreIssuingData) -> Option<Self> {
        if pre.family_name != FINEID_PRE_ISSUING_FAMILY
            || pre.product_name != FINEID_PRE_ISSUING_PRODUCT
        {
            return None;
        }
        match pre.os_version {
            FINEID_OS_VERSION_THALES_V5_0 => Some(Self::ThalesMultiAppV5_0),
            FINEID_OS_VERSION_GEMALTO_V4_2 => Some(Self::GemaltoMultiAppV4_2),
            _ => None,
        }
    }

    /// DVV's category label for this model.
    #[must_use]
    pub const fn card_type(self) -> CardType {
        match self {
            Self::ThalesMultiAppV5_0 | Self::GemaltoMultiAppV4_2 => CardType::CitizenEid,
        }
    }

    /// Vendor whose name DVV publishes for this model.
    #[must_use]
    pub const fn vendor(self) -> CardVendor {
        match self {
            Self::ThalesMultiAppV5_0 => CardVendor::Thales,
            Self::GemaltoMultiAppV4_2 => CardVendor::Gemalto,
        }
    }

    /// Vendor's product family name (`"MultiApp"` for both
    /// in-scope models -- pre/post Gemalto -> Thales rebrand
    /// is the same product line).
    #[must_use]
    pub const fn vendor_product(self) -> &'static str {
        match self {
            Self::ThalesMultiAppV5_0 | Self::GemaltoMultiAppV4_2 => "MultiApp",
        }
    }

    /// Vendor's product version, bare ("5.0", "4.2"). The
    /// "v" prefix DVV uses in prose (e.g. "v5.0") is not
    /// part of the version value; the wire field name
    /// announces "this is a version" already.
    #[must_use]
    pub const fn vendor_product_version(self) -> &'static str {
        match self {
            Self::ThalesMultiAppV5_0 => "5.0",
            Self::GemaltoMultiAppV4_2 => "4.2",
        }
    }

    /// FINEID specification document this model implements
    /// (DVV canonical identifier, e.g. "S4-1").
    #[must_use]
    pub const fn fineid_specification(self) -> &'static str {
        match self {
            Self::ThalesMultiAppV5_0 | Self::GemaltoMultiAppV4_2 => "S4-1",
        }
    }

    /// Version of the FINEID specification document. Bare,
    /// no leading "v".
    #[must_use]
    pub const fn fineid_specification_version(self) -> &'static str {
        match self {
            Self::ThalesMultiAppV5_0 => "4.0",
            Self::GemaltoMultiAppV4_2 => "3.1",
        }
    }

    /// Contact-interface ATR byte sequences this model is known
    /// to emit. Multiple entries are legitimate: same FINEID
    /// specification + same vendor product version can ship with
    /// different historical bytes across manufacturing batches.
    /// DVV's ATR/ATS technote v1.0 (2024-08-12) records one
    /// representative ATR per model; refineid records every ATR
    /// the project has confirmed in the field.
    #[must_use]
    pub const fn contact_atr_byte_sets(self) -> &'static [&'static [u8]] {
        match self {
            Self::ThalesMultiAppV5_0 => &[
                // DVV ATR/ATS technote v1.0 section "Thales MultiApp v5.0
                // (FINEID S4-1 v4.0)". Citizen eID, in production
                // 2023-03-13 ->. Chip-revision "v 1.0.0" per the
                // version label printed under the chip on the
                // physical card.
                &[
                    0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0, 0x85, 0x05, 0x00,
                    0x11, 0x12, 0x24, 0x60, 0x82, 0x90, 0x00,
                ],
                // Same FINEID S4-1 v4.0 product, chip-revision
                // "v 2.0.0" per the version label printed under
                // the chip. Shares the v5.0 family marker (0x05
                // at byte 11) with the v 1.0.0 batch; differs in
                // the historical bytes at positions 12-13.
                // Field-observed 2026-05-24 on a freshly-issued
                // 2026 production card.
                &[
                    0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0, 0x85, 0x05, 0x10,
                    0x24, 0x12, 0x24, 0x60, 0x82, 0x90, 0x00,
                ],
            ],
            Self::GemaltoMultiAppV4_2 => &[
                // DVV ATR/ATS technote v1.0 section "Gemalto MultiApp
                // v4.2 (FINEID S4-1 v3.1)". Citizen eID, in
                // production 2021-01-11 - 2023-03-12.
                &[
                    0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0, 0x85, 0x04, 0x02,
                    0x1B, 0x12, 0x00, 0xF6, 0x82, 0x90, 0x00,
                ],
            ],
        }
    }

    /// Contactless-interface ATS byte sequences this model is
    /// known to emit. Same multi-entry rationale as
    /// [`contact_atr_byte_sets`](Self::contact_atr_byte_sets).
    #[must_use]
    pub const fn contactless_ats_byte_sets(self) -> &'static [&'static [u8]] {
        match self {
            Self::ThalesMultiAppV5_0 => &[&[
                0x14, 0x78, 0x77, 0x95, 0x02, 0x80, 0x31, 0xB8, 0x65, 0xB0, 0x85, 0x05, 0x00, 0x11,
                0x12, 0x24, 0x60, 0x82, 0x90, 0x00,
            ]],
            Self::GemaltoMultiAppV4_2 => &[&[
                0x14, 0x78, 0x77, 0x95, 0x02, 0x80, 0x31, 0xB8, 0x65, 0xB0, 0x85, 0x04, 0x02, 0x1B,
                0x12, 0x00, 0xF6, 0x82, 0x90, 0x00,
            ]],
        }
    }
}

/// Error returned by [`Atr::classify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CardClassificationError {
    /// Observed ATR didn't match any in-scope FINEID card
    /// model. Out-of-scope DVV cards (expired older
    /// generations, social welfare / organizational, health
    /// care) land here, as does any non-FINEID smartcard.
    UnknownOrUnsupportedAtr {
        /// The ATR bytes that didn't classify. Surfaced so the
        /// operator can compare against
        /// `doc/fineid-card-models.md`.
        observed: Atr,
    },
}

impl fmt::Display for CardClassificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownOrUnsupportedAtr { observed } => write!(
                f,
                "card ATR `{observed}` does not match any in-scope FINEID card model; \
                 see doc/fineid-card-models.md for the supported set"
            ),
        }
    }
}

impl core::error::Error for CardClassificationError {}

// `classify_card_by_atr` is a method on `Atr` (see `Atr::classify`).

#[cfg(test)]
mod tests {

    use super::{
        Atr, AtrError, Ats, AtsError, CardClassificationError, CardType, CardVendor,
        FineidCardModel, FineidPreIssuingData,
    };
    use crate::atr::{Convention, MINIMAL_DIRECT_ATR, T0, Yi};

    #[test]
    fn fineid_pre_issuing_extracts_named_fields() {
        // Thales MultiApp v5.0, chip-rev v1.0.0.
        let atr = Atr::new([
            0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0, 0x85, 0x05, 0x00, 0x11,
            0x12, 0x24, 0x60, 0x82, 0x90, 0x00,
        ])
        .expect("Thales v5.0 ATR fixture parses");
        let pre = atr.fineid_pre_issuing().expect("pre-issuing present");
        assert_eq!(
            pre,
            FineidPreIssuingData {
                family_name: 0xB0,
                product_name: 0x85,
                os_version: 0x05,
                program_version: 0x00,
                chip_id: 0x11,
            }
        );
    }

    #[test]
    fn classify_is_generation_stable_across_chip_revisions() {
        // Same Thales v5.0 OS-version marker (05), but a chip
        // revision never enumerated in the byte tables (program
        // version FE, chip id A5). Field-driven classify still
        // recognises it -- the payoff over whole-ATR byte matching.
        let atr = Atr::new([
            0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0, 0x85, 0x05, 0xFE, 0xA5,
            0x12, 0x24, 0x60, 0x82, 0x90, 0x00,
        ])
        .expect("unknown-chip-revision ATR fixture parses");
        assert_eq!(atr.classify(), Ok(FineidCardModel::ThalesMultiAppV5_0));
    }

    #[test]
    fn classify_rejects_expired_v3_0_generation() {
        // Gemalto MultiApp v3.0: pre-issuing OS-version marker 03,
        // out of scope. Must not classify as any in-scope model.
        let atr = Atr::new([
            0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0, 0x85, 0x03, 0x00, 0xEF,
            0x12, 0x00, 0xF6, 0x82, 0x90, 0x00,
        ])
        .expect("Gemalto v3.0 ATR fixture parses");
        assert!(matches!(
            atr.classify(),
            Err(CardClassificationError::UnknownOrUnsupportedAtr { .. })
        ));
    }

    #[test]
    fn classify_rejects_non_fineid_markers() {
        // FINEID-shaped C-TLV but wrong family/product markers
        // (AA BB instead of B0 85): not a FINEID MultiApp card.
        let atr = Atr::new([
            0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xAA, 0xBB, 0x05, 0x00, 0x11,
            0x12, 0x24, 0x60, 0x82, 0x90, 0x00,
        ])
        .expect("non-FINEID-marker ATR fixture parses");
        assert!(atr.fineid_pre_issuing().is_some());
        assert!(matches!(
            atr.classify(),
            Err(CardClassificationError::UnknownOrUnsupportedAtr { .. })
        ));
    }

    #[test]
    fn atr_rejects_too_short() {
        assert_eq!(Atr::new([0x3B]), Err(AtrError::TooShort { got: 1 }));
        assert_eq!(Atr::new([]), Err(AtrError::TooShort { got: 0 }));
    }

    #[test]
    fn atr_rejects_too_long() {
        let v = vec![0_u8; 34];
        assert_eq!(Atr::new(v), Err(AtrError::TooLong { got: 34 }));
    }

    #[test]
    fn atr_accepts_minimum_window() {
        let _atr = Atr::new(MINIMAL_DIRECT_ATR).expect("minimal direct ATR parses");
    }

    #[test]
    fn atr_display_is_space_separated_uppercase_hex() {
        // Minimal valid ATR: TS=Direct convention, T0 with
        // Y1 nibble = 0 (no interface bytes) and K = 0 (no
        // historical bytes). No TCK because no non-T=0
        // protocol is indicated. Renders as the two-byte hex
        // pair.
        let minimal_t0 = T0 {
            y1: Yi::from_nibble(0),
            historical_byte_count: 0,
        };
        let atr = Atr::new([Convention::Direct.as_ts(), minimal_t0.as_byte()])
            .expect("two-byte minimal ATR parses");
        let convention_byte_hex = format!("{:02X}", Convention::Direct.as_ts());
        let format_byte_hex = format!("{:02X}", minimal_t0.as_byte());
        assert_eq!(
            format!("{atr}"),
            format!("{convention_byte_hex} {format_byte_hex}")
        );
    }

    #[test]
    fn ats_rejects_empty() {
        assert_eq!(Ats::new([]), Err(AtsError::Empty));
    }

    #[test]
    fn ats_rejects_too_long() {
        let v = vec![0_u8; 255];
        assert_eq!(Ats::new(v), Err(AtsError::TooLong { got: 255 }));
    }

    #[test]
    fn every_known_thales_multiapp_v5_atr_classifies() {
        for bytes in FineidCardModel::ThalesMultiAppV5_0.contact_atr_byte_sets() {
            let atr = Atr::new(*bytes).expect("known Thales v5.0 ATR parses");
            assert_eq!(
                atr.classify().expect("known Thales v5.0 ATR classifies"),
                FineidCardModel::ThalesMultiAppV5_0,
                "ATR {atr} should classify as Thales MultiApp v5.0"
            );
        }
    }

    #[test]
    fn dvv_gemalto_multiapp_v4_2_atr_classifies() {
        for bytes in FineidCardModel::GemaltoMultiAppV4_2.contact_atr_byte_sets() {
            let atr = Atr::new(*bytes).expect("known Gemalto v4.2 ATR parses");
            assert_eq!(
                atr.classify().expect("known Gemalto v4.2 ATR classifies"),
                FineidCardModel::GemaltoMultiAppV4_2
            );
        }
    }

    #[test]
    fn out_of_scope_gemalto_v3_0_atr_is_rejected() {
        // From the DVV ATR/ATS note: "Gemalto MultiApp v3.0
        // (FINEID S4-1 v3.0)", production 2017-01-01 -
        // 2021-01-10. Newest card expired 2026-01-10, before
        // today; out of scope.
        let bytes: [u8; 20] = [
            0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0, 0x85, 0x03, 0x00, 0xEF,
            0x12, 0x00, 0xF6, 0x82, 0x90, 0x00,
        ];
        let atr = Atr::new(bytes).expect("Gemalto v3.0 ATR fixture parses");
        match atr.classify() {
            Err(CardClassificationError::UnknownOrUnsupportedAtr { observed }) => {
                assert_eq!(observed, atr);
            }
            other => panic!("expected UnknownOrUnsupportedAtr, got {other:?}"),
        }
    }

    #[test]
    fn social_welfare_atr_is_rejected_in_citizen_classifier() {
        // Idemia Cosmo X (FINEID S1 v5.0), Social welfare /
        // organizational -- out of scope.
        let bytes: [u8; 22] = [
            0x3B, 0xDD, 0x96, 0x00, 0x80, 0x31, 0xFE, 0x45, 0x00, 0x31, 0xB8, 0x64, 0x04, 0x29,
            0xEC, 0xC1, 0x73, 0x94, 0x01, 0x80, 0x83, 0x49,
        ];
        let atr = Atr::new(bytes).expect("social welfare ATR fixture parses");
        assert!(matches!(
            atr.classify(),
            Err(CardClassificationError::UnknownOrUnsupportedAtr { .. })
        ));
    }

    #[test]
    fn wire_strings_thales_multiapp_v5() {
        let m = FineidCardModel::ThalesMultiAppV5_0;
        assert_eq!(m.card_type().as_dvv_label(), "Citizen eID");
        assert_eq!(m.vendor().as_dvv_label(), "Thales");
        assert_eq!(m.vendor_product(), "MultiApp");
        assert_eq!(m.vendor_product_version(), "5.0");
        assert_eq!(m.fineid_specification(), "S4-1");
        assert_eq!(m.fineid_specification_version(), "4.0");
    }

    #[test]
    fn wire_strings_gemalto_multiapp_v4_2() {
        let m = FineidCardModel::GemaltoMultiAppV4_2;
        assert_eq!(m.card_type().as_dvv_label(), "Citizen eID");
        assert_eq!(m.vendor().as_dvv_label(), "Gemalto");
        assert_eq!(m.vendor_product(), "MultiApp");
        assert_eq!(m.vendor_product_version(), "4.2");
        assert_eq!(m.fineid_specification(), "S4-1");
        assert_eq!(m.fineid_specification_version(), "3.1");
    }

    #[test]
    fn card_type_all_dvv_labels() {
        assert_eq!(CardType::CitizenEid.as_dvv_label(), "Citizen eID");
        assert_eq!(
            CardType::SocialWelfareAndOrganizational.as_dvv_label(),
            "Social welfare and organizational"
        );
        assert_eq!(
            CardType::HealthCareAndOrganizational.as_dvv_label(),
            "Health care and organizational"
        );
    }

    #[test]
    fn card_vendor_all_dvv_labels() {
        assert_eq!(CardVendor::Thales.as_dvv_label(), "Thales");
        assert_eq!(CardVendor::Gemalto.as_dvv_label(), "Gemalto");
    }

    #[test]
    fn all_known_covers_two_in_scope_models() {
        assert_eq!(FineidCardModel::all_known().len(), 2);
    }

    #[test]
    fn dvv_contact_atrs_are_in_iso7816_window() {
        for &m in FineidCardModel::all_known() {
            for bytes in m.contact_atr_byte_sets() {
                let n = bytes.len();
                assert!(
                    (2..=33).contains(&n),
                    "{m:?} ATR length {n} out of ISO 7816-3 window"
                );
            }
        }
    }
}
