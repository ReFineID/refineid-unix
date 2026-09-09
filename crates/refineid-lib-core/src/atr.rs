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

//! ISO 7816-3 §8 ATR (Answer to Reset) parsing as a typed
//! structure.
//!
//! The card emits an ATR as soon as the host issues a reset
//! (cold or warm). It's the *first* protocol layer a host sees
//! and carries the information the host needs before sending
//! its first APDU: which transmission convention (direct /
//! inverse bit order), which T-protocol(s), what timing
//! parameters, and which historical bytes (vendor / application
//! identification).
//!
//! Wire shape per ISO 7816-3 §8:
//!
//! ```text
//!   TS   T0   [TA1 [TB1 [TC1 [TD1]]]]                     <- interface group 1
//!             [TA2 [TB2 [TC2 [TD2]]]]                     <- interface group 2 (if TD1.Yi set)
//!             ...                                          <- chain via TDi.next_yi
//!        <historical-bytes: K bytes>                       <- K from T0 low nibble
//!        [TCK]                                             <- iff any TDi protocol != T=0
//! ```
//!
//! Where:
//!
//! - **TS** picks the bit-order convention: `3Bh` direct or
//!   `3Fh` inverse.
//! - **T0** packs two values: the Y1 nibble (which of `TA1` /
//!   `TB1` / `TC1` / `TD1` follow) and the K nibble (how many
//!   historical bytes after the interface chain).
//! - Each **`TDi`** byte's *high nibble* is the next group's `Yi`
//!   (chaining); its *low nibble* names the T-protocol that the
//!   *previous* group's parameters belong to.
//! - **TCK** is an XOR checksum byte present only when any
//!   protocol indicator was non-zero (i.e., not pure T=0).
//!
//! Refineid's typed parse decomposes the wire bytes into the
//! [`Atr`] structure at construction. Consumers read typed
//! fields ([`Atr::convention`], [`Atr::historical_bytes`], ...)
//! instead of reaching into the byte sequence.

use core::fmt;

/// Minimum ATR length per ISO 7816-3 §8.1: TS + T0 = 2 bytes.
pub const ATR_MIN_LEN: usize = 2;

/// Maximum ATR length per ISO 7816-3 §8.1: TS + T0 + 4 interface
/// groups of 4 bytes each + 15 historical bytes + TCK = 33 bytes.
pub const ATR_MAX_LEN: usize = 33;

/// TS byte values per ISO 7816-3 §8.1.
///
/// `3Bh` selects direct convention (LSB first, positive logic);
/// every FINEID card uses this.
const TS_DIRECT: u8 = 0x3B;
/// TS byte for inverse convention (MSB first, inverse logic) per
/// ISO 7816-3 §8.1. Encountered only on legacy GSM/SIM cards.
const TS_INVERSE: u8 = 0x3F;

/// Transmission convention per ISO 7816-3 §8.1: the first byte
/// of the ATR fixes which bit order the rest of the
/// communication uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Convention {
    /// `TS = 3Bh` -- direct convention. LSB first on the wire;
    /// state Z = logic 1; positive logic for bit values. Used by
    /// every FINEID card and the overwhelming majority of cards
    /// in production.
    Direct,
    /// `TS = 3Fh` -- inverse convention. MSB first; state A =
    /// logic 1; inverse logic. Legacy GSM / SIM cards used this;
    /// modern smartcards rarely do.
    Inverse,
}

impl Convention {
    /// Decode the TS byte. `None` for any value that isn't a
    /// valid convention indicator.
    #[inline]
    #[must_use]
    pub const fn from_ts(ts: u8) -> Option<Self> {
        match ts {
            TS_DIRECT => Some(Self::Direct),
            TS_INVERSE => Some(Self::Inverse),
            _ => None,
        }
    }

    /// Re-emit the TS wire byte.
    #[inline]
    #[must_use]
    pub const fn as_ts(self) -> u8 {
        match self {
            Self::Direct => TS_DIRECT,
            Self::Inverse => TS_INVERSE,
        }
    }
}

impl fmt::Display for Convention {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => write!(f, "direct"),
            Self::Inverse => write!(f, "inverse"),
        }
    }
}

/// The shortest well-formed ATR (ISO 7816-3 §8.1 minimum: TS + T0).
///
/// Direct-convention TS and a format byte of `0` -- Y1 nibble `0`
/// (no interface bytes) and K nibble `0` (no historical bytes), so
/// no TCK. The canonical valid-ATR placeholder for transports and
/// fakes that need *some* well-formed ATR without asserting on its
/// content -- so call sites never spell raw ATR bytes inline.
pub const MINIMAL_DIRECT_ATR: [u8; ATR_MIN_LEN] = [
    Convention::Direct.as_ts(),
    T0 {
        y1: Yi::from_nibble(0),
        historical_byte_count: 0,
    }
    .as_byte(),
];

/// `Y_i` nibble (high nibble of T0 / `TDi`): 4-bit bitmap of which
/// of TA, TB, TC, TD follow in the *next* interface group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Yi(u8);

impl Yi {
    /// Wrap the low 4 bits of a byte as a Yi nibble. Bits above
    /// b4 are masked off so callers can pass either the raw
    /// high nibble of T0/TDi (which already lives in bits b8..b5
    /// of the source byte) or a pre-shifted value.
    #[inline]
    #[must_use]
    pub const fn from_nibble(nibble: u8) -> Self {
        Self(nibble & 0x0F)
    }

    /// `true` if `TA_{i+1}` follows the parent T0 / `TD_i` byte.
    /// Encoded as bit b5 of the source byte (b1 of the nibble).
    #[inline]
    #[must_use]
    pub const fn ta_present(self) -> bool {
        self.0 & 0b0001 != 0
    }

    /// `true` if TB_{i+1} follows.
    #[inline]
    #[must_use]
    pub const fn tb_present(self) -> bool {
        self.0 & 0b0010 != 0
    }

    /// `true` if TC_{i+1} follows.
    #[inline]
    #[must_use]
    pub const fn tc_present(self) -> bool {
        self.0 & 0b0100 != 0
    }

    /// `true` if TD_{i+1} follows -- which chains another
    /// interface group after the current one.
    #[inline]
    #[must_use]
    pub const fn td_present(self) -> bool {
        self.0 & 0b1000 != 0
    }

    /// `true` if any of TA / TB / TC / TD is present (i.e. the
    /// current group has at least one byte).
    #[inline]
    #[must_use]
    pub const fn any_present(self) -> bool {
        self.0 != 0
    }

    /// Raw nibble value (4 bits).
    #[inline]
    #[must_use]
    pub const fn as_nibble(self) -> u8 {
        self.0
    }
}

/// T0 byte: the format character per ISO 7816-3 §8.2.
///
/// `T0` packs the first Y nibble (which interface bytes of
/// group 1 follow) and the count of historical bytes that
/// appear after the interface byte chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct T0 {
    /// High nibble: Y1, the presence bitmap for group 1's
    /// (TA1, TB1, TC1, TD1) interface bytes.
    pub y1: Yi,
    /// Low nibble: K, the count of historical bytes following
    /// the interface byte chain. Range 0..=15 by construction.
    pub historical_byte_count: u8,
}

impl T0 {
    /// Decode the T0 byte into its two nibbles.
    #[inline]
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        Self {
            y1: Yi::from_nibble(b >> 4),
            historical_byte_count: b & 0x0F,
        }
    }

    /// Re-emit the wire byte.
    #[inline]
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        (self.y1.as_nibble() << 4) | (self.historical_byte_count & 0x0F)
    }
}

/// `TA_i` byte: bit-rate / clock parameters when in interface
/// group 1; subsequent groups define different per-protocol
/// parameters.
///
/// Refineid keeps the raw byte plus accessors for the standard
/// TA1 interpretation (FI / DI nibbles per ISO 7816-3
/// Table 7 / Table 8). For non-T0 protocols the `TAi` semantics
/// vary; consumers in those flows would use [`TaByte::as_byte`]
/// and decode per the relevant protocol's spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaByte(u8);

impl TaByte {
    /// Wrap a raw TA byte.
    #[inline]
    #[must_use]
    pub const fn new(b: u8) -> Self {
        Self(b)
    }

    /// Raw wire byte.
    #[inline]
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self.0
    }

    /// FI nibble (high) -- clock-rate conversion integer for
    /// TA1 (ISO 7816-3 Table 7). Meaningful only for the first
    /// interface group; later groups reuse `TAi` for different
    /// protocol parameters.
    #[inline]
    #[must_use]
    pub const fn fi_index(self) -> u8 {
        (self.0 >> 4) & 0x0F
    }

    /// DI nibble (low) -- bit-rate adjustment integer for TA1
    /// (ISO 7816-3 Table 8).
    #[inline]
    #[must_use]
    pub const fn di_index(self) -> u8 {
        self.0 & 0x0F
    }

    /// TA1 clock-rate conversion integer `Fi`, looked up from the
    /// FI nibble (ISO 7816-3 Table 7). `None` for the RFU indices
    /// (7, 8, E, F). Meaningful only for the first interface group.
    #[inline]
    #[must_use]
    pub const fn ta1_clock_rate_conversion(self) -> Option<u16> {
        match self.fi_index() {
            0 | 1 => Some(372),
            2 => Some(558),
            3 => Some(744),
            4 => Some(1116),
            5 => Some(1488),
            6 => Some(1860),
            9 => Some(512),
            10 => Some(768),
            11 => Some(1024),
            12 => Some(1536),
            13 => Some(2048),
            _ => None,
        }
    }

    /// TA1 maximum clock frequency `f(max)` in kHz, looked up from
    /// the FI nibble (ISO 7816-3 Table 7; kHz keeps the 7.5 MHz row
    /// integral). `None` for the RFU indices.
    #[inline]
    #[must_use]
    pub const fn ta1_max_frequency_khz(self) -> Option<u32> {
        match self.fi_index() {
            0 => Some(4_000),
            1 | 9 => Some(5_000),
            2 => Some(6_000),
            3 => Some(8_000),
            10 => Some(7_500),
            11 => Some(10_000),
            4 => Some(12_000),
            12 => Some(15_000),
            5 => Some(16_000),
            6 | 13 => Some(20_000),
            _ => None,
        }
    }

    /// TA1 bit-rate adjustment integer `Di`, looked up from the DI
    /// nibble (ISO 7816-3 Table 8). `None` for the RFU indices
    /// (0, A..=F). Meaningful only for the first interface group.
    #[inline]
    #[must_use]
    pub const fn ta1_bit_rate_adjustment(self) -> Option<u16> {
        match self.di_index() {
            1 => Some(1),
            2 => Some(2),
            3 => Some(4),
            4 => Some(8),
            5 => Some(16),
            6 => Some(32),
            7 => Some(64),
            8 => Some(12),
            9 => Some(20),
            _ => None,
        }
    }
}

/// `TB_i` byte: programming voltage / current parameters
/// (deprecated for modern cards; refineid carries the raw
/// byte without further decoding).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TbByte(u8);

impl TbByte {
    /// Wrap a raw TB byte.
    #[inline]
    #[must_use]
    pub const fn new(b: u8) -> Self {
        Self(b)
    }

    /// Raw wire byte.
    #[inline]
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self.0
    }
}

/// `TC_i` byte: per-protocol parameters. For TC1 the byte is the
/// "extra guard time" between successive characters; for
/// subsequent groups the meaning is protocol-specific.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcByte(u8);

impl TcByte {
    /// Wrap a raw TC byte.
    #[inline]
    #[must_use]
    pub const fn new(b: u8) -> Self {
        Self(b)
    }

    /// Raw wire byte.
    #[inline]
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self.0
    }
}

/// `TD_i` byte: protocol indicator (low nibble) for the *current*
/// interface group, plus the next Y nibble (high) that picks
/// which interface bytes follow in the *next* group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TdByte(u8);

impl TdByte {
    /// Wrap a raw TD byte.
    #[inline]
    #[must_use]
    pub const fn new(b: u8) -> Self {
        Self(b)
    }

    /// Raw wire byte.
    #[inline]
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self.0
    }

    /// T-protocol indicator (low nibble): `0` = T=0, `1` =
    /// T=1, ..., `14` = T=14, `15` = reserved.
    #[inline]
    #[must_use]
    pub const fn protocol_indicator(self) -> u8 {
        self.0 & 0x0F
    }

    /// Y nibble (high): presence bitmap for the next interface
    /// group's (TA, TB, TC, TD) bytes.
    #[inline]
    #[must_use]
    pub const fn next_yi(self) -> Yi {
        Yi::from_nibble(self.0 >> 4)
    }
}

/// One interface byte group (`TAi`, `TBi`, `TCi`, `TDi`).
///
/// Per ISO 7816-3 §8.2, an interface byte appears only if the
/// previous T0 (for group 1) or `TDi` (for groups 2+) signalled
/// it in the `Yi` nibble. Absent bytes are `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct InterfaceByteGroup {
    /// TA: present iff the previous Yi had `ta_present()`.
    pub ta: Option<TaByte>,
    /// TB.
    pub tb: Option<TbByte>,
    /// TC.
    pub tc: Option<TcByte>,
    /// TD; when present, its `next_yi` continues the chain.
    pub td: Option<TdByte>,
}

/// Historical bytes per ISO 7816-4 §8 (the trailing K bytes of
/// the ATR).
///
/// The first byte is the *category indicator*; values:
///
/// - `00h`: status indicator follows directly (no category-
///   length structure).
/// - `10h`: a single DIR data reference follows.
/// - `80h`: compact-TLV format (every FINEID card uses this).
/// - `81h..8Fh`: reserved.
/// - other: proprietary.
///
/// Refineid keeps the raw historical bytes plus accessors for
/// the category indicator and compact-TLV walk. Per-card
/// classification reads named TLVs to identify the FINEID
/// model and chip revision.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HistoricalBytes {
    /// Raw historical-byte payload extracted from the ATR, length 0..=15.
    bytes: Vec<u8>,
}

impl HistoricalBytes {
    /// Wrap historical-byte bytes parsed out of an ATR.
    pub(crate) const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrow the raw historical bytes (TS / T0 / interface
    /// bytes / TCK excluded).
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Number of historical bytes (matches T0's `K` low
    /// nibble).
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// `true` when the card emitted zero historical bytes
    /// (`K = 0`); rare but spec-allowed.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Category indicator (the first byte) per ISO 7816-4 §8.1.
    /// `None` when the historical bytes are empty.
    #[inline]
    #[must_use]
    pub fn category_indicator(&self) -> Option<u8> {
        self.bytes.first().copied()
    }

    /// `true` when the category indicator is `80h` (compact-TLV
    /// format follows). FINEID cards always use this.
    #[inline]
    #[must_use]
    pub fn is_compact_tlv(&self) -> bool {
        self.category_indicator() == Some(0x80)
    }

    /// Walk the compact-TLV body (after the `80h` category
    /// indicator) and yield each `(tag, value)` pair per ISO
    /// 7816-4 §8.1.1.2. Empty when the historical bytes aren't
    /// in compact-TLV format.
    ///
    /// In compact-TLV, each entry packs `(tag, length)` into
    /// one byte: high nibble = tag (0..=15), low nibble =
    /// length (0..=15 bytes of value follow).
    #[inline]
    #[must_use]
    pub fn compact_tlv_entries(&self) -> Vec<CompactTlv> {
        if !self.is_compact_tlv() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut idx = 1; // skip the 0x80 indicator
        while idx < self.bytes.len() {
            let Some(&header) = self.bytes.get(idx) else {
                break;
            };
            idx = idx.saturating_add(1);
            let tag = header >> 4_u8;
            let len = usize::from(header & 0x0F);
            let Some(value_end) = idx.checked_add(len) else {
                break;
            };
            let Some(value) = self.bytes.get(idx..value_end) else {
                break;
            };
            out.push(CompactTlv {
                tag,
                value: value.to_vec(),
            });
            idx = value_end;
        }
        out
    }

    /// Walk the compact-TLV body and lift each entry into a typed
    /// [`HistoricalDataObject`] (the generic ISO 7816-4 §8.1.1
    /// interpretation). Empty when the historical bytes aren't in
    /// compact-TLV format.
    #[inline]
    #[must_use]
    pub fn data_objects(&self) -> Vec<HistoricalDataObject> {
        self.compact_tlv_entries()
            .iter()
            .map(CompactTlv::interpret)
            .collect()
    }
}

/// One compact-TLV entry from [`HistoricalBytes::compact_tlv_entries`].
///
/// Compact-TLV encodes `(tag, length)` into a single byte (high
/// nibble = tag 0..=15, low nibble = length 0..=15); the value
/// bytes follow. Known compact-TLV tags per ISO 7816-4 §8.1.1:
///
/// - Tag `1` -- country code / national-use marker.
/// - Tag `2` -- issuer identification number.
/// - Tag `3` -- card service data byte.
/// - Tag `4` -- initial access data.
/// - Tag `5` -- card issuer's data.
/// - Tag `6` -- pre-issuing data.
/// - Tag `7` -- card capabilities.
/// - Tag `8` -- status indicator (LCS byte + SW1-SW2 form).
///
/// [`CompactTlv::interpret`] lifts the raw `(tag, value)` into the
/// typed [`HistoricalDataObject`] using the **generic ISO** meaning
/// (card-agnostic); a card-specific layer reads issuer-proprietary
/// interiors on top of that.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CompactTlv {
    /// Tag (0..=15) from the header's high nibble.
    pub tag: u8,
    /// Value bytes (length from the header's low nibble).
    pub value: Vec<u8>,
}

/// Compact-TLV tag for the country/issuer indicator (ISO 7816-4 §8.1.1).
const CTLV_TAG_COUNTRY: u8 = 0x1;
/// Compact-TLV tag for the issuer identification number.
const CTLV_TAG_ISSUER_ID: u8 = 0x2;
/// Compact-TLV tag for the card service data byte.
const CTLV_TAG_CARD_SERVICE: u8 = 0x3;
/// Compact-TLV tag for the initial access data.
const CTLV_TAG_INITIAL_ACCESS: u8 = 0x4;
/// Compact-TLV tag for the card issuer's data.
const CTLV_TAG_CARD_ISSUER: u8 = 0x5;
/// Compact-TLV tag for the pre-issuing data (issuer-proprietary
/// interior).
const CTLV_TAG_PRE_ISSUING: u8 = 0x6;
/// Compact-TLV tag for the card capabilities bitfields.
const CTLV_TAG_CARD_CAPABILITIES: u8 = 0x7;
/// Compact-TLV tag for the status indicator (LCS / SW1-SW2).
const CTLV_TAG_STATUS: u8 = 0x8;

impl CompactTlv {
    /// Lift this raw entry into a typed [`HistoricalDataObject`] by
    /// its ISO 7816-4 §8.1.1 tag. Structured tags (card service
    /// data, card capabilities, status indicator, country) decode
    /// their interior; issuer-proprietary tags keep their bytes
    /// verbatim (ISO does not define the interior -- a card layer
    /// interprets them).
    #[must_use]
    pub fn interpret(&self) -> HistoricalDataObject {
        match self.tag {
            CTLV_TAG_COUNTRY => HistoricalDataObject::CountryCode(CountryIndicator {
                bytes: self.value.clone(),
            }),
            CTLV_TAG_ISSUER_ID => HistoricalDataObject::IssuerIdNumber(self.value.clone()),
            CTLV_TAG_CARD_SERVICE => self.single_byte().map_or_else(
                || self.proprietary(),
                |b| HistoricalDataObject::CardServiceData(CardServiceData(b)),
            ),
            CTLV_TAG_INITIAL_ACCESS => HistoricalDataObject::InitialAccessData(self.value.clone()),
            CTLV_TAG_CARD_ISSUER => HistoricalDataObject::CardIssuerData(self.value.clone()),
            CTLV_TAG_PRE_ISSUING => HistoricalDataObject::PreIssuingData(self.value.clone()),
            CTLV_TAG_CARD_CAPABILITIES => {
                HistoricalDataObject::CardCapabilities(CardCapabilities {
                    bytes: self.value.clone(),
                })
            }
            CTLV_TAG_STATUS => self
                .status_indicator()
                .map_or_else(|| self.proprietary(), HistoricalDataObject::StatusIndicator),
            _ => self.proprietary(),
        }
    }

    /// The value as a single byte, when it is exactly one byte long.
    fn single_byte(&self) -> Option<u8> {
        match self.value.as_slice() {
            [b] => Some(*b),
            _ => None,
        }
    }

    /// Decode a tag-8 status indicator from this entry's value
    /// (1 byte = LCS, 2 = SW1-SW2, 3 = LCS + SW1-SW2); `None` for
    /// any other length.
    fn status_indicator(&self) -> Option<StatusIndicator> {
        match self.value.as_slice() {
            [lcs] => Some(StatusIndicator::LifeCycle { lcs: *lcs }),
            [sw1, sw2] => Some(StatusIndicator::StatusWord {
                sw1: *sw1,
                sw2: *sw2,
            }),
            [lcs, sw1, sw2] => Some(StatusIndicator::Full {
                lcs: *lcs,
                sw1: *sw1,
                sw2: *sw2,
            }),
            _ => None,
        }
    }

    /// Fall back to the proprietary/unknown variant, preserving the
    /// raw tag and value.
    fn proprietary(&self) -> HistoricalDataObject {
        HistoricalDataObject::Other {
            tag: self.tag,
            value: self.value.clone(),
        }
    }
}

/// ISO 7816-4 §8.1.1 card service data byte (compact-TLV tag 3):
/// one bitfield byte describing how applications and data objects
/// are selected and accessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CardServiceData(u8);

impl CardServiceData {
    /// Wrap the raw card-service-data byte.
    #[inline]
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        Self(b)
    }

    /// Raw wire byte.
    #[inline]
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self.0
    }

    /// b8: application selection by full DF name is available.
    #[inline]
    #[must_use]
    pub const fn app_selection_by_full_df_name(self) -> bool {
        self.0 & 0b1000_0000 != 0
    }

    /// b7: application selection by partial DF name is available.
    #[inline]
    #[must_use]
    pub const fn app_selection_by_partial_df_name(self) -> bool {
        self.0 & 0b0100_0000 != 0
    }

    /// b6: BER-TLV data objects are available in `EF.DIR`.
    #[inline]
    #[must_use]
    pub const fn ber_tlv_in_ef_dir(self) -> bool {
        self.0 & 0b0010_0000 != 0
    }

    /// b5: BER-TLV data objects are available in `EF.ATR`/`INFO`.
    #[inline]
    #[must_use]
    pub const fn ber_tlv_in_ef_atr(self) -> bool {
        self.0 & 0b0001_0000 != 0
    }

    /// b4..b2: the `EF.DIR` / `EF.ATR` access-services method
    /// (3-bit field). ISO 7816-4 enumerates the values; FINEID
    /// cards emit `0b100` -- access by the READ BINARY command.
    #[inline]
    #[must_use]
    pub const fn ef_access_services(self) -> u8 {
        (self.0 >> 1) & 0b0000_0111
    }

    /// b1: a master file (MF) is present (`0` = with MF, `1` =
    /// without).
    #[inline]
    #[must_use]
    pub const fn has_master_file(self) -> bool {
        self.0 & 0b0000_0001 == 0
    }
}

/// ISO 7816-4 §8.1.1 status indicator (compact-TLV tag 8): a life
/// cycle status byte and/or a status word, by value length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatusIndicator {
    /// 1-byte form: life cycle status (LCS) only.
    LifeCycle {
        /// Card life-cycle status byte.
        lcs: u8,
    },
    /// 2-byte form: status word `SW1 SW2` only.
    StatusWord {
        /// SW1.
        sw1: u8,
        /// SW2.
        sw2: u8,
    },
    /// 3-byte form: LCS followed by `SW1 SW2`.
    Full {
        /// Card life-cycle status byte.
        lcs: u8,
        /// SW1.
        sw1: u8,
        /// SW2.
        sw2: u8,
    },
}

/// ISO 7816-4 §8.1.1 country/issuer indicator (compact-TLV tag 1):
/// an ISO 3166-1 numeric country code packed as quartets (three
/// digits) followed by issuer/national subsequent data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CountryIndicator {
    /// Raw quartet-packed bytes (country digits + subsequent data).
    bytes: Vec<u8>,
}

impl CountryIndicator {
    /// Raw value bytes.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The three-digit ISO 3166-1 numeric country code, read from
    /// the first three quartets (e.g. `246` = Finland). `None` if
    /// fewer than two bytes are present or any of the three quartets
    /// is not a decimal digit.
    #[must_use]
    pub fn country_code(&self) -> Option<u16> {
        let first = *self.bytes.first()?;
        let second = *self.bytes.get(1)?;
        let d0 = first >> 4_u8;
        let d1 = first & 0x0F;
        let d2 = second >> 4_u8;
        if d0 > 9 || d1 > 9 || d2 > 9 {
            return None;
        }
        // Each quartet is 0..=9, so the result is 0..=999; saturating
        // ops keep the arithmetic total (Rust restriction lint) with
        // no reachable saturation.
        let hundreds = u16::from(d0).saturating_mul(100);
        let tens = u16::from(d1).saturating_mul(10);
        Some(hundreds.saturating_add(tens).saturating_add(u16::from(d2)))
    }
}

/// ISO 7816-4 §8.1.1 card capabilities (compact-TLV tag 7, or the
/// `0x47` object in `EF.ATR`).
///
/// One to three bitfield bytes -- selection methods, data coding,
/// then command chaining / logical channels. Refineid keeps the raw
/// bytes plus typed accessors for each present byte.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CardCapabilities {
    /// Raw capability bytes (1..=3 per ISO 7816-4).
    bytes: Vec<u8>,
}

impl CardCapabilities {
    /// Raw capability bytes.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// First byte -- selection methods (DF selection by full name /
    /// path / FID, implicit selection, short EF identifiers, record
    /// numbering). `None` when absent.
    #[inline]
    #[must_use]
    pub fn selection_methods(&self) -> Option<u8> {
        self.bytes.first().copied()
    }

    /// Second byte -- data coding (BER-TLV EF support, write
    /// behaviour, tag/padding handling, data unit size). `None` when
    /// absent.
    #[inline]
    #[must_use]
    pub fn data_coding(&self) -> Option<u8> {
        self.bytes.get(1).copied()
    }

    /// Third byte -- command chaining, length fields, and logical
    /// channels (extended Lc/Le, extended length info in `EF.ATR`,
    /// channel assignment). `None` when absent.
    #[inline]
    #[must_use]
    pub fn command_chaining(&self) -> Option<u8> {
        self.bytes.get(2).copied()
    }

    /// b7 of the command-chaining byte: command chaining is
    /// supported. `None` when the byte is absent.
    #[inline]
    #[must_use]
    pub fn supports_command_chaining(&self) -> Option<bool> {
        self.command_chaining().map(|b| b & 0b1000_0000 != 0)
    }

    /// b7 of the command-chaining byte: extended `Lc`/`Le` fields are
    /// supported. `None` when the byte is absent.
    #[inline]
    #[must_use]
    pub fn supports_extended_length(&self) -> Option<bool> {
        self.command_chaining().map(|b| b & 0b0100_0000 != 0)
    }
}

/// A typed ISO 7816-4 §8.1.1 historical-byte data object, lifted
/// from a [`CompactTlv`] by [`CompactTlv::interpret`].
///
/// Variants carry the **generic ISO** interpretation. The
/// issuer-proprietary objects (issuer id, initial access, card
/// issuer data, pre-issuing data) keep their bytes verbatim because
/// ISO does not define their interior -- a card-specific layer reads
/// those (e.g. FINEID's pre-issuing product / OS / chip fields).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HistoricalDataObject {
    /// Tag 1: country / issuer indicator.
    CountryCode(CountryIndicator),
    /// Tag 2: issuer identification number (proprietary bytes).
    IssuerIdNumber(Vec<u8>),
    /// Tag 3: card service data bitfield.
    CardServiceData(CardServiceData),
    /// Tag 4: initial access data (proprietary bytes).
    InitialAccessData(Vec<u8>),
    /// Tag 5: card issuer's data (proprietary bytes).
    CardIssuerData(Vec<u8>),
    /// Tag 6: pre-issuing data (issuer-proprietary interior).
    PreIssuingData(Vec<u8>),
    /// Tag 7: card capabilities bitfields.
    CardCapabilities(CardCapabilities),
    /// Tag 8: status indicator (LCS and/or SW1-SW2).
    StatusIndicator(StatusIndicator),
    /// Any other / reserved tag: raw tag and value.
    Other {
        /// Compact-TLV tag (0..=15).
        tag: u8,
        /// Raw value bytes.
        value: Vec<u8>,
    },
}

/// TCK (check character) per ISO 7816-3 §8.2.5: XOR of T0
/// through the last historical byte equals TCK. Present only
/// when any `TDi` indicated a protocol other than T=0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TckByte(u8);

impl TckByte {
    /// Wrap a raw TCK byte.
    #[inline]
    #[must_use]
    pub const fn new(b: u8) -> Self {
        Self(b)
    }

    /// Raw wire byte.
    #[inline]
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self.0
    }
}

/// Parsed ATR (Answer to Reset) per ISO 7816-3 §8.
///
/// Construction via [`Atr::new`] parses the wire bytes into the
/// structured form below; the constructor is the trust boundary.
/// Consumers read typed fields rather than reaching into the
/// byte sequence.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Atr {
    /// TS: transmission convention (direct / inverse).
    convention: Convention,
    /// T0: Y1 nibble (which interface bytes follow) + K nibble
    /// (count of historical bytes).
    t0: T0,
    /// Interface byte chain (TA1/TB1/TC1/TD1, then groups 2+
    /// per each `TDi.next_yi` until a `TDi` without TD-present
    /// terminates the chain).
    interface_groups: Vec<InterfaceByteGroup>,
    /// Historical bytes (K of them, K from T0's low nibble).
    historical: HistoricalBytes,
    /// TCK: present iff any interface group's `TDi` indicated a
    /// protocol != T=0.
    tck: Option<TckByte>,
}

/// Errors returned by [`Atr::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtrError {
    /// Input was shorter than [`ATR_MIN_LEN`] (TS + T0 = 2).
    TooShort {
        /// Length of the rejected input in bytes.
        got: usize,
    },
    /// Input was longer than [`ATR_MAX_LEN`] (33 bytes).
    TooLong {
        /// Length of the rejected input in bytes.
        got: usize,
    },
    /// TS byte wasn't `3Bh` direct or `3Fh` inverse.
    InvalidConvention {
        /// The offending TS byte.
        got: u8,
    },
    /// Interface byte chain referenced bytes past the end of
    /// the buffer.
    TruncatedAtInterfaceBytes,
    /// K historical bytes referenced past the end of the
    /// buffer.
    TruncatedAtHistoricalBytes,
    /// TCK was required (a non-T=0 protocol indicator was seen)
    /// but the buffer ended before TCK.
    MissingTck,
    /// The buffer carried extra bytes after TCK / the last
    /// historical byte.
    TrailingBytes {
        /// Byte position where the parse expected the ATR to
        /// end.
        expected_end: usize,
        /// Actual buffer length.
        got: usize,
    },
}

impl fmt::Display for AtrError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { got } => write!(
                f,
                "ATR too short: got {got} bytes, ISO 7816-3 §8.1 requires at least {ATR_MIN_LEN}"
            ),
            Self::TooLong { got } => write!(
                f,
                "ATR too long: got {got} bytes, ISO 7816-3 §8.1 caps at {ATR_MAX_LEN}"
            ),
            Self::InvalidConvention { got } => write!(
                f,
                "ATR TS byte {got:#04X} is neither 3Bh (direct) nor 3Fh (inverse)"
            ),
            Self::TruncatedAtInterfaceBytes => {
                write!(f, "ATR truncated: interface byte chain extends past buffer")
            }
            Self::TruncatedAtHistoricalBytes => {
                write!(f, "ATR truncated: K historical bytes extend past buffer")
            }
            Self::MissingTck => write!(
                f,
                "ATR missing TCK: a non-T=0 protocol was indicated but TCK byte is absent"
            ),
            Self::TrailingBytes { expected_end, got } => {
                write!(
                    f,
                    "ATR has trailing bytes: expected to end at byte {expected_end}, buffer is {got} bytes"
                )
            }
        }
    }
}

impl core::error::Error for AtrError {}

impl Atr {
    /// Parse a wire ATR into the typed structure.
    ///
    /// # Errors
    /// [`AtrError`] when the bytes don't satisfy the ISO 7816-3
    /// §8 structure: out-of-range length, unknown TS, truncated
    /// chain, missing TCK, etc.
    #[inline]
    pub fn new<B: AsRef<[u8]>>(input: B) -> Result<Self, AtrError> {
        let bytes = input.as_ref();
        if bytes.len() < ATR_MIN_LEN {
            return Err(AtrError::TooShort { got: bytes.len() });
        }
        if bytes.len() > ATR_MAX_LEN {
            return Err(AtrError::TooLong { got: bytes.len() });
        }

        let mut idx = 0;

        // TS. Index access is bounded by the `bytes.len() < ATR_MIN_LEN`
        // check above (ATR_MIN_LEN = 2, indices 0 and 1 are in range).
        let ts = *bytes
            .get(idx)
            .ok_or(AtrError::TooShort { got: bytes.len() })?;
        idx = idx.saturating_add(1);
        let convention = Convention::from_ts(ts).ok_or(AtrError::InvalidConvention { got: ts })?;

        // T0
        let t0_byte = *bytes
            .get(idx)
            .ok_or(AtrError::TooShort { got: bytes.len() })?;
        let t0 = T0::from_byte(t0_byte);
        idx = idx.saturating_add(1);

        // Interface byte chain. Y_i starts from T0.y1; each
        // TDi.next_yi chains the next group; absent TDi
        // terminates the chain.
        let mut interface_groups: Vec<InterfaceByteGroup> = Vec::new();
        let mut yi = t0.y1;
        let mut any_non_t0_protocol = false;

        while yi.any_present() {
            let mut group = InterfaceByteGroup::default();

            if yi.ta_present() {
                let b = *bytes.get(idx).ok_or(AtrError::TruncatedAtInterfaceBytes)?;
                group.ta = Some(TaByte::new(b));
                idx = idx.saturating_add(1);
            }
            if yi.tb_present() {
                let b = *bytes.get(idx).ok_or(AtrError::TruncatedAtInterfaceBytes)?;
                group.tb = Some(TbByte::new(b));
                idx = idx.saturating_add(1);
            }
            if yi.tc_present() {
                let b = *bytes.get(idx).ok_or(AtrError::TruncatedAtInterfaceBytes)?;
                group.tc = Some(TcByte::new(b));
                idx = idx.saturating_add(1);
            }
            if yi.td_present() {
                let b = *bytes.get(idx).ok_or(AtrError::TruncatedAtInterfaceBytes)?;
                let td = TdByte::new(b);
                idx = idx.saturating_add(1);
                if td.protocol_indicator() != 0 {
                    any_non_t0_protocol = true;
                }
                let next = td.next_yi();
                group.td = Some(td);
                interface_groups.push(group);
                yi = next;
            } else {
                interface_groups.push(group);
                break;
            }
        }

        // Historical bytes
        let k = usize::from(t0.historical_byte_count);
        let hist_end = idx
            .checked_add(k)
            .ok_or(AtrError::TruncatedAtHistoricalBytes)?;
        let hist_slice = bytes
            .get(idx..hist_end)
            .ok_or(AtrError::TruncatedAtHistoricalBytes)?;
        let historical = HistoricalBytes::from_bytes(hist_slice.to_vec());
        idx = hist_end;

        // TCK present iff any non-T=0 protocol was seen.
        let tck = if any_non_t0_protocol {
            let b = *bytes.get(idx).ok_or(AtrError::MissingTck)?;
            idx = idx.saturating_add(1);
            Some(TckByte::new(b))
        } else {
            None
        };

        if idx != bytes.len() {
            return Err(AtrError::TrailingBytes {
                expected_end: idx,
                got: bytes.len(),
            });
        }

        Ok(Self {
            convention,
            t0,
            interface_groups,
            historical,
            tck,
        })
    }

    /// Transmission convention from the TS byte.
    #[inline]
    #[must_use]
    pub const fn convention(&self) -> Convention {
        self.convention
    }

    /// T0 byte unpacked (Y1 + K nibbles).
    #[inline]
    #[must_use]
    pub const fn t0(&self) -> T0 {
        self.t0
    }

    /// Interface byte chain (groups 1..N).
    #[inline]
    #[must_use]
    pub fn interface_groups(&self) -> &[InterfaceByteGroup] {
        &self.interface_groups
    }

    /// Historical bytes (K bytes from T0's K nibble).
    #[inline]
    #[must_use]
    pub const fn historical_bytes(&self) -> &HistoricalBytes {
        &self.historical
    }

    /// TCK byte; `None` when only T=0 was indicated (TCK is
    /// absent from the wire form per ISO 7816-3 §8.2.5).
    #[inline]
    #[must_use]
    pub const fn tck(&self) -> Option<TckByte> {
        self.tck
    }

    /// Re-emit the wire bytes from the typed structure.
    ///
    /// Useful for byte-equality comparison against reference
    /// tables (`FineidCardModel::contact_atr_byte_sets`)
    /// without losing the typed shape downstream.
    #[inline]
    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ATR_MAX_LEN);
        out.push(self.convention.as_ts());
        out.push(self.t0.as_byte());
        for group in &self.interface_groups {
            if let Some(ta) = group.ta {
                out.push(ta.as_byte());
            }
            if let Some(tb) = group.tb {
                out.push(tb.as_byte());
            }
            if let Some(tc) = group.tc {
                out.push(tc.as_byte());
            }
            if let Some(td) = group.td {
                out.push(td.as_byte());
            }
        }
        out.extend_from_slice(self.historical.as_bytes());
        if let Some(tck) = self.tck {
            out.push(tck.as_byte());
        }
        out
    }

    /// `true` if any interface group indicated a protocol
    /// other than T=0. When `false`, only T=0 was advertised
    /// and the ATR has no TCK byte.
    #[inline]
    #[must_use]
    pub fn supports_non_t0_protocol(&self) -> bool {
        self.interface_groups
            .iter()
            .any(|g| g.td.is_some_and(|td| td.protocol_indicator() != 0))
    }
}

impl fmt::Display for Atr {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.to_wire_bytes().iter().enumerate() {
            if i > 0 {
                write!(f, " ")?;
            }
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    /// Gemalto `MultiApp` v4.2 / FINEID S4-1 v3.1 ATR (the "old"
    /// card on the OMNIKEY reader).
    const ATR_GEMALTO_MULTIAPP_V4_2: &[u8] = &[
        0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0, 0x85, 0x04, 0x02, 0x1B, 0x12,
        0x00, 0xF6, 0x82, 0x90, 0x00,
    ];

    /// Thales `MultiApp` v5.0 / FINEID S4-1 v4.0 ATR, chip rev
    /// v1.0.0 (the "new" card on the ACS reader, first batch).
    const ATR_THALES_MULTIAPP_V5_0_REV_1_0: &[u8] = &[
        0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0, 0x85, 0x05, 0x00, 0x11, 0x12,
        0x24, 0x60, 0x82, 0x90, 0x00,
    ];

    #[test]
    fn parses_gemalto_multiapp_v4_2() -> Result<(), AtrError> {
        let atr = Atr::new(ATR_GEMALTO_MULTIAPP_V4_2)?;
        // TS: direct convention.
        assert_eq!(atr.convention(), Convention::Direct);
        // T0 = 7F: Y1 = 0111 (TA1/TB1/TC1 present, no TD1),
        // K = 15.
        assert_eq!(atr.t0().y1.as_nibble(), 0b0111);
        assert!(atr.t0().y1.ta_present());
        assert!(atr.t0().y1.tb_present());
        assert!(atr.t0().y1.tc_present());
        assert!(!atr.t0().y1.td_present());
        assert_eq!(atr.t0().historical_byte_count, 15);
        // Interface group 1: TA1=96, TB1=00, TC1=00, no TD1.
        let g = &atr.interface_groups()[0];
        assert_eq!(g.ta.expect("TA1 present").as_byte(), 0x96);
        assert_eq!(g.tb.expect("TB1 present").as_byte(), 0x00);
        assert_eq!(g.tc.expect("TC1 present").as_byte(), 0x00);
        assert!(g.td.is_none());
        // TA1: FI=9, DI=6 (high-speed).
        assert_eq!(g.ta.expect("TA1 present").fi_index(), 9);
        assert_eq!(g.ta.expect("TA1 present").di_index(), 6);
        // No TD => only T=0 => no TCK.
        assert!(!atr.supports_non_t0_protocol());
        assert!(atr.tck().is_none());
        // Historical bytes: 15 bytes starting with 80h (compact-TLV).
        assert_eq!(atr.historical_bytes().len(), 15);
        assert_eq!(atr.historical_bytes().category_indicator(), Some(0x80));
        assert!(atr.historical_bytes().is_compact_tlv());
        // Round-trip wire bytes.
        assert_eq!(atr.to_wire_bytes(), ATR_GEMALTO_MULTIAPP_V4_2);
        Ok(())
    }

    #[test]
    fn parses_thales_multiapp_v5_0_compact_tlv_entries() -> Result<(), AtrError> {
        let atr = Atr::new(ATR_THALES_MULTIAPP_V5_0_REV_1_0)?;
        let entries = atr.historical_bytes().compact_tlv_entries();
        // First entry: tag 3 (card service data), length 1, value B8.
        assert_eq!(entries[0].tag, 0x3);
        assert_eq!(entries[0].value, vec![0xB8]);
        // Second entry: tag 6 (pre-issuing data), length 5.
        assert_eq!(entries[1].tag, 0x6);
        assert_eq!(entries[1].value.len(), 5);
        // Third entry: tag 1 (country/national use), length 2.
        assert_eq!(entries[2].tag, 0x1);
        assert_eq!(entries[2].value.len(), 2);
        // Fourth entry: tag 8 (status indicator), length 2, value 90 00.
        assert_eq!(entries[3].tag, 0x8);
        assert_eq!(entries[3].value, vec![0x90, 0x00]);
        Ok(())
    }

    #[test]
    fn ta1_decodes_iso_physical_values() -> Result<(), AtrError> {
        // FINEID TA1 = 0x96: FI=9, DI=6 -> Fi=512, f(max)=5 MHz,
        // Di=32 (FINEID S4-1 §3.3.1 / ISO 7816-3 Tables 7-8).
        let atr = Atr::new(ATR_GEMALTO_MULTIAPP_V4_2)?;
        let ta1 = atr.interface_groups()[0].ta.expect("TA1 present");
        assert_eq!(ta1.ta1_clock_rate_conversion(), Some(512));
        assert_eq!(ta1.ta1_max_frequency_khz(), Some(5_000));
        assert_eq!(ta1.ta1_bit_rate_adjustment(), Some(32));
        // RFU index -> None (FI=7).
        assert_eq!(TaByte::new(0x70).ta1_clock_rate_conversion(), None);
        assert_eq!(TaByte::new(0x70).ta1_max_frequency_khz(), None);
        // DI=0 is RFU.
        assert_eq!(TaByte::new(0x90).ta1_bit_rate_adjustment(), None);
        Ok(())
    }

    #[test]
    fn typed_data_objects_decode_fineid_historical_bytes() -> Result<(), AtrError> {
        let atr = Atr::new(ATR_THALES_MULTIAPP_V5_0_REV_1_0)?;
        let objects = atr.historical_bytes().data_objects();
        // FINEID S4-1 §3.3.1 order: card service data (3),
        // pre-issuing data (6), country code (1), status (8).
        assert_eq!(objects.len(), 4);

        // Tag 3: card service data B8 = 1011_1000.
        let HistoricalDataObject::CardServiceData(csd) = &objects[0] else {
            panic!("expected CardServiceData, got {:?}", objects[0]);
        };
        assert_eq!(csd.as_byte(), 0xB8);
        assert!(csd.app_selection_by_full_df_name()); // b8
        assert!(!csd.app_selection_by_partial_df_name()); // b7
        assert!(csd.ber_tlv_in_ef_dir()); // b6
        assert!(csd.ber_tlv_in_ef_atr()); // b5
        assert!(csd.has_master_file()); // b1 == 0

        // Tag 6: pre-issuing data stays ISO-opaque (the FINEID layer
        // names the interior); 5 bytes B0 85 05 00 11.
        let HistoricalDataObject::PreIssuingData(pre) = &objects[1] else {
            panic!("expected PreIssuingData, got {:?}", objects[1]);
        };
        assert_eq!(pre, &vec![0xB0, 0x85, 0x05, 0x00, 0x11]);

        // Tag 1: country code 246 (FIN) from value 24 60.
        let HistoricalDataObject::CountryCode(country) = &objects[2] else {
            panic!("expected CountryCode, got {:?}", objects[2]);
        };
        assert_eq!(country.country_code(), Some(246));

        // Tag 8: status indicator SW1 SW2 = 90 00.
        let HistoricalDataObject::StatusIndicator(status) = &objects[3] else {
            panic!("expected StatusIndicator, got {:?}", objects[3]);
        };
        assert_eq!(
            *status,
            StatusIndicator::StatusWord {
                sw1: 0x90,
                sw2: 0x00
            }
        );
        Ok(())
    }

    #[test]
    fn rejects_too_short() {
        let one_byte_err = Atr::new([0x3B]).expect_err("one-byte ATR is rejected");
        assert_eq!(one_byte_err, AtrError::TooShort { got: 1 });
        let empty: [u8; 0] = [];
        let empty_err = Atr::new(empty).expect_err("empty ATR is rejected");
        assert_eq!(empty_err, AtrError::TooShort { got: 0 });
    }

    #[test]
    fn rejects_too_long() {
        let v = vec![0x3B; ATR_MAX_LEN + 1];
        let err = Atr::new(v).expect_err("overlong ATR is rejected");
        assert_eq!(
            err,
            AtrError::TooLong {
                got: ATR_MAX_LEN + 1
            }
        );
    }

    #[test]
    fn rejects_invalid_convention() {
        const NOT_DIRECT_OR_INVERSE: u8 = 0x00;
        let err = Atr::new([NOT_DIRECT_OR_INVERSE, 0x00]).expect_err("invalid TS byte is rejected");
        assert_eq!(
            err,
            AtrError::InvalidConvention {
                got: NOT_DIRECT_OR_INVERSE
            }
        );
    }

    #[test]
    fn minimal_atr_ts_t0_only() -> Result<(), AtrError> {
        // TS=3B, T0=00 (Y1=0 no interface bytes, K=0 no
        // historical), no TCK because no protocol indicator.
        let atr = Atr::new([Convention::Direct.as_ts(), 0x00])?;
        assert_eq!(atr.convention(), Convention::Direct);
        assert_eq!(atr.t0().y1.as_nibble(), 0);
        assert_eq!(atr.t0().historical_byte_count, 0);
        assert!(atr.interface_groups().is_empty());
        assert!(atr.historical_bytes().is_empty());
        assert!(atr.tck().is_none());
        Ok(())
    }

    #[test]
    fn td1_t1_protocol_requires_tck() -> Result<(), AtrError> {
        // TS=3B, T0=80 (Y1=1000: TD1 present, K=0), TD1=01
        // (protocol T=1, next Yi=0 -> chain ends), TCK=0x81
        // (XOR of T0 ^ TD1 = 0x80 ^ 0x01 = 0x81).
        let atr = Atr::new([0x3B, 0x80, 0x01, 0x81])?;
        assert!(atr.t0().y1.td_present());
        let group = &atr.interface_groups()[0];
        assert_eq!(group.td.expect("TD1 present").protocol_indicator(), 1);
        assert!(atr.supports_non_t0_protocol());
        assert_eq!(atr.tck().expect("TCK present").as_byte(), 0x81);
        Ok(())
    }
}
