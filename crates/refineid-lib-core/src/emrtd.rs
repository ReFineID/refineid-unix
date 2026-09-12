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

//! ICAO 9303 EMRTD (Electronic Machine-Readable Travel Document)
//! file reading + MRZ / face-image parsing.
//!
//! Pre-conditions: the transport passed to `select_application`
//! and `read_file` **must** already speak Secure Messaging -- the
//! eMRTD applet on a FINEID card refuses any unprotected APDU.
//! Build the SM-wrapped transport by first running
//! [`crate::pace::run_pace_with_can`] and then wrapping the raw
//! transport in [`crate::secure_messaging::SmTransport`].
//!
//! The module ports `EMRTDReader.swift` and `ParsedMRZ.swift` from
//! `legacy/refinneid-core` -- the iOS reference reader the project
//! shipped before the Rust rewrite. The wire-protocol surface
//! (SELECT, READ BINARY by SFI / offset, 0x6282 end-of-file
//! handling) and the TD1 MRZ-field layout (ICAO 9303-5 §4.2.2)
//! follow the standard.
//!
//! Out of scope for v0:
//!
//! - Passive authentication via EF.SOD (chains DG hashes to the
//!   document-signing certificate of the issuing CSCA). Required
//!   for tamper-proof reads; nice-to-have but separable from the
//!   data-extraction shape.
//! - Active Authentication / Chip Authentication. Both are
//!   optional on FINEID-S1 cards.
//! - DG3-DG16 except DG2 (face). DG11 (extended personal data,
//!   notably full names with diacritics) is an obvious next
//!   addition; deferred until a consumer needs it.
//! - Image format detection beyond JPEG / JPEG2000 magic-byte
//!   scanning. The CBEFF/BHT envelope is stripped by locating
//!   the embedded image rather than parsing the biometric
//!   header proper.

use crate::apdu::iso7816::{ReadBinaryByOffset, ReadBinaryBySfi, SelectByAidNoFci};
use crate::apdu::primitives::Aid;
use crate::apdu::status_word::StatusWord;
use crate::ber::{BerError, BerTag, BerTlv, BerTlvIter, Integer, Oid, Sequence, Set};

// Module-local tag markers for the eMRTD application-class
// wrappers. ICAO 9303-10 §3.5 / 9303-11 §9.2 fix each Data
// Group's outer tag; carrying that identity at the type level
// keeps DG1 / DG14 / DG15 parsers from accidentally accepting
// the wrong wrapper.

/// `[APPLICATION 1]` -- DG1 (MRZ) wrapper.
#[derive(Debug, Clone, Copy)]
pub struct Dg1Wrapper;
/// Wire tag byte for the DG1 `[APPLICATION 1]` wrapper.
const DG1_WRAPPER_TAG_BYTE: u8 = 0x61;
impl BerTag for Dg1Wrapper {
    const TAG: u16 = u16::from_be_bytes([0, DG1_WRAPPER_TAG_BYTE]);
}

/// `[APPLICATION 11]` -- DG11 (additional personal data) wrapper.
#[derive(Debug, Clone, Copy)]
pub struct Dg11Wrapper;
impl BerTag for Dg11Wrapper {
    const TAG: u16 = 0x6B;
}

/// `[APPLICATION 12]` -- DG12 (additional document data) wrapper.
#[derive(Debug, Clone, Copy)]
pub struct Dg12Wrapper;
impl BerTag for Dg12Wrapper {
    const TAG: u16 = 0x6C;
}

/// `[APPLICATION 14]` -- DG14 (Security Options) wrapper.
#[derive(Debug, Clone, Copy)]
pub struct Dg14Wrapper;
impl BerTag for Dg14Wrapper {
    const TAG: u16 = 0x6E;
}

/// `[APPLICATION 15]` -- DG15 (Active Authentication public
/// key) wrapper.
#[derive(Debug, Clone, Copy)]
pub struct Dg15Wrapper;
impl BerTag for Dg15Wrapper {
    const TAG: u16 = 0x6F;
}

/// `[0]` context-specific constructed container (tag 0xA0).
///
/// Used inside DG11 (around nested `5F0F` other-name entries)
/// and DG12 (around nested `5F1A` name-of-other-person
/// entries). Same byte in both DG contexts; the parent DG
/// sub-tag inside selects the semantic.
#[derive(Debug, Clone, Copy)]
pub struct Dg1xContainerA0;
impl BerTag for Dg1xContainerA0 {
    const TAG: u16 = 0xA0;
}

/// ICAO 9303-10 data-element tags: the two-byte `5F xx` context
/// tags carried inside DG1 (MRZ), DG11 (additional personal
/// details, Table 71) and DG12 (additional document details,
/// Table 72). Named once here so the DG parsers match on a tag's
/// *meaning*, never a bare hex literal (Rule E -- the hex-offender
/// gate flagged the old `0x5F0E => ...` arms).
mod dg_tag {
    /// DG1 MRZ data element (the MRZ string inside `[APPLICATION 1]`).
    pub(super) const MRZ_DATA: u16 = 0x5F1F;

    // --- DG11: additional personal details (ICAO 9303-10 Table 71) ---
    /// Full name of holder.
    pub(super) const FULL_NAME: u16 = 0x5F0E;
    /// Other names (nested inside the `0xA0` container).
    pub(super) const OTHER_NAMES: u16 = 0x5F0F;
    /// Personal number.
    pub(super) const PERSONAL_NUMBER: u16 = 0x5F10;
    /// Full date of birth (`YYYYMMDD`).
    pub(super) const FULL_DATE_OF_BIRTH: u16 = 0x5F2B;
    /// Place of birth.
    pub(super) const PLACE_OF_BIRTH: u16 = 0x5F11;
    /// Permanent address.
    pub(super) const PERMANENT_ADDRESS: u16 = 0x5F42;
    /// Telephone.
    pub(super) const TELEPHONE: u16 = 0x5F12;
    /// Profession.
    pub(super) const PROFESSION: u16 = 0x5F13;
    /// Title.
    pub(super) const TITLE: u16 = 0x5F14;
    /// Personal summary.
    pub(super) const PERSONAL_SUMMARY: u16 = 0x5F15;
    /// Proof-of-citizenship image.
    pub(super) const PROOF_OF_CITIZENSHIP: u16 = 0x5F16;
    /// Other valid TD numbers (`<`-separated list).
    pub(super) const OTHER_TD_NUMBERS: u16 = 0x5F17;
    /// Custody information.
    pub(super) const CUSTODY_INFORMATION: u16 = 0x5F18;

    // --- DG12: additional document details (ICAO 9303-10 Table 72) ---
    /// Issuing authority.
    pub(super) const ISSUING_AUTHORITY: u16 = 0x5F19;
    /// Name of other person (nested inside the `0xA0` container).
    pub(super) const NAME_OF_OTHER_PERSON: u16 = 0x5F1A;
    /// Endorsements / observations.
    pub(super) const ENDORSEMENTS: u16 = 0x5F1B;
    /// Tax / exit requirements.
    pub(super) const TAX_EXIT: u16 = 0x5F1C;
    /// Image of document front.
    pub(super) const IMAGE_FRONT: u16 = 0x5F1D;
    /// Image of document rear.
    pub(super) const IMAGE_REAR: u16 = 0x5F1E;
    /// Date of issue (`YYYYMMDD`).
    pub(super) const DATE_OF_ISSUE: u16 = 0x5F26;
    /// Personalisation time (`YYYYMMDDHHMMSS`).
    pub(super) const PERSONALISATION_TIME: u16 = 0x5F55;
    /// Personalisation device serial.
    pub(super) const PERSONALISATION_DEVICE_SERIAL: u16 = 0x5F56;
}

/// BER leading-tag-byte structure (ITU-T X.690 §8.1.2), for the
/// hand-rolled two-byte-tag reader in this module. Named so the
/// structural masks aren't bare hex in comparisons (Rule E).
mod ber_tag {
    /// Low 5 bits of the leading tag byte. All-ones (`0x1F`) is the
    /// high-tag-number form: the tag number continues in the
    /// following byte(s).
    pub(super) const HIGH_TAG_NUMBER_MASK: u8 = 0x1F;
    /// High bit used by multi-byte tags and long-form lengths.
    pub(super) const CONTINUATION_OR_LONG_FORM_MASK: u8 = 0x80;
    /// Low 7 bits carry the long-form length-of-length.
    pub(super) const LONG_FORM_LENGTH_COUNT_MASK: u8 = 0x7F;
}
use crate::identity::{
    CustodyInformation, DateOfBirth, Dg11FullName, Endorsements, IssueDate, IssuingAuthority,
    MrzDate, MrzGivenName, MrzSex, MrzSurname, OtherName, OtherPerson, OtherTdNumber,
    PermanentAddress, PersonalNumber, PersonalSummary, PersonalisationDeviceSerial,
    PersonalisationTime, PlaceOfBirth, Profession, TaxExit, Telephone, Title,
};
use crate::pace;
use crate::secure_messaging::SmTransport;
use crate::transport::CardTransport;

/// Applet AID per ICAO 9303-11 §4.1.2.
pub const APPLET_AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01];

// Compile-time guard: catches accidental edits that resize
// `APPLET_AID` outside the ISO 7816-5 length range. The runtime
// `Aid::from_slice` check inside `select_application` becomes
// statically provable.
const _: () = assert!(
    APPLET_AID.len() >= 5 && APPLET_AID.len() <= 16,
    "APPLET_AID must satisfy ISO 7816-5 AID length range 5..=16"
);

// Short File Identifier brought into scope so the `SFI_EF_*`
// const definitions below can use the bare type name. Demoted
// from `pub use` to `use` because no external caller depends on
// the re-export -- `Sfi` is reachable via its canonical path
// `crate::apdu::primitives::Sfi`.
use crate::apdu::primitives::Sfi;

/// SFI for EF.COM (Common Data Element list) per ICAO Doc 9303-10 §3.6.
pub const SFI_EF_COM: Sfi = Sfi::from_const(0x1E);
/// SFI for DG1 (MRZ) per ICAO Doc 9303-10 §4.7.1.
pub const SFI_EF_DG1: Sfi = Sfi::from_const(0x01);
/// SFI for DG2 (encoded face) per ICAO Doc 9303-10 §4.7.2.
pub const SFI_EF_DG2: Sfi = Sfi::from_const(0x02);
/// SFI for DG3 (encoded fingerprints; EAC-protected) per ICAO
/// Doc 9303-10 §4.7.3.
pub const SFI_EF_DG3: Sfi = Sfi::from_const(0x03);
/// SFI for DG7 (displayed signature or usual mark) per ICAO
/// Doc 9303-10 §4.7.7.
pub const SFI_EF_DG7: Sfi = Sfi::from_const(0x07);
/// SFI for DG11 (additional personal details) per ICAO
/// Doc 9303-10 §4.7.11.
pub const SFI_EF_DG11: Sfi = Sfi::from_const(0x0B);
/// SFI for DG12 (additional document details) per ICAO
/// Doc 9303-10 §4.7.12.
pub const SFI_EF_DG12: Sfi = Sfi::from_const(0x0C);
/// SFI for DG13 (issuing-state optional details) per ICAO
/// Doc 9303-10 §4.7.13.
pub const SFI_EF_DG13: Sfi = Sfi::from_const(0x0D);
/// SFI for DG14 (chip-auth security infos) per ICAO Doc 9303-11
/// §9.2.
pub const SFI_EF_DG14: Sfi = Sfi::from_const(0x0E);
/// SFI for DG15 (active-authentication public key) per ICAO
/// Doc 9303-11 §9.1.
pub const SFI_EF_DG15: Sfi = Sfi::from_const(0x0F);
/// SFI for EF.SOD (Document Security Object, CMS `SignedData` per
/// RFC 5652) per ICAO Doc 9303-10 §4.6.2.
pub const SFI_EF_SOD: Sfi = Sfi::from_const(0x1D);

/// Max read chunk per ISO 7816-4 single-byte Le, leaving room for SM
/// overhead (eMRTD SM wraps every command into DO87 + DO8E adding
/// ~28 bytes of fixed envelope). Matches `EMRTDReader.swift`.
const MAX_CHUNK: usize = 0xE0;

/// SELECT the eMRTD applet by AID. Returns the SW as a `u16`.
/// Typical successful SW is `0x9000`.
///
/// # Errors
///
/// Returns [`EmrtdError::Transport`] when the underlying APDU exchange fails.
/// # Panics
/// Never in practice -- `APPLET_AID` is a 7-byte compile-time
/// constant within the [`Aid`] 5..=16-byte invariant.
///
/// [`Aid`]: Aid
#[inline]
pub(crate) fn select_application<T: CardTransport>(
    transport: &mut T,
) -> Result<StatusWord, EmrtdError<T::Error>> {
    // Compile-time const-assert above (see the `const _: () = assert!(...)`
    // guarding `APPLET_AID.len()`) makes the constructor's length check
    // statically provable; the `expect` cannot fire.
    #[expect(
        clippy::expect_used,
        clippy::unwrap_in_result,
        reason = "APPLET_AID is a 7-byte compile-time constant proven in-range by the `const _: () = assert!` above; the runtime check cannot fail.  Both lints (`expect_used` from the call, `unwrap_in_result` from being inside a `Result`-returning fn) are suppressed by the same rationale."
    )]
    let aid = Aid::from_slice(&APPLET_AID)
        .expect("APPLET_AID is a 7-byte constant within ISO 7816-5 length range");
    let apdu = SelectByAidNoFci { aid }.into_apdu();
    let r = transport
        .transmit(apdu.as_bytes())
        .map_err(EmrtdError::Transport)?;
    Ok(r.status_word())
}

/// Read the entire contents of an EF by Short File Identifier.
///
/// Strategy (mirrors `EMRTDReader.readFile` from the iOS port):
///
/// 1. READ BINARY by SFI for 4 bytes -- enough to decode the outer
///    ASN.1 length and learn the total EF size.
/// 2. Loop READ BINARY by offset until we've read that many bytes
///    or the card signals end-of-file (`SW=0x6282`).
///
/// On a clean read the returned buffer starts with the outer
/// ICAO TLV envelope (tag varies per DG -- DG1 is `61`, DG2 is `75`).
///
/// # Errors
///
/// Returns [`EmrtdError::Transport`] when an APDU exchange fails and
/// [`EmrtdError::Sw`] when the card reports a non-success status word
/// (other than `0x6282` end-of-file, which is benign).
#[inline]
pub(crate) fn read_file<T: CardTransport>(
    transport: &mut T,
    sfi: Sfi,
) -> Result<Vec<u8>, EmrtdError<T::Error>> {
    let header = read_chunk(transport, AddressMode::Sfi(sfi), 0, 4)?;
    if header.len() < 2 {
        return Ok(header);
    }
    let total = BerInput::parse(&header)
        .map_or_else(|_err| header.len(), EmrtdHelpers::decode_outer_total_length);

    let mut collected = header;
    while collected.len() < total {
        // `want` is bounded by MAX_CHUNK = 0xE0, which fits in u8
        // by construction; the outer `while` guard guarantees
        // `total > collected.len()` so the subtraction does not
        // underflow.
        let remaining = total.saturating_sub(collected.len());
        let want = u8::try_from(core::cmp::min(MAX_CHUNK, remaining)).unwrap_or(u8::MAX);
        // EF.DG1/DG2 sizes on a FINEID card sit well below 64 KiB, and
        // ICAO 9303 caps EFs at 65535 bytes anyway (BER long-form Le=0x82).
        // Past 0xFFFF we stop -- the card can't address higher
        // anyway under the short-form READ BINARY shape.
        let Ok(offset) = u16::try_from(collected.len()) else {
            break;
        };
        let chunk = read_chunk(transport, AddressMode::Offset, offset, want)?;
        if chunk.is_empty() {
            break;
        }
        collected.extend_from_slice(&chunk);
    }
    Ok(collected)
}

/// Which addressing form a chunked READ BINARY uses against an
/// eMRTD application.
///
/// ISO 7816-4 §7.2.3 defines two `READ BINARY` shapes: short-EF
/// implicit (SFI in P1) and offset-only (current EF, offset in
/// P1||P2). The eMRTD select chain typically selects DG1..DG16
/// once via SFI to pick up the SOD-promised file, then continues
/// with offset-form reads to walk through it.
#[derive(Debug, Clone, Copy)]
enum AddressMode {
    /// Short EF identifier addressing -- ISO 7816-4 §7.2.3 (P1
    /// has the SFI marker, P2 has the byte offset 0..127).
    Sfi(Sfi),
    /// Current-EF offset addressing -- ISO 7816-4 §7.2.3 (P1||P2
    /// is the 15-bit offset against the previously-selected EF).
    Offset,
}

/// Issue one READ BINARY APDU and return the response body.
///
/// ISO 7816-4 §7.2.3 -- this is the per-chunk primitive that the
/// outer file-streaming loop uses. Treats `6282` (end-of-file
/// reached before `length` bytes) as success because eMRTD data
/// groups are read by walking off the end intentionally;
/// callers detect EOF by the short response, not by an error.
fn read_chunk<T: CardTransport>(
    transport: &mut T,
    mode: AddressMode,
    offset: u16,
    length: u8,
) -> Result<Vec<u8>, EmrtdError<T::Error>> {
    let apdu = match mode {
        AddressMode::Sfi(sfi) => ReadBinaryBySfi {
            sfi,
            // SFI-form READ BINARY P2 carries the offset; for
            // the eMRTD first-chunk discovery refineid always
            // passes 0 here (full read starts at byte 0).  The
            // low byte of the offset is the on-wire P2 byte; the
            // high byte travels in P1 alongside the SFI marker
            // for the alternate-form variant we don't use here.
            // `to_be_bytes()[1]` reads as "low byte of the
            // big-endian repr" and silences
            // clippy::little_endian_bytes (which prefers be_bytes
            // workspace-wide).
            offset: offset.to_be_bytes()[1],
            le: length,
        }
        .into_apdu(),
        AddressMode::Offset => ReadBinaryByOffset { offset, le: length }.into_apdu(),
    };
    let r = transport
        .transmit(apdu.as_bytes())
        .map_err(EmrtdError::Transport)?;
    // EndOfFile (`0x6282`) is benign for a READ BINARY -- the
    // body up to the boundary is still valid; return whatever
    // the card actually gave us.
    if matches!(r.status_word(), StatusWord::Success | StatusWord::EndOfFile) {
        Ok(r.body)
    } else {
        Err(EmrtdError::Sw {
            op: "READ BINARY",
            sw: r.sw(),
        })
    }
}

/// Decode the *total* length (tag + length-field + value) from the
/// first few bytes of an ASN.1 DER blob. Used to learn how many
/// more bytes need to be read after the initial SFI-read header.
///
/// Supports single-byte and multi-byte tags (per ISO 7816-4 §5.2.2.1:
/// low five bits of the first tag byte all 1s -> continuation bytes
/// follow with high bit set, terminated by one byte with high bit
/// clear). Length form is short-form (`< 0x80`) or long-form
/// (`0x81`, `0x82`, ...).
/// Helpers hosted on a unit struct (typing-discipline: no
/// free fns with borrowed parameters; see
/// `doc/typing-discipline.md`).
struct EmrtdHelpers;

#[derive(Debug, Clone, Copy)]
/// Empty input for a typed BER byte view.
struct BerInputError;

/// Non-empty BER input slice under local parser control.
#[derive(Debug, Clone, Copy)]
struct BerInput<'a> {
    /// Bytes left for the hand-rolled BER reader.
    bytes: &'a [u8],
}

/// Value bytes of one BER TLV after tag and length parsing.
#[derive(Debug, Clone, Copy)]
struct BerValue<'a> {
    /// Borrowed content octets of the current TLV.
    bytes: &'a [u8],
}

/// Result of reading one BER TLV with this module's light parser.
#[derive(Debug, Clone, Copy)]
struct BerTlvRead<'a> {
    /// Numeric BER tag, including both bytes for `5F xx` tags.
    tag: u16,
    /// Borrowed value bytes for the TLV.
    value: BerValue<'a>,
    /// Full encoded TLV size: tag + length + value.
    total_size: usize,
}

impl<'a> BerInput<'a> {
    /// Build a BER input view, rejecting empty slices.
    const fn parse(bytes: &'a [u8]) -> Result<Self, BerInputError> {
        if bytes.is_empty() {
            Err(BerInputError)
        } else {
            Ok(Self { bytes })
        }
    }

    /// Borrow the underlying BER bytes.
    const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Return the remaining byte length.
    const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return the first byte, if present.
    const fn first(&self) -> Option<u8> {
        self.bytes.first().copied()
    }

    /// Return a new input view starting at `offset`.
    fn remaining_from(&self, offset: usize) -> Option<Self> {
        Self::parse(self.bytes.get(offset..)?).ok()
    }

    /// Test whether the first byte matches a single-byte typed tag.
    fn has_tag<T: BerTag>(&self) -> bool {
        self.first().map(u16::from) == Some(T::TAG)
    }
}

impl<'a> BerValue<'a> {
    /// Borrow the TLV value bytes.
    const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

impl EmrtdHelpers {
    /// Best-effort outer-TLV total length from the first bytes
    /// of a DG file.
    ///
    /// Returns `header.len()` when the header is too short to
    /// decode -- the eMRTD streaming loop then issues a single
    /// follow-up READ that captures whatever's there; the higher
    /// layer reports the error against the full file body, not
    /// the chunk header. Short tag (low 5 bits ≠ `1F`) and
    /// short-form length are the common case for DG1/DG2/DG14.
    fn decode_outer_total_length(header: BerInput<'_>) -> usize {
        Self::decode_outer_total_length_inner(header).unwrap_or(header.len())
    }

    /// `?`-propagating inner form. `None` collapses to "give up,
    /// caller reads what's there"; the public wrapper above turns
    /// that into `header.len()`. Bounds are checked at every byte
    /// access via `.get(..)?`, so the function cannot panic.
    fn decode_outer_total_length_inner(header: BerInput<'_>) -> Option<usize> {
        let first = header.first()?;
        let mut i: usize = 1;
        if first & ber_tag::HIGH_TAG_NUMBER_MASK == ber_tag::HIGH_TAG_NUMBER_MASK {
            // Multi-byte tag: continuation bytes have the high
            // bit set; the terminator has the high bit clear.
            while header
                .bytes()
                .get(i)
                .is_some_and(|b| b & ber_tag::CONTINUATION_OR_LONG_FORM_MASK != 0)
            {
                i = i.checked_add(1)?;
            }
            // Consume the terminator byte (high bit clear).
            if header.bytes().get(i).is_some() {
                i = i.checked_add(1)?;
            }
        }
        let tag_bytes = i;

        let len_first = *header.bytes().get(i)?;
        i = i.checked_add(1)?;
        let (length_field_bytes, value_len) = if len_first < ber_tag::CONTINUATION_OR_LONG_FORM_MASK
        {
            (1_usize, usize::from(len_first))
        } else {
            let n = usize::from(len_first & ber_tag::LONG_FORM_LENGTH_COUNT_MASK);
            let mut v: usize = 0;
            for j in 0..n {
                let idx = i.checked_add(j)?;
                let b = *header.bytes().get(idx)?;
                v = v.checked_shl(8)?.checked_add(usize::from(b))?;
            }
            (1_usize.checked_add(n)?, v)
        };
        tag_bytes
            .checked_add(length_field_bytes)?
            .checked_add(value_len)
    }
}

/// Parsed three-line ICAO 9303-5 Machine Readable Zone (TD1 format,
/// 30 characters per line -- the ID-1 sized documents like the
/// Finnish FINEID card use this).
///
/// Date fields stay in their MRZ-printed `YYMMDD` form; callers
/// resolve the century with whatever sliding-window rule matches
/// their domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMrz {
    /// Whitespace-stripped MRZ string the parse consumed (90
    /// ASCII chars for TD1). Tier 0 `String` -- presentational;
    /// the typed projections are the per-field newtypes below.
    pub raw: String,
    /// Document type code per ICAO 9303-3 §4.4 (e.g. "I",
    /// "ID", "P"). Tier 0 `String` -- a tighter form would be an
    /// enum of the spec-defined codes; today the parser carries
    /// the bytes through after `<` trim.
    pub document_type: String,
    /// ICAO 9303 issuing-state code from MRZ DG1, parsed into
    /// the typed [`crate::country::IcaoCountry`] so downstream
    /// cross-checks against X.509 DN `countryName` go through
    /// the typed `country::icao_to_iso` table.
    pub issuing_country: crate::country::IcaoCountry,
    /// Document number (positions 5..14 of MRZ line 1 for TD1).
    /// Tier 0 `String` -- a tighter form would be a
    /// `DocumentNumber` newtype enforcing the alphanumeric ASCII
    /// + filler-char class of ICAO 9303-3 §4.7.
    pub document_number: String,
    /// MRZ date of birth (`YYMMDD`, century-resolution at
    /// consumer time via [`MrzDate::date`]).
    pub date_of_birth: MrzDate,
    /// Typed sex code per ICAO 9303-3 §4.5.
    pub sex: MrzSex,
    /// MRZ date of expiry (`YYMMDD`, century-resolution at
    /// consumer time via `MrzDate::resolve_as_issue_date` --
    /// the same algorithm; the typed return value is a
    /// semantically-correct issue/expiry date, not a
    /// [`crate::identity::DateOfBirth`]).
    pub date_of_expiry: MrzDate,
    /// ICAO 9303 nationality code from MRZ DG1.
    pub nationality: crate::country::IcaoCountry,
    /// Primary identifier (surname), in MRZ-transliterated form
    /// (A-Z + `<` only). Native-form surname lives in the cert
    /// subject DN and DG11; this is the ICAO 9303-3 §6
    /// transliterated copy.
    pub primary_identifier: MrzSurname,
    /// Secondary identifier (given names), MRZ-transliterated.
    /// Multiple given names join with single `<`.
    pub secondary_identifier: MrzGivenName,
}

impl ParsedMrz {
    /// Convenience: Fluent-friendly token for i18n message
    /// variant selection. Delegates to [`MrzSex::fluent_token`].
    #[inline]
    #[must_use]
    pub const fn gender_token(&self) -> &'static str {
        self.sex.fluent_token()
    }
}

/// Total TD1 MRZ length: three ICAO 9303-5 lines of 30 bytes.
const TD1_TOTAL_LEN: usize = 90;
/// One TD1 MRZ line length in bytes.
const TD1_LINE_LEN: usize = 30;
/// TD1 line-1 byte range for the document-type code.
const MRZ_DOCUMENT_TYPE_RANGE: core::ops::Range<usize> = 0..2;
/// TD1 line-1 byte range for the issuing-state code.
const MRZ_ISSUING_COUNTRY_RANGE: core::ops::Range<usize> = 2..5;
/// TD1 line-1 byte range for the document number.
const MRZ_DOCUMENT_NUMBER_RANGE: core::ops::Range<usize> = 5..14;
/// TD1 line-2 byte range for the `YYMMDD` birth date.
const MRZ_BIRTH_DATE_RANGE: core::ops::Range<usize> = 0..6;
/// TD1 line-2 byte offset for the sex marker.
const MRZ_SEX_OFFSET: usize = 7;
/// TD1 line-2 byte range for the `YYMMDD` expiry date.
const MRZ_EXPIRY_DATE_RANGE: core::ops::Range<usize> = 8..14;
/// TD1 line-2 byte range for the nationality code.
const MRZ_NATIONALITY_RANGE: core::ops::Range<usize> = 15..18;

/// Failure class for TD1 MRZ parsing.
#[derive(Debug, Clone)]
pub(crate) enum MrzParseError {
    /// The MRZ did not have TD1 shape: length, line split, or ASCII.
    Shape {
        /// Human-readable parse detail.
        detail: String,
    },
    /// A shaped field failed semantic validation.
    Field {
        /// Human-readable validation detail.
        detail: String,
    },
}

impl MrzParseError {
    /// Build a shape error from a static parser detail.
    fn shape_detail(detail: &'static str) -> Self {
        Self::Shape {
            detail: detail.to_owned(),
        }
    }

    /// Build a shape error that carries the original conversion failure.
    fn shape_error<E: core::fmt::Display>(err: E) -> Self {
        Self::Shape {
            detail: err.to_string(),
        }
    }

    /// Build a field error from a static validation detail.
    fn field_detail(detail: &'static str) -> Self {
        Self::Field {
            detail: detail.to_owned(),
        }
    }

    /// Build a field error that carries the original validation failure.
    fn field_error<E: core::fmt::Display>(err: E) -> Self {
        Self::Field {
            detail: err.to_string(),
        }
    }
}

impl core::fmt::Display for MrzParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Shape { detail } => write!(f, "TD1 shape: {detail}"),
            Self::Field { detail } => write!(f, "TD1 field: {detail}"),
        }
    }
}

/// Validated EF.DG1 wire bytes with the `[APPLICATION 1]` wrapper.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Dg1Bytes<'a> {
    /// Parsed outer DG1 BER wrapper.
    outer: BerTlv<'a, Dg1Wrapper>,
}

impl<'a> Dg1Bytes<'a> {
    /// Parse raw EF.DG1 bytes into a typed DG1 wrapper.
    pub(crate) fn parse(dg1: &'a [u8]) -> Result<Self, BerError> {
        Ok(Self {
            outer: BerTlv::<Dg1Wrapper>::parse(dg1)?,
        })
    }
}

/// ASCII field slice inside a TD1 MRZ line.
#[derive(Debug, Clone, Copy)]
struct MrzField<'a> {
    /// Raw field bytes before filler trimming.
    bytes: &'a [u8],
}

/// TD1 name line containing primary and secondary identifiers.
#[derive(Debug, Clone, Copy)]
struct MrzNameField<'a> {
    /// The complete third TD1 MRZ line.
    line: &'a [u8; TD1_LINE_LEN],
}

impl<'a> MrzField<'a> {
    /// Validate an MRZ field slice as ASCII.
    fn parse(bytes: &'a [u8]) -> Result<Self, MrzParseError> {
        if bytes.is_ascii() {
            Ok(Self { bytes })
        } else {
            Err(MrzParseError::field_detail("field is not ASCII"))
        }
    }

    /// Return the field with ICAO filler `<` bytes trimmed from both ends.
    fn trim_fillers(&self) -> String {
        String::from_utf8_lossy(self.bytes)
            .trim_matches('<')
            .to_owned()
    }
}

impl<'a> MrzNameField<'a> {
    /// Wrap the TD1 name line.
    const fn from_line(line: &'a [u8; TD1_LINE_LEN]) -> Self {
        Self { line }
    }

    /// Split the name line at the ICAO `<<` primary/secondary separator.
    fn split(self) -> (String, String) {
        let name_field = String::from_utf8_lossy(self.line).into_owned();
        let trimmed = name_field.trim_end_matches('<');
        let mut parts = trimmed.splitn(2, "<<");
        let surname = parts.next().unwrap_or("").to_owned();
        let given = parts.next().unwrap_or("").to_owned();
        (surname, given)
    }
}

/// Extract the raw MRZ string from EF.DG1 bytes.
///
/// EF.DG1 layout per ICAO 9303-10 §3.6.1:
///
/// ```text
/// 61 [L] 5F1F [L] <MRZ bytes>
/// ```
///
/// For TD1 ID cards the MRZ is 90 characters (3 × 30); for TD3
/// passports it's 88 characters (2 × 44). Returns `None` on any
/// shape we don't recognise.
#[inline]
#[must_use]
pub(crate) fn extract_mrz_string(dg1: &Dg1Bytes<'_>) -> Option<String> {
    let outer = dg1.outer;
    // The inner SHOULD be just `5F 1F` followed by the MRZ bytes,
    // but defensively iterate in case a future profile adds siblings.
    // The 5F1F two-byte tag is one-off enough that peek-and-match
    // beats defining a marker for it.
    let mut iter = BerTlvIter::new(outer.value);
    while let Some(Ok(child)) = iter.next() {
        if child.tag == dg_tag::MRZ_DATA {
            return core::str::from_utf8(child.value).ok().map(str::to_owned);
        }
    }
    None
}

impl ParsedMrz {
    /// Parse a TD1-format MRZ into typed fields.
    pub(crate) fn parse_td1(raw: &str) -> Result<Self, MrzParseError> {
        let stripped: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
        if !stripped.is_ascii() {
            return Err(MrzParseError::shape_detail("MRZ contains non-ASCII bytes"));
        }
        let mrz: &[u8; TD1_TOTAL_LEN] = stripped
            .as_bytes()
            .try_into()
            .map_err(MrzParseError::shape_error)?;

        let (line1_slice, rest) = mrz.split_at(TD1_LINE_LEN);
        let (line2_slice, line3_slice) = rest.split_at(TD1_LINE_LEN);
        let line1: &[u8; TD1_LINE_LEN] =
            line1_slice.try_into().map_err(MrzParseError::shape_error)?;
        let line2: &[u8; TD1_LINE_LEN] =
            line2_slice.try_into().map_err(MrzParseError::shape_error)?;
        let line3: &[u8; TD1_LINE_LEN] =
            line3_slice.try_into().map_err(MrzParseError::shape_error)?;

        let document_type = MrzField::parse(
            line1
                .get(MRZ_DOCUMENT_TYPE_RANGE)
                .ok_or_else(|| MrzParseError::shape_detail("document-type range missing"))?,
        )?
        .trim_fillers();
        let issuing_country =
            crate::country::IcaoCountry::new(
                &MrzField::parse(line1.get(MRZ_ISSUING_COUNTRY_RANGE).ok_or_else(|| {
                    MrzParseError::shape_detail("issuing-country range missing")
                })?)?
                .trim_fillers(),
            )
            .map_err(MrzParseError::field_error)?;
        let document_number = MrzField::parse(
            line1
                .get(MRZ_DOCUMENT_NUMBER_RANGE)
                .ok_or_else(|| MrzParseError::shape_detail("document-number range missing"))?,
        )?
        .trim_fillers();

        let birth_date_bytes: [u8; 6] = line2
            .get(MRZ_BIRTH_DATE_RANGE)
            .ok_or_else(|| MrzParseError::shape_detail("birth-date range missing"))?
            .try_into()
            .map_err(MrzParseError::shape_error)?;
        let date_of_birth =
            MrzDate::from_mrz_yymmdd(birth_date_bytes).map_err(MrzParseError::field_error)?;
        let sex = MrzSex::from_mrz_byte(
            *line2
                .get(MRZ_SEX_OFFSET)
                .ok_or_else(|| MrzParseError::shape_detail("sex offset missing"))?,
        );
        let expiry_date_bytes: [u8; 6] = line2
            .get(MRZ_EXPIRY_DATE_RANGE)
            .ok_or_else(|| MrzParseError::shape_detail("expiry-date range missing"))?
            .try_into()
            .map_err(MrzParseError::shape_error)?;
        let date_of_expiry =
            MrzDate::from_mrz_yymmdd(expiry_date_bytes).map_err(MrzParseError::field_error)?;
        let nationality = crate::country::IcaoCountry::new(
            &MrzField::parse(
                line2
                    .get(MRZ_NATIONALITY_RANGE)
                    .ok_or_else(|| MrzParseError::shape_detail("nationality range missing"))?,
            )?
            .trim_fillers(),
        )
        .map_err(MrzParseError::field_error)?;

        // Name field: surname << given names. The on-card form
        // (A-Z + `<`) flows through to the typed identifiers
        // verbatim; converting `<` to spaces is a presentation
        // concern, handled by display call sites.
        let (primary, secondary) = MrzNameField::from_line(line3).split();
        let primary_identifier = MrzSurname::new(primary).map_err(MrzParseError::field_error)?;
        let secondary_identifier =
            MrzGivenName::new(secondary).map_err(MrzParseError::field_error)?;

        Ok(Self {
            raw: stripped,
            document_type,
            issuing_country,
            document_number,
            date_of_birth,
            sex,
            date_of_expiry,
            nationality,
            primary_identifier,
            secondary_identifier,
        })
    }
}

/// Embedded document image format.
///
/// One canonical type for every JPEG / JPEG2000 image that crosses
/// the eMRTD boundary: DG2 facial image, DG7 displayed-signature
/// image, DG11 `0x5F16` proof-of-citizenship image, and DG12
/// `0x5F1D` / `0x5F1E` front/rear document images. The constructor
/// (the `extract_document_image` scan) is the trust boundary that
/// proves the bytes really do start with a recognised magic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocumentImage {
    /// Image payload whose first bytes match the JPEG magic
    /// `FF D8 FF` (ITU-T T.81 / JFIF).
    Jpeg(Vec<u8>),
    /// Image payload whose first bytes match the JPEG2000
    /// magic `00 00 00 0C 6A 50 20 20` (ISO/IEC 15444-1
    /// JP2 signature box).
    Jpeg2000(Vec<u8>),
}

/// No recognised JPEG / JPEG2000 payload was found in a DG image body.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DocumentImageError;

/// Candidate byte slice scanned for an embedded document image.
#[derive(Debug, Clone, Copy)]
struct DocumentImageCandidate<'a> {
    /// Raw DG payload or biometric envelope bytes.
    bytes: &'a [u8],
}

/// Compile-time image magic byte sequence.
#[derive(Debug, Clone, Copy)]
struct ImageMagic<const N: usize> {
    /// Magic bytes that identify one image container.
    bytes: [u8; N],
}

/// JPEG start-of-image magic used inside DG2 / DG7 / DG11 / DG12.
const JPEG_MAGIC: ImageMagic<3> = ImageMagic {
    bytes: [0xFF, 0xD8, 0xFF],
};
/// JPEG2000 JP2 signature-box magic used inside DG2 / DG7 / DG11 / DG12.
const JP2_MAGIC: ImageMagic<8> = ImageMagic {
    bytes: [0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20],
};

impl DocumentImage {
    /// Validate and wrap the first JPEG / JPEG2000 payload in `buf`.
    pub(crate) fn parse(buf: &[u8]) -> Result<Self, DocumentImageError> {
        let candidate = DocumentImageCandidate { bytes: buf };
        if let Some(off) = candidate.scan_for_magic(&JPEG_MAGIC) {
            let bytes = candidate
                .bytes
                .get(off..)
                .ok_or(DocumentImageError)?
                .to_vec();
            return Ok(Self::Jpeg(bytes));
        }
        if let Some(off) = candidate.scan_for_magic(&JP2_MAGIC) {
            let bytes = candidate
                .bytes
                .get(off..)
                .ok_or(DocumentImageError)?
                .to_vec();
            return Ok(Self::Jpeg2000(bytes));
        }
        Err(DocumentImageError)
    }

    /// Borrow the image payload bytes (the magic-bytes-onward
    /// slice the extract step wrapped).
    #[inline]
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Jpeg(b) | Self::Jpeg2000(b) => b,
        }
    }

    /// File-extension suggestion ("jpg" / "jp2") for save paths.
    /// Tier 0 `&'static str` from a fixed compile-time set.
    #[inline]
    #[must_use]
    pub const fn extension(&self) -> &'static str {
        match self {
            Self::Jpeg(_) => "jpg",
            Self::Jpeg2000(_) => "jp2",
        }
    }
}

impl DocumentImageCandidate<'_> {
    /// Linear-scan the candidate for the first occurrence of the
    /// magic bytes, returning the offset or `None`.
    fn scan_for_magic<const N: usize>(&self, needle: &ImageMagic<N>) -> Option<usize> {
        if N == 0 || self.bytes.len() < N {
            return None;
        }
        self.bytes.windows(N).position(|w| w == needle.bytes)
    }
}

/// eMRTD-layer error class. Mirrors the manual-`Error`-impl pattern
/// used by [`crate::error::IoError`] and [`crate::secure_messaging::SmError`]
/// so the lib stays `thiserror`-free.
#[derive(Debug)]
pub enum EmrtdError<TE>
where
    TE: core::fmt::Debug + core::fmt::Display,
{
    /// Transport-level dispatch failure (PC/SC / APDU exchange).
    Transport(crate::transport::TransportDispatchError<TE>),
    /// Card returned a non-success status word at a labelled
    /// operation.
    Sw {
        /// Operation label (e.g. "SELECT", "READ BINARY DG1").
        /// Tier 0 `&'static str` from a fixed compile-time set.
        op: &'static str,
        /// Card-returned status word per ISO 7816-4 §5.1.3.
        /// Tier 0 `u16` -- the typed projection is `StatusWord`.
        sw: u16,
    },
    /// BER / TLV parse failure on a card-returned data element.
    Ber(BerError),
    /// PACE handshake failed. PACE's internal error type lives in a
    /// `pub(crate)` module, so the message is formatted opaquely here
    /// to keep the public eMRTD surface independent of PACE internals.
    Pace(String),
    /// PACE failed in a way that specifically indicates the
    /// supplied CAN didn't match this card -- card returned the
    /// auth-failure SW (`0x6300`) or our mutual-auth tag check
    /// rejected. Separated from [`EmrtdError::Pace`] so the
    /// caller can give the operator a specific "wrong CAN,
    /// check the card front" message instead of a generic
    /// "PACE failed".
    BadCan,
    /// Secure-messaging wrap / unwrap failed (MAC mismatch, malformed
    /// DO87/DO99/DO8E, command overflow). Opaque for the same reason
    /// as [`EmrtdError::Pace`] -- the SM module is `pub(crate)`.
    SecureMessaging(String),
    /// The card reset mid-operation. Recoverable: the user pulls
    /// the card out and re-inserts it. Surfaced separately from
    /// [`EmrtdError::Pace`] so the UI can show a specific
    /// "remove and reinsert your card" message instead of a
    /// generic PACE failure.
    CardReset,
    /// A DG was read and structurally well-formed, but a specific
    /// field couldn't be extracted. The `&'static str` names which
    /// part (e.g. `"DG1 MRZ"`, `"MRZ TD1"`).
    ParseFailure(&'static str),
    /// A DG parse failed with a preserved parser detail.
    ParseFailureDetail {
        /// DG or field name that failed.
        what: &'static str,
        /// Parser-supplied failure detail.
        detail: String,
    },
}

impl<TE> core::fmt::Display for EmrtdError<TE>
where
    TE: core::fmt::Debug + core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport: {e}"),
            Self::Sw { op, sw } => write!(f, "{op}: SW={sw:#06X}"),
            Self::Ber(e) => write!(f, "BER parse: {e}"),
            Self::Pace(msg) => write!(f, "PACE: {msg}"),
            Self::BadCan => write!(
                f,
                "CAN did not match the card -- verify the CAN printed on the card front \
                 matches what you passed"
            ),
            Self::SecureMessaging(msg) => write!(f, "SM: {msg}"),
            Self::CardReset => write!(f, "card was reset mid-operation"),
            Self::ParseFailure(what) => write!(f, "could not parse {what}"),
            Self::ParseFailureDetail { what, detail } => {
                write!(f, "could not parse {what}: {detail}")
            }
        }
    }
}

impl<TE> core::error::Error for EmrtdError<TE> where
    TE: core::fmt::Debug + core::fmt::Display + 'static
{
}

impl<TE> From<BerError> for EmrtdError<TE>
where
    TE: core::fmt::Debug + core::fmt::Display,
{
    fn from(e: BerError) -> Self {
        Self::Ber(e)
    }
}

/// Aggregate of the personal data we currently extract from a
/// FINEID card's eMRTD application.
///
/// Holds the parsed MRZ (always present) plus the facial image from
/// DG2 (present whenever DG2 carries a recognised JPEG / JPEG2000
/// magic).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmrtdPersonalData {
    /// Parsed DG1 MRZ (always populated for FINEID cards; the
    /// parse step refuses if DG1 didn't yield a TD1 MRZ).
    pub mrz: ParsedMrz,
    /// DG2 facial image when the magic-byte scan found a
    /// recognised payload; `None` otherwise.
    pub face: Option<DocumentImage>,
    /// Decoded `DG11` additional personal data fields. `None`
    /// when the card didn't provision DG11 or the read returned
    /// an error.
    pub additional_personal: Option<AdditionalPersonalData>,
    /// Decoded `DG12` document-detail fields (issuing date /
    /// office / personalisation system version etc.).
    pub additional_document: Option<AdditionalDocumentData>,
    /// `DG7` displayed-signature image parsed via the same
    /// JPEG / JPEG2000 magic-byte scan as DG2. `None` when the
    /// scan didn't find a recognised magic -- the underlying
    /// DG7 bytes may still be present in `dg7_der`.
    pub signature_image: Option<DocumentImage>,
    /// Raw DG1 bytes, kept for Passive Authentication hash
    /// verification against EF.SOD.
    pub dg1_der: Vec<u8>,
    /// Raw DG2 bytes (same reason).
    pub dg2_der: Vec<u8>,
    /// Raw DG7 bytes when DG7 was provisioned and read. Kept
    /// independently of `signature_image` so callers can
    /// recover the bytes even when the JPEG / JPEG2000 magic
    /// scan fails (e.g. if a profile uses a different image
    /// format inside the ICAO biometric envelope).
    pub dg7_der: Option<Vec<u8>>,
    /// Raw EF.SOD bytes (when the card published one). The
    /// caller runs `cms::parse_signed_data` + per-DG hash
    /// verification against this blob to complete Passive
    /// Authentication.
    pub sod_der: Option<Vec<u8>>,
    /// Raw DG14 bytes when DG14 was provisioned and read. DG14
    /// is `SecurityInfos` (a SET of protocol-OID + parameters),
    /// notably carrying `ChipAuthenticationPublicKeyInfo` for
    /// the v4.0 anti-cloning round-trip and PACE / SM
    /// configuration metadata.
    pub dg14_der: Option<Vec<u8>>,
    /// Raw DG15 bytes when DG15 was provisioned and read. DG15
    /// wraps a `SubjectPublicKeyInfo` (the Active Authentication
    /// public key); on v3.1 cards this is the anti-cloning
    /// key the chip's matching private key signs an
    /// `INTERNAL AUTHENTICATE` challenge with.
    pub dg15_der: Option<Vec<u8>>,
    /// Active Authentication round-trip result, when DG15 was
    /// present and the AA APDU was attempted. `None` for cards
    /// without DG15 (the v4.0 generation uses Chip
    /// Authentication via DG14 instead -- handled separately).
    pub aa_result: Option<crate::aa::AaOutcome>,
    /// Chip Authentication round-trip result, when DG14
    /// advertised a supported CA protocol and the handshake
    /// was attempted. `Verified` indicates the SM session was
    /// successfully rotated to CA-derived keys mid-read; the
    /// subsequent DG reads then implicitly verify CA by `MAC`-ing
    /// with the new keys.
    pub ca_result: Option<crate::ca::CaOutcome>,
}

/// Inventory of data groups listed by EF.SOD.
#[derive(Debug, Clone)]
struct DgInventory {
    /// ICAO data-group numbers present in the LDS security object.
    numbers: Vec<u32>,
}

impl DgInventory {
    /// Return whether the EF.SOD inventory lists data group `number`.
    fn has(&self, number: u32) -> bool {
        self.numbers.contains(&number)
    }
}

/// Optional raw data groups read after EF.SOD inventory filtering.
#[derive(Debug, Clone)]
struct OptionalDgs {
    /// Raw DG7 bytes when listed by EF.SOD and readable.
    dg7: Option<Vec<u8>>,
    /// Raw DG11 bytes when listed by EF.SOD and readable.
    dg11: Option<Vec<u8>>,
    /// Raw DG12 bytes when listed by EF.SOD and readable.
    dg12: Option<Vec<u8>>,
    /// Raw DG14 bytes when listed by EF.SOD and readable.
    dg14: Option<Vec<u8>>,
    /// Raw DG15 bytes when listed by EF.SOD and readable.
    dg15: Option<Vec<u8>>,
}

/// Read one optional data group, mapping absent or access-denied SW to `None`.
fn read_optional_dg<T: CardTransport>(
    sm: &mut SmTransport<T>,
    sfi: Sfi,
) -> Result<Option<Vec<u8>>, EmrtdError<T::Error>> {
    match read_file(sm, sfi).map_err(map_sm_emrtd_error) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(EmrtdError::Sw { .. }) => Ok(None),
        Err(other) => Err(other),
    }
}

/// Read optional data groups only when EF.SOD says they exist.
fn read_optional_dgs<T: CardTransport>(
    sm: &mut SmTransport<T>,
    inventory: &DgInventory,
) -> Result<OptionalDgs, EmrtdError<T::Error>> {
    Ok(OptionalDgs {
        dg7: if inventory.has(7) {
            read_optional_dg(sm, SFI_EF_DG7)?
        } else {
            None
        },
        dg11: if inventory.has(11) {
            read_optional_dg(sm, SFI_EF_DG11)?
        } else {
            None
        },
        dg12: if inventory.has(12) {
            read_optional_dg(sm, SFI_EF_DG12)?
        } else {
            None
        },
        dg14: if inventory.has(14) {
            read_optional_dg(sm, SFI_EF_DG14)?
        } else {
            None
        },
        dg15: if inventory.has(15) {
            read_optional_dg(sm, SFI_EF_DG15)?
        } else {
            None
        },
    })
}

/// DG11 -- additional personal data (ICAO 9303-10 §4.7.11,
/// Table 71). All fields are optional; cards advertise what
/// they carry via the `0x5C` tag list at the head of the
/// template.
///
/// Free-text fields use distinct domain newtypes so the
/// compiler refuses to swap a [`Title`] for a [`Profession`]
/// or [`PlaceOfBirth`] for a [`PermanentAddress`]. Dates are
/// not yet typed (still `Option<String>` in the canonical
/// `YYYYMMDD` shape -- a follow-up will add a typed `IsoDate`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdditionalPersonalData {
    /// `0x5F0E` -- name of holder in full, often with diacritics
    /// that the MRZ would have transliterated. Encoded per
    /// Doc 9303 rules; filler `<` replaces spaces.
    pub full_name: Option<Dg11FullName>,
    /// `0x5F0F` -- other name(s) of holder. Nested under the
    /// `0xA0` content-specific wrapper; ICAO permits multiple
    /// instances. The parser surfaces every instance.
    pub other_names: Vec<OtherName>,
    /// `0x5F10` -- personal number (HETU in Finland; format
    /// varies by issuing state).
    pub personal_number: Option<PersonalNumber>,
    /// `0x5F2B` -- full date of birth, `YYYYMMDD` (8 bytes).
    /// Parsed at TLV read into the typed [`DateOfBirth`]; an
    /// unparseable on-card value drops to `None` (the raw bytes
    /// are not surfaced separately).
    pub full_date_of_birth: Option<DateOfBirth>,
    /// `0x5F11` -- place of birth, fields separated by `<`.
    pub place_of_birth: Option<PlaceOfBirth>,
    /// `0x5F42` -- permanent address, fields separated by `<`.
    pub permanent_address: Option<PermanentAddress>,
    /// `0x5F12` -- telephone.
    pub telephone: Option<Telephone>,
    /// `0x5F13` -- profession.
    pub profession: Option<Profession>,
    /// `0x5F14` -- title.
    pub title: Option<Title>,
    /// `0x5F15` -- personal summary.
    pub personal_summary: Option<PersonalSummary>,
    /// `0x5F16` -- proof of citizenship, JPEG/JPEG2000 image.
    /// Wrapped as a typed [`DocumentImage`] via the magic-byte
    /// scan; `None` when the field is absent or the bytes don't
    /// start with a recognised image magic.
    pub proof_of_citizenship: Option<DocumentImage>,
    /// `0x5F17` -- other valid travel-document numbers.
    /// The on-card field separates entries with `<`; the parser
    /// splits and emits one entry per element.
    pub other_td_numbers: Vec<OtherTdNumber>,
    /// `0x5F18` -- **custody information**. (Earlier revisions
    /// of this module mislabelled this as "tax / exit
    /// requirements"; that's actually `0x5F1C` in DG12, not
    /// `0x5F18` in DG11. Spec Table 71 calls this slot
    /// "Custody information".)
    pub custody_information: Option<CustodyInformation>,
}

/// DG12 -- additional document data (ICAO 9303-10 §4.7.12,
/// Table 73).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdditionalDocumentData {
    /// `0x5F19` -- issuing authority.
    pub issuing_authority: Option<IssuingAuthority>,
    /// `0x5F26` -- date of issue, `YYYYMMDD` (8 bytes).
    /// Parsed at TLV read into the typed [`IssueDate`].
    pub date_of_issue: Option<IssueDate>,
    /// `0x5F1A` -- name of another person referenced on the
    /// document. Nested under the `0xA0` content-specific
    /// wrapper; ICAO permits multiple instances. The parser
    /// surfaces every instance.
    pub other_persons: Vec<OtherPerson>,
    /// `0x5F1B` -- endorsements / observations.
    pub endorsements: Option<Endorsements>,
    /// `0x5F1C` -- tax / exit requirements. (The label
    /// mistakenly applied to `0x5F18` in earlier code.)
    pub tax_exit: Option<TaxExit>,
    /// `0x5F1D` -- image of front of document, JPEG/JPEG2000.
    /// Wrapped as a typed [`DocumentImage`] via the magic-byte
    /// scan; `None` when absent or the bytes don't start with a
    /// recognised image magic.
    pub image_front: Option<DocumentImage>,
    /// `0x5F1E` -- image of rear of document, JPEG/JPEG2000.
    /// Same wrapping policy as `image_front`.
    pub image_rear: Option<DocumentImage>,
    /// `0x5F55` -- date and time of document personalisation,
    /// `YYYYMMDDhhmmss` (14 ASCII digits). Parsed at TLV read
    /// into the typed [`PersonalisationTime`]; BCD-encoded
    /// off-spec emitters fall through to `None`.
    pub personalisation_time: Option<PersonalisationTime>,
    /// `0x5F56` -- serial number of personalisation system.
    pub personalisation_device_serial: Option<PersonalisationDeviceSerial>,
}

/// Drive the full eMRTD personal-data read against a raw
/// `CardTransport`.
///
/// Consumes the transport: the eMRTD read uses PACE+SM and changes
/// the card's security state, so the caller should reopen the card
/// to do PIN1 work afterwards.
///
/// `can` is the Card Access Number -- six digits printed on the
/// front of the FINEID card. PACE rejects with the standard
/// ICAO 9303-11 retry-burning shape if it's wrong, surfaced here
/// as [`EmrtdError::Pace`].
///
/// On success, the returned [`EmrtdPersonalData`] always contains
/// a parsed MRZ; the facial image is `Some` whenever DG2 yielded
/// a recognised JPEG/JPEG2000 envelope.
///
/// Wire flow (mirrors `EMRTDReader` integration in the legacy iOS
/// reader):
///
/// 1. PACE with the CAN -- yields the AES-256 SM keys.
/// 2. Wrap the transport in [`SmTransport`].
/// 3. SELECT the eMRTD applet by AID.
/// 4. READ BINARY EF.DG1 -- parse MRZ -> sex / names / dates.
/// 5. READ BINARY EF.DG2 -- strip the CBEFF/BHT envelope, return
///    the embedded image.
///
/// # Errors
///
/// Returns [`EmrtdError::Pace`] if the PACE handshake fails (e.g.
/// wrong CAN), [`EmrtdError::CardReset`] if the card resets
/// mid-handshake, [`EmrtdError::Transport`] for lower-level APDU
/// errors, [`EmrtdError::Sw`] if the applet SELECT or a READ BINARY
/// returns a non-success status word, [`EmrtdError::SecureMessaging`]
/// on SM wrap/unwrap failure, or [`EmrtdError::ParseFailure`] when
/// EF.DG1 doesn't yield a parseable MRZ.
// Locals like `dg11` / `dg12` mirror ICAO 9303-10's data-group
// numbering, which is how the eMRTD spec (and every reader
// implementation) names them.  The numeric suffixes look alike
// to `clippy::similar_names`; the suppression below names the
// spec convention as the load-bearing reason.
#[expect(
    clippy::similar_names,
    reason = "Locals `dg7` / `dg11` / `dg12` / `dg14` mirror ICAO 9303-10's data-group numbering verbatim (DG1, DG2, DG7, DG11, DG12, DG14, DG15). The numeric suffix IS the spec identifier; renaming to disambiguate would break the source-to-spec cross-reference every reader implementation relies on."
)]
#[inline]
pub fn read_personal_data<T: CardTransport>(
    mut transport: T,
    can: crate::can::Can,
) -> Result<EmrtdPersonalData, EmrtdError<T::Error>> {
    let pace_session = pace::run_pace_with_can(&mut transport, can).map_err(|e| {
        // Specific variants come first so the UI can show the
        // most-actionable message for the most-common failure
        // modes (wrong CAN, card pulled out mid-PACE). Anything
        // else falls through to the generic Pace(string) variant.
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "PaceError is #[non_exhaustive]; the fallback arm intentionally absorbs both today's non-CAN variants (Transport, Ber, Sw(non-0x6300), UnexpectedResponse, InvalidPoint, Random) and any future variant, message-matching on the formatted string to lift transport-card-reset into EmrtdError::CardReset."
        )]
        match &e {
            // Card-reported "authentication failed" (0x6300) or
            // our mutual-auth tag check failing both mean the
            // CAN-derived key didn't agree with what the card
            // expected: i.e. wrong CAN.
            pace::PaceError::Sw(_, 0x6300) | pace::PaceError::AuthMismatch => EmrtdError::BadCan,
            _ => {
                // Card-reset errors during PACE deserve their own
                // variant so the UI can show a specific "remove
                // and reinsert your card" prompt. We detect by
                // message-matching because PaceError's inner
                // transport-error type is parameterised.
                let s = format!("{e}");
                if s.contains("card reset") || s.contains("CardReset") {
                    EmrtdError::CardReset
                } else {
                    EmrtdError::Pace(s)
                }
            }
        }
    })?;
    let mut sm = SmTransport::new(transport, pace_session);

    let sw = select_application(&mut sm).map_err(map_sm_emrtd_error)?;
    if !sw.is_success() {
        return Err(EmrtdError::Sw {
            op: "SELECT eMRTD applet",
            sw: sw.as_u16(),
        });
    }

    let dg1 = read_file(&mut sm, SFI_EF_DG1).map_err(map_sm_emrtd_error)?;
    let dg1_typed = Dg1Bytes::parse(&dg1).map_err(EmrtdError::Ber)?;
    let mrz_str = extract_mrz_string(&dg1_typed).ok_or(EmrtdError::ParseFailure("DG1 MRZ"))?;
    let mrz = ParsedMrz::parse_td1(&mrz_str).map_err(|err| EmrtdError::ParseFailureDetail {
        what: "MRZ TD1",
        detail: err.to_string(),
    })?;

    let dg2 = read_file(&mut sm, SFI_EF_DG2).map_err(map_sm_emrtd_error)?;
    let face = DocumentImage::parse(&dg2).ok();

    // Optional-DG order:
    //
    // A failed READ BINARY for a non-provisioned DG can desync
    // the SM SSC on FINEID cards, which causes *every* later
    // read to also fail. So we never speculatively read an
    // optional DG -- we read EF.SOD first (always present),
    // parse its inventory of `(dataGroupNumber, hash)` pairs,
    // then only attempt to read the optional DGs the SOD
    // confirms are provisioned. Cards without DG7 / DG11 / DG12
    // never see a failing read for those DGs, so SM stays
    // intact through the whole sequence.
    //
    // If SOD itself is missing or unparseable, the inventory
    // collapses to empty and we skip every optional DG -- we
    // still return DG1 + DG2 + face, which is enough for a
    // useful report.
    let sod_der = read_optional_dg(&mut sm, SFI_EF_SOD)?;
    let inventory = DgInventory {
        numbers: sod_der
            .as_deref()
            .and_then(|s| crate::cms::SignedData::parse(s).ok())
            .and_then(|sd| crate::cms::LdsSecurityObject::parse(sd.econtent_der).ok())
            .map(|lds| lds.data_group_hashes.iter().map(|(n, _)| *n).collect())
            .unwrap_or_default(),
    };
    let optional = read_optional_dgs(&mut sm, &inventory)?;
    let dg7 = optional.dg7;
    let signature_image = dg7
        .as_deref()
        .and_then(|dg7_der| DocumentImage::parse(dg7_der).ok());
    let dg11 = optional.dg11;
    let additional_personal = dg11
        .as_deref()
        .and_then(|dg11_der| Dg11Bytes::parse(dg11_der).ok())
        .map(parse_dg11);
    let dg12 = optional.dg12;
    let additional_document = dg12
        .as_deref()
        .and_then(|dg12_der| Dg12Bytes::parse(dg12_der).ok())
        .map(parse_dg12);
    let dg14_der = optional.dg14;
    // Chip Authentication happens between DG14 (read with PACE
    // keys) and DG15 (read potentially with CA-derived keys).
    // A successful CA round-trip rotates the SM session keys
    // on this transport in-place; the subsequent DG15 read +
    // any later SM APDU acts as the implicit verification that
    // the chip held the matching CA private key. Failure modes
    // (no supported protocol / card-rejected / unsupported
    // curve) leave the transport on PACE keys -- the rest of
    // the read continues unaffected.
    let ca_result = dg14_der.as_deref().and_then(|dg14| {
        let dg14_typed = Dg14Bytes::try_from(dg14).ok()?;
        let entries = parse_dg14(dg14_typed);
        crate::ca::run_chip_authentication(&mut sm, &entries).ok()
    });
    let dg15_der = optional.dg15;

    // Active Authentication round-trip when DG15 is present
    // and parses as an RSA SPKI. The round-trip is best-effort
    // -- transport / parse failures collapse to `None` rather
    // than aborting the whole read, since the eMRTD personal
    // data we already extracted is still useful even if the
    // anti-cloning check couldn't run.
    let aa_result = dg15_der.as_deref().and_then(|dg15| {
        let dg15_typed = Dg15Bytes::try_from(dg15).ok()?;
        let spki = parse_dg15_spki(dg15_typed);
        let pubkey = crate::x509::extract_rsa_public_key(spki)?;
        crate::aa::run_active_authentication(&mut sm, &pubkey).ok()
    });

    Ok(EmrtdPersonalData {
        mrz,
        face,
        additional_personal,
        additional_document,
        signature_image,
        dg1_der: dg1,
        dg2_der: dg2,
        sod_der,
        dg7_der: dg7,
        dg14_der,
        dg15_der,
        aa_result,
        ca_result,
    })
}

/// Parse DG11 (additional personal data, ICAO 9303-10 §6.3).
///
/// Outer wrapper is application tag `[APPLICATION 11]` (`0x6B`)
/// containing a list of context tags. Each tag carries a UTF-8
/// or PrintableString-shaped value -- we surface the ones a
/// human reader cares about.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Dg11Bytes<'a> {
    /// Parsed outer DG11 BER wrapper.
    outer: BerTlv<'a, Dg11Wrapper>,
}

impl<'a> Dg11Bytes<'a> {
    /// Parse raw EF.DG11 bytes into a typed DG11 wrapper.
    pub(crate) fn parse(dg11_der: &'a [u8]) -> Result<Self, BerError> {
        Ok(Self {
            outer: BerTlv::<Dg11Wrapper>::parse(dg11_der)?,
        })
    }

    /// Borrow the DG11 body inside the `[APPLICATION 11]` wrapper.
    const fn body(&self) -> &'a [u8] {
        self.outer.value
    }
}

/// Parse validated DG11 bytes into surfaced personal-data fields.
#[inline]
#[must_use]
pub(crate) fn parse_dg11(dg11_der: Dg11Bytes<'_>) -> AdditionalPersonalData {
    let mut out = AdditionalPersonalData::default();
    EmrtdHelpers::walk_personal_tags(dg11_der, &mut out);
    out
}

impl EmrtdHelpers {
    /// Walk DG11's `[APPLICATION 11]` body and extract the
    /// personal-data sub-tags refineid surfaces.
    ///
    /// ICAO 9303 Part 10 §3.11. The tag-list `5Cxx` enumerating
    /// present sub-tags is ignored -- every TLV is walked and
    /// the recognised ones are populated. Unknown tags are
    /// silently skipped (forward-compat: ICAO may add tags in
    /// later revisions; ignoring them keeps the parser stable).
    fn walk_personal_tags(dg11_der: Dg11Bytes<'_>, out: &mut AdditionalPersonalData) {
        // DG11 starts with `6B LL <body>`. Inside is a `5C LL <list>`
        // tag listing the present sub-tags, then the sub-tags
        // themselves. We don't need the tag list; we just walk every
        // TLV in the body and look at the ones we surface.
        let der = dg11_der.body();
        let mut cursor = 0_usize;
        while cursor < der.len() {
            let Some(remaining_bytes) = der.get(cursor..) else {
                break;
            };
            let Ok(remaining) = BerInput::parse(remaining_bytes) else {
                break;
            };
            let Some(tlv) = Self::read_two_byte_tag_tlv(remaining) else {
                break;
            };
            match tlv.tag {
                dg_tag::FULL_NAME => {
                    out.full_name = Dg11FullName::new(Self::read_string(tlv.value)).ok();
                }
                dg_tag::PERSONAL_NUMBER => {
                    out.personal_number = PersonalNumber::new(Self::read_string(tlv.value)).ok();
                }
                dg_tag::FULL_DATE_OF_BIRTH => {
                    out.full_date_of_birth = <[u8; 8]>::try_from(tlv.value.bytes())
                        .ok()
                        .and_then(|b| DateOfBirth::from_yyyymmdd(b).ok());
                }
                dg_tag::PLACE_OF_BIRTH => {
                    out.place_of_birth = PlaceOfBirth::new(Self::read_string(tlv.value)).ok();
                }
                dg_tag::PERMANENT_ADDRESS => {
                    out.permanent_address =
                        PermanentAddress::new(Self::read_string(tlv.value)).ok();
                }
                dg_tag::TELEPHONE => {
                    out.telephone = Telephone::new(Self::read_string(tlv.value)).ok();
                }
                dg_tag::PROFESSION => {
                    out.profession = Profession::new(Self::read_string(tlv.value)).ok();
                }
                dg_tag::TITLE => out.title = Title::new(Self::read_string(tlv.value)).ok(),
                dg_tag::PERSONAL_SUMMARY => {
                    out.personal_summary = PersonalSummary::new(Self::read_string(tlv.value)).ok();
                }
                dg_tag::PROOF_OF_CITIZENSHIP => {
                    out.proof_of_citizenship = DocumentImage::parse(tlv.value.bytes()).ok();
                }
                // Other-TD-number list is `<`-separated; emit one
                // typed value per non-empty segment.
                dg_tag::OTHER_TD_NUMBERS => {
                    let joined = Self::read_string(tlv.value);
                    out.other_td_numbers = joined
                        .split('<')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .filter_map(|s| OtherTdNumber::new(s.to_owned()).ok())
                        .collect();
                }
                // Custody information per ICAO 9303-10 Table 71.
                // Earlier code mislabelled this "tax / exit", which
                // is the wrong DG (that is TAX_EXIT, 0x5F1C, in DG12).
                dg_tag::CUSTODY_INFORMATION => {
                    out.custody_information =
                        CustodyInformation::new(Self::read_string(tlv.value)).ok();
                }
                // Other names (OTHER_NAMES) live inside the 0xA0
                // content-specific wrapper alongside an 0x02
                // instance-count byte; handled by the nested
                // extractor below.
                _ => {}
            }
            // 0xA0 content-specific wrapper around 0x02 + 0x5F0F
            // (other names). Single-byte tag, so the two-byte
            // helper above skipped it -- handle separately.
            if remaining.has_tag::<Dg1xContainerA0>() {
                Self::extract_nested_5f0f(remaining, out);
            }
            let Some(next) = cursor.checked_add(tlv.total_size) else {
                break;
            };
            cursor = next;
        }
    }
}

/// Walk a DG11 `0xA0` wrapper (content-specific class) looking
/// for `0x5F0F` "other name" sub-tags.
impl EmrtdHelpers {
    /// Pull every `0x5F0F` "other name" TLV from a DG11 `0xA0`
    /// wrapper (ICAO 9303 Part 10 §3.11.4).
    ///
    /// `0xA0` is a context-specific constructed wrapper that
    /// holds repeated `5F0F` entries when the holder has more
    /// than one name. Returns silently on malformed input; any
    /// failure means "no extra names found", not a hard error.
    fn extract_nested_5f0f(a0_tlv: BerInput<'_>, out: &mut AdditionalPersonalData) {
        let Ok(outer) = BerTlv::<Dg1xContainerA0>::parse(a0_tlv.bytes()) else {
            return;
        };
        let Ok(body) = BerInput::parse(outer.value) else {
            return;
        };
        let mut cursor = 0_usize;
        while cursor < body.len() {
            let Some(remaining) = body.remaining_from(cursor) else {
                break;
            };
            let Some(tlv) = Self::read_two_byte_tag_tlv(remaining) else {
                break;
            };
            if tlv.tag == dg_tag::OTHER_NAMES
                && let Ok(n) = OtherName::new(Self::read_string(tlv.value))
            {
                out.other_names.push(n);
            }
            let Some(next) = cursor.checked_add(tlv.total_size) else {
                break;
            };
            cursor = next;
        }
    }
}

/// DG12 equivalent of `extract_nested_5f0f`: pulls every
/// `0x5F1A` "name of other person" out of the `0xA0` wrapper.
impl EmrtdHelpers {
    /// Pull every `0x5F1A` "name of other person" TLV from a
    /// DG12 `0xA0` wrapper (ICAO 9303 Part 10 §3.12.4).
    ///
    /// Same structure as [`Self::extract_nested_5f0f`] but
    /// targets DG12's document-issuance-context "person who
    /// applied for the document on behalf of the holder" field.
    /// Failures collapse to no-op for the same forward-compat
    /// reason.
    fn extract_nested_5f1a(a0_tlv: BerInput<'_>, out: &mut AdditionalDocumentData) {
        let Ok(outer) = BerTlv::<Dg1xContainerA0>::parse(a0_tlv.bytes()) else {
            return;
        };
        let Ok(body) = BerInput::parse(outer.value) else {
            return;
        };
        let mut cursor = 0_usize;
        while cursor < body.len() {
            let Some(remaining) = body.remaining_from(cursor) else {
                break;
            };
            let Some(tlv) = Self::read_two_byte_tag_tlv(remaining) else {
                break;
            };
            if tlv.tag == dg_tag::NAME_OF_OTHER_PERSON
                && let Ok(p) = OtherPerson::new(Self::read_string(tlv.value))
            {
                out.other_persons.push(p);
            }
            let Some(next) = cursor.checked_add(tlv.total_size) else {
                break;
            };
            cursor = next;
        }
    }
}

/// Parse DG15 (Active Authentication public key, ICAO 9303-11
/// §6.1.1).
///
/// DG15 wraps a single `SubjectPublicKeyInfo` under
/// application tag `[APPLICATION 15]` (`0x6F`):
///
/// ```text
/// 6F [L] 30 [L] <SubjectPublicKeyInfo body>
/// ```
///
/// Returns the inner SPKI bytes (DER-encoded) so the caller can
/// run them through [`crate::x509::parse_subject_public_key_info`]
/// for algorithm + key-shape extraction, or hand them straight
/// to a signature verifier for the AA round-trip.
///
/// Wire bytes of EF.DG15 (`SubjectPublicKeyInfo` for Active
/// Authentication), parse-validated at the trust boundary.
///
/// Construction via [`Dg15Bytes::try_from`] runs the outer
/// `[APPLICATION 15]` (`0x6F`) parse once per ICAO 9303-11
/// §9.1.2.  Downstream code consumes the validated value via
/// [`parse_dg15_spki`] without re-parsing the outer wrapper.
///
/// Borrowed, since the wire bytes live inside the
/// [`EmrtdPersonalData::dg15_der`] storage on the call site.
#[derive(Debug, Clone, Copy)]
pub struct Dg15Bytes<'a> {
    /// Inner SPKI bytes (the outer `[APPLICATION 15]` envelope's
    /// value), validated to start with the SEQUENCE tag in the
    /// `TryFrom` impl below.
    spki_tlv_bytes: &'a [u8],
}

/// Boundary parser: build [`Dg15Bytes`] from raw DG15 wire
/// bytes.  Runs the outer `[APPLICATION 15]` (`0x6F`) parse and
/// confirms the inner content starts with the SEQUENCE tag
/// (`0x30`) so the caller's SPKI parser sees its expected
/// outer envelope.
impl<'a> TryFrom<&'a [u8]> for Dg15Bytes<'a> {
    type Error = BerError;
    #[inline]
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let outer = BerTlv::<Dg15Wrapper>::parse(bytes)?;
        // The inner must be the SPKI SEQUENCE (tag 0x30).
        if outer.value.first().copied().map(u16::from) != Some(<Sequence as BerTag>::TAG) {
            return Err(BerError::UnexpectedTag {
                expected: <Sequence as BerTag>::TAG,
                got: u16::from(outer.value.first().copied().unwrap_or(0)),
            });
        }
        Ok(Self {
            spki_tlv_bytes: outer.value,
        })
    }
}

/// Extract the SPKI SEQUENCE TLV bytes from validated DG15
/// wire bytes.
///
/// Returns an owned `Vec<u8>` because the caller's SPKI parser
/// typically wants an owned copy; the underlying borrow is
/// freed after this returns.
#[inline]
#[must_use]
pub fn parse_dg15_spki(dg15: Dg15Bytes<'_>) -> Vec<u8> {
    dg15.spki_tlv_bytes.to_vec()
}

/// One `SecurityInfo` entry recognised from DG14.
///
/// Each entry is a `SEQUENCE { protocolOid, ANY }` where the
/// `ANY` payload is protocol-specific (version, key, params).
/// We recognise the OIDs the FINEID card actually publishes
/// today and surface them in a friendly form for `card info`;
/// unrecognised OIDs round-trip as `Other` with the raw OID
/// bytes so the operator still sees what the chip advertises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dg14SecurityInfo {
    /// `id-CA-*` -- Chip Authentication protocol info: a
    /// protocol-OID + version. Carries no key material; the
    /// matching `ChipAuthenticationPublicKeyInfo` carries the
    /// CA pubkey.
    ChipAuthenticationInfo {
        /// Friendly protocol-OID label (e.g.
        /// `"id-CA-ECDH-AES-CBC-CMAC-128"`). Tier 0
        /// `&'static str` from a fixed compile-time lookup.
        protocol_label: &'static str,
        /// Raw X.690 OID body bytes. Tier 0 `Vec<u8>` -- a
        /// tighter form would be the typed `Oid<'a>` newtype
        /// (BSI TR-03110 §A.6 `id-CA-*` identifiers).
        oid: Vec<u8>,
        /// Protocol version per BSI TR-03110 §A.1.1.1 -- usually
        /// `1` (CA v1) or `2` (CA v2). Tier 0 `u32` -- the spec
        /// only defines a small range; the bound (1..=2) is
        /// enforced by the parser, not by the field type.
        version: Option<u32>,
    },
    /// `id-PK-ECDH` / `id-PK-DH` -- carries the chip's CA
    /// public key (the one the reader's ephemeral key
    /// performs ECDH against).
    ChipAuthenticationPublicKeyInfo {
        /// Raw protocol OID body bytes per BSI TR-03110 §A.6.4.
        /// Tier 0 `Vec<u8>`; tighter form would be `Oid<'a>`.
        oid: Vec<u8>,
        /// Raw `SubjectPublicKeyInfo`-shaped bytes, ready to
        /// hand to [`crate::x509::parse_subject_public_key_info`].
        spki_der: Vec<u8>,
    },
    /// `id-TA-*` -- Terminal Authentication protocol info.
    /// FINEID-S1 cards publish this but EAC TA isn't reachable
    /// from a citizen-tier reader.
    TerminalAuthenticationInfo {
        /// Raw protocol OID body bytes per BSI TR-03110 §A.6.
        /// Tier 0 `Vec<u8>`; tighter form would be `Oid<'a>`.
        oid: Vec<u8>,
    },
    /// `id-PACE-*` -- PACE protocol info. Usually duplicates
    /// the entries in EF.CardAccess.
    PaceInfo {
        /// Raw protocol OID body bytes per BSI TR-03110 §A.6.
        /// Tier 0 `Vec<u8>`; tighter form would be `Oid<'a>`.
        oid: Vec<u8>,
    },
    /// Any other `SecurityInfo` -- surfaced with the OID bytes
    /// so the operator can see what's there without us having
    /// to whitelist every possible identifier.
    Other {
        /// Raw protocol OID body bytes the chip published.
        /// Tier 0 `Vec<u8>`; tighter form would be `Oid<'a>`.
        oid: Vec<u8>,
    },
}

/// Wire bytes of EF.DG14 (`SecurityInfos`), parse-validated at
/// the trust boundary.
///
/// Construction via [`Dg14Bytes::try_from`] runs the outer
/// `[APPLICATION 14]` + inner `SET OF SecurityInfo` parse once
/// per ICAO 9303-10 §4.7.14.  Downstream code consumes the
/// validated value via [`parse_dg14`] without re-parsing the
/// outer wrapper.  This prevents the swap `parse_dg11`'s
/// bytes ever reach [`parse_dg14`] (and vice versa); the
/// function-name commitment is now backed by the type.
///
/// Borrowed, since the wire bytes live inside the
/// [`EmrtdPersonalData::dg14_der`] storage on the call site.
#[derive(Debug, Clone, Copy)]
pub struct Dg14Bytes<'a> {
    /// Inner `SET OF SecurityInfo` body, validated via the
    /// chained typed-BER parse in [`Dg14Bytes::try_from`].
    security_infos_set: BerTlv<'a, Set>,
}

/// Boundary parser: build [`Dg14Bytes`] from raw DG14 wire
/// bytes.  Runs the outer `[APPLICATION 14]` (`0x6E`) + inner
/// `SET OF SecurityInfo` parse per ICAO 9303-10 §4.7.14.
/// Conversion fails when either layer's typed BER tag doesn't
/// match -- the `BerError` surfaces the specific failure.
///
/// `TryFrom` rather than an inherent `try_new`/`new` to keep
/// the `pub fn` surface free of raw `&[u8]` parameters (typing-
/// discipline Rule B); trait-impl methods are not flagged.
impl<'a> TryFrom<&'a [u8]> for Dg14Bytes<'a> {
    type Error = BerError;
    #[inline]
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let outer = BerTlv::<Dg14Wrapper>::parse(bytes)?;
        let security_infos_set = BerTlv::<Set>::parse(outer.value)?;
        Ok(Self { security_infos_set })
    }
}

/// Parse DG14's `SecurityInfos` SET into recognisable entries.
///
/// Returns the list of [`Dg14SecurityInfo`] entries the SET
/// contains, in the order they appear. Best-effort: a single
/// malformed entry returns whatever we managed to parse before
/// it, rather than aborting; the operator still sees partial
/// info in `card info`.  The wrapper-validated [`Dg14Bytes`]
/// input means the outer-tag-check happened once at the trust
/// boundary; this fn iterates the inner SET only.
#[inline]
#[must_use]
pub fn parse_dg14(dg14: Dg14Bytes<'_>) -> Vec<Dg14SecurityInfo> {
    let body = dg14.security_infos_set.value;
    let mut out = Vec::new();
    for tlv in BerTlvIter::new(body) {
        let Ok(any) = tlv else { break };
        let Ok(seq) = any.expect::<Sequence>() else {
            continue;
        };
        let mut inner = BerTlvIter::new(seq.value);
        let Some(Ok(oid_any)) = inner.next() else {
            continue;
        };
        let Ok(oid_tlv) = oid_any.expect::<Oid>() else {
            continue;
        };
        let entry = classify_dg14_entry(oid_tlv, &mut inner, seq);
        out.push(entry);
    }
    out
}

/// DER OID body prefix used to classify DG14 `SecurityInfo` entries.
#[derive(Debug, Clone, Copy)]
struct OidPrefix<const N: usize> {
    /// Prefix bytes without the OID tag or length octets.
    bytes: [u8; N],
}

/// Borrowed DER OID body from one DG14 `SecurityInfo` entry.
#[derive(Debug, Clone, Copy)]
struct Dg14Oid<'a> {
    /// OID body bytes, excluding BER tag and length.
    bytes: &'a [u8],
}

impl<'a> Dg14Oid<'a> {
    /// Wrap a typed OID TLV as a DG14 classifier input.
    const fn from_tlv(tlv: BerTlv<'a, Oid>) -> Self {
        Self { bytes: tlv.value }
    }

    /// Test whether this OID starts with `prefix`.
    fn matches_prefix<const N: usize>(&self, prefix: &OidPrefix<N>) -> bool {
        self.bytes.starts_with(&prefix.bytes)
    }

    /// Return the first OID arc byte after `prefix`.
    fn tail_byte<const N: usize>(&self, _prefix: &OidPrefix<N>) -> Option<u8> {
        self.bytes.get(N).copied()
    }

    /// Return the second OID arc byte after `prefix`.
    fn tail_next_byte<const N: usize>(&self, _prefix: &OidPrefix<N>) -> Option<u8> {
        let offset = N.checked_add(1)?;
        self.bytes.get(offset).copied()
    }

    /// Copy the OID body into owned bytes for public reporting.
    fn to_vec(self) -> Vec<u8> {
        self.bytes.to_vec()
    }
}

/// OID-to-variant dispatch. Walks the rest of the SEQUENCE for
/// protocol-specific payload bytes when relevant. `outer` is the
/// SEQUENCE TLV the OID was extracted from; needed for the SPKI
/// re-encoding path (`id-PK-*`), passed through typed so the
/// helper isn't taking raw bytes that could be from anything.
fn classify_dg14_entry(
    oid_tlv: BerTlv<'_, Oid>,
    rest: &mut BerTlvIter<'_>,
    outer: BerTlv<'_, Sequence>,
) -> Dg14SecurityInfo {
    let oid = Dg14Oid::from_tlv(oid_tlv);
    // OID prefix 0.4.0.127.0.7.2.2.3 = id-CA-*; next arc
    // distinguishes the key-agreement family (.1 = DH, .2 =
    // ECDH) and the final arc the cipher choice. FINEID's
    // ECDH-AES variants land here.
    if oid.matches_prefix(&OID_PREFIX_CA)
        && let Some(family_byte) = oid.tail_byte(&OID_PREFIX_CA)
        && let Some(cipher_byte) = oid.tail_next_byte(&OID_PREFIX_CA)
    {
        // family_byte / cipher_byte are decoded via the combined
        // (family_byte, cipher_byte) match below; the individual
        // family / cipher labels are not currently surfaced on the
        // returned Dg14SecurityInfo::ChipAuthenticationInfo variant.
        // Retaining the per-byte decode tables as documentation of
        // the OID semantics; the combined label is what the return
        // uses.
        let label: &'static str = match (family_byte, cipher_byte) {
            (OID_CA_FAMILY_ECDH, OID_CA_CIPHER_3DES) => "id-CA-ECDH-3DES-CBC-CBC",
            (OID_CA_FAMILY_ECDH, OID_CA_CIPHER_AES_128) => "id-CA-ECDH-AES-CBC-CMAC-128",
            (OID_CA_FAMILY_ECDH, OID_CA_CIPHER_AES_192) => "id-CA-ECDH-AES-CBC-CMAC-192",
            (OID_CA_FAMILY_ECDH, OID_CA_CIPHER_AES_256) => "id-CA-ECDH-AES-CBC-CMAC-256",
            (OID_CA_FAMILY_DH, OID_CA_CIPHER_3DES) => "id-CA-DH-3DES-CBC-CBC",
            (OID_CA_FAMILY_DH, OID_CA_CIPHER_AES_128) => "id-CA-DH-AES-CBC-CMAC-128",
            (OID_CA_FAMILY_DH, OID_CA_CIPHER_AES_192) => "id-CA-DH-AES-CBC-CMAC-192",
            (OID_CA_FAMILY_DH, OID_CA_CIPHER_AES_256) => "id-CA-DH-AES-CBC-CMAC-256",
            _ => "id-CA-?",
        };
        let version = EmrtdHelpers::read_integer_u32(rest);
        return Dg14SecurityInfo::ChipAuthenticationInfo {
            protocol_label: label,
            oid: oid.to_vec(),
            version,
        };
    }
    // OID prefix 0.4.0.127.0.7.2.2.1 = id-PK-* (CA pubkey info,
    // .1 = DH, .2 = ECDH). Both variants carry an SPKI.
    if oid.matches_prefix(&OID_PREFIX_PK) {
        // The remaining bytes of the outer SEQUENCE after the
        // OID are the SubjectPublicKeyInfo (a SEQUENCE).
        // Easier to slice from the SEQUENCE body directly.
        let spki_der = EmrtdHelpers::extract_remaining_spki(outer).unwrap_or_default();
        return Dg14SecurityInfo::ChipAuthenticationPublicKeyInfo {
            oid: oid.to_vec(),
            spki_der,
        };
    }
    if oid.matches_prefix(&OID_PREFIX_TA) {
        return Dg14SecurityInfo::TerminalAuthenticationInfo { oid: oid.to_vec() };
    }
    if oid.matches_prefix(&OID_PREFIX_PACE) {
        return Dg14SecurityInfo::PaceInfo { oid: oid.to_vec() };
    }
    Dg14SecurityInfo::Other { oid: oid.to_vec() }
}

impl EmrtdHelpers {
    /// Read the next BER child as an INTEGER and decode it as a
    /// big-endian unsigned `u32`.
    ///
    /// Returns `None` if the iterator is exhausted, the child is
    /// not an INTEGER, or the integer's magnitude overflows
    /// `u32`. Used by DG14 `SecurityInfo` parsing for the
    /// `version` field and the algorithm-id integer.
    fn read_integer_u32(it: &mut BerTlvIter<'_>) -> Option<u32> {
        let tlv = it.next()?.ok()?.expect::<Integer>().ok()?;
        let mut v: u32 = 0;
        for &b in tlv.value {
            v = v.checked_shl(8)?.checked_add(u32::from(b))?;
        }
        Some(v)
    }

    /// Pull the post-OID `SubjectPublicKeyInfo` SEQUENCE out of
    /// a `ChipAuthenticationPublicKeyInfo` entry and re-encode it
    /// as standalone SPKI DER (outer SEQUENCE tag + length +
    /// value), suitable for handing to `SpkiDer::try_from`.
    ///
    /// Input: the outer `ChipAuthenticationPublicKeyInfo`
    /// SEQUENCE TLV (the caller has already pinned the
    /// `Sequence` tag via `BerTlv::expect`).
    ///
    /// Output: owned bytes; `None` if the inner `SubjectPublicKeyInfo`
    /// is missing or its tag is not SEQUENCE.
    fn extract_remaining_spki(outer: BerTlv<'_, Sequence>) -> Option<Vec<u8>> {
        // Re-encode the SEQUENCE TLV so the caller's SPKI parser
        // sees its expected outer tag. `SEQUENCE` is a single-byte
        // tag (0x30); the compile-time assert pins the wire-format
        // identity between the typed `BerTag` const and the byte
        // literal we push.
        const SEQUENCE_TAG: u8 = 0x30;
        // Widen SEQUENCE_TAG to u16 without an `as` cast (denied) by
        // placing it as the low byte; pins the typed BerTag const to
        // the byte we push.
        const _: () = assert!(
            <Sequence as BerTag>::TAG == u16::from_be_bytes([0, SEQUENCE_TAG]),
            "<Sequence as BerTag>::TAG must equal SEQUENCE_TAG"
        );

        let mut iter = BerTlvIter::new(outer.value);
        let _oid = iter.next()?.ok()?;
        let spki = iter.next()?.ok()?.expect::<Sequence>().ok()?;
        let mut out = Vec::with_capacity(spki.value.len().saturating_add(4));
        out.push(SEQUENCE_TAG);
        Self::push_def_length(&mut out, spki.value.len());
        out.extend_from_slice(spki.value);
        Some(out)
    }

    /// Encode a BER/DER definite-form length and append it to
    /// `out`.
    ///
    /// ITU-T X.690 §8.1.3. The short-form / one-byte long-form /
    /// two-byte long-form branches cover every length up to
    /// `u16::MAX`, which is the ICAO 9303 cap on an EF body.
    /// Values beyond `u16::MAX` are clamped (saturating) rather
    /// than panicking; caller-side validation is expected to
    /// have rejected them first.
    fn push_def_length(out: &mut Vec<u8>, n: usize) {
        // BER definite-form length:
        //   0..=0x7F          -> single short-form byte
        //   0x80..=0xFF       -> `0x81 NN` long-form, one length byte
        //   0x100..=0xFFFF    -> `0x82 NN NN` long-form, two length bytes
        // Larger sizes don't occur in this codebase (SPKI bodies fit
        // in u16; ICAO 9303 caps EFs at 65535 bytes). On the
        // ICAO-out-of-range path we fall through to encoding the
        // low 16 bits, matching the legacy `(n >> 8) as u8` shape
        // -- caller-side validation should refuse n > u16::MAX
        // before this point.
        if let Ok(byte) = u8::try_from(n)
            && byte < 0x80
        {
            out.push(byte);
        } else if let Ok(byte) = u8::try_from(n) {
            out.push(0x81);
            out.push(byte);
        } else {
            let word = u16::try_from(n).unwrap_or(u16::MAX);
            out.push(0x82);
            out.extend_from_slice(&word.to_be_bytes());
        }
    }
}

// BSI OID 0.4.0.127.0.7 = bsi-de
// .2.2 = id-icao-mrtd? -- actually .2.2 here is part of the
// BSI TR-03110 "Protocols for the Electronic Identification".
//
// The encoded DER prefix bytes for these OIDs:
// 0.4.0.127.0.7.2.2.3.1 -> 04 00 7F 00 07 02 02 03 01 (9 bytes)
// 0.4.0.127.0.7.2.2.1   -> 04 00 7F 00 07 02 02 01    (8 bytes)
// 0.4.0.127.0.7.2.2.2   -> 04 00 7F 00 07 02 02 02    (8 bytes -- TA)
// 0.4.0.127.0.7.2.2.4   -> 04 00 7F 00 07 02 02 04    (8 bytes -- PACE)
// Carve-out from the `oid::known` consolidation (and the
// `oid-const-grep` gate, which exempts `*_PREFIX_*`): these are OID
// *prefixes*, matched against longer concrete-variant OIDs by their
// algorithm tail (`starts_with`), not complete OIDs compared for
// identity. Modelling them as full `Oid` constants would mis-state
// what they are, so they stay raw byte fragments here.
/// BSI TR-03110 `id-CA` OID prefix (Chip Authentication --
/// `0.4.0.127.0.7.2.2.3`). Algorithm-specific tail bytes (e.g.
/// `.2` = ECDH-AES-CMAC-128) distinguish concrete variants.
const OID_PREFIX_CA: OidPrefix<8> = OidPrefix {
    bytes: [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03],
};
/// BSI TR-03110 `id-PK` OID prefix (Public-Key info --
/// `0.4.0.127.0.7.2.2.1`). Used by `ChipAuthenticationPublicKeyInfo`
/// entries to publish the chip's CA public key.
const OID_PREFIX_PK: OidPrefix<8> = OidPrefix {
    bytes: [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x01],
};
/// BSI TR-03110 `id-TA` OID prefix (Terminal Authentication --
/// `0.4.0.127.0.7.2.2.2`). FINEID cards publish TA info but
/// the inspection systems we target rarely run TA.
const OID_PREFIX_TA: OidPrefix<8> = OidPrefix {
    bytes: [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02],
};
/// BSI TR-03110 `id-PACE` OID prefix (Password Authenticated
/// Connection Establishment -- `0.4.0.127.0.7.2.2.4`). Per ICAO
/// 9303 Part 11 §9.2 / BSI TR-03110-2 §A.1.1.2.
const OID_PREFIX_PACE: OidPrefix<8> = OidPrefix {
    bytes: [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04],
};
/// `id-CA-DH-*` family arc after the `id-CA` OID prefix.
const OID_CA_FAMILY_DH: u8 = 0x01;
/// `id-CA-ECDH-*` family arc after the `id-CA` OID prefix.
const OID_CA_FAMILY_ECDH: u8 = 0x02;
/// `3DES-CBC-CBC` cipher arc after the CA family arc.
const OID_CA_CIPHER_3DES: u8 = 0x01;
/// `AES-CBC-CMAC-128` cipher arc after the CA family arc.
const OID_CA_CIPHER_AES_128: u8 = 0x02;
/// `AES-CBC-CMAC-192` cipher arc after the CA family arc.
const OID_CA_CIPHER_AES_192: u8 = 0x03;
/// `AES-CBC-CMAC-256` cipher arc after the CA family arc.
const OID_CA_CIPHER_AES_256: u8 = 0x04;

// `parse_dg14_security_infos_body` was the old internal helper
// that parsed DG14's `[APPLICATION 14]` + inner `SET OF
// SecurityInfo` shape and returned the SET body bytes.  Both
// layers now live inside [`Dg14Bytes::try_from`] (above), so the
// outer-tag check and the inner-SET check happen once at the
// trust boundary rather than being deferred into each call of
// [`parse_dg14`].  Removing the helper avoids two parse-paths
// for the same wire shape diverging silently.

/// Parse DG12 (additional document data, ICAO 9303-10 §4.7.12
/// Table 73). Surfaces the recognisable tags into
/// [`AdditionalDocumentData`]; unrecognised TLVs are skipped.
///
/// `0x5F1A` "name of other person" is nested inside an `0xA0`
/// content-specific wrapper alongside an `0x02` instance-count
/// byte; we walk into it to extract the first instance.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Dg12Bytes<'a> {
    /// Parsed outer DG12 BER wrapper.
    outer: BerTlv<'a, Dg12Wrapper>,
}

impl<'a> Dg12Bytes<'a> {
    /// Parse raw EF.DG12 bytes into a typed DG12 wrapper.
    pub(crate) fn parse(dg12_der: &'a [u8]) -> Result<Self, BerError> {
        Ok(Self {
            outer: BerTlv::<Dg12Wrapper>::parse(dg12_der)?,
        })
    }

    /// Borrow the DG12 body inside the `[APPLICATION 12]` wrapper.
    const fn body(&self) -> &'a [u8] {
        self.outer.value
    }
}

/// Parse validated DG12 bytes into surfaced document-data fields.
#[inline]
#[must_use]
pub(crate) fn parse_dg12(dg12_der: Dg12Bytes<'_>) -> AdditionalDocumentData {
    let mut out = AdditionalDocumentData::default();
    let dg12_body = dg12_der.body();
    let mut cursor = 0_usize;
    while cursor < dg12_body.len() {
        let Some(remaining_bytes) = dg12_body.get(cursor..) else {
            break;
        };
        let Ok(remaining) = BerInput::parse(remaining_bytes) else {
            break;
        };
        // 0xA0 wrapper for nested 0x5F1A (other persons). Walk
        // into it before the two-byte-tag helper bails.
        if remaining.has_tag::<Dg1xContainerA0>() {
            EmrtdHelpers::extract_nested_5f1a(remaining, &mut out);
            let Ok(outer) = BerTlv::<Dg1xContainerA0>::parse(remaining.bytes()) else {
                break;
            };
            // `BerTlv::size` is the total TLV byte count
            // (tag + length-of-length + length + value); advancing
            // the cursor by that lands on the next sibling TLV.
            let Some(next) = cursor.checked_add(outer.size) else {
                break;
            };
            cursor = next;
            continue;
        }
        let Some(tlv) = EmrtdHelpers::read_two_byte_tag_tlv(remaining) else {
            break;
        };
        match tlv.tag {
            dg_tag::ISSUING_AUTHORITY => {
                out.issuing_authority =
                    IssuingAuthority::new(EmrtdHelpers::read_string(tlv.value)).ok();
            }
            dg_tag::DATE_OF_ISSUE => {
                out.date_of_issue = <[u8; 8]>::try_from(tlv.value.bytes())
                    .ok()
                    .and_then(|b| IssueDate::from_yyyymmdd(b).ok());
            }
            dg_tag::ENDORSEMENTS => {
                out.endorsements = Endorsements::new(EmrtdHelpers::read_string(tlv.value)).ok();
            }
            dg_tag::TAX_EXIT => {
                out.tax_exit = TaxExit::new(EmrtdHelpers::read_string(tlv.value)).ok();
            }
            dg_tag::IMAGE_FRONT => out.image_front = DocumentImage::parse(tlv.value.bytes()).ok(),
            dg_tag::IMAGE_REAR => out.image_rear = DocumentImage::parse(tlv.value.bytes()).ok(),
            dg_tag::PERSONALISATION_TIME => {
                out.personalisation_time = <[u8; 14]>::try_from(tlv.value.bytes())
                    .ok()
                    .and_then(|b| PersonalisationTime::from_yyyymmddhhmmss(b).ok());
            }
            dg_tag::PERSONALISATION_DEVICE_SERIAL => {
                out.personalisation_device_serial =
                    PersonalisationDeviceSerial::new(EmrtdHelpers::read_string(tlv.value)).ok();
            }
            _ => {}
        }
        let Some(next) = cursor.checked_add(tlv.total_size) else {
            break;
        };
        cursor = next;
    }
    out
}

impl EmrtdHelpers {
    /// Decode an MRZ / DG-extension UTF-8-ish byte slice into an
    /// owned `String`, trimming ASCII whitespace.
    ///
    /// DG11 / DG12 sub-tag values are nominally `UTF8String` per
    /// ICAO 9303-10 §3.11.5; in practice some issuers right-pad
    /// with spaces. Lossy decoding plus `trim()` makes the
    /// parser tolerant without admitting non-UTF-8 bytes to
    /// downstream typed wrappers.
    fn read_string(value: BerValue<'_>) -> String {
        String::from_utf8_lossy(value.bytes()).trim().to_owned()
    }

    /// Read a `5F xx` two-byte BER tag + BER length. Returns
    /// `(tag, header_size, content_len)` or `None` if the header
    /// doesn't fit.
    fn read_two_byte_tag_tlv(bytes: BerInput<'_>) -> Option<BerTlvRead<'_>> {
        let first = bytes.first()?;
        let (tag, idx): (u16, usize) =
            if first & ber_tag::HIGH_TAG_NUMBER_MASK == ber_tag::HIGH_TAG_NUMBER_MASK {
                let second = *bytes.bytes().get(1)?;
                (
                    u16::from(first)
                        .checked_shl(8)?
                        .checked_add(u16::from(second))?,
                    2_usize,
                )
            } else {
                (u16::from(first), 1_usize)
            };
        let (len_size, content_len) = Self::read_ber_length(bytes.remaining_from(idx)?)?;
        let header_size = idx.checked_add(len_size)?;
        let total_size = header_size.checked_add(content_len)?;
        if total_size > bytes.len() {
            return None;
        }
        let value = BerValue {
            bytes: bytes.bytes().get(header_size..total_size)?,
        };
        Some(BerTlvRead {
            tag,
            value,
            total_size,
        })
    }

    /// Decode a BER definite-form length field at the start of
    /// `bytes`.
    ///
    /// Returns `(length_field_bytes, content_length)`. Indefinite
    /// form (`0x80`) is rejected because ICAO 9303 mandates
    /// definite-form (Part 10 §3.3) and no FINEID DG file uses
    /// indefinite. Long-form length-of-length above 4 bytes is
    /// rejected because no DG body fits inside `usize` if it
    /// declares more than 4 length bytes on a 32-bit target.
    fn read_ber_length(bytes: BerInput<'_>) -> Option<(usize, usize)> {
        let first = bytes.first()?;
        if first < ber_tag::CONTINUATION_OR_LONG_FORM_MASK {
            return Some((1_usize, usize::from(first)));
        }
        let extra = usize::from(first & ber_tag::LONG_FORM_LENGTH_COUNT_MASK);
        if extra == 0 || bytes.len() < 1_usize.checked_add(extra)? {
            return None;
        }
        let mut v: usize = 0;
        // Length-bytes span: indices 1..=extra; both ends in-range
        // by the bounds check above.
        let tail = bytes.bytes().get(1..=extra)?;
        for &b in tail {
            v = v.checked_shl(8)?.checked_add(usize::from(b))?;
        }
        Some((1_usize.checked_add(extra)?, v))
    }
}

/// Project an SM-transport error back to the underlying transport's
/// error type for the outer [`EmrtdError`]. The SM layer's
/// MAC-mismatch / malformed-response variants stringify; the
/// transport-passthrough variant unwraps. We don't expose the
/// `SmError` enum on the public surface because
/// `secure_messaging` is a `pub(crate)` module.
fn map_sm_emrtd_error<TE>(e: EmrtdError<crate::secure_messaging::SmError<TE>>) -> EmrtdError<TE>
where
    TE: core::fmt::Debug + core::fmt::Display,
{
    use crate::secure_messaging::SmError;
    use crate::transport::TransportDispatchError;
    match e {
        EmrtdError::Sw { op, sw } => EmrtdError::Sw { op, sw },
        EmrtdError::Ber(b) => EmrtdError::Ber(b),
        EmrtdError::Pace(p) => EmrtdError::Pace(p),
        EmrtdError::BadCan => EmrtdError::BadCan,
        EmrtdError::SecureMessaging(m) => EmrtdError::SecureMessaging(m),
        EmrtdError::CardReset => EmrtdError::CardReset,
        EmrtdError::ParseFailure(p) => EmrtdError::ParseFailure(p),
        EmrtdError::ParseFailureDetail { what, detail } => {
            EmrtdError::ParseFailureDetail { what, detail }
        }
        EmrtdError::Transport(td) => match td {
            TransportDispatchError::Error(SmError::Transport(inner)) => {
                EmrtdError::Transport(TransportDispatchError::Error(inner))
            }
            TransportDispatchError::Error(sm_err) => {
                EmrtdError::SecureMessaging(format!("{sm_err}"))
            }
            TransportDispatchError::Outcome(o) => {
                EmrtdError::Transport(TransportDispatchError::Outcome(o))
            }
        },
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::ber;

    /// The Wikipedia ICAO 9303 TD1 example. Document type `I<`,
    /// issuer `UTO` (Utopia, the spec's example country), surname
    /// ERIKSSON, given names ANNA MARIA, sex F.
    const TD1_FIXTURE: &str = "\
I<UTOD231458907<<<<<<<<<<<<<<<\
7408122F1204159UTO<<<<<<<<<<<6\
ERIKSSON<<ANNA<MARIA<<<<<<<<<<";

    #[test]
    fn parse_td1_wikipedia_fixture() {
        let p = ParsedMrz::parse_td1(TD1_FIXTURE).expect("parse");
        assert_eq!(p.document_type, "I");
        assert_eq!(p.issuing_country.as_str(), "UTO");
        assert_eq!(p.document_number, "D23145890");
        // MrzDate wraps Iso8601 internally; round-trip the
        // on-card form via .to_mrz_yymmdd() and check the
        // resolved calendar year via the semantic projection.
        assert_eq!(p.date_of_birth.to_mrz_yymmdd(), "740812");
        assert_eq!(p.date_of_birth.date().year(), 1974);
        assert_eq!(p.sex, MrzSex::Female);
        assert_eq!(p.date_of_expiry.to_mrz_yymmdd(), "120415");
        assert_eq!(p.date_of_expiry.date().year(), 2012);
        assert_eq!(p.nationality.as_str(), "UTO");
        // On-card MRZ form: inner `<` separates given names;
        // trailing fillers are trimmed by the parser.
        assert_eq!(p.primary_identifier, "ERIKSSON");
        assert_eq!(p.secondary_identifier, "ANNA<MARIA");
        // Presentation form converts inner `<` to spaces.
        assert_eq!(p.secondary_identifier.spaced(), "ANNA MARIA");
        assert_eq!(p.gender_token(), "female");
    }

    #[test]
    fn parse_td1_male_finnish_shaped() {
        // Synthetic FIN-shaped TD1 -- doc number / DOB / DOE
        // / name are all placeholders. Check digits aren't
        // validated by ParsedMrz::parse_td1, so any digit works.
        let raw: String = format!(
            "{}{}{}",
            "IDFIN999999999<<<<<<<<<<<<<<<<",
            "0101019M0101010FIN<<<<<<<<<<<0",
            "SAMPLE<<TEST<<<<<<<<<<<<<<<<<<",
        );
        let p = ParsedMrz::parse_td1(&raw).expect("parse");
        assert_eq!(p.document_type, "ID");
        assert_eq!(p.issuing_country.as_str(), "FIN");
        assert_eq!(p.nationality.as_str(), "FIN");
        assert_eq!(p.sex, MrzSex::Male);
        assert_eq!(p.primary_identifier, "SAMPLE");
        assert_eq!(p.secondary_identifier, "TEST");
        assert_eq!(p.gender_token(), "male");
    }

    #[test]
    fn parse_td1_unspecified_sex() {
        let raw: String = format!(
            "{}{}{}",
            "IDFIN140378711<<<<<<<<<<<<<<<<",
            "7102156<3501016FIN<<<<<<<<<<<6",
            "DOE<<JOHN<<<<<<<<<<<<<<<<<<<<<",
        );
        let p = ParsedMrz::parse_td1(&raw).expect("parse");
        assert_eq!(p.sex, MrzSex::Unspecified);
        assert_eq!(p.gender_token(), "unspecified");
    }

    #[test]
    fn parse_td1_rejects_wrong_length() {
        ParsedMrz::parse_td1("too short").expect_err("under 90 chars is rejected");
        let too_long = "X".repeat(91);
        ParsedMrz::parse_td1(&too_long).expect_err("over 90 chars is rejected");
    }

    #[test]
    fn parse_td1_strips_line_breaks() {
        let formatted = format!(
            "{}\n{}\n{}",
            "I<UTOD231458907<<<<<<<<<<<<<<<",
            "7408122F1204159UTO<<<<<<<<<<<6",
            "ERIKSSON<<ANNA<MARIA<<<<<<<<<<",
        );
        let p = ParsedMrz::parse_td1(&formatted).expect("parse with line breaks");
        assert_eq!(p.primary_identifier, "ERIKSSON");
    }

    /// Build a synthetic EF.DG1: `61 [L] 5F1F [L] <90 MRZ chars>`.
    fn synth_dg1(mrz: &ParsedMrz) -> Vec<u8> {
        let inner = ber::tlv2(dg_tag::MRZ_DATA, mrz.raw.as_bytes());
        ber::tlv(DG1_WRAPPER_TAG_BYTE, inner)
    }

    #[test]
    fn extract_mrz_from_synthetic_dg1() {
        let parsed = ParsedMrz::parse_td1(TD1_FIXTURE).expect("parse");
        let dg1 = synth_dg1(&parsed);
        let dg1_typed = Dg1Bytes::parse(&dg1).expect("DG1 wrapper");
        let mrz = extract_mrz_string(&dg1_typed).expect("extract");
        assert_eq!(mrz, TD1_FIXTURE);
    }

    #[test]
    fn extract_mrz_with_long_form_length() {
        // 90 chars fits in a short-form length byte; force the
        // long-form path with an intentionally-padded ASN.1 buffer
        // by manually building the bytes.
        let fixture_len = u8::try_from(TD1_FIXTURE.len()).expect("TD1_FIXTURE is 90 bytes");
        let mut bytes = vec![0x5F, 0x1F, 0x81, fixture_len];
        bytes.extend_from_slice(TD1_FIXTURE.as_bytes());
        let bytes_len = u8::try_from(bytes.len()).expect("90-byte fixture + 4-byte header = 94");
        let mut outer = vec![0x61, 0x81, bytes_len];
        outer.extend_from_slice(&bytes);
        let dg1_typed = Dg1Bytes::parse(&outer).expect("DG1 wrapper");
        let mrz = extract_mrz_string(&dg1_typed).expect("extract");
        assert_eq!(mrz, TD1_FIXTURE);
    }

    #[test]
    fn extract_document_image_finds_jpeg() {
        // Pretend EF.DG2 with a CBEFF prefix and a JPEG inside.
        let mut dg2 = vec![0x7F, 0x61, 0x82, 0x00, 0x10, 0xAA, 0xBB, 0xCC, 0xDD];
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46];
        dg2.extend_from_slice(&jpeg);
        let img = DocumentImage::parse(&dg2).expect("found image");
        match img {
            DocumentImage::Jpeg(bytes) => {
                assert_eq!(&bytes[..jpeg.len()], &jpeg);
                assert_eq!(document_image_extension(&DocumentImage::Jpeg(bytes)), "jpg");
            }
            other @ DocumentImage::Jpeg2000(_) => panic!("expected JPEG, got {other:?}"),
        }
    }

    fn document_image_extension(img: &DocumentImage) -> &'static str {
        img.extension()
    }

    #[test]
    fn extract_document_image_finds_jpeg2000() {
        let mut dg2 = vec![0xAA, 0xBB, 0xCC];
        let jp2 = [
            0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87, 0x0A,
        ];
        dg2.extend_from_slice(&jp2);
        let img = DocumentImage::parse(&dg2).expect("found image");
        match img {
            DocumentImage::Jpeg2000(bytes) => {
                assert_eq!(&bytes[..jp2.len()], &jp2);
            }
            other @ DocumentImage::Jpeg(_) => panic!("expected JPEG2000, got {other:?}"),
        }
    }

    #[test]
    fn extract_document_image_returns_none_on_pure_random_bytes() {
        let dg2 = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x42, 0x42, 0x42];
        DocumentImage::parse(&dg2).expect_err("random bytes contain no image marker");
    }

    #[test]
    fn decode_outer_total_length_short_form() {
        // Tag `61`, length `0x07`, then 7 bytes of value.
        let buf = [0x61, 0x07, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00];
        assert_eq!(
            EmrtdHelpers::decode_outer_total_length(BerInput::parse(&buf).expect("header")),
            1 + 1 + 7
        );
    }

    #[test]
    fn decode_outer_total_length_long_form() {
        // Tag `61`, length `0x82 0x01 0x00` (256 bytes), then value.
        let buf = [0x61, 0x82, 0x01, 0x00];
        // Header length = 1 tag + 1 length-marker + 2 length-bytes = 4.
        // Plus value length 256 = total 260.
        assert_eq!(
            EmrtdHelpers::decode_outer_total_length(BerInput::parse(&buf).expect("header")),
            4 + 256
        );
    }

    #[test]
    fn decode_outer_total_length_two_byte_tag() {
        // Tag `5F 1F`, length `0x05`, then 5 bytes.
        let buf = [0x5F, 0x1F, 0x05, b'h', b'e', b'l', b'l', b'o'];
        // Header = 2 tag + 1 length = 3. Plus value 5 = 8.
        assert_eq!(
            EmrtdHelpers::decode_outer_total_length(BerInput::parse(&buf).expect("header")),
            8
        );
    }

    #[test]
    fn sfi_p1_encoding() {
        assert_eq!(SFI_EF_DG1.as_p1_short_form(), 0x81);
        assert_eq!(SFI_EF_DG2.as_p1_short_form(), 0x82);
        assert_eq!(SFI_EF_COM.as_p1_short_form(), 0x9E);
        assert_eq!(SFI_EF_SOD.as_p1_short_form(), 0x9D);
    }
}
