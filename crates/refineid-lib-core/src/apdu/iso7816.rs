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

//! Typed ISO 7816-4 command structs shared across protocol
//! modules.
//!
//! Each struct represents one specific ISO 7816-4 command shape
//! that refineid actually issues. `into_apdu(self) -> CommandApdu`
//! does the byte serialisation at the transport boundary; before
//! that point everything is typed values, after that point the
//! bytes are an opaque `CommandApdu` newtype.
//!
//! Protocol-specific commands (e.g. PACE's `GeneralAuthenticate`
//! with its step-1 to step-5 distinctions, signature's
//! `PerformSecurityOperation` variants) live in
//! `<module>::commands` rather than here. This module hosts only
//! the generic commands that more than one protocol issues.
//!
//! See `doc/typing-discipline.md` for the rules these commands
//! exist to enforce.

use core::error::Error as CoreError;
use core::fmt;

use crate::apdu::primitives::{Aid, Sfi};
use crate::transport::CommandApdu;

/// ISO 7816-4 `SELECT` by application identifier (`INS=0xA4
/// P1=0x04 P2=0x0C`), no FCI returned.
///
/// Produced by `pkcs15::select_pkcs15_application` and
/// `emrtd::select_application`. The `Aid` newtype enforces the
/// 5..=16-byte length at construction; the serialiser never
/// emits a malformed Lc.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SelectByAidNoFci {
    /// 5..=16-byte application identifier per ISO 7816-5 / ISO
    /// 7816-4 §8.2.1.2; the [`Aid`] newtype enforces the range.
    pub aid: Aid,
}

impl SelectByAidNoFci {
    /// ISO 7816-4 class byte `0x00`.
    pub const CLA: u8 = 0x00;
    /// ISO 7816-4 `SELECT` instruction.
    pub const INS: u8 = 0xA4;
    /// P1: select by application identifier (`0x04`).
    pub const P1: u8 = 0x04;
    /// P2 = `0x0C`: select first / only occurrence, return no
    /// FCI (refineid never uses the FCI from these SELECTs).
    pub const P2: u8 = 0x0C;

    /// Serialise into the wire APDU. `aid.len()` is bounded
    /// 5..=16 by [`Aid::new`]'s invariant; the Lc fits in `u8`
    /// without truncation.
    #[inline]
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        let bytes = self.aid.as_bytes();
        // Aid::new caps len at 16 bytes; u8::try_from is
        // infallible here, with a saturating fallback to
        // u8::MAX = 255 (still inside the Lc short-form range).
        let cap = APDU_HEADER_LEN
            .saturating_add(1)
            .saturating_add(bytes.len());
        let mut out = Vec::with_capacity(cap);
        out.extend_from_slice(&[Self::CLA, Self::INS, Self::P1, Self::P2]);
        let lc = u8::try_from(bytes.len()).unwrap_or(u8::MAX);
        out.push(lc);
        out.extend_from_slice(bytes);
        CommandApdu::new(out)
    }
}

/// ISO 7816-4 short-form command APDU header: CLA + INS + P1 + P2.
const APDU_HEADER_LEN: usize = 4;

/// CLA byte for FINEID S1 v4.2 commands.
///
/// Per FINEID S1 v4.2 §3.1 / §3.2 / §3.3 / §3.4 / ... every
/// FINEID command's CLA byte is one of:
///
/// - `00h` -- plain command, no secure messaging, no chaining,
///   logical channel 0.
/// - `0Ch` -- secure messaging applies per ISO 7816-4 §5.4
///   (SM with command header authenticated). The
///   secure-messaging wrap itself is applied by
///   `crate::secure_messaging`; this enum picks which CLA byte
///   goes on the wire before that wrap.
///
/// Used by every command struct in this module that needs a
/// `CLA` field. Future variants (command-chaining, alternative
/// logical channels) land as new variants if FINEID ever
/// requires them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ApduClass {
    /// `00h` -- plain command, no secure messaging.
    Plain,
    /// `0Ch` -- secure messaging applies per ISO 7816-4 §5.4.
    SecureMessaging,
    /// `10h` -- "transmit first portion of data in chaining
    /// mode with no secure messaging and wait for final
    /// portion" (FINEID S1 v4.2 §3.6.2). Used by commands that
    /// split the body across multiple APDUs (MSE: SET with a
    /// long CRDO list, PSO: DECIPHER for RSA-3072+).
    ChainedFirst,
}

impl ApduClass {
    /// Wire byte per FINEID S1 v4.2 §3.x.
    #[inline]
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Plain => 0x00,
            Self::SecureMessaging => 0x0C,
            Self::ChainedFirst => 0x10,
        }
    }
}

/// SELECT occurrence selector (P2) for the FINEID S1 v4.2 §3.1
/// SELECT command (Table 2).
///
/// When the card has multiple applications matching the AID
/// (uncommon but allowed by ISO 7816-5), the host iterates by
/// alternating First / Next.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SelectOccurrence {
    /// `00h` -- select first or only occurrence.
    First,
    /// `02h` -- select next occurrence (after a previous
    /// First / Next).
    Next,
}

impl SelectOccurrence {
    /// P2 wire byte per FINEID S1 v4.2 §3.1 Table 2.
    #[inline]
    #[must_use]
    pub const fn as_p2(self) -> u8 {
        match self {
            Self::First => 0x00,
            Self::Next => 0x02,
        }
    }
}

/// FINEID S1 v4.2 §3.1 SELECT command (Table 2): select an
/// application on the card by AID. Returns FCI per Table 3.
///
/// > The Select command selects an application on the card. All
/// > successive commands are handled by the selected application
/// > until a new application selection is made.
/// > -- FINEID S1 v4.2 §3.1.
///
/// Wire shape per Table 2:
/// `CLA INS=A4 P1=04 P2 Lc <AID> Le=00`.
///
/// Each field has a specific spec-defined meaning, captured at
/// the type level:
///
/// - `CLA`: [`ApduClass`] -- plain (`00h`) or secure messaging
///   (`0Ch`).
/// - `INS`: fixed at `A4h` (the SELECT instruction).
/// - `P1`: fixed at `04h` ("select by name (by AID)").
/// - `P2`: [`SelectOccurrence`] -- First (`00h`) or Next
///   (`02h`).
/// - `Lc`: derived from `aid.as_bytes().len()`; bounded
///   `5..=16` by [`Aid::new`].
/// - `Data`: [`Aid`] (typed AID bytes).
/// - `Le`: fixed at `00h` ("any length" -- the card returns
///   the FCI of whatever size).
///
/// Sibling to [`SelectByAidNoFci`] (which uses P2 = `0Ch` to
/// suppress the FCI; refineid uses that variant for PKCS#15
/// app selection where the FCI is discarded). The two are kept
/// as separate types so the wire-distinct shapes can't be
/// confused at the call site.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SelectByAidWithFci {
    /// CLA byte; plain or secure-messaging.
    pub class: ApduClass,
    /// P2 byte: which AID occurrence to select.
    pub occurrence: SelectOccurrence,
    /// Data field: the AID (5..=16 bytes; the [`Aid`] newtype
    /// enforces the range).
    pub aid: Aid,
}

impl SelectByAidWithFci {
    /// INS byte per FINEID S1 v4.2 §3.1 Table 2.
    pub const INS: u8 = 0xA4;
    /// P1 byte per Table 2: "select by name (by AID)".
    pub const P1: u8 = 0x04;
    /// Le byte per Table 2: any length.
    pub const LE: u8 = 0x00;

    /// Serialise into the wire APDU per Table 2.
    ///
    /// Wire layout: `<CLA> A4 04 <P2> <Lc=AID.len> <AID...> 00`.
    /// `Lc` is bounded by [`Aid::new`]'s 5..=16 invariant; the
    /// cast to `u8` is exact.
    #[inline]
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        let aid_bytes = self.aid.as_bytes();
        // Aid::new caps len at 16 bytes; capacity uses
        // saturating arithmetic and the u8 cast falls back to
        // u8::MAX = 255 (still inside Lc short-form).
        let cap = APDU_HEADER_LEN
            .saturating_add(1) // Lc
            .saturating_add(aid_bytes.len())
            .saturating_add(1); // Le
        let mut out = Vec::with_capacity(cap);
        out.push(self.class.as_byte());
        out.push(Self::INS);
        out.push(Self::P1);
        out.push(self.occurrence.as_p2());
        let lc = u8::try_from(aid_bytes.len()).unwrap_or(u8::MAX);
        out.push(lc);
        out.extend_from_slice(aid_bytes);
        out.push(Self::LE);
        CommandApdu::new(out)
    }
}

/// 2-byte ISO 7816-4 §5.3.1.1 file identifier.
///
/// EF / DF / MF identifiers are exactly two bytes on the wire.
/// Common well-known values:
///
/// - `3F 00` -- Master File (MF).
/// - `2F 00` -- EF.DIR per ISO 7816-4 §8.2.1.1.
/// - `5031` -- EF.ODF per PKCS#15 / FINEID S4 §A.2.
/// - `4331` / `4332` -- FINEID auth / non-repudiation cert EFs.
///
/// The type carries the fixed 2-byte length contract via an
/// owned array; the `as_bytes` accessor yields the wire bytes
/// for inclusion in the SELECT FILE Data field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct FileId([u8; 2]);

impl FileId {
    /// File identifier of the Master File: `3F 00`. ISO 7816-4
    /// §8.2.1.1 reserves this FID for the MF.
    pub const MF: Self = Self([0x3F, 0x00]);

    /// PKCS#15 application DF: `50 15`. Per ISO/IEC 7816-15 the
    /// PKCS#15 application's DF FID is the conventional `5015h`
    /// when not selected by AID.
    pub const PKCS15_DF: Self = Self([0x50, 0x15]);

    /// PKCS#15 EF.ODF (Object Directory File): `50 31`. The
    /// PKCS#15 root file inside the application DF that lists
    /// every PKCS#15 object directory present on the card.
    pub const EF_ODF: Self = Self([0x50, 0x31]);

    /// PKCS#15 EF.TokenInfo: `50 32`. Per ISO/IEC 7816-15 §6.1
    /// the PKCS#15 application descriptor file.
    pub const EF_TOKEN_INFO: Self = Self([0x50, 0x32]);

    /// Wrap the two wire bytes.
    #[inline]
    #[must_use]
    pub const fn new(bytes: [u8; 2]) -> Self {
        Self(bytes)
    }

    /// Borrow the two wire bytes for inclusion in SELECT FILE
    /// data fields or for FID comparisons.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 2] {
        &self.0
    }
}

/// Absolute path from the MF, per FINEID S1 v4.2 §3.2.2 (P1 =
/// `08h` Data semantics): a sequence of file identifiers from
/// the immediate MF children down to the target, **without** the
/// `3F00h` MF prefix.
///
/// Empty path = MF itself (which the spec instead expresses as
/// the P1=`00h` empty-data form; `AbsolutePath` is therefore
/// non-empty by construction).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct AbsolutePath {
    /// Ordered DF/EF identifiers from the MF down to the target,
    /// with the implicit `3F00h` MF prefix omitted per ISO 7816-4
    /// §7.1.1 (path data object encoding).
    fids: Vec<FileId>,
}

/// Construction errors for [`AbsolutePath`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AbsolutePathError {
    /// Caller passed an empty list; per the spec, that's MF
    /// selection -- use the P1=`00h` empty-data form instead.
    Empty,
    /// The path starts with `3F00h` (MF). Per the spec, the MF
    /// prefix is omitted from the wire form; pass the path
    /// without it.
    StartsWithMf,
}

impl fmt::Display for AbsolutePathError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "AbsolutePath: empty (use P1=00h empty-data form for MF)"),
            Self::StartsWithMf => write!(
                f,
                "AbsolutePath: starts with 3F00h MF prefix (omit per FINEID S1 v4.2 \u{00a7}3.2.2)"
            ),
        }
    }
}

impl CoreError for AbsolutePathError {}

impl AbsolutePath {
    /// Build a path from a non-empty sequence of FIDs.
    ///
    /// # Errors
    /// - [`AbsolutePathError::Empty`] if `fids` is empty.
    /// - [`AbsolutePathError::StartsWithMf`] if the first FID
    ///   is `3F00h` -- the spec wire form omits the MF prefix.
    #[inline]
    pub fn new(fids: Vec<FileId>) -> Result<Self, AbsolutePathError> {
        if fids.is_empty() {
            return Err(AbsolutePathError::Empty);
        }
        if fids.first() == Some(&FileId::MF) {
            return Err(AbsolutePathError::StartsWithMf);
        }
        Ok(Self { fids })
    }

    /// Borrow the FID sequence.
    #[inline]
    #[must_use]
    pub fn as_fids(&self) -> &[FileId] {
        &self.fids
    }
}

/// SELECT FILE selection target per FINEID S1 v4.2 §3.2.2.
///
/// Each variant encodes one of the four P1 modes; the inner
/// payload is the Data-field shape that mode requires. The
/// command serialiser reads `P1` and `Data` straight off the
/// variant.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SelectFileTarget {
    /// `P1=00h` -- select EF, DF or MF by file identifier.
    /// `None` means "select MF" (empty data field per the spec
    /// note on §3.2 -- but the spec also says "if P1, P2 and
    /// Lc are all zero, the command selects the root but
    /// returns no data; to select the root and return the FCI
    /// information, you must select it by its file ID 3F00h",
    /// which is the explicit `Some(FileId::MF)` form).
    AnyByFileId(Option<FileId>),
    /// `P1=02h` -- select EF by file identifier under the
    /// current DF.
    EfUnderCurrentDf(FileId),
    /// `P1=04h` -- select DF or MF by name. The "name" is the
    /// application identifier (AID) per ISO 7816-5.
    ByName(Aid),
    /// `P1=08h` -- select file by absolute path from MF
    /// without the `3F00h` prefix.
    AbsolutePath(AbsolutePath),
}

impl SelectFileTarget {
    /// P1 wire byte per FINEID S1 v4.2 §3.2.2.
    #[inline]
    #[must_use]
    pub const fn as_p1(&self) -> u8 {
        match self {
            Self::AnyByFileId(_) => 0x00,
            Self::EfUnderCurrentDf(_) => 0x02,
            Self::ByName(_) => 0x04,
            Self::AbsolutePath(_) => 0x08,
        }
    }

    /// Length of the Data field for this target.
    #[inline]
    #[must_use]
    pub fn data_len(&self) -> usize {
        match self {
            Self::AnyByFileId(None) => 0,
            Self::AnyByFileId(Some(_)) | Self::EfUnderCurrentDf(_) => 2,
            Self::ByName(aid) => aid.as_bytes().len(),
            // Each FID is exactly 2 bytes; FINEID short-form APDU Lc
            // caps total path length at 255 bytes (=> at most 127
            // FIDs); `len * 2` cannot overflow usize.
            Self::AbsolutePath(path) => path.as_fids().len().saturating_mul(2),
        }
    }

    /// Append the Data-field bytes for this target to `out`.
    fn append_data(&self, out: &mut Vec<u8>) {
        match self {
            Self::AnyByFileId(None) => {}
            Self::AnyByFileId(Some(fid)) | Self::EfUnderCurrentDf(fid) => {
                out.extend_from_slice(fid.as_bytes());
            }
            Self::ByName(aid) => out.extend_from_slice(aid.as_bytes()),
            Self::AbsolutePath(path) => {
                for fid in path.as_fids() {
                    out.extend_from_slice(fid.as_bytes());
                }
            }
        }
    }
}

/// SELECT FILE response selector (P2) per FINEID S1 v4.2 §3.2.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SelectFileResponseMode {
    /// `P2=00h` -- card returns the FCI template (Annex A).
    Fci,
    /// `P2=04h` -- card returns the FCP template (Annex A).
    Fcp,
    /// `P2=0Ch` -- card returns no response data.
    None,
}

impl SelectFileResponseMode {
    /// P2 wire byte per FINEID S1 v4.2 §3.2.2.
    #[inline]
    #[must_use]
    pub const fn as_p2(self) -> u8 {
        match self {
            Self::Fci => 0x00,
            Self::Fcp => 0x04,
            Self::None => 0x0C,
        }
    }
}

/// FINEID S1 v4.2 §3.2 SELECT FILE: select a DF or an EF.
///
/// Generalisation of the focused [`SelectEfNoFci`] command (which
/// covers the P1=`02h` P2=`0Ch` subset). The four P1 modes and
/// three P2 modes from §3.2.2 are reified as
/// [`SelectFileTarget`] / [`SelectFileResponseMode`] enums;
/// the wire bytes follow mechanically from the typed inputs.
///
/// Wire shape per §3.2.2:
/// `CLA A4 <P1> <P2> [Lc <Data>] [Le=00]`.
///
/// `Lc` and `Data` are emitted only when [`SelectFileTarget`]
/// carries data. `Le=00` is emitted only when the response
/// mode is [`SelectFileResponseMode::Fci`] or
/// [`SelectFileResponseMode::Fcp`] (P2=`0Ch` is "no response"
/// so Le has no meaning).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SelectFile {
    /// CLA byte: plain or secure-messaging.
    pub class: ApduClass,
    /// P1 selector + matching Data shape.
    pub target: SelectFileTarget,
    /// P2 selector: which response template the card returns.
    pub response_mode: SelectFileResponseMode,
}

impl SelectFile {
    /// INS byte per §3.2.2.
    pub const INS: u8 = 0xA4;
    /// Le byte when a response is expected (P2 = `00h` or
    /// `04h`).
    pub const LE_ANY: u8 = 0x00;

    /// Serialise into the wire APDU per §3.2.2.
    ///
    /// Emits Lc + Data only when the target carries bytes; emits
    /// Le only when the response mode expects a body.
    #[inline]
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        let data_len = self.target.data_len();
        // SelectFileTarget invariants bound data_len at
        // FINEID's short-form Lc max (255); saturating
        // arithmetic keeps the capacity computation panic-free.
        let cap = APDU_HEADER_LEN
            .saturating_add(1) // Lc
            .saturating_add(data_len)
            .saturating_add(1); // Le
        let mut out = Vec::with_capacity(cap);
        out.push(self.class.as_byte());
        out.push(Self::INS);
        out.push(self.target.as_p1());
        out.push(self.response_mode.as_p2());
        if data_len > 0 {
            let lc = u8::try_from(data_len).unwrap_or(u8::MAX);
            out.push(lc);
            self.target.append_data(&mut out);
        }
        if matches!(
            self.response_mode,
            SelectFileResponseMode::Fci | SelectFileResponseMode::Fcp
        ) {
            out.push(Self::LE_ANY);
        }
        CommandApdu::new(out)
    }
}

/// FINEID S1 v4.2 §3.3 GET RESPONSE: fetch response data from
/// the card for a case-4 APDU.
///
/// Used after SELECT FILE / PSO:CDS / PSO:DECIPHER when the
/// card signalled chained-response availability (SW `61XX`)
/// or the host wanted to fetch the body separately.
///
/// Wire shape per §3.3.2:
/// `CLA C0 00 00 Le`.
///
/// Each field has a specific spec-defined meaning, captured at
/// the type level:
///
/// - `CLA`: [`ApduClass`] -- plain (`00h`) or secure messaging
///   (`0Ch`).
/// - `INS`: fixed at `C0h` (GET RESPONSE).
/// - `P1`: fixed at `00h`.
/// - `P2`: fixed at `00h`.
/// - `Lc`: empty (no data field).
/// - `Data`: empty.
/// - `Le`: maximum bytes the host is willing to receive.
///
/// Response payload is what the card stashed waiting for the
/// host. Status word semantics per §3.3.3:
///
/// - `9000h`: success, `Le == Licc` (the host's expected
///   length matched the available length).
/// - `61XXh`: `Le < Licc`, `XX` is the remaining number of
///   data bytes still in the card. Caller may follow up with
///   another GET RESPONSE.
/// - `6CXXh`: `Le > Licc`, `XX` is `Licc` (re-issue with the
///   correct Le).
/// - `6884h`: chaining mechanism not available for the prior
///   command.
/// - `6982h`: security status not satisfied.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct GetResponse {
    /// CLA byte.
    pub class: ApduClass,
    /// Maximum response bytes expected (`Le` per §3.3.2). `0`
    /// means "any length"; the card will return up to its
    /// internal buffer maximum.
    pub le: u8,
}

impl GetResponse {
    /// INS byte per §3.3.2.
    pub const INS: u8 = 0xC0;
    /// P1 byte per §3.3.2.
    pub const P1: u8 = 0x00;
    /// P2 byte per §3.3.2.
    pub const P2: u8 = 0x00;

    /// Construct a GET RESPONSE for the given class and `Le`.
    ///
    /// `le` is the maximum response bytes the host will accept
    /// (`0` means "any length"); a `61XX` continuation passes the
    /// card's reported `XX` here. The struct is `#[non_exhaustive]`,
    /// so this is the cross-crate construction path.
    #[inline]
    #[must_use]
    pub const fn new(class: ApduClass, le: u8) -> Self {
        Self { class, le }
    }

    /// Serialise into the wire APDU per §3.3.2.
    ///
    /// Wire layout: `<CLA> C0 00 00 <Le>` -- 5 bytes total. No
    /// Lc / Data; the only variable byte is `Le`.
    #[inline]
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        CommandApdu::new(vec![
            self.class.as_byte(),
            Self::INS,
            Self::P1,
            Self::P2,
            self.le,
        ])
        .allow_wrong_le_retry()
    }
}

/// ISO 7816-4 `SELECT` by 2-byte file identifier under the
/// current DF without response data (`INS=0xA4 P1=0x02 P2=0x0C`).
///
/// This is the proven FINEID wire shape used by the Apple port:
/// a case-3 APDU with no trailing `Le`. Keeping the command case-3
/// also avoids the Windows T=0 stack rejecting the old case-4
/// FCI-request shape with `ERROR_INVALID_PARAMETER`.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct SelectEfNoFci {
    /// 2-byte file identifier per ISO 7816-4 §5.3.1.1. Owned
    /// array carries the "exactly 2 bytes" invariant at the
    /// type level.
    pub fid: [u8; 2],
}

impl SelectEfNoFci {
    /// ISO 7816-4 class byte `0x00`.
    pub const CLA: u8 = 0x00;
    /// ISO 7816-4 `SELECT` instruction.
    pub const INS: u8 = 0xA4;
    /// P1: select by file identifier under current DF (`0x02`).
    pub const P1: u8 = 0x02;
    /// P2 = `0x0C`: return no file control information.
    pub const P2: u8 = 0x0C;

    /// Serialise into the wire APDU
    /// (`00 A4 02 0C 02 <fid0> <fid1>`; 7 bytes).
    #[inline]
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        // CLA INS P1 P2 Lc=02 FID
        CommandApdu::new(vec![
            Self::CLA,
            Self::INS,
            Self::P1,
            Self::P2,
            0x02,
            self.fid[0],
            self.fid[1],
        ])
    }
}

/// Direct-selection byte offset for FINEID S1 v4.2 §3.4 READ
/// BINARY (and §3.13 UPDATE BINARY, §3.14 ERASE BINARY which
/// share the P1-P2 coding).
///
/// Per §3.4.2 coding table, the direct-selection form uses
/// `b8` of P1 set to `0` and the remaining 15 bits (b7..b1 of
/// P1 || b8..b1 of P2) for the byte offset within the
/// currently-selected EF. Maximum addressable offset is
/// therefore `0x7FFF` (32767).
///
/// `DirectOffset15` enforces the 15-bit range at construction;
/// the serialiser doesn't need to mask, and the typed value
/// can't silently round-trip into the SFI-form encoding
/// (which would happen if `b8` of P1 ever ended up set).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct DirectOffset15(u16);

/// Construction error for [`DirectOffset15`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DirectOffset15Error {
    /// Offset above the 15-bit cap.
    OutOfRange {
        /// The offending offset value.
        got: u16,
        /// Maximum allowed (always `0x7FFF`).
        max: u16,
    },
}

impl fmt::Display for DirectOffset15Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange { got, max } => write!(
                f,
                "READ BINARY direct offset {got:#06X} exceeds 15-bit cap {max:#06X}"
            ),
        }
    }
}

impl CoreError for DirectOffset15Error {}

impl DirectOffset15 {
    /// Maximum 15-bit offset value (`0x7FFF`).
    pub const MAX: u16 = 0x7FFF;

    /// Wrap a `u16` offset, validating it fits in 15 bits.
    ///
    /// # Errors
    /// [`DirectOffset15Error::OutOfRange`] when `offset >
    /// 0x7FFF`.
    #[inline]
    pub const fn try_new(offset: u16) -> Result<Self, DirectOffset15Error> {
        if offset > Self::MAX {
            return Err(DirectOffset15Error::OutOfRange {
                got: offset,
                max: Self::MAX,
            });
        }
        Ok(Self(offset))
    }

    /// Read the underlying offset value.
    #[inline]
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// P1 byte: high octet of the 15-bit offset (b8 = 0 to
    /// signal direct-selection mode per §3.4.2 coding table).
    #[inline]
    #[must_use]
    pub const fn as_p1(self) -> u8 {
        // `try_new` caps `self.0` at 0x7FFF so the high byte
        // never exceeds 0x7F; using to_be_bytes() avoids any
        // `as u8` truncation cast.
        let [hi, _lo] = self.0.to_be_bytes();
        hi
    }

    /// P2 byte: low octet of the 15-bit offset.
    #[inline]
    #[must_use]
    pub const fn as_p2(self) -> u8 {
        let [_hi, lo] = self.0.to_be_bytes();
        lo
    }
}

/// READ BINARY offset/SFI selector per FINEID S1 v4.2 §3.4.2
/// coding table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReadBinaryOffset {
    /// Direct-selection form (`b8` of P1 = 0). Reads from the
    /// currently-selected EF at the given 15-bit byte offset.
    Direct(DirectOffset15),
    /// SFI-form (`b8` of P1 = 1). P1 carries the short FID in
    /// bits b5..b1; P2 is an 8-bit byte offset within that EF.
    /// The card implicitly selects the EF as part of the read.
    BySfi {
        /// Short file identifier (1..=30 per ISO 7816-4
        /// §5.3.1.1; the [`Sfi`] newtype enforces the range).
        /// SFI `0x1F` (31) is excluded by §3.4.2's note.
        sfi: Sfi,
        /// 8-bit byte offset within the EF identified by `sfi`.
        offset: u8,
    },
}

impl ReadBinaryOffset {
    /// P1 wire byte per §3.4.2 coding table.
    #[inline]
    #[must_use]
    pub const fn as_p1(self) -> u8 {
        match self {
            Self::Direct(o) => o.as_p1(),
            Self::BySfi { sfi, .. } => sfi.as_p1_short_form(),
        }
    }

    /// P2 wire byte per §3.4.2 coding table.
    #[inline]
    #[must_use]
    pub const fn as_p2(self) -> u8 {
        match self {
            Self::Direct(o) => o.as_p2(),
            Self::BySfi { offset, .. } => offset,
        }
    }
}

/// FINEID S1 v4.2 §3.4 READ BINARY: read all or part of a
/// transparent EF.
///
/// Two referencing modes per §3.4 intro (the [`ReadBinaryOffset`]
/// variants encode both):
///
/// 1. **Implicit selection** -- specify the EF by its short
///    file identifier (SFI); the card selects + reads in one
///    APDU.
/// 2. **Direct selection** -- the EF must have been previously
///    selected via SELECT FILE; offset addresses the
///    currently-selected EF.
///
/// Wire shape per §3.4.2:
/// `CLA B0 <P1> <P2> <Le>` (5 bytes; no Lc / Data).
///
/// Each field has a specific spec-defined meaning:
///
/// - `CLA`: [`ApduClass`] -- plain (`00h`) or secure messaging.
/// - `INS`: fixed at `B0h`.
/// - `P1`/`P2`: derived from [`ReadBinaryOffset`] per the
///   §3.4.2 coding table.
/// - `Lc`: empty.
/// - `Data`: empty.
/// - `Le`: bytes to read (0..=255). 0 means "read until end of
///   file, up to 255 bytes (including SM data if used)".
///
/// `ReadBinary` supersedes [`ReadBinaryBySfi`] /
/// [`ReadBinaryByOffset`] (the legacy split where the offset
/// shape lived in the struct name and the 15-bit cap was
/// enforced only at serialise time via `& 0x7F` masking).
/// Existing consumers continue to compile against the legacy
/// types until migrated.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ReadBinary {
    /// CLA byte.
    pub class: ApduClass,
    /// P1/P2 selector + data shape per §3.4.2 coding table.
    pub offset: ReadBinaryOffset,
    /// Le: bytes to read, 0..=255. `0` = read until end of EF.
    pub le: u8,
}

impl ReadBinary {
    /// INS byte per §3.4.2.
    pub const INS: u8 = 0xB0;

    /// Serialise into the wire APDU per §3.4.2.
    ///
    /// 5 bytes: `CLA B0 P1 P2 Le`. No Lc / Data field.
    #[inline]
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        CommandApdu::new(vec![
            self.class.as_byte(),
            Self::INS,
            self.offset.as_p1(),
            self.offset.as_p2(),
            self.le,
        ])
        .allow_wrong_le_retry()
    }
}

/// ISO 7816-4 `READ BINARY` by Short File Identifier
/// (`INS=0xB0 P1=0x80|sfi`).
///
/// Used by `emrtd::read_file` to read `DG_n`. The SFI is encoded
/// into P1 with the high bit set; the [`Sfi`] newtype enforces
/// the 1..=30 range.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ReadBinaryBySfi {
    /// Short File Identifier (1..=30 per ISO 7816-4 §5.3.1.1);
    /// encoded into P1 as `0x80 | sfi` via [`Sfi::as_p1_short_form`].
    pub sfi: Sfi,
    /// Offset within the EF, 0..=255 (short-form addressing).
    pub offset: u8,
    /// Le byte: 0 = "as many as the card has".
    pub le: u8,
}

impl ReadBinaryBySfi {
    /// ISO 7816-4 class byte `0x00`.
    pub const CLA: u8 = 0x00;
    /// ISO 7816-4 `READ BINARY` instruction.
    pub const INS: u8 = 0xB0;

    /// Serialise into the wire APDU
    /// (`00 B0 <0x80|sfi> <offset> <le>`; 5 bytes).
    #[inline]
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        CommandApdu::new(vec![
            Self::CLA,
            Self::INS,
            self.sfi.as_p1_short_form(),
            self.offset,
            self.le,
        ])
        .allow_wrong_le_retry()
    }
}

/// ISO 7816-4 `INTERNAL AUTHENTICATE` (`INS=0x88 P1=0 P2=0`)
/// with an 8-byte host challenge.
///
/// Used by Active Authentication (eMRTD, ICAO 9303-11 §6.1) --
/// the card signs the challenge with its DG15-published private
/// key.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct InternalAuthenticate {
    /// 8-byte host-supplied challenge per ICAO 9303-11 §6.1.
    /// Owned array carries the "exactly 8 bytes" invariant at
    /// the type level.
    pub challenge: [u8; 8],
}

impl InternalAuthenticate {
    /// ISO 7816-4 class byte `0x00`.
    pub const CLA: u8 = 0x00;
    /// ISO 7816-4 `INTERNAL AUTHENTICATE` instruction.
    pub const INS: u8 = 0x88;
    /// P1: reserved (`0x00`).
    pub const P1: u8 = 0x00;
    /// P2: reserved (`0x00`).
    pub const P2: u8 = 0x00;

    /// Serialise into the wire APDU
    /// (`00 88 00 00 08 <challenge[..8]> 00`; 14 bytes).
    #[inline]
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        let mut out = Vec::with_capacity(5 + 8 + 1);
        out.extend_from_slice(&[Self::CLA, Self::INS, Self::P1, Self::P2, 0x08]);
        out.extend_from_slice(&self.challenge);
        out.push(0x00); // Le = 0 -> "as many as the card has".
        CommandApdu::new(out)
    }
}

/// ISO 7816-4 `READ BINARY` by offset within the currently-
/// selected EF (`INS=0xB0 P1=(offset>>8) P2=(offset&0xFF)`).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ReadBinaryByOffset {
    /// Byte offset within the currently selected EF (15-bit
    /// max per ISO 7816-4 §6 short-form). Tier 0 `u16` -- the
    /// spec's 15-bit cap is enforced at serialise time (`P1 &=
    /// 0x7F`); the field type alone admits `0x8000..=0xFFFF`.
    pub offset: u16,
    /// Le byte; 0 = up to 256 bytes.
    pub le: u8,
}

impl ReadBinaryByOffset {
    /// ISO 7816-4 class byte `0x00`.
    pub const CLA: u8 = 0x00;
    /// ISO 7816-4 `READ BINARY` instruction.
    pub const INS: u8 = 0xB0;

    /// Serialise into the wire APDU
    /// (`00 B0 <offset_hi&0x7F> <offset_lo> <le>`; 5 bytes).
    #[inline]
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        // 15-bit max addressable offset per ISO 7816-4 §6 (the
        // 0x80 bit of P1 distinguishes SFI form). Refineid never
        // reads past 32 KB so the high bit is always zero; the
        // mask is defensive against caller bugs and the
        // be-bytes accessor avoids `as u8` truncation casts.
        let [hi, lo] = self.offset.to_be_bytes();
        let p1 = hi & 0x7F;
        let p2 = lo;
        CommandApdu::new(vec![Self::CLA, Self::INS, p1, p2, self.le]).allow_wrong_le_retry()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn select_by_aid_serialises_correctly() -> Result<(), Box<dyn core::error::Error>> {
        let aid = Aid::from_slice(&[0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01])?;
        let apdu = SelectByAidNoFci { aid }.into_apdu();
        assert_eq!(
            apdu.as_bytes(),
            &[
                0x00, 0xA4, 0x04, 0x0C, 0x07, 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01
            ]
        );
        Ok(())
    }

    /// Build the expected wire bytes for a SELECT-by-AID-with-FCI
    /// command from its typed components, per FINEID S1 v4.2 §3.1
    /// Table 2. The expected bytes are derived from the named
    /// symbols on the typed types, not hand-coded hex literals,
    /// so the test fixture and the production code share one
    /// source of truth for each spec-defined value.
    fn expected_wire(class: ApduClass, occurrence: SelectOccurrence, aid_bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(6 + aid_bytes.len());
        out.push(class.as_byte());
        out.push(SelectByAidWithFci::INS);
        out.push(SelectByAidWithFci::P1);
        out.push(occurrence.as_p2());
        out.push(u8::try_from(aid_bytes.len()).expect("Lc: AID length is bounded by Aid::new"));
        out.extend_from_slice(aid_bytes);
        out.push(SelectByAidWithFci::LE);
        out
    }

    #[test]
    fn select_by_aid_with_fci_serialises_per_fineid_s1_table_2()
    -> Result<(), Box<dyn core::error::Error>> {
        // FINEID S1 v4.2 §3.1 Table 2: plain CLA, first
        // occurrence, AID = the PKCS#15 application AID published
        // by FINEID S4-2 §3.1 (constant `PKCS15_AID`).
        let aid = Aid::from_slice(crate::pkcs15::PKCS15_AID)?;
        let apdu = SelectByAidWithFci {
            class: ApduClass::Plain,
            occurrence: SelectOccurrence::First,
            aid,
        }
        .into_apdu();
        assert_eq!(
            apdu.as_bytes(),
            expected_wire(
                ApduClass::Plain,
                SelectOccurrence::First,
                crate::pkcs15::PKCS15_AID,
            ),
        );
        Ok(())
    }

    #[test]
    fn select_by_aid_with_fci_secure_messaging_cla() -> Result<(), Box<dyn core::error::Error>> {
        // Test-local AID with a different shape (smallest 5-byte
        // AID per ISO 7816-5 lower bound + two payload bytes for
        // 7 total) used to exercise the secure-messaging CLA and
        // the Next-occurrence P2 path.
        const TEST_DEMO_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01];
        let aid = Aid::from_slice(TEST_DEMO_AID)?;
        let apdu = SelectByAidWithFci {
            class: ApduClass::SecureMessaging,
            occurrence: SelectOccurrence::Next,
            aid,
        }
        .into_apdu();
        assert_eq!(
            apdu.as_bytes(),
            expected_wire(
                ApduClass::SecureMessaging,
                SelectOccurrence::Next,
                TEST_DEMO_AID,
            ),
        );
        Ok(())
    }

    #[test]
    fn select_ef_serialises_correctly() {
        let apdu = SelectEfNoFci { fid: [0x3F, 0x00] }.into_apdu();
        assert_eq!(apdu.as_bytes(), &[0x00, 0xA4, 0x02, 0x0C, 0x02, 0x3F, 0x00]);
    }

    #[test]
    fn read_binary_by_sfi_serialises_correctly() -> Result<(), Box<dyn core::error::Error>> {
        let apdu = ReadBinaryBySfi {
            sfi: Sfi::new(1)?,
            offset: 0,
            le: 0,
        }
        .into_apdu();
        assert_eq!(apdu.as_bytes(), &[0x00, 0xB0, 0x81, 0x00, 0x00]);
        Ok(())
    }

    #[test]
    fn read_binary_by_offset_serialises_correctly() {
        let apdu = ReadBinaryByOffset {
            offset: 0x1234,
            le: 4,
        }
        .into_apdu();
        assert_eq!(apdu.as_bytes(), &[0x00, 0xB0, 0x12, 0x34, 0x04]);
    }

    // === SELECT FILE (§3.2) =========================================

    /// Build the expected wire bytes for a SELECT FILE command
    /// from its typed components per §3.2.2. Derived from the
    /// named symbols (`ApduClass::*.as_byte()`, `SelectFile::INS`,
    /// `target.as_p1()`, `response_mode.as_p2()`, ...), so the
    /// test fixture and the production serialiser share one
    /// source of truth.
    fn expected_select_file_wire(
        class: ApduClass,
        target: &SelectFileTarget,
        response_mode: SelectFileResponseMode,
    ) -> Vec<u8> {
        let data_len = target.data_len();
        let mut out = Vec::with_capacity(6 + data_len);
        out.push(class.as_byte());
        out.push(SelectFile::INS);
        out.push(target.as_p1());
        out.push(response_mode.as_p2());
        if data_len > 0 {
            out.push(u8::try_from(data_len).expect("SELECT FILE data is a FID or short AID"));
            target.append_data(&mut out);
        }
        if matches!(
            response_mode,
            SelectFileResponseMode::Fci | SelectFileResponseMode::Fcp
        ) {
            out.push(SelectFile::LE_ANY);
        }
        out
    }

    #[test]
    fn select_file_p1_any_by_fid_with_fci() {
        // P1=00h with explicit MF FID, P2=00h FCI returned.
        let target = SelectFileTarget::AnyByFileId(Some(FileId::MF));
        let cmd = SelectFile {
            class: ApduClass::Plain,
            target: target.clone(),
            response_mode: SelectFileResponseMode::Fci,
        };
        assert_eq!(
            cmd.into_apdu().as_bytes(),
            expected_select_file_wire(ApduClass::Plain, &target, SelectFileResponseMode::Fci),
        );
    }

    #[test]
    fn select_file_p1_any_empty_data_selects_mf() {
        // P1=00h with empty data = select MF (the implicit form).
        let target = SelectFileTarget::AnyByFileId(None);
        let cmd = SelectFile {
            class: ApduClass::Plain,
            target: target.clone(),
            response_mode: SelectFileResponseMode::None,
        };
        let wire = cmd.into_apdu();
        // Per spec note: "if P1, P2 and Lc are all zero, the
        // command selects the root but returns no data". Here
        // we use P2=0Ch (no response); the wire has no Lc /
        // Data / Le.
        assert_eq!(
            wire.as_bytes(),
            expected_select_file_wire(ApduClass::Plain, &target, SelectFileResponseMode::None),
        );
        // Sanity-check the no-Lc / no-Le shape.
        assert_eq!(wire.as_bytes().len(), 4);
    }

    #[test]
    fn select_file_p1_ef_under_current_df() {
        // P1=02h: select EF under current DF, here EF.ODF.
        let target = SelectFileTarget::EfUnderCurrentDf(FileId::EF_ODF);
        let cmd = SelectFile {
            class: ApduClass::Plain,
            target: target.clone(),
            response_mode: SelectFileResponseMode::Fci,
        };
        assert_eq!(
            cmd.into_apdu().as_bytes(),
            expected_select_file_wire(ApduClass::Plain, &target, SelectFileResponseMode::Fci),
        );
    }

    #[test]
    fn select_file_p1_by_name_with_fcp() -> Result<(), Box<dyn core::error::Error>> {
        // P1=04h: select DF by name (AID). P2=04h: FCP returned.
        let aid = Aid::from_slice(crate::pkcs15::PKCS15_AID)?;
        let target = SelectFileTarget::ByName(aid);
        let cmd = SelectFile {
            class: ApduClass::SecureMessaging,
            target: target.clone(),
            response_mode: SelectFileResponseMode::Fcp,
        };
        assert_eq!(
            cmd.into_apdu().as_bytes(),
            expected_select_file_wire(
                ApduClass::SecureMessaging,
                &target,
                SelectFileResponseMode::Fcp,
            ),
        );
        Ok(())
    }

    #[test]
    fn select_file_p1_absolute_path() -> Result<(), Box<dyn core::error::Error>> {
        // P1=08h: select by absolute path from MF (no 3F00
        // prefix). Path: PKCS#15 DF (5015) -> EF.ODF (5031).
        let path = AbsolutePath::new(vec![FileId::PKCS15_DF, FileId::EF_ODF])?;
        let target = SelectFileTarget::AbsolutePath(path);
        let cmd = SelectFile {
            class: ApduClass::Plain,
            target: target.clone(),
            response_mode: SelectFileResponseMode::Fci,
        };
        assert_eq!(
            cmd.into_apdu().as_bytes(),
            expected_select_file_wire(ApduClass::Plain, &target, SelectFileResponseMode::Fci),
        );
        Ok(())
    }

    #[test]
    fn absolute_path_rejects_empty() {
        assert_eq!(AbsolutePath::new(vec![]), Err(AbsolutePathError::Empty));
    }

    #[test]
    fn absolute_path_rejects_mf_prefix() {
        assert_eq!(
            AbsolutePath::new(vec![FileId::MF, FileId::EF_ODF]),
            Err(AbsolutePathError::StartsWithMf),
        );
    }

    // === GET RESPONSE (§3.3) =======================================

    #[test]
    fn get_response_serialises_per_fineid_s1_table() {
        // §3.3.2 Format: CLA C0 00 00 Le. Plain CLA, Le=128
        // (host expects up to 128 bytes).
        const TEST_LE: u8 = 128;
        let cmd = GetResponse {
            class: ApduClass::Plain,
            le: TEST_LE,
        };
        let expected: Vec<u8> = vec![
            ApduClass::Plain.as_byte(),
            GetResponse::INS,
            GetResponse::P1,
            GetResponse::P2,
            TEST_LE,
        ];
        assert_eq!(cmd.into_apdu().as_bytes(), expected);
    }

    #[test]
    fn get_response_secure_messaging() {
        // SM CLA, Le=0 (any length).
        const ANY_LENGTH: u8 = 0x00;
        let cmd = GetResponse {
            class: ApduClass::SecureMessaging,
            le: ANY_LENGTH,
        };
        let expected: Vec<u8> = vec![
            ApduClass::SecureMessaging.as_byte(),
            GetResponse::INS,
            GetResponse::P1,
            GetResponse::P2,
            ANY_LENGTH,
        ];
        assert_eq!(cmd.into_apdu().as_bytes(), expected);
    }

    // === READ BINARY (§3.4) ========================================

    /// `0x80` = bit 8 (b8) of the READ BINARY P1 byte; FINEID S1 v4.2
    /// §3.4.1 / ISO 7816-4 §7.2.3: 0 = direct-offset mode, 1 = SFI
    /// mode. Used by the round-trip tests below to sanity-check the
    /// mode bit on the assembled wire byte.
    const SFI_MODE_BIT: u8 = 0x80;

    fn expected_read_binary_wire(class: ApduClass, offset: ReadBinaryOffset, le: u8) -> Vec<u8> {
        vec![
            class.as_byte(),
            ReadBinary::INS,
            offset.as_p1(),
            offset.as_p2(),
            le,
        ]
    }

    #[test]
    fn read_binary_direct_offset() -> Result<(), Box<dyn core::error::Error>> {
        // Direct-selection mode (b8 of P1 = 0). Offset 0x1234.
        const TEST_OFFSET: u16 = 0x1234;
        const TEST_LE: u8 = 64;
        let offset = ReadBinaryOffset::Direct(DirectOffset15::try_new(TEST_OFFSET)?);
        let cmd = ReadBinary {
            class: ApduClass::Plain,
            offset,
            le: TEST_LE,
        };
        assert_eq!(
            cmd.into_apdu().as_bytes(),
            expected_read_binary_wire(ApduClass::Plain, offset, TEST_LE),
        );
        // Sanity: P1 b8 must be 0 in direct mode.
        assert_eq!(offset.as_p1() & SFI_MODE_BIT, 0);
        Ok(())
    }

    #[test]
    fn read_binary_by_sfi() -> Result<(), Box<dyn core::error::Error>> {
        // SFI mode (b8 of P1 = 1). SFI=5, offset within EF=16.
        const TEST_SFI: u8 = 5;
        const TEST_OFFSET: u8 = 16;
        const TEST_LE: u8 = 32;
        let offset = ReadBinaryOffset::BySfi {
            sfi: Sfi::new(TEST_SFI)?,
            offset: TEST_OFFSET,
        };
        let cmd = ReadBinary {
            class: ApduClass::SecureMessaging,
            offset,
            le: TEST_LE,
        };
        assert_eq!(
            cmd.into_apdu().as_bytes(),
            expected_read_binary_wire(ApduClass::SecureMessaging, offset, TEST_LE),
        );
        // Sanity: P1 b8 must be 1 in SFI mode.
        assert_eq!(offset.as_p1() & SFI_MODE_BIT, SFI_MODE_BIT);
        Ok(())
    }

    #[test]
    fn direct_offset15_rejects_above_15_bit_cap() {
        // Anything above 0x7FFF must be rejected.
        const ABOVE_CAP: u16 = 0x8000;
        let err = DirectOffset15::try_new(ABOVE_CAP).expect_err("offset above 0x7FFF is rejected");
        assert_eq!(
            err,
            DirectOffset15Error::OutOfRange {
                got: ABOVE_CAP,
                max: DirectOffset15::MAX,
            }
        );
    }

    #[test]
    fn direct_offset15_accepts_boundary_values() -> Result<(), Box<dyn core::error::Error>> {
        // 0 and MAX both allowed.
        let _zero = DirectOffset15::try_new(0)?;
        let _max = DirectOffset15::try_new(DirectOffset15::MAX)?;
        Ok(())
    }
}
