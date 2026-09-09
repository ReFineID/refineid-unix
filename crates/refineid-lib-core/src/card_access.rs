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

//! `EF.CardAccess` reader + parser.
//!
//! `EF.CardAccess` (FID `011C`) sits directly under MF and is
//! readable on the plain contact interface (no PACE / SM
//! required). It carries the `SecurityInfos` `SET OF
//! SecurityInfo` that tell the terminal which PACE protocol
//! variant + domain parameters the card supports.
//!
//! ICAO 9303-11 §9 / BSI TR-03110-3 §A.1.1.4.

use crate::ber::{BerTlv, BerTlvAny, BerTlvIter, Integer, Oid, Sequence, Set};
use crate::pkcs15::{Pkcs15Error, Pkcs15Ops as _, TxError};
use crate::transport::CardTransport;

/// `EF.CardAccess` reader layered as a default-impl method on
/// every [`CardTransport`]. Same pattern as
/// [`crate::pkcs15::Pkcs15Ops`] / [`crate::auth::PinOps`] /
/// [`crate::sign::SignOps`].
pub trait CardAccessOps: CardTransport {
    /// Read + parse `EF.CardAccess` from the card.
    ///
    /// Requires plain (non-SM) transport. Should be called
    /// *before* any PACE / SM is established; the file is
    /// publicly readable.
    ///
    /// # Errors
    /// SELECT / READ BINARY failure, a non-existent
    /// `EF.CardAccess`, or [`Pkcs15Error::InvalidData`] when the
    /// file's bytes don't decode as a `SET OF SecurityInfo` per
    /// ICAO 9303-11 §9.2.  The `InvalidData` variant is distinct
    /// from `Empty` (zero-byte read) and `Sw` (card rejected the
    /// read) so the caller can branch on the specific failure
    /// mode rather than seeing a defaulted empty value.
    fn read_card_access(&mut self) -> Result<CardAccess, Pkcs15Error<TxError<Self>>>
    where
        Self: Sized,
    {
        self.select_mf()?;
        self.select_ef(EF_CARD_ACCESS_FID)?;
        let bytes = self.read_binary_der_object("EF.CardAccess")?;
        CardAccess::parse(&bytes).map_err(|e| Pkcs15Error::InvalidData(e.as_static_str()))
    }
}

impl<T: CardTransport + ?Sized> CardAccessOps for T {}

/// FID of `EF.CardAccess` under MF.
pub const EF_CARD_ACCESS_FID: [u8; 2] = [0x01, 0x1C];

/// A PACE protocol we recognize and support, identified by its
/// `protocol` OID (BSI TR-03110-3 §A.6.2,
/// `0.4.0.127.0.7.2.2.4.{2,4}.{n}`).
///
/// This is a **closed** set: `PaceProtocol::from_oid` returns
/// `None` for any other OID, and `CardAccess::parse` turns that
/// into a hard [`CardAccessError::UnsupportedProtocol`]. We do
/// not keep the raw OID bytes of protocols we don't model -- an
/// EF.CardAccess advertising one is an unsupported card, surfaced
/// loudly, not data carried forward un-named. The identity (which
/// PACE variant) is the type; there is no `&[u8]` leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaceProtocol {
    /// `id-PACE-ECDH-GM-AES-CBC-CMAC-128`.
    EcdhGmAesCbcCmac128,
    /// `id-PACE-ECDH-GM-AES-CBC-CMAC-192`.
    EcdhGmAesCbcCmac192,
    /// `id-PACE-ECDH-GM-AES-CBC-CMAC-256` (the FINEID S4-2
    /// published variant).
    EcdhGmAesCbcCmac256,
    /// `id-PACE-ECDH-CAM-AES-CBC-CMAC-128`.
    EcdhCamAesCbcCmac128,
    /// `id-PACE-ECDH-CAM-AES-CBC-CMAC-256`.
    EcdhCamAesCbcCmac256,
}

impl PaceProtocol {
    /// Recognize a PACE protocol from its OID *value* bytes (no
    /// tag, no length). `None` for any OID outside the supported
    /// set -- the caller rejects it.
    #[must_use]
    fn from_oid(oid: &[u8]) -> Option<Self> {
        // 0.4.0.127.0.7.2.2.4.{2,6}.<n> -- BSI TR-03110-3 §A.1.1.1:
        // the mapping arc is 2 for ECDH-GM and 6 for ECDH-CAM (4 is
        // ECDH-IM, which we do not support). A production FINEID
        // card's EF.CardAccess advertises both GM-256 (...4.2.4) and
        // CAM-256 (...4.6.4); an earlier revision of this table had
        // CAM on the IM arc and hard-rejected that real file.
        match oid {
            [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02] => {
                Some(Self::EcdhGmAesCbcCmac128)
            }
            [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x03] => {
                Some(Self::EcdhGmAesCbcCmac192)
            }
            [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04] => {
                Some(Self::EcdhGmAesCbcCmac256)
            }
            [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x02] => {
                Some(Self::EcdhCamAesCbcCmac128)
            }
            [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x04] => {
                Some(Self::EcdhCamAesCbcCmac256)
            }
            _ => None,
        }
    }

    /// Short `id-PACE-...` name, for diagnostic display. Total --
    /// the enum is closed, so there is no `"<unknown>"` case.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::EcdhGmAesCbcCmac128 => "id-PACE-ECDH-GM-AES-CBC-CMAC-128",
            Self::EcdhGmAesCbcCmac192 => "id-PACE-ECDH-GM-AES-CBC-CMAC-192",
            Self::EcdhGmAesCbcCmac256 => "id-PACE-ECDH-GM-AES-CBC-CMAC-256",
            Self::EcdhCamAesCbcCmac128 => "id-PACE-ECDH-CAM-AES-CBC-CMAC-128",
            Self::EcdhCamAesCbcCmac256 => "id-PACE-ECDH-CAM-AES-CBC-CMAC-256",
        }
    }
}

/// One `PACEInfo` entry from `EF.CardAccess`:
/// `PACEInfo ::= SEQUENCE { protocol OID, version INTEGER,
/// parameterId INTEGER OPTIONAL }` (ICAO 9303-11 §9.2 / BSI
/// TR-03110-3 §A.1.1.1).
///
/// Every field is typed; nothing raw is retained. `parameter_id`
/// stays an `Option<u32>` because it is a spec-defined optional
/// integer *reference* into the domain-parameter registry, not
/// raw bytes -- and nothing in the product consumes it (the PACE
/// driver hardcodes brainpoolP384r1; see `crate::pace`). It is
/// diagnostic metadata; the moment a code path *acts* on it, it
/// gets a typed domain-parameter enum, not before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaceSecurityInfo {
    /// The supported PACE protocol variant.
    pub protocol: PaceProtocol,
    /// Protocol version per BSI TR-03110-2 §A.1.1.1 -- usually `2`.
    pub version: u32,
    /// `parameterId` referencing the curve / MODP group; `None`
    /// when the PACE info omits it (the field is OPTIONAL).
    pub parameter_id: Option<u32>,
}

impl PaceSecurityInfo {
    /// Friendly curve / group name for `parameter_id`, for
    /// diagnostic display. `"<absent>"` when the optional field
    /// is omitted.
    #[must_use]
    pub fn parameter_label(&self) -> &'static str {
        self.parameter_id.map_or("<absent>", pace_parameter_label)
    }
}

/// Every accepted `PACEInfo` entry from a card's `EF.CardAccess`.
///
/// Holds *only* PACE entries: `CardAccess::parse` rejects any
/// `SecurityInfo` whose protocol we don't model rather than
/// carrying it, so an existing `CardAccess` is proof that every
/// entry it holds is a recognized PACE protocol.
#[derive(Debug, Clone, Default)]
pub struct CardAccess {
    /// `PACEInfo` entries in the order they appear in the SET.
    pub security_infos: Vec<PaceSecurityInfo>,
}

// `read_card_access` is a method on [`CardAccessOps`]; see the
// trait definition above.

/// Why an `EF.CardAccess` blob failed to decode as a
/// `SET OF SecurityInfo` per ICAO 9303-11 §9.2.
///
/// Promotes the former `Option` return of `CardAccess::parse`
/// so "malformed" is a *distinct, described* failure rather than
/// the same `None` the absent-file case would produce -- see
/// `doc/security/der-trust-boundary.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardAccessError {
    /// The outer TLV is neither a SET nor a SEQUENCE, or is
    /// itself malformed BER (truncated, unsupported length form,
    /// no tag byte). Carries the underlying decoder error.
    NotSetOrSequence(crate::ber::BerError),
    /// A well-formed leading TLV is followed by undeclared
    /// trailing bytes (`outer.size != der.len()`). Per ICAO
    /// 9303-11 §9.2 a valid file is a single outer TLV that fills
    /// the file, so trailing bytes signal a card-side bug rather
    /// than data to silently drop.
    TrailingBytes,
    /// A `SecurityInfo` entry was malformed BER (not a SEQUENCE,
    /// or its OID / version field was missing the right tag or
    /// encoding). Carries the underlying decoder error.
    MalformedSecurityInfo(crate::ber::BerError),
    /// A `SecurityInfo` SEQUENCE was structurally incomplete -- a
    /// required `PACEInfo` field (`protocol` OID or `version`)
    /// was absent.
    IncompletePaceInfo,
    /// No `SecurityInfo` entry advertised a `protocol` OID
    /// inside the supported [`PaceProtocol`] set. Individual
    /// unsupported entries are skipped without retaining a byte
    /// (spec-legal siblings share the SET per ICAO 9303-11
    /// s9.2); this error means the whole file offered nothing
    /// this implementation can run, surfaced loudly per the
    /// "no speculative support, no just-in-case data" rule in
    /// `doc/typing-discipline.md`.
    UnsupportedProtocol,
}

impl CardAccessError {
    /// A `&'static str` summary for surfacing through
    /// [`Pkcs15Error::InvalidData`] (which carries a static
    /// label, not an owned message).
    #[must_use]
    pub const fn as_static_str(self) -> &'static str {
        match self {
            Self::NotSetOrSequence(_) => "EF.CardAccess: outer TLV not a SET/SEQUENCE",
            Self::TrailingBytes => "EF.CardAccess: trailing bytes past outer TLV",
            Self::MalformedSecurityInfo(_) => "EF.CardAccess: malformed SecurityInfo entry",
            Self::IncompletePaceInfo => "EF.CardAccess: incomplete PACEInfo entry",
            Self::UnsupportedProtocol => "EF.CardAccess: unsupported PACE protocol OID",
        }
    }
}

impl CardAccess {
    /// Validating constructor: parse raw `EF.CardAccess` bytes
    /// (as read from MF's `011C`) into a typed `CardAccess`. This
    /// *is* the trust boundary -- the card hands raw bytes and
    /// there is no earlier validation; construction and validation
    /// are the same step, so there is no unvalidated `CardAccess`
    /// value to misuse.
    ///
    /// `der` is borrowed because the result owns everything it
    /// keeps; the bytes need not outlive the call. The raw
    /// `&[u8]` here is the sanctioned validation-boundary carve-out
    /// (see `doc/typing-discipline.md` Rule B / the typing-grep
    /// register), not a leak -- the single door, on the validated
    /// type itself.
    ///
    /// Returns [`CardAccessError`] on malformed input (wrong
    /// outer tag, truncated length, trailing garbage past the
    /// outer TLV); the caller surfaces that as
    /// [`Pkcs15Error::InvalidData`]. A described error --
    /// distinct from the caller's "file absent" path -- is the
    /// boundary tightening over the former `Option`.
    ///
    /// Trailing-byte handling: a well-formed EF.CardAccess is a
    /// single outer TLV whose declared length matches the file
    /// size. We require `outer_tlv.size == der.len()` so a card
    /// that returns a valid leading TLV followed by extra bytes
    /// is classified as [`CardAccessError::TrailingBytes`] -- the
    /// trailing bytes carry no defined semantic per ICAO 9303-11
    /// §9.2 and silently dropping them would mask a card-side bug.
    pub(crate) fn parse(der: &[u8]) -> Result<Self, CardAccessError> {
        // Spec says SET OF, but some cards write SEQUENCE OF.
        // Accept either: try SET first, then SEQUENCE. The child
        // value bytes are identical in both shapes.
        let (outer_size, outer_value) = if let Ok(t) = BerTlv::<Set>::parse(der) {
            (t.size, t.value)
        } else {
            let t = BerTlv::<Sequence>::parse(der).map_err(CardAccessError::NotSetOrSequence)?;
            (t.size, t.value)
        };
        if outer_size != der.len() {
            return Err(CardAccessError::TrailingBytes);
        }
        let mut out = Self::default();
        for entry in BerTlvIter::new(outer_value) {
            // Every entry must be a structurally well-formed
            // SecurityInfo SEQUENCE. An entry whose protocol OID
            // is outside the supported PACE set is a spec-legal
            // sibling (ICAO 9303-11 s9.2 registers
            // ChipAuthenticationInfo, PACE-CAM, and more in the
            // same SET): it is skipped without retaining a byte --
            // no Other arm, no stashed OID -- so the cardinal
            // rule's no-junk-drawer posture holds while a card
            // that also advertises a supported protocol stays
            // usable. Field-forced 2026-08-12: the old-generation
            // card's EF.CardAccess carries an entry whose protocol
            // OID is outside the supported set, and rejecting the
            // whole file over it made the card unreadable over
            // PC/SC contactless.
            let entry = entry.map_err(CardAccessError::MalformedSecurityInfo)?;
            let entry = entry
                .expect::<Sequence>()
                .map_err(CardAccessError::MalformedSecurityInfo)?;
            match PaceSecurityInfo::parse(entry.value) {
                Ok(info) => out.security_infos.push(info),
                Err(CardAccessError::UnsupportedProtocol) => {}
                Err(e) => return Err(e),
            }
        }
        // A file with no supported protocol still fails loudly --
        // the unsupported card surfaces as an error, not as an
        // empty success.
        if out.security_infos.is_empty() {
            return Err(CardAccessError::UnsupportedProtocol);
        }
        Ok(out)
    }
}

/// Helpers hosted on a unit struct (typing-discipline: no
/// free fns with borrowed parameters; see
/// `doc/typing-discipline.md`).
struct CardAccessHelpers;

impl PaceSecurityInfo {
    /// Decode one `SecurityInfo` SEQUENCE body (the bytes inside
    /// the outer SEQUENCE tag) into a typed [`PaceSecurityInfo`].
    ///
    /// ICAO 9303 Part 11 §9.2 -- `SecurityInfo ::= SEQUENCE {
    /// protocol OBJECT IDENTIFIER, requiredData ANY, optionalData
    /// ANY OPTIONAL }`, here required to be a `PACEInfo`.
    ///
    /// **Rejects** anything that is not a supported `PACEInfo`:
    /// malformed BER -> [`CardAccessError::MalformedSecurityInfo`],
    /// missing required field -> [`CardAccessError::IncompletePaceInfo`],
    /// an OID outside [`PaceProtocol`] ->
    /// [`CardAccessError::UnsupportedProtocol`]. We do **not**
    /// retain bytes for protocols we don't model -- see the
    /// "no speculative support, no just-in-case data" rule in
    /// `doc/typing-discipline.md`.
    fn parse(body: &[u8]) -> Result<Self, CardAccessError> {
        let mut it = BerTlvIter::new(body);
        // protocol OBJECT IDENTIFIER -- required.
        let oid_tlv = it
            .next()
            .ok_or(CardAccessError::IncompletePaceInfo)?
            .map_err(CardAccessError::MalformedSecurityInfo)?
            .expect::<Oid>()
            .map_err(CardAccessError::MalformedSecurityInfo)?;
        let protocol =
            PaceProtocol::from_oid(oid_tlv.value).ok_or(CardAccessError::UnsupportedProtocol)?;
        // version INTEGER -- required.
        let version_tlv = it
            .next()
            .ok_or(CardAccessError::IncompletePaceInfo)?
            .map_err(CardAccessError::MalformedSecurityInfo)?
            .expect::<Integer>()
            .map_err(CardAccessError::MalformedSecurityInfo)?;
        let version = CardAccessHelpers::u32_be(version_tlv.value);
        // parameterId INTEGER -- OPTIONAL; absent is legal.
        let parameter_id = it
            .next()
            .and_then(Result::ok)
            .and_then(|any: BerTlvAny<'_>| any.expect::<Integer>().ok())
            .map(|t| CardAccessHelpers::u32_be(t.value));
        Ok(Self {
            protocol,
            version,
            parameter_id,
        })
    }
}

impl CardAccessHelpers {
    /// Big-endian byte slice -> `u32`, saturating at the high
    /// bits if the input is wider than 4 bytes.
    fn u32_be(bytes: &[u8]) -> u32 {
        let mut v: u32 = 0;
        for &b in bytes {
            v = (v << 8_u32) | u32::from(b);
        }
        v
    }
}

/// Map a PACE `parameterId` byte to its named curve / group
/// (BSI TR-03110-3 §A.6.6.1 + FINEID's documented extension
/// at `0x10`).
const fn pace_parameter_label(id: u32) -> &'static str {
    match id {
        0..=7 => "GFP modp group",
        8 => "NIST P-192",
        9 => "BrainpoolP192r1",
        10 => "NIST P-224",
        11 => "BrainpoolP224r1",
        12 => "NIST P-256",
        13 => "BrainpoolP256r1",
        14 => "NIST P-384",
        15 => "BrainpoolP320r1",
        // Standardised values stop at 18; FINEID uses 16 (0x10)
        // for brainpoolP384r1 by empirical agreement with the
        // legacy iOS reader -- see crate::pace.
        16 => "BrainpoolP384r1 (FINEID convention)",
        17 => "BrainpoolP512r1",
        18 => "NIST P-521",
        _ => "<unknown>",
    }
}

#[cfg(test)]
mod tests {

    use super::{CardAccess, CardAccessError, PaceProtocol};
    use crate::ber::{BerTag as _, Integer, Oid, Sequence, Set};

    // BER universal-class tag bytes the fixture builders below
    // splat into Vec<u8>.  Derived from the BerTag marker impls
    // in `ber.rs` so the fixture wire shape stays in lockstep
    // with the parser the tests exercise -- if a future commit
    // changes one of these tag values, the synthetic blob the
    // tests build moves with it.
    //
    // BerTag::TAG is u16; the universal-class tags here all fit
    // in u8 (Set=0x31, Sequence=0x30, Oid=0x06, Integer=0x02).
    // `single_byte_tag` pins that invariant at compile time --
    // if a future BerTag is bumped to a multi-byte tag, these
    // const initialisers fail to compile rather than silently
    // truncating.
    const TAG_OID: u8 = single_byte_tag(Oid::TAG);
    const TAG_INTEGER: u8 = single_byte_tag(Integer::TAG);
    const TAG_SEQUENCE: u8 = single_byte_tag(Sequence::TAG);
    const TAG_SET: u8 = single_byte_tag(Set::TAG);

    /// Convert a `BerTag::TAG` (`u16`) to its single-byte wire form.
    /// Panics at compile time (when used in a const initialiser) if
    /// the tag does not fit in one byte.
    const fn single_byte_tag(tag: u16) -> u8 {
        let [high_byte, low_byte] = tag.to_be_bytes();
        assert!(high_byte == 0, "BER tag does not fit in a single byte");
        low_byte
    }

    // OID value bytes for `id-PACE-ECDH-GM-AES-CBC-CMAC-256`
    // (1.0.18013.5.1.0.0.4.2.4 -> 0.4.0.127.0.7.2.2.4.2.4 in
    // BSI's prefix tree).  Bare value -- no tag, no length
    // prefix.  Mirrors the entry at lines 210-212 of this file
    // where the protocol-label lookup recognises the same bytes.
    const OID_PACE_ECDH_GM_AES_CBC_CMAC_256: [u8; 10] =
        [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04];
    // PACEInfo version field: `2` is what BSI TR-03110-3 §A.1.1.1
    // mandates for the v2 protocol family this test pins.
    const PACE_VERSION: u8 = 2;
    // FINEID-S4-2 published PACE `parameterId`: 0x10 = 16 is the
    // non-standard alias for BrainpoolP384r1 documented at
    // crate::pace.
    const FINEID_PACE_PARAMETER_ID: u8 = 0x10;

    /// One supported `PACEInfo` `SecurityInfo` SEQUENCE (TLV bytes).
    fn supported_pace_security_info() -> Vec<u8> {
        // PACEInfo body = OID TLV || INTEGER(version) || INTEGER(parameterId)
        let oid_len =
            u8::try_from(OID_PACE_ECDH_GM_AES_CBC_CMAC_256.len()).expect("10-byte OID fits in u8");
        let oid_tlv: Vec<u8> = {
            let mut v = vec![TAG_OID, oid_len];
            v.extend_from_slice(&OID_PACE_ECDH_GM_AES_CBC_CMAC_256);
            v
        };
        let version_tlv: Vec<u8> = vec![TAG_INTEGER, 1, PACE_VERSION];
        let parameter_id_tlv: Vec<u8> = vec![TAG_INTEGER, 1, FINEID_PACE_PARAMETER_ID];

        let mut info_body = oid_tlv;
        info_body.extend_from_slice(&version_tlv);
        info_body.extend_from_slice(&parameter_id_tlv);

        let info_seq_len = u8::try_from(info_body.len()).expect("18-byte PACEInfo body fits in u8");
        let mut info_seq = vec![TAG_SEQUENCE, info_seq_len];
        info_seq.extend_from_slice(&info_body);
        info_seq
    }

    fn synthetic_pace_security_infos_set() -> Vec<u8> {
        let info_seq = supported_pace_security_info();
        let set_len = u8::try_from(info_seq.len()).expect("20-byte PACEInfo TLV fits in u8");
        let mut set = vec![TAG_SET, set_len];
        set.extend_from_slice(&info_seq);
        set
    }

    /// Synthetic `SecurityInfos` SET containing a single
    /// `PACEInfo` for `id-PACE-ECDH-GM-AES-CBC-CMAC-256` with
    /// `parameterId` 0x10 -- the FINEID-S4-2 published profile.
    #[test]
    fn parses_pace_info() {
        let set = synthetic_pace_security_infos_set();
        let ca = CardAccess::parse(&set).expect("parses");
        assert_eq!(ca.security_infos.len(), 1);
        let info = &ca.security_infos[0];
        assert_eq!(info.protocol, PaceProtocol::EcdhGmAesCbcCmac256);
        assert_eq!(info.protocol.label(), "id-PACE-ECDH-GM-AES-CBC-CMAC-256");
        assert_eq!(info.version, 2);
        assert_eq!(info.parameter_id, Some(16));
        assert_eq!(
            info.parameter_label(),
            "BrainpoolP384r1 (FINEID convention)"
        );
    }

    /// Parse a production FINEID card's real `EF.CardAccess`,
    /// captured over the contactless interface (ACR1581 PICC,
    /// 2026-07-24): two `PACEInfo` entries, GM-256 and CAM-256,
    /// both v2 on parameter 0x10 (`BrainpoolP384r1`). The bytes are
    /// public protocol parameters; nothing card- or person-
    /// identifying is in them.
    ///
    /// Regression: the CAM `from_oid` arms originally sat on the
    /// ECDH-IM arc (`...2.2.4.4.<n>`) instead of the ECDH-CAM arc
    /// (`...2.2.4.6.<n>`, BSI TR-03110-3 §A.1.1.1), so this real
    /// file -- whose second entry is `...2.2.4.6.4` -- was hard-
    /// rejected as `UnsupportedProtocol`. That made every
    /// CardAccess-probing flow fail against the actual card.
    #[test]
    fn parses_production_fineid_card_access_capture() {
        let der = hex::decode(concat!(
            "31283012060a04007f00070202040204020102020110",
            "3012060a04007f00070202040604020102020110",
        ))
        .expect("capture hex decodes");
        let ca = CardAccess::parse(&der).expect("real EF.CardAccess parses");
        assert_eq!(ca.security_infos.len(), 2);
        assert_eq!(
            ca.security_infos[0].protocol,
            PaceProtocol::EcdhGmAesCbcCmac256
        );
        assert_eq!(
            ca.security_infos[1].protocol,
            PaceProtocol::EcdhCamAesCbcCmac256
        );
        for info in &ca.security_infos {
            assert_eq!(info.version, 2);
            assert_eq!(info.parameter_id, Some(16));
        }
    }

    /// Pin the BSI TR-03110-3 §A.6.6.1 "Standardized Domain
    /// Parameters" table against [`pace_parameter_label`].
    ///
    /// This test is the mechanical guardrail for the mapping a
    /// recent AI-suggested PR tried to change (specifically
    /// rewriting `15 => BrainpoolP320r1` to
    /// `15 => BrainpoolP384r1`, which would have collapsed two
    /// distinct standardised IDs onto one label and silently
    /// broken every cert reader keyed on the brainpoolP320r1
    /// curve).  The doc-comment citation directly above
    /// `pace_parameter_label` was not enough to prevent that
    /// proposal; this test makes the spec violation a hard
    /// build failure -- tests beat comments.
    ///
    /// IDs 8-18 are the BSI-standardised range; 16 carries the
    /// FINEID-specific alias so the test also pins that
    /// non-standard mapping per `crate::pace`.
    #[test]
    fn pace_parameter_label_pins_bsi_tr_03110_a_6_6_1_table() {
        use super::pace_parameter_label;
        // GFP modp group identifiers (0..=7): collapsed to one
        // label by the implementation; we pin a representative
        // sample rather than the whole range.
        assert_eq!(pace_parameter_label(0), "GFP modp group");
        assert_eq!(pace_parameter_label(7), "GFP modp group");
        // ECP standardised range from BSI TR-03110-3 §A.6.6.1:
        assert_eq!(pace_parameter_label(8), "NIST P-192");
        assert_eq!(pace_parameter_label(9), "BrainpoolP192r1");
        assert_eq!(pace_parameter_label(10), "NIST P-224");
        assert_eq!(pace_parameter_label(11), "BrainpoolP224r1");
        assert_eq!(pace_parameter_label(12), "NIST P-256");
        assert_eq!(pace_parameter_label(13), "BrainpoolP256r1");
        assert_eq!(pace_parameter_label(14), "NIST P-384");
        // ID 15 is BrainpoolP320r1 in the spec.  Do NOT change to
        // BrainpoolP384r1 -- that is the standard mapping for 16
        // (or, in FINEID's case, the non-standard alias on 16).
        assert_eq!(pace_parameter_label(15), "BrainpoolP320r1");
        // ID 16 is FINEID's non-standard alias for BrainpoolP384r1
        // (BSI standardises 16 as BrainpoolP384r1 in some tables;
        // the FINEID-published cards use 16 by empirical agreement
        // with the legacy iOS reader -- see crate::pace).
        assert_eq!(
            pace_parameter_label(16),
            "BrainpoolP384r1 (FINEID convention)"
        );
        assert_eq!(pace_parameter_label(17), "BrainpoolP512r1");
        assert_eq!(pace_parameter_label(18), "NIST P-521");
        // Sentinel for any IDs the spec does not standardise.
        assert_eq!(pace_parameter_label(19), "<unknown>");
        assert_eq!(pace_parameter_label(255), "<unknown>");
    }

    /// Pin the no-junk-drawer contract: a file whose only
    /// `SecurityInfo` advertises an unsupported `protocol` OID
    /// fails with [`CardAccessError::UnsupportedProtocol`] --
    /// nothing usable remains -- and no raw bytes are retained.
    ///
    /// This is the regression guard for the cardinal rule: we
    /// make features / parse data we *need*. We do not keep an
    /// `Other`/`Unknown` arm of un-named bytes "just in case."
    /// An earlier version of this parser had exactly such an
    /// arm; this test exists so no future agent re-introduces
    /// one. Unsupported entries beside a supported one are
    /// skipped, not fatal -- see
    /// `unsupported_sibling_is_skipped_without_retention` for
    /// the field-forced half of the contract.
    #[test]
    fn unsupported_protocol_oid_is_rejected_not_retained() {
        // OID value bytes for 1.2.3.4 -- a deliberately
        // unsupported protocol OID (`1.2` packs to 0x2A = 1*40+2,
        // then `.3 .4`). `PaceProtocol::from_oid` maps no PACE
        // variant to it. Bare value -- no tag, no length -- same
        // shape as `OID_PACE_ECDH_GM_AES_CBC_CMAC_256` above.
        const UNSUPPORTED_PROTOCOL_OID: [u8; 3] = [0x2A, 0x03, 0x04];

        // SecurityInfo SEQUENCE carrying just that OID. The parser
        // rejects on the OID alone -- it never reaches a version /
        // parameterId field, so no payload is needed here.
        let oid_len = u8::try_from(UNSUPPORTED_PROTOCOL_OID.len()).expect("3-byte OID fits in u8");
        let mut info_seq_body = vec![TAG_OID, oid_len];
        info_seq_body.extend_from_slice(&UNSUPPORTED_PROTOCOL_OID);

        let info_seq_len =
            u8::try_from(info_seq_body.len()).expect("5-byte SecurityInfo body fits in u8");
        let mut info_seq = vec![TAG_SEQUENCE, info_seq_len];
        info_seq.extend_from_slice(&info_seq_body);

        let set_len = u8::try_from(info_seq.len()).expect("7-byte SecurityInfo TLV fits in u8");
        let mut set = vec![TAG_SET, set_len];
        set.extend_from_slice(&info_seq);

        assert_eq!(
            CardAccess::parse(&set).expect_err("unsupported protocol OID is rejected"),
            CardAccessError::UnsupportedProtocol,
            "an unsupported protocol OID must be rejected, never carried as raw bytes"
        );
    }

    /// Field-forced companion (2026-08-12): the old-generation
    /// card's EF.CardAccess pairs a supported PACE-GM entry with
    /// an ECDH-CAM entry this implementation does not run. The
    /// supported entry must survive, the unsupported sibling must
    /// vanish without a retained byte, and the file must parse.
    #[test]
    fn unsupported_sibling_is_skipped_without_retention() {
        const UNSUPPORTED_PROTOCOL_OID: [u8; 3] = [0x2A, 0x03, 0x04];
        let oid_len = u8::try_from(UNSUPPORTED_PROTOCOL_OID.len()).expect("3-byte OID fits in u8");
        let mut unsupported_body = vec![TAG_OID, oid_len];
        unsupported_body.extend_from_slice(&UNSUPPORTED_PROTOCOL_OID);
        let unsupported_len =
            u8::try_from(unsupported_body.len()).expect("SecurityInfo body fits in u8");
        let mut unsupported_seq = vec![TAG_SEQUENCE, unsupported_len];
        unsupported_seq.extend_from_slice(&unsupported_body);

        let supported_seq = supported_pace_security_info();

        let set_body_len = u8::try_from(
            supported_seq
                .len()
                .checked_add(unsupported_seq.len())
                .expect("small test TLVs"),
        )
        .expect("SET body fits in u8");
        let mut set = vec![TAG_SET, set_body_len];
        set.extend_from_slice(&supported_seq);
        set.extend_from_slice(&unsupported_seq);

        let parsed = CardAccess::parse(&set).expect("supported entry keeps the file usable");
        assert_eq!(
            parsed.security_infos.len(),
            1,
            "exactly the supported entry survives; the unsupported sibling is not retained"
        );
    }

    /// Pin the "trailing bytes -> malformed" contract that the
    /// outer-TLV size check in [`CardAccess::parse`] enforces.
    ///
    /// A well-formed EF.CardAccess is a single outer TLV whose
    /// declared length matches the file size; trailing garbage
    /// past the outer TLV is undefined per ICAO 9303-11 §9.2.
    /// Earlier versions of the parser used `BerTlv::<Set>::parse(der)`
    /// directly, which accepts a valid leading TLV without
    /// checking full consumption -- a card returning
    /// `[valid SET TLV][garbage]` was classified as well-formed
    /// (Codex review on PR #9 surfaced this).  This test pins
    /// the tightened contract: trailing bytes =>
    /// `CardAccessError::TrailingBytes` =>
    /// `Pkcs15Error::InvalidData` at the caller.
    #[test]
    fn parse_card_access_rejects_trailing_bytes_past_outer_tlv() {
        // Reuse the same synthetic SET as `parses_pace_info` --
        // a single byte of trailing garbage past the outer TLV's
        // declared length boundary is the only difference.  The
        // exact tail byte value doesn't matter; 0xAA is a
        // visually distinctive sentinel.
        const TRAILING_GARBAGE_SENTINEL: u8 = 0xAA;

        let mut set = synthetic_pace_security_infos_set();
        set.push(TRAILING_GARBAGE_SENTINEL);

        assert_eq!(
            CardAccess::parse(&set).expect_err("trailing garbage is rejected"),
            CardAccessError::TrailingBytes,
            "trailing garbage past the outer SET TLV must classify as malformed"
        );
    }
}
