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

//! PKCS#15 file-system access on the FINEID card.
//!
//! Layered on top of any [`CardTransport`] -- typically an
//! `SmTransport` once PACE has produced session keys, but plain
//! transports work too on the contact interface (the cert files
//! are not PIN-protected and need no secure messaging).
//!
//! Operations:
//!
//! - `select_pkcs15_application` -- `00 A4 04 0C` with the PKCS#15
//!   AID `A0 00 00 00 63 50 4B 43 53 2D 31 35` (ASCII `"PKCS-15"`
//!   with a 5-byte international prefix). Lands the current DF on
//!   the PKCS#15 application.
//! - `select_ef` -- `00 A4 02 0C` with a 2-byte file ID. Used to
//!   select EF.4331 (the authentication certificate) and friends.
//! - `read_binary_to_end` -- drives `00 B0 P1 P2 80` reads in
//!   128-byte chunks until the card returns a short read or
//!   `SW=6282` (EOF marker) -- the standard PKCS#15 "read until
//!   done" pattern.
//! - `read_authentication_certificate` -- composes the three
//!   above: SELECT PKCS#15, SELECT EF.4331, read the X.509 DER blob.
//!
use crate::apdu::iso7816::{
    ApduClass, FileId, ReadBinaryByOffset, SelectByAidNoFci, SelectEfNoFci, SelectFile,
    SelectFileResponseMode, SelectFileTarget,
};
use crate::apdu::primitives::{Aid, AidError};
use crate::apdu::status_word::StatusWord;
use crate::transport::{CardTransport, TransportDispatchError};

/// Convenience alias for [`TransportDispatchError`] specialised to
/// a [`CardTransport`] implementation's own error type.
pub type TxError<T> = TransportDispatchError<<T as CardTransport>::Error>;

/// `A0 00 00 00 63 50 4B 43 53 2D 31 35` -- the PKCS#15 application
/// identifier the FINEID card publishes per FINEID S4-2 §3.1.
pub const PKCS15_AID: &[u8] = &[
    0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35,
];

// Compile-time guard: catches accidental edits that take
// `PKCS15_AID` outside the ISO 7816-5 length range. The runtime
// `Aid::from_slice` check inside `select_pkcs15_application`
// becomes statically provable -- the `.expect(...)` there
// documents an invariant that this assertion enforces at
// compile time.
const _: () = assert!(
    PKCS15_AID.len() >= 5 && PKCS15_AID.len() <= 16,
    "PKCS15_AID must satisfy ISO 7816-5 AID length range 5..=16"
);

/// File IDs FINEID S4-2 publishes for the public certificates.
///
/// The layout was verified empirically against an EF.CD #1 read
/// of a v3.1 reference card. Algorithm (RSA vs ECC) varies by card -- the
/// algorithm shown for each slot is what production v3.1 cards
/// carry today, but we don't hardcode the assumption; the
/// caller parses the cert DER to discover the real key alg.
/// `EF.4331` authentication certificate file ID.
pub const EF_AUTH_CERT_FID: [u8; 2] = [0x43, 0x31];
/// `EF.4332` qualified-signature certificate file ID.
pub const EF_SIGN_CERT_FID: [u8; 2] = [0x43, 0x32];
/// `EF.4333` second authentication slot (typically ECC on
/// dual-algorithm cards).
pub const EF_AUTH_CERT_ALT_FID: [u8; 2] = [0x43, 0x33];
/// `EF.4334` on-card root CA certificate file ID. Lives directly
/// under MF, not under `DF.5016`.
pub const EF_ROOT_CA_FID: [u8; 2] = [0x43, 0x34];
/// `EF.4335` second qualified-signature slot
/// ("allekirjoitusvarmenne 2", typically ECC).
pub const EF_SIGN_CERT_ALT_FID: [u8; 2] = [0x43, 0x35];
/// `EF.4336` on-card issuing intermediate CA certificate file ID.
///
/// `DVV Citizen Certificates - G4E` (ECC, signed by the G3 ECC
/// root); lives directly under MF, like the root CA. Read=ALW.
/// Published alongside the leaf so a TLS client sends the
/// `leaf -> G4E` chain and the system can match the server's
/// accepted-CA hint (FINEID S2 §5.1, S4-1 v4.2 §8.1.16).
pub const EF_ISSUING_CA_ECC_FID: [u8; 2] = [0x43, 0x36];
/// PKCS#15 `EF.TokenInfo` -- card label / manufacturer / serial.
pub const EF_TOKEN_INFO_FID: [u8; 2] = [0x50, 0x32];

/// Where a slot lives in the card's file tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotPath {
    /// Direct child of the PKCS#15 application DF.
    UnderPkcs15App,
    /// Lives under `MF / 5016`.
    UnderDf5016,
    /// Lives directly under MF.
    UnderMf,
}

/// One slot in the FINEID certificate directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertSlot {
    /// Authentication certificate (`EF.4331`) -- TLS client cert,
    /// S/MIME signing, suomi.fi-tunnistus. RSA on current cards.
    Authentication,
    /// Qualified-signature certificate (`EF.4332`) -- eIDAS
    /// qualified electronic signatures. RSA on current cards.
    Signature,
    /// Second authentication slot (`EF.4333`) -- typically the
    /// ECC counterpart to `EF.4331` on dual-algorithm cards, but
    /// the algorithm isn't fixed by the slot; parse the cert
    /// DER to see what's actually there.
    AuthenticationAlt,
    /// On-card copy of the issuing root CA (`EF.4334`). Lives
    /// directly under MF, not under `DF 5016`. Useful when
    /// verifying the chain offline. DVV's current G3 root in the
    /// field is RSA 4096; algorithm varies by card generation.
    RootCa,
    /// Second qualified-signature slot (`EF.4335`,
    /// "allekirjoitusvarmenne 2") -- typically the ECC
    /// counterpart to `EF.4332`.
    SignatureAlt,
    /// On-card issuing intermediate CA (`EF.4336`,
    /// `DVV Citizen Certificates - G4E`, ECC). Lives under MF.
    /// The cert that chains the citizen auth leaf up to the G3
    /// ECC root; read it to publish the leaf->G4E chain.
    IssuingCaEcc,
}

impl CertSlot {
    /// Project this slot to its 2-byte file ID (`EF.4331` etc.).
    /// The lookup feeds [`SelectEfNoFci::fid`].
    #[must_use]
    #[inline]
    pub const fn fid(self) -> [u8; 2] {
        match self {
            Self::Authentication => EF_AUTH_CERT_FID,
            Self::Signature => EF_SIGN_CERT_FID,
            Self::AuthenticationAlt => EF_AUTH_CERT_ALT_FID,
            Self::RootCa => EF_ROOT_CA_FID,
            Self::SignatureAlt => EF_SIGN_CERT_ALT_FID,
            Self::IssuingCaEcc => EF_ISSUING_CA_ECC_FID,
        }
    }

    /// Human-readable label for the slot, used in report
    /// output and error messages.
    #[must_use]
    #[inline]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Authentication => "authentication (EF.4331)",
            Self::Signature => "qualified signature (EF.4332)",
            Self::AuthenticationAlt => "authentication, alt slot (EF.4333)",
            Self::RootCa => "on-card issuing root CA (EF.4334)",
            Self::SignatureAlt => "qualified signature, alt slot (EF.4335)",
            Self::IssuingCaEcc => "issuing intermediate CA, G4E ECC (EF.4336)",
        }
    }

    /// Directory location of this slot's EF on a FINEID S4-2
    /// card.
    ///
    /// FINEID S4-2 §3 splits the cert slots across three
    /// directories: the auth-cert sits directly under the
    /// PKCS#15 application (`5015`), signing certs and the
    /// alt slots live under DF `5016`, and the on-card root CA
    /// is under the MF. Drives the SELECT chain used by
    /// `CertSlot::find_in`.
    const fn path(self) -> SlotPath {
        match self {
            Self::Authentication => SlotPath::UnderPkcs15App,
            Self::Signature | Self::AuthenticationAlt | Self::SignatureAlt => SlotPath::UnderDf5016,
            Self::RootCa | Self::IssuingCaEcc => SlotPath::UnderMf,
        }
    }

    /// `true` when reaching this slot walks out to the MF.
    ///
    /// Matters over a PACE secure channel: selecting the MF
    /// tears the channel down on FINEID cards, so the next
    /// SM-wrapped command fails (`SW=0x6988`, SM data objects
    /// incorrect) and every command after that fails too
    /// (`SW=0x6999`). Contactless callers must therefore skip
    /// these slots -- reading one costs them the whole session,
    /// including the PIN counters they have not read yet.
    /// Measured on a production card over an ACR1581 PICC slot,
    /// 2026-07-24.
    ///
    /// Only [`CertSlot::Authentication`] stays inside the
    /// PKCS#15 application and is reachable under SM.
    #[must_use]
    #[inline]
    pub const fn requires_mf_traversal(self) -> bool {
        !matches!(self.path(), SlotPath::UnderPkcs15App)
    }

    /// All cert slots a FINEID S4-2 card *may* publish, in
    /// directory order. Callers probe each; absent slots return
    /// `SW=0x6A82` from the underlying SELECT, which higher
    /// layers should treat as "not provisioned" rather than an
    /// error.
    #[must_use]
    #[inline]
    pub const fn all() -> [Self; 5] {
        [
            Self::Authentication,
            Self::Signature,
            Self::AuthenticationAlt,
            Self::RootCa,
            Self::SignatureAlt,
        ]
    }
}

/// Maximum bytes per `READ BINARY` we ask for. The card's command
/// buffer is small; 128 is the chunk size the FINEID published
/// examples assume.
const READ_CHUNK: u8 = 0x80;

/// Hard cap on the cert size -- guards against runaway reads if
/// the card never returns a short response. FINEID auth certs are
/// approximately 1.5 KiB; a 16 KiB ceiling leaves room for future
/// variants.
const MAX_CERT_BYTES: usize = 0x4000;

/// Return the total encoded length of the single-byte-tag DER object
/// at the start of `prefix` once its complete length field is present.
///
/// This intentionally matches the bounded subset used by the current
/// Apple port: short-form lengths and long-form lengths containing one
/// or two octets. `Ok(None)` means the header is not complete yet;
/// `Err(())` means the length field is malformed.
fn der_object_total_length(prefix: &[u8]) -> Result<Option<usize>, ()> {
    const TAG_AND_FIRST_LENGTH_OCTET: usize = 2;
    const MAXIMUM_LENGTH_OCTETS: usize = 2;
    const LONG_FORM_MASK: u8 = 0x80;
    const LENGTH_COUNT_MASK: u8 = 0x7F;

    if prefix.len() < TAG_AND_FIRST_LENGTH_OCTET {
        return Ok(None);
    }
    let first = prefix[1];
    if first & LONG_FORM_MASK == 0 {
        return TAG_AND_FIRST_LENGTH_OCTET
            .checked_add(usize::from(first))
            .map(Some)
            .ok_or(());
    }

    let octet_count = usize::from(first & LENGTH_COUNT_MASK);
    if octet_count == 0 || octet_count > MAXIMUM_LENGTH_OCTETS {
        return Err(());
    }
    let header_len = TAG_AND_FIRST_LENGTH_OCTET
        .checked_add(octet_count)
        .ok_or(())?;
    if prefix.len() < header_len {
        return Ok(None);
    }

    let mut content_len = 0_usize;
    for byte in &prefix[TAG_AND_FIRST_LENGTH_OCTET..header_len] {
        content_len = content_len
            .checked_shl(8)
            .and_then(|length| length.checked_add(usize::from(*byte)))
            .ok_or(())?;
    }
    header_len.checked_add(content_len).map(Some).ok_or(())
}

/// Error returned from PKCS#15 cert reads and EF.TokenInfo
/// parses.
#[derive(Debug)]
pub enum Pkcs15Error<TE> {
    /// Transport-level failure (PC/SC error, USB I/O, etc.).
    Transport(TE),
    /// Card returned a non-success status word per ISO 7816-4
    /// §5.1.3. Tier 0 `u16` -- the typed projection is
    /// `StatusWord`; this variant carries the raw bytes for
    /// diagnostic visibility.
    Sw(u16),
    /// `Aid::from_slice` rejected an AID constant outside the ISO
    /// 7816-5 5..=16 length range. The module-level `const _: () =
    /// assert!(...)` makes this unreachable for `PKCS15_AID`, but
    /// the variant exists so the failure path is typed rather than
    /// a panic.
    Aid(AidError),
    /// Cert was empty or the read loop returned no bytes.
    Empty,
    /// Cert exceeded `MAX_CERT_BYTES`.
    TooLarge,
    /// A read-and-parse step received bytes the parser couldn't
    /// decode against its expected shape.  The `&'static str` is
    /// the human-readable element name (e.g. `"EF.CardAccess"`)
    /// so the operator-facing error message names the file that
    /// failed to parse rather than silently defaulting to an
    /// empty value.  Distinct from `Empty` (zero-byte read) and
    /// `Sw` (card rejected the read) so callers can branch on
    /// the specific failure mode.
    InvalidData(&'static str),
}

impl<TE: core::fmt::Display> core::fmt::Display for Pkcs15Error<TE> {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "PKCS#15 transport: {e}"),
            Self::Sw(sw) => write!(f, "PKCS#15: card returned SW={sw:#06X}"),
            Self::Aid(e) => write!(f, "PKCS#15: AID constant rejected by Aid::from_slice: {e}"),
            Self::Empty => write!(f, "PKCS#15: read returned no bytes"),
            Self::TooLarge => write!(f, "PKCS#15: cert exceeds {MAX_CERT_BYTES} bytes"),
            Self::InvalidData(what) => write!(f, "PKCS#15: malformed {what}"),
        }
    }
}

impl<TE: core::fmt::Debug + core::fmt::Display + 'static> core::error::Error for Pkcs15Error<TE> {}

/// PKCS#15 file-system operations layered as default-impl methods
/// on every [`CardTransport`].
///
/// Import via `use refineid_lib_core::pkcs15::Pkcs15Ops;`. See
/// `auth::PinOps` and `sign::SignOps` for the same pattern
/// applied to PIN and signing wire paths.
pub trait Pkcs15Ops: CardTransport {
    /// SELECT the PKCS#15 application by AID, no FCI returned
    /// (P2=0x0C).
    ///
    /// # Errors
    /// Transport-level failures or a non-success status word
    /// from the card.
    ///
    /// # Panics
    /// Never in practice. `PKCS15_AID` is a 12-byte compile-time
    /// constant; the [`Aid`] length-range invariant is satisfied
    /// by construction. The `expect` documents the proven
    /// invariant.
    ///
    /// [`Aid`]: Aid.
    #[inline]
    fn select_pkcs15_application(&mut self) -> Result<(), Pkcs15Error<TxError<Self>>>
    where
        Self: Sized,
    {
        // PKCS15_AID is a 12-byte compile-time constant proven in
        // the module-level `const _: () = assert!(...)` to lie in
        // the ISO 7816-5 length range; `Aid::from_slice` would only
        // reject on a length outside that range. Map the
        // unreachable AidError through Pkcs15Error::Aid so the path
        // stays fail-closed without an .expect() at the call site.
        let aid = Aid::from_slice(PKCS15_AID).map_err(Pkcs15Error::Aid)?;
        let apdu = SelectByAidNoFci { aid }.into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(Pkcs15Error::Transport)?;
        if !r.is_ok() {
            return Err(Pkcs15Error::Sw(r.sw()));
        }
        Ok(())
    }

    /// SELECT an EF by 2-byte file ID without response data.
    ///
    /// The current Apple implementation first tries P1=02
    /// (EF under current DF), then P1=00 (any file by ID).
    /// Both variants were established against real FINEID card
    /// generations and use P2=0C with no trailing Le.
    ///
    /// # Errors
    /// Transport-level failures or a non-success status word.
    #[inline]
    fn select_ef(&mut self, fid: [u8; 2]) -> Result<(), Pkcs15Error<TxError<Self>>>
    where
        Self: Sized,
    {
        let file_id = FileId::new(fid);
        let attempts = [
            SelectEfNoFci { fid }.into_apdu(),
            SelectFile {
                class: ApduClass::Plain,
                target: SelectFileTarget::AnyByFileId(Some(file_id)),
                response_mode: SelectFileResponseMode::None,
            }
            .into_apdu(),
        ];
        let mut last_sw = 0_u16;
        for apdu in attempts {
            let response = self
                .transmit(apdu.as_bytes())
                .map_err(Pkcs15Error::Transport)?;
            if response.is_ok() {
                return Ok(());
            }
            last_sw = response.sw();
        }
        Err(Pkcs15Error::Sw(last_sw))
    }

    /// SELECT MF (`3F00`). Tries `P1=0x00` then `P1=0x04` because
    /// FINEID variants disagree on which they accept after a
    /// deep-DF SELECT.
    ///
    /// # Errors
    /// Transport failure or a non-success status word.
    #[inline]
    fn select_mf(&mut self) -> Result<(), Pkcs15Error<TxError<Self>>>
    where
        Self: Sized,
    {
        let attempts: &[[u8; 7]] = &[
            [0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00],
            [0x00, 0xA4, 0x04, 0x0C, 0x02, 0x3F, 0x00],
        ];
        let mut last_sw: u16 = 0;
        for apdu in attempts {
            let r = self.transmit(apdu).map_err(Pkcs15Error::Transport)?;
            if r.is_ok() {
                return Ok(());
            }
            last_sw = r.sw();
        }
        Err(Pkcs15Error::Sw(last_sw))
    }

    /// SELECT a child DF under the current context. Helper for
    /// the slot-walk inside `read_certificate`.
    ///
    /// # Errors
    /// [`Pkcs15Error::Transport`] on wire-level failure,
    /// [`Pkcs15Error::Sw`] if the card rejected both the
    /// short-form (`P2=0x0C`) and the FCI-returning
    /// (`P2=0x00`) SELECT variants.
    #[inline]
    fn select_child_df(&mut self, fid: [u8; 2]) -> Result<(), Pkcs15Error<TxError<Self>>>
    where
        Self: Sized,
    {
        let variants: &[[u8; 7]] = &[
            [0x00, 0xA4, 0x01, 0x0C, 0x02, fid[0], fid[1]],
            [0x00, 0xA4, 0x00, 0x0C, 0x02, fid[0], fid[1]],
        ];
        let mut last_sw: u16 = 0;
        for apdu in variants {
            let r = self.transmit(apdu).map_err(Pkcs15Error::Transport)?;
            if r.is_ok() {
                return Ok(());
            }
            last_sw = r.sw();
        }
        Err(Pkcs15Error::Sw(last_sw))
    }

    /// `READ BINARY` in 128-byte chunks against the currently
    /// selected EF until EOF marker / short read / cap reached.
    ///
    /// # Errors
    /// Transport failures, non-success SW other than EOF, empty
    /// result, or a read exceeding `MAX_CERT_BYTES`.
    #[inline]
    fn read_binary_to_end(
        &mut self,
        expected_size: Option<usize>,
    ) -> Result<Vec<u8>, Pkcs15Error<TxError<Self>>>
    where
        Self: Sized,
    {
        let cap = expected_size.unwrap_or(MAX_CERT_BYTES).min(MAX_CERT_BYTES);
        let mut collected = Vec::with_capacity(cap.max(2048));
        let mut offset: usize = 0;
        // Loop bounds, fail-closed:
        //   cap <= MAX_CERT_BYTES (16 KiB) < u16::MAX -> offset fits
        //     in u16; if it ever wouldn't, .try_into bounces us out
        //     with TooLarge.
        //   cap - offset is always >= 0 inside `while offset < cap`;
        //     checked_sub guards the corner anyway.
        //   (remaining).min(READ_CHUNK as usize) is bounded by
        //     READ_CHUNK (u8), so the result fits in u8.
        while offset < cap {
            let remaining = cap.checked_sub(offset).ok_or(Pkcs15Error::TooLarge)?;
            let want_usize = remaining.min(usize::from(READ_CHUNK));
            let want = u8::try_from(want_usize).or(Err(Pkcs15Error::TooLarge))?;
            let offset_u16 = u16::try_from(offset).or(Err(Pkcs15Error::TooLarge))?;
            let apdu = ReadBinaryByOffset {
                offset: offset_u16,
                le: want,
            }
            .into_apdu();
            let r = self
                .transmit(apdu.as_bytes())
                .map_err(Pkcs15Error::Transport)?;
            let eof = matches!(r.status_word(), StatusWord::EndOfFile);
            if !r.is_ok() && !eof {
                return Err(Pkcs15Error::Sw(r.sw()));
            }
            let body_len = r.body.len();
            collected.extend_from_slice(&r.body);
            if body_len == 0 || body_len < usize::from(want) || eof {
                break;
            }
            offset = offset.checked_add(body_len).ok_or(Pkcs15Error::TooLarge)?;
        }
        if collected.is_empty() {
            return Err(Pkcs15Error::Empty);
        }
        if collected.len() > MAX_CERT_BYTES {
            return Err(Pkcs15Error::TooLarge);
        }
        Ok(collected)
    }

    /// Read exactly one DER object from the currently selected EF.
    ///
    /// The first chunk supplies the DER header. Once its declared total
    /// length is known, the last `READ BINARY` requests exactly the
    /// remaining bytes. This mirrors the current Apple implementation
    /// and avoids both padded-EF bytes and cards that reject an
    /// overlong final read instead of returning a partial body.
    ///
    /// # Errors
    /// Transport failure, unexpected status, malformed/truncated DER,
    /// an empty response, or a declared object above the 16 KiB cap.
    #[inline]
    fn read_binary_der_object(
        &mut self,
        what: &'static str,
    ) -> Result<Vec<u8>, Pkcs15Error<TxError<Self>>>
    where
        Self: Sized,
    {
        let mut collected = Vec::with_capacity(2048);
        let mut total_length: Option<usize> = None;

        loop {
            let cap = total_length.unwrap_or(MAX_CERT_BYTES);
            if collected.len() >= cap {
                collected.truncate(cap);
                return Ok(collected);
            }

            let remaining = cap
                .checked_sub(collected.len())
                .ok_or(Pkcs15Error::TooLarge)?;
            let want_usize = remaining.min(usize::from(READ_CHUNK));
            let want = u8::try_from(want_usize).or(Err(Pkcs15Error::TooLarge))?;
            let offset = u16::try_from(collected.len()).or(Err(Pkcs15Error::TooLarge))?;
            let apdu = ReadBinaryByOffset { offset, le: want }.into_apdu();
            let response = self
                .transmit(apdu.as_bytes())
                .map_err(Pkcs15Error::Transport)?;
            let eof = matches!(response.status_word(), StatusWord::EndOfFile);
            if !response.is_ok() && !eof {
                return Err(Pkcs15Error::Sw(response.sw()));
            }
            if response.body.len() > usize::from(want) {
                return Err(Pkcs15Error::InvalidData(what));
            }
            if response.body.is_empty() {
                return if collected.is_empty() {
                    Err(Pkcs15Error::Empty)
                } else {
                    Err(Pkcs15Error::InvalidData(what))
                };
            }

            let body_len = response.body.len();
            collected.extend_from_slice(&response.body);

            if total_length.is_none() {
                let parsed = der_object_total_length(&collected)
                    .map_err(|()| Pkcs15Error::InvalidData(what))?;
                if let Some(total) = parsed {
                    if total > MAX_CERT_BYTES {
                        return Err(Pkcs15Error::TooLarge);
                    }
                    total_length = Some(total);
                }
            }

            if let Some(total) = total_length
                && collected.len() >= total
            {
                collected.truncate(total);
                return Ok(collected);
            }

            if body_len < usize::from(want) || eof {
                return Err(Pkcs15Error::InvalidData(what));
            }
        }
    }

    /// Generic single-cert read; routes to the right SELECT chain
    /// per slot path. See [`CertSlot`] doc for the routing rules.
    ///
    /// # Errors
    /// Any underlying SELECT or READ BINARY failure. `SW=0x6A82`
    /// ("file not found") for absent slots; callers should treat
    /// that as "not provisioned" rather than a hard error.
    #[inline]
    fn read_certificate(
        &mut self,
        slot: CertSlot,
    ) -> Result<crate::cert_state::CertDer, Pkcs15Error<TxError<Self>>>
    where
        Self: Sized,
    {
        let bytes = match slot.path() {
            SlotPath::UnderPkcs15App => {
                self.select_pkcs15_application()?;
                self.select_ef(slot.fid())?;
                self.read_binary_der_object(slot.label())?
            }
            SlotPath::UnderDf5016 => {
                self.select_mf()?;
                self.select_child_df([0x50, 0x16])?;
                self.select_ef(slot.fid())?;
                self.read_binary_der_object(slot.label())?
            }
            SlotPath::UnderMf => {
                self.select_mf()?;
                self.select_ef(slot.fid())?;
                self.read_binary_der_object(slot.label())?
            }
        };
        Ok(crate::cert_state::CertDer::new(bytes))
    }

    /// Read + parse `EF.TokenInfo` (`5032`).
    ///
    /// # Errors
    /// SELECT / READ BINARY failures from the underlying file
    /// operations.
    #[inline]
    fn read_token_info(&mut self) -> Result<TokenInfo, Pkcs15Error<TxError<Self>>>
    where
        Self: Sized,
    {
        self.select_pkcs15_application()?;
        self.select_ef(EF_TOKEN_INFO_FID)?;
        let bytes = self.read_binary_der_object("EF.TokenInfo")?;
        // Fail closed on a bad parse rather than defaulting (a wrong card
        // generation is worse than a clear error). InvalidData carries a
        // static label, not the parse error, so name-ignore it (clippy
        // map_err_ignore) instead of dropping it anonymously.
        TokenInfo::parse(&bytes).map_err(|_parse_err| Pkcs15Error::InvalidData("EF.TokenInfo"))
    }
}

impl<T: CardTransport + ?Sized> Pkcs15Ops for T {}

/// File Control Information (FCI) bytes returned by a SELECT
/// EF that requested FCI (P2=0x00).
///
/// Typed wrapper so consumers don't pass arbitrary `Vec<u8>`
/// into the FCI-parsing helpers -- the wrapped bytes were
/// produced by the card as the response to a SELECT EF and
/// nothing else.
///
/// Parse the embedded file-size DO via
/// [`Fci::parse_file_size`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fci {
    /// `bytes` field.
    bytes: Vec<u8>,
}

impl Fci {
    /// Wrap raw FCI bytes from a SELECT response.
    #[must_use]
    #[inline]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrow the underlying FCI / FCP bytes (the ISO 7816-4
    /// §5.3.3 template the card returned).
    #[must_use]
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Parse the file-size data object from this FCI/FCP
    /// template.
    ///
    /// Walks a `62` (FCI) or `6F` (FCP) template looking for
    /// `80` (total length including structural overhead) or
    /// `81` (length of the file's data content), per ISO
    /// 7816-4 §5.3.3. Returns the parsed size or `None` if the
    /// FCI doesn't carry one.
    ///
    /// FINEID's S4-2 PKCS#15 application uses the `6F` wrapper
    /// with an `81 02 LL LL` DO; that is what the on-card auth
    /// cert EF.4331 returns and what the read loop sizes
    /// against.
    #[must_use]
    #[inline]
    pub fn parse_file_size(&self) -> Option<usize> {
        use crate::ber::{BerTlvAny, BerTlvIter};
        // FCI wrapper tag is either 0x62 (FCP-only) or 0x6F
        // (FCI). Both are application-class IMPLICIT
        // constructed; peek the tag rather than expect a
        // specific marker since we accept either.
        const TAG_FCP: u16 = 0x62;
        const TAG_FCI: u16 = 0x6F;
        const TAG_FILE_LENGTH_NON_TLV: u16 = 0x80;
        const TAG_FILE_LENGTH_TLV: u16 = 0x81;
        let outer = BerTlvAny::parse(&self.bytes).ok()?;
        if outer.tag != TAG_FCP && outer.tag != TAG_FCI {
            return None;
        }
        for child in BerTlvIter::new(outer.value) {
            let c = child.ok()?;
            if c.tag == TAG_FILE_LENGTH_NON_TLV || c.tag == TAG_FILE_LENGTH_TLV {
                let mut v: usize = 0;
                for &b in c.value {
                    v = (v << 8_u32) | usize::from(b);
                }
                return Some(v);
            }
        }
        None
    }
}

// `select_ef` / `read_binary_to_end` / `select_mf` / `select_child_df` /
// `read_certificate` are methods on [`Pkcs15Ops`]; see the trait
// definition above.

// ----- EF.TokenInfo -----

/// Subset of PKCS#15 `TokenInfo` the `card status` CLI surfaces.
#[derive(Debug, Clone, Default)]
pub struct TokenInfo {
    /// `EF.TokenInfo.version` per PKCS#15 §6.6.1; the integer
    /// version of the `TokenInfo` structure. Tier 0 `u32` -- spec
    /// allows any non-negative INTEGER.
    pub version: Option<u32>,
    /// `EF.TokenInfo.serialNumber` -- the chip-side PKCS#15
    /// long serial. Surfaced as the typed
    /// [`crate::identity::TokenSerial`] (kept distinct from the
    /// plastic-printed `PrintedSerial` and the X.509
    /// `CertSerial` per `doc/typing-discipline.md`).
    pub serial_number_hex: Option<crate::identity::TokenSerial>,
    /// `EF.TokenInfo.manufacturerID` per PKCS#15 §6.6.1
    /// (`UTF8String`). Tier 0 `String` -- a tighter form would be
    /// `ManufacturerId` enforcing the length cap; not enforced
    /// at this layer today.
    pub manufacturer_id: Option<String>,
    /// `EF.TokenInfo.label` per PKCS#15 §6.6.1 (`UTF8String`).
    /// Tier 0 `String`; presentational.
    pub label: Option<String>,
}

// `read_token_info` is a method on [`Pkcs15Ops`]; see the trait
// definition above.

/// `[0] IMPLICIT` `Label` in PKCS#15 `TokenInfo` -- the
/// alternate location for the label string when not a
/// universal `UTF8String` / `PrintableString`.
const TAG_TOKEN_INFO_LABEL_IMPLICIT: u16 = 0x80;

impl TokenInfo {
    /// Validating constructor: parse raw `EF.TokenInfo` bytes
    /// (as read from the card's `5032`) into a typed `TokenInfo`.
    /// This *is* the trust boundary -- the card hands raw bytes
    /// and there is no earlier validation; construction and
    /// validation are the same step, so there is no unvalidated
    /// `TokenInfo` value to misuse.
    ///
    /// `der` is borrowed because the result owns everything it
    /// keeps (it copies the fields out); the bytes need not
    /// outlive the call. The raw `&[u8]` here is the sanctioned
    /// validation-boundary carve-out (see `doc/typing-discipline.md`
    /// Rule B / the typing-grep register), not a leak -- it is the
    /// single door, on the validated type itself.
    ///
    /// Best-effort *within* a well-formed outer SEQUENCE --
    /// silently treats malformed / unsupported sub-objects as
    /// absent rather than failing the whole read, because cards
    /// diverge on which fields they populate. The one hard
    /// failure is the outer SEQUENCE itself not decoding: that
    /// returns [`BerError`](crate::ber::BerError) so a malformed
    /// file is distinct from the caller's "absent / use
    /// defaults" path (see `doc/security/der-trust-boundary.md`).
    pub(crate) fn parse(der: &[u8]) -> Result<Self, crate::ber::BerError> {
        use crate::ber::{
            BerTag, BerTlv, BerTlvIter, Integer, OctetString, PrintableString, Sequence, Utf8String,
        };
        let outer = BerTlv::<Sequence>::parse(der)?;
        let mut info = Self::default();
        let mut it = BerTlvIter::new(outer.value);

        // Version INTEGER.
        if let Some(Ok(version_any)) = it.next()
            && let Ok(version_tlv) = version_any.expect::<Integer>()
        {
            let mut v: u32 = 0;
            for &b in version_tlv.value {
                v = (v << 8_u32) | u32::from(b);
            }
            info.version = Some(v);
        }
        // Serial number OCTET STRING.
        if let Some(Ok(serial_any)) = it.next()
            && let Ok(serial_tlv) = serial_any.expect::<OctetString>()
        {
            info.serial_number_hex = Some(crate::identity::TokenSerial::new(
                crate::hex::Hex::encode(serial_tlv.value),
            ));
        }
        // The rest of the fields are all optional + variably tagged.
        // Walk what's left, picking out string-shaped fields by
        // tag (UTF8String/PrintableString) and the `[0] label`
        // IMPLICIT-tagged label as best-effort.
        for entry in it {
            let Ok(entry) = entry else { continue };
            if entry.tag == <Utf8String as BerTag>::TAG
                || entry.tag == <PrintableString as BerTag>::TAG
            {
                let s = String::from_utf8_lossy(entry.value).into_owned();
                if info.manufacturer_id.is_none() {
                    info.manufacturer_id = Some(s);
                } else if info.label.is_none() {
                    info.label = Some(s);
                } else {
                    // Both slots filled; extra string entries ignored.
                }
            } else if entry.tag == TAG_TOKEN_INFO_LABEL_IMPLICIT {
                // [0] Label -- IMPLICIT UTF8String.
                info.label = Some(String::from_utf8_lossy(entry.value).into_owned());
            } else {
                // Other tags in TokenInfo: ignored.
            }
        }
        Ok(info)
    }
}

/// Which generation of FINEID card we're talking to.
///
/// DVV has shipped two production card families that differ
/// in their activation-PIN length: the **older** RSA-based
/// generation requires an 8-digit activation PIN / PUK, and
/// the **newer** ECC-based generation requires a 7-digit
/// one-time activation PIN (plus a separately-orderable PUK
/// of unspecified length). The card OS itself rejects wrong-
/// length input and burns one of the 5 try-counter slots, so
/// the host needs to know which length is correct *before*
/// sending the APDU.
///
/// Detection rides on the auth cert's issuer Common Name --
/// DVV's CSCAs encode the family in the suffix:
///
/// - `"... - G4R"` / `"... - G3R"` (R for RSA) -> older
/// - `"... - G4E"` / `"... - G3E"` (E for ECC) -> newer.
///
/// Any other shape returns [`CardGeneration::Unknown`], and
/// callers should refuse to make activation-length decisions
/// on its behalf. The correlation between issuer family and
/// card-OS generation is empirical, not protocol-guaranteed;
/// see `doc/dvv-terminology.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardGeneration {
    /// Older FINEID card (RSA-based citizen certs, DVV G3/G4 R
    /// issuer). Activation PIN is 8 digits.
    Older,
    /// Newer FINEID card (ECC-based citizen certs, DVV G3/G4 E
    /// issuer). Activation PIN is 7 digits.
    Newer,
    /// Couldn't classify (issuer DN missing, unfamiliar suffix,
    /// auth cert unreadable). Callers should not infer
    /// activation PIN length.
    Unknown,
}

impl CardGeneration {
    /// Hardcoded activation-PIN length for this generation, or
    /// `None` when the generation didn't classify and we refuse
    /// to guess. The card-OS will only accept this length;
    /// anything else burns a try-counter slot.
    #[must_use]
    #[inline]
    pub const fn activation_pin_length(self) -> Option<usize> {
        match self {
            Self::Older => Some(8),
            Self::Newer => Some(7),
            Self::Unknown => None,
        }
    }
}

/// Classify a FINEID card by auth-cert issuance date.
///
/// **Authoritative classifier.** DVV cut over to the new
/// activation-PIN model on 2026-01-13; the auth cert's
/// `notBefore` is the most reliable card-side signal for which
/// side of that boundary a card sits on. Per
/// <https://dvv.fi/en/activation-of-the-citizen-certificate>,
/// the issuance date is also printed on the card surface for
/// human verification.
///
/// Compared with [`classify_card_generation`] (issuer-CN
/// suffix), this approach reads the date the spec itself
/// names as the cutoff, so it survives DVV CA renaming /
/// renumbering without code churn.
#[must_use]
#[inline]
pub fn classify_card_generation_by_issuance(not_before: crate::x509::DateTime) -> CardGeneration {
    // 2026-01-13 is the cutoff DVV publishes.
    let cutoff_year: u16 = 2026;
    let cutoff_month: u8 = 1;
    let cutoff_day: u8 = 13;
    let date_tuple = (not_before.year(), not_before.month(), not_before.day());
    let cutoff_tuple = (cutoff_year, cutoff_month, cutoff_day);
    if date_tuple >= cutoff_tuple {
        CardGeneration::Newer
    } else {
        CardGeneration::Older
    }
}

/// Classify a FINEID card by its auth-cert issuer DN.
///
/// Heuristic fallback for when the issuance date isn't
/// available (e.g. malformed cert validity, very early test
/// builds). The authoritative classifier is
/// [`classify_card_generation_by_issuance`]; callers that have
/// access to the parsed cert should prefer that one and use
/// this only as a cross-check or when `not_before` couldn't
/// be parsed.
///
/// See [`CardGeneration`] for the matching rules.
#[must_use]
#[inline]
pub fn classify_card_generation(issuer: crate::x509::Name<'_>) -> CardGeneration {
    let Some(cn) = issuer.common_name() else {
        return CardGeneration::Unknown;
    };
    // Match the family suffix at the end of the issuer CN so a
    // future "G5E" / "G5R" generation still classifies. Use
    // case-sensitive match against DVV's own spelling.
    if cn.ends_with('R') && (cn.contains("G3") || cn.contains("G4") || cn.contains("G5")) {
        CardGeneration::Older
    } else if cn.ends_with('E') && (cn.contains("G3") || cn.contains("G4") || cn.contains("G5")) {
        CardGeneration::Newer
    } else {
        CardGeneration::Unknown
    }
}

/// Output of `pick_fineid_reader` -- a reader plus the identity
/// of the card currently inserted in it.
///
/// The identity is best-effort: EF.TokenInfo serial(s) are always
/// derivable from a FINEID-responding card; the auth-cert subject
/// fields (surname / given names / PEUIN) are populated when the
/// cert reads cleanly. Callers use this for a pre-flight "we're
/// about to talk to `<card>` in `<reader>`" print so the operator can
/// abort before consuming a CAN / PIN against the wrong card.
#[derive(Debug, Clone)]
pub struct FineidReaderPick {
    /// PC/SC reader id of the matched reader.
    pub reader_id: crate::backend::ReaderId,
    /// Credential identity captured at pick time (FINEID S2
    /// §6.3.8.3 subject fields when the auth cert read cleanly).
    pub identity: crate::identity::CredentialIdentity,
}

/// FINEID-aware reader picker.
///
/// Like `backend::pick_single_reader`, but instead of
/// treating every card-present reader as a candidate, it probes
/// each one with SELECT PKCS#15 + `EF.TokenInfo` + auth-cert
/// read, then considers only the readers that actually
/// responded as FINEID. This skips non-FINEID smartcard tokens
/// (`YubiKey` in `CCID` mode, `OpenPGP` cards, etc.) before the
/// ambiguity check, so the `--reader` flag is optional again
/// when exactly one FINEID-format card is connected even
/// alongside other tokens.
///
/// For the winning reader, returns the full
/// [`CredentialIdentity`] (token serials + DN-derived fields)
/// the caller uses for the pre-flight identity print.
///
/// Failure modes mirror `pick_single_reader` plus
/// `ReaderPickError::NoFineidCard` for the "readers connected,
/// cards present, none are FINEID" case.
///
/// # Errors
/// Any [`ReaderPickError`] variant.
///
/// [`CredentialIdentity`]: crate::identity::CredentialIdentity
/// [`ReaderPickError`]: crate::backend::ReaderPickError.
///
/// FINEID-aware extension on [`crate::backend::ReaderBackend`].
/// Adds the multi-card-safety picker and per-reader probe via
/// default-impl methods on `&self`. Same shape as `PinOps` /
/// `SignOps` / `Pkcs15Ops` / `CardAccessOps` -- import this
/// trait to put the methods in scope.
pub trait FineidReaderPicker: crate::backend::ReaderBackend
where
    Self::Error: core::fmt::Display,
{
    /// See `pick_fineid_reader`.
    ///
    /// # Errors
    /// As for `pick_fineid_reader`.
    #[inline]
    fn pick_fineid_reader(
        &self,
        filter: Option<&crate::backend::ReaderFilter>,
    ) -> Result<FineidReaderPick, crate::backend::ReaderPickError>
    where
        Self: Sized,
    {
        pick_fineid_reader(self, filter)
    }

    /// See `enumerate_fineid_readers`.
    ///
    /// # Errors
    /// As for `enumerate_fineid_readers`.
    #[inline]
    fn enumerate_fineid_readers(
        &self,
        filter: Option<&crate::backend::ReaderFilter>,
    ) -> Result<Vec<FineidReaderPick>, crate::backend::ReaderPickError>
    where
        Self: Sized,
    {
        enumerate_fineid_readers(self, filter)
    }

    /// See `pick_contactless_reader`.
    ///
    /// # Errors
    /// As for `pick_contactless_reader`.
    #[inline]
    fn pick_contactless_reader(
        &self,
        filter: Option<&crate::backend::ReaderFilter>,
    ) -> Result<crate::backend::ReaderId, crate::backend::ReaderPickError>
    where
        Self: Sized,
    {
        pick_contactless_reader(self, filter)
    }

    /// See `enumerate_contactless_readers`.
    ///
    /// # Errors
    /// As for `enumerate_contactless_readers`.
    #[inline]
    fn enumerate_contactless_readers(
        &self,
        filter: Option<&crate::backend::ReaderFilter>,
    ) -> Result<Vec<crate::backend::ReaderId>, crate::backend::ReaderPickError>
    where
        Self: Sized,
    {
        enumerate_contactless_readers(self, filter)
    }
}

impl<B: crate::backend::ReaderBackend + ?Sized> FineidReaderPicker for B where
    B::Error: core::fmt::Display
{
}

/// FINEID-aware single-reader picker, deterministic for the CLI.
///
/// Same shape as [`crate::backend::pick_single_reader`] but
/// runs ATR classification ([`crate::fineid_card::Atr`]) on
/// each candidate so the pick can disambiguate when the user
/// has two readers and only one holds a FINEID-recognised
/// card. Returns `NoCardPresent` if no FINEID card is found
/// (a non-FINEID card in the reader does not count) and
/// `MultipleReaders` if more than one FINEID card is present.
pub(crate) fn pick_fineid_reader<B: crate::backend::ReaderBackend>(
    backend: &B,
    filter: Option<&crate::backend::ReaderFilter>,
) -> Result<FineidReaderPick, crate::backend::ReaderPickError>
where
    B::Error: core::fmt::Display,
{
    use crate::backend::{ReaderInfo, ReaderPickError};

    let readers = backend
        .enumerate()
        .map_err(|_backend_err| ReaderPickError::NoReaders)?;
    if readers.is_empty() {
        return Err(ReaderPickError::NoReaders);
    }
    let present: Vec<ReaderInfo> = readers.into_iter().filter(|r| r.card_present).collect();
    if present.is_empty() {
        return Err(ReaderPickError::NoCardPresent);
    }

    // Probe every card-present reader. Readers whose card
    // doesn't respond to PKCS#15 SELECT (or whose TokenInfo
    // isn't readable) are dropped from the candidate set --
    // they're physically inserted cards (YubiKey in CCID mode,
    // OpenPGP token, etc.) but not FINEID for our purposes.
    let mut all_names: Vec<String> = Vec::with_capacity(present.len());
    let mut probed: Vec<(ReaderInfo, crate::identity::CredentialIdentity)> =
        Vec::with_capacity(present.len());
    for info in &present {
        all_names.push(info.id.as_str().to_owned());
        if let Some(identity) = probe_fineid_identity(backend, &info.id) {
            probed.push((info.clone(), identity));
        }
    }

    if probed.is_empty() {
        return Err(ReaderPickError::NoFineidCard {
            available: all_names,
        });
    }

    // Filter / ambiguity resolution operates on the FINEID-
    // responding subset only. A `--reader` substring that
    // matches a non-FINEID reader effectively doesn't match
    // anything -- which is the right behaviour for this layer.
    let matched: Vec<&(ReaderInfo, crate::identity::CredentialIdentity)> = filter.map_or_else(
        || probed.iter().collect(),
        |f| {
            let needle = f.as_str();
            probed
                .iter()
                .filter(|(r, _)| r.id.as_str().contains(needle))
                .collect()
        },
    );

    let winner = match (filter, matched.as_slice()) {
        (_, [single]) => *single,
        (Some(f), []) => {
            return Err(ReaderPickError::NoMatchingReader {
                filter: f.as_str().to_owned(),
                available: probed
                    .iter()
                    .map(|(r, _)| r.id.as_str().to_owned())
                    .collect(),
            });
        }
        (Some(f), many) => {
            return Err(ReaderPickError::AmbiguousFilter {
                filter: f.as_str().to_owned(),
                matched: many.iter().map(|(r, _)| r.id.as_str().to_owned()).collect(),
            });
        }
        (None, many) => {
            return Err(ReaderPickError::MultipleReadersNoFilter {
                available: many.iter().map(|(r, _)| r.id.as_str().to_owned()).collect(),
            });
        }
    };

    Ok(FineidReaderPick {
        reader_id: winner.0.id.clone(),
        identity: winner.1.clone(),
    })
}

/// Probe a single reader by opening + SELECT PKCS#15 +
/// `EF.TokenInfo` + auth-cert read. Returns the assembled
/// [`crate::identity::CredentialIdentity`] when the card
/// responds as FINEID-shape; `None` for any other token (no
/// SELECT, no `TokenInfo`, etc.).
///
/// The auth-cert read is best-effort: a FINEID card whose
/// `TokenInfo` reads but whose cert doesn't still counts as
/// FINEID (some card states have a `TokenInfo` present but cert
/// reads gated by activation status). The identity in that
/// case carries only the token serial(s).
fn probe_fineid_identity<B: crate::backend::ReaderBackend>(
    backend: &B,
    reader_id: &crate::backend::ReaderId,
) -> Option<crate::identity::CredentialIdentity>
where
    B::Error: core::fmt::Display,
{
    use crate::backend::ReaderAccessCap;
    use crate::identity::{CredentialIdentity, derive_printed_serial, render_token_serial};

    let mut transport = backend
        .open_session(reader_id, ReaderAccessCap::Read)
        .ok()?;
    // read_token_info SELECTs PKCS#15 internally; failure means
    // the card isn't FINEID-shape. The full token serial is
    // computed only to derive the printed form; it doesn't
    // flow into the identity itself -- that's session state,
    // not person identity.
    let token = transport.read_token_info().ok()?;
    let token_full = token.serial_number_hex.map(render_token_serial)?;
    let printed_serial = derive_printed_serial(&token_full);

    // Cert read for human-readable identity. Best effort.
    let (surname, given_names, peuin) = transport
        .read_certificate(CertSlot::Authentication)
        .or_else(|_| transport.read_certificate(CertSlot::AuthenticationAlt))
        .ok()
        .and_then(|der| {
            crate::x509::Certificate::from_der(der.as_bytes())
                .ok()
                .map(|cert| {
                    let subject = cert.subject;
                    (subject.surname(), subject.given_names(), subject.peuin())
                })
        })
        .unwrap_or_default();

    let mut id = CredentialIdentity::new();
    if let Some(s) = surname {
        id = id.with_surname(s);
    }
    if let Some(n) = given_names.first {
        id = id.with_first_name(n);
    }
    if let Some(n) = given_names.second {
        id = id.with_second_name(n);
    }
    id = id.with_additional_names(given_names.additional);
    if let Some(p) = peuin {
        id = id.with_peuin(p);
    }
    if let Some(s) = printed_serial {
        id = id.with_printed_serial(s);
    }
    Some(id)
}

/// Probe a single reader for a card that serves `EF.CardAccess`
/// on the plain (pre-PACE) channel.
///
/// The contactless counterpart of [`probe_fineid_identity`]: over
/// the contactless interface a FINEID card answers SELECT PKCS#15
/// with SW `6982` until PACE has run, so the PKCS#15 probe can
/// never recognise it. What the card does serve pre-PACE -- by
/// design, so the terminal can learn the PACE parameters -- is
/// `EF.CardAccess` under the MF. A card-present reader whose card
/// yields a parseable `EF.CardAccess` is therefore a PACE-capable
/// eMRTD candidate.
///
/// No CAN is consumed and nothing person-identifying is read:
/// `EF.CardAccess` carries only public protocol parameters.
fn probe_card_access<B: crate::backend::ReaderBackend>(
    backend: &B,
    reader_id: &crate::backend::ReaderId,
) -> bool
where
    B::Error: core::fmt::Display,
{
    use crate::backend::ReaderAccessCap;
    use crate::card_access::CardAccessOps as _;

    backend
        .open_session(reader_id, ReaderAccessCap::Read)
        .ok()
        .is_some_and(|mut transport| transport.read_card_access().is_ok())
}

/// Every connected reader whose card serves `EF.CardAccess` on
/// the plain channel, i.e. every PACE-capable contactless
/// candidate.
///
/// The contactless counterpart of [`enumerate_fineid_readers`],
/// and the multi-reader form of [`pick_contactless_reader`]:
/// no single-match requirement, no ambiguity errors, just the
/// candidates in enumeration order. Returns bare
/// [`ReaderId`]s -- pre-PACE there is no identity to attach.
///
/// [`ReaderId`]: crate::backend::ReaderId
///
/// # Errors
/// [`ReaderPickError::NoReaders`] when the backend reports none.
/// An empty result is `Ok(vec![])`, not an error.
///
/// [`ReaderPickError::NoReaders`]: crate::backend::ReaderPickError::NoReaders
pub(crate) fn enumerate_contactless_readers<B: crate::backend::ReaderBackend>(
    backend: &B,
    filter: Option<&crate::backend::ReaderFilter>,
) -> Result<Vec<crate::backend::ReaderId>, crate::backend::ReaderPickError>
where
    B::Error: core::fmt::Display,
{
    use crate::backend::ReaderPickError;

    let readers = backend
        .enumerate()
        .map_err(|_backend_err| ReaderPickError::NoReaders)?;
    if readers.is_empty() {
        return Err(ReaderPickError::NoReaders);
    }
    Ok(readers
        .into_iter()
        .filter(|r| r.card_present)
        .filter(|r| filter.is_none_or(|f| r.id.as_str().contains(f.as_str())))
        .filter(|r| probe_card_access(backend, &r.id))
        .map(|r| r.id)
        .collect())
}

/// Contactless (PACE-first) reader pick for the eMRTD flow.
///
/// Mirrors `pick_fineid_reader`'s candidate / filter / ambiguity
/// rules, but the per-reader probe is [`probe_card_access`]
/// instead of the PKCS#15 identity read: over contactless the
/// PKCS#15 application is sealed until PACE has run, so no
/// pre-flight identity can exist. Callers that fall back to this
/// pick proceed without one, and the operator's pre-PACE
/// confirmation is the reader name alone. That is an acceptable
/// trade because the CAN is printed on the card and carries no
/// retry counter -- a PACE run against an unintended card wastes
/// nothing.
///
/// The empty-candidate case reuses `NoFineidCard`; the intended
/// caller (the eMRTD contact-probe fallback) reports its original
/// contact-side error in that case, so this fn's PKCS#15-worded
/// message never reaches the operator.
///
/// # Errors
/// Any [`ReaderPickError`] variant.
///
/// [`ReaderPickError`]: crate::backend::ReaderPickError
pub(crate) fn pick_contactless_reader<B: crate::backend::ReaderBackend>(
    backend: &B,
    filter: Option<&crate::backend::ReaderFilter>,
) -> Result<crate::backend::ReaderId, crate::backend::ReaderPickError>
where
    B::Error: core::fmt::Display,
{
    use crate::backend::{ReaderInfo, ReaderPickError};

    let readers = backend
        .enumerate()
        .map_err(|_backend_err| ReaderPickError::NoReaders)?;
    if readers.is_empty() {
        return Err(ReaderPickError::NoReaders);
    }
    let present: Vec<ReaderInfo> = readers.into_iter().filter(|r| r.card_present).collect();
    if present.is_empty() {
        return Err(ReaderPickError::NoCardPresent);
    }

    let mut all_names: Vec<String> = Vec::with_capacity(present.len());
    let mut candidates: Vec<&ReaderInfo> = Vec::with_capacity(present.len());
    for info in &present {
        all_names.push(info.id.as_str().to_owned());
        if probe_card_access(backend, &info.id) {
            candidates.push(info);
        }
    }
    if candidates.is_empty() {
        return Err(ReaderPickError::NoFineidCard {
            available: all_names,
        });
    }

    let matched: Vec<&ReaderInfo> = filter.map_or_else(
        || candidates.clone(),
        |f| {
            let needle = f.as_str();
            candidates
                .iter()
                .copied()
                .filter(|r| r.id.as_str().contains(needle))
                .collect()
        },
    );

    match (filter, matched.as_slice()) {
        (_, [single]) => Ok(single.id.clone()),
        (Some(f), []) => Err(ReaderPickError::NoMatchingReader {
            filter: f.as_str().to_owned(),
            available: candidates
                .iter()
                .map(|r| r.id.as_str().to_owned())
                .collect(),
        }),
        (Some(f), many) => Err(ReaderPickError::AmbiguousFilter {
            filter: f.as_str().to_owned(),
            matched: many.iter().map(|r| r.id.as_str().to_owned()).collect(),
        }),
        (None, many) => Err(ReaderPickError::MultipleReadersNoFilter {
            available: many.iter().map(|r| r.id.as_str().to_owned()).collect(),
        }),
    }
}

/// Enumerate every connected reader whose currently-inserted
/// card responds as FINEID-shape.
///
/// The probe is PKCS#15 SELECT + EF.TokenInfo readable. Non-
/// FINEID tokens (`YubiKey` in `CCID` mode, `OpenPGP` cards,
/// etc.) are skipped transparently. The optional substring
/// filter narrows the result further; an empty result is
/// returned as `Ok(vec![])` (no error) so the caller can
/// decide how to surface "no FINEID cards" in iteration
/// contexts -- distinct from `pick_fineid_reader`'s
/// "pick exactly one or error" contract.
///
/// # Errors
/// PC/SC enumeration failure surfaces as
/// `ReaderPickError::NoReaders`.
///
/// [`ReaderPickError`]: crate::backend::ReaderPickError.
pub(crate) fn enumerate_fineid_readers<B: crate::backend::ReaderBackend>(
    backend: &B,
    filter: Option<&crate::backend::ReaderFilter>,
) -> Result<Vec<FineidReaderPick>, crate::backend::ReaderPickError>
where
    B::Error: core::fmt::Display,
{
    use crate::backend::ReaderPickError;

    let readers = backend
        .enumerate()
        .map_err(|_backend_err| ReaderPickError::NoReaders)?;
    let mut out: Vec<FineidReaderPick> = Vec::new();
    for info in readers {
        if !info.card_present {
            continue;
        }
        if let Some(f) = filter
            && !info.id.as_str().contains(f.as_str())
        {
            continue;
        }
        if let Some(identity) = probe_fineid_identity(backend, &info.id) {
            out.push(FineidReaderPick {
                reader_id: info.id,
                identity,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {

    use super::{CertSlot, EF_AUTH_CERT_FID, Fci, PKCS15_AID, Pkcs15Error, Pkcs15Ops as _};
    use crate::atr::{Atr, AtrError, MINIMAL_DIRECT_ATR};
    use crate::transport::{CardTransport, CommandApdu, ResponseApdu, TransportOutcome};

    /// Scripted in-memory transport that replays a canned `(request,
    /// response)` trace. Same shape as `transport::tests::MockTransport`
    /// but local to this module so cross-module test access isn't
    /// needed.
    struct ScriptedTransport {
        script: Vec<(Vec<u8>, ResponseApdu)>,
        cursor: usize,
    }

    impl ScriptedTransport {
        fn new(script: Vec<(Vec<u8>, ResponseApdu)>) -> Self {
            Self { script, cursor: 0 }
        }
    }

    impl CardTransport for ScriptedTransport {
        type Error = String;
        fn transmit_outcome(
            &mut self,
            apdu: &CommandApdu,
        ) -> Result<TransportOutcome, Self::Error> {
            let (expected, response) = self
                .script
                .get(self.cursor)
                .ok_or_else(|| format!("script exhausted at step {}", self.cursor))?;
            if expected != apdu.as_bytes() {
                return Err(format!(
                    "step {}: expected {} got {}",
                    self.cursor,
                    hex::encode(expected),
                    hex::encode(apdu.as_bytes())
                ));
            }
            self.cursor += 1;
            Ok(TransportOutcome::Response(response.clone()))
        }
        fn atr(&self) -> Result<Atr, AtrError> {
            Atr::new(MINIMAL_DIRECT_ATR)
        }
    }

    fn ok(body: &[u8]) -> ResponseApdu {
        ResponseApdu {
            body: body.to_vec(),
            sw1: 0x90,
            sw2: 0x00,
        }
    }

    #[test]
    fn pkcs15_aid_is_ascii_pkcs_15_with_prefix() {
        // "PKCS-15" = 0x50 0x4B 0x43 0x53 0x2D 0x31 0x35
        assert_eq!(&PKCS15_AID[5..], b"PKCS-15");
        assert_eq!(PKCS15_AID.len(), 12);
    }

    #[test]
    fn select_pkcs15_application_apdu_layout() {
        let mut tx = ScriptedTransport::new(vec![(
            vec![
                0x00, 0xA4, 0x04, 0x0C, 0x0C, 0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53,
                0x2D, 0x31, 0x35,
            ],
            ok(&[]),
        )]);
        tx.select_pkcs15_application().expect("selects");
    }

    #[test]
    fn select_ef_apdu_layout() {
        let mut tx = ScriptedTransport::new(vec![(
            vec![0x00, 0xA4, 0x02, 0x0C, 0x02, 0x43, 0x31],
            ok(&[]),
        )]);
        tx.select_ef(EF_AUTH_CERT_FID).expect("selects");
    }

    #[test]
    fn select_ef_falls_back_to_any_file_by_id() {
        let mut tx = ScriptedTransport::new(vec![
            (
                vec![0x00, 0xA4, 0x02, 0x0C, 0x02, 0x43, 0x31],
                ResponseApdu {
                    body: Vec::new(),
                    sw1: 0x6A,
                    sw2: 0x82,
                },
            ),
            (vec![0x00, 0xA4, 0x00, 0x0C, 0x02, 0x43, 0x31], ok(&[])),
        ]);
        tx.select_ef(EF_AUTH_CERT_FID)
            .expect("fallback selection succeeds");
    }

    /// FINEID's FCI uses tag `80` with a 2-byte big-endian file size.
    #[test]
    fn parse_fci_file_size_finds_80_do() {
        // 62 L (80 02 06 80)(82 02 00 11) -- outer template, file
        // size 0x0680 = 1664, followed by an unrelated 82 DO that we
        // should skip past.
        let fci = Fci::new(hex::decode("62088002068082020011").expect("FCI fixture hex decodes"));
        assert_eq!(fci.parse_file_size(), Some(0x0680));

        // FINEID's actual EF.4331 FCP, captured against a real card:
        //   6F 18 81 02 06 F8 82 01 01 83 02 43 31 8A 01 05 8C 03 03 FF 00 9C 03 03 FF 00
        // Outer is `6F` (FCP), file-size DO is `81 02 06 f8` = 1784.
        let fci = Fci::new(
            hex::decode("6f18810206f8820101830243318a01058c0303ff009c0303ff00")
                .expect("captured FCP hex decodes"),
        );
        assert_eq!(fci.parse_file_size(), Some(1784));

        // No 62/6F wrapper -> None.
        assert_eq!(
            Fci::new(hex::decode("80020100").expect("bare DO hex decodes")).parse_file_size(),
            None
        );
    }

    #[test]
    fn read_binary_concatenates_until_short_response() {
        // First two reads: 0x80 bytes each. Third: 0x40 bytes (short).
        let chunk_a = vec![0xAA; 0x80];
        let chunk_b = vec![0xBB; 0x80];
        let chunk_c = vec![0xCC; 0x40];

        let mut tx = ScriptedTransport::new(vec![
            (vec![0x00, 0xB0, 0x00, 0x00, 0x80], ok(&chunk_a)),
            (vec![0x00, 0xB0, 0x00, 0x80, 0x80], ok(&chunk_b)),
            (vec![0x00, 0xB0, 0x01, 0x00, 0x80], ok(&chunk_c)),
        ]);
        let out = tx.read_binary_to_end(None).expect("reads");
        assert_eq!(out.len(), 0x80 + 0x80 + 0x40);
        assert_eq!(&out[..0x80], &chunk_a[..]);
        assert_eq!(&out[0x80..0x100], &chunk_b[..]);
        assert_eq!(&out[0x100..], &chunk_c[..]);
    }

    /// When the FCI tells us the size, we send the exact tail `Le`
    /// on the last read. The FINEID card answers `SW=6282` with an
    /// empty body when `Le` exceeds remaining; pinning `Le` to the
    /// right value avoids the truncation hit on hardware.
    #[test]
    fn read_binary_with_known_size_uses_exact_le_for_tail() {
        let chunk_a = vec![0xAA; 0x80];
        let chunk_b = vec![0xBB; 0x80];
        let chunk_c = vec![0xCC; 0x18]; // 24-byte tail
        let mut tx = ScriptedTransport::new(vec![
            (vec![0x00, 0xB0, 0x00, 0x00, 0x80], ok(&chunk_a)),
            (vec![0x00, 0xB0, 0x00, 0x80, 0x80], ok(&chunk_b)),
            // Last read asks for exactly 0x18 bytes
            // (= 0x80 + 0x80 + 0x18 = 280 total).
            (vec![0x00, 0xB0, 0x01, 0x00, 0x18], ok(&chunk_c)),
        ]);
        let out = tx
            .read_binary_to_end(Some(0x80 + 0x80 + 0x18))
            .expect("reads");
        assert_eq!(out.len(), 0x80 + 0x80 + 0x18);
    }

    #[test]
    fn read_der_object_discards_padding_from_first_chunk() {
        let expected = [0x30, 0x02, 0x05, 0x00];
        let mut padded = vec![0_u8; 0x80];
        padded[..expected.len()].copy_from_slice(&expected);
        let mut tx =
            ScriptedTransport::new(vec![(vec![0x00, 0xB0, 0x00, 0x00, 0x80], ok(&padded))]);

        let out = tx
            .read_binary_der_object("test object")
            .expect("reads one object");
        assert_eq!(out, expected);
    }

    #[test]
    fn read_der_object_pins_the_final_chunk_to_declared_length() {
        let mut object = vec![0x30, 0x82, 0x01, 0x00];
        object.extend(core::iter::repeat_n(0xA5, 0x100));
        let mut tx = ScriptedTransport::new(vec![
            (vec![0x00, 0xB0, 0x00, 0x00, 0x80], ok(&object[..0x80])),
            (vec![0x00, 0xB0, 0x00, 0x80, 0x80], ok(&object[0x80..0x100])),
            (vec![0x00, 0xB0, 0x01, 0x00, 0x04], ok(&object[0x100..])),
        ]);

        let out = tx
            .read_binary_der_object("test object")
            .expect("reads one object");
        assert_eq!(out, object);
    }

    #[test]
    fn read_binary_handles_eof_marker() {
        let chunk_a = vec![0xAA; 0x80];
        // Card returns `SW=6282` (EOF reached) on the second read
        // with a body shorter than what we asked for.
        let chunk_b = vec![0xBB; 0x10];
        let mut tx = ScriptedTransport::new(vec![
            (vec![0x00, 0xB0, 0x00, 0x00, 0x80], ok(&chunk_a)),
            (
                vec![0x00, 0xB0, 0x00, 0x80, 0x80],
                ResponseApdu {
                    body: chunk_b,
                    sw1: 0x62,
                    sw2: 0x82,
                },
            ),
        ]);
        let out = tx.read_binary_to_end(None).expect("reads");
        assert_eq!(out.len(), 0x80 + 0x10);
    }

    #[test]
    fn read_binary_propagates_card_error() {
        let mut tx = ScriptedTransport::new(vec![(
            vec![0x00, 0xB0, 0x00, 0x00, 0x80],
            ResponseApdu {
                body: vec![],
                sw1: 0x6A,
                sw2: 0x82,
            },
        )]);
        let err = tx
            .read_binary_to_end(None)
            .expect_err("card error status aborts the read");
        assert!(matches!(err, Pkcs15Error::Sw(0x6A82)));
    }

    /// End-to-end SELECT+SELECT+READ flow against a tiny script.
    /// The SELECT asks for no FCI and the short READ response ends
    /// the file.
    #[test]
    fn read_authentication_certificate_drives_full_sequence() {
        let cert = vec![0x30_u8, 0x02, 0x05, 0x00];
        let mut tx = ScriptedTransport::new(vec![
            // SELECT PKCS#15 application (P2=0x0C, no FCI on the
            // app SELECT).
            (
                vec![
                    0x00, 0xA4, 0x04, 0x0C, 0x0C, 0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43,
                    0x53, 0x2D, 0x31, 0x35,
                ],
                ok(&[]),
            ),
            // SELECT EF.4331 without response data.
            (vec![0x00, 0xA4, 0x02, 0x0C, 0x02, 0x43, 0x31], ok(&[])),
            // READ BINARY -- the four-byte response is short and
            // therefore terminates the read.
            (vec![0x00, 0xB0, 0x00, 0x00, 0x80], ok(&cert)),
        ]);
        let der = tx
            .read_certificate(CertSlot::Authentication)
            .expect("reads cert");
        assert_eq!(der.as_bytes(), cert.as_slice());
    }

    // ----- contactless (PACE-first) reader pick -----

    use crate::backend::{ReaderAccessCap, ReaderBackend, ReaderId, ReaderInfo, ReaderPickError};

    /// One reader's canned `(request, response)` APDU trace.
    type ReaderScript = Vec<(Vec<u8>, ResponseApdu)>;

    /// Backend whose readers each replay their own scripted
    /// transport. `open_session` clones the reader's script, so
    /// every open starts the trace from the top -- matching a
    /// fresh card session per probe.
    struct ScriptedBackend {
        readers: Vec<(ReaderInfo, ReaderScript)>,
    }

    impl ReaderBackend for ScriptedBackend {
        type Transport = ScriptedTransport;
        type Error = String;

        fn enumerate(&self) -> Result<Vec<ReaderInfo>, Self::Error> {
            Ok(self.readers.iter().map(|(info, _)| info.clone()).collect())
        }

        fn open_session(
            &self,
            reader: &ReaderId,
            _access: ReaderAccessCap,
        ) -> Result<Self::Transport, Self::Error> {
            self.readers
                .iter()
                .find(|(info, _)| info.id == *reader)
                .map(|(_, script)| ScriptedTransport::new(script.clone()))
                .ok_or_else(|| format!("no script for reader {}", reader.as_str()))
        }
    }

    fn sw_only(sw1: u8, sw2: u8) -> ResponseApdu {
        ResponseApdu {
            body: Vec::new(),
            sw1,
            sw2,
        }
    }

    fn present(name: &str) -> ReaderInfo {
        ReaderInfo {
            id: ReaderId::new(name.to_owned()),
            card_present: true,
        }
    }

    /// The `EF.CardAccess` read trace a contactless FINEID card
    /// serves pre-PACE, with the file body captured from a
    /// production card (see
    /// `card_access::tests::parses_production_fineid_card_access_capture`).
    fn card_access_script() -> ReaderScript {
        let body = hex::decode(concat!(
            "31283012060a04007f00070202040204020102020110",
            "3012060a04007f00070202040604020102020110",
        ))
        .expect("capture hex decodes");
        vec![
            // SELECT MF, first attempt (P1=0x00) accepted.
            (vec![0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00], ok(&[])),
            // SELECT EF.CardAccess (011C) without response data.
            (vec![0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1C], ok(&[])),
            // READ BINARY, whole 42-byte file in one chunk.
            (vec![0x00, 0xB0, 0x00, 0x00, 0x80], ok(&body)),
        ]
    }

    /// A card (SAM slot, non-eID token, ...) that refuses SELECT
    /// MF on both attempted parameterisations: not an `EF.CardAccess`
    /// candidate.
    fn refusing_script() -> ReaderScript {
        vec![
            (
                vec![0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00],
                sw_only(0x6A, 0x82),
            ),
            (
                vec![0x00, 0xA4, 0x04, 0x0C, 0x02, 0x3F, 0x00],
                sw_only(0x6A, 0x82),
            ),
        ]
    }

    /// The real ACR1581 shape: SAM slot card-present but not an
    /// eID, PICC slot serving `EF.CardAccess`. The pick must land
    /// on the PICC reader without any filter.
    #[test]
    fn contactless_pick_selects_the_card_access_server() {
        let backend = ScriptedBackend {
            readers: vec![
                (present("Dual Reader SAM"), refusing_script()),
                (present("Dual Reader PICC"), card_access_script()),
            ],
        };
        let id = super::pick_contactless_reader(&backend, None).expect("picks the PICC reader");
        assert_eq!(id.as_str(), "Dual Reader PICC");
    }

    /// No reader serves `EF.CardAccess`: the pick reports
    /// `NoFineidCard` naming every card-present reader (the
    /// eMRTD fallback caller replaces it with the contact-side
    /// error, but the variant must still classify correctly).
    #[test]
    fn contactless_pick_without_servers_is_no_fineid_card() {
        let backend = ScriptedBackend {
            readers: vec![(present("Dual Reader SAM"), refusing_script())],
        };
        assert!(matches!(
            super::pick_contactless_reader(&backend, None),
            Err(ReaderPickError::NoFineidCard { available }) if available == ["Dual Reader SAM"]
        ));
    }

    /// Two serving readers demand a `--reader` filter, and the
    /// filter then disambiguates -- same rules as the contact
    /// pick.
    #[test]
    fn contactless_pick_ambiguity_follows_the_contact_rules() {
        let backend = ScriptedBackend {
            readers: vec![
                (present("Reader A PICC"), card_access_script()),
                (present("Reader B PICC"), card_access_script()),
            ],
        };
        assert!(matches!(
            super::pick_contactless_reader(&backend, None),
            Err(ReaderPickError::MultipleReadersNoFilter { available }) if available.len() == 2
        ));
        let filter = crate::backend::ReaderFilter::new("B PICC");
        let id =
            super::pick_contactless_reader(&backend, Some(&filter)).expect("filter disambiguates");
        assert_eq!(id.as_str(), "Reader B PICC");
    }
}
