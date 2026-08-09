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

//! PC/SC adapter that implements [`refineid_lib_core::backend::ReaderBackend`]
//! and [`refineid_lib_core::transport::CardTransport`] over the
//! `pcsc` crate.
//!
//! Two T=0 transport conventions live here rather than leaking up
//! into use cases:
//!
//! - **`SW=61xx` `GET RESPONSE` chaining.** The card signals "more
//!   bytes available, ask with `Le=xx`". The adapter loops until
//!   the chain terminates and surfaces a single concatenated
//!   body to the caller.
//! - **`SW=6Cxx` wrong-Le retry.** A typed read-only case-2
//!   command may be corrected and resent exactly once. Raw and
//!   credential-bearing commands treat `6Cxx` as terminal.
//!
//! Both paths are bounded so a pathological card can't deadlock
//! the session: the correction permission is consumed by its one
//! use, and the `61xx` chain is bounded by progress plus the
//! `EXTENDED_RESPONSE_DATA_MAX_BYTES` ceiling.
//!
//! ATR + status snapshots are taken with `SCardGetStatusChange`
//! and `SCardStatus2` so the same handle can be reused across
//! many `transmit` calls without an `SCardReconnect`.
//!
//! Atomicity against concurrent card consumers comes from PC/SC
//! transactions, at one of two scopes chosen by
//! [`ReaderAccessCap`] at open:
//!
//! - **`Read`**: every APDU exchange runs in its own transaction
//!   (`Card::transaction()` RAII around the `61xx`/`6Cxx` loop),
//!   so single commands are atomic but concurrent peers may run
//!   between commands. Right for probes, cert reads, and
//!   long-lived sessions that must not starve other consumers.
//! - **`PinSequence`**: ONE transaction is held for the
//!   transport's whole lifetime, so the entire
//!   SELECT -> VERIFY -> operation sequence is atomic -- no peer
//!   can interleave and disturb or consume the card's security
//!   state mid-sequence. The holder must stay busy (resource
//!   managers reset idle transactions), which the
//!   collect-credentials-before-open rule guarantees.

#![forbid(unsafe_code)]

extern crate alloc;

use alloc::ffi::CString;

use pcsc::{Card, Context, Disposition, Protocol, Protocols, ReaderState, Scope, ShareMode, State};

use refineid_lib_core::apdu::iso7816::{ApduClass, GetResponse};
use refineid_lib_core::atr::{Atr, AtrError};
use refineid_lib_core::backend::{ReaderAccessCap, ReaderBackend, ReaderId, ReaderInfo};
use refineid_lib_core::transport::{
    CardTransport, CommandApdu, ResponseApdu, TransportErrorExt, TransportErrorKind,
    TransportOutcome,
};

/// Receive-buffer size for one PC/SC `transmit` call, sized to
/// hold the ISO 7816-4 extended-length APDU max response data
/// field. ISO 7816-4 §5.3.2 caps the extended Le response at
/// `2^16` bytes (encoded as `00 00 00` in the trailing Le); the
/// 2-byte trailing SW1 SW2 lives outside the data field for the
/// purposes of PC/SC's `transmit` accounting. Allocated on the
/// heap so transmitting a max-length response cannot stack-bust
/// on embedded targets.
const EXTENDED_RESPONSE_DATA_MAX_BYTES: usize = 1 << 16;

/// ISO 7816-3 T=0 procedure-byte `SW1` prefixes the transport loop
/// acts on. `61xx` -- more response bytes available; drive
/// `GET RESPONSE` with `SW2` as `Le`. `6Cxx` -- wrong `Le`; resend
/// the same command with `SW2` as the corrected `Le`. Every other
/// `SW1` is terminal and handed back to the caller.
const SW1_BYTES_AVAILABLE: u8 = 0x61;
/// See [`SW1_BYTES_AVAILABLE`]: `6Cxx` wrong-`Le` retry prefix.
const SW1_WRONG_LE: u8 = 0x6C;

/// Convert one short ISO 7816 case-4 command into the case-3 command
/// Windows PC/SC accepts for T=0. The card then announces the response
/// with `61xx`, which [`run_t0_exchange`] continues with `GET RESPONSE`.
///
/// Returns `None` for case-1/2/3 commands and extended-length shapes.
fn t0_case3_from_short_case4(apdu: &CommandApdu) -> Option<CommandApdu> {
    const HEADER_AND_LC_BYTES: usize = 5;
    const TRAILING_LE_BYTES: usize = 1;

    let bytes = apdu.as_bytes();
    let lc = usize::from(*bytes.get(4)?);
    if lc == 0 {
        return None;
    }
    let case4_len = HEADER_AND_LC_BYTES
        .checked_add(lc)?
        .checked_add(TRAILING_LE_BYTES)?;
    if bytes.len() != case4_len {
        return None;
    }

    Some(CommandApdu::new(bytes[..bytes.len() - 1].to_vec()))
}

// ----- Errors -----

/// PC/SC adapter errors.
#[derive(Debug)]
pub enum PcscError {
    /// Underlying `pcsc` crate error (`SCardConnect` /
    /// `SCardTransmit` / `SCardGetStatusChange` / ...).
    Pcsc(pcsc::Error),
    /// Transport-layer logic error with no direct `pcsc::Error`
    /// counterpart (response shorter than 2 bytes, retry-loop
    /// ceiling exceeded, etc.).
    Transport(String),
}

impl From<pcsc::Error> for PcscError {
    fn from(e: pcsc::Error) -> Self {
        Self::Pcsc(e)
    }
}

impl core::fmt::Display for PcscError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Pcsc(e) => write!(f, "PCSC: {e}"),
            Self::Transport(s) => write!(f, "PCSC transport: {s}"),
        }
    }
}

impl core::error::Error for PcscError {}

impl TransportErrorExt for PcscError {
    fn kind(&self) -> TransportErrorKind {
        match self {
            Self::Pcsc(pcsc::Error::NoSmartcard) => TransportErrorKind::NoCard,
            Self::Pcsc(pcsc::Error::RemovedCard) => TransportErrorKind::ReaderRemoved,
            Self::Pcsc(pcsc::Error::ResetCard) => TransportErrorKind::CardReset,
            Self::Transport(_) | Self::Pcsc(_) => TransportErrorKind::Backend,
        }
    }
}

// ----- Context + enumeration helpers -----

/// Establish a fresh PC/SC user-scope context.
///
/// # Errors
/// PC/SC service unavailable or platform-level failure.
pub fn establish_context() -> Result<Context, PcscError> {
    Ok(Context::establish(Scope::User)?)
}

/// Enumerate reader names. Returns an empty `Vec` when no
/// readers are connected (rather than the `NoReadersAvailable`
/// PC/SC error), so callers can treat "no readers" as a normal
/// empty-state.
///
/// # Errors
/// PC/SC service errors other than `NoReadersAvailable`.
pub(crate) fn list_readers(ctx: &Context) -> Result<Vec<String>, PcscError> {
    let mut buffer = [0_u8; 4096];
    let readers = match ctx.list_readers(&mut buffer) {
        Ok(it) => it,
        Err(pcsc::Error::NoReadersAvailable) => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    Ok(readers.map(|r| r.to_string_lossy().into_owned()).collect())
}

/// Open a card on `reader` in shared mode.
///
/// Returns `Ok(Some(_))` when a card is present, `Ok(None)`
/// when the reader is empty / just removed. Callers translate
/// `None` into "slot present, token absent".
///
/// The connection is shared with PC/SC's normal arbitration --
/// all APDU exchanges happen inside transactions (see
/// [`PcscCard::transmit_outcome`]) so concurrent peers can't
/// interleave commands on the same card.
///
/// # Errors
/// Reader name has interior NUL, PC/SC connect failure other
/// than "no card present", or status query failure.
pub(crate) fn connect(ctx: &Context, reader: &str) -> Result<Option<PcscCard>, PcscError> {
    let cstr = CString::new(reader)
        .map_err(|e| PcscError::Transport(format!("reader name has interior NUL: {e}")))?;
    let card = match ctx.connect(&cstr, ShareMode::Shared, Protocols::ANY) {
        Ok(c) => c,
        Err(pcsc::Error::NoSmartcard | pcsc::Error::RemovedCard) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut names_buf = [0_u8; 256];
    let mut atr_buf = [0_u8; pcsc::MAX_ATR_SIZE];
    let status = card.status2(&mut names_buf, &mut atr_buf)?;
    let atr = status.atr().to_vec();
    let protocol = status
        .protocol2()
        .ok_or_else(|| PcscError::Transport("connected card has no active protocol".into()))?;
    Ok(Some(PcscCard {
        card,
        atr,
        protocol,
        holds_transaction: false,
    }))
}

// ----- Connected card -----

/// Connected card wrapped around a `pcsc::Card`. Drops back to
/// the OS PC/SC handle release on `Drop`
/// (`SCardDisconnect(SCARD_LEAVE_CARD)`).
pub struct PcscCard {
    /// Owned `pcsc::Card` handle. Drops to
    /// `SCardDisconnect(SCARD_LEAVE_CARD)` on this struct's
    /// drop; the card is left powered for subsequent connects.
    card: Card,
    /// Card's Answer-To-Reset bytes, captured at connect time
    /// via `SCardStatus`. Cached so the ATR-classification
    /// step (see `refineid-lib-core::Atr`) doesn't have to
    /// re-call into the PC/SC service mid-session.
    atr: Vec<u8>,
    /// Active protocol captured from `SCardStatus`.
    protocol: Protocol,
    /// Whether this transport holds one PC/SC transaction for
    /// its whole lifetime ([`ReaderAccessCap::PinSequence`]).
    /// When set, [`CardTransport::transmit_outcome`] transmits
    /// inside the already-held transaction instead of opening a
    /// per-APDU one; `SCardDisconnect` at drop ends the held
    /// transaction per the PC/SC contract.
    holds_transaction: bool,
}

impl PcscCard {
    /// Begin one PC/SC transaction and hold it for this
    /// transport's whole lifetime (the [`ReaderAccessCap::PinSequence`]
    /// contract): between now and drop, no other card consumer can
    /// interleave an APDU, so a SELECT -> VERIFY -> operation
    /// sequence is atomic against concurrent peers.
    ///
    /// Mechanism: `Card::transaction()` runs
    /// `SCardBeginTransaction`; forgetting the returned RAII guard
    /// skips its `SCardEndTransaction`, leaving the transaction
    /// active on the handle. `SCardDisconnect` at drop ends a held
    /// transaction per the PC/SC contract, so nothing leaks. This
    /// stays within safe Rust -- the guard borrows the card, so it
    /// cannot be *stored* alongside it, but it can be forgotten.
    ///
    /// The caller keeps the transport busy: PC/SC resource
    /// managers reset a card whose transaction sits idle (Windows:
    /// five seconds without an operation), which is fine for a
    /// card-command sequence and exactly the watchdog we want
    /// against a hung holder.
    fn hold_transaction(&mut self) -> Result<(), PcscError> {
        let tx = self.card.transaction()?;
        std::mem::forget(tx);
        self.holds_transaction = true;
        Ok(())
    }

    /// Reset the card, returning it to its post-ATR state.
    ///
    /// `SCardReconnect` with `SCARD_UNPOWER_CARD`: a full power
    /// cycle, which on a contactless slot means dropping the RF
    /// field. Every volatile session state goes with it --
    /// selected DF, any established PACE / secure-messaging
    /// channel, and a **suspended PACE password**.
    ///
    /// The weaker `SCARD_RESET_CARD` (warm reset) was measured
    /// **not** to clear a suspended CAN on this card; only the
    /// unpowered cycle does.
    ///
    /// That last one is why this exists. After a PACE run fails
    /// (wrong CAN), the card suspends the CAN and answers later
    /// PACE attempts as though the CAN were wrong even when it is
    /// correct -- BSI TR-03110-3 §2.4 lets an authentication
    /// password be suspended until the chip is reset. Without a
    /// reset the operator sees a permanent, and false, "CAN did
    /// not match" for the rest of the card's presentation.
    /// Observed on a production FINEID card over an ACR1581 PICC
    /// slot, 2026-07-24.
    ///
    /// This does not prove recovery from `MultiApp` v5's separate
    /// progressive CAN-PACE delay. Its reset rule is undisclosed; see
    /// `doc/bugs/2026-08-09-thales-can-pace-delay.md`.
    ///
    /// The refreshed ATR replaces the cached one, so
    /// [`CardTransport::atr`] keeps reporting what the card
    /// actually answered.
    ///
    /// # Errors
    /// `SCardReconnect` or the follow-up `SCardStatus` failing.
    pub fn reset(&mut self) -> Result<(), PcscError> {
        self.card
            .reconnect(ShareMode::Shared, Protocols::ANY, Disposition::UnpowerCard)?;
        let mut names_buf = [0_u8; 256];
        let mut atr_buf = [0_u8; pcsc::MAX_ATR_SIZE];
        let status = self.card.status2(&mut names_buf, &mut atr_buf)?;
        self.atr = status.atr().to_vec();
        self.protocol = status.protocol2().ok_or_else(|| {
            PcscError::Transport("reconnected card has no active protocol".into())
        })?;
        // SCardReconnect releases a held transaction along with the
        // rest of the session state; re-acquire it so the
        // PinSequence atomicity contract survives a mid-sequence
        // power cycle.
        if self.holds_transaction {
            self.holds_transaction = false;
            self.hold_transaction()?;
        }
        Ok(())
    }
}

impl core::fmt::Debug for PcscCard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Redact the raw OS handle (`pcsc::Card` doesn't impl
        // Debug and even if it did, dumping the handle into a
        // trace would leak per-process resource bookkeeping that
        // isn't useful to a reader). Show just the ATR length so
        // a logger can tell two cards apart by shape.
        f.debug_struct("PcscCard")
            .field("card", &"<pcsc handle>")
            .field("atr_len", &self.atr.len())
            .field("protocol", &self.protocol)
            .field("holds_transaction", &self.holds_transaction)
            .finish()
    }
}

// ----- T=0 transport loop (61xx chaining + 6Cxx retry) -----

/// The single low-level "send one C-APDU, receive its raw R-APDU"
/// primitive the T=0 transport loop drives. The production impl
/// ([`PcscTransmitter`]) forwards to `pcsc::Transaction::transmit`;
/// the loop itself ([`run_t0_exchange`]) is written against this
/// trait so the `61xx` chaining and `6Cxx` retry conventions can be
/// exercised by a scripted fake with no reader attached.
trait T0Transmitter {
    /// Transmit `apdu` and return the card's raw response (data body
    /// followed by the 2-byte `SW1 SW2`) written into `buf`. A
    /// terminal transport state the loop must surface verbatim (the
    /// card removed / reset mid-exchange) is returned as
    /// `Err(TransmitBreak::Outcome(_))`; a hard adapter failure as
    /// `Err(TransmitBreak::Error(_))`.
    fn transmit<'buf>(
        &mut self,
        apdu: &[u8],
        buf: &'buf mut [u8],
    ) -> Result<&'buf [u8], TransmitBreak>;
}

/// Non-continuable result of one [`T0Transmitter::transmit`] call:
/// either a terminal [`TransportOutcome`] to hand straight back to
/// the caller, or a hard [`PcscError`].
enum TransmitBreak {
    /// A terminal transport state (`NoCard` / `ReaderRemoved` /
    /// `CardReset`) the loop returns as `Ok(outcome)`.
    Outcome(TransportOutcome),
    /// A hard adapter error the loop returns as `Err(_)`.
    Error(PcscError),
}

/// Production [`T0Transmitter`] over a live PC/SC card. The card is
/// always inside a transaction when this runs -- either the
/// per-APDU one opened by `transmit_outcome` (reached through the
/// `Transaction`'s deref to [`Card`]) or the held
/// [`ReaderAccessCap::PinSequence`] transaction. Maps the
/// card-state `pcsc::Error` variants to the matching terminal
/// [`TransportOutcome`] so they flow back to the caller unchanged;
/// every other `pcsc::Error` becomes a hard [`PcscError`].
struct PcscTransmitter<'card>(&'card Card);

impl T0Transmitter for PcscTransmitter<'_> {
    fn transmit<'buf>(
        &mut self,
        apdu: &[u8],
        buf: &'buf mut [u8],
    ) -> Result<&'buf [u8], TransmitBreak> {
        match self.0.transmit(apdu, buf) {
            Ok(response) => Ok(response),
            Err(pcsc::Error::NoSmartcard) => Err(TransmitBreak::Outcome(TransportOutcome::NoCard)),
            Err(pcsc::Error::RemovedCard) => {
                Err(TransmitBreak::Outcome(TransportOutcome::ReaderRemoved))
            }
            Err(pcsc::Error::ResetCard) => Err(TransmitBreak::Outcome(TransportOutcome::CardReset)),
            Err(e) => Err(TransmitBreak::Error(e.into())),
        }
    }
}

/// Drive one logical APDU exchange over `transmitter`, applying the
/// two T=0 reader conventions documented at the crate root: the
/// one permitted `6Cxx` wrong-`Le` correction and the `61xx` `GET RESPONSE`
/// chaining (inner loop, bounded by progress plus the
/// [`EXTENDED_RESPONSE_DATA_MAX_BYTES`] ceiling). Returns the single
/// concatenated terminal response, or the transport outcome / error
/// that ended the exchange.
///
/// Split out from [`PcscCard::transmit_outcome`] so the loop logic
/// is exercisable against a scripted [`T0Transmitter`] without a
/// reader.
fn run_t0_exchange<T: T0Transmitter>(
    transmitter: &mut T,
    apdu: &CommandApdu,
) -> Result<TransportOutcome, PcscError> {
    let mut sent = apdu.clone();
    let mut recv_buf = vec![0_u8; EXTENDED_RESPONSE_DATA_MAX_BYTES];
    let mut chain_buf = vec![0_u8; EXTENDED_RESPONSE_DATA_MAX_BYTES];
    loop {
        let response = match transmitter.transmit(sent.as_bytes(), &mut recv_buf) {
            Ok(response) => response,
            Err(TransmitBreak::Outcome(outcome)) => return Ok(outcome),
            Err(TransmitBreak::Error(e)) => return Err(e),
        };
        // Split off the trailing 2-byte SW; `split_last_chunk`
        // returns `None` when the response is too short, which
        // we map to ProtocolDesync rather than panicking via
        // index arithmetic.
        let Some((body, sw_bytes)) = response.split_last_chunk::<2>() else {
            return Ok(TransportOutcome::ProtocolDesync);
        };
        let [sw1, sw2] = *sw_bytes;

        // Only builder-proven read-only case-2 commands permit one
        // corrected resend. Every other 6Cxx is terminal.
        if sw1 == SW1_WRONG_LE
            && let Some(corrected) = sent.corrected_wrong_le(sw2)
        {
            sent = corrected;
            continue;
        }

        // SW=61xx -- more bytes available; loop GET RESPONSE
        // until the chain terminates.
        if sw1 == SW1_BYTES_AVAILABLE {
            let mut combined: Vec<u8> = body.to_vec();
            let mut next_le = sw2;
            let mut chained_sw1: u8;
            let mut chained_sw2: u8;
            loop {
                let get_resp = GetResponse::new(ApduClass::Plain, next_le).into_apdu();
                let chain_resp = match transmitter.transmit(get_resp.as_bytes(), &mut chain_buf) {
                    Ok(response) => response,
                    Err(TransmitBreak::Outcome(outcome)) => return Ok(outcome),
                    Err(TransmitBreak::Error(e)) => return Err(e),
                };
                let Some((chain_body, chain_sw)) = chain_resp.split_last_chunk::<2>() else {
                    return Ok(TransportOutcome::ProtocolDesync);
                };
                let progressed = !chain_body.is_empty();
                let Some(next_len) = combined.len().checked_add(chain_body.len()) else {
                    return Err(PcscError::Transport(
                        "61xx GET RESPONSE chain exceeded 64 KiB".into(),
                    ));
                };
                if next_len > EXTENDED_RESPONSE_DATA_MAX_BYTES {
                    return Err(PcscError::Transport(
                        "61xx GET RESPONSE chain exceeded 64 KiB".into(),
                    ));
                }
                combined.extend_from_slice(chain_body);
                chained_sw1 = chain_sw[0];
                chained_sw2 = chain_sw[1];
                if chained_sw1 == SW1_BYTES_AVAILABLE {
                    // A card that signals "more bytes available"
                    // yet returns an empty body makes no progress:
                    // `combined` never grows, so the byte ceiling
                    // below would never trip and this loop would
                    // spin forever. Bound by progress, not a fixed
                    // count, so a legitimate multi-KiB chain still
                    // completes.
                    if !progressed {
                        return Err(PcscError::Transport(
                            "card signalled 61xx but returned no bytes (stalled chain)".into(),
                        ));
                    }
                    next_le = chained_sw2;
                    continue;
                }
                break;
            }
            return Ok(TransportOutcome::Response(ResponseApdu {
                body: combined,
                sw1: chained_sw1,
                sw2: chained_sw2,
            }));
        }

        // All other status words are terminal -- pass the
        // body + SW back to the use case to interpret.
        return Ok(TransportOutcome::Response(ResponseApdu {
            body: body.to_vec(),
            sw1,
            sw2,
        }));
    }
}

impl CardTransport for PcscCard {
    type Error = PcscError;

    fn transmit_outcome(&mut self, apdu: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
        let t0_command = if self.protocol == Protocol::T0 {
            t0_case3_from_short_case4(apdu)
        } else {
            None
        };
        let physical_command = t0_command.as_ref().unwrap_or(apdu);
        if self.holds_transaction {
            // The whole transport lifetime is one held transaction
            // (ReaderAccessCap::PinSequence); transmit directly
            // inside it. Beginning a nested per-APDU transaction
            // here would be redundant at best and
            // resource-manager-dependent at worst.
            return run_t0_exchange(&mut PcscTransmitter(&self.card), physical_command);
        }
        // Open the per-APDU PC/SC transaction here (so the whole
        // 61xx/6Cxx exchange is atomic against concurrent peers),
        // then hand the byte-level work to `run_t0_exchange` over a
        // live-transaction transmitter (deref to the card).
        let tx = match self.card.transaction() {
            Ok(tx) => tx,
            Err(pcsc::Error::NoSmartcard) => return Ok(TransportOutcome::NoCard),
            Err(pcsc::Error::RemovedCard) => return Ok(TransportOutcome::ReaderRemoved),
            Err(pcsc::Error::ResetCard) => return Ok(TransportOutcome::CardReset),
            Err(e) => return Err(e.into()),
        };
        run_t0_exchange(&mut PcscTransmitter(&tx), physical_command)
    }

    fn atr(&self) -> Result<Atr, AtrError> {
        Atr::new(&self.atr)
    }
}

// ----- ReaderBackend -----

/// Reader (IFD) hardware version from
/// `SCARD_ATTR_VENDOR_IFD_VERSION`.
///
/// The attribute is a DWORD encoded `0xMMmmbbbb` (PC/SC Workgroup
/// spec Part 3 s3.1.9.3 -- `MM` major, `mm` minor, `bbbb` build),
/// arriving little-endian, so the major is the fourth byte and
/// the minor the third.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IfdVersion {
    /// Version major (`MM` of the attribute DWORD).
    pub major: u8,
    /// Version minor (`mm` of the attribute DWORD).
    pub minor: u8,
}

/// Reader (IFD) identity attributes for one reader: what the
/// reader's own driver reports about the physical device, as
/// opposed to the card in it.
#[derive(Debug, Clone, Default)]
pub struct ReaderIdentity {
    /// `SCARD_ATTR_VENDOR_NAME`: the reader vendor (for example
    /// "HID Global"), NUL/whitespace-trimmed. `None` when the
    /// driver does not supply the attribute.
    pub vendor_name: Option<String>,
    /// `SCARD_ATTR_VENDOR_IFD_VERSION`, parsed. `None` when the
    /// driver does not supply the attribute or it is too short.
    pub ifd_version: Option<IfdVersion>,
}

/// Read the reader's own identity attributes via `SCardGetAttrib`
/// on a direct-mode (card-less) connection.
///
/// Direct mode talks to the reader driver, not the card, so this
/// works on an empty reader and does not contend with a card
/// session held by a peer.
///
/// Best-effort by design: any context / connect / attribute
/// failure yields the field-level `None`s of
/// [`ReaderIdentity::default`], never an error -- reader identity
/// is cosmetic metadata and must not break slot enumeration.
#[must_use]
pub fn read_reader_identity(reader: &ReaderId) -> ReaderIdentity {
    let Ok(ctx) = establish_context() else {
        return ReaderIdentity::default();
    };
    let Ok(cstr) = CString::new(reader.as_str()) else {
        return ReaderIdentity::default();
    };
    let Ok(card) = ctx.connect(&cstr, ShareMode::Direct, Protocols::UNDEFINED) else {
        return ReaderIdentity::default();
    };
    let mut vendor_buf = [0_u8; 128];
    let vendor_name = card
        .get_attribute(pcsc::Attribute::VendorName, &mut vendor_buf)
        .ok()
        .map(|bytes| {
            String::from_utf8_lossy(bytes)
                .trim_matches(|c: char| c == '\0' || c.is_whitespace())
                .to_owned()
        })
        .filter(|name| !name.is_empty());
    let mut version_buf = [0_u8; 16];
    let ifd_version = card
        .get_attribute(pcsc::Attribute::VendorIfdVersion, &mut version_buf)
        .ok()
        .and_then(|bytes| match bytes {
            [_build_lo, _build_hi, minor, major, ..] => Some(IfdVersion {
                major: *major,
                minor: *minor,
            }),
            _short => None,
        });
    ReaderIdentity {
        vendor_name,
        ifd_version,
    }
}

/// CCID escape control code, Windows convention: the ACS
/// reference manuals specify `0x310000 + 3500 * 4`, the Windows
/// `SCARD_CTL_CODE(3500)` value (ACR1581U Reference Manual
/// s5.1.4). `pcsc::DWORD`-typed because the PC/SC `DWORD` differs
/// per platform (u64 on pcsc-lite/64-bit, u32 on Windows/macOS).
const CCID_ESCAPE_CONTROL_CODE_WINDOWS: pcsc::ffi::DWORD = 0x0031_0000 + 3500 * 4;

/// CCID escape control code, pcsc-lite convention:
/// `SCARD_CTL_CODE(x)` is `0x42000000 + x` there, and Apple's
/// PC/SC follows it -- the Windows code is rejected with an
/// invalid-value error on macOS (measured against an ACR1581).
const CCID_ESCAPE_CONTROL_CODE_PCSC_LITE: pcsc::ffi::DWORD = 0x4200_0000 + 3500;

/// pcsc-lite's `IOCTL_SMARTCARD_VENDOR_IFD_EXCHANGE`
/// (`SCARD_CTL_CODE(1)`), which some stacks whitelist as the only
/// permitted escape route.
const VENDOR_IFD_EXCHANGE_CONTROL_CODE: pcsc::ffi::DWORD = 0x4200_0000 + 1;

/// Send a vendor escape command to the reader itself over a
/// direct-mode (card-less) connection and return the raw
/// response bytes.
///
/// Direct mode talks to the reader driver, not the card, so a
/// card need not be present and no card session is disturbed.
/// The command bytes are vendor protocol (for ACS readers the
/// `E0 ...` escape set); interpreting the response is the
/// caller's business.
///
/// # Errors
/// Context, connect, or `SCardControl` failure.
pub fn reader_escape(reader: &ReaderId, command: &[u8]) -> Result<Vec<u8>, PcscError> {
    let ctx = establish_context()?;
    let cstr = CString::new(reader.as_str())
        .map_err(|e| PcscError::Transport(format!("reader name has interior NUL: {e}")))?;
    let mut recv = [0_u8; 300];
    // The escape control codes in the wild: pcsc-lite's
    // IOCTL_CCID_ESCAPE, the Windows value from the vendor
    // manuals, and pcsc-lite's IOCTL_SMARTCARD_VENDOR_IFD_EXCHANGE
    // which some stacks whitelist exclusively.
    let codes = [
        CCID_ESCAPE_CONTROL_CODE_PCSC_LITE,
        CCID_ESCAPE_CONTROL_CODE_WINDOWS,
        VENDOR_IFD_EXCHANGE_CONTROL_CODE,
    ];
    // Route 1: SCardControl on a direct-mode (card-less)
    // connection -- the route the vendor manuals document.
    if let Ok(card) = ctx.connect(&cstr, ShareMode::Direct, Protocols::UNDEFINED) {
        for code in codes {
            match card.control(code, command, &mut recv) {
                Ok(bytes) => return Ok(bytes.to_vec()),
                Err(pcsc::Error::InvalidValue | pcsc::Error::InvalidParameter) => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
    // Route 2: SCardControl on a shared card connection -- some
    // stacks only honor control on an active card handle.
    let card = ctx.connect(&cstr, ShareMode::Shared, Protocols::ANY)?;
    for code in codes {
        match card.control(code, command, &mut recv) {
            Ok(bytes) => return Ok(bytes.to_vec()),
            Err(pcsc::Error::InvalidValue | pcsc::Error::InvalidParameter) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err(PcscError::Transport(
        "reader escape rejected on every control route (SCardControl blocked?)".into(),
    ))
}

/// Default desktop reader backend implementation. Stateless --
/// each call builds a fresh PC/SC context.
#[derive(Debug, Default, Clone, Copy)]
pub struct PcscBackend;

impl ReaderBackend for PcscBackend {
    type Transport = PcscCard;
    type Error = PcscError;

    fn enumerate(&self) -> Result<Vec<ReaderInfo>, Self::Error> {
        let ctx = establish_context()?;
        let names = list_readers(&ctx)?;
        let mut out = Vec::with_capacity(names.len());
        for name in names {
            let cstr = CString::new(name.as_str())
                .map_err(|e| PcscError::Transport(format!("reader name has interior NUL: {e}")))?;
            // Card-presence probe: SCardGetStatusChange with a
            // zero timeout. Doesn't open a card session so it
            // won't contend with peers running PACE.
            let mut states = vec![ReaderState::new(cstr, State::UNAWARE)];
            let card_present = match ctx.get_status_change(core::time::Duration::ZERO, &mut states)
            {
                Ok(()) | Err(pcsc::Error::Timeout) => {
                    // `states` was constructed with exactly one
                    // element above, so `.first()` is always
                    // `Some`. Use a typed match to keep the access
                    // panic-free even if the loop body is later
                    // edited to push more states.
                    let Some(state) = states.first() else {
                        return Err(PcscError::Transport(
                            "reader-state vector unexpectedly empty".into(),
                        ));
                    };
                    let event = state.event_state();
                    event.contains(State::PRESENT) && !event.contains(State::EMPTY)
                }
                Err(e) => return Err(e.into()),
            };
            out.push(ReaderInfo {
                id: ReaderId::new(name),
                card_present,
            });
        }
        Ok(out)
    }

    fn open_session(
        &self,
        reader: &ReaderId,
        access: ReaderAccessCap,
    ) -> Result<Self::Transport, Self::Error> {
        let ctx = establish_context()?;
        let mut card =
            connect(&ctx, reader.as_str())?.ok_or(PcscError::Pcsc(pcsc::Error::NoSmartcard))?;
        if matches!(access, ReaderAccessCap::PinSequence) {
            card.hold_transaction()?;
        }
        Ok(card)
    }
}

// ----- Presence monitoring -----

/// Reader names paired with card-present flags, as sampled by
/// [`presence_signature`]. Two signatures compare equal exactly when
/// the same readers are attached and the same slots hold a card.
pub type PresenceSignature = Vec<(String, bool)>;

/// Sample the current reader / card-presence signature.
///
/// Uses `SCardGetStatusChange` presence probes only -- no card is
/// ever opened, so sampling cannot disturb a peer mid-operation
/// (a TLS handshake signing on the card, a PACE session).
///
/// # Errors
/// PC/SC service unavailable or platform-level failure.
pub fn presence_signature() -> Result<PresenceSignature, PcscError> {
    use refineid_lib_core::backend::ReaderBackend as _;
    Ok(PcscBackend
        .enumerate()?
        .into_iter()
        .map(|info| (info.id.as_str().to_owned(), info.card_present))
        .collect())
}

/// Block until the reader set or card presence differs from
/// `baseline`, or `timeout` elapses. `Ok(true)` means the signature
/// changed; `Ok(false)` means the wait timed out with nothing to do.
///
/// The wait parks inside `SCardGetStatusChange` (readers plus the
/// `PnP` pseudo-reader, so reader arrival wakes it too) and never
/// opens a card. Peer activity that does not change presence -- a
/// browser holding the card for a signature -- is deliberately not
/// a wake-up: reacting to it is how a poller disturbs the peer.
///
/// # Errors
/// PC/SC service unavailable or platform-level failure.
pub fn wait_for_presence_change(
    baseline: &[(String, bool)],
    timeout: core::time::Duration,
) -> Result<bool, PcscError> {
    if presence_signature()? != baseline {
        return Ok(true);
    }
    let ctx = establish_context()?;
    let names = list_readers(&ctx)?;
    let mut states = Vec::with_capacity(names.len().saturating_add(1));
    states.push(ReaderState::new(pcsc::PNP_NOTIFICATION(), State::UNAWARE));
    for name in &names {
        let cstr = CString::new(name.as_str())
            .map_err(|e| PcscError::Transport(format!("reader name has interior NUL: {e}")))?;
        states.push(ReaderState::new(cstr, State::UNAWARE));
    }
    // Prime the current state from a zero-timeout call: UNAWARE
    // entries otherwise report CHANGED immediately and the blocking
    // wait would never park.
    match ctx.get_status_change(core::time::Duration::ZERO, &mut states) {
        Ok(()) | Err(pcsc::Error::Timeout) => {}
        Err(e) => return Err(e.into()),
    }
    for state in &mut states {
        state.sync_current_state();
    }
    match ctx.get_status_change(timeout, &mut states) {
        Ok(()) => Ok(presence_signature()? != baseline),
        Err(pcsc::Error::Timeout) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {

    use super::{
        EXTENDED_RESPONSE_DATA_MAX_BYTES, PcscError, ResponseApdu, SW1_BYTES_AVAILABLE,
        SW1_WRONG_LE, T0Transmitter, TransmitBreak, TransportErrorExt as _, TransportErrorKind,
        TransportOutcome, run_t0_exchange, t0_case3_from_short_case4,
    };
    use refineid_lib_core::apdu::iso7816::{ApduClass, GetResponse};
    use refineid_lib_core::transport::CommandApdu;

    /// One scripted action the fake card performs on a single
    /// [`T0Transmitter::transmit`] call, consumed in order.
    enum Step {
        /// Hand back these raw R-APDU bytes (data body followed by
        /// the trailing `SW1 SW2`).
        Reply(Vec<u8>),
        /// Surface this terminal transport outcome -- mirrors a real
        /// `pcsc::transmit` reporting the card removed / reset
        /// mid-exchange.
        Outcome(TransportOutcome),
        /// Fail with this hard adapter error.
        Error(PcscError),
    }

    /// [`T0Transmitter`] that replays a fixed list of [`Step`]s and
    /// records every C-APDU the loop emitted, so a test can assert
    /// both the result and the exact bytes the loop put on the wire
    /// (rewritten `Le`, `GET RESPONSE` shape, retry count).
    struct ScriptedCard {
        /// Remaining steps, stored reversed so `pop()` yields them
        /// in the caller's original order.
        steps: Vec<Step>,
        /// Every C-APDU passed to `transmit`, in order.
        sent: Vec<Vec<u8>>,
    }

    impl ScriptedCard {
        /// Build a fake card that will perform `steps` in order.
        fn new(mut steps: Vec<Step>) -> Self {
            steps.reverse();
            Self {
                steps,
                sent: Vec::new(),
            }
        }
    }

    impl T0Transmitter for ScriptedCard {
        fn transmit<'buf>(
            &mut self,
            apdu: &[u8],
            buf: &'buf mut [u8],
        ) -> Result<&'buf [u8], TransmitBreak> {
            self.sent.push(apdu.to_vec());
            match self
                .steps
                .pop()
                .expect("scripted card: no step queued for this transmit")
            {
                Step::Reply(bytes) => {
                    buf[..bytes.len()].copy_from_slice(&bytes);
                    Ok(&buf[..bytes.len()])
                }
                Step::Outcome(outcome) => Err(TransmitBreak::Outcome(outcome)),
                Step::Error(err) => Err(TransmitBreak::Error(err)),
            }
        }
    }

    /// Build one scripted reply: `body` bytes followed by the 2-byte
    /// status word, exactly as a card lays an R-APDU on the wire.
    fn reply(body: &[u8], sw1: u8, sw2: u8) -> Step {
        let mut raw = body.to_vec();
        raw.push(sw1);
        raw.push(sw2);
        Step::Reply(raw)
    }

    /// Wire bytes of the plain-class `GET RESPONSE` the chaining loop
    /// emits for a given `Le` (`CLA=00 INS=C0 P1=00 P2=00 Le`).
    fn get_response(le: u8) -> Vec<u8> {
        vec![0x00, 0xC0, 0x00, 0x00, le]
    }

    /// Run the T=0 loop against a scripted card, returning the loop
    /// result paired with every C-APDU the loop transmitted.
    fn drive<A: Into<CommandApdu>>(
        steps: Vec<Step>,
        apdu: A,
    ) -> (Result<TransportOutcome, PcscError>, Vec<Vec<u8>>) {
        let mut card = ScriptedCard::new(steps);
        let apdu = apdu.into();
        let outcome = run_t0_exchange(&mut card, &apdu);
        (outcome, card.sent)
    }

    // ----- Terminal status: no looping -----

    #[test]
    fn t0_short_case4_is_sent_as_case3_then_continued() {
        let logical = CommandApdu::from(
            &[
                0x00, 0xCB, 0x00, 0xFF, 0x05, 0xA0, 0x03, 0x83, 0x01, 0x83, 0x00,
            ][..],
        );
        let physical =
            t0_case3_from_short_case4(&logical).expect("short case-4 command is recognized");
        let (outcome, sent) = drive(
            vec![
                reply(&[], SW1_BYTES_AVAILABLE, 0x02),
                reply(&[0xAA, 0xBB], 0x90, 0x00),
            ],
            physical,
        );

        assert!(matches!(
            outcome,
            Ok(TransportOutcome::Response(ResponseApdu {
                body,
                sw1: 0x90,
                sw2: 0x00,
            })) if body == [0xAA, 0xBB]
        ));
        assert_eq!(
            sent,
            vec![
                vec![0x00, 0xCB, 0x00, 0xFF, 0x05, 0xA0, 0x03, 0x83, 0x01, 0x83],
                get_response(0x02),
            ]
        );
    }

    #[test]
    fn terminal_status_passes_through_without_get_response() {
        let apdu = [0x00, 0xA4, 0x04, 0x00];
        let (outcome, sent) = drive(vec![reply(&[0xAA, 0xBB], 0x90, 0x00)], &apdu);
        assert_eq!(
            outcome.expect("terminal-SW exchange completes"),
            TransportOutcome::Response(ResponseApdu {
                body: vec![0xAA, 0xBB],
                sw1: 0x90,
                sw2: 0x00,
            })
        );
        // A terminal SW must not trigger any GET RESPONSE / resend.
        assert_eq!(sent, vec![apdu.to_vec()]);
    }

    #[test]
    fn non_9000_terminal_status_is_handed_back_verbatim() {
        // 6A82 (file not found) is terminal -- the loop passes the
        // body+SW up untouched, it is not a 61xx/6Cxx procedure byte.
        let (outcome, sent) = drive(
            vec![reply(&[], 0x6A, 0x82)],
            &[0x00, 0xB0, 0x00, 0x00, 0x10],
        );
        assert_eq!(
            outcome.expect("6A82 exchange completes"),
            TransportOutcome::Response(ResponseApdu {
                body: vec![],
                sw1: 0x6A,
                sw2: 0x82,
            })
        );
        assert_eq!(sent.len(), 1);
    }

    // ----- 6Cxx wrong-Le retry -----

    #[test]
    fn wrong_le_6c_retry_rewrites_last_byte_and_resends() {
        let apdu = GetResponse::new(ApduClass::Plain, 0).into_apdu();
        let body = vec![0x11_u8; 0x1A];
        let (outcome, sent) = drive(
            vec![reply(&[], SW1_WRONG_LE, 0x1A), reply(&body, 0x90, 0x00)],
            apdu,
        );
        assert_eq!(
            outcome.expect("6C retry exchange completes"),
            TransportOutcome::Response(ResponseApdu {
                body,
                sw1: 0x90,
                sw2: 0x00,
            })
        );
        // Exactly one resend, with only the trailing Le byte rewritten
        // to the card's requested 0x1A.
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0], vec![0x00, 0xC0, 0x00, 0x00, 0x00]);
        assert_eq!(sent[1], vec![0x00, 0xC0, 0x00, 0x00, 0x1A]);
    }

    #[test]
    fn wrong_le_6c_on_raw_command_is_terminal() {
        let (outcome, sent) = drive(vec![reply(&[], SW1_WRONG_LE, 0x05)], &[]);
        assert_eq!(
            outcome.expect("raw-command 6C response completes"),
            TransportOutcome::Response(ResponseApdu {
                body: vec![],
                sw1: SW1_WRONG_LE,
                sw2: 0x05,
            })
        );
        assert_eq!(sent, vec![Vec::<u8>::new()]);
    }

    #[test]
    fn pin1_unblock_6c_is_one_physical_transmit() {
        const PLAIN_CLASS: u8 = 0x00;
        const RESET_RETRY_COUNTER_INSTRUCTION: u8 = 0x2C;
        const RESET_AND_REPLACE_MODE: u8 = 0x00;
        const PIN1_REFERENCE_PKCS15: u8 = 0x11;
        const PAD_BYTE: u8 = 0x00;
        const PADDED_PAIR_LENGTH: u8 = 0x18;
        const WRONG_LENGTH_HINT: u8 = 0x18;

        let mut wire = vec![
            PLAIN_CLASS,
            RESET_RETRY_COUNTER_INSTRUCTION,
            RESET_AND_REPLACE_MODE,
            PIN1_REFERENCE_PKCS15,
            PADDED_PAIR_LENGTH,
        ];
        wire.extend_from_slice(b"49071234");
        wire.extend_from_slice(&[PAD_BYTE; 4]);
        wire.extend_from_slice(b"4907");
        wire.extend_from_slice(&[PAD_BYTE; 8]);
        let command = CommandApdu::from(wire.as_slice());
        let expected = command.as_bytes().to_vec();

        let (outcome, sent) = drive(vec![reply(&[], SW1_WRONG_LE, WRONG_LENGTH_HINT)], command);
        assert!(matches!(
            outcome,
            Ok(TransportOutcome::Response(response))
                if response.sw1 == SW1_WRONG_LE && response.sw2 == WRONG_LENGTH_HINT
        ));
        assert_eq!(sent, vec![expected]);
    }

    #[test]
    fn second_wrong_le_is_terminal_after_one_retry() {
        let apdu = GetResponse::new(ApduClass::Plain, 0).into_apdu();
        let (outcome, sent) = drive(
            vec![
                reply(&[], SW1_WRONG_LE, 0x10),
                reply(&[], SW1_WRONG_LE, 0x20),
            ],
            apdu,
        );
        assert_eq!(
            outcome.expect("second 6C response is terminal"),
            TransportOutcome::Response(ResponseApdu {
                body: vec![],
                sw1: SW1_WRONG_LE,
                sw2: 0x20,
            })
        );
        assert_eq!(sent.len(), 2);
    }

    // ----- 61xx GET RESPONSE chaining -----

    #[test]
    fn bytes_available_61_single_get_response_concatenates() {
        let apdu = [0x00, 0xCA, 0x00, 0x00, 0x00];
        let (outcome, sent) = drive(
            vec![
                reply(&[0x01, 0x02], SW1_BYTES_AVAILABLE, 0x05),
                reply(&[0x03, 0x04, 0x05, 0x06, 0x07], 0x90, 0x00),
            ],
            &apdu,
        );
        assert_eq!(
            outcome.expect("single-hop 61xx chain completes"),
            TransportOutcome::Response(ResponseApdu {
                // First-response body + the GET RESPONSE body, in order.
                body: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
                sw1: 0x90,
                sw2: 0x00,
            })
        );
        assert_eq!(sent.len(), 2);
        // GET RESPONSE carries the card's reported SW2 (0x05) as Le.
        assert_eq!(sent[1], get_response(0x05));
    }

    #[test]
    fn bytes_available_61_multi_hop_chain_concatenates_in_order() {
        let (outcome, sent) = drive(
            vec![
                reply(&[0xA0], SW1_BYTES_AVAILABLE, 0x02),
                reply(&[0xB0, 0xB1], SW1_BYTES_AVAILABLE, 0x03),
                reply(&[0xC0, 0xC1, 0xC2], 0x90, 0x00),
            ],
            &[0x00, 0xCA, 0x00, 0x00, 0x00],
        );
        assert_eq!(
            outcome.expect("multi-hop 61xx chain completes"),
            TransportOutcome::Response(ResponseApdu {
                body: vec![0xA0, 0xB0, 0xB1, 0xC0, 0xC1, 0xC2],
                sw1: 0x90,
                sw2: 0x00,
            })
        );
        // Two GET RESPONSEs, each carrying the previous hop's SW2 as Le.
        assert_eq!(sent.len(), 3);
        assert_eq!(sent[1], get_response(0x02));
        assert_eq!(sent[2], get_response(0x03));
    }

    #[test]
    fn chain_terminal_status_word_is_preserved() {
        // The SW that ends the chain (here a non-9000 warning) is the
        // one surfaced, not the intermediate 61xx procedure bytes.
        let (outcome, _sent) = drive(
            vec![
                reply(&[0xA0], SW1_BYTES_AVAILABLE, 0x02),
                reply(&[0xB0, 0xB1], 0x63, 0x00),
            ],
            &[0x00, 0xCA, 0x00, 0x00, 0x00],
        );
        assert_eq!(
            outcome.expect("chain with terminal warning SW completes"),
            TransportOutcome::Response(ResponseApdu {
                body: vec![0xA0, 0xB0, 0xB1],
                sw1: 0x63,
                sw2: 0x00,
            })
        );
    }

    #[test]
    fn stalled_61_chain_with_no_progress_is_rejected() {
        // Card claims "more bytes" yet hands back an empty body: no
        // progress, so the loop must bail rather than spin forever.
        let (outcome, _sent) = drive(
            vec![
                reply(&[0x01], SW1_BYTES_AVAILABLE, 0x02),
                reply(&[], SW1_BYTES_AVAILABLE, 0x02),
            ],
            &[0x00, 0xCA, 0x00, 0x00, 0x00],
        );
        match outcome {
            Err(PcscError::Transport(msg)) => {
                assert!(msg.contains("stalled chain"), "unexpected message: {msg}");
            }
            other => panic!("expected stalled-chain Transport error, got {other:?}"),
        }
    }

    #[test]
    fn chain_exceeding_64_kib_ceiling_is_rejected() {
        // Two 40 KiB hops still signalling 61xx push `combined` past
        // the 64 KiB extended-response ceiling -> hard reject.
        let chunk = 40_000;
        assert!(chunk + 2 <= EXTENDED_RESPONSE_DATA_MAX_BYTES);
        let big = vec![0xAB_u8; chunk];
        let (outcome, sent) = drive(
            vec![
                reply(&[], SW1_BYTES_AVAILABLE, 0xFF),
                reply(&big, SW1_BYTES_AVAILABLE, 0xFF),
                reply(&big, SW1_BYTES_AVAILABLE, 0xFF),
            ],
            &[0x00, 0xCA, 0x00, 0x00, 0x00],
        );
        match outcome {
            Err(PcscError::Transport(msg)) => {
                assert!(msg.contains("64 KiB"), "unexpected message: {msg}");
            }
            other => panic!("expected ceiling Transport error, got {other:?}"),
        }
        // First transmit + two chain hops, then the ceiling trips.
        assert_eq!(sent.len(), 3);
    }

    // ----- Short / malformed responses -----

    #[test]
    fn short_first_response_maps_to_protocol_desync() {
        // Fewer than 2 bytes back cannot carry an SW pair.
        let (single, _) = drive(vec![Step::Reply(vec![0x90])], &[0x00, 0xA4]);
        assert_eq!(
            single.expect("one-byte reply maps to an outcome"),
            TransportOutcome::ProtocolDesync
        );
        let (empty, _) = drive(vec![Step::Reply(vec![])], &[0x00, 0xA4]);
        assert_eq!(
            empty.expect("empty reply maps to an outcome"),
            TransportOutcome::ProtocolDesync
        );
    }

    #[test]
    fn short_chain_response_maps_to_protocol_desync() {
        // The inner GET RESPONSE leg has its own short-response guard.
        let (outcome, _) = drive(
            vec![
                reply(&[0x01], SW1_BYTES_AVAILABLE, 0x02),
                Step::Reply(vec![0x61]),
            ],
            &[0x00, 0xCA, 0x00, 0x00, 0x00],
        );
        assert_eq!(
            outcome.expect("short chain reply maps to an outcome"),
            TransportOutcome::ProtocolDesync
        );
    }

    // ----- Transmit-level interrupts surfaced verbatim -----

    #[test]
    fn terminal_outcome_from_first_transmit_is_surfaced() {
        let (outcome, _) = drive(
            vec![Step::Outcome(TransportOutcome::ReaderRemoved)],
            &[0x00, 0xA4],
        );
        assert_eq!(
            outcome.expect("reader-removed outcome surfaces"),
            TransportOutcome::ReaderRemoved
        );
    }

    #[test]
    fn terminal_outcome_from_chain_transmit_is_surfaced() {
        // A card vanishing mid-chain surfaces the same outcome.
        let (outcome, _) = drive(
            vec![
                reply(&[0x01], SW1_BYTES_AVAILABLE, 0x02),
                Step::Outcome(TransportOutcome::CardReset),
            ],
            &[0x00, 0xCA, 0x00, 0x00, 0x00],
        );
        assert_eq!(
            outcome.expect("card-reset outcome surfaces"),
            TransportOutcome::CardReset
        );
    }

    #[test]
    fn hard_error_from_first_transmit_propagates() {
        let (outcome, _) = drive(
            vec![Step::Error(PcscError::Transport("boom".into()))],
            &[0x00, 0xA4],
        );
        match outcome {
            Err(PcscError::Transport(msg)) => assert_eq!(msg, "boom"),
            other => panic!("expected propagated Transport error, got {other:?}"),
        }
    }

    #[test]
    fn hard_error_from_chain_transmit_propagates() {
        let (outcome, _) = drive(
            vec![
                reply(&[0x01], SW1_BYTES_AVAILABLE, 0x02),
                Step::Error(PcscError::Pcsc(pcsc::Error::InvalidValue)),
            ],
            &[0x00, 0xCA, 0x00, 0x00, 0x00],
        );
        assert!(matches!(outcome, Err(PcscError::Pcsc(_))));
    }

    // ----- Error classification + Display -----

    #[test]
    fn pcsc_error_kind_classification() {
        assert_eq!(
            PcscError::Pcsc(pcsc::Error::NoSmartcard).kind(),
            TransportErrorKind::NoCard
        );
        assert_eq!(
            PcscError::Pcsc(pcsc::Error::RemovedCard).kind(),
            TransportErrorKind::ReaderRemoved
        );
        assert_eq!(
            PcscError::Pcsc(pcsc::Error::ResetCard).kind(),
            TransportErrorKind::CardReset
        );
        // Any other pcsc error and all Transport errors are Backend.
        assert_eq!(
            PcscError::Pcsc(pcsc::Error::InvalidValue).kind(),
            TransportErrorKind::Backend
        );
        assert_eq!(
            PcscError::Transport("x".into()).kind(),
            TransportErrorKind::Backend
        );
    }

    #[test]
    fn pcsc_error_display_arms() {
        assert_eq!(
            PcscError::Transport("boom".into()).to_string(),
            "PCSC transport: boom"
        );
        let pcsc_display = PcscError::Pcsc(pcsc::Error::NoSmartcard).to_string();
        assert!(
            pcsc_display.starts_with("PCSC: "),
            "unexpected Display: {pcsc_display}"
        );
    }

    /// Hardware smoke for the [`ReaderAccessCap::PinSequence`] held
    /// transaction: commands run inside the held transaction, and
    /// dropping the transport releases it (a second `PinSequence`
    /// open on the same reader must succeed and operate).
    ///
    /// Ignored by default: needs a FINEID card in a PC/SC reader.
    /// Run with `cargo test -p refineid-lib-pcsc -- --ignored`.
    #[test]
    #[ignore = "requires a FINEID card present in a PC/SC reader"]
    fn pin_sequence_held_transaction_smoke() {
        use refineid_lib_core::backend::{ReaderAccessCap, ReaderBackend as _};
        use refineid_lib_core::pkcs15::Pkcs15Ops as _;

        use super::PcscBackend;

        let backend = PcscBackend;
        let readers = backend.enumerate().expect("enumerate readers");
        let Some(reader) = readers.into_iter().find(|r| r.card_present) else {
            eprintln!("skip: no card-present reader");
            return;
        };
        let mut card = backend
            .open_session(&reader.id, ReaderAccessCap::PinSequence)
            .expect("open with held transaction");
        card.select_pkcs15_application()
            .expect("SELECT inside the held transaction");
        card.select_pkcs15_application()
            .expect("second SELECT inside the same held transaction");
        drop(card);
        let mut card = backend
            .open_session(&reader.id, ReaderAccessCap::PinSequence)
            .expect("reopen: drop must have released the held transaction");
        card.select_pkcs15_application()
            .expect("SELECT after reopen");
    }
}
