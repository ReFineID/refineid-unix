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

//! Card transport port.
//!
//! [`CardTransport`] is the boundary between the protocol layer
//! and the actual card-access mechanism (PC/SC today; future NFC,
//! USB CCID, embedded HAL). Adapters that satisfy this trait live
//! in their own crates so the protocol layer stays unaware of
//! where the bytes are going.

use crate::apdu::status_word::StatusWord;
use crate::atr::{Atr, AtrError};

/// One outgoing smart-card command APDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandApdu {
    /// Raw ISO 7816-4 command APDU bytes (`CLA INS P1 P2 [Lc
    /// data] [Le]`). The typed command builders construct this
    /// field; downstream code reads through [`Self::as_bytes`]
    /// without re-parsing.
    bytes: Vec<u8>,
    /// Whether a T=0 adapter may correct `Le` once after `6Cxx`.
    /// Raw APDUs and all credential-bearing commands default to
    /// `false`; only typed, read-only case-2 builders opt in.
    wrong_le_retry: bool,
}

impl CommandApdu {
    /// Wrap an owned byte buffer as a `CommandApdu`. No
    /// structural check; the typed command builders
    /// (`MseSetDst::into_apdu`, etc.) are the boundary that
    /// guarantees a well-formed ISO 7816-4 command shape.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            wrong_le_retry: false,
        }
    }

    /// Mark a builder-proven short case-2 command as safe for one
    /// corrected-`Le` retry. This is intentionally crate-private:
    /// transport adapters and callers handling raw APDUs cannot opt
    /// arbitrary commands into replay.
    #[must_use]
    pub(crate) fn allow_wrong_le_retry(mut self) -> Self {
        const SHORT_CASE_2_BYTES: usize = 5;
        debug_assert_eq!(self.bytes.len(), SHORT_CASE_2_BYTES);
        self.wrong_le_retry = self.bytes.len() == SHORT_CASE_2_BYTES;
        self
    }

    /// Return the single corrected command permitted by a typed
    /// read-only builder. The returned command cannot be corrected
    /// again, so adapters cannot replay indefinitely after repeated
    /// `6Cxx` responses.
    #[must_use]
    pub fn corrected_wrong_le(&self, le: u8) -> Option<Self> {
        if !self.wrong_le_retry {
            return None;
        }
        let mut corrected = self.clone();
        let last = corrected.bytes.last_mut()?;
        *last = le;
        corrected.wrong_le_retry = false;
        Some(corrected)
    }

    /// Borrow the underlying APDU bytes for transmission to the
    /// transport adapter.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the command and return the owned APDU bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl From<Vec<u8>> for CommandApdu {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<&[u8]> for CommandApdu {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }
}

impl<const N: usize> From<&[u8; N]> for CommandApdu {
    fn from(bytes: &[u8; N]) -> Self {
        Self::new(bytes.to_vec())
    }
}

impl AsRef<[u8]> for CommandApdu {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// One smartcard APDU response: body plus the two status bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseApdu {
    /// Response data body (excluding SW1/SW2). Empty for
    /// status-only responses. Tier 0 `Vec<u8>` -- the typed
    /// shape depends on the command (cert DER, PIN status, ...).
    pub body: Vec<u8>,
    /// First status byte per ISO 7816-4 §5.1.3. Tier 0 `u8`;
    /// the typed projection is
    /// `StatusWord` via
    /// [`status_word`](Self::status_word).
    pub sw1: u8,
    /// Second status byte per ISO 7816-4 §5.1.3. Tier 0 `u8`.
    pub sw2: u8,
}

impl ResponseApdu {
    /// `SW1 << 8 | SW2` as a raw `u16`. Prefer
    /// [`status_word`] for typed matching; the raw value is
    /// kept available for diagnostics and JSON-Lines event
    /// fields where the typed enum would lose the exact byte
    /// shape.
    ///
    /// [`status_word`]: ResponseApdu::status_word
    #[must_use]
    pub const fn sw(&self) -> u16 {
        // `u16::from(u8)` is not yet const-callable (the
        // `From` trait is not const-stable). The widening
        // `as u16` cast is exact for u8 -> u16; the per-site
        // allow is the minimal escape hatch in a const fn.
        #[expect(
            clippy::as_conversions,
            reason = "u8 -> u16 widening in a const fn; u16::from is not const-callable (From trait not yet const-stable). The widening is exact; cast_lossless is no longer suppressed because clippy doesn't flag widening casts on this path today."
        )]
        let combined = ((self.sw1 as u16) << 8_u32) | (self.sw2 as u16);
        combined
    }

    /// Decoded ISO 7816-4 status word, per
    /// [`StatusWord`]. This is the
    /// canonical accessor -- consumers should match on the
    /// typed enum rather than compare against raw `sw1` /
    /// `sw2` / [`sw`] values.
    ///
    /// [`sw`]: ResponseApdu::sw
    #[must_use]
    pub const fn status_word(&self) -> StatusWord {
        StatusWord::from_bytes(self.sw1, self.sw2)
    }

    /// `true` iff the status word is exactly `0x9000`. Thin
    /// shorthand over [`status_word`] for the common case where
    /// the caller doesn't care which non-success status arrived.
    ///
    /// [`status_word`]: ResponseApdu::status_word
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self.status_word(), StatusWord::Success)
    }
}

/// Transport-level state transitions and faults that matter above
/// the pure byte-moving layer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportOutcome {
    /// A real APDU response (body + SW1/SW2). Pipeline can match
    /// on `response.status_word()` and continue.
    Response(ResponseApdu),
    /// Card slot was sensed empty during the exchange.
    NoCard,
    /// Transport timed out with the card in an unknown state
    /// (the response may have landed before the timeout fired).
    TimeoutUnknownState,
    /// Card reset itself (warm or cold) during the exchange.
    CardReset,
    /// T=1 block-numbering / window state lost; subsequent
    /// frames cannot be interpreted.
    ProtocolDesync,
    /// Reader was unplugged or its session terminated.
    ReaderRemoved,
}

impl TransportOutcome {
    /// Drop the outcome wrapper if it carries a real APDU
    /// response; otherwise hand the outcome back as an error.
    ///
    /// # Errors
    /// Any non-response transport state (no card, reader removed,
    /// card reset, etc.).
    pub fn into_response(self) -> Result<ResponseApdu, Self> {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "TransportOutcome is #[non_exhaustive]; the non-Response variants (NoCard, CardReset, ReaderRemoved, ...) and any future variant are uniformly surfaced as Err(outcome) for the caller's typed dispatch."
        )]
        match self {
            Self::Response(response) => Ok(response),
            other => Err(other),
        }
    }

    /// Project a non-response outcome to its
    /// [`TransportErrorKind`]; `None` for the `Response` variant.
    #[must_use]
    pub const fn kind(&self) -> Option<TransportErrorKind> {
        match self {
            Self::Response(_) => None,
            Self::NoCard => Some(TransportErrorKind::NoCard),
            Self::TimeoutUnknownState => Some(TransportErrorKind::TimeoutUnknownState),
            Self::CardReset => Some(TransportErrorKind::CardReset),
            Self::ProtocolDesync => Some(TransportErrorKind::ProtocolDesync),
            Self::ReaderRemoved => Some(TransportErrorKind::ReaderRemoved),
        }
    }
}

impl core::fmt::Display for TransportOutcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Response(response) => write!(
                f,
                "response SW={:#06X} body={}B",
                response.sw(),
                response.body.len()
            ),
            Self::NoCard => write!(f, "no card present"),
            Self::TimeoutUnknownState => write!(f, "transport timeout; card state unknown"),
            Self::CardReset => write!(f, "card reset during transport"),
            Self::ProtocolDesync => write!(f, "transport protocol desynchronised"),
            Self::ReaderRemoved => write!(f, "reader or card removed"),
        }
    }
}

/// Coarse classification for transport errors that are not
/// already represented as a [`TransportOutcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportErrorKind {
    /// Backend-specific error (PC/SC error, USB CCID glitch,
    /// ...). The adapter's `Display` carries the detail.
    Backend,
    /// Card slot was sensed empty.
    NoCard,
    /// Transport timed out; card state unknown.
    TimeoutUnknownState,
    /// Card reset mid-exchange.
    CardReset,
    /// T=1 protocol desync (window / block numbering corrupted).
    ProtocolDesync,
    /// Reader unplugged / session terminated.
    ReaderRemoved,
}

/// Adapter-specific transport errors classify themselves into a
/// small stable fault vocabulary so the use-case layer can match
/// on a typed kind rather than a substring of `Display`.
pub trait TransportErrorExt {
    /// Classify this error into the [`TransportErrorKind`]
    /// vocabulary. Default impl returns `Backend`; adapters that
    /// have richer information (PC/SC's
    /// `SCARD_W_REMOVED_CARD`, etc.) override.
    fn kind(&self) -> TransportErrorKind {
        TransportErrorKind::Backend
    }
}

impl TransportErrorExt for String {}
impl TransportErrorExt for &'static str {}

/// "I expected a real APDU response, but the transport had a
/// higher-level state transition or backend failure instead."
#[derive(Debug)]
pub enum TransportDispatchError<E> {
    /// Backend / adapter-specific error (PC/SC return code,
    /// USB CCID I/O, etc.).
    Error(E),
    /// Transport-layer state transition that isn't a real APDU
    /// response (`NoCard`, `CardReset`, ...).
    Outcome(TransportOutcome),
}

impl<E: TransportErrorExt> TransportDispatchError<E> {
    /// Project to the [`TransportErrorKind`] vocabulary. Either
    /// delegates to the adapter's classifier (`Error` variant)
    /// or maps the outcome to its kind (`Outcome` variant).
    pub fn kind(&self) -> TransportErrorKind {
        match self {
            Self::Error(error) => error.kind(),
            Self::Outcome(outcome) => outcome.kind().unwrap_or(TransportErrorKind::Backend),
        }
    }
}

impl<E: core::fmt::Display> core::fmt::Display for TransportDispatchError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Error(error) => write!(f, "{error}"),
            Self::Outcome(outcome) => write!(f, "{outcome}"),
        }
    }
}

impl<E: core::fmt::Debug + core::fmt::Display + 'static> core::error::Error
    for TransportDispatchError<E>
{
}

/// Send-and-receive APDU primitive. Implementations are
/// responsible for transport-level retries that do not surface to
/// the protocol layer (`61xx GET RESPONSE` chains, `6Cxx`
/// wrong-`Le` retries, etc.).
pub trait CardTransport {
    /// Adapter-specific error type. Must implement `Display`
    /// (for diagnostics) and [`TransportErrorExt`] (for the
    /// typed fault classifier).
    type Error: core::fmt::Debug + core::fmt::Display + TransportErrorExt;

    /// Synchronously transmit the APDU and return either a
    /// concrete response or a transport-level state transition.
    ///
    /// # Errors
    /// Transport-specific failures other than the
    /// [`TransportOutcome`] state transitions.
    fn transmit_outcome(&mut self, apdu: &CommandApdu) -> Result<TransportOutcome, Self::Error>;

    /// Convenience path for higher protocol layers that require a
    /// real APDU response body and SW pair. Non-response transport
    /// outcomes are surfaced explicitly rather than flattened into
    /// a string.
    ///
    /// # Errors
    /// Either a backend error or a transport-level outcome that
    /// is not a real APDU response.
    fn transmit(&mut self, apdu: &[u8]) -> Result<ResponseApdu, TransportDispatchError<Self::Error>>
    where
        Self: Sized,
    {
        let command = CommandApdu::from(apdu);
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "TransportOutcome is #[non_exhaustive]; non-Response state transitions (NoCard, CardReset, ReaderRemoved, ...) and any future variant are lifted into TransportDispatchError::Outcome so the caller can branch on TransportErrorKind."
        )]
        match self
            .transmit_outcome(&command)
            .map_err(TransportDispatchError::Error)?
        {
            TransportOutcome::Response(response) => Ok(response),
            outcome => Err(TransportDispatchError::Outcome(outcome)),
        }
    }

    /// Card's ATR, parsed into the typed [`Atr`]. Upper layers read
    /// the typed structure (convention, historical data objects,
    /// FINEID model) instead of re-parsing raw bytes -- the boundary
    /// hands forward a domain value, not a `&[u8]`.
    ///
    /// # Errors
    /// [`AtrError`] if the card's ATR bytes are outside the
    /// ISO 7816-3 structure (length window, bad TS, truncated chain).
    fn atr(&self) -> Result<Atr, AtrError>;
}

#[cfg(test)]
mod tests {

    use super::{CardTransport, CommandApdu, ResponseApdu, TransportErrorKind, TransportOutcome};
    use crate::atr::{Atr, AtrError, MINIMAL_DIRECT_ATR};

    /// In-memory transport that replays a canned `(request,
    /// response)` trace. Used by protocol-layer unit tests to
    /// drive PACE and secure messaging against recorded byte
    /// streams without needing a card.
    pub(super) struct MockTransport {
        atr: Vec<u8>,
        script: Vec<(Vec<u8>, ResponseApdu)>,
        cursor: usize,
    }

    impl MockTransport {
        fn new(atr: Vec<u8>, script: Vec<(Vec<u8>, ResponseApdu)>) -> Self {
            Self {
                atr,
                script,
                cursor: 0,
            }
        }
    }

    impl CardTransport for MockTransport {
        type Error = String;

        fn transmit_outcome(
            &mut self,
            apdu: &CommandApdu,
        ) -> Result<TransportOutcome, Self::Error> {
            let (expected, response) = self.script.get(self.cursor).ok_or_else(|| {
                format!("MockTransport: script exhausted at step {}", self.cursor)
            })?;
            if expected != apdu.as_bytes() {
                return Err(format!(
                    "MockTransport step {}: expected {} but got {}",
                    self.cursor,
                    hex::encode(expected),
                    hex::encode(apdu.as_bytes()),
                ));
            }
            self.cursor += 1;
            Ok(TransportOutcome::Response(response.clone()))
        }

        fn atr(&self) -> Result<Atr, AtrError> {
            Atr::new(&self.atr)
        }
    }

    #[test]
    fn apdu_response_status_helpers() {
        let ok = ResponseApdu {
            body: vec![],
            sw1: 0x90,
            sw2: 0x00,
        };
        assert!(ok.is_ok());
        assert_eq!(ok.sw(), 0x9000);

        let pin_wrong = ResponseApdu {
            body: vec![],
            sw1: 0x63,
            sw2: 0xC3,
        };
        assert!(!pin_wrong.is_ok());
        assert_eq!(pin_wrong.sw(), 0x63C3);
    }

    #[test]
    fn transport_outcome_preserves_fault_kind() {
        assert_eq!(
            TransportOutcome::CardReset.kind(),
            Some(TransportErrorKind::CardReset)
        );
        assert_eq!(
            TransportOutcome::Response(ResponseApdu {
                body: vec![],
                sw1: 0x90,
                sw2: 0x00,
            })
            .kind(),
            None
        );
    }

    #[test]
    fn mock_transport_drives_a_script() {
        let mut tx = MockTransport::new(
            MINIMAL_DIRECT_ATR.to_vec(),
            vec![(
                vec![0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00],
                ResponseApdu {
                    body: vec![],
                    sw1: 0x90,
                    sw2: 0x00,
                },
            )],
        );
        let r = tx
            .transmit(&[0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00])
            .expect("scripted SELECT MF transmit succeeds");
        assert!(r.is_ok());
        assert_eq!(
            tx.atr().expect("mock exposes its ATR").to_wire_bytes(),
            MINIMAL_DIRECT_ATR
        );
    }
}
