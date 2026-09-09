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

//! APDU-level structured tracing for the `card activate` flow.
//!
//! [`ApduTraceTransport`] is a thin [`CardTransport`] middleware
//! that records every command APDU + its response on stderr in
//! the project's JSON Lines event format (see
//! `doc/observability.md`). It pairs each call with a
//! monotonic step counter so a log scraper can match a tx event
//! with the matching rx event without resorting to ordering by
//! timestamp.
//!
//! Command and response data are redacted at the source. Only
//! public command headers, byte lengths, status words, and
//! transport outcomes reach the event sink.
//!
//! ## Scope
//!
//! The wrapper is currently used by `card activate` only
//! (`crates/refineid-client/src/card_pin.rs`). The
//! `change-pin*` / `unblock-pin*` flows will move to it next; the
//! observability surface they need is the same.

use refineid_lib_core::atr::{Atr, AtrError};
use refineid_lib_core::transport::{CardTransport, CommandApdu, ResponseApdu, TransportOutcome};

/// Transport-layer middleware that records every APDU sent
/// through it as a `card.activate.apdu.{tx,rx}` event pair.
///
/// Holds the inner transport by value (no double-borrow) and
/// forwards `atr()` unchanged. The step counter wraps at
/// `u32::MAX` -- not a real concern for the activate flow (10ish
/// APDUs per run).
pub struct ApduTraceTransport<T: CardTransport> {
    /// Wrapped transport that does the actual PC/SC I/O. Held
    /// by value so the trace wrapper has unambiguous ownership;
    /// `atr()` and `transmit_outcome()` forward directly.
    inner: T,
    /// Sequential APDU step counter, used as the `step` field
    /// in each emitted `card.activate.apdu.{tx,rx}` event. Wraps
    /// at `u32::MAX`; the activate flow uses ~10 APDUs per run
    /// so wraparound is not reachable in practice.
    step: u32,
}

impl<T: CardTransport> core::fmt::Debug for ApduTraceTransport<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ApduTraceTransport")
            .field("step", &self.step)
            .field("inner", &"<CardTransport>")
            .finish()
    }
}

impl<T: CardTransport> ApduTraceTransport<T> {
    /// Wrap an already-opened transport in the trace
    /// middleware. The wrapped value is consumed.
    #[must_use]
    pub const fn new(inner: T) -> Self {
        Self { inner, step: 0 }
    }

    /// Reclaim the inner transport. Useful when a downstream
    /// step needs to operate against the bare transport
    /// (e.g. handing it off to a secure-messaging layer); not
    /// used by the activate flow today.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: CardTransport> CardTransport for ApduTraceTransport<T> {
    type Error = T::Error;

    fn transmit_outcome(&mut self, apdu: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
        self.step = self.step.wrapping_add(1);
        let step_str = format!("{}", self.step);
        let bytes = apdu.as_bytes();
        let header_len = bytes.len().min(4);
        let header_hex = hex::encode(&bytes[..header_len]);
        crate::events::CardActivateApduTx {
            step: &step_str,
            header_hex: &header_hex,
            command_len: bytes.len(),
        }
        .emit();

        let outcome = self.inner.transmit_outcome(apdu);

        match &outcome {
            Ok(TransportOutcome::Response(response)) => {
                Self::emit_response(&step_str, response);
            }
            Ok(other) => {
                Self::emit_non_response(&step_str, other);
            }
            Err(_) => {
                // Transport error -- caller will surface it.
                // Emit an rx event with the non-response slot
                // populated so a scraper sees the failed step.
                crate::events::CardActivateApduRx {
                    step: &step_str,
                    response_len: 0,
                    sw: "",
                    transport_outcome: "Error",
                }
                .emit();
            }
        }
        outcome
    }

    fn atr(&self) -> Result<Atr, AtrError> {
        self.inner.atr()
    }
}

impl<T: CardTransport> ApduTraceTransport<T> {
    /// Emit a `card.activate.apdu.rx` event with the response
    /// length and status word.
    ///
    /// Helper to keep `transmit_outcome` readable; the `step`
    /// string is borrowed because the caller already owns it.
    /// Status word is rendered upper-case hex (`6300`, `9000`,
    /// ...) for readability against ISO 7816-4 tables.
    fn emit_response(step: &str, response: &ResponseApdu) {
        let sw_str = format!("{:04X}", response.sw());
        crate::events::CardActivateApduRx {
            step,
            response_len: response.body.len(),
            sw: &sw_str,
            transport_outcome: "",
        }
        .emit();
    }

    /// Emit a `card.activate.apdu.rx` event for a non-response
    /// transport outcome (`NoCard`, `TimeoutUnknownState`,
    /// `CardReset`, etc.) so the trace stays continuous.
    ///
    /// Without this helper the rx-event stream would drop on
    /// any transport-level non-response, making post-mortem
    /// audit harder. Response length and SW are zero/empty; the
    /// `transport_outcome` label names the variant.
    fn emit_non_response(step: &str, outcome: &TransportOutcome) {
        let label = match outcome {
            TransportOutcome::Response(_) => "Response",
            TransportOutcome::NoCard => "NoCard",
            TransportOutcome::TimeoutUnknownState => "TimeoutUnknownState",
            TransportOutcome::CardReset => "CardReset",
            TransportOutcome::ProtocolDesync => "ProtocolDesync",
            TransportOutcome::ReaderRemoved => "ReaderRemoved",
            _ => "UnknownTransportOutcome",
        };
        crate::events::CardActivateApduRx {
            step,
            response_len: 0,
            sw: "",
            transport_outcome: label,
        }
        .emit();
    }
}
