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

//! Card / Reader object model -- **Phase 1**.
//!
//! The natural Rust expression of "a Reader holds a Card; the
//! Card has state and methods you can run on it." Typestate
//! parameters carry compile-time proof of which protocol
//! checkpoints have run; methods that act on card-side state
//! only exist on the matching `Card<State>`.
//!
//! ## Why this exists
//!
//! Free-function code (`pkcs15::read_certificate(transport,
//! slot)`, `auth::change_pin(transport, slot, ...)`) passes a
//! mutable transport around and re-builds card context at every
//! entry point. As trust gates, session-revocation re-checks,
//! ATR classification, and AODF reads accreted, that pattern
//! turned into ceremony. Card / Reader as named objects hold
//! the ceremony once and expose narrow methods that match
//! operator intent.
//!
//! ## Phases
//!
//! Phase 1 (this commit) introduces:
//!
//! - [`Reader`] -- a backend-borrow + reader-id pair, with
//!   methods to `enumerate` every connected
//!   reader and [`open`](Reader::open) one of them.
//! - [`Card<State>`](Card) -- owns a [`B::Transport`], the
//!   captured [`Atr`], and a state marker. Generic over the
//!   backend so eMRTD relay / embedded HAL futures can plug in.
//! - [`Untrusted`] state with [`Card::classify_model`].
//!
//! Subsequent phases (sketched in [`doc/typing-discipline.md`]
//! and the Card/Reader proposal):
//!
//! - Phase 2: `Card<Trusted>` + `trust_gate()`. Wraps the
//!   current `establish_trusted_session` logic.
//! - Phase 3: AODF read + `Card<Trusted>::read_pin_state()`
//!   yields `Card<Activated>` or `Card<Unactivated>`.
//! - Phase 4: migrate activate / change-pin / unblock-pin to
//!   be `Card<State>` methods.
//! - Phase 5: migrate sign / decrypt similarly.
//! - Phase 6: retire the free-function escape hatches.
//!
//! [`B::Transport`]: crate::backend::ReaderBackend::Transport
//! [`doc/typing-discipline.md`]: ../../../../doc/typing-discipline.md

use core::fmt;

use crate::backend::{ReaderAccessCap, ReaderBackend, ReaderId, ReaderInfo};
use crate::fineid_card::{Atr, AtrError, CardClassificationError, FineidCardModel};
use crate::transport::CardTransport as _;

// ----- Reader -----------------------------------------------

/// A physical card reader, identified and reachable through a
/// [`ReaderBackend`].
///
/// The struct holds a borrow of the backend and the reader's
/// platform-published id; constructing one does not open a card
/// session. Call [`open`](Self::open) to start interacting with
/// the card currently inserted (if any).
pub struct Reader<'b, B: ReaderBackend> {
    /// Borrow of the platform reader backend used to (later) open
    /// a transport against this reader. Held by reference so the
    /// `Reader` never owns the PC/SC service handle.
    backend: &'b B,
    /// Platform-published reader id (Windows-style "Foo Reader 0",
    /// macOS USB descriptor string, etc.). Pass-through; the lib
    /// never parses it.
    id: ReaderId,
    /// Snapshot of whether a card was inserted at enumerate time.
    /// Stale by definition -- the user can remove the card between
    /// enumeration and `open()`; the `Card::open` path
    /// re-checks via the backend.
    card_present: bool,
}

impl<'b, B: ReaderBackend> Reader<'b, B> {
    /// Enumerate every reader the backend knows about. Empty
    /// list if no PC/SC service is running or no readers are
    /// physically connected.
    ///
    /// # Errors
    /// Backend enumeration failure -- typically a PC/SC service
    /// unreachable or a platform-specific I/O error.
    #[expect(
        clippy::allow_attributes,
        reason = "the `#[allow(dead_code)]` below is the Rule E22 structural carve-out: dead_code fires under `cargo build --lib` (no tests) but not under `cargo clippy --all-targets` (tests use the fn).  `#[expect(dead_code)]` would oscillate between the two configurations.  This nested `#[expect(allow_attributes)]` documents that the allow is deliberate, not a missed migration."
    )]
    #[allow(
        dead_code,
        reason = "Phased rollout: Phase 1 ships Card open; high-level enumerate API isn't wired into the client crate yet (it currently goes via the backend directly). Reachable from unit tests only, so dead_code fires under `cargo build --lib` but not under `cargo clippy --all-targets`; `#[expect]` would oscillate between the two configurations per Rule E22's structural carve-out."
    )]
    pub(crate) fn enumerate(backend: &'b B) -> Result<Vec<Self>, B::Error> {
        let infos = backend.enumerate()?;
        Ok(infos
            .into_iter()
            .map(|info| Self::from_info(backend, info))
            .collect())
    }

    /// Lift a backend-published [`ReaderInfo`] snapshot into a
    /// `Reader` borrowing the same backend. Helper for
    /// [`Self::enumerate`]; declared private because the
    /// `card_present` field captured here is transient.
    fn from_info(backend: &'b B, info: ReaderInfo) -> Self {
        Self {
            backend,
            id: info.id,
            card_present: info.card_present,
        }
    }

    /// Borrow the reader's platform-reported id.
    #[must_use]
    pub const fn id(&self) -> &ReaderId {
        &self.id
    }

    /// `true` when the reader reports a card physically present.
    /// Read at enumerate-time; can become stale between
    /// enumeration and [`open`](Self::open).
    #[must_use]
    pub const fn has_card(&self) -> bool {
        self.card_present
    }

    /// Open a session against the card currently in the reader.
    /// Returns a [`Card`] in the [`Untrusted`] typestate.
    ///
    /// The transport is opened with the default
    /// [`ReaderAccessCap::Read`] capability; the FINEID protocol
    /// suite reaches modify APDUs through this access mode (the
    /// PC/SC layer takes per-APDU transactions, not session-
    /// exclusive locks).
    ///
    /// # Errors
    /// - [`OpenError::Backend`] from the backend's
    ///   `open_session`.
    /// - [`OpenError::Atr`] if the card's ATR is outside the
    ///   ISO 7816-3 length window.
    pub fn open(&self) -> Result<Card<'b, B, Untrusted>, OpenError<B::Error>> {
        let transport = self
            .backend
            .open_session(&self.id, ReaderAccessCap::Read)
            .map_err(OpenError::Backend)?;
        let atr = transport.atr().map_err(OpenError::Atr)?;
        Ok(Card {
            #[cfg(any())]
            backend: self.backend,
            reader_id: self.id.clone(),
            _transport: transport,
            atr,
            state: Untrusted,
            _backend: core::marker::PhantomData,
        })
    }
}

impl<B: ReaderBackend> fmt::Debug for Reader<'_, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reader")
            .field("id", &self.id)
            .field("card_present", &self.card_present)
            .finish_non_exhaustive()
    }
}

// ----- OpenError --------------------------------------------

/// Error returned by [`Reader::open`].
#[derive(Debug)]
pub enum OpenError<E> {
    /// The backend's `open_session` failed (PC/SC error,
    /// reader vanished, etc.).
    Backend(E),
    /// The card returned an ATR outside ISO 7816-3 (`2..=33`
    /// bytes). Either a transport bug or a non-conforming card.
    Atr(AtrError),
}

impl<E: fmt::Display> fmt::Display for OpenError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend(e) => write!(f, "backend open failed: {e}"),
            Self::Atr(e) => write!(f, "ATR rejected: {e}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> core::error::Error for OpenError<E> {}

// ----- Card -------------------------------------------------

/// Open card session with a typed state.
///
/// `State` is a zero-sized marker that proves which protocol
/// checkpoints have run. Methods that act on later-stage
/// information only exist on the matching `Card<State>` impl --
/// e.g. `change_pin` will only exist on `Card<Activated>` once
/// Phase 4 lands, so trying to change a PIN on a never-
/// activated card becomes a compile error.
///
/// The struct owns the [`B::Transport`]; dropping the `Card`
/// closes the PC/SC connection.
///
/// [`B::Transport`]: ReaderBackend::Transport
pub struct Card<'b, B: ReaderBackend, State> {
    /// Reader id this session was opened against. Captured at
    /// open time so the `Card` does not need to keep a borrow of
    /// the [`Reader`] alive (the transport is the live handle).
    reader_id: ReaderId,
    /// Owned transport; Phase 2+ methods will `&mut transport`
    /// to drive SELECTs, READ BINARYs and modify APDUs. Phase 1
    /// only captures the ATR at open time. The `_` prefix
    /// signals "intentionally held but not yet read" so
    /// `dead_code` is satisfied without a per-site allow.
    _transport: B::Transport,
    /// Answer-To-Reset bytes captured at open. Used by
    /// [`Card::classify_model`] and surfaced via [`Card::atr`].
    /// Single-source-of-truth for the card's protocol-layer
    /// identity for the lifetime of the session.
    atr: Atr,
    /// Zero-sized typestate marker (e.g. [`Untrusted`]) that
    /// gates which methods exist on this `Card`. See the
    /// typestate discussion above.
    state: State,
    // Phase 2 will add `backend: &'b B` here for transport
    // reconstruction on session-revocation re-checks. For Phase
    // 1 we don't need it; the lifetime `'b` is parked via
    // PhantomData so the variance + outlives bounds line up
    // with future use.
    /// Parked variance / outlives bound for the future `&'b B`
    /// backend reference (see comment above). Carries no runtime
    /// data; exists only to keep the lifetime `'b` non-trivial.
    _backend: core::marker::PhantomData<&'b B>,
}

impl<B: ReaderBackend, S: fmt::Debug> fmt::Debug for Card<'_, B, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Card")
            .field("reader_id", &self.reader_id)
            .field("atr", &self.atr)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl<B: ReaderBackend, S> Card<'_, B, S> {
    /// The reader this card session is bound to. Useful for
    /// logs and disambiguation.
    #[must_use]
    pub const fn reader_id(&self) -> &ReaderId {
        &self.reader_id
    }

    /// The card's Answer-To-Reset, captured at open time.
    #[must_use]
    pub const fn atr(&self) -> &Atr {
        &self.atr
    }
}

// ----- Untrusted state --------------------------------------

/// Initial state of a freshly-opened `Card`. The card has
/// returned its ATR, nothing else has been read or trusted.
///
/// The only method available in this state is
/// [`Card::classify_model`] -- ATR matching against the
/// in-scope FINEID model set. This is a protocol-level signal,
/// not a trust signal; the pinned-root SHA-256 check is the
/// next stage and lives on Phase 2's `Card<Trusted>`.
#[derive(Debug, Clone, Copy)]
pub struct Untrusted;

impl<B: ReaderBackend> Card<'_, B, Untrusted> {
    /// Classify the card by its ATR against the in-scope
    /// [`FineidCardModel`] set. See
    /// [`doc/fineid-card-models.md`][doc] for the supported set
    /// and the validity-window reasoning.
    ///
    /// # Errors
    /// [`CardClassificationError::UnknownOrUnsupportedAtr`]
    /// when the ATR doesn't match any in-scope model.
    ///
    /// [doc]: ../../../../doc/fineid-card-models.md
    pub fn classify_model(&self) -> Result<FineidCardModel, CardClassificationError> {
        self.atr.classify()
    }
}

#[cfg(test)]
mod tests {

    use super::{OpenError, Reader, Untrusted};
    use crate::atr::{Atr, AtrError};
    use crate::backend::{ReaderAccessCap, ReaderBackend, ReaderId, ReaderInfo};
    use crate::fineid_card::FineidCardModel;
    use crate::transport::{CardTransport, ResponseApdu, TransportOutcome};

    /// Minimal test backend. `atr` is the byte sequence the
    /// opened transport reports; `apdu_response` (unused for
    /// Phase 1 tests) is whatever every APDU returns.
    struct FakeBackend {
        readers: Vec<ReaderInfo>,
        atr: Vec<u8>,
    }

    struct FakeTransport {
        atr: Vec<u8>,
    }

    impl CardTransport for FakeTransport {
        type Error = String;
        fn transmit_outcome(
            &mut self,
            _apdu: &crate::transport::CommandApdu,
        ) -> Result<TransportOutcome, Self::Error> {
            Ok(TransportOutcome::Response(ResponseApdu {
                body: Vec::new(),
                sw1: 0x90,
                sw2: 0x00,
            }))
        }
        fn atr(&self) -> Result<Atr, AtrError> {
            Atr::new(&self.atr)
        }
    }

    impl ReaderBackend for FakeBackend {
        type Transport = FakeTransport;
        type Error = String;
        fn enumerate(&self) -> Result<Vec<ReaderInfo>, Self::Error> {
            Ok(self.readers.clone())
        }
        fn open_session(
            &self,
            _reader: &ReaderId,
            _access: ReaderAccessCap,
        ) -> Result<Self::Transport, Self::Error> {
            Ok(FakeTransport {
                atr: self.atr.clone(),
            })
        }
    }

    fn fake(atr: Vec<u8>, present: bool) -> FakeBackend {
        FakeBackend {
            readers: vec![ReaderInfo {
                id: ReaderId::new("FakeReader".to_owned()),
                card_present: present,
            }],
            atr,
        }
    }

    #[test]
    fn enumerate_yields_readers() {
        let backend = fake(vec![], true);
        let readers = Reader::enumerate(&backend).expect("backend enumerates readers");
        assert_eq!(readers.len(), 1);
        assert_eq!(readers[0].id().as_str(), "FakeReader");
        assert!(readers[0].has_card());
    }

    #[test]
    fn enumerate_no_card_present() {
        let backend = fake(vec![], false);
        let readers = Reader::enumerate(&backend).expect("backend enumerates readers");
        assert!(!readers[0].has_card());
    }

    #[test]
    fn open_yields_card_with_typed_atr() {
        // DVV-published Thales MultiApp v5.0 (FINEID S4-1 v4.0,
        // chip-revision v 1.0.0) ATR.
        let atr_bytes = vec![
            0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0, 0x85, 0x05, 0x00, 0x11,
            0x12, 0x24, 0x60, 0x82, 0x90, 0x00,
        ];
        let backend = fake(atr_bytes.clone(), true);
        let readers = Reader::enumerate(&backend).expect("backend enumerates readers");
        let card = readers[0].open().expect("open");
        assert_eq!(card.atr().to_wire_bytes(), atr_bytes);
        assert_eq!(card.reader_id().as_str(), "FakeReader");
    }

    #[test]
    fn untrusted_classify_model_recognises_in_scope_atr() {
        // Thales MultiApp v5.0, chip-revision v 2.0.0
        // (field-observed 2026-05-24).
        let atr_bytes = vec![
            0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0, 0x85, 0x05, 0x10, 0x24,
            0x12, 0x24, 0x60, 0x82, 0x90, 0x00,
        ];
        let backend = fake(atr_bytes, true);
        let readers = Reader::enumerate(&backend).expect("backend enumerates readers");
        let card = readers[0].open().expect("in-scope card opens");
        let model = card.classify_model().expect("classify");
        assert_eq!(model, FineidCardModel::ThalesMultiAppV5_0);
    }

    #[test]
    fn untrusted_classify_model_rejects_out_of_scope_atr() {
        // Gemalto MultiApp v3.0 -- expired generation, out of
        // scope per doc/fineid-card-models.md.
        let atr_bytes = vec![
            0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0, 0x85, 0x03, 0x00, 0xEF,
            0x12, 0x00, 0xF6, 0x82, 0x90, 0x00,
        ];
        let backend = fake(atr_bytes, true);
        let readers = Reader::enumerate(&backend).expect("backend enumerates readers");
        let card = readers[0].open().expect("out-of-scope card still opens");
        card.classify_model()
            .expect_err("out-of-scope ATR fails classification");
    }

    #[test]
    fn open_with_too_short_atr_errors() {
        let backend = fake(vec![0x3B], true);
        let readers = Reader::enumerate(&backend).expect("backend enumerates readers");
        match readers[0].open() {
            Err(OpenError::Atr(_)) => {}
            other => panic!("expected OpenError::Atr, got {other:?}"),
        }
    }

    #[test]
    fn open_passes_through_backend_error() {
        struct FailingBackend;
        impl ReaderBackend for FailingBackend {
            type Transport = FakeTransport;
            type Error = &'static str;
            fn enumerate(&self) -> Result<Vec<ReaderInfo>, Self::Error> {
                Ok(vec![ReaderInfo {
                    id: ReaderId::new("X".to_owned()),
                    card_present: true,
                }])
            }
            fn open_session(
                &self,
                _reader: &ReaderId,
                _access: ReaderAccessCap,
            ) -> Result<Self::Transport, Self::Error> {
                Err("simulated failure")
            }
        }
        let backend = FailingBackend;
        let readers = Reader::enumerate(&backend).expect("backend enumerates readers");
        match readers[0].open() {
            Err(OpenError::Backend(e)) => assert_eq!(e, "simulated failure"),
            other => panic!("expected OpenError::Backend, got {other:?}"),
        }
    }

    #[test]
    fn untrusted_marker_is_zero_sized() {
        // The state marker is a ZST -- carries no runtime cost.
        assert_eq!(size_of::<Untrusted>(), 0);
    }
}
