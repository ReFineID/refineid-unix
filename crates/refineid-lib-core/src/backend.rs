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

//! Backend authority boundary.
//!
//! The backend is the only layer allowed to talk to hardware. It
//! enumerates readers, opens a transport, may reset a card, and
//! moves APDU bytes -- but it must not grow business policy.
//!
//! [`ReaderId`], [`ReaderInfo`], and [`ReaderAccessCap`] live with
//! the [`crate::card`] Session API and land when that module ports.

use crate::transport::CardTransport;

/// Identifier for a PC/SC reader.
///
/// A minimal newtype so the [`ReaderBackend`] trait signature can
/// be expressed without pulling the whole `card` module in.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReaderId(pub String);

impl ReaderId {
    /// Wrap a platform-reported reader name. No structural check
    /// -- the typed wrapper just records "this string is a
    /// reader id".
    #[must_use]
    pub const fn new(name: String) -> Self {
        Self(name)
    }

    /// Borrow the underlying reader-name string for emission.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Read-only metadata about a connected reader.
#[derive(Debug, Clone)]
pub struct ReaderInfo {
    /// Platform-reported reader name.
    pub id: ReaderId,
    /// Whether a card is currently presented in this reader.
    pub card_present: bool,
}

/// Coarse access requested when opening a card on a reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReaderAccessCap {
    /// Card-public reads only (eMRTD via PACE, ATR-derived
    /// metadata).
    Read,
    /// A PIN-bearing command sequence: VERIFY / CHANGE REFERENCE
    /// DATA / RESET RETRY COUNTER and the operations they gate
    /// (PSO after VERIFY). The transport must make the WHOLE
    /// sequence atomic against concurrent card consumers -- on
    /// PC/SC by holding one transaction for the transport's
    /// lifetime -- so no other process can interleave an APDU
    /// between the SELECT, the VERIFY, and the operation it
    /// authorised (stealing or disturbing the card's security
    /// state mid-sequence).
    ///
    /// Caller contract: the transport must stay busy. PC/SC
    /// resource managers reset a card whose transaction sits
    /// idle (Windows: five seconds without an operation), so a
    /// `PinSequence` transport must never be held across a PIN
    /// prompt, network wait, or any other non-card work --
    /// collect credentials BEFORE opening.
    PinSequence,
}

/// Errors surfaced by `pick_single_reader` when the count of
/// card-present readers can't be reduced to exactly one
/// unambiguously.
///
/// The rule the picker enforces is the project's universal
/// multi-card-safety policy: when more than one card is
/// inserted across the connected readers, the caller MUST
/// disambiguate via `--reader SUBSTR`. The picker never guesses;
/// guessing could fire a card-state-changing APDU (PIN verify,
/// signature, PUK rotation) against the wrong physical card.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ReaderPickError {
    /// `backend.enumerate()` returned no readers at all.
    NoReaders,
    /// One or more readers connected, none with a card inserted.
    NoCardPresent,
    /// More than one card-present reader, and the caller didn't
    /// supply a `--reader` filter. `available` lists every
    /// card-present reader name so the caller can surface an
    /// actionable error message.
    MultipleReadersNoFilter {
        /// Connected card-present reader names. Tier 0
        /// `Vec<String>`; presentational.
        available: Vec<String>,
    },
    /// `filter` was supplied but matched no card-present reader.
    NoMatchingReader {
        /// The filter string the operator supplied. Tier 0
        /// `String`; presentational.
        filter: String,
        /// Connected card-present reader names presented back
        /// so the operator can correct the filter.
        available: Vec<String>,
    },
    /// `filter` was supplied and matched more than one
    /// card-present reader. The caller has to narrow it.
    AmbiguousFilter {
        /// The filter string the operator supplied.
        filter: String,
        /// Card-present reader names that matched the filter.
        matched: Vec<String>,
    },
    /// Cards are inserted, but none of them respond as FINEID
    /// when probed (no SELECT PKCS#15 success). Surfaced only
    /// by `pkcs15::pick_fineid_reader`, which probes
    /// every card-present reader to skip non-FINEID tokens like
    /// YubiKey-in-CCID-mode.
    NoFineidCard {
        /// Card-present reader names that didn't respond as
        /// FINEID. Helps the operator see which readers had
        /// non-FINEID tokens.
        available: Vec<String>,
    },
}

impl core::fmt::Display for ReaderPickError {
    #[expect(
        clippy::use_debug,
        reason = "operator-supplied --reader filter strings are rendered with Debug-quoting so whitespace-only / empty / control-character inputs surface visibly in diagnostics; `{filter}` would silently drop those distinctions"
    )]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoReaders => write!(f, "no PC/SC readers connected"),
            Self::NoCardPresent => write!(f, "no card present in any reader"),
            Self::MultipleReadersNoFilter { available } => write!(
                f,
                "{} cards present; pass --reader SUBSTR to pick one: [{}]",
                available.len(),
                available.join(", ")
            ),
            Self::NoMatchingReader { filter, available } => write!(
                f,
                "no card-present reader matched --reader {filter:?}; \
                 connected card-present readers: [{}]",
                available.join(", ")
            ),
            Self::AmbiguousFilter { filter, matched } => write!(
                f,
                "--reader {filter:?} matched more than one card-present reader: \
                 [{}] -- narrow the substring",
                matched.join(", ")
            ),
            Self::NoFineidCard { available } => write!(
                f,
                "no FINEID-format card responded to probe; readers had cards \
                 but none accepted SELECT PKCS#15: [{}]",
                available.join(", ")
            ),
        }
    }
}

impl core::error::Error for ReaderPickError {}

/// Operator-supplied reader-name substring filter, typed at the
/// trust boundary.
///
/// Used by the `--reader SUBSTR` CLI option and by the
/// programmatic picker entry points to narrow which card-present
/// reader the operation targets. The constructor is the single
/// place an arbitrary string crosses into "matches an actual
/// reader name" semantics.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReaderFilter(String);

impl ReaderFilter {
    /// Wrap an owned filter string. No structural validation:
    /// the substring will be matched against
    /// `ReaderInfo::id.as_str().contains(filter)`, so an empty
    /// string matches every reader (which is rarely useful, but
    /// not an error -- callers usually skip the filter
    /// altogether for that case).
    #[must_use]
    pub fn new<S: AsRef<str>>(s: S) -> Self {
        Self(s.as_ref().to_owned())
    }

    /// Borrow the underlying filter string for matching.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for ReaderFilter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Pick exactly one card-present reader, enforcing the project's
/// universal multi-card-safety rule.
///
/// Behaviour:
/// - 0 readers connected: [`ReaderPickError::NoReaders`].
/// - readers connected but no cards inserted: `NoCardPresent`.
/// - exactly 1 card present, no filter: return that reader.
/// - exactly 1 card present, filter matches it: return it.
/// - exactly 1 card present, filter doesn't match: `NoMatchingReader`.
/// - 2+ cards present, no filter: `MultipleReadersNoFilter`.
/// - 2+ cards present, filter matches exactly 1: return it.
/// - 2+ cards present, filter matches 0: `NoMatchingReader`.
/// - 2+ cards present, filter matches 2+: `AmbiguousFilter`.
///
/// The picker never guesses when more than one card is present.
/// Auto-picking risks running a card-state-changing APDU (PIN
/// verify, sign, PUK rotate) against the wrong physical card.
///
/// # Errors
/// [`ReaderPickError`] for any of the failure cases above. The
/// underlying backend's enumerate error is intentionally not
/// surfaced here -- callers run [`ReaderBackend::enumerate`]
/// directly when they need that distinction.
/// Extension trait that hosts the multi-card-safety picker on
/// every [`ReaderBackend`]. Same default-impl pattern as
/// `auth::PinOps` / `sign::SignOps` / `pkcs15::Pkcs15Ops`.
pub trait ReaderBackendOps: ReaderBackend
where
    Self::Error: core::fmt::Display,
{
    /// See `pick_single_reader`.
    ///
    /// # Errors
    /// As for `pick_single_reader`.
    fn pick_single_reader(&self, filter: Option<ReaderFilter>) -> Result<ReaderId, ReaderPickError>
    where
        Self: Sized,
    {
        pick_single_reader(self, filter)
    }
}

impl<B: ReaderBackend + ?Sized> ReaderBackendOps for B where B::Error: core::fmt::Display {}

/// Selects exactly one reader for an operation, applying the
/// CLI's deterministic single-reader policy.
///
/// Returns `NoReaders` if enumeration yields nothing,
/// `NoCardPresent` if no enumerated reader has a card inserted,
/// and `MultipleReaders` if more than one reader (after the
/// optional `filter`) has a card. The lib refuses to guess which
/// reader the user meant; callers must disambiguate via
/// `ReaderFilter` or a UI prompt.
pub(crate) fn pick_single_reader<B: ReaderBackend>(
    backend: &B,
    filter: Option<ReaderFilter>,
) -> Result<ReaderId, ReaderPickError>
where
    B::Error: core::fmt::Display,
{
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

    filter.map_or_else(
        || match present.as_slice() {
            [single] => Ok(single.id.clone()),
            many => Err(ReaderPickError::MultipleReadersNoFilter {
                available: many.iter().map(|r| r.id.as_str().to_owned()).collect(),
            }),
        },
        |f| {
            let needle = f.as_str();
            let matched: Vec<&ReaderInfo> = present
                .iter()
                .filter(|r| r.id.as_str().contains(needle))
                .collect();
            match matched.as_slice() {
                [] => Err(ReaderPickError::NoMatchingReader {
                    filter: needle.to_owned(),
                    available: present.iter().map(|r| r.id.as_str().to_owned()).collect(),
                }),
                [single] => Ok(single.id.clone()),
                many => Err(ReaderPickError::AmbiguousFilter {
                    filter: needle.to_owned(),
                    matched: many.iter().map(|r| r.id.as_str().to_owned()).collect(),
                }),
            }
        },
    )
}

/// Hardware authority boundary. Concrete adapters (PC/SC, future
/// relay, embedded HAL) implement this trait and return a narrow
/// [`CardTransport`] object to the session layer.
pub trait ReaderBackend {
    /// The backend-specific [`CardTransport`] implementation
    /// returned from [`open_session`](Self::open_session).
    type Transport: CardTransport;
    /// Backend-specific error type for enumeration / connect
    /// failures. Implements `Display` so the caller can render
    /// the diagnostic without knowing the concrete type.
    type Error: core::fmt::Debug + core::fmt::Display;

    /// Enumerate usable readers without opening a card session.
    ///
    /// # Errors
    /// Backend-specific I/O or platform failures.
    fn enumerate(&self) -> Result<Vec<ReaderInfo>, Self::Error>;

    /// Open a session transport for one reader. The session layer
    /// is responsible for all higher-level policy after this point.
    ///
    /// # Errors
    /// Backend-specific I/O or platform failures.
    fn open_session(
        &self,
        reader: &ReaderId,
        access: ReaderAccessCap,
    ) -> Result<Self::Transport, Self::Error>;
}

#[cfg(test)]
mod tests {

    use super::{
        ReaderAccessCap, ReaderBackend, ReaderBackendOps as _, ReaderFilter, ReaderId, ReaderInfo,
        ReaderPickError, pick_single_reader,
    };
    use crate::atr::{Atr, AtrError};
    use crate::transport::{CardTransport, CommandApdu, TransportOutcome};

    /// Transport that is declared but never opened. `pick_single_reader`
    /// decides purely from `enumerate()` and returns a [`ReaderId`];
    /// it never opens a session. The backend below makes that a hard
    /// invariant by panicking in `open_session`, so no transport is
    /// ever constructed and these methods are unreachable.
    struct UnusedTransport;

    impl CardTransport for UnusedTransport {
        type Error = &'static str;
        fn transmit_outcome(
            &mut self,
            _apdu: &CommandApdu,
        ) -> Result<TransportOutcome, Self::Error> {
            unreachable!("pick_single_reader never opens a transport")
        }
        fn atr(&self) -> Result<Atr, AtrError> {
            unreachable!("pick_single_reader never opens a transport")
        }
    }

    /// Backend whose `enumerate()` replays a fixed result. `Ok`
    /// hands back the configured reader list; `Err` simulates a
    /// PC/SC enumeration failure so the picker's error-mapping path
    /// is exercised.
    struct MockBackend {
        enumerate_result: Result<Vec<ReaderInfo>, &'static str>,
    }

    impl ReaderBackend for MockBackend {
        type Transport = UnusedTransport;
        type Error = &'static str;

        fn enumerate(&self) -> Result<Vec<ReaderInfo>, Self::Error> {
            self.enumerate_result.clone()
        }

        fn open_session(
            &self,
            _reader: &ReaderId,
            _access: ReaderAccessCap,
        ) -> Result<Self::Transport, Self::Error> {
            // The picker never opens; reaching here is a bug in the
            // code under test, not a legitimate transport failure.
            panic!("pick_single_reader must not open a transport");
        }
    }

    fn reader(name: &str, card_present: bool) -> ReaderInfo {
        ReaderInfo {
            id: ReaderId::new(name.to_owned()),
            card_present,
        }
    }

    fn backend(readers: Vec<ReaderInfo>) -> MockBackend {
        MockBackend {
            enumerate_result: Ok(readers),
        }
    }

    fn pick(readers: Vec<ReaderInfo>, filter: Option<&str>) -> Result<ReaderId, ReaderPickError> {
        pick_single_reader(&backend(readers), filter.map(ReaderFilter::new))
    }

    // ----- enumeration failures collapse to NoReaders -----

    /// A backend `enumerate()` failure is intentionally flattened to
    /// `NoReaders` (the doc comment notes callers run `enumerate`
    /// directly when they need the underlying distinction).
    #[test]
    fn enumerate_error_maps_to_no_readers() {
        let backend = MockBackend {
            enumerate_result: Err("SCARD_E_NO_SERVICE"),
        };
        assert!(matches!(
            pick_single_reader(&backend, None),
            Err(ReaderPickError::NoReaders)
        ));
    }

    #[test]
    fn no_readers_connected_is_no_readers() {
        assert!(matches!(
            pick(vec![], None),
            Err(ReaderPickError::NoReaders)
        ));
    }

    // ----- no card inserted -----

    /// Readers are connected but every slot is empty: distinct from
    /// `NoReaders` so the operator knows to insert a card rather
    /// than to plug in a reader.
    #[test]
    fn readers_present_but_no_card_is_no_card_present() {
        let readers = vec![reader("Reader Alpha", false), reader("Reader Beta", false)];
        assert!(matches!(
            pick(readers, None),
            Err(ReaderPickError::NoCardPresent)
        ));
    }

    /// A filter cannot resurrect an empty slot: with no card present
    /// anywhere, the picker reports `NoCardPresent` before it ever
    /// considers the filter.
    #[test]
    fn no_card_present_short_circuits_before_filter() {
        let readers = vec![reader("Reader Alpha", false)];
        assert!(matches!(
            pick(readers, Some("Alpha")),
            Err(ReaderPickError::NoCardPresent)
        ));
    }

    // ----- exactly one card present -----

    #[test]
    fn single_card_no_filter_returns_it() {
        let picked = pick(vec![reader("Reader Alpha", true)], None).expect("picks the lone card");
        assert_eq!(picked.as_str(), "Reader Alpha");
    }

    #[test]
    fn single_card_matching_filter_returns_it() {
        let picked = pick(vec![reader("Reader Alpha", true)], Some("Alpha"))
            .expect("filter selects the lone card");
        assert_eq!(picked.as_str(), "Reader Alpha");
    }

    #[test]
    fn single_card_non_matching_filter_is_no_matching_reader() {
        match pick(vec![reader("Reader Alpha", true)], Some("Beta")) {
            Err(ReaderPickError::NoMatchingReader { filter, available }) => {
                assert_eq!(filter, "Beta");
                assert_eq!(available, vec!["Reader Alpha".to_owned()]);
            }
            other => panic!("expected NoMatchingReader, got {other:?}"),
        }
    }

    // ----- the multi-card safety rule (the audit's focus) -----

    /// THE rule: more than one card present and no filter -> refuse,
    /// listing every candidate so the caller can craft a `--reader`
    /// substring. The picker never guesses, because guessing could
    /// fire a card-state-changing APDU at the wrong physical card.
    #[test]
    fn multiple_cards_no_filter_refuses_and_lists_all() {
        let readers = vec![reader("Reader Alpha", true), reader("Reader Beta", true)];
        match pick(readers, None) {
            Err(ReaderPickError::MultipleReadersNoFilter { available }) => {
                // Order is preserved from enumeration so the operator
                // sees readers in the same order the platform reports.
                assert_eq!(
                    available,
                    vec!["Reader Alpha".to_owned(), "Reader Beta".to_owned()]
                );
            }
            other => panic!("expected MultipleReadersNoFilter, got {other:?}"),
        }
    }

    #[test]
    fn multiple_cards_filter_selecting_one_returns_it() {
        let readers = vec![reader("Reader Alpha", true), reader("Reader Beta", true)];
        let picked = pick(readers, Some("Beta")).expect("filter narrows to one card");
        assert_eq!(picked.as_str(), "Reader Beta");
    }

    #[test]
    fn multiple_cards_filter_matching_none_is_no_matching_reader() {
        let readers = vec![reader("Reader Alpha", true), reader("Reader Beta", true)];
        match pick(readers, Some("Gamma")) {
            Err(ReaderPickError::NoMatchingReader { filter, available }) => {
                assert_eq!(filter, "Gamma");
                assert_eq!(
                    available,
                    vec!["Reader Alpha".to_owned(), "Reader Beta".to_owned()]
                );
            }
            other => panic!("expected NoMatchingReader, got {other:?}"),
        }
    }

    /// A filter that still matches more than one card is ambiguous:
    /// the same no-guessing rule applies, but the error reports only
    /// the matched subset (`matched`), not the whole field.
    #[test]
    fn multiple_cards_ambiguous_filter_reports_matched_subset() {
        let readers = vec![
            reader("Reader Alpha", true),
            reader("Reader Beta", true),
            reader("Other Gizmo", true),
        ];
        // "Reader " is a substring of the first two but not the third.
        match pick(readers, Some("Reader ")) {
            Err(ReaderPickError::AmbiguousFilter { filter, matched }) => {
                assert_eq!(filter, "Reader ");
                assert_eq!(
                    matched,
                    vec!["Reader Alpha".to_owned(), "Reader Beta".to_owned()]
                );
            }
            other => panic!("expected AmbiguousFilter, got {other:?}"),
        }
    }

    // ----- card_present is the only thing that counts -----

    /// Only card-present readers are candidates: one empty slot plus
    /// one inserted card is an unambiguous single, not a multi-card
    /// refusal.
    #[test]
    fn empty_slot_alongside_one_card_picks_the_card() {
        let readers = vec![reader("Reader Alpha", false), reader("Reader Beta", true)];
        let picked = pick(readers, None).expect("the single card wins");
        assert_eq!(picked.as_str(), "Reader Beta");
    }

    /// Empty slots are excluded from both candidacy and the
    /// presented `available` list, even when a filter names one.
    #[test]
    fn filter_ignores_empty_slots() {
        let readers = vec![reader("Reader Alpha", true), reader("Reader Beta", false)];
        match pick(readers, Some("Beta")) {
            Err(ReaderPickError::NoMatchingReader { filter, available }) => {
                assert_eq!(filter, "Beta");
                // Reader Beta is omitted: it has no card, so it is
                // neither a candidate nor shown as available.
                assert_eq!(available, vec!["Reader Alpha".to_owned()]);
            }
            other => panic!("expected NoMatchingReader, got {other:?}"),
        }
    }

    // ----- substring-filter semantics -----

    /// The filter is a plain `str::contains` substring test, so an
    /// interior match anywhere in the reader name selects it.
    #[test]
    fn filter_matches_interior_substring() {
        let readers = vec![
            reader("Alcor Micro USB Smart Card Reader 0", true),
            reader("Generic EMV Smartcard Reader 1", true),
        ];
        let picked = pick(readers, Some("Alcor")).expect("interior substring matches");
        assert_eq!(picked.as_str(), "Alcor Micro USB Smart Card Reader 0");
    }

    /// `str::contains` is case-sensitive, so a wrong-case filter does
    /// not match. This pins the documented substring contract; it is
    /// not an accidental behaviour.
    #[test]
    fn filter_is_case_sensitive() {
        let readers = vec![reader("Reader Alpha", true)];
        assert!(matches!(
            pick(readers, Some("alpha")),
            Err(ReaderPickError::NoMatchingReader { .. })
        ));
    }

    /// An empty filter substring matches every reader (documented on
    /// `ReaderFilter::new`). With one card that still resolves to a
    /// single pick...
    #[test]
    fn empty_filter_with_one_card_returns_it() {
        let picked =
            pick(vec![reader("Reader Alpha", true)], Some("")).expect("empty filter matches all");
        assert_eq!(picked.as_str(), "Reader Alpha");
    }

    /// ...but with two cards the empty filter matches both and is
    /// therefore ambiguous -- it does not silently fall back to the
    /// no-filter "refuse" path, it goes through `AmbiguousFilter`.
    #[test]
    fn empty_filter_with_two_cards_is_ambiguous() {
        let readers = vec![reader("Reader Alpha", true), reader("Reader Beta", true)];
        match pick(readers, Some("")) {
            Err(ReaderPickError::AmbiguousFilter { filter, matched }) => {
                assert_eq!(filter, "");
                assert_eq!(matched.len(), 2);
            }
            other => panic!("expected AmbiguousFilter, got {other:?}"),
        }
    }

    // ----- the trait wrapper delegates to the free function -----

    /// `ReaderBackendOps::pick_single_reader` is the public surface;
    /// it must behave identically to the free function on both the
    /// success and the refuse paths.
    #[test]
    fn trait_method_matches_free_function() {
        let one = backend(vec![reader("Reader Alpha", true)]);
        assert_eq!(
            one.pick_single_reader(None).expect("trait picks").as_str(),
            "Reader Alpha"
        );

        let many = backend(vec![
            reader("Reader Alpha", true),
            reader("Reader Beta", true),
        ]);
        assert!(matches!(
            many.pick_single_reader(None),
            Err(ReaderPickError::MultipleReadersNoFilter { .. })
        ));
    }

    // ----- operator-facing diagnostics -----

    /// The refuse message is actionable: it states the count, the
    /// remedy (`--reader SUBSTR`), and every candidate name.
    #[test]
    fn multiple_readers_display_is_actionable() {
        let err = ReaderPickError::MultipleReadersNoFilter {
            available: vec!["Reader Alpha".to_owned(), "Reader Beta".to_owned()],
        };
        assert_eq!(
            err.to_string(),
            "2 cards present; pass --reader SUBSTR to pick one: [Reader Alpha, Reader Beta]"
        );
    }

    /// Filter strings are rendered with `Debug`-quoting so an empty
    /// or whitespace-only `--reader` argument stays visible in the
    /// diagnostic instead of collapsing into surrounding text.
    #[test]
    fn filter_strings_render_with_debug_quoting() {
        let blank = ReaderPickError::NoMatchingReader {
            filter: "  ".to_owned(),
            available: vec!["Reader Alpha".to_owned()],
        };
        let rendered = blank.to_string();
        assert!(
            rendered.contains("--reader \"  \""),
            "whitespace filter should be quoted: {rendered}"
        );

        let empty = ReaderPickError::NoMatchingReader {
            filter: String::new(),
            available: vec!["Reader Alpha".to_owned()],
        };
        assert!(
            empty.to_string().contains("--reader \"\""),
            "empty filter should render as visible empty quotes"
        );
    }

    #[test]
    fn ambiguous_and_remaining_displays_render() {
        let ambiguous = ReaderPickError::AmbiguousFilter {
            filter: "Reader".to_owned(),
            matched: vec!["Reader Alpha".to_owned(), "Reader Beta".to_owned()],
        };
        assert_eq!(
            ambiguous.to_string(),
            "--reader \"Reader\" matched more than one card-present reader: \
             [Reader Alpha, Reader Beta] -- narrow the substring"
        );

        assert_eq!(
            ReaderPickError::NoReaders.to_string(),
            "no PC/SC readers connected"
        );
        assert_eq!(
            ReaderPickError::NoCardPresent.to_string(),
            "no card present in any reader"
        );

        // NoFineidCard lives here but is raised by pkcs15's picker;
        // its rendering is still part of this module's contract.
        let no_fineid = ReaderPickError::NoFineidCard {
            available: vec!["YubiKey OTP+FIDO+CCID".to_owned()],
        };
        assert!(no_fineid.to_string().contains("SELECT PKCS#15"));
    }

    // ----- typed boundary wrappers -----

    #[test]
    fn reader_filter_roundtrips_and_borrows() {
        let filter = ReaderFilter::new("Alpha");
        assert_eq!(filter.as_str(), "Alpha");
        assert_eq!(filter.to_string(), "Alpha");
        // `AsRef<str>` constructor accepts an owned String too.
        assert_eq!(ReaderFilter::new(String::from("Beta")).as_str(), "Beta");
    }

    #[test]
    fn reader_id_roundtrips() {
        let id = ReaderId::new("Reader Alpha".to_owned());
        assert_eq!(id.as_str(), "Reader Alpha");
    }
}
