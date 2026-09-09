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

//! Structured event infrastructure.
//!
//! Library and binary crates emit observable events through this
//! module. Events are typed Rust structs that implement the
//! [`EventRecord`] trait; sinks are runtime-configurable
//! implementations of [`LogSink`]. The wire form is flat-key-
//! value JSON Lines per `doc/observability.md`.
//!
//! The full architectural reasoning -- deployment profiles
//! (personal / enterprise / air-gap), severity contract, three-
//! tier persistence, privacy classification, network-by-
//! instruction rules -- lives in `doc/observability.md` and
//! `doc/security/excellence-rules.md` (Rules E15 through E21).
//! This module is the implementation foundation those documents
//! describe.
//!
//! ## What this module provides today
//!
//! - The [`EventRecord`] trait: every event type's compile-time
//!   API. Hardcodes its [`EventName`], [`Severity`],
//!   [`Persistence`], and the typed-field iteration.
//! - Validated identifier newtypes: [`EventName`] and
//!   [`FieldName`] with `const fn` constructors that reject
//!   malformed input at compile time.
//! - Enum primitives: [`Severity`] (eight RFC 5424 levels per
//!   Rule E16), [`Persistence`] (three tiers per Rule E18),
//!   [`FieldPrivacy`] and [`FieldDescriptor`] (per-field
//!   privacy classification per Rule E1's privacy model).
//! - The [`LogSink`] trait + the [`StderrSink`] implementation
//!   that writes the canonical JSON Lines wire form.
//! - The global emission mechanism: [`set_global_sink`] and
//!   [`emit`]. The shape matches `log::set_logger` /
//!   `tracing::set_global_default`: first-write-wins, no-op
//!   when unset (with a one-time stderr notice on first emit
//!   into a no-sink state).
//!
//! ## What this module does NOT provide yet
//!
//! - Per-platform sinks (`os_log`, `journald`, `eventlog`).
//! - Remote sinks (`syslog` over TLS, OTLP). The personal-
//!   profile build deliberately excludes these (Rule E17);
//!   the enterprise-profile feature gate is future work.
//! - The `no_network` Cargo feature for air-gap builds.
//! - The `refineid-events-derive` proc-macro. Manual `impl
//!   EventRecord` for now; add the macro when event count
//!   grows past ~30 per the Open follow-ups in
//!   `doc/observability.md`.
//!
//! Each follow-up has a matching entry in observability.md's
//! Open follow-ups section.

use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};
use std::io::{self, Write as _};
use std::sync::OnceLock;

// ===========================================================
// Identifier newtypes with compile-time validation
// ===========================================================

/// Event-name newtype. Carries a `&'static str` that has been
/// validated at compile time to satisfy the project's event-name
/// format rules.
///
/// Format rules enforced by [`EventName::new`] at `const`
/// context (the call site fails to compile if violated):
///
/// - 1..=64 bytes. RFC 5424 SD-NAME is strictly 1..=32; we use
///   64 to match the journald field-name limit and to allow the
///   project's descriptive verb-past-participle naming
///   (`card.activate.preflight.pin_changed_probed`). Syslog
///   sinks targeting strict-RFC-5424 parsers truncate names
///   above 32 bytes (documented in
///   `doc/observability.md -> Sinks -> Encoding details`).
/// - Lower-case ASCII letters, digits, underscores, and dots.
/// - Must start with a lowercase letter.
/// - Must contain at least one dot (dotted namespace).
/// - No leading dot, no trailing dot, no consecutive dots.
///
/// Construct via the const constructor:
///
/// ```ignore
/// const CARD_TARGET: EventName = EventName::new("card.target");
/// ```
///
/// A typo or format violation produces a compile-time panic
/// with a descriptive message; the call site is the failure
/// location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EventName(&'static str);

impl EventName {
    /// Construct a validated event name.
    ///
    /// Panics at compile time if `name` violates the format
    /// rules. The panic surfaces as a build failure pointing
    /// at the call site.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// const OK: EventName = EventName::new("card.target");
    /// // const BAD: EventName = EventName::new("Card.Target");  // build fails
    /// ```
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self(validate_event_name(name))
    }

    /// Return the validated name as a `&'static str`.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        self.0
    }
}

impl fmt::Display for EventName {
    /// Display the event name as its canonical string form.
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// Field-name newtype. Carries a `&'static str` validated at
/// compile time to satisfy the field-name format rules.
///
/// Format rules enforced by [`FieldName::new`] at `const`
/// context:
///
/// - 1..=64 bytes (matches journald field-name limit and the
///   relaxed-from-RFC-5424 [`EventName`] limit).
/// - Lower-case ASCII letters, digits, and underscores only.
/// - Must start with a lowercase letter.
/// - No dots (unlike [`EventName`], field names are not
///   namespaced).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FieldName(&'static str);

impl FieldName {
    /// Construct a validated field name.
    ///
    /// Panics at compile time if `name` violates the format
    /// rules.
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self(validate_field_name(name))
    }

    /// Return the validated name as a `&'static str`.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        self.0
    }
}

impl fmt::Display for FieldName {
    /// Display the field name as its canonical string form.
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// Validate an event name at `const` context. Panics with a
/// descriptive message on violation; the panic IS the compile
/// error. Returns the validated bytes wrapped in the same
/// `&'static str` slice (the validator does not allocate).
#[expect(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "const-time validator: indexing is bounds-checked in source by prior length / non-empty checks; arithmetic (bytes.len() - 1) is guarded by the explicit is_empty check. (assert! does not trigger clippy::panic, so that lint is not listed.)"
)]
const fn validate_event_name(name: &'static str) -> &'static str {
    let bytes = name.as_bytes();
    assert!(!bytes.is_empty(), "EventName must not be empty");
    assert!(
        bytes.len() <= 64,
        "EventName must be at most 64 bytes (journald field-name limit; strict-RFC-5424 syslog sinks truncate at 32 bytes)"
    );
    let first = bytes[0];
    assert!(
        first >= b'a' && first <= b'z',
        "EventName must start with a lowercase ASCII letter"
    );
    let last = bytes[bytes.len() - 1];
    assert!(last != b'.', "EventName must not end with a dot");

    let mut i: usize = 0;
    let mut prev_dot = false;
    let mut has_dot = false;
    while i < bytes.len() {
        let b = bytes[i];
        let is_lower = b >= b'a' && b <= b'z';
        let is_digit = b >= b'0' && b <= b'9';
        let is_underscore = b == b'_';
        let is_dot = b == b'.';
        assert!(
            is_lower || is_digit || is_underscore || is_dot,
            "EventName: only lower_snake_case ASCII letters, digits, underscores, and dots are allowed"
        );
        assert!(
            !(is_dot && prev_dot),
            "EventName: consecutive dots are forbidden"
        );
        if is_dot {
            has_dot = true;
        }
        prev_dot = is_dot;
        i = i.wrapping_add(1);
    }
    assert!(
        has_dot,
        "EventName must be a dotted namespace (e.g. 'card.target')"
    );
    name
}

/// Validate a field name at `const` context. Same shape as
/// [`validate_event_name`] but without the dotted-namespace
/// requirement (field names are flat identifiers).
#[expect(
    clippy::indexing_slicing,
    reason = "const-time validator: indexing is bounds-checked in source by prior length / non-empty checks. (assert! does not trigger clippy::panic, so that lint is not listed.)"
)]
const fn validate_field_name(name: &'static str) -> &'static str {
    let bytes = name.as_bytes();
    assert!(!bytes.is_empty(), "FieldName must not be empty");
    assert!(bytes.len() <= 64, "FieldName must be at most 64 bytes");
    let first = bytes[0];
    assert!(
        first >= b'a' && first <= b'z',
        "FieldName must start with a lowercase ASCII letter"
    );

    let mut i: usize = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let is_lower = b >= b'a' && b <= b'z';
        let is_digit = b >= b'0' && b <= b'9';
        let is_underscore = b == b'_';
        assert!(
            is_lower || is_digit || is_underscore,
            "FieldName: only lower_snake_case ASCII letters, digits, and underscores are allowed"
        );
        i = i.wrapping_add(1);
    }
    name
}

// ===========================================================
// Severity (Rule E16)
// ===========================================================

/// Event severity.
///
/// Eight levels per RFC 5424 (per Rule E16 in
/// `doc/security/excellence-rules.md`). The level a given event
/// emits is hardcoded in its [`EventRecord`] impl; it is part of
/// the event's compile-time API.
///
/// Per-level definitions and frequency expectations live in
/// `doc/observability.md -> Severity -> The eight levels`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    /// Trust assumptions of the deployment are violated. Audit
    /// chain tamper detected, pinned-root SHA-256 mismatch.
    /// Never in normal operation.
    Emerg,
    /// Active intervention required. Cryptographic primitive
    /// returned a result violating its specification, `PinBytes`
    /// drop panicked. Never in normal operation.
    Alert,
    /// Component failure -- the tool cannot do its job. PC/SC
    /// subsystem unavailable, audit-chain writer cannot persist.
    /// Rare.
    Crit,
    /// Operation failed in a way the caller will see as failure.
    /// Already propagates as `Result::Err`; the event records
    /// the failure for forensics. 0-1 per failed invocation.
    Err,
    /// Operation succeeded but is suspect, or was rejected for a
    /// recoverable reason. Cert chain validated via fallback
    /// root, PIN verified on last attempt. 0-3 per typical
    /// invocation.
    Warning,
    /// Normal but security-relevant. Session lifecycle, trust
    /// transitions, PIN changes, signing acts. The tier SOC
    /// dashboards want by default. 2-10 per typical invocation.
    Notice,
    /// Routine flow. PACE step transitions, APDU framing
    /// decisions, cert reads. 10-100 per typical invocation.
    Info,
    /// Diagnostic detail. State machine transitions, hex dumps.
    /// Off by default at every sink; compile out from release
    /// when expensive.
    Debug,
}

impl Severity {
    /// Return the numeric RFC 5424 priority (0..=7). Lower
    /// number = higher severity.
    #[must_use]
    pub const fn priority(self) -> u8 {
        match self {
            Self::Emerg => 0,
            Self::Alert => 1,
            Self::Crit => 2,
            Self::Err => 3,
            Self::Warning => 4,
            Self::Notice => 5,
            Self::Info => 6,
            Self::Debug => 7,
        }
    }

    /// Return the canonical lowercase string form (`"emerg"`,
    /// `"alert"`, ..., `"debug"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Emerg => "emerg",
            Self::Alert => "alert",
            Self::Crit => "crit",
            Self::Err => "err",
            Self::Warning => "warning",
            Self::Notice => "notice",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }
}

impl fmt::Display for Severity {
    /// Display the severity as its canonical lowercase string.
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ===========================================================
// Persistence (Rule E18)
// ===========================================================

/// Event persistence tier.
///
/// Defined by Rule E18 in `doc/security/excellence-rules.md`.
/// The tier a given event declares is hardcoded in its
/// [`EventRecord`] impl; changing it requires a `CHANGELOG.md`
/// entry and reviewer signoff.
///
/// Per-tier definitions live in
/// `doc/observability.md -> Persistence`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Persistence {
    /// stderr only, gone when the terminal closes. No disk
    /// artifact ever. Default for routine flow.
    Ephemeral,
    /// Platform log (`os_log` / `journald` / `eventlog`) with
    /// platform-default retention. Citizen-readable via the
    /// platform's own diagnostic tooling.
    OsManaged,
    /// Audit chain with citizen-controlled retention,
    /// tamper-evident, encrypted at rest.
    /// Used for the citizen's own deliberate acts where durable
    /// proof matters.
    Forensic,
}

impl Persistence {
    /// Return the canonical lowercase string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ephemeral => "ephemeral",
            Self::OsManaged => "os_managed",
            Self::Forensic => "forensic",
        }
    }
}

impl fmt::Display for Persistence {
    /// Display the persistence tier as its canonical lowercase
    /// string.
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ===========================================================
// Field privacy and descriptor
// ===========================================================

/// Per-field privacy classification.
///
/// Bundled into [`FieldDescriptor`] so the privacy bit travels
/// with the field name through [`EventRecord::for_each_field`];
/// there is no separate `private_fields` list that could drift
/// out of sync with the actual field set.
///
/// The `Secret` tier (PIN bytes, private keys) is enforced one
/// type-layer up: secret-bearing types deliberately do not
/// implement `Display`, so they cannot be passed to the field-
/// iteration callback at all. Two layers, neither relying on
/// the other for the guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldPrivacy {
    /// Field value is safe to emit to any destination class
    /// (operator stderr, SOC syslog, remote OTLP).
    Public,
    /// Field value is PII (per Rule E1's privacy classification)
    /// and must be redacted on destination-public sinks. Per-
    /// platform privacy primitives (`os_log %{private}`,
    /// chmod-640 syslog files) honor it; sinks without native
    /// support pre-redact at the encoding boundary.
    Private,
}

/// Field-descriptor: name plus privacy.
///
/// A [`FieldName`] bundled with its [`FieldPrivacy`]
/// classification. Carried inline through the
/// [`EventRecord::for_each_field`] callback so the privacy bit
/// cannot drift from the field set.
#[derive(Debug, Clone, Copy)]
pub struct FieldDescriptor {
    /// The field's compile-time-validated name.
    pub name: FieldName,
    /// The field's per-event privacy classification.
    pub privacy: FieldPrivacy,
}

impl FieldDescriptor {
    /// Construct a field descriptor from name + privacy. Used
    /// in per-event `const` blocks alongside [`FieldName::new`].
    #[must_use]
    pub const fn new(name: FieldName, privacy: FieldPrivacy) -> Self {
        Self { name, privacy }
    }
}

// ===========================================================
// EventRecord trait
// ===========================================================

/// Universal interface for events emitted to logging sinks.
///
/// The trait uses dynamic dispatch (`&dyn EventRecord` at the
/// sink boundary, `&mut dyn FnMut(...)` for the field iteration,
/// `&dyn fmt::Display` for field values) rather than generics
/// to preserve object safety. Object safety lets
/// `Box<dyn LogSink>` hold heterogeneous sinks at runtime --
/// the multi-sink fan-out that the deployment-profile
/// architecture (Rules E17 / E18 / E19) depends on.
///
/// Each `impl EventRecord` block is fully concretely typed; the
/// typing-discipline is enforced at the impl site, not at the
/// trait boundary. The `dyn` parameters are the contract-
/// enforcement layer (the compiler proves the value satisfies
/// the trait at every conversion point), not a relaxation of
/// strong typing.
///
/// See `doc/observability.md -> Trait shape and dynamic
/// dispatch` for the full architectural reasoning.
pub trait EventRecord {
    /// Return the event's compile-time-validated name. Hardcoded
    /// per impl as a `const EVENT_NAME: EventName` in the
    /// event's accompanying impl block.
    fn event_name(&self) -> EventName;

    /// Return the event's severity. Hardcoded per impl. The
    /// level is part of the event's public API contract per
    /// Rule E16; changing it requires a `CHANGELOG.md` entry.
    fn level(&self) -> Severity;

    /// Return the event's persistence tier. Default is
    /// [`Persistence::Ephemeral`] per Rule E18 (routine
    /// successful operations leave no disk artifact). Hardcoded
    /// per impl when the event is forensic-grade or warrants
    /// OS-managed retention.
    fn persistence(&self) -> Persistence {
        Persistence::Ephemeral
    }

    /// Yield each field of the event as a [`FieldDescriptor`]
    /// (name + privacy) paired with the field's value as
    /// `&dyn fmt::Display`.
    ///
    /// The callback shape (rather than `-> impl Iterator`) is
    /// what preserves object safety on this trait, which in
    /// turn enables `&dyn EventRecord` to be passed to
    /// [`LogSink::emit`]. The sink renders each value via
    /// `Display` when it needs the wire-form string; the
    /// trait does not allocate.
    fn for_each_field(&self, f: &mut dyn FnMut(FieldDescriptor, &dyn fmt::Display));
}

// ===========================================================
// LogSink trait
// ===========================================================

/// Universal interface for logging sinks.
///
/// Sinks are object-safe (`Box<dyn LogSink>`) so the runtime
/// sink set can be configured per deployment profile. Each
/// emit accepts a `&dyn EventRecord` and is responsible for
/// encoding the event into its target's native form (the
/// canonical JSON Lines wire form for stderr, RFC 5424 SD-
/// element for syslog, native fields for journald, etc.).
///
/// `Send + Sync` is required because the global sink lives in
/// a `OnceLock<Box<dyn LogSink>>` accessible from any thread.
/// Sinks must be internally synchronized (mutex, channel,
/// atomic) if their underlying resource is not thread-safe.
pub trait LogSink: Send + Sync {
    /// Emit a single event to the sink.
    ///
    /// Sinks SHOULD be best-effort: a sink that cannot write
    /// to its destination drops the event silently rather than
    /// propagating an error (which would force the emit caller
    /// to handle a failure case for what is fundamentally a
    /// best-effort observability path). Persistent forensic
    /// records flow through the audit chain, which is a
    /// separate channel with stronger durability guarantees.
    fn emit(&self, event: &dyn EventRecord);
}

// ===========================================================
// Null sink (no-op)
// ===========================================================

/// No-op sink. Drops every event silently. Useful for tests
/// that exercise event-emitting code paths without caring
/// about the emissions.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullSink;

impl NullSink {
    /// Construct a no-op sink.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl LogSink for NullSink {
    /// Drop the event silently.
    #[inline]
    fn emit(&self, _event: &dyn EventRecord) {}
}

// ===========================================================
// Stderr sink
// ===========================================================

/// Stderr sink. Writes the canonical JSON Lines wire form to
/// `stderr`, one event per line. This is the default sink
/// across all deployment profiles per
/// `doc/observability.md -> Sinks`.
///
/// The wire format is a flat JSON object with `"event"` and
/// `"severity"` as the first two fields, followed by the
/// event's typed fields in iteration order. A single space
/// follows every `:` and `,` (RFC 8259 insignificant
/// whitespace) so `jq -c .` round-trips identically; the form
/// stays grep-friendly for operators reading raw stderr.
///
/// Best-effort write semantics: stderr write errors are
/// silently dropped (a process that cannot write to stderr
/// cannot usefully continue, but we do not abort over it).
#[derive(Debug, Clone, Copy, Default)]
pub struct StderrSink;

impl StderrSink {
    /// Construct a stderr sink.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl LogSink for StderrSink {
    /// Encode the event as JSON Lines and write one line to
    /// `stderr`. Best-effort: errors are dropped.
    fn emit(&self, event: &dyn EventRecord) {
        /// Initial buffer size for one JSONL envelope. Re-
        /// allocates transparently for larger payloads; sized
        /// for the typical `card.target` / `card.sign.*` event.
        const ENVELOPE_INITIAL_CAPACITY: usize = 128;
        let mut buf = Vec::with_capacity(ENVELOPE_INITIAL_CAPACITY);

        // Open the object and write the canonical leading fields:
        //   {"event": "<name>", "severity": "<level>"
        buf.extend_from_slice(b"{\"event\": \"");
        Json::write_escaped(&mut buf, event.event_name().as_str());
        buf.extend_from_slice(b"\", \"severity\": \"");
        Json::write_escaped(&mut buf, event.level().as_str());
        buf.extend_from_slice(b"\"");

        // Iterate the event's typed fields. Each call writes
        //   , "<name>": "<display-of-value>"
        // into the buffer, JSON-escaping both name and value.
        event.for_each_field(&mut |descriptor, value| {
            buf.extend_from_slice(b", \"");
            Json::write_escaped(&mut buf, descriptor.name.as_str());
            buf.extend_from_slice(b"\": \"");
            match descriptor.privacy {
                // `Private` fields carry PII / secret material (PIN
                // bytes, VERIFY/CHANGE-REFERENCE-DATA APDU payloads).
                // This sink is the terminal source-level renderer, so
                // it MUST redact rather than emit the value -- the
                // "redacted at the source" guarantee WARNING.md makes.
                // A platform sink that maps `Private` to `os_log
                // %{private}` can render the real value under an audit
                // entitlement; plain stderr never does.
                FieldPrivacy::Private => buf.extend_from_slice(b"<redacted>"),
                FieldPrivacy::Public => {
                    // Render the Display value into the buffer,
                    // escaping JSON-special characters as we go. No
                    // intermediate String allocation.
                    let mut esc = JsonEscapingWriter { buf: &mut buf };
                    // `fmt::write` returns fmt::Result; we discard it
                    // because JsonEscapingWriter never fails (its
                    // Write impl only extends a Vec). Explicit type
                    // annotation satisfies clippy::let_underscore_must_use
                    // without invoking drop() on a Copy type.
                    let _fmt: fmt::Result = fmt::write(&mut esc, format_args!("{value}"));
                }
            }
            buf.extend_from_slice(b"\"");
        });

        buf.extend_from_slice(b"}\n");

        // Best-effort write to stderr. Lock once to keep the
        // line atomic against concurrent emits.
        let stderr = io::stderr();
        let mut handle = stderr.lock();
        // io::Result intentionally dropped: best-effort sink.
        drop(handle.write_all(&buf));
    }
}

/// JSON-encoding helpers grouped on a zero-sized namespace
/// struct (typing-discipline Rule A: free fns with borrowed
/// parameters are not allowed; methods on a natural carrier
/// type are).  The encoder is otherwise stateless -- no
/// configuration, no per-instance buffer -- so `Json` carries
/// no fields.
pub(crate) struct Json;

impl Json {
    /// Write `s` to `out` with JSON string-content escaping per
    /// RFC 8259 §7. Handles the seven required escapes (`"`, `\`,
    /// `\n`, `\r`, `\t`, `\b`, `\f`), `\u00XX` for other control
    /// characters under 0x20, and UTF-8 pass-through for
    /// everything else. Multi-byte UTF-8 is written verbatim
    /// (RFC 8259 §8.1 allows non-ASCII Unicode in JSON strings).
    pub(crate) fn write_escaped(out: &mut Vec<u8>, s: &str) {
        for c in s.chars() {
            Self::write_escaped_char(out, c);
        }
    }

    /// Write one Unicode scalar with JSON escape encoding into
    /// `out`. See [`Json::write_escaped`] for the encoding rules.
    pub(crate) fn write_escaped_char(out: &mut Vec<u8>, c: char) {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{0008}' => out.extend_from_slice(b"\\b"),
            '\u{000C}' => out.extend_from_slice(b"\\f"),
            // C0 control chars are everything below ASCII space.
            ctrl if u32::from(ctrl) < u32::from(b' ') => {
                // Other C0 control chars: \u00XX form. Width-4 lowercase
                // hex matches the convention serde_json uses (and the
                // pinned wire-format tests in the existing log_event.rs).
                // write_fmt cannot fail on Vec<u8>; explicit type
                // annotation satisfies the must-use lint without drop()
                // on a Copy type.
                let _fmt: io::Result<()> = write!(out, "\\u{:04x}", u32::from(ctrl));
            }
            other => {
                // UTF-8 pass-through. encode_utf8 writes 1..=4 bytes
                // into a stack buffer; we copy to out.
                let mut tmp = [0_u8; 4];
                let encoded = other.encode_utf8(&mut tmp);
                out.extend_from_slice(encoded.as_bytes());
            }
        }
    }
}

/// `fmt::Write` adapter that JSON-escapes characters as they are
/// written into an underlying `Vec<u8>`. Used by [`StderrSink`]
/// to materialise a field's `&dyn fmt::Display` value directly
/// into the output buffer without an intermediate `String`
/// allocation.
struct JsonEscapingWriter<'a> {
    /// Output buffer the escaped UTF-8 is appended to.
    buf: &'a mut Vec<u8>,
}

impl fmt::Write for JsonEscapingWriter<'_> {
    /// Append `s` to the buffer with JSON string-content
    /// escaping. Cannot fail (the underlying `Vec` extension is
    /// infallible).
    fn write_str(&mut self, s: &str) -> fmt::Result {
        Json::write_escaped(self.buf, s);
        Ok(())
    }
}

// ===========================================================
// Global sink + emit dispatch
// ===========================================================

/// Process-global log sink. Set once at startup via
/// [`set_global_sink`]; subsequent set attempts return
/// [`SinkAlreadySet`].
static GLOBAL_SINK: OnceLock<Box<dyn LogSink>> = OnceLock::new();

/// Flag tracking whether the no-sink-configured warning has
/// already been emitted to stderr. Ensures the warning fires
/// at most once per process; subsequent `emit()` calls with no
/// sink configured are silently dropped.
static NO_SINK_WARNED: AtomicBool = AtomicBool::new(false);

/// Error returned by [`set_global_sink`] when the global sink
/// has already been set in this process.
#[derive(Debug, Clone, Copy)]
pub struct SinkAlreadySet;

impl fmt::Display for SinkAlreadySet {
    /// Display the error as a human-readable message.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("global log sink has already been set in this process")
    }
}

impl core::error::Error for SinkAlreadySet {}

/// Install the process-global log sink. First call wins;
/// subsequent calls return [`SinkAlreadySet`] without
/// replacing the sink.
///
/// Matches the shape of `log::set_logger` and
/// `tracing::set_global_default`: the bin crate calls this
/// once at startup after parsing flags / env vars to select
/// the deployment profile, and the sink set stays fixed for
/// the process lifetime.
///
/// # Errors
/// Returns [`SinkAlreadySet`] if the global sink has already
/// been installed in this process.
pub fn set_global_sink(sink: Box<dyn LogSink>) -> Result<(), SinkAlreadySet> {
    GLOBAL_SINK.set(sink).map_err(|_unused| SinkAlreadySet)
}

/// Emit an event through the process-global log sink.
///
/// If no sink has been configured (see [`set_global_sink`]),
/// the event is silently dropped. A one-time stderr warning
/// is emitted on the first such drop per process, surfacing
/// the misconfiguration to operators without flooding stderr
/// with repeated messages. See
/// `doc/observability.md -> Trait shape -> When no sink is
/// configured` for the rationale.
pub fn emit<E: EventRecord>(event: &E) {
    match GLOBAL_SINK.get() {
        Some(sink) => sink.emit(event),
        None => warn_no_sink_once(),
    }
}

/// Write the one-time "no log sink configured" warning to
/// stderr. The atomic swap guarantees the message is emitted
/// at most once per process; subsequent calls are a fast
/// load-and-skip.
fn warn_no_sink_once() {
    if !NO_SINK_WARNED.swap(true, Ordering::Relaxed) {
        let stderr = io::stderr();
        let mut handle = stderr.lock();
        // Best-effort; errors are dropped because a process
        // that cannot write to stderr cannot usefully continue
        // but we don't abort over it.
        drop(handle.write_all(
            b"refineid: no log sink configured; events will not be visible. \
              Call refineid_lib_core::events::set_global_sink() at startup.\n",
        ));
    }
}

// ===========================================================
// Tests
// ===========================================================

#[cfg(test)]
mod tests {
    use super::{
        EventName, EventRecord, FieldDescriptor, FieldName, FieldPrivacy, Json, LogSink, NullSink,
        Persistence, Severity, StderrSink,
    };
    use core::fmt;

    // -- EventName / FieldName const-validation --
    //
    // Positive cases (success) are exercised here. Negative cases
    // (compile-time rejection of malformed names) are not
    // exercised in #[cfg(test)] because they require
    // compile-fail testing infrastructure (`trybuild` or
    // similar), which is added in a follow-up.

    #[test]
    fn event_name_accepts_valid_dotted_namespace() {
        const NAME: EventName = EventName::new("card.target");
        assert_eq!(NAME.as_str(), "card.target");
    }

    #[test]
    fn event_name_accepts_deep_namespace() {
        const NAME: EventName = EventName::new("card.activate.preflight.ready");
        assert_eq!(NAME.as_str(), "card.activate.preflight.ready");
    }

    #[test]
    fn event_name_accepts_digits_and_underscores() {
        const NAME: EventName = EventName::new("card.activate.pin1.set");
        assert_eq!(NAME.as_str(), "card.activate.pin1.set");
    }

    #[test]
    fn field_name_accepts_valid_identifier() {
        const NAME: FieldName = FieldName::new("device");
        assert_eq!(NAME.as_str(), "device");
    }

    #[test]
    fn field_name_accepts_with_underscores_and_digits() {
        const NAME: FieldName = FieldName::new("trust_root_sha256");
        assert_eq!(NAME.as_str(), "trust_root_sha256");
    }

    // -- Severity --

    #[test]
    fn severity_priority_matches_rfc_5424() {
        assert_eq!(Severity::Emerg.priority(), 0);
        assert_eq!(Severity::Alert.priority(), 1);
        assert_eq!(Severity::Crit.priority(), 2);
        assert_eq!(Severity::Err.priority(), 3);
        assert_eq!(Severity::Warning.priority(), 4);
        assert_eq!(Severity::Notice.priority(), 5);
        assert_eq!(Severity::Info.priority(), 6);
        assert_eq!(Severity::Debug.priority(), 7);
    }

    #[test]
    fn severity_canonical_strings() {
        assert_eq!(Severity::Notice.as_str(), "notice");
        assert_eq!(Severity::Err.as_str(), "err");
        assert_eq!(Severity::Debug.as_str(), "debug");
    }

    // -- Persistence --

    #[test]
    fn persistence_canonical_strings() {
        assert_eq!(Persistence::Ephemeral.as_str(), "ephemeral");
        assert_eq!(Persistence::OsManaged.as_str(), "os_managed");
        assert_eq!(Persistence::Forensic.as_str(), "forensic");
    }

    // -- JSON escape --

    #[test]
    fn json_escape_basic_pass_through() {
        let mut out = Vec::new();
        Json::write_escaped(&mut out, "hello world");
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn json_escape_quote_and_backslash() {
        let mut out = Vec::new();
        Json::write_escaped(&mut out, r#"a"b\c"#);
        assert_eq!(out, br#"a\"b\\c"#);
    }

    #[test]
    fn json_escape_control_characters() {
        let mut out = Vec::new();
        Json::write_escaped(&mut out, "a\nb\tc\rd");
        assert_eq!(out, b"a\\nb\\tc\\rd");
    }

    #[test]
    fn json_escape_other_control_uses_u_hex() {
        let mut out = Vec::new();
        Json::write_escaped(&mut out, "\u{0001}\u{001F}");
        assert_eq!(out, b"\\u0001\\u001f");
    }

    #[test]
    fn json_escape_utf8_pass_through() {
        let mut out = Vec::new();
        Json::write_escaped(&mut out, "K\u{00f6}istinen");
        // UTF-8: ö is 0xc3 0xb6
        assert_eq!(out, "K\u{00f6}istinen".as_bytes());
    }

    // -- Trait object safety + StderrSink emission --

    /// Minimal sample event used by sink tests. Exercises every
    /// `EventRecord` method including the field iteration callback,
    /// with one `Public` and one `Private` field so redaction is
    /// covered.
    struct SampleEvent<'a> {
        device: &'a str,
        secret: &'a str,
    }

    impl SampleEvent<'_> {
        const EVENT_NAME: EventName = EventName::new("test.sample");
        const LEVEL: Severity = Severity::Notice;
        const F_DEVICE: FieldDescriptor =
            FieldDescriptor::new(FieldName::new("device"), FieldPrivacy::Public);
        const F_SECRET: FieldDescriptor =
            FieldDescriptor::new(FieldName::new("secret"), FieldPrivacy::Private);
    }

    impl EventRecord for SampleEvent<'_> {
        fn event_name(&self) -> EventName {
            Self::EVENT_NAME
        }

        fn level(&self) -> Severity {
            Self::LEVEL
        }

        fn for_each_field(&self, f: &mut dyn FnMut(FieldDescriptor, &dyn fmt::Display)) {
            f(Self::F_DEVICE, &self.device);
            f(Self::F_SECRET, &self.secret);
        }
    }

    #[test]
    fn event_record_is_object_safe() {
        // Compile-time test: this would fail to compile if
        // EventRecord were not object-safe.
        let event = SampleEvent {
            device: "x",
            secret: "s",
        };
        let _: &dyn EventRecord = &event;
    }

    #[test]
    fn log_sink_is_object_safe() {
        // Compile-time test: this would fail to compile if
        // LogSink were not object-safe. We drop() the boxed
        // sinks explicitly to satisfy must_use.
        drop::<Box<dyn LogSink>>(Box::new(StderrSink::new()));
        drop::<Box<dyn LogSink>>(Box::new(NullSink::new()));
    }

    #[test]
    fn null_sink_drops_silently() {
        let sink = NullSink::new();
        let event = SampleEvent {
            device: "x",
            secret: "s",
        };
        // No assertion: the test passes if emit returns without
        // panicking or writing anywhere observable.
        sink.emit(&event);
    }

    /// Render an event through the same encoding path `StderrSink`
    /// uses, into a buffer instead of stderr. Lets tests assert
    /// the canonical wire form.
    fn render_to_buffer(event: &dyn EventRecord) -> String {
        use super::JsonEscapingWriter;
        use core::fmt::Write as _;

        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"{\"event\": \"");
        Json::write_escaped(&mut buf, event.event_name().as_str());
        buf.extend_from_slice(b"\", \"severity\": \"");
        Json::write_escaped(&mut buf, event.level().as_str());
        buf.extend_from_slice(b"\"");
        event.for_each_field(&mut |descriptor, value| {
            buf.extend_from_slice(b", \"");
            Json::write_escaped(&mut buf, descriptor.name.as_str());
            buf.extend_from_slice(b"\": \"");
            match descriptor.privacy {
                FieldPrivacy::Private => buf.extend_from_slice(b"<redacted>"),
                FieldPrivacy::Public => {
                    let mut esc = JsonEscapingWriter { buf: &mut buf };
                    let _fmt: fmt::Result = write!(esc, "{value}");
                }
            }
            buf.extend_from_slice(b"\"");
        });
        buf.extend_from_slice(b"}");
        // `JsonEscapingWriter` only writes valid UTF-8 (input is
        // UTF-8, escapes are ASCII), so from_utf8 cannot fail
        // here. The unwrap is in test code only; production
        // sinks write bytes directly without round-tripping
        // through String.
        #[expect(
            clippy::expect_used,
            reason = "test-only render helper; JsonEscapingWriter produces valid UTF-8 by construction (UTF-8 input + ASCII-only escapes), so from_utf8 cannot fail"
        )]
        String::from_utf8(buf).expect(
            "JsonEscapingWriter only writes valid UTF-8 (input is UTF-8, escapes are ASCII)",
        )
    }

    #[test]
    fn stderr_sink_canonical_wire_form() {
        let event = SampleEvent {
            device: "OMNIKEY",
            secret: "1234",
        };
        let rendered = render_to_buffer(&event);
        let want = r#"{"event": "test.sample", "severity": "notice", "device": "OMNIKEY", "secret": "<redacted>"}"#;
        assert_eq!(rendered, want);
    }

    #[test]
    fn stderr_sink_escapes_special_characters_in_values() {
        let event = SampleEvent {
            device: "a\"b\\c\nd",
            secret: "1234",
        };
        let rendered = render_to_buffer(&event);
        let want = r#"{"event": "test.sample", "severity": "notice", "device": "a\"b\\c\nd", "secret": "<redacted>"}"#;
        assert_eq!(rendered, want);
    }

    #[test]
    fn stderr_sink_redacts_private_fields() {
        // A Private field's value must never reach the rendered
        // line -- this is the "redacted at the source" guarantee.
        let event = SampleEvent {
            device: "OMNIKEY",
            secret: "8471",
        };
        let rendered = render_to_buffer(&event);
        assert!(
            !rendered.contains("8471"),
            "PRIVATE field value leaked into output: {rendered}"
        );
        assert!(
            rendered.contains(r#""secret": "<redacted>""#),
            "got: {rendered}"
        );
    }
}
