# Excellent-by-default: mechanical rules

ReFineID is engineered to be auditable by any serious security
reviewer. This is the condensed public rule set the code comments
cite; each rule keeps its stable ID.

### Rule E1 -- PIN bytes use `zeroize::Zeroizing`

Every type that holds PIN, PUK, activation-PIN, or CAN material
wraps the byte storage in `zeroize::Zeroizing` or implements `Drop`
with explicit zeroization. The type does not derive `Debug`,
`Clone`, `Copy`, `Serialize`, `Deserialize`, or `PartialEq`.
PIN-bearing types never appear in `format!` strings, structured
events, error messages, or panic messages. PIN bytes must not
survive past the operation that needs them.

### Rule E6 -- No PII / secret material in observability

Structured event values may not contain PIN bytes, PUK bytes,
private-key material, or unredacted CAN values in production
builds. PIN-bearing APDU data is redacted at the event source;
sink-side privacy labels are not an acceptable substitute.

### Rule E7 -- Verify-after-sign

Every signing operation has a paired local verify against the
on-card cert's public key. A sign-then-fail-to-verify outcome is
reported to the caller as a failure and the signature is not
delivered. A compromised card, firmware bug, or wire-level
tampering can produce a signature that does not verify; the local
verify catches that class before the signature reaches any
external system.

### Rule E16 -- Event severity is a compile-time API

Every event carries one of the eight RFC 5424 severity levels,
hardcoded in the event type's `EventRecord` impl and treated as a
stable public contract -- downstream severity filters must not
break silently between releases. Levels and frequency expectations:
[`doc/observability.md`](../observability.md).

### Rule E17 -- No call home in the personal profile

Every outbound network call corresponds to a user-initiated task in
the current session. No telemetry, analytics, usage statistics, or
crash reports without per-incident consent.

### Rule E18 -- Persistence requires per-event justification

Events are ephemeral by default; routine successful operations
leave no disk artifact. OS-managed or forensic persistence requires
a documented per-event rationale
([`doc/observability.md`](../observability.md) persistence tiers).

### Rule E19 -- Network operations are by explicit instruction

Every network call is a named user operation in the current
session. Local-by-default.

### Rule E22 -- Lint suppressions use `#[expect]`; dead ones get deleted

Every lint suppression uses `#[expect(LINT, reason = "...")]`.
`#[allow]` is reserved for the narrow case where the lint provably
cannot fire at the annotated scope and `#[expect]` would always be
unfulfilled. When `unfulfilled_lint_expectations` warns, the
suppression is deleted -- not broadened to `#[allow]`. `#[expect]`
flips suppression decay: the compiler points at carve-outs that are
no longer load-bearing.
