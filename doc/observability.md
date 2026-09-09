# Observability

The condensed contract the code comments cite: how ReFineID emits
events, what severity means, and what may persist.

Events are OBSERVATIONS about operations, delivered through
`refineid_lib_core::events`. They are not primary output: the CLI's
answer to the user goes to stdout/stderr as ordinary prints, in the
client crate only; library crates never print.

## Privacy posture

- **No call home.** Every outbound network call corresponds to a
  user-initiated task in the current session. No telemetry,
  analytics, usage statistics, or crash reports without per-incident
  consent.
- **Persistence requires per-event justification.** Events are
  ephemeral by default; routine successful operations leave no disk
  artifact.
- **No PII or secret material in events.** PIN bytes, keys, and
  personal identifiers never enter an event field at any severity.

A successful card login leaves no persistent trace: stderr shows the
citizen what happened while it happened; nothing durable is written,
because successful authentication is not a forensic-grade act for
the citizen.

## Format

JSON Lines, flat fields, RFC 8259-strict. Event names are
dot-separated namespaces from broad to specific
(`card.activate.preflight.refused`, `card.cert.chain.verified`),
terminating in a verb-past-participle for completed actions or a
noun for snapshots.

## Severity

Eight levels, numeric priority per RFC 5424 (higher number = lower
severity):

| `n` | Severity | When to use |
|-----|----------|-------------|
| 0 | `emerg` | Trust assumptions violated (pinned trust-root mismatch, audit tamper). |
| 1 | `alert` | Active intervention required (secret-material zeroize failed). |
| 2 | `crit` | Component failure: the tool cannot do its job (PC/SC gone). |
| 3 | `err` | Operation failed as the caller will see it; recorded for forensics. |
| 4 | `warning` | Succeeded but suspect, or rejected recoverably. |
| 5 | `notice` | Normal but security-relevant (session lifecycle, chain verified). |
| 6 | `info` | Routine flow detail. |
| 7 | `debug` | Diagnostic detail (APDU hex). Off by default at every sink. |

Severity is part of an event's compile-time API, not a runtime
argument.

## Persistence tiers

Each event type declares exactly one tier, hardcoded per type:

| Tier | Where | Retention |
|------|-------|-----------|
| `ephemeral` | stderr only | Until the process exits. The default. |
| `os_managed` | Platform log (`journald` / `os_log` / `eventlog`) | Platform default. For failures the citizen may want to diagnose later. |
| `forensic` | Audit chain | Citizen-controlled. Only for the citizen's own deliberate acts (signing, PIN change, activation) where durable proof matters. |
