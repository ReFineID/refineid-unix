# Revocation cache & evidence -- design decision

How refineid holds a certificate's revocation status once it has been
checked. Companion to [`der-trust-boundary.md`](der-trust-boundary.md)
(the `VerifiedOcspResponse` / `VerifiedCrl` lattices that produce the
verdict) and the trust-by-construction model in
[`../typing-discipline.md`](../typing-discipline.md).

## The decisions

1. **In-memory only. Never on disk** -- this is *mandated*, not
   merely preferred. [`doc/observability.md`](../observability.md)
   section "A successful Suomi.fi login leaves no persistent trace" is a
   standing architectural commitment: a successful login creates **no
   disk artifact** ("the privacy bomb is not created"), and its event
   table lists `card.cert.revocation.ocsp.checked` itself as
   `ephemeral`. An on-disk revocation cache would *manufacture the
   exact persistent trace that commitment forbids* -- a record of
   which cards/serials this machine checked and when. (It is also a
   **poisoning surface**: anything that can write the file can inject
   a `good` entry for a revoked cert and bypass revocation.)
   In-memory dies with the process: no trace, nothing to tamper with
   at rest. The cross-session "don't re-fetch" benefit is marginal
   for an occasionally-run tool, and a CRL fetch leaks nothing about
   *which* card anyway. The only sanctioned exception, on proven need
   (Rule E21): persist the **raw signed CRL** and **re-verify its
   signature on load** (a poisoned file fails the `VerifiedCrl`
   check) -- never a parsed verdict. Default: in-memory.

2. **Public data -> not the PIN vault.** OCSP/CRL artifacts are
   public; there is nothing to protect. They must NOT live in the
   secret PIN vault (whose discipline -- zeroize, never-persist -- is
   wasted on public data, and whose persistence would be wrong for a
   secret). Secret -> the vault; public-and-validity-windowed -> a
   plain in-memory store. They share a session, not storage.

3. **`Option<RevocationEvidence>` on the card data object, never
   auto-filled.** The slot starts `None` on parse/open and is set to
   `Some` *only* by an explicit, user-initiated validation. There is
   no code path from "card inserted" to a populated field, so the
   per-use privacy beacon is **impossible by construction**, not by
   policy. `None` means *"not checked"* -- a first-class state,
   distinct from `Good`. The data model never conflates "didn't ask"
   with "fine."

4. **Evidence is verified and dated.** [`RevocationEvidence`] is
   constructed only from a [`VerifiedOcspResponse`] / [`VerifiedCrl`]
   (so the verdict is signature-checked, never a forgeable read), and
   carries `checked_at` plus `valid_until` (the OCSP/CRL
   `nextUpdate`). A consumer can tell `Some(fresh)` from
   `Some(stale)` from `None`.

5. **Asymmetric freshness.** `Revoked` is **sticky** -- a cert never
   un-revokes, so a cached `Revoked` is served regardless of age.
   `Good` (and every non-revoked verdict) is served **only inside its
   validity window** (`now <= valid_until`); past it, the cache
   misses and the caller must re-check. The asymmetry lives in the
   cache's lookup, not the evidence.

## Acting vs. knowing

The cache/field answers *"what do we currently know?"*. It never
*grants* trust by itself: a consumer that wants to act on
"non-revoked" reads the field, and checks it is `Some`, **fresh**,
and (by construction) **verified**. The trust *decision* still climbs
the cert-state typestate (`... -> RevocationCheckedCert ->
PurposeBoundCert`). The cache is evidence; the decision is a
deliberate step.

## Status

The evidence + in-memory cache types live in
[`crates/refineid-lib-core/src/revocation.rs`](../../crates/refineid-lib-core/src/revocation.rs).
The `Option<RevocationEvidence>` field on the card data object and the
session-scoped wiring land with the secure-session service (still
scaffolding); the types and their in-memory, verified-only,
asymmetric-freshness semantics are implemented and tested now.

[`RevocationEvidence`]: ../../crates/refineid-lib-core/src/revocation.rs
[`VerifiedOcspResponse`]: ../../crates/refineid-lib-core/src/ocsp.rs
[`VerifiedCrl`]: ../../crates/refineid-lib-core/src/crl.rs
