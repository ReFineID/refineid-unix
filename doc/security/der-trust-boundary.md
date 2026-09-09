# DER trust-boundary map

Design map for extending **trust by construction** (see
[`doc/typing-discipline.md`](../typing-discipline.md) "Trust by
construction") from the certificate path -- where it is already done
right -- to the rest of the trust-bearing DER the product handles.

DER is not "just bytes": it is rigidly structured, self-describing,
canonical TLV (ASN.1). A `der: &[u8]` discards three checkable facts
the bytes carry -- *well-formed DER*, *what it encodes* (a cert, an
OCSP response, a CRL, a key -- not interchangeable), and
*provenance*. The job of this map is to find the front doors where
untrusted DER enters, where that trust currently leaks into the
interior un-typed, and the minimal set of unforgeable validated-DER
types that closes the gap.

This is read-only design. No code changes here; it is the blueprint
to design before pouring.

## The exemplar: the certificate lattice (already correct)

`crates/refineid-lib-core/src/cert_state.rs` is the template. A
6-stage typestate lattice, each stage a type whose constructor
validates one more guarantee, the type system forbidding any skip:

```
CertDer (owned, card-read)        provenance only, honestly unvalidated
  -> RawDer<'a>                   borrowed view
  -> ParsedCert<'a>               X.509 syntax validated
  -> PathValidatedCert<'a>        chain validated
  -> RevocationCheckedCert<'a>    revocation checked
  -> PurposeBoundCert<'a, P>      bound to Auth / NonRep / CSCA / DSC / MLS
```

A `PurposeBoundCert<AuthPurpose>` is unforgeable proof that every
prior check passed. `CertDer`'s "no syntactic check" is *honest*:
it does not claim validity, it exists as the **owned backing store**
that the borrowed `ParsedCert<'a>` views (Rust lifetimes: something
must own the bytes the parsed view borrows), and the type system
**forbids** using a `CertDer` where a validated cert is required.
Validation happens at first parse (`RawDer::parse`), exactly as it
should; the unvalidated entry stage cannot masquerade as trusted.

**This is the pattern to replicate.** Owned provenance wrapper at
the door -> `.parse()` is the single validating boundary ->
borrowed validated view -> further stages for further guarantees.

## Front doors (where untrusted DER enters)

| Source | Entry point | Hands back | Notes |
|---|---|---|---|
| Card cert slot | `pkcs15::read_certificate` | `CertDer` ✅ | already typed-at-ingress |
| Card EF.TokenInfo | `TokenInfo::parse(der: &[u8])` | `Result<TokenInfo, BerError>` ✅ | validating ctor; malformed distinct from absent |
| Card EF.CardAccess | `CardAccess::parse(der: &[u8])` | `Result<CardAccess, CardAccessError>` ✅ | validating ctor; described malformation |
| Network (OCSP) | `client::http::get -> Vec<u8>` then `ocsp::parse_response(der: &[u8])` | `OcspResponse<'_>` | raw `Vec<u8>` threaded to parser |
| Network (CRL) | `client::http::get -> Vec<u8>` then `crl::parse_crl(der: &[u8])` | `Crl<'_>` | raw `Vec<u8>` threaded |
| eMRTD SOD | `cms::parse_lds_security_object(der: &[u8])` | `LdsSecurityObject<'_>` | raw `&[u8]` |
| Login chain | `CertDer::new(der.to_vec())` (suomi_login, fineid) | `CertDer` ✅ | typed |

The literal front door legitimately takes `&[u8]` / `Vec<u8>` -- at
that instant the bytes are an *unvalidated claim* off the wire/card.
The rule is: wrap-and-parse immediately; never thread the raw bytes
deeper than the first parse.

## Where trust leaks today

- **OCSP / CRL have no owned-provenance wrapper and no lattice.**
  `parse_response(&[u8])` / `parse_crl(&[u8])` are free functions
  returning borrowed views straight off raw bytes. The fact "these
  bytes are an OCSP response, signature-verified" is never captured
  in a type -- so an OCSP response and a cert are both reachable as
  `&[u8]`, mix-ups are not a compile error, and provenance is lost.
  Both *do* have a verification step (`verify_crl_signature`,
  OCSP response signature) that is applied ad-hoc rather than being
  the constructor of a `Verified*` type.
- **`Vec<u8>` threaded from `http::get` to the parser.** The OCSP/CRL
  bytes travel as anonymous `Vec<u8>` between fetch and parse instead
  of a `OcspResponseDer` / `CrlDer` the moment they are fetched.
- **Redundant raw+parsed passing.** e.g.
  `icao_pkd::from_cert(der: &[u8], cert: &Certificate<'_>)` takes
  both the bytes and the parsed view -- the parsed view already
  borrows the bytes; passing both invites them to disagree.
- ~~**`parse_token_info` / `parse_card_access` return `Option`,** so a
  parse failure is indistinguishable from "absent" -- a weaker
  boundary than the `Result` the cert/OCSP/CRL parsers use.~~
  **(closed)** -- both are now *validating constructors on the
  validated type itself*: `TokenInfo::parse(&[u8]) ->
  Result<TokenInfo, BerError>` (hard-fails only on a malformed outer
  SEQUENCE; sub-objects stay best-effort) and `CardAccess::parse(&[u8])
  -> Result<CardAccess, CardAccessError>` (a described
  `NotSetOrSequence` / `TrailingBytes` rather than a bare `None`).
  Construction *is* validation -- no intermediate `*Der` wrapper,
  because (unlike `CertDer`) nothing borrows the bytes after the
  parse, so there is no unvalidated-but-named value to misuse. The
  raw `&[u8]` is the single door, on the type, as the sanctioned
  validation-boundary carve-out.

## Minimal validated-DER type set to add

Replicate the cert-lattice shape, no deeper than each datum's real
guarantees:

1. **`OcspResponseDer` (owned) + `VerifiedOcspResponse<'a>`.**
   `OcspResponseDer` is the owned-provenance wrapper produced the
   instant the HTTP body returns. Its `.parse()` is the single
   validating door to `OcspResponse<'a>` (syntax); a further
   `.verify(signer)` is the *only* constructor of
   `VerifiedOcspResponse` (signature checked). Revocation decisions
   take `VerifiedOcspResponse`, never `&[u8]`.
2. **`CrlDer` (owned) + `VerifiedCrl<'a>`.** Same shape; the CRL
   signature check becomes the constructor of `VerifiedCrl`.
3. **eMRTD SOD: `VerifiedSignedData<'a>`** (done) -- the CMS
   `SignedData` whose signer (DSC) signature verified. Its
   `lds_security_object()` is the only door to the DG-hash table, so a
   passive-auth DG-hash comparison can't be computed from an
   unverified, attacker-controlled SOD. (Verifying against the
   *embedded* DSC is necessary-but-not-sufficient; the DSC->CSCA chain
   is the separate cert-state-lattice step. Unlike OCSP/CRL the
   consumers are diagnostic displays, not a consumed verdict, so the
   win is display honesty -- an unverified SOD shows "not checked"
   rather than a meaningless "DG hash: ok".)
4. Promote `parse_token_info` / `parse_card_access` from `Option`
   to `Result` so "malformed" is distinct from "absent" --
   closing the weak boundary. **(done)** Each parser returns the
   narrowest honest error: `BerError` for token-info (its only hard
   failure is the outer SEQUENCE), a dedicated two-variant
   `CardAccessError` for card-access (it has a second failure mode --
   trailing bytes past the outer TLV -- that `BerError` doesn't
   model). No generic `Pkcs15Error<E>` leaked into a pure parser.

`SpkiDer<'a>` already exists and is the model for the borrowed
validated view; `CertDer` / `RawDer` are the model for the owned
wrapper + borrowed view split.

## Sequencing (deliberate, test-backed, core-first)

1. OCSP first (highest stakes: a forged/return-stale OCSP response
   is an authentication-relevant lie), backed by the existing OCSP
   KATs. **(done -- `VerifiedOcspResponse`)**
2. CRL next, same shape, backed by the CRL KATs. **(done --
   `VerifiedCrl`)**
3. SOD next. **(done -- `VerifiedSignedData`)** No isolated KATs: the
   CMS module had no unit-test fixtures and a full signed-SOD fixture
   is disproportionate, so the gate is type-enforced
   (`lds_security_object` unreachable without `verify`).
4. token-info / card-access (lower stakes): promote
   `parse_token_info` / `parse_card_access` from `Option` to `Result`
   so "malformed" is distinct from "absent". **(done)** A boundary
   tightening, not a verified-signature lattice -- these carry no
   signature to check; the win is that a card-side malformation no
   longer reads as a benign "field absent".

Each step: introduce the owned wrapper at the fetch/read site, make
`.parse()`/`.verify()` the only validating doors, then **delete the
downstream `&[u8]` threading** -- the payoff is the interior getting
*simpler* as it stops handling raw bytes. The typing-grep debt for
these sites falls out as a side effect of the core getting more
certain, not as the goal. Do not touch the ECDSA verify-path
byte-crunchers (Rule E21: genuine local byte math, raw is correct).

## Why not validate at the very first construction?

Because the validated views borrow their bytes (`ParsedCert<'a>`,
`OcspResponse<'a>`), something must *own* the bytes for the view to
borrow. So the owned wrapper (`CertDer` / `OcspResponseDer`) holds
them and `.parse()` is one cheap call away -- and the type system
forbids using the unparsed owned wrapper where a validated value is
required. Validation still happens at first parse; the owned stage
is the lifetime anchor, not a trust gap.
