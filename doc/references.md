# Annotated references

Companion to [`references.bib`](references.bib). The `.bib` file is the
machine-parseable citation list; this file explains what each entry is
cited *for*, and what it does **not** prove.

Two kinds of source appear here, and they carry very different weight:

- **Normative specifications** decide behaviour. When the code and a
  specification disagree, the code is wrong. `AGENTS.md` puts it as
  "verify from specifications, don't wild guess" — this file is the
  index that makes that possible.
- **Engineering literature** informs design. It never decides anything
  on its own, and citing it is not an argument from authority.

## How to use this file

Cite by BibTeX key, e.g. `[cockburn2005hexagonal](doc/references.md#cockburn2005hexagonal)`.
Grep `references.bib` for `@cockburn2005hexagonal` to recover the
bibliographic data, and this file for the same anchor to recover the
interpretation attached to it. A `###` heading in this file is always a
BibTeX key; `####` headings are only grouping, so the anchors stay
machine-checkable.

## Citation hygiene rules

1. **Every citation answers three questions:** what it supports, what
   it does NOT prove, and what its `source_quality` tag means.
2. **`source_quality` is honest, not aspirational.** A blog post is
   `industry-published`, not `peer-reviewed`. A pattern noticed across
   several products is `observation`, not science.
3. **Stale-citation guard.** If `last_verified` is more than twelve
   months old, re-check the URL and the claim before reusing the entry.
4. **Counter-evidence is required for non-trivial decisions.** Four
   entries that all agree and none that challenge means the
   bibliography is reflecting an echo chamber rather than the
   literature. Say so explicitly when that is the actual state — see
   [§ evidence we do not have](#evidence-we-do-not-have).
5. **Normative beats persuasive.** Never cite a paper for a claim a
   specification settles. If both are cited, the specification governs
   and the paper is context.

## Normative specifications

These are the sources the implementation must obey. Counts are how
often each is cited across this tree, as a rough guide to how
load-bearing it is.

#### The card itself

- **FINEID S1** (`fineid_specifications`, 84 citations) — the electronic ID application:
  file structure, PINs, signing commands. The single most load-bearing
  document in this repository.
- **FINEID S4-1** (50) and **S4-2** (18) — current card model profiles.
  Where card behaviour differs between models, these are why.
- **FINEID S2** (13) — certificate profile. See also
  [`fineid-s2-cert-profile.md`](fineid-s2-cert-profile.md).
- **ISO/IEC 7816-4** (`iso7816_4`) — APDU structure, file selection, security
  architecture. FINEID is a profile on top of it; when S1 is silent,
  7816-4 is the fallback, not invention.
- **ISO/IEC 7816-15** (`iso7816_15`) — cryptographic information application (the
  PKCS#15 structures the card publishes).

Published by DVV at <https://dvv.fi/en/fineid-specifications>.

#### Contactless and travel-document mechanisms

- **BSI TR-03110** (`bsi_tr03110`, 62) — PACE, and the secure messaging that follows
  it. The contactless interface seals PKCS#15 behind PACE; this is the
  specification that says how the seal opens.
- **ICAO Doc 9303** (`icao9303`, 51) — machine-readable travel documents. Part 11
  carries the security mechanisms; the eMRTD support follows it.

#### Vendor card behavior

### thales_multiapp_v5_security_target

- **Supports:** the MultiApp v5.0.A FIA_AFL.1/PACE rule. One failed
  MRZ/CAN authentication exponentially increases the delay before a
  new attempt; the CAN refinement defines a presentation-count
  parameter in the range 0 to 255 and an increasing wait before the
  card sends its PACE response.
- **Does NOT prove:** the numeric delay schedule, counter persistence,
  recovery rule, or that every interrupted exchange increments it. A
  slow exchange still needs a command-level trace before it is assigned
  to this defense.
- **Source quality:** industry-published vendor security target,
  evaluated under Common Criteria. It describes product behavior but
  leaves recovery parameters undisclosed.

#### Certificates, revocation, signatures

- **RFC 5280** (`rfc5280`, 106) — X.509 certificate and CRL profile. The most
  cited RFC in the tree by a wide margin.
- **RFC 6960** (`rfc6960`, 36) and **RFC 8954** (14) — OCSP and its nonce
  extension. See [`security/revocation-cache.md`](security/revocation-cache.md).
- **RFC 5652** (`rfc5652`, 14) — Cryptographic Message Syntax, the envelope under
  CAdES.
- **RFC 3161** (`rfc3161`, 13) — Time-Stamp Protocol. What a qualified timestamp
  is, and why signing at LT or LTA has to contact a timestamp
  authority.
- **RFC 3739** — qualified certificate profile. **RFC 8017** — PKCS#1.
  **RFC 5480**, **RFC 5639**, **RFC 6979** — ECC key material, curves
  and deterministic ECDSA. **ISO/IEC 9796-2** and **ISO/IEC 10118-3** —
  signature schemes and hash functions as the card names them.

#### Signature formats and the legal frame

- **ETSI EN 319 122** (`etsi_aades`) (CAdES), **EN 319 142** (PAdES), **EN 319 132**
  (XAdES), **EN 319 162** (ASiC containers), **EN 319 412**
  (certificate profiles). These define the baseline / LT / LTA levels
  the signer produces; the level names are theirs, not ours.
- **Regulation (EU) No 910/2014 (eIDAS)** (`eidas910_2014`) — what "qualified" means in
  law. Cite it for the definition, never as proof that a given
  implementation achieves it.

#### Interfaces

- **PKCS#11 v2.40** (`pkcs11_v240`, 8) — the module implements v2.40 semantics.
  OASIS publishes v3.0 and v3.2 as well; where a consumer asks for a
  later interface, the version field of the 2.40 list stays 2.40
  because the specification fixes it.

## Engineering literature

### parnas1972decomposing

- **Supports:** modules are defined by the decisions they hide, not by
  steps in a process. The reason the core owns protocol knowledge and
  knows nothing about PC/SC, TLS or a GUI.
- **Does NOT prove:** any specific number of layers, or that this
  particular boundary is right. The paper is a criterion, not a recipe.
- **Source quality:** peer-reviewed (CACM 1972).

### cockburn2005hexagonal

- **Supports:** ports and adapters. `refineid-lib-core` is the inner
  ring with no I/O; `refineid-lib-pcsc` and `refineid-lib-tls` are
  adapters implementing its ports. Reader quirks live in the adapter,
  never in the core.
- **Does NOT prove:** that hexagonal is optimal for every card-bound
  abstraction. It fits this case; it is not a universal mandate.
- **Source quality:** industry-published (online article).

### metz2016wrong

- **Supports:** "duplication is far cheaper than the wrong
  abstraction." Justifies waiting for a second real consumer before
  hardening a boundary.
- **Does NOT prove:** that all early abstraction is wrong. It is a
  bias-correction, not a blanket rule.
- **Source quality:** industry-published (blog post).

### fowler1999refactoring

- **Supports:** the Rule of Three — wait for the third occurrence
  before factoring out a shared abstraction.
- **Does NOT prove:** that three is a measured threshold. For crypto
  primitives and security helpers the right number is one.
- **Source quality:** industry-published (textbook). The rule
  originates with Don Roberts; Fowler popularised it.

### nygard2011adr

- **Supports:** the Architecture-Decision-Record pattern — recording
  the decision, the principle behind it, and the alternative that was
  considered and rejected.
- **Does NOT prove:** any particular granularity. One decision per
  file is the original pattern; collapsing them into a single document
  is a readability trade-off.
- **Source quality:** industry-published (blog post), seminal for ADRs.

### norman1988design

- **Supports:** affordances and signifiers — visible cues for what can
  be done. In the GUI that means the card's state being legible before
  a PIN is asked for, rather than after it fails.
- **Does NOT prove:** the form those cues should take. Norman writes
  about doors and stovetops; screens are derivative.
- **Source quality:** industry-published (textbook, foundational HCI).

### nielsen1994heuristics

- **Supports:** visibility of system status, recognition over recall,
  user control, error prevention — the four most relevant to an
  application where the expensive mistake (a spent PIN retry, a wrong
  key) is not undoable.
- **Does NOT prove:** any ranking among the ten. It is a list, not a
  measured priority order.
- **Source quality:** industry-published (NN/g), derived from
  peer-reviewed work by Nielsen and Molich (1990).

### miller1956magical

- **Supports:** the working-memory chunk limit, used as a *soft* cap
  on how many choices are put in front of someone at once.
- **Does NOT prove:** that seven is a screen-design cap. The paper is
  about chunking in cognitive tasks and is widely over-applied; it is
  cited here for the upper bound it suggests, nothing more.
- **Source quality:** peer-reviewed (Psychological Review 1956).

### bainbridge1983ironies

- **Supports:** automation that changes behaviour without saying so
  leaves the operator confidently wrong. The reason document signing
  **fails** when a timestamp authority is unreachable rather than
  quietly producing a weaker signature: a baseline signature and an
  LTA signature look identical to the person who just watched the file
  appear.
- **Does NOT prove:** that failing is always right. Where a fallback is
  visible and reversible, degrading can be kinder than refusing.
- **Source quality:** peer-reviewed (Automatica 1983).

## Evidence we do not have

Listing what cannot be cited is part of avoiding echo-chamber
reasoning. Add to this section whenever a decision is made on judgement
rather than evidence.

### On failing rather than degrading a signature level

- **No controlled study** shows that users of signing software
  understand signature levels well enough for a silent downgrade to be
  safe. The argument rests on the analogy to protocol downgrade attacks
  (where silent acceptance of a weaker mode is the vulnerability) and
  on the automation-surprise literature, not on measurement of this
  population.
- The honest framing is "reasoning by analogy from adjacent fields,"
  not "the literature shows".

### On the architecture

- **No trial** compares this layering against alternatives for a
  smartcard middleware of this size. The citations above justify the
  *shape* of the reasoning, not the conclusion. The concrete evidence
  is that the core stays testable without hardware and that adapters
  have been swapped without touching it.
