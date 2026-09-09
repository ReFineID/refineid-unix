# FINEID card models

The set of FINEID card models refineid recognises, the
engineering identifiers used for them, and why some models
are explicitly out of scope.

This is the canonical taxonomy. Code that classifies cards by
ATR/ATS, names a card model in an event payload, or branches
on FINEID spec version should reference this doc rather than
duplicating the table.

## Source of truth

DVV publishes the authoritative ATR/ATS table for every
certificate card it has ever issued:

- [DVV ATR/ATS technology note (v1.0, 2024-08-12)][dvv-atr]
  -- "Technology note - DVV certificate card ATR/ATS bytes",
  ICT Unit / Pirinen Jari.

[dvv-atr]: https://dvv.fi/documents/16079645/17324992/Technology+note+-+ATR+bytes.pdf

Every fact in the tables below comes from that note. If DVV
revises the note (model added, ATR corrected), update this
doc, the type lattice in
[`doc/typing-discipline.md`](typing-discipline.md), and the
classifier in `refineid-lib-core` in the same change.

## Scope: in-production citizen eID cards only

refineid's `card activate` and related flows target **citizen
eID cards still in the field**. As of 2026-05-24 that is two
models:

| Card type   | Vendor  | Vendor product | Vendor product version | FINEID specification | FINEID specification version | Production window     | Newest card expires |
|-------------|---------|----------------|------------------------|----------------------|------------------------------|-----------------------|---------------------|
| Citizen eID | Thales  | MultiApp       | 5.0                    | S4-1                 | 4.0                          | 2023-03-13 ->         | 2028-03-12 +        |
| Citizen eID | Gemalto | MultiApp       | 4.2                    | S4-1                 | 3.1                          | 2021-01-11 - 2023-03-12 | 2028-03-12        |

Citizen FINEID cards have a 5-year validity. Any card model
whose latest production date plus 5 years falls before today
(2026-05-24) has no valid representative in the field; refineid
refuses to engineer for it.

### Wire identifiers (engineering canonical)

In the JSON Lines event stream every event that names a card
model emits six literal-string fields, all verbatim from DVV's
publications:

```json
"card_type": "Citizen eID",
"card_vendor": "Thales",
"card_vendor_product": "MultiApp",
"card_vendor_product_version": "5.0",
"fineid_specification": "S4-1",
"fineid_specification_version": "4.0"
```

The values are DVV-published strings, decomposed by their
own structural seams. They are not lowercased, not
snake-cased, not normalised. (The
[observability spec](observability.md) requires
`lower_snake_case` for **field keys**; values are
unconstrained JSON strings.) Decomposing by structural seam
gives SOC operators independent axes to filter on:

- `card_type` -- DVV category. Triage by this first.
- `card_vendor` -- "Thales" or "Gemalto". The vendor
  rebrand (Gemalto -> Thales after the 2019 acquisition)
  changes this value across an otherwise-continuous product
  line; filter on either to follow the lineage.
- `card_vendor_product` -- product family name, e.g.
  "MultiApp". Stable across vendor renames in the cases
  DVV ships.
- `card_vendor_product_version` -- bare version number
  (`5.0`, `4.2`). No leading `v` -- the field name already
  announces that this is a version.
- `fineid_specification` -- DVV's canonical FINEID document
  identifier (`S4-1`, `S1`, `S2`, `S5`). See "FINEID
  specification numbering" below for what each code names.
- `fineid_specification_version` -- bare version number of
  that document (`4.0`, `3.1`).

Allowed `card_type` values (the literals DVV uses, minus the
trailing "card"/"cards" plural):

- `"Citizen eID"` -- the in-scope category.
- `"Social welfare and organizational"` -- out of scope for
  now; deferred (see below).
- `"Health care and organizational"` -- out of scope; legacy.

### FINEID specification numbering

DVV maintains a numbered series of FINEID specification
documents. The codes that appear in the
`fineid_specification` field come from DVV's
[FINEID specifications index][fineid-specs].

[fineid-specs]: https://dvv.fi/en/fineid-specifications

| Code     | Document name                                        | What it specifies                                                  |
|----------|------------------------------------------------------|--------------------------------------------------------------------|
| `S1`     | Electronic ID Application                            | Base eID application layer; social welfare / organizational cards. |
| `S2`     | CA-model and certificate contents                    | DVV CA structure and cert profile.                                  |
| `S4-1`   | Implementation profile for Finnish Electronic ID Card | Citizen eID card implementation profile (the in-scope spec).        |
| `S4-2`   | Implementation Profile for Organizational Usage      | Organizational usage profile.                                       |
| `S5`     | Directory Specification                              | Directory structure on the card.                                   |

`S4-1` is the in-scope specification for refineid's `card
activate` flow: the implementation profile a Finnish citizen
eID card follows.

The codes are DVV's canonical identifiers and are used
verbatim in their own materials -- the dashed form (`S4-1`)
is not decomposed further on the wire. If a future need
arises to compare across the `S4` series (`S4-1` vs `S4-2`),
add a `fineid_specification_family: "S4"` field at that
point; do not anticipate it.

### ATR / ATS bytes

Multiple ATR variants per FINEID specification + vendor
product + version are legitimate: same product line ships
with revised historical bytes across manufacturing batches.
The distinguishing data is the chip-revision label printed
under the chip on the physical card (`v 1.0.0`, `v 2.0.0`,
...). The classifier accepts every recorded variant.

#### FINEID S4-1 v4.0 (Thales MultiApp v5.0)

| Chip rev | Contact interface (ATR)                                                    | Contactless interface (ATS) |
|----------|----------------------------------------------------------------------------|------------------------------|
| `v 1.0.0` | `3B 7F 96 00 00 80 31 B8 65 B0 85 05 00 11 12 24 60 82 90 00`              | `14 78 77 95 02 80 31 B8 65 B0 85 05 00 11 12 24 60 82 90 00` |
| `v 2.0.0` | `3B 7F 96 00 00 80 31 B8 65 B0 85 05 10 24 12 24 60 82 90 00`              | (not yet field-observed)     |

Bytes 0..=11 are the family marker (the `0x05` at position
11 is DVV's v5.0 indicator). Bytes 12..=13 vary per
manufacturing batch.

The v4.0 profile is the ECC variant: its authentication and qualified
signature certificates use `secp384r1` (P-384). The qualified certificate
is EF.4332 with `nonRepudiation`; it is independently usable with PIN2 even
when the EF.4331 authentication key's PIN1 is locked. Windows registration
uses the stable first 12 ATR bytes and masks manufacturing-specific bytes
12..=16, then dispatches to the same ReFineID minidriver. The minidriver
reports an ECDSA P-384 signature container and drives PIN2 separately for
each qualified signature; it never attempts to verify PIN1 on that path.

#### FINEID S4-1 v3.1 (Gemalto MultiApp v4.2)

| Chip rev | Contact interface (ATR)                                                    | Contactless interface (ATS)                                                |
|----------|----------------------------------------------------------------------------|----------------------------------------------------------------------------|
| (DVV technote v1.0) | `3B 7F 96 00 00 80 31 B8 65 B0 85 04 02 1B 12 00 F6 82 90 00`     | `14 78 77 95 02 80 31 B8 65 B0 85 04 02 1B 12 00 F6 82 90 00`              |

ATR matching is a classification signal, **not** a trust
signal. The trust gate remains the pinned-root SHA-256 check
(see `crates/refineid-client/src/card_pin.rs` and
[`doc/typing-discipline.md`](typing-discipline.md)). A
forged card could in principle reproduce an ATR; only the
pinned root anchors trust.

That said, ATR matching is a useful weak counterfeit-card
detector: a card whose ATR doesn't match any in-scope model
gets rejected before any further reads, regardless of trust
gate state.

## Out of scope, but recorded for context

The remaining models in the DVV ATR/ATS note exist, but
refineid does not classify or activate them.

### Citizen eID, expired

| Card type   | Card vendor and product | FINEID specification | Production window         | Reason out of scope                              |
|-------------|-------------------------|----------------------|---------------------------|--------------------------------------------------|
| Citizen eID | Gemalto MultiApp v3.0   | S4-1 v3.0            | 2017-01-01 - 2021-01-10   | Newest card expired 2026-01-10 (before today)    |
| Citizen eID | Setec SetCOS 5.1.X      | (legacy)             | legacy product            | Predates current FINEID profile, all expired     |

ATR / ATS for these models is in the DVV note above; not
reproduced here because refineid won't act on them.

If a card with one of these ATRs appears at a reader,
refineid returns `UnknownOrUnsupportedModel { atr }` and
refuses to proceed. (The expired auth cert would fail path
validation anyway; ATR rejection is the earlier and clearer
signal.)

### Social welfare / organizational cards

These are a different card category from citizen eID: the card
application follows the FINEID `S1` specification line and the
electrical profile follows `S4-2` ("Implementation Profile 2 for
Organizational Usage"). The Cosmo X generation is supported for
`card` readout and signing: the certificate slot table already
covers its layout (auth `3F00/4331`, signature `3F00/5016/4332`,
root `3F00/4334`; the issuing CA EFs are not readable on the
card), and the credential references resolve at runtime via
`PinOps::resolve_pin_reference_scheme` -- S4-2 v4.0 numbers its
credentials by security-data-object identifier (PIN AUTH `03`,
PIN SIG `04`, PIN PUK `12`, per section 4.2) where the citizen
line uses S1 v4.2 section 3.5.2 references (`11`/`82`/`83`).
PIN management (`card pin`) still gates on ATR model
classification, which does not yet name the Cosmo X.

| Card type                              | Card vendor and product            | FINEID specification | Production window         | Status                            |
|----------------------------------------|------------------------------------|----------------------|---------------------------|-----------------------------------|
| Social welfare and organizational      | Idemia Cosmo X                     | S1 v5.0 / S4-2 v4.0  | ~2025 ->                  | Readout + sign; pin gated on ATR  |
| Social welfare and organizational      | Idemia ID.me IDeal Citiz 2.17-i    | S1 v4.0              | 2019-12-17 ->             | Not in scope                      |
| Social welfare and organizational      | Oberthur Cosmo v7 IAS-ECC          | (no FINEID spec id)  | ~2010 - 2019-12-16        | All expired                       |

### Health care / organizational cards

| Card type                          | Card vendor and product | Reason out of scope                                |
|------------------------------------|-------------------------|----------------------------------------------------|
| Health care and organizational     | Segenmark FINEID        | Legacy product, health care category, all expired  |

## Detecting unactivated vs activated cards

Refineid cannot reliably distinguish an activated from an
unactivated FINEID card via card-side query alone on the
in-scope OSes. Live-tested 2026-05-24:

| Card model | `pin_status(PIN1)` on UNACTIVATED card |
|------------|----------------------------------------|
| Thales MultiApp v5.0 (FINEID S4-1 v4.0) | `Remaining(5)` -- indistinguishable from an activated card with 5 retries left. |
| Gemalto MultiApp v4.2 (FINEID S4-1 v3.1) | (not tested unactivated; the maintainer's old card has been activated since 2022.) |

Implications for the PIN-management commands:

- `change-pin*` / `unblock-pin*` run a `pin_status`
  preflight that refuses on `NoInfo` / `Other` / no-probe
  states. This catches *some* unactivated cards but NOT
  Thales MultiApp v5.0.
- The type system enforces a strict command/path split via
  `PinManagementCardContext` vs `ActivationCardContext` (see
  the code in `crates/refineid-client/src/card_pin.rs`) --
  a refactor that mis-routes a context fails to compile.
- The runtime burn-protection ultimately comes down to the
  card's own try counter. Operator error (inserting an
  unactivated card and running `change-pin1`) costs one PIN
  try and one PUK / activation-PIN try.

Open follow-up: probe the activation-PIN slot (`0x83`) for
its retry-counter state. On an unactivated card that slot
should report `Remaining(5)` (activation PIN never used);
on an activated card it should report the post-consumption
state which is OS-specific (`Locked` on Thales v5.0,
`Remaining(N)` on Gemalto v4.2 since the slot doubles as
PUK). This would close the detection gap on Thales v5.0 but
requires extending the `PinSlot` enum in
`refineid-lib-core::auth` to expose slot 0x83, plus live
validation on both card models with a known-state card. Not
yet implemented.

## Orthogonal classifications

A card model classification answers "which hardware is this?"
and is identified by ATR/ATS. It does **not** answer the
following independent questions, which have their own
classifiers:

### Activation PIN length

DVV cut the activation-PIN mechanism over from 8 digits
(reusable, doubles as PUK) to 7 digits (single-use,
separately ordered PUK) on **2026-01-13**. That cutoff falls
**inside** Thales MultiApp v5.0's production window, so the
same physical card model has both pre-cutoff (8-digit) and
post-cutoff (7-digit) instances in the field.

| Card_issued (auth-cert notBefore) | Activation PIN length |
|-----------------------------------|-----------------------|
| < 2026-01-13                      | 8 digits (reusable / PUK-equivalent on old card) |
| >= 2026-01-13                     | 7 digits (single-use) |

The classifier is `classify_card_generation_by_issuance` in
`refineid-lib-core::pkcs15`. See
[`doc/dvv-terminology.md`](dvv-terminology.md) for the
activation-PIN-vs-PUK terminology, the citation, and the
typed `ActivationPinSeven` / `ActivationPinEight` /
`ActivationCode` lattice.

Engineering canonical for this dimension on the wire:

```json
"activation_pin_length": "8"
```

(Plain decimal digit string per
[`doc/i18n-l10n.md`](i18n-l10n.md)'s engineering-canonical-forms
table.)

### Key algorithm family

Citizen FINEID cards have used both RSA and ECC keys in
their lifetime; the issuer DN suffix (G3R / G4R for RSA, G3E
/ G4E for ECC) is a heuristic signal. Not every card model
maps cleanly onto a single algorithm family. Where
operations branch on algorithm family, do it via the parsed
public key, not via the card-model enum.

## Type lattice (planned)

Following [`doc/typing-discipline.md`](typing-discipline.md),
the in-scope classification will be encoded as typed values
in `refineid-lib-core`:

```rust
pub struct Atr(/* bounded byte array */);
pub struct Ats(/* bounded byte array */);

/// DVV's category label. Three known values; only `CitizenEid`
/// is currently in scope. Each variant's `as_dvv_label()`
/// returns the canonical literal used on the wire
/// ("Citizen eID", "Social welfare and organizational",
/// "Health care and organizational").
pub enum CardType {
    CitizenEid,
    SocialWelfareAndOrganizational,
    HealthCareAndOrganizational,
}

/// Vendor of the smart-card hardware as DVV publishes it.
/// "Gemalto" became "Thales" after the 2019 acquisition --
/// both labels appear in DVV's current ATR/ATS table because
/// pre-acquisition Gemalto cards are still in the field.
pub enum CardVendor { Thales, Gemalto }

pub enum FineidCardModel {
    ThalesMultiAppV5,    // Citizen eID, FINEID S4-1 v4.0
    GemaltoMultiAppV4_2, // Citizen eID, FINEID S4-1 v3.1
}

impl FineidCardModel {
    pub fn card_type(self) -> CardType { ... }
    pub fn vendor(self) -> CardVendor { ... }
    pub fn vendor_product(self) -> &'static str { ... } // "MultiApp"
    pub fn vendor_product_version(self) -> &'static str { ... } // "5.0" / "4.2"
    pub fn fineid_specification(self) -> &'static str { ... } // "S4-1"
    pub fn fineid_specification_version(self) -> &'static str { ... } // "4.0" / "3.1"
    pub fn contact_atr(self) -> Atr { ... }
    pub fn contactless_ats(self) -> Ats { ... }
}

pub enum CardClassificationError {
    UnknownOrUnsupportedModel { observed_atr: Atr },
    ContactlessOnlyAtsForContactReader { observed_ats: Ats },
}
```

The classifier reads the reader's ATR (or ATS, contactless)
at session-open and returns either `FineidCardModel` or an
explicit reject. The activation flow takes the typed model
through its `ActivationCardContext` (next to the existing
`bound_serial`, `issuance_date`, `trust` fields).

`CardGeneration` (the current `{ Older, Newer, Unknown }`
enum) is downgraded from a card-identity concept to a pure
projection of the activation-PIN dimension. Code that uses
it to decide PIN length keeps working; code that uses it to
infer card model migrates to `FineidCardModel`.

## What this doc is not

- **Not a parsing spec.** ATR/ATS internal structure (TS,
  T0, TA/TB/TC interface bytes, TCK checksum) is in
  ISO 7816-3 / -4. This doc cites the bytes refineid matches
  against; it does not re-derive what they mean.
- **Not an exhaustive ATR catalogue.** Only the FINEID cards
  DVV ships appear here. A FIDO key or a PIV smartcard's ATR
  is none of refineid's business.
- **Not a guarantee that out-of-scope models will stay out
  of scope.** S1 v5.0 (Idemia Cosmo X) social welfare /
  organizational cards may be added when that use case
  becomes a refineid surface.

## References

- [DVV ATR/ATS technology note][dvv-atr] -- canonical
  upstream.
- [`doc/typing-discipline.md`](typing-discipline.md) -- the
  newtype discipline `FineidCardModel`, `Atr`, `Ats` will
  follow.
- [`doc/dvv-terminology.md`](dvv-terminology.md) -- DVV
  vocabulary, activation-PIN-vs-PUK lattice.
- [`doc/observability.md`](observability.md) -- the wire
  shape (flat string-to-string JSON Lines) that uses the
  `card_type`, `card_vendor`, `card_vendor_product`,
  `card_vendor_product_version`, `fineid_specification`,
  and `fineid_specification_version` field names.
- [`doc/i18n-l10n.md`](i18n-l10n.md) -- the
  engineering-canonical-vs-locale-rendered distinction these
  values play into.
