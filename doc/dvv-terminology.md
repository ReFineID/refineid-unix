# DVV terminology

Code identifiers use universal PKI terms; user-facing strings
(CLI prompts, error messages, audit JSON `human` field, doc copy)
use the DVV vocabulary.

## Codes that protect the card

The Finnish citizen ID card (FINEID) protects key operations with
up to **four** distinct codes. The first two are user-set during
activation; the second two are issued by DVV.

| Code identifier in repo | English (DVV)        | suomi                  | svenska         | Length         | Set by   |
|-------------------------|----------------------|------------------------|-----------------|----------------|----------|
| `Pin1`                  | basic PIN code       | perustunnusluku        | baskod          | 4-12 digits    | citizen  |
| `Pin2`                  | signature PIN code   | allekirjoitustunnusluku | signaturkod    | 6-12 digits    | citizen  |
| (n/a in code)           | activation PIN       | aktivointitunnusluku   | aktiveringskod  | 7 digits (new card) / 8 digits (old card) | DVV (in the activation letter) |
| `Puk`                   | PUK code             | PUK-tunnusluku         | PUK-kod         | 7 or 8 digits  | DVV (separately ordered) |

> ⚠ **The 2026-01-13 cutoff is normative.** Per DVV
> (<https://dvv.fi/en/activation-of-the-citizen-certificate>):
>
> - **Cards issued on or after 2026-01-13**: 7-digit activation
>   PIN, **single-use** -- consumed by the activation step,
>   cannot subsequently unblock PIN1 / PIN2. Recovery from
>   lockout requires a separately-ordered PUK (paid).
> - **Cards issued before 2026-01-13**: 8-digit activation PIN,
>   **reusable** -- doubles as the card's PUK, can unblock
>   PIN1 / PIN2 after they lock. Exhausting it via 5 wrong
>   tries permanently locks the chip for e-services (the card
>   still works as ID document and travel document; a new card
>   from the Police is the only recovery).
>
> The card's issuance date is printed on its surface.
>
> In refineid the two activation flows are *two distinct
> types*:
>
> - `ActivationPinSeven` -- new-card single-use code, paired
>   with `CardGeneration::Newer`.
> - `ActivationPinEight` -- old-card reusable code, paired
>   with `CardGeneration::Older`.
> - `Puk` -- generation-independent unblock code accepting exactly
>   7 or 8 digits. An 8-digit PUK is also issued separately for
>   current ECC cards; length does not identify card generation.
>   The older-card 8-digit form is identical in wire shape to the
>   reusable activation PIN, but distinguished from it by type to
>   reflect operator intent.
>
> The CLI parses the operator's input length at the prompt
> boundary into the matching typed variant; `activate_first`
> then matches the variant against the detected card
> generation and refuses on mismatch before any modify APDU
> goes out.
>
> **Engineering-wise** the activation PIN and PUK may still be
> the same card-side password slot (`0x83`) on either card --
> see below.

> ⚠ **DVV uses two names for what may be a single card-side
> mechanism.** Current-generation activation letters ship a
> 7-digit *activation PIN* (aktivointitunnusluku); the *PUK
> code* (PUK-tunnusluku) is separately orderable for a fee.
> Engineering-wise these are plausibly the same password
> reference inside the card (`0x83` per FINEID S4-1 v3.1) --
> the activation letter ships an initial value, DVV writes a
> new value into the same slot when the citizen orders a PUK,
> and the card sees one mechanism with one try counter. The
> previous-generation card spelled this out by calling the
> single 8-digit code "aktivointitunnusluku" for both roles.
>
> Treat the two names as distinct in **user-facing strings,
> audit logs, and prose** -- that is how DVV communicates and
> what citizens see on the letter and on dvv.fi. Don't assert
> they're separate hardware mechanisms in committed prose.
> FINEID S4-2 v4.0 (the organizational profile) settles the
> question for that line only: one PIN PUK security data object
> (`12`) whose EF.AOD label is "aktivointitunnusluku", with
> change reference data and reset retry counter both Never
> (sections 4.2-4.3) -- one mechanism, one counter, never
> replaceable. The citizen line's S4-1 stays silent, so the
> caution stands there.
>
> refineid uses the activation PIN only for factory activation and
> uses the PUK for `card unblock-pin1` / `card unblock-pin2`.
> FINEID S4-1 v4.2 section 4.6 requires both PINs to be initialized,
> but there is no combined two-PIN card command. Middleware sends one
> per-slot command for PIN1 and then one for PIN2: `RESET RETRY COUNTER`
> on the old scheme and `CHANGE REFERENCE DATA` on the new scheme.
> Later recovery targets only the selected blocked PIN.

The terms above are DVV's own -- see the activation letter that
ships with every new card and the public DVV pages.

Canonical DVV sources:

- <https://dvv.fi/en/personal-identity-code>
- <https://dvv.fi/henkilotunnus>
- <https://dvv.fi/sv/personbeteckning>
- <https://dvv.fi/citizen-certificate>

## Operational rules for each code

### `Pin1` / `Pin2`

- Set during card activation (citizen chooses).
- Card-side try counter; 5 wrong tries blocks the PIN.
- A blocked PIN is recoverable only via the PUK
  (`card unblock-pin1` / `card unblock-pin2`).

### Activation PIN (`aktivointitunnusluku` / `aktiveringskod`)

- 7 digits on cards issued from ~2025; 8 digits on older cards.
- Single-use. Used once during card activation to set the
  initial `Pin1` and `Pin2`.
- 5 wrong tries during activation **locks the activation PIN
  itself**. After that the card can only be activated via the
  PUK (next row).
- Distributed inside the DVV activation letter that ships with
  the card. The letter explicitly warns to keep it separate
  from the card.

### PUK (`PUK-tunnusluku` / `PUK-kod`)

- Exactly 7 or 8 digits, independent of card generation. Field
  evidence includes an 8-digit separately ordered PUK for a current
  ECC card; therefore generation must not select the accepted length.
- Separately ordered from DVV, *paid service*.
- Used to (a) unblock `Pin1` / `Pin2` after lockout, and
  (b) activate the card if the activation PIN got locked.
- PUK has its own try counter. Exhausting it permanently
  bricks the card -- DVV reissue is the only recovery.
- FINEID S4-1 v4.2 section 4.1 sets the PUK try limit to 5,
  its usage counter to `No limit`, and both PIN unblocking counters
  to `No limit`. A successful unblock resets the PUK retry counter.
  Production ECC-card validation confirmed two successive PIN2
  recoveries with the same PUK; after each recovery both PIN2 and
  PUK reported 5 retries remaining.
- refineid's `card unblock-pin1 / card unblock-pin2` drive
  this code via the PKCS#15 `RESET RETRY COUNTER` APDU.

### CAN (Card Access Number)

- suomi: *kortin pääsykoodi*; svenska: *kortets åtkomstkod*. An
  access code, which is what a Card Access Number is - not a
  "käyttönumero"/"användningsnummer", which would name usage.
- 6 digits, **printed on the card front**, **not secret**.
- Used to set up the PACE secure channel before reading the
  eMRTD application. The CAN is the bearer of the operator's
  intent to physically possess the card; an attacker who can
  see the card front can read it too.
- refineid surfaces the CAN as a normal argv option
  (`--can NNNNNN`) -- not subject to the no-PIN-in-argv rule,
  precisely because it isn't secret.

## Naming rules

### Personal Identity Code (PIC)

PIC is the DVV-published English term. **Never "SSN"** -- that's
American social-security terminology and wrong for Finnish
identifiers. The suomi term is *henkilötunnus* (abbreviated
HETU); the svenska term is *personbeteckning*. Either of those
is acceptable inside suomi or svenska user-facing strings
respectively; in English prose, code, and committed docs use
PIC.

### Activation PIN vs PUK -- code-side discipline

Old refineid prose treated *aktivointitunnusluku* as a synonym
for PUK because the previous-generation card conflated them.
On the current-generation card they are distinct. Code review
should flag any new occurrence of either pattern:

- "PUK (aktivointitunnusluku)" -- wrong, those are different
  codes now. Use either "PUK" or "activation PIN" depending on
  which code is meant.
- "8-digit activation PIN" -- wrong, the new card's activation
  PIN is 7 digits. Eight digits is one accepted PUK length and the
  old-generation activation-code length.

The PUK-related code in `refineid-lib-core::auth` and
`refineid-client::card_pin` operates on the PUK proper -- the
naming is correct, only the surrounding doc comments needed
the conflation removed.

### Project name forms

**ReFineID / refineid / REFINEID / `librefineid_*`** -- four
written forms; not interchangeable.

- `ReFineID` for prose
- `refineid` for command and crate names
- `REFINEID` for environment variables
- `librefineid_*` for FFI symbols

The name layers deliberately: **Re** = reimplementation (not Rust),
**Fin** = Finn(ish citizen), **e** = electronic, **ID** = identity.
The lowercase `refineid` contains the Swedish `finne` (= Finn), and
the library name `librefineid_pkcs11` reads as "Libre Finn e-ID";
spoken aloud, `ReFineID` is approximately "refine". Every layer is a
deliberate decision, not a typo -- do not "correct" the spelling,
the capitalisation, or the `lib` prefix.
