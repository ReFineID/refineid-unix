# ReFineID GUI

Native desktop application for managing supported FINEID cards through PC/SC readers.

## User interface principles

The interface follows **simple as possible, but no simpler**:

- Do not add redundant headings, explanatory success text, nested intention levels, decorative indentation, or layout-only whitespace.
- The selected card is indicated directly in the card list with a stronger border and bold label. Do not repeat selection as status text elsewhere.
- PIN and Portrait views are the only top-level content navigation. Operation buttons select the security form; forms do not repeat their operation as a heading.
- Align related controls using stable columns. In the Reactivate Card form, the PUK/help/error column must align with PIN1 and PIN2 fields.

## Status messages

Show feedback only when it helps the user act:

- Show concise success/failure feedback for PIN activation, PIN changes, and PIN reactivation, on every supported card generation (S4-1 v3.1 RSA-3072 and v4.0 ECC P-384).
- Show detailed information for errors and warnings.
- Do not show routine success messages such as card discovery, card selection, portrait loading, or signature loading.
- The Portrait page status area is for CAN/image-related errors before loading. Once image data loads, hide the CAN input, Load action, and prior page status because loaded data is cached for the selected card during the session.

## Portrait and signature

- Before images are loaded, request the six-digit CAN and show load failures.
- After a portrait or signature is available, display the images and their Copy/Save actions without redundant image headings.
- Cache CAN and image data by physical card identity for the current application session. Clear sensitive/session state when the card changes or is removed.

## Numeric secret input and validation

- PIN, PUK, activation-code, and CAN fields accept digits only.
- Secret fields are masked where appropriate and input is length-limited before card commands are sent.
- Reject predictable weak PINs in the GUI, including obvious repeated and consecutive-digit values.
- Validate PIN confirmation live, but avoid premature mismatch feedback until both fields have their minimum relevant length and equal entered length.
- Keep the PUK after a successful PIN1 reactivation so it can be used for PIN2; clear it when leaving the reactivation context or changing cards.

## Reactivation and PUK retries

- Show the counter-safe live PUK retry count in both factory activation and
  individual PIN recovery views, alongside the PIN retry state.
- Reactivation errors must be user-facing, never Rust debug output.
- `WrongPuk { retries_left: ... }` is rendered as `Wrong PUK. N attempts remaining.`
- The PUK has its own retry counter. A successful reset-retry-counter command
  resets both the target PIN retry counter and the PUK try counter to their
  configured limits; production old- and new-generation cards confirm this.
- Query PUK retries with the credential-free PIN-container `GET DATA` form
  from FINEID S1 v4.2 section 3.15. Never probe by submitting an intentionally
  wrong PUK because that consumes an attempt.
- A locked or invalidated PUK/card is terminal and should clearly tell the user that replacement is required.

## Card status monitoring

- Open the window immediately. Full card inspection runs outside Slint's
  UI thread.
- No timed polling. A background monitor parks in `SCardGetStatusChange`
  and requests one inspection per card insertion/removal or reader
  arrival. Peer activity that does not change presence (a browser
  holding the card for a TLS signature) never triggers card traffic.
- Never overlap full inspections. Buttons remain disabled while an inspection
  is in flight, and completed reports are applied on the UI event loop.

## Versioning

The window title uses the release-controlled workspace CalVer from `Cargo.toml`.

## Validation

Run the crate check after UI or behavior changes:

```text
cargo check -p refineid-card-manager
```

When a visible behavior change is requested, rebuild and launch the application with:

```text
cargo run -p refineid-card-manager
```
