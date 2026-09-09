# Typing discipline

The condensed rule set the code comments cite. The model is *parse,
don't validate*: external data is parsed once at the boundary into a
domain type, then carried as that type. Downstream code takes the
domain type, not the raw bytes or string that happened to produce it
-- compile-time evidence that the parse happened.

```rust
// Bad: a string and a hope that some caller validated it.
fn validate_can(s: &str) -> Result<(), CanError>;
fn authenticate(can: &str);

// Good: possession of a Can proves the parse.
struct Can([u8; 6]);
impl Can {
    fn from_ascii_digits(bytes: [u8; 6]) -> Result<Self, CanError>;
}
fn authenticate(can: Can);
```

Refine at trust boundaries, not everywhere: a newtype pays when it
carries an invariant; a wrapper that adds a name but no invariant is
ceremony. Build for needs that exist, never for imagined ones.

## Boundary rules

- **Rule A (policy, not a gate)** -- free functions should not take
  base-type borrows (`&[u8]`, `&str`). Make the function a method on
  a natural typed receiver, or introduce a named input type. Private
  helpers taking an already-refined borrow (`&OwnedCert`) are fine --
  the borrow carries its invariant.
- **Rule B** -- public APIs take refined inputs. The public interface
  is the hard signature gate.
- **Rule C** -- `impl AsRef<[u8]>` / `impl AsRef<str>` is not a
  boundary type: it accepts arbitrary bytes from arbitrary origins
  and adds no provenance. Fine for representation access and generic
  glue; not a parser boundary.
- **Rule D** -- trait conversions (`TryFrom<&[u8]>`) are not escape
  hatches; prefer constructors that name the typed origin
  (`from_card_response`, `from_http_body`, `from_file`). Fixed-size
  wire forms are the exception: `[u8; N]` is honest when the length
  itself is the protocol invariant.
- **Rule E** -- no magic numbers anywhere, in production code and
  tests alike: every literal with domain meaning goes through a
  named constant or typed value.
- **Rule F** -- literal representation: hex with `_` grouping for
  values whose semantics live at bit/byte/power-of-2 boundaries
  (`0x10_000`), decimal for named ecosystem conventions (ports, HTTP
  statuses, RSA bit sizes); pair with a unit-bearing comment
  (`// 64 KiB`) where the human-unit synonym helps.

## Banned shapes

- **Pass-through wrappers**: a newtype whose constructor accepts
  anything and whose only method hands the raw value back adds a
  name, not an invariant.
- **`Other`/catch-all enum arms** that retain unrecognised protocol
  input: unsupported input is rejected at the boundary with a typed
  error, not carried along.

## Type tiers

- **Tier 0 -- raw representation**: exists only at the boundary.
- **Tier 1 -- validated wrapper**: proof a check happened
  (`Can`, `PinBytes`).
- **Tier 2 -- structured domain value**: parsed structure with typed
  accessors (`Atr`, `CommandApdu`, `Uri`).
