# refineid-lib-pcsc

PC/SC adapter for refineid-lib-core:
implements the core's `ReaderBackend` and `CardTransport` ports over the `pcsc` crate (winscard / pcsc-lite).
This is the default desktop card transport on macOS, Windows, Linux, and the BSDs.

Single-module crate (`lib.rs`): reader enumeration and filtering, exclusive/shared card connections,
and T=0 APDU exchange including the `61xx` GET RESPONSE / `6Cxx` wrong-Le chaining conventions.
