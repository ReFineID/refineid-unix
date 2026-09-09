# refineid-lib-core

FINEID smartcard protocol core -- entities and use cases only.
No PKCS#11, HTTP, GUI, or platform awareness;
card and network I/O happen behind ports (traits) that adapter crates implement.

## Contents

- **Card protocol**: `apdu/` (ISO 7816-4 command/response types, status words), `atr.rs`,
  `transport.rs` / `backend.rs` (the `CardTransport` / `ReaderBackend` ports), `fineid_card.rs`,
  `pkcs15.rs` (on-card file layout), `pin.rs` (zeroizing PIN containers), `sign.rs` (PSO sign/decipher operations).
- **eMRTD / ICAO**: `pace.rs` (PACE key agreement), `secure_messaging.rs` (AES CBC/CMAC session channel),
  `emrtd.rs` (data-group reads), `aa.rs` / `ca.rs` (Active/Chip Authentication), `icao_pkd.rs`, `ldif.rs`,
  `card_access.rs`, `can.rs`.
- **PKI**: `x509.rs`, `crl.rs`, `ocsp.rs`, `cms.rs`, `revocation.rs`, `cert_state.rs`
  -- parsing plus signature verification, with "verified" wrapper types so unchecked data cannot be consumed.
- **Primitives**: `ber.rs` (BER-TLV), `oid.rs` (typed OIDs, compile-time dotted-decimal constants),
  `crypto/` (AES/CMAC/ECDH containers, Brainpool P-384 math for PACE), `identity.rs` (typed card-holder fields),
  `iso8601.rs`, `hex.rs`, `events.rs` (structured, privacy-classified event stream), `error.rs`, `rng.rs`.

Consumed by every other crate in the workspace.
