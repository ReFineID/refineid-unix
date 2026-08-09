# ReFineID for Unix

**Refined Electronic Identification.**

Open Source reimplementation of FINEID middleware for Finnish identity
card users, built from
[public specifications](https://dvv.fi/en/fineid-specifications) --
never from guesswork or from reverse-engineering the incumbent. The
specifications this tree implements are indexed, with what each one
governs, in [`doc/references.md`](doc/references.md).

This repository is the Unix (Linux and BSD) tree. It ships three
things:

- **`refineid`** -- command-line tool: card readout, PIN management,
  qualified document signing (PAdES / CAdES / ASiC-E with RFC 3161
  timestamps and eIDAS trusted-list validation), revocation checks.
- **`librefineid_pkcs11.so`** -- PKCS#11 v2.40 module (read-only,
  sign-only) for Firefox/NSS card login, and for OpenSSL / GnuTLS /
  OpenSSH through p11-kit.
- **`refineid-gui`** -- desktop GUI (Slint): PIN activation, PIN
  change, PUK unblock, viewing the card's portrait and signature
  images, and PDF document signing.

Project stage: beta. The CLI, the PKCS#11 Firefox/NSS card login, and
the reproducible NixOS install are proven against real FINEID
hardware; breadth of card-model coverage is still growing, and
PIN-change stays off by default until validated on a 2026 ECC card.
The macOS/iPadOS app lives in
[ReFineID-Apple](https://github.com/ReFineID/ReFineID-Apple).

## Install

On NixOS, see [doc/install-nixos.md](doc/install-nixos.md) -- one
option in `configuration.nix` installs everything, including automatic
Firefox card-login integration.

On other distributions: install `pcsc-lite` (with the CCID driver),
`fontconfig`, `pkg-config`, and a Rust toolchain (1.95 or newer), then

```sh
cargo build --release --workspace
```

Binaries land in `target/release/`. Register
`librefineid_pkcs11.so` with p11-kit (see
[doc/install-nixos.md](doc/install-nixos.md) for the module-file
shape) or directly in Firefox via
Settings > Privacy & Security > Security Devices.

## Workspace layout

| Crate | Purpose |
| --- | --- |
| [refineid-lib-core](crates/refineid-lib-core/) | FINEID smartcard protocol core: APDUs, PACE, secure messaging, eMRTD, X.509/CRL/OCSP/CMS parsing and verification. No I/O, no platform code. |
| [refineid-lib-pcsc](crates/refineid-lib-pcsc/) | PC/SC adapter implementing the core's reader/transport ports. |
| [refineid-lib-tls](crates/refineid-lib-tls/) | Server-authenticated HTTPS client (rustls) for timestamp authorities and EU trusted lists. |
| [refineid-client](crates/refineid-client/) | Client library and the `refineid` CLI. |
| [refineid-pkcs11](crates/refineid-pkcs11/) | PKCS#11 v2.40 cdylib for Firefox/NSS card login. |
| [refineid-gui](crates/refineid-gui/) | Desktop GUI (Slint): PIN management, portrait/signature, document signing. |

## Maintainer

Petri Koistinen <petri.koistinen@refineid.fi>. Issues and discussion:
<https://github.com/ReFineID/ReFineID-Unix>.

## License

Apache-2.0. See [LICENSE](LICENSE).
