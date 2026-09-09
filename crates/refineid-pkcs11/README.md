# refineid-pkcs11

A minimal, read-only, sign-only PKCS#11 v2.40 (cryptoki) module for FINEID cards.
It builds as a C ABI shared library (`librefineid_pkcs11.so` on Linux, `.dylib` on macOS) plus an `rlib` for tests.

Its single job is Firefox / NSS client-certificate TLS authentication:
it exposes the card's authentication certificate and its private key, takes PIN1 through `C_Login`,
and signs the TLS `CertificateVerify` digest on the card.
The same module also drives OpenSSL through the `pkcs11-provider` bridge once registered with p11-kit.

## Scope

Deliberately small.
Implemented:

- Discovery: `C_Initialize`, `C_Finalize`, `C_GetInfo`, `C_GetFunctionList`, `C_GetSlotList`, `C_GetSlotInfo`,
  `C_GetTokenInfo`, `C_GetMechanismList`, `C_GetMechanismInfo`, `C_WaitForSlotEvent` (non-blocking: reports card insertion / removal events, so NSS notices a card without a browser restart).
- Sessions: `C_OpenSession` (serial, read-only), `C_CloseSession`, `C_CloseAllSessions`, `C_GetSessionInfo`.
- Login: `C_Login` (`CKU_USER` only), `C_Logout`.
  On success the module best-effort forwards PIN1 over a local
  pin-channel socket to the ReFineID signature-creation-service
  daemon when one is running (a separate component), and reports
  card removal the same way, so that daemon neither prompts a
  second time nor serves a stale cache. Forwards run detached;
  failure is a diagnostic line, never an error to NSS.
  PIN1 is validated as 4..=12 ASCII digits and cached in memory for
  at most five minutes;
  it is verified on the card inside each sign, never logged, and zeroized on logout, session close, or finalize.
- Objects: `C_FindObjectsInit` / `C_FindObjects` / `C_FindObjectsFinal` and `C_GetAttributeValue` over three objects
  -- the authentication certificate (`CKO_CERTIFICATE`, `CKC_X_509`),
  its public key (`CKO_PUBLIC_KEY`, from the certificate SPKI, for
  consumers such as p11tool / libp11 that enumerate public keys),
  and its private key (`CKO_PRIVATE_KEY`, `CKK_RSA` or `CKK_EC`).
  They share one `CKA_ID` so NSS pairs them.
  The private key answers `CKA_EXTRACTABLE` false and
  `CKA_NEVER_EXTRACTABLE` / `CKA_ALWAYS_SENSITIVE` true -- the FINEID
  key never leaves the card.
- Signing: `C_SignInit` / `C_Sign` (single-part).
  `CKM_RSA_PKCS` takes a DER `DigestInfo` (SHA-256 only) on the RSA-3072 card;
  `CKM_ECDSA` takes a raw digest of any hash on the ECC P-384 card and returns raw `r || s`.
  The card slot is exactly 48 bytes,
  so shorter digests (TLS 1.2 commonly negotiates ECDSA+SHA-256) are left-padded with zeros
  and longer ones truncated to the leftmost 384 bits,
  per the PKCS#11 v2.40 s6.4.1 ECDSA rule -- see `doc/bugs/2026-07-07-ckm-ecdsa-digest-len.md`.
  The two-call length query works without touching the card.
- Verifying: `C_VerifyInit` / `C_Verify` (single-part), pure
  software against the cached certificate public key -- no card
  IO, no PIN. Same input shapes as signing.

Everything else in the v2.40 function list is present but returns `CKR_FUNCTION_NOT_SUPPORTED`,
except where the spec names a more specific code for a permanent refusal:
`C_InitToken` returns `CKR_TOKEN_WRITE_PROTECTED`,
`C_SignRecoverInit` / `C_UnwrapKey` return `CKR_KEY_FUNCTION_NOT_PERMITTED`,
`C_DigestKey` returns `CKR_KEY_INDIGESTIBLE`,
`C_SeedRandom` returns `CKR_RANDOM_SEED_NOT_SUPPORTED`,
and the legacy `C_GetFunctionStatus` / `C_CancelFunction` return `CKR_FUNCTION_NOT_PARALLEL` as v2.40 mandates.
There is no object creation, no key generation, no encryption / decryption / digesting, no write path;
verification is software-only (above);
the token reports `CKF_WRITE_PROTECTED`.

## Diagnostics

Off by default. `REFINEID_PKCS11_LOG=<path>` appends the NSS call
sequence (function names, handles, byte lengths -- never PIN bytes or
attribute values) to an operator-named file; without it,
`REFINEID_DEBUG=1` writes the same lines to stderr. There is
deliberately no default log path: the module runs inside the
browser's address space, and an implicit file in a world-writable
directory would be a symlink-attack surface. The environment is read
once per process.

`examples/nss_debug.rs` answers "why doesn't Firefox see the card"
without launching Firefox: it dlopens the built module exactly like
NSS and replays NSS's discovery probes, including the vendor-defined
builtin-root class and the `CKO_PROFILE` search this module must
answer with zero matches (the eager-PIN1 rule). Run
`cargo run -p refineid-pkcs11 --example nss_debug` with a card
present; add `--login` (PIN1 from `REFINEID_PIN1`) and
`--sign-probe` for the key path.

## Hardware test rigs (`test/`)

Operator-run, gated on `REFINEID_HARDWARE_TEST=1`; neither runs in
the commit hooks.

- `test/pkcs11-hardware-suite.sh` -- pkcs11-tool + CLI sweep with a
  PIN-retry-counter guard around every card-touching phase (aborts
  the moment a counter drops) and offline openssl verification of
  every signature. PIN-change and PUK-unblock phases are separately
  opt-in.
- `test/headless-cert-auth.sh` -- real TLS client-cert
  authentication through NSS's `tstclnt` against a fresh NSS
  profile, no browser; supports A/B comparison of two module builds
  by diffing their `C_Login`/`C_Sign` log lines. Reproduces in ~5
  seconds the cross-layer regression class that once evaded every
  unit test.

## Card access

The module opens the reader itself through `refineid-lib-pcsc` (`PcscBackend::open_session`),
reads what it needs, and drops the transport immediately.
PIN-bearing opens use `ReaderAccessCap::PinSequence`: the whole
SELECT -> VERIFY -> operation span runs inside one held PC/SC
transaction, so a concurrent card consumer can neither interleave
an APDU mid-sequence nor consume the card's verified state.
It never holds the card open across PKCS#11 calls, and it does not hold the module lock across card IO,
so a shared desktop reader stays usable.

## Versions

- Library version: tracks the workspace CalVer (see the root `VERSION` file).
- Cryptoki version: `2.40`.

## Register with p11-kit

Install the built library somewhere on the system module path (for example `/usr/lib64/pkcs11/librefineid_pkcs11.so`)
and drop a p11-kit module file, e.g. `/usr/share/p11-kit/modules/refineid.module`:

```
module: librefineid_pkcs11.so
critical: no
```

Use an absolute path if the library is not on the default module search path:

```
module: /usr/lib64/pkcs11/librefineid_pkcs11.so
critical: no
```

Firefox / NSS then load the module through p11-kit,
or you can add it directly with `modutil -dbdir sql:$HOME/.pki/nssdb -add "ReFineID" -libfile /usr/lib64/pkcs11/librefineid_pkcs11.so`.
OpenSSL reaches the same module through `pkcs11-provider`, which also enumerates p11-kit modules.

This README documents the file content only; it installs nothing.

## Build

```
cargo build -p refineid-pkcs11
```

The `cdylib` builds on both Linux and macOS; PC/SC access is cross-platform through `refineid-lib-pcsc`.
