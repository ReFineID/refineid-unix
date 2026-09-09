# PKCS#11 support matrix -- what works, what's stubbed, and why

The canonical inventory of what `refineid-pkcs11` supports. Every
cell is a deliberate decision; nothing here is "we forgot to
implement that". If a consumer asks "can I do X with this token?",
this page answers it.

Ground truth is `src/api.rs` (the v2.40 vtable and every stub),
`src/sign.rs` (mechanism parsing and the card leg), and
`src/token.rs` (objects, PIN guard). The module is read-only and
sign-only: its single job is Firefox / NSS client-certificate TLS
authentication (see [`../README.md`](../README.md)).

## Versioning

| Aspect | Value |
|---|---|
| Cryptoki version (`C_GetInfo`, vtable) | 2.40 |
| Function list | all 68 v2.40 slots non-NULL, per spec |
| Library version | CalVer `year.month`, derived from `Cargo.toml` at build time |

## Function support

Implemented functions, by v2.40 category:

| Category | Functions | Notes |
|---|---|---|
| Module | `C_Initialize`, `C_Finalize`, `C_GetInfo`, `C_GetFunctionList` | `C_Finalize` zeroizes any cached PIN1 |
| Slot / token | `C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo`, `C_GetMechanismList`, `C_GetMechanismInfo` | slot = PC/SC reader; token info carries the live PIN1 retry-state flags |
| Slot events | `C_WaitForSlotEvent` | non-blocking (`CKF_DONT_BLOCK`): refreshes the slot table and reports each card presence change exactly once; no pending change answers `CKR_NO_EVENT`. A blocking call answers `CKR_FUNCTION_NOT_SUPPORTED` (it would need an event thread inside the host) |
| Sessions | `C_OpenSession` (serial), `C_CloseSession`, `C_CloseAllSessions`, `C_GetSessionInfo` | parallel sessions refused with `CKR_SESSION_PARALLEL_NOT_SUPPORTED` |
| Login | `C_Login` (`CKU_USER` only), `C_Logout` | PIN1 validated locally (4..=12 ASCII digits), then verified on the live card before caching |
| Objects | `C_FindObjectsInit` / `C_FindObjects` / `C_FindObjectsFinal`, `C_GetAttributeValue` | three fixed objects: auth certificate, public key, private key, sharing one `CKA_ID` |
| Signing | `C_SignInit`, `C_Sign` (single-part) | two-call length query answered without touching the card |
| Verifying | `C_VerifyInit`, `C_Verify` (single-part) | pure software against the cached certificate public key -- no card IO, no PIN. Input shapes mirror the sign path: `CKM_RSA_PKCS` takes `DigestInfo \|\| SHA-256 hash`; `CKM_ECDSA` takes a raw digest (SHA-1/224/256/384/512 lengths) with raw `r \|\| s` signatures |
| PIN change | `C_SetPIN` | only in the opt-in `pin-change` build; the default (login-only) build stubs it with `CKR_FUNCTION_NOT_SUPPORTED` |

Everything else returns `CKR_FUNCTION_NOT_SUPPORTED`, except where
v2.40 names a more specific code for a permanent refusal:

| Function | CK_RV | Why this code |
|---|---|---|
| `C_InitToken` | `CKR_TOKEN_WRITE_PROTECTED` | DVV personalises the card; the token reports `CKF_WRITE_PROTECTED` |
| `C_SignRecoverInit` | `CKR_KEY_FUNCTION_NOT_PERMITTED` | the FINEID auth key signs without message recovery |
| `C_UnwrapKey` | `CKR_KEY_FUNCTION_NOT_PERMITTED` | no key on this token can unwrap, and the read-only token could never store the result |
| `C_DigestKey` | `CKR_KEY_INDIGESTIBLE` | no key on this token can be digested |
| `C_SeedRandom` | `CKR_RANDOM_SEED_NOT_SUPPORTED` | the token accepts no seed material |
| `C_GetFunctionStatus` | `CKR_FUNCTION_NOT_PARALLEL` | legacy parallel-function call; v2.40 s11.16 mandates this return |
| `C_CancelFunction` | `CKR_FUNCTION_NOT_PARALLEL` | same |

There is no object creation, no key generation, no
encrypt / decrypt / digest, no wrap / derive, and no write path of
any kind.

## Mechanisms

Exactly one mechanism is advertised per token, chosen by reading
the card's authentication certificate (SPKI algorithm decides):

| `CKM_*` | Card profile | Input | Output | Mechanism info |
|---|---|---|---|---|
| `CKM_RSA_PKCS` | RSA-3072 (FINEID S4-1 v3.1) | PKCS#1 v1.5 `DigestInfo` DER, SHA-256 only | 384-byte PKCS#1 signature | key size 3072/3072, `CKF_SIGN` |
| `CKM_ECDSA` | ECC P-384 (FINEID v4.0) | raw digest of any hash, fitted to 48 bytes | raw `r \|\| s`, 96 bytes | key size 384/384, `CKF_SIGN \| CKF_EC_F_P \| CKF_EC_NAMEDCURVE \| CKF_EC_UNCOMPRESS` |

Digest fitting rule (`CKM_ECDSA`): the card's SHA384-ECDSA slot is
exactly 48 bytes, and ECDSA treats the digest as an integer, so a
shorter digest (TLS 1.2 commonly negotiates ECDSA+SHA-256) is
left-padded with zeros -- the same integer -- and a longer one is
truncated to the leftmost 384 bits, per the PKCS#11 v2.40 s6.4.1
ECDSA rule. See
[`bugs/2026-07-07-ckm-ecdsa-digest-len.md`](bugs/2026-07-07-ckm-ecdsa-digest-len.md).

Input rejection: a malformed or non-SHA-256 `DigestInfo` answers
`CKR_DATA_INVALID`; an empty ECDSA input answers
`CKR_DATA_LEN_RANGE`; the degenerate sentinels 0 / 1 / -1
(all-zero, all-ones, lone `0x01` in either byte order -- the
signature of an uninitialised buffer upstream, never a real hash)
answer `CKR_DATA_INVALID` on both legs. Requesting the mechanism
the card does not have answers `CKR_MECHANISM_INVALID` at
`C_GetMechanismInfo` and `C_SignInit`.

## Advertisement vs reality

Guiding principle: **advertise only what the token can actually
perform end-to-end.** One card has one auth key and one sign
mechanism, so the list has one entry. Pure-software shims (digest,
verify, encrypt) would tick conformance boxes but mislead callers
about what the token does; they are deliberately absent. The
converse also holds: a mechanism absent from `C_GetMechanismList`
is refused at `C_SignInit` with `CKR_MECHANISM_INVALID`, never
implemented-but-hidden.

## Where this matrix is enforced

| Source | What |
|---|---|
| `src/api.rs::c_get_mechanism_list` / `card_mechanism` | the one-entry mechanism list, read from the card |
| `src/api.rs::c_get_mechanism_info` | key-size bounds and capability flags |
| `src/api.rs` bottom half | every stub and its specific CK_RV |
| `src/sign.rs::Mechanism` | ck-type mapping, signature lengths, input parsing |
| `src/token.rs::TokenObjects::fill_key_material` | SPKI -> key type -> mechanism selection |

## Adding a mechanism

If a future consumer needs another mechanism:

1. Confirm the card can run it: check DVV's published FINEID
   specifications (S1 algorithm tables; S4-1 PrKDF access modes)
   at <https://dvv.fi/en/fineid-specifications>, then prove the
   algRef on real hardware.
2. Add the variant to `Mechanism` in `src/sign.rs` with its input
   parser and card leg (`sign_with_card`), plus its
   `signature_len` for the two-call query.
3. Advertise it: extend `card_mechanism` / `c_get_mechanism_list`
   and give it correct flags and key-size bounds in
   `c_get_mechanism_info`.
4. Hardware-validate the full flow (card + reader on the target
   platform) per AGENTS.md hard rule #2; the operator rigs in
   `test/` are the starting point.
5. Update this matrix.
