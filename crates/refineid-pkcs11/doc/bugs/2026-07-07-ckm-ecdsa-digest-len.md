# CKM_ECDSA digest length: card wants exactly 48 bytes

Date: 2026-07-07. Fixed: the module now fits any `CKM_ECDSA`
digest to the P-384 card slot.

## Symptom

Firefox suomi.fi card login stalled on
`https://kortti.tunnistautuminen.suomi.fi/hstidp/hst-prompt` after
the PIN1 prompt and certificate picker, eventually timing out to
`?e=1` (IdP: no client certificate received). Other mTLS services
worked.

## Diagnosis method

`pkcs11-spy` interposed between p11-kit and the module (override
`/etc/pkcs11/modules/refineid.module` to point at
`/usr/lib64/pkcs11/pkcs11-spy.so`, export `PKCS11SPY=<real module>`),
driven by NSS `tstclnt` against the production kortti IdP. The trace
showed `C_Login` OK, `C_SignInit(CKM_ECDSA)` OK, then `C_Sign` with
**32 bytes** of data returning `CKR_DATA_LEN_RANGE`. NSS maps any
sign failure to "Failed to load a suitable client certificate", so
the handshake continued without a certificate and the IdP timed out.

## Root cause

The kortti IdP terminates the card hop on TLS 1.2 and its
`CertificateRequest` advertises `ecdsa_secp384r1_sha384` after
SHA-256 pairs; NSS picks ECDSA+SHA-256 for the P-384 key, which TLS
1.2 permits (RFC 5246 does not couple curve and hash). `CKM_ECDSA`
is defined over "any length" input, so NSS hands the module the raw
32-byte SHA-256 digest. The module demanded exactly 48 bytes because
the FINEID card's `SHA384-ECDSA` algorithm reference consumes a fixed
48-byte block.

The CLI backends never hit this because they always pair P-384 with
SHA-384 in their own signature-algorithm knobs. Firefox previously
"worked" through OpenSC, which pads the digest to the field length.

## Fix

PKCS#11 v2.40 s6.4.1: for ECDSA the token uses the leftmost
`ceil(log2(n))` bits of the digest. Under ECDSA the digest is an
integer, so left-padding a shorter digest with zeros preserves its
value; longer digests keep the leftmost 384 bits. Empty input is
rejected (`CKR_DATA_LEN_RANGE`).

Implemented as the `CkEcdsaDigest` newtype in `src/sign.rs`: raw
CKM_ECDSA bytes enter through `fit_p384()`, and only the explicit
`into_card_hash()` boundary converts the fitted block into the
lib-core `Sha384` type handed to the card. A padded SHA-256 digest
is never disguised as a SHA-384 hash anywhere else in the pipeline.

## Recurrence note

This same card behaviour (fixed 48-byte input for P-384 operations)
had been encountered before in earlier work and was fixed then by
strong typing at the boundary; it was not documented at the time,
which is why it had to be rediscovered with a spy trace. Hence this
file.
