# Test vectors

Fixtures used only by `#[cfg(test)]` code in this crate.
They are **not** trust anchors and must never be loaded by production code (those live in `../trust-anchors/`).

## `fineid-intermediate-01-citizen-g4e.der`

The DVV *Citizen Certificates - G4E* intermediate CA,
byte-for-byte identical to `platform/apple/RefineID/Resources/fineid-intermediate-01-citizen-g4e.der`
(verify with `shasum -a 256`).
Copied here so the `cert_chain` tests can build a real two-link chain without reaching outside the crate directory:

- leaf  = this intermediate (`ecdsa-with-SHA384`, EC P-384)
- issuer = `../trust-anchors/dvv-gov-root-ca-g3-ecc.der` (self-signed root)

The intermediate's `issuer` DN is byte-identical to the ECC root's `subject` DN,
and the root's key verifies the intermediate's signature,
so `walk_chain` resolves the issuer from the pool and exercises the real ECDSA-P384/SHA-384 chain-verify path.
