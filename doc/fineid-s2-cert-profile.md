# FINEID S2 certificate profile

The contents of DVV-issued certificates, the CA hierarchy
behind them, and which subset of all that refineid's cert
layer leans on.

This is the canonical reference. Code that classifies certs,
matches a pinned root, builds a path, or interprets a KeyUsage
bit pattern should cite this doc; the spec values are not
duplicated into module-level comments.

## Source of truth

DVV publishes the full spec at:

- [FINEID specifications index][fineid-specs]
- [FINEID-S2 v5.2, dated 2024-03-12][s2-pdf] -- "DVV CA model
  and certificate contents", Jari Pirinen (DVV ICT Unit).

[fineid-specs]: https://dvv.fi/en/fineid-specifications
[s2-pdf]: https://dvv.fi/en/fineid-specifications

S2 is itself based on:

- IETF RFC 5280 -- Internet X.509 PKI Certificate and CRL
  Profile (D. Cooper, NIST, May 2008). The Basic Path
  Validation algorithm in §6.1 is normative for *every*
  trust decision refineid makes.
- ETSI EN 319 412 series -- Certificate Profiles, parts 2-5
  (natural persons, legal persons, web sites, QCStatements).
- RFC 3739 -- Qualified Certificates Profile.
- RFC 6960 -- OCSP.
- CA/Browser Forum Baseline Requirements -- serial-number
  entropy.

Any disagreement between this doc and the linked PDF is a
bug in this doc; the spec wins.

## CA hierarchy

DVV runs **two parallel G3 roots** since 2021-05-06, one per
algorithm family. Both must be pinned -- a citizen card is
either RSA-keyed (chains to the RSA root) or ECC-keyed
(chains to the ECC root). They are not interchangeable.

### Root certificates

| Root                          | Algorithm     | Valid from | Valid until | Self-signed |
|-------------------------------|---------------|------------|-------------|-------------|
| `DVV Gov. Root CA - G3 RSA`   | 4096-bit RSA  | 2021-05-06 | 2042-05-05  | yes         |
| `DVV Gov. Root CA - G3 ECC`   | 384-bit ECDSA | 2021-05-06 | 2042-05-05  | yes         |

Both root certs are X.509 v3, `subject == issuer`, with
`keyUsage = keyCertSign + cRLSign` and `basicConstraints
cA=TRUE (critical)`.

### Root certificate SHA-256 fingerprints (S2 §8.2)

```
DVV Gov. Root CA - G3 RSA
  D3ED3FC40AD26B52E001E1E18F4B9449529DEB75A81D5EB680D7B62DB23BA96D

DVV Gov. Root CA - G3 ECC
  5546A52504FBA74F61FFD4890067529ADE3B9C9D07E502592831CCDA9B369FD3
```

These are the pinned trust anchors in
`crates/refineid-client/src/trust_roots.rs::PINNED_ROOT_SHA256`.
Both are pinned. A card whose on-card root cert (EF.4334)
hashes to neither value is refused by the activation flow's
trust gate.

### Intermediate sub-CAs (citizen scope)

All in-scope citizen FINEID cards chain to one of two
intermediates, depending on key family:

| Sub-CA CN                                    | Family | Parent root           | Key length |
|----------------------------------------------|--------|-----------------------|------------|
| `DVV Citizen Certificates - G4R`             | RSA    | `DVV Gov. Root CA - G3 RSA` | 4096 bit   |
| `DVV Citizen Certificates - G4E`             | ECC    | `DVV Gov. Root CA - G3 ECC` | 384 bit EC |

S2 §5 mandates `pathLenConstraint = 0` on every
intermediate, so end-entity issuance is the only legal next
hop -- no sub-sub-CAs.

Other intermediates listed in S2 §5 (`DVV Service
Certificates - G5R`/`G5E`, `DVV Organisational Certificates -
G4R`/`G4E`, social welfare / time stamp / temporary sub-CAs)
are not in refineid's `card activate` scope; see
[`fineid-card-models.md`](fineid-card-models.md).

### Test hierarchy

DVV publishes a parallel `DVV TEST Root CA - G3 RSA` /
`DVV TEST Root CA - G3 ECC` hierarchy (S2 §3, second tree)
for software developer use. refineid does not pin the test
roots -- production-only pin set keeps test certs out of
trust decisions automatically.

## Certificate content essentials

### Signature and key algorithms (S2 §6.2.2, §6.3.7, §7.2.2)

| Purpose                | OID                    | Symbol                  |
|------------------------|------------------------|-------------------------|
| RSA cert signature     | 1.2.840.113549.1.1.13  | `sha512WithRSAEncryption` |
| ECC cert signature     | 1.2.840.10045.4.3.3    | `ecdsa-with-SHA384`     |
| RSA public key         | 1.2.840.113549.1.1.1   | `rsaEncryption`         |
| ECC public key         | 1.2.840.10045.2.1      | `ecPublicKey`           |
| ECC curve (citizen)    | 1.2.840.10045.3.1.7    | `secp256r1`             |
| ECC curve (citizen / non-citizen) | 1.3.132.0.34 | `secp384r1`             |

Citizen ECC end-entity certs use `secp256r1` *or*
`secp384r1`; everything outside citizen scope (organizational,
service, social welfare, time stamp, professional) uses
`secp384r1` only.

### KeyUsage bit patterns (S2 §6.3.8.3) -- the cert purpose split

KeyUsage is a **critical** extension. Citizen cards always
carry two end-entity certs with distinct purposes; the spec
spells out exactly which bits each one sets.

| Cert purpose                                   | KeyUsage bits set                                           | Encoded byte |
|------------------------------------------------|-------------------------------------------------------------|--------------|
| Citizen authentication & encryption            | `digitalSignature` + `keyEncipherment` + `dataEncipherment` | `0xB0`       |
| Citizen non-repudiation (qualified signature)  | `nonRepudiation`                                            | `0x40`       |

The spec says, verbatim, of `nonRepudiation`:
> "This bit shall not be combined with other bits."

This is normative for the `AuthCert` vs `NonRepCert` split
in [`typing-discipline.md`](typing-discipline.md): the type
system enforces what the spec already requires by KeyUsage
bit pattern. Code that picks "which key handles this
operation" should dispatch on the typed purpose, not parse
the KeyUsage bits at the call site.

`nonRepudiation` private keys are generated **inside the
smart-card chip** and never leave (S2 §2). There are no
copies anywhere.

Other end-entity profiles set different bit patterns:

| Profile                          | KeyUsage                                       | Byte   |
|----------------------------------|------------------------------------------------|--------|
| System signature                 | `digitalSignature` + `nonRepudiation`          | `0xC0` |
| Seal certificate (eIDAS QC seal) | `digitalSignature` + `nonRepudiation`          | `0xC0` |
| Service for email                | `digitalSignature` + `keyEncipherment` + `dataEncipherment` | `0xB0` |

### Subject DN attributes (S2 §6.3.6, §8.1)

The attribute OIDs refineid's parser must recognise:

| Attribute              | OID            | ASN.1 type        | Source         |
|------------------------|----------------|-------------------|----------------|
| commonName             | `2.5.4.3`      | UTF8String        | id-at 3        |
| surname                | `2.5.4.4`      | UTF8String        | id-at 4        |
| givenName              | `2.5.4.42`     | UTF8String        | id-at 42       |
| serialNumber           | `2.5.4.5`      | PrintableString   | id-at 5 (FINUID: 8 digits + checksum) |
| title                  | `2.5.4.12`     | UTF8String        | id-at 12       |
| pseudonym              | `2.5.4.65`     | PrintableString   | id-at 65 (Doctor ID in SWHC certs) |
| organizationalUnitName | `2.5.4.11`     | UTF8String        | id-at 11       |
| organizationName       | `2.5.4.10`     | UTF8String        | id-at 10       |
| stateOrProvinceName    | `2.5.4.8`      | UTF8String        | id-at 8        |
| localityName           | `2.5.4.7`      | UTF8String        | id-at 7        |
| countryName            | `2.5.4.6`      | PrintableString   | id-at 6 (`FI`) |

For citizen certs the **mandatory** attribute set is:
`commonName, surname, givenName, serialNumber, countryName`.

The commonName value is a *combination* of surname +
givenName + serialNumber (e.g. `Tormanen Paivi 12345678N`).

#### DirectoryString encoding rule (S2 §6.3.4)

> "The DirectoryString shall be coded as UTF8String with
> ISO 8859-1 characters. In FINEID context, teletexString,
> universalString and bmpString types are not used."

The parser may reject an end-entity cert that uses
`teletexString` / `universalString` / `bmpString` for any
DirectoryString-typed attribute. PrintableString is fine for
`countryName` and `serialNumber` (those aren't
DirectoryString).

### Extension presence and criticality (S2 §6.3.8)

| Extension                | Presence  | Critical?     | Notes                                                                      |
|--------------------------|-----------|---------------|----------------------------------------------------------------------------|
| `authorityKeyIdentifier` | mandatory | non-critical  | keyIdentifier element only; no authorityCertIssuer / authorityCertSerialNumber. |
| `subjectKeyIdentifier`   | mandatory | non-critical  | Required in all CA certs AND all conforming end-entity certs.              |
| `keyUsage`               | mandatory | **CRITICAL**  | Bit pattern from the table above.                                          |
| `certificatePolicies`    | mandatory | non-critical  | One or more policy OIDs.                                                   |
| `subjectAltName`         | optional  | non-critical  | rfc822Name for email; UPN OtherName for MS smart-card logon.               |
| `basicConstraints`       | mandatory | **CRITICAL**  | `cA` boolean; `pathLenConstraint = 0` on intermediates.                    |
| `cRLDistributionPoints`  | mandatory | non-critical  | HTTP URI; LDAP CDP deprecated.                                             |
| `extKeyUsage`            | optional  | non-critical  | "Included for compatibility only"; usage "discouraged" per S2 §6.3.8.7.    |
| `authorityInfoAccess`    | mandatory | non-critical  | `id-ad-caIssuers` + `id-ad-ocsp`.                                          |
| `qcStatements`           | mandatory (QC) | non-critical | Present in non-repudiation qualified certs and seal certs.            |

RFC 5280 mandate: a critical extension that the verifier
does not recognise MUST cause the cert to be rejected.
Non-critical unrecognised extensions MAY be ignored.

### UPN OtherName (S2 §6.3.8.5)

Microsoft smart-card logon requires the auth cert's SAN to
carry a `Principal Name` OtherName:

```
type-id: 1.3.6.1.4.1.311.20.2.3   (Microsoft UPN)
value:   ASN.1-encoded UTF8 string, e.g. "1234567890@example.fi"
```

S2 explicitly notes: **non-repudiation certs do NOT contain
a Principal Name field.**

### Smart Card Logon EKU

```
1.3.6.1.4.1.311.20.2 -- Smart Card Logon
```

(Microsoft proprietary, listed in S2 §6.3.8.7 for
compatibility.)

### ETSI QCStatements (S2 §6.3.9.2)

| OID                       | Statement                |
|---------------------------|--------------------------|
| `0.4.0.1862.1.1`          | `QcCompliance`           |
| `0.4.0.1862.1.6.1`        | `QcType: eSign`          |
| `0.4.0.1862.1.6.2`        | `QcType: eSeal`          |
| `0.4.0.1862.1.6.3`        | `QcType: web`            |
| `0.4.0.1862.1.4`          | `QcSSCD`                 |

Present in citizen non-repudiation certs, eSeal certs, and
qualified web/server certs.

## Validity-date encoding (S2 §6.3.5, §7.2.4, §7.2.5)

> "CAs conforming to this profile MUST always encode
> certificate validity dates through the year 2049 as
> UTCTime; certificate validity dates in 2050 or later MUST
> be encoded as GeneralizedTime."

Same rule applies to CRL `thisUpdate` / `nextUpdate`. The
parser must accept both forms and project them onto the
typed `Asn1Time` representation.

### Citizen end-entity validity window

S2 §8.1 (summary tables): citizen personal certificates are
issued with **maximum 5-year validity**. This is the math
behind refineid's card-model in-scope set
([`fineid-card-models.md`](fineid-card-models.md)): a model
whose latest production date + 5 years already passed is
out of scope by construction.

## Path validation and revocation

### Path validation (S2 §2)

> "When handling certificates and/or digitally signed data,
> software products and network services SHALL perform Basic
> Path Validation as described in RFC 5280, §6.1."

This is the spec authority for the cert state lattice
typestate planned in
[`doc/typing-discipline.md`](typing-discipline.md):

```
RawDer
  -> ParsedCertificate          -- syntax check + signature alg recognised
  -> PathValidatedCertificate   -- RFC 5280 §6.1 basic path validation
  -> RevocationCheckedCertificate -- CRL or OCSP, against valid issuer
  -> PurposeBoundTrustedCertificate<Purpose>  -- KeyUsage + EKU + policy bound to a typed purpose
```

Each transition is a constructor that consumes the
predecessor; bypassing a stage is a compile error.

### CRL / OCSP / ARL discipline (S2 §2)

S2 mandates an active revocation check on every trust
decision:

> "Service providers and software products MUST always check
> validity of certificate against valid CRL or OCSP service
> before trusting a single certificate."

> "Service providers and software products SHALL always
> check validity of intermediate CA certificate against
> valid ARL, CRL or OCSP service before trusting an
> intermediate CA certificate."

CRL URIs are HTTP only (LDAP CDP is deprecated as of S2 v5.2):

```
http://proxy.fineid.fi/crl/dvvcqc4rc.crl   (G4R citizen)
http://proxy.fineid.fi/crl/dvvcqc4ec.crl   (G4E citizen)
http://proxy.fineid.fi/crl/dvvroot3rc.crl  (G3 RSA root)
http://proxy.fineid.fi/crl/dvvroot3ec.crl  (G3 ECC root)
```

OCSP URIs follow the `authorityInfoAccess` extension on
each cert; published per sub-CA in S2 §8.4. refineid does
not hardcode them -- it reads them from the cert at runtime.

#### CRL semantics rules from the spec

- A revoked cert stays on the CRL until the cert's own
  natural expiry; **expiration is not a CRL reason**
  (S2 §2). Revoked-then-expired entries do not silently
  disappear.
- `revocationDate` records when DVV processed the revocation
  request.
- `invalidityDate` (CRL entry extension, non-critical)
  records when the private key is believed to have been
  compromised. May be earlier than `revocationDate`.
  Signatures made before `invalidityDate` are NOT
  retroactively invalidated by inclusion on the CRL --
  S2 §2: "digital signatures and other transactions occurred
  BEFORE certificate revocation, are still valid despite of
  certificate been revoked."
- A revoked intermediate invalidates everything signed
  under it from the revocation moment forward (S2 §2).
- `CRLNumber` is monotonically increasing per (issuer,
  scope). A verifier seeing a lower-numbered CRL after a
  higher-numbered one has been seen MUST refuse the lower
  one as out-of-date.
- CRL entry `reasonCode` values used by DVV:
  `unspecified, keyCompromise, cACompromise,
  affiliationChanged, superseded, cessationOfOperation,
  certificateHold, removeFromCRL, privilegeWithdrawn,
  aACompromise`. Note `removeFromCRL` (8) is a delta-CRL
  signal; refineid currently uses base CRLs only.

## Anti-patterns the spec forbids

Things the refineid code review should reject on sight,
each with its S2 citation:

- A path-validation routine that accepts a cert because the
  chain *parsed*, without checking signatures. S2 §2 + RFC
  5280 §6.1.
- Accepting a cert without a revocation check (CRL or OCSP).
  S2 §2.
- Trusting an intermediate CA cert without an ARL/CRL/OCSP
  check on it specifically (separate from the end-entity).
  S2 §2.
- Conflating the auth/encryption key and the non-repudiation
  key. They have different KeyUsage bit patterns, different
  certs, different on-card slots, and different operator
  consent semantics. S2 §6.3.8.3.
- Encoding a DirectoryString as `teletexString`,
  `universalString`, or `bmpString` in any FINEID cert
  field. S2 §6.3.4.
- Treating cert *expiry* as a revocation event. CRLs only
  carry revocations of non-expired certs. S2 §2.
- Honoring an LDAP CDP entry. LDAP CDP is deprecated;
  HTTP only. S2 §6.3.8.5.

## References

- [`doc/fineid-card-models.md`](fineid-card-models.md) --
  the card model side: which physical cards we accept and
  why.
- [`doc/typing-discipline.md`](typing-discipline.md) -- the
  cert state lattice this profile binds to.
- [`doc/observability.md`](observability.md) -- the JSON
  Lines wire shape for trust-gate / cert-validation events.
- [`doc/dvv-terminology.md`](dvv-terminology.md) -- DVV
  vocabulary, activation-PIN / PUK terminology.
- FINEID S2 v5.2 PDF (cited above).
- RFC 5280 §6.1 (Basic Path Validation).
- ETSI EN 319 412-5 (QCStatements).
