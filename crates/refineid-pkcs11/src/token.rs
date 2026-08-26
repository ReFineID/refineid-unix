// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! Slot / token / object model over PC/SC.
//!
//! A FINEID token exposes exactly three objects for Firefox / NSS
//! client-cert TLS: the authentication certificate
//! ([`ObjectKind::Certificate`], handle [`OBJ_CERTIFICATE`]), its
//! public key ([`ObjectKind::PublicKey`], handle [`OBJ_PUBLIC_KEY`],
//! for consumers such as p11tool / libp11 that enumerate public
//! keys), and its auth private key ([`ObjectKind::PrivateKey`],
//! handle [`OBJ_PRIVATE_KEY`]). All carry the same
//! [`crate::ck::CKA_ID`] so NSS pairs them.
//!
//! The card is opened only for the moment it takes to read the
//! certificate or run a signature, then dropped -- this module never
//! holds a PC/SC handle across PKCS#11 calls, so the desktop CLI
//! shares the reader.

use std::sync::{Arc, Mutex};

#[cfg(feature = "pin-change")]
use refineid_lib_core::auth::ChangePinOutcome;
use refineid_lib_core::auth::{PinOps as _, PinSlot, PinStatus, VerifyOutcome};
use refineid_lib_core::backend::{ReaderAccessCap, ReaderBackend as _, ReaderId};
use refineid_lib_core::crypto::container::{EcdsaP384, RsaPkcs1Sha256, Signature};
use refineid_lib_core::crypto::digest::{Sha1, Sha224, Sha256, Sha384, Sha512};
use refineid_lib_core::identity::{TokenSerial, derive_printed_serial, render_token_serial};
use refineid_lib_core::pin::PinBytes;
use refineid_lib_core::pin_cache::PinSafetyCache;
use refineid_lib_core::pin_retry_risk::{PinRetryRisk, pin1_status_permits_reusable_cache};
use refineid_lib_core::pkcs15::{CertSlot, Pkcs15Ops as _};
use refineid_lib_core::x509::{EcCurve, OwnedCert, PublicKeyAlgorithm, extract_rsa_public_key};
use refineid_lib_pcsc::PcscBackend;

#[cfg(feature = "pin-change")]
use crate::ck::CKR_PIN_LEN_RANGE;
use crate::ck::{
    CK_CERTIFICATE_CATEGORY_AUTHORITY, CK_CERTIFICATE_CATEGORY_TOKEN_USER, CK_FALSE, CK_TRUE,
    CKA_ALWAYS_AUTHENTICATE, CKA_ALWAYS_SENSITIVE, CKA_CERTIFICATE_CATEGORY, CKA_CERTIFICATE_TYPE,
    CKA_CLASS, CKA_DERIVE, CKA_EC_PARAMS, CKA_EC_POINT, CKA_ENCRYPT, CKA_EXTRACTABLE, CKA_ID,
    CKA_ISSUER, CKA_KEY_TYPE, CKA_LABEL, CKA_LOCAL, CKA_MODULUS, CKA_MODULUS_BITS,
    CKA_NEVER_EXTRACTABLE, CKA_PRIVATE, CKA_PUBLIC_EXPONENT, CKA_SENSITIVE, CKA_SERIAL_NUMBER,
    CKA_SIGN, CKA_SIGN_RECOVER, CKA_SUBJECT, CKA_TOKEN, CKA_TRUSTED, CKA_UNWRAP, CKA_VALUE,
    CKA_VERIFY, CKA_WRAP, CKC_X_509, CKK_EC, CKK_RSA, CKO_CERTIFICATE, CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CKR_OK,
    CKR_PIN_INCORRECT, CKR_PIN_LOCKED, CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE,
    CKR_USER_NOT_LOGGED_IN, CkAttributeType, CkBbool, CkObjectHandle, CkRv, CkUlong,
};
use crate::sign::{Mechanism, sign_with_card};

/// Object handle for the authentication certificate. Fixed for the
/// process; the session's slot disambiguates which card it belongs
/// to. Non-zero (0 is [`crate::ck::CK_INVALID_HANDLE`]).
pub const OBJ_CERTIFICATE: CkObjectHandle = 1;
/// Object handle for the authentication private key. Fixed for the
/// process; shares [`CKA_ID`] with the certificate so NSS pairs them.
pub const OBJ_PRIVATE_KEY: CkObjectHandle = 2;
/// Object handle for the authentication public key, derived from the
/// certificate SPKI. Shares [`CKA_ID`] with the other two objects.
pub const OBJ_PUBLIC_KEY: CkObjectHandle = 3;
/// Object handles for the embedded DVV intermediate and root CA certificates.
pub const OBJ_CA_CITIZEN_G4E: CkObjectHandle = 4;
pub const OBJ_CA_CITIZEN_G4R: CkObjectHandle = 5;
pub const OBJ_CA_CITIZEN_G3: CkObjectHandle = 6;
pub const OBJ_CA_ORG_G4R: CkObjectHandle = 7;
pub const OBJ_CA_ROOT_ECC: CkObjectHandle = 8;
pub const OBJ_CA_ROOT_RSA: CkObjectHandle = 9;

const DVV_CA_CITIZEN_G4E_DER: &[u8] =
    include_bytes!("../ca-certs/fineid-intermediate-01-citizen-g4e.der");
const DVV_CA_CITIZEN_G4R_DER: &[u8] =
    include_bytes!("../ca-certs/fineid-intermediate-02-citizen-g4r.der");
const DVV_CA_CITIZEN_G3_DER: &[u8] =
    include_bytes!("../ca-certs/fineid-intermediate-00-citizen-g3.der");
const DVV_CA_ORG_G4R_DER: &[u8] =
    include_bytes!("../ca-certs/fineid-intermediate-03-organisation-g4r.der");
const DVV_CA_ROOT_ECC_DER: &[u8] = include_bytes!("../ca-certs/dvv-gov-root-ca-g3-ecc.der");
const DVV_CA_ROOT_RSA_DER: &[u8] = include_bytes!("../ca-certs/dvv-gov-root-ca-g3-rsa.der");

/// Fixed human-readable token / object label used when the card's
/// certificate carries no usable common name. NSS shows it in the
/// certificate-selection UI.
const DEFAULT_LABEL: &str = "FINEID";

/// ASN.1 DER tag for `INTEGER` (X.690 s8.3; universal 2). Used to
/// rebuild the [`CKA_SERIAL_NUMBER`] TLV from the parsed value bytes.
const DER_TAG_INTEGER: u8 = 0x02;
/// ASN.1 DER tag for `OCTET STRING` (X.690 s8.7; universal 4). Wraps
/// the SEC1 point for [`CKA_EC_POINT`].
const DER_TAG_OCTET_STRING: u8 = 0x04;
/// X.690 s8.1.3.5 long-form length marker: a length octet with bit 8
/// set introduces long-form length. Values below it are short-form
/// (the length is the octet itself).
const DER_SHORT_FORM_LIMIT: usize = 0x80;
/// X.690 s8.1.3.5 long-form prefix for a length encoded in one
/// subsequent octet (`0x80 | 1`).
const DER_LONG_FORM_ONE_OCTET: u8 = 0x81;
/// X.690 s8.1.3.5 long-form prefix for a length encoded in two
/// subsequent octets (`0x80 | 2`).
const DER_LONG_FORM_TWO_OCTETS: u8 = 0x82;

/// ASN.1 `DigestInfo` prefix for SHA-256 (RFC 8017 s9.2 note 1):
/// `SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.2.1, NULL },
/// OCTET STRING (32) }` minus the hash bytes. `CKM_RSA_PKCS`
/// callers pass `DigestInfo || hash` -- the same input shape the
/// sign path takes to the card.
const DIGEST_INFO_SHA256_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// DER encoding of the ANSI X9.62 named-curve OID for secp384r1 /
/// NIST P-384 (`1.3.132.0.34`): `OBJECT IDENTIFIER` TLV. This is the
/// value NSS expects for [`CKA_EC_PARAMS`] on the ECC FINEID card
/// (RFC 5480 s2.1.1; SEC2 v2 s2.6.1).
const EC_PARAMS_SECP384R1: [u8; 7] = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];

/// Which of the token's three objects an attribute query refers to.
///
/// HARD LIMIT: never add a `CKO_PROFILE` object (or any object
/// answering `CKA_PROFILE_ID` = `CKP_AUTHENTICATION_TOKEN`). NSS
/// reads that profile as permission to log in proactively and
/// prompts for PIN1 at Firefox startup, before the user asked for
/// anything -- a blocker-severity regression when it was tried
/// (eager PIN1 from `CKP_AUTHENTICATION_TOKEN`). PIN prompts must
/// appear only when a TLS handshake actually needs the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    /// The X.509 authentication certificate ([`CKO_CERTIFICATE`]).
    Certificate,
    /// The authentication public key ([`CKO_PUBLIC_KEY`]), from the
    /// certificate SPKI.
    PublicKey,
    /// The authentication private key ([`CKO_PRIVATE_KEY`]).
    PrivateKey,
    /// Embedded CA: DVV Citizen Certificates - G4E
    CaCitizenG4e,
    /// Embedded CA: DVV Citizen Certificates - G4R
    CaCitizenG4r,
    /// Embedded CA: VRK Gov. CA for Citizen Certificates - G3
    CaCitizenG3,
    /// Embedded CA: DVV Organisational Certificates - G4R
    CaOrgG4r,
    /// Embedded CA: DVV Gov. Root CA - G3 ECC
    CaRootEcc,
    /// Embedded CA: DVV Gov. Root CA - G3 RSA
    CaRootRsa,
}

impl ObjectKind {
    /// Resolve a fixed object handle to its kind, or `None` when the
    /// handle names no object this token exposes.
    #[must_use]
    pub(crate) const fn from_handle(handle: CkObjectHandle) -> Option<Self> {
        match handle {
            OBJ_CERTIFICATE => Some(Self::Certificate),
            OBJ_PRIVATE_KEY => Some(Self::PrivateKey),
            OBJ_PUBLIC_KEY => Some(Self::PublicKey),
            OBJ_CA_CITIZEN_G4E => Some(Self::CaCitizenG4e),
            OBJ_CA_CITIZEN_G4R => Some(Self::CaCitizenG4r),
            OBJ_CA_CITIZEN_G3 => Some(Self::CaCitizenG3),
            OBJ_CA_ORG_G4R => Some(Self::CaOrgG4r),
            OBJ_CA_ROOT_ECC => Some(Self::CaRootEcc),
            OBJ_CA_ROOT_RSA => Some(Self::CaRootRsa),
            _ => None,
        }
    }

    /// The fixed object handle for this kind.
    #[must_use]
    pub(crate) const fn handle(self) -> CkObjectHandle {
        match self {
            Self::Certificate => OBJ_CERTIFICATE,
            Self::PrivateKey => OBJ_PRIVATE_KEY,
            Self::PublicKey => OBJ_PUBLIC_KEY,
            Self::CaCitizenG4e => OBJ_CA_CITIZEN_G4E,
            Self::CaCitizenG4r => OBJ_CA_CITIZEN_G4R,
            Self::CaCitizenG3 => OBJ_CA_CITIZEN_G3,
            Self::CaOrgG4r => OBJ_CA_ORG_G4R,
            Self::CaRootEcc => OBJ_CA_ROOT_ECC,
            Self::CaRootRsa => OBJ_CA_ROOT_RSA,
        }
    }

    /// All object kinds exposed by the token.
    pub(crate) const ALL: [Self; 9] = [
        Self::Certificate,
        Self::PublicKey,
        Self::PrivateKey,
        Self::CaCitizenG4e,
        Self::CaCitizenG4r,
        Self::CaCitizenG3,
        Self::CaOrgG4r,
        Self::CaRootEcc,
        Self::CaRootRsa,
    ];
}

/// Result of an attribute lookup: either a concrete DER / scalar
/// value, or a marker that the attribute exists but is sensitive
/// (the private key's [`CKA_VALUE`]) and must be reported as
/// unavailable rather than disclosed.
#[derive(Debug, Clone)]
pub enum AttrValue {
    /// The attribute's encoded bytes (a scalar in native-endian
    /// [`CkUlong`] form, a single [`CkBbool`] octet, or DER).
    Available(Vec<u8>),
    /// The attribute exists but its value is sensitive and withheld.
    Sensitive,
}

/// The two token objects, parsed once from the card's authentication
/// certificate and cached per slot while the same card stays present.
#[derive(Debug, Clone)]
pub struct TokenObjects {
    /// Key type: [`CKK_RSA`] or [`CKK_EC`], from the certificate SPKI.
    key_type: CkUlong,
    /// Sign mechanism this card profile uses, derived from
    /// [`Self::key_type`].
    mechanism: Mechanism,
    /// UTF-8 label bytes for [`CKA_LABEL`] (common name, else
    /// [`DEFAULT_LABEL`]).
    label: Vec<u8>,
    /// [`CKA_ID`]: SHA-1 of the SPKI DER, shared by cert and key.
    id: Vec<u8>,
    /// [`CKA_VALUE`] for the certificate object: the raw cert DER.
    cert_der: Vec<u8>,
    /// [`CKA_ISSUER`]: the issuer `Name` SEQUENCE DER.
    issuer_der: Vec<u8>,
    /// [`CKA_SUBJECT`]: the subject `Name` SEQUENCE DER.
    subject_der: Vec<u8>,
    /// [`CKA_SERIAL_NUMBER`]: the serial rebuilt as a DER INTEGER.
    serial_der: Vec<u8>,
    /// Chip serial from PKCS#15 EF.TokenInfo: the plastic-printed
    /// card identifier when [`derive_printed_serial`] recognises
    /// the chip generation (the form a citizen can check against
    /// the card body), else the full rendered serial via
    /// [`render_token_serial`]; empty when the card reports none.
    /// Reported in `CK_TOKEN_INFO.serialNumber`.
    token_serial: String,
    /// [`CKA_MODULUS`] for an RSA key: big-endian modulus bytes.
    modulus: Option<Vec<u8>>,
    /// [`CKA_MODULUS_BITS`] for an RSA key.
    modulus_bits: Option<CkUlong>,
    /// [`CKA_PUBLIC_EXPONENT`] for an RSA key: big-endian bytes.
    public_exponent: Option<Vec<u8>>,
    /// [`CKA_EC_PARAMS`] for an EC key: the named-curve OID DER.
    ec_params: Option<Vec<u8>>,
    /// [`CKA_EC_POINT`] for an EC key: DER OCTET STRING of the SEC1
    /// point.
    ec_point: Option<Vec<u8>>,
    /// Embedded DVV intermediate and root CA certificate objects.
    ca_certs: Vec<CaCertData>,
}

/// Parsed data for an embedded CA certificate object.
#[derive(Debug, Clone)]
struct CaCertData {
    label: Vec<u8>,
    id: Vec<u8>,
    cert_der: Vec<u8>,
    issuer_der: Vec<u8>,
    subject_der: Vec<u8>,
    serial_der: Vec<u8>,
}

fn load_ca_cert(cert_der: &'static [u8]) -> Result<CaCertData, CkRv> {
    let parsed = OwnedCert::from_der(cert_der).map_err(|_err| CKR_DEVICE_ERROR)?;
    let view = parsed.view();
    let id = Sha1::of(view.spki.as_der()).as_bytes().to_vec();
    let label = view.subject.common_name().map_or_else(
        || b"CA Certificate".to_vec(),
        |cn| cn.as_str().as_bytes().to_vec(),
    );
    Ok(CaCertData {
        label,
        id,
        cert_der: cert_der.to_vec(),
        issuer_der: view.issuer.as_der().to_vec(),
        subject_der: view.subject.as_der().to_vec(),
        serial_der: der_integer(view.serial_der),
    })
}

/// Encode a [`CkUlong`] attribute value in native-endian form, the
/// in-memory layout NSS uses for `CK_ULONG` templates and result
/// buffers.
#[expect(
    clippy::host_endian_bytes,
    reason = "PKCS#11 CK_ULONG attribute values live in caller memory as a native-endian machine word; NSS reads them back as CK_ULONG, so the on-wire bytes must match the host byte order, not a fixed endianness"
)]
fn ulong_attr(value: CkUlong) -> Vec<u8> {
    value.to_ne_bytes().to_vec()
}

/// Encode a [`CkBbool`] attribute value ([`CK_TRUE`] / [`CK_FALSE`]).
fn bool_attr(value: CkBbool) -> Vec<u8> {
    vec![value]
}

/// Append a DER length for `len` to `out` (X.690 s8.1.3). Handles the
/// short form and one/two-octet long forms; every value this module
/// encodes is far below 65536 bytes.
fn push_der_len(out: &mut Vec<u8>, len: usize) {
    if len < DER_SHORT_FORM_LIMIT {
        if let Ok(short) = u8::try_from(len) {
            out.push(short);
        }
    } else if let Ok(one) = u8::try_from(len) {
        out.push(DER_LONG_FORM_ONE_OCTET);
        out.push(one);
    } else {
        let high = u8::try_from(len.checked_shr(8).unwrap_or(0) & 0xFF).unwrap_or(0);
        let low = u8::try_from(len & 0xFF).unwrap_or(0);
        out.push(DER_LONG_FORM_TWO_OCTETS);
        out.push(high);
        out.push(low);
    }
}

/// Rebuild a DER `INTEGER` TLV from the certificate's serial value
/// bytes (`Certificate::serial_der` yields the INTEGER contents only,
/// no tag/length). NSS matches [`CKA_SERIAL_NUMBER`] against the full
/// TLV.
fn der_integer(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len().saturating_add(2));
    out.push(DER_TAG_INTEGER);
    push_der_len(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

/// Treat an empty DER span as an absent attribute. A parse that
/// produced no bytes must surface as
/// [`crate::ck::CKR_ATTRIBUTE_TYPE_INVALID`], not as a zero-length
/// DN / serial value that NSS would treat as real data.
fn non_empty(bytes: Vec<u8>) -> Option<Vec<u8>> {
    if bytes.is_empty() { None } else { Some(bytes) }
}

/// Wrap raw bytes in a DER `OCTET STRING` TLV (X.690 s8.7). Used to
/// form [`CKA_EC_POINT`] from the SEC1 point.
fn der_octet_string(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len().saturating_add(2));
    out.push(DER_TAG_OCTET_STRING);
    push_der_len(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

impl TokenObjects {
    /// Parse the two objects from a certificate DER blob.
    ///
    /// # Errors
    /// [`CKR_DEVICE_ERROR`] if the DER does not parse or the key
    /// algorithm is neither RSA nor secp384r1 EC (the only two FINEID
    /// auth profiles).
    pub(crate) fn from_cert_der(cert_der: Vec<u8>) -> Result<Self, CkRv> {
        let parsed = OwnedCert::from_der(&cert_der).map_err(|_parse_err| CKR_DEVICE_ERROR)?;
        let view = parsed.view();
        let id = Sha1::of(view.spki.as_der()).as_bytes().to_vec();
        let label = view.subject.common_name().map_or_else(
            || DEFAULT_LABEL.as_bytes().to_vec(),
            |cn| cn.as_str().as_bytes().to_vec(),
        );
        let issuer_der = view.issuer.as_der().to_vec();
        let subject_der = view.subject.as_der().to_vec();
        let serial_der = der_integer(view.serial_der);
        let mut token = Self {
            key_type: CKK_RSA,
            mechanism: Mechanism::RsaPkcs,
            label,
            id,
            cert_der,
            issuer_der,
            subject_der,
            serial_der,
            token_serial: String::new(),
            modulus: None,
            modulus_bits: None,
            public_exponent: None,
            ec_params: None,
            ec_point: None,
            ca_certs: vec![
                load_ca_cert(DVV_CA_CITIZEN_G4E_DER)?,
                load_ca_cert(DVV_CA_CITIZEN_G4R_DER)?,
                load_ca_cert(DVV_CA_CITIZEN_G3_DER)?,
                load_ca_cert(DVV_CA_ORG_G4R_DER)?,
                load_ca_cert(DVV_CA_ROOT_ECC_DER)?,
                load_ca_cert(DVV_CA_ROOT_RSA_DER)?,
            ],
        };
        token.fill_key_material(&view.spki)?;
        Ok(token)
    }

    /// Populate the key-type-specific attribute cache from the SPKI.
    ///
    /// # Errors
    /// [`CKR_DEVICE_ERROR`] for any algorithm outside RSA / secp384r1
    /// EC.
    fn fill_key_material(
        &mut self,
        spki: &refineid_lib_core::x509::SpkiDer<'_>,
    ) -> Result<(), CkRv> {
        match spki.algorithm() {
            PublicKeyAlgorithm::Rsa { modulus_bits } => {
                let public = extract_rsa_public_key(spki.as_der()).ok_or(CKR_DEVICE_ERROR)?;
                self.key_type = CKK_RSA;
                self.mechanism = Mechanism::RsaPkcs;
                self.modulus = Some(public.modulus.as_bytes().to_vec());
                self.modulus_bits = CkUlong::try_from(modulus_bits).ok();
                self.public_exponent = Some(public.exponent.as_bytes().to_vec());
                Ok(())
            }
            PublicKeyAlgorithm::Ec(EcCurve::Secp384r1) => {
                let point = spki.ec_public_key_point().ok_or(CKR_DEVICE_ERROR)?;
                self.key_type = CKK_EC;
                self.mechanism = Mechanism::Ecdsa;
                self.ec_params = Some(EC_PARAMS_SECP384R1.to_vec());
                self.ec_point = Some(der_octet_string(point.as_bytes()));
                Ok(())
            }
            PublicKeyAlgorithm::Ec(_)
            | PublicKeyAlgorithm::EcExplicit { .. }
            | PublicKeyAlgorithm::Other => Err(CKR_DEVICE_ERROR),
        }
    }

    /// The sign mechanism for this card profile.
    #[must_use]
    pub(crate) const fn mechanism(&self) -> Mechanism {
        self.mechanism
    }

    /// The rendered chip serial from EF.TokenInfo; empty when the
    /// card did not report one.
    #[must_use]
    pub(crate) fn token_serial(&self) -> &str {
        &self.token_serial
    }

    /// Look up one attribute of one object.
    ///
    /// Returns `None` when the attribute type does not apply to the
    /// object (the caller maps that to
    /// [`crate::ck::CKR_ATTRIBUTE_TYPE_INVALID`]); returns
    /// [`AttrValue::Sensitive`] for the private key's [`CKA_VALUE`].
    #[must_use]
    pub(crate) fn attribute(&self, kind: ObjectKind, attr: CkAttributeType) -> Option<AttrValue> {
        match kind {
            ObjectKind::Certificate => self.certificate_attribute(attr),
            ObjectKind::PublicKey => self.public_key_attribute(attr),
            ObjectKind::PrivateKey => self.private_key_attribute(attr),
            ObjectKind::CaCitizenG4e => self.ca_attribute(0, attr),
            ObjectKind::CaCitizenG4r => self.ca_attribute(1, attr),
            ObjectKind::CaCitizenG3 => self.ca_attribute(2, attr),
            ObjectKind::CaOrgG4r => self.ca_attribute(3, attr),
            ObjectKind::CaRootEcc => self.ca_attribute(4, attr),
            ObjectKind::CaRootRsa => self.ca_attribute(5, attr),
        }
    }

    /// Attribute lookup for an embedded CA certificate object.
    fn ca_attribute(&self, index: usize, attr: CkAttributeType) -> Option<AttrValue> {
        let ca = self.ca_certs.get(index)?;
        let bytes = match attr {
            CKA_CLASS => ulong_attr(CKO_CERTIFICATE),
            CKA_CERTIFICATE_TYPE => ulong_attr(CKC_X_509),
            CKA_CERTIFICATE_CATEGORY => ulong_attr(CK_CERTIFICATE_CATEGORY_AUTHORITY),
            CKA_TOKEN => bool_attr(CK_TRUE),
            CKA_PRIVATE => bool_attr(CK_FALSE),
            CKA_TRUSTED => bool_attr(CK_TRUE),
            CKA_LABEL => ca.label.clone(),
            CKA_ID => ca.id.clone(),
            CKA_VALUE => ca.cert_der.clone(),
            CKA_ISSUER => non_empty(ca.issuer_der.clone())?,
            CKA_SUBJECT => non_empty(ca.subject_der.clone())?,
            CKA_SERIAL_NUMBER => non_empty(ca.serial_der.clone())?,
            _ => return None,
        };
        Some(AttrValue::Available(bytes))
    }

    /// Attribute lookup for the certificate object.
    ///
    /// [`CKA_TRUSTED`] and [`CKA_LOCAL`] are answered `CK_FALSE`
    /// rather than left absent: both are honest (an end-entity
    /// credential is not a trust anchor; the certificate was
    /// personalised by DVV, not generated through this module) and a
    /// concrete answer keeps `pkcs11-tool --list-objects` free of
    /// attribute-read failure noise.
    fn certificate_attribute(&self, attr: CkAttributeType) -> Option<AttrValue> {
        let bytes = match attr {
            CKA_CLASS => ulong_attr(CKO_CERTIFICATE),
            CKA_CERTIFICATE_TYPE => ulong_attr(CKC_X_509),
            CKA_CERTIFICATE_CATEGORY => ulong_attr(CK_CERTIFICATE_CATEGORY_TOKEN_USER),
            CKA_KEY_TYPE => ulong_attr(self.key_type),
            CKA_TOKEN => bool_attr(CK_TRUE),
            CKA_PRIVATE | CKA_TRUSTED | CKA_LOCAL => bool_attr(CK_FALSE),
            CKA_LABEL => self.label.clone(),
            CKA_ID => self.id.clone(),
            CKA_VALUE => self.cert_der.clone(),
            CKA_ISSUER => non_empty(self.issuer_der.clone())?,
            CKA_SUBJECT => non_empty(self.subject_der.clone())?,
            CKA_SERIAL_NUMBER => non_empty(self.serial_der.clone())?,
            _ => return None,
        };
        Some(AttrValue::Available(bytes))
    }

    /// Attribute lookup for the public key object, served from the
    /// certificate SPKI. [`CKA_VERIFY`] is `CK_TRUE` (the key's
    /// purpose per the certificate); the other usage flags are
    /// `CK_FALSE` because this token performs none of those
    /// operations.
    fn public_key_attribute(&self, attr: CkAttributeType) -> Option<AttrValue> {
        let bytes = match attr {
            CKA_CLASS => ulong_attr(CKO_PUBLIC_KEY),
            CKA_KEY_TYPE => ulong_attr(self.key_type),
            CKA_TOKEN | CKA_VERIFY => bool_attr(CK_TRUE),
            CKA_PRIVATE | CKA_ENCRYPT | CKA_WRAP | CKA_DERIVE => bool_attr(CK_FALSE),
            CKA_LABEL => self.label.clone(),
            CKA_ID => self.id.clone(),
            CKA_SUBJECT => non_empty(self.subject_der.clone())?,
            CKA_MODULUS => self.modulus.clone()?,
            CKA_MODULUS_BITS => ulong_attr(self.modulus_bits?),
            CKA_PUBLIC_EXPONENT => self.public_exponent.clone()?,
            CKA_EC_PARAMS => self.ec_params.clone()?,
            CKA_EC_POINT => self.ec_point.clone()?,
            _ => return None,
        };
        Some(AttrValue::Available(bytes))
    }

    /// Attribute lookup for the private key object.
    ///
    /// The extractability triple ([`CKA_EXTRACTABLE`] false,
    /// [`CKA_NEVER_EXTRACTABLE`] / [`CKA_ALWAYS_SENSITIVE`] true)
    /// states the FINEID guarantee that the private key never leaves
    /// the card -- it is what a security review greps for, and an
    /// absent attribute never matches a find template asking for
    /// `CKA_EXTRACTABLE = FALSE`.
    fn private_key_attribute(&self, attr: CkAttributeType) -> Option<AttrValue> {
        let bytes = match attr {
            CKA_CLASS => ulong_attr(CKO_PRIVATE_KEY),
            CKA_KEY_TYPE => ulong_attr(self.key_type),
            CKA_TOKEN
            | CKA_PRIVATE
            | CKA_SIGN
            | CKA_SENSITIVE
            | CKA_NEVER_EXTRACTABLE
            | CKA_ALWAYS_SENSITIVE => bool_attr(CK_TRUE),
            CKA_ALWAYS_AUTHENTICATE
            | CKA_EXTRACTABLE
            | CKA_SIGN_RECOVER
            | CKA_UNWRAP
            | CKA_DERIVE => bool_attr(CK_FALSE),
            CKA_LABEL => self.label.clone(),
            CKA_ID => self.id.clone(),
            CKA_SUBJECT => non_empty(self.subject_der.clone())?,
            CKA_VALUE => return Some(AttrValue::Sensitive),
            CKA_MODULUS => self.modulus.clone()?,
            CKA_MODULUS_BITS => ulong_attr(self.modulus_bits?),
            CKA_PUBLIC_EXPONENT => self.public_exponent.clone()?,
            CKA_EC_PARAMS => self.ec_params.clone()?,
            CKA_EC_POINT => self.ec_point.clone()?,
            _ => return None,
        };
        Some(AttrValue::Available(bytes))
    }

    /// Software signature verification against the cached
    /// certificate public key -- pure host-side computation, no
    /// card IO, no PIN. Serves `C_Verify` so `pkcs11-tool
    /// --verify` and libp11-style consumers work without the
    /// caller re-extracting the public key.
    ///
    /// Input shapes mirror the sign path exactly:
    /// `CKM_RSA_PKCS` takes `DigestInfo || SHA-256 hash`;
    /// `CKM_ECDSA` takes a raw digest (SHA-1/224/256/384/512
    /// lengths accepted) with raw `r || s` signatures.
    pub(crate) fn verify_signature(
        &self,
        mechanism: Mechanism,
        data: &[u8],
        signature: &[u8],
    ) -> CkRv {
        if signature.len() != mechanism.signature_len() {
            return CKR_SIGNATURE_LEN_RANGE;
        }
        match mechanism {
            Mechanism::RsaPkcs => self.verify_rsa_pkcs(data, signature),
            Mechanism::Ecdsa => self.verify_ecdsa(data, signature),
        }
    }

    /// `CKM_RSA_PKCS` software verify: strict `DigestInfo`
    /// (SHA-256) input, PKCS#1 v1.5 padding check in lib-core.
    fn verify_rsa_pkcs(&self, data: &[u8], signature: &[u8]) -> CkRv {
        let Some(hash) = data.strip_prefix(&DIGEST_INFO_SHA256_PREFIX) else {
            return CKR_DATA_INVALID;
        };
        let Ok(digest) = <[u8; 32]>::try_from(hash) else {
            return CKR_DATA_INVALID;
        };
        let Ok(parsed) = OwnedCert::from_der(&self.cert_der) else {
            return CKR_DEVICE_ERROR;
        };
        let Some(key) = extract_rsa_public_key(parsed.view().spki.as_der()) else {
            return CKR_DEVICE_ERROR;
        };
        let sig = Signature::<RsaPkcs1Sha256>::new(signature.to_vec());
        match key.verify_pkcs1v15_sha256_digest(&digest, &sig) {
            Ok(()) => CKR_OK,
            Err(_mismatch) => CKR_SIGNATURE_INVALID,
        }
    }

    /// `CKM_ECDSA` software verify: the digest length selects the
    /// hash family (PKCS#11 attaches no hash to `CKM_ECDSA`; the
    /// caller already hashed), the signature is card-native raw
    /// `r || s`.
    fn verify_ecdsa(&self, data: &[u8], signature: &[u8]) -> CkRv {
        let Ok(parsed) = OwnedCert::from_der(&self.cert_der) else {
            return CKR_DEVICE_ERROR;
        };
        let Some(point) = parsed.view().spki.ec_public_key_point() else {
            return CKR_DEVICE_ERROR;
        };
        let sig = Signature::<EcdsaP384>::new(signature.to_vec());
        let outcome = if let Ok(digest) = <[u8; 20]>::try_from(data) {
            point.verify_p384_sha1_raw(sig, Sha1::from_bytes(digest))
        } else if let Ok(digest) = <[u8; 28]>::try_from(data) {
            point.verify_p384_sha224_raw(sig, Sha224::from_bytes(digest))
        } else if let Ok(digest) = <[u8; 32]>::try_from(data) {
            point.verify_p384_sha256_raw(sig, Sha256::from_bytes(digest))
        } else if let Ok(digest) = <[u8; 48]>::try_from(data) {
            point.verify_p384_sha384_raw(sig, Sha384::from_bytes(digest))
        } else if let Ok(digest) = <[u8; 64]>::try_from(data) {
            point.verify_p384_sha512_raw(sig, Sha512::from_bytes(digest))
        } else {
            return CKR_DATA_LEN_RANGE;
        };
        match outcome {
            Ok(()) => CKR_OK,
            Err(_mismatch) => CKR_SIGNATURE_INVALID,
        }
    }

    /// Test whether an object matches every `(type, value)` pair in a
    /// `C_FindObjects` template. A template entry matches only when
    /// the attribute is present, concrete, and byte-equal; a
    /// sensitive or absent attribute never matches.
    #[must_use]
    pub(crate) fn matches(
        &self,
        kind: ObjectKind,
        template: &[(CkAttributeType, Vec<u8>)],
    ) -> bool {
        template
            .iter()
            .all(|(attr, wanted)| match self.attribute(kind, *attr) {
                Some(AttrValue::Available(have)) => have == *wanted,
                _ => false,
            })
    }
}

/// Build the token objects for `reader_name`: open the card once,
/// read EF.TokenInfo (chip serial, card label) and the
/// authentication certificate via the PKCS#15 chain, drop the
/// card, and parse.
///
/// A missing or unreadable EF.TokenInfo is tolerated (empty
/// serial / label); the certificate read is mandatory.
///
/// # Errors
/// [`CKR_DEVICE_ERROR`] if the reader cannot be opened or the
/// certificate cannot be read or parsed.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is used by sibling state module; plain pub would violate the public-surface typing grep"
)]
pub(super) fn build_token_objects(reader_name: &str) -> Result<TokenObjects, CkRv> {
    let backend = PcscBackend;
    let reader = ReaderId::new(reader_name.to_owned());
    let mut card = backend
        .open_session(&reader, ReaderAccessCap::Read)
        .map_err(|_open_err| CKR_DEVICE_ERROR)?;
    let token_info = card.read_token_info().ok();
    let serial = token_info
        .as_ref()
        .and_then(|info| info.serial_number_hex.clone())
        .map(render_token_serial)
        .map(|full| {
            derive_printed_serial(&full).map_or_else(
                || full.as_str().to_owned(),
                |printed| printed.as_str().to_owned(),
            )
        });
    let cert = card
        .read_certificate(CertSlot::Authentication)
        .map_err(|_read_err| CKR_DEVICE_ERROR)?;
    drop(card);
    let mut objects = TokenObjects::from_cert_der(cert.into_bytes())?;
    if let Some(serial) = serial {
        objects.token_serial = serial;
    }
    Ok(objects)
}

/// Probe the live PIN1 retry state without consuming a retry.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is used by sibling api module; plain pub would violate the public-surface typing grep"
)]
pub(super) fn card_pin1_status(reader_name: &str) -> Result<PinStatus, CkRv> {
    let backend = PcscBackend;
    let reader = ReaderId::new(reader_name.to_owned());
    let mut card = backend
        .open_session(&reader, ReaderAccessCap::Read)
        .map_err(|_open_err| CKR_DEVICE_ERROR)?;
    card.select_pkcs15_application()
        .map_err(|_select_err| CKR_DEVICE_ERROR)?;
    card.pin_status(PinSlot::Pin1)
        .map_err(|_status_err| CKR_DEVICE_ERROR)
}

/// Run a signature on the card at `reader_name`.
///
/// Mirrors the proven FINEID chain: open the card, select the
/// PKCS#15 application, VERIFY PIN1 in that application context (the
/// card refuses VERIFY from MF context with `SW=6985`), then run the
/// pre-hashed PSO chain via [`sign_with_card`]. The card is dropped
/// before returning.
///
/// # Errors
/// [`CKR_PIN_INCORRECT`] / [`CKR_PIN_LOCKED`] on PIN failure,
/// [`CKR_DEVICE_ERROR`] on any card / transport failure, or the
/// mechanism-specific data errors from [`sign_with_card`].
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is used by sibling api module; plain pub would violate the public-surface typing grep"
)]
pub(super) fn card_sign(
    reader_name: &str,
    pin_cache: &Arc<Mutex<PinSafetyCache>>,
    mechanism: Mechanism,
    input: &[u8],
) -> Result<Vec<u8>, CkRv> {
    if let Some(hex_id) = reader_name.strip_prefix("rapp:") {
        return remote_card_sign(hex_id, mechanism, input);
    }
    let backend = PcscBackend;
    let reader = ReaderId::new(reader_name.to_owned());
    // PinSequence: the whole SELECT -> probe -> VERIFY -> PSO span
    // runs inside one held PC/SC transaction, so no concurrent
    // card consumer can interleave and disturb the security state
    // between our APDUs. The PIN is already in the cache -- no
    // prompt or non-card wait happens while the card is open.
    let mut card = backend
        .open_session(&reader, ReaderAccessCap::PinSequence)
        .map_err(|_open_err| CKR_DEVICE_ERROR)?;
    card.select_pkcs15_application()
        .map_err(|_select_err| CKR_DEVICE_ERROR)?;
    let serial = match live_token_serial(&mut card) {
        Ok(serial) => serial,
        Err(error) => {
            clear_positive(pin_cache);
            return Err(error);
        }
    };
    let pin1_status = match card.pin_status(PinSlot::Pin1) {
        Ok(status) => status,
        Err(_status_err) => {
            clear_positive(pin_cache);
            return Err(CKR_DEVICE_ERROR);
        }
    };
    if let Err(error) = pin1_verify_guard(pin1_status) {
        clear_positive(pin_cache);
        return Err(error);
    }
    let checkout = pin_cache
        .lock()
        .map_err(|_poisoned| CKR_DEVICE_ERROR)?
        .checkout_pin1(&serial)
        .ok_or(CKR_USER_NOT_LOGGED_IN)?;
    let outcome = card
        .verify_pin(PinSlot::Pin1, checkout.pin().clone())
        .map_err(|_verify_err| CKR_DEVICE_ERROR);
    match outcome {
        Ok(VerifyOutcome::Ok) => {
            let signature = sign_with_card(&mut card, mechanism, input)?;
            let mut cache = pin_cache.lock().map_err(|_poisoned| CKR_DEVICE_ERROR)?;
            checkout.restore_after_success(&mut cache);
            Ok(signature)
        }
        Ok(VerifyOutcome::WrongPin { .. }) => {
            pin_cache
                .lock()
                .map_err(|_poisoned| CKR_DEVICE_ERROR)?
                .record_rejected(&serial, PinSlot::Pin1, checkout.pin());
            Err(CKR_PIN_INCORRECT)
        }
        Ok(VerifyOutcome::Locked) => Err(CKR_PIN_LOCKED),
        Ok(VerifyOutcome::Other(_)) | Err(_) => Err(CKR_DEVICE_ERROR),
    }
}

fn remote_card_sign(hex_id: &str, mechanism: Mechanism, input: &[u8]) -> Result<Vec<u8>, CkRv> {
    let vault = refineid_lib_core::rapp::RappDeviceVault::new_default();
    let pairs = vault.active_pairs().map_err(|_| CKR_DEVICE_ERROR)?;
    let pair = pairs
        .into_iter()
        .find(|p| refineid_lib_core::hex::Hex::encode(&p.pair_id) == hex_id)
        .ok_or(CKR_DEVICE_ERROR)?;

    let (key_profile, algorithm, digest) = match mechanism {
        Mechanism::Ecdsa => {
            let digest_bytes = if input.len() == 48 {
                input.to_vec()
            } else if input.len() == 32 {
                let mut d = vec![0u8; 16];
                d.extend_from_slice(input);
                d
            } else {
                return Err(CKR_DATA_LEN_RANGE);
            };
            ("eccP384", "ecdsaSha384", digest_bytes)
        }
        Mechanism::RsaPkcs => ("rsa3072", "rsaPkcs1Sha256", input.to_vec()),
    };

    let op = refineid_lib_core::rapp::CardOperation::BrowserAuthenticate {
        origin: "Browser Authentication".into(),
        key_profile: key_profile.into(),
        algorithm: algorithm.into(),
        digest,
    };

    let result = refineid_lib_core::rapp::execute_operation_with_pair(&pair, &op)
        .map_err(|_| CKR_DEVICE_ERROR)?;

    match result {
        refineid_lib_core::rapp::CardOperationResult::Signature { signature_bytes } => {
            Ok(signature_bytes)
        }
        _ => Err(CKR_DEVICE_ERROR),
    }
}

/// Verify and cache a `C_Login` PIN only after the live card accepts it.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is used by sibling api module; plain pub would violate the public-surface typing grep"
)]
pub(super) fn card_login(
    reader_name: &str,
    pin_cache: &Arc<Mutex<PinSafetyCache>>,
    pin1: PinBytes,
) -> Result<(), CkRv> {
    if reader_name.starts_with("rapp:") {
        return Ok(());
    }
    let backend = PcscBackend;
    let reader = ReaderId::new(reader_name.to_owned());
    // PinSequence: SELECT -> probe -> VERIFY is one held
    // transaction; the PIN arrived with the call, so nothing
    // non-card happens while the card is open.
    let mut card = backend
        .open_session(&reader, ReaderAccessCap::PinSequence)
        .map_err(|_open_err| CKR_DEVICE_ERROR)?;
    card.select_pkcs15_application()
        .map_err(|_select_err| CKR_DEVICE_ERROR)?;
    let serial = match live_token_serial(&mut card) {
        Ok(serial) => serial,
        Err(error) => {
            clear_positive(pin_cache);
            return Err(error);
        }
    };
    let pin1_status = match card.pin_status(PinSlot::Pin1) {
        Ok(status) => status,
        Err(_status_err) => {
            clear_positive(pin_cache);
            return Err(CKR_DEVICE_ERROR);
        }
    };
    if let Err(error) = pin1_verify_guard(pin1_status) {
        clear_positive(pin_cache);
        return Err(error);
    }
    let mut cache = pin_cache.lock().map_err(|_poisoned| CKR_DEVICE_ERROR)?;
    if cache.is_rejected(&serial, PinSlot::Pin1, &pin1) {
        return Err(CKR_PIN_INCORRECT);
    }
    match card
        .verify_pin(PinSlot::Pin1, pin1.clone())
        .map_err(|_verify_err| CKR_DEVICE_ERROR)?
    {
        VerifyOutcome::Ok => {
            let stored = if pin1_status_permits_reusable_cache(pin1_status) {
                cache.store_pin1(serial, pin1)
            } else {
                cache.stage_pin1_once(serial, pin1)
            };
            stored.map_err(|_rejected| CKR_PIN_INCORRECT)
        }
        VerifyOutcome::WrongPin { .. } => {
            cache.record_rejected(&serial, PinSlot::Pin1, &pin1);
            drop(cache);
            Err(CKR_PIN_INCORRECT)
        }
        VerifyOutcome::Locked => Err(CKR_PIN_LOCKED),
        VerifyOutcome::Other(_sw) => Err(CKR_DEVICE_ERROR),
    }
}

/// Refuse every PIN-bearing APDU once fewer than three attempts remain.
/// Firefox does not surface retry warnings, so the module may consume
/// attempts down to two remaining and no further: a near-last attempt is
/// never `ReFineID`'s to spend, and only another middleware locks the card.
/// Mirrors the `CryptoTokenKit` adapter's retry floor of three.
const fn pin1_verify_guard(status: PinStatus) -> Result<(), CkRv> {
    match status {
        PinStatus::Remaining(retries) => match PinRetryRisk::from_retries(retries) {
            Some(risk) if risk.permits_pkcs11() => Ok(()),
            Some(_) => Err(CKR_PIN_LOCKED),
            None => Err(CKR_DEVICE_ERROR),
        },
        PinStatus::Locked => Err(CKR_PIN_LOCKED),
        PinStatus::Verified => Ok(()),
        PinStatus::NoInfo | PinStatus::Other(_) => Err(CKR_DEVICE_ERROR),
    }
}

fn live_token_serial(card: &mut refineid_lib_pcsc::PcscCard) -> Result<TokenSerial, CkRv> {
    card.read_token_info()
        .map_err(|_read_err| CKR_DEVICE_ERROR)?
        .serial_number_hex
        .map(render_token_serial)
        .filter(|serial| !serial.as_str().is_empty())
        .ok_or(CKR_DEVICE_ERROR)
}

fn clear_positive(pin_cache: &Arc<Mutex<PinSafetyCache>>) {
    if let Ok(mut cache) = pin_cache.lock() {
        cache.clear_positive();
    }
}

/// Change PIN1 on the card at `reader_name`.
///
/// Only compiled into the `pin-change` build; the default
/// (login-only) beta stubs `C_SetPIN`, so this has no caller there.
///
/// Mirrors [`card_sign`]'s proven chain: open the card, select the
/// PKCS#15 application (reference-data commands are refused from MF
/// context the same way VERIFY is), then run `CHANGE REFERENCE
/// DATA` with the current + new PIN pair in one command -- no prior
/// VERIFY is needed. The card is dropped before returning. On `Ok`
/// the card has reset the retry counter and cleared its PIN
/// presentation, so the caller must refresh any cached PIN1.
///
/// Typed inputs cross the boundary owned: [`ReaderId`] names the
/// reader and both PINs are consumed (their buffers zeroize on
/// drop), matching [`refineid_lib_core::auth::PinOps::change_pin`].
///
/// # Errors
/// [`CKR_PIN_INCORRECT`] when the current PIN is wrong,
/// [`CKR_PIN_LOCKED`] when the slot is blocked,
/// [`CKR_PIN_LEN_RANGE`] on a length rejection (local policy or
/// card-side), [`CKR_DEVICE_ERROR`] on any card / transport failure.
#[cfg(feature = "pin-change")]
#[expect(
    clippy::redundant_pub_crate,
    reason = "private root module helper is called from sibling api module; plain pub would violate the public-surface typing grep"
)]
pub(super) fn card_change_pin1(
    reader: &ReaderId,
    current_pin1: PinBytes,
    new_pin1: PinBytes,
) -> Result<(), CkRv> {
    let backend = PcscBackend;
    // PinSequence: SELECT -> probe -> CHANGE REFERENCE DATA is one
    // held transaction; both PINs arrived with the call.
    let mut card = backend
        .open_session(reader, ReaderAccessCap::PinSequence)
        .map_err(|_open_err| CKR_DEVICE_ERROR)?;
    card.select_pkcs15_application()
        .map_err(|_select_err| CKR_DEVICE_ERROR)?;
    // The empty-body VERIFY probe consumes no retry. Apply the same
    // consumer floor as login and signing before CHANGE REFERENCE DATA.
    let status = card
        .pin_status(PinSlot::Pin1)
        .map_err(|_probe_err| CKR_DEVICE_ERROR)?;
    pin1_verify_guard(status)?;
    let outcome = card
        .change_pin(PinSlot::Pin1, current_pin1, new_pin1)
        .map_err(|_change_err| CKR_DEVICE_ERROR)?;
    match outcome {
        ChangePinOutcome::Ok => Ok(()),
        ChangePinOutcome::WrongCurrentPin { .. } => Err(CKR_PIN_INCORRECT),
        ChangePinOutcome::Locked => Err(CKR_PIN_LOCKED),
        ChangePinOutcome::LengthError => Err(CKR_PIN_LEN_RANGE),
        ChangePinOutcome::Other(_sw) => Err(CKR_DEVICE_ERROR),
    }
}

#[cfg(test)]
#[expect(
    clippy::indexing_slicing,
    reason = "unit tests assert on fixed offsets of compile-time-known byte fixtures; production code stays panic-free."
)]
mod tests {
    use refineid_lib_core::apdu::status_word::PinRetries;
    use refineid_lib_core::auth::PinStatus;

    use super::{
        DER_TAG_INTEGER, DER_TAG_OCTET_STRING, OBJ_CERTIFICATE, OBJ_PRIVATE_KEY, OBJ_PUBLIC_KEY,
        ObjectKind, der_integer, der_octet_string, pin1_verify_guard,
    };
    use crate::ck::{CKR_DEVICE_ERROR, CKR_PIN_LOCKED};

    #[test]
    fn pin1_verify_guard_refuses_near_last_attempts() {
        let retries = |count| {
            PinRetries::from_nibble(count).expect("test retry count fits the status-word nibble")
        };

        assert_eq!(pin1_verify_guard(PinStatus::Remaining(retries(5))), Ok(()));
        assert_eq!(pin1_verify_guard(PinStatus::Remaining(retries(4))), Ok(()));
        assert_eq!(pin1_verify_guard(PinStatus::Remaining(retries(3))), Ok(()));
        assert_eq!(
            pin1_verify_guard(PinStatus::Remaining(retries(2))),
            Err(CKR_PIN_LOCKED)
        );
        assert_eq!(
            pin1_verify_guard(PinStatus::Remaining(retries(1))),
            Err(CKR_PIN_LOCKED)
        );
        assert_eq!(
            pin1_verify_guard(PinStatus::Remaining(retries(0))),
            Err(CKR_PIN_LOCKED)
        );
        assert_eq!(pin1_verify_guard(PinStatus::Locked), Err(CKR_PIN_LOCKED));
        assert_eq!(pin1_verify_guard(PinStatus::NoInfo), Err(CKR_DEVICE_ERROR));
        assert_eq!(
            pin1_verify_guard(PinStatus::Other(1)),
            Err(CKR_DEVICE_ERROR)
        );
    }

    #[test]
    fn object_kind_handle_round_trip() {
        assert_eq!(
            ObjectKind::from_handle(OBJ_CERTIFICATE),
            Some(ObjectKind::Certificate)
        );
        assert_eq!(
            ObjectKind::from_handle(OBJ_PRIVATE_KEY),
            Some(ObjectKind::PrivateKey)
        );
        assert_eq!(
            ObjectKind::from_handle(OBJ_PUBLIC_KEY),
            Some(ObjectKind::PublicKey)
        );
        assert_eq!(ObjectKind::from_handle(0), None);
        assert_eq!(ObjectKind::Certificate.handle(), OBJ_CERTIFICATE);
        assert_eq!(ObjectKind::PrivateKey.handle(), OBJ_PRIVATE_KEY);
        assert_eq!(ObjectKind::PublicKey.handle(), OBJ_PUBLIC_KEY);
    }

    #[test]
    fn empty_der_span_is_an_absent_attribute() {
        assert_eq!(super::non_empty(Vec::new()), None);
        assert_eq!(super::non_empty(vec![0x30]), Some(vec![0x30]));
    }

    #[test]
    fn der_integer_short_form() {
        let tlv = der_integer(&[0x01, 0x02, 0x03]);
        assert_eq!(tlv, vec![DER_TAG_INTEGER, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn der_octet_string_short_form() {
        let tlv = der_octet_string(&[0xAA, 0xBB]);
        assert_eq!(tlv, vec![DER_TAG_OCTET_STRING, 0x02, 0xAA, 0xBB]);
    }

    #[test]
    fn der_length_long_form_one_octet() {
        let body = vec![0x00_u8; 200];
        let tlv = der_octet_string(&body);
        // 0x04 tag, 0x81 long-form marker, 0xC8 = 200 length octet.
        assert_eq!(tlv[0], DER_TAG_OCTET_STRING);
        assert_eq!(tlv[1], 0x81);
        assert_eq!(tlv[2], 0xC8);
        assert_eq!(tlv.len(), 203);
    }
}
