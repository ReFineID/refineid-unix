//! `CAdES`-B `SignedData`, signed by a card that holds the key.
//!
//! [`crate::cms`] reads a `SignedData`; this writes one. The two are
//! separate because they have opposite problems. The reader is handed a
//! finished structure and must not trust it. The writer must produce
//! bytes another implementation will verify, and gets no second chance:
//! a signature over the wrong octets is indistinguishable from a
//! tampered document.
//!
//! # Why the API is in two halves
//!
//! The signature comes from the card, which is on the other side of a
//! PIN prompt and an APDU exchange. So the structure cannot be built in
//! one call: [`signed_attributes`] produces exactly the octets to be
//! hashed and sent to PSO:CDS, and [`signed_data`] takes the signature
//! back and assembles the result. Nothing in between touches a key.
//!
//! # The trap in RFC 5652 section 5.4
//!
//! `signedAttrs` appears in `SignerInfo` under an implicit `[0]` tag
//! (`0xA0`), but the octets that get signed are the *same attributes
//! re-tagged as a universal SET* (`0x31`). Sign the `0xA0` form and
//! every verifier rejects it. [`ToBeSigned`] therefore hands out the
//! `0x31` form and [`signed_data`] re-tags for the structure, so the
//! two can never be confused at a call site.
//!
//! # Conformance
//!
//! - RFC 5652 (CMS): `SignedData`, `SignerInfo`, `Attribute`.
//! - RFC 5035 (ESS): `SigningCertificateV2`, mandatory for `CAdES`.
//! - ETSI EN 319 122-1 (`CAdES`): the baseline B-B profile is
//!   `content-type` + `message-digest` + `signing-time` +
//!   `signing-certificate-v2`, which is what this builds.
//!
//! Long-term levels (B-T and up) add a timestamp token as an unsigned
//! attribute. Not built here: a timestamp needs a TSA round trip, which
//! is a network operation and belongs above this module.

use crate::ber::tlv;
use crate::crypto::digest::{Sha256, Sha384};
use crate::oid;
use crate::sign::validation::ValidationMaterial;
use crate::x509::Certificate;

/// Universal SEQUENCE (`0x30`).
const TAG_SEQUENCE: u8 = 0x30;

/// Universal SET / SET OF (`0x31`). Also the tag the signed attributes
/// carry while being signed, per RFC 5652 section 5.4.
const TAG_SET: u8 = 0x31;

/// Universal OBJECT IDENTIFIER (`0x06`).
const TAG_OID: u8 = 0x06;

/// Universal OCTET STRING (`0x04`).
const TAG_OCTET_STRING: u8 = 0x04;

/// Universal INTEGER (`0x02`).
const TAG_INTEGER: u8 = 0x02;

/// Universal `UTCTime` (`0x17`).
const TAG_UTC_TIME: u8 = 0x17;

/// Context-specific constructed `[1]` (`0xA1`), the implicit tag on
/// `unsignedAttrs` in `SignerInfo`.
const TAG_CONTEXT_1: u8 = 0xA1;

/// Context-specific constructed `[0]` (`0xA0`).
///
/// Three different things in this file wear this tag: the explicit
/// wrapper around `SignedData` in `ContentInfo`, the implicit
/// `certificates` field, and the implicit `signedAttrs` field. The
/// parent structure decides which; the byte is the same.
const TAG_CONTEXT_0: u8 = 0xA0;

/// CMS version 1: `SignerInfo` identified by issuer and serial, and an
/// `eContentType` of `id-data` (RFC 5652 section 5.1).
const CMS_VERSION_V1: u8 = 0x01;

/// CMS version 5, required once `certificates` or `crls` carries an
/// entry of the `other` choice (RFC 5652 section 5.1).
const CMS_VERSION_V5: u8 = 0x05;

/// Which digest the content and the attributes are hashed under.
///
/// FINEID cards sign SHA-256 under RSA and both SHA-256 and SHA-384
/// under ECDSA; nothing here offers SHA-1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    /// SHA-256 (FIPS 180-4).
    Sha256,
    /// SHA-384 (FIPS 180-4).
    Sha384,
}

impl DigestAlgorithm {
    /// Digest of `input` under this algorithm.
    #[must_use]
    pub fn digest(self, input: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::of(input).as_bytes().to_vec(),
            Self::Sha384 => Sha384::of(input).as_bytes().to_vec(),
        }
    }

    /// The OID for this digest algorithm.
    #[must_use]
    pub(crate) const fn oid(self) -> oid::Oid<'static> {
        match self {
            Self::Sha256 => oid::known::SHA256,
            Self::Sha384 => oid::known::SHA384,
        }
    }

    /// The `AlgorithmIdentifier` SEQUENCE for this digest.
    ///
    /// The parameters field is absent rather than NULL: RFC 5754
    /// section 2 requires the absent form for the SHA-2 family, and
    /// some verifiers reject the NULL form.
    pub(crate) fn algorithm_identifier(self) -> Vec<u8> {
        let oid_der = match self {
            Self::Sha256 => tlv(TAG_OID, oid::known::SHA256.as_bytes()),
            Self::Sha384 => tlv(TAG_OID, oid::known::SHA384.as_bytes()),
        };
        tlv(TAG_SEQUENCE, oid_der)
    }
}

/// Which signature the card will produce over the attribute digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017).
    RsaPkcs1Sha256,
    /// RSASSA-PKCS1-v1_5 with SHA-384 (RFC 8017).
    RsaPkcs1Sha384,
    /// ECDSA with SHA-256 (FIPS 186-4).
    EcdsaSha256,
    /// ECDSA with SHA-384 (FIPS 186-4).
    EcdsaSha384,
}

impl SignatureAlgorithm {
    /// The digest this signature is computed over.
    #[must_use]
    pub const fn digest_algorithm(self) -> DigestAlgorithm {
        match self {
            Self::RsaPkcs1Sha256 | Self::EcdsaSha256 => DigestAlgorithm::Sha256,
            Self::RsaPkcs1Sha384 | Self::EcdsaSha384 => DigestAlgorithm::Sha384,
        }
    }

    /// The `AlgorithmIdentifier` SEQUENCE for `signatureAlgorithm`.
    ///
    /// RSA carries an explicit NULL parameter (RFC 8017 appendix A.2.4);
    /// ECDSA omits parameters entirely (RFC 5758 section 3.2). The
    /// difference is not cosmetic -- verifiers check it.
    fn algorithm_identifier(self) -> Vec<u8> {
        match self {
            Self::RsaPkcs1Sha256 => Self::rsa_identifier(oid::known::SHA256_WITH_RSA),
            Self::RsaPkcs1Sha384 => Self::rsa_identifier(oid::known::SHA384_WITH_RSA),
            Self::EcdsaSha256 => tlv(
                TAG_SEQUENCE,
                tlv(TAG_OID, oid::known::ECDSA_WITH_SHA256.as_bytes()),
            ),
            Self::EcdsaSha384 => tlv(
                TAG_SEQUENCE,
                tlv(TAG_OID, oid::known::ECDSA_WITH_SHA384.as_bytes()),
            ),
        }
    }

    /// An RSA `AlgorithmIdentifier`: OID plus the mandatory NULL.
    fn rsa_identifier(algorithm: oid::Oid<'_>) -> Vec<u8> {
        let mut body = tlv(TAG_OID, algorithm.as_bytes());
        // NULL is tag 0x05, length 0. Written as a literal pair rather
        // than through `tlv` because there is no value to pass.
        body.extend_from_slice(&[0x05, 0x00]);
        tlv(TAG_SEQUENCE, body)
    }
}

/// Whether the signed content travels inside the structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encapsulation {
    /// `eContent` omitted. The verifier is given the document
    /// separately -- what `PAdES` and `ASiC` both need, because the
    /// document is the PDF or the container entry itself.
    Detached,
    /// `eContent` carried inside the `SignedData`. Self-contained, at
    /// the cost of storing the document twice if it is also kept
    /// alongside.
    Attached,
}

/// The exact octets the card must sign.
///
/// Carries the DER SET (`0x31`) form, which is what RFC 5652
/// section 5.4 signs -- not the `[0]` implicit form the same attributes
/// wear inside `SignerInfo`. Keeping the two apart in the type system
/// is the point of this wrapper existing at all.
#[derive(Debug, Clone)]
pub struct ToBeSigned {
    /// Attributes as a universal SET, ready to hash.
    der: Vec<u8>,
}

impl ToBeSigned {
    /// The octets to hash and send to the card.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.der
    }

    /// The digest the card signs, under `algorithm`.
    #[must_use]
    pub fn digest(&self, algorithm: DigestAlgorithm) -> Vec<u8> {
        algorithm.digest(&self.der)
    }
}

/// Signing time, as the `UTCTime` CMS wants.
///
/// `YYMMDDHHMMSSZ`, which is what RFC 5652 section 11.3 requires for
/// years before 2050. The caller supplies the parts rather than a clock:
/// this crate has no ambient time source, and a signature's claimed time
/// is the caller's assertion to make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningTime {
    /// Year, four digits. Must be 1950..=2049 for the `UTCTime` form.
    pub year: u16,
    /// Month, 1..=12.
    pub month: u8,
    /// Day of month, 1..=31.
    pub day: u8,
    /// Hour, 0..=23.
    pub hour: u8,
    /// Minute, 0..=59.
    pub minute: u8,
    /// Second, 0..=59.
    pub second: u8,
}

impl SigningTime {
    /// Lowest year the `UTCTime` two-digit form can express unambiguously.
    const UTC_TIME_FIRST_YEAR: u16 = 1950;

    /// First year that needs `GeneralizedTime` instead.
    const UTC_TIME_LAST_YEAR: u16 = 2050;

    /// Century divisor for the two-digit year.
    const YEAR_MODULO: u16 = 100;

    /// The `UTCTime` body, or `None` outside the representable range.
    fn to_utc_time(self) -> Option<Vec<u8>> {
        if self.year < Self::UTC_TIME_FIRST_YEAR || self.year >= Self::UTC_TIME_LAST_YEAR {
            return None;
        }
        let two_digit_year = self.year % Self::YEAR_MODULO;
        let mut text = Vec::with_capacity(13);
        Self::push_pair(&mut text, two_digit_year);
        Self::push_pair(&mut text, u16::from(self.month));
        Self::push_pair(&mut text, u16::from(self.day));
        Self::push_pair(&mut text, u16::from(self.hour));
        Self::push_pair(&mut text, u16::from(self.minute));
        Self::push_pair(&mut text, u16::from(self.second));
        text.push(b'Z');
        Some(text)
    }

    /// Two zero-padded ASCII digits of `value`.
    fn push_pair(out: &mut Vec<u8>, value: u16) {
        /// Radix for the decimal pair.
        const TEN: u16 = 10;
        let tens = (value / TEN) % TEN;
        let units = value % TEN;
        // `u8::try_from` cannot fail: both operands are < 10 by the
        // modulo above.
        out.push(b'0'.saturating_add(tens as u8));
        out.push(b'0'.saturating_add(units as u8));
    }
}

/// What the signature is being made over and by whom.
#[derive(Debug, Clone, Copy)]
pub struct SignerParameters<'a> {
    /// The signer's certificate, DER, as read from the card.
    pub certificate: &'a Certificate<'a>,
    /// Digest for the content and the attributes.
    pub digest_algorithm: DigestAlgorithm,
    /// Signature the card will produce.
    pub signature_algorithm: SignatureAlgorithm,
    /// Claimed signing time, if one is asserted.
    pub signing_time: Option<SigningTime>,
}

/// Build the signed attributes for one signer.
///
/// `content_digest` is the digest of the document under
/// `parameters.digest_algorithm` -- of the PDF byte ranges for `PAdES`,
/// of the container entry for `ASiC`, of the file for a detached
/// signature. This function never sees the document itself.
///
/// The four attributes are the `CAdES` B-B set. They are emitted in DER
/// SET order, which is ascending by encoded octets rather than by OID
/// value or by any order chosen here (X.690 section 11.6). A SET that is
/// merely in a sensible order is not DER and verifiers do reject it.
#[must_use]
pub fn signed_attributes(parameters: &SignerParameters<'_>, content_digest: &[u8]) -> ToBeSigned {
    let mut attributes: Vec<Vec<u8>> = Vec::with_capacity(4);

    attributes.push(attribute(
        oid::known::CONTENT_TYPE,
        tlv(TAG_OID, oid::known::DATA.as_bytes()),
    ));
    attributes.push(attribute(
        oid::known::MESSAGE_DIGEST,
        tlv(TAG_OCTET_STRING, content_digest),
    ));
    if let Some(time) = parameters.signing_time.and_then(SigningTime::to_utc_time) {
        attributes.push(attribute(oid::known::SIGNING_TIME, tlv(TAG_UTC_TIME, time)));
    }
    attributes.push(attribute(
        oid::known::SIGNING_CERTIFICATE_V2,
        signing_certificate_v2(parameters),
    ));

    attributes.sort_unstable();
    let mut body = Vec::new();
    for attribute_der in attributes {
        body.extend_from_slice(&attribute_der);
    }
    ToBeSigned {
        der: tlv(TAG_SET, body),
    }
}

/// One `Attribute ::= SEQUENCE { attrType OID, attrValues SET OF ANY }`.
fn attribute(attribute_type: oid::Oid<'_>, value_der: Vec<u8>) -> Vec<u8> {
    let mut body = tlv(TAG_OID, attribute_type.as_bytes());
    body.extend_from_slice(&tlv(TAG_SET, value_der));
    tlv(TAG_SEQUENCE, body)
}

/// `SigningCertificateV2` (RFC 5035 section 3), binding the signature to
/// the exact certificate that made it.
///
/// Without it a signature can be replayed against a different
/// certificate carrying the same key, which is why `CAdES` makes it
/// mandatory rather than optional.
///
/// `issuerSerial` is omitted. It is OPTIONAL in the ASN.1 and the
/// `certHash` already pins the certificate uniquely; including it would
/// add a second, weaker identifier that has to agree with the first.
fn signing_certificate_v2(parameters: &SignerParameters<'_>) -> Vec<u8> {
    let cert_hash = parameters
        .digest_algorithm
        .digest(parameters.certificate.raw_der);

    // ESSCertIDv2 ::= SEQUENCE { hashAlgorithm DEFAULT sha256,
    //                            certHash OCTET STRING, ... }
    // The DEFAULT must be omitted when it is the value, per DER.
    let mut cert_id_body = Vec::new();
    if parameters.digest_algorithm != DigestAlgorithm::Sha256 {
        cert_id_body.extend_from_slice(&parameters.digest_algorithm.algorithm_identifier());
    }
    cert_id_body.extend_from_slice(&tlv(TAG_OCTET_STRING, cert_hash));
    let cert_id = tlv(TAG_SEQUENCE, cert_id_body);

    // SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }
    tlv(TAG_SEQUENCE, tlv(TAG_SEQUENCE, cert_id))
}

/// Convert a raw `r || s` ECDSA signature to the DER form CMS carries.
///
/// FINEID cards return the raw pair -- 96 bytes for P-384, per S1 v4.2
/// sec.3.8.3 -- and CMS wants `SEQUENCE { r INTEGER, s INTEGER }`. The
/// mismatch is silent in the worst way: the raw bytes go into the
/// `signature` OCTET STRING happily and produce a structure that every
/// verifier rejects for a reason that points nowhere near the encoding.
///
/// The reverse conversion, for XML signatures, is
/// [`crate::sign::xades::ecdsa_signature_to_xml`]. Cards need this one;
/// signers backed by OpenSSL need that one.
///
/// Returns `None` unless `raw` is an even, non-empty number of bytes, or already a valid DER sequence.
#[must_use]
pub fn ecdsa_signature_to_cms(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() >= 6 && raw[0] == TAG_SEQUENCE {
        let (len_len, payload_len) = match raw.get(1)? {
            b if *b < 0x80 => (1, *b as usize),
            0x81 => (2, *raw.get(2)? as usize),
            0x82 => {
                let hi = *raw.get(2)? as usize;
                let lo = *raw.get(3)? as usize;
                (3, (hi << 8) | lo)
            }
            _ => return None,
        };
        if raw.len() == 1 + len_len + payload_len {
            return Some(raw.to_vec());
        }
    }
    if raw.is_empty() || !raw.len().is_multiple_of(2) {
        return None;
    }
    let (r, s) = raw.split_at(raw.len() / 2);
    let mut body = der_integer(r);
    body.extend_from_slice(&der_integer(s));
    Some(tlv(TAG_SEQUENCE, body))
}

/// One coordinate as a DER INTEGER.
///
/// Two adjustments, both required by X.690 sec.8.3 and both a common
/// source of signatures that verify in one library and not another:
/// leading zero octets are stripped because DER INTEGERs are minimal,
/// and a zero octet is then prepended when the top bit is set, because
/// without it the value would read as negative.
fn der_integer(coordinate: &[u8]) -> Vec<u8> {
    // All zero falls back to a single `0x00`: a DER INTEGER always has
    // at least one content octet.
    let magnitude = coordinate.iter().position(|byte| *byte != 0).map_or_else(
        || &[0][..],
        |first| coordinate.get(first..).unwrap_or_default(),
    );
    let mut value = Vec::with_capacity(magnitude.len().saturating_add(1));
    if magnitude.first().is_some_and(|byte| *byte & 0x80 != 0) {
        value.push(0);
    }
    value.extend_from_slice(magnitude);
    tlv(TAG_INTEGER, value)
}

/// Assemble the finished `ContentInfo`-wrapped `SignedData`.
///
/// `signature` is what the card returned for
/// `signed_attributes(..).digest(..)`. `content` is the document, needed
/// only for [`Encapsulation::Attached`]; detached signatures ignore it.
///
/// The `attributes` are re-tagged from SET to implicit `[0]` here, which
/// is the one place in this module allowed to do that.
#[must_use]
pub fn signed_data(
    parameters: &SignerParameters<'_>,
    attributes: &ToBeSigned,
    signature: &[u8],
    encapsulation: Encapsulation,
    content: &[u8],
    material: &ValidationMaterial,
    timestamps: &[Vec<u8>],
) -> Vec<u8> {
    let mut signed_data_body = Vec::new();

    // RFC 5652 sec.5.1: the version is 5 once `crls` carries anything
    // of the `other` choice, which an OCSP response is. Leaving it at 1
    // produces a structure a strict parser rejects.
    let version = if material.ocsp_responses.is_empty() {
        CMS_VERSION_V1
    } else {
        CMS_VERSION_V5
    };
    signed_data_body.extend_from_slice(&tlv(TAG_INTEGER, [version]));
    signed_data_body.extend_from_slice(&tlv(
        TAG_SET,
        parameters.digest_algorithm.algorithm_identifier(),
    ));
    signed_data_body.extend_from_slice(&encapsulated_content(encapsulation, content));

    // The signer's certificate, then whatever completes the chain. A
    // verifier that has to fetch an issuer is a verifier that stops
    // working the day the fetch does.
    // `certificates [0] IMPLICIT CertificateSet` is a SET OF, so DER
    // orders it by encoding rather than by the order the chain was
    // walked in (X.690 sec.11.6). Concatenating in walk order is the
    // kind of DER violation a lenient parser accepts and a strict one
    // rejects, which is the worst combination to ship.
    let mut certificates: Vec<Vec<u8>> = vec![parameters.certificate.raw_der.to_vec()];
    certificates.extend(material.certificates.iter().cloned());
    certificates.sort_unstable();
    certificates.dedup();
    let mut certificate_set = Vec::new();
    for certificate in certificates {
        certificate_set.extend_from_slice(&certificate);
    }
    signed_data_body.extend_from_slice(&tlv(TAG_CONTEXT_0, certificate_set));

    // `crls [1] IMPLICIT RevocationInfoChoices`. A CRL goes in as
    // itself; an OCSP response has no CHOICE of its own and travels
    // wrapped as `other`, per RFC 5940.
    if material.revocation_count() > 0 {
        let mut choices = Vec::new();
        for crl in &material.crls {
            choices.push(crl.clone());
        }
        for response in &material.ocsp_responses {
            // `other [1] IMPLICIT OtherRevocationInfoFormat`. IMPLICIT
            // replaces the SEQUENCE tag with the `[1]` -- it does not
            // wrap it. Writing `[1] { SEQUENCE { .. } }` is one layer
            // too many, and a parser reading the contents as an OID
            // meets a SEQUENCE tag and gives up.
            let mut other = tlv(
                TAG_OID,
                oid::known::OCSP_RESPONSE_REVOCATION_INFO.as_bytes(),
            );
            other.extend_from_slice(response);
            choices.push(tlv(TAG_CONTEXT_1, other));
        }
        // DER SET OF, so ordered by encoding rather than by the order
        // the responders answered in.
        choices.sort_unstable();
        choices.dedup();
        let mut body = Vec::new();
        for choice in choices {
            body.extend_from_slice(&choice);
        }
        signed_data_body.extend_from_slice(&tlv(TAG_CONTEXT_1, body));
    }

    signed_data_body.extend_from_slice(&tlv(
        TAG_SET,
        signer_info(parameters, attributes, signature, timestamps),
    ));

    let signed_data_der = tlv(TAG_SEQUENCE, signed_data_body);

    // ContentInfo ::= SEQUENCE { contentType, content [0] EXPLICIT }
    let mut content_info = tlv(TAG_OID, oid::known::SIGNED_DATA.as_bytes());
    content_info.extend_from_slice(&tlv(TAG_CONTEXT_0, signed_data_der));
    tlv(TAG_SEQUENCE, content_info)
}

/// `EncapsulatedContentInfo`: the type, and the content when attached.
fn encapsulated_content(encapsulation: Encapsulation, content: &[u8]) -> Vec<u8> {
    let mut body = tlv(TAG_OID, oid::known::DATA.as_bytes());
    if encapsulation == Encapsulation::Attached {
        body.extend_from_slice(&tlv(TAG_CONTEXT_0, tlv(TAG_OCTET_STRING, content)));
    }
    tlv(TAG_SEQUENCE, body)
}

/// One `SignerInfo`, identified by issuer and serial.
fn signer_info(
    parameters: &SignerParameters<'_>,
    attributes: &ToBeSigned,
    signature: &[u8],
    timestamps: &[Vec<u8>],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&tlv(TAG_INTEGER, [CMS_VERSION_V1]));
    body.extend_from_slice(&issuer_and_serial(parameters.certificate));
    body.extend_from_slice(&parameters.digest_algorithm.algorithm_identifier());

    // The SET tag the attributes were signed under becomes the implicit
    // [0] the structure carries. Same contents, same length; only the
    // first octet differs.
    let mut tagged_attributes = attributes.as_bytes().to_vec();
    if let Some(first) = tagged_attributes.first_mut() {
        *first = TAG_CONTEXT_0;
    }
    body.extend_from_slice(&tagged_attributes);

    body.extend_from_slice(&parameters.signature_algorithm.algorithm_identifier());
    body.extend_from_slice(&tlv(TAG_OCTET_STRING, signature));

    // `unsignedAttrs [1] IMPLICIT`, after the signature because it is
    // computed over it. A timestamp cannot live among the signed
    // attributes for the same reason a photograph cannot contain the
    // camera that took it.
    //
    // One attribute instance per token rather than one attribute
    // holding several values: `EN 319 122-1` says several instances of
    // signature-time-stamp may occur, from different TSAs, and that is
    // the shape validators look for. Each token attests the same
    // signature, so they are alternatives rather than a sequence -- one
    // surviving is enough.
    if !timestamps.is_empty() {
        let mut instances: Vec<Vec<u8>> = timestamps
            .iter()
            .map(|token| attribute(oid::known::SIGNATURE_TIME_STAMP_TOKEN, token.clone()))
            .collect();
        // DER SET OF is ordered by encoding, not by the order the
        // tokens arrived in (X.690 sec.11.6).
        instances.sort_unstable();
        instances.dedup();
        let mut attributes = Vec::new();
        for instance in instances {
            attributes.extend_from_slice(&instance);
        }
        body.extend_from_slice(&tlv(TAG_CONTEXT_1, attributes));
    }
    tlv(TAG_SEQUENCE, body)
}

/// `IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }`.
///
/// Both come from the parsed certificate as raw DER, so the issuer name
/// is byte-identical to the one in the certificate. Re-encoding a name
/// is how signatures stop verifying: two DER encodings of the "same"
/// name are not the same octets.
fn issuer_and_serial(certificate: &Certificate<'_>) -> Vec<u8> {
    let mut body = certificate.issuer.as_der().to_vec();
    // `serial_der` is the INTEGER *value* octets -- no tag, no length --
    // because the parser preserves any leading sign byte for OCSP and
    // CRL comparison. It has to be re-wrapped here, and writing it raw
    // produces a structure OpenSSL rejects at exactly this offset.
    body.extend_from_slice(&tlv(TAG_INTEGER, certificate.serial_der));
    tlv(TAG_SEQUENCE, body)
}

#[cfg(test)]
mod tests {
    use crate::sign::validation::ValidationMaterial;
    /// `other [1] IMPLICIT OtherRevocationInfoFormat` replaces the
    /// SEQUENCE tag rather than wrapping it. The wrapped form is
    /// well-formed DER that parses as far as the `[1]`, then hands a
    /// SEQUENCE tag to something expecting an OID -- so a validator
    /// throws rather than reporting an invalid signature. Two of them
    /// answered HTTP 500 before this was right.
    #[test]
    fn an_ocsp_response_is_tagged_implicitly_not_wrapped() {
        let certificate = Certificate::from_der(fixture_certificate()).expect("certificate");
        let parameters = SignerParameters {
            certificate: &certificate,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            signing_time: None,
        };
        let attributes = signed_attributes(&parameters, &[0x11; 32]);
        // A stand-in response: a SEQUENCE the encoder must not add a
        // second SEQUENCE in front of.
        let response = vec![0x30, 0x03, 0x02, 0x01, 0x07];
        let material = ValidationMaterial {
            certificates: Vec::new(),
            ocsp_responses: vec![response],
            crls: Vec::new(),
        };
        let cms = signed_data(
            &parameters,
            &attributes,
            &[0xAA_u8; 384],
            Encapsulation::Detached,
            &[],
            &material,
            &[],
        );

        // `A1` then the OID, with no `30` in between.
        let oid = [0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x10, 0x02];
        let at = cms
            .windows(oid.len())
            .position(|window| window == oid)
            .expect("the RFC 5940 OID must be present");
        assert_eq!(
            cms[at - 2],
            0xA1,
            "the OID must sit directly inside the [1] tag, not behind a SEQUENCE"
        );

        // And the version rises to 5, as RFC 5652 sec.5.1 requires once
        // anything of the `other` choice is present.
        assert!(
            cms.windows(3).any(|w| w == [0x02, 0x01, 0x05]),
            "CMS version must be 5 when crls carries an OCSP response"
        );
    }

    /// The two encodings of one ECDSA signature, and the round trip
    /// between them. A card hands out the raw pair; CMS wants DER; XML
    /// wants the raw pair back. Getting either direction wrong produces
    /// a document that is well-formed and unverifiable.
    #[test]
    fn raw_ecdsa_becomes_der_and_back() {
        use crate::sign::xades::ecdsa_signature_to_xml;

        // r has its top bit set, so DER must prepend a zero octet; s
        // has leading zeros, which DER must strip.
        let raw = [0xFF, 0x01, 0x02, 0x03, 0x00, 0x00, 0x0A, 0x0B];
        let der = super::ecdsa_signature_to_cms(&raw).expect("der");
        assert_eq!(
            der,
            vec![
                0x30, 0x0B, // SEQUENCE, 11 bytes: a 7-byte r and a 4-byte s
                0x02, 0x05, 0x00, 0xFF, 0x01, 0x02, 0x03, // r, sign byte added
                0x02, 0x02, 0x0A, 0x0B, // s, leading zeros stripped
            ]
        );
        assert_eq!(super::ecdsa_signature_to_cms(&der), Some(der.clone()));
        // Back to the fixed-width form the card produced.
        assert_eq!(
            ecdsa_signature_to_xml(&der, raw.len() / 2).expect("raw"),
            raw.to_vec()
        );

        // A zero coordinate still needs one content octet.
        let zero = super::ecdsa_signature_to_cms(&[0x00, 0x00]).expect("der");
        assert_eq!(zero, vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]);

        // An odd length cannot be split into two coordinates.
        assert_eq!(super::ecdsa_signature_to_cms(&[0x01, 0x02, 0x03]), None);
        assert_eq!(super::ecdsa_signature_to_cms(&[]), None);
    }

    use super::{
        DigestAlgorithm, Encapsulation, SignatureAlgorithm, SignerParameters, SigningTime,
        signed_attributes, signed_data,
    };
    use crate::x509::Certificate;

    /// Universal SET, the tag the attributes are signed under.
    const TAG_SET: u8 = 0x31;

    /// Implicit `[0]`, the tag they wear inside `SignerInfo`.
    const TAG_CONTEXT_0: u8 = 0xA0;

    /// A fixed signing time, so the attribute bytes are deterministic
    /// and a fixture signature stays valid.
    const FIXED_TIME: SigningTime = SigningTime {
        year: 2026,
        month: 8,
        day: 3,
        hour: 12,
        minute: 0,
        second: 0,
    };

    /// A committed FINEID intermediate, used only as a well-formed
    /// certificate to encode issuer/serial and hash. Nothing here
    /// verifies against its key.
    fn fixture_certificate() -> &'static [u8] {
        include_bytes!(
            "../../../refineid-client/test-vectors/fineid-intermediate-01-citizen-g4e.der"
        )
    }

    /// Walk consecutive TLVs, returning each element's whole encoding.
    fn elements(mut body: &[u8]) -> Vec<&[u8]> {
        let mut out = Vec::new();
        while !body.is_empty() {
            let (header, length) = length_at(body);
            let total = header + length;
            out.push(&body[..total]);
            body = &body[total..];
        }
        out
    }

    /// Header size and value length of the TLV at the front of `der`.
    fn length_at(der: &[u8]) -> (usize, usize) {
        /// Long-form marker bit.
        const LONG_FORM: u8 = 0x80;
        /// Mask for the count of length octets in the long form.
        const COUNT_MASK: u8 = 0x7F;
        let first = der[1];
        if first & LONG_FORM == 0 {
            return (2, usize::from(first));
        }
        let count = usize::from(first & COUNT_MASK);
        let mut length = 0_usize;
        for byte in &der[2..2 + count] {
            length = (length << 8) | usize::from(*byte);
        }
        (2 + count, length)
    }

    #[test]
    fn signs_the_set_form_not_the_context_form() {
        let der = fixture_certificate();
        let certificate = Certificate::from_der(der).expect("fixture parses");
        let parameters = SignerParameters {
            certificate: &certificate,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            signing_time: Some(FIXED_TIME),
        };
        let attributes = signed_attributes(&parameters, &[0x11_u8; 32]);

        // What the card signs must be the universal SET.
        assert_eq!(attributes.as_bytes()[0], TAG_SET);

        // What the structure carries must be the implicit [0], and
        // must be otherwise byte-identical: same length, same body.
        let assembled = signed_data(
            &parameters,
            &attributes,
            &[0xAA_u8; 384],
            Encapsulation::Detached,
            &[],
            &ValidationMaterial::default(),
            &[],
        );
        let signed_form = attributes.as_bytes();
        let mut carried_form = signed_form.to_vec();
        carried_form[0] = TAG_CONTEXT_0;
        assert!(
            assembled
                .windows(carried_form.len())
                .any(|window| window == carried_form.as_slice()),
            "SignerInfo must carry the [0] re-tagging of the signed SET"
        );
        assert!(
            !assembled
                .windows(signed_form.len())
                .any(|window| window == signed_form),
            "the universal SET form must not appear in the structure"
        );
    }

    #[test]
    fn attributes_are_in_der_set_order() {
        let der = fixture_certificate();
        let certificate = Certificate::from_der(der).expect("fixture parses");
        let parameters = SignerParameters {
            certificate: &certificate,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            signing_time: Some(FIXED_TIME),
        };
        let attributes = signed_attributes(&parameters, &[0x22_u8; 32]);

        let (header, _) = length_at(attributes.as_bytes());
        let members = elements(&attributes.as_bytes()[header..]);
        assert_eq!(members.len(), 4, "content-type, digest, time, cert-v2");

        // X.690 sec.11.6: a DER SET OF is sorted by encoded octets.
        let mut sorted = members.clone();
        sorted.sort_unstable();
        assert_eq!(members, sorted, "SET OF members must be in DER order");
    }

    #[test]
    fn omitting_signing_time_drops_the_attribute() {
        let der = fixture_certificate();
        let certificate = Certificate::from_der(der).expect("fixture parses");
        let parameters = SignerParameters {
            certificate: &certificate,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            signing_time: None,
        };
        let attributes = signed_attributes(&parameters, &[0x33_u8; 32]);
        let (header, _) = length_at(attributes.as_bytes());
        assert_eq!(elements(&attributes.as_bytes()[header..]).len(), 3);
    }

    #[test]
    fn detached_omits_econtent_and_attached_carries_it() {
        let der = fixture_certificate();
        let certificate = Certificate::from_der(der).expect("fixture parses");
        let parameters = SignerParameters {
            certificate: &certificate,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            signing_time: Some(FIXED_TIME),
        };
        let attributes = signed_attributes(&parameters, &[0x44_u8; 32]);
        let document = b"declaration of a means of cryptology";

        let detached = signed_data(
            &parameters,
            &attributes,
            &[0xBB_u8; 384],
            Encapsulation::Detached,
            document,
            &ValidationMaterial::default(),
            &[],
        );
        let attached = signed_data(
            &parameters,
            &attributes,
            &[0xBB_u8; 384],
            Encapsulation::Attached,
            document,
            &ValidationMaterial::default(),
            &[],
        );
        assert!(
            !detached
                .windows(document.len())
                .any(|window| window == document),
            "a detached signature must not carry the document"
        );
        assert!(
            attached
                .windows(document.len())
                .any(|window| window == document),
            "an attached signature must carry the document"
        );
    }
}

/// End-to-end interoperability against OpenSSL.
///
/// Structural tests prove the encoder agrees with its author. These
/// prove it agrees with an independent implementation, which is the
/// only thing that matters for a signature format: the verifier is
/// never us.
///
/// Ignored by default because they shell out to `openssl`. Run with:
///
/// ```text
/// cargo test -p refineid-lib-core --lib sign::cades::openssl -- --ignored
/// ```
#[cfg(test)]
mod openssl_interop {
    use crate::sign::validation::ValidationMaterial;
    use std::process::Command;

    use super::{
        DigestAlgorithm, Encapsulation, SignatureAlgorithm, SignerParameters, SigningTime,
        signed_attributes, signed_data,
    };
    use crate::x509::Certificate;

    /// Runs a command, returning stdout and failing loudly otherwise.
    fn run(program: &str, args: &[&str]) -> Vec<u8> {
        let output = Command::new(program)
            .args(args)
            .output()
            .unwrap_or_else(|error| panic!("{program} not runnable: {error}"));
        assert!(
            output.status.success(),
            "{program} {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    #[test]
    #[ignore = "requires the openssl binary"]
    fn openssl_verifies_an_attached_signature() {
        let dir = std::env::temp_dir().join("refineid-cades-interop");
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = |name: &str| dir.join(name).to_string_lossy().into_owned();

        // A throwaway signer. The card is simulated by asking OpenSSL
        // to raw-sign the same digest the card would be given.
        run("openssl", &["genrsa", "-out", &path("key.pem"), "3072"]);
        run(
            "openssl",
            &[
                "req",
                "-x509",
                "-new",
                "-key",
                &path("key.pem"),
                "-out",
                &path("cert.pem"),
                "-sha256",
                "-days",
                "1",
                "-subj",
                "/CN=RefineID CAdES interop",
            ],
        );
        run(
            "openssl",
            &[
                "x509",
                "-in",
                &path("cert.pem"),
                "-outform",
                "DER",
                "-out",
                &path("cert.der"),
            ],
        );

        let cert_der = std::fs::read(path("cert.der")).expect("cert der");
        let certificate = Certificate::from_der(&cert_der).expect("cert parses");
        let document = b"RefineID -- declaration of a means of cryptology";

        let parameters = SignerParameters {
            certificate: &certificate,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            signing_time: Some(SigningTime {
                year: 2026,
                month: 8,
                day: 3,
                hour: 12,
                minute: 0,
                second: 0,
            }),
        };

        let content_digest = parameters.digest_algorithm.digest(document);
        let attributes = signed_attributes(&parameters, &content_digest);

        // What the card would be handed. Signed here by OpenSSL over
        // the same octets, using PKCS#1 v1.5 with SHA-256.
        std::fs::write(path("tbs.der"), attributes.as_bytes()).expect("write tbs");
        run(
            "openssl",
            &[
                "dgst",
                "-sha256",
                "-sign",
                &path("key.pem"),
                "-out",
                &path("sig.bin"),
                &path("tbs.der"),
            ],
        );
        let signature = std::fs::read(path("sig.bin")).expect("signature");

        let cms = signed_data(
            &parameters,
            &attributes,
            &signature,
            Encapsulation::Attached,
            document,
            &ValidationMaterial::default(),
            &[],
        );
        std::fs::write(path("out.p7s"), &cms).expect("write cms");

        // The verdict that counts.
        run(
            "openssl",
            &[
                "cms",
                "-verify",
                "-inform",
                "DER",
                "-in",
                &path("out.p7s"),
                "-CAfile",
                &path("cert.pem"),
                "-purpose",
                "any",
                "-out",
                &path("recovered.bin"),
            ],
        );
        let recovered = std::fs::read(path("recovered.bin")).expect("recovered content");
        assert_eq!(recovered, document, "OpenSSL recovered the signed content");
    }

    #[test]
    #[ignore = "requires the openssl binary"]
    fn openssl_verifies_a_detached_signature() {
        let dir = std::env::temp_dir().join("refineid-cades-interop-detached");
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = |name: &str| dir.join(name).to_string_lossy().into_owned();

        run("openssl", &["genrsa", "-out", &path("key.pem"), "3072"]);
        run(
            "openssl",
            &[
                "req",
                "-x509",
                "-new",
                "-key",
                &path("key.pem"),
                "-out",
                &path("cert.pem"),
                "-sha256",
                "-days",
                "1",
                "-subj",
                "/CN=RefineID CAdES detached",
            ],
        );
        run(
            "openssl",
            &[
                "x509",
                "-in",
                &path("cert.pem"),
                "-outform",
                "DER",
                "-out",
                &path("cert.der"),
            ],
        );

        let cert_der = std::fs::read(path("cert.der")).expect("cert der");
        let certificate = Certificate::from_der(&cert_der).expect("cert parses");
        let document = b"detached over the document, as PAdES and ASiC need";
        std::fs::write(path("doc.bin"), document).expect("write doc");

        let parameters = SignerParameters {
            certificate: &certificate,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            signing_time: None,
        };
        let content_digest = parameters.digest_algorithm.digest(document);
        let attributes = signed_attributes(&parameters, &content_digest);
        std::fs::write(path("tbs.der"), attributes.as_bytes()).expect("write tbs");
        run(
            "openssl",
            &[
                "dgst",
                "-sha256",
                "-sign",
                &path("key.pem"),
                "-out",
                &path("sig.bin"),
                &path("tbs.der"),
            ],
        );
        let signature = std::fs::read(path("sig.bin")).expect("signature");

        let cms = signed_data(
            &parameters,
            &attributes,
            &signature,
            Encapsulation::Detached,
            &[],
            &ValidationMaterial::default(),
            &[],
        );
        std::fs::write(path("out.p7s"), &cms).expect("write cms");

        run(
            "openssl",
            &[
                "cms",
                "-verify",
                "-inform",
                "DER",
                "-in",
                &path("out.p7s"),
                "-content",
                &path("doc.bin"),
                "-CAfile",
                &path("cert.pem"),
                "-purpose",
                "any",
                "-out",
                &path("/dev/null"),
            ],
        );
    }
}
