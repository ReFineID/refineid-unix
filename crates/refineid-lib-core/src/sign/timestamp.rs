//! RFC 3161 timestamps: turning a claimed time into an attested one.
//!
//! A signature carries the time its maker says it was made. Nothing in
//! the card, the certificate or the signature proves that claim -- the
//! clock it came from is the signer's, and a signer who can set their
//! own clock can date a signature whenever they like.
//!
//! A timestamp replaces the claim with someone else's assertion. A
//! Time Stamp Authority signs "this digest existed at this time", and
//! because the digest is over the signature, the signature must have
//! existed by then. That is what raises a baseline signature from level
//! B to level T.
//!
//! # Why it matters after the certificate expires
//!
//! Without a timestamp a signature is only checkable while the signing
//! certificate is valid. Afterwards a verifier cannot tell a signature
//! made in good time from one made after the key was revoked, and has
//! to treat both the same. With one, the verifier has a trusted time to
//! evaluate the certificate against, and the signature keeps its
//! meaning past the certificate's expiry.
//!
//! # What is checked, and what is not
//!
//! [`verified_token`] (and the compatibility [`token`] wrapper) checks
//! that the token answers *this* request: that its
//! `messageImprint` is the digest that was sent, and that the nonce
//! comes back unchanged. It also verifies the token's CMS signature
//! with the one embedded TSA certificate selected by CMS
//! `SignerIdentifier` and the signed ESS certificate hash. The
//! certificate must be an end entity whose sole critical Extended Key
//! Usage is `id-kp-timeStamping`, with compatible Key Usage, and it must
//! be valid at the token's `genTime`. Transport security remains useful
//! defence in depth, but none of these checks relies on it.
//!
//! What is not checked in this core parser is the dynamic trust path:
//! whether the authenticated TSA certificate chains to an anchor the
//! caller trusts for timestamping. [`verified_token`] returns the
//! signer certificate and `genTime` so the client can apply its own
//! authority trust decision without weakening the cryptographic checks
//! performed here.
//!
//! # Conformance
//!
//! - RFC 3161: `TimeStampReq`, `TimeStampResp`, `PKIStatusInfo`.
//! - `ETSI EN 319 122-1` / `EN 319 142-1`: the token travels as the
//!   unsigned attribute `id-aa-signatureTimeStampToken`, over the
//!   signature value.

use crate::ber::{
    BerTag, BerTlv, BerTlvAny, BerTlvIter, BitString, Boolean, Integer, OctetString, Oid as BerOid,
    Sequence, Utf8String, tlv,
};
use crate::cms::{SignedAttribute, SignedData, SignerIdentifier};
use crate::oid::known;
use crate::sign::cades::DigestAlgorithm;
use crate::x509::{Certificate, DateTime};
use sha1::{Digest as _, Sha1};
use sha2::{Sha256, Sha384, Sha512};
use spki::der::Decode as _;
use spki::der::asn1::GeneralizedTime;

/// Universal SEQUENCE (`0x30`).
const TAG_SEQUENCE: u8 = 0x30;

/// Universal INTEGER (`0x02`).
const TAG_INTEGER: u8 = 0x02;

/// Universal OCTET STRING (`0x04`).
const TAG_OCTET_STRING: u8 = 0x04;

/// Universal BOOLEAN (`0x01`).
const TAG_BOOLEAN: u8 = 0x01;

/// Universal `GeneralizedTime` (`0x18`).
const TAG_GENERALIZED_TIME: u8 = 0x18;

/// Context-specific constructed tag zero.
const TAG_CONTEXT_0_CONSTRUCTED: u16 = 0xA0;

/// Context-specific constructed tag one.
const TAG_CONTEXT_1_CONSTRUCTED: u16 = 0xA1;

/// `GeneralName.directoryName [4]`.
const TAG_DIRECTORY_NAME: u16 = 0xA4;

/// `GeneralName.rfc822Name [1]`.
const TAG_RFC822_NAME: u16 = 0x81;

/// `Accuracy.millis [0] IMPLICIT INTEGER`.
const TAG_ACCURACY_MILLIS: u16 = 0x80;

/// `Accuracy.micros [1] IMPLICIT INTEGER`.
const TAG_ACCURACY_MICROS: u16 = 0x81;

/// Universal NULL.
const TAG_NULL: u16 = 0x05;

/// `TimeStampReq` version 1, the only version RFC 3161 defines.
const VERSION_V1: u8 = 0x01;

/// DER TRUE. X.690 sec.11.1 allows exactly this encoding.
const DER_TRUE: u8 = 0xFF;

/// BER FALSE value.
const BER_FALSE: u8 = 0x00;

/// `PKIStatus` granted (RFC 3161 sec.2.4.2).
const STATUS_GRANTED: u64 = 0;

/// `PKIStatus` granted with modifications. The token is still usable;
/// the TSA is saying it did not honour every field of the request.
const STATUS_GRANTED_WITH_MODS: u64 = 1;

/// What can go wrong between asking for a timestamp and having one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampError {
    /// The response is not a well-formed `TimeStampResp`.
    Malformed(&'static str),
    /// The TSA refused. Carries the `PKIStatus` it returned.
    Rejected {
        /// `PKIStatus` from RFC 3161 sec.2.4.2: 2 rejection,
        /// 3 waiting, 4 revocation warning, 5 revoked.
        status: u64,
    },
    /// The status said granted but no token came with it.
    NoToken,
    /// The token attests a digest other than the one requested. Over
    /// plain HTTP, this is what a substituted answer looks like.
    ImprintMismatch,
    /// The nonce did not come back, or came back changed: the answer
    /// belongs to some other request.
    NonceMismatch,
    /// The token's CMS signature did not verify under any embedded
    /// certificate.
    TokenSignatureInvalid,
    /// No embedded certificate matched the CMS `SignerIdentifier`.
    NoMatchingTsaCertificate,
    /// More than one distinct embedded certificate matched the CMS
    /// `SignerIdentifier`.
    AmbiguousTsaCertificate,
    /// The signed ESS certificate-binding attribute was absent,
    /// ambiguous, malformed, or did not identify the selected signer.
    SigningCertificateAttributeInvalid,
    /// `TSTInfo.tsa`, when present, did not exactly identify the CMS signer.
    TsaNameMismatch,
    /// The token did not carry an embedded TSA certificate that is valid
    /// for timestamp signing at `genTime`.
    NoUsableTsaCertificate,
}

impl core::fmt::Display for TimestampError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Malformed(what) => write!(f, "malformed timestamp response: {what}"),
            Self::Rejected { status } => {
                write!(f, "the timestamp authority refused (PKIStatus {status})")
            }
            Self::NoToken => f.write_str("the timestamp authority granted but sent no token"),
            Self::ImprintMismatch => {
                f.write_str("the token attests a digest other than the one requested")
            }
            Self::NonceMismatch => f.write_str("the token does not echo the nonce sent"),
            Self::TokenSignatureInvalid => f.write_str("the token's CMS signature does not verify"),
            Self::NoMatchingTsaCertificate => {
                f.write_str("the token has no certificate matching its signer identifier")
            }
            Self::AmbiguousTsaCertificate => {
                f.write_str("the token has multiple certificates matching its signer identifier")
            }
            Self::SigningCertificateAttributeInvalid => f.write_str(
                "the token's signed ESS certificate binding is absent, malformed, or mismatched",
            ),
            Self::TsaNameMismatch => {
                f.write_str("the token's TSTInfo tsa name does not identify its signer")
            }
            Self::NoUsableTsaCertificate => {
                f.write_str("the token has no embedded TSA certificate valid for timestamp signing")
            }
        }
    }
}

impl core::error::Error for TimestampError {}

/// A cryptographically verified RFC 3161 token and its authenticated
/// signer metadata.
///
/// The CMS signature, signer identifier, ESS certificate binding, TSA
/// certificate profile, and certificate validity at `generated_at` have
/// all been checked. This does not prove that the signer chains to a
/// caller-approved trust anchor or is authorised by a trusted list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTimestampToken {
    /// Original `TimeStampToken` CMS `ContentInfo` DER.
    pub token: Vec<u8>,
    /// DER of the certificate that authenticated the token.
    pub signer_certificate: Vec<u8>,
    /// Every distinct, parseable X.509 certificate embedded in the CMS
    /// `SignedData`, in encoded order. This includes the signer certificate;
    /// byte-identical duplicates are removed. Trust-path validation remains
    /// the caller's responsibility.
    pub embedded_certificates: Vec<Vec<u8>>,
    /// Authenticated `TSTInfo.genTime`.
    pub generated_at: DateTime,
}

/// Authenticated fields recovered while checking one timestamp token.
struct VerifiedBinding {
    /// DER of the CMS signer certificate.
    signer_certificate: Vec<u8>,
    /// Distinct parseable certificates carried by CMS.
    embedded_certificates: Vec<Vec<u8>>,
    /// Authenticated `TSTInfo.genTime`.
    generated_at: DateTime,
}

/// Build a `TimeStampReq` over `digest`.
///
/// `digest` is the hash of the signature value, under `algorithm`.
///
/// `nonce` is passed to the TSA, which uses it to keep from replaying
/// an older token. Omitting it is legal and some TSAs ignore it.
///
/// `request_certificate` asks the TSA to embed its own certificate in
/// the token. Say yes: a token whose signer certificate has to be
/// fetched separately is a token that stops verifying the day that
/// fetch fails, which defeats the point of having one.
#[must_use]
pub fn request(
    digest: &[u8],
    algorithm: DigestAlgorithm,
    nonce: Option<&[u8]>,
    request_certificate: bool,
) -> Vec<u8> {
    // MessageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage }
    let mut imprint = algorithm.algorithm_identifier();
    imprint.extend_from_slice(&tlv(TAG_OCTET_STRING, digest));

    let mut body = tlv(TAG_INTEGER, [VERSION_V1]);
    body.extend_from_slice(&tlv(TAG_SEQUENCE, imprint));
    if let Some(nonce) = nonce {
        body.extend_from_slice(&tlv(TAG_INTEGER, positive_integer(nonce)));
    }
    // DEFAULT FALSE, so the field is only written when it is true.
    if request_certificate {
        body.extend_from_slice(&tlv(TAG_BOOLEAN, [DER_TRUE]));
    }
    tlv(TAG_SEQUENCE, body)
}

/// Make `bytes` a valid non-negative DER INTEGER body.
///
/// A nonce is a bag of random bits, and half of them have the top bit
/// set, which DER would read as a negative number. A leading zero octet
/// keeps it positive without changing the value.
fn positive_integer(bytes: &[u8]) -> Vec<u8> {
    // Strip leading zero octets first. A nonce is random, so one byte
    // in 256 starts with 0x00, and prepending a sign octet to that
    // yields 00 00 ... -- a non-minimal INTEGER, which DER forbids and
    // a strict TSA may reject. Minimise, then re-add the sign octet
    // only when the top bit actually needs it.
    let magnitude = bytes
        .iter()
        .position(|byte| *byte != 0)
        .map_or(&[][..], |first| bytes.get(first..).unwrap_or_default());
    if magnitude.is_empty() {
        // All zero, or empty. A DER INTEGER always has one content
        // octet, and zero is written as a single 0x00.
        return vec![0];
    }
    let mut out = Vec::with_capacity(magnitude.len().saturating_add(1));
    if magnitude.first().is_some_and(|byte| *byte & 0x80 != 0) {
        out.push(0);
    }
    out.extend_from_slice(magnitude);
    out
}

/// Extract the `TimeStampToken` from a `TimeStampResp`.
///
/// The token is returned as its own DER, ready to be attached as an
/// unsigned attribute. It is a CMS `ContentInfo` in its own right.
///
/// # Errors
/// [`TimestampError::Rejected`] when the TSA refused,
/// [`TimestampError::NoToken`] when it granted without sending one, and
/// [`TimestampError::Malformed`] when the response does not parse.
pub fn token(
    response: &[u8],
    expected_digest: &[u8],
    expected_algorithm: DigestAlgorithm,
    nonce: Option<&[u8]>,
) -> Result<Vec<u8>, TimestampError> {
    verified_token(response, expected_digest, expected_algorithm, nonce)
        .map(|verified| verified.token)
}

/// Extract and cryptographically verify a `TimeStampToken`, retaining
/// the authenticated signer certificate and generation time.
///
/// # Errors
/// Returns [`TimestampError`] for malformed responses, request-binding
/// failures, ambiguous signer selection, signature or ESS failures, and
/// TSA certificates outside the required RFC 3161 profile.
pub fn verified_token(
    response: &[u8],
    expected_digest: &[u8],
    expected_algorithm: DigestAlgorithm,
    nonce: Option<&[u8]>,
) -> Result<VerifiedTimestampToken, TimestampError> {
    // TimeStampResp ::= SEQUENCE { status PKIStatusInfo,
    //                              timeStampToken TimeStampToken OPTIONAL }
    let response_tlv = BerTlv::<Sequence>::parse(response)
        .map_err(|_ignored| TimestampError::Malformed("not a SEQUENCE"))?;
    if response_tlv.size != response.len() {
        return Err(TimestampError::Malformed(
            "trailing bytes after TimeStampResp",
        ));
    }
    let body = response_tlv.value;

    let status_info = BerTlvAny::parse(body)
        .map_err(|_ignored| TimestampError::Malformed("no PKIStatusInfo"))?
        .expect::<Sequence>()
        .map_err(|_ignored| TimestampError::Malformed("PKIStatusInfo is not a SEQUENCE"))?;
    let status = parse_status_info(status_info)?;

    // Whatever follows the status is the token, and it is wanted whole
    // -- tag and length included -- because it gets re-emitted as an
    // attribute value rather than taken apart.
    let after_status = body
        .get(status_info_size(body)?..)
        .ok_or(TimestampError::Malformed("truncated after status"))?;
    let token = if after_status.is_empty() {
        None
    } else {
        let token_tlv = BerTlvAny::parse(after_status)
            .map_err(|_ignored| TimestampError::Malformed("token does not parse"))?;
        if token_tlv.size != after_status.len() {
            return Err(TimestampError::Malformed(
                "trailing bytes after timestamp token",
            ));
        }
        Some(
            after_status
                .get(..token_tlv.size)
                .ok_or(TimestampError::Malformed("token truncated"))?,
        )
    };
    if status != STATUS_GRANTED && status != STATUS_GRANTED_WITH_MODS {
        return Err(TimestampError::Rejected { status });
    }
    let token = token.ok_or(TimestampError::NoToken)?;
    let binding = check_binding(token, expected_digest, expected_algorithm, nonce)?;
    Ok(VerifiedTimestampToken {
        token: token.to_vec(),
        signer_certificate: binding.signer_certificate,
        embedded_certificates: binding.embedded_certificates,
        generated_at: binding.generated_at,
    })
}

/// Check the token answers this request and no other.
fn check_binding(
    token: &[u8],
    expected_digest: &[u8],
    expected_algorithm: DigestAlgorithm,
    nonce: Option<&[u8]>,
) -> Result<VerifiedBinding, TimestampError> {
    let signed_data = SignedData::parse(token)
        .map_err(|_ignored| TimestampError::Malformed("token is not CMS SignedData"))?;
    if signed_data.econtent_type_oid != known::TST_INFO {
        return Err(TimestampError::Malformed(
            "token eContentType is not TSTInfo",
        ));
    }
    if signed_data.signer.signed_data_to_verify.is_none() {
        return Err(TimestampError::Malformed(
            "token signerInfo has no signed attributes",
        ));
    }
    let tst_info = parse_tst_info(signed_data.econtent_der)?;
    if tst_info.imprint_algorithm_oid != expected_algorithm.oid().as_bytes()
        || tst_info.message_imprint != expected_digest
    {
        return Err(TimestampError::ImprintMismatch);
    }
    if let Some(nonce) = nonce
        && tst_info.nonce != Some(positive_integer(nonce).as_slice())
    {
        return Err(TimestampError::NonceMismatch);
    }
    let certificate = select_signer_certificate(&signed_data)?;
    if let Some(tsa) = tst_info.tsa
        && !tsa_name_matches_certificate(tsa, certificate)?
    {
        return Err(TimestampError::TsaNameMismatch);
    }
    signed_data
        .verify(certificate.spki.as_der())
        .map_err(|_ignored| TimestampError::TokenSignatureInvalid)?;
    verify_signing_certificate_attribute(&signed_data, &certificate)?;
    tsa_certificate_is_usable(&certificate, tst_info.gen_time)?;
    Ok(VerifiedBinding {
        signer_certificate: certificate.raw_der.to_vec(),
        embedded_certificates: parseable_embedded_certificates(&signed_data),
        generated_at: tst_info.gen_time,
    })
}

/// Retain parseable CMS certificates while removing byte-identical repeats.
fn parseable_embedded_certificates(signed_data: &SignedData<'_>) -> Vec<Vec<u8>> {
    let mut certificates = Vec::new();
    for certificate_der in &signed_data.certificates_der {
        if Certificate::from_der(certificate_der).is_err()
            || certificates
                .iter()
                .any(|existing: &Vec<u8>| existing.as_slice() == *certificate_der)
        {
            continue;
        }
        certificates.push(certificate_der.to_vec());
    }
    certificates
}

/// Parsed RFC 3161 `TSTInfo` fields this module needs.
struct TstInfo<'a> {
    /// `messageImprint.hashAlgorithm.algorithm`.
    imprint_algorithm_oid: &'a [u8],
    /// `messageImprint.hashedMessage`.
    message_imprint: &'a [u8],
    /// `genTime`.
    gen_time: DateTime,
    /// Optional nonce INTEGER value, as canonical DER content bytes.
    nonce: Option<&'a [u8]>,
    /// Optional authority name, retained for exact signer binding.
    tsa: Option<TsaName<'a>>,
}

/// `GeneralName` forms this verifier can compare exactly to a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TsaName<'a> {
    /// Exact DER `Name`, compared byte-for-byte with the signer subject.
    DirectoryName(&'a [u8]),
    /// Validated UTF-8 mailbox, compared byte-for-byte with a SAN rfc822Name.
    Rfc822Name(&'a [u8]),
}

/// Parsed optional `TSTInfo` tail.
struct TstInfoOptionalFields<'a> {
    nonce: Option<&'a [u8]>,
    tsa: Option<TsaName<'a>>,
}

/// Parse the signed `TSTInfo` eContent.
fn parse_tst_info(econtent: &[u8]) -> Result<TstInfo<'_>, TimestampError> {
    let outer = BerTlv::<Sequence>::parse(econtent)
        .map_err(|_ignored| TimestampError::Malformed("TSTInfo is not a SEQUENCE"))?;
    if outer.size != econtent.len() {
        return Err(TimestampError::Malformed("trailing bytes after TSTInfo"));
    }
    let mut it = outer.iter_children();

    let version = next_integer(&mut it, "TSTInfo missing version")?;
    if unsigned_integer(version.value) != Some(u64::from(VERSION_V1)) {
        return Err(TimestampError::Malformed("TSTInfo version is not v1"));
    }
    let policy = next_oid(&mut it, "TSTInfo missing policy")?;
    crate::oid::Oid::new(policy.value)
        .map_err(|_ignored| TimestampError::Malformed("TSTInfo policy OID malformed"))?;
    let imprint = next_sequence(&mut it, "TSTInfo missing messageImprint")?;
    let (imprint_algorithm_oid, message_imprint) = parse_message_imprint(imprint.value)?;
    let serial = next_integer(&mut it, "TSTInfo missing serialNumber")?;
    if !nonnegative_der_integer(serial.value) {
        return Err(TimestampError::Malformed(
            "TSTInfo serialNumber is not a non-negative DER INTEGER",
        ));
    }
    let gen_time = next_any(&mut it, "TSTInfo missing genTime")?;
    if gen_time.tag != u16::from(TAG_GENERALIZED_TIME) {
        return Err(TimestampError::Malformed(
            "TSTInfo genTime is not GeneralizedTime",
        ));
    }
    let gen_time = parse_generalized_time(gen_time.value)?;

    let mut optional = Vec::new();
    for child in it {
        optional.push(
            child.map_err(|_ignored| {
                TimestampError::Malformed("TSTInfo optional field malformed")
            })?,
        );
    }
    let optional = parse_tst_info_optional_fields(&optional)?;

    Ok(TstInfo {
        imprint_algorithm_oid,
        message_imprint,
        gen_time,
        nonce: optional.nonce,
        tsa: optional.tsa,
    })
}

/// Parse the optional tail of `TSTInfo` in ASN.1 field order.
fn parse_tst_info_optional_fields<'a>(
    optional: &[BerTlvAny<'a>],
) -> Result<TstInfoOptionalFields<'a>, TimestampError> {
    let mut index = 0_usize;
    let mut tsa_name = None;
    if optional
        .get(index)
        .is_some_and(|child| child.tag == <Sequence as BerTag>::TAG)
    {
        parse_accuracy(
            optional
                .get(index)
                .ok_or(TimestampError::Malformed("TSTInfo accuracy missing"))?
                .value,
        )?;
        index = index.saturating_add(1);
    }
    if optional
        .get(index)
        .is_some_and(|child| child.tag == <Boolean as BerTag>::TAG)
    {
        let ordering = optional
            .get(index)
            .ok_or(TimestampError::Malformed("TSTInfo ordering missing"))?;
        if ordering.value != [DER_TRUE] {
            return Err(TimestampError::Malformed(
                "TSTInfo ordering is not canonical DER TRUE",
            ));
        }
        index = index.saturating_add(1);
    }
    let mut nonce = None;
    if optional
        .get(index)
        .is_some_and(|child| child.tag == <Integer as BerTag>::TAG)
    {
        let value = optional
            .get(index)
            .ok_or(TimestampError::Malformed("TSTInfo nonce missing"))?
            .value;
        if !nonnegative_der_integer(value) {
            return Err(TimestampError::Malformed(
                "TSTInfo nonce is not a non-negative DER INTEGER",
            ));
        }
        nonce = Some(value);
        index = index.saturating_add(1);
    }
    if optional
        .get(index)
        .is_some_and(|child| child.tag == TAG_CONTEXT_0_CONSTRUCTED)
    {
        let tsa = optional
            .get(index)
            .ok_or(TimestampError::Malformed("TSTInfo tsa missing"))?;
        let name = BerTlvAny::parse(tsa.value)
            .map_err(|_ignored| TimestampError::Malformed("TSTInfo tsa malformed"))?;
        if name.size != tsa.value.len() {
            return Err(TimestampError::Malformed("TSTInfo tsa has trailing bytes"));
        }
        tsa_name = Some(match name.tag {
            TAG_DIRECTORY_NAME => {
                crate::x509::Name::try_from(name.value).map_err(|_ignored| {
                    TimestampError::Malformed("TSTInfo tsa directoryName malformed")
                })?;
                TsaName::DirectoryName(name.value)
            }
            TAG_RFC822_NAME => {
                let mailbox = core::str::from_utf8(name.value).map_err(|_ignored| {
                    TimestampError::Malformed("TSTInfo tsa rfc822Name is not UTF-8")
                })?;
                crate::identity::EmailAddress::new(mailbox).map_err(|_ignored| {
                    TimestampError::Malformed("TSTInfo tsa rfc822Name malformed")
                })?;
                TsaName::Rfc822Name(name.value)
            }
            _ => {
                return Err(TimestampError::Malformed(
                    "unsupported TSTInfo tsa GeneralName",
                ));
            }
        });
        index = index.saturating_add(1);
    }
    if optional
        .get(index)
        .is_some_and(|child| child.tag == TAG_CONTEXT_1_CONSTRUCTED)
    {
        let extensions = optional
            .get(index)
            .ok_or(TimestampError::Malformed("TSTInfo extensions missing"))?;
        parse_timestamp_extensions(extensions.value)?;
        index = index.saturating_add(1);
    }
    if index != optional.len() {
        return Err(TimestampError::Malformed(
            "TSTInfo has duplicate, unknown, or out-of-order optional fields",
        ));
    }
    Ok(TstInfoOptionalFields {
        nonce,
        tsa: tsa_name,
    })
}

/// Parse `MessageImprint`.
fn parse_message_imprint(imprint: &[u8]) -> Result<(&[u8], &[u8]), TimestampError> {
    let mut it = BerTlvIter::new(imprint);
    let algorithm = next_sequence(&mut it, "messageImprint missing hashAlgorithm")?;
    let algorithm_oid = parse_algorithm_identifier(algorithm.value)?;
    let hashed = next_octet_string(&mut it, "messageImprint missing hashedMessage")?;
    if it.next().is_some() {
        return Err(TimestampError::Malformed(
            "messageImprint has trailing fields",
        ));
    }
    Ok((algorithm_oid.value, hashed.value))
}

/// Decode RFC 3161 `genTime`.
fn parse_generalized_time(value: &[u8]) -> Result<DateTime, TimestampError> {
    let encoded = tlv(TAG_GENERALIZED_TIME, value);
    GeneralizedTime::from_der(&encoded)
        .map(|time| time.to_date_time())
        .map_err(|_ignored| TimestampError::Malformed("TSTInfo genTime is invalid"))
}

/// Select exactly one distinct embedded certificate by CMS SID.
fn select_signer_certificate<'a>(
    signed_data: &SignedData<'a>,
) -> Result<Certificate<'a>, TimestampError> {
    let mut matches = Vec::new();
    for cert_der in &signed_data.certificates_der {
        let Ok(certificate) = Certificate::from_der(cert_der) else {
            continue;
        };
        if !certificate_matches_sid(&certificate, signed_data.signer.signer_identifier)? {
            continue;
        }
        if !matches
            .iter()
            .any(|existing: &Certificate<'_>| existing.raw_der == certificate.raw_der)
        {
            matches.push(certificate);
        }
    }
    match matches.as_slice() {
        [] => Err(TimestampError::NoMatchingTsaCertificate),
        [certificate] => Ok(*certificate),
        _ => Err(TimestampError::AmbiguousTsaCertificate),
    }
}

/// Match the two CMS `SignerIdentifier` alternatives.
fn certificate_matches_sid(
    certificate: &Certificate<'_>,
    sid: SignerIdentifier<'_>,
) -> Result<bool, TimestampError> {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber {
            issuer_der,
            serial_number,
        } => Ok(
            certificate.issuer.as_der() == issuer_der && certificate.serial_der == serial_number
        ),
        SignerIdentifier::SubjectKeyIdentifier(wanted) => {
            let Some(extensions) = certificate.extensions else {
                return Ok(false);
            };
            let parsed = parse_extensions(extensions)?;
            Ok(parsed.subject_key_identifier == Some(wanted))
        }
    }
}

/// Enforce the RFC 3161 TSA certificate profile at authenticated genTime.
fn tsa_certificate_is_usable(
    certificate: &Certificate<'_>,
    gen_time: DateTime,
) -> Result<(), TimestampError> {
    if gen_time < certificate.not_before || certificate.not_after < gen_time {
        return Err(TimestampError::NoUsableTsaCertificate);
    }
    let extensions = certificate
        .extensions
        .ok_or(TimestampError::NoUsableTsaCertificate)?;
    let extensions =
        parse_extensions(extensions).map_err(|_ignored| TimestampError::NoUsableTsaCertificate)?;
    if extensions.basic_constraints_ca {
        return Err(TimestampError::NoUsableTsaCertificate);
    }
    let eku = extensions
        .extended_key_usage
        .ok_or(TimestampError::NoUsableTsaCertificate)?;
    if !eku.critical || eku.oids.as_slice() != [known::KP_TIME_STAMPING] {
        return Err(TimestampError::NoUsableTsaCertificate);
    }
    if let Some(usage) = extensions.key_usage
        && (!usage.allows_timestamp_signature || usage.allows_ca_signing)
    {
        return Err(TimestampError::NoUsableTsaCertificate);
    }
    Ok(())
}

/// Validate the complete `PKIStatusInfo` and return its status code.
fn parse_status_info(status_info: BerTlv<'_, Sequence>) -> Result<u64, TimestampError> {
    let mut fields = Vec::new();
    for field in status_info.iter_children() {
        fields
            .push(field.map_err(|_ignored| TimestampError::Malformed("PKIStatusInfo malformed"))?);
    }
    let status = fields
        .first()
        .ok_or(TimestampError::Malformed("no PKIStatus"))?
        .expect::<Integer>()
        .map_err(|_ignored| TimestampError::Malformed("PKIStatus is not INTEGER"))?;
    let status = unsigned_integer(status.value)
        .ok_or(TimestampError::Malformed("PKIStatus out of range"))?;

    let mut index = 1_usize;
    if fields
        .get(index)
        .is_some_and(|field| field.tag == <Sequence as BerTag>::TAG)
    {
        let free_text = fields
            .get(index)
            .ok_or(TimestampError::Malformed("statusString missing"))?
            .expect::<Sequence>()
            .map_err(|_ignored| TimestampError::Malformed("statusString malformed"))?;
        let mut count = 0_usize;
        for text in free_text.iter_children() {
            text.map_err(|_ignored| TimestampError::Malformed("statusString malformed"))?
                .expect::<Utf8String>()
                .map_err(|_ignored| {
                    TimestampError::Malformed("statusString entry is not UTF8String")
                })?;
            count = count.saturating_add(1);
        }
        if count == 0 {
            return Err(TimestampError::Malformed("statusString is empty"));
        }
        index = index.saturating_add(1);
    }
    if fields
        .get(index)
        .is_some_and(|field| field.tag == <BitString as BerTag>::TAG)
    {
        validate_bit_string(
            fields
                .get(index)
                .ok_or(TimestampError::Malformed("failInfo missing"))?
                .value,
            "failInfo BIT STRING malformed",
        )?;
        index = index.saturating_add(1);
    }
    if index != fields.len() {
        return Err(TimestampError::Malformed(
            "PKIStatusInfo has unknown or duplicate fields",
        ));
    }
    Ok(status)
}

/// Parse an `AlgorithmIdentifier` body, allowing only absent or NULL
/// parameters, and return its validated OID TLV.
fn parse_algorithm_identifier(body: &[u8]) -> Result<BerTlv<'_, BerOid>, TimestampError> {
    let mut it = BerTlvIter::new(body);
    let oid = next_oid(&mut it, "AlgorithmIdentifier missing OID")?;
    crate::oid::Oid::new(oid.value)
        .map_err(|_ignored| TimestampError::Malformed("AlgorithmIdentifier OID malformed"))?;
    if let Some(parameters) = it.next() {
        let parameters = parameters
            .map_err(|_ignored| TimestampError::Malformed("AlgorithmIdentifier malformed"))?;
        if parameters.tag != TAG_NULL || !parameters.value.is_empty() {
            return Err(TimestampError::Malformed(
                "AlgorithmIdentifier parameters are not NULL",
            ));
        }
        if it.next().is_some() {
            return Err(TimestampError::Malformed(
                "AlgorithmIdentifier has trailing fields",
            ));
        }
    }
    Ok(oid)
}

/// Validate RFC 3161 `Accuracy` optional fields and ranges.
fn parse_accuracy(body: &[u8]) -> Result<(), TimestampError> {
    let mut fields = Vec::new();
    for field in BerTlvIter::new(body) {
        fields.push(field.map_err(|_ignored| TimestampError::Malformed("Accuracy malformed"))?);
    }
    let mut index = 0_usize;
    if fields
        .get(index)
        .is_some_and(|field| field.tag == <Integer as BerTag>::TAG)
    {
        let seconds = unsigned_integer(
            fields
                .get(index)
                .ok_or(TimestampError::Malformed("Accuracy seconds missing"))?
                .value,
        )
        .ok_or(TimestampError::Malformed("Accuracy seconds malformed"))?;
        if seconds == 0 {
            return Err(TimestampError::Malformed("Accuracy seconds is zero"));
        }
        index = index.saturating_add(1);
    }
    for (tag, label) in [
        (TAG_ACCURACY_MILLIS, "Accuracy millis malformed"),
        (TAG_ACCURACY_MICROS, "Accuracy micros malformed"),
    ] {
        if fields.get(index).is_some_and(|field| field.tag == tag) {
            let value = unsigned_integer(
                fields
                    .get(index)
                    .ok_or(TimestampError::Malformed(label))?
                    .value,
            )
            .ok_or(TimestampError::Malformed(label))?;
            if !(1..=999).contains(&value) {
                return Err(TimestampError::Malformed(label));
            }
            index = index.saturating_add(1);
        }
    }
    if index != fields.len() || fields.is_empty() {
        return Err(TimestampError::Malformed(
            "Accuracy has unknown, duplicate, or out-of-order fields",
        ));
    }
    Ok(())
}

/// Compare a retained `TSTInfo.tsa` name to the selected CMS signer.
/// Only name forms with an exact comparison are retained by the parser.
fn tsa_name_matches_certificate(
    tsa: TsaName<'_>,
    certificate: Certificate<'_>,
) -> Result<bool, TimestampError> {
    match tsa {
        TsaName::DirectoryName(name_der) => Ok(name_der == certificate.subject.as_der()),
        TsaName::Rfc822Name(mailbox) => {
            let Some(extensions) = certificate.extensions else {
                return Ok(false);
            };
            let parsed = parse_extensions(extensions)?;
            Ok(parsed.subject_alt_rfc822_names.contains(&mailbox))
        }
    }
}

/// Relevant fields from a strictly parsed X.509 `Extensions` value.
struct ParsedExtensions<'a> {
    /// Unique subject-key-identifier value.
    subject_key_identifier: Option<&'a [u8]>,
    /// Whether Basic Constraints asserts `cA`.
    basic_constraints_ca: bool,
    /// Optional Key Usage.
    key_usage: Option<ParsedKeyUsage>,
    /// Optional Extended Key Usage.
    extended_key_usage: Option<ParsedExtendedKeyUsage<'a>>,
    /// Validated SAN rfc822Name values, retained as exact wire bytes.
    subject_alt_rfc822_names: Vec<&'a [u8]>,
}

/// Timestamp-relevant Key Usage bits.
#[derive(Debug, Clone, Copy)]
struct ParsedKeyUsage {
    /// `digitalSignature` or `nonRepudiation` / `contentCommitment`.
    allows_timestamp_signature: bool,
    /// `keyCertSign` or `cRLSign`.
    allows_ca_signing: bool,
}

/// Strict EKU value and extension criticality.
struct ParsedExtendedKeyUsage<'a> {
    /// `KeyPurposeId` values.
    oids: Vec<crate::oid::Oid<'a>>,
    /// Extension critical flag.
    critical: bool,
}

/// Parse every Extension, reject duplicates, and retain the fields used
/// by signer selection and the TSA profile.
fn parse_extensions(extensions: &[u8]) -> Result<ParsedExtensions<'_>, TimestampError> {
    parse_extensions_with_policy(extensions, ExtensionBooleanPolicy::StrictDer)
}

/// Parse the extensions carried inside `TSTInfo`.
///
/// Sectigo's deployed qualified service writes the DEFAULT FALSE critical
/// field explicitly. Its meaning is unambiguous, but DER would omit it. Keep
/// that compatibility here; certificate extensions remain strict above.
fn parse_timestamp_extensions(extensions: &[u8]) -> Result<ParsedExtensions<'_>, TimestampError> {
    parse_extensions_with_policy(extensions, ExtensionBooleanPolicy::AllowExplicitFalse)
}

/// BOOLEAN compatibility permitted at one precisely chosen boundary.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ExtensionBooleanPolicy {
    /// RFC 5280 DER: absent is FALSE and the only encoded value is TRUE.
    StrictDer,
    /// Also admit an explicitly encoded FALSE in `TSTInfo` extensions.
    AllowExplicitFalse,
}

/// Parse extensions under the selected BOOLEAN encoding policy.
fn parse_extensions_with_policy(
    extensions: &[u8],
    boolean_policy: ExtensionBooleanPolicy,
) -> Result<ParsedExtensions<'_>, TimestampError> {
    let mut seen = Vec::new();
    let mut subject_key_identifier = None;
    let mut basic_constraints_ca = false;
    let mut key_usage = None;
    let mut extended_key_usage = None;
    let mut subject_alt_rfc822_names = Vec::new();

    for extension in BerTlvIter::new(extensions) {
        let extension = extension
            .map_err(|_ignored| TimestampError::Malformed("extension malformed"))?
            .expect::<Sequence>()
            .map_err(|_ignored| TimestampError::Malformed("extension is not SEQUENCE"))?;
        let mut fields = extension.iter_children();
        let oid = next_oid(&mut fields, "extension missing OID")?;
        let oid = crate::oid::Oid::new(oid.value)
            .map_err(|_ignored| TimestampError::Malformed("extension OID malformed"))?;
        if seen.contains(&oid) {
            return Err(TimestampError::Malformed("duplicate certificate extension"));
        }
        seen.push(oid);

        let next = next_any(&mut fields, "extension missing extnValue")?;
        let (critical, value) = if next.tag == <Boolean as BerTag>::TAG {
            let critical = match next.value {
                [DER_TRUE] => true,
                [BER_FALSE] if boolean_policy == ExtensionBooleanPolicy::AllowExplicitFalse => {
                    false
                }
                _ => {
                    return Err(TimestampError::Malformed(
                        "extension critical flag is not canonical DER TRUE",
                    ));
                }
            };
            let value = next_octet_string(&mut fields, "extension missing extnValue")?;
            (critical, value)
        } else {
            let value = next
                .expect::<OctetString>()
                .map_err(|_ignored| TimestampError::Malformed("extnValue is not OCTET STRING"))?;
            (false, value)
        };
        if fields.next().is_some() {
            return Err(TimestampError::Malformed("extension has trailing fields"));
        }

        if oid == known::SUBJECT_KEY_IDENTIFIER {
            let ski = parse_exact::<OctetString>(
                value.value,
                "subjectKeyIdentifier extension malformed",
            )?;
            if ski.value.is_empty() {
                return Err(TimestampError::Malformed(
                    "subjectKeyIdentifier extension is empty",
                ));
            }
            subject_key_identifier = Some(ski.value);
        } else if oid == known::BASIC_CONSTRAINTS {
            basic_constraints_ca = parse_basic_constraints(value.value)?;
        } else if oid == known::KEY_USAGE {
            key_usage = Some(parse_key_usage(value.value)?);
        } else if oid == known::EXT_KEY_USAGE {
            extended_key_usage = Some(parse_extended_key_usage(value.value, critical)?);
        } else if oid == known::SUBJECT_ALT_NAME {
            subject_alt_rfc822_names = parse_subject_alt_names(value.value, critical)?;
        } else if critical {
            return Err(TimestampError::Malformed(
                "unsupported critical TSA certificate extension",
            ));
        }
    }
    if seen.is_empty() {
        return Err(TimestampError::Malformed("Extensions is empty"));
    }
    Ok(ParsedExtensions {
        subject_key_identifier,
        basic_constraints_ca,
        key_usage,
        extended_key_usage,
        subject_alt_rfc822_names,
    })
}

/// Strictly parse SANs and retain the one name form this verifier compares.
fn parse_subject_alt_names(value: &[u8], critical: bool) -> Result<Vec<&[u8]>, TimestampError> {
    let outer = parse_exact::<Sequence>(value, "Subject Alternative Name malformed")?;
    let mut mailboxes = Vec::new();
    let mut saw_name = false;
    for name in outer.iter_children() {
        let name = name.map_err(|_ignored| TimestampError::Malformed("GeneralName malformed"))?;
        saw_name = true;
        if name.tag == TAG_RFC822_NAME {
            let mailbox = core::str::from_utf8(name.value)
                .map_err(|_ignored| TimestampError::Malformed("SAN rfc822Name is not UTF-8"))?;
            crate::identity::EmailAddress::new(mailbox)
                .map_err(|_ignored| TimestampError::Malformed("SAN rfc822Name malformed"))?;
            mailboxes.push(name.value);
        } else if critical {
            return Err(TimestampError::Malformed(
                "unsupported GeneralName in critical TSA SAN",
            ));
        }
    }
    if !saw_name {
        return Err(TimestampError::Malformed(
            "Subject Alternative Name is empty",
        ));
    }
    Ok(mailboxes)
}

/// Parse Basic Constraints and return its `cA` flag.
fn parse_basic_constraints(value: &[u8]) -> Result<bool, TimestampError> {
    let outer = parse_exact::<Sequence>(value, "Basic Constraints malformed")?;
    let mut fields = outer.iter_children();
    let mut ca = false;
    let mut next = fields
        .next()
        .transpose()
        .map_err(|_ignored| TimestampError::Malformed("Basic Constraints child malformed"))?;
    if next.is_some_and(|field| field.tag == <Boolean as BerTag>::TAG) {
        let flag = next.ok_or(TimestampError::Malformed("Basic Constraints cA missing"))?;
        if flag.value != [DER_TRUE] {
            return Err(TimestampError::Malformed(
                "Basic Constraints cA is not canonical DER TRUE",
            ));
        }
        ca = true;
        next = fields
            .next()
            .transpose()
            .map_err(|_ignored| TimestampError::Malformed("Basic Constraints pathLen malformed"))?;
    }
    if let Some(path_len) = next {
        let path_len = path_len.expect::<Integer>().map_err(|_ignored| {
            TimestampError::Malformed("Basic Constraints pathLen is not INTEGER")
        })?;
        if !ca || unsigned_integer(path_len.value).is_none() {
            return Err(TimestampError::Malformed(
                "Basic Constraints pathLen invalid",
            ));
        }
    }
    if fields.next().is_some() {
        return Err(TimestampError::Malformed(
            "Basic Constraints has trailing fields",
        ));
    }
    Ok(ca)
}

/// Parse Key Usage with DER named-bit-list canonicality checks.
fn parse_key_usage(value: &[u8]) -> Result<ParsedKeyUsage, TimestampError> {
    /// Any signing-capable bit accepted for a TSA key.
    const TIMESTAMP_SIGNATURE_MASK: u8 = 0xC0;
    /// CA-signing bits forbidden on a TSA end entity.
    const CA_SIGNING_MASK: u8 = 0x06;
    /// Only `decipherOnly` is defined in the second Key Usage octet.
    const SECOND_OCTET_UNKNOWN_MASK: u8 = 0x7F;

    let bit_string = parse_exact::<BitString>(value, "Key Usage malformed")?;
    validate_bit_string(bit_string.value, "Key Usage BIT STRING malformed")?;
    let unused = bit_string
        .value
        .first()
        .copied()
        .ok_or(TimestampError::Malformed("Key Usage BIT STRING empty"))?;
    let bits = bit_string
        .value
        .get(1..)
        .ok_or(TimestampError::Malformed("Key Usage BIT STRING empty"))?;
    if bits.is_empty() || bits.len() > 2 {
        return Err(TimestampError::Malformed("Key Usage width invalid"));
    }
    let last = bits
        .last()
        .copied()
        .ok_or(TimestampError::Malformed("Key Usage BIT STRING empty"))?;
    if last == 0 || last.trailing_zeros() != u32::from(unused) {
        return Err(TimestampError::Malformed(
            "Key Usage named bits are not DER-minimal",
        ));
    }
    let first = bits.first().copied().unwrap_or(0);
    let second = bits.get(1).copied().unwrap_or(0);
    if second & SECOND_OCTET_UNKNOWN_MASK != 0 {
        return Err(TimestampError::Malformed("Key Usage has unknown bits"));
    }
    Ok(ParsedKeyUsage {
        allows_timestamp_signature: first & TIMESTAMP_SIGNATURE_MASK != 0,
        allows_ca_signing: first & CA_SIGNING_MASK != 0,
    })
}

/// Parse Extended Key Usage.
fn parse_extended_key_usage(
    value: &[u8],
    critical: bool,
) -> Result<ParsedExtendedKeyUsage<'_>, TimestampError> {
    let outer = parse_exact::<Sequence>(value, "Extended Key Usage malformed")?;
    let mut oids = Vec::new();
    for oid in outer.iter_children() {
        let oid = oid
            .map_err(|_ignored| TimestampError::Malformed("EKU entry malformed"))?
            .expect::<BerOid>()
            .map_err(|_ignored| TimestampError::Malformed("EKU entry is not OID"))?;
        let oid = crate::oid::Oid::new(oid.value)
            .map_err(|_ignored| TimestampError::Malformed("EKU OID malformed"))?;
        if oids.contains(&oid) {
            return Err(TimestampError::Malformed("duplicate EKU OID"));
        }
        oids.push(oid);
    }
    if oids.is_empty() {
        return Err(TimestampError::Malformed("Extended Key Usage is empty"));
    }
    Ok(ParsedExtendedKeyUsage { oids, critical })
}

/// ESS certificate-hash algorithm.
#[derive(Debug, Clone, Copy)]
enum EssHashAlgorithm {
    /// SHA-1, fixed by `ESSCertID`.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl EssHashAlgorithm {
    /// Digest a complete certificate DER value.
    fn digest(self, input: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => Sha1::digest(input).to_vec(),
            Self::Sha256 => Sha256::digest(input).to_vec(),
            Self::Sha384 => Sha384::digest(input).to_vec(),
            Self::Sha512 => Sha512::digest(input).to_vec(),
        }
    }
}

/// Parsed ESS certificate reference.
struct EssCertificateReference<'a> {
    /// Certificate digest algorithm.
    hash_algorithm: EssHashAlgorithm,
    /// Certificate digest bytes.
    cert_hash: &'a [u8],
    /// Optional `IssuerSerial` SEQUENCE body.
    issuer_serial: Option<&'a [u8]>,
}

/// Verify the unique signed `signingCertificate` or
/// `signingCertificateV2` attribute against the selected signer.
fn verify_signing_certificate_attribute(
    signed_data: &SignedData<'_>,
    certificate: &Certificate<'_>,
) -> Result<(), TimestampError> {
    let v1: Vec<&SignedAttribute<'_>> = signed_data
        .signer
        .signed_attributes
        .iter()
        .filter(|attribute| attribute.oid == known::SIGNING_CERTIFICATE)
        .collect();
    let v2: Vec<&SignedAttribute<'_>> = signed_data
        .signer
        .signed_attributes
        .iter()
        .filter(|attribute| attribute.oid == known::SIGNING_CERTIFICATE_V2)
        .collect();
    let (attribute, v2) = match (v1.as_slice(), v2.as_slice()) {
        ([attribute], []) => (*attribute, false),
        ([], [attribute]) => (*attribute, true),
        _ => return Err(TimestampError::SigningCertificateAttributeInvalid),
    };

    let value = parse_exact::<Sequence>(
        attribute.values_der,
        "ESS attribute must have exactly one value",
    )
    .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?;
    let mut fields = value.iter_children();
    let certs = fields
        .next()
        .ok_or(TimestampError::SigningCertificateAttributeInvalid)?
        .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?
        .expect::<Sequence>()
        .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?;

    let mut references = certs.iter_children();
    let first = references
        .next()
        .ok_or(TimestampError::SigningCertificateAttributeInvalid)?
        .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?
        .expect::<Sequence>()
        .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?;
    let first = parse_ess_certificate_reference(first.value, v2)?;
    if first.hash_algorithm.digest(certificate.raw_der) != first.cert_hash {
        return Err(TimestampError::SigningCertificateAttributeInvalid);
    }
    if let Some(issuer_serial) = first.issuer_serial
        && !issuer_serial_matches(issuer_serial, certificate)?
    {
        return Err(TimestampError::SigningCertificateAttributeInvalid);
    }
    for reference in references {
        let reference = reference
            .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?
            .expect::<Sequence>()
            .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?;
        parse_ess_certificate_reference(reference.value, v2)?;
    }

    if let Some(policies) = fields.next() {
        let policies = policies
            .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?
            .expect::<Sequence>()
            .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?;
        let mut count = 0_usize;
        for policy in policies.iter_children() {
            policy
                .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?
                .expect::<Sequence>()
                .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?;
            count = count.saturating_add(1);
        }
        if count == 0 {
            return Err(TimestampError::SigningCertificateAttributeInvalid);
        }
    }
    if fields.next().is_some() {
        return Err(TimestampError::SigningCertificateAttributeInvalid);
    }
    Ok(())
}

/// Parse one `ESSCertID` or `ESSCertIDv2`.
fn parse_ess_certificate_reference(
    body: &[u8],
    v2: bool,
) -> Result<EssCertificateReference<'_>, TimestampError> {
    let mut fields = BerTlvIter::new(body);
    let first = fields
        .next()
        .ok_or(TimestampError::SigningCertificateAttributeInvalid)?
        .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?;
    let (hash_algorithm, cert_hash) = if v2 && first.tag == <Sequence as BerTag>::TAG {
        let algorithm = first
            .expect::<Sequence>()
            .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?;
        let oid = parse_algorithm_identifier(algorithm.value)
            .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?;
        let algorithm = match oid.value {
            value if value == known::SHA1.as_bytes() => EssHashAlgorithm::Sha1,
            value if value == known::SHA256.as_bytes() => EssHashAlgorithm::Sha256,
            value if value == known::SHA384.as_bytes() => EssHashAlgorithm::Sha384,
            value if value == known::SHA512.as_bytes() => EssHashAlgorithm::Sha512,
            _ => return Err(TimestampError::SigningCertificateAttributeInvalid),
        };
        let hash = fields
            .next()
            .ok_or(TimestampError::SigningCertificateAttributeInvalid)?
            .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?
            .expect::<OctetString>()
            .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?;
        (algorithm, hash.value)
    } else {
        let hash = first
            .expect::<OctetString>()
            .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?;
        (
            if v2 {
                EssHashAlgorithm::Sha256
            } else {
                EssHashAlgorithm::Sha1
            },
            hash.value,
        )
    };
    if cert_hash.is_empty() {
        return Err(TimestampError::SigningCertificateAttributeInvalid);
    }
    let issuer_serial = match fields.next() {
        None => None,
        Some(issuer_serial) => Some(
            issuer_serial
                .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?
                .expect::<Sequence>()
                .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?
                .value,
        ),
    };
    if fields.next().is_some() {
        return Err(TimestampError::SigningCertificateAttributeInvalid);
    }
    if let Some(issuer_serial) = issuer_serial {
        validate_issuer_serial(issuer_serial)?;
    }
    Ok(EssCertificateReference {
        hash_algorithm,
        cert_hash,
        issuer_serial,
    })
}

/// Validate an ESS `IssuerSerial` structurally.
fn validate_issuer_serial(body: &[u8]) -> Result<(), TimestampError> {
    let mut fields = BerTlvIter::new(body);
    let names = fields
        .next()
        .ok_or(TimestampError::SigningCertificateAttributeInvalid)?
        .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?
        .expect::<Sequence>()
        .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?;
    let mut name_count = 0_usize;
    for name in names.iter_children() {
        let name = name.map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?;
        if name.tag == TAG_DIRECTORY_NAME {
            parse_exact::<Sequence>(name.value, "ESS directoryName malformed")
                .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?;
        }
        name_count = name_count.saturating_add(1);
    }
    let serial = fields
        .next()
        .ok_or(TimestampError::SigningCertificateAttributeInvalid)?
        .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?
        .expect::<Integer>()
        .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?;
    if name_count == 0 || !nonnegative_der_integer(serial.value) || fields.next().is_some() {
        return Err(TimestampError::SigningCertificateAttributeInvalid);
    }
    Ok(())
}

/// Compare an optional ESS `IssuerSerial` with the selected certificate.
fn issuer_serial_matches(
    body: &[u8],
    certificate: &Certificate<'_>,
) -> Result<bool, TimestampError> {
    validate_issuer_serial(body)?;
    let mut fields = BerTlvIter::new(body);
    let names = fields
        .next()
        .ok_or(TimestampError::SigningCertificateAttributeInvalid)?
        .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?
        .expect::<Sequence>()
        .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?;
    let issuer_matches = names.iter_children().any(|name| {
        name.is_ok_and(|name| {
            name.tag == TAG_DIRECTORY_NAME && name.value == certificate.issuer.as_der()
        })
    });
    let serial = fields
        .next()
        .ok_or(TimestampError::SigningCertificateAttributeInvalid)?
        .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?
        .expect::<Integer>()
        .map_err(|_ignored| TimestampError::SigningCertificateAttributeInvalid)?;
    Ok(issuer_matches && serial.value == certificate.serial_der)
}

/// Parse one exact typed TLV.
fn parse_exact<'a, T: BerTag>(
    input: &'a [u8],
    malformed: &'static str,
) -> Result<BerTlv<'a, T>, TimestampError> {
    let value =
        BerTlv::<T>::parse(input).map_err(|_ignored| TimestampError::Malformed(malformed))?;
    if value.size != input.len() {
        return Err(TimestampError::Malformed(malformed));
    }
    Ok(value)
}

/// Validate a DER BIT STRING body, including unused-bit zeroing.
fn validate_bit_string(value: &[u8], malformed: &'static str) -> Result<(), TimestampError> {
    let unused = value
        .first()
        .copied()
        .ok_or(TimestampError::Malformed(malformed))?;
    if unused > 7 {
        return Err(TimestampError::Malformed(malformed));
    }
    let bits = value.get(1..).ok_or(TimestampError::Malformed(malformed))?;
    if bits.is_empty() {
        return (unused == 0)
            .then_some(())
            .ok_or(TimestampError::Malformed(malformed));
    }
    let mask = if unused == 0 {
        0
    } else {
        (1_u8 << unused).saturating_sub(1)
    };
    if bits.last().is_none_or(|last| last & mask != 0) {
        return Err(TimestampError::Malformed(malformed));
    }
    Ok(())
}

/// Whether an INTEGER body is canonical DER and non-negative.
fn nonnegative_der_integer(value: &[u8]) -> bool {
    let Some((&first, rest)) = value.split_first() else {
        return false;
    };
    if first & 0x80 != 0 {
        return false;
    }
    if first == 0 && rest.first().is_some_and(|second| second & 0x80 == 0) {
        return false;
    }
    true
}

fn next_any<'a>(
    it: &mut BerTlvIter<'a>,
    missing: &'static str,
) -> Result<BerTlvAny<'a>, TimestampError> {
    it.next()
        .ok_or(TimestampError::Malformed(missing))?
        .map_err(|_ignored| TimestampError::Malformed(missing))
}

fn next_integer<'a>(
    it: &mut BerTlvIter<'a>,
    missing: &'static str,
) -> Result<BerTlv<'a, Integer>, TimestampError> {
    next_any(it, missing)?
        .expect::<Integer>()
        .map_err(|_ignored| TimestampError::Malformed(missing))
}

fn next_oid<'a>(
    it: &mut BerTlvIter<'a>,
    missing: &'static str,
) -> Result<BerTlv<'a, BerOid>, TimestampError> {
    next_any(it, missing)?
        .expect::<BerOid>()
        .map_err(|_ignored| TimestampError::Malformed(missing))
}

fn next_sequence<'a>(
    it: &mut BerTlvIter<'a>,
    missing: &'static str,
) -> Result<BerTlv<'a, Sequence>, TimestampError> {
    next_any(it, missing)?
        .expect::<Sequence>()
        .map_err(|_ignored| TimestampError::Malformed(missing))
}

fn next_octet_string<'a>(
    it: &mut BerTlvIter<'a>,
    missing: &'static str,
) -> Result<BerTlv<'a, OctetString>, TimestampError> {
    next_any(it, missing)?
        .expect::<OctetString>()
        .map_err(|_ignored| TimestampError::Malformed(missing))
}

/// Total encoded length of the `PKIStatusInfo` at the front of `body`.
fn status_info_size(body: &[u8]) -> Result<usize, TimestampError> {
    BerTlvAny::parse(body)
        .map(|tlv| tlv.size)
        .map_err(|_ignored| TimestampError::Malformed("no PKIStatusInfo"))
}

/// A small DER INTEGER as a `u64`, or `None` if it will not fit.
fn unsigned_integer(value: &[u8]) -> Option<u64> {
    /// Widest INTEGER body a `u64` can hold, allowing a sign octet.
    const MAX_BODY: usize = 9;
    if !nonnegative_der_integer(value) || value.len() > MAX_BODY {
        return None;
    }
    let mut out = 0_u64;
    for byte in value {
        out = out.checked_mul(0x100)?.checked_add(u64::from(*byte))?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{
        BER_FALSE, DER_TRUE, TAG_BOOLEAN, TAG_OCTET_STRING, TAG_SEQUENCE, TimestampError,
        parse_basic_constraints, parse_extensions, parse_subject_alt_names,
        parse_timestamp_extensions, parse_tst_info, positive_integer, request,
        select_signer_certificate, token, tsa_certificate_is_usable, tsa_name_matches_certificate,
        verified_token, verify_signing_certificate_attribute,
    };
    use crate::ber::{BerTlvAny, Oid as BerOid, tlv};
    use crate::cms::{SignedData, SignerIdentifier};
    use crate::oid::known;
    use crate::sign::cades::DigestAlgorithm;
    use crate::x509::{Certificate, DateTime};

    /// Locally generated ECDSA RFC 3161 token. It deliberately embeds
    /// the same signer certificate twice, exercising duplicate-DER
    /// de-duplication without creating signer ambiguity.
    const TIMESTAMP_TOKEN_HEX: &str = "\
        3082059806092a864886f70d010702a082058930820585020103310f300d060960864801650304020105003081b0060b2a864886f70d0109100104a081a004819d30819a02010106032a03043041300d06096086480165030402020500043038\
        b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b020101180f32303236303830343037353332355a300a020101800201f48101640101ff02087ed2094220bf4c2fa020a41e\
        301c311a301806035504030c11526546696e654944205465737420545341a082036e308201b330820158a00302010202143077c4fc699d4af1b7f82411c474a71737cfd88c300a06082a8648ce3d040302301c311a301806035504030c115265\
        46696e654944205465737420545341301e170d3236303830343037353332355a170d3336303830313037353332355a301c311a301806035504030c11526546696e6549442054657374205453413059301306072a8648ce3d020106082a8648ce\
        3d03010703420004499aff663c52acc174d8bdbe52e8150f961c55bc3c24eeebb374926863975f04bb49048d3aed17acb9c05d555dff64b457675095fe473e85112e3d9301bb703ba3783076301d0603551d0e04160414d8f8beb89ad21c40c5\
        124fd26fd9709a44d78b9b301f0603551d23041830168014d8f8beb89ad21c40c5124fd26fd9709a44d78b9b300c0603551d130101ff04023000300e0603551d0f0101ff0404030206c030160603551d250101ff040c300a06082b0601050507\
        0308300a06082a8648ce3d0403020349003046022100c2fc9f9a589bc7a3dff0a9ab63b55f818c316ebe7a03cd110736bf27870f625102210098b22e62a20207d43ac51840c10eb52b8da6a77cc397a7c1a2b618c833dee886308201b3308201\
        58a00302010202143077c4fc699d4af1b7f82411c474a71737cfd88c300a06082a8648ce3d040302301c311a301806035504030c11526546696e654944205465737420545341301e170d3236303830343037353332355a170d33363038303130\
        37353332355a301c311a301806035504030c11526546696e6549442054657374205453413059301306072a8648ce3d020106082a8648ce3d03010703420004499aff663c52acc174d8bdbe52e8150f961c55bc3c24eeebb374926863975f04bb\
        49048d3aed17acb9c05d555dff64b457675095fe473e85112e3d9301bb703ba3783076301d0603551d0e04160414d8f8beb89ad21c40c5124fd26fd9709a44d78b9b301f0603551d23041830168014d8f8beb89ad21c40c5124fd26fd9709a44\
        d78b9b300c0603551d130101ff04023000300e0603551d0f0101ff0404030206c030160603551d250101ff040c300a06082b06010505070308300a06082a8648ce3d0403020349003046022100c2fc9f9a589bc7a3dff0a9ab63b55f818c316e\
        be7a03cd110736bf27870f625102210098b22e62a20207d43ac51840c10eb52b8da6a77cc397a7c1a2b618c833dee88631820148308201440201013034301c311a301806035504030c11526546696e65494420546573742054534102143077c4\
        fc699d4af1b7f82411c474a71737cfd88c300d06096086480165030402010500a081a4301a06092a864886f70d010903310d060b2a864886f70d0109100104301c06092a864886f70d010905310f170d3236303830343037353332355a302f06\
        092a864886f70d0109043122042009fb1854c4329c0ec28f3e36d3e525db4ccd62ee1d9669485242b637c6bae9dc3037060b2a864886f70d010910022f31283026302430220420e0c8e5e288bd9b94630097cd0937e1d6e3397bb7e4dc5469f2\
        a5151402a24748300a06082a8648ce3d04030204473045022100d6ccde399b1dd61a96d549a47d9d011fead6b02c6a6285d452edf0fad999792402206ec63c57bc92af50d9ce80e8730e9760ccf255242ed6a394a90806223319bc56";

    const TIMESTAMP_CERTIFICATE_HEX: &str = "\
        308201b330820158a00302010202143077c4fc699d4af1b7f82411c474a71737cfd88c300a06082a8648ce3d040302301c311a301806035504030c11526546696e654944205465737420545341301e170d3236303830343037353332355a170d\
        3336303830313037353332355a301c311a301806035504030c11526546696e6549442054657374205453413059301306072a8648ce3d020106082a8648ce3d03010703420004499aff663c52acc174d8bdbe52e8150f961c55bc3c24eeebb374\
        926863975f04bb49048d3aed17acb9c05d555dff64b457675095fe473e85112e3d9301bb703ba3783076301d0603551d0e04160414d8f8beb89ad21c40c5124fd26fd9709a44d78b9b301f0603551d23041830168014d8f8beb89ad21c40c512\
        4fd26fd9709a44d78b9b300c0603551d130101ff04023000300e0603551d0f0101ff0404030206c030160603551d250101ff040c300a06082b06010505070308300a06082a8648ce3d0403020349003046022100c2fc9f9a589bc7a3dff0a9ab\
        63b55f818c316ebe7a03cd110736bf27870f625102210098b22e62a20207d43ac51840c10eb52b8da6a77cc397a7c1a2b618c833dee886";

    const INTERMEDIATE_CERTIFICATE_DER: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../refineid-client/test-vectors/fineid-intermediate-01-citizen-g4e.der"
    ));

    const EMPTY_SHA384_HEX: &str = "\
        38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
        274edebfe76f65fbd51ad2f14898b95b";
    const TIMESTAMP_NONCE_HEX: &str = "7ed2094220bf4c2f";

    fn unhex(hex_fixture: &str) -> Vec<u8> {
        let cleaned: String = hex_fixture
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect();
        hex::decode(cleaned).expect("fixture hex decodes")
    }

    fn granted_response(token_der: &[u8]) -> Vec<u8> {
        let status = tlv(0x30, tlv(0x02, [0x00_u8]));
        let mut body = status;
        body.extend_from_slice(token_der);
        tlv(0x30, body)
    }

    fn certificate_extension(oid: const_oid::ObjectIdentifier, critical: bool) -> Vec<u8> {
        let oid_tag = u8::try_from(<BerOid as crate::ber::BerTag>::TAG)
            .expect("universal OID tag fits in one octet");
        let mut body = tlv(oid_tag, oid.as_bytes());
        if critical {
            body.extend_from_slice(&tlv(TAG_BOOLEAN, [DER_TRUE]));
        }
        body.extend_from_slice(&tlv(TAG_OCTET_STRING, tlv(TAG_SEQUENCE, Vec::<u8>::new())));
        tlv(TAG_SEQUENCE, body)
    }

    fn split_tlvs(mut encoded: &[u8]) -> Vec<&[u8]> {
        let mut children = Vec::new();
        while !encoded.is_empty() {
            let child = BerTlvAny::parse(encoded).expect("fixture child TLV parses");
            let (child_der, rest) = encoded.split_at(child.size);
            children.push(child_der);
            encoded = rest;
        }
        children
    }

    /// Add two copies of a certificate without changing any signed CMS data.
    fn token_with_extra_certificate(token_der: &[u8], extra_der: &[u8]) -> Vec<u8> {
        let content_info = BerTlvAny::parse(token_der).expect("ContentInfo parses");
        assert_eq!(content_info.tag, 0x30);
        assert_eq!(content_info.size, token_der.len());
        let content_info_fields = split_tlvs(content_info.value);
        assert_eq!(content_info_fields.len(), 2);

        let explicit = BerTlvAny::parse(content_info_fields[1]).expect("[0] content parses");
        assert_eq!(explicit.tag, 0xA0);
        let signed_data = BerTlvAny::parse(explicit.value).expect("SignedData parses");
        assert_eq!(signed_data.tag, 0x30);
        assert_eq!(signed_data.size, explicit.value.len());

        let mut replaced_certificates = false;
        let mut signed_data_body = Vec::new();
        for field_der in split_tlvs(signed_data.value) {
            let field = BerTlvAny::parse(field_der).expect("SignedData field parses");
            if field.tag == super::TAG_CONTEXT_0_CONSTRUCTED && !replaced_certificates {
                let mut certificates = split_tlvs(field.value);
                certificates.push(extra_der);
                certificates.push(extra_der);
                certificates.sort_unstable();
                let mut certificate_body = Vec::new();
                for certificate_der in certificates {
                    certificate_body.extend_from_slice(certificate_der);
                }
                signed_data_body.extend_from_slice(&tlv(0xA0, certificate_body));
                replaced_certificates = true;
            } else {
                signed_data_body.extend_from_slice(field_der);
            }
        }
        assert!(replaced_certificates, "fixture carries certificates");

        let mut content_info_body = content_info_fields[0].to_vec();
        content_info_body.extend_from_slice(&tlv(0xA0, tlv(0x30, signed_data_body)));
        tlv(0x30, content_info_body)
    }

    fn fixture_time() -> DateTime {
        DateTime::new(2026, 8, 4, 7, 53, 25).expect("valid fixture time")
    }

    #[test]
    fn returned_token_signature_sid_ess_profile_and_time_are_verified() {
        let token_der = unhex(TIMESTAMP_TOKEN_HEX);
        let response = granted_response(&token_der);
        let digest = unhex(EMPTY_SHA384_HEX);
        let nonce = unhex(TIMESTAMP_NONCE_HEX);

        let verified = verified_token(&response, &digest, DigestAlgorithm::Sha384, Some(&nonce))
            .expect("fixture token verifies");
        assert_eq!(verified.token, token_der);
        assert_eq!(
            verified.signer_certificate,
            unhex(TIMESTAMP_CERTIFICATE_HEX)
        );
        assert_eq!(
            verified.embedded_certificates,
            vec![unhex(TIMESTAMP_CERTIFICATE_HEX)],
            "duplicate signer DER is retained once"
        );
        assert_eq!(verified.generated_at, fixture_time());
        assert_eq!(
            token(&response, &digest, DigestAlgorithm::Sha384, Some(&nonce))
                .expect("compatibility wrapper verifies"),
            verified.token
        );
    }

    #[test]
    fn embedded_signer_and_intermediate_certificates_are_retained_once() {
        let token_der =
            token_with_extra_certificate(&unhex(TIMESTAMP_TOKEN_HEX), INTERMEDIATE_CERTIFICATE_DER);
        let response = granted_response(&token_der);
        let verified = verified_token(
            &response,
            &unhex(EMPTY_SHA384_HEX),
            DigestAlgorithm::Sha384,
            Some(&unhex(TIMESTAMP_NONCE_HEX)),
        )
        .expect("token with an embedded intermediate verifies");

        let signer = unhex(TIMESTAMP_CERTIFICATE_HEX);
        assert_eq!(verified.signer_certificate, signer);
        assert_eq!(verified.embedded_certificates.len(), 2);
        assert!(
            verified
                .embedded_certificates
                .iter()
                .any(|certificate| certificate == &verified.signer_certificate),
            "signer certificate is retained"
        );
        assert!(
            verified
                .embedded_certificates
                .iter()
                .any(|certificate| certificate == INTERMEDIATE_CERTIFICATE_DER),
            "intermediate certificate is retained"
        );
    }

    #[test]
    fn response_and_tst_info_require_complete_der_consumption() {
        let token_der = unhex(TIMESTAMP_TOKEN_HEX);
        let mut response = granted_response(&token_der);
        response.push(0x00);
        assert!(matches!(
            verified_token(&response, &[], DigestAlgorithm::Sha384, None),
            Err(TimestampError::Malformed(
                "trailing bytes after TimeStampResp"
            ))
        ));

        let signed_data = SignedData::parse(&token_der).expect("fixture CMS parses");
        let mut tst_info = signed_data.econtent_der.to_vec();
        tst_info.push(0x00);
        assert!(matches!(
            parse_tst_info(&tst_info),
            Err(TimestampError::Malformed("trailing bytes after TSTInfo"))
        ));
    }

    #[test]
    fn tampered_timestamp_signature_is_rejected() {
        let mut token_der = unhex(TIMESTAMP_TOKEN_HEX);
        let last = token_der.last_mut().expect("signature byte exists");
        *last ^= 0x01;
        let response = granted_response(&token_der);
        assert_eq!(
            verified_token(
                &response,
                &unhex(EMPTY_SHA384_HEX),
                DigestAlgorithm::Sha384,
                Some(&unhex(TIMESTAMP_NONCE_HEX)),
            ),
            Err(TimestampError::TokenSignatureInvalid)
        );
    }

    #[test]
    fn sid_must_select_one_distinct_embedded_certificate() {
        let token_der = unhex(TIMESTAMP_TOKEN_HEX);
        let mut signed_data = SignedData::parse(&token_der).expect("fixture CMS parses");
        // The fixture embeds the same DER twice. That is one distinct
        // certificate, not an ambiguity.
        select_signer_certificate(&signed_data).expect("duplicate DER is de-duplicated");

        signed_data.signer.signer_identifier =
            SignerIdentifier::SubjectKeyIdentifier(b"not-the-signer");
        assert!(matches!(
            select_signer_certificate(&signed_data),
            Err(TimestampError::NoMatchingTsaCertificate)
        ));
    }

    #[test]
    fn signed_ess_attribute_must_hash_the_selected_certificate() {
        let token_der = unhex(TIMESTAMP_TOKEN_HEX);
        let signed_data = SignedData::parse(&token_der).expect("fixture CMS parses");
        let certificate = select_signer_certificate(&signed_data).expect("signer selected");
        verify_signing_certificate_attribute(&signed_data, &certificate)
            .expect("fixture ESS binding matches");

        let mut different_der = unhex(TIMESTAMP_CERTIFICATE_HEX);
        let last = different_der
            .last_mut()
            .expect("certificate signature byte");
        *last ^= 0x01;
        let different = Certificate::from_der(&different_der).expect("mutated cert still parses");
        assert_eq!(
            verify_signing_certificate_attribute(&signed_data, &different),
            Err(TimestampError::SigningCertificateAttributeInvalid)
        );

        let mut missing = signed_data.clone();
        missing.signer.signed_attributes.retain(|attribute| {
            attribute.oid != known::SIGNING_CERTIFICATE
                && attribute.oid != known::SIGNING_CERTIFICATE_V2
        });
        assert_eq!(
            verify_signing_certificate_attribute(&missing, &certificate),
            Err(TimestampError::SigningCertificateAttributeInvalid)
        );
    }

    #[test]
    fn tsa_profile_enforces_end_entity_key_purpose_usage_and_gen_time() {
        let certificate_der = unhex(TIMESTAMP_CERTIFICATE_HEX);
        let certificate = Certificate::from_der(&certificate_der).expect("fixture cert parses");
        tsa_certificate_is_usable(&certificate, fixture_time()).expect("fixture profile is valid");

        let before_validity = DateTime::new(2026, 8, 4, 7, 53, 24).expect("valid time");
        assert_eq!(
            tsa_certificate_is_usable(&certificate, before_validity),
            Err(TimestampError::NoUsableTsaCertificate)
        );

        let ca_constraints = tlv(0x30, tlv(0x01, [0xFF_u8]));
        assert!(parse_basic_constraints(&ca_constraints).expect("CA constraints parse"));

        // Replace digitalSignature|contentCommitment with keyCertSign,
        // retaining the same DER width so the surrounding certificate
        // remains parseable.
        let mut ca_usage_der = certificate_der.clone();
        let usage = [0x03_u8, 0x02, 0x06, 0xC0];
        let usage_at = ca_usage_der
            .windows(usage.len())
            .position(|window| window == usage)
            .expect("fixture Key Usage found");
        ca_usage_der[usage_at.saturating_add(2)] = 0x01;
        ca_usage_der[usage_at.saturating_add(3)] = 0x04;
        let ca_usage = Certificate::from_der(&ca_usage_der).expect("mutated cert parses");
        assert_eq!(
            tsa_certificate_is_usable(&ca_usage, fixture_time()),
            Err(TimestampError::NoUsableTsaCertificate)
        );

        // Change id-kp-timeStamping to the adjacent OCSP-signing OID.
        let mut wrong_eku_der = certificate_der;
        let eku = [
            0x06_u8, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08,
        ];
        let eku_at = wrong_eku_der
            .windows(eku.len())
            .position(|window| window == eku)
            .expect("fixture EKU found");
        wrong_eku_der[eku_at.saturating_add(9)] = 0x09;
        let wrong_eku = Certificate::from_der(&wrong_eku_der).expect("mutated cert parses");
        assert_eq!(
            tsa_certificate_is_usable(&wrong_eku, fixture_time()),
            Err(TimestampError::NoUsableTsaCertificate)
        );
    }

    #[test]
    fn tsa_certificate_parser_rejects_unknown_critical_extensions() {
        let private_extension = const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.1");
        let noncritical = certificate_extension(private_extension, false);
        parse_extensions(&noncritical).expect("unknown non-critical extension may be ignored");

        let critical = certificate_extension(private_extension, true);
        assert_eq!(
            parse_extensions(&critical).err(),
            Some(TimestampError::Malformed(
                "unsupported critical TSA certificate extension"
            ))
        );
    }

    #[test]
    fn tst_info_accepts_sectigo_explicit_false_without_weakening_certificates() {
        let private_extension = const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.2");
        let oid_tag = u8::try_from(<BerOid as crate::ber::BerTag>::TAG)
            .expect("universal OID tag fits in one octet");
        let mut body = tlv(oid_tag, private_extension.as_bytes());
        body.extend_from_slice(&tlv(TAG_BOOLEAN, [BER_FALSE]));
        body.extend_from_slice(&tlv(TAG_OCTET_STRING, tlv(TAG_SEQUENCE, Vec::<u8>::new())));
        let extension = tlv(TAG_SEQUENCE, body);

        parse_timestamp_extensions(&extension)
            .expect("deployed TSTInfo explicit FALSE is semantically non-critical");
        assert_eq!(
            parse_extensions(&extension).err(),
            Some(TimestampError::Malformed(
                "extension critical flag is not canonical DER TRUE"
            )),
            "certificate extension parsing remains strict DER"
        );
    }

    #[test]
    fn a_request_carries_the_digest_and_asks_for_the_certificate() {
        let digest = DigestAlgorithm::Sha256.digest(b"a signature value");
        let der = request(&digest, DigestAlgorithm::Sha256, Some(&[0x01, 0x02]), true);
        assert_eq!(der.first(), Some(&0x30), "a TimeStampReq is a SEQUENCE");
        // The digest travels verbatim inside the message imprint.
        assert!(
            der.windows(digest.len()).any(|window| window == digest),
            "the digest must be in the request"
        );
        // certReq TRUE is DER 01 01 FF.
        assert!(
            der.windows(3).any(|window| window == [0x01, 0x01, 0xFF]),
            "certReq must be asserted"
        );
        // Omitting it entirely is also legal; DEFAULT FALSE is not written.
        let without = request(&digest, DigestAlgorithm::Sha256, None, false);
        assert!(
            !without
                .windows(3)
                .any(|window| window == [0x01, 0x01, 0xFF])
        );
    }

    /// A nonce is random, so half the time its top bit is set. Written
    /// raw, DER would read that as a negative integer.
    #[test]
    fn a_high_nonce_stays_positive() {
        let der = request(
            &[0_u8; 32],
            DigestAlgorithm::Sha256,
            Some(&[0xFF, 0x01]),
            false,
        );
        assert!(
            der.windows(5)
                .any(|window| window == [0x02, 0x03, 0x00, 0xFF, 0x01]),
            "a leading zero keeps the nonce non-negative"
        );
    }

    #[test]
    fn a_rejection_is_not_mistaken_for_a_token() {
        // TimeStampResp { PKIStatusInfo { status 2 } }, no token.
        let rejected = [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02];
        assert_eq!(
            token(&rejected, &[], DigestAlgorithm::Sha256, None),
            Err(TimestampError::Rejected { status: 2 })
        );

        // Granted, but nothing followed.
        let empty = [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00];
        assert_eq!(
            token(&empty, &[], DigestAlgorithm::Sha256, None),
            Err(TimestampError::NoToken)
        );

        assert!(matches!(
            token(&[0x02, 0x01, 0x00], &[], DigestAlgorithm::Sha256, None),
            Err(TimestampError::Malformed(_))
        ));
    }

    #[test]
    fn a_granted_response_must_carry_a_real_token() {
        // Granted, followed by a stand-in token TLV.
        let mut response = vec![0x30, 0x0B, 0x30, 0x03, 0x02, 0x01, 0x00];
        let token_der = [0x30, 0x04, 0x04, 0x02, 0xAA, 0xBB];
        response.extend_from_slice(&token_der);
        assert!(matches!(
            token(&response, &[0xAA, 0xBB], DigestAlgorithm::Sha256, None),
            Err(TimestampError::Malformed(_))
        ));
    }

    #[test]
    fn tst_info_is_parsed_for_imprint_algorithm_and_nonce() {
        let digest = DigestAlgorithm::Sha256.digest(b"signature value");
        let nonce = [0x80, 0x01];
        let der = tst_info(&digest, DigestAlgorithm::Sha256, Some(&nonce));
        let parsed = parse_tst_info(&der).expect("TSTInfo parses");
        assert_eq!(parsed.imprint_algorithm_oid, known::SHA256.as_bytes());
        assert_eq!(parsed.message_imprint, digest);
        let expected_nonce = positive_integer(&nonce);
        assert_eq!(parsed.nonce, Some(expected_nonce.as_slice()));
    }

    #[test]
    fn tst_info_tsa_directory_name_is_exactly_bound_to_signer_subject() {
        let certificate_der = unhex(TIMESTAMP_CERTIFICATE_HEX);
        let certificate = Certificate::from_der(&certificate_der).expect("certificate");
        let digest = DigestAlgorithm::Sha256.digest(b"signature value");
        let matching_name = tlv(0xA4, certificate.subject.as_der());
        let der = tst_info_with_tsa(&digest, DigestAlgorithm::Sha256, None, Some(&matching_name));
        let parsed = parse_tst_info(&der).expect("TSTInfo parses");
        assert!(
            tsa_name_matches_certificate(parsed.tsa.expect("tsa name"), certificate)
                .expect("certificate extensions parse")
        );

        let different_name = tlv(0xA4, tlv(TAG_SEQUENCE, []));
        let der = tst_info_with_tsa(
            &digest,
            DigestAlgorithm::Sha256,
            None,
            Some(&different_name),
        );
        let parsed = parse_tst_info(&der).expect("different valid Name parses");
        let certificate = Certificate::from_der(&certificate_der).expect("certificate");
        assert!(
            !tsa_name_matches_certificate(parsed.tsa.expect("tsa name"), certificate)
                .expect("certificate extensions parse")
        );
    }

    #[test]
    fn unsupported_tst_info_tsa_general_name_fails_closed() {
        let digest = DigestAlgorithm::Sha256.digest(b"signature value");
        let uri_name = tlv(0x86, b"https://tsa.invalid/");
        let der = tst_info_with_tsa(&digest, DigestAlgorithm::Sha256, None, Some(&uri_name));
        assert!(matches!(
            parse_tst_info(&der),
            Err(TimestampError::Malformed(
                "unsupported TSTInfo tsa GeneralName"
            ))
        ));
    }

    #[test]
    fn tsa_rfc822_name_comparison_is_validated_and_byte_exact() {
        let mailbox = b"TSA@example.invalid";
        let encoded_names = tlv(TAG_SEQUENCE, tlv(0x81, mailbox));
        let names = parse_subject_alt_names(&encoded_names, false).expect("valid rfc822Name SAN");
        assert!(names.contains(&mailbox.as_slice()));
        assert!(!names.contains(&b"tsa@example.invalid".as_slice()));

        assert!(
            parse_subject_alt_names(&tlv(TAG_SEQUENCE, tlv(0x86, b"https://tsa.invalid/")), true,)
                .is_err()
        );
    }

    fn tst_info(digest: &[u8], algorithm: DigestAlgorithm, nonce: Option<&[u8]>) -> Vec<u8> {
        tst_info_with_tsa(digest, algorithm, nonce, None)
    }

    fn tst_info_with_tsa(
        digest: &[u8],
        algorithm: DigestAlgorithm,
        nonce: Option<&[u8]>,
        tsa: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut imprint = algorithm.algorithm_identifier();
        imprint.extend_from_slice(&tlv(0x04, digest));
        let mut body = tlv(0x02, [0x01]);
        body.extend_from_slice(&tlv(0x06, known::TST_INFO.as_bytes()));
        body.extend_from_slice(&tlv(0x30, imprint));
        body.extend_from_slice(&tlv(0x02, [0x01]));
        body.extend_from_slice(&tlv(0x18, b"20260803120000Z"));
        if let Some(nonce) = nonce {
            body.extend_from_slice(&tlv(0x02, positive_integer(nonce)));
        }
        if let Some(tsa) = tsa {
            body.extend_from_slice(&tlv(0xA0, tsa));
        }
        tlv(0x30, body)
    }
}
