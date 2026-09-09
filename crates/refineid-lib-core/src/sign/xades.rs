//! `XAdES`: the XML signature `ASiC-E` and `BDOC` carry.
//!
//! [`crate::sign::cades`] signs octets. This signs a *document*, and the
//! difference is the whole problem. XML has more than one serialisation
//! for the same document -- `<a/>` and `<a></a>`, attributes in either
//! order, a namespace declared here or three levels up -- so before a
//! digest means anything the XML has to be reduced to one form. That
//! reduction is canonicalisation, and every verifier does it
//! independently. Ours has to land on the same octets theirs does.
//!
//! # Why there is no canonicaliser in this file
//!
//! The usual shape is: build a DOM, serialise it, parse it back,
//! canonicalise, digest. That needs an XML parser, a namespace-aware
//! node model, and an implementation of `Exclusive XML Canonicalization`
//! -- a few thousand lines whose only job is to undo the freedom the
//! serialiser just used.
//!
//! This module removes the freedom instead. Every element it writes is
//! already in canonical form: never self-closed, attributes in canonical
//! order, namespace declarations repeated at each subtree root that uses
//! them, and text escaped by the canonicalisation rules rather than the
//! looser XML ones. Canonicalising this output is the identity function,
//! so the bytes can be digested where they stand.
//!
//! That is a real constraint, not a convention, and it is why the string
//! literals below look redundant. See `canonical form` on each writer.
//!
//! # The rules being satisfied
//!
//! From `Exclusive XML Canonicalization 1.0` and `Canonical XML 1.0`
//! sec.2:
//!
//! - UTF-8, no XML declaration inside a canonicalised subset.
//! - Empty elements as a start/end pair: `<a></a>`, never `<a/>`.
//! - Attributes sorted: namespace declarations first, then by namespace
//!   URI and local name. Unprefixed attributes sort among themselves by
//!   name, which is the only case here.
//! - Attribute values escape `&`, `<`, `"` and the three whitespace
//!   characters -- but *not* `>` and *not* `'`. Text escapes `&`, `<`,
//!   `>` and carriage return. Escaping more than that is valid XML and
//!   is still wrong: the canonicaliser would unescape it.
//! - Exclusive canonicalisation renders a namespace declaration on the
//!   outermost element of the subset that visibly uses the prefix, and
//!   nowhere below it. So a subtree that gets digested on its own must
//!   carry its own declarations.
//!
//! # Conformance
//!
//! - `ETSI EN 319 132-1` (`XAdES`): the B-B profile -- `SigningTime`
//!   and `SigningCertificateV2` in `SignedProperties`, one
//!   `ds:Reference` per data object plus one over the properties.
//! - `ETSI EN 319 162-1` (`ASiC-E`): signatures under
//!   `META-INF/signatures*.xml`.
//! - `BDOC 2.1`: the same container, the same signature; see
//!   [`crate::sign::asic`] for why one writer serves both.
//! - RFC 4051: the algorithm identifiers.

use core::fmt::Write as _;

use crate::base64;
use crate::ber::{BerTlv, Integer, Sequence};
use crate::sign::asic::{DataObject, NAMESPACE_ASIC};
use crate::sign::cades::{DigestAlgorithm, SignatureAlgorithm, SignerParameters, SigningTime};
use crate::sign::validation::ValidationMaterial;

/// XML digital signature namespace (RFC 3275).
pub(crate) const NAMESPACE_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";

/// `XAdES` 1.3.2 namespace, the version `ASiC-E` and `BDOC` both name.
const NAMESPACE_XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";

/// `SHA-256` digest method identifier (RFC 4051 sec.2.1).
pub(crate) const DIGEST_METHOD_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

/// `SHA-384` digest method identifier (RFC 4051 sec.2.1).
pub(crate) const DIGEST_METHOD_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";

/// Exclusive canonicalisation, without comments.
const CANONICALIZATION_EXCLUSIVE: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// `Type` marking the reference that covers the signed properties.
///
/// Note the namespace has no minor version: `01903#SignedProperties`,
/// not `01903/v1.3.2#`. It is a fixed string in `EN 319 132-1`, and
/// verifiers match it literally.
const TYPE_SIGNED_PROPERTIES: &str = "http://uri.etsi.org/01903#SignedProperties";

/// Identifier of the one signature this module writes.
const SIGNATURE_ID: &str = "SIG-1";

/// Identifier of its `SignedProperties`, the target of the second
/// reference.
const SIGNED_PROPERTIES_ID: &str = "SIG-1-SIGNEDPROPS";

/// Identifier of the `SignatureValue`, which `XAdES` timestamps refer to
/// when a signature is later raised to a long-term level.
const SIGNATURE_VALUE_ID: &str = "SIG-1-SIGVAL";

/// What can go wrong before a signature exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XadesError {
    /// No signing time was supplied.
    ///
    /// `CAdES` treats `signing-time` as optional; `XAdES` does not.
    /// `EN 319 132-1 sec.5.2.1` makes `SigningTime` mandatory in
    /// `SignedSignatureProperties`, so there is nothing sensible to
    /// write when the caller leaves it out.
    SigningTimeRequired,
    /// The container carries no data objects. A signature over nothing
    /// verifies happily and attests nothing.
    NoDataObjects,
}

impl core::fmt::Display for XadesError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::SigningTimeRequired => f.write_str("XAdES requires a signing time"),
            Self::NoDataObjects => f.write_str("XAdES requires at least one data object"),
        }
    }
}

impl core::error::Error for XadesError {}

/// A signature with everything built except the signature value.
#[derive(Debug, Clone)]
pub struct SignaturePlan {
    /// `ds:SignedInfo`, in canonical form: the octets to sign.
    signed_info: String,
    /// `xades:SignedProperties`, in canonical form. Already digested
    /// into `signed_info`; kept because it has to be written out again,
    /// byte for byte, inside `ds:Object`.
    signed_properties: String,
    /// The signer's certificate, for `ds:KeyInfo`.
    certificate_der: Vec<u8>,
}

impl SignaturePlan {
    /// The octets the card must sign.
    ///
    /// `ds:SignedInfo` in its canonical form. The verifier will
    /// canonicalise its own copy and expect these same bytes; a
    /// re-serialisation, a reindent, or a stray XML declaration produces
    /// a signature over octets nobody else computes.
    #[must_use]
    pub const fn signed_info(&self) -> &[u8] {
        self.signed_info.as_bytes()
    }

    /// Digest of [`Self::signed_info`], to hand to the card.
    #[must_use]
    pub fn digest(&self, algorithm: DigestAlgorithm) -> Vec<u8> {
        algorithm.digest(self.signed_info.as_bytes())
    }

    /// The `ds:SignatureValue` element, in canonical form.
    ///
    /// This is what a `SignatureTimeStamp` is computed over --
    /// `EN 319 132-1 sec.5.2.3.1` timestamps the canonicalised
    /// *element*, tags and all, not the signature octets and not the
    /// base64 text. Digesting the raw signature instead produces a
    /// token that attests something appearing nowhere in the document.
    ///
    /// # Canonical form
    ///
    /// `xmlns:ds` is declared here, redundantly with the enclosing
    /// `ds:Signature`, for the reason [`Self::signed_info`] gives: a
    /// subtree digested on its own is canonicalised with no ancestors
    /// in scope, so it has to carry the declaration it uses. Attributes
    /// follow canonical order -- namespace declarations, then `Id`.
    #[must_use]
    pub fn signature_value_element(signature: &[u8]) -> String {
        format!(
            "<ds:SignatureValue xmlns:ds=\"{NAMESPACE_DSIG}\" Id=\"{SIGNATURE_VALUE_ID}\">{}</ds:SignatureValue>",
            base64::encode(signature)
        )
    }

    /// Digest of [`Self::signature_value_element`], for a TSA.
    #[must_use]
    pub fn timestamp_digest(signature: &[u8], algorithm: DigestAlgorithm) -> Vec<u8> {
        algorithm.digest(Self::signature_value_element(signature).as_bytes())
    }

    /// Assemble `META-INF/signatures0.xml`.
    ///
    /// `signature` is what the card returned for [`Self::digest`].
    /// `timestamps` are RFC 3161 tokens over
    /// [`Self::signature_value_element`]; each becomes its own
    /// `xades:SignatureTimeStamp`, and an empty slice leaves the
    /// signature at baseline level `B`.
    ///
    /// # ECDSA
    ///
    /// XML signatures carry an ECDSA signature as the raw `r || s`
    /// coordinate pair (RFC 4051 sec.2.3), each padded to the field
    /// size. CMS carries the same signature as a DER `SEQUENCE` of two
    /// INTEGERs. They are not interchangeable and the difference is
    /// silent: a DER blob here produces a well-formed document that
    /// every verifier rejects. If the card returns DER -- most do --
    /// convert it with [`ecdsa_signature_to_xml`] first.
    #[must_use]
    pub fn finish(
        &self,
        signature: &[u8],
        timestamps: &[Vec<u8>],
        material: &ValidationMaterial,
    ) -> Vec<u8> {
        let mut document = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
        document.push('\n');
        // The container-level wrapper. Not canonicalised and not
        // digested -- nothing signs it -- so ordinary XML rules apply
        // from here down, except inside the two subtrees that are.
        let _ignored = writeln!(
            document,
            r#"<asic:XAdESSignatures xmlns:asic="{NAMESPACE_ASIC}">"#
        );
        let _ignored = writeln!(
            document,
            r#"<ds:Signature xmlns:ds="{NAMESPACE_DSIG}" Id="{SIGNATURE_ID}">"#
        );

        // Byte for byte as signed. Never rebuilt here.
        document.push_str(&self.signed_info);
        document.push('\n');

        // Byte for byte as the timestamp digested it, whether or not
        // one was taken: one spelling of this element, always.
        document.push_str(&Self::signature_value_element(signature));
        document.push('\n');

        document.push_str("<ds:KeyInfo>\n<ds:X509Data>\n");
        let _ignored = writeln!(
            document,
            "<ds:X509Certificate>{}</ds:X509Certificate>",
            base64::encode(&self.certificate_der)
        );
        document.push_str("</ds:X509Data>\n</ds:KeyInfo>\n");

        document.push_str("<ds:Object>\n");
        let _ignored = writeln!(
            document,
            r##"<xades:QualifyingProperties xmlns:xades="{NAMESPACE_XADES}" Target="#{SIGNATURE_ID}">"##
        );
        // Byte for byte as digested by the second reference.
        document.push_str(&self.signed_properties);
        document.push('\n');
        // Unsigned, so ordinary XML rules apply here: nothing digests
        // this subtree, which is the whole reason a timestamp over the
        // signature can live in it.
        if !timestamps.is_empty() || !material.is_empty() {
            document.push_str("<xades:UnsignedProperties>\n");
            document.push_str("<xades:UnsignedSignatureProperties>\n");
            for (index, token) in timestamps.iter().enumerate() {
                let _ignored = writeln!(
                    document,
                    r#"<xades:SignatureTimeStamp Id="{SIGNATURE_ID}-TS-{index}">"#
                );
                // Which canonicalisation the verifier must apply before
                // digesting `ds:SignatureValue`. It has to name the one
                // actually used, or the verifier hashes different bytes.
                let _ignored = writeln!(
                    document,
                    r#"<ds:CanonicalizationMethod Algorithm="{CANONICALIZATION_EXCLUSIVE}"></ds:CanonicalizationMethod>"#
                );
                let _ignored = writeln!(
                    document,
                    "<xades:EncapsulatedTimeStamp>{}</xades:EncapsulatedTimeStamp>",
                    base64::encode(token)
                );
                document.push_str("</xades:SignatureTimeStamp>\n");
            }
            // The evidence a verifier would otherwise have to fetch.
            // Schema order is fixed: certificates, then revocation
            // values, and inside those CRLs before OCSP responses
            // (`XAdES` `RevocationValuesType`).
            if !material.certificates.is_empty() {
                document.push_str("<xades:CertificateValues>\n");
                for certificate in &material.certificates {
                    let _ignored = writeln!(
                        document,
                        "<xades:EncapsulatedX509Certificate>{}</xades:EncapsulatedX509Certificate>",
                        base64::encode(certificate)
                    );
                }
                document.push_str("</xades:CertificateValues>\n");
            }
            if material.revocation_count() > 0 {
                document.push_str("<xades:RevocationValues>\n");
                if !material.crls.is_empty() {
                    document.push_str("<xades:CRLValues>\n");
                    for crl in &material.crls {
                        let _ignored = writeln!(
                            document,
                            "<xades:EncapsulatedCRLValue>{}</xades:EncapsulatedCRLValue>",
                            base64::encode(crl)
                        );
                    }
                    document.push_str("</xades:CRLValues>\n");
                }
                if !material.ocsp_responses.is_empty() {
                    document.push_str("<xades:OCSPValues>\n");
                    for response in &material.ocsp_responses {
                        let _ignored = writeln!(
                            document,
                            "<xades:EncapsulatedOCSPValue>{}</xades:EncapsulatedOCSPValue>",
                            base64::encode(response)
                        );
                    }
                    document.push_str("</xades:OCSPValues>\n");
                }
                document.push_str("</xades:RevocationValues>\n");
            }
            document.push_str("</xades:UnsignedSignatureProperties>\n");
            document.push_str("</xades:UnsignedProperties>\n");
        }
        document.push_str("</xades:QualifyingProperties>\n");
        document.push_str("</ds:Object>\n");

        document.push_str("</ds:Signature>\n");
        document.push_str("</asic:XAdESSignatures>\n");
        document.into_bytes()
    }
}

/// Build the signature over `objects` and return the plan to sign it.
///
/// # Errors
///
/// [`XadesError::SigningTimeRequired`] when `parameters.signing_time` is
/// `None`, [`XadesError::NoDataObjects`] when `objects` is empty.
pub fn plan(
    objects: &[DataObject],
    parameters: &SignerParameters<'_>,
) -> Result<SignaturePlan, XadesError> {
    let Some(signing_time) = parameters.signing_time else {
        return Err(XadesError::SigningTimeRequired);
    };
    if objects.is_empty() {
        return Err(XadesError::NoDataObjects);
    }

    let signed_properties = write_signed_properties(objects, parameters, signing_time);
    let properties_digest = parameters
        .digest_algorithm
        .digest(signed_properties.as_bytes());
    let signed_info = write_signed_info(objects, parameters, &properties_digest);

    Ok(SignaturePlan {
        signed_info,
        signed_properties,
        certificate_der: parameters.certificate.raw_der.to_vec(),
    })
}

/// `ds:Reference` identifier for the data object at `index`.
fn reference_id(index: usize) -> String {
    format!("{SIGNATURE_ID}-REF-{index}")
}

/// Write `ds:SignedInfo` in canonical form.
///
/// # Canonical form
///
/// `xmlns:ds` is declared here even though the enclosing `ds:Signature`
/// already declares it. Under exclusive canonicalisation this element is
/// digested as a subset of its own, with no ancestors in scope, so the
/// declaration it visibly uses has to appear on it. Removing the
/// apparent redundancy breaks every verifier.
///
/// Attributes are written in canonical order: `Id`, then `Type`, then
/// `URI`. That is alphabetical, which is what the rule reduces to when
/// no attribute is namespace-qualified.
fn write_signed_info(
    objects: &[DataObject],
    parameters: &SignerParameters<'_>,
    properties_digest: &[u8],
) -> String {
    let digest_method = digest_method_uri(parameters.digest_algorithm);
    let signature_method = signature_method_uri(parameters.signature_algorithm);

    let mut out = String::new();
    let _ignored = writeln!(out, r#"<ds:SignedInfo xmlns:ds="{NAMESPACE_DSIG}">"#);
    let _ignored = writeln!(
        out,
        r#"<ds:CanonicalizationMethod Algorithm="{CANONICALIZATION_EXCLUSIVE}"></ds:CanonicalizationMethod>"#
    );
    let _ignored = writeln!(
        out,
        r#"<ds:SignatureMethod Algorithm="{signature_method}"></ds:SignatureMethod>"#
    );

    // One reference per file. The URI is the entry name, resolved
    // against the container root rather than against the directory the
    // signature sits in -- `EN 319 162-1 sec.A.4`. So a file at the top
    // of the archive is named plainly here, even though this document
    // lives under `META-INF/`.
    for (index, object) in objects.iter().enumerate() {
        let id = reference_id(index);
        let uri = escape_attribute(&object.name);
        let digest = base64::encode(&parameters.digest_algorithm.digest(&object.content));
        let _ignored = writeln!(out, r#"<ds:Reference Id="{id}" URI="{uri}">"#);
        let _ignored = writeln!(
            out,
            r#"<ds:DigestMethod Algorithm="{digest_method}"></ds:DigestMethod>"#
        );
        let _ignored = writeln!(out, "<ds:DigestValue>{digest}</ds:DigestValue>");
        out.push_str("</ds:Reference>\n");
    }

    // The reference that makes this XAdES rather than bare XML-DSig: it
    // pulls the signed properties -- signing time, signing certificate
    // -- under the same signature as the files.
    //
    // The transform is not decoration. A same-document reference yields
    // a node set, and XML-DSig canonicalises a node set with *inclusive*
    // C14N when no transform says otherwise. Inclusive would drag in the
    // ancestors' namespace declarations, and the digest would not match
    // the octets written below. Naming exclusive canonicalisation here
    // is what makes the subtree digestible on its own.
    let properties_digest_base64 = base64::encode(properties_digest);
    let _ignored = writeln!(
        out,
        r##"<ds:Reference Id="{SIGNATURE_ID}-REF-SP" Type="{TYPE_SIGNED_PROPERTIES}" URI="#{SIGNED_PROPERTIES_ID}">"##
    );
    out.push_str("<ds:Transforms>\n");
    let _ignored = writeln!(
        out,
        r#"<ds:Transform Algorithm="{CANONICALIZATION_EXCLUSIVE}"></ds:Transform>"#
    );
    out.push_str("</ds:Transforms>\n");
    let _ignored = writeln!(
        out,
        r#"<ds:DigestMethod Algorithm="{digest_method}"></ds:DigestMethod>"#
    );
    let _ignored = writeln!(
        out,
        "<ds:DigestValue>{properties_digest_base64}</ds:DigestValue>"
    );
    out.push_str("</ds:Reference>\n");

    out.push_str("</ds:SignedInfo>");
    out
}

/// Write `xades:SignedProperties` in canonical form.
///
/// # Canonical form
///
/// Two prefixes appear, and they are declared at different depths for
/// the same reason. `xades` is used by this element, so exclusive
/// canonicalisation renders it here. `ds` is used only by the two digest
/// elements inside `CertDigest`, and their ancestors do not use it, so
/// the declaration is rendered on each of those two elements
/// individually -- not on a common parent, which would never have been
/// asked to declare it.
fn write_signed_properties(
    objects: &[DataObject],
    parameters: &SignerParameters<'_>,
    signing_time: SigningTime,
) -> String {
    let digest_method = digest_method_uri(parameters.digest_algorithm);
    let certificate_digest = base64::encode(
        &parameters
            .digest_algorithm
            .digest(parameters.certificate.raw_der),
    );

    let mut out = String::new();
    let _ignored = writeln!(
        out,
        r#"<xades:SignedProperties xmlns:xades="{NAMESPACE_XADES}" Id="{SIGNED_PROPERTIES_ID}">"#
    );
    out.push_str("<xades:SignedSignatureProperties>\n");
    let _ignored = writeln!(
        out,
        "<xades:SigningTime>{}</xades:SigningTime>",
        xml_date_time(signing_time)
    );

    // The XML spelling of the CAdES signing-certificate-v2 attribute,
    // and mandatory for the same reason: without it a signature can be
    // replayed against another certificate carrying the same key.
    //
    // `IssuerSerialV2` is optional and omitted, matching
    // `crate::sign::cades`: the digest already pins the certificate
    // uniquely, and a second, weaker identifier only creates a way for
    // the two to disagree.
    out.push_str("<xades:SigningCertificateV2>\n<xades:Cert>\n<xades:CertDigest>\n");
    let _ignored = writeln!(
        out,
        r#"<ds:DigestMethod xmlns:ds="{NAMESPACE_DSIG}" Algorithm="{digest_method}"></ds:DigestMethod>"#
    );
    let _ignored = writeln!(
        out,
        r#"<ds:DigestValue xmlns:ds="{NAMESPACE_DSIG}">{certificate_digest}</ds:DigestValue>"#
    );
    out.push_str("</xades:CertDigest>\n</xades:Cert>\n</xades:SigningCertificateV2>\n");
    out.push_str("</xades:SignedSignatureProperties>\n");

    // Each file's media type, signed rather than left to the container
    // to assert. `BDOC 2.1 sec.6.3` requires one entry per reference.
    out.push_str("<xades:SignedDataObjectProperties>\n");
    for (index, object) in objects.iter().enumerate() {
        let id = reference_id(index);
        let _ignored = writeln!(out, r##"<xades:DataObjectFormat ObjectReference="#{id}">"##);
        let _ignored = writeln!(
            out,
            "<xades:MimeType>{}</xades:MimeType>",
            escape_text(&object.mime_type)
        );
        out.push_str("</xades:DataObjectFormat>\n");
    }
    out.push_str("</xades:SignedDataObjectProperties>\n");

    out.push_str("</xades:SignedProperties>");
    out
}

/// `xsd:dateTime` in UTC, which is what `SigningTime` is typed as.
fn xml_date_time(time: SigningTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        time.year, time.month, time.day, time.hour, time.minute, time.second
    )
}

/// The `DigestMethod` identifier for a digest.
const fn digest_method_uri(algorithm: DigestAlgorithm) -> &'static str {
    match algorithm {
        DigestAlgorithm::Sha256 => DIGEST_METHOD_SHA256,
        DigestAlgorithm::Sha384 => DIGEST_METHOD_SHA384,
    }
}

/// The `SignatureMethod` identifier for a signature (RFC 4051 sec.2.3).
const fn signature_method_uri(algorithm: SignatureAlgorithm) -> &'static str {
    match algorithm {
        SignatureAlgorithm::RsaPkcs1Sha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        SignatureAlgorithm::RsaPkcs1Sha384 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
        SignatureAlgorithm::EcdsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
        SignatureAlgorithm::EcdsaSha384 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
    }
}

/// Percent-encode a container entry name for use as a reference URI.
///
/// The name goes into `ds:Reference/@URI`, which RFC 3986 reads as a
/// URI and not as a file name. `a#b.txt` unencoded is the URI `a` with
/// the fragment `b.txt`, so a verifier digests the wrong file or none;
/// `?`, space and `%` mislead in the same way. Only the unreserved set
/// plus `/` survives, which leaves ordinary names untouched.
pub(crate) fn percent_encode_path(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for byte in name.bytes() {
        let unreserved =
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/');
        if unreserved {
            out.push(char::from(byte));
        } else {
            let _ignored = core::fmt::Write::write_fmt(&mut out, format_args!("%{byte:02X}"));
        }
    }
    out
}

/// Escape an attribute value the way canonicalisation would write it.
///
/// `&`, `<` and `"`, plus the three whitespace characters a parser would
/// otherwise fold into spaces. Deliberately *not* `>` or `'`: both are
/// legal raw in an attribute value, and a canonicaliser writes them raw.
/// Escaping them anyway yields valid XML whose canonical form differs
/// from what was written -- which is the one failure this module exists
/// to prevent.
pub(crate) fn escape_attribute(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            other => out.push(other),
        }
    }
    out
}

/// Escape text content the way canonicalisation would write it.
///
/// `&`, `<`, `>` and carriage return. `>` is escaped here and not in an
/// attribute value; the asymmetry is in `Canonical XML 1.0 sec.2.3` and
/// is not a mistake.
fn escape_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            other => out.push(other),
        }
    }
    out
}

/// Convert a DER ECDSA signature to the `r || s` form XML signatures use.
///
/// CMS carries `SEQUENCE { r INTEGER, s INTEGER }`; XML-DSig carries the
/// two coordinates concatenated, each left-padded to the field size
/// (RFC 4051 sec.2.3). Cards and PKCS#11 return the DER form, so this
/// sits between them and [`SignaturePlan::finish`].
///
/// `coordinate_octets` is the field size of the curve the key is on --
/// 32 for P-256, 48 for P-384 -- and must come from the key, not from
/// the digest: a P-384 key signing a SHA-256 digest is legal and would
/// be padded wrongly if inferred.
///
/// Returns `None` if `der` is not a two-INTEGER SEQUENCE, or if either
/// coordinate does not fit in `coordinate_octets`.
#[must_use]
pub fn ecdsa_signature_to_xml(der: &[u8], coordinate_octets: usize) -> Option<Vec<u8>> {
    let sequence = BerTlv::<Sequence>::parse(der).ok()?;
    let mut children = sequence.iter_children();
    let r = children.next()?.ok()?.expect::<Integer>().ok()?;
    let s = children.next()?.ok()?.expect::<Integer>().ok()?;
    if children.next().is_some() {
        return None;
    }

    let mut out = Vec::with_capacity(coordinate_octets.saturating_mul(2));
    for coordinate in [r, s] {
        // DER INTEGERs are signed, so a coordinate whose top bit is set
        // carries a leading zero that is padding, not magnitude.
        let magnitude = match coordinate.value {
            [0x00, rest @ ..] => rest,
            whole => whole,
        };
        let pad = coordinate_octets.checked_sub(magnitude.len())?;
        out.extend(core::iter::repeat_n(0_u8, pad));
        out.extend_from_slice(magnitude);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use crate::sign::validation::ValidationMaterial;

    use super::{
        DataObject, SignerParameters, ecdsa_signature_to_xml, escape_attribute, escape_text, plan,
        write_signed_properties,
    };
    use crate::sign::cades::{DigestAlgorithm, SignatureAlgorithm, SigningTime};
    use crate::x509::Certificate;

    /// A certificate to name as the signer. Its contents do not matter
    /// to these tests -- only that its bytes are hashed into
    /// `CertDigest` -- so a real one on hand serves.
    const CERTIFICATE_DER: &[u8] = include_bytes!(
        "../../../refineid-client/test-vectors/fineid-intermediate-01-citizen-g4e.der"
    );

    fn signer<'a>(certificate: &'a Certificate<'a>) -> SignerParameters<'a> {
        SignerParameters {
            certificate,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            signing_time: Some(SigningTime {
                year: 2026,
                month: 8,
                day: 3,
                hour: 12,
                minute: 34,
                second: 56,
            }),
        }
    }

    fn sample() -> Vec<DataObject> {
        vec![DataObject {
            name: "dossier.pdf".to_owned(),
            mime_type: "application/pdf".to_owned(),
            content: b"a declaration of a means of cryptology".to_vec(),
        }]
    }

    #[test]
    fn the_signed_info_is_already_in_canonical_form() {
        let certificate = Certificate::from_der(CERTIFICATE_DER).expect("certificate");
        let plan = plan(&sample(), &signer(&certificate)).expect("plan");
        let signed_info = core::str::from_utf8(plan.signed_info()).expect("utf-8");

        // The three ways generated XML usually fails to be canonical.
        assert!(!signed_info.contains("/>"), "no element may be self-closed");
        assert!(
            !signed_info.contains("<?xml"),
            "a canonicalised subset carries no declaration"
        );
        assert!(
            signed_info.starts_with("<ds:SignedInfo xmlns:ds="),
            "the subset root must declare the prefix it uses: {signed_info}"
        );
        assert!(
            signed_info.ends_with("</ds:SignedInfo>"),
            "the octets end at the element, with no trailing newline"
        );
    }

    #[test]
    fn the_signed_properties_declare_both_prefixes_where_they_are_used() {
        let certificate = Certificate::from_der(CERTIFICATE_DER).expect("certificate");
        let parameters = signer(&certificate);
        let properties = write_signed_properties(
            &sample(),
            &parameters,
            parameters.signing_time.expect("time"),
        );

        assert!(properties.starts_with("<xades:SignedProperties xmlns:xades="));
        // `ds` is used only by the digest elements, so it is declared on
        // each of them and on no ancestor.
        assert!(properties.contains(r"<ds:DigestMethod xmlns:ds="));
        assert!(properties.contains(r"<ds:DigestValue xmlns:ds="));
        assert!(
            !properties.contains("<xades:CertDigest xmlns:ds="),
            "no ancestor visibly uses ds, so none may declare it"
        );
        assert!(properties.contains("<xades:SigningTime>2026-08-03T12:34:56Z</xades:SigningTime>"));
    }

    #[test]
    fn every_data_object_gets_a_reference_and_a_format() {
        let certificate = Certificate::from_der(CERTIFICATE_DER).expect("certificate");
        let objects = vec![
            DataObject {
                name: "a.pdf".to_owned(),
                mime_type: "application/pdf".to_owned(),
                content: b"one".to_vec(),
            },
            DataObject {
                name: "b.txt".to_owned(),
                mime_type: "text/plain".to_owned(),
                content: b"two".to_vec(),
            },
        ];
        let parameters = signer(&certificate);
        let plan = plan(&objects, &parameters).expect("plan");
        let signed_info = core::str::from_utf8(plan.signed_info()).expect("utf-8");
        let document = plan.finish(b"signature", &[], &ValidationMaterial::default());
        let text = String::from_utf8(document).expect("utf-8");

        let expected_a = crate::base64::encode(&DigestAlgorithm::Sha256.digest(b"one"));
        assert!(signed_info.contains(r#"<ds:Reference Id="SIG-1-REF-0" URI="a.pdf">"#));
        assert!(signed_info.contains(&format!("<ds:DigestValue>{expected_a}</ds:DigestValue>")));
        assert!(signed_info.contains(r#"<ds:Reference Id="SIG-1-REF-1" URI="b.txt">"#));
        // Each format entry points back at its reference by Id.
        assert!(text.contains(r##"<xades:DataObjectFormat ObjectReference="#SIG-1-REF-0">"##));
        assert!(text.contains("<xades:MimeType>text/plain</xades:MimeType>"));
    }

    #[test]
    fn the_document_embeds_the_signed_octets_unchanged() {
        let certificate = Certificate::from_der(CERTIFICATE_DER).expect("certificate");
        let plan = plan(&sample(), &signer(&certificate)).expect("plan");
        let signed_info = String::from_utf8(plan.signed_info().to_vec()).expect("utf-8");
        let text =
            String::from_utf8(plan.finish(b"signature", &[], &ValidationMaterial::default()))
                .expect("utf-8");
        assert!(
            text.contains(&signed_info),
            "what was signed must appear in the document byte for byte"
        );
    }

    #[test]
    fn a_missing_signing_time_is_refused() {
        let certificate = Certificate::from_der(CERTIFICATE_DER).expect("certificate");
        let mut parameters = signer(&certificate);
        parameters.signing_time = None;
        assert_eq!(
            plan(&sample(), &parameters).err(),
            Some(super::XadesError::SigningTimeRequired)
        );
        parameters.signing_time = signer(&certificate).signing_time;
        assert_eq!(
            plan(&[], &parameters).err(),
            Some(super::XadesError::NoDataObjects)
        );
    }

    #[test]
    fn escaping_follows_the_canonicalisation_rules_not_the_xml_ones() {
        // `>` and `'` stay raw in an attribute value; a canonicaliser
        // writes them raw, so escaping them would change the digest.
        assert_eq!(escape_attribute("a>b'c"), "a>b'c");
        assert_eq!(escape_attribute("a&b\"c<d"), "a&amp;b&quot;c&lt;d");
        assert_eq!(escape_attribute("a\nb"), "a&#xA;b");
        // `>` is escaped in text, where the rule is the other way round.
        assert_eq!(escape_text("a>b'c"), "a&gt;b'c");
        assert_eq!(escape_text("a&b<c"), "a&amp;b&lt;c");
    }

    #[test]
    fn ecdsa_der_becomes_a_padded_coordinate_pair() {
        // SEQUENCE { INTEGER 0x00AABB, INTEGER 0x01 } -- the first with
        // a DER sign byte that is padding, not magnitude.
        let der = [0x30, 0x08, 0x02, 0x03, 0x00, 0xAA, 0xBB, 0x02, 0x01, 0x01];
        let pair = ecdsa_signature_to_xml(&der, 4).expect("converted");
        assert_eq!(pair, vec![0x00, 0x00, 0xAA, 0xBB, 0x00, 0x00, 0x00, 0x01]);
        // A coordinate wider than the field is a curve mismatch.
        assert_eq!(ecdsa_signature_to_xml(&der, 1), None);
        // Not a SEQUENCE of exactly two INTEGERs.
        assert_eq!(ecdsa_signature_to_xml(&[0x30, 0x00], 4), None);
    }
}

/// The signature checked by a verifier that is not ours.
///
/// Every other test in this file inspects our own output with our own
/// expectations, which cannot catch the failure this module is built to
/// avoid: output that is well-formed XML but not in canonical form.
/// Only an independent canonicaliser can. `xmlsec1` canonicalises
/// `SignedInfo` itself, recomputes both reference digests, and checks
/// the signature -- so if it agrees, the octets we signed are the octets
/// a verifier computes.
///
/// Ignored by default -- needs `xmlsec1` and `openssl`. Run:
///
/// ```text
/// cargo test -p refineid-lib-core --lib sign::xades::xmlsec -- --ignored --nocapture
/// ```
#[cfg(test)]
mod xmlsec_interop {
    use crate::sign::validation::ValidationMaterial;

    use std::path::Path;
    use std::process::Command;

    use super::{DataObject, SignerParameters, plan};
    use crate::sign::cades::{DigestAlgorithm, SignatureAlgorithm, SigningTime};
    use crate::x509::Certificate;

    /// Run a command in `directory`, returning its output, failing
    /// loudly.
    ///
    /// The working directory matters: `xmlsec1` resolves a relative
    /// reference URI against the process's directory rather than the
    /// document's, so it has to be run from inside the container.
    fn run_in(directory: &Path, program: &str, arguments: &[&str]) -> String {
        let output = Command::new(program)
            .current_dir(directory)
            .args(arguments)
            .output()
            .unwrap_or_else(|error| panic!("{program} not runnable: {error}"));
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.status.success(),
            "{program} {arguments:?} failed:\n{combined}"
        );
        combined
    }

    #[test]
    #[ignore = "requires the xmlsec1 and openssl binaries"]
    #[allow(
        clippy::too_many_lines,
        reason = "the external interoperability transcript is clearest as one linear test"
    )]
    fn xmlsec1_verifies_the_signature() {
        let dir = std::env::temp_dir().join("refineid-xades-interop");
        let _ignored = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let run = |program: &str, arguments: &[&str]| run_in(&dir, program, arguments);

        // A key and certificate standing in for the card.
        run(
            "openssl",
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=ReFineID XAdES interop",
                "-keyout",
                "key.pem",
                "-out",
                "cert.pem",
            ],
        );
        run(
            "openssl",
            &[
                "x509", "-in", "cert.pem", "-outform", "der", "-out", "cert.der",
            ],
        );
        let certificate_der = std::fs::read(dir.join("cert.der")).expect("cert.der");
        let certificate = Certificate::from_der(&certificate_der).expect("parse certificate");

        // The data objects, written where the reference URIs point.
        // Inside a container these resolve against the archive root; on
        // disk that is the directory holding the signature.
        let objects = vec![
            DataObject {
                name: "dossier.pdf".to_owned(),
                mime_type: "application/pdf".to_owned(),
                content: b"ReFineID -- declaration d'un moyen de cryptologie".to_vec(),
            },
            DataObject {
                name: "formulaire.txt".to_owned(),
                mime_type: "text/plain".to_owned(),
                content: b"annexe I, completee et signee".to_vec(),
            },
        ];
        for object in &objects {
            std::fs::write(dir.join(&object.name), &object.content).expect("write data object");
        }

        let parameters = SignerParameters {
            certificate: &certificate,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            signing_time: Some(SigningTime {
                year: 2026,
                month: 8,
                day: 3,
                hour: 12,
                minute: 34,
                second: 56,
            }),
        };
        let signature_plan = plan(&objects, &parameters).expect("plan");

        // Sign exactly the octets handed out -- no reserialisation.
        std::fs::write(dir.join("signedinfo.xml"), signature_plan.signed_info())
            .expect("write signed info");
        run(
            "openssl",
            &[
                "dgst",
                "-sha256",
                "-sign",
                "key.pem",
                "-out",
                "signature.bin",
                "signedinfo.xml",
            ],
        );
        let signature = std::fs::read(dir.join("signature.bin")).expect("signature");

        let document = signature_plan.finish(&signature, &[], &ValidationMaterial::default());
        std::fs::write(dir.join("signatures0.xml"), &document).expect("write signature document");
        println!("{}", String::from_utf8_lossy(&document));

        // `--id-attr` tells xmlsec1 which attribute the same-document
        // reference resolves against. Nothing in the document declares
        // it, because a container carries no DTD or schema, so every
        // verifier of this format is told the same thing out of band.
        let arguments = [
            "--verify",
            "--verbose",
            "--trusted-pem",
            "cert.pem",
            "--id-attr:Id",
            "http://uri.etsi.org/01903/v1.3.2#:SignedProperties",
            "signatures0.xml",
        ];
        let report = run("xmlsec1", &arguments);
        println!("{report}");
        assert!(
            report.contains("Verification status: OK"),
            "xmlsec1 did not verify the signature:\n{report}"
        );
        // Both references, not just the easy one. The second covers
        // `SignedProperties`, which is the subtree whose canonical form
        // this module has to get right without a canonicaliser; a
        // verifier that skipped it would report OK for the wrong reason.
        assert!(
            report.contains("SignedInfo References (ok/all): 3/3"),
            "xmlsec1 must have checked every reference:\n{report}"
        );

        // A verifier that says OK to a changed document says nothing at
        // all. Change one data object and it must refuse.
        std::fs::write(dir.join("dossier.pdf"), b"tampered").expect("tamper");
        let tampered = Command::new("xmlsec1")
            .current_dir(&dir)
            .args(arguments)
            .output()
            .expect("xmlsec1 runnable");
        assert!(
            !tampered.status.success(),
            "a changed data object must break the signature"
        );
    }

    /// The whole pipeline, through a real container.
    ///
    /// The test above verifies a signature sitting in a directory. This
    /// one puts it where it actually ships -- inside a ZIP, under
    /// `META-INF/`, with the files it covers at the archive root -- then
    /// has `unzip` take it apart and `xmlsec1` check what falls out.
    /// Between the two, nothing about the format is taken on trust from
    /// our own writers.
    #[test]
    #[ignore = "requires the xmlsec1, openssl and unzip binaries"]
    #[allow(
        clippy::too_many_lines,
        reason = "the external interoperability transcript is clearest as one linear test"
    )]
    fn a_container_survives_unzip_and_verifies() {
        let dir = std::env::temp_dir().join("refineid-xades-container");
        let _ignored = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let run = |program: &str, arguments: &[&str]| run_in(&dir, program, arguments);

        run(
            "openssl",
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=ReFineID ASiC interop",
                "-keyout",
                "key.pem",
                "-out",
                "cert.pem",
            ],
        );
        run(
            "openssl",
            &[
                "x509", "-in", "cert.pem", "-outform", "der", "-out", "cert.der",
            ],
        );
        let certificate_der = std::fs::read(dir.join("cert.der")).expect("cert.der");
        let certificate = Certificate::from_der(&certificate_der).expect("parse certificate");

        let objects = vec![
            DataObject {
                name: "dossier.pdf".to_owned(),
                mime_type: "application/pdf".to_owned(),
                content: b"ReFineID -- declaration d'un moyen de cryptologie".to_vec(),
            },
            DataObject {
                name: "annexe.txt".to_owned(),
                mime_type: "text/plain".to_owned(),
                content: b"fiche technique".to_vec(),
            },
        ];
        let parameters = SignerParameters {
            certificate: &certificate,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            signing_time: Some(SigningTime {
                year: 2026,
                month: 8,
                day: 3,
                hour: 12,
                minute: 34,
                second: 56,
            }),
        };
        let signature_plan = plan(&objects, &parameters).expect("plan");
        std::fs::write(dir.join("signedinfo.xml"), signature_plan.signed_info())
            .expect("write signed info");
        run(
            "openssl",
            &[
                "dgst",
                "-sha256",
                "-sign",
                "key.pem",
                "-out",
                "signature.bin",
                "signedinfo.xml",
            ],
        );
        let signature = std::fs::read(dir.join("signature.bin")).expect("signature");
        let document = signature_plan.finish(&signature, &[], &ValidationMaterial::default());

        let container = crate::sign::asic::xades_container(&objects, &document).expect("fits");
        std::fs::write(dir.join("out.asice"), &container).expect("write container");

        // Taken apart by a reader that knows nothing about us.
        let listing = run("unzip", &["-t", "out.asice"]);
        println!("{listing}");
        assert!(listing.contains("No errors detected"), "{listing}");
        run("unzip", &["-o", "-q", "out.asice", "-d", "extracted"]);

        // Verified from the archive root, which is where a container
        // reader resolves the reference URIs from.
        let root = dir.join("extracted");
        let report = run_in(
            &root,
            "xmlsec1",
            &[
                "--verify",
                "--verbose",
                "--trusted-pem",
                "../cert.pem",
                "--id-attr:Id",
                "http://uri.etsi.org/01903/v1.3.2#:SignedProperties",
                "META-INF/signatures0.xml",
            ],
        );
        println!("{report}");
        assert!(
            report.contains("Verification status: OK"),
            "the extracted signature must verify:\n{report}"
        );
        assert!(
            report.contains("SignedInfo References (ok/all): 3/3"),
            "every reference must be checked:\n{report}"
        );

        // The unsigned inventory is present and names every file.
        let manifest = std::fs::read_to_string(root.join("META-INF/manifest.xml"))
            .expect("META-INF/manifest.xml");
        for object in &objects {
            assert!(
                manifest.contains(&object.name),
                "manifest omits {}: {manifest}",
                object.name
            );
        }
    }
}
