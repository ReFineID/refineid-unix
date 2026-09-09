//! One flow for every signature format the CLI offers.
//!
//! The four format modules each expose the same two-phase shape --
//! build, sign, assemble -- because the key is behind a PIN. Each also
//! wants that shape spelled slightly differently: `PAdES` reserves a
//! hole and patches it, `ASiC` writes an archive, `CAdES` returns a
//! structure. A caller that supports all of them would otherwise carry
//! a five-way match at every step.
//!
//! This collapses that into [`plan`] and [`DocumentPlan::finish`]. What
//! is left in the caller is a choice of [`Format`] and a card.
//!
//! # The signature encoding
//!
//! [`DocumentPlan::finish`] takes the signature **exactly as the card
//! returned it**: PKCS#1 for RSA, and the raw `r || s` pair for ECDSA
//! (FINEID S1 v4.2 sec.3.8.3). Which encoding each format wants differs
//! -- CMS needs DER, XML needs the raw pair -- and converting is this
//! module's job, not the caller's. A caller signing with something that
//! already produces DER has to undo that first; see
//! [`crate::sign::xades::ecdsa_signature_to_xml`].

use crate::sign::asic::{self, ContainerPlan, DataObject};
use crate::sign::cades::{
    self, DigestAlgorithm, Encapsulation, SignatureAlgorithm, SignerParameters, SigningTime,
    ToBeSigned,
};
use crate::sign::pades::{self, PdfError, Placeholder, SignatureMetadata};
use crate::sign::validation::ValidationMaterial;
use crate::sign::xades::{self, XadesError};

/// Which signature format to produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// `CAdES` with the document inside the structure. One file in,
    /// one `.p7m` out, self-contained.
    Cades,
    /// `CAdES` with the document left outside. One file in, one `.p7s`
    /// out, which is meaningless without the original alongside.
    CadesDetached,
    /// `PAdES`: the signature goes inside the PDF, which stays a PDF
    /// and stays readable in anything.
    Pades,
    /// `ASiC-E` carrying a detached `CAdES` over a manifest.
    AsicECades,
    /// `ASiC-E` carrying an `XAdES`. Also what a `.bdoc` is; only the
    /// file extension differs.
    AsicEXades,
}

impl Format {
    /// Whether the format signs exactly one file.
    ///
    /// The `ASiC` containers carry a set; the rest sign a document.
    /// This is not a limitation to route around -- signing three files
    /// as `PAdES` is three signatures, which is a different assertion
    /// from one signature over three files.
    #[must_use]
    pub const fn is_single_file(self) -> bool {
        match self {
            Self::Cades | Self::CadesDetached | Self::Pades => true,
            Self::AsicECades | Self::AsicEXades => false,
        }
    }

    /// The conventional extension for the output.
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Cades => "p7m",
            Self::CadesDetached => "p7s",
            Self::Pades => "pdf",
            // `.bdoc` is the same bytes under another name; the caller
            // names the file, so this offers the European spelling.
            Self::AsicECades | Self::AsicEXades => "asice",
        }
    }
}

/// What can go wrong before or after the card is asked to sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentError {
    /// Nothing to sign.
    NoInput,
    /// More than one file was offered to a format that signs one.
    SingleFileOnly {
        /// The format that refused.
        format: Format,
        /// How many files were offered.
        offered: usize,
    },
    /// The PDF could not be prepared or the signature did not fit.
    Pdf(PdfError),
    /// The `XAdES` could not be built.
    Xades(XadesError),
    /// An archive timestamp was asked of a format that does not build
    /// one this way.
    ArchiveUnsupported,
    /// A data object cannot be carried under the name it was given.
    ///
    /// A container reserves `mimetype` and everything under
    /// `META-INF/` for its own structure, and a name used twice leaves
    /// a reader to pick. Absolute paths, parent-directory components,
    /// backslashes and control characters have no single portable
    /// archive meaning. Any of those can displace a manifest or a
    /// signature after extraction.
    UnusableObjectName,
    /// The archive outgrew the 32-bit fields a ZIP can describe.
    ContainerTooLarge,
    /// An ECDSA signature that is not an even number of octets, so it
    /// cannot be split into two coordinates.
    MalformedEcdsaSignature {
        /// Length the card returned.
        length: usize,
    },
}

impl core::fmt::Display for DocumentError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoInput => f.write_str("no input files"),
            Self::SingleFileOnly { format, offered } => write!(
                f,
                "{format:?} signs one file, but {offered} were given -- use asice to cover a set"
            ),
            Self::Pdf(error) => write!(f, "PDF: {error}"),
            Self::Xades(error) => write!(f, "XAdES: {error}"),
            Self::ArchiveUnsupported => {
                f.write_str("this format does not take an ASiC archive manifest")
            }
            Self::UnusableObjectName => f.write_str(
                "a file name is reserved, repeated, absolute, escaping, or not portable in a ZIP container",
            ),
            Self::ContainerTooLarge => {
                f.write_str("the container outgrew what a 32-bit ZIP can describe")
            }
            Self::MalformedEcdsaSignature { length } => {
                write!(f, "ECDSA signature of {length} octets is not a coordinate pair")
            }
        }
    }
}

impl core::error::Error for DocumentError {}

impl From<PdfError> for DocumentError {
    fn from(error: PdfError) -> Self {
        Self::Pdf(error)
    }
}

impl From<XadesError> for DocumentError {
    fn from(error: XadesError) -> Self {
        Self::Xades(error)
    }
}

/// Everything built, waiting on the one thing only the card can supply.
#[derive(Debug, Clone)]
pub struct DocumentPlan {
    /// Format-specific state.
    state: State,
}

/// The half-built signature, per format.
#[derive(Debug, Clone)]
enum State {
    /// `CAdES`, with the content kept when it travels inside.
    Cades {
        /// The signed attributes, which are what gets signed.
        attributes: ToBeSigned,
        /// Whether the content travels inside.
        encapsulation: Encapsulation,
        /// The document, needed only when attached.
        content: Vec<u8>,
    },
    /// `PAdES`, with the hole reserved in the PDF.
    Pades {
        /// The signed attributes.
        attributes: ToBeSigned,
        /// The PDF with the signature hole waiting.
        placeholder: Box<Placeholder>,
    },
    /// `ASiC-E` over a `CAdES`-signed manifest.
    AsicECades {
        /// The signed attributes.
        attributes: ToBeSigned,
        /// The container with its manifest built.
        container: ContainerPlan,
    },
    /// `ASiC-E` over an `XAdES`.
    AsicEXades {
        /// The signature with everything but the value.
        signature: xades::SignaturePlan,
        /// The files, needed again to write the archive.
        objects: Vec<DataObject>,
    },
}

impl DocumentPlan {
    /// The octets the card must sign.
    ///
    /// For the CMS formats this is the DER SET of signed attributes;
    /// for `XAdES` it is the canonical `ds:SignedInfo`. In both cases
    /// it is the document only indirectly -- through a digest -- which
    /// is why nothing here needs the file again.
    #[must_use]
    pub fn to_be_signed(&self) -> &[u8] {
        match self.state {
            State::Cades { ref attributes, .. }
            | State::Pades { ref attributes, .. }
            | State::AsicECades { ref attributes, .. } => attributes.as_bytes(),
            State::AsicEXades { ref signature, .. } => signature.signed_info(),
        }
    }

    /// The digest a Time Stamp Authority must sign for this signature.
    ///
    /// The two families timestamp different things, and neither is the
    /// signature octets as the card produced them. `CMS` timestamps the
    /// signature value in the encoding the structure stores -- DER for
    /// ECDSA, not the card's coordinate pair. `XAdES` timestamps the
    /// canonicalised `ds:SignatureValue` *element*, tags included
    /// (`EN 319 132-1 sec.5.2.3.1`). Sending the wrong one yields a
    /// token attesting a byte string that appears nowhere in the
    /// finished document, and no validator will connect it to the
    /// signature.
    ///
    /// # Errors
    /// [`DocumentError::MalformedEcdsaSignature`] if the signature is
    /// not a coordinate pair.
    pub fn timestamp_digest(
        &self,
        parameters: &SignerParameters<'_>,
        signature: &[u8],
        algorithm: DigestAlgorithm,
    ) -> Result<Vec<u8>, DocumentError> {
        match self.state {
            State::AsicEXades { .. } => {
                Ok(xades::SignaturePlan::timestamp_digest(signature, algorithm))
            }
            State::Cades { .. } | State::Pades { .. } | State::AsicECades { .. } => {
                let der = for_cms(parameters.signature_algorithm, signature)?;
                Ok(algorithm.digest(&der))
            }
        }
    }

    /// Assemble the finished document.
    ///
    /// `signature` is what the card returned for [`Self::to_be_signed`],
    /// in the card's own encoding; see the module docs.
    ///
    /// `parameters` must be the same ones [`plan`] was given. They are
    /// asked for again rather than stored because they borrow the
    /// certificate, and the caller already holds it for the whole card
    /// session.
    ///
    /// # Errors
    /// [`DocumentError::MalformedEcdsaSignature`] if an ECDSA signature
    /// cannot be split into two coordinates, or
    /// [`DocumentError::Pdf`] if the finished `CAdES` outgrew the space
    /// reserved for it in the PDF.
    pub fn finish(
        self,
        parameters: &SignerParameters<'_>,
        signature: &[u8],
        timestamps: &[Vec<u8>],
        material: &ValidationMaterial,
    ) -> Result<Vec<u8>, DocumentError> {
        match self.state {
            State::Cades {
                attributes,
                encapsulation,
                content,
            } => {
                let der = for_cms(parameters.signature_algorithm, signature)?;
                Ok(cades::signed_data(
                    parameters,
                    &attributes,
                    &der,
                    encapsulation,
                    &content,
                    material,
                    timestamps,
                ))
            }
            State::Pades {
                attributes,
                placeholder,
            } => {
                let der = for_cms(parameters.signature_algorithm, signature)?;
                // PAdES keeps its evidence in the document rather than
                // the CMS, so the material does not go into the
                // signature -- it is appended after it.
                let bare = ValidationMaterial::default();
                let cms = cades::signed_data(
                    parameters,
                    &attributes,
                    &der,
                    Encapsulation::Detached,
                    &[],
                    &bare,
                    timestamps,
                );
                let signed = placeholder.finish(&cms)?;
                Ok(pades::append_validation_store(
                    &signed,
                    &material.certificates,
                    &material.ocsp_responses,
                    &material.crls,
                )?)
            }
            State::AsicECades {
                attributes,
                container,
            } => {
                let der = for_cms(parameters.signature_algorithm, signature)?;
                let cms = cades::signed_data(
                    parameters,
                    &attributes,
                    &der,
                    Encapsulation::Detached,
                    &[],
                    material,
                    timestamps,
                );
                container
                    .finish(&cms)
                    .ok_or(DocumentError::ContainerTooLarge)
            }
            State::AsicEXades {
                signature: plan,
                objects,
            } => {
                // XML wants the raw pair, which is what the card gave
                // us, so this is the one path that converts nothing.
                let document = plan.finish(signature, timestamps, material);
                asic::xades_container(&objects, &document).ok_or(DocumentError::ContainerTooLarge)
            }
        }
    }

    /// The archive manifest and the digest a TSA must attest for it.
    ///
    /// `ASiC-E` with `CAdES` reaches level LTA through a second manifest
    /// and a timestamp over it rather than through a signature
    /// attribute (`EN 319 162-1 clause 4.4.5 item 2`). The manifest
    /// covers the signature, so it exists only after signing; the caller
    /// hands the digest to an authority and the token back to
    /// [`Self::finish_archived`].
    ///
    /// Returns `None` for every other format, which archives by other
    /// means or not at all.
    #[must_use]
    pub fn archive_manifest(
        &self,
        parameters: &SignerParameters<'_>,
        signature: &[u8],
        algorithm: DigestAlgorithm,
    ) -> Option<Vec<u8>> {
        match self.state {
            State::AsicECades { ref container, .. } => {
                let der = for_cms(parameters.signature_algorithm, signature).ok()?;
                Some(container.archive_manifest(&der, algorithm))
            }
            State::Cades { .. } | State::Pades { .. } | State::AsicEXades { .. } => None,
        }
    }

    /// Assemble an `ASiC-E` `CAdES` container at level LTA.
    ///
    /// # Errors
    /// [`DocumentError::MalformedEcdsaSignature`] as for
    /// [`Self::finish`], or [`DocumentError::ArchiveUnsupported`] for a
    /// format that does not archive this way.
    pub fn finish_archived(
        self,
        parameters: &SignerParameters<'_>,
        signature: &[u8],
        timestamps: &[Vec<u8>],
        material: &ValidationMaterial,
        archive_manifest: &[u8],
        token: &[u8],
    ) -> Result<Vec<u8>, DocumentError> {
        match self.state {
            State::AsicECades {
                attributes,
                container,
            } => {
                let der = for_cms(parameters.signature_algorithm, signature)?;
                let cms = cades::signed_data(
                    parameters,
                    &attributes,
                    &der,
                    Encapsulation::Detached,
                    &[],
                    material,
                    timestamps,
                );
                container
                    .finish_archived(&cms, archive_manifest, token)
                    .ok_or(DocumentError::ContainerTooLarge)
            }
            State::Cades { .. } | State::Pades { .. } | State::AsicEXades { .. } => {
                Err(DocumentError::ArchiveUnsupported)
            }
        }
    }
}

/// A [`SigningTime`] as the PDF date string `/M` wants.
///
/// `D:YYYYMMDDHHmmSS+00'00'` (ISO 32000-1 sec.7.9.4). The offset is
/// written out rather than left implicit: a PDF date with no zone is
/// local time by an unstated clock, which is not what was asserted.
fn pdf_date(time: SigningTime) -> String {
    format!(
        "D:{:04}{:02}{:02}{:02}{:02}{:02}+00'00'",
        time.year, time.month, time.day, time.hour, time.minute, time.second
    )
}

/// Refuse names a container cannot carry.
///
/// `mimetype` and `META-INF/` belong to the container, and a repeated
/// name leaves a reader to choose which entry wins. Any of the three
/// lets an input file take the place of a manifest or a signature once
/// the archive is unpacked, so they are refused rather than mangled
/// into something unique.
fn check_object_names(objects: &[DataObject]) -> Result<(), DocumentError> {
    let mut seen: Vec<&str> = Vec::with_capacity(objects.len());
    for object in objects {
        let name = object.name.as_str();
        if unusable_object_name(name) || seen.contains(&name) {
            return Err(DocumentError::UnusableObjectName);
        }
        seen.push(name);
    }
    Ok(())
}

fn unusable_object_name(name: &str) -> bool {
    name.is_empty()
        || name.eq_ignore_ascii_case("mimetype")
        || name.eq_ignore_ascii_case("META-INF")
        || name.len() >= "META-INF/".len()
            && name
                .get(.."META-INF/".len())
                .is_some_and(|head| head.eq_ignore_ascii_case("META-INF/"))
        || name.starts_with('/')
        || name.contains('\\')
        || name
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
        || name.chars().any(char::is_control)
}

/// Re-encode an ECDSA signature for CMS, and pass RSA through.
fn for_cms(algorithm: SignatureAlgorithm, signature: &[u8]) -> Result<Vec<u8>, DocumentError> {
    match algorithm {
        SignatureAlgorithm::RsaPkcs1Sha256 | SignatureAlgorithm::RsaPkcs1Sha384 => {
            Ok(signature.to_vec())
        }
        SignatureAlgorithm::EcdsaSha256 | SignatureAlgorithm::EcdsaSha384 => {
            cades::ecdsa_signature_to_cms(signature).ok_or(DocumentError::MalformedEcdsaSignature {
                length: signature.len(),
            })
        }
    }
}

/// Build a signature of `format` over `objects`.
///
/// `metadata` is used only by [`Format::Pades`]; the other formats have
/// nowhere to record a reason or a location.
///
/// # Errors
/// [`DocumentError::NoInput`] for an empty set,
/// [`DocumentError::SingleFileOnly`] when a one-file format is given
/// several, and the format's own errors otherwise.
pub fn plan(
    format: Format,
    objects: Vec<DataObject>,
    parameters: &SignerParameters<'_>,
    metadata: &SignatureMetadata,
) -> Result<DocumentPlan, DocumentError> {
    if objects.is_empty() {
        return Err(DocumentError::NoInput);
    }
    if format.is_single_file() && objects.len() > 1 {
        return Err(DocumentError::SingleFileOnly {
            format,
            offered: objects.len(),
        });
    }
    if !format.is_single_file() {
        check_object_names(&objects)?;
    }

    let state = match format {
        Format::Cades | Format::CadesDetached => {
            // `is_single_file` was checked above, so there is exactly
            // one; `first` rather than an index keeps that provable.
            let content = objects
                .first()
                .map(|o| o.content.clone())
                .unwrap_or_default();
            let digest = parameters.digest_algorithm.digest(&content);
            let attributes = cades::signed_attributes(parameters, &digest);
            let encapsulation = if format == Format::Cades {
                Encapsulation::Attached
            } else {
                Encapsulation::Detached
            };
            State::Cades {
                attributes,
                encapsulation,
                content,
            }
        }
        Format::Pades => {
            let pdf = objects
                .first()
                .map(|o| o.content.as_slice())
                .unwrap_or_default();
            // `PAdES` keeps the claimed signing time in the signature
            // dictionary's `/M`, and `EN 319 142-1 table 1` forbids the
            // `CAdES` `signing-time` attribute alongside it. Carrying
            // both would be two records of one fact with two chances to
            // disagree, and a validator that finds the attribute grades
            // the result `PAdES-BES` rather than the baseline profile.
            //
            // So the time the caller gave moves from one to the other
            // here. The caller still states it once.
            let mut pdf_metadata = metadata.clone();
            if pdf_metadata.signing_time.is_none() {
                pdf_metadata.signing_time = parameters.signing_time.map(pdf_date);
            }
            let placeholder =
                pades::prepare(pdf, &pdf_metadata, pades::DEFAULT_SIGNATURE_CAPACITY)?;
            let digest = placeholder.digest(parameters.digest_algorithm);
            let mut cms_parameters = *parameters;
            cms_parameters.signing_time = None;
            let attributes = cades::signed_attributes(&cms_parameters, &digest);
            State::Pades {
                attributes,
                placeholder: Box::new(placeholder),
            }
        }
        Format::AsicECades => {
            let container = asic::plan(objects, parameters.digest_algorithm);
            let digest = container.digest(parameters.digest_algorithm);
            let attributes = cades::signed_attributes(parameters, &digest);
            State::AsicECades {
                attributes,
                container,
            }
        }
        Format::AsicEXades => {
            let signature = xades::plan(&objects, parameters)?;
            State::AsicEXades { signature, objects }
        }
    };
    Ok(DocumentPlan { state })
}

#[cfg(test)]
mod tests {
    use crate::sign::validation::ValidationMaterial;

    use super::{DataObject, DocumentError, Format, SignatureMetadata, SignerParameters, plan};
    use crate::sign::cades::{DigestAlgorithm, SignatureAlgorithm, SigningTime};
    use crate::x509::Certificate;

    const CERTIFICATE_DER: &[u8] = include_bytes!(
        "../../../refineid-client/test-vectors/fineid-intermediate-01-citizen-g4e.der"
    );

    /// The smallest thing `pades::prepare` accepts, so the format can
    /// be exercised without a fixture file.
    fn minimal_pdf() -> Vec<u8> {
        let bodies = [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R >>",
        ];
        let mut pdf = Vec::from("%PDF-1.4\n");
        let mut offsets = Vec::new();
        for (index, body) in bodies.iter().enumerate() {
            offsets.push(pdf.len());
            pdf.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", index + 1).as_bytes());
        }
        let xref_at = pdf.len();
        pdf.extend_from_slice(format!("xref\n0 {}\n", bodies.len() + 1).as_bytes());
        pdf.extend_from_slice(b"0000000000 65535 f \n");
        for offset in offsets {
            pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        pdf.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n",
                bodies.len() + 1
            )
            .as_bytes(),
        );
        pdf
    }

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

    fn objects(count: usize) -> Vec<DataObject> {
        (0..count)
            .map(|index| DataObject {
                name: format!("file{index}.txt"),
                mime_type: "text/plain".to_owned(),
                content: format!("contents {index}").into_bytes(),
            })
            .collect()
    }

    /// Every format reaches a signature and back without the caller
    /// knowing which one it picked.
    #[test]
    fn every_format_plans_and_finishes() {
        let certificate = Certificate::from_der(CERTIFICATE_DER).expect("certificate");
        let parameters = signer(&certificate);
        for format in [
            Format::Cades,
            Format::CadesDetached,
            Format::Pades,
            Format::AsicECades,
            Format::AsicEXades,
        ] {
            let files = if format == Format::Pades {
                vec![DataObject {
                    name: "doc.pdf".to_owned(),
                    mime_type: "application/pdf".to_owned(),
                    content: minimal_pdf(),
                }]
            } else {
                objects(1)
            };
            let document_plan = plan(format, files, &parameters, &SignatureMetadata::default())
                .unwrap_or_else(|error| panic!("{format:?} plan: {error}"));
            assert!(
                !document_plan.to_be_signed().is_empty(),
                "{format:?} must have octets to sign"
            );
            // An RSA-shaped signature: the length is what a 3072-bit
            // key produces, and nothing here verifies it.
            let output = document_plan
                .finish(
                    &parameters,
                    &[0x41; 384],
                    &[],
                    &ValidationMaterial::default(),
                )
                .unwrap_or_else(|error| panic!("{format:?} finish: {error}"));
            assert!(!output.is_empty(), "{format:?} produced nothing");
        }
    }

    /// A PDF that came out of `finish` is still a PDF, and an archive
    /// is still an archive. Cheap, but it catches a plan wired to the
    /// The signing time goes in the `PDF` and nowhere else.
    ///
    /// EN 319 142-1 puts the claimed time in the signature
    /// dictionary's `/M`, and a `CAdES` `signing-time` attribute
    /// beside it is two records of one fact with two chances to
    /// disagree -- a validator that finds the attribute grades the
    /// result `PAdES-BES` rather than the baseline profile, which is
    /// the whole point of putting it in one place.
    ///
    /// This is pinned because it has been wrong before: a
    /// `signing-time` attribute in the `CAdES` was one of three
    /// reasons `DVV` refused an earlier build's `PAdES`, and the
    /// caller still passes a signing time -- `plan` moves it, and a
    /// refactor that stopped moving it would look harmless.
    #[test]
    fn a_pades_signature_carries_no_signing_time_attribute() {
        /// `id-signingTime`, as a DER `OBJECT IDENTIFIER` TLV.
        const SIGNING_TIME_TLV: &[u8] = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05,
        ];

        let certificate = Certificate::from_der(CERTIFICATE_DER).expect("certificate");
        let parameters = signer(&certificate);
        // The caller asks for a signing time, so the attribute would
        // be there if nothing moved it.
        assert!(parameters.signing_time.is_some());

        let plan = plan(
            Format::Pades,
            vec![DataObject {
                name: "doc.pdf".to_owned(),
                mime_type: "application/pdf".to_owned(),
                content: minimal_pdf(),
            }],
            &parameters,
            &SignatureMetadata::default(),
        )
        .expect("plan");

        assert!(
            !plan
                .to_be_signed()
                .windows(SIGNING_TIME_TLV.len())
                .any(|window| window == SIGNING_TIME_TLV),
            "a PAdES signature named the CAdES signing-time attribute"
        );

        // ...and the time did not simply vanish: the PDF carries it.
        let signed = plan
            .finish(
                &parameters,
                &[0x41; 384],
                &[],
                &ValidationMaterial::default(),
            )
            .expect("finish");
        assert!(
            signed.windows(3).any(|window| window == b"/M "),
            "the signature dictionary carries no /M"
        );
    }

    /// wrong assembler.
    #[test]
    fn each_format_produces_its_own_shape() {
        let certificate = Certificate::from_der(CERTIFICATE_DER).expect("certificate");
        let parameters = signer(&certificate);

        let pdf = plan(
            Format::Pades,
            vec![DataObject {
                name: "doc.pdf".to_owned(),
                mime_type: "application/pdf".to_owned(),
                content: minimal_pdf(),
            }],
            &parameters,
            &SignatureMetadata::default(),
        )
        .expect("plan")
        .finish(
            &parameters,
            &[0x41; 384],
            &[],
            &ValidationMaterial::default(),
        )
        .expect("finish");
        assert!(pdf.starts_with(b"%PDF-"), "PAdES must still be a PDF");

        for format in [Format::AsicECades, Format::AsicEXades] {
            let archive = plan(
                format,
                objects(2),
                &parameters,
                &SignatureMetadata::default(),
            )
            .expect("plan")
            .finish(
                &parameters,
                &[0x41; 384],
                &[],
                &ValidationMaterial::default(),
            )
            .expect("finish");
            assert_eq!(&archive[..2], b"PK", "{format:?} must be a ZIP");
        }

        let cms = plan(
            Format::CadesDetached,
            objects(1),
            &parameters,
            &SignatureMetadata::default(),
        )
        .expect("plan")
        .finish(
            &parameters,
            &[0x41; 384],
            &[],
            &ValidationMaterial::default(),
        )
        .expect("finish");
        assert_eq!(cms.first(), Some(&0x30), "CMS must be a DER SEQUENCE");
    }

    /// Where the signing time goes decides the profile. `EN 319 142-1`
    /// puts a `PAdES` claimed time in the signature dictionary's `/M` and
    /// forbids the `CAdES` attribute; a validator that finds the
    /// attribute grades the result `PAdES-BES` instead of the baseline
    /// profile, and the signature is worth less for it.
    #[test]
    fn pades_puts_the_signing_time_in_the_pdf_not_the_attributes() {
        let certificate = Certificate::from_der(CERTIFICATE_DER).expect("certificate");
        let parameters = signer(&certificate);
        let document_plan = plan(
            Format::Pades,
            vec![DataObject {
                name: "doc.pdf".to_owned(),
                mime_type: "application/pdf".to_owned(),
                content: minimal_pdf(),
            }],
            &parameters,
            &SignatureMetadata::default(),
        )
        .expect("plan");

        // 1.2.840.113549.1.9.5 is signing-time; its DER prefix is the
        // OID's encoded octets. It must not be among the attributes.
        let signing_time_oid = [
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05,
        ];
        let attributes = document_plan.to_be_signed();
        assert!(
            !attributes
                .windows(signing_time_oid.len())
                .any(|window| window == signing_time_oid),
            "PAdES must not carry the CAdES signing-time attribute"
        );

        let pdf = document_plan
            .finish(
                &parameters,
                &[0x41; 384],
                &[],
                &ValidationMaterial::default(),
            )
            .expect("finish");
        let text = String::from_utf8_lossy(&pdf);
        assert!(
            text.contains("/M (D:20260803123456+00'00')"),
            "the claimed time belongs in /M"
        );
    }

    /// The other formats keep the attribute, because it is where the
    /// signing time lives for them.
    #[test]
    fn the_cms_formats_keep_the_signing_time_attribute() {
        let certificate = Certificate::from_der(CERTIFICATE_DER).expect("certificate");
        let parameters = signer(&certificate);
        let signing_time_oid = [
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05,
        ];
        for format in [Format::Cades, Format::CadesDetached, Format::AsicECades] {
            let document_plan = plan(
                format,
                objects(1),
                &parameters,
                &SignatureMetadata::default(),
            )
            .expect("plan");
            assert!(
                document_plan
                    .to_be_signed()
                    .windows(signing_time_oid.len())
                    .any(|window| window == signing_time_oid),
                "{format:?} must carry signing-time"
            );
        }
    }

    /// A timestamp is computed over the signature, so it cannot be
    /// among the attributes the signature covers -- it has to ride in
    /// `unsignedAttrs`. Getting that backwards is not a subtle bug: the
    /// structure would have to contain a hash of itself.
    #[test]
    fn a_timestamp_rides_outside_the_signed_attributes() {
        let certificate = Certificate::from_der(CERTIFICATE_DER).expect("certificate");
        let parameters = signer(&certificate);
        let token = b"a stand-in for a TimeStampToken".to_vec();

        let document_plan = plan(
            Format::CadesDetached,
            objects(1),
            &parameters,
            &SignatureMetadata::default(),
        )
        .expect("plan");
        // The octets the card signs must not mention the token.
        let signed = document_plan.to_be_signed().to_vec();
        assert!(
            !signed.windows(token.len()).any(|window| window == token),
            "the token cannot be inside what the signature covers"
        );
        let cms = document_plan
            .finish(
                &parameters,
                &[0x41; 384],
                std::slice::from_ref(&token),
                &ValidationMaterial::default(),
            )
            .expect("finish");
        assert!(
            cms.windows(token.len()).any(|window| window == token),
            "the token must reach the structure"
        );
        // 0xA1 is `unsignedAttrs [1] IMPLICIT`; it appears only when a
        // token is attached.
        let without = plan(
            Format::CadesDetached,
            objects(1),
            &parameters,
            &SignatureMetadata::default(),
        )
        .expect("plan")
        .finish(
            &parameters,
            &[0x41; 384],
            &[],
            &ValidationMaterial::default(),
        )
        .expect("finish");
        assert!(
            cms.len() > without.len(),
            "the timestamped structure carries more"
        );
    }

    /// Several authorities may attest the same signature. They are
    /// alternatives, not a chain: the signature keeps a proven time for
    /// as long as any one of them is still trusted, which matters over
    /// the years a certificate stays valid.
    #[test]
    fn several_timestamps_each_get_their_own_attribute() {
        let certificate = Certificate::from_der(CERTIFICATE_DER).expect("certificate");
        let parameters = signer(&certificate);
        let tokens = vec![
            b"token from the first authority".to_vec(),
            b"token from the second authority".to_vec(),
            b"token from the third authority".to_vec(),
        ];
        let cms = plan(
            Format::CadesDetached,
            objects(1),
            &parameters,
            &SignatureMetadata::default(),
        )
        .expect("plan")
        .finish(
            &parameters,
            &[0x41; 384],
            &tokens,
            &ValidationMaterial::default(),
        )
        .expect("finish");

        for token in &tokens {
            assert!(
                cms.windows(token.len()).any(|window| window == token),
                "every token must reach the structure"
            );
        }
        // The attribute OID appears once per token: separate instances,
        // which is the shape EN 319 122-1 describes and validators look
        // for, not one attribute holding three values.
        let oid = [
            0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E,
        ];
        let instances = cms.windows(oid.len()).filter(|w| *w == oid).count();
        assert_eq!(instances, 3, "one attribute instance per authority");
    }

    /// A repeated token is not two attestations. DER SET OF has no
    /// room for duplicates and a validator counting them would be
    /// counting the same evidence twice.
    #[test]
    fn a_repeated_token_is_collapsed() {
        let certificate = Certificate::from_der(CERTIFICATE_DER).expect("certificate");
        let parameters = signer(&certificate);
        let token = b"the very same token".to_vec();
        let cms = plan(
            Format::CadesDetached,
            objects(1),
            &parameters,
            &SignatureMetadata::default(),
        )
        .expect("plan")
        .finish(
            &parameters,
            &[0x41; 384],
            &[token.clone(), token],
            &ValidationMaterial::default(),
        )
        .expect("finish");
        let oid = [
            0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E,
        ];
        assert_eq!(cms.windows(oid.len()).filter(|w| *w == oid).count(), 1);
    }

    /// `XAdES` timestamps the canonicalised `ds:SignatureValue`
    /// element rather than the signature octets, so the digest handed
    /// to the TSA must be over the element -- angle brackets, namespace
    /// declaration, `Id` and all.
    #[test]
    fn xades_timestamps_the_element_not_the_octets() {
        let certificate = Certificate::from_der(CERTIFICATE_DER).expect("certificate");
        let parameters = signer(&certificate);
        let document_plan = plan(
            Format::AsicEXades,
            objects(1),
            &parameters,
            &SignatureMetadata::default(),
        )
        .expect("plan");
        let signature = [0x41; 96];

        let element = crate::sign::xades::SignaturePlan::signature_value_element(&signature);
        assert!(element.starts_with("<ds:SignatureValue xmlns:ds="));
        assert_eq!(
            document_plan
                .timestamp_digest(&parameters, &signature, DigestAlgorithm::Sha256)
                .expect("digest"),
            DigestAlgorithm::Sha256.digest(element.as_bytes()),
            "the digest must be over the canonical element"
        );
        // And not over the raw signature, which is the easy mistake.
        assert_ne!(
            document_plan
                .timestamp_digest(&parameters, &signature, DigestAlgorithm::Sha256)
                .expect("digest"),
            DigestAlgorithm::Sha256.digest(&signature)
        );

        let container = document_plan
            .finish(
                &parameters,
                &signature,
                &[b"a token".to_vec()],
                &ValidationMaterial::default(),
            )
            .expect("finish");
        let text = String::from_utf8_lossy(&container);
        assert!(text.contains("<xades:SignatureTimeStamp"));
        assert!(text.contains("<xades:EncapsulatedTimeStamp>"));
        // The element written must be the element digested.
        assert!(
            text.contains(&element),
            "SignatureValue must match byte for byte"
        );
    }

    #[test]
    fn one_file_formats_refuse_a_set() {
        let certificate = Certificate::from_der(CERTIFICATE_DER).expect("certificate");
        let parameters = signer(&certificate);
        for format in [Format::Cades, Format::CadesDetached, Format::Pades] {
            assert_eq!(
                plan(
                    format,
                    objects(2),
                    &parameters,
                    &SignatureMetadata::default()
                )
                .err(),
                Some(DocumentError::SingleFileOnly { format, offered: 2 }),
                "{format:?} must refuse two files"
            );
        }
        assert_eq!(
            plan(
                Format::AsicECades,
                Vec::new(),
                &parameters,
                &SignatureMetadata::default()
            )
            .err(),
            Some(DocumentError::NoInput)
        );
    }

    #[test]
    fn container_formats_refuse_ambiguous_object_names() {
        let certificate = Certificate::from_der(CERTIFICATE_DER).expect("certificate");
        let parameters = signer(&certificate);
        for name in [
            "",
            "mimetype",
            "META-INF",
            "META-INF/signature.p7s",
            "/absolute.pdf",
            "a/../b.pdf",
            "a/./b.pdf",
            "a//b.pdf",
            r"a\b.pdf",
            "bad\u{7f}.pdf",
        ] {
            let mut files = objects(1);
            files[0].name = name.to_owned();
            assert_eq!(
                plan(
                    Format::AsicECades,
                    files,
                    &parameters,
                    &SignatureMetadata::default()
                )
                .err(),
                Some(DocumentError::UnusableObjectName),
                "{name:?} must not be accepted as an archive entry"
            );
        }
    }

    #[test]
    fn harmless_dots_inside_a_path_component_are_allowed() {
        let certificate = Certificate::from_der(CERTIFICATE_DER).expect("certificate");
        let parameters = signer(&certificate);
        let mut files = objects(1);
        files[0].name = "a..b.pdf".to_owned();
        assert!(
            plan(
                Format::AsicECades,
                files,
                &parameters,
                &SignatureMetadata::default()
            )
            .is_ok()
        );
    }

    /// The card returns ECDSA as a raw coordinate pair. CMS needs DER,
    /// so the CMS formats must convert and the XML one must not.
    #[test]
    fn ecdsa_is_re_encoded_only_where_cms_needs_it() {
        let certificate = Certificate::from_der(CERTIFICATE_DER).expect("certificate");
        let mut parameters = signer(&certificate);
        parameters.signature_algorithm = SignatureAlgorithm::EcdsaSha384;
        parameters.digest_algorithm = DigestAlgorithm::Sha384;

        // 96 octets: P-384's pair.
        let raw = [0x7F; 96];
        let cms = plan(
            Format::CadesDetached,
            objects(1),
            &parameters,
            &SignatureMetadata::default(),
        )
        .expect("plan")
        .finish(&parameters, &raw, &[], &ValidationMaterial::default())
        .expect("finish");
        // The DER form is longer than the raw pair -- two INTEGER
        // headers -- so the raw bytes cannot have been passed through.
        assert!(
            cms.windows(raw.len()).all(|window| window != raw),
            "the raw pair must not appear verbatim in the CMS"
        );

        // An odd length is not a coordinate pair.
        assert_eq!(
            plan(
                Format::CadesDetached,
                objects(1),
                &parameters,
                &SignatureMetadata::default()
            )
            .expect("plan")
            .finish(
                &parameters,
                &[0x01; 95],
                &[],
                &ValidationMaterial::default()
            )
            .err(),
            Some(DocumentError::MalformedEcdsaSignature { length: 95 })
        );
    }
}

/// The routed formats, checked by the verifiers that judge each one.
///
/// The per-format modules each prove their own output. What is left
/// unproven by those is this module's wiring: it computes the digest
/// every format is planned around, so routing a format to the right
/// assembler with the wrong digest would pass every test above and
/// produce a document nothing accepts. Signing for real and handing
/// the result to `openssl` and `xmlsec1` is what closes that gap.
///
/// Ignored by default -- needs `openssl`, `xmlsec1` and `unzip`. Run:
///
/// ```text
/// cargo test -p refineid-lib-core --lib sign::document::interop -- --ignored --nocapture
/// ```
#[cfg(test)]
mod interop {
    use crate::sign::validation::ValidationMaterial;

    use std::path::Path;
    use std::process::Command;

    use super::{DataObject, Format, SignatureMetadata, SignerParameters, plan};
    use crate::sign::cades::{DigestAlgorithm, SignatureAlgorithm, SigningTime};
    use crate::x509::Certificate;

    /// Run a command in `directory` and fail loudly, returning output.
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

    /// Stand in for the card: sign the plan's octets with OpenSSL,
    /// producing the same PKCS#1 signature a card with an RSA key
    /// would.
    fn sign_like_a_card(dir: &Path, to_be_signed: &[u8]) -> Vec<u8> {
        std::fs::write(dir.join("tbs.bin"), to_be_signed).expect("write tbs");
        run_in(
            dir,
            "openssl",
            &[
                "dgst", "-sha256", "-sign", "key.pem", "-out", "sig.bin", "tbs.bin",
            ],
        );
        std::fs::read(dir.join("sig.bin")).expect("signature")
    }

    /// A key and certificate in `dir`, and the parsed DER.
    fn issue_certificate(dir: &Path, common_name: &str) -> Vec<u8> {
        run_in(
            dir,
            "openssl",
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:3072",
                "-sha256",
                "-days",
                "1",
                "-nodes",
                "-subj",
                &format!("/CN={common_name}"),
                "-keyout",
                "key.pem",
                "-out",
                "cert.pem",
            ],
        );
        run_in(
            dir,
            "openssl",
            &[
                "x509", "-in", "cert.pem", "-outform", "DER", "-out", "cert.der",
            ],
        );
        std::fs::read(dir.join("cert.der")).expect("cert.der")
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(name);
        let _ignored = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn parameters_for<'a>(certificate: &'a Certificate<'a>) -> SignerParameters<'a> {
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

    /// A detached `CAdES` routed through this module, checked by
    /// OpenSSL against the original file.
    #[test]
    #[ignore = "requires the openssl binary"]
    fn openssl_verifies_a_routed_cades() {
        let dir = scratch("refineid-document-cades");
        let certificate_der = issue_certificate(&dir, "ReFineID document CAdES");
        let certificate = Certificate::from_der(&certificate_der).expect("certificate");
        let parameters = parameters_for(&certificate);

        let content = b"ReFineID -- declaration d'un moyen de cryptologie".to_vec();
        std::fs::write(dir.join("doc.bin"), &content).expect("write doc");
        let objects = vec![DataObject {
            name: "doc.bin".to_owned(),
            mime_type: "application/octet-stream".to_owned(),
            content,
        }];

        let document_plan = plan(
            Format::CadesDetached,
            objects,
            &parameters,
            &SignatureMetadata::default(),
        )
        .expect("plan");
        let signature = sign_like_a_card(&dir, document_plan.to_be_signed());
        let cms = document_plan
            .finish(&parameters, &signature, &[], &ValidationMaterial::default())
            .expect("finish");
        std::fs::write(dir.join("out.p7s"), &cms).expect("write cms");

        let report = run_in(
            &dir,
            "openssl",
            &[
                "cms",
                "-verify",
                "-inform",
                "DER",
                "-in",
                "out.p7s",
                "-content",
                "doc.bin",
                "-binary",
                "-CAfile",
                "cert.pem",
                "-purpose",
                "any",
                "-out",
                "/dev/null",
            ],
        );
        println!("{report}");

        // And it must refuse a document that changed.
        std::fs::write(dir.join("doc.bin"), b"tampered").expect("tamper");
        let tampered = Command::new("openssl")
            .current_dir(&dir)
            .args([
                "cms",
                "-verify",
                "-inform",
                "DER",
                "-in",
                "out.p7s",
                "-content",
                "doc.bin",
                "-binary",
                "-CAfile",
                "cert.pem",
                "-purpose",
                "any",
                "-out",
                "/dev/null",
            ])
            .output()
            .expect("openssl runnable");
        assert!(
            !tampered.status.success(),
            "a changed document must break the signature"
        );
    }

    /// An `ASiC-E` container routed through this module, taken apart by
    /// `unzip` and checked by `xmlsec1`.
    #[test]
    #[ignore = "requires the openssl, xmlsec1 and unzip binaries"]
    fn xmlsec1_verifies_a_routed_container() {
        let dir = scratch("refineid-document-asice");
        let certificate_der = issue_certificate(&dir, "ReFineID document ASiC");
        let certificate = Certificate::from_der(&certificate_der).expect("certificate");
        let parameters = parameters_for(&certificate);

        let objects = vec![
            DataObject {
                name: "dossier.pdf".to_owned(),
                mime_type: "application/pdf".to_owned(),
                content: b"declaration d'un moyen de cryptologie".to_vec(),
            },
            DataObject {
                name: "annexe.txt".to_owned(),
                mime_type: "text/plain".to_owned(),
                content: b"fiche technique".to_vec(),
            },
        ];

        let document_plan = plan(
            Format::AsicEXades,
            objects,
            &parameters,
            &SignatureMetadata::default(),
        )
        .expect("plan");
        let signature = sign_like_a_card(&dir, document_plan.to_be_signed());
        let container = document_plan
            .finish(&parameters, &signature, &[], &ValidationMaterial::default())
            .expect("finish");
        std::fs::write(dir.join("out.asice"), &container).expect("write container");

        run_in(&dir, "unzip", &["-o", "-q", "out.asice", "-d", "extracted"]);
        let report = run_in(
            &dir.join("extracted"),
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
            "the routed container must verify:\n{report}"
        );
        assert!(
            report.contains("SignedInfo References (ok/all): 3/3"),
            "every reference must be checked:\n{report}"
        );
    }
}
