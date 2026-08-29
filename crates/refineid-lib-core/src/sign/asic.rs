//! `ASiC-E` containers: a ZIP holding documents and the signature over
//! them.
//!
//! Where `PAdES` puts the signature inside the document, `ASiC` puts the
//! documents and the signature side by side in one archive. That is the
//! right shape when a submission is several files -- a form, a dossier,
//! an attachment -- because one signature then covers the set rather
//! than one member of it.
//!
//! # What is actually signed
//!
//! Not the files. The signature is a detached `CAdES` over
//! `META-INF/ASiCManifest.xml`, and the manifest carries a digest of
//! each file. So the chain is: signature attests the manifest, manifest
//! attests the files. Changing a byte of any file breaks its digest in
//! the manifest, which breaks the signature over the manifest.
//!
//! This indirection is why the API is two-phase in the same way `CAdES`
//! and `PAdES` are: [`plan`] builds the manifest and hands out the
//! octets to sign, [`ContainerPlan::finish`] takes the signature back
//! and writes the archive.
//!
//! # The mimetype rule
//!
//! `EN 319 162-1 sec.A.1` requires the first archive entry to be named
//! `mimetype`, stored uncompressed, with no extra field. It exists so a
//! reader can identify the container by reading a fixed offset near the
//! start of the file rather than parsing the ZIP directory. This writer
//! stores every entry uncompressed, which satisfies that rule by
//! construction and keeps the archive verifiable without a decompressor.
//!
//! # Conformance
//!
//! - `ETSI EN 319 162-1`: `ASiC-E`, `ASiCManifest`, the mimetype rule.
//! - `ISO/IEC 21320-1`: the ZIP profile -- stored or deflated only, no
//!   encryption, no multi-volume.

use core::fmt::Write as _;

use crate::base64;
use crate::sign::cades::DigestAlgorithm;
use crate::sign::xades::{
    DIGEST_METHOD_SHA256, DIGEST_METHOD_SHA384, NAMESPACE_DSIG, escape_attribute,
    percent_encode_path,
};

/// Media type of an `ASiC-E` container.
const MIMETYPE_ASICE: &str = "application/vnd.etsi.asic-e+zip";

/// Entry name the media type must be stored under, first, uncompressed.
const MIMETYPE_ENTRY: &str = "mimetype";

/// Where the manifest lives, in the `CAdES` flavour.
const MANIFEST_ENTRY: &str = "META-INF/ASiCManifest.xml";

/// Where the detached `CAdES` lives.
const SIGNATURE_ENTRY: &str = "META-INF/signature.p7s";

/// Media type of a `CAdES` detached signature, named by the manifest.
const MIMETYPE_SIGNATURE: &str = "application/pkcs7-signature";

/// Where the archive manifest lives (`EN 319 162-1 clause A.7`).
///
/// The name is fixed: the file called this is always the most recently
/// added one, and earlier ones are renamed as newer ones arrive.
const ARCHIVE_MANIFEST_ENTRY: &str = "META-INF/ASiCArchiveManifest.xml";

/// Where the archive timestamp token lives. The clause allows any
/// `META-INF/*timestamp*.tst`; this picks one and keeps to it.
const ARCHIVE_TIMESTAMP_ENTRY: &str = "META-INF/timestamp.tst";

/// Media type of an RFC 3161 token, named by the archive manifest.
const MIMETYPE_TIMESTAMP: &str = "application/vnd.etsi.timestamp-token";

/// Media type recorded for the XML files the archive manifest covers.
const MIMETYPE_XML: &str = "text/xml";

/// Where the manifest lives, in the `XAdES` flavour.
///
/// A different file with a different schema, not a renaming of the one
/// above. See [`xades_container`].
const MANIFEST_ENTRY_ODF: &str = "META-INF/manifest.xml";

/// Where an `XAdES` signature lives.
///
/// Numbered, because a container may carry several signatures over the
/// same files. This writer produces the first.
const SIGNATURE_ENTRY_XADES: &str = "META-INF/signatures0.xml";

/// `OpenDocument` manifest namespace, which `ASiC` reuses rather than
/// defining its own (`EN 319 162-1 sec.A.5`).
const NAMESPACE_MANIFEST: &str = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";

/// `ASiC` namespace (`EN 319 162-1`).
pub(crate) const NAMESPACE_ASIC: &str = "http://uri.etsi.org/02918/v1.2.1#";

/// One file to be carried and attested.
#[derive(Debug, Clone)]
pub struct DataObject {
    /// Entry name inside the container. Also the `URI` in the manifest.
    pub name: String,
    /// Media type recorded for the entry.
    pub mime_type: String,
    /// The file's bytes.
    pub content: Vec<u8>,
}

/// A container with its manifest built and its signature still missing.
#[derive(Debug, Clone)]
pub struct ContainerPlan {
    /// The files to carry.
    objects: Vec<DataObject>,
    /// `META-INF/ASiCManifest.xml`, exactly as it will be stored.
    manifest: Vec<u8>,
}

impl ContainerPlan {
    /// The octets the signature covers.
    ///
    /// The manifest as it will be written, byte for byte. Signing
    /// anything else -- a re-serialisation, a pretty-printed copy --
    /// produces a container that verifies against nothing.
    #[must_use]
    pub fn manifest(&self) -> &[u8] {
        &self.manifest
    }

    /// Digest of the manifest, for the `CAdES` `message-digest`.
    #[must_use]
    pub fn digest(&self, algorithm: DigestAlgorithm) -> Vec<u8> {
        algorithm.digest(&self.manifest)
    }

    /// Write the finished `.asice` archive.
    ///
    /// Entry order is fixed and load-bearing: `mimetype` first for the
    /// reason in the module docs, then the data objects, then the
    /// manifest and the signature under `META-INF/`.
    #[must_use]
    pub fn finish(self, signature_der: &[u8]) -> Option<Vec<u8>> {
        let mut archive = ZipWriter::new();
        archive.add(MIMETYPE_ENTRY, MIMETYPE_ASICE.as_bytes());
        for object in &self.objects {
            archive.add(&object.name, &object.content);
        }
        archive.add(MANIFEST_ENTRY, &self.manifest);
        archive.add(SIGNATURE_ENTRY, signature_der);
        archive.finish()
    }
}

impl ContainerPlan {
    /// Build the archive manifest covering everything in the container.
    ///
    /// `EN 319 162-1 clause A.7`. An `ASiC-E` `CAdES` container does not
    /// reach long-term protection through a `CAdES` archive-timestamp
    /// attribute -- clause 4.4.5 item 2 sends it here instead. A second
    /// manifest lists the data objects, the first manifest and the
    /// signature, each with a digest, and a timestamp over that manifest
    /// attests the lot.
    ///
    /// The result covers the signature, so it can only be built once the
    /// card has produced one.
    #[must_use]
    pub fn archive_manifest(&self, signature_der: &[u8], algorithm: DigestAlgorithm) -> Vec<u8> {
        let method = digest_method_uri(algorithm);
        let mut manifest = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
        let _ignored = writeln!(
            manifest,
            "\n<asic:ASiCManifest xmlns:asic=\"{NAMESPACE_ASIC}\" xmlns:ds=\"{NAMESPACE_DSIG}\">"
        );
        // The token that attests this manifest, not the signature: a
        // reader follows SigReference to whatever protects the file it
        // is reading.
        let _ignored = writeln!(
            manifest,
            "  <asic:SigReference URI=\"{ARCHIVE_TIMESTAMP_ENTRY}\" MimeType=\"{MIMETYPE_TIMESTAMP}\"/>"
        );
        // Everything already in the container: the data, the manifest
        // that binds it, and the signature over that manifest. Leaving
        // any of them out would let it be swapped without detection.
        for (name, mime, content) in self
            .objects
            .iter()
            .map(|object| {
                (
                    object.name.as_str(),
                    object.mime_type.as_str(),
                    object.content.as_slice(),
                )
            })
            .chain([
                (MANIFEST_ENTRY, MIMETYPE_XML, self.manifest.as_slice()),
                (SIGNATURE_ENTRY, MIMETYPE_SIGNATURE, signature_der),
            ])
        {
            let digest = base64::encode(&algorithm.digest(content));
            let uri = escape_attribute(&percent_encode_path(name));
            let media = escape_attribute(mime);
            let _ignored = writeln!(
                manifest,
                "  <asic:DataObjectReference URI=\"{uri}\" MimeType=\"{media}\">"
            );
            let _ignored = writeln!(manifest, "    <ds:DigestMethod Algorithm=\"{method}\"/>");
            let _ignored = writeln!(manifest, "    <ds:DigestValue>{digest}</ds:DigestValue>");
            manifest.push_str("  </asic:DataObjectReference>\n");
        }
        manifest.push_str("</asic:ASiCManifest>\n");
        manifest.into_bytes()
    }

    /// Write the archive-protected `.asice`.
    ///
    /// As [`Self::finish`], plus the archive manifest and the token
    /// that attests it.
    #[must_use]
    pub fn finish_archived(
        self,
        signature_der: &[u8],
        archive_manifest: &[u8],
        token: &[u8],
    ) -> Option<Vec<u8>> {
        let mut archive = ZipWriter::new();
        archive.add(MIMETYPE_ENTRY, MIMETYPE_ASICE.as_bytes());
        for object in &self.objects {
            archive.add(&object.name, &object.content);
        }
        archive.add(MANIFEST_ENTRY, &self.manifest);
        archive.add(SIGNATURE_ENTRY, signature_der);
        archive.add(ARCHIVE_MANIFEST_ENTRY, archive_manifest);
        archive.add(ARCHIVE_TIMESTAMP_ENTRY, token);
        archive.finish()
    }
}

/// The `DigestMethod` identifier for a digest.
const fn digest_method_uri(algorithm: DigestAlgorithm) -> &'static str {
    match algorithm {
        DigestAlgorithm::Sha256 => DIGEST_METHOD_SHA256,
        DigestAlgorithm::Sha384 => DIGEST_METHOD_SHA384,
    }
}

/// Build the manifest for `objects` and return the plan to sign it.
#[must_use]
pub fn plan(objects: Vec<DataObject>, algorithm: DigestAlgorithm) -> ContainerPlan {
    let method = digest_method_uri(algorithm);

    let mut manifest = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    // `writeln!` into a String cannot fail; the result is discarded
    // rather than unwrapped so no formatting call can panic here.
    let _ignored = writeln!(
        manifest,
        "\n<asic:ASiCManifest xmlns:asic=\"{NAMESPACE_ASIC}\" xmlns:ds=\"{NAMESPACE_DSIG}\">"
    );
    let _ignored = writeln!(
        manifest,
        "  <asic:SigReference URI=\"{SIGNATURE_ENTRY}\" MimeType=\"{MIMETYPE_SIGNATURE}\"/>"
    );
    for object in &objects {
        let digest = base64::encode(&algorithm.digest(&object.content));
        let uri = escape_attribute(&percent_encode_path(&object.name));
        let mime = escape_attribute(&object.mime_type);
        let _ignored = writeln!(
            manifest,
            "  <asic:DataObjectReference URI=\"{uri}\" MimeType=\"{mime}\">"
        );
        let _ignored = writeln!(manifest, "    <ds:DigestMethod Algorithm=\"{method}\"/>");
        let _ignored = writeln!(manifest, "    <ds:DigestValue>{digest}</ds:DigestValue>");
        manifest.push_str("  </asic:DataObjectReference>\n");
    }
    manifest.push_str("</asic:ASiCManifest>\n");

    ContainerPlan {
        objects,
        manifest: manifest.into_bytes(),
    }
}

/// Write an `ASiC-E` container carrying an `XAdES` signature.
///
/// `signature_xml` is what [`crate::sign::xades::SignaturePlan::finish`]
/// produced.
///
/// # Why this is not [`ContainerPlan::finish`]
///
/// The two flavours of `ASiC-E` differ by more than which signature
/// file they carry. `CAdES` signs `ASiCManifest.xml`, which holds a
/// digest of every file, so the signature reaches the files only
/// through the manifest. `XAdES` has a `ds:Reference` per file and so
/// covers them directly; its `manifest.xml` is a borrowed
/// `OpenDocument` inventory that records media types and is not signed
/// at all. Same archive, opposite direction of attestation.
///
/// That is also why this takes a finished signature rather than
/// returning a plan: for `XAdES` the digests live in the signature, so
/// there is nothing for the container to compute.
///
/// # `.asice` and `.bdoc`
///
/// One writer, because they are one format. `BDOC 2.1` is `ASiC-E` with
/// `XAdES` -- same media type, same entry names, same signature -- and
/// the extension is all that differs. Estonian software writes `.bdoc`;
/// the rest of Europe writes `.asice`. Name the output file either way.
#[must_use]
pub fn xades_container(objects: &[DataObject], signature_xml: &[u8]) -> Option<Vec<u8>> {
    let mut archive = ZipWriter::new();
    archive.add(MIMETYPE_ENTRY, MIMETYPE_ASICE.as_bytes());
    for object in objects {
        archive.add(&object.name, &object.content);
    }
    archive.add(MANIFEST_ENTRY_ODF, &odf_manifest(objects));
    archive.add(SIGNATURE_ENTRY_XADES, signature_xml);
    archive.finish()
}

/// The `OpenDocument` inventory: one entry per file, plus the container.
///
/// Nothing signs this, so it is an aid to readers rather than evidence.
/// A verifier that trusted a media type from here would be trusting an
/// unsigned claim; the signed copy is in `DataObjectFormat`.
fn odf_manifest(objects: &[DataObject]) -> Vec<u8> {
    let mut manifest = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    let _ignored = writeln!(
        manifest,
        "\n<manifest:manifest xmlns:manifest=\"{NAMESPACE_MANIFEST}\">"
    );
    // The container itself, named by the root path. Required first.
    let _ignored = writeln!(
        manifest,
        r#"  <manifest:file-entry manifest:full-path="/" manifest:media-type="{MIMETYPE_ASICE}"/>"#
    );
    for object in objects {
        let path = escape_attribute(&object.name);
        let media = escape_attribute(&object.mime_type);
        let _ignored = writeln!(
            manifest,
            r#"  <manifest:file-entry manifest:full-path="{path}" manifest:media-type="{media}"/>"#
        );
    }
    manifest.push_str("</manifest:manifest>\n");
    manifest.into_bytes()
}

/// A minimal ZIP writer: stored entries only.
///
/// The workspace carries no ZIP crate and this needs one method of one
/// compression mode. Stored entries also mean the archive can be read
/// with nothing but an offset table, which is the property `ASiC` leans
/// on for the mimetype entry.
#[derive(Debug, Default)]
struct ZipWriter {
    /// Bytes written so far: local headers and entry data.
    out: Vec<u8>,
    /// Central-directory records, emitted at the end.
    directory: Vec<u8>,
    /// Number of entries added.
    count: u16,
    /// Set when an entry could not be described by the 32-bit fields.
    ///
    /// Sticky: once true the archive is unusable, so `finish` refuses
    /// rather than returning something that looks like a container.
    overflowed: bool,
}

/// Local file header signature.
const SIGNATURE_LOCAL_HEADER: u32 = 0x0403_4B50;

/// Central directory file header signature.
const SIGNATURE_CENTRAL_HEADER: u32 = 0x0201_4B50;

/// End of central directory signature.
const SIGNATURE_END_OF_DIRECTORY: u32 = 0x0605_4B50;

/// Minimum version needed to extract: 2.0, meaning stored or deflated.
const VERSION_NEEDED: u16 = 20;

/// Compression method 0: stored.
const METHOD_STORED: u16 = 0;

/// General-purpose bit 11: the entry name is UTF-8 (APPNOTE 4.4.4).
const UTF8_NAME_FLAG: u16 = 0x0800;

impl ZipWriter {
    /// A writer with nothing in it.
    fn new() -> Self {
        Self::default()
    }

    /// Append one stored entry.
    ///
    /// Returns false when the entry cannot be described by the 32-bit
    /// ZIP fields. Clamping instead would write a length that does not
    /// match the data and call it a success.
    fn add(&mut self, name: &str, content: &[u8]) -> bool {
        let (Ok(offset), Ok(size), Ok(name_length)) = (
            u32::try_from(self.out.len()),
            u32::try_from(content.len()),
            u16::try_from(name.len()),
        ) else {
            self.overflowed = true;
            return false;
        };
        let Some(next_count) = self.count.checked_add(1) else {
            self.overflowed = true;
            return false;
        };
        let crc = crc32(content);

        self.out
            .extend_from_slice(&SIGNATURE_LOCAL_HEADER.to_le_bytes());
        self.out.extend_from_slice(&VERSION_NEEDED.to_le_bytes());
        // Bit 11 declares the name UTF-8. Without it a reader falls
        // back to CP437 and "resume.txt" with accents comes out as
        // mojibake -- a data object whose name no longer matches the
        // one the manifest signed. No other flag: no encryption, no
        // data descriptor.
        let flags = if name.is_ascii() {
            0_u16
        } else {
            UTF8_NAME_FLAG
        };
        self.out.extend_from_slice(&flags.to_le_bytes());
        self.out.extend_from_slice(&METHOD_STORED.to_le_bytes());
        // Zero timestamps rather than a clock read: a container that is
        // byte-identical for identical inputs is worth more than a
        // modification time nobody consults.
        self.out.extend_from_slice(&0_u16.to_le_bytes());
        self.out.extend_from_slice(&0_u16.to_le_bytes());
        self.out.extend_from_slice(&crc.to_le_bytes());
        self.out.extend_from_slice(&size.to_le_bytes());
        self.out.extend_from_slice(&size.to_le_bytes());
        self.out.extend_from_slice(&name_length.to_le_bytes());
        self.out.extend_from_slice(&0_u16.to_le_bytes());
        self.out.extend_from_slice(name.as_bytes());
        self.out.extend_from_slice(content);

        self.directory
            .extend_from_slice(&SIGNATURE_CENTRAL_HEADER.to_le_bytes());
        // Version made by, then version needed.
        self.directory
            .extend_from_slice(&VERSION_NEEDED.to_le_bytes());
        self.directory
            .extend_from_slice(&VERSION_NEEDED.to_le_bytes());
        self.directory.extend_from_slice(&flags.to_le_bytes());
        self.directory
            .extend_from_slice(&METHOD_STORED.to_le_bytes());
        self.directory.extend_from_slice(&0_u16.to_le_bytes());
        self.directory.extend_from_slice(&0_u16.to_le_bytes());
        self.directory.extend_from_slice(&crc.to_le_bytes());
        self.directory.extend_from_slice(&size.to_le_bytes());
        self.directory.extend_from_slice(&size.to_le_bytes());
        self.directory.extend_from_slice(&name_length.to_le_bytes());
        // Extra field, comment, disk number, internal attributes.
        for _ in 0..4 {
            self.directory.extend_from_slice(&0_u16.to_le_bytes());
        }
        self.directory.extend_from_slice(&0_u32.to_le_bytes());
        self.directory.extend_from_slice(&offset.to_le_bytes());
        self.directory.extend_from_slice(name.as_bytes());

        self.count = next_count;
        true
    }

    /// Close the archive: central directory, then its locator.
    ///
    /// `None` when anything overflowed the 32-bit fields.
    fn finish(mut self) -> Option<Vec<u8>> {
        if self.overflowed {
            return None;
        }
        let directory_at = u32::try_from(self.out.len()).ok()?;
        let directory_size = u32::try_from(self.directory.len()).ok()?;
        self.out.extend_from_slice(&self.directory);
        self.out
            .extend_from_slice(&SIGNATURE_END_OF_DIRECTORY.to_le_bytes());
        // Disk numbers: single-volume, as ISO/IEC 21320-1 requires.
        self.out.extend_from_slice(&0_u16.to_le_bytes());
        self.out.extend_from_slice(&0_u16.to_le_bytes());
        self.out.extend_from_slice(&self.count.to_le_bytes());
        self.out.extend_from_slice(&self.count.to_le_bytes());
        self.out.extend_from_slice(&directory_size.to_le_bytes());
        self.out.extend_from_slice(&directory_at.to_le_bytes());
        self.out.extend_from_slice(&0_u16.to_le_bytes());
        Some(self.out)
    }
}

/// CRC-32 as ZIP defines it (IEEE 802.3 polynomial, reflected).
///
/// Computed bitwise rather than from a table: this runs once per entry
/// over files measured in kilobytes, and a 1 KiB table earns nothing
/// here but a thing to get wrong.
fn crc32(data: &[u8]) -> u32 {
    /// Reflected IEEE 802.3 polynomial.
    const POLYNOMIAL: u32 = 0xEDB8_8320;
    /// Bits per input byte.
    const BITS: usize = 8;
    let mut crc = u32::MAX;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..BITS {
            let carry = crc & 1;
            crc >>= 1;
            if carry != 0 {
                crc ^= POLYNOMIAL;
            }
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::{
        DataObject, MANIFEST_ENTRY, MIMETYPE_ASICE, MIMETYPE_ENTRY, SIGNATURE_ENTRY, ZipWriter,
        crc32, plan,
    };
    use crate::sign::cades::DigestAlgorithm;

    /// Local file header length before the entry name begins. A reader
    /// identifies the container by looking exactly here.
    const LOCAL_HEADER_LEN: usize = 30;

    fn sample() -> Vec<DataObject> {
        vec![DataObject {
            name: "dossier.pdf".to_owned(),
            mime_type: "application/pdf".to_owned(),
            content: b"a declaration of a means of cryptology".to_vec(),
        }]
    }

    #[test]
    fn crc32_matches_the_known_check_value() {
        // The standard CRC-32 check value for "123456789".
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn the_manifest_carries_a_digest_of_every_object() {
        let objects = sample();
        let expected = crate::base64::encode(&DigestAlgorithm::Sha256.digest(&objects[0].content));
        let plan = plan(objects, DigestAlgorithm::Sha256);
        let manifest = String::from_utf8(plan.manifest().to_vec()).expect("utf-8");
        assert!(manifest.contains(r#"URI="dossier.pdf""#));
        assert!(manifest.contains(&format!("<ds:DigestValue>{expected}</ds:DigestValue>")));
        assert!(manifest.contains(&format!(r#"URI="{SIGNATURE_ENTRY}""#)));
    }

    #[test]
    fn mimetype_is_first_and_stored_at_a_fixed_offset() {
        let archive = plan(sample(), DigestAlgorithm::Sha256)
            .finish(b"not really a cms")
            .expect("fits");
        let name_at = LOCAL_HEADER_LEN;
        let name_end = name_at + MIMETYPE_ENTRY.len();
        assert_eq!(&archive[name_at..name_end], MIMETYPE_ENTRY.as_bytes());
        assert_eq!(
            &archive[name_end..name_end + MIMETYPE_ASICE.len()],
            MIMETYPE_ASICE.as_bytes()
        );
    }

    #[test]
    fn every_expected_entry_is_present() {
        let archive = plan(sample(), DigestAlgorithm::Sha256)
            .finish(b"cms")
            .expect("fits");
        let text = String::from_utf8_lossy(&archive);
        for entry in [
            MIMETYPE_ENTRY,
            "dossier.pdf",
            MANIFEST_ENTRY,
            SIGNATURE_ENTRY,
        ] {
            assert!(text.contains(entry), "missing entry {entry}");
        }
    }

    #[test]
    fn too_many_entries_are_refused_before_the_count_wraps() {
        let mut archive = ZipWriter::new();
        archive.count = u16::MAX;
        assert!(!archive.add("one-too-many.txt", b""));
        assert!(archive.finish().is_none());
    }

    /// A name reaches the manifest as a URI, not as text: it is
    /// percent-encoded first (RFC 3986) and XML-escaped after. The
    /// order matters -- `#` XML-escapes to nothing and would silently
    /// truncate the reference to everything before it, so a verifier
    /// would digest the wrong file or none.
    #[test]
    fn names_are_percent_encoded_before_xml_escaping() {
        let objects = vec![DataObject {
            name: "a&b\"c#d e.pdf".to_owned(),
            mime_type: "application/pdf".to_owned(),
            content: b"x".to_vec(),
        }];
        let plan = plan(objects, DigestAlgorithm::Sha256);
        let manifest = String::from_utf8(plan.manifest().to_vec()).expect("utf-8");
        assert!(
            manifest.contains(r#"URI="a%26b%22c%23d%20e.pdf""#),
            "name must be percent-encoded: {manifest}"
        );
        // Nothing XML-special survives the encoding, so the escaper has
        // nothing left to do on a URI -- and the raw `#` never reaches
        // the attribute.
        assert!(!manifest.contains("c#d"), "a bare # would truncate the URI");
    }

    /// A media type is not a URI: it is XML-escaped and not encoded.
    #[test]
    fn media_types_are_escaped_but_not_encoded() {
        let objects = vec![DataObject {
            name: "a.bin".to_owned(),
            mime_type: "text/plain; x=\"1&2\"".to_owned(),
            content: b"x".to_vec(),
        }];
        let plan = plan(objects, DigestAlgorithm::Sha256);
        let manifest = String::from_utf8(plan.manifest().to_vec()).expect("utf-8");
        assert!(
            manifest.contains(r#"MimeType="text/plain; x=&quot;1&amp;2&quot;""#),
            "{manifest}"
        );
    }
}

/// The archive read back by tools that are not ours.
///
/// A hand-written ZIP that only this crate can open is not a container.
/// `unzip` walks the central directory, checks every CRC, and extracts;
/// if it agrees, the offsets and checksums are right.
///
/// Ignored by default -- needs `unzip`. Run:
///
/// ```text
/// cargo test -p refineid-lib-core --lib sign::asic::unzip -- --ignored --nocapture
/// ```
#[cfg(test)]
mod unzip_interop {
    use std::process::Command;

    use super::{DataObject, MIMETYPE_ASICE, MIMETYPE_ENTRY, plan};
    use crate::sign::cades::DigestAlgorithm;

    #[test]
    #[ignore = "requires the unzip binary"]
    fn unzip_reads_and_verifies_the_container() {
        let dir = std::env::temp_dir().join("refineid-asic-interop");
        let _ignored = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let container = dir.join("out.asice");

        let dossier = b"ReFineID -- declaration d'un moyen de cryptologie".to_vec();
        let objects = vec![
            DataObject {
                name: "dossier.pdf".to_owned(),
                mime_type: "application/pdf".to_owned(),
                content: dossier.clone(),
            },
            DataObject {
                name: "formulaire.pdf".to_owned(),
                mime_type: "application/pdf".to_owned(),
                content: b"annexe I, completee et signee".to_vec(),
            },
        ];
        let archive = plan(objects, DigestAlgorithm::Sha256)
            .finish(b"detached CAdES would go here")
            .expect("fits");
        std::fs::write(&container, &archive).expect("write container");

        // Every CRC and every offset, checked by an outside reader.
        let test = Command::new("unzip")
            .args(["-t", &container.to_string_lossy()])
            .output()
            .expect("unzip runnable");
        let report = String::from_utf8_lossy(&test.stdout).into_owned();
        println!("{report}");
        assert!(
            test.status.success(),
            "unzip rejected the archive:\n{report}{}",
            String::from_utf8_lossy(&test.stderr)
        );
        assert!(report.contains("No errors detected"), "{report}");

        // The entries come back byte-identical.
        let extracted = dir.join("x");
        let out = Command::new("unzip")
            .args([
                "-o",
                "-q",
                &container.to_string_lossy(),
                "-d",
                &extracted.to_string_lossy(),
            ])
            .output()
            .expect("unzip runnable");
        assert!(out.status.success(), "extraction failed");
        assert_eq!(
            std::fs::read(extracted.join("dossier.pdf")).expect("extracted"),
            dossier,
            "a data object must survive the round trip unchanged"
        );
        assert_eq!(
            std::fs::read(extracted.join(MIMETYPE_ENTRY)).expect("mimetype"),
            MIMETYPE_ASICE.as_bytes(),
            "the mimetype entry identifies the container"
        );
        assert!(
            extracted.join("META-INF/ASiCManifest.xml").exists(),
            "the manifest must be under META-INF"
        );
    }
}
