//! `PAdES`: a `CAdES` signature carried inside a PDF.
//!
//! The signature is appended as an *incremental update* -- the original
//! bytes are never touched, and everything new goes after them with a
//! fresh cross-reference section pointing back at the old one. That is
//! not a stylistic choice: `/ByteRange` covers the whole file either
//! side of the signature, so any edit to the original would invalidate
//! the signature it is meant to carry.
//!
//! # The circularity, and how it is broken
//!
//! A PDF signature signs the file it lives in. The signature's own
//! octets cannot be part of what is signed, so `/ByteRange` names two
//! spans -- everything before the signature and everything after it --
//! and the hole between them is exactly the `/Contents` hex string.
//!
//! Writing that requires knowing offsets that depend on what is written.
//! [`prepare`] resolves it by emitting the update with fixed-width
//! placeholders, so patching the real numbers in afterwards cannot move
//! a single byte. [`Placeholder::finish`] then splices the DER into the
//! hole without shifting anything.
//!
//! # Scope
//!
//! Both cross-reference shapes: classic tables and the streams that
//! replaced them in PDF 1.5, with the objects those index inside
//! object streams ([`xref_stream`]). A revision is closed in the shape
//! the document already uses. A stream behind a filter or predictor
//! this reader does not decode is refused with
//! [`PdfError::UnsupportedCrossReferenceStream`] rather than
//! mis-signed: an update whose xref the reader cannot follow produces a
//! file that opens and shows a broken signature, which is worse than a
//! refusal.
//!
//! # Conformance
//!
//! - ISO 32000-1 sec.12.8: signature dictionary, `/ByteRange`.
//! - ETSI EN 319 142-1: the `PAdES` baseline. `/SubFilter` is
//!   `ETSI.CAdES.detached`, which is what makes it `PAdES` rather than a
//!   legacy PKCS#7 signature.

use crate::sign::cades::DigestAlgorithm;

mod appearance;
mod spot;
mod xref_stream;

pub use appearance::{SignatureInk, VisibleSignature};
use std::collections::HashSet;

/// Signature dictionary `/SubFilter` for `PAdES` (EN 319 142-1 sec.5.1).
const SUBFILTER_PADES: &str = "/ETSI.CAdES.detached";

/// Default space reserved for the signature, in bytes.
///
/// A `CAdES` `SignedData` carrying an RSA-3072 signature and a `FINEID`
/// certificate chain lands near 6 KiB. The rest is headroom for
/// timestamp tokens, which a B-T upgrade adds without the file being
/// re-signed from scratch -- and there is room for several, because
/// several is what a signature that wants to outlive one authority's
/// standing asks for.
///
/// 16 KiB was the figure while a signature carried one token. Measured
/// 2026-08-03, a signature over four qualified timestamps with
/// long-term validation material needed 23 500 bytes, so 16 KiB failed
/// at the last step of signing -- after the card operation, after every
/// round trip. A fifth token puts it near 29 KiB. 48 KiB leaves room
/// for a sixth and for an authority whose chain is larger than the ones
/// measured.
///
/// The cost is padding: the hole is written as hex, so this is 96 KiB
/// in the file whether or not it is used. A caller who knows it wants
/// no timestamps can pass less -- [`prepare`] takes the capacity, and
/// this is only the default. Sizing it from the number of authorities
/// requested would be better than either, and wants the count plumbed
/// down to here.
pub const DEFAULT_SIGNATURE_CAPACITY: usize = 49_152;

/// Width of each `/ByteRange` number, in decimal digits.
///
/// Fixed so the array can be patched without moving anything after it.
/// Ten digits addresses just under 10 GB, past any PDF that exists.
const BYTE_RANGE_DIGITS: usize = 10;

/// Why a PDF could not be prepared for signing.
///
/// `SignatureTooLarge` is wider than the other variants because it
/// carries both numbers a caller needs to act on -- what was needed and
/// what was reserved. Boxing two `usize` to even the variants out would
/// trade a pointer chase for nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdfError {
    /// No `%PDF-` header: not a PDF at all.
    NotAPdf,
    /// No `startxref`, or it does not parse.
    MissingStartXref,
    /// The cross-reference chain could not be read.
    MissingTrailer,
    /// The trailer has no `/Root`.
    MissingCatalogReference,
    /// The object the trailer points at is not in the file.
    MissingObject(u32),
    /// A cross-reference or object stream uses a filter or predictor
    /// this reader does not decode.
    UnsupportedCrossReferenceStream,
    /// The document is encrypted; this writer cannot extend it.
    UnsupportedEncryption,
    /// The catalog has no `/Pages`, or the page tree has no leaf.
    MissingPageTree,
    /// Existing `AcroForm` fields cannot be read safely enough to choose
    /// a distinct signature-field name.
    UnreadableForm,
    /// An existing document security store cannot be retained safely.
    UnreadableValidationStore,
    /// The signature did not fit the reserved space.
    ///
    /// Both numbers are `u32` rather than `usize`: a reserved signature
    /// past four gigabytes is not a case worth widening the error for,
    /// and the narrower pair keeps this variant close in size to the
    /// rest.
    SignatureTooLarge {
        /// Bytes the signature needed.
        needed: u32,
        /// Bytes reserved.
        capacity: u32,
    },
}

impl core::fmt::Display for PdfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::NotAPdf => f.write_str("not a PDF: no %PDF- header"),
            Self::MissingStartXref => f.write_str("no usable startxref"),
            Self::MissingTrailer => f.write_str("the cross-reference chain could not be read"),
            Self::MissingCatalogReference => f.write_str("the trailer has no /Root"),
            Self::MissingObject(number) => write!(f, "object {number} is not in the file"),
            Self::UnsupportedCrossReferenceStream => {
                f.write_str("the cross-reference stream uses an unsupported encoding")
            }
            Self::UnsupportedEncryption => {
                f.write_str("the document is encrypted, which this writer cannot extend")
            }
            Self::MissingPageTree => f.write_str("the catalog has no reachable first page"),
            Self::UnreadableForm => f.write_str("the existing PDF form is not safely readable"),
            Self::UnreadableValidationStore => {
                f.write_str("the existing PDF validation store is not safely readable")
            }
            Self::SignatureTooLarge { needed, capacity } => write!(
                f,
                "the signature needs {needed} bytes but {capacity} were reserved"
            ),
        }
    }
}

impl core::error::Error for PdfError {}

/// What to record about the signature in the document.
#[derive(Debug, Clone, Default)]
pub struct SignatureMetadata {
    /// `/Reason`, why the document was signed.
    pub reason: Option<String>,
    /// `/Location`, where it was signed.
    pub location: Option<String>,
    /// `/ContactInfo`, how to reach the signer.
    pub contact: Option<String>,
    /// `/Name`, the signer as displayed. Readers prefer the
    /// certificate's subject when this is absent, which is usually
    /// better than a self-asserted string.
    pub name: Option<String>,
    /// `/M`, the claimed signing time as a PDF date string.
    pub signing_time: Option<String>,
    /// Visible widget appearance authenticated by this signature.
    ///
    /// `None` retains the standard invisible signature field.
    pub visible_signature: Option<VisibleSignature>,
}

/// A PDF with the signature update written and the hole still empty.
#[derive(Debug, Clone)]
pub struct Placeholder {
    /// Whole document, placeholders patched, signature hole zeroed.
    document: Vec<u8>,
    /// `[start1, len1, start2, len2]`, as written into `/ByteRange`.
    byte_range: [usize; 4],
    /// Offset of the `<` that opens `/Contents`.
    contents_open: usize,
    /// Signature capacity in bytes (half the hex characters).
    capacity: usize,
}

impl Placeholder {
    /// The octets the signature is computed over.
    ///
    /// The two `/ByteRange` spans concatenated, in order -- everything
    /// except the signature's own hex string. This is what gets hashed
    /// and becomes the `CAdES` `message-digest`.
    #[must_use]
    pub fn signed_octets(&self) -> Vec<u8> {
        let [start1, len1, start2, len2] = self.byte_range;
        let mut out = Vec::with_capacity(len1 + len2);
        out.extend_from_slice(&self.document[start1..start1 + len1]);
        out.extend_from_slice(&self.document[start2..start2 + len2]);
        out
    }

    /// Digest of [`Self::signed_octets`] under `algorithm`.
    #[must_use]
    pub fn digest(&self, algorithm: DigestAlgorithm) -> Vec<u8> {
        algorithm.digest(&self.signed_octets())
    }

    /// Splice the CMS into the reserved hole.
    ///
    /// Nothing moves: the DER is hex-encoded into the placeholder and
    /// the remaining space stays as zero padding, which is what the
    /// reserved length is for. Every offset written earlier stays true.
    ///
    /// # Errors
    /// [`PdfError::SignatureTooLarge`] if the CMS exceeds the capacity
    /// reserved by [`prepare`]. Raise the capacity and prepare again --
    /// the signature cannot be trimmed to fit.
    pub fn finish(mut self, cms_der: &[u8]) -> Result<Vec<u8>, PdfError> {
        if cms_der.len() > self.capacity {
            return Err(PdfError::SignatureTooLarge {
                needed: u32::try_from(cms_der.len()).unwrap_or(u32::MAX),
                capacity: u32::try_from(self.capacity).unwrap_or(u32::MAX),
            });
        }
        // The hex field starts one byte past the opening '<'.
        let mut cursor = self.contents_open.saturating_add(1);
        for byte in cms_der {
            let (high, low) = hex_pair(*byte);
            self.document[cursor] = high;
            self.document[cursor.saturating_add(1)] = low;
            cursor = cursor.saturating_add(2);
        }
        Ok(self.document)
    }
}

/// Uppercase hex digits of one byte.
fn hex_pair(byte: u8) -> (u8, u8) {
    /// Digits used for the hex string.
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    /// Bits in a hex digit.
    const NIBBLE: usize = 4;
    /// Mask for the low nibble.
    const LOW_MASK: usize = 0x0F;
    let value = usize::from(byte);
    (DIGITS[value >> NIBBLE], DIGITS[value & LOW_MASK])
}

/// Append a signature placeholder to `pdf`.
///
/// Produces the complete document with the incremental update in place
/// and the signature hole reserved but empty. Hash
/// [`Placeholder::signed_octets`], sign that on the card, build the
/// `CAdES`, and hand it to [`Placeholder::finish`].
///
/// # Errors
/// See [`PdfError`]. A malformed or unsupported PDF is refused rather
/// than half-signed.
pub fn prepare(
    pdf: &[u8],
    metadata: &SignatureMetadata,
    capacity: usize,
) -> Result<Placeholder, PdfError> {
    prepare_kind(pdf, metadata, capacity, Reserved::Signature)
}

/// Reserve space for a document timestamp rather than a signature.
///
/// A `PAdES` archive timestamp is its own revision: the same
/// placeholder machinery, but `EN 319 142-1 sec.5.4.3` requires
/// `/Type /DocTimeStamp`, asks for `/SubFilter /ETSI.RFC3161`, and puts
/// a bare RFC 3161 token in `/Contents` where a signature would put a
/// `CMS SignedData`. The byte range covers the whole document including
/// this dictionary, so the token attests everything before it -- the
/// earlier signature and the validation store included.
///
/// No metadata is written. The same clause says `Name`, `M`,
/// `Location`, `Reason` and `ContactInfo` should be absent, because the
/// token already carries that information and a reader should trust the
/// token over a dictionary entry nobody signed.
///
/// # Errors
/// See [`PdfError`].
pub fn prepare_document_timestamp(pdf: &[u8], capacity: usize) -> Result<Placeholder, PdfError> {
    prepare_kind(
        pdf,
        &SignatureMetadata::default(),
        capacity,
        Reserved::DocumentTimestamp,
    )
}

/// Which kind of dictionary the reserved hole belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reserved {
    /// `/Type /Sig`, holding a `CAdES` detached signature.
    Signature,
    /// `/Type /DocTimeStamp`, holding an RFC 3161 token.
    DocumentTimestamp,
}

impl Reserved {
    /// The `/Type` and `/SubFilter` this kind carries.
    const fn dictionary_head(self) -> (&'static str, &'static str) {
        match self {
            Self::Signature => ("/Sig", SUBFILTER_PADES),
            Self::DocumentTimestamp => ("/DocTimeStamp", "/ETSI.RFC3161"),
        }
    }

    /// First field-name candidate, derived from the new object number.
    fn field_name_base(self, signature_number: u32) -> String {
        match self {
            Self::Signature => format!("Signature{signature_number}"),
            Self::DocumentTimestamp => format!("Timestamp{signature_number}"),
        }
    }
}

/// Shared body of [`prepare`] and [`prepare_document_timestamp`].
fn prepare_kind(
    pdf: &[u8],
    metadata: &SignatureMetadata,
    capacity: usize,
    kind: Reserved,
) -> Result<Placeholder, PdfError> {
    if !pdf.starts_with(b"%PDF-") {
        return Err(PdfError::NotAPdf);
    }
    let index = PdfIndex::parse(pdf)?;
    let trailer = index.trailer();
    // An encrypted document needs every string and stream written
    // under its own crypt filter. This writer emits neither, so the
    // update it produces would be unreadable -- refuse rather than
    // hand back something that opens and then fails.
    if find_first(trailer, b"/Encrypt").is_some() {
        return Err(PdfError::UnsupportedEncryption);
    }
    let catalog_number =
        dictionary_reference(trailer, b"/Root").ok_or(PdfError::MissingCatalogReference)?;
    let next_object = dictionary_integer(trailer, b"/Size").unwrap_or(0).max(1);

    // Object numbers for what the update adds.
    let signature_number = next_object;
    let field_number = next_object.saturating_add(1);
    let rendered_appearance = rendered_signature_appearance(kind, metadata);
    let new_size = field_number.saturating_add(if rendered_appearance.is_some() { 3 } else { 1 });
    let catalog = index
        .object_body(catalog_number)
        .ok_or(PdfError::MissingObject(catalog_number))?;
    let field_name = unique_field_name(&index, &catalog, kind, signature_number)?;
    let (page_number, page) = signature_page(&index, &catalog, rendered_appearance.is_some())?;

    let mut update = Vec::new();
    let mut offsets: Vec<(u32, usize)> = Vec::new();
    let base = pdf.len();

    // The original file must end with a newline before the update, or
    // the first appended token joins the last existing one.
    let mut out = pdf.to_vec();
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    let update_start = out.len();

    // --- the signature dictionary, with placeholders ------------------
    offsets.push((signature_number, update_start));
    push_dictionary_head(&mut update, signature_number, kind, metadata);
    update.extend_from_slice(b"/ByteRange [");
    let byte_range_at = update_start.saturating_add(update.len());
    // Four fixed-width fields, patched once the offsets are known.
    for _ in 0..4 {
        update.push(b' ');
        update.extend_from_slice(&b"0".repeat(BYTE_RANGE_DIGITS));
    }
    update.extend_from_slice(b" ]\n/Contents ");
    let contents_open = update_start.saturating_add(update.len());
    update.push(b'<');
    update.extend_from_slice(&b"0".repeat(capacity.saturating_mul(2)));
    update.push(b'>');
    update.extend_from_slice(b"\n>>\nendobj\n");

    // --- the signature field and optional visible appearance ----------
    for (number, object) in signature_field_objects(
        &index,
        page_number,
        &page,
        field_number,
        signature_number,
        &field_name,
        rendered_appearance.as_ref(),
    ) {
        offsets.push((number, update_start.saturating_add(update.len())));
        update.extend_from_slice(&object);
    }

    // --- the page the widget lives on ---------------------------------
    //
    // A signature field is a widget annotation, and PDF 32000-1
    // sec.12.7.3.1 requires a widget to appear in the `/Annots` of the
    // page it is on. Listing it only in `/AcroForm/Fields` leaves it
    // orphaned: readers that walk from the field to its page find
    // nothing there. Poppler tolerates that and reports a valid
    // signature; the EU DSS validator throws on it, so the signature
    // is unverifiable exactly where it matters.
    match plan_annotation(&page, field_number) {
        AnnotsTarget::Page(body) => {
            offsets.push((page_number, update_start.saturating_add(update.len())));
            update.extend_from_slice(format!("{page_number} 0 obj\n").as_bytes());
            update.extend_from_slice(&body);
            update.extend_from_slice(b"\nendobj\n");
        }
        AnnotsTarget::Array(array_number) => {
            let array = index
                .object_body(array_number)
                .ok_or(PdfError::MissingObject(array_number))?;
            let entry = format!("{field_number} 0 R");
            let body = append_to_array(&array, 0, &entry);
            offsets.push((array_number, update_start.saturating_add(update.len())));
            update.extend_from_slice(format!("{array_number} 0 obj\n").as_bytes());
            update.extend_from_slice(&body);
            update.extend_from_slice(b"\nendobj\n");
        }
    }

    // --- the catalog, reissued with an AcroForm -----------------------
    let (edited_number, edited_body) = match plan_field_list(&index, &catalog, field_number) {
        FieldListTarget::Catalog(body) => (catalog_number, body),
        FieldListTarget::Object(number, body) => (number, body),
    };
    offsets.push((edited_number, update_start.saturating_add(update.len())));
    update.extend_from_slice(format!("{edited_number} 0 obj\n").as_bytes());
    update.extend_from_slice(&edited_body);
    update.extend_from_slice(b"\nendobj\n");

    // --- cross-reference section and trailer --------------------------
    push_xref_and_trailer(
        &mut update,
        update_start,
        &mut offsets,
        new_size,
        catalog_number,
        &index,
    )?;

    out.extend_from_slice(&update);
    let _ = base;
    Ok(finish_placeholder(
        out,
        byte_range_at,
        contents_open,
        capacity,
    ))
}

fn rendered_signature_appearance(
    kind: Reserved,
    metadata: &SignatureMetadata,
) -> Option<appearance::RenderedAppearance> {
    metadata
        .visible_signature
        .as_ref()
        .filter(|_visible| kind == Reserved::Signature)
        .map(VisibleSignature::render)
}

/// The page carrying the signature widget.
///
/// A visible mark goes where a paper signature does: the end of the
/// document, so it stands under everything it signs. An invisible
/// widget has no such place, and stays on the first page a reader
/// opens.
fn signature_page(
    index: &PdfIndex<'_>,
    catalog: &[u8],
    visible: bool,
) -> Result<(u32, Vec<u8>), PdfError> {
    let number = if visible {
        last_page_number(index, catalog)?
    } else {
        first_page_number(index, catalog)?
    };
    let page = index
        .object_body(number)
        .ok_or(PdfError::MissingObject(number))?;
    Ok((number, page))
}

fn signature_field_objects(
    index: &PdfIndex<'_>,
    page_number: u32,
    page: &[u8],
    field_number: u32,
    signature_number: u32,
    field_name: &str,
    appearance: Option<&appearance::RenderedAppearance>,
) -> Vec<(u32, Vec<u8>)> {
    let Some(appearance) = appearance else {
        let field = format!(
            "{field_number} 0 obj\n<< /Type /Annot /Subtype /Widget /FT /Sig /T ({field_name}) \
             /V {signature_number} 0 R /P {page_number} 0 R /Rect [0 0 0 0] /F 132 >>\nendobj\n"
        );
        return vec![(field_number, field.into_bytes())];
    };

    let appearance_number = field_number.saturating_add(1);
    let font_number = field_number.saturating_add(2);
    let rectangle = visible_signature_rectangle(index, page_number, page, appearance.side);
    let field = format!(
        "{field_number} 0 obj\n<< /Type /Annot /Subtype /Widget /FT /Sig \
         /T ({field_name}) /V {signature_number} 0 R /P {page_number} 0 R \
         /Rect [{:.4} {:.4} {:.4} {:.4}] /F 132 \
         /AP << /N {appearance_number} 0 R >> >>\nendobj\n",
        rectangle[0], rectangle[1], rectangle[2], rectangle[3]
    );
    let mut form = format!(
        "{appearance_number} 0 obj\n<< /Type /XObject /Subtype /Form \
         /BBox [0 0 {:.4} {:.4}] \
         /Resources << /Font << /F1 {font_number} 0 R >> >> \
         /Length {} >>\nstream\n",
        appearance.side,
        appearance.side,
        appearance.operators.len()
    )
    .into_bytes();
    form.extend_from_slice(&appearance.operators);
    form.extend_from_slice(b"endstream\nendobj\n");
    let font = format!(
        "{font_number} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica \
         /Encoding /WinAnsiEncoding >>\nendobj\n"
    );
    vec![
        (field_number, field.into_bytes()),
        (appearance_number, form),
        (font_number, font.into_bytes()),
    ]
}

/// Maximum nesting accepted while retaining existing PDF values.
///
/// The document security store can carry extension dictionaries and a
/// `/VRI` tree that this writer must preserve without interpreting. A
/// fixed bound keeps that preservation from becoming an unbounded parser
/// recursion on an attacker-supplied PDF.
const MAX_PDF_VALUE_DEPTH: usize = 64;

/// One indirect PDF object reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PdfObjectReference {
    number: u32,
    generation: u16,
}

impl PdfObjectReference {
    fn rendered(self) -> String {
        format!("{} {} R", self.number, self.generation)
    }
}

/// One top-level dictionary entry, retaining the exact value byte span.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PdfDictionaryEntry {
    /// Decoded name bytes, without the leading slash.
    name: Vec<u8>,
    /// Exact value bytes in the dictionary source.
    value: core::ops::Range<usize>,
}

/// A parsed top-level dictionary.
struct PdfDictionary {
    entries: Vec<PdfDictionaryEntry>,
    /// Offset of the outer dictionary's closing `>>`.
    closing: usize,
}

impl PdfDictionary {
    /// Parse one complete dictionary, with only trivia around it.
    fn parse(bytes: &[u8]) -> Result<Self, PdfError> {
        let mut parser = PdfValueParser::new(bytes);
        parser.skip_trivia();
        let dictionary = parser.dictionary(1)?;
        parser.require_end()?;
        Ok(dictionary)
    }

    /// The sole entry whose decoded name equals `name`.
    ///
    /// Duplicate spellings such as `/DSS` and `/D#53S` are ambiguous;
    /// refuse them instead of silently choosing which earlier store to
    /// discard.
    fn entry(&self, name: &[u8]) -> Result<Option<&PdfDictionaryEntry>, PdfError> {
        let mut matching = self.entries.iter().filter(|entry| entry.name == name);
        let found = matching.next();
        if matching.next().is_some() {
            return Err(PdfError::UnreadableValidationStore);
        }
        Ok(found)
    }
}

/// Byte-oriented parser for the PDF value grammar needed to retain a DSS.
struct PdfValueParser<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PdfValueParser<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn dictionary(&mut self, depth: usize) -> Result<PdfDictionary, PdfError> {
        Self::check_depth(depth)?;
        if !self.consume(b"<<") {
            return Err(PdfError::UnreadableValidationStore);
        }
        let mut entries = Vec::new();
        loop {
            self.skip_trivia();
            let closing = self.offset;
            if self.consume(b">>") {
                return Ok(PdfDictionary { entries, closing });
            }
            let name = self.name()?;
            self.skip_trivia();
            let value = self.value(depth)?;
            entries.push(PdfDictionaryEntry { name, value });
        }
    }

    fn value(&mut self, depth: usize) -> Result<core::ops::Range<usize>, PdfError> {
        self.skip_trivia();
        let start = self.offset;
        if self.starts_with(b"<<") {
            let _dictionary = self.dictionary(depth.saturating_add(1))?;
        } else if self.consume(b"[") {
            self.array_remainder(depth.saturating_add(1))?;
        } else if self.consume(b"(") {
            self.literal_string_remainder()?;
        } else if self.consume(b"<") {
            self.hex_string_remainder()?;
        } else if self.starts_with(b"/") {
            let _name = self.name()?;
        } else {
            let first = self.atom()?;
            self.consume_reference_tail(first);
        }
        Ok(start..self.offset)
    }

    fn array_remainder(&mut self, depth: usize) -> Result<(), PdfError> {
        Self::check_depth(depth)?;
        loop {
            self.skip_trivia();
            if self.consume(b"]") {
                return Ok(());
            }
            let _value = self.value(depth)?;
        }
    }

    fn literal_string_remainder(&mut self) -> Result<(), PdfError> {
        let mut depth = 1_usize;
        while let Some(byte) = self.bytes.get(self.offset).copied() {
            self.offset = self.offset.saturating_add(1);
            match byte {
                b'\\' => {
                    let Some(escaped) = self.bytes.get(self.offset).copied() else {
                        return Err(PdfError::UnreadableValidationStore);
                    };
                    self.offset = self.offset.saturating_add(1);
                    if escaped == b'\r' && self.bytes.get(self.offset) == Some(&b'\n') {
                        self.offset = self.offset.saturating_add(1);
                    }
                }
                b'(' => {
                    depth = depth.saturating_add(1);
                    Self::check_depth(depth)?;
                }
                b')' => {
                    depth = depth
                        .checked_sub(1)
                        .ok_or(PdfError::UnreadableValidationStore)?;
                    if depth == 0 {
                        return Ok(());
                    }
                }
                _ => {}
            }
        }
        Err(PdfError::UnreadableValidationStore)
    }

    fn hex_string_remainder(&mut self) -> Result<(), PdfError> {
        while let Some(byte) = self.bytes.get(self.offset).copied() {
            self.offset = self.offset.saturating_add(1);
            if byte == b'>' {
                return Ok(());
            }
        }
        Err(PdfError::UnreadableValidationStore)
    }

    /// A name decoded according to PDF's `#xx` byte escapes.
    fn name(&mut self) -> Result<Vec<u8>, PdfError> {
        if !self.consume(b"/") {
            return Err(PdfError::UnreadableValidationStore);
        }
        let mut decoded = Vec::new();
        while let Some(byte) = self.bytes.get(self.offset).copied() {
            if Self::is_whitespace(byte) || Self::is_delimiter(byte) {
                break;
            }
            if byte == b'#' {
                let high = self
                    .bytes
                    .get(self.offset.saturating_add(1))
                    .and_then(|byte| Self::hex_digit(*byte));
                let low = self
                    .bytes
                    .get(self.offset.saturating_add(2))
                    .and_then(|byte| Self::hex_digit(*byte));
                let (Some(high), Some(low)) = (high, low) else {
                    return Err(PdfError::UnreadableValidationStore);
                };
                decoded.push(high.saturating_mul(16).saturating_add(low));
                self.offset = self.offset.saturating_add(3);
            } else {
                decoded.push(byte);
                self.offset = self.offset.saturating_add(1);
            }
        }
        Ok(decoded)
    }

    /// One non-delimiter token.
    fn atom(&mut self) -> Result<core::ops::Range<usize>, PdfError> {
        let start = self.offset;
        while self
            .bytes
            .get(self.offset)
            .is_some_and(|byte| !Self::is_whitespace(*byte) && !Self::is_delimiter(*byte))
        {
            self.offset = self.offset.saturating_add(1);
        }
        if start == self.offset {
            return Err(PdfError::UnreadableValidationStore);
        }
        Ok(start..self.offset)
    }

    /// Extend an atom value across `N N R` when that complete shape follows.
    fn consume_reference_tail(&mut self, first: core::ops::Range<usize>) {
        if parse_u32(&self.bytes[first]).is_none() {
            return;
        }
        let after_first = self.offset;
        let Some(_generation) = self.unsigned_u16() else {
            self.offset = after_first;
            return;
        };
        self.skip_trivia();
        if !self.consume_keyword(b"R") {
            self.offset = after_first;
        }
    }

    /// A complete indirect reference at the current position.
    fn reference(&mut self) -> Option<PdfObjectReference> {
        let start = self.offset;
        let number = self.unsigned_u32()?;
        let Some(generation) = self.unsigned_u16() else {
            self.offset = start;
            return None;
        };
        self.skip_trivia();
        if !self.consume_keyword(b"R") {
            self.offset = start;
            return None;
        }
        Some(PdfObjectReference { number, generation })
    }

    fn unsigned_u32(&mut self) -> Option<u32> {
        self.unsigned_digits().and_then(parse_u32)
    }

    fn unsigned_u16(&mut self) -> Option<u16> {
        self.unsigned_digits().and_then(parse_u16)
    }

    fn unsigned_digits(&mut self) -> Option<&'a [u8]> {
        self.skip_trivia();
        let start = self.offset;
        while self.bytes.get(self.offset).is_some_and(u8::is_ascii_digit) {
            self.offset = self.offset.saturating_add(1);
        }
        if start == self.offset
            || self
                .bytes
                .get(self.offset)
                .is_some_and(|byte| !Self::is_whitespace(*byte) && !Self::is_delimiter(*byte))
        {
            self.offset = start;
            return None;
        }
        self.bytes.get(start..self.offset)
    }

    fn consume_keyword(&mut self, keyword: &[u8]) -> bool {
        if !self.starts_with(keyword) {
            return false;
        }
        let after = self.offset.saturating_add(keyword.len());
        if self
            .bytes
            .get(after)
            .is_some_and(|byte| !Self::is_whitespace(*byte) && !Self::is_delimiter(*byte))
        {
            return false;
        }
        self.offset = after;
        true
    }

    fn require_end(&mut self) -> Result<(), PdfError> {
        self.skip_trivia();
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(PdfError::UnreadableValidationStore)
        }
    }

    fn skip_trivia(&mut self) {
        loop {
            while self
                .bytes
                .get(self.offset)
                .is_some_and(|byte| Self::is_whitespace(*byte))
            {
                self.offset = self.offset.saturating_add(1);
            }
            if self.bytes.get(self.offset) != Some(&b'%') {
                return;
            }
            while self
                .bytes
                .get(self.offset)
                .is_some_and(|byte| *byte != b'\r' && *byte != b'\n')
            {
                self.offset = self.offset.saturating_add(1);
            }
        }
    }

    fn consume(&mut self, token: &[u8]) -> bool {
        if !self.starts_with(token) {
            return false;
        }
        self.offset = self.offset.saturating_add(token.len());
        true
    }

    fn starts_with(&self, token: &[u8]) -> bool {
        self.bytes
            .get(self.offset..)
            .is_some_and(|rest| rest.starts_with(token))
    }

    const fn is_whitespace(byte: u8) -> bool {
        byte == 0 || byte == b'\t' || byte == b'\n' || byte == 12 || byte == b'\r' || byte == b' '
    }

    const fn is_delimiter(byte: u8) -> bool {
        matches!(byte, b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'/' | b'%')
    }

    const fn hex_digit(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    const fn check_depth(depth: usize) -> Result<(), PdfError> {
        if depth <= MAX_PDF_VALUE_DEPTH {
            Ok(())
        } else {
            Err(PdfError::UnreadableValidationStore)
        }
    }
}

/// Parse a value as exactly one indirect reference.
fn complete_object_reference(value: &[u8]) -> Result<Option<PdfObjectReference>, PdfError> {
    let mut parser = PdfValueParser::new(value);
    parser.skip_trivia();
    let reference = parser.reference();
    if reference.is_some() {
        parser.require_end()?;
    }
    Ok(reference)
}

/// Parse a DSS category as an array containing only indirect references.
fn complete_reference_array(value: &[u8]) -> Result<Vec<PdfObjectReference>, PdfError> {
    let mut parser = PdfValueParser::new(value);
    parser.skip_trivia();
    if !parser.consume(b"[") {
        return Err(PdfError::UnreadableValidationStore);
    }
    PdfValueParser::check_depth(1)?;
    let mut references = Vec::new();
    loop {
        parser.skip_trivia();
        if parser.consume(b"]") {
            parser.require_end()?;
            return Ok(references);
        }
        let Some(reference) = parser.reference() else {
            return Err(PdfError::UnreadableValidationStore);
        };
        references.push(reference);
    }
}

/// Keep the first occurrence of each reference.
fn ordered_unique_references(
    references: impl IntoIterator<Item = PdfObjectReference>,
) -> Vec<PdfObjectReference> {
    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    for reference in references {
        if seen.insert(reference) {
            unique.push(reference);
        }
    }
    unique
}

/// A direct reference array, in stable first-seen order.
fn reference_array_text(references: &[PdfObjectReference]) -> String {
    let body = references
        .iter()
        .map(|reference| reference.rendered())
        .collect::<Vec<_>>()
        .join(" ");
    format!("[{body}]")
}

/// Resolve a direct or indirect DSS reference array.
fn validation_references(
    index: &PdfIndex<'_>,
    value: &[u8],
) -> Result<Vec<PdfObjectReference>, PdfError> {
    let mut parser = PdfValueParser::new(value);
    parser.skip_trivia();
    if parser.starts_with(b"[") {
        return complete_reference_array(value);
    }
    let reference = complete_object_reference(value)?.ok_or(PdfError::UnreadableValidationStore)?;
    let array = index
        .object_body_reference(reference)
        .ok_or(PdfError::MissingObject(reference.number))?;
    complete_reference_array(&array)
}

/// Replace one byte span without transcoding any retained PDF bytes.
fn replace_bytes(bytes: &[u8], span: core::ops::Range<usize>, replacement: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        bytes
            .len()
            .saturating_sub(span.len())
            .saturating_add(replacement.len()),
    );
    out.extend_from_slice(&bytes[..span.start]);
    out.extend_from_slice(replacement);
    out.extend_from_slice(&bytes[span.end..]);
    out
}

/// Insert one entry before the outer dictionary's closing delimiter.
fn insert_dictionary_entry(bytes: &[u8], closing: usize, entry: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len().saturating_add(entry.len()).saturating_add(2));
    out.extend_from_slice(&bytes[..closing]);
    out.extend_from_slice(b"\n");
    out.extend_from_slice(entry);
    out.extend_from_slice(b"\n");
    out.extend_from_slice(&bytes[closing..]);
    out
}

/// Add the new blobs to an existing `/DSS` dictionary.
///
/// A document signed a second time already has a store, and its arrays
/// have to be extended rather than replaced: the earlier signature's
/// evidence is still needed to validate the earlier signature.
fn merge_validation_store(
    index: &PdfIndex<'_>,
    store: Vec<u8>,
    certificates: &[u32],
    ocsp_responses: &[u32],
    crls: &[u32],
) -> Result<Vec<u8>, PdfError> {
    let mut merged = store;
    for (name, spelling, numbers) in [
        (b"Certs".as_slice(), "/Certs", certificates),
        (b"OCSPs".as_slice(), "/OCSPs", ocsp_responses),
        (b"CRLs".as_slice(), "/CRLs", crls),
    ] {
        let dictionary = PdfDictionary::parse(&merged)?;
        let existing = dictionary.entry(name)?;
        if existing.is_none() && numbers.is_empty() {
            continue;
        }
        let mut references = if let Some(entry) = existing {
            validation_references(index, &merged[entry.value.clone()])?
        } else {
            Vec::new()
        };
        references.extend(numbers.iter().map(|number| PdfObjectReference {
            number: *number,
            generation: 0,
        }));
        let references = ordered_unique_references(references);
        let replacement = reference_array_text(&references);
        merged = if let Some(entry) = existing {
            replace_bytes(&merged, entry.value.clone(), replacement.as_bytes())
        } else {
            let entry = format!("{spelling} {replacement}");
            insert_dictionary_entry(&merged, dictionary.closing, entry.as_bytes())
        };
    }
    Ok(merged)
}

/// Keep the first copy of each new evidence blob.
fn ordered_unique_blobs(blobs: &[Vec<u8>]) -> Vec<&[u8]> {
    let mut unique: Vec<&[u8]> = Vec::new();
    for blob in blobs {
        if !unique.contains(&blob.as_slice()) {
            unique.push(blob);
        }
    }
    unique
}

/// A fresh `/DSS` dictionary body referencing the emitted blob objects.
fn validation_store_body(certificates: &[u32], ocsp_responses: &[u32], crls: &[u32]) -> Vec<u8> {
    let mut store = Vec::from("<< /Type /DSS");
    for (key, numbers) in [
        ("/Certs", certificates),
        ("/OCSPs", ocsp_responses),
        ("/CRLs", crls),
    ] {
        if numbers.is_empty() {
            continue;
        }
        store.extend_from_slice(format!(" {key} [").as_bytes());
        for number in numbers {
            store.extend_from_slice(format!("{number} 0 R ").as_bytes());
        }
        store.extend_from_slice(b"]");
    }
    store.extend_from_slice(b" >>");
    store
}

/// Patch `/ByteRange` now that every offset is final, and hand back the
/// placeholder.
///
/// The two spans can only be written once the whole update is in place,
/// because the second runs to the end of the file.
fn finish_placeholder(
    mut out: Vec<u8>,
    byte_range_at: usize,
    contents_open: usize,
    capacity: usize,
) -> Placeholder {
    let contents_close = contents_open
        .saturating_add(1)
        .saturating_add(capacity.saturating_mul(2));
    let start2 = contents_close.saturating_add(1);
    let byte_range = [
        0_usize,
        contents_open,
        start2,
        out.len().saturating_sub(start2),
    ];
    write_byte_range(&mut out, byte_range_at, byte_range);
    debug_assert_eq!(out[contents_open], b'<');
    debug_assert_eq!(out[contents_close], b'>');
    Placeholder {
        document: out,
        byte_range,
        contents_open,
        capacity,
    }
}

/// Close an incremental update: its cross-reference section, then the
/// trailer that points at it.
///
/// Shared by the two writers so the `/Prev` chain and the carried
/// `/ID` are built the same way in both. `offsets` is sorted here
/// rather than by the caller, because a cross-reference section that
/// is not in object order is one a reader may not follow. A document
/// whose newest section is a stream is closed with a stream, in which
/// case the stream object itself takes the number `size` and the
/// written `/Size` moves past it.
fn push_xref_and_trailer(
    update: &mut Vec<u8>,
    update_start: usize,
    offsets: &mut [(u32, usize)],
    size: u32,
    catalog_number: u32,
    index: &PdfIndex<'_>,
) -> Result<(), PdfError> {
    let previous_xref = index.start_xref();
    let xref_at = update_start.saturating_add(update.len());
    offsets.sort_unstable_by_key(|(number, _)| *number);
    let carried = trailer_carry_forward(index.trailer());
    if index.newest_is_stream() {
        return xref_stream::push_stream_close(
            update,
            xref_at,
            offsets,
            size,
            catalog_number,
            previous_xref,
            &carried,
        );
    }
    update.extend_from_slice(&cross_reference_section(offsets));
    update.extend_from_slice(
        format!(
            "trailer\n<< /Size {size} /Root {catalog_number} 0 R /Prev {previous_xref}{carried}\
             >>\nstartxref\n{xref_at}\n%%EOF\n"
        )
        .as_bytes(),
    );
    Ok(())
}

/// What the source trailer must hand to the update's trailer.
///
/// An incremental update writes a fresh trailer, and anything the old
/// one carried that is not repeated is lost. `/ID` identifies the file
/// and some validators treat its absence on a signed document as a
/// defect; `/Info` points at the title, author and dates. Neither is
/// required for the file to parse, which is exactly why losing them is
/// quiet.
///
/// An incremental update carries the file identifier forward. Dropping
/// it changes what a reader believes the file is, and some validators
/// treat a missing `/ID` on a signed document as a defect.
fn trailer_carry_forward(trailer: &[u8]) -> String {
    let mut carried = String::new();

    // `/ID` is an array written inline.
    if let Some(at) = find_first(trailer, b"/ID") {
        let rest = &trailer[at.saturating_add(b"/ID".len())..];
        if let Some(open) = find_first(rest, b"[")
            && let Some(close) = find_first(&rest[open..], b"]")
        {
            let array = &rest[open..=open.saturating_add(close)];
            let _ignored = core::fmt::Write::write_fmt(
                &mut carried,
                format_args!(" /ID {}", String::from_utf8_lossy(array)),
            );
        }
    }

    // `/Info` is a reference to the document information dictionary,
    // which holds the title, author and dates. Dropping it does not
    // break the file, so nothing complains -- the signed document just
    // arrives with no title, and a reader shows the filename instead.
    if let Some(number) = indirect_value(trailer, b"/Info") {
        let _ignored =
            core::fmt::Write::write_fmt(&mut carried, format_args!(" /Info {number} 0 R"));
    }
    carried
}

/// Where the tokenizer is while walking an object body.
enum Scan {
    Regular,
    Comment,
    HexString,
    LiteralString { depth: u32, escaped: bool },
}

/// Open the signature or timestamp dictionary and write its metadata.
fn push_dictionary_head(
    out: &mut Vec<u8>,
    number: u32,
    kind: Reserved,
    metadata: &SignatureMetadata,
) {
    let (type_name, subfilter) = kind.dictionary_head();
    out.extend_from_slice(
        format!(
            "{number} 0 obj\n<< /Type {type_name} /Filter /Adobe.PPKLite /SubFilter {subfilter}\n"
        )
        .as_bytes(),
    );
    push_optional_text(out, "/Reason", metadata.reason.as_deref());
    push_optional_text(out, "/Location", metadata.location.as_deref());
    push_optional_text(out, "/ContactInfo", metadata.contact.as_deref());
    push_optional_text(out, "/Name", metadata.name.as_deref());
    if let Some(time) = metadata.signing_time.as_deref() {
        out.extend_from_slice(format!("/M ({time})\n").as_bytes());
    }
}

/// Maximum number of field dictionaries inspected while choosing a
/// signature-field name.
const MAX_FORM_FIELD_OBJECTS: usize = 4_096;

/// Maximum `/Kids` depth in the `AcroForm` field tree.
const MAX_FORM_FIELD_DEPTH: usize = 64;

/// Maximum decoded byte length accepted for one partial field name.
const MAX_FIELD_NAME_BYTES: usize = 4_096;

/// UTF-16 big-endian byte-order mark used by PDF text strings.
const UTF16_BE_BOM: &[u8] = &[0xFE, 0xFF];

/// UTF-8 byte-order mark admitted by PDF 2.0 text strings.
const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

/// Choose a top-level field name that is absent from the existing form.
///
/// Object numbers are unique, but field names are user-controlled text.
/// A document can therefore already contain `Signature5` even when the
/// next object happens to be object 5. Keep the old compact spelling
/// when it is available and add the first free numeric suffix when it
/// is not.
fn unique_field_name(
    index: &PdfIndex<'_>,
    catalog: &[u8],
    kind: Reserved,
    signature_number: u32,
) -> Result<String, PdfError> {
    let used = existing_field_names(index, catalog)?;
    let base = kind.field_name_base(signature_number);
    if !used.contains(&base) {
        return Ok(base);
    }
    for suffix in 2..=used.len().saturating_add(2) {
        let candidate = format!("{base}-{suffix}");
        if !used.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err(PdfError::UnreadableForm)
}

/// Fully-qualified `AcroForm` field names that can collide with an ASCII
/// top-level name emitted by this writer.
fn existing_field_names(index: &PdfIndex<'_>, catalog: &[u8]) -> Result<HashSet<String>, PdfError> {
    let catalog_dictionary =
        PdfDictionary::parse(catalog).map_err(|_ignored| PdfError::UnreadableForm)?;
    let Some(acroform_entry) = catalog_dictionary
        .entry(b"AcroForm")
        .map_err(|_ignored| PdfError::UnreadableForm)?
    else {
        return Ok(HashSet::new());
    };
    let acroform_value = catalog
        .get(acroform_entry.value.clone())
        .ok_or(PdfError::UnreadableForm)?;
    let acroform = if let Some(reference) =
        complete_object_reference(acroform_value).map_err(|_ignored| PdfError::UnreadableForm)?
    {
        index
            .object_body_reference(reference)
            .ok_or(PdfError::UnreadableForm)?
    } else {
        acroform_value.to_vec()
    };
    let acroform_dictionary =
        PdfDictionary::parse(&acroform).map_err(|_ignored| PdfError::UnreadableForm)?;
    let Some(fields_entry) = acroform_dictionary
        .entry(b"Fields")
        .map_err(|_ignored| PdfError::UnreadableForm)?
    else {
        return Ok(HashSet::new());
    };
    let roots = validation_references(index, &acroform[fields_entry.value.clone()])
        .map_err(|_ignored| PdfError::UnreadableForm)?;
    if roots.len() > MAX_FORM_FIELD_OBJECTS {
        return Err(PdfError::UnreadableForm);
    }

    let mut pending: Vec<(PdfObjectReference, Option<String>, usize)> = roots
        .into_iter()
        .rev()
        .map(|reference| (reference, Some(String::new()), 1))
        .collect();
    let mut visited = HashSet::new();
    let mut names = HashSet::new();
    while let Some((reference, parent_name, depth)) = pending.pop() {
        if depth > MAX_FORM_FIELD_DEPTH
            || visited.len() >= MAX_FORM_FIELD_OBJECTS
            || !visited.insert(reference)
        {
            return Err(PdfError::UnreadableForm);
        }
        let field = index
            .object_body_reference(reference)
            .ok_or(PdfError::UnreadableForm)?;
        let dictionary =
            PdfDictionary::parse(&field).map_err(|_ignored| PdfError::UnreadableForm)?;

        let name_entry = dictionary
            .entry(b"T")
            .map_err(|_ignored| PdfError::UnreadableForm)?;
        let field_name = if let Some(entry) = name_entry {
            let component = ascii_field_name(&field[entry.value.clone()])?;
            let qualified = qualified_field_name(parent_name.as_deref(), component.as_deref())?;
            if let Some(name) = qualified.as_ref()
                && !name.is_empty()
            {
                names.insert(name.clone());
            }
            qualified
        } else {
            parent_name
        };

        if let Some(kids_entry) = dictionary
            .entry(b"Kids")
            .map_err(|_ignored| PdfError::UnreadableForm)?
        {
            let children = validation_references(index, &field[kids_entry.value.clone()])
                .map_err(|_ignored| PdfError::UnreadableForm)?;
            if pending.len().saturating_add(children.len()) > MAX_FORM_FIELD_OBJECTS {
                return Err(PdfError::UnreadableForm);
            }
            pending.extend(
                children
                    .into_iter()
                    .rev()
                    .map(|child| (child, field_name.clone(), depth.saturating_add(1))),
            );
        }
    }
    Ok(names)
}

/// Join one partial field name to its parent without allowing the fully
/// qualified name to exceed the same bound as an individual component.
fn qualified_field_name(
    parent: Option<&str>,
    component: Option<&str>,
) -> Result<Option<String>, PdfError> {
    let (Some(parent), Some(component)) = (parent, component) else {
        return Ok(None);
    };
    let separator = usize::from(!parent.is_empty());
    let length = parent
        .len()
        .checked_add(separator)
        .and_then(|length| length.checked_add(component.len()))
        .ok_or(PdfError::UnreadableForm)?;
    if length > MAX_FIELD_NAME_BYTES {
        return Err(PdfError::UnreadableForm);
    }

    let mut qualified = String::with_capacity(length);
    qualified.push_str(parent);
    if separator == 1 {
        qualified.push('.');
    }
    qualified.push_str(component);
    Ok(Some(qualified))
}

/// Decode one PDF text string when its value can equal an ASCII name.
///
/// `None` means a well-formed non-ASCII name, which cannot collide with
/// the ASCII names generated here. Malformed strings are refused.
fn ascii_field_name(value: &[u8]) -> Result<Option<String>, PdfError> {
    let decoded = if value.starts_with(b"(") && value.ends_with(b")") {
        decode_literal_string(&value[1..value.len().saturating_sub(1)])?
    } else if value.starts_with(b"<") && value.ends_with(b">") && !value.starts_with(b"<<") {
        decode_hex_string(&value[1..value.len().saturating_sub(1)])?
    } else {
        return Err(PdfError::UnreadableForm);
    };
    if decoded.len() > MAX_FIELD_NAME_BYTES {
        return Err(PdfError::UnreadableForm);
    }

    if let Some(encoded) = decoded.strip_prefix(UTF16_BE_BOM) {
        if !encoded.len().is_multiple_of(2) {
            return Err(PdfError::UnreadableForm);
        }
        let units: Vec<u16> = encoded
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect();
        let text = String::from_utf16(&units).map_err(|_ignored| PdfError::UnreadableForm)?;
        return Ok(text.is_ascii().then_some(text));
    }
    if let Some(encoded) = decoded.strip_prefix(UTF8_BOM) {
        let text = core::str::from_utf8(encoded)
            .map_err(|_ignored| PdfError::UnreadableForm)?
            .to_owned();
        return Ok(text.is_ascii().then_some(text));
    }
    if decoded.is_ascii() {
        return String::from_utf8(decoded)
            .map(Some)
            .map_err(|_ignored| PdfError::UnreadableForm);
    }
    Ok(None)
}

/// Decode the contents of a PDF literal string.
fn decode_literal_string(encoded: &[u8]) -> Result<Vec<u8>, PdfError> {
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut at = 0_usize;
    while let Some(byte) = encoded.get(at).copied() {
        at = at.saturating_add(1);
        if byte != b'\\' {
            decoded.push(byte);
            continue;
        }
        let escaped = encoded.get(at).copied().ok_or(PdfError::UnreadableForm)?;
        at = at.saturating_add(1);
        match escaped {
            b'n' => decoded.push(b'\n'),
            b'r' => decoded.push(b'\r'),
            b't' => decoded.push(b'\t'),
            b'b' => decoded.push(8),
            b'f' => decoded.push(12),
            b'\r' => {
                if encoded.get(at) == Some(&b'\n') {
                    at = at.saturating_add(1);
                }
            }
            b'\n' => {}
            b'0'..=b'7' => {
                let mut octal = u16::from(escaped.saturating_sub(b'0'));
                for _ in 1..3 {
                    let Some(next @ b'0'..=b'7') = encoded.get(at).copied() else {
                        break;
                    };
                    at = at.saturating_add(1);
                    octal = octal
                        .saturating_mul(8)
                        .saturating_add(u16::from(next.saturating_sub(b'0')));
                }
                decoded.push(u8::try_from(octal).map_err(|_ignored| PdfError::UnreadableForm)?);
            }
            other => decoded.push(other),
        }
        if decoded.len() > MAX_FIELD_NAME_BYTES {
            return Err(PdfError::UnreadableForm);
        }
    }
    Ok(decoded)
}

/// Decode the contents of a PDF hexadecimal string.
fn decode_hex_string(encoded: &[u8]) -> Result<Vec<u8>, PdfError> {
    let mut decoded = Vec::with_capacity(encoded.len().saturating_add(1) / 2);
    let mut high: Option<u8> = None;
    for byte in encoded.iter().copied() {
        if PdfValueParser::is_whitespace(byte) {
            continue;
        }
        let digit = PdfValueParser::hex_digit(byte).ok_or(PdfError::UnreadableForm)?;
        if let Some(first) = high.take() {
            decoded.push(first.saturating_mul(16).saturating_add(digit));
        } else {
            high = Some(digit);
        }
        if decoded.len() > MAX_FIELD_NAME_BYTES {
            return Err(PdfError::UnreadableForm);
        }
    }
    if let Some(first) = high {
        decoded.push(first.saturating_mul(16));
    }
    Ok(decoded)
}

/// Where the new signature field has to be recorded.
///
/// The field list can be in three places, and a document that already
/// has form fields -- which is most documents worth signing -- puts it
/// in the last one.
#[derive(Debug, PartialEq, Eq)]
enum FieldListTarget {
    /// Reissue the catalog with this body.
    Catalog(Vec<u8>),
    /// Reissue this object with this body: the `/AcroForm` dictionary,
    /// or the `/Fields` array, whichever holds the list.
    Object(u32, Vec<u8>),
}

/// Work out how to add the field to the document's `/AcroForm`.
///
/// A second revision -- an archive timestamp over an already-signed
/// document -- meets an `/AcroForm` that exists, and its `/Fields` has
/// to be joined rather than skipped, or the earlier signature's widget
/// is orphaned. But `/AcroForm` is usually an indirect reference, and
/// then the catalog contains no `/Fields` to find: looking only there
/// finds nothing, declines to add an `/AcroForm` because one is already
/// named, and leaves the new field referenced by nobody. The signature
/// is then present in the file and invisible to any reader that walks
/// the form rather than scanning for objects -- which is the difference
/// between poppler reporting a valid signature and `PDFBox` reporting
/// no signature at all.
fn plan_field_list(index: &PdfIndex<'_>, catalog: &[u8], field_number: u32) -> FieldListTarget {
    let entry = format!("{field_number} 0 R");

    // `/AcroForm` held indirectly: the list is in that object, or in an
    // array the object points at.
    if let Some(acroform_number) = indirect_value(catalog, b"/AcroForm")
        && let Some(acroform) = index.object_body(acroform_number)
    {
        if let Some(fields_number) = indirect_value(&acroform, b"/Fields")
            && let Some(fields) = index.object_body(fields_number)
        {
            return FieldListTarget::Object(fields_number, append_to_array(&fields, 0, &entry));
        }
        if let Some(at) = find_first(&acroform, b"/Fields") {
            return FieldListTarget::Object(
                acroform_number,
                append_to_array(&acroform, at, &entry),
            );
        }
        // An `/AcroForm` with no `/Fields` at all: give it one.
        return FieldListTarget::Object(
            acroform_number,
            insert_into_dictionary(&acroform, &format!("/Fields [{entry}]"), b"/Fields"),
        );
    }

    // Held inline, or absent entirely.
    find_first(catalog, b"/Fields").map_or_else(
        || {
            let acroform = format!("/AcroForm << /Fields [{entry}] /SigFlags 3 >>");
            FieldListTarget::Catalog(insert_into_dictionary(catalog, &acroform, b"/AcroForm"))
        },
        |at| FieldListTarget::Catalog(append_to_array(catalog, at, &entry)),
    )
}

/// The object number of an indirect `key N 0 R`, if that is its shape.
///
/// Returns `None` when the key is absent or its value is written
/// inline, which the caller has to tell apart.
fn indirect_value(dictionary: &[u8], key: &[u8]) -> Option<u32> {
    let at = find_first(dictionary, key)?;
    let rest = dictionary.get(at.saturating_add(key.len())..)?;
    let first = rest.iter().position(|byte| !byte.is_ascii_whitespace())?;
    if !rest.get(first)?.is_ascii_digit() {
        return None;
    }
    leading_reference(rest)
}

/// Object numbers assigned to the three validation-material categories.
struct ValidationObjectNumbers {
    certificates: Vec<u32>,
    ocsp_responses: Vec<u32>,
    crls: Vec<u32>,
}

/// Objects that make the newest catalog point at the merged store.
struct ValidationStorePlan {
    next_object: u32,
    objects: Vec<(u32, Vec<u8>)>,
}

/// Emit one stream for each distinct new evidence blob.
fn emit_validation_blobs(
    blobs: &[Vec<u8>],
    next_object: &mut u32,
    update_start: usize,
    update: &mut Vec<u8>,
    offsets: &mut Vec<(u32, usize)>,
) -> Vec<u32> {
    let unique = ordered_unique_blobs(blobs);
    let mut numbers = Vec::with_capacity(unique.len());
    for blob in unique {
        let number = *next_object;
        *next_object = (*next_object).saturating_add(1);
        offsets.push((number, update_start.saturating_add(update.len())));
        update.extend_from_slice(
            format!("{number} 0 obj\n<< /Length {} >>\nstream\n", blob.len()).as_bytes(),
        );
        update.extend_from_slice(blob);
        update.extend_from_slice(b"\nendstream\nendobj\n");
        numbers.push(number);
    }
    numbers
}

/// Plan the store and catalog objects after the evidence streams exist.
fn validation_store_plan(
    index: &PdfIndex<'_>,
    catalog: &[u8],
    catalog_number: u32,
    next_object: u32,
    numbers: &ValidationObjectNumbers,
) -> Result<ValidationStorePlan, PdfError> {
    let dictionary = PdfDictionary::parse(catalog)?;
    let store_value = dictionary.entry(b"DSS")?.map(|entry| entry.value.clone());
    let Some(value_span) = store_value else {
        let store_number = next_object;
        let entry = format!("/DSS {store_number} 0 R");
        return Ok(ValidationStorePlan {
            next_object: next_object.saturating_add(1),
            objects: vec![
                (
                    store_number,
                    validation_store_body(
                        &numbers.certificates,
                        &numbers.ocsp_responses,
                        &numbers.crls,
                    ),
                ),
                (
                    catalog_number,
                    insert_dictionary_entry(catalog, dictionary.closing, entry.as_bytes()),
                ),
            ],
        });
    };

    let value = catalog
        .get(value_span.clone())
        .ok_or(PdfError::UnreadableValidationStore)?;
    if let Some(reference) = complete_object_reference(value)? {
        if reference.generation != 0 {
            return Err(PdfError::UnreadableValidationStore);
        }
        let store = index
            .object_body_reference(reference)
            .ok_or(PdfError::MissingObject(reference.number))?;
        let merged = merge_validation_store(
            index,
            store,
            &numbers.certificates,
            &numbers.ocsp_responses,
            &numbers.crls,
        )?;
        return Ok(ValidationStorePlan {
            next_object,
            objects: vec![(reference.number, merged)],
        });
    }

    let store_number = next_object;
    let merged = merge_validation_store(
        index,
        value.to_vec(),
        &numbers.certificates,
        &numbers.ocsp_responses,
        &numbers.crls,
    )?;
    let entry = format!("{store_number} 0 R");
    Ok(ValidationStorePlan {
        next_object: next_object.saturating_add(1),
        objects: vec![
            (store_number, merged),
            (
                catalog_number,
                replace_bytes(catalog, value_span, entry.as_bytes()),
            ),
        ],
    })
}

/// Append a `/DSS` dictionary carrying the validation material.
///
/// `PAdES` keeps its long-term evidence in a Document Security Store at
/// the catalog level, not in the `CMS` (`EN 319 142-1 sec.5.4`). The
/// store is added in a further incremental update, *after* signing --
/// which is the point. The signature covers the revisions before it and
/// says nothing about this one, so evidence can be added to a signed
/// document years later without breaking anything, and by someone other
/// than the signer.
///
/// A validator reads the store, sees the signature covers only an
/// earlier revision, and checks that what came after is a permitted
/// addition rather than a change to the signed content.
///
/// # Errors
/// [`PdfError`] if the finished document cannot be re-read well enough
/// to extend it.
pub fn append_validation_store(
    signed_pdf: &[u8],
    certificates: &[Vec<u8>],
    ocsp_responses: &[Vec<u8>],
    crls: &[Vec<u8>],
) -> Result<Vec<u8>, PdfError> {
    if certificates.is_empty() && ocsp_responses.is_empty() && crls.is_empty() {
        return Ok(signed_pdf.to_vec());
    }
    let index = PdfIndex::parse(signed_pdf)?;
    let trailer = index.trailer();
    let catalog_number =
        dictionary_reference(trailer, b"/Root").ok_or(PdfError::MissingCatalogReference)?;
    let mut next_object = dictionary_integer(trailer, b"/Size").unwrap_or(0).max(1);

    let mut out = signed_pdf.to_vec();
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    let update_start = out.len();
    let mut update = Vec::new();
    let mut offsets: Vec<(u32, usize)> = Vec::new();

    // Streams carry binary DER without PDF-string transcoding.
    let numbers = ValidationObjectNumbers {
        certificates: emit_validation_blobs(
            certificates,
            &mut next_object,
            update_start,
            &mut update,
            &mut offsets,
        ),
        ocsp_responses: emit_validation_blobs(
            ocsp_responses,
            &mut next_object,
            update_start,
            &mut update,
            &mut offsets,
        ),
        crls: emit_validation_blobs(
            crls,
            &mut next_object,
            update_start,
            &mut update,
            &mut offsets,
        ),
    };

    let catalog = index
        .object_body(catalog_number)
        .ok_or(PdfError::MissingObject(catalog_number))?;
    let plan = validation_store_plan(&index, &catalog, catalog_number, next_object, &numbers)?;
    next_object = plan.next_object;
    for (number, body) in plan.objects {
        offsets.push((number, update_start.saturating_add(update.len())));
        update.extend_from_slice(format!("{number} 0 obj\n").as_bytes());
        update.extend_from_slice(&body);
        update.extend_from_slice(b"\nendobj\n");
    }

    push_xref_and_trailer(
        &mut update,
        update_start,
        &mut offsets,
        next_object,
        catalog_number,
        &index,
    )?;
    out.extend_from_slice(&update);
    Ok(out)
}

/// Write the four `/ByteRange` values into their reserved fields.
///
/// Each is right-aligned in [`BYTE_RANGE_DIGITS`] characters and
/// preceded by the space written during reservation, so the array's
/// length is identical before and after.
fn write_byte_range(document: &mut [u8], at: usize, values: [usize; 4]) {
    /// One space plus the digits, per field.
    const FIELD_STRIDE: usize = BYTE_RANGE_DIGITS + 1;
    for (index, value) in values.iter().enumerate() {
        let text = format!("{value:>BYTE_RANGE_DIGITS$}");
        let start = at
            .saturating_add(index.saturating_mul(FIELD_STRIDE))
            .saturating_add(1);
        document[start..start.saturating_add(BYTE_RANGE_DIGITS)].copy_from_slice(text.as_bytes());
    }
}

/// A classic cross-reference section covering exactly `offsets`.
///
/// Written as one subsection per object so the numbers need not be
/// contiguous -- the catalog keeps its original number while the new
/// objects take fresh ones at the end.
fn cross_reference_section(offsets: &[(u32, usize)]) -> Vec<u8> {
    let mut out = Vec::from("xref\n");
    for (number, offset) in offsets {
        out.extend_from_slice(format!("{number} 1\n{offset:010} 00000 n \n").as_bytes());
    }
    out
}

/// `/Key (text)` when the text is present, with PDF string escaping.
fn push_optional_text(out: &mut Vec<u8>, key: &str, value: Option<&str>) {
    let Some(value) = value else { return };
    out.extend_from_slice(key.as_bytes());
    out.extend_from_slice(b" (");
    for byte in value.bytes() {
        // Backslash, and both parens, must be escaped inside a literal
        // string or the dictionary ends early (ISO 32000-1 sec.7.3.4.2).
        if byte == b'\\' || byte == b'(' || byte == b')' {
            out.push(b'\\');
        }
        out.push(byte);
    }
    out.extend_from_slice(b")\n");
}

/// The offset recorded by the file's last `startxref`.
fn find_start_xref(pdf: &[u8]) -> Result<usize, PdfError> {
    let at = find_last(pdf, b"startxref").ok_or(PdfError::MissingStartXref)?;
    let tail = &pdf[at.saturating_add(b"startxref".len())..];
    let digits: Vec<u8> = tail
        .iter()
        .skip_while(|byte| byte.is_ascii_whitespace())
        .take_while(|byte| byte.is_ascii_digit())
        .copied()
        .collect();
    if digits.is_empty() {
        return Err(PdfError::MissingStartXref);
    }
    let text = String::from_utf8_lossy(&digits);
    text.parse().map_err(|_ignored| PdfError::MissingStartXref)
}

/// Where one live object's bytes sit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XrefLocation {
    /// Free, or an entry type this reader does not know: the number
    /// is claimed so older sections' copies stay shadowed, and a
    /// reference to it resolves to nothing.
    Free,
    /// At a byte offset in the file, written as `N G obj`.
    Direct {
        /// The offset of the object header.
        offset: usize,
    },
    /// Inside an object stream (ISO 32000-1 sec.7.5.7).
    Compressed {
        /// The object stream's own number.
        container: u32,
        /// The object's position among the stream's contents.
        position: u32,
    },
}

/// One object entry resolved from the xref chain.
#[derive(Debug, Clone, Copy)]
struct XrefEntry {
    number: u32,
    generation: u16,
    location: XrefLocation,
}

/// The xref view of the current PDF revision, whichever shape its
/// sections take.
struct PdfIndex<'a> {
    pdf: &'a [u8],
    trailer: Vec<u8>,
    start_xref: usize,
    /// Whether the newest section is a cross-reference stream, which
    /// decides the shape of the section an update appends.
    newest_is_stream: bool,
    objects: Vec<XrefEntry>,
}

impl<'a> PdfIndex<'a> {
    /// Maximum number of incremental updates followed through `/Prev`.
    const MAX_XREF_DEPTH: usize = 64;

    fn parse(pdf: &'a [u8]) -> Result<Self, PdfError> {
        let start_xref = find_start_xref(pdf)?;
        let mut next = Some(start_xref);
        let mut visited = Vec::new();
        let mut trailer = None;
        let mut newest_is_stream = false;
        let mut objects = Vec::new();

        for _ in 0..Self::MAX_XREF_DEPTH {
            let Some(offset) = next else { break };
            if visited.contains(&offset) {
                return Err(PdfError::MissingTrailer);
            }
            visited.push(offset);

            let section = parse_xref_section(pdf, offset)?;
            if trailer.is_none() {
                trailer = Some(section.trailer.clone());
                newest_is_stream = section.is_stream;
            }
            for entry in section.entries {
                // Newer xref sections win. Keep a newer free entry too:
                // it deletes the object and must suppress older copies.
                if !objects
                    .iter()
                    .any(|existing: &XrefEntry| existing.number == entry.number)
                {
                    objects.push(entry);
                }
            }
            next = dictionary_usize(&section.trailer, b"/Prev");
        }

        Ok(Self {
            pdf,
            trailer: trailer.ok_or(PdfError::MissingTrailer)?,
            start_xref,
            newest_is_stream,
            objects,
        })
    }

    fn trailer(&self) -> &[u8] {
        &self.trailer
    }

    const fn start_xref(&self) -> usize {
        self.start_xref
    }

    /// Whether an update must close with a cross-reference stream.
    const fn newest_is_stream(&self) -> bool {
        self.newest_is_stream
    }

    fn object_body(&self, number: u32) -> Option<Vec<u8>> {
        self.object_body_reference(PdfObjectReference {
            number,
            generation: 0,
        })
    }

    fn object_body_reference(&self, reference: PdfObjectReference) -> Option<Vec<u8>> {
        let entry = self.objects.iter().find(|entry| {
            entry.number == reference.number && entry.generation == reference.generation
        })?;
        match entry.location {
            XrefLocation::Free => None,
            XrefLocation::Direct { offset } => {
                object_body_at(self.pdf, reference.number, reference.generation, offset)
            }
            XrefLocation::Compressed {
                container,
                position,
            } => {
                let carrier = self
                    .objects
                    .iter()
                    .find(|entry| entry.number == container)?;
                let XrefLocation::Direct { offset } = carrier.location else {
                    return None;
                };
                xref_stream::compressed_body(self.pdf, offset, reference.number, position)
            }
        }
    }
}

struct XrefSection {
    trailer: Vec<u8>,
    entries: Vec<XrefEntry>,
    /// Whether the section is a cross-reference stream.
    is_stream: bool,
}

fn parse_xref_section(pdf: &[u8], offset: usize) -> Result<XrefSection, PdfError> {
    let mut cursor = skip_pdf_whitespace(pdf, offset);
    let Some(rest) = pdf.get(cursor..) else {
        return Err(PdfError::MissingStartXref);
    };
    if !rest.starts_with(b"xref") {
        return xref_stream::parse_stream_section(pdf, cursor);
    }
    cursor = cursor.saturating_add(b"xref".len());

    let mut entries = Vec::new();
    loop {
        let token = read_pdf_token(pdf, &mut cursor).ok_or(PdfError::MissingTrailer)?;
        if token == b"trailer" {
            let (trailer, _after) = dictionary_at(pdf, cursor).ok_or(PdfError::MissingTrailer)?;
            return hybrid_merged(pdf, trailer, entries);
        }

        let start = parse_u32(token).ok_or(PdfError::MissingTrailer)?;
        let count = parse_u32(read_pdf_token(pdf, &mut cursor).ok_or(PdfError::MissingTrailer)?)
            .ok_or(PdfError::MissingTrailer)?;

        for index in 0..count {
            let object_offset =
                parse_usize(read_pdf_token(pdf, &mut cursor).ok_or(PdfError::MissingTrailer)?)
                    .ok_or(PdfError::MissingTrailer)?;
            let generation =
                parse_u16(read_pdf_token(pdf, &mut cursor).ok_or(PdfError::MissingTrailer)?)
                    .ok_or(PdfError::MissingTrailer)?;
            let flag = read_pdf_token(pdf, &mut cursor).ok_or(PdfError::MissingTrailer)?;
            let number = start.checked_add(index).ok_or(PdfError::MissingTrailer)?;
            let location = if flag == b"n" {
                XrefLocation::Direct {
                    offset: object_offset,
                }
            } else {
                XrefLocation::Free
            };
            entries.push(XrefEntry {
                number,
                generation,
                location,
            });
        }
    }
}

/// A classic table section, merged with the cross-reference stream a
/// hybrid trailer names.
///
/// A hybrid revision keeps the authoritative copy of its entries in
/// the stream its `/XRefStm` key points at; the table is the fallback
/// for readers that predate streams (ISO 32000-1 sec.7.5.8.4). The
/// stream's entries go first, so they win the newest-copy merge.
fn hybrid_merged(
    pdf: &[u8],
    trailer: Vec<u8>,
    entries: Vec<XrefEntry>,
) -> Result<XrefSection, PdfError> {
    let Some(hybrid) = dictionary_usize(&trailer, b"/XRefStm") else {
        return Ok(XrefSection {
            trailer,
            entries,
            is_stream: false,
        });
    };
    let stream = xref_stream::parse_stream_section(pdf, skip_pdf_whitespace(pdf, hybrid))?;
    let mut combined = stream.entries;
    combined.extend(entries);
    Ok(XrefSection {
        trailer,
        entries: combined,
        is_stream: false,
    })
}

fn skip_pdf_whitespace(pdf: &[u8], mut cursor: usize) -> usize {
    while pdf.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor = cursor.saturating_add(1);
    }
    cursor
}

fn read_pdf_token<'a>(pdf: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    *cursor = skip_pdf_whitespace(pdf, *cursor);
    let start = *cursor;
    while pdf
        .get(*cursor)
        .is_some_and(|byte| !byte.is_ascii_whitespace())
    {
        *cursor = (*cursor).saturating_add(1);
    }
    (start < *cursor).then(|| &pdf[start..*cursor])
}

fn parse_usize(digits: &[u8]) -> Option<usize> {
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut out = 0_usize;
    for digit in digits {
        out = out
            .checked_mul(10)?
            .checked_add(usize::from(digit.saturating_sub(b'0')))?;
    }
    Some(out)
}

fn parse_u32(digits: &[u8]) -> Option<u32> {
    parse_usize(digits).and_then(|value| u32::try_from(value).ok())
}

fn parse_u16(digits: &[u8]) -> Option<u16> {
    parse_usize(digits).and_then(|value| u16::try_from(value).ok())
}

fn dictionary_at(pdf: &[u8], cursor: usize) -> Option<(Vec<u8>, usize)> {
    let start = skip_pdf_whitespace(pdf, cursor);
    if !pdf.get(start..)?.starts_with(b"<<") {
        return None;
    }

    let mut cursor = start;
    let mut depth = 0_u32;
    let mut state = Scan::Regular;
    while cursor < pdf.len() {
        let byte = pdf[cursor];
        match state {
            Scan::Regular => match byte {
                b'%' => {
                    state = Scan::Comment;
                    cursor = cursor.saturating_add(1);
                }
                b'(' => {
                    state = Scan::LiteralString {
                        depth: 1,
                        escaped: false,
                    };
                    cursor = cursor.saturating_add(1);
                }
                b'<' if pdf.get(cursor.saturating_add(1)) == Some(&b'<') => {
                    depth = depth.saturating_add(1);
                    cursor = cursor.saturating_add(2);
                }
                b'<' => {
                    state = Scan::HexString;
                    cursor = cursor.saturating_add(1);
                }
                b'>' if pdf.get(cursor.saturating_add(1)) == Some(&b'>') => {
                    depth = depth.checked_sub(1)?;
                    cursor = cursor.saturating_add(2);
                    if depth == 0 {
                        return Some((pdf[start..cursor].to_vec(), cursor));
                    }
                }
                _ => cursor = cursor.saturating_add(1),
            },
            Scan::Comment => {
                cursor = cursor.saturating_add(1);
                if byte == b'\r' || byte == b'\n' {
                    state = Scan::Regular;
                }
            }
            Scan::HexString => {
                cursor = cursor.saturating_add(1);
                if byte == b'>' {
                    state = Scan::Regular;
                }
            }
            Scan::LiteralString {
                mut depth,
                mut escaped,
            } => {
                cursor = cursor.saturating_add(1);
                if escaped {
                    escaped = false;
                    state = Scan::LiteralString { depth, escaped };
                    continue;
                }
                match byte {
                    b'\\' => {
                        escaped = true;
                        state = Scan::LiteralString { depth, escaped };
                    }
                    b'(' => {
                        depth = depth.saturating_add(1);
                        state = Scan::LiteralString { depth, escaped };
                    }
                    b')' => {
                        depth = depth.checked_sub(1)?;
                        if depth == 0 {
                            state = Scan::Regular;
                        } else {
                            state = Scan::LiteralString { depth, escaped };
                        }
                    }
                    _ => state = Scan::LiteralString { depth, escaped },
                }
            }
        }
    }
    None
}

/// The `N 0 R` object number stored under `key`.
fn dictionary_reference(dictionary: &[u8], key: &[u8]) -> Option<u32> {
    let at = find_first(dictionary, key)?;
    let rest = &dictionary[at.saturating_add(key.len())..];
    let digits: Vec<u8> = rest
        .iter()
        .skip_while(|byte| byte.is_ascii_whitespace())
        .take_while(|byte| byte.is_ascii_digit())
        .copied()
        .collect();
    String::from_utf8_lossy(&digits).parse().ok()
}

/// The integer stored under `key`.
fn dictionary_integer(dictionary: &[u8], key: &[u8]) -> Option<u32> {
    dictionary_usize(dictionary, key).and_then(|value| u32::try_from(value).ok())
}

fn dictionary_usize(dictionary: &[u8], key: &[u8]) -> Option<usize> {
    let at = find_first(dictionary, key)?;
    let rest = &dictionary[at.saturating_add(key.len())..];
    let digits: Vec<u8> = rest
        .iter()
        .skip_while(|byte| byte.is_ascii_whitespace())
        .take_while(|byte| byte.is_ascii_digit())
        .copied()
        .collect();
    parse_usize(&digits)
}

/// Test helper for small PDF fragments. Production reads through
/// [`PdfIndex::object_body`].
#[cfg(test)]
fn object_body(pdf: &[u8], number: u32) -> Option<Vec<u8>> {
    PdfIndex::parse(pdf)
        .ok()
        .and_then(|index| index.object_body(number))
        .or_else(|| raw_object_body(pdf, number))
}

fn object_body_at(pdf: &[u8], number: u32, generation: u16, offset: usize) -> Option<Vec<u8>> {
    let mut cursor = offset;
    let actual_number = parse_u32(read_pdf_token(pdf, &mut cursor)?)?;
    let actual_generation = parse_u16(read_pdf_token(pdf, &mut cursor)?)?;
    let keyword = read_pdf_token(pdf, &mut cursor)?;
    if actual_number != number || actual_generation != generation || keyword != b"obj" {
        return None;
    }
    let end = find_first(pdf.get(cursor..)?, b"endobj")?;
    Some(pdf[cursor..cursor.saturating_add(end)].to_vec())
}

#[cfg(test)]
fn raw_object_body(pdf: &[u8], number: u32) -> Option<Vec<u8>> {
    let header = format!("{number} 0 obj");
    let at = last_object_header(pdf, header.as_bytes())?;
    let after = at.saturating_add(header.len());
    let end = find_first(&pdf[after..], b"endobj")?;
    Some(pdf[after..after.saturating_add(end)].to_vec())
}

/// Offset of the last `N 0 obj` header, matching whole numbers only.
///
/// A plain search for `1 0 obj` also matches the tail of `481 0 obj`,
/// which silently returns a different object -- and in a large file
/// with a low-numbered target, almost always does. The preceding byte
/// must therefore not be a digit. It was this, not the page-tree walk,
/// that first put a signature widget into a content stream.
#[cfg(test)]
fn last_object_header(pdf: &[u8], header: &[u8]) -> Option<usize> {
    let mut found = None;
    let mut from = 0_usize;
    while let Some(offset) = find_first(pdf.get(from..)?, header) {
        let at = from.saturating_add(offset);
        let preceded_by_digit = at
            .checked_sub(1)
            .and_then(|before| pdf.get(before))
            .is_some_and(u8::is_ascii_digit);
        if !preceded_by_digit {
            found = Some(at);
        }
        from = at.saturating_add(1);
    }
    found
}

/// The object number of the first page.
///
/// Walks catalog -> `/Pages` -> `/Kids[0]`, descending through
/// intermediate `/Pages` nodes until a leaf is reached. The signature
/// widget has to live on a page, and with an invisible `/Rect` any page
/// serves; the first is the one a reader opens.
fn first_page_number(index: &PdfIndex<'_>, catalog: &[u8]) -> Result<u32, PdfError> {
    /// Depth bound. A page tree deeper than this is not a document, and
    /// a `/Kids` cycle would otherwise spin here forever.
    const MAX_DEPTH: usize = 32;

    let mut number = dictionary_reference(catalog, b"/Pages").ok_or(PdfError::MissingPageTree)?;
    for _ in 0..MAX_DEPTH {
        let node = index
            .object_body(number)
            .ok_or(PdfError::MissingObject(number))?;
        let Some(kids_at) = find_first(&node, b"/Kids") else {
            // No `/Kids`: this is a leaf, so it is the page.
            return Ok(number);
        };
        let after = &node[kids_at.saturating_add(b"/Kids".len())..];
        let open = find_first(after, b"[").ok_or(PdfError::MissingPageTree)?;
        let first = &after[open.saturating_add(1)..];
        number = leading_reference(first).ok_or(PdfError::MissingPageTree)?;
    }
    Err(PdfError::MissingPageTree)
}

/// The object number of the last page.
///
/// Walks catalog -> `/Pages` -> last of `/Kids`, descending through
/// intermediate `/Pages` nodes until a leaf is reached. This is where a
/// visible signature lives -- see [`signature_page`].
fn last_page_number(index: &PdfIndex<'_>, catalog: &[u8]) -> Result<u32, PdfError> {
    /// Depth bound. A page tree deeper than this is not a document, and
    /// a `/Kids` cycle would otherwise spin here forever.
    const MAX_DEPTH: usize = 32;

    let mut number = dictionary_reference(catalog, b"/Pages").ok_or(PdfError::MissingPageTree)?;
    for _ in 0..MAX_DEPTH {
        let node = index
            .object_body(number)
            .ok_or(PdfError::MissingObject(number))?;
        let Some(kids_at) = find_first(&node, b"/Kids") else {
            // No `/Kids`: this is a leaf, so it is the page.
            return Ok(number);
        };
        let after = &node[kids_at.saturating_add(b"/Kids".len())..];
        let open = find_first(after, b"[").ok_or(PdfError::MissingPageTree)?;
        let members = &after[open.saturating_add(1)..];
        let close = find_first(members, b"]").ok_or(PdfError::MissingPageTree)?;
        number = last_reference(&members[..close]).ok_or(PdfError::MissingPageTree)?;
    }
    Err(PdfError::MissingPageTree)
}

/// The `N 0 R` closest to the end of `bytes`, or `None` without one.
fn last_reference(bytes: &[u8]) -> Option<u32> {
    let mut last = None;
    let mut two_back: Option<&[u8]> = None;
    let mut one_back: Option<&[u8]> = None;
    for token in bytes
        .split(u8::is_ascii_whitespace)
        .filter(|token| !token.is_empty())
    {
        if token == b"R".as_slice() {
            let generation_is_number =
                one_back.is_some_and(|token| token.iter().all(u8::is_ascii_digit));
            if generation_is_number {
                let number = two_back
                    .and_then(|token| core::str::from_utf8(token).ok())
                    .and_then(|token| token.parse().ok());
                last = number.or(last);
            }
        }
        two_back = one_back;
        one_back = Some(token);
    }
    last
}

/// Placement for a visible signature on its page.
///
/// The mark goes where the page has room: [`spot::free`] reads the
/// page's own content and finds the conventional spot nearest the
/// lower right that covers nothing already printed. When the content
/// cannot be read conservatively, the fixed lower-right corner is the
/// fallback -- ink there is covered rather than misplaced.
///
/// Page boxes are inherited through the page tree. A malformed or unusual box
/// falls back to ISO A4 dimensions rather than putting the annotation at an
/// unbounded coordinate supplied by the input.
fn visible_signature_rectangle(
    index: &PdfIndex<'_>,
    page_number: u32,
    page: &[u8],
    natural_side: f64,
) -> [f64; 4] {
    const A4_WIDTH_POINTS: f64 = 595.0;
    const A4_HEIGHT_POINTS: f64 = 842.0;
    const MAX_MARGIN: f64 = 24.0;
    const MARGIN_SHARE: f64 = 0.05;
    const MINIMUM_SIDE: f64 = 1.0;

    let page_box = inherited_page_rectangle(index, page_number, page).unwrap_or([
        0.0,
        0.0,
        A4_WIDTH_POINTS,
        A4_HEIGHT_POINTS,
    ]);
    let left = page_box[0].min(page_box[2]);
    let right = page_box[0].max(page_box[2]);
    let bottom = page_box[1].min(page_box[3]);
    let top = page_box[1].max(page_box[3]);
    if let Some(rectangle) = spot::free(index, page, [left, bottom, right, top], natural_side) {
        return rectangle;
    }
    let width = right - left;
    let height = top - bottom;
    let shorter = width.min(height).max(MINIMUM_SIDE);
    let margin = (shorter * MARGIN_SHARE).min(MAX_MARGIN);
    let side = natural_side
        .min((width - margin * 2.0).max(MINIMUM_SIDE))
        .min((height - margin * 2.0).max(MINIMUM_SIDE));
    let x1 = right - margin;
    let x0 = x1 - side;
    let y0 = bottom + margin;
    let y1 = y0 + side;
    [x0, y0, x1, y1]
}

/// Nearest inherited `/CropBox`, otherwise nearest inherited `/MediaBox`.
fn inherited_page_rectangle(
    index: &PdfIndex<'_>,
    page_number: u32,
    page: &[u8],
) -> Option<[f64; 4]> {
    const MAX_DEPTH: usize = 32;

    let mut number = page_number;
    let mut body = page.to_vec();
    let mut media_box = None;
    for _ in 0..MAX_DEPTH {
        if let Some(crop) = dictionary_rectangle(&body, b"CropBox") {
            return Some(crop);
        }
        media_box = media_box.or_else(|| dictionary_rectangle(&body, b"MediaBox"));
        let Some(parent) = dictionary_reference(&body, b"/Parent") else {
            break;
        };
        if parent == number {
            break;
        }
        number = parent;
        body = index.object_body(number)?;
    }
    media_box
}

/// Four finite numbers carried by one direct page-box array.
fn dictionary_rectangle(dictionary: &[u8], name: &[u8]) -> Option<[f64; 4]> {
    let parsed = PdfDictionary::parse(dictionary).ok()?;
    let entry = parsed.entry(name).ok()??;
    let value = core::str::from_utf8(&dictionary[entry.value.clone()]).ok()?;
    let trimmed = value.trim();
    let inner = trimmed.strip_prefix('[')?.strip_suffix(']')?;
    let numbers = inner
        .split_ascii_whitespace()
        .map(str::parse::<f64>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let &[x0, y0, x1, y1] = numbers.as_slice() else {
        return None;
    };
    if [x0, y0, x1, y1].iter().all(|value| value.is_finite()) {
        Some([x0, y0, x1, y1])
    } else {
        None
    }
}

/// The `N 0 R` at the start of `bytes`, skipping leading whitespace.
fn leading_reference(bytes: &[u8]) -> Option<u32> {
    let digits: Vec<u8> = bytes
        .iter()
        .skip_while(|byte| byte.is_ascii_whitespace())
        .take_while(|byte| byte.is_ascii_digit())
        .copied()
        .collect();
    String::from_utf8_lossy(&digits).parse().ok()
}

/// Where the widget reference has to be written.
///
/// Three shapes, because real page trees use all of them: no `/Annots`
/// at all, a direct array, or an indirect reference to an array object.
/// The third cannot be fixed by rewriting the page, because the array
/// is not in it.
#[derive(Debug, PartialEq, Eq)]
enum AnnotsTarget {
    /// Reissue the page with this body.
    Page(Vec<u8>),
    /// Reissue this object; it holds the array.
    Array(u32),
}

/// Work out how to get `reference` into the page's `/Annots`.
fn plan_annotation(page: &[u8], reference: u32) -> AnnotsTarget {
    let entry = format!("{reference} 0 R");
    let Some(at) = find_first(page, b"/Annots") else {
        // Absent. `insert_into_dictionary` is guarded on the key being
        // missing, which is exactly the case here.
        return AnnotsTarget::Page(insert_into_dictionary(
            page,
            &format!("/Annots [{entry}]"),
            b"/Annots",
        ));
    };
    let after = at.saturating_add(b"/Annots".len());
    let rest = &page[after..];
    let first_token = rest
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .map(|index| rest[index]);
    if first_token == Some(b'[') {
        return AnnotsTarget::Page(append_to_array(page, after, &entry));
    }
    // `/Annots 12 0 R`: the array is its own object.
    leading_reference(rest).map_or_else(|| AnnotsTarget::Page(page.to_vec()), AnnotsTarget::Array)
}

/// Insert `entry` just before the `]` of the array starting after
/// `from`.
fn append_to_array(body: &[u8], from: usize, entry: &str) -> Vec<u8> {
    let Some(open) = find_first(&body[from..], b"[") else {
        return body.to_vec();
    };
    let open = from.saturating_add(open);
    let Some(close) = find_first(&body[open..], b"]") else {
        return body.to_vec();
    };
    let close = open.saturating_add(close);
    let mut out = body[..close].to_vec();
    out.extend_from_slice(b" ");
    out.extend_from_slice(entry.as_bytes());
    out.extend_from_slice(&body[close..]);
    out
}

/// Insert `entry` into the outermost dictionary of `object`, unless
/// `key` is already present.
fn insert_into_dictionary(object: &[u8], entry: &str, key: &[u8]) -> Vec<u8> {
    let trimmed: Vec<u8> = object.to_vec();
    if find_first(&trimmed, key).is_some() {
        return trimmed;
    }
    let Some(close) = find_last(&trimmed, b">>") else {
        return trimmed;
    };
    let mut out = trimmed[..close].to_vec();
    out.extend_from_slice(b"\n");
    out.extend_from_slice(entry.as_bytes());
    out.extend_from_slice(b"\n>>");
    out.extend_from_slice(&trimmed[close.saturating_add(2)..]);
    out
}

/// First occurrence of `needle`.
fn find_first(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Last occurrence of `needle`.
fn find_last(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use crate::sign::asic::DataObject;
    use crate::sign::cades::{DigestAlgorithm, SignatureAlgorithm, SignerParameters};
    use crate::sign::document::{Format, plan as plan_document};
    use crate::sign::validation::ValidationMaterial;
    use crate::x509::Certificate;

    use super::{
        AnnotsTarget, DEFAULT_SIGNATURE_CAPACITY, FieldListTarget, MAX_FIELD_NAME_BYTES,
        PdfDictionary, PdfError, PdfIndex, SignatureInk, SignatureMetadata, VisibleSignature,
        XrefEntry, XrefLocation, append_validation_store, complete_object_reference,
        dictionary_reference, existing_field_names, last_object_header, last_reference,
        object_body, plan_annotation, plan_field_list, prepare, prepare_document_timestamp,
        validation_references,
    };

    const CERTIFICATE_DER: &[u8] = include_bytes!(
        "../../../refineid-client/test-vectors/fineid-intermediate-01-citizen-g4e.der"
    );

    /// A minimal but structurally complete PDF: catalog, page tree, one
    /// page, a classic cross-reference table and a trailer.
    ///
    /// Built here rather than committed so the offsets are computed
    /// from the bytes, which is the only way a fixture PDF stays valid
    /// when somebody edits it.
    pub(super) fn minimal_pdf() -> Vec<u8> {
        let bodies = [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
        ];
        let mut pdf = Vec::from("%PDF-1.7\n");
        let mut offsets = Vec::new();
        for (index, body) in bodies.iter().enumerate() {
            offsets.push(pdf.len());
            pdf.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", index + 1).as_bytes());
        }
        let xref_at = pdf.len();
        pdf.extend_from_slice(format!("xref\n0 {}\n", bodies.len() + 1).as_bytes());
        pdf.extend_from_slice(b"0000000000 65535 f \n");
        for offset in &offsets {
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

    /// Like [`minimal_pdf`], with a second page after the first.
    fn two_page_pdf() -> Vec<u8> {
        let bodies = [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
        ];
        let mut pdf = Vec::from("%PDF-1.7\n");
        let mut offsets = Vec::new();
        for (index, body) in bodies.iter().enumerate() {
            offsets.push(pdf.len());
            pdf.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", index + 1).as_bytes());
        }
        let xref_at = pdf.len();
        pdf.extend_from_slice(format!("xref\n0 {}\n", bodies.len() + 1).as_bytes());
        pdf.extend_from_slice(b"0000000000 65535 f \n");
        for offset in &offsets {
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

    /// Like [`minimal_pdf`], closed by a cross-reference stream with
    /// the catalog, page tree and page inside an object stream -- the
    /// shape PDF 1.5 writers emit (ISO 32000-1 sec.7.5.7, sec.7.5.8).
    /// With `encoded`, the entry rows go behind the PNG Up predictor
    /// and `FlateDecode`.
    fn stream_pdf(encoded: bool) -> Vec<u8> {
        let bodies = [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
        ];
        let mut header = String::new();
        let mut contents = String::new();
        for (index, body) in bodies.iter().enumerate() {
            let _ignored = core::fmt::Write::write_fmt(
                &mut header,
                format_args!("{} {} ", index + 1, contents.len()),
            );
            contents.push_str(body);
            contents.push('\n');
        }
        let payload = format!("{header}{contents}");
        let mut pdf = Vec::from("%PDF-1.7\n");
        let container_at = pdf.len();
        pdf.extend_from_slice(
            format!(
                "4 0 obj\n<< /Type /ObjStm /N {} /First {} /Length {} \
                 >>\nstream\n{payload}\nendstream\nendobj\n",
                bodies.len(),
                header.len(),
                payload.len()
            )
            .as_bytes(),
        );
        let xref_at = pdf.len();
        // One row per object: type, two offset bytes, two more bytes.
        let mut rows: Vec<u8> = vec![0, 0, 0, 0, 0];
        for position in 0..bodies.len() {
            rows.push(2);
            rows.extend_from_slice(&4_u16.to_be_bytes());
            rows.extend_from_slice(
                &u16::try_from(position)
                    .expect("small fixture")
                    .to_be_bytes(),
            );
        }
        for offset in [container_at, xref_at] {
            rows.push(1);
            rows.extend_from_slice(&u16::try_from(offset).expect("small fixture").to_be_bytes());
            rows.extend_from_slice(&0_u16.to_be_bytes());
        }
        let parameters = if encoded {
            rows = miniz_oxide::deflate::compress_to_vec_zlib(&up_predicted(&rows, 5), 6);
            " /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 5 >>"
        } else {
            ""
        };
        pdf.extend_from_slice(
            format!(
                "5 0 obj\n<< /Type /XRef /Size 6 /Root 1 0 R /W [1 2 2]{parameters} \
                 /Length {} >>\nstream\n",
                rows.len()
            )
            .as_bytes(),
        );
        pdf.extend_from_slice(&rows);
        pdf.extend_from_slice(
            format!("\nendstream\nendobj\nstartxref\n{xref_at}\n%%EOF\n").as_bytes(),
        );
        pdf
    }

    /// The rows as PNG Up rows, each relative to the one above.
    fn up_predicted(rows: &[u8], columns: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut above = vec![0_u8; columns];
        for row in rows.chunks_exact(columns) {
            out.push(2);
            for (column, byte) in row.iter().enumerate() {
                out.push(byte.wrapping_sub(above[column]));
            }
            above = row.to_vec();
        }
        out
    }

    #[test]
    fn signs_behind_a_cross_reference_stream() {
        let pdf = stream_pdf(false);
        let signed = prepare(&pdf, &SignatureMetadata::default(), 64)
            .expect("a stream-indexed PDF prepares")
            .document;
        let update = String::from_utf8_lossy(&signed[pdf.len()..]).into_owned();
        assert!(signed.starts_with(&pdf), "the original bytes survive");
        assert!(
            update.contains("/SubFilter /ETSI.CAdES.detached"),
            "the signature dictionary is written"
        );
    }

    #[test]
    fn the_stream_revision_is_closed_with_a_stream() {
        let pdf = stream_pdf(false);
        let signed = prepare(&pdf, &SignatureMetadata::default(), 64)
            .expect("prepares")
            .document;
        let update = String::from_utf8_lossy(&signed[pdf.len()..]).into_owned();
        assert!(update.contains("/Type /XRef"), "closed by a stream");
        assert!(
            !update.contains("trailer"),
            "no classic trailer on a stream chain"
        );
        assert!(update.contains("/Prev "), "the chain continues");
    }

    #[test]
    fn the_catalog_is_read_out_of_the_object_stream() {
        let pdf = stream_pdf(false);
        let signed = prepare(&pdf, &SignatureMetadata::default(), 64)
            .expect("prepares")
            .document;
        let update = String::from_utf8_lossy(&signed[pdf.len()..]).into_owned();
        assert!(
            update.contains("/Type /Catalog") && update.contains("/AcroForm"),
            "the catalog is reissued with the form"
        );
    }

    #[test]
    fn its_own_stream_revision_can_be_extended() {
        let once = prepare(&stream_pdf(false), &SignatureMetadata::default(), 64)
            .expect("first revision prepares")
            .finish(&[1])
            .expect("first signature fits");
        let again = prepare_document_timestamp(&once, 64)
            .expect("the writer re-reads its own stream revision")
            .document;
        assert!(again.starts_with(&once), "the chain grows in place");
    }

    #[test]
    fn flate_and_up_predictor_are_decoded() {
        let signed = prepare(&stream_pdf(true), &SignatureMetadata::default(), 64)
            .expect("an encoded stream section decodes")
            .document;
        let text = String::from_utf8_lossy(&signed);
        assert!(text.contains("/AcroForm"), "the catalog was reachable");
    }

    #[test]
    fn the_validation_store_is_appended_behind_a_stream() {
        let pdf = stream_pdf(false);
        let stored = append_validation_store(&pdf, &[vec![1, 2, 3]], &[], &[])
            .expect("the store appends behind a stream chain");
        let update = String::from_utf8_lossy(&stored[pdf.len()..]).into_owned();
        assert!(update.contains("/Type /DSS"), "the store is written");
        assert!(update.contains("/Type /XRef"), "closed by a stream");
        assert!(!update.contains("trailer"), "no classic trailer");
    }

    fn fragment_index(pdf: &[u8]) -> PdfIndex<'_> {
        let mut objects = Vec::new();
        for number in 1..32 {
            let header = format!("{number} 0 obj");
            if let Some(offset) = last_object_header(pdf, header.as_bytes()) {
                objects.push(XrefEntry {
                    number,
                    generation: 0,
                    location: XrefLocation::Direct { offset },
                });
            }
        }
        PdfIndex {
            pdf,
            trailer: Vec::new(),
            start_xref: 0,
            newest_is_stream: false,
            objects,
        }
    }

    /// The stream objects named by one top-level DSS category.
    fn validation_object_bodies(pdf: &[u8], category: &[u8]) -> Vec<Vec<u8>> {
        let index = PdfIndex::parse(pdf).expect("PDF indexes");
        let catalog_number =
            dictionary_reference(index.trailer(), b"/Root").expect("catalog reference");
        let catalog = index.object_body(catalog_number).expect("catalog object");
        let catalog_dictionary = PdfDictionary::parse(&catalog).expect("catalog dictionary");
        let dss_entry = catalog_dictionary
            .entry(b"DSS")
            .expect("DSS key is unambiguous")
            .expect("DSS is present");
        let dss_reference = complete_object_reference(&catalog[dss_entry.value.clone()])
            .expect("DSS reference parses")
            .expect("DSS is indirect");
        let store = index
            .object_body_reference(dss_reference)
            .expect("DSS object");
        let store_dictionary = PdfDictionary::parse(&store).expect("DSS dictionary");
        let category_entry = store_dictionary
            .entry(category)
            .expect("category key is unambiguous")
            .expect("category is present");
        validation_references(&index, &store[category_entry.value.clone()])
            .expect("category references parse")
            .into_iter()
            .map(|reference| {
                index
                    .object_body_reference(reference)
                    .expect("validation object")
            })
            .collect()
    }

    fn pdf_with_stream_mentioning_fake_catalog() -> Vec<u8> {
        let fake_catalog = b"1 0 obj\n<< /Type /Catalog /Pages 5 0 R >>\nendobj";
        let stream = [b"BT\n(".as_slice(), fake_catalog, b") Tj\nET\n".as_slice()].concat();
        let bodies = [
            b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>".to_vec(),
            [
                format!("<< /Length {} >>\nstream\n", stream.len()).as_bytes(),
                stream.as_slice(),
                b"endstream",
            ]
            .concat(),
            b"<< /Type /Pages /Kids [6 0 R 7 0 R] /Count 2 >>".to_vec(),
            b"<< /Type /Page /Parent 5 0 R /MediaBox [0 0 200 200] >>".to_vec(),
            b"<< /Type /Page /Parent 5 0 R /MediaBox [0 0 200 200] >>".to_vec(),
        ];

        let mut pdf = Vec::from("%PDF-1.7\n");
        let mut offsets = Vec::new();
        for (index, body) in bodies.iter().enumerate() {
            offsets.push(pdf.len());
            pdf.extend_from_slice(format!("{} 0 obj\n", index + 1).as_bytes());
            pdf.extend_from_slice(body);
            pdf.extend_from_slice(b"\nendobj\n");
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

    fn pdf_with_direct_dss() -> Vec<u8> {
        let bodies = [
            "<< /Type /Catalog /Pages 2 0 R /DSS << /Certs [8 0 R] >> >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
        ];
        let mut pdf = Vec::from("%PDF-1.7\n");
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
            format!("trailer\n<< /Size 9 /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n").as_bytes(),
        );
        pdf
    }

    /// A valid one-page PDF with one unsigned top-level signature field.
    fn pdf_with_existing_field(name: &str) -> Vec<u8> {
        let bodies = [
            "<< /Type /Catalog /Pages 2 0 R \
             /AcroForm << /Fields [4 0 R] /SigFlags 3 >> >>"
                .to_owned(),
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned(),
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] \
             /Annots [4 0 R] >>"
                .to_owned(),
            format!(
                "<< /Type /Annot /Subtype /Widget /FT /Sig /T ({name}) \
                 /Rect [0 0 0 0] /F 132 >>"
            ),
        ];
        let mut pdf = Vec::from("%PDF-1.7\n");
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

    /// A complete PDF whose catalog and validation store exercise the
    /// syntax that byte searches cannot distinguish from real keys.
    fn pdf_with_indirect_dss_store(store: Vec<u8>) -> Vec<u8> {
        let bodies = [
            b"<< /Type /Catalog /Pages 2 0 R /Note (quoted /DSS 99 0 R) \
              /Metadata << /DSS 98 0 R >> /D#53S 4 0 R >>"
                .to_vec(),
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>".to_vec(),
            store,
            b"[6 0 R 6 0 R]".to_vec(),
            b"<< /Length 8 >>\nstream\nCERT-OLD\nendstream".to_vec(),
            b"<< /Length 8 >>\nstream\nOCSP-OLD\nendstream".to_vec(),
            b"<< /Length 7 >>\nstream\nCRL-OLD\nendstream".to_vec(),
            b"<< /OLD 6 0 R >>".to_vec(),
            b"<< /Value (kept) >>".to_vec(),
        ];
        let mut pdf = Vec::from("%PDF-1.7\n");
        let mut offsets = Vec::new();
        for (index, body) in bodies.iter().enumerate() {
            offsets.push(pdf.len());
            pdf.extend_from_slice(format!("{} 0 obj\n", index + 1).as_bytes());
            pdf.extend_from_slice(body);
            pdf.extend_from_slice(b"\nendobj\n");
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

    /// A signature field is a widget annotation, and a widget that is
    /// on no page is orphaned: a reader walking from the field to its
    /// page finds nothing. Poppler tolerates it and reports a valid
    /// signature; the EU DSS validator does not, which is the opinion
    /// that decides whether a signature is worth anything.
    #[test]
    fn the_widget_is_attached_to_a_page() {
        let signed = prepare(&minimal_pdf(), &SignatureMetadata::default(), 512)
            .expect("prepares")
            .document;
        let text = String::from_utf8_lossy(&signed);
        // Object 3 is the page. It must be reissued carrying the widget.
        let reissued = text
            .rfind("3 0 obj")
            .map(|at| &text[at..])
            .expect("the page is reissued");
        assert!(
            reissued.contains("/Type /Page") && reissued.contains("/Annots [5 0 R]"),
            "the page must carry the widget: {}",
            &reissued[..reissued.len().min(200)]
        );
    }

    #[test]
    fn visible_signature_is_the_widget_appearance() {
        let ink = SignatureInk::from_rgba(2, 1, &[0, 0, 0, 255, 0, 0, 0, 255]);
        let visible =
            VisibleSignature::new("Test Signer", "12345678A", ink).expect("valid visible identity");
        let metadata = SignatureMetadata {
            visible_signature: Some(visible),
            ..SignatureMetadata::default()
        };
        let prepared = prepare(&minimal_pdf(), &metadata, 512).expect("visible PDF prepares");
        let text = String::from_utf8_lossy(&prepared.document);
        // The fixture page is blank, so the free-spot search settles
        // the mark at clearance distance from the lower-right corner.
        assert!(
            text.contains("/Rect [68.0000 4.0000 196.0000 132.0000]"),
            "visible field has lower-right page coordinates"
        );
        assert!(
            text.contains("/AP << /N 6 0 R >>"),
            "appearance belongs to the signature widget"
        );
        assert!(text.contains("/Subtype /Form"));
        assert!(text.contains("/BaseFont /Helvetica"));
        assert!(text.contains("Test Signer"));
        assert!(text.contains("12345678A"));
        assert!(
            prepared
                .signed_octets()
                .windows(b"Test Signer".len())
                .any(|window| window == b"Test Signer"),
            "the PAdES byte range authenticates the appearance"
        );
    }

    /// A visible mark goes where a paper signature does -- the end of
    /// the document -- while an invisible widget stays on the first
    /// page a reader opens.
    #[test]
    fn visible_signature_lands_on_the_last_page() {
        let visible =
            VisibleSignature::new("Test Signer", "12345678A", None).expect("valid identity");
        let metadata = SignatureMetadata {
            visible_signature: Some(visible),
            ..SignatureMetadata::default()
        };
        let signed = prepare(&two_page_pdf(), &metadata, 512)
            .expect("prepares")
            .document;
        let text = String::from_utf8_lossy(&signed);
        assert!(
            text.contains("/P 4 0 R"),
            "the widget lives on the last page"
        );
        let reissued = text
            .rfind("4 0 obj")
            .map(|at| &text[at..])
            .expect("the last page is reissued");
        assert!(
            reissued.contains("/Annots [6 0 R]"),
            "the last page carries the widget: {}",
            &reissued[..reissued.len().min(200)]
        );

        let invisible = prepare(&two_page_pdf(), &SignatureMetadata::default(), 512)
            .expect("prepares")
            .document;
        let text = String::from_utf8_lossy(&invisible);
        assert!(
            text.contains("/P 3 0 R"),
            "an invisible widget stays on the first page"
        );
    }

    #[test]
    fn last_reference_takes_the_reference_closest_to_the_end() {
        assert_eq!(last_reference(b"3 0 R 4 0 R"), Some(4));
        assert_eq!(last_reference(b" 12 0 R "), Some(12));
        assert_eq!(last_reference(b""), None);
        assert_eq!(last_reference(b"3 0"), None);
        assert_eq!(last_reference(b"not a reference"), None);
    }

    /// `/Annots` comes in three shapes and all three occur in real
    /// files. Absent is the common case; a direct array must be
    /// appended to rather than replaced; an indirect reference names
    /// another object to rewrite instead.
    #[test]
    fn annotations_are_added_to_whichever_shape_the_page_uses() {
        let absent = plan_annotation(b"<< /Type /Page >>", 9);
        match absent {
            AnnotsTarget::Page(body) => {
                assert!(String::from_utf8_lossy(&body).contains("/Annots [9 0 R]"));
            }
            AnnotsTarget::Array(_) => panic!("an absent /Annots is a page rewrite"),
        }

        // An existing entry must survive.
        let direct = plan_annotation(b"<< /Type /Page /Annots [7 0 R] >>", 9);
        match direct {
            AnnotsTarget::Page(body) => {
                let text = String::from_utf8_lossy(&body).into_owned();
                assert!(
                    text.contains("7 0 R"),
                    "the existing annotation stays: {text}"
                );
                assert!(text.contains("9 0 R"), "the widget is added: {text}");
            }
            AnnotsTarget::Array(_) => panic!("a direct array is a page rewrite"),
        }

        assert_eq!(
            plan_annotation(b"<< /Type /Page /Annots 12 0 R >>", 9),
            AnnotsTarget::Array(12),
            "an indirect /Annots names the object holding the array"
        );
    }

    /// An incremental update writes a new trailer, and whatever the old
    /// one carried and the new one omits is gone. `/Info` points at the
    /// title, author and dates; losing it costs the signed document its
    /// title while leaving a file that parses cleanly, so nothing
    /// complains -- the reader just shows a filename.
    #[test]
    fn the_update_trailer_carries_id_and_info_forward() {
        let pdf = b"%PDF-1.7\n\
1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n\
3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>\nendobj\n\
4 0 obj\n<< /Title (Titre) >>\nendobj\n\
trailer\n<< /Size 5 /Root 1 0 R /Info 4 0 R /ID[<AA><BB>] >>\nstartxref\n0\n%%EOF\n";
        let carried =
            super::trailer_carry_forward(b"<< /Size 5 /Root 1 0 R /Info 4 0 R /ID[<AA><BB>] >>");
        assert!(
            carried.contains("/Info 4 0 R"),
            "info must survive: {carried}"
        );
        assert!(
            carried.contains("/ID [<AA><BB>]") || carried.contains("/ID [<AA><BB>]"),
            "id must survive: {carried}"
        );
        let _ = pdf;
    }

    /// `/AcroForm` is usually an indirect reference, and then the
    /// catalog holds no `/Fields` to append to. Looking only in the
    /// catalog finds nothing, declines to add an `/AcroForm` because
    /// one is already named, and leaves the new signature field
    /// referenced by nobody -- present in the file, invisible to any
    /// reader that walks the form. Poppler reported such a signature as
    /// valid; DVV reported the document as `NOT_SIGNED`.
    #[test]
    fn an_indirect_acroform_is_followed_to_its_field_list() {
        let pdf = b"%PDF-1.7\n\
1 0 obj\n<< /Type /Catalog /AcroForm 2 0 R /Pages 4 0 R >>\nendobj\n\
2 0 obj\n<< /Fields [7 0 R] /SigFlags 3 >>\nendobj\n";
        let index = fragment_index(pdf);
        let catalog = object_body(pdf, 1).expect("catalog");
        match plan_field_list(&index, &catalog, 9) {
            FieldListTarget::Object(number, body) => {
                assert_eq!(number, 2, "the AcroForm object is the one to reissue");
                let text = String::from_utf8_lossy(&body).into_owned();
                assert!(text.contains("7 0 R"), "the existing field stays: {text}");
                assert!(text.contains("9 0 R"), "the new field is added: {text}");
            }
            FieldListTarget::Catalog(_) => {
                panic!("an indirect /AcroForm must not be edited in the catalog")
            }
        }
    }

    /// The list can be one hop further out again: `/AcroForm` indirect,
    /// and its `/Fields` indirect too.
    #[test]
    fn an_indirect_field_array_is_followed_as_well() {
        let pdf = b"%PDF-1.7\n\
1 0 obj\n<< /Type /Catalog /AcroForm 2 0 R >>\nendobj\n\
2 0 obj\n<< /Fields 3 0 R /SigFlags 3 >>\nendobj\n\
3 0 obj\n[7 0 R]\nendobj\n";
        let index = fragment_index(pdf);
        let catalog = object_body(pdf, 1).expect("catalog");
        match plan_field_list(&index, &catalog, 9) {
            FieldListTarget::Object(number, body) => {
                assert_eq!(number, 3, "the array object is the one to reissue");
                let text = String::from_utf8_lossy(&body).into_owned();
                assert!(text.contains("7 0 R") && text.contains("9 0 R"), "{text}");
            }
            FieldListTarget::Catalog(_) => panic!("must follow the indirect array"),
        }
    }

    /// A document with no form at all still gets one.
    #[test]
    fn a_document_without_a_form_gains_one() {
        let pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 4 0 R >>\nendobj\n";
        let index = fragment_index(pdf);
        let catalog = object_body(pdf, 1).expect("catalog");
        match plan_field_list(&index, &catalog, 9) {
            FieldListTarget::Catalog(body) => {
                assert!(String::from_utf8_lossy(&body).contains("/AcroForm << /Fields [9 0 R]"));
            }
            FieldListTarget::Object(..) => panic!("nothing to follow"),
        }
    }

    /// `1 0 obj` is a substring of `481 0 obj`, so a plain search for
    /// the header finds the wrong object -- and in a real file, where
    /// the low numbers are the catalog and page tree and the high ones
    /// are content streams, it reliably finds a stream. That is how a
    /// signature widget first ended up inside one.
    #[test]
    fn object_lookup_matches_whole_numbers_only() {
        let pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /Pages >>\nendobj\n\
481 0 obj\n<< /Length 10 >>\nendobj\n";
        let body = object_body(pdf, 1).expect("object 1");
        assert!(
            String::from_utf8_lossy(&body).contains("/Type /Pages"),
            "object 1 is the page tree, not the tail of 481: {}",
            String::from_utf8_lossy(&body)
        );
        let body = object_body(pdf, 481).expect("object 481");
        assert!(String::from_utf8_lossy(&body).contains("/Length 10"));
    }

    /// A content stream may contain text that looks like an object
    /// header. It is not live unless the xref table points at it.
    #[test]
    fn object_lookup_follows_xref_not_stream_text() {
        let signed = prepare(
            &pdf_with_stream_mentioning_fake_catalog(),
            &SignatureMetadata::default(),
            512,
        )
        .expect("prepares")
        .document;
        let text = String::from_utf8_lossy(&signed);
        let catalog = text
            .rfind("1 0 obj")
            .map(|at| &text[at..])
            .expect("catalog reissued");
        assert!(
            catalog.contains("/Pages 2 0 R"),
            "the live catalog keeps the real page tree: {}",
            &catalog[..catalog.len().min(240)]
        );
        let page = text
            .rfind("3 0 obj")
            .map(|at| &text[at..])
            .expect("real first page reissued");
        assert!(
            page.contains("/Annots [9 0 R]"),
            "the widget goes on the real first page: {}",
            &page[..page.len().min(240)]
        );
    }

    #[test]
    fn a_direct_dss_is_promoted_and_merged() {
        let updated =
            append_validation_store(&pdf_with_direct_dss(), &[b"new cert".to_vec()], &[], &[])
                .expect("validation store appends");
        let text = String::from_utf8_lossy(&updated);

        let catalog = text
            .rfind("1 0 obj")
            .map(|at| &text[at..])
            .expect("catalog reissued");
        assert!(
            catalog.contains("/DSS 10 0 R"),
            "the direct store is promoted to an indirect object: {}",
            &catalog[..catalog.len().min(240)]
        );

        let store = text
            .rfind("10 0 obj")
            .map(|at| &text[at..])
            .expect("new DSS object");
        assert!(
            store.contains("/Certs [8 0 R 9 0 R]"),
            "existing and new evidence are both retained: {}",
            &store[..store.len().min(240)]
        );
    }

    /// LT evidence is written after the signature and before the
    /// document timestamp. The archive timestamp must therefore cover
    /// the whole DSS revision, including evidence for both the signer
    /// and the TSA that supplied the signature timestamp.
    #[test]
    fn lt_evidence_precedes_and_is_covered_by_the_archive_timestamp() {
        /// DER tag for the structurally valid stand-in timestamp value.
        const DER_SEQUENCE_TAG: u8 = 0x30;
        /// Empty DER content length.
        const DER_EMPTY_LENGTH: u8 = 0x00;
        const SIGNER_CHAIN_CERTIFICATE: &[u8] = b"SIGNER-CHAIN-CERTIFICATE";
        const TSA_CERTIFICATE: &[u8] = b"TSA-CERTIFICATE";
        const SIGNER_STATUS: &[u8] = b"SIGNER-OCSP-RESPONSE";
        const TSA_STATUS: &[u8] = b"TSA-OCSP-RESPONSE";

        let certificate = Certificate::from_der(CERTIFICATE_DER).expect("certificate");
        let parameters = SignerParameters {
            certificate: &certificate,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            signing_time: None,
        };
        let material = ValidationMaterial {
            certificates: vec![SIGNER_CHAIN_CERTIFICATE.to_vec(), TSA_CERTIFICATE.to_vec()],
            ocsp_responses: vec![SIGNER_STATUS.to_vec(), TSA_STATUS.to_vec()],
            crls: Vec::new(),
        };
        let signature_timestamp = vec![DER_SEQUENCE_TAG, DER_EMPTY_LENGTH];
        let signed_lt = plan_document(
            Format::Pades,
            vec![DataObject {
                name: "document.pdf".to_owned(),
                mime_type: "application/pdf".to_owned(),
                content: minimal_pdf(),
            }],
            &parameters,
            &SignatureMetadata::default(),
        )
        .expect("PAdES plan")
        .finish(&parameters, &[b'S'; 384], &[signature_timestamp], &material)
        .expect("PAdES-LT document");

        let certificate_objects = validation_object_bodies(&signed_lt, b"Certs");
        let status_objects = validation_object_bodies(&signed_lt, b"OCSPs");
        let carries = |objects: &[Vec<u8>], expected: &[u8]| {
            objects.iter().any(|object| {
                object
                    .windows(expected.len())
                    .any(|window| window == expected)
            })
        };
        assert_eq!(certificate_objects.len(), 2);
        assert!(carries(&certificate_objects, SIGNER_CHAIN_CERTIFICATE));
        assert!(carries(&certificate_objects, TSA_CERTIFICATE));
        assert_eq!(status_objects.len(), 2);
        assert!(carries(&status_objects, SIGNER_STATUS));
        assert!(carries(&status_objects, TSA_STATUS));

        let dss_at = signed_lt
            .windows(b"/Type /DSS".len())
            .position(|window| window == b"/Type /DSS")
            .expect("DSS object");
        let dss_end = signed_lt[dss_at..]
            .windows(b"endobj".len())
            .position(|window| window == b"endobj")
            .map(|length| {
                dss_at
                    .saturating_add(length)
                    .saturating_add(b"endobj".len())
            })
            .expect("end of DSS object");

        let archive =
            prepare_document_timestamp(&signed_lt, 128).expect("archive timestamp placeholder");
        let [first_start, first_length, second_start, second_length] = archive.byte_range;
        assert_eq!(first_start, 0);
        assert!(
            dss_end <= first_length,
            "the archive ByteRange must cover the complete DSS object"
        );
        assert_eq!(
            second_start.saturating_add(second_length),
            archive.document.len(),
            "the archive ByteRange must run to the end of its revision"
        );
        assert_eq!(
            &archive.signed_octets()[dss_at..dss_end],
            &signed_lt[dss_at..dss_end],
            "the archive digest input must contain the DSS unchanged"
        );

        let timestamped = archive
            .finish(&[DER_SEQUENCE_TAG, DER_EMPTY_LENGTH])
            .expect("archive timestamp fits");
        let timestamp_at = timestamped
            .windows(b"/Type /DocTimeStamp".len())
            .position(|window| window == b"/Type /DocTimeStamp")
            .expect("document timestamp dictionary");
        assert!(dss_at < timestamp_at);
        assert!(
            timestamp_at >= signed_lt.len(),
            "the document timestamp must be a revision after the DSS"
        );
        assert_eq!(
            &timestamped[..signed_lt.len()],
            signed_lt.as_slice(),
            "adding the archive timestamp must not rewrite the LT revision"
        );
    }

    /// Each signature field has one fully-qualified name. Reusing a
    /// fixed name makes a later revision look like a second value for the
    /// first field, which validators report as an inconsistent signature
    /// dictionary.
    #[test]
    fn repeated_signatures_and_timestamps_have_unique_field_names() {
        let first_signature = prepare(&minimal_pdf(), &SignatureMetadata::default(), 32)
            .expect("first signature prepares");
        let once_signed = first_signature.finish(&[1]).expect("first signature fits");
        let second_signature = prepare(&once_signed, &SignatureMetadata::default(), 32)
            .expect("second signature prepares");
        let twice_signed = second_signature
            .finish(&[2])
            .expect("second signature fits");

        let first_timestamp =
            prepare_document_timestamp(&twice_signed, 32).expect("first timestamp prepares");
        let once_timestamped = first_timestamp.finish(&[3]).expect("first timestamp fits");
        let second_timestamp =
            prepare_document_timestamp(&once_timestamped, 32).expect("second timestamp prepares");
        let finished = second_timestamp
            .finish(&[4])
            .expect("second timestamp fits");
        let text = String::from_utf8_lossy(&finished);

        for name in ["Signature4", "Signature6", "Timestamp8", "Timestamp10"] {
            assert_eq!(
                text.matches(&format!("/T ({name})")).count(),
                1,
                "field name {name} must identify exactly one field"
            );
        }
        assert!(!text.contains("/T (Signature1)"));
        assert!(!text.contains("/T (Timestamp1)"));
    }

    /// Object numbers do not reserve field names. A form may already
    /// use the exact spelling derived from the next object number, so
    /// the writer must inspect the form rather than emit a duplicate
    /// fully-qualified name.
    #[test]
    fn a_preexisting_field_name_collision_is_disambiguated() {
        for (existing, timestamp) in [("Signature5", false), ("Timestamp5", true)] {
            let pdf = pdf_with_existing_field(existing);
            let placeholder = if timestamp {
                prepare_document_timestamp(&pdf, 32)
            } else {
                prepare(&pdf, &SignatureMetadata::default(), 32)
            }
            .expect("field-name collision is resolved");
            let text = String::from_utf8_lossy(&placeholder.document);
            assert_eq!(
                text.matches(&format!("/T ({existing})")).count(),
                1,
                "the existing field remains unique"
            );
            assert_eq!(
                text.matches(&format!("/T ({existing}-2)")).count(),
                1,
                "the new field receives a free name"
            );
        }
    }

    /// Individually valid partial names must not combine into an
    /// unbounded fully-qualified field name while walking `/Kids`.
    #[test]
    fn an_overlong_fully_qualified_field_name_is_refused() {
        let parent = "A".repeat(MAX_FIELD_NAME_BYTES);
        let objects = format!(
            "4 0 obj\n<< /T ({parent}) /Kids [5 0 R] >>\nendobj\n\
             5 0 obj\n<< /T (B) >>\nendobj\n"
        );
        let index = fragment_index(objects.as_bytes());
        let catalog = b"<< /AcroForm << /Fields [4 0 R] >> >>";

        assert_eq!(
            existing_field_names(&index, catalog),
            Err(PdfError::UnreadableForm)
        );
    }

    /// Existing category arrays can be indirect, names can be escaped,
    /// and category-looking bytes can live in comments, strings and
    /// nested dictionaries. Only the three top-level semantic keys are
    /// merged; VRI and extension entries remain byte-for-byte present.
    #[test]
    fn dss_merge_is_token_aware_deduplicated_and_retains_extensions() {
        let mut store = concat!(
            "<< /Type /DSS /C#65rts 5 0 R /CertsExtra [99 0 R]\n",
            "/OCSPs [7 0 R % ] /Certs 77 0 R\n",
            "] /CRLs [8 0 R]\n",
            "/VRI << /One << /Certs [6 0 R] >> >>\n",
            "/Future [(text ] /Certs 66 0 R) << /OCSPs [88 0 R] >>]\n",
            "/Raw (raw-X-byte) /Extension 10 0 R >>"
        )
        .as_bytes()
        .to_vec();
        let marker = b"raw-X-byte";
        let raw_at = store
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("raw marker")
            .saturating_add(b"raw-".len());
        store[raw_at] = 233;
        let original = pdf_with_indirect_dss_store(store);

        let updated = append_validation_store(
            &original,
            &[b"CERT-NEW".to_vec(), b"CERT-NEW".to_vec()],
            &[b"OCSP-NEW".to_vec()],
            &[],
        )
        .expect("validation store appends");
        let index = PdfIndex::parse(&updated).expect("updated PDF indexes");
        let latest_store = index.object_body(4).expect("DSS object is reissued");
        let text = String::from_utf8_lossy(&latest_store);

        assert!(
            text.contains("/C#65rts [6 0 R 11 0 R]"),
            "escaped Certs key is merged and duplicate references disappear: {text}"
        );
        assert!(
            text.contains("/OCSPs [7 0 R 12 0 R]"),
            "direct OCSP array is merged across a bracket-looking comment: {text}"
        );
        assert!(
            text.contains("/CRLs [8 0 R]"),
            "untouched CRL survives: {text}"
        );
        assert!(
            text.contains("/CertsExtra [99 0 R]"),
            "a prefixed name is not the Certs key: {text}"
        );
        assert!(
            text.contains("/VRI << /One << /Certs [6 0 R] >> >>"),
            "nested VRI is retained: {text}"
        );
        assert!(
            text.contains("/Future [(text ] /Certs 66 0 R) << /OCSPs [88 0 R] >>]"),
            "strings and nested values are retained: {text}"
        );
        assert!(text.contains("/Extension 10 0 R"));
        assert!(
            latest_store.contains(&233),
            "raw PDF string byte is retained"
        );
        assert_eq!(
            updated
                .windows(b"stream\nCERT-NEW".len())
                .filter(|window| *window == b"stream\nCERT-NEW")
                .count(),
            1,
            "duplicate input blobs produce one stream"
        );
    }

    #[test]
    fn an_unreadable_existing_dss_array_is_refused() {
        let original = pdf_with_indirect_dss_store(b"<< /Certs [6 0 R false] >>".to_vec());
        assert_eq!(
            append_validation_store(&original, &[b"new".to_vec()], &[], &[]),
            Err(PdfError::UnreadableValidationStore),
            "malformed earlier evidence must not be silently discarded"
        );
    }

    #[test]
    fn retained_pdf_values_have_a_nesting_limit() {
        let nested =
            |depth: usize| format!("<< /Future {}0{} >>", "[".repeat(depth), "]".repeat(depth));
        assert!(
            PdfDictionary::parse(nested(63).as_bytes()).is_ok(),
            "the root dictionary plus 63 arrays is the depth limit"
        );
        assert!(matches!(
            PdfDictionary::parse(nested(64).as_bytes()),
            Err(PdfError::UnreadableValidationStore)
        ));
    }

    #[test]
    fn refuses_what_is_not_a_pdf() {
        assert!(matches!(
            prepare(b"not a pdf", &SignatureMetadata::default(), 1024),
            Err(PdfError::NotAPdf)
        ));
    }

    #[test]
    fn byte_range_covers_everything_except_the_signature() {
        let placeholder = prepare(
            &minimal_pdf(),
            &SignatureMetadata::default(),
            DEFAULT_SIGNATURE_CAPACITY,
        )
        .expect("prepares");

        let [start1, len1, start2, len2] = placeholder.byte_range;
        let document = &placeholder.document;

        // The hole is exactly the hex string, brackets included.
        assert_eq!(start1, 0);
        assert_eq!(document[len1], b'<', "first span ends at the '<'");
        assert_eq!(document[start2 - 1], b'>', "second span starts after '>'");
        assert_eq!(
            start2 + len2,
            document.len(),
            "second span runs to end of file"
        );
        // Nothing outside the two spans except the hole itself.
        assert_eq!(
            document.len() - (len1 + len2),
            DEFAULT_SIGNATURE_CAPACITY * 2 + 2
        );
    }

    #[test]
    fn the_original_bytes_are_untouched() {
        let original = minimal_pdf();
        let placeholder =
            prepare(&original, &SignatureMetadata::default(), 4096).expect("prepares");
        assert_eq!(
            &placeholder.document[..original.len()],
            original.as_slice(),
            "an incremental update must not rewrite a single original byte"
        );
    }

    #[test]
    fn a_signature_that_does_not_fit_is_refused() {
        let placeholder =
            prepare(&minimal_pdf(), &SignatureMetadata::default(), 16).expect("prepares");
        assert_eq!(
            placeholder.finish(&[0_u8; 32]),
            Err(PdfError::SignatureTooLarge {
                needed: 32,
                capacity: 16
            })
        );
    }

    #[test]
    fn finishing_moves_nothing() {
        let placeholder =
            prepare(&minimal_pdf(), &SignatureMetadata::default(), 4096).expect("prepares");
        let before = placeholder.document.len();
        let contents_open = placeholder.contents_open;
        let signed = placeholder.finish(&[0xAB_u8; 100]).expect("fits");
        assert_eq!(signed.len(), before, "splicing must not resize the file");
        assert_eq!(signed[contents_open], b'<');
        assert_eq!(&signed[contents_open + 1..contents_open + 5], b"ABAB");
    }

    #[test]
    fn metadata_strings_are_escaped() {
        let metadata = SignatureMetadata {
            reason: Some("a (parenthesised) reason".to_owned()),
            ..SignatureMetadata::default()
        };
        let placeholder = prepare(&minimal_pdf(), &metadata, 1024).expect("prepares");
        let text = String::from_utf8_lossy(&placeholder.document);
        assert!(
            text.contains(r"/Reason (a \(parenthesised\) reason)"),
            "parentheses must be escaped or the dictionary ends early"
        );
    }
}

/// End-to-end against poppler's `pdfsig` and OpenSSL.
///
/// The structural tests prove the file is shaped the way this module
/// intends. Only an independent verifier can say whether the signature
/// is one: `pdfsig` walks `/ByteRange`, digests the spans itself, and
/// checks the CMS. If it agrees, the two halves of the circularity were
/// resolved consistently.
///
/// Ignored by default -- needs `openssl` and `pdfsig` (poppler). Run:
///
/// ```text
/// cargo test -p refineid-lib-core --lib sign::pades::pdfsig -- --ignored --nocapture
/// ```
#[cfg(test)]
mod pdfsig_interop {
    use crate::sign::validation::ValidationMaterial;
    use std::process::Command;

    use super::tests::minimal_pdf;
    use super::{
        DEFAULT_SIGNATURE_CAPACITY, SignatureInk, SignatureMetadata, VisibleSignature, prepare,
    };
    use crate::sign::cades::{
        DigestAlgorithm, Encapsulation, SignatureAlgorithm, SignerParameters, signed_attributes,
        signed_data,
    };
    use crate::x509::Certificate;

    /// Runs a command, returning stdout, failing loudly otherwise.
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
    #[ignore = "requires openssl and pdfsig (poppler)"]
    fn pdfsig_accepts_a_signed_document() {
        let dir = std::env::temp_dir().join("refineid-pades-interop");
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
                "/CN=ReFineID PAdES interop",
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

        // 1. Reserve the hole and learn what has to be signed.
        let ink = SignatureInk::from_rgba(2, 1, &[0, 0, 0, 255, 0, 0, 0, 255]);
        let metadata = SignatureMetadata {
            reason: Some("Declaration d'un moyen de cryptologie".to_owned()),
            location: Some("Helsinki".to_owned()),
            visible_signature: VisibleSignature::new("Test Signer", "12345678A", ink),
            ..SignatureMetadata::default()
        };
        let placeholder =
            prepare(&minimal_pdf(), &metadata, DEFAULT_SIGNATURE_CAPACITY).expect("prepares");

        // 2. Digest the byte ranges -- what the CAdES attests to.
        let parameters = SignerParameters {
            certificate: &certificate,
            digest_algorithm: DigestAlgorithm::Sha256,
            signature_algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
            signing_time: None,
        };
        let content_digest = placeholder.digest(DigestAlgorithm::Sha256);
        let attributes = signed_attributes(&parameters, &content_digest);

        // 3. The card's job, done here by OpenSSL over the same octets.
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

        // 4. Detached CAdES, spliced into the reserved hole.
        let cms = signed_data(
            &parameters,
            &attributes,
            &signature,
            Encapsulation::Detached,
            &[],
            &ValidationMaterial::default(),
            &[],
        );
        let signed_pdf = placeholder.finish(&cms).expect("cms fits");
        std::fs::write(path("signed.pdf"), &signed_pdf).expect("write pdf");

        // 5. The verdict from an implementation that is not ours.
        let report = String::from_utf8_lossy(&run("pdfsig", &[&path("signed.pdf")])).into_owned();
        println!("{report}");
        assert!(
            report.contains("Signature #1"),
            "pdfsig found no signature:\n{report}"
        );
        assert!(
            report.contains("Signature is Valid"),
            "pdfsig rejected the signature:\n{report}"
        );
    }
}
