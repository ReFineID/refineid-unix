//! Cross-reference streams and the object streams they index.
//!
//! A PDF 1.5 writer closes a revision with a *cross-reference stream*
//! (ISO 32000-1 sec.7.5.8): the section's entries are binary rows in a
//! stream object whose dictionary doubles as the trailer. The same
//! writers move small objects -- typically the catalog and the page
//! tree -- into *object streams* (sec.7.5.7), so reading such a file
//! means decoding both. Rows and object streams are `FlateDecode`
//! compressed, often behind a PNG row predictor (sec.7.4.4.4).
//!
//! Writing follows reading: a document whose newest section is a
//! stream is extended with a stream, because its readers have already
//! committed to following them. The rows this writer emits are left
//! unfiltered -- a handful of entries buys nothing from compression,
//! and unfiltered rows keep the update inspectable.

use super::{
    PdfDictionary, PdfError, XrefEntry, XrefLocation, XrefSection, dictionary_at, dictionary_usize,
    find_first, parse_u16, parse_u32, parse_usize, read_pdf_token, skip_pdf_whitespace,
};

/// Bound on any one decoded stream, so a hostile document cannot make
/// this reader allocate without limit.
const DECODED_LIMIT: usize = 1 << 26;

/// The predictor value meaning none was applied.
const NO_PREDICTOR: usize = 1;

/// The first PNG row predictor; lower values other than none are the
/// TIFF predictor, which this reader does not decode.
const PNG_PREDICTOR_FLOOR: usize = 10;

/// PNG row filter: the row as written.
const PNG_NONE: u8 = 0;

/// PNG row filter: each byte relative to its left neighbour.
const PNG_SUB: u8 = 1;

/// PNG row filter: each byte relative to the byte above.
const PNG_UP: u8 = 2;

/// PNG row filter: each byte relative to the mean of left and above.
const PNG_AVERAGE: u8 = 3;

/// PNG row filter: each byte relative to the Paeth prediction.
const PNG_PAETH: u8 = 4;

/// The sample shape this reader decodes: one colour of eight bits,
/// which is what cross-reference streams use.
const SUPPORTED_COLORS: usize = 1;

/// Bits per component in the supported shape.
const SUPPORTED_BITS: usize = 8;

/// Fields in one cross-reference stream entry: `/W` is three wide
/// (ISO 32000-1 sec.7.5.8.2).
const ENTRY_FIELDS: usize = 3;

/// Type code of an entry at a byte offset in the file
/// (ISO 32000-1 Table 18; type 0 is free).
const TYPE_DIRECT: usize = 1;

/// Type code of an entry inside an object stream.
const TYPE_COMPRESSED: usize = 2;

/// Tokens per pair in an object stream's leading table: an object
/// number and its offset relative to `/First`.
const PAIR_TOKENS: usize = 2;

/// Field widths this writer emits: one type byte, a four-byte offset,
/// a two-byte generation.
const WRITTEN_WIDTHS: [usize; ENTRY_FIELDS] = [1, 4, 2];

/// One stream object: its dictionary and its decoded payload.
struct StreamObject {
    /// The stream dictionary, as written.
    dictionary: Vec<u8>,
    /// The payload with its filter and predictor undone.
    payload: Vec<u8>,
}

/// One cross-reference stream section at `offset`.
pub(super) fn parse_stream_section(pdf: &[u8], offset: usize) -> Result<XrefSection, PdfError> {
    let object = parse_stream_object(pdf, offset)?;
    if find_first(&object.dictionary, b"/XRef").is_none() {
        return Err(PdfError::MissingTrailer);
    }
    let widths = integer_array(&object.dictionary, b"/W");
    if widths.len() != ENTRY_FIELDS {
        return Err(PdfError::MissingTrailer);
    }
    let size = dictionary_usize(&object.dictionary, b"/Size").ok_or(PdfError::MissingTrailer)?;
    let mut subsections = integer_array(&object.dictionary, b"/Index");
    if subsections.is_empty() {
        subsections = vec![0, size];
    }
    let entries = stream_entries(&object.payload, &widths, &subsections)?;
    Ok(XrefSection {
        trailer: object.dictionary,
        entries,
        is_stream: true,
    })
}

/// One compressed object's bytes: its slice of the object stream at
/// `container_offset` (ISO 32000-1 sec.7.5.7).
pub(super) fn compressed_body(
    pdf: &[u8],
    container_offset: usize,
    number: u32,
    position: u32,
) -> Option<Vec<u8>> {
    let object = parse_stream_object(pdf, container_offset).ok()?;
    let first = dictionary_usize(&object.dictionary, b"/First")?;
    let count = dictionary_usize(&object.dictionary, b"/N")?;
    let position = usize::try_from(position).ok()?;
    if position >= count || first > object.payload.len() {
        return None;
    }
    let header = object.payload.get(..first)?;
    let tokens: Vec<&[u8]> = header
        .split(u8::is_ascii_whitespace)
        .filter(|token| !token.is_empty())
        .collect();
    let declared = parse_u32(tokens.get(position.saturating_mul(PAIR_TOKENS)).copied()?)?;
    if declared != number {
        return None;
    }
    let offset_token = tokens
        .get(position.saturating_mul(PAIR_TOKENS).saturating_add(1))
        .copied()?;
    let start = first.saturating_add(parse_usize(offset_token)?);
    let next = position.saturating_add(1);
    let end = if next < count {
        let token = tokens
            .get(next.saturating_mul(PAIR_TOKENS).saturating_add(1))
            .copied()?;
        first.saturating_add(parse_usize(token)?)
    } else {
        object.payload.len()
    };
    object.payload.get(start..end).map(<[u8]>::to_vec)
}

/// Close the revision with a cross-reference stream: one subsection
/// per object, unfiltered rows, the stream object taking the number
/// just past the revision's other additions.
pub(super) fn push_stream_close(
    update: &mut Vec<u8>,
    xref_at: usize,
    offsets: &[(u32, usize)],
    size: u32,
    catalog_number: u32,
    previous_xref: usize,
    carried: &str,
) -> Result<(), PdfError> {
    let stream_number = size;
    let mut entries: Vec<(u32, usize)> = offsets.to_vec();
    entries.push((stream_number, xref_at));
    entries.sort_unstable_by_key(|(number, _)| *number);
    let mut index = String::new();
    let mut rows: Vec<u8> = Vec::new();
    for (number, offset) in &entries {
        let narrow = u32::try_from(*offset).map_err(|_ignored| PdfError::MissingStartXref)?;
        let _ignored =
            core::fmt::Write::write_fmt(&mut index, format_args!("{number} 1 "));
        rows.push(u8::try_from(TYPE_DIRECT).unwrap_or(1));
        rows.extend_from_slice(&narrow.to_be_bytes());
        rows.extend_from_slice(&0_u16.to_be_bytes());
    }
    let head = format!(
        "{stream_number} 0 obj\n<< /Type /XRef /Size {} /Root {catalog_number} 0 R \
         /Prev {previous_xref}{carried} /Index [ {index}] /W [{} {} {}] /Length {} \
         >>\nstream\n",
        stream_number.saturating_add(1),
        WRITTEN_WIDTHS[0],
        WRITTEN_WIDTHS[1],
        WRITTEN_WIDTHS[2],
        rows.len()
    );
    update.extend_from_slice(head.as_bytes());
    update.extend_from_slice(&rows);
    update.extend_from_slice(
        format!("\nendstream\nendobj\nstartxref\n{xref_at}\n%%EOF\n").as_bytes(),
    );
    Ok(())
}

/// The stream object at `offset`, its payload decoded.
fn parse_stream_object(pdf: &[u8], offset: usize) -> Result<StreamObject, PdfError> {
    let mut cursor = skip_pdf_whitespace(pdf, offset);
    let _number = parse_u32(read_pdf_token(pdf, &mut cursor).ok_or(PdfError::MissingTrailer)?)
        .ok_or(PdfError::MissingTrailer)?;
    let _generation = parse_u16(read_pdf_token(pdf, &mut cursor).ok_or(PdfError::MissingTrailer)?)
        .ok_or(PdfError::MissingTrailer)?;
    if read_pdf_token(pdf, &mut cursor).ok_or(PdfError::MissingTrailer)? != b"obj" {
        return Err(PdfError::MissingTrailer);
    }
    let (dictionary, after) = dictionary_at(pdf, cursor).ok_or(PdfError::MissingTrailer)?;
    let raw = raw_payload(pdf, after, &dictionary)?;
    let payload = decoded(&raw, &dictionary)?;
    Ok(StreamObject {
        dictionary,
        payload,
    })
}

/// The raw payload bytes between `stream` and `endstream`.
///
/// A direct `/Length` names the span exactly; without one the payload
/// runs to the `endstream` keyword, less the line ending the format
/// puts before it.
fn raw_payload(pdf: &[u8], after: usize, dictionary: &[u8]) -> Result<Vec<u8>, PdfError> {
    let keyword = find_first(pdf.get(after..).ok_or(PdfError::MissingTrailer)?, b"stream")
        .ok_or(PdfError::MissingTrailer)?;
    // The keyword is followed by CRLF or LF (ISO 32000-1 sec.7.3.8.1).
    let mut start = after.saturating_add(keyword).saturating_add(b"stream".len());
    if pdf.get(start) == Some(&b'\r') {
        start = start.saturating_add(1);
    }
    if pdf.get(start) == Some(&b'\n') {
        start = start.saturating_add(1);
    }
    if let Some(length) = direct_length(dictionary)
        && let Some(payload) = pdf.get(start..start.saturating_add(length))
    {
        return Ok(payload.to_vec());
    }
    let tail = pdf.get(start..).ok_or(PdfError::MissingTrailer)?;
    let keyword_at = find_first(tail, b"endstream").ok_or(PdfError::MissingTrailer)?;
    let mut end = keyword_at;
    if end > 0 && tail.get(end.saturating_sub(1)) == Some(&b'\n') {
        end = end.saturating_sub(1);
    }
    if end > 0 && tail.get(end.saturating_sub(1)) == Some(&b'\r') {
        end = end.saturating_sub(1);
    }
    Ok(tail[..end].to_vec())
}

/// The direct `/Length` value, or `None` when absent or indirect.
fn direct_length(dictionary: &[u8]) -> Option<usize> {
    let parsed = PdfDictionary::parse(dictionary).ok()?;
    let entry = parsed.entry(b"Length").ok()??;
    parse_usize(trim(&dictionary[entry.value.clone()]))
}

/// The payload with its filter chain and predictor undone.
fn decoded(raw: &[u8], dictionary: &[u8]) -> Result<Vec<u8>, PdfError> {
    let inflated = if flate_only(dictionary)? {
        miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(raw, DECODED_LIMIT)
            .map_err(|_ignored| PdfError::MissingTrailer)?
    } else {
        raw.to_vec()
    };
    unpredicted(inflated, dictionary)
}

/// Whether the filter chain is exactly `FlateDecode`; absent means
/// the payload is raw, anything else is refused.
fn flate_only(dictionary: &[u8]) -> Result<bool, PdfError> {
    let parsed = PdfDictionary::parse(dictionary).map_err(|_ignored| PdfError::MissingTrailer)?;
    let Some(entry) = parsed
        .entry(b"Filter")
        .map_err(|_ignored| PdfError::MissingTrailer)?
    else {
        return Ok(false);
    };
    let mut name = trim(&dictionary[entry.value.clone()]);
    if let Some(inner) = name
        .strip_prefix(b"[")
        .and_then(|inner| inner.strip_suffix(b"]"))
    {
        name = trim(inner);
    }
    if name == b"/FlateDecode" {
        Ok(true)
    } else {
        Err(PdfError::UnsupportedCrossReferenceStream)
    }
}

/// The payload with the predictor `/DecodeParms` names undone
/// (ISO 32000-1 sec.7.4.4.4).
fn unpredicted(data: Vec<u8>, dictionary: &[u8]) -> Result<Vec<u8>, PdfError> {
    let Some(parameters) = decode_parameters(dictionary)? else {
        return Ok(data);
    };
    let predictor = dictionary_usize(&parameters, b"/Predictor").unwrap_or(NO_PREDICTOR);
    if predictor == NO_PREDICTOR {
        return Ok(data);
    }
    if predictor < PNG_PREDICTOR_FLOOR
        || dictionary_usize(&parameters, b"/Colors").unwrap_or(SUPPORTED_COLORS)
            != SUPPORTED_COLORS
        || dictionary_usize(&parameters, b"/BitsPerComponent").unwrap_or(SUPPORTED_BITS)
            != SUPPORTED_BITS
    {
        return Err(PdfError::UnsupportedCrossReferenceStream);
    }
    let columns = dictionary_usize(&parameters, b"/Columns").unwrap_or(1);
    png_unfiltered(&data, columns)
}

/// The direct `/DecodeParms` dictionary, under either spelling.
fn decode_parameters(dictionary: &[u8]) -> Result<Option<Vec<u8>>, PdfError> {
    let parsed = PdfDictionary::parse(dictionary).map_err(|_ignored| PdfError::MissingTrailer)?;
    let entry = match parsed
        .entry(b"DecodeParms")
        .map_err(|_ignored| PdfError::MissingTrailer)?
    {
        Some(entry) => Some(entry),
        None => parsed
            .entry(b"DP")
            .map_err(|_ignored| PdfError::MissingTrailer)?,
    };
    let Some(entry) = entry else { return Ok(None) };
    let value = trim(&dictionary[entry.value.clone()]);
    if value.starts_with(b"<<") {
        return Ok(Some(value.to_vec()));
    }
    // An indirect or array-shaped parameter set is not a shape this
    // reader follows.
    Err(PdfError::UnsupportedCrossReferenceStream)
}

/// The rows with their per-row PNG filters undone, one-byte samples.
fn png_unfiltered(data: &[u8], columns: usize) -> Result<Vec<u8>, PdfError> {
    let stride = columns.saturating_add(1);
    if columns == 0 || !data.len().is_multiple_of(stride) {
        return Err(PdfError::MissingTrailer);
    }
    let mut out = Vec::with_capacity(data.len().saturating_sub(data.len() / stride));
    let mut above = vec![0_u8; columns];
    for row in data.chunks_exact(stride) {
        let filter = row[0];
        let mut decoded = vec![0_u8; columns];
        for column in 0..columns {
            let raw = row[column.saturating_add(1)];
            let left = if column > 0 { decoded[column - 1] } else { 0 };
            let upper = above[column];
            let upper_left = if column > 0 { above[column - 1] } else { 0 };
            let prediction = match filter {
                PNG_NONE => 0,
                PNG_SUB => left,
                PNG_UP => upper,
                PNG_AVERAGE => average(left, upper),
                PNG_PAETH => paeth(left, upper, upper_left),
                _ => return Err(PdfError::MissingTrailer),
            };
            decoded[column] = raw.wrapping_add(prediction);
        }
        out.extend_from_slice(&decoded);
        above = decoded;
    }
    Ok(out)
}

/// The mean of the left and upper neighbours, rounded down.
fn average(left: u8, upper: u8) -> u8 {
    let sum = u16::from(left) + u16::from(upper);
    u8::try_from(sum / 2).unwrap_or(u8::MAX)
}

/// The Paeth prediction: whichever neighbour is closest to the
/// initial estimate `left + upper - upper_left`.
fn paeth(left: u8, upper: u8, upper_left: u8) -> u8 {
    let estimate = i32::from(left) + i32::from(upper) - i32::from(upper_left);
    let distance_left = (estimate - i32::from(left)).abs();
    let distance_upper = (estimate - i32::from(upper)).abs();
    let distance_upper_left = (estimate - i32::from(upper_left)).abs();
    if distance_left <= distance_upper && distance_left <= distance_upper_left {
        left
    } else if distance_upper <= distance_upper_left {
        upper
    } else {
        upper_left
    }
}

/// The decoded entry rows as section entries (ISO 32000-1 sec.7.5.8.3).
fn stream_entries(
    payload: &[u8],
    widths: &[usize],
    subsections: &[usize],
) -> Result<Vec<XrefEntry>, PdfError> {
    let row_length = widths.iter().sum::<usize>();
    if row_length == 0 || !subsections.len().is_multiple_of(2) {
        return Err(PdfError::MissingTrailer);
    }
    let mut entries = Vec::new();
    let mut cursor = 0_usize;
    for pair in subsections.chunks_exact(2) {
        let first = pair[0];
        for entry in 0..pair[1] {
            let row = payload
                .get(cursor..cursor.saturating_add(row_length))
                .ok_or(PdfError::MissingTrailer)?;
            cursor = cursor.saturating_add(row_length);
            let number = u32::try_from(first.saturating_add(entry))
                .map_err(|_ignored| PdfError::MissingTrailer)?;
            entries.push(entry_from_row(number, row, widths)?);
        }
    }
    Ok(entries)
}

/// One entry from one row's big-endian fields.
///
/// A zero-width type field defaults to a direct entry; other absent
/// fields default to zero. Free, and any type this reader does not
/// know, claims the number with no location -- a reference to such an
/// object is a reference to null.
fn entry_from_row(number: u32, row: &[u8], widths: &[usize]) -> Result<XrefEntry, PdfError> {
    let mut fields = [0_usize; ENTRY_FIELDS];
    let mut at = 0_usize;
    for (position, width) in widths.iter().enumerate() {
        let mut value = 0_usize;
        for _ in 0..*width {
            value = value
                .checked_mul(256)
                .and_then(|wide| wide.checked_add(usize::from(row[at])))
                .ok_or(PdfError::MissingTrailer)?;
            at = at.saturating_add(1);
        }
        if position == 0 && *width == 0 {
            value = TYPE_DIRECT;
        }
        fields[position] = value;
    }
    let location = match fields[0] {
        TYPE_DIRECT => XrefLocation::Direct { offset: fields[1] },
        TYPE_COMPRESSED => XrefLocation::Compressed {
            container: u32::try_from(fields[1]).map_err(|_ignored| PdfError::MissingTrailer)?,
            position: u32::try_from(fields[2]).map_err(|_ignored| PdfError::MissingTrailer)?,
        },
        _ => XrefLocation::Free,
    };
    Ok(XrefEntry {
        number,
        generation: 0,
        location,
    })
}

/// The integer array under `key`, empty when absent or malformed.
fn integer_array(dictionary: &[u8], key: &[u8]) -> Vec<usize> {
    let Some(at) = find_first(dictionary, key) else {
        return Vec::new();
    };
    let rest = &dictionary[at.saturating_add(key.len())..];
    let Some(open) = rest.iter().position(|byte| !byte.is_ascii_whitespace()) else {
        return Vec::new();
    };
    if rest.get(open) != Some(&b'[') {
        return Vec::new();
    }
    let body = &rest[open.saturating_add(1)..];
    let Some(close) = find_first(body, b"]") else {
        return Vec::new();
    };
    let mut values = Vec::new();
    for token in body[..close]
        .split(u8::is_ascii_whitespace)
        .filter(|token| !token.is_empty())
    {
        let Some(value) = parse_usize(token) else {
            return Vec::new();
        };
        values.push(value);
    }
    values
}

/// `bytes` without leading and trailing PDF whitespace.
fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |found| found.saturating_add(1));
    &bytes[start..end]
}
