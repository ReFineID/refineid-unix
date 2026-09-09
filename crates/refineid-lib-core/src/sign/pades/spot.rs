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

//! Finds somewhere on the signature page the mark can sit without
//! covering anything.
//!
//! The page's content streams are interpreted just far enough to know
//! where ink lands: paths and text are reduced to conservative
//! bounding boxes, images and forms to their placed extents, and every
//! existing annotation counts as occupied, so a mark left by an
//! earlier signer is avoided without being a special case.
//!
//! The estimate errs toward occupied, never toward free. Text width is
//! taken above any common font's, colour spaces that cannot be read
//! are treated as ink, and anything this module cannot interpret -- an
//! unknown filter, a shading, an inline image, a malformed stream --
//! abandons the search entirely rather than mistaking unread content
//! for blank paper. The caller then falls back to the fixed corner
//! placement, so the search can only ever do better than not having
//! one.
//!
//! Within a size, the bottom-right corner is where a signature
//! conventionally sits: the search starts there, steps left along the
//! foot of the page, and rises a row to sweep right to left again only
//! once a whole row is occupied. Shrinking is the last thing given up,
//! not the first, because a mark sitting a little further in is worth
//! more than one small enough for the very corner.

use super::{
    PdfDictionary, PdfIndex, PdfObjectReference, PdfValueParser, complete_object_reference,
    complete_reference_array, parse_usize, validation_references,
};

/// How far the search moves between candidate positions, in points.
const SEARCH_STEP: f64 = 6.0;

/// Clear space demanded around the mark, in points.
const CLEARANCE: f64 = 4.0;

/// The sizes tried, as shares of the mark's full size, largest first.
///
/// The mark carries a name and an identifier, and below the smallest
/// share here they stop being readable on paper - a mark nobody can
/// read is worse than one sitting further from the corner.
const SHARES: [f64; 5] = [1.0, 0.9, 0.8, 0.7, 0.6];

/// How light a fill may be and still count as ink, as a luminance
/// share, so that a page-sized white background does not occupy the
/// whole page.
const INK_LUMINANCE: f64 = 0.95;

/// Text width allowed per shown byte, in em - above any common font's
/// average, so an estimated line never ends before the printed one.
const TEXT_EM_PER_BYTE: f64 = 0.6;

/// Decoded content larger than this is not a page, and inflating it
/// unchecked would hand the input control of memory.
const DECODED_LIMIT: usize = 1 << 26;

/// Interpreting more operators than this is not a page either.
const OPERATOR_LIMIT: usize = 200_000;

/// More occupied regions than this and the search would cost more than
/// it is worth; give up and let the corner fallback answer.
const REGION_LIMIT: usize = 4_096;

/// Nesting bound for the graphics-state and operand structures.
const STACK_LIMIT: usize = 64;

/// Where a mark of `natural_side` points fits free of content, in page
/// coordinates, or `None` when the page has no room at any accepted
/// size or its content cannot be read conservatively.
pub(super) fn free(
    index: &PdfIndex<'_>,
    page: &[u8],
    page_box: [f64; 4],
    natural_side: f64,
) -> Option<[f64; 4]> {
    let dictionary = PdfDictionary::parse(page).ok()?;
    let mut occupied = annotation_boxes(index, &dictionary, page)?;
    let content = content_bytes(index, &dictionary, page)?;
    let mut interpreter = Interpreter::new(index, page);
    occupied.extend(interpreter.run(&content)?);
    search(page_box, &occupied, natural_side)
}

/// The same right-to-left, bottom-to-top sweep the desktop platforms
/// use, over boxes instead of rendered pixels.
#[expect(
    clippy::while_float,
    reason = "the sweep walks page coordinates in fixed steps and both bounds are finite"
)]
fn search(page_box: [f64; 4], occupied: &[[f64; 4]], natural_side: f64) -> Option<[f64; 4]> {
    let [left, bottom, right, top] = page_box;
    let reach = natural_side / 2.0;
    for share in SHARES {
        // Each size keeps its own margin to the page's edge, so a
        // shrunken mark sits in the corner rather than floating where
        // a larger one would have.
        let room = reach.mul_add(share, CLEARANCE);
        let mut centre_y = bottom + room;
        while centre_y + room <= top {
            let mut centre_x = right - room;
            while centre_x - room >= left {
                let candidate = [
                    centre_x - room,
                    centre_y - room,
                    centre_x + room,
                    centre_y + room,
                ];
                if occupied
                    .iter()
                    .all(|region| !intersects(*region, candidate))
                {
                    let half = reach * share;
                    return Some([
                        centre_x - half,
                        centre_y - half,
                        centre_x + half,
                        centre_y + half,
                    ]);
                }
                centre_x -= SEARCH_STEP;
            }
            centre_y += SEARCH_STEP;
        }
    }
    None
}

/// Whether two normalised boxes share any interior.
fn intersects(a: [f64; 4], b: [f64; 4]) -> bool {
    a[0] < b[2] && a[2] > b[0] && a[1] < b[3] && a[3] > b[1]
}

/// Every existing annotation's `/Rect`, or `None` when one cannot be
/// read - an annotation whose place is unknown could be anywhere.
fn annotation_boxes(
    index: &PdfIndex<'_>,
    dictionary: &PdfDictionary,
    page: &[u8],
) -> Option<Vec<[f64; 4]>> {
    let Some(entry) = dictionary.entry(b"Annots").ok()? else {
        return Some(Vec::new());
    };
    let references = validation_references(index, &page[entry.value.clone()]).ok()?;
    let mut boxes = Vec::new();
    for reference in references {
        let body = index.object_body_reference(reference)?;
        let annotation = PdfDictionary::parse(&body).ok()?;
        let rectangle = annotation.entry(b"Rect").ok()??;
        let numbers = numbers_in(&body[rectangle.value.clone()])?;
        let &[x0, y0, x1, y1] = numbers.as_slice() else {
            return None;
        };
        boxes.push([x0.min(x1), y0.min(y1), x0.max(x1), y0.max(y1)]);
    }
    Some(boxes)
}

/// The page's decoded content, in stream order, or `None` when any
/// stream cannot be read.
///
/// An absent `/Contents` is a blank page, which reads as no content
/// rather than as a failure.
fn content_bytes(index: &PdfIndex<'_>, dictionary: &PdfDictionary, page: &[u8]) -> Option<Vec<u8>> {
    let Some(entry) = dictionary.entry(b"Contents").ok()? else {
        return Some(Vec::new());
    };
    let mut content = Vec::new();
    for reference in content_references(index, &page[entry.value.clone()])? {
        content.extend_from_slice(&stream_data(index, reference)?);
        // Streams split mid-token must not join into one token.
        content.push(b'\n');
    }
    Some(content)
}

/// `/Contents` as references: a direct array, one stream reference, or
/// a reference to an array of streams.
fn content_references(index: &PdfIndex<'_>, value: &[u8]) -> Option<Vec<PdfObjectReference>> {
    let trimmed = trim(value);
    if trimmed.starts_with(b"[") {
        return complete_reference_array(trimmed).ok();
    }
    let reference = complete_object_reference(trimmed).ok()??;
    let body = index.object_body_reference(reference)?;
    let body = trim(&body);
    if body.starts_with(b"[") {
        complete_reference_array(body).ok()
    } else {
        Some(vec![reference])
    }
}

/// One stream object's decoded data, or `None` when its length,
/// filter, or framing cannot be read.
fn stream_data(index: &PdfIndex<'_>, reference: PdfObjectReference) -> Option<Vec<u8>> {
    let body = index.object_body_reference(reference)?;
    let mut parser = PdfValueParser::new(&body);
    parser.skip_trivia();
    let dictionary = parser.dictionary(1).ok()?;
    let mut cursor = parser.offset;
    while body.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor = cursor.saturating_add(1);
    }
    if !body.get(cursor..)?.starts_with(b"stream") {
        return None;
    }
    cursor = cursor.saturating_add(b"stream".len());
    if body.get(cursor) == Some(&b'\r') {
        cursor = cursor.saturating_add(1);
    }
    if body.get(cursor) == Some(&b'\n') {
        cursor = cursor.saturating_add(1);
    }
    let length = stream_length(index, &body, &dictionary)?;
    let data = body.get(cursor..cursor.checked_add(length)?)?;

    // Predictors change what inflation yields; none are expected on a
    // page and none are interpreted.
    if dictionary.entry(b"DecodeParms").ok()?.is_some() || dictionary.entry(b"DP").ok()?.is_some() {
        return None;
    }
    let Some(filter) = dictionary.entry(b"Filter").ok()? else {
        return Some(data.to_vec());
    };
    let mut filter_name = trim(&body[filter.value.clone()]);
    if let Some(inner) = filter_name
        .strip_prefix(b"[")
        .and_then(|inner| inner.strip_suffix(b"]"))
    {
        filter_name = trim(inner);
    }
    if filter_name == b"/FlateDecode" {
        miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(data, DECODED_LIMIT).ok()
    } else {
        None
    }
}

/// A stream's `/Length`, directly or through one reference.
fn stream_length(index: &PdfIndex<'_>, body: &[u8], dictionary: &PdfDictionary) -> Option<usize> {
    let entry = dictionary.entry(b"Length").ok()??;
    let value = trim(&body[entry.value.clone()]);
    if let Some(length) = parse_usize(value) {
        return Some(length);
    }
    let reference = complete_object_reference(value).ok()??;
    let resolved = index.object_body_reference(reference)?;
    parse_usize(trim(&resolved))
}

/// `bytes` without leading or trailing PDF whitespace.
fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |at| at.saturating_add(1));
    &bytes[start..end]
}

/// Whitespace-separated numbers, with any surrounding brackets.
fn numbers_in(value: &[u8]) -> Option<Vec<f64>> {
    let mut inner = trim(value);
    if let Some(stripped) = inner
        .strip_prefix(b"[")
        .and_then(|stripped| stripped.strip_suffix(b"]"))
    {
        inner = stripped;
    }
    let text = core::str::from_utf8(inner).ok()?;
    let mut numbers = Vec::new();
    for token in text.split_ascii_whitespace() {
        let number: f64 = token.parse().ok()?;
        if !number.is_finite() {
            return None;
        }
        numbers.push(number);
    }
    Some(numbers)
}

/// A PDF transformation matrix `[a b c d e f]`.
#[derive(Clone, Copy)]
struct Matrix {
    a: f64,
    b: f64,
    c: f64,
    d: f64,
    e: f64,
    f: f64,
}

impl Matrix {
    const IDENTITY: Self = Self {
        a: 1.0,
        b: 0.0,
        c: 0.0,
        d: 1.0,
        e: 0.0,
        f: 0.0,
    };

    const fn translation(tx: f64, ty: f64) -> Self {
        Self {
            a: 1.0,
            b: 0.0,
            c: 0.0,
            d: 1.0,
            e: tx,
            f: ty,
        }
    }

    const fn from_numbers(numbers: [f64; 6]) -> Self {
        Self {
            a: numbers[0],
            b: numbers[1],
            c: numbers[2],
            d: numbers[3],
            e: numbers[4],
            f: numbers[5],
        }
    }

    /// The matrix applying `self` first and `after` second.
    fn then(self, after: Self) -> Self {
        Self {
            a: self.a.mul_add(after.a, self.b * after.c),
            b: self.a.mul_add(after.b, self.b * after.d),
            c: self.c.mul_add(after.a, self.d * after.c),
            d: self.c.mul_add(after.b, self.d * after.d),
            e: self.e.mul_add(after.a, self.f * after.c) + after.e,
            f: self.e.mul_add(after.b, self.f * after.d) + after.f,
        }
    }

    fn apply(self, x: f64, y: f64) -> (f64, f64) {
        (
            self.a.mul_add(x, self.c * y) + self.e,
            self.b.mul_add(x, self.d * y) + self.f,
        )
    }
}

/// One content-stream operand, reduced to what occupancy needs.
enum Operand {
    Number(f64),
    Name(Vec<u8>),
    /// A shown string, reduced to its byte count.
    Text(usize),
    Array(Vec<Self>),
    /// A dictionary or brace, carried only so operand counts line up.
    Opaque,
}

/// Interprets a page's content just far enough to bound its ink.
struct Interpreter<'a> {
    index: &'a PdfIndex<'a>,
    page: &'a [u8],
    /// Page resources, resolved on the first `Do` and kept.
    resources: Option<Vec<u8>>,
    resources_resolved: bool,
    matrix: Matrix,
    saved: Vec<Matrix>,
    /// Device-space bound of the path being built, if any.
    path: Option<[f64; 4]>,
    line_width: f64,
    fill_is_ink: bool,
    stroke_is_ink: bool,
    text_matrix: Matrix,
    line_matrix: Matrix,
    font_size: f64,
    leading: f64,
    occupied: Vec<[f64; 4]>,
}

impl<'a> Interpreter<'a> {
    const fn new(index: &'a PdfIndex<'a>, page: &'a [u8]) -> Self {
        Self {
            index,
            page,
            resources: None,
            resources_resolved: false,
            matrix: Matrix::IDENTITY,
            saved: Vec::new(),
            path: None,
            line_width: 1.0,
            fill_is_ink: true,
            stroke_is_ink: true,
            text_matrix: Matrix::IDENTITY,
            line_matrix: Matrix::IDENTITY,
            font_size: 0.0,
            leading: 0.0,
            occupied: Vec::new(),
        }
    }

    /// Every box the content may have inked, or `None` when the
    /// content cannot be interpreted conservatively.
    fn run(&mut self, content: &[u8]) -> Option<Vec<[f64; 4]>> {
        let mut tokens = Tokens {
            bytes: content,
            offset: 0,
        };
        let mut operands: Vec<Operand> = Vec::new();
        for _ in 0..OPERATOR_LIMIT {
            match tokens.next()? {
                Token::End => return Some(core::mem::take(&mut self.occupied)),
                Token::Operand(operand) => {
                    if operands.len() >= STACK_LIMIT {
                        return None;
                    }
                    operands.push(operand);
                }
                Token::Operator(name) => {
                    self.operate(&name, &operands)?;
                    operands.clear();
                }
            }
            if self.occupied.len() > REGION_LIMIT {
                return None;
            }
        }
        None
    }

    fn operate(&mut self, name: &[u8], operands: &[Operand]) -> Option<()> {
        match name {
            b"q" => {
                if self.saved.len() >= STACK_LIMIT {
                    return None;
                }
                self.saved.push(self.matrix);
            }
            b"Q" => self.matrix = self.saved.pop()?,
            b"cm" => {
                self.matrix = Matrix::from_numbers(numbers::<6>(operands)?).then(self.matrix);
            }
            b"w" => self.line_width = numbers::<1>(operands)?[0].abs(),
            b"g" => self.fill_is_ink = numbers::<1>(operands)?[0] < INK_LUMINANCE,
            b"G" => self.stroke_is_ink = numbers::<1>(operands)?[0] < INK_LUMINANCE,
            b"rg" => self.fill_is_ink = rgb_is_ink(numbers::<3>(operands)?),
            b"RG" => self.stroke_is_ink = rgb_is_ink(numbers::<3>(operands)?),
            b"k" => self.fill_is_ink = cmyk_is_ink(numbers::<4>(operands)?),
            b"K" => self.stroke_is_ink = cmyk_is_ink(numbers::<4>(operands)?),
            // A colour this module cannot read must be assumed dark.
            b"cs" | b"sc" | b"scn" => self.fill_is_ink = true,
            b"CS" | b"SC" | b"SCN" => self.stroke_is_ink = true,
            b"m" | b"l" => {
                let [x, y] = numbers::<2>(operands)?;
                self.extend_path(&[[x, y]]);
            }
            b"c" => {
                let [x1, y1, x2, y2, x3, y3] = numbers::<6>(operands)?;
                self.extend_path(&[[x1, y1], [x2, y2], [x3, y3]]);
            }
            b"v" | b"y" => {
                let [x1, y1, x2, y2] = numbers::<4>(operands)?;
                self.extend_path(&[[x1, y1], [x2, y2]]);
            }
            b"re" => {
                let [x, y, width, height] = numbers::<4>(operands)?;
                self.extend_path(&[
                    [x, y],
                    [x + width, y],
                    [x, y + height],
                    [x + width, y + height],
                ]);
            }
            b"n" => self.path = None,
            b"f" | b"F" | b"f*" => self.paint(self.fill_is_ink, 0.0),
            b"S" | b"s" => self.paint(self.stroke_is_ink, self.line_width),
            b"B" | b"B*" | b"b" | b"b*" => {
                self.paint(self.fill_is_ink || self.stroke_is_ink, self.line_width);
            }
            b"BT" => {
                self.text_matrix = Matrix::IDENTITY;
                self.line_matrix = Matrix::IDENTITY;
            }
            b"TL" => self.leading = numbers::<1>(operands)?[0],
            b"Tf" => self.font_size = numbers::<1>(operands)?[0].abs(),
            b"Tm" => {
                self.line_matrix = Matrix::from_numbers(numbers::<6>(operands)?);
                self.text_matrix = self.line_matrix;
            }
            b"Td" => {
                let [tx, ty] = numbers::<2>(operands)?;
                self.next_line(tx, ty);
            }
            b"TD" => {
                let [tx, ty] = numbers::<2>(operands)?;
                self.leading = -ty;
                self.next_line(tx, ty);
            }
            b"T*" => self.next_line(0.0, -self.leading),
            b"Tj" => self.show_text(last_text(operands)?),
            b"'" | b"\"" => {
                self.next_line(0.0, -self.leading);
                self.show_text(last_text(operands)?);
            }
            b"TJ" => {
                let Some(Operand::Array(elements)) = operands.last() else {
                    return None;
                };
                let bytes = elements
                    .iter()
                    .map(|element| match element {
                        Operand::Text(count) => *count,
                        _ => 0,
                    })
                    .sum();
                self.show_text(bytes);
            }
            b"Do" => {
                let Some(Operand::Name(xobject)) = operands.last() else {
                    return None;
                };
                let placed = self.xobject_box(&xobject.clone())?;
                self.occupied.push(placed);
            }
            b"h" | b"W" | b"W*" | b"ET" | b"Tc" | b"Tw" | b"Tz" | b"Tr" | b"Ts" | b"gs" | b"ri"
            | b"i" | b"j" | b"J" | b"M" | b"d" | b"d0" | b"d1" | b"BMC" | b"BDC" | b"EMC"
            | b"MP" | b"DP" | b"BX" | b"EX" => {}
            // Shadings and inline images paint where only rendering
            // can say; reading past them would mistake ink for paper.
            _ => return None,
        }
        Some(())
    }

    /// Widen the pending path bound by these user-space points.
    fn extend_path(&mut self, points: &[[f64; 2]]) {
        for &[x, y] in points {
            let (device_x, device_y) = self.matrix.apply(x, y);
            let bound = self
                .path
                .get_or_insert([device_x, device_y, device_x, device_y]);
            bound[0] = bound[0].min(device_x);
            bound[1] = bound[1].min(device_y);
            bound[2] = bound[2].max(device_x);
            bound[3] = bound[3].max(device_y);
        }
    }

    /// Commit the pending path as occupied, when it lands ink.
    fn paint(&mut self, is_ink: bool, pad: f64) {
        if let Some([x0, y0, x1, y1]) = self.path.take()
            && is_ink
        {
            self.occupied.push([x0 - pad, y0 - pad, x1 + pad, y1 + pad]);
        }
    }

    /// Move the text and line matrices to the next line's start.
    fn next_line(&mut self, tx: f64, ty: f64) {
        self.line_matrix = Matrix::translation(tx, ty).then(self.line_matrix);
        self.text_matrix = self.line_matrix;
    }

    /// Commit an over-wide bound for `bytes` shown glyphs and advance.
    fn show_text(&mut self, bytes: usize) {
        let count = u32::try_from(bytes.min(1 << 20)).map_or(f64::INFINITY, f64::from);
        let width = TEXT_EM_PER_BYTE * self.font_size * count;
        if width > 0.0 && self.fill_is_ink {
            let placed = self.text_matrix.then(self.matrix);
            let corners = [
                (0.0, -0.25 * self.font_size),
                (width, -0.25 * self.font_size),
                (0.0, self.font_size),
                (width, self.font_size),
            ];
            let mut bound: Option<[f64; 4]> = None;
            for (x, y) in corners {
                let (device_x, device_y) = placed.apply(x, y);
                let bound = bound.get_or_insert([device_x, device_y, device_x, device_y]);
                bound[0] = bound[0].min(device_x);
                bound[1] = bound[1].min(device_y);
                bound[2] = bound[2].max(device_x);
                bound[3] = bound[3].max(device_y);
            }
            if let Some(bound) = bound {
                self.occupied.push(bound);
            }
        }
        self.text_matrix = Matrix::translation(width, 0.0).then(self.text_matrix);
    }

    /// The device-space extent of a placed image or form, or `None`
    /// when the object cannot be found or read.
    fn xobject_box(&mut self, name: &[u8]) -> Option<[f64; 4]> {
        if !self.resources_resolved {
            self.resources = inherited_resources(self.index, self.page);
            self.resources_resolved = true;
        }
        let resources = self.resources.as_deref()?;
        let body = xobject_body(self.index, resources, name)?;
        let mut parser = PdfValueParser::new(&body);
        parser.skip_trivia();
        let dictionary = parser.dictionary(1).ok()?;
        let subtype_entry = dictionary.entry(b"Subtype").ok()??;
        let subtype = trim(&body[subtype_entry.value.clone()]);
        let (corners_box, placement) = if subtype == b"/Image" {
            // An image is drawn into the unit square.
            ([0.0, 0.0, 1.0, 1.0], self.matrix)
        } else if subtype == b"/Form" {
            let bbox_entry = dictionary.entry(b"BBox").ok()??;
            let numbers = numbers_in(&body[bbox_entry.value.clone()])?;
            let &[x0, y0, x1, y1] = numbers.as_slice() else {
                return None;
            };
            let form_matrix = match dictionary.entry(b"Matrix").ok()? {
                Some(entry) => {
                    let numbers = numbers_in(&body[entry.value.clone()])?;
                    let entries: [f64; 6] = numbers.as_slice().try_into().ok()?;
                    Matrix::from_numbers(entries)
                }
                None => Matrix::IDENTITY,
            };
            ([x0, y0, x1, y1], form_matrix.then(self.matrix))
        } else {
            return None;
        };
        let [x0, y0, x1, y1] = corners_box;
        let mut bound: Option<[f64; 4]> = None;
        for (x, y) in [(x0, y0), (x1, y0), (x0, y1), (x1, y1)] {
            let (device_x, device_y) = placement.apply(x, y);
            let bound = bound.get_or_insert([device_x, device_y, device_x, device_y]);
            bound[0] = bound[0].min(device_x);
            bound[1] = bound[1].min(device_y);
            bound[2] = bound[2].max(device_x);
            bound[3] = bound[3].max(device_y);
        }
        bound
    }
}

/// Whether an RGB fill is dark enough to read as ink.
fn rgb_is_ink([red, green, blue]: [f64; 3]) -> bool {
    let luminance = 0.299_f64.mul_add(red, 0.587_f64.mul_add(green, 0.114 * blue));
    luminance < INK_LUMINANCE
}

/// Whether a CMYK fill is dark enough to read as ink.
fn cmyk_is_ink([cyan, magenta, yellow, key]: [f64; 4]) -> bool {
    let ink = 0.299_f64.mul_add(cyan, 0.587_f64.mul_add(magenta, 0.114 * yellow));
    (1.0 - key) * (1.0 - ink) < INK_LUMINANCE
}

/// The last `N` operands as numbers.
fn numbers<const N: usize>(operands: &[Operand]) -> Option<[f64; N]> {
    let tail = operands.len().checked_sub(N)?;
    let mut out = [0.0; N];
    for (slot, operand) in out.iter_mut().zip(&operands[tail..]) {
        let Operand::Number(value) = operand else {
            return None;
        };
        *slot = *value;
    }
    Some(out)
}

/// The last operand's shown-string byte count.
fn last_text(operands: &[Operand]) -> Option<usize> {
    match operands.last()? {
        Operand::Text(count) => Some(*count),
        _ => None,
    }
}

/// The nearest `/Resources`, on the page or inherited from the tree.
fn inherited_resources(index: &PdfIndex<'_>, page: &[u8]) -> Option<Vec<u8>> {
    const MAX_DEPTH: usize = 32;

    let mut body = page.to_vec();
    for _ in 0..MAX_DEPTH {
        let dictionary = PdfDictionary::parse(&body).ok()?;
        if let Some(entry) = dictionary.entry(b"Resources").ok()? {
            let value = trim(&body[entry.value.clone()]);
            if value.starts_with(b"<<") {
                return Some(value.to_vec());
            }
            let reference = complete_object_reference(value).ok()??;
            return index.object_body_reference(reference);
        }
        let entry = dictionary.entry(b"Parent").ok()??;
        let parent = complete_object_reference(trim(&body[entry.value.clone()])).ok()??;
        body = index.object_body_reference(parent)?;
    }
    None
}

/// The named object under the resources' `/XObject`.
fn xobject_body(index: &PdfIndex<'_>, resources: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    let dictionary = PdfDictionary::parse(resources).ok()?;
    let entry = dictionary.entry(b"XObject").ok()??;
    let value = trim(&resources[entry.value.clone()]);
    let owned;
    let xobjects = if value.starts_with(b"<<") {
        value
    } else {
        let reference = complete_object_reference(value).ok()??;
        owned = index.object_body_reference(reference)?;
        &owned
    };
    let map = PdfDictionary::parse(xobjects).ok()?;
    let entry = map.entry(name).ok()??;
    let reference = complete_object_reference(trim(&xobjects[entry.value.clone()])).ok()??;
    index.object_body_reference(reference)
}

/// One lexed content token.
enum Token {
    Operand(Operand),
    Operator(Vec<u8>),
    End,
}

/// Lexer over one decoded content stream.
struct Tokens<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Tokens<'_> {
    /// The next token, or `None` when the stream cannot be lexed.
    fn next(&mut self) -> Option<Token> {
        self.skip_trivia();
        let Some(&byte) = self.bytes.get(self.offset) else {
            return Some(Token::End);
        };
        match byte {
            b'[' => {
                self.offset = self.offset.saturating_add(1);
                self.array(1).map(Token::Operand)
            }
            b'(' => {
                self.offset = self.offset.saturating_add(1);
                self.literal_string().map(Token::Operand)
            }
            b'<' => {
                if self.bytes.get(self.offset.saturating_add(1)) == Some(&b'<') {
                    self.dictionary().map(Token::Operand)
                } else {
                    self.offset = self.offset.saturating_add(1);
                    self.hex_string().map(Token::Operand)
                }
            }
            b'/' => {
                self.offset = self.offset.saturating_add(1);
                Some(Token::Operand(Operand::Name(self.name())))
            }
            b'{' | b'}' => {
                self.offset = self.offset.saturating_add(1);
                Some(Token::Operand(Operand::Opaque))
            }
            b']' | b')' | b'>' => None,
            _ => self.atom(),
        }
    }

    fn skip_trivia(&mut self) {
        while let Some(&byte) = self.bytes.get(self.offset) {
            if byte.is_ascii_whitespace() {
                self.offset = self.offset.saturating_add(1);
            } else if byte == b'%' {
                while self
                    .bytes
                    .get(self.offset)
                    .is_some_and(|byte| *byte != b'\n' && *byte != b'\r')
                {
                    self.offset = self.offset.saturating_add(1);
                }
            } else {
                return;
            }
        }
    }

    /// An array of operands, after its opening bracket.
    fn array(&mut self, depth: usize) -> Option<Operand> {
        if depth > STACK_LIMIT {
            return None;
        }
        let mut elements = Vec::new();
        loop {
            self.skip_trivia();
            if self.bytes.get(self.offset) == Some(&b']') {
                self.offset = self.offset.saturating_add(1);
                return Some(Operand::Array(elements));
            }
            if self.bytes.get(self.offset) == Some(&b'[') {
                self.offset = self.offset.saturating_add(1);
                elements.push(self.array(depth.saturating_add(1))?);
                continue;
            }
            match self.next()? {
                Token::Operand(operand) => elements.push(operand),
                // An operator inside an array, or a truncated one, is
                // not content this module can trust.
                Token::Operator(_) | Token::End => return None,
            }
            if elements.len() > STACK_LIMIT {
                return None;
            }
        }
    }

    /// A literal string, after its opening parenthesis, as a byte
    /// count that can only overstate the shown glyphs.
    fn literal_string(&mut self) -> Option<Operand> {
        let start = self.offset;
        let mut depth = 1_usize;
        while let Some(&byte) = self.bytes.get(self.offset) {
            self.offset = self.offset.saturating_add(1);
            match byte {
                b'\\' => self.offset = self.offset.saturating_add(1),
                b'(' => depth = depth.saturating_add(1),
                b')' => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        let span = self.offset.saturating_sub(start).saturating_sub(1);
                        return Some(Operand::Text(span));
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// A hex string, after its opening bracket.
    fn hex_string(&mut self) -> Option<Operand> {
        let mut digits = 0_usize;
        while let Some(&byte) = self.bytes.get(self.offset) {
            self.offset = self.offset.saturating_add(1);
            if byte == b'>' {
                return Some(Operand::Text(digits.div_ceil(2)));
            }
            if byte.is_ascii_hexdigit() {
                digits = digits.saturating_add(1);
            }
        }
        None
    }

    /// A dictionary operand, kept only for operand counting.
    fn dictionary(&mut self) -> Option<Operand> {
        let mut parser = PdfValueParser::new(self.bytes.get(self.offset..)?);
        parser.skip_trivia();
        parser.dictionary(1).ok()?;
        self.offset = self.offset.saturating_add(parser.offset);
        Some(Operand::Opaque)
    }

    /// A name's bytes, after its slash, decoding `#xx` escapes.
    fn name(&mut self) -> Vec<u8> {
        let mut decoded = Vec::new();
        while let Some(&byte) = self.bytes.get(self.offset) {
            if byte.is_ascii_whitespace() || is_delimiter(byte) {
                break;
            }
            if byte == b'#' {
                let high = self
                    .bytes
                    .get(self.offset.saturating_add(1))
                    .copied()
                    .and_then(hex_digit);
                let low = self
                    .bytes
                    .get(self.offset.saturating_add(2))
                    .copied()
                    .and_then(hex_digit);
                if let (Some(high), Some(low)) = (high, low) {
                    decoded.push(high.saturating_mul(16).saturating_add(low));
                    self.offset = self.offset.saturating_add(3);
                    continue;
                }
            }
            decoded.push(byte);
            self.offset = self.offset.saturating_add(1);
        }
        decoded
    }

    /// A number or an operator.
    fn atom(&mut self) -> Option<Token> {
        let start = self.offset;
        while self
            .bytes
            .get(self.offset)
            .is_some_and(|byte| !byte.is_ascii_whitespace() && !is_delimiter(*byte))
        {
            self.offset = self.offset.saturating_add(1);
        }
        if start == self.offset {
            return None;
        }
        let atom = &self.bytes[start..self.offset];
        let number = core::str::from_utf8(atom)
            .ok()
            .and_then(|text| text.parse::<f64>().ok());
        match number {
            Some(value) if value.is_finite() => Some(Token::Operand(Operand::Number(value))),
            Some(_) => None,
            None => Some(Token::Operator(atom.to_vec())),
        }
    }
}

const fn is_delimiter(byte: u8) -> bool {
    matches!(
        byte,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::super::PdfIndex;
    use super::free;

    /// A one-page PDF whose page dictionary carries `page_extra`, with
    /// `extra_objects` numbered from four.
    fn one_page_pdf(page_extra: &str, extra_objects: &[Vec<u8>]) -> Vec<u8> {
        let mut bodies = vec![
            b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
            format!("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] {page_extra} >>")
                .into_bytes(),
        ];
        bodies.extend_from_slice(extra_objects);
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

    fn stream_object(dictionary: &str, data: &[u8]) -> Vec<u8> {
        [dictionary.as_bytes(), b"\nstream\n", data, b"\nendstream"].concat()
    }

    fn content_object(operators: &str) -> Vec<u8> {
        stream_object(
            &format!("<< /Length {} >>", operators.len()),
            operators.as_bytes(),
        )
    }

    fn free_spot(pdf: &[u8]) -> Option<[f64; 4]> {
        let index = PdfIndex::parse(pdf).expect("PDF indexes");
        let page = index.object_body(3).expect("page object");
        free(&index, &page, [0.0, 0.0, 200.0, 200.0], 128.0)
    }

    #[track_caller]
    fn assert_close(actual: [f64; 4], expected: [f64; 4]) {
        for (value, wanted) in actual.iter().zip(expected) {
            assert!(
                (value - wanted).abs() < 1e-9,
                "got {actual:?}, wanted {expected:?}"
            );
        }
    }

    #[test]
    fn a_blank_page_offers_the_lower_right_corner() {
        let pdf = one_page_pdf("", &[]);
        let spot = free_spot(&pdf).expect("a blank page has room");
        assert_close(spot, [68.0, 4.0, 196.0, 132.0]);
    }

    #[test]
    fn ink_along_the_foot_moves_the_mark_up() {
        let pdf = one_page_pdf("/Contents 4 0 R", &[content_object("0 0 200 50 re f")]);
        let spot = free_spot(&pdf).expect("the upper page is clear");
        assert_close(spot, [68.0, 58.0, 196.0, 186.0]);
    }

    #[test]
    fn a_white_background_is_paper_not_ink() {
        let pdf = one_page_pdf("/Contents 4 0 R", &[content_object("1 g 0 0 200 200 re f")]);
        let spot = free_spot(&pdf).expect("white fill occupies nothing");
        assert_close(spot, [68.0, 4.0, 196.0, 132.0]);
    }

    #[test]
    fn flate_compressed_content_is_read() {
        let operators = b"0 0 200 50 re f";
        let compressed = miniz_oxide::deflate::compress_to_vec_zlib(operators, 6);
        let pdf = one_page_pdf(
            "/Contents 4 0 R",
            &[stream_object(
                &format!("<< /Length {} /Filter /FlateDecode >>", compressed.len()),
                &compressed,
            )],
        );
        let spot = free_spot(&pdf).expect("inflated content is interpreted");
        assert_close(spot, [68.0, 58.0, 196.0, 186.0]);
    }

    #[test]
    fn an_unknown_filter_abandons_the_search() {
        let pdf = one_page_pdf(
            "/Contents 4 0 R",
            &[stream_object("<< /Length 3 /Filter /LZWDecode >>", b"abc")],
        );
        assert!(
            free_spot(&pdf).is_none(),
            "unread ink must not count as paper"
        );
    }

    #[test]
    fn an_inline_image_abandons_the_search() {
        let pdf = one_page_pdf("/Contents 4 0 R", &[content_object("BI /W 1 /H 1 ID x EI")]);
        assert!(free_spot(&pdf).is_none(), "inline images paint unknowably");
    }

    #[test]
    fn text_is_avoided_with_width_to_spare() {
        let pdf = one_page_pdf(
            "/Contents 4 0 R",
            &[content_object("BT /F1 12 Tf 20 40 Td (Hello there) Tj ET")],
        );
        let spot = free_spot(&pdf).expect("the page is mostly clear");
        assert_close(spot, [68.0, 58.0, 196.0, 186.0]);
    }

    #[test]
    fn an_earlier_annotation_is_occupied() {
        let pdf = one_page_pdf(
            "/Annots [4 0 R]",
            &[b"<< /Type /Annot /Subtype /Square /Rect [0 0 200 60] >>".to_vec()],
        );
        let spot = free_spot(&pdf).expect("the page above the annotation is clear");
        assert_close(spot, [68.0, 64.0, 196.0, 192.0]);
    }

    #[test]
    fn a_placed_image_is_occupied() {
        let pdf = one_page_pdf(
            "/Contents 4 0 R /Resources << /XObject << /Im0 5 0 R >> >>",
            &[
                content_object("q 200 0 0 50 0 0 cm /Im0 Do Q"),
                stream_object("<< /Subtype /Image /Length 1 >>", b"x"),
            ],
        );
        let spot = free_spot(&pdf).expect("the page above the image is clear");
        assert_close(spot, [68.0, 58.0, 196.0, 186.0]);
    }

    #[test]
    fn a_crowded_page_shrinks_the_mark_before_giving_up() {
        let pdf = one_page_pdf(
            "/Contents 4 0 R",
            &[content_object("0 0 200 80 re f 0 0 110 200 re f")],
        );
        let spot = free_spot(&pdf).expect("the upper-right pocket fits a smaller mark");
        assert_close(spot, [119.2, 88.0, 196.0, 164.8]);
        let side = spot[2] - spot[0];
        assert!((side - 76.8).abs() < 1e-9, "smallest accepted share");
    }

    #[test]
    fn a_page_with_no_room_yields_nothing() {
        let pdf = one_page_pdf("/Contents 4 0 R", &[content_object("0 0 200 200 re f")]);
        assert!(free_spot(&pdf).is_none(), "a full page has no spot");
    }
}
