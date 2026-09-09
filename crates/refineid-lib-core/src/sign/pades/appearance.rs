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

//! Restrained visible appearance for a PDF signature widget.
//!
//! The appearance is presentation, not evidence. The enclosing `PAdES`
//! signature authenticates the widget, certificate, and document. This module
//! only renders the holder's card-carried handwriting, certificate name, and
//! PEUIN/SATU as a compact vector rubber stamp.

use core::fmt::Write as _;

use crate::rng;

/// One horizontal run of dark pixels in a displayed-signature image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InkRun {
    x: u32,
    y: u32,
    width: u32,
}

/// A card-carried handwritten signature reduced to opaque vector runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureInk {
    height: u32,
    runs: Vec<InkRun>,
    left: u32,
    right: u32,
    top: u32,
    bottom: u32,
}

impl SignatureInk {
    /// Trace an RGBA image into horizontal ink runs.
    ///
    /// Empty or malformed images return `None`. Alpha below one half is
    /// treated as paper; opaque pixels below the middle luminance become ink.
    #[must_use]
    pub fn from_rgba(width: u32, height: u32, rgba: &[u8]) -> Option<Self> {
        const CHANNELS: usize = 4;
        const RED_WEIGHT: u32 = 299;
        const GREEN_WEIGHT: u32 = 587;
        const BLUE_WEIGHT: u32 = 114;
        const WEIGHT_SCALE: u32 = 1_000;
        const MIDDLE: u8 = u8::MAX / 2;

        let width_usize = usize::try_from(width).ok()?;
        let height_usize = usize::try_from(height).ok()?;
        let pixels = width_usize.checked_mul(height_usize)?;
        if width == 0 || height == 0 || rgba.len() != pixels.checked_mul(CHANNELS)? {
            return None;
        }

        let is_ink = |index: usize| {
            let at = index.saturating_mul(CHANNELS);
            let red = u32::from(rgba[at]);
            let green = u32::from(rgba[at.saturating_add(1)]);
            let blue = u32::from(rgba[at.saturating_add(2)]);
            let alpha = rgba[at.saturating_add(3)];
            let luminance =
                (red * RED_WEIGHT + green * GREEN_WEIGHT + blue * BLUE_WEIGHT) / WEIGHT_SCALE;
            alpha >= MIDDLE && luminance < u32::from(MIDDLE)
        };

        let mut runs = Vec::new();
        let mut left = width;
        let mut right = 0_u32;
        let mut top = height;
        let mut bottom = 0_u32;
        for y in 0..height {
            let mut x = 0_u32;
            while x < width {
                let index =
                    usize::try_from(y).ok()?.checked_mul(width_usize)? + usize::try_from(x).ok()?;
                if !is_ink(index) {
                    x = x.saturating_add(1);
                    continue;
                }
                let start = x;
                while x < width {
                    let run_index = usize::try_from(y).ok()?.checked_mul(width_usize)?
                        + usize::try_from(x).ok()?;
                    if !is_ink(run_index) {
                        break;
                    }
                    x = x.saturating_add(1);
                }
                let run_width = x.saturating_sub(start);
                runs.push(InkRun {
                    x: start,
                    y,
                    width: run_width,
                });
                left = left.min(start);
                right = right.max(x);
                top = top.min(y);
                bottom = bottom.max(y.saturating_add(1));
            }
        }
        if runs.is_empty() || right <= left || bottom <= top {
            return None;
        }
        Some(Self {
            height,
            runs,
            left,
            right,
            top,
            bottom,
        })
    }
}

/// Certificate identity and optional handwriting shown on the signed page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VisibleSignature {
    name: String,
    identifier: String,
    handwriting: Option<SignatureInk>,
}

impl VisibleSignature {
    /// Build a mark from identity already authenticated by the signing cert.
    #[must_use]
    pub fn new(name: &str, identifier: &str, handwriting: Option<SignatureInk>) -> Option<Self> {
        const MAX_TEXT_BYTES: usize = 256;
        let name = name.trim();
        let identifier = identifier.trim();
        if name.is_empty()
            || name.len() > MAX_TEXT_BYTES
            || identifier.len() > MAX_TEXT_BYTES
            || name.chars().any(char::is_control)
            || identifier.chars().any(char::is_control)
        {
            return None;
        }
        Some(Self {
            name: name.to_owned(),
            identifier: identifier.to_owned(),
            handwriting,
        })
    }

    /// Render a self-contained Form `XObject` content stream.
    pub(super) fn render(&self) -> RenderedAppearance {
        let mut operators = String::from("q\n");
        operators.push_str(&tilt());
        operators.push_str("0.6902 0.1255 0.1255 RG\n0.6902 0.1255 0.1255 rg\n");
        operators.push_str(&circle(OUTER_RADIUS, OUTER_LINE_WIDTH));
        operators.push_str(&circle(INNER_RADIUS, INNER_LINE_WIDTH));
        if let Some(ref handwriting) = self.handwriting {
            operators.push_str(&render_handwriting(handwriting));
            operators.push_str(&text_line(&self.name, NAME_BASELINE, MAX_NAME_SIZE));
            if !self.identifier.is_empty() {
                operators.push_str(&text_line(
                    &self.identifier,
                    IDENTIFIER_BASELINE,
                    MAX_IDENTIFIER_SIZE,
                ));
            }
        } else {
            let name_baseline = if self.identifier.is_empty() {
                IDENTITY_ONLY_SINGLE_BASELINE
            } else {
                IDENTITY_ONLY_NAME_BASELINE
            };
            operators.push_str(&text_line(&self.name, name_baseline, MAX_NAME_SIZE));
            if !self.identifier.is_empty() {
                operators.push_str(&text_line(
                    &self.identifier,
                    IDENTITY_ONLY_IDENTIFIER_BASELINE,
                    MAX_IDENTIFIER_SIZE,
                ));
            }
        }
        operators.push_str("Q\nQ\n");
        RenderedAppearance {
            side: MARK_SIDE,
            operators: operators.into_bytes(),
        }
    }
}

/// A turn of 10 to 20 degrees clockwise about the mark's centre, so no
/// two stamps land at the same angle.
///
/// A rubber stamp is never put down square, and one that lands at
/// exactly the same angle every time looks like what it is: a drawing.
/// The range starts well away from square, because a turn of a degree
/// or two reads as a mistake rather than a hand. Everything the mark
/// draws stays within 63 units of the centre, and the form box allows
/// 64, so no tilt in the range can clip it.
fn tilt() -> String {
    // The tilt is presentation, not secrecy: the enclosing signature
    // authenticates the document either way, so a dead OS RNG parks
    // the stamp mid-range instead of failing the signing operation.
    let fraction = rng::array::<4>().map_or(0.5, |bytes| {
        f64::from(u32::from_le_bytes(bytes)) / f64::from(u32::MAX)
    });
    let degrees = fraction.mul_add(MOST_TILT_DEGREES - LEAST_TILT_DEGREES, LEAST_TILT_DEGREES);
    let turn = -degrees.to_radians();
    let (sine, cosine) = turn.sin_cos();
    let shift_x = CENTRE.mul_add(sine, CENTRE.mul_add(-cosine, CENTRE));
    let shift_y = CENTRE.mul_add(-cosine, CENTRE.mul_add(-sine, CENTRE));
    format!(
        "q {cosine:.4} {sine:.4} {minus_sine:.4} {cosine:.4} {shift_x:.4} {shift_y:.4} cm\n",
        minus_sine = -sine
    )
}

/// Content and natural dimensions of one signature appearance.
pub(super) struct RenderedAppearance {
    pub(super) side: f64,
    pub(super) operators: Vec<u8>,
}

const MARK_SIDE: f64 = 128.0;
const CENTRE: f64 = MARK_SIDE / 2.0;
const LEAST_TILT_DEGREES: f64 = 10.0;
const MOST_TILT_DEGREES: f64 = 20.0;
const OUTER_RADIUS: f64 = 62.0;
const INNER_RADIUS: f64 = 55.0;
const OUTER_LINE_WIDTH: f64 = 1.8;
const INNER_LINE_WIDTH: f64 = 0.9;
const ARC_CONTROL: f64 = 0.552_284_8;
const BASELINE_Y: f64 = 61.0;
const BASELINE_LEFT: f64 = 19.0;
const BASELINE_RIGHT: f64 = 109.0;
const BASELINE_WIDTH: f64 = 1.2;
const HANDWRITING_MAX_HEIGHT: f64 = 29.0;
const NAME_BASELINE: f64 = 42.0;
const IDENTIFIER_BASELINE: f64 = 31.0;
const IDENTITY_ONLY_NAME_BASELINE: f64 = 67.0;
const IDENTITY_ONLY_IDENTIFIER_BASELINE: f64 = 51.0;
const IDENTITY_ONLY_SINGLE_BASELINE: f64 = 59.0;
const TEXT_ROOM: f64 = 92.0;
const MAX_NAME_SIZE: f64 = 11.0;
const MAX_IDENTIFIER_SIZE: f64 = 9.0;

fn render_handwriting(ink: &SignatureInk) -> String {
    let ink_width = f64::from(ink.right.saturating_sub(ink.left));
    let ink_height = f64::from(ink.bottom.saturating_sub(ink.top));
    if ink_width <= 0.0 || ink_height <= 0.0 {
        return String::new();
    }
    let scale =
        ((BASELINE_RIGHT - BASELINE_LEFT) / ink_width).min(HANDWRITING_MAX_HEIGHT / ink_height);
    let source_bottom = f64::from(ink.height.saturating_sub(ink.bottom));
    let translate_x = f64::from(ink.left).mul_add(-scale, BASELINE_LEFT);
    let translate_y = source_bottom.mul_add(-scale, BASELINE_Y + 2.0);
    let mut out = format!("q {scale:.5} 0 0 {scale:.5} {translate_x:.5} {translate_y:.5} cm\n");
    for run in &ink.runs {
        let y = ink.height.saturating_sub(run.y).saturating_sub(1);
        let _ignored = writeln!(&mut out, "{} {} {} 1 re", run.x, y, run.width);
    }
    out.push_str("f\nQ\n");
    let _ignored = writeln!(
        &mut out,
        "{BASELINE_WIDTH:.4} w {BASELINE_LEFT:.4} {BASELINE_Y:.4} m {BASELINE_RIGHT:.4} {BASELINE_Y:.4} l S"
    );
    out
}

fn text_line(text: &str, baseline: f64, maximum_size: f64) -> String {
    let encoded = win_ansi_literal(text);
    let units = helvetica_width(text);
    if encoded.is_empty() || units <= 0.0 {
        return String::new();
    }
    let size = maximum_size.min(TEXT_ROOM * 1_000.0 / units);
    let width = units * size / 1_000.0;
    let x = CENTRE - width / 2.0;
    format!("BT\n/F1 {size:.4} Tf\n1 0 0 1 {x:.4} {baseline:.4} Tm\n({encoded}) Tj\nET\n")
}

fn helvetica_width(text: &str) -> f64 {
    text.chars()
        .map(|character| match character {
            ' ' | 'I' | 'i' | 'j' | 'l' | 't' | '1' => 278.0,
            'f' | 'r' => 333.0,
            'm' | 'w' | 'M' | 'W' => 833.0,
            'A'..='Z' => 667.0,
            '0'..='9' => 556.0,
            _ => 500.0,
        })
        .sum()
}

/// PDF literal-string bytes under `WinAnsiEncoding`.
fn win_ansi_literal(text: &str) -> String {
    let mut out = String::new();
    for character in text.chars() {
        let byte = u8::try_from(u32::from(character)).unwrap_or(b'?');
        match byte {
            b'(' | b')' | b'\\' => {
                out.push('\\');
                out.push(char::from(byte));
            }
            b' '..=b'~' => out.push(char::from(byte)),
            _ => {
                let _ignored = write!(&mut out, "\\{byte:03o}");
            }
        }
    }
    out
}

fn circle(radius: f64, line_width: f64) -> String {
    let pull = radius * ARC_CONTROL;
    let left = CENTRE - radius;
    let right = CENTRE + radius;
    let bottom = CENTRE - radius;
    let top = CENTRE + radius;
    let upper = CENTRE + pull;
    let lower = CENTRE - pull;
    format!(
        "{line_width:.4} w\n{right:.4} {CENTRE:.4} m\n\
         {right:.4} {upper:.4} {upper:.4} {top:.4} {CENTRE:.4} {top:.4} c\n\
         {lower:.4} {top:.4} {left:.4} {upper:.4} {left:.4} {CENTRE:.4} c\n\
         {left:.4} {lower:.4} {lower:.4} {bottom:.4} {CENTRE:.4} {bottom:.4} c\n\
         {upper:.4} {bottom:.4} {right:.4} {lower:.4} {right:.4} {CENTRE:.4} c\nS\n",
    )
}

#[cfg(test)]
mod tests {
    use super::{SignatureInk, VisibleSignature};

    #[test]
    fn rgba_trace_keeps_only_dark_opaque_runs() {
        let pixels = [
            255, 255, 255, 255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255, 255,
        ];
        let ink = SignatureInk::from_rgba(4, 1, &pixels).expect("two dark pixels");
        assert_eq!(ink.runs.len(), 1);
        assert_eq!(ink.left, 1);
        assert_eq!(ink.right, 3);
    }

    #[test]
    fn blank_image_has_no_handwriting() {
        assert!(SignatureInk::from_rgba(1, 1, &[255, 255, 255, 255]).is_none());
    }

    #[test]
    fn mark_is_tilted_like_a_hand_stamp() {
        let mark = VisibleSignature::new("Test Signer", "12345678A", None).expect("identity");
        let text = String::from_utf8(mark.render().operators).expect("ASCII operators");
        let matrix = text.lines().nth(1).expect("tilt line");
        let parts: Vec<&str> = matrix.split_whitespace().collect();
        assert_eq!(parts.first(), Some(&"q"), "tilt opens its own state");
        assert_eq!(parts.last(), Some(&"cm"), "tilt is one matrix");
        let cosine: f64 = parts[1].parse().expect("cosine");
        let sine: f64 = parts[2].parse().expect("sine");
        let degrees = -sine.atan2(cosine).to_degrees();
        // Written at four decimal places, so allow rounding at the edges.
        assert!(
            (9.99..=20.01).contains(&degrees),
            "clockwise tilt within range, got {degrees}"
        );
        let length = sine.mul_add(sine, cosine * cosine);
        assert!((length - 1.0).abs() < 0.001, "a rotation, not a scale");
    }

    #[test]
    fn mark_contains_line_name_and_identifier() {
        let ink = SignatureInk::from_rgba(2, 1, &[0, 0, 0, 255, 0, 0, 0, 255]);
        let mark = VisibleSignature::new("Test Signer", "12345678A", ink).expect("identity");
        let rendered = mark.render();
        let text = String::from_utf8(rendered.operators).expect("ASCII operators");
        assert!(text.contains("Test Signer"));
        assert!(text.contains("12345678A"));
        assert!(text.contains(" l S"), "handwriting baseline");
    }
}
