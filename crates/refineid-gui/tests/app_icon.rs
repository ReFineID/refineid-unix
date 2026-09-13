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

//! The freedesktop app icon flattens the Apple AppIcon composition
//! (card layer plus the chip layer nudged by its translate offset).
//! The contact chip must sit vertically centered on the card body the
//! way the composed Apple icon places it, not drifted toward the top.

use std::path::PathBuf;

const ICON: &str = "assets/app-icon.svg";
const CARD_MARKER: &str = "<!-- the card body -->";
const CHIP_FILL: &str = "fill=\"#D9B96B\"";
const FLIP_MARKER: &str = "matrix(1,0,0,-1,0,";
const TRANSLATE_MARKER: &str = "transform=\"translate(";
/// Apple composes the chip 7pt below the exact card middle; accept the
/// composed placement plus raster rounding, reject a drifted chip.
const CENTER_TOLERANCE_PX: f64 = 10.0;

fn icon_text() -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(ICON);
    std::fs::read_to_string(&path).expect("app icon must be readable")
}

fn attr(line: &str, name: &str) -> f64 {
    let key = format!("{name}=\"");
    let start = line
        .find(&key)
        .unwrap_or_else(|| panic!("{line} lacks {name}"))
        + key.len();
    let end = line[start..].find('"').expect("attribute must close") + start;
    line[start..end].parse().expect("attribute must be numeric")
}

fn view_box_size(text: &str) -> f64 {
    let line = text
        .lines()
        .find(|l| l.contains("viewBox"))
        .expect("svg needs a viewBox");
    let start = line.find("viewBox=\"").expect("viewBox attribute") + 9;
    let end = line[start..].find('"').expect("viewBox must close") + start;
    let parts: Vec<&str> = line[start..end].split_whitespace().collect();
    assert!(parts.len() == 4, "viewBox needs four components");
    parts[3].parse().expect("viewBox height must be numeric")
}

#[test]
fn chip_is_vertically_centered_on_card() {
    let text = icon_text();
    let canvas = view_box_size(&text);

    let card_line = text
        .lines()
        .skip_while(|l| !l.contains(CARD_MARKER))
        .nth(1)
        .expect("card body rect follows its marker");
    let card_cy = attr(card_line, "y") + attr(card_line, "height") / 2.0;

    let chip_line = text
        .lines()
        .find(|l| l.contains(CHIP_FILL))
        .expect("gold chip pad");
    let pad_mid = attr(chip_line, "y") + attr(chip_line, "height") / 2.0;

    assert!(
        text.contains(&format!("{FLIP_MARKER}{canvas}")),
        "chip layer keeps the y-up flip about the canvas middle"
    );
    let after_card: String = text
        .lines()
        .skip_while(|l| !l.contains(CARD_MARKER))
        .collect();
    let translate = after_card
        .find(TRANSLATE_MARKER)
        .expect("chip translate follows the card")
        + TRANSLATE_MARKER.len();
    let rest = &after_card[translate..];
    let comma = rest.find(',').expect("translate has x,y");
    let end = rest.find(')').expect("translate must close");
    let ty: f64 = rest[comma + 1..end]
        .trim()
        .parse()
        .expect("translate y must be numeric");

    let chip_cy = (canvas - pad_mid) + ty;
    assert!(
        (chip_cy - card_cy).abs() <= CENTER_TOLERANCE_PX,
        "chip center {chip_cy} must sit on card center {card_cy}"
    );
}
