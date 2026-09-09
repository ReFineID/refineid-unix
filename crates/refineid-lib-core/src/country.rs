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

//! ICAO 3-letter -> ISO 3166 2-letter country-code mapping.
//!
//! eMRTDs use the ICAO 9303 3-letter codes (`FIN`, `DEU`, `USA`,
//! ...) for the `issuing country` and `nationality` fields of
//! the MRZ. X.509 certificate DNs use ISO 3166-1 alpha-2
//! 2-letter codes (`FI`, `DE`, `US`, ...) for the `countryName`
//! attribute. BSI TR-03135-1 §4.6.4.5 requires an inspection
//! system to cross-check the two -- a Finnish ID card's DG1
//! should say `FIN` and its DSC's issuer should say `FI`. A
//! mismatch indicates a manipulated document.
//!
//! The mapping is mostly the obvious "drop the third letter"
//! rule but with enough exceptions (Switzerland CHE->CH,
//! Germany DEU->DE, Netherlands NLD->NL, ...) that a table is
//! the safest implementation. This module's table covers the
//! EU/EEA + the common travel destinations; ICAO 9303 also
//! defines additional special codes (e.g. `UNK` for unknown,
//! `XBA` African Development Bank) which we don't enumerate.
//!
//! When the table doesn't know a code, callers should
//! interpret the check as `undetermined` per BSI -- *not*
//! `failed`. Adding a missing entry is a one-line table edit.

/// One ICAO -> ISO country-code pair. The order in the table
/// doesn't matter; lookup is linear.
struct CountryCode {
    /// ICAO 9303 three-letter country code as printed on MRZ documents.
    icao: &'static str,
    /// ISO 3166-1 alpha-2 country code used on PKI subject/issuer DNs.
    iso: &'static str,
}

/// ICAO-to-ISO crosswalk for the EEA + Switzerland country set
/// the EU eIDAS framework cares about, plus a few non-EEA states
/// that ship FINEID-compatible eMRTDs.
///
/// Linear search is intentional: the table is short (~35 rows),
/// the lookup is off the hot path (CSCA validation), and a
/// pre-computed map would force a runtime allocation. Order is
/// audit-grouped (EEA first, then alphabetical) for readability,
/// not lookup speed.
const TABLE: &[CountryCode] = &[
    // EU member states + EEA + Switzerland.
    CountryCode {
        icao: "AUT",
        iso: "AT",
    },
    CountryCode {
        icao: "BEL",
        iso: "BE",
    },
    CountryCode {
        icao: "BGR",
        iso: "BG",
    },
    CountryCode {
        icao: "CHE",
        iso: "CH",
    },
    CountryCode {
        icao: "CYP",
        iso: "CY",
    },
    CountryCode {
        icao: "CZE",
        iso: "CZ",
    },
    CountryCode {
        icao: "DEU",
        iso: "DE",
    },
    CountryCode {
        icao: "DNK",
        iso: "DK",
    },
    CountryCode {
        icao: "ESP",
        iso: "ES",
    },
    CountryCode {
        icao: "EST",
        iso: "EE",
    },
    CountryCode {
        icao: "FIN",
        iso: "FI",
    },
    CountryCode {
        icao: "FRA",
        iso: "FR",
    },
    CountryCode {
        icao: "GBR",
        iso: "GB",
    },
    CountryCode {
        icao: "GRC",
        iso: "GR",
    },
    CountryCode {
        icao: "HRV",
        iso: "HR",
    },
    CountryCode {
        icao: "HUN",
        iso: "HU",
    },
    CountryCode {
        icao: "IRL",
        iso: "IE",
    },
    CountryCode {
        icao: "ISL",
        iso: "IS",
    },
    CountryCode {
        icao: "ITA",
        iso: "IT",
    },
    CountryCode {
        icao: "LIE",
        iso: "LI",
    },
    CountryCode {
        icao: "LTU",
        iso: "LT",
    },
    CountryCode {
        icao: "LUX",
        iso: "LU",
    },
    CountryCode {
        icao: "LVA",
        iso: "LV",
    },
    CountryCode {
        icao: "MLT",
        iso: "MT",
    },
    CountryCode {
        icao: "NLD",
        iso: "NL",
    },
    CountryCode {
        icao: "NOR",
        iso: "NO",
    },
    CountryCode {
        icao: "POL",
        iso: "PL",
    },
    CountryCode {
        icao: "PRT",
        iso: "PT",
    },
    CountryCode {
        icao: "ROU",
        iso: "RO",
    },
    CountryCode {
        icao: "SVK",
        iso: "SK",
    },
    CountryCode {
        icao: "SVN",
        iso: "SI",
    },
    CountryCode {
        icao: "SWE",
        iso: "SE",
    },
    // Common travel destinations.
    CountryCode {
        icao: "AUS",
        iso: "AU",
    },
    CountryCode {
        icao: "BRA",
        iso: "BR",
    },
    CountryCode {
        icao: "CAN",
        iso: "CA",
    },
    CountryCode {
        icao: "CHN",
        iso: "CN",
    },
    CountryCode {
        icao: "IND",
        iso: "IN",
    },
    CountryCode {
        icao: "JPN",
        iso: "JP",
    },
    CountryCode {
        icao: "KOR",
        iso: "KR",
    },
    CountryCode {
        icao: "MEX",
        iso: "MX",
    },
    CountryCode {
        icao: "NZL",
        iso: "NZ",
    },
    CountryCode {
        icao: "RUS",
        iso: "RU",
    },
    CountryCode {
        icao: "TUR",
        iso: "TR",
    },
    CountryCode {
        icao: "UKR",
        iso: "UA",
    },
    CountryCode {
        icao: "USA",
        iso: "US",
    },
];

/// ICAO 9303 country code from the MRZ.
///
/// 1-3 ASCII letters (uppercase, after MRZ filler-strip). Most
/// countries use the full 3-letter form ("FIN", "DEU"), but a
/// few historical forms are shorter ("D" for Germany in older
/// passports). Construction validates ASCII letter shape and
/// uppercases.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IcaoCountry(String);

/// ISO 3166-1 alpha-2 country code.
///
/// Exactly 2 ASCII uppercase letters. Used in X.509 DN
/// `countryName` attributes (RFC 5280 references ISO 3166-1).
/// Distinct type from [`IcaoCountry`] -- the compiler enforces
/// "don't mix ICAO-from-MRZ with ISO-from-cert-DN".
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IsoAlpha2(String);

/// Error returned by the country-code newtype constructors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountryError {
    /// Empty input or only fillers.
    Empty,
    /// Too short / too long for the expected shape.
    WrongLength {
        /// Human-readable description of the expected length
        /// (e.g. "2 letters", "3 letters"). Tier 0 `&'static
        /// str` from a fixed compile-time set.
        expected: &'static str,
        /// Length of the rejected input in bytes. Tier 0 `usize`.
        got: usize,
    },
    /// A non-ASCII-letter byte appeared.
    NotAsciiLetter {
        /// Byte index of the offending value.
        at: usize,
        /// The offending byte (anything outside `A..=Z` /
        /// `a..=z`).
        byte: u8,
    },
}

impl core::fmt::Display for CountryError {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => write!(f, "country code cannot be empty"),
            Self::WrongLength { expected, got } => {
                write!(
                    f,
                    "country code wrong length: expected {expected}, got {got}"
                )
            }
            Self::NotAsciiLetter { at, byte } => write!(
                f,
                "country code must be ASCII letters only; non-letter at offset {at}: byte {byte:#04x}"
            ),
        }
    }
}

impl core::error::Error for CountryError {}

impl IcaoCountry {
    /// Parse `s` (already filler-stripped) as an ICAO MRZ
    /// country code. Accepts 1-3 ASCII letters; uppercases at
    /// construction.
    ///
    /// # Errors
    /// Empty, wrong length, or any non-ASCII-letter byte.
    pub(crate) fn new(s: &str) -> Result<Self, CountryError> {
        let bytes = s.as_bytes();
        if bytes.is_empty() {
            return Err(CountryError::Empty);
        }
        if bytes.len() > 3 {
            return Err(CountryError::WrongLength {
                expected: "1-3 ASCII letters",
                got: bytes.len(),
            });
        }
        for (i, &b) in bytes.iter().enumerate() {
            if !b.is_ascii_alphabetic() {
                return Err(CountryError::NotAsciiLetter { at: i, byte: b });
            }
        }
        Ok(Self(s.to_ascii_uppercase()))
    }

    /// String view, guaranteed uppercase ASCII letters.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Map this MRZ-derived ICAO code to its ISO 3166-1 alpha-2
    /// equivalent for cross-checking against an X.509 DN
    /// `countryName`. Returns `None` for codes the table doesn't
    /// enumerate.
    #[inline]
    #[must_use]
    pub fn to_iso_alpha2(&self) -> Option<IsoAlpha2> {
        let upper = self.as_str();
        TABLE
            .iter()
            .find(|c| c.icao.eq_ignore_ascii_case(upper))
            .map(|c| IsoAlpha2(c.iso.to_owned()))
    }
}

impl IsoAlpha2 {
    /// Parse `s` as an ISO 3166-1 alpha-2 country code.
    /// Requires exactly 2 ASCII letters; uppercases at
    /// construction.
    ///
    /// # Errors
    /// Empty, wrong length (not 2), or any non-ASCII-letter byte.
    pub(crate) fn new(s: &str) -> Result<Self, CountryError> {
        let bytes = s.as_bytes();
        if bytes.is_empty() {
            return Err(CountryError::Empty);
        }
        if bytes.len() != 2 {
            return Err(CountryError::WrongLength {
                expected: "2 ASCII letters",
                got: bytes.len(),
            });
        }
        for (i, &b) in bytes.iter().enumerate() {
            if !b.is_ascii_alphabetic() {
                return Err(CountryError::NotAsciiLetter { at: i, byte: b });
            }
        }
        Ok(Self(s.to_ascii_uppercase()))
    }

    /// Map this DN-derived ISO code to its ICAO MRZ equivalent
    /// for cross-checking against DG1. Returns `None` for codes
    /// the table doesn't enumerate.
    #[inline]
    #[must_use]
    pub fn to_icao(&self) -> Option<IcaoCountry> {
        let upper = self.as_str();
        TABLE
            .iter()
            .find(|c| c.iso.eq_ignore_ascii_case(upper))
            .map(|c| IcaoCountry(c.icao.to_owned()))
    }

    /// String view, guaranteed 2 uppercase ASCII letters.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for IcaoCountry {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::fmt::Display for IsoAlpha2 {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

// `icao_to_iso` / `iso_to_icao` are methods on `IcaoCountry` /
// `IsoAlpha2`; see the trait definition above.

#[cfg(test)]
mod tests {

    use super::{CountryError, IcaoCountry, IsoAlpha2};

    fn icao(s: &str) -> IcaoCountry {
        IcaoCountry::new(s).expect("test fixture is a valid ICAO code")
    }
    fn iso(s: &str) -> IsoAlpha2 {
        IsoAlpha2::new(s).expect("test fixture is a valid alpha-2 code")
    }

    #[test]
    fn finland_round_trip() {
        assert_eq!(icao("FIN").to_iso_alpha2(), Some(iso("FI")));
        assert_eq!(iso("FI").to_icao(), Some(icao("FIN")));
    }

    #[test]
    fn case_insensitive_construction() {
        assert_eq!(
            IcaoCountry::new("fin")
                .expect("lowercase ICAO code is accepted")
                .as_str(),
            "FIN"
        );
        assert_eq!(
            IsoAlpha2::new("fi")
                .expect("lowercase alpha-2 code is accepted")
                .as_str(),
            "FI"
        );
    }

    #[test]
    fn unknown_returns_none() {
        assert_eq!(icao("XYZ").to_iso_alpha2(), None);
        assert_eq!(iso("XY").to_icao(), None);
    }

    #[test]
    fn three_letter_drop_exceptions() {
        assert_eq!(icao("CHE").to_iso_alpha2(), Some(iso("CH")));
        assert_eq!(icao("DEU").to_iso_alpha2(), Some(iso("DE")));
        assert_eq!(icao("NLD").to_iso_alpha2(), Some(iso("NL")));
        assert_eq!(icao("GBR").to_iso_alpha2(), Some(iso("GB")));
        assert_eq!(icao("ESP").to_iso_alpha2(), Some(iso("ES")));
        assert_eq!(icao("SWE").to_iso_alpha2(), Some(iso("SE")));
    }

    #[test]
    fn icao_rejects_too_long() {
        assert!(matches!(
            IcaoCountry::new("ABCD"),
            Err(CountryError::WrongLength { got: 4, .. })
        ));
    }

    #[test]
    fn icao_rejects_digits() {
        assert!(matches!(
            IcaoCountry::new("F1N"),
            Err(CountryError::NotAsciiLetter { at: 1, .. })
        ));
    }

    #[test]
    fn iso_requires_exactly_two() {
        assert!(matches!(
            IsoAlpha2::new("F"),
            Err(CountryError::WrongLength { got: 1, .. })
        ));
        assert!(matches!(
            IsoAlpha2::new("FIN"),
            Err(CountryError::WrongLength { got: 3, .. })
        ));
    }

    #[test]
    fn iso_rejects_digits() {
        assert!(matches!(
            IsoAlpha2::new("F1"),
            Err(CountryError::NotAsciiLetter { at: 1, .. })
        ));
    }

    #[test]
    fn icao_uppercases() {
        let c = IcaoCountry::new("FiN").expect("mixed-case ICAO code is accepted");
        assert_eq!(c.as_str(), "FIN");
    }
}
