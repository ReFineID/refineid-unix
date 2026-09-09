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

//! ISO 8601-1:2019 canonical time storage.
//!
//! The [`Iso8601`] enum is refineid's single internal
//! representation for every reasonable variation of date and
//! time that appears on a FINEID card or in an X.509 cert. Wire
//! forms (DG11 / DG12 `YYYYMMDD`, MRZ `YYMMDD`, ASN.1 `UTCTime`
//! / `GeneralizedTime`, the ISO 8601 dashed form) parse INTO an
//! [`Iso8601`] at the construction boundary; render paths emit
//! the canonical ISO 8601 form via [`fmt::Display`] (or a wire-
//! specific emitter when the consumer asks for one).
//!
//! ## Variant coverage (today)
//!
//! - [`Iso8601::Date`] -- calendar date `YYYY-MM-DD`. Sources:
//!   cert subject DN (future), DG11 `0x5F2B`, DG12 `0x5F26`, MRZ
//!   DG1 (after century resolution).
//! - [`Iso8601::DateTime`] -- date + time + offset. Future
//!   sources: DG12 `0x5F55` (personalisation timestamp), X.509
//!   `notBefore` / `notAfter` (`UTCTime` / `GeneralizedTime`).
//!
//! `Duration`, `Interval`, `Recurring` variants are *not* in this
//! module yet -- per `doc/typing-discipline.md`'s "extended and
//! derived" rule, ISO 8601-1:2019 productions are added as new
//! enum variants only when a refineid consumer needs them.
//!
//! ## Role wrappers
//!
//! Role-specific newtypes (`identity::DateOfBirth`,
//! `identity::IssueDate`, `identity::MrzDate`, future
//! `CertNotBefore` / `CertNotAfter` / `PersonalisationTime`) wrap
//! [`Iso8601`] and enforce the variant invariant at the
//! constructor. They expose a semantic projection (`date()` /
//! `datetime()`) returning the inner [`Date`] / [`DateTime`] for
//! representation-level operations; they do **not** expose the
//! umbrella [`Iso8601`] via an `inner()` / `as_iso8601()` escape
//! hatch. See `doc/typing-discipline.md` for the policy rules
//! that keep this architecture honest.
//!
//! ## Parser visibility
//!
//! The generic wire-form parsers on [`Date`] (`from_yyyymmdd`,
//! `from_mrz_yymmdd`, `from_iso_date_string`) are `pub(crate)`:
//! they're the low-level primitives that role constructors
//! delegate to. Public construction goes through the role
//! types (`DateOfBirth::from_yyyymmdd(s)`).

use core::fmt;

/// Canonical ISO 8601 value. Variants cover the productions
/// refineid currently consumes; add new variants when a real
/// consumer needs them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Iso8601 {
    /// Calendar date, `YYYY-MM-DD`.
    Date(Date),
    /// Date + time + offset, `YYYY-MM-DDTHH:MM:SS[Z|±HH:MM]`.
    DateTime(DateTime),
}

/// Calendar date payload of [`Iso8601::Date`]. Fields private so
/// every consumer goes through the semantic projection on the
/// role wrapper that holds the date.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Date {
    /// Proleptic Gregorian calendar year, range checked at construction.
    year: u16,
    /// Month of the year, `1..=12`.
    month: u8,
    /// Day of the month, valid for [`Date::month`] including leap years.
    day: u8,
}

/// Date + time + offset payload of [`Iso8601::DateTime`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DateTime {
    /// Calendar date portion.
    date: Date,
    /// Wall-clock hour, `0..=23`.
    hour: u8,
    /// Wall-clock minute, `0..=59`.
    minute: u8,
    /// Wall-clock second, `0..=59` (leap seconds are not represented).
    second: u8,
    /// Timezone designator paired with the wall-clock instant.
    offset: TimeOffset,
}

/// Timezone designator on a [`DateTime`].
///
/// `Unspecified` is the explicit "no offset given" state -- a
/// naive local datetime per ICAO 9303-10 DG12 `0x5F55` (which
/// emits `YYYYMMDDhhmmss` with no zone). It is **not** the same
/// as `Utc`: a naive timestamp at `12:00` may be UTC noon or
/// local noon in any zone; the standard refuses to coerce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TimeOffset {
    /// No offset given on the wire.
    Unspecified,
    /// Coordinated Universal Time (`Z` suffix per ISO 8601-1:2019
    /// §4.3.13).
    Utc,
    /// East of UTC. Constructor / parser enforces
    /// `hours <= 14` and `minutes < 60` per ISO 8601-1:2019
    /// §4.3.13.4 (with implementation-specific cap; UTC zones in
    /// the IANA database top out at +14:00).
    Plus {
        /// 0..=14. Type is `u8` (Tier 0 inside a Tier 1 variant);
        /// `OffsetHoursOutOfRange` enforces the bound at parse.
        hours: u8,
        /// 0..=59. Type is `u8` (Tier 0); `OffsetMinutesOutOfRange`
        /// enforces the bound at parse.
        minutes: u8,
    },
    /// West of UTC. Constructor / parser enforces
    /// `hours <= 12` and `minutes < 60` per ISO 8601-1:2019
    /// §4.3.13.4 (cap chosen to match IANA's westmost zones at
    /// -12:00).
    Minus {
        /// 0..=12. Type is `u8` (Tier 0 inside a Tier 1 variant);
        /// `OffsetHoursOutOfRange` enforces the bound at parse.
        hours: u8,
        /// 0..=59. Type is `u8` (Tier 0); `OffsetMinutesOutOfRange`
        /// enforces the bound at parse.
        minutes: u8,
    },
}

/// Refineid's calendar year range -- inclusive lower bound for
/// every year-bearing parser / constructor in this module.
///
/// 1900..=2100 covers every FINEID card minted to date and the
/// full validity window of any plausible cert / DG11 birth date.
/// Extended to wider ranges when a real consumer needs it.
pub const YEAR_MIN: u16 = 1900;
/// Inclusive upper bound for the calendar year range; see
/// [`YEAR_MIN`].
pub const YEAR_MAX: u16 = 2100;

/// Construction / parse errors emitted by every entry point
/// in this module.
///
/// The variants are *diagnostic*: each carries the offending
/// value plus the bound it violated so a CLI caller can render
/// a human-readable error without re-extracting the inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Iso8601Error {
    /// Year outside the module's accepted range.
    YearOutOfRange {
        /// The offending year value the caller supplied.
        year: u16,
        /// Lower bound (inclusive); same as [`YEAR_MIN`].
        min: u16,
        /// Upper bound (inclusive); same as [`YEAR_MAX`].
        max: u16,
    },
    /// Calendar month not in `1..=12`.
    MonthOutOfRange {
        /// The offending month value.
        month: u8,
    },
    /// Day outside the per-month-per-year valid range. The
    /// range depends on the month and whether the year is a
    /// leap year per ISO 8601-1:2019 §4.2.5.1.
    DayOutOfRange {
        /// The offending day value.
        day: u8,
        /// The month context that the day failed against.
        month: u8,
        /// The year context (needed for February leap-day).
        year: u16,
    },
    /// Hour-of-day not in `0..=23`.
    HourOutOfRange {
        /// The offending hour value.
        hour: u8,
    },
    /// Minute-of-hour not in `0..=59`.
    MinuteOutOfRange {
        /// The offending minute value.
        minute: u8,
    },
    /// Second-of-minute not in `0..=59`. Leap seconds (60) are
    /// rejected here; the wire formats this module parses
    /// don't carry them.
    SecondOutOfRange {
        /// The offending second value.
        second: u8,
    },
    /// Timezone-offset hour not in the accepted range
    /// (`0..=14` for `+`, `0..=12` for `-`).
    OffsetHoursOutOfRange {
        /// The offending offset-hour value.
        hours: u8,
    },
    /// Timezone-offset minute not in `0..=59`.
    OffsetMinutesOutOfRange {
        /// The offending offset-minute value.
        minutes: u8,
    },
    /// Input length didn't match the expected wire shape for
    /// `production` (e.g. `YYYYMMDD` requires exactly 8 bytes).
    ParseShape {
        /// Name of the wire production that was being parsed
        /// (e.g. `"YYYYMMDD"`, `"YYMMDD"`).
        production: &'static str,
        /// How many bytes the input actually contained.
        got_bytes: usize,
    },
    /// Input had the right length but a character outside the
    /// allowed class for the production (e.g. non-ASCII-digit
    /// in a numeric production).
    ParseChars {
        /// Name of the wire production that was being parsed.
        production: &'static str,
        /// Byte offset (0-based) where the bad character was
        /// found.
        at: usize,
    },
}

impl fmt::Display for Iso8601Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::YearOutOfRange { year, min, max } => {
                write!(f, "year {year} outside {min}..={max}")
            }
            Self::MonthOutOfRange { month } => write!(f, "month {month} outside 1..=12"),
            Self::DayOutOfRange { day, month, year } => {
                write!(f, "day {day} outside valid range for {year:04}-{month:02}")
            }
            Self::HourOutOfRange { hour } => write!(f, "hour {hour} outside 0..=23"),
            Self::MinuteOutOfRange { minute } => write!(f, "minute {minute} outside 0..=59"),
            Self::SecondOutOfRange { second } => write!(f, "second {second} outside 0..=60"),
            Self::OffsetHoursOutOfRange { hours } => {
                write!(f, "offset hours {hours} outside 0..=14")
            }
            Self::OffsetMinutesOutOfRange { minutes } => {
                write!(f, "offset minutes {minutes} outside 0..=59")
            }
            Self::ParseShape {
                production,
                got_bytes,
            } => {
                write!(
                    f,
                    "{production}: got {got_bytes} bytes, expected the production's fixed length"
                )
            }
            Self::ParseChars { production, at } => {
                write!(
                    f,
                    "{production}: byte at index {at} is outside the production's character class"
                )
            }
        }
    }
}

impl core::error::Error for Iso8601Error {}

// =========================================================
// Date -- calendar date payload.
// =========================================================

impl Date {
    /// Construct from validated calendar components.
    ///
    /// # Errors
    /// [`Iso8601Error::YearOutOfRange`] / [`MonthOutOfRange`] /
    /// [`DayOutOfRange`]. Leap-year-aware day check.
    ///
    /// `pub(crate)` -- public construction goes through the role
    /// wrapper that semantically owns the calendar date.
    ///
    /// [`MonthOutOfRange`]: Iso8601Error::MonthOutOfRange
    /// [`DayOutOfRange`]: Iso8601Error::DayOutOfRange
    pub(crate) const fn new(year: u16, month: u8, day: u8) -> Result<Self, Iso8601Error> {
        match validate_calendar(year, month, day) {
            Ok(()) => Ok(Self { year, month, day }),
            Err(e) => Err(e),
        }
    }

    /// Parse the ISO 8601 extended calendar-date form
    /// `YYYY-MM-DD`.
    ///
    /// # Errors
    /// [`Iso8601Error::ParseShape`] for wrong length;
    /// [`Iso8601Error::ParseChars`] for wrong character class;
    /// otherwise the per-field range errors.
    ///
    /// No production consumer yet; pinned by tests. The first
    /// consumer (likely a JSON / config parser surface) will
    /// remove this attribute.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Phased rollout: no production consumer yet; the first JSON/config parser surface that needs YYYY-MM-DD parsing will remove this."
        )
    )]
    pub(crate) fn from_iso_date_string(s: &str) -> Result<Self, Iso8601Error> {
        const PROD: &str = "YYYY-MM-DD";
        let bytes = s.as_bytes();
        if bytes.len() != 10 {
            return Err(Iso8601Error::ParseShape {
                production: PROD,
                got_bytes: bytes.len(),
            });
        }
        // .get(..) over indexing: avoids indexing_slicing panic
        // shape. Length is already 10 here so each get is
        // infallible, but `?` keeps the lint clean.
        let shape_err = || Iso8601Error::ParseShape {
            production: PROD,
            got_bytes: bytes.len(),
        };
        let year_bytes = bytes.get(0..4).ok_or_else(shape_err)?;
        let dash_at_4 = bytes.get(4).ok_or_else(shape_err)?;
        let month_bytes = bytes.get(5..7).ok_or_else(shape_err)?;
        let dash_at_7 = bytes.get(7).ok_or_else(shape_err)?;
        let day_bytes = bytes.get(8..10).ok_or_else(shape_err)?;
        if *dash_at_4 != b'-' {
            return Err(Iso8601Error::ParseChars {
                production: PROD,
                at: 4,
            });
        }
        if *dash_at_7 != b'-' {
            return Err(Iso8601Error::ParseChars {
                production: PROD,
                at: 7,
            });
        }
        check_ascii_digits(year_bytes, PROD, 0)?;
        check_ascii_digits(month_bytes, PROD, 5)?;
        check_ascii_digits(day_bytes, PROD, 8)?;
        let year = AsciiDigits::parse_u16(year_bytes);
        let month = AsciiDigits::parse_u8(month_bytes);
        let day = AsciiDigits::parse_u8(day_bytes);
        Self::new(year, month, day)
    }

    /// Parse the ICAO 9303-10 basic calendar-date form
    /// `YYYYMMDD` (8 ASCII digits, no separators). Used by DG11
    /// `0x5F2B` and DG12 `0x5F26`.
    ///
    /// # Errors
    /// See `Date::from_iso_date_string`.
    #[inline]
    pub fn from_yyyymmdd(bytes: [u8; 8]) -> Result<Self, Iso8601Error> {
        const PROD: &str = "YYYYMMDD";
        check_ascii_digits(&bytes, PROD, 0)?;
        let year = AsciiDigits::parse_u16(&bytes[0..4]);
        let month = AsciiDigits::parse_u8(&bytes[4..6]);
        let day = AsciiDigits::parse_u8(&bytes[6..8]);
        Self::new(year, month, day)
    }

    /// Parse the ICAO 9303-3 MRZ wire form `YYMMDD` (6 ASCII
    /// digits, no century) and resolve the century via the 50/50
    /// rule per ICAO 9303-3 §4.5: `YY < 50` => `20YY`,
    /// otherwise `19YY`.
    ///
    /// # Errors
    /// See `Date::from_iso_date_string`.
    #[inline]
    pub fn from_mrz_yymmdd(bytes: [u8; 6]) -> Result<Self, Iso8601Error> {
        const PROD: &str = "YYMMDD";
        check_ascii_digits(&bytes, PROD, 0)?;
        let yy = AsciiDigits::parse_u8(&bytes[0..2]);
        let month = AsciiDigits::parse_u8(&bytes[2..4]);
        let day = AsciiDigits::parse_u8(&bytes[4..6]);
        let year: u16 = if yy < 50 {
            2000 + u16::from(yy)
        } else {
            1900 + u16::from(yy)
        };
        Self::new(year, month, day)
    }

    /// Year component (1900..=2100).
    ///
    /// Representation-level accessor: meant for code that
    /// needs to drive a year-bearing API (e.g. `der::DateTime`
    /// for cert validity date math). Domain consumers go through
    /// role wrappers and their semantic projection ([`date`])
    /// before reaching this layer.
    ///
    /// [`date`]: crate::identity::DateOfBirth::date
    #[inline]
    #[must_use]
    pub const fn year(&self) -> u16 {
        self.year
    }

    /// Month component, 1..=12.
    #[inline]
    #[must_use]
    pub const fn month(&self) -> u8 {
        self.month
    }

    /// Day component, 1..=last-day-of(month, year).
    #[inline]
    #[must_use]
    pub const fn day(&self) -> u8 {
        self.day
    }

    /// Emit the ICAO 9303-10 wire form `YYYYMMDD`.
    #[inline]
    #[must_use]
    pub fn to_yyyymmdd(&self) -> String {
        format!("{:04}{:02}{:02}", self.year, self.month, self.day)
    }

    /// Emit the ICAO 9303-3 MRZ wire form `YYMMDD` (century
    /// stripped).
    #[inline]
    #[must_use]
    pub fn to_mrz_yymmdd(&self) -> String {
        format!("{:02}{:02}{:02}", self.year % 100, self.month, self.day)
    }
}

impl fmt::Display for Date {
    /// Canonical ISO 8601 extended calendar-date form
    /// (`YYYY-MM-DD`).
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

// =========================================================
// DateTime -- date + time + offset payload.
// =========================================================

impl DateTime {
    /// Construct from validated components.
    ///
    /// # Errors
    /// Field-range errors from [`Date::new`] for the date half;
    /// hour / minute / second / offset range errors otherwise.
    pub(crate) const fn new(
        date: Date,
        hour: u8,
        minute: u8,
        second: u8,
        offset: TimeOffset,
    ) -> Result<Self, Iso8601Error> {
        if hour > 23 {
            return Err(Iso8601Error::HourOutOfRange { hour });
        }
        if minute > 59 {
            return Err(Iso8601Error::MinuteOutOfRange { minute });
        }
        // Second 0..=60 to allow the ISO 8601 leap-second slot.
        if second > 60 {
            return Err(Iso8601Error::SecondOutOfRange { second });
        }
        if let Err(e) = validate_offset(offset) {
            return Err(e);
        }
        Ok(Self {
            date,
            hour,
            minute,
            second,
            offset,
        })
    }

    /// Parse the ICAO 9303-10 `YYYYMMDDhhmmss` 14-digit
    /// timestamp form (DG12 tag `0x5F55` personalisation
    /// timestamp). Naive datetime -- the wire form carries no
    /// offset, so [`TimeOffset::Unspecified`] is returned.
    ///
    /// # Errors
    /// [`Iso8601Error::ParseShape`] for wrong length;
    /// [`Iso8601Error::ParseChars`] for non-digit input;
    /// otherwise the per-field range errors.
    #[inline]
    pub fn from_yyyymmddhhmmss(bytes: [u8; 14]) -> Result<Self, Iso8601Error> {
        const PROD: &str = "YYYYMMDDhhmmss";
        check_ascii_digits(&bytes, PROD, 0)?;
        let year = AsciiDigits::parse_u16(&bytes[0..4]);
        let month = AsciiDigits::parse_u8(&bytes[4..6]);
        let day = AsciiDigits::parse_u8(&bytes[6..8]);
        let hour = AsciiDigits::parse_u8(&bytes[8..10]);
        let minute = AsciiDigits::parse_u8(&bytes[10..12]);
        let second = AsciiDigits::parse_u8(&bytes[12..14]);
        let date = Date::new(year, month, day)?;
        Self::new(date, hour, minute, second, TimeOffset::Unspecified)
    }

    // Field accessors land alongside the first consumer that
    // needs them. Display uses field access directly within
    // this module.
}

impl fmt::Display for DateTime {
    /// Canonical ISO 8601 form: `YYYY-MM-DDTHH:MM:SS` plus the
    /// offset suffix (`Z`, `+HH:MM`, `-HH:MM`, or nothing when
    /// [`TimeOffset::Unspecified`]).
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}T{:02}:{:02}:{:02}",
            self.date, self.hour, self.minute, self.second
        )?;
        match self.offset {
            TimeOffset::Unspecified => Ok(()),
            TimeOffset::Utc => f.write_str("Z"),
            TimeOffset::Plus { hours, minutes } => write!(f, "+{hours:02}:{minutes:02}"),
            TimeOffset::Minus { hours, minutes } => write!(f, "-{hours:02}:{minutes:02}"),
        }
    }
}

// =========================================================
// Iso8601 umbrella -- variant accessors + Display.
// =========================================================

impl Iso8601 {
    /// Borrow the calendar-date payload if this is the `Date`
    /// variant.
    #[inline]
    #[must_use]
    pub const fn as_date(&self) -> Option<&Date> {
        match self {
            Self::Date(d) => Some(d),
            Self::DateTime(_) => None,
        }
    }

    /// Borrow the date+time payload if this is the `DateTime`
    /// variant.
    #[inline]
    #[must_use]
    pub const fn as_datetime(&self) -> Option<&DateTime> {
        match self {
            Self::DateTime(dt) => Some(dt),
            Self::Date(_) => None,
        }
    }
}

impl fmt::Display for Iso8601 {
    /// Render the canonical ISO 8601 form for whichever variant
    /// is held.
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Date(d) => write!(f, "{d}"),
            Self::DateTime(dt) => write!(f, "{dt}"),
        }
    }
}

// =========================================================
// Private validation + parse helpers.
// =========================================================

/// Validate a `(year, month, day)` triple against the proleptic
/// Gregorian calendar over the year window
/// `YEAR_MIN..=YEAR_MAX`.
///
/// `const fn` so [`Date::new`] can call it from a `const`
/// context. Returns the most-specific error variant for the
/// first failure encountered (year, then month, then day) so
/// the caller's `Display` impl can blame the right field.
const fn validate_calendar(year: u16, month: u8, day: u8) -> Result<(), Iso8601Error> {
    if year < YEAR_MIN || year > YEAR_MAX {
        return Err(Iso8601Error::YearOutOfRange {
            year,
            min: YEAR_MIN,
            max: YEAR_MAX,
        });
    }
    if month < 1 || month > 12 {
        return Err(Iso8601Error::MonthOutOfRange { month });
    }
    let last_day = days_in_month(year, month);
    if day < 1 || day > last_day {
        return Err(Iso8601Error::DayOutOfRange { day, month, year });
    }
    Ok(())
}

/// Validate a [`TimeOffset`] against ISO 8601:2019 §5.4.2.1
/// (offset from UTC).
///
/// `Plus`/`Minus` hours are capped at 14 to admit known
/// production offsets (UTC+14 is the maximum civilian offset)
/// while still refusing nonsense like UTC+99. Minutes are
/// rejected above 59 -- ISO 8601 forbids the 60-minute leap-
/// second carry inside an offset.
const fn validate_offset(offset: TimeOffset) -> Result<(), Iso8601Error> {
    match offset {
        TimeOffset::Unspecified | TimeOffset::Utc => Ok(()),
        TimeOffset::Plus { hours, minutes } | TimeOffset::Minus { hours, minutes } => {
            // Wider than the practical max (UTC+14) leaves room
            // for off-spec emitters without admitting nonsense
            // like UTC+99.
            if hours > 14 {
                return Err(Iso8601Error::OffsetHoursOutOfRange { hours });
            }
            if minutes > 59 {
                return Err(Iso8601Error::OffsetMinutesOutOfRange { minutes });
            }
            Ok(())
        }
    }
}

/// Return the last calendar day of `month` in `year` per the
/// proleptic Gregorian calendar.
///
/// February uses the Gregorian leap-year rule: divisible by 4
/// AND (not divisible by 100 OR divisible by 400). The `_ => 0`
/// fall-through is safe because the caller (`validate_calendar`)
/// has already rejected `month` outside `1..=12`; the `0` lets
/// any downstream `day > last_day` check fail closed for an
/// out-of-range month.
const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            // Gregorian leap-year rule.
            let leap =
                year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
            if leap { 29 } else { 28 }
        }
        _ => 0,
    }
}

/// Verify every byte in `bytes` is ASCII `0..=9`. `slice_start`
/// is the source-string index of the first byte; errors index
/// into the *original* string for legibility.
fn check_ascii_digits(
    bytes: &[u8],
    production: &'static str,
    slice_start: usize,
) -> Result<(), Iso8601Error> {
    for (i, &b) in bytes.iter().enumerate() {
        if !b.is_ascii_digit() {
            return Err(Iso8601Error::ParseChars {
                production,
                // saturating_add: `slice_start` and `i` come from
                // local string offsets bounded by the input length
                // (<= isize::MAX); overflow is unreachable but the
                // saturating form is cheap and lint-clean.
                at: slice_start.saturating_add(i),
            });
        }
    }
    Ok(())
}

/// Unit struct hosting the infallible ASCII-digit accumulators
/// (typing-discipline: no free fns with borrowed parameters;
/// see `doc/typing-discipline.md`). Caller guarantees
/// [`check_ascii_digits`] passed; non-digit input yields a
/// wrong value, not a panic.
struct AsciiDigits;

impl AsciiDigits {
    /// Accumulate a pre-verified ASCII-digit slice into a `u16`.
    ///
    /// `wrapping_mul` / `wrapping_add` are deliberate: every call
    /// site in this module passes a slice of at most 4 ASCII
    /// digits (max 9999), well within `u16::MAX = 65535`, so the
    /// wrap shape is never reached in practice. The arithmetic
    /// here is a local accumulator, not a protocol value.
    fn parse_u16(bytes: &[u8]) -> u16 {
        bytes.iter().fold(0_u16, |acc, &b| {
            acc.wrapping_mul(10)
                .wrapping_add(u16::from(b.wrapping_sub(b'0')))
        })
    }

    /// Accumulate a pre-verified ASCII-digit slice into a `u8`.
    ///
    /// `wrapping_mul` / `wrapping_add` are deliberate: every call
    /// site passes at most 2 ASCII digits (max 99), well within
    /// `u8::MAX = 255`. See [`Self::parse_u16`].
    fn parse_u8(bytes: &[u8]) -> u8 {
        bytes.iter().fold(0_u8, |acc, &b| {
            acc.wrapping_mul(10).wrapping_add(b.wrapping_sub(b'0'))
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    // Tests propagate Result rather than .unwrap() per
    // doc/typing-discipline.md.

    #[test]
    fn date_constructs_in_range() -> Result<(), Iso8601Error> {
        let d = Date::new(1990, 5, 12)?;
        assert_eq!(d.year(), 1990);
        assert_eq!(d.month(), 5);
        assert_eq!(d.day(), 12);
        assert_eq!(format!("{d}"), "1990-05-12");
        Ok(())
    }

    #[test]
    fn date_accepts_leap_day() -> Result<(), Iso8601Error> {
        let _y2k: Date = Date::new(2000, 2, 29)?; // div by 400 -- leap
        let _y2004: Date = Date::new(2004, 2, 29)?; // div by 4, not 100
        Ok(())
    }

    #[test]
    fn date_rejects_non_leap_feb_29() {
        assert!(matches!(
            Date::new(1900, 2, 29),
            Err(Iso8601Error::DayOutOfRange { .. })
        ));
        assert!(matches!(
            Date::new(2001, 2, 29),
            Err(Iso8601Error::DayOutOfRange { .. })
        ));
    }

    #[test]
    fn date_rejects_year_out_of_range() {
        assert!(matches!(
            Date::new(1899, 1, 1),
            Err(Iso8601Error::YearOutOfRange { year: 1899, .. })
        ));
        assert!(matches!(
            Date::new(2101, 1, 1),
            Err(Iso8601Error::YearOutOfRange { year: 2101, .. })
        ));
    }

    #[test]
    fn date_rejects_month_out_of_range() {
        assert!(matches!(
            Date::new(2000, 0, 1),
            Err(Iso8601Error::MonthOutOfRange { month: 0 })
        ));
        assert!(matches!(
            Date::new(2000, 13, 1),
            Err(Iso8601Error::MonthOutOfRange { month: 13 })
        ));
    }

    #[test]
    fn date_rejects_day_31_in_short_month() {
        assert!(matches!(
            Date::new(2000, 4, 31),
            Err(Iso8601Error::DayOutOfRange { .. })
        ));
    }

    #[test]
    fn date_parses_iso_extended_form() -> Result<(), Iso8601Error> {
        let d = Date::from_iso_date_string("1974-11-30")?;
        assert_eq!(d.year(), 1974);
        assert_eq!(d.month(), 11);
        assert_eq!(d.day(), 30);
        Ok(())
    }

    #[test]
    fn date_iso_extended_rejects_wrong_separator() {
        assert!(matches!(
            Date::from_iso_date_string("1974/11/30"),
            Err(Iso8601Error::ParseChars { at: 4, .. })
        ));
    }

    #[test]
    fn date_parses_yyyymmdd() -> Result<(), Iso8601Error> {
        let d = Date::from_yyyymmdd(*b"19741130")?;
        assert_eq!(d.year(), 1974);
        assert_eq!(d.month(), 11);
        assert_eq!(d.day(), 30);
        assert_eq!(d.to_yyyymmdd(), "19741130");
        Ok(())
    }

    #[test]
    fn date_yyyymmdd_rejects_non_digits() {
        assert!(matches!(
            Date::from_yyyymmdd(*b"1974AB30"),
            Err(Iso8601Error::ParseChars { at: 4, .. })
        ));
    }

    #[test]
    fn date_parses_mrz_yymmdd_with_50_50_split() -> Result<(), Iso8601Error> {
        // YY < 50 -> 20YY, else 19YY.
        assert_eq!(Date::from_mrz_yymmdd(*b"740812")?.year(), 1974);
        assert_eq!(Date::from_mrz_yymmdd(*b"260520")?.year(), 2026);
        assert_eq!(Date::from_mrz_yymmdd(*b"490101")?.year(), 2049);
        assert_eq!(Date::from_mrz_yymmdd(*b"500101")?.year(), 1950);
        Ok(())
    }

    #[test]
    fn date_mrz_to_mrz_round_trips() -> Result<(), Iso8601Error> {
        let d = Date::from_mrz_yymmdd(*b"740812")?;
        assert_eq!(d.to_mrz_yymmdd(), "740812");
        // Display uses canonical ISO 8601 form, not on-card.
        assert_eq!(format!("{d}"), "1974-08-12");
        Ok(())
    }

    #[test]
    fn date_mrz_rejects_bad_month() {
        assert!(matches!(
            Date::from_mrz_yymmdd(*b"741312"),
            Err(Iso8601Error::MonthOutOfRange { month: 13 })
        ));
    }

    #[test]
    fn date_mrz_rejects_non_digits() {
        assert!(matches!(
            Date::from_mrz_yymmdd(*b"<<<<<<"),
            Err(Iso8601Error::ParseChars { at: 0, .. })
        ));
    }

    #[test]
    fn datetime_constructs_and_renders_utc() -> Result<(), Iso8601Error> {
        let date = Date::new(2021, 1, 1)?;
        let dt = DateTime::new(date, 14, 30, 0, TimeOffset::Utc)?;
        assert_eq!(format!("{dt}"), "2021-01-01T14:30:00Z");
        Ok(())
    }

    #[test]
    fn datetime_renders_unspecified_offset() -> Result<(), Iso8601Error> {
        let date = Date::new(2021, 1, 1)?;
        let dt = DateTime::new(date, 14, 30, 0, TimeOffset::Unspecified)?;
        // No suffix when the wire form didn't carry one.
        assert_eq!(format!("{dt}"), "2021-01-01T14:30:00");
        Ok(())
    }

    #[test]
    fn datetime_renders_plus_offset() -> Result<(), Iso8601Error> {
        let date = Date::new(2021, 1, 1)?;
        let dt = DateTime::new(
            date,
            14,
            30,
            0,
            TimeOffset::Plus {
                hours: 2,
                minutes: 0,
            },
        )?;
        assert_eq!(format!("{dt}"), "2021-01-01T14:30:00+02:00");
        Ok(())
    }

    #[test]
    fn datetime_renders_minus_offset() -> Result<(), Iso8601Error> {
        let date = Date::new(2021, 1, 1)?;
        let dt = DateTime::new(
            date,
            14,
            30,
            0,
            TimeOffset::Minus {
                hours: 5,
                minutes: 30,
            },
        )?;
        assert_eq!(format!("{dt}"), "2021-01-01T14:30:00-05:30");
        Ok(())
    }

    #[test]
    fn datetime_rejects_hour_out_of_range() -> Result<(), Iso8601Error> {
        let date = Date::new(2021, 1, 1)?;
        assert!(matches!(
            DateTime::new(date, 24, 0, 0, TimeOffset::Utc),
            Err(Iso8601Error::HourOutOfRange { hour: 24 })
        ));
        Ok(())
    }

    #[test]
    fn datetime_accepts_leap_second() -> Result<(), Iso8601Error> {
        let date = Date::new(2016, 12, 31)?;
        // 23:59:60 -- the 2016-12-31 leap second.
        let dt = DateTime::new(date, 23, 59, 60, TimeOffset::Utc)?;
        assert_eq!(format!("{dt}"), "2016-12-31T23:59:60Z");
        Ok(())
    }

    #[test]
    fn iso8601_date_variant_round_trips() -> Result<(), Iso8601Error> {
        let d = Date::new(1974, 11, 30)?;
        let value = Iso8601::Date(d);
        assert_eq!(format!("{value}"), "1974-11-30");
        assert_eq!(value.as_date(), Some(&d));
        assert_eq!(value.as_datetime(), None);
        Ok(())
    }

    #[test]
    fn iso8601_datetime_variant_round_trips() -> Result<(), Iso8601Error> {
        let date = Date::new(2021, 1, 1)?;
        let dt = DateTime::new(date, 14, 30, 0, TimeOffset::Utc)?;
        let value = Iso8601::DateTime(dt);
        assert_eq!(format!("{value}"), "2021-01-01T14:30:00Z");
        assert_eq!(value.as_datetime(), Some(&dt));
        assert_eq!(value.as_date(), None);
        Ok(())
    }

    #[test]
    fn time_offset_unspecified_is_distinct_from_utc() {
        // The whole point of the explicit variant.
        assert_ne!(TimeOffset::Unspecified, TimeOffset::Utc);
    }
}
