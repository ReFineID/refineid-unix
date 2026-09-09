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

//! Centralized `User-Agent` policy for refineid's outbound HTTP.
//!
//! Every outbound HTTP request goes through one of two paths:
//!
//! - **Honest** ([`honest`]): the default. RFC 7231 §5.5.3
//!   product/version shape carrying `ReFineID/<version>
//!   (+https://www.refineid.fi/)`. Used for everything that
//!   accepts a non-browser identity -- CRL distribution points,
//!   OCSP responders, AIA caIssuers, etc. This is the right
//!   identity to send: it lets endpoint operators contact the
//!   project, makes our traffic auditable in their logs, and
//!   doesn't pretend to be something refineid isn't.
//!
//! - **Masquerade** ([`masquerade_as_browser`]): a desktop-
//!   browser-shaped string, used **only** at specific endpoints
//!   that refuse non-browser User-Agents. Every call site that
//!   masquerades MUST hand a [`MasqueradeReason`] to the
//!   helper -- the type makes the workaround impossible to
//!   sneak through code review.
//!
//! ## Audit trail
//!
//! New masquerade reasons live in [`KNOWN_MASQUERADES`]. Adding
//! one is a deliberate, reviewable act with three fields: which
//! host, why, since when. To audit the full set of endpoints
//! the project ever lies to, grep this module.
//!
//! The browser identity returned by [`masquerade_as_browser`]
//! is a snapshot of a recent Firefox on Linux desktop; refresh
//! [`BROWSER_UA_SET_ON`] / `BROWSER_UA` when servers start
//! rejecting it.
//!
//! ## What this module DOES NOT do
//!
//! - It does not let callers pass an arbitrary UA string. Only
//!   `honest()` and `masquerade_as_browser(reason)` are exposed.
//! - It does not embed per-install state (hostname, reader,
//!   user) in either UA. The UA ends up in CDN / CA / responder
//!   logs and per the project's
//!   [[no-local-transport-in-portable-artifacts]] rule must
//!   carry only intrinsic project state.

/// Honest `User-Agent` string sent to every well-behaved
/// endpoint. RFC 7231 §5.5.3 `product/version (comment)` shape.
///
/// The version comes from `REFINEID_VERSION` at compile time
/// so it tracks the workspace and can't go stale. The contact
/// URL lets server operators reach the project if our traffic
/// causes them issues.
const HONEST: &str = concat!(
    "ReFineID/",
    env!("REFINEID_VERSION"),
    " (+https://www.refineid.fi/)"
);

/// A documented endpoint exception where refineid sends a
/// browser-shaped `User-Agent` instead of the honest one.
///
/// Every masquerade call site builds (or references) one of
/// these. Reviewers should ensure every new instance is
/// justified -- the workaround should be a last resort, applied
/// only when an endpoint refuses the honest identity and there
/// is no operator-side fix available.
#[derive(Debug, Clone, Copy)]
pub struct MasqueradeReason {
    /// Host the workaround applies to (e.g. `"example.gov"`).
    pub host: &'static str,
    /// One-sentence explanation of why the honest UA was
    /// refused (`"403 on every refineid UA, accepts Firefox"`).
    pub why: &'static str,
    /// ISO 8601 date the workaround was added. Lets reviewers
    /// re-test stale entries -- endpoint UA sniffs sometimes
    /// soften over time.
    pub added_on: &'static str,
}

/// Registry of every endpoint at which refineid masquerades as
/// a desktop browser. Empty by design: each addition needs a
/// reviewed justification.
///
/// Adding an entry isn't sufficient on its own -- a call site
/// also has to invoke [`masquerade_as_browser`] with that
/// entry. The registry serves as the audit-trail anchor: grep
/// for `KNOWN_MASQUERADES` (the list) and `masquerade_as_browser`
/// (the actual lies) to enumerate the surface.
pub const KNOWN_MASQUERADES: &[MasqueradeReason] = &[
    // No entries today. The honest UA has been accepted by
    // every endpoint the project hits (DVV CRLs, DVV OCSP,
    // AIA caIssuers). Add an entry here if and only if a real
    // endpoint refuses honest identification.
];

/// Browser-shaped fake UA returned by [`masquerade_as_browser`].
/// Snapshot of a recent stable Firefox on Linux desktop --
/// vanilla enough to bypass naive UA sniffs without picking a
/// fingerprintable corner of the User-Agent space.
const BROWSER_UA: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";

/// ISO date `BROWSER_UA` was last refreshed. If servers start
/// rejecting our masquerade, bump both this constant and
/// `BROWSER_UA` to a current browser snapshot.
pub const BROWSER_UA_SET_ON: &str = "2026-05-24";

/// Honest `User-Agent` for refineid's outbound HTTP. Default
/// for every endpoint that accepts a project-identified client.
#[must_use]
pub const fn honest() -> &'static str {
    HONEST
}

/// Browser-shaped `User-Agent` for endpoints that refuse the
/// honest identity.
///
/// The `_reason` parameter is unused in the returned string
/// but is mandatory at the call site so every masquerade can
/// be grep-located alongside its justification.
///
/// Implementations should pass a reference to one of the
/// [`KNOWN_MASQUERADES`] entries; constructing a one-off
/// [`MasqueradeReason`] inline is allowed but discouraged --
/// the registry is what makes the surface auditable.
#[must_use]
pub const fn masquerade_as_browser(_reason: &MasqueradeReason) -> &'static str {
    BROWSER_UA
}

#[cfg(test)]
mod tests {
    use super::{BROWSER_UA_SET_ON, HONEST, MasqueradeReason, masquerade_as_browser};

    #[test]
    fn honest_carries_version_and_contact_url() {
        assert!(HONEST.starts_with("ReFineID/"), "honest UA was {HONEST:?}");
        assert!(
            HONEST.contains(env!("REFINEID_VERSION")),
            "honest UA missing version: {HONEST:?}"
        );
        assert!(
            HONEST.contains("refineid.fi"),
            "honest UA missing contact URL: {HONEST:?}"
        );
    }

    #[test]
    fn masquerade_looks_like_firefox() {
        let reason = MasqueradeReason {
            host: "example.test",
            why: "synthetic test",
            added_on: "2026-05-24",
        };
        let ua = masquerade_as_browser(&reason);
        assert!(ua.starts_with("Mozilla/5.0"), "masquerade was {ua:?}");
        assert!(
            ua.contains("Firefox/"),
            "masquerade missing Firefox token: {ua:?}"
        );
    }

    #[test]
    fn browser_ua_set_on_is_iso_date() {
        // Bumping BROWSER_UA without bumping BROWSER_UA_SET_ON
        // would let stale entries linger; pin the shape so the
        // pair stays coupled.
        assert_eq!(BROWSER_UA_SET_ON.len(), 10_usize);
        assert_eq!(BROWSER_UA_SET_ON.get(4..5), Some("-"));
        assert_eq!(BROWSER_UA_SET_ON.get(7..8), Some("-"));
    }
}
