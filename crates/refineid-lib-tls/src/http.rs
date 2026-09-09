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

//! TLS-agnostic HTTP/1.1 protocol types: cookie jar, response
//! parser, form encoding. No I/O -- the byte moving lives in the
//! backend clients.
//!
//! URLs are the single [`refineid_lib_core::text::Uri`] type
//! (scheme / host / port / path / query, validated and
//! reconstructable); this module builds the cookie jar, the
//! `Set-Cookie`/response parsers, and form encoding on top of it.

use core::fmt;
use std::collections::HashMap;

use refineid_lib_core::text::{Host, Scheme, Uri, UriError};

/// Backward-compatible alias for the older `UrlParts` name used by
/// the bridge branch.
pub type UrlParts = Uri;
/// Backward-compatible alias for the older `UrlError` name used by
/// the bridge branch.
pub type UrlError = UriError;

/// Separator between the HTTP head and body (RFC 9112 §2.1).
const HEAD_BODY_SEPARATOR: &[u8] = b"\r\n\r\n";

// ----- Status -----

/// HTTP status code. Tier-0 `u16` wrapped so consumers match on
/// typed helpers instead of bare numerals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HttpStatus(u16);

impl HttpStatus {
    /// Wrap a raw status code.
    #[must_use]
    pub const fn new(code: u16) -> Self {
        Self(code)
    }

    /// The raw code for logging / exit-code mapping.
    #[must_use]
    pub const fn code(&self) -> u16 {
        self.0
    }

    /// `2xx`?
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.0 >= 200 && self.0 <= 299
    }

    /// A redirect status this client follows (RFC 9110 §15.4:
    /// 301 / 302 / 303 / 307 / 308).
    #[must_use]
    pub const fn is_redirect(&self) -> bool {
        matches!(self.0, 301 | 302 | 303 | 307 | 308)
    }

    /// `true` for 303 See Other and (per long-standing browser
    /// behaviour, RFC 9110 §15.4.3) 301/302 after a POST: the
    /// redirect is followed with GET.
    #[must_use]
    pub const fn redirect_switches_to_get(&self) -> bool {
        matches!(self.0, 301..=303)
    }
}

impl fmt::Display for HttpStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ----- Cookies -----

/// One raw `Set-Cookie` header value, as received.
#[derive(Debug, Clone)]
pub struct SetCookie(String);

impl SetCookie {
    /// Wrap a raw header value.
    #[must_use]
    pub const fn new(raw: String) -> Self {
        Self(raw)
    }

    /// Parse into a typed [`Cookie`] scoped to `from_host`.
    /// Returns `None` for values without a `name=value` lead.
    /// The `Domain=` attribute is deliberately ignored -- the
    /// cookies these flows chase are host-scoped (`__Host-`
    /// style), and honouring `Domain=` is a security minefield.
    #[must_use]
    pub fn parse(&self, from_host: &Host) -> Option<Cookie> {
        let mut parts = self.0.split(';');
        let lead = parts.next()?.trim();
        let (name, value) = lead.split_once('=')?;
        let mut path = "/".to_owned();
        let mut secure = false;
        for attribute in parts {
            let attribute = attribute.trim();
            if attribute.eq_ignore_ascii_case("Secure") {
                secure = true;
            } else if let Some((key, val)) = attribute.split_once('=')
                && key.trim().eq_ignore_ascii_case("Path")
            {
                val.trim().clone_into(&mut path);
            } else {
                // Other attributes (Domain=, Expires=, SameSite=,
                // HttpOnly) are deliberately ignored; see the
                // SetCookie::parse docstring.
            }
        }
        Some(Cookie {
            name: name.trim().to_owned(),
            value: value.trim().to_owned(),
            host: from_host.clone(),
            path,
            secure,
        })
    }
}

/// One stored cookie: the minimum attribute set RFC 6265 §5.3
/// needs for these auth flows.
#[derive(Debug, Clone)]
pub struct Cookie {
    /// Cookie name.
    pub name: String,
    /// Cookie value.
    pub value: String,
    /// Host the `Set-Cookie` came from (host-only scoping).
    pub host: Host,
    /// `Path=` attribute, default `/`.
    pub path: String,
    /// `Secure` attribute present.
    pub secure: bool,
}

impl Cookie {
    /// Does this cookie apply to a request to `target`? Host
    /// must match (host-only scoping), the path must match per
    /// RFC 6265 §5.1.4, and `Secure` cookies require https.
    fn applies_to(&self, target: &Uri) -> bool {
        // Both hosts are lowercased at construction, so `==` is the
        // case-insensitive host match (host-only scoping).
        if self.host != *target.host() {
            return false;
        }
        if self.secure && target.scheme() != Scheme::Https {
            return false;
        }
        // RFC 6265 §5.1.4 path-match is string-prefix work, so
        // the caller renders the typed path here at the boundary.
        let request_path = target.path().to_string();
        if self.path == "/" || request_path == self.path {
            return true;
        }
        if let Some(tail) = request_path.strip_prefix(self.path.as_str()) {
            return self.path.ends_with('/') || tail.starts_with('/');
        }
        false
    }
}

/// Host-scoped cookie store shared across the hops of one login
/// flow.
#[derive(Debug, Default)]
pub struct CookieJar {
    /// Stored cookies, replace-on-(host, path, name)-collision.
    cookies: Vec<Cookie>,
}

impl CookieJar {
    /// Empty jar.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Iterate the stored cookies (Netscape `cookies.txt`
    /// export, diagnostics).
    pub fn iter(&self) -> impl Iterator<Item = &Cookie> {
        self.cookies.iter()
    }

    /// Merge every `Set-Cookie` from `response` into the jar,
    /// scoped to the response's host. Same-(host, path, name)
    /// cookies are replaced.
    pub fn ingest(&mut self, response: &Response) {
        let from_host = response.final_url.host().clone();
        for raw in &response.set_cookies {
            if let Some(cookie) = raw.parse(&from_host) {
                self.cookies.retain(|existing| {
                    !(existing.host == cookie.host
                        && existing.path == cookie.path
                        && existing.name == cookie.name)
                });
                self.cookies.push(cookie);
            }
        }
    }

    /// Build the `Cookie:` header value for a request to
    /// `target`; `None` when nothing matches.
    #[must_use]
    pub fn header_for(&self, target: &Uri) -> Option<String> {
        let pairs: Vec<String> = self
            .cookies
            .iter()
            .filter(|cookie| cookie.applies_to(target))
            .map(|cookie| format!("{}={}", cookie.name, cookie.value))
            .collect();
        if pairs.is_empty() {
            None
        } else {
            Some(pairs.join("; "))
        }
    }
}

// ----- Response -----

/// Why a raw HTTP response failed to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HttpParseError {
    /// No `CRLF CRLF` head/body separator found.
    NoHeadTerminator,
    /// Head bytes were not UTF-8.
    HeadNotUtf8,
    /// Status line missing or its code unparseable.
    MalformedStatusLine,
}

impl fmt::Display for HttpParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoHeadTerminator => f.write_str("no end-of-headers marker in HTTP response"),
            Self::HeadNotUtf8 => f.write_str("HTTP head is not UTF-8"),
            Self::MalformedStatusLine => f.write_str("malformed HTTP status line"),
        }
    }
}

impl core::error::Error for HttpParseError {}

/// Parsed HTTP response.
#[derive(Debug, Clone)]
pub struct Response {
    /// Status code.
    pub status: HttpStatus,
    /// Headers, keys lowercased. `Set-Cookie` is excluded (it is
    /// multi-valued; see [`Response::set_cookies`]).
    pub headers: HashMap<String, String>,
    /// Every `Set-Cookie` value, in arrival order.
    pub set_cookies: Vec<SetCookie>,
    /// Response body bytes.
    pub body: Vec<u8>,
    /// The URL this response was served from (after the client's
    /// redirect following).
    pub final_url: Uri,
}

impl Response {
    /// Parse the raw response bytes a backend read off its TLS
    /// stream. `requested_url` becomes [`Response::final_url`].
    ///
    /// # Errors
    /// [`HttpParseError`] on a malformed head.
    pub fn parse(raw: Vec<u8>, requested_url: &Uri) -> Result<Self, HttpParseError> {
        let head_end = raw
            .windows(HEAD_BODY_SEPARATOR.len())
            .position(|window| window == HEAD_BODY_SEPARATOR)
            .ok_or(HttpParseError::NoHeadTerminator)?;
        let body_start = head_end.saturating_add(HEAD_BODY_SEPARATOR.len());
        let mut buffer = raw;
        let body = buffer.split_off(body_start.min(buffer.len()));
        buffer.truncate(head_end);
        let head = String::from_utf8(buffer).map_err(|_utf8_error| HttpParseError::HeadNotUtf8)?;

        let mut lines = head.split("\r\n");
        let status_line = lines.next().ok_or(HttpParseError::MalformedStatusLine)?;
        let mut status_parts = status_line.splitn(3, ' ');
        let _version = status_parts.next();
        let status_code: u16 = status_parts
            .next()
            .and_then(|code| code.parse().ok())
            .ok_or(HttpParseError::MalformedStatusLine)?;

        let mut headers: HashMap<String, String> = HashMap::new();
        let mut set_cookies: Vec<SetCookie> = Vec::new();
        for line in lines {
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim().to_owned();
                if key == "set-cookie" {
                    set_cookies.push(SetCookie::new(value));
                } else {
                    headers.insert(key, value);
                }
            }
        }

        Ok(Self {
            status: HttpStatus::new(status_code),
            headers,
            set_cookies,
            body,
            final_url: requested_url.clone(),
        })
    }

    /// Body decoded as UTF-8 (lossy) -- convenience for the
    /// `text/html` responses these flows actually hit.
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

// ----- Percent-encoding -----

/// A token in percent-encoded **wire form** (the
/// `application/x-www-form-urlencoded` / query-string encoding over
/// the RFC 3986 §2.3 unreserved set `A-Za-z0-9-_.~`).
///
/// The type exists to keep encoded and decoded text from being
/// silently interchanged -- the bug class behind double-encoding.
/// `str::percent_encoded` is the
/// only path from plaintext, so encoding a value twice cannot be
/// written without an explicit, conspicuous round-trip through
/// [`as_wire`](Self::as_wire). There is deliberately **no** runtime
/// "is this already encoded?" heuristic: `%` is legal plaintext, so
/// such a guess would silently corrupt legitimate values (and, on
/// the SAML path, break a signature digest). Double-encoding is made
/// unrepresentable at the type level instead of detected after the
/// fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PercentEncoded(String);

impl PercentEncoded {
    /// Wrap a token that is **already** in wire form (e.g. a query
    /// value scraped verbatim from a URL). The name makes the
    /// caller's "I vouch this is encoded" assumption visible at the
    /// call site; no encoding happens.
    #[must_use]
    pub const fn from_wire(encoded: String) -> Self {
        Self(encoded)
    }

    /// The encoded wire form, for building a URL query or request
    /// body.
    #[must_use]
    pub const fn as_wire(&self) -> &str {
        self.0.as_str()
    }

    /// Percent-encode decoded plaintext: every byte outside the
    /// RFC 3986 §2.3 unreserved set (`A-Za-z0-9-_.~`) becomes
    /// `%XX` (upper-case hex), spaces included (`%20`, never `+`).
    /// The single typed encoder for callers building a query value
    /// from plaintext (e.g. an OIDC `redirect_uri`); the internal
    /// `PercentEncode` trait delegates here so there is one
    /// encoding, not two that can drift. `pub(crate)`: no
    /// cross-crate caller builds from raw plaintext (external code
    /// goes through [`Form`]).
    #[must_use]
    pub(crate) fn encode(plaintext: &str) -> Self {
        use core::fmt::Write as _;
        let mut out = String::with_capacity(plaintext.len());
        for byte in plaintext.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(char::from(byte));
                }
                _ => {
                    let _fmt: fmt::Result = write!(out, "%{byte:02X}");
                }
            }
        }
        Self(out)
    }

    /// Decode back to plaintext: each `%XX` becomes its byte; a `%`
    /// not followed by two hex digits is left literal; the result is
    /// UTF-8 decoded lossily. The inverse of
    /// `percent_encoded` for
    /// anything it produces. (`+` is left literal -- this encoder
    /// emits `%20` for spaces, never `+`.)
    #[must_use]
    pub fn decode(&self) -> String {
        // The two-hex-digit escape at `raw[at]` (the `%`), or None
        // when fewer than two follow or either is not a hex digit.
        // A local closure, not a fn: keeps a raw `&[u8]` out of the
        // crate's signatures (typing-discipline Rule B).
        let raw = self.0.as_bytes();
        let hex_escape_at = |at: usize| -> Option<u8> {
            let hi = raw.get(at.checked_add(1)?)?;
            let lo = raw.get(at.checked_add(2)?)?;
            if !hi.is_ascii_hexdigit() || !lo.is_ascii_hexdigit() {
                return None;
            }
            // `is_ascii_hexdigit` excludes the sign chars
            // `from_str_radix` would accept, so the parse is total
            // over [0, 255].
            let pair = [*hi, *lo];
            let text = core::str::from_utf8(&pair).ok()?;
            u8::from_str_radix(text, 16).ok()
        };
        let mut out: Vec<u8> = Vec::with_capacity(raw.len());
        let mut idx: usize = 0;
        while let Some(&byte) = raw.get(idx) {
            let escape = (byte == b'%').then(|| hex_escape_at(idx)).flatten();
            if let Some(value) = escape {
                out.push(value);
                idx = idx.saturating_add(3);
            } else {
                out.push(byte);
                idx = idx.saturating_add(1);
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }
}

/// Percent-encode decoded plaintext into [`PercentEncoded`] wire
/// form.
///
/// An extension trait on the text rather than a free encoder taking
/// raw `str`: the conversion attaches to the value it transforms (the
/// sanctioned receiver form -- see typing-discipline Rule B / "Audit
/// Greps"), which both reads as `value.percent_encoded()` and keeps a
/// borrowed raw parameter off the crate's function signatures.
/// `pub(crate)`: no cross-crate caller needs raw encoding (external
/// code builds a [`Form`] of decoded [`FormField`]s and calls
/// [`Form::urlencoded`]).
pub(crate) trait PercentEncode {
    /// This text, with every byte outside the RFC 3986 §2.3
    /// unreserved set (`A-Za-z0-9-_.~`) replaced by `%XX` (upper-case
    /// hex).
    fn percent_encoded(&self) -> PercentEncoded;
}

impl PercentEncode for str {
    fn percent_encoded(&self) -> PercentEncoded {
        PercentEncoded::encode(self)
    }
}

// ----- Forms -----

/// One `name=value` form field. The name/value are **decoded
/// plaintext**; [`Form::urlencoded`] percent-encodes them for the
/// wire (see [`PercentEncoded`]).
#[derive(Debug, Clone)]
pub struct FormField {
    /// Field name, decoded plaintext.
    pub name: String,
    /// Field value, decoded plaintext.
    pub value: String,
}

/// An `application/x-www-form-urlencoded` body under
/// construction.
#[derive(Debug, Clone, Default)]
pub struct Form {
    /// Fields in submission order.
    fields: Vec<FormField>,
}

impl Form {
    /// Empty form.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one field.
    pub fn push(&mut self, field: FormField) {
        self.fields.push(field);
    }

    /// Number of fields (observability events log counts, never
    /// contents).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.fields.len()
    }

    /// `true` when no fields have been pushed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Encode as the request body (RFC 1866 §8.2.1
    /// percent-encoding with the unreserved set of RFC 3986
    /// §2.3). Each field's decoded name/value is encoded exactly
    /// once via [`PercentEncoded`].
    #[must_use]
    pub fn urlencoded(&self) -> String {
        let mut out = String::new();
        for (index, field) in self.fields.iter().enumerate() {
            if index > 0 {
                out.push('&');
            }
            out.push_str(field.name.percent_encoded().as_wire());
            out.push('=');
            out.push_str(field.value.percent_encoded().as_wire());
        }
        out
    }
}

impl FromIterator<FormField> for Form {
    fn from_iter<I: IntoIterator<Item = FormField>>(iter: I) -> Self {
        Self {
            fields: iter.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    // Allow-free tests: failures surface through assert! only.

    use super::{Form, FormField, HttpStatus, PercentEncoded, Response, SetCookie, Uri};
    // Method-syntax only -- bring the extension trait into scope
    // anonymously so `.percent_encoded()` resolves.
    use super::PercentEncode as _;

    // URL parsing / redirect joining are exercised by the `Uri` type
    // itself in refineid-lib-core (text.rs); these tests cover the
    // lib-tls cookie jar and response parser that build on it.

    /// Cookie jar: ingest scopes to the response host; the header
    /// builder honours host / path / secure.
    #[test]
    fn cookie_jar_scoping() {
        let parsed = Uri::parse("https://kortti.example/auth/login".to_owned()).ok();
        assert!(parsed.is_some(), "url must parse");
        let Some(secure_url) = parsed else {
            return; // unreachable: asserted above
        };
        let response = Response {
            status: HttpStatus::new(200),
            headers: std::collections::HashMap::new(),
            set_cookies: vec![
                SetCookie::new("SESSION=abc; Path=/auth; Secure".to_owned()),
                SetCookie::new("plain=1".to_owned()),
            ],
            body: Vec::new(),
            final_url: secure_url.clone(),
        };
        let mut jar = super::CookieJar::new();
        jar.ingest(&response);
        assert_eq!(jar.iter().count(), 2);

        let header = jar.header_for(&secure_url).unwrap_or_default();
        assert!(header.contains("SESSION=abc"), "got: {header}");
        assert!(header.contains("plain=1"), "got: {header}");

        // Path scoping: /other does not match /auth.
        let other_header = Uri::parse("https://kortti.example/other".to_owned())
            .ok()
            .and_then(|other| jar.header_for(&other))
            .unwrap_or_default();
        assert!(!other_header.contains("SESSION"), "got: {other_header}");

        // Secure cookies don't cross to http://.
        let insecure_header = Uri::parse("http://kortti.example/auth/login".to_owned())
            .ok()
            .and_then(|insecure| jar.header_for(&insecure))
            .unwrap_or_default();
        assert!(
            !insecure_header.contains("SESSION"),
            "got: {insecure_header}"
        );

        // Other hosts see nothing.
        if let Ok(foreign) = Uri::parse("https://evil.example/auth/login".to_owned()) {
            assert!(jar.header_for(&foreign).is_none());
        }
    }

    /// Response parsing: status, headers, multi-valued
    /// Set-Cookie, body split.
    #[test]
    fn response_parse_splits_head_and_body() {
        let raw = b"HTTP/1.1 302 Found\r\n\
            Location: /next\r\n\
            Set-Cookie: a=1\r\n\
            Set-Cookie: b=2; Path=/x\r\n\
            Content-Type: text/html\r\n\
            \r\n\
            <html>body</html>"
            .to_vec();
        let parsed = Uri::parse("https://idp.example/start".to_owned()).ok();
        assert!(parsed.is_some(), "url must parse");
        let Some(url) = parsed else {
            return; // unreachable: asserted above
        };
        let ok = match Response::parse(raw, &url) {
            Ok(response) => {
                assert_eq!(response.status.code(), 302);
                assert!(response.status.is_redirect());
                assert!(response.status.redirect_switches_to_get());
                assert_eq!(
                    response.headers.get("location").map(String::as_str),
                    Some("/next")
                );
                assert_eq!(response.set_cookies.len(), 2);
                assert_eq!(response.text(), "<html>body</html>");
                true
            }
            Err(_) => false,
        };
        assert!(ok, "response must parse");
        assert!(matches!(
            Response::parse(b"garbage".to_vec(), &url),
            Err(super::HttpParseError::NoHeadTerminator)
        ));
    }

    /// Form encoding percent-encodes outside the unreserved set
    /// and preserves field order.
    #[test]
    fn form_urlencoding() {
        let form: Form = [
            FormField {
                name: "_csrf".to_owned(),
                value: "a b+c".to_owned(),
            },
            FormField {
                name: "redirectUrl".to_owned(),
                value: "/x?y=1".to_owned(),
            },
        ]
        .into_iter()
        .collect();
        assert_eq!(form.len(), 2);
        assert!(!form.is_empty());
        assert_eq!(
            form.urlencoded(),
            "_csrf=a%20b%2Bc&redirectUrl=%2Fx%3Fy%3D1"
        );
    }

    /// `PercentEncoded`: encode covers the reserved set, wrap is
    /// verbatim, and decode inverts encode (round-trip).
    #[test]
    fn percent_encoded_roundtrip() {
        // encode: unreserved survive, everything else -> %XX.
        assert_eq!("a b+c".percent_encoded().as_wire(), "a%20b%2Bc");
        assert_eq!("/x?y=1".percent_encoded().as_wire(), "%2Fx%3Fy%3D1");
        assert_eq!("-_.~AZaz09".percent_encoded().as_wire(), "-_.~AZaz09");

        // from_wire is verbatim (no encoding).
        assert_eq!(
            PercentEncoded::from_wire("already%2Fencoded".to_owned()).as_wire(),
            "already%2Fencoded"
        );

        // decode inverts encode for tricky plaintext (UTF-8, reserved).
        // "\u{e4}/\u{f6}?x=1" == "ä/ö?x=1" (escaped to keep the
        // source ASCII; exercises multi-byte UTF-8 round-tripping).
        for plain in ["/frontpage", "a b+c", "\u{e4}/\u{f6}?x=1", "100%", ""] {
            assert_eq!(
                plain.percent_encoded().decode(),
                plain,
                "round-trip for {plain:?}"
            );
        }
    }

    /// The whole point of the type: a re-encode double-encodes, and
    /// only the explicit decode-first path is idempotent.
    #[test]
    fn percent_encoded_blocks_double_encoding() {
        let once = "/frontpage".percent_encoded();
        assert_eq!(once.as_wire(), "%2Ffrontpage");

        // Re-encoding the *wire* form (the bug) mangles the '%'.
        let twice = once.as_wire().percent_encoded();
        assert_eq!(twice.as_wire(), "%252Ffrontpage");
        assert_ne!(twice.as_wire(), once.as_wire());

        // The correct round-trip (decode back to plaintext, re-encode)
        // is idempotent -- this is the path the types make you write.
        assert_eq!(once.decode().percent_encoded().as_wire(), once.as_wire());
    }

    /// decode leaves malformed escapes literal (no panic, no guess).
    #[test]
    fn percent_decode_tolerates_malformed_escapes() {
        assert_eq!(
            PercentEncoded::from_wire("100%".to_owned()).decode(),
            "100%"
        );
        assert_eq!(PercentEncoded::from_wire("a%2".to_owned()).decode(), "a%2");
        assert_eq!(
            PercentEncoded::from_wire("a%zzb".to_owned()).decode(),
            "a%zzb"
        );
        // A valid escape adjacent to a literal '%'.
        assert_eq!(
            PercentEncoded::from_wire("%25%20".to_owned()).decode(),
            "% "
        );
    }
}
