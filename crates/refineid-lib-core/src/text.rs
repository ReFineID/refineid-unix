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

//! String refinement types: text validated to a narrow charset.
//!
//! The string half of the refinement-type discipline (see
//! `doc/typing-discipline.md` "Refinement types"); the byte half is
//! the `[u8]` newtypes elsewhere in this crate (`Aid`, `Sha256`,
//! ...). A bare `&str`/`String` admits any Unicode -- emoji, control
//! characters, homoglyphs, attacker-chosen bytes -- so it is the
//! *absence* of a gate. A refinement type is the gate: a base type
//! plus a predicate, whose constructor admits only the characters
//! its charset allows and rejects everything else ("denies aliens")
//! at the boundary, so a value of the type is proof the text is
//! well-formed.
//!
//! # The family
//!
//! Members are named `<Charset>String` and grow along two axes --
//! **width** (which characters) and **case** (the base name is the
//! permissive both-case form; the `Lower` prefix is the stricter
//! lower-only variant). You always pick the **narrowest member that
//! fits the value**:
//!
//! - [`AlphaString`] / [`LowerAlphaString`] -- `[A-Za-z]` / `[a-z]`.
//! - [`AlphaNumString`] / [`LowerAlphaNumString`] -- `[A-Za-z0-9]` /
//!   `[a-z0-9]`.
//! - [`TokenString`] / [`LowerTokenString`] -- the above plus
//!   `. _ -` (dotted / snake protocol tokens, e.g.
//!   `telia.ftn.oidc.hst.1`, `rsa_pkcs1_sha256`).
//! - [`Uri`] -- the one URL type: it deconstructs an `http(s)` URL
//!   into validated components ([`Scheme`], [`Host`], port, [`Path`],
//!   [`Query`]) and reconstructs via `Display`. Each string-shaped
//!   component is itself a refined type, so structural validation
//!   (RFC 3986 charset, RFC 7230 length, RFC 1123 host) falls out of
//!   construction. A `Uri` is a URL, not a string -- it has no
//!   `as_str`; ask it for typed components or render it.
//!
//! Grow the family deliberately, one charset at a time, only when a
//! real value needs it; never reach for a wider type than the data.
//! Human / free text (names that carry non-ASCII letters) is *not*
//! in this ASCII family -- it is validated by Unicode category in
//! [`crate::identity`], the family's sibling.
//!
//! This is the foundation, not the finished migration: the bulk of
//! the workspace's `&str` still has to move onto these types over
//! time. The bare `&str` that remains here is the
//! single sanctioned place: a validating constructor's input and an
//! `as_str` rendering accessor -- the gate itself, not a hole.

use core::fmt;

/// A byte outside a Strong String type's allowed charset, with the
/// position where validation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CharsetError {
    /// Zero-based byte offset of the first offending byte.
    pub position: usize,
    /// The offending byte.
    pub byte: u8,
}

impl fmt::Display for CharsetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "byte 0x{:02X} at position {} is outside the allowed charset",
            self.byte, self.position
        )
    }
}

impl core::error::Error for CharsetError {}

/// Unit-struct host for the shared charset-scan (typing-discipline
/// Rule A: no top-level fn with a borrowed parameter).
struct Charset;

impl Charset {
    /// First byte of `text` for which `allowed` is false, with its
    /// position -- the validation failure, if any. Iterator-based
    /// so there is no indexing or offset arithmetic.
    fn first_violation(text: &str, allowed: fn(u8) -> bool) -> Option<CharsetError> {
        text.bytes()
            .enumerate()
            .find(|&(_, byte)| !allowed(byte))
            .map(|(position, byte)| CharsetError { position, byte })
    }
}

/// Define one charset-tiered Strong String type: a `Box<str>`
/// newtype whose `parse` validates every byte against `$pred`,
/// rejecting the first alien with a [`CharsetError`]. The owned
/// `String` input is the sanctioned validation-constructor form;
/// `as_str` / `Display` are the only `&str` the type exposes.
macro_rules! charset_string {
    ($(#[$meta:meta])* $name:ident => $pred:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name(Box<str>);

        impl $name {
            /// Validate `text` against this type's charset.
            ///
            /// # Errors
            /// [`CharsetError`] for the first byte outside the charset.
            pub fn parse(text: String) -> Result<Self, CharsetError> {
                match Charset::first_violation(&text, $pred) {
                    Some(error) => Err(error),
                    None => Ok(Self(text.into_boxed_str())),
                }
            }

            /// The validated text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

charset_string!(
    /// Text restricted to `[A-Za-z]` (both cases).
    AlphaString => |byte| byte.is_ascii_alphabetic()
);
charset_string!(
    /// Text restricted to `[a-z]` -- the lower-only stricter form of
    /// [`AlphaString`].
    LowerAlphaString => |byte| byte.is_ascii_lowercase()
);
charset_string!(
    /// Text restricted to `[A-Za-z0-9]`.
    AlphaNumString => |byte| byte.is_ascii_alphanumeric()
);
charset_string!(
    /// Text restricted to `[a-z0-9]` -- the lower-only stricter form
    /// of [`AlphaNumString`].
    LowerAlphaNumString => |byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()
);
charset_string!(
    /// Text restricted to `[A-Za-z0-9._-]` -- dotted / snake protocol
    /// tokens (both cases).
    TokenString => |byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
);
charset_string!(
    /// Text restricted to `[a-z0-9._-]` -- the lower-only stricter
    /// form of [`TokenString`], e.g. `telia.ftn.oidc.hst.1`.
    LowerTokenString =>
        |byte| (byte.is_ascii_lowercase() || byte.is_ascii_digit())
            || matches!(byte, b'.' | b'_' | b'-')
);

/// Longest URI accepted, in bytes. RFC 7230/9112 §3.1.1
/// recommends recipients support request-targets of at least this
/// many octets (past it a server may answer 414). RFC 3986 itself
/// sets no maximum, so this is an HTTP-pragmatic cap.
const MAX_URI_LEN: usize = 8000;
/// Longest host in characters: RFC 1035 §3.1 caps a name at
/// 255 octets on the wire, which is 253 in dotted presentation form.
const MAX_HOST_LEN: usize = 253;
/// Longest DNS label in characters (RFC 1035 §2.3.4).
const MAX_LABEL_LEN: usize = 63;
/// The `http` scheme-default port (RFC 7230).
const DEFAULT_HTTP_PORT: u16 = 80;
/// The `https` scheme-default port (RFC 7230).
const DEFAULT_HTTPS_PORT: u16 = 443;

/// Why a path/query failed RFC 3986 character validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriCharError {
    /// A byte that is not a URI character and is not part of a `%XX`
    /// escape, at this position.
    IllegalByte {
        /// Zero-based byte offset of the offending byte.
        position: usize,
        /// The offending byte.
        byte: u8,
    },
    /// A `%` not followed by two hex digits, at this position.
    MalformedEscape {
        /// Zero-based byte offset of the `%`.
        position: usize,
    },
}

impl fmt::Display for UriCharError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IllegalByte { position, byte } => {
                write!(
                    f,
                    "byte {byte:#04X} at position {position} is not a URI character"
                )
            }
            Self::MalformedEscape { position } => {
                write!(f, "malformed percent-escape at position {position}")
            }
        }
    }
}

impl core::error::Error for UriCharError {}

/// Why a host is not a valid RFC 1123 / RFC 1035 DNS name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostError {
    /// The host (authority before any `:port`) was empty.
    Empty,
    /// The whole host exceeded `MAX_HOST_LEN` octets.
    TooLong {
        /// The rejected host length, in octets.
        len: usize,
    },
    /// A dot-separated label was empty (leading, trailing, or double
    /// dot).
    EmptyLabel,
    /// A label exceeded `MAX_LABEL_LEN` octets.
    LabelTooLong {
        /// The rejected label length, in octets.
        len: usize,
    },
    /// A label began or ended with `-` (RFC 1123 / RFC 952 LDH rule:
    /// labels may contain hyphens but not at either end).
    LabelHyphenBoundary,
    /// A byte outside the DNS host charset `[a-z0-9.-]`.
    Byte {
        /// The offending byte (after lowercasing).
        byte: u8,
    },
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty host"),
            Self::TooLong { len } => {
                write!(f, "host is {len} octets, over the {MAX_HOST_LEN} limit")
            }
            Self::EmptyLabel => f.write_str("empty host label (leading, trailing, or double dot)"),
            Self::LabelTooLong { len } => {
                write!(
                    f,
                    "host label is {len} octets, over the {MAX_LABEL_LEN} limit"
                )
            }
            Self::LabelHyphenBoundary => f.write_str("host label begins or ends with a hyphen"),
            Self::Byte { byte } => {
                write!(f, "byte {byte:#04X} is outside the host charset [a-z0-9.-]")
            }
        }
    }
}

impl core::error::Error for HostError {}

/// Why a string is not a valid `http(s)` URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UriError {
    /// Longer than `MAX_URI_LEN` bytes.
    TooLong {
        /// The rejected input length.
        len: usize,
    },
    /// No `http://` / `https://` prefix. Other schemes (`ldap`, `ftp`,
    /// schemeless) are out of scope.
    Scheme,
    /// The authority carried userinfo (`user@host`), which is not
    /// accepted.
    Userinfo,
    /// A port that was not `*DIGIT` in `u16` range.
    BadPort,
    /// The host component was invalid.
    Host(HostError),
    /// The path component was invalid.
    Path(UriCharError),
    /// The query component was invalid.
    Query(UriCharError),
}

impl fmt::Display for UriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { len } => write!(f, "URI is {len} bytes, over the {MAX_URI_LEN} limit"),
            Self::Scheme => f.write_str("URI scheme is not http:// or https://"),
            Self::Userinfo => {
                f.write_str("URI authority carries userinfo (user@host), not accepted")
            }
            Self::BadPort => f.write_str("URI port is not a u16-range *DIGIT"),
            Self::Host(error) => write!(f, "URI host: {error}"),
            Self::Path(error) => write!(f, "URI path: {error}"),
            Self::Query(error) => write!(f, "URI query: {error}"),
        }
    }
}

impl core::error::Error for UriError {}

/// RFC 3986 §3.1 scheme, restricted to the two schemes this
/// codebase speaks.
///
/// Stored normalised to lowercase (RFC 3986 §6.2.2.1). An
/// "https only" requirement is a match on this value, never a naive
/// string test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// The `http` scheme.
    Http,
    /// The `https` scheme.
    Https,
}

impl Scheme {
    /// The scheme-default port (RFC 7230): 80 for http, 443 for https.
    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Http => DEFAULT_HTTP_PORT,
            Self::Https => DEFAULT_HTTPS_PORT,
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Http => "http",
            Self::Https => "https",
        })
    }
}

/// RFC 3986 `pchar` (minus `pct-encoded`): the byte set shared by path
/// and query segments -- `unreserved / sub-delims / ":" / "@"`.
const fn is_pchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            // unreserved
            b'-' | b'.' | b'_' | b'~'
            // sub-delims
            | b'!' | b'$' | b'&' | b'\'' | b'(' | b')'
            | b'*' | b'+' | b',' | b';' | b'='
            // pchar extras
            | b':' | b'@'
        )
}

/// Shared `%XX`-aware charset scan for the path and query components.
/// Slice-pattern two-byte lookahead, so no indexing or offset
/// arithmetic (the position is the consumed-prefix length).
struct PctScan;

impl PctScan {
    /// First charset violation in `text`, or `None` when every byte is
    /// `allowed` or part of a well-formed `%XX` escape.
    fn first_error(text: &str, allowed: fn(u8) -> bool) -> Option<UriCharError> {
        let full = text.as_bytes();
        let mut rest: &[u8] = full;
        loop {
            let position = full.len().saturating_sub(rest.len());
            match rest {
                [] => return None,
                [b'%', hi, lo, tail @ ..] if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit() => {
                    rest = tail;
                }
                [b'%', ..] => return Some(UriCharError::MalformedEscape { position }),
                [first, tail @ ..] if allowed(*first) => rest = tail,
                [first, ..] => {
                    return Some(UriCharError::IllegalByte {
                        position,
                        byte: *first,
                    });
                }
            }
        }
    }
}

/// RFC 1123 / RFC 1035 DNS host (the `reg-name` form).
///
/// `[a-z0-9.-]`, dot-separated labels of `1..=63` octets, `<= 253`
/// octets total, no empty label, and no label that begins or ends with
/// `-` (the LDH rule). Lowercased on parse (RFC 3986 §6.2.2.1),
/// so two hosts differing only in case compare equal. This validates
/// the reg-name *charset and structure* -- it does not interpret
/// IPv4/IPv6 literals (an IPv4-shaped host is accepted as a reg-name).
/// Compared with `==`, rendered with `Display`; it is a component, not
/// a string -- there is no `as_str`. Built only via [`Uri::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host(Box<str>);

impl Host {
    /// Validate `text` (the authority with any `:port` already split
    /// off) as a DNS host, lowercasing it in place first.
    ///
    /// # Errors
    /// [`HostError`] for an empty / over-long host, an empty / over-long
    /// label, a label with a boundary hyphen, or a byte outside
    /// `[a-z0-9.-]`.
    pub(crate) fn parse(mut text: String) -> Result<Self, HostError> {
        text.make_ascii_lowercase();
        if text.is_empty() {
            return Err(HostError::Empty);
        }
        // RFC 1035 caps the name at 255 octets (253 in presentation form);
        // the host charset is ASCII, so byte length is the octet count.
        let total = text.len();
        if total > MAX_HOST_LEN {
            return Err(HostError::TooLong { len: total });
        }
        for label in text.split('.') {
            if label.is_empty() {
                return Err(HostError::EmptyLabel);
            }
            if label.len() > MAX_LABEL_LEN {
                return Err(HostError::LabelTooLong { len: label.len() });
            }
            // RFC 1123 / RFC 952 LDH: a label may carry hyphens but not
            // at either end.
            if label.starts_with('-') || label.ends_with('-') {
                return Err(HostError::LabelHyphenBoundary);
            }
            if let Some(byte) = label
                .bytes()
                .find(|byte| !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-'))
            {
                return Err(HostError::Byte { byte });
            }
        }
        Ok(Self(text.into_boxed_str()))
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// RFC 3986 `path-abempty` in origin form.
///
/// `*( "/" pchar )` with `%XX` escapes. An empty path normalises to
/// `/`. Compared with `==` (exact bytes -- percent-escape hex case is
/// not folded, unlike the host), rendered with `Display`. Built only
/// via [`Uri::parse`], which guarantees a leading `/` or empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path(Box<str>);

impl Path {
    /// Validate `text` as a URI path.
    ///
    /// # Errors
    /// [`UriCharError`] for the first illegal byte or malformed `%XX`.
    pub(crate) fn parse(text: String) -> Result<Self, UriCharError> {
        if let Some(error) = PctScan::first_error(&text, |byte| is_pchar(byte) || byte == b'/') {
            return Err(error);
        }
        let normalised = if text.is_empty() {
            "/".to_owned()
        } else {
            text
        };
        Ok(Self(normalised.into_boxed_str()))
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// RFC 3986 `query` component.
///
/// `*( pchar / "/" / "?" )` with `%XX` escapes. An empty `Query`
/// renders as no query and reports [`Query::is_empty`] -- the "needs a
/// new `?`" vs "append with `&`" signal. A present-but-empty `?` is
/// not distinguished from an absent query (both are empty); the
/// federation never emits a bare `?`. Compared with `==` (exact bytes
/// -- percent-escape hex case is not folded), rendered with `Display`.
/// Built only via [`Uri::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query(Box<str>);

impl Query {
    /// Validate `text` as a URI query (the part after `?`).
    ///
    /// # Errors
    /// [`UriCharError`] for the first illegal byte or malformed `%XX`.
    pub(crate) fn parse(text: String) -> Result<Self, UriCharError> {
        if let Some(error) =
            PctScan::first_error(&text, |byte| is_pchar(byte) || matches!(byte, b'/' | b'?'))
        {
            return Err(error);
        }
        Ok(Self(text.into_boxed_str()))
    }

    /// `true` when the URI carried no query at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The one URL type in the codebase.
///
/// It deconstructs an `http(s)://host[:port]/path[?query]` string into
/// validated components, and reconstructs it via `Display`. A `Uri` is
/// a URL, not a string: there is deliberately no `as_str`. Comparison
/// and matching (host equality, cookie path scoping) are the caller's
/// job, over the typed components this exposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uri {
    /// The scheme (`http` / `https`).
    scheme: Scheme,
    /// The host, validated to RFC 1123 and lowercased.
    host: Host,
    /// The effective port: explicit, or the scheme default.
    port: u16,
    /// The origin-form path (empty input normalised to `/`).
    path: Path,
    /// The query (empty when the URI carried no `?`).
    query: Query,
}

impl Uri {
    /// Deconstruct and validate `input` as an `http(s)` URL: scheme,
    /// host (RFC 1123), port, path, and query are each validated by
    /// their component constructor. Any fragment is parsed off and
    /// dropped (RFC 3986 §3.5 is client-side, never sent).
    ///
    /// # Errors
    /// [`UriError`] for an over-long input, a non-`http(s)` scheme,
    /// userinfo, a bad port, or an invalid host / path / query.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "owned String is the boundary input the pub-fn typing rule mandates; deconstructed into typed components, not stored, so no into_boxed_str consume"
    )]
    pub fn parse(input: String) -> Result<Self, UriError> {
        if input.len() > MAX_URI_LEN {
            return Err(UriError::TooLong { len: input.len() });
        }
        // Split the scheme (case-insensitive, RFC 3986 §6.2.2.1);
        // byte-prefix compare so a non-ASCII lead can't land mid-UTF-8.
        let bytes = input.as_bytes();
        let (scheme, after_scheme) = if bytes
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"https://"))
        {
            (Scheme::Https, input.get(8..).unwrap_or_default())
        } else if bytes
            .get(..7)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"http://"))
        {
            (Scheme::Http, input.get(7..).unwrap_or_default())
        } else {
            return Err(UriError::Scheme);
        };
        let authority_end = after_scheme
            .find(['/', '?', '#'])
            .unwrap_or(after_scheme.len());
        let authority = after_scheme.get(..authority_end).unwrap_or_default();
        let after_authority = after_scheme.get(authority_end..).unwrap_or_default();
        if authority.contains('@') {
            return Err(UriError::Userinfo);
        }
        let (host_raw, port) = match authority.rsplit_once(':') {
            Some((host_raw, port_raw)) => {
                // RFC 3986 `port = *DIGIT`: only ASCII digits. `u16::from_str`
                // also accepts a leading `+`, so guard the charset first.
                if port_raw.is_empty() || !port_raw.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(UriError::BadPort);
                }
                let port: u16 = port_raw.parse().map_err(|_error| UriError::BadPort)?;
                // Port 0 is reserved (RFC 6335 §6) -- never a
                // connectable TCP/UDP port, so a `:0` authority is bad.
                if port == 0 {
                    return Err(UriError::BadPort);
                }
                (host_raw, port)
            }
            None => (authority, scheme.default_port()),
        };
        let host = Host::parse(host_raw.to_owned()).map_err(UriError::Host)?;
        let without_fragment = after_authority.split('#').next().unwrap_or_default();
        let (path_raw, query_raw) = match without_fragment.split_once('?') {
            Some((path_raw, query_raw)) => (path_raw, query_raw),
            None => (without_fragment, ""),
        };
        let path = Path::parse(path_raw.to_owned()).map_err(UriError::Path)?;
        let query = Query::parse(query_raw.to_owned()).map_err(UriError::Query)?;
        Ok(Self {
            scheme,
            host,
            port,
            path,
            query,
        })
    }

    /// The scheme component.
    #[must_use]
    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The host component.
    #[must_use]
    pub const fn host(&self) -> &Host {
        &self.host
    }

    /// The effective port: explicit, or the scheme default.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The path component.
    #[must_use]
    pub const fn path(&self) -> &Path {
        &self.path
    }

    /// The query component (empty when the URI carried no `?`).
    #[must_use]
    pub const fn query(&self) -> &Query {
        &self.query
    }

    /// Resolve a redirect `Location` against this URL (RFC 3986
    /// §5 subset): absolute URLs replace; `//authority...`
    /// keeps the scheme; `/path` keeps the authority; a relative path
    /// resolves against this URL's directory.
    ///
    /// Subset, not the full §5.3 recomposition: dot-segments
    /// (`.` / `..`) are kept verbatim (no §5.2.4 removal), and a
    /// query-only (`?...`), fragment-only (`#...`), or empty reference
    /// is treated as a relative path rather than special-cased. The
    /// federation servers emit only absolute and absolute-path
    /// `Location`s, so these edges are unreached in practice.
    ///
    /// # Errors
    /// [`UriError`] when the resolved URL fails to parse.
    pub fn join(&self, location: String) -> Result<Self, UriError> {
        if location.starts_with("http://") || location.starts_with("https://") {
            return Self::parse(location);
        }
        if let Some(scheme_relative) = location.strip_prefix("//") {
            return Self::parse(format!("{}://{scheme_relative}", self.scheme));
        }
        let authority = self.authority_string();
        if location.starts_with('/') {
            return Self::parse(format!("{}://{authority}{location}", self.scheme));
        }
        let path = self.path.to_string();
        let dir_end = path.rfind('/').map_or(0, |index| index.saturating_add(1));
        let dir = path.get(..dir_end).unwrap_or("/");
        Self::parse(format!("{}://{authority}{dir}{location}", self.scheme))
    }

    /// `host[:port]`, with the scheme-default port elided.
    fn authority_string(&self) -> String {
        if self.port == self.scheme.default_port() {
            self.host.to_string()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.scheme, self.authority_string())?;
        write!(f, "{}", self.path)?;
        if !self.query.is_empty() {
            write!(f, "?{}", self.query)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AlphaNumString, AlphaString, Host, HostError, LowerAlphaNumString, LowerAlphaString,
        LowerTokenString, MAX_HOST_LEN, MAX_URI_LEN, Scheme, TokenString, Uri, UriCharError,
        UriError,
    };

    /// Each charset member admits its set and rejects the first alien;
    /// the case axis distinguishes the base (both-case) from `Lower`.
    #[test]
    fn charset_members_admit_and_deny() {
        let Ok(_) = AlphaString::parse("AbcXYZ".to_owned()) else {
            unreachable!()
        };
        let Err(_) = AlphaString::parse("Abc1".to_owned()) else {
            unreachable!()
        };
        let Ok(_) = LowerAlphaString::parse("abc".to_owned()) else {
            unreachable!()
        };
        let Err(_) = LowerAlphaString::parse("Abc".to_owned()) else {
            unreachable!()
        };

        let Ok(_) = AlphaNumString::parse("Abc123".to_owned()) else {
            unreachable!()
        };
        let Err(_) = AlphaNumString::parse("abc_1".to_owned()) else {
            unreachable!()
        };
        let Ok(_) = LowerAlphaNumString::parse("abc123".to_owned()) else {
            unreachable!()
        };
        let Err(_) = LowerAlphaNumString::parse("Abc123".to_owned()) else {
            unreachable!()
        };

        let Ok(_) = TokenString::parse("Telia.FTN-1".to_owned()) else {
            unreachable!()
        };
        let Ok(_) = LowerTokenString::parse("telia.ftn.oidc.hst.1".to_owned()) else {
            unreachable!()
        };
        let Ok(_) = LowerTokenString::parse("rsa_pkcs1_sha256".to_owned()) else {
            unreachable!()
        };
        let Err(_) = LowerTokenString::parse("Telia".to_owned()) else {
            unreachable!()
        };
    }

    /// The canonical alien: the Space Invader emoji, which literally
    /// invades the charset's space, is rejected by every member.
    /// `\u{1F47E}` is the invader, written as an escape because the
    /// repo source is ASCII-only -- which is the whole point.
    #[test]
    fn emoji_is_always_an_alien() {
        let alien = "ok\u{1F47E}".to_owned();
        let Err(_) = AlphaString::parse(alien.clone()) else {
            unreachable!()
        };
        let Err(_) = LowerAlphaNumString::parse(alien.clone()) else {
            unreachable!()
        };
        let Err(_) = TokenString::parse(alien.clone()) else {
            unreachable!()
        };
        let Err(_) = Uri::parse(alien) else {
            unreachable!()
        };
    }

    /// A real URL deconstructs into all five typed components.
    #[test]
    fn uri_deconstructs_all_components() {
        let Ok(uri) = Uri::parse(
            "https://broker.example.test/uas/authn/x/select?entityID=ea339bdc&method=hst.1"
                .to_owned(),
        ) else {
            unreachable!()
        };
        assert_eq!(uri.scheme(), Scheme::Https);
        assert_eq!(uri.host().to_string(), "broker.example.test");
        assert_eq!(uri.port(), 443);
        assert_eq!(uri.path().to_string(), "/uas/authn/x/select");
        assert_eq!(uri.query().to_string(), "entityID=ea339bdc&method=hst.1");
        assert!(!uri.query().is_empty());
    }

    /// Scheme is case-insensitive and lowercased; host is lowercased;
    /// an empty path normalises to `/`; no `?` means an empty query.
    #[test]
    fn uri_normalises_scheme_host_and_path() {
        let Ok(uri) = Uri::parse("HTTP://SP.Example.TEST".to_owned()) else {
            unreachable!()
        };
        assert_eq!(uri.scheme(), Scheme::Http);
        assert_eq!(uri.host().to_string(), "sp.example.test");
        assert_eq!(uri.port(), 80);
        assert_eq!(uri.path().to_string(), "/");
        assert!(uri.query().is_empty());
    }

    /// Display reconstructs; the scheme-default port is elided, an
    /// explicit non-default port is kept, and a fragment is dropped.
    #[test]
    fn uri_reconstructs_via_display() {
        let Ok(elided) = Uri::parse("https://sp.example.test:443/app/?x=1".to_owned()) else {
            unreachable!()
        };
        assert_eq!(elided.to_string(), "https://sp.example.test/app/?x=1");
        let Ok(kept) = Uri::parse("https://idp.example.test:8443/saml2/SSO".to_owned()) else {
            unreachable!()
        };
        assert_eq!(kept.to_string(), "https://idp.example.test:8443/saml2/SSO");
        let Ok(fragment) = Uri::parse("https://sp.example.test/app/#section".to_owned()) else {
            unreachable!()
        };
        assert_eq!(fragment.to_string(), "https://sp.example.test/app/");
    }

    /// Redirect resolution: absolute replaces, `//authority` keeps the
    /// scheme, `/path` keeps the authority, relative resolves against
    /// the current directory.
    #[test]
    fn uri_join_resolves_redirects() {
        let Ok(base) = Uri::parse("https://sp.example.test/app/login".to_owned()) else {
            unreachable!()
        };
        let join = |location: &str| {
            base.join(location.to_owned())
                .unwrap_or_else(|_| unreachable!())
                .to_string()
        };
        assert_eq!(
            join("https://other.example.test/x"),
            "https://other.example.test/x"
        );
        assert_eq!(join("//cdn.example.test/y"), "https://cdn.example.test/y");
        assert_eq!(join("/api/v1"), "https://sp.example.test/api/v1");
        assert_eq!(join("step2"), "https://sp.example.test/app/step2");
    }

    /// Non-`http(s)` schemes, schemeless input, and a percent-encoded
    /// pseudo-URL are all rejected at the scheme gate.
    #[test]
    fn uri_rejects_non_http_schemes() {
        for bad in [
            "ldap://x/",
            "ftp://x/",
            "sp.example.test/p",
            "https%3A%2F%2Fx%2F",
        ] {
            assert_eq!(Uri::parse(bad.to_owned()), Err(UriError::Scheme), "{bad}");
        }
    }

    /// Userinfo, a zero / out-of-range port, an over-long URI, and a
    /// malformed query escape each surface a specific error.
    #[test]
    fn uri_rejects_structural_faults() {
        assert_eq!(
            Uri::parse("https://user@host.example.test/".to_owned()),
            Err(UriError::Userinfo)
        );
        assert_eq!(
            Uri::parse("https://host.example.test:99999/".to_owned()),
            Err(UriError::BadPort)
        );
        assert_eq!(
            Uri::parse("https://host.example.test:0/".to_owned()),
            Err(UriError::BadPort)
        );
        // `u16::from_str` accepts a leading `+`; RFC 3986 `port = *DIGIT` does not.
        assert_eq!(
            Uri::parse("https://host.example.test:+443/".to_owned()),
            Err(UriError::BadPort)
        );
        let over = format!("https://host.example.test/{}", "a".repeat(MAX_URI_LEN));
        assert!(matches!(Uri::parse(over), Err(UriError::TooLong { .. })));
        assert!(matches!(
            Uri::parse("https://host.example.test/p?a%2".to_owned()),
            Err(UriError::Query(UriCharError::MalformedEscape { .. }))
        ));
    }

    /// The host component enforces the RFC 1123 / RFC 1035 limits.
    #[test]
    fn host_enforces_dns_limits() {
        assert_eq!(Host::parse(String::new()), Err(HostError::Empty));
        assert_eq!(Host::parse("a..b".to_owned()), Err(HostError::EmptyLabel));
        assert!(matches!(
            Host::parse("a".repeat(64)),
            Err(HostError::LabelTooLong { len: 64 })
        ));
        let over_total = vec!["a"; 128].join(".");
        assert!(matches!(
            Host::parse(over_total),
            Err(HostError::TooLong { .. })
        ));
        assert_eq!(
            Host::parse("under_score".to_owned()),
            Err(HostError::Byte { byte: b'_' })
        );
        // RFC 1123 / RFC 952 LDH: a label may not begin or end with `-`.
        assert_eq!(
            Host::parse("-foo.example.test".to_owned()),
            Err(HostError::LabelHyphenBoundary)
        );
        assert_eq!(
            Host::parse("foo-.example.test".to_owned()),
            Err(HostError::LabelHyphenBoundary)
        );
        // A hyphen inside a label is fine.
        let Ok(_) = Host::parse("a-b.example.test".to_owned()) else {
            unreachable!()
        };
        let Ok(_) = Host::parse("idp.example.test".to_owned()) else {
            unreachable!()
        };
    }

    /// The host total-length cap is exact at the 253-octet boundary.
    #[test]
    fn host_length_boundary() {
        let at_limit = vec!["a"; 127].join("."); // 127 + 126 dots = 253
        assert_eq!(at_limit.len(), MAX_HOST_LEN);
        let Ok(_) = Host::parse(at_limit) else {
            unreachable!()
        };
        let over = format!("{}a", vec!["a"; 127].join(".")); // 254
        assert!(matches!(
            Host::parse(over),
            Err(HostError::TooLong { len: 254 })
        ));
    }

    /// The core invariant: parse -> Display -> parse is a fixed point.
    #[test]
    fn uri_round_trip_is_idempotent() {
        for raw in [
            "https://broker.example.test/uas/authn/x?entityID=ea339bdc&method=hst.1",
            "http://sp.example.test/",
            "https://idp.example.test:8443/saml2/SSO",
            "https://sp.example.test/app/#frag",
            "https://host.example.test/p?a=1",
            "https://host.example.test/a%2Fb?q=%2F",
        ] {
            let Ok(once) = Uri::parse(raw.to_owned()) else {
                unreachable!()
            };
            let Ok(twice) = Uri::parse(once.to_string()) else {
                unreachable!()
            };
            assert_eq!(once, twice, "round-trip changed: {raw}");
        }
    }

    /// A `%` escape truncated at end-of-input is rejected in path or query.
    #[test]
    fn uri_rejects_truncated_escape_at_end() {
        for bad in [
            "https://host.example.test/p%",
            "https://host.example.test/p%a",
            "https://host.example.test/?q%a",
        ] {
            assert!(
                matches!(
                    Uri::parse(bad.to_owned()),
                    Err(UriError::Path(UriCharError::MalformedEscape { .. })
                        | UriError::Query(UriCharError::MalformedEscape { .. }))
                ),
                "{bad}"
            );
        }
    }

    /// A second colon in the authority leaves a `:` in the host, which
    /// the host charset rejects (pins the error-variant behaviour).
    #[test]
    fn uri_multi_colon_authority_rejected() {
        assert_eq!(
            Uri::parse("https://h.example.test:8080:9090/".to_owned()),
            Err(UriError::Host(HostError::Byte { byte: b':' }))
        );
    }
}

/// Property tests: falsify the parser's invariants over generated
/// inputs rather than hand-picked examples (see the "scientifically
/// smart" stop criterion -- correlated reviews have converged).
#[cfg(test)]
mod prop_tests {
    use super::Uri;
    use proptest::prelude::*;

    /// A strategy biased toward parseable `http(s)` URLs, so the
    /// round-trip property exercises host/port/path/query validation,
    /// not just the scheme gate. Hosts avoid hyphens (the LDH rule is
    /// unit-tested) so most generated URLs parse and get checked.
    fn url_like() -> impl Strategy<Value = String> {
        (
            prop::sample::select(vec!["http", "https"]),
            "[a-z][a-z0-9]{0,12}(\\.[a-z][a-z0-9]{0,12}){0,3}",
            prop::option::of(1_u16..=u16::MAX),
            "(/[a-zA-Z0-9._~!$&'()*+,;=:@-]{0,12}){0,4}",
            prop::option::of("[a-zA-Z0-9._~!$&'()*+,;=:@/?-]{0,24}"),
        )
            .prop_map(|(scheme, host, port, path, query)| {
                let mut url = format!("{scheme}://{host}");
                if let Some(port) = port {
                    url.push(':');
                    url.push_str(&port.to_string());
                }
                url.push_str(&path);
                if let Some(query) = query {
                    url.push('?');
                    url.push_str(&query);
                }
                url
            })
    }

    proptest! {
        /// Totality: no input -- arbitrary text or a generated URL --
        /// can make `Uri::parse` panic, overflow, or slice out of
        /// bounds. The denied indexing/arithmetic lints argue this
        /// statically; this proves it empirically.
        #[test]
        fn parse_never_panics(input in prop_oneof![".*", url_like()]) {
            let _ignored = Uri::parse(input);
        }

        /// Idempotence: anything that parses re-parses from its own
        /// `Display` to an equal value (`parse . to_string` is the
        /// identity on the accepted set).
        #[test]
        fn parse_display_round_trips(input in url_like()) {
            if let Ok(uri) = Uri::parse(input) {
                let reparsed = Uri::parse(uri.to_string());
                prop_assert_eq!(Ok(uri), reparsed);
            }
        }
    }
}
