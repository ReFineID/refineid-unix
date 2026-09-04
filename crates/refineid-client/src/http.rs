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

//! Minimal HTTP/1.1 client for the revocation and timestamp fetch paths.
//!
//! Scope is deliberately tiny:
//!
//! - GET and POST only.
//! - Plain `http://` in default builds. When compiled with
//!   `https` plus a TLS backend (`tls-rustls`, `tls-boringssl` or `tls-openssl`),
//!   `https://` uses server-authenticated TLS through
//!   `refineid-lib-tls::simple_https`. It does not present the
//!   FINEID client certificate.
//! - Certificate-published endpoints are resolved once, every answer
//!   must be a public address, and the connection uses one exact vetted
//!   answer. The same policy is applied again to each bounded redirect.
//! - No connection pooling. One fetch per invocation, drop the
//!   socket.
//! - Handles `Content-Length` and `Transfer-Encoding: chunked`
//!   responses. That covers what the FINEID servers actually
//!   send today.
//!
//! Connections use `std::net::TcpStream`; DNSSEC validation uses a
//! bounded Hickory resolver attempt before one platform-resolver fallback.

use alloc::fmt;
use core::time::Duration;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};

use hickory_resolver::Resolver;
use hickory_resolver::config::ResolveHosts;
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::dnssec::Proof;
use hickory_resolver::proto::rr::{RData, RecordType};
use refineid_lib_core::text::{Scheme, Uri};

/// Helpers hosted on a unit struct (typing-discipline: no
/// free fns with borrowed parameters; see
/// `doc/typing-discipline.md`).
struct HttpHelpers;

impl HttpHelpers {
    /// The `Host` header value: host, and the port when it is not the
    /// scheme's default.
    ///
    /// RFC 9110 sec.7.2 wants the authority, not the bare host. A TSA
    /// answering on `tsa.example.org:8318` is a different virtual host from
    /// `tsa.example.org`, and omitting the port is how a request reaches
    /// the wrong one -- or is refused by a server that checks.
    fn authority(url: &Uri) -> String {
        /// Default port for the only scheme this client dials.
        const DEFAULT_HTTP_PORT: u16 = 80;
        let host = url.host();
        let port = url.port();
        if port == DEFAULT_HTTP_PORT {
            host.to_string()
        } else {
            format!("{host}:{port}")
        }
    }
}

// `User-Agent` policy lives in `crate::user_agent`. This module
// stays UA-agnostic -- callers hand in the bytes they want sent.
// Two flavours exist there: the honest project-identifying UA
// (default for every endpoint we hit today) and a per-endpoint
// browser masquerade for the rare server that refuses non-
// browser clients.

/// Errors from `get`.
#[derive(Debug)]
pub enum HttpError {
    /// URL did not parse as a supported HTTP or HTTPS URL.
    BadUrl(&'static str),
    /// The URL used a scheme other than HTTP or HTTPS, or HTTPS was
    /// disabled at build time.
    UnsupportedScheme(String),
    /// TCP / I/O failure.
    Io(io::Error),
    /// HTTP status line wasn't well-formed.
    BadStatusLine(String),
    /// Non-2xx status.
    HttpStatus {
        /// HTTP status code returned by the server.
        code: u16,
        /// Reason-phrase from the status line. Tier 0 `String`;
        /// presentational.
        reason: String,
        /// Where the server said the resource moved to, when it said
        /// so. Carried rather than dropped: a certificate authority
        /// answering 301 to its own AIA URL is common enough that
        /// dropping it costs a chain.
        location: Option<String>,
    },
    /// Response was missing both `Content-Length` and
    /// `Transfer-Encoding: chunked`. We refuse the read-until-EOF
    /// case so the caller can't be fooled by a stream that just
    /// closes mid-body.
    UnknownBodyLength,
    /// Chunked encoding chunk-size line wasn't valid hex.
    BadChunkSize(String),
    /// `Content-Length` exceeded the supplied `max_bytes`.
    BodyTooLarge {
        /// `Content-Length` value the server announced. Tier 0
        /// `usize`; arithmetic count.
        content_length: usize,
        /// The caller-supplied `max_bytes` ceiling. Tier 0 `usize`.
        limit: usize,
    },
    /// A certificate-published endpoint used a local, special-purpose,
    /// mixed, oversized, or ambiguously numeric destination.
    UnsafeDestination(String),
    /// A redirect crossed a policy boundary or exceeded its hop budget.
    UnsafeRedirect(String),
    /// Authentication material was offered without server-authenticated TLS.
    InsecureCredentials,
    /// HTTPS failed in the optional TLS-backed path.
    Https {
        /// Redacted transport detail.
        detail: String,
        /// Whether reconnecting may recover without changing policy or input.
        retryable: bool,
    },
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadUrl(s) => write!(f, "bad URL: {s}"),
            Self::UnsupportedScheme(s) => write!(f, "unsupported URL scheme: {s}"),
            Self::Io(e) => write!(f, "i/o: {e}"),
            Self::BadStatusLine(s) => write!(f, "bad HTTP status line: {s:?}"),
            Self::HttpStatus { code, reason, .. } => write!(f, "HTTP {code} {reason}"),
            Self::UnknownBodyLength => write!(
                f,
                "response had no Content-Length and was not chunked; refusing"
            ),
            Self::BadChunkSize(s) => write!(f, "bad chunk-size: {s:?}"),
            Self::BodyTooLarge {
                content_length,
                limit,
            } => write!(
                f,
                "Content-Length {content_length} exceeds caller limit {limit}"
            ),
            Self::UnsafeDestination(detail) => write!(f, "unsafe destination: {detail}"),
            Self::UnsafeRedirect(detail) => write!(f, "unsafe redirect: {detail}"),
            Self::InsecureCredentials => {
                f.write_str("timestamp credentials require an HTTPS authority")
            }
            Self::Https { detail, .. } => write!(f, "HTTPS: {detail}"),
        }
    }
}

impl HttpError {
    /// Whether a timestamp authority request may be repeated unchanged.
    pub(crate) fn is_retryable_authority_failure(&self) -> bool {
        match self {
            Self::Io(error) => matches!(
                error.kind(),
                io::ErrorKind::TimedOut
                    | io::ErrorKind::Interrupted
                    | io::ErrorKind::WouldBlock
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
            ),
            Self::HttpStatus { code, .. } => {
                matches!(*code, 408 | 425 | 429 | 500 | 502 | 503 | 504)
            }
            Self::Https { retryable, .. } => *retryable,
            Self::BadUrl(_)
            | Self::UnsupportedScheme(_)
            | Self::BadStatusLine(_)
            | Self::UnknownBodyLength
            | Self::BadChunkSize(_)
            | Self::BodyTooLarge { .. }
            | Self::UnsafeDestination(_)
            | Self::UnsafeRedirect(_)
            | Self::InsecureCredentials => false,
        }
    }
}

/// Why one HTTP exchange is being made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endpoint {
    /// A URL learned from a certificate, revocation object, or signed
    /// infrastructure document. It must resolve only to public addresses.
    CertificateMaterial,
    /// A timestamp authority explicitly configured by the caller. Local
    /// services remain usable, but redirects cannot change its origin.
    Authority,
}

/// Largest distinct DNS answer set accepted for one host.
const MAX_RESOLVED_ADDRESSES: usize = 8;

/// Maximum wall-clock time spent on the locally validated DNSSEC attempt.
const DNSSEC_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(8);

/// Per-query timeout inside the bounded DNSSEC attempt.
const DNSSEC_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Public certificate material may use a canonical-host and one CDN hop.
const MAX_CERTIFICATE_REDIRECTS: usize = 2;

/// A configured authority may make one tightly constrained hop.
const MAX_AUTHORITY_REDIRECTS: usize = 1;

impl core::error::Error for HttpError {}

impl From<io::Error> for HttpError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl HttpHelpers {
    /// Origin-form request target (`/path[?query]`) for the request
    /// line (RFC 9112 §3.1.1), composed from the typed [`Uri`]
    /// components.
    fn request_target(url: &Uri) -> String {
        if url.query().is_empty() {
            url.path().to_string()
        } else {
            format!("{}?{}", url.path(), url.query())
        }
    }
}

/// GET `url` and return the response body. Caps the body at
/// `max_bytes` to bound the worst case.
///
/// Connect + read timeouts default to 30 seconds; FINEID CDPs
/// serve ~13 MB CRLs and a slow link still finishes inside that
/// window.
///
/// # Errors
/// URL parse failure, TCP failure, non-2xx HTTP status, malformed
/// HTTP framing, body exceeding `max_bytes`.
pub(crate) fn get(url: &Uri, max_bytes: usize, user_agent: &str) -> Result<Vec<u8>, HttpError> {
    get_for(url, max_bytes, user_agent, Endpoint::CertificateMaterial)
}

/// Redirect statuses worth following for a `GET` of a static file
/// (RFC 9110 sec.15.4). 303 is absent: it means "fetch something else
/// with GET", which for a certificate URL is not the certificate.
const REDIRECT_CODES: [u16; 4] = [301, 302, 307, 308];

/// POST `body` to `url` with the supplied `content_type` header
/// (e.g. `application/ocsp-request`). Returns the response body
/// capped at `max_bytes`. Same plain-HTTP scope as [`get`].
///
/// # Errors
/// As for [`get`].
pub(crate) fn post(
    url: &Uri,
    content_type: &str,
    body: &[u8],
    max_bytes: usize,
    user_agent: &str,
) -> Result<Vec<u8>, HttpError> {
    post_for(
        url,
        content_type,
        body,
        max_bytes,
        user_agent,
        Endpoint::CertificateMaterial,
        None,
    )
}

/// POST to an explicitly configured timestamp authority.
///
/// Unlike certificate-controlled URLs, an authority may intentionally
/// be a service on a private development network. Its address is still
/// resolved once and pinned through connection, and any redirect is
/// constrained to the same origin or a same-host HTTP-to-HTTPS upgrade.
pub(crate) fn post_authority(
    url: &Uri,
    content_type: &str,
    body: &[u8],
    max_bytes: usize,
    user_agent: &str,
    authorization: Option<&str>,
) -> Result<Vec<u8>, HttpError> {
    if authorization.is_some() && url.scheme() != Scheme::Https {
        return Err(HttpError::InsecureCredentials);
    }
    post_for(
        url,
        content_type,
        body,
        max_bytes,
        user_agent,
        Endpoint::Authority,
        authorization,
    )
}

/// One response, including a redirect status the caller still has to
/// decide whether to follow.
#[derive(Debug)]
struct ExchangeResponse {
    code: u16,
    reason: String,
    location: Option<String>,
    body: Vec<u8>,
}

impl ExchangeResponse {
    const fn is_success(&self) -> bool {
        self.code >= 200 && self.code < 300
    }
}

fn get_for(
    url: &Uri,
    max_bytes: usize,
    user_agent: &str,
    endpoint: Endpoint,
) -> Result<Vec<u8>, HttpError> {
    let mut current = url.clone();
    let maximum = maximum_redirects(endpoint);
    for followed in 0..=maximum {
        let mut response = get_once(&current, max_bytes, user_agent, endpoint)?;
        if response.is_success() {
            return Ok(response.body);
        }
        if !REDIRECT_CODES.contains(&response.code) {
            return Err(response.into_error());
        }
        if followed == maximum {
            return Err(HttpError::UnsafeRedirect(format!(
                "more than {maximum} redirects"
            )));
        }
        let Some(location) = response.location.take() else {
            return Err(response.into_error());
        };
        let next = current
            .join(location)
            .map_err(|error| HttpError::UnsafeRedirect(error.to_string()))?;
        check_redirect(&current, &next, endpoint)?;
        current = next;
    }
    Err(HttpError::UnsafeRedirect("redirect loop".to_owned()))
}

fn post_for(
    url: &Uri,
    content_type: &str,
    body: &[u8],
    max_bytes: usize,
    user_agent: &str,
    endpoint: Endpoint,
    authorization: Option<&str>,
) -> Result<Vec<u8>, HttpError> {
    let mut current = url.clone();
    let maximum = maximum_redirects(endpoint);
    for followed in 0..=maximum {
        let mut response = post_once(
            &current,
            content_type,
            body,
            max_bytes,
            user_agent,
            endpoint,
            authorization,
        )?;
        if response.is_success() {
            return Ok(response.body);
        }
        // Only 307 and 308 explicitly preserve the request method and
        // body. Replaying an OCSP or timestamp POST as a GET after
        // 301/302 is neither useful nor unambiguous.
        if !matches!(response.code, 307 | 308) {
            return Err(response.into_error());
        }
        if followed == maximum {
            return Err(HttpError::UnsafeRedirect(format!(
                "more than {maximum} redirects"
            )));
        }
        let Some(location) = response.location.take() else {
            return Err(response.into_error());
        };
        let next = current
            .join(location)
            .map_err(|error| HttpError::UnsafeRedirect(error.to_string()))?;
        check_redirect(&current, &next, endpoint)?;
        current = next;
    }
    Err(HttpError::UnsafeRedirect("redirect loop".to_owned()))
}

impl ExchangeResponse {
    fn into_error(self) -> HttpError {
        HttpError::HttpStatus {
            code: self.code,
            reason: self.reason,
            location: self.location,
        }
    }
}

const fn maximum_redirects(endpoint: Endpoint) -> usize {
    match endpoint {
        Endpoint::CertificateMaterial => MAX_CERTIFICATE_REDIRECTS,
        Endpoint::Authority => MAX_AUTHORITY_REDIRECTS,
    }
}

fn check_redirect(from: &Uri, to: &Uri, endpoint: Endpoint) -> Result<(), HttpError> {
    if from.scheme() == Scheme::Https && to.scheme() == Scheme::Http {
        return Err(HttpError::UnsafeRedirect(
            "HTTPS may not downgrade to HTTP".to_owned(),
        ));
    }
    if endpoint == Endpoint::Authority {
        let same_origin =
            from.scheme() == to.scheme() && from.host() == to.host() && from.port() == to.port();
        let same_host_upgrade = from.scheme() == Scheme::Http
            && to.scheme() == Scheme::Https
            && from.host() == to.host();
        if !same_origin && !same_host_upgrade {
            return Err(HttpError::UnsafeRedirect(
                "configured authority changed origin".to_owned(),
            ));
        }
    }
    Ok(())
}

fn get_once(
    url: &Uri,
    max_bytes: usize,
    user_agent: &str,
    endpoint: Endpoint,
) -> Result<ExchangeResponse, HttpError> {
    let address = resolve_destination(url, endpoint)?;
    if url.scheme() == Scheme::Https {
        return https_get_to(url, address, max_bytes, user_agent);
    }
    let stream = connected_stream(address)?;
    match do_get(
        stream,
        &HttpHelpers::authority(url),
        &HttpHelpers::request_target(url),
        max_bytes,
        user_agent,
    ) {
        Ok(body) => Ok(ExchangeResponse {
            code: 200,
            reason: "OK".to_owned(),
            location: None,
            body,
        }),
        Err(HttpError::HttpStatus {
            code,
            reason,
            location,
        }) => Ok(ExchangeResponse {
            code,
            reason,
            location,
            body: Vec::new(),
        }),
        Err(error) => Err(error),
    }
}

fn post_once(
    url: &Uri,
    content_type: &str,
    body: &[u8],
    max_bytes: usize,
    user_agent: &str,
    endpoint: Endpoint,
    authorization: Option<&str>,
) -> Result<ExchangeResponse, HttpError> {
    let address = resolve_destination(url, endpoint)?;
    if url.scheme() == Scheme::Https {
        return https_post_to(
            url,
            address,
            content_type,
            body,
            max_bytes,
            user_agent,
            authorization,
        );
    }
    let stream = connected_stream(address)?;
    match do_post(
        stream,
        &HttpHelpers::authority(url),
        &HttpHelpers::request_target(url),
        content_type,
        body,
        max_bytes,
        user_agent,
    ) {
        Ok(body) => Ok(ExchangeResponse {
            code: 200,
            reason: "OK".to_owned(),
            location: None,
            body,
        }),
        Err(HttpError::HttpStatus {
            code,
            reason,
            location,
        }) => Ok(ExchangeResponse {
            code,
            reason,
            location,
            body: Vec::new(),
        }),
        Err(error) => Err(error),
    }
}

fn connected_stream(address: SocketAddr) -> Result<TcpStream, HttpError> {
    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(30))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    Ok(stream)
}

/// Issue an HTTP/1.1 GET on an already-connected TCP stream.
///
/// RFC 9112 §3. `Connection: close` so the server can stream
/// the body without chunked framing if it prefers; the
/// response reader handles both. Headers are minimal --
/// `Host`, `User-Agent`, `Accept`. No keep-alive: every
/// FINEID PKI fetch is one round trip.
fn do_get<S: Read + Write>(
    mut stream: S,
    host_header: &str,
    path: &str,
    max_bytes: usize,
    user_agent: &str,
) -> Result<Vec<u8>, HttpError> {
    let req = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         User-Agent: {user_agent}\r\n\
         Accept: */*\r\n\
         Connection: close\r\n\
         \r\n"
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;
    HttpHelpers::read_response(&mut BufReader::new(stream), max_bytes)
}

/// Issue an HTTP/1.1 POST on an already-connected TCP stream.
///
/// RFC 9112 §3. Mirrors [`do_get`] but adds `Content-Type`
/// and `Content-Length`. Used for OCSP requests
/// (`application/ocsp-request` payloads, RFC 6960 §2.1).
fn do_post<S: Read + Write>(
    mut stream: S,
    host_header: &str,
    path: &str,
    content_type: &str,
    body: &[u8],
    max_bytes: usize,
    user_agent: &str,
) -> Result<Vec<u8>, HttpError> {
    let head = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         User-Agent: {user_agent}\r\n\
         Accept: */*\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n",
        len = body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    HttpHelpers::read_response(&mut BufReader::new(stream), max_bytes)
}

fn resolve_destination(url: &Uri, endpoint: Endpoint) -> Result<SocketAddr, HttpError> {
    let host = url.host().to_string();
    if endpoint == Endpoint::CertificateMaterial && !host_could_be_public(&host) {
        return Err(HttpError::UnsafeDestination(host));
    }
    let mut addresses = Vec::new();
    for address in resolve_addresses(&host, url.port(), endpoint)? {
        if addresses.contains(&address) {
            continue;
        }
        addresses.push(address);
        if addresses.len() > MAX_RESOLVED_ADDRESSES {
            return Err(HttpError::UnsafeDestination(format!(
                "{host} resolved to more than {MAX_RESOLVED_ADDRESSES} addresses"
            )));
        }
    }
    if addresses.is_empty() {
        return Err(HttpError::BadUrl("no address resolved"));
    }
    if endpoint == Endpoint::CertificateMaterial
        && let Some(unsafe_address) = addresses.iter().find(|address| !is_public(address.ip()))
    {
        return Err(HttpError::UnsafeDestination(format!(
            "{host} resolved to non-public address {}",
            unsafe_address.ip()
        )));
    }
    addresses
        .into_iter()
        .next()
        .ok_or(HttpError::BadUrl("no address resolved"))
}

/// Result of one local DNSSEC validation attempt.
#[derive(Debug, PartialEq, Eq)]
enum DnssecLookup {
    /// At least one address was chained to the root trust anchor.
    Secure(Vec<IpAddr>),
    /// DNSSEC securely proved that this record type has no address.
    SecureEmpty,
    /// The zone is unsigned or validation was unavailable.
    Fallback,
    /// A signed answer failed local validation.
    Bogus,
}

fn resolve_addresses(
    host: &str,
    port: u16,
    endpoint: Endpoint,
) -> Result<Vec<SocketAddr>, HttpError> {
    use std::net::ToSocketAddrs as _;

    if let Ok(address) = host.trim_end_matches('.').parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(address, port)]);
    }
    // Explicit authorities are allowed to name local development services.
    // DNSSEC intentionally has no role for localhost, mDNS, or legacy numeric
    // spellings; preserve the platform resolver semantics for those names.
    if endpoint == Endpoint::Authority && authority_uses_platform_resolver(host) {
        return Ok((host, port).to_socket_addrs()?.collect());
    }

    match dnssec_lookup(host) {
        DnssecLookup::Secure(addresses) => Ok(addresses
            .into_iter()
            .map(|address| SocketAddr::new(address, port))
            .collect()),
        DnssecLookup::SecureEmpty => Err(HttpError::BadUrl(
            "DNSSEC securely denied an address family and no secure address was available",
        )),
        DnssecLookup::Bogus => Err(HttpError::UnsafeDestination(format!(
            "{host} failed DNSSEC validation"
        ))),
        DnssecLookup::Fallback => Ok((host, port).to_socket_addrs()?.collect()),
    }
}

fn authority_uses_platform_resolver(host: &str) -> bool {
    let normalized = host.trim_end_matches('.');
    !host_could_be_public(normalized) || !normalized.contains('.')
}

/// Run Hickory on its own current-thread runtime. The extra OS thread keeps
/// this synchronous API usable even when its caller already runs on Tokio.
fn dnssec_lookup(host: &str) -> DnssecLookup {
    let host = host.to_owned();
    let worker = std::thread::Builder::new()
        .name("refineid-dnssec".to_owned())
        .spawn(move || dnssec_lookup_on_worker(&host));
    worker.map_or(DnssecLookup::Fallback, |worker| {
        worker.join().unwrap_or(DnssecLookup::Fallback)
    })
}

fn dnssec_lookup_on_worker(host: &str) -> DnssecLookup {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    else {
        return DnssecLookup::Fallback;
    };
    let Ok(mut builder) = Resolver::builder_tokio() else {
        return DnssecLookup::Fallback;
    };
    let options = builder.options_mut();
    options.validate = true;
    options.timeout = DNSSEC_QUERY_TIMEOUT;
    options.attempts = 1;
    options.use_hosts_file = ResolveHosts::Never;
    options.preserve_intermediates = true;
    options.try_tcp_on_error = true;
    let Ok(resolver) = builder.build() else {
        return DnssecLookup::Fallback;
    };
    let name = format!("{}.", host.trim_end_matches('.'));
    runtime.block_on(async {
        let deadline = tokio::time::Instant::now() + DNSSEC_ATTEMPT_TIMEOUT;
        let (ipv4, ipv6) = tokio::join!(
            tokio::time::timeout_at(deadline, resolver.lookup(&name, RecordType::A)),
            tokio::time::timeout_at(deadline, resolver.lookup(&name, RecordType::AAAA)),
        );
        let ipv4 = ipv4.map_or(DnssecLookup::Fallback, |result| {
            classify_dnssec_lookup(result, RecordType::A)
        });
        let ipv6 = ipv6.map_or(DnssecLookup::Fallback, |result| {
            classify_dnssec_lookup(result, RecordType::AAAA)
        });
        combine_dnssec_lookups(ipv4, ipv6)
    })
}

fn classify_dnssec_lookup(result: Result<Lookup, NetError>, expected: RecordType) -> DnssecLookup {
    match result {
        Ok(lookup) => {
            let records = lookup.answers().iter().filter_map(|record| {
                let address = match &record.data {
                    RData::A(address) if expected == RecordType::A => Some(IpAddr::V4(address.0)),
                    RData::AAAA(address) if expected == RecordType::AAAA => {
                        Some(IpAddr::V6(address.0))
                    }
                    RData::CNAME(_) => None,
                    _ => return None,
                };
                Some((record.proof, address))
            });
            classify_proven_addresses(records)
        }
        Err(error) => classify_dnssec_error(&error),
    }
}

fn classify_dnssec_error(error: &NetError) -> DnssecLookup {
    match error {
        NetError::Dns(DnsError::Nsec { proof, .. }) => match proof {
            Proof::Bogus => DnssecLookup::Bogus,
            Proof::Secure => DnssecLookup::SecureEmpty,
            Proof::Insecure | Proof::Indeterminate => DnssecLookup::Fallback,
        },
        NetError::Dns(DnsError::NoRecordsFound(no_records)) => {
            let Some(authorities) = no_records.authorities.as_deref() else {
                return DnssecLookup::Fallback;
            };
            let records = authorities.iter().filter_map(|record| {
                matches!(record.record_type(), RecordType::NSEC | RecordType::NSEC3)
                    .then_some((record.proof, None))
            });
            classify_proven_addresses(records)
        }
        _ => DnssecLookup::Fallback,
    }
}

fn classify_proven_addresses(
    records: impl IntoIterator<Item = (Proof, Option<IpAddr>)>,
) -> DnssecLookup {
    let mut addresses = Vec::new();
    let mut saw_record = false;
    let mut needs_fallback = false;
    for (proof, address) in records {
        saw_record = true;
        match proof {
            Proof::Secure => {
                if let Some(address) = address
                    && !addresses.contains(&address)
                {
                    addresses.push(address);
                }
            }
            Proof::Bogus => return DnssecLookup::Bogus,
            Proof::Insecure | Proof::Indeterminate => needs_fallback = true,
        }
    }
    if !saw_record || needs_fallback {
        DnssecLookup::Fallback
    } else if addresses.is_empty() {
        DnssecLookup::SecureEmpty
    } else {
        DnssecLookup::Secure(addresses)
    }
}

fn combine_dnssec_lookups(first: DnssecLookup, second: DnssecLookup) -> DnssecLookup {
    let has_secure_empty =
        first == DnssecLookup::SecureEmpty || second == DnssecLookup::SecureEmpty;
    let has_bogus = first == DnssecLookup::Bogus || second == DnssecLookup::Bogus;
    let mut addresses = Vec::new();
    for lookup in [first, second] {
        if let DnssecLookup::Secure(found) = lookup {
            for address in found {
                if !addresses.contains(&address) {
                    addresses.push(address);
                }
            }
        }
    }
    // DNSSEC status belongs to one queried RRset. A secure A answer remains
    // authenticated when the independent AAAA lookup is bogus (and vice
    // versa), so connect only to the secure addresses. Bogus stays fatal when
    // neither family supplied an authenticated address.
    if !addresses.is_empty() {
        DnssecLookup::Secure(addresses)
    } else if has_bogus {
        DnssecLookup::Bogus
    } else if has_secure_empty {
        DnssecLookup::SecureEmpty
    } else {
        DnssecLookup::Fallback
    }
}

fn host_could_be_public(host: &str) -> bool {
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized == "localhost"
        || normalized.strip_suffix(".localhost").is_some()
        || normalized == "local"
        || normalized.strip_suffix(".local").is_some()
    {
        return false;
    }
    if let Ok(address) = normalized.parse::<IpAddr>() {
        return is_public(address);
    }
    !looks_like_numeric_address(&normalized)
}

fn looks_like_numeric_address(host: &str) -> bool {
    host.bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || host.starts_with("0x")
}

const fn is_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

const fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [first, second, third, _fourth] = address.octets();
    if first == 0 || first == 10 || first == 127 || first >= 224 {
        return false;
    }
    if first == 100 && second >= 64 && second <= 127 {
        return false;
    }
    if first == 169 && second == 254 {
        return false;
    }
    if first == 172 && second >= 16 && second <= 31 {
        return false;
    }
    if first == 192 && (second == 0 || second == 168) {
        return false;
    }
    if first == 198 && (second == 18 || second == 19) {
        return false;
    }
    // RFC 5737 documentation networks.
    if (first == 192 && second == 0 && third == 2)
        || (first == 198 && second == 51 && third == 100)
        || (first == 203 && second == 0 && third == 113)
    {
        return false;
    }
    true
}

const fn is_public_ipv6(address: Ipv6Addr) -> bool {
    let bytes = address.octets();
    if address.is_unspecified() || address.is_loopback() {
        return false;
    }

    // IPv4-compatible, IPv4-mapped, well-known NAT64 and 6to4 forms
    // carry a destination that must be classified as IPv4 rather than
    // accepted because its outer address looks global.
    if let Some(embedded) = embedded_ipv4(bytes) {
        return is_public_ipv4(embedded);
    }

    let first = bytes[0];
    let second = bytes[1];
    if first == 252 || first == 253 || first == 255 {
        return false;
    }
    if first == 254 && second >= 128 {
        return false;
    }
    if bytes[0] == 32 && bytes[1] == 1 && bytes[2] == 13 && bytes[3] == 184 {
        return false;
    }
    // RFC 8215 local-use translation prefix 64:ff9b:1::/48.
    if bytes[0] == 0
        && bytes[1] == 100
        && bytes[2] == 255
        && bytes[3] == 155
        && bytes[4] == 0
        && bytes[5] == 1
    {
        return false;
    }
    true
}

const fn embedded_ipv4(bytes: [u8; 16]) -> Option<Ipv4Addr> {
    let compatible = bytes[0] == 0
        && bytes[1] == 0
        && bytes[2] == 0
        && bytes[3] == 0
        && bytes[4] == 0
        && bytes[5] == 0
        && bytes[6] == 0
        && bytes[7] == 0
        && bytes[8] == 0
        && bytes[9] == 0
        && bytes[10] == 0
        && bytes[11] == 0;
    let mapped = bytes[0] == 0
        && bytes[1] == 0
        && bytes[2] == 0
        && bytes[3] == 0
        && bytes[4] == 0
        && bytes[5] == 0
        && bytes[6] == 0
        && bytes[7] == 0
        && bytes[8] == 0
        && bytes[9] == 0
        && bytes[10] == 255
        && bytes[11] == 255;
    let nat64 = bytes[0] == 0
        && bytes[1] == 100
        && bytes[2] == 255
        && bytes[3] == 155
        && bytes[4] == 0
        && bytes[5] == 0
        && bytes[6] == 0
        && bytes[7] == 0
        && bytes[8] == 0
        && bytes[9] == 0
        && bytes[10] == 0
        && bytes[11] == 0;
    if compatible || mapped || nat64 {
        return Some(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]));
    }
    if bytes[0] == 32 && bytes[1] == 2 {
        return Some(Ipv4Addr::new(bytes[2], bytes[3], bytes[4], bytes[5]));
    }
    None
}

#[cfg(feature = "https")]
fn https_get_to(
    url: &Uri,
    address: SocketAddr,
    max_bytes: usize,
    user_agent: &str,
) -> Result<ExchangeResponse, HttpError> {
    let response = refineid_lib_tls::simple_https::get_to(url, address, max_bytes, user_agent)
        .map_err(|error| map_https_error(&error))?;
    Ok(ExchangeResponse {
        code: response.status,
        reason: String::new(),
        location: response.location,
        body: response.body,
    })
}

#[cfg(not(feature = "https"))]
fn https_get_to(
    _url: &Uri,
    _address: SocketAddr,
    _max_bytes: usize,
    _user_agent: &str,
) -> Result<ExchangeResponse, HttpError> {
    Err(HttpError::UnsupportedScheme(
        "https (build lacks the `https` feature)".to_owned(),
    ))
}

#[cfg(feature = "https")]
fn https_post_to(
    url: &Uri,
    address: SocketAddr,
    content_type: &str,
    body: &[u8],
    max_bytes: usize,
    user_agent: &str,
    authorization: Option<&str>,
) -> Result<ExchangeResponse, HttpError> {
    let response = authorization
        .map_or_else(
            || {
                refineid_lib_tls::simple_https::post_to(
                    url,
                    address,
                    content_type,
                    body,
                    max_bytes,
                    user_agent,
                )
            },
            |authorization| {
                refineid_lib_tls::simple_https::post_to_authorized(
                    url,
                    address,
                    content_type,
                    body,
                    max_bytes,
                    user_agent,
                    authorization,
                )
            },
        )
        .map_err(|error| map_https_error(&error))?;
    Ok(ExchangeResponse {
        code: response.status,
        reason: String::new(),
        location: response.location,
        body: response.body,
    })
}

#[cfg(feature = "https")]
fn map_https_error(error: &refineid_lib_tls::simple_https::HttpsError) -> HttpError {
    let retryable = error.is_transient();
    HttpError::Https {
        detail: error.to_string(),
        retryable,
    }
}

#[cfg(not(feature = "https"))]
fn https_post_to(
    _url: &Uri,
    _address: SocketAddr,
    _content_type: &str,
    _body: &[u8],
    _max_bytes: usize,
    _user_agent: &str,
    _authorization: Option<&str>,
) -> Result<ExchangeResponse, HttpError> {
    Err(HttpError::UnsupportedScheme(
        "https (build lacks the `https` feature)".to_owned(),
    ))
}

impl HttpHelpers {
    /// Parse an HTTP/1.1 response (status line + headers +
    /// body) from a `BufRead` source, capping the body at
    /// `max_bytes`.
    ///
    /// RFC 9112 §4 (status line), §5 (headers), §7 (body).
    /// Body length is taken from `Content-Length` or
    /// transfer-encoding `chunked`; absent both is rejected as
    /// [`HttpError::UnknownBodyLength`] so the caller never
    /// gets a partial response. 4xx/5xx and unknown status
    /// classes return [`HttpError::HttpStatus`].
    fn read_response<R: BufRead>(reader: &mut R, max_bytes: usize) -> Result<Vec<u8>, HttpError> {
        /// Inclusive lower bound of HTTP success-class status
        /// codes (RFC 9110 §15.3).
        const HTTP_SUCCESS_MIN: u16 = 200;
        /// Exclusive upper bound of HTTP success-class status
        /// codes (300 = first redirection-class code).
        const HTTP_SUCCESS_END: u16 = 300;

        // Status line.
        let mut status_line = String::new();
        let _read_bytes: usize = reader.read_line(&mut status_line)?;
        let trimmed = status_line.trim_end_matches(['\r', '\n']);
        let mut parts = trimmed.splitn(3, ' ');
        let _version = parts
            .next()
            .ok_or_else(|| HttpError::BadStatusLine(trimmed.to_owned()))?;
        let code: u16 = parts
            .next()
            .ok_or_else(|| HttpError::BadStatusLine(trimmed.to_owned()))?
            .parse()
            // BadStatusLine already carries the original status
            // line; the ParseIntError text would be redundant.
            .map_err(|_parse_err: core::num::ParseIntError| {
                HttpError::BadStatusLine(trimmed.to_owned())
            })?;
        let reason = parts.next().unwrap_or("").to_owned();

        // Headers.
        let mut content_length: Option<usize> = None;
        let mut chunked = false;
        let mut location: Option<String> = None;
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line)?;
            if n == 0 {
                break;
            }
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                break;
            }
            if let Some((name, value)) = trimmed.split_once(':') {
                let name = name.trim().to_ascii_lowercase();
                let value = value.trim();
                if name == "content-length" {
                    content_length = value.parse::<usize>().ok();
                } else if name == "transfer-encoding" && value.eq_ignore_ascii_case("chunked") {
                    chunked = true;
                } else if name == "location" {
                    location = Some(value.to_owned());
                } else {
                    // Other response headers: not consumed by this client.
                }
            }
        }

        if !(HTTP_SUCCESS_MIN..HTTP_SUCCESS_END).contains(&code) {
            return Err(HttpError::HttpStatus {
                code,
                reason,
                location,
            });
        }

        let body = if chunked {
            Self::read_chunked_body(reader, max_bytes)?
        } else if let Some(len) = content_length {
            if len > max_bytes {
                return Err(HttpError::BodyTooLarge {
                    content_length: len,
                    limit: max_bytes,
                });
            }
            let mut buf = vec![0_u8; len];
            reader.read_exact(&mut buf)?;
            buf
        } else {
            return Err(HttpError::UnknownBodyLength);
        };

        Ok(body)
    }
}

impl HttpHelpers {
    /// Decode an HTTP/1.1 chunked-encoded body.
    ///
    /// RFC 9112 §7.1. Each chunk is `hex-size CRLF data
    /// CRLF`; the terminator is a zero-size chunk. Chunk-
    /// extensions (everything after `;` on the size line) are
    /// ignored per the spec. Refuses bodies that exceed
    /// `max_bytes` mid-stream so an unbounded chunk encoder
    /// can't OOM us.
    fn read_chunked_body<R: BufRead>(
        reader: &mut R,
        max_bytes: usize,
    ) -> Result<Vec<u8>, HttpError> {
        /// Radix for chunk-size hex per RFC 9112 §7.1.
        const CHUNK_SIZE_RADIX: u32 = 16;
        /// CRLF length (two bytes per RFC 9112 §7.1 chunk
        /// framing).
        const CRLF_LEN: usize = 2;
        let mut out = Vec::new();
        loop {
            let mut size_line = String::new();
            let _read_bytes: usize = reader.read_line(&mut size_line)?;
            let size_str = size_line
                .trim_end_matches(['\r', '\n'])
                .split(';')
                .next()
                .unwrap_or("");
            let size = usize::from_str_radix(size_str, CHUNK_SIZE_RADIX)
                // BadChunkSize already carries the offending hex
                // string; ParseIntError prose would duplicate it.
                .map_err(|_parse_err: core::num::ParseIntError| {
                    HttpError::BadChunkSize(size_str.to_owned())
                })?;
            if size == 0 {
                // Trailer + final CRLF -- skip any trailer headers.
                loop {
                    let mut t = String::new();
                    let n = reader.read_line(&mut t)?;
                    if n == 0 {
                        break;
                    }
                    if t.trim_end_matches(['\r', '\n']).is_empty() {
                        break;
                    }
                }
                break;
            }
            let projected = out.len().checked_add(size).ok_or(HttpError::BodyTooLarge {
                content_length: usize::MAX,
                limit: max_bytes,
            })?;
            if projected > max_bytes {
                return Err(HttpError::BodyTooLarge {
                    content_length: projected,
                    limit: max_bytes,
                });
            }
            let start = out.len();
            out.resize(projected, 0_u8);
            let chunk_slice = out.get_mut(start..).ok_or_else(|| {
                // Cannot happen: we just resized to `projected >= start`.
                // Surface as BadChunkSize rather than panicking so a
                // pathological resize is propagated, not asserted.
                HttpError::BadChunkSize("chunk slice bounds".to_owned())
            })?;
            reader.read_exact(chunk_slice)?;
            // Each chunk is followed by CRLF.
            let mut crlf = [0_u8; CRLF_LEN];
            reader.read_exact(&mut crlf)?;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DnssecLookup, Endpoint, HttpError, HttpHelpers, authority_uses_platform_resolver,
        check_redirect, classify_proven_addresses, combine_dnssec_lookups, host_could_be_public,
        is_public, looks_like_numeric_address, post_authority, resolve_addresses,
    };
    use crate::test_util::{TestResult, check, check_true};

    #[test]
    fn authority_credentials_are_refused_before_plain_http_io() {
        let url = Uri::parse("http://127.0.0.1:9/tsa".to_owned()).expect("test URL");
        let auth_header = format!(
            "Basic {}",
            refineid_lib_core::base64::encode(b"test-user:test-pass")
        );
        let error = post_authority(
            &url,
            "application/timestamp-query",
            b"request",
            1024,
            "test",
            Some(&auth_header),
        )
        .expect_err("credentials cannot cross plain HTTP");
        assert!(matches!(error, HttpError::InsecureCredentials));
    }

    #[test]
    fn authority_retry_classification_separates_temporary_and_permanent_failures() {
        let status = |code| HttpError::HttpStatus {
            code,
            reason: String::new(),
            location: None,
        };
        for code in [408, 425, 429, 500, 502, 503, 504] {
            assert!(status(code).is_retryable_authority_failure(), "HTTP {code}");
        }
        for code in [400, 401, 403, 411, 413, 415, 501] {
            assert!(
                !status(code).is_retryable_authority_failure(),
                "HTTP {code}"
            );
        }
        assert!(
            HttpError::Io(std::io::Error::from(std::io::ErrorKind::TimedOut))
                .is_retryable_authority_failure()
        );
        assert!(
            !HttpError::UnsafeDestination("DNSSEC validation failed".to_owned())
                .is_retryable_authority_failure()
        );
    }
    use hickory_resolver::proto::dnssec::Proof;
    use refineid_lib_core::text::Uri;
    use std::io::Cursor;
    use std::net::IpAddr;

    // URL parsing lives in the `Uri` type (refineid-lib-core
    // text.rs). These tests cover HTTP framing.

    fn synthetic_response(headers: &str, body: &[u8]) -> Vec<u8> {
        let mut v = headers.as_bytes().to_vec();
        // CRLF terminating the last header field + the empty line
        // that ends the header block.
        v.extend_from_slice(b"\r\n\r\n");
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn content_length_response_round_trips() -> TestResult {
        let body: &[u8] = b"hello";
        let resp = synthetic_response(
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close",
            body,
        );
        let parsed = HttpHelpers::read_response(&mut Cursor::new(resp), 1024_usize)?;
        check(parsed.as_slice(), body, "body")
    }

    #[test]
    fn chunked_response_round_trips() -> TestResult {
        // Three chunks: 4, 6, 0
        let mut resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        resp.extend_from_slice(b"4\r\nWiki\r\n6\r\npedia!\r\n0\r\n\r\n");
        let parsed = HttpHelpers::read_response(&mut Cursor::new(resp), 1024_usize)?;
        check(parsed.as_slice(), b"Wikipedia!".as_slice(), "body")
    }

    #[test]
    fn rejects_404() -> TestResult {
        let resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec();
        let r = HttpHelpers::read_response(&mut Cursor::new(resp), 1024_usize);
        match r {
            Err(HttpError::HttpStatus { code, .. }) => check(&code, &404_u16, "code"),
            other => Err(format!("expected HttpStatus, got {other:?}").into()),
        }
    }

    #[test]
    fn rejects_oversized_content_length() -> TestResult {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n".to_vec();
        let r = HttpHelpers::read_response(&mut Cursor::new(resp), 10_usize);
        check_true(
            matches!(r, Err(HttpError::BodyTooLarge { .. })),
            "BodyTooLarge",
        )
    }

    #[test]
    fn rejects_unknown_body_length() -> TestResult {
        let resp = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello".to_vec();
        let r = HttpHelpers::read_response(&mut Cursor::new(resp), 1024_usize);
        check_true(
            matches!(r, Err(HttpError::UnknownBodyLength)),
            "UnknownBodyLength",
        )
    }

    #[test]
    fn case_insensitive_header_names() -> TestResult {
        let body: &[u8] = b"abc";
        let resp = synthetic_response("HTTP/1.1 200 OK\r\nCONTENT-LENGTH: 3", body);
        let parsed = HttpHelpers::read_response(&mut Cursor::new(resp), 1024_usize)?;
        check(parsed.as_slice(), body, "body")
    }

    #[test]
    fn certificate_hosts_reject_local_and_ambiguous_numeric_forms() -> TestResult {
        for host in [
            "localhost",
            "service.localhost",
            "printer.local",
            "127.1",
            "0177.0.0.1",
            "2130706433",
            "0x7f000001",
        ] {
            check_true(
                !host_could_be_public(host),
                &format!("{host} must be refused"),
            )?;
        }
        check_true(looks_like_numeric_address("127.1"), "short IPv4 spelling")?;
        check_true(host_could_be_public("pki.example.com"), "ordinary DNS host")
    }

    #[test]
    fn explicit_local_authority_keeps_platform_resolution() -> TestResult {
        let addresses = resolve_addresses("localhost", 8318, Endpoint::Authority)?;
        check_true(!addresses.is_empty(), "localhost address")?;
        check_true(
            addresses.iter().all(|address| address.ip().is_loopback()),
            "localhost must stay local",
        )
    }

    #[test]
    fn single_label_authority_keeps_platform_search_domains() -> TestResult {
        check_true(
            authority_uses_platform_resolver("tsa"),
            "single-label authority",
        )?;
        check_true(
            !authority_uses_platform_resolver("tsa.example"),
            "fully qualified authority",
        )
    }

    #[test]
    fn ipv4_policy_rejects_non_public_ranges() -> TestResult {
        for text in [
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.0.2.1",
            "192.168.0.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            let address: IpAddr = text.parse()?;
            check_true(!is_public(address), &format!("{text} must be refused"))?;
        }
        for text in ["8.8.8.8", "93.184.216.34"] {
            let address: IpAddr = text.parse()?;
            check_true(is_public(address), &format!("{text} must be accepted"))?;
        }
        Ok(())
    }

    #[test]
    fn ipv6_policy_classifies_embedded_and_local_addresses() -> TestResult {
        for text in [
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "64:ff9b::10.0.0.1",
            "64:ff9b:1::1",
            "2001:db8::1",
            "2002:0a00:0001::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
        ] {
            let address: IpAddr = text.parse()?;
            check_true(!is_public(address), &format!("{text} must be refused"))?;
        }
        for text in ["2606:4700:4700::1111", "2001:4860:4860::8888"] {
            let address: IpAddr = text.parse()?;
            check_true(is_public(address), &format!("{text} must be accepted"))?;
        }
        Ok(())
    }

    #[test]
    fn dnssec_secure_answers_are_preferred_over_unavailable_family() -> TestResult {
        let address: IpAddr = "93.184.216.34".parse()?;
        let secure = classify_proven_addresses([(Proof::Secure, Some(address))]);
        let combined = combine_dnssec_lookups(secure, DnssecLookup::Fallback);
        check(
            &combined,
            &DnssecLookup::Secure(vec![address]),
            "secure DNSSEC address",
        )
    }

    #[test]
    fn dnssec_bogus_proof_never_downgrades_to_system_resolution() -> TestResult {
        let address: IpAddr = "93.184.216.34".parse()?;
        let bogus = classify_proven_addresses([(Proof::Bogus, Some(address))]);
        let combined = combine_dnssec_lookups(DnssecLookup::Fallback, bogus);
        check(&combined, &DnssecLookup::Bogus, "bogus DNSSEC answer")
    }

    #[test]
    fn dnssec_secure_address_survives_bogus_other_family() -> TestResult {
        let address: IpAddr = "93.184.216.34".parse()?;
        for combined in [
            combine_dnssec_lookups(DnssecLookup::Secure(vec![address]), DnssecLookup::Bogus),
            combine_dnssec_lookups(DnssecLookup::Bogus, DnssecLookup::Secure(vec![address])),
        ] {
            check(
                &combined,
                &DnssecLookup::Secure(vec![address]),
                "independently secure address-family answer",
            )?;
        }
        Ok(())
    }

    #[test]
    fn dnssec_unsigned_or_indeterminate_chain_uses_one_fallback() -> TestResult {
        let address: IpAddr = "93.184.216.34".parse()?;
        for proof in [Proof::Insecure, Proof::Indeterminate] {
            let result = classify_proven_addresses([(Proof::Secure, None), (proof, Some(address))]);
            check(&result, &DnssecLookup::Fallback, "unvalidated DNS chain")?;
        }
        Ok(())
    }

    #[test]
    fn dnssec_secure_negative_answers_do_not_fall_back() -> TestResult {
        let empty = classify_proven_addresses([(Proof::Secure, None)]);
        let combined = combine_dnssec_lookups(empty, DnssecLookup::SecureEmpty);
        check(
            &combined,
            &DnssecLookup::SecureEmpty,
            "secure negative DNSSEC answer",
        )
    }

    #[test]
    fn dnssec_secure_ipv4_negative_blocks_unscoped_ipv6_fallback() -> TestResult {
        let combined = combine_dnssec_lookups(DnssecLookup::SecureEmpty, DnssecLookup::Fallback);
        check(
            &combined,
            &DnssecLookup::SecureEmpty,
            "secure A denial must not permit an all-family fallback",
        )
    }

    #[test]
    fn dnssec_secure_ipv6_negative_blocks_unscoped_ipv4_fallback() -> TestResult {
        let combined = combine_dnssec_lookups(DnssecLookup::Fallback, DnssecLookup::SecureEmpty);
        check(
            &combined,
            &DnssecLookup::SecureEmpty,
            "secure AAAA denial must not permit an all-family fallback",
        )
    }

    #[test]
    fn authority_redirect_stays_on_origin_or_upgrades_same_host() -> TestResult {
        let initial = Uri::parse("http://tsa.example:8080/old".to_owned())?;
        let same_origin = Uri::parse("http://tsa.example:8080/new".to_owned())?;
        check_redirect(&initial, &same_origin, Endpoint::Authority)?;

        let upgrade = Uri::parse("https://tsa.example/new".to_owned())?;
        check_redirect(&initial, &upgrade, Endpoint::Authority)?;

        let other = Uri::parse("https://relay.example/new".to_owned())?;
        check_true(
            check_redirect(&initial, &other, Endpoint::Authority).is_err(),
            "cross-host authority redirect",
        )?;

        let secure = Uri::parse("https://tsa.example/old".to_owned())?;
        let downgrade = Uri::parse("http://tsa.example/new".to_owned())?;
        check_true(
            check_redirect(&secure, &downgrade, Endpoint::CertificateMaterial).is_err(),
            "HTTPS downgrade",
        )
    }
}
