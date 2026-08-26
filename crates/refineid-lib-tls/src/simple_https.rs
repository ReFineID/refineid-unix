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

//! Small server-authenticated HTTPS client.
//!
//! Public infrastructure fetches such as EU trusted-list downloads,
//! RFC 3161 TSA calls, and validator APIs need ordinary HTTPS server
//! authentication, not FINEID client-certificate authentication. This
//! module never configures a client certificate or private-key
//! callback.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use refineid_lib_core::text::{Scheme, Uri};
use zeroize::Zeroizing;

use crate::framing::{Framing, FramingError};
use crate::http::HttpParseError;
use crate::policy::TransportPolicy;

/// Connect/read/write timeout for one simple HTTPS request.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// What failed while fetching over server-authenticated HTTPS.
#[derive(Debug)]
#[non_exhaustive]
pub enum HttpsError {
    /// URL was not `https://`.
    UnsupportedScheme,
    /// The crate was built without a TLS backend feature.
    NoTlsBackend,
    /// DNS resolution or TCP connection failed.
    Connect(String),
    /// TLS configuration or handshake failed.
    Tls(String),
    /// HTTP response framing failed.
    Framing(FramingError),
    /// HTTP response parsing failed.
    Http(HttpParseError),
    /// Server returned a non-2xx status.
    HttpStatus {
        /// HTTP status code.
        code: u16,
    },
    /// An authorization value was not a single RFC 7617 Basic header value.
    InvalidAuthorization,
}

/// One response from the deliberately small HTTPS client.
///
/// Unlike [`get`] and [`post`], the address-pinned entry points return
/// redirect responses to their caller. The caller owns redirect policy
/// because only it knows whether the URL came from a certificate, a
/// trusted list, or an explicit user configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleResponse {
    /// HTTP status code.
    pub status: u16,
    /// `Location` header, when present.
    pub location: Option<String>,
    /// Response body, bounded by the caller's `max_bytes` limit.
    pub body: Vec<u8>,
}

impl SimpleResponse {
    /// Return the body of a successful response, or a typed HTTP-status
    /// error for every other status class.
    fn success_body(self) -> Result<Vec<u8>, HttpsError> {
        if (200..300).contains(&self.status) {
            Ok(self.body)
        } else {
            Err(HttpsError::HttpStatus { code: self.status })
        }
    }
}

impl core::fmt::Display for HttpsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedScheme => f.write_str("URL is not https://"),
            Self::NoTlsBackend => f.write_str("no TLS backend compiled into this build"),
            Self::Connect(detail) => write!(f, "connect: {detail}"),
            Self::Tls(detail) => write!(f, "TLS: {detail}"),
            Self::Framing(error) => write!(f, "HTTP framing: {error}"),
            Self::Http(error) => write!(f, "HTTP parse: {error}"),
            Self::HttpStatus { code } => write!(f, "HTTP {code}"),
            Self::InvalidAuthorization => f.write_str("invalid Basic authorization value"),
        }
    }
}

impl core::error::Error for HttpsError {}

impl HttpsError {
    /// Whether repeating the same request may recover without changing its
    /// URL, credentials, trust policy, or payload.
    #[must_use]
    pub const fn is_transient(&self) -> bool {
        matches!(self, Self::Connect(_) | Self::Framing(_))
    }
}

impl From<FramingError> for HttpsError {
    fn from(error: FramingError) -> Self {
        Self::Framing(error)
    }
}

impl From<HttpParseError> for HttpsError {
    fn from(error: HttpParseError) -> Self {
        Self::Http(error)
    }
}

/// HTTPS GET, returning the response body for a 2xx response.
///
/// # Errors
/// [`HttpsError`] on unsupported scheme, missing TLS backend,
/// connection/TLS failure, malformed HTTP, oversized body, or non-2xx
/// HTTP status.
pub fn get(url: &Uri, max_bytes: usize, user_agent: &str) -> Result<Vec<u8>, HttpsError> {
    request(url, RequestBody::None, max_bytes, user_agent, None)?.success_body()
}

/// HTTPS GET through an already-vetted destination address.
///
/// DNS is not consulted by this function. TLS authentication and the
/// HTTP `Host` header still use `url`, so certificate-name validation is
/// preserved while the caller is protected from a second resolution
/// between address policy and connection.
///
/// # Errors
/// [`HttpsError`] on a port mismatch, missing TLS backend,
/// connection/TLS failure, malformed HTTP, or an oversized body. HTTP
/// redirects and other non-success statuses are returned in
/// [`SimpleResponse`] for the caller to apply policy.
pub fn get_to(
    url: &Uri,
    address: SocketAddr,
    max_bytes: usize,
    user_agent: &str,
) -> Result<SimpleResponse, HttpsError> {
    request(url, RequestBody::None, max_bytes, user_agent, Some(address))
}

/// HTTPS POST, returning the response body for a 2xx response.
///
/// # Errors
/// [`HttpsError`] as for [`get`].
pub fn post(
    url: &Uri,
    content_type: &str,
    body: &[u8],
    max_bytes: usize,
    user_agent: &str,
) -> Result<Vec<u8>, HttpsError> {
    request(
        url,
        RequestBody::Bytes {
            content_type,
            body,
            authorization: None,
        },
        max_bytes,
        user_agent,
        None,
    )
    .and_then(SimpleResponse::success_body)
}

/// HTTPS POST through an already-vetted destination address.
///
/// DNS is not consulted; SNI, certificate-name validation and `Host`
/// continue to use `url`. Non-success responses are returned so the
/// caller can enforce a context-specific redirect policy.
///
/// # Errors
/// As for [`get_to`].
pub fn post_to(
    url: &Uri,
    address: SocketAddr,
    content_type: &str,
    body: &[u8],
    max_bytes: usize,
    user_agent: &str,
) -> Result<SimpleResponse, HttpsError> {
    request(
        url,
        RequestBody::Bytes {
            content_type,
            body,
            authorization: None,
        },
        max_bytes,
        user_agent,
        Some(address),
    )
}

/// HTTPS POST through an already-vetted destination address with HTTP Basic
/// authorization.
///
/// The value must be the complete `Basic ...` header value. It is checked
/// before connection and zeroized after the request header is written.
///
/// # Errors
/// As for [`post_to`], plus [`HttpsError::InvalidAuthorization`].
pub fn post_to_authorized(
    url: &Uri,
    address: SocketAddr,
    content_type: &str,
    body: &[u8],
    max_bytes: usize,
    user_agent: &str,
    authorization: &str,
) -> Result<SimpleResponse, HttpsError> {
    validate_basic_authorization(authorization)?;
    request(
        url,
        RequestBody::Bytes {
            content_type,
            body,
            authorization: Some(authorization),
        },
        max_bytes,
        user_agent,
        Some(address),
    )
}

fn request(
    url: &Uri,
    body: RequestBody<'_>,
    max_bytes: usize,
    user_agent: &str,
    address: Option<SocketAddr>,
) -> Result<SimpleResponse, HttpsError> {
    if url.scheme() != Scheme::Https {
        return Err(HttpsError::UnsupportedScheme);
    }
    let policy = TransportPolicy::client_auth();
    #[cfg(feature = "tls-rustls")]
    {
        request_with_rustls(url, body, max_bytes, user_agent, &policy, address)
    }
    #[cfg(not(feature = "tls-rustls"))]
    {
        let _unused = (body, max_bytes, user_agent, policy, address);
        Err(HttpsError::NoTlsBackend)
    }
}

#[cfg(feature = "tls-rustls")]
fn request_with_rustls(
    url: &Uri,
    body: RequestBody<'_>,
    max_bytes: usize,
    user_agent: &str,
    policy: &TransportPolicy,
    address: Option<SocketAddr>,
) -> Result<SimpleResponse, HttpsError> {
    use std::sync::Arc;

    // The platform CA bundle, read here rather than handed to the
    // library: rustls takes roots as parsed certificates, not as a path.
    use rustls::pki_types::pem::PemObject as _;

    let ca_path = ca_bundle_path(policy)?;
    let file = std::fs::File::open(&ca_path)
        .map_err(|e| HttpsError::Tls(format!("open({ca_path}): {e}")))?;
    let mut reader = std::io::BufReader::new(file);
    let mut roots = rustls::RootCertStore::empty();
    // PEM parsing comes from rustls-pki-types rather than
    // rustls-pemfile: the latter is archived upstream and is now a
    // wrapper around exactly this code (RUSTSEC-2025-0134).
    for entry in rustls::pki_types::CertificateDer::pem_reader_iter(&mut reader) {
        let cert = entry.map_err(|e| HttpsError::Tls(format!("{ca_path}: parse: {e}")))?;
        roots
            .add(cert)
            .map_err(|e| HttpsError::Tls(format!("{ca_path}: root rejected: {e}")))?;
    }
    if roots.is_empty() {
        return Err(HttpsError::Tls(format!("{ca_path}: no usable roots")));
    }

    // rustls speaks 1.2 and 1.3 only, so the TLS 1.2 floor holds by
    // construction. The ceiling is an escape hatch for a server that
    // mishandles 1.3.
    let versions: &[&rustls::SupportedProtocolVersion] =
        match std::env::var("REFINEID_TLS_MAX").as_deref() {
            Ok("1.2") => &[&rustls::version::TLS12],
            _ => &[&rustls::version::TLS12, &rustls::version::TLS13],
        };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|e| HttpsError::Tls(format!("protocol versions: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();

    let host = url.host().to_string();
    let server_name = rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|e| HttpsError::Tls(format!("server name {host}: {e}")))?;
    let connection = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| HttpsError::Tls(format!("client connection: {e}")))?;
    let socket = tcp_connect(url, address)?;
    // StreamOwned drives the handshake lazily on first read or write,
    // so a handshake failure surfaces from send_request rather than
    // from here.
    let mut stream = rustls::StreamOwned::new(connection, socket);
    send_request(&mut stream, url, body, max_bytes, user_agent)
}

fn send_request<S: Read + Write>(
    stream: &mut S,
    url: &Uri,
    body: RequestBody<'_>,
    max_bytes: usize,
    user_agent: &str,
) -> Result<SimpleResponse, HttpsError> {
    use core::fmt::Write as _;

    let method = body.method();
    let mut request = Zeroizing::new(String::new());
    let _fmt: core::fmt::Result = write!(request, "{method} {} HTTP/1.1\r\n", request_target(url));
    let _fmt: core::fmt::Result = write!(request, "Host: {}\r\n", authority(url));
    let _fmt: core::fmt::Result = write!(request, "User-Agent: {user_agent}\r\n");
    request.push_str("Accept: */*\r\n");
    request.push_str("Accept-Encoding: identity\r\n");
    request.push_str("Connection: close\r\n");
    if let RequestBody::Bytes {
        content_type,
        body,
        authorization,
    } = body
    {
        if let Some(authorization) = authorization {
            validate_basic_authorization(authorization)?;
            let _fmt: core::fmt::Result = write!(request, "Authorization: {authorization}\r\n");
        }
        let _fmt: core::fmt::Result = write!(request, "Content-Type: {content_type}\r\n");
        let _fmt: core::fmt::Result = write!(request, "Content-Length: {}\r\n", body.len());
        request.push_str("\r\n");
        stream
            .write_all(request.as_bytes())
            .map_err(|e| HttpsError::Tls(format!("HTTP write: {e}")))?;
        stream
            .write_all(body)
            .map_err(|e| HttpsError::Tls(format!("HTTP body write: {e}")))?;
    } else {
        request.push_str("\r\n");
        stream
            .write_all(request.as_bytes())
            .map_err(|e| HttpsError::Tls(format!("HTTP write: {e}")))?;
    }
    stream
        .flush()
        .map_err(|e| HttpsError::Tls(format!("HTTP flush: {e}")))?;

    let raw = Framing::read_response(stream, max_bytes)?;
    let response = crate::http::Response::parse(raw, url)?;
    Ok(SimpleResponse {
        status: response.status.code(),
        location: response.headers.get("location").cloned(),
        body: response.body,
    })
}

fn tcp_connect(url: &Uri, address: Option<SocketAddr>) -> Result<TcpStream, HttpsError> {
    use std::net::ToSocketAddrs as _;

    let host = url.host().to_string();
    let socket_addr = if let Some(address) = address {
        if address.port() != url.port() {
            return Err(HttpsError::Connect(format!(
                "vetted address port {} does not match URL port {}",
                address.port(),
                url.port()
            )));
        }
        address
    } else {
        (host.as_str(), url.port())
            .to_socket_addrs()
            .map_err(|e| HttpsError::Connect(format!("{host}:{} resolve: {e}", url.port())))?
            .next()
            .ok_or_else(|| HttpsError::Connect(format!("{host}:{}: no address", url.port())))?
    };
    let stream = TcpStream::connect_timeout(&socket_addr, IO_TIMEOUT)
        .map_err(|e| HttpsError::Connect(format!("{host}:{}: {e}", url.port())))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|e| HttpsError::Connect(format!("set_read_timeout: {e}")))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|e| HttpsError::Connect(format!("set_write_timeout: {e}")))?;
    Ok(stream)
}

fn ca_bundle_path(policy: &TransportPolicy) -> Result<String, HttpsError> {
    if let Ok(path) = std::env::var("REFINEID_CA_BUNDLE")
        && !path.trim().is_empty()
    {
        return Ok(path);
    }
    policy
        .ca_bundle_paths
        .iter()
        .find(|path| path.is_file())
        .map(|path| path.to_string_lossy().into_owned())
        .ok_or_else(|| HttpsError::Tls("no CA bundle found".to_owned()))
}

fn authority(url: &Uri) -> String {
    if url.port() == url.scheme().default_port() {
        url.host().to_string()
    } else {
        format!("{}:{}", url.host(), url.port())
    }
}

fn request_target(url: &Uri) -> String {
    if url.query().is_empty() {
        url.path().to_string()
    } else {
        format!("{}?{}", url.path(), url.query())
    }
}

#[derive(Debug, Clone, Copy)]
enum RequestBody<'a> {
    None,
    Bytes {
        content_type: &'a str,
        body: &'a [u8],
        authorization: Option<&'a str>,
    },
}

impl RequestBody<'_> {
    const fn method(self) -> &'static str {
        match self {
            Self::None => "GET",
            Self::Bytes { .. } => "POST",
        }
    }
}

fn validate_basic_authorization(value: &str) -> Result<(), HttpsError> {
    let Some(encoded) = value.strip_prefix("Basic ") else {
        return Err(HttpsError::InvalidAuthorization);
    };
    if encoded.is_empty() || encoded.len() % 4 != 0 {
        return Err(HttpsError::InvalidAuthorization);
    }
    let first_padding = encoded.find('=').unwrap_or(encoded.len());
    if encoded[first_padding..].len() > 2
        || !encoded[..first_padding]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
        || !encoded[first_padding..].bytes().all(|byte| byte == b'=')
    {
        return Err(HttpsError::InvalidAuthorization);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};

    struct ScriptedIo {
        response: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl Read for ScriptedIo {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.response.read(buffer)
        }
    }

    impl Write for ScriptedIo {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn basic_authorization_rejects_header_injection() {
        let valid_auth = format!(
            "Basic {}",
            refineid_lib_core::base64::encode(b"test-user:test-pass")
        );
        assert!(super::validate_basic_authorization(&valid_auth).is_ok());
        assert!(super::validate_basic_authorization("Bearer token").is_err());
        let injection = format!(
            "Basic {}\r\nX-Evil: yes",
            refineid_lib_core::base64::encode(b"user")
        );
        assert!(super::validate_basic_authorization(&injection).is_err());
        assert!(super::validate_basic_authorization("Basic abc=def=").is_err());
    }

    #[test]
    fn transient_https_errors_are_narrowly_classified() {
        assert!(super::HttpsError::Connect("timeout".to_owned()).is_transient());
        assert!(!super::HttpsError::Tls("certificate rejected".to_owned()).is_transient());
        assert!(!super::HttpsError::InvalidAuthorization.is_transient());
    }

    #[test]
    fn authorized_post_writes_one_basic_header() {
        let url = refineid_lib_core::text::Uri::parse(
            "https://timestamp.sectigo.com/qualified".to_owned(),
        )
        .expect("test URL");
        let mut io = ScriptedIo {
            response: Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()),
            written: Vec::new(),
        };
        let auth_header = format!(
            "Basic {}",
            refineid_lib_core::base64::encode(b"test-user:test-pass")
        );
        super::send_request(
            &mut io,
            &url,
            super::RequestBody::Bytes {
                content_type: "application/timestamp-query",
                body: b"DER",
                authorization: Some(&auth_header),
            },
            1024,
            "test",
        )
        .expect("scripted response");
        let request = String::from_utf8(io.written).expect("ASCII request");
        assert_eq!(request.matches("Authorization:").count(), 1);
        assert!(request.contains(&format!("Authorization: {auth_header}\r\n")));
        assert!(request.ends_with("\r\n\r\nDER"));
    }

    /// A real HTTPS round trip, against a real qualified timestamp
    /// authority.
    ///
    /// Ignored by default because it needs the network and a third
    /// party's uptime, neither of which belongs in a check that gates
    /// a commit. It is here because a TLS backend that compiles proves
    /// nothing: what has to be true is that the handshake completes
    /// against a live server with the platform CA bundle, and that the
    /// answer comes back framed correctly. Sectigo is the target
    /// because it is the primary qualified timestamp authority.
    ///
    /// Run it with:
    ///   cargo test -p refineid-lib-tls --features tls-rustls -- --ignored --nocapture
    #[test]
    #[ignore = "needs the network and a live timestamp authority"]
    #[cfg(feature = "tls-rustls")]
    fn rustls_reaches_a_live_timestamp_authority() {
        use refineid_lib_core::sign::cades::DigestAlgorithm;
        use refineid_lib_core::text::Uri;

        let algorithm = DigestAlgorithm::Sha256;
        let digest = algorithm.digest(b"refineid rustls backend probe");
        let request = refineid_lib_core::sign::timestamp::request(&digest, algorithm, None, true);
        let url = Uri::parse("https://timestamp.sectigo.com/qualified".to_owned())
            .expect("the probe URL parses");

        let response = super::post(
            &url,
            "application/timestamp-query",
            &request,
            64 * 1024,
            "refineid-rustls-probe",
        )
        .expect("the authority answers over TLS");

        // A DER SEQUENCE, and big enough to be a token rather than a
        // rejection: proof the handshake completed and the framing held.
        assert_eq!(response.first(), Some(&0x30), "a DER SEQUENCE came back");
        assert!(response.len() > 1000, "got {} bytes", response.len());
        let token = refineid_lib_core::sign::timestamp::token(&response, &digest, algorithm, None)
            .expect("the token binds to the digest we asked about");
        assert!(!token.is_empty(), "a token came back");
    }
}
