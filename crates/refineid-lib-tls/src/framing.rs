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

//! Backend-agnostic HTTP/1.1 response framing.
//!
//! Reads one complete response off any `Read` stream, handling
//! `Content-Length`, `Transfer-Encoding: chunked`, and the no-body
//! status codes. The TLS type doesn't matter -- only that it
//! implements `Read`.

use std::io::Read;

/// Read-buffer chunk size for one `read()` call.
const READ_CHUNK_BYTES: usize = 4096;
/// Initial response-buffer capacity.
const INITIAL_BUFFER_BYTES: usize = 8192;
/// Defensive ceiling on the header section.
const MAX_HEADER_BYTES: usize = 64 * 1024;
/// Defensive ceiling on one chunk-size line.
const MAX_CHUNK_SIZE_LINE_BYTES: usize = 16 * 1024;
/// Head/body separator (RFC 9112 §2.1).
const HEAD_BODY_SEPARATOR: &[u8] = b"\r\n\r\n";
/// Line separator.
const CRLF: &[u8] = b"\r\n";

/// Why a response failed to frame.
#[derive(Debug)]
#[non_exhaustive]
pub enum FramingError {
    /// Peer closed before the end of the headers.
    ClosedInHeaders,
    /// Header section exceeded `MAX_HEADER_BYTES`.
    HeadersTooLarge,
    /// Peer closed before `Content-Length` bytes arrived.
    ClosedInBody,
    /// Chunked coding violated RFC 9112 §7.1 (bad size line,
    /// truncated chunk).
    BadChunking(String),
    /// Response body exceeded the caller-supplied `max_bytes`
    /// ceiling (Content-Length, chunked accumulation, or
    /// read-to-close).
    BodyTooLarge(usize),
    /// Underlying stream error.
    Io(std::io::Error),
}

impl core::fmt::Display for FramingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ClosedInHeaders => f.write_str("server closed before end of headers"),
            Self::HeadersTooLarge => write!(f, "response headers exceed {MAX_HEADER_BYTES} bytes"),
            Self::ClosedInBody => f.write_str("server closed before Content-Length completed"),
            Self::BadChunking(detail) => write!(f, "chunked coding: {detail}"),
            Self::BodyTooLarge(limit) => write!(f, "response body exceeds {limit} bytes"),
            Self::Io(error) => write!(f, "HTTP read: {error}"),
        }
    }
}

impl core::error::Error for FramingError {}

/// Unit-struct host for the framing reader (typing-discipline
/// Rule A: no top-level fns with borrowed parameters).
#[derive(Debug, Clone, Copy)]
pub struct Framing;

impl Framing {
    /// Read one complete HTTP/1.1 response (head + body) off
    /// `stream`:
    ///
    /// - `Content-Length: N` -- read exactly N body bytes.
    /// - `Transfer-Encoding: chunked` -- decode the chunked body
    ///   (the returned bytes carry the head verbatim followed by
    ///   the *decoded* entity bytes).
    /// - 1xx / 204 / 304 -- no body.
    /// - Otherwise -- read to connection close.
    ///
    /// The body is bounded by `max_bytes`: a server announcing a
    /// huge `Content-Length` or streaming unbounded chunks /
    /// read-to-close data is rejected with [`FramingError::BodyTooLarge`]
    /// rather than exhausting memory.
    ///
    /// # Errors
    /// [`FramingError`] on early close, oversized sections, bad
    /// chunk coding, an oversized body, or stream errors.
    pub fn read_response<S: Read>(
        stream: &mut S,
        max_bytes: usize,
    ) -> Result<Vec<u8>, FramingError> {
        let mut raw: Vec<u8> = Vec::with_capacity(INITIAL_BUFFER_BYTES);
        let mut buf = [0_u8; READ_CHUNK_BYTES];

        let head_end = loop {
            match stream.read(&mut buf) {
                Ok(0) => return Err(FramingError::ClosedInHeaders),
                Ok(n) => raw.extend_from_slice(buf.get(..n).unwrap_or_default()),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e)
                    if e.kind() == std::io::ErrorKind::ConnectionAborted
                        || e.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    return Err(FramingError::ClosedInHeaders);
                }
                Err(e) => return Err(FramingError::Io(e)),
            }
            if let Some(pos) = raw
                .windows(HEAD_BODY_SEPARATOR.len())
                .position(|window| window == HEAD_BODY_SEPARATOR)
            {
                break pos.saturating_add(HEAD_BODY_SEPARATOR.len());
            }
            if raw.len() > MAX_HEADER_BYTES {
                return Err(FramingError::HeadersTooLarge);
            }
        };

        let head_lower =
            String::from_utf8_lossy(raw.get(..head_end).unwrap_or_default()).to_ascii_lowercase();
        let chunked = head_lower
            .lines()
            .any(|line| line.starts_with("transfer-encoding:") && line.contains("chunked"));
        let content_length: Option<usize> = head_lower
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .and_then(|value| value.trim().parse().ok());
        let status: u16 = head_lower
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or(0);
        let no_body = matches!(status, 100..=199 | 204 | 304);

        if no_body {
            return Ok(raw);
        }
        if chunked {
            return Self::read_chunked(stream, raw, head_end, max_bytes);
        }
        if let Some(length) = content_length {
            if length > max_bytes {
                return Err(FramingError::BodyTooLarge(max_bytes));
            }
            let need = head_end.saturating_add(length);
            while raw.len() < need {
                match stream.read(&mut buf) {
                    Ok(0) => return Err(FramingError::ClosedInBody),
                    Ok(n) => raw.extend_from_slice(buf.get(..n).unwrap_or_default()),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(FramingError::Io(e)),
                }
            }
            raw.truncate(need);
            return Ok(raw);
        }
        // No framing: read to close.
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => raw.extend_from_slice(buf.get(..n).unwrap_or_default()),
                Err(e)
                    if e.kind() == std::io::ErrorKind::ConnectionAborted
                        || e.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(FramingError::Io(e)),
            }
            if raw.len().saturating_sub(head_end) > max_bytes {
                return Err(FramingError::BodyTooLarge(max_bytes));
            }
        }
        Ok(raw)
    }

    /// RFC 9112 §7.1 chunked transfer-coding: decode chunks into
    /// the entity bytes, return head + decoded body.
    fn read_chunked<S: Read>(
        stream: &mut S,
        mut raw: Vec<u8>,
        head_end: usize,
        max_bytes: usize,
    ) -> Result<Vec<u8>, FramingError> {
        let mut buf = [0_u8; READ_CHUNK_BYTES];
        let mut decoded_body: Vec<u8> = Vec::new();
        let mut cursor = head_end;
        loop {
            let size_line_end = loop {
                let tail = raw.get(cursor..).unwrap_or_default();
                if let Some(rel) = tail.windows(CRLF.len()).position(|window| window == CRLF) {
                    break cursor.saturating_add(rel);
                }
                let n = stream.read(&mut buf).map_err(FramingError::Io)?;
                if n == 0 {
                    return Err(FramingError::BadChunking(
                        "server closed before chunk-size CRLF".to_owned(),
                    ));
                }
                raw.extend_from_slice(buf.get(..n).unwrap_or_default());
                if raw.len().saturating_sub(cursor) > MAX_CHUNK_SIZE_LINE_BYTES {
                    return Err(FramingError::BadChunking(
                        "chunk-size line too long".to_owned(),
                    ));
                }
            };
            let size_text =
                String::from_utf8_lossy(raw.get(cursor..size_line_end).unwrap_or_default())
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_owned();
            let chunk_len = usize::from_str_radix(&size_text, 16).map_err(|parse_error| {
                FramingError::BadChunking(format!("bad chunk-size {size_text:?}: {parse_error}"))
            })?;
            let data_start = size_line_end.saturating_add(CRLF.len());
            let data_end = data_start.saturating_add(chunk_len);
            let crlf_end = data_end.saturating_add(CRLF.len());
            while raw.len() < crlf_end {
                let n = stream.read(&mut buf).map_err(FramingError::Io)?;
                if n == 0 {
                    return Err(FramingError::BadChunking(
                        "server closed mid-chunk".to_owned(),
                    ));
                }
                raw.extend_from_slice(buf.get(..n).unwrap_or_default());
            }
            if chunk_len == 0 {
                // Drain optional trailers until a CRLF.
                while !raw
                    .get(data_start..)
                    .unwrap_or_default()
                    .windows(CRLF.len())
                    .any(|window| window == CRLF)
                {
                    let n = stream.read(&mut buf).map_err(FramingError::Io)?;
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(buf.get(..n).unwrap_or_default());
                }
                break;
            }
            decoded_body.extend_from_slice(raw.get(data_start..data_end).unwrap_or_default());
            if decoded_body.len() > max_bytes {
                return Err(FramingError::BodyTooLarge(max_bytes));
            }
            cursor = crlf_end;
        }
        let mut result = raw.get(..head_end).unwrap_or_default().to_vec();
        result.append(&mut decoded_body);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::{Framing, FramingError};

    /// Generous body ceiling for tests that aren't exercising the
    /// limit itself.
    const TEST_MAX_BODY: usize = 1 << 20;

    /// Content-Length framing reads exactly N bytes. The declared
    /// length (5) matches the "hello" prefix; the trailing bytes are
    /// the next response and must be left unread.
    #[test]
    fn content_length_framing() {
        let wire = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhellotrailing-garbage".to_vec();
        let mut cursor = std::io::Cursor::new(wire);
        let framed = Framing::read_response(&mut cursor, TEST_MAX_BODY).unwrap_or_default();
        let text = String::from_utf8_lossy(&framed).into_owned();
        assert!(text.ends_with("hello"), "got: {text}");
    }

    /// Chunked framing decodes the entity bytes and drops the
    /// chunk envelope.
    #[test]
    fn chunked_framing_decodes() {
        let wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
            4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
            .to_vec();
        let mut cursor = std::io::Cursor::new(wire);
        let framed = Framing::read_response(&mut cursor, TEST_MAX_BODY).unwrap_or_default();
        let text = String::from_utf8_lossy(&framed).into_owned();
        assert!(text.ends_with("Wikipedia"), "got: {text}");
    }

    /// 204 has no body even without framing headers.
    #[test]
    fn no_body_statuses() {
        let wire = b"HTTP/1.1 204 No Content\r\nServer: x\r\n\r\n".to_vec();
        let mut cursor = std::io::Cursor::new(wire);
        let ok = Framing::read_response(&mut cursor, TEST_MAX_BODY)
            .is_ok_and(|bytes| bytes.ends_with(b"\r\n\r\n"));
        assert!(ok, "204 must frame to the bare head");
    }

    /// Early close inside the headers is a typed error.
    #[test]
    fn early_close_is_typed() {
        let wire = b"HTTP/1.1 200 OK\r\nContent-".to_vec();
        let mut cursor = std::io::Cursor::new(wire);
        assert!(matches!(
            Framing::read_response(&mut cursor, TEST_MAX_BODY),
            Err(FramingError::ClosedInHeaders)
        ));
    }

    /// A well-formed response whose `Content-Length` exceeds
    /// `max_bytes` is rejected on the declared length, before the
    /// body is read.
    #[test]
    fn content_length_over_limit_rejected() {
        // 11-byte body ("hello world"), declared honestly as 11;
        // rejected purely for exceeding the 10-byte ceiling.
        let wire = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world".to_vec();
        let mut cursor = std::io::Cursor::new(wire);
        assert!(matches!(
            Framing::read_response(&mut cursor, 10),
            Err(FramingError::BodyTooLarge(10))
        ));
    }

    /// A chunked body whose decoded length exceeds `max_bytes` is
    /// rejected as it accumulates.
    #[test]
    fn chunked_over_limit_rejected() {
        let wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
            4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
            .to_vec();
        let mut cursor = std::io::Cursor::new(wire);
        assert!(matches!(
            Framing::read_response(&mut cursor, 5),
            Err(FramingError::BodyTooLarge(5))
        ));
    }
}
