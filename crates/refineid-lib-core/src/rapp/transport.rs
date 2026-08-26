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

//! Transport framing for length-prefixed stream profiles (`fi.refineid.stream.v1`).

use alloc::vec::Vec;
use std::io::{Read, Write};

use super::wire::WireError;

/// Maximum frame size over length-prefixed stream.
pub const MAX_STREAM_FRAME: usize = 65535;

/// Write one 2-byte big-endian length-prefixed binary frame.
pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> Result<(), WireError> {
    if payload.is_empty() || payload.len() > MAX_STREAM_FRAME {
        return Err(WireError::OversizedPlaintext { got: payload.len() });
    }
    let len = payload.len() as u16;
    writer
        .write_all(&len.to_be_bytes())
        .map_err(|_| WireError::InvalidValue { field: "transport_write" })?;
    writer
        .write_all(payload)
        .map_err(|_| WireError::InvalidValue { field: "transport_write" })?;
    writer
        .flush()
        .map_err(|_| WireError::InvalidValue { field: "transport_flush" })?;
    Ok(())
}

/// Read one 2-byte big-endian length-prefixed binary frame.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Vec<u8>, WireError> {
    let mut len_bytes = [0u8; 2];
    reader
        .read_exact(&mut len_bytes)
        .map_err(|_| WireError::Truncated)?;
    let len = u16::from_be_bytes(len_bytes) as usize;
    if len == 0 || len > MAX_STREAM_FRAME {
        return Err(WireError::InvalidValue { field: "frame_length" });
    }
    let mut buffer = vec![0u8; len];
    reader
        .read_exact(&mut buffer)
        .map_err(|_| WireError::Truncated)?;
    Ok(buffer)
}
