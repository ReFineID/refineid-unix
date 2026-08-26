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

//! RAPP common message envelope and sequence verification.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use super::crypto::WIRE_VERSION;
use super::wire::{MAX_FRAME_PLAINTEXT, WireError, WireValue, decode_deterministic_cbor};

/// Registered RAPP message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Initial pairing hello containing client parameters.
    PairingHello,
    /// Mutual confirmation of agreed profiles.
    PairingConfirm,
    /// Explicit abort of pairing ceremony.
    PairingAbort,
    /// Session readiness notification.
    SessionReady,
    /// Explicit session termination.
    SessionClose,
    /// Connection liveness check request.
    LivenessPing,
    /// Liveness response.
    LivenessPong,
    /// Operation dispatch request.
    OperationRequest,
    /// Pre-execution phase preparation confirmation.
    OperationPrepared,
    /// Two-phase commit trigger.
    OperationCommit,
    /// Cancellation of in-flight operation.
    OperationCancel,
    /// Completed operation result.
    OperationResult,
    /// Acknowledgment of received operation result.
    OperationResultAck,
    /// Query for async operation status.
    OperationStatusRequest,
    /// Async operation status update.
    OperationStatus,
    /// Protocol error indication.
    Error,
}

impl MessageType {
    /// Canonical specification name of this message type.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PairingHello => "pairing.hello",
            Self::PairingConfirm => "pairing.confirm",
            Self::PairingAbort => "pairing.abort",
            Self::SessionReady => "session.ready",
            Self::SessionClose => "session.close",
            Self::LivenessPing => "liveness.ping",
            Self::LivenessPong => "liveness.pong",
            Self::OperationRequest => "operation.request",
            Self::OperationPrepared => "operation.prepared",
            Self::OperationCommit => "operation.commit",
            Self::OperationCancel => "operation.cancel",
            Self::OperationResult => "operation.result",
            Self::OperationResultAck => "operation.result_ack",
            Self::OperationStatusRequest => "operation.status_request",
            Self::OperationStatus => "operation.status",
            Self::Error => "error",
        }
    }

    /// Parse message type from specification string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pairing.hello" => Some(Self::PairingHello),
            "pairing.confirm" => Some(Self::PairingConfirm),
            "pairing.abort" => Some(Self::PairingAbort),
            "session.ready" => Some(Self::SessionReady),
            "session.close" => Some(Self::SessionClose),
            "liveness.ping" => Some(Self::LivenessPing),
            "liveness.pong" => Some(Self::LivenessPong),
            "operation.request" => Some(Self::OperationRequest),
            "operation.prepared" => Some(Self::OperationPrepared),
            "operation.commit" => Some(Self::OperationCommit),
            "operation.cancel" => Some(Self::OperationCancel),
            "operation.result" => Some(Self::OperationResult),
            "operation.result_ack" => Some(Self::OperationResultAck),
            "operation.status_request" => Some(Self::OperationStatusRequest),
            "operation.status" => Some(Self::OperationStatus),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

/// One decoded, validated RAPP message envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RappEnvelope {
    /// Protocol wire version tuple.
    pub version: (u64, u64),
    /// Message type discriminant.
    pub msg_type: MessageType,
    /// 16-byte session identifier.
    pub session_id: [u8; 16],
    /// Monotonically increasing message sequence number.
    pub sequence: u64,
    /// Typed message body fields.
    pub body: BTreeMap<String, WireValue>,
    /// List of critical extension names that must be recognized.
    pub critical: Vec<String>,
    /// Optional extension fields.
    pub extensions: BTreeMap<String, WireValue>,
}

impl RappEnvelope {
    /// Create a new envelope with standard wire version.
    pub fn new(
        msg_type: MessageType,
        session_id: [u8; 16],
        sequence: u64,
        body: BTreeMap<String, WireValue>,
    ) -> Self {
        Self {
            version: WIRE_VERSION,
            msg_type,
            session_id,
            sequence,
            body,
            critical: Vec::new(),
            extensions: BTreeMap::new(),
        }
    }

    /// Encode envelope to deterministic CBOR.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut map = BTreeMap::new();
        map.insert(
            "version".into(),
            WireValue::Array(vec![
                WireValue::Unsigned(self.version.0),
                WireValue::Unsigned(self.version.1),
            ]),
        );
        map.insert("type".into(), WireValue::Text(self.msg_type.as_str().into()));
        map.insert("session_id".into(), WireValue::Bytes(self.session_id.to_vec()));
        map.insert("sequence".into(), WireValue::Unsigned(self.sequence));
        map.insert("body".into(), WireValue::Map(self.body.clone()));

        if !self.critical.is_empty() {
            map.insert(
                "critical".into(),
                WireValue::Array(self.critical.iter().cloned().map(WireValue::Text).collect()),
            );
        }
        if !self.extensions.is_empty() {
            map.insert("extensions".into(), WireValue::Map(self.extensions.clone()));
        }

        let val = WireValue::Map(map);
        val.encode()
    }

    /// Decode envelope from deterministic CBOR bytes and validate schema.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_FRAME_PLAINTEXT {
            return Err(WireError::OversizedPlaintext { got: bytes.len() });
        }
        let val = decode_deterministic_cbor(bytes)?;
        let mut map = match val {
            WireValue::Map(m) => m,
            _ => return Err(WireError::WrongType { field: "envelope" }),
        };

        let version_val = map
            .remove("version")
            .ok_or(WireError::MissingField { field: "version" })?;
        let version = match version_val {
            WireValue::Array(arr) if arr.len() == 2 => match (&arr[0], &arr[1]) {
                (WireValue::Unsigned(maj), WireValue::Unsigned(min)) => (*maj, *min),
                _ => return Err(WireError::WrongType { field: "version" }),
            },
            _ => return Err(WireError::WrongType { field: "version" }),
        };
        if version != WIRE_VERSION {
            return Err(WireError::UnsupportedVersion);
        }

        let type_val = map
            .remove("type")
            .ok_or(WireError::MissingField { field: "type" })?;
        let msg_type = match type_val {
            WireValue::Text(t) => MessageType::from_str(&t).ok_or(WireError::UnknownMessageType)?,
            _ => return Err(WireError::WrongType { field: "type" }),
        };

        let session_val = map
            .remove("session_id")
            .ok_or(WireError::MissingField { field: "session_id" })?;
        let session_id = match session_val {
            WireValue::Bytes(b) if b.len() == 16 => {
                let mut id = [0u8; 16];
                id.copy_from_slice(&b);
                id
            }
            WireValue::Bytes(b) => {
                return Err(WireError::WrongLength {
                    field: "session_id",
                    expected: 16,
                    got: b.len(),
                });
            }
            _ => return Err(WireError::WrongType { field: "session_id" }),
        };

        let seq_val = map
            .remove("sequence")
            .ok_or(WireError::MissingField { field: "sequence" })?;
        let sequence = match seq_val {
            WireValue::Unsigned(s) => s,
            _ => return Err(WireError::WrongType { field: "sequence" }),
        };

        let body_val = map
            .remove("body")
            .ok_or(WireError::MissingField { field: "body" })?;
        let body = match body_val {
            WireValue::Map(m) => m,
            _ => return Err(WireError::WrongType { field: "body" }),
        };

        let critical = match map.remove("critical") {
            Some(WireValue::Array(arr)) => {
                let mut crit = Vec::with_capacity(arr.len());
                for item in arr {
                    match item {
                        WireValue::Text(t) => crit.push(t),
                        _ => return Err(WireError::WrongType { field: "critical" }),
                    }
                }
                crit
            }
            Some(_) => return Err(WireError::WrongType { field: "critical" }),
            None => Vec::new(),
        };

        let extensions = match map.remove("extensions") {
            Some(WireValue::Map(m)) => m,
            Some(_) => return Err(WireError::WrongType { field: "extensions" }),
            None => BTreeMap::new(),
        };

        for crit_name in &critical {
            if !extensions.contains_key(crit_name) {
                return Err(WireError::CriticalExtensionMissing);
            }
        }

        if !map.is_empty() {
            return Err(WireError::UnknownField);
        }

        Ok(Self {
            version,
            msg_type,
            session_id,
            sequence,
            body,
            critical,
            extensions,
        })
    }
}

/// Enforces strictly sequential nonces and message counters independently in each direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SequenceGuard {
    next_sequence: u64,
}

impl Default for SequenceGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl SequenceGuard {
    /// Create a new sequence guard initialized to sequence 0.
    pub const fn new() -> Self {
        Self { next_sequence: 0 }
    }

    /// Advance sending sequence number and return value.
    pub fn advance_send(&mut self) -> Result<u64, WireError> {
        let seq = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(WireError::IntegerOverflow)?;
        Ok(seq)
    }

    /// Check received sequence number and advance expected count.
    pub fn check_and_advance_recv(&mut self, seq: u64) -> Result<(), WireError> {
        if seq != self.next_sequence {
            return Err(WireError::InvalidValue { field: "sequence" });
        }
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(WireError::IntegerOverflow)?;
        Ok(())
    }

    /// Last accepted or sent sequence number.
    pub const fn last_seen(&self) -> u64 {
        if self.next_sequence == 0 {
            0
        } else {
            self.next_sequence - 1
        }
    }
}
