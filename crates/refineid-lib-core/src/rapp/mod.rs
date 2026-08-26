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

//! Remote Authorization Proxy Protocol (RAPP) Core implementation.
//!
//! Enables Linux/Unix to pair with mobile devices (iOS / Android) and utilize them
//! as remote smart-card readers for authentication and digital signing.

pub mod crypto;
pub mod envelope;
pub mod messages;
pub mod session;
pub mod transport;
pub mod vault;
pub mod wire;

#[cfg(test)]
pub mod conformance_tests;

pub use crypto::{
    NoiseHandshakeState, NoisePatternKind, PAIRING_SUITE, SESSION_SUITE, WIRE_VERSION,
    derive_grants_hash, derive_pair_id, derive_rendezvous_token, derive_request_hash,
    derive_session_id, pairing_prologue, session_prologue,
};
pub use envelope::{MessageType, RappEnvelope, SequenceGuard};
pub use messages::{
    CardInspection, CardOperation, CardOperationResult, PROFILE_AUTH, PROFILE_SIGN, PROFILE_STATUS,
    PairRecord, PairingOffer, ResultStatus, StreamRendezvous, TRANSPORT_BLE, TRANSPORT_STREAM,
    TransportCandidate,
};
pub use session::{
    PairOfferContext, execute_operation_over_stream, execute_operation_with_pair,
    pair_requester_over_stream,
};
pub use transport::{read_frame, write_frame};
pub use vault::RappDeviceVault;
pub use wire::{WireError, WireValue, decode_deterministic_cbor};
