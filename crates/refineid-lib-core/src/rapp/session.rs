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

//! High-level RAPP requester session drivers for pairing and card operations.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use super::crypto::{
    NoiseHandshakeState, NoisePatternKind, PAIRING_SUITE, SESSION_SUITE, WIRE_VERSION,
    derive_grants_hash, derive_pair_id, derive_rendezvous_token, derive_request_hash,
    derive_session_id, pairing_prologue, session_prologue,
};
use super::envelope::{MessageType, RappEnvelope, SequenceGuard};
use super::messages::{
    CardOperation, CardOperationResult, PairRecord, PairingOffer, ResultStatus, StreamRendezvous,
};
use super::transport::{read_frame, write_frame};
use super::wire::{WireError, WireValue};

/// Default socket timeout for interactive operations.
pub const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Perform the RAPP Pairing Ceremony over an accepted stream as the Requester.
pub fn pair_requester_over_stream<S: Read + Write>(
    stream: &mut S,
    offer: &PairOfferContext,
    display_name: &str,
    platform: &str,
) -> Result<PairRecord, WireError> {
    // 1. Read preamble
    let preamble_bytes = read_frame(stream)?;
    let rendezvous = StreamRendezvous::decode(&preamble_bytes)?;
    if rendezvous != StreamRendezvous::Pairing {
        return Err(WireError::InvalidValue {
            field: "rendezvous_purpose",
        });
    }

    // 2. Generate local static keypair for this pairing
    let mut local_static_bytes = [0u8; 32];
    getrandom::fill(&mut local_static_bytes).expect("CSPRNG");
    let local_static_sec = StaticSecret::from(local_static_bytes);
    let local_static_pub = X25519PublicKey::from(&local_static_sec).to_bytes();

    let offer_hash = offer.offer.offer_hash()?;
    let prologue = pairing_prologue(&offer_hash, &offer.selected_transport)?;

    let mut handshake = NoiseHandshakeState::new(
        NoisePatternKind::XxPsk3,
        PAIRING_SUITE,
        &prologue,
        true, // Initiator
        &local_static_bytes,
        None,
        Some(offer.offer.pairing_secret),
        None,
    );

    // Message 1 (->)
    let msg1 = handshake.write_message(&[])?;
    write_frame(stream, &msg1)?;

    // Message 2 (<-)
    let msg2 = read_frame(stream)?;
    handshake.read_message(&msg2)?;

    // Message 3 (->)
    let msg3 = handshake.write_message(&[])?;
    write_frame(stream, &msg3)?;

    let remote_static_pub = handshake
        .remote_static_public()
        .ok_or(WireError::MissingField {
            field: "remote_static",
        })?;
    let handshake_hash = *handshake.handshake_hash();
    let session_id = derive_session_id(&handshake_hash);
    let pair_id = derive_pair_id(&handshake_hash);
    let rendezvous_token = derive_rendezvous_token(&handshake_hash);

    let (mut send_cipher, mut recv_cipher) = handshake.split()?;
    let mut send_seq = SequenceGuard::new();
    let mut recv_seq = SequenceGuard::new();

    // 3. Send pairing.hello
    let mut params_map = BTreeMap::new();
    params_map.insert(
        "version".into(),
        WireValue::Array(vec![
            WireValue::Unsigned(WIRE_VERSION.0),
            WireValue::Unsigned(WIRE_VERSION.1),
        ]),
    );
    params_map.insert("suite".into(), WireValue::Text(PAIRING_SUITE.into()));
    params_map.insert("offer_hash".into(), WireValue::Bytes(offer_hash.to_vec()));
    params_map.insert(
        "transport_profile".into(),
        WireValue::Text(offer.selected_transport.clone()),
    );
    params_map.insert(
        "candidate_id".into(),
        WireValue::Text(offer.selected_candidate_id.clone()),
    );

    let mut hello_body = BTreeMap::new();
    hello_body.insert("parameters".into(), WireValue::Map(params_map));
    hello_body.insert("display_name".into(), WireValue::Text(display_name.into()));
    hello_body.insert("platform".into(), WireValue::Text(platform.into()));
    hello_body.insert(
        "requested_profiles".into(),
        WireValue::Array(
            offer
                .offer
                .profiles
                .iter()
                .cloned()
                .map(WireValue::Text)
                .collect(),
        ),
    );

    let hello_env = RappEnvelope::new(
        MessageType::PairingHello,
        session_id,
        send_seq.advance_send()?,
        hello_body,
    );
    let hello_plain = hello_env.encode()?;
    let hello_cipher = send_cipher.encrypt(&[], &hello_plain)?;
    write_frame(stream, &hello_cipher)?;

    // 4. Receive proxy pairing.hello
    let resp_cipher = read_frame(stream)?;
    let resp_plain = recv_cipher.decrypt(&[], &resp_cipher)?;
    let proxy_hello_env = RappEnvelope::decode(&resp_plain)?;
    if proxy_hello_env.msg_type != MessageType::PairingHello {
        return Err(WireError::InvalidValue {
            field: "pairing_hello_expected",
        });
    }
    recv_seq.check_and_advance_recv(proxy_hello_env.sequence)?;

    let proxy_name = match proxy_hello_env.body.get("display_name") {
        Some(WireValue::Text(s)) => Some(s.clone()),
        _ => None,
    };
    let proxy_platform = match proxy_hello_env.body.get("platform") {
        Some(WireValue::Text(s)) => Some(s.clone()),
        _ => None,
    };

    // 5. Receive pairing.confirm from proxy
    let confirm_cipher = read_frame(stream)?;
    let confirm_plain = recv_cipher.decrypt(&[], &confirm_cipher)?;
    let proxy_confirm_env = RappEnvelope::decode(&confirm_plain)?;
    if proxy_confirm_env.msg_type != MessageType::PairingConfirm {
        return Err(WireError::InvalidValue {
            field: "pairing_confirm_expected",
        });
    }
    recv_seq.check_and_advance_recv(proxy_confirm_env.sequence)?;

    let granted_profiles = match proxy_confirm_env.body.get("granted_profiles") {
        Some(WireValue::Array(arr)) => {
            let mut res = Vec::new();
            for it in arr {
                if let WireValue::Text(s) = it {
                    res.push(s.clone());
                }
            }
            res
        }
        _ => offer.offer.profiles.clone(),
    };

    // 6. Send pairing.confirm
    let mut confirm_body = BTreeMap::new();
    confirm_body.insert(
        "granted_profiles".into(),
        WireValue::Array(
            granted_profiles
                .iter()
                .cloned()
                .map(WireValue::Text)
                .collect(),
        ),
    );

    let confirm_env = RappEnvelope::new(
        MessageType::PairingConfirm,
        session_id,
        send_seq.advance_send()?,
        confirm_body,
    );
    let confirm_plain = confirm_env.encode()?;
    let confirm_cipher = send_cipher.encrypt(&[], &confirm_plain)?;
    write_frame(stream, &confirm_cipher)?;

    let grants_hash = derive_grants_hash(&granted_profiles)?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    Ok(PairRecord {
        pair_id,
        rendezvous_token,
        role: "requester".into(),
        local_static_private: local_static_bytes,
        local_static_public: local_static_pub,
        remote_static_public: remote_static_pub,
        grants_hash,
        profiles: granted_profiles,
        transport_profile: offer.selected_transport.clone(),
        candidate_id: offer.selected_candidate_id.clone(),
        transport_parameters: offer.transport_parameters.clone(),
        created_at_ms: now_ms,
        display_name: proxy_name,
        platform: proxy_platform,
        cached_auth_cert: None,
    })
}

/// Context for an active pairing offer.
#[derive(Debug, Clone)]
pub struct PairOfferContext {
    /// Underlying pairing offer.
    pub offer: PairingOffer,
    /// Selected transport profile name.
    pub selected_transport: String,
    /// Identifier of the selected candidate.
    pub selected_candidate_id: String,
    /// Transport parameters associated with the candidate.
    pub transport_parameters: BTreeMap<String, WireValue>,
}

/// Execute a typed card operation against a paired proxy over stream transport.
pub fn execute_operation_over_stream<S: Read + Write>(
    stream: &mut S,
    pair: &PairRecord,
    operation: &CardOperation,
) -> Result<CardOperationResult, WireError> {
    // 1. Send preamble
    let preamble = StreamRendezvous::Session {
        rendezvous_token: pair.rendezvous_token,
    };
    let preamble_bytes = preamble.encode()?;
    write_frame(stream, &preamble_bytes)?;

    // 2. Run Noise KK handshake
    let prologue = session_prologue(&pair.pair_id, &pair.grants_hash, &pair.transport_profile)?;

    let mut handshake = NoiseHandshakeState::new(
        NoisePatternKind::Kk,
        SESSION_SUITE,
        &prologue,
        true, // Initiator
        &pair.local_static_private,
        Some(pair.remote_static_public),
        None,
        None,
    );

    // Msg 1 (->)
    let msg1 = handshake.write_message(&[])?;
    write_frame(stream, &msg1)?;

    // Msg 2 (<-)
    let msg2 = read_frame(stream)?;
    handshake.read_message(&msg2)?;

    let handshake_hash = *handshake.handshake_hash();
    let session_id = derive_session_id(&handshake_hash);
    let (mut send_cipher, mut recv_cipher) = handshake.split()?;
    let mut send_seq = SequenceGuard::new();
    let mut recv_seq = SequenceGuard::new();

    // 3. Send session.ready
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).expect("CSPRNG");

    let mut session_params = BTreeMap::new();
    session_params.insert(
        "version".into(),
        WireValue::Array(vec![
            WireValue::Unsigned(WIRE_VERSION.0),
            WireValue::Unsigned(WIRE_VERSION.1),
        ]),
    );
    session_params.insert("suite".into(), WireValue::Text(SESSION_SUITE.into()));
    session_params.insert(
        "transport_profile".into(),
        WireValue::Text(pair.transport_profile.clone()),
    );
    session_params.insert(
        "candidate_id".into(),
        WireValue::Text(pair.candidate_id.clone()),
    );
    session_params.insert(
        "grants_hash".into(),
        WireValue::Bytes(pair.grants_hash.to_vec()),
    );

    let mut ready_body = BTreeMap::new();
    ready_body.insert("parameters".into(), WireValue::Map(session_params));
    ready_body.insert("nonce".into(), WireValue::Bytes(nonce.to_vec()));

    let ready_env = RappEnvelope::new(
        MessageType::SessionReady,
        session_id,
        send_seq.advance_send()?,
        ready_body,
    );
    let ready_plain = ready_env.encode()?;
    let ready_cipher = send_cipher.encrypt(&[], &ready_plain)?;
    write_frame(stream, &ready_cipher)?;

    // 4. Receive proxy session.ready
    let resp_cipher = read_frame(stream)?;
    let resp_plain = recv_cipher.decrypt(&[], &resp_cipher)?;
    let proxy_ready_env = RappEnvelope::decode(&resp_plain)?;
    if proxy_ready_env.msg_type != MessageType::SessionReady {
        return Err(WireError::InvalidValue {
            field: "session_ready_expected",
        });
    }
    recv_seq.check_and_advance_recv(proxy_ready_env.sequence)?;

    // 5. Send operation.request
    let mut op_id = [0u8; 16];
    getrandom::fill(&mut op_id).expect("CSPRNG");

    let profile = operation.required_profile();
    let action = operation.action_name();
    let context_map = operation.context_map();
    let payload_map = operation.payload_map();

    let req_hash = derive_request_hash(
        &session_id,
        &op_id,
        profile,
        action,
        &context_map,
        &payload_map,
    )?;

    let mut req_body = BTreeMap::new();
    req_body.insert("operation_id".into(), WireValue::Bytes(op_id.to_vec()));
    req_body.insert("profile".into(), WireValue::Text(profile.into()));
    req_body.insert("action".into(), WireValue::Text(action.into()));
    req_body.insert("request_hash".into(), WireValue::Bytes(req_hash.to_vec()));
    req_body.insert("expires_after_ms".into(), WireValue::Unsigned(30_000));
    req_body.insert("context".into(), WireValue::Map(context_map));
    req_body.insert("payload".into(), WireValue::Map(payload_map));

    let req_env = RappEnvelope::new(
        MessageType::OperationRequest,
        session_id,
        send_seq.advance_send()?,
        req_body,
    );
    let req_plain = req_env.encode()?;
    let req_cipher = send_cipher.encrypt(&[], &req_plain)?;
    write_frame(stream, &req_cipher)?;

    // 6. If consequential, handle prepare & commit
    if operation.is_consequential() {
        let prep_cipher = read_frame(stream)?;
        let prep_plain = recv_cipher.decrypt(&[], &prep_cipher)?;
        let prep_env = RappEnvelope::decode(&prep_plain)?;
        if prep_env.msg_type != MessageType::OperationPrepared {
            return Err(WireError::InvalidValue {
                field: "operation_prepared_expected",
            });
        }
        recv_seq.check_and_advance_recv(prep_env.sequence)?;

        // Send operation.commit
        let mut commit_body = BTreeMap::new();
        commit_body.insert("operation_id".into(), WireValue::Bytes(op_id.to_vec()));
        commit_body.insert("request_hash".into(), WireValue::Bytes(req_hash.to_vec()));

        let commit_env = RappEnvelope::new(
            MessageType::OperationCommit,
            session_id,
            send_seq.advance_send()?,
            commit_body,
        );
        let commit_plain = commit_env.encode()?;
        let commit_cipher = send_cipher.encrypt(&[], &commit_plain)?;
        write_frame(stream, &commit_cipher)?;
    }

    // 7. Receive operation.result
    let result_cipher = read_frame(stream)?;
    let result_plain = recv_cipher.decrypt(&[], &result_cipher)?;
    let result_env = RappEnvelope::decode(&result_plain)?;
    if result_env.msg_type != MessageType::OperationResult {
        return Err(WireError::InvalidValue {
            field: "operation_result_expected",
        });
    }
    recv_seq.check_and_advance_recv(result_env.sequence)?;

    let status_str = match result_env.body.get("status") {
        Some(WireValue::Text(s)) => s.as_str(),
        _ => return Err(WireError::MissingField { field: "status" }),
    };
    let status = ResultStatus::from_str(status_str).ok_or(WireError::InvalidValue { field: "status" })?;
    if status != ResultStatus::Completed {
        return Err(WireError::InvalidValue {
            field: "operation_rejected",
        });
    }

    // 8. Send operation.result_ack
    let mut ack_body = BTreeMap::new();
    ack_body.insert("operation_id".into(), WireValue::Bytes(op_id.to_vec()));
    ack_body.insert("request_hash".into(), WireValue::Bytes(req_hash.to_vec()));

    let ack_env = RappEnvelope::new(
        MessageType::OperationResultAck,
        session_id,
        send_seq.advance_send()?,
        ack_body,
    );
    let ack_plain = ack_env.encode()?;
    let ack_cipher = send_cipher.encrypt(&[], &ack_plain)?;
    write_frame(stream, &ack_cipher)?;

    let result_body = match result_env.body.get("body") {
        Some(WireValue::Map(m)) => m.clone(),
        _ => BTreeMap::new(),
    };

    CardOperationResult::from_wire_body(result_body)
}

/// Connect to a paired remote proxy over TCP and perform a card operation.
pub fn execute_operation_with_pair(
    pair: &PairRecord,
    operation: &CardOperation,
) -> Result<CardOperationResult, WireError> {
    let endpoints = match pair.transport_parameters.get("endpoints") {
        Some(WireValue::Array(arr)) => {
            let mut list = Vec::new();
            for it in arr {
                if let WireValue::Text(s) = it {
                    list.push(s.clone());
                }
            }
            list
        }
        _ => return Err(WireError::MissingField { field: "endpoints" }),
    };

    if endpoints.is_empty() {
        return Err(WireError::MissingField { field: "endpoints" });
    }

    let mut last_err = WireError::InvalidValue { field: "connect" };
    for endpoint in endpoints {
        if let Ok(mut stream) = TcpStream::connect_timeout(
            &endpoint
                .parse::<SocketAddr>()
                .map_err(|_| WireError::InvalidValue { field: "endpoint" })?,
            Duration::from_secs(5),
        ) {
            let _ = stream.set_read_timeout(Some(DEFAULT_OPERATION_TIMEOUT));
            let _ = stream.set_write_timeout(Some(DEFAULT_OPERATION_TIMEOUT));
            return execute_operation_over_stream(&mut stream, pair, operation);
        } else {
            last_err = WireError::InvalidValue { field: "connect_failed" };
        }
    }
    Err(last_err)
}
