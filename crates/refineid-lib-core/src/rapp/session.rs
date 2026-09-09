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
    NoiseCipherState, NoiseHandshakeState, NoisePatternKind, PAIRING_SUITE, SESSION_SUITE,
    WIRE_VERSION, derive_grants_hash, derive_pair_id, derive_rendezvous_token, derive_request_hash,
    derive_session_id, pairing_prologue, session_prologue,
};
use super::envelope::{MessageType, RappEnvelope, SequenceGuard};
use super::messages::{
    CardOperation, CardOperationResult, PairRecord, PairingOffer, ResultStatus, StreamRendezvous,
    StreamRendezvousName,
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
    // 1. Send preamble
    let preamble = StreamRendezvous::Pairing.encode()?;
    write_frame(stream, &preamble)?;

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

fn read_operation_envelope<S: Read + Write>(
    stream: &mut S,
    send_cipher: &mut NoiseCipherState,
    recv_cipher: &mut NoiseCipherState,
    send_seq: &mut SequenceGuard,
    recv_seq: &mut SequenceGuard,
    session_id: &[u8; 16],
) -> Result<RappEnvelope, WireError> {
    loop {
        let cipher = read_frame(stream)?;
        let plain = recv_cipher.decrypt(&[], &cipher)?;
        let env = RappEnvelope::decode(&plain)?;
        recv_seq.check_and_advance_recv(env.sequence)?;
        match env.msg_type {
            MessageType::LivenessPing => {
                let challenge = match env.body.get("challenge") {
                    Some(WireValue::Bytes(b)) => b.clone(),
                    _ => return Err(WireError::MissingField { field: "challenge" }),
                };
                let mut pong_body = BTreeMap::new();
                pong_body.insert("challenge".into(), WireValue::Bytes(challenge));
                pong_body.insert(
                    "last_received_sequence".into(),
                    WireValue::Unsigned(recv_seq.last_seen()),
                );
                let pong_env = RappEnvelope::new(
                    MessageType::LivenessPong,
                    *session_id,
                    send_seq.advance_send()?,
                    pong_body,
                );
                let pong_plain = pong_env.encode()?;
                let pong_cipher = send_cipher.encrypt(&[], &pong_plain)?;
                write_frame(stream, &pong_cipher)?;
            }
            MessageType::OperationStatus => {
                continue;
            }
            _ => return Ok(env),
        }
    }
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
        let prep_env = read_operation_envelope(
            stream,
            &mut send_cipher,
            &mut recv_cipher,
            &mut send_seq,
            &mut recv_seq,
            &session_id,
        )?;
        if prep_env.msg_type != MessageType::OperationPrepared {
            return Err(WireError::InvalidValue {
                field: "operation_prepared_expected",
            });
        }

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
    let result_env = read_operation_envelope(
        stream,
        &mut send_cipher,
        &mut recv_cipher,
        &mut send_seq,
        &mut recv_seq,
        &session_id,
    )?;
    if result_env.msg_type != MessageType::OperationResult {
        return Err(WireError::InvalidValue {
            field: "operation_result_expected",
        });
    }

    let status_str = match result_env.body.get("status") {
        Some(WireValue::Text(s)) => s.as_str(),
        _ => return Err(WireError::MissingField { field: "status" }),
    };
    let status =
        ResultStatus::from_str(status_str).ok_or(WireError::InvalidValue { field: "status" })?;
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

fn resolve_mdns_via_udp(service_name: &str, hints: &[&str]) -> Vec<String> {
    use std::net::UdpSocket;
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let _ = socket.set_read_timeout(Some(Duration::from_millis(600)));

    let mut packet = vec![
        0x00, 0x00, // ID
        0x00, 0x00, // Flags
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for part in ["_refineid-stream", "_tcp", "local"] {
        packet.push(part.len() as u8);
        packet.extend_from_slice(part.as_bytes());
    }
    packet.push(0x00);
    // PTR query with QU bit set (0x8001: unicast-response requested, RFC 6762 §5.4).
    // This allows discovery to succeed in sandboxed environments (e.g. Snap/Flatpak)
    // where multicast response reception on 5353 is blocked or claimed by host daemons.
    packet.extend_from_slice(&[0x00, 0x0c, 0x80, 0x01]);

    let _ = socket.send_to(&packet, "224.0.0.251:5353");

    // Also send direct unicast mDNS queries to any candidate hint IPs on UDP port 5353.
    // Over Wi-Fi, Apple and Android devices often drop or filter multicast when power saving,
    // but standard mDNS responders directly reply to unicast queries sent to port 5353 (RFC 6762 §5.5).
    for hint in hints {
        let ip_part = if let Ok(addr) = hint.parse::<SocketAddr>() {
            addr.ip().to_string()
        } else if let Some((ip, _)) = hint.split_once(':') {
            ip.trim_matches(|c| c == '[' || c == ']').to_string()
        } else {
            hint.to_string()
        };
        if let Ok(ip) = ip_part.parse::<std::net::IpAddr>() {
            let _ = socket.send_to(&packet, SocketAddr::new(ip, 5353));
        }
    }

    let mut buf = [0u8; 4096];
    let service_bytes = service_name.as_bytes();
    let mut results = Vec::new();

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_millis(1500) {
        if let Ok((len, src_addr)) = socket.recv_from(&mut buf) {
            let data = &buf[..len];
            if data
                .windows(service_bytes.len())
                .any(|w| w == service_bytes)
            {
                for i in 0..data.len().saturating_sub(16) {
                    if data[i..].starts_with(&[0x00, 0x21, 0x00, 0x01])
                        || data[i..].starts_with(&[0x00, 0x21, 0x80, 0x01])
                    {
                        let port = u16::from_be_bytes([data[i + 14], data[i + 15]]);
                        if port > 0 {
                            let mut target_ip = None;
                            for j in 0..data.len().saturating_sub(14) {
                                if (data[j..].starts_with(&[0x00, 0x01, 0x00, 0x01])
                                    || data[j..].starts_with(&[0x00, 0x01, 0x80, 0x01]))
                                    && data[j + 8..].starts_with(&[0x00, 0x04])
                                {
                                    let b = &data[j + 10..j + 14];
                                    target_ip = Some(std::net::IpAddr::V4(
                                        std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]),
                                    ));
                                    break;
                                }
                            }
                            let ip = target_ip.unwrap_or_else(|| src_addr.ip());
                            let addr_str = if ip.is_ipv6() {
                                format!("[{ip}]:{port}")
                            } else {
                                format!("{ip}:{port}")
                            };
                            if !results.contains(&addr_str) {
                                results.push(addr_str);
                            }
                        }
                    }
                }
                if !results.is_empty() {
                    return results;
                }
            }
        }
    }
    results
}

/// Resolve candidate IP:port endpoints advertised by `_refineid-stream._tcp` for the given service name.
#[must_use]
pub fn resolve_mdns_stream_endpoints(service_name: &str) -> Vec<String> {
    resolve_mdns_stream_endpoints_with_hints(service_name, &[])
}

/// Resolve candidate IP:port endpoints advertised by `_refineid-stream._tcp` for the given service name,
/// including direct unicast queries to previously known hint endpoints/IPs.
#[must_use]
pub fn resolve_mdns_stream_endpoints_with_hints(service_name: &str, hints: &[&str]) -> Vec<String> {
    // 1. If avahi-browse is present on the host, prefer it as it uses the system mDNS cache
    if let Some(output) = std::process::Command::new("avahi-browse")
        .args(["-r", "-t", "-p", "-k", "_refineid-stream._tcp"])
        .output()
        .ok()
        .filter(|o| o.status.success())
    {
        let text = String::from_utf8_lossy(&output.stdout);
        let mut ipv4_list = Vec::new();
        let mut ipv6_list = Vec::new();

        for line in text.lines() {
            if !line.starts_with('=') {
                continue;
            }
            let fields: Vec<&str> = line.split(';').collect();
            if fields.len() < 9 {
                continue;
            }
            let proto = fields[2];
            let name = fields[3];
            let ip = fields[7];
            let port = fields[8];

            if name == service_name && !ip.is_empty() && !port.is_empty() {
                let addr = if ip.contains(':') {
                    format!("[{ip}]:{port}")
                } else {
                    format!("{ip}:{port}")
                };
                if proto == "IPv4" {
                    if !ipv4_list.contains(&addr) {
                        ipv4_list.push(addr);
                    }
                } else if !ipv6_list.contains(&addr) {
                    ipv6_list.push(addr);
                }
            }
        }

        if !ipv4_list.is_empty() || !ipv6_list.is_empty() {
            let mut result = ipv4_list;
            result.extend(ipv6_list);
            return result;
        }
    }

    // 2. Fall back to direct UDP query (useful in sandboxes without avahi-browse, or if avahi missed the service)
    let udp_results = resolve_mdns_via_udp(service_name, hints);
    if !udp_results.is_empty() {
        return udp_results;
    }

    Vec::new()
}

/// Connect to a paired remote proxy over TCP and perform a card operation.
pub fn execute_operation_with_pair(
    pair: &PairRecord,
    operation: &CardOperation,
) -> Result<CardOperationResult, WireError> {
    let fresh_pair = crate::rapp::RappDeviceVault::new_default()
        .active_pairs()
        .ok()
        .and_then(|list| list.into_iter().find(|p| p.pair_id == pair.pair_id));
    let pair = fresh_pair.as_ref().unwrap_or(pair);

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
        _ => Vec::new(),
    };

    let mut last_err = WireError::InvalidValue { field: "connect" };

    // 1. Try previously stored endpoints first
    for endpoint in &endpoints {
        if let Ok(addr) = endpoint.parse::<SocketAddr>() {
            if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
                let _ = stream.set_read_timeout(Some(DEFAULT_OPERATION_TIMEOUT));
                let _ = stream.set_write_timeout(Some(DEFAULT_OPERATION_TIMEOUT));
                match execute_operation_over_stream(&mut stream, pair, operation) {
                    Ok(res) => return Ok(res),
                    Err(e) => {
                        eprintln!("execute_operation_over_stream stored failed: {e:?}");
                        last_err = e;
                    }
                }
            } else {
                eprintln!("connect_timeout stored endpoint {addr} failed");
                last_err = WireError::InvalidValue {
                    field: "connect_failed",
                };
            }
        }
    }

    let rendezvous_name = StreamRendezvousName::name_from_rendezvous_token(&pair.rendezvous_token);
    let hint_strs: Vec<&str> = endpoints.iter().map(String::as_str).collect();
    let mut resolved = resolve_mdns_stream_endpoints_with_hints(&rendezvous_name, &hint_strs);
    resolved.dedup();
    for endpoint in &resolved {
        if let Ok(addr) = endpoint.parse::<SocketAddr>() {
            if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
                let _ = stream.set_read_timeout(Some(DEFAULT_OPERATION_TIMEOUT));
                let _ = stream.set_write_timeout(Some(DEFAULT_OPERATION_TIMEOUT));
                let mut updated_pair = pair.clone();
                let mut tp = updated_pair.transport_parameters.clone();
                tp.insert(
                    "endpoints".into(),
                    WireValue::Array(vec![WireValue::Text(endpoint.clone())]),
                );
                updated_pair.transport_parameters = tp;
                let vault = crate::rapp::RappDeviceVault::new_default();
                let _ = vault.save_pair(&updated_pair);
                match execute_operation_over_stream(&mut stream, &updated_pair, operation) {
                    Ok(res) => return Ok(res),
                    Err(e) => {
                        eprintln!("execute_operation_over_stream resolved failed: {e:?}");
                        last_err = e;
                    }
                }
            } else if last_err == (WireError::InvalidValue { field: "connect" }) {
                eprintln!("connect_timeout resolved endpoint {addr} failed");
                last_err = WireError::InvalidValue {
                    field: "connect_failed",
                };
            }
        }
    }

    if endpoints.is_empty() && resolved.is_empty() {
        return Err(WireError::MissingField { field: "endpoints" });
    }

    Err(last_err)
}

#[cfg(test)]
mod live_tests {
    use super::*;
    use crate::hex::Hex;
    use crate::rapp::RappDeviceVault;

    #[test]
    #[ignore]
    fn test_live_session_operation() {
        let vault = RappDeviceVault::new_default();
        let pairs = vault.active_pairs().expect("vault active pairs");
        assert!(!pairs.is_empty(), "Need at least 1 active pair");
        let pair = &pairs[0];
        println!("Pair info:");
        println!("  pair_id: {}", Hex::encode(&pair.pair_id));
        println!(
            "  rendezvous_token: {}",
            Hex::encode(&pair.rendezvous_token)
        );
        println!("  role: {}", pair.role);
        println!("  transport_profile: {}", pair.transport_profile);
        println!("  candidate_id: {}", pair.candidate_id);
        println!("  grants_hash: {}", Hex::encode(&pair.grants_hash));
        println!("  profiles: {:?}", pair.profiles);
        println!("  transport_parameters: {:?}", pair.transport_parameters);

        let op = CardOperation::ReadCertificate {
            kind: "authentication".into(),
        };
        let res = execute_operation_with_pair(pair, &op);
        println!("Result: {res:?}");
        assert!(res.is_ok());
    }

    #[test]
    #[ignore]
    fn test_live_browser_authenticate() {
        let vault = RappDeviceVault::new_default();
        let pairs = vault.active_pairs().expect("vault active pairs");
        assert!(!pairs.is_empty(), "Need at least 1 active pair");
        let pair = &pairs[0];
        let rname = StreamRendezvousName::name_from_rendezvous_token(&pair.rendezvous_token);
        println!("Rendezvous name: {rname}");
        println!(
            "Stored endpoints: {:?}",
            pair.transport_parameters.get("endpoints")
        );
        let resolved = resolve_mdns_stream_endpoints(&rname);
        println!("Resolved endpoints: {resolved:?}");

        let op = CardOperation::BrowserAuthenticate {
            origin: "https://card.refineid.fi".into(),
            key_profile: "ecdsa_p384".into(),
            algorithm: "ecdsa_sha384".into(),
            digest: vec![0x42; 48],
        };
        let res = execute_operation_with_pair(pair, &op);
        println!("Result: {res:?}");
        assert!(res.is_ok());
    }
}
