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

//! Conformance tests and end-to-end synthetic pairing/operation verification for RAPP.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use std::io::{self, Read, Write};
use std::sync::mpsc::{Receiver, Sender, channel};

use super::crypto::*;
use super::envelope::*;
use super::messages::*;
use super::session::*;
use super::transport::*;
use super::wire::*;

/// Bidirectional in-memory pipe for testing protocol streams.
#[derive(Debug)]
pub struct DuplexPipe {
    reader: Receiver<Vec<u8>>,
    writer: Sender<Vec<u8>>,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl DuplexPipe {
    /// Create a connected pair of bidirectional in-memory pipes.
    #[must_use]
    pub fn pair() -> (Self, Self) {
        let (tx1, rx1) = channel();
        let (tx2, rx2) = channel();
        let pipe_a = Self {
            reader: rx2,
            writer: tx1,
            read_buf: Vec::new(),
            read_pos: 0,
        };
        let pipe_b = Self {
            reader: rx1,
            writer: tx2,
            read_buf: Vec::new(),
            read_pos: 0,
        };
        (pipe_a, pipe_b)
    }
}

impl Read for DuplexPipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.read_pos >= self.read_buf.len() {
            match self.reader.recv() {
                Ok(data) => {
                    self.read_buf = data;
                    self.read_pos = 0;
                }
                Err(_) => return Ok(0), // EOF
            }
        }
        let available = self.read_buf.len() - self.read_pos;
        let to_copy = available.min(buf.len());
        buf[..to_copy].copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + to_copy]);
        self.read_pos += to_copy;
        Ok(to_copy)
    }
}

impl Write for DuplexPipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer
            .send(buf.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn test_cbor_primitives_deterministic() {
    assert_eq!(WireValue::Unsigned(0).encode().expect("ok"), [0x00]);
    assert_eq!(WireValue::Unsigned(23).encode().expect("ok"), [0x17]);
    assert_eq!(WireValue::Unsigned(24).encode().expect("ok"), [0x18, 0x18]);
    assert_eq!(WireValue::Unsigned(255).encode().expect("ok"), [0x18, 0xFF]);
    assert_eq!(
        WireValue::Unsigned(256).encode().expect("ok"),
        [0x19, 0x01, 0x00]
    );
    assert_eq!(WireValue::Negative(-1).encode().expect("ok"), [0x20]);
    assert_eq!(WireValue::Negative(-24).encode().expect("ok"), [0x37]);
    assert_eq!(WireValue::Negative(-25).encode().expect("ok"), [0x38, 0x18]);
    assert_eq!(WireValue::Boolean(true).encode().expect("ok"), [0xF5]);
    assert_eq!(WireValue::Boolean(false).encode().expect("ok"), [0xF4]);
    assert_eq!(WireValue::Null.encode().expect("ok"), [0xF6]);
    assert_eq!(
        WireValue::Text("RAPP".into()).encode().expect("ok"),
        [0x64, b'R', b'A', b'P', b'P']
    );
    assert_eq!(
        WireValue::Bytes(vec![0x00, 0x01, 0xFF])
            .encode()
            .expect("ok"),
        [0x43, 0x00, 0x01, 0xFF]
    );
}

#[test]
fn test_pairing_offer_uri_roundtrip() {
    let transports = vec![
        TransportCandidate::new_stream("stream-0", &["192.168.1.50:52424".into()]),
        TransportCandidate::new_ble("ble-0", "FA1D0001-C34A-4836-843B-7603B5749A32", Some(161)),
    ];
    let offer = PairingOffer::generate(transports);
    let uri = offer.to_uri().expect("ok");
    assert!(uri.starts_with("rapp:"));

    let decoded_offer = PairingOffer::from_uri(&uri).expect("ok");
    assert_eq!(offer.offer_id, decoded_offer.offer_id);
    assert_eq!(offer.pairing_secret, decoded_offer.pairing_secret);
    assert_eq!(offer.suites, decoded_offer.suites);
    assert_eq!(offer.profiles, decoded_offer.profiles);
    assert_eq!(offer.transports.len(), 2);
}

#[test]
fn test_stream_rendezvous_encoding() {
    let pairing_rendezvous = StreamRendezvous::Pairing;
    let enc_pairing = pairing_rendezvous.encode().expect("ok");
    let dec_pairing = StreamRendezvous::decode(&enc_pairing).expect("ok");
    assert_eq!(pairing_rendezvous, dec_pairing);

    let token = [0x42u8; 16];
    let session_rendezvous = StreamRendezvous::Session {
        rendezvous_token: token,
    };
    let enc_session = session_rendezvous.encode().expect("ok");
    let dec_session = StreamRendezvous::decode(&enc_session).expect("ok");
    assert_eq!(session_rendezvous, dec_session);
}

#[test]
fn test_synthetic_pairing_and_operation_roundtrip() {
    let (mut requester_pipe, mut proxy_pipe) = DuplexPipe::pair();

    let candidate = TransportCandidate::new_stream("stream-0", &["127.0.0.1:52424".into()]);
    let offer = PairingOffer::generate(vec![candidate.clone()]);
    let offer_ctx = PairOfferContext {
        offer: offer.clone(),
        selected_transport: TRANSPORT_STREAM.into(),
        selected_candidate_id: "stream-0".into(),
        transport_parameters: candidate.parameters.clone(),
    };

    // Spawn proxy thread to simulate iPhone/Android
    let proxy_handle = std::thread::spawn(move || -> PairRecord {
        // 1. Read preamble sent by requester
        let preamble_bytes = read_frame(&mut proxy_pipe).expect("ok");
        let dec_preamble = StreamRendezvous::decode(&preamble_bytes).expect("ok");
        assert_eq!(dec_preamble, StreamRendezvous::Pairing);

        // 2. Drive Noise XXpsk3 as responder
        let proxy_static_bytes = [0x55u8; 32];
        let proxy_sec = x25519_dalek::StaticSecret::from(proxy_static_bytes);
        let proxy_pub = x25519_dalek::PublicKey::from(&proxy_sec).to_bytes();

        let offer_hash = offer.offer_hash().expect("ok");
        let prologue = pairing_prologue(&offer_hash, TRANSPORT_STREAM).expect("ok");

        let mut hs = NoiseHandshakeState::new(
            NoisePatternKind::XxPsk3,
            PAIRING_SUITE,
            &prologue,
            false, // Responder
            &proxy_static_bytes,
            None,
            Some(offer.pairing_secret),
            None,
        );

        // Msg 1 (<-)
        let msg1 = read_frame(&mut proxy_pipe).expect("ok");
        hs.read_message(&msg1).expect("ok");

        // Msg 2 (->)
        let msg2 = hs.write_message(&[]).expect("ok");
        write_frame(&mut proxy_pipe, &msg2).expect("ok");

        // Msg 3 (<-)
        let msg3 = read_frame(&mut proxy_pipe).expect("ok");
        hs.read_message(&msg3).expect("ok");

        let handshake_hash = *hs.handshake_hash();
        let session_id = derive_session_id(&handshake_hash);
        let pair_id = derive_pair_id(&handshake_hash);
        let rendezvous_token = derive_rendezvous_token(&handshake_hash);
        let remote_static_pub = hs.remote_static_public().expect("ok");

        let (mut send_cipher, mut recv_cipher) = hs.split().expect("ok");
        let mut send_seq = SequenceGuard::new();
        let mut recv_seq = SequenceGuard::new();

        // Read pairing.hello
        let req_hello_cipher = read_frame(&mut proxy_pipe).expect("ok");
        let req_hello_plain = recv_cipher.decrypt(&[], &req_hello_cipher).expect("ok");
        let req_hello_env = RappEnvelope::decode(&req_hello_plain).expect("ok");
        assert_eq!(req_hello_env.msg_type, MessageType::PairingHello);
        recv_seq
            .check_and_advance_recv(req_hello_env.sequence)
            .expect("ok");

        // Send proxy pairing.hello
        let mut proxy_hello_body = BTreeMap::new();
        proxy_hello_body.insert(
            "display_name".into(),
            WireValue::Text("iPhone 17 Pro".into()),
        );
        proxy_hello_body.insert("platform".into(), WireValue::Text("iOS".into()));
        let proxy_hello_env = RappEnvelope::new(
            MessageType::PairingHello,
            session_id,
            send_seq.advance_send().expect("ok"),
            proxy_hello_body,
        );
        let proxy_hello_plain = proxy_hello_env.encode().expect("ok");
        let proxy_hello_cipher = send_cipher.encrypt(&[], &proxy_hello_plain).expect("ok");
        write_frame(&mut proxy_pipe, &proxy_hello_cipher).expect("ok");

        // Send proxy pairing.confirm
        let mut proxy_confirm_body = BTreeMap::new();
        proxy_confirm_body.insert(
            "granted_profiles".into(),
            WireValue::Array(vec![
                WireValue::Text(PROFILE_STATUS.into()),
                WireValue::Text(PROFILE_AUTH.into()),
                WireValue::Text(PROFILE_SIGN.into()),
            ]),
        );
        let proxy_confirm_env = RappEnvelope::new(
            MessageType::PairingConfirm,
            session_id,
            send_seq.advance_send().expect("ok"),
            proxy_confirm_body,
        );
        let proxy_confirm_plain = proxy_confirm_env.encode().expect("ok");
        let proxy_confirm_cipher = send_cipher.encrypt(&[], &proxy_confirm_plain).expect("ok");
        write_frame(&mut proxy_pipe, &proxy_confirm_cipher).expect("ok");

        // Read requester pairing.confirm
        let req_confirm_cipher = read_frame(&mut proxy_pipe).expect("ok");
        let req_confirm_plain = recv_cipher.decrypt(&[], &req_confirm_cipher).expect("ok");
        let req_confirm_env = RappEnvelope::decode(&req_confirm_plain).expect("ok");
        assert_eq!(req_confirm_env.msg_type, MessageType::PairingConfirm);
        recv_seq
            .check_and_advance_recv(req_confirm_env.sequence)
            .expect("ok");

        let grants = vec![
            PROFILE_STATUS.into(),
            PROFILE_AUTH.into(),
            PROFILE_SIGN.into(),
        ];
        let grants_hash = derive_grants_hash(&grants).expect("ok");

        PairRecord {
            pair_id,
            rendezvous_token,
            role: "proxy".into(),
            local_static_private: proxy_static_bytes,
            local_static_public: proxy_pub,
            remote_static_public: remote_static_pub,
            grants_hash,
            profiles: grants,
            transport_profile: TRANSPORT_STREAM.into(),
            candidate_id: "stream-0".into(),
            transport_parameters: candidate.parameters.clone(),
            created_at_ms: 1000,
            display_name: Some("iPhone 17 Pro".into()),
            platform: Some("iOS".into()),
            cached_auth_cert: None,
        }
    });

    // Run requester pairing on main thread
    let pair_record =
        pair_requester_over_stream(&mut requester_pipe, &offer_ctx, "ReFineID Ubuntu", "Linux")
            .expect("ok");

    let proxy_record = proxy_handle.join().expect("ok");
    assert_eq!(pair_record.pair_id, proxy_record.pair_id);
    assert_eq!(pair_record.rendezvous_token, proxy_record.rendezvous_token);
    assert_eq!(
        pair_record.local_static_public,
        proxy_record.remote_static_public
    );
    assert_eq!(
        pair_record.remote_static_public,
        proxy_record.local_static_public
    );
    assert_eq!(pair_record.display_name.as_deref(), Some("iPhone 17 Pro"));
    assert_eq!(pair_record.platform.as_deref(), Some("iOS"));

    // Now test an operation (browser_authenticate / sign_digest) over a fresh stream
    let (mut requester_op_pipe, mut proxy_op_pipe) = DuplexPipe::pair();

    let op = CardOperation::BrowserAuthenticate {
        origin: "https://suomi.fi".into(),
        key_profile: "eccP384".into(),
        algorithm: "ecdsaSha384".into(),
        digest: vec![0xAA; 48],
    };

    let proxy_op_handle = std::thread::spawn(move || {
        // Read preamble
        let preamble_bytes = read_frame(&mut proxy_op_pipe).expect("ok");
        let rendezvous = StreamRendezvous::decode(&preamble_bytes).expect("ok");
        assert_eq!(
            rendezvous,
            StreamRendezvous::Session {
                rendezvous_token: proxy_record.rendezvous_token
            }
        );

        // Run Noise KK responder
        let prologue = session_prologue(
            &proxy_record.pair_id,
            &proxy_record.grants_hash,
            TRANSPORT_STREAM,
        )
        .expect("ok");
        let mut hs = NoiseHandshakeState::new(
            NoisePatternKind::Kk,
            SESSION_SUITE,
            &prologue,
            false, // Responder
            &proxy_record.local_static_private,
            Some(proxy_record.remote_static_public),
            None,
            None,
        );

        // Msg 1 (<-)
        let msg1 = read_frame(&mut proxy_op_pipe).expect("ok");
        hs.read_message(&msg1).expect("ok");

        // Msg 2 (->)
        let msg2 = hs.write_message(&[]).expect("ok");
        write_frame(&mut proxy_op_pipe, &msg2).expect("ok");

        let session_id = derive_session_id(hs.handshake_hash());
        let (mut send_cipher, mut recv_cipher) = hs.split().expect("ok");
        let mut send_seq = SequenceGuard::new();
        let mut recv_seq = SequenceGuard::new();

        // Read session.ready
        let ready_cipher = read_frame(&mut proxy_op_pipe).expect("ok");
        let ready_plain = recv_cipher.decrypt(&[], &ready_cipher).expect("ok");
        let ready_env = RappEnvelope::decode(&ready_plain).expect("ok");
        assert_eq!(ready_env.msg_type, MessageType::SessionReady);
        recv_seq
            .check_and_advance_recv(ready_env.sequence)
            .expect("ok");

        // Send proxy session.ready
        let mut proxy_ready_body = BTreeMap::new();
        proxy_ready_body.insert(
            "parameters".into(),
            ready_env.body.get("parameters").expect("ok").clone(),
        );
        proxy_ready_body.insert("nonce".into(), WireValue::Bytes(vec![0x77; 32]));
        let proxy_ready_env = RappEnvelope::new(
            MessageType::SessionReady,
            session_id,
            send_seq.advance_send().expect("ok"),
            proxy_ready_body,
        );
        let proxy_ready_plain = proxy_ready_env.encode().expect("ok");
        let proxy_ready_cipher = send_cipher.encrypt(&[], &proxy_ready_plain).expect("ok");
        write_frame(&mut proxy_op_pipe, &proxy_ready_cipher).expect("ok");

        // Read operation.request
        let req_cipher = read_frame(&mut proxy_op_pipe).expect("ok");
        let req_plain = recv_cipher.decrypt(&[], &req_cipher).expect("ok");
        let req_env = RappEnvelope::decode(&req_plain).expect("ok");
        assert_eq!(req_env.msg_type, MessageType::OperationRequest);
        recv_seq
            .check_and_advance_recv(req_env.sequence)
            .expect("ok");

        let op_id = req_env.body.get("operation_id").expect("ok").clone();
        let req_hash = req_env.body.get("request_hash").expect("ok").clone();

        // Send operation.prepared
        let mut prep_body = BTreeMap::new();
        prep_body.insert("operation_id".into(), op_id.clone());
        prep_body.insert("request_hash".into(), req_hash.clone());
        let prep_env = RappEnvelope::new(
            MessageType::OperationPrepared,
            session_id,
            send_seq.advance_send().expect("ok"),
            prep_body,
        );
        let prep_plain = prep_env.encode().expect("ok");
        let prep_cipher = send_cipher.encrypt(&[], &prep_plain).expect("ok");
        write_frame(&mut proxy_op_pipe, &prep_cipher).expect("ok");

        // Read operation.commit
        let commit_cipher = read_frame(&mut proxy_op_pipe).expect("ok");
        let commit_plain = recv_cipher.decrypt(&[], &commit_cipher).expect("ok");
        let commit_env = RappEnvelope::decode(&commit_plain).expect("ok");
        assert_eq!(commit_env.msg_type, MessageType::OperationCommit);
        recv_seq
            .check_and_advance_recv(commit_env.sequence)
            .expect("ok");

        // Send operation.result (with mock signature)
        let mock_sig = vec![0x30, 0x44, 0x02, 0x20, 0x11, 0x22, 0x33, 0x44];
        let mut res_body_inner = BTreeMap::new();
        res_body_inner.insert("type".into(), WireValue::Text("signature".into()));
        res_body_inner.insert("signature".into(), WireValue::Bytes(mock_sig));

        let mut res_body = BTreeMap::new();
        res_body.insert("operation_id".into(), op_id);
        res_body.insert("request_hash".into(), req_hash);
        res_body.insert("status".into(), WireValue::Text("completed".into()));
        res_body.insert("body".into(), WireValue::Map(res_body_inner));

        let res_env = RappEnvelope::new(
            MessageType::OperationResult,
            session_id,
            send_seq.advance_send().expect("ok"),
            res_body,
        );
        let res_plain = res_env.encode().expect("ok");
        let res_cipher = send_cipher.encrypt(&[], &res_plain).expect("ok");
        write_frame(&mut proxy_op_pipe, &res_cipher).expect("ok");

        // Read operation.result_ack
        let ack_cipher = read_frame(&mut proxy_op_pipe).expect("ok");
        let ack_plain = recv_cipher.decrypt(&[], &ack_cipher).expect("ok");
        let ack_env = RappEnvelope::decode(&ack_plain).expect("ok");
        assert_eq!(ack_env.msg_type, MessageType::OperationResultAck);
        recv_seq
            .check_and_advance_recv(ack_env.sequence)
            .expect("ok");
    });

    let outcome =
        execute_operation_over_stream(&mut requester_op_pipe, &pair_record, &op).expect("ok");
    proxy_op_handle.join().expect("ok");

    match outcome {
        CardOperationResult::Signature { signature_bytes } => {
            assert_eq!(
                signature_bytes,
                vec![0x30, 0x44, 0x02, 0x20, 0x11, 0x22, 0x33, 0x44]
            );
        }
        _ => panic!("expected signature result"),
    }
}
