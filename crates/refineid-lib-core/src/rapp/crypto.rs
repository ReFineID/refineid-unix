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

//! Cryptographic primitives and Noise Protocol engine for RAPP.
//!
//! Implements `Noise_XXpsk3_25519_ChaChaPoly_SHA256` and `Noise_KK_25519_ChaChaPoly_SHA256`
//! according to the Noise Protocol Framework (Revision 34) and RAPP specification.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use chacha20poly1305::aead::{Aead, KeyInit as AeadKeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use super::wire::{WireError, WireValue};

/// Wire version tuple (26, 8).
pub const WIRE_VERSION: (u64, u64) = (26, 8);

/// Mandatory pairing cipher suite name.
pub const PAIRING_SUITE: &str = "Noise_XXpsk3_25519_ChaChaPoly_SHA256";
/// Mandatory session cipher suite name.
pub const SESSION_SUITE: &str = "Noise_KK_25519_ChaChaPoly_SHA256";

/// Domain prefix for pairing prologue.
pub const PAIRING_PROLOGUE_DOMAIN: &str = "RAPP-pairing-v1";
/// Domain prefix for session prologue.
pub const SESSION_PROLOGUE_DOMAIN: &str = "RAPP-session-v1";

/// Domain prefix for session identifier derivation.
pub const SESSION_ID_DOMAIN: &str = "RAPP-session-id-v1";
/// Domain prefix for pair identifier derivation.
pub const PAIR_ID_DOMAIN: &str = "RAPP-pair-id-v1";
/// Domain prefix for rendezvous token derivation.
pub const RENDEZVOUS_DOMAIN: &str = "RAPP-rendezvous-v1";
/// Domain prefix for request hash derivation.
pub const REQUEST_DOMAIN: &str = "RAPP-request-v1";

/// Length in bytes of public keys and hashes.
pub const HASH_LEN: usize = 32;
/// Length in bytes of derived identifiers.
pub const ID_LEN: usize = 16;
/// Poly1305 authentication tag length.
pub const TAG_LEN: usize = 16;

/// One direction of an established Noise channel.
#[derive(Clone, Copy)]
pub struct NoiseCipherState {
    key: Option<[u8; 32]>,
    counter: u64,
}

impl core::fmt::Debug for NoiseCipherState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NoiseCipherState")
            .field("has_key", &self.key.is_some())
            .field("counter", &self.counter)
            .finish()
    }
}

impl Default for NoiseCipherState {
    fn default() -> Self {
        Self::new()
    }
}

impl NoiseCipherState {
    /// Create a new, unkeyed cipher state.
    pub const fn new() -> Self {
        Self {
            key: None,
            counter: 0,
        }
    }

    /// Whether this cipher state has a key configured.
    pub const fn has_key(&self) -> bool {
        self.key.is_some()
    }

    /// Set the cipher key and reset the counter.
    pub fn initialize_key(&mut self, key: [u8; 32]) {
        self.key = Some(key);
        self.counter = 0;
    }

    fn nonce(counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&counter.to_le_bytes());
        nonce
    }

    /// Encrypt plaintext with associated authenticated data.
    pub fn encrypt(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, WireError> {
        let Some(key_bytes) = self.key else {
            return Ok(plaintext.to_vec());
        };
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let nonce_bytes = Self::nonce(self.counter);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| WireError::InvalidValue { field: "cipher" })?;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(WireError::IntegerOverflow)?;
        Ok(ciphertext)
    }

    /// Decrypt ciphertext with associated authenticated data.
    pub fn decrypt(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, WireError> {
        let Some(key_bytes) = self.key else {
            return Ok(ciphertext.to_vec());
        };
        if ciphertext.len() < TAG_LEN {
            return Err(WireError::Truncated);
        }
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let nonce_bytes = Self::nonce(self.counter);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| WireError::NonCanonical)?;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(WireError::IntegerOverflow)?;
        Ok(plaintext)
    }
}

/// The symmetric chaining key and transcript hash state.
#[derive(Clone, Copy, Debug)]
pub struct NoiseSymmetricState {
    chaining_key: [u8; 32],
    handshake_hash: [u8; 32],
    cipher: NoiseCipherState,
}

impl NoiseSymmetricState {
    /// Initialize symmetric state with protocol suite name.
    pub fn new(protocol_name: &str) -> Self {
        let name_bytes = protocol_name.as_bytes();
        let handshake_hash = if name_bytes.len() <= 32 {
            let mut h = [0u8; 32];
            h[..name_bytes.len()].copy_from_slice(name_bytes);
            h
        } else {
            Sha256::digest(name_bytes).into()
        };
        let chaining_key = handshake_hash;
        Self {
            chaining_key,
            handshake_hash,
            cipher: NoiseCipherState::new(),
        }
    }

    /// Current transcript handshake hash.
    pub const fn handshake_hash(&self) -> &[u8; 32] {
        &self.handshake_hash
    }

    fn hkdf_derive(ck: &[u8; 32], material: &[u8], num_outputs: usize) -> Vec<[u8; 32]> {
        let s_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, ck);
        let temp_tag = ring::hmac::sign(&s_key, material);
        let temp_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, temp_tag.as_ref());

        let mut results = Vec::with_capacity(num_outputs);
        let mut prev = Vec::new();
        for i in 1..=num_outputs {
            let mut msg = Vec::with_capacity(prev.len() + 1);
            msg.extend_from_slice(&prev);
            msg.push(i as u8);
            let tag = ring::hmac::sign(&temp_key, &msg);
            let mut output = [0u8; 32];
            output.copy_from_slice(tag.as_ref());
            prev = output.to_vec();
            results.push(output);
        }
        results
    }

    /// Mix data into the handshake transcript hash.
    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(&self.handshake_hash);
        hasher.update(data);
        self.handshake_hash = hasher.finalize().into();
    }

    /// Mix key material into chaining key and re-key cipher.
    pub fn mix_key(&mut self, material: &[u8]) {
        let outputs = Self::hkdf_derive(&self.chaining_key, material, 2);
        self.chaining_key = outputs[0];
        self.cipher.initialize_key(outputs[1]);
    }

    /// Mix key material and hash.
    pub fn mix_key_and_hash(&mut self, material: &[u8]) {
        let outputs = Self::hkdf_derive(&self.chaining_key, material, 3);
        self.chaining_key = outputs[0];
        self.mix_hash(&outputs[1]);
        self.cipher.initialize_key(outputs[2]);
    }

    /// Encrypt plaintext with current handshake hash as AAD, then mix ciphertext into hash.
    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, WireError> {
        let ciphertext = self.cipher.encrypt(&self.handshake_hash, plaintext)?;
        self.mix_hash(&ciphertext);
        Ok(ciphertext)
    }

    /// Decrypt ciphertext with current handshake hash as AAD, then mix ciphertext into hash.
    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, WireError> {
        let plaintext = self.cipher.decrypt(&self.handshake_hash, ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    /// Split chaining key into two 32-byte transport keys (initiator-sends, responder-sends).
    pub fn split(&self) -> ([u8; 32], [u8; 32]) {
        let outputs = Self::hkdf_derive(&self.chaining_key, &[], 2);
        (outputs[0], outputs[1])
    }
}

/// Token in a Noise handshake pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoiseToken {
    /// Ephemeral public key token `e`.
    Ephemeral,
    /// Static public key token `s`.
    StaticKey,
    /// Ephemeral-Ephemeral DH token `ee`.
    EphemeralEphemeral,
    /// Ephemeral-Static DH token `es`.
    EphemeralStatic,
    /// Static-Ephemeral DH token `se`.
    StaticEphemeral,
    /// Static-Static DH token `ss`.
    StaticStatic,
    /// Pre-shared key mixing token `psk`.
    PresharedKey,
}

/// Noise handshake pattern definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoisePatternKind {
    /// `Noise_XXpsk3`: Mutual static exchange with PSK mixed into final turn.
    XxPsk3,
    /// `Noise_KK`: Mutual static keys known in advance.
    Kk,
}

impl NoisePatternKind {
    /// Handshake pattern name.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::XxPsk3 => "XXpsk3",
            Self::Kk => "KK",
        }
    }

    /// Whether this pattern requires a pre-shared key (PSK).
    pub const fn uses_psk(&self) -> bool {
        match self {
            Self::XxPsk3 => true,
            Self::Kk => false,
        }
    }

    /// Sequence of tokens for the given message index in the pattern.
    pub fn message_tokens(&self, index: usize) -> Option<&'static [NoiseToken]> {
        match self {
            Self::XxPsk3 => match index {
                0 => Some(&[NoiseToken::Ephemeral]),
                1 => Some(&[
                    NoiseToken::Ephemeral,
                    NoiseToken::EphemeralEphemeral,
                    NoiseToken::StaticKey,
                    NoiseToken::EphemeralStatic,
                ]),
                2 => Some(&[
                    NoiseToken::StaticKey,
                    NoiseToken::StaticEphemeral,
                    NoiseToken::PresharedKey,
                ]),
                _ => None,
            },
            Self::Kk => match index {
                0 => Some(&[
                    NoiseToken::Ephemeral,
                    NoiseToken::EphemeralStatic,
                    NoiseToken::StaticStatic,
                ]),
                1 => Some(&[
                    NoiseToken::Ephemeral,
                    NoiseToken::EphemeralEphemeral,
                    NoiseToken::StaticEphemeral,
                ]),
                _ => None,
            },
        }
    }
}

/// Complete state machine for a Noise handshake.
pub struct NoiseHandshakeState {
    symmetric: NoiseSymmetricState,
    pattern: NoisePatternKind,
    is_initiator: bool,
    preshared_key: Option<[u8; 32]>,
    local_static_secret: StaticSecret,
    local_static_public: [u8; 32],
    local_ephemeral_secret: Option<StaticSecret>,
    local_ephemeral_public: Option<[u8; 32]>,
    remote_static_public: Option<[u8; 32]>,
    remote_ephemeral_public: Option<[u8; 32]>,
    message_index: usize,
}

impl core::fmt::Debug for NoiseHandshakeState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NoiseHandshakeState")
            .field("pattern", &self.pattern)
            .field("is_initiator", &self.is_initiator)
            .field("message_index", &self.message_index)
            .finish()
    }
}

impl NoiseHandshakeState {
    /// Initialize a new handshake state.
    pub fn new(
        pattern: NoisePatternKind,
        suite_name: &str,
        prologue: &[u8],
        is_initiator: bool,
        local_static_secret_bytes: &[u8; 32],
        remote_static_public: Option<[u8; 32]>,
        preshared_key: Option<[u8; 32]>,
        fixed_ephemeral_secret_bytes: Option<[u8; 32]>,
    ) -> Self {
        let local_static_secret = StaticSecret::from(*local_static_secret_bytes);
        let local_static_public: [u8; 32] = X25519PublicKey::from(&local_static_secret).to_bytes();

        let (local_ephemeral_secret, local_ephemeral_public) =
            if let Some(bytes) = fixed_ephemeral_secret_bytes {
                let sec = StaticSecret::from(bytes);
                let pubkey = X25519PublicKey::from(&sec).to_bytes();
                (Some(sec), Some(pubkey))
            } else {
                (None, None)
            };

        let mut symmetric = NoiseSymmetricState::new(suite_name);
        symmetric.mix_hash(prologue);

        // Pre-messages for KK
        if pattern == NoisePatternKind::Kk {
            if is_initiator {
                symmetric.mix_hash(&local_static_public);
                symmetric.mix_hash(&remote_static_public.expect("KK requires remote static"));
            } else {
                symmetric.mix_hash(&remote_static_public.expect("KK requires remote static"));
                symmetric.mix_hash(&local_static_public);
            }
        }

        Self {
            symmetric,
            pattern,
            is_initiator,
            preshared_key,
            local_static_secret,
            local_static_public,
            local_ephemeral_secret,
            local_ephemeral_public,
            remote_static_public,
            remote_ephemeral_public: None,
            message_index: 0,
        }
    }

    /// Handshake transcript hash.
    pub const fn handshake_hash(&self) -> &[u8; 32] {
        self.symmetric.handshake_hash()
    }

    /// Authenticated remote static public key.
    pub const fn remote_static_public(&self) -> Option<[u8; 32]> {
        self.remote_static_public
    }

    /// Whether the handshake sequence is complete.
    pub fn is_complete(&self) -> bool {
        self.pattern.message_tokens(self.message_index).is_none()
    }

    fn local_writes_next(&self) -> bool {
        (self.message_index % 2 == 0) == self.is_initiator
    }

    fn ensure_local_ephemeral(&mut self) {
        if self.local_ephemeral_secret.is_none() {
            let mut rand_bytes = [0u8; 32];
            getrandom::fill(&mut rand_bytes).expect("CSPRNG available");
            let sec = StaticSecret::from(rand_bytes);
            let pubkey = X25519PublicKey::from(&sec).to_bytes();
            self.local_ephemeral_secret = Some(sec);
            self.local_ephemeral_public = Some(pubkey);
        }
    }

    fn diffie_hellman(sec: &StaticSecret, pub_bytes: &[u8; 32]) -> [u8; 32] {
        let remote_pub = X25519PublicKey::from(*pub_bytes);
        sec.diffie_hellman(&remote_pub).to_bytes()
    }

    /// Write next message in the handshake.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, WireError> {
        if self.is_complete() || !self.local_writes_next() {
            return Err(WireError::InvalidValue {
                field: "handshake_turn",
            });
        }
        let tokens = self
            .pattern
            .message_tokens(self.message_index)
            .ok_or(WireError::InvalidValue { field: "handshake" })?;
        let mut buffer = Vec::new();

        for token in tokens {
            match token {
                NoiseToken::Ephemeral => {
                    self.ensure_local_ephemeral();
                    let pub_bytes = self.local_ephemeral_public.expect("ephemeral generated");
                    buffer.extend_from_slice(&pub_bytes);
                    self.symmetric.mix_hash(&pub_bytes);
                    if self.pattern.uses_psk() {
                        self.symmetric.mix_key(&pub_bytes);
                    }
                }
                NoiseToken::StaticKey => {
                    let cipher = self.symmetric.encrypt_and_hash(&self.local_static_public)?;
                    buffer.extend_from_slice(&cipher);
                }
                NoiseToken::EphemeralEphemeral => {
                    let sec = self
                        .local_ephemeral_secret
                        .as_ref()
                        .expect("local ephemeral");
                    let remote_pub = self
                        .remote_ephemeral_public
                        .as_ref()
                        .expect("remote ephemeral");
                    let ss = Self::diffie_hellman(sec, remote_pub);
                    self.symmetric.mix_key(&ss);
                }
                NoiseToken::EphemeralStatic => {
                    let ss = if self.is_initiator {
                        let sec = self
                            .local_ephemeral_secret
                            .as_ref()
                            .expect("local ephemeral");
                        let remote_pub = self.remote_static_public.as_ref().expect("remote static");
                        Self::diffie_hellman(sec, remote_pub)
                    } else {
                        let remote_pub = self
                            .remote_ephemeral_public
                            .as_ref()
                            .expect("remote ephemeral");
                        Self::diffie_hellman(&self.local_static_secret, remote_pub)
                    };
                    self.symmetric.mix_key(&ss);
                }
                NoiseToken::StaticEphemeral => {
                    let ss = if self.is_initiator {
                        let remote_pub = self
                            .remote_ephemeral_public
                            .as_ref()
                            .expect("remote ephemeral");
                        Self::diffie_hellman(&self.local_static_secret, remote_pub)
                    } else {
                        let sec = self
                            .local_ephemeral_secret
                            .as_ref()
                            .expect("local ephemeral");
                        let remote_pub = self.remote_static_public.as_ref().expect("remote static");
                        Self::diffie_hellman(sec, remote_pub)
                    };
                    self.symmetric.mix_key(&ss);
                }
                NoiseToken::StaticStatic => {
                    let remote_pub = self.remote_static_public.as_ref().expect("remote static");
                    let ss = Self::diffie_hellman(&self.local_static_secret, remote_pub);
                    self.symmetric.mix_key(&ss);
                }
                NoiseToken::PresharedKey => {
                    let psk = self.preshared_key.expect("PSK required");
                    self.symmetric.mix_key_and_hash(&psk);
                }
            }
        }

        let payload_cipher = self.symmetric.encrypt_and_hash(payload)?;
        buffer.extend_from_slice(&payload_cipher);
        self.message_index += 1;
        Ok(buffer)
    }

    /// Read next message in the handshake.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, WireError> {
        if self.is_complete() || self.local_writes_next() {
            return Err(WireError::InvalidValue {
                field: "handshake_turn",
            });
        }
        let tokens = self
            .pattern
            .message_tokens(self.message_index)
            .ok_or(WireError::InvalidValue { field: "handshake" })?;
        let mut offset = 0;

        for token in tokens {
            match token {
                NoiseToken::Ephemeral => {
                    if message.len() < offset + 32 {
                        return Err(WireError::Truncated);
                    }
                    let mut pub_bytes = [0u8; 32];
                    pub_bytes.copy_from_slice(&message[offset..offset + 32]);
                    offset += 32;
                    self.remote_ephemeral_public = Some(pub_bytes);
                    self.symmetric.mix_hash(&pub_bytes);
                    if self.pattern.uses_psk() {
                        self.symmetric.mix_key(&pub_bytes);
                    }
                }
                NoiseToken::StaticKey => {
                    let len = if self.symmetric.cipher.has_key() {
                        32 + TAG_LEN
                    } else {
                        32
                    };
                    if message.len() < offset + len {
                        return Err(WireError::Truncated);
                    }
                    let plain = self
                        .symmetric
                        .decrypt_and_hash(&message[offset..offset + len])?;
                    offset += len;
                    let mut pub_bytes = [0u8; 32];
                    pub_bytes.copy_from_slice(&plain[..32]);
                    self.remote_static_public = Some(pub_bytes);
                }
                NoiseToken::EphemeralEphemeral => {
                    let sec = self
                        .local_ephemeral_secret
                        .as_ref()
                        .expect("local ephemeral");
                    let remote_pub = self
                        .remote_ephemeral_public
                        .as_ref()
                        .expect("remote ephemeral");
                    let ss = Self::diffie_hellman(sec, remote_pub);
                    self.symmetric.mix_key(&ss);
                }
                NoiseToken::EphemeralStatic => {
                    let ss = if self.is_initiator {
                        let sec = self
                            .local_ephemeral_secret
                            .as_ref()
                            .expect("local ephemeral");
                        let remote_pub = self.remote_static_public.as_ref().expect("remote static");
                        Self::diffie_hellman(sec, remote_pub)
                    } else {
                        let remote_pub = self
                            .remote_ephemeral_public
                            .as_ref()
                            .expect("remote ephemeral");
                        Self::diffie_hellman(&self.local_static_secret, remote_pub)
                    };
                    self.symmetric.mix_key(&ss);
                }
                NoiseToken::StaticEphemeral => {
                    let ss = if self.is_initiator {
                        let remote_pub = self
                            .remote_ephemeral_public
                            .as_ref()
                            .expect("remote ephemeral");
                        Self::diffie_hellman(&self.local_static_secret, remote_pub)
                    } else {
                        let sec = self
                            .local_ephemeral_secret
                            .as_ref()
                            .expect("local ephemeral");
                        let remote_pub = self.remote_static_public.as_ref().expect("remote static");
                        Self::diffie_hellman(sec, remote_pub)
                    };
                    self.symmetric.mix_key(&ss);
                }
                NoiseToken::StaticStatic => {
                    let remote_pub = self.remote_static_public.as_ref().expect("remote static");
                    let ss = Self::diffie_hellman(&self.local_static_secret, remote_pub);
                    self.symmetric.mix_key(&ss);
                }
                NoiseToken::PresharedKey => {
                    let psk = self.preshared_key.expect("PSK required");
                    self.symmetric.mix_key_and_hash(&psk);
                }
            }
        }

        let payload = self.symmetric.decrypt_and_hash(&message[offset..])?;
        self.message_index += 1;
        Ok(payload)
    }

    /// Split into transport ciphers (send, receive).
    pub fn split(self) -> Result<(NoiseCipherState, NoiseCipherState), WireError> {
        if !self.is_complete() {
            return Err(WireError::InvalidValue {
                field: "handshake_incomplete",
            });
        }
        let (first, second) = self.symmetric.split();
        let mut send = NoiseCipherState::new();
        let mut recv = NoiseCipherState::new();
        if self.is_initiator {
            send.initialize_key(first);
            recv.initialize_key(second);
        } else {
            send.initialize_key(second);
            recv.initialize_key(first);
        }
        Ok((send, recv))
    }
}

// --- Derivations -------------------------------------------------------------

/// Derive 16-byte session identifier from completed handshake hash.
pub fn derive_session_id(handshake_hash: &[u8; 32]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_ID_DOMAIN.as_bytes());
    hasher.update(handshake_hash);
    let digest = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

/// Derive 16-byte pair identifier from completed pairing handshake hash.
pub fn derive_pair_id(handshake_hash: &[u8; 32]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(PAIR_ID_DOMAIN.as_bytes());
    hasher.update(handshake_hash);
    let digest = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

/// Derive 16-byte rendezvous token from completed pairing handshake hash.
pub fn derive_rendezvous_token(handshake_hash: &[u8; 32]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(RENDEZVOUS_DOMAIN.as_bytes());
    hasher.update(handshake_hash);
    let digest = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

/// Compute grants hash from a list of profile names.
pub fn derive_grants_hash(profiles: &[String]) -> Result<[u8; 32], WireError> {
    let mut unique: Vec<String> = profiles.to_vec();
    unique.sort();
    unique.dedup();
    let val = WireValue::Array(unique.into_iter().map(WireValue::Text).collect());
    let encoded = val.encode()?;
    Ok(Sha256::digest(&encoded).into())
}

/// Compute pairing prologue for Noise XXpsk3 handshake.
pub fn pairing_prologue(
    offer_hash: &[u8; 32],
    transport_profile: &str,
) -> Result<Vec<u8>, WireError> {
    let val = WireValue::Array(vec![
        WireValue::Text(PAIRING_PROLOGUE_DOMAIN.into()),
        WireValue::Array(vec![
            WireValue::Unsigned(WIRE_VERSION.0),
            WireValue::Unsigned(WIRE_VERSION.1),
        ]),
        WireValue::Text(PAIRING_SUITE.into()),
        WireValue::Bytes(offer_hash.to_vec()),
        WireValue::Text(transport_profile.into()),
    ]);
    val.encode()
}

/// Compute session prologue for Noise KK handshake.
pub fn session_prologue(
    pair_id: &[u8; 16],
    grants_hash: &[u8; 32],
    transport_profile: &str,
) -> Result<Vec<u8>, WireError> {
    let val = WireValue::Array(vec![
        WireValue::Text(SESSION_PROLOGUE_DOMAIN.into()),
        WireValue::Array(vec![
            WireValue::Unsigned(WIRE_VERSION.0),
            WireValue::Unsigned(WIRE_VERSION.1),
        ]),
        WireValue::Text(SESSION_SUITE.into()),
        WireValue::Bytes(pair_id.to_vec()),
        WireValue::Bytes(grants_hash.to_vec()),
        WireValue::Text(transport_profile.into()),
    ]);
    val.encode()
}

/// Compute request hash binding for an operation request.
pub fn derive_request_hash(
    session_id: &[u8; 16],
    operation_id: &[u8; 16],
    profile: &str,
    action: &str,
    context: &BTreeMap<String, WireValue>,
    payload: &BTreeMap<String, WireValue>,
) -> Result<[u8; 32], WireError> {
    let val = WireValue::Array(vec![
        WireValue::Text(REQUEST_DOMAIN.into()),
        WireValue::Bytes(session_id.to_vec()),
        WireValue::Bytes(operation_id.to_vec()),
        WireValue::Text(profile.into()),
        WireValue::Text(action.into()),
        WireValue::Map(context.clone()),
        WireValue::Map(payload.clone()),
    ]);
    let encoded = val.encode()?;
    Ok(Sha256::digest(&encoded).into())
}
