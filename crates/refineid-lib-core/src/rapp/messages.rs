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

//! High-level typed RAPP data structures, pairing offers, pair records, and card operations.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use super::crypto::{PAIRING_SUITE, WIRE_VERSION};
use super::wire::{WireError, WireValue, decode_deterministic_cbor};
use crate::base64::{decode_url_unpadded, encode_url_unpadded};

/// Scheme prefix carried by the scanned QR URI.
pub const OFFER_URI_PREFIX: &str = "rapp:";
/// Scheme name repeated inside the encoded offer.
pub const OFFER_SCHEME_NAME: &str = "rapp";

/// Maximum size of an encoded pairing offer (in bytes) before QR encoding.
pub const MAX_OFFER_SIZE: usize = 1024;
/// Maximum TTL in milliseconds for an offer (3 minutes).
pub const MAX_OFFER_TTL_MS: u64 = 180_000;
/// Stored pair record format version.
pub const PAIR_RECORD_FORMAT_VERSION: u64 = 2;

/// Standard status profile name (`fi.refineid.status.v1`).
pub const PROFILE_STATUS: &str = "fi.refineid.status.v1";
/// Standard client authentication profile name (`fi.refineid.auth.v1`).
pub const PROFILE_AUTH: &str = "fi.refineid.auth.v1";
/// Standard document signature profile name (`fi.refineid.sign.v1`).
pub const PROFILE_SIGN: &str = "fi.refineid.sign.v1";

/// Standard stream transport profile name.
pub const TRANSPORT_STREAM: &str = "fi.refineid.stream.v1";
/// Standard BLE transport profile name.
pub const TRANSPORT_BLE: &str = "fi.refineid.ble.v1";

/// Transport candidate in a pairing offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportCandidate {
    /// Transport profile URI (e.g. `fi.refineid.stream.v1`).
    pub profile: String,
    /// Unique candidate ID within the offer.
    pub candidate_id: String,
    /// Profile-specific connection parameters.
    pub parameters: BTreeMap<String, WireValue>,
}

impl TransportCandidate {
    /// Create a new stream candidate with given endpoints.
    pub fn new_stream(candidate_id: &str, endpoints: &[String]) -> Self {
        let mut params = BTreeMap::new();
        params.insert(
            "endpoints".into(),
            WireValue::Array(endpoints.iter().cloned().map(WireValue::Text).collect()),
        );
        Self {
            profile: TRANSPORT_STREAM.into(),
            candidate_id: candidate_id.into(),
            parameters: params,
        }
    }

    /// Create a new BLE transport candidate.
    pub fn new_ble(candidate_id: &str, service_uuid: &str, psm: Option<u16>) -> Self {
        let mut params = BTreeMap::new();
        params.insert("service_uuid".into(), WireValue::Text(service_uuid.into()));
        if let Some(p) = psm {
            params.insert("psm".into(), WireValue::Unsigned(p as u64));
        }
        Self {
            profile: TRANSPORT_BLE.into(),
            candidate_id: candidate_id.into(),
            parameters: params,
        }
    }

    /// Encode as deterministic CBOR WireValue.
    pub fn to_wire_value(&self) -> WireValue {
        let mut map = BTreeMap::new();
        map.insert("profile".into(), WireValue::Text(self.profile.clone()));
        map.insert(
            "candidate_id".into(),
            WireValue::Text(self.candidate_id.clone()),
        );
        map.insert("parameters".into(), WireValue::Map(self.parameters.clone()));
        WireValue::Map(map)
    }

    /// Decode from deterministic CBOR WireValue.
    pub fn from_wire_value(val: &WireValue) -> Result<Self, WireError> {
        let map = match val {
            WireValue::Map(m) => m,
            _ => {
                return Err(WireError::WrongType {
                    field: "transport_candidate",
                });
            }
        };
        let profile = match map.get("profile") {
            Some(WireValue::Text(s)) => s.clone(),
            _ => return Err(WireError::MissingField { field: "profile" }),
        };
        let candidate_id = match map.get("candidate_id") {
            Some(WireValue::Text(s)) => s.clone(),
            _ => {
                return Err(WireError::MissingField {
                    field: "candidate_id",
                });
            }
        };
        let parameters = match map.get("parameters") {
            Some(WireValue::Map(m)) => m.clone(),
            _ => {
                return Err(WireError::MissingField {
                    field: "parameters",
                });
            }
        };
        Ok(Self {
            profile,
            candidate_id,
            parameters,
        })
    }
}

/// A high-entropy pairing offer rendered into a QR code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingOffer {
    /// Unique 32-byte identifier for this offer.
    pub offer_id: [u8; 32],
    /// 32-byte pre-shared secret (PSK) for Noise_XXpsk3.
    pub pairing_secret: [u8; 32],
    /// Supported cryptographic cipher suites.
    pub suites: Vec<String>,
    /// Profiles requested by the requester.
    pub profiles: Vec<String>,
    /// Candidate transport endpoints.
    pub transports: Vec<TransportCandidate>,
    /// Time-to-live in milliseconds.
    pub offer_ttl_ms: u64,
}

impl PairingOffer {
    /// Generate a fresh random pairing offer for the given transport candidates.
    pub fn generate(transports: Vec<TransportCandidate>) -> Self {
        let mut offer_id = [0u8; 32];
        let mut pairing_secret = [0u8; 32];
        getrandom::fill(&mut offer_id).expect("CSPRNG");
        getrandom::fill(&mut pairing_secret).expect("CSPRNG");

        Self {
            offer_id,
            pairing_secret,
            suites: vec![PAIRING_SUITE.into()],
            profiles: vec![
                PROFILE_STATUS.into(),
                PROFILE_AUTH.into(),
                PROFILE_SIGN.into(),
            ],
            transports,
            offer_ttl_ms: MAX_OFFER_TTL_MS,
        }
    }

    fn as_wire_map(&self, include_secret: bool) -> BTreeMap<String, WireValue> {
        let mut map = BTreeMap::new();
        map.insert("scheme".into(), WireValue::Text(OFFER_SCHEME_NAME.into()));
        map.insert(
            "version".into(),
            WireValue::Array(vec![
                WireValue::Unsigned(WIRE_VERSION.0),
                WireValue::Unsigned(WIRE_VERSION.1),
            ]),
        );
        map.insert("offer_id".into(), WireValue::Bytes(self.offer_id.to_vec()));
        if include_secret {
            map.insert(
                "pairing_secret".into(),
                WireValue::Bytes(self.pairing_secret.to_vec()),
            );
        }
        map.insert(
            "suites".into(),
            WireValue::Array(self.suites.iter().cloned().map(WireValue::Text).collect()),
        );
        map.insert(
            "profiles".into(),
            WireValue::Array(self.profiles.iter().cloned().map(WireValue::Text).collect()),
        );
        map.insert(
            "transports".into(),
            WireValue::Array(
                self.transports
                    .iter()
                    .map(TransportCandidate::to_wire_value)
                    .collect(),
            ),
        );
        map.insert(
            "offer_ttl_ms".into(),
            WireValue::Unsigned(self.offer_ttl_ms),
        );
        map
    }

    /// Compute `offer_hash` (SHA-256 of deterministic CBOR map with `pairing_secret` removed).
    pub fn offer_hash(&self) -> Result<[u8; 32], WireError> {
        let map = self.as_wire_map(false);
        let encoded = WireValue::Map(map).encode()?;
        Ok(Sha256::digest(&encoded).into())
    }

    /// Convert to `rapp:` URI string for QR code generation.
    pub fn to_uri(&self) -> Result<String, WireError> {
        let map = self.as_wire_map(true);
        let encoded = WireValue::Map(map).encode()?;
        if encoded.len() > MAX_OFFER_SIZE {
            return Err(WireError::OversizedPlaintext { got: encoded.len() });
        }
        let b64 = encode_url_unpadded(&encoded);
        Ok(format!("{OFFER_URI_PREFIX}{b64}"))
    }

    /// Parse and validate a `rapp:` URI from a scanned QR code.
    pub fn from_uri(uri: &str) -> Result<Self, WireError> {
        if !uri.starts_with(OFFER_URI_PREFIX) {
            return Err(WireError::InvalidValue {
                field: "uri_scheme",
            });
        }
        let b64 = &uri[OFFER_URI_PREFIX.len()..];
        let bytes =
            decode_url_unpadded(b64).map_err(|_| WireError::InvalidValue { field: "base64" })?;
        if bytes.len() > MAX_OFFER_SIZE {
            return Err(WireError::OversizedPlaintext { got: bytes.len() });
        }
        let val = decode_deterministic_cbor(&bytes)?;
        let mut map = match val {
            WireValue::Map(m) => m,
            _ => return Err(WireError::WrongType { field: "offer" }),
        };

        let offer_id_bytes = match map.remove("offer_id") {
            Some(WireValue::Bytes(b)) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            _ => return Err(WireError::MissingField { field: "offer_id" }),
        };

        let pairing_secret_bytes = match map.remove("pairing_secret") {
            Some(WireValue::Bytes(b)) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            _ => {
                return Err(WireError::MissingField {
                    field: "pairing_secret",
                });
            }
        };

        let suites = match map.remove("suites") {
            Some(WireValue::Array(arr)) => {
                let mut res = Vec::new();
                for it in arr {
                    match it {
                        WireValue::Text(s) => res.push(s),
                        _ => return Err(WireError::WrongType { field: "suites" }),
                    }
                }
                res
            }
            _ => return Err(WireError::MissingField { field: "suites" }),
        };

        let profiles = match map.remove("profiles") {
            Some(WireValue::Array(arr)) => {
                let mut res = Vec::new();
                for it in arr {
                    match it {
                        WireValue::Text(s) => res.push(s),
                        _ => return Err(WireError::WrongType { field: "profiles" }),
                    }
                }
                res
            }
            _ => return Err(WireError::MissingField { field: "profiles" }),
        };

        let transports = match map.remove("transports") {
            Some(WireValue::Array(arr)) => {
                let mut res = Vec::new();
                for it in arr {
                    res.push(TransportCandidate::from_wire_value(&it)?);
                }
                res
            }
            _ => {
                return Err(WireError::MissingField {
                    field: "transports",
                });
            }
        };

        let offer_ttl_ms = match map.remove("offer_ttl_ms") {
            Some(WireValue::Unsigned(u)) => u,
            _ => {
                return Err(WireError::MissingField {
                    field: "offer_ttl_ms",
                });
            }
        };

        Ok(Self {
            offer_id: offer_id_bytes,
            pairing_secret: pairing_secret_bytes,
            suites,
            profiles,
            transports,
            offer_ttl_ms,
        })
    }
}

/// Plaintext stream rendezvous preamble frame (`RAPP-stream-v1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRendezvous {
    /// Initial pairing rendezvous.
    Pairing,
    /// Reconnecting to an existing paired session with rendezvous token.
    Session {
        /// 16-byte token identifying the pairing.
        rendezvous_token: [u8; 16],
    },
}

impl StreamRendezvous {
    /// Domain tag for stream rendezvous frames.
    pub const DOMAIN: &str = "RAPP-stream-v1";

    /// Encode stream rendezvous preamble to deterministic CBOR.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let (purpose, token) = match self {
            Self::Pairing => ("pairing", Vec::new()),
            Self::Session { rendezvous_token } => ("session", rendezvous_token.to_vec()),
        };
        let val = WireValue::Array(vec![
            WireValue::Text(Self::DOMAIN.into()),
            WireValue::Text(purpose.into()),
            WireValue::Bytes(token),
        ]);
        val.encode()
    }

    /// Decode stream rendezvous preamble from deterministic CBOR.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let val = decode_deterministic_cbor(bytes)?;
        let arr = match val {
            WireValue::Array(a) if a.len() == 3 => a,
            _ => {
                return Err(WireError::WrongType {
                    field: "rendezvous",
                });
            }
        };
        match (&arr[0], &arr[1], &arr[2]) {
            (WireValue::Text(dom), WireValue::Text(purpose), WireValue::Bytes(token)) => {
                if dom != Self::DOMAIN {
                    return Err(WireError::InvalidValue { field: "domain" });
                }
                if purpose == "pairing" && token.is_empty() {
                    Ok(Self::Pairing)
                } else if purpose == "session" && token.len() == 16 {
                    let mut arr_token = [0u8; 16];
                    arr_token.copy_from_slice(token);
                    Ok(Self::Session {
                        rendezvous_token: arr_token,
                    })
                } else {
                    Err(WireError::InvalidValue {
                        field: "rendezvous_purpose",
                    })
                }
            }
            _ => Err(WireError::WrongType {
                field: "rendezvous",
            }),
        }
    }
}

/// A stored pairing relationship in the device vault (Format version 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairRecord {
    /// 16-byte unique identifier for this pairing.
    pub pair_id: [u8; 16],
    /// 16-byte rendezvous token for session reconnection.
    pub rendezvous_token: [u8; 16],
    /// Role performed by this node ("requester" or "proxy").
    pub role: String,
    /// 32-byte local static private key for Curve25519.
    pub local_static_private: [u8; 32],
    /// 32-byte local static public key.
    pub local_static_public: [u8; 32],
    /// 32-byte remote static public key.
    pub remote_static_public: [u8; 32],
    /// 32-byte hash over agreed granted profiles.
    pub grants_hash: [u8; 32],
    /// List of granted profile names.
    pub profiles: Vec<String>,
    /// Selected transport profile name.
    pub transport_profile: String,
    /// Selected candidate identifier.
    pub candidate_id: String,
    /// Stored transport parameters.
    pub transport_parameters: BTreeMap<String, WireValue>,
    /// Creation timestamp in milliseconds since UNIX epoch.
    pub created_at_ms: u64,
    /// User-friendly name of the paired remote device.
    pub display_name: Option<String>,
    /// Operating system platform of the remote device (e.g. "iOS", "Android").
    pub platform: Option<String>,
    /// Cached DER authentication certificate bytes if previously retrieved.
    pub cached_auth_cert: Option<Vec<u8>>,
}

impl PairRecord {
    /// Encode pair record to deterministic CBOR.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut map = BTreeMap::new();
        map.insert(
            "format_version".into(),
            WireValue::Unsigned(PAIR_RECORD_FORMAT_VERSION),
        );
        map.insert("pair_id".into(), WireValue::Bytes(self.pair_id.to_vec()));
        map.insert(
            "rendezvous_token".into(),
            WireValue::Bytes(self.rendezvous_token.to_vec()),
        );
        map.insert("role".into(), WireValue::Text(self.role.clone()));
        map.insert(
            "local_static_private".into(),
            WireValue::Bytes(self.local_static_private.to_vec()),
        );
        map.insert(
            "local_static_public".into(),
            WireValue::Bytes(self.local_static_public.to_vec()),
        );
        map.insert(
            "remote_static_public".into(),
            WireValue::Bytes(self.remote_static_public.to_vec()),
        );
        map.insert(
            "grants_hash".into(),
            WireValue::Bytes(self.grants_hash.to_vec()),
        );
        map.insert(
            "profiles".into(),
            WireValue::Array(self.profiles.iter().cloned().map(WireValue::Text).collect()),
        );
        map.insert(
            "transport_profile".into(),
            WireValue::Text(self.transport_profile.clone()),
        );
        map.insert(
            "candidate_id".into(),
            WireValue::Text(self.candidate_id.clone()),
        );
        map.insert(
            "transport_parameters".into(),
            WireValue::Map(self.transport_parameters.clone()),
        );
        map.insert(
            "created_at_ms".into(),
            WireValue::Unsigned(self.created_at_ms),
        );

        if let Some(ref name) = self.display_name {
            map.insert("display_name".into(), WireValue::Text(name.clone()));
        }
        if let Some(ref plat) = self.platform {
            map.insert("platform".into(), WireValue::Text(plat.clone()));
        }
        if let Some(ref cert) = self.cached_auth_cert {
            map.insert("cached_auth_cert".into(), WireValue::Bytes(cert.clone()));
        }

        WireValue::Map(map).encode()
    }

    /// Decode pair record from deterministic CBOR bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let val = decode_deterministic_cbor(bytes)?;
        let mut map = match val {
            WireValue::Map(m) => m,
            _ => {
                return Err(WireError::WrongType {
                    field: "pair_record",
                });
            }
        };

        let format_version = match map.remove("format_version") {
            Some(WireValue::Unsigned(v)) => v,
            _ => {
                return Err(WireError::MissingField {
                    field: "format_version",
                });
            }
        };
        if format_version != PAIR_RECORD_FORMAT_VERSION {
            return Err(WireError::UnsupportedVersion);
        }

        let pair_id = match map.remove("pair_id") {
            Some(WireValue::Bytes(b)) if b.len() == 16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&b);
                arr
            }
            _ => return Err(WireError::MissingField { field: "pair_id" }),
        };

        let rendezvous_token = match map.remove("rendezvous_token") {
            Some(WireValue::Bytes(b)) if b.len() == 16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&b);
                arr
            }
            _ => {
                return Err(WireError::MissingField {
                    field: "rendezvous_token",
                });
            }
        };

        let role = match map.remove("role") {
            Some(WireValue::Text(s)) => s,
            _ => return Err(WireError::MissingField { field: "role" }),
        };

        let local_static_private = match map.remove("local_static_private") {
            Some(WireValue::Bytes(b)) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            _ => {
                return Err(WireError::MissingField {
                    field: "local_static_private",
                });
            }
        };

        let local_static_public = match map.remove("local_static_public") {
            Some(WireValue::Bytes(b)) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            _ => {
                return Err(WireError::MissingField {
                    field: "local_static_public",
                });
            }
        };

        let remote_static_public = match map.remove("remote_static_public") {
            Some(WireValue::Bytes(b)) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            _ => {
                return Err(WireError::MissingField {
                    field: "remote_static_public",
                });
            }
        };

        let grants_hash = match map.remove("grants_hash") {
            Some(WireValue::Bytes(b)) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            _ => {
                return Err(WireError::MissingField {
                    field: "grants_hash",
                });
            }
        };

        let profiles = match map.remove("profiles") {
            Some(WireValue::Array(arr)) => {
                let mut res = Vec::new();
                for it in arr {
                    match it {
                        WireValue::Text(s) => res.push(s),
                        _ => return Err(WireError::WrongType { field: "profiles" }),
                    }
                }
                res
            }
            _ => return Err(WireError::MissingField { field: "profiles" }),
        };

        let transport_profile = match map.remove("transport_profile") {
            Some(WireValue::Text(s)) => s,
            _ => {
                return Err(WireError::MissingField {
                    field: "transport_profile",
                });
            }
        };

        let candidate_id = match map.remove("candidate_id") {
            Some(WireValue::Text(s)) => s,
            _ => {
                return Err(WireError::MissingField {
                    field: "candidate_id",
                });
            }
        };

        let transport_parameters = match map.remove("transport_parameters") {
            Some(WireValue::Map(m)) => m,
            _ => {
                return Err(WireError::MissingField {
                    field: "transport_parameters",
                });
            }
        };

        let created_at_ms = match map.remove("created_at_ms") {
            Some(WireValue::Unsigned(u)) => u,
            _ => {
                return Err(WireError::MissingField {
                    field: "created_at_ms",
                });
            }
        };

        let display_name = match map.remove("display_name") {
            Some(WireValue::Text(s)) => Some(s),
            _ => None,
        };

        let platform = match map.remove("platform") {
            Some(WireValue::Text(s)) => Some(s),
            _ => None,
        };

        let cached_auth_cert = match map.remove("cached_auth_cert") {
            Some(WireValue::Bytes(b)) => Some(b),
            _ => None,
        };

        Ok(Self {
            pair_id,
            rendezvous_token,
            role,
            local_static_private,
            local_static_public,
            remote_static_public,
            grants_hash,
            profiles,
            transport_profile,
            candidate_id,
            transport_parameters,
            created_at_ms,
            display_name,
            platform,
            cached_auth_cert,
        })
    }
}

/// Status of an operation execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultStatus {
    /// Operation completed successfully.
    Completed,
    /// User declined the consent prompt on the proxy device.
    UserDenied,
    /// Credential (e.g. PIN) verification failed on card.
    CredentialRejected,
    /// State of operation is ambiguous due to communication loss during commit.
    Ambiguous,
    /// Card is not present or reader disconnected.
    CardUnavailable,
    /// Internal failure occurred on proxy device.
    InternalFailure,
}

impl ResultStatus {
    /// Convert status to specification string.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::UserDenied => "user_denied",
            Self::CredentialRejected => "credential_rejected",
            Self::Ambiguous => "ambiguous",
            Self::CardUnavailable => "card_unavailable",
            Self::InternalFailure => "internal_failure",
        }
    }

    /// Parse status from specification string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "completed" => Some(Self::Completed),
            "user_denied" => Some(Self::UserDenied),
            "credential_rejected" => Some(Self::CredentialRejected),
            "ambiguous" => Some(Self::Ambiguous),
            "card_unavailable" => Some(Self::CardUnavailable),
            "internal_failure" => Some(Self::InternalFailure),
            _ => None,
        }
    }
}

/// High-level card operation requested from the remote proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CardOperation {
    /// Inspect card status, retry counters, and factory PIN state.
    InspectCard,
    /// Read cardholder name and identity code (HETU).
    ReadIdentity,
    /// Read authentication or signing X.509 certificate.
    ReadCertificate {
        /// Certificate kind ("authentication" or "signing").
        kind: String,
    },
    /// Perform client TLS authentication hash signing.
    BrowserAuthenticate {
        /// Web origin requesting authentication.
        origin: String,
        /// Requested key profile (e.g. "eccP384").
        key_profile: String,
        /// Signature algorithm (e.g. "ecdsaSha384").
        algorithm: String,
        /// Hash digest to sign.
        digest: Vec<u8>,
    },
    /// Sign document digest with qualified signature PIN.
    SignDocument {
        /// Display name of the document being signed.
        document_name: String,
        /// Requested key profile (e.g. "eccP384").
        key_profile: String,
        /// Signature algorithm (e.g. "ecdsaSha384").
        algorithm: String,
        /// Hash digest to sign.
        digest: Vec<u8>,
    },
}

impl CardOperation {
    /// Profile owning this operation.
    pub fn required_profile(&self) -> &'static str {
        match self {
            Self::InspectCard | Self::ReadIdentity => PROFILE_STATUS,
            Self::ReadCertificate { kind } if kind == "signing" => PROFILE_SIGN,
            Self::ReadCertificate { .. } | Self::BrowserAuthenticate { .. } => PROFILE_AUTH,
            Self::SignDocument { .. } => PROFILE_SIGN,
        }
    }

    /// Registered action name in wire protocol.
    pub fn action_name(&self) -> &'static str {
        match self {
            Self::InspectCard => "inspect_card",
            Self::ReadIdentity => "read_identity",
            Self::ReadCertificate { .. } => "read_certificate",
            Self::BrowserAuthenticate { .. } => "browser_authenticate",
            Self::SignDocument { .. } => "sign_document",
        }
    }

    /// Whether this operation requires holder consent and two-phase commit.
    pub fn is_consequential(&self) -> bool {
        matches!(
            self,
            Self::BrowserAuthenticate { .. } | Self::SignDocument { .. }
        )
    }

    /// Context map presented for holder consent.
    pub fn context_map(&self) -> BTreeMap<String, WireValue> {
        let mut map = BTreeMap::new();
        match self {
            Self::BrowserAuthenticate { origin, .. } => {
                map.insert("origin".into(), WireValue::Text(origin.clone()));
            }
            Self::SignDocument { document_name, .. } => {
                map.insert(
                    "document_name".into(),
                    WireValue::Text(document_name.clone()),
                );
            }
            _ => {}
        }
        map
    }

    /// Payload map carrying operation parameters.
    pub fn payload_map(&self) -> BTreeMap<String, WireValue> {
        let mut map = BTreeMap::new();
        match self {
            Self::ReadCertificate { kind } => {
                map.insert("kind".into(), WireValue::Text(kind.clone()));
            }
            Self::BrowserAuthenticate {
                key_profile,
                algorithm,
                digest,
                ..
            }
            | Self::SignDocument {
                key_profile,
                algorithm,
                digest,
                ..
            } => {
                map.insert("key_profile".into(), WireValue::Text(key_profile.clone()));
                map.insert("algorithm".into(), WireValue::Text(algorithm.clone()));
                map.insert("digest".into(), WireValue::Bytes(digest.clone()));
            }
            _ => {}
        }
        map
    }
}

/// Typed card inspection report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CardInspection {
    /// Whether PIN1 is still set to factory default.
    pub pin1_factory: bool,
    /// Whether PIN2 is still set to factory default.
    pub pin2_factory: bool,
    /// Remaining retry attempts for PIN1.
    pub pin1_attempts: Option<u8>,
    /// Remaining retry attempts for PIN2.
    pub pin2_attempts: Option<u8>,
    /// Remaining retry attempts for PUK.
    pub puk_attempts: Option<u8>,
}

/// Typed output of a completed card operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CardOperationResult {
    /// Inspection counters and factory PIN states.
    Inspection(CardInspection),
    /// Holder identity information.
    Identity {
        /// Holder formatted display name.
        display_name: String,
        /// Finnish Personal Identity Code (HETU).
        person_id: String,
    },
    /// Retrieved X.509 certificate.
    Certificate {
        /// DER-encoded certificate octets.
        der_bytes: Vec<u8>,
        /// Optional physical card serial number.
        card_serial: Option<String>,
    },
    /// Cryptographic digital signature.
    Signature {
        /// Raw or formatted signature bytes.
        signature_bytes: Vec<u8>,
    },
}

impl CardOperationResult {
    /// Parse typed result from decoded wire body map.
    pub fn from_wire_body(mut map: BTreeMap<String, WireValue>) -> Result<Self, WireError> {
        let typ = match map.remove("type") {
            Some(WireValue::Text(s)) => s,
            _ => return Err(WireError::MissingField { field: "type" }),
        };
        match typ.as_str() {
            "inspection" => {
                let pin1_factory = match map.remove("pin1_factory") {
                    Some(WireValue::Boolean(b)) => b,
                    _ => false,
                };
                let pin2_factory = match map.remove("pin2_factory") {
                    Some(WireValue::Boolean(b)) => b,
                    _ => false,
                };
                let pin1_attempts = match map.remove("pin1_attempts") {
                    Some(WireValue::Unsigned(u)) => Some(u as u8),
                    _ => None,
                };
                let pin2_attempts = match map.remove("pin2_attempts") {
                    Some(WireValue::Unsigned(u)) => Some(u as u8),
                    _ => None,
                };
                let puk_attempts = match map.remove("puk_attempts") {
                    Some(WireValue::Unsigned(u)) => Some(u as u8),
                    _ => None,
                };
                Ok(Self::Inspection(CardInspection {
                    pin1_factory,
                    pin2_factory,
                    pin1_attempts,
                    pin2_attempts,
                    puk_attempts,
                }))
            }
            "identity" => {
                let display_name = match map.remove("display_name") {
                    Some(WireValue::Text(s)) => s,
                    _ => {
                        return Err(WireError::MissingField {
                            field: "display_name",
                        });
                    }
                };
                let person_id = match map.remove("person_id") {
                    Some(WireValue::Text(s)) => s,
                    _ => return Err(WireError::MissingField { field: "person_id" }),
                };
                Ok(Self::Identity {
                    display_name,
                    person_id,
                })
            }
            "certificate" => {
                let der_bytes = match map.remove("der") {
                    Some(WireValue::Bytes(b)) => b,
                    _ => return Err(WireError::MissingField { field: "der" }),
                };
                let card_serial = match map.remove("card_serial") {
                    Some(WireValue::Text(s)) => Some(s),
                    _ => None,
                };
                Ok(Self::Certificate {
                    der_bytes,
                    card_serial,
                })
            }
            "signature" => {
                let signature_bytes = match map.remove("signature") {
                    Some(WireValue::Bytes(b)) => b,
                    _ => return Err(WireError::MissingField { field: "signature" }),
                };
                Ok(Self::Signature { signature_bytes })
            }
            _ => Err(WireError::InvalidValue {
                field: "result_type",
            }),
        }
    }
}
