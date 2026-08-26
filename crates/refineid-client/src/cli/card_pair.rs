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

//! `refineid pair`, `refineid pairs`, and `refineid unpair` CLI commands.

use alloc::string::String;
use alloc::vec::Vec;
use std::net::{IpAddr, Ipv4Addr, TcpListener, UdpSocket};
use std::process::ExitCode;

use refineid_lib_core::hex::Hex;
use refineid_lib_core::rapp::{
    CardOperation, CardOperationResult, PairOfferContext, PairRecord, PairingOffer,
    RappDeviceVault, TRANSPORT_STREAM, TransportCandidate, execute_operation_with_pair,
    pair_requester_over_stream,
};

use super::ArgParseError;
use super::argv::RemainingArgv;
use super::verb::VerbTag;

/// Default TCP port for RAPP local stream pairing.
pub const DEFAULT_PAIR_PORT: u16 = 52424;

/// Arguments for `refineid pair`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairArgs {
    /// Port to listen on for stream pairing.
    pub port: u16,
}

impl PairArgs {
    /// Parse arguments for `refineid pair`.
    ///
    /// # Errors
    /// Returns [`ArgParseError`] on invalid flag values or unexpected flags.
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let mut port = DEFAULT_PAIR_PORT;
        let tokens = argv.into_vec();
        let mut iter = tokens.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--port" | "-p" => {
                    let val = iter.next().ok_or(ArgParseError::MissingValue {
                        cmd: VerbTag::CardPair,
                        flag: "--port",
                    })?;
                    port = val.parse::<u16>().map_err(|_| ArgParseError::BadValue {
                        cmd: VerbTag::CardPair,
                        flag: "--port",
                        value: val.clone(),
                        reason: "must be a valid TCP port (1-65535)".into(),
                    })?;
                }
                other => {
                    return Err(ArgParseError::Unexpected {
                        cmd: VerbTag::CardPair,
                        got: other.to_owned(),
                    });
                }
            }
        }
        Ok(Self { port })
    }

    /// Execute the pairing ceremony.
    #[must_use]
    pub fn run(self) -> ExitCode {
        // 1. Detect local IP addresses for candidate endpoints
        let local_ips = detect_local_ips();
        let endpoints: Vec<String> = local_ips
            .iter()
            .map(|ip| format!("{ip}:{}", self.port))
            .collect();

        if endpoints.is_empty() {
            eprintln!("Error: No network interfaces found for pairing.");
            return ExitCode::FAILURE;
        }

        let code = generate_random_pairing_code();
        let candidate = TransportCandidate::new_stream("stream-0", &endpoints);
        let offer = PairingOffer::generate_numeric(code, vec![candidate.clone()]);

        let code_str = format!("{code:06}");
        let d = code_str.as_bytes();
        let formatted_code = format!(
            "{} {} {}   {} {} {}",
            char::from(d[0]),
            char::from(d[1]),
            char::from(d[2]),
            char::from(d[3]),
            char::from(d[4]),
            char::from(d[5]),
        );

        println!("======================================================");
        println!("              ReFineID Device Pairing                 ");
        println!("======================================================");
        println!();
        println!("  PAIRING CODE:  {formatted_code}");
        println!();
        println!("  1. Open ReFineID on your phone (iPhone / Android)");
        println!("  2. Select \"Pair New Device\"");
        println!("  3. Enter the 6-digit code shown above");
        println!();
        println!("Listening for connection on port {}...", self.port);
        println!("======================================================");

        let listener = match TcpListener::bind(("0.0.0.0", self.port)) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Error binding to port {}: {e}", self.port);
                return ExitCode::FAILURE;
            }
        };

        let (mut stream, peer_addr) = match listener.accept() {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("Error accepting connection: {e}");
                return ExitCode::FAILURE;
            }
        };

        println!("Connected from {peer_addr}! Executing Noise_XXpsk3 handshake...");

        let offer_ctx = PairOfferContext {
            offer,
            selected_transport: TRANSPORT_STREAM.into(),
            selected_candidate_id: "stream-0".into(),
            transport_parameters: candidate.parameters,
        };

        let mut pair_record =
            match pair_requester_over_stream(&mut stream, &offer_ctx, "ReFineID Linux", "Linux") {
                Ok(rec) => rec,
                Err(e) => {
                    eprintln!("Pairing failed: {e}");
                    return ExitCode::FAILURE;
                }
            };

        let dev_name = pair_record
            .display_name
            .clone()
            .unwrap_or_else(|| "Remote Device".into());
        let dev_plat = pair_record
            .platform
            .clone()
            .unwrap_or_else(|| "Mobile".into());
        println!("Pairing established with {dev_name} ({dev_plat})!");

        // 3. Cache initial authentication certificate
        println!("Retrieving authentication certificate for offline caching...");
        let cert_op = CardOperation::ReadCertificate {
            kind: "authentication".into(),
        };
        if let Ok(res) = execute_operation_with_pair(&pair_record, &cert_op)
            && let CardOperationResult::Certificate { der_bytes, .. } = res
        {
            pair_record.cached_auth_cert = Some(der_bytes);
            println!("Cached authentication certificate.");
        }

        // 4. Save to vault
        let vault = RappDeviceVault::new_default();
        if let Err(e) = vault.save_pair(&pair_record) {
            eprintln!("Error saving pairing to vault: {e}");
            return ExitCode::FAILURE;
        }

        println!();
        println!("Successfully paired!");
        println!("Pair ID: {}", Hex::encode(&pair_record.pair_id));
        println!("Granted profiles: {}", pair_record.profiles.join(", "));
        println!("Remote reader is now active for PKCS#11 (Firefox / suomi.fi) and CLI!");
        ExitCode::SUCCESS
    }
}

/// Arguments for `refineid pairs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairsArgs;

impl PairsArgs {
    /// Parse arguments for `refineid pairs`.
    ///
    /// # Errors
    /// Returns [`ArgParseError`] on unexpected arguments.
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let tokens = argv.into_vec();
        if let Some(arg) = tokens.into_iter().next() {
            return Err(ArgParseError::Unexpected {
                cmd: VerbTag::CardPairs,
                got: arg,
            });
        }
        Ok(Self)
    }

    /// List all paired devices.
    #[must_use]
    pub fn run(self) -> ExitCode {
        let vault = RappDeviceVault::new_default();
        let pairs = match vault.active_pairs() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Error reading vault: {e}");
                return ExitCode::FAILURE;
            }
        };

        if pairs.is_empty() {
            println!("No paired remote devices found.");
            println!("Run `refineid pair` to pair an iPhone or Android phone.");
            return ExitCode::SUCCESS;
        }

        println!("Paired Remote Card Readers ({}):", pairs.len());
        for (idx, pair) in pairs.iter().enumerate() {
            let name = pair.display_name.as_deref().unwrap_or("Unknown Device");
            let plat = pair.platform.as_deref().unwrap_or("Mobile");
            let pair_id_hex = Hex::encode(&pair.pair_id);
            println!("\n  [{}] {name} ({plat})", idx + 1);
            println!("      Pair ID:    {pair_id_hex}");
            println!("      Profiles:   {}", pair.profiles.join(", "));
            println!("      Transport:  {}", pair.transport_profile);
            println!(
                "      Cert cache: {}",
                if pair.cached_auth_cert.is_some() {
                    "Cached"
                } else {
                    "None"
                }
            );
        }
        ExitCode::SUCCESS
    }
}

/// Arguments for `refineid unpair`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpairArgs {
    /// Hex pair ID or prefix to remove.
    pub pair_id: String,
}

impl UnpairArgs {
    /// Parse arguments for `refineid unpair`.
    ///
    /// # Errors
    /// Returns [`ArgParseError`] on missing required argument or unexpected flags.
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let tokens = argv.into_vec();
        let mut iter = tokens.into_iter();
        let pair_id = iter.next().ok_or(ArgParseError::Required {
            cmd: VerbTag::CardUnpair,
            name: "PAIR_ID",
        })?;
        if let Some(extra) = iter.next() {
            return Err(ArgParseError::Unexpected {
                cmd: VerbTag::CardUnpair,
                got: extra,
            });
        }
        Ok(Self { pair_id })
    }

    /// Delete the pair record from disk.
    #[must_use]
    pub fn run(self) -> ExitCode {
        let vault = RappDeviceVault::new_default();
        let pairs = match vault.active_pairs() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Error reading vault: {e}");
                return ExitCode::FAILURE;
            }
        };

        let matching: Vec<&PairRecord> = pairs
            .iter()
            .filter(|p| Hex::encode(&p.pair_id).starts_with(&self.pair_id))
            .collect();

        if matching.is_empty() {
            eprintln!("No paired device matches ID '{}'.", self.pair_id);
            return ExitCode::FAILURE;
        }

        if matching.len() > 1 {
            eprintln!("Ambiguous ID '{}' matches multiple pairs.", self.pair_id);
            return ExitCode::FAILURE;
        }

        let target = matching[0];
        let id_hex = Hex::encode(&target.pair_id);
        if let Err(e) = vault.delete_pair(&target.pair_id) {
            eprintln!("Error deleting pair {id_hex}: {e}");
            return ExitCode::FAILURE;
        }

        println!("Unpaired and revoked {id_hex}.");
        ExitCode::SUCCESS
    }
}

fn detect_local_ips() -> Vec<IpAddr> {
    let mut ips = Vec::new();
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0")
        && socket.connect("8.8.8.8:80").is_ok()
        && let Ok(addr) = socket.local_addr()
    {
        ips.push(addr.ip());
    }
    if ips.is_empty() {
        ips.push(IpAddr::V4(Ipv4Addr::LOCALHOST));
    }
    ips
}

/// Generate a cryptographically random 6-digit numeric pairing code (000000..999999).
fn generate_random_pairing_code() -> u32 {
    let mut bytes = [0u8; 4];
    refineid_lib_core::rng::fill(&mut bytes).expect("CSPRNG");
    let val = u32::from_ne_bytes(bytes);
    val % 1_000_000
}
