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

//! Transport-level policy for the HTTPS client: CA-bundle
//! discovery.

use std::path::PathBuf;

/// Transport-policy bundle threaded into the HTTPS client.
/// One named place for what would otherwise be hard-coded;
/// adding a knob is a new field, not an API change.
#[derive(Debug, Clone)]
pub struct TransportPolicy {
    /// CA-bundle search order; first existing path wins.
    /// `REFINEID_CA_BUNDLE` overrides the whole list (operator
    /// escape hatch).
    pub ca_bundle_paths: Vec<PathBuf>,
}

impl TransportPolicy {
    /// Policy for one server-authenticated HTTPS request.
    #[must_use]
    pub fn client_auth() -> Self {
        Self {
            ca_bundle_paths: CaBundleProbe::paths(),
        }
    }
}

/// Unit-struct host for CA-bundle discovery (typing-discipline
/// Rule A: no top-level fns with borrowed parameters).
struct CaBundleProbe;

impl CaBundleProbe {
    /// CA-bundle search list: `SSL_CERT_FILE` / `SSL_CERT_DIR` env
    /// first when set, then the well-known distro bundle paths.
    fn paths() -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = Vec::new();
        if let Some(file) = std::env::var_os("SSL_CERT_FILE").map(PathBuf::from) {
            paths.push(file);
        }
        if let Some(dir) = std::env::var_os("SSL_CERT_DIR").map(PathBuf::from) {
            paths.push(dir);
        }
        for candidate in [
            "/etc/ssl/certs/ca-certificates.crt",     // Debian family, NixOS
            "/etc/pki/tls/certs/ca-bundle.crt",       // Fedora family
            "/etc/ssl/ca-bundle.pem",                 // openSUSE
            "/usr/local/share/certs/ca-root-nss.crt", // FreeBSD ca_root_nss
            "/etc/openssl/certs/ca-certificates.crt", // NetBSD mozilla-rootcerts
        ] {
            let path = PathBuf::from(candidate);
            if path.is_file() {
                paths.push(path);
            }
        }
        // The base-system default last.
        let default_bundle = PathBuf::from("/etc/ssl/cert.pem");
        if default_bundle.is_file() {
            paths.push(default_bundle);
        }
        paths
    }
}
