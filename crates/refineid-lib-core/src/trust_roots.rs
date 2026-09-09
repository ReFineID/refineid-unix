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

//! In-memory cache and accessors for FINEID root and intermediate CA certificates.
//!
//! Rather than hardcoding CA certificates across different applications and
//! platforms, certificates can be fetched directly from the smart card
//! (`EF.4334` for Root CA, `EF.4336` for Intermediate CA) or distributed over
//! the RAPP protocol when an application starts.
//!
//! Aggressive in-memory caching is implemented using `OnceLock<Box<RootCertificates>>`
//! to ensure thread safety and instant subsequent lookups across all platforms.

use std::sync::OnceLock;

use crate::crypto::digest::Sha256;
use crate::pkcs15::{CertSlot, Pkcs15Ops};
use crate::transport::CardTransport;

/// Well-known pinned DVV Gov. Root CA - G3 RSA SHA-256 fingerprint.
pub const PINNED_DVV_G3_RSA_SHA256: Sha256 = Sha256::from_bytes([
    0xD3, 0xED, 0x3F, 0xC4, 0x0A, 0xD2, 0x6B, 0x52, 0xE0, 0x01, 0xE1, 0xE1, 0x8F, 0x4B, 0x94, 0x49,
    0x52, 0x9D, 0xEB, 0x75, 0xA8, 0x1D, 0x5E, 0xB6, 0x80, 0xD7, 0xB6, 0x2D, 0xB2, 0x3B, 0xA9, 0x6D,
]);

/// Well-known pinned DVV Gov. Root CA - G3 ECC SHA-256 fingerprint.
pub const PINNED_DVV_G3_ECC_SHA256: Sha256 = Sha256::from_bytes([
    0x55, 0x46, 0xA5, 0x25, 0x04, 0xFB, 0xA7, 0x4F, 0x61, 0xFF, 0xD4, 0x89, 0x00, 0x67, 0x52, 0x9A,
    0xDE, 0x3B, 0x9C, 0x9D, 0x07, 0xE5, 0x02, 0x59, 0x28, 0x31, 0xCC, 0xDA, 0x9B, 0x36, 0x9F, 0xD3,
]);

/// Global in-memory dynamic root certificate cache.
static ROOT_CERTIFICATES: OnceLock<Box<RootCertificates>> = OnceLock::new();

/// Cached root and intermediate CA certificates.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RootCertificates {
    /// On-card issuing root CA certificate (`EF.4334`) in DER format.
    pub root_ca: Option<Vec<u8>>,
    /// On-card issuing intermediate CA certificate (`EF.4336`) in DER format.
    pub intermediate_ca: Option<Vec<u8>>,
    /// Additional CA certificates if any.
    pub extra_cas: Vec<Vec<u8>>,
}

impl RootCertificates {
    /// Construct a new collection of root and intermediate CA certificates.
    #[must_use]
    pub const fn new(root_ca: Option<Vec<u8>>, intermediate_ca: Option<Vec<u8>>) -> Self {
        Self {
            root_ca,
            intermediate_ca,
            extra_cas: Vec::new(),
        }
    }

    /// Add extra CA certificates to this collection.
    #[must_use]
    pub fn with_extra_cas(mut self, extra_cas: Vec<Vec<u8>>) -> Self {
        self.extra_cas = extra_cas;
        self
    }

    /// Returns true if no certificates are present in this collection.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.root_ca.is_none() && self.intermediate_ca.is_none() && self.extra_cas.is_empty()
    }

    /// Returns slices of all available CA certificate DER bytes.
    #[must_use]
    pub fn certs(&self) -> Vec<&[u8]> {
        let mut list = Vec::new();
        if let Some(ref r) = self.root_ca {
            list.push(r.as_slice());
        }
        if let Some(ref i) = self.intermediate_ca {
            list.push(i.as_slice());
        }
        for extra in &self.extra_cas {
            list.push(extra.as_slice());
        }
        list
    }

    /// Returns true if any certificate in this collection matches the SHA-256 fingerprint.
    #[must_use]
    pub fn contains_fingerprint(&self, fingerprint: Sha256) -> bool {
        self.certs()
            .iter()
            .any(|der| Sha256::of(der) == fingerprint)
    }

    /// Encodes all certificates in this collection into a PKCS#7 (CMS)
    /// certs-only `SignedData` structure.
    #[must_use]
    pub fn to_pkcs7_bundle(&self) -> Vec<u8> {
        let certs = self.certs();
        build_pkcs7_certs_bundle(&certs)
    }
}

/// Stores CA certificates into the global in-memory cache.
///
/// # Errors
///
/// Returns `Err("already initialized")` if the cache was previously set.
pub fn set_root_certificates(roots: RootCertificates) -> Result<(), &'static str> {
    ROOT_CERTIFICATES
        .set(Box::new(roots))
        .map_err(|_| "already initialized")
}

/// Returns a reference to the active cached root certificates, if initialized.
#[must_use]
pub fn active_root_certificates() -> Option<&'static RootCertificates> {
    ROOT_CERTIFICATES.get().map(|b| &**b)
}

/// Checks whether a SHA-256 fingerprint matches a trusted root CA.
///
/// Checks the dynamic in-memory cache first, falling back to the known
/// pinned DVV G3 roots if the cache is empty or does not contain the cert.
#[must_use]
pub fn is_trusted_root(fingerprint: Sha256) -> bool {
    if let Some(cached) = active_root_certificates()
        && cached.contains_fingerprint(fingerprint)
    {
        return true;
    }
    fingerprint == PINNED_DVV_G3_RSA_SHA256 || fingerprint == PINNED_DVV_G3_ECC_SHA256
}

/// Reads the root CA and intermediate CA from the card if available, and
/// populates the global in-memory cache.
///
/// If the cache is already populated, returns the cached instance immediately.
pub fn fetch_and_cache_from_card<T: CardTransport>(
    transport: &mut T,
) -> Option<&'static RootCertificates> {
    if let Some(cached) = active_root_certificates() {
        return Some(cached);
    }

    let root_ca = transport
        .read_certificate(CertSlot::RootCa)
        .ok()
        .map(crate::cert_state::CertDer::into_bytes);
    let intermediate_ca = transport
        .read_certificate(CertSlot::IssuingCaEcc)
        .ok()
        .map(crate::cert_state::CertDer::into_bytes);

    if root_ca.is_some() || intermediate_ca.is_some() {
        let roots = RootCertificates::new(root_ca, intermediate_ca);
        let _ = set_root_certificates(roots);
    }

    active_root_certificates()
}

/// Encodes a sequence of X.509 DER certificates into a PKCS#7 (CMS)
/// certs-only `SignedData` structure.
#[must_use]
pub fn build_pkcs7_certs_bundle(certs: &[&[u8]]) -> Vec<u8> {
    let mut certificates_bytes = Vec::new();
    for cert in certs {
        certificates_bytes.extend_from_slice(cert);
    }

    let certificates_tagged = encode_tlv(0xA0, &certificates_bytes);

    let signed_data_version = vec![0x02, 0x01, 0x01];
    let digest_algorithms_empty_set = vec![0x31, 0x00];
    let content_info_pkcs7_data = vec![
        0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
    ];
    let signer_infos_empty_set = vec![0x31, 0x00];

    let mut signed_data_content = Vec::new();
    signed_data_content.extend_from_slice(&signed_data_version);
    signed_data_content.extend_from_slice(&digest_algorithms_empty_set);
    signed_data_content.extend_from_slice(&content_info_pkcs7_data);
    signed_data_content.extend_from_slice(&certificates_tagged);
    signed_data_content.extend_from_slice(&signer_infos_empty_set);

    let signed_data_seq = encode_tlv(0x30, &signed_data_content);
    let signed_data_oid = vec![
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
    ];
    let content_explicit = encode_tlv(0xA0, &signed_data_seq);

    let mut content_info_content = Vec::new();
    content_info_content.extend_from_slice(&signed_data_oid);
    content_info_content.extend_from_slice(&content_explicit);

    encode_tlv(0x30, &content_info_content)
}

fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(tag);
    let len = value.len();
    if let Ok(l) = u8::try_from(len) {
        if l >= 0x80 {
            out.push(0x81);
        }
        out.push(l);
    } else if let Ok(l) = u16::try_from(len) {
        out.push(0x82);
        out.extend_from_slice(&l.to_be_bytes());
    } else if let Ok(l) = u32::try_from(len) {
        if l <= 0x00FF_FFFF {
            out.push(0x83);
            out.extend_from_slice(&l.to_be_bytes()[1..]);
        } else {
            out.push(0x84);
            out.extend_from_slice(&l.to_be_bytes());
        }
    }
    out.extend_from_slice(value);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_certificates_empty() {
        let roots = RootCertificates::default();
        assert!(roots.is_empty());
        assert!(roots.certs().is_empty());
    }

    #[test]
    fn test_root_certificates_with_certs() {
        let cert1 = vec![0x30, 0x05, 0x02, 0x01, 0x01, 0x00, 0x00];
        let cert2 = vec![0x30, 0x05, 0x02, 0x01, 0x02, 0x00, 0x00];
        let roots = RootCertificates::new(Some(cert1.clone()), Some(cert2.clone()));
        assert!(!roots.is_empty());
        assert_eq!(roots.certs().len(), 2);
        assert!(roots.contains_fingerprint(Sha256::of(&cert1)));
        assert!(roots.contains_fingerprint(Sha256::of(&cert2)));
    }

    #[test]
    fn test_build_pkcs7_certs_bundle() {
        let cert = vec![0x30, 0x03, 0x02, 0x01, 0x01];
        let bundle = build_pkcs7_certs_bundle(&[&cert]);
        assert_eq!(bundle[0], 0x30);
        assert!(bundle.windows(cert.len()).any(|w| w == cert.as_slice()));
    }

    #[test]
    fn test_is_trusted_root_fallback() {
        assert!(is_trusted_root(PINNED_DVV_G3_RSA_SHA256));
        assert!(is_trusted_root(PINNED_DVV_G3_ECC_SHA256));
        assert!(!is_trusted_root(Sha256::from_bytes([0u8; 32])));
    }
}
