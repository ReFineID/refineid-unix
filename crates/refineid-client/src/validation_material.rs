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

//! Gather the certificates and revocation answers a level-LT signature
//! carries.
//!
//! [`refineid_lib_core::sign::validation`] defines the shape; this
//! fills it. Doing so means going to the network -- following the
//! authority information access extension up the chain, and asking each
//! issuer's responder whether the certificate below it is still good --
//! which is why it lives here and not in the core.
//!
//! # Why it is worth the round trips
//!
//! Everything collected here is available to a verifier today, over the
//! same URLs. The point is that it will not always be. A FINEID
//! certificate is valid for five years and the responder answering for
//! it is a service someone operates; when either goes, a signature
//! without this material becomes uncheckable. Collecting it at signing
//! time freezes the evidence while it is still there to freeze.

use refineid_lib_core::crl::{OwnedCrl, VerifiedCrl};
use refineid_lib_core::ocsp;
use refineid_lib_core::revocation::{self, RevocationStatus};
use refineid_lib_core::sign::validation::ValidationMaterial;
use refineid_lib_core::text::Uri;
use refineid_lib_core::x509::{
    Certificate, DateTime, Name, OwnedCert, PathExtensionProfile, extract_ca_issuers_urls,
    extract_crl_distribution_urls, extract_key_usage, extract_ocsp_urls, path_extension_profile,
};
use sha1::{Digest as Sha1Digest, Sha1};

use crate::{http, user_agent};

/// Cap on a fetched certificate or OCSP response.
const MAX_FETCH_BYTES: usize = 64 * 1024;

/// SHA-1 output width, for the OCSP `CertID` hashes.
const SHA1_OUTPUT_LEN: usize = 20;

/// How far a responder's clock may run ahead of ours before its answer
/// is treated as wrong rather than merely skewed.
///
/// `now` is read once before the walk, so every response is compared
/// against a reading that predates its own round trip. Five minutes is
/// the allowance validators conventionally give between two machines,
/// and is small enough that a genuinely misdated response still fails.
const MAX_CLOCK_SKEW: core::time::Duration = core::time::Duration::from_mins(5);

/// Maximum age of an OCSP answer whose responder omitted `nextUpdate`.
///
/// RFC 6960 leaves that bound to the relying party. Seven days keeps
/// pre-produced responses usable without turning an unbounded answer
/// into permanent archival evidence.
const MAX_OCSP_AGE_WITHOUT_NEXT_UPDATE: core::time::Duration =
    core::time::Duration::from_hours(168);

/// Cap on a fetched revocation list.
///
/// Larger than the certificate cap because a list is not one answer but
/// every answer the issuer has ever had to give. The timestamp
/// authorities' lists run to a few hundred bytes; a public CA's can run
/// to megabytes, and a signature is not improved by carrying one.
const MAX_CRL_BYTES: usize = 1024 * 1024;

/// How far up the chain to walk before giving up.
///
/// A real chain is three or four links. A longer one is a loop or a
/// misconfiguration, and following it forever helps nobody.
const MAX_DEPTH: usize = 8;

/// Maximum distinct endpoints accepted from one certificate extension.
///
/// AIA and CRL locations are certificate-controlled input. Three leaves
/// room for redundant responders without allowing one certificate to turn
/// a signing operation into an unbounded sequence of network timeouts.
const MAX_CERTIFICATE_ADDRESSES: usize = 3;

/// What went wrong while collecting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaterialError {
    /// No certificate chain was supplied, so no LT material could be
    /// authenticated.
    NoChain,
    /// A chain supplied no explicit policy-approved trust anchor.
    NoTrustAnchor,
    /// A certificate in the path was malformed, expired, premature,
    /// or otherwise unusable in its path role.
    Certificate(String),
    /// A child-to-issuer link did not satisfy X.509 name, signature,
    /// CA, key-usage, or time requirements.
    InvalidIssuer(String),
    /// Nothing above the signer could be fetched, so there is no chain
    /// to embed and no issuer to ask about revocation.
    NoIssuer(String),
    /// A certificate appeared twice in one path before an approved
    /// anchor was reached.
    ChainCycle,
    /// The bounded path length was exhausted before an approved anchor
    /// was reached.
    ChainTooDeep,
    /// The OS random source failed, so no nonce could be drawn.
    ///
    /// Fail closed rather than send a nonce-less request: a responder's
    /// answer to that is replayable, and an old "good" replayed into a
    /// long-term signature is exactly the thing LT exists to prevent.
    Rng(String),
    /// A responder was unreachable, or its answer did not hold up.
    Revocation(String),
    /// The responder says the signing certificate is revoked.
    ///
    /// Not a failure of the machinery: the answer arrived, was checked,
    /// and says the key should no longer be used. Embedding it would
    /// build a long-term signature whose own evidence refutes it.
    Revoked(String),
}

impl core::fmt::Display for MaterialError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoChain => f.write_str("no certificate chain supplied"),
            Self::NoTrustAnchor => f.write_str("no approved trust anchor supplied"),
            Self::Certificate(detail) => write!(f, "certificate: {detail}"),
            Self::InvalidIssuer(detail) => write!(f, "invalid issuer: {detail}"),
            Self::NoIssuer(detail) => write!(f, "no issuer certificate: {detail}"),
            Self::ChainCycle => f.write_str("certificate chain contains a cycle"),
            Self::ChainTooDeep => f.write_str("certificate chain exceeds the depth limit"),
            Self::Rng(detail) => write!(f, "no random nonce: {detail}"),
            Self::Revocation(detail) => write!(f, "revocation: {detail}"),
            Self::Revoked(detail) => write!(f, "certificate revoked: {detail}"),
        }
    }
}

impl core::error::Error for MaterialError {}

/// Whether an OCSP responder must echo the request nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoncePolicy {
    /// Require an exact nonce echo. Appropriate for the live card
    /// signer's certificate.
    RequireEcho,
    /// Accept a signed, current pre-produced answer that omits the
    /// nonce. Appropriate only when a caller's policy permits it.
    AllowMissingEcho,
}

/// One independently authenticated certificate path to preserve.
///
/// A signer path and every timestamp path get separate starts so each
/// can carry the policy anchors that authorize that exact role. In
/// particular, a public `WebPKI` root is not evidence that a timestamp
/// service is qualified.
#[derive(Debug, Clone, Copy)]
pub struct ChainStart<'a> {
    /// Certificate at which path construction begins.
    pub leaf_der: &'a [u8],
    /// Authenticated instant at which the path must be valid: signing
    /// time for the card signer, timestamp `genTime` for a TSA.
    pub reference_time: DateTime,
    /// Exact DER identities at which this path is allowed to stop.
    pub approved_anchor_ders: &'a [&'a [u8]],
    /// Freshness rule for the path's OCSP requests.
    pub nonce_policy: NoncePolicy,
    /// Whether the leaf itself belongs in the output store. The card
    /// signer is already carried by the primary signature; a TSA leaf
    /// may need to be copied into a format-specific validation store.
    pub include_leaf: bool,
    /// Whether the exact approved terminal certificate belongs in the
    /// output store. A card root can be omitted because it is already a
    /// local trust decision; a TSA path's anchor must travel with the
    /// path so an offline validator can reconstruct it.
    pub include_anchor: bool,
}

/// Collect authenticated LT material for every supplied chain.
///
/// Every non-anchor certificate must have a cryptographically verified,
/// current OCSP response or CRL. Every child-to-issuer signature is
/// verified, and a path ends only at a byte-identical anchor supplied
/// for that specific [`ChainStart`]. Partial material is never returned.
///
/// # Errors
/// [`MaterialError`] when any path, issuer, trust anchor, or revocation
/// answer cannot be authenticated. Failing is deliberate: a caller who
/// asked for LT must not silently receive T.
pub fn collect_chains(starts: &[ChainStart<'_>]) -> Result<ValidationMaterial, MaterialError> {
    collect_chains_with(
        starts,
        crate::card_check::now_date_time(),
        &HttpEvidenceProvider,
    )
}

/// Collect authenticated LT material while making already-embedded
/// certificates available to path construction.
///
/// RFC 3161 tokens commonly carry their issuer chain beside the signer.
/// Those certificates are candidates, not anchors: every one still has
/// to issue the child cryptographically and the walk still has to end at
/// an exact policy-approved anchor from [`ChainStart`]. Retaining them
/// avoids a needless AIA dependency when the signed token already
/// supplied the required intermediate.
///
/// # Errors
/// The same authenticated-path and revocation failures as
/// [`collect_chains`].
pub fn collect_chains_with_candidates(
    starts: &[ChainStart<'_>],
    candidate_ders: &[&[u8]],
) -> Result<ValidationMaterial, MaterialError> {
    collect_chains_seeded_with(
        starts,
        candidate_ders,
        crate::card_check::now_date_time(),
        &HttpEvidenceProvider,
    )
}

/// Verify one certificate path to an exact policy-approved anchor.
///
/// This is the trust decision used for a level-T timestamp: certificate
/// signatures, issuer roles, validity at the authenticated token time,
/// cycles, and the explicit terminal identity are all checked. It does
/// not require a revocation responder to be online and does not claim LT
/// evidence. Call [`collect_chains_with_candidates`] when the verified
/// path and current status objects must also be embedded.
///
/// The returned path contains the leaf first and the approved anchor
/// last. Supplied candidates may satisfy issuer links but never become
/// implicit anchors.
///
/// # Errors
/// [`MaterialError`] when the path is malformed, invalid, cyclic, too
/// deep, or cannot reach one of `approved_anchor_ders`.
pub fn verify_chain_to_approved_anchor(
    leaf_der: &[u8],
    reference_time: DateTime,
    approved_anchor_ders: &[&[u8]],
    candidate_ders: &[&[u8]],
) -> Result<Vec<Vec<u8>>, MaterialError> {
    let mut collection = Collection::default();
    push_candidate(&mut collection, leaf_der);
    for candidate in candidate_ders {
        push_candidate(&mut collection, candidate);
    }
    verify_chain_with(
        leaf_der,
        reference_time,
        approved_anchor_ders,
        &HttpEvidenceProvider,
        &mut collection,
    )
}

/// Legacy entry point retained only to fail closed while callers move to
/// [`collect_chains`]. It has no anchor input and therefore cannot make
/// an LT claim.
///
/// # Errors
/// Always returns [`MaterialError::NoTrustAnchor`].
#[deprecated(note = "use collect_chains with explicit per-chain approved anchors")]
pub const fn collect(_signer_der: &[u8]) -> Result<ValidationMaterial, MaterialError> {
    Err(MaterialError::NoTrustAnchor)
}

/// Legacy timestamp entry point that fails closed.
///
/// Callers must move verified timestamp signers into separate
/// [`ChainStart`] values. Parsing every embedded CMS certificate is not
/// path authentication.
///
/// # Errors
/// Always returns [`MaterialError::NoTrustAnchor`].
#[deprecated(note = "verify each timestamp and use collect_chains with its approved anchors")]
pub const fn collect_with_timestamps(
    _signer_der: &[u8],
    _tokens: &[Vec<u8>],
) -> Result<ValidationMaterial, MaterialError> {
    Err(MaterialError::NoTrustAnchor)
}

/// Material plus every certificate available for later path starts.
/// Candidate retention is separate from output retention: a card signer
/// already carried by the signature may still issue another supplied
/// path, without being duplicated into the DSS.
#[derive(Debug, Default)]
struct Collection {
    material: ValidationMaterial,
    candidates: Vec<Vec<u8>>,
}

/// Authenticated revocation bytes returned by the production evidence
/// provider. The enum prevents OCSP and CRL encodings from being put in
/// the wrong output collection.
#[derive(Debug, Clone, PartialEq, Eq)]
enum StatusEvidence {
    Ocsp(Vec<u8>),
    Crl(Vec<u8>),
}

/// Private seam around network evidence. The public collector always
/// uses [`HttpEvidenceProvider`]; tests substitute deterministic results
/// to exercise path policy without network I/O.
trait EvidenceProvider {
    fn fetch_issuer(&self, url: &Uri) -> Result<Vec<u8>, String>;

    fn status(
        &self,
        nonce_policy: NoncePolicy,
        subject: &Certificate<'_>,
        issuer: &Certificate<'_>,
        evidence_time: DateTime,
    ) -> Result<StatusEvidence, MaterialError>;
}

#[derive(Debug, Clone, Copy)]
struct HttpEvidenceProvider;

impl EvidenceProvider for HttpEvidenceProvider {
    fn fetch_issuer(&self, url: &Uri) -> Result<Vec<u8>, String> {
        let fetched =
            http::get(url, MAX_FETCH_BYTES, user_agent::honest()).map_err(|e| e.to_string())?;
        // A `.crt` served as PEM is ordinary, whatever the content
        // type says. The validation store carries the canonical DER.
        crate::text::decode_cert_pem_or_der(&fetched)
            .ok_or_else(|| "response is neither one DER nor one PEM certificate".to_owned())
    }

    fn status(
        &self,
        nonce_policy: NoncePolicy,
        subject: &Certificate<'_>,
        issuer: &Certificate<'_>,
        evidence_time: DateTime,
    ) -> Result<StatusEvidence, MaterialError> {
        collect_status(nonce_policy, subject, issuer, evidence_time)
    }
}

fn collect_chains_with<P: EvidenceProvider>(
    starts: &[ChainStart<'_>],
    evidence_time: DateTime,
    provider: &P,
) -> Result<ValidationMaterial, MaterialError> {
    collect_chains_seeded_with(starts, &[], evidence_time, provider)
}

fn collect_chains_seeded_with<P: EvidenceProvider>(
    starts: &[ChainStart<'_>],
    candidate_ders: &[&[u8]],
    evidence_time: DateTime,
    provider: &P,
) -> Result<ValidationMaterial, MaterialError> {
    if starts.is_empty() {
        return Err(MaterialError::NoChain);
    }
    let mut collection = Collection::default();
    for start in starts {
        push_candidate(&mut collection, start.leaf_der);
    }
    for candidate in candidate_ders {
        push_candidate(&mut collection, candidate);
    }
    for start in starts {
        walk(*start, evidence_time, provider, &mut collection)?;
    }
    Ok(collection.material)
}

/// Per-path cycle and depth guard.
#[derive(Debug, Default)]
struct WalkGuard {
    visited: Vec<Vec<u8>>,
}

impl WalkGuard {
    fn enter(&mut self, certificate_der: &[u8]) -> Result<(), MaterialError> {
        if self
            .visited
            .iter()
            .any(|visited| visited.as_slice() == certificate_der)
        {
            return Err(MaterialError::ChainCycle);
        }
        if self.visited.len() >= MAX_DEPTH {
            return Err(MaterialError::ChainTooDeep);
        }
        self.visited.push(certificate_der.to_vec());
        Ok(())
    }
}

/// Walk one path to one of its own explicitly approved anchors.
fn walk<P: EvidenceProvider>(
    start: ChainStart<'_>,
    evidence_time: DateTime,
    provider: &P,
    collection: &mut Collection,
) -> Result<(), MaterialError> {
    if start.approved_anchor_ders.is_empty() {
        return Err(MaterialError::NoTrustAnchor);
    }
    let mut current_der = start.leaf_der.to_vec();
    let mut guard = WalkGuard::default();
    let mut subordinate_ca_count = 0_u32;

    if start.include_leaf {
        push_certificate(&mut collection.material, &current_der);
    }

    loop {
        let current = OwnedCert::from_der(&current_der)
            .map_err(|e| MaterialError::Certificate(format!("path certificate parse: {e}")))?;
        let current_view = current.view();
        validate_certificate_time(&current_view, start.reference_time)?;
        guard.enter(&current_der)?;

        if is_approved_anchor(&current_der, start.approved_anchor_ders) {
            if start.include_anchor {
                push_certificate(&mut collection.material, &current_der);
            }
            return Ok(());
        }

        let current_extensions = validate_non_anchor_extensions(&current_view)?;
        if current_extensions.basic_constraints.ca
            && current_view.issuer.as_der() != current_view.subject.as_der()
        {
            subordinate_ca_count = subordinate_ca_count.saturating_add(1);
        }

        let issuer_der = find_issuer(
            &current_view,
            start.reference_time,
            subordinate_ca_count,
            start.approved_anchor_ders,
            &collection.candidates,
            provider,
        )?;
        let issuer = OwnedCert::from_der(&issuer_der)
            .map_err(|e| MaterialError::InvalidIssuer(format!("parse: {e}")))?;
        let issuer_view = issuer.view();
        // `find_issuer` verifies this already. Repeat at the trust
        // transition so later refactors cannot accidentally return an
        // unchecked local or fetched candidate.
        validate_direct_issuer_for_path(
            &current_view,
            &issuer_view,
            start.reference_time,
            subordinate_ca_count,
            is_approved_anchor(&issuer_der, start.approved_anchor_ders),
        )?;

        let evidence = provider.status(
            start.nonce_policy,
            &current_view,
            &issuer_view,
            evidence_time,
        )?;
        push_status(&mut collection.material, evidence);

        let issuer_is_anchor = is_approved_anchor(&issuer_der, start.approved_anchor_ders);
        push_candidate(collection, &issuer_der);
        if !issuer_is_anchor || start.include_anchor {
            push_certificate(&mut collection.material, &issuer_der);
        }
        current_der = issuer_der;
    }
}

/// Construct and authenticate a path without collecting revocation
/// evidence. This is deliberately separate from [`walk`]: reaching an
/// approved timestamp identity establishes level-T trust, while freezing
/// current status for every link is the additional LT operation.
fn verify_chain_with<P: EvidenceProvider>(
    leaf_der: &[u8],
    reference_time: DateTime,
    approved_anchor_ders: &[&[u8]],
    provider: &P,
    collection: &mut Collection,
) -> Result<Vec<Vec<u8>>, MaterialError> {
    if approved_anchor_ders.is_empty() {
        return Err(MaterialError::NoTrustAnchor);
    }
    let mut current_der = leaf_der.to_vec();
    let mut guard = WalkGuard::default();
    let mut path = Vec::new();
    let mut subordinate_ca_count = 0_u32;
    loop {
        let current = OwnedCert::from_der(&current_der)
            .map_err(|e| MaterialError::Certificate(format!("path certificate parse: {e}")))?;
        let current_view = current.view();
        validate_certificate_time(&current_view, reference_time)?;
        guard.enter(&current_der)?;
        path.push(current_der.clone());
        if is_approved_anchor(&current_der, approved_anchor_ders) {
            return Ok(path);
        }
        let current_extensions = validate_non_anchor_extensions(&current_view)?;
        if current_extensions.basic_constraints.ca
            && current_view.issuer.as_der() != current_view.subject.as_der()
        {
            subordinate_ca_count = subordinate_ca_count.saturating_add(1);
        }
        let issuer_der = find_issuer(
            &current_view,
            reference_time,
            subordinate_ca_count,
            approved_anchor_ders,
            &collection.candidates,
            provider,
        )?;
        let issuer = OwnedCert::from_der(&issuer_der)
            .map_err(|e| MaterialError::InvalidIssuer(format!("parse: {e}")))?;
        validate_direct_issuer_for_path(
            &current_view,
            &issuer.view(),
            reference_time,
            subordinate_ca_count,
            is_approved_anchor(&issuer_der, approved_anchor_ders),
        )?;
        push_candidate(collection, &issuer_der);
        current_der = issuer_der;
    }
}

/// Find one directly valid issuer in approved anchors, material already
/// discovered by another path, or the subject's AIA locations.
fn find_issuer<P: EvidenceProvider>(
    subject: &Certificate<'_>,
    reference_time: DateTime,
    subordinate_ca_count: u32,
    anchors: &[&[u8]],
    candidates: &[Vec<u8>],
    provider: &P,
) -> Result<Vec<u8>, MaterialError> {
    for candidate_der in anchors
        .iter()
        .copied()
        .chain(candidates.iter().map(Vec::as_slice))
    {
        if candidate_der == subject.raw_der {
            continue;
        }
        let Ok(candidate) = OwnedCert::from_der(candidate_der) else {
            continue;
        };
        if validate_direct_issuer_for_path(
            subject,
            &candidate.view(),
            reference_time,
            subordinate_ca_count,
            is_approved_anchor(candidate_der, anchors),
        )
        .is_ok()
        {
            return Ok(candidate_der.to_vec());
        }
    }

    let Some(extensions) = subject.extensions else {
        return Err(MaterialError::NoIssuer(
            "certificate has no extensions and is not an approved anchor".to_owned(),
        ));
    };
    let urls = bounded_certificate_addresses(extract_ca_issuers_urls(extensions));
    if urls.is_empty() {
        return Err(MaterialError::NoIssuer(
            "certificate has no CA Issuers address and is not an approved anchor".to_owned(),
        ));
    }

    let mut failures = Vec::new();
    for url in urls {
        let candidate_der = match provider.fetch_issuer(&url) {
            Ok(der) => der,
            Err(why) => {
                failures.push(format!("{url}: {why}"));
                continue;
            }
        };
        let candidate = match OwnedCert::from_der(&candidate_der) {
            Ok(cert) => cert,
            Err(why) => {
                failures.push(format!("{url}: parse: {why}"));
                continue;
            }
        };
        match validate_direct_issuer_for_path(
            subject,
            &candidate.view(),
            reference_time,
            subordinate_ca_count,
            is_approved_anchor(&candidate_der, anchors),
        ) {
            Ok(()) => return Ok(candidate_der),
            Err(why) => failures.push(format!("{url}: {why}")),
        }
    }
    Err(MaterialError::NoIssuer(failures.join("; ")))
}

/// Verify one link while keeping explicit trust anchors outside the
/// certification path's intermediate-certificate policy.
///
/// An exact caller-approved anchor contributes its name and public key as trust
/// input. Its certificate extensions are not silently promoted into policy.
/// Every non-anchor issuer, by contrast, must satisfy all supported CA
/// constraints and may not carry constraints this implementation cannot apply.
fn validate_direct_issuer_for_path(
    subject: &Certificate<'_>,
    issuer: &Certificate<'_>,
    reference_time: DateTime,
    subordinate_ca_count: u32,
    issuer_is_anchor: bool,
) -> Result<(), MaterialError> {
    if subject.issuer.as_der() != issuer.subject.as_der() {
        return Err(MaterialError::InvalidIssuer(
            "subject issuer name does not equal candidate subject name".to_owned(),
        ));
    }
    if issuer_is_anchor {
        validate_certificate_time(issuer, reference_time)
            .map_err(|e| MaterialError::InvalidIssuer(e.to_string()))?;
    } else {
        validate_issuing_certificate(issuer, reference_time, subordinate_ca_count)?;
    }
    subject
        .verify_signed_by(*issuer)
        .map_err(|e| MaterialError::InvalidIssuer(format!("certificate signature: {e}")))
}

fn validate_certificate_time(
    certificate: &Certificate<'_>,
    reference_time: DateTime,
) -> Result<(), MaterialError> {
    if reference_time < certificate.not_before {
        return Err(MaterialError::Certificate(format!(
            "not valid before {}",
            certificate.not_before
        )));
    }
    if reference_time > certificate.not_after {
        return Err(MaterialError::Certificate(format!(
            "expired at {}",
            certificate.not_after
        )));
    }
    Ok(())
}

fn validate_issuing_certificate(
    issuer: &Certificate<'_>,
    reference_time: DateTime,
    subordinate_ca_count: u32,
) -> Result<(), MaterialError> {
    validate_certificate_time(issuer, reference_time)
        .map_err(|e| MaterialError::InvalidIssuer(e.to_string()))?;
    let profile = validate_path_extensions(issuer).map_err(MaterialError::InvalidIssuer)?;
    let constraints = profile.basic_constraints;
    if !constraints.present || !constraints.ca {
        return Err(MaterialError::InvalidIssuer(
            "issuer is not a CA".to_owned(),
        ));
    }
    if !constraints.critical {
        return Err(MaterialError::InvalidIssuer(
            "issuer Basic Constraints is not critical".to_owned(),
        ));
    }
    enforce_path_length(constraints.path_len, subordinate_ca_count)?;
    if !profile
        .key_usage
        .is_some_and(|usage| usage.key_usage.key_cert_sign)
    {
        return Err(MaterialError::InvalidIssuer(
            "issuer has no Key Usage permitting certificate signing".to_owned(),
        ));
    }
    Ok(())
}

fn validate_non_anchor_extensions(
    certificate: &Certificate<'_>,
) -> Result<PathExtensionProfile, MaterialError> {
    validate_path_extensions(certificate).map_err(MaterialError::Certificate)
}

fn validate_path_extensions(certificate: &Certificate<'_>) -> Result<PathExtensionProfile, String> {
    let profile = path_extension_profile(certificate.extensions.unwrap_or_default())
        .map_err(|error| error.to_string())?;
    enforce_non_anchor_extension_policy(profile)?;
    Ok(profile)
}

fn enforce_non_anchor_extension_policy(profile: PathExtensionProfile) -> Result<(), String> {
    if profile.name_constraints_present {
        return Err(
            "non-anchor certificate carries Name Constraints, which this path builder cannot enforce"
                .to_owned(),
        );
    }
    if profile.basic_constraints.ca && profile.extended_key_usage_present {
        return Err(
            "non-anchor CA carries Extended Key Usage, whose purpose constraints this generic path builder cannot enforce"
                .to_owned(),
        );
    }
    Ok(())
}

fn enforce_path_length(
    path_len: Option<u32>,
    subordinate_ca_count: u32,
) -> Result<(), MaterialError> {
    if let Some(limit) = path_len
        && subordinate_ca_count > limit
    {
        return Err(MaterialError::InvalidIssuer(format!(
            "issuer Basic Constraints pathLen permits at most {limit} subordinate CA certificates, found {subordinate_ca_count}"
        )));
    }
    Ok(())
}

fn is_approved_anchor(certificate_der: &[u8], anchors: &[&[u8]]) -> bool {
    anchors.contains(&certificate_der)
}

fn push_candidate(collection: &mut Collection, der: &[u8]) {
    if !collection
        .candidates
        .iter()
        .any(|candidate| candidate.as_slice() == der)
    {
        collection.candidates.push(der.to_vec());
    }
}

fn push_status(material: &mut ValidationMaterial, evidence: StatusEvidence) {
    let target = match evidence {
        StatusEvidence::Ocsp(der) => (&mut material.ocsp_responses, der),
        StatusEvidence::Crl(der) => (&mut material.crls, der),
    };
    if !target.0.iter().any(|held| held == &target.1) {
        target.0.push(target.1);
    }
}

/// Add `der` to the store unless it is already there.
///
/// Returns whether it was new. The store goes into a CMS
/// `CertificateSet` or a `PDF` `/DSS`, and a certificate repeated in
/// either is bytes a verifier reads twice to learn the same thing.
fn push_certificate(material: &mut ValidationMaterial, der: &[u8]) -> bool {
    if material.certificates.iter().any(|held| held == der) {
        return false;
    }
    material.certificates.push(der.to_vec());
    true
}

/// Obtain one authenticated, current status answer for `subject`.
///
/// Every advertised OCSP service is tried before every full CRL. A
/// malformed or unreachable endpoint does not mask a later usable one,
/// but an authenticated revoked verdict stops immediately. Absence of
/// all usable evidence is an error rather than partial LT material.
fn collect_status(
    nonce_policy: NoncePolicy,
    subject: &Certificate<'_>,
    issuer: &Certificate<'_>,
    evidence_time: DateTime,
) -> Result<StatusEvidence, MaterialError> {
    let extensions = subject.extensions.ok_or_else(|| {
        MaterialError::Revocation("certificate has no revocation extensions".to_owned())
    })?;
    let mut failures = Vec::new();
    let (ocsp_response, random_failure) = collect_ocsp_status(
        nonce_policy,
        subject,
        issuer,
        evidence_time,
        extensions,
        &mut failures,
    )?;
    if let Some(response) = ocsp_response {
        return Ok(StatusEvidence::Ocsp(response));
    }
    if let Some(list) =
        collect_crl_status(subject, issuer, evidence_time, extensions, &mut failures)?
    {
        return Ok(StatusEvidence::Crl(list));
    }
    if let Some(why) = random_failure {
        return Err(MaterialError::Rng(why));
    }
    if failures.is_empty() {
        return Err(MaterialError::Revocation(
            "certificate advertises neither OCSP nor a CRL distribution point".to_owned(),
        ));
    }
    Err(MaterialError::Revocation(failures.join("; ")))
}

/// Try all advertised OCSP services, retaining why each failed.
fn collect_ocsp_status(
    nonce_policy: NoncePolicy,
    subject: &Certificate<'_>,
    issuer: &Certificate<'_>,
    reference_time: DateTime,
    extensions: &[u8],
    failures: &mut Vec<String>,
) -> Result<(Option<Vec<u8>>, Option<String>), MaterialError> {
    let key_hash = ocsp::IssuerKeyHash::from_subject_public_key(&issuer.spki);
    let name_hash = issuer_name_hash(&subject.issuer);

    for url in bounded_certificate_addresses(extract_ocsp_urls(extensions)) {
        let nonce = match ocsp::OcspNonce::random() {
            Ok(nonce) => nonce,
            Err(why) => {
                return Ok((None, Some(why.to_string())));
            }
        };
        let request =
            ocsp::build_request_with_nonce(name_hash, key_hash, &subject.serial(), &nonce);
        let response = match http::post(
            &url,
            "application/ocsp-request",
            request.as_der(),
            MAX_FETCH_BYTES,
            user_agent::honest(),
        ) {
            Ok(response) => response,
            Err(why) => {
                failures.push(format!("{url}: {why}"));
                continue;
            }
        };
        match check_response(
            nonce_policy,
            &response,
            subject,
            issuer,
            name_hash,
            key_hash,
            &nonce,
            reference_time,
        ) {
            Ok(()) => return Ok((Some(response), None)),
            Err(revoked @ MaterialError::Revoked(_)) => return Err(revoked),
            Err(why) => failures.push(format!("{url}: {why}")),
        }
    }
    Ok((None, None))
}

/// Try all advertised full CRLs, retaining why each failed.
fn collect_crl_status(
    subject: &Certificate<'_>,
    issuer: &Certificate<'_>,
    reference_time: DateTime,
    extensions: &[u8],
    failures: &mut Vec<String>,
) -> Result<Option<Vec<u8>>, MaterialError> {
    let issuer_may_sign_crls = issuer
        .extensions
        .and_then(extract_key_usage)
        .is_some_and(|usage| usage.crl_sign);
    for url in bounded_certificate_addresses(extract_crl_distribution_urls(extensions)) {
        if !issuer_may_sign_crls {
            failures.push(format!(
                "{url}: issuer Key Usage does not permit CRL signing"
            ));
            break;
        }
        let der = match http::get(&url, MAX_CRL_BYTES, user_agent::honest()) {
            Ok(der) => der,
            Err(why) => {
                failures.push(format!("{url}: {why}"));
                continue;
            }
        };
        let list = match OwnedCrl::from_der(&der) {
            Ok(list) => list,
            Err(why) => {
                failures.push(format!("{url}: parse: {why}"));
                continue;
            }
        };
        let view = list.view();
        if let Err(why) = check_crl_times(view.this_update, view.next_update, reference_time) {
            failures.push(format!("{url}: {why}"));
            continue;
        }

        let verified = match VerifiedCrl::verify(&view, *issuer) {
            Ok(verified) => verified,
            Err(why) => {
                failures.push(format!("{url}: signature: {why}"));
                continue;
            }
        };
        match revocation::check_against_crl(*subject, &verified, reference_time) {
            RevocationStatus::Good => return Ok(Some(der)),
            RevocationStatus::Revoked { at, reason } => {
                return Err(MaterialError::Revoked(format!(
                    "{url}: revoked {at} ({reason:?})"
                )));
            }
            other => failures.push(format!("{url}: list unusable ({other:?})")),
        }
    }
    Ok(None)
}

/// Require a bounded, current validity interval on a CRL.
fn check_crl_times(
    this_update: DateTime,
    next_update: Option<DateTime>,
    reference_time: DateTime,
) -> Result<(), &'static str> {
    let future_limit = reference_time
        .unix_duration()
        .saturating_add(MAX_CLOCK_SKEW);
    if this_update.unix_duration() > future_limit {
        return Err("CRL thisUpdate is in the future");
    }
    let Some(next_update) = next_update else {
        return Err("CRL has no nextUpdate");
    };
    if next_update <= this_update {
        return Err("CRL nextUpdate is not after thisUpdate");
    }
    if reference_time.unix_duration() > next_update.unix_duration().saturating_add(MAX_CLOCK_SKEW) {
        return Err("CRL is past nextUpdate");
    }
    Ok(())
}

/// Refuse an OCSP response that does not stand up.
///
/// Four checks, each covering something a stale cache or an attacker on
/// a plain-HTTP path could otherwise slip past: the responder signed it
/// and the signature verifies against the issuer or a responder the
/// issuer delegated to; the nonce comes back unchanged, which is what
/// ties this answer to this request; the entry is about this
/// certificate; and the status is good rather than revoked or unknown.
///
/// The exact status entry is read through `VerifiedOcspResponse`, so a
/// status can only be read after signer identity, authorization, and
/// signature verification; the type system says so rather than a
/// comment.
#[expect(
    clippy::too_many_arguments,
    reason = "Every argument is one thing the check needs and none can be derived from the others: the response, the certificate it should be about, the issuer that should have signed it, the two CertID hashes naming that issuer, the nonce sent, the clock reading the whole walk shares, and whether a missing echo is fatal. Bundling them into a struct would move the same eight values behind a name that adds nothing."
)]
fn check_response(
    nonce_policy: NoncePolicy,
    der: &[u8],
    subject: &Certificate<'_>,
    issuer: &Certificate<'_>,
    name_hash: ocsp::IssuerNameHash,
    key_hash: ocsp::IssuerKeyHash,
    nonce: &ocsp::OcspNonce,
    now: DateTime,
) -> Result<(), MaterialError> {
    let owned = ocsp::OwnedOcspResponse::from_der(der)
        .map_err(|e| MaterialError::Revocation(format!("parse: {e}")))?;
    let response = owned.view();
    if response.status != ocsp::OcspResponseStatus::Successful {
        return Err(MaterialError::Revocation(format!(
            "responder returned {:?}",
            response.status
        )));
    }
    let basic = response
        .basic
        .ok_or_else(|| MaterialError::Revocation("no basic response".to_owned()))?;

    // Signed by the issuer, or by a responder the issuer delegated to.
    let verified = ocsp::VerifiedOcspResponse::verify(&basic, *issuer, *issuer)
        .ok()
        .or_else(|| {
            basic.embedded_cert_ders.iter().find_map(|embedded| {
                let owned = OwnedCert::from_der(embedded).ok()?;
                let responder = owned.view();
                ocsp::VerifiedOcspResponse::verify(&basic, responder, *issuer).ok()
            })
        })
        .ok_or_else(|| {
            MaterialError::Revocation(
                "signature verifies against neither the issuer nor an embedded responder"
                    .to_owned(),
            )
        })?;

    // The nonce is what makes this answer this request's, rather than
    // one recorded earlier and replayed.
    match basic.nonce.as_deref() {
        Some(echoed) if echoed == nonce.as_bytes() => {}
        Some(_) => {
            return Err(MaterialError::Revocation(
                "nonce came back changed".to_owned(),
            ));
        }
        // A responder that echoes nothing has not tied its answer to
        // this request. For the signer's own certificate that is
        // refused: an old "good", replayed, is exactly what a long-term
        // signature must not carry.
        //
        // For a timestamp authority's certificate the calculus runs the
        // other way. Many public responders serve pre-produced answers
        // without a nonce, so refusing them embeds no revocation at all,
        // and a validator detecting the long-term profile wants one per
        // timestamp certificate. The answer is still signed by the
        // responder, still about this serial, still inside its own
        // window; what it lacks is proof of freshness, and the archive
        // timestamp over the whole document is what supplies that.
        None if nonce_policy == NoncePolicy::RequireEcho => {
            return Err(MaterialError::Revocation(
                "responder echoed no nonce, so the answer cannot be tied to this request"
                    .to_owned(),
            ));
        }
        None => {}
    }

    let subject_serial = subject.serial();
    let Some(answer) = verified.single_responses().iter().find(|entry| {
        entry
            .cert_id
            .matches_request(name_hash, key_hash, &subject_serial)
    }) else {
        return Err(MaterialError::Revocation(
            "response carries no SingleResponse for this request's CertID".to_owned(),
        ));
    };
    check_ocsp_times(
        basic.produced_at,
        answer.this_update,
        answer.next_update,
        now,
    )?;

    // Read the exact CertID match checked above. A serial-only lookup
    // could select an entry for another issuer if a malformed signed
    // response carried the same serial more than once.
    match answer.status {
        ocsp::CertStatus::Good => Ok(()),
        ocsp::CertStatus::Revoked { revoked_at, .. } => {
            Err(MaterialError::Revoked(format!("revoked at {revoked_at}")))
        }
        ocsp::CertStatus::Unknown => Err(MaterialError::Revocation(
            "responder does not know this certificate".to_owned(),
        )),
        _ => Err(MaterialError::Revocation(
            "responder returned an unsupported certificate status".to_owned(),
        )),
    }
}

/// Enforce the freshness window on one matching OCSP answer.
fn check_ocsp_times(
    produced_at: DateTime,
    this_update: DateTime,
    next_update: Option<DateTime>,
    now: DateTime,
) -> Result<(), MaterialError> {
    // The request is sent after `now` is sampled, so a small future
    // allowance covers the round trip and independently skewed clocks.
    if produced_at.unix_duration() > now.unix_duration().saturating_add(MAX_CLOCK_SKEW) {
        return Err(MaterialError::Revocation(format!(
            "response producedAt {produced_at} is further ahead than clock skew explains"
        )));
    }
    // Same allowance as producedAt above, and for the same reason with
    // one addition: `now` is read once before the walk, and the walk
    // grew. With one authority it is a few seconds of round trip; with
    // five it is five timestamp requests, then a chain fetch and a
    // responder call for each, and a responder that mints its answer on
    // demand -- APED does -- stamps it well after our reading. Zero
    // tolerance here rejected exactly those answers, so the material
    // that reaches the document depended on how many authorities were
    // asked. Measured: one authority embedded five OCSP answers and
    // graded BASELINE-LTA; five authorities embedded the same five and
    // graded BASELINE-T, because two were thrown away for being dated
    // after a clock reading taken minutes earlier.
    if this_update.unix_duration() > now.unix_duration().saturating_add(MAX_CLOCK_SKEW) {
        return Err(MaterialError::Revocation(
            "response thisUpdate is further ahead than clock skew explains".to_owned(),
        ));
    }
    if this_update.unix_duration() > produced_at.unix_duration().saturating_add(MAX_CLOCK_SKEW) {
        return Err(MaterialError::Revocation(
            "response thisUpdate is later than producedAt".to_owned(),
        ));
    }
    if let Some(next_update) = next_update {
        if next_update <= this_update {
            return Err(MaterialError::Revocation(
                "response nextUpdate is not after thisUpdate".to_owned(),
            ));
        }
        if now.unix_duration() > next_update.unix_duration().saturating_add(MAX_CLOCK_SKEW) {
            return Err(MaterialError::Revocation(
                "response is past its nextUpdate".to_owned(),
            ));
        }
    } else if now.unix_duration()
        > this_update
            .unix_duration()
            .saturating_add(MAX_OCSP_AGE_WITHOUT_NEXT_UPDATE)
            .saturating_add(MAX_CLOCK_SKEW)
    {
        return Err(MaterialError::Revocation(
            "response without nextUpdate is too old".to_owned(),
        ));
    }
    Ok(())
}

/// SHA-1 of an issuer's DER name, as `CertID` wants it.
fn issuer_name_hash(issuer: &Name<'_>) -> ocsp::IssuerNameHash {
    let mut hash = <Sha1 as Sha1Digest>::new();
    hash.update(issuer.as_der());
    let out = hash.finalize();
    let mut buffer = [0_u8; SHA1_OUTPUT_LEN];
    buffer.copy_from_slice(&out);
    ocsp::IssuerNameHash::new(buffer)
}

/// Keep certificate-advertised endpoints distinct and bounded in their
/// original order.
fn bounded_certificate_addresses(addresses: Vec<Uri>) -> Vec<Uri> {
    let mut selected = Vec::new();
    for address in addresses {
        if selected.contains(&address) {
            continue;
        }
        selected.push(address);
        if selected.len() == MAX_CERTIFICATE_ADDRESSES {
            break;
        }
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{TestResult, check, check_true};
    use core::cell::Cell;
    use refineid_lib_core::oid::{Oid, known};

    /// A real directly verified path: this intermediate is signed by
    /// the G3 ECC root below.
    const DVV_INTERMEDIATE_DER: &[u8] =
        include_bytes!("../test-vectors/fineid-intermediate-01-citizen-g4e.der");
    const DVV_ROOT_ECC_DER: &[u8] = include_bytes!("../trust-anchors/dvv-gov-root-ca-g3-ecc.der");
    const DVV_ROOT_RSA_DER: &[u8] = include_bytes!("../trust-anchors/dvv-gov-root-ca-g3-rsa.der");
    const APED_OCSP_DER: &[u8] =
        include_bytes!("../../refineid-lib-core/tests/data/aped-ocsp-response.der");
    const TEST_STATUS: &[u8] = b"authenticated-status-test-sentinel";

    fn reference_time() -> Result<DateTime, Box<dyn core::error::Error>> {
        DateTime::new(2026, 8, 4, 12, 0, 0).map_err(Into::into)
    }

    fn start<'a>(
        leaf_der: &'a [u8],
        anchors: &'a [&'a [u8]],
        include_leaf: bool,
    ) -> Result<ChainStart<'a>, Box<dyn core::error::Error>> {
        Ok(ChainStart {
            leaf_der,
            reference_time: reference_time()?,
            approved_anchor_ders: anchors,
            nonce_policy: NoncePolicy::RequireEcho,
            include_leaf,
            include_anchor: false,
        })
    }

    fn replace_extension_oid_last_arc(
        certificate_der: &[u8],
        oid: Oid<'_>,
    ) -> Result<Vec<u8>, Box<dyn core::error::Error>> {
        let mut changed = certificate_der.to_vec();
        let oid_bytes = oid.as_bytes();
        let at = changed
            .windows(oid_bytes.len())
            .position(|window| window == oid_bytes)
            .ok_or("fixture extension OID not found")?;
        let last = at
            .checked_add(oid_bytes.len().saturating_sub(1))
            .ok_or("fixture OID position overflow")?;
        let replacement = changed
            .get(last)
            .copied()
            .and_then(|arc| arc.checked_add(1))
            .ok_or("fixture OID final arc cannot be incremented")?;
        let target = changed
            .get_mut(last)
            .ok_or("fixture OID final arc is out of bounds")?;
        *target = replacement;
        Ok(changed)
    }

    #[derive(Debug, Default)]
    struct GoodEvidence {
        fetches: Cell<usize>,
        statuses: Cell<usize>,
        last_evidence_time: Cell<Option<DateTime>>,
    }

    impl EvidenceProvider for GoodEvidence {
        fn fetch_issuer(&self, _url: &Uri) -> Result<Vec<u8>, String> {
            self.fetches.set(self.fetches.get().saturating_add(1));
            Err("offline fixture has no fetched issuer".to_owned())
        }

        fn status(
            &self,
            _nonce_policy: NoncePolicy,
            _subject: &Certificate<'_>,
            _issuer: &Certificate<'_>,
            evidence_time: DateTime,
        ) -> Result<StatusEvidence, MaterialError> {
            self.statuses.set(self.statuses.get().saturating_add(1));
            self.last_evidence_time.set(Some(evidence_time));
            Ok(StatusEvidence::Ocsp(TEST_STATUS.to_vec()))
        }
    }

    #[derive(Debug, Default)]
    struct MissingEvidence {
        statuses: Cell<usize>,
    }

    impl EvidenceProvider for MissingEvidence {
        fn fetch_issuer(&self, _url: &Uri) -> Result<Vec<u8>, String> {
            Err("issuer unavailable".to_owned())
        }

        fn status(
            &self,
            _nonce_policy: NoncePolicy,
            _subject: &Certificate<'_>,
            _issuer: &Certificate<'_>,
            _reference_time: DateTime,
        ) -> Result<StatusEvidence, MaterialError> {
            self.statuses.set(self.statuses.get().saturating_add(1));
            Err(MaterialError::Revocation(
                "no authenticated current answer".to_owned(),
            ))
        }
    }

    #[test]
    fn empty_start_set_cannot_claim_lt() -> TestResult {
        let error = collect_chains_with(&[], reference_time()?, &GoodEvidence::default())
            .err()
            .ok_or("empty start set unexpectedly succeeded")?;
        check(&error, &MaterialError::NoChain, "empty start error")
    }

    #[test]
    fn certificate_addresses_are_distinct_and_bounded() -> TestResult {
        let first = Uri::parse("https://one.example/status".to_owned())?;
        let second = Uri::parse("https://two.example/status".to_owned())?;
        let third = Uri::parse("https://three.example/status".to_owned())?;
        let fourth = Uri::parse("https://four.example/status".to_owned())?;
        let selected = bounded_certificate_addresses(vec![
            first.clone(),
            second.clone(),
            first,
            third.clone(),
            fourth,
        ]);
        check(
            &selected,
            &vec![
                Uri::parse("https://one.example/status".to_owned())?,
                second,
                third,
            ],
            "first three distinct endpoints",
        )
    }

    #[test]
    fn empty_anchor_set_fails_before_path_or_network_work() -> TestResult {
        let provider = GoodEvidence::default();
        let chain = start(DVV_INTERMEDIATE_DER, &[], false)?;
        let error = collect_chains_with(&[chain], reference_time()?, &provider)
            .err()
            .ok_or("anchorless chain unexpectedly succeeded")?;
        check(&error, &MaterialError::NoTrustAnchor, "anchorless error")?;
        check(&provider.fetches.get(), &0, "issuer fetch count")?;
        check(&provider.statuses.get(), &0, "status count")
    }

    #[test]
    fn verified_link_reaches_only_the_explicit_anchor() -> TestResult {
        let provider = GoodEvidence::default();
        let anchors = [DVV_ROOT_ECC_DER];
        let chain = start(DVV_INTERMEDIATE_DER, &anchors, false)?;
        let evidence_time = DateTime::new(2026, 8, 5, 12, 0, 0)?;
        let material = collect_chains_with(&[chain], evidence_time, &provider)?;

        check(&provider.fetches.get(), &0, "local anchor avoids AIA")?;
        check(&provider.statuses.get(), &1, "one non-anchor status")?;
        check(
            &provider.last_evidence_time.get(),
            &Some(evidence_time),
            "revocation freshness uses collection time",
        )?;
        check(&material.certificates.len(), &0, "anchor omitted")?;
        check(
            &material.ocsp_responses,
            &vec![TEST_STATUS.to_vec()],
            "authenticated status retained",
        )
    }

    #[test]
    fn level_t_path_verification_needs_no_revocation_answer() -> TestResult {
        let provider = MissingEvidence::default();
        let anchors = [DVV_ROOT_ECC_DER];
        let mut collection = Collection::default();
        let path = verify_chain_with(
            DVV_INTERMEDIATE_DER,
            reference_time()?,
            &anchors,
            &provider,
            &mut collection,
        )?;
        check(
            &path,
            &vec![DVV_INTERMEDIATE_DER.to_vec(), DVV_ROOT_ECC_DER.to_vec()],
            "leaf-to-approved-anchor path",
        )?;
        check(
            &provider.statuses.get(),
            &0,
            "level-T trust does not fetch LT status evidence",
        )
    }

    #[test]
    fn timestamp_path_can_retain_its_exact_policy_anchor() -> TestResult {
        let provider = GoodEvidence::default();
        let anchors = [DVV_ROOT_ECC_DER];
        let mut chain = start(DVV_INTERMEDIATE_DER, &anchors, true)?;
        chain.include_anchor = true;
        let material = collect_chains_with(&[chain], reference_time()?, &provider)?;
        check(
            &material.certificates,
            &vec![DVV_INTERMEDIATE_DER.to_vec(), DVV_ROOT_ECC_DER.to_vec()],
            "complete timestamp path including its anchor",
        )
    }

    #[test]
    fn missing_revocation_evidence_fails_the_whole_chain() -> TestResult {
        let provider = MissingEvidence::default();
        let anchors = [DVV_ROOT_ECC_DER];
        let chain = start(DVV_INTERMEDIATE_DER, &anchors, false)?;
        let error = collect_chains_with(&[chain], reference_time()?, &provider)
            .err()
            .ok_or("chain without status unexpectedly succeeded")?;
        check_true(
            matches!(error, MaterialError::Revocation(_)),
            "missing evidence is fatal",
        )?;
        check(&provider.statuses.get(), &1, "status attempted")
    }

    #[test]
    fn self_issued_name_is_not_an_implicit_anchor() -> TestResult {
        let provider = GoodEvidence::default();
        let unrelated = [DVV_ROOT_RSA_DER];
        let chain = start(DVV_ROOT_ECC_DER, &unrelated, false)?;
        let error = collect_chains_with(&[chain], reference_time()?, &provider)
            .err()
            .ok_or("unapproved self-issued root unexpectedly succeeded")?;
        check_true(
            matches!(error, MaterialError::NoIssuer(_)),
            "self-issued certificate did not terminate path",
        )?;
        check(&provider.statuses.get(), &0, "no status without issuer")
    }

    #[test]
    fn exact_non_self_signed_service_identity_can_be_an_anchor() -> TestResult {
        let provider = GoodEvidence::default();
        let anchors = [DVV_INTERMEDIATE_DER];
        let chain = start(DVV_INTERMEDIATE_DER, &anchors, true)?;
        let material = collect_chains_with(&[chain], reference_time()?, &provider)?;
        check(
            &material.certificates,
            &vec![DVV_INTERMEDIATE_DER.to_vec()],
            "requested anchor leaf retained",
        )?;
        check(&provider.statuses.get(), &0, "anchor needs no status")
    }

    #[test]
    fn exact_anchor_extensions_are_not_treated_as_intermediate_policy() -> TestResult {
        let provider = GoodEvidence::default();
        let anchor_with_unknown_critical_extension =
            replace_extension_oid_last_arc(DVV_ROOT_ECC_DER, known::KEY_USAGE)?;
        let anchors = [anchor_with_unknown_critical_extension.as_slice()];
        let chain = start(DVV_INTERMEDIATE_DER, &anchors, false)?;

        let material = collect_chains_with(&[chain], reference_time()?, &provider)?;
        check(&provider.statuses.get(), &1, "one non-anchor status")?;
        check(
            &material.certificates.len(),
            &0,
            "explicit trust anchor remains omitted",
        )
    }

    #[test]
    fn non_anchor_unknown_critical_extension_is_rejected() -> TestResult {
        let changed = replace_extension_oid_last_arc(DVV_INTERMEDIATE_DER, known::KEY_USAGE)?;
        let certificate = OwnedCert::from_der(changed)?;
        let error = validate_non_anchor_extensions(&certificate.view())
            .err()
            .ok_or("unknown critical extension unexpectedly accepted")?;
        check_true(
            matches!(error, MaterialError::Certificate(detail) if detail.contains("unsupported critical")),
            "unknown critical extension fails closed",
        )
    }

    #[test]
    fn non_anchor_unknown_noncritical_extension_is_allowed() -> TestResult {
        let changed =
            replace_extension_oid_last_arc(DVV_INTERMEDIATE_DER, known::CERTIFICATE_POLICIES)?;
        let certificate = OwnedCert::from_der(changed)?;
        let profile = validate_non_anchor_extensions(&certificate.view())?;
        check_true(
            profile.basic_constraints.ca,
            "unknown non-critical extension does not hide CA constraints",
        )
    }

    #[test]
    fn unsupported_ca_constraints_fail_closed_and_path_len_is_enforced() -> TestResult {
        let certificate = OwnedCert::from_der(DVV_INTERMEDIATE_DER)?;
        let extensions = certificate
            .view()
            .extensions
            .ok_or("intermediate fixture has no extensions")?;
        let profile = path_extension_profile(extensions)?;
        check(
            &profile.basic_constraints.path_len,
            &Some(0),
            "fixture pathLen",
        )?;
        enforce_path_length(profile.basic_constraints.path_len, 0)?;
        let path_error = enforce_path_length(profile.basic_constraints.path_len, 1)
            .err()
            .ok_or("pathLen zero unexpectedly permitted a subordinate CA")?;
        check_true(
            matches!(path_error, MaterialError::InvalidIssuer(detail) if detail.contains("pathLen")),
            "pathLen violation fails closed",
        )?;

        let mut eku_constrained_ca = profile;
        eku_constrained_ca.extended_key_usage_present = true;
        let eku_error = enforce_non_anchor_extension_policy(eku_constrained_ca)
            .err()
            .ok_or("CA EKU unexpectedly ignored")?;
        check_true(
            eku_error.contains("Extended Key Usage"),
            "unsupported CA purpose constraint fails closed",
        )?;

        let mut name_constrained_ca = profile;
        name_constrained_ca.name_constraints_present = true;
        let name_error = enforce_non_anchor_extension_policy(name_constrained_ca)
            .err()
            .ok_or("Name Constraints unexpectedly ignored")?;
        check_true(
            name_error.contains("Name Constraints"),
            "unsupported name constraint fails closed",
        )
    }

    #[test]
    fn anchor_is_matched_by_exact_der_not_issuer_name() -> TestResult {
        let provider = GoodEvidence::default();
        let unrelated = [DVV_ROOT_RSA_DER];
        let chain = start(DVV_INTERMEDIATE_DER, &unrelated, false)?;
        let error = collect_chains_with(&[chain], reference_time()?, &provider)
            .err()
            .ok_or("unrelated anchor unexpectedly terminated path")?;
        check_true(
            matches!(error, MaterialError::NoIssuer(_)),
            "unrelated anchor rejected",
        )?;
        check(
            &provider.fetches.get(),
            &1,
            "AIA tried after anchor mismatch",
        )
    }

    #[test]
    fn embedded_candidate_can_build_a_link_but_cannot_become_an_anchor() -> TestResult {
        let provider = GoodEvidence::default();
        let approved = [DVV_ROOT_RSA_DER];
        let chain = start(DVV_INTERMEDIATE_DER, &approved, false)?;
        let candidates = [DVV_ROOT_ECC_DER];
        let error = collect_chains_seeded_with(&[chain], &candidates, reference_time()?, &provider)
            .err()
            .ok_or("unapproved embedded issuer unexpectedly became an anchor")?;
        check_true(
            matches!(error, MaterialError::NoIssuer(_)),
            "path still had to reach the separately approved anchor",
        )?;
        check(
            &provider.statuses.get(),
            &1,
            "embedded candidate was used as a verified issuer",
        )
    }

    #[test]
    fn child_signature_is_verified_before_issuer_acceptance() -> TestResult {
        let mut tampered = DVV_INTERMEDIATE_DER.to_vec();
        let last = tampered
            .last_mut()
            .ok_or("intermediate fixture unexpectedly empty")?;
        *last ^= 1;
        let child = OwnedCert::from_der(&tampered)?;
        let issuer = OwnedCert::from_der(DVV_ROOT_ECC_DER)?;
        let error = validate_direct_issuer_for_path(
            &child.view(),
            &issuer.view(),
            reference_time()?,
            0,
            false,
        )
        .err()
        .ok_or("tampered child signature unexpectedly verified")?;
        check_true(
            matches!(error, MaterialError::InvalidIssuer(detail) if detail.contains("signature")),
            "signature failure surfaced",
        )
    }

    #[test]
    fn non_ca_ocsp_responder_cannot_issue_path_certificates() -> TestResult {
        let response = ocsp::OwnedOcspResponse::from_der(APED_OCSP_DER)?;
        let response_view = response.view();
        let basic = response_view
            .basic
            .ok_or("APED fixture unexpectedly has no basic response")?;
        let responder_der = basic
            .embedded_cert_ders
            .first()
            .copied()
            .ok_or("APED fixture unexpectedly has no responder certificate")?;
        let responder = OwnedCert::from_der(responder_der)?;
        let error = validate_issuing_certificate(&responder.view(), reference_time()?, 0)
            .err()
            .ok_or("non-CA OCSP responder unexpectedly accepted as issuer")?;
        check_true(
            matches!(error, MaterialError::InvalidIssuer(detail) if detail.contains("not a CA")),
            "CA constraint enforced",
        )
    }

    #[test]
    fn issuer_must_be_valid_at_the_chain_reference_time() -> TestResult {
        let root = OwnedCert::from_der(DVV_ROOT_ECC_DER)?;
        let after_expiry = DateTime::new(2050, 1, 1, 0, 0, 0)?;
        let error = validate_issuing_certificate(&root.view(), after_expiry, 0)
            .err()
            .ok_or("expired issuer unexpectedly accepted")?;
        check_true(
            matches!(error, MaterialError::InvalidIssuer(detail) if detail.contains("expired")),
            "issuer validity enforced",
        )
    }

    #[test]
    fn ocsp_freshness_is_bounded_even_without_next_update() -> TestResult {
        let now = reference_time()?;
        check(
            &check_ocsp_times(now, now, None, now),
            &Ok(()),
            "fresh response without nextUpdate",
        )?;

        let old = DateTime::new(2026, 7, 20, 12, 0, 0)?;
        let error = check_ocsp_times(now, old, None, now)
            .err()
            .ok_or("old response without nextUpdate unexpectedly accepted")?;
        check_true(
            matches!(error, MaterialError::Revocation(detail) if detail.contains("too old")),
            "unbounded old OCSP response rejected",
        )?;

        let issued = DateTime::new(2026, 8, 2, 12, 0, 0)?;
        let expired = DateTime::new(2026, 8, 3, 12, 0, 0)?;
        let error = check_ocsp_times(issued, issued, Some(expired), now)
            .err()
            .ok_or("expired OCSP response unexpectedly accepted")?;
        check_true(
            matches!(error, MaterialError::Revocation(_)),
            "expired OCSP response rejected",
        )
    }

    #[test]
    fn crl_requires_a_current_ordered_next_update() -> TestResult {
        let now = reference_time()?;
        let yesterday = DateTime::new(2026, 8, 3, 12, 0, 0)?;
        let tomorrow = DateTime::new(2026, 8, 5, 12, 0, 0)?;
        check(
            &check_crl_times(yesterday, Some(tomorrow), now),
            &Ok(()),
            "current CRL",
        )?;
        check(
            &check_crl_times(yesterday, None, now),
            &Err("CRL has no nextUpdate"),
            "missing nextUpdate",
        )?;
        check(
            &check_crl_times(yesterday, Some(yesterday), now),
            &Err("CRL nextUpdate is not after thisUpdate"),
            "unordered CRL validity",
        )?;
        let two_days_ago = DateTime::new(2026, 8, 2, 12, 0, 0)?;
        check(
            &check_crl_times(two_days_ago, Some(yesterday), tomorrow),
            &Err("CRL is past nextUpdate"),
            "expired CRL",
        )
    }

    #[test]
    fn walk_guard_rejects_cycles_and_excessive_depth() -> TestResult {
        let mut cycle = WalkGuard::default();
        cycle.enter(b"same certificate")?;
        check(
            &cycle.enter(b"same certificate"),
            &Err(MaterialError::ChainCycle),
            "cycle error",
        )?;

        let mut deep = WalkGuard::default();
        for index in 0..MAX_DEPTH {
            deep.enter(&index.to_le_bytes())?;
        }
        check(
            &deep.enter(&MAX_DEPTH.to_le_bytes()),
            &Err(MaterialError::ChainTooDeep),
            "depth error",
        )
    }

    #[test]
    #[allow(
        deprecated,
        reason = "the test proves the temporary compatibility gates fail closed"
    )]
    fn legacy_anchorless_entry_points_fail_closed() -> TestResult {
        check(
            &collect(DVV_INTERMEDIATE_DER),
            &Err(MaterialError::NoTrustAnchor),
            "legacy signer collector",
        )?;
        check(
            &collect_with_timestamps(DVV_INTERMEDIATE_DER, &[]),
            &Err(MaterialError::NoTrustAnchor),
            "legacy timestamp collector",
        )
    }
}
