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

//! Revocation orchestration: tie a parsed [`crate::x509::Certificate`]
//! to a parsed [`crate::crl::Crl`] or [`crate::ocsp::OcspResponse`]
//! and surface a single [`RevocationStatus`].
//!
//! Scope is deliberately narrow:
//!
//! - **Signature verification is not done here.** Callers must
//!   verify the CRL / OCSP response signature against a trusted
//!   issuer cert *before* calling in. A bare-bones "look up the
//!   serial" path with no signature check is exactly how MITM
//!   attacks succeed; this module makes that contract explicit
//!   instead of pretending it doesn't exist.
//! - **Time-validity is checked relative to an
//!   [`crate::x509::DateTime`] supplied by the caller**, not via
//!   any system clock. lib-core stays I/O-free; the binding to
//!   `SystemTime` (or whatever clock the use case needs) lives
//!   one layer up.
//!
//! The module ships in full; the card-status subcommand that
//! consumes it is queued.

use crate::crl::VerifiedCrl;
use crate::ocsp::{CertStatus, VerifiedOcspResponse};
use crate::x509::{Certificate, DateTime};

/// Result of a single revocation check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationStatus {
    /// Cert is on neither the CRL nor an OCSP `revoked` reply.
    Good,
    /// The supplied revocation source doesn't apply to this
    /// cert:
    ///
    /// - CRL: the CRL's issuer DN doesn't match `cert.issuer`.
    /// - OCSP: top-level status was not `successful`, the response
    ///   body wasn't a basic OCSP response, or no
    ///   `SingleResponse` for the target certificate's full `CertID` was present.
    ///
    /// The typed [`InapplicableReason`] surfaces which case fired.
    Inapplicable(InapplicableReason),
    /// Cert is revoked. `at` and `reason` come straight from the
    /// CRL entry or OCSP `RevokedInfo`.
    Revoked {
        /// `revocationDate` from the CRL entry per RFC 5280
        /// §5.3.1, or OCSP `revocationTime` per RFC 6960
        /// §4.2.2.2.
        at: DateTime,
        /// `CRLReason`, when supplied. `None` means the issuer
        /// didn't include a reason.
        reason: Option<crate::crl::CrlReason>,
    },
    /// The supplied revocation source is stale: `now > nextUpdate`.
    Stale,
    /// CRL or OCSP responder reported the cert as unknown.
    /// (For CRL this is impossible -- only OCSP has a "not on
    /// our books" status.)
    Unknown,
}

/// Why a supplied revocation source did not apply to the cert under
/// check.
///
/// The closed set of [`RevocationStatus::Inapplicable`] cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InapplicableReason {
    /// CRL path: the CRL's `issuer` DN does not match the cert's
    /// `issuer`, so this CRL says nothing about this cert.
    CrlIssuerMismatch,
    /// OCSP path: the verified response carried no `SingleResponse`
    /// for the target's full issuer-name hash, issuer-key hash, and serial.
    OcspNoMatchingCertId,
}

impl core::fmt::Display for InapplicableReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = match *self {
            Self::CrlIssuerMismatch => "CRL issuer DN mismatch",
            Self::OcspNoMatchingCertId => "OCSP response had no exact CertID entry",
        };
        f.write_str(text)
    }
}

/// Check a cert against a **verified** CRL.
///
/// Takes a [`VerifiedCrl`], not a raw parsed CRL: the type makes it
/// impossible to consult a revocation list without having verified
/// the CRL signature first (trust by construction).
///
/// Returns [`RevocationStatus::Inapplicable`] when the CRL was
/// issued by a different issuer than the cert,
/// [`RevocationStatus::Stale`] when `now > crl.nextUpdate`, and
/// otherwise `Good` / `Revoked`.
#[inline]
#[must_use]
pub fn check_against_crl(
    cert: Certificate<'_>,
    crl: &VerifiedCrl<'_>,
    now: DateTime,
) -> RevocationStatus {
    let crl = crl.as_crl();
    if crl.issuer != cert.issuer {
        return RevocationStatus::Inapplicable(InapplicableReason::CrlIssuerMismatch);
    }
    if let Some(next) = crl.next_update
        && now > next
    {
        return RevocationStatus::Stale;
    }
    crl.find_serial(&cert.serial())
        .map_or(RevocationStatus::Good, |entry| RevocationStatus::Revoked {
            at: entry.revocation_date,
            reason: entry.reason,
        })
}

/// Check a cert against a **verified** basic OCSP response.
///
/// Takes a [`VerifiedOcspResponse`], not a raw parsed response: the
/// type makes it impossible to read a revocation status without
/// having verified the responder signature first (trust by
/// construction). The top-level `successful` / basic-OCSP checks
/// happen earlier, where the response is verified -- a
/// `VerifiedOcspResponse` only exists for a successful, basic reply.
///
/// Returns [`RevocationStatus::Inapplicable`] when no
/// `SingleResponse` matches the target's exact SHA-1 `CertID`, and
/// [`RevocationStatus::Stale`] when `now > nextUpdate` of the
/// matching `SingleResponse` (if `nextUpdate` is present).
#[inline]
#[must_use]
pub fn check_against_ocsp_response(
    cert: Certificate<'_>,
    response: &VerifiedOcspResponse<'_>,
    now: DateTime,
) -> RevocationStatus {
    let Some(single) = response.response_for(cert) else {
        return RevocationStatus::Inapplicable(InapplicableReason::OcspNoMatchingCertId);
    };
    if let Some(next) = single.next_update
        && now > next
    {
        return RevocationStatus::Stale;
    }
    match single.status {
        CertStatus::Good => RevocationStatus::Good,
        CertStatus::Revoked { revoked_at, reason } => RevocationStatus::Revoked {
            at: revoked_at,
            reason,
        },
        CertStatus::Unknown => RevocationStatus::Unknown,
    }
}

/// Which source produced a revocation verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationSource {
    /// An OCSP responder reply (RFC 6960).
    Ocsp,
    /// A certificate revocation list (RFC 5280).
    Crl,
}

/// A signature-verified, timestamped revocation verdict for one
/// certificate.
///
/// Trust by construction: built only from a [`VerifiedOcspResponse`]
/// / [`VerifiedCrl`], so the verdict is signature-checked, never a
/// forgeable read. Carries when it was obtained (`checked_at`) and
/// the source's `nextUpdate` (`valid_until`) so a consumer can tell
/// fresh from stale. The inner value of the card object's
/// `Option<RevocationEvidence>` slot. See
/// `doc/security/revocation-cache.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationEvidence {
    /// The verified verdict.
    status: RevocationStatus,
    /// Which source produced it.
    source: RevocationSource,
    /// Time the check was performed.
    checked_at: DateTime,
    /// Source `nextUpdate`, when present -- the freshness window.
    valid_until: Option<DateTime>,
}

impl RevocationEvidence {
    /// Build evidence from a verified OCSP response: the verdict plus
    /// the matching `SingleResponse`'s `nextUpdate`. `now` is the
    /// time of the check.
    #[must_use]
    pub fn from_ocsp(
        cert: Certificate<'_>,
        verified: &VerifiedOcspResponse<'_>,
        now: DateTime,
    ) -> Self {
        let status = check_against_ocsp_response(cert, verified, now);
        let valid_until = verified.response_for(cert).and_then(|r| r.next_update);
        Self {
            status,
            source: RevocationSource::Ocsp,
            checked_at: now,
            valid_until,
        }
    }

    /// Build evidence from a verified CRL: the verdict plus the CRL's
    /// `nextUpdate`.
    #[must_use]
    pub fn from_crl(cert: Certificate<'_>, verified: &VerifiedCrl<'_>, now: DateTime) -> Self {
        Self {
            status: check_against_crl(cert, verified, now),
            source: RevocationSource::Crl,
            checked_at: now,
            valid_until: verified.as_crl().next_update,
        }
    }

    /// The verified revocation verdict.
    #[must_use]
    pub const fn status(&self) -> RevocationStatus {
        self.status
    }

    /// Which source produced the verdict.
    #[must_use]
    pub const fn source(&self) -> RevocationSource {
        self.source
    }

    /// When the check was performed.
    #[must_use]
    pub const fn checked_at(&self) -> DateTime {
        self.checked_at
    }

    /// `true` while still inside the validity window
    /// (`now <= nextUpdate`). Evidence with no `nextUpdate` is never
    /// considered fresh beyond the check itself -- a non-revoked
    /// verdict without a window must be re-obtained.
    #[must_use]
    pub fn is_fresh(&self, now: DateTime) -> bool {
        self.valid_until
            .is_some_and(|valid_until| now <= valid_until)
    }
}

/// In-memory revocation-evidence cache, keyed by `(issuer DN, serial)`.
///
/// **In-memory only -- never persisted.** An on-disk cache would
/// create the persistent trace `doc/observability.md` forbids ("a
/// successful Suomi.fi login leaves no persistent trace") and a
/// poisoning surface. It is a *passive* store: it performs no network
/// I/O and is populated only by an explicit [`insert`](Self::insert),
/// so it can never become a per-use beacon. Lookup is asymmetric: a
/// cached `Revoked` is sticky (a cert never un-revokes); every other
/// verdict is served only inside its validity window. See
/// `doc/security/revocation-cache.md`.
#[derive(Debug, Default)]
pub struct RevocationCache {
    /// Evidence keyed by the cert's owned (issuer, serial) identity.
    /// A plain `Vec` linear-scanned by [`CachedCertId`] equality
    /// rather than a `HashMap`: the key's halves are ASN.1 domain
    /// types (`x509_cert::name::Name` has no `Hash`), and a
    /// revocation cache only ever holds the few certs of one
    /// verification chain, so linear scan is not a cost.
    entries: Vec<CacheEntry>,
}

/// One cached (cert identity -> revocation evidence) association.
/// Named rather than a bare `(CachedCertId, RevocationEvidence)`
/// tuple because the cache hand-rolls its own scan, so the halves
/// are read by name here instead of by tuple position.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Identity of the cert this evidence is about.
    id: CachedCertId,
    /// The verified revocation verdict for that cert.
    evidence: RevocationEvidence,
}

/// Owned (issuer, serial) identity of a certificate -- the standard
/// RFC 5652 "issuer and serial number" pairing -- used as the
/// revocation-cache key. Owned (not the borrowed `Name<'a>` / serial
/// views) because the cache outlives any single [`Certificate`]
/// borrow, and built from ecosystem ASN.1 types so the key carries
/// its meaning rather than riding as anonymous bytes. Equality is
/// the structural DN/serial match used for chain building.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedCertId {
    /// Issuer Distinguished Name (owned, structurally parsed).
    issuer: x509_cert::name::Name,
    /// Certificate serial number.
    serial: crate::identity::CertSerial,
}

impl CachedCertId {
    /// Build the owned identity from `cert`'s borrowed issuer DN and
    /// serial. Fallible because materialising the borrowed issuer DN
    /// into an owned [`x509_cert::name::Name`] is a strict DER
    /// reparse; `None` when that reparse rejects the DN (a cert our
    /// lenient cert-parse accepted but x509-cert's strict `RDNSequence`
    /// decode does not). A `None` key simply means "do not cache this
    /// cert" -- the caller re-checks, so correctness never depends on
    /// the cache succeeding.
    fn for_cert(cert: Certificate<'_>) -> Option<Self> {
        use x509_cert::der::Decode as _;
        let issuer = x509_cert::name::Name::from_der(cert.issuer.as_der()).ok()?;
        Some(Self {
            issuer,
            serial: cert.serial(),
        })
    }
}

impl RevocationCache {
    /// Store evidence for `cert`, replacing any prior evidence for the
    /// same identity. Population is always explicit -- the cache never
    /// fetches anything itself. A cert whose issuer DN fails the strict
    /// key reparse is silently not cached (the cache key cannot be
    /// built, so the caller re-checks).
    pub fn insert(&mut self, cert: Certificate<'_>, evidence: RevocationEvidence) {
        let Some(id) = CachedCertId::for_cert(cert) else {
            return;
        };
        if let Some(slot) = self.entries.iter_mut().find(|entry| entry.id == id) {
            slot.evidence = evidence;
        } else {
            self.entries.push(CacheEntry { id, evidence });
        }
    }

    /// Look up usable evidence for `cert` at `now`. A cached `Revoked`
    /// is returned regardless of age (sticky); any other verdict only
    /// while still fresh. Returns `None` on a miss or a stale
    /// non-revoked entry, so the caller re-checks rather than trusting
    /// a stale `good`.
    #[must_use]
    pub fn get(&self, cert: Certificate<'_>, now: DateTime) -> Option<&RevocationEvidence> {
        let id = CachedCertId::for_cert(cert)?;
        let evidence = self
            .entries
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| &entry.evidence)?;
        let usable =
            matches!(evidence.status, RevocationStatus::Revoked { .. }) || evidence.is_fresh(now);
        usable.then_some(evidence)
    }
}

#[cfg(test)]
mod tests {

    use super::{
        RevocationCache, RevocationEvidence, RevocationSource, RevocationStatus, check_against_crl,
        check_against_ocsp_response,
    };
    use crate::ber::{BerTag as _, Oid, Sequence, Set, Utf8String};
    use crate::crl::{Crl, VerifiedCrl};
    use crate::ocsp::{
        IssuerKeyHash, IssuerNameHash, OcspResponse, OcspResponseStatus, VerifiedOcspResponse,
    };
    use crate::x509::{Certificate, DateTime};

    /// Wrap a parsed synthetic OCSP response as
    /// [`VerifiedOcspResponse`] WITHOUT a real signature check --
    /// these tests exercise the status-translation logic in
    /// isolation (the signature path has its own tests). Panics if
    /// the response carries no basic body.
    fn verified_for_test(resp: OcspResponse<'_>) -> VerifiedOcspResponse<'_> {
        let basic = resp.basic.expect("basic OCSP body");
        VerifiedOcspResponse::from_unverified_basic_for_test(
            basic,
            IssuerNameHash::new([0xAA; 20]),
            IssuerKeyHash::new([0xBB; 20]),
        )
    }

    // BER universal-class tag bytes the fixture builders below
    // splat into Vec<u8>.  The structural tags are derived from the
    // `BerTag` marker impls in `ber.rs` so the fixture wire-shape
    // stays in lockstep with the parser the tests exercise; the two
    // time tags are X.690 universal primitives (UTCTime 0x17,
    // GeneralizedTime 0x18) now decoded by x509-cert, so they are
    // named directly here.
    const TAG_OID: u8 = single_byte_tag(Oid::TAG);
    const TAG_UTF8STRING: u8 = single_byte_tag(Utf8String::TAG);
    const TAG_UTCTIME: u8 = 0x17;
    const TAG_GENERALIZEDTIME: u8 = 0x18;
    const TAG_SEQUENCE: u8 = single_byte_tag(Sequence::TAG);
    const TAG_SET: u8 = single_byte_tag(Set::TAG);

    /// Convert a `BerTag::TAG` (`u16`) to its single-byte wire form.
    /// Panics at compile time (when used in a const initialiser) if
    /// the tag does not fit in one byte.
    const fn single_byte_tag(tag: u16) -> u8 {
        let [high_byte, low_byte] = tag.to_be_bytes();
        assert!(high_byte == 0, "BER tag does not fit in a single byte");
        low_byte
    }

    // OID value bytes for `id-at-commonName` (2.5.4.3) per
    // RFC 5280 §A.1.  Bare value -- no tag, no length prefix.
    const OID_AT_COMMON_NAME: [u8; 3] = [0x55, 0x04, 0x03];

    const DER_SHORT_FORM_CEILING: u8 = 0x80;

    fn push_len(out: &mut Vec<u8>, n: usize) {
        match u8::try_from(n) {
            Ok(short) if short < DER_SHORT_FORM_CEILING => out.push(short),
            Ok(short) => {
                out.push(0x81);
                out.push(short);
            }
            Err(_) => {
                let long = u16::try_from(n).expect("test TLV lengths fit in u16");
                let [high_byte, low_byte] = long.to_be_bytes();
                out.push(0x82);
                out.push(high_byte);
                out.push(low_byte);
            }
        }
    }

    fn wrap(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(value.len() + 4);
        v.push(tag);
        push_len(&mut v, value.len());
        v.extend_from_slice(value);
        v
    }

    fn utc_time(yymmddhhmmss: &str) -> Vec<u8> {
        let mut v = vec![TAG_UTCTIME, 13];
        v.extend_from_slice(yymmddhhmmss.as_bytes());
        v.push(b'Z');
        v
    }

    fn gen_time(yyyymmddhhmmss: &str) -> Vec<u8> {
        let mut v = vec![TAG_GENERALIZEDTIME, 15];
        v.extend_from_slice(yyyymmddhhmmss.as_bytes());
        v.push(b'Z');
        v
    }

    /// Build an `AttributeTypeAndValue` for
    /// `id-at-commonName = <utf8>` per RFC 5280 §A.1, then wrap it
    /// in a one-entry RDN SET inside the outer Name SEQUENCE.  The
    /// `cn_utf8` parameter is the UTF-8 bytes of the common name
    /// (e.g. `b"Issuer"`).
    fn cn_rdn_sequence(cn_utf8: &[u8]) -> Vec<u8> {
        let cn_value_tlv = wrap(TAG_UTF8STRING, cn_utf8);
        let oid_tlv = wrap(TAG_OID, &OID_AT_COMMON_NAME);
        let mut atv_body = oid_tlv;
        atv_body.extend_from_slice(&cn_value_tlv);
        let atv = wrap(TAG_SEQUENCE, &atv_body);
        let rdn = wrap(TAG_SET, &atv);
        wrap(TAG_SEQUENCE, &rdn)
    }

    /// `CN=Issuer`.
    fn issuer_name() -> Vec<u8> {
        cn_rdn_sequence(b"Issuer")
    }

    /// `CN=Different`.
    fn different_issuer() -> Vec<u8> {
        cn_rdn_sequence(b"Different")
    }

    fn subject_name() -> Vec<u8> {
        cn_rdn_sequence(b"Alice")
    }

    fn build_cert(serial: &[u8], issuer: &[u8]) -> Vec<u8> {
        let sig_alg: Vec<u8> = vec![
            0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05,
            0x00,
        ];
        let spki = wrap(0x30, &{
            let mut b = sig_alg.clone();
            b.extend_from_slice(&[0x03, 0x05, 0x00, 0xAA, 0xBB, 0xCC, 0xDD]);
            b
        });
        let validity = {
            let mut body = Vec::new();
            body.extend_from_slice(&utc_time("260101000000"));
            body.extend_from_slice(&utc_time("310101000000"));
            wrap(0x30, &body)
        };
        let mut tbs_body = Vec::new();
        tbs_body.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x02]);
        tbs_body.extend_from_slice(&wrap(0x02, serial));
        tbs_body.extend_from_slice(&sig_alg);
        tbs_body.extend_from_slice(issuer);
        tbs_body.extend_from_slice(&validity);
        tbs_body.extend_from_slice(&subject_name());
        tbs_body.extend_from_slice(&spki);
        let tbs = wrap(0x30, &tbs_body);
        let signature: Vec<u8> = vec![0x03, 0x05, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        let mut outer_body = Vec::new();
        outer_body.extend_from_slice(&tbs);
        outer_body.extend_from_slice(&sig_alg);
        outer_body.extend_from_slice(&signature);
        wrap(0x30, &outer_body)
    }

    fn build_crl(
        revoked_serial: Option<&[u8]>,
        issuer: &[u8],
        next_update: Option<&str>,
    ) -> Vec<u8> {
        let version = vec![0x02, 0x01, 0x01];
        let sig_alg: Vec<u8> = vec![
            0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05,
            0x00,
        ];
        let this_update = utc_time("260520120000");

        let mut tbs_body = Vec::new();
        tbs_body.extend_from_slice(&version);
        tbs_body.extend_from_slice(&sig_alg);
        tbs_body.extend_from_slice(issuer);
        tbs_body.extend_from_slice(&this_update);
        if let Some(nu) = next_update {
            tbs_body.extend_from_slice(&utc_time(nu));
        }
        if let Some(serial) = revoked_serial {
            let mut entry_body = Vec::new();
            entry_body.extend_from_slice(&wrap(0x02, serial));
            entry_body.extend_from_slice(&utc_time("260301000000"));
            let entry = wrap(0x30, &entry_body);
            let revoked_seq = wrap(0x30, &entry);
            tbs_body.extend_from_slice(&revoked_seq);
        }
        let tbs = wrap(0x30, &tbs_body);
        let signature: Vec<u8> = vec![0x03, 0x05, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        let mut outer_body = Vec::new();
        outer_body.extend_from_slice(&tbs);
        outer_body.extend_from_slice(&sig_alg);
        outer_body.extend_from_slice(&signature);
        wrap(0x30, &outer_body)
    }

    fn build_ocsp_response(
        serial: &[u8],
        status_tag: u8,
        status_value: &[u8],
        next_update: Option<&str>,
        top_status: u8,
    ) -> Vec<u8> {
        // Build a SingleResponse and wrap up through the basic-OCSP
        // hierarchy. Reuses the synthetic builder logic from
        // ocsp::tests by re-implementing it locally.
        let alg = {
            let mut b = vec![0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A];
            b.extend_from_slice(&[0x05, 0x00]);
            wrap(0x30, &b)
        };
        let cert_id = {
            let name_hash = wrap(0x04, &[0xAA; 20]);
            let key_hash = wrap(0x04, &[0xBB; 20]);
            let serial_int = wrap(0x02, serial);
            let mut body = Vec::new();
            body.extend_from_slice(&alg);
            body.extend_from_slice(&name_hash);
            body.extend_from_slice(&key_hash);
            body.extend_from_slice(&serial_int);
            wrap(0x30, &body)
        };
        let mut cert_status = vec![status_tag];
        push_len(&mut cert_status, status_value.len());
        cert_status.extend_from_slice(status_value);
        let this_update = gen_time("20260520120000");
        let mut sr_body = Vec::new();
        sr_body.extend_from_slice(&cert_id);
        sr_body.extend_from_slice(&cert_status);
        sr_body.extend_from_slice(&this_update);
        if let Some(nu) = next_update {
            let nu_time = gen_time(nu);
            let wrapped = wrap(0xA0, &nu_time);
            sr_body.extend_from_slice(&wrapped);
        }
        let single = wrap(0x30, &sr_body);

        let responder_id_by_key = {
            let key = [0xCC; 20];
            let key_octet = wrap(0x04, &key);
            wrap(0xA2, &key_octet)
        };
        let produced_at = gen_time("20260520120000");
        let responses_seq = wrap(0x30, &single);
        let mut tbs_body = Vec::new();
        tbs_body.extend_from_slice(&responder_id_by_key);
        tbs_body.extend_from_slice(&produced_at);
        tbs_body.extend_from_slice(&responses_seq);
        let tbs_response_data = wrap(0x30, &tbs_body);

        let sig_alg: Vec<u8> = vec![
            0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05,
            0x00,
        ];
        let signature: Vec<u8> = vec![0x03, 0x05, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        let mut basic_body = Vec::new();
        basic_body.extend_from_slice(&tbs_response_data);
        basic_body.extend_from_slice(&sig_alg);
        basic_body.extend_from_slice(&signature);
        let basic = wrap(0x30, &basic_body);

        let response_type: Vec<u8> = vec![
            0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01,
        ];
        let response_octet = wrap(0x04, &basic);
        let mut rb_body = Vec::new();
        rb_body.extend_from_slice(&response_type);
        rb_body.extend_from_slice(&response_octet);
        let rb_seq = wrap(0x30, &rb_body);
        let rb_explicit = wrap(0xA0, &rb_seq);

        let status_enum = vec![0x0A, 0x01, top_status];
        let mut body = Vec::new();
        body.extend_from_slice(&status_enum);
        body.extend_from_slice(&rb_explicit);
        wrap(0x30, &body)
    }

    fn now() -> DateTime {
        DateTime::new(2026, 5, 23, 0, 0, 0).expect("valid test instant")
    }

    #[test]
    fn crl_good_when_serial_not_present() {
        let cert_der = build_cert(&[0x01], &issuer_name());
        let cert = Certificate::from_der(&cert_der).expect("cert");
        let crl_der = build_crl(None, &issuer_name(), Some("260620120000"));
        let crl = VerifiedCrl::from_unverified_for_test(Crl::parse(&crl_der).expect("crl"));
        assert_eq!(check_against_crl(cert, &crl, now()), RevocationStatus::Good);
    }

    #[test]
    fn crl_revoked_when_serial_present() {
        let cert_der = build_cert(&[0x01], &issuer_name());
        let cert = Certificate::from_der(&cert_der).expect("cert");
        let crl_der = build_crl(Some(&[0x01]), &issuer_name(), Some("260620120000"));
        let crl = VerifiedCrl::from_unverified_for_test(Crl::parse(&crl_der).expect("crl"));
        let status = check_against_crl(cert, &crl, now());
        assert!(matches!(status, RevocationStatus::Revoked { .. }));
    }

    #[test]
    fn crl_inapplicable_when_issuer_mismatch() {
        let cert_der = build_cert(&[0x01], &issuer_name());
        let cert = Certificate::from_der(&cert_der).expect("cert");
        let crl_der = build_crl(None, &different_issuer(), Some("260620120000"));
        let crl = VerifiedCrl::from_unverified_for_test(Crl::parse(&crl_der).expect("crl"));
        assert!(matches!(
            check_against_crl(cert, &crl, now()),
            RevocationStatus::Inapplicable(_)
        ));
    }

    #[test]
    fn crl_stale_when_now_past_next_update() {
        let cert_der = build_cert(&[0x01], &issuer_name());
        let cert = Certificate::from_der(&cert_der).expect("cert");
        // nextUpdate = 2026-05-22, now = 2026-05-23 -> stale.
        let crl_der = build_crl(None, &issuer_name(), Some("260522120000"));
        let crl = VerifiedCrl::from_unverified_for_test(Crl::parse(&crl_der).expect("crl"));
        assert_eq!(
            check_against_crl(cert, &crl, now()),
            RevocationStatus::Stale
        );
    }

    #[test]
    fn ocsp_good_translates() {
        let cert_der = build_cert(&[0x01, 0x23], &issuer_name());
        let cert = Certificate::from_der(&cert_der).expect("cert");
        let resp_der = build_ocsp_response(&[0x01, 0x23], 0x80, &[], Some("20260622120000"), 0);
        let verified = verified_for_test(OcspResponse::parse(&resp_der).expect("ocsp"));
        assert_eq!(
            check_against_ocsp_response(cert, &verified, now()),
            RevocationStatus::Good
        );
    }

    #[test]
    fn ocsp_same_serial_under_different_issuer_hash_is_inapplicable() {
        let cert_der = build_cert(&[0x01, 0x23], &issuer_name());
        let cert = Certificate::from_der(&cert_der).expect("cert");
        let resp_der = build_ocsp_response(&[0x01, 0x23], 0x80, &[], Some("20260622120000"), 0);
        let basic = OcspResponse::parse(&resp_der)
            .expect("ocsp")
            .basic
            .expect("basic OCSP body");
        let wrong_issuer = VerifiedOcspResponse::from_unverified_basic_for_test(
            basic,
            IssuerNameHash::new([0xAC; 20]),
            IssuerKeyHash::new([0xBB; 20]),
        );
        assert!(matches!(
            check_against_ocsp_response(cert, &wrong_issuer, now()),
            RevocationStatus::Inapplicable(_)
        ));
    }

    #[test]
    fn ocsp_revoked_translates() {
        let cert_der = build_cert(&[0x42], &issuer_name());
        let cert = Certificate::from_der(&cert_der).expect("cert");
        // RevokedInfo: SEQUENCE { revocationTime, [0] CRLReason }
        let revocation_time = gen_time("20260501080000");
        let reason_explicit = {
            let enum_body = vec![0x0A, 0x01, 0x04]; // superseded
            wrap(0xA0, &enum_body)
        };
        let mut revoked_info = Vec::new();
        revoked_info.extend_from_slice(&revocation_time);
        revoked_info.extend_from_slice(&reason_explicit);
        let resp_der = build_ocsp_response(&[0x42], 0xA1, &revoked_info, Some("20260622120000"), 0);
        let verified = verified_for_test(OcspResponse::parse(&resp_der).expect("ocsp"));
        let status = check_against_ocsp_response(cert, &verified, now());
        match status {
            RevocationStatus::Revoked { reason, .. } => {
                assert_eq!(reason, Some(crate::crl::CrlReason::Superseded));
            }
            RevocationStatus::Good
            | RevocationStatus::Inapplicable(_)
            | RevocationStatus::Stale
            | RevocationStatus::Unknown => panic!("expected Revoked, got {status:?}"),
        }
    }

    #[test]
    fn ocsp_unknown_translates() {
        let cert_der = build_cert(&[0x07], &issuer_name());
        let cert = Certificate::from_der(&cert_der).expect("cert");
        let resp_der = build_ocsp_response(&[0x07], 0x82, &[], None, 0);
        let verified = verified_for_test(OcspResponse::parse(&resp_der).expect("ocsp"));
        assert_eq!(
            check_against_ocsp_response(cert, &verified, now()),
            RevocationStatus::Unknown
        );
    }

    #[test]
    fn try_later_response_has_no_verifiable_body() {
        // responseStatus = tryLater (3): no basic body, so it can
        // never become a VerifiedOcspResponse -- the status is
        // unreadable by construction, which is stronger than the old
        // runtime Inapplicable check.
        let resp_der = wrap(0x30, &[0x0A, 0x01, 0x03]);
        let resp = OcspResponse::parse(&resp_der).expect("ocsp parse");
        assert!(resp.basic.is_none());
        assert_ne!(resp.status, OcspResponseStatus::Successful);
    }

    #[test]
    fn ocsp_inapplicable_when_serial_not_in_response() {
        let cert_der = build_cert(&[0x99], &issuer_name());
        let cert = Certificate::from_der(&cert_der).expect("cert");
        let resp_der = build_ocsp_response(&[0x01], 0x80, &[], None, 0);
        let verified = verified_for_test(OcspResponse::parse(&resp_der).expect("ocsp"));
        assert!(matches!(
            check_against_ocsp_response(cert, &verified, now()),
            RevocationStatus::Inapplicable(_)
        ));
    }

    #[test]
    fn ocsp_stale_when_now_past_next_update() {
        let cert_der = build_cert(&[0x01], &issuer_name());
        let cert = Certificate::from_der(&cert_der).expect("cert");
        // nextUpdate 2026-05-22; now 2026-05-23 -> stale.
        let resp_der = build_ocsp_response(&[0x01], 0x80, &[], Some("20260522120000"), 0);
        let verified = verified_for_test(OcspResponse::parse(&resp_der).expect("ocsp"));
        assert_eq!(
            check_against_ocsp_response(cert, &verified, now()),
            RevocationStatus::Stale
        );
    }

    // A date after the fixtures' 2026-06-22 nextUpdate windows.
    fn after_window() -> DateTime {
        DateTime::new(2026, 7, 1, 0, 0, 0).expect("valid test instant")
    }

    #[test]
    fn evidence_from_verified_ocsp_carries_status_source_window() {
        let cert_der = build_cert(&[0x01, 0x23], &issuer_name());
        let cert = Certificate::from_der(&cert_der).expect("cert");
        let resp_der = build_ocsp_response(&[0x01, 0x23], 0x80, &[], Some("20260622120000"), 0);
        let verified = verified_for_test(OcspResponse::parse(&resp_der).expect("ocsp"));
        let evidence = RevocationEvidence::from_ocsp(cert, &verified, now());
        assert_eq!(evidence.status(), RevocationStatus::Good);
        assert_eq!(evidence.source(), RevocationSource::Ocsp);
        assert!(evidence.is_fresh(now())); // 2026-05-23 <= 2026-06-22
        assert!(!evidence.is_fresh(after_window())); // 2026-07-01 > window
    }

    #[test]
    fn evidence_from_verified_crl_carries_status_source() {
        let cert_der = build_cert(&[0x01], &issuer_name());
        let cert = Certificate::from_der(&cert_der).expect("cert");
        let crl_der = build_crl(None, &issuer_name(), Some("260620120000"));
        let crl = VerifiedCrl::from_unverified_for_test(Crl::parse(&crl_der).expect("crl"));
        let evidence = RevocationEvidence::from_crl(cert, &crl, now());
        assert_eq!(evidence.status(), RevocationStatus::Good);
        assert_eq!(evidence.source(), RevocationSource::Crl);
    }

    #[test]
    fn cache_serves_fresh_good_misses_stale_good() {
        let cert_der = build_cert(&[0x01, 0x23], &issuer_name());
        let cert = Certificate::from_der(&cert_der).expect("cert");
        let resp_der = build_ocsp_response(&[0x01, 0x23], 0x80, &[], Some("20260622120000"), 0);
        let verified = verified_for_test(OcspResponse::parse(&resp_der).expect("ocsp"));
        let evidence = RevocationEvidence::from_ocsp(cert, &verified, now());

        let mut cache = RevocationCache::default();
        cache.insert(cert, evidence);
        // Fresh: within the window -> hit.
        assert!(cache.get(cert, now()).is_some());
        // Stale good: past nextUpdate -> miss (caller must re-check).
        assert!(cache.get(cert, after_window()).is_none());
    }

    #[test]
    fn cache_serves_revoked_even_when_stale() {
        let cert_der = build_cert(&[0x42], &issuer_name());
        let cert = Certificate::from_der(&cert_der).expect("cert");
        // RevokedInfo: SEQUENCE { revocationTime, [0] CRLReason }.
        let revocation_time = gen_time("20260501080000");
        let reason_explicit = wrap(0xA0, &[0x0A, 0x01, 0x04]);
        let mut revoked_info = Vec::new();
        revoked_info.extend_from_slice(&revocation_time);
        revoked_info.extend_from_slice(&reason_explicit);
        let resp_der = build_ocsp_response(&[0x42], 0xA1, &revoked_info, Some("20260622120000"), 0);
        let verified = verified_for_test(OcspResponse::parse(&resp_der).expect("ocsp"));
        // Checked while fresh -> verdict is Revoked, window 2026-06-22.
        let evidence = RevocationEvidence::from_ocsp(cert, &verified, now());
        assert!(matches!(
            evidence.status(),
            RevocationStatus::Revoked { .. }
        ));

        let mut cache = RevocationCache::default();
        cache.insert(cert, evidence);
        // Past the window, Revoked is still served (sticky).
        assert!(cache.get(cert, after_window()).is_some());
    }

    #[test]
    fn cache_misses_unknown_cert() {
        let cert_der = build_cert(&[0xAB], &issuer_name());
        let cert = Certificate::from_der(&cert_der).expect("cert");
        let cache = RevocationCache::default();
        assert!(cache.get(cert, now()).is_none());
    }
}
