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

//! `refineid cert chain CERT [--issuer-dir DIR] [--aia-fetch]`.
//!
//! Walk the cert chain from a leaf up to a self-signed root,
//! sourcing each issuer from `DIR` first and (optionally) from
//! the cert's AIA `caIssuers` URL when the local pool misses.
//! Per-link result: who signed whom + verify outcome. Exit 0
//! if the chain reaches a self-signed root, 1 otherwise.
//!
//! AIA fetch is HTTP-only -- CA certs are self-authenticating
//! (the next hop's verify gates trust), so there's no HTTPS
//! bootstrap to do.

use alloc::fmt;
use std::path::{Path, PathBuf};

/// Helpers hosted on a unit struct (typing-discipline: no
/// free fns with borrowed parameters; see
/// `doc/typing-discipline.md`).
struct CertChainHelpers;

use refineid_lib_core::x509::{Name, OwnedCert, X509Error, extract_ca_issuers_urls};

use crate::http;
use crate::text::decode_cert_pem_or_der;

/// Cap on a single AIA HTTP fetch. CA certs are tiny -- typical
/// DVV / `WebPKI` intermediates are 1-3 KB. The cap guards
/// against a misconfigured CDP serving a giant blob; we'll never
/// see a legitimate cert near it.
const AIA_MAX_BYTES: usize = 256 * 1024;

/// One pretty-printed chain walk.
#[derive(Debug)]
pub struct CertChainReport {
    /// Filesystem path to the leaf cert (the `CERT` positional
    /// passed in on argv). Carried so the report header names
    /// the walk's starting point.
    pub root_path: PathBuf,
    /// `--issuer-dir DIR` value when supplied; surfaced so the
    /// report header records which on-disk pool the walk
    /// consulted.
    pub issuer_dir: Option<PathBuf>,
    /// Per-cert entries in walk order: leaf at index 0, then each
    /// issuer found by the search, terminating at a self-signed
    /// root (or at the first link that couldn't be resolved).
    pub links: Vec<ChainLink>,
    /// `true` when the last cert in `links` is self-signed AND
    /// its signature verifies against its own key.
    pub reaches_self_signed_root: bool,
}

/// One step in the chain walk.
#[derive(Debug)]
pub struct ChainLink {
    /// Depth from the leaf (0 = the file passed in on argv).
    pub depth: usize,
    /// Where this cert came from on disk. The leaf is the
    /// `CERT` argument; issuers come from `--issuer-dir`.
    pub source_path: PathBuf,
    /// Common Name attribute from this cert's subject DN per
    /// RFC 5280 §4.1.2.6. `None` if absent / unparseable.
    pub subject_cn: Option<refineid_lib_core::identity::CommonName>,
    /// Common Name attribute from this cert's issuer DN per
    /// RFC 5280 §4.1.2.4. `None` if absent / unparseable.
    pub issuer_cn: Option<refineid_lib_core::identity::CommonName>,
    /// Outcome of "this cert was signed by the next one in the
    /// chain". `None` on the last link if no issuer was found.
    pub verify: Option<LinkVerify>,
}

/// Outcome of one signature verification hop in the chain walk.
#[derive(Debug)]
pub enum LinkVerify {
    /// Signature verifies against the issuer cert listed in the
    /// next link.
    Ok,
    /// Same as `Ok`, but the issuer cert was discovered via an
    /// AIA HTTP fetch rather than supplied through `--issuer-dir`.
    OkViaAia {
        /// URL the issuer cert was fetched from (per RFC 5280
        /// §4.2.2.1 `id-ad-caIssuers`). Surfaced so the report
        /// names the network dependency that satisfied the walk.
        url: refineid_lib_core::text::Uri,
    },
    /// Cert is self-signed (subject DN == issuer DN) and its
    /// signature verifies against its own key. Chain terminates
    /// here.
    SelfSignedRoot,
    /// Signature is structurally invalid or the algorithm isn't
    /// implemented in lib-core's verify path.
    Failed(String),
    /// AIA fetch was attempted but the server returned a non-cert
    /// body (or a cert whose subject DN didn't match the child's
    /// issuer DN). Listed for diagnostic visibility.
    AiaFetchFailed {
        /// URL the fetch was attempted against.
        url: refineid_lib_core::text::Uri,
        /// Human-readable detail (HTTP error, parser error,
        /// subject-DN mismatch). Tier 0 `String`; presentational.
        detail: String,
    },
    /// No matching issuer cert in `--issuer-dir`, and either AIA
    /// fetch was disabled or no `caIssuers` URL was present.
    IssuerMissing,
}

/// Error returned from the chain walk entrypoint.
#[derive(Debug)]
pub enum CertChainError {
    /// Cert file I/O failure (`NotFound`, `PermissionDenied`, ...).
    Read {
        /// Filesystem path the read was attempted against.
        path: PathBuf,
        /// Underlying `std::io::Error`.
        source: std::io::Error,
    },
    /// Cert file loaded but didn't decode as DER or PEM, or the
    /// decoded bytes weren't a valid X.509 cert.
    Decode {
        /// Filesystem path the decode was attempted against.
        path: PathBuf,
        /// Human-readable decoder / parser error. Tier 0
        /// `String`; presentational.
        detail: String,
    },
    /// `--issuer-dir DIR` scan failed (directory I/O error).
    IssuerDirScan {
        /// Filesystem path the scan was attempted against.
        path: PathBuf,
        /// Underlying `std::io::Error`.
        source: std::io::Error,
    },
}

impl fmt::Display for CertChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => write!(f, "read {}: {source}", path.display()),
            Self::Decode { path, detail } => write!(f, "decode {}: {detail}", path.display()),
            Self::IssuerDirScan { path, source } => {
                write!(f, "scan issuer-dir {}: {source}", path.display())
            }
        }
    }
}

impl core::error::Error for CertChainError {}

/// Why an AIA `caIssuers` fetch failed (RFC 5280 §4.2.2.1).
#[derive(Debug)]
enum AiaFetchError {
    /// The caIssuers URL used `https`; we can't bootstrap TLS
    /// without the very cert we're fetching.
    HttpsUnsupported,
    /// The HTTP GET of the caIssuers URL failed.
    HttpGet(http::HttpError),
    /// The fetched body decoded as neither PEM nor DER.
    NotPemOrDer,
    /// The fetched bytes did not parse as an X.509 certificate.
    Parse(X509Error),
    /// The fetched cert's subject DN did not match the child's
    /// issuer DN -- it is not the cert we were climbing toward.
    SubjectDnMismatch,
}

impl fmt::Display for AiaFetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HttpsUnsupported => {
                write!(
                    f,
                    "HTTPS AIA URLs not supported; CA certs are self-authenticating"
                )
            }
            Self::HttpGet(source) => write!(f, "HTTP get: {source}"),
            Self::NotPemOrDer => write!(f, "fetched body is neither PEM nor DER cert"),
            Self::Parse(source) => write!(f, "parse fetched cert: {source}"),
            Self::SubjectDnMismatch => {
                write!(
                    f,
                    "fetched cert's subject DN doesn't match the child's issuer DN"
                )
            }
        }
    }
}

/// A cert in the issuer pool: its source (a real file path or the
/// synthetic `aia:<url>`) and the parsed cert. Parsed once at load
/// so the chain walk reads typed certs, not raw DER.
struct PoolCert {
    /// Where the cert came from (filesystem path or `aia:<url>`).
    source: PathBuf,
    /// The parsed cert.
    cert: OwnedCert,
}

/// Walk the chain from `leaf` upward toward a self-signed root.
///
/// Issuers are picked from `issuer_dir`. When `aia_fetch` is
/// true, a missing issuer triggers an HTTP fetch of the cert's
/// AIA `caIssuers` URL; the fetched cert is added to the
/// in-process pool so deeper hops can re-use it.
///
/// Caps the walk at 16 hops so a pathological directory
/// (cyclic, very deep) can't hang forever.
///
/// # Errors
/// File read, cert decode, or issuer-dir scan failure. Chain
/// breaks (missing issuer, bad signature, unsupported alg, AIA
/// fetch failure) are surfaced as a [`LinkVerify`] variant on
/// the report rather than as an error so the caller can render
/// the partial chain.
/// Outcome of a per-hop AIA caIssuers fetch.
enum AiaFetchOutcome {
    /// Cert has no caIssuers URL -- skip AIA, fall through to
    /// `IssuerMissing`.
    NoUrl,
    /// AIA fetch succeeded; the fetched cert was appended to
    /// `issuer_pool` and is also returned for the per-hop match.
    /// `url` is recorded for `LinkVerify::OkViaAia`.
    Fetched {
        /// Synthetic filesystem path (`aia:<url>`) recorded in
        /// the chain report so the source of the intermediate
        /// is unambiguous when the operator audits the run.
        path: PathBuf,
        /// The fetched intermediate cert.
        cert: OwnedCert,
        /// Source URL of the fetched cert (for the
        /// `LinkVerify::OkViaAia` provenance line).
        url: refineid_lib_core::text::Uri,
    },
    /// AIA URL existed but fetching it failed.
    Failed {
        /// URL we attempted to fetch.
        url: refineid_lib_core::text::Uri,
        /// Why the fetch failed.
        error: AiaFetchError,
    },
}

/// Try an AIA caIssuers fetch on `cert` and append the result to
/// `issuer_pool` on success.
/// Attempt an AIA `caIssuers` fetch for `cert` and (on
/// success) append the result to `issuer_pool`.
///
/// RFC 5280 §4.2.2.1 -- `caIssuers` URLs point at the
/// signing cert. The fetched cert is added to the same pool
/// used for filesystem-supplied intermediates so a deep
/// chain that re-uses one CA doesn't re-fetch on every hop.
/// Returns one of the [`AiaFetchOutcome`] variants for the
/// caller to attribute the next-hop verdict.
fn try_aia_fetch(
    cert: &refineid_lib_core::x509::Certificate<'_>,
    issuer_pool: &mut Vec<PoolCert>,
) -> AiaFetchOutcome {
    let aia_urls = cert
        .extensions
        .map(extract_ca_issuers_urls)
        .unwrap_or_default();
    let Some(url) = aia_urls.first() else {
        return AiaFetchOutcome::NoUrl;
    };
    match CertChainHelpers::fetch_aia_cert(url, cert.issuer) {
        Ok(fetched) => {
            let synthetic_path = PathBuf::from(format!("aia:{url}"));
            // Add to the pool for deeper-hop reuse, and return a copy
            // for this hop's match.
            issuer_pool.push(PoolCert {
                source: synthetic_path.clone(),
                cert: fetched.clone(),
            });
            AiaFetchOutcome::Fetched {
                path: synthetic_path,
                cert: fetched,
                url: url.clone(),
            }
        }
        Err(error) => AiaFetchOutcome::Failed {
            url: url.clone(),
            error,
        },
    }
}

/// Verdict from a self-signed cert at the chain root.
///
/// `Terminated(true)` = self-signature verified; chain ends here.
/// `Terminated(false)` = self-signature failed; chain ends here.
/// Verify a self-signed cert at the top of the chain and
/// append a terminal `ChainLink` to `links`.
///
/// RFC 5280 §6.1 step (a) -- a self-issued cert closes the
/// chain when its self-signature verifies. Returns `true` to
/// signal the walker to stop; `false` records the failure
/// but still appends a link so the report shows where the
/// chain broke. Either way the walker stops here -- there
/// is no parent to climb to.
fn process_self_signed(
    cert: &refineid_lib_core::x509::Certificate<'_>,
    depth: usize,
    source_path: PathBuf,
    subject_cn: Option<refineid_lib_core::identity::CommonName>,
    issuer_cn: Option<refineid_lib_core::identity::CommonName>,
    links: &mut Vec<ChainLink>,
) -> bool {
    match cert.verify_signed_by(*cert) {
        Ok(()) => {
            links.push(ChainLink {
                depth,
                source_path,
                subject_cn,
                issuer_cn,
                verify: Some(LinkVerify::SelfSignedRoot),
            });
            true
        }
        Err(e) => {
            links.push(ChainLink {
                depth,
                source_path,
                subject_cn,
                issuer_cn,
                verify: Some(LinkVerify::Failed(format!("self-sign: {e}"))),
            });
            false
        }
    }
}

/// Walk a cert chain from a leaf PEM/DER file up to a self-
/// signed root, returning a structured [`CertChainReport`].
///
/// RFC 5280 §6.1 (sketch -- this is not a full path-validation
/// engine). At each depth the walker looks for the issuer in
/// the pre-loaded `--issuer-dir` pool; if not found and
/// `aia_fetch` is set, it tries the leaf's AIA `caIssuers`
/// URL and appends the result to the pool. Depth is capped at
/// 16 to prevent pathological loops.
#[expect(
    clippy::too_many_lines,
    reason = "one cohesive chain-climb loop -- load leaf, then per hop: parse, self-signed check, find/AIA-fetch the issuer, verify, climb. Splitting it would scatter the carried walk state (current cert/path, depth, links) across helpers for no clarity gain."
)]
pub(crate) fn walk_chain(
    leaf: &Path,
    issuer_dir: Option<&Path>,
    aia_fetch: bool,
) -> Result<CertChainReport, CertChainError> {
    const MAX_DEPTH: usize = 16;

    // Pre-load every cert in --issuer-dir up front. Tiny memory
    // cost (a few MB at most for any realistic CA collection)
    // and we avoid re-reading the directory on every hop.
    // AIA-fetched intermediates are appended to the same pool so
    // a single fetch covers multiple deep-chain reuses.
    let mut issuer_pool: Vec<PoolCert> = match issuer_dir {
        Some(dir) => CertChainHelpers::load_issuer_dir(dir)?,
        None => Vec::new(),
    };

    let mut links: Vec<ChainLink> = Vec::new();
    let mut current_path = leaf.to_path_buf();
    let leaf_bytes = std::fs::read(&current_path).map_err(|source| CertChainError::Read {
        path: current_path.clone(),
        source,
    })?;
    let leaf_der = decode_cert_pem_or_der(&leaf_bytes).ok_or_else(|| CertChainError::Decode {
        path: current_path.clone(),
        detail: "not a PEM or DER certificate".to_owned(),
    })?;
    let mut current =
        OwnedCert::from_der(&leaf_der).map_err(|e: X509Error| CertChainError::Decode {
            path: current_path.clone(),
            detail: format!("{e}"),
        })?;
    let mut depth = 0;

    let reaches_self_signed_root = loop {
        if depth >= MAX_DEPTH {
            break false;
        }
        let cert = current.view();
        let subject_cn = cert.subject.common_name();
        let issuer_cn = cert.issuer.common_name();
        let self_signed = cert.subject == cert.issuer;

        if self_signed {
            break process_self_signed(
                &cert,
                depth,
                current_path,
                subject_cn,
                issuer_cn,
                &mut links,
            );
        }

        // Non-self-signed: find an issuer whose subject DN equals
        // this cert's issuer DN, then verify the signature.
        let mut issuer_match = CertChainHelpers::find_issuer_in_pool(&issuer_pool, cert.issuer);
        // Track whether the matched parent came from an AIA fetch
        // this turn so we can record `OkViaAia` instead of `Ok`.
        let mut aia_url_used: Option<refineid_lib_core::text::Uri> = None;

        if issuer_match.is_none() && aia_fetch {
            // Try AIA fetch. Pick the first caIssuers URL the cert
            // advertises; FINEID + WebPKI both publish one URL,
            // and the second is usually a duplicate / mirror.
            match try_aia_fetch(&cert, &mut issuer_pool) {
                AiaFetchOutcome::Fetched {
                    path,
                    cert: fetched_cert,
                    url,
                } => {
                    issuer_match = Some((path, fetched_cert));
                    aia_url_used = Some(url);
                }
                AiaFetchOutcome::NoUrl => {}
                AiaFetchOutcome::Failed { url, error } => {
                    links.push(ChainLink {
                        depth,
                        source_path: current_path,
                        subject_cn,
                        issuer_cn,
                        verify: Some(LinkVerify::AiaFetchFailed {
                            url,
                            detail: error.to_string(),
                        }),
                    });
                    break false;
                }
            }
        }

        let Some((parent_path, parent_cert)) = issuer_match else {
            links.push(ChainLink {
                depth,
                source_path: current_path,
                subject_cn,
                issuer_cn,
                verify: Some(LinkVerify::IssuerMissing),
            });
            break false;
        };

        // `parent_cert` is already parsed (the pool holds typed certs).
        let outcome = match cert.verify_signed_by(parent_cert.view()) {
            Ok(()) => aia_url_used.map_or(LinkVerify::Ok, |url| LinkVerify::OkViaAia { url }),
            Err(e) => LinkVerify::Failed(format!("{e}")),
        };
        let link_failed = matches!(outcome, LinkVerify::Failed(_));
        links.push(ChainLink {
            depth,
            source_path: current_path.clone(),
            subject_cn,
            issuer_cn,
            verify: Some(outcome),
        });
        if link_failed {
            break false;
        }

        // Walk up: next iteration starts from the issuer.
        current_path = parent_path;
        current = parent_cert;
        depth = depth.saturating_add(1);
    };

    Ok(CertChainReport {
        root_path: leaf.to_path_buf(),
        issuer_dir: issuer_dir.map(Path::to_path_buf),
        links,
        reaches_self_signed_root,
    })
}

impl CertChainHelpers {
    /// Walk the issuer pool for a cert whose subject DN matches
    /// `issuer_dn`, returning its source path and a clone of the
    /// parsed cert.
    fn find_issuer_in_pool(pool: &[PoolCert], issuer_dn: Name<'_>) -> Option<(PathBuf, OwnedCert)> {
        pool.iter()
            .find(|pc| pc.cert.view().subject == issuer_dn)
            .map(|pc| (pc.source.clone(), pc.cert.clone()))
    }

    /// Fetch a cert via AIA `caIssuers` URL and confirm its
    /// subject DN matches the child cert's `expected_issuer_dn`.
    ///
    /// RFC 5280 §4.2.2.1. Only `http://` URLs are honoured;
    /// `https://` is refused because we'd need to bootstrap
    /// TLS without the very cert we're fetching. The fetched
    /// body is decoded as PEM or raw DER; the DN equality
    /// check rejects responses that don't match the chain we
    /// were walking.
    ///
    /// # Errors
    /// [`AiaFetchError`] for each failure mode (https refused, HTTP
    /// GET failed, body not a cert, parse failed, DN mismatch).
    fn fetch_aia_cert(
        url: &refineid_lib_core::text::Uri,
        expected_issuer_dn: Name<'_>,
    ) -> Result<OwnedCert, AiaFetchError> {
        // noinspection HttpUrlsUsage -- AIA caIssuers is HTTP per RFC 5280 §4.2.2.1 (self-authenticating CA certs)
        // `Uri` guarantees an http(s) scheme. The in-tree HTTP client
        // is plain-HTTP only (same shape as the CRL / OCSP paths); CA
        // certs are self-authenticating so http:// is fine, but HTTPS
        // would need to bootstrap TLS without the very cert we're
        // fetching -- a chicken-and-egg we don't try to solve.
        if url.scheme() == refineid_lib_core::text::Scheme::Https {
            return Err(AiaFetchError::HttpsUnsupported);
        }
        let bytes = http::get(url, AIA_MAX_BYTES, crate::user_agent::honest())
            .map_err(AiaFetchError::HttpGet)?;
        // The body may be raw DER (FINEID, most WebPKI) or PEM.
        let der = decode_cert_pem_or_der(&bytes).ok_or(AiaFetchError::NotPemOrDer)?;
        let fetched = OwnedCert::from_der(&der).map_err(AiaFetchError::Parse)?;
        if fetched.view().subject != expected_issuer_dn {
            return Err(AiaFetchError::SubjectDnMismatch);
        }
        Ok(fetched)
    }
}

impl CertChainHelpers {
    /// Load every file in `dir` that decodes as a PEM or DER
    /// X.509 cert into the issuer pool, parsed once at load.
    ///
    /// Silently skips non-cert files (symlinks, junk, non-cert
    /// PEMs, certs that don't parse) so the operator can point at
    /// a real `/etc/ssl/certs`-style directory without curating it.
    /// Read failures on individual entries are swallowed; only a
    /// `read_dir` failure on the directory itself returns
    /// [`CertChainError::IssuerDirScan`].
    fn load_issuer_dir(dir: &Path) -> Result<Vec<PoolCert>, CertChainError> {
        let mut out = Vec::new();
        let entries = std::fs::read_dir(dir).map_err(|source| CertChainError::IssuerDirScan {
            path: dir.to_path_buf(),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| CertChainError::IssuerDirScan {
                path: dir.to_path_buf(),
                source,
            })?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            let Some(der) = decode_cert_pem_or_der(&bytes) else {
                continue;
            };
            let Ok(cert) = OwnedCert::from_der(&der) else {
                continue;
            };
            out.push(PoolCert { source: path, cert });
        }
        Ok(out)
    }
}

impl fmt::Display for CertChainReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "leaf: {}", self.root_path.display())?;
        if let Some(d) = &self.issuer_dir {
            writeln!(f, "issuer dir: {}", d.display())?;
        }
        for link in &self.links {
            writeln!(
                f,
                "  [{}] {} (subject CN: {})",
                link.depth,
                link.source_path.display(),
                link.subject_cn.as_deref().unwrap_or("<none>")
            )?;
            writeln!(
                f,
                "       issuer CN: {}",
                link.issuer_cn.as_deref().unwrap_or("<none>")
            )?;
            match &link.verify {
                Some(LinkVerify::Ok) => writeln!(f, "       verify: signed by parent link -- ok")?,
                Some(LinkVerify::OkViaAia { url }) => writeln!(
                    f,
                    "       verify: signed by parent link -- ok (issuer AIA-fetched from {url})"
                )?,
                Some(LinkVerify::SelfSignedRoot) => {
                    writeln!(f, "       verify: self-signed root -- ok")?;
                }
                Some(LinkVerify::Failed(s)) => writeln!(f, "       verify: FAILED ({s})")?,
                Some(LinkVerify::AiaFetchFailed { url, detail }) => {
                    writeln!(f, "       verify: AIA fetch FAILED ({url}: {detail})")?;
                }
                Some(LinkVerify::IssuerMissing) => {
                    writeln!(
                        f,
                        "       verify: no issuer cert in --issuer-dir (try --aia-fetch)"
                    )?;
                }
                None => {}
            }
        }
        writeln!(
            f,
            "chain reaches self-signed root: {}",
            if self.reaches_self_signed_root {
                "yes"
            } else {
                "no"
            }
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{TempDir, TestResult, check, check_true};
    use refineid_lib_core::text::Uri;

    // A self-signed sha256WithRSA CSCA root (PEM).
    const ICAO_CSCA_PEM: &[u8] = include_bytes!("../trust-anchors/icao-pkd-un-csca-2.pem");
    // A real two-link DVV chain: the G4E citizen intermediate
    // (leaf) is signed by the self-signed G3 ECC root. See
    // ../test-vectors/README.md for provenance.
    const DVV_INTERMEDIATE_G4E_DER: &[u8] =
        include_bytes!("../test-vectors/fineid-intermediate-01-citizen-g4e.der");
    const DVV_ROOT_ECC_DER: &[u8] = include_bytes!("../trust-anchors/dvv-gov-root-ca-g3-ecc.der");

    fn uri(s: &str) -> Result<Uri, Box<dyn core::error::Error>> {
        Uri::parse(s.to_owned()).map_err(|e| format!("uri: {e}").into())
    }

    #[test]
    fn self_signed_root_terminates_the_walk() -> TestResult {
        // Real RSA-PKCS1v15-SHA256 self-signature verification.
        let dir = TempDir::new("chain-selfsigned")?;
        let leaf = dir.write("csca.pem", ICAO_CSCA_PEM)?;
        let report = walk_chain(&leaf, None, false).map_err(|e| format!("walk: {e}"))?;
        check_true(report.reaches_self_signed_root, "reaches self-signed root")?;
        check(&report.links.len(), &1_usize, "one link")?;
        check_true(
            matches!(
                report.links.first().and_then(|l| l.verify.as_ref()),
                Some(LinkVerify::SelfSignedRoot)
            ),
            "link verify is SelfSignedRoot",
        )
    }

    #[test]
    fn two_link_chain_verifies_intermediate_against_root() -> TestResult {
        // Real ECDSA-P384/SHA-384 chain verification: the leaf is
        // the G4E intermediate, the issuer pool holds the G3 ECC
        // root it was signed by.
        let leaf_dir = TempDir::new("chain-leaf")?;
        let leaf = leaf_dir.write("g4e.der", DVV_INTERMEDIATE_G4E_DER)?;
        let issuer_dir = TempDir::new("chain-issuers")?;
        issuer_dir.write("root-ecc.der", DVV_ROOT_ECC_DER)?;

        let report =
            walk_chain(&leaf, Some(issuer_dir.path()), false).map_err(|e| format!("walk: {e}"))?;
        check_true(report.reaches_self_signed_root, "reaches self-signed root")?;
        check(&report.links.len(), &2_usize, "two links")?;
        // link 0: intermediate signed by the pool root.
        check_true(
            matches!(
                report.links.first().and_then(|l| l.verify.as_ref()),
                Some(LinkVerify::Ok)
            ),
            "leaf verifies against issuer",
        )?;
        // link 1: the root, self-signed.
        check_true(
            matches!(
                report.links.get(1).and_then(|l| l.verify.as_ref()),
                Some(LinkVerify::SelfSignedRoot)
            ),
            "issuer is the self-signed root",
        )
    }

    #[test]
    fn missing_issuer_breaks_the_chain_without_aia() -> TestResult {
        // Intermediate, but no issuer in the (empty) pool and AIA
        // off -> IssuerMissing, chain doesn't reach a root.
        let leaf_dir = TempDir::new("chain-leaf2")?;
        let leaf = leaf_dir.write("g4e.der", DVV_INTERMEDIATE_G4E_DER)?;
        let empty_issuers = TempDir::new("chain-empty")?;
        let report = walk_chain(&leaf, Some(empty_issuers.path()), false)
            .map_err(|e| format!("walk: {e}"))?;
        check_true(!report.reaches_self_signed_root, "no root reached")?;
        check_true(
            matches!(
                report.links.first().and_then(|l| l.verify.as_ref()),
                Some(LinkVerify::IssuerMissing)
            ),
            "IssuerMissing",
        )
    }

    #[test]
    fn issuer_dir_silently_skips_non_cert_files() -> TestResult {
        // A junk file alongside the real root must not derail the
        // pool load; the chain still resolves.
        let leaf_dir = TempDir::new("chain-leaf3")?;
        let leaf = leaf_dir.write("g4e.der", DVV_INTERMEDIATE_G4E_DER)?;
        let issuer_dir = TempDir::new("chain-mixed")?;
        issuer_dir.write("notes.txt", b"this is not a certificate\n")?;
        issuer_dir.write("root-ecc.der", DVV_ROOT_ECC_DER)?;
        let report =
            walk_chain(&leaf, Some(issuer_dir.path()), false).map_err(|e| format!("walk: {e}"))?;
        check_true(
            report.reaches_self_signed_root,
            "junk skipped, root still found",
        )
    }

    #[test]
    fn tampered_self_signature_is_reported_as_failed() -> TestResult {
        // Flip the last DER byte (inside the signature BIT STRING):
        // the cert still parses and is still self-signed by DN, but
        // its signature no longer verifies.
        let mut tampered = decode_cert_pem_or_der(ICAO_CSCA_PEM).ok_or("decode")?;
        let last = tampered.len().checked_sub(1).ok_or("empty der")?;
        *tampered.get_mut(last).ok_or("index out of range")? ^= 0xFF;
        let dir = TempDir::new("chain-tampered")?;
        let leaf = dir.write("bad.der", &tampered)?;
        let report = walk_chain(&leaf, None, false).map_err(|e| format!("walk: {e}"))?;
        check_true(!report.reaches_self_signed_root, "tampered root rejected")?;
        check_true(
            matches!(
                report.links.first().and_then(|l| l.verify.as_ref()),
                Some(LinkVerify::Failed(_))
            ),
            "link verify is Failed",
        )
    }

    #[test]
    fn missing_leaf_file_is_a_read_error() -> TestResult {
        let dir = TempDir::new("chain-noleaf")?;
        let leaf = dir.path().join("nope.der");
        check_true(
            matches!(
                walk_chain(&leaf, None, false),
                Err(CertChainError::Read { .. })
            ),
            "Read error",
        )
    }

    #[test]
    fn undecodable_leaf_is_a_decode_error() -> TestResult {
        let dir = TempDir::new("chain-badleaf")?;
        let leaf = dir.write("junk.bin", b"\x30\x05not-a-cert")?;
        check_true(
            matches!(
                walk_chain(&leaf, None, false),
                Err(CertChainError::Decode { .. })
            ),
            "Decode error",
        )
    }

    #[test]
    fn missing_issuer_dir_is_a_scan_error() -> TestResult {
        // The pool is loaded up front, so a bad --issuer-dir fails
        // the whole walk before any link is processed.
        let dir = TempDir::new("chain-baddir")?;
        let leaf = dir.write("csca.pem", ICAO_CSCA_PEM)?;
        let missing_dir = dir.path().join("no-such-dir");
        check_true(
            matches!(
                walk_chain(&leaf, Some(&missing_dir), false),
                Err(CertChainError::IssuerDirScan { .. })
            ),
            "IssuerDirScan error",
        )
    }

    #[test]
    fn chain_error_display() -> TestResult {
        check_true(
            CertChainError::Read {
                path: PathBuf::from("/c.der"),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "gone"),
            }
            .to_string()
            .contains("read /c.der: gone"),
            "read",
        )?;
        check_true(
            CertChainError::Decode {
                path: PathBuf::from("/c.der"),
                detail: "bad TLV".to_owned(),
            }
            .to_string()
            .contains("decode /c.der: bad TLV"),
            "decode",
        )?;
        check_true(
            CertChainError::IssuerDirScan {
                path: PathBuf::from("/dir"),
                source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
            }
            .to_string()
            .contains("scan issuer-dir /dir: denied"),
            "issuer-dir scan",
        )
    }

    /// Build a report whose links cover every [`LinkVerify`]
    /// variant -- including `OkViaAia` and `AiaFetchFailed`, which
    /// the offline tests above can't reach without a network
    /// fetch -- and assert each renders its own line.
    #[test]
    fn report_display_covers_every_link_verdict() -> TestResult {
        let link = |depth, verify| ChainLink {
            depth,
            source_path: PathBuf::from(format!("/p{depth}")),
            subject_cn: None,
            issuer_cn: None,
            verify: Some(verify),
        };
        let report = CertChainReport {
            root_path: PathBuf::from("/leaf.der"),
            issuer_dir: Some(PathBuf::from("/issuers")),
            links: vec![
                link(0, LinkVerify::Ok),
                link(
                    1,
                    LinkVerify::OkViaAia {
                        url: uri("http://ca.example/i.crt")?,
                    },
                ),
                link(2, LinkVerify::Failed("bad sig".to_owned())),
                link(
                    3,
                    LinkVerify::AiaFetchFailed {
                        url: uri("http://ca.example/x.crt")?,
                        detail: "404".to_owned(),
                    },
                ),
                link(4, LinkVerify::IssuerMissing),
                link(5, LinkVerify::SelfSignedRoot),
            ],
            reaches_self_signed_root: true,
        };
        let s = report.to_string();
        check_true(s.contains("leaf: /leaf.der"), "header")?;
        check_true(s.contains("issuer dir: /issuers"), "issuer dir line")?;
        check_true(s.contains("signed by parent link -- ok"), "Ok")?;
        check_true(
            s.contains("AIA-fetched from http://ca.example/i.crt"),
            "OkViaAia",
        )?;
        check_true(s.contains("FAILED (bad sig)"), "Failed")?;
        check_true(s.contains("AIA fetch FAILED"), "AiaFetchFailed")?;
        check_true(
            s.contains("no issuer cert in --issuer-dir"),
            "IssuerMissing",
        )?;
        check_true(s.contains("self-signed root -- ok"), "SelfSignedRoot")?;
        check_true(s.contains("chain reaches self-signed root: yes"), "footer")
    }
}
