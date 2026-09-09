//! The evidence a signature needs to outlive its certificate.
//!
//! A level-T signature proves *when* it was made. It does not carry
//! what a verifier needs to decide whether the signing certificate was
//! good at that moment: the issuing certificates, and the revocation
//! answer for each. Today a verifier fetches those over the network,
//! and it works because the certificate is current and the responder is
//! running.
//!
//! Neither stays true. A FINEID certificate is valid for five years;
//! the OCSP responder that answers for it is a service someone operates
//! and will eventually retire. When either goes, a level-T signature
//! stops being checkable -- not because anything is wrong with it, but
//! because the evidence needed to judge it is gone.
//!
//! Level LT puts that evidence inside the document. The signature then
//! proves itself with no network at all, which is the property that
//! matters for something filed once and read years later.
//!
//! # What this module is
//!
//! A carrier. Gathering the material means fetching certificates and
//! OCSP responses, which is network work and belongs above this crate.
//! Embedding it differs per format and belongs to each format's module.
//! This is the shape they agree on.
//!
//! # Conformance
//!
//! - `ETSI EN 319 122-1` sec.6.3, `EN 319 132-1` sec.6.3,
//!   `EN 319 142-1` sec.6.3: the LT-level requirements.
//! - RFC 5940: OCSP responses inside a CMS `SignedData`.

/// Certificates and revocation answers, ready to embed.
///
/// Empty means level B or T, depending on whether a timestamp is also
/// supplied. Anything present raises the signature to LT, so a caller
/// that gathers material it cannot vouch for has weakened nothing but
/// has claimed something.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidationMaterial {
    /// DER certificates completing the chain above the signer.
    ///
    /// The signer's own certificate is already in the signature and
    /// does not belong here. The trust anchor may be omitted -- a
    /// verifier that does not already trust the root will not start
    /// because the document said so.
    pub certificates: Vec<Vec<u8>>,
    /// DER `OCSPResponse` structures, one per certificate checked.
    pub ocsp_responses: Vec<Vec<u8>>,
    /// DER `CertificateList` structures, for issuers that publish a CRL
    /// rather than answering OCSP.
    pub crls: Vec<Vec<u8>>,
}

impl ValidationMaterial {
    /// Whether there is nothing to embed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.certificates.is_empty() && self.ocsp_responses.is_empty() && self.crls.is_empty()
    }

    /// How many revocation answers are carried, of either kind.
    #[must_use]
    pub const fn revocation_count(&self) -> usize {
        self.ocsp_responses.len().saturating_add(self.crls.len())
    }
}

#[cfg(test)]
mod tests {
    use super::ValidationMaterial;

    #[test]
    fn empty_material_is_recognised_as_empty() {
        let mut material = ValidationMaterial::default();
        assert!(material.is_empty());
        assert_eq!(material.revocation_count(), 0);

        // A chain with no revocation answer is still material: it saves
        // a verifier a fetch, even though it does not on its own make
        // the signature checkable offline.
        material.certificates.push(vec![0x30, 0x00]);
        assert!(!material.is_empty());
        assert_eq!(material.revocation_count(), 0);

        material.ocsp_responses.push(vec![0x30, 0x00]);
        assert_eq!(material.revocation_count(), 1);
    }
}
