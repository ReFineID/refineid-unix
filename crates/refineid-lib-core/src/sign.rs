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

//! Card-side signing primitives for FINEID.
//!
//! Minimal sign-chain for the SHA-256 + RSA-PKCS1v15 path against
//! the auth key (key reference `0x01`). The flow is the spec-
//! mandated three-APDU choreography:
//!
//! 1. **MSE:Set DST** `00 22 41 B6` -- pin the security environment
//!    to (algRef = 0x42, key ref = 0x01). On every catalogued
//!    FINEID variant the wire byte for SHA-256+RSA-PKCS1v15 is
//!    `0x42` (FINEID S1 v4.2 §3.6.4).
//! 2. **PSO:HASH** `00 2A 90 A0` with the pre-computed 32-byte
//!    SHA-256 digest in the `90 20 ...` "external hash" DO. The
//!    card adds the SHA-256 `DigestInfo` prefix internally before
//!    `PKCS1v15` padding -- caller ships the raw hash, not the
//!    `DigestInfo`.
//! 3. **PSO:CDS** `00 2A 9E 9A` with empty Lc -- the card signs the
//!    previously stored hash and returns the raw RSA-3072
//!    signature (384 B).
//!
//! VERIFY PIN1 (see [`crate::auth`]) must succeed before
//! `sign_pre_hashed_sha256_rsa_auth` is called; the card returns
//! `SW=6982` (security status not satisfied) otherwise. The PIN
//! state stays valid for the rest of the card session.
//!
//! Scope: only the **auth key** RSA-PKCS1v15-SHA256 path is wired
//! here. The qualified-signature key, ECDSA cards, RSA-PSS, and
//! the data-driven PSO:HASH-then-CDS paths are intentionally
//! out of scope -- this is a pre-hash path tailored for
//! `refineid card sign-auth`.

use crate::apdu::iso7816::ApduClass;
use crate::crypto::container::{
    Ciphertext, EcdsaP256, EcdsaP384, Plaintext, RsaPkcs1, RsaPkcs1Sha256, Signature,
};
use crate::crypto::digest::{Sha1, Sha224, Sha256, Sha384, Sha512};
use crate::transport::{CardTransport, TransportDispatchError};

/// Shortened transport-error alias for sign-path dispatchers.
/// Same pattern as the auth-flow and PACE aliases; saves
/// repeating the nested generic in every `Result` return type
/// across the sign module.
type TxError<T> = TransportDispatchError<<T as CardTransport>::Error>;

pub mod asic;
pub mod cades;
pub mod commands;
pub mod document;
pub mod pades;
pub mod timestamp;
pub mod validation;
pub mod xades;

/// PKCS#15 key reference for the FINEID **auth key** -- the one
/// used for TLS client cert / SSH / agent identity. FINEID S1
/// v4.2 §3.5.
pub const KEY_REF_AUTH: u8 = 0x01;

/// PKCS#15 key reference for the FINEID **qualified-signature
/// key** -- non-repudiation, PIN2-gated. Provided for callers that
/// need to dispatch on slot; this module's sign chain only drives
/// the auth slot.
pub const KEY_REF_SIGN: u8 = 0x02;

/// PKCS#15 key reference enum, typed at the sign-API boundary.
///
/// Per FINEID S1 v4.2 §3.5 the card publishes exactly two
/// private-key references: `0x01` (auth) and `0x02` (qualified
/// signature). `KeyRef` captures the dispatch at the type level
/// so the sign / decrypt chain refuses arbitrary `u8` values --
/// only `Auth` and `Sign` cross the boundary; the runtime byte
/// is emitted at the MSE:Set DST/CT APDU build site via
/// [`KeyRef::as_u8`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyRef {
    /// Authentication key, PIN1-gated. Wire byte `0x01`.
    Auth,
    /// Qualified-signature key, PIN2-gated. Wire byte `0x02`.
    Sign,
}

impl KeyRef {
    /// The card-side reference byte for MSE:Set DST/CT.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Auth => KEY_REF_AUTH,
            Self::Sign => KEY_REF_SIGN,
        }
    }
}

/// Expected signature length for RSA-3072: 384 bytes. Every
/// catalogued FINEID auth-key returns exactly this many bytes
/// from PSO:CDS under algRef = 0x42.
pub const RSA_3072_SIG_BYTES: usize = 384;

/// Expected signature length for ECDSA over secp384r1 (NIST
/// P-384) in raw `r || s` form: 48 + 48 = 96 bytes.
///
/// FINEID S1 v4.2 §3.8.3 specifies the response as "r || s,
/// where r and s are integers and are the co-ordinates of the
/// point on the elliptic curve". No DER wrapper, no length
/// prefixes.
pub const ECDSA_P384_SIG_BYTES: usize = 96;

/// Expected signature length for ECDSA over secp256r1 (NIST
/// P-256) in raw `r || s` form: 32 + 32 = 64 bytes. Same
/// no-DER-wrapper convention as [`ECDSA_P384_SIG_BYTES`].
pub const ECDSA_P256_SIG_BYTES: usize = 64;

/// SHA-256 digest size: 32 bytes.
pub const SHA256_DIGEST_LEN: usize = 32;

/// SHA-384 digest size: 48 bytes.
pub const SHA384_DIGEST_LEN: usize = 48;

/// Sign-path errors.
#[derive(Debug)]
pub enum SignError<TE> {
    /// Transport-layer failure.
    Transport(TE),
    /// Card returned a non-success SW at the labelled stage.
    Sw(&'static str, u16),
    /// Card returned a signature of an unexpected length. Expected
    /// `RSA_3072_SIG_BYTES` for the algRef-0x42 auth-key path; any
    /// other length surfaces hardware misconfiguration or a key
    /// that isn't RSA-3072 (e.g. an ECC v4.0 card on a code path
    /// that hard-codes RSA).
    UnexpectedSignatureLength(usize),
    /// Host input cannot be represented by the ISO 7816 APDU
    /// length field used by the signing command.
    InputTooLong(usize),
}

impl<TE: core::fmt::Display> core::fmt::Display for SignError<TE> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "sign transport: {e}"),
            Self::Sw(stage, sw) => write!(f, "sign {stage}: card returned SW={sw:#06X}"),
            Self::UnexpectedSignatureLength(n) => {
                write!(
                    f,
                    "sign: card returned {n}-byte signature; expected {RSA_3072_SIG_BYTES} (RSA-3072)"
                )
            }
            Self::InputTooLong(n) => write!(
                f,
                "sign: {n}-byte input exceeds the ISO 7816 signing command length"
            ),
        }
    }
}

impl<TE: core::fmt::Debug + core::fmt::Display + 'static> core::error::Error for SignError<TE> {}

/// FINEID sign / decrypt chain layered as default-impl methods on
/// every [`CardTransport`].
///
/// The trait keeps these APIs out of the "`pub fn` with borrowed
/// parameters" category and groups the wire helpers
/// (`mse_set_dst`, `pso_hash_external_sha256`, etc.) as trait
/// methods on `&mut self`. Import via
/// `use refineid_lib_core::sign::SignOps;` -- the blanket impl
/// below applies to every transport. Helper methods are public-by-
/// trait but expected to be invoked only through the high-level
/// `sign_pre_hashed_sha256_rsa*` / `decrypt_rsa_pkcs1_auth` entry
/// points; their wire shapes are documented for callers that need
/// to compose a non-canonical chain.
pub trait SignOps: CardTransport {
    /// `MSE:Set DST` -- pin the security environment for the next
    /// signing PSO chain. Wire: `00 22 41 B6 06 80 01 <algRef>
    /// 84 01 <keyRef>`. Helper for [`SignOps::sign_pre_hashed_sha256_rsa`].
    ///
    /// # Errors
    /// Transport failure or non-9000 SW from the card.
    fn mse_set_dst(
        &mut self,
        alg_ref: commands::SignatureAlgRef,
        key_ref: KeyRef,
    ) -> Result<(), SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        let apdu = commands::MseSet {
            class: ApduClass::Plain,
            template: commands::MseSetTemplate::DigitalSignature { alg_ref, key_ref },
        }
        .into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(SignError::Transport)?;
        if !r.is_ok() {
            return Err(SignError::Sw("MSE:Set DST", r.sw()));
        }
        Ok(())
    }

    /// `MSE:Set CT` -- pin the security environment for a
    /// subsequent PSO:DECIPHER. Wire: `00 22 41 B8 06 80 01
    /// <algRef> 84 01 <keyRef>`.
    ///
    /// # Errors
    /// Transport failure or non-9000 SW from the card.
    fn mse_set_ct(
        &mut self,
        alg_ref: commands::DecipherAlgRef,
        key_ref: KeyRef,
    ) -> Result<(), SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        let apdu = commands::MseSet {
            class: ApduClass::Plain,
            template: commands::MseSetTemplate::DeciphermentRsa { alg_ref, key_ref },
        }
        .into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(SignError::Transport)?;
        if !r.is_ok() {
            return Err(SignError::Sw("MSE:Set CT", r.sw()));
        }
        Ok(())
    }

    /// `MSE:Set AT` -- same body shape as `MSE:Set DST` but the
    /// Authentication Template (P2 = `A4h`). FINEID cards gate the
    /// raw-PKCS signing primitive on the auth key behind the AT.
    /// Wire: `00 22 41 A4 06 80 01 <algRef> 84 01 <keyRef>`.
    ///
    /// # Errors
    /// Transport failure or non-9000 SW from the card.
    fn mse_set_at(
        &mut self,
        alg_ref: commands::SignatureAlgRef,
        key_ref: KeyRef,
    ) -> Result<(), SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        let apdu = commands::MseSet {
            class: ApduClass::Plain,
            template: commands::MseSetTemplate::Authentication { alg_ref, key_ref },
        }
        .into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(SignError::Transport)?;
        if !r.is_ok() {
            return Err(SignError::Sw("MSE:Set AT", r.sw()));
        }
        Ok(())
    }

    /// `PSO:CDS` with a host-supplied data field -- the card signs
    /// the given bytes directly under the raw security environment
    /// previously selected via `MSE:Set AT` / `MSE:Set DST`.
    ///
    /// Blocks longer than 255 bytes (every RSA-3072 encoded
    /// message: 384 B) are shipped with ISO 7816-4 command
    /// chaining: a first chunk under CLA `10h`, the final chunk
    /// under CLA `00h` with Le = 0 so the transport GET-RESPONSE
    /// chain fetches the full signature.
    ///
    /// # Errors
    /// Transport failure or non-9000 SW at either chunk.
    fn pso_cds_with_data<Alg>(
        &mut self,
        data: &[u8],
    ) -> Result<Signature<Alg>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        const PSO_CDS_HEADER: [u8; 4] = [
            0x00,
            commands::PsoComputeDigitalSignature::INS,
            commands::PsoComputeDigitalSignature::P1,
            commands::PsoComputeDigitalSignature::P2,
        ];
        const PSO_CDS_CHAINED_HEADER: [u8; 4] = [
            0x10,
            commands::PsoComputeDigitalSignature::INS,
            commands::PsoComputeDigitalSignature::P1,
            commands::PsoComputeDigitalSignature::P2,
        ];
        if data.len() <= 255 {
            let data_len =
                u8::try_from(data.len()).map_err(|_| SignError::InputTooLong(data.len()))?;
            let mut apdu = Vec::with_capacity(5 + data.len() + 1);
            apdu.extend_from_slice(&PSO_CDS_HEADER);
            apdu.push(data_len);
            apdu.extend_from_slice(data);
            apdu.push(0x00);
            let r = self.transmit(&apdu).map_err(SignError::Transport)?;
            if !r.is_ok() {
                return Err(SignError::Sw("PSO:CDS data", r.sw()));
            }
            return Ok(Signature::new(r.body));
        }
        // Extended-length form first: FINEID cards accept the whole
        // RSA-3072 block (384 B) in one extended APDU and reject the
        // chained form with 6985 (hardware-proven). Chaining below
        // stays as the fallback for readers that cannot ship
        // extended APDUs.
        let mut ext = Vec::with_capacity(7 + data.len() + 2);
        let data_len =
            u16::try_from(data.len()).map_err(|_| SignError::InputTooLong(data.len()))?;
        ext.extend_from_slice(&PSO_CDS_HEADER);
        ext.push(0x00);
        ext.extend_from_slice(&data_len.to_be_bytes());
        ext.extend_from_slice(data);
        ext.extend_from_slice(&0_u16.to_be_bytes());
        let ext_sw = if let Ok(r) = self.transmit(&ext) {
            if r.is_ok() {
                return Ok(Signature::new(r.body));
            }
            r.sw()
        } else {
            0
        };
        // Command chaining keeps RSA-3072 raw blocks (384 B) inside
        // short-form APDUs.
        let half = data.len() / 2;
        let (first, second) = data.split_at(half);
        let first_len =
            u8::try_from(first.len()).map_err(|_| SignError::InputTooLong(data.len()))?;
        let second_len =
            u8::try_from(second.len()).map_err(|_| SignError::InputTooLong(data.len()))?;

        let mut apdu1 = Vec::with_capacity(5 + first.len());
        apdu1.extend_from_slice(&PSO_CDS_CHAINED_HEADER);
        apdu1.push(first_len);
        apdu1.extend_from_slice(first);
        let r1 = self.transmit(&apdu1).map_err(SignError::Transport)?;
        if !r1.is_ok() {
            // Surface the extended-form SW when it also failed --
            // the chained SW alone hides the primary rejection.
            if ext_sw != 0 {
                return Err(SignError::Sw("PSO:CDS extended", ext_sw));
            }
            return Err(SignError::Sw("PSO:CDS chunk 1/2", r1.sw()));
        }

        let mut apdu2 = Vec::with_capacity(5 + second.len() + 1);
        apdu2.extend_from_slice(&PSO_CDS_HEADER);
        apdu2.push(second_len);
        apdu2.extend_from_slice(second);
        apdu2.push(0x00);
        let r2 = self.transmit(&apdu2).map_err(SignError::Transport)?;
        if !r2.is_ok() {
            return Err(SignError::Sw("PSO:CDS chunk 2/2", r2.sw()));
        }
        Ok(Signature::new(r2.body))
    }

    /// Raw RSA private-key operation over a host-encoded block
    /// (EMSA-PSS or any other RFC 8017 encoding) against `key_ref`.
    ///
    /// The auth key selects the security environment via `MSE:Set
    /// AT` (FINEID gates raw-PKCS client-auth signing behind the
    /// Authentication Template); the qualified-signature key uses
    /// the regular DST. Both use algRef `40h` (RSA-PKCS, no hash
    /// indicated) and ship `encoded` through `PSO:CDS` with
    /// command chaining.
    ///
    /// Used by RSA-PSS consumers: TLS 1.3
    /// `CertificateVerify` requires RSASSA-PSS, the card only pads
    /// PKCS#1 v1.5 internally, so the host performs EMSA-PSS
    /// encoding and the card does the private-key operation only.
    ///
    /// # Errors
    /// Transport failure or a non-9000 SW at any stage.
    fn sign_rsa_raw(
        &mut self,
        key_ref: KeyRef,
        encoded: &[u8],
    ) -> Result<Signature<RsaPkcs1>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        match key_ref {
            KeyRef::Auth => self.mse_set_at(commands::SignatureAlgRef::RSA_PKCS1_RAW, key_ref)?,
            KeyRef::Sign => self.mse_set_dst(commands::SignatureAlgRef::RSA_PKCS1_RAW, key_ref)?,
        }
        self.pso_cds_with_data::<RsaPkcs1>(encoded)
    }

    /// `PSO:HASH` external hash form: ship the pre-computed
    /// SHA-256 digest in the `90 20 <hash>` DO. Wire: `00 2A 90
    /// A0 22 90 20 <32-byte-hash>`. Helper for
    /// [`SignOps::sign_pre_hashed_sha256_rsa`].
    ///
    /// # Errors
    /// Transport failure or non-9000 SW from the card.
    fn pso_hash_external_sha256(&mut self, hash: Sha256) -> Result<(), SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        let apdu = commands::PsoHash {
            class: ApduClass::Plain,
            mode: commands::PsoHashMode::External {
                hash: commands::ExternalHashValue::Sha256(*hash.as_bytes()),
            },
        }
        .into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(SignError::Transport)?;
        if !r.is_ok() {
            return Err(SignError::Sw("PSO:HASH", r.sw()));
        }
        Ok(())
    }

    /// `PSO:HASH` external hash form for SHA-1: ship the pre-computed
    /// digest in the `90 10 <hash>` DO. Wire: `00 2A 90 A0 16 90 10
    /// <20-byte-hash>`. Helper for the ECDSA-P384 sign chain when a
    /// relying party still requests SHA-1.
    ///
    /// # Errors
    /// Transport failure or non-9000 SW from the card.
    fn pso_hash_external_sha1(&mut self, hash: Sha1) -> Result<(), SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        let apdu = commands::PsoHash {
            class: ApduClass::Plain,
            mode: commands::PsoHashMode::External {
                hash: commands::ExternalHashValue::Sha1(*hash.as_bytes()),
            },
        }
        .into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(SignError::Transport)?;
        if !r.is_ok() {
            return Err(SignError::Sw("PSO:HASH", r.sw()));
        }
        Ok(())
    }

    /// `PSO:HASH` external hash form for SHA-384: ship the pre-
    /// computed digest in the `90 30 <hash>` DO. Wire: `00 2A 90
    /// A0 32 90 30 <48-byte-hash>`. Helper for the ECDSA-P384
    /// sign chain (FINEID S4-1 v4.2 §4.2 Newer-scheme ECC P-384).
    ///
    /// # Errors
    /// Transport failure or non-9000 SW from the card.
    fn pso_hash_external_sha384(&mut self, hash: Sha384) -> Result<(), SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        let apdu = commands::PsoHash {
            class: ApduClass::Plain,
            mode: commands::PsoHashMode::External {
                hash: commands::ExternalHashValue::Sha384(*hash.as_bytes()),
            },
        }
        .into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(SignError::Transport)?;
        if !r.is_ok() {
            return Err(SignError::Sw("PSO:HASH", r.sw()));
        }
        Ok(())
    }

    /// `PSO:HASH` external hash form for SHA-512: ship the pre-computed
    /// digest in the `90 60 <hash>` DO. Wire: `00 2A 90 A0 42 90 60
    /// <64-byte-hash>`. Helper for the ECDSA-P384 sign chain when a
    /// relying party requests SHA-512.
    ///
    /// # Errors
    /// Transport failure or non-9000 SW from the card.
    fn pso_hash_external_sha512(&mut self, hash: Sha512) -> Result<(), SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        let apdu = commands::PsoHash {
            class: ApduClass::Plain,
            mode: commands::PsoHashMode::External {
                hash: commands::ExternalHashValue::Sha512(*hash.as_bytes()),
            },
        }
        .into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(SignError::Transport)?;
        if !r.is_ok() {
            return Err(SignError::Sw("PSO:HASH", r.sw()));
        }
        Ok(())
    }

    /// `PSO:HASH` external hash form for SHA-224: ship the pre-
    /// computed digest in the `90 20 <hash>` DO. Wire: `00 2A 90
    /// A0 22 90 20 <28-byte-hash>`. Helper for the ECDSA-P384
    /// sign chain where the trust-service profile requests
    /// SHA-224.
    ///
    /// # Errors
    /// Transport failure or non-9000 SW from the card.
    fn pso_hash_external_sha224(&mut self, hash: Sha224) -> Result<(), SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        let apdu = commands::PsoHash {
            class: ApduClass::Plain,
            mode: commands::PsoHashMode::External {
                hash: commands::ExternalHashValue::Sha224(*hash.as_bytes()),
            },
        }
        .into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(SignError::Transport)?;
        if !r.is_ok() {
            return Err(SignError::Sw("PSO:HASH", r.sw()));
        }
        Ok(())
    }

    /// `PSO:CDS` with an explicit `Le` -- the card signs the previously
    /// stored hash. Wire: `00 2A 9E 9A <le>`.
    ///
    /// The algorithm marker is a type parameter so the returned
    /// [`Signature<Alg>`] reflects what `MSE:Set DST` selected.
    /// Length is **not** validated here; the caller decides what
    /// length is correct for the algorithm (RSA-3072 = 384,
    /// ECDSA P-384 raw r||s = 96, etc.) and surfaces the
    /// mismatch as [`SignError::UnexpectedSignatureLength`].
    ///
    /// [`Signature<Alg>`]: Signature
    ///
    /// # Errors
    /// Transport failure or non-9000 SW.
    fn pso_cds_empty<Alg>(&mut self, le: u8) -> Result<Signature<Alg>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        let apdu = commands::PsoComputeDigitalSignature {
            class: ApduClass::Plain,
        }
        .into_apdu_with_le(le);
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(SignError::Transport)?;
        if !r.is_ok() {
            return Err(SignError::Sw("PSO:CDS", r.sw()));
        }
        Ok(Signature::new(r.body))
    }

    /// SHA-256 + RSA-PKCS1v15 sign chain for any FINEID RSA key.
    /// Drives MSE:Set DST + PSO:HASH + PSO:CDS against `key_ref`.
    ///
    /// `hash` is consumed by value (`Sha256` is `Copy`).
    ///
    /// # Errors
    /// Transport failure, a card SW other than `0x9000` at any
    /// stage, or a signature length other than
    /// [`RSA_3072_SIG_BYTES`].
    fn sign_pre_hashed_sha256_rsa(
        &mut self,
        key_ref: KeyRef,
        hash: Sha256,
    ) -> Result<Signature<RsaPkcs1Sha256>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.mse_set_dst(commands::SignatureAlgRef::SHA256_RSA_PKCS1_V1_5, key_ref)?;
        self.pso_hash_external_sha256(hash)?;
        let sig = self
            .pso_cds_empty::<RsaPkcs1Sha256>(commands::PsoComputeDigitalSignature::LE_MAX_SHORT)?;
        if sig.len() != RSA_3072_SIG_BYTES {
            return Err(SignError::UnexpectedSignatureLength(sig.len()));
        }
        Ok(sig)
    }

    /// [`Self::sign_pre_hashed_sha256_rsa`] in the organizational
    /// card's form: no PSO:HASH, the off-card digest rides in the
    /// PSO:CDS data field (organizational cards specification
    /// §6.6.2.3). The `MultiApp` external-hash DO answers `6A80` on
    /// that platform, which is how the two forms tell apart.
    ///
    /// # Errors
    /// As [`Self::sign_pre_hashed_sha256_rsa`].
    fn sign_pre_hashed_sha256_rsa_hash_in_command(
        &mut self,
        key_ref: KeyRef,
        hash: Sha256,
    ) -> Result<Signature<RsaPkcs1Sha256>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.mse_set_dst(commands::SignatureAlgRef::SHA256_RSA_PKCS1_V1_5, key_ref)?;
        let apdu = commands::PsoComputeDigitalSignature {
            class: ApduClass::Plain,
        }
        .into_apdu_with_hash(
            hash.as_bytes(),
            commands::PsoComputeDigitalSignature::LE_MAX_SHORT,
        );
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(SignError::Transport)?;
        if !r.is_ok() {
            return Err(SignError::Sw("PSO:CDS", r.sw()));
        }
        let sig = Signature::<RsaPkcs1Sha256>::new(r.body);
        if sig.len() != RSA_3072_SIG_BYTES {
            return Err(SignError::UnexpectedSignatureLength(sig.len()));
        }
        Ok(sig)
    }

    /// SHA-384 + ECDSA P-384 sign chain for FINEID Newer-scheme
    /// ECC keys (S4-1 v4.2 §4.2 auth key / qualified-signature
    /// ECC key, both `secp384r1`).
    ///
    /// Drives MSE:Set DST (algRef `54h`) + PSO:HASH (SHA-384
    /// external) + PSO:CDS against `key_ref`. The returned
    /// signature is the raw `r || s` form per S1 v4.2 §3.8.3,
    /// 96 bytes total (48 + 48). Caller is responsible for
    /// converting to DER if a downstream verifier needs that
    /// encoding.
    ///
    /// # Errors
    /// Transport failure, a card SW other than `0x9000` at any
    /// stage, or a signature length other than
    /// [`ECDSA_P384_SIG_BYTES`].
    fn sign_pre_hashed_sha384_ecdsa_p384(
        &mut self,
        key_ref: KeyRef,
        hash: Sha384,
    ) -> Result<Signature<EcdsaP384>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.mse_set_dst(commands::SignatureAlgRef::SHA384_ECDSA, key_ref)?;
        self.pso_hash_external_sha384(hash)?;
        let sig =
            self.pso_cds_empty::<EcdsaP384>(commands::PsoComputeDigitalSignature::LE_ECDSA_P384)?;
        if sig.len() != ECDSA_P384_SIG_BYTES {
            return Err(SignError::UnexpectedSignatureLength(sig.len()));
        }
        Ok(sig)
    }

    /// ECDSA P-384 over a pre-computed SHA-1 digest. Same key and curve
    /// as the SHA-384 path; only the algRef and digest length differ.
    ///
    /// # Errors
    /// Transport failure, a card SW other than `0x9000` at any stage,
    /// or a signature length other than [`ECDSA_P384_SIG_BYTES`].
    fn sign_pre_hashed_sha1_ecdsa_p384(
        &mut self,
        key_ref: KeyRef,
        hash: Sha1,
    ) -> Result<Signature<EcdsaP384>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.mse_set_dst(
            commands::SignatureAlgRef::from_parts(
                commands::HashAlgorithm::Sha1,
                commands::SignatureAlgorithm::Ecdsa,
            ),
            key_ref,
        )?;
        self.pso_hash_external_sha1(hash)?;
        let sig =
            self.pso_cds_empty::<EcdsaP384>(commands::PsoComputeDigitalSignature::LE_ECDSA_P384)?;
        if sig.len() != ECDSA_P384_SIG_BYTES {
            return Err(SignError::UnexpectedSignatureLength(sig.len()));
        }
        Ok(sig)
    }

    /// ECDSA P-384 over a pre-computed SHA-224 digest. Same key and
    /// curve as [`Self::sign_pre_hashed_sha384_ecdsa_p384`]; only the
    /// algRef (`34h`) and the external-hash length (28 bytes) differ.
    /// Some trust-service profiles request this shape alongside
    /// ECDSA+SHA-256 for P-384 keys.
    ///
    /// # Errors
    /// Transport failure, a card SW other than `0x9000` at any stage,
    /// or a signature length other than [`ECDSA_P384_SIG_BYTES`].
    fn sign_pre_hashed_sha224_ecdsa_p384(
        &mut self,
        key_ref: KeyRef,
        hash: Sha224,
    ) -> Result<Signature<EcdsaP384>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.mse_set_dst(commands::SignatureAlgRef::SHA224_ECDSA, key_ref)?;
        self.pso_hash_external_sha224(hash)?;
        let sig =
            self.pso_cds_empty::<EcdsaP384>(commands::PsoComputeDigitalSignature::LE_ECDSA_P384)?;
        if sig.len() != ECDSA_P384_SIG_BYTES {
            return Err(SignError::UnexpectedSignatureLength(sig.len()));
        }
        Ok(sig)
    }

    /// ECDSA P-384 over a pre-computed SHA-512 digest.
    ///
    /// # Errors
    /// Transport failure, a card SW other than `0x9000` at any stage,
    /// or a signature length other than [`ECDSA_P384_SIG_BYTES`].
    fn sign_pre_hashed_sha512_ecdsa_p384(
        &mut self,
        key_ref: KeyRef,
        hash: Sha512,
    ) -> Result<Signature<EcdsaP384>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.mse_set_dst(
            commands::SignatureAlgRef::from_parts(
                commands::HashAlgorithm::Sha512,
                commands::SignatureAlgorithm::Ecdsa,
            ),
            key_ref,
        )?;
        self.pso_hash_external_sha512(hash)?;
        let sig =
            self.pso_cds_empty::<EcdsaP384>(commands::PsoComputeDigitalSignature::LE_ECDSA_P384)?;
        if sig.len() != ECDSA_P384_SIG_BYTES {
            return Err(SignError::UnexpectedSignatureLength(sig.len()));
        }
        Ok(sig)
    }

    /// ECDSA P-384 over a pre-computed SHA-256 digest. Same key and
    /// curve as [`Self::sign_pre_hashed_sha384_ecdsa_p384`]; only the
    /// algRef (`44h`) and the external-hash length (32 bytes) differ.
    /// macOS `SecureTransport` requests ECDSA+SHA-256 for the suomi.fi
    /// kortti TLS-1.2 `CertificateVerify` even with a P-384 key. Returns
    /// the raw `r || s` (96 bytes).
    ///
    /// # Errors
    /// Transport failure, a card SW other than `0x9000` at any stage,
    /// or a signature length other than [`ECDSA_P384_SIG_BYTES`].
    fn sign_pre_hashed_sha256_ecdsa_p384(
        &mut self,
        key_ref: KeyRef,
        hash: Sha256,
    ) -> Result<Signature<EcdsaP384>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.mse_set_dst(commands::SignatureAlgRef::SHA256_ECDSA, key_ref)?;
        self.pso_hash_external_sha256(hash)?;
        let sig =
            self.pso_cds_empty::<EcdsaP384>(commands::PsoComputeDigitalSignature::LE_ECDSA_P384)?;
        if sig.len() != ECDSA_P384_SIG_BYTES {
            return Err(SignError::UnexpectedSignatureLength(sig.len()));
        }
        Ok(sig)
    }

    /// Auth-slot convenience wrapper for
    /// [`SignOps::sign_pre_hashed_sha256_rsa`].
    ///
    /// # Errors
    /// See [`SignOps::sign_pre_hashed_sha256_rsa`].
    fn sign_pre_hashed_sha256_rsa_auth(
        &mut self,
        hash: Sha256,
    ) -> Result<Signature<RsaPkcs1Sha256>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.sign_pre_hashed_sha256_rsa(KeyRef::Auth, hash)
    }

    /// Qualified-signature-slot convenience wrapper for
    /// [`SignOps::sign_pre_hashed_sha256_rsa`]. Targets key ref
    /// `0x02`. **Caller must have verified PIN2** in this
    /// session.
    ///
    /// # Errors
    /// See [`SignOps::sign_pre_hashed_sha256_rsa`].
    fn sign_pre_hashed_sha256_rsa_qualified(
        &mut self,
        hash: Sha256,
    ) -> Result<Signature<RsaPkcs1Sha256>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.sign_pre_hashed_sha256_rsa(KeyRef::Sign, hash)
    }

    /// `PSO:DECIPHER` -- RSA decrypt the ciphertext under the
    /// key pinned by [`SignOps::mse_set_ct`]. For RSA-3072 the
    /// body is `1 + 384 = 385` B (exceeds short-form Lc=255), so
    /// chaining splits at the halfway point.
    ///
    /// Caller is responsible for VERIFY PIN1 + MSE:Set CT before
    /// invoking this method.
    ///
    /// # Errors
    /// Transport failure or non-9000 SW from any chunk.
    fn pso_decipher(
        &mut self,
        ciphertext: Ciphertext<RsaPkcs1>,
    ) -> Result<Plaintext<RsaPkcs1>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        let ct_bytes = ciphertext.as_bytes();
        let mut body = Vec::with_capacity(ct_bytes.len().saturating_add(1));
        body.push(0x81);
        body.extend_from_slice(ct_bytes);

        if body.len() <= 255 {
            let apdu = commands::PsoDecipher { body, chain: false }.into_apdu();
            let r = self
                .transmit(apdu.as_bytes())
                .map_err(SignError::Transport)?;
            if !r.is_ok() {
                return Err(SignError::Sw("PSO:DECIPHER", r.sw()));
            }
            return Ok(Plaintext::new(r.body));
        }

        // Chaining: split at halfway. RSA-3072 body = 385 B;
        // halves are 192 + 193, both well under short-form
        // Lc=255. `div_euclid` is the typed-quotient form (no
        // `integer_division` lint to silence).
        let half = body.len().div_euclid(2);
        let (first, second) = body.split_at(half);

        let apdu1 = commands::PsoDecipher {
            body: first.to_vec(),
            chain: true,
        }
        .into_apdu();
        let r1 = self
            .transmit(apdu1.as_bytes())
            .map_err(SignError::Transport)?;
        if !r1.is_ok() {
            return Err(SignError::Sw("PSO:DECIPHER chunk 1/2", r1.sw()));
        }

        let apdu2 = commands::PsoDecipher {
            body: second.to_vec(),
            chain: false,
        }
        .into_apdu();
        let r2 = self
            .transmit(apdu2.as_bytes())
            .map_err(SignError::Transport)?;
        if !r2.is_ok() {
            return Err(SignError::Sw("PSO:DECIPHER chunk 2/2", r2.sw()));
        }
        Ok(Plaintext::new(r2.body))
    }

    /// RSA-PKCS1v1.5 decrypt against the **auth key** (key ref
    /// `0x01`).
    ///
    /// Pre-conditions:
    /// - VERIFY PIN1 has succeeded earlier in this card session.
    /// - `ciphertext.len() == RSA_3072_SIG_BYTES`; otherwise the
    ///   call fails with
    ///   [`SignError::UnexpectedSignatureLength`].
    ///
    /// Returns the PKCS#1 v1.5-unpadded plaintext. Length is
    /// determined by the card.
    ///
    /// # Errors
    /// Transport failure, a card SW other than `0x9000` at MSE
    /// or either DECIPHER chunk, or a wrong-length ciphertext.
    fn decrypt_rsa_pkcs1_auth(
        &mut self,
        ciphertext: Ciphertext<RsaPkcs1>,
    ) -> Result<Plaintext<RsaPkcs1>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.decrypt_rsa_pkcs1(KeyRef::Auth, ciphertext)
    }

    /// `PSO:HASH` external-hash form for any catalogued digest
    /// size. Generalises [`pso_hash_external_sha256`] /
    /// [`pso_hash_external_sha384`] across the digest set the card
    /// accepts (FINEID S1 v4.2 §3.7.2.3 Algorithm-ID table); the
    /// active SE algorithm (set by the preceding MSE:Set DST)
    /// selects which length the card expects.
    ///
    /// [`pso_hash_external_sha256`]: SignOps::pso_hash_external_sha256
    /// [`pso_hash_external_sha384`]: SignOps::pso_hash_external_sha384
    ///
    /// # Errors
    /// Transport failure or a non-9000 SW.
    fn pso_hash_external(
        &mut self,
        hash: commands::ExternalHashValue,
    ) -> Result<(), SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        let apdu = commands::PsoHash {
            class: ApduClass::Plain,
            mode: commands::PsoHashMode::External { hash },
        }
        .into_apdu();
        let r = self
            .transmit(apdu.as_bytes())
            .map_err(SignError::Transport)?;
        if !r.is_ok() {
            return Err(SignError::Sw("PSO:HASH", r.sw()));
        }
        Ok(())
    }

    /// Pre-hashed RSA-PKCS#1 v1.5 sign over any catalogued digest
    /// (SHA-1/224/256/384/512) against `key_ref`. Drives MSE:Set
    /// DST (algRef = digest x RSA-PKCS1) + PSO:HASH external +
    /// PSO:CDS; the card builds the `DigestInfo` internally, exactly
    /// as on the proven SHA-256 auth path.
    ///
    /// Unlike [`sign_pre_hashed_sha256_rsa`] the signature length
    /// is **not** pinned here -- the RSA modulus size is key-
    /// dependent, so the caller validates the returned
    /// [`Signature<RsaPkcs1>`] length against the key it selected.
    ///
    /// Only SHA-256 is hardware-proven today (the suomi.fi TLS
    /// path); the other digests follow the same spec choreography
    /// but are pending FINEID hardware re-validation.
    ///
    /// [`sign_pre_hashed_sha256_rsa`]: SignOps::sign_pre_hashed_sha256_rsa
    ///
    /// # Errors
    /// Transport failure or a non-9000 SW at any stage.
    fn sign_pre_hashed_rsa_pkcs1(
        &mut self,
        key_ref: KeyRef,
        hash: commands::ExternalHashValue,
    ) -> Result<Signature<RsaPkcs1>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        let alg_ref = commands::SignatureAlgRef::from_parts(
            hash.hash_algorithm(),
            commands::SignatureAlgorithm::RsaPkcs1V1_5,
        );
        self.mse_set_dst(alg_ref, key_ref)?;
        self.pso_hash_external(hash)?;
        self.pso_cds_empty::<RsaPkcs1>(commands::PsoComputeDigitalSignature::LE_MAX_SHORT)
    }

    /// Pre-hashed native RSA-PSS sign against `key_ref`. FINEID S1
    /// v4.2 Table 6 assigns low nibble `5h` to RSA-PSS, so the card
    /// performs PSS encoding internally after `PSO:HASH` receives the
    /// caller's digest. This avoids the unsupported 384-byte raw-RSA
    /// `PSO:CDS` operation.
    ///
    /// The card profile does not expose a salt-length parameter. Callers
    /// must request the TLS-standard salt length equal to the digest size.
    ///
    /// # Errors
    /// Transport failure or a non-9000 SW at any stage.
    fn sign_pre_hashed_rsa_pss(
        &mut self,
        key_ref: KeyRef,
        hash: commands::ExternalHashValue,
    ) -> Result<Signature<RsaPkcs1>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        let alg_ref = commands::SignatureAlgRef::from_parts(
            hash.hash_algorithm(),
            commands::SignatureAlgorithm::RsaPss,
        );
        self.mse_set_dst(alg_ref, key_ref)?;
        self.pso_hash_external(hash)?;
        let signature =
            self.pso_cds_empty::<RsaPkcs1>(commands::PsoComputeDigitalSignature::LE_MAX_SHORT)?;
        if signature.len() != RSA_3072_SIG_BYTES {
            return Err(SignError::UnexpectedSignatureLength(signature.len()));
        }
        Ok(signature)
    }

    /// SHA-256 + ECDSA P-256 sign chain (algRef `44h` = SHA256 x
    /// ECDSA) against `key_ref`: MSE:Set DST + PSO:HASH SHA-256
    /// external + PSO:CDS. Returns the raw `r || s`, 64 bytes
    /// ([`ECDSA_P256_SIG_BYTES`]) per FINEID S1 v4.2 §3.8.3.
    ///
    /// Pending FINEID hardware re-validation (only the P-384 ECDSA
    /// path is proven today).
    ///
    /// # Errors
    /// Transport failure, a card SW other than `0x9000` at any
    /// stage, or a signature length other than
    /// [`ECDSA_P256_SIG_BYTES`].
    fn sign_pre_hashed_sha256_ecdsa_p256(
        &mut self,
        key_ref: KeyRef,
        hash: Sha256,
    ) -> Result<Signature<EcdsaP256>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        self.mse_set_dst(commands::SignatureAlgRef::SHA256_ECDSA, key_ref)?;
        self.pso_hash_external_sha256(hash)?;
        let sig =
            self.pso_cds_empty::<EcdsaP256>(commands::PsoComputeDigitalSignature::LE_ECDSA_P256)?;
        if sig.len() != ECDSA_P256_SIG_BYTES {
            return Err(SignError::UnexpectedSignatureLength(sig.len()));
        }
        Ok(sig)
    }

    /// RSA-PKCS#1 v1.5 decrypt against `key_ref`. Generalises
    /// [`decrypt_rsa_pkcs1_auth`] to either key slot: MSE:Set CT
    /// (`RsassaPkcs1V1_5`) + PSO:DECIPHER. Requires the matching
    /// PIN verified earlier in this card session.
    ///
    /// [`decrypt_rsa_pkcs1_auth`]: SignOps::decrypt_rsa_pkcs1_auth
    ///
    /// # Errors
    /// Transport failure, a card SW other than `0x9000`, or a
    /// ciphertext length other than [`RSA_3072_SIG_BYTES`].
    fn decrypt_rsa_pkcs1(
        &mut self,
        key_ref: KeyRef,
        ciphertext: Ciphertext<RsaPkcs1>,
    ) -> Result<Plaintext<RsaPkcs1>, SignError<TxError<Self>>>
    where
        Self: Sized,
    {
        if ciphertext.len() != RSA_3072_SIG_BYTES {
            return Err(SignError::UnexpectedSignatureLength(ciphertext.len()));
        }
        self.mse_set_ct(commands::DecipherAlgRef::RsassaPkcs1V1_5, key_ref)?;
        self.pso_decipher(ciphertext)
    }
}

impl<T: CardTransport + ?Sized> SignOps for T {}

// All sign / decrypt fns are methods on [`SignOps`]. See the trait
// definition above.

#[cfg(test)]
mod tests {

    use super::*;
    use crate::atr::{Atr, AtrError, MINIMAL_DIRECT_ATR};
    use crate::transport::{CommandApdu, ResponseApdu, TransportOutcome};

    /// Scripted transport that asserts each APDU matches an
    /// expected sequence and returns canned responses.
    struct Scripted {
        steps: alloc::collections::VecDeque<(Vec<u8>, ResponseApdu)>,
    }
    impl Scripted {
        fn new(steps: Vec<(Vec<u8>, ResponseApdu)>) -> Self {
            Self {
                steps: steps.into(),
            }
        }
    }
    impl CardTransport for Scripted {
        type Error = String;
        fn transmit_outcome(
            &mut self,
            apdu: &CommandApdu,
        ) -> Result<TransportOutcome, Self::Error> {
            let (expected, response) = self
                .steps
                .pop_front()
                .expect("Scripted: unexpected extra APDU");
            assert_eq!(apdu.as_bytes(), expected.as_slice(), "APDU mismatch");
            Ok(TransportOutcome::Response(response))
        }
        fn atr(&self) -> Result<Atr, AtrError> {
            Atr::new(MINIMAL_DIRECT_ATR)
        }
    }

    use crate::apdu::status_word::StatusWord;

    /// Build a typed `ResponseApdu` carrying `sw` and `body`.
    /// Bytes are decomposed from the typed `StatusWord` value so
    /// the test fixtures don't carry raw `0x9000` / `0x6982`
    /// hex literals.
    fn response(sw: StatusWord, body: Vec<u8>) -> ResponseApdu {
        // Decompose the typed status word to its big-endian wire
        // pair. `to_be_bytes` is the lossless typed decomposition;
        // it sidesteps `as u8` truncation casts entirely.
        let [sw1, sw2] = sw.as_u16().to_be_bytes();
        ResponseApdu { body, sw1, sw2 }
    }

    fn ok(body: &[u8]) -> ResponseApdu {
        response(StatusWord::Success, body.to_vec())
    }
    fn sw_err(sw: StatusWord) -> ResponseApdu {
        response(sw, vec![])
    }

    // Expected-APDU builders for `Scripted` -- each one
    // constructs the wire bytes via the same typed command
    // struct the production code uses. This way the higher-
    // level sign-chain tests below check WHICH command + WHICH
    // typed parameters refineid dispatches (the test fails if
    // sign_pre_hashed_sha384_ecdsa_p384 accidentally uses
    // SHA256_RSA_PKCS1_V1_5 or KeyRef::Sign, etc.), while the
    // raw byte-shape of each individual command is locked by
    // the dedicated wire-format tests in `sign::commands`.
    //
    // Per typing-discipline.md "Allowed Boundary Shapes": typed
    // values cross every boundary -- KeyRef, SignatureAlgRef,
    // ExternalHashValue, ApduClass -- no raw hex constants
    // here.
    use crate::apdu::iso7816::ApduClass;
    use commands::{
        ExternalHashValue, MseSet, MseSetTemplate, PsoComputeDigitalSignature, PsoHash,
        PsoHashMode, SignatureAlgRef,
    };

    fn expected_mse_set_dst(alg_ref: SignatureAlgRef, key_ref: KeyRef) -> Vec<u8> {
        MseSet {
            class: ApduClass::Plain,
            template: MseSetTemplate::DigitalSignature { alg_ref, key_ref },
        }
        .into_apdu()
        .into_bytes()
    }

    fn expected_pso_hash(hash: ExternalHashValue) -> Vec<u8> {
        PsoHash {
            class: ApduClass::Plain,
            mode: PsoHashMode::External { hash },
        }
        .into_apdu()
        .into_bytes()
    }

    fn expected_pso_cds(le: u8) -> Vec<u8> {
        PsoComputeDigitalSignature {
            class: ApduClass::Plain,
        }
        .into_apdu_with_le(le)
        .into_bytes()
    }

    fn expected_mse_set_ct(alg_ref: commands::DecipherAlgRef, key_ref: KeyRef) -> Vec<u8> {
        MseSet {
            class: ApduClass::Plain,
            template: MseSetTemplate::DeciphermentRsa { alg_ref, key_ref },
        }
        .into_apdu()
        .into_bytes()
    }

    fn expected_pso_decipher(body: Vec<u8>, chain: bool) -> Vec<u8> {
        commands::PsoDecipher { body, chain }
            .into_apdu()
            .into_bytes()
    }

    /// Deterministic fixture-fill byte for placeholder buffers.
    /// One value reused across every placeholder helper -- the
    /// tests care about length + structure, not content.
    const FIXTURE_FILL: u8 = 0xAA;

    /// RSA PKCS#1 v1.5 padding-indicator key per FINEID S1 v4.2
    /// §3.9 -- prepended by [`SignOps::pso_decipher`] before the
    /// ciphertext when wrapping the body for the card.
    const RSA_PKCS1_PADDING_INDICATOR_KEY: u8 = 0x81;

    fn placeholder_sha256_digest() -> Sha256 {
        Sha256::from_bytes([FIXTURE_FILL; SHA256_DIGEST_LEN])
    }

    fn placeholder_sha1_digest() -> Sha1 {
        Sha1::from_bytes([FIXTURE_FILL; 20])
    }

    fn placeholder_sha224_digest() -> Sha224 {
        Sha224::from_bytes([FIXTURE_FILL; 28])
    }

    fn placeholder_sha384_digest() -> Sha384 {
        Sha384::from_bytes([FIXTURE_FILL; SHA384_DIGEST_LEN])
    }

    fn placeholder_sha512_digest() -> Sha512 {
        Sha512::from_bytes([FIXTURE_FILL; 64])
    }

    fn placeholder_sig_bytes(len: usize) -> Vec<u8> {
        vec![FIXTURE_FILL; len]
    }

    fn placeholder_ciphertext_rsa_3072() -> Ciphertext<RsaPkcs1> {
        Ciphertext::new(placeholder_sig_bytes(RSA_3072_SIG_BYTES))
    }

    fn placeholder_ciphertext_short() -> Ciphertext<RsaPkcs1> {
        // Any non-RSA-3072 length triggers the length gate. 128
        // is the AES-128 block-times-8 size that historical
        // crypto-tooling shorthand uses for "not RSA".
        const SHORT_CT_LEN: usize = 128;
        Ciphertext::new(placeholder_sig_bytes(SHORT_CT_LEN))
    }

    #[test]
    fn full_chain_yields_signature() {
        let hash = placeholder_sha256_digest();
        let sig = placeholder_sig_bytes(RSA_3072_SIG_BYTES);
        let mut tx = Scripted::new(vec![
            (
                expected_mse_set_dst(SignatureAlgRef::SHA256_RSA_PKCS1_V1_5, KeyRef::Auth),
                ok(&[]),
            ),
            (
                expected_pso_hash(ExternalHashValue::Sha256(*hash.as_bytes())),
                ok(&[]),
            ),
            (
                expected_pso_cds(PsoComputeDigitalSignature::LE_MAX_SHORT),
                ok(&sig),
            ),
        ]);
        let out = tx.sign_pre_hashed_sha256_rsa_auth(hash).expect("ok");
        assert_eq!(out.as_bytes(), sig.as_slice());
    }

    #[test]
    fn rsa_pss_sha256_composes_algref_45() {
        let digest = ExternalHashValue::Sha256([FIXTURE_FILL; 32]);
        let alg_ref = SignatureAlgRef::from_parts(
            commands::HashAlgorithm::Sha256,
            commands::SignatureAlgorithm::RsaPss,
        );
        let sig = placeholder_sig_bytes(RSA_3072_SIG_BYTES);
        let mut tx = Scripted::new(vec![
            (expected_mse_set_dst(alg_ref, KeyRef::Auth), ok(&[])),
            (expected_pso_hash(digest), ok(&[])),
            (
                expected_pso_cds(PsoComputeDigitalSignature::LE_MAX_SHORT),
                ok(&sig),
            ),
        ]);
        let out = tx
            .sign_pre_hashed_rsa_pss(KeyRef::Auth, digest)
            .expect("ok");
        assert_eq!(out.as_bytes(), sig.as_slice());
    }

    #[test]
    fn ecdsa_p384_sha1_chain_yields_96_byte_signature() {
        let hash = placeholder_sha1_digest();
        let sig = placeholder_sig_bytes(ECDSA_P384_SIG_BYTES);
        let mut tx = Scripted::new(vec![
            (
                expected_mse_set_dst(
                    SignatureAlgRef::from_parts(
                        commands::HashAlgorithm::Sha1,
                        commands::SignatureAlgorithm::Ecdsa,
                    ),
                    KeyRef::Auth,
                ),
                ok(&[]),
            ),
            (
                expected_pso_hash(ExternalHashValue::Sha1(*hash.as_bytes())),
                ok(&[]),
            ),
            (
                expected_pso_cds(PsoComputeDigitalSignature::LE_ECDSA_P384),
                ok(&sig),
            ),
        ]);
        let out = tx
            .sign_pre_hashed_sha1_ecdsa_p384(KeyRef::Auth, hash)
            .expect("ok");
        assert_eq!(out.as_bytes(), sig.as_slice());
    }

    #[test]
    fn rsa_pkcs1_sha512_composes_algref_62() {
        // Generalised multi-digest RSA-PKCS1: a SHA-512 digest must
        // drive MSE:Set DST with algRef = (Sha512 x RsaPkcs1) and
        // ship the 64-byte external hash. The chain is identical in
        // shape to the proven SHA-256 path; only the algRef byte and
        // the hash length differ.
        let digest = ExternalHashValue::Sha512([FIXTURE_FILL; 64]);
        let alg_ref = SignatureAlgRef::from_parts(
            commands::HashAlgorithm::Sha512,
            commands::SignatureAlgorithm::RsaPkcs1V1_5,
        );
        let sig = placeholder_sig_bytes(RSA_3072_SIG_BYTES);
        let mut tx = Scripted::new(vec![
            (expected_mse_set_dst(alg_ref, KeyRef::Auth), ok(&[])),
            (expected_pso_hash(digest), ok(&[])),
            (
                expected_pso_cds(PsoComputeDigitalSignature::LE_MAX_SHORT),
                ok(&sig),
            ),
        ]);
        let out = tx
            .sign_pre_hashed_rsa_pkcs1(KeyRef::Auth, digest)
            .expect("ok");
        assert_eq!(out.as_bytes(), sig.as_slice());
    }

    #[test]
    fn ecdsa_p256_chain_yields_64_byte_sig() {
        let hash = placeholder_sha256_digest();
        let sig = placeholder_sig_bytes(ECDSA_P256_SIG_BYTES);
        let mut tx = Scripted::new(vec![
            (
                expected_mse_set_dst(SignatureAlgRef::SHA256_ECDSA, KeyRef::Auth),
                ok(&[]),
            ),
            (
                expected_pso_hash(ExternalHashValue::Sha256(*hash.as_bytes())),
                ok(&[]),
            ),
            (
                expected_pso_cds(PsoComputeDigitalSignature::LE_ECDSA_P256),
                ok(&sig),
            ),
        ]);
        let out = tx
            .sign_pre_hashed_sha256_ecdsa_p256(KeyRef::Auth, hash)
            .expect("ok");
        assert_eq!(out.as_bytes(), sig.as_slice());
    }

    #[test]
    fn ecdsa_p384_sha512_chain_yields_96_byte_signature() {
        let hash = placeholder_sha512_digest();
        let sig = placeholder_sig_bytes(ECDSA_P384_SIG_BYTES);
        let mut tx = Scripted::new(vec![
            (
                expected_mse_set_dst(
                    SignatureAlgRef::from_parts(
                        commands::HashAlgorithm::Sha512,
                        commands::SignatureAlgorithm::Ecdsa,
                    ),
                    KeyRef::Auth,
                ),
                ok(&[]),
            ),
            (
                expected_pso_hash(ExternalHashValue::Sha512(*hash.as_bytes())),
                ok(&[]),
            ),
            (
                expected_pso_cds(PsoComputeDigitalSignature::LE_ECDSA_P384),
                ok(&sig),
            ),
        ]);
        let out = tx
            .sign_pre_hashed_sha512_ecdsa_p384(KeyRef::Auth, hash)
            .expect("ok");
        assert_eq!(out.as_bytes(), sig.as_slice());
    }

    #[test]
    fn decrypt_rsa_pkcs1_targets_requested_key_ref() {
        // decrypt_rsa_pkcs1 must pin MSE:Set CT to the caller's
        // key_ref (here the qualified-signature slot, 0x02), then
        // chain the 385-byte (0x81 || 384-byte CT) body.
        let ct = placeholder_ciphertext_rsa_3072();
        let mut body = vec![RSA_PKCS1_PADDING_INDICATOR_KEY];
        body.extend_from_slice(ct.as_bytes());
        let half = body.len().div_euclid(2);
        let (first, second) = body.split_at(half);
        let plaintext = placeholder_sig_bytes(48);
        let mut tx = Scripted::new(vec![
            (
                expected_mse_set_ct(commands::DecipherAlgRef::RsassaPkcs1V1_5, KeyRef::Sign),
                ok(&[]),
            ),
            (expected_pso_decipher(first.to_vec(), true), ok(&[])),
            (
                expected_pso_decipher(second.to_vec(), false),
                ok(&plaintext),
            ),
        ]);
        let out = tx.decrypt_rsa_pkcs1(KeyRef::Sign, ct).expect("ok");
        assert_eq!(out.as_bytes(), plaintext.as_slice());
    }

    #[test]
    fn qualified_slot_uses_key_ref_02() {
        let hash = placeholder_sha256_digest();
        let sig = placeholder_sig_bytes(RSA_3072_SIG_BYTES);
        let mut tx = Scripted::new(vec![
            (
                expected_mse_set_dst(SignatureAlgRef::SHA256_RSA_PKCS1_V1_5, KeyRef::Sign),
                ok(&[]),
            ),
            (
                expected_pso_hash(ExternalHashValue::Sha256(*hash.as_bytes())),
                ok(&[]),
            ),
            (
                expected_pso_cds(PsoComputeDigitalSignature::LE_MAX_SHORT),
                ok(&sig),
            ),
        ]);
        let out = tx.sign_pre_hashed_sha256_rsa_qualified(hash).expect("ok");
        assert_eq!(out.as_bytes(), sig.as_slice());
    }

    #[test]
    fn mse_failure_surfaces_sw() {
        let hash = placeholder_sha256_digest();
        let mut tx = Scripted::new(vec![(
            expected_mse_set_dst(SignatureAlgRef::SHA256_RSA_PKCS1_V1_5, KeyRef::Auth),
            sw_err(StatusWord::ReferenceDataNotFound),
        )]);
        let err = tx
            .sign_pre_hashed_sha256_rsa_auth(hash)
            .expect_err("MSE:Set DST error status aborts the chain");
        assert!(matches!(
            err,
            SignError::Sw("MSE:Set DST", sw) if sw == StatusWord::ReferenceDataNotFound.as_u16()
        ));
    }

    #[test]
    fn pso_hash_failure_surfaces_sw() {
        let hash = placeholder_sha256_digest();
        let mut tx = Scripted::new(vec![
            (
                expected_mse_set_dst(SignatureAlgRef::SHA256_RSA_PKCS1_V1_5, KeyRef::Auth),
                ok(&[]),
            ),
            (
                expected_pso_hash(ExternalHashValue::Sha256(*hash.as_bytes())),
                sw_err(StatusWord::SecurityNotSatisfied),
            ),
        ]);
        let err = tx
            .sign_pre_hashed_sha256_rsa_auth(hash)
            .expect_err("PSO:HASH error status aborts the chain");
        assert!(matches!(
            err,
            SignError::Sw("PSO:HASH", sw) if sw == StatusWord::SecurityNotSatisfied.as_u16()
        ));
    }

    #[test]
    fn pso_cds_security_status_surfaces_sw() {
        let hash = placeholder_sha256_digest();
        let mut tx = Scripted::new(vec![
            (
                expected_mse_set_dst(SignatureAlgRef::SHA256_RSA_PKCS1_V1_5, KeyRef::Auth),
                ok(&[]),
            ),
            (
                expected_pso_hash(ExternalHashValue::Sha256(*hash.as_bytes())),
                ok(&[]),
            ),
            (
                expected_pso_cds(PsoComputeDigitalSignature::LE_MAX_SHORT),
                sw_err(StatusWord::SecurityNotSatisfied),
            ),
        ]);
        let err = tx
            .sign_pre_hashed_sha256_rsa_auth(hash)
            .expect_err("PSO:CDS error status aborts the chain");
        assert!(matches!(
            err,
            SignError::Sw("PSO:CDS", sw) if sw == StatusWord::SecurityNotSatisfied.as_u16()
        ));
    }

    #[test]
    fn decrypt_chain_rsa_3072_uses_chained_pso_decipher() {
        // RSA-3072 ciphertext = RSA_3072_SIG_BYTES; body =
        // <PI byte> || ciphertext = RSA_3072_SIG_BYTES + 1; the
        // production code splits at the body midpoint so each
        // chunk fits in short-form Lc.
        let ciphertext = placeholder_ciphertext_rsa_3072();
        let ct_bytes_for_chunks = placeholder_sig_bytes(RSA_3072_SIG_BYTES);
        let mut body = vec![RSA_PKCS1_PADDING_INDICATOR_KEY];
        body.extend_from_slice(&ct_bytes_for_chunks);
        let (first, second) = body.split_at(body.len() / 2);
        let chunk1 = expected_pso_decipher(first.to_vec(), true);
        let chunk2 = expected_pso_decipher(second.to_vec(), false);

        let plaintext = b"the answer is 42".to_vec();
        let mut tx = Scripted::new(vec![
            (
                expected_mse_set_ct(commands::DecipherAlgRef::RsassaPkcs1V1_5, KeyRef::Auth),
                ok(&[]),
            ),
            (chunk1, ok(&[])),
            (chunk2, ok(&plaintext)),
        ]);
        let out = tx.decrypt_rsa_pkcs1_auth(ciphertext).expect("ok");
        assert_eq!(out.as_bytes(), plaintext.as_slice());
    }

    #[test]
    fn decrypt_rejects_wrong_ciphertext_length() {
        let mut tx = Scripted::new(vec![]);
        let short = placeholder_ciphertext_short();
        let short_len = short.len();
        let err = tx
            .decrypt_rsa_pkcs1_auth(short)
            .expect_err("non-RSA-3072-size ciphertext is rejected");
        assert!(matches!(
            err,
            SignError::UnexpectedSignatureLength(n) if n == short_len
        ));
    }

    #[test]
    fn decrypt_mse_failure_surfaces_sw() {
        let ciphertext = placeholder_ciphertext_rsa_3072();
        let mut tx = Scripted::new(vec![(
            expected_mse_set_ct(commands::DecipherAlgRef::RsassaPkcs1V1_5, KeyRef::Auth),
            sw_err(StatusWord::ReferenceDataNotFound),
        )]);
        let err = tx
            .decrypt_rsa_pkcs1_auth(ciphertext)
            .expect_err("MSE:Set CT error status aborts the chain");
        assert!(matches!(
            err,
            SignError::Sw("MSE:Set CT", sw) if sw == StatusWord::ReferenceDataNotFound.as_u16()
        ));
    }

    #[test]
    fn pso_cds_wrong_signature_length_surfaces_unexpected_length() {
        let hash = placeholder_sha256_digest();
        // Wrong length: ECDSA-shape signature on an RSA chain.
        let sig = placeholder_sig_bytes(ECDSA_P384_SIG_BYTES);
        let mut tx = Scripted::new(vec![
            (
                expected_mse_set_dst(SignatureAlgRef::SHA256_RSA_PKCS1_V1_5, KeyRef::Auth),
                ok(&[]),
            ),
            (
                expected_pso_hash(ExternalHashValue::Sha256(*hash.as_bytes())),
                ok(&[]),
            ),
            (
                expected_pso_cds(PsoComputeDigitalSignature::LE_MAX_SHORT),
                ok(&sig),
            ),
        ]);
        let err = tx
            .sign_pre_hashed_sha256_rsa_auth(hash)
            .expect_err("ECDSA-size signature on an RSA chain is rejected");
        assert!(matches!(
            err,
            SignError::UnexpectedSignatureLength(n) if n == ECDSA_P384_SIG_BYTES
        ));
    }

    #[test]
    fn ecdsa_p384_chain_yields_96_byte_signature() {
        let hash = placeholder_sha384_digest();
        let sig = placeholder_sig_bytes(ECDSA_P384_SIG_BYTES);
        let mut tx = Scripted::new(vec![
            (
                expected_mse_set_dst(SignatureAlgRef::SHA384_ECDSA, KeyRef::Auth),
                ok(&[]),
            ),
            (
                expected_pso_hash(ExternalHashValue::Sha384(*hash.as_bytes())),
                ok(&[]),
            ),
            (
                expected_pso_cds(PsoComputeDigitalSignature::LE_ECDSA_P384),
                ok(&sig),
            ),
        ]);
        let out = tx
            .sign_pre_hashed_sha384_ecdsa_p384(KeyRef::Auth, hash)
            .expect("ok");
        assert_eq!(out.as_bytes(), sig.as_slice());
    }

    #[test]
    fn ecdsa_p384_sha224_chain_yields_96_byte_signature() {
        let hash = placeholder_sha224_digest();
        let sig = placeholder_sig_bytes(ECDSA_P384_SIG_BYTES);
        let mut tx = Scripted::new(vec![
            (
                expected_mse_set_dst(SignatureAlgRef::SHA224_ECDSA, KeyRef::Auth),
                ok(&[]),
            ),
            (
                expected_pso_hash(ExternalHashValue::Sha224(*hash.as_bytes())),
                ok(&[]),
            ),
            (
                expected_pso_cds(PsoComputeDigitalSignature::LE_ECDSA_P384),
                ok(&sig),
            ),
        ]);
        let out = tx
            .sign_pre_hashed_sha224_ecdsa_p384(KeyRef::Auth, hash)
            .expect("ok");
        assert_eq!(out.as_bytes(), sig.as_slice());
    }

    #[test]
    fn ecdsa_p384_chain_wrong_length_surfaces_unexpected_length() {
        let hash = placeholder_sha384_digest();
        // Wrong length: RSA-shape signature on an ECDSA chain.
        let sig = placeholder_sig_bytes(RSA_3072_SIG_BYTES);
        let mut tx = Scripted::new(vec![
            (
                expected_mse_set_dst(SignatureAlgRef::SHA384_ECDSA, KeyRef::Auth),
                ok(&[]),
            ),
            (
                expected_pso_hash(ExternalHashValue::Sha384(*hash.as_bytes())),
                ok(&[]),
            ),
            (
                expected_pso_cds(PsoComputeDigitalSignature::LE_ECDSA_P384),
                ok(&sig),
            ),
        ]);
        let err = tx
            .sign_pre_hashed_sha384_ecdsa_p384(KeyRef::Auth, hash)
            .expect_err("RSA-size signature on an ECDSA chain is rejected");
        assert!(matches!(
            err,
            SignError::UnexpectedSignatureLength(n) if n == RSA_3072_SIG_BYTES
        ));
    }
}
