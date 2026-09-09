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

//! Chip Authentication (BSI TR-03110-3 §3.4, ICAO 9303-11 §6.2).
//!
//! Anti-cloning round-trip for v4.0-era eMRTDs that publish a
//! Chip Authentication public key in DG14 (and hold the
//! matching private key on chip). CA both proves the chip
//! produced the response (the v4.0 equivalent of AA's chip-
//! binding property) and establishes new Secure Messaging
//! session keys derived from the ECDH shared secret.
//!
//! Flow:
//!
//! 1. Parse DG14's `ChipAuthenticationPublicKeyInfo` to get the
//!    chip's CA public point `Q_PICC` plus the CA protocol OID.
//! 2. Pick a CA protocol entry the chip advertises (FINEID v4.0
//!    cards publish `id-CA-ECDH-AES-CBC-CMAC-256` on Brainpool
//!    P-384).
//! 3. `MSE:Set AT (CA)` -- `00 22 41 A4 <data>` with the OID
//!    inside an `0x80` TLV. Card validates the request.
//! 4. Generate ephemeral keypair `(d_PCD, Q_PCD)` on the same
//!    curve as `Q_PICC`. `General Authenticate (CA)` --
//!    `00 86 00 00 <data> 00` with `Q_PCD` wrapped in
//!    `0x7C { 0x80 { uncompressed point bytes } }`.
//! 5. Compute shared secret `K = d_PCD * Q_PICC`, take its
//!    x-coordinate as the KDF input.
//! 6. Derive new session keys: `K_ENC = KDF(K_x, c=1)`,
//!    `K_MAC = KDF(K_x, c=2)`, reset `SSC` to all zero.
//! 7. Rotate the `SmTransport`'s keys to the CA-derived pair.
//! 8. A subsequent SM-MAC'd APDU is the implicit verification --
//!    if the chip didn't have the right private key, the MACs
//!    won't agree and the next op fails with SM-mismatch.
//!
//! v0 limits:
//! - Only ECDH variants supported (FINEID's CA protocols are all
//!   ECDH-flavoured; DH is rare in the field).
//! - Only Brainpool P-384 supported (matches both new and old
//!   FINEID card variants we've seen). Other named curves +
//!   explicit-params decoding follow when needed.
//! - Only AES-256 cipher suite (`id-CA-ECDH-AES-CBC-CMAC-256`).
//!   FINEID v3.1 cards also advertise the legacy 3DES variant
//!   but we don't pick it.

use core::error::Error as CoreError;
use core::fmt::{Debug, Display, Formatter, Result as FmtResult};

use crypto_bigint::U384;
use zeroize::{Zeroize as _, Zeroizing};

use crate::apdu::iso7816::ReadBinaryBySfi;
use crate::ber;
use crate::crypto::brainpool_p384::{AffinePoint, n as brainpool_n};
use crate::crypto::symmetric::{KdfParam, kdf_aes256};
use crate::emrtd::{Dg14SecurityInfo, SFI_EF_DG1};
use crate::pace::commands::{GeneralAuthenticate, MseSetAt};
use crate::secure_messaging::{SmError, SmTransport};
use crate::transport::{CardTransport, TransportDispatchError};
use crate::x509::SpkiDer;

/// MSE:Set AT P1 for Chip Authentication: "set for computation"
/// (BSI TR-03110-3 B.11.1). PACE's MSE:Set AT uses 0xC1
/// ("set + restore") instead -- see [`MseSetAt::P1`].
const CA_MSE_SET_AT_P1: u8 = 0x41;

/// Outcome of a CA round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaOutcome {
    /// `General Authenticate` was sent but the card refused.
    /// Same recovery property as `MseRejected` -- SM session is
    /// unchanged.
    GaRejected {
        /// Card-returned status word per ISO 7816-4 §5.1.3.
        sw: u16,
    },
    /// `MSE:Set AT` was sent but the card refused (non-success
    /// SW). No keys have been rotated; the `SmTransport` still
    /// holds the PACE-derived keys.
    MseRejected {
        /// Card-returned status word per ISO 7816-4 §5.1.3.
        sw: u16,
    },
    /// DG14 didn't advertise a CA protocol we know how to drive
    /// (no `ECDH-AES-256` entry, or no
    /// `ChipAuthenticationPublicKeyInfo`). Nothing was sent to
    /// the card.
    NoSupportedProtocol,
    /// DG14 advertised CA but the public-key SPKI didn't decode
    /// as a Brainpool P-384 point. Nothing was sent to the card.
    UnsupportedCurve,
    /// MSE + GA succeeded and the keys were rotated, but the
    /// post-rekey probe APDU failed -- either MAC mismatch
    /// (chip didn't hold the matching private key) or a card-
    /// side rejection. The transport is still on the new keys;
    /// the caller may want to re-PACE to recover.
    VerificationFailed {
        /// Human-readable detail naming the verification failure
        /// (MAC mismatch, SW from the probe). Tier 0 `String`;
        /// presentational.
        detail: String,
    },
    /// CA succeeded AND the post-rekey validation probe MAC'd
    /// correctly -- the chip held the CA private key matching
    /// DG14's pubkey. The SM session is now on CA-derived keys.
    Verified {
        /// Friendly label of the CA protocol that was driven
        /// (e.g. `id-CA-ECDH-AES-CBC-CMAC-256`).
        protocol_label: &'static str,
    },
}

/// Errors that abort the round-trip before any keys could be
/// rotated.
///
/// Card-side rejections are surfaced via [`CaOutcome`] variants
/// so the caller can distinguish "we never tried" from "we tried
/// and the chip said no". Parameterised over the underlying
/// transport's error type -- `SmTransport`'s `transmit` returns
/// `SmError<TE>` so the `Transport` variant wraps that.
#[derive(Debug)]
pub enum CaError<TE>
where
    TE: Debug + Display,
{
    /// MSE:Set AT body byte count didn't fit in the u8 Lc field
    /// (would only fire if the CA OID exceeded the BSI TR-03110-3
    /// §A.6.2 length bound -- structurally unreachable, retained as
    /// a fail-closed surface).
    MseBodyTooLong {
        /// The `mse_data.len()` value that didn't fit in u8.
        got: usize,
    },
    /// `getrandom` failed to supply ephemeral-key bytes.
    Random(crate::rng::Failure),
    /// Transport-level failure (PC/SC error, SM failure)
    /// before MSE / GA could complete.
    Transport(TransportDispatchError<SmError<TE>>),
}

impl<TE> Display for CaError<TE>
where
    TE: Debug + Display,
{
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Transport(err) => write!(f, "CA transport: {err}"),
            Self::Random(err) => write!(f, "CA random: {err}"),
            Self::MseBodyTooLong { got } => {
                write!(f, "CA MSE:Set AT body {got} bytes; > u8 Lc cap")
            }
        }
    }
}

impl<TE> CoreError for CaError<TE> where TE: Debug + Display + 'static {}

/// Run a Chip Authentication round-trip against an SM-wrapped
/// transport, picking a supported protocol from the DG14
/// `SecurityInfo` entries.
///
/// On success the transport's SM keys are rotated to the CA-
/// derived pair and the SSC reset. The caller's next SM APDU
/// validates the rotation: if the chip didn't actually hold the
/// matching CA private key, the next MAC will fail and the
/// transport surfaces an `SmError::MacMismatch`.
///
/// # Errors
/// [`CaError`] for transport / RNG failures. The returned
/// [`CaOutcome`] carries the non-error variants (card-rejected,
/// no-supported-protocol, unsupported-curve).
pub(crate) fn run_chip_authentication<T: CardTransport>(
    transport: &mut SmTransport<T>,
    dg14_entries: &[Dg14SecurityInfo],
) -> Result<CaOutcome, CaError<T::Error>> {
    // Find the highest-strength CA protocol we know how to drive
    // (currently only id-CA-ECDH-AES-CBC-CMAC-256) and the
    // matching ChipAuthenticationPublicKeyInfo.
    let Some((proto_oid, proto_label)) = CaHelpers::pick_protocol(dg14_entries) else {
        return Ok(CaOutcome::NoSupportedProtocol);
    };
    // `pick_public_key` returns the decoded AffinePoint directly:
    // it already validates Brainpool P-384 SEC 1 uncompressed
    // shape internally via `decode_brainpool_p384_point` before
    // selecting an entry, so the previous redundant re-decode
    // (and its dead `UnsupportedCurve` arm) is gone.  A `None`
    // here means either no `ChipAuthenticationPublicKeyInfo`
    // entries exist in DG14 or none decoded as a Brainpool P-384
    // point.
    let Some(q_picc) = CaHelpers::pick_public_key(dg14_entries) else {
        return Ok(CaOutcome::NoSupportedProtocol);
    };

    // Step 3: MSE:Set AT for CA. Body is `80 <len> <OID>`.
    // CA's MSE:Set AT uses P1 "set for computation"
    // (CA_MSE_SET_AT_P1), distinct from PACE's P1=0xC1
    // ("set + restore"), so the typed command lives inline here
    // rather than reusing pace::commands::MseSetAt wholesale --
    // only its CLA/INS/P2 bytes are shared.
    let mse_data = ber::tlv(0x80, proto_oid);
    // Capacity hint: 5-byte ISO 7816 APDU header + the BER TLV body.
    // mse_data is TLV(0x80, CA OID) with the OID at most 12 bytes
    // (BSI TR-03110-3 §A.6.2), so the sum is well under usize::MAX;
    // saturating_add is the lint-safe form.
    let cap = 5_usize.saturating_add(mse_data.len());
    let mut mse_apdu = Vec::with_capacity(cap);
    mse_apdu.extend_from_slice(&[MseSetAt::CLA, MseSetAt::INS, CA_MSE_SET_AT_P1, MseSetAt::P2]);
    // mse_data.len() fits in u8 by the same BSI bound (< 16 bytes).
    // try_from -> map_err is the typed projection; the OID-too-long
    // path is reported as a card-rejection-equivalent outcome rather
    // than a panic.
    let lc = u8::try_from(mse_data.len()).or(Err(CaError::MseBodyTooLong {
        got: mse_data.len(),
    }))?;
    mse_apdu.push(lc);
    mse_apdu.extend_from_slice(&mse_data);
    let mse_resp = transport.transmit(&mse_apdu).map_err(CaError::Transport)?;
    if !mse_resp.is_ok() {
        return Ok(CaOutcome::MseRejected { sw: mse_resp.sw() });
    }

    // Step 4: generate ephemeral keypair on the same curve, send
    // General Authenticate. `d_pcd` is the ephemeral CA private
    // scalar; it is wiped at the end of step 5 (see below) once the
    // shared secret has been computed.
    let mut d_pcd = random_scalar_in_range_n().map_err(CaError::Random)?;
    let q_pcd = AffinePoint::generator().scalar_mul(&d_pcd);
    let Some(q_pcd_bytes) = q_pcd.encode_uncompressed() else {
        // Generator * scalar should never be identity; if it
        // somehow is, we're better off bailing than sending a
        // bogus point.
        return Ok(CaOutcome::UnsupportedCurve);
    };
    // GA data: 7C { 80 <len> <q_pcd_bytes> }
    let inner_80 = ber::tlv(0x80, q_pcd_bytes);
    let ga_data = ber::tlv(0x7C, &inner_80);
    let ga_apdu = GeneralAuthenticate {
        chain: false,
        payload: ga_data,
    }
    .into_apdu();
    let ga_resp = transport
        .transmit(ga_apdu.as_bytes())
        .map_err(CaError::Transport)?;
    if !ga_resp.is_ok() {
        return Ok(CaOutcome::GaRejected { sw: ga_resp.sw() });
    }

    // Step 5: compute shared secret K = d_PCD * Q_PICC, take x.
    let k_point = q_picc.scalar_mul(&d_pcd);
    // The ephemeral private scalar is dead now that the shared point
    // is computed; wipe it before it drops so it does not linger.
    d_pcd.zeroize();
    let Some(k_bytes) = k_point.encode_uncompressed() else {
        return Ok(CaOutcome::UnsupportedCurve);
    };
    // The shared secret is the x-coordinate of K, bytes 1..49 of
    // the 97-byte uncompressed encoding (after the 0x04 prefix).
    // Copy it into a zeroize-on-drop buffer so the KDF-input keying
    // material is wiped at end of scope rather than left as stack
    // residue in the SEC1 point encoding.
    let Some(k_x) = k_bytes
        .as_bytes()
        .get(1..49)
        .map(|x| Zeroizing::new(x.to_vec()))
    else {
        return Ok(CaOutcome::UnsupportedCurve);
    };

    // Step 6: derive new SM keys.
    let new_k_enc = kdf_aes256(&k_x, KdfParam::Encryption);
    let new_k_mac = kdf_aes256(&k_x, KdfParam::Mac);

    // Step 7: rotate the SmTransport.
    transport.rekey(new_k_enc, new_k_mac);

    // Step 8: validation probe. Send a tiny SM-MAC'd read of
    // EF.DG1's first 4 bytes -- the eMRTD applet is already
    // selected, DG1 is always provisioned. If our derived keys
    // don't match the chip's (i.e. the chip didn't actually
    // hold the matching CA private key) the SM-MAC on its
    // response will fail and the transport surfaces an
    // SmError::MacMismatch.
    let probe = ReadBinaryBySfi {
        sfi: SFI_EF_DG1,
        offset: 0,
        le: 4,
    }
    .into_apdu();
    match transport.transmit(probe.as_bytes()) {
        Ok(probe_resp) if probe_resp.is_ok() => Ok(CaOutcome::Verified {
            protocol_label: proto_label,
        }),
        Ok(probe_resp) => Ok(CaOutcome::VerificationFailed {
            detail: format!("probe SW={:#06X}", probe_resp.sw()),
        }),
        Err(err) => Ok(CaOutcome::VerificationFailed {
            detail: format!("{err}"),
        }),
    }
}

/// Helpers hosted on a unit struct (typing-discipline: no
/// free fns with borrowed parameters; see
/// `doc/typing-discipline.md`).
struct CaHelpers;

impl CaHelpers {
    /// Pick the highest-strength CA protocol from the DG14
    /// entries that we know how to drive. Returns the OID bytes
    /// plus a friendly label, or `None` if no supported protocol
    /// is advertised.
    fn pick_protocol(entries: &[Dg14SecurityInfo]) -> Option<(&[u8], &'static str)> {
        // `id-CA-ECDH-AES-CBC-CMAC-256` is the only one we drive
        // in this iteration. AES-128/192 variants would slot in
        // here with their own KDF/cipher parameters; 3DES is
        // legacy and not worth implementing for new code.
        for entry in entries {
            if let Dg14SecurityInfo::ChipAuthenticationInfo {
                protocol_label,
                oid,
                ..
            } = entry
                && *protocol_label == "id-CA-ECDH-AES-CBC-CMAC-256"
            {
                return Some((oid.as_slice(), protocol_label));
            }
        }
        None
    }

    /// Pick the matching `ChipAuthenticationPublicKeyInfo`
    /// entry and return its decoded Brainpool P-384 public point.
    fn pick_public_key(entries: &[Dg14SecurityInfo]) -> Option<AffinePoint> {
        for entry in entries {
            if let Dg14SecurityInfo::ChipAuthenticationPublicKeyInfo { spki_der, .. } = entry {
                // Raw eMRTD DG14 SPKI bytes cross into the typed
                // SpkiDer at this boundary; the key material is then
                // reached through the type, not a raw free function.
                let Ok(spki) = SpkiDer::try_from(spki_der.as_slice()) else {
                    continue;
                };
                if let Some(point) =
                    Self::decode_brainpool_p384_point(spki.subject_public_key_bits())
                {
                    return Some(point);
                }
            }
        }
        None
    }

    /// Decodes an uncompressed SEC 1 Brainpool P-384 public point.
    ///
    /// Expects exactly 97 bytes in the form `0x04 || X || Y`
    /// (1-byte tag + 48-byte X + 48-byte Y).
    ///
    /// Returns `Some(AffinePoint)` only when the encoding parses
    /// successfully and the resulting point is on the Brainpool P-384
    /// curve; otherwise returns `None`.
    fn decode_brainpool_p384_point(bytes: &[u8]) -> Option<AffinePoint> {
        // Uncompressed Brainpool P-384 point: leading 0x04 +
        // 48-byte X + 48-byte Y = 97 bytes (SEC 1 §2.3.3).
        if bytes.len() != 97 || bytes.first() != Some(&0x04) {
            return None;
        }
        let mut buf = [0_u8; 97];
        buf.copy_from_slice(bytes);
        let point = AffinePoint::decode_uncompressed(&buf)?;
        if !point.is_on_curve() {
            return None;
        }
        Some(point)
    }
}

/// Random scalar in [1, n) for the Brainpool P-384 curve.
/// Standalone copy of the PACE module's local helper -- both
/// are 6-line rejection-sampling loops; not worth a public
/// surface.
fn random_scalar_in_range_n() -> Result<U384, crate::rng::Failure> {
    let n = brainpool_n();
    loop {
        let mut buf = [0_u8; 48];
        crate::rng::fill(&mut buf)?;
        let cand = U384::from_be_slice(&buf);
        if cand != U384::ZERO && cand < n {
            return Ok(cand);
        }
    }
}

#[cfg(test)]
mod tests {

    use super::{
        CA_MSE_SET_AT_P1, CaError, CaHelpers, CaOutcome, random_scalar_in_range_n,
        run_chip_authentication,
    };
    use crate::apdu::iso7816::ReadBinaryBySfi;
    use crate::apdu::status_word::StatusWord;
    use crate::atr::{Atr, AtrError, MINIMAL_DIRECT_ATR};
    use crate::ber::{self, BerTlvIter};
    use crate::crypto::brainpool_p384::{AffinePoint, n};
    use crate::crypto::container::{AesCbc, Ciphertext};
    use crate::crypto::symmetric::{
        AES_BLOCK, Aes256Key, KdfParam, aes256_cbc_decrypt_no_padding,
        aes256_cbc_encrypt_no_padding, aes256_cmac_truncated, aes256_ecb_encrypt_block, kdf_aes256,
    };
    use crate::emrtd::{Dg14SecurityInfo, SFI_EF_DG1};
    use crate::pace::commands::{GeneralAuthenticate, MseSetAt};
    use crate::pace::{PaceSession, Ssc};
    use crate::secure_messaging::{SmError, SmTransport};
    use crate::transport::{
        CardTransport, CommandApdu, ResponseApdu, TransportDispatchError, TransportOutcome,
    };
    use crypto_bigint::U384;

    /// The CA protocol label the driver looks for in DG14.
    const CA_LABEL: &str = "id-CA-ECDH-AES-CBC-CMAC-256";
    /// Body bytes of the `id-CA-ECDH-AES-CBC-CMAC-256` OID
    /// (`0.4.0.127.0.7.2.2.3.2.4`). The driver echoes these into the
    /// MSE:Set AT `80` DO; the mock dispatches on the APDU header, so
    /// the exact bytes only need to round-trip, not be re-parsed.
    const CA_PROTOCOL_OID: [u8; 10] = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x03, 0x02, 0x04];
    /// `id-ecPublicKey` (`1.2.840.10045.2.1`) as a full OID TLV.
    const OID_EC_PUBLIC_KEY: [u8; 9] = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    /// `brainpoolP384r1` (`1.3.36.3.3.2.8.1.1.11`) as a full OID TLV.
    const OID_BRAINPOOL_P384R1: [u8; 11] = [
        0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B,
    ];

    // MARK: - Fixture builders

    /// A deterministic, in-range Brainpool P-384 private scalar.
    ///
    /// The leading byte is forced below `0x8C` so the value is always
    /// `< n` (n starts `0x8CB9...`) and non-zero; varying `seed`
    /// produces distinct scalars (and thus distinct public points).
    fn fixed_scalar(seed: u8) -> U384 {
        let mut bytes = [0_u8; 48];
        for (i, b) in bytes.iter_mut().enumerate() {
            let idx = u8::try_from(i).expect("48-byte buffer index fits in u8");
            *b = seed.wrapping_add(idx).wrapping_mul(7);
        }
        bytes[0] = 0x12;
        U384::from_be_slice(&bytes)
    }

    /// Build a `SubjectPublicKeyInfo` DER for a Brainpool P-384 point,
    /// in the exact shape `SpkiDer::try_from` + the CA pubkey decoder
    /// expect: `SEQUENCE { SEQUENCE { ecPublicKey, brainpoolP384r1 },
    /// BIT STRING { 04 || X || Y } }`.
    fn brainpool_spki(point: &AffinePoint) -> Vec<u8> {
        let encoded = point.encode_uncompressed().expect("finite point encodes");
        let mut alg = Vec::new();
        alg.extend_from_slice(&OID_EC_PUBLIC_KEY);
        alg.extend_from_slice(&OID_BRAINPOOL_P384R1);
        let alg_id = ber::tlv(0x30, &alg);
        // BIT STRING value: leading 0x00 = "no unused bits", then the
        // 97-byte uncompressed point. `subject_public_key.raw_bytes()`
        // hands the decoder back exactly the 97 point bytes.
        let mut bit_string_value = Vec::with_capacity(98);
        bit_string_value.push(0x00);
        bit_string_value.extend_from_slice(encoded.as_bytes());
        let bit_string = ber::tlv(0x03, &bit_string_value);
        let mut spki = Vec::new();
        spki.extend_from_slice(&alg_id);
        spki.extend_from_slice(&bit_string);
        ber::tlv(0x30, &spki)
    }

    /// DG14 entries advertising CA over `brainpoolP384r1` with the
    /// chip's public point `q_picc`.
    fn dg14_for(q_picc: &AffinePoint) -> Vec<Dg14SecurityInfo> {
        vec![
            Dg14SecurityInfo::ChipAuthenticationInfo {
                protocol_label: CA_LABEL,
                oid: CA_PROTOCOL_OID.to_vec(),
                version: Some(1),
            },
            Dg14SecurityInfo::ChipAuthenticationPublicKeyInfo {
                oid: Vec::new(),
                spki_der: brainpool_spki(q_picc),
            },
        ]
    }

    fn pace_session(enc: [u8; 32], mac: [u8; 32]) -> PaceSession {
        PaceSession {
            k_enc: Aes256Key::from_bytes(enc).expect("non-zero K_enc"),
            k_mac: Aes256Key::from_bytes(mac).expect("non-zero K_mac"),
            ssc: Ssc::INITIAL,
        }
    }

    /// ISO/IEC 7816-4 mode-2 padding (local copy of the SM layer's
    /// private helper; `SmHelpers` is not reachable from this module).
    fn iso7816_pad(data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        out.push(0x80);
        while !out.len().is_multiple_of(AES_BLOCK) {
            out.push(0x00);
        }
        out
    }

    /// A bare transport-level rejection (non-9000 outer SW, empty
    /// body): the SM layer returns it verbatim without attempting an
    /// unwrap, which is how the driver distinguishes a card refusal
    /// from a successful SM exchange.
    fn raw_status(sw: u16) -> TransportOutcome {
        let [sw1, sw2] = sw.to_be_bytes();
        TransportOutcome::Response(ResponseApdu {
            body: Vec::new(),
            sw1,
            sw2,
        })
    }

    // MARK: - Chip-side mock

    /// In-memory chip that plays the PICC half of a CA round-trip.
    ///
    /// It mirrors the PCD's SM session exactly: it holds the same
    /// PACE-derived keys, tracks the SSC in lockstep (one bump per
    /// command, one per response), and -- on `General Authenticate` --
    /// recovers the reader's ephemeral point `Q_PCD` from the
    /// encrypted command body, runs ECDH against its CA private key
    /// `d_picc`, derives the new SM keys with the same KDF the driver
    /// uses, and rolls its own SM session onto them. The driver's
    /// probe APDU then succeeds iff both halves derived the same keys.
    struct ChipMock {
        k_enc: [u8; 32],
        k_mac: [u8; 32],
        ssc: Ssc,
        d_picc: U384,
        mse_sw: u16,
        ga_sw: u16,
    }

    impl ChipMock {
        fn new(enc: [u8; 32], mac: [u8; 32], d_picc: U384) -> Self {
            Self {
                k_enc: enc,
                k_mac: mac,
                ssc: Ssc::INITIAL,
                d_picc,
                mse_sw: 0x9000,
                ga_sw: 0x9000,
            }
        }

        fn reject_mse(mut self, sw: u16) -> Self {
            self.mse_sw = sw;
            self
        }

        fn reject_ga(mut self, sw: u16) -> Self {
            self.ga_sw = sw;
            self
        }

        /// Build an SM-protected response (response-side SSC bump,
        /// optional encrypted `DO87`, `DO99` status, `DO8E` MAC) under
        /// the chip's *current* keys -- the inverse of the driver's
        /// `SmTransport::unwrap`.
        fn sm_response(&mut self, body: &[u8], sw: u16) -> ResponseApdu {
            self.ssc.increment();
            let do_cipher = if body.is_empty() {
                Vec::new()
            } else {
                let padded = iso7816_pad(body);
                let iv = aes256_ecb_encrypt_block(&self.k_enc, self.ssc.as_bytes());
                let cipher = aes256_cbc_encrypt_no_padding(&self.k_enc, &iv, &padded)
                    .expect("padded body is block-aligned");
                let mut value = Vec::with_capacity(1 + cipher.as_bytes().len());
                value.push(0x01);
                value.extend_from_slice(cipher.as_bytes());
                ber::tlv(0x87, &value)
            };
            let do_status = ber::tlv(0x99, sw.to_be_bytes());
            let mut mac_input = Vec::new();
            mac_input.extend_from_slice(self.ssc.as_bytes());
            mac_input.extend_from_slice(&do_cipher);
            mac_input.extend_from_slice(&do_status);
            let mac_input = iso7816_pad(&mac_input);
            let tag = aes256_cmac_truncated(&self.k_mac, &mac_input);
            let do_mac = ber::tlv(0x8E, tag.as_bytes());
            let mut resp = Vec::new();
            resp.extend_from_slice(&do_cipher);
            resp.extend_from_slice(&do_status);
            resp.extend_from_slice(&do_mac);
            ResponseApdu {
                body: resp,
                sw1: 0x90,
                sw2: 0x00,
            }
        }

        /// Decrypt the `General Authenticate` command body and pull out
        /// the reader's ephemeral point `Q_PCD` from the
        /// `7C { 80 <point> }` payload. Uses the just-incremented
        /// command-side SSC for the per-message IV.
        fn recover_q_pcd(&self, wrapped: &[u8]) -> AffinePoint {
            assert!(wrapped.len() >= 5, "GA APDU carries a header and Lc");
            let lc = usize::from(wrapped[4]);
            let body = &wrapped[5..5 + lc];
            let mut cipher_do: Option<&[u8]> = None;
            for parsed in BerTlvIter::new(body) {
                let tlv = parsed.expect("SM command body is well-formed BER");
                if tlv.tag == u16::from(0x87_u8) {
                    cipher_do = Some(tlv.value);
                }
            }
            let cipher_do = cipher_do.expect("GA command carries an encrypted DO87");
            let cipher_bytes = &cipher_do[1..]; // strip the 0x01 padding indicator
            let iv = aes256_ecb_encrypt_block(&self.k_enc, self.ssc.as_bytes());
            let cipher = Ciphertext::<AesCbc>::new(cipher_bytes.to_vec());
            let plain = aes256_cbc_decrypt_no_padding(&self.k_enc, &iv, &cipher)
                .expect("DO87 ciphertext is block-aligned");
            // plain = 7C L { 80 L <97-byte point> } followed by padding;
            // BER length fields delimit the point, so trailing padding
            // is simply not consumed.
            let outer = BerTlvIter::new(&plain)
                .next()
                .expect("GA payload present")
                .expect("GA payload is valid BER");
            assert_eq!(outer.tag, u16::from(0x7C_u8), "GA payload wrapper is 0x7C");
            let inner = BerTlvIter::new(outer.value)
                .next()
                .expect("public-key DO present")
                .expect("public-key DO is valid BER");
            assert_eq!(inner.tag, u16::from(0x80_u8), "public-key DO is 0x80");
            AffinePoint::decode_uncompressed(inner.value).expect("Q_PCD is a valid curve point")
        }
    }

    impl CardTransport for ChipMock {
        type Error = String;

        fn transmit_outcome(&mut self, apdu: &CommandApdu) -> Result<TransportOutcome, String> {
            let wrapped = apdu.as_bytes();
            assert!(wrapped.len() >= 4, "SM APDU carries a 4-byte header");
            // INS/P1/P2 ride in the clear (only the CLA SM bit is set),
            // so the chip dispatches on the header without decrypting.
            let (ins, p1, p2) = (wrapped[1], wrapped[2], wrapped[3]);
            self.ssc.increment(); // command-side bump, mirrors the driver's wrap

            // MSE:Set AT (CA): 00 22 41 A4 ...
            if ins == MseSetAt::INS && p1 == CA_MSE_SET_AT_P1 && p2 == MseSetAt::P2 {
                if !StatusWord::from_u16(self.mse_sw).is_success() {
                    return Ok(raw_status(self.mse_sw));
                }
                return Ok(TransportOutcome::Response(self.sm_response(&[], 0x9000)));
            }

            // General Authenticate: 00 86 00 00 ...
            if ins == GeneralAuthenticate::INS
                && p1 == GeneralAuthenticate::P1
                && p2 == GeneralAuthenticate::P2
            {
                if !StatusWord::from_u16(self.ga_sw).is_success() {
                    return Ok(raw_status(self.ga_sw));
                }
                let q_pcd = self.recover_q_pcd(wrapped);
                // Acknowledge under the still-current PACE keys...
                let resp = self.sm_response(&[], 0x9000);
                // ...then derive CA session keys from the ECDH shared
                // secret and roll the chip's SM session over to them.
                let k_point = q_pcd.scalar_mul(&self.d_picc);
                let k_bytes = k_point
                    .encode_uncompressed()
                    .expect("shared secret is not the point at infinity");
                let k_x = &k_bytes.as_bytes()[1..49];
                self.k_enc = *kdf_aes256(k_x, KdfParam::Encryption).as_bytes();
                self.k_mac = *kdf_aes256(k_x, KdfParam::Mac).as_bytes();
                self.ssc = Ssc::INITIAL;
                return Ok(TransportOutcome::Response(resp));
            }

            // Validation probe: READ BINARY of short-EF DG1 (00 B0 81 00 04).
            if ins == ReadBinaryBySfi::INS && p1 == SFI_EF_DG1.as_p1_short_form() {
                return Ok(TransportOutcome::Response(
                    self.sm_response(&[0x61, 0x5B, 0x5F, 0x1F], 0x9000),
                ));
            }

            Err(format!("ChipMock: unexpected command INS={ins:#04X}"))
        }

        fn atr(&self) -> Result<Atr, AtrError> {
            Atr::new(MINIMAL_DIRECT_ATR)
        }
    }

    // MARK: - Helper unit tests (no card)

    #[test]
    fn pick_protocol_selects_aes256_ca() {
        let entries = vec![Dg14SecurityInfo::ChipAuthenticationInfo {
            protocol_label: CA_LABEL,
            oid: vec![1, 2, 3],
            version: Some(1),
        }];
        let (oid, label) = CaHelpers::pick_protocol(&entries).expect("AES-256 CA is supported");
        assert_eq!(label, CA_LABEL);
        assert_eq!(oid, &[1, 2, 3]);
    }

    #[test]
    fn pick_protocol_none_for_unsupported_or_empty() {
        assert!(CaHelpers::pick_protocol(&[]).is_none());
        let other = vec![
            Dg14SecurityInfo::ChipAuthenticationInfo {
                // legacy 3DES variant we deliberately don't drive
                protocol_label: "id-CA-ECDH-3DES-CBC-CBC",
                oid: vec![9],
                version: Some(1),
            },
            Dg14SecurityInfo::PaceInfo { oid: vec![7] },
        ];
        assert!(CaHelpers::pick_protocol(&other).is_none());
    }

    #[test]
    fn pick_public_key_decodes_brainpool_point() {
        let q = AffinePoint::generator().scalar_mul(&fixed_scalar(0x05));
        let entries = vec![Dg14SecurityInfo::ChipAuthenticationPublicKeyInfo {
            oid: Vec::new(),
            spki_der: brainpool_spki(&q),
        }];
        let decoded = CaHelpers::pick_public_key(&entries).expect("brainpool point decodes");
        assert_eq!(decoded, q);
    }

    #[test]
    fn pick_public_key_none_when_absent_or_undecodable() {
        assert!(CaHelpers::pick_public_key(&[]).is_none());
        // Structurally valid DER (empty SEQUENCE) but not a SPKI.
        let junk = vec![Dg14SecurityInfo::ChipAuthenticationPublicKeyInfo {
            oid: Vec::new(),
            spki_der: vec![0x30, 0x00],
        }];
        assert!(CaHelpers::pick_public_key(&junk).is_none());
    }

    #[test]
    fn decode_brainpool_p384_point_accepts_generator() {
        let g = AffinePoint::generator();
        let enc = g.encode_uncompressed().expect("generator encodes");
        let decoded =
            CaHelpers::decode_brainpool_p384_point(enc.as_bytes()).expect("on-curve point");
        assert_eq!(decoded, g);
    }

    #[test]
    fn decode_brainpool_p384_point_rejects_bad_shape() {
        let enc = *AffinePoint::generator()
            .encode_uncompressed()
            .expect("generator encodes")
            .as_bytes();
        // Wrong length.
        assert!(CaHelpers::decode_brainpool_p384_point(&enc[..96]).is_none());
        assert!(CaHelpers::decode_brainpool_p384_point(&[]).is_none());
        // Right length, wrong leading tag (0x04 is the only one we take).
        let mut bad_tag = enc;
        bad_tag[0] = 0x05;
        assert!(CaHelpers::decode_brainpool_p384_point(&bad_tag).is_none());
        // Right shape, coordinates off the curve (X = Y = 1).
        let mut off_curve = [0_u8; 97];
        off_curve[0] = 0x04;
        off_curve[48] = 0x01;
        off_curve[96] = 0x01;
        assert!(CaHelpers::decode_brainpool_p384_point(&off_curve).is_none());
    }

    #[test]
    fn random_scalar_is_nonzero_and_below_n() {
        let order = n();
        for _ in 0..64 {
            let s = random_scalar_in_range_n().expect("host RNG available");
            assert_ne!(s, U384::ZERO);
            assert!(s < order);
        }
    }

    #[test]
    fn ca_error_display_arms() {
        let too_long: CaError<String> = CaError::MseBodyTooLong { got: 300 };
        let rendered = format!("{too_long}");
        assert!(rendered.contains("300"), "{rendered}");
        assert!(rendered.contains("u8 Lc"), "{rendered}");

        let transport: CaError<String> =
            CaError::Transport(TransportDispatchError::Error(SmError::MacMismatch));
        let rendered = format!("{transport}");
        assert!(rendered.contains("CA transport"), "{rendered}");
        assert!(rendered.contains("MAC"), "{rendered}");
    }

    // MARK: - Driver outcome tests (against the chip mock)

    #[test]
    fn no_supported_protocol_when_dg14_lacks_ca() {
        // pick_protocol fails: no ChipAuthenticationInfo at all.
        let mut sm = SmTransport::new(
            ChipMock::new([0x11; 32], [0x22; 32], fixed_scalar(0x11)),
            pace_session([0x11; 32], [0x22; 32]),
        );
        let entries = vec![Dg14SecurityInfo::PaceInfo { oid: vec![1] }];
        assert_eq!(
            run_chip_authentication(&mut sm, &entries).expect("nothing sent to card"),
            CaOutcome::NoSupportedProtocol
        );
    }

    #[test]
    fn no_supported_protocol_when_public_key_missing() {
        // pick_protocol succeeds, but there's no pubkey info to ECDH against.
        let mut sm = SmTransport::new(
            ChipMock::new([0x11; 32], [0x22; 32], fixed_scalar(0x11)),
            pace_session([0x11; 32], [0x22; 32]),
        );
        let entries = vec![Dg14SecurityInfo::ChipAuthenticationInfo {
            protocol_label: CA_LABEL,
            oid: CA_PROTOCOL_OID.to_vec(),
            version: Some(1),
        }];
        assert_eq!(
            run_chip_authentication(&mut sm, &entries).expect("nothing sent to card"),
            CaOutcome::NoSupportedProtocol
        );
    }

    #[test]
    fn mse_rejected_surfaces_card_status() {
        let d_picc = fixed_scalar(0x11);
        let q_picc = AffinePoint::generator().scalar_mul(&d_picc);
        let card = ChipMock::new([0x33; 32], [0x44; 32], d_picc).reject_mse(0x6982);
        let mut sm = SmTransport::new(card, pace_session([0x33; 32], [0x44; 32]));
        assert_eq!(
            run_chip_authentication(&mut sm, &dg14_for(&q_picc)).expect("no transport error"),
            CaOutcome::MseRejected { sw: 0x6982 }
        );
    }

    #[test]
    fn ga_rejected_surfaces_card_status() {
        let d_picc = fixed_scalar(0x11);
        let q_picc = AffinePoint::generator().scalar_mul(&d_picc);
        // MSE accepted (full SM round-trip), GA refused.
        let card = ChipMock::new([0x33; 32], [0x44; 32], d_picc).reject_ga(0x6A80);
        let mut sm = SmTransport::new(card, pace_session([0x33; 32], [0x44; 32]));
        assert_eq!(
            run_chip_authentication(&mut sm, &dg14_for(&q_picc)).expect("no transport error"),
            CaOutcome::GaRejected { sw: 0x6A80 }
        );
    }

    /// The full anti-cloning round-trip: ephemeral keypair, ECDH shared
    /// secret, KDF rekey, and the post-rekey probe all line up because
    /// the chip holds the CA private key DG14 advertises.
    #[test]
    fn verified_on_full_round_trip() {
        let d_picc = fixed_scalar(0x11);
        let q_picc = AffinePoint::generator().scalar_mul(&d_picc);
        let card = ChipMock::new([0x33; 32], [0x44; 32], d_picc);
        let mut sm = SmTransport::new(card, pace_session([0x33; 32], [0x44; 32]));
        assert_eq!(
            run_chip_authentication(&mut sm, &dg14_for(&q_picc)).expect("no transport error"),
            CaOutcome::Verified {
                protocol_label: CA_LABEL
            }
        );
    }

    /// The validation-probe MAC-mismatch path: the chip holds a CA
    /// private key that does *not* match the public point DG14
    /// advertises, so the ECDH halves diverge, the derived SM keys
    /// differ, and the probe's response MAC fails to verify.
    #[test]
    fn verification_failed_when_chip_key_mismatches_dg14() {
        // DG14 advertises the point for the "real" key...
        let q_picc = AffinePoint::generator().scalar_mul(&fixed_scalar(0x11));
        // ...but the chip actually holds a different private key.
        let card = ChipMock::new([0x33; 32], [0x44; 32], fixed_scalar(0x77));
        let mut sm = SmTransport::new(card, pace_session([0x33; 32], [0x44; 32]));
        let outcome =
            run_chip_authentication(&mut sm, &dg14_for(&q_picc)).expect("no transport error");
        let CaOutcome::VerificationFailed { detail } = outcome else {
            panic!("expected VerificationFailed, got {outcome:?}");
        };
        assert!(
            detail.contains("MAC"),
            "expected MAC-mismatch detail: {detail}"
        );
    }
}
