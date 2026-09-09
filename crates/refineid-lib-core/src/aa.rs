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

//! Active Authentication (ICAO 9303-11 §6.1).
//!
//! Anti-cloning round-trip for v3.1-era eMRTDs that carry an AA
//! private key on chip and the matching public key in DG15. The
//! reader generates an 8-byte challenge, sends it via the
//! `INTERNAL AUTHENTICATE` APDU, and the chip signs
//! `F = 6A || M1 || H(M1 || RND.IFD) || T` per ISO/IEC 9796-2
//! Digital Signature Scheme 1. The reader RSA-recovers `F`,
//! decodes the trailer to learn the hash algorithm, extracts
//! `M1` and the embedded hash, and verifies the chip used a
//! private key matching DG15's public key.
//!
//! Successful AA proves the chip itself produced the signature
//! -- a clone with only the public DGs (which are signed by the
//! CSCA but not chip-bound) couldn't produce the response. AA
//! is mutually exclusive with Chip Authentication (CA, the v4.0
//! replacement) but a card may publish either or both; FINEID
//! v3.1 cards publish AA via DG15, v4.0 cards publish CA via
//! DG14.
//!
//! AA must run after PACE on a FINEID card -- the eMRTD applet
//! refuses the INTERNAL AUTHENTICATE APDU outside Secure
//! Messaging. Callers pass an already-SM-wrapped transport.

use crate::apdu::iso7816::InternalAuthenticate;
use crate::crypto::rsa::{HashAlg, RsaPublicKey, RsaVerifyError, verify_iso9796_2_ds1};
use crate::transport::{CardTransport, TransportDispatchError};

/// Outcome of an AA round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AaOutcome {
    /// Chip's signature verified against the DG15 public key
    /// -- the chip is the genuine card, not a clone of the DGs.
    Verified {
        /// Hash function the chip used (decoded from the
        /// ISO 9796-2 trailer).
        hash: HashAlg,
        /// Length of the recovered `M1` (random padding from
        /// the chip). Surfaced for inspection; not load-bearing.
        m1_len: usize,
    },
    /// Card refused the `INTERNAL AUTHENTICATE` APDU. Typical
    /// causes: AA disabled on this chip, applet doesn't
    /// implement AA, SM session not yet established.
    CardRejected {
        /// Card-returned status word per ISO 7816-4 §5.1.3.
        sw: u16,
    },
    /// Card responded but the signature didn't verify. Either
    /// the chip's private key doesn't match DG15 (the card has
    /// been tampered with) or our verifier rejected the padding
    /// shape.
    SignatureInvalid {
        /// Human-readable detail naming the verifier rejection
        /// (padding shape, trailer byte, recovered-hash
        /// mismatch). Tier 0 `String`; presentational.
        detail: String,
    },
}

/// Errors that abort the round-trip before the verifier sees a
/// response.
#[derive(Debug)]
pub enum AaError<TE>
where
    TE: core::fmt::Debug + core::fmt::Display,
{
    /// Transport / SM I/O failure.
    Transport(TransportDispatchError<TE>),
    /// The DG15 `SubjectPublicKeyInfo` didn't parse as an RSA
    /// public key. ECC AA keys are also valid per ICAO 9303-11
    /// but FINEID v3.1 cards in scope use RSA; ECDSA-AA
    /// support is a future addition.
    UnsupportedKey,
    /// The OS random source failed -- shouldn't happen on a
    /// healthy host, surfaced rather than silently retried.
    Random(crate::rng::Failure),
}

impl<TE> core::fmt::Display for AaError<TE>
where
    TE: core::fmt::Debug + core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "AA transport: {e}"),
            Self::UnsupportedKey => write!(
                f,
                "AA pubkey isn't RSA (only RSA AA keys currently supported)"
            ),
            Self::Random(e) => write!(f, "AA random: {e}"),
        }
    }
}

impl<TE> core::error::Error for AaError<TE> where TE: core::fmt::Debug + core::fmt::Display + 'static
{}

/// Run an Active Authentication round-trip against `transport`
/// using the supplied `dg15_pubkey`.
///
/// Generates a fresh 8-byte challenge, sends `INTERNAL
/// AUTHENTICATE` (`CLA=00 INS=88 P1=00 P2=00 Lc=08
/// Data=challenge Le=00`), and verifies the chip's
/// ISO/IEC 9796-2 DS1 signature against the public key.
///
/// `transport` must already be running Secure Messaging post-
/// PACE -- the eMRTD applet refuses unprotected APDUs.
///
/// # Errors
/// [`AaError`] for transport / key-parse / RNG failures. The
/// returned [`AaOutcome`] distinguishes successful verification
/// from card-rejected and signature-invalid cases, so callers
/// can render the right diagnostic.
pub(crate) fn run_active_authentication<T: CardTransport>(
    transport: &mut T,
    dg15_pubkey: &RsaPublicKey,
) -> Result<AaOutcome, AaError<T::Error>> {
    let mut rnd_ifd = [0_u8; 8];
    crate::rng::fill(&mut rnd_ifd).map_err(AaError::Random)?;

    let apdu = InternalAuthenticate { challenge: rnd_ifd }.into_apdu();
    let response = transport
        .transmit(apdu.as_bytes())
        .map_err(AaError::Transport)?;
    if !response.is_ok() {
        return Ok(AaOutcome::CardRejected { sw: response.sw() });
    }
    let signature = response.body;
    match verify_iso9796_2_ds1(dg15_pubkey, &rnd_ifd, &signature) {
        Ok(recovered) => Ok(AaOutcome::Verified {
            hash: recovered.hash,
            m1_len: recovered.m1.len(),
        }),
        Err(e) => Ok(AaOutcome::SignatureInvalid {
            detail: format!("{e}"),
        }),
    }
}

/// Wire the `RsaVerifyError` enum into the AA outcome's
/// `SignatureInvalid` carrier without forcing the outcome enum
/// to depend on the crypto error type.
impl From<RsaVerifyError> for AaOutcome {
    fn from(e: RsaVerifyError) -> Self {
        Self::SignatureInvalid {
            detail: format!("{e}"),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::{AaError, AaOutcome, run_active_authentication};
    use crate::atr::{Atr, AtrError, MINIMAL_DIRECT_ATR};
    use crate::crypto::rsa::{
        HashAlg, RsaModulus, RsaPublicExponent, RsaPublicKey, RsaVerifyError,
    };
    use crate::transport::{
        CardTransport, CommandApdu, ResponseApdu, TransportDispatchError, TransportOutcome,
    };
    use crypto_bigint::{
        BoxedUint, Odd,
        modular::{BoxedMontyForm, BoxedMontyParams},
    };
    use sha1::Sha1;
    use sha2::{Digest as _, Sha256, Sha384, Sha512};

    // An RSA-1024 keypair built offline with OpenSSL -- lib-core is
    // verify-only and never generates or holds private keys, so the
    // chip-mock signer below needs a committed private exponent to
    // play the PICC half of the ISO 9796-2 DS1 round-trip. Generated
    // with:
    //
    // ```sh
    // openssl genrsa 1024 > aa_test.pem
    // openssl rsa -in aa_test.pem -text -noout
    // ```
    //
    // then the modulus / private-exponent blocks were hex-joined with
    // the ASN.1 sign byte stripped. e = 65537 (the OpenSSL default and
    // the value FINEID issues). 1024-bit clears the 512-bit
    // `RsaModulus::MIN_BITS` floor while keeping the in-test modexp fast.

    /// DG15 RSA modulus `n` (128 bytes, canonical PKCS#1, no sign byte).
    const N_HEX: &str = "dc6b0cc4238ded3c8d7053307b1f321be3b0500ec973e64ea47596cbfacf91d9\
4126d5b059fe1ca835c1a4b6868e0d82ceab655e9556b4ffb58d159b06b587ce5\
504badce3a2e2d043e06387e5cb3c2ff4d97c365add868e47ba31964c23a96533\
ea5b5fbbdd1fe129b69e2923b9620db65592a4a94e4be1be731488849ed193";
    /// Matching private exponent `d` (held only by the chip mock).
    const D_HEX: &str = "b57624226daaf07e836acff1ffcae4f3f4f538539422289ee1e234ed6564f18b\
cc896e2f2b477acc38c55d172f9b4f203b88fb816cacdf820d334370478bb76ae\
d7ceb4ad6b8b5baf2a6bbd26bc34d8e3f5393c38af42ec4a6c0ed2fa056a5ad26\
b3dbd3288fcb53327ee5a5ebd487e96e8f4e8a41c998494dcf1288a39a9b91";

    /// `INTERNAL AUTHENTICATE` instruction byte (ISO 7816-4).
    const INS_INTERNAL_AUTHENTICATE: u8 = 0x88;
    /// Leading byte of an ISO 9796-2 DS1 recoverable message.
    const ISO9796_DS1_LEADING_BYTE: u8 = 0x6A;
    /// Implicit trailer (SHA-1).
    const TRAILER_SHA1: &[u8] = &[0xBC];
    /// Explicit trailer for SHA-256 (`HFI=0x34 || 0xCC`).
    const TRAILER_SHA256: &[u8] = &[0x34, 0xCC];
    /// Explicit trailer for SHA-384 (`HFI=0x36 || 0xCC`, ISO/IEC 10118-3).
    const TRAILER_SHA384: &[u8] = &[0x36, 0xCC];
    /// Explicit trailer for SHA-512 (`HFI=0x35 || 0xCC`, ISO/IEC 10118-3).
    const TRAILER_SHA512: &[u8] = &[0x35, 0xCC];

    // MARK: - Fixture builders

    fn modulus_bytes() -> Vec<u8> {
        hex::decode(N_HEX).expect("N_HEX is valid hex")
    }

    fn private_exponent_bytes() -> Vec<u8> {
        hex::decode(D_HEX).expect("D_HEX is valid hex")
    }

    /// The DG15 public key the driver verifies against.
    fn dg15_pubkey() -> RsaPublicKey {
        RsaPublicKey {
            modulus: RsaModulus::try_from_pkcs1(modulus_bytes())
                .expect("committed 1024-bit modulus is canonical PKCS#1"),
            exponent: RsaPublicExponent::e_65537(),
        }
    }

    /// Per-hash digest length and trailer bytes (ICAO 9303-11 §6.1 /
    /// ISO 9796-2 §9).
    fn hash_params(hash: HashAlg) -> (usize, &'static [u8]) {
        match hash {
            HashAlg::Sha1 => (20, TRAILER_SHA1),
            HashAlg::Sha256 => (32, TRAILER_SHA256),
            HashAlg::Sha384 => (48, TRAILER_SHA384),
            HashAlg::Sha512 => (64, TRAILER_SHA512),
        }
    }

    /// `H(m1 || m2)` for the trailer's hash function.
    fn digest_concat(hash: HashAlg, m1: &[u8], m2: &[u8]) -> Vec<u8> {
        match hash {
            HashAlg::Sha1 => {
                let mut h = Sha1::new();
                h.update(m1);
                h.update(m2);
                h.finalize().to_vec()
            }
            HashAlg::Sha256 => {
                let mut h = Sha256::new();
                h.update(m1);
                h.update(m2);
                h.finalize().to_vec()
            }
            HashAlg::Sha384 => {
                let mut h = Sha384::new();
                h.update(m1);
                h.update(m2);
                h.finalize().to_vec()
            }
            HashAlg::Sha512 => {
                let mut h = Sha512::new();
                h.update(m1);
                h.update(m2);
                h.finalize().to_vec()
            }
        }
    }

    /// RSA raw exponentiation `base^exp mod n`, returned as exactly `k`
    /// big-endian bytes -- the chip's private-key operation, the inverse
    /// of the verifier's `raw_recover`. Mirrors the crypto-bigint modexp
    /// the production verifier uses so the two halves agree bit-for-bit.
    fn raw_rsa_exp(n: &[u8], exp: &[u8], base: &[u8]) -> Vec<u8> {
        let k = n.len();
        let bits =
            (u32::try_from(k).expect("modulus byte length fits u32") * 8).next_multiple_of(64);
        let modulus = BoxedUint::from_be_slice(n, bits).expect("modulus decodes");
        let exponent = BoxedUint::from_be_slice_vartime(exp);
        let base_uint = BoxedUint::from_be_slice(base, bits).expect("base decodes");
        let odd: Odd<BoxedUint> = Option::from(Odd::new(modulus)).expect("modulus is odd");
        let params = BoxedMontyParams::new(odd);
        let form = BoxedMontyForm::new(base_uint, &params);
        let result = form.pow(&exponent).retrieve().to_be_bytes();
        // Right-align into a k-byte buffer (the modexp result never
        // exceeds the modulus, so it fits in k bytes).
        let src = result.as_ref();
        let mut out = vec![0_u8; k];
        let copy = src.len().min(k);
        out[k - copy..].copy_from_slice(&src[src.len() - copy..]);
        out
    }

    /// Build a valid ISO 9796-2 DS1 signature over `challenge` using the
    /// committed private key: `s = (6A || M1 || H(M1 || challenge) || T)^d
    /// mod n`. `M1` is sized so the recoverable message fills the whole
    /// modulus.
    fn ds1_signature(hash: HashAlg, challenge: &[u8]) -> Vec<u8> {
        let n = modulus_bytes();
        let d = private_exponent_bytes();
        let k = n.len();
        let (digest_len, trailer) = hash_params(hash);
        let m1_len = k - 1 - digest_len - trailer.len();
        let m1 = vec![0xA5_u8; m1_len];
        let digest = digest_concat(hash, &m1, challenge);
        let mut f = Vec::with_capacity(k);
        f.push(ISO9796_DS1_LEADING_BYTE);
        f.extend_from_slice(&m1);
        f.extend_from_slice(&digest);
        f.extend_from_slice(trailer);
        assert_eq!(f.len(), k, "recoverable message must be exactly k bytes");
        raw_rsa_exp(&n, &d, &f)
    }

    // MARK: - Chip-side mock

    /// What the in-memory chip does when it receives `INTERNAL
    /// AUTHENTICATE`.
    enum ChipBehavior {
        /// Sign the received challenge correctly with the given hash.
        Sign(HashAlg),
        /// Sign a *mutated* challenge -- structurally valid DS1, wrong
        /// digest. Models a response not bound to *this* nonce.
        SignWrongChallenge(HashAlg),
        /// Reply with a non-success status word (AA disabled / not in SM).
        Reject(u16),
        /// Reply 9000 but with a body that isn't a `k`-byte signature.
        MalformedBody(Vec<u8>),
        /// Backend transport failure before any response arrives.
        TransportFail,
    }

    /// In-memory chip that plays the PICC half of an AA round-trip: it
    /// reads the reader's 8-byte challenge straight out of the APDU
    /// (offset 5..13) and reacts per its [`ChipBehavior`].
    struct AaChip {
        behavior: ChipBehavior,
    }

    impl AaChip {
        fn new(behavior: ChipBehavior) -> Self {
            Self { behavior }
        }
    }

    impl CardTransport for AaChip {
        type Error = String;

        fn transmit_outcome(&mut self, apdu: &CommandApdu) -> Result<TransportOutcome, String> {
            let bytes = apdu.as_bytes();
            // 00 88 00 00 08 <8-byte challenge> 00  == 14 bytes.
            assert_eq!(bytes.len(), 14, "AA APDU is 14 bytes");
            assert_eq!(
                bytes[1], INS_INTERNAL_AUTHENTICATE,
                "INS is INTERNAL AUTHENTICATE"
            );
            assert_eq!(bytes[4], 0x08, "Lc announces an 8-byte challenge");
            let challenge = &bytes[5..13];

            let response = match &self.behavior {
                ChipBehavior::TransportFail => {
                    return Err("simulated reader I/O failure".to_owned());
                }
                ChipBehavior::Reject(sw) => {
                    let [sw1, sw2] = sw.to_be_bytes();
                    ResponseApdu {
                        body: Vec::new(),
                        sw1,
                        sw2,
                    }
                }
                ChipBehavior::MalformedBody(body) => ResponseApdu {
                    body: body.clone(),
                    sw1: 0x90,
                    sw2: 0x00,
                },
                ChipBehavior::Sign(hash) => ResponseApdu {
                    body: ds1_signature(*hash, challenge),
                    sw1: 0x90,
                    sw2: 0x00,
                },
                ChipBehavior::SignWrongChallenge(hash) => {
                    let mut wrong = challenge.to_vec();
                    wrong[0] ^= 0x01; // guarantee it differs from the real nonce
                    ResponseApdu {
                        body: ds1_signature(*hash, &wrong),
                        sw1: 0x90,
                        sw2: 0x00,
                    }
                }
            };
            Ok(TransportOutcome::Response(response))
        }

        fn atr(&self) -> Result<Atr, AtrError> {
            Atr::new(MINIMAL_DIRECT_ATR)
        }
    }

    // MARK: - Driver outcome tests (against the chip mock)

    /// Drive a full round-trip against a chip that signs correctly with
    /// `hash` and assert the `Verified` outcome carries that hash plus
    /// the expected recovered-`M1` length.
    fn assert_verified_for(hash: HashAlg) {
        let mut transport = AaChip::new(ChipBehavior::Sign(hash));
        let outcome =
            run_active_authentication(&mut transport, &dg15_pubkey()).expect("no transport error");
        let k = modulus_bytes().len();
        let (digest_len, trailer) = hash_params(hash);
        let expected_m1 = k - 1 - digest_len - trailer.len();
        assert_eq!(
            outcome,
            AaOutcome::Verified {
                hash,
                m1_len: expected_m1
            },
            "hash={hash:?}"
        );
    }

    #[test]
    fn verified_round_trip_sha256() {
        assert_verified_for(HashAlg::Sha256);
    }

    #[test]
    fn verified_round_trip_sha1_implicit_trailer() {
        assert_verified_for(HashAlg::Sha1);
    }

    #[test]
    fn verified_round_trip_sha384_and_sha512() {
        assert_verified_for(HashAlg::Sha384);
        assert_verified_for(HashAlg::Sha512);
    }

    #[test]
    fn card_rejected_surfaces_status_word() {
        // 0x6982 "security status not satisfied" -- e.g. AA attempted
        // outside an established SM session.
        let mut transport = AaChip::new(ChipBehavior::Reject(0x6982));
        let outcome = run_active_authentication(&mut transport, &dg15_pubkey())
            .expect("card refusal is an outcome, not an error");
        assert_eq!(outcome, AaOutcome::CardRejected { sw: 0x6982 });
    }

    #[test]
    fn signature_invalid_on_challenge_mismatch() {
        // The chip signs a different challenge than the reader sent. The
        // DS1 structure recovers cleanly, but H(M1 || wrong) != H(M1 ||
        // RND.IFD), so the verifier rejects with a digest mismatch. This
        // is AA's anti-cloning core: a response not cryptographically
        // bound to *this* fresh nonce is refused.
        let mut transport = AaChip::new(ChipBehavior::SignWrongChallenge(HashAlg::Sha256));
        let outcome = run_active_authentication(&mut transport, &dg15_pubkey())
            .expect("verification failure is an outcome, not an error");
        let AaOutcome::SignatureInvalid { detail } = outcome else {
            panic!("expected SignatureInvalid, got {outcome:?}");
        };
        assert!(detail.contains("digest"), "{detail}");
    }

    #[test]
    fn signature_invalid_on_malformed_body() {
        // Card answers 9000 but the body is too short to be a k-byte RSA
        // signature -- the verifier's length guard fires.
        let mut transport = AaChip::new(ChipBehavior::MalformedBody(vec![0xDE, 0xAD, 0xBE, 0xEF]));
        let outcome = run_active_authentication(&mut transport, &dg15_pubkey())
            .expect("verification failure is an outcome, not an error");
        let AaOutcome::SignatureInvalid { detail } = outcome else {
            panic!("expected SignatureInvalid, got {outcome:?}");
        };
        assert!(detail.contains("range"), "{detail}");
    }

    #[test]
    fn transport_error_aborts_round_trip() {
        let mut transport = AaChip::new(ChipBehavior::TransportFail);
        let err = run_active_authentication(&mut transport, &dg15_pubkey())
            .expect_err("a backend I/O failure aborts the round-trip");
        let AaError::Transport(_) = err else {
            panic!("expected AaError::Transport, got {err:?}");
        };
    }

    // MARK: - Pure unit tests (no card)

    #[test]
    fn rsa_verify_error_maps_to_signature_invalid() {
        let outcome: AaOutcome = RsaVerifyError::BadDigest.into();
        let AaOutcome::SignatureInvalid { detail } = outcome else {
            panic!("From<RsaVerifyError> must produce SignatureInvalid, got {outcome:?}");
        };
        assert_eq!(detail, format!("{}", RsaVerifyError::BadDigest));
    }

    #[test]
    fn aa_error_display_arms() {
        let transport: AaError<String> =
            AaError::Transport(TransportDispatchError::Outcome(TransportOutcome::NoCard));
        assert!(
            format!("{transport}").contains("AA transport"),
            "{transport}"
        );

        let unsupported: AaError<String> = AaError::UnsupportedKey;
        assert!(format!("{unsupported}").contains("RSA"), "{unsupported}");

        let random: AaError<String> = AaError::Random(crate::rng::Failure::UNSUPPORTED);
        assert!(format!("{random}").starts_with("AA random"), "{random}");
    }
}
