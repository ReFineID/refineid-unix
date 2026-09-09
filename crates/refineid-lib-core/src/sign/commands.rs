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

//! Typed APDU commands for the sign / decrypt module.
//!
//! Refineid issues these FINEID S1 v4.2 commands during a
//! signing or decryption flow:
//!
//! - `MSE: SET` (§3.6) picks the security-environment template
//!   (Hashing / DST / CT) and the algorithm + key reference.
//! - `PSO: HASH` (§3.7) ships an externally-computed digest to
//!   the card for it to sign.
//! - `PSO: CDS` (§3.8) returns the signature over the
//!   previously stored hash.
//! - `PSO: DECIPHER` (§3.9 / §3.10) sends ciphertext and
//!   receives plaintext.
//!
//! Each command is one typed struct here; `into_apdu(self) ->
//! CommandApdu` does the byte serialisation at the transport
//! boundary so consumers cannot build a malformed signing APDU.

use crate::apdu::iso7816::ApduClass;
use crate::sign::KeyRef;
use crate::transport::CommandApdu;

/// CRDO tag for the algorithm reference inside the MSE: SET
/// data field per FINEID S1 v4.2 §3.6.3 Table 4.
pub const CRDO_TAG_ALG_REF: u8 = 0x80;

/// CRDO tag for the key reference inside the MSE: SET data
/// field per FINEID S1 v4.2 §3.6.3 Table 4.
pub const CRDO_TAG_KEY_REF: u8 = 0x84;

/// CRDO length byte: refineid only emits 1-byte algorithm /
/// key references (matches Table 5: `80 01 xx`, `84 01 xx`).
const CRDO_VALUE_LEN_BYTE: u8 = 0x01;

/// Hash algorithm component of a DST / Hashing-template
/// algorithm reference per FINEID S1 v4.2 §3.6.3 Table 6.
///
/// The algorithm-reference byte is split nibble-wise: the high
/// nibble names the hash function, the low nibble names the
/// signature scheme. [`SignatureAlgRef::from_parts`] composes
/// the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// `0Xh` -- no hash indicated (hash function defined
    /// implicitly or not applicable).
    None,
    /// `1Xh` -- SHA-1.
    Sha1,
    /// `3Xh` -- SHA-224.
    Sha224,
    /// `4Xh` -- SHA-256.
    Sha256,
    /// `5Xh` -- SHA-384.
    Sha384,
    /// `6Xh` -- SHA-512.
    Sha512,
}

impl HashAlgorithm {
    /// High nibble of the algorithm-reference byte per Table 6.
    #[must_use]
    pub const fn high_nibble(self) -> u8 {
        match self {
            Self::None => 0x0,
            Self::Sha1 => 0x1,
            Self::Sha224 => 0x3,
            Self::Sha256 => 0x4,
            Self::Sha384 => 0x5,
            Self::Sha512 => 0x6,
        }
    }
}

/// Signature-scheme component of a DST / Hashing-template
/// algorithm reference per FINEID S1 v4.2 §3.6.3 Table 6.
///
/// Carried as the *low* nibble of the algorithm-reference byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    /// `X1h` -- RSA with padding per ISO 9796-2.
    RsaIso9796V2,
    /// `X2h` -- RSASSA-PKCS1-v1_5 (PKCS#1 v2.2 with RSA,
    /// compatible with PKCS#1 v1.5). The FINEID-issued
    /// signing key uses `42h` = SHA-256 + this scheme.
    RsaPkcs1V1_5,
    /// `X3h` -- RSA with padding per RFC 2409.
    RsaRfc2409,
    /// `X4h` -- ECDSA.
    Ecdsa,
    /// `X5h` -- RSA PSS.
    RsaPss,
}

impl SignatureAlgorithm {
    /// Low nibble of the algorithm-reference byte per Table 6.
    #[must_use]
    pub const fn low_nibble(self) -> u8 {
        match self {
            Self::RsaIso9796V2 => 0x1,
            Self::RsaPkcs1V1_5 => 0x2,
            Self::RsaRfc2409 => 0x3,
            Self::Ecdsa => 0x4,
            Self::RsaPss => 0x5,
        }
    }
}

/// Algorithm-reference byte for the DST / Hashing template
/// (tag `80h` CRDO in MSE: SET data field) per FINEID S1 v4.2
/// §3.6.3 Table 6.
///
/// The wire byte packs `(hash high-nibble | sig low-nibble)`.
/// Construction via [`SignatureAlgRef::from_parts`] keeps the
/// two halves explicit at every call site; named constants
/// expose the values FINEID cards actually accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignatureAlgRef {
    /// Packed `(hash high-nibble | sig low-nibble)` byte per
    /// FINEID S1 v4.2 §3.6.3 Table 6. Single source of truth
    /// for the wire byte sent inside `MSE:SET` DO `80`.
    byte: u8,
}

impl SignatureAlgRef {
    /// Compose a (hash, signature) pair into the algorithm-
    /// reference byte.
    #[must_use]
    pub const fn from_parts(hash: HashAlgorithm, signature: SignatureAlgorithm) -> Self {
        Self {
            byte: (hash.high_nibble() << 4) | signature.low_nibble(),
        }
    }

    /// SHA-256 + RSASSA-PKCS1-v1_5 = `42h`. Refineid's default
    /// signing chain (FINEID S1 v4.2 §3.6, every catalogued
    /// production card).
    pub const SHA256_RSA_PKCS1_V1_5: Self =
        Self::from_parts(HashAlgorithm::Sha256, SignatureAlgorithm::RsaPkcs1V1_5);

    /// SHA-384 + ECDSA = `54h`. FINEID S4-1 v4.2 §4.2 Newer-
    /// scheme ECC P-384 (secp384r1) auth and qualified-signature
    /// keys sign under this algRef.
    pub const SHA384_ECDSA: Self =
        Self::from_parts(HashAlgorithm::Sha384, SignatureAlgorithm::Ecdsa);

    /// SHA-224 + ECDSA = `34h`. Some government trust-service
    /// profiles request this digest for P-384 keys, so the card
    /// command table keeps it as a named constant.
    pub const SHA224_ECDSA: Self =
        Self::from_parts(HashAlgorithm::Sha224, SignatureAlgorithm::Ecdsa);

    /// SHA-256 + ECDSA = `44h`. The same P-384 auth key signs a
    /// SHA-256 digest under this algRef -- FINEID S4-1 v4.2 lists
    /// `ckm-ecdsa-sha256` (`CIAInfo` ref 18, compute-signature) on the
    /// auth key. macOS `SecureTransport` requests ECDSA+SHA-256 for the
    /// TLS-1.2 `CertificateVerify` against `kortti.tunnistautuminen.suomi.fi`
    /// even with a P-384 key, so this algRef is required for that hop.
    pub const SHA256_ECDSA: Self =
        Self::from_parts(HashAlgorithm::Sha256, SignatureAlgorithm::Ecdsa);

    /// Raw RSASSA-PKCS1 = `40h` -- the "no hash indicated" RSA-PKCS
    /// reference the FINEID S4 RSA security environment recognises
    /// (S1 v4.2 §4.7.1). The host supplies the fully padded /
    /// encoded block via PSO:CDS data; the card performs only the
    /// private-key operation. Required by the RSA-PSS path where
    /// EMSA-PSS encoding happens host-side.
    pub const RSA_PKCS1_RAW: Self = Self { byte: 0x40 };

    /// Wire byte.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self.byte
    }
}

/// Algorithm reference for the Confidentiality Template (tag
/// `80h` CRDO under P2 = B8h) per FINEID S1 v4.2 §3.6.3 Table 7.
///
/// Decipher algorithms are listed as fixed byte values rather
/// than nibble-packed pairs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecipherAlgRef {
    /// `1Ah` -- RSASSA PKCS#1 v1.5. (Table 7 lists this in the
    /// decipher set; semantically PKCS#1 v1.5 RSA decryption.)
    RsassaPkcs1V1_5,
    /// `1Dh` -- RSAES-OAEP with SHA-1 (160 bits).
    RsaesOaepSha1,
    /// `3Dh` -- RSAES-OAEP with SHA-224.
    RsaesOaepSha224,
    /// `4Dh` -- RSAES-OAEP with SHA-256.
    RsaesOaepSha256,
    /// `5Dh` -- RSAES-OAEP with SHA-384.
    RsaesOaepSha384,
    /// `6Dh` -- RSAES-OAEP with SHA-512.
    RsaesOaepSha512,
}

impl DecipherAlgRef {
    /// Wire byte per Table 7.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::RsassaPkcs1V1_5 => 0x1A,
            Self::RsaesOaepSha1 => 0x1D,
            Self::RsaesOaepSha224 => 0x3D,
            Self::RsaesOaepSha256 => 0x4D,
            Self::RsaesOaepSha384 => 0x5D,
            Self::RsaesOaepSha512 => 0x6D,
        }
    }
}

/// Which security-environment template MSE: SET targets per
/// FINEID S1 v4.2 §3.6.3 Table 5.
///
/// The variant picks both the P2 byte and the body shape:
///
/// - [`MseSetTemplate::Hashing`] -> P2 = `AAh`, body `80 01 <alg>`
/// - [`MseSetTemplate::DigitalSignature`] -> P2 = B6h, body
///   `80 01 <alg> 84 01 <key>`
/// - [`MseSetTemplate::DeciphermentRsa`] -> P2 = B8h, body
///   `80 01 <alg> 84 01 <key>`
/// - [`MseSetTemplate::DeciphermentElc`] -> P2 = B8h, body
///   `84 01 <key>` (ELC use omits the algorithm reference)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MseSetTemplate {
    /// Hashing template (HT). Card prepares to hash the next
    /// PSO: HASH bytes under `alg_ref`.
    Hashing {
        /// Hash algorithm reference. The signature-scheme low
        /// nibble is irrelevant when only hashing is requested;
        /// callers typically pass `(hash, RsaPkcs1V1_5)` to
        /// match the subsequent signing chain.
        alg_ref: SignatureAlgRef,
    },
    /// Digital Signature Template (DST). Card prepares to sign
    /// a previously hashed message under `(alg_ref, key_ref)`.
    DigitalSignature {
        /// Signing algorithm reference (hash + sig nibbles).
        alg_ref: SignatureAlgRef,
        /// Private-key reference to use for the signature.
        key_ref: KeyRef,
    },
    /// Authentication Template (AT). Same body shape as the DST
    /// but P2 = `A4h`. FINEID cards gate the raw-PKCS signing
    /// primitive on the **auth key** behind the AT -- client-auth
    /// use cases (RSA-PSS host-side padding) select the security
    /// environment through this template instead of the DST.
    Authentication {
        /// Signing algorithm reference.
        alg_ref: SignatureAlgRef,
        /// Private-key reference to use for the signature.
        key_ref: KeyRef,
    },
    /// Confidentiality Template (CT) for RSA decipherment.
    DeciphermentRsa {
        /// Decipher algorithm reference.
        alg_ref: DecipherAlgRef,
        /// Private-key reference for the decrypt operation.
        key_ref: KeyRef,
    },
    /// Confidentiality Template (CT) for ELC decipherment.
    /// Spec omits the algorithm-reference CRDO; only the
    /// key-reference CRDO is sent.
    DeciphermentElc {
        /// Private-key reference for the decrypt operation.
        key_ref: KeyRef,
    },
}

impl MseSetTemplate {
    /// P2 wire byte per Table 5.
    #[must_use]
    pub const fn p2(self) -> u8 {
        match self {
            Self::Hashing { .. } => 0xAA,
            Self::DigitalSignature { .. } => 0xB6,
            Self::Authentication { .. } => 0xA4,
            Self::DeciphermentRsa { .. } | Self::DeciphermentElc { .. } => 0xB8,
        }
    }
}

/// FINEID S1 v4.2 §3.6 MANAGE SECURITY ENVIRONMENT: SET.
///
/// Updates a CRT (Control Reference Template) in the current
/// SE. Per §3.6 the original SE's CRT value is unaffected --
/// the update applies only to the current SE.
///
/// Wire shape per §3.6.2:
/// `CLA 22 41 <P2> Lc <CRDOs>`. No Le.
///
/// Field semantics:
///
/// - `CLA`: [`ApduClass`] -- plain (`00h`), secure messaging
///   (`0Ch`), or chained-first (`10h`).
/// - `INS`: fixed at `22h`.
/// - `P1`: fixed at `41h` (SET = computation and deciphering).
/// - `P2`: from [`MseSetTemplate::p2`].
/// - `Lc` + `Data`: concatenation of CRDOs per Table 5; refineid
///   builds the byte sequence from the typed
///   [`MseSetTemplate`]. The data does NOT contain the tag or
///   length of the CRT itself.
/// - `Le`: empty.
///
/// §3.6.3 status words:
/// - `9000h` success
/// - `6700h` incorrect length (Lc > 30)
/// - `6982h` security status not satisfied (SM error)
/// - `6985h` conditions of use not satisfied
/// - `6A80h` incorrect data (no algorithm ID referenced)
/// - `6A86h` incorrect P1/P2
#[derive(Debug, Clone, Copy)]
pub struct MseSet {
    /// CLA byte.
    pub class: ApduClass,
    /// Template selector (drives both P2 and the body shape).
    pub template: MseSetTemplate,
}

impl MseSet {
    /// INS byte per §3.6.2.
    pub const INS: u8 = 0x22;
    /// P1: SET (computation and deciphering) per §3.6.2.
    pub const P1_SET: u8 = 0x41;

    /// Serialise into the wire APDU per §3.6.2.
    ///
    /// 5-byte header (`CLA INS P1 P2 Lc`) followed by the CRDO
    /// concatenation. The data length is always 3 (Hashing,
    /// ELC) or 6 (DST, RSA decipherment) -- well below the
    /// `Lc > 30` rejection threshold.
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        let p2 = self.template.p2();
        // Each variant's Lc + body are computed together so the
        // length is a const u8 literal (3 or 6) rather than a
        // `body.len() as u8` cast at the wire-emit site.
        let (lc, body): (u8, Vec<u8>) = match self.template {
            MseSetTemplate::Hashing { alg_ref } => (
                3,
                vec![CRDO_TAG_ALG_REF, CRDO_VALUE_LEN_BYTE, alg_ref.as_byte()],
            ),
            MseSetTemplate::DigitalSignature { alg_ref, key_ref }
            | MseSetTemplate::Authentication { alg_ref, key_ref } => (
                6,
                vec![
                    CRDO_TAG_ALG_REF,
                    CRDO_VALUE_LEN_BYTE,
                    alg_ref.as_byte(),
                    CRDO_TAG_KEY_REF,
                    CRDO_VALUE_LEN_BYTE,
                    key_ref.as_u8(),
                ],
            ),
            MseSetTemplate::DeciphermentRsa { alg_ref, key_ref } => (
                6,
                vec![
                    CRDO_TAG_ALG_REF,
                    CRDO_VALUE_LEN_BYTE,
                    alg_ref.as_byte(),
                    CRDO_TAG_KEY_REF,
                    CRDO_VALUE_LEN_BYTE,
                    key_ref.as_u8(),
                ],
            ),
            MseSetTemplate::DeciphermentElc { key_ref } => (
                3,
                vec![CRDO_TAG_KEY_REF, CRDO_VALUE_LEN_BYTE, key_ref.as_u8()],
            ),
        };
        debug_assert_eq!(usize::from(lc), body.len(), "MSE:SET Lc/body mismatch");
        let mut out = Vec::with_capacity(body.len().saturating_add(5));
        out.push(self.class.as_byte());
        out.push(Self::INS);
        out.push(Self::P1_SET);
        out.push(p2);
        out.push(lc);
        out.extend_from_slice(&body);
        CommandApdu::new(out)
    }
}

/// TLV tag `90h` per FINEID S1 v4.2 §3.7 Tables 9 and the
/// §3.7.2.3 hash-value envelope -- carries the intermediate
/// hash || counter (partially-by-card mode) or the final hash
/// (external mode).
pub const PSO_HASH_TAG_HASH_VALUE: u8 = 0x90;

/// TLV tag `80h` per FINEID S1 v4.2 §3.7 Tables 9 -- carries
/// the final / only data block (entirely-by-card final mode or
/// the second TLV of partially-by-card mode).
pub const PSO_HASH_TAG_FINAL_BLOCK: u8 = 0x80;

/// Hash value provided by the host when the card does no
/// hashing itself (FINEID S1 v4.2 §3.7.2.3).
///
/// Each variant pins the wire length per §3.7.2.3 Algorithm-ID
/// table: SHA-1 = 20 B, SHA-224 = 28 B, SHA-256 = 32 B,
/// SHA-384 = 48 B, SHA-512 = 64 B. The current SE's algorithm
/// (set by [`MseSetTemplate::Hashing`] or
/// [`MseSetTemplate::DigitalSignature`]) selects which variant
/// the card expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExternalHashValue {
    /// SHA-1 hash (20 bytes). Algorithm ID `11h` or `12h`.
    Sha1([u8; 20]),
    /// SHA-224 hash (28 bytes). Algorithm ID `32h`.
    Sha224([u8; 28]),
    /// SHA-256 hash (32 bytes). Algorithm ID `41h` or `42h`.
    /// Refineid's signing chain uses this variant.
    Sha256([u8; 32]),
    /// SHA-384 hash (48 bytes). Algorithm ID `52h`.
    Sha384([u8; 48]),
    /// SHA-512 hash (64 bytes). Algorithm ID `62h`.
    Sha512([u8; 64]),
}

impl ExternalHashValue {
    /// Raw hash bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Sha1(b) => b,
            Self::Sha224(b) => b,
            Self::Sha256(b) => b,
            Self::Sha384(b) => b,
            Self::Sha512(b) => b,
        }
    }

    /// Length byte for the `90h L <hash>` TLV. Each variant's
    /// length fits in `u8` by construction (max 64).
    #[must_use]
    pub const fn len_byte(&self) -> u8 {
        // Pinned per §3.7.2.3 Algorithm-ID table; each variant
        // returns its const-known u8 length so no `as` cast is
        // needed at the wire-emit site.
        match self {
            Self::Sha1(_) => 20,
            Self::Sha224(_) => 28,
            Self::Sha256(_) => 32,
            Self::Sha384(_) => 48,
            Self::Sha512(_) => 64,
        }
    }

    /// The [`HashAlgorithm`] this digest represents, for composing
    /// the matching [`SignatureAlgRef`] via
    /// [`SignatureAlgRef::from_parts`]. Lets a sign chain derive
    /// the MSE:Set DST algorithm byte from the digest it is about
    /// to ship in the external-hash DO.
    #[must_use]
    pub const fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            Self::Sha1(_) => HashAlgorithm::Sha1,
            Self::Sha224(_) => HashAlgorithm::Sha224,
            Self::Sha256(_) => HashAlgorithm::Sha256,
            Self::Sha384(_) => HashAlgorithm::Sha384,
            Self::Sha512(_) => HashAlgorithm::Sha512,
        }
    }
}

/// Intermediate-hash state + bit-length counter shipped to the
/// card when the host has hashed all but the final block
/// (FINEID S1 v4.2 §3.7.2.2, Tables 9 + 10).
///
/// Each variant pins (intermediate length, counter length) per
/// the spec table; SHA-384 / SHA-512 allow either an 8-byte or
/// a 16-byte counter form (the leading 8 bytes of a 16-byte
/// counter must be zero per §3.7's "for the sake of
/// simplicity" note, but both encodings are spec-valid).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntermediateHashState {
    /// SHA-1: 20-byte intermediate || 8-byte counter (XX=1Ch=28).
    Sha1 {
        /// SHA-1 intermediate hash (20 bytes).
        intermediate: [u8; 20],
        /// 8-byte big-endian count of bits already hashed.
        counter: [u8; 8],
    },
    /// SHA-224: 32-byte intermediate || 8-byte counter (XX=28h=40).
    Sha224 {
        /// SHA-224 intermediate hash (32 bytes).
        intermediate: [u8; 32],
        /// 8-byte big-endian count of bits already hashed.
        counter: [u8; 8],
    },
    /// SHA-256: 32-byte intermediate || 8-byte counter (XX=28h=40).
    Sha256 {
        /// SHA-256 intermediate hash (32 bytes).
        intermediate: [u8; 32],
        /// 8-byte big-endian count of bits already hashed.
        counter: [u8; 8],
    },
    /// SHA-384, 8-byte counter form (XX=48h=72).
    Sha384Counter8 {
        /// SHA-384 intermediate hash (64 bytes).
        intermediate: [u8; 64],
        /// 8-byte big-endian count of bits already hashed.
        counter: [u8; 8],
    },
    /// SHA-384, 16-byte counter form (XX=50h=80).
    Sha384Counter16 {
        /// SHA-384 intermediate hash (64 bytes).
        intermediate: [u8; 64],
        /// 16-byte big-endian count of bits already hashed
        /// (leading 8 bytes must be zero per §3.7).
        counter: [u8; 16],
    },
    /// SHA-512, 8-byte counter form (XX=48h=72).
    Sha512Counter8 {
        /// SHA-512 intermediate hash (64 bytes).
        intermediate: [u8; 64],
        /// 8-byte big-endian count of bits already hashed.
        counter: [u8; 8],
    },
    /// SHA-512, 16-byte counter form (XX=50h=80).
    Sha512Counter16 {
        /// SHA-512 intermediate hash (64 bytes).
        intermediate: [u8; 64],
        /// 16-byte big-endian count of bits already hashed
        /// (leading 8 bytes must be zero per §3.7).
        counter: [u8; 16],
    },
}

impl IntermediateHashState {
    /// XX length byte for the `90h XX <intermediate||counter>`
    /// TLV per §3.7.2.2 Table 10.
    #[must_use]
    pub const fn xx_byte(&self) -> u8 {
        match self {
            Self::Sha1 { .. } => 0x1C,
            Self::Sha224 { .. } | Self::Sha256 { .. } => 0x28,
            Self::Sha384Counter8 { .. } | Self::Sha512Counter8 { .. } => 0x48,
            Self::Sha384Counter16 { .. } | Self::Sha512Counter16 { .. } => 0x50,
        }
    }

    /// Serialise this intermediate hash state plus its counter
    /// into `out`, in the on-wire order the card expects.
    ///
    /// FINEID S1 v4.2 §3.7.2.2 (intermediate-state mode). The
    /// per-variant payload layout differs by SHA family
    /// (intermediate-block widths and counter sizes), but
    /// always emits `intermediate || counter`; the leading
    /// algorithm-id byte is added by the caller.
    fn extend_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Sha1 {
                intermediate,
                counter,
            } => {
                out.extend_from_slice(intermediate);
                out.extend_from_slice(counter);
            }
            Self::Sha224 {
                intermediate,
                counter,
            }
            | Self::Sha256 {
                intermediate,
                counter,
            } => {
                out.extend_from_slice(intermediate);
                out.extend_from_slice(counter);
            }
            Self::Sha384Counter8 {
                intermediate,
                counter,
            }
            | Self::Sha512Counter8 {
                intermediate,
                counter,
            } => {
                out.extend_from_slice(intermediate);
                out.extend_from_slice(counter);
            }
            Self::Sha384Counter16 {
                intermediate,
                counter,
            }
            | Self::Sha512Counter16 {
                intermediate,
                counter,
            } => {
                out.extend_from_slice(intermediate);
                out.extend_from_slice(counter);
            }
        }
    }
}

/// Raw hash-input block carried in §3.7.2.1 (entirely-by-card)
/// modes.
///
/// FINEID S1 v4.2 §3.7.2.1 caps the block at the hash
/// algorithm's block length: 64 bytes for SHA-1 / SHA-224 /
/// SHA-256, 128 bytes for SHA-384 / SHA-512. Refineid validates
/// the upper bound (128) at construction; the card rejects any
/// over-the-algorithm-block-length case with a status word.
/// Short-form Lc additionally caps short-APDU bodies at 255 B.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HashBlock {
    /// Validated raw block bytes (length already checked
    /// against [`HASH_BLOCK_MAX_LEN`] by [`HashBlock::new`]).
    /// Carried verbatim into the PSO:HASH command body; no
    /// padding or framing applied here.
    bytes: Vec<u8>,
}

/// Errors returned by [`HashBlock::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashBlockError {
    /// Block exceeded the spec maximum of 128 bytes (the
    /// SHA-384 / SHA-512 block length).
    Overlength {
        /// Length of the rejected block.
        got: usize,
    },
}

/// Maximum hash-input block length across all supported SHA
/// algorithms (SHA-384 / SHA-512 block length per FINEID S1
/// v4.2 §3.7 Table 8).
pub const HASH_BLOCK_MAX_LEN: usize = 128;

/// Same bound as [`HASH_BLOCK_MAX_LEN`] but typed `u8`. Used as
/// the defensive fallback in [`HashBlock::len_byte`] -- the
/// constructor refuses any input above this bound, so the
/// fallback is unreachable for a [`HashBlock`] built via
/// [`HashBlock::new`].
const HASH_BLOCK_MAX_LEN_U8: u8 = 128;

impl HashBlock {
    /// Wrap a block of input bytes after a max-length check.
    ///
    /// # Errors
    /// [`HashBlockError::Overlength`] when `bytes.len() >
    /// HASH_BLOCK_MAX_LEN`.
    pub fn new<B: AsRef<[u8]>>(bytes: B) -> Result<Self, HashBlockError> {
        let slice = bytes.as_ref();
        if slice.len() > HASH_BLOCK_MAX_LEN {
            return Err(HashBlockError::Overlength { got: slice.len() });
        }
        Ok(Self {
            bytes: slice.to_vec(),
        })
    }

    /// Borrow the block bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Block byte length. Fits in `u8` by the
    /// [`HASH_BLOCK_MAX_LEN`] = 128 invariant enforced by
    /// [`HashBlock::new`].
    #[must_use]
    pub fn len_byte(&self) -> u8 {
        // `try_from` carries the bound at the type level; the
        // `unwrap_or` fallback is a defensive no-op (the
        // constructor refuses any length > 128 < u8::MAX).
        u8::try_from(self.bytes.len()).unwrap_or(HASH_BLOCK_MAX_LEN_U8)
    }
}

/// FINEID S1 v4.2 §3.7 PSO: HASH mode. Selects both the P2
/// byte and the body shape per §3.7.2.1 / §3.7.2.2 / §3.7.2.3.
///
/// Mode summary:
///
/// - [`PsoHashMode::EntirelyByCardBlock`] -- §3.7.2.1, P2=80h.
///   Body: raw block bytes (no TLV). Used iteratively until
///   the final block, which uses
///   [`PsoHashMode::EntirelyByCardFinal`].
/// - [`PsoHashMode::EntirelyByCardFinal`] -- §3.7.2.1, P2=A0h.
///   Body: `80h L <final block>`.
/// - [`PsoHashMode::PartiallyByCard`] -- §3.7.2.2, P2=A0h.
///   Body: `90h XX <intermediate || counter>` `80h L <final>`.
/// - [`PsoHashMode::External`] -- §3.7.2.3, P2=A0h. Body:
///   `90h L <hash>`. Refineid's signing chain uses this with
///   [`ExternalHashValue::Sha256`].
#[derive(Debug, Clone)]
pub enum PsoHashMode {
    /// Hashing entirely by card; non-final block (P2=80h).
    EntirelyByCardBlock {
        /// Block to hash; <= one algorithm block length.
        block: HashBlock,
    },
    /// Hashing entirely by card; final / only block (P2=A0h).
    EntirelyByCardFinal {
        /// Final or only data block; wrapped in TLV `80h L block`.
        final_block: HashBlock,
    },
    /// Hashing partially by card (P2=A0h): host supplies the
    /// intermediate state, card hashes the final block.
    PartiallyByCard {
        /// Intermediate hash + bit-counter from the host's
        /// partial computation.
        state: IntermediateHashState,
        /// Final block to be hashed by the card.
        final_block: HashBlock,
    },
    /// Hashing entirely externally (P2=A0h): host supplies the
    /// full hash value, card sets it as the hash to be signed.
    External {
        /// The hash value; length matches the algorithm pinned
        /// by the prior MSE: SET.
        hash: ExternalHashValue,
    },
}

impl PsoHashMode {
    /// P2 byte per §3.7.2.1: 80h for non-final
    /// entirely-by-card; A0h for every other variant.
    #[must_use]
    pub const fn p2(&self) -> u8 {
        match self {
            Self::EntirelyByCardBlock { .. } => 0x80,
            Self::EntirelyByCardFinal { .. }
            | Self::PartiallyByCard { .. }
            | Self::External { .. } => 0xA0,
        }
    }
}

/// FINEID S1 v4.2 §3.7 PERFORM SECURITY OPERATION: HASH.
///
/// Provides the hashed message to be used as input for the
/// next PSO: COMPUTE DIGITAL SIGNATURE command. Per §3.7 the
/// hash can be performed entirely by the card, entirely by the
/// host, or partially by each -- see [`PsoHashMode`] for the
/// three variants.
///
/// Wire shape per §3.7.2:
/// `CLA 2A 90 <P2> Lc <Data>`. No Le.
///
/// - `CLA`: [`ApduClass`] -- plain (`00h`) or secure messaging
///   (`0Ch`).
/// - `INS`: fixed at `2Ah`.
/// - `P1`: fixed at `90h` (HASH).
/// - `P2`: from [`PsoHashMode::p2`]: `80h` for non-final
///   blocks, `A0h` for final / partial / external.
/// - `Lc` + `Data`: derived from [`PsoHashMode`].
/// - `Le`: empty (refineid never sets the optional "return the
///   hash in the response" length for the entirely-by-card
///   final variant; downstream callers consume the hash via
///   the subsequent PSO: CDS instead).
#[derive(Debug, Clone)]
pub struct PsoHash {
    /// CLA byte.
    pub class: ApduClass,
    /// Mode selector (drives P2 + body).
    pub mode: PsoHashMode,
}

impl PsoHash {
    /// INS byte per §3.7.2.
    pub const INS: u8 = 0x2A;
    /// P1: HASH per §3.7.2.
    pub const P1: u8 = 0x90;

    /// Serialise into the wire APDU per §3.7.2.
    ///
    /// # Panics
    /// If the assembled body exceeds 255 bytes (short-form Lc
    /// limit). For SHA-256 external (`PsoHashMode::External`)
    /// the body is `90h 20h <32 bytes>` = 34 bytes; partial /
    /// entirely-by-card final modes stay within the limit
    /// because the spec caps both the intermediate-state TLV
    /// (max 82 bytes) and the final block (max 130 bytes
    /// including the `80h L` header).
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        let p2 = self.mode.p2();
        let body = match self.mode {
            PsoHashMode::EntirelyByCardBlock { block } => block.as_bytes().to_vec(),
            PsoHashMode::EntirelyByCardFinal { final_block } => {
                let mut out = Vec::with_capacity(final_block.as_bytes().len().saturating_add(2));
                out.push(PSO_HASH_TAG_FINAL_BLOCK);
                out.push(final_block.len_byte());
                out.extend_from_slice(final_block.as_bytes());
                out
            }
            PsoHashMode::PartiallyByCard { state, final_block } => {
                let xx = state.xx_byte();
                let mut out = Vec::with_capacity(
                    usize::from(xx)
                        .saturating_add(final_block.as_bytes().len())
                        .saturating_add(4),
                );
                out.push(PSO_HASH_TAG_HASH_VALUE);
                out.push(xx);
                state.extend_into(&mut out);
                out.push(PSO_HASH_TAG_FINAL_BLOCK);
                out.push(final_block.len_byte());
                out.extend_from_slice(final_block.as_bytes());
                out
            }
            PsoHashMode::External { hash } => {
                let mut out = Vec::with_capacity(hash.as_bytes().len().saturating_add(2));
                out.push(PSO_HASH_TAG_HASH_VALUE);
                out.push(hash.len_byte());
                out.extend_from_slice(hash.as_bytes());
                out
            }
        };
        // `u8::try_from` is the typed range check; the Err arm
        // is the same precondition the previous `assert! + as u8`
        // pair encoded, but typed at the conversion site so no
        // `as` cast / clippy allow is needed.
        let Ok(lc) = u8::try_from(body.len()) else {
            unreachable!("PSO:HASH body exceeds short-form Lc (255 bytes)")
        };
        let mut out = Vec::with_capacity(body.len().saturating_add(5));
        out.push(self.class.as_byte());
        out.push(Self::INS);
        out.push(Self::P1);
        out.push(p2);
        out.push(lc);
        out.extend_from_slice(&body);
        CommandApdu::new(out)
    }
}

/// `PSO:DECIPHER` carrying a body of `81 || <ciphertext>` (the
/// `0x81` padding-content indicator distinguishes the
/// confidentiality template format).
///
/// `chain == true` sets the command-chaining bit (`CLA=0x10`)
/// and omits `Le`; the final / non-chained round uses
/// `CLA=0x00` and sets `Le=0`.
#[derive(Debug, Clone)]
pub struct PsoDecipher {
    /// One half (or whole) of the ciphertext body to be
    /// decrypted. Tier 0 `Vec<u8>` -- the typed projection is
    /// `Ciphertext<RsaPkcs1>` upstream; this struct serialises
    /// the bytes onto the wire and must accept arbitrary
    /// per-round splits.
    pub body: Vec<u8>,
    /// When `true`, this APDU is part of a command-chain
    /// sequence (CLA `0x10`); when `false`, it's the final / sole
    /// round (CLA `0x00`).
    pub chain: bool,
}

impl PsoDecipher {
    /// ISO 7816-8 `PERFORM SECURITY OPERATION` instruction.
    pub const INS: u8 = 0x2A;
    /// P1: DECIPHER (`0x80`).
    pub const P1: u8 = 0x80;
    /// P2: padding-content indicator `0x86` (RSA-PKCS#1 v1.5).
    pub const P2: u8 = 0x86;

    /// Serialise into the wire APDU.
    ///
    /// # Panics
    /// If `body.len() > 255`. RSA-3072 deciphered bodies are
    /// 385 bytes total; the caller splits at the halfway point
    /// for chained transmission. Each half fits in short-form
    /// Lc.
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        // Typed range check via `u8::try_from`; the Err arm is
        // the same precondition the previous `assert! + as u8`
        // pair encoded.
        let Ok(lc) = u8::try_from(self.body.len()) else {
            unreachable!("PSO:DECIPHER body too large (>255 bytes)")
        };
        let cla = if self.chain { 0x10 } else { 0x00 };
        let mut out = Vec::with_capacity(self.body.len().saturating_add(6));
        out.extend_from_slice(&[cla, Self::INS, Self::P1, Self::P2]);
        out.push(lc);
        out.extend_from_slice(&self.body);
        if !self.chain {
            out.push(0x00); // Le = 0 -> up to 256 bytes.
        }
        CommandApdu::new(out)
    }
}

/// FINEID S1 v4.2 §3.8 PERFORM SECURITY OPERATION: COMPUTE
/// DIGITAL SIGNATURE.
///
/// Computes a digital signature over the hash previously
/// loaded via [`PsoHash`]. The current SE's DST must reference
/// a signature-capable private key (set by
/// [`MseSetTemplate::DigitalSignature`]).
///
/// Wire shape per §3.8.2:
/// `CLA 2A 9E 9A 00`. No Lc, no body, Le=00h.
///
/// Field semantics:
///
/// - `CLA`: [`ApduClass`] -- plain (`00h`) or secure messaging
///   (`0Ch`).
/// - `INS`: fixed at `2Ah` (PERFORM SECURITY OPERATION).
/// - `P1`: fixed at `9Eh` (digital signature data object
///   returned in response).
/// - `P2`: fixed at `9Ah` (data field contains data to be
///   signed -- the hash loaded by the prior PSO: HASH).
/// - `Lc`: empty.
/// - `Data`: empty.
/// - `Le`: `00h`. Per §3.8.2 note: "If the response is greater
///   than 256 bytes... the card opens a retrieval sequence."
///   RSA-3072 signatures are 384 bytes, so the transport's
///   GET RESPONSE chain (§3.3) pulls the remainder; refineid
///   always issues the short-form Le=00 here.
///
/// §3.8.3 response: `digital signature || SW1 SW2`. RSA
/// signatures are unformatted; ECDSA signatures are `r || s`
/// where r and s are the elliptic-curve point coordinates.
///
/// §3.8.3 status-word semantics:
/// - `9000h` success
/// - `6982h` security conditions not satisfied (PIN unverified,
///   SM error, DTBS integrity failed)
/// - `6985h` conditions of use not satisfied (no hash from prior
///   PSO: HASH, no DST in SE, algorithm not recognised, etc.)
/// - `6986h` SHA-1 disabled by cryptographic-environment policy
/// - `6A84h` signature counter exceeds maximum
/// - `6A86h` incorrect P1/P2 (must be 9E 9A)
#[derive(Debug, Clone, Copy)]
pub struct PsoComputeDigitalSignature {
    /// CLA byte.
    pub class: ApduClass,
}

impl PsoComputeDigitalSignature {
    /// INS byte per §3.8.2 (PERFORM SECURITY OPERATION).
    pub const INS: u8 = 0x2A;
    /// P1 per §3.8.2: digital signature data object returned.
    pub const P1: u8 = 0x9E;
    /// P2 per §3.8.2: data field contains data to be signed.
    pub const P2: u8 = 0x9A;
    /// Le per §3.8.2: `00h` requests up to 256 bytes; if the
    /// signature is longer the card opens a GET RESPONSE
    /// retrieval sequence (§3.3 / Annex B).
    pub const LE_MAX_SHORT: u8 = 0x00;

    /// Exact `Le` for an ECDSA P-384 raw `r || s` signature (96
    /// bytes). The G4E card answers PSO:CDS `Le=00h` with `6C60`
    /// on some sessions, and the ISO 7816-4 re-issue is not
    /// reachable from every transport (the CTK callback
    /// transport's retry-permission flag does not survive the
    /// APDU's trip across the FFI byte boundary), so the ECDSA
    /// sign chains send the exact length up front.
    pub const LE_ECDSA_P384: u8 = 96;

    /// Exact `Le` for an ECDSA P-256 raw `r || s` signature (64
    /// bytes), same rationale as [`Self::LE_ECDSA_P384`].
    pub const LE_ECDSA_P256: u8 = 64;

    /// Serialise into the wire APDU per §3.8.2
    /// (`<CLA> 2A 9E 9A 00`; 5 bytes total).
    ///
    /// Short case-2, so the T=0 `6Cxx` wrong-`Le` correction is
    /// permitted: the G4E card answers `6C60` to `Le=00h`, and the
    /// ISO 7816-4 re-issue with `Le=60h` is how the 96-byte P-384
    /// signature is retrieved. The re-issue is safe -- the rejected
    /// first attempt never executed the PSO.
    #[must_use]
    pub fn into_apdu(self) -> CommandApdu {
        self.into_apdu_with_le(Self::LE_MAX_SHORT)
    }

    /// Serialise with an explicit `Le` -- see [`Self::LE_ECDSA_P384`]
    /// for why the ECDSA chains pass the exact signature length.
    #[must_use]
    pub fn into_apdu_with_le(self, le: u8) -> CommandApdu {
        CommandApdu::new(vec![
            self.class.as_byte(),
            Self::INS,
            Self::P1,
            Self::P2,
            le,
        ])
        .allow_wrong_le_retry()
    }

    /// Serialise with the off-card hash in the data field.
    ///
    /// The Idemia organizational cards take the externally computed
    /// hash directly in PSO:CDS (organizational cards specification
    /// §6.6.2.3: Lc = hash length, Data = computed hash) -- their
    /// PSO:HASH exists only for card-side hashing, so the FINEID v4
    /// external-hash DO answers `6A80` there. Wire:
    /// `<CLA> 2A 9E 9A <Lc> <hash> <Le>`.
    #[must_use]
    pub fn into_apdu_with_hash(self, hash: &[u8], le: u8) -> CommandApdu {
        let Ok(lc) = u8::try_from(hash.len()) else {
            unreachable!("PSO:CDS hash exceeds short-form Lc")
        };
        let mut out = Vec::with_capacity(hash.len().saturating_add(6));
        out.push(self.class.as_byte());
        out.push(Self::INS);
        out.push(Self::P1);
        out.push(Self::P2);
        out.push(lc);
        out.extend_from_slice(hash);
        out.push(le);
        CommandApdu::new(out).allow_wrong_le_retry()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn signature_alg_ref_sha256_rsa_pkcs1_is_42h() {
        // Per Table 6: hash high nibble 4 (SHA-256) | sig low
        // nibble 2 (PKCS#1 v1.5) = 42h.
        let expected = (HashAlgorithm::Sha256.high_nibble() << 4)
            | SignatureAlgorithm::RsaPkcs1V1_5.low_nibble();
        assert_eq!(SignatureAlgRef::SHA256_RSA_PKCS1_V1_5.as_byte(), expected);
    }

    #[test]
    fn mse_set_dst_serialises_per_table_5_dst_row() {
        // Table 5 DST row: P1=41, P2=B6, data = 80 01 xx 84 01 xx.
        let apdu = MseSet {
            class: ApduClass::Plain,
            template: MseSetTemplate::DigitalSignature {
                alg_ref: SignatureAlgRef::SHA256_RSA_PKCS1_V1_5,
                key_ref: KeyRef::Auth,
            },
        }
        .into_apdu();
        let expected: Vec<u8> = vec![
            ApduClass::Plain.as_byte(),
            MseSet::INS,
            MseSet::P1_SET,
            MseSetTemplate::DigitalSignature {
                alg_ref: SignatureAlgRef::SHA256_RSA_PKCS1_V1_5,
                key_ref: KeyRef::Auth,
            }
            .p2(),
            6,
            CRDO_TAG_ALG_REF,
            CRDO_VALUE_LEN_BYTE,
            SignatureAlgRef::SHA256_RSA_PKCS1_V1_5.as_byte(),
            CRDO_TAG_KEY_REF,
            CRDO_VALUE_LEN_BYTE,
            KeyRef::Auth.as_u8(),
        ];
        assert_eq!(apdu.as_bytes(), expected.as_slice());
    }

    #[test]
    fn mse_set_ct_rsa_serialises_per_table_5_b8_rsa_row() {
        // Table 5 CT (RSA) row: P1=41, P2=B8, data = 80 01 xx 84 01 xx.
        let apdu = MseSet {
            class: ApduClass::Plain,
            template: MseSetTemplate::DeciphermentRsa {
                alg_ref: DecipherAlgRef::RsassaPkcs1V1_5,
                key_ref: KeyRef::Auth,
            },
        }
        .into_apdu();
        let expected: Vec<u8> = vec![
            ApduClass::Plain.as_byte(),
            MseSet::INS,
            MseSet::P1_SET,
            MseSetTemplate::DeciphermentRsa {
                alg_ref: DecipherAlgRef::RsassaPkcs1V1_5,
                key_ref: KeyRef::Auth,
            }
            .p2(),
            6,
            CRDO_TAG_ALG_REF,
            CRDO_VALUE_LEN_BYTE,
            DecipherAlgRef::RsassaPkcs1V1_5.as_byte(),
            CRDO_TAG_KEY_REF,
            CRDO_VALUE_LEN_BYTE,
            KeyRef::Auth.as_u8(),
        ];
        assert_eq!(apdu.as_bytes(), expected.as_slice());
    }

    #[test]
    fn mse_set_ct_elc_omits_alg_ref_crdo_per_table_5_b8_elc_row() {
        // Table 5 CT (ELC) row: data = 84 01 xx ONLY -- no alg_ref CRDO.
        let apdu = MseSet {
            class: ApduClass::Plain,
            template: MseSetTemplate::DeciphermentElc {
                key_ref: KeyRef::Auth,
            },
        }
        .into_apdu();
        let expected: Vec<u8> = vec![
            ApduClass::Plain.as_byte(),
            MseSet::INS,
            MseSet::P1_SET,
            MseSetTemplate::DeciphermentElc {
                key_ref: KeyRef::Auth,
            }
            .p2(),
            3,
            CRDO_TAG_KEY_REF,
            CRDO_VALUE_LEN_BYTE,
            KeyRef::Auth.as_u8(),
        ];
        assert_eq!(apdu.as_bytes(), expected.as_slice());
    }

    #[test]
    fn mse_set_hashing_template_uses_aa_p2_and_alg_crdo_only() {
        // Table 5 HT row: P2=AA, data = 80 01 xx.
        let apdu = MseSet {
            class: ApduClass::Plain,
            template: MseSetTemplate::Hashing {
                alg_ref: SignatureAlgRef::SHA256_RSA_PKCS1_V1_5,
            },
        }
        .into_apdu();
        let expected: Vec<u8> = vec![
            ApduClass::Plain.as_byte(),
            MseSet::INS,
            MseSet::P1_SET,
            MseSetTemplate::Hashing {
                alg_ref: SignatureAlgRef::SHA256_RSA_PKCS1_V1_5,
            }
            .p2(),
            3,
            CRDO_TAG_ALG_REF,
            CRDO_VALUE_LEN_BYTE,
            SignatureAlgRef::SHA256_RSA_PKCS1_V1_5.as_byte(),
        ];
        assert_eq!(apdu.as_bytes(), expected.as_slice());
    }

    #[test]
    fn mse_set_chained_first_class_carries_10h() {
        let apdu = MseSet {
            class: ApduClass::ChainedFirst,
            template: MseSetTemplate::DigitalSignature {
                alg_ref: SignatureAlgRef::SHA256_RSA_PKCS1_V1_5,
                key_ref: KeyRef::Sign,
            },
        }
        .into_apdu();
        assert_eq!(apdu.as_bytes()[0], ApduClass::ChainedFirst.as_byte());
    }

    #[test]
    fn pso_hash_external_sha256_serialises_per_spec_3_7_2_3() {
        // §3.7.2.3 external hash: P1=90h HASH, P2=A0h,
        // body=`90h L <hash>`. SHA-256 L=32.
        const SHA256_FIXTURE_FILL: u8 = 0xAB;
        let hash_fixture = [SHA256_FIXTURE_FILL; 32];
        let apdu = PsoHash {
            class: ApduClass::Plain,
            mode: PsoHashMode::External {
                hash: ExternalHashValue::Sha256(hash_fixture),
            },
        }
        .into_apdu();
        let body_len_bytes: u8 =
            2 + u8::try_from(hash_fixture.len()).expect("32-byte SHA-256 hash fits in u8");
        let mut expected: Vec<u8> = vec![
            ApduClass::Plain.as_byte(),
            PsoHash::INS,
            PsoHash::P1,
            PsoHashMode::External {
                hash: ExternalHashValue::Sha256(hash_fixture),
            }
            .p2(),
            body_len_bytes,
            PSO_HASH_TAG_HASH_VALUE,
            ExternalHashValue::Sha256(hash_fixture).len_byte(),
        ];
        expected.extend_from_slice(&hash_fixture);
        assert_eq!(apdu.as_bytes(), expected.as_slice());
    }

    #[test]
    fn pso_hash_entirely_by_card_non_final_uses_p2_80_and_raw_block() {
        // §3.7.2.1 non-final: P2=80h, body = raw block, no TLV.
        const BLOCK_FILL: u8 = 0xCD;
        let block_bytes = vec![BLOCK_FILL; 64];
        let block = HashBlock::new(block_bytes.clone()).expect("64-byte block is within the cap");
        let apdu = PsoHash {
            class: ApduClass::Plain,
            mode: PsoHashMode::EntirelyByCardBlock { block },
        }
        .into_apdu();
        let expected: Vec<u8> = {
            let mut v = vec![
                ApduClass::Plain.as_byte(),
                PsoHash::INS,
                PsoHash::P1,
                PsoHashMode::EntirelyByCardBlock {
                    block: HashBlock::new(block_bytes.clone())
                        .expect("64-byte block is within the cap"),
                }
                .p2(),
                u8::try_from(block_bytes.len()).expect("64-byte block length fits in u8"),
            ];
            v.extend_from_slice(&block_bytes);
            v
        };
        assert_eq!(apdu.as_bytes(), expected.as_slice());
    }

    #[test]
    fn pso_hash_entirely_by_card_final_wraps_block_in_80_l_tlv() {
        // §3.7.2.1 final/only: P2=A0h, body=`80h L <block>`.
        const BLOCK_FILL: u8 = 0xEF;
        let block_bytes = vec![BLOCK_FILL; 7];
        let final_block =
            HashBlock::new(block_bytes.clone()).expect("7-byte block is within the cap");
        let apdu = PsoHash {
            class: ApduClass::Plain,
            mode: PsoHashMode::EntirelyByCardFinal { final_block },
        }
        .into_apdu();
        let body_len_bytes = 2 + block_bytes.len();
        let mut expected = vec![
            ApduClass::Plain.as_byte(),
            PsoHash::INS,
            PsoHash::P1,
            PsoHashMode::EntirelyByCardFinal {
                final_block: HashBlock::new(block_bytes.clone())
                    .expect("7-byte block is within the cap"),
            }
            .p2(),
            u8::try_from(body_len_bytes).expect("9-byte TLV body fits in u8"),
            PSO_HASH_TAG_FINAL_BLOCK,
            u8::try_from(block_bytes.len()).expect("7-byte block length fits in u8"),
        ];
        expected.extend_from_slice(&block_bytes);
        assert_eq!(apdu.as_bytes(), expected.as_slice());
    }

    #[test]
    fn pso_hash_partially_by_card_carries_two_concatenated_tlvs() {
        // §3.7.2.2 partial: P2=A0h, body=`90 XX <intermediate||counter> 80 L <final>`.
        // SHA-256: XX=28h (= 32+8 bytes).
        const INTERMEDIATE_FILL: u8 = 0x11;
        const COUNTER_FILL: u8 = 0x22;
        const FINAL_FILL: u8 = 0x33;
        let intermediate_fixture = [INTERMEDIATE_FILL; 32];
        let counter_fixture = [COUNTER_FILL; 8];
        let final_bytes = vec![FINAL_FILL; 5];

        let state = IntermediateHashState::Sha256 {
            intermediate: intermediate_fixture,
            counter: counter_fixture,
        };
        let final_block =
            HashBlock::new(final_bytes.clone()).expect("5-byte block is within the cap");
        let apdu = PsoHash {
            class: ApduClass::Plain,
            mode: PsoHashMode::PartiallyByCard { state, final_block },
        }
        .into_apdu();

        let xx = state.xx_byte();
        let body_len_bytes = 2 + usize::from(xx) + 2 + final_bytes.len();
        let mut expected = vec![
            ApduClass::Plain.as_byte(),
            PsoHash::INS,
            PsoHash::P1,
            PsoHashMode::PartiallyByCard {
                state,
                final_block: HashBlock::new(final_bytes.clone())
                    .expect("5-byte block is within the cap"),
            }
            .p2(),
            u8::try_from(body_len_bytes).expect("49-byte TLV body fits in u8"),
            PSO_HASH_TAG_HASH_VALUE,
            xx,
        ];
        expected.extend_from_slice(&intermediate_fixture);
        expected.extend_from_slice(&counter_fixture);
        expected.push(PSO_HASH_TAG_FINAL_BLOCK);
        expected.push(u8::try_from(final_bytes.len()).expect("5-byte block length fits in u8"));
        expected.extend_from_slice(&final_bytes);
        assert_eq!(apdu.as_bytes(), expected.as_slice());
    }

    #[test]
    fn external_hash_value_length_bytes_match_spec_3_7_2_3_table() {
        // Per §3.7.2.3 Algorithm-ID table.
        assert_eq!(ExternalHashValue::Sha1([0; 20]).len_byte(), 20);
        assert_eq!(ExternalHashValue::Sha224([0; 28]).len_byte(), 28);
        assert_eq!(ExternalHashValue::Sha256([0; 32]).len_byte(), 32);
        assert_eq!(ExternalHashValue::Sha384([0; 48]).len_byte(), 48);
        assert_eq!(ExternalHashValue::Sha512([0; 64]).len_byte(), 64);
    }

    #[test]
    fn intermediate_hash_state_xx_bytes_match_spec_table_10() {
        // Per §3.7.2.2 Table 10.
        assert_eq!(
            IntermediateHashState::Sha1 {
                intermediate: [0; 20],
                counter: [0; 8],
            }
            .xx_byte(),
            0x1C
        );
        assert_eq!(
            IntermediateHashState::Sha256 {
                intermediate: [0; 32],
                counter: [0; 8],
            }
            .xx_byte(),
            0x28
        );
        assert_eq!(
            IntermediateHashState::Sha384Counter8 {
                intermediate: [0; 64],
                counter: [0; 8],
            }
            .xx_byte(),
            0x48
        );
        assert_eq!(
            IntermediateHashState::Sha512Counter16 {
                intermediate: [0; 64],
                counter: [0; 16],
            }
            .xx_byte(),
            0x50
        );
    }

    #[test]
    fn hash_block_rejects_over_128_bytes() {
        let too_long = vec![0_u8; HASH_BLOCK_MAX_LEN + 1];
        let err = HashBlock::new(too_long).expect_err("129-byte block exceeds the cap");
        assert_eq!(
            err,
            HashBlockError::Overlength {
                got: HASH_BLOCK_MAX_LEN + 1
            }
        );
    }

    #[test]
    fn pso_cds_serialises_per_spec_3_8_2() {
        // §3.8.2 plain form: <CLA=00> 2A 9E 9A 00.
        let apdu = PsoComputeDigitalSignature {
            class: ApduClass::Plain,
        }
        .into_apdu();
        let expected: Vec<u8> = vec![
            ApduClass::Plain.as_byte(),
            PsoComputeDigitalSignature::INS,
            PsoComputeDigitalSignature::P1,
            PsoComputeDigitalSignature::P2,
            PsoComputeDigitalSignature::LE_MAX_SHORT,
        ];
        assert_eq!(apdu.as_bytes(), expected.as_slice());
    }

    #[test]
    fn pso_cds_secure_messaging_class_carries_0c() {
        let apdu = PsoComputeDigitalSignature {
            class: ApduClass::SecureMessaging,
        }
        .into_apdu();
        assert_eq!(apdu.as_bytes()[0], ApduClass::SecureMessaging.as_byte());
    }
}
