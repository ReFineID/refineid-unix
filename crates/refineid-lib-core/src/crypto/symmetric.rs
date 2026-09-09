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

//! Symmetric primitives PACE + secure messaging need on top of the
//! `aes`, `cbc`, `cmac` crates.
//!
//! ICAO Doc 9303 Part 11 sec.9.7.1 spells out the KDF the FINEID PACE
//! handshake derives session keys with:
//!
//! ```text
//! KDF(K, c) = H( K || c )    truncated/encoded for the AES-CBC IV
//!                            and AES-CMAC keys
//! ```
//!
//! For AES-256 (the variant FINEID's S4-2 spec selects via the
//! `id-PACE-ECDH-GM-AES-CBC-CMAC-256` OID) the `H` is SHA-256 and
//! the counter `c` distinguishes:
//!
//! - `c = 1` -> encryption key (`K_enc`, 256 bits)
//! - `c = 2` -> MAC key (`K_mac`, 256 bits)
//! - `c = 3` -> password-derived key (used only during the initial
//!   encrypted-nonce step)
//!
//! Live consumers come online with [`crate::pace`] /
//! `crate::secure_messaging`.

use aes::cipher::block_padding::NoPadding;
use aes::cipher::{
    BlockCipherEncrypt as _, BlockModeDecrypt as _, BlockModeEncrypt as _, KeyInit, KeyIvInit as _,
};
use cmac::{Cmac, Mac as _};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::container::{AesCbc, Ciphertext, CmacAesTruncated, Mac};

/// AES-256 block size, in bytes. Same value as `cbc::BlockSize` for
/// AES-256 -- kept locally so callers do not have to chase the
/// constant through the `aes` crate's generics.
pub const AES_BLOCK: usize = 16;

/// AES-256 key length.
pub const AES_KEY_LEN: usize = 32;

/// AES-CMAC tag length used during PACE authentication.
pub const CMAC_TAG_FULL: usize = 16;

/// Secure messaging truncates the CMAC tag to 8 bytes for the DO 8E
/// field (BSI TR-03110-3).
pub const CMAC_TAG_TRUNCATED: usize = 8;

/// PACE / secure-messaging KDF counter byte.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum KdfParam {
    /// Derive the encryption key `K_enc` (counter byte `1`).
    Encryption = 1,
    /// Derive the MAC key `K_mac` (counter byte `2`).
    Mac = 2,
    /// Derive the PACE password key (counter byte `3`).
    Password = 3,
}

impl From<KdfParam> for u8 {
    #[inline]
    fn from(p: KdfParam) -> Self {
        match p {
            KdfParam::Encryption => 1,
            KdfParam::Mac => 2,
            KdfParam::Password => 3,
        }
    }
}

/// 32 bytes of AES-256 key material -- an ICAO 9303 `K_enc` /
/// `K_mac` / `K_pi`, or any AES-256 key.
///
/// Secret keying material with hygiene the type *enforces*, not
/// merely documents: zeroized on drop and `Debug`-redacted, so the
/// key bytes never linger after the value drops nor leak through a
/// `{:?}` / `dbg!()`. (The secure-messaging layer's "zeroization
/// discipline" comments predate this type and described a property
/// a bare `[u8; 32]` never had.) Distinct from any other
/// `[u8; AES_KEY_LEN]` (a digest, an SSC block, an IV), so a key
/// can't be swapped for a non-key by accident. The raw bytes are
/// reachable only through `Aes256Key::as_bytes` -- the single,
/// deliberate hand-off point to the byte-level AES primitives.
// `pub` (not `pub(crate)`) only so it can appear in the public
// `PaceSession` fields / `SmTransport::rekey` signature without a
// private-in-public error. Encapsulation is the *private field* +
// `pub(crate)` accessors: an external crate can hold and move a key
// but cannot read or forge its bytes.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Aes256Key([u8; AES_KEY_LEN]);

impl Aes256Key {
    /// Borrow the raw key bytes for an AES primitive. The only
    /// place the bytes are exposed; kept crate-private.
    #[must_use]
    #[inline]
    pub(crate) const fn as_bytes(&self) -> &[u8; AES_KEY_LEN] {
        &self.0
    }

    /// Wrap raw key bytes that did **not** come from the KDF (an
    /// entered or loaded key). `None` for the two lost-data
    /// sentinels: **all-zero** and **all-ones**.
    ///
    /// Neither is ever a real key -- both are the signatures of
    /// *uninitialised / never-entered* material: all-zero is
    /// zeroed/`memset(0)` memory, all-ones (`u8::MAX` in every
    /// byte) is the `-1` / `0xFFFF...` "error" / erased-flash fill.
    /// Using either would make encryption catastrophically
    /// predictable. This is the one value rule on key bytes,
    /// mirroring `Can` rejecting `000000`. The *derived* path
    /// ([`kdf_aes256`]) is exempt: a SHA-256 output is neither
    /// sentinel, so a key that was actually derived is real by
    /// construction -- the only way to get a sentinel key is to
    /// not initialise / enter it, which is what this rejects.
    ///
    /// Test-only today; a future entered / loaded-key path reuses
    /// this same checked entry point.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn from_bytes(bytes: [u8; AES_KEY_LEN]) -> Option<Self> {
        let all_zero = bytes.iter().all(|&b| b == 0);
        let all_ones = bytes.iter().all(|&b| b == u8::MAX);
        if all_zero || all_ones {
            None
        } else {
            Some(Self(bytes))
        }
    }
}

impl core::fmt::Debug for Aes256Key {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never render key bytes -- redacted by construction.
        f.write_str("Aes256Key(<redacted>)")
    }
}

/// ICAO Doc 9303 Part 11 sec.9.7.1.2 KDF for AES-256:
///
/// ```text
/// kdf(K, c) = SHA-256( K || (uint32-be) c )
/// ```
///
/// Returns 32 bytes of derived key material -- the right length for
/// AES-256-CBC and AES-256-CMAC.
#[must_use]
pub(crate) fn kdf_aes256(k: &[u8], c: KdfParam) -> Aes256Key {
    let mut h = Sha256::new();
    h.update(k);
    // ICAO 9303 Part 11 §9.7.1 KDF counter byte: 1/2/3 for
    // K_enc/K_mac/K_password. From<KdfParam> for u8 keeps the
    // discriminant extraction explicit (no `as` cast).
    let counter: u32 = u32::from(u8::from(c));
    h.update(counter.to_be_bytes());
    let mut out = h.finalize();
    let mut buf = [0_u8; AES_KEY_LEN];
    buf.copy_from_slice(&out);
    // The digest IS the derived key; wipe the hasher's output
    // residue so a second copy of the key does not linger on the
    // stack after `buf` moves into the zeroize-on-drop `Aes256Key`.
    out.as_mut_slice().zeroize();
    Aes256Key(buf)
}

/// AES-CBC input was not aligned to the block size.
///
/// Returned by `aes256_cbc_encrypt_no_padding` and
/// `aes256_cbc_decrypt_no_padding` (both `pub(crate)`, hence code
/// spans not doc links) when the caller hands a buffer whose
/// length is not a multiple of [`AES_BLOCK`].
/// Callers that pre-pad (via ISO 7816-4 padding or a block-size
/// check) will never see this error; it exists so the library
/// can surface a misuse as a recoverable `Result` instead of a
/// process-abort `panic!`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnalignedInput {
    /// The buffer length that was not block-aligned.
    pub len: usize,
}

impl core::fmt::Display for UnalignedInput {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "AES-CBC no-padding: input length {} is not a multiple of {AES_BLOCK}",
            self.len
        )
    }
}

impl core::error::Error for UnalignedInput {}

/// AES-256-CBC encrypt with no padding.
///
/// The caller pads ISO/IEC 7816-4 mode 2 if needed. IV is passed
/// explicitly so the secure-messaging IV derivation
/// (`IV = AES-ECB(K_enc, SSC)`) lives in the state machine, not here.
///
/// Returns a [`Ciphertext<AesCbc>`] -- the type binds the bytes
/// to the cipher that produced them, so downstream code cannot
/// silently feed CBC ciphertext into an ECB / GCM decryptor.
///
/// # Errors
/// [`UnalignedInput`] if `plaintext.len()` is not a multiple of
/// [`AES_BLOCK`].
pub(crate) fn aes256_cbc_encrypt_no_padding(
    key: &[u8; 32],
    iv: &[u8; 16],
    plaintext: &[u8],
) -> Result<Ciphertext<AesCbc>, UnalignedInput> {
    type Enc = cbc::Encryptor<aes::Aes256>;
    if !plaintext.len().is_multiple_of(AES_BLOCK) {
        return Err(UnalignedInput {
            len: plaintext.len(),
        });
    }
    // Infallible array-typed constructor: `KeyIvInit::new` accepts
    // `&Key<Self>` / `&Iv<Self>` which `From<&[u8; N]>` for our
    // fixed-size arrays produces with no length check at runtime.
    let cipher = Enc::new(key.into(), iv.into());
    let mut buf = plaintext.to_vec();
    // `encrypt_padded` returns `Result<&[u8], PadError>` viewing the
    // already-mutated `buf`. With NoPadding and a whole-block input
    // the only failure mode is `msg_len != buf.len()`, which the
    // check above rules out. The view itself is discarded because
    // `buf` already holds the ciphertext in place.
    let _view_ok = cipher.encrypt_padded::<NoPadding>(&mut buf, plaintext.len());
    Ok(Ciphertext::new(buf))
}

/// AES-256-CBC decrypt with no padding.
///
/// Takes a typed [`Ciphertext<AesCbc>`] so the compiler refuses
/// to decrypt an ECB-produced ciphertext as CBC. Returns
/// plaintext as `Vec<u8>` -- plaintext is the recovered secret
/// and doesn't have an algorithm-distinguishing role.
///
/// # Errors
/// [`UnalignedInput`] if the ciphertext length is not a multiple
/// of [`AES_BLOCK`].
pub(crate) fn aes256_cbc_decrypt_no_padding(
    key: &[u8; 32],
    iv: &[u8; 16],
    ciphertext: &Ciphertext<AesCbc>,
) -> Result<Vec<u8>, UnalignedInput> {
    type Dec = cbc::Decryptor<aes::Aes256>;
    let mut buf = ciphertext.as_bytes().to_vec();
    if !buf.len().is_multiple_of(AES_BLOCK) {
        return Err(UnalignedInput { len: buf.len() });
    }
    let cipher = Dec::new(key.into(), iv.into());
    // `decrypt_padded` returns `Result<&[u8], block_padding::Error>`
    // viewing `buf` after the in-place transform. NoPadding never
    // strips bytes (the only failure mode is length mismatch,
    // ruled out by the check above); the view is dropped because
    // `buf` already holds the plaintext.
    let _view_ok = cipher.decrypt_padded::<NoPadding>(&mut buf);
    Ok(buf)
}

/// AES-256-ECB encrypt of a single 16-byte block. Secure messaging
/// uses this for IV derivation: `IV = AES-ECB(K_enc, SSC)`.
#[must_use]
pub(crate) fn aes256_ecb_encrypt_block(key: &[u8; 32], block: &[u8; 16]) -> [u8; 16] {
    // Infallible array-typed constructor; see comment in
    // `aes256_cbc_encrypt_no_padding`.
    let cipher = <aes::Aes256 as KeyInit>::new(key.into());
    let mut buf = *block;
    cipher.encrypt_block((&mut buf).into());
    buf
}

/// AES-256-CMAC (RFC 4493 with AES-256), full 16-byte tag.
///
/// Returns `[u8; 16]` because this function's role is "produce
/// the 16 bytes". The secure-messaging caller wraps the slice
/// into a typed [`Mac<CmacAes>`] when
/// the bytes leave the crypto layer; see
/// [`aes256_cmac_truncated`] for the typed wire-form
/// (`Mac<CmacAesTruncated>`) variant.
///
/// [`CmacAes`]: crate::crypto::container::CmacAes
#[must_use]
pub(crate) fn aes256_cmac(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
    // Infallible array-typed constructor; see comment in
    // `aes256_cbc_encrypt_no_padding`.
    let mut mac = <Cmac<aes::Aes256> as KeyInit>::new(key.into());
    mac.update(message);
    let tag = mac.finalize().into_bytes();
    let mut out = [0_u8; 16];
    out.copy_from_slice(&tag);
    out
}

/// AES-256-CMAC truncated to 8 bytes for the DO 8E secure-messaging
/// field.
///
/// Returns a typed [`Mac<CmacAesTruncated>`] -- this is the
/// shape that goes on the wire and cannot be confused with a
/// full 16-byte tag.
///
/// [`Mac<CmacAesTruncated>`]: Mac
#[must_use]
pub(crate) fn aes256_cmac_truncated(key: &[u8; 32], message: &[u8]) -> Mac<CmacAesTruncated> {
    let full = aes256_cmac(key, message);
    Mac::new(full[..8].to_vec())
}

#[cfg(test)]
mod tests {
    use super::{
        KdfParam, aes256_cbc_decrypt_no_padding, aes256_cbc_encrypt_no_padding, aes256_cmac,
        aes256_ecb_encrypt_block, kdf_aes256,
    };
    use crate::hex::Hex;

    /// AES-256 key shared by the RFC 4493 sec.4 / NIST SP 800-38B
    /// Example 4 and SP 800-38A F.1.5 vectors, decoded at
    /// const-eval time (a mistyped digit fails compilation).
    const NIST_EXAMPLE_AES256_KEY: [u8; 32] = Hex::decode_const(concat!(
        "603DEB1015CA71BE2B73AEF0857D7781",
        "1F352C073B6108D72D9810A30914DFF4",
    ));
    /// First example message block `M1` shared by the same vector
    /// sets.
    const NIST_EXAMPLE_BLOCK_M1: [u8; 16] = Hex::decode_const("6BC1BEE22E409F96E93D7E117393172A");

    /// AES-256-CMAC RFC 4493 sec.4 / NIST SP 800-38B Example 4 vectors.
    #[test]
    fn aes256_cmac_rfc4493_example_4_empty() {
        let tag = aes256_cmac(&NIST_EXAMPLE_AES256_KEY, b"");
        assert_eq!(
            hex::encode(tag).to_uppercase(),
            "028962F61B7BF89EFC6B551F4667D983"
        );
    }

    #[test]
    fn aes256_cmac_rfc4493_example_4_one_block() {
        let tag = aes256_cmac(&NIST_EXAMPLE_AES256_KEY, &NIST_EXAMPLE_BLOCK_M1);
        assert_eq!(
            hex::encode(tag).to_uppercase(),
            "28A7023F452E8F82BD4BF28D8C37C35C"
        );
    }

    #[test]
    fn aes256_cbc_roundtrip() {
        let key = [0x42_u8; 32];
        let iv = [0x77_u8; 16];
        let plaintext = b"this is one block this is two   ".to_vec();
        // Chain the two `Result`s and assert on the value -- the module bans
        // expect()/unwrap(), and an assertion inside a Result-returning fn
        // trips panic_in_result_fn, so keep this a `()` test over `and_then`.
        let round_tripped = aes256_cbc_encrypt_no_padding(&key, &iv, &plaintext)
            .and_then(|ct| aes256_cbc_decrypt_no_padding(&key, &iv, &ct));
        assert_eq!(round_tripped, Ok(plaintext));
    }

    #[test]
    fn aes256_ecb_known_vector() {
        // NIST SP 800-38A AES-256 ECB Example F.1.5.
        let ct = aes256_ecb_encrypt_block(&NIST_EXAMPLE_AES256_KEY, &NIST_EXAMPLE_BLOCK_M1);
        assert_eq!(
            hex::encode(ct).to_uppercase(),
            "F3EED1BDB5D2A03C064B5A7E3DB181F8"
        );
    }

    #[test]
    fn kdf_distinguishes_counters() {
        let k = b"shared secret bytes";
        // Compare via as_bytes(): Aes256Key deliberately has no
        // PartialEq (a secret key isn't a comparison subject).
        let a = kdf_aes256(k, KdfParam::Encryption);
        let b = kdf_aes256(k, KdfParam::Mac);
        let c = kdf_aes256(k, KdfParam::Password);
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), c.as_bytes());
        assert_ne!(b.as_bytes(), c.as_bytes());
        assert_eq!(kdf_aes256(k, KdfParam::Encryption).as_bytes(), a.as_bytes());
    }

    /// The two lost-data sentinels -- all-zero (`memset(0)`) and
    /// all-ones (`-1` / erased-flash fill) -- are the signatures of
    /// uninitialised / never-entered material; `from_bytes` rejects
    /// both, while any other key is accepted.
    #[test]
    fn from_bytes_rejects_sentinel_keys() {
        use super::Aes256Key;
        assert!(Aes256Key::from_bytes([0_u8; 32]).is_none());
        assert!(Aes256Key::from_bytes([u8::MAX; 32]).is_none());
        // A single bit away from a sentinel is enough -- the rule is
        // "not uninitialised", not "high-entropy".
        let mut almost_zero = [0_u8; 32];
        almost_zero[31] = 1;
        assert!(Aes256Key::from_bytes(almost_zero).is_some());
        let mut almost_ones = [u8::MAX; 32];
        almost_ones[31] = 0;
        assert!(Aes256Key::from_bytes(almost_ones).is_some());
    }
}
