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

//! ISO 7816-4 / BSI TR-03110-3 §A.5 secure-messaging wrapper for the
//! AES-256 session keys produced by PACE.
//!
//! Wrap (host -> card):
//!
//! 1. Set CLA bit `0x0C` (SM with header authentication).
//! 2. Increment the 16-byte big-endian Send Sequence Counter (SSC).
//! 3. If the plain APDU has a data field: ISO/IEC 7816-4 mode-2 pad
//!    it (`0x80 || 0x00...`) to 16 B, encrypt with AES-256-CBC where
//!    `IV = AES-256-ECB(K_enc, SSC)`, then build
//!    `DO87 = 87 L 01 || ciphertext`.
//! 4. If the plain APDU has Le: build `DO97 = 97 01 Le`.
//! 5. MAC input is `SSC || pad(header) || DO87 || DO97`, padded once
//!    more to 16 B; the AES-CMAC tag truncated to 8 B becomes
//!    `DO8E = 8E 08 <tag>`.
//! 6. Wrapped APDU: `CLA' INS P1 P2 LC DO87 DO97 DO8E LE=00`.
//!
//! Unwrap (card -> host):
//!
//! 1. Increment the SSC.
//! 2. Parse `DO87?`, `DO99`, `DO8E` from the response body.
//! 3. Verify the DO8E tag against `AES-CMAC(K_mac, SSC || DO87 || DO99)`
//!    (padded). On mismatch the channel is broken - every subsequent
//!    transmission would fail anyway, so we surface it as an error.
//! 4. If DO87 is present, decrypt + strip padding to get the body.
//! 5. The two SW bytes come from DO99.
//!
//! `SmTransport` itself implements [`CardTransport`], so layers above
//! the SM channel (cert read, VERIFY PIN, PSO:CDS) treat it as just
//! another transport - the SM mechanics are invisible.
//!
//! Reserved-for-future: this layer sits on top of [`crate::pace`]
//! and shares its "not yet wired into a live adapter" status.
//! It compiles in full but stays unreferenced until the
//! contactless / SM-on-contact paths land.
use subtle::ConstantTimeEq as _;

use crate::atr::{Atr, AtrError};
use crate::ber::{self, BerTlvIter};
use crate::crypto::container::{AesCbc, Ciphertext};
use crate::crypto::symmetric::{
    AES_BLOCK, Aes256Key, aes256_cbc_decrypt_no_padding, aes256_cbc_encrypt_no_padding,
    aes256_cmac_truncated, aes256_ecb_encrypt_block,
};
use crate::pace::{PaceSession, Ssc};
use crate::transport::{
    CardTransport, CommandApdu, ResponseApdu, TransportErrorExt, TransportErrorKind,
    TransportOutcome,
};

/// SM tagged data objects we touch.
///
/// ISO 7816-4 §10.2.3 (SM data objects). `DO87` carries the
/// encrypted-with-padding command body; the leading byte inside
/// the value is the padding-indicator (`01` for ISO 7816-4
/// padding).
const TAG_DO87: u8 = 0x87;
/// `DO97`: protected `Le` for the wrapped command (ISO 7816-4
/// §10.2.3.3). One or two bytes; refineid only emits one-byte
/// `Le` because PACE channels short-form responses.
const TAG_DO97: u8 = 0x97;
/// `DO99`: protected SW1-SW2 (ISO 7816-4 §10.2.3.4). The two
/// status-word bytes returned by the card, MAC'd alongside the
/// response so a wire-tampered SW can't slip past.
const TAG_DO99: u8 = 0x99;
/// `DO8E`: cryptographic checksum (MAC) over the preceding
/// SM-encoded data (ISO 7816-4 §10.2.3.5). The PACE channel
/// uses AES-CMAC truncated to 8 bytes (BSI TR-03110-3 §F.2).
const TAG_DO8E: u8 = 0x8E;

/// ISO 7816-4 short-form command APDU header: CLA + INS + P1 + P2.
const APDU_HEADER_LEN: usize = 4;
/// `Le = 0` in ISO 7816-4 short form means "return all available
/// response bytes up to 256". Used at the end of every SM APDU.
const LE_AS_MUCH_AS_CARD_HAS: u8 = 0x00;

/// DO87 padding-content indicator (ISO 7816-4 §5.6.3.4): the byte
/// preceding the ciphertext. `0x01` = "padded per ISO 7816".
const DO87_PADDING_INDICATOR: u8 = 0x01;
/// ISO 7816-4 mode-2 padding: a `0x80` marker byte followed by
/// `0x00` filler bytes to the block boundary.
const ISO7816_PAD_MARKER: u8 = 0x80;
/// See [`ISO7816_PAD_MARKER`]: the `0x00` filler that follows it.
const ISO7816_PAD_FILLER: u8 = 0x00;

/// `SmTransport` wraps a raw transport with an established
/// [`PaceSession`]; the wrapped transport is itself a transport.
#[expect(
    missing_debug_implementations,
    reason = "SmTransport carries the post-PACE session keys k_enc / k_mac; deriving Debug would route AES-256 key material into accidental {:?} / dbg!() calls. Manual omission keeps key bytes off any formatter."
)]
#[non_exhaustive]
pub struct SmTransport<T: CardTransport> {
    /// Raw transport this SM channel encrypts on top of.
    /// Borrows / owns are decided by the caller; `SmTransport`
    /// makes no assumption beyond `CardTransport`.
    inner: T,
    /// AES-256 encryption key derived from the PACE shared
    /// secret (`KDF(Z, c=1)`, BSI TR-03110-3 §A.2.4 / §F.2).
    /// Never logged; `Aes256Key` zeroizes the bytes when this
    /// struct drops and redacts them from any formatter.
    k_enc: Aes256Key,
    /// AES-256 CMAC key derived from the PACE shared secret
    /// (`KDF(Z, c=2)`). Used for the `DO8E` MAC over each
    /// wrapped APDU. Same `Aes256Key` zeroize-on-drop hygiene as
    /// `k_enc`.
    k_mac: Aes256Key,
    /// Send-Sequence Counter (BSI TR-03110-3 §F.4), incremented
    /// before every wrap and every unwrap; mismatch between PCD
    /// and PICC SSCs instantly fails the MAC check on the next
    /// exchange. Typed [`Ssc`] so it can't be confused with an IV
    /// / cipher block.
    ssc: Ssc,
}

/// Error returned by the secure-messaging wrap / unwrap layer
/// (BSI TR-03110-3 §F.3).
#[non_exhaustive]
#[derive(Debug)]
pub enum SmError<TE> {
    /// Transport-layer failure (PC/SC error, USB CCID, ...).
    Transport(TE),
    /// SM response could not be parsed into DO87?/DO99/DO8E.
    Malformed(&'static str),
    /// The card's MAC did not match - channel integrity broken.
    MacMismatch,
    /// Wrapped command exceeded short-form Lc (255 bytes). `FINeID`
    /// PACE-protected commands stay well under this; if we ever
    /// need extended length, plumb it through here.
    CommandTooLong,
}

impl<TE: core::fmt::Display> core::fmt::Display for SmError<TE> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "SM transport: {e}"),
            Self::Malformed(w) => write!(f, "SM: malformed response - {w}"),
            Self::MacMismatch => write!(f, "SM: card MAC did not match"),
            Self::CommandTooLong => write!(f, "SM: wrapped command exceeds 255 bytes"),
        }
    }
}

impl<TE: core::fmt::Debug + core::fmt::Display + 'static> core::error::Error for SmError<TE> {}

impl<TE: TransportErrorExt> TransportErrorExt for SmError<TE> {
    fn kind(&self) -> TransportErrorKind {
        match self {
            Self::Transport(error) => error.kind(),
            Self::Malformed(_) | Self::MacMismatch => TransportErrorKind::ProtocolDesync,
            Self::CommandTooLong => TransportErrorKind::Backend,
        }
    }
}

impl<T: CardTransport> SmTransport<T> {
    /// Adopt the keys + SSC from a freshly completed PACE handshake.
    //
    // `session` is consumed by value: its secret `Aes256Key`
    // K_enc / K_mac are *moved* into the SM transport, so the PACE
    // caller is left with no copy to reuse after the SM channel is
    // established (the move-check enforces the anti-reuse policy).
    // Not `const fn`: `Aes256Key` is `ZeroizeOnDrop`, and a moved-
    // from value with a destructor can't be handled in const eval.
    #[inline]
    pub fn new(inner: T, session: PaceSession) -> Self {
        Self {
            inner,
            k_enc: session.k_enc,
            k_mac: session.k_mac,
            ssc: session.ssc,
        }
    }

    /// Drop SM and return the underlying transport. Useful to switch
    /// back to plain transmission after an SM session ends, though in
    /// practice we keep SM up for the lifetime of the card connection.
    #[inline]
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Borrow the underlying raw transport without sending an SM command.
    ///
    /// This is used only by platform adapters that must refresh an
    /// OS-owned card handle or re-establish PACE after the OS reset the card.
    #[inline]
    pub const fn inner(&self) -> &T {
        &self.inner
    }

    /// Mutably borrow the underlying raw transport without sending an SM
    /// command.
    ///
    /// Callers must not issue ordinary application APDUs through this borrow
    /// while the current SM session is live. The intended use is the
    /// pre-PACE reset and handshake that replaces that session immediately.
    #[inline]
    pub const fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Replace every PACE-derived SM value after the operating system reset
    /// the card and a new PACE handshake completed on the raw transport.
    #[inline]
    pub fn replace_session(&mut self, session: PaceSession) {
        self.k_enc = session.k_enc;
        self.k_mac = session.k_mac;
        self.ssc = session.ssc;
    }

    /// Replace the SM session keys with a freshly-derived pair
    /// (post-CA / post-rekey) and reset the SSC to all zero.
    ///
    /// Used by `ca::run_chip_authentication` to roll the
    /// SM session over from PACE-derived keys to CA-derived
    /// keys after a successful ECDH handshake. The next APDU
    /// wrapped through this transport uses the new keys; if the
    /// chip didn't actually hold the matching CA private key,
    /// its MACs won't agree and the next op surfaces as
    /// [`SmError::MacMismatch`] -- which is the implicit
    /// verification that CA succeeded.
    #[inline]
    pub fn rekey(&mut self, k_enc: Aes256Key, k_mac: Aes256Key) {
        self.k_enc = k_enc;
        self.k_mac = k_mac;
        self.ssc = Ssc::INITIAL;
    }

    /// SSC + 1, big-endian, with rollover. Bumped before MAC of both
    /// command and response.
    fn increment_ssc(&mut self) {
        self.ssc.increment();
    }

    /// Wrap a plain ISO 7816-4 command APDU into a PACE-protected
    /// SM APDU.
    ///
    /// BSI TR-03110-3 §F.3. Steps performed in order:
    ///
    ///   1. SSC := SSC + 1 (pre-increment so MAC input pins
    ///      this counter value).
    ///   2. Set CLA bit 4 (SM indicator `0Ch`).
    ///   3. Build `DO87` (encrypted body with padding-indicator
    ///      `01`) when the plain APDU has a data field.
    ///   4. Build `DO97` (protected `Le`) when the plain APDU
    ///      has a response-length byte.
    ///   5. CMAC over `SSC || pad(header) || DO87 || DO97`,
    ///      ISO 7816-4 padded, AES-256-CMAC truncated to 8
    ///      bytes -> `DO8E`.
    ///   6. Assemble wrapped APDU; reject when total body
    ///      exceeds short-form `Lc` (255 bytes).
    ///
    /// Extended-length APDUs are out of scope; FINEID PACE
    /// traffic fits in short form.
    fn wrap(&mut self, plain: &[u8]) -> Result<Vec<u8>, SmError<T::Error>> {
        // APDU header is fixed at CLA INS P1 P2; reject anything shorter
        // as a malformed input rather than panicking inside a Result fn.
        let header: [u8; 4] = plain
            .get(..4)
            .and_then(|h| <[u8; 4]>::try_from(h).ok())
            .ok_or(SmError::Malformed("APDU shorter than 4-byte header"))?;
        let cla = header[0] | 0x0C;
        let ins = header[1];
        let p1 = header[2];
        let p2 = header[3];

        // Decode short-form case 1/2/3/4. Extended-length APDUs are
        // out of scope for v0.1 - FINeID PACE traffic stays under
        // 255 B per request.
        let (data, le) = SmHelpers::decode_short_apdu(plain)
            .ok_or(SmError::Malformed("APDU does not match a short-form case"))?;

        self.increment_ssc();

        let do87 = if data.is_empty() {
            Vec::new()
        } else {
            let padded = SmHelpers::iso7816_4_pad(data);
            let iv = aes256_ecb_encrypt_block(self.k_enc.as_bytes(), self.ssc.as_bytes());
            let cipher = aes256_cbc_encrypt_no_padding(self.k_enc.as_bytes(), &iv, &padded)
                .map_err(|_unaligned| {
                    SmError::Malformed("SM wrap: padded plaintext not block-aligned")
                })?;
            // DO87 value is `0x01 || ciphertext`; the leading byte is
            // the "padding-content indicator" per ISO 7816-4 §5.6.3.4
            // (value 1 = padded according to ISO 7816-4).
            //
            // Capacity hint: `1 + cipher.len()`. AES-CBC ciphertexts
            // here are short-form-bounded (well under usize::MAX);
            // saturating_add keeps the hint panic-free even if a
            // future caller drove cipher.len() to overflow.
            let mut do87_value = Vec::with_capacity(1_usize.saturating_add(cipher.len()));
            do87_value.push(0x01);
            do87_value.extend_from_slice(cipher.as_bytes());
            ber::tlv(TAG_DO87, &do87_value)
        };

        let do97 = le.map_or_else(Vec::new, |le_byte| ber::tlv(TAG_DO97, [le_byte]));

        // MAC input: SSC || pad(header) || DO87 || DO97, then pad once
        // more to a 16-byte boundary. Capacity hint uses
        // `saturating_add` to keep the allocation request panic-free.
        let mac_cap = 16_usize
            .saturating_add(16)
            .saturating_add(do87.len())
            .saturating_add(do97.len())
            .saturating_add(16);
        let mut mac_input = Vec::with_capacity(mac_cap);
        mac_input.extend_from_slice(self.ssc.as_bytes());
        mac_input.extend_from_slice(&SmHelpers::iso7816_4_pad(&[cla, ins, p1, p2]));
        mac_input.extend_from_slice(&do87);
        mac_input.extend_from_slice(&do97);
        mac_input = SmHelpers::iso7816_4_pad(&mac_input);
        let tag = aes256_cmac_truncated(self.k_mac.as_bytes(), &mac_input);
        let do_mac = ber::tlv(TAG_DO8E, tag.as_bytes());

        let body_len = do87
            .len()
            .saturating_add(do97.len())
            .saturating_add(do_mac.len());
        if body_len > 255 {
            return Err(SmError::CommandTooLong);
        }

        // body_len <= 255 from the early-return; use saturating
        // arithmetic so the capacity hint can never overflow. The
        // u8::try_from result falls back to u8::MAX = 255, the
        // asserted upper bound.
        let apdu_cap = APDU_HEADER_LEN
            .saturating_add(1) // Lc
            .saturating_add(body_len)
            .saturating_add(1); // Le
        let mut apdu = Vec::with_capacity(apdu_cap);
        let lc = u8::try_from(body_len).unwrap_or(u8::MAX);
        apdu.extend_from_slice(&[cla, ins, p1, p2, lc]);
        apdu.extend_from_slice(&do87);
        apdu.extend_from_slice(&do97);
        apdu.extend_from_slice(&do_mac);
        // Always request response - Le=0x00 means "up to 256 bytes",
        // which the underlying transport's 6Cxx/61xx loops handle.
        apdu.push(LE_AS_MUCH_AS_CARD_HAS);
        Ok(apdu)
    }

    /// Verify and decrypt a PACE-protected SM response.
    ///
    /// BSI TR-03110-3 §F.3. Returns `(plaintext, sw)` where
    /// `sw` is the 16-bit status word from the protected `DO99`
    /// after MAC verification. Order of operations:
    ///
    ///   1. SSC := SSC + 1 (pre-increment, same as `wrap`).
    ///   2. Walk TLVs, capture `DO87` / `DO99` / `DO8E`.
    ///   3. Recompute CMAC over `SSC || DO87? || DO99`,
    ///      compare against `DO8E` (constant-time).
    ///   4. Decrypt `DO87` ciphertext with the per-message IV
    ///      `AES-ECB(K_enc, SSC)` (BSI §F.2.2), strip
    ///      ISO 7816-4 padding.
    ///
    /// A failed MAC returns [`SmError::MacMismatch`] and the
    /// channel is unusable -- the caller should drop the
    /// `SmTransport`; the keys are no longer trusted.
    fn unwrap(&mut self, response: &[u8]) -> Result<(Vec<u8>, u16), SmError<T::Error>> {
        self.increment_ssc();

        let mut do87_value: Option<&[u8]> = None;
        let mut do99_value: Option<&[u8]> = None;
        let mut do_mac_value: Option<&[u8]> = None;

        let iter = BerTlvIter::new(response);
        for parsed in iter {
            let tlv = parsed.map_err(|_ber_err| SmError::Malformed("BER parse failed"))?;
            match tlv.tag {
                t if t == u16::from(TAG_DO87) => do87_value = Some(tlv.value),
                t if t == u16::from(TAG_DO99) => do99_value = Some(tlv.value),
                t if t == u16::from(TAG_DO8E) => do_mac_value = Some(tlv.value),
                _ => {} // Tolerate unexpected DOs; SM responses can carry DO81/DO82 too.
            }
        }

        let do99 = do99_value.ok_or(SmError::Malformed("no DO99"))?;
        let do_mac = do_mac_value.ok_or(SmError::Malformed("no DO8E"))?;
        let do99_bytes: [u8; 2] =
            <[u8; 2]>::try_from(do99).map_err(|_try_err| SmError::Malformed("DO99 not 2 bytes"))?;
        let do_mac_bytes: [u8; 8] = <[u8; 8]>::try_from(do_mac)
            .map_err(|_try_err| SmError::Malformed("DO8E not 8 bytes"))?;

        // Verify MAC over SSC || DO87 || DO99 (each as full TLV bytes), padded.
        let mac_cap = 16_usize.saturating_add(4).saturating_add(response.len());
        let mut mac_input = Vec::with_capacity(mac_cap);
        mac_input.extend_from_slice(self.ssc.as_bytes());
        if let Some(v) = do87_value {
            mac_input.extend_from_slice(&ber::tlv(TAG_DO87, v));
        }
        mac_input.extend_from_slice(&ber::tlv(TAG_DO99, do99));
        mac_input = SmHelpers::iso7816_4_pad(&mac_input);
        let computed = aes256_cmac_truncated(self.k_mac.as_bytes(), &mac_input);
        // Constant-time compare: both byte slices are 8 bytes
        // (DO8E length-checked above; Mac<CmacAesTruncated>
        // length-fixed by type). `subtle::ConstantTimeEq` is
        // guaranteed not to short-circuit, unlike a hand-rolled
        // XOR loop which LLVM may optimize away.
        if !bool::from(computed.as_bytes().ct_eq(do_mac_bytes.as_slice())) {
            return Err(SmError::MacMismatch);
        }

        // Decrypt DO87 if present.
        let body = if let Some(v) = do87_value {
            // DO87 value is `0x01 || ciphertext` per ISO 7816-4
            // §5.6.3.4; split off the indicator before checking
            // the ciphertext shape.
            let (indicator, cipher_bytes) =
                v.split_first().ok_or(SmError::Malformed("DO87 empty"))?;
            if *indicator != DO87_PADDING_INDICATOR {
                return Err(SmError::Malformed("DO87 missing 0x01 indicator"));
            }
            if !cipher_bytes.len().is_multiple_of(AES_BLOCK) {
                return Err(SmError::Malformed("DO87 cipher not whole blocks"));
            }
            let cipher = Ciphertext::<AesCbc>::new(cipher_bytes.to_vec());
            let iv = aes256_ecb_encrypt_block(self.k_enc.as_bytes(), self.ssc.as_bytes());
            let plain = aes256_cbc_decrypt_no_padding(self.k_enc.as_bytes(), &iv, &cipher)
                .map_err(|_unaligned| SmError::Malformed("DO87 cipher not whole blocks"))?;
            SmHelpers::iso7816_4_unpad(&plain)
        } else {
            Vec::new()
        };

        let sw = u16::from_be_bytes(do99_bytes);
        Ok((body, sw))
    }
}

impl<T: CardTransport> CardTransport for SmTransport<T> {
    type Error = SmError<T::Error>;

    fn transmit_outcome(&mut self, apdu: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
        let wrapped = self.wrap(apdu.as_bytes())?;
        let wrapped = CommandApdu::from(wrapped);
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "TransportOutcome is #[non_exhaustive]; non-Response state transitions (NoCard, CardReset, ReaderRemoved, ...) and any future variant are forwarded unchanged to the SM caller."
        )]
        let raw = match self
            .inner
            .transmit_outcome(&wrapped)
            .map_err(SmError::Transport)?
        {
            TransportOutcome::Response(response) => response,
            other => return Ok(other),
        };
        // A protected response body must always be unwrapped, even
        // when the outer status is not 9000. FINEID can return an
        // outer warning such as 6282 while still carrying authenticated
        // DO99/DO8E data. The card has already advanced its SSC to MAC
        // that body, so skipping unwrap would desynchronise every later
        // exchange. Only a bare response with no protected body is a
        // transport-level refusal that can pass through unchanged.
        if raw.body.is_empty() {
            return Ok(TransportOutcome::Response(raw));
        }
        let (body, sw) = self.unwrap(&raw.body)?;
        let [sw1, sw2] = sw.to_be_bytes();
        Ok(TransportOutcome::Response(ResponseApdu { body, sw1, sw2 }))
    }

    fn atr(&self) -> Result<Atr, AtrError> {
        self.inner.atr()
    }
}

// MARK: - Helpers

/// Helpers hosted on a unit struct (typing-discipline: no free
/// fns with borrowed parameters; see `doc/typing-discipline.md`).
struct SmHelpers;

impl SmHelpers {
    /// ISO/IEC 7816-4 padding mode 2: append `0x80`, then
    /// `0x00`s to a 16-byte boundary. Always adds at least one
    /// byte.
    fn iso7816_4_pad(data: &[u8]) -> Vec<u8> {
        // Round up to the next 16-byte boundary, plus always at
        // least one full new block when `data` already aligns
        // (the mode-2 invariant: padding is never empty).
        //
        // `data.len() / AES_BLOCK` is exact-integer floor and the
        // intent here ("how many full blocks fit so far"), so
        // div_euclid is the right named primitive; the `+1`
        // models the always-add-one-more-block rule.
        let full_blocks = data.len().div_euclid(AES_BLOCK);
        let cap = full_blocks.saturating_add(1).saturating_mul(AES_BLOCK);
        let mut out = Vec::with_capacity(cap);
        out.extend_from_slice(data);
        out.push(ISO7816_PAD_MARKER);
        while !out.len().is_multiple_of(AES_BLOCK) {
            out.push(ISO7816_PAD_FILLER);
        }
        out
    }

    /// Inverse of [`Self::iso7816_4_pad`]. Walks back from the
    /// end past `0x00` bytes; the next byte must be `0x80`.
    /// Anything before is the recovered plaintext.
    fn iso7816_4_unpad(data: &[u8]) -> Vec<u8> {
        // Find the trailing `0x80` marker by walking from the
        // end with a typed reverse iterator -- avoids `i - 1`
        // arithmetic on a usize and naked indexing.
        let trailing_zeros = data
            .iter()
            .rev()
            .take_while(|&&b| b == ISO7816_PAD_FILLER)
            .count();
        // After skipping trailing zeros, the next byte must be
        // 0x80; if not, return the input untouched (matches
        // legacy behaviour for malformed inputs).
        let Some(marker_index_from_end) = trailing_zeros.checked_add(1) else {
            return data.to_vec();
        };
        let Some(marker_pos) = data.len().checked_sub(marker_index_from_end) else {
            return data.to_vec();
        };
        // `marker_pos` is in `0..data.len()`; the slice index is safe.
        match data.get(marker_pos) {
            Some(&ISO7816_PAD_MARKER) => data
                .get(..marker_pos)
                .map_or_else(|| data.to_vec(), <[u8]>::to_vec),
            _ => data.to_vec(),
        }
    }

    /// Decode a short-form APDU into `(data_field, optional_le)`.
    /// Cases:
    ///
    /// - 1: header only
    /// - 2: header + Le
    /// - 3: header + Lc + data
    /// - 4: header + Lc + data + Le
    ///
    /// Returns `None` if the APDU does not match any short-form
    /// case (too short, or `Lc` does not match the body length).
    fn decode_short_apdu(apdu: &[u8]) -> Option<(&[u8], Option<u8>)> {
        match apdu.len() {
            // Case 1: header only.
            4 => Some((&[], None)),
            // Case 2: header + Le.
            5 => apdu.get(4).map(|&le| (&[][..], Some(le))),
            _ => {
                // Case 3 or 4: header + Lc + data [+ Le]. Read Lc and
                // dispatch on the remaining bytes.
                let lc = usize::from(*apdu.get(4)?);
                let body_start = 5_usize;
                let body_end = body_start.checked_add(lc)?;
                let data = apdu.get(body_start..body_end)?;
                if apdu.len() == body_end {
                    Some((data, None))
                } else if apdu.len() == body_end.checked_add(1)? {
                    let le = *apdu.get(body_end)?;
                    Some((data, Some(le)))
                } else {
                    None
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::atr::MINIMAL_DIRECT_ATR;

    #[test]
    fn iso7816_4_pad_round_trips() {
        let cases: &[&[u8]] = &[
            b"",
            b"a",
            b"abcdef",
            b"0123456789abcdef",  // exact block - pad still adds a full new block
            b"0123456789abcdef0", // 17 bytes
        ];
        for &c in cases {
            let p = SmHelpers::iso7816_4_pad(c);
            assert!(
                p.len().is_multiple_of(16),
                "padded length must be a multiple of 16"
            );
            assert!(p.len() > c.len(), "padding always adds at least one byte");
            assert_eq!(SmHelpers::iso7816_4_unpad(&p), c.to_vec());
        }
    }

    #[test]
    fn ssc_increments_by_one_with_rollover() {
        // Build the SSC for a small counter value in the typed
        // domain, so the test asserts on whole-counter equality
        // rather than poking individual byte offsets.
        fn ssc_for(value: u16) -> Ssc {
            let mut bytes = [0_u8; 16];
            // Big-endian: the counter's low 16 bits occupy the last
            // two bytes (BSI TR-03110-3 §F.4).
            let [hi, lo] = value.to_be_bytes();
            *bytes.last_mut().expect("16-byte SSC is non-empty") = lo;
            let second_last = bytes.len().saturating_sub(2);
            if let Some(slot) = bytes.get_mut(second_last) {
                *slot = hi;
            }
            Ssc::from_bytes(bytes)
        }

        let mut sm = SmTransport::new(
            NullTransport,
            PaceSession {
                k_enc: Aes256Key::from_bytes([1_u8; 32]).expect("non-zero test key"),
                k_mac: Aes256Key::from_bytes([1_u8; 32]).expect("non-zero test key"),
                ssc: Ssc::INITIAL,
            },
        );

        // One step off the all-zero start is counter value 1.
        sm.increment_ssc();
        assert_eq!(sm.ssc, ssc_for(1));

        // Exactly `u8::MAX + 1` total steps roll the last byte
        // through its full range once: it wraps back to zero and
        // carries 1 into the next byte -- counter value 0x0100.
        for _ in 1..=u16::from(u8::MAX) {
            sm.increment_ssc();
        }
        assert_eq!(sm.ssc, ssc_for(u16::from(u8::MAX) + 1));
    }

    #[test]
    fn decode_short_apdu_all_four_cases() {
        // Case 1.
        assert_eq!(
            SmHelpers::decode_short_apdu(&[0, 0xA4, 0, 0]),
            Some((&[][..], None))
        );
        // Case 2: Le.
        assert_eq!(
            SmHelpers::decode_short_apdu(&[0, 0xB0, 0, 0, 0x10]),
            Some((&[][..], Some(0x10)))
        );
        // Case 3: data, no Le.
        assert_eq!(
            SmHelpers::decode_short_apdu(&[0, 0x20, 0, 0, 4, 1, 2, 3, 4]),
            Some((&[1_u8, 2, 3, 4][..], None))
        );
        // Case 4: data + Le.
        assert_eq!(
            SmHelpers::decode_short_apdu(&[0, 0x20, 0, 0, 4, 1, 2, 3, 4, 0]),
            Some((&[1_u8, 2, 3, 4][..], Some(0)))
        );
    }

    /// Round-trip wrap -> unwrap with both endpoints sharing keys and
    /// SSC: encrypt a SELECT EF APDU, then verify a fake card-side
    /// response. The "card" here is a second `SmTransport` instance
    /// driven manually so we can swap its role.
    #[test]
    fn wrap_unwrap_round_trip_with_shared_keys() {
        let k_enc = [0x42_u8; 32];
        let k_mac = [0x77_u8; 32];

        // PCD SSC starts at 0; both sides will increment in lockstep.
        let pcd_session = PaceSession {
            k_enc: Aes256Key::from_bytes(k_enc).expect("non-zero test key"),
            k_mac: Aes256Key::from_bytes(k_mac).expect("non-zero test key"),
            ssc: Ssc::INITIAL,
        };
        let card_session = PaceSession {
            k_enc: Aes256Key::from_bytes(k_enc).expect("non-zero test key"),
            k_mac: Aes256Key::from_bytes(k_mac).expect("non-zero test key"),
            ssc: Ssc::INITIAL,
        };

        // PCD wraps a case-3 SELECT-EF APDU.
        let plain: &[u8] = &[0x00, 0xA4, 0x02, 0x0C, 0x02, 0x43, 0x31];
        let mut pcd = SmTransport::new(NullTransport, pcd_session);
        let wrapped = pcd.wrap(plain).expect("wrap ok");

        // Card-side: SmTransport.unwrap is the *response* unwrap; but
        // the wrapper-and-verifier of an incoming command is the same
        // shape transposed (SSC bumped first, MAC over header || ...).
        // For a round-trip test we instead synthesise a "card response"
        // here on the same SmTransport (used as the response unwrapper).

        // Simulate the card replying with success and a 4-byte body.
        // We need to: bump SSC (the card would), build DO87(plain="DEAD"),
        // DO99=9000, then DO8E over SSC||DO87||DO99, all from the
        // card's perspective.
        let mut card = SmTransport::new(NullTransport, card_session);
        card.increment_ssc(); // matches PCD's command-side bump

        // Card-side response build (mirrors `unwrap`'s inverse):
        card.increment_ssc(); // response-side SSC bump
        let payload = b"\xDE\xAD\xBE\xEF";
        let padded = SmHelpers::iso7816_4_pad(payload);
        let iv = aes256_ecb_encrypt_block(card.k_enc.as_bytes(), card.ssc.as_bytes());
        let cipher = aes256_cbc_encrypt_no_padding(card.k_enc.as_bytes(), &iv, &padded)
            .expect("iso7816_4_pad guarantees block alignment");
        let mut do87_value = Vec::with_capacity(1 + cipher.len());
        do87_value.push(0x01);
        do87_value.extend_from_slice(cipher.as_bytes());
        let do_cipher = ber::tlv(TAG_DO87, &do87_value);
        let do_status = ber::tlv(TAG_DO99, [0x90, 0x00]);

        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(card.ssc.as_bytes());
        mac_input.extend_from_slice(&do_cipher);
        mac_input.extend_from_slice(&do_status);
        let mac_input = SmHelpers::iso7816_4_pad(&mac_input);
        let tag = aes256_cmac_truncated(card.k_mac.as_bytes(), &mac_input);
        let do_mac = ber::tlv(TAG_DO8E, tag.as_bytes());

        let mut response = Vec::new();
        response.extend_from_slice(&do_cipher);
        response.extend_from_slice(&do_status);
        response.extend_from_slice(&do_mac);

        // PCD unwraps. Its SSC was bumped once (command); now bumps
        // again for the response - should land on the same value the
        // card used to MAC.
        let (body, sw) = pcd.unwrap(&response).expect("unwrap ok");
        assert_eq!(sw, 0x9000);
        assert_eq!(body, payload);

        // Verify both SSCs ended up identical.
        assert_eq!(pcd.ssc, card.ssc);

        // The wrapped APDU survives the round-trip - sanity check it
        // sets the SM CLA bits and starts with our forged header.
        assert_eq!(wrapped[0], 0x0C); // 0x00 | 0x0C
        assert_eq!(wrapped[1], 0xA4);
        assert_eq!(wrapped[2], 0x02);
        assert_eq!(wrapped[3], 0x0C);
    }

    #[test]
    fn protected_body_is_unwrapped_despite_outer_warning() {
        let k_enc = [0x42_u8; 32];
        let k_mac = [0x77_u8; 32];
        let payload = [0xAA_u8, 0xBB];

        let mut card = SmTransport::new(
            NullTransport,
            PaceSession {
                k_enc: Aes256Key::from_bytes(k_enc).expect("non-zero test key"),
                k_mac: Aes256Key::from_bytes(k_mac).expect("non-zero test key"),
                ssc: Ssc::INITIAL,
            },
        );
        card.increment_ssc();
        card.increment_ssc();

        let padded = SmHelpers::iso7816_4_pad(&payload);
        let iv = aes256_ecb_encrypt_block(card.k_enc.as_bytes(), card.ssc.as_bytes());
        let cipher = aes256_cbc_encrypt_no_padding(card.k_enc.as_bytes(), &iv, &padded)
            .expect("padded payload is block-aligned");
        let mut do87_value = Vec::with_capacity(1_usize.saturating_add(cipher.len()));
        do87_value.push(DO87_PADDING_INDICATOR);
        do87_value.extend_from_slice(cipher.as_bytes());
        let cryptogram_object = ber::tlv(TAG_DO87, &do87_value);
        let status_object = ber::tlv(TAG_DO99, [0x62, 0x82]);

        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(card.ssc.as_bytes());
        mac_input.extend_from_slice(&cryptogram_object);
        mac_input.extend_from_slice(&status_object);
        let mac_input = SmHelpers::iso7816_4_pad(&mac_input);
        let tag = aes256_cmac_truncated(card.k_mac.as_bytes(), &mac_input);
        let mac_object = ber::tlv(TAG_DO8E, tag.as_bytes());

        let mut protected_body = Vec::new();
        protected_body.extend_from_slice(&cryptogram_object);
        protected_body.extend_from_slice(&status_object);
        protected_body.extend_from_slice(&mac_object);

        let inner = FixedResponseTransport {
            response: Some(ResponseApdu {
                body: protected_body,
                sw1: 0x62,
                sw2: 0x82,
            }),
        };
        let mut pcd = SmTransport::new(
            inner,
            PaceSession {
                k_enc: Aes256Key::from_bytes(k_enc).expect("non-zero test key"),
                k_mac: Aes256Key::from_bytes(k_mac).expect("non-zero test key"),
                ssc: Ssc::INITIAL,
            },
        );
        let outcome = pcd
            .transmit_outcome(&CommandApdu::from(&[0x00, 0xB0, 0x00, 0x00, 0x02]))
            .expect("protected warning response is accepted");
        assert_eq!(
            outcome,
            TransportOutcome::Response(ResponseApdu {
                body: payload.to_vec(),
                sw1: 0x62,
                sw2: 0x82,
            })
        );
        assert_eq!(pcd.ssc, card.ssc);
    }

    /// A tampered DO87 must trip the MAC mismatch check.
    #[test]
    fn unwrap_rejects_mac_mismatch() {
        let k_enc = [0x42_u8; 32];
        let k_mac = [0x77_u8; 32];
        let session = PaceSession {
            k_enc: Aes256Key::from_bytes(k_enc).expect("non-zero test key"),
            k_mac: Aes256Key::from_bytes(k_mac).expect("non-zero test key"),
            ssc: Ssc::INITIAL,
        };
        let mut pcd = SmTransport::new(NullTransport, session);
        // DO87 value is `0x01 || 16-byte cipher block`; the cipher
        // contents don't matter because we'll fail at the MAC step
        // before any decryption is attempted.
        let mut do87_value = vec![0x01];
        do87_value.extend_from_slice(&[0_u8; 16]);
        let do_cipher = ber::tlv(TAG_DO87, &do87_value);
        let do_status = ber::tlv(TAG_DO99, [0x90, 0x00]);
        let bogus_tag = [0_u8; 8];
        let do_mac = ber::tlv(TAG_DO8E, bogus_tag);
        let mut response = Vec::new();
        response.extend_from_slice(&do_cipher);
        response.extend_from_slice(&do_status);
        response.extend_from_slice(&do_mac);
        let err = pcd
            .unwrap(&response)
            .expect_err("bogus DO8E MAC is rejected");
        assert!(matches!(err, SmError::MacMismatch));
    }

    /// In-memory "no-op" transport - never called, present only so we
    /// can construct an `SmTransport` whose mechanics we drive through
    /// `wrap`/`unwrap` directly in tests.
    struct NullTransport;
    impl CardTransport for NullTransport {
        type Error = String;
        fn transmit_outcome(&mut self, _: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            unreachable!("NullTransport is for direct wrap/unwrap testing")
        }
        fn atr(&self) -> Result<Atr, AtrError> {
            Atr::new(MINIMAL_DIRECT_ATR)
        }
    }

    struct FixedResponseTransport {
        response: Option<ResponseApdu>,
    }

    impl CardTransport for FixedResponseTransport {
        type Error = String;

        fn transmit_outcome(&mut self, _: &CommandApdu) -> Result<TransportOutcome, Self::Error> {
            self.response
                .take()
                .map(TransportOutcome::Response)
                .ok_or_else(|| "fixed response already consumed".to_owned())
        }

        fn atr(&self) -> Result<Atr, AtrError> {
            Atr::new(MINIMAL_DIRECT_ATR)
        }
    }
}
