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

//! `refineid card decrypt-auth`: RSA-PKCS1v15 decrypt with the
//! card's auth key.
//!
//! Reads a 384-byte ciphertext (RSA-3072 modulus length), VERIFY
//! PIN1, MSE:Set CT to the auth key, PSO:DECIPHER (with command
//! chaining for the 385-byte body), writes the unpadded plaintext
//! to disk. The auth-key decrypt path is what TLS RSA key
//! exchange and S/MIME envelopes need.

use alloc::fmt;
use std::path::PathBuf;

use refineid_lib_core::auth::{AuthError, PinOps as _, PinPolicyReason, VerifyOutcome};
use refineid_lib_core::backend::{
    ReaderAccessCap, ReaderBackend as _, ReaderBackendOps as _, ReaderPickError,
};
use refineid_lib_core::crypto::container::{Ciphertext, RsaPkcs1};
use refineid_lib_core::pin::PinBytes;
use refineid_lib_core::pkcs15::Pkcs15Ops as _;
use refineid_lib_core::sign::{RSA_3072_SIG_BYTES, SignError, SignOps as _};
use refineid_lib_pcsc::{PcscBackend, PcscError};

/// Inputs.
#[derive(Debug)]
pub struct DecryptAuthOptions {
    /// Filesystem path to the 384-byte RSA-3072 ciphertext
    /// (matches the modulus octet count).
    pub input: PathBuf,
    /// Filesystem path where the unpadded plaintext bytes will
    /// be written. The card strips PKCS#1 v1.5 padding before
    /// returning, so this file holds only the plaintext payload.
    pub output: PathBuf,
    /// PIN1 value gating the auth key. Consumed and zeroized at
    /// function return.
    pub pin: PinBytes,
    /// Optional reader-name substring; required when more than
    /// one card is present. Tier 0 `String`; presentational input
    /// to `ReaderFilter::new`.
    pub reader_filter: Option<String>,
}

/// One reader's worth of decrypt output.
#[derive(Debug, Clone)]
pub struct DecryptReport {
    /// PC/SC reader name the decrypt APDU chain landed against.
    /// Tier 0 `String` from `ReaderId::as_str().to_owned()`.
    pub reader: String,
    /// Length of the input ciphertext in bytes. Tier 0 `usize`;
    /// arithmetic count, the spec value is `RSA_3072_SIG_BYTES`.
    pub ciphertext_len: usize,
    /// Length of the unpadded plaintext returned by the card.
    /// Tier 0 `usize`; bounded by `RSA_3072_SIG_BYTES - 11`
    /// per PKCS#1 v1.5 padding floor (RFC 8017 §7.2.1).
    pub plaintext_len: usize,
    /// Filesystem path the plaintext was written to (mirrors
    /// `DecryptAuthOptions::output`).
    pub plaintext_path: PathBuf,
}

/// Error returned from the auth-key decrypt entrypoint.
#[derive(Debug)]
pub enum DecryptAuthError {
    /// Reader-selection failure (none / multiple / bad filter).
    ReaderPick(ReaderPickError),
    /// PC/SC connect / transmit error.
    Pcsc(PcscError),
    /// Ciphertext file I/O failure.
    InputRead {
        /// Filesystem path the read was attempted against.
        path: PathBuf,
        /// Underlying `std::io::Error`.
        source: std::io::Error,
    },
    /// Plaintext output I/O failure.
    PlaintextWrite {
        /// Filesystem path the write was attempted against.
        path: PathBuf,
        /// Underlying `std::io::Error`.
        source: std::io::Error,
    },
    /// Ciphertext wasn't exactly `RSA_3072_SIG_BYTES = 384` bytes.
    WrongCiphertextLength(usize),
    /// VERIFY of PIN1 returned a non-Ok outcome.
    PinRejected(VerifyOutcome),
    /// Local-policy rejection on PIN1 (length / non-digit)
    /// before any APDU went out. Counter is unaffected.
    PinPolicy(PinPolicyReason),
    /// `SELECT PKCS#15 application` failed. Tier 0 `String`;
    /// presentational copy of the upstream error.
    Pkcs15Select(String),
    /// Card returned an unexpected status word at one of the
    /// decrypt-chain stages.
    DecryptSw {
        /// Pipeline stage label (e.g. "MSE:SET CT",
        /// "PSO:Decipher"). Tier 0 `&'static str` from a fixed
        /// compile-time set.
        stage: &'static str,
        /// Card-returned status word per ISO 7816-4 §5.1.3.
        /// Tier 0 `u16` -- the typed projection is `StatusWord`
        /// from `lib-core::apdu`.
        sw: u16,
    },
    /// Lower-level transport / APDU failure not covered by the
    /// per-stage variants. Tier 0 `String`; presentational copy
    /// of the upstream error.
    Transport(String),
}

impl fmt::Display for DecryptAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReaderPick(e) => write!(f, "{e}"),
            Self::Pcsc(e) => write!(f, "PC/SC: {e}"),
            Self::InputRead { path, source } => {
                write!(f, "read ciphertext {}: {source}", path.display())
            }
            Self::PlaintextWrite { path, source } => {
                write!(f, "write plaintext {}: {source}", path.display())
            }
            Self::WrongCiphertextLength(n) => write!(
                f,
                "ciphertext is {n} bytes; RSA-3072 decrypt expects exactly {RSA_3072_SIG_BYTES}"
            ),
            Self::PinRejected(VerifyOutcome::WrongPin { retries_left }) => {
                write!(f, "PIN1 rejected (wrong PIN, {retries_left} retries left)")
            }
            Self::PinRejected(VerifyOutcome::Locked) => {
                write!(f, "PIN1 is blocked -- card needs a PUK unblock")
            }
            Self::PinRejected(VerifyOutcome::Other(sw)) => {
                write!(f, "PIN1 verify: unexpected SW={sw:#06X}")
            }
            Self::PinRejected(VerifyOutcome::Ok) => {
                write!(f, "internal: PinRejected(Ok) is not an error state")
            }
            Self::PinPolicy(r) => write!(f, "PIN1 rejected locally: {r}"),
            Self::Pkcs15Select(s) => write!(f, "SELECT PKCS#15 app: {s}"),
            Self::DecryptSw { stage, sw } => {
                write!(f, "decrypt failed at {stage}: SW={sw:#06X}")
            }
            Self::Transport(s) => write!(f, "transport: {s}"),
        }
    }
}

impl core::error::Error for DecryptAuthError {}

impl From<PcscError> for DecryptAuthError {
    fn from(e: PcscError) -> Self {
        Self::Pcsc(e)
    }
}

impl From<ReaderPickError> for DecryptAuthError {
    fn from(e: ReaderPickError) -> Self {
        Self::ReaderPick(e)
    }
}

/// Decrypt `options.input` against the first reader with a card.
///
/// `options` is taken by value so the embedded [`PinBytes`] drops
/// (and zeroes) when this function returns.
///
/// # Errors
/// PC/SC enumeration / connect failure, PIN policy / verify
/// failure, MSE / DECIPHER SW failure, ciphertext-length
/// mismatch, or I/O failure on input or output.
pub(crate) fn decrypt_auth_first(
    backend: PcscBackend,
    options: DecryptAuthOptions,
) -> Result<DecryptReport, DecryptAuthError> {
    let reader_id = backend.pick_single_reader(
        options
            .reader_filter
            .clone()
            .map(refineid_lib_core::backend::ReaderFilter::new),
    )?;

    let ct_bytes = std::fs::read(&options.input).map_err(|source| DecryptAuthError::InputRead {
        path: options.input.clone(),
        source,
    })?;
    if ct_bytes.len() != RSA_3072_SIG_BYTES {
        return Err(DecryptAuthError::WrongCiphertextLength(ct_bytes.len()));
    }
    let ciphertext_len = ct_bytes.len();
    let ciphertext: Ciphertext<RsaPkcs1> = Ciphertext::new(ct_bytes);

    // PinSequence: the PIN arrived in `options` and the
    // ciphertext was read before the open, so the VERIFY ->
    // decipher span is card-bound inside one held transaction.
    let mut transport = backend.open_session(&reader_id, ReaderAccessCap::PinSequence)?;
    transport
        .select_pkcs15_application()
        .map_err(|e| DecryptAuthError::Pkcs15Select(format!("{e}")))?;

    let outcome = transport
        .verify_pin1(options.pin.clone())
        .map_err(|e| match e {
            AuthError::Transport(t) => DecryptAuthError::Transport(format!("{t}")),
            AuthError::PinPolicy(r) => DecryptAuthError::PinPolicy(r),
        })?;
    match outcome {
        VerifyOutcome::Ok => {}
        rejected @ (VerifyOutcome::WrongPin { .. }
        | VerifyOutcome::Locked
        | VerifyOutcome::Other(_)) => return Err(DecryptAuthError::PinRejected(rejected)),
    }

    let plaintext = transport
        .decrypt_rsa_pkcs1_auth(ciphertext)
        .map_err(|e| match e {
            SignError::Transport(t) => DecryptAuthError::Transport(format!("{t}")),
            SignError::Sw(stage, sw) => DecryptAuthError::DecryptSw { stage, sw },
            SignError::UnexpectedSignatureLength(n) | SignError::InputTooLong(n) => {
                DecryptAuthError::WrongCiphertextLength(n)
            }
        })?;
    let plaintext_len = plaintext.len();

    std::fs::write(&options.output, plaintext.as_bytes()).map_err(|source| {
        DecryptAuthError::PlaintextWrite {
            path: options.output.clone(),
            source,
        }
    })?;

    Ok(DecryptReport {
        reader: reader_id.as_str().to_owned(),
        ciphertext_len,
        plaintext_len,
        plaintext_path: options.output,
    })
}

impl fmt::Display for DecryptReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "reader: {}", self.reader)?;
        writeln!(
            f,
            "ciphertext: {} bytes (RSA-3072 modulus)",
            self.ciphertext_len
        )?;
        writeln!(
            f,
            "plaintext: {} ({} bytes, PKCS#1 v1.5 unpadded)",
            self.plaintext_path.display(),
            self.plaintext_len
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{TestResult, check_true};
    use refineid_lib_core::apdu::status_word::PinRetries;

    fn pin_retries(n: u8) -> Result<PinRetries, Box<dyn core::error::Error>> {
        PinRetries::from_nibble(n).ok_or_else(|| "bad nibble".into())
    }

    #[test]
    fn pin_rejected_display_covers_each_outcome() -> TestResult {
        check_true(
            DecryptAuthError::PinRejected(VerifyOutcome::WrongPin {
                retries_left: pin_retries(3)?,
            })
            .to_string()
            .contains("PIN1 rejected (wrong PIN"),
            "wrong pin",
        )?;
        check_true(
            DecryptAuthError::PinRejected(VerifyOutcome::Locked)
                .to_string()
                .contains("PIN1 is blocked"),
            "locked",
        )?;
        check_true(
            DecryptAuthError::PinRejected(VerifyOutcome::Other(0x6F00))
                .to_string()
                .contains("unexpected SW=0x6F00"),
            "other sw",
        )?;
        check_true(
            DecryptAuthError::PinRejected(VerifyOutcome::Ok)
                .to_string()
                .contains("internal"),
            "ok guard",
        )
    }

    #[test]
    fn wrong_ciphertext_length_names_the_expected_size() -> TestResult {
        // RSA-3072 decrypt insists on exactly the modulus octet
        // count; the error must surface both the bad length and 384.
        let s = DecryptAuthError::WrongCiphertextLength(385).to_string();
        check_true(s.contains("385 bytes"), "actual length")?;
        check_true(
            s.contains(&RSA_3072_SIG_BYTES.to_string()),
            "expected length",
        )
    }

    #[test]
    fn stage_and_transport_error_display() -> TestResult {
        check_true(
            DecryptAuthError::PinPolicy(PinPolicyReason::NonDigit { byte_offset: 0 })
                .to_string()
                .contains("PIN1 rejected locally"),
            "pin policy",
        )?;
        check_true(
            DecryptAuthError::Pkcs15Select("6A82".to_owned())
                .to_string()
                .contains("SELECT PKCS#15 app: 6A82"),
            "pkcs15 select",
        )?;
        check_true(
            DecryptAuthError::DecryptSw {
                stage: "PSO:Decipher",
                sw: 0x6982,
            }
            .to_string()
            .contains("decrypt failed at PSO:Decipher: SW=0x6982"),
            "decrypt sw",
        )?;
        check_true(
            DecryptAuthError::Transport("reader vanished".to_owned())
                .to_string()
                .contains("transport: reader vanished"),
            "transport",
        )?;
        check_true(
            DecryptAuthError::ReaderPick(ReaderPickError::NoReaders)
                .to_string()
                .contains("readers"),
            "reader pick passthrough",
        )?;
        check_true(
            DecryptAuthError::Pcsc(PcscError::Transport("short response".to_owned()))
                .to_string()
                .starts_with("PC/SC: "),
            "pcsc prefix",
        )
    }

    #[test]
    fn io_error_display_includes_path_and_source() -> TestResult {
        let read = DecryptAuthError::InputRead {
            path: PathBuf::from("/tmp/ct.bin"),
            source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
        };
        check_true(
            read.to_string().contains("read ciphertext /tmp/ct.bin"),
            "read path",
        )?;
        check_true(read.to_string().contains("denied"), "read source")?;

        let write = DecryptAuthError::PlaintextWrite {
            path: PathBuf::from("/tmp/pt.bin"),
            source: std::io::Error::other("disk full"),
        };
        check_true(
            write.to_string().contains("write plaintext /tmp/pt.bin"),
            "write path",
        )?;
        check_true(write.to_string().contains("disk full"), "write source")
    }

    #[test]
    fn report_display_lists_reader_and_lengths() -> TestResult {
        let report = DecryptReport {
            reader: "ACR39U".to_owned(),
            ciphertext_len: 384,
            plaintext_len: 32,
            plaintext_path: PathBuf::from("/tmp/pt.bin"),
        };
        let s = report.to_string();
        check_true(s.contains("reader: ACR39U"), "reader")?;
        check_true(
            s.contains("ciphertext: 384 bytes (RSA-3072 modulus)"),
            "ct line",
        )?;
        check_true(
            s.contains("plaintext: /tmp/pt.bin (32 bytes, PKCS#1 v1.5 unpadded)"),
            "pt line",
        )
    }
}
