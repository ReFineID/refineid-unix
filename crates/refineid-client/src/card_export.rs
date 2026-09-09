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

//! `refineid card export-all DIR`: dump every card-public artifact
//! to one directory.
//!
//! No PIN required. Writes:
//!
//! - `EF.<fid>.der` for each cert slot present on the card
//!   (authentication, qualified-signature, on-card root CA, alt
//!   slots when populated).
//! - `EF.011C.der` -- raw EF.CardAccess (PACE info, parameter
//!   sets).
//! - `EF.5032.der` -- raw EF.TokenInfo (PKCS#15 token metadata).
//! - `atr.hex` -- single-line lowercase-hex ATR for offline
//!   variant lookup.
//!
//! Files are written with the card's exact bytes -- callers can
//! re-parse with `refineid cert show`, openssl, or any tool that
//! groks DER.

use alloc::fmt;
use std::path::{Path, PathBuf};

use refineid_lib_core::apdu::status_word::StatusWord;
use refineid_lib_core::backend::{
    ReaderAccessCap, ReaderBackend as _, ReaderBackendOps as _, ReaderPickError,
};
use refineid_lib_core::card_access::EF_CARD_ACCESS_FID;
use refineid_lib_core::pkcs15::{CertSlot, EF_TOKEN_INFO_FID, Pkcs15Error, Pkcs15Ops as _};
use refineid_lib_core::transport::CardTransport;
use refineid_lib_pcsc::{PcscBackend, PcscError};

/// Inputs.
#[derive(Debug, Clone)]
pub struct ExportAllOptions {
    /// Target directory for the dump. Created if absent; cert
    /// files written inside it as `EF.<fid>.der`.
    pub directory: PathBuf,
    /// Optional substring match against reader names. Tier 0
    /// `String`; presentational input to `ReaderFilter::new`.
    pub reader_filter: Option<String>,
}

/// One reader's worth of export output.
#[derive(Debug, Clone)]
pub struct ExportReport {
    /// PC/SC reader the export ran against. Tier 0 `String`
    /// from `ReaderId::as_str().to_owned()`.
    pub reader: String,
    /// Directory the files were written into.
    pub directory: PathBuf,
    /// What we actually wrote, in order.
    pub written: Vec<WrittenFile>,
    /// Slots / files that returned "absent" (SW=6A82) and were
    /// quietly skipped. Listed by file ID so the caller can see
    /// the gaps without fail-stop.
    pub skipped: Vec<String>,
}

/// One file the export wrote.
#[derive(Debug, Clone)]
pub struct WrittenFile {
    /// Filesystem path the file was written to.
    pub path: PathBuf,
    /// Length in bytes of the file just written. Tier 0
    /// `usize`; arithmetic count.
    pub bytes: usize,
    /// Human label for the file kind ("auth cert", "qualified-
    /// signature cert", "EF.CardAccess", "EF.TokenInfo", "ATR
    /// hex"). Tier 0 `&'static str` from a fixed compile-time
    /// set.
    pub kind: &'static str,
}

/// Error returned from the export entrypoint.
#[derive(Debug)]
pub enum ExportError {
    /// Reader-selection failure.
    ReaderPick(ReaderPickError),
    /// PC/SC connect / transmit error.
    Pcsc(PcscError),
    /// Directory create failure.
    Mkdir {
        /// Filesystem path the mkdir was attempted against.
        path: PathBuf,
        /// Underlying `std::io::Error`.
        source: std::io::Error,
    },
    /// File write failure.
    Write {
        /// Filesystem path the write was attempted against.
        path: PathBuf,
        /// Underlying `std::io::Error`.
        source: std::io::Error,
    },
    /// Card's ATR did not parse as a valid ISO 7816-3 structure
    /// (operationally never; the transport's invariant guarantees a
    /// well-formed ATR). Tier 0 `String`; presentational copy.
    AtrInvalid(String),
    /// Lower-level transport / APDU failure (cert read, EF
    /// read, etc.). Tier 0 `String`; presentational copy of the
    /// upstream error.
    Transport(String),
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReaderPick(e) => write!(f, "{e}"),
            Self::Pcsc(e) => write!(f, "PC/SC: {e}"),
            Self::Mkdir { path, source } => write!(f, "mkdir {}: {source}", path.display()),
            Self::Write { path, source } => write!(f, "write {}: {source}", path.display()),
            Self::AtrInvalid(e) => write!(f, "card returned an unparseable ATR: {e}"),
            Self::Transport(s) => write!(f, "transport: {s}"),
        }
    }
}

impl core::error::Error for ExportError {}

impl From<PcscError> for ExportError {
    fn from(e: PcscError) -> Self {
        Self::Pcsc(e)
    }
}

impl From<ReaderPickError> for ExportError {
    fn from(e: ReaderPickError) -> Self {
        Self::ReaderPick(e)
    }
}

/// Dump all card-public state to `options.directory` from the
/// first reader with a card present.
///
/// `read_certificate` already handles SELECT-chain per slot;
/// EF.CardAccess + EF.TokenInfo are read directly here so we get
/// the raw bytes for the export (the lib-core parsing helpers
/// don't surface raw DER).
///
/// # Errors
/// PC/SC enumeration / connect failure, directory creation
/// failure, write failure, or transport failure. Absent slots /
/// meta files (SW=6A82) are silently skipped and listed in
/// [`ExportReport::skipped`].
pub(crate) fn export_all_first(
    backend: PcscBackend,
    options: &ExportAllOptions,
) -> Result<ExportReport, ExportError> {
    let reader_id = backend.pick_single_reader(
        options
            .reader_filter
            .clone()
            .map(refineid_lib_core::backend::ReaderFilter::new),
    )?;

    std::fs::create_dir_all(&options.directory).map_err(|source| ExportError::Mkdir {
        path: options.directory.clone(),
        source,
    })?;

    let mut transport = backend.open_session(&reader_id, ReaderAccessCap::Read)?;
    let mut written: Vec<WrittenFile> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();

    // ATR -- parsed off the transport handle, re-emitted as wire
    // bytes for the hex dump.
    let atr_wire = transport
        .atr()
        .map_err(|e| ExportError::AtrInvalid(format!("{e}")))?
        .to_wire_bytes();
    let atr_path = options.directory.join("atr.hex");
    let atr_line = format!("{}\n", hex::encode(&atr_wire));
    std::fs::write(&atr_path, atr_line.as_bytes()).map_err(|source| ExportError::Write {
        path: atr_path.clone(),
        source,
    })?;
    written.push(WrittenFile {
        path: atr_path,
        bytes: atr_wire.len(),
        kind: "ATR",
    });

    // EF.CardAccess (MF/011C) -- public, no app SELECT needed.
    match read_raw_ef_under_mf(&mut transport, EF_CARD_ACCESS_FID) {
        Ok(bytes) => write_file(
            &options.directory,
            "EF.011C.der",
            "EF.CardAccess",
            &bytes,
            &mut written,
        )?,
        Err(EfReadError::NotFound) => skipped.push("EF.011C (EF.CardAccess)".to_owned()),
        Err(EfReadError::Transport(t)) => return Err(ExportError::Transport(t)),
    }

    // EF.TokenInfo (DF.5015 PKCS#15 app / 5032) -- needs the
    // PKCS#15 app selected.
    if let Err(e) = transport.select_pkcs15_application() {
        // If PKCS#15 SELECT itself fails, surface as transport;
        // the rest of the cert-slot reads will fail the same way
        // and there's nothing meaningful left to dump.
        return Err(ExportError::Transport(format!("SELECT PKCS#15 app: {e}")));
    }
    match read_raw_ef_under_current_df(&mut transport, EF_TOKEN_INFO_FID) {
        Ok(bytes) => write_file(
            &options.directory,
            "EF.5032.der",
            "EF.TokenInfo",
            &bytes,
            &mut written,
        )?,
        Err(EfReadError::NotFound) => skipped.push("EF.5032 (EF.TokenInfo)".to_owned()),
        Err(EfReadError::Transport(t)) => return Err(ExportError::Transport(t)),
    }

    // Cert slots -- read_certificate handles its own SELECT chain
    // per slot (UnderPkcs15App / UnderDf5016 / UnderMf), so we
    // don't need to babysit DF state here.
    for slot in CertSlot::all() {
        match transport.read_certificate(slot) {
            Ok(der) => {
                let fid = slot.fid();
                let name = format!("EF.{:02x}{:02x}.der", fid[0], fid[1]);
                write_file(
                    &options.directory,
                    &name,
                    slot.label(),
                    der.as_bytes(),
                    &mut written,
                )?;
            }
            // Absent slot: SELECT returns FileNotFound (SW 0x6A82) ->
            // "not provisioned", recorded as skipped, not an error.
            Err(Pkcs15Error::Sw(sw)) if StatusWord::from_u16(sw) == StatusWord::FileNotFound => {
                skipped.push(format!(
                    "EF.{:02x}{:02x} ({})",
                    slot.fid()[0],
                    slot.fid()[1],
                    slot.label()
                ));
            }
            Err(e) => return Err(ExportError::Transport(format!("{e}"))),
        }
    }

    Ok(ExportReport {
        reader: reader_id.as_str().to_owned(),
        directory: options.directory.clone(),
        written,
        skipped,
    })
}

/// Write one exported artefact to `dir/name` and record the
/// outcome in `log`.
///
/// Both the path and `kind` label are captured in the
/// [`WrittenFile`] entry so the report can list each
/// artefact's role (cert slot, EF.SOD, DG2 face, etc.); the
/// label is `&'static str` so the audit trail uses stable
/// names from the call site rather than allocations.
fn write_file(
    dir: &Path,
    name: &str,
    kind: &'static str,
    bytes: &[u8],
    log: &mut Vec<WrittenFile>,
) -> Result<(), ExportError> {
    let path = dir.join(name);
    std::fs::write(&path, bytes).map_err(|source| ExportError::Write {
        path: path.clone(),
        source,
    })?;
    log.push(WrittenFile {
        path,
        bytes: bytes.len(),
        kind,
    });
    Ok(())
}

/// Result of attempting to read an EF under MF / current DF.
///
/// Distinguishes "card explicitly said file-not-found"
/// (ISO 7816-4 `6A82` -- a routine outcome for unprovisioned
/// slots) from any other transport-layer error (PC/SC failure,
/// reader vanished, protocol violation). The export pipeline
/// quietly skips `NotFound`; `Transport` bubbles up.
enum EfReadError {
    /// SELECT returned `6A82` "file not found" -- the slot
    /// is genuinely not provisioned on this card.
    NotFound,
    /// Any other transport-layer failure during the SELECT/
    /// READ BINARY round-trip. String form for the report.
    Transport(String),
}

/// Select the MF first, then read the EF identified by `fid`.
///
/// Used to export EFs whose absolute path is `MF/EF.fid` --
/// the on-card root cert (`MF/4334`) and EF.CardAccess
/// (`MF/011C`). Pre-selecting the MF resets any DF context the
/// previous read may have left behind so the lookup is
/// path-deterministic.
fn read_raw_ef_under_mf<T: CardTransport>(
    transport: &mut T,
    fid: [u8; 2],
) -> Result<Vec<u8>, EfReadError> {
    if let Err(e) = transport.select_mf() {
        return Err(EfReadError::Transport(format!("SELECT MF: {e}")));
    }
    read_raw_ef_under_current_df(transport, fid)
}

/// Read the EF `fid` under whatever DF is currently selected.
///
/// Used after a DF select has already been issued (e.g.
/// PKCS#15 metadata under `DF.5015`/`DF.5016`). These exported
/// EFs contain one DER object, so its declared length bounds
/// the last READ BINARY without depending on FCI response data.
fn read_raw_ef_under_current_df<T: CardTransport>(
    transport: &mut T,
    fid: [u8; 2],
) -> Result<Vec<u8>, EfReadError> {
    match transport.select_ef(fid) {
        Ok(()) => {}
        Err(Pkcs15Error::Sw(sw)) if StatusWord::from_u16(sw) == StatusWord::FileNotFound => {
            return Err(EfReadError::NotFound);
        }
        Err(e) => return Err(EfReadError::Transport(e.to_string())),
    }
    transport
        .read_binary_der_object("exported EF")
        .map_err(|e| EfReadError::Transport(e.to_string()))
}

impl fmt::Display for ExportReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "reader: {}", self.reader)?;
        writeln!(f, "directory: {}", self.directory.display())?;
        writeln!(f, "wrote {} files:", self.written.len())?;
        for w in &self.written {
            writeln!(
                f,
                "  {} -- {} ({} bytes)",
                w.path.display(),
                w.kind,
                w.bytes
            )?;
        }
        if !self.skipped.is_empty() {
            writeln!(f, "skipped {} absent files:", self.skipped.len())?;
            for s in &self.skipped {
                writeln!(f, "  {s}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{TempDir, TestResult, check, check_true};

    #[test]
    fn write_file_writes_bytes_and_records_a_log_entry() -> TestResult {
        let dir = TempDir::new("export-ok")?;
        let mut log: Vec<WrittenFile> = Vec::new();
        write_file(
            dir.path(),
            "EF.4331.der",
            "auth cert",
            b"\x30\x82\x01\x00",
            &mut log,
        )
        .map_err(|e| format!("write_file: {e}"))?;

        // The bytes hit disk verbatim...
        let on_disk =
            std::fs::read(dir.path().join("EF.4331.der")).map_err(|e| format!("read back: {e}"))?;
        check(
            &on_disk,
            &b"\x30\x82\x01\x00".to_vec(),
            "round-tripped bytes",
        )?;

        // ...and the log records the path, length, and kind label.
        check(&log.len(), &1_usize, "log length")?;
        let entry = log.first().ok_or("log entry")?;
        check(&entry.bytes, &4_usize, "logged byte count")?;
        check(&entry.kind, &"auth cert", "logged kind")?;
        check_true(entry.path.ends_with("EF.4331.der"), "logged path filename")
    }

    #[test]
    fn write_file_surfaces_io_failure_and_leaves_log_untouched() -> TestResult {
        // Target a directory that doesn't exist: fs::write doesn't
        // create parents, so the write fails and nothing is logged.
        let dir = TempDir::new("export-fail")?;
        let missing = dir.path().join("no-such-subdir");
        let mut log: Vec<WrittenFile> = Vec::new();
        let result = write_file(&missing, "x.der", "auth cert", b"ab", &mut log);
        check_true(
            matches!(result, Err(ExportError::Write { .. })),
            "Write error on missing parent dir",
        )?;
        check(&log.len(), &0_usize, "log stays empty on failure")
    }

    #[test]
    fn export_error_display() -> TestResult {
        check_true(
            ExportError::Mkdir {
                path: PathBuf::from("/out"),
                source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
            }
            .to_string()
            .contains("mkdir /out: denied"),
            "mkdir",
        )?;
        check_true(
            ExportError::Write {
                path: PathBuf::from("/out/a.der"),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "gone"),
            }
            .to_string()
            .contains("write /out/a.der: gone"),
            "write",
        )?;
        check_true(
            ExportError::AtrInvalid("bad TS byte".to_owned())
                .to_string()
                .contains("unparseable ATR: bad TS byte"),
            "atr invalid",
        )?;
        check_true(
            ExportError::Transport("read EF.SOD: timeout".to_owned())
                .to_string()
                .contains("transport: read EF.SOD: timeout"),
            "transport",
        )?;
        check_true(
            ExportError::Pcsc(PcscError::Transport("short".to_owned()))
                .to_string()
                .starts_with("PC/SC: "),
            "pcsc prefix",
        )?;
        check_true(
            ExportError::ReaderPick(ReaderPickError::NoCardPresent)
                .to_string()
                .contains("card"),
            "reader pick passthrough",
        )
    }

    #[test]
    fn report_display_lists_written_and_skipped() -> TestResult {
        let report = ExportReport {
            reader: "OMNIKEY".to_owned(),
            directory: PathBuf::from("/dump"),
            written: vec![
                WrittenFile {
                    path: PathBuf::from("/dump/atr.hex"),
                    bytes: 40,
                    kind: "ATR",
                },
                WrittenFile {
                    path: PathBuf::from("/dump/EF.4331.der"),
                    bytes: 1200,
                    kind: "auth cert",
                },
            ],
            skipped: vec!["EF.5032 (EF.TokenInfo)".to_owned()],
        };
        let s = report.to_string();
        check_true(s.contains("reader: OMNIKEY"), "reader")?;
        check_true(s.contains("directory: /dump"), "directory")?;
        check_true(s.contains("wrote 2 files:"), "written count")?;
        check_true(s.contains("/dump/atr.hex -- ATR (40 bytes)"), "atr entry")?;
        check_true(
            s.contains("/dump/EF.4331.der -- auth cert (1200 bytes)"),
            "cert entry",
        )?;
        check_true(s.contains("skipped 1 absent files:"), "skipped count")?;
        check_true(s.contains("EF.5032 (EF.TokenInfo)"), "skipped entry")
    }

    #[test]
    fn report_display_omits_skipped_section_when_empty() -> TestResult {
        let report = ExportReport {
            reader: "OMNIKEY".to_owned(),
            directory: PathBuf::from("/dump"),
            written: Vec::new(),
            skipped: Vec::new(),
        };
        check_true(
            !report.to_string().contains("skipped"),
            "no skipped section",
        )
    }
}
