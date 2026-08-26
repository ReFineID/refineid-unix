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

//! Persistent device vault for stored pairings on Linux/Unix.

use alloc::vec::Vec;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

use super::messages::PairRecord;
use super::wire::WireError;

/// Device vault managing stored RAPP pairings.
#[derive(Debug, Clone)]
pub struct RappDeviceVault {
    storage_dir: PathBuf,
}

impl Default for RappDeviceVault {
    fn default() -> Self {
        Self::new_default()
    }
}

impl RappDeviceVault {
    /// Create a vault using the default user configuration path (`~/.config/refineid/pairs/`).
    pub fn new_default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        let storage_dir = PathBuf::from(home)
            .join(".config")
            .join("refineid")
            .join("pairs");
        Self { storage_dir }
    }

    /// Create a vault with a custom storage path.
    pub fn new(storage_dir: PathBuf) -> Self {
        Self { storage_dir }
    }

    fn ensure_dir(&self) -> Result<(), WireError> {
        fs::create_dir_all(&self.storage_dir).map_err(|_| WireError::InvalidValue { field: "vault_dir" })
    }

    fn pair_file_path(&self, pair_id: &[u8; 16]) -> PathBuf {
        let hex_name = crate::hex::Hex::encode(pair_id);
        self.storage_dir.join(format!("{hex_name}.cbor"))
    }

    /// Save a pair record to disk atomically.
    pub fn save_pair(&self, record: &PairRecord) -> Result<(), WireError> {
        self.ensure_dir()?;
        let encoded = record.encode()?;
        let path = self.pair_file_path(&record.pair_id);
        let tmp_path = self.storage_dir.join(format!("{}.tmp", crate::hex::Hex::encode(&record.pair_id)));

        let mut file = File::create(&tmp_path).map_err(|_| WireError::InvalidValue { field: "vault_write" })?;
        file.write_all(&encoded).map_err(|_| WireError::InvalidValue { field: "vault_write" })?;
        file.sync_all().map_err(|_| WireError::InvalidValue { field: "vault_write" })?;
        fs::rename(&tmp_path, &path).map_err(|_| WireError::InvalidValue { field: "vault_write" })?;
        Ok(())
    }

    /// Load a pair record by pair ID.
    pub fn load_pair(&self, pair_id: &[u8; 16]) -> Result<Option<PairRecord>, WireError> {
        let path = self.pair_file_path(pair_id);
        if !path.exists() {
            return Ok(None);
        }
        let mut file = File::open(&path).map_err(|_| WireError::InvalidValue { field: "vault_read" })?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|_| WireError::InvalidValue { field: "vault_read" })?;
        let record = PairRecord::decode(&bytes)?;
        Ok(Some(record))
    }

    /// List all active pair records stored in this vault.
    pub fn active_pairs(&self) -> Result<Vec<PairRecord>, WireError> {
        if !self.storage_dir.exists() {
            return Ok(Vec::new());
        }
        let entries = fs::read_dir(&self.storage_dir).map_err(|_| WireError::InvalidValue { field: "vault_read" })?;
        let mut pairs = Vec::new();

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "cbor") {
                if let Ok(mut file) = File::open(&path) {
                    let mut bytes = Vec::new();
                    if file.read_to_end(&mut bytes).is_ok() {
                        if let Ok(record) = PairRecord::decode(&bytes) {
                            pairs.push(record);
                        }
                    }
                }
            }
        }
        pairs.sort_by(|a, b| b.created_at_ms.cmp(&a.created_at_ms));
        Ok(pairs)
    }

    /// Delete and revoke a pair record.
    pub fn delete_pair(&self, pair_id: &[u8; 16]) -> Result<bool, WireError> {
        let path = self.pair_file_path(pair_id);
        if path.exists() {
            fs::remove_file(&path).map_err(|_| WireError::InvalidValue { field: "vault_delete" })?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Load the primary active paired remote device (the most recently paired).
    pub fn selected_pair(&self) -> Result<Option<PairRecord>, WireError> {
        let pairs = self.active_pairs()?;
        Ok(pairs.into_iter().next())
    }

    /// Update cached authentication certificate for a pair record.
    pub fn update_cached_auth_cert(&self, pair_id: &[u8; 16], cert_der: &[u8]) -> Result<(), WireError> {
        if let Some(mut pair) = self.load_pair(pair_id)? {
            pair.cached_auth_cert = Some(cert_der.to_vec());
            self.save_pair(&pair)?;
        }
        Ok(())
    }
}
