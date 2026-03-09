//! Device key store for Apple App Attest.
//!
//! Stores EC public keys from one-time attestation registration,
//! used for subsequent assertion signature verification.
//! Tracks monotonic counters for replay protection.
//!
//! Supports optional file-backed persistence: use [`DeviceKeyStore::new_persistent`]
//! to load/save entries as JSON on disk, or [`DeviceKeyStore::new`] for in-memory only.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceKeyEntry {
    pub key_id: String,
    /// PEM-encoded EC public key (P-256).
    pub public_key_pem: String,
    /// Monotonic counter for replay protection.
    pub counter: u32,
    pub created_at: u64,
}

/// Device key store with optional file-backed persistence.
pub struct DeviceKeyStore {
    store: HashMap<String, DeviceKeyEntry>,
    /// When set, the store flushes to this path after every mutation.
    path: Option<PathBuf>,
}

impl DeviceKeyStore {
    /// Create a purely in-memory store (no persistence).
    pub fn new() -> Self {
        Self {
            store: HashMap::new(),
            path: None,
        }
    }

    /// Create a file-backed store.
    ///
    /// If the file at `path` exists it is loaded; otherwise the store starts
    /// empty and the file will be created on the first mutation.
    pub fn new_persistent(path: &str) -> Self {
        let path_buf = PathBuf::from(path);
        let store = match std::fs::read_to_string(&path_buf) {
            Ok(contents) => match serde_json::from_str::<HashMap<String, DeviceKeyEntry>>(
                &contents,
            ) {
                Ok(map) => {
                    info!(
                        path = %path_buf.display(),
                        entries = map.len(),
                        "loaded device key store from disk"
                    );
                    map
                }
                Err(e) => {
                    warn!(
                        path = %path_buf.display(),
                        error = %e,
                        "failed to parse device key store file, starting empty"
                    );
                    HashMap::new()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                info!(
                    path = %path_buf.display(),
                    "device key store file not found, starting empty"
                );
                HashMap::new()
            }
            Err(e) => {
                warn!(
                    path = %path_buf.display(),
                    error = %e,
                    "failed to read device key store file, starting empty"
                );
                HashMap::new()
            }
        };

        Self {
            store,
            path: Some(path_buf),
        }
    }

    pub fn save_key(&mut self, key_id: &str, public_key_pem: &str, counter: u32) -> Result<(), String> {
        if self.store.contains_key(key_id) {
            warn!(key_id = %key_id, "attempted to re-register existing device key");
            return Err(format!("device key already registered: {key_id}"));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        self.store.insert(
            key_id.to_string(),
            DeviceKeyEntry {
                key_id: key_id.to_string(),
                public_key_pem: public_key_pem.to_string(),
                counter,
                created_at: now,
            },
        );

        self.flush_to_disk();
        Ok(())
    }

    pub fn get_key(&self, key_id: &str) -> Option<&DeviceKeyEntry> {
        self.store.get(key_id)
    }

    pub fn update_counter(&mut self, key_id: &str, counter: u32) -> Result<(), String> {
        let entry = self
            .store
            .get_mut(key_id)
            .ok_or_else(|| format!("device key not found: {key_id}"))?;
        entry.counter = counter;

        self.flush_to_disk();

        Ok(())
    }

    /// Write the full store to disk if a persistence path is configured.
    ///
    /// Uses write-to-temp-then-rename for atomic updates (prevents corruption
    /// if the process is killed mid-write).
    fn flush_to_disk(&self) {
        let Some(path) = &self.path else {
            return;
        };

        let json = match serde_json::to_string_pretty(&self.store) {
            Ok(j) => j,
            Err(e) => {
                warn!(error = %e, "failed to serialize device key store");
                return;
            }
        };

        let tmp_path = path.with_extension("tmp");
        if let Err(e) = std::fs::write(&tmp_path, &json) {
            warn!(
                path = %tmp_path.display(),
                error = %e,
                "failed to write device key store temp file"
            );
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
        }
        if let Err(e) = std::fs::rename(&tmp_path, path) {
            warn!(
                error = %e,
                "failed to rename device key store temp file"
            );
            return;
        }

        info!(
            path = %path.display(),
            entries = self.store.len(),
            "flushed device key store to disk"
        );
    }
}
