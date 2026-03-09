//! Per-device rate limiting with optional file-backed persistence.
//!
//! Timestamps are stored as Unix epoch milliseconds (`u64`) so that state
//! survives serialization (unlike `std::time::Instant`).  When persistence
//! is enabled the state file is rewritten after every successful
//! `check_and_record` call; expired entries are swept at that time to keep
//! the file compact.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ONE_HOUR_MS: u64 = 3_600_000;
const ONE_DAY_MS: u64 = 86_400_000;

/// Maximum number of distinct device entries in the rate limiter.
/// If the map exceeds this size after sweeping expired entries,
/// new requests are rejected to prevent memory exhaustion from
/// an attacker generating unlimited unique device IDs.
const MAX_ENTRIES: usize = 2_000_000;

// ---------------------------------------------------------------------------
// Per-device state (internal)
// ---------------------------------------------------------------------------

/// Serializable per-device rate state.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct DeviceRateState {
    /// Timestamps (epoch millis) within the current hour window.
    hour_window: Vec<u64>,
    /// Timestamps (epoch millis) within the current day window.
    day_window: Vec<u64>,
}

impl DeviceRateState {
    fn new() -> Self {
        Self {
            hour_window: Vec::new(),
            day_window: Vec::new(),
        }
    }

    /// Prune timestamps older than the respective windows and attempt to
    /// record a new request.  Returns `Ok(())` on success or a static error
    /// message when a limit is exceeded.
    fn check_and_record(
        &mut self,
        now_ms: u64,
        per_hour: u32,
        per_day: u32,
    ) -> Result<(), &'static str> {
        let hour_cutoff = now_ms.saturating_sub(ONE_HOUR_MS);
        let day_cutoff = now_ms.saturating_sub(ONE_DAY_MS);

        self.hour_window.retain(|&t| t > hour_cutoff);
        self.day_window.retain(|&t| t > day_cutoff);

        if self.hour_window.len() >= per_hour as usize {
            return Err("hourly rate limit exceeded");
        }
        if self.day_window.len() >= per_day as usize {
            return Err("daily rate limit exceeded");
        }

        self.hour_window.push(now_ms);
        self.day_window.push(now_ms);
        Ok(())
    }

    /// Returns `true` when both windows are empty (i.e. all timestamps have
    /// expired), meaning this entry can be removed entirely.
    fn is_empty(&self) -> bool {
        self.hour_window.is_empty() && self.day_window.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Per-device rate limiter with optional JSON file persistence.
pub struct RateLimiter {
    devices: HashMap<String, DeviceRateState>,
    /// `None` means in-memory only; `Some(path)` enables auto-flush.
    persist_path: Option<PathBuf>,
}

impl RateLimiter {
    /// Create a purely in-memory rate limiter (state is lost on restart).
    pub fn new() -> Self {
        info!("rate_limit: created in-memory rate limiter");
        Self {
            devices: HashMap::new(),
            persist_path: None,
        }
    }

    /// Create a rate limiter backed by a JSON file at `path`.
    ///
    /// If the file exists it is loaded; otherwise the limiter starts empty
    /// and the file will be created on the first flush.
    pub fn new_persistent(path: &str) -> Self {
        let persist_path = PathBuf::from(path);
        let devices = Self::load_from_disk(&persist_path);
        info!(
            path = %persist_path.display(),
            devices = devices.len(),
            "rate_limit: loaded persistent state"
        );
        Self {
            devices,
            persist_path: Some(persist_path),
        }
    }

    /// Return the number of devices that currently have rate limit entries.
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Check the rate limit for `device_id` and, if allowed, record a new
    /// request.  When persistence is enabled the state file is flushed
    /// automatically after a successful recording.
    pub fn check_and_record(
        &mut self,
        device_id: &str,
        per_hour: u32,
        per_day: u32,
    ) -> Result<(), &'static str> {
        let now_ms = Self::now_epoch_ms();

        // If this is a new device (not already tracked), check the entry cap
        // to prevent memory exhaustion from an attacker generating unlimited
        // unique device IDs.
        if !self.devices.contains_key(device_id) && self.devices.len() >= MAX_ENTRIES {
            // Try to reclaim space by sweeping expired entries first.
            self.sweep_expired();
            if self.devices.len() >= MAX_ENTRIES {
                warn!(
                    entries = self.devices.len(),
                    "rate_limit: entry cap reached, rejecting new device"
                );
                return Err("rate limit capacity exceeded — try again later");
            }
        }

        let state = self
            .devices
            .entry(device_id.to_owned())
            .or_insert_with(DeviceRateState::new);

        state.check_and_record(now_ms, per_hour, per_day)?;

        debug!(
            device_id,
            hour_count = state.hour_window.len(),
            day_count = state.day_window.len(),
            "rate_limit: request recorded"
        );

        // Auto-flush when persistent.
        if self.persist_path.is_some() {
            self.flush();
        }

        Ok(())
    }

    /// Write current state to the backing file (no-op if in-memory only).
    ///
    /// Expired entries are swept before writing so the file stays compact.
    pub fn flush(&mut self) {
        let path = match &self.persist_path {
            Some(p) => p.clone(),
            None => return,
        };

        self.sweep_expired();

        let json = match serde_json::to_string_pretty(&self.devices) {
            Ok(j) => j,
            Err(e) => {
                warn!(error = %e, "rate_limit: failed to serialize state");
                return;
            }
        };

        // Atomic-ish write: write to a temp file then rename.
        let tmp_path = path.with_extension("tmp");
        if let Err(e) = std::fs::write(&tmp_path, json.as_bytes()) {
            warn!(
                path = %tmp_path.display(),
                error = %e,
                "rate_limit: failed to write temp file"
            );
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
        }
        if let Err(e) = std::fs::rename(&tmp_path, &path) {
            warn!(
                error = %e,
                "rate_limit: failed to rename temp file to state file"
            );
            return;
        }

        debug!(
            path = %path.display(),
            devices = self.devices.len(),
            "rate_limit: flushed state to disk"
        );
    }

    // -- private helpers ----------------------------------------------------

    /// Remove devices whose windows are completely empty.
    fn sweep_expired(&mut self) {
        let now_ms = Self::now_epoch_ms();
        let hour_cutoff = now_ms.saturating_sub(ONE_HOUR_MS);
        let day_cutoff = now_ms.saturating_sub(ONE_DAY_MS);

        // First prune each device's windows, then remove empty devices.
        self.devices.values_mut().for_each(|s| {
            s.hour_window.retain(|&t| t > hour_cutoff);
            s.day_window.retain(|&t| t > day_cutoff);
        });
        let before = self.devices.len();
        self.devices.retain(|_, s| !s.is_empty());
        let swept = before - self.devices.len();
        if swept > 0 {
            debug!(swept, "rate_limit: swept expired device entries");
        }
    }

    /// Load device state from a JSON file, returning an empty map on any
    /// error (missing file, corrupt JSON, etc.).
    fn load_from_disk(path: &PathBuf) -> HashMap<String, DeviceRateState> {
        let data = match std::fs::read_to_string(path) {
            Ok(d) => d,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "rate_limit: could not read state file, starting fresh"
                    );
                }
                return HashMap::new();
            }
        };

        match serde_json::from_str::<HashMap<String, DeviceRateState>>(&data) {
            Ok(map) => map,
            Err(e) => {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "rate_limit: corrupt state file, starting fresh"
                );
                HashMap::new()
            }
        }
    }

    /// Current time as milliseconds since the Unix epoch.
    fn now_epoch_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_millis() as u64
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn basic_rate_limiting() {
        let mut rl = RateLimiter::new();

        // Allow 2 per hour, 5 per day.
        assert!(rl.check_and_record("dev1", 2, 5).is_ok());
        assert!(rl.check_and_record("dev1", 2, 5).is_ok());
        assert_eq!(
            rl.check_and_record("dev1", 2, 5),
            Err("hourly rate limit exceeded")
        );

        // Different device is independent.
        assert!(rl.check_and_record("dev2", 2, 5).is_ok());
    }

    #[test]
    fn daily_limit() {
        let mut rl = RateLimiter::new();

        for _ in 0..3 {
            assert!(rl.check_and_record("dev1", 100, 3).is_ok());
        }
        assert_eq!(
            rl.check_and_record("dev1", 100, 3),
            Err("daily rate limit exceeded")
        );
    }

    #[test]
    fn persistence_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rate_state.json");
        let path_str = path.to_str().unwrap();

        {
            let mut rl = RateLimiter::new_persistent(path_str);
            rl.check_and_record("dev1", 10, 30).unwrap();
            rl.check_and_record("dev1", 10, 30).unwrap();
            // State should already be flushed (auto-flush).
        }

        // Reload from disk.
        {
            let mut rl = RateLimiter::new_persistent(path_str);
            // The two previous requests should still be counted.
            // Record a third — should succeed since limits are 10/30.
            assert!(rl.check_and_record("dev1", 10, 30).is_ok());
            // Verify internal count.
            let state = rl.devices.get("dev1").unwrap();
            assert_eq!(state.hour_window.len(), 3);
        }
    }

    #[test]
    fn corrupt_file_starts_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rate_state.json");

        // Write garbage.
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"NOT VALID JSON!!!").unwrap();
        }

        let rl = RateLimiter::new_persistent(path.to_str().unwrap());
        assert!(rl.devices.is_empty());
    }

    #[test]
    fn sweep_removes_empty_entries() {
        let mut rl = RateLimiter::new();

        // Manually insert a device with only expired timestamps.
        rl.devices.insert(
            "stale-device".to_owned(),
            DeviceRateState {
                hour_window: vec![0], // epoch 0 is definitely expired
                day_window: vec![0],
            },
        );
        assert_eq!(rl.devices.len(), 1);

        rl.sweep_expired();
        assert!(rl.devices.is_empty());
    }
}
