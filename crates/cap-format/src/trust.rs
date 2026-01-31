use crate::error::{CapError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq)]
pub enum TrustResult {
    FirstUse,
    Trusted,
    Mismatch { expected: String, got: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedKey {
    pub pubkey_hex: String,
    pub first_seen: String,
    pub last_seen: String,
}

pub struct TrustStore {
    store_path: PathBuf,
    pins: HashMap<String, PinnedKey>,
}

impl TrustStore {
    /// Open the default trust store at `~/.config/cap-runtime/known_publishers.json`.
    pub fn open() -> Result<Self> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| CapError::Invalid("cannot determine config directory".into()))?;
        let store_path = config_dir.join("cap-runtime").join("known_publishers.json");
        Self::open_at(store_path)
    }

    /// Open a trust store at a specific path (useful for testing).
    pub fn open_at(store_path: PathBuf) -> Result<Self> {
        let pins = if store_path.exists() {
            let bytes = std::fs::read(&store_path)?;
            serde_json::from_slice(&bytes)
                .map_err(|e| CapError::Invalid(format!("trust store parse error: {e}")))?
        } else {
            HashMap::new()
        };
        Ok(Self { store_path, pins })
    }

    /// Check whether a public key is trusted for a given app ID.
    pub fn check(&mut self, app_id: &str, pubkey_hex: &str) -> TrustResult {
        match self.pins.get(app_id) {
            None => {
                self.pin(app_id, pubkey_hex);
                TrustResult::FirstUse
            }
            Some(pinned) => {
                if pinned.pubkey_hex == pubkey_hex {
                    // Update last_seen
                    if let Some(entry) = self.pins.get_mut(app_id) {
                        entry.last_seen = now_iso8601();
                    }
                    TrustResult::Trusted
                } else {
                    TrustResult::Mismatch {
                        expected: pinned.pubkey_hex.clone(),
                        got: pubkey_hex.to_string(),
                    }
                }
            }
        }
    }

    /// Pin a public key for an app ID.
    pub fn pin(&mut self, app_id: &str, pubkey_hex: &str) {
        let now = now_iso8601();
        self.pins.insert(
            app_id.to_string(),
            PinnedKey {
                pubkey_hex: pubkey_hex.to_string(),
                first_seen: now.clone(),
                last_seen: now,
            },
        );
    }

    /// Remove a pinned key for an app ID.
    pub fn unpin(&mut self, app_id: &str) {
        self.pins.remove(app_id);
    }

    /// List all pinned keys.
    pub fn list(&self) -> &HashMap<String, PinnedKey> {
        &self.pins
    }

    /// Save the trust store to disk.
    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.store_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.pins)
            .map_err(|e| CapError::Invalid(format!("trust store serialize: {e}")))?;
        let tmp_path = self.store_path.with_extension("json.tmp");
        std::fs::write(&tmp_path, &json)?;
        std::fs::rename(&tmp_path, &self.store_path)?;
        Ok(())
    }
}

fn now_iso8601() -> String {
    // Use a simple system time approach without external chrono dependency
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}Z", dur.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_store_first_use() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("trust.json");
        let mut store = TrustStore::open_at(path).expect("open");

        let result = store.check("com.test.app", "aabbccdd");
        assert_eq!(result, TrustResult::FirstUse);

        // Second call with same key should return Trusted
        let result = store.check("com.test.app", "aabbccdd");
        assert_eq!(result, TrustResult::Trusted);
    }

    #[test]
    fn trust_store_mismatch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("trust.json");
        let mut store = TrustStore::open_at(path).expect("open");

        store.check("com.test.app", "aabbccdd");

        let result = store.check("com.test.app", "eeff0011");
        assert_eq!(
            result,
            TrustResult::Mismatch {
                expected: "aabbccdd".into(),
                got: "eeff0011".into()
            }
        );
    }

    #[test]
    fn trust_store_unpin() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("trust.json");
        let mut store = TrustStore::open_at(path).expect("open");

        store.check("com.test.app", "aabbccdd");
        assert_eq!(store.list().len(), 1);

        store.unpin("com.test.app");
        assert_eq!(store.list().len(), 0);

        // Should be FirstUse again
        let result = store.check("com.test.app", "aabbccdd");
        assert_eq!(result, TrustResult::FirstUse);
    }

    #[test]
    fn trust_store_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("trust.json");

        {
            let mut store = TrustStore::open_at(path.clone()).expect("open");
            store.check("com.test.app1", "key1");
            store.check("com.test.app2", "key2");
            store.save().expect("save");
        }

        // Reload from disk
        let store2 = TrustStore::open_at(path).expect("reload");
        assert_eq!(store2.list().len(), 2);
        assert_eq!(store2.list()["com.test.app1"].pubkey_hex, "key1");
        assert_eq!(store2.list()["com.test.app2"].pubkey_hex, "key2");
    }
}
