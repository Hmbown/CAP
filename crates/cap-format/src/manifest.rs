use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

use crate::error::{CapError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub cap_version: u32,
    pub app: App,
    pub entrypoints: Entrypoints,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub targets: Option<Targets>,

    #[serde(default)]
    pub capabilities: Capabilities,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_contract: Option<DataContract>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updates: Option<Updates>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing: Option<SigningPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct App {
    pub id: String,
    pub name: String,
    pub version: String,
    pub publisher: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_runtime: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entrypoints {
    /// Virtual path (e.g. "ui/index.html")
    pub ui: String,

    /// Optional virtual path to a WASM core module (e.g. "core/app.wasm")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_wasm: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Targets {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desktop: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub android: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ios: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harmony: Option<BTreeMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capabilities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkCap>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<FilesystemCap>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kv_store: Option<KvStoreCap>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notifications: Option<NotificationsCap>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crypto_keystore: Option<CryptoKeystoreCap>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_accel: Option<NativeAccelCap>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCap {
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemCap {
    /// List of virtual scopes such as:
    /// - "documents://myapp/*"
    /// - "cache://myapp/*"
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvStoreCap {
    /// Whether the shell may persist the KV store to disk.
    #[serde(default)]
    pub persistent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationsCap {
    #[serde(default)]
    pub use_notifications: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoKeystoreCap {
    #[serde(default)]
    pub use_keystore: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeAccelCap {
    /// Allowlisted accelerator module identifiers
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataContract {
    #[serde(default)]
    pub telemetry: TelemetryMode,

    #[serde(default)]
    pub data_export: bool,

    #[serde(default)]
    pub data_delete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryMode {
    OffByDefault,
    On,
    Off,
}

impl Default for TelemetryMode {
    fn default() -> Self {
        TelemetryMode::OffByDefault
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Updates {
    pub channel: String,
    #[serde(default)]
    pub rollback: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningPolicy {
    #[serde(default)]
    pub required: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher_key_id: Option<String>,
}

impl Manifest {
    pub fn load_toml(path: &Path) -> Result<Self> {
        let s = std::fs::read_to_string(path)?;
        let m: Manifest = toml::from_str(&s)?;
        Ok(m)
    }

    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(self, &mut out)
            .map_err(|e| CapError::CborEncode(e.to_string()))?;
        Ok(out)
    }

    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self> {
        let m: Manifest = ciborium::de::from_reader(bytes)
            .map_err(|e| CapError::CborDecode(e.to_string()))?;
        Ok(m)
    }
}
