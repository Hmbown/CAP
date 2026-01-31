use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

use crate::error::{CapError, Result};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entrypoints {
    /// Virtual path (e.g. "ui/index.html")
    pub ui: String,

    /// Optional virtual path to a WASM core module (e.g. "core/app.wasm")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_wasm: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkCap {
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FilesystemCap {
    /// List of virtual scopes such as:
    /// - "documents://myapp/*"
    /// - "cache://myapp/*"
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KvStoreCap {
    /// Whether the shell may persist the KV store to disk.
    #[serde(default)]
    pub persistent: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NotificationsCap {
    #[serde(default)]
    pub use_notifications: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CryptoKeystoreCap {
    #[serde(default)]
    pub use_keystore: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NativeAccelCap {
    /// Allowlisted accelerator module identifiers
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DataContract {
    #[serde(default)]
    pub telemetry: TelemetryMode,

    #[serde(default)]
    pub data_export: bool,

    #[serde(default)]
    pub data_delete: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryMode {
    #[default]
    OffByDefault,
    On,
    Off,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Updates {
    pub channel: String,
    #[serde(default)]
    pub rollback: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
        m.validate()?;
        Ok(m)
    }

    /// Validate manifest fields against CAP 1.0 spec requirements.
    pub fn validate(&self) -> Result<()> {
        if self.cap_version != 1 {
            return Err(CapError::Validation(format!(
                "unsupported cap_version: {} (expected 1)",
                self.cap_version
            )));
        }

        if self.app.id.is_empty() {
            return Err(CapError::Validation("app.id must not be empty".into()));
        }

        // app.id: ASCII alphanumerics, hyphens, dots, underscores only
        if !self
            .app
            .id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
        {
            return Err(CapError::Validation(format!(
                "app.id contains invalid characters: '{}' (only ASCII alphanumerics, hyphens, dots, underscores allowed)",
                self.app.id
            )));
        }

        if self.app.name.is_empty() {
            return Err(CapError::Validation("app.name must not be empty".into()));
        }

        if self.app.version.is_empty() {
            return Err(CapError::Validation("app.version must not be empty".into()));
        }

        if self.app.publisher.is_empty() {
            return Err(CapError::Validation(
                "app.publisher must not be empty".into(),
            ));
        }

        if self.entrypoints.ui.is_empty() {
            return Err(CapError::Validation(
                "entrypoints.ui must not be empty".into(),
            ));
        }

        if let Some(ref core) = self.entrypoints.core_wasm {
            if core.is_empty() {
                return Err(CapError::Validation(
                    "entrypoints.core_wasm must not be empty when specified".into(),
                ));
            }
        }

        // Validate filesystem scope formats
        if let Some(ref fs) = self.capabilities.filesystem {
            let valid_types = ["documents", "cache", "temp"];
            for scope in &fs.scopes {
                // Each scope must match: <type>://<id>/<path-or-wildcard>
                let Some((scope_type, rest)) = scope.split_once("://") else {
                    return Err(CapError::Validation(format!(
                        "invalid filesystem scope format (expected <type>://<id>/<path>): '{scope}'"
                    )));
                };
                if !valid_types.contains(&scope_type) {
                    return Err(CapError::Validation(format!(
                        "invalid filesystem scope type '{scope_type}' in '{scope}' (must be one of: {valid_types:?})"
                    )));
                }
                // Must have at least <id>/<something>
                if !rest.contains('/') {
                    return Err(CapError::Validation(format!(
                        "filesystem scope must include app id and path: '{scope}'"
                    )));
                }
            }
        }

        Ok(())
    }

    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(self, &mut out)
            .map_err(|e| CapError::CborEncode(e.to_string()))?;
        Ok(out)
    }

    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self> {
        let m: Manifest =
            ciborium::de::from_reader(bytes).map_err(|e| CapError::CborDecode(e.to_string()))?;
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{FileEntry, Index};
    use std::collections::BTreeMap;

    /// Helper to build a fully-populated Manifest for testing.
    fn make_full_manifest() -> Manifest {
        Manifest {
            cap_version: 1,
            app: App {
                id: "com.test.app".into(),
                name: "Test App".into(),
                version: "1.0.0".into(),
                publisher: "Test Publisher".into(),
                description: Some("A test application".into()),
                homepage: Some("https://example.com".into()),
                min_runtime: Some("cap-runtime>=0.1".into()),
            },
            entrypoints: Entrypoints {
                ui: "ui/index.html".into(),
                core_wasm: Some("core/app.wasm".into()),
            },
            targets: None,
            capabilities: Capabilities {
                network: Some(NetworkCap {
                    allow: vec!["https://api.example.com/*".into()],
                }),
                filesystem: None,
                kv_store: Some(KvStoreCap { persistent: true }),
                notifications: None,
                crypto_keystore: None,
                native_accel: None,
            },
            data_contract: Some(DataContract {
                telemetry: TelemetryMode::Off,
                data_export: true,
                data_delete: true,
            }),
            updates: Some(Updates {
                channel: "stable".into(),
                rollback: true,
            }),
            signing: Some(SigningPolicy {
                required: true,
                publisher_key_id: Some("key-001".into()),
            }),
        }
    }

    #[test]
    fn toml_cbor_roundtrip_from_file() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/hello-cap/Cap.toml");
        let original = Manifest::load_toml(&path).expect("load toml");
        let cbor = original.to_cbor_bytes().expect("to cbor");
        let decoded = Manifest::from_cbor_bytes(&cbor).expect("from cbor");
        assert_eq!(original, decoded);
    }

    #[test]
    fn toml_cbor_roundtrip_programmatic() {
        let original = make_full_manifest();
        let cbor = original.to_cbor_bytes().expect("to cbor");
        let decoded = Manifest::from_cbor_bytes(&cbor).expect("from cbor");
        assert_eq!(original, decoded);
    }

    #[test]
    fn toml_cbor_roundtrip_field_values() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/hello-cap/Cap.toml");
        let original = Manifest::load_toml(&path).expect("load toml");
        let cbor = original.to_cbor_bytes().expect("to cbor");
        let decoded = Manifest::from_cbor_bytes(&cbor).expect("from cbor");

        assert_eq!(decoded.cap_version, 1);
        assert_eq!(decoded.app.id, "com.example.hello-cap");
        assert_eq!(decoded.app.name, "Hello CAP");
        assert_eq!(decoded.app.version, "0.1.0");
        assert_eq!(decoded.entrypoints.ui, "ui/index.html");
        assert_eq!(
            decoded.entrypoints.core_wasm.as_deref(),
            Some("core/hello_cap_core.wasm")
        );
        assert!(decoded.capabilities.kv_store.is_some());
        assert!(decoded.capabilities.kv_store.as_ref().unwrap().persistent);
    }

    #[test]
    fn cbor_encoding_is_deterministic() {
        let m = make_full_manifest();
        let bytes1 = m.to_cbor_bytes().expect("encode 1");
        let bytes2 = m.to_cbor_bytes().expect("encode 2");
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn cbor_roundtrip_produces_identical_bytes() {
        let m = make_full_manifest();
        let bytes1 = m.to_cbor_bytes().expect("encode");
        let decoded = Manifest::from_cbor_bytes(&bytes1).expect("decode");
        let bytes2 = decoded.to_cbor_bytes().expect("re-encode");
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn cbor_determinism_across_constructions() {
        let m1 = make_full_manifest();
        let m2 = make_full_manifest();
        let bytes1 = m1.to_cbor_bytes().expect("encode 1");
        let bytes2 = m2.to_cbor_bytes().expect("encode 2");
        assert_eq!(bytes1, bytes2);
    }

    // ── Validation tests ──────────────────────────────────────────

    #[test]
    fn validate_ok() {
        make_full_manifest().validate().expect("should pass");
    }

    #[test]
    fn validate_bad_cap_version() {
        let mut m = make_full_manifest();
        m.cap_version = 99;
        let err = m.validate().unwrap_err().to_string();
        assert!(err.contains("cap_version"), "error: {err}");
    }

    #[test]
    fn validate_empty_app_id() {
        let mut m = make_full_manifest();
        m.app.id = String::new();
        let err = m.validate().unwrap_err().to_string();
        assert!(err.contains("app.id"), "error: {err}");
    }

    #[test]
    fn validate_invalid_app_id_chars() {
        let mut m = make_full_manifest();
        m.app.id = "com.test app!!".into();
        let err = m.validate().unwrap_err().to_string();
        assert!(err.contains("invalid characters"), "error: {err}");
    }

    #[test]
    fn validate_empty_app_name() {
        let mut m = make_full_manifest();
        m.app.name = String::new();
        let err = m.validate().unwrap_err().to_string();
        assert!(err.contains("app.name"), "error: {err}");
    }

    #[test]
    fn validate_empty_version() {
        let mut m = make_full_manifest();
        m.app.version = String::new();
        let err = m.validate().unwrap_err().to_string();
        assert!(err.contains("app.version"), "error: {err}");
    }

    #[test]
    fn validate_empty_publisher() {
        let mut m = make_full_manifest();
        m.app.publisher = String::new();
        let err = m.validate().unwrap_err().to_string();
        assert!(err.contains("app.publisher"), "error: {err}");
    }

    #[test]
    fn validate_empty_ui_entrypoint() {
        let mut m = make_full_manifest();
        m.entrypoints.ui = String::new();
        let err = m.validate().unwrap_err().to_string();
        assert!(err.contains("entrypoints.ui"), "error: {err}");
    }

    #[test]
    fn validate_empty_core_wasm() {
        let mut m = make_full_manifest();
        m.entrypoints.core_wasm = Some(String::new());
        let err = m.validate().unwrap_err().to_string();
        assert!(err.contains("core_wasm"), "error: {err}");
    }

    #[test]
    fn validate_invalid_filesystem_scope() {
        let mut m = make_full_manifest();
        m.capabilities.filesystem = Some(FilesystemCap {
            scopes: vec!["invalid-scope-no-scheme".into()],
        });
        let err = m.validate().unwrap_err().to_string();
        assert!(err.contains("invalid filesystem scope"), "error: {err}");

        // Invalid scope type
        m.capabilities.filesystem = Some(FilesystemCap {
            scopes: vec!["badtype://app/file".into()],
        });
        let err = m.validate().unwrap_err().to_string();
        assert!(
            err.contains("invalid filesystem scope type"),
            "error: {err}"
        );

        // Missing path component
        m.capabilities.filesystem = Some(FilesystemCap {
            scopes: vec!["documents://apponly".into()],
        });
        let err = m.validate().unwrap_err().to_string();
        assert!(err.contains("must include app id"), "error: {err}");

        // Valid scope should pass
        m.capabilities.filesystem = Some(FilesystemCap {
            scopes: vec!["documents://app/*".into()],
        });
        m.validate().expect("valid scope should pass");
    }

    // ── CBOR snapshot tests ──────────────────────────────────────

    #[test]
    fn manifest_cbor_snapshot() {
        let m = Manifest {
            cap_version: 1,
            app: App {
                id: "com.test.snapshot".into(),
                name: "Snapshot".into(),
                version: "1.0.0".into(),
                publisher: "Test".into(),
                description: None,
                homepage: None,
                min_runtime: None,
            },
            entrypoints: Entrypoints {
                ui: "ui/index.html".into(),
                core_wasm: None,
            },
            targets: None,
            capabilities: Capabilities::default(),
            data_contract: None,
            updates: None,
            signing: None,
        };
        let cbor = m.to_cbor_bytes().expect("encode");
        let snapshot = hex::encode(&cbor);
        // Pin the exact CBOR output — update only if encoding intentionally changes.
        // If ciborium changes encoding, this test will break and alert us.
        let expected = "a46b6361705f76657273696f6e0163617070a462696471636f6d2e746573742e736e617073686f74646e616d6568536e617073686f746776657273696f6e65312e302e30697075626c697368657264546573746b656e747279706f696e7473a16275696d75692f696e6465782e68746d6c6c6361706162696c6974696573a0";
        assert_eq!(
            snapshot, expected,
            "Manifest CBOR snapshot changed! If this is intentional, update the expected value."
        );
    }

    #[test]
    fn manifest_optional_field_encoding_stability() {
        // Manifest with all optional fields None
        let m_none = Manifest {
            cap_version: 1,
            app: App {
                id: "com.test.opts".into(),
                name: "Opts".into(),
                version: "1.0.0".into(),
                publisher: "Test".into(),
                description: None,
                homepage: None,
                min_runtime: None,
            },
            entrypoints: Entrypoints {
                ui: "ui/index.html".into(),
                core_wasm: None,
            },
            targets: None,
            capabilities: Capabilities::default(),
            data_contract: None,
            updates: None,
            signing: None,
        };

        // Manifest with all optional fields Some
        let m_some = Manifest {
            cap_version: 1,
            app: App {
                id: "com.test.opts".into(),
                name: "Opts".into(),
                version: "1.0.0".into(),
                publisher: "Test".into(),
                description: Some("desc".into()),
                homepage: Some("https://example.com".into()),
                min_runtime: Some("cap-runtime>=0.1".into()),
            },
            entrypoints: Entrypoints {
                ui: "ui/index.html".into(),
                core_wasm: Some("core/app.wasm".into()),
            },
            targets: None,
            capabilities: Capabilities::default(),
            data_contract: None,
            updates: None,
            signing: None,
        };

        // Both should roundtrip stably
        let bytes_none_1 = m_none.to_cbor_bytes().unwrap();
        let decoded_none = Manifest::from_cbor_bytes(&bytes_none_1).unwrap();
        let bytes_none_2 = decoded_none.to_cbor_bytes().unwrap();
        assert_eq!(
            bytes_none_1, bytes_none_2,
            "None optional fields roundtrip mismatch"
        );

        let bytes_some_1 = m_some.to_cbor_bytes().unwrap();
        let decoded_some = Manifest::from_cbor_bytes(&bytes_some_1).unwrap();
        let bytes_some_2 = decoded_some.to_cbor_bytes().unwrap();
        assert_eq!(
            bytes_some_1, bytes_some_2,
            "Some optional fields roundtrip mismatch"
        );

        // And they should differ (optional fields affect encoding)
        assert_ne!(
            bytes_none_1, bytes_some_1,
            "None vs Some should produce different CBOR"
        );
    }

    #[test]
    fn index_cbor_determinism_insertion_order() {
        let entry_a = FileEntry {
            hash: "aa".repeat(32),
            size: 100,
            compressed_size: 80,
            compression: "zstd".into(),
            mime: Some("text/html".into()),
        };
        let entry_b = FileEntry {
            hash: "bb".repeat(32),
            size: 200,
            compressed_size: 150,
            compression: "zstd".into(),
            mime: Some("application/wasm".into()),
        };

        // Insert in order a, b
        let mut files1 = BTreeMap::new();
        files1.insert("a/file.html".into(), entry_a.clone());
        files1.insert("b/file.wasm".into(), entry_b.clone());
        let idx1 = Index { files: files1 };

        // Insert in order b, a
        let mut files2 = BTreeMap::new();
        files2.insert("b/file.wasm".into(), entry_b);
        files2.insert("a/file.html".into(), entry_a);
        let idx2 = Index { files: files2 };

        let bytes1 = idx1.to_cbor_bytes().expect("encode 1");
        let bytes2 = idx2.to_cbor_bytes().expect("encode 2");
        assert_eq!(bytes1, bytes2);
    }
}
