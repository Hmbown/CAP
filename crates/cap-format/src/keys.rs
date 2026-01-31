use crate::error::{CapError, Result};
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

#[derive(Debug, Serialize, Deserialize)]
struct KeyFile {
    kind: String,
    encoding: String,
    key: String,
}

pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut rng = OsRng;
    let sk = SigningKey::generate(&mut rng);
    let pk = sk.verifying_key();
    (sk, pk)
}

pub fn save_signing_key_json(path: &Path, sk: &SigningKey) -> Result<()> {
    let bytes = sk.to_bytes();
    let f = KeyFile {
        kind: "ed25519".into(),
        encoding: "base64".into(),
        key: B64.encode(bytes),
    };
    let json = serde_json::to_string_pretty(&f)
        .map_err(|e| CapError::Invalid(format!("json encode key: {e}")))?;
    std::fs::write(path, json)?;
    Ok(())
}

pub fn save_verifying_key_json(path: &Path, pk: &VerifyingKey) -> Result<()> {
    let bytes = pk.to_bytes();
    let f = KeyFile {
        kind: "ed25519".into(),
        encoding: "base64".into(),
        key: B64.encode(bytes),
    };
    let json = serde_json::to_string_pretty(&f)
        .map_err(|e| CapError::Invalid(format!("json encode key: {e}")))?;
    std::fs::write(path, json)?;
    Ok(())
}

pub fn load_signing_key_json(path: &Path) -> Result<SigningKey> {
    let s = std::fs::read_to_string(path)?;
    let f: KeyFile =
        serde_json::from_str(&s).map_err(|e| CapError::Invalid(format!("json parse key: {e}")))?;
    if f.kind != "ed25519" || f.encoding != "base64" {
        return Err(CapError::Invalid("unsupported key file format".into()));
    }
    let bytes = B64
        .decode(f.key.as_bytes())
        .map_err(|e| CapError::Invalid(format!("base64 decode key: {e}")))?;
    if bytes.len() != 32 {
        return Err(CapError::Invalid(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&arr))
}

pub fn load_verifying_key_json(path: &Path) -> Result<VerifyingKey> {
    let s = std::fs::read_to_string(path)?;
    let f: KeyFile =
        serde_json::from_str(&s).map_err(|e| CapError::Invalid(format!("json parse key: {e}")))?;
    if f.kind != "ed25519" || f.encoding != "base64" {
        return Err(CapError::Invalid("unsupported key file format".into()));
    }
    let bytes = B64
        .decode(f.key.as_bytes())
        .map_err(|e| CapError::Invalid(format!("base64 decode key: {e}")))?;
    if bytes.len() != 32 {
        return Err(CapError::Invalid(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr).map_err(|e| CapError::Invalid(format!("verifying key: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn generate_keypair_produces_valid_pair() {
        let (sk, pk) = generate_keypair();
        assert_eq!(sk.verifying_key(), pk);
    }

    #[test]
    fn signing_key_save_load_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sk.json");

        let (sk, _pk) = generate_keypair();
        save_signing_key_json(&path, &sk).expect("save sk");
        let loaded = load_signing_key_json(&path).expect("load sk");
        assert_eq!(sk.to_bytes(), loaded.to_bytes());
    }

    #[test]
    fn verifying_key_save_load_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pk.json");

        let (_sk, pk) = generate_keypair();
        save_verifying_key_json(&path, &pk).expect("save pk");
        let loaded = load_verifying_key_json(&path).expect("load pk");
        assert_eq!(pk.to_bytes(), loaded.to_bytes());
    }

    #[test]
    fn full_keypair_save_load_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sk_path = dir.path().join("sk.json");
        let pk_path = dir.path().join("pk.json");

        let (sk, pk) = generate_keypair();
        save_signing_key_json(&sk_path, &sk).expect("save sk");
        save_verifying_key_json(&pk_path, &pk).expect("save pk");

        let loaded_sk = load_signing_key_json(&sk_path).expect("load sk");
        let loaded_pk = load_verifying_key_json(&pk_path).expect("load pk");

        // Derived public key from loaded secret matches loaded public key
        assert_eq!(loaded_sk.verifying_key(), loaded_pk);
    }

    #[test]
    fn key_json_format_is_correct() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sk_path = dir.path().join("sk.json");
        let pk_path = dir.path().join("pk.json");

        let (sk, pk) = generate_keypair();
        save_signing_key_json(&sk_path, &sk).expect("save sk");
        save_verifying_key_json(&pk_path, &pk).expect("save pk");

        let sk_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&sk_path).unwrap()).unwrap();
        assert_eq!(sk_json["kind"], "ed25519");
        assert_eq!(sk_json["encoding"], "base64");
        assert!(sk_json["key"].is_string());

        let pk_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&pk_path).unwrap()).unwrap();
        assert_eq!(pk_json["kind"], "ed25519");
        assert_eq!(pk_json["encoding"], "base64");
        assert!(pk_json["key"].is_string());
    }

    #[test]
    fn load_nonexistent_key_fails() {
        let bad_path = PathBuf::from("/tmp/does-not-exist-cap-test-key.json");
        let result = load_signing_key_json(&bad_path);
        assert!(result.is_err());

        let result = load_verifying_key_json(&bad_path);
        assert!(result.is_err());
    }
}
