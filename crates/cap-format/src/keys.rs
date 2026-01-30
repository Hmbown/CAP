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
    let f: KeyFile = serde_json::from_str(&s)
        .map_err(|e| CapError::Invalid(format!("json parse key: {e}")))?;
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
    let f: KeyFile = serde_json::from_str(&s)
        .map_err(|e| CapError::Invalid(format!("json parse key: {e}")))?;
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
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| CapError::Invalid(format!("verifying key: {e}")))
}
