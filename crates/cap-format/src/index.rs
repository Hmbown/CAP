use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::error::{CapError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Index {
    /// Virtual path -> file entry
    pub files: BTreeMap<String, FileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// SHA-256 of the *raw* bytes, hex encoded (64 chars)
    pub hash: String,

    pub size: u64,
    pub compressed_size: u64,

    /// Compression name (CAP 1.0 uses "zstd")
    pub compression: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
}

impl Index {
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(self, &mut out)
            .map_err(|e| CapError::CborEncode(e.to_string()))?;
        Ok(out)
    }

    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self> {
        let idx: Index = ciborium::de::from_reader(bytes)
            .map_err(|e| CapError::CborDecode(e.to_string()))?;
        Ok(idx)
    }
}

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// CAP root hash = SHA256("CAPROOT\0" || manifest_hash || sorted(path\0hash\n)...)
pub fn compute_root(manifest_hash: [u8; 32], index: &Index) -> Result<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(b"CAPROOT\0");
    h.update(manifest_hash);

    for (path, entry) in index.files.iter() {
        h.update(path.as_bytes());
        h.update(b"\0");
        let hash_bytes = hex::decode(&entry.hash)
            .map_err(|e| CapError::Invalid(format!("bad hex hash for {path}: {e}")))?;
        if hash_bytes.len() != 32 {
            return Err(CapError::Invalid(format!(
                "hash for {path} must be 32 bytes, got {}",
                hash_bytes.len()
            )));
        }
        h.update(&hash_bytes);
        h.update(b"\n");
    }

    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    Ok(arr)
}
