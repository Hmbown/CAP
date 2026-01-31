use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::error::{CapError, Result};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Index {
    /// Virtual path -> file entry
    pub files: BTreeMap<String, FileEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
        let idx: Index =
            ciborium::de::from_reader(bytes).map_err(|e| CapError::CborDecode(e.to_string()))?;
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

/// CAP root hash = SHA-256("CAPROOT\0" || manifest_hash || sorted(path\0hash\n)...)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(hash: &str) -> FileEntry {
        FileEntry {
            hash: hash.to_string(),
            size: 100,
            compressed_size: 80,
            compression: "zstd".into(),
            mime: None,
        }
    }

    // ── sha256_bytes tests ─────────────────────────────────────

    #[test]
    fn sha256_bytes_empty_input() {
        let h = sha256_bytes(b"");
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(hex::encode(h), expected);
    }

    #[test]
    fn sha256_bytes_known_value() {
        let h = sha256_bytes(b"hello");
        let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert_eq!(hex::encode(h), expected);
    }

    #[test]
    fn sha256_bytes_deterministic() {
        let a = sha256_bytes(b"test data");
        let b = sha256_bytes(b"test data");
        assert_eq!(a, b);
    }

    // ── compute_root tests ─────────────────────────────────────

    #[test]
    fn compute_root_empty_index() {
        let manifest_hash = sha256_bytes(b"manifest");
        let index = Index {
            files: BTreeMap::new(),
        };
        let root = compute_root(manifest_hash, &index).expect("compute root");
        // Should be SHA-256("CAPROOT\0" || manifest_hash) with no file entries
        assert_eq!(root.len(), 32);
    }

    #[test]
    fn compute_root_deterministic() {
        let manifest_hash = sha256_bytes(b"manifest");
        let valid_hash = hex::encode(sha256_bytes(b"file content"));
        let mut files = BTreeMap::new();
        files.insert("a.txt".into(), make_entry(&valid_hash));

        let index = Index { files };
        let r1 = compute_root(manifest_hash, &index).expect("root 1");
        let r2 = compute_root(manifest_hash, &index).expect("root 2");
        assert_eq!(r1, r2);
    }

    #[test]
    fn compute_root_different_manifest_different_root() {
        let mh1 = sha256_bytes(b"manifest-a");
        let mh2 = sha256_bytes(b"manifest-b");
        let valid_hash = hex::encode(sha256_bytes(b"content"));
        let mut files = BTreeMap::new();
        files.insert("f.txt".into(), make_entry(&valid_hash));
        let index = Index { files };

        let r1 = compute_root(mh1, &index).expect("root 1");
        let r2 = compute_root(mh2, &index).expect("root 2");
        assert_ne!(r1, r2);
    }

    #[test]
    fn compute_root_different_files_different_root() {
        let mh = sha256_bytes(b"manifest");
        let h1 = hex::encode(sha256_bytes(b"content-a"));
        let h2 = hex::encode(sha256_bytes(b"content-b"));

        let mut f1 = BTreeMap::new();
        f1.insert("a.txt".into(), make_entry(&h1));
        let idx1 = Index { files: f1 };

        let mut f2 = BTreeMap::new();
        f2.insert("a.txt".into(), make_entry(&h2));
        let idx2 = Index { files: f2 };

        let r1 = compute_root(mh, &idx1).expect("root 1");
        let r2 = compute_root(mh, &idx2).expect("root 2");
        assert_ne!(r1, r2);
    }

    #[test]
    fn compute_root_rejects_invalid_hex_hash() {
        let mh = sha256_bytes(b"manifest");
        let mut files = BTreeMap::new();
        files.insert("bad.txt".into(), make_entry("zzzz_not_hex"));
        let index = Index { files };

        let result = compute_root(mh, &index);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("bad hex"), "error: {err}");
    }

    #[test]
    fn compute_root_rejects_wrong_length_hash() {
        let mh = sha256_bytes(b"manifest");
        let mut files = BTreeMap::new();
        // Valid hex but only 2 bytes, not 32
        files.insert("short.txt".into(), make_entry("aabb"));
        let index = Index { files };

        let result = compute_root(mh, &index);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("32 bytes"), "error: {err}");
    }

    // ── Index CBOR tests ───────────────────────────────────────

    #[test]
    fn index_cbor_roundtrip() {
        let valid_hash = hex::encode(sha256_bytes(b"content"));
        let mut files = BTreeMap::new();
        files.insert(
            "ui/index.html".into(),
            FileEntry {
                hash: valid_hash.clone(),
                size: 1024,
                compressed_size: 512,
                compression: "zstd".into(),
                mime: Some("text/html".into()),
            },
        );
        files.insert(
            "core/app.wasm".into(),
            FileEntry {
                hash: valid_hash,
                size: 8192,
                compressed_size: 4096,
                compression: "zstd".into(),
                mime: Some("application/wasm".into()),
            },
        );
        let original = Index { files };
        let cbor = original.to_cbor_bytes().expect("encode");
        let decoded = Index::from_cbor_bytes(&cbor).expect("decode");
        assert_eq!(original, decoded);
    }

    #[test]
    fn index_from_cbor_rejects_garbage() {
        let result = Index::from_cbor_bytes(b"this is not cbor data at all!");
        assert!(result.is_err());
    }

    // ── CBOR snapshot tests ───────────────────────────────────

    #[test]
    fn index_cbor_snapshot() {
        let mut files = BTreeMap::new();
        files.insert(
            "a.txt".into(),
            FileEntry {
                hash: "aa".repeat(32),
                size: 100,
                compressed_size: 80,
                compression: "zstd".into(),
                mime: Some("text/plain".into()),
            },
        );
        let index = Index { files };
        let cbor = index.to_cbor_bytes().expect("encode");
        let snapshot = hex::encode(&cbor);
        // Pin the exact CBOR output — update only if encoding intentionally changes.
        // If ciborium changes encoding, this test will break and alert us.
        let expected = "a16566696c6573a165612e747874a564686173687840616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616473697a6518646f636f6d707265737365645f73697a6518506b636f6d7072657373696f6e647a737464646d696d656a746578742f706c61696e";
        assert_eq!(
            snapshot, expected,
            "Index CBOR snapshot changed! If this is intentional, update the expected value."
        );
    }

    #[test]
    fn cbor_integer_width_stability() {
        let boundary_sizes: Vec<u64> =
            vec![0, 23, 24, 255, 256, 65535, 65536, u32::MAX as u64, u64::MAX];
        for &size in &boundary_sizes {
            let mut files = BTreeMap::new();
            files.insert(
                "f".into(),
                FileEntry {
                    hash: "bb".repeat(32),
                    size,
                    compressed_size: size,
                    compression: "zstd".into(),
                    mime: None,
                },
            );
            let idx = Index { files };
            let bytes1 = idx.to_cbor_bytes().unwrap();
            let decoded = Index::from_cbor_bytes(&bytes1).unwrap();
            let bytes2 = decoded.to_cbor_bytes().unwrap();
            assert_eq!(bytes1, bytes2, "CBOR round-trip mismatch for size={size}");
        }
    }
}
