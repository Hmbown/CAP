use crate::error::{CapError, Result};
use crate::index::{compute_root, sha256_bytes, FileEntry, Index};
use crate::manifest::Manifest;

use ed25519_dalek::Signer;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use walkdir::WalkDir;

/// Build a `.cap` file from a manifest TOML and the project directory layout.
///
/// CAP 1.0 transport uses ZIP; files are stored as content-addressed Zstd blobs.
pub fn build_cap_from_manifest(
    manifest_path: &Path,
    out_path: &Path,
    signing_key: &SigningKey,
) -> Result<()> {
    let project_root = manifest_path
        .parent()
        .ok_or_else(|| CapError::Invalid("manifest has no parent dir".into()))?;

    let manifest = Manifest::load_toml(manifest_path)?;

    // Collect files to include.
    let mut include_paths: Vec<(String, PathBuf)> = Vec::new();

    // UI: include all files under the directory containing the UI entrypoint.
    let ui_entry_rel = PathBuf::from(&manifest.entrypoints.ui);
    let ui_entry_abs = project_root.join(&ui_entry_rel);
    let ui_root_abs = ui_entry_abs
        .parent()
        .ok_or_else(|| CapError::Invalid("ui entrypoint has no parent".into()))?
        .to_path_buf();

    collect_dir_files(project_root, &ui_root_abs, &mut include_paths)?;

    // Core wasm: include the single wasm file if present.
    if let Some(core_rel) = &manifest.entrypoints.core_wasm {
        let core_abs = project_root.join(core_rel);
        if !core_abs.exists() {
            return Err(CapError::Invalid(format!(
                "core_wasm file not found: {}",
                core_abs.display()
            )));
        }
        let vpath = normalize_virtual_path(&path_relative(project_root, &core_abs)?);
        include_paths.push((vpath, core_abs));
    }

    // Deduplicate by virtual path (last wins).
    let mut by_vpath: BTreeMap<String, PathBuf> = BTreeMap::new();
    for (v, p) in include_paths {
        by_vpath.insert(v, p);
    }

    // Blob store: hash -> compressed bytes.
    let mut blobs: HashMap<String, Vec<u8>> = HashMap::new();
    let mut index_files: BTreeMap<String, FileEntry> = BTreeMap::new();

    for (vpath, abs_path) in by_vpath.iter() {
        let raw = std::fs::read(abs_path)?;
        let hash = sha256_bytes(&raw);
        let hash_hex = hex::encode(hash);

        // compress (once per unique hash)
        if !blobs.contains_key(&hash_hex) {
            let payload = zstd::stream::encode_all(std::io::Cursor::new(&raw), 10)?;
            blobs.insert(hash_hex.clone(), payload);
        }
        let compressed_len = blobs.get(&hash_hex).map(|v| v.len()).unwrap_or(0);

        index_files.insert(
            vpath.clone(),
            FileEntry {
                hash: hash_hex.clone(),
                size: raw.len() as u64,
                compressed_size: compressed_len as u64,
                compression: "zstd".into(),
                mime: mime_guess::from_path(vpath).first().map(|m| m.to_string()),
            },
        );
    }

    let index = Index { files: index_files };

    // Validate that declared entrypoints exist in the built index.
    let ui_vpath = normalize_virtual_path(&ui_entry_rel);
    if !index.files.contains_key(&ui_vpath) {
        return Err(CapError::MissingEntrypoint(format!(
            "UI entrypoint '{}' not found in built index",
            ui_vpath
        )));
    }
    if let Some(core_rel) = &manifest.entrypoints.core_wasm {
        let core_vpath = normalize_virtual_path(&PathBuf::from(core_rel));
        if !index.files.contains_key(&core_vpath) {
            return Err(CapError::MissingEntrypoint(format!(
                "core_wasm entrypoint '{}' not found in built index",
                core_vpath
            )));
        }
    }

    let manifest_cbor = manifest.to_cbor_bytes()?;
    let manifest_hash = sha256_bytes(&manifest_cbor);
    let root = compute_root(manifest_hash, &index)?;

    let sig: Signature = signing_key.sign(&root);
    let pk: VerifyingKey = signing_key.verifying_key();

    // Write ZIP
    let f = File::create(out_path)?;
    let mut zip = ZipWriter::new(f);

    // Store entries uncompressed (we already compress blobs).
    let opts = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .unix_permissions(0o644);

    zip.start_file("_cap/manifest.cbor", opts)?;
    zip.write_all(&manifest_cbor)?;

    let index_cbor = index.to_cbor_bytes()?;
    zip.start_file("_cap/index.cbor", opts)?;
    zip.write_all(&index_cbor)?;

    zip.start_file("_cap/root.sha256", opts)?;
    zip.write_all(hex::encode(root).as_bytes())?;
    zip.write_all(b"\n")?;

    zip.start_file("_cap/signature.ed25519", opts)?;
    zip.write_all(sig.to_bytes().as_slice())?;

    zip.start_file("_cap/publisher.ed25519.pk", opts)?;
    zip.write_all(pk.to_bytes().as_slice())?;

    // Write blobs
    for (hash_hex, payload) in blobs.iter() {
        let name = format!("blobs/{hash_hex}.zst");
        zip.start_file(name, opts)?;
        zip.write_all(payload)?;
    }

    zip.finish()?;
    Ok(())
}

fn collect_dir_files(
    project_root: &Path,
    dir: &Path,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<()> {
    if !dir.exists() {
        return Err(CapError::Invalid(format!(
            "directory not found: {}",
            dir.display()
        )));
    }
    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let p = entry.path();
        if p.is_file() {
            let rel = path_relative(project_root, p)?;
            let vpath = normalize_virtual_path(&rel);
            out.push((vpath, p.to_path_buf()));
        }
    }
    Ok(())
}

fn path_relative(base: &Path, path: &Path) -> Result<PathBuf> {
    path.strip_prefix(base)
        .map(|p| p.to_path_buf())
        .map_err(|_| {
            CapError::Invalid(format!(
                "path {} not under {}",
                path.display(),
                base.display()
            ))
        })
}

fn normalize_virtual_path(p: &Path) -> String {
    // Convert to forward slashes, no leading './'
    p.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// Read-only view of a CAP archive.
pub struct CapReader {
    pub manifest: Manifest,
    pub index: Index,
    pub root: [u8; 32],
    pub signature: [u8; 64],
    pub publisher_pk: Option<VerifyingKey>,
    pub manifest_hash: [u8; 32],
    archive: ZipArchive<File>,
}

impl CapReader {
    pub fn open(path: &Path) -> Result<Self> {
        let f = File::open(path)?;
        let mut archive = ZipArchive::new(f)?;

        let manifest_cbor = read_zip_bytes(&mut archive, "_cap/manifest.cbor")?;
        let manifest = Manifest::from_cbor_bytes(&manifest_cbor)?;
        let manifest_hash = sha256_bytes(&manifest_cbor);

        let index_cbor = read_zip_bytes(&mut archive, "_cap/index.cbor")?;
        let index = Index::from_cbor_bytes(&index_cbor)?;

        // Validate all index paths against path traversal
        for path in index.files.keys() {
            validate_zip_entry_name(path)?;
        }

        let root_hex = String::from_utf8(read_zip_bytes(&mut archive, "_cap/root.sha256")?)
            .map_err(|e| CapError::Invalid(format!("root.sha256 utf8: {e}")))?;
        let root_hex = root_hex.trim();
        let root_vec = hex::decode(root_hex)
            .map_err(|e| CapError::Invalid(format!("root.sha256 hex: {e}")))?;
        if root_vec.len() != 32 {
            return Err(CapError::Invalid("root hash must be 32 bytes".into()));
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&root_vec);

        let sig_bytes = read_zip_bytes(&mut archive, "_cap/signature.ed25519")?;
        if sig_bytes.len() != 64 {
            return Err(CapError::Invalid("signature must be 64 bytes".into()));
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&sig_bytes);

        let publisher_pk = match read_zip_bytes(&mut archive, "_cap/publisher.ed25519.pk") {
            Ok(pk_bytes) => {
                if pk_bytes.len() != 32 {
                    None
                } else {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&pk_bytes);
                    VerifyingKey::from_bytes(&arr).ok()
                }
            }
            Err(_) => None,
        };

        Ok(Self {
            manifest,
            index,
            root,
            signature,
            publisher_pk,
            manifest_hash,
            archive,
        })
    }

    /// Verify signature + (optionally) every blob hash.
    pub fn verify(&mut self, pubkey_override: Option<&VerifyingKey>, full: bool) -> Result<()> {
        // recompute root using the manifest hash as stored in the archive
        let recomputed_root = compute_root(self.manifest_hash, &self.index)?;

        if recomputed_root != self.root {
            return Err(CapError::Invalid("root hash mismatch".into()));
        }

        let pk = pubkey_override
            .or(self.publisher_pk.as_ref())
            .ok_or_else(|| {
                CapError::Invalid("no publisher public key provided or embedded".into())
            })?;

        let sig = Signature::from_bytes(&self.signature);
        pk.verify_strict(&self.root, &sig)
            .map_err(|e| CapError::Signature(e.to_string()))?;

        if full {
            let entries: Vec<(String, String)> = self
                .index
                .files
                .iter()
                .map(|(path, entry)| (path.clone(), entry.hash.clone()))
                .collect();
            for (path, expected_hash) in &entries {
                let raw = self.read_virtual_file(path)?;
                let h = sha256_bytes(&raw);
                let hexh = hex::encode(h);
                if hexh != *expected_hash {
                    return Err(CapError::Invalid(format!(
                        "hash mismatch for {}: expected {}, got {}",
                        path, expected_hash, hexh
                    )));
                }
            }
        }
        Ok(())
    }

    /// Read a virtual file (decompressed raw bytes).
    pub fn read_virtual_file(&mut self, vpath: &str) -> Result<Vec<u8>> {
        validate_zip_entry_name(vpath)?;
        let entry = self
            .index
            .files
            .get(vpath)
            .ok_or_else(|| CapError::Invalid(format!("no such path in index: {vpath}")))?;

        let blob_name = format!("blobs/{}.zst", entry.hash);
        let payload = read_zip_bytes(&mut self.archive, &blob_name)?;
        let raw = zstd::stream::decode_all(std::io::Cursor::new(payload))?;
        Ok(raw)
    }

    /// Convenience: load all files under a prefix into memory.
    pub fn read_prefix(&mut self, prefix: &str) -> Result<BTreeMap<String, Vec<u8>>> {
        let paths: Vec<String> = self
            .index
            .files
            .keys()
            .filter(|p| p.starts_with(prefix))
            .cloned()
            .collect();
        let mut out = BTreeMap::new();
        for path in &paths {
            out.insert(path.clone(), self.read_virtual_file(path)?);
        }
        Ok(out)
    }
}

/// Validate a ZIP entry name against path traversal attacks.
///
/// Rejects names containing null bytes, absolute paths, or `..` components.
pub fn validate_zip_entry_name(name: &str) -> Result<()> {
    if name.contains('\0') {
        return Err(CapError::Invalid(format!(
            "ZIP entry name contains null byte: {:?}",
            name
        )));
    }
    if name.starts_with('/') || name.starts_with('\\') {
        return Err(CapError::Invalid(format!(
            "ZIP entry name is an absolute path: {:?}",
            name
        )));
    }
    // Check for .. traversal — split on both / and \
    for component in name.split(['/', '\\']) {
        if component == ".." {
            return Err(CapError::Invalid(format!(
                "ZIP entry name contains path traversal: {:?}",
                name
            )));
        }
    }
    Ok(())
}

fn read_zip_bytes(archive: &mut ZipArchive<File>, name: &str) -> Result<Vec<u8>> {
    validate_zip_entry_name(name)?;
    let mut f = archive.by_name(name)?;
    let mut buf = Vec::with_capacity(f.size() as usize);
    f.read_to_end(&mut buf)?;
    Ok(buf)
}
