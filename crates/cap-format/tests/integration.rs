use std::io::{Read, Write};
use std::path::Path;

use cap_format::keys::{generate_keypair, save_signing_key_json, save_verifying_key_json};
use cap_format::package::{build_cap_from_manifest, validate_zip_entry_name, CapReader};
use tempfile::TempDir;

/// Path to the hello-cap example manifest.
fn hello_cap_manifest() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/hello-cap/Cap.toml")
}

/// Build the hello-cap example into a temporary .cap file, returning (tempdir, cap_path, pk).
fn build_hello_cap() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    ed25519_dalek::VerifyingKey,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let cap_path = dir.path().join("hello-cap.cap");
    let sk_path = dir.path().join("sk.json");
    let pk_path = dir.path().join("pk.json");

    let (sk, pk) = generate_keypair();
    save_signing_key_json(&sk_path, &sk).expect("save sk");
    save_verifying_key_json(&pk_path, &pk).expect("save pk");

    build_cap_from_manifest(&hello_cap_manifest(), &cap_path, &sk).expect("build cap");
    (dir, cap_path, pk)
}

// ── Build & verify tests ──────────────────────────────────────────

#[test]
fn build_and_verify_signature_only() {
    let (_dir, cap_path, pk) = build_hello_cap();
    let mut reader = CapReader::open(&cap_path).expect("open cap");
    reader
        .verify(Some(&pk), false)
        .expect("signature-only verification");
}

#[test]
fn build_and_verify_with_embedded_key() {
    let (_dir, cap_path, _pk) = build_hello_cap();
    let mut reader = CapReader::open(&cap_path).expect("open cap");
    reader
        .verify(None, false)
        .expect("verify with embedded key");
}

#[test]
fn build_and_verify_full() {
    let (_dir, cap_path, pk) = build_hello_cap();
    let mut reader = CapReader::open(&cap_path).expect("open cap");
    reader.verify(Some(&pk), true).expect("full verification");
}

#[test]
fn built_cap_has_correct_manifest() {
    let (_dir, cap_path, _pk) = build_hello_cap();
    let reader = CapReader::open(&cap_path).expect("open cap");

    assert_eq!(reader.manifest.cap_version, 1);
    assert_eq!(reader.manifest.app.id, "com.example.hello-cap");
    assert_eq!(reader.manifest.app.name, "Hello CAP");
    assert_eq!(reader.manifest.app.version, "0.1.0");
    assert_eq!(reader.manifest.entrypoints.ui, "ui/index.html");
    assert_eq!(
        reader.manifest.entrypoints.core_wasm.as_deref(),
        Some("core/hello_cap_core.wasm")
    );
}

#[test]
fn built_cap_has_expected_files() {
    let (_dir, cap_path, _pk) = build_hello_cap();
    let reader = CapReader::open(&cap_path).expect("open cap");

    let paths: Vec<&str> = reader.index.files.keys().map(|s| s.as_str()).collect();
    assert!(paths.contains(&"ui/index.html"), "missing ui/index.html");
    assert!(paths.contains(&"ui/app.js"), "missing ui/app.js");
    assert!(
        paths.contains(&"ui/wasm_glue.js"),
        "missing ui/wasm_glue.js"
    );
    assert!(
        paths.contains(&"core/hello_cap_core.wasm"),
        "missing core/hello_cap_core.wasm"
    );
}

#[test]
fn can_read_virtual_files() {
    let (_dir, cap_path, _pk) = build_hello_cap();
    let mut reader = CapReader::open(&cap_path).expect("open cap");

    let html = reader
        .read_virtual_file("ui/index.html")
        .expect("read html");
    assert!(!html.is_empty(), "index.html should be non-empty");
    let html_str = String::from_utf8_lossy(&html);
    assert!(
        html_str.contains("<html") || html_str.contains("<!DOCTYPE") || html_str.contains("<HTML"),
        "expected HTML content"
    );
}

// ── Tamper detection tests ────────────────────────────────────────

/// Read a .cap ZIP, flip the first byte of the first `blobs/*` entry, rewrite to a new file.
fn tamper_first_blob(src: &Path, dst: &Path) {
    let src_file = std::fs::File::open(src).expect("open src");
    let mut archive = zip::ZipArchive::new(src_file).expect("zip archive");

    let dst_file = std::fs::File::create(dst).expect("create dst");
    let mut writer = zip::ZipWriter::new(dst_file);

    let opts =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    // Find the first blobs/* entry name
    let blob_name: Option<String> = (0..archive.len()).find_map(|i| {
        let entry = archive.by_index(i).ok()?;
        let name = entry.name().to_string();
        if name.starts_with("blobs/") {
            Some(name)
        } else {
            None
        }
    });
    let blob_name = blob_name.expect("cap should have at least one blob");

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).expect("entry");
        let name = entry.name().to_string();
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).expect("read entry");

        writer.start_file(&name, opts).expect("start file");
        if name == blob_name && !buf.is_empty() {
            buf[0] ^= 0xff; // flip first byte
        }
        writer.write_all(&buf).expect("write entry");
    }
    writer.finish().expect("finish zip");
}

#[test]
fn tampered_blob_fails_full_verification() {
    let (dir, cap_path, pk) = build_hello_cap();
    let tampered_path = dir.path().join("tampered.cap");
    tamper_first_blob(&cap_path, &tampered_path);

    let mut reader = CapReader::open(&tampered_path).expect("open tampered cap");
    let result = reader.verify(Some(&pk), true);
    // Tampering a compressed blob may cause a decompression error or a hash mismatch —
    // either way, full verification must fail.
    assert!(result.is_err(), "full verify should fail on tampered blob");
}

#[test]
fn tampered_blob_passes_signature_only() {
    let (dir, cap_path, pk) = build_hello_cap();
    let tampered_path = dir.path().join("tampered.cap");
    tamper_first_blob(&cap_path, &tampered_path);

    let mut reader = CapReader::open(&tampered_path).expect("open tampered cap");
    // Signature-only check doesn't inspect blobs, so it should pass
    reader
        .verify(Some(&pk), false)
        .expect("signature-only verify should pass on tampered blob");
}

#[test]
fn wrong_key_fails_verification() {
    let (_dir, cap_path, _pk) = build_hello_cap();
    // Generate a completely different keypair
    let (_sk2, pk2) = generate_keypair();

    let mut reader = CapReader::open(&cap_path).expect("open cap");
    let result = reader.verify(Some(&pk2), false);
    assert!(result.is_err(), "verification with wrong key should fail");
}

// ── MIME and entrypoint validation tests ──────────────────────

#[test]
fn build_populates_mime_types() {
    let (_dir, cap_path, _pk) = build_hello_cap();
    let reader = CapReader::open(&cap_path).expect("open cap");

    let html_entry = reader
        .index
        .files
        .get("ui/index.html")
        .expect("ui/index.html in index");
    assert_eq!(html_entry.mime.as_deref(), Some("text/html"));

    let wasm_entry = reader
        .index
        .files
        .get("core/hello_cap_core.wasm")
        .expect("core/hello_cap_core.wasm in index");
    assert_eq!(wasm_entry.mime.as_deref(), Some("application/wasm"));
}

#[test]
fn build_missing_ui_entrypoint_fails() {
    let dir = TempDir::new().expect("tempdir");
    let project = dir.path().join("myapp");
    std::fs::create_dir_all(project.join("ui")).expect("mkdir ui");

    // Write a Cap.toml referencing ui/index.html, but don't create the file.
    let cap_toml = r#"
cap_version = 1

[app]
id = "com.test.missing-ui"
name = "Missing UI"
version = "0.1.0"
publisher = "Test"

[entrypoints]
ui = "ui/index.html"
"#;
    std::fs::write(project.join("Cap.toml"), cap_toml).expect("write Cap.toml");

    let (sk, _pk) = generate_keypair();
    let out_path = dir.path().join("out.cap");

    let result = build_cap_from_manifest(&project.join("Cap.toml"), &out_path, &sk);
    assert!(
        result.is_err(),
        "should fail when UI entrypoint file is missing"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("not found") || err.contains("entrypoint") || err.contains("directory"),
        "unexpected error: {err}"
    );
}

#[test]
fn build_missing_core_wasm_file_fails() {
    let dir = TempDir::new().expect("tempdir");
    let project = dir.path().join("myapp");
    std::fs::create_dir_all(project.join("ui")).expect("mkdir ui");

    // Write a valid ui/index.html
    std::fs::write(project.join("ui/index.html"), "<html></html>").expect("write html");

    // Cap.toml references a core wasm that doesn't exist.
    let cap_toml = r#"
cap_version = 1

[app]
id = "com.test.missing-core"
name = "Missing Core"
version = "0.1.0"
publisher = "Test"

[entrypoints]
ui = "ui/index.html"
core_wasm = "core/app.wasm"
"#;
    std::fs::write(project.join("Cap.toml"), cap_toml).expect("write Cap.toml");

    let (sk, _pk) = generate_keypair();
    let out_path = dir.path().join("out.cap");

    let result = build_cap_from_manifest(&project.join("Cap.toml"), &out_path, &sk);
    assert!(
        result.is_err(),
        "should fail when core_wasm file is missing"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("not found") || err.contains("core_wasm"),
        "unexpected error: {err}"
    );
}

// ── read_prefix and read_virtual_file error tests ─────────────

#[test]
fn read_prefix_returns_matching_files() {
    let (_dir, cap_path, _pk) = build_hello_cap();
    let mut reader = CapReader::open(&cap_path).expect("open cap");

    let ui_files = reader.read_prefix("ui/").expect("read_prefix ui/");
    let keys: Vec<&String> = ui_files.keys().collect();
    assert!(keys.iter().any(|k| k.as_str() == "ui/index.html"));
    assert!(keys.iter().any(|k| k.as_str() == "ui/app.js"));
    // core/ files should NOT appear
    assert!(!keys.iter().any(|k| k.starts_with("core/")));
}

#[test]
fn read_prefix_empty_for_unknown() {
    let (_dir, cap_path, _pk) = build_hello_cap();
    let mut reader = CapReader::open(&cap_path).expect("open cap");

    let result = reader.read_prefix("nonexistent/").expect("read_prefix");
    assert!(result.is_empty(), "should be empty for unknown prefix");
}

#[test]
fn read_prefix_core_files() {
    let (_dir, cap_path, _pk) = build_hello_cap();
    let mut reader = CapReader::open(&cap_path).expect("open cap");

    let core_files = reader.read_prefix("core/").expect("read_prefix core/");
    assert_eq!(core_files.len(), 1, "should have exactly 1 core file");
    assert!(core_files.contains_key("core/hello_cap_core.wasm"));
}

#[test]
fn read_virtual_file_nonexistent_fails() {
    let (_dir, cap_path, _pk) = build_hello_cap();
    let mut reader = CapReader::open(&cap_path).expect("open cap");

    let result = reader.read_virtual_file("does/not/exist.txt");
    assert!(result.is_err(), "should fail for nonexistent virtual path");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("no such path"), "unexpected error: {err}");
}

// ── Tampered manifest test ────────────────────────────────────

/// Replace `_cap/manifest.cbor` with flipped bytes, rewrite to new file.
fn tamper_manifest(src: &Path, dst: &Path) {
    let src_file = std::fs::File::open(src).expect("open src");
    let mut archive = zip::ZipArchive::new(src_file).expect("zip archive");

    let dst_file = std::fs::File::create(dst).expect("create dst");
    let mut writer = zip::ZipWriter::new(dst_file);

    let opts =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).expect("entry");
        let name = entry.name().to_string();
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).expect("read entry");

        writer.start_file(&name, opts).expect("start file");
        if name == "_cap/manifest.cbor" && !buf.is_empty() {
            buf[0] ^= 0xff; // flip first byte
        }
        writer.write_all(&buf).expect("write entry");
    }
    writer.finish().expect("finish zip");
}

#[test]
fn tampered_manifest_fails_verification() {
    let (dir, cap_path, pk) = build_hello_cap();
    let tampered_path = dir.path().join("tampered-manifest.cap");
    tamper_manifest(&cap_path, &tampered_path);

    // The tampered manifest may fail at open (CBOR decode) or at verify (root hash mismatch).
    let result = CapReader::open(&tampered_path).and_then(|mut r| {
        r.verify(Some(&pk), false)?;
        Ok(())
    });
    assert!(
        result.is_err(),
        "verification should fail on tampered manifest"
    );
}

// ── ZIP entry path traversal tests ────────────────────────────

#[test]
fn validate_zip_entry_rejects_parent_traversal() {
    assert!(validate_zip_entry_name("../etc/passwd").is_err());
    assert!(validate_zip_entry_name("foo/../../etc").is_err());
    assert!(validate_zip_entry_name("foo\\..\\bar").is_err());
}

#[test]
fn validate_zip_entry_rejects_absolute_paths() {
    assert!(validate_zip_entry_name("/etc/passwd").is_err());
    assert!(validate_zip_entry_name("\\Windows\\System32").is_err());
}

#[test]
fn validate_zip_entry_rejects_null_bytes() {
    assert!(validate_zip_entry_name("foo\0bar").is_err());
}

#[test]
fn validate_zip_entry_allows_normal_paths() {
    assert!(validate_zip_entry_name("_cap/manifest.cbor").is_ok());
    assert!(validate_zip_entry_name("blobs/abc.zst").is_ok());
    assert!(validate_zip_entry_name("ui/index.html").is_ok());
    assert!(validate_zip_entry_name("core/hello_cap_core.wasm").is_ok());
}
