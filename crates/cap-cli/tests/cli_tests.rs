use assert_cmd::Command;
use predicates::prelude::*;
use std::path::Path;
use tempfile::TempDir;

fn cap_cmd() -> Command {
    #[allow(deprecated)]
    Command::cargo_bin("cap").expect("binary exists")
}

/// Generate test keys in a temp directory, return (dir, sk_path, pk_path).
fn generate_test_keys() -> (TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let keys_dir = dir.path().join("keys");

    cap_cmd()
        .args(["keys", "generate", "--out"])
        .arg(&keys_dir)
        .assert()
        .success();

    let sk = keys_dir.join("publisher.ed25519.sk.json");
    let pk = keys_dir.join("publisher.ed25519.pk.json");
    (dir, sk, pk)
}

/// Build the hello-cap example, return (dir, cap_path, sk_path, pk_path).
fn build_hello_cap() -> (
    TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let (dir, sk, pk) = generate_test_keys();
    let cap_path = dir.path().join("hello-cap.cap");

    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/hello-cap/Cap.toml");

    cap_cmd()
        .args(["build", "--manifest"])
        .arg(&manifest)
        .arg("--key")
        .arg(&sk)
        .arg("--out")
        .arg(&cap_path)
        .assert()
        .success();

    (dir, cap_path, sk, pk)
}

// ── Keys tests ────────────────────────────────────────────────

#[test]
fn keys_generate_creates_files() {
    let dir = TempDir::new().expect("tempdir");
    let keys_dir = dir.path().join("keys");

    cap_cmd()
        .args(["keys", "generate", "--out"])
        .arg(&keys_dir)
        .assert()
        .success()
        .stdout(predicate::str::contains("Wrote"));

    assert!(keys_dir.join("publisher.ed25519.sk.json").exists());
    assert!(keys_dir.join("publisher.ed25519.pk.json").exists());
}

#[test]
fn keys_generate_refuses_overwrite() {
    let dir = TempDir::new().expect("tempdir");
    let keys_dir = dir.path().join("keys");

    // First generation
    cap_cmd()
        .args(["keys", "generate", "--out"])
        .arg(&keys_dir)
        .assert()
        .success();

    // Second run without --force should fail
    cap_cmd()
        .args(["keys", "generate", "--out"])
        .arg(&keys_dir)
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exist"));
}

#[test]
fn keys_generate_force_overwrites() {
    let dir = TempDir::new().expect("tempdir");
    let keys_dir = dir.path().join("keys");

    // First generation
    cap_cmd()
        .args(["keys", "generate", "--out"])
        .arg(&keys_dir)
        .assert()
        .success();

    // Force overwrite
    cap_cmd()
        .args(["keys", "generate", "--out"])
        .arg(&keys_dir)
        .arg("--force")
        .assert()
        .success();
}

// ── Build tests ───────────────────────────────────────────────

#[test]
fn build_produces_cap_file() {
    let (_dir, cap_path, _sk, _pk) = build_hello_cap();
    assert!(cap_path.exists());
    assert!(
        std::fs::metadata(&cap_path).unwrap().len() > 0,
        ".cap file should be non-empty"
    );
}

// ── Inspect tests ─────────────────────────────────────────────

#[test]
fn inspect_shows_manifest_info() {
    let (_dir, cap_path, _sk, _pk) = build_hello_cap();

    cap_cmd()
        .args(["inspect"])
        .arg(&cap_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("com.example.hello-cap"))
        .stdout(predicate::str::contains("Hello CAP"))
        .stdout(predicate::str::contains("Files"));
}

// ── Verify tests ──────────────────────────────────────────────

#[test]
fn verify_signature_only_succeeds() {
    let (_dir, cap_path, _sk, pk) = build_hello_cap();

    cap_cmd()
        .args(["verify"])
        .arg(&cap_path)
        .arg("--pubkey")
        .arg(&pk)
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));
}

#[test]
fn verify_full_succeeds() {
    let (_dir, cap_path, _sk, pk) = build_hello_cap();

    cap_cmd()
        .args(["verify"])
        .arg(&cap_path)
        .arg("--pubkey")
        .arg(&pk)
        .arg("--full")
        .assert()
        .success()
        .stdout(predicate::str::contains("full"));
}

#[test]
fn verify_with_embedded_key() {
    let (_dir, cap_path, _sk, _pk) = build_hello_cap();

    cap_cmd()
        .args(["verify"])
        .arg(&cap_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));
}

// ── Extract tests ─────────────────────────────────────────────

#[test]
fn extract_produces_files() {
    let (_dir, cap_path, _sk, _pk) = build_hello_cap();
    let out_dir = _dir.path().join("extracted");

    cap_cmd()
        .args(["extract"])
        .arg(&cap_path)
        .arg("--out")
        .arg(&out_dir)
        .assert()
        .success()
        .stdout(predicate::str::contains("Extracted"));

    assert!(out_dir.join("ui/index.html").exists());
    assert!(out_dir.join("ui/app.js").exists());
    assert!(out_dir.join("core/hello_cap_core.wasm").exists());
    assert!(out_dir.join("_cap/manifest.toml").exists());
    assert!(out_dir.join("_cap/root.sha256").exists());
}

// ── Init tests ────────────────────────────────────────────────

#[test]
fn init_scaffolds_project() {
    let dir = TempDir::new().expect("tempdir");

    cap_cmd()
        .args(["init", "myapp", "--dir"])
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("Created"));

    let project = dir.path().join("myapp");
    assert!(project.join("Cap.toml").exists());
    assert!(project.join("ui/index.html").exists());

    let toml_content = std::fs::read_to_string(project.join("Cap.toml")).expect("read Cap.toml");
    assert!(toml_content.contains("com.example.myapp"));
}

#[test]
fn init_refuses_existing_directory() {
    let dir = TempDir::new().expect("tempdir");
    let project = dir.path().join("myapp");
    std::fs::create_dir_all(&project).expect("pre-create dir");

    cap_cmd()
        .args(["init", "myapp", "--dir"])
        .arg(dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

// ── Lint tests ────────────────────────────────────────────────

#[test]
fn lint_valid_manifest_passes() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/hello-cap/Cap.toml");

    cap_cmd()
        .args(["lint"])
        .arg(&manifest)
        .assert()
        .success()
        .stdout(predicate::str::contains("Lint: OK"));
}

#[test]
fn lint_invalid_manifest_fails() {
    let dir = TempDir::new().expect("tempdir");
    let manifest = dir.path().join("Cap.toml");
    std::fs::write(&manifest, "this is not valid toml {{{{").expect("write garbage");

    cap_cmd()
        .args(["lint"])
        .arg(&manifest)
        .assert()
        .failure()
        .stdout(predicate::str::contains("ERROR"));
}

#[test]
fn lint_missing_entrypoint_file_errors() {
    let dir = TempDir::new().expect("tempdir");
    let manifest = dir.path().join("Cap.toml");
    let cap_toml = r#"
cap_version = 1

[app]
id = "com.test.lint"
name = "Lint Test"
version = "0.1.0"
publisher = "Test"

[entrypoints]
ui = "ui/index.html"
"#;
    std::fs::write(&manifest, cap_toml).expect("write Cap.toml");

    cap_cmd()
        .args(["lint"])
        .arg(&manifest)
        .assert()
        .failure()
        .stdout(predicate::str::contains("ERROR"));
}

#[test]
fn lint_warns_on_missing_description() {
    let dir = TempDir::new().expect("tempdir");
    let manifest = dir.path().join("Cap.toml");
    std::fs::create_dir_all(dir.path().join("ui")).expect("mkdir ui");
    std::fs::write(dir.path().join("ui/index.html"), "<html></html>").expect("write html");

    let cap_toml = r#"
cap_version = 1

[app]
id = "com.test.lint"
name = "Lint Test"
version = "0.1.0"
publisher = "Test"

[entrypoints]
ui = "ui/index.html"
"#;
    std::fs::write(&manifest, cap_toml).expect("write Cap.toml");

    cap_cmd()
        .args(["lint"])
        .arg(&manifest)
        .assert()
        .success()
        .stdout(predicate::str::contains("WARN"));
}

#[test]
fn lint_warns_on_mismatched_fs_scope() {
    let dir = TempDir::new().expect("tempdir");
    let manifest = dir.path().join("Cap.toml");
    std::fs::create_dir_all(dir.path().join("ui")).expect("mkdir ui");
    std::fs::write(dir.path().join("ui/index.html"), "<html></html>").expect("write html");

    let cap_toml = r#"
cap_version = 1

[app]
id = "com.test.lint"
name = "Lint Test"
version = "0.1.0"
publisher = "Test"
description = "Test app"

[entrypoints]
ui = "ui/index.html"

[capabilities.filesystem]
scopes = ["documents://com.wrong.appid/*"]
"#;
    std::fs::write(&manifest, cap_toml).expect("write Cap.toml");

    cap_cmd()
        .args(["lint"])
        .arg(&manifest)
        .assert()
        .success()
        .stdout(predicate::str::contains("WARN"))
        .stdout(predicate::str::contains("com.wrong.appid"));
}

// ── Diff tests ────────────────────────────────────────────────

#[test]
fn diff_same_file_shows_no_changes() {
    let (_dir, cap_path, _sk, _pk) = build_hello_cap();

    cap_cmd()
        .args(["diff"])
        .arg(&cap_path)
        .arg(&cap_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("no changes"))
        .stdout(predicate::str::contains("unchanged"));
}

// ── Trust tests ───────────────────────────────────────────────

#[test]
fn trust_pin_and_list() {
    let (dir, _sk, pk) = generate_test_keys();
    let store = dir.path().join("trust.json");

    cap_cmd()
        .args(["trust", "pin", "com.test.app", "--pubkey"])
        .arg(&pk)
        .arg("--store")
        .arg(&store)
        .assert()
        .success()
        .stdout(predicate::str::contains("Pinned"));

    cap_cmd()
        .args(["trust", "list", "--store"])
        .arg(&store)
        .assert()
        .success()
        .stdout(predicate::str::contains("com.test.app"));
}

#[test]
fn trust_unpin() {
    let (dir, _sk, pk) = generate_test_keys();
    let store = dir.path().join("trust.json");

    // Pin first
    cap_cmd()
        .args(["trust", "pin", "com.test.app", "--pubkey"])
        .arg(&pk)
        .arg("--store")
        .arg(&store)
        .assert()
        .success();

    // Unpin
    cap_cmd()
        .args(["trust", "unpin", "com.test.app", "--store"])
        .arg(&store)
        .assert()
        .success()
        .stdout(predicate::str::contains("Unpinned"));

    // List should show no pins
    cap_cmd()
        .args(["trust", "list", "--store"])
        .arg(&store)
        .assert()
        .success()
        .stdout(predicate::str::contains("No pinned"));
}

#[test]
fn trust_list_empty() {
    let dir = TempDir::new().expect("tempdir");
    let store = dir.path().join("trust.json");

    cap_cmd()
        .args(["trust", "list", "--store"])
        .arg(&store)
        .assert()
        .success()
        .stdout(predicate::str::contains("No pinned"));
}

// ── Error handling ────────────────────────────────────────────

#[test]
fn run_nonexistent_file_fails() {
    cap_cmd()
        .args(["run", "/tmp/does_not_exist_12345.cap"])
        .assert()
        .failure();
}
