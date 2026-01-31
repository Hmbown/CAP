use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use cap_format::keys::{
    generate_keypair, load_signing_key_json, load_verifying_key_json, save_signing_key_json,
    save_verifying_key_json,
};
use cap_format::package::{build_cap_from_manifest, CapReader};
use cap_format::trust::{TrustResult, TrustStore};

#[derive(Parser)]
#[command(
    name = "cap",
    version,
    about = "CAP (.cap) — Capability Application Package CLI"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a publisher Ed25519 keypair.
    Keys {
        #[command(subcommand)]
        cmd: KeysCmd,
    },

    /// Build a .cap file from a Cap.toml manifest.
    Build {
        /// Path to Cap.toml
        #[arg(long)]
        manifest: PathBuf,

        /// Path to publisher secret key JSON
        #[arg(long)]
        key: PathBuf,

        /// Output .cap path
        #[arg(long)]
        out: PathBuf,
    },

    /// Print manifest + index summary.
    Inspect { cap: PathBuf },

    /// Verify signature and (optionally) all blob hashes.
    Verify {
        cap: PathBuf,

        /// Path to publisher public key JSON. If omitted, tries embedded public key.
        #[arg(long)]
        pubkey: Option<PathBuf>,

        /// Verify every blob hash (slower).
        #[arg(long)]
        full: bool,
    },

    /// Run a .cap in the reference desktop runtime.
    Run {
        cap: PathBuf,

        /// Path to publisher public key JSON. If omitted, tries embedded public key.
        #[arg(long)]
        pubkey: Option<PathBuf>,
    },

    /// Extract a .cap bundle to a directory.
    Extract {
        /// Path to the .cap file.
        cap: PathBuf,

        /// Output directory (default: current dir).
        #[arg(long, default_value = ".")]
        out: PathBuf,
    },

    /// Scaffold a new CAP project.
    Init {
        /// App name (used for directory and app id).
        name: String,

        /// Parent directory to create the project in.
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },

    /// Lint a Cap.toml manifest for common issues.
    Lint {
        /// Path to Cap.toml manifest.
        #[arg(default_value = "Cap.toml")]
        manifest: PathBuf,
    },

    /// Compare two .cap bundles.
    Diff {
        /// First .cap file.
        a: PathBuf,
        /// Second .cap file.
        b: PathBuf,
    },

    /// Manage publisher key trust (TOFU).
    Trust {
        #[command(subcommand)]
        action: TrustAction,
    },
}

#[derive(Subcommand)]
enum KeysCmd {
    /// Generate a new keypair into a directory.
    Generate {
        #[arg(long, default_value = "./keys")]
        out: PathBuf,

        /// Overwrite existing keys if present.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum TrustAction {
    /// Pin a publisher key for an app.
    Pin {
        /// The app ID to pin.
        app_id: String,

        /// Path to the publisher public key JSON file.
        #[arg(long)]
        pubkey: PathBuf,

        /// Path to trust store file (default: system config).
        #[arg(long)]
        store: Option<PathBuf>,
    },

    /// Remove a pinned key for an app.
    Unpin {
        /// The app ID to unpin.
        app_id: String,

        /// Path to trust store file (default: system config).
        #[arg(long)]
        store: Option<PathBuf>,
    },

    /// List all pinned publisher keys.
    List {
        /// Path to trust store file (default: system config).
        #[arg(long)]
        store: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Command::Keys { cmd } => match cmd {
            KeysCmd::Generate { out, force } => {
                let sk_path = out.join("publisher.ed25519.sk.json");
                let pk_path = out.join("publisher.ed25519.pk.json");

                if !force && (sk_path.exists() || pk_path.exists()) {
                    bail!(
                        "keys already exist in {}. Use --force to overwrite.",
                        out.display()
                    );
                }

                std::fs::create_dir_all(&out)?;
                let (sk, pk) = generate_keypair();
                save_signing_key_json(&sk_path, &sk)?;
                save_verifying_key_json(&pk_path, &pk)?;
                println!("Wrote:");
                println!("  {}", sk_path.display());
                println!("  {}", pk_path.display());
            }
        },

        Command::Build { manifest, key, out } => {
            let sk = load_signing_key_json(&key)
                .with_context(|| format!("load signing key {}", key.display()))?;
            build_cap_from_manifest(&manifest, &out, &sk).with_context(|| "build cap")?;
            println!("Built: {}", out.display());
        }

        Command::Inspect { cap } => {
            let mut r = CapReader::open(&cap).with_context(|| format!("open {}", cap.display()))?;

            // Verification status
            let verify_status = match r.verify(None, false) {
                Ok(()) => "OK (embedded key)".to_string(),
                Err(e) => format!("FAILED: {e}"),
            };
            println!("== Verification ==");
            println!("  Status: {verify_status}");
            println!("  Root hash: {}", hex::encode(r.root));
            println!("  Signature: {}...", hex::encode(&r.signature[..8]));
            if let Some(pk) = &r.publisher_pk {
                println!("  Publisher PK: {}", hex::encode(pk.as_bytes()));
            } else {
                println!("  Publisher PK: (not embedded)");
            }
            println!();

            // Manifest summary
            let m = &r.manifest;
            println!("== Manifest ==");
            println!("  id:         {}", m.app.id);
            println!("  name:       {}", m.app.name);
            println!("  version:    {}", m.app.version);
            println!("  publisher:  {}", m.app.publisher);
            println!("  ui:         {}", m.entrypoints.ui);
            if let Some(ref core) = m.entrypoints.core_wasm {
                println!("  core_wasm:  {core}");
            }
            println!();

            // Capabilities summary
            println!("== Capabilities ==");
            let caps = &m.capabilities;
            let mut any_cap = false;
            if let Some(ref net) = caps.network {
                println!("  network: allow {:?}", net.allow);
                any_cap = true;
            }
            if let Some(ref fs) = caps.filesystem {
                println!("  filesystem: scopes {:?}", fs.scopes);
                any_cap = true;
            }
            if let Some(ref kv) = caps.kv_store {
                println!("  kv_store: persistent={}", kv.persistent);
                any_cap = true;
            }
            if let Some(ref n) = caps.notifications {
                println!("  notifications: {}", n.use_notifications);
                any_cap = true;
            }
            if let Some(ref ck) = caps.crypto_keystore {
                println!("  crypto_keystore: {}", ck.use_keystore);
                any_cap = true;
            }
            if let Some(ref na) = caps.native_accel {
                println!("  native_accel: allow {:?}", na.allow);
                any_cap = true;
            }
            if !any_cap {
                println!("  (none)");
            }
            println!();

            // File listing
            println!("== Files ({}) ==", r.index.files.len());
            let mut total_size: u64 = 0;
            let mut total_compressed: u64 = 0;
            for (vpath, entry) in &r.index.files {
                total_size += entry.size;
                total_compressed += entry.compressed_size;
                let ratio = if entry.size > 0 {
                    (entry.compressed_size as f64 / entry.size as f64) * 100.0
                } else {
                    0.0
                };
                let mime_str = entry.mime.as_deref().unwrap_or("-");
                println!(
                    "  {vpath}  ({} -> {} bytes, {ratio:.0}%)  [{mime_str}]",
                    entry.size, entry.compressed_size
                );
            }
            let total_ratio = if total_size > 0 {
                (total_compressed as f64 / total_size as f64) * 100.0
            } else {
                0.0
            };
            println!();
            println!(
                "  Total: {} -> {} bytes ({total_ratio:.0}%)",
                total_size, total_compressed
            );
        }

        Command::Verify { cap, pubkey, full } => {
            let mut r = CapReader::open(&cap).with_context(|| format!("open {}", cap.display()))?;
            let pk_override = if let Some(p) = pubkey.as_ref() {
                Some(load_verifying_key_json(p)?)
            } else {
                None
            };
            r.verify(pk_override.as_ref(), full)?;

            let mode = if full {
                "full (signature + all blob hashes)"
            } else {
                "signature only"
            };
            let key_source = if pubkey.is_some() {
                "provided key"
            } else {
                "embedded key"
            };
            println!("OK: {} [{mode}] [{key_source}]", cap.display());
        }

        Command::Run { cap, pubkey } => {
            // Verify + TOFU check before launching runtime
            let mut reader =
                CapReader::open(&cap).with_context(|| format!("open {}", cap.display()))?;
            let pk_override = if let Some(ref p) = pubkey {
                Some(load_verifying_key_json(p)?)
            } else {
                None
            };
            reader.verify(pk_override.as_ref(), false)?;

            // Determine public key hex for TOFU
            let pubkey_hex = if let Some(ref pk) = pk_override {
                hex::encode(pk.as_bytes())
            } else if let Some(ref embedded_pk) = reader.publisher_pk {
                hex::encode(embedded_pk.as_bytes())
            } else {
                bail!("no public key available for TOFU check (provide --pubkey or embed key in .cap)");
            };

            let app_id = &reader.manifest.app.id;
            let mut trust_store = TrustStore::open().with_context(|| "open trust store")?;
            match trust_store.check(app_id, &pubkey_hex) {
                TrustResult::FirstUse => {
                    trust_store.save().with_context(|| "save trust store")?;
                    println!("Pinned publisher key for {app_id}");
                }
                TrustResult::Trusted => {}
                TrustResult::Mismatch { expected, got } => {
                    bail!(
                        "TRUST VIOLATION: publisher key for '{app_id}' has changed!\n  \
                         Expected: {expected}\n  Got:      {got}\n\n\
                         If this is intentional, run: cap trust unpin {app_id}"
                    );
                }
            }

            let pk_path = pubkey.as_deref();
            cap_runtime_desktop::run(&cap, pk_path).with_context(|| "run runtime")?;
        }

        Command::Extract { cap, out } => {
            let mut r = CapReader::open(&cap).with_context(|| format!("open {}", cap.display()))?;

            std::fs::create_dir_all(&out)?;

            // Write _cap/manifest.toml (human-readable)
            let cap_meta_dir = out.join("_cap");
            std::fs::create_dir_all(&cap_meta_dir)?;

            let toml_str = toml::to_string_pretty(&r.manifest)
                .with_context(|| "serialize manifest to TOML")?;
            std::fs::write(cap_meta_dir.join("manifest.toml"), toml_str)?;

            // Write _cap/root.sha256
            std::fs::write(
                cap_meta_dir.join("root.sha256"),
                format!("{}\n", hex::encode(r.root)),
            )?;

            // Extract all virtual files
            let vpaths: Vec<String> = r.index.files.keys().cloned().collect();
            let mut count = 0u32;
            for vpath in &vpaths {
                let data = r
                    .read_virtual_file(vpath)
                    .with_context(|| format!("read {vpath}"))?;
                let dest = out.join(vpath);
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&dest, data)?;
                count += 1;
            }

            println!("Extracted {} files + metadata to {}", count, out.display());
        }

        Command::Lint { manifest } => {
            let mut warnings = 0u32;
            let mut errors = 0u32;

            let m = match cap_format::manifest::Manifest::load_toml(&manifest) {
                Ok(m) => m,
                Err(e) => {
                    println!("ERROR: failed to parse manifest: {e}");
                    bail!("lint failed: invalid manifest");
                }
            };

            // Warn if version doesn't look like semver (no '.')
            if !m.app.version.contains('.') {
                println!(
                    "WARN: app.version '{}' does not look like semver",
                    m.app.version
                );
                warnings += 1;
            }

            // Warn if description is missing
            if m.app.description.is_none() {
                println!("WARN: app.description is missing");
                warnings += 1;
            }

            // Error if UI entrypoint file doesn't exist on disk
            let project_root = manifest
                .parent()
                .ok_or_else(|| anyhow::anyhow!("manifest has no parent dir"))?;
            let ui_path = project_root.join(&m.entrypoints.ui);
            if !ui_path.exists() {
                println!("ERROR: UI entrypoint file not found: {}", ui_path.display());
                errors += 1;
            }

            // Error if core_wasm declared but file missing
            if let Some(ref core) = m.entrypoints.core_wasm {
                let core_path = project_root.join(core);
                if !core_path.exists() {
                    println!("ERROR: core_wasm file not found: {}", core_path.display());
                    errors += 1;
                }
            }

            // Warn if no capabilities declared
            let caps = &m.capabilities;
            let has_any_cap = caps.network.is_some()
                || caps.filesystem.is_some()
                || caps.kv_store.is_some()
                || caps.notifications.is_some()
                || caps.crypto_keystore.is_some()
                || caps.native_accel.is_some();
            if !has_any_cap {
                println!("WARN: no capabilities declared");
                warnings += 1;
            }

            // Warn if filesystem has issues
            if let Some(ref fs) = caps.filesystem {
                if fs.scopes.is_empty() {
                    println!("WARN: filesystem.scopes is empty");
                    warnings += 1;
                }
                for scope in &fs.scopes {
                    // Check if scope references an app ID that doesn't match manifest app.id
                    if let Some((_scheme, rest)) = scope.split_once("://") {
                        if let Some((scope_app_id, _path)) = rest.split_once('/') {
                            if scope_app_id != m.app.id {
                                println!(
                                    "WARN: filesystem scope references app id '{scope_app_id}' but manifest app.id is '{}'",
                                    m.app.id
                                );
                                warnings += 1;
                            }
                        }
                    }
                }
            }

            // Warn if network.allow is empty or contains wildcard
            if let Some(ref net) = caps.network {
                if net.allow.is_empty() {
                    println!("WARN: network.allow is empty");
                    warnings += 1;
                }
                if net.allow.iter().any(|o| o == "*") {
                    println!("WARN: network.allow contains wildcard '*'");
                    warnings += 1;
                }
            }

            // Summary
            if errors > 0 {
                println!("\nLint: {errors} error(s), {warnings} warning(s)");
                bail!("lint failed with {errors} error(s)");
            } else if warnings > 0 {
                println!("\nLint: OK with {warnings} warning(s)");
            } else {
                println!("Lint: OK");
            }
        }

        Command::Diff { a, b } => {
            let reader_a = CapReader::open(&a).with_context(|| format!("open {}", a.display()))?;
            let reader_b = CapReader::open(&b).with_context(|| format!("open {}", b.display()))?;

            let ma = &reader_a.manifest;
            let mb = &reader_b.manifest;

            // Manifest changes
            println!("== Manifest ==");
            let mut manifest_changed = false;
            if ma.app.name != mb.app.name {
                println!("  name: {} -> {}", ma.app.name, mb.app.name);
                manifest_changed = true;
            }
            if ma.app.id != mb.app.id {
                println!("  id: {} -> {}", ma.app.id, mb.app.id);
                manifest_changed = true;
            }
            if ma.app.version != mb.app.version {
                println!("  version: {} -> {}", ma.app.version, mb.app.version);
                manifest_changed = true;
            }
            if ma.capabilities != mb.capabilities {
                println!("  capabilities: changed");
                manifest_changed = true;
            }
            if !manifest_changed {
                println!("  (unchanged)");
            }
            println!();

            // File changes
            println!("== Files ==");
            let files_a = &reader_a.index.files;
            let files_b = &reader_b.index.files;

            let mut added = 0u32;
            let mut removed = 0u32;
            let mut modified = 0u32;
            let mut unchanged = 0u32;
            let mut size_delta: i64 = 0;

            // Added or modified in B
            for (path, entry_b) in files_b {
                match files_a.get(path) {
                    None => {
                        println!("  + {path} ({} bytes)", entry_b.size);
                        size_delta += entry_b.size as i64;
                        added += 1;
                    }
                    Some(entry_a) => {
                        if entry_a.hash != entry_b.hash {
                            let delta = entry_b.size as i64 - entry_a.size as i64;
                            let sign = if delta >= 0 { "+" } else { "" };
                            println!("  ~ {path} ({sign}{delta} bytes)");
                            size_delta += delta;
                            modified += 1;
                        } else {
                            unchanged += 1;
                        }
                    }
                }
            }

            // Removed from A
            for (path, entry_a) in files_a {
                if !files_b.contains_key(path) {
                    println!("  - {path} ({} bytes)", entry_a.size);
                    size_delta -= entry_a.size as i64;
                    removed += 1;
                }
            }

            if added == 0 && removed == 0 && modified == 0 {
                println!("  (no changes)");
            }

            println!();
            let sign = if size_delta >= 0 { "+" } else { "" };
            println!(
                "Summary: {} added, {} removed, {} modified, {} unchanged ({sign}{} bytes)",
                added, removed, modified, unchanged, size_delta
            );
        }

        Command::Trust { action } => match action {
            TrustAction::Pin {
                app_id,
                pubkey,
                store,
            } => {
                let pk = load_verifying_key_json(&pubkey)
                    .with_context(|| format!("load public key {}", pubkey.display()))?;
                let pubkey_hex = hex::encode(pk.as_bytes());

                let mut trust_store = if let Some(path) = store {
                    TrustStore::open_at(path)?
                } else {
                    TrustStore::open()?
                };
                trust_store.pin(&app_id, &pubkey_hex);
                trust_store.save().with_context(|| "save trust store")?;
                println!("Pinned {app_id} -> {pubkey_hex}");
            }
            TrustAction::Unpin { app_id, store } => {
                let mut trust_store = if let Some(path) = store {
                    TrustStore::open_at(path)?
                } else {
                    TrustStore::open()?
                };
                trust_store.unpin(&app_id);
                trust_store.save().with_context(|| "save trust store")?;
                println!("Unpinned {app_id}");
            }
            TrustAction::List { store } => {
                let trust_store = if let Some(path) = store {
                    TrustStore::open_at(path)?
                } else {
                    TrustStore::open()?
                };
                let pins = trust_store.list();
                if pins.is_empty() {
                    println!("No pinned publisher keys.");
                } else {
                    println!("Pinned publisher keys:");
                    for (app_id, pin) in pins {
                        println!(
                            "  {app_id} -> {} (first: {}, last: {})",
                            pin.pubkey_hex, pin.first_seen, pin.last_seen
                        );
                    }
                }
            }
        },

        Command::Init { name, dir } => {
            let project = dir.join(&name);
            if project.exists() {
                bail!("directory '{}' already exists", project.display());
            }

            std::fs::create_dir_all(project.join("ui"))?;

            let cap_toml = format!(
                r#"cap_version = 1

[app]
id = "com.example.{name}"
name = "{name}"
version = "0.1.0"
publisher = "Your Name"

[entrypoints]
ui = "ui/index.html"
"#,
                name = name
            );
            std::fs::write(project.join("Cap.toml"), cap_toml)?;

            let index_html = format!(
                r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>{name}</title></head>
<body>
  <h1>{name}</h1>
  <pre id="out"></pre>
  <script>
    (async () => {{
      const out = document.getElementById("out");
      if (window.CAP) {{
        const ping = await window.CAP.ping();
        out.textContent = "Runtime: " + ping.runtime;
      }} else {{
        out.textContent = "No CAP runtime detected.";
      }}
    }})();
  </script>
</body>
</html>
"#,
                name = name
            );
            std::fs::write(project.join("ui/index.html"), index_html)?;

            println!("Created new CAP project: {}", project.display());
            println!();
            println!("Next steps:");
            println!("  cap keys generate --out {}/keys", project.display());
            println!(
                "  cap build --manifest {}/Cap.toml --key {}/keys/publisher.ed25519.sk.json --out {}.cap",
                project.display(),
                project.display(),
                name
            );
        }
    }

    Ok(())
}
