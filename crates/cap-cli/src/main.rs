use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use cap_format::keys::{
    generate_keypair, load_signing_key_json, load_verifying_key_json, save_signing_key_json,
    save_verifying_key_json,
};
use cap_format::package::{build_cap_from_manifest, CapReader};

#[derive(Parser)]
#[command(name = "cap", version, about = "CAP (.cap) — Capability Application Package CLI")]
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
    Inspect {
        cap: PathBuf,
    },

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
}

#[derive(Subcommand)]
enum KeysCmd {
    /// Generate a new keypair into a directory.
    Generate {
        #[arg(long, default_value = "./keys")]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Command::Keys { cmd } => match cmd {
            KeysCmd::Generate { out } => {
                std::fs::create_dir_all(&out)?;
                let (sk, pk) = generate_keypair();
                let sk_path = out.join("publisher.ed25519.sk.json");
                let pk_path = out.join("publisher.ed25519.pk.json");
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
            build_cap_from_manifest(&manifest, &out, &sk)
                .with_context(|| "build cap")?;
            println!("Built: {}", out.display());
        }

        Command::Inspect { cap } => {
            let mut r = CapReader::open(&cap).with_context(|| format!("open {}", cap.display()))?;
            // best-effort verify using embedded pk if present
            let _ = r.verify(None, false);

            let m_json = serde_json::to_string_pretty(&r.manifest)?;
            println!("== Manifest ==\n{m_json}\n");

            println!("== Index ==\nfiles: {}", r.index.files.len());
            for (UST in r.index.files.keys().take(20) {
                println!("  {UST}");
            }
            if r.index.files.len() > 20 {
                println!("  ...");
            }
        }

        Command::Verify { cap, pubkey, full } => {
            let mut r = CapReader::open(&cap).with_context(|| format!("open {}", cap.display()))?;
            let pk_override = if let Some(p) = pubkey.as_ref() {
                Some(load_verifying_key_json(p)?)
            } else {
                None
            };
            r.verify(pk_override.as_ref(), full)?;
            println!("OK: {}", cap.display());
        }

        Command::Run { cap, pubkey } => {
            let pk_path = pubkey.as_deref();
            cap_runtime_desktop::run(&cap, pk_path)
                .with_context(|| "run runtime")?;
        }
    }

    Ok(())
}
