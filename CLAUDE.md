# CLAUDE.md — Project Intelligence for CAP

## What is CAP?

CAP (Capability Application Package) is a signed, content-addressed app bundle format.
A `.cap` file is a single artifact that can be inspected, verified, cached, delta-updated,
and executed across desktop, mobile, and web inside a constrained runtime.

## Repository layout

```
spec/                          # CAP 1.0 format specification
crates/cap-format/             # Core library: manifest/index types (CBOR), packager, signer, reader, verifier
crates/cap-cli/                # `cap` CLI binary (keys, build, inspect, verify, run)
crates/cap-core-sdk/           # WASM ABI helpers for building CAP core modules
crates/cap-runtime-desktop/    # Reference desktop runtime (wry WebView, cap:// protocol)
examples/hello-cap/            # Minimal working CAP app (HTML/JS UI + WASM core + KV demo)
scripts/demo.sh                # End-to-end demo script
```

## Build & run

Requires **Rust stable** (see `rust-toolchain.toml`).

```bash
# Install the CLI from the workspace
cargo install --path crates/cap-cli

# Generate a publisher Ed25519 keypair
cap keys generate --out ./keys

# Build the example app into a .cap bundle
cap build \
  --manifest examples/hello-cap/Cap.toml \
  --key ./keys/publisher.ed25519.sk.json \
  --out examples/hello-cap/hello-cap.cap

# Run in the desktop runtime
cap run examples/hello-cap/hello-cap.cap --pubkey ./keys/publisher.ed25519.pk.json
```

### Building the WASM core (optional)

The example ships a prebuilt `hello_cap_core.wasm`. To rebuild:

```bash
rustup target add wasm32-unknown-unknown
cargo build --manifest-path examples/hello-cap/core/Cargo.toml \
  --target wasm32-unknown-unknown --release
cp target/wasm32-unknown-unknown/release/hello_cap_core.wasm \
  examples/hello-cap/core/hello_cap_core.wasm
```

### Running workspace tests

```bash
cargo test --workspace
```

### Checking the workspace compiles

```bash
cargo check --workspace
```

## Architecture & key abstractions

### .cap file internals (ZIP container)

| Entry | Purpose |
|---|---|
| `_cap/manifest.cbor` | Canonical CBOR manifest (app identity, capabilities, entrypoints) |
| `_cap/index.cbor` | File index mapping virtual paths to blob hashes |
| `_cap/root.sha256` | Hex root hash |
| `_cap/signature.ed25519` | 64-byte Ed25519 signature over root hash |
| `_cap/publisher.ed25519.pk` | Optional embedded 32-byte public key |
| `blobs/<sha256>.zst` | Zstd-compressed file payloads keyed by SHA-256 |

ZIP entries are stored **uncompressed**; individual blobs are zstd-compressed inside.

### Root hash computation

```
manifest_hash = SHA-256(manifest_cbor_bytes)
root = SHA-256("CAPROOT\0" || manifest_hash || for each (path, hash) sorted: path || hash)
signature = ed25519_sign(sk, root)
```

### Capability model

No ambient authority. Every privileged operation must be declared in the manifest under
`[capabilities]` and enforced at the runtime boundary. Current capability types:
`network`, `filesystem`, `kv_store`, `notifications`, `crypto_keystore`, `native_accel`.

### Runtime execution model

1. UI assets served via `cap://` custom protocol in a system WebView (`wry`).
2. Runtime injects `window.CAP` JavaScript API with methods gated by declared capabilities.
3. Optional WASM core loaded via JS glue; communicates through `cap_invoke` ABI
   (JSON-encoded `Invocation` -> `Reply`).

### Crate dependency graph

```
cap-core-sdk  (standalone, for WASM targets)

cap-format  <--  cap-cli
            <--  cap-runtime-desktop  <--  cap-cli (for `cap run`)
```

## Coding conventions

- **Edition:** Rust 2021
- **License:** Dual MIT OR Apache-2.0 (every crate inherits from workspace)
- **Error handling:** `thiserror` for library errors (`CapError` enum in `cap-format`), `anyhow` in binaries
- **Serialization:** TOML for human-authored manifests (`Cap.toml`), CBOR for canonical wire format, JSON for key files and runtime API responses
- **CLI framework:** `clap` with derive macros
- **Naming:** snake_case for files/modules, `Cap` prefix for domain types (`CapError`, `CapReader`)
- **WASM ABI:** Stable C-ABI exports (`cap_alloc`, `cap_dealloc`, `cap_invoke`); use `cap_export!` macro

## Key files to know

| File | What it does |
|---|---|
| `crates/cap-format/src/package.rs` | `build_cap_from_manifest()` — main packaging pipeline; `CapReader` — reading/verifying .cap files |
| `crates/cap-format/src/manifest.rs` | `Manifest` struct + TOML/CBOR round-trip |
| `crates/cap-format/src/index.rs` | `Index`/`FileEntry` types, root hash computation |
| `crates/cap-format/src/keys.rs` | Ed25519 keypair generation, JSON load/save |
| `crates/cap-cli/src/main.rs` | All CLI subcommands |
| `crates/cap-runtime-desktop/src/lib.rs` | WebView setup, `cap://` protocol, `window.CAP` injection, KV store |
| `crates/cap-core-sdk/src/lib.rs` | WASM ABI + `cap_export!` macro |
| `examples/hello-cap/Cap.toml` | Example manifest (good template for new apps) |
| `spec/CAP-1.0.md` | Full format specification |

## Common tasks

### Adding a new capability type

1. Add the struct to `crates/cap-format/src/manifest.rs` under `Capabilities`.
2. Update `Cap.toml` parsing in `Manifest::load_toml`.
3. Implement enforcement in `crates/cap-runtime-desktop/src/lib.rs` (`handle_api` and init script).
4. Add JS surface to the `cap_init_script()` function.
5. Document in `spec/CAP-1.0.md`.

### Creating a new example app

1. Create `examples/<name>/Cap.toml` with app metadata and capabilities.
2. Add `ui/index.html` (and any JS/CSS).
3. Optionally add a `core/` WASM module using `cap-core-sdk`.
4. Add the core crate to `Cargo.toml` workspace members if applicable.
5. Build with `cap build --manifest examples/<name>/Cap.toml ...`.

### Adding a new CLI subcommand

1. Add a variant to the `Commands` enum in `crates/cap-cli/src/main.rs`.
2. Implement the handler in the `match` block.
3. Add any new dependencies to `crates/cap-cli/Cargo.toml`.

## Gotchas

- ZIP entries inside `.cap` are stored **uncompressed** (compression is per-blob via zstd). Don't add ZIP-level compression.
- The embedded public key in `_cap/publisher.ed25519.pk` is a **convenience**. For real verification, always pin a known key.
- `compute_root()` expects paths sorted lexicographically. Changing sort order breaks signature verification.
- The `wry` runtime needs platform WebView deps on Linux (e.g., `libwebkit2gtk-4.1-dev`).
