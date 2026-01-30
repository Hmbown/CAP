# CAP — Capability Application Package (.cap)

CAP is a **signed, content-addressed app bundle format** intended to be the “app file” for 2027:
one artifact that can be **inspected, verified, cached, updated by delta**, and executed in a constrained
runtime across **desktop, mobile, and web**.

This repo includes:

- `spec/` — a concrete CAP 1.0 spec (transport uses ZIP for now; canonical container can be upgraded later)
- `crates/cap-format` — manifest/index/types + packaging + signing utilities
- `crates/cap-cli` — `cap` CLI to generate keys, build/inspect/verify `.cap` files
- `crates/cap-runtime-desktop` — reference desktop runtime using the **system WebView** via `wry`
- `examples/hello-cap` — a minimal CAP app that uses:
  - **UI**: plain HTML/JS
  - **Core**: a tiny WebAssembly module (included prebuilt) that exposes a stable `cap_invoke` ABI

> Note: The runtime is a reference implementation. The format is designed so other shells (iOS/Android/Harmony)
> can embed the same `.cap` and expose the same capability surface.

---

## Quickstart (desktop)

### 0) Prereqs
- Rust stable toolchain
- Platform WebView deps as required by `wry` on your OS (see wry docs if Linux)

### 1) Install the CLI (from this repo)
```bash
cargo install --path crates/cap-cli
```

### 2) Generate a publisher keypair
```bash
cap keys generate --out ./keys
# produces:
#   ./keys/publisher.ed25519.sk.json
#   ./keys/publisher.ed25519.pk.json
```

### 3) Build the example app into a `.cap`
```bash
cap build \
  --manifest examples/hello-cap/Cap.toml \
  --key ./keys/publisher.ed25519.sk.json \
  --out ./examples/hello-cap/hello-cap.cap
```

### 4) Run it
```bash
cap run ./examples/hello-cap/hello-cap.cap --pubkey ./keys/publisher.ed25519.pk.json
```

---

## What “CAP” means in practice

A `.cap` file contains:

- `ui/…` web assets (runs everywhere)
- an optional portable `core/*.wasm` module (runs on desktop, mobile, and web)
- `_cap/manifest.cbor` + `_cap/index.cbor` (signed metadata)
- `blobs/<sha256>.zst` chunk store (content-addressed, compressed)

### Core idea
**No ambient authority.** Any privileged operation goes through an explicit capability declared in the manifest
and enforced by the runtime shell.

---

## Repo layout

```
spec/                     # format + capability grammar
crates/cap-format/         # packager + signing + reader
crates/cap-cli/            # `cap` command
crates/cap-runtime-desktop/# reference runtime (wry custom protocol)
crates/cap-core-sdk/       # ABI helpers for WASM cores (optional)
examples/hello-cap/        # sample CAP app
```

---

## License
Dual-licensed under **Apache-2.0 OR MIT** (matching much of the Rust ecosystem).
