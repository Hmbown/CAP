# CAP — Capability Application Package

[![CI](https://github.com/Hmbown/cap/actions/workflows/ci.yml/badge.svg)](https://github.com/Hmbown/cap/actions/workflows/ci.yml)

CAP is a **signed, content-addressed app bundle format**. A single `.cap` file can be inspected, verified, cached, delta-updated, and executed in a sandboxed runtime across desktop, mobile, and web.

**Status:** Early-stage specification and reference implementation. The format is usable today; the runtime and tooling are evolving.

## What's in a `.cap` file

| Layer | Contents |
|-------|----------|
| **UI** | HTML/JS/CSS assets served via a custom protocol in a system WebView |
| **Core** | Optional WASM module with a stable `cap_invoke` ABI |
| **Metadata** | CBOR manifest + file index, Ed25519-signed root hash |
| **Storage** | Content-addressed blobs (`blobs/<sha256>.zst`), individually zstd-compressed |

**Core principle:** No ambient authority. Every privileged operation (network, filesystem, KV store, keystore, notifications) must be declared in the manifest and is enforced by the runtime.

## Quickstart

Requires Rust stable. On Linux, also install `libwebkit2gtk-4.1-dev`.

```bash
# Install the CLI
cargo install --path crates/cap-cli

# Generate a publisher keypair
cap keys generate --out ./keys

# Build the example app
cap build \
  --manifest examples/hello-cap/Cap.toml \
  --key ./keys/publisher.ed25519.sk.json \
  --out ./examples/hello-cap/hello-cap.cap

# Run in the desktop runtime
cap run ./examples/hello-cap/hello-cap.cap \
  --pubkey ./keys/publisher.ed25519.pk.json
```

## Repo layout

```
spec/                        # CAP 1.0 format specification
crates/cap-format/           # Core library: manifest, index, packager, signer, reader, verifier
crates/cap-cli/              # `cap` CLI (keys, build, inspect, verify, run)
crates/cap-core-sdk/         # WASM ABI helpers for building CAP core modules
crates/cap-runtime-desktop/  # Reference desktop runtime (wry WebView, cap:// protocol)
examples/hello-cap/          # Minimal working CAP app
```

The runtime is a reference implementation. The format is designed so that other runtimes (iOS, Android, embedded) can load the same `.cap` files and enforce the same capability model.

## Running tests

```bash
cargo test --workspace
```

## Specification

The full format spec lives in [`spec/CAP-1.0.md`](spec/CAP-1.0.md).

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE) OR [MIT](LICENSE-MIT).
