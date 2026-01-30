# Hello CAP example

This example demonstrates:

- CAP packaging (`cap build`) from `Cap.toml`
- Desktop runtime (`cap run`) that:
  - serves `ui/` and `core/` assets via `cap://` custom protocol
  - exposes a minimal `window.CAP` capability API (`kv_store`)

Files:
- `Cap.toml` — manifest (declares `kv_store`)
- `ui/` — static web UI
- `core/hello_cap_core.wasm` — small core wasm module

## Run (from repo root)
```bash
cap keys generate --out ./keys
cap build --manifest examples/hello-cap/Cap.toml --key ./keys/publisher.ed25519.sk.json --out examples/hello-cap/hello-cap.cap
cap run examples/hello-cap/hello-cap.cap --pubkey ./keys/publisher.ed25519.pk.json
```
