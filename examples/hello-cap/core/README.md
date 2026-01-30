# hello-cap core

This directory contains:

- `hello_cap_core.wasm` — **prebuilt** minimal core used by the demo UI (returns a fixed reply).
- `src/lib.rs` — a real Rust implementation using `cap-core-sdk`.

To rebuild the wasm core yourself:

```bash
rustup target add wasm32-unknown-unknown
cargo build -p hello_cap_core --target wasm32-unknown-unknown --release
cp target/wasm32-unknown-unknown/release/hello_cap_core.wasm ./examples/hello-cap/core/hello_cap_core.wasm
```

Then rebuild the `.cap` file:
```bash
cap build --manifest examples/hello-cap/Cap.toml --key ./keys/publisher.ed25519.sk.json --out examples/hello-cap/hello-cap.cap
```
