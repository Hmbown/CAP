#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT"

cargo install --path crates/cap-cli

cap keys generate --out ./keys
cap build --manifest examples/hello-cap/Cap.toml --key ./keys/publisher.ed25519.sk.json --out examples/hello-cap/hello-cap.cap
cap run examples/hello-cap/hello-cap.cap --pubkey ./keys/publisher.ed25519.pk.json
