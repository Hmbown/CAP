# Codex Execution Prompt — CAP Roadmap Implementation

Use this prompt to hand to an autonomous coding agent (Codex, Claude Code, etc.) to continue building the CAP project through its roadmap phases.

---

## Prompt

You are working on **CAP (Capability Application Package)** — a signed, content-addressed app bundle format implemented in Rust. The repo is at the root of this workspace.

Before doing anything, read these files completely:
- `ROADMAP.md` — the phased implementation plan with risks
- `CLAUDE.md` — project structure, build commands, architecture, conventions
- `AGENTS.md` — module ownership and cross-cutting workflows
- `Cargo.toml` — workspace layout
- `spec/CAP-1.0.md` — the format specification (source of truth)

Your job is to **execute the roadmap in order**, phase by phase, task by task. Work through as many phases as you can. Do not skip ahead — later phases depend on earlier ones.

---

### Rules

1. **Always compile before committing.** Run `cargo check --workspace` after every meaningful change. If it doesn't compile, fix it before moving on.

2. **Always test before committing.** Run `cargo test --workspace` after adding or modifying tests. Never commit failing tests.

3. **Commit after each completed task** (each checkbox item in the roadmap). Use clear commit messages that reference the roadmap phase and task (e.g., `Phase 0.1: Add manifest TOML/CBOR round-trip tests`).

4. **Don't break signatures.** If you change `compute_root()`, manifest CBOR encoding, or signing logic, you are making a breaking change. Flag it clearly in the commit message and update `spec/CAP-1.0.md` to match.

5. **Follow existing conventions.** Rust 2021, `thiserror` for library errors, `anyhow` for binaries, `clap` derive for CLI, `BTreeMap` for deterministic ordering. Read the existing code in a module before modifying it.

6. **Spec is source of truth.** If you implement something that diverges from `spec/CAP-1.0.md`, update the spec to match or change your implementation to match the spec. They must never disagree.

7. **Don't over-engineer.** Implement what the roadmap says. Don't add features, abstractions, or configuration that isn't called for. Keep diffs minimal and focused.

8. **When stuck on a platform-specific issue** (e.g., wry API differences across OSes), implement for macOS first, add `#[cfg]` stubs for other platforms, and leave a `// TODO:` with the specific issue.

9. **Update ROADMAP.md** as you go — check off completed items with `[x]`.

---

### Phase 0 — Stabilize the Foundation

#### 0.1 Test Suite

Create `crates/cap-format/tests/` with integration tests:

```
crates/cap-format/tests/
  roundtrip.rs        — manifest TOML → CBOR → back, index CBOR round-trip
  packaging.rs        — build hello-cap into .cap, open with CapReader, verify
  tamper.rs           — modify a blob/manifest in a .cap, confirm verify() fails
  root_hash.rs        — test compute_root() with known inputs and expected output
  keys.rs             — generate keypair, save, load, verify round-trip
  snapshot.rs         — CBOR output snapshot tests (save expected bytes, compare)
```

For `packaging.rs`, use the `examples/hello-cap/` directory as input. Build a `.cap` to a tempfile, open it, assert:
- `reader.manifest.app.id == "com.example.hello-cap"`
- `reader.verify(Some(&pk), true)` succeeds (full blob verification)
- Every file in the index can be read via `reader.read_virtual_file()`

For `tamper.rs`, build a valid `.cap`, then:
- Overwrite one byte in a blob entry in the ZIP, reopen, assert `verify(..., true)` fails with hash mismatch
- Modify `_cap/manifest.cbor` bytes, reopen, assert root hash mismatch

For `snapshot.rs`:
- Create a `Manifest` with known field values
- Serialize to CBOR
- Compare against a saved expected byte vector
- If this test ever fails without an intentional schema change, it means CBOR encoding has drifted

For the SDK crate, add `crates/cap-core-sdk/tests/abi.rs`:
- Test `Invocation` JSON round-trip
- Test `Reply::ok()` and `Reply::err()` serialization

Add `[dev-dependencies]` as needed: `tempfile`, `assert_matches`, etc.

#### 0.2 CI Pipeline

Create `.github/workflows/ci.yml`:

```yaml
name: CI
on: [push, pull_request]
jobs:
  check:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: wasm32-unknown-unknown
      - name: Install Linux deps
        if: runner.os == 'Linux'
        run: sudo apt-get update && sudo apt-get install -y libwebkit2gtk-4.1-dev libayatana-appindicator3-dev
      - run: cargo fmt --check
      - run: cargo clippy --workspace -- -D warnings
      - run: cargo check --workspace
      - run: cargo test --workspace
      - run: cargo check -p cap-core-sdk --target wasm32-unknown-unknown
      - run: cargo check -p hello_cap_core --target wasm32-unknown-unknown
```

Adjust Linux dependencies if wry requires different packages for the version pinned.

#### 0.3 CBOR Canonicalization Audit

In `crates/cap-format/tests/snapshot.rs` (or a dedicated `cbor_determinism.rs`):

1. Create two `Manifest` structs with identical logical content but constructed in different code paths
2. Serialize both to CBOR
3. Assert the bytes are identical
4. Do the same for `Index`
5. If they differ, investigate which field is non-deterministic and fix it (e.g., by sorting keys, normalizing optional encoding, or using explicit CBOR canonical encoding)

Also check: does `ciborium` encode integers with minimal width? Does it encode `None` the same as a missing key? Create test cases that exercise edge cases.

If ciborium is not deterministic enough, consider:
- Sorting the struct into a `BTreeMap<String, ciborium::Value>` and encoding that
- Or switching to manual CBOR encoding for the signed types

#### 0.4 Wry API Compatibility

Read `crates/cap-runtime-desktop/Cargo.toml` and check the `wry` version. Then:

1. Try `cargo check -p cap-runtime-desktop`. If it fails, fix the API calls to match the pinned wry version.
2. If wry is unpinned (e.g., `wry = "0"` or `wry = "*"`), pin it to a specific working version.
3. Add a comment in `Cargo.toml` documenting the wry version and why it's pinned.

The wry API changed significantly between 0.35→0.37→0.39 and then again at 0.46+. Common breakages:
- `EventLoop` moved from `wry::application` to `tao`
- `WebViewBuilder::new()` may take a `&Window` or use `WebViewBuilder::new(&window)` vs `build(&window)`
- Custom protocol handler signatures changed (some versions pass `Request<Vec<u8>>`, others `Request<String>`)

Fix whatever is broken to compile clean against the pinned version.

---

### Phase 1 — Security Hardening

#### 1.1 Content Security Policy

In `crates/cap-runtime-desktop/src/lib.rs`, modify `cap_init_script()`:

1. Before the `window.CAP` setup, inject a `<meta>` tag that sets a strict CSP:
   ```
   default-src 'self' cap:; script-src 'self' cap: 'unsafe-inline'; style-src 'self' cap: 'unsafe-inline'; connect-src cap: /__cap/*; img-src 'self' cap: data: blob:; font-src 'self' cap: data:; object-src 'none'; base-uri 'none';
   ```
2. If the manifest declares `capabilities.network` with an `allow` list, add those origins to `connect-src`.
3. Add a test: load a `.cap` app and verify that a `fetch()` to an external URL is blocked (this may need to be a manual verification if headless WebView testing isn't feasible — document the expected behavior).

#### 1.2 WASM Sandboxing

This phase applies if/when the runtime loads WASM cores natively (currently WASM is loaded by the JS UI via `wasm_glue.js`). For now:

1. Add a `[capabilities.wasm_limits]` section to the manifest schema:
   ```toml
   [capabilities.wasm_limits]
   max_memory_pages = 256  # 16 MB
   ```
2. Update the manifest struct in `crates/cap-format/src/manifest.rs`
3. In the JS init script, add a wrapper around `WebAssembly.instantiate` that enforces `maximum` on the memory import
4. Update the spec

#### 1.3 KV Store Encryption

In `crates/cap-runtime-desktop/src/lib.rs`:

1. Add a dependency on a platform keychain crate (e.g., `keyring` for cross-platform secret storage)
2. On first launch for an app, generate a random 256-bit key and store it in the platform keychain under `cap-runtime/{app_id}/kv-key`
3. Encrypt KV data before writing to disk using AES-256-GCM (use the `aes-gcm` crate)
4. Decrypt on load
5. If the keychain is unavailable, fall back to unencrypted with a warning log

#### 1.4 Key Pinning

1. Create a `~/.config/cap-runtime/known_publishers.json` file that maps `app_id → pinned_public_key_hex`
2. On first `cap run`, if no pin exists, store the key (TOFU — trust on first use)
3. On subsequent runs, verify the `.cap`'s publisher key matches the pin
4. If mismatch, refuse to run and print a clear error explaining key pinning
5. Add `cap keys pin <app_id> <pubkey_file>` CLI command for manual pinning
6. Add `cap keys unpin <app_id>` for removing a pin

#### 1.5 Rate Limiting

In `crates/cap-runtime-desktop/src/lib.rs`:

1. Add a simple token-bucket rate limiter to `AppState` for API calls
2. Default: 100 calls/second per capability category
3. Return HTTP 429 with a clear error when rate limit is exceeded
4. Add KV value size limit (default 1 MB per value, 100 MB total per app)
5. Add KV key length limit (256 bytes)

---

### Phase 2 — Merkle Index and Delta Updates

**This phase contains a breaking change to root hash computation.**

#### 2.1 Merkle Tree Index

1. In `crates/cap-format/src/index.rs`, add a `MerkleTree` struct:
   - Leaf nodes: `SHA-256(path_bytes || "\0" || hash_bytes)` for each (path, hash) pair, sorted by path
   - Internal nodes: `SHA-256(left_child_hash || right_child_hash)`
   - If the number of leaves is odd, promote the last leaf
   - Store the tree as a vector of hashes (level by level) for compact CBOR serialization

2. Add `compute_root_merkle()` that replaces `compute_root()`:
   ```
   root = SHA-256("CAPROOT\0" || manifest_hash || merkle_root_of_index)
   ```

3. Add `inclusion_proof(path) -> Vec<[u8; 32]>` that returns the sibling hashes needed to verify a single path belongs to the tree

4. Add `verify_inclusion(root, path, hash, proof) -> bool`

5. Update `build_cap_from_manifest()` to use the new root computation

6. Update `CapReader::verify()` to use the new root computation

7. **Bump `cap_version` to 2** in the manifest to distinguish from the old format

8. Update `spec/CAP-1.0.md` (or create `spec/CAP-2.0.md`) with the new root hash algorithm

9. Add thorough tests: known-answer test for a small tree, inclusion proof verification, proof rejection for wrong path

10. Rebuild `examples/hello-cap/` with the new format and update its `Cap.toml` to `cap_version = 2`

#### 2.2 Delta Update Protocol

1. Create `crates/cap-update/` with:
   - `DeltaManifest`: lists blob hashes present in old version vs. new version
   - `compute_delta(old_index, new_index) -> DeltaManifest`
   - `apply_delta(old_cap_path, delta_blobs, new_metadata) -> new_cap_path`

2. Define the HTTP API (as a spec document `spec/CAP-UPDATE-PROTOCOL.md`):
   ```
   GET  /api/v1/apps/{app_id}/latest?channel={channel}
        → { root_hash, version, signature, manifest_url, index_url }

   POST /api/v1/apps/{app_id}/delta
        Body: { client_root_hash }
        → { new_root_hash, added_blobs: [hash], removed_blobs: [hash], manifest_cbor_url, index_cbor_url }

   GET  /api/v1/blobs/{hash}
        → raw zstd blob
   ```

3. Add `cap update <cap_path> --server <url>` CLI command
4. Add tests with a mock HTTP server (use `wiremock` or similar)

#### 2.3 Update Channel Signing

1. Extend the manifest `[updates]` section to include `allowed_signers: [key_id]`
2. Implement `cap update` to verify the new package against the channel's allowed signers
3. Implement rollback: `cap rollback <app_id>` restores the previous version from a local cache

---

### Phase 3 — Complete Capability Implementation

For each capability, the pattern is:
1. Add JS API surface in `cap_init_script()`
2. Add API endpoint(s) in `handle_api()`
3. Add capability check (return 403 if not declared)
4. Add types/logic as needed
5. Add test
6. Update spec

#### 3.1 Network Capability

1. In `cap_init_script()`, override `window.fetch` with a wrapper that:
   - Extracts the URL
   - Checks against `capabilities.network.allow` patterns
   - Blocks with a clear error if not allowed
   - Passes through if allowed
2. Also override `XMLHttpRequest.prototype.open` and `WebSocket` constructor
3. For image/script/link loads, rely on the CSP from Phase 1.1
4. Add `window.CAP.network.allowed()` that returns the allowlist for UI introspection

#### 3.2 Filesystem Capability

1. Add `window.CAP.fs` API:
   - `readFile(scope, path) -> Uint8Array`
   - `writeFile(scope, path, data)`
   - `listDir(scope, path) -> string[]`
   - `remove(scope, path)`
2. Add API endpoints: `/__cap/fs/read`, `/__cap/fs/write`, `/__cap/fs/list`, `/__cap/fs/remove`
3. Map scopes to real paths:
   - `documents://app/*` → `~/Documents/CAP/{app_id}/`
   - `cache://app/*` → platform cache dir + `CAP/{app_id}/`
4. Validate paths to prevent traversal (reject `..`, absolute paths, symlink escapes)

#### 3.3–3.5 Notifications, Crypto Keystore, Native Accel

Follow the same pattern. For native accel, implement as a stub that logs the request and returns an error explaining it's not yet supported — this is the most dangerous capability and needs a thorough design before implementation.

---

### Phase 4+ — Multi-Platform Runtimes

If you reach this phase:

#### 4.1 Web Runtime

Create `crates/cap-runtime-web/` as a Rust crate compiled to WASM (via `wasm-bindgen`) that:
1. Parses a `.cap` file fetched via `fetch()`
2. Registers a Service Worker that serves assets from the in-memory blob map
3. Exposes `window.CAP` using browser-native APIs (IndexedDB for KV, Notification API, etc.)
4. Degrades gracefully — `window.CAP.fs` returns "not supported in web mode"

This is a large task. Start with just KV store + ping working in a browser.

---

### Verification Checkpoints

After each phase, verify:

- [ ] `cargo check --workspace` passes
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] The hello-cap example still builds and runs: `cap build --manifest examples/hello-cap/Cap.toml --key ./keys/publisher.ed25519.sk.json --out /tmp/test.cap`
- [ ] `ROADMAP.md` checkboxes are updated
- [ ] Any spec changes are reflected in `spec/CAP-1.0.md`
- [ ] All new code has tests

If a verification checkpoint fails, fix it before proceeding to the next phase.

---

### If You Get Stuck

1. **wry won't compile**: Check the version. Read wry's CHANGELOG for the pinned version. The API surface changes frequently. Look at wry's examples directory for the correct usage pattern.

2. **CBOR determinism is broken**: Switch to manually encoding signed types. Build a `BTreeMap<String, ciborium::Value>` with explicit field ordering and encode that instead of deriving Serialize.

3. **Custom protocol doesn't work on a platform**: Check wry's platform support matrix. Some platforms need `with_asynchronous_custom_protocol` instead of `with_custom_protocol`. Some need the scheme registered differently.

4. **Tests need a built .cap file**: Create a test helper function that builds a .cap from the hello-cap example to a tempdir. Reuse it across test files.

5. **Can't test WebView behavior in CI**: That's expected — headless WebView testing is fragile. Mark those tests `#[ignore]` with a comment explaining they require a display server. Focus integration tests on the format/packaging layer which is fully testable without a GUI.
