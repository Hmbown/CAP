# CAP Roadmap

This document lays out the development trajectory for CAP from reference implementation to production-grade ecosystem. Each phase identifies **what to build**, **what problems it solves**, and **known risks** that need to be addressed.

---

## Phase 0 — Stabilize the Foundation

**Goal:** Make the existing reference implementation reliable enough to build on.

### 0.1 Test Suite

- [ ] Unit tests for `cap-format`: manifest TOML/CBOR round-trip, index serialization, root hash computation, key generation/load/save
- [ ] Unit tests for `cap-core-sdk`: alloc/dealloc, invoke encoding, `cap_export!` macro
- [ ] Integration test: build a `.cap` from the hello-cap example, open it with `CapReader`, verify signature and all blob hashes
- [ ] Integration test: tamper with a blob and confirm verification fails
- [ ] Integration test: tamper with the manifest and confirm root hash mismatch
- [ ] Snapshot tests for CBOR output to catch accidental serialization changes

**Problem this solves:** There are currently zero tests. Any change to the format crate could silently break signature verification or packaging without anyone noticing.

### 0.2 CI Pipeline

- [ ] GitHub Actions workflow: `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, `cargo fmt --check`
- [ ] Cross-compile check for `wasm32-unknown-unknown` target (cap-core-sdk + hello-cap core)
- [ ] macOS, Linux, and Windows matrix for the desktop runtime (wry has platform-specific behavior)

**Problem this solves:** Without CI, contributors can't tell if their changes break other platforms. The wry crate in particular behaves differently across OSes.

### 0.3 CBOR Canonicalization Audit

- [ ] Verify that `ciborium` produces deterministic output for the exact types used in `Manifest` and `Index`
- [ ] Add a test that serializes the same manifest from two differently-ordered in-memory representations and asserts byte-identical CBOR
- [ ] If ciborium is non-deterministic for any field type, switch to explicit canonical encoding or pin field order

**Problem this solves:** Signatures are computed over CBOR bytes. If two implementations serialize the same logical manifest to different bytes, signatures become non-portable. This is the single most dangerous correctness risk in the format — a subtle non-determinism bug means `.cap` files built on one machine can't be verified on another. `BTreeMap` handles key ordering, but CBOR integer widths, optional field encoding, and string normalization also matter.

### 0.4 Wry API Compatibility

- [ ] Pin `wry` to a specific version in `Cargo.toml` and document the required version
- [ ] Audit the `wry` custom protocol API — the current code uses patterns from an older wry version; the event loop and webview builder APIs have changed across 0.x releases
- [ ] Add a build-verification test that opens and closes a WebView headlessly (or confirm this isn't feasible and document manual testing)

**Problem this solves:** `wry` is pre-1.0 and has made breaking API changes between minor versions. The current code may not compile against the latest wry release.

---

## Phase 1 — Security Hardening

**Goal:** Close the gaps between "demo" and "actually safe to run untrusted packages."

### 1.1 Content Security Policy

- [ ] Inject a strict CSP into the WebView that blocks inline scripts, eval, and external resource loading by default
- [ ] Allow the manifest to declare CSP overrides (e.g., apps that need `connect-src` for network capability)
- [ ] The runtime must merge the manifest's CSP with a baseline policy that cannot be weakened

**Problem this solves:** Right now the WebView has no CSP. A compromised UI asset could load arbitrary external scripts, exfiltrate data via image tags, or use eval-based attacks — all bypassing the capability model entirely.

### 1.2 WASM Sandboxing

- [ ] Enforce memory limits on the WASM core (currently no limit — a malicious module could allocate unbounded memory)
- [ ] Add execution time limits (fuel/metering) to prevent infinite loops in wasm cores
- [ ] Consider running the WASM module in a separate process or thread with its own memory budget

**Problem this solves:** The WASM core runs in the same process as the WebView. A malicious or buggy core can OOM the host or hang the UI thread.

### 1.3 KV Store Encryption

- [ ] Encrypt persistent KV data at rest (currently stored as plaintext JSON in a well-known config directory)
- [ ] Derive encryption key from the app ID + a platform secret (macOS Keychain, Windows DPAPI, Linux secret-tool)
- [ ] Add `crypto_keystore` capability enforcement for apps that need raw keystore access

**Problem this solves:** Any process on the user's machine can read another CAP app's persistent KV data. For apps that store tokens, preferences, or sensitive state, this is a data exposure risk.

### 1.4 Key Pinning and Rotation

- [ ] Design a key pinning mechanism: first-run pin (TOFU) + optional out-of-band pin configuration
- [ ] Support key rotation: new `.cap` signed by key B includes a "rotation attestation" signed by key A
- [ ] Add `cap keys rotate` CLI command

**Problem this solves:** The only current verification option is "pass a pubkey file on the command line." There's no mechanism to remember which key a given app was signed with, or to safely transition to a new key when the old one is compromised or expired.

### 1.5 Rate Limiting and Abuse Prevention

- [ ] Rate-limit capability API calls (e.g., max N KV writes per second)
- [ ] Add size limits to KV keys and values
- [ ] Log capability usage for auditability

**Problem this solves:** A malicious UI could flood the KV store with writes, fill the disk, or abuse other capabilities at high frequency. There are no guardrails on API call volume.

---

## Phase 2 — Real Merkle Index and Delta Updates

**Goal:** Replace the flat root hash with a proper Merkle tree and implement the delta update protocol.

### 2.1 Merkle Tree Index

- [ ] Replace `compute_root()` with a binary Merkle tree over (path, hash) pairs
- [ ] Store the Merkle tree structure in `_cap/index.cbor` (or a separate `_cap/merkle.cbor`)
- [ ] Support inclusion proofs: given a virtual path, produce a proof that it belongs to the signed root
- [ ] Support partial verification: verify a subset of files without downloading the full index

**Problem this solves:** The current root hash is a flat SHA-256 over the concatenation of all paths and hashes. This means:
- You must have the complete index to verify anything (no partial verification)
- Delta updates can't prove "this blob is part of the signed set" without the full index
- There's no efficient way to identify which blobs changed between two versions

**Risk:** This is a **breaking change** to the root hash computation. Every existing `.cap` file's signature will become invalid. Must be done before any real adoption, or require a `cap_version` bump.

### 2.2 Delta Update Protocol

- [ ] Implement root negotiation: client sends current root hash, server responds with new root + list of changed blob hashes
- [ ] Implement blob fetch: client downloads only missing/changed blobs
- [ ] Implement atomic swap: replace the active root only after all blobs are verified
- [ ] Add `cap update` CLI command
- [ ] Define the HTTP API contract for update servers

**Problem this solves:** Currently the only way to update an app is to download the entire `.cap` file again. For large apps, this wastes bandwidth and time. Content-addressed blobs make delta updates possible, but no protocol exists yet.

**Risk:** The update protocol needs to handle interrupted downloads, partial state, and rollback. A half-applied update that leaves the app in an inconsistent state is worse than no update mechanism at all.

### 2.3 Update Channel Signing

- [ ] Support multiple update channels (stable, beta, canary) with independent signing keys
- [ ] Add channel pinning to the manifest's `[updates]` section
- [ ] Implement rollback: revert to a previous root if the new version is broken

**Problem this solves:** The manifest has an `[updates]` section with `channel` and `rollback` fields, but they're not enforced anywhere. Without channel signing, an attacker who compromises the update server can serve arbitrary packages.

---

## Phase 3 — Complete Capability Implementation

**Goal:** Implement all declared capability types so the runtime actually enforces the full security model.

### 3.1 Network Capability

- [ ] Intercept all network requests from the WebView (fetch, XHR, WebSocket, image/script/link loads)
- [ ] Block requests that don't match `network.allow` URL patterns
- [ ] Support wildcard patterns and scheme restrictions
- [ ] Return clear errors to the UI when a request is blocked

**Problem this solves:** The manifest can declare `[capabilities.network]` with an allowlist, but the runtime doesn't enforce it. The WebView can currently make arbitrary network requests.

**Risk:** Intercepting network requests reliably in wry is platform-dependent. macOS WKWebView, Windows WebView2, and Linux WebKitGTK all have different interception APIs. Some don't support intercepting WebSocket connections.

### 3.2 Filesystem Capability

- [ ] Implement scoped filesystem access via the `window.CAP.fs` API
- [ ] Map virtual scopes (`documents://app/*`, `cache://app/*`) to platform-appropriate directories
- [ ] Enforce read/write/list permissions per scope
- [ ] Prevent path traversal attacks (e.g., `documents://app/../../etc/passwd`)

**Problem this solves:** The manifest can declare filesystem scopes, but there's no implementation. Apps that need to read/write files have no way to do so.

### 3.3 Notifications Capability

- [ ] Implement `window.CAP.notifications.send()` API
- [ ] Gate behind `capabilities.notifications` check
- [ ] Use platform-native notification APIs (macOS `NSUserNotification`/`UNUserNotificationCenter`, Windows toast, Linux `notify-send`)

### 3.4 Crypto Keystore Capability

- [ ] Implement `window.CAP.keystore` API for storing/retrieving secrets
- [ ] Use platform keychain (macOS Keychain, Windows Credential Manager, Linux secret-service)
- [ ] Scope keystore entries by app ID to prevent cross-app access

### 3.5 Native Acceleration Capability

- [ ] Define the native module loading mechanism (shared libraries? additional WASM modules?)
- [ ] Implement allowlist enforcement from `capabilities.native_accel`
- [ ] Sandbox native modules (this is the hardest capability to make safe)

**Risk:** Native modules are inherently dangerous — they run outside the WASM sandbox with host privileges. The allowlist approach only works if module identifiers are trustworthy, which requires its own signing/verification chain.

---

## Phase 4 — Multi-Platform Runtimes

**Goal:** Deliver on the "one artifact, every platform" promise.

### 4.1 Web Runtime

- [ ] Build a `cap-runtime-web` that runs `.cap` files in a standard browser
- [ ] Serve assets from a Service Worker or in-memory cache
- [ ] Map `window.CAP` APIs to browser equivalents (IndexedDB for KV, Notification API, etc.)
- [ ] Degrade gracefully when capabilities aren't available (e.g., no filesystem access in browser)

**Problem this solves:** CAP claims to work on the web, but there's no web runtime. The current implementation is desktop-only.

**Risk:** Browsers don't support custom protocols like `cap://`. The web runtime will need a fundamentally different asset-serving strategy (Service Worker, blob URLs, or a bundler). This may require changes to how UI assets reference each other (relative paths vs. absolute cap:// URLs).

### 4.2 iOS Runtime

- [ ] Build `cap-runtime-ios` using WKWebView
- [ ] Implement capability APIs using iOS frameworks (UserDefaults/CoreData for KV, Keychain for crypto, UNNotification for notifications)
- [ ] Package as an iOS framework that host apps can embed
- [ ] Handle App Store review requirements (no arbitrary code execution concerns — WASM is interpreted, not JIT'd on iOS)

**Risk:** Apple's App Store policies around code execution are strict. While WASM interpretation is generally allowed, the capability model needs to align with iOS permission prompts (location, photos, etc.) which work differently than CAP's declare-at-build-time model.

### 4.3 Android Runtime

- [ ] Build `cap-runtime-android` using Android WebView
- [ ] Implement capability APIs using Android frameworks
- [ ] Package as an AAR library
- [ ] Handle Play Store policies

### 4.4 HarmonyOS Runtime

- [ ] Build `cap-runtime-harmony` using HarmonyOS WebView
- [ ] This was listed in the manifest's `targets` section — research HarmonyOS WebView capabilities and constraints

---

## Phase 5 — Developer Experience and Ecosystem

**Goal:** Make it practical for developers to build, distribute, and maintain CAP apps.

### 5.1 Developer Tooling

- [ ] `cap init` — scaffold a new CAP app (interactive manifest creation, directory structure, starter UI)
- [ ] `cap dev` — local dev server with hot reload (watch UI files, rebuild and refresh WebView)
- [ ] `cap lint` — validate `Cap.toml` against the spec (required fields, valid capability syntax, version format)
- [ ] `cap diff <a.cap> <b.cap>` — show what changed between two versions (added/removed/modified files, manifest diffs, blob-level delta size)
- [ ] `cap size` — size analysis (largest blobs, deduplication savings, compression ratios)

**Problem this solves:** The current developer experience is: edit files, run `cap build`, run `cap run`, repeat. No hot reload, no scaffolding, no validation feedback. This friction will prevent adoption.

### 5.2 Package Registry

- [ ] Design a registry protocol (publish, fetch, search, version resolution)
- [ ] Implement `cap publish` and `cap install` CLI commands
- [ ] Build a reference registry server
- [ ] Support private registries for enterprise use
- [ ] Integrate with the delta update protocol (registry serves blob diffs)

**Problem this solves:** There's no way to distribute `.cap` files except manually copying them. Without a registry, there's no ecosystem.

**Risk:** A package registry is a high-value attack target. It needs:
- Publisher identity verification (not just "anyone with an Ed25519 key")
- Package name squatting prevention
- Malware scanning or at least reproducible build verification
- Availability guarantees (CDN, mirrors)

### 5.3 Enterprise Policy Overlays

- [ ] Design a policy overlay format that enterprises can apply on top of the manifest's declared capabilities
- [ ] Support restricting capabilities (e.g., "this org blocks all network access for CAP apps")
- [ ] Support requiring capabilities (e.g., "all apps in this org must declare `data_contract.telemetry = off`")
- [ ] Implement `cap policy apply` and `cap policy verify` CLI commands
- [ ] MDM (Mobile Device Management) integration points

**Problem this solves:** Enterprises need to control what apps can do beyond what the publisher declares. The spec mentions "enterprise policy overlays" but provides no implementation.

### 5.4 Capability Schema Registry

- [ ] Define a schema format for capability types (inputs, outputs, constraints)
- [ ] Allow third-party capabilities to be registered (e.g., `bluetooth`, `camera`, `geolocation`)
- [ ] Runtime discovers capability schemas and validates manifest declarations against them
- [ ] Version capabilities independently from the core spec

**Problem this solves:** The current set of capabilities is hardcoded in the `Capabilities` struct. Adding a new capability requires changing the format crate, runtime, and spec. This doesn't scale to the diversity of platform APIs.

---

## Phase 6 — Format Evolution

**Goal:** Address the long-term limitations of the ZIP transport and current cryptographic choices.

### 6.1 Streaming Container

- [ ] Design a streaming container format to replace ZIP (chunk table + Merkle tree, seekable but also streamable)
- [ ] Support progressive loading: start rendering UI before all blobs are downloaded
- [ ] Maintain backward compatibility: runtimes should handle both ZIP and streaming containers via `cap_version` detection

**Problem this solves:** ZIP requires seeking to read the central directory (located at the end of the file). This makes it impossible to start processing a `.cap` file while it's still downloading. For large apps, this means the user waits for the entire download before anything happens.

**Risk:** Designing a new container format is a large undertaking. Getting it wrong means another migration later. Consider adopting an existing format (e.g., a subset of CSAR, or a custom flatbuffer-based format) rather than inventing one.

### 6.2 Cryptographic Agility

- [ ] Support multiple signature algorithms (Ed25519, Ed448, ECDSA P-256) via an algorithm field in the signature metadata
- [ ] Support multiple hash algorithms (SHA-256, SHA-3, BLAKE3) via an algorithm field in the index
- [ ] Design the migration path: how does a runtime that only knows SHA-256 handle a SHA-3 package?

**Problem this solves:** Ed25519 and SHA-256 are the only options. If either is broken or deprecated, every `.cap` file and every runtime must be updated simultaneously. Algorithm agility is a standard requirement for long-lived cryptographic formats.

**Risk:** Cryptographic agility itself is a security risk — it creates downgrade attack surface. The design must prevent an attacker from forcing use of a weaker algorithm. Consider a "mandatory minimum" approach where new algorithms can be added but old ones can only be removed by spec version bump.

### 6.3 Encrypted Blob Payloads

- [ ] Support encrypting blob payloads for confidential distribution (enterprise DRM, private beta)
- [ ] Key distribution mechanism (per-device keys, group keys, or key-wrapping)
- [ ] Separate encryption from signing — a package can be signed (publicly verifiable) and encrypted (privately readable)

**Problem this solves:** Currently all `.cap` contents are readable by anyone who has the file. Some distribution scenarios require confidentiality (internal enterprise apps, paid apps before purchase, beta programs).

### 6.4 Reproducible Builds

- [ ] Document the exact build pipeline required for reproducible `.cap` output
- [ ] Ensure `cap build` with the same inputs always produces byte-identical output (pin zstd level, sort order, CBOR encoding, ZIP entry order)
- [ ] Add `cap reproduce` command that verifies a `.cap` matches its claimed source

**Problem this solves:** Without reproducible builds, there's no way to verify that a published `.cap` actually corresponds to its claimed source code. This is essential for trust in the supply chain.

**Risk:** Reproducible builds are notoriously difficult. Timestamps, file ordering, compression dictionary differences, and floating-point determinism can all cause non-reproducibility. The ZIP format itself includes timestamps that must be zeroed or pinned.

---

## Cross-Phase Concerns

### Documentation

- [ ] API reference for `window.CAP` JavaScript surface
- [ ] Guide: "Building your first CAP app"
- [ ] Guide: "Porting an existing web app to CAP"
- [ ] Architecture decision records (ADRs) for major design choices
- [ ] Threat model document

### Performance

- [ ] Benchmark: package build time vs. package size
- [ ] Benchmark: cold start time (open `.cap` -> first paint)
- [ ] Profile memory usage of the desktop runtime (all assets loaded into memory currently)
- [ ] Lazy blob loading: don't decompress all assets at startup; decompress on first access

**Problem this solves:** The current runtime loads ALL UI assets into memory at startup (`read_prefix`). For large apps with many images/fonts, this will cause unacceptable startup times and memory usage.

### Accessibility

- [ ] Ensure the WebView runtime respects platform accessibility settings
- [ ] Add manifest fields for accessibility metadata (language, screen reader hints)
- [ ] Test with screen readers on each platform

---

## Known Architectural Risks (Summary)

| Risk | Severity | Phase | Notes |
|---|---|---|---|
| CBOR non-determinism breaks signatures across implementations | **Critical** | 0 | Must verify before any real adoption |
| No tests — regressions go undetected | **Critical** | 0 | Blocking for all other work |
| No CSP in WebView — capability model is bypassable | **High** | 1 | XSS in a UI asset = full capability bypass |
| Root hash is not a Merkle tree — blocks delta updates | **High** | 2 | Breaking change to root computation |
| Only KV store capability is actually enforced | **High** | 3 | Five of six capability types are declared but not implemented |
| WebView network requests are uncontrolled | **High** | 3 | Apps can phone home regardless of manifest |
| All assets loaded into memory at startup | **Medium** | Perf | Will fail for large apps |
| wry API instability across versions | **Medium** | 0 | May not compile against latest wry |
| No web/mobile runtimes | **Medium** | 4 | Core value proposition is cross-platform |
| ZIP transport can't stream | **Medium** | 6 | Blocks progressive loading |
| Ed25519-only, SHA-256-only | **Low** | 6 | Fine for now, plan for agility |
| No package registry | **Low** | 5 | Manual distribution works for early adoption |
