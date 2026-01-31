# CAP Next Steps

## Executive Summary

CAP is a capability-based app bundle format (.cap) with a Rust reference implementation. Currently at **Phase 0 - Foundation**: the format and CLI exist but there are **zero tests**, no CI, and the runtime may not compile against current wry. The ROADMAP has clear phases through security hardening (Phase 1) and delta updates (Phase 2).

---

## Priority 1: This Week

### 1.1 Fix CI / Make it Compile
- [ ] Pin `wry` to a working version in `Cargo.toml`
- [ ] Verify `cargo build --workspace` succeeds
- [ ] Set up basic GitHub Actions: `check`, `test`, `clippy`, `fmt`

### 1.2 Write First Tests
- [ ] Unit test: TOML manifest → CBOR roundtrip
- [ ] Unit test: Key generation/load/save
- [ ] Integration test: Build hello-cap.cap → verify signature → verify blob hashes
- [ ] Integration test: Tamper with blob → verify it fails

### 1.3 Audit CBOR Determinism
- [ ] Verify `ciborium` produces identical bytes for identical manifests
- [ ] Test with differently-ordered HashMaps to ensure canonicalization
- [ ] Document findings (this affects signature portability across platforms)

**Blocker Risk:** HIGH - Without this, signatures may not be portable.

---

## Priority 2: Next 2-4 Weeks

### 2.1 Security Hardening - CSP
- [ ] Inject strict CSP into WebView (no inline scripts, no eval, no external resources)
- [ ] Allow manifest to declare CSP overrides for network capabilities
- [ ] Runtime merges manifest CSP with baseline that cannot be weakened

### 2.2 Security Hardening - WASM Sandboxing
- [ ] Enforce memory limits on WASM cores
- [ ] Add execution fuel/metering to prevent infinite loops
- [ ] Document current threat model (WASM in same process as WebView)

### 2.3 KV Store Encryption
- [ ] Encrypt KV data at rest using platform secrets (Keychain/DPAPI/secret-tool)
- [ ] Derive key from app ID + platform secret
- [ ] Add `crypto_keystore` capability

### 2.4 Complete Test Suite
- [ ] cap-core-sdk: alloc/dealloc, invoke encoding tests
- [ ] Snapshot tests for CBOR output
- [ ] Cross-platform CI matrix (macOS, Linux, Windows)
- [ ] wasm32-unknown-unknown build check

---

## Priority 3: Months Out

### 3.1 Merkle Tree Index
- [ ] Replace flat root hash with binary Merkle tree over (path, hash) pairs
- [ ] Enables partial verification and delta updates

### 3.2 Delta Update Protocol
- [ ] Client fetches new manifest, computes needed blobs
- [ ] Download only changed blobs via content-addressed fetch
- [ ] Verify partial tree against known-good root hash

### 3.3 Key Pinning & Rotation
- [ ] TOFU (Trust On First Use) key pinning
- [ ] Key rotation with attestation chain
- [ ] `cap keys rotate` CLI command

### 3.4 Production Runtime
- [ ] iOS runtime shell
- [ ] Android runtime shell
- [ ] Web runtime (WASM-only mode)

---

## Blockers / Questions

1. **Wry version:** What version of wry was this built against? Current code may not compile.

2. **CBOR library:** Is `ciborium` deterministic enough for signatures? Need to verify or switch.

3. **Test strategy:** No tests currently exist. What's the priority - unit tests first or integration tests?

4. **Security audit:** Before Phase 1 security work, should there be a threat model document?

5. **Hello-cap status:** Does the example app currently work end-to-end?

---

## Current State Quick Check

```bash
# Does it build?
cargo build --workspace

# Does hello-cap work?
cap build --manifest examples/hello-cap/Cap.toml --key ./keys/publisher.ed25519.sk.json --out ./hello.cap
cap run ./hello.cap --pubkey ./keys/publisher.ed25519.pk.json

# How many tests?
cargo test --workspace  # Currently: 0
```

---

*Generated: 2026-01-31*
