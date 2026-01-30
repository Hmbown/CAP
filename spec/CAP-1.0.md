# CAP 1.0 — Capability Application Package

**Status:** Draft 1.0 (transport = ZIP, canonical container TBD)**File extension:** `.cap`**Goal:** a single, inspectable, signed application artifact for desktop, mobile, and web.

---

## 1. Rationale

CAP is a response to three problems in “cross-platform apps”:

1. **Opaque blobs**: users and enterprises can’t easily inspect what an app does.
2. **Ambient authority**: common desktop shells default to “everything can access everything.”
3. **Inefficient updates**: installers and store artifacts download too much, too often.

CAP addresses this by making an app a **signed bundle of (UI + code + policy)** with **content-addressed blobs**
and an explicit, enforceable **capability surface**.

---

## 2. Terminology

- **CAP file**: the `.cap` container.
- **Publisher**: entity that signs the CAP root.
- **Shell / Runtime**: platform-specific host responsible for enforcing capabilities and rendering UI.
- **UI**: web assets rendered in a WebView (desktop/mobile) or browser (web mode).
- **Core**: portable compute module(s), typically WebAssembly.
- **Blob**: a content-addressed byte array (SHA-256 hash).
- **Index**: mapping from virtual paths → blob hashes and metadata.
- **Manifest**: the app metadata + entrypoints + capability declarations.
- **Root hash**: a hash of the manifest hash + index mapping.
- **Signature**: Ed25519 signature over the root hash.

---

## 3. Transport container (CAP 1.0)

CAP 1.0 uses **ZIP** as the transport container for ease of distribution and tooling.
ZIP is NOT the long-term constraint; the internal layout is designed to be transferable to a
dedicated streaming container later.

A CAP ZIP contains:

```
_cap/manifest.cbor         # canonical CBOR manifest
_cap/index.cbor            # canonical CBOR index
_cap/root.sha256           # hex-encoded root hash (SHA-256, 32 bytes)
_cap/signature.ed25519     # raw 64-byte Ed25519 signature over root
_cap/publisher.ed25519.pk  # optional raw 32-byte verifying key (convenience only)
blobs/<sha256>.zst         # zstd-compressed blob payloads, content-addressed
```

### 3.1. Constraints
- ZIP entries SHOULD be stored without additional ZIP compression for deterministic hashing.
- Blobs are individually compressed with Zstandard (`.zst`) to support delta-friendly chunking.

---

## 4. Content addressing

Each file included in the app is stored as a **blob**:

- `hash = SHA-256(raw_bytes)`
- payload stored as: `zstd(raw_bytes)` at `blobs/<hex(hash)>.zst`

The same blob may be referenced by multiple virtual paths (dedupe).

---

## 5. Index (CBOR)

The Index maps virtual paths (POSIX-style, UTF-8) to blob references.

### 5.1. Canonical form
CAP 1.0 requires index maps to be encoded using deterministic ordering:

- Top-level file map MUST be ordered lexicographically by path.
- Nested maps MUST be ordered lexicographically by key.

(Reference implementation uses `BTreeMap` in Rust to enforce ordering.)

### 5.2. Schema (logical)

```
Index {
  files: map<path, FileEntry>
}

FileEntry {
  hash: hex-string(sha256)          # 64 hex chars
  size: uint                        # raw byte length
  compressed_size: uint             # zstd payload length
  compression: "zstd"
  mime: optional string             # e.g. "text/html"
}
```

---

## 6. Manifest (CBOR)

The manifest declares:

- app identity + versioning
- entrypoints (UI, optional core wasm)
- capability declarations (policy)
- optional privacy/data contract
- optional update channels

### 6.1. Schema (logical)

```
Manifest {
  cap_version: 1
  app: { id, name, version, publisher, ... }
  entrypoints: { ui, core_wasm? }
  targets?: { ... }                 # wrappers/export hints
  capabilities: { ... }             # typed capabilities
  data_contract?: { ... }
  updates?: { ... }
  signing?: { ... }
}
```

---

## 7. Root hash and signature

### 7.1. Manifest hash
`manifest_hash = SHA-256(manifest.cbor_bytes)`

### 7.2. Root hash
The root hash binds the manifest to the set of file paths and their blob hashes.

Reference algorithm:

```
H = SHA-256()
H.update("CAPROOT\0")
H.update(manifest_hash)

for each (path, entry) in index.files sorted by path:
  H.update(path_bytes)
  H.update("\0")
  H.update(bytes_from_hex(entry.hash))
  H.update("\n")

root = H.finalize()
```

### 7.3. Signature
CAP 1.0 uses Ed25519:

`signature = ed25519_sign(publisher_sk, root)`

Verification:

`ed25519_verify(publisher_pk, root, signature)`

---

## 8. Capability grammar (CAP 1.0)

Capabilities are **typed** and **scoped**. If not declared, the operation MUST be denied.

### 8.1. Example capability set

- `network.allow`: allowlist of URL origins (scheme+host+port)
- `filesystem.scopes`: virtual roots mapped by the shell (e.g. `documents://app/*`)
- `kv_store`: key-value storage (persistent or volatile)
- `notifications`: permission to request notifications
- `crypto_keystore`: access to OS keystore
- `native_accel`: permission to load native modules (names allowlisted)

### 8.2. Policy enforcement
- Shell MUST enforce capability checks at the boundary where privileged behavior occurs.
- Shell SHOULD expose an inspection UI to show requested capabilities at install/run time.

---

## 9. Execution model

CAP does not mandate a single UI framework. A common pattern:

- UI runs in a WebView and loads `core_wasm` (if present) with `WebAssembly.instantiate`.
- Shell exposes privileged operations through an injected JS API (e.g. `window.CAP.*`),
  which routes through a secure bridge that enforces the manifest-declared capabilities.

This enables:
- “same core runs on web” (browser provides limited host APIs)
- “same core runs on desktop/mobile” (shell provides richer capabilities)

---

## 10. Updates (delta-friendly)

Because blobs are content-addressed:
- A new release is (mostly) “the same blobs + a new manifest/index/root.”
- A CAP store can ship only missing blob hashes.

A minimal update protocol:
1. client requests latest `root` for app id + channel
2. if signature valid and policy allows, download missing blobs
3. atomically swap to new root

---

## 11. Security considerations

- Treat `_cap/publisher.ed25519.pk` as **convenience only**; policy engines should pin known keys.
- Disallow native modules unless `native_accel` is granted.
- Consider “enterprise policy overlays” that can further restrict capabilities at install time.
- Prefer sandboxed storage roots (`vault://`, `documents://`) over raw filesystem paths.

---

## 12. Future work

- Replace ZIP transport with a streaming container (chunk table + Merkle tree) while preserving the same logical model.
- Standardize a transparency log format for publisher key attestations and revocations.
- Add optional encrypted blob payloads (enterprise distribution).
