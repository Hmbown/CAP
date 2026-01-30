# AGENTS.md — Multi-Agent Coordination for CAP

This file defines agent roles, responsibilities, and workflows for AI-assisted development on the CAP codebase.

## Agent Roles

### Format Agent

**Scope:** `crates/cap-format/`, `spec/CAP-1.0.md`

**Responsibilities:**
- Maintain the CAP format specification and its Rust implementation
- Evolve manifest schema, index structures, and content addressing
- Implement packaging (`build_cap_from_manifest`), reading (`CapReader`), and verification
- Ensure CBOR/TOML serialization round-trips are correct
- Manage Ed25519 signing and key management utilities

**Key constraints:**
- Changes to `compute_root()` or manifest CBOR encoding are **breaking** — they invalidate all existing `.cap` signatures
- Index paths must remain lexicographically sorted
- ZIP entries must stay uncompressed (blob-level zstd only)
- Keep `spec/CAP-1.0.md` in sync with any structural changes

### CLI Agent

**Scope:** `crates/cap-cli/`

**Responsibilities:**
- Implement and maintain CLI subcommands (`keys`, `build`, `inspect`, `verify`, `run`)
- User-facing error messages and output formatting
- Integrate with `cap-format` for packaging and `cap-runtime-desktop` for execution

**Key constraints:**
- Uses `clap` derive macros — follow existing patterns for new subcommands
- Error handling via `anyhow` — surface actionable messages
- `cap run` delegates to `cap-runtime-desktop::run()` — don't duplicate runtime logic

### Runtime Agent

**Scope:** `crates/cap-runtime-desktop/`

**Responsibilities:**
- Desktop WebView shell (via `wry`) with `cap://` custom protocol
- JavaScript API injection (`window.CAP`) and capability enforcement
- Asset serving from in-memory blob map
- Implement capability-gated APIs (KV store, future: network, filesystem, etc.)

**Key constraints:**
- Every API endpoint must check the manifest's declared capabilities before execution
- The `cap://` protocol handler serves assets and routes `/__cap/*` API calls
- KV persistence uses `directories::ProjectDirs` for platform-appropriate paths
- Thread safety: KV store uses `Arc<Mutex<>>` for concurrent access

### SDK Agent

**Scope:** `crates/cap-core-sdk/`

**Responsibilities:**
- Maintain the stable WASM ABI (`cap_alloc`, `cap_dealloc`, `cap_invoke`)
- Provide the `cap_export!` macro for core module authors
- Keep `Invocation`/`Reply` types and JSON encoding stable

**Key constraints:**
- ABI is `extern "C"` — changes break all existing WASM cores
- Memory management: `cap_alloc` uses `Vec::with_capacity` + `mem::forget`; `cap_dealloc` reconstructs the `Vec`
- `cap_invoke` returns a packed `u64` (ptr in high 32 bits, len in low 32 bits)

### Example Agent

**Scope:** `examples/hello-cap/`

**Responsibilities:**
- Maintain the hello-cap reference app as a working demo
- Keep `Cap.toml` manifest, UI assets, and WASM core in sync with format changes
- Ensure the prebuilt `hello_cap_core.wasm` is up to date

**Key constraints:**
- UI is plain HTML/JS — no build tooling or framework dependencies
- WASM glue (`wasm_glue.js`) must match the `cap_invoke` ABI exactly
- `Cap.toml` serves as the canonical template for new app manifests

## Cross-Cutting Workflows

### Adding a New Capability

Involves: **Format Agent** + **Runtime Agent** + **Example Agent**

1. **Format Agent:** Add capability struct to `Manifest.capabilities` in `manifest.rs`. Update TOML parsing. Update `spec/CAP-1.0.md`.
2. **Runtime Agent:** Add enforcement logic in `handle_api()`. Expose new JS method in `cap_init_script()`.
3. **Example Agent:** Optionally add a demo usage to `hello-cap` or create a new example.

### Changing the Manifest Schema

Involves: **Format Agent** + **CLI Agent** + **Runtime Agent**

1. **Format Agent:** Update `Manifest` struct, CBOR encoding, and TOML loading.
2. **CLI Agent:** Update `inspect` output to display new fields.
3. **Runtime Agent:** Consume new manifest fields as needed (e.g., new entrypoint types).
4. **Format Agent:** Bump guidance in spec if this is a breaking change.

### Evolving the WASM ABI

Involves: **SDK Agent** + **Runtime Agent** + **Example Agent**

1. **SDK Agent:** Modify ABI exports or `Invocation`/`Reply` types.
2. **Runtime Agent:** Update WASM instantiation or invocation glue if the calling convention changes.
3. **Example Agent:** Rebuild `hello_cap_core.wasm` and update `wasm_glue.js`.

### Release Checklist

1. All crates compile: `cargo check --workspace`
2. All tests pass: `cargo test --workspace`
3. Example app builds and runs: `scripts/demo.sh`
4. Spec document reflects current implementation
5. Version numbers bumped in relevant `Cargo.toml` files
6. CLAUDE.md and AGENTS.md updated if architecture changed

## Coordination Rules

- **Spec is source of truth.** If implementation diverges from `spec/CAP-1.0.md`, the spec wins unless an explicit spec amendment is agreed upon.
- **Signature-breaking changes require explicit approval.** Any change to root hash computation, manifest CBOR encoding, or signing flow must be flagged.
- **ABI stability.** The `cap_invoke` WASM ABI is frozen for the current major version. Use new exports rather than modifying existing ones.
- **Capability enforcement is mandatory.** Never expose a privileged operation without checking the manifest's capability declarations.
- **Test at the boundary.** Integration tests should exercise the full pipeline: build `.cap` -> verify -> run.
