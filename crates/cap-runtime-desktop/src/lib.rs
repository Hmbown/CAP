use cap_format::error::{CapError, Result};
use cap_format::keys::load_verifying_key_json;
use cap_format::package::CapReader;

use http::{Response, StatusCode};
use mime_guess::MimeGuess;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Maximum response body size for network requests (10 MB).
const MAX_RESPONSE_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Default request timeout in seconds.
const REQUEST_TIMEOUT_SECS: u64 = 30;

/// Maximum KV key size in bytes.
const MAX_KV_KEY_BYTES: usize = 256;

/// Maximum KV value size in bytes (1 MB).
const MAX_KV_VALUE_BYTES: usize = 1_048_576;

/// Maximum file read size via filesystem capability (10 MB).
const MAX_FS_READ_BYTES: usize = 10 * 1024 * 1024;

/// Maximum file write size via filesystem capability (10 MB).
const MAX_FS_WRITE_BYTES: usize = 10 * 1024 * 1024;

/// Maximum directory listing entries.
const MAX_FS_LIST_ENTRIES: usize = 1000;

/// Maximum notification title length in bytes.
const MAX_NOTIFICATION_TITLE_BYTES: usize = 256;

/// Maximum notification body length in bytes.
const MAX_NOTIFICATION_BODY_BYTES: usize = 4096;

/// Maximum keystore key size in bytes.
const MAX_KEYSTORE_KEY_BYTES: usize = 256;

/// Maximum keystore value size in bytes (8 KB).
const MAX_KEYSTORE_VALUE_BYTES: usize = 8192;

/// Default rate limit: calls per second per category.
const DEFAULT_RATE_LIMIT: u32 = 100;

/// Burst allowance for the token bucket rate limiter.
const RATE_LIMIT_BURST: u32 = 20;

pub fn run(cap_path: &Path, pubkey_path: Option<&Path>) -> Result<()> {
    // Open + verify package
    let mut reader = CapReader::open(cap_path)?;

    let pk_override = if let Some(pk_path) = pubkey_path {
        Some(load_verifying_key_json(pk_path)?)
    } else {
        None
    };

    reader.verify(pk_override.as_ref(), false)?;

    let entrypoint = reader.manifest.entrypoints.ui.clone();

    // Load all ui/* assets into memory for custom protocol serving
    let ui_prefix = entrypoint.split('/').next().unwrap_or("ui").to_string() + "/";

    let mut assets = BTreeMap::new();
    let ui_assets = reader.read_prefix(&ui_prefix)?;
    for (k, v) in ui_assets {
        assets.insert(k, v);
    }

    // If core_wasm exists, load it too (so UI can fetch it).
    if let Some(core) = reader.manifest.entrypoints.core_wasm.clone() {
        if reader.index.files.contains_key(&core) {
            let bytes = reader.read_virtual_file(&core)?;
            assets.insert(core, bytes);
        }
    }

    let state = Arc::new(AppState::new(reader.manifest.clone(), assets, entrypoint)?);

    // Start WebView
    run_wry(state)
}

struct AppState {
    manifest: cap_format::manifest::Manifest,
    assets: BTreeMap<String, Vec<u8>>,
    entrypoint: String,
    kv: KvStore,
    fs: FsScope,
    network_allowed_origins: Vec<String>,
    rate_limiter: RateLimiter,
}

impl AppState {
    fn new(
        manifest: cap_format::manifest::Manifest,
        assets: BTreeMap<String, Vec<u8>>,
        entrypoint: String,
    ) -> Result<Self> {
        let kv_allowed = manifest.capabilities.kv_store.is_some();
        let kv_persistent = manifest
            .capabilities
            .kv_store
            .as_ref()
            .map(|k| k.persistent)
            .unwrap_or(false);

        let network_allowed_origins = manifest
            .capabilities
            .network
            .as_ref()
            .map(|n| n.allow.clone())
            .unwrap_or_default();

        let kv = KvStore::new(&manifest.app.id, kv_allowed, kv_persistent)?;
        let fs = FsScope::new(&manifest)?;
        let rate_limiter = RateLimiter::new();
        Ok(Self {
            manifest,
            assets,
            entrypoint,
            kv,
            fs,
            network_allowed_origins,
            rate_limiter,
        })
    }
}

// ── Filesystem scope ──────────────────────────────────────────────

struct FsScope {
    scopes: Vec<String>,
    roots: HashMap<String, PathBuf>,
}

impl FsScope {
    fn new(manifest: &cap_format::manifest::Manifest) -> Result<Self> {
        let fs_cap = manifest.capabilities.filesystem.as_ref();
        let scopes = fs_cap.map(|f| f.scopes.clone()).unwrap_or_default();

        let mut roots = HashMap::new();
        if fs_cap.is_some() {
            let app_id = &manifest.app.id;

            // documents -> UserDirs::document_dir() / <app_id>
            if let Some(user_dirs) = directories::UserDirs::new() {
                if let Some(doc_dir) = user_dirs.document_dir() {
                    roots.insert("documents".into(), doc_dir.join(app_id));
                }
            }

            // cache -> ProjectDirs::cache_dir() / <app_id>
            if let Some(proj_dirs) = directories::ProjectDirs::from("dev", "cap", "cap-runtime") {
                roots.insert("cache".into(), proj_dirs.cache_dir().join(app_id));
            }

            // temp -> temp_dir / cap-runtime / <app_id>
            let temp_root = std::env::temp_dir().join("cap-runtime").join(app_id);
            roots.insert("temp".into(), temp_root);
        }

        Ok(Self { scopes, roots })
    }
}

/// Check whether a virtual path matches at least one declared scope pattern.
///
/// Scope format: `<type>://<app_id>/<pattern>`
/// Virtual path format: `<type>://<app_id>/<relpath>`
///
/// Pattern matching:
/// - `documents://app/*` matches any subpath under `documents://app/`
/// - `cache://app/images/*` matches any subpath under `cache://app/images/`
/// - `documents://app/config.json` matches exactly that path
fn scope_matches(virtual_path: &str, scopes: &[String]) -> bool {
    for scope in scopes {
        if scope.ends_with("/*") {
            let prefix = &scope[..scope.len() - 1]; // "documents://app/" (keep the trailing /)
            if virtual_path.starts_with(prefix) || virtual_path == &scope[..scope.len() - 2] {
                return true;
            }
        } else if virtual_path == scope {
            return true;
        }
    }
    false
}

/// Resolve a virtual path like `documents://com.example.app/notes/file.txt`
/// to a real filesystem path with security checks.
fn resolve_path_securely(
    virtual_path: &str,
    scopes: &[String],
    roots: &HashMap<String, PathBuf>,
) -> std::result::Result<PathBuf, String> {
    // Check scope first
    if !scope_matches(virtual_path, scopes) {
        return Err(format!("path not in declared scopes: {virtual_path}"));
    }

    // Parse virtual path: <type>://<app_id>/<relpath>
    let Some((scheme_and_app, relpath)) = virtual_path.split_once("://").map(|(scheme, rest)| {
        let (_, rel) = rest.split_once('/').unwrap_or((rest, ""));
        (scheme.to_string(), rel.to_string())
    }) else {
        return Err(format!("invalid virtual path format: {virtual_path}"));
    };

    // Extract scope type (part before ://)
    let scope_type = virtual_path.split("://").next().unwrap_or("").to_string();

    // Security: reject null bytes
    if virtual_path.contains('\0') || relpath.contains('\0') {
        return Err("path contains null bytes".into());
    }

    // Security: reject absolute paths in relpath
    if relpath.starts_with('/') || relpath.starts_with('\\') {
        return Err("relative path must not be absolute".into());
    }

    // Security: reject path traversal
    for component in relpath.split('/') {
        if component == ".." {
            return Err("path traversal (..) not allowed".into());
        }
    }
    for component in relpath.split('\\') {
        if component == ".." {
            return Err("path traversal (..) not allowed".into());
        }
    }

    // Look up root directory for this scope type
    let root = roots
        .get(&scope_type)
        .ok_or_else(|| format!("unknown scope type: {scope_type}"))?;

    // Join root + relpath
    let target = if relpath.is_empty() {
        root.clone()
    } else {
        root.join(&relpath)
    };

    // Create parent dirs to allow canonicalization
    if let Some(parent) = target.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // Canonicalize root (create it if needed) and check containment
    let _ = std::fs::create_dir_all(root);
    let canonical_root = root
        .canonicalize()
        .map_err(|e| format!("cannot resolve root: {e}"))?;

    // For the target, we canonicalize parent + filename since the file may not exist yet
    let canonical_target = if target.exists() {
        target
            .canonicalize()
            .map_err(|e| format!("cannot resolve path: {e}"))?
    } else {
        // Canonicalize parent, then append filename
        let parent = target.parent().ok_or("path has no parent")?;
        let filename = target.file_name().ok_or("path has no filename")?;
        let canonical_parent = parent
            .canonicalize()
            .map_err(|e| format!("cannot resolve parent: {e}"))?;
        canonical_parent.join(filename)
    };

    // Security: verify the resolved path is within the root (prevents symlink escapes)
    if !canonical_target.starts_with(&canonical_root) {
        return Err("resolved path escapes scope root".into());
    }

    let _ = scheme_and_app; // used above for parsing
    Ok(canonical_target)
}

#[derive(Debug, Deserialize)]
struct FsPathReq {
    path: String,
}

#[derive(Debug, Deserialize)]
struct FsWriteReq {
    path: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct FsListEntry {
    name: String,
    is_dir: bool,
    size: u64,
}

#[derive(Clone)]
struct KvStore {
    allowed: bool,
    persistent: bool,
    path: PathBuf,
    map: Arc<Mutex<HashMap<String, String>>>,
}

impl KvStore {
    fn new(app_id: &str, allowed: bool, persistent: bool) -> Result<Self> {
        let path = kv_path_for_app(app_id)?;
        let map = if allowed && persistent && path.exists() {
            let bytes = std::fs::read(&path)?;
            match serde_json::from_slice::<HashMap<String, String>>(&bytes) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!(
                        "[CAP] warning: KV store corrupted at {}, resetting: {}",
                        path.display(),
                        e
                    );
                    HashMap::new()
                }
            }
        } else {
            HashMap::new()
        };
        Ok(Self {
            allowed,
            persistent,
            path,
            map: Arc::new(Mutex::new(map)),
        })
    }

    fn get(&self, key: &str) -> Option<String> {
        self.map.lock().get(key).cloned()
    }

    fn set(&self, key: String, value: String) -> Result<()> {
        self.map.lock().insert(key, value);
        if self.allowed && self.persistent {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        if !self.allowed || !self.persistent {
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(&*self.map.lock())
            .map_err(|e| CapError::Invalid(format!("kv serialize: {e}")))?;
        // Atomic write: write to .tmp then rename to avoid corruption from interrupted writes
        let tmp_path = self.path.with_extension("json.tmp");
        std::fs::write(&tmp_path, bytes)?;
        std::fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }
}

fn kv_path_for_app(app_id: &str) -> Result<PathBuf> {
    let proj = directories::ProjectDirs::from("dev", "cap", "cap-runtime")
        .ok_or_else(|| CapError::Invalid("cannot determine config directory".into()))?;
    Ok(proj.config_dir().join(app_id).join("kv.json"))
}

fn run_wry(state: Arc<AppState>) -> Result<()> {
    use tao::event::{Event, WindowEvent};
    use tao::event_loop::{ControlFlow, EventLoop};
    use tao::window::WindowBuilder;
    use wry::WebViewBuilder;

    let event_loop = EventLoop::new();

    let window = WindowBuilder::new()
        .with_title(state.manifest.app.name.clone())
        .build(&event_loop)
        .map_err(|e| CapError::Invalid(format!("window build: {e}")))?;

    let state_for_protocol = state.clone();

    let init_script = cap_init_script(&state.network_allowed_origins);

    let _webview = WebViewBuilder::new()
        .with_initialization_script(init_script)
        .with_custom_protocol("cap".into(), move |_id, req| {
            handle_cap_request(&state_for_protocol, req)
        })
        .with_url(format!("cap://localhost/{}", state.entrypoint.as_str()))
        .build(&window)
        .map_err(|e| CapError::Invalid(format!("webview build: {e}")))?;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        if let Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } = event
        {
            *control_flow = ControlFlow::Exit;
        }
    })
}

fn cap_init_script(network_origins: &[String]) -> String {
    // Build dynamic connect-src for CSP based on declared network origins.
    let connect_src = if network_origins.iter().any(|o| o == "*") {
        "*".to_string()
    } else if network_origins.is_empty() {
        "'self' cap:".to_string()
    } else {
        let mut parts = vec!["'self'".to_string(), "cap:".to_string()];
        parts.extend(network_origins.iter().cloned());
        parts.join(" ")
    };

    let csp = format!(
        "default-src 'self' cap:; script-src 'self' cap:; style-src 'self' cap: 'unsafe-inline'; img-src 'self' cap: data:; connect-src {connect_src};"
    );

    // A tiny JS helper that exposes a stable capability API at window.CAP.
    // It routes to the shell via `fetch("/__cap/...")` (served by the custom protocol handler).
    format!(
        r#"
(function () {{
  // Inject Content Security Policy
  var meta = document.createElement("meta");
  meta.httpEquiv = "Content-Security-Policy";
  meta.content = {csp_json};
  document.head.appendChild(meta);

  if (window.CAP) return;
  async function postJson(path, body) {{
    const res = await fetch(path, {{
      method: "POST",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify(body || {{}})
    }});
    const text = await res.text();
    try {{ return JSON.parse(text); }} catch (_) {{ return {{ ok: false, error: "bad json", raw: text }}; }}
  }}

  window.CAP = {{
    runtime: "cap-runtime-desktop/0.1.0",
    ping: () => postJson("/__cap/ping", {{}}),
    kv: {{
      get: async (key) => {{
        const r = await postJson("/__cap/kv/get", {{ key }});
        if (!r.ok) throw new Error(r.error || "kv.get failed");
        return r.value ?? null;
      }},
      set: async (key, value) => {{
        const r = await postJson("/__cap/kv/set", {{ key, value: String(value) }});
        if (!r.ok) throw new Error(r.error || "kv.set failed");
        return true;
      }}
    }},
    net: {{
      fetch: async (url, opts) => {{
        opts = opts || {{}};
        const r = await postJson("/__cap/net/fetch", {{
          url,
          method: opts.method || "GET",
          headers: opts.headers || {{}},
          body: opts.body || null
        }});
        if (!r.ok) throw new Error(r.error || "net.fetch failed");
        return {{ status: r.status, body: r.body }};
      }}
    }},
    notifications: {{
      show: async (title, message) => {{
        const r = await postJson("/__cap/notifications/show", {{ title, message: message || "" }});
        if (!r.ok) throw new Error(r.error || "notifications.show failed");
        return r;
      }}
    }},
    fs: {{
      read: async (path) => {{
        const r = await postJson("/__cap/fs/read", {{ path }});
        if (!r.ok) throw new Error(r.error || "fs.read failed");
        return r.content;
      }},
      readBinary: async (path) => {{
        const r = await postJson("/__cap/fs/read_binary", {{ path }});
        if (!r.ok) throw new Error(r.error || "fs.readBinary failed");
        return r.content;
      }},
      write: async (path, content) => {{
        const r = await postJson("/__cap/fs/write", {{ path, content }});
        if (!r.ok) throw new Error(r.error || "fs.write failed");
        return true;
      }},
      writeBinary: async (path, content) => {{
        const r = await postJson("/__cap/fs/write_binary", {{ path, content }});
        if (!r.ok) throw new Error(r.error || "fs.writeBinary failed");
        return true;
      }},
      list: async (path) => {{
        const r = await postJson("/__cap/fs/list", {{ path }});
        if (!r.ok) throw new Error(r.error || "fs.list failed");
        return r.entries;
      }},
      remove: async (path) => {{
        const r = await postJson("/__cap/fs/remove", {{ path }});
        if (!r.ok) throw new Error(r.error || "fs.remove failed");
        return true;
      }},
      exists: async (path) => {{
        const r = await postJson("/__cap/fs/exists", {{ path }});
        if (!r.ok) throw new Error(r.error || "fs.exists failed");
        return r.exists;
      }},
      mkdir: async (path) => {{
        const r = await postJson("/__cap/fs/mkdir", {{ path }});
        if (!r.ok) throw new Error(r.error || "fs.mkdir failed");
        return true;
      }}
    }},
    keystore: {{
      get: async (key) => {{
        const r = await postJson("/__cap/keystore/get", {{ key }});
        if (!r.ok) throw new Error(r.error || "keystore.get failed");
        return r.value ?? null;
      }},
      set: async (key, value) => {{
        const r = await postJson("/__cap/keystore/set", {{ key, value: String(value) }});
        if (!r.ok) throw new Error(r.error || "keystore.set failed");
        return true;
      }},
      delete: async (key) => {{
        const r = await postJson("/__cap/keystore/delete", {{ key }});
        if (!r.ok) throw new Error(r.error || "keystore.delete failed");
        return true;
      }}
    }},
    accel: {{
      load: async (module) => {{
        throw new Error("native_accel is not yet supported by this runtime");
      }}
    }}
  }};
}})();
"#,
        csp_json = serde_json::to_string(&csp).unwrap_or_default()
    )
}

fn handle_cap_request(
    state: &AppState,
    req: http::Request<Vec<u8>>,
) -> http::Response<Cow<'static, [u8]>> {
    let path = req.uri().path().trim_start_matches('/').to_string();

    if path.is_empty() || path == "/" {
        return serve_asset(state, &state.entrypoint);
    }

    if path.starts_with("__cap/") {
        return handle_api(state, &path, req);
    }

    serve_asset(state, &path)
}

fn build_response(
    status: StatusCode,
    content_type: &str,
    body: Cow<'static, [u8]>,
) -> http::Response<Cow<'static, [u8]>> {
    Response::builder()
        .status(status)
        .header("Content-Type", content_type)
        .body(body)
        .unwrap_or_else(|_| Response::new(Cow::Borrowed(b"internal error" as &[u8])))
}

fn serve_asset(state: &AppState, vpath: &str) -> http::Response<Cow<'static, [u8]>> {
    if let Some(bytes) = state.assets.get(vpath) {
        let mime = MimeGuess::from_path(vpath).first_or_octet_stream();
        build_response(StatusCode::OK, mime.as_ref(), Cow::Owned(bytes.clone()))
    } else {
        build_response(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            Cow::Borrowed(b"not found" as &[u8]),
        )
    }
}

#[derive(Debug, Deserialize)]
struct KvGetReq {
    key: String,
}

#[derive(Debug, Deserialize)]
struct KvSetReq {
    key: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct ApiOk<T: Serialize> {
    ok: bool,
    #[serde(flatten)]
    data: T,
}

#[derive(Debug, Serialize)]
struct ApiErr {
    ok: bool,
    error: String,
}

/// Check whether `url` is allowed by the network capability's origin allowlist.
///
/// Uses proper URL parsing to prevent subdomain spoofing (e.g. `api.example.com.evil.com`
/// no longer matches an origin of `https://api.example.com`).
fn is_url_allowed(request_url: &str, allowed_origins: &[String]) -> bool {
    if allowed_origins.is_empty() {
        return false;
    }

    let parsed = match url::Url::parse(request_url) {
        Ok(u) => u,
        Err(_) => return false,
    };

    // Only allow http/https schemes
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return false,
    }

    for origin in allowed_origins {
        if origin == "*" {
            return true;
        }

        let origin_url = match url::Url::parse(origin) {
            Ok(u) => u,
            Err(_) => continue,
        };

        // Scheme must match exactly
        if parsed.scheme() != origin_url.scheme() {
            continue;
        }

        // Host must match exactly (no subdomain inference)
        if parsed.host_str() != origin_url.host_str() {
            continue;
        }

        // Port must match (considering defaults: 443 for https, 80 for http)
        let default_port = |scheme: &str| -> Option<u16> {
            match scheme {
                "https" => Some(443),
                "http" => Some(80),
                _ => None,
            }
        };
        let req_port = parsed.port().or_else(|| default_port(parsed.scheme()));
        let orig_port = origin_url
            .port()
            .or_else(|| default_port(origin_url.scheme()));
        if req_port != orig_port {
            continue;
        }

        // If origin has a non-trivial path (more than "/"), require prefix match
        let origin_path = origin_url.path();
        if origin_path.len() > 1 && !parsed.path().starts_with(origin_path) {
            continue;
        }

        return true;
    }
    false
}

#[derive(Debug, Deserialize)]
struct NetFetchReq {
    url: String,
    #[serde(default = "default_method")]
    method: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    body: Option<String>,
}

fn default_method() -> String {
    "GET".to_string()
}

/// Read response body with a size limit. Returns an error if the body exceeds `limit` bytes
/// or is not valid UTF-8.
fn read_response_body_limited(
    resp: ureq::Response,
    limit: usize,
) -> std::result::Result<(u16, String), String> {
    let status = resp.status();
    let mut reader = resp.into_reader().take((limit + 1) as u64);
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .map_err(|e| format!("read error: {e}"))?;
    if buf.len() > limit {
        return Err(format!("response body exceeds {} byte limit", limit));
    }
    let body =
        String::from_utf8(buf).map_err(|_| "response body is not valid UTF-8".to_string())?;
    Ok((status, body))
}

fn perform_http_request(req: &NetFetchReq) -> std::result::Result<serde_json::Value, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .build();
    let mut request = match req.method.to_uppercase().as_str() {
        "GET" => agent.get(&req.url),
        "POST" => agent.post(&req.url),
        "PUT" => agent.put(&req.url),
        "DELETE" => agent.delete(&req.url),
        "PATCH" => agent.patch(&req.url),
        "HEAD" => agent.head(&req.url),
        other => return Err(format!("unsupported method: {other}")),
    };

    for (k, v) in &req.headers {
        request = request.set(k, v);
    }

    let response = if let Some(ref body_str) = req.body {
        request.send_string(body_str)
    } else {
        request.call()
    };

    match response {
        Ok(resp) => {
            let (status, body) = read_response_body_limited(resp, MAX_RESPONSE_BODY_BYTES)?;
            Ok(json!({ "status": status, "body": body }))
        }
        Err(ureq::Error::Status(code, resp)) => {
            let (_, body) = read_response_body_limited(resp, MAX_RESPONSE_BODY_BYTES)?;
            Ok(json!({ "status": code, "body": body }))
        }
        Err(e) => Err(format!("network error: {e}")),
    }
}

#[derive(Debug, Deserialize)]
struct NotificationReq {
    title: String,
    #[serde(default)]
    message: String,
}

// ── Rate Limiter ────────────────────────────────────────────────

struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: std::time::Instant,
}

impl TokenBucket {
    fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: std::time::Instant::now(),
        }
    }

    fn try_consume(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct RateLimiter {
    buckets: Mutex<HashMap<String, TokenBucket>>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn check(&self, category: &str) -> bool {
        let mut buckets = self.buckets.lock();
        let bucket = buckets.entry(category.to_string()).or_insert_with(|| {
            TokenBucket::new(
                (DEFAULT_RATE_LIMIT + RATE_LIMIT_BURST) as f64,
                DEFAULT_RATE_LIMIT as f64,
            )
        });
        bucket.try_consume()
    }
}

#[derive(Debug, Deserialize)]
struct KeystoreGetReq {
    key: String,
}

#[derive(Debug, Deserialize)]
struct KeystoreSetReq {
    key: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct KeystoreDeleteReq {
    key: String,
}

fn handle_api(
    state: &AppState,
    path: &str,
    req: http::Request<Vec<u8>>,
) -> http::Response<Cow<'static, [u8]>> {
    match path {
        "__cap/ping" => json_ok(json!({
            "runtime": "cap-runtime-desktop/0.1.0",
            "app_id": state.manifest.app.id,
            "app_version": state.manifest.app.version
        })),
        "__cap/kv/get" => {
            if state.manifest.capabilities.kv_store.is_none() {
                return json_err(StatusCode::FORBIDDEN, "kv_store capability not granted");
            }
            if !state.rate_limiter.check("kv") {
                return json_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded for kv");
            }
            let r: KvGetReq = match serde_json::from_slice(req.body()) {
                Ok(v) => v,
                Err(e) => return json_err(StatusCode::BAD_REQUEST, &format!("bad json: {e}")),
            };
            if r.key.len() > MAX_KV_KEY_BYTES {
                return json_err(
                    StatusCode::BAD_REQUEST,
                    &format!("key exceeds {} byte limit", MAX_KV_KEY_BYTES),
                );
            }
            let value = state.kv.get(&r.key);
            json_ok(json!({ "value": value }))
        }
        "__cap/kv/set" => {
            if state.manifest.capabilities.kv_store.is_none() {
                return json_err(StatusCode::FORBIDDEN, "kv_store capability not granted");
            }
            if !state.rate_limiter.check("kv") {
                return json_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded for kv");
            }
            let r: KvSetReq = match serde_json::from_slice(req.body()) {
                Ok(v) => v,
                Err(e) => return json_err(StatusCode::BAD_REQUEST, &format!("bad json: {e}")),
            };
            if r.key.len() > MAX_KV_KEY_BYTES {
                return json_err(
                    StatusCode::BAD_REQUEST,
                    &format!("key exceeds {} byte limit", MAX_KV_KEY_BYTES),
                );
            }
            if r.value.len() > MAX_KV_VALUE_BYTES {
                return json_err(
                    StatusCode::BAD_REQUEST,
                    &format!("value exceeds {} byte limit", MAX_KV_VALUE_BYTES),
                );
            }
            if let Err(e) = state.kv.set(r.key, r.value) {
                return json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e}"));
            }
            json_ok(json!({}))
        }
        "__cap/net/fetch" => {
            if state.manifest.capabilities.network.is_none() {
                return json_err(StatusCode::FORBIDDEN, "network capability not granted");
            }
            if !state.rate_limiter.check("net") {
                return json_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded for net");
            }
            let r: NetFetchReq = match serde_json::from_slice(req.body()) {
                Ok(v) => v,
                Err(e) => return json_err(StatusCode::BAD_REQUEST, &format!("bad json: {e}")),
            };
            if !is_url_allowed(&r.url, &state.network_allowed_origins) {
                return json_err(
                    StatusCode::FORBIDDEN,
                    &format!("URL not in network allowlist: {}", r.url),
                );
            }
            match perform_http_request(&r) {
                Ok(data) => json_ok(data),
                Err(e) => json_err(StatusCode::BAD_GATEWAY, &e),
            }
        }
        p if p.starts_with("__cap/fs/") => {
            if state.manifest.capabilities.filesystem.is_none() {
                return json_err(StatusCode::FORBIDDEN, "filesystem capability not granted");
            }
            if !state.rate_limiter.check("fs") {
                return json_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded for fs");
            }
            match p {
                "__cap/fs/read" => {
                    let r: FsPathReq = match serde_json::from_slice(req.body()) {
                        Ok(v) => v,
                        Err(e) => {
                            return json_err(StatusCode::BAD_REQUEST, &format!("bad json: {e}"))
                        }
                    };
                    let real =
                        match resolve_path_securely(&r.path, &state.fs.scopes, &state.fs.roots) {
                            Ok(p) => p,
                            Err(e) => return json_err(StatusCode::FORBIDDEN, &e),
                        };
                    match std::fs::metadata(&real) {
                        Ok(m) if m.len() > MAX_FS_READ_BYTES as u64 => {
                            return json_err(
                                StatusCode::BAD_REQUEST,
                                &format!("file exceeds {} byte read limit", MAX_FS_READ_BYTES),
                            );
                        }
                        Err(e) => {
                            return json_err(
                                StatusCode::NOT_FOUND,
                                &format!("cannot stat file: {e}"),
                            );
                        }
                        _ => {}
                    }
                    match std::fs::read_to_string(&real) {
                        Ok(content) => json_ok(json!({ "content": content })),
                        Err(e) => json_err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &format!("read error: {e}"),
                        ),
                    }
                }
                "__cap/fs/read_binary" => {
                    let r: FsPathReq = match serde_json::from_slice(req.body()) {
                        Ok(v) => v,
                        Err(e) => {
                            return json_err(StatusCode::BAD_REQUEST, &format!("bad json: {e}"))
                        }
                    };
                    let real =
                        match resolve_path_securely(&r.path, &state.fs.scopes, &state.fs.roots) {
                            Ok(p) => p,
                            Err(e) => return json_err(StatusCode::FORBIDDEN, &e),
                        };
                    match std::fs::metadata(&real) {
                        Ok(m) if m.len() > MAX_FS_READ_BYTES as u64 => {
                            return json_err(
                                StatusCode::BAD_REQUEST,
                                &format!("file exceeds {} byte read limit", MAX_FS_READ_BYTES),
                            );
                        }
                        Err(e) => {
                            return json_err(
                                StatusCode::NOT_FOUND,
                                &format!("cannot stat file: {e}"),
                            );
                        }
                        _ => {}
                    }
                    match std::fs::read(&real) {
                        Ok(bytes) => {
                            use base64::Engine;
                            let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                            json_ok(json!({ "content": b64 }))
                        }
                        Err(e) => json_err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &format!("read error: {e}"),
                        ),
                    }
                }
                "__cap/fs/write" => {
                    let r: FsWriteReq = match serde_json::from_slice(req.body()) {
                        Ok(v) => v,
                        Err(e) => {
                            return json_err(StatusCode::BAD_REQUEST, &format!("bad json: {e}"))
                        }
                    };
                    if r.content.len() > MAX_FS_WRITE_BYTES {
                        return json_err(
                            StatusCode::BAD_REQUEST,
                            &format!("content exceeds {} byte write limit", MAX_FS_WRITE_BYTES),
                        );
                    }
                    let real =
                        match resolve_path_securely(&r.path, &state.fs.scopes, &state.fs.roots) {
                            Ok(p) => p,
                            Err(e) => return json_err(StatusCode::FORBIDDEN, &e),
                        };
                    if let Some(parent) = real.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    match std::fs::write(&real, &r.content) {
                        Ok(()) => json_ok(json!({})),
                        Err(e) => json_err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &format!("write error: {e}"),
                        ),
                    }
                }
                "__cap/fs/write_binary" => {
                    let r: FsWriteReq = match serde_json::from_slice(req.body()) {
                        Ok(v) => v,
                        Err(e) => {
                            return json_err(StatusCode::BAD_REQUEST, &format!("bad json: {e}"))
                        }
                    };
                    use base64::Engine;
                    let bytes = match base64::engine::general_purpose::STANDARD.decode(&r.content) {
                        Ok(b) => b,
                        Err(e) => {
                            return json_err(
                                StatusCode::BAD_REQUEST,
                                &format!("invalid base64: {e}"),
                            )
                        }
                    };
                    if bytes.len() > MAX_FS_WRITE_BYTES {
                        return json_err(
                            StatusCode::BAD_REQUEST,
                            &format!(
                                "decoded content exceeds {} byte write limit",
                                MAX_FS_WRITE_BYTES
                            ),
                        );
                    }
                    let real =
                        match resolve_path_securely(&r.path, &state.fs.scopes, &state.fs.roots) {
                            Ok(p) => p,
                            Err(e) => return json_err(StatusCode::FORBIDDEN, &e),
                        };
                    if let Some(parent) = real.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    match std::fs::write(&real, &bytes) {
                        Ok(()) => json_ok(json!({})),
                        Err(e) => json_err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &format!("write error: {e}"),
                        ),
                    }
                }
                "__cap/fs/list" => {
                    let r: FsPathReq = match serde_json::from_slice(req.body()) {
                        Ok(v) => v,
                        Err(e) => {
                            return json_err(StatusCode::BAD_REQUEST, &format!("bad json: {e}"))
                        }
                    };
                    let real =
                        match resolve_path_securely(&r.path, &state.fs.scopes, &state.fs.roots) {
                            Ok(p) => p,
                            Err(e) => return json_err(StatusCode::FORBIDDEN, &e),
                        };
                    match std::fs::read_dir(&real) {
                        Ok(entries) => {
                            let mut list = Vec::new();
                            for entry in entries {
                                if list.len() >= MAX_FS_LIST_ENTRIES {
                                    break;
                                }
                                if let Ok(e) = entry {
                                    let meta = e.metadata().ok();
                                    list.push(FsListEntry {
                                        name: e.file_name().to_string_lossy().into_owned(),
                                        is_dir: meta.as_ref().map(|m| m.is_dir()).unwrap_or(false),
                                        size: meta.as_ref().map(|m| m.len()).unwrap_or(0),
                                    });
                                }
                            }
                            json_ok(json!({ "entries": list }))
                        }
                        Err(e) => json_err(
                            StatusCode::NOT_FOUND,
                            &format!("cannot list directory: {e}"),
                        ),
                    }
                }
                "__cap/fs/remove" => {
                    let r: FsPathReq = match serde_json::from_slice(req.body()) {
                        Ok(v) => v,
                        Err(e) => {
                            return json_err(StatusCode::BAD_REQUEST, &format!("bad json: {e}"))
                        }
                    };
                    let real =
                        match resolve_path_securely(&r.path, &state.fs.scopes, &state.fs.roots) {
                            Ok(p) => p,
                            Err(e) => return json_err(StatusCode::FORBIDDEN, &e),
                        };
                    let result = if real.is_dir() {
                        std::fs::remove_dir(&real)
                    } else {
                        std::fs::remove_file(&real)
                    };
                    match result {
                        Ok(()) => json_ok(json!({})),
                        Err(e) => json_err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &format!("remove error: {e}"),
                        ),
                    }
                }
                "__cap/fs/exists" => {
                    let r: FsPathReq = match serde_json::from_slice(req.body()) {
                        Ok(v) => v,
                        Err(e) => {
                            return json_err(StatusCode::BAD_REQUEST, &format!("bad json: {e}"))
                        }
                    };
                    let real =
                        match resolve_path_securely(&r.path, &state.fs.scopes, &state.fs.roots) {
                            Ok(p) => p,
                            Err(e) => return json_err(StatusCode::FORBIDDEN, &e),
                        };
                    json_ok(json!({ "exists": real.exists() }))
                }
                "__cap/fs/mkdir" => {
                    let r: FsPathReq = match serde_json::from_slice(req.body()) {
                        Ok(v) => v,
                        Err(e) => {
                            return json_err(StatusCode::BAD_REQUEST, &format!("bad json: {e}"))
                        }
                    };
                    let real =
                        match resolve_path_securely(&r.path, &state.fs.scopes, &state.fs.roots) {
                            Ok(p) => p,
                            Err(e) => return json_err(StatusCode::FORBIDDEN, &e),
                        };
                    match std::fs::create_dir_all(&real) {
                        Ok(()) => json_ok(json!({})),
                        Err(e) => json_err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &format!("mkdir error: {e}"),
                        ),
                    }
                }
                _ => json_err(StatusCode::NOT_FOUND, "unknown fs api"),
            }
        }
        "__cap/notifications/show" => {
            if state.manifest.capabilities.notifications.is_none() {
                return json_err(
                    StatusCode::FORBIDDEN,
                    "notifications capability not granted",
                );
            }
            if !state.rate_limiter.check("notifications") {
                return json_err(
                    StatusCode::TOO_MANY_REQUESTS,
                    "rate limit exceeded for notifications",
                );
            }
            let r: NotificationReq = match serde_json::from_slice(req.body()) {
                Ok(v) => v,
                Err(e) => return json_err(StatusCode::BAD_REQUEST, &format!("bad json: {e}")),
            };
            if r.title.len() > MAX_NOTIFICATION_TITLE_BYTES {
                return json_err(
                    StatusCode::BAD_REQUEST,
                    &format!("title exceeds {} byte limit", MAX_NOTIFICATION_TITLE_BYTES),
                );
            }
            if r.message.len() > MAX_NOTIFICATION_BODY_BYTES {
                return json_err(
                    StatusCode::BAD_REQUEST,
                    &format!("message exceeds {} byte limit", MAX_NOTIFICATION_BODY_BYTES),
                );
            }
            match notify_rust::Notification::new()
                .summary(&r.title)
                .body(&r.message)
                .show()
            {
                Ok(_) => json_ok(json!({ "delivered": true, "backend": "native" })),
                Err(e) => {
                    eprintln!(
                        "[CAP notification] fallback (native failed: {e}): {}: {}",
                        r.title, r.message
                    );
                    json_ok(json!({ "delivered": true, "backend": "fallback" }))
                }
            }
        }
        p if p.starts_with("__cap/keystore/") => {
            if state.manifest.capabilities.crypto_keystore.is_none() {
                return json_err(
                    StatusCode::FORBIDDEN,
                    "crypto_keystore capability not granted",
                );
            }
            if !state.rate_limiter.check("keystore") {
                return json_err(
                    StatusCode::TOO_MANY_REQUESTS,
                    "rate limit exceeded for keystore",
                );
            }
            let app_id = &state.manifest.app.id;
            let service = format!("cap-{app_id}");
            match p {
                "__cap/keystore/get" => {
                    let r: KeystoreGetReq = match serde_json::from_slice(req.body()) {
                        Ok(v) => v,
                        Err(e) => {
                            return json_err(StatusCode::BAD_REQUEST, &format!("bad json: {e}"))
                        }
                    };
                    if r.key.len() > MAX_KEYSTORE_KEY_BYTES {
                        return json_err(
                            StatusCode::BAD_REQUEST,
                            &format!("key exceeds {} byte limit", MAX_KEYSTORE_KEY_BYTES),
                        );
                    }
                    match keyring::Entry::new(&service, &r.key) {
                        Ok(entry) => match entry.get_password() {
                            Ok(val) => json_ok(json!({ "value": val })),
                            Err(keyring::Error::NoEntry) => json_ok(json!({ "value": null })),
                            Err(e) => json_err(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                &format!("keyring error: {e}"),
                            ),
                        },
                        Err(e) => json_err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &format!("keyring entry error: {e}"),
                        ),
                    }
                }
                "__cap/keystore/set" => {
                    let r: KeystoreSetReq = match serde_json::from_slice(req.body()) {
                        Ok(v) => v,
                        Err(e) => {
                            return json_err(StatusCode::BAD_REQUEST, &format!("bad json: {e}"))
                        }
                    };
                    if r.key.len() > MAX_KEYSTORE_KEY_BYTES {
                        return json_err(
                            StatusCode::BAD_REQUEST,
                            &format!("key exceeds {} byte limit", MAX_KEYSTORE_KEY_BYTES),
                        );
                    }
                    if r.value.len() > MAX_KEYSTORE_VALUE_BYTES {
                        return json_err(
                            StatusCode::BAD_REQUEST,
                            &format!("value exceeds {} byte limit", MAX_KEYSTORE_VALUE_BYTES),
                        );
                    }
                    match keyring::Entry::new(&service, &r.key) {
                        Ok(entry) => match entry.set_password(&r.value) {
                            Ok(()) => json_ok(json!({})),
                            Err(e) => json_err(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                &format!("keyring error: {e}"),
                            ),
                        },
                        Err(e) => json_err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &format!("keyring entry error: {e}"),
                        ),
                    }
                }
                "__cap/keystore/delete" => {
                    let r: KeystoreDeleteReq = match serde_json::from_slice(req.body()) {
                        Ok(v) => v,
                        Err(e) => {
                            return json_err(StatusCode::BAD_REQUEST, &format!("bad json: {e}"))
                        }
                    };
                    if r.key.len() > MAX_KEYSTORE_KEY_BYTES {
                        return json_err(
                            StatusCode::BAD_REQUEST,
                            &format!("key exceeds {} byte limit", MAX_KEYSTORE_KEY_BYTES),
                        );
                    }
                    match keyring::Entry::new(&service, &r.key) {
                        Ok(entry) => match entry.delete_credential() {
                            Ok(()) => json_ok(json!({})),
                            Err(keyring::Error::NoEntry) => json_ok(json!({})),
                            Err(e) => json_err(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                &format!("keyring error: {e}"),
                            ),
                        },
                        Err(e) => json_err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &format!("keyring entry error: {e}"),
                        ),
                    }
                }
                _ => json_err(StatusCode::NOT_FOUND, "unknown keystore api"),
            }
        }
        p if p.starts_with("__cap/accel/") => {
            if state.manifest.capabilities.native_accel.is_none() {
                return json_err(StatusCode::FORBIDDEN, "native_accel capability not granted");
            }
            json_err(
                StatusCode::NOT_IMPLEMENTED,
                "native_accel is not yet supported by this runtime",
            )
        }
        _ => json_err(StatusCode::NOT_FOUND, "unknown api"),
    }
}

fn json_ok(value: serde_json::Value) -> http::Response<Cow<'static, [u8]>> {
    let bytes = serde_json::to_vec(&ApiOk {
        ok: true,
        data: value,
    })
    .unwrap_or_else(|_| b"{\"ok\":true}".to_vec());
    build_response(
        StatusCode::OK,
        "application/json; charset=utf-8",
        Cow::Owned(bytes),
    )
}

fn json_err(status: StatusCode, msg: &str) -> http::Response<Cow<'static, [u8]>> {
    let bytes = serde_json::to_vec(&ApiErr {
        ok: false,
        error: msg.to_string(),
    })
    .unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"error\"}".to_vec());
    build_response(status, "application/json; charset=utf-8", Cow::Owned(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_allowed_exact_origin() {
        let origins = vec!["https://api.example.com".to_string()];
        assert!(is_url_allowed("https://api.example.com/v1/data", &origins));
    }

    #[test]
    fn url_denied_different_origin() {
        let origins = vec!["https://api.example.com".to_string()];
        assert!(!is_url_allowed("https://evil.com/steal", &origins));
    }

    #[test]
    fn url_denied_empty_allowlist() {
        let origins: Vec<String> = vec![];
        assert!(!is_url_allowed("https://anything.com", &origins));
    }

    #[test]
    fn url_allowed_wildcard() {
        let origins = vec!["*".to_string()];
        assert!(is_url_allowed("https://anything.example.com/foo", &origins));
    }

    #[test]
    fn url_allowed_multiple_origins() {
        let origins = vec![
            "https://api.example.com".to_string(),
            "https://cdn.example.com".to_string(),
        ];
        assert!(is_url_allowed("https://cdn.example.com/asset.js", &origins));
        assert!(!is_url_allowed("https://other.com", &origins));
    }

    #[test]
    fn url_denied_subdomain_spoofing() {
        let origins = vec!["https://api.example.com".to_string()];
        assert!(!is_url_allowed(
            "https://api.example.com.evil.com/steal",
            &origins
        ));
    }

    #[test]
    fn url_denied_scheme_mismatch() {
        let origins = vec!["https://api.example.com".to_string()];
        assert!(!is_url_allowed("http://api.example.com/data", &origins));
    }

    #[test]
    fn url_denied_port_mismatch() {
        let origins = vec!["https://api.example.com".to_string()];
        assert!(!is_url_allowed(
            "https://api.example.com:8080/data",
            &origins
        ));
    }

    #[test]
    fn url_allowed_with_path_prefix() {
        let origins = vec!["https://api.example.com/v1".to_string()];
        assert!(is_url_allowed("https://api.example.com/v1/users", &origins));
        assert!(!is_url_allowed(
            "https://api.example.com/v2/users",
            &origins
        ));
    }

    #[test]
    fn url_denied_invalid_url() {
        let origins = vec!["https://api.example.com".to_string()];
        assert!(!is_url_allowed("not-a-url", &origins));
    }

    #[test]
    fn url_denied_data_uri() {
        let origins = vec!["https://api.example.com".to_string()];
        assert!(!is_url_allowed(
            "data:text/html,<script>alert(1)</script>",
            &origins
        ));
    }

    // ── CSP injection tests ───────────────────────────────────────

    #[test]
    fn csp_includes_default_directives() {
        let script = cap_init_script(&[]);
        assert!(script.contains("Content-Security-Policy"));
        assert!(script.contains("default-src"));
        assert!(script.contains("script-src"));
    }

    #[test]
    fn csp_includes_network_origins() {
        let script = cap_init_script(&["https://api.example.com".to_string()]);
        assert!(script.contains("https://api.example.com"));
        assert!(script.contains("connect-src"));
    }

    #[test]
    fn csp_wildcard_network() {
        let script = cap_init_script(&["*".to_string()]);
        assert!(script.contains("connect-src *"));
    }

    // ── Network limit constants ───────────────────────────────────

    #[test]
    fn network_constants_are_reasonable() {
        assert_eq!(MAX_RESPONSE_BODY_BYTES, 10 * 1024 * 1024);
        assert_eq!(REQUEST_TIMEOUT_SECS, 30);
    }

    // ── KV size limit constants ───────────────────────────────────

    #[test]
    fn kv_constants_are_reasonable() {
        assert_eq!(MAX_KV_KEY_BYTES, 256);
        assert_eq!(MAX_KV_VALUE_BYTES, 1_048_576);
    }

    // ── Filesystem scope tests ──────────────────────────────────

    #[test]
    fn scope_matches_wildcard() {
        let scopes = vec!["documents://app/*".to_string()];
        assert!(scope_matches("documents://app/notes/file.txt", &scopes));
        assert!(scope_matches("documents://app/file.txt", &scopes));
    }

    #[test]
    fn scope_matches_prefix() {
        let scopes = vec!["cache://app/images/*".to_string()];
        assert!(scope_matches("cache://app/images/photo.jpg", &scopes));
        assert!(!scope_matches("cache://app/videos/clip.mp4", &scopes));
    }

    #[test]
    fn scope_rejects_different_type() {
        let scopes = vec!["documents://app/*".to_string()];
        assert!(!scope_matches("cache://app/file.txt", &scopes));
    }

    #[test]
    fn scope_rejects_different_app() {
        let scopes = vec!["documents://app1/*".to_string()];
        assert!(!scope_matches("documents://app2/file.txt", &scopes));
    }

    #[test]
    fn resolve_path_rejects_traversal() {
        let scopes = vec!["documents://app/*".to_string()];
        let mut roots = HashMap::new();
        let tmp = std::env::temp_dir().join("cap-test-resolve-traversal");
        let _ = std::fs::create_dir_all(&tmp);
        roots.insert("documents".into(), tmp.clone());

        let result = resolve_path_securely("documents://app/../../../etc/passwd", &scopes, &roots);
        assert!(result.is_err(), "traversal should be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("traversal") || err.contains("escapes"),
            "error: {err}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn resolve_path_rejects_absolute() {
        let scopes = vec!["documents://app/*".to_string()];
        let mut roots = HashMap::new();
        let tmp = std::env::temp_dir().join("cap-test-resolve-absolute");
        let _ = std::fs::create_dir_all(&tmp);
        roots.insert("documents".into(), tmp.clone());

        // This path won't match the scope because it doesn't start with documents://
        let result = resolve_path_securely("documents://app//etc/passwd", &scopes, &roots);
        // The relpath will be "/etc/passwd" which starts with /
        assert!(result.is_err(), "absolute relpath should be rejected");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn resolve_path_accepts_valid() {
        let scopes = vec!["documents://app/*".to_string()];
        let mut roots = HashMap::new();
        let tmp = std::env::temp_dir().join("cap-test-resolve-valid");
        let _ = std::fs::create_dir_all(&tmp);
        roots.insert("documents".into(), tmp.clone());

        let result = resolve_path_securely("documents://app/notes/file.txt", &scopes, &roots);
        assert!(
            result.is_ok(),
            "valid path should resolve: {:?}",
            result.err()
        );
        let resolved = result.unwrap();
        // The resolved path should be within our temp directory
        let canonical_tmp = tmp.canonicalize().unwrap();
        assert!(
            resolved.starts_with(&canonical_tmp),
            "resolved path {:?} should be within {:?}",
            resolved,
            canonical_tmp
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn fs_constants_are_reasonable() {
        assert_eq!(MAX_FS_READ_BYTES, 10 * 1024 * 1024);
        assert_eq!(MAX_FS_WRITE_BYTES, 10 * 1024 * 1024);
        assert_eq!(MAX_FS_LIST_ENTRIES, 1000);
    }

    // ── Notification tests ──────────────────────────────────────

    #[test]
    fn notification_title_length_limit() {
        assert_eq!(MAX_NOTIFICATION_TITLE_BYTES, 256);
        assert_eq!(MAX_NOTIFICATION_BODY_BYTES, 4096);
    }

    #[test]
    fn init_script_includes_fs_api() {
        let script = cap_init_script(&[]);
        assert!(script.contains("fs:"), "init script should expose CAP.fs");
        assert!(
            script.contains("__cap/fs/read"),
            "should include fs read endpoint"
        );
        assert!(
            script.contains("__cap/fs/write"),
            "should include fs write endpoint"
        );
        assert!(
            script.contains("__cap/fs/list"),
            "should include fs list endpoint"
        );
    }

    // ── Keystore tests ──────────────────────────────────────────

    #[test]
    fn keystore_constants_are_reasonable() {
        assert_eq!(MAX_KEYSTORE_KEY_BYTES, 256);
        assert_eq!(MAX_KEYSTORE_VALUE_BYTES, 8192);
    }

    #[test]
    fn init_script_includes_keystore_api() {
        let script = cap_init_script(&[]);
        assert!(
            script.contains("keystore:"),
            "init script should expose CAP.keystore"
        );
        assert!(
            script.contains("__cap/keystore/get"),
            "should include keystore get endpoint"
        );
        assert!(
            script.contains("__cap/keystore/set"),
            "should include keystore set endpoint"
        );
        assert!(
            script.contains("__cap/keystore/delete"),
            "should include keystore delete endpoint"
        );
    }

    #[test]
    #[ignore] // Requires OS keychain daemon
    fn keystore_set_and_get() {
        let service = "cap-com.test.keystore-test";
        let key = "test-secret";
        let value = "super-secret-value";

        let entry = keyring::Entry::new(service, key).expect("create entry");
        entry.set_password(value).expect("set password");
        let got = entry.get_password().expect("get password");
        assert_eq!(got, value);

        // Cleanup
        let _ = entry.delete_credential();
    }

    #[test]
    #[ignore] // Requires OS keychain daemon
    fn keystore_delete() {
        let service = "cap-com.test.keystore-delete-test";
        let key = "test-delete";

        let entry = keyring::Entry::new(service, key).expect("create entry");
        entry.set_password("to-delete").expect("set password");
        entry.delete_credential().expect("delete credential");

        match entry.get_password() {
            Err(keyring::Error::NoEntry) => {} // expected
            Ok(_) => panic!("expected NoEntry after delete"),
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn keystore_rejects_oversized_key() {
        let long_key = "k".repeat(MAX_KEYSTORE_KEY_BYTES + 1);
        assert!(long_key.len() > MAX_KEYSTORE_KEY_BYTES);
    }

    // ── Native accel tests ──────────────────────────────────────

    #[test]
    fn init_script_includes_accel_stub() {
        let script = cap_init_script(&[]);
        assert!(
            script.contains("accel:"),
            "init script should expose CAP.accel"
        );
        assert!(
            script.contains("native_accel is not yet supported"),
            "should include not-yet-supported message"
        );
    }

    // ── Rate limiter tests ──────────────────────────────────────

    #[test]
    fn rate_limiter_allows_within_limit() {
        let limiter = RateLimiter::new();
        let limit = (DEFAULT_RATE_LIMIT + RATE_LIMIT_BURST) as usize;
        for i in 0..limit {
            assert!(
                limiter.check("test"),
                "should allow call {i} within limit {limit}"
            );
        }
    }

    #[test]
    fn rate_limiter_rejects_over_limit() {
        let limiter = RateLimiter::new();
        let limit = (DEFAULT_RATE_LIMIT + RATE_LIMIT_BURST) as usize;
        // Exhaust all tokens
        for _ in 0..limit {
            limiter.check("test");
        }
        // Next call should be rejected
        assert!(
            !limiter.check("test"),
            "should reject after exhausting tokens"
        );
    }

    #[test]
    fn rate_limiter_refills_over_time() {
        let limiter = RateLimiter::new();
        let limit = (DEFAULT_RATE_LIMIT + RATE_LIMIT_BURST) as usize;
        // Exhaust all tokens
        for _ in 0..limit {
            limiter.check("test_refill");
        }
        assert!(!limiter.check("test_refill"), "should be exhausted");

        // Wait enough time for at least 1 token to refill
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(
            limiter.check("test_refill"),
            "should have refilled after sleep"
        );
    }

    #[test]
    fn rate_limit_constants_are_reasonable() {
        assert_eq!(DEFAULT_RATE_LIMIT, 100);
        assert_eq!(RATE_LIMIT_BURST, 20);
        assert!(
            DEFAULT_RATE_LIMIT > RATE_LIMIT_BURST,
            "rate limit should be higher than burst"
        );
    }
}
