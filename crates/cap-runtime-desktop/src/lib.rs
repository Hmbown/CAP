use cap_format::error::{CapError, Result};
use cap_format::keys::load_verifying_key_json;
use cap_format::package::CapReader;

use http::{Response, StatusCode};
use mime_guess::MimeGuess;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
    let ui_prefix = entrypoint
        .split('/')
        .next()
        .unwrap_or("ui")
        .to_string()
        + "/";

    let mut assets = BTreeMap::new();
    let ui_assets = reader.read_prefix(&ui_prefix)?;
    for (k, v) in ui_assets {
        assets.insert(k, v);
    }

    // If core_wasm exists, load it too (so UI can fetch it).
    if let Some(core) = &reader.manifest.entrypoints.core_wasm {
        if reader.index.files.contains_key(core) {
            let bytes = reader.read_virtual_file(core)?;
            assets.insert(core.clone(), bytes);
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
}

impl AppState {
    fn new(manifest: cap_format::manifest::Manifest, assets: BTreeMap<String, Vec<u8>>, entrypoint: String) -> Result<Self> {
        let kv_allowed = manifest.capabilities.kv_store.is_some();
        let kv_persistent = manifest
            .capabilities
            .kv_store
            .as_ref()
            .map(|k| k.persistent)
            .unwrap_or(false);

        let kv = KvStore::new(&manifest.app.id, kv_allowed, kv_persistent)?;
        Ok(Self { manifest, assets, entrypoint, kv })
    }
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
            serde_json::from_slice::<HashMap<String, String>>(&bytes).unwrap_or_default()
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
        std::fs::write(&self.path, bytes)?;
        Ok(())
    }
}

fn kv_path_for_app(app_id: &str) -> Result<PathBuf> {
    let proj = directories::ProjectDirs::from("dev", "cap", "cap-runtime")
        .ok_or_else(|| CapError::Invalid("cannot determine config directory".into()))?;
    Ok(proj.config_dir().join(app_id).join("kv.json"))
}

fn run_wry(state: Arc<AppState>) -> Result<()> {
    use wry::application::event::{Event, WindowEvent};
    use wry::application::event_loop::{ControlFlow, EventLoop};
    use wry::application::window::WindowBuilder;
    use wry::WebViewBuilder;

    let event_loop = EventLoop::new();

    let window = WindowBuilder::new()
        .with_title(state.manifest.app.name.clone())
        .build(&event_loop)
        .map_err(|e| CapError::Invalid(format!("window build: {e}")))?;

    let state_for_protocol = state.clone();

    let init_script = cap_init_script();

    let webview = WebViewBuilder::new()
        .with_initialization_script(init_script)
        .with_custom_protocol("cap".into(), move |_id, req| {
            handle_cap_request(&state_for_protocol, req)
        })
        .with_url(format!("cap://localhost/{}", state.entrypoint.as_str()))
        .build(&window)
        .map_err(|e| CapError::Invalid(format!("webview build: {e}")))?;

    // keep webview alive
    let _webview = webview;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => *control_flow = ControlFlow::Exit,
            _ => {}
        }
    });
}

fn cap_init_script() -> String {
    // A tiny JS helper that exposes a stable capability API at window.CAP.
    // It routes to the shell via `fetch("/__cap/...")` (served by the custom protocol handler).
    r#"
(function () {
  if (window.CAP) return;
  async function postJson(path, body) {
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {})
    });
    const text = await res.text();
    try { return JSON.parse(text); } catch (_) { return { ok: false, error: "bad json", raw: text }; }
  }

  window.CAP = {
    runtime: "cap-runtime-desktop/0.1.0",
    ping: () => postJson("/__cap/ping", {}),
    kv: {
      get: async (key) => {
        const r = await postJson("/__cap/kv/get", { key });
        if (!r.ok) throw new Error(r.error || "kv.get failed");
        return r.value ?? null;
      },
      set: async (key, value) => {
        const r = await postJson("/__cap/kv/set", { key, value: String(value) });
        if (!r.ok) throw new Error(r.error || "kv.set failed");
        return true;
      }
    }
  };
})();
"#
    .to_string()
}

fn handle_cap_request(state: &AppState, req: http::Request<Vec<u8>>) -> http::Response<Cow<'static, [u8]>> {
    let path = req.uri().path().trim_start_matches('/');

    if path.is_empty() || path == "/" {
        return serve_asset(state, &state.entrypoint);
    }

    if path.starts_with("__cap/") {
        return handle_api(state, path, req);
    }

    serve_asset(state, path)
}

fn serve_asset(state: &AppState, vpath: &str) -> http::Response<Cow<'static, [u8]>> {
    if let Some(bytes) = state.assets.get(vpath) {
        let mime = MimeGuess::from_path(vpath).first_or_octet_stream();
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", mime.as_ref())
            .body(Cow::Owned(bytes.clone()))
            .unwrap()
    } else {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "text/plain; charset=utf-8")
            .body(Cow::Borrowed(b"not found"))
            .unwrap()
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

fn handle_api(state: &AppState, path: &str, req: http::Request<Vec<u8>>) -> http::Response<Cow<'static, [u8]>> {
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
            let r: KvGetReq = match serde_json::from_slice(req.body()) {
                Ok(v) => v,
                Err(e) => return json_err(StatusCode::BAD_REQUEST, &format!("bad json: {e}")),
            };
            let value = state.kv.get(&r.key);
            json_ok(json!({ "value": value }))
        }
        "__cap/kv/set" => {
            if state.manifest.capabilities.kv_store.is_none() {
                return json_err(StatusCode::FORBIDDEN, "kv_store capability not granted");
            }
            let r: KvSetReq = match serde_json::from_slice(req.body()) {
                Ok(v) => v,
                Err(e) => return json_err(StatusCode::BAD_REQUEST, &format!("bad json: {e}")),
            };
            if let Err(e) = state.kv.set(r.key, r.value) {
                return json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e}"));
            }
            json_ok(json!({}))
        }
        _ => json_err(StatusCode::NOT_FOUND, "unknown api"),
    }
}

fn json_ok(value: serde_json::Value) -> http::Response<Cow<'static, [u8]>> {
    let bytes = serde_json::to_vec(&ApiOk { ok: true, data: value })
        .unwrap_or_else(|_| b"{\"ok\":true}".to_vec());
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json; charset=utf-8")
        .body(Cow::Owned(bytes))
        .unwrap()
}

fn json_err(status: StatusCode, msg: &str) -> http::Response<Cow<'static, [u8]>> {
    let bytes = serde_json::to_vec(&ApiErr { ok: false, error: msg.to_string() })
        .unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"error\"}".to_vec());
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json; charset=utf-8")
        .body(Cow::Owned(bytes))
        .unwrap()
}

// A small helper macro usable without pulling in serde_json::json into every scope.
macro_rules! json {
    ($($t:tt)*) => { serde_json::json!($($t)*) };
}
