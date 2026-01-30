use cap_core_sdk::{cap_export, Invocation, Reply};
use serde_json::json;

fn handle(inv: Invocation) -> Reply {
    match inv.cmd.as_str() {
        "greet" => {
            let name = inv
                .args
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("world");
            Reply::ok(json!({
                "message": format!("Hello, {name}! (from Rust core)")
            }))
        }
        _ => Reply::err(format!("unknown cmd: {}", inv.cmd)),
    }
}

cap_export!(handle);
