#![allow(clippy::not_unsafe_ptr_arg_deref)]
// This crate defines a tiny stable ABI for CAP WebAssembly "cores".
// The ABI is designed for JS (WebView/browser) hosts:
//
// - `cap_alloc(size: u32) -> u32`
// - `cap_dealloc(ptr: u32, size: u32)`
// - `cap_invoke(ptr: u32, len: u32) -> u64` where return packs (ptr_out, len_out)
//
// The core reads a UTF-8 JSON request and returns a UTF-8 JSON response.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invocation {
    pub cmd: String,
    #[serde(default)]
    pub args: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reply {
    pub ok: bool,
    #[serde(default)]
    pub data: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Reply {
    pub fn ok(data: Value) -> Self {
        Self { ok: true, data, error: None }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Self { ok: false, data: Value::Null, error: Some(msg.into()) }
    }
}

#[no_mangle]
pub extern "C" fn cap_alloc(size: u32) -> u32 {
    use std::alloc::{alloc, Layout};
    let layout = Layout::from_size_align(size as usize, 8).unwrap();
    unsafe { alloc(layout) as u32 }
}

#[no_mangle]
pub extern "C" fn cap_dealloc(ptr: u32, size: u32) {
    use std::alloc::{dealloc, Layout};
    if ptr == 0 || size == 0 {
        return;
    }
    let layout = Layout::from_size_align(size as usize, 8).unwrap();
    unsafe { dealloc(ptr as *mut u8, layout) }
}

/// Pack (ptr, len) into a u64: low32 = ptr, high32 = len
fn pack(ptr: u32, len: u32) -> u64 {
    (ptr as u64) | ((len as u64) << 32)
}

/// Export `cap_invoke` that dispatches to your handler.
///
/// Your handler signature must be:
/// `fn handle(inv: Invocation) -> Reply`
#[macro_export]
macro_rules! cap_export {
    ($handler:path) => {
        #[no_mangle]
        pub extern "C" fn cap_invoke(ptr: u32, len: u32) -> u64 {
            // Read input bytes from linear memory.
            let input = unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) };
            let inv: $crate::Invocation = match serde_json::from_slice(input) {
                Ok(v) => v,
                Err(e) => {
                    let r = $crate::Reply::err(format!("bad request json: {e}"));
                    return $crate::cap_core_sdk__write_reply(&r);
                }
            };

            let reply: $crate::Reply = $handler(inv);
            $crate::cap_core_sdk__write_reply(&reply)
        }
    };
}

#[doc(hidden)]
pub fn cap_core_sdk__write_reply(reply: &Reply) -> u64 {
    let bytes = match serde_json::to_vec(reply) {
        Ok(b) => b,
        Err(e) => serde_json::to_vec(&Reply::err(format!("reply json encode failed: {e}")))
            .unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"fatal\"}".to_vec()),
    };

    let out_len = bytes.len() as u32;
    let out_ptr = cap_alloc(out_len);

    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr as *mut u8, bytes.len());
    }

    pack(out_ptr, out_len)
}
