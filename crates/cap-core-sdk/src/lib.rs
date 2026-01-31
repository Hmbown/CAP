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
        Self {
            ok: true,
            data,
            error: None,
        }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            data: Value::Null,
            error: Some(msg.into()),
        }
    }
}

/// Allocate `size` bytes with alignment 8 in the WASM linear memory.
///
/// Returns a non-zero pointer on success, a sentinel value of 8 for zero-sized
/// allocations, or 0 on failure.
#[no_mangle]
pub extern "C" fn cap_alloc(size: u32) -> u32 {
    use std::alloc::{alloc, Layout};
    if size == 0 {
        return 8; // non-null sentinel for zero-sized allocations
    }
    let layout = match Layout::from_size_align(size as usize, 8) {
        Ok(l) => l,
        Err(_) => return 0,
    };
    // SAFETY: `layout` has non-zero size (checked above) and valid alignment.
    // The returned pointer is valid for `size` bytes or null on OOM.
    let ptr = unsafe { alloc(layout) };
    ptr as u32
}

/// Deallocate a previously allocated region.
///
/// No-op if `ptr` or `size` is zero.
#[no_mangle]
pub extern "C" fn cap_dealloc(ptr: u32, size: u32) {
    use std::alloc::{dealloc, Layout};
    if ptr == 0 || size == 0 {
        return;
    }
    let layout = match Layout::from_size_align(size as usize, 8) {
        Ok(l) => l,
        Err(_) => return,
    };
    // SAFETY: `ptr` was previously returned by `cap_alloc` with the same `size`
    // and alignment 8. `layout` matches the original allocation.
    unsafe { dealloc(ptr as *mut u8, layout) }
}

/// Pack (ptr, len) into a u64: low32 = ptr, high32 = len
pub fn pack(ptr: u32, len: u32) -> u64 {
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
            // SAFETY: `ptr` and `len` describe a valid UTF-8 JSON buffer in WASM
            // linear memory, written by the host before calling this export.
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
#[allow(non_snake_case)]
pub fn cap_core_sdk__write_reply(reply: &Reply) -> u64 {
    let bytes = match serde_json::to_vec(reply) {
        Ok(b) => b,
        Err(e) => serde_json::to_vec(&Reply::err(format!("reply json encode failed: {e}")))
            .unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"fatal\"}".to_vec()),
    };

    let out_len = bytes.len() as u32;
    let out_ptr = cap_alloc(out_len);

    // SAFETY: `out_ptr` was just returned by `cap_alloc(out_len)` and is valid
    // for `out_len` bytes. `bytes` is a valid slice of the same length.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr as *mut u8, bytes.len());
    }

    pack(out_ptr, out_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reply_ok_serializes() {
        let r = Reply::ok(json!({"greeting": "hello"}));
        assert!(r.ok);
        assert_eq!(r.data, json!({"greeting": "hello"}));
        assert!(r.error.is_none());

        let json_str = serde_json::to_string(&r).expect("serialize");
        assert!(json_str.contains("\"ok\":true"));
    }

    #[test]
    fn reply_err_serializes() {
        let r = Reply::err("something went wrong");
        assert!(!r.ok);
        assert_eq!(r.error.as_deref(), Some("something went wrong"));

        let json_str = serde_json::to_string(&r).expect("serialize");
        assert!(json_str.contains("\"ok\":false"));
        assert!(json_str.contains("something went wrong"));
    }

    #[test]
    fn invocation_roundtrip() {
        let inv = Invocation {
            cmd: "greet".into(),
            args: json!({"name": "world"}),
        };
        let bytes = serde_json::to_vec(&inv).expect("encode");
        let decoded: Invocation = serde_json::from_slice(&bytes).expect("decode");
        assert_eq!(decoded.cmd, "greet");
        assert_eq!(decoded.args, json!({"name": "world"}));
    }

    #[test]
    fn pack_encodes_correctly() {
        let packed = pack(0x1234, 0x5678);
        assert_eq!(packed & 0xFFFF_FFFF, 0x1234);
        assert_eq!(packed >> 32, 0x5678);
    }

    #[test]
    fn pack_zero() {
        assert_eq!(pack(0, 0), 0);
    }

    #[test]
    fn reply_json_roundtrip() {
        let original = Reply::ok(json!({"items": [1, 2, 3]}));
        let bytes = serde_json::to_vec(&original).expect("encode");
        let decoded: Reply = serde_json::from_slice(&bytes).expect("decode");
        assert_eq!(decoded.ok, original.ok);
        assert_eq!(decoded.data, original.data);
        assert_eq!(decoded.error, original.error);
    }

    #[test]
    fn cap_alloc_zero_returns_nonzero() {
        let ptr = cap_alloc(0);
        assert_ne!(ptr, 0, "zero-size alloc should return non-zero sentinel");
    }

    #[test]
    fn cap_dealloc_zero_ptr_noop() {
        // Should not panic
        cap_dealloc(0, 64);
    }

    #[test]
    fn cap_dealloc_zero_size_noop() {
        // Should not panic
        cap_dealloc(1024, 0);
    }
}
