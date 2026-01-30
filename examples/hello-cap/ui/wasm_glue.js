/**
 * Minimal JS glue for a CAP WebAssembly core that follows the cap-core-sdk ABI:
 * - exports memory
 * - exports cap_alloc(size)->ptr
 * - exports cap_dealloc(ptr,size)
 * - exports cap_invoke(ptr,len)->u64 packed(ptr_out,len_out)
 */

const te = new TextEncoder();
const td = new TextDecoder();

export async function loadCapWasm(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`failed to fetch wasm: ${res.status}`);
  const bytes = await res.arrayBuffer();

  const { instance } = await WebAssembly.instantiate(bytes, {});
  const { memory, cap_alloc, cap_dealloc, cap_invoke } = instance.exports;

  if (!memory || !cap_alloc || !cap_invoke) {
    throw new Error("wasm module missing required exports (memory/cap_alloc/cap_invoke)");
  }

  function writeBytes(buf) {
    const ptr = Number(cap_alloc(buf.length));
    new Uint8Array(memory.buffer, ptr, buf.length).set(buf);
    return ptr;
  }

  function readBytes(ptr, len) {
    return new Uint8Array(memory.buffer, ptr, len);
  }

  async function invoke(cmd, args) {
    const payload = te.encode(JSON.stringify({ cmd, args }));
    const inPtr = writeBytes(payload);

    // i64 returns as BigInt in JS.
    const packed = cap_invoke(inPtr, payload.length);
    const big = typeof packed === "bigint" ? packed : BigInt(packed);

    const outPtr = Number(big & 0xffffffffn);
    const outLen = Number((big >> 32n) & 0xffffffffn);

    const out = td.decode(readBytes(outPtr, outLen));
    try { return JSON.parse(out); } catch (_) { return { ok: false, error: "bad json", raw: out }; }
    finally {
      // Caller may deallocate; cap_dealloc is optional/no-op in many cores.
      if (cap_dealloc) {
        try { cap_dealloc(inPtr, payload.length); } catch (_) {}
        try { cap_dealloc(outPtr, outLen); } catch (_) {}
      }
    }
  }

  return { invoke };
}
