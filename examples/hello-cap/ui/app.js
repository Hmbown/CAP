import { loadCapWasm } from "./wasm_glue.js";

const out = document.getElementById("out");
const nameEl = document.getElementById("name");
const btn = document.getElementById("btn");

function log(line) {
  out.textContent += `\n${line}`;
}

async function main() {
  out.textContent = "Hello CAP demo";
  log(`UserAgent: ${navigator.userAgent}`);

  if (window.CAP) {
    try {
      const ping = await window.CAP.ping();
      log(`CAP runtime: ${ping.runtime}`);
      log(`App: ${ping.app_id} v${ping.app_version}`);

      // Demonstrate a capability: kv_store
      const now = new Date().toISOString();
      await window.CAP.kv.set("last_open", now);
      const v = await window.CAP.kv.get("last_open");
      log(`kv_store:last_open = ${v}`);

      // Demonstrate filesystem capability
      if (window.CAP.fs) {
        try {
          const greeting = `Hello from CAP at ${new Date().toISOString()}`;
          await window.CAP.fs.write("documents://com.example.hello-cap/hello.txt", greeting);
          const content = await window.CAP.fs.read("documents://com.example.hello-cap/hello.txt");
          log(`fs: wrote and read back: ${content}`);
        } catch (e) {
          log(`fs failed: ${e}`);
        }
      }

      // Demonstrate network capability
      if (window.CAP.net) {
        try {
          const resp = await window.CAP.net.fetch("https://httpbin.org/get");
          log(`net.fetch status: ${resp.status}`);
        } catch (e) {
          log(`net.fetch failed: ${e}`);
        }
      }
    } catch (e) {
      log(`CAP ping/kv failed: ${e}`);
    }
  } else {
    log("No CAP runtime detected (web mode?)");
  }

  // Load core wasm (served by the shell as cap://localhost/core/...)
  let wasm;
  try {
    wasm = await loadCapWasm("../core/hello_cap_core.wasm");
    log("Loaded core wasm.");
  } catch (e) {
    log(`Failed to load core wasm: ${e}`);
  }

  btn.addEventListener("click", async () => {
    if (!wasm) return log("No wasm loaded.");
    try {
      const name = nameEl.value || "world";
      const r = await wasm.invoke("greet", { name });
      log(`wasm reply: ${JSON.stringify(r)}`);
    } catch (e) {
      log(`invoke failed: ${e}`);
    }
  });
}

main();
