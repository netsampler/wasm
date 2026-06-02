self.addEventListener("message", (event) => {
  const message = event.data || {};
  if (message.type !== "run") {
    return;
  }
  run(message);
});

async function run(message) {
  try {
    await loadRuntime(message.runtime, message.adapter?.globalName);
    const api = self[message.adapter.globalName];
    if (!api?.run) {
      throw new Error("WASM is not ready");
    }
    const response = api.run(message.request);
    self.postMessage({
      type: "result",
      id: message.id,
      response,
    });
  } catch (error) {
    self.postMessage({
      type: "error",
      id: message.id,
      error: serializeError(error),
    });
  }
}

async function loadRuntime(runtime, globalName) {
  if (!runtime?.execPath || !runtime?.wasmPath) {
    throw new Error("missing WASM runtime paths");
  }
  if (!globalName) {
    throw new Error("missing adapter runtime name");
  }
  self.importScripts(runtime.execPath);
  self[globalName] = null;
  const go = new self.Go();
  const response = await fetch(runtime.wasmPath);
  const result = await WebAssembly.instantiateStreaming(response, go.importObject).catch(async () => {
    const bytes = await response.arrayBuffer();
    return WebAssembly.instantiate(bytes, go.importObject);
  });
  go.run(result.instance);
}

function serializeError(error) {
  return {
    name: error?.name || "Error",
    message: error?.message || String(error),
    stack: error?.stack || "",
  };
}
