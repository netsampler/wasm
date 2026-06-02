import { createApp, nextTick } from "vue";
import WireViewApp from "wireview/src/App.vue";
import { manager } from "wireview/src/globals.js";
import "wireview/src/style.css";

const style = document.createElement("style");
style.textContent = `
  html,
  body {
    height: 100%;
    margin: 0;
  }

  body {
    overflow-x: hidden;
    overflow-y: hidden;
  }

  #wireview-app {
    display: flex;
    width: 100%;
    height: 100%;
    min-width: 0;
    min-height: 0;
    flex-direction: column;
    overflow-x: hidden;
    overflow-y: hidden;
    scrollbar-gutter: auto;
  }

  #wireview-app * {
    min-width: 0;
  }

  @media (max-width: 520px) {
    .packet-list-scrollable {
      overflow-x: hidden !important;
    }

    .layout-container .bottom {
      flex-direction: column !important;
    }

    .layout-container .bottom > .quarter {
      width: 100% !important;
      min-height: 0;
      flex: 1 1 0;
      border-right: none;
      border-left: none;
    }

    .layout-container .h-resize {
      width: 100% !important;
      height: 4px;
      cursor: ns-resize;
      border-top: var(--ws-pane-border);
    }
  }

  .welcome-container-wrap {
    display: none !important;
  }

  label[aria-disabled="true"],
  .icon[aria-disabled="true"] {
    display: none !important;
  }
`;
document.head.append(style);

let currentCapture = null;
let captureControlsInitialized = false;

createApp(WireViewApp).mount("#wireview-app");
customizeCaptureControls();

globalThis.goflowWireView = {
  async openCapture(capture) {
    await waitUntilReady();
    currentCapture = null;
    customizeCaptureControls();
    const file = new File([captureBytes(capture)], capture.filename, {
      type: capture.mimeType,
    });
    await manager.openFile(file);
    if (!manager.sessionInfo) {
      throw new Error(wireViewOpenErrorMessage(manager.lastFileOpenError));
    }
    currentCapture = capture;
    await nextTick();
    customizeCaptureControls();
    return {
      packetCount: manager.packetCount,
      frameCount: manager.frameCount,
    };
  },
  async clearCapture() {
    await waitUntilReady();
    currentCapture = null;
    if (manager.sessionInfo) {
      await manager.closeFile();
    }
    await nextTick();
    customizeCaptureControls();
    return { cleared: true };
  },
};

globalThis.addEventListener("message", async ({ data, source }) => {
  if (data?.type === "goflow-wireview-ping") {
    source?.postMessage({ type: "goflow-wireview-ready" }, "*");
    return;
  }
  if (data?.type !== "goflow-wireview-open" && data?.type !== "goflow-wireview-clear") {
    return;
  }
  try {
    const result =
      data.type === "goflow-wireview-clear"
        ? await globalThis.goflowWireView.clearCapture()
        : await globalThis.goflowWireView.openCapture(data.capture);
    source?.postMessage(
      {
        type: data.type === "goflow-wireview-clear" ? "goflow-wireview-cleared" : "goflow-wireview-opened",
        result,
      },
      "*",
    );
  } catch (error) {
    source?.postMessage(
      {
        type: "goflow-wireview-error",
        error: error.message || String(error),
      },
      "*",
    );
  }
});

globalThis.parent?.postMessage({ type: "goflow-wireview-ready" }, "*");

function customizeCaptureControls() {
  if (!document.body) {
    requestAnimationFrame(customizeCaptureControls);
    return;
  }

  const customize = () => {
    for (const input of document.querySelectorAll('input[type="file"]')) {
      input.disabled = true;
      const control = input.closest("label");
      if (control) {
        control.setAttribute("aria-disabled", "true");
        control.title = "Capture data is provided by the left pane";
      }
    }

    const saveCaptureControl = document.querySelector(
      '[data-goflow-control="save-capture"], [title="Save capture file"]',
    );
    if (saveCaptureControl) {
      saveCaptureControl.dataset.goflowControl = "save-capture";
      saveCaptureControl.title = "Save capture file";
      saveCaptureControl.tabIndex = 0;
      saveCaptureControl.setAttribute("role", "button");
      saveCaptureControl.classList.toggle("disabled", !currentCapture);
      if (currentCapture) {
        saveCaptureControl.removeAttribute("aria-disabled");
      } else {
        saveCaptureControl.setAttribute("aria-disabled", "true");
      }
    }

    for (const selector of ['[title="Close this capture file"]', '[title="Reload this file"]']) {
      const control = document.querySelector(selector);
      if (control) {
        control.classList.add("disabled");
        control.setAttribute("aria-disabled", "true");
        control.title = "Capture data is provided by the left pane";
      }
    }
  };

  customize();

  if (captureControlsInitialized) {
    return;
  }
  captureControlsInitialized = true;

  const observer = new MutationObserver(customize);
  observer.observe(document.body, {
    childList: true,
    subtree: true,
  });

  document.addEventListener(
    "keydown",
    (event) => {
      const saveCaptureControl = closestElement(event.target, '[data-goflow-control="save-capture"]');
      if (!saveCaptureControl || !["Enter", " "].includes(event.key)) {
        return;
      }
      event.preventDefault();
      event.stopPropagation();
      downloadCurrentCapture();
    },
    true,
  );

  document.addEventListener(
    "click",
    (event) => {
      const saveCaptureControl = closestElement(event.target, '[data-goflow-control="save-capture"]');
      if (saveCaptureControl) {
        event.preventDefault();
        event.stopPropagation();
        downloadCurrentCapture();
        return;
      }
      if (closestElement(event.target, '[aria-disabled="true"]')) {
        event.preventDefault();
        event.stopPropagation();
      }
    },
    true,
  );
}

function closestElement(target, selector) {
  return target instanceof Element ? target.closest(selector) : null;
}

function downloadCurrentCapture() {
  if (!currentCapture) {
    return;
  }
  const blob = new Blob([captureBytes(currentCapture)], {
    type: currentCapture.mimeType || "application/octet-stream",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = currentCapture.filename || "goflow-capture.pcap";
  link.click();
  URL.revokeObjectURL(url);
}

function wireViewOpenErrorMessage(error) {
  const detail = error?.error || error?.message || error?.summary?.error || String(error || "");
  return ["WireView could not open capture", detail].filter(Boolean).join(": ");
}

function waitUntilReady() {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const tick = () => {
      if (manager.initialized && manager.canOpenFile) {
        resolve();
        return;
      }
      if (Date.now() - started > 15000) {
        reject(new Error("WireView did not finish loading"));
        return;
      }
      requestAnimationFrame(tick);
    };
    tick();
  });
}

function base64ToBytes(base64) {
  const raw = atob(base64);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) {
    bytes[i] = raw.charCodeAt(i);
  }
  return bytes;
}

function captureBytes(capture) {
  if (capture?.bytes instanceof Uint8Array) {
    return capture.bytes;
  }
  if (capture?.bytes instanceof ArrayBuffer) {
    return new Uint8Array(capture.bytes);
  }
  if (ArrayBuffer.isView(capture?.bytes)) {
    return new Uint8Array(capture.bytes.buffer, capture.bytes.byteOffset, capture.bytes.byteLength);
  }
  return base64ToBytes(capture?.base64 || "");
}
