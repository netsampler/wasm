import "./styles.css";

const inputTypes = {
  bytes: "Bytes",
  flow: "Flow",
  json: "JSON",
  pcap: "PCAP",
  pcapng: "PCAPNG",
  unknown: "Unknown",
};
const outputFormats = {
  packet: "Packet",
  raw: "Raw",
};
const outputEncodings = {
  pretty: "Pretty",
  text: "Text",
  hex: "Hex",
  base64: "Base64",
};
const binaryInputTypes = new Set(["bytes", "flow", "pcap", "pcapng"]);
const processableInputTypes = new Set(["bytes", "flow", "json", "pcap", "pcapng"]);
const mappingPath = "mapping.yaml";
const defaultCommandOptions = Object.freeze({ scheme: "flow", produce: "sample", format: "json" });
const protoCommandOptions = Object.freeze({ scheme: "flow", produce: "sample", format: "bin" });
const rawCommandOptions = Object.freeze({ scheme: "flow", produce: "raw", format: "json" });
const goflow2OutputPresets = Object.freeze({
  proto: { label: "Proto", options: protoCommandOptions },
  raw: { label: "Raw", options: rawCommandOptions },
  json: { label: "JSON", options: defaultCommandOptions },
});
const base64WrapColumns = 76;
const urlConfigParam = "config";
const urlConfigVersion = 1;
const syntheticFlowSourcePort = 49152;
const captureImportAccept = ".pcap,.pcapng,.cap,application/octet-stream";
const jsonInputImportAccept = ".json,application/json";
const flowPresetPackets = Object.freeze({
  ipfixOptionsTemplate: "000a00246553f100000001c80000031500030014012d0002000100950004002200040000",
  ipfixOptionsData: "000a001c6553f100000001c800000315012d000c00000315000003e8",
  ipfixTemplate:
    "000a00446630f0000000000000003039000200340100000b00080004000c00040004000100070002000b0002000a0004000e000400010008000200080098000800990008",
  ipfixData:
    "000a004c6630f00100000001000030390100003cc000020ac633641406303901bb0000000a0000000e00000000000005dc000000000000000a0000018f2f2980000000018f2f2984d2000000",
  netflowv9OptionsTemplate: "00090001000000646553f1000000012c000001900001001401010004000400010004002200040000",
  netflowv9OptionsData: "00090001000000646553f1000000012c000001900101000c00000001000003e8",
  netflowv9Template: "00090001000000646553f1000000012c0000019000000010010000020001000400080004",
  netflowv9Data: "00090001000000646553f1000000012c000001900100000c0000000ac0000201",
  netflowv5: "00050001000000646553f100000000000000000101020064c000020ac6336414cb007101000a001400000007000001410000003200000064303901bb001206b8fc00fc0118190000",
  sflowSamples:
    "0000000500000001c633640100000007000000080000000900000002000000010000003c0000002a000000070000000a0000001400000000000000010000000200000001000000010000001400000001000000400000000000000040deadbeef00000003000000540000002b000000020000006300000190000001f400000000000000010000000a00000002000000140000000100000003000000200000003c00000006c000020ac633641400003039000001bb0000001200000010",
  sflowCounters:
    "0000000500000001c633640100000007000000080000000900000002000000020000006c0000000a0000000b0000000100000001000000580000000c0000000000000000000003e80000000100000005000000000000007b00000000000000000000000000000002000000000000000000000000000001c8000000000000000000000000000000040000000300000000000000040000004c0000000b000000020000000c000000010000000200000034000000000000000200000000000000000000000000000000000000000000000000000000000000000000b000000000000000d",
});

const goflow2InputPresets = Object.freeze({
  ipfix: {
    label: "IPFIX options + data",
    entries: () => flowPresetEntries(["ipfixOptionsTemplate", "ipfixOptionsData", "ipfixTemplate", "ipfixData"]),
  },
  netflowv9: {
    label: "NetFlow v9 options + data",
    entries: () => flowPresetEntries(["netflowv9OptionsTemplate", "netflowv9OptionsData", "netflowv9Template", "netflowv9Data"]),
  },
  netflowv5: {
    label: "NetFlow v5",
    entries: () => flowPresetEntries(["netflowv5"]),
  },
  sflow: {
    label: "sFlow samples",
    entries: () => flowPresetEntries(["sflowSamples"]),
  },
});

const defaultMapping = `formatter:
  fields:
    - type
    - time_received_ns
    - sequence_num
    - sampling_rate
    - flow_direction
    - sampler_address
    - time_flow_start_ns
    - time_flow_end_ns
    - bytes
    - packets
    - src_addr
    - dst_addr
    - proto
    - src_port
    - dst_port
    - in_if
    - out_if
  key:
    - sampler_address
  protobuf:
    - name: flow_direction
      index: 42
      type: varint
  render:
    time_received_ns: datetimenano
ipfix:
  mapping:
    - field: 61
      destination: flow_direction
netflowv9:
  mapping:
    - field: 61
      destination: flow_direction
`;

const starterConfig = `processor:
  type: builtin

aggregators:
  - stream: flow_data
    window:
      idle_flush_after_ms: 60000
    fields:
      - key:src_addr
      - key:dst_addr
      - key:proto
      - key:src_port
      - key:dst_port
      - sum:bytes
      - sum:packets
      - first:start_time_unix
      - current:end_time_unix

encoder:
  type: json
  json:
    flavor: canonical
`;

const reflowProcessorPresets = {
  Builtin: `processor:
  type: builtin`,
  "NAT replacement": `processor:
  type: builtin
  builtin:
    nat:
      swap_pre_post: true`,
  "decode encap": `processor:
  type: builtin
  builtin:
    packet_decoder:
      decode_beyond_l4: true
    aggregation_helpers:
      ip_layers: 2`,
};

const reflowAggregatorPresets = {
  None: `aggregators: []`,
  "Aggregate flow": `aggregators:
  - stream: flow_data
    window:
      idle_flush_after_ms: 60000
    fields:
      - key:src_addr
      - key:dst_addr
      - key:proto
      - key:src_port
      - key:dst_port
      - sum:bytes
      - sum:packets
      - first:start_time_unix
      - current:end_time_unix`,
  "Aggregate NAT": `aggregators:
  - stream: flow_data
    window:
      idle_flush_after_ms: 60000
    fields:
      - key:src_addr
      - key:dst_addr
      - key:proto
      - key:src_port
      - key:dst_port
      - sum:bytes
      - sum:packets
      - first:start_time_unix
      - current:end_time_unix
      - current:nat_src_addr
      - current:nat_dst_addr
      - current:nat_src_port
      - current:nat_dst_port`,
  "Aggregate encap": `aggregators:
  - stream: flow_data
    window:
      idle_flush_after_ms: 60000
    fields:
      - key:outer_proto
      - key:outer_src_addr
      - key:outer_dst_addr
      - key:outer_src_port
      - key:outer_dst_port
      - key:src_addr
      - key:dst_addr
      - key:proto
      - key:src_port
      - key:dst_port
      - sum:bytes
      - sum:packets
      - first:start_time_unix
      - current:end_time_unix
      - current:outer_proto_name
      - current:encap_depth`,
  "Aggregate interfaces": `aggregators:
  - stream: interface_options
    match:
      record_kind: interface_option
    window:
      idle_flush_after_ms: 500
    template_id: 1300
    fields:
      - static:tflow_record_type:options
      - key:observation_domain_id
      - key:input_if
      - current:interface_name`,
  "IPFIX options": `aggregators:
  - stream: options_data
    match:
      record_kind: options_data
    window:
      idle_flush_after_ms: 500
    template_id: 1024
    fields:
      - static:tflow_record_type:options
      - key:source_id
      - current:sampling_rate`,
  "IPFIX interface options": `aggregators:
  - stream: options_data
    match:
      record_kind: options_data
    window:
      idle_flush_after_ms: 500
    template_id: 1300
    fields:
      - static:tflow_record_type:options
      - key:observation_domain_id
      - key:input_if
      - current:interface_name`,
  Passthrough: `aggregators:
  - stream: flow_data
    fields:
      - key:src_addr
      - key:dst_addr
      - key:proto
      - key:src_port
      - key:dst_port
      - current:end_time_unix`,
  "Periodic flow": `aggregators:
  - stream: flow_data
    periodic:
      every_ms: 1000
    fields:
      - key:src_addr
      - key:dst_addr
      - key:proto
      - key:src_port
      - key:dst_port
      - sum:bytes
      - sum:packets
      - first:start_time_unix
      - current:end_time_unix`,
};

const reflowEncoderPresets = {
  "Enable Batch (sFlow, IPFIX, NetFlow v9 only)": `encoder:
  batch:
    enabled: true
    max_records: 32
    max_bytes: 4096
    flush_interval_ms: 250`,
  JSON: `encoder:
  type: json
  json:
    flavor: canonical`,
  Protobuf: `encoder:
  type: protobuf
  protobuf:
    flavor: canonical
    length_prefixed: false`,
  sFlow: `encoder:
  type: sflow
  sflow:
    counter_format: standard
    max_header_bytes: 128`,
  IPFIX: `encoder:
  type: ipfix
  templated_flow:
    template_refresh_ms: 60000
    options_refresh_ms: 30000`,
  "IPFIX enterprise": `encoder:
  type: ipfix
  templated_flow:
    template_refresh_ms: 60000
    options_refresh_ms: 30000
    data:
      overrides:
        custom_counter:
          name: customCounter
          id: 2000
          pen: 64512
          enterprise_scoped: true
          length: 8
          type: unsigned64
        compact_enterprise: 4000:4:u32[pen=64513]
        vendor_latency_ms: 4001:4:u32[pen=64513]
        vendor_policy_id: 4002:65535:str[pen=64513]`,
  "NetFlow v5": `encoder:
  type: netflowv5`,
  "NetFlow v9": `encoder:
  type: netflowv9
  templated_flow:
    template_refresh_ms: 60000
    options_refresh_ms: 30000`,
  PCAP: `encoder:
  type: pcap
  pcap:
    packet_source: auto
    link_type: ethernet
    snaplen: 65535`,
  PCAPNG: `encoder:
  type: pcapng
  pcap:
    packet_source: auto
    link_type: ethernet
    snaplen: 65535`,
};

const reflowPipelinePresets = {
  "flow JSON": starterConfig,
  "interface IPFIX": `processor:
  type: builtin
  builtin:
    drop_message: true

${reflowAggregatorPresets["Aggregate interfaces"]}

encoder:
  type: ipfix
  batch:
    enabled: true
    max_records: 2
    flush_interval_ms: 500
  templated_flow:
    observation_domain_id: 777
    options_refresh_ms: 30000`,
  "counters sFlow": `processor:
  type: builtin
  workers: 1
  builtin:
    drop_message: true
    drop_payload: true

encoder:
  type: sflow
  workers: 1
  sflow:
    counter_format: expanded
  batch:
    enabled: true
    max_records: 32
    max_bytes: 1200
    flush_interval_ms: 2000`,
  "batch IPFIX": `processor:
  type: builtin

encoder:
  type: ipfix
  batch:
    enabled: true
    max_records: 100
    max_bytes: 4096
    flush_interval_ms: 1000`,
};

const reflowJSONPresetRecords = Object.freeze({
  flowA: {
    src_addr: "192.0.2.1",
    dst_addr: "198.51.100.2",
    proto: 6,
    src_port: 12345,
    dst_port: 443,
    bytes: 10,
    packets: 1,
    start_time_unix: 1714483200123,
    end_time_unix: 1714483200123,
  },
  flowB: {
    src_addr: "192.0.2.1",
    dst_addr: "198.51.100.2",
    proto: 6,
    src_port: 12345,
    dst_port: 443,
    bytes: 20,
    packets: 2,
    start_time_unix: 1714483200123,
    end_time_unix: 1714483202623,
  },
  interfaceOptionA: {
    record_kind: "interface_option",
    observation_domain_id: 777,
    input_if: 10,
    interface_name: "uplink-a",
  },
  interfaceOptionB: {
    record_kind: "interface_option",
    observation_domain_id: 777,
    input_if: 20,
    interface_name: "uplink-b",
  },
});

const reflowInputPresets = Object.freeze({
  ...goflow2InputPresets,
  "json-flow": {
    label: "ReFlow JSON flows (2)",
    entries: () => jsonPresetEntries([reflowJSONPresetRecords.flowA, reflowJSONPresetRecords.flowB]),
  },
  "json-interface": {
    label: "ReFlow interface JSON (2)",
    entries: () => jsonPresetEntries([reflowJSONPresetRecords.interfaceOptionA, reflowJSONPresetRecords.interfaceOptionB]),
  },
  "sflow-counters": {
    label: "ReFlow sFlow counters",
    entries: () => flowPresetEntries(["sflowCounters"]),
  },
});

const publicAssetBase = import.meta.env.BASE_URL || "/";

function publicAssetPath(path) {
  return `${publicAssetBase.replace(/\/?$/, "/")}${String(path).replace(/^\//, "")}`;
}

const adapters = {
  goflow2: {
    id: "goflow2",
    title: "GoFlow2 WASM",
    manifestPath: publicAssetPath("goflow2-wasm-manifest.json"),
    fallbackRuntime: {
      id: "current",
      label: "Current build",
      version: "unknown",
      commit: "unknown",
      wasmPath: publicAssetPath("goflow2.wasm"),
      execPath: publicAssetPath("wasm_exec.js"),
    },
    globalName: "goflow2",
    enabledInputTypes: ["bytes", "flow"],
    enabledOutputFormats: ["packet", "raw"],
    initialEntries: defaultGoFlow2Entries,
    inputPresets: goflow2InputPresets,
    initState: () => ({
      commandOptions: { ...defaultCommandOptions },
      presetsCollapsed: false,
      useMapping: false,
      protobufFraming: false,
      mappingYAML: defaultMapping,
    }),
    renderConfigPanel: renderAdapterConfigPanel,
    buildRunRequest: buildGoFlow2RunRequest,
    normalizeRunResult: normalizeGoFlow2Result,
    async importCapture(files, options) {
      const imported = [];
      for (const file of files) {
        const payload = await fileToBase64(file);
        const response = globalThis.goflow2.inspectCapture({
          name: file.name,
          data: payload,
          mimeType: file.type || "application/octet-stream",
          importType: options.importType,
        });
        if (!response?.ok) {
          throw new Error(response?.error || `Could not inspect ${file.name}`);
        }
        imported.push(...response.result.packets.map((packet) => entryFromPacket(packet, options.importType)));
      }
      return imported;
    },
  },
  reflow: {
    id: "reflow",
    title: "ReFlow WASM",
    manifestPath: publicAssetPath("reflow-wasm-manifest.json"),
    fallbackRuntime: {
      id: "current",
      label: "Current build",
      version: "unknown",
      commit: "unknown",
      wasmPath: publicAssetPath("reflow.wasm"),
      execPath: publicAssetPath("wasm_exec.js"),
    },
    globalName: "reflow",
    enabledInputTypes: ["bytes", "flow", "json", "pcap", "pcapng"],
    enabledOutputFormats: ["packet", "raw"],
    inputPresets: reflowInputPresets,
    initialEntries: () => reflowInputPresets["json-flow"].entries(),
    initState: () => ({
      configYAML: starterConfig,
      presetsCollapsed: false,
      outputLimitEnabled: true,
      outputLimit: 100,
    }),
    renderConfigPanel: renderAdapterConfigPanel,
    buildRunRequest: buildReFlowRunRequest,
    normalizeRunResult: normalizeReFlowResult,
    async importCapture(files, options) {
      if (options.importType === "pcap" || options.importType === "pcapng") {
        return Promise.all(
          files.map(async (file) =>
            entry({
              type: options.importType,
              encoding: "base64",
              text: await fileToBase64(file),
              fileName: file.name,
            }),
          ),
        );
      }
      const response = globalThis.reflow.importCapture({
        files: await Promise.all(files.map(async (file) => ({ name: file.name, bytes: new Uint8Array(await file.arrayBuffer()) }))),
        format: "",
        payloadOnly: options.importType === "flow",
      });
      if (!response?.ok) {
        throw new Error(response?.error || "capture import failed");
      }
      return (response.result.entries || []).map((item) =>
        entry({
          type: item.type || options.importType || "bytes",
          encoding: "base64",
          text: item.payload || bytesToBase64(item.bytes || new Uint8Array()),
          receivedAt: item.receivedAt || "",
          capturedLen: item.length || 0,
          originalLen: item.length || 0,
        }),
      );
    },
  },
};

let activeAdapter = null;
let state = null;
let els = {};
let nextEntryID = 1;
let wasmScriptLoaded = false;
let wireViewReady = false;
let pendingWireViewMessage = null;
let pendingOutputWireViewCapture = null;
let inputWireViewCache = null;
let lastInputWireViewKey = "";
let lastOutputWireViewKey = "";
let protoDecodeCache = new Map();
const adapterWorkspaceCache = new Map();
let activeReceivedAtDraft = null;
let activeReceivedAtPickerID = null;
let inputWireViewUpdateTimer = 0;
let activeRun = null;
let nextRunID = 1;

const app = document.querySelector("#app");

window.addEventListener("hashchange", () => mount(routeFromHash()));
window.addEventListener("message", handleWireViewMessage);
document.addEventListener("click", handleDocumentClick);
mount(routeFromHash());

function hashRouteAndParams() {
  const raw = window.location.hash.replace(/^#\/?/, "");
  const queryStart = raw.indexOf("?");
  const route = (queryStart === -1 ? raw : raw.slice(0, queryStart)).split("&")[0];
  const query = queryStart === -1 ? "" : raw.slice(queryStart + 1);
  return { route, params: new URLSearchParams(query) };
}

function replaceHashRoute(route, params = hashRouteAndParams().params) {
  const query = params.toString();
  window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}#/${route}${query ? `?${query}` : ""}`);
}

function hashHref(route) {
  const params = hashRouteAndParams().params;
  const query = params.toString();
  return `#/${route}${query ? `?${query}` : ""}`;
}

function urlConfigState(params = hashRouteAndParams().params) {
  const encoded = params.get(urlConfigParam);
  if (!encoded) {
    return {};
  }
  try {
    const decoded = decodeURLJSON(encoded);
    return decoded?.v === urlConfigVersion && isPlainObject(decoded.adapters) ? decoded.adapters : {};
  } catch {
    return {};
  }
}

function writeURLConfigState(nextState) {
  const { route, params } = hashRouteAndParams();
  const adaptersConfig = Object.fromEntries(Object.entries(nextState || {}).filter(([, value]) => isPlainObject(value)));
  if (Object.keys(adaptersConfig).length) {
    params.set(urlConfigParam, encodeURLJSON({ v: urlConfigVersion, adapters: adaptersConfig }));
  } else {
    params.delete(urlConfigParam);
  }
  replaceHashRoute(adapters[route] ? route : activeAdapter?.id || "goflow2", params);
  updateDashboardNavHrefs();
}

function persistActiveAdapterConfig() {
  if (!activeAdapter || !state?.adapterState) {
    return;
  }
  writeURLConfigState({
    ...urlConfigState(),
    [activeAdapter.id]: serializedAdapterConfig(activeAdapter.id, state.adapterState),
  });
}

function resetActiveAdapter() {
  if (!activeAdapter) {
    return;
  }
  const nextState = { ...urlConfigState() };
  delete nextState[activeAdapter.id];
  adapterWorkspaceCache.delete(activeAdapter.id);
  writeURLConfigState(nextState);
  mount(activeAdapter.id, { preserveCurrent: false });
}

function updateDashboardNavHrefs() {
  for (const link of document.querySelectorAll("[data-dashboard-link]")) {
    link.href = hashHref(link.dataset.dashboardLink);
  }
}

function applyURLAdapterConfig(adapterID, adapterState, value) {
  if (!isPlainObject(value)) {
    return;
  }
  if (adapterID === "goflow2") {
    if (isPlainObject(value.commandOptions)) {
      adapterState.commandOptions = {
        ...adapterState.commandOptions,
        ...pickStringFields(value.commandOptions, ["scheme", "produce", "format"]),
      };
    }
    if (typeof value.useMapping === "boolean") {
      adapterState.useMapping = value.useMapping;
    }
    if (typeof value.protobufFraming === "boolean") {
      adapterState.protobufFraming = value.protobufFraming;
    }
    if (typeof value.mappingYAML === "string") {
      adapterState.mappingYAML = value.mappingYAML;
    }
    return;
  }
  if (adapterID === "reflow") {
    if (typeof value.configYAML === "string") {
      adapterState.configYAML = value.configYAML;
    }
    if (typeof value.outputLimitEnabled === "boolean") {
      adapterState.outputLimitEnabled = value.outputLimitEnabled;
    }
    if (Number.isFinite(value.outputLimit)) {
      adapterState.outputLimit = Math.max(1, Math.trunc(value.outputLimit));
    }
  }
}

function serializedAdapterConfig(adapterID, adapterState) {
  if (adapterID === "goflow2") {
    return {
      commandOptions: pickStringFields(adapterState.commandOptions || {}, ["scheme", "produce", "format"]),
      useMapping: Boolean(adapterState.useMapping),
      protobufFraming: Boolean(adapterState.protobufFraming),
      mappingYAML: adapterState.mapping?.value ?? adapterState.mappingYAML ?? defaultMapping,
    };
  }
  if (adapterID === "reflow") {
    return {
      configYAML: adapterState.config?.value ?? adapterState.configYAML ?? starterConfig,
      outputLimitEnabled: Boolean(adapterState.outputLimitEnabled),
      outputLimit: Math.max(1, Number(adapterState.outputLimit) || 100),
    };
  }
  return {};
}

function pickStringFields(source, fields) {
  const picked = {};
  for (const field of fields) {
    if (typeof source?.[field] === "string") {
      picked[field] = source[field];
    }
  }
  return picked;
}

function encodeURLJSON(value) {
  const json = JSON.stringify(value);
  const bytes = new TextEncoder().encode(json);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

function decodeURLJSON(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  const bytes = Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes));
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function routeFromHash() {
  const { route, params } = hashRouteAndParams();
  if (adapters[route]) {
    return route;
  }
  replaceHashRoute("goflow2", params);
  return "goflow2";
}

function cacheActiveAdapterWorkspace() {
  if (!activeAdapter || !state) {
    return;
  }
  try {
    if (els.packetList) {
      syncAllEntries({ lenient: true, allowInvalid: true });
    }
  } catch {
    // Keep the latest in-memory state even if a half-edited field cannot sync.
  }
  adapterWorkspaceCache.set(activeAdapter.id, {
    ui: serializedAdapterUIState(state.adapterState),
    entries: cloneInputEntries(state.entries),
    lastResult: cloneCacheValue(state.lastResult),
    outputFormat: state.outputFormat,
    outputEncoding: state.outputEncoding,
    collapsedOutputEntries: [...(state.collapsedOutputEntries || new Set())],
    logs: [...(state.logs || [])],
  });
}

function cloneInputEntries(entries = []) {
  return entries.map((item) => ({
    ...item,
    rawPayload: cloneInputPayloadValue(item.rawPayload),
  }));
}

function cloneCacheValue(value) {
  if (!value || typeof value !== "object") {
    return value;
  }
  if (typeof structuredClone === "function") {
    try {
      return structuredClone(value);
    } catch {
      return value;
    }
  }
  return value;
}

function serializedAdapterUIState(adapterState) {
  return {
    presetsCollapsed: Boolean(adapterState?.presetsCollapsed),
  };
}

function applyCachedAdapterUIState(adapterState, value) {
  if (!isPlainObject(value)) {
    return;
  }
  if (typeof value.presetsCollapsed === "boolean") {
    adapterState.presetsCollapsed = value.presetsCollapsed;
  }
}

function nextInputEntryID(entries = []) {
  return entries.reduce((nextID, item) => Math.max(nextID, Number(item.id) + 1 || 1), 1);
}

function mount(route, options = {}) {
  disposeActiveRun();
  if (options.preserveCurrent !== false) {
    cacheActiveAdapterWorkspace();
  }
  activeAdapter = adapters[route] || adapters.goflow2;
  nextEntryID = 1;
  inputWireViewCache = null;
  lastInputWireViewKey = "";
  lastOutputWireViewKey = "";
  protoDecodeCache = new Map();
  pendingOutputWireViewCapture = null;
  activeReceivedAtDraft = null;
  activeReceivedAtPickerID = null;
  clearInputWireViewUpdate();
  const adapterState = activeAdapter.initState();
  applyURLAdapterConfig(activeAdapter.id, adapterState, urlConfigState()[activeAdapter.id]);
  const cachedWorkspace = adapterWorkspaceCache.get(activeAdapter.id);
  applyCachedAdapterUIState(adapterState, cachedWorkspace?.ui);
  const entries = sortedInputEntries(cachedWorkspace?.entries?.length ? cloneInputEntries(cachedWorkspace.entries) : activeAdapter.initialEntries());
  nextEntryID = nextInputEntryID(entries);
  state = {
    adapterState,
    entries,
    runtime: activeAdapter.fallbackRuntime,
    runtimes: [activeAdapter.fallbackRuntime],
    lastResult: cloneCacheValue(cachedWorkspace?.lastResult || null),
    outputFormat: cachedWorkspace?.outputFormat || activeAdapter.enabledOutputFormats[0],
    outputEncoding: cachedWorkspace?.outputEncoding || "pretty",
    paneWeights: [0.34, 0.32, 0.38],
    stackSplits: {
      inputWireView: [0.48, 0.52],
      outputWireView: [0.56, 0.44],
      runtimeLog: [0.68, 0.32],
    },
    collapsedOutputEntries: new Set(cachedWorkspace?.collapsedOutputEntries || []),
    logs: [...(cachedWorkspace?.logs || [])],
    status: "Loading WASM",
    statusTone: "",
    running: false,
  };
  renderShell();
  renderInput();
  renderActiveConfigPanel();
  setLogEntries(state.logs);
  renderOutput();
  loadWasm().catch((error) => {
    setStatus(`WASM failed: ${error.message || error}`, "error");
    appendLogEntries([logEntry("stderr", "runtime", error)]);
  });
}

function renderShell() {
  app.innerHTML = `
    <main class="shell" data-dashboard="${activeAdapter.id}">
      <header class="app-toolbar" aria-label="Runtime controls">
        <nav class="dashboard-nav" aria-label="Dashboards">
          <a data-dashboard-link="goflow2" href="${escapeHTML(hashHref("goflow2"))}" class="${activeAdapter.id === "goflow2" ? "active" : ""}">GoFlow2</a>
          <a data-dashboard-link="reflow" href="${escapeHTML(hashHref("reflow"))}" class="${activeAdapter.id === "reflow" ? "active" : ""}">ReFlow</a>
        </nav>
        <label class="wasm-select-label" for="wasm-version-select" aria-label="WASM version">
          <span class="wasm-select-prefix" aria-hidden="true">WASM</span>
          <select id="wasm-version-select" class="wasm-version-select" aria-label="WASM version" disabled></select>
        </label>
      </header>
      <section class="pane input-pane" aria-label="Input">
        <header class="pane-header">
          <h1>${escapeHTML(activeAdapter.title)}</h1>
          <div class="header-actions">
            <button id="reset" class="secondary" type="button">Reset</button>
            <button id="run" class="primary" type="button" disabled>Run</button>
          </div>
        </header>
        <div class="import-panel">
          <input id="capture-file" type="file" accept="${captureImportAccept}" multiple hidden />
          <select id="import-capture-action" class="capture-import-select" aria-label="Import or add input">
            <option value="">Import/add...</option>
            ${
              activeAdapter.enabledInputTypes.includes("bytes")
                ? `<optgroup label="Add">
                    <option value="add-empty">Add empty</option>
                  </optgroup>`
                : ""
            }
            <optgroup label="Import">
              <option value="json-list">Import JSON input list</option>
              ${activeAdapter.enabledInputTypes.includes("bytes") ? `<option value="bytes">Import PCAP as bytes</option>` : ""}
              ${activeAdapter.enabledInputTypes.includes("flow") ? `<option value="flow">Import PCAP as flow</option>` : ""}
              ${activeAdapter.enabledInputTypes.includes("pcap") ? `<option value="pcap">Import whole PCAP</option>` : ""}
              ${activeAdapter.enabledInputTypes.includes("pcapng") ? `<option value="pcapng">Import whole PCAPNG</option>` : ""}
            </optgroup>
            ${renderInputPresetOptions()}
          </select>
        </div>
        <div class="input-split${hasInputWireView() ? "" : " input-split--editor-only"}">
          <section class="packet-input-panel" aria-label="Packet input">
            <div class="section-title packet-input-title">
              <label>Input Entries</label>
              <div class="packet-input-actions">
                <span id="packet-input-meta" class="capture-summary">0 entries</span>
                <button id="copy-inputs" type="button">Copy</button>
                <button id="download-inputs" type="button">Download</button>
                <button id="collapse-all-packets" class="collapse-icon-button panel-icon-button" type="button" aria-label="Collapse all input entries" title="Collapse all input entries">${collapseChevron(false)}</button>
                <button id="expand-all-packets" class="collapse-icon-button panel-icon-button" type="button" aria-label="Expand all input entries" title="Expand all input entries">${collapseChevron(true)}</button>
                <button id="clear-inputs" type="button">Clear all</button>
              </div>
            </div>
            <div id="packet-list" class="packet-list"></div>
          </section>
          ${
            hasInputWireView()
              ? `<div class="splitter splitter-horizontal" data-splitter="input-wireview" role="separator" aria-orientation="horizontal" tabindex="0"></div>
                <section class="wireview-panel" aria-label="WireView input packet">
                  <div class="wireview-header">
                    <span>WireView</span>
                    <span id="wireview-status">No capture</span>
                  </div>
                  <iframe id="wireview-frame" title="WireView capture visualization" src="/wireview.html"></iframe>
                </section>`
              : ""
          }
        </div>
      </section>
      <div class="splitter splitter-vertical" data-splitter="input-config" role="separator" aria-orientation="vertical" tabindex="0"></div>
      <section class="pane config-pane" aria-label="Configuration">
        <div class="config-split">
          <div id="config-root"></div>
          <div class="splitter splitter-horizontal" data-splitter="runtime-log" role="separator" aria-orientation="horizontal" tabindex="0"></div>
          <section class="log-section" aria-label="Runtime log">
            <header class="log-header">
              <div class="log-title">
                <h2>${escapeHTML(activeAdapter.title)} log</h2>
                <p id="wasm-version" class="wasm-version">Loading runtime metadata</p>
              </div>
              <div class="log-actions">
                <button id="clear-log" type="button">Clear</button>
              </div>
            </header>
            <pre id="log" class="runtime-log" aria-live="polite"></pre>
          </section>
        </div>
      </section>
      <div class="splitter splitter-vertical" data-splitter="config-output" role="separator" aria-orientation="vertical" tabindex="0"></div>
      <section class="pane output-pane" aria-label="Output">
        <header class="pane-header">
          <h2>Output</h2>
        </header>
        <div class="output-toolbar">
          <span id="status" class="status hidden">Loading WASM</span>
          <div class="byte-output-options">
            <span>Display</span>
            <div id="output-format" class="output-format-slider segmented" role="tablist" aria-label="Output display"></div>
          </div>
          <label id="encoding-options" class="byte-output-options hidden">
            Format
            <select id="output-encoding">
            </select>
          </label>
          <button id="copy-output" type="button" disabled>Copy</button>
          <button id="download-output" type="button" disabled>Download</button>
          <button id="collapse-all-output" class="collapse-icon-button panel-icon-button" type="button" aria-label="Collapse all output records" title="Collapse all output records">${collapseChevron(false)}</button>
          <button id="expand-all-output" class="collapse-icon-button panel-icon-button" type="button" aria-label="Expand all output records" title="Expand all output records">${collapseChevron(true)}</button>
        </div>
        <div id="stats" class="stats"></div>
        <div class="output-split">
          <div id="output" class="output-body"></div>
          <div class="splitter splitter-horizontal hidden" data-splitter="output-wireview" role="separator" aria-orientation="horizontal" tabindex="0"></div>
          <section id="output-wireview-panel" class="wireview-panel output-wireview-panel hidden" aria-label="WireView output packet">
            <div class="wireview-header">
              <span>WireView</span>
              <span id="output-wireview-status">No capture</span>
            </div>
            <iframe id="output-wireview-frame" class="output-wireview-frame" title="Output WireView capture visualization" src="/wireview.html"></iframe>
          </section>
        </div>
      </section>
    </main>
  `;
  els = {
    captureFile: document.querySelector("#capture-file"),
    importCaptureAction: document.querySelector("#import-capture-action"),
    packetList: document.querySelector("#packet-list"),
    shell: document.querySelector(".shell"),
    inputSplit: document.querySelector(".input-split"),
    configSplit: document.querySelector(".config-split"),
    inputPane: document.querySelector(".input-pane"),
    configPane: document.querySelector(".config-pane"),
    outputPane: document.querySelector(".output-pane"),
    packetInputMeta: document.querySelector("#packet-input-meta"),
    wireviewFrame: document.querySelector("#wireview-frame"),
    wireviewPanel: document.querySelector("#wireview-frame")?.closest(".wireview-panel") || null,
    wireviewStatus: document.querySelector("#wireview-status"),
    configRoot: document.querySelector("#config-root"),
    log: document.querySelector("#log"),
    wasmVersion: document.querySelector("#wasm-version"),
    wasmVersionSelect: document.querySelector("#wasm-version-select"),
    status: document.querySelector("#status"),
    stats: document.querySelector("#stats"),
    output: document.querySelector("#output"),
    outputSplit: document.querySelector(".output-split"),
    outputWireViewSplitter: document.querySelector('[data-splitter="output-wireview"]'),
    outputWireViewPanel: document.querySelector("#output-wireview-panel"),
    outputWireViewStatus: document.querySelector("#output-wireview-status"),
    outputWireViewFrame: document.querySelector("#output-wireview-frame"),
    outputFormat: document.querySelector("#output-format"),
    outputEncoding: document.querySelector("#output-encoding"),
    encodingOptions: document.querySelector("#encoding-options"),
    run: document.querySelector("#run"),
  };
  document.querySelector("#reset").addEventListener("click", resetActiveAdapter);
  els.run.addEventListener("click", handleRunClick);
  els.packetList.addEventListener("input", handleInputEdit);
  els.packetList.addEventListener("change", handleInputEdit);
  els.packetList.addEventListener("copy", handleInputCopy);
  els.packetList.addEventListener("click", handleInputClick);
  els.packetList.addEventListener("focusin", handleInputFocus);
  els.packetList.addEventListener("focusout", handleInputBlur);
  document.querySelector("#clear-inputs").addEventListener("click", clearInputEntries);
  document.querySelector("#copy-inputs").addEventListener("click", copyInputs);
  document.querySelector("#download-inputs").addEventListener("click", downloadInputs);
  document.querySelector("#collapse-all-packets").addEventListener("click", () => setAllInputCollapsed(true));
  document.querySelector("#expand-all-packets").addEventListener("click", () => setAllInputCollapsed(false));
  els.importCaptureAction.addEventListener("change", startCaptureImport);
  els.captureFile.addEventListener("change", finishCaptureImport);
  els.wasmVersionSelect.addEventListener("change", () => switchWasmRuntime(els.wasmVersionSelect.value));
  document.querySelector("#clear-log").addEventListener("click", () => setLogEntries([]));
  els.outputFormat.addEventListener("click", (event) => {
    const button = event.target.closest?.("button[data-output-format]");
    if (!button) {
      return;
    }
    state.outputFormat = button.dataset.outputFormat;
    state.collapsedOutputEntries = state.outputFormat === "packet" ? initialCollapsedOutputEntries(state.lastResult) : new Set();
    renderOutput();
  });
  els.outputEncoding.addEventListener("change", () => {
    state.outputEncoding = els.outputEncoding.value;
    renderOutput();
  });
  document.querySelector("#collapse-all-output").addEventListener("click", () => setAllOutputCollapsed(true));
  document.querySelector("#expand-all-output").addEventListener("click", () => setAllOutputCollapsed(false));
  document.querySelector("#copy-output").addEventListener("click", copyOutput);
  document.querySelector("#download-output").addEventListener("click", downloadOutput);
  for (const splitter of document.querySelectorAll(".splitter-vertical")) {
    splitter.addEventListener("pointerdown", (event) => startPaneResize(event, splitter.dataset.splitter));
  }
  document.querySelector('[data-splitter="input-wireview"]')?.addEventListener("pointerdown", startInputWireViewResize);
  document.querySelector('[data-splitter="runtime-log"]').addEventListener("pointerdown", startRuntimeLogResize);
  els.outputWireViewSplitter.addEventListener("pointerdown", startOutputWireViewResize);
  els.wireviewFrame?.addEventListener("load", () => {
    wireViewReady = false;
    sendWireViewMessage({ type: "goflow-wireview-ping" });
  });
  els.outputWireViewFrame.addEventListener("load", () => {
    if (pendingOutputWireViewCapture) {
      postOutputWireViewCapture(pendingOutputWireViewCapture);
    }
  });
  applyPaneWeights();
  applyStackSplit(els.inputSplit, "inputWireView", "--packet-input-pane", "--wireview-pane");
  applyStackSplit(els.configSplit, "runtimeLog", "--config-editor-pane", "--runtime-log-pane");
  applyStackSplit(els.outputSplit, "outputWireView", "--output-results-pane", "--output-wireview-pane");
  renderOutputFormatControls();
}

function renderActiveConfigPanel() {
  activeAdapter.renderConfigPanel(els.configRoot, state.adapterState);
}

function hasInputWireView() {
  return activeAdapter?.id === "goflow2";
}

function renderAdapterConfigPanel(container, adapterState) {
  if (activeAdapter.id === "goflow2") {
    container.innerHTML = `
      <header class="pane-header">
        <h2>Command and Mapping</h2>
        <div class="header-actions">
          <button id="toggle-goflow-presets" class="preset-toggle collapse-icon-button panel-icon-button" type="button" aria-label="${
            adapterState.presetsCollapsed ? "Expand presets" : "Minimize presets"
          }" title="${adapterState.presetsCollapsed ? "Expand presets" : "Minimize presets"}" aria-expanded="${String(!adapterState.presetsCollapsed)}" aria-controls="goflow-preset-body">
            ${collapseChevron(adapterState.presetsCollapsed)}
          </button>
        </div>
      </header>
      <div class="command-panel config-preset-panel goflow-preset-panel${adapterState.presetsCollapsed ? " preset-panel--collapsed" : ""}" aria-label="Command presets" ${
        adapterState.presetsCollapsed ? "hidden" : ""
      }>
        <div id="goflow-preset-body" class="preset-panel-body" ${adapterState.presetsCollapsed ? "hidden" : ""}>
          <div class="goflow-preset-tools">
            <label for="goflow-output-preset">
              Output
              <select id="goflow-output-preset" class="preset-selector">
                ${Object.entries(goflow2OutputPresets)
                  .map(
                    ([key, preset]) =>
                      `<option value="${key}" ${selectedGoFlow2OutputPreset(adapterState.commandOptions) === key ? "selected" : ""}>${escapeHTML(preset.label)}</option>`,
                  )
                  .join("")}
              </select>
            </label>
            <button id="apply-goflow-output-preset" class="goflow-preset-action" type="button">Apply</button>
          </div>
        </div>
      </div>
      <div class="command-panel">
        <div class="section-title">
          <label for="command-input">CLI</label>
          <label class="mapping-toggle" for="use-mapping">
            <input id="use-mapping" type="checkbox" />
            <span>Use ${mappingPath}</span>
          </label>
          <label class="mapping-toggle" for="goflow-protobuf-framing">
            <input id="goflow-protobuf-framing" type="checkbox" ${adapterState.protobufFraming ? "checked" : ""} />
            <span>Length-delimited protobuf</span>
          </label>
        </div>
        <textarea id="command-input" spellcheck="false" readonly aria-readonly="true"></textarea>
      </div>
      <div class="mapping-panel goflow-mapping-editor">
        <div class="section-title">
          <label for="mapping-input">Mapping YAML</label>
          <button id="reset-mapping" type="button">Reset Mapping</button>
        </div>
        <textarea id="mapping-input" spellcheck="false">${escapeHTML(adapterState.mappingYAML)}</textarea>
      </div>
    `;
    adapterState.command = container.querySelector("#command-input");
    adapterState.mapping = container.querySelector("#mapping-input");
    adapterState.useMappingInput = container.querySelector("#use-mapping");
    adapterState.protobufFramingInput = container.querySelector("#goflow-protobuf-framing");
    container
      .querySelector("#toggle-goflow-presets")
      .addEventListener("click", () => setPresetPanelCollapsed(container, adapterState, !adapterState.presetsCollapsed));
    container.querySelector("#apply-goflow-output-preset").addEventListener("click", () => {
      const key = container.querySelector("#goflow-output-preset").value;
      setGoFlow2Command(goflow2OutputPresets[key]?.options || defaultCommandOptions);
    });
    container.querySelector("#reset-mapping").addEventListener("click", () => {
      const changed = adapterState.mappingYAML !== defaultMapping;
      adapterState.mapping.value = defaultMapping;
      adapterState.mappingYAML = defaultMapping;
      updateGoFlow2MappingInputHeight();
      persistActiveAdapterConfig();
      if (changed) {
        invalidateRunOutput();
      }
    });
    adapterState.mapping.addEventListener("input", () => {
      adapterState.mappingYAML = adapterState.mapping.value;
      updateGoFlow2MappingInputHeight();
      persistActiveAdapterConfig();
      invalidateRunOutput();
    });
    adapterState.useMappingInput.addEventListener("change", () => {
      adapterState.useMapping = adapterState.useMappingInput.checked;
      updateGoFlow2CommandDisplay();
      persistActiveAdapterConfig();
      invalidateRunOutput();
    });
    adapterState.protobufFramingInput.addEventListener("change", () => {
      adapterState.protobufFraming = adapterState.protobufFramingInput.checked;
      updateGoFlow2CommandDisplay();
      persistActiveAdapterConfig();
      invalidateRunOutput();
    });
    updateGoFlow2CommandDisplay();
    updateGoFlow2MappingInputHeight();
    return;
  }

  container.innerHTML = `
    <header class="pane-header">
      <h2>ReFlow Pipeline</h2>
      <div class="header-actions">
        <button id="copy-config" type="button">Copy</button>
        <button id="download-config" type="button">Download</button>
        <button id="toggle-reflow-presets" class="preset-toggle collapse-icon-button panel-icon-button" type="button" aria-label="${
          adapterState.presetsCollapsed ? "Expand presets" : "Minimize presets"
        }" title="${adapterState.presetsCollapsed ? "Expand presets" : "Minimize presets"}" aria-expanded="${String(!adapterState.presetsCollapsed)}" aria-controls="reflow-preset-body">
          ${collapseChevron(adapterState.presetsCollapsed)}
        </button>
        <button id="reset-config" type="button">Reset</button>
      </div>
    </header>
    <div class="command-panel config-preset-panel reflow-preset-panel${adapterState.presetsCollapsed ? " preset-panel--collapsed" : ""}" aria-label="Pipeline presets" ${
      adapterState.presetsCollapsed ? "hidden" : ""
    }>
      <div id="reflow-preset-body" class="preset-panel-body" ${adapterState.presetsCollapsed ? "hidden" : ""}>
        <div class="reflow-preset-tools">
          <label for="pipeline-preset">
            Pipeline preset
            <select id="pipeline-preset">
              ${Object.keys(reflowPipelinePresets).map((key) => `<option value="${key}">${escapeHTML(key)}</option>`).join("")}
            </select>
          </label>
          <button id="apply-pipeline-preset" class="reflow-preset-action" type="button">Apply</button>
        </div>
        <div class="reflow-preset-tools">
          <label for="processor-preset">
            Processor preset
            <select id="processor-preset">
              ${Object.keys(reflowProcessorPresets).map((key) => `<option value="${key}">${escapeHTML(key)}</option>`).join("")}
            </select>
          </label>
          <button id="apply-processor-preset" class="reflow-preset-action" type="button">Apply</button>
        </div>
        <div class="reflow-preset-tools">
          <label for="aggregator-preset">
            Aggregate preset
            <select id="aggregator-preset">
              ${Object.keys(reflowAggregatorPresets).map((key) => `<option value="${key}">${escapeHTML(key)}</option>`).join("")}
            </select>
          </label>
          <button id="apply-aggregator-preset" class="reflow-preset-action" type="button">Apply</button>
          <button id="append-aggregator-preset" class="reflow-preset-action" type="button">Append</button>
        </div>
        <div class="reflow-preset-tools">
          <label for="encoder-preset">
            Encoder preset
            <select id="encoder-preset">
              ${Object.keys(reflowEncoderPresets).map((key) => `<option value="${key}">${escapeHTML(key)}</option>`).join("")}
            </select>
          </label>
          <button id="apply-encoder-preset" class="reflow-preset-action" type="button">Apply</button>
        </div>
        <div class="reflow-preset-tools reflow-output-limit-tools">
          <label class="mapping-toggle" for="limit-output">
            <input id="limit-output" type="checkbox" ${adapterState.outputLimitEnabled ? "checked" : ""} />
            <span>Cap output</span>
          </label>
          <input id="output-limit" type="number" min="1" step="1" value="${escapeHTML(adapterState.outputLimit)}" ${adapterState.outputLimitEnabled ? "" : "disabled"} />
        </div>
      </div>
    </div>
    <div class="reflow-config-scroll">
      <div class="command-panel reflow-browser-panel">
        <div class="section-title">
          <span class="config-section-label">Source YAML</span>
          <span>generated from input entries</span>
        </div>
        <pre id="source-config-preview" class="locked-config-block" aria-label="Generated source YAML"></pre>
      </div>
      <div class="mapping-panel reflow-config-editor">
        <div class="section-title"><label for="config-input">Pipeline YAML</label></div>
        <textarea id="config-input" spellcheck="false">${escapeHTML(adapterState.configYAML)}</textarea>
      </div>
      <div class="command-panel reflow-browser-panel reflow-sink-panel">
        <div class="section-title">
          <span class="config-section-label">Sink YAML</span>
          <span>browser runtime output</span>
        </div>
        <pre id="sink-config-preview" class="locked-config-block" aria-label="Generated sink YAML"></pre>
      </div>
    </div>
  `;
  adapterState.config = container.querySelector("#config-input");
  adapterState.sourceConfigPreview = container.querySelector("#source-config-preview");
  adapterState.sinkConfigPreview = container.querySelector("#sink-config-preview");
  updateReFlowBrowserPreview();
  container
    .querySelector("#toggle-reflow-presets")
    .addEventListener("click", () => setPresetPanelCollapsed(container, adapterState, !adapterState.presetsCollapsed));
  adapterState.config.addEventListener("input", () => {
    adapterState.configYAML = adapterState.config.value;
    updateReFlowBrowserPreview();
    persistActiveAdapterConfig();
    invalidateRunOutput();
  });
  container.querySelector("#reset-config").addEventListener("click", () => {
    const changed = adapterState.configYAML !== starterConfig;
    adapterState.config.value = starterConfig;
    adapterState.configYAML = starterConfig;
    updateReFlowBrowserPreview();
    persistActiveAdapterConfig();
    if (changed) {
      invalidateRunOutput();
    }
  });
  container.querySelector("#download-config").addEventListener("click", () => {
    downloadText(buildReFlowBrowserConfig(adapterState.config.value), "reflow-browser-config.yaml", "text/yaml");
    setStatus("Config downloaded");
  });
  container.querySelector("#copy-config").addEventListener("click", async () => {
    await copyText(buildReFlowBrowserConfig(adapterState.config.value));
    setStatus("Config copied");
  });
  container.querySelector("#apply-pipeline-preset").addEventListener("click", () => {
    const key = container.querySelector("#pipeline-preset").value;
    adapterState.config.value = reflowPipelinePresets[key];
    adapterState.configYAML = adapterState.config.value;
    updateReFlowBrowserPreview();
    persistActiveAdapterConfig();
    invalidateRunOutput();
  });
  container.querySelector("#apply-processor-preset").addEventListener("click", () => {
    const key = container.querySelector("#processor-preset").value;
    adapterState.config.value = setYAMLSectionValues(adapterState.config.value, "processor", reflowProcessorPresets[key]);
    adapterState.configYAML = adapterState.config.value;
    updateReFlowBrowserPreview();
    persistActiveAdapterConfig();
    invalidateRunOutput();
  });
  container.querySelector("#apply-aggregator-preset").addEventListener("click", () => {
    const key = container.querySelector("#aggregator-preset").value;
    adapterState.config.value = replaceYAMLSection(adapterState.config.value, "aggregators:", reflowAggregatorPresets[key]);
    adapterState.configYAML = adapterState.config.value;
    updateReFlowBrowserPreview();
    persistActiveAdapterConfig();
    invalidateRunOutput();
  });
  container.querySelector("#append-aggregator-preset").addEventListener("click", () => {
    const key = container.querySelector("#aggregator-preset").value;
    adapterState.config.value = appendYAMLListItems(adapterState.config.value, "aggregators", reflowAggregatorPresets[key]);
    adapterState.configYAML = adapterState.config.value;
    updateReFlowBrowserPreview();
    persistActiveAdapterConfig();
    invalidateRunOutput();
  });
  container.querySelector("#apply-encoder-preset").addEventListener("click", () => {
    const key = container.querySelector("#encoder-preset").value;
    adapterState.config.value = setYAMLSectionValues(adapterState.config.value, "encoder", reflowEncoderPresets[key]);
    adapterState.configYAML = adapterState.config.value;
    updateReFlowBrowserPreview();
    persistActiveAdapterConfig();
    invalidateRunOutput();
  });
  container.querySelector("#limit-output").addEventListener("change", (event) => {
    adapterState.outputLimitEnabled = event.target.checked;
    container.querySelector("#output-limit").disabled = !adapterState.outputLimitEnabled;
    persistActiveAdapterConfig();
    invalidateRunOutput();
  });
  container.querySelector("#output-limit").addEventListener("input", (event) => {
    adapterState.outputLimit = Math.max(1, Number.parseInt(event.target.value, 10) || 100);
    persistActiveAdapterConfig();
    invalidateRunOutput();
  });
}

function updateReFlowBrowserPreview() {
  if (activeAdapter.id !== "reflow" || !state?.adapterState?.sourceConfigPreview || !state?.adapterState?.sinkConfigPreview) {
    return;
  }
  state.adapterState.sourceConfigPreview.textContent = `${generatedReFlowSourcesYAML()}\n`;
  state.adapterState.sinkConfigPreview.textContent = generatedReFlowSinkYAML();
  updateReFlowConfigInputHeight();
}

function updateReFlowConfigInputHeight() {
  const input = state?.adapterState?.config;
  if (activeAdapter.id !== "reflow" || !input) {
    return;
  }
  input.style.height = "auto";
  input.style.height = `${input.scrollHeight}px`;
}

function setPresetPanelCollapsed(container, adapterState, collapsed) {
  adapterState.presetsCollapsed = collapsed;
  const toggle = container.querySelector(".preset-toggle");
  const panel = container.querySelector(".config-preset-panel");
  const body = container.querySelector(".preset-panel-body");
  panel?.classList.toggle("preset-panel--collapsed", collapsed);
  if (panel) {
    panel.hidden = collapsed;
  }
  if (body) {
    body.hidden = collapsed;
  }
  if (toggle) {
    const label = collapsed ? "Expand presets" : "Minimize presets";
    toggle.innerHTML = collapseChevron(collapsed);
    toggle.setAttribute("aria-label", label);
    toggle.setAttribute("title", label);
    toggle.setAttribute("aria-expanded", String(!collapsed));
  }
}

function collapseChevron(collapsed) {
  return `<span class="collapse-chevron ${collapsed ? "collapse-chevron--expand" : "collapse-chevron--minimize"}" aria-hidden="true">${collapsed ? "+" : "_"}</span>`;
}

function selectedGoFlow2OutputPreset(options) {
  if (options?.produce === "raw") {
    return "raw";
  }
  if (options?.format === "bin") {
    return "proto";
  }
  return "json";
}

function setGoFlow2Command(options) {
  const nextOptions = { ...options };
  const changed = !sameCommandOptions(state.adapterState.commandOptions, nextOptions);
  state.adapterState.commandOptions = nextOptions;
  updateGoFlow2CommandDisplay();
  persistActiveAdapterConfig();
  if (changed) {
    invalidateRunOutput();
  }
}

function sameCommandOptions(left = {}, right = {}) {
  return left.scheme === right.scheme && left.produce === right.produce && left.format === right.format;
}

function updateGoFlow2CommandDisplay() {
  const adapterState = state.adapterState;
  if (adapterState.commandOptions.produce === "raw") {
    adapterState.useMapping = false;
  }
  const useMapping = adapterState.commandOptions.produce !== "raw" && adapterState.useMapping;
  adapterState.command.value = buildGoFlow2Command(adapterState.commandOptions, useMapping);
  adapterState.useMappingInput.checked = useMapping;
  adapterState.useMappingInput.disabled = adapterState.commandOptions.produce === "raw";
  if (adapterState.protobufFramingInput) {
    adapterState.protobufFramingInput.checked = Boolean(adapterState.protobufFraming);
    adapterState.protobufFramingInput.disabled = adapterState.commandOptions.format !== "bin";
  }
  const outputPreset = document.querySelector("#goflow-output-preset");
  if (outputPreset) {
    outputPreset.value = selectedGoFlow2OutputPreset(adapterState.commandOptions);
  }
}

function updateGoFlow2MappingInputHeight() {
  const input = state?.adapterState?.mapping;
  if (activeAdapter.id !== "goflow2" || !input) {
    return;
  }
  input.style.height = "auto";
  input.style.height = `${input.scrollHeight}px`;
}

function buildGoFlow2Command(options, includeMapping) {
  const args = [
    "goflow2",
    "-listen",
    `${options.scheme || "flow"}://pcap`,
    "-produce",
    options.produce || "sample",
    "-format",
    options.format || "json",
  ];
  if (includeMapping) {
    args.push("-mapping", mappingPath);
  }
  return args.join(" ");
}

function renderInput() {
  sortInputEntries();
  els.packetList.innerHTML = state.entries.map(renderInputEntry).join("");
  for (const textarea of els.packetList.querySelectorAll("textarea")) {
    updateByteEditor(textarea);
  }
  updateInputMeta();
  updateRunAvailability();
  updateInputWireView();
  updateReFlowBrowserPreview();
}

function renderInputPresetOptions() {
  const presets = Object.entries(activeAdapter.inputPresets || {});
  if (presets.length === 0) {
    return "";
  }
  return [
    `<optgroup label="Presets">`,
    ...presets.map(([key, preset]) => `<option value="preset:${escapeHTML(key)}">Preset: ${escapeHTML(preset.label || key)}</option>`),
    `</optgroup>`,
  ].join("");
}

function renderInputEntry(item, index) {
  const type = displayInputType(item);
  const encoding = type === "unknown" ? "raw" : item.encoding === "base64" ? "base64" : "hex";
  const title = inputEntryTitle(item, index);
  const bodyID = `entry-body-${item.id}`;
  const receivedAtID = `received-at-${item.id}`;
  const collapsed = Boolean(item.collapsed);
  const inputError = inputEntryValidationError(item);
  return `
    <article class="packet-card${collapsed ? " packet-card--collapsed" : ""}" data-entry-id="${item.id}" data-packet-type="${escapeHTML(type)}" data-packet-encoding="${escapeHTML(encoding)}">
      <header class="packet-card-head" data-input-action="toggle-collapse" aria-expanded="${collapsed ? "false" : "true"}" aria-controls="${escapeHTML(bodyID)}">
        <div class="packet-card-title">
          <strong>${escapeHTML(title)}</strong>
          <span data-packet-meta>${escapeHTML(inputMetaLabel(item))}</span>
        </div>
        <div class="packet-card-actions">
          <button class="packet-icon-button" type="button" data-input-action="duplicate" aria-label="Duplicate ${escapeHTML(title)}" title="Duplicate ${escapeHTML(title)}">⧉</button>
          <button class="packet-icon-button collapse-icon-button" type="button" data-input-action="toggle-collapse" aria-label="${collapsed ? "Expand" : "Collapse"} ${escapeHTML(title)}">${collapseChevron(collapsed)}</button>
          <button class="packet-icon-button" type="button" data-input-action="remove" aria-label="Remove ${escapeHTML(title)}">✕</button>
        </div>
      </header>
      <div class="packet-card-tools" ${collapsed ? "hidden" : ""}>
        <label>
          Type
          <select data-field="type">
            ${
              type === "unknown"
                ? `<option value="unknown" selected>${escapeHTML(inputTypes.unknown)}</option>`
                : ""
            }
            ${activeAdapter.enabledInputTypes.map((candidate) => `<option value="${candidate}"${candidate === type ? " selected" : ""}>${escapeHTML(inputTypes[candidate])}</option>`).join("")}
          </select>
        </label>
        <div class="packet-time-field">
          <label for="${escapeHTML(receivedAtID)}">Received</label>
          <span class="packet-time-control">
            <input id="${escapeHTML(receivedAtID)}" type="text" data-field="receivedAt" value="${escapeHTML(receivedAtInputValue(item.receivedAt, item.id))}" placeholder="YYYY-MM-DD HH:mm:ss.SSS" autocomplete="off" spellcheck="false" aria-label="Received timestamp" />
            <button class="packet-time-pick" type="button" data-input-action="received-at-toggle" aria-label="Open received time picker" title="Open received time picker" aria-expanded="${activeReceivedAtPickerID === item.id ? "true" : "false"}">${calendarIcon()}</button>
            ${activeReceivedAtPickerID === item.id ? renderReceivedAtPicker(item) : ""}
          </span>
        </div>
      </div>
      ${
        type === "json"
          ? renderJSONEntryEditor(item, bodyID, collapsed)
          : `<div id="${escapeHTML(bodyID)}" class="packet-byte-editor packet-byte-editor--${escapeHTML(encoding)}${inputError ? " packet-byte-editor--invalid" : ""}" ${collapsed ? "hidden" : ""}>
              <div class="packet-byte-toolbar">
                <span>${escapeHTML(type === "unknown" ? "Payload" : encoding === "base64" ? "Base64 payload" : "Hex payload")}</span>
                <div class="packet-byte-actions">
                  ${
                    type === "unknown"
                      ? ""
                      : `<div class="packet-encoding-slider segmented" role="tablist" aria-label="${escapeHTML(title)} encoding">
                          <button class="${encoding === "hex" ? "active" : ""}" type="button" role="tab" data-packet-encoding="hex">Hex</button>
                          <button class="${encoding === "base64" ? "active" : ""}" type="button" role="tab" data-packet-encoding="base64">Base64</button>
                        </div>`
                  }
                </div>
              </div>
              <pre class="packet-byte-addresses" aria-hidden="true"></pre>
              <textarea spellcheck="false" wrap="${encoding === "hex" ? "off" : "soft"}" aria-invalid="${inputError ? "true" : "false"}">${escapeHTML(type === "unknown" ? item.text || "" : payloadText(item.text || "", encoding))}</textarea>
            </div>`
      }
    </article>
  `;
}

function renderReceivedAtPicker(item) {
  const values = receivedAtPickerValues(item);
  return `
    <div class="packet-time-picker" role="dialog" aria-label="Received time picker">
      <label>
        Date
        <span class="packet-time-picker-field">
          <input type="date" data-received-at-part="date" value="${escapeHTML(values.date)}" />
        </span>
      </label>
      <label>
        Time
        <span class="packet-time-picker-field">
          <input type="time" data-received-at-part="time" value="${escapeHTML(values.time)}" step="0.001" />
        </span>
      </label>
      <div class="packet-time-picker-actions">
        <button type="button" data-input-action="received-at-close">Close</button>
        <button type="button" data-input-action="received-at-now">Now</button>
        <button class="primary" type="button" data-input-action="received-at-apply">Apply</button>
      </div>
    </div>
  `;
}

function calendarIcon() {
  return `
    <svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      <path d="M4.5 2.5v2M11.5 2.5v2M3 5.5h10M3.5 3.5h9a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1h-9a1 1 0 0 1-1-1v-9a1 1 0 0 1 1-1Z" />
    </svg>
  `;
}

function renderJSONEntryEditor(item, bodyID, collapsed) {
  const text = item.text || "{}";
  const parsed = parseJSONEditorValue(text);
  const mode = jsonEditorMode(item);
  const tableMode = mode === "format" && parsed.ok && parsed.table;
  const rawText = prettyJSONText(text);
  return `
    <div id="${escapeHTML(bodyID)}" class="json-entry-editor" ${collapsed ? "hidden" : ""}>
      <div class="json-entry-toolbar">
        <span data-json-status>${escapeHTML(jsonEditorStatus(text))}</span>
        <div class="json-entry-actions">
          <div class="json-mode-slider segmented" role="tablist" aria-label="JSON editor mode">
            <button class="${mode === "raw" ? "active" : ""}" type="button" role="tab" data-json-mode="raw">Raw</button>
            <button class="${mode === "format" ? "active" : ""}" type="button" role="tab" data-json-mode="format">Format</button>
          </div>
        </div>
      </div>
      ${
        tableMode
          ? renderJSONFieldTable(parsed.value)
          : `<textarea class="json-raw-editor" data-json-raw spellcheck="false">${escapeHTML(rawText)}</textarea>`
      }
    </div>
  `;
}

function renderJSONFieldTable(value) {
  const rows = Object.entries(value).map(([key, child]) => renderJSONFieldRow(key, child)).join("");
  return `
    <div class="json-table-wrap">
      <table class="json-field-table">
        <thead>
          <tr>
            <th>Field</th>
            <th>Value</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          ${rows || renderJSONFieldRow("", "")}
        </tbody>
      </table>
      <div class="json-table-footer">
        <button type="button" data-input-action="add-json-field">Add Field</button>
      </div>
    </div>
  `;
}

function renderJSONFieldRow(key, value) {
  return `
    <tr data-json-row>
      <td><input data-json-field="key" value="${escapeHTML(key)}" spellcheck="false" /></td>
      <td>${renderJSONValueControl(value)}</td>
      <td><button class="packet-icon-button" type="button" data-input-action="remove-json-field" aria-label="Remove JSON field">✕</button></td>
    </tr>
  `;
}

function renderJSONValueControl(value) {
  const type = jsonValueType(value);
  if (type === "object" || type === "array") {
    return `<textarea data-json-field="value" data-json-value spellcheck="false">${escapeHTML(JSON.stringify(value, null, 2))}</textarea>`;
  }
  return `<input data-json-field="value" data-json-value value="${escapeHTML(jsonValueInputText(value))}" spellcheck="false" />`;
}

function handleInputClick(event) {
  const jsonModeButton = event.target.closest?.(".json-mode-slider button[data-json-mode]");
  if (jsonModeButton) {
    const card = jsonModeButton.closest(".packet-card");
    const item = entryByID(card?.dataset.entryId);
    if (!item) {
      return;
    }
    try {
      syncEntryFromCard(card, item, { lenient: true });
      item.jsonMode = jsonModeButton.dataset.jsonMode === "raw" ? "raw" : "format";
      item.text = item.jsonMode === "raw" ? prettyJSONText(item.text) : item.text;
      renderInput();
      setStatus(state.runtimeReady ? "WASM ready" : state.status, state.statusTone);
    } catch (error) {
      setStatus(error.message || String(error), "error");
    }
    return;
  }
  const encodingButton = event.target.closest?.(".packet-encoding-slider button[data-packet-encoding]");
  if (encodingButton) {
    const card = encodingButton.closest(".packet-card");
    const item = entryByID(card?.dataset.entryId);
    if (!item) {
      return;
    }
    try {
      syncEntryFromCard(card, item, { lenient: true });
      const nextEncoding = encodingButton.dataset.packetEncoding;
      item.text = convertPayloadText(item.text || "", item.encoding || "hex", nextEncoding);
      item.encoding = nextEncoding;
      renderInput();
    } catch (error) {
      setStatus(error.message || String(error), "error");
    }
    return;
  }
  const action = event.target.closest?.("[data-input-action]")?.dataset.inputAction;
  if (!action) {
    return;
  }
  const card = event.target.closest(".packet-card");
  const item = entryByID(card?.dataset.entryId);
  if (!item) {
    return;
  }
  if (action === "add-json-field") {
    try {
      syncEntryFromCard(card, item, { lenient: true });
      const value = jsonObjectValue(item.text);
      value[nextJSONFieldName(value)] = "";
      item.text = JSON.stringify(value, null, 2);
      renderInput();
      setStatus(state.runtimeReady ? "WASM ready" : state.status, state.statusTone);
    } catch (error) {
      setStatus(error.message || String(error), "error");
    }
  } else if (action === "remove-json-field") {
    try {
      event.preventDefault();
      const row = event.target.closest("[data-json-row]");
      row?.remove();
      syncEntryFromCard(card, item, { lenient: true });
      renderInput();
      setStatus(state.runtimeReady ? "WASM ready" : state.status, state.statusTone);
    } catch (error) {
      setStatus(error.message || String(error), "error");
    }
  } else if (action === "format-json" || action === "compact-json") {
    try {
      syncEntryFromCard(card, item, { lenient: true });
      item.text = formatJSONText(item.text, action === "format-json" ? 2 : 0);
      renderInput();
      setStatus(state.runtimeReady ? "WASM ready" : state.status, state.statusTone);
    } catch (error) {
      setStatus(error.message || String(error), "error");
    }
  } else if (action === "received-at-toggle") {
    event.preventDefault();
    try {
      activeReceivedAtDraft = {
        entryID: item.id,
        value: card.querySelector('input[data-field="receivedAt"]')?.value || "",
      };
      syncEntryFromCard(card, item, { lenient: true });
      activeReceivedAtPickerID = activeReceivedAtPickerID === item.id ? null : item.id;
      renderInput();
      setStatus(state.runtimeReady ? "WASM ready" : state.status, state.statusTone);
    } catch (error) {
      setStatus(error.message || String(error), "error");
    }
  } else if (action === "received-at-close") {
    event.preventDefault();
    activeReceivedAtPickerID = null;
    renderInput();
    setStatus(state.runtimeReady ? "WASM ready" : state.status, state.statusTone);
  } else if (action === "received-at-apply") {
    event.preventDefault();
    try {
      syncEntryFromCard(card, item, { lenient: true });
      item.receivedAt = readReceivedAtPicker(card).toISOString();
      activeReceivedAtDraft = null;
      activeReceivedAtPickerID = null;
      sortInputEntries();
      renderInput();
      setStatus(state.runtimeReady ? "WASM ready" : state.status, state.statusTone);
    } catch (error) {
      setStatus(error.message || String(error), "error");
    }
  } else if (action === "received-at-now") {
    event.preventDefault();
    try {
      syncEntryFromCard(card, item, { lenient: true, commitReceivedAt: true });
      activeReceivedAtDraft = null;
      activeReceivedAtPickerID = null;
      item.receivedAt = new Date().toISOString();
      sortInputEntries();
      renderInput();
      setStatus(state.runtimeReady ? "WASM ready" : state.status, state.statusTone);
    } catch (error) {
      setStatus(error.message || String(error), "error");
    }
  } else if (action === "duplicate") {
    try {
      syncEntryFromCard(card, item, { lenient: true, commitReceivedAt: true });
      activeReceivedAtDraft = null;
      activeReceivedAtPickerID = null;
      const index = state.entries.indexOf(item);
      const copy = duplicateInputEntry(item);
      state.entries.splice(index < 0 ? state.entries.length : index + 1, 0, copy);
      sortInputEntries();
      renderInput();
      setStatus("Input duplicated");
    } catch (error) {
      setStatus(error.message || String(error), "error");
    }
  } else if (action === "remove") {
    state.entries = state.entries.filter((candidate) => candidate.id !== item.id);
    renderInput();
  } else if (action === "toggle-collapse") {
    item.collapsed = !item.collapsed;
    applyInputEntryCollapsed(card, item.collapsed, item);
  }
}

function applyInputEntryCollapsed(card, collapsed, item = entryByID(card?.dataset.entryId)) {
  if (!card) {
    return;
  }
  card.classList.toggle("packet-card--collapsed", collapsed);
  const header = card.querySelector(".packet-card-head");
  header?.setAttribute("aria-expanded", collapsed ? "false" : "true");
  const title = item ? inputEntryTitle(item, state.entries.indexOf(item)) : "input entry";
  const button = card.querySelector(".collapse-icon-button[data-input-action='toggle-collapse']");
  if (button) {
    button.setAttribute("aria-label", `${collapsed ? "Expand" : "Collapse"} ${title}`);
    button.innerHTML = collapseChevron(collapsed);
  }
  for (const body of card.querySelectorAll(":scope > .packet-card-tools, :scope > .packet-byte-editor, :scope > .json-entry-editor")) {
    body.hidden = collapsed;
  }
}

function handleInputEdit(event) {
  if (event.target.closest?.(".packet-time-picker")) {
    return;
  }
  const card = event.target.closest?.(".packet-card");
  const item = entryByID(card?.dataset.entryId);
  if (!item) {
    return;
  }
  if (event.target.matches?.('input[data-field="receivedAt"]')) {
    activeReceivedAtDraft = {
      entryID: item.id,
      value: event.target.value,
    };
  }
  try {
    const previousType = item.type;
    const liveByteEdit = event.target.matches?.(".packet-byte-editor textarea");
    syncEntryFromCard(card, item, { commitReceivedAt: event.type === "change", allowInvalid: liveByteEdit });
    if (event.target.matches?.('input[data-field="receivedAt"]')) {
      updateInputEntryMeta(card, item);
      updateInputMeta();
      updateRunAvailability();
      updateInputWireView();
      setStatus(state.runtimeReady ? "WASM ready" : state.status, state.statusTone);
      if (event.type === "change") {
        activeReceivedAtDraft = null;
        sortInputEntries();
        renderInput();
      }
      return;
    }
    if (event.target.matches?.('select[data-field="type"]') || item.type !== previousType) {
      renderInput();
      setStatus(state.runtimeReady ? "WASM ready" : state.status, state.statusTone);
      return;
    }
    if (liveByteEdit && !item.inputError) {
      formatHexEditorInput(event.target);
    }
    updateByteEditor(card.querySelector("textarea"));
    updateInputEntryMeta(card, item);
    updateInputMeta();
    updateRunAvailability();
    if (item.inputError) {
      scheduleInputWireViewUpdate();
      setStatus(item.inputError, "error");
      return;
    }
    if (liveByteEdit) {
      scheduleInputWireViewUpdate();
    } else {
      updateInputWireView();
    }
    setStatus(state.runtimeReady ? "WASM ready" : state.status, state.statusTone);
  } catch (error) {
    setStatus(error.message || String(error), "error");
    if (els.wireviewStatus) {
      els.wireviewStatus.textContent = error.message || String(error);
    }
  }
}

function handleInputCopy(event) {
  const textarea = event.target.closest?.(".packet-byte-editor--hex textarea");
  if (!textarea || textarea.selectionStart === textarea.selectionEnd) {
    return;
  }
  event.clipboardData?.setData("text/plain", textarea.value.slice(textarea.selectionStart, textarea.selectionEnd).replace(/\s+/g, ""));
  event.preventDefault();
}

function handleInputFocus(event) {
  if (!event.target.matches?.('input[data-field="receivedAt"]')) {
    return;
  }
  const card = event.target.closest(".packet-card");
  const item = entryByID(card?.dataset.entryId);
  if (!item) {
    return;
  }
  activeReceivedAtDraft = {
    entryID: item.id,
    value: event.target.value,
  };
}

function handleInputBlur(event) {
  if (!event.target.matches?.('input[data-field="receivedAt"]')) {
    return;
  }
  const card = event.target.closest(".packet-card");
  const item = entryByID(card?.dataset.entryId);
  if (!item) {
    return;
  }
  if (isReceivedAtControlTarget(event.relatedTarget, card)) {
    activeReceivedAtDraft = {
      entryID: item.id,
      value: event.target.value,
    };
    return;
  }
  try {
    activeReceivedAtDraft = {
      entryID: item.id,
      value: event.target.value,
    };
    syncEntryFromCard(card, item, { commitReceivedAt: true });
    activeReceivedAtDraft = null;
    sortInputEntries();
    renderInput();
    setStatus(state.runtimeReady ? "WASM ready" : state.status, state.statusTone);
  } catch (error) {
    setStatus(error.message || String(error), "error");
  }
}

function handleDocumentClick(event) {
  if (!activeReceivedAtPickerID || event.target.closest?.(".packet-time-control")) {
    return;
  }
  activeReceivedAtPickerID = null;
  renderInput();
}

function isReceivedAtControlTarget(target, card) {
  if (!target || !card?.contains?.(target)) {
    return false;
  }
  return Boolean(target.closest?.(".packet-time-control"));
}

function syncEntryFromCard(card, item, options = {}) {
  const previousType = card.dataset.packetType || item.type;
  const previousEncoding = previousType === "json" ? "utf8" : card.querySelector(".packet-encoding-slider button.active")?.dataset.packetEncoding || card.dataset.packetEncoding || item.encoding || "hex";
  const nextType = card.querySelector('select[data-field="type"]')?.value || previousType;
  const textarea = card.querySelector("textarea");
  const jsonText = previousType === "json" ? jsonTextFromEditor(card, options) : "{}";
  const normalizedNextType = activeAdapter.enabledInputTypes.includes(nextType) || nextType === "unknown" ? nextType : previousType;
  item.receivedAt = readReceivedAt(card, item.receivedAt, {
    commit: Boolean(options.commitReceivedAt) || !isEditingReceivedAt(item.id),
  });
  item.collapsed = card.classList.contains("packet-card--collapsed");
  if (previousType === "unknown" && normalizedNextType === "unknown") {
    item.type = "unknown";
    item.encoding = "raw";
    item.inputError = "";
    item.text = textarea?.value || "";
    if (item.text !== item.rawPayloadText) {
      item.rawPayload = item.text;
      item.rawPayloadText = item.text;
    }
    return;
  }
  if (normalizedNextType !== previousType) {
    const source = {
      type: previousType,
      encoding: previousEncoding === "base64" ? "base64" : previousType === "json" ? "utf8" : "hex",
      text:
        previousType === "json"
          ? jsonText
          : normalizedPayloadText(textarea?.value || "", previousEncoding === "base64" ? "base64" : "hex", options),
    };
    item.type = normalizedNextType;
    item.inputError = "";
    if (item.type !== "unknown") {
      item.originalType = "";
      item.rawPayload = undefined;
      item.rawPayloadText = "";
    } else {
      item.encoding = "raw";
      item.text = source.text || "";
      item.rawPayload = item.text;
      item.rawPayloadText = item.text;
      return;
    }
    item.encoding = defaultInputEncoding(normalizedNextType, source);
    item.text = convertEntryText(source, normalizedNextType, item.encoding, options);
    if (item.type === "json" && !options.lenient) {
      JSON.parse(item.text || "{}");
    }
    return;
  }
  item.type = normalizedNextType;
  item.inputError = "";
  if (item.type === "json") {
    item.encoding = "utf8";
    item.text = jsonText;
    if (!options.lenient) {
      JSON.parse(item.text || "{}");
    }
    return;
  }
  const encoding = card.querySelector(".packet-encoding-slider button.active")?.dataset.packetEncoding || card.dataset.packetEncoding || "hex";
  item.encoding = encoding === "base64" ? "base64" : "hex";
  const payload = payloadEditorValue(textarea?.value || "", item.encoding, options);
  item.text = payload.text;
  item.inputError = payload.error;
}

function clearInputEntries() {
  state.entries = [];
  state.lastResult = null;
  renderInput();
  renderOutput();
  setStatus(state.runtimeReady ? "WASM ready" : state.status, state.statusTone);
}

function setAllInputCollapsed(collapsed) {
  for (const item of state.entries) {
    item.collapsed = collapsed;
  }
  const cards = [...els.packetList.querySelectorAll(".packet-card")];
  if (cards.length) {
    for (const card of cards) {
      applyInputEntryCollapsed(card, collapsed, entryByID(card.dataset.entryId));
    }
    return;
  }
  renderInput();
}

function entryByID(id) {
  return state.entries.find((item) => String(item.id) === String(id));
}

async function startCaptureImport() {
  const importType = els.importCaptureAction.value;
  if (!importType) {
    return;
  }
  if (importType === "add-empty") {
    els.importCaptureAction.value = "";
    addEmptyInputEntry();
    return;
  }
  if (importType.startsWith("preset:")) {
    els.importCaptureAction.value = "";
    applyInputPreset(importType.slice("preset:".length));
    return;
  }
  els.captureFile.value = "";
  els.captureFile.accept = importType === "json-list" ? jsonInputImportAccept : captureImportAccept;
  els.captureFile.click();
}

function addEmptyInputEntry() {
  try {
    syncAllEntries({ lenient: true });
    state.entries.push(entry({ type: "bytes" }));
    renderInput();
    setStatus("Empty bytes entry added");
  } catch (error) {
    setStatus(error.message || String(error), "error");
    appendLogEntries([logEntry("stderr", "import", error)]);
  }
}

async function finishCaptureImport() {
  const importType = els.importCaptureAction.value;
  const files = [...(els.captureFile.files || [])];
  els.importCaptureAction.value = "";
  if (!importType || files.length === 0) {
    return;
  }
  try {
    setStatus("Importing capture");
    syncAllEntries({ lenient: true });
    const imported = importType === "json-list" ? await importInputList(files) : await activeAdapter.importCapture(files, { importType });
    state.entries.push(...imported);
    appendLogEntries([logEntry("stdout", "import", `imported ${imported.length} ${importLabel(importType)} entries`)]);
    renderInput();
    setStatus(importType === "json-list" ? "Input list imported" : "Capture imported");
  } catch (error) {
    setStatus(error.message || String(error), "error");
    appendLogEntries([logEntry("stderr", "import", error)]);
  }
}

function applyInputPreset(key) {
  const preset = activeAdapter.inputPresets?.[key];
  if (!preset) {
    setStatus(`Unknown preset ${key}`, "error");
    return;
  }
  try {
    syncAllEntries({ lenient: true });
    const imported = preset.entries();
    state.entries.push(...imported);
    appendLogEntries([logEntry("stdout", "import", `imported preset ${preset.label || key} (${imported.length} entries)`)]);
    renderInput();
    setStatus("Preset imported");
  } catch (error) {
    setStatus(error.message || String(error), "error");
    appendLogEntries([logEntry("stderr", "import", error)]);
  }
}

async function importInputList(files) {
  const imported = [];
  for (const file of files) {
    const value = JSON.parse(await file.text());
    imported.push(...entriesFromExportedInputValue(value));
  }
  return imported;
}

function importLabel(importType) {
  return importType === "json-list" ? "JSON input list" : importType;
}

function renderOutputFormatControls(activeFormat = availableOutputFormat(state.outputFormat, state.lastResult)) {
  els.outputFormat.innerHTML = activeAdapter.enabledOutputFormats
    .map(
      (format) => `
        <button class="${format === activeFormat ? "active" : ""}" type="button" role="tab" aria-selected="${String(format === activeFormat)}" data-output-format="${format}">
          ${escapeHTML(outputFormats[format])}
        </button>
      `,
    )
    .join("");
}

function renderOutput() {
  updateStatusElement();
  const result = state.lastResult;
  const format = availableOutputFormat(state.outputFormat, result);
  state.outputFormat = format;
  renderOutputFormatControls(format);
  const encodings = outputEncodingOptions(result, format);
  const encodingLocked = format === "raw" && encodings.length <= 1;
  const encoding = effectiveOutputEncoding(result, format);
  const displayedEncoding = encodingLocked ? state.outputEncoding || encoding : encoding;
  const displayedEncodings = encodingLocked ? [{ value: displayedEncoding, disabled: false }] : outputEncodingDisplayOptions(result, format, encodings);
  if (!encodingLocked) {
    state.outputEncoding = encoding;
  }
  els.encodingOptions.classList.toggle("hidden", encodings.length <= 1 && !encodingLocked);
  els.outputEncoding.disabled = encodingLocked;
  els.outputEncoding.innerHTML = displayedEncodings
    .map(
      (item) =>
        `<option value="${item.value}"${item.value === displayedEncoding ? " selected" : ""}${item.disabled ? " disabled" : ""}>${escapeHTML(
          outputEncodings[item.value] || item.value,
        )}</option>`,
    )
    .join("");
  document.querySelector("#copy-output").disabled = !result;
  document.querySelector("#download-output").disabled = !result;
  els.stats.textContent = result ? statsText(result.stats) : "";
  updateOutputWireView(result);
  if (!result) {
    els.output.innerHTML = `<div class="empty-state">Run a capture to see output</div>`;
    return;
  }
  if (format === "packet") {
    renderPacketOutput(result, encoding);
  } else {
    els.output.innerHTML = `<pre>${escapeHTML(rawOutputText(result, encoding))}</pre>`;
  }
}

function invalidateRunOutput(message = "Config changed. Run again to refresh output.") {
  if (!state?.lastResult) {
    return false;
  }
  state.lastResult = null;
  state.collapsedOutputEntries = new Set();
  protoDecodeCache = new Map();
  lastOutputWireViewKey = "";
  pendingOutputWireViewCapture = null;
  setStatus(message, "stale");
  renderOutput();
  return true;
}

function availableOutputFormat(format, result) {
  if (!activeAdapter.enabledOutputFormats.includes(format)) {
    return activeAdapter.enabledOutputFormats[0];
  }
  return format;
}

function outputEncodingOptions(result, format) {
  if (format === "raw") {
    if (result && (hasProtobufOutput(result) || hasBinaryOutput(result))) {
      return ["hex", "base64"];
    }
    return ["text"];
  }
  if (!result) {
    return format === "packet" ? ["pretty", "text"] : ["text", "pretty"];
  }
  if (hasProtobufOutput(result)) {
    return format === "packet" ? ["pretty", "hex", "base64"] : ["hex", "base64", "pretty"];
  }
  if (hasBinaryOutput(result)) {
    return ["hex", "base64"];
  }
  return format === "packet" ? ["pretty", "text"] : ["text", "pretty"];
}

function normalizedOutputEncoding(value, options) {
  if (options.includes(value)) {
    return value;
  }
  return options[0] || "text";
}

function outputEncodingDisplayOptions(result, format, encodings) {
  const disabled = format === "raw" && result && hasProtobufOutput(result) ? ["pretty"] : [];
  const items = [];
  const seen = new Set();
  for (const value of [...disabled, ...encodings]) {
    if (seen.has(value)) {
      continue;
    }
    seen.add(value);
    items.push({ value, disabled: disabled.includes(value) });
  }
  return items;
}

function effectiveOutputEncoding(result = state.lastResult, format = state.outputFormat) {
  const encodings = outputEncodingOptions(result, format);
  if (format === "raw" && encodings.length <= 1) {
    return encodings[0] || "text";
  }
  return normalizedOutputEncoding(state.outputEncoding, encodings);
}

function renderPacketOutput(result, encoding) {
  const sections = [];
  const entries = shouldRenderParsedOutputEntries(result) ? parsedEntries(result) : [];
  const packets = packetPayloadEntries(result);
  if (entries.length) {
    sections.push(
      encoding === "text"
        ? `<pre>${escapeHTML(jsonLinesText(result, "text"))}</pre>`
        : entries.map(renderOutputRecord).join(""),
    );
  }
  if (packets.length) {
    sections.push(packets.map((item, index) => renderPacketPayloadRecord(item, index, encoding)).join(""));
  }
  els.output.innerHTML = sections.length ? sections.join("") : `<div class="empty-state">No packet output</div>`;
  for (const button of els.output.querySelectorAll("[data-output-action='download-packet']")) {
    button.addEventListener("click", downloadOutputPacket);
  }
  for (const header of els.output.querySelectorAll("[data-output-action='toggle-collapse']")) {
    header.addEventListener("click", toggleOutputRecord);
  }
}

function renderOutputRecord(entry) {
  const key = entry.key || String(entry.index);
  const collapsed = state.collapsedOutputEntries.has(key);
  const rows = Object.entries(flattenObject(entry.fields || entry.parsed || {}))
    .map(([name, value]) => `<tr><th>${escapeHTML(name)}</th><td>${escapeHTML(formatValue(value))}</td></tr>`)
    .join("");
  return `
    <article class="record output-record${collapsed ? " output-record--collapsed" : ""}" data-output-entry="${escapeHTML(key)}">
      <header data-output-action="toggle-collapse" aria-expanded="${collapsed ? "false" : "true"}">
        <div class="record-title">
          <strong>${escapeHTML(entry.title || `#${entry.index}`)}</strong>
          <span>${escapeHTML(entry.summary || "")}</span>
        </div>
        <div class="record-actions">
          <button class="record-collapse-button collapse-icon-button" type="button" aria-label="${collapsed ? "Expand" : "Collapse"} output record">${collapseChevron(collapsed)}</button>
        </div>
      </header>
      <table ${collapsed ? "hidden" : ""}>${rows}</table>
    </article>
  `;
}

function renderPacketPayloadRecord(item, index, encoding) {
  const key = item.key || String(index + 1);
  const collapsed = state.collapsedOutputEntries.has(key);
  const sizeLabel = formatBytes(payloadLength(item));
  const html = collapsed ? "" : renderPacketPayloadBody(item, encoding);
  const label = item.protobuf && encoding === "pretty" ? protobufOutputLabel(item) : outputEncodings[encoding];
  return `
    <article class="record output-record proto-record${collapsed ? " output-record--collapsed" : ""}" data-output-entry="${escapeHTML(key)}" data-output-packet-index="${index}">
      <header data-output-action="toggle-collapse" aria-expanded="${collapsed ? "false" : "true"}">
        <div class="record-title">
          <strong>#${index + 1} ${escapeHTML(item.label || "Packet")}</strong>
          <span>${escapeHTML(item.summary || sizeLabel)}</span>
        </div>
        <div class="record-actions">
          <button class="record-action-button" type="button" data-output-action="download-packet" aria-label="Download packet #${index + 1}" title="Download packet #${index + 1}">↓</button>
          <button class="record-collapse-button collapse-icon-button" type="button" aria-label="${collapsed ? "Expand" : "Collapse"} packet output">${collapseChevron(collapsed)}</button>
        </div>
      </header>
      <div class="proto-record-body" data-output-body-rendered="${collapsed ? "false" : "true"}" data-output-body-encoding="${escapeHTML(encoding)}" ${collapsed ? "hidden" : ""}>
        <label>${escapeHTML(label)}</label>
        ${html}
      </div>
    </article>
  `;
}

function renderPacketPayloadBody(item, encoding) {
  if (item.protobuf && encoding === "pretty") {
    return `<pre>${escapeHTML(decodedProtoPayloadText(item))}</pre>`;
  }
  if (encoding === "base64") {
    return `<pre>${escapeHTML(wrapText(outputPayloadBase64(item), base64WrapColumns))}</pre>`;
  }
  return hexDumpHTML(outputPayloadHex(item), item.protobuf ? protoPayloadHexRanges(item) : []);
}

function protobufOutputLabel(item) {
  return item?.protobufFraming === "delimited" ? "protoc --decode_raw (varint-delimited)" : "protoc --decode_raw";
}

function updateOutputWireView(result) {
  const capture = outputWireViewCapture(result);
  if (!capture) {
    if (lastOutputWireViewKey === "empty") {
      return;
    }
    lastOutputWireViewKey = "empty";
    pendingOutputWireViewCapture = null;
    els.outputSplit.classList.remove("has-output-wireview");
    els.outputWireViewSplitter.classList.add("hidden");
    els.outputWireViewPanel.classList.add("hidden");
    els.outputWireViewStatus.textContent = "No capture";
    els.outputWireViewFrame.contentWindow?.postMessage({ type: "goflow-wireview-clear" }, window.location.origin);
    return;
  }
  const key = outputWireViewCacheKey(capture);
  pendingOutputWireViewCapture = capture;
  els.outputSplit.classList.add("has-output-wireview");
  els.outputWireViewSplitter.classList.remove("hidden");
  els.outputWireViewPanel.classList.remove("hidden");
  applyStackSplit(els.outputSplit, "outputWireView", "--output-results-pane", "--output-wireview-pane");
  if (key === lastOutputWireViewKey) {
    return;
  }
  lastOutputWireViewKey = key;
  els.outputWireViewStatus.textContent = "Loading";
  postOutputWireViewCapture(capture);
}

function outputWireViewCapture(result) {
  if (!result || activeAdapter.id !== "reflow" || !result.wireview) {
    return null;
  }
  if (result.kind === "json" || hasProtobufOutput(result)) {
    return null;
  }
  return hasBinaryOutput(result) ? result.wireview : null;
}

function postOutputWireViewCapture(capture) {
  els.outputWireViewFrame.contentWindow?.postMessage({ type: "goflow-wireview-open", capture }, window.location.origin);
}

function outputWireViewCacheKey(capture) {
  const bytes = captureBytes(capture);
  return [
    capture.filename || "",
    capture.mimeType || "",
    bytes.byteLength,
    capture.timeline?.length || 0,
    capture.timestamps?.length || 0,
    byteFingerprint(bytes),
  ].join("\u001f");
}

function byteFingerprint(bytes) {
  if (!bytes?.byteLength) {
    return "0";
  }
  let hash = 2166136261;
  const stride = Math.max(1, Math.floor(bytes.byteLength / 64));
  for (let index = 0; index < bytes.byteLength; index += stride) {
    hash ^= bytes[index];
    hash = Math.imul(hash, 16777619);
  }
  hash ^= bytes[bytes.byteLength - 1];
  hash = Math.imul(hash, 16777619);
  return String(hash >>> 0);
}

function toggleOutputRecord(event) {
  const article = event.target.closest("[data-output-entry]");
  const key = article?.dataset.outputEntry;
  if (!key) {
    return;
  }
  const collapsed = !state.collapsedOutputEntries.has(key);
  if (collapsed) {
    state.collapsedOutputEntries.add(key);
  } else {
    state.collapsedOutputEntries.delete(key);
  }
  applyOutputRecordCollapsed(article, collapsed);
}

function downloadOutputPacket(event) {
  event.stopPropagation();
  const article = event.currentTarget.closest("[data-output-packet-index]");
  const index = Number.parseInt(article?.dataset.outputPacketIndex, 10);
  const item = packetPayloadEntries(state.lastResult || {})[index];
  if (!item) {
    setStatus("Packet download unavailable", "error");
    return;
  }
  downloadBlob(new Blob([payloadBytes(item)], { type: outputPacketMimeType(state.lastResult, item) }), outputPacketDownloadName(state.lastResult, item, index));
  setStatus(`Packet #${index + 1} downloaded`);
}

function setAllOutputCollapsed(collapsed) {
  const result = state.lastResult;
  if (!result) {
    return;
  }
  const entries = shouldRenderParsedOutputEntries(result) ? parsedEntries(result) : [];
  const items = state.outputFormat === "packet" ? [...entries, ...packetPayloadEntries(result)] : [];
  state.collapsedOutputEntries = collapsed ? new Set(items.map((item, index) => item.key || String(item.index || index + 1))) : new Set();
  const articles = [...els.output.querySelectorAll("[data-output-entry]")];
  if (state.outputFormat === "packet" && articles.length) {
    for (const article of articles) {
      applyOutputRecordCollapsed(article, collapsed);
    }
    return;
  }
  renderOutput();
}

function applyOutputRecordCollapsed(article, collapsed) {
  article.classList.toggle("output-record--collapsed", collapsed);
  const header = article.querySelector(":scope > header");
  header?.setAttribute("aria-expanded", collapsed ? "false" : "true");
  const button = article.querySelector(".record-collapse-button");
  if (button) {
    const noun = article.classList.contains("proto-record") ? "packet output" : "output record";
    button.setAttribute("aria-label", `${collapsed ? "Expand" : "Collapse"} ${noun}`);
    button.innerHTML = collapseChevron(collapsed);
  }
  const body = article.querySelector(":scope > table, :scope > .proto-record-body");
  if (!body) {
    return;
  }
  if (!collapsed && article.classList.contains("proto-record")) {
    hydrateProtoOutputBody(article, body);
  }
  body.hidden = collapsed;
}

function hydrateProtoOutputBody(article, body) {
  if (body.dataset.outputBodyRendered === "true" && body.dataset.outputBodyEncoding === state.outputEncoding) {
    return;
  }
  const index = Number.parseInt(article.dataset.outputPacketIndex, 10);
  const item = packetPayloadEntries(state.lastResult || {})[index];
  if (!item) {
    return;
  }
  const label = item.protobuf && state.outputEncoding === "pretty" ? protobufOutputLabel(item) : outputEncodings[state.outputEncoding];
  body.innerHTML = `<label>${escapeHTML(label)}</label>${renderPacketPayloadBody(item, state.outputEncoding)}`;
  body.dataset.outputBodyRendered = "true";
  body.dataset.outputBodyEncoding = state.outputEncoding;
}

class RunStoppedError extends Error {
  constructor(message = "Run stopped") {
    super(message);
    this.name = "RunStoppedError";
  }
}

function handleRunClick() {
  if (state?.running) {
    stopPipeline();
    return;
  }
  runPipeline();
}

async function runPipeline() {
  if (state?.running) {
    return;
  }
  const runState = state;
  const adapter = activeAdapter;
  const runID = nextRunID++;
  const worker = createRunWorker();
  const run = {
    id: runID,
    state: runState,
    adapterID: adapter.id,
    worker,
    reject: null,
  };
  activeRun = run;
  runState.running = true;
  updateRunAvailability();
  try {
    syncAllEntries();
    setStatus("Running");
    await nextFrame();
    if (activeRun?.id !== runID) {
      throw new RunStoppedError();
    }
    const request = await adapter.buildRunRequest(runState);
    if (activeRun?.id !== runID) {
      throw new RunStoppedError();
    }
    const response = await runPipelineInWorker(run, {
      adapter: {
        id: adapter.id,
        globalName: adapter.globalName,
      },
      runtime: runState.runtime,
      request,
    });
    if (activeRun?.id !== runID || state !== runState) {
      throw new RunStoppedError();
    }
    if (!response?.ok) {
      throw new Error(response?.error || "run failed");
    }
    runState.lastResult = adapter.normalizeRunResult(response.result);
    runState.outputEncoding = outputEncodingOptions(runState.lastResult, runState.outputFormat)[0];
    protoDecodeCache = new Map();
    runState.collapsedOutputEntries = initialCollapsedOutputEntries(runState.lastResult);
    setStatus("Done");
    appendLogEntries([logEntry("stdout", "run", runLogText(runState.lastResult))]);
    renderOutput();
  } catch (error) {
    if (!(error instanceof RunStoppedError)) {
      setStatus(error.message || String(error), "error");
      appendLogEntries([logEntry("stderr", "run", error)]);
    }
  } finally {
    if (activeRun?.id === runID) {
      disposeActiveRun();
    } else {
      worker.terminate();
    }
    runState.running = false;
    if (state === runState) {
      updateRunAvailability();
    }
  }
}

function createRunWorker() {
  return new Worker(publicAssetPath("wasm-runner-worker.js"));
}

function runPipelineInWorker(run, payload) {
  return new Promise((resolve, reject) => {
    run.reject = reject;
    run.worker.addEventListener("message", (event) => {
      const message = event.data || {};
      if (message.id !== run.id) {
        return;
      }
      if (message.type === "result") {
        resolve(message.response);
        return;
      }
      reject(workerError(message.error));
    });
    run.worker.addEventListener("error", (event) => {
      reject(new Error(event.message || "run worker failed"));
    });
    run.worker.postMessage({
      type: "run",
      id: run.id,
      ...payload,
    });
  });
}

function workerError(error) {
  const nextError = new Error(error?.message || String(error || "run failed"));
  nextError.name = error?.name || "Error";
  if (error?.stack) {
    nextError.stack = error.stack;
  }
  return nextError;
}

function stopPipeline() {
  const run = activeRun;
  if (!run) {
    return;
  }
  activeRun = null;
  run.worker.terminate();
  run.state.running = false;
  run.reject?.(new RunStoppedError());
  if (state === run.state) {
    setStatus("Stopped", "stale");
    appendLogEntries([logEntry("stdout", "run", "stopped by user")]);
    updateRunAvailability();
  }
}

function disposeActiveRun() {
  if (!activeRun) {
    return;
  }
  activeRun.worker.terminate();
  activeRun.state.running = false;
  activeRun.reject?.(new RunStoppedError());
  activeRun = null;
}

async function buildGoFlow2RunRequest(appState) {
  const adapterState = appState.adapterState;
  return {
    command: adapterState.command.value,
    mappingYaml: adapterState.mapping.value,
    capture: captureFromEntries(),
    options: {
      ...adapterState.commandOptions,
      useMapping: adapterState.commandOptions.produce !== "raw" && adapterState.useMapping,
      protobufFraming: adapterState.commandOptions.format === "bin" && adapterState.protobufFraming ? "delimited" : "",
    },
  };
}

async function buildReFlowRunRequest(appState) {
  const adapterState = appState.adapterState;
  const outputLimit = adapterState.outputLimitEnabled ? Math.max(1, Number(adapterState.outputLimit) || 100) : null;
  const editableYAML = adapterState.config?.value ?? adapterState.configYAML;
  return {
    configYaml: buildReFlowBrowserConfig(editableYAML),
    input: {
      mode: "entries",
      entries: await reflowInputEntries(),
    },
    outputLimit,
  };
}

function buildReFlowBrowserConfig(editableYAML) {
  return [
    generatedReFlowSourcesYAML(),
    stripLockedBrowserSections(editableYAML).trim(),
    generatedReFlowSinkYAML(),
  ]
    .filter(Boolean)
    .join("\n\n")
    .concat("\n");
}

function generatedReFlowSourcesYAML() {
  const types = [];
  for (const item of state.entries.filter(isProcessableInputEntry)) {
    const type = String(item.type || "json").toLowerCase();
    if (!types.includes(type)) {
      types.push(type);
    }
  }
  return [
    "sources:",
    ...(types.length ? types : ["json"]).flatMap((type) => {
      const lines = ["  - network: stream", `    type: ${type}`];
      if (type === "json") {
        lines.push("    json:", "      flavor: reflow");
      }
      return lines;
    }),
  ].join("\n");
}

function generatedReFlowSinkYAML() {
  return "sink:\n  type: stdout";
}

function stripLockedBrowserSections(yaml) {
  const lockedKeys = new Set(["sources", "sink"]);
  const output = [];
  let skipping = false;
  for (const line of String(yaml || "").split("\n")) {
    const topLevelKey = line.match(/^([A-Za-z_][A-Za-z0-9_-]*):(?:\s|$)/)?.[1];
    if (topLevelKey) {
      skipping = lockedKeys.has(topLevelKey);
      if (skipping) {
        continue;
      }
    }
    if (!skipping) {
      output.push(line);
    }
  }
  return output.join("\n");
}

function normalizeGoFlow2Result(result) {
  const stats = result.stats || {};
  const protobufFraming = result.command?.format === "bin" ? result.command.protobufFraming || "" : "";
  return {
    kind: "goflow2",
    protobufFraming,
    entries: result.entries || [],
    stats: {
      ...stats,
      inputs: stats.inputs ?? state.entries.filter((item) => ["bytes", "flow"].includes(item.type) && item.text?.trim()).length,
    },
    logs: result.logs || [],
    warnings: result.warnings || [],
    text: (result.entries || []).map((item) => prettyJSON(item.parsed, item.json)).join("\n"),
  };
}

function normalizeReFlowResult(result) {
  const entries = result.kind === "json" ? parseJSONPackets(result.text || "") : [];
  return {
    kind: result.kind,
    encoderType: result.encoderType,
    protobufFraming: result.encoderType === "protobuf" ? reflowProtobufFraming() : "",
    entries,
    payloads: result.payloads || [],
    wireview: result.wireview || null,
    stats: result.stats || {},
    text: result.text || "",
  };
}

function reflowProtobufFraming() {
  const configYAML = buildReFlowBrowserConfig(state.adapterState.config?.value ?? state.adapterState.configYAML);
  const values = scalarYAMLSectionValues("encoder", configYAML);
  const type = yamlScalarPathValue(values, ["type"]);
  if (unquoteYAMLScalar(type).toLowerCase() !== "protobuf") {
    return "";
  }
  return yamlBooleanScalar(yamlScalarPathValue(values, ["protobuf", "length_prefixed"])) ? "delimited" : "";
}

function yamlScalarPathValue(values, path) {
  const item = values.find((candidate) => candidate.path.length === path.length && candidate.path.every((part, index) => part === path[index]));
  return item?.value || "";
}

function yamlBooleanScalar(value) {
  return ["true", "yes", "on", "1"].includes(unquoteYAMLScalar(value).toLowerCase());
}

function unquoteYAMLScalar(value) {
  return String(value || "")
    .trim()
    .replace(/\s+#.*$/u, "")
    .replace(/^['"]|['"]$/g, "");
}

async function loadWasm() {
  const manifest = await fetchManifest(activeAdapter);
  state.runtimes = normalizeRuntimes(manifest, activeAdapter.fallbackRuntime);
  state.runtime = state.runtimes.find((runtime) => runtime.id === manifest.defaultVersion) || state.runtimes[0] || activeAdapter.fallbackRuntime;
  renderWasmSelector();
  await loadScript(state.runtime.execPath);
  globalThis[activeAdapter.globalName] = null;
  const go = new Go();
  const response = await fetch(state.runtime.wasmPath);
  const result = await WebAssembly.instantiateStreaming(response, go.importObject).catch(async () => {
    const bytes = await response.arrayBuffer();
    return WebAssembly.instantiate(bytes, go.importObject);
  });
  go.run(result.instance);
  const metadata = globalThis[activeAdapter.globalName]?.metadata || {};
  els.wasmVersion.textContent = `${metadata.version || state.runtime.version} · ${metadata.commit || state.runtime.commit}`;
  state.runtimeReady = true;
  renderWasmSelector();
  setStatus("WASM ready");
  if (!state.logs.length) {
    appendLogEntries([logEntry("stdout", "runtime", `wasm loaded: ${els.wasmVersion.textContent}`)]);
  }
  updateRunAvailability();
}

async function switchWasmRuntime(runtimeID) {
  const next = state.runtimes.find((runtime) => runtime.id === runtimeID);
  if (!next || next.id === state.runtime.id) {
    renderWasmSelector();
    return;
  }
  state.runtime = next;
  state.runtimeReady = false;
  setStatus("Switching WASM");
  await loadWasm();
}

async function fetchManifest(adapter) {
  try {
    const response = await fetch(adapter.manifestPath, { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json();
  } catch (error) {
    appendLogEntries([logEntry("stderr", "runtime", `could not load ${adapter.manifestPath}: ${error.message || error}`)]);
    return { defaultVersion: adapter.fallbackRuntime.id, versions: [adapter.fallbackRuntime] };
  }
}

function normalizeRuntimes(manifest, fallback) {
  const runtimes = (manifest.versions || []).map((runtime) => ({
    ...fallback,
    ...runtime,
    id: runtime.id || fallback.id,
    label: runtime.label || runtime.version || fallback.label,
    wasmPath: runtime.wasmPath || fallback.wasmPath,
    execPath: runtime.execPath || fallback.execPath,
  }));
  return runtimes.length ? runtimes : [fallback];
}

function renderWasmSelector() {
  const longestLabelLength = state.runtimes.reduce(
    (length, runtime) => Math.max(length, String(runtime.label || runtime.id || "").length),
    0,
  );
  els.wasmVersionSelect.parentElement?.style.setProperty("--wasm-version-select-width", `${Math.min(Math.max(longestLabelLength + 12, 24), 58)}ch`);
  els.wasmVersionSelect.innerHTML = state.runtimes
    .map((runtime) => `<option value="${escapeHTML(runtime.id)}"${runtime.id === state.runtime.id ? " selected" : ""}>${escapeHTML(runtime.label || runtime.id)}</option>`)
    .join("");
  els.wasmVersionSelect.disabled = state.runtimes.length <= 1 || !state.runtimeReady || state.running;
}

function updateRunAvailability() {
  if (state.running) {
    els.run.textContent = "Stop";
    els.run.classList.remove("primary");
    els.run.classList.add("danger");
    els.run.disabled = false;
    renderWasmSelector();
    return;
  }
  els.run.textContent = "Run";
  els.run.classList.add("primary");
  els.run.classList.remove("danger");
  els.run.disabled =
    !state.runtimeReady ||
    state.entries.some(inputEntryValidationError) ||
    !state.entries.some((item) => isProcessableInputEntry(item) && item.text?.trim());
  renderWasmSelector();
}

function updateInputMeta() {
  const count = state.entries.filter((item) => item.text?.trim()).length;
  els.packetInputMeta.textContent = `${count} ${count === 1 ? "entry" : "entries"}`;
}

function updateInputWireView() {
  if (!hasInputWireView() || !els.wireviewFrame) {
    return;
  }
  try {
    const inputError = firstInputValidationError();
    if (inputError) {
      if (lastInputWireViewKey !== "invalid") {
        sendWireViewMessage({ type: "goflow-wireview-clear" });
      }
      lastInputWireViewKey = "invalid";
      els.wireviewStatus.textContent = inputError;
      return;
    }
    const capture = inputWireViewCapture();
    if (!capture) {
      if (lastInputWireViewKey === "empty") {
        return;
      }
      lastInputWireViewKey = "empty";
      els.wireviewStatus.textContent = "No capture";
      sendWireViewMessage({ type: "goflow-wireview-clear" });
      return;
    }
    if (capture.cacheKey === lastInputWireViewKey) {
      return;
    }
    lastInputWireViewKey = capture.cacheKey;
    els.wireviewStatus.textContent = "Loading";
    sendWireViewMessage({ type: "goflow-wireview-open", capture });
  } catch (error) {
    els.wireviewStatus.textContent = error.message || String(error);
  }
}

function scheduleInputWireViewUpdate() {
  if (!hasInputWireView()) {
    return;
  }
  clearInputWireViewUpdate();
  inputWireViewUpdateTimer = window.setTimeout(() => {
    inputWireViewUpdateTimer = 0;
    updateInputWireView();
  }, 180);
}

function clearInputWireViewUpdate() {
  if (!inputWireViewUpdateTimer) {
    return;
  }
  window.clearTimeout(inputWireViewUpdateTimer);
  inputWireViewUpdateTimer = 0;
}

function inputWireViewCapture() {
  const captureEntries = state.entries.filter((item) => item.text?.trim());
  const cacheKey = inputWireViewCacheKey(captureEntries);
  if (inputWireViewCache?.key === cacheKey) {
    return inputWireViewCache.capture;
  }
  let capture = null;
  if (captureEntries.length === 1 && ["pcap", "pcapng"].includes(captureEntries[0].type)) {
    capture = {
      cacheKey,
      filename: captureEntries[0].fileName || `input.${captureEntries[0].type}`,
      mimeType: "application/octet-stream",
      base64: payloadBase64(captureEntries[0]),
    };
    inputWireViewCache = { key: cacheKey, capture };
    return capture;
  }
  const packets = captureEntries.filter((item) => ["bytes", "flow"].includes(item.type));
  if (!packets.length) {
    inputWireViewCache = { key: cacheKey, capture: null };
    return null;
  }
  capture = {
    cacheKey,
    filename: "input.pcap",
    mimeType: "application/vnd.tcpdump.pcap",
    base64: bytesToBase64(buildPcapBytes(packets.map(packetFromEntry), 1)),
  };
  inputWireViewCache = { key: cacheKey, capture };
  return capture;
}

function inputWireViewCacheKey(entries) {
  if (!entries.length) {
    return "empty";
  }
  return entries
    .map((item) =>
      [
        item.id,
        item.type,
        item.originalType || "",
        item.encoding || "",
        item.receivedAt || "",
        item.fileName || "",
        item.text || "",
      ].join("\u001f"),
    )
    .join("\u001e");
}

function sendWireViewMessage(message) {
  if (!hasInputWireView()) {
    return;
  }
  pendingWireViewMessage = message;
  const frame = els.wireviewFrame?.contentWindow;
  if (!frame) {
    return;
  }
  if (wireViewReady || message.type === "goflow-wireview-ping") {
    frame.postMessage(message, window.location.origin);
  } else {
    frame.postMessage({ type: "goflow-wireview-ping" }, window.location.origin);
  }
}

function handleWireViewMessage({ data, source }) {
  if (source === els.outputWireViewFrame?.contentWindow) {
    handleOutputWireViewMessage(data);
    return;
  }
  if (!hasInputWireView()) {
    return;
  }
  if (source !== els.wireviewFrame?.contentWindow) {
    return;
  }
  if (data?.type === "goflow-wireview-ready") {
    wireViewReady = true;
    if (pendingWireViewMessage) {
      els.wireviewFrame?.contentWindow?.postMessage(pendingWireViewMessage, window.location.origin);
    }
    return;
  }
  if (data?.type === "goflow-wireview-opened") {
    const count = data.result?.packetCount ?? data.result?.frameCount ?? 0;
    els.wireviewStatus.textContent = `${count} ${count === 1 ? "packet" : "packets"}`;
  } else if (data?.type === "goflow-wireview-cleared") {
    els.wireviewStatus.textContent = "No capture";
  } else if (data?.type === "goflow-wireview-error") {
    els.wireviewStatus.textContent = data.error || "WireView error";
  }
}

function handleOutputWireViewMessage(data) {
  if (data?.type === "goflow-wireview-ready") {
    if (pendingOutputWireViewCapture) {
      postOutputWireViewCapture(pendingOutputWireViewCapture);
    }
    return;
  }
  if (data?.type === "goflow-wireview-opened") {
    const count = data.result?.packetCount ?? data.result?.frameCount ?? 0;
    els.outputWireViewStatus.textContent = `${count} ${count === 1 ? "packet" : "packets"}`;
  } else if (data?.type === "goflow-wireview-cleared") {
    els.outputWireViewStatus.textContent = "No capture";
  } else if (data?.type === "goflow-wireview-error") {
    els.outputWireViewStatus.textContent = data.error || "WireView error";
  }
}

function startPaneResize(event, splitterName) {
  if (window.matchMedia("(max-width: 980px)").matches) {
    return;
  }
  event.preventDefault();
  const panes = [els.inputPane, els.configPane, els.outputPane];
  const resizeIndex = splitterName === "input-config" ? 0 : 1;
  const startX = event.clientX;
  const startWidths = panes.map((pane) => pane.getBoundingClientRect().width);
  const combined = startWidths[resizeIndex] + startWidths[resizeIndex + 1];
  const minWidths = [260, 280, 300];

  document.body.classList.add("is-col-resizing");
  event.currentTarget.setPointerCapture?.(event.pointerId);

  const move = (moveEvent) => {
    const delta = moveEvent.clientX - startX;
    const minLeft = Math.min(minWidths[resizeIndex], Math.max(0, combined - minWidths[resizeIndex + 1]));
    const maxLeft = Math.max(minLeft, combined - minWidths[resizeIndex + 1]);
    const left = clamp(startWidths[resizeIndex] + delta, minLeft, maxLeft);
    const nextWidths = [...startWidths];
    nextWidths[resizeIndex] = left;
    nextWidths[resizeIndex + 1] = combined - left;
    const total = nextWidths.reduce((sum, width) => sum + width, 0);
    state.paneWeights = nextWidths.map((width) => width / total);
    applyPaneWeights();
  };

  const done = () => {
    document.body.classList.remove("is-col-resizing");
    window.removeEventListener("pointermove", move);
    window.removeEventListener("pointerup", done);
  };

  window.addEventListener("pointermove", move);
  window.addEventListener("pointerup", done, { once: true });
}

function applyPaneWeights() {
  const [inputWeight, configWeight, outputWeight] = state.paneWeights || [0.34, 0.32, 0.38];
  els.shell.style.setProperty("--input-pane", `${Math.max(0.12, inputWeight)}fr`);
  els.shell.style.setProperty("--config-pane", `${Math.max(0.12, configWeight)}fr`);
  els.shell.style.setProperty("--output-pane", `${Math.max(0.12, outputWeight)}fr`);
}

function startInputWireViewResize(event) {
  const container = event.currentTarget.closest(".input-split");
  const top = container.querySelector(".packet-input-panel");
  const bottom = container.querySelector(".wireview-panel");
  startVerticalStackResize(event, {
    container,
    top,
    bottom,
    topVar: "--packet-input-pane",
    bottomVar: "--wireview-pane",
    stateKey: "inputWireView",
    minTop: 160,
    minBottom: 180,
  });
}

function startOutputWireViewResize(event) {
  const container = event.currentTarget.closest(".output-split");
  const top = container.querySelector(".output-body");
  const bottom = container.querySelector(".output-wireview-panel");
  startVerticalStackResize(event, {
    container,
    top,
    bottom,
    topVar: "--output-results-pane",
    bottomVar: "--output-wireview-pane",
    stateKey: "outputWireView",
    minTop: 160,
    minBottom: 220,
  });
}

function startRuntimeLogResize(event) {
  const container = event.currentTarget.closest(".config-split");
  const top = container.querySelector("#config-root");
  const bottom = container.querySelector(".log-section");
  startVerticalStackResize(event, {
    container,
    top,
    bottom,
    topVar: "--config-editor-pane",
    bottomVar: "--runtime-log-pane",
    stateKey: "runtimeLog",
    minTop: 220,
    minBottom: 150,
  });
}

function startVerticalStackResize(event, options) {
  const { container, top, bottom, topVar, bottomVar, stateKey, minTop, minBottom } = options;
  if (!container || !top || !bottom || bottom.classList.contains("hidden")) {
    return;
  }
  event.preventDefault();
  const startY = event.clientY;
  const startTop = top.getBoundingClientRect().height;
  const startBottom = bottom.getBoundingClientRect().height;
  const total = startTop + startBottom;
  if (total <= 0) {
    return;
  }
  document.body.classList.add("is-resizing");
  event.currentTarget.setPointerCapture?.(event.pointerId);
  const move = (moveEvent) => {
    const hasRoomForMinimums = total >= minTop + minBottom;
    const compressedMin = Math.max(72, total * 0.25);
    const effectiveMinTop = hasRoomForMinimums ? minTop : Math.min(minTop, compressedMin);
    const effectiveMinBottom = hasRoomForMinimums ? minBottom : Math.min(minBottom, compressedMin);
    const maxTop = Math.max(effectiveMinTop, total - effectiveMinBottom);
    const nextTop = clamp(startTop + moveEvent.clientY - startY, effectiveMinTop, maxTop);
    const topRatio = nextTop / total;
    state.stackSplits[stateKey] = [topRatio, 1 - topRatio];
    applyStackSplit(container, stateKey, topVar, bottomVar);
  };
  const done = () => {
    document.body.classList.remove("is-resizing");
    window.removeEventListener("pointermove", move);
    window.removeEventListener("pointerup", done);
  };
  window.addEventListener("pointermove", move);
  window.addEventListener("pointerup", done, { once: true });
}

function applyStackSplit(container, stateKey, topVar, bottomVar) {
  if (!container || !state.stackSplits?.[stateKey]) {
    return;
  }
  const [topRatio, bottomRatio] = state.stackSplits[stateKey];
  container.style.setProperty(topVar, `${(topRatio * 100).toFixed(2)}%`);
  container.style.setProperty(bottomVar, `${(bottomRatio * 100).toFixed(2)}%`);
}

function captureFromEntries() {
  const packets = state.entries.filter((item) => ["bytes", "flow"].includes(item.type) && item.text?.trim()).map(packetFromEntry);
  return {
    name: "browser-input.pcap",
    data: bytesToBase64(buildPcapBytes(packets, 1)),
    mimeType: "application/vnd.tcpdump.pcap",
    packets,
  };
}

function packetFromEntry(item, index = 0) {
  const hex = payloadHex(item);
  const size = hex.length / 2;
  return {
    frame: item.frame || index + 1,
    type: item.type,
    hex,
    linkType: item.linkType || 1,
    receivedAt: item.receivedAt || "",
    capturedLen: item.capturedLen || size,
    originalLen: item.originalLen || size,
    src: item.src || "",
    dst: item.dst || "",
  };
}

async function reflowInputTuples() {
  return reflowInputTuplesFromEntries(state.entries.filter(isProcessableInputEntry));
}

async function reflowInputEntries() {
  return state.entries
    .filter((item) => isProcessableInputEntry(item) && item.text?.trim())
    .map((item, index) => {
      const input = {
        type: exportedInputType(item),
        label: item.fileName || `entry ${index + 1}`,
      };
      if (item.receivedAt) {
        input.receivedAt = item.receivedAt;
      }
      if (item.type === "json") {
        input.json = item.text || "{}";
      } else {
        input.bytes = entryBytes(item);
      }
      return input;
    });
}

async function reflowInputTuplesFromEntries(entries) {
  const tuples = await Promise.all(
    entries
      .filter((item) => item.text?.trim())
      .map(async (item, index) => {
        const tuple =
          item.type === "json"
            ? ["json", JSON.parse(item.text || "{}")]
            : [exportedInputType(item), exportedInputPayload(item)];
        if (item.receivedAt) {
          tuple.push(item.receivedAt);
        }
        if (item.type !== "unknown" && tuple[0] !== "json" && typeof tuple[1] !== "string") {
          throw new Error(`entry ${index + 1} payload must be base64`);
        }
        return tuple;
      }),
  );
  return tuples;
}

async function exportedInputText() {
  syncAllEntries();
  if (activeAdapter.id === "reflow") {
    return JSON.stringify(await reflowInputTuplesFromEntries(state.entries), null, 2);
  }
  return JSON.stringify(
    state.entries
      .filter((item) => item.text?.trim())
      .map((item) => {
        const input = {
          type: exportedInputType(item),
          payload: exportedInputPayload(item),
        };
        if (item.receivedAt) {
          input.receivedAt = item.receivedAt;
        }
        for (const [key, value] of Object.entries(inputEntryMetadata(item))) {
          input[key] = value;
        }
        return input;
      }),
    null,
    2,
  );
}

function buildPcapBytes(packets, linkType = 1) {
  const packetBytes = packets.map(pcapFrameBytes);
  const totalPacketBytes = packetBytes.reduce((sum, item) => sum + item.length, 0);
  const bytes = new Uint8Array(24 + packets.length * 16 + totalPacketBytes);
  const view = new DataView(bytes.buffer);
  let offset = 0;
  const writeU16 = (value) => {
    view.setUint16(offset, value, true);
    offset += 2;
  };
  const writeU32 = (value) => {
    view.setUint32(offset, value, true);
    offset += 4;
  };
  const writeI32 = (value) => {
    view.setInt32(offset, value, true);
    offset += 4;
  };
  writeU32(0xa1b2c3d4);
  writeU16(2);
  writeU16(4);
  writeI32(0);
  writeU32(0);
  writeU32(Math.max(65535, ...packetBytes.map((item) => item.length)));
  writeU32(linkType);
  for (const [index, packet] of packets.entries()) {
    const payload = packetBytes[index];
    const ts = packetTimestamp(packet.receivedAt);
    writeU32(ts.seconds);
    writeU32(ts.microseconds);
    writeU32(payload.length);
    writeU32(packet.type === "flow" ? payload.length : packet.originalLen || payload.length);
    bytes.set(payload, offset);
    offset += payload.length;
  }
  return bytes;
}

function pcapFrameBytes(packet, index) {
  const payload = hexToBytes(packet.hex);
  if (packet.type !== "flow") {
    return payload;
  }
  return udpFlowFrameBytes(payload, index);
}

function udpFlowFrameBytes(payload, index = 0) {
  const ethernetLength = 14;
  const ipLength = 20;
  const udpLength = 8;
  const frame = new Uint8Array(ethernetLength + ipLength + udpLength + payload.length);
  const view = new DataView(frame.buffer);
  frame.set([0x02, 0x00, 0x00, 0x00, 0x00, 0x02], 0);
  frame.set([0x02, 0x00, 0x00, 0x00, 0x00, 0x01], 6);
  view.setUint16(12, 0x0800, false);

  const ipOffset = ethernetLength;
  const udpOffset = ipOffset + ipLength;
  view.setUint8(ipOffset, 0x45);
  view.setUint8(ipOffset + 1, 0);
  view.setUint16(ipOffset + 2, ipLength + udpLength + payload.length, false);
  view.setUint16(ipOffset + 4, index + 1, false);
  view.setUint16(ipOffset + 6, 0, false);
  view.setUint8(ipOffset + 8, 64);
  view.setUint8(ipOffset + 9, 17);
  frame.set([192, 0, 2, 1], ipOffset + 12);
  frame.set([192, 0, 2, 2], ipOffset + 16);
  view.setUint16(ipOffset + 10, internetChecksum(frame.subarray(ipOffset, ipOffset + ipLength)), false);

  view.setUint16(udpOffset, syntheticFlowSourcePort, false);
  view.setUint16(udpOffset + 2, flowCollectorPort(payload), false);
  view.setUint16(udpOffset + 4, udpLength + payload.length, false);
  view.setUint16(udpOffset + 6, 0, false);
  frame.set(payload, udpOffset + udpLength);
  return frame;
}

function flowCollectorPort(payload) {
  if (payload.length >= 4 && readU32BE(payload, 0) === 5) {
    return 6343;
  }
  if (payload.length >= 2 && readU16BE(payload, 0) === 10) {
    return 4739;
  }
  return 2055;
}

function readU16BE(bytes, offset) {
  return (bytes[offset] << 8) | bytes[offset + 1];
}

function readU32BE(bytes, offset) {
  return bytes[offset] * 0x1000000 + ((bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]);
}

function internetChecksum(bytes) {
  let sum = 0;
  for (let offset = 0; offset < bytes.length; offset += 2) {
    sum += (bytes[offset] << 8) + (bytes[offset + 1] || 0);
    sum = (sum & 0xffff) + (sum >>> 16);
  }
  return (~((sum & 0xffff) + (sum >>> 16))) & 0xffff;
}

function syncAllEntries(options = {}) {
  for (const card of els.packetList.querySelectorAll(".packet-card")) {
    const item = entryByID(card.dataset.entryId);
    if (item) {
      syncEntryFromCard(card, item, options);
    }
  }
  sortInputEntries();
}

function sortInputEntries() {
  state.entries = sortedInputEntries(state.entries);
}

function sortedInputEntries(entries) {
  return [...entries].sort((left, right) => {
    const leftTime = inputEntryTimestamp(left);
    const rightTime = inputEntryTimestamp(right);
    if (leftTime === rightTime) {
      return left.id - right.id;
    }
    if (leftTime === Number.POSITIVE_INFINITY) {
      return 1;
    }
    if (rightTime === Number.POSITIVE_INFINITY) {
      return -1;
    }
    return leftTime - rightTime;
  });
}

function inputEntryTimestamp(item) {
  const parsed = item?.receivedAt ? new Date(item.receivedAt) : null;
  const timestamp = parsed?.getTime();
  return Number.isFinite(timestamp) ? timestamp : Number.POSITIVE_INFINITY;
}

function displayInputType(item) {
  return activeAdapter.enabledInputTypes.includes(item?.type) ? item.type : "unknown";
}

function exportedInputType(item) {
  return item?.type === "unknown" ? item.originalType || "unknown" : item?.type || "bytes";
}

function exportedInputPayload(item) {
  return item?.type === "unknown" ? item.rawPayload ?? item.text ?? "" : payloadBase64(item);
}

function isProcessableInputEntry(item) {
  return activeAdapter.enabledInputTypes.includes(item?.type) && processableInputTypes.has(item.type);
}

function defaultGoFlow2Entries() {
  return [...goflow2InputPresets.ipfix.entries(), ...goflow2InputPresets.sflow.entries()];
}

function flowPresetEntries(keys) {
  return keys.map((key, index) =>
    entry({
      type: "flow",
      text: flowPresetPackets[key],
      receivedAt: presetReceivedAt(index),
    }),
  );
}

function jsonPresetEntries(records) {
  return records.map((record, index) =>
    entry({
      type: "json",
      text: JSON.stringify(record, null, 2),
      receivedAt: presetReceivedAt(index),
    }),
  );
}

function presetReceivedAt(index) {
  return new Date(Date.UTC(2026, 5, 2, 4, 0, 0, index)).toISOString();
}

function entriesFromExportedInputValue(value) {
  const list = Array.isArray(value) ? value : Array.isArray(value?.entries) ? value.entries : Array.isArray(value?.inputs) ? value.inputs : null;
  if (!list) {
    throw new Error("JSON input list must be an array");
  }
  return list.flatMap((item, index) => entriesFromExportedInputItem(item, index));
}

function entriesFromExportedInputItem(item, index) {
  if (Array.isArray(item)) {
    if (item.length < 2 || item.length > 3) {
      throw new Error(`input ${index + 1} tuple must be [type, payload, received_at?]`);
    }
    const importedType = normalizedImportedInputType(item[0], index);
    const { type, originalType } = importedType;
    const receivedAt = normalizeImportedReceivedAt(item[2]);
    if (type === "json") {
      return [entry({ type, text: JSON.stringify(item[1] ?? {}, null, 2), receivedAt })];
    }
    if (type === "unknown") {
      return [unknownEntry({ originalType, rawPayload: item[1], receivedAt })];
    }
    if (typeof item[1] !== "string") {
      throw new Error(`input ${index + 1} ${type} payload must be base64`);
    }
    return [entry({ type, originalType, encoding: "base64", text: item[1], receivedAt })];
  }
  if (!item || typeof item !== "object") {
    throw new Error(`input ${index + 1} must be an object or tuple`);
  }
  const importedType = normalizedImportedInputType(item.type || "bytes", index);
  const { type, originalType } = importedType;
  const receivedAt = normalizeImportedReceivedAt(item.receivedAt ?? item.received_at);
  if (type === "json") {
    const value = item.payload ?? item.value ?? item.text ?? {};
    const text = typeof value === "string" ? prettyJSONText(value) : JSON.stringify(value, null, 2);
    return [entry({ type, text, receivedAt, ...inputEntryMetadata(item) })];
  }
  if (type === "unknown") {
    const rawPayload = importedPayloadValue(item);
    return [unknownEntry({ originalType, rawPayload, receivedAt, ...inputEntryMetadata(item) })];
  }
  const encoding = item.encoding === "hex" || item.hex != null ? "hex" : "base64";
  const text = item.hex ?? item.payload ?? item.text ?? "";
  if (typeof text !== "string") {
    throw new Error(`input ${index + 1} ${type} payload must be a string`);
  }
  return [entry({ type, originalType, encoding, text: normalizedPayloadText(text, encoding), receivedAt, ...inputEntryMetadata(item) })];
}

function inputEntryMetadata(item) {
  const metadata = {};
  for (const key of ["frame", "linkType", "capturedLen", "originalLen"]) {
    if (Number.isFinite(Number(item?.[key])) && Number(item[key]) > 0) {
      metadata[key] = Number(item[key]);
    }
  }
  for (const key of ["src", "dst", "fileName"]) {
    if (item?.[key]) {
      metadata[key] = String(item[key]);
    }
  }
  return metadata;
}

function normalizedImportedInputType(value, index) {
  const originalType = String(value || "").trim();
  const type = originalType.toLowerCase();
  if (!type) {
    throw new Error(`input ${index + 1} is missing a type`);
  }
  if (!activeAdapter.enabledInputTypes.includes(type)) {
    return { type: "unknown", originalType };
  }
  return { type, originalType: "" };
}

function importedPayloadValue(item) {
  for (const key of ["payload", "value", "text", "hex"]) {
    if (Object.prototype.hasOwnProperty.call(item, key)) {
      return item[key];
    }
  }
  return "";
}

function normalizeImportedReceivedAt(value) {
  if (value == null || value === "") {
    return "";
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return new Date(value).toISOString();
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    const parsed = /^\d+$/.test(trimmed) ? new Date(Number(trimmed)) : new Date(trimmed);
    if (Number.isNaN(parsed.getTime())) {
      throw new Error(`invalid received_at ${JSON.stringify(value)}`);
    }
    return parsed.toISOString();
  }
  if (typeof value === "object") {
    for (const key of ["received_at_unix_ms", "time_unix_ms", "unix_ms"]) {
      if (value[key] != null) {
        return normalizeImportedReceivedAt(Number(value[key]));
      }
    }
    for (const key of ["received_at_unix", "time_unix", "unix"]) {
      if (value[key] != null) {
        return normalizeImportedReceivedAt(Number(value[key]) * 1000);
      }
    }
    for (const key of ["receivedAt", "received_at", "time"]) {
      if (value[key] != null) {
        return normalizeImportedReceivedAt(value[key]);
      }
    }
  }
  throw new Error(`invalid received_at ${JSON.stringify(value)}`);
}

function entry(options = {}) {
  return {
    id: nextEntryID++,
    type: options.type || "bytes",
    originalType: options.originalType || "",
    rawPayload: options.rawPayload,
    rawPayloadText: options.rawPayloadText || "",
    encoding: options.encoding || (options.type === "json" ? "utf8" : "hex"),
    text: options.text || (options.type === "json" ? "{}" : ""),
    jsonMode: options.jsonMode || "format",
    receivedAt: options.receivedAt || "",
    fileName: options.fileName || "",
    frame: options.frame || 0,
    linkType: options.linkType || 0,
    capturedLen: options.capturedLen || 0,
    originalLen: options.originalLen || 0,
    src: options.src || "",
    dst: options.dst || "",
    collapsed: Boolean(options.collapsed),
    inputError: options.inputError || "",
  };
}

function duplicateInputEntry(item) {
  return entry({
    type: item.type,
    originalType: item.originalType,
    rawPayload: cloneInputPayloadValue(item.rawPayload),
    rawPayloadText: item.rawPayloadText,
    encoding: item.encoding,
    text: item.text,
    jsonMode: item.jsonMode,
    receivedAt: item.receivedAt,
    fileName: item.fileName,
    frame: item.frame,
    linkType: item.linkType,
    capturedLen: item.capturedLen,
    originalLen: item.originalLen,
    src: item.src,
    dst: item.dst,
    collapsed: item.collapsed,
    inputError: item.inputError,
  });
}

function cloneInputPayloadValue(value) {
  if (!value || typeof value !== "object") {
    return value;
  }
  if (typeof structuredClone === "function") {
    return structuredClone(value);
  }
  return JSON.parse(JSON.stringify(value));
}

function unknownEntry(options = {}) {
  const text = unknownPayloadText(options.rawPayload);
  return entry({
    type: "unknown",
    originalType: options.originalType,
    encoding: "raw",
    text,
    rawPayload: options.rawPayload,
    rawPayloadText: text,
    receivedAt: options.receivedAt,
    fileName: options.fileName,
    frame: options.frame,
    linkType: options.linkType,
    capturedLen: options.capturedLen,
    originalLen: options.originalLen,
    src: options.src,
    dst: options.dst,
  });
}

function unknownPayloadText(value) {
  if (typeof value === "string") {
    return value;
  }
  if (value === null) {
    return "null";
  }
  if (value === undefined) {
    return "";
  }
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function entryFromPacket(packet, importType) {
  return entry({
    type: importType || packet.type || "bytes",
    encoding: "hex",
    text: packet.hex || "",
    receivedAt: packet.receivedAt || "",
    frame: packet.frame || 0,
    linkType: packet.linkType || 0,
    capturedLen: packet.capturedLen || 0,
    originalLen: packet.originalLen || 0,
    src: packet.src || "",
    dst: packet.dst || "",
  });
}

function inputEntryTitle(item, index) {
  const type = displayInputType(item);
  return `#${index + 1} ${type}`;
}

function inputMetaLabel(item) {
  return entrySummary(item);
}

function entrySummary(item) {
  const inputError = inputEntryValidationError(item);
  if (inputError) {
    return inputError;
  }
  if (item?.src || item?.dst) {
    return sourceSummary(item);
  }
  if (item?.type === "json") {
    return jsonValueSummary(item.text || "{}");
  }
  if (item?.type === "unknown") {
    return unknownPayloadMeta(item);
  }
  const size = payloadHex(item).length / 2;
  return `${formatBytes(size)}${item.fileName ? ` · ${item.fileName}` : ""}`;
}

function firstInputValidationError() {
  for (const item of state.entries) {
    const error = inputEntryValidationError(item);
    if (error) {
      return error;
    }
  }
  return "";
}

function inputEntryValidationError(item) {
  if (!item || item.type === "unknown") {
    return "";
  }
  if (item.inputError) {
    return item.inputError;
  }
  if (!isProcessableInputEntry(item) || !item.text?.trim()) {
    return "";
  }
  if (item.type === "json") {
    try {
      JSON.parse(emptyJSONText(item.text));
      return "";
    } catch {
      return "invalid JSON";
    }
  }
  if ((item.encoding || "hex") === "base64") {
    return "";
  }
  return hexInputValidationError(item.text);
}

function sourceSummary(item) {
  return [item.src, item.dst].filter(Boolean).join(" -> ");
}

function jsonValueSummary(text) {
  try {
    const value = JSON.parse(emptyJSONText(text));
    if (Array.isArray(value)) {
      return `${value.length} ${value.length === 1 ? "item" : "items"}`;
    }
    if (!value || typeof value !== "object") {
      return typeof value;
    }
    const count = Object.keys(value).length;
    return `${count} ${count === 1 ? "field" : "fields"}`;
  } catch {
    return "invalid JSON";
  }
}

function unknownPayloadMeta(item) {
  const value = item.rawPayload;
  if (Array.isArray(value)) {
    return `${value.length} ${value.length === 1 ? "item" : "items"}`;
  }
  if (value && typeof value === "object") {
    const count = Object.keys(value).length;
    return `${count} ${count === 1 ? "field" : "fields"}`;
  }
  const size = String(item.text || "").length;
  return `${size} ${size === 1 ? "char" : "chars"}`;
}

function jsonEditorStatus(text) {
  try {
    const value = JSON.parse(emptyJSONText(text));
    if (Array.isArray(value)) {
      return `${value.length} ${value.length === 1 ? "item" : "items"}`;
    }
    if (value && typeof value === "object") {
      const count = Object.keys(value).length;
      return `${count} ${count === 1 ? "field" : "fields"}`;
    }
    return typeof value;
  } catch {
    return "invalid JSON";
  }
}

function parseJSONEditorValue(text) {
  try {
    const value = JSON.parse(emptyJSONText(text));
    return {
      ok: true,
      table: value && typeof value === "object" && !Array.isArray(value),
      value,
    };
  } catch {
    return { ok: false, table: false, value: null };
  }
}

function jsonValueType(value) {
  if (value === null) {
    return "null";
  }
  if (Array.isArray(value)) {
    return "array";
  }
  if (typeof value === "object") {
    return "object";
  }
  if (typeof value === "number") {
    return "number";
  }
  if (typeof value === "boolean") {
    return "boolean";
  }
  return "string";
}

function jsonEditorMode(item) {
  return item?.jsonMode === "raw" ? "raw" : "format";
}

function jsonValueInputText(value) {
  if (value === null) {
    return "null";
  }
  if (typeof value === "string") {
    return value;
  }
  return String(value);
}

function prettyJSONText(text) {
  try {
    return JSON.stringify(JSON.parse(emptyJSONText(text)), null, 2);
  } catch {
    return String(text || "{}");
  }
}

function jsonTextFromEditor(card, options = {}) {
  const raw = card.querySelector("[data-json-raw]");
  if (raw) {
    return options.lenient ? raw.value || "{}" : emptyJSONText(raw.value);
  }
  const out = {};
  for (const row of card.querySelectorAll("[data-json-row]")) {
    const key = row.querySelector('[data-json-field="key"]')?.value ?? "";
    out[key] = jsonValueFromRow(row, options);
  }
  return JSON.stringify(out, null, 2);
}

function jsonValueFromRow(row, options = {}) {
  const control = row.querySelector("[data-json-value]");
  const text = control?.value ?? "";
  return inferredJSONValue(text, options);
}

function inferredJSONValue(text, options = {}) {
  const raw = String(text ?? "");
  const trimmed = raw.trim();
  if (trimmed === "") {
    return "";
  }
  if (trimmed === "true") {
    return true;
  }
  if (trimmed === "false") {
    return false;
  }
  if (trimmed === "null") {
    return null;
  }
  if (/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:e[+-]?\d+)?$/i.test(trimmed)) {
    const value = Number(trimmed);
    if (Number.isFinite(value)) {
      return value;
    }
  }
  if (/^[\[{"]/.test(trimmed)) {
    try {
      return JSON.parse(trimmed);
    } catch (error) {
      if (!options.lenient && /^[\[{]/.test(trimmed)) {
        throw error;
      }
    }
  }
  return raw;
}

function jsonObjectValue(text) {
  const parsed = parseJSONEditorValue(text);
  return parsed.table ? { ...parsed.value } : {};
}

function nextJSONFieldName(value) {
  let index = 1;
  while (Object.prototype.hasOwnProperty.call(value, `field_${index}`)) {
    index += 1;
  }
  return `field_${index}`;
}

function payloadText(text, encoding) {
  if (encoding === "base64") {
    return wrapText(text.replace(/\s+/g, ""), base64WrapColumns);
  }
  if (hexInputValidationError(text)) {
    return String(text || "");
  }
  return formatHexBlock(text);
}

function defaultInputEncoding(type, source = {}) {
  if (type === "json") {
    return "utf8";
  }
  if (binaryInputTypes.has(type) && source.encoding === "base64") {
    return "base64";
  }
  return "hex";
}

function convertEntryText(source, nextType, nextEncoding, options = {}) {
  if (nextType === source.type) {
    return source.text || (nextType === "json" ? "{}" : "");
  }
  if (nextType === "json") {
    return jsonTextFromEntryBytes(entryBytes(source, options));
  }
  if (binaryInputTypes.has(nextType)) {
    const bytes = entryBytes(source, options);
    return nextEncoding === "base64" ? bytesToBase64(bytes) : bytesToHex(bytes);
  }
  return source.text || "";
}

function entryBytes(source, options = {}) {
  if (source.type === "json") {
    const text = options.lenient ? source.text || "{}" : emptyJSONText(source.text);
    if (!options.lenient) {
      JSON.parse(text);
    }
    return new TextEncoder().encode(text);
  }
  if ((source.encoding || "hex") === "base64") {
    return base64ToBytes(source.text || "");
  }
  return hexToBytes(normalizedPayloadText(source.text || "", "hex", options));
}

function jsonTextFromEntryBytes(bytes) {
  const text = new TextDecoder().decode(bytes);
  if (!text.trim()) {
    return "{}";
  }
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return JSON.stringify(text);
  }
}

function formatJSONText(text, spaces) {
  const value = JSON.parse(emptyJSONText(text));
  return JSON.stringify(value, null, spaces);
}

function emptyJSONText(text) {
  return String(text || "").trim() ? String(text) : "{}";
}

function payloadHex(item) {
  if (item.type === "json") {
    return bytesToHex(new TextEncoder().encode(item.text || "{}"));
  }
  if ((item.encoding || "hex") === "base64") {
    return bytesToHex(base64ToBytes(item.text || ""));
  }
  return normalizedPayloadText(item.text || "", "hex");
}

function payloadBase64(item) {
  if ((item.encoding || "hex") === "base64") {
    return String(item.text || "").replace(/\s+/g, "");
  }
  return bytesToBase64(hexToBytes(normalizedPayloadText(item.text || "", "hex")));
}

function normalizedPayloadText(text, encoding, options = {}) {
  if (encoding === "base64") {
    const base64 = String(text || "").replace(/\s+/g, "");
    if (!base64) {
      return "";
    }
    if (!options.lenient) {
      base64ToBytes(base64);
    }
    return base64;
  }
  const error = hexInputValidationError(text);
  if (error && !options.lenient) {
    throw new Error(error);
  }
  return cleanHexText(text);
}

function payloadEditorValue(text, encoding, options = {}) {
  if (encoding === "base64") {
    try {
      return { text: normalizedPayloadText(text, encoding, options), error: "" };
    } catch (error) {
      if (!options.allowInvalid && !options.lenient) {
        throw error;
      }
      return { text: String(text || ""), error: error.message || String(error) };
    }
  }
  const error = hexInputValidationError(text);
  if (error) {
    if (!options.allowInvalid && !options.lenient) {
      throw new Error(error);
    }
    return { text: String(text || ""), error };
  }
  return { text: cleanHexText(text), error: "" };
}

function formatHexEditorInput(textarea) {
  if (!textarea?.closest?.(".packet-byte-editor--hex")) {
    return;
  }
  const clean = cleanHexText(textarea.value);
  const formatted = formatHexBlock(clean);
  if (textarea.value === formatted) {
    return;
  }
  const selectionStartHex = cleanHexText(textarea.value.slice(0, textarea.selectionStart ?? 0)).length;
  const selectionEndHex = cleanHexText(textarea.value.slice(0, textarea.selectionEnd ?? textarea.selectionStart ?? 0)).length;
  textarea.value = formatted;
  textarea.setSelectionRange(hexFormattedOffset(formatted, selectionStartHex), hexFormattedOffset(formatted, selectionEndHex));
}

function hexFormattedOffset(formatted, hexCount) {
  if (hexCount <= 0) {
    return 0;
  }
  let seen = 0;
  for (let index = 0; index < formatted.length; index += 1) {
    if (/[0-9a-f]/i.test(formatted[index])) {
      seen += 1;
      if (seen >= hexCount) {
        return index + 1;
      }
    }
  }
  return formatted.length;
}

function convertPayloadText(text, fromEncoding, toEncoding) {
  if (fromEncoding === toEncoding) {
    return text;
  }
  if (fromEncoding === "base64") {
    const bytes = base64ToBytes(text);
    return toEncoding === "hex" ? bytesToHex(bytes) : text;
  }
  const bytes = hexToBytes(cleanHexText(text));
  return toEncoding === "base64" ? bytesToBase64(bytes) : bytesToHex(bytes);
}

function updateByteEditor(textarea) {
  if (!textarea || !textarea.closest(".packet-byte-editor")) {
    return;
  }
  const editor = textarea.closest(".packet-byte-editor");
  const card = textarea.closest(".packet-card");
  const item = entryByID(card?.dataset.entryId);
  const inputError = inputEntryValidationError(item);
  editor.classList.toggle("packet-byte-editor--invalid", Boolean(inputError));
  textarea.setAttribute("aria-invalid", inputError ? "true" : "false");
  const addresses = editor.querySelector(".packet-byte-addresses");
  if (!addresses) {
    return;
  }
  if (editor.classList.contains("packet-byte-editor--raw")) {
    addresses.textContent = "";
    return;
  }
  const encoding = editor.classList.contains("packet-byte-editor--base64") ? "base64" : "hex";
  if (encoding === "base64") {
    addresses.textContent = "";
    return;
  }
  const clean = cleanHexText(textarea.value);
  const lines = Math.max(1, Math.ceil(clean.length / 32));
  addresses.textContent = Array.from({ length: lines }, (_, index) => hexAddress(index * 16)).join("\n");
}

function updateInputEntryMeta(card, item) {
  const meta = card.querySelector("[data-packet-meta]");
  if (meta) {
    meta.textContent = inputMetaLabel(item);
  }
  const jsonStatus = card.querySelector("[data-json-status]");
  if (jsonStatus) {
    jsonStatus.textContent = jsonEditorStatus(item.text || "{}");
  }
}

function parsedEntries(result) {
  if (activeAdapter.id === "goflow2") {
    return (result.entries || []).map((item) => ({
      key: String(item.index),
      index: item.index,
      title: `#${item.index} ${outputTitleLabel(item.protocol, "record")}`,
      summary: jsonValueSummary(JSON.stringify(outputEntryFields(item))),
      parsed: item.parsed,
    }));
  }
  return (result.entries || []).map((packet, index) => ({
    key: String(index),
    index: index + 1,
    title: `#${index + 1} ${outputTitleLabel(jsonPacketType(packet.value), "json")}`,
    summary: packetSummary(packet.value),
    parsed: packet.value ?? { raw: packet.raw },
  }));
}

function shouldRenderParsedOutputEntries(result) {
  return !(activeAdapter.id === "goflow2" && protoEntries(result).length > 0);
}

function outputEntryFields(item) {
  if (item?.parsed && typeof item.parsed === "object") {
    return item.parsed;
  }
  if (item?.json) {
    try {
      return JSON.parse(item.json);
    } catch {
      return {};
    }
  }
  return {};
}

function binaryEntries(result) {
  return (result.payloads || []).map((payload, index) => ({
    key: `payload-${index + 1}`,
    base64: payload.base64,
    hex: payload.hex,
    bytes: payload.bytes,
    length: payload.length,
    label: packetPayloadLabel(result),
    protobuf: result.encoderType === "protobuf",
    protobufFraming: result.encoderType === "protobuf" ? result.protobufFraming || "" : "",
  }));
}

function payloadBytes(item) {
  if (item?.bytes instanceof Uint8Array) {
    return item.bytes;
  }
  if (item?.bytes instanceof ArrayBuffer) {
    return new Uint8Array(item.bytes);
  }
  if (ArrayBuffer.isView(item?.bytes)) {
    return new Uint8Array(item.bytes.buffer, item.bytes.byteOffset, item.bytes.byteLength);
  }
  if (item?.base64) {
    return base64ToBytes(item.base64);
  }
  if (item?.hex) {
    return hexToBytes(item.hex);
  }
  return new Uint8Array();
}

function payloadLength(item) {
  if (Number.isFinite(item?.length) && item.length >= 0) {
    return item.length;
  }
  if (item?.bytes instanceof Uint8Array || item?.bytes instanceof ArrayBuffer || ArrayBuffer.isView(item?.bytes)) {
    return payloadBytes(item).byteLength;
  }
  if (item?.base64) {
    const padding = item.base64.endsWith("==") ? 2 : item.base64.endsWith("=") ? 1 : 0;
    return Math.max(0, Math.floor((item.base64.length * 3) / 4) - padding);
  }
  if (item?.hex) {
    return Math.floor(cleanHexText(item.hex).length / 2);
  }
  return 0;
}

function outputPayloadBase64(item) {
  return item?.base64 || bytesToBase64(payloadBytes(item));
}

function outputPayloadHex(item) {
  return item?.hex || bytesToHex(payloadBytes(item));
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
  if (capture?.base64) {
    return base64ToBytes(capture.base64);
  }
  return new Uint8Array();
}

function protoEntries(result) {
  if (activeAdapter.id === "goflow2") {
    return (result.entries || [])
      .filter((entry) => entry.protoBase64)
      .map((entry) => ({
        key: `proto-${entry.index}`,
        base64: entry.protoBase64,
        hex: entry.protoHex,
        length: entry.protoSize,
        label: "Protobuf",
        protobuf: true,
        protobufFraming: result.protobufFraming || "",
      }));
  }
  if (result.encoderType === "protobuf") {
    return binaryEntries(result);
  }
  return [];
}

function packetPayloadEntries(result) {
  if (activeAdapter.id === "goflow2") {
    return protoEntries(result);
  }
  return binaryEntries(result);
}

function packetPayloadLabel(result) {
  if (result.encoderType === "protobuf") {
    return "Protobuf";
  }
  if (result.encoderType) {
    return outputTitleLabel(result.encoderType, "packet");
  }
  return "Packet";
}

function outputPacketDownloadName(result, item, index) {
  return `${activeAdapter.id}-output-packet-${index + 1}.${outputPacketFileExtension(result, item)}`;
}

function outputPacketFileExtension(result, item) {
  if (item?.protobuf || result?.encoderType === "protobuf") {
    return "pb";
  }
  if (activeAdapter.id === "goflow2") {
    return "bin";
  }
  switch (result?.encoderType) {
    case "pcap":
      return "pcap";
    case "pcapng":
      return "pcapng";
    case "ipfix":
      return "ipfix";
    case "sflow":
      return "sflow";
    case "netflowv5":
      return "nfv5";
    case "netflowv9":
      return "nfv9";
    default:
      return "bin";
  }
}

function outputPacketMimeType(result, item) {
  if (result?.encoderType === "pcap") {
    return "application/vnd.tcpdump.pcap";
  }
  if (result?.encoderType === "pcapng") {
    return "application/x-pcapng";
  }
  if (item?.protobuf || result?.encoderType === "protobuf") {
    return "application/x-protobuf";
  }
  return "application/octet-stream";
}

function nativeOutputFile(result) {
  if (!result) {
    return null;
  }
  if (isNativeCaptureOutput(result)) {
    const bytes = captureBytes(result.wireview);
    if (bytes.byteLength) {
      return {
        blob: new Blob([bytes], { type: result.wireview.mimeType || outputNativeMimeType(result) }),
        name: result.wireview.filename || outputNativeDownloadName(result),
      };
    }
  }
  const packets = packetPayloadEntries(result);
  const parts = packets.map(payloadBytes).filter((bytes) => bytes.byteLength);
  if (!parts.length) {
    return null;
  }
  return {
    blob: new Blob(parts, { type: outputNativeMimeType(result, packets[0]) }),
    name: outputNativeDownloadName(result, packets[0]),
  };
}

function isNativeCaptureOutput(result) {
  return Boolean(result?.wireview && (result.encoderType === "pcap" || result.encoderType === "pcapng"));
}

function outputNativeDownloadName(result, item) {
  return `${activeAdapter.id}-output.${outputPacketFileExtension(result, item)}`;
}

function outputNativeMimeType(result, item) {
  return outputPacketMimeType(result, item) || "application/octet-stream";
}

function hasProtobufOutput(result) {
  return protoEntries(result).length > 0;
}

function hasBinaryOutput(result) {
  return packetPayloadEntries(result).length > 0;
}

function initialCollapsedOutputEntries(result) {
  if (!result || !hasProtobufOutput(result)) {
    return new Set();
  }
  const packets = packetPayloadEntries(result);
  const totalBytes = packets.reduce((sum, item) => sum + payloadLength(item), 0);
  if (packets.length <= 12 && totalBytes <= 64 * 1024) {
    return new Set();
  }
  return new Set(packets.map((item, index) => item.key || String(index + 1)));
}

function rawOutputText(result, encoding = state.outputEncoding) {
  const packets = packetPayloadEntries(result);
  if (packets.length) {
    return packets
      .map((item) => {
        if (encoding === "base64") {
          return outputPayloadBase64(item);
        }
        if (item.protobuf && encoding === "pretty") {
          return decodedProtoPayloadText(item);
        }
        return cleanHexText(outputPayloadHex(item));
      })
      .join("\n");
  }
  return jsonLinesText(result, encoding);
}

function jsonLinesText(result, encoding = "text") {
  if (activeAdapter.id === "goflow2") {
    const lines = (result.entries || []).map((entry) => entry.json || prettyJSON(entry.parsed, entry.json));
    if (encoding === "pretty") {
      return lines.map(prettyJSONLine).join("\n\n");
    }
    return lines.join("\n");
  }
  if (encoding === "pretty") {
    return (result.text || "").split("\n").filter((line) => line.trim()).map(prettyJSONLine).join("\n\n");
  }
  return result.text || "";
}

function prettyJSONLine(line) {
  try {
    return JSON.stringify(JSON.parse(line), null, 2);
  } catch {
    return line;
  }
}

function outputText() {
  const result = state.lastResult;
  if (!result) {
    return "";
  }
  const encoding = effectiveOutputEncoding(result, state.outputFormat);
  if (state.outputFormat === "packet") {
    const sections = [];
    const entries = shouldRenderParsedOutputEntries(result) ? parsedEntries(result) : [];
    if (entries.length) {
      sections.push(encoding === "text" ? jsonLinesText(result, "text") : JSON.stringify(entries.map((item) => item.parsed), null, 2));
    }
    const packets = packetPayloadEntries(result);
    if (packets.length) {
      sections.push(
        packets
          .map((item) => {
            if (item.protobuf && encoding === "pretty") {
              return `# ${item.label}\n${decodedProtoPayloadText(item)}`;
            }
            return encoding === "base64" ? outputPayloadBase64(item) : hexDumpText(outputPayloadHex(item));
          })
          .join("\n\n"),
      );
    }
    if (result.wireview) {
      sections.push(`# WireView\n${result.wireview.filename || "output.pcap"}`);
    }
    return sections.join("\n\n");
  }
  return rawOutputText(result, encoding);
}

async function copyOutput() {
  const native = nativeOutputFile(state.lastResult);
  if (native && (await copyBlob(native.blob))) {
    setStatus("Native output copied");
    return;
  }
  await copyText(outputText());
  setStatus(native ? "Clipboard copied displayed output" : "Output copied", native ? "stale" : "");
}

async function copyInputs() {
  try {
    await copyText(await exportedInputText());
    setStatus("Inputs copied");
  } catch (error) {
    setStatus(error.message || String(error), "error");
    appendLogEntries([logEntry("stderr", "export", error)]);
  }
}

async function downloadInputs() {
  try {
    downloadText(await exportedInputText(), `${activeAdapter.id}-inputs.json`, "application/json");
    setStatus("Inputs downloaded");
  } catch (error) {
    setStatus(error.message || String(error), "error");
    appendLogEntries([logEntry("stderr", "export", error)]);
  }
}

function downloadOutput() {
  const result = state.lastResult;
  const native = nativeOutputFile(result);
  if (native) {
    downloadBlob(native.blob, native.name);
    setStatus("Native output downloaded");
    return;
  }
  downloadText(outputText(), `${activeAdapter.id}-output.txt`, "text/plain");
  setStatus("Output downloaded");
}

function statsText(stats = {}) {
  const inputs = stats.inputs ?? stats.udpDatagrams ?? stats.frames ?? 0;
  const decoded = stats.decoded ?? stats.inputs ?? stats.udpDatagrams ?? 0;
  const parts = [`input ${inputs}`, `decoded ${decoded}`, `output ${stats.outputs || 0}`, `errors ${stats.errors || 0}`];
  if (stats.totalElapsedNs > 0) {
    parts.push(`time ${formatDurationNs(stats.totalElapsedNs)}`);
  }
  if (stats.nsPerPacket > 0) {
    parts.push(`${formatDurationNs(stats.nsPerPacket)}/packet`);
  }
  if (stats.truncated && stats.limit > 0) {
    parts.push(`cap ${stats.limit}`);
  }
  return parts.join(" · ");
}

function runLogText(result) {
  const timing = statsTimingText(result.stats);
  return activeAdapter.id === "goflow2"
    ? `decoded ${result.stats?.decoded || 0}; emitted ${result.stats?.outputs || 0}; ${result.stats?.errors || 0} errors${timing}`
    : `processed ${result.stats?.inputs || 0} inputs; emitted ${result.stats?.outputs || 0} outputs${timing}`;
}

function statsTimingText(stats = {}) {
  const parts = [];
  if (stats.totalElapsedNs > 0) {
    parts.push(`total ${formatDurationNs(stats.totalElapsedNs)}`);
  }
  if (stats.nsPerPacket > 0) {
    parts.push(`${formatDurationNs(stats.nsPerPacket)} per packet`);
  }
  return parts.length ? `; ${parts.join("; ")}` : "";
}

function formatDurationNs(ns) {
  if (!Number.isFinite(ns) || ns <= 0) {
    return "0 ns";
  }
  if (ns >= 1_000_000_000) {
    return `${formatDurationNumber(ns / 1_000_000_000)} s`;
  }
  if (ns >= 1_000_000) {
    return `${formatDurationNumber(ns / 1_000_000)} ms`;
  }
  if (ns >= 1_000) {
    return `${formatDurationNumber(ns / 1_000)} us`;
  }
  return `${Math.round(ns)} ns`;
}

function formatDurationNumber(value) {
  if (value >= 100) {
    return value.toFixed(0);
  }
  if (value >= 10) {
    return value.toFixed(1);
  }
  return value.toFixed(2);
}

function parseJSONPackets(text) {
  return text
    .split("\n")
    .filter((line) => line.trim())
    .map((line, index) => {
      try {
        return { value: JSON.parse(line), raw: line, sourceIndex: index };
      } catch {
        return { value: null, raw: line, sourceIndex: index };
      }
    });
}

function jsonPacketType(packet) {
  if (!packet || typeof packet !== "object" || Array.isArray(packet)) {
    return "JSON";
  }
  return packet.kind || packet.stream || packet.record_kind || "JSON";
}

function outputTitleLabel(value, fallback) {
  return String(value || fallback).toLowerCase();
}

function packetSummary(packet) {
  if (!packet || typeof packet !== "object" || Array.isArray(packet)) {
    return "JSON value";
  }
  return jsonValueSummary(JSON.stringify(packet));
}

function replaceYAMLSection(text, marker, replacement) {
  const section = String(marker || "").replace(/:\s*$/, "");
  const lines = String(text || "").trimEnd().split("\n");
  const start = lines.findIndex((line) => yamlTopLevelKey(line) === section);
  if (start < 0) {
    return `${String(text || "").trimEnd()}\n\n${replacement.trimEnd()}\n`;
  }
  let end = start + 1;
  while (end < lines.length && !yamlTopLevelKey(lines[end])) {
    end += 1;
  }
  return [lines.slice(0, start).join("\n").trimEnd(), replacement.trimEnd(), lines.slice(end).join("\n").trimStart()]
    .filter(Boolean)
    .join("\n\n")
    .concat("\n");
}

function setYAMLSectionValues(text, sectionName, sectionYAML) {
  return setTopLevelYAMLSectionValues(String(text || ""), sectionName, sectionYAML)
    .trim()
    .concat("\n");
}

function appendYAMLListItems(text, sectionName, appendYAML) {
  const nextYAML = appendTopLevelYAMLListItems(String(text || ""), sectionName, appendYAML).trim();
  return nextYAML ? nextYAML.concat("\n") : String(text || "");
}

function setTopLevelYAMLSectionValues(configYAML, sectionName, sectionYAML) {
  const values = scalarYAMLSectionValues(sectionName, sectionYAML);
  if (values.length === 0) {
    return configYAML;
  }

  const sections = splitTopLevelYAMLSections(configYAML);
  const nextSections = [];
  let updated = false;

  for (const section of sections) {
    if (section.name === sectionName) {
      let text = section.text;
      for (const item of values) {
        text = setYAMLSectionScalarValue(text, sectionName, item.path, item.value);
      }
      nextSections.push({ name: sectionName, text });
      updated = true;
      continue;
    }
    nextSections.push(section);
  }

  if (!updated) {
    let text = `${sectionName}:`;
    for (const item of values) {
      text = setYAMLSectionScalarValue(text, sectionName, item.path, item.value);
    }
    const insertIndex =
      sectionName === "processor" ? 0 : nextSections.findIndex((section) => section.name === "encoder");
    if (insertIndex >= 0) {
      nextSections.splice(insertIndex, 0, { name: sectionName, text });
    } else {
      nextSections.push({ name: sectionName, text });
    }
  }

  return nextSections
    .map((section) => section.text.trim())
    .filter(Boolean)
    .join("\n\n");
}

function scalarYAMLSectionValues(sectionName, sectionYAML) {
  const section = splitTopLevelYAMLSections(sectionYAML).find((item) => item.name === sectionName);
  if (!section) {
    return [];
  }

  const values = [];
  const stack = [];
  const lines = section.text.split("\n").slice(1);
  for (const line of lines) {
    if (!line.trim() || line.trimStart().startsWith("- ")) {
      continue;
    }
    const match = line.match(/^(\s*)([A-Za-z_][A-Za-z0-9_-]*):(.*)$/);
    if (!match) {
      continue;
    }
    const indent = match[1].length;
    const key = match[2];
    const value = match[3].trim();
    stack.length = Math.max(0, Math.floor(indent / 2) - 1);
    stack.push(key);
    if (value) {
      values.push({ path: [...stack], value });
    }
  }
  return values;
}

function setYAMLSectionScalarValue(sectionText, sectionName, path, value) {
  if (path.length === 0) {
    return sectionText;
  }

  const lines = sectionText.trimEnd().split("\n");
  if (!topLevelYAMLHeader(lines[0]) || topLevelYAMLHeader(lines[0]).name !== sectionName) {
    lines.unshift(`${sectionName}:`);
  }

  let parentIndex = 0;
  let parentIndent = 0;
  for (const key of path.slice(0, -1)) {
    const childIndent = parentIndent + 2;
    let childIndex = directYAMLChildIndex(lines, parentIndex, parentIndent, key);
    if (childIndex < 0) {
      childIndex = yamlBlockEndIndex(lines, parentIndex, parentIndent);
      lines.splice(childIndex, 0, `${" ".repeat(childIndent)}${key}:`);
    }
    parentIndex = childIndex;
    parentIndent = childIndent;
  }

  const leaf = path[path.length - 1];
  const leafIndent = parentIndent + 2;
  const leafIndex = directYAMLChildIndex(lines, parentIndex, parentIndent, leaf);
  const line = `${" ".repeat(leafIndent)}${leaf}: ${value}`;
  if (leafIndex >= 0) {
    lines[leafIndex] = line;
  } else {
    lines.splice(yamlBlockEndIndex(lines, parentIndex, parentIndent), 0, line);
  }
  return lines.join("\n");
}

function directYAMLChildIndex(lines, parentIndex, parentIndent, key) {
  const childIndent = parentIndent + 2;
  const keyPattern = new RegExp(`^\\s{${childIndent}}${escapeRegExp(key)}:(?:\\s|$)`);
  for (let index = parentIndex + 1; index < lines.length; index += 1) {
    if (!lines[index].trim()) {
      continue;
    }
    const indent = leadingSpaces(lines[index]);
    if (indent <= parentIndent) {
      break;
    }
    if (indent === childIndent && keyPattern.test(lines[index])) {
      return index;
    }
  }
  return -1;
}

function yamlBlockEndIndex(lines, parentIndex, parentIndent) {
  for (let index = parentIndex + 1; index < lines.length; index += 1) {
    if (!lines[index].trim()) {
      continue;
    }
    if (leadingSpaces(lines[index]) <= parentIndent) {
      return index;
    }
  }
  return lines.length;
}

function appendTopLevelYAMLListItems(configYAML, sectionName, appendYAML) {
  const appendItems = topLevelYAMLListItems(sectionName, appendYAML);
  if (!appendItems) {
    return configYAML;
  }

  const sections = splitTopLevelYAMLSections(configYAML);
  const nextSections = [];
  let appended = false;

  for (const section of sections) {
    if (section.name === sectionName) {
      if (!appended) {
        nextSections.push({
          name: sectionName,
          text: appendTopLevelYAMLListSection(section.text, sectionName, appendItems),
        });
      }
      appended = true;
      continue;
    }
    nextSections.push(section);
  }

  if (!appended) {
    return replaceYAMLSection(configYAML, `${sectionName}:`, appendYAML);
  }

  return nextSections
    .map((section) => section.text.trim())
    .filter(Boolean)
    .join("\n\n");
}

function topLevelYAMLListItems(sectionName, sectionYAML) {
  const section = splitTopLevelYAMLSections(sectionYAML).find((item) => item.name === sectionName);
  if (!section) {
    return "";
  }

  const lines = section.text.trimEnd().split("\n");
  const header = topLevelYAMLHeader(lines[0]);
  if (!header || header.name !== sectionName || header.value) {
    return "";
  }

  return lines.slice(1).join("\n").trimEnd();
}

function appendTopLevelYAMLListSection(sectionText, sectionName, appendItems) {
  const lines = sectionText.trimEnd().split("\n");
  const header = topLevelYAMLHeader(lines[0]);
  const body = lines.slice(1).join("\n").trimEnd();

  if (!header || header.name !== sectionName || header.value === "[]" || (header.value && !body) || !body) {
    return `${sectionName}:\n${appendItems}`;
  }

  return `${sectionText.trimEnd()}\n${appendItems}`;
}

function splitTopLevelYAMLSections(yaml) {
  const sections = [];
  let current = null;
  for (const line of String(yaml || "").split("\n")) {
    const topLevelKey = yamlTopLevelKey(line);
    if (topLevelKey) {
      if (current) {
        sections.push({ name: current.name, text: current.lines.join("\n") });
      }
      current = { name: topLevelKey, lines: [line] };
    } else if (current) {
      current.lines.push(line);
    } else if (line.trim()) {
      current = { name: "", lines: [line] };
    }
  }
  if (current) {
    sections.push({ name: current.name, text: current.lines.join("\n") });
  }
  return sections.filter((section) => section.text.trim());
}

function topLevelYAMLHeader(line = "") {
  const match = line.match(/^([A-Za-z_][A-Za-z0-9_-]*):(.*)$/);
  if (!match) {
    return null;
  }
  return { name: match[1], value: match[2].trim() };
}

function leadingSpaces(line) {
  return line.match(/^ */)?.[0].length || 0;
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function yamlTopLevelKey(line) {
  return line.match(/^([A-Za-z_][A-Za-z0-9_-]*):(?:\s|$)/)?.[1] || "";
}

function setStatus(message, tone = "") {
  state.status = message;
  state.statusTone = tone;
  updateStatusElement();
}

function updateStatusElement() {
  if (!els.status) {
    return;
  }
  els.status.textContent = state.status;
  els.status.dataset.tone = state.statusTone;
  els.status.classList.toggle("hidden", !state.statusTone);
}

function logEntry(stream, stage, value) {
  const message = value?.stack || value?.message || String(value);
  return `[${stream}] ${stage}: ${message}`;
}

function setLogEntries(entries) {
  state.logs = entries.filter(Boolean);
  els.log.textContent = state.logs.join("\n");
  els.log.scrollTop = els.log.scrollHeight;
}

function appendLogEntries(entries) {
  setLogEntries([...(state.logs || []), ...entries]);
}

function loadScript(src) {
  if (wasmScriptLoaded || document.querySelector(`script[src="${CSS.escape(src)}"]`)) {
    wasmScriptLoaded = true;
    return Promise.resolve();
  }
  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = src;
    script.onload = () => {
      wasmScriptLoaded = true;
      resolve();
    };
    script.onerror = () => reject(new Error(`could not load ${src}`));
    document.head.append(script);
  });
}

function readReceivedAt(card, fallback, options = {}) {
  const value = card?.querySelector?.('input[data-field="receivedAt"]')?.value;
  if (!value) {
    return options.commit ? "" : fallback || "";
  }
  const parsed = parseReceivedAtInput(value);
  return Number.isNaN(parsed.getTime()) ? fallback || "" : parsed.toISOString();
}

function receivedAtInputValue(value, entryID) {
  if (activeReceivedAtDraft && String(activeReceivedAtDraft.entryID) === String(entryID)) {
    return activeReceivedAtDraft.value;
  }
  if (!value) {
    return "";
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return "";
  }
  return formatReceivedAtInputValue(parsed);
}

function isEditingReceivedAt(entryID) {
  return activeReceivedAtDraft && String(activeReceivedAtDraft.entryID) === String(entryID);
}

function receivedAtPickerValues(item) {
  const inputValue = receivedAtInputValue(item.receivedAt, item.id);
  let parsed = inputValue ? parseReceivedAtInput(inputValue) : new Date(item.receivedAt || Date.now());
  if (Number.isNaN(parsed.getTime())) {
    parsed = new Date(item.receivedAt || Date.now());
  }
  if (Number.isNaN(parsed.getTime())) {
    parsed = new Date();
  }
  return {
    date: formatPickerDateValue(parsed),
    time: formatPickerTimeValue(parsed),
  };
}

function readReceivedAtPicker(card) {
  const dateValue = card.querySelector('input[data-received-at-part="date"]')?.value || "";
  const timeValue = card.querySelector('input[data-received-at-part="time"]')?.value || "00:00:00.000";
  const date = parsePickerDateTime(dateValue, timeValue);
  if (Number.isNaN(date.getTime())) {
    throw new Error("Choose a valid received date and time");
  }
  return date;
}

function parseReceivedAtInput(value) {
  const text = String(value || "").trim();
  const localParts = text.match(/^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?)?$/);
  if (localParts) {
    const [, year, month, day, hour = "0", minute = "0", second = "0", millisecond = "0"] = localParts;
    return new Date(
      Number(year),
      Number(month) - 1,
      Number(day),
      Number(hour),
      Number(minute),
      Number(second),
      Number(millisecond.padEnd(3, "0")),
    );
  }
  const compactParts = text.match(/^(\d{4})(\d{2})(\d{2})(?:(\d{2})(\d{2})(?:(\d{2})(\d{1,3})?)?)?$/);
  if (compactParts) {
    const [, year, month, day, hour = "0", minute = "0", second = "0", millisecond = "0"] = compactParts;
    return new Date(
      Number(year),
      Number(month) - 1,
      Number(day),
      Number(hour),
      Number(minute),
      Number(second),
      Number(millisecond.padEnd(3, "0")),
    );
  }
  const parsed = new Date(text);
  return Number.isNaN(parsed.getTime()) ? new Date(Number.NaN) : parsed;
}

function formatReceivedAtInputValue(date) {
  return [
    date.getFullYear(),
    "-",
    padDatePart(date.getMonth() + 1),
    "-",
    padDatePart(date.getDate()),
    " ",
    padDatePart(date.getHours()),
    ":",
    padDatePart(date.getMinutes()),
    ":",
    padDatePart(date.getSeconds()),
    ".",
    String(date.getMilliseconds()).padStart(3, "0"),
  ].join("");
}

function formatPickerDateValue(date) {
  return [
    date.getFullYear(),
    "-",
    padDatePart(date.getMonth() + 1),
    "-",
    padDatePart(date.getDate()),
  ].join("");
}

function formatPickerTimeValue(date) {
  return [
    padDatePart(date.getHours()),
    ":",
    padDatePart(date.getMinutes()),
    ":",
    padDatePart(date.getSeconds()),
    ".",
    String(date.getMilliseconds()).padStart(3, "0"),
  ].join("");
}

function parsePickerDateTime(dateValue, timeValue) {
  const dateParts = String(dateValue || "").match(/^(\d{4})-(\d{2})-(\d{2})$/);
  const timeParts = String(timeValue || "").match(/^(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?$/);
  if (!dateParts || !timeParts) {
    return new Date(Number.NaN);
  }
  const [, year, month, day] = dateParts;
  const [, hour, minute, second = "0", millisecond = "0"] = timeParts;
  return new Date(
    Number(year),
    Number(month) - 1,
    Number(day),
    Number(hour),
    Number(minute),
    Number(second),
    Number(millisecond.padEnd(3, "0")),
  );
}

function padDatePart(value) {
  return String(value).padStart(2, "0");
}

function packetTimestamp(value) {
  const parsed = value ? new Date(value) : new Date();
  const date = Number.isNaN(parsed.getTime()) ? new Date() : parsed;
  const ms = date.getTime();
  return {
    seconds: Math.floor(ms / 1000),
    microseconds: (ms % 1000) * 1000,
  };
}

function prettyJSON(parsed, fallback) {
  if (parsed !== undefined && parsed !== null) {
    return JSON.stringify(parsed);
  }
  return fallback || "";
}

function flattenObject(value, prefix = "", out = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    out[prefix || "value"] = value;
    return out;
  }
  for (const [key, child] of Object.entries(value)) {
    const nextKey = prefix ? `${prefix}.${key}` : key;
    if (child && typeof child === "object" && !Array.isArray(child)) {
      flattenObject(child, nextKey, out);
    } else {
      out[nextKey] = child;
    }
  }
  return out;
}

function formatValue(value) {
  return typeof value === "string" ? value : JSON.stringify(value);
}

function wrapText(text, width) {
  return String(text || "").match(new RegExp(`.{1,${width}}`, "g"))?.join("\n") || "";
}

function formatHexBlock(hex) {
  const clean = cleanHexText(hex);
  return clean.match(/.{1,32}/g)?.map((line) => line.match(/.{1,2}/g)?.join(" ") || "").join("\n") || "";
}

function cleanHexText(text) {
  return String(text || "").replace(/[^0-9a-f]/gi, "").toLowerCase();
}

function hexInputValidationError(text) {
  const value = String(text || "");
  if (!value.trim()) {
    return "";
  }
  const invalid = value.match(/[^0-9a-f\s:,_-]/i);
  if (invalid) {
    return `hex input contains ${JSON.stringify(invalid[0])}`;
  }
  if (cleanHexText(value).length % 2 !== 0) {
    return "hex input has odd length";
  }
  return "";
}

function hexToBytes(hex) {
  const clean = cleanHexText(hex);
  if (clean.length % 2 !== 0) {
    throw new Error("hex input has odd length");
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = Number.parseInt(clean.slice(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function base64ToBytes(base64) {
  const raw = atob(String(base64 || "").replace(/\s+/g, ""));
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) {
    bytes[i] = raw.charCodeAt(i);
  }
  return bytes;
}

function bytesToBase64(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function fileToBase64(file) {
  return file.arrayBuffer().then((buffer) => bytesToBase64(new Uint8Array(buffer)));
}

function arrayBufferToBase64(buffer) {
  return bytesToBase64(new Uint8Array(buffer));
}

function hexAddress(offset) {
  return offset.toString(16).padStart(4, "0");
}

function hexDumpHTML(hex, ranges = []) {
  const clean = cleanHexText(hex);
  if (!clean) {
    return `<div class="proto-hex"></div>`;
  }
  const rows = [];
  for (let offset = 0; offset < clean.length / 2; offset += 16) {
    const slice = clean.slice(offset * 2, (offset + 16) * 2);
    const bytes = [];
    for (let index = 0; index < slice.length; index += 2) {
      const byteOffset = offset + index / 2;
      const range = ranges.find((candidate) => byteOffset >= candidate.start && byteOffset < candidate.end);
      const className = range ? ` proto-hex-byte--${range.kind}` : "";
      bytes.push(`<span class="proto-hex-byte${className}">${slice.slice(index, index + 2)}</span>`);
    }
    rows.push(`<div class="proto-hex-row"><span class="proto-hex-address">${hexAddress(offset)}:</span><span class="proto-hex-bytes">${bytes.join(" ")}</span></div>`);
  }
  return `<div class="proto-hex">${rows.join("")}</div>`;
}

function hexDumpText(hex) {
  const clean = cleanHexText(hex);
  const lines = [];
  for (let offset = 0; offset < clean.length / 2; offset += 16) {
    const slice = clean.slice(offset * 2, (offset + 16) * 2);
    lines.push(`${hexAddress(offset)}: ${slice.match(/.{1,2}/g)?.join(" ") || ""}`);
  }
  return lines.join("\n");
}

function decodedProtoPayloadText(item) {
  const cached = protoPayloadCacheEntry(item);
  if (cached.text !== undefined) {
    return cached.text;
  }
  try {
    const bytes = cachedProtoPayloadBytes(item, cached);
    cached.text = decodeProtobufPayloadText(bytes, item);
  } catch (error) {
    cached.text = `Unable to decode protobuf payload: ${error.message || String(error)}`;
  }
  return cached.text;
}

function protoPayloadHexRanges(item) {
  const cached = protoPayloadCacheEntry(item);
  if (cached.ranges !== undefined) {
    return cached.ranges;
  }
  try {
    cached.ranges = protobufPayloadHexRanges(cachedProtoPayloadBytes(item, cached), item);
  } catch {
    cached.ranges = [];
  }
  return cached.ranges;
}

function protoPayloadCacheEntry(item) {
  const key = protoPayloadCacheKey(item);
  let cached = protoDecodeCache.get(key);
  if (!cached) {
    cached = {};
    protoDecodeCache.set(key, cached);
  }
  return cached;
}

function cachedProtoPayloadBytes(item, cached = protoPayloadCacheEntry(item)) {
  if (!cached.bytes) {
    cached.bytes = payloadBytes(item);
  }
  return cached.bytes;
}

function protoPayloadCacheKey(item) {
  const base64 = item?.base64 || "";
  const hex = item?.hex || "";
  return [
    item?.key || "",
    item?.protobufFraming || "",
    payloadLength(item),
    base64.length,
    base64.slice(0, 24),
    base64.slice(-24),
    hex.length,
    hex.slice(0, 24),
    hex.slice(-24),
  ].join("\u001f");
}

function decodeProtoBytes(bytes) {
  try {
    return { text: decodeRawProtobufFields(bytes, 0, bytes.length, 0).join("\n"), ranges: rawProtobufHexRanges(bytes, 0, bytes.length) };
  } catch (error) {
    return { text: `Unable to decode protobuf payload: ${error.message || String(error)}`, ranges: [] };
  }
}

function decodeProtobufPayloadText(bytes, item) {
  if (item?.protobufFraming !== "delimited") {
    return decodeRawProtobufFields(bytes, 0, bytes.length, 0).join("\n");
  }
  const messages = delimitedProtobufMessages(bytes);
  if (!messages.length) {
    return "";
  }
  return messages
    .map((message, index) => {
      const header = `# Message ${index + 1} (${formatBytes(message.length)})`;
      const body = decodeRawProtobufFields(bytes, message.start, message.end, 0).join("\n");
      return `${header}\n${body}`;
    })
    .join("\n\n");
}

function decodeRawProtobufFields(bytes, start, end, depth) {
  const lines = [];
  let offset = start;
  const indent = "  ".repeat(depth);
  while (offset < end) {
    const tag = readProtobufVarint(bytes, offset, end);
    offset = tag.offset;
    if (tag.value === 0n) {
      throw new Error("invalid field tag");
    }
    const fieldNumber = tag.value >> 3n;
    const wireType = Number(tag.value & 7n);
    if (wireType === 0) {
      const value = readProtobufVarint(bytes, offset, end);
      offset = value.offset;
      lines.push(`${indent}${fieldNumber}: ${value.value}`);
    } else if (wireType === 1) {
      ensureProtobufBytes(bytes, offset, 8, end);
      lines.push(`${indent}${fieldNumber}: fixed64 0x${bytesToHex(bytes.subarray(offset, offset + 8))}`);
      offset += 8;
    } else if (wireType === 2) {
      const size = readProtobufVarint(bytes, offset, end);
      offset = size.offset;
      const length = Number(size.value);
      if (!Number.isSafeInteger(length) || length < 0) {
        throw new Error("protobuf field length is too large");
      }
      ensureProtobufBytes(bytes, offset, length, end);
      lines.push(`${indent}${fieldNumber}: bytes(${length}) ${bytesToHex(bytes.subarray(offset, offset + Math.min(length, 16)))}`);
      offset += length;
    } else if (wireType === 5) {
      ensureProtobufBytes(bytes, offset, 4, end);
      lines.push(`${indent}${fieldNumber}: fixed32 0x${bytesToHex(bytes.subarray(offset, offset + 4))}`);
      offset += 4;
    } else {
      throw new Error(`unsupported wire type ${wireType}`);
    }
  }
  return lines;
}

function protobufPayloadHexRanges(bytes, item) {
  if (item?.protobufFraming !== "delimited") {
    return rawProtobufHexRanges(bytes, 0, bytes.length);
  }
  const ranges = [];
  for (const message of delimitedProtobufMessages(bytes)) {
    ranges.push({ start: message.prefixStart, end: message.prefixEnd, kind: "length" });
    ranges.push(...rawProtobufHexRanges(bytes, message.start, message.end));
  }
  return ranges;
}

function delimitedProtobufMessages(bytes) {
  const messages = [];
  let offset = 0;
  while (offset < bytes.length) {
    const prefixStart = offset;
    const size = readProtobufVarint(bytes, offset);
    const length = Number(size.value);
    if (!Number.isSafeInteger(length) || length < 0) {
      throw new Error("protobuf frame length is too large");
    }
    const start = size.offset;
    const end = start + length;
    ensureProtobufBytes(bytes, start, length);
    messages.push({
      prefixStart,
      prefixEnd: start,
      start,
      end,
      length,
    });
    offset = end;
  }
  return messages;
}

function rawProtobufHexRanges(bytes, start = 0, end = bytes.length) {
  const ranges = [];
  let offset = start;
  while (offset < end) {
    const tagStart = offset;
    const tag = readProtobufVarint(bytes, offset, end);
    offset = tag.offset;
    ranges.push({ start: tagStart, end: offset, kind: "tag" });
    const wireType = Number(tag.value & 7n);
    if (wireType === 0) {
      offset = readProtobufVarint(bytes, offset, end).offset;
    } else if (wireType === 1) {
      ensureProtobufBytes(bytes, offset, 8, end);
      offset += 8;
    } else if (wireType === 2) {
      const lengthStart = offset;
      const size = readProtobufVarint(bytes, offset, end);
      offset = size.offset;
      const length = Number(size.value);
      if (!Number.isSafeInteger(length) || length < 0) {
        throw new Error("protobuf field length is too large");
      }
      ranges.push({ start: lengthStart, end: offset, kind: "length" });
      ensureProtobufBytes(bytes, offset, length, end);
      offset += length;
    } else if (wireType === 5) {
      ensureProtobufBytes(bytes, offset, 4, end);
      offset += 4;
    } else {
      throw new Error(`unsupported wire type ${wireType}`);
    }
  }
  if (offset !== end) {
    throw new Error("protobuf message length mismatch");
  }
  return ranges;
}

function readProtobufVarint(bytes, offset, end = bytes.length) {
  let value = 0n;
  let shift = 0n;
  for (let i = 0; i < 10; i += 1) {
    ensureProtobufBytes(bytes, offset, 1, end);
    const byte = bytes[offset];
    offset += 1;
    value |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      return { value, offset };
    }
    shift += 7n;
  }
  throw new Error("varint is too long");
}

function ensureProtobufBytes(bytes, offset, length, end = bytes.length) {
  if (offset + length > end || end > bytes.length) {
    throw new Error("truncated protobuf field");
  }
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) {
    return "0 B";
  }
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

async function copyText(text) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
  }
}

async function copyBlob(blob) {
  if (!navigator.clipboard?.write || typeof ClipboardItem === "undefined") {
    return false;
  }
  for (const type of clipboardBlobTypes(blob)) {
    try {
      await navigator.clipboard.write([new ClipboardItem({ [type]: blob })]);
      return true;
    } catch {
      // Try the next representation; most browsers only allow a narrow set.
    }
  }
  return false;
}

function clipboardBlobTypes(blob) {
  const nativeType = blob.type || "application/octet-stream";
  const candidates = [nativeType, "application/octet-stream", `web ${nativeType}`, "web application/octet-stream"];
  const seen = new Set();
  return candidates.filter((type) => {
    if (seen.has(type)) {
      return false;
    }
    seen.add(type);
    return type.startsWith("web ") || typeof ClipboardItem.supports !== "function" || ClipboardItem.supports(type);
  });
}

function downloadText(text, name, mimeType = "text/plain") {
  downloadBlob(new Blob([text], { type: mimeType }), name);
}

function downloadBase64(base64, name, mimeType = "application/octet-stream") {
  downloadBlob(new Blob([base64ToBytes(base64)], { type: mimeType }), name);
}

function downloadBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  URL.revokeObjectURL(url);
}

function nextFrame() {
  return new Promise((resolve) => requestAnimationFrame(resolve));
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}
