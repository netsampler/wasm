import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";

const reflowModule = "github.com/netsampler/goflow2/v3";
const buildTags = "reflow_nopcap,reflow_noebpf";
const manifestPath = "public/reflow-wasm-manifest.json";
const runtimeID = process.env.REFLOW_WASM_ID || "current";
const wasmPath = process.env.REFLOW_WASM_PATH || "/reflow.wasm";
const execPath = process.env.REFLOW_WASM_EXEC_PATH || "/wasm_exec.js";
const builtAt = new Date().toISOString();

execFileSync("node", ["scripts/copy-wasm-assets.mjs"], { stdio: "inherit" });

const reflowInfo = JSON.parse(
  execFileSync("go", ["list", "-m", "-json", reflowModule], {
    cwd: "apps/reflow/wasm",
    encoding: "utf8",
  }),
);
const reflowDir = reflowInfo.Replace?.Dir || reflowInfo.Dir;
const commit =
  gitOutput(reflowDir, ["rev-parse", "--short=12", "HEAD"]) ||
  commitFromVersion(reflowInfo.Version) ||
  "unknown";
const describe =
  gitOutput(reflowDir, ["describe", "--tags", "--always", "--dirty"]) ||
  reflowInfo.Version ||
  "unknown";

const ldflags = [
  `-X main.reflowVersion=${describe}`,
  `-X main.reflowCommit=${commit}`,
  `-X main.reflowModule=${reflowModule}`,
  `-X main.reflowBuildTime=${builtAt}`,
  `-X main.wasmRuntimeID=${runtimeID}`,
].join(" ");

execFileSync(
  "go",
  [
    "build",
    "-tags",
    buildTags,
    "-ldflags",
    ldflags,
    "-o",
    "../../../public/reflow.wasm",
    ".",
  ],
  {
    cwd: "apps/reflow/wasm",
    env: {
      ...process.env,
      GOOS: "js",
      GOARCH: "wasm",
      CGO_ENABLED: "0",
    },
    stdio: "inherit",
  },
);

const generatedRuntime = {
  id: runtimeID,
  label: labelForRuntime(describe, commit),
  version: describe,
  commit,
  module: reflowModule,
  builtAt,
  wasmPath,
  execPath,
};

const manifest = readManifest();
const preservedVersions = (manifest.versions || []).filter((runtime) => runtime.id !== runtimeID);
writeFileSync(
  manifestPath,
  `${JSON.stringify(
    {
      schemaVersion: 1,
      defaultVersion: runtimeID,
      versions: [generatedRuntime, ...preservedVersions],
    },
    null,
    2,
  )}\n`,
);

function gitOutput(cwd, args) {
  if (!cwd) {
    return "";
  }
  try {
    return execFileSync("git", ["-C", cwd, ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return "";
  }
}

function commitFromVersion(version) {
  const match = String(version || "").match(/-([0-9a-f]{12,40})$/u);
  return match?.[1]?.slice(0, 12) || "";
}

function labelForRuntime(version, commit) {
  if (version === "unknown" && commit === "unknown") {
    return "Current build";
  }
  if (commit === "unknown") {
    return version;
  }
  return `${version} (${commit})`;
}

function readManifest() {
  if (!existsSync(manifestPath)) {
    return { versions: [] };
  }
  try {
    return JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch {
    return { versions: [] };
  }
}
