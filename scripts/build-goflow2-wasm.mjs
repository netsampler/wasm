import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";

const goflowModule = "github.com/netsampler/goflow2/v3";
const manifestPath = "public/goflow2-wasm-manifest.json";
const runtimeID = process.env.GOFLOW2_WASM_ID || "current";
const wasmPath = process.env.GOFLOW2_WASM_PATH || "/goflow2.wasm";
const execPath = process.env.GOFLOW2_WASM_EXEC_PATH || "/wasm_exec.js";
const builtAt = new Date().toISOString();

execFileSync("node", ["scripts/copy-wasm-assets.mjs"], { stdio: "inherit" });

const goflowInfo = JSON.parse(
  execFileSync("go", ["list", "-m", "-json", goflowModule], {
    cwd: "apps/goflow2/wasm",
    encoding: "utf8",
  }),
);
const goflowDir = goflowInfo.Replace?.Dir || goflowInfo.Dir;
const commit =
  gitOutput(goflowDir, ["rev-parse", "--short=12", "HEAD"]) ||
  commitFromVersion(goflowInfo.Version) ||
  "unknown";
const describe =
  gitOutput(goflowDir, ["describe", "--tags", "--always", "--dirty"]) ||
  goflowInfo.Version ||
  "unknown";

const ldflags = [
  `-X main.goflowVersion=${describe}`,
  `-X main.goflowCommit=${commit}`,
  `-X main.goflowModule=${goflowModule}`,
  `-X main.goflowBuildTime=${builtAt}`,
  `-X main.wasmRuntimeID=${runtimeID}`,
].join(" ");

execFileSync("go", ["build", "-ldflags", ldflags, "-o", "../../../public/goflow2.wasm", "."], {
  cwd: "apps/goflow2/wasm",
  env: {
    ...process.env,
    GOOS: "js",
    GOARCH: "wasm",
    CGO_ENABLED: "0",
  },
  stdio: "inherit",
});

const generatedRuntime = {
  id: runtimeID,
  label: labelForRuntime(describe, commit),
  version: describe,
  commit,
  module: goflowModule,
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
