import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";

const goroot = execFileSync("go", ["env", "GOROOT"], { encoding: "utf8" }).trim();
const source = join(goroot, "lib", "wasm", "wasm_exec.js");
const target = join("public", "wasm_exec.js");

if (!existsSync(source)) {
  throw new Error(`wasm_exec.js not found at ${source}`);
}

mkdirSync(dirname(target), { recursive: true });
copyFileSync(source, target);

const require = createRequire(import.meta.url);
const wireviewPackage = require.resolve("wireview/package.json");
const wireviewRoot = dirname(wireviewPackage);
patchWireViewWorker(wireviewRoot);
for (const asset of ["wiregasm.js", "wiregasm.wasm", "wiregasm.bmp", "wireshark.svg"]) {
  copyFileSync(join(wireviewRoot, "public", asset), join("public", asset));
}

function patchWireViewWorker(root) {
  const workerPath = join(root, "src", "worker.js");
  let worker = readFileSync(workerPath, "utf8");
  if (worker.includes("wireviewAssetPath")) {
    return;
  }

  worker = worker
    .replace(
      'importScripts("/wiregasm.js");',
      `const wireviewAssetPath = (path) => {
  if (self.location.pathname.includes("/node_modules/wireview/")) {
    return new URL(path, self.location.origin + "/").toString();
  }
  return new URL(\`../\${path}\`, self.location.href).toString();
};

importScripts(wireviewAssetPath("wiregasm.js"));`,
    )
    .replace('return "/wiregasm.bmp";', 'return wireviewAssetPath("wiregasm.bmp");')
    .replace('return "/wiregasm.wasm";', 'return wireviewAssetPath("wiregasm.wasm");');

  writeFileSync(workerPath, worker);
}
