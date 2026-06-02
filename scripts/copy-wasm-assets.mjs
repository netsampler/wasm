import { copyFileSync, existsSync, mkdirSync } from "node:fs";
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
for (const asset of ["wiregasm.js", "wiregasm.wasm", "wiregasm.bmp", "wireshark.svg"]) {
  copyFileSync(join(wireviewRoot, "public", asset), join("public", asset));
}
