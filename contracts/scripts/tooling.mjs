import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve, join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
export const contractsRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const generatedRoot = resolve(contractsRoot, "../packages/apex-contracts-ts/src/gen");
// event.proto has a frozen, independently built ControlAction enum. Never merge
// its descriptor namespace with the management API or alter its hash contract.
export const sources = ["control", "governance", "mcp_proxy", "proxy_approval", "proxy_trace", "proxy_management", "proxy_runtime", "proxy_runtime_authority"];
export function buf(args) {
  const result = spawnSync(process.execPath, [require.resolve("@bufbuild/buf/bin/buf"), ...args], { cwd: contractsRoot, encoding: "utf8" });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(result.stderr || result.stdout || "buf failed");
  return result.stdout;
}
export function withInput(callback) {
  const temporary = mkdtempSync(join(tmpdir(), "apex-contract-input-"));
  try {
    mkdirSync(join(temporary, "apex/v1"), { recursive: true });
    for (const source of sources) {
      const input = join(contractsRoot, "proto/apex/v1", source + ".proto");
      if (existsSync(input)) copyFileSync(input, join(temporary, "apex/v1", source + ".proto"));
    }
    writeFileSync(join(temporary, "buf.yaml"), "version: v2\nmodules:\n  - path: .\nbreaking:\n  use: [FILE]\n");
    return callback(temporary);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}
export const plugin = require.resolve("@bufbuild/protoc-gen-es/bin/protoc-gen-es");
