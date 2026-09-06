import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import test from "node:test";
import { contractsRoot } from "../scripts/tooling.mjs";

function gitHash(input, path) {
  const result = spawnSync("git", [
    "hash-object", "--stdin", path ? `--path=${path}` : "--no-filters",
  ], { cwd: resolve(contractsRoot, ".."), input });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr?.toString());
  return result.stdout.toString().trim();
}

for (const path of [
  "packages/apex-contracts-ts/src/gen/descriptor.binpb",
  "packages/apex-contracts-ts/src/gen/event/descriptor.binpb",
]) {
  test(`Git preserves binary descriptor bytes at ${path}`, () => {
    // CR/LF are valid protobuf bytes, not checkout line endings. Exercise the
    // actual clean filter without writing an object or touching the index.
    const bytes = Buffer.from([0x0a, 0x0d, 0x0a, 0x08, 0x01, 0x0d, 0x0a]);
    assert.equal(gitHash(bytes, path), gitHash(bytes));
  });
}

test("generated JavaScript retains canonical LF normalization", () => {
  const path = "packages/apex-contracts-ts/src/gen/event/apex/v1/event_pb.js";
  assert.equal(gitHash(Buffer.from("a\r\nb\r\n"), path), gitHash(Buffer.from("a\nb\n")));
});
