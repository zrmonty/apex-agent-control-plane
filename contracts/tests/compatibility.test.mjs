import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { buf, withInput, contractsRoot, generatedRoot } from "../scripts/tooling.mjs";

test("compatibility gate actually detects reassigned existing field numbers", () => {
  withInput(input => {
    const path = join(input, "apex/v1/mcp_proxy.proto");
    const original = readFileSync(path, "utf8");
    assert.ok(original.includes("string request_id = 1;"));
    writeFileSync(path, original.replace("string request_id = 1;", "string request_id = 101;"));
    assert.throws(
      () => buf(["breaking", input, "--against", join(contractsRoot, "compatibility-baseline.binpb")]),
      /previously present|deleted|changed/i,
    );
  });
});

test("browser allowlist contains only management methods, not host or policy RPCs", () => {
  const methods = JSON.parse(readFileSync(join(generatedRoot, "browser-rpcs.json"), "utf8"));
  assert.equal(methods.length, 22);
  assert.ok(methods.every(method => method.service === "apex.v1.McpProxyService"));
  for (const name of ["GetProxyCapabilities", "GetProxyTrace", "DecideProxyApproval"]) {
    assert.ok(methods.some(method => method.method === name));
  }
  for (const name of ["EnsureRuntime", "RemoveRuntime", "AuthorizeManagedCall", "SubmitCommand"]) {
    assert.ok(methods.every(method => method.method !== name));
  }
});
