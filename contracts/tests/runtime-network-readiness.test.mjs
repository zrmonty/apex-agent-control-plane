import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import * as contracts from "../../packages/apex-contracts-ts/src/index.js";

test("network inspection has separate Controller and managed workload RPC boundaries", () => {
  for (const name of ["RuntimeNetworkInspection", "ManagedNetworkReadiness"]) {
    assert.equal(contracts[name]?.typeName, `apex.v1.${name}`);
    assert.deepEqual(contracts[name].methods.map(m => [m.name, m.methodKind, m.input.typeName, m.output.typeName]), [
      ["Check", "unary", "apex.v1.RuntimeNetworkInspectionRequest", "apex.v1.RuntimeNetworkInspectionResponse"],
    ]);
  }
  const browser = JSON.parse(readFileSync(new URL("../../packages/apex-contracts-ts/src/gen/browser-rpcs.json", import.meta.url)));
  assert.equal(browser.length, 22);
  assert.ok(browser.every(m => m.service === "apex.v1.McpProxyService"));
});

test("network probe selects only immutable deployment plus nonce, never topology or a command", () => {
  assert.deepEqual(contracts.RuntimeNetworkInspectionRequestSchema?.fields.map(f => [f.number, f.name]), [
    [1, "schema_version"], [2, "binding"], [3, "nonce"],
  ]);
  assert.deepEqual(contracts.RuntimeNetworkInspectionResponseSchema?.fields.map(f => [f.number, f.name]), [
    [1, "schema_version"], [2, "binding"], [3, "nonce"], [4, "network_binding_sha256"],
    [5, "gateway_process_sha256"], [6, "guard_process_sha256"], [7, "valid_for_us"], [8, "confined"],
  ]);
});

test("network report preserves full original integers and defaults to not confined", () => {
  const schema = contracts.RuntimeNetworkInspectionResponseSchema;
  assert.ok(schema);
  const report = create(schema, {
    schemaVersion: 1, nonce: new Uint8Array(32).fill(7), validForUs: 10000000n,
    binding: { target: { generation: 9007199254740993n, fencingToken: 9007199254740995n } },
  });
  const decoded = fromBinary(schema, toBinary(schema, report));
  assert.equal(decoded.confined, false);
  assert.equal(decoded.validForUs, 10000000n);
  assert.equal(decoded.binding.target.generation, 9007199254740993n);
  assert.equal(decoded.binding.target.fencingToken, 9007199254740995n);
  assert.deepEqual(decoded.nonce, report.nonce);
});
