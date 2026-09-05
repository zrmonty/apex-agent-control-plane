import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fromBinary, toBinary } from "@bufbuild/protobuf";
import * as contracts from "../../packages/apex-contracts-ts/src/index.js";

test("deployment resolution is separate, unary and excluded from browser RPCs", () => {
  assert.equal(contracts.RuntimeDeploymentService?.typeName, "apex.v1.RuntimeDeploymentService");
  assert.deepEqual(contracts.RuntimeDeploymentService.methods.map(m => [m.name, m.methodKind, m.input.typeName, m.output.typeName]),
    [["ResolveRuntimeDeployment", "unary", "apex.v1.CheckRuntimeAuthorityRequest", "apex.v1.RuntimeDeploymentSnapshot"]]);
  const browser = JSON.parse(readFileSync(new URL("../../packages/apex-contracts-ts/src/gen/browser-rpcs.json", import.meta.url)));
  assert.equal(browser.length, 22);
  assert.ok(browser.every(m => m.service === "apex.v1.McpProxyService"));
});

test("deployment document generated wire preserves integer microseconds above JS precision", () => {
  const schema = contracts.RuntimeDeploymentBindingsDocumentSchema;
  assert.equal(schema?.typeName, "apex.v1.RuntimeDeploymentBindingsDocument");
  const input = { schemaVersion: 1, version: "bindings-1", validFromUnixUs: "9007199254740993", expiresAtUnixUs: "9007199254740994" };
  const message = contracts.decodeStrict(schema, JSON.stringify(input));
  assert.equal(message.validFromUnixUs, 9007199254740993n);
  assert.deepEqual(contracts.encodeJson(schema, fromBinary(schema, toBinary(schema, message))), input);
  assert.throws(() => contracts.decodeStrict(schema, '{"schemaVersion":1,"version":"one","version":"two"}'));
  assert.throws(() => contracts.decodeStrict(schema, '{"validFromUnixUs":9007199254740993}'));
});

test("published deployment response includes config but does not add caller launch fields", () => {
  assert.deepEqual(contracts.RuntimeDeploymentSnapshotSchema?.fields.map(f => f.name),
    ["schema_version", "authority", "configuration", "deployment_bindings_version"]);
  assert.equal(contracts.RuntimeDeploymentProfileSchema?.fields.length, 15);
  assert.ok(!contracts.CheckRuntimeAuthorityRequestSchema.fields.some(f => /configuration|image|secret|profile/.test(f.name)));
});
