import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fromBinary, toBinary } from "@bufbuild/protobuf";
import * as contracts from "../../packages/apex-contracts-ts/src/index.js";

test("agent deployment registration is separate and never a browser or grant surface", () => {
  assert.equal(contracts.RuntimeDeploymentRegistry?.typeName, "apex.v1.RuntimeDeploymentRegistry");
  assert.deepEqual(contracts.RuntimeDeploymentRegistry.methods.map(m => [m.name, m.methodKind]), [["RegisterDeployment", "unary"]]);
  assert.deepEqual(contracts.RegisterRuntimeDeploymentRequestSchema.fields.map(f => [f.name, f.number]), [
    ["authority", 1], ["attestation", 2],
  ]);
  assert.deepEqual(contracts.RuntimeDeploymentRegistrationReceiptSchema.fields.map(f => [f.name, f.number]), [
    ["binding", 1], ["attestation_sha256", 2], ["authority", 3],
  ]);
  const browser = JSON.parse(readFileSync(new URL("../../packages/apex-contracts-ts/src/gen/browser-rpcs.json", import.meta.url)));
  assert.equal(browser.length, 22);
  assert.ok(browser.every(m => m.service === "apex.v1.McpProxyService"));
});

test("registration preserves original launch fence separately from current operation fence", () => {
  const schema = contracts.RegisterRuntimeDeploymentRequestSchema;
  assert.ok(schema);
  const input = { authority: { target: { generation: "9007199254740993", fencingToken: "9007199254740997" } },
    attestation: { schemaVersion: 1, launch: { target: { generation: "9007199254740993", fencingToken: "9007199254740995" } },
      instanceProofSha256: "a".repeat(64), stagedManifestSha256: "b".repeat(64) } };
  const value = contracts.decodeStrict(schema, JSON.stringify(input));
  assert.deepEqual(contracts.encodeJson(schema, fromBinary(schema, toBinary(schema, value))), input);
  assert.throws(() => contracts.decodeStrict(schema, '{"rawProof":"secret"}'));
});
