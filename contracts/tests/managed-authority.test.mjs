import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fromBinary, toBinary } from "@bufbuild/protobuf";
import * as contracts from "../../packages/apex-contracts-ts/src/index.js";

test("managed renewal/preflight/cleanup is a separate non-browser authority", () => {
  assert.equal(contracts.ManagedRuntimeAuthority?.typeName, "apex.v1.ManagedRuntimeAuthority");
  assert.deepEqual(contracts.ManagedRuntimeAuthority.methods.map(m => [m.name, m.methodKind]), [
    ["RenewDeployment", "unary"], ["GetManagedPolicy", "unary"], ["CompleteManagedCall", "unary"],
  ]);
  const browser = JSON.parse(readFileSync(new URL("../../packages/apex-contracts-ts/src/gen/browser-rpcs.json", import.meta.url)));
  assert.equal(browser.length, 22);
  assert.ok(browser.every(m => m.service === "apex.v1.McpProxyService"));
});

test("managed grants preserve nonce bytes, original fence, epoch and integer microseconds", () => {
  const schema = contracts.ManagedDeploymentGrantSchema;
  assert.equal(schema?.typeName, "apex.v1.ManagedDeploymentGrant");
  const input = { binding: { installationId: "installation", target: {
    workspaceId: "work", namespaceId: "ns", proxyId: "proxy", revisionId: "revision",
    generation: "9007199254740993", fencingToken: "9007199254740995",
  }, processInstanceId: "instance", configHash: "a".repeat(64), launchContextHash: "b".repeat(64) },
  nonce: Buffer.alloc(32, 7).toString("base64"), decisionId: "decision", epoch: "9007199254740999",
  mode: "MANAGED_GRANT_MODE_PREPARE", validForUs: "7" };
  const decoded = contracts.decodeStrict(schema, JSON.stringify(input));
  assert.equal(decoded.epoch, 9007199254740999n);
  assert.equal(decoded.validForUs, 7n);
  assert.deepEqual(contracts.encodeJson(schema, fromBinary(schema, toBinary(schema, decoded))), input);
  assert.throws(() => contracts.decodeStrict(schema, '{"epoch":9007199254740999}'));
  assert.throws(() => contracts.decodeStrict(schema, '{"epoch":"1","epoch":"2"}'));
});

test("managed business calls add immutable instance binding without renumbering existing fields", () => {
  assert.deepEqual(contracts.ManagedCallAuthorizationRequestSchema.fields.map(f => [f.name, f.number]), [
    ["caller", 1], ["scope", 2], ["proxy_id", 3], ["revision_id", 4], ["generation", 5],
    ["call_id", 6], ["tool_alias", 7], ["action", 8], ["resource", 9], ["classification", 10],
    ["arguments_hash", 11], ["trace", 12], ["approval_id", 13], ["binding", 14],
  ]);
  assert.deepEqual(contracts.GovernanceGateway.methods.map(m => m.name), ["Authorize", "GetPolicy"]);
});

test("managed admissions preserve local duration and epoch without narrowing policy revision", () => {
  const schema = contracts.ManagedCallAuthorizationDecisionSchema;
  assert.deepEqual(schema.fields.map(f => [f.name, f.number]), [
    ["decision", 1], ["approval", 2], ["admission_id", 3], ["expires_at_unix_us", 4],
    ["policy_revision", 5], ["valid_for_us", 6], ["epoch", 7],
  ]);
  for (const duration of ["1", "7", "999"]) {
    const input = { policyRevision: "18446744073709551615", expiresAtUnixUs: "9007199254740993", validForUs: duration, epoch: "9007199254740995" };
    const value = contracts.decodeStrict(schema, JSON.stringify(input));
    assert.equal(value.validForUs, BigInt(duration));
    assert.deepEqual(contracts.encodeJson(schema, fromBinary(schema, toBinary(schema, value))), input);
  }
});
