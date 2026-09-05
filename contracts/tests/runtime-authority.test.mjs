import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fromBinary, ScalarType, toBinary } from "@bufbuild/protobuf";
import * as contracts from "../../packages/apex-contracts-ts/src/index.js";

// Absent exports are assertion RED, not an import/setup failure. Examples are
// wire data only, never enrollment, authenticated observations or execution permits.
function schema(name) {
  const value = contracts[`${name}Schema`];
  assert.equal(value?.typeName, `apex.v1.${name}`, `${name} must be generated/exported`);
  return value;
}
function roundTrip(name, input) {
  const descriptor = schema(name);
  const decoded = contracts.decodeStrict(descriptor, JSON.stringify(input));
  assert.deepEqual(contracts.encodeJson(descriptor, decoded), input);
  const bytes = toBinary(descriptor, decoded);
  assert.ok(bytes.length < 4096, "wire example fits the later transport ceiling");
  assert.deepEqual(contracts.encodeJson(descriptor, fromBinary(descriptor, bytes)), input);
  return decoded;
}
const id = suffix => `0191b7f1-7f2c-7c13-9a61-2f29f2be10${suffix}`;
const target = { workspaceId: "acme", namespaceId: "prod", proxyId: id("01"), revisionId: id("02"),
  generation: "9007199254740993", fencingToken: "18446744073709551615" };
const request = { schemaVersion: 1, target, operationId: id("03"), commandId: id("04"),
  action: "RUNTIME_AUTHORITY_ACTION_CHECK_CURRENT_OPERATION", installationId: id("05"),
  observedControllerCertificateSha256: Buffer.alloc(32, 0xab).toString("base64") };
const snapshot = { schemaVersion: 1, target, operationId: id("03"), commandId: id("04"),
  action: request.action, installationId: id("05"), agentIdentityId: "host-agent-a",
  observedControllerIdentityId: "controller-a", peerPolicyVersion: "policy-1",
  enrollmentVersion: "enrollment-1", hostPolicyVersion: "host-1",
  desiredState: "PROXY_DESIRED_STATE_SERVING", observedState: "PROXY_OBSERVED_STATE_RECONCILING",
  configHash: "a".repeat(64), checkedAtUnixUs: "9007199254740993", leaseExpiresAtUnixUs: "9007199254741000" };

test("runtime authority exposes only one generated unary check, outside the browser API", () => {
  const service = contracts.RuntimeAuthorityService;
  assert.equal(service?.typeName, "apex.v1.RuntimeAuthorityService");
  assert.deepEqual(service.methods.map(method => [method.name, method.methodKind, method.input.typeName, method.output.typeName]),
    [["CheckRuntimeAuthority", "unary", "apex.v1.CheckRuntimeAuthorityRequest", "apex.v1.RuntimeAuthoritySnapshot"]]);
  const browser = JSON.parse(readFileSync(new URL("../../packages/apex-contracts-ts/src/gen/browser-rpcs.json", import.meta.url)));
  assert.equal(browser.length, 22);
  assert.ok(browser.every(method => method.service === "apex.v1.McpProxyService"));
});

const fields = {
  CheckRuntimeAuthorityRequest: [
    [1, "schema_version", "scalar", "UINT32"], [2, "target", "message", "apex.v1.RuntimeTarget"],
    [3, "operation_id", "scalar", "STRING"], [4, "command_id", "scalar", "STRING"],
    [5, "action", "enum", "apex.v1.RuntimeAuthorityAction"], [6, "installation_id", "scalar", "STRING"],
    [7, "observed_controller_certificate_sha256", "scalar", "BYTES"],
  ],
  RuntimeAuthoritySnapshot: [
    [1, "schema_version", "scalar", "UINT32"], [2, "target", "message", "apex.v1.RuntimeTarget"],
    [3, "operation_id", "scalar", "STRING"], [4, "command_id", "scalar", "STRING"],
    [5, "action", "enum", "apex.v1.RuntimeAuthorityAction"], [6, "installation_id", "scalar", "STRING"],
    [7, "agent_identity_id", "scalar", "STRING"], [8, "observed_controller_identity_id", "scalar", "STRING"],
    [9, "peer_policy_version", "scalar", "STRING"], [10, "enrollment_version", "scalar", "STRING"],
    [11, "host_policy_version", "scalar", "STRING"], [12, "desired_state", "enum", "apex.v1.ProxyDesiredState"],
    [13, "observed_state", "enum", "apex.v1.ProxyObservedState"], [14, "config_hash", "scalar", "STRING"],
    [15, "checked_at_unix_us", "scalar", "UINT64"], [16, "lease_expires_at_unix_us", "scalar", "UINT64"],
  ],
  RuntimeTarget: [
    [1, "workspace_id", "scalar", "STRING"], [2, "namespace_id", "scalar", "STRING"],
    [3, "proxy_id", "scalar", "STRING"], [4, "revision_id", "scalar", "STRING"],
    [5, "generation", "scalar", "UINT64"], [6, "fencing_token", "scalar", "UINT64"],
  ],
};
for (const [name, expected] of Object.entries(fields)) test(`${name} has exact fields without secret or execution capability expansion`, () => {
  assert.deepEqual(schema(name).fields.map(field => [field.number, field.name, field.fieldKind,
    field.message?.typeName ?? field.enum?.typeName ?? ScalarType[field.scalar]]), expected);
});

test("authority action has only unspecified and a non-executing current-operation check", () => {
  const descriptor = contracts.RuntimeAuthorityActionSchema;
  assert.equal(descriptor?.typeName, "apex.v1.RuntimeAuthorityAction");
  assert.deepEqual(descriptor.values.map(value => [value.name, value.number]), [
    ["RUNTIME_AUTHORITY_ACTION_UNSPECIFIED", 0], ["RUNTIME_AUTHORITY_ACTION_CHECK_CURRENT_OPERATION", 1],
  ]);
});
test("authority wire preserves observed pin bytes and the complete immutable target", () => {
  const decoded = roundTrip("CheckRuntimeAuthorityRequest", request);
  assert.deepEqual(Buffer.from(decoded.observedControllerCertificateSha256), Buffer.alloc(32, 0xab));
  assert.equal(decoded.target.generation, 9007199254740993n);
  assert.equal(decoded.target.fencingToken, 18446744073709551615n);
});
test("authority snapshot preserves 1, 7 and 999 microseconds and full uint64 width through JSON and binary", () => {
  for (const duration of [1n, 7n, 999n]) {
    const input = { ...snapshot, leaseExpiresAtUnixUs: String(9007199254740993n + duration) };
    const decoded = roundTrip("RuntimeAuthoritySnapshot", input);
    assert.equal(decoded.leaseExpiresAtUnixUs - decoded.checkedAtUnixUs, duration);
  }
  assert.equal(roundTrip("RuntimeAuthoritySnapshot", { ...snapshot, leaseExpiresAtUnixUs: "18446744073709551615" })
    .leaseExpiresAtUnixUs, 18446744073709551615n);
});
test("authority JSON rejects unsafe or noncanonical integer representations", () => {
  const descriptor = schema("RuntimeAuthoritySnapshot");
  for (const field of ["checkedAtUnixUs", "leaseExpiresAtUnixUs"]) {
    for (const value of [9007199254740992, -1, 1.5, "01", "-1", "1e3", "18446744073709551616"]) {
      assert.throws(() => contracts.decodeStrict(descriptor, JSON.stringify({ ...snapshot, [field]: value })));
    }
  }
});
test("authority JSON keeps original duplicate, alias, unknown field and unknown enum checks", () => {
  const descriptor = schema("CheckRuntimeAuthorityRequest");
  roundTrip("CheckRuntimeAuthorityRequest", request);
  for (const text of ['{"schemaVersion":1,"schemaVersion":1}', '{"schemaVersion":1,"schema_version":1}',
    '{"workerId":"forged"}', '{"target":{"commandId":"forged"}}', '{"action":777}',
    '{"action":"RUNTIME_AUTHORITY_ACTION_ENSURE"}']) {
    assert.throws(() => contracts.decodeStrict(descriptor, text));
  }
});
