import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fromBinary, ScalarType, toBinary } from "@bufbuild/protobuf";
import { decodeStrict, encodeJson } from "../../packages/apex-contracts-ts/src/json.js";
import * as runtime from "../../packages/apex-contracts-ts/src/gen/apex/v1/proxy_runtime_pb.js";

// These are wire examples, not trusted launches, secret material or readiness proof.
// Namespace import makes absent new messages assertion RED, not an import failure.
function schema(name) {
  const value = runtime[`${name}Schema`];
  assert.equal(value?.typeName, `apex.v1.${name}`, `${name} generated schema must exist`);
  return value;
}

function roundTrip(name, input) {
  const descriptor = schema(name);
  const message = decodeStrict(descriptor, JSON.stringify(input));
  assert.deepEqual(encodeJson(descriptor, message), input);
  assert.deepEqual(encodeJson(descriptor, fromBinary(descriptor, toBinary(descriptor, message))), input);
  return message;
}

const target = {
  workspaceId: "acme", namespaceId: "prod",
  proxyId: "0191b7f1-7f2c-7c13-9a61-2f29f2be1001",
  revisionId: "0191b7f1-7f2c-7c13-9a61-2f29f2be1002",
  generation: "9007199254740993", fencingToken: "18446744073709551615",
};
const material = {
  role: "RUNTIME_MATERIAL_ROLE_HEALTH_TOKEN", reference: "secret://deployment/health", version: "version-1",
};
const health = { port: 8081, credentialRef: "secret://deployment/health" };
const check = {
  id: "READINESS_CHECK_ID_LAUNCH", status: "READINESS_CHECK_STATUS_PENDING", reason: "READINESS_REASON_UNAVAILABLE",
};
function stage(durationUs = "7", durationNs = "7000") {
  return {
    name: "launch", startedAtUnixUs: "9007199254740993", durationUs, durationNs,
    otelTraceId: "0123456789abcdef0123456789abcdef", spanId: "0123456789abcdef",
    parentSpanId: "fedcba9876543210", processInstanceId: "0191b7f1-7f2c-7c13-9a61-2f29f2be1003",
    clockSource: "wire-example", clockResolutionNs: "1000", clockUncertaintyUs: "1",
  };
}
function launch() {
  return {
    schemaVersion: 1, target: { ...target }, configHash: "a".repeat(64), runtimeManifestHash: "b".repeat(64),
    imageRef: `registry.example.test/apex/mcp-gateway@sha256:${"c".repeat(64)}`,
    processInstanceId: "0191b7f1-7f2c-7c13-9a61-2f29f2be1003", health: { ...health }, materials: [{ ...material }],
    launchContextHash: "d".repeat(64), authorityProfileRef: "profile://deployment/live", authorityProfileVersion: "version-1",
  };
}
function report() {
  return {
    live: true, target: { ...target }, observedAtUnixUs: "18446744073709551615",
    configHash: "a".repeat(64), runtimeManifestHash: "b".repeat(64),
    processInstanceId: "0191b7f1-7f2c-7c13-9a61-2f29f2be1003",
    checks: [{ ...check }], stages: [stage()], launchContextHash: "d".repeat(64),
  };
}
const oldObservation = {
  target, runtimeId: "owned-wire-example", state: "wire-example", ready: true, admitting: true,
  activeCalls: "7", observedAtUnixUs: "9007199254740993", errorCode: "WIRE_EXAMPLE",
  resourceUrl: "https://proxy.example.test/mcp", stages: [stage()],
};

const fields = {
  RuntimeMaterialBinding: [[1, "role", "enum", "apex.v1.RuntimeMaterialRole"], [2, "reference", "scalar", "STRING"], [3, "version", "scalar", "STRING"]],
  RuntimeHealthBinding: [[1, "port", "scalar", "UINT32"], [2, "credential_ref", "scalar", "STRING"]],
  RuntimeLaunchContext: [
    [1, "schema_version", "scalar", "UINT32"], [2, "target", "message", "apex.v1.RuntimeTarget"],
    [3, "config_hash", "scalar", "STRING"], [4, "runtime_manifest_hash", "scalar", "STRING"],
    [5, "image_ref", "scalar", "STRING"], [6, "process_instance_id", "scalar", "STRING"],
    [7, "health", "message", "apex.v1.RuntimeHealthBinding"], [8, "materials", "list", "apex.v1.RuntimeMaterialBinding"],
    [9, "launch_context_hash", "scalar", "STRING"], [10, "authority_profile_ref", "scalar", "STRING"],
    [11, "authority_profile_version", "scalar", "STRING"],
  ],
  ReadinessCheck: [
    [1, "id", "enum", "apex.v1.ReadinessCheckId"], [2, "status", "enum", "apex.v1.ReadinessCheckStatus"],
    [3, "reason", "enum", "apex.v1.ReadinessReason"],
  ],
  ReadinessReport: [
    [1, "live", "scalar", "BOOL"], [2, "ready", "scalar", "BOOL"], [3, "target", "message", "apex.v1.RuntimeTarget"],
    [4, "observed_at_unix_us", "scalar", "UINT64"], [5, "config_hash", "scalar", "STRING"],
    [6, "runtime_manifest_hash", "scalar", "STRING"], [7, "process_instance_id", "scalar", "STRING"],
    [8, "checks", "list", "apex.v1.ReadinessCheck"], [9, "stages", "list", "apex.v1.ProxyStageTiming"],
    [10, "launch_context_hash", "scalar", "STRING"],
  ],
  RuntimeObservation: [
    [1, "target", "message", "apex.v1.RuntimeTarget"], [2, "runtime_id", "scalar", "STRING"], [3, "state", "scalar", "STRING"],
    [4, "ready", "scalar", "BOOL"], [5, "admitting", "scalar", "BOOL"], [6, "active_calls", "scalar", "UINT64"],
    [7, "observed_at_unix_us", "scalar", "UINT64"], [8, "error_code", "scalar", "STRING"],
    [9, "resource_url", "scalar", "STRING"], [10, "stages", "list", "apex.v1.ProxyStageTiming"],
    [11, "readiness", "message", "apex.v1.ReadinessReport"],
  ],
};
for (const [name, expected] of Object.entries(fields)) {
  test(`${name} preserves assigned binary field numbers, types and cardinality`, () => {
    assert.deepEqual(schema(name).fields.map(field => [
      field.number, field.name, field.fieldKind, field.message?.typeName ?? field.enum?.typeName ?? ScalarType[field.scalar],
    ]), expected);
  });
}

const enums = {
  RuntimeMaterialRole: ["RUNTIME_MATERIAL_ROLE_", [
    ["UNSPECIFIED", 0], ["HEALTH_TOKEN", 1], ["GOVERNANCE_CA", 2], ["GOVERNANCE_CERT", 3],
    ["GOVERNANCE_KEY", 4], ["GOVERNANCE_TOKEN", 5], ["EVIDENCE_CA", 6], ["EVIDENCE_CERT", 7],
    ["EVIDENCE_KEY", 8], ["EVIDENCE_TOKEN", 9], ["INBOUND_JWKS", 10], ["WORKLOAD_CA", 11],
    ["WORKLOAD_CERT", 12], ["WORKLOAD_KEY", 13],
  ], "RuntimeMaterialBinding", "role"],
  ReadinessCheckId: ["READINESS_CHECK_ID_", [
    ["UNSPECIFIED", 0], ["CONFIG", 1], ["LAUNCH", 2], ["MATERIAL", 3], ["INBOUND_AUTH", 4],
    ["UPSTREAM_CATALOG", 5], ["GOVERNANCE", 6], ["EVIDENCE_ADMISSION", 7], ["NETWORK", 8], ["ADMISSION", 9],
  ], "ReadinessCheck", "id"],
  ReadinessCheckStatus: ["READINESS_CHECK_STATUS_", [["UNSPECIFIED", 0], ["PENDING", 1], ["PASS", 2], ["FAIL", 3]], "ReadinessCheck", "status"],
  ReadinessReason: ["READINESS_REASON_", [
    ["UNSPECIFIED", 0], ["OK", 1], ["INVALID", 2], ["UNAVAILABLE", 3], ["TIMEOUT", 4],
    ["CANCELLED", 5], ["STALE", 6], ["MISMATCH", 7], ["SHUTTING_DOWN", 8],
  ], "ReadinessCheck", "reason"],
};
for (const [name, [prefix, entries, messageName, field]] of Object.entries(enums)) {
  test(`${name} keeps each assigned enum number and canonical JSON name`, () => {
    const descriptor = schema(messageName);
    const enumDescriptor = runtime[`${name}Schema`];
    assert.equal(enumDescriptor?.typeName, `apex.v1.${name}`);
    assert.deepEqual(enumDescriptor.values.map(value => [value.name, value.number]), entries.map(([label, number]) => [prefix + label, number]));
    for (const [label, number] of entries) {
      for (const input of [prefix + label, number]) {
        const message = decodeStrict(descriptor, { [field]: input });
        assert.equal(message[field], number);
        assert.deepEqual(encodeJson(descriptor, message), number === 0 ? {} : { [field]: prefix + label });
      }
    }
  });
}

for (const [name, input] of [
  ["RuntimeMaterialBinding", material], ["RuntimeHealthBinding", health], ["RuntimeLaunchContext", launch()],
  ["ReadinessCheck", check], ["ReadinessReport", report()],
]) {
  test(`${name} round-trips strict JSON and binary without dropping fields`, () => roundTrip(name, input));
}
test("observation carries additive readiness without conflating ready and admitting", () => {
  const input = { ...report(), ready: true };
  const message = roundTrip("RuntimeObservation", { readiness: input });
  assert.equal(message.readiness.ready, true);
  assert.equal(message.ready, false);
  assert.equal(message.admitting, false);
  // No cross-binding/readiness semantics are implemented by this wire operation.
});
for (const [durationUs, durationNs] of [["1", "1000"], ["7", "7000"], ["999", "999000"]]) {
  test(`nested readiness timing retains ${durationUs} microseconds and clock metadata`, () => {
    const input = report();
    input.stages = [stage(durationUs, durationNs)];
    const message = roundTrip("RuntimeObservation", { readiness: input });
    assert.equal(message.readiness.stages[0].durationUs, BigInt(durationUs));
    assert.equal(message.readiness.stages[0].durationNs, BigInt(durationNs));
  });
}
for (const value of ["9007199254740993", "18446744073709551615"]) {
  test(`launch/report nested uint64 retains exact ${value} values`, () => {
    const input = launch();
    input.target.generation = value;
    input.target.fencingToken = value;
    const context = roundTrip("RuntimeLaunchContext", input);
    assert.equal(context.target.generation, BigInt(value));
    assert.equal(context.target.fencingToken, BigInt(value));
    const readiness = report();
    readiness.observedAtUnixUs = value;
    const message = roundTrip("ReadinessReport", readiness);
    assert.equal(message.observedAtUnixUs, BigInt(value));
  });
}

const badIntegers = [1, 9007199254740992, "", "01", "+1", "-1", "1.0", "1e3", " 1", "1\n", "18446744073709551616"];
for (const [name, wrap] of [
  ["RuntimeLaunchContext", value => ({ target: { generation: value } })],
  ["RuntimeLaunchContext", value => ({ target: { fencingToken: value } })],
  ["ReadinessReport", value => ({ observedAtUnixUs: value })],
  ["RuntimeObservation", value => ({ readiness: { stages: [{ durationUs: value }] } })],
]) {
  test(`${name} rejects malformed uint64 at ${JSON.stringify(wrap("field"))}`, () => {
    const descriptor = schema(name);
    // Require new nested schema before asserting rejection on the existing observation.
    schema("ReadinessReport");
    for (const value of badIntegers) {
      const input = wrap(value);
      assert.throws(() => decodeStrict(descriptor, input), /decimal integer string|64-bit range/);
      assert.throws(() => decodeStrict(descriptor, JSON.stringify(input)), /decimal integer string|64-bit range/);
    }
  });
}
test("health port and launch version retain uint32 width", () => {
  for (const [name, field] of [["RuntimeHealthBinding", "port"], ["RuntimeLaunchContext", "schemaVersion"]]) {
    const descriptor = schema(name);
    roundTrip(name, { [field]: 4294967295 });
    for (const value of [-1, 1.5, 4294967296]) assert.throws(() => decodeStrict(descriptor, { [field]: value }));
  }
  // Width checks are not a listener-port or supported launch-version policy.
});

for (const [name, input] of [
  ["RuntimeLaunchContext", { surprise: true }],
  ["RuntimeLaunchContext", { target: { surprise: true } }],
  ["RuntimeLaunchContext", { health: { host: "example.invalid" } }],
  ["RuntimeLaunchContext", { materials: [{ secretBytes: "wire-canary" }] }],
  ["ReadinessReport", { surprise: true }],
  ["ReadinessReport", { target: { surprise: true } }],
  ["ReadinessReport", { checks: [{ description: "wire-canary" }] }],
  ["ReadinessReport", { stages: [{ surprise: true }] }],
  ["RuntimeObservation", { readiness: { surprise: true } }],
]) {
  test(`${name} rejects nested unknown wire fields: ${JSON.stringify(input)}`, () => {
    const descriptor = schema(name);
    schema("ReadinessReport");
    for (const value of [input, JSON.stringify(input)]) assert.throws(() => decodeStrict(descriptor, value), /unknown field/);
  });
}
for (const [name, wrap] of [
  ["RuntimeLaunchContext", role => ({ materials: [{ role }] })],
  ["ReadinessReport", id => ({ checks: [{ id }] })],
  ["ReadinessReport", status => ({ checks: [{ status }] })],
  ["RuntimeObservation", reason => ({ readiness: { checks: [{ reason }] } })],
]) {
  test(`${name} rejects unknown nested enum at ${JSON.stringify(wrap("field"))}`, () => {
    const descriptor = schema(name);
    schema("ReadinessReport");
    for (const value of [999, -1, "UNKNOWN", "2"]) {
      assert.throws(() => decodeStrict(descriptor, JSON.stringify(wrap(value))), /unknown enum/);
    }
  });
}
for (const [name, input] of [
  ["RuntimeLaunchContext", '{"authorityProfileRef":"a","authority_profile_ref":"b"}'],
  ["RuntimeLaunchContext", '{"materials":[{"reference":"a","reference":"b"}]}'],
  ["ReadinessReport", '{"observedAtUnixUs":"1","observed_at_unix_us":"2"}'],
  ["RuntimeObservation", String.raw`{"readiness":{"checks":[{"status":1,"sta\u0074us":2}]}}`],
]) {
  test(`${name} rejects duplicate JSON keys/aliases in new boundaries`, () => {
    const descriptor = schema(name);
    schema("ReadinessReport");
    assert.throws(() => decodeStrict(descriptor, input), /duplicate/);
  });
}

test("empty launch/report/check messages remain wire defaults, not validated authority", () => {
  const context = roundTrip("RuntimeLaunchContext", {});
  assert.equal(context.schemaVersion, 0);
  assert.equal(context.target, undefined);
  assert.equal(context.health, undefined);
  assert.deepEqual(context.materials, []);
  const readiness = roundTrip("ReadinessReport", {});
  assert.equal(readiness.live, false);
  assert.equal(readiness.ready, false);
  assert.equal(readiness.target, undefined);
  assert.equal(readiness.observedAtUnixUs, 0n);
  assert.deepEqual(readiness.checks, []);
  const pending = roundTrip("ReadinessCheck", {});
  assert.equal(pending.id, 0);
  assert.equal(pending.status, 0);
  assert.equal(pending.reason, 0);
});
test("semantic check-count and readiness consistency remain outside strict wire decoding", () => {
  const input = { ready: true, checks: Array.from({ length: 17 }, () => ({})) };
  const message = roundTrip("ReadinessReport", input);
  assert.equal(message.ready, true);
  assert.equal(message.target, undefined);
  assert.equal(message.checks.length, 17);
  // Deliberately NOT a valid readiness report; later owners must reject it.
});
test("old observations without readiness preserve all previous wire fields", () => {
  const message = roundTrip("RuntimeObservation", oldObservation);
  assert.equal(message.readiness, undefined);
  assert.equal(message.activeCalls, 7n);
});
test("golden runtime v1 bytes and existing configuration meaning remain unchanged", () => {
  const text = readFileSync(new URL("../fixtures/mcp-proxy/runtime-revision.json", import.meta.url), "utf8");
  // Normalize checkout line endings only; raw local file hash is also recorded in handback.
  assert.equal(createHash("sha256").update(text.replace(/\r\n/g, "\n")).digest("hex"),
    "992215e75db03e105c90027a2c45fe0ff9849e3847901a0285356ac6dac83342");
  const input = JSON.parse(text);
  const message = roundTrip("RuntimeConfiguration", input);
  assert.equal(message.schemaVersion, 1);
  assert.deepEqual(message.secretRefs, ["secret://vault/upstreams/portfolio-reader"]);
  assert.throws(() => decodeStrict(schema("RuntimeConfiguration"), { ...input, health }), /unknown field/);
  assert.throws(() => decodeStrict(schema("RuntimeConfiguration"), { ...input, schemaVersion: 2 }), /unsupported runtime schema/);
});
