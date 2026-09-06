import assert from "node:assert/strict";
import test from "node:test";
import { RuntimeLaunchContextSchema, type RuntimeLaunchContext } from "@apex/contracts";
import { toJson } from "@bufbuild/protobuf";
import { launchContextHash, parseRuntimeLaunchContext } from "../launch-context.js";
import { parseManagedIngressProfile, type IngressProfileContext } from "./ingress-profile.js";
import { profileFixture } from "./ingress-profile-fixture.js";

test("explicit profile matches the exact launch and preserves source metadata", () => {
  const f = profileFixture();
  assert.deepEqual(parseManagedIngressProfile(f.bytes(), f.context), f.value);
});

function reject(bytes: Uint8Array, context: IngressProfileContext) {
  assert.throws(() => parseManagedIngressProfile(bytes, context), error => {
    assert.ok(error instanceof Error);
    assert.equal(error.message, "managed ingress profile rejected");
    assert.equal(error.cause, undefined);
    return true;
  });
}
function set(value: unknown, path: string, replacement: unknown) {
  const parts = path.split("/");
  let record = value as Record<string, unknown>;
  for (const part of parts.slice(0, -1)) record = record[part] as Record<string, unknown>;
  record[parts.at(-1)!] = replacement;
}
const invalid: [string, unknown][] = [
  ["schema_version", 1], ["schema_version", 2], ["schema_version", 4], ["schema_version", "3"],
  ["catalog_version", ""], ["catalog_version", "a".repeat(129)],
  ["profile", []], ["profile/mode", "managed_preparation"], ["profile/mode", { managed_ingress: null }],
  ["profile/managed", null], ["profile/managed", []],
  ["profile/managed/evidence_agent_id", ["managed-evidence"]], ["profile/managed/evidence_agent_id", "a..b"],
  ["profile/managed/upstream_credentials", "bearer"], ["profile/managed/upstream_credentials", { managed_upstream_v1: null }],
  ["profile/managed/network_policy", ["isolated-gateway", "v1"]],
  ["profile/managed/network_policy/reference", "../escape"], ["profile/managed/network_policy/version", null],
  ["profile/managed/ingress", []], ["profile/managed/ingress/port", 8081], ["profile/managed/ingress/port", "8080"],
  ["profile/managed/ingress/port", 8080.5],
  ...["", "Gateway.example", "*.example", "gateway.example.", "127.0.0.1", "::1", "-gateway", "gate_way", "a..b", "a".repeat(64)]
    .map(name => ["profile/managed/ingress/tls_server_name", name] as [string, unknown]),
  ...[[], null, "a".repeat(64), ["a".repeat(64), "a".repeat(64)], ["a".repeat(64), "b".repeat(64), "c".repeat(64)],
    ["0".repeat(64)], ["A".repeat(64)], ["a".repeat(63)], [false], [["a".repeat(64)]]]
    .map(pins => ["profile/managed/ingress/edge_certificate_sha256", pins] as [string, unknown]),
  ...["https://127.0.0.1", "https://other.example", "https://GOVERNANCE.example", "https://governance.example/path",
    "https://governance.example?", "https://governance.example#", "https://user:CANARY@governance.example", "http://governance.example"]
    .map(endpoint => ["profile/governance/endpoint", endpoint] as [string, unknown]),
  ["profile/evidence/tls_server_name", "Evidence.example"], ["profile/host_policy_version", "a..b"],
];
for (const [index, [path, replacement]] of invalid.entries()) {
  test(`invalid metadata ${index}: ${path}`, () => {
    const f = profileFixture(); set(f.value, path, replacement); reject(f.bytes(), f.context);
  });
}
for (const path of ["", "profile", "profile/governance", "profile/evidence", "profile/managed", "profile/managed/network_policy", "profile/managed/ingress"]) {
  test(`all required keys and no extra keys at ${path || "document"}`, () => {
    const f = profileFixture();
    const original = (path ? path.split("/").reduce((v, k) => (v as Record<string, unknown>)[k], f.value as unknown) : f.value) as Record<string, unknown>;
    for (const key of Object.keys(original)) {
      const value = structuredClone(f.value);
      const object = (path ? path.split("/").reduce((v, k) => (v as Record<string, unknown>)[k], value as unknown) : value) as Record<string, unknown>;
      delete object[key]; reject(Buffer.from(JSON.stringify(value)), f.context);
    }
    original.extra = "CANARY"; reject(f.bytes(), f.context);
  });
}
for (const field of ["installation_id", "workspace_id", "namespace_id", "proxy_id", "reference", "version"]) {
  test(`profile binds ${field} to the exact deployment`, () => {
    const f = profileFixture(); set(f.value, `profile/${field}`, "other"); reject(f.bytes(), f.context);
  });
}
for (const key of ["workspaceId", "namespaceId", "installationId", "proxyId", "revisionId", "processInstanceId", "configHash", "launchContextHash", "generation", "fencingToken"] as const) {
  test(`deployment binding ${key} cannot drift from the profile/launch`, () => {
    const f = profileFixture();
    const replacement = ["generation", "fencingToken"].includes(key) ? 9007199254740997n :
      ["configHash", "launchContextHash"].includes(key) ? "d".repeat(64) :
      ["workspaceId", "namespaceId"].includes(key) ? "other" : "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e99";
    const binding = { ...f.context.binding, [key]: replacement };
    reject(f.bytes(), { ...f.context, binding });
  });
}
test("missing or reused deployment TLS role metadata refuses even if launch hash is recomputed", () => {
  for (const change of ["missing", "shared"]) {
    const f = profileFixture(), launch = structuredClone(f.context.launch) as RuntimeLaunchContext;
    if (change === "missing") launch.materials.pop();
    else launch.materials[2].reference = launch.materials[1].reference;
    launch.launchContextHash = launchContextHash(launch);
    const context = { ...f.context, launch: parseRuntimeLaunchContext(toJson(RuntimeLaunchContextSchema, launch), f.context.config),
      binding: { ...f.context.binding, launchContextHash: launch.launchContextHash } };
    reject(f.bytes(), context);
  }
});
test("duplicate keys, escaped duplicates, trailing JSON and invalid UTF8 refuse", () => {
  const f = profileFixture(), text = f.bytes().toString();
  for (const value of [text.replace('"port":8080', '"port":8080,"port":8080'),
    text.replace('"port":8080', '"port":8080,"p\\u006frt":8080'), `${text}{}`, text.replace('"v1"', '"\\ud800"')]) reject(Buffer.from(value), f.context);
  for (const bytes of [Buffer.alloc(0), Buffer.alloc(262145, 32), Buffer.from([255]), Buffer.concat([Buffer.from([239, 187, 191]), f.bytes()])]) reject(bytes, f.context);
});
test("owned input/output copies, rotation pins and passive native byte views", () => {
  const f = profileFixture(); f.value.profile.managed.ingress.edge_certificate_sha256.push("b".repeat(64));
  const bytes = f.bytes(); let hooks = 0;
  Object.defineProperty(bytes, "byteLength", { get() { hooks++; throw new Error("CANARY"); } });
  Object.defineProperty(bytes, "length", { get() { hooks++; throw new Error("CANARY"); } });
  Object.defineProperty(bytes, "valueOf", { value() { hooks++; throw new Error("CANARY"); } });
  const result = parseManagedIngressProfile(bytes, f.context);
  assert.deepEqual(result, f.value); assert.equal(hooks, 0);
  Uint8Array.prototype.fill.call(bytes, 0); f.value.profile.managed.ingress.edge_certificate_sha256[0] = "c".repeat(64);
  assert.equal(result.profile.managed.ingress.edge_certificate_sha256[0], "a".repeat(64));
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.profile.managed.ingress.edge_certificate_sha256));
});
test("active context/byte proxies refuse without invoking hooks", () => {
  const f = profileFixture(); let hooks = 0;
  const context = { ...f.context };
  Object.defineProperty(context, "binding", { enumerable: true, get() { hooks++; throw new Error("CANARY"); } });
  reject(f.bytes(), context);
  reject(new Proxy(f.bytes(), { get() { hooks++; throw new Error("CANARY"); } }), f.context);
  reject(f.bytes(), new Proxy(f.context, { ownKeys() { hooks++; throw new Error("CANARY"); } }));
  reject(new Uint8Array(new SharedArrayBuffer(16)), f.context);
  assert.equal(hooks, 0);
});

for (const [field, value] of [["schema_version", "3e0"], ["port", "8080.0"]]) {
  test(`original ${field} numeric token must match Rust integer syntax`, () => {
    const f = profileFixture(), original = field === "port" ? "8080" : "3";
    reject(Buffer.from(f.bytes().toString().replace(`"${field}":${original}`, `"${field}":${value}`)), f.context);
  });
}
