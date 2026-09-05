import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { RuntimeConfigurationSchema } from "@apex/contracts";
import { fromJson, type JsonObject, type JsonValue } from "@bufbuild/protobuf";
import { launchContextHash, parseRuntimeLaunchContext, type ReadonlyRuntimeLaunchContext } from "../launch-context.js";
import type { ReadonlyRuntimeConfiguration } from "../runtime-config.js";
import { config, generated, rejectsSafely, resign, source } from "./test-support.js";
import { resign as resignConfig, setField, source as configSource } from "../runtime-config/test-support.js";

test("original-text duplicate, escaped and protobuf alias keys cannot be hidden", () => {
  const text = JSON.stringify(source());
  for (const input of [
    text.replace('"schemaVersion":1', '"schemaVersion":2,"schemaVersion":1'),
    text.replace('"schemaVersion":1', String.raw`"schema\u0056ersion":1,"schemaVersion":1`),
    text.replace('"fencingToken":"9007199254740993"', '"fencing_token":"7","fencingToken":"9007199254740993"'),
    text.replace('"port":8081', '"port":8080,"port":8081'),
    text.replace('"version":"v1"', '"version":"LAUNCH_CANARY","version":"v1"'),
  ]) {
    assert.notEqual(input, text);
    rejectsSafely(() => parseRuntimeLaunchContext(input, config));
  }
});
for (const pointer of ["/unknown", "/target/unknown", "/health/host", "/materials/0/rawSecret"]) {
  test(`unknown typed field rejected with fixed error: ${pointer}`, () => {
    const input = source();
    setField(input, pointer, "LAUNCH_CANARY");
    rejectsSafely(() => parseRuntimeLaunchContext(input, config));
    rejectsSafely(() => parseRuntimeLaunchContext(JSON.stringify(input), config));
  });
}
for (const value of [0, 9007199254740992, "01", "-1", "+1", "1e3", " 1", "1\n", "18446744073709551616"]) {
  test(`noncanonical or overflowing fence rejected: ${JSON.stringify(value)}`, () => {
    const input = source();
    setField(input, "/target/fencingToken", value);
    rejectsSafely(() => parseRuntimeLaunchContext(JSON.stringify(input), config));
  });
}
for (const role of [999, -1, "RUNTIME_MATERIAL_ROLE_FUTURE", "1"]) {
  test(`unknown material role rejected: ${role}`, () => {
    const input = source();
    setField(input, "/materials/1/role", role);
    rejectsSafely(() => parseRuntimeLaunchContext(input, config));
  });
}
test("invalid UTF-16 is rejected in raw text, escaped text, object values and keys", () => {
  for (const value of ["\ud800", "\udfff", "\ud800x", "x\udfff"]) {
    const input = source();
    input.authorityProfileVersion = value;
    rejectsSafely(() => parseRuntimeLaunchContext(input, config));
    rejectsSafely(() => parseRuntimeLaunchContext(JSON.stringify(input), config));
    const raw = JSON.stringify(source()).replace('"authorityProfileVersion":"v1"', `"authorityProfileVersion":"${value}"`);
    rejectsSafely(() => parseRuntimeLaunchContext(raw, config));
    rejectsSafely(() => parseRuntimeLaunchContext({ ...source(), [value]: "x" }, config));
    const context = generated();
    context.authorityProfileVersion = value;
    rejectsSafely(() => launchContextHash(context));
  }
});

test("raw launch text includes whitespace in the inclusive 16 KiB UTF-8 bound", () => {
  const text = JSON.stringify(source());
  const exact = text + " ".repeat(16384 - Buffer.byteLength(text));
  assert.doesNotThrow(() => parseRuntimeLaunchContext(exact, config));
  rejectsSafely(() => parseRuntimeLaunchContext(exact + " ", config));
});
test("raw launch byte bound precedes JSON parsing, including multibyte text", context => {
  for (const input of [" ".repeat(16385), '"' + "雪".repeat(6000) + '"']) {
    let parsed = 0;
    const original = JSON.parse;
    const probe = context.mock.method(JSON, "parse", (value: string) => {
      if (value === input) { parsed++; throw new Error("LAUNCH_CANARY"); }
      return original(value);
    });
    try {
      rejectsSafely(() => parseRuntimeLaunchContext(input, config));
      assert.equal(parsed, 0, "raw oversized text must not reach the JSON parser");
    } finally { probe.mock.restore(); }
  }
});
test("hash helper enforces final generated ProtoJSON 16 KiB bound, including omitted defaults", () => {
  const context = generated();
  context.authorityProfileRef = "";
  // Empty field is omitted; adding the field costs its JSON key, colon, quotes and comma.
  const empty = JSON.parse(JSON.stringify(source())) as JsonObject;
  delete empty.authorityProfileRef;
  const available = 16384 - Buffer.byteLength(JSON.stringify(empty)) - '"authorityProfileRef":"",'.length;
  context.authorityProfileRef = "p".repeat(available);
  assert.match(launchContextHash(context), /^[0-9a-f]{64}$/);
  context.authorityProfileRef += "p";
  rejectsSafely(() => launchContextHash(context));
  // Shape-only hashing is not semantic acceptance of this overlong profile.
});
test("object/generated escaped output is bounded even when compact raw values fit", () => {
  const input = source();
  input.authorityProfileRef = "\u0000".repeat(3000);
  assert.ok(JSON.stringify(input).length > 16384);
  rejectsSafely(() => parseRuntimeLaunchContext(input, config));
  rejectsSafely(() => launchContextHash(generated(input)));
});

/** Spy only at the real codec's serialization boundary, before a shared graph
 * could amplify. A RED run cannot stringify the unsafe root through this seam. */
function beforeSerialization(context: TestContext, input: unknown): void {
  let serialized = 0;
  const stringify = JSON.stringify;
  const probe = context.mock.method(JSON, "stringify", (value: unknown) => {
    if (value === input) { serialized++; throw new Error("LAUNCH_CANARY"); }
    return stringify(value);
  });
  try {
    rejectsSafely(() => parseRuntimeLaunchContext(input, config));
    assert.equal(serialized, 0);
  } finally { probe.mock.restore(); }
}
test("object preflight rejects amplified shared values, keys and escaped data before serialization", context => {
  for (const value of ["x".repeat(16384), { ["k".repeat(16384)]: "" }, "\u0000".repeat(4096)]) {
    const input = source();
    input.materials = Array(17).fill(value);
    beforeSerialization(context, input);
  }
});
test("generated hash object amplification is rejected before encoding", context => {
  const input = generated();
  input.materials = Array(17).fill({ ...input.materials[0], reference: "x".repeat(16384) });
  let serialized = false;
  let caught: unknown;
  // The generated codec creates a new JSON tree. Observe every stringify during
  // this isolated hash invocation and stop before amplified serialization.
  const probe = context.mock.method(JSON, "stringify", () => {
    serialized = true;
    throw new Error("LAUNCH_CANARY");
  });
  try { launchContextHash(input); }
  catch (error: unknown) { caught = error; }
  finally { probe.mock.restore(); }
  // Diagnostic inspection itself stringifies the error; it is outside the spy.
  rejectsSafely(() => { if (caught !== undefined) throw caught; });
  assert.equal(serialized, false, "amplified generated input must fail before any codec serialization");
});

function activeValues(onExecution: () => never): unknown[] {
  const accessor = Object.defineProperty({}, "schemaVersion", { enumerable: true, get: onExecution });
  const nested = source();
  nested.health = Object.defineProperty({}, "port", { enumerable: true, get: onExecution });
  const array = source();
  const list: unknown[] = [];
  Object.defineProperty(list, 0, { enumerable: true, get: onExecution });
  array.materials = list as JsonValue[];
  return [
    accessor, nested, array,
    Object.defineProperty(source(), "toJSON", { value: onExecution }),
    new Proxy(source(), { get: onExecution, getPrototypeOf: onExecution, ownKeys: onExecution }),
    { ...source(), target: new Proxy({}, { get: onExecution, ownKeys: onExecution }) },
  ];
}
test("active launch inputs never execute accessors, proxies or serialization hooks", () => {
  let executed = 0;
  const canary = (): never => { executed++; throw new Error("LAUNCH_CANARY"); };
  for (const input of activeValues(canary)) rejectsSafely(() => parseRuntimeLaunchContext(input, config));
  assert.equal(executed, 0);
});
test("active supplied configurations never execute getters, proxies or hooks", () => {
  let executed = 0;
  const canary = (): never => { executed++; throw new Error("LAUNCH_CANARY"); };
  const accessor = Object.defineProperty(structuredClone(config), "runtimeManifestHash", { enumerable: true, get: canary });
  const nested = structuredClone(config);
  Object.defineProperty(nested.spec!, "ingress", { enumerable: true, get: canary });
  const hook = Object.defineProperty(structuredClone(config), "toJSON", { value: canary });
  const proxy = new Proxy(config, { get: canary, ownKeys: canary, getPrototypeOf: canary });
  for (const untrusted of [accessor, nested, hook, proxy]) {
    rejectsSafely(() => parseRuntimeLaunchContext(source(), untrusted));
  }
  assert.equal(executed, 0);
});
test("forged but re-signed configuration cannot bypass the existing semantic parser", () => {
  for (const [pointer, value] of [["/spec/runtimeProfile/rootless", false], ["/secretRefs", []]] as const) {
    const input = configSource();
    setField(input, pointer, value as JsonValue);
    const forged = fromJson(RuntimeConfigurationSchema, resignConfig(input));
    const launch = source();
    launch.runtimeManifestHash = forged.runtimeManifestHash;
    rejectsSafely(() => parseRuntimeLaunchContext(resign(launch), forged));
  }
});
test("hidden fields, cycles, nonplain prototypes and malformed generated config fail safely", () => {
  const cycle: Record<string, unknown> = { ...source() };
  cycle.self = cycle;
  const sparse = source();
  sparse.materials = Array(2) as JsonValue[];
  for (const input of [
    cycle, sparse, new Date(), Object.assign(Object.create({ inherited: true }), source()),
    Object.defineProperty(source(), "hidden", { value: "LAUNCH_CANARY" }),
    { ...source(), [Symbol("LAUNCH_CANARY")]: "hidden" }, undefined, null, [],
  ]) rejectsSafely(() => parseRuntimeLaunchContext(input, config));
  const hiddenConfig = Object.defineProperty(structuredClone(config), "hidden", { value: "LAUNCH_CANARY" });
  for (const untrusted of [hiddenConfig, { ...config, surprise: "LAUNCH_CANARY" }, { ...config, generation: 1 }]) {
    rejectsSafely(() => parseRuntimeLaunchContext(source(), untrusted as ReadonlyRuntimeConfiguration));
  }
});
test("hash helper rejects active/generated-object extras before codec can erase them", () => {
  let executed = 0;
  const canary = (): never => { executed++; throw new Error("LAUNCH_CANARY"); };
  const accessor = Object.defineProperty(generated(), "imageRef", { enumerable: true, get: canary });
  const nested = generated();
  Object.assign(nested.materials[0], { unknown: "LAUNCH_CANARY" });
  const hidden = Object.defineProperty(generated(), "hidden", { value: "LAUNCH_CANARY" });
  const cycle = generated();
  Object.assign(cycle, { self: cycle });
  for (const input of [
    accessor, nested, hidden, cycle, new Proxy(generated(), { get: canary, ownKeys: canary }),
    { ...generated(), unknown: "LAUNCH_CANARY" }, { ...generated(), schemaVersion: 1.5 },
    { ...generated(), target: { ...generated().target, generation: 1 } },
  ]) rejectsSafely(() => launchContextHash(input as ReadonlyRuntimeLaunchContext));
  assert.equal(executed, 0);
});
test("a caller can self-sign a shaped launch; this parser cannot authenticate it", () => {
  const input = source();
  input.authorityProfileRef = "untrusted-profile-reference";
  setField(input, "/target/fencingToken", "42");
  setField(input, "/materials/1/version", "untrusted-version");
  const parsed = parseRuntimeLaunchContext(resign(input), config);
  assert.equal(parsed.authorityProfileRef, "untrusted-profile-reference");
  assert.equal(parsed.target?.fencingToken, 42n);
  assert.equal(parsed.materials[1].version, "untrusted-version");
  // No provenance, current lease, material existence or readiness assertion.
});

test("raw character ceiling rejects before even scanning oversized UTF-8", context => {
  const input = " ".repeat(16385);
  let measured = 0;
  const original = Buffer.byteLength;
  const probe = context.mock.method(Buffer, "byteLength", (...args: Parameters<typeof original>) => {
    if (args[0] === input) measured++;
    return original(...args);
  });
  try {
    rejectsSafely(() => parseRuntimeLaunchContext(input, config));
    assert.equal(measured, 0);
  } finally { probe.mock.restore(); }
});

test("config digest remains exactly 64 lowercase hex even if a re-signed config carries a line ending", () => {
  const input = configSource();
  input.configHash = `${config.configHash}\n`;
  const untrusted = fromJson(RuntimeConfigurationSchema, resignConfig(input));
  const launch = source();
  launch.configHash = untrusted.configHash;
  launch.runtimeManifestHash = untrusted.runtimeManifestHash;
  rejectsSafely(() => parseRuntimeLaunchContext(resign(launch), untrusted));
});
