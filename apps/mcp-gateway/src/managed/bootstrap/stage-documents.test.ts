import assert from "node:assert/strict";
import test from "node:test";
import { parseManagedStageDocuments } from "./stage-documents.js";
import { documentsFixture } from "./stage-documents-fixture.js";
import { encodeJson, RuntimeConfigurationSchema, RuntimeLaunchContextSchema, type RuntimeConfiguration, type RuntimeLaunchContext } from "@apex/contracts";
import { launchContextHash } from "../launch-context.js";

test("all four stage documents bind to the original selected deployment", () => {
  const f = documentsFixture();
  assert.deepEqual(parseManagedStageDocuments(f.stage, f.selection), {
    config: f.context.config, launch: f.context.launch, binding: f.context.binding,
    authority: f.value, tools: f.tools,
  });
});

function reject(f: ReturnType<typeof documentsFixture>) {
  assert.throws(() => parseManagedStageDocuments(f.stage, f.selection), error => {
    assert.ok(error instanceof Error); assert.equal(error.message, "managed stage documents rejected");
    assert.equal(error.cause, undefined); return true;
  });
}
for (const key of ["installation_id", "workspace_id", "namespace_id", "proxy_id", "revision_id", "config_hash", "host_policy_version"]) {
  test(`tool binding ${key} must match the same launch/profile`, () => {
    const f = documentsFixture();
    (f.tools as Record<string, unknown>)[key] = ["workspace_id", "namespace_id", "host_policy_version"].includes(key) ? "other" :
      key === "config_hash" ? "d".repeat(64) : "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e99";
    f.stage.files["tool-bindings.json"] = Buffer.from(JSON.stringify(f.tools)); f.reseal(); reject(f);
  });
}
test("every tool document and entry field is exact, required and bounded", () => {
  for (const entry of [false, true]) {
    const keys = Object.keys(entry ? documentsFixture().tools.entries[0] : documentsFixture().tools);
    for (const key of [...keys, "extra"]) {
      const f = documentsFixture(), object = (entry ? f.tools.entries[0] : f.tools) as Record<string, unknown>;
      if (key === "extra") object.extra = "CANARY"; else delete object[key];
      f.stage.files["tool-bindings.json"] = Buffer.from(JSON.stringify(f.tools)); f.reseal(); reject(f);
    }
  }
  for (const key of ["catalog_version", "deployment_bindings_version"]) {
    for (const value of ["", "a".repeat(129), "a..b", [], null]) {
      const f = documentsFixture(); (f.tools as Record<string, unknown>)[key] = value;
      f.stage.files["tool-bindings.json"] = Buffer.from(JSON.stringify(f.tools)); f.reseal(); reject(f);
    }
  }
});
for (const [key, value] of [["reference", "secret://other/token"], ["reference", ["secret://tool/token"]],
  ["version", ""], ["version", "a".repeat(129)], ["filename", "../canary"], ["filename", `tool-${"f".repeat(64)}`]] as const) {
  test(`tool entry rejects malformed or substituted ${key}`, () => {
    const f = documentsFixture(); (f.tools.entries[0] as Record<string, unknown>)[key] = value;
    f.stage.files["tool-bindings.json"] = Buffer.from(JSON.stringify(f.tools)); f.reseal(); reject(f);
  });
}
test("duplicate/missing/extra references and positional documents cannot select tools", () => {
  for (const change of ["empty", "duplicate", "array", "schema", "missing-file", "extra-file"]) {
    const f = documentsFixture();
    if (change === "empty") f.tools.entries = [];
    if (change === "duplicate") f.tools.entries.push({ ...f.tools.entries[0] });
    if (change === "schema") f.tools.schema_version = 2;
    if (change === "missing-file") delete f.stage.files[f.tools.entries[0].filename];
    if (change === "extra-file") f.stage.files["tool-extra"] = Buffer.from("CANARY");
    f.stage.files["tool-bindings.json"] = Buffer.from(JSON.stringify(change === "array" ? Object.values(f.tools) : f.tools));
    f.reseal(); reject(f);
  }
});
test("handoff references and manifest hash cannot drift from the loaded documents", () => {
  for (const kind of ["hash", "scope", "refs", "duplicate-refs", "bad-ref"]) {
    const f = documentsFixture();
    if (kind === "hash") f.selection.expectedManifestSha256 = "d".repeat(64);
    if (kind === "scope") f.selection.installationId = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e99";
    if (kind === "refs") f.selection.toolSecretReferences = [];
    if (kind === "duplicate-refs") f.selection.toolSecretReferences.push(f.selection.toolSecretReferences[0]);
    if (kind === "bad-ref") f.selection.toolSecretReferences = ["CANARY"];
    reject(f);
  }
});
test("original duplicate keys, integer syntax, Unicode and document caps survive composition", () => {
  for (const name of ["runtime-revision.json", "launch-context.json", "authority-profile.json", "tool-bindings.json"]) {
    const f = documentsFixture(), original = f.stage.files[name];
    for (const bytes of [Buffer.from([255]), Buffer.from(`${original.toString()}{}`), Buffer.alloc(name === "runtime-revision.json" ? 262145 : 65537, 32)]) {
      f.stage.files[name] = bytes; f.reseal(); reject(f);
    }
  }
  for (const suffix of ['"schema_version":1,"schema_version":1', '"schema_version":1e0', '"schema_version":1.0']) {
    const f = documentsFixture(); f.stage.files["tool-bindings.json"] = Buffer.from(f.stage.files["tool-bindings.json"].toString().replace('"schema_version":1', suffix));
    f.reseal(); reject(f);
  }
});
test("recomputed launch cannot substitute authority-profile selection", () => {
  const f = documentsFixture(), launch = structuredClone(f.context.launch) as RuntimeLaunchContext;
  launch.authorityProfileRef = "other"; launch.launchContextHash = launchContextHash(launch);
  f.stage.files["launch-context.json"] = Buffer.from(JSON.stringify(encodeJson(RuntimeLaunchContextSchema, launch)));
  f.reseal(); reject(f);
});
test("input byte hooks and active records cannot be invoked by the decoder", () => {
  let hooks = 0;
  const f = documentsFixture(), bytes = f.stage.files["runtime-revision.json"];
  Object.defineProperty(bytes, "length", { get() { hooks++; throw new Error("CANARY"); } });
  Object.defineProperty(bytes, "valueOf", { value() { hooks++; throw new Error("CANARY"); } });
  const result = parseManagedStageDocuments(f.stage, f.selection);
  assert.deepEqual(result.config, f.context.config);
  const getter = documentsFixture(); Object.defineProperty(getter.stage.files, "governance-key", {
    enumerable: true, get() { hooks++; throw new Error("CANARY"); } }); reject(getter);
  const proxy = documentsFixture(); proxy.stage.files = new Proxy(proxy.stage.files, { ownKeys() { hooks++; throw new Error("CANARY"); } }); reject(proxy);
  const selection = documentsFixture(); Object.defineProperty(selection.selection, "installationId", {
    enumerable: true, get() { hooks++; throw new Error("CANARY"); } }); reject(selection);
  assert.equal(hooks, 0);
});
test("decoder output is metadata only, deeply frozen and isolated from later stage mutations", () => {
  const f = documentsFixture(), result = parseManagedStageDocuments(f.stage, f.selection);
  for (const bytes of Object.values(f.stage.files)) bytes.fill(0);
  assert.equal(result.binding.generation, 9007199254740993n);
  assert.deepEqual(result.tools.entries, f.tools.entries);
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.tools.entries[0]));
  assert.ok(!JSON.stringify(result.tools).includes("synthetic tool credential bytes"));
  const config = encodeJson(RuntimeConfigurationSchema, result.config as RuntimeConfiguration);
  assert.ok(config);
});
