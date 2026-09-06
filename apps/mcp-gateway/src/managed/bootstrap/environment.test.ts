import assert from "node:assert/strict";
import test from "node:test";
import { parseSealedStageEnvironment } from "./environment.js";
import { options as stageOptions } from "../stage-reader/validation.js";

function fixture(): NodeJS.ProcessEnv {
  return { NODE_ENV: "production", HOME: "/tmp/apex", APEX_MCP_PROFILE: "managed", APEX_MCP_GOVERNANCE_MODE: "live",
    APEX_RUNTIME_CONFIG_FILE: "/apex/runtime/runtime-revision.json", APEX_RUNTIME_LAUNCH_FILE: "/apex/runtime/launch-context.json",
    APEX_MCP_MANAGED_BOOTSTRAP: "sealed-stage-v1", APEX_INSTALLATION_ID: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01",
    APEX_STAGE_MANIFEST_SHA256: "a".repeat(64), APEX_TOOL_SECRET_REFERENCES: '["secret://tool/a-token","secret://tool/z-token"]' };
}
test("fixed agent handoff supplies immutable nonsecret stage-reader selection", () => {
  assert.deepEqual(parseSealedStageEnvironment(fixture()), {
    installationId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01", expectedManifestSha256: "a".repeat(64),
    toolSecretReferences: ["secret://tool/a-token", "secret://tool/z-token"],
  });
});

function reject(env: NodeJS.ProcessEnv) {
  assert.throws(() => parseSealedStageEnvironment(env), error => {
    assert.ok(error instanceof Error); assert.equal(error.message, "managed stage environment rejected");
    assert.equal(error.cause, undefined); return true;
  });
}
for (const key of Object.keys(fixture())) {
  test(`${key} must be an exact present fixed value`, () => {
    const env = fixture(); delete env[key]; reject(env);
    for (const value of [undefined, "", " CANARY", "CANARY\n"]) reject({ ...fixture(), [key]: value });
  });
}
for (const key of ["APEX_MCP_PROXY_REVISION_CONFIG", "APEX_MCP_PROXY_REVISION_CONFIG_FILE", "APEX_MCP_LISTEN_HOST", "APEX_MCP_LISTEN_PORT",
  "APEX_UNKNOWN", "apex_mcp_profile", "NODE_OPTIONS", "NODE_EXTRA_CA_CERTS", "NODE_TLS_REJECT_UNAUTHORIZED", "SSL_CERT_FILE", "SSL_CERT_DIR",
  "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "NODE_USE_ENV_PROXY", "OPENSSL_CONF", "OPENSSL_MODULES"]) {
  test(`ambient override ${key} refuses even if empty`, () => {
    for (const value of ["", "CANARY", undefined]) reject({ ...fixture(), [key]: value });
  });
}
for (const [name, raw] of [
  ["object", "{}"], ["null", "null"], ["scalar", '"secret://tool/a"'],
  ["duplicate", '["secret://tool/a","secret://tool/a"]'], ["unsorted", '["secret://tool/z","secret://tool/a"]'],
  ["whitespace", '[ "secret://tool/a" ]'], ["escaped", '["secret:\\/\\/tool/a"]'],
  ["surrogate", '["secret://tool/\\ud800"]'], ["array coercion", '[["secret://tool/a"]]'],
  ["plain", '["CANARY"]'], ["traversal", '["secret://tool/../escape"]'], ["empty segment", '["secret://tool//token"]'],
  ["unicode", '["secret://tool/é"]'], ["query", '["secret://tool/a?token=CANARY"]'], ["consecutive dots", '["secret://tool/a..b"]'],
  ["nonalphanumeric start", '["secret://-tool/a"]'], ["oversized reference", JSON.stringify([`secret://${"x".repeat(248)}`])],
  ["too many", JSON.stringify(Array.from({ length: 33 }, (_, i) => `secret://tool/a-${i}`))], ["oversized JSON", " ".repeat(8290)],
]) {
  test(`reference inventory rejects ${name}`, () => reject({ ...fixture(), APEX_TOOL_SECRET_REFERENCES: raw }));
}
test("UUID and hash stay primitive canonical exact-length strings", () => {
  for (const value of ["A".repeat(64), "a".repeat(63), "a".repeat(65), `${"a".repeat(64)}\n`]) reject({ ...fixture(), APEX_STAGE_MANIFEST_SHA256: value });
  for (const value of ["018f3d4a-8b9c-4d0e-8f12-3a4b5c6d7e01", "018F3D4A-8B9C-7D0E-8F12-3A4B5C6D7E01",
    "018f3d4a-8b9c-7d0e-0f12-3a4b5c6d7e01"]) reject({ ...fixture(), APEX_INSTALLATION_ID: value });
  reject({ ...fixture(), APEX_STAGE_MANIFEST_SHA256: ["a".repeat(64)] } as unknown as NodeJS.ProcessEnv);
});
test("zero and maximum inventories feed the exact existing stage reader inventory", () => {
  for (const count of [0, 32]) {
    const refs = Array.from({ length: count }, (_, i) => `secret://tool/${String(i).padStart(2, "0")}`.padEnd(256, "x"));
    const raw = JSON.stringify(refs);
    if (count === 32) assert.equal(raw.length, 8289);
    const result = parseSealedStageEnvironment({ ...fixture(), APEX_TOOL_SECRET_REFERENCES: raw });
    assert.deepEqual(result.toolSecretReferences, refs);
    const validated = stageOptions({ ...result, onFatal() { assert.fail("validation cannot call supervisor"); } });
    assert.equal(validated.names.size, 18 + count);
  }
});
test("copies are immutable and metadata getters/proxies are never invoked", () => {
  const env = fixture(), result = parseSealedStageEnvironment(env);
  env.APEX_TOOL_SECRET_REFERENCES = "[]"; env.APEX_STAGE_MANIFEST_SHA256 = "b".repeat(64);
  assert.equal(result.toolSecretReferences.length, 2); assert.equal(result.expectedManifestSha256, "a".repeat(64));
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.toolSecretReferences));
  let hooks = 0;
  for (const key of Object.keys(fixture())) {
    const env = fixture(); Object.defineProperty(env, key, { enumerable: true, get() { hooks++; throw new Error("CANARY"); } });
    reject(env);
  }
  reject(new Proxy(fixture(), { ownKeys() { hooks++; throw new Error("CANARY"); } }));
  const unrelated = fixture(); Object.defineProperty(unrelated, "UNRELATED", { get() { hooks++; throw new Error("CANARY"); } });
  assert.deepEqual(parseSealedStageEnvironment(unrelated), result);
  assert.equal(hooks, 0);
});
test("inherited values, hidden metadata and huge ambient environments refuse", () => {
  const env = Object.create(fixture()) as NodeJS.ProcessEnv; reject(env);
  const hidden = fixture(); Object.defineProperty(hidden, "APEX_INSTALLATION_ID", { enumerable: false }); reject(hidden);
  const oversized = fixture(); for (let i = 0; i < 247; i++) oversized[`OTHER_${i}`] = ""; reject(oversized);
});
