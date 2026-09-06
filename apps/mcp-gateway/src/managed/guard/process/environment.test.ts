import assert from "node:assert/strict";
import { test } from "node:test";
import { guardEnvironment } from "./environment.js";
import { setup } from "./fixture.js";
import { startGuard } from "./job.js";

test("guard environment captures exact separate guard metadata, not gateway bootstrap", () => {
  const s = setup(), result = guardEnvironment({ ...s.env, PATH: "/usr/bin", HOSTNAME: "guard-test" });
  assert.equal(result.manifest, s.manifest); assert.equal(result.expected.installationId, s.env.APEX_INSTALLATION_ID);
  assert(Object.isFrozen(result)); assert(Object.isFrozen(result.expected));
});
for (const key of Object.keys(setup().env)) test(`guard requires own ${key}`, () => {
  const s = setup(), env: NodeJS.ProcessEnv = { ...s.env }; delete env[key]; assert.throws(() => guardEnvironment(env));
});
for (const key of ["NODE_OPTIONS", "NODE_EXTRA_CA_CERTS", "NODE_TLS_REJECT_UNAUTHORIZED", "SSL_CERT_FILE", "SSL_CERT_DIR",
  "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "NODE_USE_ENV_PROXY", "OPENSSL_CONF", "OPENSSL_MODULES",
  "APEX_MCP_MANAGED_BOOTSTRAP", "APEX_RUNTIME_CONFIG_FILE", "APEX_TOOL_SECRET_REFERENCES", "apex_installation_id"])
  test(`guard forbids ${key} even when empty`, () => {
    const s = setup(); assert.throws(() => guardEnvironment({ ...s.env, [key]: "" }));
    assert.throws(() => guardEnvironment({ ...s.env, [key.toLowerCase()]: "" }));
  });
test("guard refuses missing/wrong modes and malformed identity/hash", () => {
  const s = setup();
  for (const change of [{ NODE_ENV: "development" }, { HOME: "/tmp" }, { APEX_MCP_PROFILE: "managed" },
    { APEX_MCP_GUARD_BOOTSTRAP: "sealed-stage-v2" }, { APEX_INSTALLATION_ID: "bad" },
    { APEX_STAGE_MANIFEST_SHA256: "A".repeat(64) }, { APEX_NETWORK_BINDING_SHA256: "a".repeat(63) },
    { APEX_NETWORK_TOPOLOGY_SHA256: "a".repeat(64) + "\n" }]) assert.throws(() => guardEnvironment({ ...s.env, ...change }));
});
test("guard rejects case aliases for fixed environment fields", () => {
  for (const key of ["home", "node_env", "apex_mcp_profile"])
    assert.throws(() => guardEnvironment({ ...setup().env, [key]: "alternate" }));
});
test("guard bounds environment key and value lengths and total captured entries", () => {
  for (const extra of [{ ["X".repeat(129)]: "x" }, { PATH: "x".repeat(16385) },
    Object.fromEntries(Array.from({ length: 8 }, (_, i) => [`FIELD_${i}`, "x".repeat(10000)]))])
    assert.throws(() => guardEnvironment({ ...setup().env, ...extra }));
});
test("guard refuses passive environment boundary violations without executing hooks", () => {
  const s = setup(); let calls = 0;
  const cases = [new Proxy(s.env, { ownKeys() { calls++; return []; } }), Object.create(s.env),
    Object.defineProperty({ ...s.env }, "APEX_INSTALLATION_ID", { get() { calls++; return s.env.APEX_INSTALLATION_ID; } }),
    Object.defineProperty({ ...s.env }, "PATH", { get() { calls++; return "x"; } }), { ...s.env, [Symbol("x")]: "x" },
    { ...s.env, PATH: undefined }, { ...s.env, ...Object.fromEntries(Array.from({ length: 257 }, (_, i) => [`FIELD_${i}`, "x"])) }];
  for (const env of cases) assert.throws(() => guardEnvironment(env)); assert.equal(calls, 0);
});
test("invalid process options have no byte-reader or listener effect", async () => {
  const s = setup(); let called = 0;
  for (const options of [{ ...s.options, reader: "override" }, { ...s.options, onFatal: null },
    Object.defineProperty({ ...s.options }, "env", { get() { called++; return s.env; } }),
    new Proxy(s.options, { get() { called++; throw new Error(); } })]) {
    const owner = startGuard(options as typeof s.options, s.deps, s.gate);
    await assert.rejects(owner.result); await owner.closed;
  }
  assert.equal(called, 0); assert.equal(s.state().loads, 0); assert.equal(s.relays.length, 0);
});
