import assert from "node:assert/strict";
import test from "node:test";
import { parseSealedStageEnvironment } from "./environment.js";
import { startOwnedStage } from "./stage-owner/job.js";
import { ownerFixture } from "./stage-owner/fixture.js";
import { disposeStageOwner } from "./stage-owner.js";
import { parseManagedStageDocuments } from "./stage-documents.js";

function fixture() {
  const f = ownerFixture();
  const env: NodeJS.ProcessEnv = { ...f.env, APEX_MCP_MANAGED_BOOTSTRAP: "sealed-stage-v2",
    APEX_MCP_NETWORK_PROFILE: "isolated-bridge-v1", APEX_MCP_GUARD_ADDRESS: "10.96.0.3",
    APEX_MCP_NETWORK_BINDING_SHA256: "b".repeat(64) };
  return { ...f, env };
}
const expected = Object.freeze({ profile: "isolated-bridge-v1", guardAddress: "10.96.0.3",
  guardPort: 18080, gatewayAddress: "10.96.0.2", bindingSha256: "b".repeat(64) });

test("v2 explicitly captures immutable agent-selected network metadata", () => {
  const f = fixture(), selection = parseSealedStageEnvironment(f.env);
  assert.deepEqual(selection, { ...f.selection, network: expected });
  assert(Object.isFrozen(selection));
  assert(Object.isFrozen(selection.network));
});

test("v2 owner publishes original capture without widening the document or reader contracts", async () => {
  const f = fixture(), h = startOwnedStage(f, f.load, f.time, f.gate);
  f.env.APEX_MCP_GUARD_ADDRESS = "10.96.0.11";
  f.env.APEX_MCP_NETWORK_BINDING_SHA256 = "c".repeat(64);
  f.env.APEX_MCP_MANAGED_BOOTSTRAP = "sealed-stage-v1";
  f.result.resolve(f.material); f.closed.resolve();
  const owner = await h.result;
  assert.deepEqual(owner.network, expected);
  assert(Object.isFrozen(owner.network));
  assert.deepEqual(Object.keys(f.options()).sort(), ["expectedManifestSha256", "monotonicNowNs", "onFatal", "toolSecretReferences"]);
  assert.deepEqual(owner.documents.binding.installationId, f.selection.installationId);
  disposeStageOwner(owner); await h.closed;
  assert.equal(f.counts.disposals, 1);
});

const reject = (env: NodeJS.ProcessEnv) => assert.throws(() => parseSealedStageEnvironment(env), error =>
  error instanceof Error && error.message === "managed stage environment rejected" && error.cause === undefined);
const extraKeys = ["APEX_MCP_NETWORK_PROFILE", "APEX_MCP_GUARD_ADDRESS", "APEX_MCP_NETWORK_BINDING_SHA256"];

for (const key of extraKeys) {
  test(`v2 ${key} is required, passive and never accepted in v1`, async () => {
    const f = fixture();
    for (const value of [undefined, "", "CANARY", "CANARY\n"]) reject({ ...f.env, [key]: value });
    const missing = { ...f.env }; delete missing[key]; reject(missing);
    const inherited = { ...f.env }; delete inherited[key]; Object.setPrototypeOf(inherited, { [key]: f.env[key] }); reject(inherited);
    const hidden = { ...f.env }; Object.defineProperty(hidden, key, { enumerable: false }); reject(hidden);
    for (const value of [undefined, "", f.env[key]]) reject({ ...ownerFixture().env, [key]: value });
    let hooks = 0;
    const active = { ...f.env }; Object.defineProperty(active, key, { get() { hooks++; throw new Error("CANARY"); } });
    reject(active); assert.equal(hooks, 0);
    const h = startOwnedStage({ ...f, env: missing }, f.load, f.time, f.gate);
    await assert.rejects(h.result, /managed stage bootstrap rejected/); await h.closed;
    assert.equal(f.counts.loads, 0); assert.equal(f.counts.fatals, 0);
  });
}

test("v2 validates every /29 slot offset and private-pool boundary without DNS", () => {
  const f = fixture();
  for (const prefix of ["10.0.0", "10.255.255", "172.16.0", "172.31.255", "192.168.0", "192.168.255"]) {
    for (let last = 0; last < 256; last++) {
      const guardAddress = `${prefix}.${last}`, env = { ...f.env, APEX_MCP_GUARD_ADDRESS: guardAddress };
      if (last % 8 !== 3) reject(env);
      else assert.deepEqual(parseSealedStageEnvironment(env).network,
        { ...expected, guardAddress, gatewayAddress: `${prefix}.${last - 1}` });
    }
  }
});

for (const value of ["127.0.0.3", "0.0.0.3", "169.254.0.3", "224.0.0.3", "100.64.0.3", "8.8.8.3", "172.15.0.3",
  "172.32.0.3", "192.167.0.3", "192.169.0.3", "10.256.0.3", "10.0.0.259", "010.0.0.3", "10.00.0.3", "10.0.0.03",
  "0x0a.0.0.3", "167772163", "10.3", "10.0.3", "10.0.0.3.", "10.0.0.3:18080", "http://10.0.0.3", "guard.local",
  "::1", "::ffff:10.0.0.3", "[::ffff:a00:3]", "10.0.0.3%eth0", " 10.0.0.3", "10.0.0.3\n", "10.0.0.3\u0000"]) {
  test(`v2 refuses noncanonical or out-of-profile address ${JSON.stringify(value)}`, () =>
    reject({ ...fixture().env, APEX_MCP_GUARD_ADDRESS: value }));
}

test("v2 binding is a bounded canonical digest, not an authority credential", () => {
  const f = fixture();
  for (const value of ["B".repeat(64), "b".repeat(63), "b".repeat(65), `${"b".repeat(64)}\n`, "sha256:" + "b".repeat(64)])
    reject({ ...f.env, APEX_MCP_NETWORK_BINDING_SHA256: value });
  for (const value of ["b".repeat(64), "0".repeat(64)])
    assert.equal(parseSealedStageEnvironment({ ...f.env, APEX_MCP_NETWORK_BINDING_SHA256: value }).network?.bindingSha256, value);
  // Shape acceptance, including any exact hash, never authenticates an instance.
  assert.throws(() => parseManagedStageDocuments(f.stage, parseSealedStageEnvironment(f.env)), /managed stage documents rejected/);
});

test("v2 permits no alternate ports, ambient network overrides or unknown modes", () => {
  const f = fixture();
  for (const key of ["APEX_MCP_GUARD_PORT", "APEX_MCP_GATEWAY_ADDRESS", "APEX_MCP_LISTEN_HOST", "apex_mcp_guard_address",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "NODE_OPTIONS", "NODE_USE_ENV_PROXY", "SSL_CERT_FILE"]) {
    for (const value of [undefined, "", "CANARY"]) reject({ ...f.env, [key]: value });
  }
  for (const value of ["sealed-stage-v3", "sealed-stage-v2\n", "SEALED-STAGE-V2", "", undefined])
    reject({ ...f.env, APEX_MCP_MANAGED_BOOTSTRAP: value });
  for (const value of ["isolated-bridge-v2", "isolated-bridge-v1\n", "", undefined])
    reject({ ...f.env, APEX_MCP_NETWORK_PROFILE: value });
});

test("v2 still refuses revoked proxies and env accessors without invoking hooks", async () => {
  const f = fixture(); let hooks = 0;
  const proxy = new Proxy(f.env, { ownKeys() { hooks++; throw new Error("CANARY"); } }); reject(proxy);
  const revoked = Proxy.revocable(f.env, {}); revoked.revoke(); reject(revoked.proxy);
  const h = startOwnedStage({ ...f, env: proxy }, f.load, f.time, f.gate);
  assert.equal(hooks, 0); assert.equal(f.counts.loads, 0);
  await Promise.all([assert.rejects(h.result, /managed stage bootstrap rejected/), h.closed]);
});
