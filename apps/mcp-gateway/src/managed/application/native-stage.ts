// Unsigned disposable Linux fixture only. Generates synthetic staged material
// in a newly owned volume; never used by the production application.
import { mkdir, writeFile, chmod, chown, readdir } from "node:fs/promises";
import { X509Certificate } from "node:crypto";
import assert from "node:assert/strict";
import { decodeStrict, encodeJson, RuntimeConfigurationSchema, RuntimeLaunchContextSchema } from "@apex/contracts";
import { materialFixture } from "../bootstrap/runtime-materials/fixture.js";
import { disposeStageOwner } from "../bootstrap/stage-owner.js";
import { fixture as pki } from "../bootstrap/tls-role-fixture.js";
import { jwks, token } from "../bootstrap/inbound-verifier/fixture.js";
import { runtimeManifestHash } from "../runtime-config.js";
import { launchContextHash } from "../launch-context.js";

assert.equal(process.platform, "linux"); assert.equal(process.getuid!(), 0);
assert.deepEqual(await readdir("/fixture"), []);
const f = await materialFixture(f => {
  Object.assign(f.env, { APEX_MCP_MANAGED_BOOTSTRAP: "sealed-stage-v2", APEX_MCP_NETWORK_PROFILE: "isolated-bridge-v1",
    APEX_MCP_GUARD_ADDRESS: "10.248.245.3", APEX_MCP_NETWORK_BINDING_SHA256: "b".repeat(64) });
  const files = f.stage.files, config = decodeStrict(RuntimeConfigurationSchema, files["runtime-revision.json"].toString());
  config.spec!.upstreams[0].endpointOrCommandRef = "https://gateway.test:41003/mcp";
  config.spec!.upstreams[0].serverIdentity = "gateway.test";
  config.networkGrants.forEach(g => { g.host = "gateway.test"; g.port = 41003; });
  config.spec!.runtimeProfile!.egressDestinations.forEach(g => { g.host = "gateway.test"; g.port = 41003; });
  config.runtimeManifestHash = runtimeManifestHash(config);
  const launch = decodeStrict(RuntimeLaunchContextSchema, files["launch-context.json"].toString());
  launch.runtimeManifestHash = config.runtimeManifestHash; launch.launchContextHash = launchContextHash(launch);
  files["runtime-revision.json"] = Buffer.from(JSON.stringify(encodeJson(RuntimeConfigurationSchema, config)));
  files["launch-context.json"] = Buffer.from(JSON.stringify(encodeJson(RuntimeLaunchContextSchema, launch)));
  for (const [purpose, port] of [["governance", 41001], ["evidence", 41002]] as const) {
    f.value.profile[purpose] = { endpoint: `https://gateway.test:${port}`, tls_server_name: "gateway.test" };
  }
  // Reuse this generated fixture's client leaf only; no production enrollment.
  f.value.profile.managed.ingress.edge_certificate_sha256 = [
    new X509Certificate(pki.governance.cert).fingerprint256.replaceAll(":", "").toLowerCase(),
  ];
  files["authority-profile.json"] = f.bytes(); files["inbound-jwks"] = jwks();
});
try {
  await mkdir("/fixture/stage", { mode: 0o700 });
  for (const [name, bytes] of Object.entries(f.stage.files)) {
    assert.match(name, /^[a-z0-9.-]+$/);
    const path = `/fixture/stage/${name}`;
    await writeFile(path, bytes, { flag: "wx", mode: 0o400 }); await chown(path, 10001, 10001);
  }
  await chmod("/fixture/stage", 0o500); await chown("/fixture/stage", 10001, 10001);
  await writeFile("/fixture/client.json", JSON.stringify({ env: f.env, token: await token() }), { flag: "wx", mode: 0o400 });
  await chown("/fixture/client.json", 10001, 10001);
} finally { disposeStageOwner(f.stageOwner); await f.bootstrap.closed; }
// Metadata only; the daemon fixture passes these references through Docker's
// container environment without reopening UID-10001 private material as root.
export const nativeEnvironment = Object.freeze({ ...f.env });
