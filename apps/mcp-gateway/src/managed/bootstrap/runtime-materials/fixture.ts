import { ownerFixture } from "../stage-owner/fixture.js";
import { startOwnedStage } from "../stage-owner/job.js";
import { fixture as pki } from "../tls-role-fixture.js";
export const now = 1783123456123456n;
export async function materialFixture(change?: (value: ReturnType<typeof ownerFixture>) => void) {
  const f = ownerFixture(), files = f.stage.files;
  for (const [prefix, role] of [["governance", "governance"], ["evidence", "evidence"], ["workload", "ingress"]] as const) {
    files[`${prefix}-ca`] = Buffer.from(pki.ca);
    files[`${prefix}-cert`] = Buffer.from(pki[role].cert);
    files[`${prefix}-key`] = Buffer.from(pki[role].key);
  }
  files["governance-token"] = Buffer.from("synthetic-dedicated-governance-token");
  files["evidence-token"] = Buffer.from("synthetic-dedicated-evidence-token");
  files["health-token"] = Buffer.from(Buffer.alloc(32, 8).toString("base64url"));
  files["inbound-jwks"] = Buffer.from('{"keys":[]}'); // Verified only by later inbound factory.
  f.value.profile.managed.ingress.tls_server_name = "gateway.test";
  files["authority-profile.json"] = f.bytes();
  for (const tool of f.tools.entries) files[tool.filename] = Buffer.from(JSON.stringify({ schema_version: 1,
    authentication: "bearer", server_ca: pki.ca, token: "synthetic-dedicated-upstream-token" }));
  change?.(f); f.reseal();
  f.env.APEX_STAGE_MANIFEST_SHA256 = f.selection.expectedManifestSha256;
  const material = { files, manifestSha256: f.stage.manifestSha256, dispose() {
    f.counts.disposals++; for (const value of Object.values(files)) value.fill(0);
  } };
  const bootstrap = startOwnedStage({ env: f.env, onFatal: f.onFatal }, f.load, f.time, f.gate);
  f.closed.resolve(); f.result.resolve(material);
  const stage = await bootstrap.result;
  return { ...f, stageOwner: stage, bootstrap };
}
