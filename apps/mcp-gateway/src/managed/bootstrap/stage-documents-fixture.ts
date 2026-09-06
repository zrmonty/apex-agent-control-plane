import { encodeJson, RuntimeConfigurationSchema, RuntimeLaunchContextSchema, type RuntimeConfiguration, type RuntimeLaunchContext } from "@apex/contracts";
import { createHash } from "node:crypto";
import { completeFiles, fixtureHash } from "../stage-reader/fixture.js";
import { profileFixture } from "./ingress-profile-fixture.js";

export function documentsFixture() {
  const f = profileFixture(), files = completeFiles();
  const { config, launch } = f.context;
  files["runtime-revision.json"] = Buffer.from(JSON.stringify(encodeJson(RuntimeConfigurationSchema, config as RuntimeConfiguration)));
  files["launch-context.json"] = Buffer.from(JSON.stringify(encodeJson(RuntimeLaunchContextSchema, launch as RuntimeLaunchContext)));
  files["authority-profile.json"] = f.bytes();
  const entries = config.secretRefs.map(reference => ({ reference, version: "v1", filename: `tool-${createHash("sha256").update(reference).digest("hex")}` }));
  for (const e of entries) files[e.filename] = Buffer.from("synthetic tool credential bytes");
  const tools = { schema_version: 1, catalog_version: "tools-v1", installation_id: f.context.binding.installationId,
    workspace_id: config.workspaceId, namespace_id: config.namespaceId, proxy_id: config.proxyId, revision_id: config.revisionId,
    config_hash: config.configHash, host_policy_version: f.value.profile.host_policy_version,
    deployment_bindings_version: "bindings-v1", entries };
  files["tool-bindings.json"] = Buffer.from(JSON.stringify(tools));
  const stage = { files, manifestSha256: fixtureHash(files) };
  const selection = { installationId: f.context.binding.installationId, expectedManifestSha256: stage.manifestSha256,
    toolSecretReferences: [...config.secretRefs].sort() };
  return { ...f, tools, stage, selection, reseal() { stage.manifestSha256 = fixtureHash(files); selection.expectedManifestSha256 = stage.manifestSha256; } };
}
