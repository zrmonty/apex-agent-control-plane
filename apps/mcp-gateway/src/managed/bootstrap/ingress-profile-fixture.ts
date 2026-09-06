import { create, toJson } from "@bufbuild/protobuf";
import { RuntimeLaunchContextSchema, RuntimeMaterialRole } from "@apex/contracts";
import { fixture as callFixture } from "../call-preparation/fixture.js";
import { launchContextHash, parseRuntimeLaunchContext } from "../launch-context.js";

export function profileFixture() {
  const { options: { config, binding } } = callFixture();
  const roles = Object.values(RuntimeMaterialRole).filter((v): v is RuntimeMaterialRole => typeof v === "number" && v !== 0);
  const materials = roles.map(role => ({ role, reference: `secret://deployment/role-${role}`, version: "v1" }));
  const launch = create(RuntimeLaunchContextSchema, {
    schemaVersion: 1, target: { workspaceId: binding.workspaceId, namespaceId: binding.namespaceId,
      proxyId: binding.proxyId, revisionId: binding.revisionId, generation: binding.generation, fencingToken: binding.fencingToken },
    configHash: config.configHash, runtimeManifestHash: config.runtimeManifestHash, imageRef: config.imageRef,
    processInstanceId: binding.processInstanceId, authorityProfileRef: "managed-live", authorityProfileVersion: "v1",
    health: { port: 8081, credentialRef: materials.find(m => m.role === RuntimeMaterialRole.HEALTH_TOKEN)!.reference }, materials,
  });
  launch.launchContextHash = launchContextHash(launch);
  const context = { config, launch: parseRuntimeLaunchContext(toJson(RuntimeLaunchContextSchema, launch), config),
    binding: { ...binding, launchContextHash: launch.launchContextHash } };
  const value = { schema_version: 3, catalog_version: "v1", profile: {
    installation_id: binding.installationId, workspace_id: binding.workspaceId, namespace_id: binding.namespaceId,
    proxy_id: binding.proxyId, host_policy_version: "h1", reference: launch.authorityProfileRef, version: launch.authorityProfileVersion,
    mode: "managed_ingress", governance: { endpoint: "https://governance.example", tls_server_name: "governance.example" },
    evidence: { endpoint: "https://evidence.example:9443", tls_server_name: "evidence.example" },
    managed: { evidence_agent_id: "managed-evidence", upstream_credentials: "managed_upstream_v1",
      network_policy: { reference: "isolated-gateway", version: "v1" },
      ingress: { port: 8080, tls_server_name: "gateway.example", edge_certificate_sha256: ["a".repeat(64)] } },
  } };
  return { value, context, bytes: () => Buffer.from(JSON.stringify(value)) };
}
