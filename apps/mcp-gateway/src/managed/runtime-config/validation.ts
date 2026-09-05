import {
  McpProxyExposure, McpProxyToolClassification, McpProxyTransport, ProxyApprovalMode,
  type RuntimeConfiguration,
} from "@apex/contracts";
import { hash, httpsUrl, identifier, reference, requireValue, textBound, unique } from "./boundary.js";
import { hostName, validateNetwork } from "./network.js";
import { schemaJson } from "./schemas.js";

const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** Metadata parity with proxy/runtime_config and existing domain validation.
 * The catalog and approved output-profile registry are NOT in this wire message:
 * their authority must come from trusted provisioning, never a self-signed hash.
 * Full schema/output enforcement and admission remain later runtime stages.
 */
export function validateMetadata(config: RuntimeConfiguration): void {
  requireValue(config.schemaVersion === 1 && config.generation > 0n);
  requireValue(identifier(config.workspaceId, 256) && identifier(config.namespaceId, 256));
  requireValue(UUID_V7.test(config.proxyId) && UUID_V7.test(config.revisionId));
  requireValue(hash(config.configHash) && hash(config.runtimeManifestHash));
  const spec = config.spec;
  const ingress = spec?.ingress;
  const profile = spec?.runtimeProfile;
  const governance = spec?.governanceBinding;
  const auth = config.auth;
  const telemetry = config.telemetry;
  requireValue(spec && ingress && profile && governance && auth && telemetry);
  requireValue(ingress.transport === McpProxyTransport.STREAMABLE_HTTP && ingress.protocolRevision === "2025-11-25");
  requireValue([McpProxyExposure.PRIVATE, McpProxyExposure.EXTERNAL].includes(ingress.exposure));
  requireValue(ingress.inboundAuthenticationRequired && spec.cliProfiles.length === 0);
  requireValue(profile.rootless && profile.networkPolicy === "default-deny" && profile.filesystemPolicy === "read-only-rootfs");
  hostName(ingress.host);
  textBound(ingress.path);
  const resource = httpsUrl(config.resourceUrl);
  requireValue(resource.href === config.resourceUrl && resource.hostname === ingress.host);
  requireValue(resource.pathname === ingress.path && (!resource.port || resource.port === "443"));
  requireValue(auth.audience === config.resourceUrl);
  requireValue(ingress.allowedOrigins.length <= 32);
  unique(ingress.allowedOrigins);
  for (const origin of ingress.allowedOrigins) requireValue(httpsUrl(origin).pathname === "/");
  httpsUrl(auth.issuer);
  httpsUrl(auth.jwksUri);
  reference(auth.workloadIdentityRef, "identity://");
  requireValue(auth.requiredScopes.length > 0 && auth.requiredScopes.length <= 64);
  unique(auth.requiredScopes);
  requireValue(auth.requiredScopes.every(scope => identifier(scope)));

  requireValue(spec.upstreams.length > 0 && spec.upstreams.length <= 64);
  const upstreamIds = unique(spec.upstreams.map(upstream => upstream.upstreamId));
  const declaredSecrets = new Set<string>();
  function secret(value: string): void { reference(value, "secret://"); declaredSecrets.add(value); }
  for (const upstream of spec.upstreams) {
    requireValue(identifier(upstream.upstreamId) && upstream.transport === McpProxyTransport.STREAMABLE_HTTP);
    textBound(upstream.displayName);
    textBound(upstream.serverIdentity);
    requireValue(hash(upstream.toolCatalogHash) && upstream.secretRefs.length <= 32);
    const endpoint = httpsUrl(upstream.endpointOrCommandRef);
    requireValue(config.networkGrants.some(grant => endpoint.hostname === grant.host && Number(endpoint.port || "443") === grant.port));
    secret(upstream.credentialRef);
    unique(upstream.secretRefs);
    upstream.secretRefs.forEach(secret);
  }
  requireValue(spec.authBindings.length <= 32);
  unique(spec.authBindings.map(binding => binding.bindingId));
  for (const binding of spec.authBindings) {
    requireValue(identifier(binding.bindingId) && binding.scopes.length <= 64);
    textBound(binding.inboundSubject);
    secret(binding.outboundCredentialRef);
    unique(binding.scopes);
    requireValue(binding.scopes.every(scope => identifier(scope)));
  }
  requireValue(config.secretRefs.length <= 4096);
  const suppliedSecrets = unique(config.secretRefs);
  requireValue(suppliedSecrets.size === declaredSecrets.size && [...suppliedSecrets].every(ref => declaredSecrets.has(ref)));

  requireValue(spec.exposedTools.length > 0 && spec.exposedTools.length <= 256);
  unique(spec.exposedTools.map(tool => tool.alias));
  const toolKey = (upstream: string, tool: string): string => JSON.stringify([upstream, tool]);
  const exposed = new Set(spec.exposedTools.map(tool => toolKey(tool.upstreamId, tool.toolName)));
  for (const tool of spec.exposedTools) {
    requireValue(upstreamIds.has(tool.upstreamId) && identifier(tool.toolName) && identifier(tool.alias));
    requireValue([McpProxyToolClassification.READ, McpProxyToolClassification.BUSINESS_WRITE, McpProxyToolClassification.HIGH_IMPACT].includes(tool.classification));
    requireValue(tool.toolName !== "portfolio.read" || tool.classification === McpProxyToolClassification.READ);
  }
  requireValue(config.toolSchemas.length === exposed.size && config.toolSchemas.length <= 256);
  unique(config.toolSchemas.map(schema => toolKey(schema.upstreamId, schema.toolName)));
  for (const schema of config.toolSchemas) {
    requireValue(exposed.has(toolKey(schema.upstreamId, schema.toolName)));
    requireValue(identifier(schema.outputProfileId) && hash(schema.schemaHash));
    schemaJson(schema.inputSchemaJson);
    schemaJson(schema.outputSchemaJson);
  }

  requireValue(identifier(governance.policyId));
  const modes = new Map([
    ["none", ProxyApprovalMode.NONE], ["operator", ProxyApprovalMode.OPERATOR], ["dual-operator", ProxyApprovalMode.DUAL_OPERATOR],
  ]);
  requireValue(modes.has(governance.approvalMode) && modes.get(governance.approvalMode) === config.approvalMode);
  requireValue(["public", "internal", "confidential", "restricted"].includes(governance.dataClassification));
  limit(governance.rateLimit, "/m", 1000000n);
  limit(governance.concurrencyLimit, "", 1000000n);
  limit(governance.budget, "/d", 1000000n);
  limit(governance.retention, "d", 3650n);
  const cpu = profile.cpuLimit.endsWith("m") ? decimal(profile.cpuLimit.slice(0, -1)) : decimal(profile.cpuLimit) * 1000n;
  const unit = /^(\d+)(Ki|Mi|Gi)?$/.exec(profile.memoryLimit);
  requireValue(unit);
  const scale = new Map([["Ki", 1024n], ["Mi", 1048576n], ["Gi", 1073741824n]]);
  const memory = decimal(unit[1]) * (unit[2] ? scale.get(unit[2])! : 1n);
  requireValue(cpu >= 1n && cpu <= 4000n && BigInt(config.cpuMillis) === cpu);
  requireValue(memory >= 16777216n && memory <= 2147483648n && config.memoryBytes === memory);
  requireValue(config.pidLimit >= 16 && config.pidLimit <= 1024);
  image(config.imageRef, profile.imageDigest);
  validateNetwork(profile.egressDestinations, config.networkGrants);
  requireValue(telemetry.fullTraceSamplePerMillion >= 1 && telemetry.fullTraceSamplePerMillion <= 1000000);
  requireValue(telemetry.maxStages >= 1 && telemetry.maxStages <= 32);
  requireValue(telemetry.maxSummaryBytes >= 1 && telemetry.maxSummaryBytes <= 65536);
  requireValue(telemetry.maxSpans >= 1 && telemetry.maxSpans <= 128);
  requireValue(telemetry.maxAttributesPerSpan >= 1 && telemetry.maxAttributesPerSpan <= 64);
  requireValue(telemetry.maxExportQueueBytes >= 1n && telemetry.maxExportQueueBytes <= 8388608n);
}

function decimal(value: string): bigint {
  requireValue(value.length <= 512 && /^[0-9]+$/.test(value));
  const parsed = BigInt(value);
  requireValue(parsed <= (1n << 64n) - 1n);
  return parsed;
}

function limit(value: string, suffix: string, maximum: bigint): void {
  requireValue(value.endsWith(suffix));
  const digits = suffix ? value.slice(0, -suffix.length) : value;
  requireValue(/^[1-9][0-9]*$/.test(digits));
  requireValue(decimal(digits) <= maximum);
}

function image(value: string, digest: string): void {
  requireValue(/^sha256:[0-9a-f]{64}$/.test(digest) && value.length <= 512);
  const parts = value.split("@");
  requireValue(parts.length === 2 && parts[1] === digest);
  const slash = parts[0].indexOf("/");
  requireValue(slash > 0);
  const registry = parts[0].slice(0, slash);
  const repository = parts[0].slice(slash + 1);
  const url = httpsUrl(`https://${registry}/`);
  requireValue(registry.includes(".") && url.pathname === "/" && url.origin === `https://${registry}`);
  requireValue(repository.split("/").every(part => /^[a-z0-9][a-z0-9._-]*$/.test(part) && !part.includes("..")));
}
