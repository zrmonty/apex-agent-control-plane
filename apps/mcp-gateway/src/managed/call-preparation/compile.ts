import { isDeepStrictEqual } from "node:util";
import { McpProxyToolClassification, McpProxyTransport, ProxyApprovalMode,
  type RuntimeConfiguration } from "@apex/contracts";
import type { Clock } from "../../telemetry/clock.js";
import type { CallPreparationOptions } from "../call-preparation-types.js";
import { runtimeManifestHash, type ReadonlyRuntimeConfiguration } from "../runtime-config.js";
import { assertDataTree } from "../runtime-config/boundary.js";
import { validateMetadata } from "../runtime-config/validation.js";
import { runtimeSpec } from "../runtime-types.js";
import { compileExposedToolIndexes } from "../upstream.js";
import { businessBinding, businessClassification } from "../authority/business-codec.js";
import { frozenTree, identifier, record, refused } from "./boundary.js";

const inputSchema = { type: "object", properties: { portfolioId: { type: "string" } },
  required: ["portfolioId"], additionalProperties: false };
const outputSchema = { type: "object" };
const bindingKeys = ["installationId", "workspaceId", "namespaceId", "proxyId", "revisionId",
  "generation", "fencingToken", "processInstanceId", "configHash", "launchContextHash"];

/** Compile data only. No call to legacy upstreamGrant or public-network authority. */
export function compile(options: CallPreparationOptions) {
  const fields = record(options, ["config", "binding", "evidenceAgentId", "dataClassification", "clock"]);
  const config = fields.config as ReadonlyRuntimeConfiguration;
  assertDataTree(config, true); frozenTree(config);
  // The digest helper also checks the complete generated message descriptor.
  if (runtimeManifestHash(config) !== config.runtimeManifestHash) throw refused();
  validateMetadata(config as RuntimeConfiguration);
  record(fields.binding, bindingKeys); assertDataTree(fields.binding, true);
  const binding = businessBinding(fields.binding);
  identifier(binding.workspaceId); identifier(binding.namespaceId);
  for (const key of ["workspaceId", "namespaceId", "proxyId", "revisionId", "generation", "configHash"] as const) {
    if (config[key] !== binding[key]) throw refused();
  }
  const spec = runtimeSpec(config), governance = spec.governanceBinding!;
  const policyId = identifier(governance.policyId), evidenceAgentId = identifier(fields.evidenceAgentId);
  const dataClassification = businessClassification(fields.dataClassification);
  if (dataClassification !== governance.dataClassification ||
    spec.ingress!.transport !== McpProxyTransport.STREAMABLE_HTTP || spec.ingress!.protocolRevision !== "2025-11-25" ||
    spec.cliProfiles.length !== 0 || config.approvalMode !== ProxyApprovalMode.NONE || governance.approvalMode !== "none" ||
    spec.exposedTools.length !== 1 || spec.upstreams.some(upstream => upstream.transport !== McpProxyTransport.STREAMABLE_HTTP)) throw refused();
  const tool = spec.exposedTools[0], schema = config.toolSchemas[0];
  if (tool.alias !== "portfolio.read" || tool.toolName !== "portfolio.read" || tool.classification !== McpProxyToolClassification.READ ||
    config.toolSchemas.length !== 1 || schema.upstreamId !== tool.upstreamId || schema.toolName !== tool.toolName ||
    schema.outputProfileId !== "portfolio-read-v1" || !isDeepStrictEqual(JSON.parse(schema.inputSchemaJson), inputSchema) ||
    !isDeepStrictEqual(JSON.parse(schema.outputSchemaJson), outputSchema)) throw refused();
  const clock = record(fields.clock, ["now"]);
  if (typeof clock.now !== "function") throw refused();
  const now = clock.now.bind(fields.clock) as Clock["now"];
  return { binding, policyId, evidenceAgentId, dataClassification, now,
    indexes: compileExposedToolIndexes(config) };
}
