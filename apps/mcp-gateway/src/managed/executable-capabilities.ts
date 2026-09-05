import { isDeepStrictEqual } from "node:util";
import { McpProxyTransport, McpProxyToolClassification, ProxyApprovalMode } from "@apex/contracts";
import { GatewayError } from "../contracts.js";
import type { ReadonlyRuntimeConfiguration } from "./runtime-config.js";
import { runtimeSpec, upstreamGrant } from "./runtime-types.js";

// This is the approved portfolio profile's schema, not a generic runtime wire
// model. A matching manifest digest does not establish catalog/policy provenance.
const portfolioInput = { type: "object", properties: { portfolioId: { type: "string" } },
  required: ["portfolioId"], additionalProperties: false };
const portfolioOutput = { type: "object" };

/** Executable subset only; this does NOT attest admission, host egress, catalog
 * drift, workload isolation or readiness. Production construction still refuses
 * until Tasks 8/13 supply those trusted enforcement implementations. */
export function assertExecutableRuntimeConfiguration(config: ReadonlyRuntimeConfiguration): void {
  try {
    const spec = runtimeSpec(config);
    if (spec.ingress!.transport !== McpProxyTransport.STREAMABLE_HTTP ||
      spec.ingress!.protocolRevision !== "2025-11-25" || spec.cliProfiles.length ||
      config.approvalMode !== ProxyApprovalMode.NONE || spec.governanceBinding!.approvalMode !== "none" ||
      !spec.exposedTools.length) throw rejected();
    for (const upstream of spec.upstreams) {
      if (upstream.transport !== McpProxyTransport.STREAMABLE_HTTP) throw rejected();
      upstreamGrant(config, upstream);
    }
    for (const tool of spec.exposedTools) {
      if (tool.toolName !== "portfolio.read" || tool.alias !== "portfolio.read" ||
        tool.classification !== McpProxyToolClassification.READ) throw rejected();
      const schema = config.toolSchemas.find(value => value.upstreamId === tool.upstreamId && value.toolName === tool.toolName);
      if (!schema || schema.outputProfileId !== "portfolio-read-v1" ||
        !isDeepStrictEqual(JSON.parse(schema.inputSchemaJson), portfolioInput) ||
        !isDeepStrictEqual(JSON.parse(schema.outputSchemaJson), portfolioOutput)) throw rejected();
    }
  } catch { throw rejected(); }
}

function rejected(): GatewayError {
  return new GatewayError("INVALID_INPUT", "managed executable capabilities rejected safely");
}
