import { GatewayError, type AuthenticatedContext } from "../contracts.js";
import type { ReadonlyRuntimeConfiguration } from "./runtime-config.js";

export type RuntimeSpec = NonNullable<ReadonlyRuntimeConfiguration["spec"]>;
export type RuntimeUpstream = RuntimeSpec["upstreams"][number];
export type RuntimeTool = RuntimeSpec["exposedTools"][number];
export type RuntimeNetworkGrant = ReadonlyRuntimeConfiguration["networkGrants"][number];

/** Required accessors return the original generated submessages, never an adapter. */
export function runtimeSpec(config: ReadonlyRuntimeConfiguration): RuntimeSpec {
  if (!config.spec?.ingress || !config.spec.governanceBinding || !config.spec.runtimeProfile) throw rejected();
  return config.spec;
}

export function runtimeAuth(config: ReadonlyRuntimeConfiguration) {
  const auth = config.auth;
  if (!auth || !auth.issuer || auth.audience !== config.resourceUrl || !auth.requiredScopes.length) throw rejected();
  return auth;
}

export function assertRuntimeScope(config: ReadonlyRuntimeConfiguration, caller: AuthenticatedContext): void {
  if (caller.workspaceId !== config.workspaceId || caller.namespaceId !== config.namespaceId) {
    throw new GatewayError("AUTHORIZATION_DENIED", "managed runtime scope rejected safely");
  }
}

export function upstreamGrant(config: ReadonlyRuntimeConfiguration, upstream: RuntimeUpstream): RuntimeNetworkGrant {
  let endpoint: URL;
  try { endpoint = new URL(upstream.endpointOrCommandRef); } catch { throw rejected(); }
  const grant = config.networkGrants.find(value => value.host === endpoint.hostname && value.port === Number(endpoint.port || "443"));
  // Public metadata checks are not socket pinning or trusted host-policy enforcement.
  // Those remain unavailable at the production construction boundary (Tasks 8/13).
  if (!grant || grant.privateDestination || grant.approvedCidrs.length) throw rejected();
  return grant;
}

function rejected(): GatewayError {
  return new GatewayError("INVALID_INPUT", "managed runtime configuration rejected safely");
}
