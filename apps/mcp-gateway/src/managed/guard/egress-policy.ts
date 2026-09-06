import { isIP } from "node:net";
import { create } from "@bufbuild/protobuf";
import { McpProxyEgressDestinationSchema, McpProxyPrivateDestinationAllowance,
  RuntimeNetworkGrantSchema, type RuntimeNetworkGrant } from "@apex/contracts";
import { assertDataTree, assertMessage } from "../runtime-config/boundary.js";
import { address, cidr, contains, validateNetwork } from "../runtime-config/network.js";

const refused = () => new Error("guard egress refused safely");
const key = (host: string, port: number) => JSON.stringify([host, port]);
type Range = ReturnType<typeof cidr>;

export type PinnedDestination = Readonly<{ host: string; port: number; address: string; family: 4 | 6 }>;
export type GuardDestination = Readonly<{
  host: string; port: number;
  pin(resolvedAddresses: readonly string[]): PinnedDestination;
}>;
export interface GuardEgressPolicy {
  select(host: string, port: number): GuardDestination;
}

/** Pure selection only. Protected staging and physical confinement are separate. */
export function compileGuardEgressPolicy(
  declared: readonly RuntimeNetworkGrant[],
  hostPolicy: readonly RuntimeNetworkGrant[],
  excludedCidrs: readonly string[],
): GuardEgressPolicy {
  try {
    const declarations = grants(declared), protectedGrants = grants(hostPolicy);
    assertDataTree(excludedCidrs, false);
    if (!Array.isArray(excludedCidrs) || !excludedCidrs.length || excludedCidrs.length > 128 ||
      new Set(excludedCidrs).size !== excludedCidrs.length) throw refused();
    const excluded = excludedCidrs.map(value => {
      if (typeof value !== "string") throw refused();
      return cidr(value);
    });
    const routes = new Map<string, GuardDestination>();
    for (const [selector, declaration] of declarations) {
      const host = protectedGrants.get(selector);
      if (!host || host.privateDestination !== declaration.privateDestination || !host.approvedCidrs.length) throw refused();
      const hostRanges = host.approvedCidrs.map(cidr);
      const publishedRanges = declaration.approvedCidrs.map(cidr);
      const intersection = publishedRanges.length ? hostRanges.flatMap(h => publishedRanges.flatMap(p =>
        contains(h, p) ? [p] : contains(p, h) ? [h] : [])) : hostRanges;
      if (!intersection.length || intersection.every(range => excluded.some(blocked => contains(blocked, range)))) throw refused();
      routes.set(selector, destination(declaration.host, declaration.port, intersection, excluded));
    }
    return Object.freeze({ select(host: string, port: number): GuardDestination {
      if (typeof host !== "string" || host.length > 512 || !Number.isSafeInteger(port) || port < 1 || port > 65535) throw refused();
      const route = routes.get(key(host, port));
      if (!route) throw refused();
      return route;
    } });
  } catch { throw refused(); }
}

function grants(input: readonly RuntimeNetworkGrant[]): Map<string, RuntimeNetworkGrant> {
  // Inspect passive data and charge bounded strings/nodes before traversing or
  // encoding caller-supplied generated messages. No getters/toJSON/Proxy hooks.
  assertDataTree(input, true);
  if (!Array.isArray(input) || !input.length || input.length > 66) throw refused();
  const result = new Map<string, RuntimeNetworkGrant>(), ids = new Set<string>();
  for (const grant of input) {
    assertMessage(RuntimeNetworkGrantSchema, grant);
    validateNetwork([create(McpProxyEgressDestinationSchema, {
      host: grant.host, port: grant.port,
      privateDestinationAllowance: grant.privateDestination ? McpProxyPrivateDestinationAllowance.ALLOWED : McpProxyPrivateDestinationAllowance.DENIED,
    })], [grant]);
    const selector = key(grant.host, grant.port);
    if (result.has(selector) || ids.has(grant.grantId) ||
      new URL(`https://${grant.host}:${grant.port}/`).hostname !== grant.host) throw refused();
    ids.add(grant.grantId);
    result.set(selector, grant);
  }
  return result;
}

function destination(host: string, port: number, allowed: Range[], excluded: Range[]): GuardDestination {
  const literalHost = host.replace(/^\[|\]$/g, "");
  const literal = isIP(literalHost) ? address(literalHost) : undefined;
  return Object.freeze({ host, port, pin(resolvedAddresses: readonly string[]): PinnedDestination {
    try {
      assertDataTree(resolvedAddresses, false);
      if (!Array.isArray(resolvedAddresses) || !resolvedAddresses.length || resolvedAddresses.length > 32) throw refused();
      let first: PinnedDestination | undefined;
      for (const value of resolvedAddresses) {
        if (typeof value !== "string" || value.length > 64 || value.includes("%") || !isIP(value)) throw refused();
        const selected = address(value);
        if (!allowed.some(range => contains(range, selected)) || excluded.some(range => contains(range, selected)) ||
          (literal && !contains(literal, selected))) throw refused();
        first ??= Object.freeze({ host, port, address: value, family: selected.width === 32 ? 4 : 6 });
      }
      return first!;
    } catch { throw refused(); }
  } });
}
