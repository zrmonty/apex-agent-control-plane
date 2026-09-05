import { isIP } from "node:net";
import { McpProxyPrivateDestinationAllowance, type McpProxyEgressDestination, type RuntimeNetworkGrant } from "@apex/contracts";
import { httpsUrl, identifier, requireValue, unique } from "./boundary.js";

/** Static range arithmetic mirrors the Rust compiler, not DNS/host authority.
 * Later admission still intersects these grants with independent host policy,
 * pins resolved addresses, and denies other proxy networks. No sockets here.
 */
export function validateNetwork(destinations: McpProxyEgressDestination[], grants: RuntimeNetworkGrant[]): void {
  requireValue(grants.length > 0 && grants.length <= 64 && grants.length === destinations.length);
  const key = (host: string, port: number): string => JSON.stringify([host, port]);
  const declared = unique(destinations.map(d => key(d.host, d.port)));
  unique(grants.map(g => key(g.host, g.port)));
  unique(grants.map(g => g.grantId));
  for (const destination of destinations) {
    hostName(destination.host);
    requireValue(destination.port > 0 && destination.port <= 65535);
    requireValue([McpProxyPrivateDestinationAllowance.DENIED, McpProxyPrivateDestinationAllowance.ALLOWED].includes(destination.privateDestinationAllowance));
  }
  for (const grant of grants) {
    requireValue(identifier(grant.grantId) && declared.has(key(grant.host, grant.port)));
    const destination = destinations.find(d => d.host === grant.host && d.port === grant.port)!;
    requireValue(grant.privateDestination === (destination.privateDestinationAllowance === McpProxyPrivateDestinationAllowance.ALLOWED));
    const endpoint = httpsUrl(`https://${grant.host}:${grant.port}/`);
    requireValue(endpoint.hostname === grant.host);
    const host = grant.host.replace(/^\[|\]$/g, "").toLowerCase();
    requireValue(!["localhost", "host.docker.internal", "gateway.docker.internal", "metadata.google.internal", "instance-data.ec2.internal"].includes(host));
    requireValue(!host.endsWith(".localhost"));
    requireValue(!(host.endsWith(".internal") || host.endsWith(".local")) || grant.privateDestination);
    requireValue(grant.approvedCidrs.length <= 64 && (!grant.privateDestination || grant.approvedCidrs.length > 0));
    unique(grant.approvedCidrs);
    const ranges = grant.approvedCidrs.map(cidr);
    requireValue(ranges.every(range => permitted(range, grant.privateDestination)));
    if (isIP(host)) {
      const literal = address(host);
      requireValue(permitted(literal, grant.privateDestination));
      requireValue(ranges.length === 0 || ranges.some(range => contains(range, literal)));
    }
  }
}

export function hostName(host: string): void {
  requireValue(host.length > 0 && host.length <= 512);
  const unbracketed = host.replace(/^\[|\]$/g, "");
  requireValue(isIP(unbracketed) !== 0 || (unbracketed.length <= 253 && unbracketed.split(".").every(label =>
    label.length <= 63 && /^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(label))));
}

type Range = { start: bigint; end: bigint; width: 32 | 128 };

function address(value: string): Range {
  const family = isIP(value);
  requireValue(family !== 0);
  if (family === 4) {
    const start = value.split(".").reduce((sum, part) => (sum << 8n) | BigInt(part), 0n);
    return { start, end: start, width: 32 };
  }
  // URL canonicalization expands embedded IPv4 into hex while retaining IPv6.
  const normalized = new URL(`https://[${value}]/`).hostname.slice(1, -1);
  const halves = normalized.split("::");
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const groups = halves.length === 2 ? [...left, ...Array<string>(8 - left.length - right.length).fill("0"), ...right] : left;
  requireValue(groups.length === 8);
  const start = groups.reduce((sum, group) => (sum << 16n) | BigInt(`0x${group}`), 0n);
  return { start, end: start, width: 128 };
}

function cidr(value: string): Range {
  requireValue(value.length <= 64);
  const parts = value.split("/");
  requireValue(parts.length === 2 && /^[1-9][0-9]*$/.test(parts[1]));
  const range = address(parts[0]);
  const bits = Number(parts[1]);
  requireValue(bits <= range.width);
  const mask = (1n << BigInt(range.width - bits)) - 1n;
  requireValue((range.start & mask) === 0n);
  return { ...range, end: range.start | mask };
}

function contains(outer: Range, inner: Range): boolean {
  return outer.width === inner.width && outer.start <= inner.start && outer.end >= inner.end;
}

function permitted(range: Range, privateDestination: boolean): boolean {
  const overlaps = ([start, end]: readonly bigint[]): boolean => range.start <= end && start <= range.end;
  if (range.width === 32) {
    const privateRanges = [[0x0a000000n, 0x0affffffn], [0xac100000n, 0xac1fffffn], [0xc0a80000n, 0xc0a8ffffn]];
    if (privateDestination) return privateRanges.some(([start, end]) => range.start >= start && range.end <= end);
    const reserved = [
      [0n, 0x00ffffffn], [0x64400000n, 0x647fffffn], [0x7f000000n, 0x7fffffffn],
      [0xa9fe0000n, 0xa9feffffn], [0xc0000000n, 0xc00000ffn], [0xc0000200n, 0xc00002ffn],
      [0xc0586300n, 0xc05863ffn], [0xc6120000n, 0xc613ffffn], [0xc6336400n, 0xc63364ffn],
      [0xcb007100n, 0xcb0071ffn], [0xe0000000n, 0xffffffffn],
    ];
    return ![...privateRanges, ...reserved].some(overlaps);
  }
  if (privateDestination) return range.start >= (0xfc00n << 112n) && range.end < (0xfe00n << 112n);
  return range.start >= (0x2000n << 112n) && range.end < (0x4000n << 112n) && ![
    [0x2001n << 112n, (0x20010200n << 96n) - 1n],
    [0x20010db8n << 96n, (0x20010db9n << 96n) - 1n],
    [0x2002n << 112n, (0x2003n << 112n) - 1n],
    [0x3fffn << 112n, (0x3fff1000n << 96n) - 1n],
  ].some(overlaps);
}
