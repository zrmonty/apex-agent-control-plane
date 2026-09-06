import { isIP } from "node:net";
import { address, cidr, contains } from "../../runtime-config/network.js";
import { exact, integer, requireValue } from "./boundary.js";
const privatePools = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"].map(cidr);
export function ipv4Cidr(value: unknown): string {
  requireValue(typeof value === "string" && value.length <= 18 && isIP(value.split("/")[0]) === 4);
  cidr(value); return value;
}
function pool(value: unknown, low: number, high: number) {
  const text = ipv4Cidr(value), range = cidr(text), prefix = Number(text.split("/")[1]);
  requireValue(prefix >= low && prefix <= high && privatePools.some(p => contains(p, range)));
  return { text, range, prefix };
}
function ip(value: bigint): string {
  return [24n, 16n, 8n, 0n].map(shift => ((value >> shift) & 255n).toString()).join(".");
}
export function topology(value: unknown) {
  const t = exact(value, ["internal_pool", "outer_subnet", "slot", "capacity", "outer_gateway", "edge_address"]);
  const inner = pool(t.internal_pool, 22, 29), outer = pool(t.outer_subnet, 24, 24);
  requireValue(inner.range.end < outer.range.start || outer.range.end < inner.range.start);
  const capacity = integer(t.capacity, 1, 128), slot = integer(t.slot, 0, capacity - 1);
  requireValue(capacity <= 2 ** (29 - inner.prefix));
  function reserved(value: unknown): string {
    requireValue(typeof value === "string" && value.length <= 15 && isIP(value) === 4);
    const selected = address(value).start;
    requireValue(selected > outer.range.start && selected <= outer.range.start + 15n); return value;
  }
  const outerGateway = reserved(t.outer_gateway), edge = reserved(t.edge_address);
  requireValue(outerGateway !== edge);
  const base = inner.range.start + BigInt(slot * 8);
  return Object.freeze({ addresses: Object.freeze({ internalSubnet: `${ip(base)}/29`, ipamGateway: ip(base + 1n),
    gateway: ip(base + 2n), guardInternal: ip(base + 3n), guardOuter: ip(outer.range.start + 16n + BigInt(slot)),
    outerGateway, edge, ingressPort: 8080 as const, egressPort: 18080 as const }),
    excluded: Object.freeze([inner.text, outer.text]) });
}
