import { create } from "@bufbuild/protobuf";
import { RuntimeNetworkGrantSchema } from "@apex/contracts";
import { compileGuardEgressPolicy } from "../egress-policy.js";
import { exact, integer, requireValue } from "./boundary.js";
import { ipv4Cidr } from "./topology.js";

export function routes(value: unknown, excluded: readonly string[]) {
  requireValue(Array.isArray(value) && value.length >= 1 && value.length <= 66);
  const selected = new Set<string>();
  const pairs = value.map((entry, index) => {
    const r = exact(entry, ["host", "port", "private_destination", "declared_cidrs", "protected_cidrs"]);
    const host = r.host, port = integer(r.port, 1, 65535);
    requireValue(typeof host === "string" && host.length >= 1 && host.length <= 253 &&
      host.split(".").every(part => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(part)));
    requireValue(new URL(`https://${host}:${port}/`).hostname === host &&
      !host.split(".").every(part => /^[0-9]+$/.test(part) || /^0x[0-9a-f]+$/.test(part)));
    const selector = JSON.stringify([host, port]); requireValue(!selected.has(selector)); selected.add(selector);
    requireValue(typeof r.private_destination === "boolean");
    const make = (input: unknown, min: number, max: number) => {
      requireValue(Array.isArray(input) && input.length >= min && input.length <= max);
      const approvedCidrs = input.map(ipv4Cidr); requireValue(new Set(approvedCidrs).size === approvedCidrs.length);
      return create(RuntimeNetworkGrantSchema, { grantId: `guard-${index}`, host, port,
        privateDestination: r.private_destination as boolean, approvedCidrs });
    };
    return [make(r.declared_cidrs, 0, 64), make(r.protected_cidrs, 1, 32)] as const;
  });
  return compileGuardEgressPolicy(pairs.map(pair => pair[0]), pairs.map(pair => pair[1]), excluded);
}
