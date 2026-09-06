import { types } from "node:util";
import { RuntimeConfigurationSchema, RuntimeLaunchContextSchema, RuntimeMaterialRole, encodeJson,
  type RuntimeConfiguration, type RuntimeLaunchContext } from "@apex/contracts";
import type { DeploymentBinding } from "../authority/types.js";
import { immutableBinding } from "../authority/binding.js";
import { parseRuntimeConfiguration, type DeepReadonly, type ReadonlyRuntimeConfiguration } from "../runtime-config.js";
import { parseRuntimeLaunchContext, type ReadonlyRuntimeLaunchContext } from "../launch-context.js";
import { assertDataTree, assertMessage, freezeTree } from "../runtime-config/boundary.js";
import { parseWireJson } from "../upstream-wire/json.js";
export interface IngressProfileContext {
  readonly binding: DeploymentBinding;
  readonly config: ReadonlyRuntimeConfiguration;
  readonly launch: ReadonlyRuntimeLaunchContext;
}
const refused = () => new Error("managed ingress profile rejected");
const uint8Prototype = Object.getPrototypeOf(Uint8Array.prototype);
const byteLength = Object.getOwnPropertyDescriptor(uint8Prototype, "byteLength")!.get!;
const backingBuffer = Object.getOwnPropertyDescriptor(uint8Prototype, "buffer")!.get!;
function requireValue(value: unknown): asserts value { if (!value) throw refused(); }

/** Pure metadata consistency, not a staged-file, enrolled-identity or serving capability.
 * Only the new schema-3 mode assigns WORKLOAD keys the ingress-server purpose. */
export function parseManagedIngressProfile(bytes: Uint8Array, context: IngressProfileContext) {
  try {
    requireValue(!types.isProxy(bytes) && types.isUint8Array(bytes));
    const length: number = byteLength.call(bytes);
    requireValue(length > 0 && length <= 262144 && !types.isSharedArrayBuffer(backingBuffer.call(bytes)));
    const copy = Buffer.alloc(length);
    Uint8Array.prototype.set.call(copy, bytes);
    const value = parseWireJson(copy);
    // Valid JSON has already been checked. Skip complete quoted strings; the
    // only numeric fields are Rust unsigned integers, never floats/exponents.
    for (const token of copy.toString("utf8").matchAll(/"(?:\\.|[^"\\])*"|(-?[0-9][0-9.eE+-]*)/g)) {
      requireValue(token[1] === undefined || /^(0|[1-9][0-9]*)$/.test(token[1]));
    }
    assertDataTree(value, false);
    assertDataTree(context, true);
    record(context, ["binding", "config", "launch"]);
    assertMessage(RuntimeConfigurationSchema, context.config);
    assertMessage(RuntimeLaunchContextSchema, context.launch);
    const config = parseRuntimeConfiguration(encodeJson(RuntimeConfigurationSchema, context.config as RuntimeConfiguration));
    const launch = parseRuntimeLaunchContext(encodeJson(RuntimeLaunchContextSchema, context.launch as RuntimeLaunchContext), config);
    const binding = immutableBinding(context.binding);
    const target = launch.target!;
    requireValue(binding.workspaceId === target.workspaceId && binding.namespaceId === target.namespaceId &&
      binding.proxyId === target.proxyId && binding.revisionId === target.revisionId &&
      binding.generation === target.generation && binding.fencingToken === target.fencingToken &&
      binding.processInstanceId === launch.processInstanceId && binding.configHash === launch.configHash &&
      binding.launchContextHash === launch.launchContextHash);
    const roles = Object.values(RuntimeMaterialRole).filter(v => typeof v === "number" && v !== 0);
    requireValue(launch.materials.length === 13 && roles.every(role => launch.materials.some(m => m.role === role)) &&
      new Set(launch.materials.map(m => m.reference)).size === 13);
    const document = record(value, ["schema_version", "catalog_version", "profile"]);
    requireValue(document.schema_version === 3);
    const p = record(document.profile, ["installation_id", "workspace_id", "namespace_id", "proxy_id", "host_policy_version",
      "reference", "version", "mode", "governance", "evidence", "managed"]);
    requireValue(p.mode === "managed_ingress" && p.installation_id === binding.installationId &&
      p.workspace_id === binding.workspaceId && p.namespace_id === binding.namespaceId && p.proxy_id === binding.proxyId &&
      p.reference === launch.authorityProfileRef && p.version === launch.authorityProfileVersion);
    const m = record(p.managed, ["evidence_agent_id", "upstream_credentials", "network_policy", "ingress"]);
    requireValue(m.upstream_credentials === "managed_upstream_v1");
    const network = record(m.network_policy, ["reference", "version"]);
    const ingress = record(m.ingress, ["port", "tls_server_name", "edge_certificate_sha256"]);
    requireValue(ingress.port === 8080);
    const pins = ingress.edge_certificate_sha256;
    requireValue(Array.isArray(pins) && pins.length >= 1 && pins.length <= 2 && new Set(pins).size === pins.length);
    requireValue(pins.every(pin => typeof pin === "string" && /^[0-9a-f]{64}$/.test(pin) && /[1-9a-f]/.test(pin)));
    const result = { schema_version: 3 as const, catalog_version: identifier(document.catalog_version), profile: {
      installation_id: binding.installationId, workspace_id: binding.workspaceId, namespace_id: binding.namespaceId,
      proxy_id: binding.proxyId, host_policy_version: identifier(p.host_policy_version),
      reference: identifier(p.reference), version: identifier(p.version), mode: "managed_ingress" as const,
      governance: transport(p.governance), evidence: transport(p.evidence), managed: {
        evidence_agent_id: identifier(m.evidence_agent_id), upstream_credentials: "managed_upstream_v1" as const,
        network_policy: { reference: identifier(network.reference), version: identifier(network.version) },
        ingress: { port: 8080 as const, tls_server_name: dns(ingress.tls_server_name), edge_certificate_sha256: pins.slice() as string[] },
      },
    } };
    return freezeTree(result) as DeepReadonly<typeof result>;
  } catch { throw refused(); }
}
export type ManagedIngressProfile = ReturnType<typeof parseManagedIngressProfile>;

function record(value: unknown, keys: string[]): Record<string, unknown> {
  requireValue(value !== null && typeof value === "object" && !Array.isArray(value));
  requireValue(Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)));
  return value as Record<string, unknown>;
}
function identifier(value: unknown): string {
  requireValue(typeof value === "string" && /^[A-Za-z0-9_.:-]{1,128}$/.test(value) && !value.includes(".."));
  return value;
}
function dns(value: unknown): string {
  requireValue(typeof value === "string" && value.length >= 1 && value.length <= 253 && /[a-z]/.test(value) &&
    value.split(".").every(part => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(part)));
  return value;
}
function transport(value: unknown) {
  const t = record(value, ["endpoint", "tls_server_name"]);
  const name = dns(t.tls_server_name), endpoint = t.endpoint;
  requireValue(typeof endpoint === "string" && endpoint.length <= 2048 && !/[\\?#]/.test(endpoint));
  const url = new URL(endpoint);
  requireValue(url.protocol === "https:" && url.hostname === name && !url.username && !url.password && url.pathname === "/" &&
    (url.href === endpoint || url.href === `${endpoint}/`));
  return { endpoint, tls_server_name: name };
}
