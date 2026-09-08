import { McpProxyTransport } from "@apex/contracts";
import { assertRuntimeMaterialsStage, runtimeUpstreamMaterial, type RuntimeMaterials } from "../bootstrap/runtime-materials.js";
import type { StageOwner } from "../bootstrap/stage-owner.js";
import { GuardedTlsConnector } from "../guard/tls-connector.js";
import { OwnedHttpClient } from "../guard/http-owner.js";
import { OwnedMcpSession } from "../upstream-wire/session.js";
import { refused } from "./types.js";

/** No ambient DNS, credential resolution or direct upstream socket. The only
 * dialer uses the stage's fixed guard; that guard owns DNS/IP intersections. */
export function createUpstream(stage: StageOwner, materials: RuntimeMaterials, now: () => bigint) {
  assertRuntimeMaterialsStage(materials, stage);
  const config = stage.documents.config, spec = config.spec!, network = stage.network;
  if (!network || spec.upstreams.length !== 1 || spec.exposedTools.length !== 1 || config.toolSchemas.length !== 1) throw refused();
  const upstream = spec.upstreams[0], tool = spec.exposedTools[0], schema = config.toolSchemas[0];
  const url = new URL(upstream.endpointOrCommandRef);
  if (upstream.transport !== McpProxyTransport.STREAMABLE_HTTP || url.protocol !== "https:" || url.username || url.password ||
    url.hash || url.hostname !== upstream.serverIdentity || tool.upstreamId !== upstream.upstreamId ||
    schema.upstreamId !== upstream.upstreamId || schema.toolName !== tool.toolName) throw refused();
  const material = runtimeUpstreamMaterial(materials, upstream.credentialRef);
  let connector: GuardedTlsConnector | undefined, http: OwnedHttpClient | undefined;
  try {
    connector = new GuardedTlsConnector({ address: network.guardAddress, port: network.guardPort }, [{
      id: "upstream", host: url.hostname, port: Number(url.port) || 443, ca: material.serverCa,
      authentication: material.clientCert ? "mutual_tls" : "server_tls", alpn: "http/1.1",
      ...(material.clientCert ? { cert: material.clientCert, key: material.clientKey } : {}),
    }], now);
    http = new OwnedHttpClient(connector, { destinationId: "upstream", url: url.href,
      ...(material.token ? { bearerToken: material.token.toString("ascii") } : {}) }, now);
    const session = new OwnedMcpSession(http, [{ name: tool.toolName,
      inputSchema: JSON.parse(schema.inputSchemaJson), outputSchema: JSON.parse(schema.outputSchemaJson) }], now);
    let closed: Promise<void> | undefined;
    return { session, alias: tool.alias, toolName: tool.toolName, close() {
      return closed ??= Promise.all([session.close(), connector!.close()]).then(() => undefined);
    } };
  } catch {
    // Constructors do no I/O; these close calls only wipe owned copies.
    void http?.close(); void connector?.close(); throw refused();
  } finally { for (const bytes of Object.values(material)) bytes.fill(0); }
}
