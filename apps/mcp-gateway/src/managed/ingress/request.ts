import type { IncomingMessage, ServerResponse } from "node:http";
import type { HeaderValues } from "../auth.js";
import { validateHttpIngressRequest, buildProtectedResourceMetadata } from "../http.js";
import type { ReadonlyRuntimeConfiguration } from "../runtime-config.js";
import { parseWireJson } from "../upstream-wire/json.js";
export const refused = () => new Error("managed ingress refused safely");
export const MAX_BODY = 1_048_576;
export const MAX_HEADERS = 64;
const sensitive = new Set(["host", "origin", "authorization", "mcp-session-id", "mcp-protocol-version",
  "content-type", "content-length", "transfer-encoding", "accept", "last-event-id"]);

export function inspect(req: IncomingMessage, config: ReadonlyRuntimeConfiguration) {
  // Node truncates rawHeaders at maxHeadersCount. Reject the boundary itself,
  // otherwise a duplicate sensitive header beyond it becomes invisible.
  if (req.rawHeaders.length >= MAX_HEADERS * 2) throw refused();
  const headers: Record<string, string[]> = Object.create(null);
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    const name = req.rawHeaders[i].toLowerCase(), value = req.rawHeaders[i + 1];
    const previous = headers[name];
    if (sensitive.has(name) && (previous || !value.length) || /[\x00-\x1f\x7f]/.test(value)) throw refused();
    (headers[name] ??= []).push(value);
  }
  const endpoint = new URL(config.resourceUrl), path = req.url;
  const method = req.method;
  if (method !== "POST" && method !== "GET" && method !== "DELETE" ||
    !path || !path.startsWith("/") || path.startsWith("//") || path.includes("\\") ||
    headers.host?.[0]?.toLowerCase() !== endpoint.host.toLowerCase() ||
    !config.spec!.ingress!.allowedOrigins.includes(headers.origin?.[0]) || headers["last-event-id"]) throw refused();
  const length = headers["content-length"]?.[0];
  const transfer = headers["transfer-encoding"]?.[0];
  if (transfer !== undefined && (transfer !== "chunked" || method !== "POST" || length !== undefined)) throw refused();
  if (length !== undefined && (!/^(0|[1-9][0-9]*)$/.test(length) || Number(length) > MAX_BODY)) throw refused();
  if (method !== "POST" && length !== undefined && length !== "0") throw refused();
  const metadata = method === "GET" && path === "/.well-known/oauth-protected-resource";
  if (metadata) return { headers: headers as HeaderValues, metadata, sessionId: undefined };
  if (path !== endpoint.pathname + endpoint.search) throw refused();
  // Validate DELETE with the same endpoint/session contract as GET, without changing the legacy listener.
  const validated = validateHttpIngressRequest({ method: method === "DELETE" ? "GET" : method,
    url: `https://${endpoint.host}${path}`, headers, bodyBytes: Number(length ?? 0) }, config);
  if (method !== "POST" && !validated.sessionId) throw refused();
  if (method === "POST" && !/^application\/json(?:\s*;|$)/i.test(headers["content-type"]?.[0] ?? "")) throw refused();
  return { headers: headers as HeaderValues, metadata, ...validated };
}
export async function readBody(req: IncomingMessage): Promise<unknown> {
  let size = 0; const chunks: Buffer[] = [];
  for await (const chunk of req) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.length; if (size > MAX_BODY) throw refused(); chunks.push(bytes);
  }
  if (req.method !== "POST") { if (size) throw refused(); return undefined; }
  return parseWireJson(Buffer.concat(chunks));
}
export function respond(res: ServerResponse, status: number, body: unknown,
  headers: Record<string, string> = {}) {
  if (res.destroyed) return;
  if (res.headersSent) { res.destroy(); return; }
  const text = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(text), ...headers });
  res.end(text);
}
export function metadataResponse(res: ServerResponse, config: ReadonlyRuntimeConfiguration) {
  respond(res, 200, buildProtectedResourceMetadata(config));
}
