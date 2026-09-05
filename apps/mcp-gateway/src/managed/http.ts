import { GatewayError } from "../contracts.js";
import { readHeaderValues, type HeaderValues } from "./auth.js";
import { McpProxyTransport } from "@apex/contracts";
import type { ReadonlyRuntimeConfiguration } from "./runtime-config.js";
import { runtimeAuth, runtimeSpec } from "./runtime-types.js";

const MAX_BODY_BYTES = 1_048_576;
const SESSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export type HttpIngressRequest = Readonly<{
  method: "GET" | "POST";
  url: string;
  headers: HeaderValues;
  bodyBytes: number;
}>;

export type ValidatedHttpIngress = Readonly<{ sessionId?: string }>;

export type ProtectedResourceMetadata = Readonly<{
  resource: string;
  authorization_servers: readonly string[];
  bearer_methods_supported: readonly ["header"];
  scopes_supported: readonly string[];
}>;

export function validateHttpIngressRequest(
  request: HttpIngressRequest,
  config: ReadonlyRuntimeConfiguration,
): ValidatedHttpIngress {
  if (
    runtimeSpec(config).ingress!.transport !== McpProxyTransport.STREAMABLE_HTTP ||
    !Number.isSafeInteger(request.bodyBytes) ||
    request.bodyBytes < 0 ||
    request.bodyBytes > MAX_BODY_BYTES
  ) {
    throw rejected();
  }
  const endpoint = parseHttpsUrl(config.resourceUrl);
  let target: URL;
  try {
    target = new URL(request.url);
  } catch {
    throw rejected();
  }
  const host = singleHeader(request.headers, "host");
  const origin = singleHeader(request.headers, "origin");
  if (
    host === undefined ||
    origin === undefined ||
    host.toLowerCase() !== endpoint.host.toLowerCase() ||
    !runtimeSpec(config).ingress!.allowedOrigins.includes(origin) ||
    (target.protocol !== "https:" && !isLocalhost(host)) ||
    target.host.toLowerCase() !== endpoint.host.toLowerCase() ||
    target.pathname !== endpoint.pathname ||
    target.search !== endpoint.search ||
    target.username !== "" ||
    target.password !== "" ||
    target.hash !== "" ||
    !["GET", "POST"].includes(request.method)
  ) {
    throw rejected();
  }
  const contentLength = singleHeader(request.headers, "content-length");
  if (
    contentLength !== undefined &&
    (!/^\d+$/.test(contentLength) || Number(contentLength) !== request.bodyBytes)
  ) {
    throw rejected();
  }
  const sessionId = singleHeader(request.headers, "mcp-session-id");
  if (sessionId !== undefined && !SESSION_PATTERN.test(sessionId)) {
    throw rejected();
  }
  const versions = readHeaderValues(request.headers, "mcp-protocol-version");
  if ((sessionId !== undefined || versions.length > 0) &&
    (versions.length !== 1 || versions[0] !== runtimeSpec(config).ingress!.protocolRevision)) throw rejected();
  return { sessionId };
}

export function buildProtectedResourceMetadata(
  config: ReadonlyRuntimeConfiguration,
): ProtectedResourceMetadata {
  const resource = parseHttpsUrl(config.resourceUrl);
  const auth = runtimeAuth(config);
  return {
    resource: resource.toString(),
    authorization_servers: [auth.issuer],
    bearer_methods_supported: ["header"],
    scopes_supported: auth.requiredScopes,
  };
}

function parseHttpsUrl(value: string | undefined): URL {
  if (value === undefined) {
    throw rejected();
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw rejected();
  }
  if (url.protocol !== "https:" || url.username || url.password || url.hash) {
    throw rejected();
  }
  return url;
}

function singleHeader(headers: HeaderValues, name: string): string | undefined {
  const values = readHeaderValues(headers, name);
  return values.length === 1 && values[0].length > 0 ? values[0] : undefined;
}

function isLocalhost(host: string): boolean {
  return host.toLowerCase().split(":")[0] === "localhost";
}

function rejected(): GatewayError {
  return new GatewayError("INVALID_INPUT", "HTTP ingress request rejected safely");
}
