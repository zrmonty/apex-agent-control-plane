import { GatewayError } from "../contracts.js";
import type { HeaderValues } from "./auth.js";
import type { ProxyRevisionConfig } from "./config.js";

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
  scopes_supported: readonly ["mcp:proxy:invoke"];
}>;

export function validateHttpIngressRequest(
  request: HttpIngressRequest,
  config: ProxyRevisionConfig,
): ValidatedHttpIngress {
  if (
    config.ingress.transport !== "streamable-http" ||
    !Number.isSafeInteger(request.bodyBytes) ||
    request.bodyBytes < 0 ||
    request.bodyBytes > MAX_BODY_BYTES
  ) {
    throw rejected();
  }
  const endpoint = parseHttpsUrl(config.ingress.endpoint);
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
    !config.ingress.allowedOrigins.includes(origin) ||
    (target.protocol !== "https:" && !isLocalhost(host)) ||
    target.host.toLowerCase() !== endpoint.host.toLowerCase() ||
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
  return { sessionId };
}

export function buildProtectedResourceMetadata(
  config: ProxyRevisionConfig,
): ProtectedResourceMetadata {
  const resource = parseHttpsUrl(config.ingress.endpoint);
  const inbound = config.authBindings.find((binding) => binding.direction === "inbound");
  const authorizationServer = inbound?.issuer ?? resource.origin;
  return {
    resource: resource.toString(),
    authorization_servers: [authorizationServer],
    bearer_methods_supported: ["header"],
    scopes_supported: ["mcp:proxy:invoke"],
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
  const values = Object.entries(headers)
    .filter(([key]) => key.toLowerCase() === name)
    .flatMap(([, value]) => value ?? []);
  return values.length === 1 && values[0].length > 0 ? values[0] : undefined;
}

function isLocalhost(host: string): boolean {
  return host.toLowerCase().split(":")[0] === "localhost";
}

function rejected(): GatewayError {
  return new GatewayError("INVALID_INPUT", "HTTP ingress request rejected safely");
}
