import { isIP } from "node:net";

import { GatewayError } from "../contracts.js";

const SAFE_PORTS = new Set([443, 8443, 9443]);
const IPV4_OCTET_COUNT = 4;

export function validateHttpsDestination(
  value: string,
  declaredHosts: readonly string[],
): URL {
  let endpoint: URL;
  try {
    endpoint = new URL(value);
  } catch {
    throw rejected();
  }

  const hostname = normalizeHostname(endpoint.hostname);
  const port = endpoint.port.length === 0 ? 443 : Number(endpoint.port);
  if (
    endpoint.protocol !== "https:" ||
    endpoint.username.length > 0 ||
    endpoint.password.length > 0 ||
    endpoint.hash.length > 0 ||
    hostname.length === 0 ||
    !Number.isInteger(port) ||
    !SAFE_PORTS.has(port) ||
    !declaredHosts.some((declared) => normalizeHostname(declared) === hostname) ||
    isObviouslyPrivateHostname(hostname)
  ) {
    throw rejected();
  }

  return endpoint;
}

export function validateResolvedAddresses(hostname: string, addresses: readonly string[]): void {
  if (hostname.length === 0 || addresses.length === 0 || addresses.some((address) => !isPublicAddress(address))) {
    throw rejected();
  }
}

export function validateRedirect(
  original: URL,
  location: string,
  declaredHosts: readonly string[],
): URL {
  const redirected = validateHttpsDestination(location, declaredHosts);
  if (redirected.origin !== original.origin) {
    throw rejected();
  }
  return redirected;
}

function normalizeHostname(value: string): string {
  return value.replace(/^\[|\]$/g, "").toLowerCase();
}

function isObviouslyPrivateHostname(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal") ||
    hostname === "metadata.google.internal" ||
    isIP(hostname) !== 0
  );
}

function isPublicAddress(value: string): boolean {
  const address = normalizeHostname(value);
  const version = isIP(address);
  if (version === 4) {
    return isPublicIpv4(address);
  }
  if (version === 6) {
    return isPublicIpv6(address);
  }
  return false;
}

function isPublicIpv4(value: string): boolean {
  const octets = value.split(".").map(Number);
  if (octets.length !== IPV4_OCTET_COUNT || octets.some((octet) => !Number.isInteger(octet))) {
    return false;
  }
  const [first, second, third] = octets;
  return !(
    first === 0 ||
    first === 10 ||
    first === 127 ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 0 && third === 0) ||
    (first === 192 && second === 0 && third === 2) ||
    (first === 192 && second === 168) ||
    (first === 198 && second >= 18 && second <= 19) ||
    (first === 198 && second === 51 && third === 100) ||
    (first === 203 && second === 0 && third === 113) ||
    first >= 224
  );
}

function isPublicIpv6(value: string): boolean {
  const normalized = value.toLowerCase();
  if (
    normalized === "::" ||
    normalized === "::1" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe8") ||
    normalized.startsWith("fe9") ||
    normalized.startsWith("fea") ||
    normalized.startsWith("feb") ||
    normalized.startsWith("ff") ||
    normalized.startsWith("2001:db8:")
  ) {
    return false;
  }
  if (normalized.startsWith("::ffff:")) {
    return isPublicIpv4(normalized.slice("::ffff:".length));
  }
  return true;
}

function rejected(): GatewayError {
  return new GatewayError("INVALID_INPUT", "network destination rejected safely");
}
