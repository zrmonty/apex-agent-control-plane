import assert from "node:assert/strict";
import test from "node:test";

import { GatewayError } from "../contracts.js";
import type { ProxyRevisionConfig } from "./config.js";
import {
  buildProtectedResourceMetadata,
  validateHttpIngressRequest,
  type HttpIngressRequest,
} from "./http.js";

const config = {
  proxyId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e84",
  revisionId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e85",
  configHash: "a".repeat(64),
  ingress: { transport: "streamable-http", endpoint: "https://proxy.example.test/mcp", allowedOrigins: ["https://console.example.test"] },
  upstreams: [],
  exposedTools: [],
  cliProfiles: [],
  authBindings: [{ bindingId: "inbound", direction: "inbound" }],
  governance: { policyId: "policy-read", approvalMode: "none", classification: "confidential" },
  runtime: { imageDigest: "sha256:" + "b".repeat(64), cpuMillis: 500, memoryBytes: 268_435_456, pidLimit: 128, readOnlyRootfs: true, networkMode: "declared-egress", noNewPrivileges: true, droppedCapabilities: ["ALL"] },
} as unknown as ProxyRevisionConfig;

const request: HttpIngressRequest = {
  method: "POST",
  url: "https://proxy.example.test/mcp",
  headers: {
    host: ["proxy.example.test"],
    origin: ["https://console.example.test"],
    "content-length": ["24"],
    "mcp-session-id": ["session-123"],
  },
  bodyBytes: 24,
};

function assertRejected(value: HttpIngressRequest): void {
  assert.throws(
    () => validateHttpIngressRequest(value, config),
    (error: unknown) => error instanceof GatewayError && error.code === "INVALID_INPUT",
  );
}

test("accepts a bounded HTTPS ingress request from an allowed origin", () => {
  const result = validateHttpIngressRequest(request, config);
  assert.equal(result.sessionId, "session-123");
});

test("rejects invalid origin, host, scheme, duplicate headers, and oversized bodies", () => {
  assertRejected({ ...request, headers: { ...request.headers, origin: ["https://evil.example.test"] } });
  assertRejected({ ...request, headers: { ...request.headers, host: ["other.example.test"] } });
  assertRejected({ ...request, url: "http://proxy.example.test/mcp" });
  assertRejected({ ...request, url: "https://proxy.example.test/other" });
  assertRejected({ ...request, headers: { ...request.headers, host: ["proxy.example.test", "proxy.example.test"] } });
  assertRejected({ ...request, bodyBytes: 1_048_577 });
});

test("publishes metadata without tokens, secrets, or proxy internals", () => {
  const metadata = buildProtectedResourceMetadata(config);
  assert.equal(metadata.resource, "https://proxy.example.test/mcp");
  assert.deepEqual(metadata.authorization_servers, ["https://proxy.example.test"]);
  assert.equal(JSON.stringify(metadata).includes("secret://"), false);
  assert.equal(JSON.stringify(metadata).includes(config.proxyId), false);
});
