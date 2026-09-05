import assert from "node:assert/strict";
import test from "node:test";

import { GatewayError } from "../contracts.js";
import { componentFixture } from "./testing/runtime-fixture.js";
import {
  buildProtectedResourceMetadata,
  validateHttpIngressRequest,
  type HttpIngressRequest,
} from "./http.js";

const config = componentFixture();

const request: HttpIngressRequest = {
  method: "POST",
  url: "https://proxy.example.test/mcp",
  headers: {
    host: ["proxy.example.test"],
    origin: ["https://console.example.test"],
    "content-length": ["24"],
    "mcp-session-id": ["session-123"],
    "mcp-protocol-version": ["2025-11-25"],
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
  assert.deepEqual(metadata.authorization_servers, ["https://issuer.example.test"]);
  assert.equal(JSON.stringify(metadata).includes("secret://"), false);
  assert.equal(JSON.stringify(metadata).includes(config.proxyId), false);
});

test("advertises every configured scope without a hardcoded default", () => {
  const scoped = componentFixture(value => { value.auth!.requiredScopes = ["portfolio:read", "evidence:admit"]; });
  assert.deepEqual(buildProtectedResourceMetadata(scoped).scopes_supported, ["portfolio:read", "evidence:admit"]);
});

test("session requests reject absent, duplicate or unsupported protocol revisions", () => {
  for (const version of [undefined, ["2025-06-18"], ["2025-11-25", "2025-11-25"]]) {
    assertRejected({ ...request, headers: { ...request.headers, "mcp-protocol-version": version } });
  }
});
