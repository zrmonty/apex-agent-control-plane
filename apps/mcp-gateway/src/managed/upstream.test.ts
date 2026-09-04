import assert from "node:assert/strict";
import test from "node:test";

import type { ProxyRevisionConfig, UpstreamConfig } from "./config.js";
import { createUpstreamSessions, type UpstreamTransport } from "./upstream.js";

const config = (proxyId: string, credentialRef: string): ProxyRevisionConfig => ({
  proxyId,
  revisionId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e85",
  configHash: "a".repeat(64),
  ingress: {
    transport: "stdio",
    allowedOrigins: [],
  },
  upstreams: [
    {
      upstreamId: "portfolio",
      transport: "streamable-http",
      endpointOrCommandRef: "https://portfolio.example.test/mcp",
      credentialRef,
    },
  ],
  exposedTools: [
    {
      upstreamId: "portfolio",
      toolName: "portfolio.read",
      alias: "portfolio.read",
      classification: "read",
    },
  ],
  cliProfiles: [],
  authBindings: [{ bindingId: "inbound", direction: "inbound" }],
  governance: { policyId: "policy-read", approvalMode: "none", classification: "confidential" },
  runtime: {
    imageDigest: "sha256:" + "b".repeat(64),
    cpuMillis: 500,
    memoryBytes: 268_435_456,
    pidLimit: 128,
    readOnlyRootfs: true,
    networkMode: "declared-egress",
    noNewPrivileges: true,
    droppedCapabilities: ["ALL"],
  },
});

class FakeTransport implements UpstreamTransport {
  readonly discoveries: string[] = [];
  readonly calls: string[] = [];
  readonly configs: UpstreamConfig[] = [];

  async discover(upstream: UpstreamConfig): Promise<unknown> {
    this.configs.push(upstream);
    this.discoveries.push(upstream.credentialRef ?? "none");
    return { tools: [{ name: "portfolio.read" }, { name: "portfolio.write" }] };
  }

  async call(upstream: UpstreamConfig, toolName: string): Promise<unknown> {
    this.calls.push(`${upstream.credentialRef}:${toolName}`);
    return { ok: true };
  }

  async close(): Promise<void> {}
}

test("creates isolated sessions, catalogs, and credential inputs per proxy", async () => {
  const transportA = new FakeTransport();
  const transportB = new FakeTransport();
  const sessionsA = createUpstreamSessions(config("018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e84", "secret://a"), transportA);
  const sessionsB = createUpstreamSessions(config("018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e86", "secret://b"), transportB);
  const sessionA = sessionsA.get("portfolio");
  const sessionB = sessionsB.get("portfolio");

  assert.ok(sessionA);
  assert.ok(sessionB);
  assert.notEqual(sessionA, sessionB);
  assert.notEqual(sessionsA, sessionsB);
  await sessionA.discover();
  await sessionB.discover();
  assert.deepEqual(transportA.discoveries, ["secret://a"]);
  assert.deepEqual(transportB.discoveries, ["secret://b"]);
});

test("quarantines discovery and refuses tools that are not explicitly exposed", async () => {
  const transport = new FakeTransport();
  const sessions = createUpstreamSessions(config("018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e84", "secret://a"), transport);
  const session = sessions.get("portfolio");
  assert.ok(session);

  await assert.rejects(() => session.call({
    upstreamId: "portfolio",
    toolName: "portfolio.read",
    alias: "portfolio.read",
    classification: "read",
  }, {}));
  const catalog = await session.discover();
  assert.equal(catalog.upstreamId, "portfolio");
  assert.equal(catalog.tools.length, 2);
  await assert.rejects(() => session.call({
    upstreamId: "portfolio",
    toolName: "portfolio.write",
    alias: "portfolio.write",
    classification: "business-write",
  }, {}));
  await session.call({
    upstreamId: "portfolio",
    toolName: "portfolio.read",
    alias: "portfolio.read",
    classification: "read",
  }, {});
  assert.deepEqual(transport.calls, ["secret://a:portfolio.read"]);
});

test("closes every session without sharing transport state", async () => {
  const transport = new FakeTransport();
  const sessions = createUpstreamSessions(config("018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e84", "secret://a"), transport);
  await Promise.all([...sessions.values()].map((session) => session.close()));
  assert.equal(sessions.size, 1);
});
