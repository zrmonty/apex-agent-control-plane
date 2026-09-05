import assert from "node:assert/strict";
import test from "node:test";

import { McpProxyToolClassification } from "@apex/contracts";
import type { RuntimeUpstream as UpstreamConfig } from "./runtime-types.js";
import { componentFixture } from "./testing/runtime-fixture.js";
import { compileExposedToolIndexes, createUpstreamSessions, type UpstreamTransport } from "./upstream.js";

const config = (proxyId: string, credentialRef: string) => componentFixture(value => {
  value.proxyId = proxyId;
  value.spec!.upstreams[0].credentialRef = credentialRef;
  value.secretRefs = [credentialRef];
});
const fixtureTool = componentFixture().spec!.exposedTools[0];

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

test("compiles alias and upstream tool indexes without changing configured order", () => {
  const multi = componentFixture(value => {
    value.spec!.upstreams.push({ ...value.spec!.upstreams[0], upstreamId: "secondary" });
    value.spec!.exposedTools.push({ ...value.spec!.exposedTools[0], upstreamId: "secondary", alias: "secondary.read" });
    value.toolSchemas.push({ ...value.toolSchemas[0], upstreamId: "secondary" });
  });
  const indexes = compileExposedToolIndexes(multi);

  assert.equal(indexes.byAlias.get("portfolio.read")?.upstreamId, "portfolio");
  assert.equal(indexes.byAlias.get("secondary.read")?.upstreamId, "secondary");
  assert.deepEqual(indexes.byUpstream.get("portfolio")?.map((tool) => tool.alias), ["portfolio.read"]);
  assert.deepEqual(indexes.byUpstream.get("secondary")?.map((tool) => tool.alias), ["secondary.read"]);
});

test("quarantines discovery and refuses tools that are not explicitly exposed", async () => {
  const transport = new FakeTransport();
  const sessions = createUpstreamSessions(config("018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e84", "secret://a"), transport);
  const session = sessions.get("portfolio");
  assert.ok(session);

  await assert.rejects(() => session.call({
    ...fixtureTool,
    upstreamId: "portfolio",
    toolName: "portfolio.read",
    alias: "portfolio.read",
    classification: McpProxyToolClassification.READ,
  }, {}));
  const catalog = await session.discover();
  assert.equal(catalog.upstreamId, "portfolio");
  assert.equal(catalog.tools.length, 2);
  await assert.rejects(() => session.call({
    ...fixtureTool,
    upstreamId: "portfolio",
    toolName: "portfolio.write",
    alias: "portfolio.write",
    classification: McpProxyToolClassification.BUSINESS_WRITE,
  }, {}));
  await session.call({
    ...fixtureTool,
    upstreamId: "portfolio",
    toolName: "portfolio.read",
    alias: "portfolio.read",
    classification: McpProxyToolClassification.READ,
  }, {});
  assert.deepEqual(transport.calls, ["secret://a:portfolio.read"]);
});

test("closes every session without sharing transport state", async () => {
  const transport = new FakeTransport();
  const sessions = createUpstreamSessions(config("018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e84", "secret://a"), transport);
  await Promise.all([...sessions.values()].map((session) => session.close()));
  assert.equal(sessions.size, 1);
});
