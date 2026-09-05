import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile, truncate } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { ReadBuffer, serializeMessage } from "@modelcontextprotocol/sdk/shared/stdio.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { artifactPath, artifactText } from "./managed/testing/runtime-fixture.js";
import { parseProxyRevisionConfig } from "./managed/config.js";
import { runNode } from "./testing/node-runner.js";

const packageRoot = fileURLToPath(new URL("../", import.meta.url));
const initialize = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {
  protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "startup-fixture", version: "1" } } }) + "\n";

function startupEnvironment(overrides: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("APEX_MCP_") && key !== "NODE_ENV"));
  Object.assign(env, { APEX_MCP_PRINCIPAL: "spiffe://apex/agent/research", APEX_MCP_AGENT_ID: "research-agent",
    APEX_MCP_WORKSPACE_ID: "acme", APEX_MCP_NAMESPACE_ID: "prod", APEX_MCP_TRACE_ID: "trace-001",
    APEX_MCP_GOVERNANCE_MODE: "live", ...overrides });
  return env;
}

async function runStartup(overrides: NodeJS.ProcessEnv) {
  const result = await runNode({ cwd: packageRoot, entrypoint: "src/index.ts", env: startupEnvironment(overrides), input: initialize });
  return { ...result, stdout: result.stdout.toString("utf8"), stderr: result.stderr.toString("utf8") };
}

function assertRefused(result: Awaited<ReturnType<typeof runStartup>>, code = "INVALID_INPUT") {
  assert.equal(result.code, 1);
  assert.equal(result.reaped, true);
  assert.throws(() => process.kill(result.pid!, 0), { code: "ESRCH" });
  assert.equal(result.stdout, "", "a supplied managed config must never open standalone stdio");
  assert.match(result.stderr, new RegExp(`^${code}: [^\\r\\n]+\\r?\\n$`));
  assert.ok(!result.stderr.includes("SENSITIVE"));
}

test("actual SDK initializes and lists only the read-only portfolio tool behind both explicit development selectors", async () => {
  const client = new Client({ name: "startup-fixture", version: "1" });
  const buffer = new ReadBuffer({ maxBufferSize: 16384 });
  let send: (input: string) => void;
  let closed = false;
  let tools: Awaited<ReturnType<Client["listTools"]>> | undefined;
  let version: ReturnType<Client["getServerVersion"]>;
  let capabilities: ReturnType<Client["getServerCapabilities"]>;
  const close = () => {
    if (closed) return;
    closed = true;
    buffer.clear();
    transport.onclose?.(); // Also cancels pending SDK requests on runner failure.
  };
  const transport: Transport = {
    start: async () => {}, send: async message => send(serializeMessage(message)), close: async () => close(),
  };
  const result = await runNode({ cwd: packageRoot, entrypoint: "src/index.ts",
    env: startupEnvironment({ APEX_MCP_PROFILE: "development-standalone", NODE_ENV: "development",
      APEX_MCP_GOVERNANCE_MODE: "local" }), dialogue: {
      start: async write => {
        send = write;
        await client.connect(transport);
        version = client.getServerVersion();
        capabilities = client.getServerCapabilities();
        tools = await client.listTools();
        await client.close();
      },
      receive: chunk => {
        buffer.append(chunk);
        for (let message = buffer.readMessage(); message !== null; message = buffer.readMessage()) transport.onmessage?.(message);
      },
      close,
    } });
  assert.equal(result.code, 0);
  assert.equal(result.stderr.byteLength, 0);
  assert.equal(result.reaped, true);
  assert.throws(() => process.kill(result.pid!, 0), { code: "ESRCH" });
  assert.equal(closed, true);
  assert.equal(version?.name, "apex-mcp-gateway");
  assert.ok(capabilities?.tools);
  assert.deepEqual(tools?.tools.map(tool => tool.name), ["portfolio.read"]);
  assert.equal(tools.tools[0]?.inputSchema.additionalProperties, false);
  assert.deepEqual(Object.keys(tools.tools[0]?.inputSchema.properties ?? {}).sort(), ["asOf", "portfolioId"]);
});

test("default production entrypoint refuses missing managed configuration instead of serving stdio", async () => {
  for (const profile of [undefined, "managed"]) {
    assertRefused(await runStartup({ NODE_ENV: "production", APEX_MCP_PROFILE: profile, APEX_MCP_GOVERNANCE_MODE: "local" }));
  }
});

test("profile selection rejects unknown, empty and inexact selectors before reading a supplied file", async () => {
  for (const profile of ["", " ", "managed ", " managed", "MANAGED", "development-standalone ", "SENSITIVE"]) {
    const result = await runStartup({ APEX_MCP_PROFILE: profile, APEX_MCP_PROXY_REVISION_CONFIG_FILE: "SENSITIVE-missing-file" });
    assertRefused(result);
    assert.equal(result.stderr.trim(), "INVALID_INPUT: gateway process profile rejected safely");
  }
});

test("NODE_ENV alone never selects development and managed requires the exact live mode", async () => {
  assertRefused(await runStartup({ NODE_ENV: "development", APEX_MCP_GOVERNANCE_MODE: "local" }));
  for (const mode of [undefined, "", " ", "local", " live", "live ", "LIVE", "SENSITIVE"]) {
    const result = await runStartup({ APEX_MCP_PROFILE: "managed", APEX_MCP_GOVERNANCE_MODE: mode,
      APEX_MCP_PROXY_REVISION_CONFIG_FILE: artifactPath });
    assertRefused(result);
    assert.equal(result.stderr.trim(), "INVALID_INPUT: gateway process profile rejected safely");
  }
});

test("development requires exact NODE_ENV and rejects every supplied managed source even if empty", async () => {
  const development = { APEX_MCP_PROFILE: "development-standalone", NODE_ENV: "development", APEX_MCP_GOVERNANCE_MODE: "local" };
  for (const nodeEnv of [undefined, "", " ", "production", "Development", " development", "development "]) {
    assertRefused(await runStartup({ ...development, NODE_ENV: nodeEnv }));
  }
  for (const source of ["APEX_MCP_PROXY_REVISION_CONFIG", "APEX_MCP_PROXY_REVISION_CONFIG_FILE"]) {
    for (const value of ["", " ", artifactPath]) {
      const result = await runStartup({ ...development, [source]: value });
      assertRefused(result);
      assert.equal(result.stderr.trim(), "INVALID_INPUT: gateway process profile rejected safely");
    }
  }
  assertRefused(await runStartup({ ...development, APEX_MCP_PROXY_REVISION_CONFIG: "",
    APEX_MCP_PROXY_REVISION_CONFIG_FILE: artifactPath }));
});

test("actual entrypoint accepts the Rust file metadata but refuses unmet runtime enforcement without fallback", async () => {
  for (const profile of [undefined, "managed"]) {
    const result = await runStartup({ APEX_MCP_PROFILE: profile, APEX_MCP_PROXY_REVISION_CONFIG_FILE: artifactPath });
    assertRefused(result, "GOVERNANCE_UNAVAILABLE");
    assert.match(result.stderr, /managed runtime enforcement is unavailable safely/);
  }
});

test("empty, inline, ambiguous and unreadable managed sources cannot select standalone", async () => {
  for (const env of [
    { APEX_MCP_PROXY_REVISION_CONFIG: "" }, { APEX_MCP_PROXY_REVISION_CONFIG: "  " },
    { APEX_MCP_PROXY_REVISION_CONFIG_FILE: "" }, { APEX_MCP_PROXY_REVISION_CONFIG_FILE: "  " },
    { APEX_MCP_PROXY_REVISION_CONFIG_FILE: "SENSITIVE-missing-file" },
    { APEX_MCP_PROXY_REVISION_CONFIG: artifactText },
    { APEX_MCP_PROXY_REVISION_CONFIG: "", APEX_MCP_PROXY_REVISION_CONFIG_FILE: artifactPath },
  ]) assertRefused(await runStartup(env));
});

test("startup file boundary rejects non-files, oversized, empty and strict-wire-invalid original text", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "apex-startup-fixture-"));
  try {
    assertRefused(await runStartup({ APEX_MCP_PROXY_REVISION_CONFIG_FILE: root }));
    const file = path.join(root, "runtime.json");
    for (const text of ["", " ", "SENSITIVE-not-json", Buffer.from([0xff, 0xfe, 0x80]),
      '{"schemaVersion":1,' + artifactText.trimStart().slice(1),
      '{"unknownField":"SENSITIVE",' + artifactText.trimStart().slice(1),
      artifactText.replace('"schemaVersion": 1', '"schemaVersion": 2'),
      artifactText.replace("db5ddc4670e5f901240e1c2910d9f78dd8a65237c86f197d13938be967afe5da", "b".repeat(64)),
      artifactText.replace("MCP_PROXY_TRANSPORT_STREAMABLE_HTTP", "UNKNOWN_TRANSPORT"),
    ]) {
      await writeFile(file, text);
      assertRefused(await runStartup({ APEX_MCP_PROXY_REVISION_CONFIG_FILE: file }));
    }
    await truncate(file, 262145);
    assertRefused(await runStartup({ APEX_MCP_PROXY_REVISION_CONFIG_FILE: file }));
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("an otherwise valid legacy revision file is rejected without old/new parser fallback", async () => {
  // Rejection-only legacy fixture; never used as the generated acceptance oracle.
  const legacy = parseProxyRevisionConfig({ proxyId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e84",
    revisionId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e85", configHash: "a".repeat(64),
    ingress: { transport: "streamable-http", endpoint: "https://proxy.example.test/mcp", allowedOrigins: [] },
    upstreams: [{ upstreamId: "portfolio", transport: "streamable-http", endpointOrCommandRef: "https://portfolio.example.test/mcp",
      credentialRef: "secret://portfolio/read" }],
    exposedTools: [{ upstreamId: "portfolio", toolName: "portfolio.read", alias: "portfolio.read", classification: "read" }],
    cliProfiles: [], authBindings: [{ bindingId: "inbound", direction: "inbound", audience: "apex-mcp-proxy" }],
    governance: { policyId: "policy-portfolio-read", approvalMode: "none", classification: "confidential" },
    runtime: { imageDigest: "sha256:" + "b".repeat(64), cpuMillis: 500, memoryBytes: 268435456, pidLimit: 128,
      readOnlyRootfs: true, networkMode: "declared-egress", noNewPrivileges: true, droppedCapabilities: ["ALL"] } });
  const root = await mkdtemp(path.join(tmpdir(), "apex-startup-legacy-"));
  try {
    const file = path.join(root, "legacy.json");
    await writeFile(file, JSON.stringify(legacy));
    assertRefused(await runStartup({ APEX_MCP_PROXY_REVISION_CONFIG_FILE: file }));
  } finally { await rm(root, { recursive: true, force: true }); }
});
