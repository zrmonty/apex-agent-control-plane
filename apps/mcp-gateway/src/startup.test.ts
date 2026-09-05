import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile, truncate } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { artifactPath, artifactText } from "./managed/testing/runtime-fixture.js";
import { parseProxyRevisionConfig } from "./managed/config.js";
import { runNode } from "./testing/node-runner.js";

const packageRoot = fileURLToPath(new URL("../", import.meta.url));
const initialize = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {
  protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "startup-fixture", version: "1" } } }) + "\n";

async function runStartup(overrides: NodeJS.ProcessEnv) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("APEX_MCP_")));
  Object.assign(env, { APEX_MCP_PRINCIPAL: "spiffe://apex/agent/research", APEX_MCP_AGENT_ID: "research-agent",
    APEX_MCP_WORKSPACE_ID: "acme", APEX_MCP_NAMESPACE_ID: "prod", APEX_MCP_TRACE_ID: "trace-001",
    APEX_MCP_GOVERNANCE_MODE: "local", ...overrides });
  const result = await runNode({ cwd: packageRoot, entrypoint: "src/index.ts", env, input: initialize });
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

test("actual entrypoint retains standalone stdio only when no managed source is supplied", async () => {
  const result = await runStartup({});
  assert.equal(result.code, 0);
  assert.equal(result.reaped, true);
  assert.throws(() => process.kill(result.pid!, 0), { code: "ESRCH" });
  const reply = JSON.parse(result.stdout.trim());
  assert.equal(reply.id, 1);
  assert.ok(reply.result.capabilities.tools);
});

test("actual entrypoint accepts the Rust file metadata but refuses unmet runtime enforcement without fallback", async () => {
  const result = await runStartup({ APEX_MCP_PROXY_REVISION_CONFIG_FILE: artifactPath });
  assertRefused(result, "GOVERNANCE_UNAVAILABLE");
  assert.match(result.stderr, /managed runtime enforcement is unavailable safely/);
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
