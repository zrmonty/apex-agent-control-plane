import assert from "node:assert/strict";
import fs from "node:fs";
import files from "node:fs/promises";
import dns from "node:dns/promises";
import net from "node:net";
import tls from "node:tls";
import { syncBuiltinESMExports } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import ts from "typescript";
import { McpProxyPrivateDestinationAllowance, ProxyApprovalMode, type RuntimeConfiguration } from "@apex/contracts";
import { GatewayError } from "../contracts.js";
import { buildManagedRuntime } from "../live/managed-runtime.js";
import { assertExecutableRuntimeConfiguration } from "./executable-capabilities.js";
import { rustConfig, runtimeFixture } from "./testing/runtime-fixture.js";

const env = { APEX_MCP_PRINCIPAL: "spiffe://apex/agent/research", APEX_MCP_AGENT_ID: "research-agent",
  APEX_MCP_WORKSPACE_ID: "acme", APEX_MCP_NAMESPACE_ID: "prod", APEX_MCP_TRACE_ID: "trace-001" };

test("valid generated metadata with unsupported schema, approval or network requirements is not executable", () => {
  const changes: Array<(config: RuntimeConfiguration) => void> = [
    c => { c.toolSchemas[0].inputSchemaJson = '{"type":"object"}'; },
    c => { c.toolSchemas[0].outputSchemaJson = '{"type":"object","additionalProperties":false}'; },
    c => { c.approvalMode = ProxyApprovalMode.OPERATOR; c.spec!.governanceBinding!.approvalMode = "operator"; },
    c => { c.networkGrants[0].approvedCidrs = ["8.8.8.8/32"]; },
    c => {
      c.networkGrants[0].privateDestination = true; c.networkGrants[0].approvedCidrs = ["10.0.0.0/8"];
      c.spec!.runtimeProfile!.egressDestinations[0].privateDestinationAllowance = McpProxyPrivateDestinationAllowance.ALLOWED;
    },
  ];
  for (const change of changes) {
    const config = runtimeFixture(change); // Valid metadata and recomputed hash, not an integrity-only refusal.
    assert.throws(() => assertExecutableRuntimeConfiguration(config), (error: unknown) =>
      error instanceof GatewayError && error.code === "INVALID_INPUT");
  }
});

test("production refuses scope mismatches and unmet enforcement before file, DNS, socket, fetch or listener work", async t => {
  const config = runtimeFixture(c => { c.toolSchemas[0].outputProfileId = "unsupported"; });
  let io = 0;
  const forbidden = () => { io++; throw new Error("SENSITIVE-unexpected-IO"); };
  t.mock.method(files, "readFile", forbidden); t.mock.method(files, "open", forbidden);
  t.mock.method(fs, "readFileSync", forbidden); t.mock.method(dns, "lookup", forbidden);
  t.mock.method(net.Socket.prototype, "connect", forbidden); t.mock.method(tls, "connect", forbidden);
  t.mock.method(net.Server.prototype, "listen", forbidden); t.mock.method(globalThis, "fetch", forbidden);
  syncBuiltinESMExports();
  try {
    for (const [candidate, context, expected] of [
      [rustConfig, env, "GOVERNANCE_UNAVAILABLE"],
      [rustConfig, { ...env, APEX_MCP_WORKSPACE_ID: "other" }, "AUTHORIZATION_DENIED"],
      [rustConfig, { ...env, APEX_MCP_NAMESPACE_ID: "other" }, "AUTHORIZATION_DENIED"],
      [config, {}, "INVALID_INPUT"], // Capability refusal precedes even caller-context reads.
    ] as const) {
      await assert.rejects(() => buildManagedRuntime(candidate, context), (error: unknown) =>
        error instanceof GatewayError && error.code === expected && !error.message.includes("SENSITIVE"));
      assert.equal(io, 0);
    }
  } finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
});

test("the production entrypoint import graph never reaches the legacy managed model, CLI or test fixtures", async () => {
  const root = fileURLToPath(new URL("../", import.meta.url));
  const visited = new Set<string>();
  async function visit(file: string): Promise<void> {
    if (visited.has(file)) return;
    visited.add(file);
    const source = ts.createSourceFile(file, await files.readFile(file, "utf8"), ts.ScriptTarget.Latest, true);
    const dependencies: string[] = [];
    function scan(node: ts.Node): void {
      const specifier = ts.isImportDeclaration(node) || ts.isExportDeclaration(node) ? node.moduleSpecifier :
        ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword ? node.arguments[0] : undefined;
      if (specifier && ts.isStringLiteral(specifier) && specifier.text.startsWith(".")) {
        dependencies.push(path.resolve(path.dirname(file), specifier.text.replace(/\.js$/, ".ts")));
      }
      ts.forEachChild(node, scan);
    }
    scan(source);
    for (const dependency of dependencies) await visit(dependency);
  }
  await visit(path.join(root, "index.ts"));
  assert.ok(visited.has(path.join(root, "managed", "startup-loader.ts")));
  assert.ok(visited.has(path.join(root, "managed", "runtime-config.ts")));
  assert.ok(visited.has(path.join(root, "live", "managed-runtime.ts")));
  assert.ok(!visited.has(path.join(root, "managed", "config.ts")));
  assert.ok(!visited.has(path.join(root, "managed", "cli.ts")));
  assert.ok([...visited].every(file => !file.endsWith(".test.ts") && !file.includes(`${path.sep}testing${path.sep}`)));
});
