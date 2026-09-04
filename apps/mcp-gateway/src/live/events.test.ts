import assert from "node:assert/strict";
import test from "node:test";

import type { ToolExecutionEvent } from "../contracts.js";
import {
  canonicalizeJson,
  createToolEventEnvelope,
  jsonToStruct,
  structToJson,
} from "./events.js";

const event: ToolExecutionEvent = {
  caller: {
    principal: "spiffe://apex/agent/research",
    agentId: "research-agent",
  },
  scope: { workspaceId: "northstar", namespaceId: "research" },
  tool: "portfolio.read",
  action: "read",
  resource: "portfolio:sha256:8994d7d97baa4a58a0fbc8192815c60605caa16a9106d50af6548810f52eaf31",
  backend: "local-portfolio",
  status: "succeeded",
  latencyMs: 12,
  retryCount: 0,
  sizes: { inputBytes: 31, sourceBytes: 208, filteredBytes: 150, outputBytes: 150 },
  filtering: { removedFields: ["client.account_number", "client.tax_id"] },
  policy: {
    outcome: "allowed",
    policyId: "apex-mcp-read-v1",
    reasonCode: "policy.allowed",
    fieldRestrictions: ["client.account_number", "client.tax_id"],
  },
  trace: { traceId: "trace-001", spanId: "span-001" },
};

test("Struct encoding round-trips metadata without raw portfolio fields", () => {
  const payload = {
    tool: event.tool,
    status: event.status,
    policy_id: event.policy.policyId,
    removed_fields: event.filtering.removedFields,
  } as const;
  assert.deepEqual(structToJson(jsonToStruct(payload)), payload);
});

test("Struct encoding uses proto-loader's camelCase Value oneof members", () => {
  assert.deepEqual(jsonToStruct({ allowed: true, count: 2, label: "ok", nested: null }), {
    fields: {
      allowed: { boolValue: true },
      count: { numberValue: 2 },
      label: { stringValue: "ok" },
      nested: { nullValue: 0 },
    },
  });
});

test("Struct encoding preserves the legal __proto__ JSON field safely", () => {
  const payload = JSON.parse('{"__proto__":{"polluted":true},"safe":"ok"}');
  const roundTripped = structToJson(jsonToStruct(payload));
  assert.equal(Object.hasOwn(roundTripped, "__proto__"), true);
  assert.deepEqual(roundTripped["__proto__"], { polluted: true });
  assert.equal(({} as { polluted?: boolean }).polluted, undefined);
});

test("canonical JSON sorts object keys deterministically", () => {
  assert.equal(canonicalizeJson({ z: 1, a: { y: true, x: "ok" } }), '{"a":{"x":"ok","y":true},"z":1}');
});

test("tool event envelope contains only server-derived metadata", () => {
  const envelope = createToolEventEnvelope(event, "01900000-0000-7000-8000-000000000001", "2026-09-03T12:00:00.000000Z");
  assert.equal(envelope.type, "TOOL");
  assert.equal(envelope.actor.type, "AGENT");
  assert.equal(envelope.actor.id, "research-agent");
  assert.equal("client" in envelope.data, false);
  assert.equal(envelope.data.tool, event.tool);
});
