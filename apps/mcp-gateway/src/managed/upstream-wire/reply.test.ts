import assert from "node:assert/strict";
import test from "node:test";
import type { OwnedHttpResponse } from "../guard/http-owner.js";
import { readMcpReply } from "./reply.js";

function response(text: string, contentType = "application/json"): OwnedHttpResponse {
  return { status: 200, contentType, body: { async *[Symbol.asyncIterator]() { yield Buffer.from(text); } } };
}

test("exact JSON call reply is validated through locked SDK result schema", async () => {
  const expected = { content: [{ type: "text", text: "approved result" }], isError: false };
  assert.deepEqual(await readMcpReply(response(JSON.stringify({ jsonrpc: "2.0", id: "call-1", result: expected })), "call-1", "tools/call"), expected);
});
test("SSE accepts matching bounded progress then the exact result, not another call's reply", async () => {
  const wire = 'data: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"call-1","progress":1}}\n\n' +
    'data: {"jsonrpc":"2.0","id":"call-1","result":{"content":[]}}\n\n';
  assert.deepEqual(await readMcpReply(response(wire, "text/event-stream; charset=utf-8"), "call-1", "tools/call"), { content: [] });
  await assert.rejects(readMcpReply(response(wire.replaceAll("call-1", "call-2"), "text/event-stream"), "call-1", "tools/call"), /managed MCP reply refused safely/);
});
test("batch, mismatched ids, upstream requests, conflicting reply fields and remote errors refuse statically", async () => {
  for (const wire of [
    '{"jsonrpc":"2.0","id":"other","result":{"content":[]}}',
    '{"jsonrpc":"2.0","id":1,"result":{"content":[]}}',
    '[{"jsonrpc":"2.0","id":"call-1","result":{"content":[]}}]',
    '{"jsonrpc":"2.0","id":"call-1","method":"sampling/createMessage","params":{}}',
    '{"jsonrpc":"2.0","id":"call-1","error":{"code":-32000,"message":"PRIVATE_REMOTE"}}',
    '{"jsonrpc":"2.0","id":"call-1","result":{"content":[]},"error":{"code":-1,"message":"x"}}',
    '{"jsonrpc":"2.0","id":"call-1","result":{"content":"not an array"}}',
  ]) await assert.rejects(readMcpReply(response(wire), "call-1", "tools/call"), /^Error: managed MCP reply refused safely$/);
});
test("discovery and initialization use their own result schema", async () => {
  assert.deepEqual(await readMcpReply(response('{"jsonrpc":"2.0","id":"root-list","result":{"tools":[]}}'), "root-list", "tools/list"), { tools: [] });
  const result = { protocolVersion: "2025-11-25", capabilities: { tools: {} }, serverInfo: { name: "test", version: "1" } };
  assert.deepEqual(await readMcpReply(response(JSON.stringify({ jsonrpc: "2.0", id: "root-init", result })), "root-init", "initialize"), result);
  await assert.rejects(readMcpReply(response('{"jsonrpc":"2.0","id":"root-init","result":{"tools":[]}}'), "root-init", "initialize"), /managed MCP reply refused safely/);
});
test("unsupported content type and incomplete SSE stream refuse", async () => {
  await assert.rejects(readMcpReply(response("{}", "text/html"), "call-1", "tools/call"), /managed MCP reply refused safely/);
  await assert.rejects(readMcpReply(response('data: {"jsonrpc":"2.0","id":"call-1","result":{"content":[]}}\n', "text/event-stream"), "call-1", "tools/call"), /managed MCP reply refused safely/);
});
