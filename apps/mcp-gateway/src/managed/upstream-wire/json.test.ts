import assert from "node:assert/strict";
import test from "node:test";
import { parseWireJson } from "./json.js";

test("wire JSON preserves a nested exact string RPC id and integer-looking text", () => {
  assert.deepEqual(parseWireJson(Buffer.from('{"jsonrpc":"2.0","id":"call-7","result":{"unixUs":"9007199254740993","content":[]}}')),
    { jsonrpc: "2.0", id: "call-7", result: { unixUs: "9007199254740993", content: [] } });
});
test("original JSON duplicates, escaped duplicate keys and invalid UTF8 refuse", () => {
  for (const text of ['{"id":"one","id":"two"}', '{"id":"one","\\u0069d":"two"}',
    '{"result":{"nested":1,"nested":2}}', '{"result":"\\ud800"}', '{"result":1e999}', '{}{}']) {
    assert.throws(() => parseWireJson(Buffer.from(text)), /^Error: managed MCP reply refused safely$/);
  }
  assert.throws(() => parseWireJson(Buffer.from([0x7b, 0x22, 0xc0, 0x80, 0x22, 0x3a, 0x31, 0x7d])), /managed MCP reply refused safely/);
});
test("wire JSON depth, nodes and bytes are bounded before full parsing", () => {
  for (const text of ["[".repeat(34) + "0" + "]".repeat(34), JSON.stringify(Array(16_385).fill(0)), " ".repeat(1_048_577)]) {
    assert.throws(() => parseWireJson(Buffer.from(text)), /managed MCP reply refused safely/);
  }
});
