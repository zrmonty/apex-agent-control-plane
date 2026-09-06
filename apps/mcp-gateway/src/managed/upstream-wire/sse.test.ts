import assert from "node:assert/strict";
import test from "node:test";
import { McpSseDecoder } from "./sse.js";

test("SSE decodes split UTF8 and CRLF without dispatching early or changing RPC id", () => {
  const decoder = new McpSseDecoder();
  const text = ': heartbeat\r\nevent: message\r\nid: cursor-1\r\ndata: {"jsonrpc":"2.0","id":"call-1",\r\ndata: "result":{"text":"🧭"}}\r\n\r\n';
  const bytes = Buffer.from(text), messages: unknown[] = [];
  for (let index = 0; index < bytes.length; index++) {
    messages.push(...decoder.push(bytes.subarray(index, index + 1)));
    // CR itself completes the blank line; its following LF is only suppressed.
    if (index < bytes.length - 2) assert.equal(messages.length, 0);
  }
  messages.push(...decoder.finish());
  assert.deepEqual(messages, [{ jsonrpc: "2.0", id: "call-1", result: { text: "🧭" } }]);
});
test("SSE rejects duplicate data JSON, invalid UTF8, unknown event and oversized pending line", () => {
  for (const input of [Buffer.from('data: {"id":1,"id":2}\n\n'), Buffer.from('event: endpoint\ndata: "https://evil.invalid"\n\n'),
    Buffer.from([0xff]), Buffer.alloc(1_048_577, 120)]) {
    assert.throws(() => new McpSseDecoder().push(input), /managed MCP reply refused safely/);
  }
});
test("SSE EOF does not turn an unterminated event into a successful response", () => {
  const decoder = new McpSseDecoder();
  assert.deepEqual(decoder.push(Buffer.from('data: {"id":"one","result":{}}\n')), []);
  assert.deepEqual(decoder.finish(), []);
});

test("SSE supports CR-only framing but cannot recover after malformed input or EOF", () => {
  const decoder = new McpSseDecoder();
  assert.deepEqual(decoder.push(Buffer.from('data: {"id":"one","result":{}}\r\r')), [{ id: "one", result: {} }]);
  assert.deepEqual(decoder.finish(), []);
  assert.throws(() => decoder.push(Buffer.from("\n")), /managed MCP reply refused safely/);
  const bad = new McpSseDecoder();
  assert.throws(() => bad.push(Buffer.from("unknown: field\n")), /managed MCP reply refused safely/);
  assert.throws(() => bad.push(Buffer.from('data: {}\n\n')), /managed MCP reply refused safely/);
});
test("SSE count, duplicate metadata and incomplete UTF8 bounds refuse", () => {
  assert.throws(() => new McpSseDecoder().push(Buffer.from('data: {}\n\n'.repeat(129))), /managed MCP reply refused safely/);
  for (const header of ['id: one\nid: two', 'event: message\nevent: message', 'retry: 1000000', 'id: bad\u0000id']) {
    assert.throws(() => new McpSseDecoder().push(Buffer.from(`${header}\ndata: {}\n\n`)), /managed MCP reply refused safely/);
  }
  const decoder = new McpSseDecoder(); decoder.push(Buffer.from([0xf0, 0x9f]));
  assert.throws(() => decoder.finish(), /managed MCP reply refused safely/);
});

test("every LF CR and CRLF split dispatches exactly once without requiring EOF", () => {
  const expected = { id: "one", result: { text: "🧭" } };
  for (const newline of ["\n", "\r", "\r\n"]) {
    const bytes = Buffer.from(`data: ${JSON.stringify(expected)}${newline}${newline}`);
    for (let split = 0; split <= bytes.length; split++) {
      const decoder = new McpSseDecoder();
      const actual = [...decoder.push(bytes.subarray(0, split)), ...decoder.push(bytes.subarray(split))];
      assert.deepEqual(actual, [expected], `line ending ${JSON.stringify(newline)} split ${split}`);
      assert.deepEqual(decoder.finish(), []);
    }
  }
});
