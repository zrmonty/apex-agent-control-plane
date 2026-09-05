import assert from "node:assert/strict";
import type { TestContext } from "node:test";
import { probeHealth } from "../../health-probe.js";
import { createClock } from "../../telemetry/clock.js";
import { completed } from "../readiness/report-codec/test-support.js";
import { bounded, token } from "./http.js";
import { rawServer, response } from "./raw-server.js";

export async function probeEnvelope(t: TestContext): Promise<void> {
  const f = await completed(); t.after(() => f.monitor.close());
  const text = f.codec.encode(f.report), good = response(text).toString();
  const cases: [string, string | Buffer, 0 | 1][] = [
    ["valid", good, 0],
    ["8192 original bytes", response(text + " ".repeat(8192 - Buffer.byteLength(text))), 0],
    ["8193 bytes", response(text + " ".repeat(8193 - Buffer.byteLength(text))), 1],
    ["truncated", good.slice(0, -1), 1],
    ["extra byte", good + "x", 1],
    ["second response", good + good, 1],
    ["http 1.0", good.replace("HTTP/1.1", "HTTP/1.0"), 1],
    ["no length", good.replace(/Content-Length: \d+\r\n/, ""), 1],
    ["noncanonical length", good.replace("Content-Length: ", "Content-Length: 0"), 1],
    ["wrong type", good.replace("application/json", "text/plain"), 1],
    ["absent type", good.replace("Content-Type: application/json\r\n", ""), 1],
    ["encoding", response(text, ["Content-Encoding: gzip"]), 1],
    ["trailer", response(text, ["Trailer: X-Note"]), 1],
    ["duplicate known", response(text, ["cOnTeNt-TyPe: application/json"]), 1],
    ["duplicate other", response(text, ["X-Note: one", "x-note: two"]), 1],
    ["33 fields", response(text, Array.from({ length: 29 }, (_, i) => `X-${i}: a`)), 1],
    ["32 fields", response(text, Array.from({ length: 28 }, (_, i) => `X-${i}: a`)), 0],
    ["oversized header", response(text, [`X-Pad: ${"x".repeat(4097)}`]), 1],
    ["chunked", `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n${Buffer.byteLength(text).toString(16)}\r\n${text}\r\n0\r\n\r\n`, 1],
    ["redirect", response(text, ["Location: http://127.0.0.1:8081/readyz"], "302 Found"), 1],
    ["interim", "HTTP/1.1 100 Continue\r\n\r\n" + good, 1],
    ["invalid utf8", response(Buffer.concat([Buffer.from(text), Buffer.from([0xff])])), 1],
    ["UTF8 BOM must reach strict JSON unchanged", response(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(text)])), 1],
    ["duplicate JSON field", response(text.replace('{', '{"live":true,')), 1],
    ["unknown JSON field", response(text.replace('{', '{"foreign":"HEALTH_CANARY",')), 1],
    ["numeric u64", response(text.replace('"9007199254740993"', '9007199254740993')), 1],
    ["wrong fence", response(text.replace('"9007199254740993"', '"9007199254740994"')), 1],
    ["wrong process", response(text.replace("01992000-0000-7000-8000-000000000001", "01992000-0000-7000-8000-000000000002")), 1],
  ];
  const base = response(text, ["X-Pad: "]).toString(), headerSize = base.indexOf("\r\n\r\n") + 4;
  cases.push(["4096 header bytes", response(text, [`X-Pad: ${"x".repeat(4096 - headerSize)}`]), 0]);
  const failures: string[] = [];
  for (const [name, bytes, expected] of cases) {
    const server = await rawServer(t, socket => socket.end(bytes));
    const result = await bounded(probeHealth({ codec: f.codec, tokenBytes: token(), clock: createClock() }));
    await server.close();
    if (result !== expected || server.stats.requests !== 1 || server.stats.connections !== 1) failures.push(`${name}: ${result}`);
    assert.equal(server.stats.request, `GET /readyz HTTP/1.1\r\nHost: 127.0.0.1:8081\r\nAuthorization: Bearer ${token().toString("base64url")}\r\nConnection: close\r\n\r\n`);
    assert.equal(server.sockets.size, 0);
  }
  assert.deepEqual(failures, [], "status alone, normalization or parsed/truncated framing is not success");
}

export async function probeDeadline(t: TestContext): Promise<void> {
  const f = await completed(); t.after(() => f.monitor.close());
  let timer: NodeJS.Timeout | undefined;
  const server = await rawServer(t, socket => {
    socket.write("HTTP/1.1 200 OK\r\nX-Trickle: ");
    timer = setInterval(() => socket.write("a"), 100);
  }); t.after(() => clearInterval(timer));
  const start = performance.now();
  const result = await bounded(probeHealth({ codec: f.codec, tokenBytes: token(), clock: createClock() }));
  clearInterval(timer); await server.close();
  assert.equal(result, 1); assert.ok(performance.now() - start >= 1800); assert.ok(performance.now() - start < 2900);
  assert.equal(server.sockets.size, 0);
}

export async function probeCallbackBudget(t: TestContext): Promise<void> {
  const f = await completed(); t.after(() => f.monitor.close());
  const text = f.codec.encode(f.report), decode = f.codec.decode.bind(f.codec);
  let ns = 1n;
  const clock = { now: () => ({ monotonicNs: ns, unixUs: 1n, resolutionNs: 1n, source: "transport-test" }) };
  f.codec.decode = value => { ns += 2000000000n; return decode(value); };
  const server = await rawServer(t, socket => socket.end(response(text)));
  assert.equal(await probeHealth({ codec: f.codec, tokenBytes: token(), clock }), 1, "decode consumes the same budget");
  await server.close(); assert.equal(server.sockets.size, 0);
}

export async function probeInvalidInput(t: TestContext): Promise<void> {
  const f = await completed(); t.after(() => f.monitor.close());
  const server = await rawServer(t, socket => socket.end(response(f.codec.encode(f.report))));
  for (const length of [0, 31, 33]) assert.equal(await probeHealth({ codec: f.codec, tokenBytes: Buffer.alloc(length), clock: createClock() }), 1);
  assert.equal(await probeHealth({ codec: f.codec, tokenBytes: token(), clock: { now() { throw new Error("HEALTH_CANARY"); } } }), 1);
  assert.equal(server.stats.connections, 0, "invalid token/clock must fail before request creation");
}
