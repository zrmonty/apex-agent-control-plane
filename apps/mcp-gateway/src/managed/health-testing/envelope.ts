import assert from "node:assert/strict";
import type { TestContext } from "node:test";
import { GatewayError } from "../../contracts.js";
import { createClock } from "../../telemetry/clock.js";
import { startHealthServer } from "../health-server.js";
import { fixture } from "../readiness/report-codec/test-support.js";
import { requestText, token, wire } from "./http.js";

export async function rejectsBeforeState(t: TestContext): Promise<void> {
  const f = fixture(); t.after(() => f.monitor.close());
  let snapshots = 0, encodes = 0;
  const encode = f.codec.encode.bind(f.codec);
  f.codec.encode = report => { encodes++; return encode(report); };
  const server = await startHealthServer({ codec: f.codec, state: { snapshot() { snapshots++; return f.monitor.snapshot(); } },
    tokenBytes: token(), clock: createClock(), onFatal: () => assert.fail("fatal") });
  t.after(() => server.close());
  const host = "Host: 127.0.0.1:8081", auth = `Authorization: Bearer ${token().toString("base64url")}`;
  const cases: [string, string][] = [
    ["missing auth", wire("/readyz", host)],
    ["wrong token", wire("/readyz", `${host}\r\nAuthorization: Bearer ${Buffer.alloc(32).toString("base64url")}`)],
    ["wrong scheme", wire("/readyz", `${host}\r\n${auth.replace("Bearer", "bearer")}`)],
    ["padding", wire("/readyz", `${host}\r\n${auth}=`)],
    ["noncanonical pad bits", wire("/readyz", `${host}\r\n${auth.slice(0, -1)}p`)],
    ["leading token whitespace", wire("/readyz", `${host}\r\n${auth.replace("Bearer ", "Bearer  ")}`)],
    ["trailing token whitespace", wire("/readyz", `${host}\r\n${auth} `)],
    ["comma token", wire("/readyz", `${host}\r\n${auth},${token().toString("base64url")}`)],
    ["duplicate auth", wire("/readyz", `${host}\r\n${auth}\r\n${auth.toLowerCase()}`)],
    ["duplicate host", wire("/readyz", `${host}\r\n${auth}\r\nhOsT: 127.0.0.1:8081`)],
    ["duplicate irrelevant", wire("/readyz", `${host}\r\n${auth}\r\nX-Note: one\r\nx-note: two`)],
    ["wrong host", wire("/readyz", `Host: localhost:8081\r\n${auth}`)],
    ["missing host", wire("/readyz", auth)],
    ["http 1.0", wire().replace("HTTP/1.1", "HTTP/1.0")],
    ...["/readyz?", "/readyz#", "/readyz/", "/%72eadyz", "//readyz", "http://127.0.0.1:8081/readyz", "/other"].map(path => [path, wire(path)] as [string, string]),
    ["POST", wire().replace("GET ", "POST ")],
    ["CONNECT", wire().replace("GET /readyz", "CONNECT 127.0.0.1:8081")],
    ["upgrade", wire("/readyz", `${host}\r\n${auth}\r\nUpgrade: websocket`)],
    ...["1", "00", "+0", "0, 0"].map(value => [`content-length ${value}`, wire("/readyz", `${host}\r\n${auth}\r\nContent-Length: ${value}`)] as [string, string]),
    ...["Transfer-Encoding: chunked", "Trailer: X-Trailer", "Expect: 100-continue", "Expect: other"].map(header => [header, wire("/readyz", `${host}\r\n${auth}\r\n${header}`)] as [string, string]),
    ["oversized header", wire("/readyz", `${host}\r\n${auth}\r\nX-Large: ${"x".repeat(4097)}`)],
    ["33 headers", wire("/readyz", `${host}\r\n${auth}\r\n${Array.from({ length: 30 }, (_, i) => `X-${i}: a`).join("\r\n")}`)],
  ];
  const failures: string[] = [];
  for (const [name, request] of cases) {
    const before = [snapshots, encodes];
    const response = await requestText(request);
    if (!(response.status === 0 || response.status >= 400) || response.body !== "" || snapshots !== before[0] || encodes !== before[1] || response.raw.includes("100 Continue")) failures.push(name);
  }
  assert.deepEqual(failures, [], "all collected requests must be rejected before state access");
  const valid = await requestText(wire("/livez", `${host}\r\n${auth.replace("Authorization", "aUtHoRiZaTiOn")}\r\nContent-Length: 0`));
  assert.equal(valid.status, 200); assert.equal(snapshots, 1); assert.equal(encodes, 1);
  assert.equal(f.stats.starts, 0);
}

export async function invalidTokens(t: TestContext): Promise<void> {
  const f = fixture(); t.after(() => f.monitor.close());
  for (const size of [0, 31, 33]) {
    await assert.rejects(async () => {
      const server = await startHealthServer({ codec: f.codec, state: f.monitor, tokenBytes: Buffer.alloc(size),
        clock: createClock(), onFatal: () => assert.fail("fatal") });
      await server.close();
    }, (error: unknown) => error instanceof GatewayError && !String(error).includes("secret") && (error as Error).cause === undefined);
  }
  const original = token();
  const server = await startHealthServer({ codec: f.codec, state: f.monitor, tokenBytes: original,
    clock: createClock(), onFatal: () => assert.fail("fatal") });
  t.after(() => server.close()); original.fill(0);
  assert.equal((await requestText(wire("/livez"))).status, 200, "listener captured independent bytes");
  await server.close(); assert.deepEqual(original, Buffer.alloc(32), "close must not change caller bytes");
}
