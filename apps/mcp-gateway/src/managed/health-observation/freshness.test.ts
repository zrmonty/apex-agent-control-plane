import test from "node:test";
import assert from "node:assert/strict";
import { observeHealth, observeFreshHealth } from "../../health-probe.js";
import { completed } from "../readiness/report-codec/test-support.js";
import { rawServer, response } from "../health-testing/raw-server.js";
import { token, requestText, wire } from "../health-testing/http.js";
import { startHealthServer } from "../health-server.js";
import { isolateHealthTransport } from "./isolated-transport.js";

// Catches treating a still-in-budget HTTP exchange as fresh after its much
// shorter dependency lease expired. The remote wall clock is irrelevant.
test("health observation rejects a lease consumed during decode", async t => {
  isolateHealthTransport(t);
  const f = await completed(); t.after(() => f.monitor.close());
  let ns = 1n;
  const decode = f.codec.decode.bind(f.codec);
  f.codec.decode = text => { ns += 7_000n; return decode(text); };
  await rawServer(t, socket => socket.end(response(f.codec.encode(f.report), [], "200 OK", "7000")));
  assert.equal(await observeHealth({ codec: f.codec, tokenBytes: token(),
    clock: { now: () => ({ monotonicNs: ns, unixUs: 3n, resolutionNs: 1n, source: "consumer" }) } }), undefined);
});

for (const ttl of [undefined, "0", "01", "+1", "-1", "1.0", "1e3", "10000000001", "18446744073709551616"]) {
  test(`health observation refuses absent or invalid lifetime ${String(ttl)}`, async t => {
    isolateHealthTransport(t);
    const f = await completed(); t.after(() => f.monitor.close());
    await rawServer(t, socket => socket.end(response(f.codec.encode(f.report),
      [], "200 OK", ttl ?? null)));
    assert.equal(await observeHealth({ codec: f.codec, tokenBytes: token(),
      clock: { now: () => ({ monotonicNs: 1n, unixUs: 3n, resolutionNs: 1n, source: "consumer" }) } }), undefined);
  });
}

test("real health server exports shrinking original validity without timestamp restamping", async t => {
  const isolation = isolateHealthTransport(t);
  const f = await completed(); t.after(() => f.monitor.close());
  const server = await startHealthServer({ codec: f.codec, state: f.monitor, tokenBytes: token(),
    clock: { now: () => ({ monotonicNs: 1n, unixUs: 1n, resolutionNs: 1n, source: "server" }) },
    onFatal: () => assert.fail("fatal") }); t.after(() => server.close());
  const first = await requestText(wire(), isolation.port());
  assert.match(first.raw, /X-Apex-Readiness-Valid-For-Ns: 10000000000\r\n/i);
  f.time.advance(7_000n);
  const second = await requestText(wire(), isolation.port());
  assert.match(second.raw, /X-Apex-Readiness-Valid-For-Ns: 9999993000\r\n/i);
  assert.equal(first.body, second.body);
  assert.equal(f.stats.starts, 9);
});

for (const elapsed of [6_999n, 7_000n]) {
  test(`receiver lease stays anchored before request dispatch at ${elapsed}ns elapsed`, async t => {
    isolateHealthTransport(t);
    const f = await completed(); t.after(() => f.monitor.close());
    let ns = 100n;
    // Delay occurs before any response header arrives, not just inside decode.
    await rawServer(t, socket => { ns += elapsed; socket.end(response(f.codec.encode(f.report), [], "200 OK", "7000")); });
    const observed = await observeFreshHealth({ codec: f.codec, tokenBytes: token(),
      clock: { now: () => ({ monotonicNs: ns, unixUs: 1n, resolutionNs: 1n, source: "receiver" }) } });
    if (elapsed === 7_000n) assert.equal(observed, undefined);
    else {
      assert.equal(observed?.validUntilMonotonicNs, 7_100n);
      assert.deepEqual(observed.report, f.report);
    }
  });
}

test("server serialization consumes the cached lease without giving the client a fresh lease", async t => {
  const isolation = isolateHealthTransport(t);
  const f = await completed(); t.after(() => f.monitor.close());
  f.time.advance(9_999_993_000n);
  let ns = 1n;
  const encode = f.codec.encode.bind(f.codec);
  f.codec.encode = report => { ns += 7_000n; return encode(report); };
  const server = await startHealthServer({ codec: f.codec, state: f.monitor, tokenBytes: token(),
    clock: { now: () => ({ monotonicNs: ns, unixUs: 1n, resolutionNs: 1n, source: "server" }) },
    onFatal: () => assert.fail("fatal") }); t.after(() => server.close());
  const result = await requestText(wire(), isolation.port());
  assert.equal(result.status, 503);
  assert.equal(result.headers["x-apex-readiness-valid-for-ns"], "0");
  assert.equal(f.stats.starts, 9);
});

test("a changed current binding cannot export any remaining readiness lease", async t => {
  const isolation = isolateHealthTransport(t);
  const f = await completed(); t.after(() => f.monitor.close());
  const server = await startHealthServer({ codec: f.codec, state: f.monitor, tokenBytes: token(),
    clock: { now: () => ({ monotonicNs: 1n, unixUs: 1n, resolutionNs: 1n, source: "server" }) },
    onFatal: () => assert.fail("fatal") }); t.after(() => server.close());
  f.stats.current = false;
  const result = await requestText(wire(), isolation.port());
  assert.equal(result.status, 503);
  assert.equal(result.headers["x-apex-readiness-valid-for-ns"], "0");
  assert.equal(f.codec.decode(result.body).ready, false);
});
