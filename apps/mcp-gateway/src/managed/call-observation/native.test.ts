import assert from "node:assert/strict";
import test from "node:test";
import { IncomingMessage } from "node:http";
import type { OutgoingHttpHeaders } from "node:http2";
import { nativeCallFixture } from "../call-owner-native-testing.js";
import { turns } from "../call-owner-testing.js";
import { paths } from "../authority/business-testing.js";

test("native auth/upstream/completion close receipts gate observations and actual dispatch", { timeout: 5000 }, async t => {
  const f = await nativeCallFixture(t);
  let authSeen!: () => void, upstreamSeen!: () => void, completionSeen!: () => void;
  const authHeld = new Promise<void>(done => { authSeen = done; });
  const upstreamHeld = new Promise<void>(done => { upstreamSeen = done; });
  const completionHeld = new Promise<void>(done => { completionSeen = done; });
  const releases = new Map<string, () => void>();
  let holding = true;
  const request = f.authoritySession.request.bind(f.authoritySession);
  t.mock.method(f.authoritySession, "request", (...args: Parameters<typeof request>) => {
    const stream = request(...args), path = String((args[0] as OutgoingHttpHeaders)[":path"]), emit = stream.emit;
    t.mock.method(stream, "emit", function (event: string | symbol, ...values: unknown[]) {
      if (holding && event === "close" && [paths.authorize, paths.complete].includes(path)) {
        releases.set(path, () => Reflect.apply(emit, stream, [event, ...values]));
        if (path === paths.authorize) authSeen(); else completionSeen();
        return true;
      }
      return Reflect.apply(emit, stream, [event, ...values]);
    });
    return stream;
  });
  const emit = IncomingMessage.prototype.emit;
  t.mock.method(IncomingMessage.prototype, "emit", function (this: IncomingMessage, event: string | symbol, ...values: unknown[]) {
    if (holding && event === "close" && this.statusCode === 200) {
      releases.set("upstream", () => Reflect.apply(emit, this, [event, ...values])); upstreamSeen(); return true;
    }
    return Reflect.apply(emit, this, [event, ...values]);
  });
  const open = f.connector.open.bind(f.connector);
  t.mock.method(f.connector, "open", (...args: Parameters<typeof open>) => {
    const exchange = open(...args);
    return { ...exchange, result: exchange.result.then(socket => {
      f.time(f.started + 7_000n); return socket;
    }) };
  });
  const release = (key: string) => { const callback = releases.get(key)!; releases.delete(key); callback(); };
  const call = f.start(); void call.result.catch(() => {});
  try {
    await authHeld; await turns();
    assert.equal(typeof call.observation, "function");
    assert.equal(call.observation().decision?.outcome, "allowed");
    assert.equal(call.observation().authorization!.closedAtMonotonicNs, undefined);
    assert.equal(call.observation().upstream, undefined);
    assert.equal(call.observation().dispatchedAtMonotonicNs, undefined);
    f.time(f.started + 1_000n); release(paths.authorize);
    await upstreamHeld; await turns();
    assert.equal(call.observation().authorization!.closedAtMonotonicNs, f.started + 1_000n);
    assert.equal(call.observation().upstream!.startedAtMonotonicNs, f.started + 1_000n);
    assert.equal(call.observation().dispatchedAtMonotonicNs, f.started + 7_000n);
    assert.ok(f.effects.includes("tools/call"));
    assert.equal(call.observation().upstream!.closedAtMonotonicNs, undefined);
    assert.equal(call.observation().closedAtMonotonicNs, undefined);
    assert.equal(f.grants.snapshot().activeCalls, 1); assert.ok(!f.effects.includes("complete"));
    f.time(f.started + 999_000n); release("upstream");
    await completionHeld; await turns();
    assert.equal(call.observation().upstream!.closedAtMonotonicNs, f.started + 999_000n);
    assert.equal(call.observation().cleanup!.resultAtMonotonicNs, f.started + 999_000n);
    assert.equal(call.observation().cleanup!.closedAtMonotonicNs, undefined);
    assert.equal(call.observation().closedAtMonotonicNs, undefined);
    f.time(f.started + 1_007_000n); release(paths.complete); await call.closed;
    assert.equal(call.observation().closedAtMonotonicNs, f.started + 1_007_000n);
    assert.equal(call.observation().cleanup!.closedAtMonotonicNs, f.started + 1_007_000n);
    assert.equal((await call.result).decision.outcome, "allowed");
    assert.equal(f.grants.snapshot().activeCalls, 0);
  } finally { holding = false; for (const callback of releases.values()) callback(); releases.clear(); }
});

test("native TLS preparation followed by grant refusal has no dispatch observation", async t => {
  const f = await nativeCallFixture(t), open = f.connector.open.bind(f.connector);
  t.mock.method(f.connector, "open", (...args: Parameters<typeof open>) => {
    const exchange = open(...args);
    return { ...exchange, result: exchange.result.then(socket => { void f.grants.close(); return socket; }) };
  });
  const call = f.start(); await assert.rejects(call.result, /managed call refused safely/); await call.closed;
  assert.equal(call.observation().decision?.outcome, "allowed");
  assert.equal(call.observation().upstream!.state, "error");
  assert.equal(call.observation().dispatchedAtMonotonicNs, undefined);
  assert.ok(!f.effects.includes("tools/call")); assert.ok(f.effects.includes("complete"));
});
