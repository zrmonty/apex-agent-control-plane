import assert from "node:assert/strict";
import test from "node:test";
import { IncomingMessage } from "node:http";
import { nativeCallFixture } from "./call-owner-native-testing.js";

test("actual mTLS renewal and durable authorization gate one guarded MCP call and completion", async t => {
  const f = await nativeCallFixture(t); const call = f.start();
  assert.deepEqual((await call.result).output, { content: [{ type: "text", text: "native result" }] });
  await call.closed; assert.equal(f.grants.snapshot().activeCalls, 0); assert.deepEqual(f.owner.pending(), []);
  assert.deepEqual(f.effects, ["renew", "initialize", "notifications/initialized", "tools/list", "authorize", "tools/call", "complete"]);
});

test("grant closure after actual TLS connection preparation blocks every business byte", async t => {
  const f = await nativeCallFixture(t);
  const open = f.connector.open.bind(f.connector);
  t.mock.method(f.connector, "open", (...args: Parameters<typeof open>) => {
    const exchange = open(...args); return { ...exchange, result: exchange.result.then(socket => { void f.grants.close(); return socket; }) };
  });
  const call = f.start(); await assert.rejects(call.result, /managed call refused safely/); await call.closed;
  assert.ok(!f.effects.includes("tools/call")); assert.equal(f.effects.filter(e => e === "complete").length, 1);
  assert.equal(f.grants.snapshot().activeCalls, 0);
});

test("actual response close owns local slot and prevents remote completion despite cancellation", async t => {
  const f = await nativeCallFixture(t); let reached!: () => void, release!: () => void;
  const held = new Promise<void>(done => { reached = done; });
  const original = IncomingMessage.prototype.emit;
  t.mock.method(IncomingMessage.prototype, "emit", function (this: IncomingMessage, event: string | symbol, ...args: unknown[]) {
    if (event === "close" && this.statusCode === 200) { release = () => Reflect.apply(original, this, [event, ...args]); reached(); return true; }
    return Reflect.apply(original, this, [event, ...args]);
  });
  const call = f.start(); const result = call.result.then(() => undefined, () => undefined);
  await held; call.cancel(); await result;
  assert.equal(f.grants.snapshot().activeCalls, 1); assert.ok(!f.effects.includes("complete"));
  let closed = false; void call.closed.then(() => { closed = true; }); await Promise.resolve(); assert.equal(closed, false);
  release(); await call.closed; assert.equal(f.grants.snapshot().activeCalls, 0); assert.ok(f.effects.includes("complete"));
});

for (const duration of [1n, 7n, 999n]) for (const offset of [-1n, 0n, 1n]) {
  test(`actual final write charges ${duration}us permit at offset ${offset}ns`, async t => {
    const f = await nativeCallFixture(t, duration), open = f.connector.open.bind(f.connector);
    t.mock.method(f.connector, "open", (...args: Parameters<typeof open>) => {
      const exchange = open(...args); return { ...exchange, result: exchange.result.then(socket => {
        f.time(f.started + duration * 1000n + offset); return socket;
      }) };
    });
    const call = f.start();
    if (offset < 0n) await call.result; else await assert.rejects(call.result, /managed call refused safely/);
    await call.closed; assert.equal(f.effects.includes("tools/call"), offset < 0n);
    assert.ok(f.effects.includes("complete")); assert.equal(f.grants.snapshot().activeCalls, 0);
  });
}

test("cancelling one actual SSE call does not cancel another call or its authority context", async t => {
  const f = await nativeCallFixture(t, 10_000_000n, true);
  const first = f.start(); const rejected = assert.rejects(first.result, /managed call refused safely/);
  await f.firstReceived;
  const second = f.start("018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7eff"); first.cancel();
  await rejected; assert.deepEqual((await second.result).output, { content: [{ type: "text", text: "native result" }] });
  await Promise.all([first.closed, second.closed]);
  assert.equal(f.effects.filter(e => e === "tools/call").length, 2);
  assert.equal(f.effects.filter(e => e === "complete").length, 2); assert.equal(f.grants.snapshot().activeCalls, 0);
});

for (const duration of [1n, 7n, 999n]) for (const offset of [-1n, 0n, 1n]) {
  test(`final authority resample crosses ${duration}us permit to offset ${offset}ns`, async t => {
    const f = await nativeCallFixture(t, duration), open = f.connector.open.bind(f.connector), snapshot = f.grants.snapshot.bind(f.grants);
    let armed = false;
    t.mock.method(f.connector, "open", (...args: Parameters<typeof open>) => {
      const exchange = open(...args); return { ...exchange, result: exchange.result.then(socket => {
        f.time(f.started + duration * 1000n - 1n); armed = true; return socket;
      }) };
    });
    t.mock.method(f.grants, "snapshot", () => {
      const value = snapshot();
      if (armed) { armed = false; f.time(f.started + duration * 1000n + offset); }
      return value;
    });
    const call = f.start(); const outcome = await call.result.then(() => "success", () => "refused"); await call.closed;
    assert.equal(outcome, offset < 0n ? "success" : "refused");
    assert.equal(f.effects.includes("tools/call"), offset < 0n);
    assert.ok(f.effects.includes("complete")); assert.equal(f.grants.snapshot().activeCalls, 0);
  });
}
