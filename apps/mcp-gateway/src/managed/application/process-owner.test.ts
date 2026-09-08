import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { deferred } from "../stage-reader/fixture.js";
import type { ApplicationOptions } from "../application.js";
import type { PendingCompletion } from "../call-owner.js";
import { runApplicationProcess } from "./process-owner.js";

const tick = async () => { for (let i = 0; i < 40; i++) await Promise.resolve(); };
function fixture(options: { reentrantSignal?: boolean; throwStart?: boolean } = {}) {
  const events = new EventEmitter(), ready = deferred<{ host: string; port: number }>(), closed = deferred<void>();
  const handoff = deferred<readonly PendingCompletion[]>(), messages: string[] = [];
  void ready.promise.catch(() => {});
  let input!: ApplicationOptions, cancellations = 0, terminations = 0, settled = false, stopping = false;
  const result = runApplicationProcess({ marker: "SENSITIVE-not-a-diagnostic" }, value => {
    input = value; if (options.throwStart) throw Error("SENSITIVE-start-error");
    if (options.reentrantSignal) events.emit("SIGTERM");
    return { result: ready.promise, closed: closed.promise, completionHandoff: handoff.promise,
      cancel() { const initiated = !stopping; stopping = true; cancellations++; ready.reject(Error("SENSITIVE-cancel-error")); return initiated; } };
  }, { on: events.on.bind(events), removeListener: events.removeListener.bind(events),
    report(value) { messages.push(value); }, terminate() { terminations++; } });
  void result.then(() => { settled = true; });
  return { result, ready, closed, handoff, messages, events, fatal: () => input.onFatal(),
    lose() { stopping = true; },
    stats: () => ({ cancellations, terminations, settled }),
    drained() { closed.resolve(); handoff.resolve([]); },
    assertUnsubscribed() { assert.equal(events.listenerCount("SIGTERM") + events.listenerCount("SIGINT"), 0); } };
}

for (const signal of ["SIGTERM", "SIGINT"] as const) {
  test(`${signal} joins physical shutdown and separate completion handoff before graceful exit`, async () => {
    const f = fixture(); f.ready.resolve({ host: "10.96.0.2", port: 8080 }); await tick();
    f.events.emit(signal); f.events.emit(signal); await tick();
    assert.ok(f.stats().cancellations >= 1); assert.equal(f.stats().settled, false);
    f.closed.resolve(); await tick(); assert.equal(f.stats().settled, false);
    f.handoff.resolve([]); assert.equal(await f.result, 0);
    assert.deepEqual(f.messages, []); assert.equal(f.stats().terminations, 0); f.assertUnsubscribed();
  });
}

test("signal during startup, including synchronous factory reentry, cancels the returned owner", async () => {
  const f = fixture({ reentrantSignal: true }); await tick();
  assert.ok(f.stats().cancellations >= 1); assert.equal(f.stats().settled, false);
  f.drained(); assert.equal(await f.result, 0); f.assertUnsubscribed();
});

test("startup refusal reports only a static failure after actual resource closure", async () => {
  const f = fixture(); f.ready.reject(Error("SENSITIVE-stage-error")); await tick();
  assert.equal(f.stats().settled, false); assert.ok(f.stats().cancellations >= 1);
  f.drained(); assert.equal(await f.result, 1); f.assertUnsubscribed();
  assert.deepEqual(f.messages, ["GOVERNANCE_UNAVAILABLE: managed application stopped safely"]);
});

test("unrequested runtime loss cannot look like graceful operator termination", async () => {
  const f = fixture(); f.ready.resolve({ host: "10.96.0.2", port: 8080 }); await tick(); f.drained();
  assert.equal(await f.result, 1); f.assertUnsubscribed();
});

for (const signal of ["SIGTERM", "SIGINT"] as const) {
  test(`loss before later ${signal} during physical drain remains failing`, async () => {
    const f = fixture(); f.ready.resolve({ host: "10.96.0.2", port: 8080 }); await tick();
    f.lose(); f.events.emit(signal); await tick();
    assert.equal(f.stats().settled, false); assert.deepEqual(f.messages, []);
    f.closed.resolve(); await tick(); assert.equal(f.stats().settled, false);
    f.handoff.resolve([]); assert.equal(await f.result, 1);
    assert.deepEqual(f.messages, ["GOVERNANCE_UNAVAILABLE: managed application stopped safely"]);
    assert.equal(f.stats().terminations, 0); f.assertUnsubscribed();
  });
}

test("unresolved exact completion produces reconciliation failure, not clean exit or leaked identifiers", async () => {
  const f = fixture(); f.ready.resolve({ host: "10.96.0.2", port: 8080 }); f.events.emit("SIGTERM");
  f.closed.resolve(); f.handoff.resolve([{ callId: "SENSITIVE-call", admissionId: "SENSITIVE-admission", state: "completion_pending" }]);
  assert.equal(await f.result, 1); f.assertUnsubscribed();
  assert.deepEqual(f.messages, ["GOVERNANCE_UNAVAILABLE: managed completion reconciliation required"]);
});

test("fatal cleanup invokes actual host termination once without inventing closure", async () => {
  const f = fixture(); f.ready.resolve({ host: "10.96.0.2", port: 8080 }); await tick();
  f.fatal(); f.fatal(); await tick();
  assert.equal(f.stats().terminations, 1); assert.equal(f.stats().settled, false);
  f.events.emit("SIGTERM"); f.drained(); assert.equal(await f.result, 1); f.assertUnsubscribed();
});

test("a factory refusal removes signal listeners and reports a static error", async () => {
  const f = fixture({ throwStart: true }); assert.equal(await f.result, 1); f.assertUnsubscribed();
  assert.deepEqual(f.messages, ["GOVERNANCE_UNAVAILABLE: managed application stopped safely"]);
});
