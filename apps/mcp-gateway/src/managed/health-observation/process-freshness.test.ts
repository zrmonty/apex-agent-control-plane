import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { FakeTime, deferred } from "../stage-reader/fixture.js";
import { runHealthObservationProcess, diagnostic } from "./process.js";

const text = '{"observedAtUnixUs":"9007199254740993"}';
test("fixed process carries shrinking remaining validity without changing the report's wall anchor", async () => {
  const events = new EventEmitter(), time = new FakeTime(), output: string[] = [], errors: string[] = [];
  const code = await runHealthObservationProcess([], {}, async () => {
    time.time = 1n;
    return { text, validUntilMonotonicNs: 7_000n };
  }, { timers: time, on: events.on.bind(events), removeListener: events.removeListener.bind(events),
    async write(line) { output.push(line); }, error(line) { errors.push(line); }, terminate() {} });
  assert.equal(code, 0);
  assert.deepEqual(errors, []);
  assert.equal(output.length, 1);
  assert.deepEqual(JSON.parse(output[0]), { schemaVersion: 1, report: { observedAtUnixUs: "9007199254740993" }, validForNs: "6999" });
  assert.ok(output[0].endsWith("\n"));
});

for (const delay of [6_999n, 7_000n]) {
  test(`stdout completion at ${delay}ns respects the original short health lease`, async () => {
    const events = new EventEmitter(), time = new FakeTime(), flush = deferred<void>(), started = deferred<void>();
    const errors: string[] = [];
    const done = runHealthObservationProcess([], {}, async () => ({ text, validUntilMonotonicNs: 7_000n }), {
      timers: time, on: events.on.bind(events), removeListener: events.removeListener.bind(events),
      write() { started.resolve(); return flush.promise; }, error(line) { errors.push(line); }, terminate() { assert.fail("no watchdog expiry"); },
    });
    await started.promise;
    time.time = delay; flush.resolve();
    assert.equal(await done, delay === 6_999n ? 0 : 1);
    assert.deepEqual(errors, delay === 6_999n ? [] : [diagnostic]);
  });
}

for (const validity of [0n, -1n, 10_000_000_001n]) {
  test(`invalid original expiry ${validity} cannot reach stdout`, async () => {
    const events = new EventEmitter(), time = new FakeTime(), output: string[] = [], errors: string[] = [];
    const code = await runHealthObservationProcess([], {}, async () => ({ text, validUntilMonotonicNs: validity }), {
      timers: time, on: events.on.bind(events), removeListener: events.removeListener.bind(events),
      async write(line) { output.push(line); }, error(line) { errors.push(line); }, terminate() {},
    });
    assert.equal(code, 1); assert.deepEqual(output, []); assert.deepEqual(errors, [diagnostic]);
  });
}
