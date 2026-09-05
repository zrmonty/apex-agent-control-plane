import assert from "node:assert/strict";
import test from "node:test";
import { ReadinessReason } from "@apex/contracts";
import { ReadinessMonitor } from "../readiness.js";
import { controlled, flush, setup } from "./test-support.js";

test("one sweep holds at most four underlying permits and replacement calls cannot duplicate work", async () => {
  const f = controlled(), monitor = new ReadinessMonitor(f.options);
  const first = monitor.checkStartup();
  assert.equal(f.active, 4);
  void monitor.checkStartup();
  assert.equal(f.stats.starts, 4);
  f.release(1); await flush();
  assert.equal(f.stats.starts, 5);
  assert.equal(f.active, 4);
  while (f.pending.size) { for (const id of [...f.pending.keys()]) f.release(id); await flush(); }
  assert.equal((await first).ready, true);
  assert.equal(f.maximum, 4);
  assert.equal(f.stats.starts, 9);
  assert.equal(f.stats.cancels, 0);
  await monitor.close();
  assert.equal(f.time.scheduled, 0);
});

test("exact whole-sweep deadline cancels once without releasing permits or publishing late successes", async () => {
  const f = controlled(), monitor = new ReadinessMonitor(f.options);
  const first = monitor.checkStartup();
  f.time.advance(2000000000n);
  assert.equal(f.stats.cancels, 4);
  const timedOut = await first;
  assert.equal(timedOut.ready, false);
  assert.ok(timedOut.checks.every(check => check.reason === ReadinessReason.TIMEOUT));
  f.time.advance(3000000000n); // Cadence elapsed, but I/O has NOT terminated.
  assert.equal((await monitor.checkStartup()).ready, false);
  assert.equal(f.stats.starts, 4);
  assert.equal(f.active, 4);
  for (const id of [...f.pending.keys()]) f.release(id);
  await flush();
  assert.equal(monitor.snapshot().ready, false);
  assert.equal(f.stats.cancels, 4);
  assert.equal(f.stats.fatal, 0);
  await monitor.close();
  assert.equal(f.time.scheduled, 0);
});

test("shutdown invalidates first then cancels exact work, waiting only for actual termination", async () => {
  const f = controlled(), monitor = new ReadinessMonitor(f.options);
  const running = monitor.checkStartup();
  const closing = monitor.close();
  assert.equal(monitor.snapshot().live, false);
  assert.equal(monitor.snapshot().ready, false);
  assert.equal(f.stats.cancels, 4);
  let closed = false; void closing.then(() => { closed = true; });
  await flush();
  assert.equal(closed, false);
  await monitor.checkStartup();
  assert.equal(f.stats.starts, 4);
  for (const id of [...f.pending.keys()]) f.release(id);
  await closing;
  assert.equal((await running).ready, false);
  await monitor.close();
  assert.equal(f.stats.cancels, 4);
  assert.equal(f.time.scheduled, 0);
});

test("unresponsive I/O invokes fatal once at cleanup bound and permanently forbids another sweep", async () => {
  const f = controlled();
  const monitor = new ReadinessMonitor({ ...f.options, onFatal: () => { f.stats.fatal++; throw new Error("SENSITIVE-fatal"); } });
  const running = monitor.checkStartup();
  f.time.advance(2000000000n);
  assert.equal(f.stats.cancels, 4);
  await running;
  f.time.advance(4999999999n);
  assert.equal(f.stats.fatal, 0);
  f.time.advance(1n);
  assert.equal(f.stats.fatal, 1);
  assert.equal(monitor.snapshot().live, false);
  f.time.advance(20000000000n);
  await monitor.checkStartup(); await monitor.close();
  assert.equal(f.stats.fatal, 1);
  assert.equal(f.stats.starts, 4);
  assert.equal(f.stats.cancels, 4);
  assert.equal(f.time.scheduled, 0);
  for (const id of [...f.pending.keys()]) f.release(id);
  await flush();
  assert.equal(monitor.snapshot().ready, false);
});

test("cached reads preserve observed time and cannot defeat the five-second sweep cadence", async () => {
  const f = setup(), monitor = new ReadinessMonitor(f.options);
  const first = await monitor.checkStartup();
  f.time.advance(4999999999n);
  for (let i = 0; i < 5; i++) {
    assert.equal(monitor.snapshot().observedAtUnixUs, first.observedAtUnixUs);
    assert.equal((await monitor.checkStartup()).observedAtUnixUs, first.observedAtUnixUs);
  }
  assert.equal(f.stats.starts, 9);
  f.time.advance(1n);
  assert.equal((await monitor.checkStartup()).ready, true);
  assert.equal(f.stats.starts, 18);
  await monitor.close();
});

test("shutdown reentered during synchronous start still owns and cancels the returned operation", async () => {
  const f = controlled();
  let monitor: ReadinessMonitor, closing: Promise<void> | undefined;
  const owners = f.options.owners.map(owner => owner.id !== 1 ? owner : { ...owner, start: (binding: Parameters<typeof owner.start>[0]) => {
    const handle = owner.start(binding);
    closing = monitor.close();
    return handle;
  } });
  monitor = new ReadinessMonitor({ ...f.options, owners });
  const running = monitor.checkStartup();
  assert.equal(f.stats.cancels, 1);
  assert.equal(f.stats.starts, 1);
  assert.equal(monitor.snapshot().live, false);
  f.release(1); await closing;
  assert.equal((await running).ready, false);
  assert.equal(f.time.scheduled, 0);
});

test("a malformed lifecycle handle cannot release unknown I/O into a future replacement sweep", async () => {
  const f = setup();
  const owners = f.owners.map(owner => owner.id !== 1 ? owner : { ...owner, start: () => ({ completion: undefined, cancel: () => { f.stats.cancels++; } }) });
  const monitor = new ReadinessMonitor({ ...f.options, owners } as never);
  assert.equal((await monitor.checkStartup()).ready, false);
  assert.equal(f.stats.fatal, 1);
  f.time.advance(10000000000n);
  await monitor.checkStartup(); await monitor.close();
  assert.equal(f.stats.starts, 0);
  assert.equal(f.stats.cancels, 1);
  assert.equal(f.stats.fatal, 1);
});
