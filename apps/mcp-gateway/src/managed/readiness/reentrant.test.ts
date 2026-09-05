import assert from "node:assert/strict";
import test from "node:test";
import { ReadinessReason } from "@apex/contracts";
import { ReadinessMonitor } from "../readiness.js";
import { controlled, flush } from "./test-support.js";

// Exercise the public predicate/clock seams, never the monitor's private state.
function reentrant(source: "predicate" | "clock") {
  const f = controlled();
  let hook = () => {}, closing: Promise<void> | undefined, monitor: ReadinessMonitor;
  const options = { ...f.options,
    isCurrent: () => { if (source === "predicate") hook(); return true; },
    clock: { now: () => { if (source === "clock") hook(); return f.time.clock.now(); } } };
  function closeOnCall(call: number): void {
    let seen = 0;
    hook = () => { if (++seen === call) { hook = () => {}; closing = monitor.close(); } };
  }
  return { f, options, closeOnCall,
    bind(value: ReadinessMonitor) { monitor = value; },
    get closing() { return closing; } };
}

for (const source of ["predicate", "clock"] as const) {
  test(`${source} startup reentry cannot replace a nested sweep's pending ownership`, async () => {
    const f = controlled();
    let monitor: ReadinessMonitor, nested: ReturnType<ReadinessMonitor["checkStartup"]> | undefined;
    let entered = false;
    const enter = () => { if (!entered) {
      entered = true; nested = monitor.checkStartup();
      // A late outer sample must not use elapsed cadence to replace pending I/O.
      f.time.advance(5000000000n, false);
    } };
    monitor = new ReadinessMonitor({ ...f.options,
      isCurrent: () => { if (source === "predicate") enter(); return true; },
      clock: { now: () => { if (source === "clock") enter(); return f.time.clock.now(); } } });
    const running = monitor.checkStartup();
    assert.ok(nested);
    assert.equal(f.stats.starts, 4, "one sweep retains all underlying permits");
    assert.equal(f.active, 4); assert.equal(f.maximum, 4);
    assert.equal(running, nested, "reentrant check joins the existing sweep");
    const closing = monitor.close();
    assert.equal(f.stats.cancels, 4);
    f.time.advance(4999999999n); await flush();
    assert.equal(f.stats.fatal, 0);
    f.time.advance(1n); await closing;
    assert.equal(f.stats.fatal, 1);
    assert.equal((await running).ready, false); assert.equal((await nested).ready, false);
    for (const id of [...f.pending.keys()]) f.release(id);
    await flush(); await monitor.checkStartup(); await monitor.close();
    assert.equal(f.stats.starts, 4); assert.equal(f.time.scheduled, 0);
  });

  test(`${source} shutdown before the first reservation starts no unowned I/O`, async () => {
    const h = reentrant(source), { f } = h;
    const monitor = new ReadinessMonitor(h.options); h.bind(monitor);
    h.closeOnCall(2); // Initial check succeeds; the first pump callback closes.
    const report = await monitor.checkStartup();
    assert.ok(h.closing); await h.closing;
    assert.equal(f.stats.starts, 0, "a released empty sweep cannot start an owner");
    assert.equal(f.active, 0); assert.equal(f.stats.cancels, 0);
    assert.equal(report.ready, false); assert.equal(report.live, false);
    assert.ok(report.checks.every(check => check.reason === ReadinessReason.SHUTTING_DOWN));
    f.time.advance(20000000000n);
    await monitor.checkStartup(); await monitor.close();
    assert.equal(f.stats.starts, 0); assert.equal(f.stats.fatal, 0);
    assert.equal(f.time.scheduled, 0);
  });

  for (const outcome of ["termination", "unresponsive"] as const) {
    test(`${source} shutdown with pending work retains cleanup until ${outcome}`, async () => {
      const h = reentrant(source), { f } = h;
      const owners = h.options.owners.map(owner => ({ ...owner, start: (binding: Parameters<typeof owner.start>[0]) => {
        const handle = owner.start(binding);
        if (owner.id === 1) h.closeOnCall(1); // Next reservation must observe this close.
        return handle;
      } }));
      const monitor = new ReadinessMonitor({ ...h.options, owners }); h.bind(monitor);
      const running = monitor.checkStartup();
      assert.ok(h.closing);
      let settled = false; void h.closing.then(() => { settled = true; });
      await flush();
      assert.equal(f.stats.starts, 1, "shutdown cannot reserve a second operation");
      assert.equal(f.active, 1); assert.equal(f.stats.cancels, 1);
      assert.equal(settled, false); assert.equal((await running).ready, false);
      assert.equal(monitor.snapshot().live, false);
      await monitor.checkStartup(); void monitor.close();
      assert.equal(f.stats.starts, 1); assert.equal(f.stats.cancels, 1);
      f.time.advance(4999999999n); await flush();
      assert.equal(settled, false); assert.equal(f.stats.fatal, 0);
      if (outcome === "termination") {
        f.release(1); await h.closing;
        assert.equal(f.stats.fatal, 0); assert.equal(f.active, 0);
      } else {
        f.time.advance(1n); await h.closing;
        assert.equal(f.stats.fatal, 1); assert.equal(f.active, 1, "fatal is not actual I/O termination");
        f.release(1); await flush();
      }
      f.time.advance(20000000000n);
      await monitor.checkStartup(); await monitor.close();
      assert.equal(f.stats.starts, 1); assert.equal(f.stats.cancels, 1);
      assert.equal(f.stats.fatal, outcome === "termination" ? 0 : 1);
      assert.equal(f.time.scheduled, 0); assert.equal(monitor.snapshot().ready, false);
    });
  }

  test(`${source} shutdown at final publication cannot replace invalidated cached evidence`, async () => {
    const h = reentrant(source), { f } = h;
    const monitor = new ReadinessMonitor(h.options); h.bind(monitor);
    const running = monitor.checkStartup();
    for (let id = 1; id <= 8; id++) { f.release(id); await flush(); }
    assert.equal(f.stats.starts, 9); assert.equal(f.active, 1);
    const before = monitor.snapshot();
    // Final completion samples once, guards once, then guards publication.
    h.closeOnCall(source === "predicate" ? 2 : 3);
    f.release(9); await flush();
    assert.ok(h.closing); await h.closing;
    assert.equal((await running).ready, false);
    const report = monitor.snapshot();
    assert.equal(report.observedAtUnixUs, before.observedAtUnixUs, "no publication after callback shutdown");
    assert.deepEqual(report.stages, before.stages);
    assert.equal(report.ready, false); assert.equal(report.live, false);
    assert.equal(f.active, 0); assert.equal(f.stats.cancels, 0);
    assert.equal(f.stats.fatal, 0); assert.equal(f.time.scheduled, 0);
  });
}
