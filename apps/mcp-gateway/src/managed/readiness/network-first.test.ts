import assert from "node:assert/strict";
import test from "node:test";
import { ReadinessCheckStatus as Status, ReadinessReason as Reason } from "@apex/contracts";
import { ReadinessMonitor } from "../readiness.js";
import { controlled, flush, pass } from "./test-support.js";

test("NETWORK physically completes before upstream, governance, evidence or admission probes start", async () => {
  const f = controlled(), monitor = new ReadinessMonitor(f.options);
  const running = monitor.checkStartup();
  try {
    assert.deepEqual([...f.pending.keys()], [1, 2, 3, 4]);
    for (const id of [1, 2, 3, 4]) { f.release(id); await flush(); }
    assert.deepEqual([...f.pending.keys()], [8]);
    assert.equal(f.stats.starts, 5);
    assert.equal(monitor.checkStartup(), running);
    f.release(8); await flush();
    assert.deepEqual([...f.pending.keys()], [5, 6, 7, 9]);
    assert.equal(f.maximum, 4);
    for (const id of [...f.pending.keys()]) f.release(id);
    assert.equal((await running).ready, true);
  } finally { for (const id of [...f.pending.keys()]) f.release(id); await monitor.close(); }
});

for (const reason of [Reason.UNAVAILABLE, Reason.MISMATCH, Reason.STALE]) {
  test(`NETWORK refusal ${reason} starts no dependent probes`, async () => {
    const f = controlled(), monitor = new ReadinessMonitor(f.options);
    const running = monitor.checkStartup();
    try {
      for (const id of [1, 2, 3, 4]) { f.release(id); await flush(); }
      assert.deepEqual([...f.pending.keys()], [8]);
      const value = pass(8, f.time.ns + 10_000_000_000n);
      f.release(8, { ...value, check: { ...value.check, status: Status.FAIL, reason } });
      const report = await running;
      assert.equal(report.ready, false); assert.equal(report.checks[7].reason, reason);
      assert.equal(f.stats.starts, 5); assert.equal(f.pending.size, 0);
    } finally { for (const id of [...f.pending.keys()]) f.release(id); await monitor.close(); }
  });
}

for (const lifetimeUs of [1n, 7n, 999n]) {
  test(`NETWORK expiry at exactly ${lifetimeUs}us prevents the next dependent start without timer polling`, async () => {
    const f = controlled();
    const owners = f.options.owners.map(owner => ({ ...owner, start(binding: Parameters<typeof owner.start>[0]) {
      const handle = owner.start(binding);
      if (owner.id === 5) f.time.advance(lifetimeUs * 1000n, false);
      return handle;
    } }));
    const monitor = new ReadinessMonitor({ ...f.options, owners });
    const running = monitor.checkStartup();
    try {
      for (const id of [1, 2, 3, 4]) { f.release(id); await flush(); }
      assert.deepEqual([...f.pending.keys()], [8]);
      f.release(8, pass(8, f.time.ns + lifetimeUs * 1000n)); await flush();
      const report = await running;
      assert.equal(report.ready, false); assert.equal(report.checks[7].reason, Reason.STALE);
      assert.equal(f.stats.starts, 6); assert.deepEqual([...f.pending.keys()], [5]);
      let closed = false; const closing = monitor.close().then(() => { closed = true; });
      await flush(); assert.equal(closed, false);
      f.release(5); await closing;
    } finally { for (const id of [...f.pending.keys()]) f.release(id); await monitor.close(); }
  });
}
