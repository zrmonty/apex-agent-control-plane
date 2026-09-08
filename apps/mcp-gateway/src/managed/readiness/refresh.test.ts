import assert from "node:assert/strict";
import test from "node:test";
import { ReadinessCheckStatus as Status, ReadinessReason as Reason } from "@apex/contracts";
import { ReadinessMonitor } from "../readiness.js";
import { controlled, flush, pass, setup } from "./test-support.js";
import type { ProbeHandle, ReadonlyReadinessReport } from "./types.js";

async function prepared(expiryNs = 10000000000n) {
  const f = controlled(), monitor = new ReadinessMonitor(f.options);
  const expiry = f.time.ns + expiryNs, running = monitor.checkStartup();
  while (f.pending.size) {
    for (const id of [...f.pending.keys()]) f.release(id, pass(id as 1, expiry));
    await flush();
  }
  const first = await running;
  assert.equal(first.ready, true);
  return { ...f, monitor, first };
}
async function finish(f: Awaited<ReturnType<typeof prepared>>) {
  while (f.pending.size) {
    for (const id of [...f.pending.keys()]) f.release(id);
    await flush();
  }
}

test("a healthy refresh retains the original unexpired evidence without renewing its age", async () => {
  const f = await prepared();
  f.time.advance(5000000000n);
  const refresh = f.monitor.checkStartup();
  try {
    assert.equal(f.monitor.snapshot().ready, true);
    assert.equal(f.monitor.snapshot(), f.first);
    assert.equal(f.monitor.checkStartup(), refresh);
    f.time.advance(1000000000n);
    assert.equal(f.monitor.snapshot(), f.first);
    await finish(f);
    const second = await refresh;
    assert.equal(second.ready, true);
    assert.notEqual(second, f.first);
    assert.equal(second.observedAtUnixUs, f.first.observedAtUnixUs + 6000000n);
  } finally { await finish(f); await f.monitor.close(); }
});

test("an in-flight refresh cannot hide the exact expiry of its cached predecessor", async () => {
  const f = await prepared(5500000000n);
  f.time.advance(5000000000n);
  const refresh = f.monitor.checkStartup();
  try {
    assert.equal(f.monitor.snapshot().ready, true);
    f.time.advance(499999999n);
    assert.equal(f.monitor.snapshot().ready, true);
    f.time.advance(1n);
    const stale = f.monitor.snapshot();
    assert.equal(stale.ready, false);
    assert.ok(stale.checks.every(check => check.reason === Reason.STALE));
    assert.equal(stale.observedAtUnixUs, f.first.observedAtUnixUs);
  } finally { await finish(f); await refresh; await f.monitor.close(); }
});

test("a newly observed dependency failure invalidates cached readiness before the sweep ends", async () => {
  const f = await prepared();
  f.time.advance(5000000000n);
  const refresh = f.monitor.checkStartup();
  try {
    assert.equal(f.monitor.snapshot().ready, true);
    const failed = pass(1, f.time.ns + 1000000000n);
    f.release(1, { ...failed, check: { ...failed.check, status: Status.FAIL, reason: Reason.UNAVAILABLE } });
    await flush();
    assert.ok(f.pending.size > 0);
    assert.equal(f.monitor.snapshot().ready, false);
    assert.equal(f.monitor.snapshot().observedAtUnixUs, f.first.observedAtUnixUs);
    await finish(f);
    assert.equal((await refresh).ready, false);
  } finally { await finish(f); await f.monitor.close(); }
});

test("a synchronous owner refusal during refresh immediately invalidates the old cache", async () => {
  const f = setup();
  let fail = false;
  const owners = f.owners.map(owner => ({ ...owner, start: () => {
    if (fail && owner.id === 1) throw Error("synthetic owner refusal");
    return owner.start({ config: f.options.configuration, launch: f.launch });
  } }));
  const monitor = new ReadinessMonitor({ ...f.options, owners });
  const first = await monitor.checkStartup();
  fail = true; f.time.advance(5000000000n);
  const refresh = monitor.checkStartup();
  assert.equal(monitor.snapshot().ready, false);
  assert.equal(monitor.snapshot().observedAtUnixUs, first.observedAtUnixUs);
  assert.equal((await refresh).ready, false);
  await monitor.close();
});

for (const cause of ["timeout", "binding", "shutdown"] as const) {
  test(`${cause} during refresh still invalidates cached readiness and retains cleanup ownership`, async () => {
    const f = await prepared();
    f.time.advance(5000000000n);
    const refresh = f.monitor.checkStartup();
    assert.equal(f.monitor.snapshot().ready, true);
    if (cause === "timeout") f.time.advance(2000000000n);
    if (cause === "binding") f.stats.current = false;
    let closed = false;
    const closing = cause === "shutdown" ? f.monitor.close().then(() => { closed = true; }) : undefined;
    assert.equal(f.monitor.snapshot().ready, false);
    assert.equal(f.monitor.snapshot().observedAtUnixUs, f.first.observedAtUnixUs);
    await flush(); assert.equal(closed, false);
    await finish(f); assert.equal((await refresh).ready, false);
    await (closing ?? f.monitor.close());
  });
}

test("snapshot refuses the exact active refresh deadline before timers run without starting or cancelling I/O", async () => {
  const f = await prepared();
  f.time.advance(5000000000n);
  const refresh = f.monitor.checkStartup();
  try {
    const starts = f.stats.starts, cancels = f.stats.cancels, timers = f.time.scheduled;
    f.time.advance(1999999999n, false);
    assert.equal(f.monitor.snapshot(), f.first);
    f.time.advance(1n, false);
    const expired = f.monitor.snapshot();
    assert.equal(expired.ready, false);
    assert.ok(expired.checks.every(check => check.reason === Reason.TIMEOUT));
    assert.equal(expired.observedAtUnixUs, f.first.observedAtUnixUs);
    assert.deepEqual(expired.stages, f.first.stages);
    assert.equal(f.stats.starts, starts); assert.equal(f.stats.cancels, cancels);
    assert.equal(f.time.scheduled, timers); assert.equal(f.pending.size, 4);
    let completed = false; void refresh.then(() => { completed = true; });
    await flush(); assert.equal(completed, false);
    await finish(f); assert.equal((await refresh).ready, false);
  } finally { await finish(f); await f.monitor.close(); }
});

test("malformed refresh invalidation is visible inside the scheduler cancellation callback before fatal cleanup", async () => {
  const f = setup();
  let malformed = false, observed: ReadonlyReadinessReport | undefined;
  const owners = f.owners.map(owner => ({ ...owner, start: () => {
    if (malformed && owner.id === 1) return undefined as unknown as ProbeHandle;
    return owner.start({ config: f.options.configuration, launch: f.launch });
  } }));
  const monitor = new ReadinessMonitor({ ...f.options, owners, scheduler: { after(ms, callback) {
    const cancel = f.time.scheduler.after(ms, callback);
    return () => {
      cancel();
      if (malformed && observed === undefined) {
        assert.equal(f.stats.fatal, 0);
        observed = monitor.snapshot();
      }
    };
  } } });
  try {
    const first = await monitor.checkStartup(); assert.equal(first.ready, true);
    malformed = true; f.time.advance(5000000000n);
    const refresh = monitor.checkStartup();
    assert.ok(observed);
    assert.equal(observed.ready, false);
    assert.ok(observed.checks.every(check => check.reason === Reason.INVALID));
    assert.equal(observed.observedAtUnixUs, first.observedAtUnixUs);
    assert.deepEqual(observed.stages, first.stages);
    assert.equal((await refresh).ready, false); assert.equal(f.stats.fatal, 1);
  } finally { await monitor.close(); }
});
