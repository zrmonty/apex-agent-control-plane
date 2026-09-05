import assert from "node:assert/strict";
import test from "node:test";
import { clone, create } from "@bufbuild/protobuf";
import { ReadinessCheckSchema, ReadinessCheckStatus as Status, ReadinessReason as Reason,
  RuntimeConfigurationSchema, type RuntimeConfiguration } from "@apex/contracts";
import { ReadinessMonitor } from "../../readiness.js";
import { ReadinessReportCodec } from "../report-codec.js";
import { controlled, flush, setup } from "../test-support.js";

test("one bound codec preserves cold unavailable ready stale shutdown and fatal monitor observations", async () => {
  for (const state of ["cold", "unavailable", "ready", "stale", "shutdown", "fatal"] as const) {
    const f = controlled(), monitor = new ReadinessMonitor(f.options);
    const codec = new ReadinessReportCodec({ config: f.options.configuration, launch: f.launch });
    if (state !== "cold") {
      const running = monitor.checkStartup();
      if (state === "shutdown") void monitor.close();
      else if (state === "fatal") { f.time.advance(2000000000n); f.time.advance(5000000000n); }
      else {
        f.time.advance(1001n);
        if (state === "unavailable") {
          f.release(1, { check: create(ReadinessCheckSchema, { id: 1, status: Status.FAIL, reason: Reason.UNAVAILABLE }),
            validUntilMonotonicNs: f.time.ns + 1000000000n }); await flush();
        }
        while (f.pending.size) { for (const id of [...f.pending.keys()]) f.release(id); await flush(); }
      }
      await running;
      if (state === "stale") f.time.advance(10000000000n);
    }
    const observed = monitor.snapshot(), before = structuredClone(observed), starts = f.stats.starts, cancels = f.stats.cancels;
    assert.equal(observed.ready, state === "ready", state);
    assert.equal(observed.live, state !== "shutdown" && state !== "fatal", state);
    assert.equal(f.stats.fatal, state === "fatal" ? 1 : 0);
    for (let i = 0; i < 3; i++) {
      assert.deepEqual(codec.decode(codec.encode(monitor.snapshot())), before);
      assert.equal(monitor.snapshot().observedAtUnixUs, before.observedAtUnixUs);
    }
    assert.equal(f.stats.starts, starts); assert.equal(f.stats.cancels, cancels);
    for (const id of [...f.pending.keys()]) f.release(id);
    await flush(); await monitor.close();
    assert.equal(f.time.scheduled, 0); assert.deepEqual(observed, before);
  }
});

test("monitor publication uses copied constructor metadata and never re-reads mutable caller inputs", async () => {
  const f = setup(), config = clone(RuntimeConfigurationSchema, f.options.configuration as RuntimeConfiguration);
  const launchContext = structuredClone(f.options.launchContext);
  const monitor = new ReadinessMonitor({ ...f.options, configuration: config, launchContext });
  let canary = 0;
  const unexpected = () => { canary++; throw new Error("REPORT_CANARY"); };
  Object.defineProperty(config, "spec", { enumerable: true, get: unexpected });
  Object.defineProperty(launchContext, "target", { enumerable: true, get: unexpected });
  const first = await monitor.checkStartup(); assert.equal(first.ready, true);
  f.time.advance(10000000000n);
  assert.equal(monitor.snapshot().ready, false);
  assert.equal(monitor.snapshot().observedAtUnixUs, first.observedAtUnixUs);
  await monitor.close(); assert.equal(canary, 0);
});
