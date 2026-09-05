import assert from "node:assert/strict";
import test from "node:test";
import { create } from "@bufbuild/protobuf";
import { ReadinessCheckSchema, ReadinessCheckStatus, ReadinessReason, ReadinessReportSchema, encodeJson, type ReadinessCheck } from "@apex/contracts";
import { ReadinessMonitor } from "./readiness.js";
import { setup, pass } from "./readiness/test-support.js";

test("only nine actual component-owner successes publish a complete immutable generated bound report", async () => {
  const f = setup(), monitor = new ReadinessMonitor(f.options);
  assert.equal(monitor.snapshot().ready, false);
  const report = await monitor.checkStartup();
  assert.equal(report.ready, true);
  assert.equal(report.live, true);
  assert.deepEqual(report.checks.map(check => check.id), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
  assert.ok(report.checks.every(check => check.status === ReadinessCheckStatus.PASS && check.reason === ReadinessReason.OK));
  assert.deepEqual(report.target, f.launch.target);
  assert.equal(report.configHash, f.launch.configHash);
  assert.equal(report.runtimeManifestHash, f.launch.runtimeManifestHash);
  assert.equal(report.launchContextHash, f.launch.launchContextHash);
  assert.equal(report.processInstanceId, f.launch.processInstanceId);
  assert.equal(report.observedAtUnixUs, 9007199254740993n);
  assert.ok(Object.isFrozen(report) && Object.isFrozen(report.target) && Object.isFrozen(report.checks[0]));
  const text = JSON.stringify(encodeJson(ReadinessReportSchema, report as never));
  assert.ok(Buffer.byteLength(text) <= 8192);
  assert.ok(!text.includes("secret://") && !text.includes("component-profile"));
  assert.equal(f.stats.starts, 9);
  await monitor.close();
});

test("each owner requires known PASS OK and strictly future evidence; malformed outcomes never leak diagnostics", async () => {
  for (let id = 1; id <= 9; id++) {
    for (const kind of ["zero", "unknown", "pending", "denied", "unavailable", "expired", "missing", "wrong-id", "extra", "throw"]) {
      const f = setup();
      const owners = f.owners.map(owner => owner.id !== id ? owner : { ...owner, start: () => {
        if (kind === "throw") throw new Error("SENSITIVE-owner-secret");
        const outcome = pass(owner.id, f.time.ns + 1000000000n);
        const check = create(ReadinessCheckSchema, outcome.check as ReadinessCheck);
        if (kind === "zero") check.status = 0;
        if (kind === "unknown") check.status = 999 as ReadinessCheckStatus;
        if (kind === "pending") check.status = ReadinessCheckStatus.PENDING;
        if (kind === "denied") { check.status = ReadinessCheckStatus.FAIL; check.reason = ReadinessReason.INVALID; }
        if (kind === "unavailable") { check.status = ReadinessCheckStatus.FAIL; check.reason = ReadinessReason.UNAVAILABLE; }
        if (kind === "wrong-id") check.id = id === 9 ? 1 : id + 1;
        const value = kind === "missing" ? {} : { ...outcome, check,
          validUntilMonotonicNs: kind === "expired" ? f.time.ns : outcome.validUntilMonotonicNs,
          ...(kind === "extra" ? { diagnostic: "SENSITIVE-owner-secret" } : {}) };
        return { completion: Promise.resolve(value as never), cancel: () => {} };
      } });
      const monitor = new ReadinessMonitor({ ...f.options, owners });
      const report = await monitor.checkStartup();
      assert.equal(report.ready, false, `${id}/${kind}`);
      assert.equal(report.checks.length, 9);
      assert.equal(report.checks[id - 1].status, ReadinessCheckStatus.FAIL);
      const expected = kind === "expired" ? ReadinessReason.STALE : ["pending", "unavailable", "throw"].includes(kind)
        ? ReadinessReason.UNAVAILABLE : ReadinessReason.INVALID;
      assert.equal(report.checks[id - 1].reason, expected);
      assert.ok(!JSON.stringify(encodeJson(ReadinessReportSchema, report as never)).includes("SENSITIVE"));
      await monitor.close();
    }
  }
});

test("missing extra duplicate unknown owners or missing trusted predicate/fatal hooks cannot construct readiness", () => {
  const f = setup();
  for (const owners of [[], f.owners.slice(1), [...f.owners, f.owners[0]],
    f.owners.map((owner, index) => index === 8 ? f.owners[0] : owner),
    f.owners.map((owner, index) => index === 8 ? { ...owner, id: 999 } : owner),
    f.owners.map((owner, index) => index === 8 ? { ...owner, start: undefined } : owner)]) {
    assert.throws(() => new ReadinessMonitor({ ...f.options, owners } as never), /INVALID_INPUT: readiness configuration rejected safely/);
  }
  for (const key of ["isCurrent", "onFatal", "clock"]) {
    assert.throws(() => new ReadinessMonitor({ ...f.options, [key]: undefined }), /INVALID_INPUT: readiness configuration rejected safely/);
  }
  assert.equal(f.stats.starts, 0);
});

test("current-binding refusal or exception starts no work; later identity loss cannot revive old evidence", async () => {
  for (const isCurrent of [() => false, () => { throw new Error("SENSITIVE-current-owner"); }]) {
    const f = setup(), monitor = new ReadinessMonitor({ ...f.options, isCurrent });
    const report = await monitor.checkStartup();
    assert.equal(report.ready, false);
    assert.ok(report.checks.every(check => check.reason === ReadinessReason.MISMATCH));
    assert.equal(f.stats.starts, 0);
    await monitor.close();
  }
  const f = setup(), monitor = new ReadinessMonitor(f.options);
  const first = await monitor.checkStartup();
  f.stats.current = false;
  assert.equal(monitor.snapshot().ready, false);
  f.stats.current = true;
  assert.equal((await monitor.checkStartup()).ready, false);
  assert.equal(monitor.snapshot().observedAtUnixUs, first.observedAtUnixUs);
  assert.equal(f.stats.starts, 9);
  await monitor.close();
});
