import assert from "node:assert/strict";
import test from "node:test";
import { RuntimeLaunchContextSchema, RuntimeConfigurationSchema, ReadinessReportSchema, ReadinessCheckSchema,
  ReadinessCheckStatus, encodeJson, type RuntimeConfiguration, type ReadinessCheck } from "@apex/contracts";
import { clone } from "@bufbuild/protobuf";
import { launchContextHash } from "../launch-context.js";
import { ReadinessMonitor } from "../readiness.js";
import { setup, pass, controlled, flush } from "./test-support.js";

test("strict parser rejects independent mismatched or active metadata without starting a probe or echoing canaries", async () => {
  const f = setup();
  const pristine = clone(RuntimeLaunchContextSchema, f.launch);
  const positive = new ReadinessMonitor({ ...setup().options, launchContext: encodeJson(RuntimeLaunchContextSchema, pristine) });
  assert.equal((await positive.checkStartup()).ready, true); await positive.close();
  for (const field of ["workspaceId", "namespaceId", "proxyId", "revisionId", "generation"] as const) {
    const launch = clone(RuntimeLaunchContextSchema, f.launch);
    if (field === "generation") launch.target!.generation++;
    else if (field === "workspaceId" || field === "namespaceId") launch.target![field] += "-other";
    else launch.target![field] = "01992000-0000-7000-8000-000000000099";
    launch.launchContextHash = launchContextHash(launch);
    assert.throws(() => new ReadinessMonitor({ ...f.options, launchContext: encodeJson(RuntimeLaunchContextSchema, launch) }),
      /^GatewayError: INVALID_INPUT: readiness configuration rejected safely$/);
    assert.deepEqual(f.launch, pristine, `${field} must not mutate the next case's pristine launch`);
  }
  for (const field of ["configHash", "runtimeManifestHash", "imageRef"] as const) {
    const launch = clone(RuntimeLaunchContextSchema, f.launch);
    launch[field] = field === "imageRef" ? launch.imageRef.replace("@", "-other@") :
      (launch[field] === "c".repeat(64) ? "d" : "c").repeat(64);
    // Valid syntax and a fresh self-digest isolate the config relation, not integrity.
    launch.launchContextHash = launchContextHash(launch);
    assert.throws(() => new ReadinessMonitor({ ...f.options, launchContext: encodeJson(RuntimeLaunchContextSchema, launch) }),
      /INVALID_INPUT: readiness configuration rejected safely/);
    assert.deepEqual(f.launch, pristine, `${field} relation must not contaminate another case`);
  }
  for (const field of ["configHash", "runtimeManifestHash", "imageRef", "processInstanceId", "launchContextHash"] as const) {
    const launch = clone(RuntimeLaunchContextSchema, f.launch); launch[field] = "SENSITIVE";
    if (field !== "launchContextHash") launch.launchContextHash = launchContextHash(launch);
    assert.throws(() => new ReadinessMonitor({ ...f.options, launchContext: encodeJson(RuntimeLaunchContextSchema, launch) }),
      /INVALID_INPUT: readiness configuration rejected safely/);
    assert.deepEqual(f.launch, pristine, `${field} must not mutate the next case's pristine launch`);
  }
  let canary = 0;
  const input = Object.defineProperty({}, "target", { enumerable: true, get() { canary++; return f.launch.target; } });
  const configuration = new Proxy(f.options.configuration, { get() { canary++; throw new Error("SENSITIVE"); } });
  assert.throws(() => new ReadinessMonitor({ ...f.options, launchContext: input }), /readiness configuration rejected safely/);
  assert.throws(() => new ReadinessMonitor({ ...f.options, configuration }), /readiness configuration rejected safely/);
  assert.equal(canary, 0); assert.equal(f.stats.starts, 0);
});

test("trusted owner sees an immutable independent full binding and no mutating authority API", async () => {
  const f = setup();
  const configuration = clone(RuntimeConfigurationSchema, f.options.configuration as RuntimeConfiguration);
  const launch = encodeJson(RuntimeLaunchContextSchema, f.launch) as Record<string, unknown>;
  const expectedConfig = structuredClone(configuration), expectedLaunch = structuredClone(f.launch);
  const owners = f.owners.map(owner => ({ ...owner, start: (binding: Parameters<typeof owner.start>[0]) => {
    assert.deepEqual(Object.keys(binding).sort(), ["config", "launch"]);
    assert.deepEqual(binding.config, expectedConfig); assert.deepEqual(binding.launch, expectedLaunch);
    assert.ok(Object.isFrozen(binding.config.spec!.runtimeProfile) && Object.isFrozen(binding.launch.target));
    return owner.start(binding);
  } }));
  const monitor = new ReadinessMonitor({ ...f.options, configuration, launchContext: launch, owners });
  configuration.configHash = "SENSITIVE"; launch.processInstanceId = "SENSITIVE";
  assert.equal((await monitor.checkStartup()).ready, true);
  await monitor.close();
});

test("each trusted live-owner target digest fence and instance change invalidates the immutable cached launch", async () => {
  for (const field of ["workspaceId", "namespaceId", "proxyId", "revisionId", "generation", "fencingToken",
    "configHash", "runtimeManifestHash", "processInstanceId", "launchContextHash"]) {
    const f = setup(), expected = structuredClone(f.launch);
    const monitor = new ReadinessMonitor({ ...f.options, isCurrent: binding => {
      try { assert.deepEqual(binding.launch, expected); return true; } catch { return false; }
    } });
    const first = await monitor.checkStartup();
    if (field === "generation" || field === "fencingToken") expected.target![field]++;
    else if (field in expected.target!) Object.assign(expected.target!, { [field]: "SENSITIVE-current-change" });
    else Object.assign(expected, { [field]: "SENSITIVE-current-change" });
    const report = monitor.snapshot();
    assert.equal(report.ready, false, field);
    assert.equal(report.observedAtUnixUs, first.observedAtUnixUs);
    assert.ok(!JSON.stringify(encodeJson(ReadinessReportSchema, report as never)).includes("SENSITIVE"));
    assert.equal(f.stats.starts, 9);
    await monitor.close();
  }
});

test("active or unknown-enum probe evidence is rejected without executing or reflecting input", async () => {
  let canary = 0;
  for (const kind of ["getter", "proxy", "zero-reason", "unknown-reason"]) {
    const f = setup();
    const owners = f.owners.map(owner => owner.id !== 1 ? owner : { ...owner, start: () => {
      const result = pass(1, f.time.ns + 1000000000n);
      const value = { ...result, check: clone(ReadinessCheckSchema, result.check as ReadinessCheck) };
      if (kind === "zero-reason") value.check.reason = 0;
      if (kind === "unknown-reason") value.check.reason = 999 as never;
      if (kind === "proxy") value.check = new Proxy(value.check, { get() { canary++; throw new Error("SENSITIVE"); } });
      const completion = Promise.resolve(kind === "getter" ? Object.defineProperty(value, "check", { get() { canary++; throw new Error("SENSITIVE"); } }) : value);
      return { completion, cancel: () => {} };
    } });
    const monitor = new ReadinessMonitor({ ...f.options, owners });
    assert.equal((await monitor.checkStartup()).ready, false);
    await monitor.close();
  }
  assert.equal(canary, 0);
});

test("completed probe evidence is copied before a caller can mutate the original generated message", async () => {
  const f = controlled(), monitor = new ReadinessMonitor(f.options), running = monitor.checkStartup();
  const outcome = pass(1, f.time.ns + 1000000000n);
  f.release(1, outcome); await flush();
  Object.assign(outcome.check, { status: ReadinessCheckStatus.UNSPECIFIED });
  while (f.pending.size) { for (const id of [...f.pending.keys()]) f.release(id); await flush(); }
  assert.equal((await running).ready, true);
  assert.equal(Object.isFrozen(outcome.check), false, "do not freeze the caller's object");
  await monitor.close();
});

test("current-binding loss in flight invalidates before any next owner start and never revives late completions", async () => {
  const f = controlled(), monitor = new ReadinessMonitor(f.options), running = monitor.checkStartup();
  f.stats.current = false;
  assert.equal(monitor.snapshot().ready, false);
  assert.equal(f.stats.cancels, 0, "snapshot itself performs no probe I/O/cancellation");
  f.stats.current = true;
  f.release(1); await flush();
  assert.equal(f.stats.cancels, 3);
  assert.equal(f.stats.starts, 4);
  assert.equal((await running).ready, false);
  for (const id of [...f.pending.keys()]) f.release(id);
  await flush(); await monitor.close();
});
