import assert from "node:assert/strict";
import test from "node:test";
import { clone } from "@bufbuild/protobuf";
import { ReadinessReportSchema, RuntimeConfigurationSchema, RuntimeLaunchContextSchema } from "@apex/contracts";
import { ReadinessReportCodec } from "../report-codec.js";
import { launchContextHash } from "../../launch-context.js";
import { runtimeManifestHash } from "../../runtime-config.js";
import { fixture, rejects, rejectsBoth } from "./test-support.js";

test("codec constructor strictly revalidates expected config and generated launch rather than trusting their types", async () => {
  const f = fixture();
  for (const kind of ["config", "config-enforcement", "launch-hash", "launch-relation", "launch-health", "missing-config", "missing-launch"]) {
    const config = clone(RuntimeConfigurationSchema, f.options.configuration as never);
    const launch = clone(RuntimeLaunchContextSchema, f.launch);
    if (kind === "config") config.schemaVersion = 2;
    if (kind === "config-enforcement") {
      config.spec!.runtimeProfile!.rootless = false;
      config.runtimeManifestHash = runtimeManifestHash(config); launch.runtimeManifestHash = config.runtimeManifestHash;
      launch.launchContextHash = launchContextHash(launch);
    }
    if (kind === "launch-hash") launch.launchContextHash = "c".repeat(64);
    if (kind === "launch-relation") { launch.target!.generation++; launch.launchContextHash = launchContextHash(launch); }
    if (kind === "launch-health") { launch.health!.port = 8080; launch.launchContextHash = launchContextHash(launch); }
    const binding = { config: kind === "missing-config" ? undefined : config, launch: kind === "missing-launch" ? undefined : launch };
    rejects(() => new ReadinessReportCodec(binding as never));
  }
  await f.monitor.close();
});

test("both codec directions require every exact bound target and digest without rounding uint64", async () => {
  const f = fixture(), pristine = structuredClone(f.report);
  for (const field of ["workspaceId", "namespaceId", "proxyId", "revisionId", "generation", "fencingToken"] as const) {
    const report = clone(ReadinessReportSchema, f.report);
    if (field === "generation") report.target!.generation++;
    else if (field === "fencingToken") report.target!.fencingToken--; // Adjacent values collapse through Number.
    else if (field === "proxyId" || field === "revisionId") report.target![field] = "01992000-0000-7000-8000-000000000099";
    else report.target![field] += "-other";
    rejectsBoth(f.codec, report);
  }
  for (const field of ["configHash", "runtimeManifestHash", "processInstanceId", "launchContextHash"] as const) {
    const report = clone(ReadinessReportSchema, f.report);
    report[field] = field === "processInstanceId" ? "01992000-0000-7000-8000-000000000099" : "c".repeat(64);
    rejectsBoth(f.codec, report);
  }
  const absent = clone(ReadinessReportSchema, f.report); absent.target = undefined;
  rejectsBoth(f.codec, absent);
  assert.deepEqual(f.report, pristine); await f.monitor.close();
});

test("codec binding is independently copied once and caller mutation cannot move subsequent requests", async () => {
  const f = fixture(), config = clone(RuntimeConfigurationSchema, f.options.configuration as never);
  const launch = clone(RuntimeLaunchContextSchema, f.launch);
  const codec = new ReadinessReportCodec({ config, launch });
  assert.equal(Object.isFrozen(config), false); assert.equal(Object.isFrozen(launch.target), false);
  config.configHash = "REPORT_CANARY"; launch.target!.fencingToken--; launch.launchContextHash = "REPORT_CANARY";
  const original = codec.encode(f.report);
  assert.deepEqual(codec.decode(original), f.report);
  const moved = clone(ReadinessReportSchema, f.report); moved.target!.fencingToken = launch.target!.fencingToken;
  rejectsBoth(codec, moved);
  rejects(() => new ReadinessReportCodec({ config, launch }));
  await f.monitor.close();
});
