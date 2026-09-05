import assert from "node:assert/strict";
import test from "node:test";
import { clone } from "@bufbuild/protobuf";
import { ReadinessReportSchema, RuntimeConfigurationSchema, RuntimeLaunchContextSchema } from "@apex/contracts";
import { ReadinessReportCodec } from "../report-codec.js";
import { completed, fixture, rejects } from "./test-support.js";

test("generated report preflight executes no root nested list Proxy getter or toJSON hook", async () => {
  const f = await completed();
  let executed = 0;
  const canary = (): never => { executed++; throw new Error("REPORT_CANARY"); };
  const root = Object.defineProperty(clone(ReadinessReportSchema, f.report), "live", { enumerable: true, get: canary });
  const stage = clone(ReadinessReportSchema, f.report);
  Object.defineProperty(stage.stages[0], "clockSource", { enumerable: true, get: canary });
  const list = clone(ReadinessReportSchema, f.report);
  Object.defineProperty(list.checks, 0, { enumerable: true, get: canary });
  const proxy = new Proxy(f.report, { get: canary, ownKeys: canary, getPrototypeOf: canary });
  const nested = clone(ReadinessReportSchema, f.report); nested.target = new Proxy(nested.target!, { get: canary, ownKeys: canary });
  const hook = Object.defineProperty(clone(ReadinessReportSchema, f.report), "toJSON", { value: canary });
  for (const report of [root, stage, list, proxy, nested, hook]) rejects(() => f.codec.encode(report));
  for (const input of [root, proxy, hook]) rejects(() => f.codec.decode(input as never));
  assert.equal(executed, 0); await f.monitor.close();
});

test("binding construction also rejects active objects and unsafe shape without coercion or execution", async () => {
  const f = fixture();
  let executed = 0;
  const canary = (): never => { executed++; throw new Error("REPORT_CANARY"); };
  const binding = { config: f.options.configuration, launch: f.launch };
  const config = clone(RuntimeConfigurationSchema, f.options.configuration as never);
  Object.defineProperty(config.spec!, "ingress", { enumerable: true, get: canary });
  const launch = clone(RuntimeLaunchContextSchema, f.launch);
  Object.defineProperty(launch, "target", { enumerable: true, get: canary });
  for (const input of [
    new Proxy(binding, { get: canary, ownKeys: canary, getPrototypeOf: canary }),
    Object.defineProperty({ ...binding }, "launch", { enumerable: true, get: canary }),
    Object.defineProperty({ ...binding }, "toJSON", { value: canary }), { ...binding, config }, { ...binding, launch },
    { ...binding, extra: "REPORT_CANARY" }, null, undefined, [],
  ]) rejects(() => new ReadinessReportCodec(input as never));
  assert.equal(executed, 0); await f.monitor.close();
});

test("no generated field can disappear through hidden properties prototypes unknown keys or invalid scalar defaults", async () => {
  const f = await completed();
  const cycle = clone(ReadinessReportSchema, f.report); Object.assign(cycle, { self: cycle });
  const sparse = clone(ReadinessReportSchema, f.report); sparse.stages = Array(2);
  const unknown = clone(ReadinessReportSchema, f.report); Object.assign(unknown.stages[0], { rawSecret: "REPORT_CANARY" });
  for (const report of [
    cycle, sparse, unknown, { ...f.report, surprise: "REPORT_CANARY" },
    Object.defineProperty(clone(ReadinessReportSchema, f.report), "hidden", { value: "REPORT_CANARY" }),
    { ...f.report, [Symbol("REPORT_CANARY")]: true }, Object.assign(Object.create({ inherited: true }), f.report),
    new Date(), new Map(), [], null,
  ]) rejects(() => f.codec.encode(report as never));
  for (const change of [{ live: undefined }, { ready: "false" }, { checks: undefined },
    { observedAtUnixUs: 0 }, { observedAtUnixUs: -1n }, { observedAtUnixUs: 1n << 64n }, { $typeName: "REPORT_CANARY" }]) {
    rejects(() => f.codec.encode(Object.assign(clone(ReadinessReportSchema, f.report), change) as never));
  }
  for (const field of ["startedAtUnixUs", "durationUs", "durationNs", "clockResolutionNs", "clockUncertaintyUs"] as const) {
    for (const value of [null, "0", 0, -1n, 1n << 64n]) {
      const report = clone(ReadinessReportSchema, f.report); Object.assign(report.stages[0], { [field]: value });
      rejects(() => f.codec.encode(report));
    }
  }
  await f.monitor.close();
});

test("shared generated data is preflighted before ANY serialization including reconstructed ProtoJSON", async context => {
  const f = await completed();
  context.after(() => f.monitor.close());
  function observe(report: typeof f.report) {
    let descriptorEntries = 0, serialized = 0, caught: unknown;
    const originalKeys = Object.keys;
    // Descriptor entry precedes the competing stage-count/unknown-key failures.
    const keys = context.mock.method(Object, "keys", (value: object) => {
      if (value === report) descriptorEntries++;
      return originalKeys(value);
    });
    try {
      const stringify = context.mock.method(JSON, "stringify", () => { serialized++; throw new Error("REPORT_CANARY"); });
      try { f.codec.encode(report); } catch (error) { caught = error; } finally { stringify.mock.restore(); }
    } finally { keys.mock.restore(); }
    return { descriptorEntries, serialized, caught };
  }
  const observations: { descriptorEntries: number; serialized: number }[] = [];
  for (const shared of [
    { ...f.report.stages[0], clockSource: "x".repeat(16384) },
    { ...f.report.stages[0], ["k".repeat(16384)]: "" },
    { ...f.report.stages[0], clockSource: "\u0000".repeat(4096) },
  ]) {
    const report = clone(ReadinessReportSchema, f.report); report.stages = Array(17).fill(shared);
    const { caught, ...observed } = observe(report);
    rejects(() => { if (caught !== undefined) throw caught; });
    observations.push(observed);
  }
  const { caught, ...positive } = observe(f.report);
  rejects(() => { if (caught !== undefined) throw caught; });
  assert.deepEqual(positive, { descriptorEntries: 1, serialized: 1 }, "valid report reaches both probes");
  assert.deepEqual(f.codec.decode(f.codec.encode(f.report)), f.report, "valid report round trips after probe restoration");
  assert.deepEqual(observations, Array(3).fill({ descriptorEntries: 0, serialized: 0 }),
    "shared values, keys and escaping stop before descriptors and ALL serialization, regardless of object identity");
});
