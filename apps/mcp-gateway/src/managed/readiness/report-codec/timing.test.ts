import assert from "node:assert/strict";
import test from "node:test";
import { clone } from "@bufbuild/protobuf";
import { ReadinessReportSchema } from "@apex/contracts";
import { completed, rejectsBoth } from "./test-support.js";

test("each stage requires original same-instance clock metadata and an exact nanosecond duration", async () => {
  const f = await completed();
  const mutations = [
    { processInstanceId: "01992000-0000-7000-8000-000000000099" }, { startedAtUnixUs: 0n },
    { clockResolutionNs: 0n }, { durationNs: undefined }, { durationNs: 1001n, durationUs: 2n },
    { clockSource: "" }, { clockSource: "x".repeat(129) }, { clockSource: " padding" }, { clockSource: "padding " },
    { clockSource: "REPORT_CANARY\n" }, { clockSource: "REPORT_CANARY\x7f" }, { clockSource: "REPORT_CANARYé" },
  ];
  for (let index = 0; index < 9; index++) for (const change of mutations) {
    const report = clone(ReadinessReportSchema, f.report); Object.assign(report.stages[index], change);
    rejectsBoth(f.codec, report);
  }
  await f.monitor.close();
});

test("fixed readiness profile has no owner for trace span or parent identifiers", async () => {
  const f = await completed();
  for (const field of ["otelTraceId", "spanId", "parentSpanId"] as const) {
    for (const value of ["REPORT_CANARY-secret://health/token", "0".repeat(32)]) {
      const report = clone(ReadinessReportSchema, f.report); report.stages[0][field] = value;
      rejectsBoth(f.codec, report);
    }
  }
  await f.monitor.close();
});

test("codec preserves 1 7 999us sub-us remainder and exact uint64 extrema without remote wall arithmetic", async () => {
  const f = await completed(), maximum = (1n << 64n) - 1n;
  const samples = [[1001n, 1n], [7001n, 7n], [999001n, 999n], [999n, 0n], [0n, 0n],
    [9007199254740993123n, 9007199254740993n], [maximum, 18446744073709551n]];
  for (const [durationNs, durationUs] of samples) {
    const report = clone(ReadinessReportSchema, f.report);
    report.observedAtUnixUs = 1n; // Codec must not invent wall-time/age arithmetic.
    Object.assign(report.stages[0], { durationNs, durationUs, startedAtUnixUs: maximum,
      clockResolutionNs: maximum, clockUncertaintyUs: maximum, clockSource: "\\".repeat(128) });
    const encoded = f.codec.encode(report), decoded = f.codec.decode(encoded);
    assert.deepEqual(decoded, report);
    assert.equal(decoded.stages[0].durationNs, durationNs); assert.equal(decoded.stages[0].durationUs, durationUs);
    assert.equal(decoded.stages[0].startedAtUnixUs, maximum); assert.equal(decoded.stages[0].clockUncertaintyUs, maximum);
    assert.ok(!Object.isFrozen(report.stages[0]));
  }
  const report = clone(ReadinessReportSchema, f.report); report.observedAtUnixUs = maximum;
  assert.equal(f.codec.decode(f.codec.encode(report)).observedAtUnixUs, maximum);
  await f.monitor.close();
});

test("optional clock uncertainty stays absent or explicit zero in generated data and ProtoJSON", async () => {
  const f = await completed();
  for (const uncertainty of [undefined, 0n]) {
    const report = clone(ReadinessReportSchema, f.report); report.stages[0].clockUncertaintyUs = uncertainty;
    report.stages[0].durationNs = 0n; report.stages[0].durationUs = 0n;
    const encoded = f.codec.encode(report), decoded = f.codec.decode(encoded);
    assert.equal(decoded.stages[0].clockUncertaintyUs, uncertainty);
    assert.equal(decoded.stages[0].durationNs, 0n);
    assert.equal(JSON.parse(encoded).stages[0].clockUncertaintyUs, uncertainty === undefined ? undefined : "0");
    assert.equal(JSON.parse(encoded).stages[0].durationNs, "0");
  }
  await f.monitor.close();
});
