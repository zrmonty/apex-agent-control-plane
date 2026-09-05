import assert from "node:assert/strict";
import { clone, toJson } from "@bufbuild/protobuf";
import { ReadinessReportSchema, type ReadinessReport } from "@apex/contracts";
import { GatewayError } from "../../../contracts.js";
import { ReadinessMonitor } from "../../readiness.js";
import { ReadinessReportCodec } from "../report-codec.js";
import { setup } from "../test-support.js";

export function fixture() {
  const f = setup(), monitor = new ReadinessMonitor(f.options);
  const codec = new ReadinessReportCodec({ config: f.options.configuration, launch: f.launch });
  return { ...f, monitor, codec, report: clone(ReadinessReportSchema, monitor.snapshot() as ReadinessReport) };
}
export async function completed() {
  const f = fixture();
  return { ...f, report: clone(ReadinessReportSchema, await f.monitor.checkStartup() as ReadinessReport) };
}
export function text(report: ReadinessReport): string { return JSON.stringify(toJson(ReadinessReportSchema, report)); }
export function rejects(action: () => unknown): void {
  assert.throws(action, (error: unknown) => {
    assert.ok(error instanceof GatewayError);
    assert.equal(error.code, "INVALID_INPUT");
    assert.equal(error.message, "INVALID_INPUT: readiness report rejected safely");
    assert.equal((error as Error & { cause?: unknown }).cause, undefined);
    assert.ok(!String(error.stack).includes("REPORT_CANARY") && !JSON.stringify(error).includes("REPORT_CANARY"));
    return true;
  });
}
export function rejectsBoth(codec: ReadinessReportCodec, report: ReadinessReport): void {
  rejects(() => codec.encode(report)); rejects(() => codec.decode(text(report)));
}
