import type { ReadonlyRuntimeLaunchContext } from "../../launch-context.js";
import { ReadinessCheckStatus as Status, ReadinessReason as Reason } from "@apex/contracts";
import { requireValue } from "../../runtime-config/boundary.js";
import { CHECK_IDS, type ReadonlyReadinessReport } from "../types.js";
import { READINESS_STAGE_NAMES } from "../timing.js";

/** Internal to the codec: requires descriptor-checked data and validated launch.
 * One semantic profile for both generated output and strict original JSON input.
 * Identity equality is not authentication, active lease, freshness or admission. */
export function validateReport(report: ReadonlyReadinessReport, launch: ReadonlyRuntimeLaunchContext): void {
  const target = report.target, expected = launch.target;
  requireValue(target && expected);
  for (const field of ["workspaceId", "namespaceId", "proxyId", "revisionId", "generation", "fencingToken"] as const) {
    requireValue(target[field] === expected[field]);
  }
  for (const field of ["configHash", "runtimeManifestHash", "processInstanceId", "launchContextHash"] as const) {
    requireValue(report[field] === launch[field]);
  }
  requireValue(report.checks.length === CHECK_IDS.length && new Set(report.checks.map(check => check.id)).size === CHECK_IDS.length);
  for (const check of report.checks) {
    requireValue(CHECK_IDS.some(id => id === check.id));
    if (check.status === Status.PASS) requireValue(check.reason === Reason.OK);
    else if (check.status === Status.PENDING) requireValue(check.reason === Reason.UNAVAILABLE);
    else requireValue(check.status === Status.FAIL && check.reason !== Reason.UNSPECIFIED && check.reason !== Reason.OK);
  }
  requireValue(report.stages.length <= 9 && new Set(report.stages.map(stage => stage.name)).size === report.stages.length);
  for (const stage of report.stages) {
    requireValue(READINESS_STAGE_NAMES.includes(stage.name) && stage.processInstanceId === launch.processInstanceId);
    requireValue(stage.startedAtUnixUs > 0n && stage.clockResolutionNs > 0n && stage.durationNs !== undefined);
    requireValue(stage.durationUs === stage.durationNs / 1000n);
    requireValue(/^[\x20-\x7e]{1,128}$/.test(stage.clockSource) && stage.clockSource.trim() === stage.clockSource);
    requireValue(stage.otelTraceId === "" && stage.spanId === "" && stage.parentSpanId === "");
    // Descriptor validation preserves optional uint64 uncertainty, including zero.
    // These wire samples establish no remote freshness or cross-host accuracy.
  }
  if (report.observedAtUnixUs === 0n) requireValue(!report.ready && report.stages.length === 0);
  if (report.ready) requireValue(report.live && report.observedAtUnixUs > 0n && report.stages.length === 9 &&
    report.checks.every(check => check.status === Status.PASS && check.reason === Reason.OK));
}
