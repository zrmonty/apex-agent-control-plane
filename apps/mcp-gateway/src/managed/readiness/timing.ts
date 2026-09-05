import { create } from "@bufbuild/protobuf";
import { ProxyStageTimingSchema, type ProxyStageTiming } from "@apex/contracts";
import { durationUs, type Clock, type ClockSnapshot } from "../../telemetry/clock.js";
import { assertDataTree } from "../runtime-config/boundary.js";
import type { CheckId } from "./types.js";

const NAMES = ["readiness.config", "readiness.launch", "readiness.material", "readiness.inbound_auth",
  "readiness.upstream_catalog", "readiness.governance", "readiness.evidence_admission", "readiness.network", "readiness.admission"];
const MAX = (1n << 64n) - 1n;

export function clockSample(clock: Clock, previous?: bigint): ClockSnapshot {
  const sample = clock.now();
  assertDataTree(sample, true);
  if (!sample || Object.keys(sample).some(key => !["monotonicNs", "unixUs", "resolutionNs", "uncertaintyUs", "source"].includes(key))) throw new Error();
  for (const value of [sample.monotonicNs, sample.unixUs, sample.resolutionNs]) {
    if (typeof value !== "bigint" || value < 0n || value > MAX) throw new Error();
  }
  if (sample.unixUs === 0n || sample.resolutionNs === 0n || (previous !== undefined && sample.monotonicNs < previous)) throw new Error();
  if (sample.uncertaintyUs !== undefined && (typeof sample.uncertaintyUs !== "bigint" || sample.uncertaintyUs < 0n || sample.uncertaintyUs > MAX)) throw new Error();
  // This is trusted clock provenance, never a probe-supplied diagnostic label.
  if (typeof sample.source !== "string" || !/^[\x20-\x7e]{1,128}$/.test(sample.source) || sample.source.trim() !== sample.source) throw new Error();
  return Object.freeze({ ...sample });
}

export function timing(id: CheckId, start: ClockSnapshot, end: ClockSnapshot, instance: string): ProxyStageTiming {
  return create(ProxyStageTimingSchema, { name: NAMES[id - 1], startedAtUnixUs: start.unixUs,
    durationUs: durationUs(start.monotonicNs, end.monotonicNs), durationNs: end.monotonicNs - start.monotonicNs,
    processInstanceId: instance, clockSource: start.source, clockResolutionNs: start.resolutionNs,
    clockUncertaintyUs: start.uncertaintyUs });
}
