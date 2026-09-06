import { randomBytes } from "node:crypto";
import type { ClockSnapshot } from "../../telemetry/clock.js";
import type { CallObservation } from "../call-observation.js";
import type { MeasuredStage } from "../evidence/types.js";
import type { StageInterval } from "./types.js";
import { consistent, snapshot } from "../call-preparation/timing.js";
import { refused } from "./types.js";

/** Reconstruct local wall presentation from the original anchor and measured
 * monotonic offset. Never subtract different wall clocks or invent boundaries. */
function anchored(original: ClockSnapshot, observed: ClockSnapshot, monotonicNs: bigint): ClockSnapshot {
  if (typeof monotonicNs !== "bigint" || monotonicNs < original.monotonicNs || monotonicNs > observed.monotonicNs) throw refused();
  const before = monotonicNs - original.monotonicNs, after = observed.monotonicNs - monotonicNs;
  // Original integer micros do not reveal the anchor's submicrosecond phase.
  // Intersect the two quantization intervals instead of resetting that phase.
  const left = original.unixUs + before / 1000n, right = observed.unixUs - (after + 999n) / 1000n;
  const unixUs = left > right ? left : right;
  if (unixUs > original.unixUs + (before + 999n) / 1000n || unixUs > observed.unixUs - after / 1000n) throw refused();
  return snapshot({ ...original, monotonicNs, unixUs });
}
export function measuredStages(original: ClockSnapshot, observed: ClockSnapshot, rootSpan: string,
  raw: CallObservation | undefined, local: readonly StageInterval[]): readonly MeasuredStage[] {
  const stages: MeasuredStage[] = [], ids = new Set([rootSpan]);
  const add = (name: string, start: ClockSnapshot, durationNs: bigint | undefined, status: "ok" | "error" | "missing") => {
    consistent(original, start); consistent(start, observed);
    if (durationNs !== undefined && (durationNs < 0n || start.monotonicNs + durationNs > observed.monotonicNs)) throw refused();
    const id = randomBytes(8).toString("hex"); if (/^0+$/.test(id) || ids.has(id)) throw refused(); ids.add(id);
    stages.push(Object.freeze({ name, spanId: id, parentSpanId: rootSpan, started: start, status,
      ...(durationNs === undefined ? {} : { durationNs }) }));
  };
  for (const name of ["authorization", "upstream"] as const) {
    const stage = raw?.[name]; if (stage?.startedAtMonotonicNs === undefined) continue;
    const start = anchored(original, observed, stage.startedAtMonotonicNs), end = stage.resultAtMonotonicNs;
    add(name, start, end === undefined ? undefined : end - start.monotonicNs,
      end === undefined ? "missing" : stage.state === "ok" ? "ok" : "error");
  }
  for (const stage of local) add(stage.name, stage.started, stage.ended.monotonicNs - stage.started.monotonicNs, stage.status);
  return Object.freeze(stages);
}
