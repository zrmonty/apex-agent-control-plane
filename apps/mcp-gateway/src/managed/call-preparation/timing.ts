import type { ClockSnapshot } from "../../telemetry/clock.js";
import { assertDataTree } from "../runtime-config/boundary.js";
import { record, refused } from "./boundary.js";

const MAX = (1n << 64n) - 1n;
export function snapshot(value: ClockSnapshot): Readonly<ClockSnapshot> {
  record(value, ["monotonicNs", "unixUs", "resolutionNs", "uncertaintyUs", "source"]);
  assertDataTree(value, true);
  for (const field of [value.monotonicNs, value.unixUs, value.resolutionNs]) {
    if (typeof field !== "bigint" || field < 0n || field > MAX) throw refused();
  }
  if (value.resolutionNs === 0n || value.uncertaintyUs !== undefined &&
    (typeof value.uncertaintyUs !== "bigint" || value.uncertaintyUs < 0n || value.uncertaintyUs > MAX) ||
    typeof value.source !== "string" || value.source.length === 0 || value.source.length > 128 ||
    /[^\x20-\x7e]/.test(value.source) || value.source.trim() !== value.source) throw refused();
  return Object.freeze({ ...value });
}
export function consistent(start: Readonly<ClockSnapshot>, end: Readonly<ClockSnapshot>): void {
  const elapsed = end.monotonicNs - start.monotonicNs;
  if (elapsed < 0n || start.source !== end.source || start.resolutionNs !== end.resolutionNs ||
    start.uncertaintyUs !== end.uncertaintyUs) throw refused();
  // Two integer-microsecond samples of one stable anchor may straddle a quantum.
  // Wall deltas only validate clock consistency; NEVER derive a budget from them.
  const wall = end.unixUs - start.unixUs;
  if (wall < elapsed / 1000n || wall > (elapsed + 999n) / 1000n) throw refused();
}
export function deadline(original: Readonly<ClockSnapshot>, value: bigint): void {
  if (typeof value !== "bigint" || value > MAX || value <= original.monotonicNs ||
    value - original.monotonicNs > 120000000000n) throw refused();
}
