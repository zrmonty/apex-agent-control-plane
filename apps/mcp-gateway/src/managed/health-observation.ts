import { createClock } from "../telemetry/clock.js";
import { observeFreshHealth } from "../health-probe.js";
import { startSealedStageBootstrap } from "./bootstrap/stage-owner.js";
import { localTimers } from "./stage-reader/fs.js";
import { observeStageHealthSample, type ObservationOptions, type PreparedHealthObservation } from "./health-observation/owner.js";

/** Fixed protected /apex/runtime + fixed loopback health only. Returned metadata
 * is NOT admission/selection authority or proof of agent-installed/current identity. */
export async function observeManagedHealth(options: ObservationOptions): Promise<string | undefined> {
  return (await observeManagedHealthSample(options))?.text;
}
export function observeManagedHealthSample(options: ObservationOptions): Promise<PreparedHealthObservation | undefined> {
  return observeStageHealthSample(options, { clock: createClock(), timers: localTimers,
    bootstrap: startSealedStageBootstrap, observe: observeFreshHealth });
}
