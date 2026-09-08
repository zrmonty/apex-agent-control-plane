import type { StageOwner } from "./bootstrap/stage-owner.js";
import type { RuntimeMaterials } from "./bootstrap/runtime-materials.js";
import type { Clock } from "../telemetry/clock.js";
import { startManagedControlTransports } from "./control-transports.js";
import { localTimers } from "./stage-reader/fs.js";
import { startCore } from "./runtime-core/job.js";
export type RuntimeCoreOptions = Readonly<{ stage: StageOwner; materials: RuntimeMaterials; clock: Clock; onFatal(): void }>;
export type { RuntimeCore, RuntimeCoreHandle } from "./runtime-core/types.js";

/** Actual stage-bound dependency root. Owns live transports and renewal, not the
 * caller's stage/materials. HTTPS/readiness must gate this root before serving. */
export function startManagedRuntimeCore(options: RuntimeCoreOptions) {
  return startCore(options, { timers: localTimers, unixMs: Date.now, control: startManagedControlTransports });
}
