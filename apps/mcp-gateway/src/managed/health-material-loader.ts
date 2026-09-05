import { startLoad } from "./health-material/job.js";
import { localFiles, timers } from "./health-material/fs.js";
import type { HealthMaterialLoad, HealthMaterialLoadOptions } from "./health-material/types.js";
export type { HealthMaterialLoad, HealthMaterialLoadOptions, HealthMaterialOwner,
  LoadedHealthMaterial } from "./health-material/types.js";

/** Uncomposed Linux fixed-mount loader, not staging authority or readiness.
 * No caller path, environment selection, timeout knob or weaker OS switch.
 * One underlying fixed-mount job is retained through actual I/O/close cleanup;
 * concurrent/retry starts refuse before I/O. Returned token lifetime is separate.
 * Completion requires actual I/O termination; fatal supervision remains a
 * trusted owner obligation, not a hard-real-time kernel/event-loop guarantee. */
export function startHealthMaterialLoad(options: HealthMaterialLoadOptions): HealthMaterialLoad {
  return startLoad(options, localFiles, timers);
}
