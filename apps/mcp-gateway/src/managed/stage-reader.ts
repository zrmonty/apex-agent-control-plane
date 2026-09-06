import { localFiles, localTimers } from "./stage-reader/fs.js";
import { startLoad } from "./stage-reader/job.js";
import type { ManagedStageLoad, ManagedStageLoadOptions } from "./stage-reader/types.js";
export type { LoadedManagedStage, ManagedStageLoad, ManagedStageLoadOptions } from "./stage-reader/types.js";
/** Linux fixed-mount bytes only. Expected digest is not provenance authority. */
export function startManagedStageLoad(options: ManagedStageLoadOptions): ManagedStageLoad {
  return startLoad(options, localFiles, localTimers);
}
