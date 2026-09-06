import { localFiles, localTimers } from "../stage-reader/fs.js";
import { startGuardLoad } from "../stage-reader/job.js";
import type { GuardStageLoadOptions } from "../stage-reader/guard-options.js";
import type { ManagedStageLoad } from "../stage-reader/types.js";
export type { GuardStageLoadOptions } from "../stage-reader/guard-options.js";
export type { LoadedManagedStage, ManagedStageLoad } from "../stage-reader/types.js";

/** Separate guard container mount: opaque bytes, not configuration or provenance approval. */
export function startGuardStageLoad(options: GuardStageLoadOptions): ManagedStageLoad {
  return startGuardLoad(options, localFiles, localTimers);
}
