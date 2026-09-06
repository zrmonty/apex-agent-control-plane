import { startManagedStageLoad } from "../stage-reader.js";
import { localTimers } from "../stage-reader/fs.js";
import { startOwnedStage, type BootstrapOptions, type StageBootstrap, type Gate } from "./stage-owner/job.js";

export type { BootstrapOptions, StageBootstrap, StageOwner } from "./stage-owner/job.js";
export { copyStageRole, copyStageTool, disposeStageOwner } from "./stage-owner/material.js";
const processGate: Gate = {};

/** Owns fixed-path, real OS stage loading followed by the actual metadata join.
 * Dormant composition primitive, not activation, provenance or Serving. */
export function startSealedStageBootstrap(options: BootstrapOptions): StageBootstrap {
  return startOwnedStage(options, startManagedStageLoad, localTimers, processGate);
}
