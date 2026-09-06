import { startGuardStageLoad } from "./stage-reader.js";
import { localTimers } from "../stage-reader/fs.js";
import { GuardEgressRelay, GuardIngressRelay } from "./relay-server.js";
import { startGuard } from "./process/job.js";
import type { Gate, GuardProcessOptions, GuardProcess } from "./process/types.js";
export type { GuardProcessOptions, GuardProcess } from "./process/types.js";
const gate: Gate = {};
/** Real fixed-stage and two-relay composition; agent launch/inspection remains separate. */
export function startGuardProcess(options: GuardProcessOptions): GuardProcess {
  return startGuard(options, { load: startGuardStageLoad, timers: localTimers, unixMs: Date.now,
    ingress: options => new GuardIngressRelay(options), egress: options => new GuardEgressRelay(options) }, gate);
}
