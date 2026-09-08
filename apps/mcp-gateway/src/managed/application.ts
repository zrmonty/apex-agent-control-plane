import { createClock } from "../telemetry/clock.js";
import { startSealedStageBootstrap } from "./bootstrap/stage-owner.js";
import { startManagedRuntimeCore } from "./runtime-core.js";
import { startHealthServer } from "./health-server.js";
import { startManagedIngress } from "./ingress.js";
import { localTimers } from "./stage-reader/fs.js";
import { startApplication, type ApplicationOptions } from "./application/owner.js";
export type { ApplicationOptions, ManagedApplication } from "./application/owner.js";

/** Owns the complete protected runtime and both fixed listeners. The executable
 * must retain this handle and provide actual process termination on fatal loss.
 * No legacy configuration, arbitrary bind address or permissive fallback. */
export function startManagedApplication(options: ApplicationOptions) {
  return startApplication(options, { clock: createClock(), timers: localTimers,
    bootstrap: startSealedStageBootstrap, core: startManagedRuntimeCore,
    health: startHealthServer, ingress: startManagedIngress });
}
