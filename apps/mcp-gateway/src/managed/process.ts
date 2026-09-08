import { startManagedApplication } from "./application.js";
import { runApplicationProcess } from "./application/process-owner.js";

/** Actual executable ownership. No test factories, alternate listeners or
 * environment-selected termination behavior cross this public boundary. */
export function runManagedProcess(env: NodeJS.ProcessEnv = process.env): Promise<0 | 1> {
  return runApplicationProcess(env, startManagedApplication, {
    on: process.on.bind(process), removeListener: process.removeListener.bind(process),
    report(message) { process.stderr.write(`${message}\n`); },
    terminate() {
      try { process.stderr.write("GOVERNANCE_UNAVAILABLE: managed application cleanup failed safely\n"); }
      finally { process.exit(1); }
    },
  });
}
