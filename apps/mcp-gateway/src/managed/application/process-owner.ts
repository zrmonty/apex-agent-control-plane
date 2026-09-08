import type { ApplicationOptions, ManagedApplication } from "../application.js";

type Signal = "SIGINT" | "SIGTERM";
export type ProcessHost = Readonly<{
  on(signal: Signal, listener: () => void): unknown;
  removeListener(signal: Signal, listener: () => void): unknown;
  report(message: string): void;
  terminate(): void;
}>;

/** Internal process-ownership seam. The public executable fixes every factory. */
export async function runApplicationProcess(env: NodeJS.ProcessEnv,
  start: (options: ApplicationOptions) => ManagedApplication, host: ProcessHost): Promise<0 | 1> {
  let owner: ManagedApplication | undefined, signalled = false, requested = false, failed = false, fatal = false;
  const report = (message: string) => { try { host.report(message); } catch { /* Exit status remains failing. */ } };
  const terminate = () => {
    if (fatal) return; fatal = true;
    try { owner?.cancel(); } finally { host.terminate(); }
  };
  const stop = () => {
    signalled = true;
    try {
      // A later signal cannot relabel an automatic stop already latched by root.
      if (owner?.cancel() === true) requested = true;
    } catch { terminate(); }
  };
  try {
    // Register before factory entry: even synchronous startup reentry is owned.
    host.on("SIGINT", stop); host.on("SIGTERM", stop);
    owner = start({ env, onFatal: terminate });
    if (signalled) stop();
    if (fatal) owner.cancel();
    try { await owner.result; }
    catch { failed = !requested; owner.cancel(); }
    await owner.closed;
    const pending = await owner.completionHandoff;
    if (pending.length) {
      report("GOVERNANCE_UNAVAILABLE: managed completion reconciliation required"); return 1;
    }
    if (failed || fatal || !requested) {
      report("GOVERNANCE_UNAVAILABLE: managed application stopped safely"); return 1;
    }
    return 0;
  } catch {
    if (owner) {
      // An ownership promise rejecting is not termination or a completed handoff.
      // The real host exits immediately; a test host cannot fabricate that proof.
      try { terminate(); } catch { /* Still uncertain, still retained. */ }
      return await new Promise<never>(() => {});
    }
    report("GOVERNANCE_UNAVAILABLE: managed application stopped safely"); return 1;
  } finally {
    host.removeListener("SIGINT", stop); host.removeListener("SIGTERM", stop);
  }
}
