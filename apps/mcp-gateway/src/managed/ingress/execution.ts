import type { CompiledExecution } from "../compiled-executor.js";

/** Never release on result failure, cancellation, or a cleanup watchdog. */
export function ownExecution(job: CompiledExecution, cleanupMs: number, onClosed: (owner: CompiledExecution) => void,
  onFatal: () => void): CompiledExecution {
  let cancelled = false, physical = false;
  let watchdog: ReturnType<typeof setTimeout> | undefined;
  const owner = Object.freeze({ ...job, cancel() {
    if (cancelled || physical) return; cancelled = true;
    watchdog = setTimeout(onFatal, cleanupMs);
    try { job.cancel(); } catch { onFatal(); }
  } });
  void job.closed.then(() => {
    physical = true; clearTimeout(watchdog); onClosed(owner);
  }, onFatal);
  return owner;
}
