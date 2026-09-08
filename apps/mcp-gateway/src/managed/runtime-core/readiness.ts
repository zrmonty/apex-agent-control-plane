import type { createUpstream } from "./upstream.js";
import type { RuntimeCore } from "./types.js";
import { refused } from "./types.js";
import type { Timers } from "../stage-reader/types.js";

type Upstream = ReturnType<typeof createUpstream>;

/** One serving session plus at most one separately owned, non-business probe.
 * A successful recurring sweep preserves the current admission/catalog state. */
export class UpstreamReadiness {
  ready = false;
  private stopped = false;
  private preparing?: Promise<void>;
  private probe?: Upstream;
  private closing?: Promise<void>;
  constructor(private readonly serving: Upstream, private readonly createProbe: () => Upstream,
    private readonly gate: () => void, private readonly stop: () => void,
    private readonly fatal: () => void, private readonly timers: Timers) {}

  prepare: RuntimeCore["prepareUpstream"] = context => {
    if (this.stopped) return Promise.reject(refused());
    if (this.preparing) return this.preparing;
    // Reserve before any callback can reenter. Keep the slot through cleanup.
    this.preparing = Promise.resolve().then(async () => {
      let probe: Upstream | undefined, stopCleanup: (() => void) | undefined;
      const timing = { ...context, beforeWrite: () => { this.check(); } };
      try {
        this.check();
        if (this.ready) this.probe = probe = this.createProbe();
        const upstream = probe ?? this.serving;
        await upstream.session.initialize(timing); await upstream.session.discover(timing);
        this.check();
        if (probe) {
          // Retire the remote probe session too; retain physical ownership if
          // DELETE, native cancellation or closure hangs beyond cleanup grace.
          stopCleanup = this.timers.after(5000, () => { this.stop(); this.fatal(); });
          await probe.session.terminate(timing);
        }
        this.check(); this.ready = true;
      } catch { this.stop(); throw refused(); }
      finally {
        try { if (probe) await probe.close(); }
        finally { stopCleanup?.(); }
        this.probe = undefined;
      }
    }).finally(() => { this.preparing = undefined; });
    return this.preparing;
  };
  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.stopped = true; this.ready = false;
    this.closing = Promise.all([this.probe?.close(), this.preparing?.catch(() => {})]).then(() => undefined);
    return this.closing;
  }
  private check() { if (this.stopped) throw refused(); this.gate(); }
}
