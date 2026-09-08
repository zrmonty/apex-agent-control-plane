import type { Clock } from "../../telemetry/clock.js";
import type { observeFreshHealth, FreshHealthObservation } from "../../health-probe.js";
import { copyStageRole, disposeStageOwner, type StageOwner, type StageBootstrap, type startSealedStageBootstrap } from "../bootstrap/stage-owner.js";
import type { Timers } from "../stage-reader/types.js";
import { parseSealedStageEnvironment } from "../bootstrap/environment.js";
import { decodeToken } from "../health-material/binding.js";
import { ReadinessReportCodec } from "../readiness/report-codec.js";
import { clockSample } from "../readiness/timing.js";
export type ObservationOptions = Readonly<{ env: NodeJS.ProcessEnv; signal: AbortSignal; onFatal(): void }>;
export type PreparedHealthObservation = Readonly<{ text: string; validUntilMonotonicNs: bigint }>;
type Dependencies = Readonly<{ clock: Clock; timers: Timers; bootstrap: typeof startSealedStageBootstrap; observe: typeof observeFreshHealth }>;
/** Private composition seam; public entry fixes OS bootstrap and HTTP transport. */
export async function observeStageHealth(options: ObservationOptions, deps: Dependencies): Promise<string | undefined> {
  return (await observeStageHealthSample(options, deps))?.text;
}

/** Retains the original local expiry through the process-output boundary. */
export async function observeStageHealthSample(options: ObservationOptions, deps: Dependencies): Promise<PreparedHealthObservation | undefined> {
  let bootstrap: StageBootstrap | undefined, stage: StageOwner | undefined;
  let encoded: Buffer | undefined, token: Buffer | undefined, codec: ReadinessReportCodec | undefined;
  let observation: FreshHealthObservation | undefined, failed = false, fatal = false, last: bigint | undefined;
  let deadline = 0n, stopTimer: (() => void) | undefined;
  const controller = new AbortController();
  const cancel = () => {
    failed = true; controller.abort();
    if (!stage) { try { bootstrap?.cancel(); } catch { fail(); } }
  };
  const fail = () => {
    if (fatal) return; fatal = true; cancel();
    try { options.onFatal(); } catch { /* Actual executable must terminate. */ }
  };
  function check() {
    const at = clockSample(deps.clock, last).monotonicNs; last = at;
    if (failed || options.signal.aborted || at >= deadline ||
      observation && at >= observation.validUntilMonotonicNs) throw Error("observation refused");
  }
  try {
    last = clockSample(deps.clock).monotonicNs; deadline = last + 7_000_000_000n;
    stopTimer = deps.timers.after(7000, fail); // Fatal watchdog is never closure proof.
    options.signal.addEventListener("abort", cancel, { once: true });
    check();
    const selection = parseSealedStageEnvironment(options.env);
    if (!selection.network) throw Error("sealed v2 required");
    bootstrap = deps.bootstrap({ env: options.env, onFatal: fail });
    if (failed || options.signal.aborted) cancel(); // Adopt factory reentry.
    stage = await bootstrap.result; check();
    // Brand/currentness checked BEFORE inspecting properties of the returned owner.
    // This is the ONLY role copied; no runtime credential/enrollment factory runs.
    encoded = copyStageRole(stage, "health-token");
    if (stage.documents.binding.installationId !== selection.installationId ||
      JSON.stringify(stage.network) !== JSON.stringify(selection.network)) throw Error("stage selection mismatch");
    token = decodeToken(encoded); encoded.fill(0); encoded = undefined;
    codec = new ReadinessReportCodec({ config: stage.documents.config, launch: stage.documents.launch });
    check();
    observation = await deps.observe({ codec, tokenBytes: token, clock: deps.clock,
      deadlineMonotonicNs: deadline, signal: controller.signal, onFatal: fail });
    check();
  } catch { failed = true; }
  finally {
    encoded?.fill(0); token?.fill(0);
    try { if (stage) disposeStageOwner(stage); } catch { fail(); }
    try { bootstrap?.cancel(); await bootstrap?.closed; } catch { fail(); }
  }
  // Unknown physical teardown deliberately retains this pending operation even
  // if a test fatal callback returns. The real process host exits nonzero.
  if (fatal) return await new Promise<never>(() => {});
  try {
    check();
    if (!observation?.report.live || !observation.report.ready || !codec) return undefined;
    const text = codec.encode(observation.report); check();
    return Object.freeze({ text, validUntilMonotonicNs: observation.validUntilMonotonicNs });
  } catch { return undefined; }
  finally { stopTimer?.(); options.signal.removeEventListener("abort", cancel); }
}
