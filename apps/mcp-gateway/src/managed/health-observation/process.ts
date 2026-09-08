import { create } from "@bufbuild/protobuf";
import { decodeStrict, encodeJson, ReadinessReportSchema, RuntimeHealthSampleSchema } from "@apex/contracts";
import type { ObservationOptions, PreparedHealthObservation } from "./owner.js";
import type { Timers } from "../stage-reader/types.js";
export const diagnostic = "GOVERNANCE_UNAVAILABLE: managed health observation refused safely\n";
type Host = { on(signal: "SIGTERM" | "SIGINT", listener: () => void): unknown;
  removeListener(signal: "SIGTERM" | "SIGINT", listener: () => void): unknown;
  write(line: string): Promise<void>; error(line: string): Promise<void> | void;
  onError?(listener: (channel: "stdout" | "stderr") => void): void; terminate(): void; timers: Timers };
/** Private process seam. A watchdog requests real process death, never closure. */
export async function runHealthObservationProcess(argv: readonly string[], env: NodeJS.ProcessEnv,
  start: (options: ObservationOptions) => Promise<PreparedHealthObservation | undefined>, host: Host): Promise<0 | 1> {
  const controller = new AbortController(); let fatal = false, reported = false, finished = false;
  let stopTimer: (() => void) | undefined, last = 0n, deadline = 0n;
  let validity: bigint | undefined;
  let diagnosticWrite: Promise<void> = Promise.resolve();
  const cancel = () => controller.abort();
  const forceExit = () => { if (!fatal) { fatal = true; cancel(); host.terminate(); } };
  const report = () => {
    if (!reported) {
      reported = true;
      try { diagnosticWrite = Promise.resolve(host.error(diagnostic)).catch(forceExit); }
      catch { forceExit(); }
    }
    return diagnosticWrite;
  };
  const terminate = () => { if (!fatal) { cancel(); void report(); forceExit(); } };
  function check() {
    const now = host.timers.now();
    if (typeof now !== "bigint" || now < last || now >= deadline || validity !== undefined && now >= validity ||
      fatal || controller.signal.aborted) throw Error();
    last = now;
  }
  try {
    last = host.timers.now(); if (typeof last !== "bigint" || last < 0n) throw Error();
    deadline = last + 7_000_000_000n; stopTimer = host.timers.after(7000, terminate);
    host.on("SIGTERM", cancel); host.on("SIGINT", cancel);
    host.onError?.(channel => { cancel(); if (channel === "stderr" || finished) terminate(); });
    if (argv.length !== 0) throw Error();
    const observation = await start({ env, signal: controller.signal, onFatal: terminate });
    check();
    if (!observation || typeof observation.validUntilMonotonicNs !== "bigint") throw Error();
    validity = observation.validUntilMonotonicNs;
    check();
    const text = observation.text;
    if (typeof text !== "string" || text.length === 0 || Buffer.byteLength(text) > 8192 || /[\r\n]/.test(text)) throw Error();
    const report = decodeStrict(ReadinessReportSchema, text); check();
    const remaining = validity - last;
    if (remaining <= 0n || remaining > 10_000_000_000n) throw Error();
    const sample = create(RuntimeHealthSampleSchema, { schemaVersion: 1, report, validForNs: remaining });
    const line = JSON.stringify(encodeJson(RuntimeHealthSampleSchema, sample)); check();
    if (Buffer.byteLength(line) > 16384) throw Error();
    await host.write(`${line}\n`); check();
    return 0;
  } catch { await report(); return 1; }
  finally { finished = true; stopTimer?.(); host.removeListener("SIGTERM", cancel); host.removeListener("SIGINT", cancel); }
}
