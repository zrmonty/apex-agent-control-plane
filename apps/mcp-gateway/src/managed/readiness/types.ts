import { ReadinessCheckId, type ReadinessCheck, type ReadinessReport } from "@apex/contracts";
import type { Clock } from "../../telemetry/clock.js";
import type { ReadonlyRuntimeLaunchContext } from "../launch-context.js";
import type { DeepReadonly, ReadonlyRuntimeConfiguration } from "../runtime-config.js";

export const CHECK_IDS = Object.freeze([ReadinessCheckId.CONFIG, ReadinessCheckId.LAUNCH,
  ReadinessCheckId.MATERIAL, ReadinessCheckId.INBOUND_AUTH, ReadinessCheckId.UPSTREAM_CATALOG,
  ReadinessCheckId.GOVERNANCE, ReadinessCheckId.EVIDENCE_ADMISSION, ReadinessCheckId.NETWORK,
  ReadinessCheckId.ADMISSION] as const);
export type CheckId = typeof CHECK_IDS[number];
export type ReadinessBinding = Readonly<{ config: ReadonlyRuntimeConfiguration; launch: ReadonlyRuntimeLaunchContext }>;
export type ReadonlyReadinessReport = DeepReadonly<ReadinessReport>;

/** Local evidence lifetime, not a second wire report. Owners must not emit events,
 * reserve admission or execute business calls. PASS is actual owner evidence. */
export type ProbeResult = Readonly<{ check: DeepReadonly<ReadinessCheck>; validUntilMonotonicNs: bigint }>;
export type ProbeHandle = Readonly<{
  /** Settles ONLY when underlying I/O has terminated, including cancellation.
   * A Promise.race timeout is not termination and must not release this permit. */
  completion: Promise<ProbeResult>;
  /** Request cancellation AND close exact owned resources; must not block. */
  cancel(): void;
}>;
export type ProbeOwner = Readonly<{
  id: CheckId;
  /** Synchronous nonblocking start; throw only before acquiring any I/O. */
  start(binding: ReadinessBinding): ProbeHandle;
}>;
/** System-boundary scheduler: asynchronous callbacks, real cancellation, no
 * synchronous blocking. Defaults to Node timers; injectable for exact-edge tests. */
export type ReadinessScheduler = Readonly<{ after(delayMs: number, callback: () => void): () => void }>;
export type ReadinessOptions = Readonly<{
  configuration: ReadonlyRuntimeConfiguration;
  launchContext: unknown;
  owners: readonly ProbeOwner[];
  clock: Clock;
  /** Trusted live owner must compare the COMPLETE exact binding, not only hashes.
   * Shape/integrity parsing is not authentication, provenance or launch authority. */
  isCurrent(binding: ReadinessBinding): boolean;
  /** Requests bounded process failure; required, nonblocking, and called once. */
  onFatal(): void;
  scheduler?: ReadinessScheduler;
  /** Explicitly shorter component bounds for tests; never above 2s / 5s.
   * No environment/profile override and no production composition in this slice. */
  limits?: Readonly<{ deadlineMs?: number; cleanupMs?: number }>;
}>;
