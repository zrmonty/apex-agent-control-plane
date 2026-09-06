import type { ManagedCallAuthorizationRequest } from "@apex/contracts";
import type { Clock, ClockSnapshot } from "../telemetry/clock.js";
import type { ReadonlyRuntimeConfiguration } from "./runtime-config.js";
import type { DeploymentBinding } from "./authority/types.js";

export type CallPreparationOptions = Readonly<{
  config: ReadonlyRuntimeConfiguration;
  binding: DeploymentBinding;
  evidenceAgentId: string;
  dataClassification: string;
  clock: Clock;
}>;
export type PreparedCallTrace = Readonly<{
  callId: string; traceId: string; spanId: string;
  startedAtUnixUs: bigint; clockSource: string; clockResolutionNs: bigint; clockUncertaintyUs?: bigint;
}>;
export type PreparedManagedCall = Readonly<{
  /** Generated message, recursively frozen by the authorization codec. */
  request: ManagedCallAuthorizationRequest;
  input: Readonly<Record<string, string>>;
  startedAtMonotonicNs: bigint;
  deadlineMonotonicNs: bigint;
  originalSnapshot: Readonly<ClockSnapshot>;
  trace: PreparedCallTrace;
}>;
