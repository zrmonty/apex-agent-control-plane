import type { CompiledManagedExecutor } from "../compiled-executor.js";
import type { ManagedInboundVerifier } from "../bootstrap/inbound-verifier.js";
import type { DeploymentGrantOwner } from "../authority/grant-owner.js";
import type { AuthenticatedBusinessTransport } from "../authority/business-transport.js";
import type { ManagedControlTransportOptions, ManagedControlTransports } from "../control-transports.js";
import type { Timers } from "../stage-reader/types.js";
import type { WireContext } from "../upstream-wire/client.js";
import type { OwnedAuthorityChannel } from "../authority/unary.js";
import type { OwnedEvidenceChannel } from "../evidence-channel.js";
import type { PendingCompletion } from "../call-owner.js";
import type { BusinessExchange } from "../authority/business-types.js";
import type { AdmissionObservation } from "../evidence/readiness-client.js";
import type { NetworkObservation } from "../authority/network-readiness.js";
import type { ReadinessMonitor } from "../readiness.js";

export type RuntimeCore = Readonly<{
  executor: CompiledManagedExecutor;
  verifier: ManagedInboundVerifier;
  grants: DeploymentGrantOwner;
  business: AuthenticatedBusinessTransport;
  /** Nine concrete owners. Passive until checkStartup; cached snapshot does no I/O. */
  readiness: ReadinessMonitor;
  /** Non-admitting initialize/catalog validation; never a tools/call or event. */
  prepareUpstream(context: Omit<WireContext, "beforeWrite">): Promise<void>;
  /** Same enrolled evidence channel/identity; no event or call reservation. */
  startEvidenceReadiness(started: bigint, deadline: bigint): BusinessExchange<AdmissionObservation>;
  /** Authenticated CP relay, exact original stage binding and network hash. */
  startNetworkReadiness(started: bigint, deadline: bigint): BusinessExchange<NetworkObservation>;
  isAdmitting(): boolean;
  /** Exact unresolved reservations; active calls may still be physically owned. */
  pendingCompletions(): readonly PendingCompletion[];
  /** Explicit retry while this core is live; never reacquires business authority. */
  retryCompletion(callId: string): BusinessExchange<boolean>;
}>;
export type RuntimeCoreHandle = Readonly<{
  result: Promise<RuntimeCore>; revoked: Promise<void>; closed: Promise<void>;
  /** Settles with physical root closure. Nonempty requires external reconciliation
   * or verified termination, not a timeout-based reservation release. */
  completionHandoff: Promise<readonly PendingCompletion[]>;
  cancel(): void;
}>;
type Control = Omit<ManagedControlTransports, "result"> & { result: Promise<Readonly<{
  authority: Pick<OwnedAuthorityChannel, "start">; evidence: Pick<OwnedEvidenceChannel, "start" | "startReadiness"> }>> };
export type Dependencies = Readonly<{ timers: Timers; unixMs(): number;
  control(options: ManagedControlTransportOptions): Control }>;
export const refused = () => new Error("managed runtime core refused safely");
