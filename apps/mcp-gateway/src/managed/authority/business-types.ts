import type { ManagedCallAuthorizationRequest } from "@apex/contracts";
import type { DeploymentBinding } from "./types.js";
import type { OwnedAuthorityChannel } from "./unary.js";

/** Local RPC stream cleanup, never evidence of upstream cleanup or remote release. */
export type BusinessExchange<T> = Readonly<{ result: Promise<T>; closed: Promise<void>; cancel(): void }>;
export type AuthorizationContext = Readonly<{ startedAtMonotonicNs: bigint; expectedEpoch: bigint }>;
export type FrozenRequest<T> = T extends object ? { readonly [K in keyof T]: FrozenRequest<T[K]> } : T;
type DecisionMetadata = Readonly<{
  policyId: string; policyRevision: bigint; reasonCode: string; fieldRestrictions: readonly string[];
}>;
/** Metadata only: the physical call owner must recheck SERVE and this deadline. */
export type BusinessDecision =
  | (DecisionMetadata & Readonly<{ outcome: "denied" | "requires_approval" }>)
  | (DecisionMetadata & Readonly<{
    outcome: "allowed"; admissionId: string; epoch: bigint; expiresAtUnixUs: bigint;
    validForUs: bigint; startDeadlineMonotonicNs: bigint;
    submittedRequest: FrozenRequest<ManagedCallAuthorizationRequest>;
  }>);
export type BusinessTransportOptions = Readonly<{
  channel: Pick<OwnedAuthorityChannel, "start">; binding: DeploymentBinding;
  policyId: string; evidenceAgentId: string; dataClassification: string; monotonicNowNs(): bigint;
}>;
