import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { GovernanceOutcome, ManagedCallAuthorizationDecisionSchema, ManagedCallAuthorizationRequestSchema,
  ManagedCallCompletionSchema, ManagedCallCompletionReceiptSchema, ManagedDeploymentBindingSchema,
  ManagedPolicyRequestSchema, ManagedPolicySnapshotSchema, type ManagedCallAuthorizationRequest,
  type ManagedDeploymentBinding } from "@apex/contracts";
import { immutableBinding, MAX_GRANT_US, nonce, uint64 } from "./binding.js";
import { readBinding, wireBinding } from "./grant-transport.js";
import type { AuthorizationContext, BusinessDecision } from "./business-types.js";
import type { DeploymentBinding } from "./types.js";

export const businessRefused = () => new Error("managed business refused safely");
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const IDENTIFIER = /^[A-Za-z0-9_.:-]{1,256}$/;
const BINDING_KEYS = ["installationId", "workspaceId", "namespaceId", "proxyId", "revisionId",
  "generation", "fencingToken", "processInstanceId", "configHash", "launchContextHash"] as const;
type Profile = Readonly<{ binding: DeploymentBinding; policyId: string; evidenceAgentId: string; dataClassification: string }>;

/** Fixed-field reads never invoke accessors, spread caller objects, or walk unknown arrays. */
function field(value: unknown, name: string): unknown {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw businessRefused();
  const descriptor = Object.getOwnPropertyDescriptor(value, name);
  if (descriptor && !("value" in descriptor)) throw businessRefused();
  return descriptor?.value;
}
function message(value: unknown): void {
  const unknown = field(value, "$unknown");
  // Unknown wire fields cannot silently disappear from a same-call semantic retry.
  if (unknown !== undefined && (!Array.isArray(unknown) || unknown.length !== 0)) throw businessRefused();
}
function string(value: unknown, max: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max ||
    Buffer.byteLength(value, "utf8") > max) throw businessRefused();
  return value;
}
export function businessIdentifier(value: unknown): string {
  const text = string(value, 256);
  if (!IDENTIFIER.test(text) || text.includes("..")) throw businessRefused();
  return text;
}
function uuid(value: unknown): string {
  const text = string(value, 36); if (!UUID.test(text)) throw businessRefused(); return text;
}
function digest(value: unknown): string {
  const text = string(value, 64); if (!nonce(text)) throw businessRefused(); return text;
}
function positive(value: unknown): bigint {
  if (!uint64(value)) throw businessRefused(); return value;
}
function principal(value: unknown): string {
  const text = string(value, 256);
  if (IDENTIFIER.test(text) && !text.includes("..")) return text;
  if (!text.startsWith("spiffe://")) throw businessRefused();
  // The whole ASCII subject was bounded before splitting/traversing its segments.
  for (const segment of text.slice(9).split("/")) businessIdentifier(segment);
  return text;
}
export function businessClassification(value: unknown): string {
  const text = string(value, 16);
  if (!["public", "internal", "confidential", "restricted"].includes(text)) throw businessRefused();
  return text;
}
export function businessBinding(value: unknown): DeploymentBinding {
  return immutableBinding({
    installationId: uuid(field(value, "installationId")), workspaceId: businessIdentifier(field(value, "workspaceId")),
    namespaceId: businessIdentifier(field(value, "namespaceId")), proxyId: uuid(field(value, "proxyId")),
    revisionId: uuid(field(value, "revisionId")), generation: positive(field(value, "generation")),
    fencingToken: positive(field(value, "fencingToken")), processInstanceId: uuid(field(value, "processInstanceId")),
    configHash: digest(field(value, "configHash")), launchContextHash: digest(field(value, "launchContextHash")),
  });
}
function boundWire(value: unknown, expected: DeploymentBinding): ManagedDeploymentBinding {
  message(value); const target = field(value, "target"); message(target);
  const copy = create(ManagedDeploymentBindingSchema, {
    installationId: uuid(field(value, "installationId")), processInstanceId: uuid(field(value, "processInstanceId")),
    configHash: digest(field(value, "configHash")), launchContextHash: digest(field(value, "launchContextHash")),
    target: {
      workspaceId: businessIdentifier(field(target, "workspaceId")), namespaceId: businessIdentifier(field(target, "namespaceId")),
      proxyId: uuid(field(target, "proxyId")), revisionId: uuid(field(target, "revisionId")),
      generation: positive(field(target, "generation")), fencingToken: positive(field(target, "fencingToken")),
    },
  });
  if (toBinary(ManagedDeploymentBindingSchema, copy).length > 4096) throw businessRefused();
  const actual = readBinding(copy);
  if (BINDING_KEYS.some(key => actual[key] !== expected[key])) throw businessRefused();
  return copy;
}
function bounded(bytes: Uint8Array, max: number): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.length > max) throw businessRefused(); return bytes;
}
function restrictions(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > 128) throw businessRefused();
  let bytes = 0;
  const copy: string[] = [];
  for (let i = 0; i < value.length; i++) {
    const item = businessIdentifier(Object.getOwnPropertyDescriptor(value, String(i))?.value);
    bytes += Buffer.byteLength(item, "utf8"); if (bytes > 8192) throw businessRefused();
    copy.push(item);
  }
  return copy;
}
/** Only called on newly constructed, bounded generated messages, never caller objects. */
function freeze<T extends object>(value: T): T {
  for (const child of Object.values(value)) if (child && typeof child === "object") freeze(child);
  return Object.freeze(value);
}

export function authorizationContext(value: AuthorizationContext): AuthorizationContext {
  const startedAtMonotonicNs = field(value, "startedAtMonotonicNs");
  if (typeof startedAtMonotonicNs !== "bigint" || startedAtMonotonicNs < 0n) throw businessRefused();
  return Object.freeze({ startedAtMonotonicNs, expectedEpoch: positive(field(value, "expectedEpoch")) });
}
export function authorizationRequest(value: ManagedCallAuthorizationRequest, profile: Profile) {
  message(value);
  const caller = field(value, "caller"), scope = field(value, "scope"), trace = field(value, "trace");
  message(caller); message(scope); message(trace);
  const binding = boundWire(field(value, "binding"), profile.binding);
  const submittedRequest = create(ManagedCallAuthorizationRequestSchema, {
    binding, caller: { principal: principal(field(caller, "principal")), agentId: businessIdentifier(field(caller, "agentId")) },
    scope: { workspaceId: businessIdentifier(field(scope, "workspaceId")), namespaceId: businessIdentifier(field(scope, "namespaceId")) },
    proxyId: uuid(field(value, "proxyId")), revisionId: uuid(field(value, "revisionId")),
    generation: positive(field(value, "generation")), callId: uuid(field(value, "callId")),
    toolAlias: businessIdentifier(field(value, "toolAlias")), action: businessIdentifier(field(value, "action")),
    resource: businessIdentifier(field(value, "resource")), classification: businessClassification(field(value, "classification")),
    argumentsHash: digest(field(value, "argumentsHash")),
    trace: { traceId: businessIdentifier(field(trace, "traceId")), spanId: businessIdentifier(field(trace, "spanId")) },
    approvalId: "",
  });
  if (field(value, "approvalId") !== "" || submittedRequest.caller!.agentId !== profile.evidenceAgentId ||
    submittedRequest.classification !== profile.dataClassification || submittedRequest.toolAlias !== "portfolio.read" ||
    submittedRequest.action !== "read" || submittedRequest.scope!.workspaceId !== profile.binding.workspaceId ||
    submittedRequest.scope!.namespaceId !== profile.binding.namespaceId || submittedRequest.proxyId !== profile.binding.proxyId ||
    submittedRequest.revisionId !== profile.binding.revisionId || submittedRequest.generation !== profile.binding.generation) throw businessRefused();
  const payload = bounded(toBinary(ManagedCallAuthorizationRequestSchema, submittedRequest), 16_384);
  return { payload, submittedRequest: freeze(submittedRequest) };
}
export function policyRequest(value: string, binding: DeploymentBinding) {
  const expectedNonce = digest(value);
  const payload = bounded(toBinary(ManagedPolicyRequestSchema, create(ManagedPolicyRequestSchema, {
    binding: boundWire(create(ManagedDeploymentBindingSchema, wireBinding(binding)), binding),
    nonce: Buffer.from(expectedNonce, "hex"),
  })), 8192);
  return { payload, expectedNonce };
}
export function completionRequest(admission: string, call: string, binding: DeploymentBinding) {
  const admissionId = uuid(admission), callId = uuid(call);
  const payload = bounded(toBinary(ManagedCallCompletionSchema, create(ManagedCallCompletionSchema, {
    binding: boundWire(create(ManagedDeploymentBindingSchema, wireBinding(binding)), binding), admissionId, callId,
  })), 8192);
  return { payload, admissionId, callId };
}
export function decodePolicy(bytes: Uint8Array, profile: Profile, expectedNonce: string) {
  const value = fromBinary(ManagedPolicySnapshotSchema, bounded(bytes, 16_384));
  message(value);
  const binding = boundWire(value.binding, profile.binding);
  if (value.nonce.length !== 32 || Buffer.from(value.nonce).toString("hex") !== expectedNonce ||
    businessIdentifier(value.policyId) !== profile.policyId || !uint64(value.revision)) throw businessRefused();
  return create(ManagedPolicySnapshotSchema, { binding, nonce: Buffer.from(value.nonce), policyId: value.policyId,
    revision: value.revision, fieldRestrictions: restrictions(value.fieldRestrictions) });
}
export function decodeAuthorization(bytes: Uint8Array, profile: Profile, context: AuthorizationContext,
  submittedRequest: ManagedCallAuthorizationRequest): BusinessDecision {
  const value = fromBinary(ManagedCallAuthorizationDecisionSchema, bounded(bytes, 16_384));
  message(value); const decision = value.decision; message(decision);
  if (!decision || value.approval !== undefined || businessIdentifier(decision.policyId) !== profile.policyId ||
    !uint64(value.policyRevision)) throw businessRefused();
  const common = { policyId: decision.policyId, policyRevision: value.policyRevision,
    reasonCode: businessIdentifier(decision.reasonCode), fieldRestrictions: Object.freeze(restrictions(decision.fieldRestrictions)) };
  if (decision.outcome === GovernanceOutcome.DENIED || decision.outcome === GovernanceOutcome.REQUIRES_APPROVAL) {
    if (value.admissionId !== "" || value.epoch !== 0n || value.expiresAtUnixUs !== 0n || value.validForUs !== 0n) throw businessRefused();
    return Object.freeze({ ...common, outcome: decision.outcome === GovernanceOutcome.DENIED ? "denied" : "requires_approval" });
  }
  if (decision.outcome !== GovernanceOutcome.ALLOWED || !uint64(value.epoch) || value.epoch !== context.expectedEpoch ||
    !uint64(value.expiresAtUnixUs) || !uint64(value.validForUs) || value.validForUs > MAX_GRANT_US) throw businessRefused();
  return Object.freeze({ ...common, outcome: "allowed", admissionId: uuid(value.admissionId), epoch: value.epoch,
    expiresAtUnixUs: value.expiresAtUnixUs, validForUs: value.validForUs,
    startDeadlineMonotonicNs: context.startedAtMonotonicNs + value.validForUs * 1000n, submittedRequest });
}
export function decodeCompletion(bytes: Uint8Array, binding: DeploymentBinding, admissionId: string, callId: string) {
  const value = fromBinary(ManagedCallCompletionReceiptSchema, bounded(bytes, 16_384));
  message(value); const actual = boundWire(value.binding, binding);
  if (value.admissionId !== admissionId || value.callId !== callId || !value.released) throw businessRefused();
  return freeze(create(ManagedCallCompletionReceiptSchema, { binding: actual, admissionId, callId, released: true }));
}
