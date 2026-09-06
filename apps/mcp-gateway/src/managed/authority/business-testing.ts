// Test support only: deterministic peer using the actual generated wire codecs.
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { GovernanceOutcome, ManagedCallAuthorizationDecisionSchema, ManagedCallAuthorizationRequestSchema,
  ManagedCallCompletionSchema, ManagedCallCompletionReceiptSchema, ManagedPolicyRequestSchema,
  ManagedPolicySnapshotSchema } from "@apex/contracts";
import { wireBinding } from "./grant-transport.js";

export const binding = Object.freeze({
  installationId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01", workspaceId: "work", namespaceId: "ns",
  proxyId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e02", revisionId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e03",
  processInstanceId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e04", generation: 9007199254740993n,
  fencingToken: 9007199254740995n, configHash: "a".repeat(64), launchContextHash: "b".repeat(64),
});
export const callId = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e05";
export const admissionId = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e06";
export const policyId = "portfolio-policy";
export const evidenceAgentId = "managed-evidence";
export const dataClassification = "confidential";
export const nonce = "c".repeat(64);
export const context = Object.freeze({ startedAtMonotonicNs: 1000n, expectedEpoch: 23n });
export const paths = {
  policy: "/apex.v1.ManagedRuntimeAuthority/GetManagedPolicy",
  authorize: "/apex.v1.ManagedProxyGovernance/AuthorizeManagedCall",
  complete: "/apex.v1.ManagedRuntimeAuthority/CompleteManagedCall",
};
export function request() {
  return create(ManagedCallAuthorizationRequestSchema, {
    binding: wireBinding(binding), caller: { principal: "spiffe://apex/agent/research", agentId: evidenceAgentId },
    scope: { workspaceId: "work", namespaceId: "ns" }, proxyId: binding.proxyId, revisionId: binding.revisionId,
    generation: binding.generation, callId, toolAlias: "portfolio.read", action: "read",
    resource: "portfolio:sha256:" + "d".repeat(64), classification: dataClassification,
    argumentsHash: "e".repeat(64), trace: { traceId: "trace-1", spanId: "span-1" }, approvalId: "",
  });
}
export function allowed() {
  return create(ManagedCallAuthorizationDecisionSchema, {
    decision: { outcome: GovernanceOutcome.ALLOWED, policyId, reasonCode: "policy.allowed", fieldRestrictions: ["ssn"] },
    admissionId, expiresAtUnixUs: 1n, policyRevision: 9007199254740993n, validForUs: 7n, epoch: 23n,
  });
}
export function policy() {
  return create(ManagedPolicySnapshotSchema, {
    binding: wireBinding(binding), nonce: Buffer.from(nonce, "hex"), policyId,
    revision: 9007199254740993n, fieldRestrictions: ["ssn"],
  });
}
export function receipt() {
  return create(ManagedCallCompletionReceiptSchema, { binding: wireBinding(binding), admissionId, callId, released: true });
}
export function peerReply(path: string, bytes: Uint8Array): Uint8Array {
  if (path === paths.policy) {
    const input = fromBinary(ManagedPolicyRequestSchema, bytes);
    return toBinary(ManagedPolicySnapshotSchema, create(ManagedPolicySnapshotSchema, {
      ...policy(), binding: input.binding, nonce: input.nonce,
    }));
  }
  if (path === paths.authorize) {
    fromBinary(ManagedCallAuthorizationRequestSchema, bytes);
    return toBinary(ManagedCallAuthorizationDecisionSchema, allowed());
  }
  if (path === paths.complete) {
    const input = fromBinary(ManagedCallCompletionSchema, bytes);
    return toBinary(ManagedCallCompletionReceiptSchema, create(ManagedCallCompletionReceiptSchema, {
      ...receipt(), binding: input.binding, admissionId: input.admissionId, callId: input.callId,
    }));
  }
  throw new Error("unexpected RPC");
}
export function deferred<T>() {
  let resolve!: (value: T) => void, reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
export function harness(reply?: Uint8Array) {
  const result = deferred<Uint8Array>(), closure = deferred<void>();
  const sent: Array<{ path: string; bytes: Uint8Array }> = [];
  let cancellations = 0;
  const channel = { start(path: string, bytes: Uint8Array) {
    sent.push({ path, bytes: Buffer.from(bytes) });
    return { result: reply ? Promise.resolve(reply) : result.promise, closed: closure.promise,
      cancel() { cancellations++; } };
  } };
  return { channel, result, closure, sent, get cancellations() { return cancellations; } };
}
export const metadata = { binding, policyId, evidenceAgentId, dataClassification };
