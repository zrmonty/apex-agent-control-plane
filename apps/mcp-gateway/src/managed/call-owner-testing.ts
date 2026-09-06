// Component scheduling fixture. Native HTTP/TLS ownership is tested separately.
import { create, toBinary } from "@bufbuild/protobuf";
import { GovernanceOutcome, ManagedCallAuthorizationDecisionSchema, ManagedCallCompletionReceiptSchema } from "@apex/contracts";
import { AuthenticatedBusinessTransport } from "./authority/business-transport.js";
import { metadata, request, allowed, receipt, paths, deferred } from "./authority/business-testing.js";
import { fromBinary } from "@bufbuild/protobuf";
import { ManagedCallAuthorizationRequestSchema, ManagedCallCompletionSchema } from "@apex/contracts";
import { OwnedCallCoordinator } from "./call-owner.js";
import { sha256CanonicalJson } from "../live/canonical.js";
import type { WireContext } from "./upstream-wire/client.js";

export function callHarness(options: { holdAuth?: boolean; holdUpstream?: boolean; failCompletion?: boolean;
  unknownAuth?: boolean; denied?: boolean; prepare?: boolean; holdCompletion?: boolean } = {}) {
  const effects: string[] = [], authClosed = deferred<void>(), upstreamClosed = deferred<void>(), upstreamResult = deferred<unknown>();
  const completionClosed = deferred<void>();
  let current = true, epoch = 23n, active = 0, now = 1000n, failCompletion = options.failCompletion;
  let gate: WireContext | undefined;
  const body = { portfolioId: "p-1" }, submitted = request();
  submitted.argumentsHash = sha256CanonicalJson(body); submitted.trace!.traceId = "1".repeat(32); submitted.trace!.spanId = "2".repeat(16);
  const business = new AuthenticatedBusinessTransport({ ...metadata, monotonicNowNs: () => now,
    channel: { start(path, bytes) {
      effects.push(path === paths.authorize ? "authorize" : "complete");
      if (path === paths.authorize && options.unknownAuth)
        return { result: Promise.reject(new Error("lost reply")), closed: authClosed.promise, cancel() {} };
      if (path === paths.complete && failCompletion)
        return { result: Promise.reject(new Error("lost receipt")), closed: Promise.resolve(), cancel() {} };
      const response = options.denied ? create(ManagedCallAuthorizationDecisionSchema, {
        decision: { outcome: GovernanceOutcome.DENIED, policyId: metadata.policyId, reasonCode: "policy.denied" }, policyRevision: 1n,
      }) : allowed();
      const completion = path === paths.complete ? fromBinary(ManagedCallCompletionSchema, bytes) : undefined;
      if (path === paths.authorize) fromBinary(ManagedCallAuthorizationRequestSchema, bytes);
      const output = path === paths.authorize ? toBinary(ManagedCallAuthorizationDecisionSchema, response)
        : toBinary(ManagedCallCompletionReceiptSchema, { ...receipt(), callId: completion!.callId, admissionId: completion!.admissionId });
      return { result: Promise.resolve(output), closed: path === paths.authorize ? authClosed.promise : completionClosed.promise,
        cancel() { if (path === paths.complete) effects.push("cancel-completion"); } };
    } } });
  const owner = new OwnedCallCoordinator({ ...metadata, business, monotonicNowNs: () => now,
    grants: { snapshot: () => ({ mode: options.prepare ? "prepare" : "serve", admitting: !options.prepare && current,
      activeCalls: active, epoch, decisionId: "decision" }),
      tryBeginCall() { active++; let released = false; return { isCurrent: () => current, release() {
        if (!released) { released = true; active--; effects.push("release"); }
      } }; } },
    routes: new Map([["portfolio.read", { toolName: "portfolio.read", session: { call(_id, _name, _input, timing) {
      gate = timing; timing.beforeWrite(); effects.push("upstream");
      return { result: upstreamResult.promise, closed: upstreamClosed.promise, cancel() { effects.push("cancel-upstream"); }, metadata: () => ({}) };
    } } }]]) });
  if (!options.holdAuth) authClosed.resolve();
  if (!options.holdCompletion) completionClosed.resolve();
  if (!options.holdUpstream) { upstreamClosed.resolve(); upstreamResult.resolve({ content: [] }); }
  return { owner, effects, submitted, body, authClosed, upstreamClosed, upstreamResult, completionClosed,
    start: () => owner.start({ request: submitted, input: body, startedAtMonotonicNs: 1000n, deadlineMonotonicNs: 100_000n }),
    revoke() { current = false; }, epoch(value: bigint) { epoch = value; }, time(value: bigint) { now = value; },
    allowCompletion() { failCompletion = false; }, get active() { return active; }, get gate() { return gate; } };
}
export async function turns() { for (let i = 0; i < 12; i++) await Promise.resolve(); }
