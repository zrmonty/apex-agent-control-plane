import assert from "node:assert/strict";
import test from "node:test";
import { toBinary } from "@bufbuild/protobuf";
import { ManagedCallAuthorizationDecisionSchema, ManagedCallCompletionReceiptSchema } from "@apex/contracts";
import { AuthenticatedBusinessTransport } from "./authority/business-transport.js";
import { metadata, request, allowed, receipt, paths } from "./authority/business-testing.js";
import { OwnedCallCoordinator } from "./call-owner.js";
import { sha256CanonicalJson } from "../live/canonical.js";

test("valid SERVE and exact durable admission dispatch once and complete after cleanup", async () => {
  const effects: string[] = [];
  let active = 0;
  const body = { portfolioId: "p-1" };
  const submitted = request(); submitted.argumentsHash = sha256CanonicalJson(body);
  submitted.trace!.traceId = "1".repeat(32); submitted.trace!.spanId = "2".repeat(16);
  const business = new AuthenticatedBusinessTransport({ ...metadata, monotonicNowNs: () => 1000n,
    channel: { start(path) {
      effects.push(path === paths.authorize ? "authorize" : "complete");
      const bytes = path === paths.authorize ? toBinary(ManagedCallAuthorizationDecisionSchema, allowed())
        : toBinary(ManagedCallCompletionReceiptSchema, receipt());
      return { result: Promise.resolve(bytes), closed: Promise.resolve(), cancel() {} };
    } } });
  const owner = new OwnedCallCoordinator({ ...metadata, business, monotonicNowNs: () => 1000n,
    grants: { snapshot: () => ({ mode: "serve", admitting: true, activeCalls: active, epoch: 23n, decisionId: "decision" }),
      tryBeginCall() { active++; return { isCurrent: () => true, release() { active--; effects.push("release"); } }; } },
    routes: new Map([["portfolio.read", { toolName: "portfolio.read", session: { call(id, name, input, timing) {
      timing.beforeWrite(); effects.push("upstream"); assert.equal(id, submitted.callId); assert.equal(name, "portfolio.read"); assert.deepEqual(input, body);
      return { result: Promise.resolve({ content: [] }), closed: Promise.resolve(), cancel() {}, metadata: () => ({}) };
    } } }]]) });
  const call = owner.start({ request: submitted, input: body, startedAtMonotonicNs: 1000n, deadlineMonotonicNs: 100_000n });
  const result = await call.result; assert.equal(result.decision.outcome, "allowed"); assert.deepEqual(result.output, { content: [] });
  await call.closed; assert.deepEqual(effects, ["authorize", "upstream", "release", "complete"]);
  assert.equal(active, 0); assert.deepEqual(owner.pending(), []); assert.deepEqual(await owner.close(), []);
});
