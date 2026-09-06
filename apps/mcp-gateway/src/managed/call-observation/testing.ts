// Component scheduling only; business decoding is real. Native ownership has a separate fixture.
import type { TestContext } from "node:test";
import { toBinary } from "@bufbuild/protobuf";
import { ManagedCallAuthorizationDecisionSchema, ManagedCallCompletionReceiptSchema } from "@apex/contracts";
import { AuthenticatedBusinessTransport } from "../authority/business-transport.js";
import { allowed, deferred, metadata, paths, receipt, request } from "../authority/business-testing.js";
import { OwnedCallCoordinator } from "../call-owner.js";
import type { WireContext } from "../upstream-wire/client.js";
import { sha256CanonicalJson } from "../../live/canonical.js";

export function observationFixture(t: TestContext, automaticGate = true, started = 9_007_199_254_740_995n) {
  let now = started, clockFailed = false, clockReads = 0, active = 0, admitting = true;
  let gate: WireContext | undefined;
  const effects: string[] = [];
  const authResult = deferred<Uint8Array>(), authClosed = deferred<void>();
  const upstreamResult = deferred<unknown>(), upstreamClosed = deferred<void>();
  const completionResult = deferred<Uint8Array>(), completionClosed = deferred<void>();
  const input = { portfolioId: "private-portfolio" }, submitted = request();
  submitted.argumentsHash = sha256CanonicalJson(input);
  submitted.trace!.traceId = "1".repeat(32); submitted.trace!.spanId = "2".repeat(16);
  const clock = () => { clockReads++; if (clockFailed) throw new Error("private clock diagnostic"); return now; };
  const business = new AuthenticatedBusinessTransport({ ...metadata, monotonicNowNs: clock, channel: {
    start(path) {
      const authorization = path === paths.authorize;
      effects.push(authorization ? "authorize" : "complete");
      return { result: authorization ? authResult.promise : completionResult.promise,
        closed: authorization ? authClosed.promise : completionClosed.promise,
        cancel() { effects.push(authorization ? "cancel-auth" : "cancel-complete"); } };
    },
  } });
  const owner = new OwnedCallCoordinator({ ...metadata, business, monotonicNowNs: clock,
    grants: { snapshot: () => ({ admitting, mode: "serve", epoch: 23n, activeCalls: active, decisionId: "decision" }),
      tryBeginCall() { active++; let released = false; return { isCurrent: () => admitting,
        release() { if (!released) { released = true; active--; effects.push("release"); } } }; } },
    routes: new Map([["portfolio.read", { toolName: "portfolio.read", session: {
      call(_id, _tool, _input, timing) {
        effects.push("session-call"); gate = timing; if (automaticGate) timing.beforeWrite();
        return { result: upstreamResult.promise, closed: upstreamClosed.promise,
          cancel() { effects.push("cancel-upstream"); }, metadata: () => ({}) };
      },
    } }]]) });
  function authorize(value = { ...allowed(), validForUs: 10_000_000n }) {
    authResult.resolve(toBinary(ManagedCallAuthorizationDecisionSchema, value));
  }
  function complete() { completionResult.resolve(toBinary(ManagedCallCompletionReceiptSchema, receipt())); }
  t.after(async () => {
    clockFailed = false;
    authorize(); authClosed.resolve(); upstreamResult.resolve({ secret: "not observation data" }); upstreamClosed.resolve();
    complete(); completionClosed.resolve(); await owner.close();
  });
  return { owner, business, input, submitted, started, effects, authorize, complete,
    authResult, authClosed, upstreamResult, upstreamClosed, completionResult, completionClosed,
    start() { const call = owner.start({ request: submitted, input,
      startedAtMonotonicNs: started, deadlineMonotonicNs: started + 30_000_000_000n });
      void call.result.catch(() => {}); return call; },
    time(value: bigint) { now = value; }, failClock() { clockFailed = true; }, revoke() { admitting = false; },
    get clockReads() { return clockReads; }, get active() { return active; }, get gate() { return gate; } };
}
