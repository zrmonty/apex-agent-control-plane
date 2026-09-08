import test from "node:test";
import assert from "node:assert/strict";
import { servingFixture, tick } from "./testing.js";
import { fromBinary, toBinary } from "@bufbuild/protobuf";
import { RuntimeNetworkInspectionResponseSchema as Network, ManagedPolicySnapshotSchema as Policy } from "@apex/contracts";
import { EvidenceAdmissionProbeResponseSchema as Evidence } from "@apex/contracts/event";
import { dependencyUnavailable } from "../authority/dependency-failure.js";
import { NetworkReadinessClient } from "../authority/network-readiness.js";

test("cold NETWORK generation mismatch remains terminal after a later correct response", async t => {
  const f = await servingFixture(t, { skipReadiness: true });
  f.holdNetworkReply(); f.holdNetworkClosure();
  const first = f.core.readiness.checkStartup(); await tick();
  f.networkProbes[0].binding!.target!.generation += 1n;
  f.replyNetwork(); await tick(); f.releaseNetwork();
  assert.equal((await first).ready, false);
  assert.equal(f.core.readiness.hasBeenReady, false);
  f.time.advance(5000); await tick();
  const second = f.core.readiness.checkStartup(); await tick();
  f.replyNetwork(); await tick(); f.releaseNetwork();
  assert.equal((await second).ready, false, "a rejected generation binding must remain terminal");
  assert.equal(f.core.isAdmitting(), false); assert.equal(f.networkProbes.length, 1);
});

for (const dependency of ["NETWORK", "EVIDENCE", "GOVERNANCE"] as const) {
  for (const defect of ["binding", "nonce", "malformed", "replay", "unknown", "spoofed-unavailable"] as const) {
    test(`cold ${dependency} ${defect} refusal is terminal before exact closure and a later healthy reply`, async t => {
      const f = await servingFixture(t, { skipReadiness: true });
      const selected = dependency === "NETWORK"
        ? { hold: f.holdNetworkClosure, release: f.releaseNetwork, requests: f.networkProbes }
        : dependency === "EVIDENCE"
          ? { hold: f.holdProbeClosure, release: f.releaseProbes, requests: f.probes }
          : { hold: f.holdPolicyClosure, release: f.releasePolicies, requests: f.policies };
      let prior: Uint8Array | undefined;
      if (defect === "replay") {
        f.response(dependency, bytes => { prior = Uint8Array.from(bytes); throw dependencyUnavailable("fixture busy"); });
        assert.equal((await f.core.readiness.checkStartup()).ready, false);
        f.time.advance(5000); await tick();
      }
      selected.hold();
      f.response(dependency, bytes => {
        if (defect === "unknown") throw Error("unknown fixture refusal");
        if (defect === "spoofed-unavailable") throw Object.assign(Error("unavailable"), { code: 14, retryable: true });
        if (defect === "malformed") return Buffer.from([255]);
        if (defect === "replay") return prior!;
        if (dependency === "NETWORK") {
          const response = fromBinary(Network, bytes);
          if (defect === "binding") response.binding!.target!.generation += 1n;
          else response.nonce = Buffer.alloc(32);
          return toBinary(Network, response);
        }
        if (dependency === "GOVERNANCE") {
          const response = fromBinary(Policy, bytes);
          if (defect === "binding") response.binding!.target!.generation += 1n;
          else response.nonce = Buffer.alloc(32);
          return toBinary(Policy, response);
        }
        const response = fromBinary(Evidence, bytes);
        response.ready = false; // Even unavailable evidence must pass ALL identity checks first.
        if (defect === "binding") response.agentId = "another-agent";
        else response.requestNonce = Buffer.alloc(32);
        return toBinary(Evidence, response);
      });
      const failed = f.core.readiness.checkStartup(); await tick();
      assert.equal(f.core.readiness.snapshot().ready, false); assert.equal(f.core.readiness.hasBeenReady, false);
      assert.equal(f.core.grants.tryBeginCall(), undefined);
      const count = selected.requests.length;
      selected.release(); await failed;
      f.response(dependency, bytes => bytes); f.time.advance(5000); await tick();
      const retry = f.core.readiness.checkStartup(); await tick(); selected.release();
      assert.equal((await retry).ready, false);
      assert.equal(selected.requests.length, count); assert.equal(f.core.isAdmitting(), false);
    });
  }
}

for (const ordinary of [false, true]) {
  test(`synchronous NETWORK refusal retries only explicitly ordinary failure (${ordinary})`, async t => {
    let refusing = true;
    const start = NetworkReadinessClient.prototype.start;
    t.mock.method(NetworkReadinessClient.prototype, "start", function (this: NetworkReadinessClient, ...args: Parameters<typeof start>) {
      if (refusing) throw ordinary ? dependencyUnavailable("private busy") : Error("unknown private failure");
      return start.apply(this, args);
    });
    const f = await servingFixture(t, { skipReadiness: true });
    assert.equal((await f.core.readiness.checkStartup()).ready, false);
    refusing = false; f.time.advance(5000); await tick();
    assert.equal((await f.core.readiness.checkStartup()).ready, ordinary);
    assert.equal(f.core.isAdmitting(), ordinary);
  });
}
