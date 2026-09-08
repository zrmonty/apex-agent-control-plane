import assert from "node:assert/strict";
import test from "node:test";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { ReadinessCheckId as Check, ReadinessReason as Reason,
  RuntimeNetworkInspectionRequestSchema as Request,
  RuntimeNetworkInspectionResponseSchema as Response } from "@apex/contracts";
import { NetworkReadinessClient } from "../authority/network-readiness.js";
import { binding, deferred } from "../authority/business-testing.js";
import { ReadinessMonitor, type ProbeOwner } from "../readiness.js";
import { flush, pass, setup } from "./test-support.js";

// Synthetic wire response at the transport boundary, using the agent's interval.
// The native agent assertion independently checks this against its real RPC.
// This exercises the actual client and monitor, not physical engine authority.
const agentObservationUs = 10_000_000n;
const second = 1_000_000_000n;

function fixture() {
  const f = setup(), origin = f.time.ns, network = "c".repeat(64);
  const pending: { payload: Uint8Array; reply: ReturnType<typeof deferred<Uint8Array>> }[] = [];
  let starts = 0;
  const client = new NetworkReadinessClient({ ...binding,
    workspaceId: f.options.configuration.workspaceId, namespaceId: f.options.configuration.namespaceId,
    proxyId: f.options.configuration.proxyId, revisionId: f.options.configuration.revisionId,
    generation: f.options.configuration.generation, fencingToken: f.launch.target!.fencingToken,
    configHash: f.options.configuration.configHash, processInstanceId: f.launch.processInstanceId,
    launchContextHash: f.launch.launchContextHash }, network, { start(path, bytes) {
    assert.equal(path, "/apex.v1.ManagedNetworkReadiness/Check");
    const request = fromBinary(Request, bytes), reply = deferred<Uint8Array>(), closed = deferred<void>();
    starts++;
    pending.push({ reply, payload: toBinary(Response, create(Response, {
      schemaVersion: 1, binding: request.binding, nonce: request.nonce, confined: true,
      networkBindingSha256: network, gatewayProcessSha256: "d".repeat(64),
      guardProcessSha256: "e".repeat(64), validForUs: agentObservationUs,
    })) });
    return { result: reply.promise, closed: closed.promise, cancel() { closed.resolve(); } };
  } }, () => f.time.ns);
  const owners = f.owners.map<ProbeOwner>(owner => owner.id !== Check.NETWORK ? owner : {
    id: Check.NETWORK, start() {
      const started = f.time.ns, job = client.start(started, started + 2n * second);
      return { cancel: () => job.cancel(), completion: (async () => {
        try { return pass(Check.NETWORK, (await job.result).validUntilMonotonicNs); }
        finally { await job.closed; }
      })() };
    },
  });
  const monitor = new ReadinessMonitor({ ...f.options, owners });
  return { ...f, monitor, origin, get starts() { return starts; },
    at(elapsed: bigint) { f.time.advance(origin + elapsed - f.time.ns); },
    async respond() {
      assert.equal(pending.length, 1);
      const operation = pending.shift()!;
      operation.reply.resolve(operation.payload);
      await flush();
    },
    async close() { await monitor.close(); await client.close(); },
  };
}

test("agent NETWORK interval bridges the five-second cadence and a timely next sweep", async () => {
  const f = fixture();
  try {
    const initial = f.monitor.checkStartup(); await flush();
    f.at(1_240_000_000n); await f.respond();
    const first = await initial; assert.equal(first.ready, true);
    // The old two-second interval failed here although all dependencies passed.
    f.at(2_100_000_000n);
    assert.equal(f.monitor.snapshot().ready, true);
    assert.equal(await f.monitor.checkStartup(), first);
    f.at(4_999_999_999n);
    assert.equal(await f.monitor.checkStartup(), first); assert.equal(f.starts, 1);
    f.at(5n * second);
    const refresh = f.monitor.checkStartup(); await flush();
    assert.equal(f.starts, 2); assert.equal(f.monitor.snapshot(), first);
    f.at(6_240_000_000n);
    assert.equal(f.monitor.snapshot(), first);
    await f.respond();
    const next = await refresh;
    assert.equal(next.ready, true); assert.notEqual(next, first);
    f.at(15n * second - 1n); assert.equal(f.monitor.snapshot(), next);
    // The successful refresh expires at its start + 10s, NOT completion + 10s.
    f.at(15n * second);
    assert.equal(f.monitor.snapshot().ready, false);
    assert.ok(f.monitor.snapshot().checks.every(check => check.reason === Reason.STALE));
  } finally { await f.close(); }
});

test("without a successful refresh, polling cannot extend original NETWORK expiry past ten seconds", async () => {
  const f = fixture();
  try {
    const initial = f.monitor.checkStartup(); await flush();
    f.at(1_240_000_000n); await f.respond();
    const first = await initial; assert.equal(first.ready, true);
    // Do not start another sweep: cached reads provide no fresh observation.
    for (const at of [2_100_000_000n, 4_999_999_999n, 5n * second, 10n * second - 1n]) {
      f.at(at); assert.equal(f.monitor.snapshot(), first);
      assert.equal(f.monitor.snapshot().ready, true); assert.equal(f.starts, 1);
    }
    f.at(10n * second);
    const stale = f.monitor.snapshot();
    assert.equal(stale.ready, false);
    assert.ok(stale.checks.every(check => check.reason === Reason.STALE));
    assert.equal(stale.observedAtUnixUs, first.observedAtUnixUs);
    assert.equal(f.starts, 1);
  } finally { await f.close(); }
});
