import assert from "node:assert/strict";
import { test } from "node:test";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { ManagedDeploymentGrantSchema, ManagedDeploymentRenewalSchema, ManagedGrantMode } from "@apex/contracts";
import { AuthenticatedGrantTransport, wireBinding } from "./grant-transport.js";
import { immutableBinding } from "./binding.js";
import type { OwnedAuthorityChannel } from "./unary.js";
import type { GrantRequest } from "./types.js";

const request: GrantRequest = { binding: {
  installationId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01", workspaceId: "work", namespaceId: "ns",
  proxyId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e02", revisionId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e03",
  processInstanceId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e04", generation: 9007199254740993n,
  fencingToken: 9007199254740995n, configHash: "a".repeat(64), launchContextHash: "b".repeat(64),
}, nonce: "c".repeat(64), renewalSequence: 9007199254740997n, applied: {
  decisionId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e05", epoch: 9007199254740999n, admitting: false, activeCalls: 7,
} };

test("grant adapter uses canonical protobuf and retains physical closure independently of decoded result", async () => {
  let close!: () => void, cancelled = 0;
  const closed = new Promise<void>(done => { close = done; });
  const channel = { start(path: string, payload: Uint8Array) {
    assert.equal(path, "/apex.v1.ManagedRuntimeAuthority/RenewDeployment");
    const input = fromBinary(ManagedDeploymentRenewalSchema, payload);
    assert.equal(input.binding?.target?.fencingToken, request.binding.fencingToken);
    assert.equal(input.applied?.epoch, request.applied!.epoch);
    assert.equal(input.applied?.activeCalls, 7);
    assert.equal(input.renewalSequence, request.renewalSequence);
    const reply = create(ManagedDeploymentGrantSchema, { binding: input.binding, nonce: input.nonce,
      decisionId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e06", epoch: 9007199254740999n,
      mode: ManagedGrantMode.PREPARE, validForUs: 7n, renewalSequence: input.renewalSequence });
    return { result: Promise.resolve(toBinary(ManagedDeploymentGrantSchema, reply)), closed, cancel() { cancelled++; } };
  } } as OwnedAuthorityChannel;
  const exchange = new AuthenticatedGrantTransport(channel).start(request);
  const reply = await exchange.result;
  assert.deepEqual(reply.binding, request.binding);
  assert.equal(reply.nonce, request.nonce);
  assert.equal(reply.epoch, request.applied!.epoch);
  assert.equal(reply.validForUs, 7n);
  assert.equal(reply.renewalSequence, request.renewalSequence);
  assert.equal(reply.mode, "prepare");
  assert.equal(exchange.closed, closed);
  exchange.cancel(); assert.equal(cancelled, 1); close(); await exchange.closed;
});

test("decoder rejects malformed or mismatched replies without replacing the physical cleanup promise", async () => {
  const good = create(ManagedDeploymentGrantSchema, { binding: wireBinding(request.binding),
    nonce: Buffer.from(request.nonce, "hex"), decisionId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e06",
    epoch: 9007199254740999n, mode: ManagedGrantMode.SERVE, validForUs: 7n, renewalSequence: request.renewalSequence });
  for (const bytes of [Buffer.from([0xff]),
    ...[{ nonce: Buffer.alloc(31) }, { nonce: Buffer.alloc(32, 0) }, { binding: undefined },
      { mode: ManagedGrantMode.UNSPECIFIED }, { validForUs: 0n }, { validForUs: 10_000_001n },
      { epoch: 0n }, { decisionId: "caller-selected" },
      { renewalSequence: 0n }, { renewalSequence: request.renewalSequence - 1n },
      { binding: { ...good.binding!, processInstanceId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e09" } },
    ].map(patch => toBinary(ManagedDeploymentGrantSchema, create(ManagedDeploymentGrantSchema, { ...good, ...patch })))]) {
    let done!: () => void, cancelled = 0;
    const closed = new Promise<void>(yes => { done = yes; });
    const channel = { start() { return { result: Promise.resolve(bytes), closed, cancel() { cancelled++; } }; } };
    const exchange = new AuthenticatedGrantTransport(channel).start(request);
    await assert.rejects(exchange.result, /managed grant refused safely/);
    assert.equal(cancelled, 1); assert.equal(exchange.closed, closed); done(); await exchange.closed;
  }
});

test("deployment scopes match the existing Apex exact 256-byte identifier grammar", () => {
  const bound = { ...request.binding, workspaceId: "_" + "a".repeat(254) + ":", namespaceId: "tenant:production" };
  assert.deepEqual(immutableBinding(bound), bound);
  for (const workspaceId of ["a".repeat(257), "has..traversal", "has/slash", "*", "", "é"])
    assert.throws(() => immutableBinding({ ...bound, workspaceId }));
});

test("invalid outgoing acknowledgement or nonce cannot dispatch an RPC", () => {
  let dispatched = 0;
  const channel = { start() { dispatched++; throw new Error(); } };
  const transport = new AuthenticatedGrantTransport(channel);
  for (const input of [ { ...request, nonce: "c".repeat(63) },
    ...[-1, 0.5, 129, Number.NaN].map(activeCalls => ({ ...request, applied: { ...request.applied!, activeCalls } })),
    { ...request, applied: { ...request.applied!, epoch: 0n } },
    { ...request, applied: { ...request.applied!, decisionId: "not-an-issued-decision" } },
  ]) assert.throws(() => transport.start(input));
  assert.equal(dispatched, 0);
});
